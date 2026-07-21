#include "ble_relay_http.h"

#include <cJSON.h>
#include <esp_log.h>

#include <algorithm>
#include <chrono>
#include <cstring>

#define TAG "BleRelayHttp"

namespace {
constexpr size_t kMaxQueuedBodyBytes = 64 * 1024;
constexpr size_t kMaxRelayBodyBytes = 8 * 1024 * 1024;
}

BleRelayHttp::BleRelayHttp() {
}

BleRelayHttp::~BleRelayHttp() {
    Close();
}

void BleRelayHttp::SetHeader(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    headers_[key] = value;
}

bool BleRelayHttp::Open(const std::string& method, const std::string& url, const std::string& content) {
    if (!BleRelayManager::GetInstance().WaitForReady(timeout_ms_)) {
        ESP_LOGE(TAG, "BLE relay not ready");
        return false;
    }

    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "method", method.c_str());
    cJSON_AddStringToObject(root, "url", url.c_str());
    cJSON_AddStringToObject(root, "body", content.c_str());
    cJSON* request_headers = cJSON_CreateObject();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ResetStateLocked();
        for (const auto& header : headers_) {
            cJSON_AddStringToObject(request_headers, header.first.c_str(), header.second.c_str());
        }
        opened_ = true;
    }
    cJSON_AddItemToObject(root, "headers", request_headers);

    char* text = cJSON_PrintUnformatted(root);
    std::string payload = text != nullptr ? std::string(text) : "{}";
    if (text != nullptr) {
        cJSON_free(text);
    }
    cJSON_Delete(root);

    BleRelayManager::GetInstance().RegisterHandler(kBleRelayHttpStreamId, this);
    if (!BleRelayManager::GetInstance().SendJsonFrame(BleRelayFrameType::kHttpOpen, kBleRelayHttpStreamId, 0, payload)) {
        BleRelayManager::GetInstance().UnregisterHandler(kBleRelayHttpStreamId, this);
        std::lock_guard<std::mutex> lock(mutex_);
        ResetStateLocked();
        return false;
    }

    std::unique_lock<std::mutex> lock(mutex_);
    if (!WaitForHeadersLocked(lock)) {
        BleRelayManager::GetInstance().UnregisterHandler(kBleRelayHttpStreamId, this);
        return false;
    }
    return true;
}

void BleRelayHttp::Close() {
    BleRelayManager::GetInstance().UnregisterHandler(kBleRelayHttpStreamId, this);
    std::lock_guard<std::mutex> lock(mutex_);
    ResetStateLocked();
}

int BleRelayHttp::GetStatusCode() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return status_code_;
}

std::string BleRelayHttp::GetResponseHeader(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = response_headers_.find(key);
    return it == response_headers_.end() ? "" : it->second;
}

size_t BleRelayHttp::GetBodyLength() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return body_length_;
}

const std::string& BleRelayHttp::GetBody() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!eof_ && !error_) {
        if (!WaitForDataLocked(lock)) {
            break;
        }
        while (!body_chunks_.empty()) {
            auto chunk = std::move(body_chunks_.front());
            body_chunks_.pop_front();
            const size_t remaining = chunk.size() - consumed_offset_;
            if (remaining > kMaxRelayBodyBytes - response_body_.size()) {
                error_ = true;
                break;
            }
            response_body_.append(
                reinterpret_cast<const char*>(chunk.data() + consumed_offset_), remaining);
            queued_body_bytes_ -= remaining;
            consumed_offset_ = 0;
        }
    }
    return response_body_;
}

int BleRelayHttp::Read(char* buffer, size_t buffer_size) {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!error_) {
        if (!body_chunks_.empty()) {
            auto& chunk = body_chunks_.front();
            const size_t available = chunk.size() - consumed_offset_;
            const size_t copy_len = std::min(available, buffer_size);
            memcpy(buffer, chunk.data() + consumed_offset_, copy_len);
            consumed_offset_ += copy_len;
            queued_body_bytes_ -= copy_len;
            if (consumed_offset_ >= chunk.size()) {
                body_chunks_.pop_front();
                consumed_offset_ = 0;
            }
            return static_cast<int>(copy_len);
        }
        if (eof_) {
            return 0;
        }
        if (!WaitForDataLocked(lock)) {
            return -1;
        }
    }
    return -1;
}

void BleRelayHttp::SetTimeout(int timeout_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    timeout_ms_ = timeout_ms;
}

void BleRelayHttp::OnBleRelayFrame(BleRelayFrameType type, uint8_t flags, const std::vector<uint8_t>& payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (type == BleRelayFrameType::kHttpResult) {
        auto* root = cJSON_ParseWithLength(reinterpret_cast<const char*>(payload.data()), payload.size());
        if (root == nullptr) {
            error_ = true;
            cv_.notify_all();
            return;
        }

        auto* status_code = cJSON_GetObjectItem(root, "status_code");
        auto* content_length = cJSON_GetObjectItem(root, "content_length");
        auto* response_headers = cJSON_GetObjectItem(root, "headers");
        if (cJSON_IsNumber(status_code)) {
            status_code_ = status_code->valueint;
        }
        if (cJSON_IsNumber(content_length)) {
            const double declared_length = content_length->valuedouble;
            if (declared_length < 0 || declared_length > kMaxRelayBodyBytes ||
                declared_length != static_cast<size_t>(declared_length)) {
                error_ = true;
            } else {
                body_length_ = static_cast<size_t>(declared_length);
            }
        }
        response_headers_.clear();
        if (cJSON_IsObject(response_headers)) {
            cJSON* item = nullptr;
            cJSON_ArrayForEach(item, response_headers) {
                if (cJSON_IsString(item) && item->string != nullptr) {
                    response_headers_[item->string] = item->valuestring;
                }
            }
        }
        headers_ready_ = true;
        cJSON_Delete(root);
        cv_.notify_all();
        return;
    }

    if (type == BleRelayFrameType::kHttpBody) {
        if (!payload.empty()) {
            if (error_ || payload.size() > kMaxQueuedBodyBytes - queued_body_bytes_) {
                error_ = true;
                eof_ = true;
            } else {
                queued_body_bytes_ += payload.size();
                body_chunks_.push_back(payload);
            }
        }
        if ((flags & kBleRelayFlagEof) != 0) {
            eof_ = true;
        }
        if ((flags & kBleRelayFlagError) != 0) {
            error_ = true;
        }
        cv_.notify_all();
    }
}

void BleRelayHttp::OnBleRelayDisconnected() {
    std::lock_guard<std::mutex> lock(mutex_);
    error_ = true;
    eof_ = true;
    cv_.notify_all();
}

void BleRelayHttp::ResetStateLocked() {
    response_headers_.clear();
    body_chunks_.clear();
    response_body_.clear();
    status_code_ = 0;
    body_length_ = 0;
    consumed_offset_ = 0;
    queued_body_bytes_ = 0;
    opened_ = false;
    headers_ready_ = false;
    eof_ = false;
    error_ = false;
}

bool BleRelayHttp::WaitForHeadersLocked(std::unique_lock<std::mutex>& lock) {
    return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms_), [this]() {
        return headers_ready_ || error_;
    }) && !error_;
}

bool BleRelayHttp::WaitForDataLocked(std::unique_lock<std::mutex>& lock) {
    return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms_), [this]() {
        return !body_chunks_.empty() || eof_ || error_;
    });
}
