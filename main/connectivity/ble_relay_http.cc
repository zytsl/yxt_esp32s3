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
constexpr size_t kMaxRequestBodyBytes = 48 * 1024;
constexpr size_t kMaxRequestHeaderBytes = 12 * 1024;
constexpr size_t kMaxMethodBytes = 16;
constexpr size_t kMaxUrlBytes = 2048;
constexpr size_t kMaxRequestHeaders = 64;
constexpr size_t kMaxHeaderNameBytes = 256;
constexpr size_t kMaxHeaderValueBytes = 8192;
bool ContainsNul(const std::string& value) {
    return value.find('\0') != std::string::npos;
}
}

BleRelayHttp::BleRelayHttp() {
}

BleRelayHttp::~BleRelayHttp() {
    Close();
}

void BleRelayHttp::SetHeader(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (opening_ || opened_ || key.empty() || ContainsNul(key) || ContainsNul(value) ||
        key.size() > kMaxHeaderNameBytes || value.size() > kMaxHeaderValueBytes ||
        (headers_.find(key) == headers_.end() && headers_.size() >= kMaxRequestHeaders)) {
        ESP_LOGE(TAG, "Rejected oversized HTTP relay header");
        return;
    }
    headers_[key] = value;
}

bool BleRelayHttp::Open(const std::string& method, const std::string& url, const std::string& content) {
    std::lock_guard<std::mutex> open_call_lock(open_call_mutex_);
    if (method.empty() || method.size() > kMaxMethodBytes || url.empty() || url.size() > kMaxUrlBytes ||
        content.size() > kMaxRequestBodyBytes || ContainsNul(method) || ContainsNul(url) || ContainsNul(content)) {
        ESP_LOGE(TAG, "Rejected invalid HTTP relay request dimensions");
        return false;
    }
    uint64_t generation = 0;
    int timeout_ms = 0;
    std::map<std::string, std::string> headers_snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (opening_ || opened_) return false;
        ResetStateLocked();
        opening_ = true;
        generation = ++operation_generation_;
        timeout_ms = timeout_ms_;
        headers_snapshot = headers_;
    }
    auto reset_if_owner = [this, generation]() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (operation_generation_ == generation) ResetStateLocked();
    };
    auto still_owner = [this, generation]() {
        std::lock_guard<std::mutex> lock(mutex_);
        return opening_ && operation_generation_ == generation;
    };

    if (!BleRelayManager::GetInstance().WaitForReady(timeout_ms)) {
        ESP_LOGE(TAG, "BLE relay not ready");
        reset_if_owner();
        return false;
    }
    if (!still_owner()) return false;

    cJSON* root = cJSON_CreateObject();
    cJSON* request_headers = cJSON_CreateObject();
    if (root == nullptr || request_headers == nullptr ||
        cJSON_AddStringToObject(root, "method", method.c_str()) == nullptr ||
        cJSON_AddStringToObject(root, "url", url.c_str()) == nullptr ||
        cJSON_AddStringToObject(root, "body", content.c_str()) == nullptr) {
        cJSON_Delete(request_headers);
        cJSON_Delete(root);
        reset_if_owner();
        return false;
    }
    bool headers_valid = true;
    size_t header_bytes = 0;
    for (const auto& header : headers_snapshot) {
        if (header.first.size() > kMaxRequestHeaderBytes - header_bytes ||
            header.second.size() > kMaxRequestHeaderBytes - header_bytes - header.first.size()) {
            headers_valid = false;
            break;
        }
        header_bytes += header.first.size() + header.second.size();
        if (cJSON_AddStringToObject(request_headers, header.first.c_str(), header.second.c_str()) == nullptr) {
            headers_valid = false;
            break;
        }
    }
    if (!headers_valid) {
        cJSON_Delete(request_headers);
        cJSON_Delete(root);
        reset_if_owner();
        return false;
    }
    if (!cJSON_AddItemToObject(root, "headers", request_headers)) {
        cJSON_Delete(request_headers);
        cJSON_Delete(root);
        reset_if_owner();
        return false;
    }

    char* text = cJSON_PrintUnformatted(root);
    std::string payload = text != nullptr ? std::string(text) : std::string();
    if (text != nullptr) {
        cJSON_free(text);
    }
    cJSON_Delete(root);
    if (payload.empty() || payload.size() > kBleRelayMessageMax) {
        reset_if_owner();
        return false;
    }

    if (!still_owner()) return false;
    auto& relay = BleRelayManager::GetInstance();
    const bool transport_v2 = relay.IsTransportV2();
    const uint32_t request_id = transport_v2 ? relay.AllocateRequestId() : 0;
    if (transport_v2 && request_id == 0) {
        reset_if_owner();
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!opening_ || operation_generation_ != generation) return false;
        active_request_id_ = request_id;
    }
    const bool registered = request_id == 0 ? relay.RegisterHandler(kBleRelayHttpStreamId, this) :
        relay.RegisterRequestHandler(kBleRelayHttpStreamId, request_id, this);
    auto unregister = [&relay, request_id, this]() {
        if (request_id == 0) relay.UnregisterHandler(kBleRelayHttpStreamId, this);
        else relay.UnregisterRequestHandler(kBleRelayHttpStreamId, request_id, this);
    };
    if (!registered || !still_owner()) {
        if (registered) unregister();
        reset_if_owner();
        return false;
    }

    bool request_sent = false;
    {
        std::lock_guard<std::mutex> operation_lock(operation_mutex_);
        if (still_owner()) {
            request_sent = request_id == 0 ? relay.SendJsonFrame(
                BleRelayFrameType::kHttpOpen, kBleRelayHttpStreamId, 0, payload) :
                relay.SendRequestJsonFrame(
                    BleRelayFrameType::kHttpOpen, kBleRelayHttpStreamId, request_id, 0, payload);
        }
    }
    if (!request_sent) {
        unregister();
        reset_if_owner();
        return false;
    }

    std::unique_lock<std::mutex> lock(mutex_);
    if (operation_generation_ != generation || !WaitForHeadersLocked(lock) || operation_generation_ != generation) {
        const bool owner = operation_generation_ == generation;
        if (owner) ResetStateLocked();
        lock.unlock();
        if (owner) {
            if (request_id != 0) {
                relay.SendRequestFrame(
                    static_cast<BleRelayFrameType>(kBleRelayV2CancelType),
                    kBleRelayHttpStreamId, request_id, 0, nullptr, 0);
            }
            unregister();
        }
        return false;
    }
    opening_ = false;
    opened_ = true;
    return true;
}

void BleRelayHttp::Close() {
    std::lock_guard<std::mutex> operation_lock(operation_mutex_);
    uint32_t request_id = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        request_id = active_request_id_;
        ++operation_generation_;
        ResetStateLocked();
        error_ = true;
        eof_ = true;
        cv_.notify_all();
    }
    auto& relay = BleRelayManager::GetInstance();
    if (request_id == 0) {
        relay.UnregisterHandler(kBleRelayHttpStreamId, this);
    } else {
        relay.SendRequestFrame(
            static_cast<BleRelayFrameType>(kBleRelayV2CancelType),
            kBleRelayHttpStreamId, request_id, 0, nullptr, 0);
        relay.UnregisterRequestHandler(kBleRelayHttpStreamId, request_id, this);
    }
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
    bool timed_out = false;
    while (!eof_ && !error_) {
        if (!WaitForDataLocked(lock)) {
            timed_out = true;
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
    const uint32_t request_id = active_request_id_;
    lock.unlock();
    if (timed_out) Close();
    else BleRelayManager::GetInstance().RefreshReceiveCredit(kBleRelayHttpStreamId, request_id);
    return response_body_;
}

int BleRelayHttp::Read(char* buffer, size_t buffer_size) {
    if (buffer == nullptr || buffer_size == 0) return -1;
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
            const uint32_t request_id = active_request_id_;
            lock.unlock();
            BleRelayManager::GetInstance().RefreshReceiveCredit(kBleRelayHttpStreamId, request_id);
            return static_cast<int>(copy_len);
        }
        if (eof_) {
            return 0;
        }
        if (!WaitForDataLocked(lock)) {
            lock.unlock();
            Close();
            return -1;
        }
    }
    return -1;
}

void BleRelayHttp::SetTimeout(int timeout_ms) {
    if (timeout_ms <= 0 || timeout_ms > 120000) return;
    std::lock_guard<std::mutex> lock(mutex_);
    timeout_ms_ = timeout_ms;
}

bool BleRelayHttp::OnBleRelayFrame(BleRelayFrameType type, uint8_t flags, const std::vector<uint8_t>& payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (type == BleRelayFrameType::kHttpResult) {
        auto* root = cJSON_ParseWithLength(reinterpret_cast<const char*>(payload.data()), payload.size());
        if (root == nullptr) {
            error_ = true;
            cv_.notify_all();
            return false;
        }

        auto* status_code = cJSON_GetObjectItem(root, "status_code");
        auto* content_length = cJSON_GetObjectItem(root, "content_length");
        auto* response_headers = cJSON_GetObjectItem(root, "headers");
        if (!cJSON_IsNumber(status_code) || status_code->valuedouble < 100 ||
            status_code->valuedouble > 599 || status_code->valuedouble != status_code->valueint ||
            !cJSON_IsNumber(content_length) || !cJSON_IsObject(response_headers)) {
            error_ = true;
        } else {
            status_code_ = status_code->valueint;
            const double declared_length = content_length->valuedouble;
            if (declared_length < 0 || declared_length > kMaxRelayBodyBytes ||
                declared_length != static_cast<size_t>(declared_length)) {
                error_ = true;
            } else {
                body_length_ = static_cast<size_t>(declared_length);
            }
        }
        response_headers_.clear();
        if (!error_) {
            size_t header_count = 0;
            cJSON* item = nullptr;
            cJSON_ArrayForEach(item, response_headers) {
                if (++header_count > kMaxRequestHeaders || !cJSON_IsString(item) || item->string == nullptr ||
                    strlen(item->string) > kMaxHeaderNameBytes || strlen(item->valuestring) > kMaxHeaderValueBytes) {
                    error_ = true;
                    response_headers_.clear();
                    break;
                }
                response_headers_[item->string] = item->valuestring;
            }
        }
        headers_ready_ = true;
        cJSON_Delete(root);
        cv_.notify_all();
        return !error_;
    }

    if (type == BleRelayFrameType::kHttpBody) {
        bool accepted = true;
        if (!payload.empty()) {
            if (error_ || received_body_bytes_ > body_length_ ||
                payload.size() > body_length_ - received_body_bytes_ ||
                queued_body_bytes_ > kMaxQueuedBodyBytes ||
                payload.size() > kMaxQueuedBodyBytes - queued_body_bytes_) {
                error_ = true;
                eof_ = true;
                body_chunks_.clear();
                queued_body_bytes_ = 0;
                consumed_offset_ = 0;
                accepted = false;
            } else {
                received_body_bytes_ += payload.size();
                queued_body_bytes_ += payload.size();
                body_chunks_.push_back(payload);
            }
        }
        if ((flags & kBleRelayFlagEof) != 0) {
            eof_ = received_body_bytes_ == body_length_;
            if (!eof_) {
                error_ = true;
                accepted = false;
            }
        }
        if ((flags & kBleRelayFlagError) != 0) {
            error_ = true;
        }
        cv_.notify_all();
        return accepted;
    }
    return false;
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
    received_body_bytes_ = 0;
    opened_ = false;
    opening_ = false;
    headers_ready_ = false;
    eof_ = false;
    error_ = false;
    active_request_id_ = 0;
}

uint8_t BleRelayHttp::AvailableReceiveCredit() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (error_ || eof_ || (!opening_ && !opened_)) return 0;
    const size_t remaining = queued_body_bytes_ >= kMaxQueuedBodyBytes
        ? 0 : kMaxQueuedBodyBytes - queued_body_bytes_;
    return static_cast<uint8_t>(std::min<size_t>(32, remaining / kBleRelayFramePayloadMax));
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
