#include "ble_relay_transport.h"

#include <cJSON.h>

#include <algorithm>
#include <chrono>
#include <cstring>

BleRelayTransport::BleRelayTransport(bool secure) : secure_(secure) {
}

BleRelayTransport::~BleRelayTransport() {
    Disconnect();
}

bool BleRelayTransport::Connect(const char* host, int port) {
    if (!BleRelayManager::GetInstance().WaitForReady(15000)) {
        return false;
    }

    BleRelayManager::GetInstance().RegisterHandler(kBleRelaySocketStreamId, this);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        opened_ = false;
        closed_ = false;
        last_error_ = 0;
        rx_chunks_.clear();
        consumed_offset_ = 0;
        connected_ = false;
    }

    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "host", host);
    cJSON_AddNumberToObject(root, "port", port);
    cJSON_AddBoolToObject(root, "secure", secure_);
    char* text = cJSON_PrintUnformatted(root);
    std::string payload = text != nullptr ? std::string(text) : "{}";
    if (text != nullptr) {
        cJSON_free(text);
    }
    cJSON_Delete(root);

    if (!BleRelayManager::GetInstance().SendJsonFrame(BleRelayFrameType::kSocketOpen, kBleRelaySocketStreamId, 0, payload)) {
        BleRelayManager::GetInstance().UnregisterHandler(kBleRelaySocketStreamId, this);
        return false;
    }

    std::unique_lock<std::mutex> lock(mutex_);
    if (!cv_.wait_for(lock, std::chrono::seconds(15), [this]() {
            return opened_ || closed_ || last_error_ != 0;
        })) {
        BleRelayManager::GetInstance().UnregisterHandler(kBleRelaySocketStreamId, this);
        return false;
    }

    if (!opened_ || last_error_ != 0) {
        BleRelayManager::GetInstance().UnregisterHandler(kBleRelaySocketStreamId, this);
        return false;
    }
    connected_ = true;
    return true;
}

void BleRelayTransport::Disconnect() {
    BleRelayManager::GetInstance().SendJsonFrame(BleRelayFrameType::kSocketClose, kBleRelaySocketStreamId, 0, "{}");
    BleRelayManager::GetInstance().UnregisterHandler(kBleRelaySocketStreamId, this);

    std::lock_guard<std::mutex> lock(mutex_);
    connected_ = false;
    closed_ = true;
    rx_chunks_.clear();
    consumed_offset_ = 0;
    cv_.notify_all();
}

int BleRelayTransport::Send(const char* data, size_t length) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!opened_ || closed_) {
        connected_ = false;
        return -1;
    }
    if (!BleRelayManager::GetInstance().SendFrame(BleRelayFrameType::kSocketData, kBleRelaySocketStreamId, 0,
            reinterpret_cast<const uint8_t*>(data), length)) {
        connected_ = false;
        return -1;
    }
    return static_cast<int>(length);
}

int BleRelayTransport::Receive(char* buffer, size_t buffer_size) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (!cv_.wait_for(lock, std::chrono::seconds(15), [this]() {
            return !rx_chunks_.empty() || closed_ || last_error_ != 0;
        })) {
        connected_ = false;
        return -1;
    }

    if (last_error_ != 0) {
        connected_ = false;
        return -1;
    }

    if (rx_chunks_.empty()) {
        connected_ = false;
        return 0;
    }

    auto& chunk = rx_chunks_.front();
    const size_t available = chunk.size() - consumed_offset_;
    const size_t copy_len = std::min(available, buffer_size);
    memcpy(buffer, chunk.data() + consumed_offset_, copy_len);
    consumed_offset_ += copy_len;
    if (consumed_offset_ >= chunk.size()) {
        rx_chunks_.pop_front();
        consumed_offset_ = 0;
    }
    return static_cast<int>(copy_len);
}

void BleRelayTransport::OnBleRelayFrame(BleRelayFrameType type, uint8_t flags, const std::vector<uint8_t>& payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    switch (type) {
        case BleRelayFrameType::kSocketOpen:
        case BleRelayFrameType::kSocketEvent: {
            auto* root = cJSON_ParseWithLength(reinterpret_cast<const char*>(payload.data()), payload.size());
            if (root == nullptr) {
                last_error_ = -1;
                break;
            }
            auto* event = cJSON_GetObjectItem(root, "event");
            if (cJSON_IsString(event)) {
                if (strcmp(event->valuestring, "opened") == 0) {
                    opened_ = true;
                    connected_ = true;
                } else if (strcmp(event->valuestring, "closed") == 0) {
                    closed_ = true;
                    connected_ = false;
                } else if (strcmp(event->valuestring, "error") == 0) {
                    last_error_ = -1;
                    closed_ = true;
                    connected_ = false;
                }
            }
            cJSON_Delete(root);
            break;
        }
        case BleRelayFrameType::kSocketData:
            rx_chunks_.push_back(payload);
            if ((flags & kBleRelayFlagEof) != 0) {
                closed_ = true;
            }
            break;
        case BleRelayFrameType::kSocketClose:
            closed_ = true;
            connected_ = false;
            break;
        default:
            break;
    }
    cv_.notify_all();
}

void BleRelayTransport::OnBleRelayDisconnected() {
    std::lock_guard<std::mutex> lock(mutex_);
    connected_ = false;
    closed_ = true;
    cv_.notify_all();
}
