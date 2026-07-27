#include "ble_relay_transport.h"

#include <cJSON.h>

#include <algorithm>
#include <chrono>
#include <cstring>

namespace {
constexpr size_t kMaxSocketQueuedBytes = 64 * 1024;
constexpr size_t kMaxHostBytes = 253;
}

BleRelayTransport::BleRelayTransport(bool secure) : secure_(secure) {
}

BleRelayTransport::~BleRelayTransport() {
    Disconnect();
}

bool BleRelayTransport::Connect(const char* host, int port) {
    if (host == nullptr || host[0] == '\0' || strnlen(host, kMaxHostBytes + 1) > kMaxHostBytes ||
        port <= 0 || port > 65535) {
        return false;
    }
    uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (connecting_ || opened_ || connected_) return false;
        generation = ++operation_generation_;
        opened_ = false;
        closed_ = false;
        last_error_ = 0;
        rx_chunks_.clear();
        queued_rx_bytes_ = 0;
        consumed_offset_ = 0;
        connected_ = false;
        connecting_ = true;
    }
    if (!BleRelayManager::GetInstance().WaitForReady(15000)) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (operation_generation_ == generation) connecting_ = false;
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!connecting_ || operation_generation_ != generation) return false;
    }
    auto& relay = BleRelayManager::GetInstance();
    const bool transport_v2 = relay.IsTransportV2();
    const uint32_t request_id = transport_v2 ? relay.AllocateRequestId() : 0;
    if (transport_v2 && request_id == 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (operation_generation_ == generation) connecting_ = false;
        return false;
    }
    const bool registered = request_id == 0 ? relay.RegisterHandler(kBleRelaySocketStreamId, this) :
        relay.RegisterRequestHandler(kBleRelaySocketStreamId, request_id, this);
    bool keep_registration = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        keep_registration = registered && connecting_ && operation_generation_ == generation;
        if (keep_registration) active_request_id_ = request_id;
        if (!keep_registration && operation_generation_ == generation) connecting_ = false;
    }
    if (!keep_registration) {
        if (registered) {
            if (request_id == 0) relay.UnregisterHandler(kBleRelaySocketStreamId, this);
            else relay.UnregisterRequestHandler(kBleRelaySocketStreamId, request_id, this);
        }
        return false;
    }

    cJSON* root = cJSON_CreateObject();
    if (root == nullptr || cJSON_AddStringToObject(root, "host", host) == nullptr ||
        cJSON_AddNumberToObject(root, "port", port) == nullptr ||
        cJSON_AddBoolToObject(root, "secure", secure_) == nullptr) {
        cJSON_Delete(root);
        if (request_id == 0) relay.UnregisterHandler(kBleRelaySocketStreamId, this);
        else relay.UnregisterRequestHandler(kBleRelaySocketStreamId, request_id, this);
        std::lock_guard<std::mutex> lock(mutex_);
        if (operation_generation_ == generation) connecting_ = false;
        return false;
    }
    char* text = cJSON_PrintUnformatted(root);
    std::string payload = text != nullptr ? std::string(text) : std::string();
    if (text != nullptr) {
        cJSON_free(text);
    }
    cJSON_Delete(root);
    if (payload.empty()) {
        if (request_id == 0) relay.UnregisterHandler(kBleRelaySocketStreamId, this);
        else relay.UnregisterRequestHandler(kBleRelaySocketStreamId, request_id, this);
        std::lock_guard<std::mutex> lock(mutex_);
        if (operation_generation_ == generation) connecting_ = false;
        return false;
    }

    bool open_sent = false;
    {
        std::lock_guard<std::mutex> operation_lock(operation_mutex_);
        std::lock_guard<std::mutex> lock(mutex_);
        if (connecting_ && operation_generation_ == generation) {
            open_sent = request_id == 0 ? relay.SendJsonFrame(
                BleRelayFrameType::kSocketOpen, kBleRelaySocketStreamId, 0, payload) :
                relay.SendRequestJsonFrame(
                    BleRelayFrameType::kSocketOpen, kBleRelaySocketStreamId, request_id, 0, payload);
        }
    }
    if (!open_sent) {
        if (request_id == 0) relay.UnregisterHandler(kBleRelaySocketStreamId, this);
        else relay.UnregisterRequestHandler(kBleRelaySocketStreamId, request_id, this);
        std::lock_guard<std::mutex> lock(mutex_);
        if (operation_generation_ == generation) connecting_ = false;
        return false;
    }

    std::unique_lock<std::mutex> lock(mutex_);
    const bool signaled = cv_.wait_for(lock, std::chrono::seconds(15), [this]() {
            return opened_ || closed_ || last_error_ != 0;
        });
    if (operation_generation_ != generation) {
        return false;
    }
    const bool connected = signaled && opened_ && last_error_ == 0;
    connected_ = connected;
    connecting_ = false;
    lock.unlock();
    if (!connected) {
        if (request_id == 0) relay.UnregisterHandler(kBleRelaySocketStreamId, this);
        else {
            relay.SendRequestFrame(
                static_cast<BleRelayFrameType>(kBleRelayV2CancelType),
                kBleRelaySocketStreamId, request_id, 0, nullptr, 0);
            relay.UnregisterRequestHandler(kBleRelaySocketStreamId, request_id, this);
        }
        return false;
    }
    return true;
}

void BleRelayTransport::Disconnect() {
    std::lock_guard<std::mutex> operation_lock(operation_mutex_);
    bool should_close = false;
    uint32_t request_id = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        should_close = connecting_ || opened_ || connected_;
        request_id = active_request_id_;
        ++operation_generation_;
        connecting_ = false;
        opened_ = false;
        connected_ = false;
        closed_ = true;
        rx_chunks_.clear();
        queued_rx_bytes_ = 0;
        consumed_offset_ = 0;
        active_request_id_ = 0;
        cv_.notify_all();
    }
    if (should_close) {
        if (request_id == 0) {
            BleRelayManager::GetInstance().SendJsonFrame(
                BleRelayFrameType::kSocketClose, kBleRelaySocketStreamId, 0, "{}");
        } else {
            BleRelayManager::GetInstance().SendRequestFrame(
                static_cast<BleRelayFrameType>(kBleRelayV2CancelType),
                kBleRelaySocketStreamId, request_id, 0, nullptr, 0);
        }
    }
    if (request_id == 0) {
        BleRelayManager::GetInstance().UnregisterHandler(kBleRelaySocketStreamId, this);
    } else {
        BleRelayManager::GetInstance().UnregisterRequestHandler(kBleRelaySocketStreamId, request_id, this);
    }
}

int BleRelayTransport::Send(const char* data, size_t length) {
    if (length > 0 && data == nullptr) return -1;
    std::lock_guard<std::mutex> operation_lock(operation_mutex_);
    uint64_t generation = 0;
    uint32_t request_id = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!opened_ || closed_ || !connected_) {
            connected_ = false;
            return -1;
        }
        generation = operation_generation_;
        request_id = active_request_id_;
    }
    const bool sent = request_id == 0 ? BleRelayManager::GetInstance().SendFrame(
        BleRelayFrameType::kSocketData, kBleRelaySocketStreamId, 0,
        reinterpret_cast<const uint8_t*>(data), length) :
        BleRelayManager::GetInstance().SendRequestFrame(
            BleRelayFrameType::kSocketData, kBleRelaySocketStreamId, request_id, 0,
            reinterpret_cast<const uint8_t*>(data), length);
    std::lock_guard<std::mutex> lock(mutex_);
    if (operation_generation_ != generation || !sent) {
        if (operation_generation_ == generation) connected_ = false;
        return -1;
    }
    return static_cast<int>(length);
}

int BleRelayTransport::Receive(char* buffer, size_t buffer_size) {
    if (buffer == nullptr || buffer_size == 0) return -1;
    std::unique_lock<std::mutex> lock(mutex_);
    if (!cv_.wait_for(lock, std::chrono::seconds(15), [this]() {
            return !rx_chunks_.empty() || closed_ || last_error_ != 0;
        })) {
        connected_ = false;
        lock.unlock();
        Disconnect();
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
    queued_rx_bytes_ -= copy_len;
    if (consumed_offset_ >= chunk.size()) {
        rx_chunks_.pop_front();
        consumed_offset_ = 0;
    }
    const uint32_t request_id = active_request_id_;
    lock.unlock();
    BleRelayManager::GetInstance().RefreshReceiveCredit(kBleRelaySocketStreamId, request_id);
    return static_cast<int>(copy_len);
}

bool BleRelayTransport::OnBleRelayFrame(BleRelayFrameType type, uint8_t flags, const std::vector<uint8_t>& payload) {
    bool overflow = false;
    bool accepted = true;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_ && !connecting_) return false;
        switch (type) {
        case BleRelayFrameType::kSocketOpen:
        case BleRelayFrameType::kSocketEvent: {
            auto* root = cJSON_ParseWithLength(reinterpret_cast<const char*>(payload.data()), payload.size());
            if (root == nullptr) {
                last_error_ = -1;
                accepted = false;
                break;
            }
            auto* event = cJSON_GetObjectItem(root, "event");
            if (cJSON_IsString(event) && cJSON_GetArraySize(root) == 1) {
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
                } else {
                    last_error_ = -1;
                    closed_ = true;
                    connected_ = false;
                }
            } else {
                last_error_ = -1;
                closed_ = true;
                connected_ = false;
                accepted = false;
            }
            cJSON_Delete(root);
            break;
        }
        case BleRelayFrameType::kSocketData:
            if (payload.empty() && (flags & (kBleRelayFlagEof | kBleRelayFlagError)) == 0) {
                last_error_ = -1;
                closed_ = true;
                connected_ = false;
                accepted = false;
            } else if ((flags & kBleRelayFlagError) != 0) {
                last_error_ = -1;
                closed_ = true;
                connected_ = false;
            } else if (queued_rx_bytes_ > kMaxSocketQueuedBytes ||
                payload.size() > kMaxSocketQueuedBytes - queued_rx_bytes_) {
                last_error_ = -1;
                closed_ = true;
                connected_ = false;
                rx_chunks_.clear();
                queued_rx_bytes_ = 0;
                consumed_offset_ = 0;
                overflow = true;
                accepted = false;
            } else {
                queued_rx_bytes_ += payload.size();
                rx_chunks_.push_back(payload);
            }
            if ((flags & kBleRelayFlagEof) != 0) {
                closed_ = true;
            }
            break;
        case BleRelayFrameType::kSocketClose:
            closed_ = true;
            connected_ = false;
            break;
        default:
            accepted = false;
            break;
        }
        cv_.notify_all();
    }
    return accepted && !overflow;
}

void BleRelayTransport::OnBleRelayDisconnected() {
    std::lock_guard<std::mutex> lock(mutex_);
    connected_ = false;
    connecting_ = false;
    closed_ = true;
    cv_.notify_all();
}

uint8_t BleRelayTransport::AvailableReceiveCredit() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_ || last_error_ != 0 || (!connecting_ && !connected_)) return 0;
    const size_t remaining = queued_rx_bytes_ >= kMaxSocketQueuedBytes
        ? 0 : kMaxSocketQueuedBytes - queued_rx_bytes_;
    return static_cast<uint8_t>(std::min<size_t>(32, remaining / kBleRelayFramePayloadMax));
}
