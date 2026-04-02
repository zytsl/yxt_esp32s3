#include "ble_relay_manager.h"

#include "board.h"
#include "settings.h"
#include "system_info.h"

#include <cJSON.h>
#include <esp_heap_caps.h>
#include <esp_log.h>
#include <esp_random.h>
#include <host/ble_att.h>
#include <host/ble_gap.h>
#include <host/ble_gatt.h>
#include <host/ble_hs.h>
#include <host/ble_hs_mbuf.h>
#include <mbedtls/sha256.h>
#include <nimble/nimble_port.h>
#include <nimble/nimble_port_freertos.h>
#include <os/os_mbuf.h>
#include <services/gap/ble_svc_gap.h>
#include <services/gatt/ble_svc_gatt.h>

#include <algorithm>
#include <cstring>
#include <tuple>

#define TAG "BleRelay"

namespace {
constexpr EventBits_t kRelayReadyBit = 1 << 0;
constexpr EventBits_t kRelayConnectedBit = 1 << 1;

constexpr const char* kConnectivityNamespace = "connectivity";
constexpr const char* kBlePeerIdKey = "ble_peer_id";
constexpr const char* kBleSecretKey = "ble_secret";
constexpr const char* kBleBoundKey = "ble_bound";
constexpr const char* kBleForcePairingKey = "force_ble_pair";
uint16_t g_ble_relay_notify_val_handle = 0;

uint32_t BuildPendingFrameKey(BleRelayFrameType type, uint16_t stream_id) {
    return (static_cast<uint32_t>(static_cast<uint8_t>(type)) << 16) | stream_id;
}

bool RequiresAssembly(BleRelayFrameType type) {
    switch (type) {
        case BleRelayFrameType::kPairResponse:
        case BleRelayFrameType::kAuthResponse:
        case BleRelayFrameType::kHttpResult:
        case BleRelayFrameType::kSocketEvent:
            return true;
        case BleRelayFrameType::kPairRequest:
        case BleRelayFrameType::kAuthRequest:
        case BleRelayFrameType::kHeartbeat:
        case BleRelayFrameType::kHttpOpen:
        case BleRelayFrameType::kHttpBody:
        case BleRelayFrameType::kSocketOpen:
        case BleRelayFrameType::kSocketData:
        case BleRelayFrameType::kSocketClose:
            return false;
    }
    return false;
}

bool IsCompleteJsonPayload(const std::vector<uint8_t>& payload) {
    cJSON* root = cJSON_ParseWithLength(reinterpret_cast<const char*>(payload.data()), payload.size());
    if (root == nullptr) {
        return false;
    }
    cJSON_Delete(root);
    return true;
}
}

BleRelayManager* BleRelayManager::instance_ = nullptr;
ble_uuid128_t BleRelayManager::service_uuid_ =
    BLE_UUID128_INIT(0x51, 0x4b, 0x2d, 0xe8, 0xb4, 0x7f, 0x58, 0x9a, 0x6f, 0x4c, 0x2d, 0xb1, 0x0c, 0x6f, 0x2e, 0x7b);
ble_uuid128_t BleRelayManager::app_to_device_uuid_ =
    BLE_UUID128_INIT(0x52, 0x4b, 0x2d, 0xe8, 0xb4, 0x7f, 0x58, 0x9a, 0x6f, 0x4c, 0x2d, 0xb1, 0x0d, 0x6f, 0x2e, 0x7b);
ble_uuid128_t BleRelayManager::device_to_app_uuid_ =
    BLE_UUID128_INIT(0x53, 0x4b, 0x2d, 0xe8, 0xb4, 0x7f, 0x58, 0x9a, 0x6f, 0x4c, 0x2d, 0xb1, 0x0e, 0x6f, 0x2e, 0x7b);

BleRelayManager& BleRelayManager::GetInstance() {
    static BleRelayManager instance;
    return instance;
}

BleRelayManager::BleRelayManager() {
    event_group_ = xEventGroupCreate();

    esp_timer_create_args_t timer_args = {
        .callback = &BleRelayManager::HeartbeatTimer,
        .arg = this,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "ble_relay_hb",
        .skip_unhandled_events = true,
    };
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &heartbeat_timer_));
}

BleRelayManager::~BleRelayManager() {
    if (heartbeat_timer_ != nullptr) {
        esp_timer_stop(heartbeat_timer_);
        esp_timer_delete(heartbeat_timer_);
    }
    if (event_group_ != nullptr) {
        vEventGroupDelete(event_group_);
    }
}

void BleRelayManager::EnsureInitialized() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) {
        return;
    }

    instance_ = this;
    LoadStateFromNvs();

    ESP_LOGI(TAG, "BLE init heap: free_internal=%" PRIu32 " largest_internal=%" PRIu32 " free_psram=%" PRIu32,
        heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
        heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
        heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    ESP_ERROR_CHECK(nimble_port_init());

    ble_hs_cfg.reset_cb = &BleRelayManager::OnReset;
    ble_hs_cfg.sync_cb = &BleRelayManager::OnSync;
    ble_hs_cfg.gatts_register_cb = &BleRelayManager::GattRegister;

    static ble_gatt_chr_def g_ble_relay_characteristics[] = {
        {
            .uuid = &BleRelayManager::app_to_device_uuid_.u,
            .access_cb = BleRelayManager::GattAccessWrite,
            .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
        },
        {
            .uuid = &BleRelayManager::device_to_app_uuid_.u,
            .access_cb = BleRelayManager::GattAccessNotify,
            .flags = BLE_GATT_CHR_F_NOTIFY,
            .val_handle = &g_ble_relay_notify_val_handle,
        },
        { 0 }
    };
    static ble_gatt_svc_def gatt_svcs[] = {
        {
            .type = BLE_GATT_SVC_TYPE_PRIMARY,
            .uuid = &BleRelayManager::service_uuid_.u,
            .characteristics = g_ble_relay_characteristics,
        },
        { 0 }
    };

    ble_svc_gap_init();
    ble_svc_gatt_init();
    int rc = ble_gatts_count_cfg(gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_count_cfg failed: %d", rc);
        abort();
    }
    rc = ble_gatts_add_svcs(gatt_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gatts_add_svcs failed: %d", rc);
        abort();
    }
    notify_val_handle_ = 0;

    std::string device_name = std::string(CONFIG_BLE_RELAY_DEVICE_NAME_PREFIX) + "-" + SystemInfo::GetMacAddress().substr(12);
    rc = ble_svc_gap_device_name_set(device_name.c_str());
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_svc_gap_device_name_set failed: %d", rc);
        abort();
    }

    nimble_port_freertos_init(&BleRelayManager::HostTask);
    initialized_ = true;
}

void BleRelayManager::Start() {
    EnsureInitialized();

    std::lock_guard<std::mutex> lock(mutex_);
    LoadStateFromNvs();
    if (!bound_ || force_pairing_) {
        GeneratePairCodeLocked();
        UpdateState(RelayLinkState::kPairing);
    } else {
        UpdateState(RelayLinkState::kAdvertising);
    }
    StartAdvertisingLocked();
}

void BleRelayManager::Stop() {
}

bool BleRelayManager::WaitForReady(int timeout_ms) {
    EventBits_t bits = xEventGroupWaitBits(event_group_, kRelayReadyBit, pdFALSE, pdTRUE,
        timeout_ms == portMAX_DELAY ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms));
    return (bits & kRelayReadyBit) != 0;
}

bool BleRelayManager::SendFrame(BleRelayFrameType type, uint16_t stream_id, uint8_t flags, const std::vector<uint8_t>& payload) {
    return SendFrame(type, stream_id, flags, payload.data(), payload.size());
}

bool BleRelayManager::SendFrame(BleRelayFrameType type, uint16_t stream_id, uint8_t flags, const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lock(mutex_);
    return SendFragmentsLocked(type, stream_id, flags, data, len);
}

bool BleRelayManager::SendJsonFrame(BleRelayFrameType type, uint16_t stream_id, uint8_t flags, const std::string& json) {
    return SendFrame(type, stream_id, flags, reinterpret_cast<const uint8_t*>(json.data()), json.size());
}

void BleRelayManager::RegisterHandler(uint16_t stream_id, BleRelayStreamHandler* handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    stream_handlers_[stream_id] = handler;
}

void BleRelayManager::UnregisterHandler(uint16_t stream_id, BleRelayStreamHandler* handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stream_handlers_.find(stream_id);
    if (it != stream_handlers_.end() && it->second == handler) {
        stream_handlers_.erase(it);
    }
}

RelayLinkState BleRelayManager::GetState() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

bool BleRelayManager::IsConnected() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_ == RelayLinkState::kConnected;
}

bool BleRelayManager::IsBound() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return bound_;
}

bool BleRelayManager::NeedsPairing() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !bound_ || force_pairing_;
}

std::string BleRelayManager::GetPairCode() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pair_code_;
}

std::string BleRelayManager::GetPeerId() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return peer_id_;
}

std::string BleRelayManager::GetSecret() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return secret_;
}

void BleRelayManager::ClearBinding() {
    std::lock_guard<std::mutex> lock(mutex_);
    Settings settings(kConnectivityNamespace, true);
    settings.SetInt(kBleBoundKey, 0);
    settings.SetInt(kBleForcePairingKey, 1);
    settings.EraseKey(kBlePeerIdKey);
    settings.EraseKey(kBleSecretKey);

    bound_ = false;
    force_pairing_ = true;
    peer_id_.clear();
    secret_.clear();
    GeneratePairCodeLocked();
    UpdateState(RelayLinkState::kPairing);
    StartAdvertisingLocked();
    if (pairing_code_callback_) {
        ESP_LOGI(TAG, "Invoking pairing code callback after clearing binding");
        pairing_code_callback_(pair_code_);
    }
}

void BleRelayManager::SetDisconnectCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    disconnect_callback_ = std::move(callback);
}

void BleRelayManager::SetReadyCallback(std::function<void()> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    ready_callback_ = std::move(callback);
}

void BleRelayManager::SetPairingCodeCallback(std::function<void(const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    pairing_code_callback_ = std::move(callback);
}

int BleRelayManager::GetMtu() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return mtu_;
}

void BleRelayManager::LoadStateFromNvs() {
    Settings settings(kConnectivityNamespace, true);
    bound_ = settings.GetInt(kBleBoundKey, 0) == 1;
    force_pairing_ = settings.GetInt(kBleForcePairingKey, 0) == 1;
    peer_id_ = settings.GetString(kBlePeerIdKey);
    secret_ = settings.GetString(kBleSecretKey);
}

void BleRelayManager::SaveBindingLocked() {
    Settings settings(kConnectivityNamespace, true);
    settings.SetInt(kBleBoundKey, bound_ ? 1 : 0);
    settings.SetInt(kBleForcePairingKey, force_pairing_ ? 1 : 0);
    settings.SetString(kBlePeerIdKey, peer_id_);
    settings.SetString(kBleSecretKey, secret_);
}

void BleRelayManager::UpdateState(RelayLinkState state) {
    state_ = state;
    ESP_LOGI(TAG, "Relay state: %s", RelayLinkStateToString(state_));
    if (state_ == RelayLinkState::kConnected) {
        xEventGroupSetBits(event_group_, kRelayConnectedBit | kRelayReadyBit);
    } else {
        xEventGroupClearBits(event_group_, kRelayReadyBit);
        if (state_ == RelayLinkState::kDisconnected || state_ == RelayLinkState::kAdvertising || state_ == RelayLinkState::kPairing) {
            xEventGroupClearBits(event_group_, kRelayConnectedBit);
        }
    }
}

void BleRelayManager::FallbackToPairingLocked(const char* reason) {
    ESP_LOGW(TAG, "Falling back to pairing: %s", reason);
    bound_ = false;
    force_pairing_ = true;
    peer_id_.clear();
    secret_.clear();
    auth_failures_ = 0;
    auth_started_time_us_ = 0;
    GeneratePairCodeLocked();
    SaveBindingLocked();
    UpdateState(RelayLinkState::kPairing);

    if (conn_handle_ != 0xFFFF) {
        SendCurrentHandshakeLocked();
    } else {
        StartAdvertisingLocked();
    }
}

void BleRelayManager::StartAdvertisingLocked() {
    if (!initialized_) {
        return;
    }

    ble_gap_adv_stop();

    // Keep primary advertising payload small and stable:
    // flags + service UUID in ADV, device name in scan response.
    ble_hs_adv_fields adv_fields = {};
    adv_fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    adv_fields.uuids128 = &service_uuid_;
    adv_fields.num_uuids128 = 1;
    adv_fields.uuids128_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&adv_fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: %d", rc);
    }

    ble_hs_adv_fields rsp_fields = {};
    const char* device_name = ble_svc_gap_device_name();
    const size_t device_name_len = strlen(device_name);
    rsp_fields.name = reinterpret_cast<const uint8_t*>(device_name);
    rsp_fields.name_len = device_name_len;
    rsp_fields.name_is_complete = 1;

    rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
    if (rc == BLE_HS_EMSGSIZE) {
        // Scan response payload max is 31 bytes. Name AD structure uses 2 bytes overhead.
        const size_t max_name_len = 29;
        rsp_fields.name_len = std::min(device_name_len, max_name_len);
        rsp_fields.name_is_complete = rsp_fields.name_len == device_name_len;
        rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
    }
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_rsp_set_fields failed: %d", rc);
    }

    ble_gap_adv_params adv_params = {};
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    rc = ble_gap_adv_start(own_addr_type_, nullptr, BLE_HS_FOREVER, &adv_params, &BleRelayManager::GapEvent, this);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_start failed: %d", rc);
        UpdateState(RelayLinkState::kError);
    }
}

void BleRelayManager::RestartAdvertisingLocked() {
    if (!bound_ || force_pairing_) {
        UpdateState(RelayLinkState::kPairing);
    } else {
        UpdateState(RelayLinkState::kAdvertising);
    }
    StartAdvertisingLocked();
}

void BleRelayManager::HandleIncomingData(const uint8_t* data, size_t len) {
    std::vector<std::tuple<BleRelayFrameType, uint8_t, uint16_t, std::vector<uint8_t>>> ready_frames;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        rx_buffer_.insert(rx_buffer_.end(), data, data + len);
        last_rx_time_us_ = esp_timer_get_time();

        while (rx_buffer_.size() >= sizeof(BleRelayFrameHeader)) {
            auto* header = reinterpret_cast<const BleRelayFrameHeader*>(rx_buffer_.data());
            const auto type = static_cast<BleRelayFrameType>(header->type);
            const uint8_t flags = header->flags;
            const uint16_t stream_id = BleRelayReadU16(reinterpret_cast<const uint8_t*>(&header->stream_id));
            const uint16_t seq = BleRelayReadU16(reinterpret_cast<const uint8_t*>(&header->seq));
            const uint16_t payload_len = BleRelayReadU16(reinterpret_cast<const uint8_t*>(&header->len));
            const size_t total_len = sizeof(BleRelayFrameHeader) + payload_len;
            if (rx_buffer_.size() < total_len) {
                break;
            }

            std::vector<uint8_t> payload(payload_len);
            if (payload_len > 0) {
                memcpy(payload.data(), rx_buffer_.data() + sizeof(BleRelayFrameHeader), payload_len);
            }

            if (!RequiresAssembly(type)) {
                ready_frames.emplace_back(
                    type,
                    flags & (kBleRelayFlagEof | kBleRelayFlagError),
                    stream_id,
                    std::move(payload));
            } else {
                const uint32_t key = BuildPendingFrameKey(type, stream_id);
                auto& combined = pending_rx_frames_[key];
                auto& next_seq = pending_rx_next_seq_[key];
                if (!combined.empty() && next_seq != seq) {
                    ESP_LOGW(TAG, "Resetting partial frame buffer: type=%d stream=%u expected_seq=%u got=%u",
                        static_cast<int>(type), static_cast<unsigned>(stream_id),
                        static_cast<unsigned>(next_seq), static_cast<unsigned>(seq));
                    combined.clear();
                }
                combined.insert(combined.end(), payload.begin(), payload.end());
                next_seq = seq + 1;

                const bool is_final = (flags & kBleRelayFlagFinal) != 0;
                const bool legacy_complete = !is_final && IsCompleteJsonPayload(combined);
                if (is_final || legacy_complete) {
                    std::vector<uint8_t> complete_payload = std::move(combined);
                    pending_rx_frames_.erase(key);
                    pending_rx_next_seq_.erase(key);
                    ready_frames.emplace_back(
                        type,
                        flags & (kBleRelayFlagEof | kBleRelayFlagError),
                        stream_id,
                        std::move(complete_payload));
                }
            }
            rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + total_len);
        }
    }

    for (auto& frame : ready_frames) {
        DispatchFrame(std::get<0>(frame), std::get<1>(frame), std::get<2>(frame), std::get<3>(frame).data(), std::get<3>(frame).size());
    }
}

void BleRelayManager::DispatchFrame(BleRelayFrameType type, uint8_t flags, uint16_t stream_id, const uint8_t* data, size_t len) {
    if (type == BleRelayFrameType::kPairResponse) {
        HandlePairResponse(std::string(reinterpret_cast<const char*>(data), len));
        return;
    }
    if (type == BleRelayFrameType::kAuthResponse) {
        HandleAuthResponse(std::string(reinterpret_cast<const char*>(data), len));
        return;
    }
    if (type == BleRelayFrameType::kHeartbeat) {
        HandleHeartbeat();
        return;
    }

    BleRelayStreamHandler* handler = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stream_handlers_.find(stream_id);
        if (it != stream_handlers_.end()) {
            handler = it->second;
        }
    }
    if (handler == nullptr) {
        ESP_LOGW(TAG, "Unhandled stream frame: type=%d stream=%u len=%u", static_cast<int>(type), stream_id, static_cast<unsigned>(len));
        return;
    }

    std::vector<uint8_t> payload(len);
    if (len > 0) {
        memcpy(payload.data(), data, len);
    }
    handler->OnBleRelayFrame(type, flags, payload);
}

void BleRelayManager::HandlePairResponse(const std::string& json) {
    auto* root = cJSON_Parse(json.c_str());
    if (root == nullptr) {
        ESP_LOGE(TAG, "Invalid pair response");
        return;
    }

    auto* pair_code = cJSON_GetObjectItem(root, "pair_code");
    auto* peer_id = cJSON_GetObjectItem(root, "peer_id");
    if (!cJSON_IsString(pair_code) || !cJSON_IsString(peer_id)) {
        cJSON_Delete(root);
        return;
    }

    std::function<void()> ready_cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pair_code_ != pair_code->valuestring) {
            cJSON_Delete(root);
            return;
        }
        peer_id_ = peer_id->valuestring;
        secret_ = GenerateSecretLocked();
        bound_ = true;
        force_pairing_ = false;
        SaveBindingLocked();
        UpdateState(RelayLinkState::kConnected);
        ready_cb = ready_callback_;
    }

    cJSON* response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "ok", true);
    cJSON_AddStringToObject(response, "peer_id", peer_id_.c_str());
    cJSON_AddStringToObject(response, "secret", secret_.c_str());
    char* text = cJSON_PrintUnformatted(response);
    if (text != nullptr) {
        SendJsonFrame(BleRelayFrameType::kPairResponse, 0, 0, text);
        cJSON_free(text);
    }
    cJSON_Delete(response);
    cJSON_Delete(root);

    if (heartbeat_timer_ != nullptr) {
        esp_timer_stop(heartbeat_timer_);
        esp_timer_start_periodic(heartbeat_timer_, 5000000);
    }
    if (ready_cb) {
        ready_cb();
    }
}

void BleRelayManager::HandleAuthResponse(const std::string& json) {
    auto* root = cJSON_Parse(json.c_str());
    if (root == nullptr) {
        ESP_LOGE(TAG, "Invalid auth response");
        return;
    }

    auto* peer_id = cJSON_GetObjectItem(root, "peer_id");
    auto* nonce = cJSON_GetObjectItem(root, "nonce");
    auto* proof = cJSON_GetObjectItem(root, "proof");
    if (!cJSON_IsString(peer_id) || !cJSON_IsString(nonce) || !cJSON_IsString(proof)) {
        cJSON_Delete(root);
        return;
    }

    bool accepted = false;
    bool fallback_to_pairing = false;
    std::string fallback_reason;
    std::function<void()> ready_cb;
    std::function<void()> disconnect_cb;
    std::function<void(const std::string&)> pairing_code_cb;
    std::string pair_code;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::string expected = ComputeProof(nonce->valuestring);
        accepted = bound_ && peer_id_ == peer_id->valuestring && expected == proof->valuestring;
        if (accepted) {
            auth_failures_ = 0;
            auth_started_time_us_ = 0;
            UpdateState(RelayLinkState::kConnected);
            ready_cb = ready_callback_;
        } else {
            auth_failures_++;
            disconnect_cb = disconnect_callback_;
            fallback_to_pairing = true;
            fallback_reason = "auth response rejected";
            FallbackToPairingLocked(fallback_reason.c_str());
            pairing_code_cb = pairing_code_callback_;
            pair_code = pair_code_;
        }
    }

    cJSON* response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "ok", accepted);
    char* text = cJSON_PrintUnformatted(response);
    if (text != nullptr) {
        SendJsonFrame(BleRelayFrameType::kAuthResponse, 0, accepted ? 0 : kBleRelayFlagError, text);
        cJSON_free(text);
    }
    cJSON_Delete(response);
    cJSON_Delete(root);

    if (accepted) {
        if (heartbeat_timer_ != nullptr) {
            esp_timer_stop(heartbeat_timer_);
            esp_timer_start_periodic(heartbeat_timer_, 5000000);
        }
        if (ready_cb) {
            ready_cb();
        }
        return;
    }

    if (disconnect_cb) {
        disconnect_cb();
    }
    if (fallback_to_pairing && pairing_code_cb && !pair_code.empty()) {
        pairing_code_cb(pair_code);
    }
}

void BleRelayManager::HandleHeartbeat() {
    last_rx_time_us_ = esp_timer_get_time();
}

void BleRelayManager::NotifyHandlersDisconnectedLocked() {
    pending_rx_frames_.clear();
    pending_rx_next_seq_.clear();
    for (const auto& entry : stream_handlers_) {
        if (entry.second != nullptr) {
            entry.second->OnBleRelayDisconnected();
        }
    }
}

void BleRelayManager::SendCurrentHandshakeLocked() {
    cJSON* root = cJSON_CreateObject();
    if (!bound_ || force_pairing_) {
        ESP_LOGI(TAG, "Sending pair request to app");
        cJSON_AddStringToObject(root, "pair_code", pair_code_.c_str());
        cJSON_AddStringToObject(root, "device_id", SystemInfo::GetMacAddress().c_str());
        cJSON_AddStringToObject(root, "client_id", Board::GetInstance().GetUuid().c_str());
        char* text = cJSON_PrintUnformatted(root);
        if (text != nullptr) {
            SendFragmentsLocked(BleRelayFrameType::kPairRequest, 0, 0,
                reinterpret_cast<const uint8_t*>(text), strlen(text));
            cJSON_free(text);
        }
    } else {
        ESP_LOGI(TAG, "Sending auth request to app for peer_id=%s", peer_id_.c_str());
        auth_started_time_us_ = esp_timer_get_time();
        cJSON_AddStringToObject(root, "peer_id", peer_id_.c_str());
        char* text = cJSON_PrintUnformatted(root);
        if (text != nullptr) {
            SendFragmentsLocked(BleRelayFrameType::kAuthRequest, 0, 0,
                reinterpret_cast<const uint8_t*>(text), strlen(text));
            cJSON_free(text);
        }
    }
    cJSON_Delete(root);
}

std::string BleRelayManager::GeneratePairCodeLocked() {
    pair_code_.clear();
    for (int i = 0; i < 6; ++i) {
        pair_code_.push_back(static_cast<char>('0' + (esp_random() % 10)));
    }
    return pair_code_;
}

std::string BleRelayManager::GenerateSecretLocked() {
    uint8_t random_bytes[16];
    esp_fill_random(random_bytes, sizeof(random_bytes));
    static const char* kHex = "0123456789abcdef";
    std::string secret;
    secret.reserve(sizeof(random_bytes) * 2);
    for (uint8_t byte : random_bytes) {
        secret.push_back(kHex[(byte >> 4) & 0x0F]);
        secret.push_back(kHex[byte & 0x0F]);
    }
    return secret;
}

std::string BleRelayManager::ComputeProof(const std::string& nonce) const {
    std::string material = secret_ + ":" + nonce;
    uint8_t digest[32];
    mbedtls_sha256(reinterpret_cast<const unsigned char*>(material.data()), material.size(), digest, 0);
    static const char* kHex = "0123456789abcdef";
    std::string proof;
    proof.reserve(sizeof(digest) * 2);
    for (uint8_t byte : digest) {
        proof.push_back(kHex[(byte >> 4) & 0x0F]);
        proof.push_back(kHex[byte & 0x0F]);
    }
    return proof;
}

bool BleRelayManager::SendFragmentsLocked(BleRelayFrameType type, uint16_t stream_id, uint8_t flags, const uint8_t* data, size_t len) {
    if (conn_handle_ == 0xFFFF || notify_val_handle_ == 0) {
        return false;
    }

    const size_t mtu_payload = std::min(static_cast<size_t>(kBleRelayFramePayloadMax),
        static_cast<size_t>(std::max(20, mtu_ - 3 - static_cast<int>(sizeof(BleRelayFrameHeader)))));

    if (len == 0) {
        auto frame = BleRelayBuildFrame(type, flags | kBleRelayFlagFinal, stream_id, next_seq_++, nullptr, 0);
        struct os_mbuf* om = ble_hs_mbuf_from_flat(frame.data(), frame.size());
        return om != nullptr && ble_gatts_notify_custom(conn_handle_, notify_val_handle_, om) == 0;
    }

    size_t offset = 0;
    while (offset < len) {
        const size_t chunk_len = std::min(mtu_payload, len - offset);
        const uint8_t chunk_flags = (offset + chunk_len >= len) ? (flags | kBleRelayFlagFinal) : 0;
        auto frame = BleRelayBuildFrame(type, chunk_flags, stream_id, next_seq_++, data + offset, chunk_len);
        struct os_mbuf* om = ble_hs_mbuf_from_flat(frame.data(), frame.size());
        if (om == nullptr) {
            return false;
        }
        const int rc = ble_gatts_notify_custom(conn_handle_, notify_val_handle_, om);
        if (rc != 0) {
            ESP_LOGE(TAG, "Notify failed: %d", rc);
            return false;
        }
        offset += chunk_len;
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    return true;
}

void BleRelayManager::HostTask(void* param) {
    nimble_port_run();
    nimble_port_freertos_deinit();
}

int BleRelayManager::GapEvent(ble_gap_event* event, void* arg) {
    auto* relay = static_cast<BleRelayManager*>(arg);
    std::function<void()> disconnect_cb;
    std::function<void(const std::string&)> pairing_code_cb;
    std::string pair_code;

    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT: {
            std::lock_guard<std::mutex> lock(relay->mutex_);
            if (event->connect.status == 0) {
                relay->conn_handle_ = event->connect.conn_handle;
                relay->mtu_ = 23;
                relay->auth_failures_ = 0;
                relay->last_rx_time_us_ = esp_timer_get_time();
                relay->auth_started_time_us_ = 0;
                relay->UpdateState(relay->bound_ && !relay->force_pairing_ ? RelayLinkState::kAuthenticating : RelayLinkState::kPairing);
                if (!relay->bound_ || relay->force_pairing_) {
                    pairing_code_cb = relay->pairing_code_callback_;
                    pair_code = relay->pair_code_;
                }
                relay->SendCurrentHandshakeLocked();
            } else {
                relay->RestartAdvertisingLocked();
            }
            break;
        }
        case BLE_GAP_EVENT_DISCONNECT: {
            std::lock_guard<std::mutex> lock(relay->mutex_);
            relay->conn_handle_ = 0xFFFF;
            relay->mtu_ = 23;
            relay->auth_started_time_us_ = 0;
            relay->UpdateState(RelayLinkState::kDisconnected);
            relay->NotifyHandlersDisconnectedLocked();
            disconnect_cb = relay->disconnect_callback_;
            relay->RestartAdvertisingLocked();
            break;
        }
        case BLE_GAP_EVENT_MTU: {
            std::lock_guard<std::mutex> lock(relay->mutex_);
            relay->mtu_ = event->mtu.value;
            break;
        }
        case BLE_GAP_EVENT_SUBSCRIBE: {
            std::lock_guard<std::mutex> lock(relay->mutex_);
            if (event->subscribe.attr_handle == relay->notify_val_handle_ && event->subscribe.cur_notify) {
                ESP_LOGI(TAG, "Notify subscribed by app, sending handshake");
                if (!relay->bound_ || relay->force_pairing_) {
                    pairing_code_cb = relay->pairing_code_callback_;
                    pair_code = relay->pair_code_;
                }
                relay->SendCurrentHandshakeLocked();
            }
            break;
        }
        default:
            break;
    }

    if (disconnect_cb) {
        disconnect_cb();
    }
    if (pairing_code_cb && !pair_code.empty()) {
        ESP_LOGI(TAG, "Replaying pairing code after BLE handshake event");
        pairing_code_cb(pair_code);
    }
    return 0;
}

void BleRelayManager::OnSync() {
    auto& relay = GetInstance();
    std::lock_guard<std::mutex> lock(relay.mutex_);
    int rc = ble_hs_id_infer_auto(0, &relay.own_addr_type_);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: %d", rc);
        relay.UpdateState(RelayLinkState::kError);
        return;
    }
    relay.StartAdvertisingLocked();
}

void BleRelayManager::OnReset(int reason) {
    ESP_LOGE(TAG, "NimBLE reset reason=%d", reason);
}

int BleRelayManager::GattAccessNotify(uint16_t conn_handle, uint16_t attr_handle, ble_gatt_access_ctxt* ctxt, void* arg) {
    switch (ctxt->op) {
        case BLE_GATT_ACCESS_OP_READ_CHR:
            return BLE_ATT_ERR_READ_NOT_PERMITTED;
        case BLE_GATT_ACCESS_OP_WRITE_CHR:
            return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
        default:
            return BLE_ATT_ERR_UNLIKELY;
    }
}

int BleRelayManager::GattAccessWrite(uint16_t conn_handle, uint16_t attr_handle, ble_gatt_access_ctxt* ctxt, void* arg) {
    std::vector<uint8_t> data(OS_MBUF_PKTLEN(ctxt->om));
    if (!data.empty()) {
        os_mbuf_copydata(ctxt->om, 0, data.size(), data.data());
    }
    GetInstance().HandleIncomingData(data.data(), data.size());
    return 0;
}

void BleRelayManager::GattRegister(ble_gatt_register_ctxt* ctxt, void* arg) {
    if (ctxt->op == BLE_GATT_REGISTER_OP_CHR &&
        ble_uuid_cmp(ctxt->chr.chr_def->uuid, &device_to_app_uuid_.u) == 0) {
        auto& relay = GetInstance();
        std::lock_guard<std::mutex> lock(relay.mutex_);
        relay.notify_val_handle_ = ctxt->chr.val_handle;
        ESP_LOGI(TAG, "Registered notify characteristic handle=%u", relay.notify_val_handle_);
    }
}

void BleRelayManager::HeartbeatTimer(void* arg) {
    auto* relay = static_cast<BleRelayManager*>(arg);
    std::function<void()> disconnect_cb;
    std::function<void(const std::string&)> pairing_code_cb;
    std::string pair_code;

    {
        std::lock_guard<std::mutex> lock(relay->mutex_);
        if (relay->conn_handle_ == 0xFFFF) {
            return;
        }

        const int64_t now = esp_timer_get_time();
        if (relay->state_ == RelayLinkState::kAuthenticating &&
            relay->auth_started_time_us_ != 0 &&
            now - relay->auth_started_time_us_ > 10000000) {
            relay->FallbackToPairingLocked("authentication timeout");
            pairing_code_cb = relay->pairing_code_callback_;
            pair_code = relay->pair_code_;
            return;
        }
        if (relay->last_rx_time_us_ != 0 && now - relay->last_rx_time_us_ > 15000000) {
            ble_gap_terminate(relay->conn_handle_, BLE_ERR_REM_USER_CONN_TERM);
            relay->conn_handle_ = 0xFFFF;
            relay->auth_started_time_us_ = 0;
            relay->UpdateState(RelayLinkState::kDisconnected);
            relay->NotifyHandlersDisconnectedLocked();
            disconnect_cb = relay->disconnect_callback_;
            relay->RestartAdvertisingLocked();
            if (disconnect_cb) {
                disconnect_cb();
            }
            return;
        }
    }

    if (pairing_code_cb && !pair_code.empty()) {
        pairing_code_cb(pair_code);
        return;
    }
    relay->SendJsonFrame(BleRelayFrameType::kHeartbeat, 0, 0, "{}");
}
