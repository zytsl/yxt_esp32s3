#include "ble_relay_manager.h"

#include "application.h"
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
#include <host/ble_store.h>
#include <mbedtls/base64.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
extern "C" {
#include <mbedtls/constant_time.h>
}
#include <nimble/nimble_port.h>
#include <nimble/nimble_port_freertos.h>
#include <os/os_mbuf.h>
#include <services/gap/ble_svc_gap.h>
#include <services/gatt/ble_svc_gatt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <tuple>

#define TAG "BleRelay"

extern "C" void ble_store_config_init(void);

#ifndef CONFIG_BLE_RELAY_DEVICE_NAME_PREFIX
#define CONFIG_BLE_RELAY_DEVICE_NAME_PREFIX "XiaoTun"
#endif

namespace {
constexpr EventBits_t kRelayReadyBit = 1 << 0;
constexpr EventBits_t kRelayConnectedBit = 1 << 1;

constexpr const char* kConnectivityNamespace = "connectivity";
constexpr const char* kBlePeerIdKey = "ble_peer_id";
constexpr const char* kBleSecretKey = "ble_secret";
constexpr const char* kBleBoundKey = "ble_bound";
constexpr const char* kBleForcePairingKey = "force_ble_pair";
constexpr const char* kBleTransportFloorKey = "ble_tx_floor";
// 用户自定义设备名（昵称）：广播名固定为 "<XiaoTun>-<custom>"，保留前缀供 App 扫描过滤。
constexpr const char* kBleCustomNameKey = "ble_custom_name";
// 扫描响应包名字段上限 29 字节，扣除前缀 "XiaoTun-" 后的安全上限。
constexpr size_t kMaxCustomNameBytes = 18;
uint16_t g_ble_relay_notify_val_handle = 0;
constexpr int kBleAuthProtocolVersion = 2;
constexpr const char* kBleAuthScheme = "hmac-sha256-v2";
constexpr int64_t kBleAuthChallengeTtlUs = 10000000;
constexpr int64_t kBlePairReceiptTtlUs = 10000000;
constexpr int kBleTransportSchema = 1;
constexpr int kBleTransportVersion = 2;
constexpr int kBleTransportInitialWindow = 8;
constexpr int kBleTransportMaxWindow = 32;
constexpr int kBleTransportMaxInflightRequests = 8;
constexpr int kBleTransportMaxFragments = 4096;
constexpr int kBleTransportMaxMessageBytes = 65535;
constexpr int64_t kBleTransportNegotiationTtlUs = 5000000;
constexpr int64_t kBleTransportInvalidHeaderWindowUs = 2000000;
constexpr uint8_t kBleTransportInvalidHeaderLimit = 8;
constexpr int64_t kBleTransportRouteTombstoneTtlUs = 30000000;
constexpr size_t kBleTransportRouteTombstonesMax = 64;

bool IsValidAuthId(const std::string& value) {
    if (value.empty() || value.size() > 64) return false;
    return std::none_of(value.begin(), value.end(), [](unsigned char c) { return c < 0x20 || c == 0x7f; });
}

// 自定义设备名：UTF-8 可见字符，不允许控制字符与 NUL（高位字节 ≥0x80 为 UTF-8 续字节，放行）。
bool IsValidCustomName(const std::string& value) {
    if (value.empty() || value.size() > kMaxCustomNameBytes) return false;
    return std::none_of(value.begin(), value.end(), [](unsigned char c) { return c < 0x20 || c == 0x7f; });
}

bool AddJsonString(cJSON* object, const char* key, const std::string& value) {
    return object != nullptr && cJSON_AddStringToObject(object, key, value.c_str()) != nullptr;
}

bool AddJsonNumber(cJSON* object, const char* key, double value) {
    return object != nullptr && cJSON_AddNumberToObject(object, key, value) != nullptr;
}

bool AddJsonBool(cJSON* object, const char* key, bool value) {
    return object != nullptr && cJSON_AddBoolToObject(object, key, value) != nullptr;
}

bool AddJsonIntArray(cJSON* object, const char* key, int first, int last) {
    cJSON* array = cJSON_CreateArray();
    if (array == nullptr) return false;
    for (int value = first; value <= last; ++value) {
        cJSON* item = cJSON_CreateNumber(value);
        if (item == nullptr || !cJSON_AddItemToArray(array, item)) {
            if (item != nullptr) cJSON_Delete(item);
            cJSON_Delete(array);
            return false;
        }
    }
    if (!cJSON_AddItemToObject(object, key, array)) {
        cJSON_Delete(array);
        return false;
    }
    return true;
}

bool AddJsonStringArray(cJSON* object, const char* key, const char* const* values, size_t count) {
    cJSON* array = cJSON_CreateArray();
    if (array == nullptr) return false;
    for (size_t index = 0; index < count; ++index) {
        cJSON* item = cJSON_CreateString(values[index]);
        if (item == nullptr || !cJSON_AddItemToArray(array, item)) {
            if (item != nullptr) cJSON_Delete(item);
            cJSON_Delete(array);
            return false;
        }
    }
    if (!cJSON_AddItemToObject(object, key, array)) {
        cJSON_Delete(array);
        return false;
    }
    return true;
}

bool JsonIntInRange(const cJSON* object, const char* key, int minimum, int maximum, int* output) {
    const cJSON* item = cJSON_GetObjectItemCaseSensitive(object, key);
    if (!cJSON_IsNumber(item) || item->valuedouble != item->valueint ||
        item->valueint < minimum || item->valueint > maximum) {
        return false;
    }
    if (output != nullptr) *output = item->valueint;
    return true;
}

bool JsonStringArrayContainsAll(const cJSON* object, const char* key,
    const char* const* required, size_t required_count) {
    const cJSON* array = cJSON_GetObjectItemCaseSensitive(object, key);
    if (!cJSON_IsArray(array)) return false;
    for (size_t required_index = 0; required_index < required_count; ++required_index) {
        bool found = false;
        const cJSON* item = nullptr;
        cJSON_ArrayForEach(item, array) {
            if (!cJSON_IsString(item)) return false;
            if (std::strcmp(item->valuestring, required[required_index]) == 0) found = true;
        }
        if (!found) return false;
    }
    return true;
}

std::string PayloadToString(const std::vector<uint8_t>& payload) {
    return payload.empty() ? std::string() :
        std::string(reinterpret_cast<const char*>(payload.data()), payload.size());
}

bool DecodeHexSecret(const std::string& value, std::vector<uint8_t>* output) {
    if (value.size() != 32 && value.size() != 64) return false;
    output->clear();
    output->reserve(value.size() / 2);
    auto nibble = [](char c) -> int { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
    for (size_t i = 0; i < value.size(); i += 2) {
        int high = nibble(value[i]);
        int low = nibble(value[i + 1]);
        if (high < 0 || low < 0) return false;
        output->push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return true;
}

std::string Base64UrlEncode(const uint8_t* data, size_t size) {
    std::vector<uint8_t> encoded(4 * ((size + 2) / 3) + 1);
    size_t written = 0;
    if (mbedtls_base64_encode(encoded.data(), encoded.size(), &written, data, size) != 0) return {};
    std::string value(reinterpret_cast<char*>(encoded.data()), written);
    std::replace(value.begin(), value.end(), '+', '-');
    std::replace(value.begin(), value.end(), '/', '_');
    while (!value.empty() && value.back() == '=') value.pop_back();
    return value;
}

bool Base64UrlDecodeExact(const std::string& value, uint8_t* output, size_t expected_size) {
    if (value.empty() || value.find('=') != std::string::npos ||
        std::any_of(value.begin(), value.end(), [](unsigned char c) {
            return !(std::isalnum(c) || c == '-' || c == '_');
        })) return false;
    std::string padded = value;
    std::replace(padded.begin(), padded.end(), '-', '+');
    std::replace(padded.begin(), padded.end(), '_', '/');
    while (padded.size() % 4 != 0) padded.push_back('=');
    size_t written = 0;
    return mbedtls_base64_decode(output, expected_size, &written,
        reinterpret_cast<const uint8_t*>(padded.data()), padded.size()) == 0 && written == expected_size;
}

void AppendLp16(std::vector<uint8_t>* output, const uint8_t* data, size_t size) {
    output->push_back(static_cast<uint8_t>((size >> 8) & 0xff));
    output->push_back(static_cast<uint8_t>(size & 0xff));
    output->insert(output->end(), data, data + size);
}

void AppendLp16(std::vector<uint8_t>* output, const std::string& value) {
    AppendLp16(output, reinterpret_cast<const uint8_t*>(value.data()), value.size());
}

bool ComputeAuthProofV2(const std::string& secret_hex, const std::string& peer_id,
    const std::string& device_id, const std::string& client_id,
    const uint8_t* session_id, const uint8_t* device_nonce, const uint8_t* app_nonce,
    std::array<uint8_t, 32>* proof) {
    if (!IsValidAuthId(peer_id) || !IsValidAuthId(device_id) || !IsValidAuthId(client_id)) return false;
    std::vector<uint8_t> key;
    if (!DecodeHexSecret(secret_hex, &key)) return false;
    static constexpr char kDomain[] = "AnimoDollBleAuth";
    std::vector<uint8_t> transcript(kDomain, kDomain + sizeof(kDomain) - 1);
    transcript.push_back(kBleAuthProtocolVersion);
    transcript.push_back(1);
    AppendLp16(&transcript, peer_id);
    AppendLp16(&transcript, device_id);
    AppendLp16(&transcript, client_id);
    AppendLp16(&transcript, session_id, 16);
    AppendLp16(&transcript, device_nonce, 32);
    AppendLp16(&transcript, app_nonce, 32);
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    const int rc = info == nullptr ? -1 : mbedtls_md_hmac(info, key.data(), key.size(),
        transcript.data(), transcript.size(), proof->data());
    mbedtls_platform_zeroize(key.data(), key.size());
    mbedtls_platform_zeroize(transcript.data(), transcript.size());
    return rc == 0;
}

bool ComputePairReceipt(const std::string& secret_hex, const std::string& peer_id,
    const std::string& receipt_id, std::array<uint8_t, 32>* proof) {
    if (!IsValidAuthId(peer_id) || receipt_id.empty() || receipt_id.size() > 64) return false;
    std::vector<uint8_t> key;
    if (!DecodeHexSecret(secret_hex, &key)) return false;
    const std::string domain = "AnimoDollPairReceipt";
    std::vector<uint8_t> transcript(domain.begin(), domain.end());
    AppendLp16(&transcript, peer_id);
    AppendLp16(&transcript, receipt_id);
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    const int rc = info == nullptr ? -1 : mbedtls_md_hmac(info, key.data(), key.size(),
        transcript.data(), transcript.size(), proof->data());
    mbedtls_platform_zeroize(key.data(), key.size());
    mbedtls_platform_zeroize(transcript.data(), transcript.size());
    return rc == 0;
}

uint64_t BuildPendingFrameKey(BleRelayFrameType type, uint16_t stream_id, uint32_t request_id) {
    return (static_cast<uint64_t>(static_cast<uint8_t>(type)) << 48) |
        (static_cast<uint64_t>(stream_id) << 32) | request_id;
}

uint64_t BuildRequestHandlerKey(uint16_t stream_id, uint32_t request_id) {
    return (static_cast<uint64_t>(stream_id) << 32) | request_id;
}

bool RequiresAssembly(BleRelayFrameType type) {
    switch (type) {
        case BleRelayFrameType::kPairResponse:
        case BleRelayFrameType::kAuthResponse:
        case BleRelayFrameType::kHeartbeat:
        case BleRelayFrameType::kHttpResult:
        case BleRelayFrameType::kSocketEvent:
            return true;
        case BleRelayFrameType::kPairRequest:
        case BleRelayFrameType::kAuthRequest:
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
ble_uuid128_t BleRelayManager::device_name_uuid_ =
    BLE_UUID128_INIT(0x54, 0x4b, 0x2d, 0xe8, 0xb4, 0x7f, 0x58, 0x9a, 0x6f, 0x4c, 0x2d, 0xb1, 0x0f, 0x6f, 0x2e, 0x7b);

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
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_DISPLAY_ONLY;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 1;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;

    static ble_gatt_chr_def g_ble_relay_characteristics[] = {
        {
            .uuid = &BleRelayManager::app_to_device_uuid_.u,
            .access_cb = BleRelayManager::GattAccessWrite,
            .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP |
                BLE_GATT_CHR_F_WRITE_AUTHEN,
        },
        {
            .uuid = &BleRelayManager::device_to_app_uuid_.u,
            .access_cb = BleRelayManager::GattAccessNotify,
            .flags = BLE_GATT_CHR_F_NOTIFY | BLE_GATT_CHR_F_NOTIFY_INDICATE_AUTHEN,
            .val_handle = &g_ble_relay_notify_val_handle,
        },
        {
            .uuid = &BleRelayManager::device_name_uuid_.u,
            .access_cb = BleRelayManager::GattAccessDeviceName,
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_AUTHEN,
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

    if (!IsValidCustomName(custom_name_)) {
        custom_name_.clear();
    }
    std::string device_name = std::string(CONFIG_BLE_RELAY_DEVICE_NAME_PREFIX) + "-" +
        (custom_name_.empty() ? SystemInfo::GetMacAddress().substr(12) : custom_name_);
    rc = ble_svc_gap_device_name_set(device_name.c_str());
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_svc_gap_device_name_set failed: %d", rc);
        abort();
    }

    ble_store_config_init();
    nimble_port_freertos_init(&BleRelayManager::HostTask);
    initialized_ = true;
}

void BleRelayManager::Start() {
    EnsureInitialized();

    std::lock_guard<std::mutex> lock(mutex_);
    running_ = true;
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
    uint16_t conn_handle = 0xFFFF;
    bool notify_disconnected = false;
    std::function<void()> disconnect_cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) return;
        running_ = false;
        if (heartbeat_timer_ != nullptr) esp_timer_stop(heartbeat_timer_);
        ble_gap_adv_stop();
        conn_handle = conn_handle_;
        notify_disconnected = conn_handle != 0xFFFF;
        conn_handle_ = 0xFFFF;
        connection_generation_.fetch_add(1, std::memory_order_release);
        mtu_ = 23;
        notify_subscribed_ = false;
        auth_started_time_us_ = 0;
        auth_challenge_active_ = false;
        auth_challenge_consumed_ = false;
        pending_pair_peer_id_.clear();
        pending_pair_secret_.clear();
        pending_pair_receipt_id_.clear();
        pending_pair_conn_handle_ = 0xFFFF;
        pending_pair_started_time_us_ = 0;
        ClearReceiveStateLocked();
        UpdateState(RelayLinkState::kDisabled);
        if (notify_disconnected) disconnect_cb = disconnect_callback_;
    }
    if (conn_handle != 0xFFFF) {
        ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }
    if (notify_disconnected) {
        NotifyHandlersDisconnected();
        if (disconnect_cb) disconnect_cb();
    }
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
    return SendFragments(type, stream_id, 0, flags, data, len);
}

bool BleRelayManager::SendJsonFrame(BleRelayFrameType type, uint16_t stream_id, uint8_t flags, const std::string& json) {
    return SendFrame(type, stream_id, flags, reinterpret_cast<const uint8_t*>(json.data()), json.size());
}

bool BleRelayManager::SendRequestFrame(BleRelayFrameType type, uint16_t stream_id, uint32_t request_id,
    uint8_t flags, const uint8_t* data, size_t len) {
    return SendFragments(type, stream_id, request_id, flags, data, len);
}

bool BleRelayManager::SendRequestJsonFrame(BleRelayFrameType type, uint16_t stream_id, uint32_t request_id,
    uint8_t flags, const std::string& json) {
    return SendRequestFrame(type, stream_id, request_id, flags,
        reinterpret_cast<const uint8_t*>(json.data()), json.size());
}

bool BleRelayManager::RegisterHandler(uint16_t stream_id, BleRelayStreamHandler* handler) {
    if (handler == nullptr) return false;
    std::lock_guard<std::recursive_mutex> callback_lock(handler_callback_mutex_);
    std::lock_guard<std::mutex> lock(mutex_);
    auto existing = stream_handlers_.find(stream_id);
    if (existing != stream_handlers_.end()) {
        return existing->second == handler;
    }
    if (stream_handlers_.size() >= kBleRelayStreamHandlersMax) {
        ESP_LOGE(TAG, "Rejecting stream handler beyond hard limit stream=%u", stream_id);
        return false;
    }
    stream_handlers_[stream_id] = handler;
    return true;
}

bool BleRelayManager::RegisterRequestHandler(uint16_t stream_id, uint32_t request_id,
    BleRelayStreamHandler* handler) {
    if (handler == nullptr || request_id == 0) return false;
    std::lock_guard<std::recursive_mutex> callback_lock(handler_callback_mutex_);
    std::lock_guard<std::mutex> lock(mutex_);
    const uint64_t key = BuildRequestHandlerKey(stream_id, request_id);
    auto existing = request_handlers_.find(key);
    if (existing != request_handlers_.end()) return existing->second == handler;
    const size_t request_limit = transport_v2_active_
        ? std::min<size_t>(transport_max_inflight_requests_, kBleRelayStreamHandlersMax)
        : kBleRelayStreamHandlersMax;
    if (request_handlers_.size() >= request_limit) return false;
    request_handlers_[key] = handler;
    return true;
}

void BleRelayManager::UnregisterHandler(uint16_t stream_id, BleRelayStreamHandler* handler) {
    std::lock_guard<std::recursive_mutex> callback_barrier(handler_callback_mutex_);
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stream_handlers_.find(stream_id);
    if (it != stream_handlers_.end() && it->second == handler) {
        stream_handlers_.erase(it);
    }
}

void BleRelayManager::UnregisterRequestHandler(uint16_t stream_id, uint32_t request_id,
    BleRelayStreamHandler* handler) {
    const uint64_t route = BuildRequestHandlerKey(stream_id, request_id);
    bool removed = false;
    std::lock_guard<std::recursive_mutex> callback_barrier(handler_callback_mutex_);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = request_handlers_.find(route);
        if (it != request_handlers_.end() && it->second == handler) {
            request_handlers_.erase(it);
            v2_tx_sequence_.erase(route);
            const auto expected = v2_rx_expected_sequence_.find(route);
            if (expected != v2_rx_expected_sequence_.end()) {
                const int64_t now = esp_timer_get_time();
                v2_route_tombstones_[route] = V2RouteTombstone{
                    static_cast<uint16_t>(expected->second - 1),
                    now + kBleTransportRouteTombstoneTtlUs};
                v2_rx_expected_sequence_.erase(expected);
                while (v2_route_tombstones_.size() > kBleTransportRouteTombstonesMax) {
                    const auto oldest = std::min_element(
                        v2_route_tombstones_.begin(), v2_route_tombstones_.end(),
                        [](const auto& left, const auto& right) {
                            return left.second.expires_at_us < right.second.expires_at_us;
                        });
                    v2_route_tombstones_.erase(oldest);
                }
            }
            removed = true;
        }
    }
    if (removed) {
        std::lock_guard<std::mutex> ack_lock(v2_ack_mutex_);
        v2_latest_ack_.erase(route);
    }
}

uint32_t BleRelayManager::AllocateRequestId() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!transport_v2_active_ || next_request_id_ == 0 || next_request_id_ == UINT32_MAX) return 0;
    return next_request_id_++;
}

bool BleRelayManager::IsTransportV2() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return transport_v2_active_;
}

uint16_t BleRelayManager::GetTransportSessionEpoch() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return transport_v2_active_ ? transport_session_epoch_ : 0;
}

void BleRelayManager::RefreshReceiveCredit(uint16_t stream_id, uint32_t request_id) {
    if (request_id == 0) return;
    BleRelayEnvelope envelope;
    uint16_t acknowledged_seq = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!transport_v2_active_) return;
        const auto expected = v2_rx_expected_sequence_.find(BuildRequestHandlerKey(stream_id, request_id));
        if (expected == v2_rx_expected_sequence_.end()) return;
        envelope.session_epoch = transport_session_epoch_;
        envelope.stream_id = stream_id;
        envelope.request_id = request_id;
        acknowledged_seq = static_cast<uint16_t>(expected->second - 1);
    }
    SendV2Ack(envelope, acknowledged_seq);
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
    const int store_rc = ble_store_clear();
    if (store_rc != 0) {
        ESP_LOGE(TAG, "Refusing to clear app binding because BLE bond store clear failed: %d", store_rc);
        return;
    }
    std::function<void(const std::string&)> pairing_code_cb;
    std::string pair_code;
    uint16_t terminate_handle = 0xFFFF;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        Settings settings(kConnectivityNamespace, true);
        settings.SetInt(kBleBoundKey, 0);
        settings.SetInt(kBleForcePairingKey, 1);
        settings.SetInt(kBleTransportFloorKey, 1);
        settings.EraseKey(kBlePeerIdKey);
        settings.EraseKey(kBleSecretKey);

        bound_ = false;
        force_pairing_ = true;
        transport_floor_ = 1;
        peer_id_.clear();
        secret_.clear();
        pending_pair_peer_id_.clear();
        pending_pair_secret_.clear();
        pending_pair_receipt_id_.clear();
        pending_pair_conn_handle_ = 0xFFFF;
        pending_pair_started_time_us_ = 0;
        pair_code = GeneratePairCodeLocked();
        UpdateState(RelayLinkState::kPairing);
        terminate_handle = conn_handle_;
        if (terminate_handle == 0xFFFF) StartAdvertisingLocked();
        pairing_code_cb = pairing_code_callback_;
    }
    if (terminate_handle != 0xFFFF) {
        const int rc = ble_gap_terminate(terminate_handle, BLE_ERR_REM_USER_CONN_TERM);
        if (rc != 0) {
            ESP_LOGE(TAG, "Failed to terminate connection while clearing binding: %d", rc);
            std::lock_guard<std::mutex> lock(mutex_);
            if (conn_handle_ == terminate_handle) UpdateState(RelayLinkState::kError);
        }
    }
    if (pairing_code_cb) {
        ESP_LOGI(TAG, "Invoking pairing code callback after clearing binding");
        pairing_code_cb(pair_code);
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
    transport_floor_ = static_cast<uint8_t>(std::max<int32_t>(1, settings.GetInt(kBleTransportFloorKey, 1)));
    peer_id_ = settings.GetString(kBlePeerIdKey);
    secret_ = settings.GetString(kBleSecretKey);
    custom_name_ = settings.GetString(kBleCustomNameKey);
}

void BleRelayManager::SaveBindingLocked() {
    Settings settings(kConnectivityNamespace, true);
    settings.SetInt(kBleBoundKey, bound_ ? 1 : 0);
    settings.SetInt(kBleForcePairingKey, force_pairing_ ? 1 : 0);
    settings.SetInt(kBleTransportFloorKey, transport_floor_);
    settings.SetString(kBlePeerIdKey, peer_id_);
    settings.SetString(kBleSecretKey, secret_);
}

void BleRelayManager::UpdateState(RelayLinkState state) {
    state_ = state;
    ESP_LOGI(TAG, "Relay state: %s", RelayLinkStateToString(state_));
    if (state_ == RelayLinkState::kConnected) {
        xEventGroupSetBits(event_group_, kRelayConnectedBit);
        if (!transport_accepted_ || transport_v2_active_) {
            xEventGroupSetBits(event_group_, kRelayReadyBit);
        } else {
            xEventGroupClearBits(event_group_, kRelayReadyBit);
        }
    } else {
        xEventGroupClearBits(event_group_, kRelayConnectedBit | kRelayReadyBit);
    }
}

void BleRelayManager::RejectAuthenticationLocked(const char* reason) {
    ESP_LOGW(TAG, "Rejecting current authentication without changing binding: %s", reason);
    auth_failures_++;
    auth_started_time_us_ = 0;
    auth_challenge_active_ = false;
    auth_challenge_consumed_ = true;
    UpdateState(RelayLinkState::kError);
}

void BleRelayManager::StartAdvertisingLocked() {
    if (!initialized_ || !running_) {
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
    if (!running_) return;
    if (!bound_ || force_pairing_) {
        UpdateState(RelayLinkState::kPairing);
    } else {
        UpdateState(RelayLinkState::kAdvertising);
    }
    StartAdvertisingLocked();
}

void BleRelayManager::HandleIncomingData(const uint8_t* data, size_t len) {
    if (len == 0) return;
    if (data == nullptr) return;
    std::lock_guard<std::recursive_mutex> callback_barrier(handler_callback_mutex_);
    std::vector<BleRelayEnvelope> ready_frames;
    std::vector<std::pair<BleRelayEnvelope, uint16_t>> acknowledgements;
    bool protocol_error = false;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        const int64_t now = esp_timer_get_time();
        last_rx_time_us_ = now;
        for (auto it = v2_route_tombstones_.begin(); it != v2_route_tombstones_.end();) {
            if (it->second.expires_at_us > now) {
                ++it;
            } else {
                it = v2_route_tombstones_.erase(it);
            }
        }
        for (auto it = pending_rx_updated_at_us_.begin(); it != pending_rx_updated_at_us_.end();) {
            if (now - it->second < kBleRelayAssemblyTimeoutUs) {
                ++it;
                continue;
            }
            pending_rx_frames_.erase(it->first);
            pending_rx_next_seq_.erase(it->first);
            pending_rx_fragment_count_.erase(it->first);
            it = pending_rx_updated_at_us_.erase(it);
            protocol_error = true;
        }
        if (len > kBleRelayRxBufferMax || rx_buffer_.size() > kBleRelayRxBufferMax - len) {
            ESP_LOGE(TAG, "BLE receive buffer limit exceeded buffered=%u incoming=%u",
                static_cast<unsigned>(rx_buffer_.size()), static_cast<unsigned>(len));
            rx_buffer_.clear();
            protocol_error = true;
        } else {
            rx_buffer_.insert(rx_buffer_.end(), data, data + len);
        }

        while (!protocol_error && transport_v2_active_ &&
            rx_buffer_.size() >= sizeof(BleRelayV2FrameHeader)) {
            size_t payload_len = 0;
            if (!BleRelayValidateV2Header(rx_buffer_.data(), rx_buffer_.size(), &payload_len)) {
                if (invalid_v2_header_window_started_at_us_ == 0 ||
                    now - invalid_v2_header_window_started_at_us_ > kBleTransportInvalidHeaderWindowUs) {
                    invalid_v2_header_window_started_at_us_ = now;
                    invalid_v2_header_count_ = 0;
                }
                invalid_v2_header_count_++;
                const bool candidate_header = BleRelayReadU16(rx_buffer_.data()) == kBleRelayV2Magic &&
                    rx_buffer_[2] == kBleRelayV2Version;
                const size_t candidate_payload_len = BleRelayReadU16(rx_buffer_.data() + 15);
                if (candidate_header && candidate_payload_len <= kBleRelayFramePayloadMax &&
                    rx_buffer_.size() >= sizeof(BleRelayV2FrameHeader) + candidate_payload_len) {
                    rx_buffer_.erase(
                        rx_buffer_.begin(),
                        rx_buffer_.begin() + sizeof(BleRelayV2FrameHeader) + candidate_payload_len);
                } else {
                    size_t next_magic = 1;
                    while (next_magic + 1 < rx_buffer_.size() &&
                        BleRelayReadU16(rx_buffer_.data() + next_magic) != kBleRelayV2Magic) {
                        ++next_magic;
                    }
                    if (next_magic + 1 < rx_buffer_.size()) {
                        rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + next_magic);
                    } else {
                        const bool keep_prefix = rx_buffer_.back() == static_cast<uint8_t>(kBleRelayV2Magic >> 8);
                        rx_buffer_.clear();
                        if (keep_prefix) rx_buffer_.push_back(static_cast<uint8_t>(kBleRelayV2Magic >> 8));
                    }
                }
                if (invalid_v2_header_count_ >= kBleTransportInvalidHeaderLimit) {
                    ESP_LOGE(TAG, "Rejecting repeated invalid BLE relay V2 headers");
                    protocol_error = true;
                }
                continue;
            }
            const size_t total_len = sizeof(BleRelayV2FrameHeader) + payload_len;
            if (rx_buffer_.size() < total_len) break;
            const uint8_t raw_type = rx_buffer_[3];
            const auto type = static_cast<BleRelayFrameType>(raw_type);
            const uint8_t flags = rx_buffer_[4];
            const uint16_t session_epoch = BleRelayReadU16(rx_buffer_.data() + 5);
            const uint16_t stream_id = BleRelayReadU16(rx_buffer_.data() + 7);
            const uint32_t request_id = BleRelayReadU32(rx_buffer_.data() + 9);
            const uint16_t seq = BleRelayReadU16(rx_buffer_.data() + 13);
            if (session_epoch != transport_session_epoch_ || payload_len > transport_max_frame_payload_ ||
                !BleRelayV2HasValidApplicationRoute(raw_type, stream_id, request_id) ||
                !BleRelayV2HasCanonicalControlEnvelope(raw_type, flags, payload_len)) {
                protocol_error = true;
                break;
            }
            std::vector<uint8_t> payload(payload_len);
            if (payload_len > 0) {
                memcpy(payload.data(), rx_buffer_.data() + sizeof(BleRelayV2FrameHeader), payload_len);
            }
            if (BleRelayV2RequiresAck(raw_type)) {
                const uint64_t route = BuildRequestHandlerKey(stream_id, request_id);
                const auto tombstone = v2_route_tombstones_.find(route);
                const bool has_handler = request_handlers_.find(route) != request_handlers_.end();
                if (!has_handler) {
                    BleRelayEnvelope rejected{type, flags, session_epoch, stream_id, request_id, seq, {}};
                    uint16_t acknowledged_seq = 0;
                    if (tombstone != v2_route_tombstones_.end()) {
                        acknowledged_seq = tombstone->second.acknowledged_seq;
                        if (raw_type == kBleRelayV2CancelType) {
                            const auto cancel = BleRelayV2ClassifySequence(
                                true,
                                static_cast<uint16_t>(acknowledged_seq + 1),
                                seq);
                            acknowledged_seq = cancel.acknowledged_seq;
                            if (cancel.accepted) {
                                tombstone->second.acknowledged_seq = seq;
                                tombstone->second.expires_at_us = now + kBleTransportRouteTombstoneTtlUs;
                            }
                        }
                    }
                    acknowledgements.emplace_back(
                        std::move(rejected),
                        acknowledged_seq);
                    rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + total_len);
                    continue;
                }
                auto expected = v2_rx_expected_sequence_.find(route);
                const auto decision = BleRelayV2ClassifySequence(
                    expected != v2_rx_expected_sequence_.end(),
                    expected == v2_rx_expected_sequence_.end() ? 0 : expected->second,
                    seq);
                if (!decision.accepted) {
                    BleRelayEnvelope duplicate{type, flags, session_epoch, stream_id, request_id, seq, {}};
                    acknowledgements.emplace_back(std::move(duplicate), decision.acknowledged_seq);
                    rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + total_len);
                    continue;
                }
                v2_rx_expected_sequence_[route] = decision.next_expected;
                BleRelayEnvelope accepted{type, flags, session_epoch, stream_id, request_id, seq, {}};
                acknowledgements.emplace_back(std::move(accepted), seq);
            }
            if (raw_type >= kBleRelayV2AckType || !RequiresAssembly(type)) {
                ready_frames.push_back(BleRelayEnvelope{
                    type,
                    static_cast<uint8_t>(flags & (kBleRelayFlagFinal | kBleRelayFlagEof | kBleRelayFlagError)),
                    session_epoch,
                    stream_id,
                    request_id,
                    seq,
                    std::move(payload)});
            } else {
                const uint64_t key = BuildPendingFrameKey(type, stream_id, request_id);
                if (pending_rx_frames_.find(key) == pending_rx_frames_.end() &&
                    pending_rx_frames_.size() >= kBleRelayPendingAssembliesMax) {
                    protocol_error = true;
                    break;
                }
                auto& combined = pending_rx_frames_[key];
                auto& next_seq = pending_rx_next_seq_[key];
                auto& fragment_count = pending_rx_fragment_count_[key];
                if (!combined.empty() && next_seq != seq) {
                    protocol_error = true;
                    break;
                }
                if (fragment_count >= transport_max_fragments_ ||
                    combined.size() > transport_max_message_bytes_ ||
                    payload.size() > transport_max_message_bytes_ - combined.size()) {
                    protocol_error = true;
                    break;
                }
                combined.insert(combined.end(), payload.begin(), payload.end());
                fragment_count++;
                next_seq = static_cast<uint16_t>(seq + 1);
                pending_rx_updated_at_us_[key] = now;
                if ((flags & kBleRelayFlagFinal) != 0) {
                    std::vector<uint8_t> complete_payload = std::move(combined);
                    pending_rx_frames_.erase(key);
                    pending_rx_next_seq_.erase(key);
                    pending_rx_fragment_count_.erase(key);
                    pending_rx_updated_at_us_.erase(key);
                    ready_frames.push_back(BleRelayEnvelope{
                        type,
                        static_cast<uint8_t>(flags & (kBleRelayFlagEof | kBleRelayFlagError)),
                        session_epoch,
                        stream_id,
                        request_id,
                        seq,
                        std::move(complete_payload)});
                }
            }
            rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + total_len);
        }

        while (!protocol_error && !transport_v2_active_ && rx_buffer_.size() >= sizeof(BleRelayFrameHeader)) {
            auto* header = reinterpret_cast<const BleRelayFrameHeader*>(rx_buffer_.data());
            if (!BleRelayIsKnownFrameType(header->type)) {
                ESP_LOGE(TAG, "Rejecting unknown BLE relay frame type=%u", header->type);
                protocol_error = true;
                break;
            }
            const auto type = static_cast<BleRelayFrameType>(header->type);
            const uint8_t flags = header->flags;
            const uint16_t stream_id = BleRelayReadU16(reinterpret_cast<const uint8_t*>(&header->stream_id));
            const uint16_t seq = BleRelayReadU16(reinterpret_cast<const uint8_t*>(&header->seq));
            const uint16_t payload_len = BleRelayReadU16(reinterpret_cast<const uint8_t*>(&header->len));
            if (payload_len > kBleRelayFramePayloadMax) {
                ESP_LOGE(TAG, "Rejecting oversized BLE relay frame payload=%u", payload_len);
                protocol_error = true;
                break;
            }
            const size_t total_len = sizeof(BleRelayFrameHeader) + payload_len;
            if (rx_buffer_.size() < total_len) {
                break;
            }

            std::vector<uint8_t> payload(payload_len);
            if (payload_len > 0) {
                memcpy(payload.data(), rx_buffer_.data() + sizeof(BleRelayFrameHeader), payload_len);
            }

            if (!RequiresAssembly(type)) {
                ready_frames.push_back(BleRelayEnvelope{
                    type,
                    static_cast<uint8_t>(flags & (kBleRelayFlagEof | kBleRelayFlagError)),
                    0,
                    stream_id,
                    0,
                    seq,
                    std::move(payload)});
            } else {
                const uint64_t key = BuildPendingFrameKey(type, stream_id, 0);
                if (pending_rx_frames_.find(key) == pending_rx_frames_.end() &&
                    pending_rx_frames_.size() >= kBleRelayPendingAssembliesMax) {
                    ESP_LOGE(TAG, "BLE pending assembly limit exceeded");
                    protocol_error = true;
                    break;
                }
                auto& combined = pending_rx_frames_[key];
                auto& next_seq = pending_rx_next_seq_[key];
                if (!combined.empty() && next_seq != seq) {
                    ESP_LOGE(TAG, "Rejecting partial frame sequence mismatch: type=%d stream=%u expected_seq=%u got=%u",
                        static_cast<int>(type), static_cast<unsigned>(stream_id),
                        static_cast<unsigned>(next_seq), static_cast<unsigned>(seq));
                    protocol_error = true;
                    break;
                }
                if (combined.size() > kBleRelayMessageMax ||
                    payload.size() > kBleRelayMessageMax - combined.size()) {
                    ESP_LOGE(TAG, "BLE assembled message limit exceeded");
                    protocol_error = true;
                    break;
                }
                combined.insert(combined.end(), payload.begin(), payload.end());
                next_seq = static_cast<uint16_t>(seq + 1);
                pending_rx_updated_at_us_[key] = now;

                const bool is_final = (flags & kBleRelayFlagFinal) != 0;
                const bool legacy_complete = !is_final && IsCompleteJsonPayload(combined);
                if (is_final || legacy_complete) {
                    std::vector<uint8_t> complete_payload = std::move(combined);
                    pending_rx_frames_.erase(key);
                    pending_rx_next_seq_.erase(key);
                    pending_rx_updated_at_us_.erase(key);
                    ready_frames.push_back(BleRelayEnvelope{
                        type,
                        static_cast<uint8_t>(flags & (kBleRelayFlagEof | kBleRelayFlagError)),
                        0,
                        stream_id,
                        0,
                        seq,
                        std::move(complete_payload)});
                }
            }
            rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + total_len);
        }
        if (protocol_error) {
            rx_buffer_.clear();
            pending_rx_frames_.clear();
            pending_rx_next_seq_.clear();
            pending_rx_fragment_count_.clear();
            pending_rx_updated_at_us_.clear();
        }
    }

    if (protocol_error) {
        uint16_t conn_handle = 0xFFFF;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            conn_handle = conn_handle_;
        }
        if (conn_handle != 0xFFFF) ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        return;
    }

    for (auto& frame : ready_frames) {
        if (!DispatchFrame(std::move(frame))) {
            uint16_t conn_handle = 0xFFFF;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                conn_handle = conn_handle_;
            }
            if (conn_handle != 0xFFFF) ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            return;
        }
    }

    for (const auto& acknowledgement : acknowledgements) {
        if (!SendV2Ack(acknowledgement.first, acknowledgement.second)) {
            uint16_t conn_handle = 0xFFFF;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                conn_handle = conn_handle_;
            }
            if (conn_handle != 0xFFFF) ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            return;
        }
    }

}

bool BleRelayManager::DispatchFrame(BleRelayEnvelope envelope) {
    const uint8_t raw_type = static_cast<uint8_t>(envelope.type);
    if (raw_type == kBleRelayV2AckType) {
        if (envelope.payload.size() != 1 || envelope.payload[0] > kBleTransportMaxWindow) {
            uint16_t conn_handle = 0xFFFF;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                conn_handle = conn_handle_;
            }
            if (conn_handle != 0xFFFF) ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            return false;
        }
        const uint64_t route = BuildRequestHandlerKey(envelope.stream_id, envelope.request_id);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!transport_v2_active_ || v2_tx_sequence_.find(route) == v2_tx_sequence_.end()) return true;
            std::lock_guard<std::mutex> ack_lock(v2_ack_mutex_);
            v2_latest_ack_[route] = V2AckState{envelope.seq, envelope.payload[0]};
        }
        v2_ack_cv_.notify_all();
        return true;
    }
    if (raw_type == kBleRelayV2ProtocolErrorType) {
        uint16_t conn_handle = 0xFFFF;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            conn_handle = conn_handle_;
        }
        if (conn_handle != 0xFFFF) ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        return false;
    }
    if (envelope.type == BleRelayFrameType::kPairResponse) {
        HandlePairResponse(PayloadToString(envelope.payload));
        return true;
    }
    if (envelope.type == BleRelayFrameType::kAuthResponse) {
        HandleAuthResponse(PayloadToString(envelope.payload));
        return true;
    }
    if (envelope.type == BleRelayFrameType::kHeartbeat) {
        HandleHeartbeat(PayloadToString(envelope.payload));
        return true;
    }
    std::lock_guard<std::recursive_mutex> callback_lock(handler_callback_mutex_);
    BleRelayStreamHandler* handler = nullptr;
    bool clear_unhandled_route = false;
    const uint64_t request_route = BuildRequestHandlerKey(envelope.stream_id, envelope.request_id);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (envelope.request_id != 0) {
            auto request = request_handlers_.find(BuildRequestHandlerKey(envelope.stream_id, envelope.request_id));
            if (request != request_handlers_.end()) handler = request->second;
        }
        if (handler == nullptr && envelope.request_id == 0) {
            auto stream = stream_handlers_.find(envelope.stream_id);
            if (stream != stream_handlers_.end()) handler = stream->second;
        }
        if (handler == nullptr && envelope.request_id != 0) {
            v2_tx_sequence_.erase(request_route);
            v2_rx_expected_sequence_.erase(request_route);
            clear_unhandled_route = true;
        }
    }
    if (clear_unhandled_route) {
        std::lock_guard<std::mutex> ack_lock(v2_ack_mutex_);
        v2_latest_ack_.erase(request_route);
    }
    if (handler == nullptr) {
        ESP_LOGW(TAG, "Unhandled stream frame: type=%d stream=%u request=%lu len=%u",
            static_cast<int>(envelope.type), envelope.stream_id,
            static_cast<unsigned long>(envelope.request_id), static_cast<unsigned>(envelope.payload.size()));
        return true;
    }
    return handler->OnBleRelayEnvelope(envelope);
}

void BleRelayManager::HandlePairResponse(const std::string& json) {
    auto* root = cJSON_Parse(json.c_str());
    if (root == nullptr) {
        ESP_LOGE(TAG, "Invalid pair response");
        return;
    }

    auto* receipt_id = cJSON_GetObjectItem(root, "receipt_id");
    auto* receipt_proof = cJSON_GetObjectItem(root, "receipt_proof");
    if (cJSON_IsString(receipt_id) || cJSON_IsString(receipt_proof)) {
        std::array<uint8_t, 32> received_proof{};
        std::array<uint8_t, 32> expected_proof{};
        std::function<void()> ready_cb;
        uint16_t conn_handle = 0xFFFF;
        std::string ack_receipt_id;
        bool committed = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            conn_handle = pending_pair_conn_handle_;
            const int64_t age = esp_timer_get_time() - pending_pair_started_time_us_;
            const bool fields_valid = cJSON_IsString(receipt_id) && cJSON_IsString(receipt_proof) &&
                Base64UrlDecodeExact(receipt_proof->valuestring, received_proof.data(), received_proof.size());
            const bool same_attempt = fields_valid && running_ && state_ == RelayLinkState::kPairing &&
                conn_handle_ != 0xFFFF && conn_handle_ == pending_pair_conn_handle_ &&
                pending_pair_receipt_id_ == receipt_id->valuestring &&
                age >= 0 && age <= kBlePairReceiptTtlUs;
            const bool computed = same_attempt && ComputePairReceipt(
                pending_pair_secret_, pending_pair_peer_id_, pending_pair_receipt_id_, &expected_proof);
            if (computed && mbedtls_ct_memcmp(
                    expected_proof.data(), received_proof.data(), expected_proof.size()) == 0) {
                peer_id_ = pending_pair_peer_id_;
                secret_ = pending_pair_secret_;
                ack_receipt_id = pending_pair_receipt_id_;
                conn_handle = conn_handle_;
                bound_ = true;
                force_pairing_ = false;
                SaveBindingLocked();
                pending_pair_peer_id_.clear();
                pending_pair_secret_.clear();
                pending_pair_receipt_id_.clear();
                pending_pair_conn_handle_ = 0xFFFF;
                pending_pair_started_time_us_ = 0;
                UpdateState(RelayLinkState::kConnected);
                ready_cb = ready_callback_;
                committed = true;
            }
        }
        mbedtls_platform_zeroize(received_proof.data(), received_proof.size());
        mbedtls_platform_zeroize(expected_proof.data(), expected_proof.size());
        cJSON_Delete(root);

        cJSON* ack = committed ? cJSON_CreateObject() : nullptr;
        const bool ack_valid = ack != nullptr && AddJsonBool(ack, "ok", true) &&
            AddJsonBool(ack, "committed", true) && AddJsonString(ack, "receipt_id", ack_receipt_id) &&
            AddJsonNumber(ack, "protocol_version", kBleAuthProtocolVersion) &&
            AddJsonString(ack, "auth_scheme", kBleAuthScheme);
        char* ack_text = ack_valid ? cJSON_PrintUnformatted(ack) : nullptr;
        const bool ack_sent = ack_text != nullptr && SendFragments(
            BleRelayFrameType::kPairResponse, 0, 0, 0,
            reinterpret_cast<const uint8_t*>(ack_text), std::strlen(ack_text));
        if (ack_text != nullptr) cJSON_free(ack_text);
        if (ack != nullptr) cJSON_Delete(ack);
        if (committed && ack_sent) {
            if (SendTransportCommit()) {
                bool waiting_for_v2 = false;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    waiting_for_v2 = transport_accepted_;
                }
                if (!waiting_for_v2 && ready_cb) Application::GetInstance().Schedule(std::move(ready_cb));
            } else if (conn_handle != 0xFFFF) {
                ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            }
        } else if (conn_handle != 0xFFFF) {
            ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        }
        return;
    }

    auto* pair_code = cJSON_GetObjectItem(root, "pair_code");
    auto* peer_id = cJSON_GetObjectItem(root, "peer_id");
    if (!cJSON_IsString(pair_code) || !cJSON_IsString(peer_id) ||
        !IsValidAuthId(peer_id->valuestring)) {
        cJSON_Delete(root);
        return;
    }

    const std::string candidate_pair_code = pair_code->valuestring;
    const std::string candidate_peer_id = peer_id->valuestring;
    std::string candidate_secret;
    std::string candidate_receipt_id;
    uint16_t candidate_conn_handle = 0xFFFF;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_ || state_ != RelayLinkState::kPairing ||
            pair_code_ != candidate_pair_code || conn_handle_ == 0xFFFF) {
            cJSON_Delete(root);
            return;
        }
        if (cJSON_GetObjectItemCaseSensitive(root, "transport_accept") != nullptr &&
            !AcceptTransportOfferLocked(root)) {
            ESP_LOGW(TAG, "Rejecting malformed BLE transport accept during pairing");
            cJSON_Delete(root);
            return;
        }
        candidate_secret = GenerateSecretLocked();
        std::array<uint8_t, 16> receipt_random{};
        esp_fill_random(receipt_random.data(), receipt_random.size());
        candidate_receipt_id = Base64UrlEncode(receipt_random.data(), receipt_random.size());
        mbedtls_platform_zeroize(receipt_random.data(), receipt_random.size());
        candidate_conn_handle = conn_handle_;
    }

    cJSON* response = cJSON_CreateObject();
    if (response == nullptr) {
        cJSON_Delete(root);
        ble_gap_terminate(candidate_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        return;
    }
    const bool response_valid = !candidate_receipt_id.empty() && AddJsonBool(response, "ok", true) &&
        AddJsonString(response, "peer_id", candidate_peer_id) &&
        AddJsonString(response, "secret", candidate_secret) &&
        AddJsonString(response, "receipt_id", candidate_receipt_id) &&
        AddJsonNumber(response, "protocol_version", kBleAuthProtocolVersion) &&
        AddJsonString(response, "auth_scheme", kBleAuthScheme);
    char* text = response_valid ? cJSON_PrintUnformatted(response) : nullptr;

    bool delivered = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (text != nullptr && running_ && conn_handle_ == candidate_conn_handle &&
            state_ == RelayLinkState::kPairing && pair_code_ == candidate_pair_code &&
            SendFragmentsLocked(
                BleRelayFrameType::kPairResponse, 0, 0, 0,
                reinterpret_cast<const uint8_t*>(text), std::strlen(text))) {
            pending_pair_peer_id_ = candidate_peer_id;
            pending_pair_secret_ = candidate_secret;
            pending_pair_receipt_id_ = candidate_receipt_id;
            pending_pair_conn_handle_ = candidate_conn_handle;
            pending_pair_started_time_us_ = esp_timer_get_time();
            delivered = true;
        } else {
            UpdateState(RelayLinkState::kError);
        }
    }
    if (text != nullptr) cJSON_free(text);
    cJSON_Delete(response);
    cJSON_Delete(root);

    if (!delivered) {
        ble_gap_terminate(candidate_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }
}

void BleRelayManager::HandleAuthResponse(const std::string& json) {
    auto* root = cJSON_Parse(json.c_str());
    bool accepted = false;
    std::function<void()> ready_cb;
    std::string response_session;
    uint16_t reject_conn_handle = 0xFFFF;
    uint16_t candidate_conn_handle = 0xFFFF;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const bool may_attempt = auth_challenge_active_ && !auth_challenge_consumed_;
        auth_challenge_consumed_ = true;
        std::array<uint8_t, 16> session{};
        std::array<uint8_t, 32> device_nonce{};
        std::array<uint8_t, 32> app_nonce{};
        std::array<uint8_t, 32> received_proof{};
        std::array<uint8_t, 32> expected_proof{};
        auto* version = root == nullptr ? nullptr : cJSON_GetObjectItem(root, "protocol_version");
        auto* scheme = root == nullptr ? nullptr : cJSON_GetObjectItem(root, "auth_scheme");
        auto* peer_id = root == nullptr ? nullptr : cJSON_GetObjectItem(root, "peer_id");
        auto* session_id = root == nullptr ? nullptr : cJSON_GetObjectItem(root, "session_id");
        auto* nonce = root == nullptr ? nullptr : cJSON_GetObjectItem(root, "device_nonce");
        auto* app = root == nullptr ? nullptr : cJSON_GetObjectItem(root, "app_nonce");
        auto* proof = root == nullptr ? nullptr : cJSON_GetObjectItem(root, "proof");
        const bool has_transport_accept = root != nullptr &&
            cJSON_GetObjectItemCaseSensitive(root, "transport_accept") != nullptr;
        const bool transport_accept_valid = has_transport_accept
            ? AcceptTransportOfferLocked(root)
            : transport_floor_ < kBleTransportVersion;
        const bool fields_valid = cJSON_IsNumber(version) && version->valueint == kBleAuthProtocolVersion &&
            cJSON_IsString(scheme) && std::strcmp(scheme->valuestring, kBleAuthScheme) == 0 &&
            cJSON_IsString(peer_id) && cJSON_IsString(session_id) && cJSON_IsString(nonce) &&
            cJSON_IsString(app) && cJSON_IsString(proof) && transport_accept_valid &&
            Base64UrlDecodeExact(session_id->valuestring, session.data(), session.size()) &&
            Base64UrlDecodeExact(nonce->valuestring, device_nonce.data(), device_nonce.size()) &&
            Base64UrlDecodeExact(app->valuestring, app_nonce.data(), app_nonce.size()) &&
            Base64UrlDecodeExact(proof->valuestring, received_proof.data(), received_proof.size());
        const int64_t age = esp_timer_get_time() - auth_started_time_us_;
        const bool challenge_matches = fields_valid && may_attempt && bound_ &&
            state_ == RelayLinkState::kAuthenticating && age >= 0 && age <= kBleAuthChallengeTtlUs &&
            peer_id_ == peer_id->valuestring &&
            std::equal(session.begin(), session.end(), auth_session_id_.begin()) &&
            std::equal(device_nonce.begin(), device_nonce.end(), auth_device_nonce_.begin());
        const bool computed = challenge_matches && ComputeAuthProofV2(secret_, peer_id_, auth_device_id_,
            auth_client_id_, auth_session_id_.data(), auth_device_nonce_.data(), app_nonce.data(), &expected_proof);
        accepted = computed && mbedtls_ct_memcmp(expected_proof.data(), received_proof.data(), expected_proof.size()) == 0;
        response_session = Base64UrlEncode(auth_session_id_.data(), auth_session_id_.size());
        candidate_conn_handle = conn_handle_;
        mbedtls_platform_zeroize(app_nonce.data(), app_nonce.size());
        mbedtls_platform_zeroize(received_proof.data(), received_proof.size());
        mbedtls_platform_zeroize(expected_proof.data(), expected_proof.size());
        if (!accepted) {
            RejectAuthenticationLocked("auth response rejected");
            reject_conn_handle = conn_handle_;
        }
    }

    cJSON* response = cJSON_CreateObject();
    char* text = nullptr;
    if (response != nullptr) {
        const bool response_valid = AddJsonBool(response, "ok", accepted) &&
            AddJsonNumber(response, "protocol_version", kBleAuthProtocolVersion) &&
            AddJsonString(response, "auth_scheme", kBleAuthScheme) &&
            AddJsonString(response, "session_id", response_session);
        if (response_valid) text = cJSON_PrintUnformatted(response);
    }

    bool committed = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const bool same_attempt = running_ && conn_handle_ == candidate_conn_handle &&
            candidate_conn_handle != 0xFFFF;
        const bool response_sent = same_attempt && text != nullptr && SendFragmentsLocked(
            BleRelayFrameType::kAuthResponse,
            0,
            0,
            accepted ? 0 : kBleRelayFlagError,
            reinterpret_cast<const uint8_t*>(text),
            std::strlen(text));
        if (accepted && response_sent && state_ == RelayLinkState::kAuthenticating) {
            auth_failures_ = 0;
            auth_started_time_us_ = 0;
            auth_challenge_active_ = false;
            UpdateState(RelayLinkState::kConnected);
            ready_cb = ready_callback_;
            committed = true;
        } else if (accepted) {
            UpdateState(RelayLinkState::kError);
            reject_conn_handle = candidate_conn_handle;
        }
    }
    if (text != nullptr) cJSON_free(text);
    if (response != nullptr) cJSON_Delete(response);
    if (root != nullptr) cJSON_Delete(root);

    if (committed) {
        if (SendTransportCommit()) {
            bool waiting_for_v2 = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                waiting_for_v2 = transport_accepted_;
            }
            if (!waiting_for_v2 && ready_cb) Application::GetInstance().Schedule(std::move(ready_cb));
        } else if (candidate_conn_handle != 0xFFFF) {
            ble_gap_terminate(candidate_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        }
        return;
    }

    if (reject_conn_handle != 0xFFFF) {
        ble_gap_terminate(reject_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }
}

void BleRelayManager::HandleHeartbeat(const std::string& json) {
    cJSON* root = json.empty() ? cJSON_CreateObject() : cJSON_Parse(json.c_str());
    bool activate_v2 = false;
    bool invalid_ack = false;
    uint16_t terminate_handle = 0xFFFF;
    std::function<void()> ready_cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_rx_time_us_ = esp_timer_get_time();
        if (state_ == RelayLinkState::kPairing || state_ == RelayLinkState::kAuthenticating) {
            ESP_LOGI(TAG, "Heartbeat received while handshake is pending, replaying handshake");
            SendCurrentHandshakeLocked();
        }
        const cJSON* ack = root == nullptr ? nullptr :
            cJSON_GetObjectItemCaseSensitive(root, "transport_ack");
        if (ack != nullptr) {
            const cJSON* offer_id = cJSON_GetObjectItemCaseSensitive(ack, "offer_id");
            int schema = 0;
            int selected = 0;
            int epoch = 0;
            const int64_t age = esp_timer_get_time() - transport_commit_started_at_us_;
            const bool valid = transport_accepted_ && transport_commit_sent_ && !transport_v2_active_ &&
                age >= 0 && age <= kBleTransportNegotiationTtlUs &&
                cJSON_IsString(offer_id) && transport_offer_id_ == offer_id->valuestring &&
                JsonIntInRange(ack, "schema", 1, 1, &schema) &&
                JsonIntInRange(ack, "selected_version", 2, 2, &selected) &&
                JsonIntInRange(ack, "session_epoch", transport_session_epoch_, transport_session_epoch_, &epoch);
            if (valid) {
                transport_v2_active_ = true;
                transport_floor_ = kBleTransportVersion;
                SaveBindingLocked();
                transport_commit_sent_ = false;
                next_seq_ = 1;
                next_request_id_ = 1;
                ClearReceiveStateLocked();
                ready_cb = ready_callback_;
                activate_v2 = true;
            } else {
                invalid_ack = true;
                terminate_handle = conn_handle_;
            }
        }
    }
    if (root != nullptr) cJSON_Delete(root);
    if (invalid_ack) {
        if (terminate_handle != 0xFFFF) ble_gap_terminate(terminate_handle, BLE_ERR_REM_USER_CONN_TERM);
        return;
    }
    if (activate_v2 && !SendRequestFrame(
            BleRelayFrameType::kHeartbeat, 0, 0, 0, nullptr, 0)) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            terminate_handle = conn_handle_;
        }
        if (terminate_handle != 0xFFFF) ble_gap_terminate(terminate_handle, BLE_ERR_REM_USER_CONN_TERM);
    } else if (activate_v2) {
        bool publish_ready = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            publish_ready = transport_v2_active_ && state_ == RelayLinkState::kConnected && conn_handle_ != 0xFFFF;
            if (publish_ready) xEventGroupSetBits(event_group_, kRelayReadyBit);
        }
        if (publish_ready && ready_cb) Application::GetInstance().Schedule(std::move(ready_cb));
    }
}

void BleRelayManager::ClearReceiveStateLocked() {
    rx_buffer_.clear();
    pending_rx_frames_.clear();
    pending_rx_next_seq_.clear();
    pending_rx_fragment_count_.clear();
    pending_rx_updated_at_us_.clear();
}

void BleRelayManager::NotifyHandlersDisconnected() {
    std::lock_guard<std::recursive_mutex> callback_lock(handler_callback_mutex_);
    std::vector<std::pair<uint16_t, BleRelayStreamHandler*>> handlers;
    std::vector<BleRelayStreamHandler*> request_handlers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        handlers.assign(stream_handlers_.begin(), stream_handlers_.end());
        request_handlers.reserve(request_handlers_.size());
        for (const auto& entry : request_handlers_) request_handlers.push_back(entry.second);
        request_handlers_.clear();
    }
    for (const auto& entry : handlers) {
        bool still_registered = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = stream_handlers_.find(entry.first);
            still_registered = it != stream_handlers_.end() && it->second == entry.second;
        }
        if (still_registered && entry.second != nullptr) entry.second->OnBleRelayDisconnected();
    }
    for (BleRelayStreamHandler* handler : request_handlers) {
        if (handler == nullptr || std::any_of(handlers.begin(), handlers.end(),
                [handler](const auto& entry) { return entry.second == handler; })) continue;
        handler->OnBleRelayDisconnected();
    }
}

void BleRelayManager::ResetTransportNegotiationLocked() {
    std::array<uint8_t, 8> random{};
    esp_fill_random(random.data(), random.size());
    static constexpr char kHex[] = "0123456789abcdef";
    transport_offer_id_.clear();
    transport_offer_id_.reserve(random.size() * 2);
    for (uint8_t byte : random) {
        transport_offer_id_.push_back(kHex[(byte >> 4) & 0x0f]);
        transport_offer_id_.push_back(kHex[byte & 0x0f]);
    }
    mbedtls_platform_zeroize(random.data(), random.size());
    transport_accepted_ = false;
    transport_commit_sent_ = false;
    transport_commit_started_at_us_ = 0;
    transport_commit_retry_task_ = nullptr;
    transport_initial_window_ = 0;
    transport_max_window_ = 0;
    transport_max_inflight_requests_ = 0;
    transport_max_frame_payload_ = 0;
    transport_max_message_bytes_ = 0;
    transport_max_fragments_ = 0;
    transport_session_epoch_ = 0;
    next_request_id_ = 1;
    transport_v2_active_ = false;
    invalid_v2_header_count_ = 0;
    invalid_v2_header_window_started_at_us_ = 0;
    v2_tx_sequence_.clear();
    v2_rx_expected_sequence_.clear();
    v2_route_tombstones_.clear();
    {
        std::lock_guard<std::mutex> ack_lock(v2_ack_mutex_);
        v2_latest_ack_.clear();
    }
    v2_ack_cv_.notify_all();
}

bool BleRelayManager::AddTransportOfferLocked(cJSON* root) {
    if (root == nullptr || transport_offer_id_.size() != 16) return false;
    cJSON* offer = cJSON_CreateObject();
    cJSON* versions = cJSON_CreateArray();
    cJSON* version = versions == nullptr ? nullptr : cJSON_CreateNumber(kBleTransportVersion);
    if (offer == nullptr || versions == nullptr || version == nullptr ||
        !cJSON_AddItemToArray(versions, version)) {
        if (version != nullptr && (versions == nullptr || version->prev == nullptr)) cJSON_Delete(version);
        if (versions != nullptr) cJSON_Delete(versions);
        if (offer != nullptr) cJSON_Delete(offer);
        return false;
    }
    static constexpr const char* kFeatures[] = {"ack", "credit", "cancel", "http", "socket"};
    const bool valid = AddJsonNumber(offer, "schema", kBleTransportSchema) &&
        AddJsonString(offer, "offer_id", transport_offer_id_) &&
        cJSON_AddItemToObject(offer, "versions", versions) &&
        AddJsonNumber(offer, "mtu", mtu_) &&
        AddJsonNumber(offer, "max_frame_payload", kBleRelayFramePayloadMax) &&
        AddJsonNumber(offer, "max_message_bytes", kBleTransportMaxMessageBytes) &&
        AddJsonNumber(offer, "max_fragments", kBleTransportMaxFragments) &&
        AddJsonIntArray(offer, "frame_types", 1, kBleRelayV2ProtocolErrorType) &&
        AddJsonStringArray(offer, "features", kFeatures, std::size(kFeatures)) &&
        AddJsonNumber(offer, "initial_window", kBleTransportInitialWindow) &&
        AddJsonNumber(offer, "max_window", kBleTransportMaxWindow) &&
        AddJsonNumber(offer, "max_inflight_requests", kBleTransportMaxInflightRequests);
    if (!valid || !cJSON_AddItemToObject(root, "transport_offer", offer)) {
        if (cJSON_GetObjectItemCaseSensitive(offer, "versions") == nullptr) cJSON_Delete(versions);
        cJSON_Delete(offer);
        return false;
    }
    return true;
}

bool BleRelayManager::AcceptTransportOfferLocked(const cJSON* root) {
    if (transport_accepted_) return true;
    const cJSON* accept = root == nullptr ? nullptr :
        cJSON_GetObjectItemCaseSensitive(root, "transport_accept");
    const cJSON* offer_id = accept == nullptr ? nullptr :
        cJSON_GetObjectItemCaseSensitive(accept, "offer_id");
    int schema = 0;
    int selected = 0;
    int frame_payload = 0;
    int message_bytes = 0;
    int fragments = 0;
    int initial_window = 0;
    int max_window = 0;
    int inflight = 0;
    static constexpr const char* kFeatures[] = {"ack", "credit", "cancel", "http", "socket"};
    const bool valid = cJSON_IsObject(accept) && cJSON_IsString(offer_id) &&
        transport_offer_id_ == offer_id->valuestring &&
        JsonIntInRange(accept, "schema", 1, 1, &schema) &&
        JsonIntInRange(accept, "selected_version", 2, 2, &selected) &&
        JsonIntInRange(accept, "max_frame_payload", 1, kBleRelayFramePayloadMax, &frame_payload) &&
        JsonIntInRange(accept, "max_message_bytes", 1, kBleTransportMaxMessageBytes, &message_bytes) &&
        JsonIntInRange(accept, "max_fragments", 1, kBleTransportMaxFragments, &fragments) &&
        JsonIntInRange(accept, "initial_window", 1, kBleTransportInitialWindow, &initial_window) &&
        JsonIntInRange(accept, "max_window", initial_window, kBleTransportMaxWindow, &max_window) &&
        JsonIntInRange(accept, "max_inflight_requests", 1, kBleTransportMaxInflightRequests, &inflight) &&
        JsonStringArrayContainsAll(accept, "features", kFeatures, std::size(kFeatures));
    if (!valid) return false;
    transport_accepted_ = true;
    transport_max_frame_payload_ = static_cast<uint16_t>(frame_payload);
    transport_initial_window_ = static_cast<uint8_t>(initial_window);
    transport_max_window_ = static_cast<uint8_t>(max_window);
    transport_max_inflight_requests_ = static_cast<uint8_t>(inflight);
    transport_max_message_bytes_ = static_cast<uint16_t>(message_bytes);
    transport_max_fragments_ = static_cast<uint16_t>(fragments);
    return true;
}

bool BleRelayManager::SendTransportCommit() {
    std::string offer_id;
    uint16_t epoch = 0;
    int initial_window = 0;
    int max_window = 0;
    int max_frame_payload = 0;
    int max_message_bytes = 0;
    int max_fragments = 0;
    int max_inflight_requests = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!transport_accepted_ || transport_v2_active_) return true;
        if (transport_session_epoch_ == 0) {
            do {
                transport_session_epoch_ = static_cast<uint16_t>(esp_random());
            } while (transport_session_epoch_ == 0);
        }
        offer_id = transport_offer_id_;
        epoch = transport_session_epoch_;
        initial_window = transport_initial_window_;
        max_window = transport_max_window_;
        max_frame_payload = transport_max_frame_payload_;
        max_message_bytes = transport_max_message_bytes_;
        max_fragments = transport_max_fragments_;
        max_inflight_requests = transport_max_inflight_requests_;
    }
    cJSON* root = cJSON_CreateObject();
    cJSON* commit = cJSON_CreateObject();
    const bool valid = root != nullptr && commit != nullptr &&
        AddJsonNumber(commit, "schema", kBleTransportSchema) &&
        AddJsonString(commit, "offer_id", offer_id) &&
        AddJsonNumber(commit, "selected_version", kBleTransportVersion) &&
        AddJsonNumber(commit, "session_epoch", epoch) &&
        AddJsonNumber(commit, "max_frame_payload", max_frame_payload) &&
        AddJsonNumber(commit, "initial_window", initial_window) &&
        AddJsonNumber(commit, "max_window", max_window) &&
        AddJsonNumber(commit, "max_message_bytes", max_message_bytes) &&
        AddJsonNumber(commit, "max_fragments", max_fragments) &&
        AddJsonNumber(commit, "max_inflight_requests", max_inflight_requests) &&
        cJSON_AddItemToObject(root, "transport_commit", commit);
    const bool commit_attached = root != nullptr &&
        cJSON_GetObjectItemCaseSensitive(root, "transport_commit") == commit;
    char* text = valid ? cJSON_PrintUnformatted(root) : nullptr;
    const bool sent = text != nullptr && SendJsonFrame(BleRelayFrameType::kHeartbeat, 0, 0, text);
    if (sent) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!transport_commit_sent_) {
            transport_commit_sent_ = true;
            transport_commit_started_at_us_ = esp_timer_get_time();
            if (transport_commit_retry_task_ == nullptr) {
                const BaseType_t created = xTaskCreate(
                    [](void* context) {
                        static_cast<BleRelayManager*>(context)->RunTransportCommitRetries();
                    },
                    "ble_v2_commit",
                    4096,
                    this,
                    3,
                    &transport_commit_retry_task_);
                if (created != pdPASS) transport_commit_retry_task_ = nullptr;
            }
        }
    }
    if (text != nullptr) cJSON_free(text);
    if (root != nullptr) cJSON_Delete(root);
    if (!commit_attached && commit != nullptr) cJSON_Delete(commit);
    return sent;
}

void BleRelayManager::RunTransportCommitRetries() {
    static constexpr int kCommitRetryDelayMs[] = {500, 1000};
    const TaskHandle_t current_task = xTaskGetCurrentTaskHandle();
    for (const int delay_ms : kCommitRetryDelayMs) {
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (transport_commit_retry_task_ != current_task || !transport_accepted_ ||
                transport_v2_active_ || !transport_commit_sent_ ||
                conn_handle_ == 0xFFFF) {
                break;
            }
        }
        if (!SendTransportCommit()) break;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (transport_commit_retry_task_ == current_task) {
            transport_commit_retry_task_ = nullptr;
        }
    }
    vTaskDelete(nullptr);
}

bool BleRelayManager::SendV2Ack(const BleRelayEnvelope& envelope, uint16_t acknowledged_seq) {
    uint16_t conn_handle = 0xFFFF;
    uint16_t notify_handle = 0;
    uint32_t generation = 0;
    uint8_t credit = kBleTransportInitialWindow;
    BleRelayStreamHandler* route_handler = nullptr;
    std::lock_guard<std::recursive_mutex> callback_lock(handler_callback_mutex_);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!transport_v2_active_ || envelope.session_epoch != transport_session_epoch_ ||
            conn_handle_ == 0xFFFF || notify_val_handle_ == 0 || !notify_subscribed_) return false;
        conn_handle = conn_handle_;
        notify_handle = notify_val_handle_;
        generation = connection_generation_.load(std::memory_order_acquire);
        credit = std::min<uint8_t>(transport_initial_window_, kBleTransportMaxWindow);
        auto handler = request_handlers_.find(BuildRequestHandlerKey(envelope.stream_id, envelope.request_id));
        if (handler != request_handlers_.end()) route_handler = handler->second;
    }
    credit = route_handler == nullptr ? 0 : std::min<uint8_t>(credit, route_handler->AvailableReceiveCredit());
    const uint8_t payload[] = {credit};
    const auto frame = BleRelayBuildV2Frame(
        kBleRelayV2AckType, kBleRelayFlagFinal, envelope.session_epoch,
        envelope.stream_id, envelope.request_id, acknowledged_seq, payload, sizeof(payload));
    if (frame.empty()) return false;
    std::lock_guard<std::recursive_mutex> send_lock(send_mutex_);
    if (connection_generation_.load(std::memory_order_acquire) != generation) return false;
    struct os_mbuf* om = ble_hs_mbuf_from_flat(frame.data(), frame.size());
    return om != nullptr && ble_gatts_notify_custom(conn_handle, notify_handle, om) == 0;
}

void BleRelayManager::SendCurrentHandshakeLocked() {
    cJSON* root = cJSON_CreateObject();
    if (root == nullptr) {
        UpdateState(RelayLinkState::kError);
        return;
    }
    if (!bound_ || force_pairing_) {
        ESP_LOGI(TAG, "Sending pair request to app");
        const bool request_valid = AddJsonString(root, "device_id", SystemInfo::GetMacAddress()) &&
            AddJsonString(root, "client_id", Board::GetInstance().GetUuid()) &&
            AddTransportOfferLocked(root);
        char* text = request_valid ? cJSON_PrintUnformatted(root) : nullptr;
        if (text != nullptr) {
            if (!SendFragmentsLocked(BleRelayFrameType::kPairRequest, 0, 0, 0,
                    reinterpret_cast<const uint8_t*>(text), strlen(text))) {
                ESP_LOGW(TAG, "Pair request notify was not sent conn=%u notify_handle=%u",
                    conn_handle_, notify_val_handle_);
            }
            cJSON_free(text);
        }
    } else {
        ESP_LOGI(TAG, "Sending BLE auth v2 request peer_present=%d", !peer_id_.empty());
        if (!auth_challenge_active_) {
            esp_fill_random(auth_session_id_.data(), auth_session_id_.size());
            esp_fill_random(auth_device_nonce_.data(), auth_device_nonce_.size());
            auth_device_id_ = SystemInfo::GetMacAddress();
            auth_client_id_ = Board::GetInstance().GetUuid();
            auth_started_time_us_ = esp_timer_get_time();
            auth_challenge_active_ = true;
            auth_challenge_consumed_ = false;
        }
        if (heartbeat_timer_ != nullptr) {
            esp_timer_stop(heartbeat_timer_);
            esp_timer_start_periodic(heartbeat_timer_, 5000000);
        }
        const std::string session_id = Base64UrlEncode(auth_session_id_.data(), auth_session_id_.size());
        const std::string device_nonce = Base64UrlEncode(auth_device_nonce_.data(), auth_device_nonce_.size());
        const bool request_valid = !session_id.empty() && !device_nonce.empty() &&
            AddJsonNumber(root, "protocol_version", kBleAuthProtocolVersion) &&
            AddJsonString(root, "auth_scheme", kBleAuthScheme) &&
            AddJsonString(root, "peer_id", peer_id_) &&
            AddJsonString(root, "device_id", auth_device_id_) &&
            AddJsonString(root, "client_id", auth_client_id_) &&
            AddJsonString(root, "session_id", session_id) &&
            AddJsonString(root, "device_nonce", device_nonce) &&
            AddJsonNumber(root, "challenge_ttl_ms", kBleAuthChallengeTtlUs / 1000) &&
            AddTransportOfferLocked(root);
        char* text = request_valid ? cJSON_PrintUnformatted(root) : nullptr;
        if (text != nullptr) {
            if (!SendFragmentsLocked(BleRelayFrameType::kAuthRequest, 0, 0, 0,
                    reinterpret_cast<const uint8_t*>(text), strlen(text))) {
                ESP_LOGW(TAG, "Auth request notify was not sent conn=%u notify_handle=%u",
                    conn_handle_, notify_val_handle_);
            }
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

bool BleRelayManager::SendFragments(BleRelayFrameType type, uint16_t stream_id, uint32_t request_id, uint8_t flags,
    const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> application_send_lock(application_send_mutex_);
    if (len > kBleRelayMessageMax || (len > 0 && data == nullptr)) {
        return false;
    }

    uint16_t conn_handle = 0xFFFF;
    uint16_t notify_val_handle = 0;
    size_t mtu_payload = 0;
    uint32_t generation = 0;
    bool transport_v2 = false;
    uint16_t session_epoch = 0;
    uint16_t seq_start = 0;
    uint8_t initial_window = 1;
    uint8_t max_window = 1;
    size_t chunk_count = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (conn_handle_ == 0xFFFF || notify_val_handle_ == 0 || !notify_subscribed_) return false;
        transport_v2 = transport_v2_active_;
        session_epoch = transport_session_epoch_;
        const uint8_t raw_type = static_cast<uint8_t>(type);
        if ((transport_v2 && (!BleRelayV2IsKnownFrameType(raw_type) ||
                !BleRelayV2HasValidApplicationRoute(raw_type, stream_id, request_id))) ||
            (!transport_v2 && (request_id != 0 || !BleRelayIsKnownFrameType(raw_type)))) return false;
        const size_t header_size = transport_v2 ? sizeof(BleRelayV2FrameHeader) : sizeof(BleRelayFrameHeader);
        const int negotiated_payload = mtu_ - 3 - static_cast<int>(header_size);
        if (negotiated_payload <= 0) return false;
        conn_handle = conn_handle_;
        notify_val_handle = notify_val_handle_;
        generation = connection_generation_.load(std::memory_order_acquire);
        mtu_payload = std::min(
            static_cast<size_t>(kBleRelayFramePayloadMax),
            static_cast<size_t>(negotiated_payload));
        if (transport_v2) {
            if (len > transport_max_message_bytes_ || transport_max_frame_payload_ == 0) return false;
            mtu_payload = std::min(mtu_payload, static_cast<size_t>(transport_max_frame_payload_));
        }
        chunk_count = len == 0 ? 1 : (len + mtu_payload - 1) / mtu_payload;
        if (transport_v2) {
            if (chunk_count > transport_max_fragments_) return false;
            const uint64_t route = BuildRequestHandlerKey(stream_id, request_id);
            auto sequence = v2_tx_sequence_.find(route);
            if (sequence == v2_tx_sequence_.end()) {
                sequence = v2_tx_sequence_.emplace(route, 1).first;
            }
            seq_start = sequence->second;
            sequence->second = static_cast<uint16_t>(sequence->second + chunk_count);
            initial_window = std::min<uint8_t>(transport_initial_window_, kBleTransportMaxWindow);
            max_window = transport_max_window_;
        }
    }

    if (transport_v2) {
        auto fail_active_transport = [this, conn_handle, generation]() {
            if (connection_generation_.load(std::memory_order_acquire) == generation && conn_handle != 0xFFFF) {
                ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
            }
            return false;
        };
        const uint8_t raw_type = static_cast<uint8_t>(type);
        const bool requires_ack = BleRelayV2RequiresAck(raw_type);
        const uint64_t route = BuildRequestHandlerKey(stream_id, request_id);
        size_t offset = 0;
        size_t frame_index = 0;
        uint8_t peer_credit = initial_window;
        while (frame_index < chunk_count) {
            if (peer_credit == 0) {
                std::unique_lock<std::mutex> ack_lock(v2_ack_mutex_);
                const bool restored = v2_ack_cv_.wait_for(
                    ack_lock, std::chrono::seconds(2), [this, route, generation]() {
                        const auto ack = v2_latest_ack_.find(route);
                        return connection_generation_.load(std::memory_order_acquire) != generation ||
                            (ack != v2_latest_ack_.end() && ack->second.credit > 0);
                    });
                if (!restored || connection_generation_.load(std::memory_order_acquire) != generation) {
                    return fail_active_transport();
                }
                peer_credit = v2_latest_ack_[route].credit;
            }
            const size_t window = requires_ack ? BleRelayV2SendWindow(
                initial_window, max_window, peer_credit, chunk_count - frame_index) :
                chunk_count - frame_index;
            std::vector<std::vector<uint8_t>> batch;
            batch.reserve(window);
            uint16_t target_seq = 0;
            for (size_t index = 0; index < window; ++index) {
                const size_t chunk_len = len == 0 ? 0 : std::min(mtu_payload, len - offset);
                const bool final = frame_index + index + 1 == chunk_count;
                const uint8_t chunk_flags = final ? (flags | kBleRelayFlagFinal) : 0;
                const uint16_t seq = static_cast<uint16_t>(seq_start + frame_index + index);
                auto frame = BleRelayBuildV2Frame(raw_type, chunk_flags, session_epoch, stream_id,
                    request_id, seq, chunk_len == 0 ? nullptr : data + offset, chunk_len);
                if (frame.empty()) return fail_active_transport();
                batch.push_back(std::move(frame));
                target_seq = seq;
                offset += chunk_len;
            }

            bool acknowledged = false;
            const int rto_ms[] = {500, 1000, 2000, 2000};
            const size_t attempts = requires_ack ? std::size(rto_ms) : 1;
            for (size_t attempt = 0; attempt < attempts && !acknowledged; ++attempt) {
                if (attempt == 0) {
                    std::lock_guard<std::mutex> ack_lock(v2_ack_mutex_);
                    v2_latest_ack_.erase(route);
                }
                {
                    std::lock_guard<std::recursive_mutex> send_lock(send_mutex_);
                    if (connection_generation_.load(std::memory_order_acquire) != generation) {
                        return fail_active_transport();
                    }
                    for (const auto& frame : batch) {
                        struct os_mbuf* om = ble_hs_mbuf_from_flat(frame.data(), frame.size());
                        if (om == nullptr || ble_gatts_notify_custom(conn_handle, notify_val_handle, om) != 0) {
                            return fail_active_transport();
                        }
                        vTaskDelay(pdMS_TO_TICKS(5));
                    }
                }
                if (!requires_ack) {
                    acknowledged = true;
                    break;
                }
                std::unique_lock<std::mutex> ack_lock(v2_ack_mutex_);
                acknowledged = v2_ack_cv_.wait_for(
                    ack_lock, std::chrono::milliseconds(rto_ms[attempt]), [this, route, target_seq, generation]() {
                        const auto ack = v2_latest_ack_.find(route);
                        return connection_generation_.load(std::memory_order_acquire) != generation ||
                            (ack != v2_latest_ack_.end() && ack->second.seq == target_seq);
                    });
                if (connection_generation_.load(std::memory_order_acquire) != generation) {
                    return fail_active_transport();
                }
                if (acknowledged) peer_credit = v2_latest_ack_[route].credit;
            }
            if (!acknowledged) return fail_active_transport();
            frame_index += window;
        }
        return true;
    }

    std::lock_guard<std::recursive_mutex> send_lock(send_mutex_);
    if (connection_generation_.load(std::memory_order_acquire) != generation) return false;
    size_t offset = 0;
    do {
        if (connection_generation_.load(std::memory_order_acquire) != generation) return false;
        const uint16_t seq = next_seq_++;

        const size_t chunk_len = len == 0 ? 0 : std::min(mtu_payload, len - offset);
        const bool final = offset + chunk_len >= len;
        const uint8_t chunk_flags = final ? (flags | kBleRelayFlagFinal) : 0;
        auto frame = BleRelayBuildFrame(type, chunk_flags, stream_id, seq,
            chunk_len == 0 ? nullptr : data + offset, chunk_len);
        if (frame.empty()) return false;
        struct os_mbuf* om = ble_hs_mbuf_from_flat(frame.data(), frame.size());
        if (om == nullptr || ble_gatts_notify_custom(conn_handle, notify_val_handle, om) != 0) return false;
        offset += chunk_len;
        if (!final) vTaskDelay(pdMS_TO_TICKS(5));
    } while (offset < len);
    return true;
}

bool BleRelayManager::SendFragmentsLocked(BleRelayFrameType type, uint16_t stream_id, uint32_t request_id,
    uint8_t flags, const uint8_t* data, size_t len) {
    std::lock_guard<std::recursive_mutex> send_lock(send_mutex_);
    if (conn_handle_ == 0xFFFF || notify_val_handle_ == 0 || !notify_subscribed_ ||
        len > kBleRelayMessageMax || (len > 0 && data == nullptr)) {
        return false;
    }

    const uint8_t raw_type = static_cast<uint8_t>(type);
    if ((transport_v2_active_ && (!BleRelayV2IsKnownFrameType(raw_type) ||
            !BleRelayV2HasValidApplicationRoute(raw_type, stream_id, request_id))) ||
        (!transport_v2_active_ && (request_id != 0 || !BleRelayIsKnownFrameType(raw_type)))) return false;
    const size_t header_size = transport_v2_active_ ? sizeof(BleRelayV2FrameHeader) : sizeof(BleRelayFrameHeader);
    const int negotiated_payload = mtu_ - 3 - static_cast<int>(header_size);
    if (negotiated_payload <= 0) {
        ESP_LOGE(TAG, "Negotiated MTU %u cannot fit a relay frame", static_cast<unsigned>(mtu_));
        return false;
    }
    const size_t mtu_payload = std::min(
        static_cast<size_t>(kBleRelayFramePayloadMax),
        static_cast<size_t>(negotiated_payload));

    if (len == 0) {
        const uint16_t seq = next_seq_++;
        auto frame = transport_v2_active_ ? BleRelayBuildV2Frame(
            raw_type, flags | kBleRelayFlagFinal, transport_session_epoch_, stream_id, request_id, seq, nullptr, 0) :
            BleRelayBuildFrame(type, flags | kBleRelayFlagFinal, stream_id, seq, nullptr, 0);
        if (frame.empty()) return false;
        struct os_mbuf* om = ble_hs_mbuf_from_flat(frame.data(), frame.size());
        return om != nullptr && ble_gatts_notify_custom(conn_handle_, notify_val_handle_, om) == 0;
    }

    size_t offset = 0;
    while (offset < len) {
        const size_t chunk_len = std::min(mtu_payload, len - offset);
        const uint8_t chunk_flags = (offset + chunk_len >= len) ? (flags | kBleRelayFlagFinal) : 0;
        const uint16_t seq = next_seq_++;
        auto frame = transport_v2_active_ ? BleRelayBuildV2Frame(
            raw_type, chunk_flags, transport_session_epoch_, stream_id, request_id, seq, data + offset, chunk_len) :
            BleRelayBuildFrame(type, chunk_flags, stream_id, seq, data + offset, chunk_len);
        if (frame.empty()) return false;
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
    bool notify_disconnected = false;
    uint16_t terminate_handle = 0xFFFF;

    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT: {
            std::lock_guard<std::mutex> lock(relay->mutex_);
            if (event->connect.status == 0) {
                if (!relay->running_) {
                    terminate_handle = event->connect.conn_handle;
                    break;
                }
                relay->conn_handle_ = event->connect.conn_handle;
                relay->connection_generation_.fetch_add(1, std::memory_order_release);
                relay->mtu_ = 23;
                relay->notify_subscribed_ = false;
                relay->auth_failures_ = 0;
                relay->last_rx_time_us_ = esp_timer_get_time();
                relay->auth_started_time_us_ = 0;
                relay->auth_challenge_active_ = false;
                relay->auth_challenge_consumed_ = false;
                relay->ResetTransportNegotiationLocked();
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
            if (relay->conn_handle_ == 0xFFFF ||
                event->disconnect.conn.conn_handle != relay->conn_handle_) break;
            if (relay->heartbeat_timer_ != nullptr) esp_timer_stop(relay->heartbeat_timer_);
            relay->conn_handle_ = 0xFFFF;
            relay->connection_generation_.fetch_add(1, std::memory_order_release);
            relay->mtu_ = 23;
            relay->notify_subscribed_ = false;
            relay->auth_started_time_us_ = 0;
            relay->auth_challenge_active_ = false;
            relay->auth_challenge_consumed_ = false;
            relay->pending_pair_peer_id_.clear();
            relay->pending_pair_secret_.clear();
            relay->pending_pair_receipt_id_.clear();
            relay->pending_pair_conn_handle_ = 0xFFFF;
            relay->pending_pair_started_time_us_ = 0;
            relay->ResetTransportNegotiationLocked();
            relay->ClearReceiveStateLocked();
            relay->UpdateState(relay->running_ ? RelayLinkState::kDisconnected : RelayLinkState::kDisabled);
            disconnect_cb = relay->disconnect_callback_;
            notify_disconnected = true;
            relay->RestartAdvertisingLocked();
            break;
        }
        case BLE_GAP_EVENT_MTU: {
            std::lock_guard<std::mutex> lock(relay->mutex_);
            if (!relay->running_ || event->mtu.conn_handle != relay->conn_handle_) break;
            relay->mtu_ = event->mtu.value;
            relay->connection_generation_.fetch_add(1, std::memory_order_release);
            break;
        }
        case BLE_GAP_EVENT_SUBSCRIBE: {
            std::lock_guard<std::mutex> lock(relay->mutex_);
            if (!relay->running_ || event->subscribe.conn_handle != relay->conn_handle_) break;
            ESP_LOGI(TAG, "Subscribe event attr=%u notify_handle=%u cur_notify=%d cur_indicate=%d",
                event->subscribe.attr_handle,
                relay->notify_val_handle_,
                event->subscribe.cur_notify,
                event->subscribe.cur_indicate);
            if (event->subscribe.attr_handle != relay->notify_val_handle_) break;
            if (relay->notify_subscribed_ != event->subscribe.cur_notify) {
                relay->connection_generation_.fetch_add(1, std::memory_order_release);
            }
            relay->notify_subscribed_ = event->subscribe.cur_notify;
            if (relay->notify_subscribed_) {
                if (relay->heartbeat_timer_ != nullptr) {
                    esp_timer_stop(relay->heartbeat_timer_);
                    esp_timer_start_periodic(relay->heartbeat_timer_, 5000000);
                }
                ESP_LOGI(TAG, "Notify subscribed by app, sending handshake");
                if (!relay->bound_ || relay->force_pairing_) {
                    pairing_code_cb = relay->pairing_code_callback_;
                    pair_code = relay->pair_code_;
                }
                relay->SendCurrentHandshakeLocked();
            }
            break;
        }
        case BLE_GAP_EVENT_PASSKEY_ACTION: {
            {
                std::lock_guard<std::mutex> lock(relay->mutex_);
                if (!relay->running_ || event->passkey.conn_handle != relay->conn_handle_) {
                    return BLE_HS_EAUTHEN;
                }
            }
            if (event->passkey.params.action != BLE_SM_IOACT_DISP) {
                ESP_LOGE(TAG, "Rejecting unsupported SMP passkey action=%u", event->passkey.params.action);
                return BLE_HS_EAUTHEN;
            }
            ble_sm_io passkey = {};
            passkey.action = BLE_SM_IOACT_DISP;
            {
                std::lock_guard<std::mutex> lock(relay->mutex_);
                if (relay->pair_code_.size() != 6) relay->GeneratePairCodeLocked();
                uint32_t value = 0;
                for (char digit : relay->pair_code_) {
                    value = value * 10 + static_cast<uint32_t>(digit - '0');
                }
                passkey.passkey = value;
                pairing_code_cb = relay->pairing_code_callback_;
                pair_code = relay->pair_code_;
            }
            const int rc = ble_sm_inject_io(event->passkey.conn_handle, &passkey);
            ESP_LOGI(TAG, "Injected SMP display passkey result=%d", rc);
            if (pairing_code_cb && !pair_code.empty()) {
                Application::GetInstance().Schedule([callback = std::move(pairing_code_cb), code = std::move(pair_code)]() {
                    callback(code);
                });
            }
            return rc;
        }
        case BLE_GAP_EVENT_ENC_CHANGE: {
            {
                std::lock_guard<std::mutex> lock(relay->mutex_);
                if (!relay->running_ || event->enc_change.conn_handle != relay->conn_handle_) break;
            }
            ble_gap_conn_desc desc = {};
            const int rc = ble_gap_conn_find(event->enc_change.conn_handle, &desc);
            const bool secure = event->enc_change.status == 0 && rc == 0 &&
                desc.sec_state.encrypted && desc.sec_state.authenticated && desc.sec_state.bonded &&
                desc.sec_state.key_size == 16;
            ESP_LOGI(TAG, "BLE security changed status=%d encrypted=%u authenticated=%u bonded=%u key_size=%u",
                event->enc_change.status,
                rc == 0 ? desc.sec_state.encrypted : 0,
                rc == 0 ? desc.sec_state.authenticated : 0,
                rc == 0 ? desc.sec_state.bonded : 0,
                rc == 0 ? desc.sec_state.key_size : 0);
            if (!secure) terminate_handle = event->enc_change.conn_handle;
            break;
        }
        case BLE_GAP_EVENT_REPEAT_PAIRING: {
            ble_gap_conn_desc desc = {};
            {
                std::lock_guard<std::mutex> lock(relay->mutex_);
                if (!relay->running_ || !relay->force_pairing_ ||
                    event->repeat_pairing.conn_handle != relay->conn_handle_) {
                    return BLE_GAP_REPEAT_PAIRING_IGNORE;
                }
            }
            const int rc = ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc);
            if (rc != 0) return BLE_GAP_REPEAT_PAIRING_IGNORE;
            if (ble_store_util_delete_peer(&desc.peer_id_addr) != 0) {
                return BLE_GAP_REPEAT_PAIRING_IGNORE;
            }
            return BLE_GAP_REPEAT_PAIRING_RETRY;
        }
        default:
            break;
    }

    if (terminate_handle != 0xFFFF) {
        ble_gap_terminate(terminate_handle, BLE_ERR_REM_USER_CONN_TERM);
    }
    if (notify_disconnected) relay->NotifyHandlersDisconnected();
    if (disconnect_cb) {
        Application::GetInstance().Schedule(std::move(disconnect_cb));
    }
    if (pairing_code_cb && !pair_code.empty()) {
        ESP_LOGI(TAG, "Replaying pairing code after BLE handshake event");
        Application::GetInstance().Schedule([callback = std::move(pairing_code_cb), code = std::move(pair_code)]() {
            callback(code);
        });
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
    if (relay.running_) relay.RestartAdvertisingLocked();
}

void BleRelayManager::OnReset(int reason) {
    ESP_LOGE(TAG, "NimBLE reset reason=%d", reason);
    auto& relay = GetInstance();
    std::function<void()> disconnect_cb;
    bool notify_disconnected = false;
    {
        std::lock_guard<std::mutex> lock(relay.mutex_);
        if (relay.heartbeat_timer_ != nullptr) esp_timer_stop(relay.heartbeat_timer_);
        notify_disconnected = relay.conn_handle_ != 0xFFFF;
        relay.conn_handle_ = 0xFFFF;
        relay.connection_generation_.fetch_add(1, std::memory_order_release);
        relay.mtu_ = 23;
        relay.notify_subscribed_ = false;
        relay.auth_started_time_us_ = 0;
        relay.auth_challenge_active_ = false;
        relay.auth_challenge_consumed_ = false;
        relay.ResetTransportNegotiationLocked();
        relay.pending_pair_peer_id_.clear();
        relay.pending_pair_secret_.clear();
        relay.pending_pair_receipt_id_.clear();
        relay.pending_pair_conn_handle_ = 0xFFFF;
        relay.pending_pair_started_time_us_ = 0;
        relay.ClearReceiveStateLocked();
        relay.UpdateState(relay.running_ ? RelayLinkState::kDisconnected : RelayLinkState::kDisabled);
        if (notify_disconnected) disconnect_cb = relay.disconnect_callback_;
    }
    if (notify_disconnected) {
        relay.NotifyHandlersDisconnected();
        if (disconnect_cb) Application::GetInstance().Schedule(std::move(disconnect_cb));
    }
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
        const int rc = os_mbuf_copydata(ctxt->om, 0, data.size(), data.data());
        if (rc != 0) {
            ESP_LOGE(TAG, "Failed to copy BLE write payload: %d", rc);
            return BLE_ATT_ERR_UNLIKELY;
        }
    }
    GetInstance().HandleIncomingData(data.data(), data.size());
    return 0;
}

// 设备名配置特征：读返回 {name,custom,mac}；写为 UTF-8 昵称（≤18 字节），
// 固件保存 NVS 并以 "<XiaoTun>-<昵称>" 重设 GAP 设备名。写需要加密链路（WRITE_AUTHEN），
// 防止路人对公共场合的玩偶恶意改名；读保持开放（名字与 MAC 本就随广播可见）。
int BleRelayManager::GattAccessDeviceName(uint16_t conn_handle, uint16_t attr_handle, ble_gatt_access_ctxt* ctxt, void* arg) {
    auto& relay = GetInstance();
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        std::string custom;
        {
            std::lock_guard<std::mutex> lock(relay.mutex_);
            custom = relay.custom_name_;
        }
        const std::string full = std::string(CONFIG_BLE_RELAY_DEVICE_NAME_PREFIX) + "-" +
            (custom.empty() ? SystemInfo::GetMacAddress().substr(12) : custom);
        cJSON* root = cJSON_CreateObject();
        if (root == nullptr) {
            return BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        AddJsonString(root, "name", full);
        AddJsonString(root, "custom", custom);
        AddJsonString(root, "mac", SystemInfo::GetMacAddress());
        char* json = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        if (json == nullptr) {
            return BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        const int rc = os_mbuf_append(ctxt->om, json, strlen(json));
        cJSON_free(json);
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
        const uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
        if (len == 0 || len > kMaxCustomNameBytes) {
            return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
        }
        std::string value(len, '\0');
        const int rc = os_mbuf_copydata(ctxt->om, 0, len, value.data());
        if (rc != 0) {
            ESP_LOGE(TAG, "Failed to copy device-name write: %d", rc);
            return BLE_ATT_ERR_UNLIKELY;
        }
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
            value.erase(value.begin());
        }
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
            value.pop_back();
        }
        if (!IsValidCustomName(value)) {
            ESP_LOGW(TAG, "Rejected custom device name len=%u", len);
            return BLE_ATT_ERR_VALUE_NOT_ALLOWED;
        }
        const std::string full = std::string(CONFIG_BLE_RELAY_DEVICE_NAME_PREFIX) + "-" + value;
        {
            std::lock_guard<std::mutex> lock(relay.mutex_);
            relay.custom_name_ = value;
            Settings settings(kConnectivityNamespace, true);
            settings.SetString(kBleCustomNameKey, value);
            ble_svc_gap_device_name_set(full.c_str());
            // 传统广播包在连接存续期间不能重启；断连路径会用新名字重建扫描响应。
            if (relay.conn_handle_ == 0xFFFF) {
                relay.RestartAdvertisingLocked();
            } else {
                ESP_LOGI(TAG, "Custom name saved; advertisement updates after disconnect");
            }
        }
        ESP_LOGI(TAG, "Device renamed to %s", full.c_str());
        return 0;
    }
    return BLE_ATT_ERR_UNLIKELY;
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
    uint16_t terminate_handle = 0xFFFF;

    {
        std::lock_guard<std::mutex> lock(relay->mutex_);
        if (!relay->running_ || relay->conn_handle_ == 0xFFFF) {
            return;
        }

        const int64_t now = esp_timer_get_time();
        const bool assembly_expired = std::any_of(
            relay->pending_rx_updated_at_us_.begin(),
            relay->pending_rx_updated_at_us_.end(),
            [now](const auto& entry) { return now - entry.second >= kBleRelayAssemblyTimeoutUs; });
        if (assembly_expired) {
            ESP_LOGE(TAG, "BLE fragmented message assembly timed out");
            relay->ClearReceiveStateLocked();
            relay->UpdateState(RelayLinkState::kError);
            terminate_handle = relay->conn_handle_;
        }
        if (relay->pending_pair_started_time_us_ > 0 &&
            now - relay->pending_pair_started_time_us_ >= kBlePairReceiptTtlUs) {
            ESP_LOGE(TAG, "BLE pair receipt timed out");
            relay->pending_pair_peer_id_.clear();
            relay->pending_pair_secret_.clear();
            relay->pending_pair_receipt_id_.clear();
            relay->pending_pair_conn_handle_ = 0xFFFF;
            relay->pending_pair_started_time_us_ = 0;
            relay->UpdateState(RelayLinkState::kError);
            terminate_handle = relay->conn_handle_;
        }
        if (relay->state_ == RelayLinkState::kAuthenticating &&
            relay->auth_challenge_active_ && relay->auth_started_time_us_ != 0 &&
            now - relay->auth_started_time_us_ > kBleAuthChallengeTtlUs) {
            relay->RejectAuthenticationLocked("authentication timeout");
            terminate_handle = relay->conn_handle_;
        }
        if (relay->transport_commit_sent_ && relay->transport_commit_started_at_us_ > 0 &&
            now - relay->transport_commit_started_at_us_ > kBleTransportNegotiationTtlUs) {
            ESP_LOGE(TAG, "BLE transport V2 activation timed out");
            relay->UpdateState(RelayLinkState::kError);
            terminate_handle = relay->conn_handle_;
        }
        if (terminate_handle == 0xFFFF && relay->last_rx_time_us_ != 0 &&
            now - relay->last_rx_time_us_ > 15000000) {
            ESP_LOGW(TAG, "BLE relay heartbeat timed out");
            relay->UpdateState(RelayLinkState::kError);
            terminate_handle = relay->conn_handle_;
        }
    }

    if (terminate_handle != 0xFFFF) {
        ble_gap_terminate(terminate_handle, BLE_ERR_REM_USER_CONN_TERM);
        return;
    }
    relay->SendJsonFrame(BleRelayFrameType::kHeartbeat, 0, 0, "{}");
}
