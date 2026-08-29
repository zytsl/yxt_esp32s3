#ifndef BLE_RELAY_MANAGER_H_
#define BLE_RELAY_MANAGER_H_

#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <freertos/task.h>
#include <host/ble_uuid.h>

#include <cstdint>
#include <array>
#include <atomic>
#include <functional>
#include <condition_variable>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "ble_relay_protocol.h"
#include "connectivity_mode.h"

struct ble_gap_event;
struct ble_gatt_access_ctxt;
struct ble_gatt_register_ctxt;
struct ble_gatt_svc_def;
struct cJSON;

struct BleRelayEnvelope {
    BleRelayFrameType type = BleRelayFrameType::kHeartbeat;
    uint8_t flags = 0;
    uint16_t session_epoch = 0;
    uint16_t stream_id = 0;
    uint32_t request_id = 0;
    uint16_t seq = 0;
    std::vector<uint8_t> payload;
};

class BleRelayStreamHandler {
public:
    virtual ~BleRelayStreamHandler() = default;
    virtual bool OnBleRelayFrame(BleRelayFrameType type, uint8_t flags, const std::vector<uint8_t>& payload) = 0;
    virtual bool OnBleRelayEnvelope(const BleRelayEnvelope& envelope) {
        if (static_cast<uint8_t>(envelope.type) == kBleRelayV2CancelType) {
            OnBleRelayCancelled();
            return true;
        }
        return OnBleRelayFrame(envelope.type, envelope.flags, envelope.payload);
    }
    virtual void OnBleRelayCancelled() { OnBleRelayDisconnected(); }
    virtual void OnBleRelayDisconnected() {}
    virtual uint8_t AvailableReceiveCredit() const { return 1; }
};

class BleRelayManager {
public:
    static BleRelayManager& GetInstance();

    void Start();
    void Stop();
    bool WaitForReady(int timeout_ms = portMAX_DELAY);
    bool SendFrame(BleRelayFrameType type, uint16_t stream_id, uint8_t flags, const uint8_t* data, size_t len);
    bool SendFrame(BleRelayFrameType type, uint16_t stream_id, uint8_t flags, const std::vector<uint8_t>& payload);
    bool SendJsonFrame(BleRelayFrameType type, uint16_t stream_id, uint8_t flags, const std::string& json);
    bool SendRequestFrame(BleRelayFrameType type, uint16_t stream_id, uint32_t request_id,
        uint8_t flags, const uint8_t* data, size_t len);
    bool SendRequestJsonFrame(BleRelayFrameType type, uint16_t stream_id, uint32_t request_id,
        uint8_t flags, const std::string& json);
    bool RegisterHandler(uint16_t stream_id, BleRelayStreamHandler* handler);
    bool RegisterRequestHandler(uint16_t stream_id, uint32_t request_id, BleRelayStreamHandler* handler);
    void UnregisterHandler(uint16_t stream_id, BleRelayStreamHandler* handler);
    void UnregisterRequestHandler(uint16_t stream_id, uint32_t request_id, BleRelayStreamHandler* handler);
    uint32_t AllocateRequestId();
    bool IsTransportV2() const;
    uint16_t GetTransportSessionEpoch() const;
    void RefreshReceiveCredit(uint16_t stream_id, uint32_t request_id);

    RelayLinkState GetState() const;
    bool IsConnected() const;
    bool IsBound() const;
    bool NeedsPairing() const;
    std::string GetPairCode() const;
    std::string GetPeerId() const;
    std::string GetSecret() const;
    void ClearBinding();
    void SetDisconnectCallback(std::function<void()> callback);
    void SetReadyCallback(std::function<void()> callback);
    void SetPairingCodeCallback(std::function<void(const std::string&)> callback);
    int GetMtu() const;

private:
    BleRelayManager();
    ~BleRelayManager();

    void EnsureInitialized();
    void LoadStateFromNvs();
    void SaveBindingLocked();
    void UpdateState(RelayLinkState state);
    void RestartAdvertisingLocked();
    void StartAdvertisingLocked();
    void HandleIncomingData(const uint8_t* data, size_t len);
    bool DispatchFrame(BleRelayEnvelope envelope);
    void HandlePairResponse(const std::string& json);
    void HandleAuthResponse(const std::string& json);
    void HandleHeartbeat(const std::string& json);
    void ClearReceiveStateLocked();
    void NotifyHandlersDisconnected();
    void SendCurrentHandshakeLocked();
    void ResetTransportNegotiationLocked();
    bool AddTransportOfferLocked(cJSON* root);
    bool AcceptTransportOfferLocked(const cJSON* root);
    bool SendTransportCommit();
    void RunTransportCommitRetries();
    bool SendV2Ack(const BleRelayEnvelope& envelope, uint16_t acknowledged_seq);
    void RejectAuthenticationLocked(const char* reason);
    std::string GeneratePairCodeLocked();
    std::string GenerateSecretLocked();
    bool SendFragments(BleRelayFrameType type, uint16_t stream_id, uint32_t request_id,
        uint8_t flags, const uint8_t* data, size_t len);
    bool SendFragmentsLocked(BleRelayFrameType type, uint16_t stream_id, uint32_t request_id,
        uint8_t flags, const uint8_t* data, size_t len);

    static void HostTask(void* param);
    static int GapEvent(ble_gap_event* event, void* arg);
    static void OnSync();
    static void OnReset(int reason);
    static int GattAccessNotify(uint16_t conn_handle, uint16_t attr_handle, ble_gatt_access_ctxt* ctxt, void* arg);
    static int GattAccessWrite(uint16_t conn_handle, uint16_t attr_handle, ble_gatt_access_ctxt* ctxt, void* arg);
    static int GattAccessDeviceName(uint16_t conn_handle, uint16_t attr_handle, ble_gatt_access_ctxt* ctxt, void* arg);
    static void GattRegister(ble_gatt_register_ctxt* ctxt, void* arg);
    static void HeartbeatTimer(void* arg);
    static BleRelayManager* instance_;

    mutable std::mutex mutex_;
    std::recursive_mutex send_mutex_;
    std::mutex application_send_mutex_;
    std::recursive_mutex handler_callback_mutex_;
    std::mutex v2_ack_mutex_;
    std::condition_variable v2_ack_cv_;
    EventGroupHandle_t event_group_ = nullptr;
    esp_timer_handle_t heartbeat_timer_ = nullptr;
    bool initialized_ = false;
    bool running_ = false;
    RelayLinkState state_ = RelayLinkState::kDisabled;
    bool bound_ = false;
    bool force_pairing_ = false;
    uint8_t transport_floor_ = 1;
    uint16_t conn_handle_ = 0xFFFF;
    std::atomic<uint32_t> connection_generation_{0};
    uint16_t notify_val_handle_ = 0;
    uint16_t next_seq_ = 1;
    uint16_t mtu_ = 23;
    uint8_t own_addr_type_ = 0;
    int auth_failures_ = 0;
    int64_t last_rx_time_us_ = 0;
    int64_t auth_started_time_us_ = 0;
    bool auth_challenge_active_ = false;
    bool auth_challenge_consumed_ = false;
    std::array<uint8_t, 16> auth_session_id_{};
    std::array<uint8_t, 32> auth_device_nonce_{};
    std::string auth_device_id_;
    std::string auth_client_id_;
    std::string pair_code_;
    std::string peer_id_;
    std::string secret_;
    std::string custom_name_;
    std::string pending_pair_peer_id_;
    std::string pending_pair_secret_;
    std::string pending_pair_receipt_id_;
    uint16_t pending_pair_conn_handle_ = 0xFFFF;
    int64_t pending_pair_started_time_us_ = 0;
    std::string transport_offer_id_;
    bool transport_accepted_ = false;
    bool transport_commit_sent_ = false;
    int64_t transport_commit_started_at_us_ = 0;
    TaskHandle_t transport_commit_retry_task_ = nullptr;
    uint8_t transport_initial_window_ = 0;
    uint8_t transport_max_window_ = 0;
    uint8_t transport_max_inflight_requests_ = 0;
    uint16_t transport_max_frame_payload_ = 0;
    uint16_t transport_max_message_bytes_ = 0;
    uint16_t transport_max_fragments_ = 0;
    std::vector<uint8_t> rx_buffer_;
    std::map<uint64_t, std::vector<uint8_t>> pending_rx_frames_;
    std::map<uint64_t, uint16_t> pending_rx_next_seq_;
    std::map<uint64_t, uint16_t> pending_rx_fragment_count_;
    std::map<uint64_t, int64_t> pending_rx_updated_at_us_;
    std::map<uint16_t, BleRelayStreamHandler*> stream_handlers_;
    std::map<uint64_t, BleRelayStreamHandler*> request_handlers_;
    uint16_t transport_session_epoch_ = 0;
    uint32_t next_request_id_ = 1;
    bool transport_v2_active_ = false;
    uint8_t invalid_v2_header_count_ = 0;
    int64_t invalid_v2_header_window_started_at_us_ = 0;
    struct V2AckState {
        uint16_t seq = 0;
        uint8_t credit = 0;
    };
    struct V2RouteTombstone {
        uint16_t acknowledged_seq = 0;
        int64_t expires_at_us = 0;
    };
    std::map<uint64_t, uint16_t> v2_tx_sequence_;
    std::map<uint64_t, uint16_t> v2_rx_expected_sequence_;
    std::map<uint64_t, V2RouteTombstone> v2_route_tombstones_;
    std::map<uint64_t, V2AckState> v2_latest_ack_;
    bool notify_subscribed_ = false;
    std::function<void()> disconnect_callback_;
    std::function<void()> ready_callback_;
    std::function<void(const std::string&)> pairing_code_callback_;

    static ble_uuid128_t service_uuid_;
    static ble_uuid128_t app_to_device_uuid_;
    static ble_uuid128_t device_to_app_uuid_;
    static ble_uuid128_t device_name_uuid_;
};

#endif
