#ifndef BLE_RELAY_MANAGER_H_
#define BLE_RELAY_MANAGER_H_

#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <host/ble_uuid.h>

#include <cstdint>
#include <array>
#include <functional>
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

class BleRelayStreamHandler {
public:
    virtual ~BleRelayStreamHandler() = default;
    virtual void OnBleRelayFrame(BleRelayFrameType type, uint8_t flags, const std::vector<uint8_t>& payload) = 0;
    virtual void OnBleRelayDisconnected() {}
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
    void RegisterHandler(uint16_t stream_id, BleRelayStreamHandler* handler);
    void UnregisterHandler(uint16_t stream_id, BleRelayStreamHandler* handler);

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
    void DispatchFrame(BleRelayFrameType type, uint8_t flags, uint16_t stream_id, const uint8_t* data, size_t len);
    void HandlePairResponse(const std::string& json);
    void HandleAuthResponse(const std::string& json);
    void HandleHeartbeat();
    void NotifyHandlersDisconnectedLocked();
    void SendCurrentHandshakeLocked();
    void RejectAuthenticationLocked(const char* reason);
    std::string GeneratePairCodeLocked();
    std::string GenerateSecretLocked();
    bool SendFragmentsLocked(BleRelayFrameType type, uint16_t stream_id, uint8_t flags, const uint8_t* data, size_t len);

    static void HostTask(void* param);
    static int GapEvent(ble_gap_event* event, void* arg);
    static void OnSync();
    static void OnReset(int reason);
    static int GattAccessNotify(uint16_t conn_handle, uint16_t attr_handle, ble_gatt_access_ctxt* ctxt, void* arg);
    static int GattAccessWrite(uint16_t conn_handle, uint16_t attr_handle, ble_gatt_access_ctxt* ctxt, void* arg);
    static void GattRegister(ble_gatt_register_ctxt* ctxt, void* arg);
    static void HeartbeatTimer(void* arg);
    static BleRelayManager* instance_;

    mutable std::mutex mutex_;
    EventGroupHandle_t event_group_ = nullptr;
    esp_timer_handle_t heartbeat_timer_ = nullptr;
    bool initialized_ = false;
    RelayLinkState state_ = RelayLinkState::kDisabled;
    bool bound_ = false;
    bool force_pairing_ = false;
    uint16_t conn_handle_ = 0xFFFF;
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
    std::vector<uint8_t> rx_buffer_;
    std::map<uint32_t, std::vector<uint8_t>> pending_rx_frames_;
    std::map<uint32_t, uint16_t> pending_rx_next_seq_;
    std::map<uint16_t, BleRelayStreamHandler*> stream_handlers_;
    std::function<void()> disconnect_callback_;
    std::function<void()> ready_callback_;
    std::function<void(const std::string&)> pairing_code_callback_;

    static ble_uuid128_t service_uuid_;
    static ble_uuid128_t app_to_device_uuid_;
    static ble_uuid128_t device_to_app_uuid_;
};

#endif
