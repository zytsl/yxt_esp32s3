#include "wifi_board.h"

#include "ble_relay_http.h"
#include "ble_relay_manager.h"
#include "ble_relay_transport.h"
#include "display.h"
#include "application.h"
#include "system_info.h"
#include "font_awesome_symbols.h"
#include "settings.h"
#include "assets/lang_config.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_http.h>
#include <esp_mqtt.h>
#include <esp_udp.h>
#include <tcp_transport.h>
#include <tls_transport.h>
#include <web_socket.h>
#include <esp_log.h>

#include <wifi_manager.h>
#include <ssid_manager.h>
#include <esp_sntp.h>
#include <algorithm>
#include <array>
#include <time.h>

static const char *TAG = "WifiBoard";

namespace {
constexpr const char* kConnectivityNamespace = "connectivity";
constexpr const char* kPreferredModeKey = "preferred_mode";
constexpr bool kForceBleDebugPairing = false;
}

WifiBoard::WifiBoard() {
    Settings settings("wifi", true);
    wifi_config_mode_ = settings.GetInt("force_ap") == 1;
    if (wifi_config_mode_) {
        ESP_LOGI(TAG, "force_ap is set to 1, reset to 0");
        settings.SetInt("force_ap", 0);
    }

    Settings connectivity_settings(kConnectivityNamespace, true);
    if (kForceBleDebugPairing) {
        connectivity_mode_ = ConnectivityMode::kBleRelay;
        connectivity_settings.SetInt(kPreferredModeKey, static_cast<int32_t>(connectivity_mode_));
        ESP_LOGW(TAG, "Force BLE debug pairing is enabled, overriding preferred mode to %s",
            ConnectivityModeToString(connectivity_mode_));
        return;
    }

    int preferred_mode = connectivity_settings.GetInt(kPreferredModeKey, -1);
    if (preferred_mode < 0) {
        connectivity_mode_ = SsidManager::GetInstance().GetSsidList().empty()
            ? ConnectivityMode::kBleRelay
            : ConnectivityMode::kWifiDirect;
        connectivity_settings.SetInt(kPreferredModeKey, static_cast<int32_t>(connectivity_mode_));
        ESP_LOGI(TAG, "No preferred connectivity mode in settings, defaulting to %s",
            ConnectivityModeToString(connectivity_mode_));
    } else {
        connectivity_mode_ = preferred_mode == static_cast<int>(ConnectivityMode::kBleRelay)
            ? ConnectivityMode::kBleRelay
            : ConnectivityMode::kWifiDirect;
        ESP_LOGI(TAG, "Loaded preferred connectivity mode: %s (raw=%d)",
            ConnectivityModeToString(connectivity_mode_), preferred_mode);
    }
}

std::string WifiBoard::GetBoardType() {
    return "wifi";
}

void WifiBoard::EnterWifiConfigMode() {
    auto& application = Application::GetInstance();
    application.SetDeviceState(kDeviceStateWifiConfiguring);

    auto& wifi_manager = WifiManager::GetInstance();
    if (!wifi_manager.IsInitialized()) {
        WifiManagerConfig config;
        config.ssid_prefix = "XiaoTun";
        config.language = Lang::CODE;
        wifi_manager.Initialize(config);
    }
    wifi_manager.StartConfigAp();

    // 显示 WiFi 配置 AP 的 SSID 和 Web 服务器 URL
    std::string hint = Lang::Strings::CONNECT_TO_HOTSPOT;
    hint += wifi_manager.GetApSsid();
    hint += Lang::Strings::ACCESS_VIA_BROWSER;
    hint += wifi_manager.GetApWebUrl();
    hint += "\n\n";
    
    // 播报配置 WiFi 的提示
    application.Alert(Lang::Strings::WIFI_CONFIG_MODE, hint.c_str(), "", Lang::Sounds::P3_WIFICONFIG);
    
    // Wait forever until reset after configuration
    while (true) {
        int free_sram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        int min_free_sram = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
        ESP_LOGI(TAG, "Free internal: %u minimal internal: %u", free_sram, min_free_sram);
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}

void WifiBoard::ShowBleRelayHint(bool pairing) {
    auto& application = Application::GetInstance();
    auto display = GetDisplay();
    std::string hint = pairing ? std::string(Lang::Strings::PAIR_PHONE) : std::string(Lang::Strings::WAITING_PHONE);

    if (pairing) {
        auto pair_code = BleRelayManager::GetInstance().GetPairCode();
        hint += "\n";
        hint += Lang::Strings::BLE_PAIR_CODE;
        hint += pair_code;
        application.ShowPairCode(pair_code, hint);
    } else {
        display->SetStatus(Lang::Strings::BLE_RELAY_MODE);
        display->SetChatMessage("system", hint.c_str());
    }
}

void WifiBoard::EnterBleRelayMode(bool force_pairing) {
    ESP_LOGI(TAG, "Entering BLE relay mode%s", force_pairing ? " with force pairing" : "");
    auto& application = Application::GetInstance();
    application.SetDeviceState(kDeviceStateBleConfiguring);

    auto& relay = BleRelayManager::GetInstance();
    relay.SetDisconnectCallback([this]() {
        if (connectivity_mode_ != ConnectivityMode::kBleRelay) {
            return;
        }

        auto& app = Application::GetInstance();
        auto state = app.GetDeviceState();
        if (state == kDeviceStateStarting || state == kDeviceStateUpgrading) {
            return;
        }
        app.SetDeviceState(kDeviceStateBleConfiguring);
        GetDisplay()->ShowNotification(Lang::Strings::WAITING_PHONE, 3000);
    });
    relay.SetReadyCallback([this]() {
        if (connectivity_mode_ == ConnectivityMode::kBleRelay) {
            auto& app = Application::GetInstance();
            if (app.IsRuntimeReady() && app.GetDeviceState() == kDeviceStateBleConfiguring) {
                ESP_LOGI(TAG, "BLE relay reconnected after app-side disconnect, restoring device state to idle");
                app.SetDeviceState(kDeviceStateIdle);
            }
            GetDisplay()->ShowNotification(Lang::Strings::BLE_CONNECTED, 3000);
            app.NotifyBleRelayDeviceState();
        }
    });
    relay.SetPairingCodeCallback([this](const std::string& pair_code) {
        if (connectivity_mode_ != ConnectivityMode::kBleRelay || pair_code.empty()) {
            return;
        }
        std::string hint = std::string(Lang::Strings::PAIR_PHONE) + "\n" + Lang::Strings::BLE_PAIR_CODE + pair_code;
        Application::GetInstance().ShowPairCode(pair_code, hint);
    });
    relay.Start();
    if (force_pairing) {
        ESP_LOGI(TAG, "BLE relay started, clearing binding to force pairing");
        relay.ClearBinding();
    }

    ShowBleRelayHint(relay.NeedsPairing());
    relay.WaitForReady(portMAX_DELAY);
}

void WifiBoard::StartNetwork() {
    ESP_LOGI(TAG, "StartNetwork with connectivity mode: %s",
        ConnectivityModeToString(connectivity_mode_));
    if (kForceBleDebugPairing) {
        ESP_LOGW(TAG, "Force BLE debug pairing is enabled, entering BLE relay mode with forced pairing");
        EnterBleRelayMode(true);
        return;
    }

    if (connectivity_mode_ == ConnectivityMode::kBleRelay) {
        EnterBleRelayMode();
        return;
    }

    // User can press BOOT button while starting to enter WiFi configuration mode
    if (wifi_config_mode_) {
        EnterWifiConfigMode();
        return;
    }

    // If no WiFi SSID is configured, enter WiFi configuration mode
    auto& ssid_manager = SsidManager::GetInstance();
    auto ssid_list = ssid_manager.GetSsidList();
    if (ssid_list.empty()) {
        wifi_config_mode_ = true;
        EnterWifiConfigMode();
        return;
    }

    auto& wifi_manager = WifiManager::GetInstance();
    WifiManagerConfig config;
    config.ssid_prefix = "XiaoTun";
    config.language = Lang::CODE;
    wifi_manager.Initialize(config);

    wifi_manager.SetEventCallback([this](WifiEvent event) {
        auto display = Board::GetInstance().GetDisplay();
        std::string notification;
        switch (event) {
            case WifiEvent::Scanning:
                display->ShowNotification(Lang::Strings::SCANNING_WIFI, 30000);
                break;
            case WifiEvent::Connecting:
                notification = Lang::Strings::CONNECT_TO;
                notification += "..."; // Ssid not easily available in event arg
                display->ShowNotification(notification.c_str(), 30000);
                break;
            case WifiEvent::Connected:
                notification = Lang::Strings::CONNECTED_TO;
                notification += WifiManager::GetInstance().GetSsid();
                display->ShowNotification(notification.c_str(), 30000);
                break;
            default:
                break;
        }
    });
    
    wifi_manager.StartStation();

    // Try to connect to WiFi, if failed, launch the WiFi configuration AP
    // Block for 60 seconds manually
    int timeout_ticks = 60 * 1000 / 100;
    while (timeout_ticks > 0) {
        if (wifi_manager.IsConnected()) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
        timeout_ticks--;
    }

    if (!wifi_manager.IsConnected()) {
        wifi_manager.StopStation();
        wifi_config_mode_ = true;
        EnterWifiConfigMode();
        return;
    }

    // Initialize SNTP
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_setservername(1, "ntp.aliyun.com");
    esp_sntp_init();

    // Set timezone to China Standard Time
    setenv("TZ", "CST-8", 1);
    tzset();
}

Http* WifiBoard::CreateHttp() {
    if (connectivity_mode_ == ConnectivityMode::kBleRelay) {
        return new BleRelayHttp();
    }
    return new EspHttp();
}

WebSocket* WifiBoard::CreateWebSocket(const std::string& url) {
    if (connectivity_mode_ == ConnectivityMode::kBleRelay) {
        return new WebSocket(new BleRelayTransport(url.find("wss://") == 0));
    }
    if (url.find("wss://") == 0) {
        return new WebSocket(new TlsTransport());
    }
    return new WebSocket(new TcpTransport());
}

Mqtt* WifiBoard::CreateMqtt() {
    if (connectivity_mode_ == ConnectivityMode::kBleRelay) {
        return nullptr;
    }
    return new EspMqtt();
}

Udp* WifiBoard::CreateUdp() {
    if (connectivity_mode_ == ConnectivityMode::kBleRelay) {
        return nullptr;
    }
    return new EspUdp();
}

const char* WifiBoard::GetNetworkStateIcon() {
    if (connectivity_mode_ == ConnectivityMode::kBleRelay) {
        return FONT_AWESOME_BLUETOOTH;
    }
    if (wifi_config_mode_) {
        return FONT_AWESOME_WIFI;
    }
    auto& wifi_manager = WifiManager::GetInstance();
    if (!wifi_manager.IsConnected()) {
        return FONT_AWESOME_WIFI_OFF;
    }
    int rssi = wifi_manager.GetRssi();
    if (rssi >= -60) {
        return FONT_AWESOME_WIFI;
    } else if (rssi >= -70) {
        return FONT_AWESOME_WIFI_FAIR;
    } else {
        return FONT_AWESOME_WIFI_WEAK;
    }
}

std::string WifiBoard::GetBoardJson() {
    // Set the board type for OTA
    auto& wifi_manager = WifiManager::GetInstance();
    std::string board_json = std::string("{\"type\":\"" BOARD_TYPE "\",");
    board_json += "\"name\":\"" BOARD_NAME "\",";
    board_json += "\"connectivity_mode\":\"" + std::string(ConnectivityModeToString(connectivity_mode_)) + "\",";
    if (connectivity_mode_ == ConnectivityMode::kBleRelay) {
        auto& relay = BleRelayManager::GetInstance();
        board_json += "\"ble_state\":\"" + std::string(RelayLinkStateToString(relay.GetState())) + "\",";
        board_json += "\"ble_bound\":" + std::to_string(relay.IsBound() ? 1 : 0) + ",";
    } else if (!wifi_config_mode_) {
        board_json += "\"ssid\":\"" + wifi_manager.GetSsid() + "\",";
        board_json += "\"rssi\":" + std::to_string(wifi_manager.GetRssi()) + ",";
        board_json += "\"channel\":" + std::to_string(wifi_manager.GetChannel()) + ",";
        board_json += "\"ip\":\"" + wifi_manager.GetIpAddress() + "\",";
    }
    board_json += "\"mac\":\"" + SystemInfo::GetMacAddress() + "\"}";
    return board_json;
}

void WifiBoard::SetPowerSaveMode(bool enabled) {
    if (connectivity_mode_ == ConnectivityMode::kBleRelay) {
        return;
    }
    auto& wifi_manager = WifiManager::GetInstance();
    wifi_manager.SetPowerSaveLevel(enabled ? WifiPowerSaveLevel::BALANCED : WifiPowerSaveLevel::PERFORMANCE);
}

ConnectivityMode WifiBoard::GetConnectivityMode() const {
    return connectivity_mode_;
}

bool WifiBoard::IsNetworkReady() const {
    if (connectivity_mode_ == ConnectivityMode::kBleRelay) {
        return BleRelayManager::GetInstance().IsConnected();
    }
    return WifiManager::GetInstance().IsConnected();
}

void WifiBoard::ResetWifiConfiguration() {
    // Set a flag and reboot the device to enter the network configuration mode
    {
        Settings settings("wifi", true);
        settings.SetInt("force_ap", 1);
    }
    {
        Settings settings(kConnectivityNamespace, true);
        settings.SetInt(kPreferredModeKey, static_cast<int32_t>(ConnectivityMode::kWifiDirect));
    }
    GetDisplay()->ShowNotification(Lang::Strings::ENTERING_WIFI_CONFIG_MODE);
    vTaskDelay(pdMS_TO_TICKS(1000));
    // Reboot the device
    esp_restart();
}

void WifiBoard::ResetBleConfiguration() {
    {
        Settings settings(kConnectivityNamespace, true);
        settings.SetInt(kPreferredModeKey, static_cast<int32_t>(ConnectivityMode::kBleRelay));
    }
    BleRelayManager::GetInstance().ClearBinding();
    GetDisplay()->ShowNotification(Lang::Strings::BLE_BIND_CLEARED);
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
}

void WifiBoard::ToggleConnectivityMode() {
    connectivity_mode_ = connectivity_mode_ == ConnectivityMode::kBleRelay
        ? ConnectivityMode::kWifiDirect
        : ConnectivityMode::kBleRelay;
    ESP_LOGI(TAG, "Toggling connectivity mode to %s",
        ConnectivityModeToString(connectivity_mode_));
    {
        Settings settings(kConnectivityNamespace, true);
        settings.SetInt(kPreferredModeKey, static_cast<int32_t>(connectivity_mode_));
    }
    GetDisplay()->ShowNotification(connectivity_mode_ == ConnectivityMode::kBleRelay
        ? Lang::Strings::SWITCH_TO_BLE
        : Lang::Strings::SWITCH_TO_WIFI);
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
}
