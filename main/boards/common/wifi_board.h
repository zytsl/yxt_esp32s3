#ifndef WIFI_BOARD_H
#define WIFI_BOARD_H

#include "board.h"

class WifiBoard : public Board {
protected:
    bool wifi_config_mode_ = false;
    ConnectivityMode connectivity_mode_ = ConnectivityMode::kWifiDirect;

    WifiBoard();
    void EnterWifiConfigMode();
    void EnterBleRelayMode(bool force_pairing = false);
    void ShowBleRelayHint(bool pairing);
    virtual std::string GetBoardJson() override;

public:
    virtual std::string GetBoardType() override;
    virtual void StartNetwork() override;
    virtual Http* CreateHttp() override;
    virtual WebSocket* CreateWebSocket(const std::string& url) override;
    virtual Mqtt* CreateMqtt() override;
    virtual Udp* CreateUdp() override;
    virtual const char* GetNetworkStateIcon() override;
    virtual void SetPowerSaveMode(bool enabled) override;
    virtual ConnectivityMode GetConnectivityMode() const override;
    virtual bool IsNetworkReady() const override;
    virtual void ResetWifiConfiguration();
    virtual void ResetBleConfiguration();
    virtual void ToggleConnectivityMode();
};

#endif // WIFI_BOARD_H
