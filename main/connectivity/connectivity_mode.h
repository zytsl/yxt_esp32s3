#ifndef CONNECTIVITY_MODE_H_
#define CONNECTIVITY_MODE_H_

enum class ConnectivityMode {
    kWifiDirect = 0,
    kBleRelay = 1,
};

enum class RelayLinkState {
    kDisabled = 0,
    kAdvertising,
    kPairing,
    kAuthenticating,
    kConnected,
    kDisconnected,
    kError,
};

inline const char* ConnectivityModeToString(ConnectivityMode mode) {
    switch (mode) {
        case ConnectivityMode::kWifiDirect:
            return "wifi_direct";
        case ConnectivityMode::kBleRelay:
            return "ble_relay";
        default:
            return "unknown";
    }
}

inline const char* RelayLinkStateToString(RelayLinkState state) {
    switch (state) {
        case RelayLinkState::kDisabled:
            return "disabled";
        case RelayLinkState::kAdvertising:
            return "advertising";
        case RelayLinkState::kPairing:
            return "pairing";
        case RelayLinkState::kAuthenticating:
            return "authenticating";
        case RelayLinkState::kConnected:
            return "connected";
        case RelayLinkState::kDisconnected:
            return "disconnected";
        case RelayLinkState::kError:
            return "error";
        default:
            return "unknown";
    }
}

#endif
