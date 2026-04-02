#ifndef BLE_RELAY_TRANSPORT_H_
#define BLE_RELAY_TRANSPORT_H_

#include <condition_variable>
#include <deque>
#include <mutex>
#include <vector>

#include <transport.h>

#include "ble_relay_manager.h"

class BleRelayTransport : public Transport, public BleRelayStreamHandler {
public:
    explicit BleRelayTransport(bool secure);
    ~BleRelayTransport() override;

    bool Connect(const char* host, int port) override;
    void Disconnect() override;
    int Send(const char* data, size_t length) override;
    int Receive(char* buffer, size_t buffer_size) override;

    void OnBleRelayFrame(BleRelayFrameType type, uint8_t flags, const std::vector<uint8_t>& payload) override;
    void OnBleRelayDisconnected() override;

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::vector<uint8_t>> rx_chunks_;
    size_t consumed_offset_ = 0;
    bool opened_ = false;
    bool secure_ = false;
    bool closed_ = false;
    int last_error_ = 0;
};

#endif
