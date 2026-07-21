#ifndef BLE_RELAY_HTTP_H_
#define BLE_RELAY_HTTP_H_

#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <http.h>

#include "ble_relay_manager.h"

class BleRelayHttp : public Http, public BleRelayStreamHandler {
public:
    BleRelayHttp();
    ~BleRelayHttp() override;

    void SetHeader(const std::string& key, const std::string& value) override;
    bool Open(const std::string& method, const std::string& url, const std::string& content = "") override;
    void Close() override;
    int GetStatusCode() const override;
    std::string GetResponseHeader(const std::string& key) const override;
    size_t GetBodyLength() const override;
    const std::string& GetBody() override;
    int Read(char* buffer, size_t buffer_size) override;
    void SetTimeout(int timeout_ms) override;

    void OnBleRelayFrame(BleRelayFrameType type, uint8_t flags, const std::vector<uint8_t>& payload) override;
    void OnBleRelayDisconnected() override;

private:
    void ResetStateLocked();
    bool WaitForHeadersLocked(std::unique_lock<std::mutex>& lock);
    bool WaitForDataLocked(std::unique_lock<std::mutex>& lock);

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::map<std::string, std::string> headers_;
    std::map<std::string, std::string> response_headers_;
    std::deque<std::vector<uint8_t>> body_chunks_;
    std::string response_body_;
    int status_code_ = 0;
    size_t body_length_ = 0;
    size_t consumed_offset_ = 0;
    size_t queued_body_bytes_ = 0;
    int timeout_ms_ = 15000;
    bool opened_ = false;
    bool headers_ready_ = false;
    bool eof_ = false;
    bool error_ = false;
};

#endif
