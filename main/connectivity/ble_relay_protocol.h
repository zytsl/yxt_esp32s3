#ifndef BLE_RELAY_PROTOCOL_H_
#define BLE_RELAY_PROTOCOL_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

enum class BleRelayFrameType : uint8_t {
    kPairRequest = 1,
    kPairResponse = 2,
    kAuthRequest = 3,
    kAuthResponse = 4,
    kHeartbeat = 5,
    kHttpOpen = 6,
    kHttpBody = 7,
    kHttpResult = 8,
    kSocketOpen = 9,
    kSocketData = 10,
    kSocketEvent = 11,
    kSocketClose = 12,
};

struct BleRelayFrameHeader {
    uint8_t type;
    uint8_t flags;
    uint16_t stream_id;
    uint16_t seq;
    uint16_t len;
} __attribute__((packed));

constexpr uint8_t kBleRelayFlagEof = 1 << 0;
constexpr uint8_t kBleRelayFlagError = 1 << 1;
constexpr uint8_t kBleRelayFlagFinal = 1 << 2;

constexpr uint16_t kBleRelayHttpStreamId = 1;
constexpr uint16_t kBleRelaySocketStreamId = 2;
constexpr size_t kBleRelayFramePayloadMax = 180;

inline uint16_t BleRelayReadU16(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);
}

inline void BleRelayWriteU16(uint8_t* data, uint16_t value) {
    data[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
    data[1] = static_cast<uint8_t>(value & 0xFF);
}

inline std::vector<uint8_t> BleRelayBuildFrame(BleRelayFrameType type, uint8_t flags, uint16_t stream_id, uint16_t seq,
    const uint8_t* payload, size_t len) {
    std::vector<uint8_t> frame(sizeof(BleRelayFrameHeader) + len);
    auto* header = reinterpret_cast<BleRelayFrameHeader*>(frame.data());
    header->type = static_cast<uint8_t>(type);
    header->flags = flags;
    BleRelayWriteU16(reinterpret_cast<uint8_t*>(&header->stream_id), stream_id);
    BleRelayWriteU16(reinterpret_cast<uint8_t*>(&header->seq), seq);
    BleRelayWriteU16(reinterpret_cast<uint8_t*>(&header->len), static_cast<uint16_t>(len));
    if (len > 0) {
        memcpy(frame.data() + sizeof(BleRelayFrameHeader), payload, len);
    }
    return frame;
}

#endif
