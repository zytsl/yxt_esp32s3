#ifndef BLE_RELAY_PROTOCOL_H_
#define BLE_RELAY_PROTOCOL_H_

#include <cstddef>
#include <algorithm>
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

struct BleRelayV2FrameHeader {
    uint16_t magic;
    uint8_t version;
    uint8_t type;
    uint8_t flags;
    uint16_t session_epoch;
    uint16_t stream_id;
    uint32_t request_id;
    uint16_t seq;
    uint16_t len;
    uint16_t header_crc;
} __attribute__((packed));

constexpr uint8_t kBleRelayFlagEof = 1 << 0;
constexpr uint8_t kBleRelayFlagError = 1 << 1;
constexpr uint8_t kBleRelayFlagFinal = 1 << 2;

constexpr uint16_t kBleRelayHttpStreamId = 1;
constexpr uint16_t kBleRelaySocketStreamId = 2;
constexpr size_t kBleRelayFramePayloadMax = 180;
constexpr size_t kBleRelayRxBufferMax = 4096;
constexpr size_t kBleRelayMessageMax = 64 * 1024;
constexpr size_t kBleRelayPendingAssembliesMax = 8;
constexpr size_t kBleRelayStreamHandlersMax = 8;
constexpr int64_t kBleRelayAssemblyTimeoutUs = 10 * 1000 * 1000;
constexpr uint16_t kBleRelayV2Magic = 0xA2D2;
constexpr uint8_t kBleRelayV2Version = 2;
constexpr uint8_t kBleRelayV2AckType = 13;
constexpr uint8_t kBleRelayV2CancelType = 14;
constexpr uint8_t kBleRelayV2ProtocolErrorType = 15;
constexpr uint16_t kBleRelayV2NoExpectedSequence = 0;

struct BleRelayV2SequenceDecision {
    bool accepted;
    uint16_t next_expected;
    uint16_t acknowledged_seq;
};

inline BleRelayV2SequenceDecision BleRelayV2ClassifySequence(
    bool has_expected, uint16_t expected, uint16_t received) {
    const uint16_t actual_expected = has_expected ? expected : 1;
    if (received == actual_expected) {
        return {true, static_cast<uint16_t>(received + 1), received};
    }
    return {false, actual_expected, static_cast<uint16_t>(actual_expected - 1)};
}

inline size_t BleRelayV2SendWindow(size_t initial_window, size_t max_window,
    size_t credit, size_t remaining) {
    if (initial_window == 0 || initial_window > 32 || max_window < initial_window ||
        max_window > 32 || credit > 32) return 0;
    return std::min(std::min(initial_window, max_window), std::min(credit, remaining));
}

inline bool BleRelayV2RequiresAck(uint8_t type) {
    return type > static_cast<uint8_t>(BleRelayFrameType::kHeartbeat) &&
        type != kBleRelayV2AckType && type != kBleRelayV2ProtocolErrorType;
}

inline bool BleRelayV2HasValidApplicationRoute(uint8_t type, uint16_t stream_id, uint32_t request_id) {
    if (type <= static_cast<uint8_t>(BleRelayFrameType::kHeartbeat)) {
        return stream_id == 0 && request_id == 0;
    }
    if (type >= static_cast<uint8_t>(BleRelayFrameType::kHttpOpen) &&
        type <= static_cast<uint8_t>(BleRelayFrameType::kHttpResult)) {
        return stream_id == kBleRelayHttpStreamId && request_id != 0;
    }
    if (type >= static_cast<uint8_t>(BleRelayFrameType::kSocketOpen) &&
        type <= static_cast<uint8_t>(BleRelayFrameType::kSocketClose)) {
        return stream_id == kBleRelaySocketStreamId && request_id != 0;
    }
    if (type == kBleRelayV2AckType || type == kBleRelayV2CancelType) {
        return (stream_id == kBleRelayHttpStreamId || stream_id == kBleRelaySocketStreamId) && request_id != 0;
    }
    return type == kBleRelayV2ProtocolErrorType && stream_id == 0 && request_id == 0;
}

inline bool BleRelayIsKnownFrameType(uint8_t type) {
    return type >= static_cast<uint8_t>(BleRelayFrameType::kPairRequest) &&
        type <= static_cast<uint8_t>(BleRelayFrameType::kSocketClose);
}

inline uint16_t BleRelayReadU16(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);
}

inline void BleRelayWriteU16(uint8_t* data, uint16_t value) {
    data[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
    data[1] = static_cast<uint8_t>(value & 0xFF);
}

inline uint32_t BleRelayReadU32(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
        (static_cast<uint32_t>(data[1]) << 16) |
        (static_cast<uint32_t>(data[2]) << 8) |
        static_cast<uint32_t>(data[3]);
}

inline void BleRelayWriteU32(uint8_t* data, uint32_t value) {
    data[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    data[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    data[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    data[3] = static_cast<uint8_t>(value & 0xFF);
}

inline uint16_t BleRelayV2HeaderCrc(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= static_cast<uint16_t>(data[i]) << 8;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 0x8000) != 0
                ? static_cast<uint16_t>((crc << 1) ^ 0x1021)
                : static_cast<uint16_t>(crc << 1);
        }
    }
    return crc;
}

inline bool BleRelayV2IsKnownFrameType(uint8_t type) {
    return type >= static_cast<uint8_t>(BleRelayFrameType::kPairRequest) &&
        type <= kBleRelayV2ProtocolErrorType;
}

inline bool BleRelayV2AllowsZeroRequestId(uint8_t type) {
    return type <= static_cast<uint8_t>(BleRelayFrameType::kHeartbeat) ||
        type == kBleRelayV2ProtocolErrorType;
}

inline bool BleRelayV2HasCanonicalControlEnvelope(uint8_t type, uint8_t flags, size_t payload_len) {
    if (type == kBleRelayV2AckType) return flags == kBleRelayFlagFinal && payload_len == 1;
    if (type == kBleRelayV2CancelType) return flags == kBleRelayFlagFinal && payload_len == 0;
    if (type == kBleRelayV2ProtocolErrorType) return flags == kBleRelayFlagFinal;
    return true;
}

inline std::vector<uint8_t> BleRelayBuildV2Frame(uint8_t type, uint8_t flags, uint16_t session_epoch,
    uint16_t stream_id, uint32_t request_id, uint16_t seq, const uint8_t* payload, size_t len) {
    if (!BleRelayV2IsKnownFrameType(type) || session_epoch == 0 ||
        (request_id == 0 && !BleRelayV2AllowsZeroRequestId(type)) ||
        len > kBleRelayFramePayloadMax || (len > 0 && payload == nullptr)) {
        return {};
    }
    std::vector<uint8_t> frame(sizeof(BleRelayV2FrameHeader) + len);
    BleRelayWriteU16(frame.data(), kBleRelayV2Magic);
    frame[2] = kBleRelayV2Version;
    frame[3] = type;
    frame[4] = flags;
    BleRelayWriteU16(frame.data() + 5, session_epoch);
    BleRelayWriteU16(frame.data() + 7, stream_id);
    BleRelayWriteU32(frame.data() + 9, request_id);
    BleRelayWriteU16(frame.data() + 13, seq);
    BleRelayWriteU16(frame.data() + 15, static_cast<uint16_t>(len));
    BleRelayWriteU16(frame.data() + 17, BleRelayV2HeaderCrc(frame.data(), 17));
    if (len > 0) memcpy(frame.data() + sizeof(BleRelayV2FrameHeader), payload, len);
    return frame;
}

inline bool BleRelayValidateV2Header(const uint8_t* data, size_t available, size_t* payload_len) {
    if (data == nullptr || available < sizeof(BleRelayV2FrameHeader) ||
        BleRelayReadU16(data) != kBleRelayV2Magic || data[2] != kBleRelayV2Version ||
        !BleRelayV2IsKnownFrameType(data[3]) || BleRelayReadU16(data + 5) == 0 ||
        (BleRelayReadU32(data + 9) == 0 && !BleRelayV2AllowsZeroRequestId(data[3])) ||
        BleRelayReadU16(data + 15) > kBleRelayFramePayloadMax ||
        BleRelayReadU16(data + 17) != BleRelayV2HeaderCrc(data, 17)) {
        return false;
    }
    if (payload_len != nullptr) *payload_len = BleRelayReadU16(data + 15);
    return true;
}

inline std::vector<uint8_t> BleRelayBuildFrame(BleRelayFrameType type, uint8_t flags, uint16_t stream_id, uint16_t seq,
    const uint8_t* payload, size_t len) {
    if (!BleRelayIsKnownFrameType(static_cast<uint8_t>(type)) ||
        len > kBleRelayFramePayloadMax || (len > 0 && payload == nullptr)) {
        return {};
    }
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
