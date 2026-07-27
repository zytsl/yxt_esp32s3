#include "connectivity/ble_relay_protocol.h"

#include <cassert>
#include <cstdint>
#include <vector>

int main() {
    static_assert(sizeof(BleRelayFrameHeader) == 8);
    static_assert(sizeof(BleRelayV2FrameHeader) == 19);
    static_assert(kBleRelayFramePayloadMax == 180);
    static_assert(kBleRelayRxBufferMax == 4096);
    static_assert(kBleRelayMessageMax == 64 * 1024);
    static_assert(kBleRelayPendingAssembliesMax == 8);
    static_assert(kBleRelayStreamHandlersMax == 8);

    const std::vector<uint8_t> payload = {0x10, 0x20, 0x30};
    const auto frame = BleRelayBuildFrame(
        BleRelayFrameType::kSocketData, kBleRelayFlagFinal, 0x1234, 0xABCD,
        payload.data(), payload.size());
    assert(frame.size() == sizeof(BleRelayFrameHeader) + payload.size());
    assert(frame[0] == static_cast<uint8_t>(BleRelayFrameType::kSocketData));
    assert(frame[1] == kBleRelayFlagFinal);
    assert(BleRelayReadU16(frame.data() + 2) == 0x1234);
    assert(BleRelayReadU16(frame.data() + 4) == 0xABCD);
    assert(BleRelayReadU16(frame.data() + 6) == payload.size());

    const std::vector<uint8_t> oversized(kBleRelayFramePayloadMax + 1, 0xAA);
    assert(BleRelayBuildFrame(
        BleRelayFrameType::kSocketData, 0, 1, 1,
        oversized.data(), oversized.size()).empty());
    assert(BleRelayBuildFrame(
        static_cast<BleRelayFrameType>(0xFF), 0, 1, 1,
        payload.data(), payload.size()).empty());
    assert(BleRelayBuildFrame(
        BleRelayFrameType::kSocketData, 0, 1, 1,
        nullptr, 1).empty());
    assert(!BleRelayBuildFrame(
        BleRelayFrameType::kHeartbeat, kBleRelayFlagFinal, 0, 1,
        nullptr, 0).empty());

    const auto v2 = BleRelayBuildV2Frame(
        static_cast<uint8_t>(BleRelayFrameType::kHttpOpen), kBleRelayFlagFinal,
        0x1234, 0x0102, 0x89ABCDEF, 0x4567, payload.data(), payload.size());
    assert(v2.size() == sizeof(BleRelayV2FrameHeader) + payload.size());
    assert(BleRelayReadU16(v2.data()) == kBleRelayV2Magic);
    assert(v2[2] == kBleRelayV2Version);
    assert(BleRelayReadU16(v2.data() + 5) == 0x1234);
    assert(BleRelayReadU16(v2.data() + 7) == 0x0102);
    assert(BleRelayReadU32(v2.data() + 9) == 0x89ABCDEF);
    assert(BleRelayReadU16(v2.data() + 13) == 0x4567);
    assert(BleRelayReadU16(v2.data() + 17) == 0xC0FC);
    size_t v2_payload_len = 0;
    assert(BleRelayValidateV2Header(v2.data(), v2.size(), &v2_payload_len));
    assert(v2_payload_len == payload.size());
    auto corrupt_v2 = v2;
    corrupt_v2[4] ^= 1;
    assert(!BleRelayValidateV2Header(corrupt_v2.data(), corrupt_v2.size(), nullptr));
    assert(BleRelayBuildV2Frame(
        static_cast<uint8_t>(BleRelayFrameType::kHttpOpen), 0, 1, 1, 0, 1,
        payload.data(), payload.size()).empty());
    assert(BleRelayBuildV2Frame(
        kBleRelayV2AckType, 0, 1, 0, 0, 1, nullptr, 0).empty());
    assert(BleRelayBuildV2Frame(
        kBleRelayV2CancelType, 0, 1, 1, 0, 1, nullptr, 0).empty());
    const auto missing_first = BleRelayV2ClassifySequence(false, 0, 0xFFFF);
    assert(!missing_first.accepted && missing_first.next_expected == 1 && missing_first.acknowledged_seq == 0);
    const auto first_seq = BleRelayV2ClassifySequence(false, 0, 1);
    assert(first_seq.accepted && first_seq.next_expected == 2 && first_seq.acknowledged_seq == 1);
    const auto wrapped_seq = BleRelayV2ClassifySequence(true, 0xFFFF, 0xFFFF);
    assert(wrapped_seq.accepted && wrapped_seq.next_expected == 0);
    const auto duplicate_seq = BleRelayV2ClassifySequence(true, 1, 0);
    assert(!duplicate_seq.accepted && duplicate_seq.acknowledged_seq == 0);
    assert(BleRelayV2SendWindow(8, 32, 0, 20) == 0);
    assert(BleRelayV2SendWindow(8, 32, 32, 20) == 8);
    assert(BleRelayV2RequiresAck(static_cast<uint8_t>(BleRelayFrameType::kHttpOpen)));
    assert(BleRelayV2RequiresAck(kBleRelayV2CancelType));
    assert(!BleRelayV2RequiresAck(kBleRelayV2AckType));
    assert(BleRelayV2HasCanonicalControlEnvelope(kBleRelayV2AckType, kBleRelayFlagFinal, 1));
    assert(!BleRelayV2HasCanonicalControlEnvelope(kBleRelayV2AckType, 0, 1));
    assert(BleRelayV2HasCanonicalControlEnvelope(kBleRelayV2CancelType, kBleRelayFlagFinal, 0));
    assert(BleRelayV2HasValidApplicationRoute(
        static_cast<uint8_t>(BleRelayFrameType::kHttpOpen), kBleRelayHttpStreamId, 1));
    assert(!BleRelayV2HasValidApplicationRoute(
        static_cast<uint8_t>(BleRelayFrameType::kHttpOpen), kBleRelaySocketStreamId, 1));
    assert(BleRelayV2HasValidApplicationRoute(kBleRelayV2CancelType, kBleRelaySocketStreamId, 1));
    return 0;
}
