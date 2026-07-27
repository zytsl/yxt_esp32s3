from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANAGER = (ROOT / "main/connectivity/ble_relay_manager.cc").read_text(encoding="utf-8")
HTTP = (ROOT / "main/connectivity/ble_relay_http.cc").read_text(encoding="utf-8")
SOCKET = (ROOT / "main/connectivity/ble_relay_transport.cc").read_text(encoding="utf-8")
APPLICATION = (ROOT / "main/application.cc").read_text(encoding="utf-8")


def parse_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[len("# "): -len(" is not set")]] = "n"
        elif line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def assert_resolved_security_config(path: Path) -> None:
    config = parse_config(path)
    required = {
        "CONFIG_BT_NIMBLE_SECURITY_ENABLE": "y",
        "CONFIG_BT_NIMBLE_SM_LEGACY": "n",
        "CONFIG_BT_NIMBLE_SM_SC": "y",
        "CONFIG_BT_NIMBLE_SM_LVL": "4",
        "CONFIG_BT_NIMBLE_SM_SC_ONLY": "1",
        "CONFIG_BT_NIMBLE_NVS_PERSIST": "y",
    }
    failures = [
        f"{key}={config.get(key)!r}, expected {value!r}"
        for key, value in required.items()
        if config.get(key) != value
    ]
    if failures:
        raise AssertionError(
            f"Resolved BLE security config is unsafe in {path}: " + "; ".join(failures)
        )


class BleSecurityProfileTest(unittest.TestCase):
    def test_nimble_requires_bonding_mitm_and_secure_connections(self):
        for setting in (
            "ble_hs_cfg.sm_bonding = 1",
            "ble_hs_cfg.sm_mitm = 1",
            "ble_hs_cfg.sm_sc = 1",
            "ble_hs_cfg.sm_io_cap = BLE_HS_IO_DISPLAY_ONLY",
            "ble_store_config_init()",
        ):
            self.assertIn(setting, MANAGER)
        for overlay in ("sdkconfig.defaults", "sdkconfig.defaults.esp32s3", "ci/sdkconfig.production"):
            assert_resolved_security_config(ROOT / overlay)

    def test_relay_characteristics_require_authenticated_encryption(self):
        self.assertIn("BLE_GATT_CHR_F_WRITE_AUTHEN", MANAGER)
        self.assertIn("BLE_GATT_CHR_F_NOTIFY_INDICATE_AUTHEN", MANAGER)
        self.assertIn("BLE_GAP_EVENT_PASSKEY_ACTION", MANAGER)
        self.assertIn("desc.sec_state.authenticated", MANAGER)
        self.assertIn("desc.sec_state.key_size == 16", MANAGER)

    def test_transport_v2_retry_and_credit_paths_are_nonblocking_and_fail_closed(self):
        commit_body = MANAGER.split("bool BleRelayManager::SendTransportCommit()", 1)[1].split(
            "void BleRelayManager::RunTransportCommitRetries()", 1
        )[0]
        self.assertNotIn("vTaskDelay", commit_body)
        self.assertIn("RunTransportCommitRetries", MANAGER)
        self.assertLess(MANAGER.index("DispatchFrame(std::move(frame))"), MANAGER.index("SendV2Ack(acknowledgement"))
        self.assertIn("if (error_ || eof_ || (!opening_ && !opened_)) return 0", HTTP)
        self.assertIn("ContainsNul", HTTP)
        self.assertIn("if (closed_ || last_error_ != 0 || (!connecting_ && !connected_)) return 0", SOCKET)
        incoming = MANAGER.split("void BleRelayManager::HandleIncomingData", 1)[1].split(
            "bool BleRelayManager::DispatchFrame", 1
        )[0]
        self.assertIn("callback_barrier(handler_callback_mutex_)", incoming)
        self.assertIn("if (!DispatchFrame(std::move(frame)))", incoming)
        self.assertLess(incoming.index("DispatchFrame(std::move(frame))"), incoming.index("SendV2Ack(acknowledgement"))
        self.assertIn("raw_type == kBleRelayV2CancelType", incoming)
        socket_callback = SOCKET.split("bool BleRelayTransport::OnBleRelayFrame", 1)[1].split(
            "void BleRelayTransport::OnBleRelayDisconnected", 1
        )[0]
        self.assertIn("return accepted && !overflow", socket_callback)
        self.assertNotIn("SendRequestFrame", socket_callback)
        self.assertNotIn("SendRequestJsonFrame", socket_callback)
        self.assertIn("relay.IsTransportV2()", APPLICATION)
        self.assertIn("? BleRelayFrameType::kHeartbeat", APPLICATION)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        assert_resolved_security_config(Path(sys.argv[1]))
        print(f"Resolved BLE security config verified: {sys.argv[1]}")
    else:
        unittest.main()
