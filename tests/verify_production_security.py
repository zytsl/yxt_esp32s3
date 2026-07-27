from pathlib import Path
import base64
import csv
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def parse_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def assert_resolved_production_config(path: Path) -> None:
    config = parse_config(path)
    required = {
        "CONFIG_SECURE_BOOT": "y",
        "CONFIG_SECURE_BOOT_V2_ENABLED": "y",
        "CONFIG_SECURE_FLASH_ENC_ENABLED": "y",
        "CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE": "y",
        "CONFIG_NVS_ENCRYPTION": "y",
        "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE": "y",
        "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK": "y",
    }
    failures = [
        f"{key}={config.get(key)!r}, expected {expected!r}"
        for key, expected in required.items()
        if config.get(key) != expected
    ]
    raw_key = config.get("CONFIG_OTA_MANIFEST_PUBLIC_KEY_BASE64", "").strip('"')
    try:
        decoded_key = base64.b64decode(raw_key, validate=True)
    except Exception as error:
        raise AssertionError(f"Invalid OTA manifest public key in {path}") from error
    if len(decoded_key) < 64 or decoded_key[:1] != b"\x30":
        failures.append("OTA manifest public key is empty or not DER SubjectPublicKeyInfo")
    if failures:
        raise AssertionError(f"Resolved production config is unsafe in {path}: " + "; ".join(failures))


class ProductionSecurityProfileTest(unittest.TestCase):
    def test_security_overlay_is_fail_closed_and_contains_no_private_key(self):
        config = parse_config(ROOT / "ci/sdkconfig.production")
        required = {
            "CONFIG_SECURE_BOOT": "y",
            "CONFIG_SECURE_BOOT_V2_ENABLED": "y",
            "CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES": "n",
            "CONFIG_SECURE_FLASH_ENC_ENABLED": "y",
            "CONFIG_SECURE_FLASH_ENCRYPTION_AES256": "y",
            "CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE": "y",
            "CONFIG_SECURE_DISABLE_ROM_DL_MODE": "y",
            "CONFIG_NVS_ENCRYPTION": "y",
            "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE": "y",
            "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK": "y",
        }
        for key, expected in required.items():
            self.assertEqual(expected, config.get(key), key)
        forbidden_enabled = {
            "CONFIG_SECURE_BOOT_ALLOW_JTAG",
            "CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC",
            "CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_DEC",
            "CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_CACHE",
        }
        for key in forbidden_enabled:
            self.assertNotEqual("y", config.get(key), key)
        text = (ROOT / "ci/sdkconfig.production").read_text(encoding="utf-8").lower()
        self.assertNotIn("private key-----", text)
        self.assertNotIn("secure_boot_signing_key=", text)

    def test_each_production_partition_table_has_encrypted_nvs_keys_and_dual_ota(self):
        for name in ("partitions.production.csv", "partitions_8M.production.csv"):
            rows = []
            with (ROOT / name).open(encoding="utf-8", newline="") as handle:
                for row in csv.reader(line for line in handle if not line.lstrip().startswith("#")):
                    rows.append([cell.strip() for cell in row])
            by_name = {row[0]: row for row in rows}
            self.assertEqual("nvs_keys", by_name["nvs_keys"][2], name)
            self.assertIn("encrypted", by_name["nvs_keys"][5], name)
            self.assertIn("ota_0", by_name, name)
            self.assertIn("ota_1", by_name, name)

    def test_board_overlays_select_only_production_partition_tables(self):
        expected = {
            "ci/sdkconfig.production.bread": '"partitions.production.csv"',
            "ci/sdkconfig.production.movecall": '"partitions_8M.production.csv"',
        }
        for name, partition in expected.items():
            config = parse_config(ROOT / name)
            self.assertEqual(partition, config.get("CONFIG_PARTITION_TABLE_CUSTOM_FILENAME"), name)

    def test_ci_fresh_builds_both_production_profiles_with_protected_ota_key(self):
        workflow = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
        self.assertIn("production-build:", workflow)
        self.assertIn("secrets.OTA_MANIFEST_PUBLIC_KEY_BASE64", workflow)
        self.assertIn("ci/sdkconfig.production", workflow)
        self.assertIn("ci/sdkconfig.production.bread", workflow)
        self.assertIn("ci/sdkconfig.production.movecall", workflow)
        self.assertIn("verify_production_security.py build-production-", workflow)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        assert_resolved_production_config(Path(sys.argv[1]))
        print(f"Resolved production config verified: {sys.argv[1]}")
    else:
        unittest.main()
