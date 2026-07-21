# OTA manifest v1

The OTA metadata service and firmware signer must use this exact contract. Unknown or missing
required fields do not weaken verification; an unsupported `schema_version` is rejected.

## JSON fields

The `firmware` object contains:

- `schema_version`: integer `1`
- `version`: dotted numeric application version, newer than the running version
- `url`: `https://animodoll.com/...` on effective port 443, without credentials
- `sha256`: lowercase hex SHA-256 of the complete firmware image
- `size`: exact image byte length and exact HTTP `Content-Length`
- `project_name`: ESP-IDF application project name, currently `xiaozhi`
- `board_type`: exact compile-time `BOARD_TYPE`
- `chip_id`: `esp32s3`
- `secure_version`: image anti-rollback secure version, in the inclusive range from the running
  version to `CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD` (16 on ESP32-S3)
- `signature`: base64 DER ECDSA signature produced by the production P-256 key

## Signed bytes

The signer encodes UTF-8 without BOM. Every line ends with a single LF, including the final line.
No escaping, whitespace normalization, or JSON serialization participates in the signature.

```text
schema_version=1
version=<version>
url=<url>
sha256=<sha256>
size=<decimal bytes>
project_name=<project_name>
board_type=<board_type>
chip_id=<chip_id>
secure_version=<decimal secure version>
```

Hash these bytes with SHA-256, sign the digest with ECDSA P-256, DER-encode the `(r,s)` signature,
then base64-encode it into `signature`. The firmware public key is a base64 SubjectPublicKeyInfo
DER value in `CONFIG_OTA_MANIFEST_PUBLIC_KEY_BASE64`. An empty key disables OTA fail-closed.

## Release gates

- Provision the production public key and retain the private key only in the signing service/HSM.
- Serve metadata and images with an exact nonzero `Content-Length`; metadata is limited to 64 KiB.
- Build and sign a distinct manifest for each board type and secure version.
- Existing devices using the historical single `factory` partition cannot receive the new partition
  table through normal app OTA. They require an approved factory/recovery reflash migration and HIL
  evidence before rollout.
- Secure Boot V2, flash encryption, eFuse provisioning, invalid-signature tests, rollback power-loss
  tests, and old-layout migration remain hardware/release gates.
