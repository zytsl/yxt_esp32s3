import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


FIELD_ORDER = (
    "schema_version",
    "version",
    "url",
    "sha256",
    "size",
    "project_name",
    "board_type",
    "chip_id",
    "secure_version",
)


def canonical_bytes(manifest: dict) -> bytes:
    return "".join(f"{field}={manifest[field]}\n" for field in FIELD_ORDER).encode("utf-8")


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        public_key_file = root / "public.der"
        signature_file = root / "signature.der"
        message_file = root / "manifest.txt"
        public_key_file.write_bytes(public_key)
        signature_file.write_bytes(signature)
        message_file.write_bytes(message)
        result = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(public_key_file),
                "-keyform",
                "DER",
                "-signature",
                str(signature_file),
                str(message_file),
            ],
            check=False,
            capture_output=True,
        )
        return result.returncode == 0


def main() -> None:
    vector = json.loads(Path(__file__).with_name("ota_manifest_v1_vector.json").read_text("utf-8"))
    canonical = canonical_bytes(vector["manifest"])
    assert hashlib.sha256(canonical).hexdigest() == vector["canonical_sha256"]

    public_key = base64.b64decode(vector["public_key_spki_der_base64"], validate=True)
    signature = base64.b64decode(vector["signature_der_base64"], validate=True)
    assert verify(public_key, signature, canonical)
    assert not verify(public_key, signature, canonical.replace(b"size=1048576", b"size=1048577"))


if __name__ == "__main__":
    main()
