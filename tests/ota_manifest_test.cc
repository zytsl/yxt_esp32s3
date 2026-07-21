#include "ota_manifest.h"

#include <cassert>
#include <string>

namespace {
OtaFirmwareManifest ValidManifest() {
    OtaFirmwareManifest manifest;
    manifest.schema_version = 1;
    manifest.version = "1.2.3";
    manifest.url = "https://animodoll.com/releases/1.2.3.bin";
    manifest.sha256 = std::string(64, 'a');
    manifest.size = 1048576;
    manifest.project_name = "xiaozhi";
    manifest.board_type = "movecall-cuican-esp32s3";
    manifest.chip_id = "esp32s3";
    manifest.secure_version = 7;
    manifest.signature = "MEUCIQExampleBase64Signature";
    return manifest;
}
}  // namespace

int main() {
    assert(IsTrustedOtaUrl("https://animodoll.com/firmware.bin"));
    assert(IsTrustedOtaUrl("https://ANIMODOLL.COM.:443/firmware.bin"));
    assert(!IsTrustedOtaUrl("http://animodoll.com/firmware.bin"));
    assert(!IsTrustedOtaUrl("https://animodoll.com:8443/firmware.bin"));
    assert(!IsTrustedOtaUrl("https://animodoll.com.evil.test/firmware.bin"));
    assert(!IsTrustedOtaUrl("https://ota.animodoll.com/firmware.bin"));
    assert(!IsTrustedOtaUrl("https://user@animodoll.com/firmware.bin"));
    assert(!IsTrustedOtaUrl("https://animodoll.com\\@evil.test/firmware.bin"));

    auto manifest = ValidManifest();
    assert(IsValidOtaManifestShape(manifest));
    assert(IsOtaManifestCompatible(
        manifest, "xiaozhi", "movecall-cuican-esp32s3", "esp32s3", 6, 16));
    assert(BuildCanonicalOtaManifest(manifest) ==
        "schema_version=1\n"
        "version=1.2.3\n"
        "url=https://animodoll.com/releases/1.2.3.bin\n"
        "sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "size=1048576\n"
        "project_name=xiaozhi\n"
        "board_type=movecall-cuican-esp32s3\n"
        "chip_id=esp32s3\n"
        "secure_version=7\n");

    manifest.project_name = "animo-doll\nchip_id=esp32";
    assert(!IsValidOtaManifestShape(manifest));
    assert(BuildCanonicalOtaManifest(manifest).empty());

    manifest = ValidManifest();
    manifest.schema_version = 2;
    assert(!IsValidOtaManifestShape(manifest));

    manifest = ValidManifest();
    manifest.secure_version = 16;
    assert(IsOtaManifestCompatible(
        manifest, "xiaozhi", "movecall-cuican-esp32s3", "esp32s3", 16, 16));
    manifest.secure_version = 17;
    assert(!IsOtaManifestCompatible(
        manifest, "xiaozhi", "movecall-cuican-esp32s3", "esp32s3", 16, 16));

    manifest = ValidManifest();
    assert(!IsOtaManifestCompatible(
        manifest, "xiaozhi", "bread-compact-wifi", "esp32s3", 6, 16));

    manifest = ValidManifest();
    manifest.sha256[0] = 'A';
    assert(!IsValidOtaManifestShape(manifest));

    manifest = ValidManifest();
    manifest.size = 0;
    assert(!IsValidOtaManifestShape(manifest));
    return 0;
}
