#ifndef OTA_MANIFEST_H_
#define OTA_MANIFEST_H_

#include <cstddef>
#include <cstdint>
#include <string>

struct OtaFirmwareManifest {
    uint32_t schema_version = 0;
    std::string version;
    std::string url;
    std::string sha256;
    uint64_t size = 0;
    std::string project_name;
    std::string board_type;
    std::string chip_id;
    uint32_t secure_version = 0;
    std::string signature;
};

bool IsLowerHexSha256(const std::string& value);
bool IsTrustedOtaUrl(const std::string& firmware_url);
bool IsValidOtaManifestShape(const OtaFirmwareManifest& manifest);
bool IsOtaManifestCompatible(
    const OtaFirmwareManifest& manifest,
    const std::string& project_name,
    const std::string& board_type,
    const std::string& chip_id,
    uint32_t current_secure_version,
    uint32_t maximum_secure_version);
std::string BuildCanonicalOtaManifest(const OtaFirmwareManifest& manifest);

#endif  // OTA_MANIFEST_H_
