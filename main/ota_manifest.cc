#include "ota_manifest.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace {
constexpr size_t kMaxOtaUrlLength = 2048;
constexpr size_t kMaxVersionLength = 31;
constexpr size_t kMaxIdentityLength = 63;
constexpr size_t kMaxSignatureLength = 1024;

bool HasForbiddenCanonicalCharacter(const std::string& value) {
    return value.find('\n') != std::string::npos || value.find('\r') != std::string::npos ||
        value.find('\0') != std::string::npos;
}

bool IsBoundedCanonicalValue(const std::string& value, size_t max_length) {
    return !value.empty() && value.size() <= max_length && !HasForbiddenCanonicalCharacter(value);
}
}  // namespace

bool IsLowerHexSha256(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

bool IsTrustedOtaUrl(const std::string& firmware_url) {
    if (firmware_url.empty() || firmware_url.size() > kMaxOtaUrlLength ||
        firmware_url.rfind("https://", 0) != 0 || HasForbiddenCanonicalCharacter(firmware_url) ||
        firmware_url.find('\\') != std::string::npos) {
        return false;
    }

    constexpr size_t authority_start = 8;
    const size_t authority_end = firmware_url.find_first_of("/?#", authority_start);
    std::string authority = firmware_url.substr(authority_start, authority_end - authority_start);
    if (authority.empty() || authority.find('@') != std::string::npos || authority.front() == '[') {
        return false;
    }

    std::string host = authority;
    const size_t port_separator = authority.find(':');
    if (port_separator != std::string::npos) {
        if (authority.find(':', port_separator + 1) != std::string::npos ||
            authority.substr(port_separator + 1) != "443") {
            return false;
        }
        host = authority.substr(0, port_separator);
    }
    if (!host.empty() && host.back() == '.') host.pop_back();
    std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return host == "animodoll.com";
}

bool IsValidOtaManifestShape(const OtaFirmwareManifest& manifest) {
    return manifest.schema_version == 1 &&
        IsBoundedCanonicalValue(manifest.version, kMaxVersionLength) &&
        IsTrustedOtaUrl(manifest.url) &&
        IsLowerHexSha256(manifest.sha256) &&
        manifest.size > 0 &&
        IsBoundedCanonicalValue(manifest.project_name, kMaxIdentityLength) &&
        IsBoundedCanonicalValue(manifest.board_type, kMaxIdentityLength) &&
        IsBoundedCanonicalValue(manifest.chip_id, kMaxIdentityLength) &&
        IsBoundedCanonicalValue(manifest.signature, kMaxSignatureLength);
}

bool IsOtaManifestCompatible(
    const OtaFirmwareManifest& manifest,
    const std::string& project_name,
    const std::string& board_type,
    const std::string& chip_id,
    uint32_t current_secure_version,
    uint32_t maximum_secure_version) {
    return IsValidOtaManifestShape(manifest) &&
        manifest.project_name == project_name &&
        manifest.board_type == board_type &&
        manifest.chip_id == chip_id &&
        manifest.secure_version >= current_secure_version &&
        manifest.secure_version <= maximum_secure_version;
}

std::string BuildCanonicalOtaManifest(const OtaFirmwareManifest& manifest) {
    if (!IsValidOtaManifestShape(manifest)) return "";
    std::ostringstream canonical;
    canonical << "schema_version=" << manifest.schema_version << '\n'
              << "version=" << manifest.version << '\n'
              << "url=" << manifest.url << '\n'
              << "sha256=" << manifest.sha256 << '\n'
              << "size=" << manifest.size << '\n'
              << "project_name=" << manifest.project_name << '\n'
              << "board_type=" << manifest.board_type << '\n'
              << "chip_id=" << manifest.chip_id << '\n'
              << "secure_version=" << manifest.secure_version << '\n';
    return canonical.str();
}
