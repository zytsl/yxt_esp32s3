#include "ota.h"
#include "system_info.h"
#include "settings.h"
#include "assets/lang_config.h"

#include <cJSON.h>
#include <esp_log.h>
#include <esp_partition.h>
#include <esp_ota_ops.h>
#include <esp_app_format.h>
#include <esp_efuse.h>
#include <esp_efuse_table.h>
#include <esp_system.h>
#include <nvs.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
extern "C" {
#include <mbedtls/constant_time.h>
}
#ifdef SOC_HMAC_SUPPORTED
#include <esp_hmac.h>
#endif

#include <cstring>
#include <cctype>
#include <cmath>
#include <limits>
#include <vector>
#include <sstream>
#include <algorithm>

#define TAG "Ota"

namespace {
constexpr size_t kMaxOtaCheckResponseBytes = 64 * 1024;

bool PersistRecoveryRequired() {
    nvs_handle_t handle = 0;
    esp_err_t result = nvs_open("ota_security", NVS_READWRITE, &handle);
    if (result == ESP_OK) {
        result = nvs_set_i32(handle, "recovery_required", 1);
    }
    if (result == ESP_OK) {
        result = nvs_commit(handle);
    }
    if (handle != 0) {
        nvs_close(handle);
    }
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "Failed to persist OTA recovery requirement: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

bool DecodeSha256(const std::string& value, uint8_t output[32]) {
    if (!IsLowerHexSha256(value)) return false;
    auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    for (size_t i = 0; i < 32; ++i) {
        output[i] = static_cast<uint8_t>((nibble(value[i * 2]) << 4) | nibble(value[i * 2 + 1]));
    }
    return true;
}

bool DecodeBase64(const std::string& value, size_t max_decoded_size, std::vector<uint8_t>* output) {
    if (value.empty() || value.size() > max_decoded_size * 2) return false;
    output->assign(max_decoded_size, 0);
    size_t decoded_size = 0;
    if (mbedtls_base64_decode(output->data(), output->size(), &decoded_size,
            reinterpret_cast<const uint8_t*>(value.data()), value.size()) != 0 || decoded_size == 0) {
        output->clear();
        return false;
    }
    output->resize(decoded_size);
    return true;
}

bool ReadUnsignedJson(cJSON* item, uint64_t maximum, uint64_t* output) {
    if (!cJSON_IsNumber(item) || !std::isfinite(item->valuedouble) || item->valuedouble < 0 ||
        item->valuedouble > static_cast<double>(maximum) || std::floor(item->valuedouble) != item->valuedouble) {
        return false;
    }
    *output = static_cast<uint64_t>(item->valuedouble);
    return true;
}

bool VerifyManifestSignature(const OtaFirmwareManifest& manifest) {
    const std::string canonical = BuildCanonicalOtaManifest(manifest);
    const std::string public_key_base64 = CONFIG_OTA_MANIFEST_PUBLIC_KEY_BASE64;
    if (canonical.empty() || public_key_base64.empty()) {
        ESP_LOGE(TAG, "OTA manifest public key is not provisioned");
        return false;
    }

    std::vector<uint8_t> public_key;
    std::vector<uint8_t> signature;
    if (!DecodeBase64(public_key_base64, 2048, &public_key) ||
        !DecodeBase64(manifest.signature, 512, &signature)) {
        ESP_LOGE(TAG, "OTA manifest key or signature is not valid base64 DER");
        return false;
    }

    uint8_t digest[32];
    mbedtls_sha256_context sha256;
    mbedtls_sha256_init(&sha256);
    const bool digest_ok = mbedtls_sha256_starts(&sha256, 0) == 0 &&
        mbedtls_sha256_update(&sha256, reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size()) == 0 &&
        mbedtls_sha256_finish(&sha256, digest) == 0;
    mbedtls_sha256_free(&sha256);
    if (!digest_ok) return false;

    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    const bool verified = mbedtls_pk_parse_public_key(&key, public_key.data(), public_key.size()) == 0 &&
        mbedtls_pk_can_do(&key, MBEDTLS_PK_ECDSA) &&
        mbedtls_pk_get_bitlen(&key) == 256 &&
        mbedtls_pk_verify(&key, MBEDTLS_MD_SHA256, digest, sizeof(digest),
            signature.data(), signature.size()) == 0;
    mbedtls_pk_free(&key);
    if (!verified) ESP_LOGE(TAG, "OTA manifest signature verification failed");
    return verified;
}

bool ManifestMatchesBuild(const OtaFirmwareManifest& manifest) {
    const esp_app_desc_t* current = esp_app_get_description();
    return IsOtaManifestCompatible(
        manifest,
        current->project_name,
        BOARD_TYPE,
        "esp32s3",
        current->secure_version,
        CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD);
}
}


Ota::Ota() {
    Settings ota_security("ota_security", false);
    recovery_required_ = ota_security.GetInt("recovery_required", 0) == 1;
#ifdef ESP_EFUSE_BLOCK_USR_DATA
    // Read Serial Number from efuse user_data
    uint8_t serial_number[33] = {0};
    if (esp_efuse_read_field_blob(ESP_EFUSE_USER_DATA, serial_number, 32 * 8) == ESP_OK) {
        if (serial_number[0] == 0) {
            has_serial_number_ = false;
        } else {
            serial_number_ = std::string(reinterpret_cast<char*>(serial_number), 32);
            has_serial_number_ = true;
        }
    }
#endif
}

Ota::~Ota() {
}

std::string Ota::GetCheckVersionUrl() {
    Settings settings("wifi", false);
    std::string url = settings.GetString("ota_url");
    if (url.empty()) {
        url = CONFIG_OTA_URL;
    }
    return url;
}

std::unique_ptr<Http> Ota::SetupHttp() {
    auto& board = Board::GetInstance();
    auto http = board.CreateHttp();
    auto user_agent = SystemInfo::GetUserAgent();
    http->SetHeader("Activation-Version", has_serial_number_ ? "2" : "1");
    http->SetHeader("Device-Id", SystemInfo::GetMacAddress().c_str());
    http->SetHeader("Client-Id", board.GetUuid());
    if (has_serial_number_) {
        http->SetHeader("Serial-Number", serial_number_.c_str());
        ESP_LOGI(TAG, "Setup HTTP, User-Agent: %s, Serial-Number: %s", user_agent.c_str(), serial_number_.c_str());
    }
    http->SetHeader("User-Agent", user_agent);
    http->SetHeader("Accept-Language", Lang::CODE);
    http->SetHeader("Content-Type", "application/json");

    return std::unique_ptr<Http>(http);
}

/* 
 * Specification: https://ccnphfhqs21z.feishu.cn/wiki/FjW6wZmisimNBBkov6OcmfvknVd
 */
esp_err_t Ota::CheckVersion() {
    auto& board = Board::GetInstance();
    auto app_desc = esp_app_get_description();

    // Check if there is a new firmware version available
    current_version_ = app_desc->version;
    ESP_LOGI(TAG, "Current version: %s", current_version_.c_str());

    std::string url = GetCheckVersionUrl();
    if (url.length() < 10) {
        ESP_LOGE(TAG, "Check version URL is not properly set");
        return ESP_ERR_INVALID_ARG;
    }
    if (!IsTrustedOtaUrl(url)) {
        ESP_LOGE(TAG, "OTA check URL is not on the production HTTPS allowlist");
        return ESP_ERR_INVALID_ARG;
    }

    auto http = SetupHttp();

    std::string data = board.GetJson();
    std::string method = data.length() > 0 ? "POST" : "GET";

    if (data.length() > 0) {
        ESP_LOGI(TAG, "Sending OTA check metadata (%u bytes)", static_cast<unsigned>(data.size()));
    }

    if (!http->Open(method, url, data)) {
        ESP_LOGE(TAG, "Failed to open HTTP connection");
        return ESP_FAIL;
    }

    auto status_code = http->GetStatusCode();
    if (status_code != 200) {
        ESP_LOGE(TAG, "Failed to check version, status_code=%d", status_code);
        return ESP_FAIL;
    }

    const size_t response_length = http->GetBodyLength();
    if (response_length == 0 || response_length > kMaxOtaCheckResponseBytes) {
        ESP_LOGE(TAG, "OTA check response length is missing or exceeds the 64 KiB limit");
        http->Close();
        return ESP_ERR_INVALID_SIZE;
    }
    data.clear();
    data.reserve(response_length);
    char response_buffer[512];
    while (data.size() < response_length) {
        const size_t remaining = response_length - data.size();
        const int read = http->Read(response_buffer, std::min(sizeof(response_buffer), remaining));
        if (read <= 0) {
            http->Close();
            ESP_LOGE(TAG, "OTA check response ended before Content-Length");
            return ESP_ERR_INVALID_SIZE;
        }
        data.append(response_buffer, static_cast<size_t>(read));
    }
    char overflow_probe = 0;
    const int overflow_read = http->Read(&overflow_probe, 1);
    http->Close();
    if (overflow_read != 0 || data.size() != response_length || data.size() > kMaxOtaCheckResponseBytes) {
        ESP_LOGE(TAG, "OTA check response body length does not match Content-Length");
        return ESP_ERR_INVALID_SIZE;
    }

    // Response: { "firmware": { "version": "1.0.0", "url": "http://" } }
    // Parse the JSON response and check if the version is newer
    // If it is, set has_new_version_ to true and store the new version and URL
    
    cJSON *root = cJSON_Parse(data.c_str());
    if (root == NULL) {
        ESP_LOGE(TAG, "Failed to parse JSON response");
        return ESP_ERR_INVALID_RESPONSE;
    }

    has_activation_code_ = false;
    has_activation_challenge_ = false;
    cJSON *activation = cJSON_GetObjectItem(root, "activation");
    if (cJSON_IsObject(activation)) {
        cJSON* message = cJSON_GetObjectItem(activation, "message");
        if (cJSON_IsString(message)) {
            activation_message_ = message->valuestring;
        }
        cJSON* code = cJSON_GetObjectItem(activation, "code");
        if (cJSON_IsString(code)) {
            activation_code_ = code->valuestring;
            has_activation_code_ = true;
        }
        cJSON* challenge = cJSON_GetObjectItem(activation, "challenge");
        if (cJSON_IsString(challenge)) {
            activation_challenge_ = challenge->valuestring;
            has_activation_challenge_ = true;
        }
        cJSON* timeout_ms = cJSON_GetObjectItem(activation, "timeout_ms");
        if (cJSON_IsNumber(timeout_ms)) {
            activation_timeout_ms_ = timeout_ms->valueint;
        }
    }

    has_mqtt_config_ = false;
    cJSON *mqtt = cJSON_GetObjectItem(root, "mqtt");
    if (cJSON_IsObject(mqtt)) {
        Settings settings("mqtt", true);
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, mqtt) {
            if (cJSON_IsString(item)) {
                if (settings.GetString(item->string) != item->valuestring) {
                    settings.SetString(item->string, item->valuestring);
                }
            } else if (cJSON_IsNumber(item)) {
                if (settings.GetInt(item->string) != item->valueint) {
                    settings.SetInt(item->string, item->valueint);
                }
            }
        }
        has_mqtt_config_ = true;
    } else {
        ESP_LOGI(TAG, "No mqtt section found !");
    }

    has_websocket_config_ = false;
    cJSON *websocket = cJSON_GetObjectItem(root, "websocket");
    if (cJSON_IsObject(websocket)) {
        Settings settings("websocket", true);
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, websocket) {
            if (cJSON_IsString(item)) {
                if (settings.GetString(item->string) != item->valuestring) {
                    settings.SetString(item->string, item->valuestring);
                }
            } else if (cJSON_IsNumber(item)) {
                if (settings.GetInt(item->string) != item->valueint) {
                    settings.SetInt(item->string, item->valueint);
                }
            }
        }
        has_websocket_config_ = true;
    } else {
        ESP_LOGI(TAG, "No websocket section found!");
    }

    has_server_time_ = false;
    cJSON *server_time = cJSON_GetObjectItem(root, "server_time");
    if (cJSON_IsObject(server_time)) {
        cJSON *timestamp = cJSON_GetObjectItem(server_time, "timestamp");
        cJSON *timezone_offset = cJSON_GetObjectItem(server_time, "timezone_offset");
        
        if (cJSON_IsNumber(timestamp)) {
            // 设置系统时间
            struct timeval tv;
            double ts = timestamp->valuedouble;
            
            // 如果有时区偏移，计算本地时间
            if (cJSON_IsNumber(timezone_offset)) {
                ts += (timezone_offset->valueint * 60 * 1000); // 转换分钟为毫秒
            }
            
            tv.tv_sec = (time_t)(ts / 1000);  // 转换毫秒为秒
            tv.tv_usec = (suseconds_t)((long long)ts % 1000) * 1000;  // 剩余的毫秒转换为微秒
            settimeofday(&tv, NULL);
            has_server_time_ = true;
        }
    } else {
        ESP_LOGW(TAG, "No server_time section found!");
    }

    has_new_version_ = false;
    cJSON *firmware = cJSON_GetObjectItem(root, "firmware");
    if (cJSON_IsObject(firmware)) {
        OtaFirmwareManifest candidate;
        cJSON *schema_version = cJSON_GetObjectItem(firmware, "schema_version");
        cJSON *version = cJSON_GetObjectItem(firmware, "version");
        cJSON *url = cJSON_GetObjectItem(firmware, "url");
        cJSON *sha256 = cJSON_GetObjectItem(firmware, "sha256");
        cJSON *size = cJSON_GetObjectItem(firmware, "size");
        cJSON *project_name = cJSON_GetObjectItem(firmware, "project_name");
        cJSON *board_type = cJSON_GetObjectItem(firmware, "board_type");
        cJSON *chip_id = cJSON_GetObjectItem(firmware, "chip_id");
        cJSON *secure_version = cJSON_GetObjectItem(firmware, "secure_version");
        cJSON *signature = cJSON_GetObjectItem(firmware, "signature");
        uint64_t parsed_size = 0;
        uint64_t parsed_schema_version = 0;
        uint64_t parsed_secure_version = 0;
        const bool complete = cJSON_IsString(version) && cJSON_IsString(url) &&
            cJSON_IsString(sha256) && cJSON_IsString(project_name) &&
            cJSON_IsString(board_type) && cJSON_IsString(chip_id) &&
            cJSON_IsString(signature) &&
            ReadUnsignedJson(schema_version, 1, &parsed_schema_version) && parsed_schema_version == 1 &&
            ReadUnsignedJson(size, std::numeric_limits<size_t>::max(), &parsed_size) &&
            ReadUnsignedJson(secure_version, std::numeric_limits<uint32_t>::max(), &parsed_secure_version);
        if (complete) {
            candidate.schema_version = static_cast<uint32_t>(parsed_schema_version);
            candidate.version = version->valuestring;
            candidate.url = url->valuestring;
            candidate.sha256 = sha256->valuestring;
            candidate.size = parsed_size;
            candidate.project_name = project_name->valuestring;
            candidate.board_type = board_type->valuestring;
            candidate.chip_id = chip_id->valuestring;
            candidate.secure_version = static_cast<uint32_t>(parsed_secure_version);
            candidate.signature = signature->valuestring;
        }

        const esp_partition_t* update_partition = esp_ota_get_next_update_partition(nullptr);
        const bool fits_partition = update_partition != nullptr && candidate.size <= update_partition->size;
        if (complete && IsValidOtaManifestShape(candidate) && fits_partition &&
            ManifestMatchesBuild(candidate) && VerifyManifestSignature(candidate)) {
            has_new_version_ = IsNewVersionAvailable(current_version_, candidate.version);
            if (has_new_version_) {
                firmware_manifest_ = std::move(candidate);
                ESP_LOGI(TAG, "Verified new firmware manifest: version=%s size=%llu",
                    firmware_manifest_.version.c_str(),
                    static_cast<unsigned long long>(firmware_manifest_.size));
            } else {
                ESP_LOGI(TAG, "Signed firmware manifest is not newer than the running version");
            }
        } else {
            ESP_LOGE(TAG, "Rejecting incomplete, unsigned, incompatible, or oversized firmware manifest");
        }
    } else {
        ESP_LOGW(TAG, "No firmware section found!");
    }

    cJSON_Delete(root);
    return ESP_OK;
}

bool Ota::MarkCurrentVersionValid() {
    auto partition = esp_ota_get_running_partition();
    if (partition == nullptr) {
        ESP_LOGE(TAG, "Failed to identify running OTA partition; blocking upgrade");
        return false;
    }
    if (strcmp(partition->label, "factory") == 0) {
        ESP_LOGI(TAG, "Running from factory partition, skipping");
        return true;
    }

    ESP_LOGI(TAG, "Running partition: %s", partition->label);
    esp_ota_img_states_t state;
    const esp_err_t state_result = esp_ota_get_state_partition(partition, &state);
    if (state_result != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get state of partition: %s; blocking upgrade",
            esp_err_to_name(state_result));
        return false;
    }

    if (state == ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_LOGI(TAG, "Marking firmware as valid");
        const esp_err_t result = esp_ota_mark_app_valid_cancel_rollback();
        if (result != ESP_OK) {
            ESP_LOGE(TAG, "Failed to finalize OTA anti-rollback state: %s", esp_err_to_name(result));
            const esp_err_t rollback_result = esp_ota_mark_app_invalid_rollback_and_reboot();
            ESP_LOGE(TAG, "Failed to roll back invalid OTA image: %s", esp_err_to_name(rollback_result));
            PersistRecoveryRequired();
            recovery_required_ = true;
            ESP_LOGE(TAG, "OTA security recovery is required; halting normal startup");
            while (true) vTaskDelay(portMAX_DELAY);
        }
        return true;
    }

    if (state == ESP_OTA_IMG_VALID) {
        return true;
    }

    ESP_LOGE(TAG, "Running OTA partition is not verified (state=%d); blocking upgrade",
        static_cast<int>(state));
    return false;
}

bool Ota::Upgrade(const OtaFirmwareManifest& manifest,
    std::function<void(int progress, size_t speed)> callback) {
    ESP_LOGI(TAG, "Upgrading firmware version %s", manifest.version.c_str());
    uint8_t expected_digest[32];
    if (!IsValidOtaManifestShape(manifest) || !ManifestMatchesBuild(manifest) ||
        !VerifyManifestSignature(manifest) || !DecodeSha256(manifest.sha256, expected_digest) ||
        !IsNewVersionAvailable(esp_app_get_description()->version, manifest.version)) {
        ESP_LOGE(TAG, "Rejecting untrusted, incompatible, or non-upgrade OTA manifest");
        return false;
    }
    esp_ota_handle_t update_handle = 0;
    auto update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        ESP_LOGE(TAG, "Failed to get update partition");
        return false;
    }
    if (manifest.size > update_partition->size) {
        ESP_LOGE(TAG, "Firmware manifest size exceeds OTA partition");
        return false;
    }

    ESP_LOGI(TAG, "Writing to partition %s at offset 0x%lx", update_partition->label, update_partition->address);
    bool image_header_checked = false;
    bool ota_started = false;
    std::string image_header;

    auto http = Board::GetInstance().CreateHttp();
    if (!http->Open("GET", manifest.url)) {
        ESP_LOGE(TAG, "Failed to open HTTP connection");
        return false;
    }

    if (http->GetStatusCode() != 200) {
        ESP_LOGE(TAG, "Failed to get firmware, status code: %d", http->GetStatusCode());
        http->Close();
        return false;
    }

    size_t content_length = http->GetBodyLength();
    if (content_length == 0 || content_length != manifest.size) {
        ESP_LOGE(TAG, "Firmware Content-Length does not match signed manifest");
        http->Close();
        return false;
    }

    mbedtls_sha256_context sha256_context;
    mbedtls_sha256_init(&sha256_context);
    if (mbedtls_sha256_starts(&sha256_context, 0) != 0) {
        mbedtls_sha256_free(&sha256_context);
        http->Close();
        return false;
    }

    char buffer[512];
    size_t total_read = 0, recent_read = 0;
    auto last_calc_time = esp_timer_get_time();
    while (true) {
        int ret = http->Read(buffer, sizeof(buffer));
        if (ret < 0) {
            ESP_LOGE(TAG, "Failed to read HTTP data: %s", esp_err_to_name(ret));
            if (ota_started) {
                esp_ota_abort(update_handle);
            }
            mbedtls_sha256_free(&sha256_context);
            http->Close();
            return false;
        }

        if (ret > 0 && (total_read > content_length ||
                static_cast<size_t>(ret) > content_length - total_read)) {
            ESP_LOGE(TAG, "Firmware response exceeds signed manifest size");
            if (ota_started) esp_ota_abort(update_handle);
            mbedtls_sha256_free(&sha256_context);
            http->Close();
            return false;
        }

        // Calculate speed and progress every second
        recent_read += ret;
        total_read += ret;
        if (esp_timer_get_time() - last_calc_time >= 1000000 || ret == 0) {
            size_t progress = total_read * 100 / content_length;
            ESP_LOGI(TAG, "Progress: %u%% (%u/%u), Speed: %uB/s", progress, total_read, content_length, recent_read);
            if (callback) {
                callback(progress, recent_read);
            }
            last_calc_time = esp_timer_get_time();
            recent_read = 0;
        }

        if (ret == 0) {
            break;
        }
        if (mbedtls_sha256_update(&sha256_context,
                reinterpret_cast<const uint8_t*>(buffer), static_cast<size_t>(ret)) != 0) {
            if (ota_started) esp_ota_abort(update_handle);
            mbedtls_sha256_free(&sha256_context);
            http->Close();
            return false;
        }
        if (!image_header_checked) {
            image_header.append(buffer, ret);
            const size_t required_header_size =
                sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t);
            if (image_header.size() < required_header_size) {
                continue;
            }

            esp_app_desc_t new_app_info;
            memcpy(&new_app_info, image_header.data() + sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t), sizeof(esp_app_desc_t));

            esp_image_header_t new_image_header;
            memcpy(&new_image_header, image_header.data(), sizeof(new_image_header));
            const std::string image_project(
                new_app_info.project_name,
                strnlen(new_app_info.project_name, sizeof(new_app_info.project_name)));
            const std::string image_version(
                new_app_info.version,
                strnlen(new_app_info.version, sizeof(new_app_info.version)));
            const bool image_identity_matches = new_image_header.magic == ESP_IMAGE_HEADER_MAGIC &&
#if CONFIG_IDF_TARGET_ESP32S3
                new_image_header.chip_id == ESP_CHIP_ID_ESP32S3 &&
#endif
                image_project == manifest.project_name &&
                image_version == manifest.version &&
                new_app_info.secure_version == manifest.secure_version;
#if CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK
            const bool secure_version_allowed = esp_efuse_check_secure_version(new_app_info.secure_version);
#else
            const bool secure_version_allowed =
                new_app_info.secure_version >= esp_app_get_description()->secure_version;
#endif
            if (!image_identity_matches || !secure_version_allowed) {
                ESP_LOGE(TAG, "Firmware image identity or secure version does not match signed manifest");
                mbedtls_sha256_free(&sha256_context);
                http->Close();
                return false;
            }

            auto current_version = esp_app_get_description()->version;
            ESP_LOGI(TAG, "Current version: %s, New version: %s", current_version, new_app_info.version);

            if (esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &update_handle) != ESP_OK) {
                ESP_LOGE(TAG, "Failed to begin OTA");
                mbedtls_sha256_free(&sha256_context);
                http->Close();
                return false;
            }
            ota_started = true;

            auto header_write = esp_ota_write(update_handle, image_header.data(), image_header.size());
            if (header_write != ESP_OK) {
                ESP_LOGE(TAG, "Failed to write buffered OTA header: %s", esp_err_to_name(header_write));
                esp_ota_abort(update_handle);
                mbedtls_sha256_free(&sha256_context);
                http->Close();
                return false;
            }
            image_header_checked = true;
            std::string().swap(image_header);
            continue;
        }
        auto err = esp_ota_write(update_handle, buffer, ret);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to write OTA data: %s", esp_err_to_name(err));
            esp_ota_abort(update_handle);
            mbedtls_sha256_free(&sha256_context);
            http->Close();
            return false;
        }
    }
    http->Close();

    if (!ota_started) {
        ESP_LOGE(TAG, "Firmware image ended before a complete image header was received");
        mbedtls_sha256_free(&sha256_context);
        return false;
    }
    if (total_read != content_length) {
        ESP_LOGE(TAG, "Firmware length mismatch: read=%u expected=%u",
            static_cast<unsigned>(total_read), static_cast<unsigned>(content_length));
        esp_ota_abort(update_handle);
        mbedtls_sha256_free(&sha256_context);
        return false;
    }

    uint8_t actual_digest[32];
    const bool digest_ok = mbedtls_sha256_finish(&sha256_context, actual_digest) == 0 &&
        mbedtls_ct_memcmp(actual_digest, expected_digest, sizeof(actual_digest)) == 0;
    mbedtls_sha256_free(&sha256_context);
    if (!digest_ok) {
        ESP_LOGE(TAG, "Firmware SHA-256 does not match manifest metadata");
        esp_ota_abort(update_handle);
        return false;
    }

    esp_err_t err = esp_ota_end(update_handle);
    if (err != ESP_OK) {
        if (err == ESP_ERR_OTA_VALIDATE_FAILED) {
            ESP_LOGE(TAG, "Image validation failed, image is corrupted");
        } else {
            ESP_LOGE(TAG, "Failed to end OTA: %s", esp_err_to_name(err));
        }
        return false;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set boot partition: %s", esp_err_to_name(err));
        return false;
    }

    ESP_LOGI(TAG, "Firmware upgrade successful");
    return true;
}

bool Ota::StartUpgrade(std::function<void(int progress, size_t speed)> callback) {
    return Upgrade(firmware_manifest_, callback);
}


std::vector<int> Ota::ParseVersion(const std::string& version) {
    std::vector<int> versionNumbers;
    std::stringstream ss(version);
    std::string segment;

    while (std::getline(ss, segment, '.')) {
        if (segment.empty() || versionNumbers.size() >= 4 ||
            !std::all_of(segment.begin(), segment.end(), [](unsigned char c) { return std::isdigit(c); }) ||
            segment.size() > 6) {
            return {};
        }
        int value = 0;
        for (char c : segment) value = value * 10 + (c - '0');
        versionNumbers.push_back(value);
    }

    return versionNumbers;
}

bool Ota::IsNewVersionAvailable(const std::string& currentVersion, const std::string& newVersion) {
    std::vector<int> current = ParseVersion(currentVersion);
    std::vector<int> newer = ParseVersion(newVersion);
    if (current.empty() || newer.empty()) return false;

    const size_t segment_count = std::max(current.size(), newer.size());
    for (size_t i = 0; i < segment_count; ++i) {
        const int current_value = i < current.size() ? current[i] : 0;
        const int newer_value = i < newer.size() ? newer[i] : 0;
        if (newer_value != current_value) return newer_value > current_value;
    }
    return false;
}

std::string Ota::GetActivationPayload() {
    if (!has_serial_number_) {
        return "{}";
    }

    std::string hmac_hex;
#ifdef SOC_HMAC_SUPPORTED
    uint8_t hmac_result[32]; // SHA-256 输出为32字节
    
    // 使用Key0计算HMAC
    esp_err_t ret = esp_hmac_calculate(HMAC_KEY0, (uint8_t*)activation_challenge_.data(), activation_challenge_.size(), hmac_result);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "HMAC calculation failed: %s", esp_err_to_name(ret));
        return "{}";
    }

    for (size_t i = 0; i < sizeof(hmac_result); i++) {
        char buffer[3];
        sprintf(buffer, "%02x", hmac_result[i]);
        hmac_hex += buffer;
    }
#endif

    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "algorithm", "hmac-sha256");
    cJSON_AddStringToObject(payload, "serial_number", serial_number_.c_str());
    cJSON_AddStringToObject(payload, "challenge", activation_challenge_.c_str());
    cJSON_AddStringToObject(payload, "hmac", hmac_hex.c_str());
    auto json_str = cJSON_PrintUnformatted(payload);
    std::string json(json_str);
    cJSON_free(json_str);
    cJSON_Delete(payload);

    return json;
}

esp_err_t Ota::Activate() {
    if (!has_activation_challenge_) {
        ESP_LOGW(TAG, "No activation challenge found");
        return ESP_FAIL;
    }

    std::string url = GetCheckVersionUrl();
    if (url.back() != '/') {
        url += "/activate";
    } else {
        url += "activate";
    }
    if (!IsTrustedOtaUrl(url)) {
        ESP_LOGE(TAG, "Activation URL is not on the production HTTPS allowlist");
        return ESP_ERR_INVALID_ARG;
    }

    auto http = SetupHttp();

    std::string data = GetActivationPayload();

    if (!http->Open("POST", url, data)) {
        ESP_LOGE(TAG, "Failed to open HTTP connection");
        return ESP_FAIL;
    }
    
    auto status_code = http->GetStatusCode();
    if (status_code == 202) {
        return ESP_ERR_TIMEOUT;
    }
    if (status_code != 200) {
        ESP_LOGE(TAG, "Failed to activate, code: %d", status_code);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Activation successful");
    return ESP_OK;
}
