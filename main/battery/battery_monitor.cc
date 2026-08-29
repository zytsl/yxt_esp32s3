#include "battery/battery_monitor.h"

#include <atomic>

#include "esp_adc/adc_oneshot.h"
#include "driver/gpio.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

BatteryMonitor& BatteryMonitor::GetInstance() {
    static BatteryMonitor instance;
    return instance;
}

#if defined(CONFIG_BATTERY_ADC_GPIO) && CONFIG_BATTERY_ADC_GPIO >= 0

static const char* TAG = "BatteryMonitor";

namespace {

constexpr int kSampleCount = 16;
constexpr int kSampleSpacingMs = 1;
constexpr int kMeasurePeriodMs = 10 * 1000;
constexpr float kEmaAlpha = 0.3f;
// 12dB 衰减下的粗略满量程（仅在 eFuse 曲线校准不可用时兜底用）。
constexpr int kFallbackFullScaleMillivolts = 2500;
constexpr int kAdcMaxRaw = 4095;

std::atomic<uint32_t> g_millivolts{0};
std::atomic<bool> g_started{false};
bool g_enabled = false;
adc_oneshot_unit_handle_t g_adc = nullptr;
adc_cali_handle_t g_cali = nullptr;
adc_channel_t g_channel = ADC_CHANNEL_0;

// ESP32-S3 ADC1：GPIO1-10 依次对应 CH0-CH9。
bool GpioToAdcChannel(int gpio, adc_channel_t* channel) {
    if (gpio >= 1 && gpio <= 10) {
        *channel = static_cast<adc_channel_t>(gpio - 1);
        return true;
    }
    ESP_LOGE(TAG, "CONFIG_BATTERY_ADC_GPIO=%d is not an ADC1 pin (1-10)", gpio);
    return false;
}

}  // namespace

void BatteryMonitor::MeasureTask(void* /*arg*/) {
    vTaskDelay(pdMS_TO_TICKS(100));  // 等分压节点与 ADC 稳定
    bool has_first = false;
    float ema = 0.0f;
    for (;;) {
        int raw_sum = 0;
        for (int i = 0; i < kSampleCount; ++i) {
            int raw = 0;
            if (adc_oneshot_read(g_adc, g_channel, &raw) != ESP_OK) {
                raw = 0;
            }
            raw_sum += raw;
            vTaskDelay(pdMS_TO_TICKS(kSampleSpacingMs));
        }
        const int raw_avg = raw_sum / kSampleCount;
        int pin_mv = 0;
        if (g_cali == nullptr || adc_cali_raw_to_voltage(g_cali, raw_avg, &pin_mv) != ESP_OK) {
            pin_mv = static_cast<int64_t>(raw_avg) * kFallbackFullScaleMillivolts / kAdcMaxRaw;
        }
        // 配置为"分压比×100"（默认 200 = 100k/100k），整型计算避免浮点 Kconfig。
        const int64_t vbat_mv =
            static_cast<int64_t>(pin_mv) * CONFIG_BATTERY_ADC_DIVIDER_PCT / 100;
        if (vbat_mv <= 0 || vbat_mv > 10000) {
            ESP_LOGW(TAG, "implausible battery reading: %lld mV (raw avg %d)",
                     static_cast<long long>(vbat_mv), raw_avg);
        } else {
            ema = has_first ? (kEmaAlpha * vbat_mv + (1.0f - kEmaAlpha) * ema)
                            : static_cast<float>(vbat_mv);
            has_first = true;
            g_millivolts.store(static_cast<uint32_t>(ema + 0.5f));
        }
        vTaskDelay(pdMS_TO_TICKS(kMeasurePeriodMs));
    }
}

void BatteryMonitor::EnsureStarted() {
    if (g_started.exchange(true)) {
        return;
    }
    if (!GpioToAdcChannel(CONFIG_BATTERY_ADC_GPIO, &g_channel)) {
        return;
    }
    adc_oneshot_unit_init_cfg_t unit_cfg = {
        .unit_id = ADC_UNIT_1,
        .ulp_mode = ADC_ULP_MODE_DISABLE,
    };
    if (adc_oneshot_new_unit(&unit_cfg, &g_adc) != ESP_OK) {
        ESP_LOGE(TAG, "adc_oneshot_new_unit failed");
        return;
    }
    adc_oneshot_chan_cfg_t chan_cfg = {
        .atten = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    if (adc_oneshot_config_channel(g_adc, g_channel, &chan_cfg) != ESP_OK) {
        ESP_LOGE(TAG, "adc_oneshot_config_channel failed");
        return;
    }
    adc_cali_curve_fitting_config_t cali_cfg = {
        .unit_id = ADC_UNIT_1,
        .chan = g_channel,
        .atten = ADC_ATTEN_DB_12,
    };
    if (adc_cali_create_scheme_curve_fitting(&cali_cfg, &g_cali) != ESP_OK) {
        g_cali = nullptr;  // 旧批次 eFuse 缺曲线数据时退回粗略换算
        ESP_LOGW(TAG, "curve fitting calibration unavailable, using raw fallback");
    }
    if (xTaskCreate(MeasureTask, "battery", 3072, nullptr, 3, nullptr) != pdPASS) {
        ESP_LOGE(TAG, "battery measure task creation failed");
        return;
    }
    g_enabled = true;
    ESP_LOGI(TAG, "battery monitor on GPIO%d (divider x%d/100)",
             CONFIG_BATTERY_ADC_GPIO, CONFIG_BATTERY_ADC_DIVIDER_PCT);
}

bool BatteryMonitor::IsEnabled() const {
    return g_enabled;
}

uint32_t BatteryMonitor::Millivolts() const {
    return g_millivolts.load();
}

uint8_t BatteryMonitor::Percent() const {
    const uint32_t mv = Millivolts();
    return mv == 0 ? 255 : LiionPercentFromMillivolts(mv);
}

#else  // 未配置电池 ADC 的板型

void BatteryMonitor::EnsureStarted() {}
bool BatteryMonitor::IsEnabled() const { return false; }
uint32_t BatteryMonitor::Millivolts() const { return 0; }
uint8_t BatteryMonitor::Percent() const { return 255; }

#endif
