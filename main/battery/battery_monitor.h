#ifndef BATTERY_MONITOR_H_
#define BATTERY_MONITOR_H_

#include <cstdint>

// 单节锂电电压 → 剩余电量百分比（纯函数，宿主测试直接覆盖，
// 见 tests/battery_curve_test.cc）。曲线取常见 1S LiCoO2 放电
// 折线的保守值；低于 3.27V 一律视为 0。
inline uint8_t LiionPercentFromMillivolts(uint32_t millivolts) {
    struct Point {
        uint32_t mv;
        uint8_t pct;
    };
    static constexpr Point kCurve[] = {
        {4200, 100}, {4060, 90}, {3980, 80}, {3920, 70}, {3870, 60},
        {3820, 50},  {3780, 40}, {3740, 30}, {3680, 20}, {3450, 10},
        {3300, 5},   {3270, 0},
    };
    constexpr int kPoints = static_cast<int>(sizeof(kCurve) / sizeof(kCurve[0]));
    if (millivolts >= kCurve[0].mv) {
        return 100;
    }
    for (int i = 1; i < kPoints; ++i) {
        if (millivolts >= kCurve[i].mv) {
            const Point& hi = kCurve[i - 1];
            const Point& lo = kCurve[i];
            const float t =
                static_cast<float>(millivolts - lo.mv) / static_cast<float>(hi.mv - lo.mv);
            return static_cast<uint8_t>(lo.pct + t * (hi.pct - lo.pct) + 0.5f);
        }
    }
    return 0;
}

// 电池电压监测：按 CONFIG_BATTERY_ADC_GPIO 配置经分压电阻采样
// （内核板 v1：GPIO2=ADC1_CH1，R14/R19=100k/100k，分压比 ×2）。
// 未配置（GPIO<0）时 EnsureStarted() 安全空转、IsEnabled()=false，
// BLE 设备信息特征会自动省略 battery 字段。
class BatteryMonitor {
public:
    static BatteryMonitor& GetInstance();

    // 幂等启动；可从任意任务上下文调用（含 nimBLE 回调）。
    void EnsureStarted();

    bool IsEnabled() const;
    // 最近一次平滑后的电池端电压（mV）；0 表示尚未测得。
    uint32_t Millivolts() const;
    // 0-100；255 表示未知（未启用或尚无测量）。
    uint8_t Percent() const;

private:
    BatteryMonitor() = default;
    static void MeasureTask(void* arg);
};

#endif  // BATTERY_MONITOR_H_
