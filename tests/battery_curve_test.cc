#include "battery/battery_monitor.h"

#include <cassert>
#include <cstdint>

// 锂电电压→百分比曲线纯函数的行为契约。
int main() {
    // 端点与钳位
    assert(LiionPercentFromMillivolts(0) == 0);
    assert(LiionPercentFromMillivolts(3269) == 0);
    assert(LiionPercentFromMillivolts(3270) == 0);
    assert(LiionPercentFromMillivolts(4200) == 100);
    assert(LiionPercentFromMillivolts(6000) == 100);

    // 折线锚点
    assert(LiionPercentFromMillivolts(3300) == 5);
    assert(LiionPercentFromMillivolts(3450) == 10);
    assert(LiionPercentFromMillivolts(3680) == 20);
    assert(LiionPercentFromMillivolts(3740) == 30);
    assert(LiionPercentFromMillivolts(3780) == 40);
    assert(LiionPercentFromMillivolts(3820) == 50);
    assert(LiionPercentFromMillivolts(3870) == 60);
    assert(LiionPercentFromMillivolts(3920) == 70);
    assert(LiionPercentFromMillivolts(3980) == 80);
    assert(LiionPercentFromMillivolts(4060) == 90);

    // 锚点之间的插值合理（中点落在两侧值之间）
    const uint8_t mid = LiionPercentFromMillivolts(3680 + (3450 - 3680) / 2);
    assert(mid > 10 && mid < 20);

    // 全程单调不减
    uint8_t prev = 0;
    for (uint32_t mv = 3200; mv <= 4210; mv += 5) {
        const uint8_t pct = LiionPercentFromMillivolts(mv);
        assert(pct >= prev);
        prev = pct;
    }
    return 0;
}
