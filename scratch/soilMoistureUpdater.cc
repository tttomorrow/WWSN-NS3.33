#include "soilMoistureUpdater.h"

namespace ns3 {

SoilMoistureUpdater::SoilMoistureUpdater(double initialMv, double minMv, double maxMv)
    : m_mv(initialMv), m_minMv(minMv), m_maxMv(maxMv) {
    ScheduleNextUpdate();
}

void SoilMoistureUpdater::ScheduleNextUpdate() {
    Time interval = Seconds(10.0); // 每10秒更新一次
    m_timer = Simulator::Schedule(interval, &SoilMoistureUpdater::UpdateMoisture, this);
}

void SoilMoistureUpdater::UpdateMoisture() {
    // 随机选择上升或下降
    if (rand() % 2 == 0) {
        // 含水量上升，增量较大
        m_mv += ((rand() % 100) / 100.0) * 0.05; // 上升幅度
    } else {
        // 含水量下降，增量较小
        m_mv -= ((rand() % 100) / 100.0) * 0.02; // 下降幅度
    }

    // 确保含水量在范围内
    m_mv = std::max(m_minMv, std::min(m_maxMv, m_mv));
    
    NS_LOG_DEBUG("Current Soil Moisture: " << m_mv);
    
    // 重新调度下次更新
    ScheduleNextUpdate();
}

double SoilMoistureUpdater::GetMv() const {
    return m_mv;
}

} // namespace ns3
