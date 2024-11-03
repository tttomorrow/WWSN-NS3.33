#include "soilMoistureUpdater.h"
#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("soilMoistureUpdater");

NS_OBJECT_ENSURE_REGISTERED (SoilMoistureUpdater);

int count = 0;

TypeId
SoilMoistureUpdater::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::SoilMoistureUpdater")
    .SetParent<Object>() // 确保这是一个 NS-3 对象
    .AddConstructor<SoilMoistureUpdater> ();
  return tid;
}

SoilMoistureUpdater::SoilMoistureUpdater(double initialMv, double minMv, double maxMv)
    : m_mv(initialMv), m_minMv(minMv), m_maxMv(maxMv) {
    ScheduleNextUpdate();
}

void SoilMoistureUpdater::ScheduleNextUpdate() {
    Time interval = Seconds(10.0); // 每10秒更新一次
    m_timer = Simulator::Schedule(interval, &SoilMoistureUpdater::UpdateMoisture, this);
}

void SoilMoistureUpdater::UpdateMoisture() {
    // 选择含水量上升或下降
    double Mv_change[] = {0,0,0.25,0.05,-0.05,-0.05,-0.05,-0.05,-0.05,-0.05, 0, 0, 0, 0, 0, 0, 0, 0};
    
    m_mv = m_mv + Mv_change[count];
    count++;
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
