#include "soilMoistureUpdater.h"
#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("soilMoistureUpdater");

NS_OBJECT_ENSURE_REGISTERED (SoilMoistureUpdater);

int count = 0;
double time = 10.0; // 每10秒更新一次,此值为下面数组Mv_change[]值的更新时间
double updateTime = 1.0; // 每次更新时间可以在指定
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
    
    Time interval = Seconds(updateTime); 
    m_timer = Simulator::Schedule(interval, &SoilMoistureUpdater::UpdateMoisture, this);
}

void SoilMoistureUpdater::UpdateMoisture() {
    // 选择含水量上升或下降
    double Mv_change[] = {0,0,0.25,0.05,-0.05,-0.05,-0.05,-0.05,-0.05,-0.05, 0, 0, 0, 0, 0, 0, 0, 0};
    
     // 每秒的变化量是原始 10 秒变化量的 1/10
    double perSecondChange = Mv_change[count] / (time / updateTime);

     // 更新土壤湿度
    m_mv += perSecondChange;

    // 增加 count，确保数组的循环
    count = (count + 1) % (sizeof(Mv_change) / sizeof(Mv_change[0])); // 确保 count 在 0 和数组长度之间循环

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
