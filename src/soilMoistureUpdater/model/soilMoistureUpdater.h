#ifndef SOIL_MOISTURE_UPDATER_H
#define SOIL_MOISTURE_UPDATER_H

#include "ns3/simulator.h"


namespace ns3 {

class SoilMoistureUpdater : public Object{
public:
    // 无参构造函数，使用默认参数
    static TypeId GetTypeId (void);
    SoilMoistureUpdater(double initialMv = 0.05, double minMv = 0.0, double maxMv = 1.0);

    // 更新函数
    void UpdateMoisture();

    // 获取当前含水量
    double GetMv() const;

private:
    void ScheduleNextUpdate();

    double m_mv;      // 当前含水量
    double m_minMv;   // 最小含水量
    double m_maxMv;   // 最大含水量
    EventId m_timer;    // 定时器
};

} // namespace ns3

#endif // SOIL_MOISTURE_UPDATER_H
