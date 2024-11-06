#include <fstream> // 包含文件流头文件，用于文件操作
#include <iostream> // 包含输入输出流头文件，用于标准输入输出
#include <vector>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include "ns3/wifi-module.h"
#include "ns3/core-module.h" // ns-3模拟器核心模块头文件
#include "ns3/network-module.h" // ns-3网络模块头文件
#include "ns3/internet-module.h" // ns-3互联网模块头文件
#include "ns3/mobility-module.h" // ns-3移动性模块头文件
#include "ns3/aodv-module.h" // ns-3 AODV路由协议模块头文件
#include "ns3/olsr-module.h" // ns-3 OLSR路由协议模块头文件
#include "ns3/dsdv-module.h" // ns-3 DSDV路由协议模块头文件
#include "ns3/dsr-module.h" // ns-3 DSR路由协议模块头文件
#include "ns3/applications-module.h" // ns-3应用模块头文件
#include "ns3/yans-wifi-helper.h" // ns-3 YANS WiFi助手头文件
#include "ns3/config-store-module.h"
#include "ns3/propagation-delay-model.h"
#include "ns3/propagation-loss-model.h"
#include "ns3/energy-module.h" // ns-3能量模块头文件
#include "ns3/wifi-radio-energy-model-helper.h" // ns-3 WiFi无线电能量模型助手头文件
#include "ns3/callback.h"
#include <cmath>
#include <complex>
#include "ns3/netanim-module.h"
#include "ns3/soilMoistureUpdater.h"
#include "ns3/AODVwithBHandSF.h"
#include "ns3/AODVwithBHandSF-helper.h"
using namespace ns3;
using namespace dsr;



extern std::string snifferExpname;


void ClearFile(const std::string &filename);

void RemainingEnergy(double oldValue, double remainingEnergy);

void TotalEnergy (double oldValue, double totalEnergy);

// 获取MAC地址对应的节点ID的函数
uint32_t GetNodeIdFromMacAddress(Mac48Address mac);

struct PacketInfo {
    std::string packetType;
    Mac48Address srcMac;
    uint32_t srcNodeId;
    uint32_t SequenceNumber;
};

PacketInfo HandlePacket(Ptr<const Packet> packet);


// 从 context 字符串中提取节点ID并加1
uint32_t GetNodeIdFromContext(const std::string &context);


void 
WWSNMonitorSnifferRx ( std::string context, 
                    Ptr<const Packet> packet, 
                    uint16_t channelFreqMhz, 
                    WifiTxVector txVector, 
                    MpduInfo aMpdu, 
                    SignalNoiseDbm signalNoise, 
                    uint16_t staId);


void 
WWSNMonitorSnifferTx ( std::string context,
                    Ptr<const Packet> packet,
                    uint16_t channelFreqMhz,
                    WifiTxVector txVector,
                    MpduInfo aMpdu,
                    uint16_t staId);


class MyApp : public Application
{
public:
    MyApp ();  // 构造函数
    virtual ~MyApp();  // 析构函数
    void RecPacket (Ptr<Socket> socket);
    void Setup (Ptr<Socket> socket, Ipv4Address source, Ipv4Address address, Mac48Address  macsource, Mac48Address  macdestination, uint32_t packetSize, uint32_t nPackets, DataRate dataRate, std::string checkThroughoutputfileName, bool sink);  // 设置应用程序参数
    

private:
    virtual void StartApplication (void);  // 启动应用程序
    virtual void StopApplication (void);  // 停止应用程序
    
    void ScheduleTx (void);  // 定时发送数据包
    void SendPacket (Ipv4Address source, Ipv4Address address, Mac48Address  macsource, Mac48Address  macdestination);  // 发送数据包
    void CheckThroughput (); // 检查吞吐量函数
    Ptr<Socket>     m_socket;  // Socket 指针
    Ipv4Address     m_source;  // 对端地址
    Ipv4Address     m_peer;  // 对端地址
    Mac48Address    mac_source;
    Mac48Address    mac_peer;
    uint32_t        m_packetSize;  // 数据包大小
    uint32_t        m_nPackets;  // 发送数据包数量
    DataRate        m_dataRate;  // 数据传输速率
    EventId         m_sendEvent;  // 发送事件
    bool            m_running;  // 是否正在运行
    uint32_t        m_packetsSent;  // 已发送数据包数量
    uint32_t        port; // 端口号
    uint32_t        bytesTotal; // 总字节数
    std::string     m_checkThroughoutputfileName; // CSV文件名
    bool m_sink;
    bool thoughoutputFirst;
};



class Experiment
{
private:

    uint32_t port; // 端口号
    uint32_t bytesTotal; // 总字节数
    uint32_t packetsReceived; // 收到的数据包数量
    std::string m_CSVfileName; // CSV文件名
    int m_nSinks; // 汇聚节点数量
    std::string m_protocolName; // 协议名称
    bool m_traceMobility; // 移动性跟踪标志
    uint32_t m_protocol; // 协议类型
    
    
    


public:
    Experiment (); // 构造函数
    void Run (  int nSinks,
                double simtime,
                int nodes, 
                double BHradio,
                double SFradio, 
                std::string expname); // 运行函数
    void LogEnergyForAllNodes();
    void setDeviceEnergyModelContainer(ns3::DeviceEnergyModelContainer deviceModels);
    void CommandSetup (int argc, char **argv); // 命令设置函数
    std::string expname;
    std::string setExpname(std::string outExpname);
    ns3::DeviceEnergyModelContainer ExpdeviceModels;
    
};

