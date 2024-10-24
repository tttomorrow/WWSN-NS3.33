#include <fstream> // 包含文件流头文件，用于文件操作
#include <iostream> // 包含输入输出流头文件，用于标准输入输出
#include <vector>
#include <string>
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
using namespace ns3;
using namespace dsr;

void ClearFile(const std::string &filename) {
    std::ofstream ofs;
    ofs.open(filename, std::ofstream::out | std::ofstream::trunc);
    ofs.close();
}

NS_LOG_COMPONENT_DEFINE ("sniffer(20240701)"); 

void RemainingEnergy(double oldValue, double remainingEnergy) {
    
    static std::fstream f("wwsn20240701remaining_energy.csv", std::ios::out | std::ios::app);
    if (!f.is_open()) {
        std::cerr << "Error opening file" << std::endl;
        return;
    }
    // 写入 CSV 文件头（仅在第一次写入时）
    static bool first = true;
    if (first) {
        ClearFile("wwsn20240701remaining_energy.csv");
        f << "Time,RemainingEnergy\n";
        first = false;
    }

    // 写入时间戳和剩余能量值到 CSV 文件
    f << Simulator::Now().GetSeconds() << "," << remainingEnergy << "\n";
}

void MonitorSnifferRx (std::string context, Ptr<const Packet> packet, uint16_t channelFreqMhz, WifiTxVector txVector, MpduInfo aMpdu, SignalNoiseDbm signalNoise, uint16_t staId)
{
    
    static std::fstream f ("wwsn20240701MonitorSnifferRx.csv", std::ios::out | std::ios::app);
    if (!f.is_open()) {
        std::cerr << "Error opening file" << std::endl;
        return;
    }
    // 写入 CSV 文件头（仅在第一次写入时）
    static bool first = true;
    if (first) {
        ClearFile("wwsn20240701MonitorSnifferRx.csv");
        f << "Context, srcAddress,destAddress, PacketSize,ChannelFreqMhz,SignalPower,NoisePower,MpduRefNumber,StaId\n";
        first = false;
    }
//     Ptr<Packet> packetCopy = packet->Copy();
//     EthernetHeader ethHeader;
//     Ipv4Header ipHeader;

//     // 提取以太网头
//     packetCopy->RemoveHeader(ethHeader);
  
//     // 提取IP头
//     packetCopy->RemoveHeader(ipHeader);

//   Mac48Address  sourceIp = ethHeader.GetSource();
//   Mac48Address  destIp = ethHeader.GetDestination();

	// uint8_t buffer[2];
	// packet->CopyData(buffer,2);



//   NS_LOG_INFO ("Received packet from Mac48Address : " << int(buffer[0]) << " to Mac48Address : " << int(buffer[1]));
    // 从数据包中提取整数
    
    // 写入参数值到 CSV 文件
    f << context << ","
    //   << sourceIp << ","
    //   << destIp << ","
      << packet->GetSize() << ","
      << channelFreqMhz << ","
      << signalNoise.signal << ","
      << signalNoise.noise << ","
      << aMpdu.mpduRefNumber << ","
      << staId << "\n";
}

void MonitorSnifferTx (std::string context, Ptr<const Packet> packet, uint16_t channelFreqMhz, WifiTxVector txVector, MpduInfo aMpdu, uint16_t staId)
{
    
    static std::fstream f ("wwsn20240701MonitorSnifferTx.csv", std::ios::out | std::ios::app);
    if (!f.is_open()) {
        std::cerr << "Error opening file" << std::endl;
        return;
    }
    // 写入 CSV 文件头（仅在第一次写入时)
    static bool first = true;
    if (first) {
        ClearFile("wwsn20240701MonitorSnifferTx.csv");
        f << "Context,srcAddress,destAddress,PacketSize,ChannelFreqMhz,MpduRefNumber,StaId\n";
        first = false;
    }

    // Ptr<Packet> packetCopy = packet->Copy();
    // EthernetHeader ethHeader;
    // Ipv4Header ipHeader;

    // // 提取以太网头
    // packetCopy->RemoveHeader(ethHeader);
  
    // // 提取IP头
    // packetCopy->RemoveHeader(ipHeader);

    // Ipv4Address sourceIp = ipHeader.GetSource();
    // Ipv4Address destIp = ipHeader.GetDestination();

    // NS_LOG_INFO ("Received packet from IP: " << sourceIp << " to IP: " << destIp);
    
    // 写入参数值到 CSV 文件
    f << context << ","
    //   << sourceIp << ","
    //   << destIp << ","
      << packet->GetUid() << ","
      << channelFreqMhz << ","
      << aMpdu.mpduRefNumber << ","
      << staId << "\n";
}

// 定义全局变量来统计数据包数量和丢失数量
std::map<uint32_t, uint32_t> packetsReceivedList; // 每个节点接收到的数据包数量
std::map<uint32_t, uint32_t> packetsSentPerNode; // 每个节点发送的数据包数量
std::map<uint32_t, uint32_t> packetsForwardedList; // 每个节点转发的数据包数量
std::map<uint32_t, uint32_t> packetsReceivedFromList; // 从每个节点接收到的数据包数量
std::map<uint32_t, double> energyConsumedList; // 每个节点消耗的能量


class MyApp : public Application
{
public:
    MyApp ();  // 构造函数
    virtual ~MyApp();  // 析构函数
    void RecPacket (Ptr<Socket> socket);
    void Setup (Ptr<Socket> socket, Ipv4Address source, Ipv4Address address, Mac48Address  macsource, Mac48Address  macdestination, uint32_t packetSize, uint32_t nPackets, DataRate dataRate);  // 设置应用程序参数

private:
    virtual void StartApplication (void);  // 启动应用程序
    virtual void StopApplication (void);  // 停止应用程序

    void ScheduleTx (void);  // 定时发送数据包
    void SendPacket (Ipv4Address source, Ipv4Address address, Mac48Address  macsource, Mac48Address  macdestination);  // 发送数据包
    
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
};

MyApp::MyApp ()
        : m_socket (0),
          m_source (),
          m_peer (),
          mac_source (),
          mac_peer (),
          m_packetSize (0),
          m_nPackets (0),
          m_dataRate (0),
          m_sendEvent (),
          m_running (false),
          m_packetsSent (0),
          port (9)
{
}

MyApp::~MyApp()
{
    m_socket = 0;
}

void
MyApp::Setup (Ptr<Socket> socket, Ipv4Address source, Ipv4Address address, Mac48Address  macsource, Mac48Address  macdestination,uint32_t packetSize, uint32_t nPackets, DataRate dataRate)
{
    m_socket = socket;
    m_source = source;
    m_peer = address;
    mac_source = macsource;
    mac_peer = macdestination;
    m_packetSize = packetSize;
    m_nPackets = nPackets;
    m_dataRate = dataRate;
}

void
MyApp::StartApplication (void)
{   
    InetSocketAddress remote = InetSocketAddress (m_peer, port); // 创建远程套接字地址
    // NS_LOG_INFO("remoteInetSocketAddress"<<remote);
    InetSocketAddress local = InetSocketAddress (m_source, port); // 创建本地套接字地址
    m_running = true;
    m_packetsSent = 0;
    m_socket->Bind (local);  // 绑定 Socket
    m_socket->Connect (remote);  // 连接对端
    SendPacket (m_source, m_peer, mac_source, mac_peer);  // 发送数据包
    
}

void
MyApp::StopApplication (void)
{
    m_running = false;

    if (m_sendEvent.IsRunning ())
    {
        Simulator::Cancel (m_sendEvent);
    }

    if (m_socket)
    {
        m_socket->Close ();  // 关闭 Socket
    }
}

void
MyApp::RecPacket(Ptr<Socket> socket)
{
    Ptr<Packet> packet; // 创建Packet指针
    Address senderAddress; // 创建地址变量
    while ((packet = socket->RecvFrom (senderAddress))) // 当接收到数据包时
    {
        packetsReceivedList[socket->GetNode ()->GetId ()]++;

        std::ostringstream ossip;
        ossip.str("");
        ossip.clear();
        InetSocketAddress addr = InetSocketAddress::ConvertFrom (senderAddress); // 转换发送者地址为InetSocketAddress类型
        Ipv4Address ipv4Addr = addr.GetIpv4(); // 获取 IPv4 地址
        ipv4Addr.Print(ossip); // 将 IPv4 地址转换为字符串
        std::string ipAddressString = ossip.str();
        size_t lastDotPosition = ipAddressString.rfind('.');

        // 提取最后两位数字的子字符串
        std::string lastTwoDigitsStr = ipAddressString.substr(lastDotPosition + 1);

        // 将子字符串转换为整数
        int lastTwoDigits = std::stoi(lastTwoDigitsStr);

        packetsReceivedFromList[lastTwoDigits-1]++; // 增加从特定节点接收的数据包数量

    }
}

void
MyApp::SendPacket (Ipv4Address source, Ipv4Address destination, Mac48Address  macsource, Mac48Address  macdestination)
{   
    uint8_t buffer[2] = { 0 };
    std::ostringstream ossip;
    ossip.str("");
    ossip.clear();
    source.Print(ossip); // 将 IPv4 地址转换为字符串
    std::string srcipAddressString = ossip.str();
    size_t srclastDotPosition = srcipAddressString.rfind('.');
    // 提取最后两位数字的子字符串
    std::string srclastTwoDigitsStr = srcipAddressString.substr(srclastDotPosition + 1);
    // 将子字符串转换为整数
    int srclastTwoDigits = std::stoi(srclastTwoDigitsStr);

    ossip.str("");
    ossip.clear();
    destination.Print(ossip); // 将 IPv4 地址转换为字符串
    std::string desipAddressString = ossip.str();
    size_t deslastDotPosition = desipAddressString.rfind('.');
    // 提取最后两位数字的子字符串
    std::string deslastTwoDigitsStr = desipAddressString.substr(deslastDotPosition + 1);

    // 将子字符串转换为整数
    int deslastTwoDigits = std::stoi(deslastTwoDigitsStr);
	
    buffer[0] = srclastTwoDigits;
    buffer[1] = deslastTwoDigits;

	Ptr<Packet> packet = ns3::Create<Packet>(buffer, 2);

	// Ptr<Packet> packet = ns3::Create<Packet>(m_packetSize);
 
// 加上IP包头：
	// 添加IP头
	Ipv4Header iph;
	iph.SetDestination(destination);
	iph.SetSource(source);
	iph.SetIdentification(0x49fb);
	iph.SetTtl(64);
	iph.SetProtocol(Icmpv4L4Protocol::PROT_NUMBER);
	iph.SetPayloadSize(packet->GetSize());
	iph.EnableChecksum();
	packet->AddHeader(iph);
// 最后加上以太网包头：
	// 添加以太网头
	EthernetHeader eeh;
	eeh.SetDestination(mac_peer);
	eeh.SetSource(mac_source);
	eeh.SetLengthType(ns3::Ipv4L3Protocol::PROT_NUMBER);
	packet->AddHeader(eeh);
    
    m_socket->Send (packet);  // 发送数据包
    // NS_LOG_INFO("source " << source << ", dest "<< address);
    if (++m_packetsSent < m_nPackets)  // 检查是否需要继续发送数据包
    {
        ScheduleTx ();  // 定时发送数据包
    }
}

void
MyApp::ScheduleTx (void)
{
    if (m_running)  // 如果应用程序正在运行
    {
        Time tNext (Seconds (m_packetSize * 8 / static_cast<double> (m_dataRate.GetBitRate ())));  // 下一次发送的时间
        m_sendEvent = Simulator::Schedule (tNext, &MyApp::SendPacket, this, m_source, m_peer, mac_source, mac_peer);  // 定时发送数据包
    }
}

class Experiment
{
private:
    void CheckThroughput (); // 检查吞吐量函数
    void ReceivePacket (Ptr<Socket> socket); // 接收数据包函数
    void SendPacket (Ptr<Socket> socket, uint32_t available); // 发送数据包函数
   

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
                std::string CSVfileName); // 运行函数
    std::string CommandSetup (int argc, char **argv); // 命令设置函数
};

Experiment::Experiment()
        : port (9), // 初始化端口号为9
          bytesTotal (0), // 初始化总字节数为0
          packetsReceived (0), // 初始化收到的数据包数量为0
          m_CSVfileName ("WWSNwithSniffer20240701.csv"), // 初始化CSV文件名
          m_traceMobility (false), // 初始化移动性跟踪标志为false
          m_protocol (2) // 初始化协议类型
{
}

static inline std::string // 内联函数，返回string类型
PrintReceivedPacket (Ptr<Socket> socket, Ptr<Packet> packet, Address senderAddress) // 打印接收到的数据包函数
{
    std::ostringstream oss; // 创建ostringstream对象
    oss << Simulator::Now ().GetSeconds () << " " << socket->GetNode ()->GetId (); // 将当前仿真时间和节点ID添加到字符串流中

    if (InetSocketAddress::IsMatchingType (senderAddress)) // 如果发送者地址类型匹配
    {
        InetSocketAddress addr = InetSocketAddress::ConvertFrom (senderAddress); // 转换发送者地址为InetSocketAddress类型
        Ipv4Address ipv4Addr = addr.GetIpv4(); // 获取 IPv4 地址
        oss << " received one packet from " << ipv4Addr; // 添加从哪个IP地址接收到的数据包到字符串流中
    }
    else // 如果发送者地址类型不匹配
    {
        oss << " received one packet!"; // 添加接收到一个数据包的消息到字符串流中
    }
    return oss.str (); // 返回字符串流转换成的字符串
}


void
Experiment::SendPacket (Ptr<Socket> socket, uint32_t datasend) // 发送数据包函数
{
    packetsSentPerNode[socket->GetNode ()->GetId ()]++; // 增加发送的数据包数量
}

void
Experiment::ReceivePacket (Ptr<Socket> socket) // 接收数据包函数
{
    // Ptr<Packet> packet; // 创建Packet指针
    // Address senderAddress; // 创建地址变量
    // packetsReceivedList[socket->GetNode ()->GetId ()]++; // 增加接收的数据包数量
    // while ((packet = socket->RecvFrom (senderAddress))) // 当接收到数据包时
    // {
    //     bytesTotal += packet->GetSize (); // 增加总字节数
    //     packetsReceived += 1; // 增加收到的数据包数量

    //     std::ostringstream ossip;
    //     ossip.str("");
    //     ossip.clear();
    //     InetSocketAddress addr = InetSocketAddress::ConvertFrom (senderAddress); // 转换发送者地址为InetSocketAddress类型
    //     Ipv4Address ipv4Addr = addr.GetIpv4(); // 获取 IPv4 地址
    //     ipv4Addr.Print(ossip); // 将 IPv4 地址转换为字符串
    //     std::string ipAddressString = ossip.str();
    //     size_t lastDotPosition = ipAddressString.rfind('.');

    //     // 提取最后两位数字的子字符串
    //     std::string lastTwoDigitsStr = ipAddressString.substr(lastDotPosition + 1);

    //     // 将子字符串转换为整数
    //     int lastTwoDigits = std::stoi(lastTwoDigitsStr);

    //     packetsReceivedFromList[lastTwoDigits-1]++; // 增加从特定节点接收的数据包数量

    //     NS_LOG_UNCOND (PrintReceivedPacket (socket, packet, senderAddress)); // 打印接收到的数据包信息
    // }
}

void
Experiment::CheckThroughput () // 检查吞吐量函数
{
    double kbs = (bytesTotal * 8.0) / 1000; // 计算吞吐量（kbps）
    bytesTotal = 0; // 清零总字节数

    std::ofstream out (m_CSVfileName.c_str (), std::ios::app); // 打开CSV文件流

    out << (Simulator::Now ()).GetSeconds () << "," // 写入当前仿真时间
        << kbs << "," // 写入吞吐量
        << packetsReceived << "," // 写入收到的数据包数量
        << m_nSinks << "," // 写入汇聚节点数量
        << m_protocolName << "," // 写入协议名称
        << std::endl; // 换行

    out.close (); // 关闭文件流
    packetsReceived = 0; // 清零收到的数据包数量
    Simulator::Schedule (Seconds (1.0), &Experiment::CheckThroughput, this); // 定时调度下一次检查吞吐量
}

std::string
Experiment::CommandSetup (int argc, char **argv) // 命令设置函数
{
    CommandLine cmd (__FILE__); // 创建命令行对象
    cmd.AddValue ("CSVfileName", "The name of the CSV output file name", m_CSVfileName); // 添加CSV文件名参数
    cmd.AddValue ("traceMobility", "Enable mobility tracing", m_traceMobility); // 添加移动性跟踪标志参数
    cmd.AddValue ("protocol", "1=OLSR;2=AODV;3=DSDV;4=DSR", m_protocol); // 添加协议类型参数
    cmd.Parse (argc, argv); // 解析命令行参数
    return m_CSVfileName; // 返回CSV文件名
}

void
Experiment::Run (int nSinks, std::string CSVfileName) // 运行函数
{
    Packet::EnablePrinting (); // 启用数据包打印
    m_nSinks = nSinks; // 设置汇聚节点数量
    m_CSVfileName = CSVfileName; // 设置CSV文件名


    // int n_maliciouse = 10;
    int n_Nodes = 20; // number of WSN nodes
    double Totaltime = 100.0; //sim time (s)
    std::string phyMode ("DsssRate1Mbps"); // 物理模式
    


    NodeContainer wwsnNodes;
    // NodeContainer malicious;
    // NodeContainer not_malicious;


    wwsnNodes.Create (n_Nodes);
    // for (int i = 0; i < n_maliciouse; i++){
    //     malicious.Add (wwsnNodes.Get (i));
    // }
    // for (int i = n_maliciouse; i < n_Nodes; i++){
    //     not_malicious.Add (wwsnNodes.Get (i));
    // }

    // Set up WiFi
    WifiHelper wifi;
    wifi.SetStandard (WIFI_STANDARD_80211b); // 设置WiFi标准为802.11b
    YansWifiPhyHelper wifiPhy; // 创建YANS WiFi物理助手
    YansWifiChannelHelper wifiChannel; // 创建YANS WiFi信道助手
    wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel"); // 设置传播延迟模型
    wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel"); // 添加传播损耗模型
    // 



    // // For range near 250m
    wifiPhy.Set ("TxPowerStart", DoubleValue(7.5));
    wifiPhy.Set ("TxPowerEnd", DoubleValue(7.5));
    // wifiPhy.Set ("TxPowerLevels", UintegerValue(1));
    // wifiPhy.Set ("TxGain", DoubleValue(0));
    // wifiPhy.Set ("RxGain", DoubleValue(0));
    // //wifiPhy.Set ("EnergyDetectionThreshold", DoubleValue(-61.8));
    // //wifiPhy.Set ("CcaMode1Threshold", DoubleValue(-64.8));
    // wifiPhy.Set ("RxSensitivity", DoubleValue(-61.8)); /*csmmmari -61.8*/
    // wifiPhy.Set ("CcaEdThreshold", DoubleValue(-64.8)); /*csmmmari*/

    wifiPhy.SetChannel (wifiChannel.Create ()); // 设置WiFi物理层的信道

    // 添加MAC并禁用速率控制
    WifiMacHelper wifiMac; // 创建WiFi MAC助手
    wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                  "DataMode",StringValue (phyMode),
                                  "ControlMode",StringValue (phyMode)); // 设置远程站管理器

    wifiMac.SetType ("ns3::AdhocWifiMac");


    NetDeviceContainer devices = 
        wifi.Install (wifiPhy, wifiMac, wwsnNodes); // 安装WiFi设备
    

    BasicEnergySourceHelper basicSourceHelper; // 基础能量源助手
    basicSourceHelper.Set ("BasicEnergySourceInitialEnergyJ", DoubleValue (100)); // 设置初始能量
    EnergySourceContainer sources = basicSourceHelper.Install (wwsnNodes); // 安装能量源

    WifiRadioEnergyModelHelper radioEnergyHelper; // 无线电能量模型助手
    radioEnergyHelper.Set ("TxCurrentA", DoubleValue (0.0174)); // 设置发送电流
    radioEnergyHelper.Set ("RxCurrentA", DoubleValue (0.0174));
    DeviceEnergyModelContainer deviceModels = radioEnergyHelper.Install (devices, sources); // 安装设备能量模型

    MobilityHelper mobilityAdhoc; // 创建移动性助手
    ObjectFactory pos; // 创建对象工厂
    pos.SetTypeId ("ns3::RandomRectanglePositionAllocator"); // 设置位置分配器类型
    pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=300.0]")); // 设置X轴均匀随机分布
    pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=300.0]")); // 设置Y轴均匀随机分布

    Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> (); // 创建位置分配器对象

    mobilityAdhoc.SetPositionAllocator (taPositionAlloc); // 设置位置分配器
    mobilityAdhoc.SetMobilityModel ("ns3::ConstantPositionMobilityModel"); // 设置移动性模型为常量位置模型
    mobilityAdhoc.Install (wwsnNodes); // 安装移动性模型

    Ptr<ConstantPositionMobilityModel> centerPosition = wwsnNodes.Get(0)->GetObject<ConstantPositionMobilityModel>();
    centerPosition->SetPosition(Vector(150.0, 150.0, 0.0)); // 设置节点0的X、Y坐标为网络中心 (250, 250)，Z坐标为0

    AodvHelper aodv; // 创建AODV助手
    OlsrHelper olsr; // 创建OLSR助手
    DsdvHelper dsdv; // 创建DSDV助手
    DsrHelper dsr; // 创建DSR助手
    DsrMainHelper dsrMain; // 创建DSR主助手
    Ipv4ListRoutingHelper list; // 创建IPv4路由助手
    InternetStackHelper internet; // 创建互联网协议栈助手
    switch (m_protocol) // 根据协议类型选择路由协议
    {
        case 1:
            list.Add (olsr, 100); // 添加OLSR路由协议到IPv4路由助手中
            m_protocolName = "OLSR"; // 设置协议名称为OLSR
            break;
        case 2:
            list.Add (aodv, 100); // 添加AODV路由协议到IPv4路由助手中
            m_protocolName = "AODV"; // 设置协议名称为AODV
            break;
        case 3:
            list.Add (dsdv, 100); // 添加DSDV路由协议到IPv4路由助手中
            m_protocolName = "DSDV"; // 设置协议名称为DSDV
            break;
        case 4:
            m_protocolName = "DSR"; // 设置协议名称为DSR
            break;
        default:
            NS_FATAL_ERROR ("No such protocol:" << m_protocol); // 输出错误信息，协议类型不存在
    }

    if (m_protocol < 4) // 如果协议类型小于4
    {
        internet.SetRoutingHelper (list); // 设置互联网协议栈的路由助手
        internet.Install (wwsnNodes); // 安装互联网协议栈
    }
    else if (m_protocol == 4) // 如果协议类型等于4
    {
        internet.Install (wwsnNodes); // 安装互联网协议栈
        dsrMain.Install (dsr, wwsnNodes); // 安装DSR主助手
    }

    Ipv4AddressHelper ipv4;
    NS_LOG_INFO ("Assign IP Addresses.");
    ipv4.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer adhocInterfaces = ipv4.Assign (devices);

    for (int i = 0; i < n_Nodes; i++) // 循环设置RemainingEnergy
    {
        Ptr<BasicEnergySource> basicSourcePtr = 
            DynamicCast<BasicEnergySource> (sources.Get (i));
        basicSourcePtr->TraceConnectWithoutContext (
            "RemainingEnergy", MakeCallback (&RemainingEnergy));
    }

    

    for (int i = 0; i < nSinks; i++) // 循环设置发送节点
    {
        TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
        Ptr<Socket> sink = Socket::CreateSocket (wwsnNodes.Get (i), tid); // 创建套接字
        InetSocketAddress local = InetSocketAddress (adhocInterfaces.GetAddress (i), port); // 创建本地套接字地址
        sink->Bind (local); // 绑定套接字
        // sink->SetRecvCallback (MakeCallback (&MyApp::RecPacket, this)); // 设置接收回调函数
    
        PacketSinkHelper packetSinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (adhocInterfaces.GetAddress (i), port));  // 创建数据包接收器助手
        ApplicationContainer sinkApps = packetSinkHelper.Install (wwsnNodes.Get (i));  // 安装数据包接收器到节点1
        sinkApps.Start (Seconds (0));  // 启动数据包接收器应用
        sinkApps.Stop (Seconds (Totaltime));  // 停止数据包接收器应用

        Mac48Address mac_peer = Mac48Address::ConvertFrom (wwsnNodes.Get (i)->GetDevice (0)->GetAddress ());
        // NS_LOG_INFO("mac_peer"<<mac_peer);
        for (int j = nSinks; j < n_Nodes; j++)
        {
        Ptr<MyApp> app = CreateObject<MyApp> ();  // 创建应用程序对象
        Ptr<Socket> source = Socket::CreateSocket (wwsnNodes.Get (j), tid);
        Mac48Address mac_sorce = Mac48Address::ConvertFrom (wwsnNodes.Get (j)->GetDevice (0)->GetAddress ());
        app->Setup (source, adhocInterfaces.GetAddress (j), adhocInterfaces.GetAddress (i), mac_sorce, mac_peer, 1040, 1000, DataRate ("1Mbps"));  // 配置应用程序参数
        app->SetStartTime (Seconds (0));  // 设置应用程序启动时间
        app->SetStopTime (Seconds (Totaltime));  // 设置应用程序停止时间
        wwsnNodes.Get (j)->AddApplication (app);  // 将应用程序安装到节点
        }
    }

    Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/MonitorSnifferRx", MakeCallback(&MonitorSnifferRx));
    Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/MonitorSnifferTx", MakeCallback(&MonitorSnifferTx));

    NS_LOG_INFO ("Run Simulation."); // 输出运行仿真信息

    CheckThroughput (); // 检查吞吐量

    wifiPhy.EnablePcapAll ("pcap\\wwsn20240701");
    AnimationInterface anim("wwsn20240701.xml"); // 创建动画接口
    Simulator::Stop (Seconds (Totaltime)); // 停止仿真
    Simulator::Run (); // 运行仿真
    
    

    Simulator::Destroy (); // 销毁仿真器

    // Trace functions
/// Trace function for remaining energy at node.

}





int
main (int argc, char *argv[]) // 主函数
{
    LogComponentEnable("sniffer(20240701)", LOG_ALL);
    Experiment experiment; // 创建Experiment对象
    std::string CSVfileName = "wwsn20240701experiment"; // 调用命令设置函数获取CSV文件名

    //清空上一个输出文件并写入列标题
    std::ofstream out (CSVfileName.c_str ());
    out << "SimulationSecond," <<
        "ReceiveRate," <<
        "PacketsReceived," <<
        "NumberOfSinks," <<
        "RoutingProtocol," <<
        "TransmissionPower" <<
        std::endl;
    out.close ();

    int nSinks = 1; // 汇聚节点数量


    experiment.Run (nSinks, CSVfileName); // 运行实验


    return 0; // 返回0表示成功
}