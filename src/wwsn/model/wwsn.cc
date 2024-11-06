#include <fstream> // 包含文件流头文件，用于文件操作
#include <iostream> // 包含输入输出流头文件，用于标准输入输出
#include <vector>
#include <string>
#include <functional>
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
#include "ns3/wwsn.h"
using namespace ns3;
using namespace dsr;


NS_LOG_COMPONENT_DEFINE ("wwsnSim"); 

std::string snifferExpname = "wwsnSim";

// 定义全局变量来统计数据包数量和丢失数量
// 定义全局变量来统计数据包数量和丢失数量
std::map<uint32_t, uint32_t> packetsReceivedList; // 每个节点接收到的数据包数量
std::map<uint32_t, uint32_t> packetsSentPerNode; // 每个节点发送的数据包数量
std::map<uint32_t, uint32_t> packetsForwardedList; // 每个节点转发的数据包数量
std::map<uint32_t, uint32_t> packetsReceivedFromList; // 从每个节点接收到的数据包数量
std::map<uint32_t, double> energyConsumedList; // 每个节点消耗的能量

void ClearFile(const std::string &filename) {
    std::ofstream ofs;
    ofs.open(filename, std::ofstream::out | std::ofstream::trunc);
    ofs.close();
}

void RemainingEnergy(double oldValue, double remainingEnergy) {
    // NS_LOG_UNCOND (Simulator::Now ().GetSeconds ()
    //              << "s Current remaining energy = " << remainingEnergy << "J");
}

void TotalEnergy (double oldValue, double totalEnergy)
{
//   NS_LOG_UNCOND (Simulator::Now ().GetSeconds ()
//                  << "s Total energy consumed by radio = " << totalEnergy << "J");
}






// 获取MAC地址对应的节点ID的函数
uint32_t GetNodeIdFromMacAddress(Mac48Address mac) {
    uint8_t macArray[6];
    mac.CopyTo(macArray);
    uint32_t nodeId = macArray[5] + 1; // 最后一字节加1
    return nodeId;
}




PacketInfo HandlePacket(Ptr<const Packet> packet) {
    uint32_t packetSize = packet->GetSize();
    Mac48Address srcMac;
    std::string packetType;
    PacketInfo info;

    // 将数据包内容复制到缓冲区
    uint8_t buffer[1500];

    packet->CopyData(buffer, packetSize);

    // 解析MAC层
    uint32_t SequenceNumber = 0;
    if (packetSize > 14) { // 至少需要14字节才能解析MAC层头部
        srcMac.CopyFrom(buffer + 10); // 第11到16字节是源MAC地址
        // packetType = "Generic Ethernet Frame";
        SequenceNumber =  (buffer[22] << 8) | buffer[23];
        if (buffer[30] == 0x08 && buffer[31] == 0x00) { // IPv4
            // 解析网络层（IPv4）
            if (packetSize >= 34) { // 至少需要34字节才能解析IPv4头部
                if (buffer[41] == 0x11 && buffer[55] == 0x09) { // UDP
                    packetType = "UDP";
                } else if (buffer[41] == 0x01) { // ICMP
                    packetType = "ICMP";
                } else if (buffer[41] == 0x11 && buffer[60] == 0x01){
                    packetType = "Route Request";
                } else if (buffer[41] == 0x11 && buffer[60] == 0x02){
                    packetType = "Route Replay";
                } else if (buffer[41] == 0x11 && buffer[60] == 0x03){
                    packetType = "Route Error";
                } else if (buffer[41] == 0x11 && buffer[60] == 0x04){
                    packetType = "Route Replay ACK";
                } 
            }
        } else if (buffer[30] == 0x08 && buffer[31] == 0x06) { // ARP
            if (buffer[39] == 0x01){
                packetType = "ARP Request";
            } else if (buffer[39] == 0x02){
                packetType = "ARP Replay";
            }
        }
    } else {
        packetType = "ACK";
        srcMac.CopyFrom(buffer + 4);
    }
    
    uint32_t srcNodeId = GetNodeIdFromMacAddress(srcMac);

    info.packetType = packetType;
    info.srcMac = srcMac;
    info.srcNodeId = srcNodeId;
    info.SequenceNumber = SequenceNumber;


    return info;
}


// 从 context 字符串中提取节点ID并加1
uint32_t GetNodeIdFromContext(const std::string &context) {
    size_t startPos = context.find("/NodeList/") + 10;
    size_t endPos = context.find("/", startPos);
    if (startPos != std::string::npos && endPos != std::string::npos) {
        uint32_t nodeId = std::stoi(context.substr(startPos, endPos - startPos));
        return nodeId;
    }
    return 0; // 未找到节点ID，返回0
}

void 
WWSNMonitorSnifferRx ( std::string context, 
                    Ptr<const Packet> packet, 
                    uint16_t channelFreqMhz, 
                    WifiTxVector txVector, 
                    MpduInfo aMpdu, 
                    SignalNoiseDbm signalNoise, 
                    uint16_t staId)
{
    std::string filename = snifferExpname + "/MonitorSnifferRx.csv";
    static std::fstream f (filename, std::ios::out | std::ios::app);
    if (!f.is_open()) {
        std::cerr << "Error opening file" << std::endl;
        return;
    }
    // 写入 CSV 文件头（仅在第一次写入时）
    static bool first = true;
    if (first) {
        ClearFile(filename);
        f << "Time,PacketType,SequenceNumber,listener,SrcNodeId,SNR,SignalPower,NoisePower,PacketSize,ChannelFreqMhz,MpduRefNumber,StaId\n";
        first = false;
    }
    double currenttime = (Simulator::Now ()).GetSeconds (); // 下一次发送的时间
    PacketInfo info = HandlePacket(packet);
    uint32_t listenerNodeId = GetNodeIdFromContext(context) + 1;
    
    // 写入参数值到 CSV 文件
    f << currenttime << ","
    << info.packetType << ","
    << info.SequenceNumber << ","
    << listenerNodeId << ","
    << info.srcNodeId << ","
    << signalNoise.signal - signalNoise.noise << ","
    << signalNoise.signal << ","
    << signalNoise.noise << ","
    << packet->GetSize() << ","
    << channelFreqMhz << ","
    << aMpdu.mpduRefNumber << ","
    << staId << "\n";
};

void 
WWSNMonitorSnifferTx ( std::string context,
                    Ptr<const Packet> packet,
                    uint16_t channelFreqMhz,
                    WifiTxVector txVector,
                    MpduInfo aMpdu,
                    uint16_t staId)
{
    std::string filename = snifferExpname + "/MonitorSnifferTx.csv";
    static std::fstream f (filename, std::ios::out | std::ios::app);
    if (!f.is_open()) {
        std::cerr << "Error opening file" << std::endl;
        return;
    }
    // 写入 CSV 文件头（仅在第一次写入时)
    static bool first = true;
    if (first) {
        ClearFile(filename);
        f << "Time,PacketType,SequenceNumber,listener,SrcNodeId,PacketSize,ChannelFreqMhz,MpduRefNumber,StaId\n";
        first = false;
    }
    double currenttime = (Simulator::Now ()).GetSeconds (); // 下一次发送的时间
    PacketInfo info = HandlePacket(packet);
    uint32_t listenerNodeId = GetNodeIdFromContext(context);
    // NS_LOG_INFO ("Received packet from IP: " << sourceIp << " to IP: " << destIp);
    
    // 写入参数值到 CSV 文件
    f << currenttime << ","
    << info.packetType << ","
    << info.SequenceNumber <<","
    << listenerNodeId << ","
    << info.srcNodeId << ","
    << packet->GetSize() << ","
    << channelFreqMhz << ","
    << aMpdu.mpduRefNumber << ","
    << staId << "\n";
}



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
          port (9),
          bytesTotal (0), // 初始化总字节数为0
          m_checkThroughoutputfileName (), // 初始化CSV文件名
          m_sink (false),
          thoughoutputFirst (true)
{
}

MyApp::~MyApp()
{
    m_socket = 0;
}

void
MyApp::Setup (Ptr<Socket> socket, 
Ipv4Address source, 
Ipv4Address address, 
Mac48Address  macsource, 
Mac48Address  macdestination,
uint32_t packetSize, 
uint32_t nPackets, 
DataRate dataRate,
std::string checkThroughoutputfileName,
bool sink)
{
    m_socket = socket;
    m_source = source;
    m_peer = address;
    mac_source = macsource;
    mac_peer = macdestination;
    m_packetSize = packetSize;
    m_nPackets = nPackets;
    m_dataRate = dataRate;
    m_checkThroughoutputfileName = checkThroughoutputfileName;
    m_sink = sink;
}

void
MyApp::StartApplication (void)
{   
    if (m_sink){
        InetSocketAddress local = InetSocketAddress (m_source, port); // 创建本地套接字地址
        m_socket->Bind (local);  // 绑定 Socket
        CheckThroughput();
        m_socket->SetRecvCallback(MakeCallback (&MyApp::RecPacket, this));
        
    } else {
        InetSocketAddress remote = InetSocketAddress (m_peer, port); // 创建远程套接字地址
        // NS_LOG_INFO("remoteInetSocketAddress"<<remote);
        InetSocketAddress local = InetSocketAddress (m_source, port); // 创建本地套接字地址
        m_running = true;
        m_packetsSent = 0;
        m_socket->Bind (local);  // 绑定 Socket
        m_socket->Connect (remote);  // 连接对端
        SendPacket (m_source, m_peer, mac_source, mac_peer);  // 发送数据包
    }
    
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
MyApp::CheckThroughput () // 检查吞吐量函数
{
    double kbs = (bytesTotal * 8.0) / 1000; // 计算吞吐量（kbps）
    bytesTotal = 0; // 清零总字节数
    std::string filename = m_checkThroughoutputfileName + "/Throughoutput.csv";
    std::ofstream out (filename.c_str (), std::ios::app); // 打开CSV文件流

        // 如果是第一次执行，写入 CSV 文件的表头
    if (thoughoutputFirst) {
        ClearFile(filename);
        out << "Time,Throughput(kbps)" << std::endl;
        thoughoutputFirst = false;
    }

    out << (Simulator::Now ()).GetSeconds () << "," // 写入当前仿真时间
        << kbs << "," // 写入吞吐量
        << std::endl; // 换行

    out.close (); // 关闭文件流
    Simulator::Schedule (Seconds (1.0), &MyApp::CheckThroughput, this); // 定时调度下一次检查吞吐量
}

void
MyApp::RecPacket(Ptr<Socket> socket)
{
    Ptr<Packet> packet; // 创建Packet指针
    Address senderAddress; // 创建地址变量
    while ((packet = socket->RecvFrom (senderAddress))) // 当接收到数据包时
    {
        packetsReceivedList[socket->GetNode ()->GetId ()]++;
        bytesTotal += packet->GetSize (); // 增加总字节数
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
        // Time tNext (Seconds (m_packetSize * 8 / static_cast<double> (m_dataRate.GetBitRate ())));  // 下一次发送的时间
        Time tNext = Seconds(0.05); // 下一次发送的时间
        m_sendEvent = Simulator::Schedule (tNext, &MyApp::SendPacket, this, m_source, m_peer, mac_source, mac_peer);  // 定时发送数据包
    }
}

Experiment::Experiment()
        : port (9), // 初始化端口号为9
          bytesTotal (0), // 初始化总字节数为0
          packetsReceived (0), // 初始化收到的数据包数量为0
          m_traceMobility (false), // 初始化移动性跟踪标志为false
          m_protocol (4) // 初始化协议类型
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

std::string 
Experiment::setExpname(std::string outExpname)
{
    expname = outExpname;
    return expname;
}



void
Experiment::CommandSetup (int argc, char **argv) // 命令设置函数
{
    CommandLine cmd (__FILE__); // 创建命令行对象
    cmd.AddValue ("traceMobility", "Enable mobility tracing", m_traceMobility); // 添加移动性跟踪标志参数
    cmd.AddValue ("protocol", "1=OLSR;2=AODV;3=DSDV;4=DSR;5=AODVBHSF", m_protocol); // 添加协议类型参数
    cmd.Parse (argc, argv); // 解析命令行参数
}

void Experiment::setDeviceEnergyModelContainer(ns3::DeviceEnergyModelContainer deviceModels){

    ExpdeviceModels = deviceModels;

};
// 定时器触发函数：每秒调用一次
void Experiment::LogEnergyForAllNodes() {
    // 获取当前模拟时间
    double currentTime = Simulator::Now().GetSeconds();
    static bool first = true;
    std::string filename = snifferExpname + "/remaining_energy.csv";
    static std::fstream f(filename, std::ios::out | std::ios::app);
    int i = 1;
    // 如果是第一次执行，写入 CSV 文件的表头
    if (first) {
        ClearFile(filename);
        f << "NodeId,Time,EnergyConsumed" << std::endl;
        first = false;
    }
    for (DeviceEnergyModelContainer::Iterator iter = ExpdeviceModels.Begin (); iter != ExpdeviceModels.End (); iter ++)
    {
        double energyConsumed = (*iter)->GetTotalEnergyConsumption ();
        // NS_LOG_UNCOND ("End of simulation (" << Simulator::Now ().GetSeconds ()
        //                 << "s) Total energy consumed by radio = " << energyConsumed << "J");
        // NS_ASSERT (energyConsumed <= 0.1);
        // 写入当前节点的剩余能量到 CSV 文件
        f << i << "," << currentTime << "," << energyConsumed << std::endl;
        i++;
    }
    // 设置下一秒定时器
    Simulator::Schedule(Seconds(1.0), &Experiment::LogEnergyForAllNodes, this);
}

void
Experiment::Run (int nSinks, double simtime, int nodes, double BHradio,
                    double SFradio, 
                    std::string expname,
                    double x_y_length,
                    int uniform
                    ) // 运行函数
{   
    Experiment::setExpname(expname);
    Packet::EnablePrinting (); // 启用数据包打印
    m_nSinks = nSinks; // 设置汇聚节点数量


    // int n_maliciouse = 10;
    int n_Nodes = nodes; // number of WSN nodes
    double Totaltime = simtime; //sim time (s)
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
    wifiChannel.AddPropagationLoss ("ns3::undergroundLoraLoss"); // 添加传播损耗模型

    // 



    // // For range near 250m
    wifiPhy.Set ("TxPowerStart", DoubleValue(22));
    wifiPhy.Set ("TxPowerEnd", DoubleValue(22));
    wifiPhy.Set ("TxPowerLevels", UintegerValue(1));
    wifiPhy.Set ("TxGain", DoubleValue(0));
    wifiPhy.Set ("RxGain", DoubleValue(0));
    wifiPhy.Set ("RxSensitivity", DoubleValue(-140)); /*csmmmari -61.8*/


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
    radioEnergyHelper.Set ("TxCurrentA", DoubleValue (0.1)); // 设置发送电流
    radioEnergyHelper.Set ("RxCurrentA", DoubleValue (0.1));
    DeviceEnergyModelContainer deviceModels = radioEnergyHelper.Install (devices, sources); // 安装设备能量模型
    Experiment::setDeviceEnergyModelContainer(deviceModels);

    MobilityHelper mobilityAdhoc; // 创建移动性助手
    ObjectFactory pos; // 创建对象工厂
    pos.SetTypeId ("ns3::RandomRectanglePositionAllocator"); // 设置位置分配器类型

    pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=" + std::to_string(x_y_length)+ "]")); // 设置X轴均匀随机分布
    pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=" + std::to_string(x_y_length)+ "]")); // 设置Y轴均匀随机分布

    Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> (); // 创建位置分配器对象

    mobilityAdhoc.SetPositionAllocator (taPositionAlloc); // 设置位置分配器
    mobilityAdhoc.SetMobilityModel ("ns3::ConstantPositionMobilityModel"); // 设置移动性模型为常量位置模型
    mobilityAdhoc.Install (wwsnNodes); // 安装移动性模型

    Ptr<ConstantPositionMobilityModel> centerPosition = wwsnNodes.Get(0)->GetObject<ConstantPositionMobilityModel>();
    centerPosition->SetPosition(Vector(x_y_length / 2, x_y_length / 2, 0.0)); // 设置节点0的X、Y坐标为网络中心 (250, 250)，Z坐标为0

    if (uniform == 1){
        // 为其他节点分配均匀的位置
        uint32_t numNodes = wwsnNodes.GetN();
        double gridSpacing = std::sqrt(x_y_length * x_y_length / (numNodes - 1)); // 根据节点数量计算网格间距

        uint32_t nodeIndex = 1;
        for (double x = gridSpacing / 2; x < x_y_length; x += gridSpacing) {
            for (double y = gridSpacing / 2; y < x_y_length; y += gridSpacing) {
                if (nodeIndex >= numNodes) break;
                Ptr<ConstantPositionMobilityModel> nodePosition = wwsnNodes.Get(nodeIndex)->GetObject<ConstantPositionMobilityModel>();
                nodePosition->SetPosition(Vector(x, y, 0.0));
                nodeIndex++;
            }
            if (nodeIndex >= numNodes) break;
        }
    }

    AodvHelper aodv; // 创建AODV助手
    OlsrHelper olsr; // 创建OLSR助手
    DsdvHelper dsdv; // 创建DSDV助手
    DsrHelper dsr; // 创建DSR助手
    AodvBHSFHelper aodvbhsf; //AODV with blackhole and selecting forwarding
    // 调用 SetMaliciousNodes 设置恶意节点
    double blackholeRatio = BHradio; // 黑洞节点比例，例如 10%
    double selectiveForwardingRatio = SFradio; // 选择性转发节点比例，例如 20%
    aodvbhsf.SetMaliciousNodes(wwsnNodes, blackholeRatio, selectiveForwardingRatio); // 使用 wwsnNodes 节点容器


    DsrMainHelper dsrMain; // 创建DSR主助手
    Ipv4ListRoutingHelper list; // 创建IPv4路由助手
    InternetStackHelper internet; // 创建互联网协议栈助手
    Ipv4AddressHelper ipv4;

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
            list.Add (aodvbhsf, 100); 
            m_protocolName = "AODVBHSF"; // 设置协议名称为DSR
            break;
        case 5:
            m_protocolName = "DSR"; // 设置协议名称为DSR
            break;
        default:
            NS_FATAL_ERROR ("No such protocol:" << m_protocol); // 输出错误信息，协议类型不存在
    }

    if (m_protocol < 5) // 如果协议类型小于4
    {
        internet.SetRoutingHelper (list); // 设置互联网协议栈的路由助手
        internet.Install (wwsnNodes); // 安装互联网协议栈
    }
    else if (m_protocol == 5) // 如果协议类型等于4
    {
        internet.Install (wwsnNodes); // 安装互联网协议栈
        dsrMain.Install (dsr, wwsnNodes); // 安装DSR主助手
    }
    ipv4.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer adhocInterfaces = ipv4.Assign (devices);
    NS_LOG_INFO ("Assign IP Addresses.");



    for (int i = 0; i < n_Nodes; i++) // 循环设置RemainingEnergy
    {
        Ptr<BasicEnergySource> basicSourcePtr = 
            DynamicCast<BasicEnergySource> (sources.Get (i));
        basicSourcePtr->TraceConnectWithoutContext (
            "RemainingEnergy", MakeCallback (&RemainingEnergy));
        Ptr<DeviceEnergyModel> basicRadioModelPtr =
        basicSourcePtr->FindDeviceEnergyModels ("ns3::WifiRadioEnergyModel").Get (0);
        NS_ASSERT (basicRadioModelPtr != NULL);
        basicRadioModelPtr->TraceConnectWithoutContext ("TotalEnergyConsumption", MakeCallback (&TotalEnergy));
    }

    Simulator::Schedule(Seconds(1.0), &Experiment::LogEnergyForAllNodes, this);

    uint32_t packets_number = uint32_t(Totaltime * 20);

    for (int i = 0; i < nSinks; i++) // 循环设置发送节点
    {
        TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
        // Ptr<Socket> sink = Socket::CreateSocket (wwsnNodes.Get (i), tid); // 创建套接字
        // InetSocketAddress local = InetSocketAddress (adhocInterfaces.GetAddress (i), port); // 创建本地套接字地址
        // sink->Bind (local); // 绑定套接字
        // // sink->SetRecvCallback (MakeCallback (&MyApp::RecPacket, this)); // 设置接收回调函数
    
        // PacketSinkHelper packetSinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (adhocInterfaces.GetAddress (i), port));  // 创建数据包接收器助手
        // ApplicationContainer sinkApps = packetSinkHelper.Install (wwsnNodes.Get (i));  // 安装数据包接收器到节点1
        // sinkApps.Start (Seconds (0));  // 启动数据包接收器应用
        // sinkApps.Stop (Seconds (Totaltime));  // 停止数据包接收器应用

        Ptr<MyApp> app = CreateObject<MyApp> ();  // 创建应用程序对象
        Ptr<Socket> source = Socket::CreateSocket (wwsnNodes.Get (i), tid);
        Mac48Address mac_sorce = Mac48Address::ConvertFrom (wwsnNodes.Get (i)->GetDevice (0)->GetAddress ());
        app->Setup (source, adhocInterfaces.GetAddress (i), adhocInterfaces.GetAddress (i), mac_sorce, mac_sorce, 1040, packets_number, DataRate ("1Mbps"), expname, true);  // 配置sink应用程序参数
        app->SetStartTime (Seconds (0));  // 设置应用程序启动时间
        app->SetStopTime (Seconds (Totaltime));  // 设置应用程序停止时间
        wwsnNodes.Get (i)->AddApplication (app);  // 将应用程序安装到节点

        Mac48Address mac_peer = Mac48Address::ConvertFrom (wwsnNodes.Get (i)->GetDevice (0)->GetAddress ());
        // NS_LOG_INFO("mac_peer"<<mac_peer);
        for (int j = nSinks; j < n_Nodes; j++)
        {
        Ptr<MyApp> app = CreateObject<MyApp> ();  // 创建应用程序对象
        Ptr<Socket> source = Socket::CreateSocket (wwsnNodes.Get (j), tid);
        Mac48Address mac_sorce = Mac48Address::ConvertFrom (wwsnNodes.Get (j)->GetDevice (0)->GetAddress ());
        app->Setup (source, adhocInterfaces.GetAddress (j), adhocInterfaces.GetAddress (i), mac_sorce, mac_peer, 1040, packets_number, DataRate ("1Mbps"), expname, false);  // 配置send应用程序参数
        app->SetStartTime (Seconds (0));  // 设置应用程序启动时间
        app->SetStopTime (Seconds (Totaltime));  // 设置应用程序停止时间
        wwsnNodes.Get (j)->AddApplication (app);  // 将应用程序安装到节点
        }
    }

    Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/MonitorSnifferRx", MakeCallback(&WWSNMonitorSnifferRx));
    Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/MonitorSnifferTx", MakeCallback(&WWSNMonitorSnifferTx));




    NS_LOG_INFO ("Run Simulation."); // 输出运行仿真信息
    std::string filename = expname + "/pcap/wwsn";
    wifiPhy.EnablePcapAll (filename);
    filename = expname + "/wwsn.xml";
    AnimationInterface anim(filename); // 创建动画接口
    Simulator::Stop (Seconds (Totaltime)); // 停止仿真
    Simulator::Run (); // 运行仿真
    
    

    Simulator::Destroy (); // 销毁仿真器

    // Trace functions
/// Trace function for remaining energy at node.
}




