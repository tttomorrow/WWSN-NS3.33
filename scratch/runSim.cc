#include <fstream> // 包含文件流头文件，用于文件操作
#include <iostream> // 包含输入输出流头文件，用于标准输入输出
#include <vector>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <ns3/wwsn.h>
using namespace ns3;
using namespace dsr;


int
main (int argc, char *argv[]) // 主函数
{   

    int nSinks = 1; // 汇聚节点数量
    double simtime = 50.0;
    int num_nodes = 50;  
    double BHradio = 0.1;
    double SFradio = 0.0;
    std::string expname = "20241101_simtime" + std::to_string(int(simtime)) 
                        + "_num_nodes" + std::to_string(int(num_nodes)) 
                        + "_BHradio" + std::to_string(int(BHradio)) 
                        + "_SFradio" + std::to_string(int(SFradio));
    const char* expname0 = expname.c_str();
    std::string expname1 = "20241101_simtime" + std::to_string(int(simtime)) 
                        + "_num_nodes" + std::to_string(int(num_nodes)) 
                        + "_BHradio" + std::to_string(int(BHradio)) 
                        + "_SFradio" + std::to_string(int(SFradio)) + "/pcap";

    Experiment experiment; // 创建Experiment对象
    snifferExpname = expname;
    const char* folder0 = expname0;
    mkdir(folder0, 0777);
    const char* folder1 = expname1.c_str();
    mkdir(folder1, 0777);

    LogComponentEnable("soilMoistureUpdater", ns3::LOG_LEVEL_DEBUG);
    LogComponentEnable("AODVWITHBHANDSF", ns3::LOG_LEVEL_DEBUG);
    LogComponentEnable("AODVWITHBHANDSF-helper", ns3::LOG_LEVEL_DEBUG);
    
    // CheckThroughput
    std::string CSVfileName = expname + "/experiment"; // 调用命令设置函数获取CSV文件名
 

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

    
    experiment.Run (nSinks, 
                    CSVfileName, 
                    simtime, 
                    num_nodes,
                    BHradio,
                    SFradio,
                    expname); // 运行实验



    return 0; // 返回0表示成功
}