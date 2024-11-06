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
    double simtime = 100.0;
    int num_nodes = 50;  
    double BHradio = 0.1;
    double SFradio = 0.0;
    double x_y_length = 20.0;// 节点范围
    int uniform = 1;//控制节点是否均匀分布
    std::string expname = "20241106_testTX_constantUniform_simtime-" + std::to_string(int(simtime)) 
                        + "_num_nodes-" + std::to_string(int(num_nodes)) 
                        + "_BHradio-" + std::to_string(int(BHradio)) 
                        + "_SFradio-" + std::to_string(int(SFradio))
                        + "_fieldLength-" + std::to_string(int(x_y_length))
                        + "_uniform-" + std::to_string(int(uniform));
    const char* expname0 = expname.c_str();
    std::string expname1 = expname + "/pcap";

    Experiment experiment; // 创建Experiment对象
    snifferExpname = expname;
    const char* folder0 = expname0;
    mkdir(folder0, 0777);
    const char* folder1 = expname1.c_str();
    mkdir(folder1, 0777);

    LogComponentEnable("soilMoistureUpdater", ns3::LOG_LEVEL_DEBUG);
    LogComponentEnable("AODVWITHBHANDSF", ns3::LOG_LEVEL_DEBUG);
    LogComponentEnable("AODVWITHBHANDSF-helper", ns3::LOG_LEVEL_DEBUG);
    // LogComponentEnable("PropagationLossModel", ns3::LOG_LEVEL_DEBUG);
    
    



    
    experiment.Run (nSinks, 
                    simtime, 
                    num_nodes,
                    BHradio,
                    SFradio,
                    expname,
                    x_y_length,
                    uniform); // 运行实验



    return 0; // 返回0表示成功
}