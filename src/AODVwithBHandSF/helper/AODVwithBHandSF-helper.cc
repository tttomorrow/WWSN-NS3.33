/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "AODVwithBHandSF-helper.h"
#include "ns3/AODVwithBHandSF.h"
#include "ns3/node-list.h"
#include "ns3/names.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-list-routing.h"
#include <iostream>
#include <unordered_set>
#include <random>

namespace ns3
{
NS_LOG_COMPONENT_DEFINE("AODVWITHBHANDSF-helper");
AodvBHSFHelper::AodvBHSFHelper() : 
  Ipv4RoutingHelper ()
{
  m_agentFactory.SetTypeId ("ns3::aodv::AodvBHSFRoutingProtocol");
}

AodvBHSFHelper* 
AodvBHSFHelper::Copy (void) const 
{
  return new AodvBHSFHelper (*this); 
}

Ptr<Ipv4RoutingProtocol> 
AodvBHSFHelper::Create (Ptr<Node> node) const
{
  // 调用重载的 Create 函数，传入默认值
  double SetInsertTime = 0.0;
  return Create(node, SetInsertTime);
}

Ptr<Ipv4RoutingProtocol> 
AodvBHSFHelper::Create (Ptr<Node> node, double insertTime) const
{
  Ptr<aodv::AodvBHSFRoutingProtocol> agent = m_agentFactory.Create<aodv::AodvBHSFRoutingProtocol> ();
  node->AggregateObject (agent);
  agent->SetInsertTime(insertTime);
  uint32_t nodeId = node->GetId();

  // 检查节点是否在黑洞节点列表中
  if (m_blackholeNodes.find(nodeId) != m_blackholeNodes.end())
  {
    agent->SetBlackhole(true);
    // NS_LOG_DEBUG("Node " << nodeId << " set as Blackhole node in Create.");
  }

  // 检查节点是否在选择性转发节点列表中
  if (m_selectiveForwardingNodes.find(nodeId) != m_selectiveForwardingNodes.end())
  {
    agent->SetSelectiveForwarding(true);
    // NS_LOG_DEBUG("Node " << nodeId << " set as Selective Forwarding node in Create.");
  }

  return agent;
}

void 
AodvBHSFHelper::Set (std::string name, const AttributeValue &value)
{
  m_agentFactory.Set (name, value);
}

void 
AodvBHSFHelper::SetMaliciousNodes(NodeContainer nodes, double blackholeRatio, double selectiveForwardingRatio)
{
  
  Ptr<UniformRandomVariable> randomVar = CreateObject<UniformRandomVariable>();
  std::unordered_set<int> uniqueNumbers;
  const uint32_t fixedSeed = 23456;  // 随机数种子
  std::mt19937 gen(fixedSeed);  // 使用 Mersenne Twister 算法
  std::uniform_int_distribution<> dis(2, nodes.GetN()); // 定义随机数分布
  uint32_t count = ((blackholeRatio + selectiveForwardingRatio) * nodes.GetN());
  uint32_t randomNumbers[count];
  NS_LOG_DEBUG("malicious Nodes number" << count << " .");
  // 生成不重复的随机数
  while (uniqueNumbers.size() < count) {
      uniqueNumbers.insert(dis(gen));
  }

  // 将生成的随机数保存到数组中
  uint32_t index = 0;
  int BHcount = 0;
  for (int number : uniqueNumbers) {
      randomNumbers[index++] = number;
      NS_LOG_DEBUG("randomNumbers" << number << " .");
  }
  for (uint32_t i = 0; i < count; i++)
  {
    
    if (BHcount < blackholeRatio * nodes.GetN())
    {
      m_blackholeNodes.insert(randomNumbers[i]);
      BHcount++;
      NS_LOG_DEBUG("Node " << randomNumbers[i] << " marked for Blackhole.");
    }
    else
    {
      m_selectiveForwardingNodes.insert(randomNumbers[i]);
      NS_LOG_DEBUG("Node " << randomNumbers[i] << " marked for Selective Forwarding.");
    }
  }
}


int64_t
AodvBHSFHelper::AssignStreams (NodeContainer c, int64_t stream)
{
  int64_t currentStream = stream;
  Ptr<Node> node;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      node = (*i);
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
      NS_ASSERT_MSG (ipv4, "Ipv4 not installed on node");
      Ptr<Ipv4RoutingProtocol> proto = ipv4->GetRoutingProtocol ();
      NS_ASSERT_MSG (proto, "Ipv4 routing not installed on node");
      Ptr<aodv::AodvBHSFRoutingProtocol> aodv = DynamicCast<aodv::AodvBHSFRoutingProtocol> (proto);
      if (aodv)
        {
          currentStream += aodv->AssignStreams (currentStream);
          continue;
        }
      // Aodv may also be in a list
      Ptr<Ipv4ListRouting> list = DynamicCast<Ipv4ListRouting> (proto);
      if (list)
        {
          int16_t priority;
          Ptr<Ipv4RoutingProtocol> listProto;
          Ptr<aodv::AodvBHSFRoutingProtocol> listAodv;
          for (uint32_t i = 0; i < list->GetNRoutingProtocols (); i++)
            {
              listProto = list->GetRoutingProtocol (i, priority);
              listAodv = DynamicCast<aodv::AodvBHSFRoutingProtocol> (listProto);
              if (listAodv)
                {
                  currentStream += listAodv->AssignStreams (currentStream);
                  break;
                }
            }
        }
    }
  return (currentStream - stream);
}

}

