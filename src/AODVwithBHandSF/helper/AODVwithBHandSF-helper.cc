/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "AODVwithBHandSF-helper.h"
#include "ns3/AODVwithBHandSF.h"
#include "ns3/node-list.h"
#include "ns3/names.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-list-routing.h"


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
  Ptr<aodv::AodvBHSFRoutingProtocol> agent = m_agentFactory.Create<aodv::AodvBHSFRoutingProtocol> ();
  node->AggregateObject (agent);
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
  // 随机数生成器
  Ptr<UniformRandomVariable> randomVar = CreateObject<UniformRandomVariable>();

  for (NodeContainer::Iterator it = nodes.Begin(); it != nodes.End(); ++it)
  {
    Ptr<Node> node = *it;
    Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
    NS_ASSERT_MSG(ipv4, "Ipv4 not installed on node");
    Ptr<Ipv4RoutingProtocol> proto = ipv4->GetRoutingProtocol();
    Ptr<aodv::AodvBHSFRoutingProtocol> aodv = DynamicCast<aodv::AodvBHSFRoutingProtocol>(proto);

    if (aodv)
    {
      // 按照比例随机设置为黑洞或选择性转发节点
      double prob = randomVar->GetValue();
      if (prob < blackholeRatio)
      {
        aodv->SetBlackhole(true);
        NS_LOG_UNCOND("Node " << node->GetId() << " set as Blackhole node.");
      }
      else if (prob < blackholeRatio + selectiveForwardingRatio)
      {
        aodv->SetSelectiveForwarding(true);
        NS_LOG_UNCOND("Node " << node->GetId() << " set as Selective Forwarding node.");
      }
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

