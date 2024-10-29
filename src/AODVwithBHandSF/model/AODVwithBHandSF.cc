/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 IITP RAS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Based on
 *      NS-2 AODV model developed by the CMU/MONARCH group and optimized and
 *      tuned by Samir Das and Mahesh Marina, University of Cincinnati;
 *
 *      AODV-UU implementation by Erik Nordström of Uppsala University
 *      http://core.it.uu.se/core/index.php/AODV-UU
 *
 * Authors: Elena Buchatskaia <borovkovaes@iitp.ru>
 *          Pavel Boyko <boyko@iitp.ru>
 */
#define NS_LOG_APPEND_CONTEXT                                            \
  if (m_ipv4)                                                            \
  {                                                                      \
    std::clog << "[node " << m_ipv4->GetObject<Node>()->GetId() << "] "; \
  }

#include "AODVwithBHandSF.h"
#include "ns3/log.h"
#include "ns3/boolean.h"
#include "ns3/random-variable-stream.h"
#include "ns3/inet-socket-address.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/udp-header.h"
#include "ns3/wifi-net-device.h"
#include "ns3/adhoc-wifi-mac.h"
#include "ns3/string.h"
#include "ns3/pointer.h"
#include <algorithm>
#include <limits>

namespace ns3
{

  NS_LOG_COMPONENT_DEFINE("AODVWITHBHANDSF");

  namespace aodv
  {
    NS_OBJECT_ENSURE_REGISTERED(AodvBHSFRoutingProtocol);

    /// UDP Port for AODV control traffic
    const uint32_t AodvBHSFRoutingProtocol::AODV_PORT = 654;

    /**
     * \ingroup aodv
     * \brief Tag used by AODV implementation
     */
    class DeferredRouteOutputTagwithBHFS : public Tag
    {

    public:
      /**
       * \brief Constructor
       * \param o the output interface
       */
      DeferredRouteOutputTagwithBHFS(int32_t o = -1) : Tag(),
                                               m_oif(o)
      {
      }

      /**
       * \brief Get the type ID.
       * \return the object TypeId
       */
      static TypeId GetTypeId()
      {
        static TypeId tid = TypeId("ns3::aodv::DeferredRouteOutputTagwithBHFS")
                                .SetParent<Tag>()
                                .SetGroupName("Aodv")
                                .AddConstructor<DeferredRouteOutputTagwithBHFS>();
        return tid;
      }

      TypeId GetInstanceTypeId() const
      {
        return GetTypeId();
      }

      /**
       * \brief Get the output interface
       * \return the output interface
       */
      int32_t GetInterface() const
      {
        return m_oif;
      }

      /**
       * \brief Set the output interface
       * \param oif the output interface
       */
      void SetInterface(int32_t oif)
      {
        m_oif = oif;
      }

      uint32_t GetSerializedSize() const
      {
        return sizeof(int32_t);
      }

      void Serialize(TagBuffer i) const
      {
        i.WriteU32(m_oif);
      }

      void Deserialize(TagBuffer i)
      {
        m_oif = i.ReadU32();
      }

      void Print(std::ostream &os) const
      {
        os << "DeferredRouteOutputTagwithBHFS: output interface = " << m_oif;
      }

    private:
      /// Positive if output device is fixed in RouteOutput
      int32_t m_oif;
    };

    NS_OBJECT_ENSURE_REGISTERED(DeferredRouteOutputTagwithBHFS);

    //-----------------------------------------------------------------------------
    AodvBHSFRoutingProtocol::AodvBHSFRoutingProtocol()
        : m_rreqRetries(2),
          m_ttlStart(1),
          m_ttlIncrement(2),
          m_ttlThreshold(7),
          m_timeoutBuffer(2),
          m_rreqRateLimit(10),
          m_rerrRateLimit(10),
          m_activeRouteTimeout(Seconds(3)),
          m_netDiameter(35),
          m_nodeTraversalTime(MilliSeconds(40)),
          m_netTraversalTime(Time((2 * m_netDiameter) * m_nodeTraversalTime)),
          m_pathDiscoveryTime(Time(2 * m_netTraversalTime)),
          m_myRouteTimeout(Time(2 * std::max(m_pathDiscoveryTime, m_activeRouteTimeout))),
          m_helloInterval(Seconds(1)),
          m_allowedHelloLoss(2),
          m_deletePeriod(Time(5 * std::max(m_activeRouteTimeout, m_helloInterval))),
          m_nextHopWait(m_nodeTraversalTime + MilliSeconds(10)),
          m_blackListTimeout(Time(m_rreqRetries * m_netTraversalTime)),
          m_maxQueueLen(64),
          m_maxQueueTime(Seconds(30)),
          m_destinationOnly(false),
          m_gratuitousReply(true),
          m_enableHello(false),
          m_routingTable(m_deletePeriod),
          m_queue(m_maxQueueLen, m_maxQueueTime),
          m_requestId(0),
          m_seqNo(0),
          m_rreqIdCache(m_pathDiscoveryTime),
          m_dpd(m_pathDiscoveryTime),
          m_nb(m_helloInterval),
          m_rreqCount(0),
          m_rerrCount(0),
          m_htimer(Timer::CANCEL_ON_DESTROY),
          m_rreqRateLimitTimer(Timer::CANCEL_ON_DESTROY),
          m_rerrRateLimitTimer(Timer::CANCEL_ON_DESTROY),
          m_lastBcastTime(Seconds(0))
    {
      m_nb.SetCallback(MakeCallback(&AodvBHSFRoutingProtocol::SendRerrWhenBreaksLinkToNextHop, this));
    }

    TypeId
    AodvBHSFRoutingProtocol::GetTypeId(void)
    {
      static TypeId tid = TypeId("ns3::aodv::AodvBHSFRoutingProtocol")
                              .SetParent<Ipv4RoutingProtocol>()
                              .SetGroupName("Aodv")
                              .AddConstructor<AodvBHSFRoutingProtocol>()
                              .AddAttribute("HelloInterval", "HELLO messages emission interval.",
                                            TimeValue(Seconds(1)),
                                            MakeTimeAccessor(&AodvBHSFRoutingProtocol::m_helloInterval),
                                            MakeTimeChecker())
                              .AddAttribute("TtlStart", "Initial TTL value for RREQ.",
                                            UintegerValue(1),
                                            MakeUintegerAccessor(&AodvBHSFRoutingProtocol::m_ttlStart),
                                            MakeUintegerChecker<uint16_t>())
                              .AddAttribute("TtlIncrement", "TTL increment for each attempt using the expanding ring search for RREQ dissemination.",
                                            UintegerValue(2),
                                            MakeUintegerAccessor(&AodvBHSFRoutingProtocol::m_ttlIncrement),
                                            MakeUintegerChecker<uint16_t>())
                              .AddAttribute("TtlThreshold", "Maximum TTL value for expanding ring search, TTL = NetDiameter is used beyond this value.",
                                            UintegerValue(7),
                                            MakeUintegerAccessor(&AodvBHSFRoutingProtocol::m_ttlThreshold),
                                            MakeUintegerChecker<uint16_t>())
                              .AddAttribute("TimeoutBuffer", "Provide a buffer for the timeout.",
                                            UintegerValue(2),
                                            MakeUintegerAccessor(&AodvBHSFRoutingProtocol::m_timeoutBuffer),
                                            MakeUintegerChecker<uint16_t>())
                              .AddAttribute("RreqRetries", "Maximum number of retransmissions of RREQ to discover a route",
                                            UintegerValue(2),
                                            MakeUintegerAccessor(&AodvBHSFRoutingProtocol::m_rreqRetries),
                                            MakeUintegerChecker<uint32_t>())
                              .AddAttribute("RreqRateLimit", "Maximum number of RREQ per second.",
                                            UintegerValue(10),
                                            MakeUintegerAccessor(&AodvBHSFRoutingProtocol::m_rreqRateLimit),
                                            MakeUintegerChecker<uint32_t>())
                              .AddAttribute("RerrRateLimit", "Maximum number of RERR per second.",
                                            UintegerValue(10),
                                            MakeUintegerAccessor(&AodvBHSFRoutingProtocol::m_rerrRateLimit),
                                            MakeUintegerChecker<uint32_t>())
                              .AddAttribute("NodeTraversalTime", "Conservative estimate of the average one hop traversal time for packets and should include "
                                                                 "queuing delays, interrupt processing times and transfer times.",
                                            TimeValue(MilliSeconds(40)),
                                            MakeTimeAccessor(&AodvBHSFRoutingProtocol::m_nodeTraversalTime),
                                            MakeTimeChecker())
                              .AddAttribute("NextHopWait", "Period of our waiting for the neighbour's RREP_ACK = 10 ms + NodeTraversalTime",
                                            TimeValue(MilliSeconds(50)),
                                            MakeTimeAccessor(&AodvBHSFRoutingProtocol::m_nextHopWait),
                                            MakeTimeChecker())
                              .AddAttribute("ActiveRouteTimeout", "Period of time during which the route is considered to be valid",
                                            TimeValue(Seconds(3)),
                                            MakeTimeAccessor(&AodvBHSFRoutingProtocol::m_activeRouteTimeout),
                                            MakeTimeChecker())
                              .AddAttribute("MyRouteTimeout", "Value of lifetime field in RREP generating by this node = 2 * max(ActiveRouteTimeout, PathDiscoveryTime)",
                                            TimeValue(Seconds(11.2)),
                                            MakeTimeAccessor(&AodvBHSFRoutingProtocol::m_myRouteTimeout),
                                            MakeTimeChecker())
                              .AddAttribute("BlackListTimeout", "Time for which the node is put into the blacklist = RreqRetries * NetTraversalTime",
                                            TimeValue(Seconds(5.6)),
                                            MakeTimeAccessor(&AodvBHSFRoutingProtocol::m_blackListTimeout),
                                            MakeTimeChecker())
                              .AddAttribute("DeletePeriod", "DeletePeriod is intended to provide an upper bound on the time for which an upstream node A "
                                                            "can have a neighbor B as an active next hop for destination D, while B has invalidated the route to D."
                                                            " = 5 * max (HelloInterval, ActiveRouteTimeout)",
                                            TimeValue(Seconds(15)),
                                            MakeTimeAccessor(&AodvBHSFRoutingProtocol::m_deletePeriod),
                                            MakeTimeChecker())
                              .AddAttribute("NetDiameter", "Net diameter measures the maximum possible number of hops between two nodes in the network",
                                            UintegerValue(35),
                                            MakeUintegerAccessor(&AodvBHSFRoutingProtocol::m_netDiameter),
                                            MakeUintegerChecker<uint32_t>())
                              .AddAttribute("NetTraversalTime", "Estimate of the average net traversal time = 2 * NodeTraversalTime * NetDiameter",
                                            TimeValue(Seconds(2.8)),
                                            MakeTimeAccessor(&AodvBHSFRoutingProtocol::m_netTraversalTime),
                                            MakeTimeChecker())
                              .AddAttribute("PathDiscoveryTime", "Estimate of maximum time needed to find route in network = 2 * NetTraversalTime",
                                            TimeValue(Seconds(5.6)),
                                            MakeTimeAccessor(&AodvBHSFRoutingProtocol::m_pathDiscoveryTime),
                                            MakeTimeChecker())
                              .AddAttribute("MaxQueueLen", "Maximum number of packets that we allow a routing protocol to buffer.",
                                            UintegerValue(64),
                                            MakeUintegerAccessor(&AodvBHSFRoutingProtocol::SetMaxQueueLen,
                                                                 &AodvBHSFRoutingProtocol::GetMaxQueueLen),
                                            MakeUintegerChecker<uint32_t>())
                              .AddAttribute("MaxQueueTime", "Maximum time packets can be queued (in seconds)",
                                            TimeValue(Seconds(30)),
                                            MakeTimeAccessor(&AodvBHSFRoutingProtocol::SetMaxQueueTime,
                                                             &AodvBHSFRoutingProtocol::GetMaxQueueTime),
                                            MakeTimeChecker())
                              .AddAttribute("AllowedHelloLoss", "Number of hello messages which may be loss for valid link.",
                                            UintegerValue(2),
                                            MakeUintegerAccessor(&AodvBHSFRoutingProtocol::m_allowedHelloLoss),
                                            MakeUintegerChecker<uint16_t>())
                              .AddAttribute("GratuitousReply", "Indicates whether a gratuitous RREP should be unicast to the node originated route discovery.",
                                            BooleanValue(true),
                                            MakeBooleanAccessor(&AodvBHSFRoutingProtocol::SetGratuitousReplyFlag,
                                                                &AodvBHSFRoutingProtocol::GetGratuitousReplyFlag),
                                            MakeBooleanChecker())
                              .AddAttribute("DestinationOnly", "Indicates only the destination may respond to this RREQ.",
                                            BooleanValue(false),
                                            MakeBooleanAccessor(&AodvBHSFRoutingProtocol::SetDestinationOnlyFlag,
                                                                &AodvBHSFRoutingProtocol::GetDestinationOnlyFlag),
                                            MakeBooleanChecker())
                              .AddAttribute("EnableHello", "Indicates whether a hello messages enable.",
                                            BooleanValue(true),
                                            MakeBooleanAccessor(&AodvBHSFRoutingProtocol::SetHelloEnable,
                                                                &AodvBHSFRoutingProtocol::GetHelloEnable),
                                            MakeBooleanChecker())
                              .AddAttribute("EnableBroadcast", "Indicates whether a broadcast data packets forwarding enable.",
                                            BooleanValue(true),
                                            MakeBooleanAccessor(&AodvBHSFRoutingProtocol::SetBroadcastEnable,
                                                                &AodvBHSFRoutingProtocol::GetBroadcastEnable),
                                            MakeBooleanChecker())
                              .AddAttribute("UniformRv",
                                            "Access to the underlying UniformRandomVariable",
                                            StringValue("ns3::UniformRandomVariable"),
                                            MakePointerAccessor(&AodvBHSFRoutingProtocol::m_uniformRandomVariable),
                                            MakePointerChecker<UniformRandomVariable>());
      return tid;
    }

    void
    AodvBHSFRoutingProtocol::SetMaxQueueLen(uint32_t len)
    {
      m_maxQueueLen = len;
      m_queue.SetMaxQueueLen(len);
    }
    void
    AodvBHSFRoutingProtocol::SetMaxQueueTime(Time t)
    {
      m_maxQueueTime = t;
      m_queue.SetQueueTimeout(t);
    }

    AodvBHSFRoutingProtocol::~AodvBHSFRoutingProtocol()
    {
    }

    void
    AodvBHSFRoutingProtocol::DoDispose()
    {
      m_ipv4 = 0;
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter =
               m_socketAddresses.begin();
           iter != m_socketAddresses.end(); iter++)
      {
        iter->first->Close();
      }
      m_socketAddresses.clear();
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter =
               m_socketSubnetBroadcastAddresses.begin();
           iter != m_socketSubnetBroadcastAddresses.end(); iter++)
      {
        iter->first->Close();
      }
      m_socketSubnetBroadcastAddresses.clear();
      Ipv4RoutingProtocol::DoDispose();
    }

    void
    AodvBHSFRoutingProtocol::PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
    {
      *stream->GetStream() << "Node: " << m_ipv4->GetObject<Node>()->GetId()
                           << "; Time: " << Now().As(unit)
                           << ", Local time: " << GetObject<Node>()->GetLocalTime().As(unit)
                           << ", AODV Routing table" << std::endl;

      m_routingTable.Print(stream, unit);
      *stream->GetStream() << std::endl;
    }

    int64_t
    AodvBHSFRoutingProtocol::AssignStreams(int64_t stream)
    {
      NS_LOG_FUNCTION(this << stream);
      m_uniformRandomVariable->SetStream(stream);
      return 1;
    }

    void
    AodvBHSFRoutingProtocol::Start()
    {
      NS_LOG_FUNCTION(this);
      if (m_enableHello)
      {
        m_nb.ScheduleTimer();
      }
      m_rreqRateLimitTimer.SetFunction(&AodvBHSFRoutingProtocol::RreqRateLimitTimerExpire,
                                       this);
      m_rreqRateLimitTimer.Schedule(Seconds(1));

      m_rerrRateLimitTimer.SetFunction(&AodvBHSFRoutingProtocol::RerrRateLimitTimerExpire,
                                       this);
      m_rerrRateLimitTimer.Schedule(Seconds(1));
    }

    Ptr<Ipv4Route>
    AodvBHSFRoutingProtocol::RouteOutput(Ptr<Packet> p, const Ipv4Header &header,
                                 Ptr<NetDevice> oif, Socket::SocketErrno &sockerr)
    {
      NS_LOG_FUNCTION(this << header << (oif ? oif->GetIfIndex() : 0));
      if (!p)
      {
        NS_LOG_DEBUG("Packet is == 0");
        return LoopbackRoute(header, oif); // later
      }
      if (m_socketAddresses.empty())
      {
        sockerr = Socket::ERROR_NOROUTETOHOST;
        NS_LOG_LOGIC("No aodv interfaces");
        Ptr<Ipv4Route> route;
        return route;
      }
      sockerr = Socket::ERROR_NOTERROR;
      Ptr<Ipv4Route> route;
      Ipv4Address dst = header.GetDestination();
      RoutingTableEntry rt;
      if (m_routingTable.LookupValidRoute(dst, rt))
      {
        route = rt.GetRoute();
        NS_ASSERT(route != 0);
        NS_LOG_DEBUG("Exist route to " << route->GetDestination() << " from interface " << route->GetSource());
        if (oif != 0 && route->GetOutputDevice() != oif)
        {
          NS_LOG_DEBUG("Output device doesn't match. Dropped.");
          sockerr = Socket::ERROR_NOROUTETOHOST;
          return Ptr<Ipv4Route>();
        }
        UpdateRouteLifeTime(dst, m_activeRouteTimeout);
        UpdateRouteLifeTime(route->GetGateway(), m_activeRouteTimeout);
        return route;
      }

      // Valid route not found, in this case we return loopback.
      // Actual route request will be deferred until packet will be fully formed,
      // routed to loopback, received from loopback and passed to RouteInput (see below)
      uint32_t iif = (oif ? m_ipv4->GetInterfaceForDevice(oif) : -1);
      DeferredRouteOutputTagwithBHFS tag(iif);
      NS_LOG_DEBUG("Valid Route not found");
      if (!p->PeekPacketTag(tag))
      {
        p->AddPacketTag(tag);
      }
      return LoopbackRoute(header, oif);
    }

    void
    AodvBHSFRoutingProtocol::DeferredRouteOutput(Ptr<const Packet> p, const Ipv4Header &header,
                                         UnicastForwardCallback ucb, ErrorCallback ecb)
    {
      NS_LOG_FUNCTION(this << p << header);
      NS_ASSERT(p != 0 && p != Ptr<Packet>());

      QueueEntry newEntry(p, header, ucb, ecb);
      bool result = m_queue.Enqueue(newEntry);
      if (result)
      {
        NS_LOG_LOGIC("Add packet " << p->GetUid() << " to queue. Protocol " << (uint16_t)header.GetProtocol());
        RoutingTableEntry rt;
        bool result = m_routingTable.LookupRoute(header.GetDestination(), rt);
        if (!result || ((rt.GetFlag() != IN_SEARCH) && result))
        {
          NS_LOG_LOGIC("Send new RREQ for outbound packet to " << header.GetDestination());
          SendRequest(header.GetDestination());
        }
      }
    }

    bool
    AodvBHSFRoutingProtocol::RouteInput(Ptr<const Packet> p, const Ipv4Header &header,
                                Ptr<const NetDevice> idev, UnicastForwardCallback ucb,
                                MulticastForwardCallback mcb, LocalDeliverCallback lcb, ErrorCallback ecb)
    {
      NS_LOG_FUNCTION(this << p->GetUid() << header.GetDestination() << idev->GetAddress());
      if (m_socketAddresses.empty())
      {
        NS_LOG_LOGIC("No aodv interfaces");
        return false;
      }
      NS_ASSERT(m_ipv4 != 0);
      NS_ASSERT(p != 0);
      // Check if input device supports IP
      NS_ASSERT(m_ipv4->GetInterfaceForDevice(idev) >= 0);
      int32_t iif = m_ipv4->GetInterfaceForDevice(idev);

      Ipv4Address dst = header.GetDestination();
      Ipv4Address origin = header.GetSource();

      // Deferred route request
      if (idev == m_lo)
      {
        DeferredRouteOutputTagwithBHFS tag;
        if (p->PeekPacketTag(tag))
        {
          DeferredRouteOutput(p, header, ucb, ecb);
          return true;
        }
      }

      // Duplicate of own packet
      if (IsMyOwnAddress(origin))
      {
        return true;
      }

      // AODV is not a multicast routing protocol
      if (dst.IsMulticast())
      {
        return false;
      }

      // Broadcast local delivery/forwarding
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
               m_socketAddresses.begin();
           j != m_socketAddresses.end(); ++j)
      {
        Ipv4InterfaceAddress iface = j->second;
        if (m_ipv4->GetInterfaceForAddress(iface.GetLocal()) == iif)
        {
          if (dst == iface.GetBroadcast() || dst.IsBroadcast())
          {
            if (m_dpd.IsDuplicate(p, header))
            {
              NS_LOG_DEBUG("Duplicated packet " << p->GetUid() << " from " << origin << ". Drop.");
              return true;
            }
            UpdateRouteLifeTime(origin, m_activeRouteTimeout);
            Ptr<Packet> packet = p->Copy();
            if (lcb.IsNull() == false)
            {
              NS_LOG_LOGIC("Broadcast local delivery to " << iface.GetLocal());
              lcb(p, header, iif);
              // Fall through to additional processing
            }
            else
            {
              NS_LOG_ERROR("Unable to deliver packet locally due to null callback " << p->GetUid() << " from " << origin);
              ecb(p, header, Socket::ERROR_NOROUTETOHOST);
            }
            if (!m_enableBroadcast)
            {
              return true;
            }
            if (header.GetProtocol() == UdpL4Protocol::PROT_NUMBER)
            {
              UdpHeader udpHeader;
              p->PeekHeader(udpHeader);
              if (udpHeader.GetDestinationPort() == AODV_PORT)
              {
                // AODV packets sent in broadcast are already managed
                return true;
              }
            }
            if (header.GetTtl() > 1)
            {
              NS_LOG_LOGIC("Forward broadcast. TTL " << (uint16_t)header.GetTtl());
              RoutingTableEntry toBroadcast;
              if (m_routingTable.LookupRoute(dst, toBroadcast))
              {
                Ptr<Ipv4Route> route = toBroadcast.GetRoute();
                ucb(route, packet, header);
              }
              else
              {
                NS_LOG_DEBUG("No route to forward broadcast. Drop packet " << p->GetUid());
              }
            }
            else
            {
              NS_LOG_DEBUG("TTL exceeded. Drop packet " << p->GetUid());
            }
            return true;
          }
        }
      }

      // Unicast local delivery
      if (m_ipv4->IsDestinationAddress(dst, iif))
      {
        UpdateRouteLifeTime(origin, m_activeRouteTimeout);
        RoutingTableEntry toOrigin;
        if (m_routingTable.LookupValidRoute(origin, toOrigin))
        {
          UpdateRouteLifeTime(toOrigin.GetNextHop(), m_activeRouteTimeout);
          m_nb.Update(toOrigin.GetNextHop(), m_activeRouteTimeout);
        }
        if (lcb.IsNull() == false)
        {
          NS_LOG_LOGIC("Unicast local delivery to " << dst);
          lcb(p, header, iif);
        }
        else
        {
          NS_LOG_ERROR("Unable to deliver packet locally due to null callback " << p->GetUid() << " from " << origin);
          ecb(p, header, Socket::ERROR_NOROUTETOHOST);
        }
        return true;
      }

      // Check if input device supports IP forwarding
      if (m_ipv4->IsForwarding(iif) == false)
      {
        NS_LOG_LOGIC("Forwarding disabled for this interface");
        ecb(p, header, Socket::ERROR_NOROUTETOHOST);
        return true;
      }

      // Forwarding
      return Forwarding(p, header, ucb, ecb);
    }

    bool
    AodvBHSFRoutingProtocol::Forwarding(Ptr<const Packet> p, const Ipv4Header &header,
                                UnicastForwardCallback ucb, ErrorCallback ecb)
    {
      NS_LOG_FUNCTION(this);
      Ipv4Address dst = header.GetDestination();
      Ipv4Address origin = header.GetSource();
      m_routingTable.Purge();
      RoutingTableEntry toDst;

      if (IsSelectiveForwardingNode() && (rand() % 10 <= 3))
      {
        NS_LOG_DEBUG("Drop packet " << p->GetUid() << " because m_isSelectiveForwarding.");
        return false;
      }

      if (IsBlackholeNode())
      {
        NS_LOG_DEBUG("Drop packet " << p->GetUid() << " because m_isBlackhole.");
        return false;
      }

      if (m_routingTable.LookupRoute(dst, toDst))
      {
        if (toDst.GetFlag() == VALID)
        {
          Ptr<Ipv4Route> route = toDst.GetRoute();
          NS_LOG_LOGIC(route->GetSource() << " forwarding to " << dst << " from " << origin << " packet " << p->GetUid());

          /*
           *  Each time a route is used to forward a data packet, its Active Route
           *  Lifetime field of the source, destination and the next hop on the
           *  path to the destination is updated to be no less than the current
           *  time plus ActiveRouteTimeout.
           */
          UpdateRouteLifeTime(origin, m_activeRouteTimeout);
          UpdateRouteLifeTime(dst, m_activeRouteTimeout);
          UpdateRouteLifeTime(route->GetGateway(), m_activeRouteTimeout);
          /*
           *  Since the route between each originator and destination pair is expected to be symmetric, the
           *  Active Route Lifetime for the previous hop, along the reverse path back to the IP source, is also updated
           *  to be no less than the current time plus ActiveRouteTimeout
           */
          RoutingTableEntry toOrigin;
          m_routingTable.LookupRoute(origin, toOrigin);
          UpdateRouteLifeTime(toOrigin.GetNextHop(), m_activeRouteTimeout);

          m_nb.Update(route->GetGateway(), m_activeRouteTimeout);
          m_nb.Update(toOrigin.GetNextHop(), m_activeRouteTimeout);

          ucb(route, p, header);
          return true;
        }
        else
        {
          if (toDst.GetValidSeqNo())
          {
            SendRerrWhenNoRouteToForward(dst, toDst.GetSeqNo(), origin);
            NS_LOG_DEBUG("Drop packet " << p->GetUid() << " because no route to forward it.");
            return false;
          }
        }
      }
      NS_LOG_LOGIC("route not found to " << dst << ". Send RERR message.");
      NS_LOG_DEBUG("Drop packet " << p->GetUid() << " because no route to forward it.");
      SendRerrWhenNoRouteToForward(dst, 0, origin);
      return false;
    }

    void
    AodvBHSFRoutingProtocol::SetIpv4(Ptr<Ipv4> ipv4)
    {
      NS_ASSERT(ipv4 != 0);
      NS_ASSERT(m_ipv4 == 0);

      m_ipv4 = ipv4;

      // Create lo route. It is asserted that the only one interface up for now is loopback
      NS_ASSERT(m_ipv4->GetNInterfaces() == 1 && m_ipv4->GetAddress(0, 0).GetLocal() == Ipv4Address("127.0.0.1"));
      m_lo = m_ipv4->GetNetDevice(0);
      NS_ASSERT(m_lo != 0);
      // Remember lo route
      RoutingTableEntry rt(/*device=*/m_lo, /*dst=*/Ipv4Address::GetLoopback(), /*know seqno=*/true, /*seqno=*/0,
                           /*iface=*/Ipv4InterfaceAddress(Ipv4Address::GetLoopback(), Ipv4Mask("255.0.0.0")),
                           /*hops=*/1, /*next hop=*/Ipv4Address::GetLoopback(),
                           /*lifetime=*/Simulator::GetMaximumSimulationTime());
      m_routingTable.AddRoute(rt);

      Simulator::ScheduleNow(&AodvBHSFRoutingProtocol::Start, this);
    }

    void
    AodvBHSFRoutingProtocol::NotifyInterfaceUp(uint32_t i)
    {
      NS_LOG_FUNCTION(this << m_ipv4->GetAddress(i, 0).GetLocal());
      Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol>();
      if (l3->GetNAddresses(i) > 1)
      {
        NS_LOG_WARN("AODV does not work with more then one address per each interface.");
      }
      Ipv4InterfaceAddress iface = l3->GetAddress(i, 0);
      if (iface.GetLocal() == Ipv4Address("127.0.0.1"))
      {
        return;
      }

      // Create a socket to listen only on this interface
      Ptr<Socket> socket = Socket::CreateSocket(GetObject<Node>(),
                                                UdpSocketFactory::GetTypeId());
      NS_ASSERT(socket != 0);
      socket->SetRecvCallback(MakeCallback(&AodvBHSFRoutingProtocol::RecvAodv, this));
      socket->BindToNetDevice(l3->GetNetDevice(i));
      socket->Bind(InetSocketAddress(iface.GetLocal(), AODV_PORT));
      socket->SetAllowBroadcast(true);
      socket->SetIpRecvTtl(true);
      m_socketAddresses.insert(std::make_pair(socket, iface));

      // create also a subnet broadcast socket
      socket = Socket::CreateSocket(GetObject<Node>(),
                                    UdpSocketFactory::GetTypeId());
      NS_ASSERT(socket != 0);
      socket->SetRecvCallback(MakeCallback(&AodvBHSFRoutingProtocol::RecvAodv, this));
      socket->BindToNetDevice(l3->GetNetDevice(i));
      socket->Bind(InetSocketAddress(iface.GetBroadcast(), AODV_PORT));
      socket->SetAllowBroadcast(true);
      socket->SetIpRecvTtl(true);
      m_socketSubnetBroadcastAddresses.insert(std::make_pair(socket, iface));

      // Add local broadcast record to the routing table
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(iface.GetLocal()));
      RoutingTableEntry rt(/*device=*/dev, /*dst=*/iface.GetBroadcast(), /*know seqno=*/true, /*seqno=*/0, /*iface=*/iface,
                           /*hops=*/1, /*next hop=*/iface.GetBroadcast(), /*lifetime=*/Simulator::GetMaximumSimulationTime());
      m_routingTable.AddRoute(rt);

      if (l3->GetInterface(i)->GetArpCache())
      {
        m_nb.AddArpCache(l3->GetInterface(i)->GetArpCache());
      }

      // Allow neighbor manager use this interface for layer 2 feedback if possible
      Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice>();
      if (wifi == 0)
      {
        return;
      }
      Ptr<WifiMac> mac = wifi->GetMac();
      if (mac == 0)
      {
        return;
      }

      mac->TraceConnectWithoutContext("TxErrHeader", m_nb.GetTxErrorCallback());
    }

    void
    AodvBHSFRoutingProtocol::NotifyInterfaceDown(uint32_t i)
    {
      NS_LOG_FUNCTION(this << m_ipv4->GetAddress(i, 0).GetLocal());

      // Disable layer 2 link state monitoring (if possible)
      Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol>();
      Ptr<NetDevice> dev = l3->GetNetDevice(i);
      Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice>();
      if (wifi != 0)
      {
        Ptr<WifiMac> mac = wifi->GetMac()->GetObject<AdhocWifiMac>();
        if (mac != 0)
        {
          mac->TraceDisconnectWithoutContext("TxErrHeader",
                                             m_nb.GetTxErrorCallback());
          m_nb.DelArpCache(l3->GetInterface(i)->GetArpCache());
        }
      }

      // Close socket
      Ptr<Socket> socket = FindSocketWithInterfaceAddress(m_ipv4->GetAddress(i, 0));
      NS_ASSERT(socket);
      socket->Close();
      m_socketAddresses.erase(socket);

      // Close socket
      socket = FindSubnetBroadcastSocketWithInterfaceAddress(m_ipv4->GetAddress(i, 0));
      NS_ASSERT(socket);
      socket->Close();
      m_socketSubnetBroadcastAddresses.erase(socket);

      if (m_socketAddresses.empty())
      {
        NS_LOG_LOGIC("No aodv interfaces");
        m_htimer.Cancel();
        m_nb.Clear();
        m_routingTable.Clear();
        return;
      }
      m_routingTable.DeleteAllRoutesFromInterface(m_ipv4->GetAddress(i, 0));
    }

    void
    AodvBHSFRoutingProtocol::NotifyAddAddress(uint32_t i, Ipv4InterfaceAddress address)
    {
      NS_LOG_FUNCTION(this << " interface " << i << " address " << address);
      Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol>();
      if (!l3->IsUp(i))
      {
        return;
      }
      if (l3->GetNAddresses(i) == 1)
      {
        Ipv4InterfaceAddress iface = l3->GetAddress(i, 0);
        Ptr<Socket> socket = FindSocketWithInterfaceAddress(iface);
        if (!socket)
        {
          if (iface.GetLocal() == Ipv4Address("127.0.0.1"))
          {
            return;
          }
          // Create a socket to listen only on this interface
          Ptr<Socket> socket = Socket::CreateSocket(GetObject<Node>(),
                                                    UdpSocketFactory::GetTypeId());
          NS_ASSERT(socket != 0);
          socket->SetRecvCallback(MakeCallback(&AodvBHSFRoutingProtocol::RecvAodv, this));
          socket->BindToNetDevice(l3->GetNetDevice(i));
          socket->Bind(InetSocketAddress(iface.GetLocal(), AODV_PORT));
          socket->SetAllowBroadcast(true);
          m_socketAddresses.insert(std::make_pair(socket, iface));

          // create also a subnet directed broadcast socket
          socket = Socket::CreateSocket(GetObject<Node>(),
                                        UdpSocketFactory::GetTypeId());
          NS_ASSERT(socket != 0);
          socket->SetRecvCallback(MakeCallback(&AodvBHSFRoutingProtocol::RecvAodv, this));
          socket->BindToNetDevice(l3->GetNetDevice(i));
          socket->Bind(InetSocketAddress(iface.GetBroadcast(), AODV_PORT));
          socket->SetAllowBroadcast(true);
          socket->SetIpRecvTtl(true);
          m_socketSubnetBroadcastAddresses.insert(std::make_pair(socket, iface));

          // Add local broadcast record to the routing table
          Ptr<NetDevice> dev = m_ipv4->GetNetDevice(
              m_ipv4->GetInterfaceForAddress(iface.GetLocal()));
          RoutingTableEntry rt(/*device=*/dev, /*dst=*/iface.GetBroadcast(), /*know seqno=*/true,
                               /*seqno=*/0, /*iface=*/iface, /*hops=*/1,
                               /*next hop=*/iface.GetBroadcast(), /*lifetime=*/Simulator::GetMaximumSimulationTime());
          m_routingTable.AddRoute(rt);
        }
      }
      else
      {
        NS_LOG_LOGIC("AODV does not work with more then one address per each interface. Ignore added address");
      }
    }

    void
    AodvBHSFRoutingProtocol::NotifyRemoveAddress(uint32_t i, Ipv4InterfaceAddress address)
    {
      NS_LOG_FUNCTION(this);
      Ptr<Socket> socket = FindSocketWithInterfaceAddress(address);
      if (socket)
      {
        m_routingTable.DeleteAllRoutesFromInterface(address);
        socket->Close();
        m_socketAddresses.erase(socket);

        Ptr<Socket> unicastSocket = FindSubnetBroadcastSocketWithInterfaceAddress(address);
        if (unicastSocket)
        {
          unicastSocket->Close();
          m_socketAddresses.erase(unicastSocket);
        }

        Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol>();
        if (l3->GetNAddresses(i))
        {
          Ipv4InterfaceAddress iface = l3->GetAddress(i, 0);
          // Create a socket to listen only on this interface
          Ptr<Socket> socket = Socket::CreateSocket(GetObject<Node>(),
                                                    UdpSocketFactory::GetTypeId());
          NS_ASSERT(socket != 0);
          socket->SetRecvCallback(MakeCallback(&AodvBHSFRoutingProtocol::RecvAodv, this));
          // Bind to any IP address so that broadcasts can be received
          socket->BindToNetDevice(l3->GetNetDevice(i));
          socket->Bind(InetSocketAddress(iface.GetLocal(), AODV_PORT));
          socket->SetAllowBroadcast(true);
          socket->SetIpRecvTtl(true);
          m_socketAddresses.insert(std::make_pair(socket, iface));

          // create also a unicast socket
          socket = Socket::CreateSocket(GetObject<Node>(),
                                        UdpSocketFactory::GetTypeId());
          NS_ASSERT(socket != 0);
          socket->SetRecvCallback(MakeCallback(&AodvBHSFRoutingProtocol::RecvAodv, this));
          socket->BindToNetDevice(l3->GetNetDevice(i));
          socket->Bind(InetSocketAddress(iface.GetBroadcast(), AODV_PORT));
          socket->SetAllowBroadcast(true);
          socket->SetIpRecvTtl(true);
          m_socketSubnetBroadcastAddresses.insert(std::make_pair(socket, iface));

          // Add local broadcast record to the routing table
          Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(iface.GetLocal()));
          RoutingTableEntry rt(/*device=*/dev, /*dst=*/iface.GetBroadcast(), /*know seqno=*/true, /*seqno=*/0, /*iface=*/iface,
                               /*hops=*/1, /*next hop=*/iface.GetBroadcast(), /*lifetime=*/Simulator::GetMaximumSimulationTime());
          m_routingTable.AddRoute(rt);
        }
        if (m_socketAddresses.empty())
        {
          NS_LOG_LOGIC("No aodv interfaces");
          m_htimer.Cancel();
          m_nb.Clear();
          m_routingTable.Clear();
          return;
        }
      }
      else
      {
        NS_LOG_LOGIC("Remove address not participating in AODV operation");
      }
    }

    bool
    AodvBHSFRoutingProtocol::IsMyOwnAddress(Ipv4Address src)
    {
      NS_LOG_FUNCTION(this << src);
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
               m_socketAddresses.begin();
           j != m_socketAddresses.end(); ++j)
      {
        Ipv4InterfaceAddress iface = j->second;
        if (src == iface.GetLocal())
        {
          return true;
        }
      }
      return false;
    }

    Ptr<Ipv4Route>
    AodvBHSFRoutingProtocol::LoopbackRoute(const Ipv4Header &hdr, Ptr<NetDevice> oif) const
    {
      NS_LOG_FUNCTION(this << hdr);
      NS_ASSERT(m_lo != 0);
      Ptr<Ipv4Route> rt = Create<Ipv4Route>();
      rt->SetDestination(hdr.GetDestination());
      //
      // Source address selection here is tricky.  The loopback route is
      // returned when AODV does not have a route; this causes the packet
      // to be looped back and handled (cached) in RouteInput() method
      // while a route is found. However, connection-oriented protocols
      // like TCP need to create an endpoint four-tuple (src, src port,
      // dst, dst port) and create a pseudo-header for checksumming.  So,
      // AODV needs to guess correctly what the eventual source address
      // will be.
      //
      // For single interface, single address nodes, this is not a problem.
      // When there are possibly multiple outgoing interfaces, the policy
      // implemented here is to pick the first available AODV interface.
      // If RouteOutput() caller specified an outgoing interface, that
      // further constrains the selection of source address
      //
      std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin();
      if (oif)
      {
        // Iterate to find an address on the oif device
        for (j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
        {
          Ipv4Address addr = j->second.GetLocal();
          int32_t interface = m_ipv4->GetInterfaceForAddress(addr);
          if (oif == m_ipv4->GetNetDevice(static_cast<uint32_t>(interface)))
          {
            rt->SetSource(addr);
            break;
          }
        }
      }
      else
      {
        rt->SetSource(j->second.GetLocal());
      }
      NS_ASSERT_MSG(rt->GetSource() != Ipv4Address(), "Valid AODV source address not found");
      rt->SetGateway(Ipv4Address("127.0.0.1"));
      rt->SetOutputDevice(m_lo);
      return rt;
    }

    void
    AodvBHSFRoutingProtocol::SendRequest(Ipv4Address dst)
    {
      NS_LOG_FUNCTION(this << dst);
      // A node SHOULD NOT originate more than RREQ_RATELIMIT RREQ messages per second.
      if (m_rreqCount == m_rreqRateLimit)
      {
        Simulator::Schedule(m_rreqRateLimitTimer.GetDelayLeft() + MicroSeconds(100),
                            &AodvBHSFRoutingProtocol::SendRequest, this, dst);
        return;
      }
      else
      {
        m_rreqCount++;
      }
      // Create RREQ header
      RreqHeader rreqHeader;
      rreqHeader.SetDst(dst);

      RoutingTableEntry rt;
      // Using the Hop field in Routing Table to manage the expanding ring search
      uint16_t ttl = m_ttlStart;
      if (m_routingTable.LookupRoute(dst, rt))
      {
        if (rt.GetFlag() != IN_SEARCH)
        {
          ttl = std::min<uint16_t>(rt.GetHop() + m_ttlIncrement, m_netDiameter);
        }
        else
        {
          ttl = rt.GetHop() + m_ttlIncrement;
          if (ttl > m_ttlThreshold)
          {
            ttl = m_netDiameter;
          }
        }
        if (ttl == m_netDiameter)
        {
          rt.IncrementRreqCnt();
        }
        if (rt.GetValidSeqNo())
        {
          rreqHeader.SetDstSeqno(rt.GetSeqNo());
        }
        else
        {
          rreqHeader.SetUnknownSeqno(true);
        }
        rt.SetHop(ttl);
        rt.SetFlag(IN_SEARCH);
        rt.SetLifeTime(m_pathDiscoveryTime);
        m_routingTable.Update(rt);
      }
      else
      {
        rreqHeader.SetUnknownSeqno(true);
        Ptr<NetDevice> dev = 0;
        RoutingTableEntry newEntry(/*device=*/dev, /*dst=*/dst, /*validSeqNo=*/false, /*seqno=*/0,
                                   /*iface=*/Ipv4InterfaceAddress(), /*hop=*/ttl,
                                   /*nextHop=*/Ipv4Address(), /*lifeTime=*/m_pathDiscoveryTime);
        // Check if TtlStart == NetDiameter
        if (ttl == m_netDiameter)
        {
          newEntry.IncrementRreqCnt();
        }
        newEntry.SetFlag(IN_SEARCH);
        m_routingTable.AddRoute(newEntry);
      }

      if (m_gratuitousReply)
      {
        rreqHeader.SetGratuitousRrep(true);
      }
      if (m_destinationOnly)
      {
        rreqHeader.SetDestinationOnly(true);
      }

      m_seqNo++;
      rreqHeader.SetOriginSeqno(m_seqNo);
      m_requestId++;
      rreqHeader.SetId(m_requestId);

      // Send RREQ as subnet directed broadcast from each interface used by aodv
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
               m_socketAddresses.begin();
           j != m_socketAddresses.end(); ++j)
      {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;

        rreqHeader.SetOrigin(iface.GetLocal());
        m_rreqIdCache.IsDuplicate(iface.GetLocal(), m_requestId);

        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag tag;
        tag.SetTtl(ttl);
        packet->AddPacketTag(tag);
        packet->AddHeader(rreqHeader);
        TypeHeader tHeader(AODVTYPE_RREQ);
        packet->AddHeader(tHeader);
        // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
        Ipv4Address destination;
        if (iface.GetMask() == Ipv4Mask::GetOnes())
        {
          destination = Ipv4Address("255.255.255.255");
        }
        else
        {
          destination = iface.GetBroadcast();
        }
        NS_LOG_DEBUG("Send RREQ with id " << rreqHeader.GetId() << " to socket");
        m_lastBcastTime = Simulator::Now();
        Simulator::Schedule(Time(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10))), &AodvBHSFRoutingProtocol::SendTo, this, socket, packet, destination);
      }
      ScheduleRreqRetry(dst);
    }

    void
    AodvBHSFRoutingProtocol::SendTo(Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination)
    {
      socket->SendTo(packet, 0, InetSocketAddress(destination, AODV_PORT));
    }
    void
    AodvBHSFRoutingProtocol::ScheduleRreqRetry(Ipv4Address dst)
    {
      NS_LOG_FUNCTION(this << dst);
      if (m_addressReqTimer.find(dst) == m_addressReqTimer.end())
      {
        Timer timer(Timer::CANCEL_ON_DESTROY);
        m_addressReqTimer[dst] = timer;
      }
      m_addressReqTimer[dst].SetFunction(&AodvBHSFRoutingProtocol::RouteRequestTimerExpire, this);
      m_addressReqTimer[dst].Cancel();
      m_addressReqTimer[dst].SetArguments(dst);
      RoutingTableEntry rt;
      m_routingTable.LookupRoute(dst, rt);
      Time retry;
      if (rt.GetHop() < m_netDiameter)
      {
        retry = 2 * m_nodeTraversalTime * (rt.GetHop() + m_timeoutBuffer);
      }
      else
      {
        NS_ABORT_MSG_UNLESS(rt.GetRreqCnt() > 0, "Unexpected value for GetRreqCount ()");
        uint16_t backoffFactor = rt.GetRreqCnt() - 1;
        NS_LOG_LOGIC("Applying binary exponential backoff factor " << backoffFactor);
        retry = m_netTraversalTime * (1 << backoffFactor);
      }
      m_addressReqTimer[dst].Schedule(retry);
      NS_LOG_LOGIC("Scheduled RREQ retry in " << retry.As(Time::S));
    }

    void
    AodvBHSFRoutingProtocol::RecvAodv(Ptr<Socket> socket)
    {
      NS_LOG_FUNCTION(this << socket);
      Address sourceAddress;
      Ptr<Packet> packet = socket->RecvFrom(sourceAddress);
      InetSocketAddress inetSourceAddr = InetSocketAddress::ConvertFrom(sourceAddress);
      Ipv4Address sender = inetSourceAddr.GetIpv4();
      Ipv4Address receiver;

      if (m_socketAddresses.find(socket) != m_socketAddresses.end())
      {
        receiver = m_socketAddresses[socket].GetLocal();
      }
      else if (m_socketSubnetBroadcastAddresses.find(socket) != m_socketSubnetBroadcastAddresses.end())
      {
        receiver = m_socketSubnetBroadcastAddresses[socket].GetLocal();
      }
      else
      {
        NS_ASSERT_MSG(false, "Received a packet from an unknown socket");
      }
      NS_LOG_DEBUG("AODV node " << this << " received a AODV packet from " << sender << " to " << receiver);

      UpdateRouteToNeighbor(sender, receiver);
      TypeHeader tHeader(AODVTYPE_RREQ);
      packet->RemoveHeader(tHeader);
      if (!tHeader.IsValid())
      {
        NS_LOG_DEBUG("AODV message " << packet->GetUid() << " with unknown type received: " << tHeader.Get() << ". Drop");
        return; // drop
      }
      switch (tHeader.Get())
      {
      case AODVTYPE_RREQ:
      {
        RecvRequest(packet, receiver, sender);
        break;
      }
      case AODVTYPE_RREP:
      {
        RecvReply(packet, receiver, sender);
        break;
      }
      case AODVTYPE_RERR:
      {
        RecvError(packet, sender);
        break;
      }
      case AODVTYPE_RREP_ACK:
      {
        RecvReplyAck(sender);
        break;
      }
      }
    }

    bool
    AodvBHSFRoutingProtocol::UpdateRouteLifeTime(Ipv4Address addr, Time lifetime)
    {
      NS_LOG_FUNCTION(this << addr << lifetime);
      RoutingTableEntry rt;
      if (m_routingTable.LookupRoute(addr, rt))
      {
        if (rt.GetFlag() == VALID)
        {
          NS_LOG_DEBUG("Updating VALID route");
          rt.SetRreqCnt(0);
          rt.SetLifeTime(std::max(lifetime, rt.GetLifeTime()));
          m_routingTable.Update(rt);
          return true;
        }
      }
      return false;
    }

    void
    AodvBHSFRoutingProtocol::UpdateRouteToNeighbor(Ipv4Address sender, Ipv4Address receiver)
    {
      NS_LOG_FUNCTION(this << "sender " << sender << " receiver " << receiver);
      RoutingTableEntry toNeighbor;
      if (!m_routingTable.LookupRoute(sender, toNeighbor))
      {
        Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver));
        RoutingTableEntry newEntry(/*device=*/dev, /*dst=*/sender, /*know seqno=*/false, /*seqno=*/0,
                                   /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
                                   /*hops=*/1, /*next hop=*/sender, /*lifetime=*/m_activeRouteTimeout);
        m_routingTable.AddRoute(newEntry);
      }
      else
      {
        Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver));
        if (toNeighbor.GetValidSeqNo() && (toNeighbor.GetHop() == 1) && (toNeighbor.GetOutputDevice() == dev))
        {
          toNeighbor.SetLifeTime(std::max(m_activeRouteTimeout, toNeighbor.GetLifeTime()));
        }
        else
        {
          RoutingTableEntry newEntry(/*device=*/dev, /*dst=*/sender, /*know seqno=*/false, /*seqno=*/0,
                                     /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
                                     /*hops=*/1, /*next hop=*/sender, /*lifetime=*/std::max(m_activeRouteTimeout, toNeighbor.GetLifeTime()));
          m_routingTable.Update(newEntry);
        }
      }
    }

    // 设置黑洞节点标志
    void
    AodvBHSFRoutingProtocol::SetBlackhole(bool isBlackhole)
    {
      m_isBlackhole = isBlackhole;
    }

    // 设置选择性转发节点标志
    void
    AodvBHSFRoutingProtocol::SetSelectiveForwarding(bool isSelectiveForwarding)
    {
      m_isSelectiveForwarding = isSelectiveForwarding;
    }

    // 检查是否是黑洞节点
    bool
    AodvBHSFRoutingProtocol::IsBlackholeNode() const
    {
      return m_isBlackhole;
    }

    // 检查是否是选择性转发节点
    bool
    AodvBHSFRoutingProtocol::IsSelectiveForwardingNode() const
    {
      return m_isSelectiveForwarding;
    }

    void AodvBHSFRoutingProtocol::RecvRequest(Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src)
    {
      NS_LOG_FUNCTION(this);       // 日志记录函数调用
      RreqHeader rreqHeader;       // 声明RREQ头部
      Ipv4Header header;           // 声明IP头部
      p->RemoveHeader(rreqHeader); // 从数据包中移除并解析RREQ头部

      // 节点忽略来自黑名单节点的所有RREQ请求
      RoutingTableEntry toPrev;
      if (m_routingTable.LookupRoute(src, toPrev))
      {
        if (toPrev.IsUnidirectional()) // 若为单向路径
        {
          NS_LOG_DEBUG("Ignoring RREQ from node in blacklist");
          return;
        }
      }

      uint32_t id = rreqHeader.GetId();            // 获取RREQ ID
      Ipv4Address origin = rreqHeader.GetOrigin(); // 获取请求源IP地址

      // 检查是否收到过相同的RREQ，若是则丢弃
      if (m_rreqIdCache.IsDuplicate(origin, id))
      {
        NS_LOG_DEBUG("Ignoring RREQ due to duplicate");
        return;
      }

      // 增加RREQ的跳数计数
      uint8_t hop = rreqHeader.GetHopCount() + 1;
      rreqHeader.SetHopCount(hop);

      // 当反向路由被创建或更新时，执行以下操作
      RoutingTableEntry toOrigin;
      if (!m_routingTable.LookupRoute(origin, toOrigin))
      {
        Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver));
        RoutingTableEntry newEntry(/*device=*/dev, /*dst=*/origin, /*validSeno=*/true, /*seqNo=*/rreqHeader.GetOriginSeqno(),
                                   /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0), /*hops=*/hop,
                                   /*nextHop*/ src, /*timeLife=*/Time((2 * m_netTraversalTime - 2 * hop * m_nodeTraversalTime)));
        m_routingTable.AddRoute(newEntry); // 将新路由项添加到路由表
      }
      else
      {
        if (toOrigin.GetValidSeqNo()) // 若序列号有效
        {
          if (int32_t(rreqHeader.GetOriginSeqno()) - int32_t(toOrigin.GetSeqNo()) > 0)
          {
            toOrigin.SetSeqNo(rreqHeader.GetOriginSeqno()); // 更新序列号
          }
        }
        else
        {
          toOrigin.SetSeqNo(rreqHeader.GetOriginSeqno()); // 设置新的序列号
        }
        toOrigin.SetValidSeqNo(true); // 设置序列号有效
        toOrigin.SetNextHop(src);     // 设置下一跳
        toOrigin.SetOutputDevice(m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver)));
        toOrigin.SetInterface(m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0));
        toOrigin.SetHop(hop); // 设置跳数
        toOrigin.SetLifeTime(std::max(Time(2 * m_netTraversalTime - 2 * hop * m_nodeTraversalTime),
                                      toOrigin.GetLifeTime())); // 更新生存时间
        m_routingTable.Update(toOrigin);                        // 更新路由表
        // m_nb.Update (src, Time (AllowedHelloLoss * HelloInterval));
      }

      // 查找源节点的路由表项
      RoutingTableEntry toNeighbor;
      if (!m_routingTable.LookupRoute(src, toNeighbor))
      {
        NS_LOG_DEBUG("Neighbor:" << src << " not found in routing table. Creating an entry");
        Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver));
        RoutingTableEntry newEntry(dev, src, false, rreqHeader.GetOriginSeqno(),
                                   m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
                                   1, src, m_activeRouteTimeout);
        m_routingTable.AddRoute(newEntry); // 添加新的邻居路由表项
      }
      else
      {
        toNeighbor.SetLifeTime(m_activeRouteTimeout);     // 设置生存时间
        toNeighbor.SetValidSeqNo(false);                  // 将序列号设为无效
        toNeighbor.SetSeqNo(rreqHeader.GetOriginSeqno()); // 更新序列号
        toNeighbor.SetFlag(VALID);                        // 设置状态为有效
        toNeighbor.SetOutputDevice(m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver)));
        toNeighbor.SetInterface(m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0));
        toNeighbor.SetHop(1);              // 设置跳数为1
        toNeighbor.SetNextHop(src);        // 设置下一跳
        m_routingTable.Update(toNeighbor); // 更新路由表
      }
      m_nb.Update(src, Time(m_allowedHelloLoss * m_helloInterval)); // 更新邻居信息

      NS_LOG_LOGIC(receiver << " receive RREQ with hop count " << static_cast<uint32_t>(rreqHeader.GetHopCount())
                            << " ID " << rreqHeader.GetId()
                            << " to destination " << rreqHeader.GetDst());

      // //如果是选择性转发节点，
      // if (IsSelectiveForwardingNode())
      // {
      //   if (rand() % 10 <= 3)
      //   {
      //     // 伪造RREP（路由回复）消息，声称自己为最短路径
      //     m_routingTable.LookupRoute(origin, toOrigin);
      //     NS_LOG_DEBUG("Send reply since I am the destination");
      //     SendReply(rreqHeader, toOrigin); // 发送RREP
      //     return;
      //   }
      // }

      if (IsBlackholeNode())
      { // 若节点为恶意节点检查是否为黑洞节点
        NS_LOG_INFO("Blackhole node " << m_ipv4->GetAddress(0, 0).GetLocal() << " received RREQ and sending fake RREP");

        // 伪造RREP（路由回复）消息，声称自己为最短路径
        m_routingTable.LookupRoute(origin, toOrigin);
        NS_LOG_DEBUG("Send reply since I am the destination");
        SendReply(rreqHeader, toOrigin); // 发送RREP
        return;
      }

      // 若节点为目的节点则生成RREP
      if (IsMyOwnAddress(rreqHeader.GetDst()))
      {
        m_routingTable.LookupRoute(origin, toOrigin);
        NS_LOG_DEBUG("Send reply since I am the destination");
        SendReply(rreqHeader, toOrigin); // 发送RREP
        return;
      }
      // 若节点有到目的节点的有效路由且序列号大于等于RREQ中的序列号，且"目的节点专属"标志未设置
      RoutingTableEntry toDst;
      Ipv4Address dst = rreqHeader.GetDst();
      if (m_routingTable.LookupRoute(dst, toDst))
      {
        if (toDst.GetNextHop() == src) // 若下一跳是源节点则丢弃RREQ
        {
          NS_LOG_DEBUG("Drop RREQ from " << src << ", dest next hop " << toDst.GetNextHop());
          return;
        }
        if ((rreqHeader.GetUnknownSeqno() || (int32_t(toDst.GetSeqNo()) - int32_t(rreqHeader.GetDstSeqno()) >= 0)) && toDst.GetValidSeqNo())
        {
          if (!rreqHeader.GetDestinationOnly() && toDst.GetFlag() == VALID)
          {
            m_routingTable.LookupRoute(origin, toOrigin);
            SendReplyByIntermediateNode(toDst, toOrigin, rreqHeader.GetGratuitousRrep()); // 由中间节点发送RREP
            return;
          }
          rreqHeader.SetDstSeqno(toDst.GetSeqNo());
          rreqHeader.SetUnknownSeqno(false); // 更新目的序列号
        }
      }

      SocketIpTtlTag tag;
      p->RemovePacketTag(tag); // 移除TTL标签
      if (tag.GetTtl() < 2)    // 若TTL小于2则丢弃
      {
        NS_LOG_DEBUG("TTL exceeded. Drop RREQ origin " << src << " destination " << dst);
        return;
      }

      // 广播RREQ消息
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
               m_socketAddresses.begin();
           j != m_socketAddresses.end(); ++j)
      {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag ttl;
        ttl.SetTtl(tag.GetTtl() - 1); // 减少TTL值
        packet->AddPacketTag(ttl);
        packet->AddHeader(rreqHeader);
        TypeHeader tHeader(AODVTYPE_RREQ);
        packet->AddHeader(tHeader);
        Ipv4Address destination;
        if (iface.GetMask() == Ipv4Mask::GetOnes())
        {
          destination = Ipv4Address("255.255.255.255"); // 全局广播
        }
        else
        {
          destination = iface.GetBroadcast(); // 子网广播
        }
        m_lastBcastTime = Simulator::Now(); // 更新广播时间
        Simulator::Schedule(Time(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10))), &AodvBHSFRoutingProtocol::SendTo, this, socket, packet, destination);
      }
    }

    void
    AodvBHSFRoutingProtocol::SendFakeRrep(Ipv4Address dst)
    {
      // 构建虚假的RREP消息，声称自己是最短路径
      Ptr<Packet> packet = Create<Packet>(100); // 假设虚假的RREP大小为100字节

      // 确保 sourceAddress 和 destinationAddress 在此作用域中可用
      Ipv4Address sourceAddress = m_ipv4->GetAddress(0, 0).GetLocal(); // 获取源节点地址
      Ipv4Address destinationAddress = dst;                            // 目标地址为收到的请求目的节点

      // 设置协议号为 UDP 的协议号
      uint8_t protocolNumber = UdpL4Protocol::PROT_NUMBER;

      // 构造虚假的路由条目
      Ptr<Ipv4Route> route = Create<Ipv4Route>(); // 创建一个新的IPv4路由对象
      route->SetDestination(destinationAddress);  // 设置目的地址
      route->SetSource(sourceAddress);            // 设置源地址

      // 声明并初始化 rrepHeader
      RrepHeader rrepHeader;

      // 构造伪造的RREP头部
      rrepHeader.SetDst(dst);              // 设置目的地址为请求发起者
      rrepHeader.SetDstSeqno(4294967295);  // 设置一个非常高的目的序列号，欺骗节点
      rrepHeader.SetHopCount(1);           // 声称只有一跳到达目的节点
      rrepHeader.SetLifeTime(Seconds(10)); // 设置路由的生命周期（注意这里使用的是 `Seconds()`，返回的是 `ns3::Time`）

      // 将RREP头部添加到数据包
      packet->AddHeader(rrepHeader);

      // 发送数据包，通过广播地址
      Ipv4Address broadcast = Ipv4Address("255.255.255.255");

      // 获取广播路由
      RoutingTableEntry toDst;
      if (m_routingTable.LookupRoute(broadcast, toDst))
      {
        m_ipv4->Send(packet, sourceAddress, destinationAddress, protocolNumber, route); // 这里修正了 sourceAddress 和 destinationAddress
      }
      else
      {
        NS_LOG_WARN("No route to broadcast address, unable to send fake RREP");
      }
    }

    void
    AodvBHSFRoutingProtocol::SendReply(RreqHeader const &rreqHeader, RoutingTableEntry const &toOrigin)
    {
      NS_LOG_FUNCTION(this << toOrigin.GetDestination());
      /*
       * Destination node MUST increment its own sequence number by one if the sequence number in the RREQ packet is equal to that
       * incremented value. Otherwise, the destination does not change its sequence number before generating the  RREP message.
       */
      if (!rreqHeader.GetUnknownSeqno() && (rreqHeader.GetDstSeqno() == m_seqNo + 1))
      {
        m_seqNo++;
      }
      RrepHeader rrepHeader(/*prefixSize=*/0, /*hops=*/0, /*dst=*/rreqHeader.GetDst(),
                            /*dstSeqNo=*/m_seqNo, /*origin=*/toOrigin.GetDestination(), /*lifeTime=*/m_myRouteTimeout);
      Ptr<Packet> packet = Create<Packet>();
      SocketIpTtlTag tag;
      tag.SetTtl(toOrigin.GetHop());
      packet->AddPacketTag(tag);
      packet->AddHeader(rrepHeader);
      TypeHeader tHeader(AODVTYPE_RREP);
      packet->AddHeader(tHeader);
      Ptr<Socket> socket = FindSocketWithInterfaceAddress(toOrigin.GetInterface());
      NS_ASSERT(socket);
      socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), AODV_PORT));
    }

    void
    AodvBHSFRoutingProtocol::SendReplyByIntermediateNode(RoutingTableEntry &toDst, RoutingTableEntry &toOrigin, bool gratRep)
    {
      NS_LOG_FUNCTION(this);
      RrepHeader rrepHeader(/*prefix size=*/0, /*hops=*/toDst.GetHop(), /*dst=*/toDst.GetDestination(), /*dst seqno=*/toDst.GetSeqNo(),
                            /*origin=*/toOrigin.GetDestination(), /*lifetime=*/toDst.GetLifeTime());
      /* If the node we received a RREQ for is a neighbor we are
       * probably facing a unidirectional link... Better request a RREP-ack
       */
      if (toDst.GetHop() == 1)
      {
        rrepHeader.SetAckRequired(true);
        RoutingTableEntry toNextHop;
        m_routingTable.LookupRoute(toOrigin.GetNextHop(), toNextHop);
        toNextHop.m_ackTimer.SetFunction(&AodvBHSFRoutingProtocol::AckTimerExpire, this);
        toNextHop.m_ackTimer.SetArguments(toNextHop.GetDestination(), m_blackListTimeout);
        toNextHop.m_ackTimer.SetDelay(m_nextHopWait);
      }
      toDst.InsertPrecursor(toOrigin.GetNextHop());
      toOrigin.InsertPrecursor(toDst.GetNextHop());
      m_routingTable.Update(toDst);
      m_routingTable.Update(toOrigin);

      Ptr<Packet> packet = Create<Packet>();
      SocketIpTtlTag tag;
      tag.SetTtl(toOrigin.GetHop());
      packet->AddPacketTag(tag);
      packet->AddHeader(rrepHeader);
      TypeHeader tHeader(AODVTYPE_RREP);
      packet->AddHeader(tHeader);
      Ptr<Socket> socket = FindSocketWithInterfaceAddress(toOrigin.GetInterface());
      NS_ASSERT(socket);
      socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), AODV_PORT));

      // Generating gratuitous RREPs
      if (gratRep)
      {
        RrepHeader gratRepHeader(/*prefix size=*/0, /*hops=*/toOrigin.GetHop(), /*dst=*/toOrigin.GetDestination(),
                                 /*dst seqno=*/toOrigin.GetSeqNo(), /*origin=*/toDst.GetDestination(),
                                 /*lifetime=*/toOrigin.GetLifeTime());
        Ptr<Packet> packetToDst = Create<Packet>();
        SocketIpTtlTag gratTag;
        gratTag.SetTtl(toDst.GetHop());
        packetToDst->AddPacketTag(gratTag);
        packetToDst->AddHeader(gratRepHeader);
        TypeHeader type(AODVTYPE_RREP);
        packetToDst->AddHeader(type);
        Ptr<Socket> socket = FindSocketWithInterfaceAddress(toDst.GetInterface());
        NS_ASSERT(socket);
        NS_LOG_LOGIC("Send gratuitous RREP " << packet->GetUid());
        socket->SendTo(packetToDst, 0, InetSocketAddress(toDst.GetNextHop(), AODV_PORT));
      }
    }

    void
    AodvBHSFRoutingProtocol::SendReplyAck(Ipv4Address neighbor)
    {
      NS_LOG_FUNCTION(this << " to " << neighbor);
      RrepAckHeader h;
      TypeHeader typeHeader(AODVTYPE_RREP_ACK);
      Ptr<Packet> packet = Create<Packet>();
      SocketIpTtlTag tag;
      tag.SetTtl(1);
      packet->AddPacketTag(tag);
      packet->AddHeader(h);
      packet->AddHeader(typeHeader);
      RoutingTableEntry toNeighbor;
      m_routingTable.LookupRoute(neighbor, toNeighbor);
      Ptr<Socket> socket = FindSocketWithInterfaceAddress(toNeighbor.GetInterface());
      NS_ASSERT(socket);
      socket->SendTo(packet, 0, InetSocketAddress(neighbor, AODV_PORT));
    }

    void
    AodvBHSFRoutingProtocol::RecvReply(Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender)
    {
      NS_LOG_FUNCTION(this << " src " << sender);
      RrepHeader rrepHeader;
      p->RemoveHeader(rrepHeader);
      Ipv4Address dst = rrepHeader.GetDst();
      NS_LOG_LOGIC("RREP destination " << dst << " RREP origin " << rrepHeader.GetOrigin());

      uint8_t hop = rrepHeader.GetHopCount() + 1;
      rrepHeader.SetHopCount(hop);

      // If RREP is Hello message
      if (dst == rrepHeader.GetOrigin())
      {
        ProcessHello(rrepHeader, receiver);
        return;
      }

      /*
       * If the route table entry to the destination is created or updated, then the following actions occur:
       * -  the route is marked as active,
       * -  the destination sequence number is marked as valid,
       * -  the next hop in the route entry is assigned to be the node from which the RREP is received,
       *    which is indicated by the source IP address field in the IP header,
       * -  the hop count is set to the value of the hop count from RREP message + 1
       * -  the expiry time is set to the current time plus the value of the Lifetime in the RREP message,
       * -  and the destination sequence number is the Destination Sequence Number in the RREP message.
       */
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver));
      RoutingTableEntry newEntry(/*device=*/dev, /*dst=*/dst, /*validSeqNo=*/true, /*seqno=*/rrepHeader.GetDstSeqno(),
                                 /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0), /*hop=*/hop,
                                 /*nextHop=*/sender, /*lifeTime=*/rrepHeader.GetLifeTime());
      RoutingTableEntry toDst;
      if (m_routingTable.LookupRoute(dst, toDst))
      {
        /*
         * The existing entry is updated only in the following circumstances:
         * (i) the sequence number in the routing table is marked as invalid in route table entry.
         */
        if (!toDst.GetValidSeqNo())
        {
          m_routingTable.Update(newEntry);
        }
        // (ii)the Destination Sequence Number in the RREP is greater than the node's copy of the destination sequence number and the known value is valid,
        else if ((int32_t(rrepHeader.GetDstSeqno()) - int32_t(toDst.GetSeqNo())) > 0)
        {
          m_routingTable.Update(newEntry);
        }
        else
        {
          // (iii) the sequence numbers are the same, but the route is marked as inactive.
          if ((rrepHeader.GetDstSeqno() == toDst.GetSeqNo()) && (toDst.GetFlag() != VALID))
          {
            m_routingTable.Update(newEntry);
          }
          // (iv)  the sequence numbers are the same, and the New Hop Count is smaller than the hop count in route table entry.
          else if ((rrepHeader.GetDstSeqno() == toDst.GetSeqNo()) && (hop < toDst.GetHop()))
          {
            m_routingTable.Update(newEntry);
          }
        }
      }
      else
      {
        // The forward route for this destination is created if it does not already exist.
        NS_LOG_LOGIC("add new route");
        m_routingTable.AddRoute(newEntry);
      }
      // Acknowledge receipt of the RREP by sending a RREP-ACK message back
      if (rrepHeader.GetAckRequired())
      {
        SendReplyAck(sender);
        rrepHeader.SetAckRequired(false);
      }
      NS_LOG_LOGIC("receiver " << receiver << " origin " << rrepHeader.GetOrigin());
      if (IsMyOwnAddress(rrepHeader.GetOrigin()))
      {
        if (toDst.GetFlag() == IN_SEARCH)
        {
          m_routingTable.Update(newEntry);
          m_addressReqTimer[dst].Cancel();
          m_addressReqTimer.erase(dst);
        }
        m_routingTable.LookupRoute(dst, toDst);
        SendPacketFromQueue(dst, toDst.GetRoute());
        return;
      }

      RoutingTableEntry toOrigin;
      if (!m_routingTable.LookupRoute(rrepHeader.GetOrigin(), toOrigin) || toOrigin.GetFlag() == IN_SEARCH)
      {
        return; // Impossible! drop.
      }
      toOrigin.SetLifeTime(std::max(m_activeRouteTimeout, toOrigin.GetLifeTime()));
      m_routingTable.Update(toOrigin);

      // Update information about precursors
      if (m_routingTable.LookupValidRoute(rrepHeader.GetDst(), toDst))
      {
        toDst.InsertPrecursor(toOrigin.GetNextHop());
        m_routingTable.Update(toDst);

        RoutingTableEntry toNextHopToDst;
        m_routingTable.LookupRoute(toDst.GetNextHop(), toNextHopToDst);
        toNextHopToDst.InsertPrecursor(toOrigin.GetNextHop());
        m_routingTable.Update(toNextHopToDst);

        toOrigin.InsertPrecursor(toDst.GetNextHop());
        m_routingTable.Update(toOrigin);

        RoutingTableEntry toNextHopToOrigin;
        m_routingTable.LookupRoute(toOrigin.GetNextHop(), toNextHopToOrigin);
        toNextHopToOrigin.InsertPrecursor(toDst.GetNextHop());
        m_routingTable.Update(toNextHopToOrigin);
      }
      SocketIpTtlTag tag;
      p->RemovePacketTag(tag);
      if (tag.GetTtl() < 2)
      {
        NS_LOG_DEBUG("TTL exceeded. Drop RREP destination " << dst << " origin " << rrepHeader.GetOrigin());
        return;
      }

      Ptr<Packet> packet = Create<Packet>();
      SocketIpTtlTag ttl;
      ttl.SetTtl(tag.GetTtl() - 1);
      packet->AddPacketTag(ttl);
      packet->AddHeader(rrepHeader);
      TypeHeader tHeader(AODVTYPE_RREP);
      packet->AddHeader(tHeader);
      Ptr<Socket> socket = FindSocketWithInterfaceAddress(toOrigin.GetInterface());
      NS_ASSERT(socket);
      socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), AODV_PORT));
    }

    void
    AodvBHSFRoutingProtocol::RecvReplyAck(Ipv4Address neighbor)
    {
      NS_LOG_FUNCTION(this);
      RoutingTableEntry rt;
      if (m_routingTable.LookupRoute(neighbor, rt))
      {
        rt.m_ackTimer.Cancel();
        rt.SetFlag(VALID);
        m_routingTable.Update(rt);
      }
    }

    void
    AodvBHSFRoutingProtocol::ProcessHello(RrepHeader const &rrepHeader, Ipv4Address receiver)
    {
      NS_LOG_FUNCTION(this << "from " << rrepHeader.GetDst());
      /*
       *  Whenever a node receives a Hello message from a neighbor, the node
       * SHOULD make sure that it has an active route to the neighbor, and
       * create one if necessary.
       */
      RoutingTableEntry toNeighbor;
      if (!m_routingTable.LookupRoute(rrepHeader.GetDst(), toNeighbor))
      {
        Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver));
        RoutingTableEntry newEntry(/*device=*/dev, /*dst=*/rrepHeader.GetDst(), /*validSeqNo=*/true, /*seqno=*/rrepHeader.GetDstSeqno(),
                                   /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
                                   /*hop=*/1, /*nextHop=*/rrepHeader.GetDst(), /*lifeTime=*/rrepHeader.GetLifeTime());
        m_routingTable.AddRoute(newEntry);
      }
      else
      {
        toNeighbor.SetLifeTime(std::max(Time(m_allowedHelloLoss * m_helloInterval), toNeighbor.GetLifeTime()));
        toNeighbor.SetSeqNo(rrepHeader.GetDstSeqno());
        toNeighbor.SetValidSeqNo(true);
        toNeighbor.SetFlag(VALID);
        toNeighbor.SetOutputDevice(m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver)));
        toNeighbor.SetInterface(m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0));
        toNeighbor.SetHop(1);
        toNeighbor.SetNextHop(rrepHeader.GetDst());
        m_routingTable.Update(toNeighbor);
      }
      if (m_enableHello)
      {
        m_nb.Update(rrepHeader.GetDst(), Time(m_allowedHelloLoss * m_helloInterval));
      }
    }

    void
    AodvBHSFRoutingProtocol::RecvError(Ptr<Packet> p, Ipv4Address src)
    {
      NS_LOG_FUNCTION(this << " from " << src);
      RerrHeader rerrHeader;
      p->RemoveHeader(rerrHeader);
      std::map<Ipv4Address, uint32_t> dstWithNextHopSrc;
      std::map<Ipv4Address, uint32_t> unreachable;
      m_routingTable.GetListOfDestinationWithNextHop(src, dstWithNextHopSrc);
      std::pair<Ipv4Address, uint32_t> un;
      while (rerrHeader.RemoveUnDestination(un))
      {
        for (std::map<Ipv4Address, uint32_t>::const_iterator i =
                 dstWithNextHopSrc.begin();
             i != dstWithNextHopSrc.end(); ++i)
        {
          if (i->first == un.first)
          {
            unreachable.insert(un);
          }
        }
      }

      std::vector<Ipv4Address> precursors;
      for (std::map<Ipv4Address, uint32_t>::const_iterator i = unreachable.begin();
           i != unreachable.end();)
      {
        if (!rerrHeader.AddUnDestination(i->first, i->second))
        {
          TypeHeader typeHeader(AODVTYPE_RERR);
          Ptr<Packet> packet = Create<Packet>();
          SocketIpTtlTag tag;
          tag.SetTtl(1);
          packet->AddPacketTag(tag);
          packet->AddHeader(rerrHeader);
          packet->AddHeader(typeHeader);
          SendRerrMessage(packet, precursors);
          rerrHeader.Clear();
        }
        else
        {
          RoutingTableEntry toDst;
          m_routingTable.LookupRoute(i->first, toDst);
          toDst.GetPrecursors(precursors);
          ++i;
        }
      }
      if (rerrHeader.GetDestCount() != 0)
      {
        TypeHeader typeHeader(AODVTYPE_RERR);
        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag tag;
        tag.SetTtl(1);
        packet->AddPacketTag(tag);
        packet->AddHeader(rerrHeader);
        packet->AddHeader(typeHeader);
        SendRerrMessage(packet, precursors);
      }
      m_routingTable.InvalidateRoutesWithDst(unreachable);
    }

    void
    AodvBHSFRoutingProtocol::RouteRequestTimerExpire(Ipv4Address dst)
    {
      NS_LOG_LOGIC(this);
      RoutingTableEntry toDst;
      if (m_routingTable.LookupValidRoute(dst, toDst))
      {
        SendPacketFromQueue(dst, toDst.GetRoute());
        NS_LOG_LOGIC("route to " << dst << " found");
        return;
      }
      /*
       *  If a route discovery has been attempted RreqRetries times at the maximum TTL without
       *  receiving any RREP, all data packets destined for the corresponding destination SHOULD be
       *  dropped from the buffer and a Destination Unreachable message SHOULD be delivered to the application.
       */
      if (toDst.GetRreqCnt() == m_rreqRetries)
      {
        NS_LOG_LOGIC("route discovery to " << dst << " has been attempted RreqRetries (" << m_rreqRetries << ") times with ttl " << m_netDiameter);
        m_addressReqTimer.erase(dst);
        m_routingTable.DeleteRoute(dst);
        NS_LOG_DEBUG("Route not found. Drop all packets with dst " << dst);
        m_queue.DropPacketWithDst(dst);
        return;
      }

      if (toDst.GetFlag() == IN_SEARCH)
      {
        NS_LOG_LOGIC("Resend RREQ to " << dst << " previous ttl " << toDst.GetHop());
        SendRequest(dst);
      }
      else
      {
        NS_LOG_DEBUG("Route down. Stop search. Drop packet with destination " << dst);
        m_addressReqTimer.erase(dst);
        m_routingTable.DeleteRoute(dst);
        m_queue.DropPacketWithDst(dst);
      }
    }

    void
    AodvBHSFRoutingProtocol::HelloTimerExpire()
    {
      NS_LOG_FUNCTION(this);
      Time offset = Time(Seconds(0));
      if (m_lastBcastTime > Time(Seconds(0)))
      {
        offset = Simulator::Now() - m_lastBcastTime;
        NS_LOG_DEBUG("Hello deferred due to last bcast at:" << m_lastBcastTime);
      }
      else
      {
        SendHello();
      }
      m_htimer.Cancel();
      Time diff = m_helloInterval - offset;
      m_htimer.Schedule(std::max(Time(Seconds(0)), diff));
      m_lastBcastTime = Time(Seconds(0));
    }

    void
    AodvBHSFRoutingProtocol::RreqRateLimitTimerExpire()
    {
      NS_LOG_FUNCTION(this);
      m_rreqCount = 0;
      m_rreqRateLimitTimer.Schedule(Seconds(1));
    }

    void
    AodvBHSFRoutingProtocol::RerrRateLimitTimerExpire()
    {
      NS_LOG_FUNCTION(this);
      m_rerrCount = 0;
      m_rerrRateLimitTimer.Schedule(Seconds(1));
    }

    void
    AodvBHSFRoutingProtocol::AckTimerExpire(Ipv4Address neighbor, Time blacklistTimeout)
    {
      NS_LOG_FUNCTION(this);
      m_routingTable.MarkLinkAsUnidirectional(neighbor, blacklistTimeout);
    }

    void
    AodvBHSFRoutingProtocol::SendHello()
    {
      NS_LOG_FUNCTION(this);
      /* Broadcast a RREP with TTL = 1 with the RREP message fields set as follows:
       *   Destination IP Address         The node's IP address.
       *   Destination Sequence Number    The node's latest sequence number.
       *   Hop Count                      0
       *   Lifetime                       AllowedHelloLoss * HelloInterval
       */
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
      {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        RrepHeader helloHeader(/*prefix size=*/0, /*hops=*/0, /*dst=*/iface.GetLocal(), /*dst seqno=*/m_seqNo,
                               /*origin=*/iface.GetLocal(), /*lifetime=*/Time(m_allowedHelloLoss * m_helloInterval));
        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag tag;
        tag.SetTtl(1);
        packet->AddPacketTag(tag);
        packet->AddHeader(helloHeader);
        TypeHeader tHeader(AODVTYPE_RREP);
        packet->AddHeader(tHeader);
        // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
        Ipv4Address destination;
        if (iface.GetMask() == Ipv4Mask::GetOnes())
        {
          destination = Ipv4Address("255.255.255.255");
        }
        else
        {
          destination = iface.GetBroadcast();
        }
        Time jitter = Time(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10)));
        Simulator::Schedule(jitter, &AodvBHSFRoutingProtocol::SendTo, this, socket, packet, destination);
      }
    }

    void
    AodvBHSFRoutingProtocol::SendPacketFromQueue(Ipv4Address dst, Ptr<Ipv4Route> route)
    {
      NS_LOG_FUNCTION(this);
      QueueEntry queueEntry;

      // 检查当前节点是否是黑洞攻击节点
      if (IsBlackholeNode())
      {
        NS_LOG_INFO("Blackhole node " << m_ipv4->GetAddress(0, 0).GetLocal() << " is dropping the packet to " << dst);
        // 直接丢弃所有目标为 dst 的数据包
        while (m_queue.Dequeue(dst, queueEntry))
        {
          NS_LOG_INFO("Blackhole attack: Dropping packet from queue");
          // 不调用 ucb，直接丢弃
          return;
        }
      }

      // 如果不是黑洞节点，继续正常处理
      while (m_queue.Dequeue(dst, queueEntry))
      {
        DeferredRouteOutputTagwithBHFS tag;
        Ptr<Packet> p = ConstCast<Packet>(queueEntry.GetPacket());
        if (p->RemovePacketTag(tag) && tag.GetInterface() != -1 && tag.GetInterface() != m_ipv4->GetInterfaceForDevice(route->GetOutputDevice()))
        {
          NS_LOG_DEBUG("Output device doesn't match. Dropped.");
          return;
        }
        UnicastForwardCallback ucb = queueEntry.GetUnicastForwardCallback();
        Ipv4Header header = queueEntry.GetIpv4Header();
        header.SetSource(route->GetSource());
        header.SetTtl(header.GetTtl() + 1); // compensate extra TTL decrement by fake loopback routing
        ucb(route, p, header);
      }
    }

    void
    AodvBHSFRoutingProtocol::SendRerrWhenBreaksLinkToNextHop(Ipv4Address nextHop)
    {
      NS_LOG_FUNCTION(this << nextHop);
      RerrHeader rerrHeader;
      std::vector<Ipv4Address> precursors;
      std::map<Ipv4Address, uint32_t> unreachable;

      RoutingTableEntry toNextHop;
      if (!m_routingTable.LookupRoute(nextHop, toNextHop))
      {
        return;
      }
      toNextHop.GetPrecursors(precursors);
      rerrHeader.AddUnDestination(nextHop, toNextHop.GetSeqNo());
      m_routingTable.GetListOfDestinationWithNextHop(nextHop, unreachable);
      for (std::map<Ipv4Address, uint32_t>::const_iterator i = unreachable.begin(); i != unreachable.end();)
      {
        if (!rerrHeader.AddUnDestination(i->first, i->second))
        {
          NS_LOG_LOGIC("Send RERR message with maximum size.");
          TypeHeader typeHeader(AODVTYPE_RERR);
          Ptr<Packet> packet = Create<Packet>();
          SocketIpTtlTag tag;
          tag.SetTtl(1);
          packet->AddPacketTag(tag);
          packet->AddHeader(rerrHeader);
          packet->AddHeader(typeHeader);
          SendRerrMessage(packet, precursors);
          rerrHeader.Clear();
        }
        else
        {
          RoutingTableEntry toDst;
          m_routingTable.LookupRoute(i->first, toDst);
          toDst.GetPrecursors(precursors);
          ++i;
        }
      }
      if (rerrHeader.GetDestCount() != 0)
      {
        TypeHeader typeHeader(AODVTYPE_RERR);
        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag tag;
        tag.SetTtl(1);
        packet->AddPacketTag(tag);
        packet->AddHeader(rerrHeader);
        packet->AddHeader(typeHeader);
        SendRerrMessage(packet, precursors);
      }
      unreachable.insert(std::make_pair(nextHop, toNextHop.GetSeqNo()));
      m_routingTable.InvalidateRoutesWithDst(unreachable);
    }

    void
    AodvBHSFRoutingProtocol::SendRerrWhenNoRouteToForward(Ipv4Address dst,
                                                  uint32_t dstSeqNo, Ipv4Address origin)
    {
      NS_LOG_FUNCTION(this);
      // A node SHOULD NOT originate more than RERR_RATELIMIT RERR messages per second.
      if (m_rerrCount == m_rerrRateLimit)
      {
        // Just make sure that the RerrRateLimit timer is running and will expire
        NS_ASSERT(m_rerrRateLimitTimer.IsRunning());
        // discard the packet and return
        NS_LOG_LOGIC("RerrRateLimit reached at " << Simulator::Now().As(Time::S) << " with timer delay left "
                                                 << m_rerrRateLimitTimer.GetDelayLeft().As(Time::S)
                                                 << "; suppressing RERR");
        return;
      }
      RerrHeader rerrHeader;
      rerrHeader.AddUnDestination(dst, dstSeqNo);
      RoutingTableEntry toOrigin;
      Ptr<Packet> packet = Create<Packet>();
      SocketIpTtlTag tag;
      tag.SetTtl(1);
      packet->AddPacketTag(tag);
      packet->AddHeader(rerrHeader);
      packet->AddHeader(TypeHeader(AODVTYPE_RERR));
      if (m_routingTable.LookupValidRoute(origin, toOrigin))
      {
        Ptr<Socket> socket = FindSocketWithInterfaceAddress(
            toOrigin.GetInterface());
        NS_ASSERT(socket);
        NS_LOG_LOGIC("Unicast RERR to the source of the data transmission");
        socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), AODV_PORT));
      }
      else
      {
        for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i =
                 m_socketAddresses.begin();
             i != m_socketAddresses.end(); ++i)
        {
          Ptr<Socket> socket = i->first;
          Ipv4InterfaceAddress iface = i->second;
          NS_ASSERT(socket);
          NS_LOG_LOGIC("Broadcast RERR message from interface " << iface.GetLocal());
          // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
          Ipv4Address destination;
          if (iface.GetMask() == Ipv4Mask::GetOnes())
          {
            destination = Ipv4Address("255.255.255.255");
          }
          else
          {
            destination = iface.GetBroadcast();
          }
          socket->SendTo(packet->Copy(), 0, InetSocketAddress(destination, AODV_PORT));
        }
      }
    }

    void
    AodvBHSFRoutingProtocol::SendRerrMessage(Ptr<Packet> packet, std::vector<Ipv4Address> precursors)
    {
      NS_LOG_FUNCTION(this);

      if (precursors.empty())
      {
        NS_LOG_LOGIC("No precursors");
        return;
      }
      // A node SHOULD NOT originate more than RERR_RATELIMIT RERR messages per second.
      if (m_rerrCount == m_rerrRateLimit)
      {
        // Just make sure that the RerrRateLimit timer is running and will expire
        NS_ASSERT(m_rerrRateLimitTimer.IsRunning());
        // discard the packet and return
        NS_LOG_LOGIC("RerrRateLimit reached at " << Simulator::Now().As(Time::S) << " with timer delay left "
                                                 << m_rerrRateLimitTimer.GetDelayLeft().As(Time::S)
                                                 << "; suppressing RERR");
        return;
      }
      // If there is only one precursor, RERR SHOULD be unicast toward that precursor
      if (precursors.size() == 1)
      {
        RoutingTableEntry toPrecursor;
        if (m_routingTable.LookupValidRoute(precursors.front(), toPrecursor))
        {
          Ptr<Socket> socket = FindSocketWithInterfaceAddress(toPrecursor.GetInterface());
          NS_ASSERT(socket);
          NS_LOG_LOGIC("one precursor => unicast RERR to " << toPrecursor.GetDestination() << " from " << toPrecursor.GetInterface().GetLocal());
          Simulator::Schedule(Time(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10))), &AodvBHSFRoutingProtocol::SendTo, this, socket, packet, precursors.front());
          m_rerrCount++;
        }
        return;
      }

      //  Should only transmit RERR on those interfaces which have precursor nodes for the broken route
      std::vector<Ipv4InterfaceAddress> ifaces;
      RoutingTableEntry toPrecursor;
      for (std::vector<Ipv4Address>::const_iterator i = precursors.begin(); i != precursors.end(); ++i)
      {
        if (m_routingTable.LookupValidRoute(*i, toPrecursor) && std::find(ifaces.begin(), ifaces.end(), toPrecursor.GetInterface()) == ifaces.end())
        {
          ifaces.push_back(toPrecursor.GetInterface());
        }
      }

      for (std::vector<Ipv4InterfaceAddress>::const_iterator i = ifaces.begin(); i != ifaces.end(); ++i)
      {
        Ptr<Socket> socket = FindSocketWithInterfaceAddress(*i);
        NS_ASSERT(socket);
        NS_LOG_LOGIC("Broadcast RERR message from interface " << i->GetLocal());
        // std::cout << "Broadcast RERR message from interface " << i->GetLocal () << std::endl;
        // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
        Ptr<Packet> p = packet->Copy();
        Ipv4Address destination;
        if (i->GetMask() == Ipv4Mask::GetOnes())
        {
          destination = Ipv4Address("255.255.255.255");
        }
        else
        {
          destination = i->GetBroadcast();
        }
        Simulator::Schedule(Time(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10))), &AodvBHSFRoutingProtocol::SendTo, this, socket, p, destination);
      }
    }

    Ptr<Socket>
    AodvBHSFRoutingProtocol::FindSocketWithInterfaceAddress(Ipv4InterfaceAddress addr) const
    {
      NS_LOG_FUNCTION(this << addr);
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
               m_socketAddresses.begin();
           j != m_socketAddresses.end(); ++j)
      {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        if (iface == addr)
        {
          return socket;
        }
      }
      Ptr<Socket> socket;
      return socket;
    }

    Ptr<Socket>
    AodvBHSFRoutingProtocol::FindSubnetBroadcastSocketWithInterfaceAddress(Ipv4InterfaceAddress addr) const
    {
      NS_LOG_FUNCTION(this << addr);
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
               m_socketSubnetBroadcastAddresses.begin();
           j != m_socketSubnetBroadcastAddresses.end(); ++j)
      {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        if (iface == addr)
        {
          return socket;
        }
      }
      Ptr<Socket> socket;
      return socket;
    }

    void
    AodvBHSFRoutingProtocol::DoInitialize(void)
    {
      NS_LOG_FUNCTION(this);
      uint32_t startTime;
      if (m_enableHello)
      {
        m_htimer.SetFunction(&AodvBHSFRoutingProtocol::HelloTimerExpire, this);
        startTime = m_uniformRandomVariable->GetInteger(0, 100);
        NS_LOG_DEBUG("Starting at time " << startTime << "ms");
        m_htimer.Schedule(MilliSeconds(startTime));
      }
      Ipv4RoutingProtocol::DoInitialize();
    }

  } // namespace aodv
} // namespace ns3
