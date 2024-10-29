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
#ifndef AODVWITHBHANDSF_H
#define AODVWITHBHANDSF_H

#include "ns3/aodv-rtable.h"
#include "ns3/aodv-rqueue.h"
#include "ns3/aodv-packet.h"
#include "ns3/aodv-neighbor.h"
#include "ns3/aodv-dpd.h"
#include "ns3/node.h"
#include "ns3/random-variable-stream.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4-interface.h"
#include "ns3/ipv4-l3-protocol.h"
#include <map>

namespace ns3
{
  namespace aodv
  {
    /**
     * \ingroup aodv
     *
     * \brief AODV 路由协议类
     */
    class AodvBHSFRoutingProtocol : public Ipv4RoutingProtocol
    {
    public:
      /**
       * \brief 获取类型ID。
       * \return 返回对象的 TypeId。
       */
      static TypeId GetTypeId(void);
      static const uint32_t AODV_PORT; ///< AODV 协议的端口号

      /// 构造函数
      AodvBHSFRoutingProtocol();
      virtual ~AodvBHSFRoutingProtocol(); ///< 析构函数
      virtual void DoDispose();   ///< 清理资源

      // 继承自 Ipv4RoutingProtocol
      Ptr<Ipv4Route> RouteOutput(Ptr<Packet> p, const Ipv4Header &header, Ptr<NetDevice> oif, Socket::SocketErrno &sockerr);
      bool RouteInput(Ptr<const Packet> p, const Ipv4Header &header, Ptr<const NetDevice> idev,
                      UnicastForwardCallback ucb, MulticastForwardCallback mcb,
                      LocalDeliverCallback lcb, ErrorCallback ecb);
      virtual void NotifyInterfaceUp(uint32_t interface);                                               ///< 通知接口启动
      virtual void NotifyInterfaceDown(uint32_t interface);                                             ///< 通知接口关闭
      virtual void NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address);                  ///< 通知添加地址
      virtual void NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address);               ///< 通知移除地址
      virtual void SetIpv4(Ptr<Ipv4> ipv4);                                                             ///< 设置 IPv4
      virtual void PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit = Time::S) const; ///< 打印路由表

      // 处理协议参数
      /**
       * 获取最大队列时间
       * \returns 最大队列时间
       */
      Time GetMaxQueueTime() const
      {
        return m_maxQueueTime;
      }

      /**
       * 设置最大队列时间
       * \param t 最大队列时间
       */
      void SetMaxQueueTime(Time t);

      /**
       * 获取最大队列长度
       * \returns 最大队列长度
       */
      uint32_t GetMaxQueueLen() const
      {
        return m_maxQueueLen;
      }

      /**
       * 设置最大队列长度
       * \param len 最大队列长度
       */
      void SetMaxQueueLen(uint32_t len);

      /**
       * 获取仅目的地标志
       * \returns 仅目的地标志
       */
      bool GetDestinationOnlyFlag() const
      {
        return m_destinationOnly;
      }

      /**
       * 设置仅目的地标志
       * \param f 仅目的地标志
       */
      void SetDestinationOnlyFlag(bool f)
      {
        m_destinationOnly = f;
      }

      /**
       * 获取无偿回复标志
       * \returns 无偿回复标志
       */
      bool GetGratuitousReplyFlag() const
      {
        return m_gratuitousReply;
      }

      /**
       * 设置无偿回复标志
       * \param f 无偿回复标志
       */
      void SetGratuitousReplyFlag(bool f)
      {
        m_gratuitousReply = f;
      }

      /**
       * 设置 Hello 消息启用
       * \param f Hello 启用标志
       */
      void SetHelloEnable(bool f)
      {
        m_enableHello = f;
      }

      /**
       * 获取 Hello 启用标志
       * \returns Hello 启用标志
       */
      bool GetHelloEnable() const
      {
        return m_enableHello;
      }

      /**
       * 设置广播启用标志
       * \param f 广播启用标志
       */
      void SetBroadcastEnable(bool f)
      {
        m_enableBroadcast = f;
      }

      /**
       * 获取广播启用标志
       * \returns 广播启用标志
       */
      bool GetBroadcastEnable() const
      {
        return m_enableBroadcast;
      }

      /**
       * 为该模型中使用的随机变量分配固定的随机变量流号。
       * 返回被分配的流号数量（可能为零）。
       *
       * \param stream 要使用的第一个流索引
       * \return 此模型分配的流索引数量
       */
      int64_t AssignStreams(int64_t stream);

      void SetBlackhole(bool isBlackhole);                     ///< 设置为黑洞节点
      void SetSelectiveForwarding(bool isSelectiveForwarding); ///< 设置为选择性转发节点

      bool IsBlackholeNode() const;           ///< 检查是否为黑洞节点
      bool IsSelectiveForwardingNode() const; ///< 检查是否为选择性转发节点

    protected:
      virtual void DoInitialize(void); ///< 初始化协议

    private:
      // 协议参数
      uint32_t m_rreqRetries;      ///< 发现路由时 RREQ 最大重传次数
      uint16_t m_ttlStart;         ///< RREQ 的初始 TTL 值
      uint16_t m_ttlIncrement;     ///< 每次尝试 RREQ 传播的 TTL 增量
      uint16_t m_ttlThreshold;     ///< 扩展环搜索的最大 TTL 值
      uint16_t m_timeoutBuffer;    ///< 超时缓冲区
      uint16_t m_rreqRateLimit;    ///< 每秒 RREQ 的最大数量
      uint16_t m_rerrRateLimit;    ///< 每秒 RERR 的最大数量
      Time m_activeRouteTimeout;   ///< 路由被认为有效的时间段
      uint32_t m_netDiameter;      ///< 网络直径
      Time m_nodeTraversalTime;    ///< 每跳的平均遍历时间估计
      Time m_netTraversalTime;     ///< 平均网络遍历时间估计
      Time m_pathDiscoveryTime;    ///< 发现网络中路由所需的最大时间估计
      Time m_myRouteTimeout;       ///< 本节点生成的 RREP 的生命周期字段值
      Time m_helloInterval;        ///< Hello 消息发送间隔
      uint32_t m_allowedHelloLoss; ///< 有效链接允许丢失的 Hello 消息数量
      Time m_deletePeriod;         ///< 上游节点对无效目的地的邻居的上限时间
      Time m_nextHopWait;          ///< 等待邻居的 RREP_ACK 的时间
      Time m_blackListTimeout;     ///< 节点被列入黑名单的时间
      uint32_t m_maxQueueLen;      ///< 路由协议允许缓冲的最大数据包数量
      Time m_maxQueueTime;         ///< 路由协议允许缓冲数据包的最大时间
      bool m_destinationOnly;      ///< 指示仅目的地可以响应此 RREQ
      bool m_gratuitousReply;      ///< 指示是否应将无偿 RREP 单播到发起路由发现的节点
      bool m_enableHello;          ///< 指示是否启用 Hello 消息
      bool m_enableBroadcast;      ///< 指示是否启用广播数据包转发

      // 黑洞节点和选择性转发节点标记
      bool m_isBlackhole = false;           // 标记是否为黑洞节点
      bool m_isSelectiveForwarding = false; // 标记是否为选择性转发节点

      /// IP 协议
      Ptr<Ipv4> m_ipv4;

      /// 每个 IP 接口的原始单播套接字，映射套接字 -> 接口地址 (IP + 掩码)
      std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_socketAddresses;

      /// 每个 IP 接口的原始子网定向广播套接字，映射套接字 -> 接口地址 (IP + 掩码)
      std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_socketSubnetBroadcastAddresses;

      /// 用于延迟 RREQ 直到数据包完全形成的回环设备
      Ptr<NetDevice> m_lo;

      /// 路由表
      RoutingTable m_routingTable;

      /// 用于缓冲没有路由的数据包的 "drop-front" 队列
      RequestQueue m_queue;

      /// 广播 ID
      uint32_t m_requestId;

      /// 请求序列号
      uint32_t m_seqNo;

      /// 处理重复 RREQ
      IdCache m_rreqIdCache;

      /// 处理重复广播/组播数据包
      DuplicatePacketDetection m_dpd;

      /// 处理邻居
      Neighbors m_nb;

      /// RREQ 速率控制使用的 RREQ 数量
      uint16_t m_rreqCount;

      /// RERR 速率控制使用的 RERR 数量
      uint16_t m_rerrCount;

    private:
      /// 启动协议操作
      void Start();

      /**
       * 排队数据包并发送路由请求
       *
       * \param p 要路由的数据包
       * \param header IP 头
       * \param ucb 单播转发回调函数
       * \param ecb 错误回调函数
       */
      void DeferredRouteOutput(Ptr<const Packet> p, const Ipv4Header &header, UnicastForwardCallback ucb, ErrorCallback ecb);

      /**
       * 如果存在有效路由，则转发数据包。
       *
       * \param p 要路由的数据包
       * \param header IP 头
       * \param ucb 单播转发回调函数
       * \param ecb 错误回调函数
       * \returns 如果已转发则返回 true
       */
      bool Forwarding(Ptr<const Packet> p, const Ipv4Header &header, UnicastForwardCallback ucb, ErrorCallback ecb);

      /**
       * 源节点对单个目的地的路由发现重复尝试使用扩展环搜索技术。
       * \param dst 目的地 IP 地址
       */
      void ScheduleRreqRetry(Ipv4Address dst);

      /**
       * 如果路由存在且有效，则将路由表条目的生命周期字段设置为现有生命周期和 lt 的最大值。
       * \param addr - 目的地址
       * \param lt - 目的地址的路由表条目的生命周期字段的提议时间
       * \return 如果目的地址 addr 的路由存在则返回 true
       */
      bool UpdateRouteLifeTime(Ipv4Address addr, Time lt);

      /**
       * 更新邻居记录。
       * \param receiver 应该是我的接口
       * \param sender 应该是我的邻居的 IP 地址
       */
      void UpdateRouteToNeighbor(Ipv4Address sender, Ipv4Address receiver);

      /**
       * 测试提供的地址是否分配给此节点的接口
       * \param src 源 IP 地址
       * \returns 如果 IP 地址是节点的 IP 地址则返回 true
       */
      bool IsMyOwnAddress(Ipv4Address src);

      /**
       * 查找具有本地接口地址 iface 的单播套接字
       *
       * \param iface 接口
       * \returns 与接口关联的套接字
       */
      Ptr<Socket> FindSocketWithInterfaceAddress(Ipv4InterfaceAddress iface) const;

      /**
       * 查找具有本地接口地址 iface 的子网定向广播套接字
       *
       * \param iface 接口
       * \returns 与接口关联的套接字
       */
      Ptr<Socket> FindSubnetBroadcastSocketWithInterfaceAddress(Ipv4InterfaceAddress iface) const;

      /**
       * 处理 Hello 消息
       *
       * \param rrepHeader RREP 消息头
       * \param receiverIfaceAddr 接收接口的 IP 地址
       */
      void ProcessHello(RrepHeader const &rrepHeader, Ipv4Address receiverIfaceAddr);

      /**
       * 为给定头创建回环路由
       *
       * \param header IP 头
       * \param oif 输出接口的网络设备
       * \returns 路由
       */
      Ptr<Ipv4Route> LoopbackRoute(const Ipv4Header &header, Ptr<NetDevice> oif) const;

      ///\name 接收控制数据包
      //\{
      /// 接收并处理控制数据包
      void RecvAodv(Ptr<Socket> socket);

      /// 接收 RREQ
      void RecvRequest(Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src);

      /// 接收 RREP
      void RecvReply(Ptr<Packet> p, Ipv4Address my, Ipv4Address src);

      /// 接收 RREP_ACK
      void RecvReplyAck(Ipv4Address neighbor);

      /// 从源节点接收 RERR
      void RecvError(Ptr<Packet> p, Ipv4Address src);
      //\}

      /// 接收数据包
      void RecvDataPacket(Ptr<Packet> p, Ipv4Address src, Ipv4Address dst);

      // 发送虚假的 RREP
      void SendFakeRrep(Ipv4Address dst);

      ///\name 发送数据包
      //\{
      /// 从路由请求队列中转发数据包
      void SendPacketFromQueue(Ipv4Address dst, Ptr<Ipv4Route> route);

      /// 发送 Hello 消息
      void SendHello();

      /// 发送 RREQ
      void SendRequest(Ipv4Address dst);

      /// 发送 RREP
      void SendReply(RreqHeader const &rreqHeader, RoutingTableEntry const &toOrigin);

      /** 从中间节点发送 RREP
       * \param toDst 目的地的路由表条目
       * \param toOrigin 发起者的路由表条目
       * \param gratRep 指示是否应将无偿 RREP 单播到目的地
       */
      void SendReplyByIntermediateNode(RoutingTableEntry &toDst, RoutingTableEntry &toOrigin, bool gratRep);

      /// 发送 RREP_ACK
      void SendReplyAck(Ipv4Address neighbor);

      /// 发起 RERR
      void SendRerrWhenBreaksLinkToNextHop(Ipv4Address nextHop);

      /// 转发 RERR
      void SendRerrMessage(Ptr<Packet> packet, std::vector<Ipv4Address> precursors);

      /**
       * 当没有路由转发输入数据包时发送 RERR。
       * 如果存在到发起节点的反向路由，则单播，否则广播。
       * \param dst - 目的节点的 IP 地址
       * \param dstSeqNo - 目的节点的序列号
       * \param origin - 发起节点的 IP 地址
       */
      void SendRerrWhenNoRouteToForward(Ipv4Address dst, uint32_t dstSeqNo, Ipv4Address origin);
      /// @}

      /**
       * 将数据包发送到目标套接字
       * \param socket - 目标节点套接字
       * \param packet - 要发送的数据包
       * \param destination - 目标节点的 IP 地址
       */
      void SendTo(Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination);

      /// Hello 定时器
      Timer m_htimer;

      /// 安排下一次发送 Hello 消息
      void HelloTimerExpire();

      /// RREQ 速率限制定时器
      Timer m_rreqRateLimitTimer;

      /// 重置 RREQ 计数并安排 RREQ 速率限制定时器，延迟 1 秒
      void RreqRateLimitTimerExpire();

      /// RERR 速率限制定时器
      Timer m_rerrRateLimitTimer;

      /// 重置 RERR 计数并安排 RERR 速率限制定时器，延迟 1 秒
      void RerrRateLimitTimerExpire();

      /// 映射 IP 地址 + RREQ 定时器
      std::map<Ipv4Address, Timer> m_addressReqTimer;

      /**
       * 处理路由发现过程
       * \param dst 目的地的 IP 地址
       */
      void RouteRequestTimerExpire(Ipv4Address dst);

      /**
       * 将与邻居节点的链接标记为单向，持续黑名单超时
       *
       * \param neighbor 邻居节点的 IP 地址
       * \param blacklistTimeout 黑名单超时时间
       */
      void AckTimerExpire(Ipv4Address neighbor, Time blacklistTimeout);

      /// 提供均匀随机变量
      Ptr<UniformRandomVariable> m_uniformRandomVariable;

      /// 记录上次广播时间
      Time m_lastBcastTime;
    };

  } // namespace aodv
} // namespace ns3

#endif /* AODVROUTINGPROTOCOL_H */
