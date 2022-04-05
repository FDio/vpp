/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define DPDK_NB_RX_DESC_DEFAULT   1024
#define DPDK_NB_TX_DESC_DEFAULT   1024
#define DPDK_MAX_LRO_SIZE_DEFAULT 65536

/* These args appear by themselves */
#define foreach_eal_double_hyphen_predicate_arg \
_(no-shconf)                                    \
_(no-hpet)                                      \
_(no-huge)                                      \
_(vmware-tsc-map)

#define foreach_eal_single_hyphen_arg           \
_(mem-alloc-request, m)                         \
_(force-ranks, r)

/* clang-format off */
/* These args are preceded by "--" and followed by a single string */
#define foreach_eal_double_hyphen_arg           \
_(huge-dir)                                     \
_(proc-type)                                    \
_(file-prefix)                                  \
_(vdev)                                         \
_(log-level)                                    \
_(iova-mode)                                    \
_(base-virtaddr)
/* clang-format on */

static_always_inline void
dpdk_device_flag_set (dpdk_device_t *xd, __typeof__ (xd->flags) flag, int val)
{
  xd->flags = val ? xd->flags | flag : xd->flags & ~flag;
}

static inline void
dpdk_get_xstats (dpdk_device_t * xd)
{
  int len, ret;

  if (!(xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP))
    return;

  len = rte_eth_xstats_get (xd->port_id, NULL, 0);
  if (len < 0)
    return;

  vec_validate (xd->xstats, len - 1);

  ret = rte_eth_xstats_get (xd->port_id, xd->xstats, len);
  if (ret < 0 || ret > len)
    {
      vec_set_len (xd->xstats, 0);
      return;
    }

  vec_set_len (xd->xstats, len);
}

#define DPDK_UPDATE_COUNTER(vnm, tidx, xd, stat, cnt)                         \
  do                                                                          \
    {                                                                         \
      u64 _v = (xd)->stats.stat;                                              \
      u64 _lv = (xd)->last_stats.stat;                                        \
      if (PREDICT_FALSE (_v != _lv))                                          \
        {                                                                     \
          if (PREDICT_FALSE (_v < _lv))                                       \
            dpdk_log_warn ("%v: %s counter decreased (before %lu after %lu)", \
                           xd->name, #stat, _lv, _v);                         \
          else                                                                \
            vlib_increment_simple_counter (                                   \
                vec_elt_at_index ((vnm)->interface_main.sw_if_counters, cnt), \
                (tidx), (xd)->sw_if_index, _v - _lv);                         \
        }                                                                     \
    }                                                                         \
  while (0)

static inline void
dpdk_update_counters (dpdk_device_t * xd, f64 now)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 thread_index = vlib_get_thread_index ();

  xd->time_last_stats_update = now ? now : xd->time_last_stats_update;
  clib_memcpy_fast (&xd->last_stats, &xd->stats, sizeof (xd->last_stats));
  rte_eth_stats_get (xd->port_id, &xd->stats);

  /* maybe bump interface rx no buffer counter */
  DPDK_UPDATE_COUNTER (vnm, thread_index, xd, rx_nombuf,
		       VNET_INTERFACE_COUNTER_RX_NO_BUF);
  DPDK_UPDATE_COUNTER (vnm, thread_index, xd, imissed,
		       VNET_INTERFACE_COUNTER_RX_MISS);
  DPDK_UPDATE_COUNTER (vnm, thread_index, xd, ierrors,
		       VNET_INTERFACE_COUNTER_RX_ERROR);

  dpdk_get_xstats (xd);
}

#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
#define RTE_MBUF_F_RX_FDIR		  PKT_RX_FDIR
#define RTE_MBUF_F_RX_FDIR_FLX		  PKT_RX_FDIR_FLX
#define RTE_MBUF_F_RX_FDIR_ID		  PKT_RX_FDIR_ID
#define RTE_MBUF_F_RX_IEEE1588_PTP	  PKT_RX_IEEE1588_PTP
#define RTE_MBUF_F_RX_IEEE1588_TMST	  PKT_RX_IEEE1588_TMST
#define RTE_MBUF_F_RX_IP_CKSUM_BAD	  PKT_RX_IP_CKSUM_BAD
#define RTE_MBUF_F_RX_IP_CKSUM_GOOD	  PKT_RX_IP_CKSUM_GOOD
#define RTE_MBUF_F_RX_IP_CKSUM_NONE	  PKT_RX_IP_CKSUM_GOOD
#define RTE_MBUF_F_RX_L4_CKSUM_BAD	  PKT_RX_L4_CKSUM_BAD
#define RTE_MBUF_F_RX_L4_CKSUM_GOOD	  PKT_RX_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_L4_CKSUM_NONE	  PKT_RX_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_LRO		  PKT_RX_LRO
#define RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD  PKT_RX_OUTER_IP_CKSUM_BAD
#define RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD  PKT_RX_OUTER_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD PKT_RX_OUTER_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_OUTER_L4_CKSUM_NONE PKT_RX_OUTER_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_QINQ		  PKT_RX_QINQ
#define RTE_MBUF_F_RX_QINQ_STRIPPED	  PKT_RX_QINQ_STRIPPED
#define RTE_MBUF_F_RX_RSS_HASH		  PKT_RX_RSS_HASH
#define RTE_MBUF_F_RX_SEC_OFFLOAD	  PKT_RX_SEC_OFFLOAD
#define RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED  PKT_RX_SEC_OFFLOAD_FAILED
#define RTE_MBUF_F_RX_VLAN		  PKT_RX_VLAN
#define RTE_MBUF_F_RX_VLAN_STRIPPED	  PKT_RX_VLAN_STRIPPED
#define RTE_MBUF_F_TX_IEEE1588_TMST	  PKT_TX_IEEE1588_TMST
#define RTE_MBUF_F_TX_IPV4		  PKT_TX_IPV4
#define RTE_MBUF_F_TX_IPV6		  PKT_TX_IPV6
#define RTE_MBUF_F_TX_IP_CKSUM		  PKT_TX_IP_CKSUM
#define RTE_MBUF_F_TX_MACSEC		  PKT_TX_MACSEC
#define RTE_MBUF_F_TX_OUTER_IPV4	  PKT_TX_OUTER_IPV4
#define RTE_MBUF_F_TX_OUTER_IPV6	  PKT_TX_OUTER_IPV6
#define RTE_MBUF_F_TX_OUTER_IP_CKSUM	  PKT_TX_OUTER_IP_CKSUM
#define RTE_MBUF_F_TX_OUTER_UDP_CKSUM	  PKT_TX_OUTER_UDP_CKSUM
#define RTE_MBUF_F_TX_QINQ		  PKT_TX_QINQ
#define RTE_MBUF_F_TX_SCTP_CKSUM	  PKT_TX_SCTP_CKSUM
#define RTE_MBUF_F_TX_SEC_OFFLOAD	  PKT_TX_SEC_OFFLOAD
#define RTE_MBUF_F_TX_TCP_CKSUM		  PKT_TX_TCP_CKSUM
#define RTE_MBUF_F_TX_TCP_SEG		  PKT_TX_TCP_SEG
#define RTE_MBUF_F_TX_TUNNEL_GENEVE	  PKT_TX_TUNNEL_GENEVE
#define RTE_MBUF_F_TX_TUNNEL_GRE	  PKT_TX_TUNNEL_GRE
#define RTE_MBUF_F_TX_TUNNEL_GTP	  PKT_TX_TUNNEL_GTP
#define RTE_MBUF_F_TX_TUNNEL_IP		  PKT_TX_TUNNEL_IP
#define RTE_MBUF_F_TX_TUNNEL_IPIP	  PKT_TX_TUNNEL_IPIP
#define RTE_MBUF_F_TX_TUNNEL_MPLSINUDP	  PKT_TX_TUNNEL_MPLSINUDP
#define RTE_MBUF_F_TX_TUNNEL_UDP	  PKT_TX_TUNNEL_UDP
#define RTE_MBUF_F_TX_TUNNEL_VXLAN	  PKT_TX_TUNNEL_VXLAN
#define RTE_MBUF_F_TX_TUNNEL_VXLAN_GPE	  PKT_TX_TUNNEL_VXLAN_GPE
#define RTE_MBUF_F_TX_UDP_CKSUM		  PKT_TX_UDP_CKSUM
#define RTE_MBUF_F_TX_UDP_SEG		  PKT_TX_UDP_SEG
#define RTE_MBUF_F_TX_VLAN		  PKT_TX_VLAN
#define RTE_ETH_RSS_FRAG_IPV4		    ETH_RSS_FRAG_IPV4
#define RTE_ETH_RSS_NONFRAG_IPV4_TCP	    ETH_RSS_NONFRAG_IPV4_TCP
#define RTE_ETH_RSS_NONFRAG_IPV4_UDP	    ETH_RSS_NONFRAG_IPV4_UDP
#define RTE_ETH_RSS_NONFRAG_IPV4_SCTP	    ETH_RSS_NONFRAG_IPV4_SCTP
#define RTE_ETH_RSS_NONFRAG_IPV4_OTHER	    ETH_RSS_NONFRAG_IPV4_OTHER
#define RTE_ETH_RSS_IPV4		    ETH_RSS_IPV4
#define RTE_ETH_RSS_IPV6_TCP_EX		    ETH_RSS_IPV6_TCP_EX
#define RTE_ETH_RSS_IPV6_UDP_EX		    ETH_RSS_IPV6_UDP_EX
#define RTE_ETH_RSS_FRAG_IPV6		    ETH_RSS_FRAG_IPV6
#define RTE_ETH_RSS_NONFRAG_IPV6_TCP	    ETH_RSS_NONFRAG_IPV6_TCP
#define RTE_ETH_RSS_NONFRAG_IPV6_UDP	    ETH_RSS_NONFRAG_IPV6_UDP
#define RTE_ETH_RSS_NONFRAG_IPV6_SCTP	    ETH_RSS_NONFRAG_IPV6_SCTP
#define RTE_ETH_RSS_NONFRAG_IPV6_OTHER	    ETH_RSS_NONFRAG_IPV6_OTHER
#define RTE_ETH_RSS_IPV6_EX		    ETH_RSS_IPV6_EX
#define RTE_ETH_RSS_IPV6		    ETH_RSS_IPV6
#define RTE_ETH_RSS_L2_PAYLOAD		    ETH_RSS_L2_PAYLOAD
#define RTE_ETH_RSS_PORT		    ETH_RSS_PORT
#define RTE_ETH_RSS_VXLAN		    ETH_RSS_VXLAN
#define RTE_ETH_RSS_GENEVE		    ETH_RSS_GENEVE
#define RTE_ETH_RSS_NVGRE		    ETH_RSS_NVGRE
#define RTE_ETH_RSS_GTPU		    ETH_RSS_GTPU
#define RTE_ETH_RSS_ESP			    ETH_RSS_ESP
#define RTE_ETH_RSS_L4_DST_ONLY		    ETH_RSS_L4_DST_ONLY
#define RTE_ETH_RSS_L4_SRC_ONLY		    ETH_RSS_L4_SRC_ONLY
#define RTE_ETH_RSS_L3_DST_ONL		    ETH_RSS_L3_DST_ONL
#define RTE_ETH_RSS_L3_SRC_ONLY		    ETH_RSS_L3_SRC_ONLY
#define RTE_ETH_RETA_GROUP_SIZE		    RTE_RETA_GROUP_SIZE
#define RTE_ETH_TX_OFFLOAD_IPV4_CKSUM	    DEV_TX_OFFLOAD_IPV4_CKSUM
#define RTE_ETH_TX_OFFLOAD_TCP_CKSUM	    DEV_TX_OFFLOAD_TCP_CKSUM
#define RTE_ETH_TX_OFFLOAD_UDP_CKSUM	    DEV_TX_OFFLOAD_UDP_CKSUM
#define RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM
#define RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM  DEV_TX_OFFLOAD_OUTER_UDP_CKSUM
#define RTE_ETH_TX_OFFLOAD_TCP_TSO	    DEV_TX_OFFLOAD_TCP_TSO
#define RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO    DEV_TX_OFFLOAD_VXLAN_TNL_TSO
#define RTE_ETH_TX_OFFLOAD_MULTI_SEGS	    DEV_TX_OFFLOAD_MULTI_SEGS
#define RTE_ETH_RX_OFFLOAD_IPV4_CKSUM	    DEV_RX_OFFLOAD_IPV4_CKSUM
#define RTE_ETH_RX_OFFLOAD_SCATTER	    DEV_RX_OFFLOAD_SCATTER
#define RTE_ETH_RX_OFFLOAD_TCP_LRO	    DEV_RX_OFFLOAD_TCP_LRO
#define RTE_ETH_MQ_RX_RSS		    ETH_MQ_RX_RSS
#define RTE_ETH_RX_OFFLOAD_TCP_CKSUM	    DEV_RX_OFFLOAD_TCP_CKSUM
#define RTE_ETH_RX_OFFLOAD_UDP_CKSUM	    DEV_RX_OFFLOAD_UDP_CKSUM
#define RTE_ETH_MQ_RX_NONE		    ETH_MQ_RX_NONE
#define RTE_ETH_LINK_FULL_DUPLEX	    ETH_LINK_FULL_DUPLEX
#define RTE_ETH_LINK_HALF_DUPLEX	    ETH_LINK_HALF_DUPLEX
#define RTE_ETH_VLAN_STRIP_OFFLOAD	    ETH_VLAN_STRIP_OFFLOAD
#define RTE_ETH_VLAN_FILTER_OFFLOAD	    ETH_VLAN_FILTER_OFFLOAD
#define RTE_ETH_VLAN_EXTEND_OFFLOAD	    ETH_VLAN_EXTEND_OFFLOAD
#define RTE_ETH_LINK_SPEED_200G		    ETH_LINK_SPEED_200G
#define RTE_ETH_LINK_SPEED_100G		    ETH_LINK_SPEED_100G
#define RTE_ETH_LINK_SPEED_56G		    ETH_LINK_SPEED_56G
#define RTE_ETH_LINK_SPEED_50G		    ETH_LINK_SPEED_50G
#define RTE_ETH_LINK_SPEED_40G		    ETH_LINK_SPEED_40G
#define RTE_ETH_LINK_SPEED_25G		    ETH_LINK_SPEED_25G
#define RTE_ETH_LINK_SPEED_20G		    ETH_LINK_SPEED_20G
#define RTE_ETH_LINK_SPEED_10G		    ETH_LINK_SPEED_10G
#define RTE_ETH_LINK_SPEED_5G		    ETH_LINK_SPEED_5G
#define RTE_ETH_LINK_SPEED_2_5G		    ETH_LINK_SPEED_2_5G
#define RTE_ETH_LINK_SPEED_1G		    ETH_LINK_SPEED_1G
#define RTE_ETH_RSS_IP			    ETH_RSS_IP
#define RTE_ETH_RSS_UDP			    ETH_RSS_UDP
#define RTE_ETH_RSS_TCP			    ETH_RSS_TCP
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
