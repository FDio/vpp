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

#define DPDK_NB_RX_DESC_DEFAULT   512
#define DPDK_NB_TX_DESC_DEFAULT   512
#define DPDK_NB_RX_DESC_VIRTIO    256
#define DPDK_NB_TX_DESC_VIRTIO    256
#define DPDK_NB_RX_DESC_10GE    2048
#define DPDK_NB_TX_DESC_10GE    2048
#define DPDK_NB_RX_DESC_40GE    (4096-128)
#define DPDK_NB_TX_DESC_40GE    2048

#if RTE_VERSION >= RTE_VERSION_NUM(2, 2, 0, 0)
#define foreach_dpdk_counter                    \
  _ (tx_frames_ok, opackets)                    \
  _ (tx_bytes_ok, obytes)                       \
  _ (tx_errors, oerrors)                        \
  _ (tx_loopback_frames_ok, olbpackets)         \
  _ (tx_loopback_bytes_ok, olbbytes)            \
  _ (rx_frames_ok, ipackets)                    \
  _ (rx_bytes_ok, ibytes)                       \
  _ (rx_errors, ierrors)                        \
  _ (rx_missed, imissed)                        \
  _ (rx_multicast_frames_ok, imcasts)           \
  _ (rx_no_bufs, rx_nombuf)                     \
  _ (rx_loopback_frames_ok, ilbpackets)         \
  _ (rx_loopback_bytes_ok, ilbbytes)
#else
#define foreach_dpdk_counter                    \
  _ (tx_frames_ok, opackets)                    \
  _ (tx_bytes_ok, obytes)                       \
  _ (tx_errors, oerrors)                        \
  _ (tx_loopback_frames_ok, olbpackets)         \
  _ (tx_loopback_bytes_ok, olbbytes)            \
  _ (rx_frames_ok, ipackets)                    \
  _ (rx_bytes_ok, ibytes)                       \
  _ (rx_errors, ierrors)                        \
  _ (rx_missed, imissed)                        \
  _ (rx_bad_crc, ibadcrc)                       \
  _ (rx_bad_length, ibadlen)                    \
  _ (rx_multicast_frames_ok, imcasts)           \
  _ (rx_no_bufs, rx_nombuf)                     \
  _ (rx_filter_match, fdirmatch)                \
  _ (rx_filter_miss, fdirmiss)                  \
  _ (tx_pause_xon, tx_pause_xon)                \
  _ (rx_pause_xon, rx_pause_xon)                \
  _ (tx_pause_xoff, tx_pause_xoff)              \
  _ (rx_pause_xoff, rx_pause_xoff)              \
  _ (rx_loopback_frames_ok, ilbpackets)         \
  _ (rx_loopback_bytes_ok, ilbbytes)
#endif

#define foreach_dpdk_q_counter                  \
  _ (rx_frames_ok, q_ipackets)                  \
  _ (tx_frames_ok, q_opackets)                  \
  _ (rx_bytes_ok, q_ibytes)                     \
  _ (tx_bytes_ok, q_obytes)                     \
  _ (rx_errors, q_errors)

#define foreach_dpdk_rss_hf                    \
  _(ETH_RSS_IPV4,               "ipv4")        \
  _(ETH_RSS_FRAG_IPV4,          "ipv4-frag")   \
  _(ETH_RSS_NONFRAG_IPV4_TCP,   "ipv4-tcp")    \
  _(ETH_RSS_NONFRAG_IPV4_UDP,   "ipv4-udp")    \
  _(ETH_RSS_NONFRAG_IPV4_SCTP,  "ipv4-sctp")   \
  _(ETH_RSS_NONFRAG_IPV4_OTHER, "ipv4-other")  \
  _(ETH_RSS_IPV6,               "ipv6")        \
  _(ETH_RSS_FRAG_IPV6,          "ipv6-frag")   \
  _(ETH_RSS_NONFRAG_IPV6_TCP,   "ipv6-tcp")    \
  _(ETH_RSS_NONFRAG_IPV6_UDP,   "ipv6-udp")    \
  _(ETH_RSS_NONFRAG_IPV6_SCTP,  "ipv6-sctp")   \
  _(ETH_RSS_NONFRAG_IPV6_OTHER, "ipv6-other")  \
  _(ETH_RSS_L2_PAYLOAD,         "l2-payload")  \
  _(ETH_RSS_IPV6_EX,            "ipv6-ex")     \
  _(ETH_RSS_IPV6_TCP_EX,        "ipv6-tcp-ex") \
  _(ETH_RSS_IPV6_UDP_EX,        "ipv6-udp-ex")

#define foreach_dpdk_rx_offload_caps            \
  _(DEV_RX_OFFLOAD_VLAN_STRIP, "vlan-strip")    \
  _(DEV_RX_OFFLOAD_IPV4_CKSUM, "ipv4-cksum")    \
  _(DEV_RX_OFFLOAD_UDP_CKSUM , "udp-cksum")     \
  _(DEV_RX_OFFLOAD_TCP_CKSUM , "tcp-cksum")     \
  _(DEV_RX_OFFLOAD_TCP_LRO   , "rcp-lro")       \
  _(DEV_RX_OFFLOAD_QINQ_STRIP, "qinq-strip")

#define foreach_dpdk_tx_offload_caps           \
  _(DEV_TX_OFFLOAD_VLAN_INSERT, "vlan-insert") \
  _(DEV_TX_OFFLOAD_IPV4_CKSUM,  "ipv4-cksum")  \
  _(DEV_TX_OFFLOAD_UDP_CKSUM  , "udp-cksum")   \
  _(DEV_TX_OFFLOAD_TCP_CKSUM  , "tcp-cksum")   \
  _(DEV_TX_OFFLOAD_SCTP_CKSUM , "sctp-cksum")  \
  _(DEV_TX_OFFLOAD_TCP_TSO    , "tcp-tso")     \
  _(DEV_TX_OFFLOAD_UDP_TSO    , "udp-tso")     \
  _(DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM, "outer-ipv4-cksum") \
  _(DEV_TX_OFFLOAD_QINQ_INSERT, "qinq-insert")

#if RTE_VERSION >= RTE_VERSION_NUM(2, 1, 0, 0)

#define foreach_dpdk_pkt_rx_offload_flag                                \
  _ (PKT_RX_VLAN_PKT, "RX packet is a 802.1q VLAN packet")              \
  _ (PKT_RX_RSS_HASH, "RX packet with RSS hash result")                 \
  _ (PKT_RX_FDIR, "RX packet with FDIR infos")                          \
  _ (PKT_RX_L4_CKSUM_BAD, "L4 cksum of RX pkt. is not OK")              \
  _ (PKT_RX_IP_CKSUM_BAD, "IP cksum of RX pkt. is not OK")              \
  _ (PKT_RX_IEEE1588_PTP, "RX IEEE1588 L2 Ethernet PT Packet")          \
  _ (PKT_RX_IEEE1588_TMST, "RX IEEE1588 L2/L4 timestamped packet")

#define foreach_dpdk_pkt_type                                   \
  _ (RTE_PTYPE_L3_IPV4, "Packet with IPv4 header")              \
  _ (RTE_PTYPE_L3_IPV4_EXT, "Packet with extended IPv4 header") \
  _ (RTE_PTYPE_L3_IPV6, "Packet with IPv6 header")              \
  _ (RTE_PTYPE_L3_IPV6_EXT, "Packet with extended IPv6 header")
#else
#define foreach_dpdk_pkt_rx_offload_flag                                \
  _ (PKT_RX_VLAN_PKT, "RX packet is a 802.1q VLAN packet")              \
  _ (PKT_RX_RSS_HASH, "RX packet with RSS hash result")                 \
  _ (PKT_RX_FDIR, "RX packet with FDIR infos")                          \
  _ (PKT_RX_L4_CKSUM_BAD, "L4 cksum of RX pkt. is not OK")              \
  _ (PKT_RX_IP_CKSUM_BAD, "IP cksum of RX pkt. is not OK")              \
  _ (PKT_RX_IPV4_HDR, "RX packet with IPv4 header")                     \
  _ (PKT_RX_IPV4_HDR_EXT, "RX packet with extended IPv4 header")        \
  _ (PKT_RX_IPV6_HDR, "RX packet with IPv6 header")                     \
  _ (PKT_RX_IPV6_HDR_EXT, "RX packet with extended IPv6 header")        \
  _ (PKT_RX_IEEE1588_PTP, "RX IEEE1588 L2 Ethernet PT Packet")          \
  _ (PKT_RX_IEEE1588_TMST, "RX IEEE1588 L2/L4 timestamped packet")

#define foreach_dpdk_pkt_type /* Dummy */
#endif /* RTE_VERSION */

#define foreach_dpdk_pkt_tx_offload_flag                                \
  _ (PKT_TX_VLAN_PKT, "TX packet is a 802.1q VLAN packet")              \
  _ (PKT_TX_IP_CKSUM, "IP cksum of TX pkt. computed by NIC")            \
  _ (PKT_TX_TCP_CKSUM, "TCP cksum of TX pkt. computed by NIC")          \
  _ (PKT_TX_SCTP_CKSUM, "SCTP cksum of TX pkt. computed by NIC")        \
  _ (PKT_TX_IEEE1588_TMST, "TX IEEE1588 packet to timestamp")

#define foreach_dpdk_pkt_offload_flag           \
  foreach_dpdk_pkt_rx_offload_flag              \
  foreach_dpdk_pkt_tx_offload_flag

static inline u8 * format_dpdk_pkt_types (u8 * s, va_list * va)
{
  u32 *pkt_types = va_arg (*va, u32 *);
  uword indent __attribute__((unused)) = format_get_indent (s) + 2;

  if (!*pkt_types)
    return s;

  s = format (s, "Packet Types");

#define _(F, S)             \
  if (*pkt_types & F)           \
    {               \
      s = format (s, "\n%U%s (0x%04x) %s",      \
      format_white_space, indent, #F, F, S);  \
    }
  
  foreach_dpdk_pkt_type

#undef _

  return s;
}

static inline u8 * format_dpdk_pkt_offload_flags (u8 * s, va_list * va)
{
  u16 *ol_flags = va_arg (*va, u16 *);
  uword indent = format_get_indent (s) + 2;

  if (!*ol_flags)
    return s;

  s = format (s, "Packet Offload Flags");

#define _(F, S)             \
  if (*ol_flags & F)            \
    {               \
      s = format (s, "\n%U%s (0x%04x) %s",      \
      format_white_space, indent, #F, F, S);  \
    }
  
  foreach_dpdk_pkt_offload_flag

#undef _

  return s;
}

static inline u8 * format_dpdk_rte_mbuf (u8 * s, va_list * va)
{
  struct rte_mbuf * mb = va_arg (*va, struct rte_mbuf *);
  uword indent = format_get_indent (s) + 2;

  s = format (s, "PKT MBUF: port %d, nb_segs %d, pkt_len %d"
              "\n%Ubuf_len %d, data_len %d, ol_flags 0x%x,"
              "\n%Upacket_type 0x%x",
              mb->port, mb->nb_segs, mb->pkt_len,
              format_white_space, indent, 
              mb->buf_len, mb->data_len, mb->ol_flags,
              format_white_space, indent, 
              mb->packet_type);

  if (mb->ol_flags)
    s = format (s, "\n%U%U", format_white_space, indent,
                format_dpdk_pkt_offload_flags, &mb->ol_flags);

  if (mb->packet_type)
    s = format (s, "\n%U%U", format_white_space, indent,
                format_dpdk_pkt_types, &mb->packet_type);
  return s;
}

#ifdef RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS
#define foreach_dpdk_pkt_ext_rx_offload_flag                    \
  _ (PKT_EXT_RX_PKT_ERROR, "RX Packet Error")                   \
  _ (PKT_EXT_RX_BAD_FCS, "RX Bad FCS checksum")                 \
  _ (PKT_EXT_RX_UDP, "RX packet with UDP L4 header")            \
  _ (PKT_EXT_RX_TCP, "RX packet with TCP L4 header")            \
  _ (PKT_EXT_RX_IPV4_FRAGMENT, "RX packet IPv4 Fragment")

#define foreach_dpdk_pkt_ext_offload_flag \
  foreach_dpdk_pkt_rx_offload_flag    \
  foreach_dpdk_pkt_ext_rx_offload_flag

static inline u8 * format_dpdk_pkt_rx_offload_flags (u8 * s, va_list * va)
{
  u16 *ol_flags = va_arg (*va, u16 *);
  uword indent = format_get_indent (s) + 2;

  if (!*ol_flags)
    return s;

  s = format (s, "Packet RX Offload Flags");

#define _(F, S)             \
  if (*ol_flags & F)            \
    {               \
      s = format (s, "\n%U%s (0x%04x) %s",      \
      format_white_space, indent, #F, F, S);  \
    }
  
  foreach_dpdk_pkt_ext_offload_flag

#undef _

  return s;
}

static inline u8 * format_dpdk_rx_rte_mbuf (u8 * s, va_list * va)
{
  struct rte_mbuf * mb = va_arg (*va, struct rte_mbuf *);
  uword indent = format_get_indent (s) + 2;

  /*
   * Note: Assumes mb is head of pkt chain -- port, nb_segs, & pkt_len
   *       are only valid for the 1st mbuf segment.
   */
  s = format (s, "PKT MBUF: port %d, nb_segs %d, pkt_len %d"
              "\n%Ubuf_len %d, data_len %d, ol_flags 0x%x"
              "\n%Upacket_type 0x%x",
              mb->port, mb->nb_segs, mb->pkt_len,
              format_white_space, indent,
              mb->buf_len, mb->data_len, mb->ol_flags,
              format_white_space, indent,
              mb->packet_type);

  if (mb->ol_flags)
    s = format (s, "\n%U%U", format_white_space, indent,
                format_dpdk_pkt_rx_offload_flags, &mb->ol_flags);

  if (mb->packet_type)
    s = format (s, "\n%U%U", format_white_space, indent,
                format_dpdk_pkt_types, &mb->packet_type);
  return s;
}
#endif /* RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS */

/* These args appear by themselves */
#define foreach_eal_double_hyphen_predicate_arg \
_(no-shconf)                                    \
_(no-hpet)                                      \
_(no-pci)                                       \
_(no-huge)                                      \
_(vmware-tsc-map)                               \
_(virtio-vhost)

#define foreach_eal_single_hyphen_mandatory_arg \
_(coremask, c)                                  \
_(nchannels, n)                                 \

#define foreach_eal_single_hyphen_arg           \
_(blacklist, b)                                 \
_(mem-alloc-request, m)                         \
_(force-ranks, r)

/* These args are preceeded by "--" and followed by a single string */
#define foreach_eal_double_hyphen_arg           \
_(huge-dir)                                     \
_(proc-type)                                    \
_(file-prefix)                                  \
_(socket-mem)                                   \
_(vdev)

static inline u32
dpdk_rx_burst ( dpdk_main_t * dm, dpdk_device_t * xd, u16 queue_id)
{
  u32 n_buffers;
  u32 n_left;
  u32 n_this_chunk;

  n_left = VLIB_FRAME_SIZE;
  n_buffers = 0;

  if (PREDICT_TRUE(xd->dev_type == VNET_DPDK_DEV_ETH))
    {
      while (n_left)
        {
          n_this_chunk = rte_eth_rx_burst (xd->device_index, queue_id,
                                           xd->rx_vectors[queue_id] + n_buffers, n_left);
          n_buffers += n_this_chunk;
          n_left -= n_this_chunk;

          /* Empirically, DPDK r1.8 produces vectors w/ 32 or fewer elts */
          if (n_this_chunk < 32)
            break;
      }
    }
  else if (xd->dev_type == VNET_DPDK_DEV_VHOST_USER)
    {
      vlib_main_t * vm = vlib_get_main();
      vlib_buffer_main_t * bm = vm->buffer_main;
      unsigned socket_id = rte_socket_id();

      if (PREDICT_FALSE(!xd->vu_is_running))
        return 0;

      n_buffers = rte_vhost_dequeue_burst(&xd->vu_vhost_dev, VIRTIO_TXQ,
                                          bm->pktmbuf_pools[socket_id],
                                          xd->rx_vectors[queue_id], VLIB_FRAME_SIZE);

      f64 now = vlib_time_now (vm);

      /* send pending interrupts if needed */
      if (dpdk_vhost_user_want_interrupt(xd, VIRTIO_TXQ)) {
          dpdk_vu_vring *vring = &(xd->vu_intf->vrings[VIRTIO_TXQ]);
          vring->n_since_last_int += n_buffers;

          if ((vring->n_since_last_int && (vring->int_deadline < now))
              || (vring->n_since_last_int > dm->vhost_coalesce_frames))
            dpdk_vhost_user_send_interrupt(vm, xd, VIRTIO_TXQ);
      }

      if (dpdk_vhost_user_want_interrupt(xd, VIRTIO_RXQ)) {
          dpdk_vu_vring *vring = &(xd->vu_intf->vrings[VIRTIO_RXQ]);
          if (vring->n_since_last_int && (vring->int_deadline < now))
            dpdk_vhost_user_send_interrupt(vm, xd, VIRTIO_RXQ);
      }

    }
  else if (xd->dev_type == VNET_DPDK_DEV_KNI)
    {
      n_buffers = rte_kni_rx_burst(xd->kni, xd->rx_vectors[queue_id], VLIB_FRAME_SIZE);
      rte_kni_handle_request(xd->kni);
    }
  else
    {
      ASSERT(0);
    }

  return n_buffers;
}


static inline void
dpdk_update_counters (dpdk_device_t * xd, f64 now)
{
  vlib_simple_counter_main_t * cm;
  vnet_main_t * vnm = vnet_get_main();
  u32 my_cpu = os_get_cpu_number();
  u64 rxerrors, last_rxerrors;
  int len;

  /* only update counters for PMD interfaces */
  if (xd->dev_type != VNET_DPDK_DEV_ETH)
    return;

  /*
   * DAW-FIXME: VMXNET3 device stop/start doesn't work,
   * therefore fake the stop in the dpdk driver by
   * silently dropping all of the incoming pkts instead of
   * stopping the driver / hardware.
   */
  if (xd->admin_up != 0xff)
    {
      xd->time_last_stats_update = now ? now : xd->time_last_stats_update;
      memcpy (&xd->last_stats, &xd->stats, sizeof (xd->last_stats));
      rte_eth_stats_get (xd->device_index, &xd->stats);

      /* maybe bump interface rx no buffer counter */
      if (PREDICT_FALSE (xd->stats.rx_nombuf != xd->last_stats.rx_nombuf))
        {
          cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
                                 VNET_INTERFACE_COUNTER_RX_NO_BUF);

          vlib_increment_simple_counter (cm, my_cpu, xd->vlib_sw_if_index,
                                         xd->stats.rx_nombuf -
                                         xd->last_stats.rx_nombuf);
        }

      /* missed pkt counter */
      if (PREDICT_FALSE (xd->stats.imissed != xd->last_stats.imissed))
        {
          cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
                                 VNET_INTERFACE_COUNTER_RX_MISS);

          vlib_increment_simple_counter (cm, my_cpu, xd->vlib_sw_if_index,
                                         xd->stats.imissed -
                                         xd->last_stats.imissed);
        }
#if RTE_VERSION >= RTE_VERSION_NUM(2, 2, 0, 0)
      rxerrors = xd->stats.ierrors;
      last_rxerrors = xd->last_stats.ierrors;
#else
      rxerrors = xd->stats.ibadcrc
        + xd->stats.ibadlen + xd->stats.ierrors;
      last_rxerrors = xd->last_stats.ibadcrc
        + xd->last_stats.ibadlen + xd->last_stats.ierrors;
#endif

      if (PREDICT_FALSE (rxerrors != last_rxerrors))
        {
          cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
                                 VNET_INTERFACE_COUNTER_RX_ERROR);

          vlib_increment_simple_counter (cm, my_cpu, xd->vlib_sw_if_index,
                                         rxerrors - last_rxerrors);
        }
    }

  if ((len = rte_eth_xstats_get(xd->device_index, NULL, 0)) > 0)
    {
      vec_validate(xd->xstats, len - 1);
      len = rte_eth_xstats_get(xd->device_index, xd->xstats, vec_len(xd->xstats));
      ASSERT(vec_len(xd->xstats) == len);
      _vec_len(xd->xstats) = len;
    }
}
