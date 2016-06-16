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
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vlib/unix/cj.h>
#include <assert.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/dpdk/dpdk.h>

#include "dpdk_priv.h"
#include <vppinfra/error.h>

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
  _(ETH_RSS_FRAG_IPV4,          "ipv4-frag")   \
  _(ETH_RSS_NONFRAG_IPV4_TCP,   "ipv4-tcp")    \
  _(ETH_RSS_NONFRAG_IPV4_UDP,   "ipv4-udp")    \
  _(ETH_RSS_NONFRAG_IPV4_SCTP,  "ipv4-sctp")   \
  _(ETH_RSS_NONFRAG_IPV4_OTHER, "ipv4-other")  \
  _(ETH_RSS_IPV4,               "ipv4")        \
  _(ETH_RSS_IPV6_TCP_EX,        "ipv6-tcp-ex") \
  _(ETH_RSS_IPV6_UDP_EX,        "ipv6-udp-ex") \
  _(ETH_RSS_FRAG_IPV6,          "ipv6-frag")   \
  _(ETH_RSS_NONFRAG_IPV6_TCP,   "ipv6-tcp")    \
  _(ETH_RSS_NONFRAG_IPV6_UDP,   "ipv6-udp")    \
  _(ETH_RSS_NONFRAG_IPV6_SCTP,  "ipv6-sctp")   \
  _(ETH_RSS_NONFRAG_IPV6_OTHER, "ipv6-other")  \
  _(ETH_RSS_L2_PAYLOAD,         "l2-payload")  \
  _(ETH_RSS_IPV6_EX,            "ipv6-ex")     \
  _(ETH_RSS_IPV6,               "ipv6")


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

#define foreach_dpdk_pkt_type                                           \
  _ (L2, ETHER, "Ethernet packet")                                      \
  _ (L2, ETHER_TIMESYNC, "Ethernet packet for time sync")               \
  _ (L2, ETHER_ARP, "ARP packet")                                       \
  _ (L2, ETHER_LLDP, "LLDP (Link Layer Discovery Protocol) packet")     \
  _ (L3, IPV4, "IPv4 packet without extension headers")                 \
  _ (L3, IPV4_EXT, "IPv4 packet with extension headers")                \
  _ (L3, IPV4_EXT_UNKNOWN, "IPv4 packet with or without extension headers") \
  _ (L3, IPV6, "IPv6 packet without extension headers")                 \
  _ (L3, IPV6_EXT, "IPv6 packet with extension headers")                \
  _ (L3, IPV6_EXT_UNKNOWN, "IPv6 packet with or without extension headers") \
  _ (L4, TCP, "TCP packet")                                             \
  _ (L4, UDP, "UDP packet")                                             \
  _ (L4, FRAG, "Fragmented IP packet")                                  \
  _ (L4, SCTP, "SCTP (Stream Control Transmission Protocol) packet")    \
  _ (L4, ICMP, "ICMP packet")                                           \
  _ (L4, NONFRAG, "Non-fragmented IP packet")                           \
  _ (TUNNEL, GRE, "GRE tunneling packet")                               \
  _ (TUNNEL, VXLAN, "VXLAN tunneling packet")                           \
  _ (TUNNEL, NVGRE, "NVGRE Tunneling packet")                           \
  _ (TUNNEL, GENEVE, "GENEVE Tunneling packet")                         \
  _ (TUNNEL, GRENAT, "Teredo, VXLAN or GRE Tunneling packet")           \
  _ (INNER_L2, ETHER, "Inner Ethernet packet")                          \
  _ (INNER_L2, ETHER_VLAN, "Inner Ethernet packet with VLAN")           \
  _ (INNER_L3, IPV4, "Inner IPv4 packet without extension headers")     \
  _ (INNER_L3, IPV4_EXT, "Inner IPv4 packet with extension headers")    \
  _ (INNER_L3, IPV4_EXT_UNKNOWN, "Inner IPv4 packet with or without extension headers") \
  _ (INNER_L3, IPV6, "Inner IPv6 packet without extension headers")     \
  _ (INNER_L3, IPV6_EXT, "Inner IPv6 packet with extension headers")    \
  _ (INNER_L3, IPV6_EXT_UNKNOWN, "Inner IPv6 packet with or without extension headers") \
  _ (INNER_L4, TCP, "Inner TCP packet")                                 \
  _ (INNER_L4, UDP, "Inner UDP packet")                                 \
  _ (INNER_L4, FRAG, "Inner fagmented IP packet")                       \
  _ (INNER_L4, SCTP, "Inner SCTP (Stream Control Transmission Protocol) packet") \
  _ (INNER_L4, ICMP, "Inner ICMP packet")                               \
  _ (INNER_L4, NONFRAG, "Inner non-fragmented IP packet")

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

#endif /* RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS */

u8 * format_dpdk_device_name (u8 * s, va_list * args)
{
  dpdk_main_t * dm = &dpdk_main;
  char *devname_format;
  char *device_name;
  u32 i = va_arg (*args, u32);
  struct rte_eth_dev_info dev_info;
  u8 * ret;

  if (dm->conf->interface_name_format_decimal)
    devname_format = "%s%d/%d/%d";
  else
    devname_format = "%s%x/%x/%x";

#ifdef RTE_LIBRTE_KNI
  if (dm->devices[i].dev_type == VNET_DPDK_DEV_KNI) {
       return format(s, "kni%d", dm->devices[i].kni_port_id);
  } else
#endif
  if (dm->devices[i].dev_type == VNET_DPDK_DEV_VHOST_USER) {
       return format(s, "VirtualEthernet0/0/%d", dm->devices[i].vu_if_id);
  }
  switch (dm->devices[i].port_type)
    {
    case VNET_DPDK_PORT_TYPE_ETH_1G:
      device_name = "GigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_10G:
      device_name = "TenGigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_40G:
      device_name = "FortyGigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_BOND:
      return format(s, "BondEthernet%d", dm->devices[i].device_index);

    case VNET_DPDK_PORT_TYPE_ETH_SWITCH:
      device_name = "EthernetSwitch";
      break;

  #ifdef NETMAP
    case VNET_DPDK_PORT_TYPE_NETMAP:
	rte_eth_dev_info_get(i, &dev_info);
	return format(s, "netmap:%s", dev_info.driver_name);
  #endif

    case VNET_DPDK_PORT_TYPE_AF_PACKET:
      rte_eth_dev_info_get(i, &dev_info);
      return format(s, "af_packet%d", dm->devices[i].af_packet_port_id);

    default:
    case VNET_DPDK_PORT_TYPE_UNKNOWN:
      device_name = "UnknownEthernet";
      break;
    }

  rte_eth_dev_info_get(i, &dev_info);
  ret = format (s, devname_format, device_name, dev_info.pci_dev->addr.bus,
		 dev_info.pci_dev->addr.devid,
		 dev_info.pci_dev->addr.function);

  /* address Chelsio cards which share PCI address */
	if (dm->devices[i].pmd ==  VNET_DPDK_PMD_CXGBE) {
    struct rte_eth_dev_info di;

    di.pci_dev = 0;
    rte_eth_dev_info_get(i+1, &di);
    if (di.pci_dev && memcmp(&dev_info.pci_dev->addr, &di.pci_dev->addr,
        sizeof(struct rte_pci_addr)) == 0)
	    return format(ret, "/0");

    di.pci_dev = 0;
    rte_eth_dev_info_get(i-1, &di);
    if (di.pci_dev && memcmp(&dev_info.pci_dev->addr, &di.pci_dev->addr,
        sizeof(struct rte_pci_addr)) == 0)
	    return format(ret, "/1");
	}
  return ret;
}

static u8 * format_dpdk_device_type (u8 * s, va_list * args)
{
  dpdk_main_t * dm = &dpdk_main;
  char *dev_type;
  u32 i = va_arg (*args, u32);

  if (dm->devices[i].dev_type == VNET_DPDK_DEV_KNI) {
       return format(s, "Kernel NIC Interface");
  } else if (dm->devices[i].dev_type == VNET_DPDK_DEV_VHOST_USER) {
       return format(s, "vhost-user interface");
  }

  switch (dm->devices[i].pmd)
    {
    case VNET_DPDK_PMD_E1000EM:
	dev_type = "Intel 82540EM (e1000)";
	break;

    case VNET_DPDK_PMD_IGB:
	dev_type = "Intel e1000";
	break;

    case VNET_DPDK_PMD_I40E:
	dev_type = "Intel X710/XL710 Family";
	break;

    case VNET_DPDK_PMD_I40EVF:
	dev_type = "Intel X710/XL710 Family VF";
	break;

    case VNET_DPDK_PMD_FM10K:
	dev_type = "Intel FM10000 Family Ethernet Switch";
	break;

    case VNET_DPDK_PMD_IGBVF:
	dev_type = "Intel e1000 VF";
	break;

    case VNET_DPDK_PMD_VIRTIO:
	dev_type = "Red Hat Virtio";
	break;

    case VNET_DPDK_PMD_IXGBEVF:
	dev_type = "Intel 82599 VF";
	break;

    case VNET_DPDK_PMD_IXGBE:
	dev_type = "Intel 82599";
	break;

    case VNET_DPDK_PMD_VICE:
    case VNET_DPDK_PMD_ENIC:
	dev_type = "Cisco VIC";
	break;

    case VNET_DPDK_PMD_CXGBE:
	dev_type = "Chelsio T4/T5";
	break;

    case VNET_DPDK_PMD_VMXNET3:
	dev_type = "VMware VMXNET3";
	break;

#ifdef NETMAP
    case VNET_DPDK_PMD_NETMAP:
	dev_type = "Netmap/Vale";
	break;
#endif

    case VNET_DPDK_PMD_AF_PACKET:
	dev_type = "af_packet";
	break;

    case VNET_DPDK_PMD_BOND:
	dev_type = "Ethernet Bonding";
	break;

    default:
    case VNET_DPDK_PMD_UNKNOWN:
	dev_type = "### UNKNOWN ###";
	break;
    }

  return format (s, dev_type);
}

static u8 * format_dpdk_link_status (u8 * s, va_list * args)
{
  dpdk_device_t * xd = va_arg (*args, dpdk_device_t *);
  struct rte_eth_link * l = &xd->link;
  vnet_main_t * vnm = vnet_get_main();
  vnet_hw_interface_t * hi = vnet_get_hw_interface (vnm, xd->vlib_hw_if_index);

  s = format (s, "%s ", l->link_status ? "up" : "down");
  if (l->link_status)
    {
      u32 promisc = rte_eth_promiscuous_get (xd->device_index);

      s = format (s, "%s duplex ", (l->link_duplex == ETH_LINK_FULL_DUPLEX) ?
                  "full" : "half");
      s = format (s, "speed %u mtu %d %s\n", l->link_speed,
		  hi->max_packet_bytes, promisc ? " promisc" : "");
    }
  else
    s = format (s, "\n");

  return s;
}

#define _line_len 72
#define _(v, str)                                            \
if (bitmap & v) {                                            \
  if (format_get_indent (s) > next_split ) {                 \
    next_split += _line_len;                                 \
    s = format(s,"\n%U", format_white_space, indent);        \
  }                                                          \
  s = format(s, "%s ", str);                                 \
}

static u8 * format_dpdk_rss_hf_name(u8 * s, va_list * args)
{
  u64 bitmap = va_arg (*args, u64);
  int next_split = _line_len;
  int indent = format_get_indent (s);

  if (!bitmap)
    return format(s, "none");

  foreach_dpdk_rss_hf

  return s;
}

static u8 * format_dpdk_rx_offload_caps(u8 * s, va_list * args)
{
  u32 bitmap = va_arg (*args, u32);
  int next_split = _line_len;
  int indent = format_get_indent (s);

  if (!bitmap)
    return format(s, "none");

  foreach_dpdk_rx_offload_caps

  return s;
}

static u8 * format_dpdk_tx_offload_caps(u8 * s, va_list * args)
{
  u32 bitmap = va_arg (*args, u32);
  int next_split = _line_len;
  int indent = format_get_indent (s);
  if (!bitmap)
    return format(s, "none");

  foreach_dpdk_tx_offload_caps

  return s;
}

#undef _line_len
#undef _

u8 * format_dpdk_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd = vec_elt_at_index (dm->devices, dev_instance);
  uword indent = format_get_indent (s);
  f64 now = vlib_time_now (dm->vlib_main);
  struct rte_eth_dev_info di;

  dpdk_update_counters (xd, now);
  dpdk_update_link_state (xd, now);

  s = format (s, "%U\n%Ucarrier %U",
	      format_dpdk_device_type, xd->device_index,
	      format_white_space, indent + 2,
	      format_dpdk_link_status, xd);

  rte_eth_dev_info_get(xd->device_index, &di);

  if (verbose > 1 && xd->dev_type == VNET_DPDK_DEV_ETH)
    {
      struct rte_pci_device * pci;
      struct rte_eth_rss_conf rss_conf;
      int vlan_off;

      rss_conf.rss_key = 0;
      rte_eth_dev_rss_hash_conf_get(xd->device_index, &rss_conf);
      pci = di.pci_dev;

      if (pci)
        s = format(s, "%Upci id:            device %04x:%04x subsystem %04x:%04x\n"
                      "%Upci address:       %04x:%02x:%02x.%02x\n",
                   format_white_space, indent + 2,
                   pci->id.vendor_id, pci->id.device_id,
                   pci->id.subsystem_vendor_id,
                   pci->id.subsystem_device_id,
                   format_white_space, indent + 2,
                   pci->addr.domain, pci->addr.bus,
                   pci->addr.devid, pci->addr.function);
      s = format(s, "%Umax rx packet len: %d\n",
                 format_white_space, indent + 2, di.max_rx_pktlen);
      s = format(s, "%Umax num of queues: rx %d tx %d\n",
                 format_white_space, indent + 2, di.max_rx_queues, di.max_tx_queues);
      s = format(s, "%Upromiscuous:       unicast %s all-multicast %s\n",
                 format_white_space, indent + 2,
                 rte_eth_promiscuous_get(xd->device_index) ? "on" : "off",
                 rte_eth_promiscuous_get(xd->device_index) ? "on" : "off");
      vlan_off = rte_eth_dev_get_vlan_offload(xd->device_index);
      s = format(s, "%Uvlan offload:      strip %s filter %s qinq %s\n",
                 format_white_space, indent + 2,
                 vlan_off & ETH_VLAN_STRIP_OFFLOAD ? "on" : "off",
                 vlan_off & ETH_VLAN_FILTER_OFFLOAD ? "on" : "off",
                 vlan_off & ETH_VLAN_EXTEND_OFFLOAD ? "on" : "off");
      s = format(s, "%Urx offload caps:   %U\n",
                 format_white_space, indent + 2,
                 format_dpdk_rx_offload_caps, di.rx_offload_capa);
      s = format(s, "%Utx offload caps:   %U\n",
                 format_white_space, indent + 2,
                 format_dpdk_tx_offload_caps, di.tx_offload_capa);
      s = format(s, "%Urss active:        %U\n"
                    "%Urss supported:     %U\n",
                 format_white_space, indent + 2,
                 format_dpdk_rss_hf_name, rss_conf.rss_hf,
                 format_white_space, indent + 2,
                 format_dpdk_rss_hf_name, di.flow_type_rss_offloads);
    }

    if (verbose && xd->dev_type == VNET_DPDK_DEV_VHOST_USER) {
        s = format(s, "%Uqueue size (max):  rx %d (%d) tx %d (%d)\n",
                 format_white_space, indent + 2,
                 xd->rx_q_used, xd->rx_q_used,
                 xd->tx_q_used, xd->tx_q_used);
    }

  s = format (s, "%Urx queues %d, rx desc %d, tx queues %d, tx desc %d\n",
              format_white_space, indent + 2,
              xd->rx_q_used, xd->nb_rx_desc,
              xd->tx_q_used, xd->nb_tx_desc);

  if (xd->cpu_socket > -1)
    s = format (s, "%Ucpu socket %d\n",
                format_white_space, indent + 2, xd->cpu_socket);

  /* $$$ MIB counters  */

  {
#define _(N, V)							\
    if ((xd->stats.V - xd->last_cleared_stats.V) != 0) {       \
      s = format (s, "\n%U%-40U%16Ld",                         \
                  format_white_space, indent + 2,              \
                  format_c_identifier, #N,                     \
                  xd->stats.V - xd->last_cleared_stats.V);     \
    }                                                          \

    foreach_dpdk_counter
#undef _
  }

  u8 * xs = 0;
  u32 i = 0;

  ASSERT(vec_len(xd->xstats) == vec_len(xd->last_cleared_xstats));

  vec_foreach_index(i, xd->xstats)
    {
      u64 delta = 0;
      struct rte_eth_xstats* xstat = vec_elt_at_index(xd->xstats, i);
      struct rte_eth_xstats* last_xstat =
        vec_elt_at_index(xd->last_cleared_xstats, i);

      delta = xstat->value - last_xstat->value;
      if (verbose == 2 || (verbose && delta))
        {
          /* format_c_identifier doesn't like c strings inside vector */
          u8 * name = format(0,"%s", xstat->name);
          xs = format(xs, "\n%U%-38U%16Ld",
                      format_white_space, indent + 4,
                      format_c_identifier, name, delta);
          vec_free(name);
        }
    }

    if (verbose && xd->dev_type == VNET_DPDK_DEV_VHOST_USER) {
        int i;
        for (i = 0; i < xd->rx_q_used * VIRTIO_QNUM; i++) {
            u8 * name;
            if (verbose == 2 || xd->vu_intf->vrings[i].packets) {
                if (i & 1) {
                    name = format(NULL, "tx q%d packets", i >> 1);
                } else {
                    name = format(NULL, "rx q%d packets", i >> 1);
                }
                xs = format(xs, "\n%U%-38U%16Ld",
                    format_white_space, indent + 4,
                    format_c_identifier, name, xd->vu_intf->vrings[i].packets);
                vec_free(name);

                if (i & 1) {
                    name = format(NULL, "tx q%d bytes", i >> 1);
                } else {
                    name = format(NULL, "rx q%d bytes", i >> 1);
                }
                xs = format(xs, "\n%U%-38U%16Ld",
                    format_white_space, indent + 4,
                    format_c_identifier, name, xd->vu_intf->vrings[i].bytes);
                vec_free(name);
            }
        }
    }

  if (xs)
    {
      s = format(s, "\n%Uextended stats:%v",
                 format_white_space, indent + 2, xs);
      vec_free(xs);
    }

  return s;
}

u8 * format_dpdk_tx_dma_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  CLIB_UNUSED (vnet_main_t * vnm) = vnet_get_main();
  dpdk_tx_dma_trace_t * t = va_arg (*va, dpdk_tx_dma_trace_t *);
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd = vec_elt_at_index (dm->devices, t->device_index);
  uword indent = format_get_indent (s);
  vnet_sw_interface_t * sw = vnet_get_sw_interface (vnm, xd->vlib_sw_if_index);

  s = format (s, "%U tx queue %d",
	      format_vnet_sw_interface_name, vnm, sw,
	      t->queue_index);

  s = format (s, "\n%Ubuffer 0x%x: %U",
	      format_white_space, indent,
	      t->buffer_index,
	      format_vlib_buffer, &t->buffer);

  s = format (s, "\n%U%U", format_white_space, indent,
	      format_ethernet_header_with_length, t->buffer.pre_data,
	      VLIB_BUFFER_PRE_DATA_SIZE);

  return s;
}

u8 * format_dpdk_rx_dma_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  CLIB_UNUSED (vnet_main_t * vnm) = vnet_get_main();
  dpdk_rx_dma_trace_t * t = va_arg (*va, dpdk_rx_dma_trace_t *);
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd = vec_elt_at_index (dm->devices, t->device_index);
  format_function_t * f;
  uword indent = format_get_indent (s);
  vnet_sw_interface_t * sw = vnet_get_sw_interface (vnm, xd->vlib_sw_if_index);

  s = format (s, "%U rx queue %d",
	      format_vnet_sw_interface_name, vnm, sw,
	      t->queue_index);

  s = format (s, "\n%Ubuffer 0x%x: %U",
	      format_white_space, indent,
	      t->buffer_index,
	      format_vlib_buffer, &t->buffer);

#ifdef RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS
  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_dpdk_rx_rte_mbuf, &t->mb);
#else
  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_dpdk_rte_mbuf, &t->mb);
#endif /* RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS */
  if (vm->trace_main.verbose)
    {
      s = format (s, "\n%UPacket Dump%s", format_white_space, indent + 2,
		  t->mb.data_len > sizeof(t->data) ? " (truncated)": "");
      s = format (s, "\n%U%U", format_white_space, indent + 4,
		  format_hexdump, &t->data,
		  t->mb.data_len > sizeof(t->data) ? sizeof(t->data) : t->mb.data_len);
    }
  f = node->format_buffer;
  if (!f)
    f = format_hex_bytes;
  s = format (s, "\n%U%U", format_white_space, indent,
	      f, t->buffer.pre_data, VLIB_BUFFER_PRE_DATA_SIZE);

  return s;
}


static inline u8 * format_dpdk_pkt_types (u8 * s, va_list * va)
{
  u32 *pkt_types = va_arg (*va, u32 *);
  uword indent __attribute__((unused)) = format_get_indent (s) + 2;

  if (!*pkt_types)
    return s;

  s = format (s, "Packet Types");

#define _(L, F, S)             \
  if ((*pkt_types & RTE_PTYPE_##L##_MASK) == RTE_PTYPE_##L##_##F)           \
    {                                                                       \
      s = format (s, "\n%U%s (0x%04x) %s", format_white_space, indent,      \
                     "RTE_PTYPE_" #L "_" #F, RTE_PTYPE_##L##_##F, S);       \
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

u8 * format_dpdk_rte_mbuf (u8 * s, va_list * va)
{
  struct rte_mbuf * mb = va_arg (*va, struct rte_mbuf *);
  uword indent = format_get_indent (s) + 2;

  s = format (s, "PKT MBUF: port %d, nb_segs %d, pkt_len %d"
              "\n%Ubuf_len %d, data_len %d, ol_flags 0x%x, data_off %d"
              "\n%Upacket_type 0x%x",
              mb->port, mb->nb_segs, mb->pkt_len,
              format_white_space, indent,
              mb->buf_len, mb->data_len, mb->ol_flags, mb->data_off,
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

u8 * format_dpdk_rx_rte_mbuf (u8 * s, va_list * va)
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

uword
unformat_socket_mem (unformat_input_t * input, va_list * va)
{
  uword ** r = va_arg (* va, uword **);
  int i = 0;
  u32 mem;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, ","))
        hash_set (*r, i, 1024);
      else if (unformat (input, "%u,", &mem))
        hash_set (*r, i, mem);
      else if (unformat (input, "%u", &mem))
        hash_set (*r, i, mem);
      else
        {
          unformat_put_input (input);
          goto done;
        }
      i++;
    }

done:
  return 1;
}

clib_error_t *
unformat_rss_fn (unformat_input_t * input, uword * rss_fn)
{
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0)
        ;
#undef _
#define _(f, s)                                 \
      else if (unformat (input, s))             \
        *rss_fn |= f;

      foreach_dpdk_rss_hf
#undef _

      else
        {
          return clib_error_return (0, "unknown input `%U'",
                                     format_unformat_error, input);
        }
    }
  return 0;
}
