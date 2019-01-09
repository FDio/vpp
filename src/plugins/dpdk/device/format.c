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

#define __USE_GNU
#include <dlfcn.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/sfp.h>
#include <dpdk/device/dpdk.h>

#include <dpdk/device/dpdk_priv.h>
#include <vppinfra/error.h>

#define foreach_dpdk_counter                    \
  _ (tx_frames_ok, opackets)                    \
  _ (tx_bytes_ok, obytes)                       \
  _ (tx_errors, oerrors)                        \
  _ (rx_frames_ok, ipackets)                    \
  _ (rx_bytes_ok, ibytes)                       \
  _ (rx_errors, ierrors)                        \
  _ (rx_missed, imissed)                        \
  _ (rx_no_bufs, rx_nombuf)

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
  _(ETH_RSS_IPV6_TCP_EX,        "ipv6-tcp-ex") \
  _(ETH_RSS_IPV6_UDP_EX,        "ipv6-udp-ex") \
  _(ETH_RSS_L2_PAYLOAD,         "l2-payload")  \
  _(ETH_RSS_IPV6_EX,            "ipv6-ex")     \
  _(ETH_RSS_IPV6_TCP_EX,        "ipv6-tcp-ex") \
  _(ETH_RSS_IPV6_UDP_EX,        "ipv6-udp-ex") \
  _(ETH_RSS_PORT,               "port")        \
  _(ETH_RSS_VXLAN,              "vxlan")       \
  _(ETH_RSS_GENEVE,             "geneve")      \
  _(ETH_RSS_NVGRE,              "nvgre")

#define foreach_dpdk_pkt_rx_offload_flag                                \
  _ (PKT_RX_VLAN, "RX packet is a 802.1q VLAN packet")                  \
  _ (PKT_RX_RSS_HASH, "RX packet with RSS hash result")                 \
  _ (PKT_RX_FDIR, "RX packet with FDIR infos")                          \
  _ (PKT_RX_L4_CKSUM_BAD, "L4 cksum of RX pkt. is not OK")              \
  _ (PKT_RX_IP_CKSUM_BAD, "IP cksum of RX pkt. is not OK")              \
  _ (PKT_RX_EIP_CKSUM_BAD, "External IP header checksum error")         \
  _ (PKT_RX_VLAN_STRIPPED, "RX packet VLAN tag stripped")               \
  _ (PKT_RX_IP_CKSUM_GOOD, "IP cksum of RX pkt. is valid")              \
  _ (PKT_RX_L4_CKSUM_GOOD, "L4 cksum of RX pkt. is valid")              \
  _ (PKT_RX_IEEE1588_PTP, "RX IEEE1588 L2 Ethernet PT Packet")          \
  _ (PKT_RX_IEEE1588_TMST, "RX IEEE1588 L2/L4 timestamped packet")      \
  _ (PKT_RX_QINQ_STRIPPED, "RX packet QinQ tags stripped") \
  _ (PKT_RX_TIMESTAMP, "Timestamp field is valid")

#define foreach_dpdk_pkt_type                                           \
  _ (L2, ETHER, "Ethernet packet")                                      \
  _ (L2, ETHER_TIMESYNC, "Ethernet packet for time sync")               \
  _ (L2, ETHER_ARP, "ARP packet")                                       \
  _ (L2, ETHER_LLDP, "LLDP (Link Layer Discovery Protocol) packet")     \
  _ (L2, ETHER_NSH, "NSH (Network Service Header) packet")              \
  _ (L2, ETHER_VLAN, "VLAN packet")                                     \
  _ (L2, ETHER_QINQ, "QinQ packet")                                     \
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
  _ (INNER_L4, FRAG, "Inner fragmented IP packet")                       \
  _ (INNER_L4, SCTP, "Inner SCTP (Stream Control Transmission Protocol) packet") \
  _ (INNER_L4, ICMP, "Inner ICMP packet")                               \
  _ (INNER_L4, NONFRAG, "Inner non-fragmented IP packet")

#define foreach_dpdk_pkt_tx_offload_flag                                \
  _ (PKT_TX_VLAN_PKT, "TX packet is a 802.1q VLAN packet")              \
  _ (PKT_TX_IP_CKSUM, "IP cksum of TX pkt. computed by NIC")            \
  _ (PKT_TX_TCP_CKSUM, "TCP cksum of TX pkt. computed by NIC")          \
  _ (PKT_TX_SCTP_CKSUM, "SCTP cksum of TX pkt. computed by NIC")        \
  _ (PKT_TX_IEEE1588_TMST, "TX IEEE1588 packet to timestamp")

#define foreach_dpdk_pkt_offload_flag           \
  foreach_dpdk_pkt_rx_offload_flag              \
  foreach_dpdk_pkt_tx_offload_flag

#define foreach_dpdk_log_level	\
  _ (EMERG, "emergency")	\
  _ (ALERT, "alert")		\
  _ (CRIT, "critical")		\
  _ (ERR, "error")		\
  _ (WARNING, "warning")	\
  _ (NOTICE, "notice")		\
  _ (INFO, "info")		\
  _ (DEBUG, "debug")

u8 *
format_dpdk_device_name (u8 * s, va_list * args)
{
  dpdk_main_t *dm = &dpdk_main;
  char *devname_format;
  char *device_name;
  u32 i = va_arg (*args, u32);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, i);
  struct rte_eth_dev_info dev_info;
  struct rte_pci_device *pci_dev;
  u8 *ret;

  if (xd->name)
    return format (s, "%s", xd->name);

  if (dm->conf->interface_name_format_decimal)
    devname_format = "%s%d/%d/%d";
  else
    devname_format = "%s%x/%x/%x";

  switch (xd->port_type)
    {
    case VNET_DPDK_PORT_TYPE_ETH_1G:
      device_name = "GigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_2_5G:
      device_name = "Two_FiveGigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_5G:
      device_name = "FiveGigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_10G:
      device_name = "TenGigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_20G:
      device_name = "TwentyGigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_25G:
      device_name = "TwentyFiveGigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_40G:
      device_name = "FortyGigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_50G:
      device_name = "FiftyGigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_56G:
      device_name = "FiftySixGigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_100G:
      device_name = "HundredGigabitEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_BOND:
      return format (s, "BondEthernet%d", xd->bond_instance_num);

    case VNET_DPDK_PORT_TYPE_ETH_SWITCH:
      device_name = "EthernetSwitch";
      break;

    case VNET_DPDK_PORT_TYPE_ETH_VF:
      device_name = "VirtualFunctionEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_AF_PACKET:
      return format (s, "af_packet%d", xd->af_packet_instance_num);

    case VNET_DPDK_PORT_TYPE_VIRTIO_USER:
      device_name = "VirtioUser";
      break;

    case VNET_DPDK_PORT_TYPE_VHOST_ETHER:
      device_name = "VhostEthernet";
      break;

    case VNET_DPDK_PORT_TYPE_FAILSAFE:
      device_name = "FailsafeEthernet";
      break;

    default:
    case VNET_DPDK_PORT_TYPE_UNKNOWN:
      device_name = "UnknownEthernet";
      break;
    }

  rte_eth_dev_info_get (xd->port_id, &dev_info);
  pci_dev = dpdk_get_pci_device (&dev_info);

  if (pci_dev && xd->port_type != VNET_DPDK_PORT_TYPE_FAILSAFE)
    ret = format (s, devname_format, device_name, pci_dev->addr.bus,
		  pci_dev->addr.devid, pci_dev->addr.function);
  else
    ret = format (s, "%s%d", device_name, xd->port_id);

  if (xd->interface_name_suffix)
    return format (ret, "/%s", xd->interface_name_suffix);
  return ret;
}

u8 *
format_dpdk_device_flags (u8 * s, va_list * args)
{
  dpdk_device_t *xd = va_arg (*args, dpdk_device_t *);
  u8 *t = 0;

#define _(a, b, c) if (xd->flags & (1 << a)) \
t = format (t, "%s%s", t ? " ":"", c);
  foreach_dpdk_device_flags
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

static u8 *
format_dpdk_device_type (u8 * s, va_list * args)
{
  dpdk_main_t *dm = &dpdk_main;
  char *dev_type;
  u32 i = va_arg (*args, u32);

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

    case VNET_DPDK_PMD_ENIC:
      dev_type = "Cisco VIC";
      break;

    case VNET_DPDK_PMD_CXGBE:
      dev_type = "Chelsio T4/T5";
      break;

    case VNET_DPDK_PMD_MLX4:
      dev_type = "Mellanox ConnectX-3 Family";
      break;

    case VNET_DPDK_PMD_MLX5:
      dev_type = "Mellanox ConnectX-4 Family";
      break;

    case VNET_DPDK_PMD_VMXNET3:
      dev_type = "VMware VMXNET3";
      break;

    case VNET_DPDK_PMD_AF_PACKET:
      dev_type = "af_packet";
      break;

    case VNET_DPDK_PMD_BOND:
      dev_type = "Ethernet Bonding";
      break;

    case VNET_DPDK_PMD_DPAA2:
      dev_type = "NXP DPAA2 Mac";
      break;

    case VNET_DPDK_PMD_VIRTIO_USER:
      dev_type = "Virtio User";
      break;

    case VNET_DPDK_PMD_THUNDERX:
      dev_type = "Cavium ThunderX";
      break;

    case VNET_DPDK_PMD_VHOST_ETHER:
      dev_type = "VhostEthernet";
      break;

    case VNET_DPDK_PMD_ENA:
      dev_type = "AWS ENA VF";
      break;

    case VNET_DPDK_PMD_FAILSAFE:
      dev_type = "FailsafeEthernet";
      break;

    case VNET_DPDK_PMD_LIOVF_ETHER:
      dev_type = "Cavium Lio VF";
      break;

    case VNET_DPDK_PMD_QEDE:
      dev_type = "Cavium QLogic FastLinQ QL4xxxx";
      break;

    case VNET_DPDK_PMD_NETVSC:
      dev_type = "Microsoft Hyper-V Netvsc";
      break;

    default:
    case VNET_DPDK_PMD_UNKNOWN:
      dev_type = "### UNKNOWN ###";
      break;
    }

  return format (s, dev_type);
}

static u8 *
format_dpdk_link_status (u8 * s, va_list * args)
{
  dpdk_device_t *xd = va_arg (*args, dpdk_device_t *);
  struct rte_eth_link *l = &xd->link;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, xd->hw_if_index);

  s = format (s, "%s ", l->link_status ? "up" : "down");
  if (l->link_status)
    {
      u32 promisc = rte_eth_promiscuous_get (xd->port_id);

      s = format (s, "%s duplex ", (l->link_duplex == ETH_LINK_FULL_DUPLEX) ?
		  "full" : "half");
      s = format (s, "mtu %d %s\n", hi->max_packet_bytes, promisc ?
		  " promisc" : "");
    }
  else
    s = format (s, "\n");

  return s;
}

#define _(v, str)                                            \
if (bitmap & v) {                                            \
  if (format_get_indent (s) > 72)                            \
    s = format(s,"\n%U", format_white_space, indent);        \
  s = format(s, "%s ", str);                                 \
}

u8 *
format_dpdk_rss_hf_name (u8 * s, va_list * args)
{
  u64 bitmap = va_arg (*args, u64);
  u32 indent = format_get_indent (s);

  if (!bitmap)
    return format (s, "none");

  foreach_dpdk_rss_hf return s;
}

#undef _

/* Convert to all lower case e.g "VLAN_STRIP" -> "vlan-strip"
   Works for both vector names and null terminated c strings. */
static u8 *
format_offload (u8 * s, va_list * va)
{
  u8 *id = va_arg (*va, u8 *);
  uword i, l;

  l = ~0;
  if (clib_mem_is_vec (id))
    l = vec_len (id);

  if (id)
    for (i = 0; id[i] != 0 && i < l; i++)
      {
	u8 c = id[i];

	if (c == '_')
	  c = '-';
	else
	  c = tolower (c);
	vec_add1 (s, c);
      }

  return s;
}

#define _(v, func)                                           \
if (bitmap & v) {                                            \
  if (format_get_indent (s) > 72)                            \
    s = format(s,"\n%U", format_white_space, indent);        \
  s = format(s, "%U ", format_offload, func (v));	     \
}

u8 *
format_dpdk_rx_offload_caps (u8 * s, va_list * args)
{
  u64 bitmap = va_arg (*args, u32);
  u32 indent = format_get_indent (s);
  uword i;

  if (!bitmap)
    return format (s, "none");

  for (i = 0; i < 64; i++)
    {
      u64 mask = (u64) 1 << i;

      _(mask, rte_eth_dev_rx_offload_name);
    }
  return s;
}

u8 *
format_dpdk_tx_offload_caps (u8 * s, va_list * args)
{
  u64 bitmap = va_arg (*args, u32);
  u32 indent = format_get_indent (s);
  uword i;

  if (!bitmap)
    return format (s, "none");

  for (i = 0; i < 64; i++)
    {
      u64 mask = (u64) 1 << i;

      _(mask, rte_eth_dev_tx_offload_name);
    }
  return s;
}

#undef _

u8 *
format_dpdk_device_errors (u8 * s, va_list * args)
{
  dpdk_device_t *xd = va_arg (*args, dpdk_device_t *);
  clib_error_t *e;
  u32 indent = format_get_indent (s);

  vec_foreach (e, xd->errors)
  {
    s = format (s, "%U%v\n", format_white_space, indent, e->what);
  }
  return s;
}

static u8 *
format_dpdk_device_module_info (u8 * s, va_list * args)
{
  dpdk_device_t *xd = va_arg (*args, dpdk_device_t *);
  struct rte_eth_dev_module_info mi = { 0 };
  struct rte_dev_eeprom_info ei = { 0 };

  if (rte_eth_dev_get_module_info (xd->port_id, &mi) != 0)
    return format (s, "unknown");

  ei.length = mi.eeprom_len;
  ei.data = clib_mem_alloc (mi.eeprom_len);

  if (rte_eth_dev_get_module_eeprom (xd->port_id, &ei) == 0)
    {
      s = format (s, "%U", format_sfp_eeprom, ei.data +
		  (mi.type == RTE_ETH_MODULE_SFF_8436 ? 0x80 : 0));
    }
  else
    s = format (s, "eeprom read error");

  clib_mem_free (ei.data);
  return s;
}

static const char *
ptr2sname (void *p)
{
  Dl_info info = { 0 };

  if (dladdr (p, &info) == 0)
    return 0;

  return info.dli_sname;
}

u8 *
format_dpdk_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  u32 indent = format_get_indent (s);
  f64 now = vlib_time_now (dm->vlib_main);
  struct rte_eth_dev_info di;

  dpdk_update_counters (xd, now);
  dpdk_update_link_state (xd, now);
  rte_eth_dev_info_get (xd->port_id, &di);

  s = format (s, "%U\n%Ucarrier %U",
	      format_dpdk_device_type, dev_instance,
	      format_white_space, indent + 2, format_dpdk_link_status, xd);
  s = format (s, "%Uflags: %U\n",
	      format_white_space, indent + 2, format_dpdk_device_flags, xd);
  s = format (s, "%Urx: queues %d (max %d), desc %d "
	      "(min %d max %d align %d)\n",
	      format_white_space, indent + 2, xd->rx_q_used, di.max_rx_queues,
	      xd->nb_rx_desc, di.rx_desc_lim.nb_min, di.rx_desc_lim.nb_max,
	      di.rx_desc_lim.nb_align);
  s = format (s, "%Utx: queues %d (max %d), desc %d "
	      "(min %d max %d align %d)\n",
	      format_white_space, indent + 2, xd->tx_q_used, di.max_tx_queues,
	      xd->nb_tx_desc, di.tx_desc_lim.nb_min, di.tx_desc_lim.nb_max,
	      di.tx_desc_lim.nb_align);

  if (xd->flags & DPDK_DEVICE_FLAG_PMD)
    {
      struct rte_pci_device *pci;
      struct rte_eth_rss_conf rss_conf;
      int vlan_off;
      int retval;

      rss_conf.rss_key = 0;
      retval = rte_eth_dev_rss_hash_conf_get (xd->port_id, &rss_conf);
      if (retval < 0)
	clib_warning ("rte_eth_dev_rss_hash_conf_get returned %d", retval);

      pci = dpdk_get_pci_device (&di);

      if (pci)
	{
	  u8 *s2;
	  if (xd->cpu_socket > -1)
	    s2 = format (0, "%d", xd->cpu_socket);
	  else
	    s2 = format (0, "unknown");
	  s = format (s, "%Upci: device %04x:%04x subsystem %04x:%04x "
		      "address %04x:%02x:%02x.%02x numa %v\n",
		      format_white_space, indent + 2, pci->id.vendor_id,
		      pci->id.device_id, pci->id.subsystem_vendor_id,
		      pci->id.subsystem_device_id, pci->addr.domain,
		      pci->addr.bus, pci->addr.devid, pci->addr.function, s2);
	  vec_free (s2);
	}

      s = format (s, "%Umodule: %U\n", format_white_space, indent + 2,
		  format_dpdk_device_module_info, xd);

      s = format (s, "%Umax rx packet len: %d\n", format_white_space,
		  indent + 2, di.max_rx_pktlen);
      s = format (s, "%Upromiscuous: unicast %s all-multicast %s\n",
		  format_white_space, indent + 2,
		  rte_eth_promiscuous_get (xd->port_id) ? "on" : "off",
		  rte_eth_allmulticast_get (xd->port_id) ? "on" : "off");
      vlan_off = rte_eth_dev_get_vlan_offload (xd->port_id);
      s = format (s, "%Uvlan offload: strip %s filter %s qinq %s\n",
		  format_white_space, indent + 2,
		  vlan_off & ETH_VLAN_STRIP_OFFLOAD ? "on" : "off",
		  vlan_off & ETH_VLAN_FILTER_OFFLOAD ? "on" : "off",
		  vlan_off & ETH_VLAN_EXTEND_OFFLOAD ? "on" : "off");
      s = format (s, "%Urx offload avail:  %U\n",
		  format_white_space, indent + 2,
		  format_dpdk_rx_offload_caps, di.rx_offload_capa);
      s = format (s, "%Urx offload active: %U\n",
		  format_white_space, indent + 2,
		  format_dpdk_rx_offload_caps, xd->port_conf.rxmode.offloads);
      s = format (s, "%Utx offload avail:  %U\n",
		  format_white_space, indent + 2,
		  format_dpdk_tx_offload_caps, di.tx_offload_capa);
      s = format (s, "%Utx offload active: %U\n",
		  format_white_space, indent + 2,
		  format_dpdk_tx_offload_caps, xd->port_conf.txmode.offloads);
      s = format (s, "%Urss avail:         %U\n"
		  "%Urss active:        %U\n",
		  format_white_space, indent + 2,
		  format_dpdk_rss_hf_name, di.flow_type_rss_offloads,
		  format_white_space, indent + 2,
		  format_dpdk_rss_hf_name, rss_conf.rss_hf);
      s = format (s, "%Utx burst function: %s\n",
		  format_white_space, indent + 2,
		  ptr2sname (rte_eth_devices[xd->port_id].tx_pkt_burst));
      s = format (s, "%Urx burst function: %s\n",
		  format_white_space, indent + 2,
		  ptr2sname (rte_eth_devices[xd->port_id].rx_pkt_burst));
    }

  /* $$$ MIB counters  */
  {
#define _(N, V)							\
    if ((xd->stats.V - xd->last_cleared_stats.V) != 0) {       \
      s = format (s, "\n%U%-40U%16Lu",                         \
                  format_white_space, indent + 2,              \
                  format_c_identifier, #N,                     \
                  xd->stats.V - xd->last_cleared_stats.V);     \
    }                                                          \

    foreach_dpdk_counter
#undef _
  }

  u8 *xs = 0;
  u32 i = 0;
  struct rte_eth_xstat *xstat, *last_xstat;
  struct rte_eth_xstat_name *xstat_names = 0;
  int len = rte_eth_xstats_get_names (xd->port_id, NULL, 0);
  vec_validate (xstat_names, len - 1);
  rte_eth_xstats_get_names (xd->port_id, xstat_names, len);

  ASSERT (vec_len (xd->xstats) == vec_len (xd->last_cleared_xstats));

  /* *INDENT-OFF* */
  vec_foreach_index(i, xd->xstats)
    {
      u64 delta = 0;
      xstat = vec_elt_at_index(xd->xstats, i);
      last_xstat = vec_elt_at_index(xd->last_cleared_xstats, i);

      delta = xstat->value - last_xstat->value;
      if (verbose == 2 || (verbose && delta))
        {
          /* format_c_identifier doesn't like c strings inside vector */
          u8 * name = format(0,"%s", xstat_names[i].name);
          xs = format(xs, "\n%U%-38U%16Lu",
                      format_white_space, indent + 4,
                      format_c_identifier, name, delta);
          vec_free(name);
        }
    }
  /* *INDENT-ON* */

  vec_free (xstat_names);

  if (xs)
    {
      s = format (s, "\n%Uextended stats:%v",
		  format_white_space, indent + 2, xs);
      vec_free (xs);
    }

  if (vec_len (xd->errors))
    {
      s = format (s, "%UErrors:\n  %U", format_white_space, indent,
		  format_dpdk_device_errors, xd);
    }

  return s;
}

u8 *
format_dpdk_tx_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  CLIB_UNUSED (vnet_main_t * vnm) = vnet_get_main ();
  dpdk_tx_trace_t *t = va_arg (*va, dpdk_tx_trace_t *);
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, t->device_index);
  u32 indent = format_get_indent (s);
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, xd->sw_if_index);

  s = format (s, "%U tx queue %d",
	      format_vnet_sw_interface_name, vnm, sw, t->queue_index);

  s = format (s, "\n%Ubuffer 0x%x: %U",
	      format_white_space, indent,
	      t->buffer_index, format_vnet_buffer, &t->buffer);

  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_dpdk_rte_mbuf, &t->mb, &t->data);

  s = format (s, "\n%U%U", format_white_space, indent,
	      format_ethernet_header_with_length, t->buffer.pre_data,
	      sizeof (t->buffer.pre_data));

  return s;
}

u8 *
format_dpdk_rx_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  CLIB_UNUSED (vnet_main_t * vnm) = vnet_get_main ();
  dpdk_rx_trace_t *t = va_arg (*va, dpdk_rx_trace_t *);
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, t->device_index);
  format_function_t *f;
  u32 indent = format_get_indent (s);
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, xd->sw_if_index);

  s = format (s, "%U rx queue %d",
	      format_vnet_sw_interface_name, vnm, sw, t->queue_index);

  s = format (s, "\n%Ubuffer 0x%x: %U",
	      format_white_space, indent,
	      t->buffer_index, format_vnet_buffer, &t->buffer);

  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_dpdk_rte_mbuf, &t->mb, &t->data);

  if (vm->trace_main.verbose)
    {
      s = format (s, "\n%UPacket Dump%s", format_white_space, indent + 2,
		  t->mb.data_len > sizeof (t->data) ? " (truncated)" : "");
      s = format (s, "\n%U%U", format_white_space, indent + 4,
		  format_hexdump, &t->data,
		  t->mb.data_len >
		  sizeof (t->data) ? sizeof (t->data) : t->mb.data_len);
    }
  f = node->format_buffer;
  if (!f)
    f = format_hex_bytes;
  s = format (s, "\n%U%U", format_white_space, indent,
	      f, t->buffer.pre_data, sizeof (t->buffer.pre_data));

  return s;
}


static inline u8 *
format_dpdk_pkt_types (u8 * s, va_list * va)
{
  u32 *pkt_types = va_arg (*va, u32 *);
  u32 indent __attribute__ ((unused)) = format_get_indent (s) + 2;

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

static inline u8 *
format_dpdk_pkt_offload_flags (u8 * s, va_list * va)
{
  u64 *ol_flags = va_arg (*va, u64 *);
  u32 indent = format_get_indent (s) + 2;

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

u8 *
format_dpdk_rte_mbuf_vlan (u8 * s, va_list * va)
{
  ethernet_vlan_header_tv_t *vlan_hdr =
    va_arg (*va, ethernet_vlan_header_tv_t *);

  if (clib_net_to_host_u16 (vlan_hdr->type) == ETHERNET_TYPE_DOT1AD)
    {
      s = format (s, "%U 802.1q vlan ",
		  format_ethernet_vlan_tci,
		  clib_net_to_host_u16 (vlan_hdr->priority_cfi_and_id));
      vlan_hdr++;
    }

  s = format (s, "%U",
	      format_ethernet_vlan_tci,
	      clib_net_to_host_u16 (vlan_hdr->priority_cfi_and_id));

  return s;
}

u8 *
format_dpdk_rte_mbuf (u8 * s, va_list * va)
{
  struct rte_mbuf *mb = va_arg (*va, struct rte_mbuf *);
  ethernet_header_t *eth_hdr = va_arg (*va, ethernet_header_t *);
  u32 indent = format_get_indent (s) + 2;

  s = format (s, "PKT MBUF: port %d, nb_segs %d, pkt_len %d"
	      "\n%Ubuf_len %d, data_len %d, ol_flags 0x%lx, data_off %d, phys_addr 0x%x"
	      "\n%Upacket_type 0x%x l2_len %u l3_len %u outer_l2_len %u outer_l3_len %u"
	      "\n%Urss 0x%x fdir.hi 0x%x fdir.lo 0x%x",
	      mb->port, mb->nb_segs, mb->pkt_len,
	      format_white_space, indent,
	      mb->buf_len, mb->data_len, mb->ol_flags, mb->data_off,
	      mb->buf_physaddr, format_white_space, indent, mb->packet_type,
	      mb->l2_len, mb->l3_len, mb->outer_l2_len, mb->outer_l3_len,
	      format_white_space, indent, mb->hash.rss, mb->hash.fdir.hi,
	      mb->hash.fdir.lo);

  if (mb->ol_flags)
    s = format (s, "\n%U%U", format_white_space, indent,
		format_dpdk_pkt_offload_flags, &mb->ol_flags);

  if ((mb->ol_flags & PKT_RX_VLAN) &&
      ((mb->ol_flags & (PKT_RX_VLAN_STRIPPED | PKT_RX_QINQ_STRIPPED)) == 0))
    {
      ethernet_vlan_header_tv_t *vlan_hdr =
	((ethernet_vlan_header_tv_t *) & (eth_hdr->type));
      s = format (s, " %U", format_dpdk_rte_mbuf_vlan, vlan_hdr);
    }

  if (mb->packet_type)
    s = format (s, "\n%U%U", format_white_space, indent,
		format_dpdk_rte_mbuf, &mb->packet_type, 0);

  return s;
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

uword
unformat_dpdk_log_level (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,s) else if (unformat (input, s)) *r = RTE_LOG_##v;
  foreach_dpdk_log_level
#undef _
    else
    return 0;
  return 1;
}

clib_error_t *
unformat_hqos (unformat_input_t * input, dpdk_device_config_hqos_t * hqos)
{
  clib_error_t *error = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "hqos-thread %u", &hqos->hqos_thread))
	hqos->hqos_thread_valid = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  break;
	}
    }

  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
