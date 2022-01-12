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

#if RTE_VERSION < RTE_VERSION_NUM(21, 5, 0, 0)
#define PKT_RX_OUTER_IP_CKSUM_BAD PKT_RX_EIP_CKSUM_BAD
#endif

#define foreach_dpdk_pkt_rx_offload_flag                                      \
  _ (RX_FDIR, "RX packet with FDIR infos")                                    \
  _ (RX_FDIR_FLX, "RX packet with FDIR_FLX info")                             \
  _ (RX_FDIR_ID, "RX packet with FDIR_ID info")                               \
  _ (RX_IEEE1588_PTP, "RX IEEE1588 L2 Ethernet PT Packet")                    \
  _ (RX_IEEE1588_TMST, "RX IEEE1588 L2/L4 timestamped packet")                \
  _ (RX_IP_CKSUM_BAD, "IP cksum of RX pkt. is not OK")                        \
  _ (RX_IP_CKSUM_GOOD, "IP cksum of RX pkt. is valid")                        \
  _ (RX_IP_CKSUM_NONE, "no IP cksum of RX pkt.")                              \
  _ (RX_L4_CKSUM_BAD, "L4 cksum of RX pkt. is not OK")                        \
  _ (RX_L4_CKSUM_GOOD, "L4 cksum of RX pkt. is valid")                        \
  _ (RX_L4_CKSUM_NONE, "no L4 cksum of RX pkt.")                              \
  _ (RX_LRO, "LRO packet")                                                    \
  _ (RX_OUTER_IP_CKSUM_BAD, "External IP header checksum error")              \
  _ (RX_OUTER_L4_CKSUM_BAD, "External L4 header checksum error")              \
  _ (RX_OUTER_L4_CKSUM_GOOD, "External L4 header checksum OK")                \
  _ (RX_QINQ, "RX packet with QinQ tags")                                     \
  _ (RX_QINQ_STRIPPED, "RX packet QinQ tags stripped")                        \
  _ (RX_RSS_HASH, "RX packet with RSS hash result")                           \
  _ (RX_SEC_OFFLOAD, "RX packet with security offload")                       \
  _ (RX_SEC_OFFLOAD_FAILED, "RX packet with security offload failed")         \
  _ (RX_VLAN, "RX packet is a 802.1q VLAN packet")                            \
  _ (RX_VLAN_STRIPPED, "RX packet VLAN tag stripped")

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

#define foreach_dpdk_pkt_tx_offload_flag                                      \
  _ (TX_IEEE1588_TMST, "TX IEEE1588 packet to timestamp")                     \
  _ (TX_IPV4, "TX IPV4")                                                      \
  _ (TX_IPV6, "TX IPV6")                                                      \
  _ (TX_IP_CKSUM, "IP cksum of TX pkt. computed by NIC")                      \
  _ (TX_MACSEC, "TX MACSEC")                                                  \
  _ (TX_OUTER_IPV4, "TX outer IPV4")                                          \
  _ (TX_OUTER_IPV6, "TX outer IPV6")                                          \
  _ (TX_OUTER_IP_CKSUM, "Outer IP cksum of Tx pkt. computed by NIC")          \
  _ (TX_OUTER_UDP_CKSUM, "TX outer UDP cksum")                                \
  _ (TX_QINQ, "TX QINQ")                                                      \
  _ (TX_SCTP_CKSUM, "SCTP cksum of TX pkt. computed by NIC")                  \
  _ (TX_SEC_OFFLOAD, "TX SEC OFFLOAD")                                        \
  _ (TX_TCP_CKSUM, "TCP cksum of TX pkt. computed by NIC")                    \
  _ (TX_TCP_SEG, "TSO of TX pkt. done by NIC")                                \
  _ (TX_TUNNEL_GENEVE, "TX tunnel GENEVE")                                    \
  _ (TX_TUNNEL_GRE, "TX tunnel GRE")                                          \
  _ (TX_TUNNEL_GTP, "TX tunnel GTP")                                          \
  _ (TX_TUNNEL_IP, "TX tunnel IP")                                            \
  _ (TX_TUNNEL_IPIP, "TX tunnel IPIP")                                        \
  _ (TX_TUNNEL_MPLSINUDP, "TX tunnel MPLSinUDP")                              \
  _ (TX_TUNNEL_UDP, "TX tunnel UDP")                                          \
  _ (TX_TUNNEL_VXLAN, "TX packet is a VXLAN packet")                          \
  _ (TX_TUNNEL_VXLAN_GPE, "TX tunnel VXLAN GPE")                              \
  _ (TX_UDP_CKSUM, "TX UDP cksum")                                            \
  _ (TX_UDP_SEG, "TX UDP SEG")                                                \
  _ (TX_VLAN, "TX packet is a 802.1q VLAN packet")

#define foreach_dpdk_pkt_offload_flag           \
  foreach_dpdk_pkt_rx_offload_flag              \
  foreach_dpdk_pkt_tx_offload_flag

#define foreach_dpdk_pkt_dyn_rx_offload_flag				\
  _ (RX_TIMESTAMP, 0, "Timestamp field is valid")

static char *device_name_by_port_type[] = {
#define _(n, s) [VNET_DPDK_PORT_TYPE_##n] = (s),
  forach_dpdk_port_type
#undef _
};

u8 *
format_dpdk_device_name (u8 * s, va_list * args)
{
  dpdk_main_t *dm = &dpdk_main;
  char *devname_format;
  char *device_name = 0;
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

  if (xd->port_type < ARRAY_LEN (device_name_by_port_type))
    device_name = device_name_by_port_type[xd->port_type];

  device_name = device_name ? device_name : "UnknownEthernet";

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
  u32 i = va_arg (*args, u32);

  if (dm->devices[i].driver)
    return format (s, dm->devices[i].driver->desc);
  else
    return format (s, "### UNKNOWN ###");
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

#define _(n, v, str)                                            \
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

u8 *
format_dpdk_burst_fn (u8 *s, va_list *args)
{
  dpdk_device_t *xd = va_arg (*args, dpdk_device_t *);
  vlib_rx_or_tx_t dir = va_arg (*args, vlib_rx_or_tx_t);
  void *p;
  Dl_info info = { 0 };

#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
#define rte_eth_fp_ops rte_eth_devices
#endif

  p = (dir == VLIB_TX) ? rte_eth_fp_ops[xd->port_id].tx_pkt_burst :
			 rte_eth_fp_ops[xd->port_id].rx_pkt_burst;

  if (dladdr (p, &info) == 0)
    return 0;

  return format (s, "%s", info.dli_sname);
}

static u8 *
format_switch_info (u8 * s, va_list * args)
{
  struct rte_eth_switch_info *si =
    va_arg (*args, struct rte_eth_switch_info *);

  if (si->name)
    s = format (s, "name %s ", si->name);

  s = format (s, "domain id %d port id %d", si->domain_id, si->port_id);

  return s;
}

u8 *
format_dpdk_rte_device (u8 *s, va_list *args)
{
  struct rte_device *d = va_arg (*args, struct rte_device *);

  if (!d)
    return format (s, "not available");

  s = format (s, "name: %s, numa: %d", d->name, d->numa_node);

  if (d->driver)
    s = format (s, ", driver: %s", d->driver->name);

  if (d->bus)
    s = format (s, ", bus: %s", d->bus->name);

  return s;
}

u8 *
format_dpdk_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  dpdk_main_t *dm = &dpdk_main;
  vlib_main_t *vm = vlib_get_main ();
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  u32 indent = format_get_indent (s);
  f64 now = vlib_time_now (vm);
  struct rte_eth_dev_info di;
  struct rte_eth_burst_mode mode;
  struct rte_pci_device *pci;
  struct rte_eth_rss_conf rss_conf;
  int vlan_off;
  int retval;

  dpdk_update_counters (xd, now);
  dpdk_update_link_state (xd, now);
  rte_eth_dev_info_get (xd->port_id, &di);

  s = format (s, "%U\n%Ucarrier %U",
	      format_dpdk_device_type, dev_instance,
	      format_white_space, indent + 2, format_dpdk_link_status, xd);
  s = format (s, "%Uflags: %U\n",
	      format_white_space, indent + 2, format_dpdk_device_flags, xd);
  if (di.device->devargs && di.device->devargs->args)
    s = format (s, "%UDevargs: %s\n",
		format_white_space, indent + 2, di.device->devargs->args);
  s = format (s,
	      "%Urx: queues %d (max %d), desc %d "
	      "(min %d max %d align %d)\n",
	      format_white_space, indent + 2, xd->conf.n_rx_queues,
	      di.max_rx_queues, xd->conf.n_rx_desc, di.rx_desc_lim.nb_min,
	      di.rx_desc_lim.nb_max, di.rx_desc_lim.nb_align);
  s = format (s,
	      "%Utx: queues %d (max %d), desc %d "
	      "(min %d max %d align %d)\n",
	      format_white_space, indent + 2, xd->conf.n_tx_queues,
	      di.max_tx_queues, xd->conf.n_tx_desc, di.tx_desc_lim.nb_min,
	      di.tx_desc_lim.nb_max, di.tx_desc_lim.nb_align);

  rss_conf.rss_key = 0;
  rss_conf.rss_hf = 0;
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
      s = format (s,
		  "%Upci: device %04x:%04x subsystem %04x:%04x "
		  "address %04x:%02x:%02x.%02x numa %v\n",
		  format_white_space, indent + 2, pci->id.vendor_id,
		  pci->id.device_id, pci->id.subsystem_vendor_id,
		  pci->id.subsystem_device_id, pci->addr.domain, pci->addr.bus,
		  pci->addr.devid, pci->addr.function, s2);
      vec_free (s2);
    }

  if (di.switch_info.domain_id != RTE_ETH_DEV_SWITCH_DOMAIN_ID_INVALID)
    {
      s = format (s, "%Uswitch info: %U\n", format_white_space, indent + 2,
		  format_switch_info, &di.switch_info);
    }

  if (1 < verbose)
    {
      s = format (s, "%Umodule: %U\n", format_white_space, indent + 2,
		  format_dpdk_device_module_info, xd);
    }

  s = format (s, "%Umax rx packet len: %d\n", format_white_space, indent + 2,
	      di.max_rx_pktlen);
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
  s = format (s, "%Urx offload avail:  %U\n", format_white_space, indent + 2,
	      format_dpdk_rx_offload_caps, di.rx_offload_capa);
  s = format (s, "%Urx offload active: %U\n", format_white_space, indent + 2,
	      format_dpdk_rx_offload_caps, xd->enabled_rx_off);
  s = format (s, "%Utx offload avail:  %U\n", format_white_space, indent + 2,
	      format_dpdk_tx_offload_caps, di.tx_offload_capa);
  s = format (s, "%Utx offload active: %U\n", format_white_space, indent + 2,
	      format_dpdk_tx_offload_caps, xd->enabled_tx_off);
  s = format (s,
	      "%Urss avail:         %U\n"
	      "%Urss active:        %U\n",
	      format_white_space, indent + 2, format_dpdk_rss_hf_name,
	      di.flow_type_rss_offloads, format_white_space, indent + 2,
	      format_dpdk_rss_hf_name, rss_conf.rss_hf);

  if (rte_eth_tx_burst_mode_get (xd->port_id, 0, &mode) == 0)
    {
      s = format (s, "%Utx burst mode: %s%s\n", format_white_space, indent + 2,
		  mode.info,
		  mode.flags & RTE_ETH_BURST_FLAG_PER_QUEUE ? " (per queue)" :
							      "");
    }

  s = format (s, "%Utx burst function: %U\n", format_white_space, indent + 2,
	      format_dpdk_burst_fn, xd, VLIB_RX);

  if (rte_eth_rx_burst_mode_get (xd->port_id, 0, &mode) == 0)
    {
      s = format (s, "%Urx burst mode: %s%s\n", format_white_space, indent + 2,
		  mode.info,
		  mode.flags & RTE_ETH_BURST_FLAG_PER_QUEUE ? " (per queue)" :
							      "");
    }

  s = format (s, "%Urx burst function: %s\n", format_white_space, indent + 2,
	      format_dpdk_burst_fn, xd, VLIB_TX);

  /* $$$ MIB counters  */
  {
#define _(N, V)							\
    if (xd->stats.V != 0) {                                    \
      s = format (s, "\n%U%-40U%16Lu",                         \
                  format_white_space, indent + 2,              \
                  format_c_identifier, #N,                     \
                  xd->stats.V);                                \
    }                                                          \

    foreach_dpdk_counter
#undef _
  }

  u8 *xs = 0;
  u32 i = 0;
  struct rte_eth_xstat *xstat;
  struct rte_eth_xstat_name *xstat_names = 0;
  int len = vec_len (xd->xstats);
  vec_validate (xstat_names, len - 1);
  int ret = rte_eth_xstats_get_names (xd->port_id, xstat_names, len);

  if (ret >= 0 && ret <= len)
    {
      /* *INDENT-OFF* */
      vec_foreach_index(i, xd->xstats)
        {
          xstat = vec_elt_at_index(xd->xstats, i);
          if (verbose == 2 || (verbose && xstat->value))
            {
              xs = format(xs, "\n%U%-38s%16Lu",
                          format_white_space, indent + 4,
                          xstat_names[i].name,
                          xstat->value);
            }
        }
      /* *INDENT-ON* */

      vec_free (xstat_names);
    }

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

  s = format (s, "\n%Ubuffer 0x%x: %U", format_white_space, indent,
	      t->buffer_index, format_vnet_buffer_no_chain, &t->buffer);

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

  s = format (s, "\n%Ubuffer 0x%x: %U", format_white_space, indent,
	      t->buffer_index, format_vnet_buffer_no_chain, &t->buffer);

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
  u64 rx_dynflag;
  int rx_dynflag_offset;

  if (!*ol_flags)
    return s;

  s = format (s, "Packet Offload Flags");

#define _(F, S)                                                               \
  if (*ol_flags & RTE_MBUF_F_##F)                                             \
    {                                                                         \
      s = format (s, "\n%U%s (0x%04x) %s", format_white_space, indent,        \
		  "PKT_" #F, RTE_MBUF_F_##F, S);                              \
    }

  foreach_dpdk_pkt_offload_flag
#undef _
#define _(F, P, S)							\
  {									\
    rx_dynflag_offset = rte_mbuf_dynflag_lookup(RTE_MBUF_DYNFLAG_##F##_NAME, \
						P);			\
    if (rx_dynflag_offset >= 0)						\
      {									\
	rx_dynflag = (u64) 1 << rx_dynflag_offset;			\
	if (*ol_flags & rx_dynflag)					\
	  {								\
	    s = format (s, "\n%U%s %s", format_white_space, indent,	\
			#F, S);						\
	  }								\
      }									\
  }
    foreach_dpdk_pkt_dyn_rx_offload_flag
#undef _
    return s;
}

u8 *
format_dpdk_rte_mbuf_tso (u8 *s, va_list *va)
{
  struct rte_mbuf *mb = va_arg (*va, struct rte_mbuf *);
  if (mb->ol_flags & RTE_MBUF_F_TX_TCP_SEG)
    {
      s = format (s, "l4_len %u tso_segsz %u", mb->l4_len, mb->tso_segsz);
    }
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

  s = format (
    s,
    "PKT MBUF: port %d, nb_segs %d, pkt_len %d"
    "\n%Ubuf_len %d, data_len %d, ol_flags 0x%lx, data_off %d, phys_addr 0x%x"
    "\n%Upacket_type 0x%x l2_len %u l3_len %u outer_l2_len %u outer_l3_len %u "
    "%U"
    "\n%Urss 0x%x fdir.hi 0x%x fdir.lo 0x%x",
    mb->port, mb->nb_segs, mb->pkt_len, format_white_space, indent,
    mb->buf_len, mb->data_len, mb->ol_flags, mb->data_off, mb->buf_iova,
    format_white_space, indent, mb->packet_type, mb->l2_len, mb->l3_len,
    mb->outer_l2_len, mb->outer_l3_len, format_dpdk_rte_mbuf_tso, mb,
    format_white_space, indent, mb->hash.rss, mb->hash.fdir.hi,
    mb->hash.fdir.lo);

  if (mb->ol_flags)
    s = format (s, "\n%U%U", format_white_space, indent,
		format_dpdk_pkt_offload_flags, &mb->ol_flags);

  if ((mb->ol_flags & RTE_MBUF_F_RX_VLAN) &&
      ((mb->ol_flags &
	(RTE_MBUF_F_RX_VLAN_STRIPPED | RTE_MBUF_F_RX_QINQ_STRIPPED)) == 0))
    {
      ethernet_vlan_header_tv_t *vlan_hdr =
	((ethernet_vlan_header_tv_t *) & (eth_hdr->type));
      s = format (s, " %U", format_dpdk_rte_mbuf_vlan, vlan_hdr);
    }

  if (mb->packet_type)
    s = format (s, "\n%U%U", format_white_space, indent,
		format_dpdk_pkt_types, &mb->packet_type);

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
#define _(n, f, s)                                 \
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


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
