/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <rdma/common.h>
#include <infiniband/verbs.h>
#include <vppinfra/pool.h>
#include <vppinfra/format_table.h>
#include <vnet/devices/netlink.h>
#include <net/if.h>

u8 *
format_rdma_ibv_wc (u8 *s, va_list *args)
{
  struct ibv_wc *wc = va_arg (*args, struct ibv_wc *);
  u32 indent = format_get_indent (s);

  s = format (s, "wr_id 0x%llx status %u opcode %u vendor_err 0x%x byte_len %u qp_num %u",
	      (unsigned long long) wc->wr_id, wc->status, wc->opcode, wc->vendor_err, wc->byte_len,
	      wc->qp_num);
  s = format_newline (s, indent);
  s = format (s, "src_qp %u wc_flags 0x%x pkey_index %u sl %u slid %u dlid_path_bits %u",
	      wc->src_qp, wc->wc_flags, wc->pkey_index, wc->sl, wc->slid, wc->dlid_path_bits);

  if (wc->wc_flags & IBV_WC_WITH_IMM)
    s = format (s, " imm_data 0x%x", wc->imm_data);

  if (wc->wc_flags & IBV_WC_WITH_INV)
    s = format (s, " invalidated_rkey 0x%x", wc->invalidated_rkey);

  return s;
}

u8 *
format_rdma_port_status (u8 *s, va_list *args)
{
  struct ibv_context *ctx = va_arg (*args, struct ibv_context *);
  u32 port_id = va_arg (*args, u32);
  u32 netdev_ifindex = va_arg (*args, u32);
  u32 indent = format_get_indent (s);
  struct ibv_port_attr port_attr = {};
  const char *state = "unknown";
  const char *link_layer = "unknown";
  u32 speed = 0;
  int rv_ibv;

  static const char *state_str[] = {
    [IBV_PORT_DOWN] = "down",
    [IBV_PORT_INIT] = "init",
    [IBV_PORT_ARMED] = "armed",
    [IBV_PORT_ACTIVE] = "active",
  };
  static const char *link_layer_str[] = {
    [IBV_LINK_LAYER_UNSPECIFIED] = "unspecified",
    [IBV_LINK_LAYER_INFINIBAND] = "infiniband",
    [IBV_LINK_LAYER_ETHERNET] = "ethernet",
  };

  rv_ibv = ibv_query_port (ctx, port_id, &port_attr);
  if (rv_ibv)
    return format (s, "ibv_query_port failed rv %d", rv_ibv);

  if (port_attr.state < ARRAY_LEN (state_str) && state_str[port_attr.state])
    state = state_str[port_attr.state];
  if (port_attr.link_layer < ARRAY_LEN (link_layer_str) && link_layer_str[port_attr.link_layer])
    link_layer = link_layer_str[port_attr.link_layer];
  speed = rdma_port_speed (&port_attr);

  s = format (s, "state %s, link-layer %s", state, link_layer);
  if (port_attr.active_width)
    s = format (s, ", active-width %u", port_attr.active_width);
  if (speed)
    s = format (s, ", speed %u Mbps", speed / 1000);
  else if (port_attr.active_speed || port_attr.active_speed_ex)
    s = format (s, ", active-speed %u/%u", port_attr.active_speed, port_attr.active_speed_ex);

  if (netdev_ifindex)
    {
      char name[IF_NAMESIZE] = {};
      u32 mtu = 0;
      clib_error_t *err = vnet_netlink_get_link_mtu (netdev_ifindex, &mtu);

      clib_error_free (err);
      s = format_newline (s, indent);
      s = format (s, "kernel netdev %s (ifindex %u), mtu %u", if_indextoname (netdev_ifindex, name),
		  netdev_ifindex, mtu);
    }

  return s;
}

u8 *
format_rdma_rss_flows (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  rdma_rss_t *rss = va_arg (*args, rdma_rss_t *);
  u32 row = 0, idx, indent = format_get_indent (s);
  table_t t = {};

  table_add_hdr_col (&t, 1, "");
  table_add_hdr_row (&t, 8, "id", "qp", "prio", "dst-mac", "mask", "etype", "mask", "action");

  for (u32 i = 0; i < ARRAY_LEN (rss->qp); i++)
    pool_foreach_index (idx, rss->qp[i].flows)
      {
	rdma_rx_flow_t *f = rss->qp[i].flows[idx];
	char *action;
	u32 unknown;

	if (f == 0)
	  continue;

	unknown = f->attr.flags & ~IBV_FLOW_ATTR_FLAGS_DONT_TRAP;
	action = (f->attr.flags & IBV_FLOW_ATTR_FLAGS_DONT_TRAP) ? "pass" : "trap";
	table_format_cell (&t, row, -1, "%u", f->pool_index);
	table_format_cell (&t, row, 0, "%s", i == RDMA_RSS_IP6 ? "ip6" : "default");
	table_format_cell (&t, row, 1, "%u", f->attr.priority);
	table_format_cell (&t, row, 2, "%U", format_ethernet_address, f->spec.eth.val.dst_mac);
	table_format_cell (&t, row, 3, "%U", format_ethernet_address, f->spec.eth.mask.dst_mac);
	table_format_cell (&t, row, 4, "0x%04x", clib_net_to_host_u16 (f->spec.eth.val.ether_type));
	table_format_cell (&t, row, 5, "0x%04x",
			   clib_net_to_host_u16 (f->spec.eth.mask.ether_type));
	if (unknown)
	  table_format_cell (&t, row, 6, "%s unknown-flags 0x%x", action, unknown);
	else
	  table_format_cell (&t, row, 6, "%s", action);
	table_set_cell_align (&t, row, 0, TTAA_LEFT);
	table_set_cell_align (&t, row, 6, TTAA_LEFT);
	row++;
      }

  if (row)
    {
      s = format (s, "rx flows:");
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_table, &t);
    }
  else
    s = format (s, "rx flows: none");
  table_free (&t);
  return s;
}

static u8 *
rdma_cap_list_format (u8 *s, const rdma_cap_name_t *caps_list, u32 n_caps, u64 caps)
{
  for (u32 i = 0; i < n_caps; i++)
    {
      s = format (s, "%s%s%c", i ? " " : "", caps_list[i].name,
		  (caps & caps_list[i].bit) ? '+' : '-');
      caps &= ~caps_list[i].bit;
    }

  while (caps)
    {
      u32 bit = get_lowest_set_bit_index (caps);

      caps &= ~(1ULL << bit);
      s = format (s, " unknown(%u)+", bit);
    }

  return format_word_wrap_last_line_with_indent (s, 100, 2);
}

u8 *
format_rdma_cap_list (u8 *s, va_list *args)
{
  rdma_cap_name_t *names = va_arg (*args, rdma_cap_name_t *);
  u32 n_names = va_arg (*args, u32);
  u64 caps = va_arg (*args, u64);

  return rdma_cap_list_format (s, names, n_names, caps);
}

static u8 *
format_rdma_ibv_device_cap_flags (u8 *s, va_list *args)
{
  u64 flags = va_arg (*args, u64);
  rdma_cap_name_t dev_caps[] = {
#define _(f, n)                                                                                    \
  {                                                                                                \
    IBV_DEVICE_##f,                                                                                \
    n,                                                                                             \
  },
    foreach_rdma_ibv_device_cap_flags
#undef _
    /* kernel uverbs bits without a libibverbs name */
    { 1ULL << 38, "flush-global" },
    { 1ULL << 39, "flush-persistent" },
    { 1ULL << 40, "atomic-write" },
    { 1ULL << 41, "cc-dma-bounce" },
    /* MLNX-OFED private kernel bits, passed through by its uverbs */
    { 1ULL << 60, "nvmf-target-offload" },
    { 1ULL << 61, "qp-modify-rmp" },
  };

  s = rdma_cap_list_format (s, dev_caps, ARRAY_LEN (dev_caps), flags);

  return s;
}

static u8 *
format_rdma_ibv_rss_caps (u8 *s, va_list *args)
{
  u64 caps = va_arg (*args, u64);
  rdma_cap_name_t rss_caps[] = {
    { IBV_RX_HASH_SRC_IPV4, "src-ipv4" },	  { IBV_RX_HASH_DST_IPV4, "dst-ipv4" },
    { IBV_RX_HASH_SRC_IPV6, "src-ipv6" },	  { IBV_RX_HASH_DST_IPV6, "dst-ipv6" },
    { IBV_RX_HASH_SRC_PORT_TCP, "src-port-tcp" }, { IBV_RX_HASH_DST_PORT_TCP, "dst-port-tcp" },
    { IBV_RX_HASH_SRC_PORT_UDP, "src-port-udp" }, { IBV_RX_HASH_DST_PORT_UDP, "dst-port-udp" },
    { IBV_RX_HASH_IPSEC_SPI, "ipsec-spi" },	  { IBV_RX_HASH_INNER, "inner" },
  };

  s = rdma_cap_list_format (s, rss_caps, ARRAY_LEN (rss_caps), caps);

  return s;
}

static u8 *
format_rdma_ibv_tso_caps (u8 *s, va_list *args)
{
  u64 caps = va_arg (*args, u32);
  rdma_cap_name_t tso_caps[] = {
    { 1u << IBV_QPT_RC, "rc" },
    { 1u << IBV_QPT_UC, "uc" },
    { 1u << IBV_QPT_UD, "ud" },
    { 1u << IBV_QPT_RAW_PACKET, "raw-packet" },
    { 1u << IBV_QPT_XRC_SEND, "xrc-send" },
    { 1u << IBV_QPT_XRC_RECV, "xrc-recv" },
  };

  s = rdma_cap_list_format (s, tso_caps, ARRAY_LEN (tso_caps), caps);

  return s;
}

static u8 *
format_rdma_ibv_raw_packet_caps (u8 *s, va_list *args)
{
  u64 caps = va_arg (*args, u32);
  rdma_cap_name_t raw_packet_caps[] = {
    { IBV_RAW_PACKET_CAP_CVLAN_STRIPPING, "cvlan-stripping" },
    { IBV_RAW_PACKET_CAP_SCATTER_FCS, "scatter-fcs" },
    { IBV_RAW_PACKET_CAP_IP_CSUM, "ip-csum" },
    { IBV_RAW_PACKET_CAP_DELAY_DROP, "delay-drop" },
  };

  s = rdma_cap_list_format (s, raw_packet_caps, ARRAY_LEN (raw_packet_caps), caps);

  return s;
}

static u8 *
format_rdma_ibv_rx_hash_fn (u8 *s, va_list *args)
{
  u64 fn = va_arg (*args, u32);
  rdma_cap_name_t hash_fns[] = {
    { IBV_RX_HASH_FUNC_TOEPLITZ, "toeplitz" },
  };

  s = rdma_cap_list_format (s, hash_fns, ARRAY_LEN (hash_fns), fn);

  return s;
}

static u8 *
format_rdma_ibv_odp_transport_caps (u8 *s, va_list *args)
{
  u64 caps = va_arg (*args, u32);
  rdma_cap_name_t odp_bits[] = {
    { IBV_ODP_SUPPORT_SEND, "send" },	  { IBV_ODP_SUPPORT_RECV, "recv" },
    { IBV_ODP_SUPPORT_WRITE, "write" },	  { IBV_ODP_SUPPORT_READ, "read" },
    { IBV_ODP_SUPPORT_ATOMIC, "atomic" }, { IBV_ODP_SUPPORT_SRQ_RECV, "srq-recv" },
  };

  s = rdma_cap_list_format (s, odp_bits, ARRAY_LEN (odp_bits), caps);

  return s;
}

u8 *
format_rdma_ibv_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  struct ibv_context *ctx = va_arg (*args, struct ibv_context *);
  struct ibv_device_attr_ex dev_attr_ex = {};
  u32 indent = format_get_indent (s);
  struct ibv_device_attr *oa;
  int rv_ibv = ibv_query_device_ex (ctx, 0, &dev_attr_ex);

  if (rv_ibv)
    return format (s, "ibv_query_device_ex failed rv %d", rv_ibv);

  oa = &dev_attr_ex.orig_attr;
  s = format (s, "hw_ver %u, fw_ver %s", oa->hw_ver, oa->fw_ver);

  if (a->debug > 0)
    {
      s = format_newline (s, indent);
      s = format (s, "max_qp %u, max_qp_wr %u, max_sge %u, max_sge_rd %u", oa->max_qp,
		  oa->max_qp_wr, oa->max_sge, oa->max_sge_rd);

      s = format_newline (s, indent);
      s = format (s, "max_cq %u, max_cqe %u, max_mr %u, max_pd %u", oa->max_cq, oa->max_cqe,
		  oa->max_mr, oa->max_pd);

      s = format_newline (s, indent);
      s = format (s, "max_mr_size %llu, page_size_cap 0x%llx, phys_port_cnt %u",
		  (unsigned long long) oa->max_mr_size, (unsigned long long) oa->page_size_cap,
		  oa->phys_port_cnt);

      s = format_newline (s, indent);
      s = format (s, "completion_timestamp_mask 0x%llx, hca_core_clock %llu",
		  (unsigned long long) dev_attr_ex.completion_timestamp_mask,
		  (unsigned long long) dev_attr_ex.hca_core_clock);

      s = format_newline (s, indent);
      s = format (s, "max_wq_type_rq %u, max_dm_size %llu, phys_port_cnt_ex %u",
		  dev_attr_ex.max_wq_type_rq, (unsigned long long) dev_attr_ex.max_dm_size,
		  dev_attr_ex.phys_port_cnt_ex);
    }

  if (dev_attr_ex.device_cap_flags_ex)
    {
      s = format_newline (s, indent);
      s = format (s, "device_cap_flags_ex:");
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_rdma_ibv_device_cap_flags, dev_attr_ex.device_cap_flags_ex);
    }

  if (dev_attr_ex.odp_caps.general_caps)
    {
      s = format_newline (s, indent);
      s = format (s, "odp_caps: general_caps 0x%llx",
		  (unsigned long long) dev_attr_ex.odp_caps.general_caps);
      s = format_newline (s, indent + 2);
      s = format (s, "per_transport_caps:");
      s = format_newline (s, indent + 4);
      s = format (s, "rc: %U", format_rdma_ibv_odp_transport_caps,
		  dev_attr_ex.odp_caps.per_transport_caps.rc_odp_caps);
      s = format_newline (s, indent + 4);
      s = format (s, "uc: %U", format_rdma_ibv_odp_transport_caps,
		  dev_attr_ex.odp_caps.per_transport_caps.uc_odp_caps);
      s = format_newline (s, indent + 4);
      s = format (s, "ud: %U", format_rdma_ibv_odp_transport_caps,
		  dev_attr_ex.odp_caps.per_transport_caps.ud_odp_caps);
    }

  if (dev_attr_ex.tm_caps.max_num_tags)
    {
      s = format_newline (s, indent);
      s = format (s, "tm_caps: max_num_tags %u, max_ops %u, max_sge %u, flags 0x%x",
		  dev_attr_ex.tm_caps.max_num_tags, dev_attr_ex.tm_caps.max_ops,
		  dev_attr_ex.tm_caps.max_sge, dev_attr_ex.tm_caps.flags);
    }

  if (dev_attr_ex.cq_mod_caps.max_cq_count || dev_attr_ex.cq_mod_caps.max_cq_period)
    {
      s = format_newline (s, indent);
      s = format (s, "cq_mod_caps: max_count %u, max_period %u",
		  dev_attr_ex.cq_mod_caps.max_cq_count, dev_attr_ex.cq_mod_caps.max_cq_period);
    }

  if (dev_attr_ex.pci_atomic_caps.fetch_add || dev_attr_ex.pci_atomic_caps.swap ||
      dev_attr_ex.pci_atomic_caps.compare_swap)
    {
      s = format_newline (s, indent);
      s = format (s, "pci_atomic_caps: fetch_add 0x%x, swap 0x%x, compare_swap 0x%x",
		  dev_attr_ex.pci_atomic_caps.fetch_add, dev_attr_ex.pci_atomic_caps.swap,
		  dev_attr_ex.pci_atomic_caps.compare_swap);
    }

  if (dev_attr_ex.rss_caps.supported_qpts)
    {
      s = format_newline (s, indent);
      s = format (s, "rss_caps:");
      s = format_newline (s, indent + 2);
      s = format (s, "supported_qpts: %U", format_rdma_ibv_tso_caps,
		  dev_attr_ex.rss_caps.supported_qpts);
      s = format_newline (s, indent + 2);
      s = format (s, "max_rwq_indirection_table_size %u",
		  dev_attr_ex.rss_caps.max_rwq_indirection_table_size);
      s = format_newline (s, indent + 2);
      s = format (s, "rx_hash_fields_mask:");
      s = format_newline (s, indent + 4);
      s = format (s, "%U", format_rdma_ibv_rss_caps, dev_attr_ex.rss_caps.rx_hash_fields_mask);
      s = format_newline (s, indent + 2);
      s = format (s, "rx_hash_function: %U", format_rdma_ibv_rx_hash_fn,
		  (u32) dev_attr_ex.rss_caps.rx_hash_function);
    }

  if (dev_attr_ex.tso_caps.max_tso)
    {
      s = format_newline (s, indent);
      s = format (s, "tso_caps:");
      s = format_newline (s, indent + 2);
      s = format (s, "max_tso %u", dev_attr_ex.tso_caps.max_tso);
      s = format_newline (s, indent + 2);
      s = format (s, "supported_qpts: %U", format_rdma_ibv_tso_caps,
		  dev_attr_ex.tso_caps.supported_qpts);
    }

  if (dev_attr_ex.packet_pacing_caps.supported_qpts)
    {
      s = format_newline (s, indent);
      s = format (s, "packet_pacing_caps:");
      s = format_newline (s, indent + 2);
      s = format (s, "qp_rate_limit_min %u, qp_rate_limit_max %u",
		  dev_attr_ex.packet_pacing_caps.qp_rate_limit_min,
		  dev_attr_ex.packet_pacing_caps.qp_rate_limit_max);
      s = format_newline (s, indent + 2);
      s = format (s, "supported_qpts: %U", format_rdma_ibv_tso_caps,
		  dev_attr_ex.packet_pacing_caps.supported_qpts);
    }

  if (dev_attr_ex.raw_packet_caps)
    {
      s = format_newline (s, indent);
      s = format (s, "raw_packet_caps: %U", format_rdma_ibv_raw_packet_caps,
		  dev_attr_ex.raw_packet_caps);
    }

  return s;
}
