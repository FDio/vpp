/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <ibverbs.h>

typedef struct
{
  u64 bit;
  const char *name;
} ibv_cap_list_entry_t;

static u8 *
format_ibv_wc (u8 *s, va_list *args)
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
format_ibv_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  ibv_rx_trace_t *t = va_arg (*args, ibv_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);
  u32 indent = format_get_indent (s);

  s = format (s, "ibverbs: %v (%d) qid %u next-node %U", hi->name, t->hw_if_index, t->qid,
	      format_vlib_next_node_name, vm, node->index, t->next_index);
  s = format_newline (s, indent);
  s = format (s, "wc: %U", format_ibv_wc, &t->wc);

  return s;
}

u8 *
format_ibv_tx_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  ibv_tx_trace_t *t = va_arg (*args, ibv_tx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);

  s = format (s, "ibverbs-tx: %v (%u) qid %u buffer %u len %u n_sge %u send_flags 0x%x dropped %u",
	      hi->name, t->hw_if_index, t->qid, t->buffer_index, t->data_len, t->n_sge,
	      t->send_flags, t->dropped);
  return s;
}

u8 *
format_ibv_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  ibv_dev_t *rd = vnet_dev_get_data (port->dev);
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

  rv_ibv = ibv_query_port (rd->ctx, port->port_id, &port_attr);
  if (rv_ibv)
    return format (s, "ibv_query_port failed rv %d", rv_ibv);

  if (port_attr.state < ARRAY_LEN (state_str) && state_str[port_attr.state])
    state = state_str[port_attr.state];
  if (port_attr.link_layer < ARRAY_LEN (link_layer_str) && link_layer_str[port_attr.link_layer])
    link_layer = link_layer_str[port_attr.link_layer];
  if (port_attr.active_speed)
    speed = ibv_port_speed (port_attr.active_speed);

  s = format (s, "state %s, link-layer %s", state, link_layer);
  if (port_attr.active_width)
    s = format (s, ", active-width %u", port_attr.active_width);
  if (port_attr.active_speed)
    {
      if (speed)
	s = format (s, ", active-speed %u Mbps", speed);
      else
	s = format (s, ", active-speed %u", port_attr.active_speed);
    }
  if (port_attr.active_mtu)
    s = format (s, ", mtu %u", ibv_port_mtu (port_attr.active_mtu));
  return s;
}

static u8 *
format_ibv_cap_list (u8 *s, const ibv_cap_list_entry_t *caps_list, u32 n_caps, u64 caps)
{
  u32 indent = format_get_indent (s);
  u32 line_len = indent;
  int first = 1;

  for (u32 i = 0; i < n_caps; i++)
    {
      u32 name_len = strlen (caps_list[i].name) + 1;
      if (first)
	{
	  s = format (s, "%s%c", caps_list[i].name, (caps & caps_list[i].bit) ? '+' : '-');
	  line_len += name_len;
	  first = 0;
	}
      else
	{
	  if (line_len + 1 + name_len > 100)
	    {
	      s = format_newline (s, indent);
	      s = format (s, "%s%c", caps_list[i].name, (caps & caps_list[i].bit) ? '+' : '-');
	      line_len = indent + name_len;
	    }
	  else
	    {
	      s = format (s, " %s%c", caps_list[i].name, (caps & caps_list[i].bit) ? '+' : '-');
	      line_len += 1 + name_len;
	    }
	}

      caps &= ~caps_list[i].bit;
    }

  while (caps)
    {
      u32 unknown_len = (sizeof ("unknown()") - 1) + 2 + 1;
      u32 bit = get_lowest_set_bit_index (caps);

      caps &= ~(1ULL << bit);
      if (!first && line_len + 1 + unknown_len > 100)
	{
	  s = format_newline (s, indent);
	  line_len = indent;
	  first = 1;
	}
      else if (!first)
	{
	  vec_add1 (s, ' ');
	  line_len += 1;
	}

      s = format (s, "unknown(%u)+", bit);
      line_len += unknown_len;
      first = 0;
    }

  return s;
}

static u8 *
format_ibv_device_cap_flags (u8 *s, va_list *args)
{
  u64 flags = va_arg (*args, u64);
  ibv_cap_list_entry_t dev_caps[] = {
#define _(f, n)                                                                                    \
  {                                                                                                \
    IBV_DEVICE_##f,                                                                                \
    n,                                                                                             \
  },
    foreach_ibv_device_cap_flags
#undef _
  };

  s = format_ibv_cap_list (s, dev_caps, ARRAY_LEN (dev_caps), flags);

  return s;
}

static u8 *
format_ibv_rss_caps (u8 *s, va_list *args)
{
  u64 caps = va_arg (*args, u64);
  ibv_cap_list_entry_t rss_caps[] = {
    { IBV_RX_HASH_SRC_IPV4, "src-ipv4" },	  { IBV_RX_HASH_DST_IPV4, "dst-ipv4" },
    { IBV_RX_HASH_SRC_IPV6, "src-ipv6" },	  { IBV_RX_HASH_DST_IPV6, "dst-ipv6" },
    { IBV_RX_HASH_SRC_PORT_TCP, "src-port-tcp" }, { IBV_RX_HASH_DST_PORT_TCP, "dst-port-tcp" },
    { IBV_RX_HASH_SRC_PORT_UDP, "src-port-udp" }, { IBV_RX_HASH_DST_PORT_UDP, "dst-port-udp" },
    { IBV_RX_HASH_IPSEC_SPI, "ipsec-spi" },	  { IBV_RX_HASH_INNER, "inner" },
  };

  s = format_ibv_cap_list (s, rss_caps, ARRAY_LEN (rss_caps), caps);

  return s;
}

static u8 *
format_ibv_tso_caps (u8 *s, va_list *args)
{
  u64 caps = va_arg (*args, u32);
  ibv_cap_list_entry_t tso_caps[] = {
    { 1u << IBV_QPT_RC, "rc" },
    { 1u << IBV_QPT_UC, "uc" },
    { 1u << IBV_QPT_UD, "ud" },
    { 1u << IBV_QPT_RAW_PACKET, "raw-packet" },
    { 1u << IBV_QPT_XRC_SEND, "xrc-send" },
    { 1u << IBV_QPT_XRC_RECV, "xrc-recv" },
  };

  s = format_ibv_cap_list (s, tso_caps, ARRAY_LEN (tso_caps), caps);

  return s;
}

static u8 *
format_ibv_raw_packet_caps (u8 *s, va_list *args)
{
  u64 caps = va_arg (*args, u32);
  ibv_cap_list_entry_t raw_packet_caps[] = {
    { IBV_RAW_PACKET_CAP_CVLAN_STRIPPING, "cvlan-stripping" },
    { IBV_RAW_PACKET_CAP_SCATTER_FCS, "scatter-fcs" },
    { IBV_RAW_PACKET_CAP_IP_CSUM, "ip-csum" },
    { IBV_RAW_PACKET_CAP_DELAY_DROP, "delay-drop" },
  };

  s = format_ibv_cap_list (s, raw_packet_caps, ARRAY_LEN (raw_packet_caps), caps);

  return s;
}

static u8 *
format_ibv_rx_hash_fn (u8 *s, va_list *args)
{
  u64 fn = va_arg (*args, u32);
  ibv_cap_list_entry_t hash_fns[] = {
    { IBV_RX_HASH_FUNC_TOEPLITZ, "toeplitz" },
  };

  s = format_ibv_cap_list (s, hash_fns, ARRAY_LEN (hash_fns), fn);

  return s;
}

static u8 *
format_ibv_odp_transport_caps (u8 *s, va_list *args)
{
  u64 caps = va_arg (*args, u32);
  ibv_cap_list_entry_t odp_bits[] = {
    { IBV_ODP_SUPPORT_SEND, "send" },	  { IBV_ODP_SUPPORT_RECV, "recv" },
    { IBV_ODP_SUPPORT_WRITE, "write" },	  { IBV_ODP_SUPPORT_READ, "read" },
    { IBV_ODP_SUPPORT_ATOMIC, "atomic" }, { IBV_ODP_SUPPORT_SRQ_RECV, "srq-recv" },
  };

  s = format_ibv_cap_list (s, odp_bits, ARRAY_LEN (odp_bits), caps);

  return s;
}

u8 *
format_ibv_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  ibv_dev_t *rd = vnet_dev_get_data (dev);
  struct ibv_device_attr_ex dev_attr_ex = {};
  u32 indent = format_get_indent (s);
  struct ibv_device_attr *oa;
  int rv_ibv = ibv_query_device_ex (rd->ctx, 0, &dev_attr_ex);

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
      s = format (s, "%U", format_ibv_device_cap_flags, dev_attr_ex.device_cap_flags_ex);
    }

  if (dev_attr_ex.odp_caps.general_caps)
    {
      s = format_newline (s, indent);
      s = format (s, "odp_caps: general_caps 0x%llx",
		  (unsigned long long) dev_attr_ex.odp_caps.general_caps);
      s = format_newline (s, indent + 2);
      s = format (s, "per_transport_caps:");
      s = format_newline (s, indent + 4);
      s = format (s, "rc: %U", format_ibv_odp_transport_caps,
		  dev_attr_ex.odp_caps.per_transport_caps.rc_odp_caps);
      s = format_newline (s, indent + 4);
      s = format (s, "uc: %U", format_ibv_odp_transport_caps,
		  dev_attr_ex.odp_caps.per_transport_caps.uc_odp_caps);
      s = format_newline (s, indent + 4);
      s = format (s, "ud: %U", format_ibv_odp_transport_caps,
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
      s =
	format (s, "supported_qpts: %U", format_ibv_tso_caps, dev_attr_ex.rss_caps.supported_qpts);
      s = format_newline (s, indent + 2);
      s = format (s, "max_rwq_indirection_table_size %u",
		  dev_attr_ex.rss_caps.max_rwq_indirection_table_size);
      s = format_newline (s, indent + 2);
      s = format (s, "rx_hash_fields_mask:");
      s = format_newline (s, indent + 4);
      s = format (s, "%U", format_ibv_rss_caps, dev_attr_ex.rss_caps.rx_hash_fields_mask);
      s = format_newline (s, indent + 2);
      s = format (s, "rx_hash_function: %U", format_ibv_rx_hash_fn,
		  (u32) dev_attr_ex.rss_caps.rx_hash_function);
    }

  if (dev_attr_ex.tso_caps.max_tso)
    {
      s = format_newline (s, indent);
      s = format (s, "tso_caps:");
      s = format_newline (s, indent + 2);
      s = format (s, "max_tso %u", dev_attr_ex.tso_caps.max_tso);
      s = format_newline (s, indent + 2);
      s =
	format (s, "supported_qpts: %U", format_ibv_tso_caps, dev_attr_ex.tso_caps.supported_qpts);
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
      s = format (s, "supported_qpts: %U", format_ibv_tso_caps,
		  dev_attr_ex.packet_pacing_caps.supported_qpts);
    }

  if (dev_attr_ex.raw_packet_caps)
    {
      s = format_newline (s, indent);
      s =
	format (s, "raw_packet_caps: %U", format_ibv_raw_packet_caps, dev_attr_ex.raw_packet_caps);
    }

  return s;
}
