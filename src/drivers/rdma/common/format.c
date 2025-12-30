/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <common/common.h>
#include <infiniband/verbs.h>
#include <vppinfra/format_ansi.h>
#include <vppinfra/format_table.h>
#include <vppinfra/pool.h>

u8 *
format_rdma_cap_list (u8 *s, vnet_dev_format_args_t *a, const rdma_cap_list_entry_t *caps_list,
		      u32 n_caps, u64 caps)
{
  u32 indent = format_get_indent (s);
  u32 line_len = indent;
  int first = 1;
  int no_color = a && a->no_color;

  for (u32 i = 0; i < n_caps; i++)
    {
      int on = (caps & caps_list[i].bit) != 0;
      u8 mark = on ? '+' : '-';
      u32 name_len = strlen (caps_list[i].name) + 1;
      if (first)
	{
	  if (no_color)
	    s = format (s, "%s%c", caps_list[i].name, mark);
	  else
	    s = format (s, "%s%s%c%s", on ? ANSI_FG_BR_GREEN : ANSI_FG_BR_RED, caps_list[i].name,
			mark, ANSI_RESET);
	  line_len += name_len;
	  first = 0;
	}
      else
	{
	  if (line_len + 1 + name_len > 100)
	    {
	      s = format_newline (s, indent);
	      if (no_color)
		s = format (s, "%s%c", caps_list[i].name, mark);
	      else
		s = format (s, "%s%s%c%s", on ? ANSI_FG_BR_GREEN : ANSI_FG_BR_RED,
			    caps_list[i].name, mark, ANSI_RESET);
	      line_len = indent + name_len;
	    }
	  else
	    {
	      if (no_color)
		s = format (s, " %s%c", caps_list[i].name, mark);
	      else
		s = format (s, " %s%s%c%s", on ? ANSI_FG_BR_GREEN : ANSI_FG_BR_RED,
			    caps_list[i].name, mark, ANSI_RESET);
	      line_len += 1 + name_len;
	    }
	}

      caps &= ~caps_list[i].bit;
    }

  if (caps)
    {
      u32 unknown_len = (sizeof ("unknown:0x") - 1) + 16;

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

      s = format (s, "unknown:0x%llx", (unsigned long long) caps);
      line_len += unknown_len;
      first = 0;
    }

  return s;
}

static u8 *
format_rdma_device_cap_flags (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  u64 flags = va_arg (*args, u64);
  rdma_cap_list_entry_t dev_caps[] = {
    { IBV_DEVICE_RESIZE_MAX_WR, "resize-max-wr" },
    { IBV_DEVICE_BAD_PKEY_CNTR, "bad-pkey-cntr" },
    { IBV_DEVICE_BAD_QKEY_CNTR, "bad-qkey-cntr" },
    { IBV_DEVICE_RAW_MULTI, "raw-multi" },
    { IBV_DEVICE_AUTO_PATH_MIG, "auto-path-mig" },
    { IBV_DEVICE_CHANGE_PHY_PORT, "change-phy-port" },
    { IBV_DEVICE_UD_AV_PORT_ENFORCE, "ud-av-port-enforce" },
    { IBV_DEVICE_CURR_QP_STATE_MOD, "curr-qp-state-mod" },
    { IBV_DEVICE_SHUTDOWN_PORT, "shutdown-port" },
    { IBV_DEVICE_INIT_TYPE, "init-type" },
    { IBV_DEVICE_PORT_ACTIVE_EVENT, "port-active-event" },
    { IBV_DEVICE_SYS_IMAGE_GUID, "sys-image-guid" },
    { IBV_DEVICE_RC_RNR_NAK_GEN, "rc-rnr-nak-gen" },
    { IBV_DEVICE_SRQ_RESIZE, "srq-resize" },
    { IBV_DEVICE_N_NOTIFY_CQ, "n-notify-cq" },
    { IBV_DEVICE_MEM_WINDOW, "mem-window" },
    { IBV_DEVICE_UD_IP_CSUM, "ud-ip-csum" },
    { IBV_DEVICE_XRC, "xrc" },
    { IBV_DEVICE_MEM_MGT_EXTENSIONS, "mem-mgt-extensions" },
    { IBV_DEVICE_MEM_WINDOW_TYPE_2A, "mem-window-type-2a" },
    { IBV_DEVICE_MEM_WINDOW_TYPE_2B, "mem-window-type-2b" },
    { IBV_DEVICE_RC_IP_CSUM, "rc-ip-csum" },
    { IBV_DEVICE_RAW_IP_CSUM, "raw-ip-csum" },
    { IBV_DEVICE_MANAGED_FLOW_STEERING, "managed-flow-steering" },
    { IBV_DEVICE_RAW_SCATTER_FCS, "raw-scatter-fcs" },
    { IBV_DEVICE_PCI_WRITE_END_PADDING, "pci-write-end-padding" },
  };

  s = format_rdma_cap_list (s, a, dev_caps, ARRAY_LEN (dev_caps), flags);

  return s;
}

static u8 *
format_rdma_rss_caps (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  u64 caps = va_arg (*args, u64);
  rdma_cap_list_entry_t rss_caps[] = {
    { IBV_RX_HASH_SRC_IPV4, "src-ipv4" },	  { IBV_RX_HASH_DST_IPV4, "dst-ipv4" },
    { IBV_RX_HASH_SRC_IPV6, "src-ipv6" },	  { IBV_RX_HASH_DST_IPV6, "dst-ipv6" },
    { IBV_RX_HASH_SRC_PORT_TCP, "src-port-tcp" }, { IBV_RX_HASH_DST_PORT_TCP, "dst-port-tcp" },
    { IBV_RX_HASH_SRC_PORT_UDP, "src-port-udp" }, { IBV_RX_HASH_DST_PORT_UDP, "dst-port-udp" },
    { IBV_RX_HASH_IPSEC_SPI, "ipsec-spi" },	  { IBV_RX_HASH_INNER, "inner" },
  };

  s = format_rdma_cap_list (s, a, rss_caps, ARRAY_LEN (rss_caps), caps);

  return s;
}

static u8 *
format_rdma_tso_caps (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  u64 caps = va_arg (*args, u32);
  rdma_cap_list_entry_t tso_caps[] = {
    { 1u << IBV_QPT_RC, "rc" },
    { 1u << IBV_QPT_UC, "uc" },
    { 1u << IBV_QPT_UD, "ud" },
    { 1u << IBV_QPT_RAW_PACKET, "raw-packet" },
    { 1u << IBV_QPT_XRC_SEND, "xrc-send" },
    { 1u << IBV_QPT_XRC_RECV, "xrc-recv" },
  };

  s = format_rdma_cap_list (s, a, tso_caps, ARRAY_LEN (tso_caps), caps);

  return s;
}

static u8 *
format_rdma_raw_packet_caps (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  u64 caps = va_arg (*args, u32);
  rdma_cap_list_entry_t raw_packet_caps[] = {
    { IBV_RAW_PACKET_CAP_CVLAN_STRIPPING, "cvlan-stripping" },
    { IBV_RAW_PACKET_CAP_SCATTER_FCS, "scatter-fcs" },
    { IBV_RAW_PACKET_CAP_IP_CSUM, "ip-csum" },
    { IBV_RAW_PACKET_CAP_DELAY_DROP, "delay-drop" },
  };

  s = format_rdma_cap_list (s, a, raw_packet_caps, ARRAY_LEN (raw_packet_caps), caps);

  return s;
}

static u8 *
format_rdma_rx_hash_fn (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  u64 fn = va_arg (*args, u32);
  rdma_cap_list_entry_t hash_fns[] = {
    { IBV_RX_HASH_FUNC_TOEPLITZ, "toeplitz" },
  };

  s = format_rdma_cap_list (s, a, hash_fns, ARRAY_LEN (hash_fns), fn);

  return s;
}

static u8 *
format_rdma_odp_transport_caps (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  u64 caps = va_arg (*args, u32);
  rdma_cap_list_entry_t odp_bits[] = {
    { IBV_ODP_SUPPORT_SEND, "send" },	  { IBV_ODP_SUPPORT_RECV, "recv" },
    { IBV_ODP_SUPPORT_WRITE, "write" },	  { IBV_ODP_SUPPORT_READ, "read" },
    { IBV_ODP_SUPPORT_ATOMIC, "atomic" }, { IBV_ODP_SUPPORT_SRQ_RECV, "srq-recv" },
  };

  s = format_rdma_cap_list (s, a, odp_bits, ARRAY_LEN (odp_bits), caps);

  return s;
}

static u8 *
format_rdma_odp_general_caps (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  u64 caps = va_arg (*args, u64);
  rdma_cap_list_entry_t odp_general[] = {
    { IBV_ODP_SUPPORT, "support" },
    { IBV_ODP_SUPPORT_IMPLICIT, "implicit" },
  };

  s = format_rdma_cap_list (s, a, odp_general, ARRAY_LEN (odp_general), caps);

  return s;
}

u8 *
format_rdma_dev_attr_ex (u8 *s, va_list *args)
{
  struct ibv_device_attr_ex *dev_attr_ex = va_arg (*args, struct ibv_device_attr_ex *);

  s = format (s, "ibv attrs max_qp %u max_cq %u max_qp_wr %u max_cqe %u phys_ports %u",
	      dev_attr_ex->orig_attr.max_qp, dev_attr_ex->orig_attr.max_cq,
	      dev_attr_ex->orig_attr.max_qp_wr, dev_attr_ex->orig_attr.max_cqe,
	      dev_attr_ex->orig_attr.phys_port_cnt);
  s = format (
    s, ", rss supported_qpts 0x%x ind_tbl_sz %u fields 0x%llx func 0x%x",
    dev_attr_ex->rss_caps.supported_qpts, dev_attr_ex->rss_caps.max_rwq_indirection_table_size,
    (u64) dev_attr_ex->rss_caps.rx_hash_fields_mask, dev_attr_ex->rss_caps.rx_hash_function);

  return s;
}

u8 *
format_rdma_port_attr (u8 *s, va_list *args)
{
  u32 port_id = va_arg (*args, u32);
  struct ibv_port_attr *port_attr = va_arg (*args, struct ibv_port_attr *);

  s = format (s, "ibv port %u state %u link_layer %u max_mtu %u active_mtu %u max_msg_sz %u",
	      port_id, port_attr->state, port_attr->link_layer, port_attr->max_mtu,
	      port_attr->active_mtu, port_attr->max_msg_sz);

  return s;
}

u8 *
format_rdma_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  struct ibv_context *ctx = va_arg (*args, struct ibv_context *);
  struct ibv_device_attr_ex dev_attr_ex = {};
  u32 indent = format_get_indent (s);
  struct ibv_device_attr *oa;
  char *title = a->no_color ? 0 : ANSI_DIM;
  char *value = a->no_color ? 0 : ANSI_BOLD;
  int rv_ibv;

  rv_ibv = ibv_query_device_ex (ctx, 0, &dev_attr_ex);
  if (rv_ibv)
    return format (s, "ibv_query_device_ex failed rv %d", rv_ibv);

  oa = &dev_attr_ex.orig_attr;
  s = format (s, "hw_ver ");
  s = format_ansi (s, value, "%u", oa->hw_ver);
  s = format (s, ", fw_ver ");
  s = format_ansi (s, value, "%s", oa->fw_ver);

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
      s = format_ansi (s, title, "device_cap_flags_ex:");
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_rdma_device_cap_flags, a, dev_attr_ex.device_cap_flags_ex);
    }

  if (dev_attr_ex.odp_caps.general_caps)
    {
      s = format_newline (s, indent);
      s = format_ansi (s, title, "odp_caps:");
      s = format_newline (s, indent + 2);
      s = format_ansi (s, title, " general_caps:");
      s = format (s, " %U", format_rdma_odp_general_caps, a, dev_attr_ex.odp_caps.general_caps);
      s = format_newline (s, indent + 2);
      s = format_ansi (s, title, "per_transport_caps:");
      s = format_newline (s, indent + 4);
      s = format (s, "rc: %U", format_rdma_odp_transport_caps, a,
		  dev_attr_ex.odp_caps.per_transport_caps.rc_odp_caps);
      s = format_newline (s, indent + 4);
      s = format (s, "uc: %U", format_rdma_odp_transport_caps, a,
		  dev_attr_ex.odp_caps.per_transport_caps.uc_odp_caps);
      s = format_newline (s, indent + 4);
      s = format (s, "ud: %U", format_rdma_odp_transport_caps, a,
		  dev_attr_ex.odp_caps.per_transport_caps.ud_odp_caps);
    }

  if (dev_attr_ex.tm_caps.max_num_tags)
    {
      s = format_newline (s, indent);
      s = format_ansi (s, title, "tm_caps:");
      s = format (s, " max_num_tags %u, max_ops %u, max_sge %u, flags 0x%x",
		  dev_attr_ex.tm_caps.max_num_tags, dev_attr_ex.tm_caps.max_ops,
		  dev_attr_ex.tm_caps.max_sge, dev_attr_ex.tm_caps.flags);
    }

  if (dev_attr_ex.cq_mod_caps.max_cq_count || dev_attr_ex.cq_mod_caps.max_cq_period)
    {
      s = format_newline (s, indent);
      s = format_ansi (s, title, "cq_mod_caps:");
      s = format (s, " max_count ");
      s = format_ansi (s, value, "%u", dev_attr_ex.cq_mod_caps.max_cq_count);
      s = format (s, ", max_period ");
      s = format_ansi (s, value, "%u", dev_attr_ex.cq_mod_caps.max_cq_period);
    }

  if (dev_attr_ex.pci_atomic_caps.fetch_add || dev_attr_ex.pci_atomic_caps.swap ||
      dev_attr_ex.pci_atomic_caps.compare_swap)
    {
      s = format_newline (s, indent);
      s = format_ansi (s, title, "pci_atomic_caps:");
      s = format (s, " fetch_add 0x%x, swap 0x%x, compare_swap 0x%x",
		  dev_attr_ex.pci_atomic_caps.fetch_add, dev_attr_ex.pci_atomic_caps.swap,
		  dev_attr_ex.pci_atomic_caps.compare_swap);
    }

  if (dev_attr_ex.rss_caps.supported_qpts)
    {
      s = format_newline (s, indent);
      s = format_ansi (s, title, "rss_caps:");
      s = format_newline (s, indent + 2);
      s = format_ansi (s, title, "supported_qpts:");
      s = format (s, " %U", format_rdma_tso_caps, a, dev_attr_ex.rss_caps.supported_qpts);
      s = format_newline (s, indent + 2);
      s = format_ansi (s, title, "max_rwq_indirection_table_size:");
      s = format (s, " %u", dev_attr_ex.rss_caps.max_rwq_indirection_table_size);
      s = format_newline (s, indent + 2);
      s = format_ansi (s, title, "rx_hash_fields_mask:");
      s = format_newline (s, indent + 4);
      s = format (s, "%U", format_rdma_rss_caps, a, dev_attr_ex.rss_caps.rx_hash_fields_mask);
      s = format_newline (s, indent + 2);
      s = format_ansi (s, title, "rx_hash_function:");
      s = format (s, " %U", format_rdma_rx_hash_fn, a, (u32) dev_attr_ex.rss_caps.rx_hash_function);
    }

  if (dev_attr_ex.tso_caps.max_tso)
    {
      s = format_newline (s, indent);
      s = format_ansi (s, title, "tso_caps:");
      s = format_newline (s, indent + 2);
      s = format_ansi (s, title, "max_tso:");
      s = format (s, " %u", dev_attr_ex.tso_caps.max_tso);
      s = format_newline (s, indent + 2);
      s = format_ansi (s, title, "supported_qpts:");
      s = format (s, " %U", format_rdma_tso_caps, a, dev_attr_ex.tso_caps.supported_qpts);
    }

  if (dev_attr_ex.packet_pacing_caps.supported_qpts)
    {
      s = format_newline (s, indent);
      s = format_ansi (s, title, "packet_pacing_caps:");
      s = format_newline (s, indent + 2);
      s = format_ansi (s, title, "qp_rate_limit:");
      s = format (s, " min ");
      s = format_ansi (s, value, "%u", dev_attr_ex.packet_pacing_caps.qp_rate_limit_min);
      s = format (s, ", max ");
      s = format_ansi (s, value, "%u", dev_attr_ex.packet_pacing_caps.qp_rate_limit_max);
      s = format_newline (s, indent + 2);
      s = format_ansi (s, title, "supported_qpts:");
      s = format (s, " %U", format_rdma_tso_caps, a, dev_attr_ex.packet_pacing_caps.supported_qpts);
    }

  if (dev_attr_ex.raw_packet_caps)
    {
      s = format_newline (s, indent);
      s = format_ansi (s, title, "raw_packet_caps:");
      s = format (s, " %U", format_rdma_raw_packet_caps, a, dev_attr_ex.raw_packet_caps);
    }

  return s;
}

u8 *
format_rdma_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  struct ibv_context *ctx = va_arg (*args, struct ibv_context *);
  u32 port_id = va_arg (*args, u32);
  struct ibv_port_attr port_attr = {};
  const char *state = "unknown";
  const char *link_layer = "unknown";
  u32 width_lanes = 0;
  u32 speed_lane = 0;
  u32 speed = 0;
  char *value = (a && a->no_color == 0) ? ANSI_BOLD : 0;
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
  width_lanes = rdma_port_width_lanes (port_attr.active_width);
  speed_lane = rdma_port_speed (port_attr.active_speed);
  if (speed_lane)
    speed = width_lanes ? speed_lane * width_lanes : speed_lane;

  s = format (s, "state ");
  s = format_ansi (s, value, "%s", state);
  s = format (s, ", link-layer ");
  s = format_ansi (s, value, "%s", link_layer);
  if (port_attr.active_width)
    {
      if (width_lanes)
	{
	  s = format (s, ", active-width ");
	  s = format_ansi (s, value, "%ux", width_lanes);
	}
      else
	s = format (s, ", active-width %u", port_attr.active_width);
    }
  if (port_attr.active_speed)
    {
      if (speed)
	{
	  if (speed > 1000000)
	    {
	      u32 gbps = speed / 1000000;
	      u32 frac = (speed % 1000000) / 1000;

	      if (frac)
		{
		  s = format (s, ", active-speed ");
		  s = format_ansi (s, value, "%u.%03u Gbps", gbps, frac);
		}
	      else
		{
		  s = format (s, ", active-speed ");
		  s = format_ansi (s, value, "%u Gbps", gbps);
		}
	    }
	  else
	    {
	      s = format (s, ", active-speed ");
	      s = format_ansi (s, value, "%u Mbps", speed / 1000);
	    }
	}
      else
	s = format (s, ", active-speed %u", port_attr.active_speed);
    }

  return s;
}

static u8 *format_rdma_ibv_flow_spec_type (u8 *s, va_list *args);

u8 *
format_rdma_ibv_flow_spec (u8 *s, va_list *args)
{
  struct ibv_flow_spec *spec = va_arg (*args, struct ibv_flow_spec *);

  if (spec == 0)
    return format (s, "none");

  if (spec->hdr.type == IBV_FLOW_SPEC_ETH)
    {
      struct ibv_flow_spec_eth *eth = (struct ibv_flow_spec_eth *) spec;
      u8 zero_mac[6] = {};
      int not_first = 0;

      if (clib_memcmp (eth->mask.src_mac, zero_mac, sizeof (zero_mac)))
	s = format (s, "%ssrc:%U/%U", not_first++ ? "," : "", format_ethernet_address,
		    eth->val.src_mac, format_ethernet_address, eth->mask.src_mac);

      if (clib_memcmp (eth->mask.dst_mac, zero_mac, sizeof (zero_mac)))
	s = format (s, "%sdst:%U/%U", not_first++ ? "," : "", format_ethernet_address,
		    eth->val.dst_mac, format_ethernet_address, eth->mask.dst_mac);

      if (eth->mask.ether_type)
	s = format (s, "%setype:0x%04x", not_first++ ? "," : "", eth->val.ether_type);

      if (eth->mask.vlan_tag)
	s = format (s, "%svlan:%u", not_first++ ? "," : "", eth->val.vlan_tag);

      if (not_first == 0)
	s = format (s, "none");

      return s;
    }

  return format (s, "type:%U", format_rdma_ibv_flow_spec_type, (u32) spec->hdr.type);
}

static u8 *
format_rdma_ibv_flow_attr_type (u8 *s, va_list *args)
{
  u32 type = va_arg (*args, u32);
  static const char *flow_attr_types[] = {
    [IBV_FLOW_ATTR_NORMAL] = "normal",
    [IBV_FLOW_ATTR_ALL_DEFAULT] = "all-default",
    [IBV_FLOW_ATTR_MC_DEFAULT] = "mc-default",
    [IBV_FLOW_ATTR_SNIFFER] = "sniffer",
  };

  if (type < ARRAY_LEN (flow_attr_types) && flow_attr_types[type])
    return format (s, "%s", flow_attr_types[type]);

  return format (s, "unknown(%u)", type);
}

u8 *
format_rdma_ibv_flow_flags (u8 *s, va_list *args)
{
  u32 flags = va_arg (*args, u32);
  static rdma_cap_list_entry_t flow_flags[] = {
    { IBV_FLOW_ATTR_FLAGS_DONT_TRAP, "dont-trap" },
    { IBV_FLOW_ATTR_FLAGS_EGRESS, "egress" },
  };
  u8 *out = 0;
  u32 unknown = flags;

  for (u32 i = 0; i < ARRAY_LEN (flow_flags); i++)
    {
      if (flags & flow_flags[i].bit)
	{
	  out = format (out, "%s%s", out ? "," : "", flow_flags[i].name);
	  unknown &= ~flow_flags[i].bit;
	}
    }

  if (unknown)
    out = format (out, "%sunknown(0x%x)", out ? "," : "", unknown);

  if (out == 0)
    return format (s, "none");

  s = format (s, "%v", out);
  vec_free (out);
  return s;
}

static u8 *
format_rdma_ibv_flow_spec_type (u8 *s, va_list *args)
{
  u32 type = va_arg (*args, u32);
  static const char *flow_spec_types[] = {
    [IBV_FLOW_SPEC_ETH] = "eth",
    [IBV_FLOW_SPEC_IPV4] = "ipv4",
    [IBV_FLOW_SPEC_IPV6] = "ipv6",
    [IBV_FLOW_SPEC_IPV4_EXT] = "ipv4-ext",
    [IBV_FLOW_SPEC_ESP] = "esp",
    [IBV_FLOW_SPEC_TCP] = "tcp",
    [IBV_FLOW_SPEC_UDP] = "udp",
    [IBV_FLOW_SPEC_VXLAN_TUNNEL] = "vxlan-tunnel",
    [IBV_FLOW_SPEC_GRE] = "gre",
    [IBV_FLOW_SPEC_MPLS] = "mpls",
    [IBV_FLOW_SPEC_INNER] = "inner",
    [IBV_FLOW_SPEC_ACTION_TAG] = "action-tag",
    [IBV_FLOW_SPEC_ACTION_DROP] = "action-drop",
    [IBV_FLOW_SPEC_ACTION_HANDLE] = "action-handle",
    [IBV_FLOW_SPEC_ACTION_COUNT] = "action-count",
  };

  if (type < ARRAY_LEN (flow_spec_types) && flow_spec_types[type])
    return format (s, "%s", flow_spec_types[type]);

  return format (s, "unknown(%u)", type);
}

u8 *
format_rdma_rxq_flows (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  rdma_rx_flow_t **flows = va_arg (*args, rdma_rx_flow_t **);
  table_t table = {}, *t = &table;
  u32 row = 0;
  u32 i;

  t->default_header_col.align = TTAA_LEFT;
  if (a->no_color == 0)
    {
      t->default_header_row.flags |= TTAF_FG_COLOR_SET;
      t->default_header_row.fg_color = TTAC_CYAN;
      t->default_header_col.flags |= TTAF_FG_COLOR_SET;
      t->default_header_col.fg_color = TTAC_CYAN;
    }
  t->default_body.align = TTAA_LEFT;
  table_add_header_col (t, 7, "idx", "type", "pri", "port", "spec-type", "spec", "flags");

  pool_foreach_index (i, flows)
    {
      rdma_rx_flow_t **fp = pool_elt_at_index (flows, i);
      rdma_rx_flow_t *f = fp[0];

      if (f == 0)
	continue;

      table_format_cell (t, row, 0, "%u", f->pool_index);
      table_format_cell (t, row, 1, "%U", format_rdma_ibv_flow_attr_type, (u32) f->attr.type);
      table_format_cell (t, row, 2, "%u", f->attr.priority);
      table_format_cell (t, row, 3, "%u", f->attr.port);
      table_format_cell (t, row, 4, "%U", format_rdma_ibv_flow_spec_type, (u32) f->spec.hdr.type);
      table_format_cell (t, row, 5, "%U", format_rdma_ibv_flow_spec, &f->spec);
      table_format_cell (t, row, 6, "%U", format_rdma_ibv_flow_flags, f->attr.flags);
      row++;
    }

  if (row == 0)
    s = format (s, "no active flows");
  else
    s = format (s, "%U", format_table, t);

  table_free (t);

  return s;
}
