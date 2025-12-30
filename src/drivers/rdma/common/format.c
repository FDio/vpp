/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <common/common.h>
#include <infiniband/verbs.h>
#include <vppinfra/format_table.h>
#include <vppinfra/pool.h>

u8 *
rdma_format_ibv_wc (u8 *s, va_list *args)
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
  if (port_attr.active_speed)
    speed = rdma_port_speed (port_attr.active_speed);

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
    s = format (s, ", mtu %u", rdma_port_mtu (port_attr.active_mtu));

  return s;
}

u8 *
format_rdma_rxq_flows (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a __clib_unused = va_arg (*args, vnet_dev_format_args_t *);
  rdma_rx_flow_t **flows = va_arg (*args, rdma_rx_flow_t **);
  table_t table = {}, *t = &table;
  u32 row = 0;
  u32 i;

  table_add_header_col (t, 7, "index", "dst-mac", "mask", "ether-type", "ether-type-mask", "action",
			"flags");
  t->default_header_col.align = TTAA_LEFT;
  t->default_body.align = TTAA_LEFT;

  pool_foreach_index (i, flows)
    {
      rdma_rx_flow_t **fp = pool_elt_at_index (flows, i);
      rdma_rx_flow_t *f = fp[0];
      const char *action;
      u8 *flags = 0;

      if (f == 0)
	continue;

      action = (f->attr.flags & IBV_FLOW_ATTR_FLAGS_DONT_TRAP) ? "pass" : "trap";
      u32 unknown = f->attr.flags & ~IBV_FLOW_ATTR_FLAGS_DONT_TRAP;

      if (f->attr.flags & IBV_FLOW_ATTR_FLAGS_DONT_TRAP)
	flags = format (flags, "dont-trap");
      if (unknown)
	flags = format (flags, "%sunknown(0x%x)", flags ? "," : "", unknown);
      if (flags == 0)
	flags = format (flags, "none");

      table_format_cell (t, row, 0, "%u", f->pool_index);
      table_format_cell (t, row, 1, "%U", format_ethernet_address, f->spec.eth.val.dst_mac);
      table_format_cell (t, row, 2, "%U", format_ethernet_address, f->spec.eth.mask.dst_mac);
      table_format_cell (t, row, 3, "0x%04x", f->spec.eth.val.ether_type);
      table_format_cell (t, row, 4, "0x%04x", f->spec.eth.mask.ether_type);
      table_format_cell (t, row, 5, "%s", action);
      table_format_cell (t, row, 6, "%v", flags);
      vec_free (flags);
      row++;
    }

  if (row == 0)
    s = format (s, "none");
  else
    s = format (s, "%U", format_table, t);

  table_free (t);

  return s;
}
