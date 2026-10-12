/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>
#include <vlib/buffer_funcs.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

static u8 *
format_qppe_edma_rx_desc (u8 *s, va_list *args)
{
  const edma_rx_desc_t *desc = va_arg (*args, const edma_rx_desc_t *);

  return format (s,
		 "buffer_address 0x%08x%02x more %u fake_mac %u cpu_code_valid %u "
		 "service_code %u acl_idx_valid %u int_pri %u opaque 0x%08x%08x "
		 "source_port_id %u source_type %u destination_port_id %u destination_type %u "
		 "packet_length %u cpu_code %u data_offset %u l4_checksum_status %u "
		 "l3_checksum_status %u pid %u l3_offset %u",
		 desc->buffer_address, desc->buffer_address_hi, desc->more, desc->fake_mac,
		 desc->cpu_code_valid, desc->service_code, desc->acl_idx_valid, desc->int_pri,
		 desc->opaque_high, desc->opaque_low, desc->source_port_id, desc->source_type,
		 desc->destination_port_id, desc->destination_type, desc->packet_length,
		 desc->cpu_code, desc->data_offset, desc->l4_checksum_status,
		 desc->l3_checksum_status, desc->pid, desc->l3_offset);
}

static u8 *
format_qppe_edma_rx_sec_desc (u8 *s, va_list *args)
{
  const edma_rx_sec_desc_t *desc = va_arg (*args, const edma_rx_sec_desc_t *);

  return format (s,
		 "timestamp 0x%08x%08x timestamp_valid %u qos_tag 0x%08x flow_idx %u "
		 "flow_idx_valid %u",
		 desc->timestamp_hi, desc->timestamp_lo, desc->timestamp_valid, desc->qos_tag,
		 desc->flow_idx, desc->flow_idx_valid);
}

u8 *
format_qppe_edma_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  qppe_rx_trace_t *t = va_arg (*args, qppe_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 indent = format_get_indent (s);

  s = format (s, "qppe: %U (%u) next-node %U", format_vnet_sw_if_index_name, vnm, t->sw_if_index,
	      t->sw_if_index, format_vlib_next_node_name, vm, node->index, t->next_index);

  s = format (s, "\n%Udesc: %U", format_white_space, indent + 2, format_qppe_edma_rx_desc,
	      &t->head.desc);
  s = format_word_wrap_last_line (s, 100);
  s = format (s, "\n%Usec_desc: %U", format_white_space, indent + 2, format_qppe_edma_rx_sec_desc,
	      &t->head.sec_desc);
  s = format_word_wrap_last_line (s, 100);

  for (u16 i = 0; i < t->n_tail; i++)
    {
      s = format (s, "\n%Utail[%u] desc: %U", format_white_space, indent + 2, i,
		  format_qppe_edma_rx_desc, &t->tail[i].desc);
      s = format_word_wrap_last_line (s, 100);
      s = format (s, "\n%Utail[%u] sec_desc: %U", format_white_space, indent + 2, i,
		  format_qppe_edma_rx_sec_desc, &t->tail[i].sec_desc);
      s = format_word_wrap_last_line (s, 100);
    }

  return s;
}

static u8 *
format_qppe_edma_tx_desc (u8 *s, va_list *args)
{
  const edma_tx_desc_t *desc = va_arg (*args, const edma_tx_desc_t *);

  return format (s,
		 "buffer_address 0x%02x%08x more %u fake_mac %u timestamp_tag_enable %u "
		 "service_code %u int_pri_valid %u int_pri %u opaque 0x%08x%08x "
		 "source_port_id %u source_type %u destination_port_id %u destination_type %u "
		 "data_length %u pool_id %u "
		 "tso_enable %u ip_checksum_enable %u l4_checksum_mode %u advanced_offload %u "
		 "data_offset %u mss %u timestamp_tag %u timestamp_enable %u",
		 desc->buffer_address_hi, desc->buffer_address, desc->more, desc->fake_mac,
		 desc->timestamp_tag_enable, desc->service_code, desc->int_pri_valid, desc->int_pri,
		 desc->opaque_high, desc->opaque_low, desc->source_port_id, desc->source_type,
		 desc->destination_port_id, desc->destination_type, desc->data_length,
		 desc->pool_id, desc->tso_enable, desc->ip_checksum_enable, desc->l4_checksum_mode,
		 desc->advanced_offload, desc->data_offset, desc->mss, desc->timestamp_tag,
		 desc->timestamp_enable);
}

u8 *
format_qppe_edma_tx_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  qppe_tx_trace_t *t = va_arg (*args, qppe_tx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 indent = format_get_indent (s);

  s = format (s, "qppe: %U tx-queue %u n-descs %u", format_vnet_hw_if_index_name, vnm,
	      t->hw_if_index, t->queue_id, t->n_descs);

  s =
    format (s, "\n%Udesc: %U", format_white_space, indent + 2, format_qppe_edma_tx_desc, &t->desc);
  s = format_word_wrap_last_line (s, 100);

  return s;
}

u8 *
format_qppe_edma_rxq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  qppe_device_t *qd = vnet_dev_get_data (rxq->port->dev);
  u32 indent = format_get_indent (s);

  if (a->debug)
    {
      qppe_rxfill_ring_t *rfr = qd->rxfill_rings + qr->fill_ring_index;
      u16 cons = qppe_mmio_read32 (qd, rfr->cons_mmio_off);
      u16 hw_prod = qppe_mmio_read32 (qd, qr->rxdesc_prod_mmio_off);

      s = format (s, "EDMA fill-ring-id %u", qr->fill_ring_index);

      s = format (
	s, ",\n%Udesc ring: hw_prod %u sw_cons %u, fill ring: hw_cons %u sw_prod %u n_buffers %u",
	format_white_space, indent, hw_prod, qr->desc_cons, cons, rfr->prod,
	rfr->buffers_posted ? (rfr->prod - cons) & (2 * rfr->size - 1) : 0);

      /* EDMA v2 interrupt status clears on read; show only its masks. */
      s = format (s, ",\n%Uint_mask 0x%08x misc_int_mask 0x%08x", format_white_space, indent,
		  qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_INT_MASK (qr->desc_ring_id)),
		  qppe_edma_reg_rd (qd, EDMA_REG_MISC_INT_MASK));

      s = format (s, ",\n%Uloopback_ctrl 0x%08x", format_white_space, indent,
		  qppe_edma_reg_rd (qd, EDMA_REG_LOOPBACK_CTRL));
    }

  return s;
}

u8 *
format_qppe_edma_txq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_tx_queue_t *txq = va_arg (*args, vnet_dev_tx_queue_t *);
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  qppe_device_t *qd = vnet_dev_get_data (txq->port->dev);
  u32 indent = format_get_indent (s);

  if (a->debug > 0 && tq->ring_ids_allocated)
    {
      u16 hw_cons = qppe_mmio_read32 (qd, tq->txdesc_cons_mmio_off);
      u16 hw_prod = qppe_mmio_read32 (qd, tq->txcmpl_prod_mmio_off);

      s = format (s,
		  "\n%UEDMA desc ring %u: sw_prod %u hw_cons %u ctrl 0x%08x, completion ring %u: "
		  "hw_prod %u sw_cons %u",
		  format_white_space, indent, tq->desc_ring_id, tq->prod, hw_cons,
		  qppe_edma_reg_rd (qd, EDMA_REG_TXDESC_CTRL (tq->desc_ring_id)), tq->cmpl_ring_id,
		  hw_prod, tq->cmpl_cons);
    }

  return s;
}

u8 *
format_qppe_edma_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  ppe_reg_edma_port_control_t port_control;
  u32 indent, version;

  if (!qd->regs)
    return s;

  port_control.as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_PORT_CTRL_ADDR);
  indent = format_get_indent (s);
  version = qppe_edma_reg_rd (qd, EDMA_REG_MAS_CTRL_ADDR);

  s = format_newline (s, indent);
  s = format (s, "EDMA version %u (0x%08x)", version, version);
  s = format_newline (s, indent);
  s = format (s, "EDMA port control 0x%08x (EDMA %s, TX padding %s)", port_control.as_u32,
	      port_control.edma_enable ? "enabled" : "disabled",
	      port_control.tx_padding_enable ? "enabled" : "disabled");

  if (a->debug > 0)
    {
      ppe_reg_port_bridge_ctrl_t cpu_bridge_ctrl = {
	.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_PORT_BRIDGE_CTRL (EDMA_CPU_PORT_ID)),
      };

      s = format_newline (s, indent);
      s = format (s, "PPE CPU PORT_BRIDGE_CTRL 0x%08x (isolation 0x%02x, txmac_en=%u)",
		  cpu_bridge_ctrl.as_u32, cpu_bridge_ctrl.port_isolation_bitmap,
		  cpu_bridge_ctrl.txmac_en);
    }

  return s;
}

/* APPE service-code fields inherited from HPPE, decoded using fal_servcode.h. */
static u8 *
format_qppe_edma_named_bits (u8 *s, u32 bitmap, const char *const *names, u32 count)
{
  u32 enabled = 0, total = 0;
  int exceptions;
  const char *separator = "";

  for (u32 i = 0; i < count; i++)
    if (names[i])
      {
	total++;
	enabled += (bitmap >> i) & 1;
      }
  if (!enabled)
    return format (s, "none");
  if (enabled == total)
    return format (s, "all");

  exceptions = enabled > total / 2;
  if (exceptions)
    s = format (s, "all except ");
  for (u32 i = 0; i < count; i++)
    if (names[i] && (((bitmap >> i) & 1) != exceptions))
      {
	s = format (s, "%s%s", separator, names[i]);
	separator = ", ";
      }
  return s;
}

static u8 *
format_qppe_service_bypass (u8 *s, va_list *args)
{
  u32 bitmap = va_arg (*args, u32);
  static const char *const names[] = {
    [0] = "in_vlan_tag_fmt_check",
    [1] = "in_vlan_member_check",
    [2] = "in_vlan_xlt",
    [3] = "my_mac_check",
    [4] = "dip_lookup",
    [5] = "flow_lookup",
    [6] = "flow_action",
    [7] = "acl",
    [8] = "fake_mac_header",
    [9] = "service_code",
    [10] = "wrong_pkt_fmt_l2",
    [11] = "wrong_pkt_fmt_l3_ipv4",
    [12] = "wrong_pkt_fmt_l3_ipv6",
    [13] = "wrong_pkt_fmt_l4",
    [14] = "flow_service_code",
    [15] = "acl_service_code",
    [16] = "fake_l2_proto",
    [17] = "pppoe_termination",
    [18] = "default_vlan",
    [19] = "default_pcp",
    [20] = "vsi_assign",
    [21] = "wrong_pkt_fmt_tunnel",
    [24] = "in_vlan_assign_fail",
    [25] = "source_guard",
    [26] = "mru_mtu_check",
    [27] = "flow_src_check",
    [28] = "flow_qos",
  };

  return format_qppe_edma_named_bits (s, bitmap, names, ARRAY_LEN (names));
}

static u8 *
format_qppe_egress_bypass (u8 *s, va_list *args)
{
  u32 bitmap = va_arg (*args, u32);
  static const char *const names[] = {
    [0] = "eg_vlan_member_check",
    [1] = "eg_vlan_xlt",
    [2] = "eg_vlan_tag_fmt_ctrl",
    [3] = "fdb_learn",
    [4] = "fdb_refresh",
    [5] = "l2_source_sec",
    [6] = "management_fwd",
    [7] = "bridging_fwd",
    [8] = "in_stp_fltr",
    [9] = "eg_stp_fltr",
    [10] = "source_fltr",
    [11] = "policer",
    [12] = "l2_pkt_edit",
    [13] = "l3_pkt_edit",
    [14] = "acl_post_routing_check",
    [15] = "port_isolation",
    [16] = "pre_acl_qos",
    [17] = "post_acl_qos",
    [18] = "dscp_qos",
    [19] = "pcp_qos",
    [20] = "preheader_qos",
    [21] = "fake_mac_drop",
    [22] = "tunnel_context",
  };

  return format_qppe_edma_named_bits (s, bitmap, names, ARRAY_LEN (names));
}

static u8 *
format_qppe_service_updates (u8 *s, va_list *args)
{
  u32 bitmap = va_arg (*args, u32);
  static const char *const names[] = {
    [0] = "capwap_en",	      [1] = "direction",	[2] = "dest_info",
    [3] = "src_info",	      [4] = "int_pri",		[5] = "service_code",
    [6] = "hash_flow_index",  [7] = "fake_l2_proto_en", [8] = "eip_flow_label",
    [9] = "allow_padding",    [10] = "strip_padding",	[11] = "keep_outer",
    [12] = "l4_checksum",     [13] = "ipv4_checksum",	[14] = "enc_last_dest",
    [15] = "wifi_qos",	      [16] = "tree_qos",	[17] = "flow_idx",
    [24] = "src_info_bypass", [25] = "dst_info_bypass", [26] = "mac_hdr_bypass",
    [27] = "fake_mac_clear",
  };

  return format_qppe_edma_named_bits (s, bitmap, names, ARRAY_LEN (names));
}

static u8 *
format_qppe_tunnel_bypass (u8 *s, va_list *args)
{
  u32 bitmap = va_arg (*args, u32);
  static const char *const names[] = {
    [0] = "service_code",
    [1] = "tunnel",
    [2] = "l3_if_check",
    [3] = "vlan_check",
    [4] = "dmac_check",
    [5] = "udp_csum_zero_check",
    [6] = "table_deaccel_check",
    [7] = "pppoe_mc_term_check",
    [8] = "ttl_exceed_check",
    [9] = "map_src_check",
    [10] = "map_dst_check",
    [11] = "lpm_dst_lookup",
    [12] = "lpm_lookup",
    [13] = "wrong_pkt_fmt_l2",
    [14] = "wrong_pkt_fmt_l3_ipv4",
    [15] = "wrong_pkt_fmt_l3_ipv6",
    [16] = "wrong_pkt_fmt_l4",
    [17] = "wrong_pkt_fmt_tunnel",
    [20] = "pre_ipo",
  };

  return format_qppe_edma_named_bits (s, bitmap, names, ARRAY_LEN (names));
}

static void
qppe_edma_service_range (qppe_device_t *qd, u32 base, u32 stride, u32 n_words, const u32 *masks,
			 u32 *sc, u32 *words)
{
  for (u32 w = 0; w < n_words; w++)
    words[w] = qppe_mmio_read32 (qd, base + stride * *sc + sizeof (u32) * w) & masks[w];
  while (*sc + 1 < HPPE_SERVICE_CODE_COUNT)
    {
      u32 next[2];

      for (u32 w = 0; w < n_words; w++)
	next[w] = qppe_mmio_read32 (qd, base + stride * (*sc + 1) + sizeof (u32) * w) & masks[w];
      if (memcmp (words, next, n_words * sizeof (words[0])))
	break;
      (*sc)++;
    }
}

u8 *
format_qppe_edma_service_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  static const u32 masks[] = {
    0x1f3fffff,
    0x1,
  };
  u32 row = 0;
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "sc", "Bypassed operations", "rx_counting_en");
  for (u32 sc = 0; sc < HPPE_SERVICE_CODE_COUNT; sc++)
    {
      u32 first = sc;
      u32 words[2];
      ppe_reg_service_tbl_w1_t w1;

      qppe_edma_service_range (qd, HPPE_REG_SERVICE_TBL (0), 16, ARRAY_LEN (masks), masks, &sc,
			       words);
      w1.as_u32 = words[1];
      if (first == sc)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, sc);
      table_format_cell (&table, row, 1, "%U", format_qppe_service_bypass, words[0]);
      table_set_cell_align (&table, row, 1, TTAA_LEFT);
      table_format_cell (&table, row, 2, "%u", w1.rx_counting_en);
      row++;
    }

  s = format (s, "SERVICE_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_edma_in_l2_service_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  static const u32 masks[] = {
    0xdfffffff,
  };
  u32 row = 0;
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 7, "sc", "dst_valid", "port", "direction", "Bypassed operations",
		     "rx_cnt_en", "tx_cnt_en");
  for (u32 sc = 0; sc < HPPE_SERVICE_CODE_COUNT; sc++)
    {
      u32 first = sc;
      u32 words[2];
      ppe_reg_in_l2_service_tbl_w0_t w0;

      qppe_edma_service_range (qd, HPPE_REG_IN_L2_SERVICE_TBL (0), 16, ARRAY_LEN (masks), masks,
			       &sc, words);
      w0.as_u32 = words[0];
      if (first == sc)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, sc);
      table_format_cell (&table, row, 1, "%u", w0.dst_port_id_valid);
      table_format_cell (&table, row, 2, "%u", w0.dst_port_id);
      table_format_cell (&table, row, 3, "%s", w0.dst_direction ? "source" : "destination");
      table_format_cell (&table, row, 4, "%U", format_qppe_egress_bypass, w0.egress_bypass_bitmap);
      table_set_cell_align (&table, row, 4, TTAA_LEFT);
      table_format_cell (&table, row, 5, "%u", w0.rx_cnt_en);
      table_format_cell (&table, row, 6, "%u", w0.tx_cnt_en);
      row++;
    }

  s = format (s, "IN_L2_SERVICE_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_edma_eg_service_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  static const u32 masks[] = {
    0xf03ffff,
    0xffff,
  };
  u32 row = 0;
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 6, "sc", "Updated fields", "next_sc", "hw_services", "offset",
		     "tx_counting_en");
  for (u32 sc = 0; sc < HPPE_SERVICE_CODE_COUNT; sc++)
    {
      u32 first = sc;
      u32 words[2];
      ppe_reg_eg_service_tbl_w1_t w1;

      qppe_edma_service_range (qd, HPPE_REG_EG_SERVICE_TBL (0), 16, ARRAY_LEN (masks), masks, &sc,
			       words);
      w1.as_u32 = words[1];
      if (first == sc)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, sc);
      table_format_cell (&table, row, 1, "%U", format_qppe_service_updates, words[0]);
      table_set_cell_align (&table, row, 1, TTAA_LEFT);
      table_format_cell (&table, row, 2, "%u", w1.next_service_code);
      table_format_cell (&table, row, 3, "%u", w1.hw_services);
      table_format_cell (&table, row, 4, "%s", w1.offset_sel ? "L4" : "L3");
      table_format_cell (&table, row, 5, "%u", w1.tx_counting_en);
      row++;
    }

  s = format (s, "EG_SERVICE_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_edma_tl_service_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  static const u32 masks[] = {
    0x13ffff,
  };
  u32 row = 0;
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 2, "sc", "Bypassed operations");
  for (u32 sc = 0; sc < HPPE_SERVICE_CODE_COUNT; sc++)
    {
      u32 first = sc;
      u32 words[2];

      qppe_edma_service_range (qd, APPE_REG_TL_SERVICE_TBL (0), 4, ARRAY_LEN (masks), masks, &sc,
			       words);
      if (first == sc)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, sc);
      table_format_cell (&table, row, 1, "%U", format_qppe_tunnel_bypass, words[0]);
      table_set_cell_align (&table, row, 1, TTAA_LEFT);
      row++;
    }

  s = format (s, "TL_SERVICE_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static const qppe_reg_field_t edma_reg_port_ctrl_diag_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_edma_reg_port_ctrl_diag_t_fields
#undef _
};

static const qppe_reg_field_t edma_reg_vlan_ctrl_diag_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_edma_reg_vlan_ctrl_diag_t_fields
#undef _
};

static const qppe_reg_field_t edma_reg_txq_ctrl_diag_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_edma_reg_txq_ctrl_diag_t_fields
#undef _
};

static const qppe_reg_field_t edma_reg_rxq_ctrl_diag_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_edma_reg_rxq_ctrl_diag_t_fields
#undef _
};

static const qppe_reg_field_t edma_reg_rxq_fc_thre_diag_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_edma_reg_rxq_fc_thre_diag_t_fields
#undef _
};

static const qppe_reg_field_t edma_reg_dmar_ctrl_diag_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_edma_reg_dmar_ctrl_diag_t_fields
#undef _
};

static const qppe_reg_field_t edma_reg_axiw_ctrl_diag_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_edma_reg_axiw_ctrl_diag_t_fields
#undef _
};

static const qppe_reg_field_t edma_reg_loopback_ctrl_diag_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_edma_reg_loopback_ctrl_diag_t_fields
#undef _
};

static const qppe_reg_field_t edma_reg_misc_int_diag_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_edma_reg_misc_int_diag_t_fields
#undef _
};

static u8 *
qppe_edma_format_register (u8 *s, const char *name, u32 value, const qppe_reg_field_t *fields,
			   uword n_fields, u32 indent, u32 *printed)
{
  if ((*printed)++)
    {
      s = format (s, "\n");
      s = format_newline (s, indent);
    }
  s = format (s, "%s: 0x%08x", name, value);
  if (n_fields == 0)
    return s;
  s = format_newline (s, indent + 2);
  return format (s, "%U", format_qppe_reg_fields, value, fields, n_fields);
}

u8 *
format_qppe_edma_errors (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 indent = format_get_indent (s), printed = 0, row = 0;
  u32 status, qid, qid2;
  u32 fill_status[EDMA_RXFILL_RING_COUNT] = {};

  if (!qd->regs)
    return s;

  /* Read each latched status once, only through this explicit command. */
  status = qppe_edma_reg_rd (qd, EDMA_REG_MISC_INT_STAT);
  qid = qppe_edma_reg_rd (qd, EDMA_REG_MISC_ERR_QID);
  qid2 = qppe_edma_reg_rd (qd, EDMA_REG_MISC_ERR_QID_REG2);
  s = qppe_edma_format_register (s, "EDMA_MISC_INT_STAT (read clears status)", status,
				 edma_reg_misc_int_diag_fields,
				 ARRAY_LEN (edma_reg_misc_int_diag_fields), indent, &printed);
  s = qppe_edma_format_register (s, "EDMA_MISC_ERR_QID", qid, 0, 0, indent, &printed);
  s = qppe_edma_format_register (s, "EDMA_MISC_ERR_QID_REG2", qid2, 0, 0, indent, &printed);

  for (u32 i = 0; i < ARRAY_LEN (qd->rxfill_rings); i++)
    if (qppe_edma_rxfill_started_queues (dev, &qd->rxfill_rings[i]))
      fill_status[i] = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_INT_STAT (i));

  table_add_hdr_row (&table, 9, "port", "queue", "desc ring", "fill ring", "desc status", "packet",
		     "urgent", "fill status", "low buffer");
  foreach_vnet_dev_port (port, dev)
    foreach_vnet_dev_port_rx_queue (rxq, port)
      {
	qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
	edma_reg_rxdesc_int_diag_t desc;
	edma_reg_rxfill_int_diag_t fill;

	if (!qr->started)
	  continue;
	desc.as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_INT_STAT (qr->desc_ring_id));
	fill.as_u32 = fill_status[qr->fill_ring_index];
	table_format_cell (&table, row, 0, "%u", port->port_id);
	table_format_cell (&table, row, 1, "%u", rxq->queue_id);
	table_format_cell (&table, row, 2, "%u", qr->desc_ring_id);
	table_format_cell (&table, row, 3, "%u", qr->fill_ring_index);
	table_format_cell (&table, row, 4, "0x%x (%u)", desc.as_u32, desc.as_u32);
	table_format_cell (&table, row, 5, "%u", desc.packet);
	table_format_cell (&table, row, 6, "%u", desc.urgent);
	table_format_cell (&table, row, 7, "0x%x (%u)", fill.as_u32, fill.as_u32);
	table_format_cell (&table, row, 8, "%u", fill.low_buffer);
	row++;
      }

  s = format (s, "\n");
  s = format_newline (s, indent);
  s = format (s, "EDMA_RX_INTERRUPT_STATUS (read clears status):");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_edma_rxfill_descriptors (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  vlib_main_t *vm = vlib_get_main ();
  table_t rings = {}, descriptors = {};
  u32 indent = format_get_indent (s), ring_row = 0, row = 0;

  if (!qd->regs)
    return s;

  table_add_hdr_row (&rings, 9, "thread", "fill ring", "size", "hw prod", "hw cons", "sw prod",
		     "buffers", "references", "started queues");
  table_add_hdr_row (&descriptors, 10, "thread", "fill ring", "slot", "posted", "buffer DMA",
		     "size", "opaque low", "opaque high", "saved buffer", "expected DMA");
  for (u32 ti = 0; ti < ARRAY_LEN (qd->rxfill_rings); ti++)
    {
      qppe_rxfill_ring_t *rfr = &qd->rxfill_rings[ti];
      u32 mask;
      u16 prod, cons;
      u32 started_queues;

      if (rfr->n_rx_queues == 0)
	continue;
      started_queues = qppe_edma_rxfill_started_queues (dev, rfr);
      mask = rfr->size - 1;
      prod = qppe_mmio_read32 (qd, rfr->prod_mmio_off);
      cons = qppe_mmio_read32 (qd, rfr->cons_mmio_off);
      table_format_cell (&rings, ring_row, 0, "%u", ti);
      table_format_cell (&rings, ring_row, 1, "%u", rfr->ring_id);
      table_format_cell (&rings, ring_row, 2, "%u", rfr->size);
      table_format_cell (&rings, ring_row, 3, "%u", prod);
      table_format_cell (&rings, ring_row, 4, "%u", cons);
      table_format_cell (&rings, ring_row, 5, "%u", rfr->prod);
      table_format_cell (&rings, ring_row, 6, "%u",
			 rfr->buffers_posted ? (prod - cons) & (2 * rfr->size - 1) : 0);
      table_format_cell (&rings, ring_row, 7, "%u", rfr->n_rx_queues);
      table_format_cell (&rings, ring_row++, 8, "%u", started_queues);

      for (u32 i = 0; i < 8; i++)
	{
	  u32 slot = i < 4 ? i : (cons + i - 4) & mask;
	  edma_rxfill_desc_t desc = rfr->descs[slot];
	  u32 posted =
	    started_queues && ((slot - cons) & mask) < ((prod - cons) & (2 * rfr->size - 1));

	  if (i >= 4 && slot < 4)
	    continue;
	  table_format_cell (&descriptors, row, 0, "%u", ti);
	  table_format_cell (&descriptors, row, 1, "%u", rfr->ring_id);
	  table_format_cell (&descriptors, row, 2, "%u", slot);
	  table_format_cell (&descriptors, row, 3, "%u", posted);
	  table_format_cell (&descriptors, row, 4, "0x%x", desc.buffer_address);
	  table_format_cell (&descriptors, row, 5, "%u", desc.buffer_size);
	  table_format_cell (&descriptors, row, 6, "%u", desc.opaque_low);
	  table_format_cell (&descriptors, row, 7, "%u", desc.opaque_high);
	  if (posted)
	    {
	      u32 bi = desc.opaque_low;
	      vlib_buffer_t *b = vlib_get_buffer (vm, bi);

	      table_format_cell (&descriptors, row, 8, "%u", bi);
	      table_format_cell (&descriptors, row, 9, "0x%lx",
				 vnet_dev_get_dma_addr (vm, dev, b->data));
	    }
	  row++;
	}
    }

  s = format (s, "EDMA_RXFILL_STATE:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &rings);
  s = format (s, "\n");
  s = format_newline (s, indent);
  s = format (s, "EDMA_RXFILL_DESCRIPTORS:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &descriptors);
  table_free (&rings);
  table_free (&descriptors);
  return s;
}

u8 *
format_qppe_edma_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s), printed = 0;

  if (!qd->regs)
    return s;

  s = qppe_edma_format_register (
    s, "EDMA_PORT_CTRL", qppe_edma_reg_rd (qd, EDMA_REG_PORT_CTRL_ADDR),
    edma_reg_port_ctrl_diag_fields, ARRAY_LEN (edma_reg_port_ctrl_diag_fields), indent, &printed);

  s = qppe_edma_format_register (s, "EDMA_VLAN_CTRL", qppe_edma_reg_rd (qd, EDMA_REG_VLAN_CTRL),
				 edma_reg_vlan_ctrl_diag_fields,
				 ARRAY_LEN (edma_reg_vlan_ctrl_diag_fields), indent, &printed);

  s = qppe_edma_format_register (s, "EDMA_TXQ_CTRL", qppe_edma_reg_rd (qd, EDMA_REG_TXQ_CTRL),
				 edma_reg_txq_ctrl_diag_fields,
				 ARRAY_LEN (edma_reg_txq_ctrl_diag_fields), indent, &printed);

  s = qppe_edma_format_register (s, "EDMA_RXQ_CTRL", qppe_edma_reg_rd (qd, EDMA_REG_RXQ_CTRL),
				 edma_reg_rxq_ctrl_diag_fields,
				 ARRAY_LEN (edma_reg_rxq_ctrl_diag_fields), indent, &printed);

  s = qppe_edma_format_register (s, "EDMA_RXQ_FC_THRE", qppe_edma_reg_rd (qd, EDMA_REG_RXQ_FC_THRE),
				 edma_reg_rxq_fc_thre_diag_fields,
				 ARRAY_LEN (edma_reg_rxq_fc_thre_diag_fields), indent, &printed);

  s = qppe_edma_format_register (s, "EDMA_DMAR_CTRL", qppe_edma_reg_rd (qd, EDMA_REG_DMAR_CTRL),
				 edma_reg_dmar_ctrl_diag_fields,
				 ARRAY_LEN (edma_reg_dmar_ctrl_diag_fields), indent, &printed);

  s = qppe_edma_format_register (s, "EDMA_AXIW_CTRL", qppe_edma_reg_rd (qd, EDMA_REG_AXIW_CTRL),
				 edma_reg_axiw_ctrl_diag_fields,
				 ARRAY_LEN (edma_reg_axiw_ctrl_diag_fields), indent, &printed);

  s = qppe_edma_format_register (s, "EDMA_LOOPBACK_CTRL",
				 qppe_edma_reg_rd (qd, EDMA_REG_LOOPBACK_CTRL),
				 edma_reg_loopback_ctrl_diag_fields,
				 ARRAY_LEN (edma_reg_loopback_ctrl_diag_fields), indent, &printed);

  s = qppe_edma_format_register (
    s, "EDMA_MISC_INT_MASK", qppe_edma_reg_rd (qd, EDMA_REG_MISC_INT_MASK),
    edma_reg_misc_int_diag_fields, ARRAY_LEN (edma_reg_misc_int_diag_fields), indent, &printed);

  /* The SDK names these registers but does not define all of their fields. */
  {
    static const struct
    {
      const char *name;
      u32 reg;
    } registers[] = {
      {
	"EDMA_TXQ_CTRL_2",
	EDMA_REG_TXQ_CTRL_2,
      },
      {
	"EDMA_TXQ_FC_0",
	EDMA_REG_TXQ_FC_0,
      },
      {
	"EDMA_TXQ_FC_1",
	EDMA_REG_TXQ_FC_1,
      },
      {
	"EDMA_TXQ_FC_2",
	EDMA_REG_TXQ_FC_2,
      },
      {
	"EDMA_TXQ_FC_3",
	EDMA_REG_TXQ_FC_3,
      },
      {
	"EDMA_AXIR_CTRL",
	EDMA_REG_AXIR_CTRL,
      },
      {
	"EDMA_MIN_MSS",
	EDMA_REG_MIN_MSS,
      },
      {
	"EDMA_DBG_CTRL",
	EDMA_REG_DBG_CTRL,
      },
      {
	"EDMA_REQ0_FIFO_THRESH",
	EDMA_REG_REQ0_FIFO_THRESH,
      },
      {
	"EDMA_WB_OS_THRESH",
	EDMA_REG_WB_OS_THRESH,
      },
      {
	"EDMA_TX_TIMEOUT_THRESH",
	EDMA_REG_TX_TIMEOUT_THRESH,
      },
    };

    for (u32 i = 0; i < ARRAY_LEN (registers); i++)
      s = qppe_edma_format_register (s, registers[i].name, qppe_edma_reg_rd (qd, registers[i].reg),
				     0, 0, indent, &printed);
  }

  return s;
}

u8 *
format_qppe_edma_status (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  static const qppe_reg_field_t fields[] = {
    {
      "version",
      32,
    },
  };
  u32 indent = format_get_indent (s), printed = 0;

  if (!qd->regs)
    return s;

  return qppe_edma_format_register (s, "EDMA_MAS_CTRL",
				    qppe_edma_reg_rd (qd, EDMA_REG_MAS_CTRL_ADDR), fields,
				    ARRAY_LEN (fields), indent, &printed);
}

typedef void (qppe_edma_ring_read_t) (qppe_device_t *, u32, u32 *);

static u8 *
qppe_edma_format_rings (u8 *s, vnet_dev_t *dev, const char *name, const char *const *columns,
			u32 n_columns, u32 n_address_columns, u32 paired_columns, u32 count,
			qppe_edma_ring_read_t *read_ring)
{
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  ASSERT (n_columns <= 25);
  table_add_hdr_row (&table, 0);
  for (u32 col = 0; col < n_columns; col++)
    if (strchr (columns[col], '\n'))
      {
	table_add_hdr_row (&table, 0);
	break;
      }
  for (u32 col = 0; col < n_columns; col++)
    {
      const char *split = strchr (columns[col], '\n');

      if (split)
	{
	  int length = split - columns[col];

	  table_format_cell (&table, -2, col, "%.*s", length, columns[col]);
	  table_format_cell (&table, -1, col, "%s", split + 1);
	}
      else
	table_format_cell (&table, -table.n_header_cols, col, "%s", columns[col]);
      if (paired_columns & (1 << col))
	for (int header = -table.n_header_cols; header < 0; header++)
	  table_set_cell_align (&table, header, col, TTAA_CENTER);
    }
  for (u32 ring = 0; ring < count; ring++)
    {
      u32 first = ring;
      u32 values[24];

      read_ring (qd, ring, values);
      while (ring + 1 < count)
	{
	  u32 next[24];

	  read_ring (qd, ring + 1, next);
	  if (memcmp (values, next, (n_columns - 1) * sizeof (values[0])))
	    break;
	  ring++;
	}
      if (first == ring)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, ring);
      for (u32 col = 1; col < n_columns; col++)
	if (col <= n_address_columns)
	  table_format_cell (&table, row, col, "0x%08x", values[col - 1]);
	else if (paired_columns & (1 << col))
	  {
	    table_format_cell (&table, row, col, "%u/%u", values[col - 1] >> 1,
			       values[col - 1] & 1);
	    table_set_cell_align (&table, row, col, TTAA_CENTER);
	  }
	else
	  table_format_cell (&table, row, col, "%u", values[col - 1]);
      row++;
    }

  s = format (s, "%s:", name);
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static void
qppe_edma_rxdesc_ring_read (qppe_device_t *qd, u32 ring, u32 *v)
{
  edma_reg_rxdesc_control_diag_t ctrl = {
    .as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_CTRL (ring)),
  };
  ppe_reg_edma_rxdesc_ring_size_t size = {
    .as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_RING_SIZE (ring)),
  };
  edma_reg_fc_threshold_diag_t fc = {
    .as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_FC_THRE (ring)),
  };

  u32 interrupt_mask = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_INT_MASK (ring));

  v[0] = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_BA (ring));
  v[1] = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_PREHEADER_BA (ring));
  v[2] = size.ring_size;
  v[3] = size.preheader_offset;
  v[4] = ctrl.enable;
  v[5] = ctrl.qdisc;
  v[6] = (ctrl.stag_remove << 1) | ctrl.ctag_remove;
  v[7] = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_PROD_IDX (ring)) & 0xffff;
  v[8] = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_CONS_IDX (ring)) & 0xffff;
  v[9] = fc.xon;
  v[10] = fc.xoff;
  v[11] = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_UGT_THRE (ring)) & 0xffff;
  v[12] = qppe_edma_reg_rd (qd, EDMA_REG_RX_MOD_TIMER (ring)) & 0xffff;
  v[13] = qppe_edma_reg_rd (qd, EDMA_REG_RX_INT_CTRL (ring)) & 3;
  v[14] = interrupt_mask & 1;
  v[15] = (interrupt_mask >> 1) & 1;
  v[16] = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_DISABLE (ring)) & 1;
  v[17] = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC_DISABLE_DONE (ring)) & 1;
}

u8 *
format_qppe_edma_rxdesc_rings (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "ring",	    "base",	  "preheader\nbase",   "size",		"preheader\noffset",
    "en",	    "qdisc",	  "remove\nstag/ctag", "prod",		"cons",
    "xon",	    "xoff",	  "low\nth",	       "mod\ntimer",	"int\nctrl",
    "packet\nmask", "timer\ndis", "disable",	       "disable\ndone",
  };

  return qppe_edma_format_rings (s, dev, "EDMA_RXDESC_RINGS", columns, ARRAY_LEN (columns), 2,
				 1 << 7, EDMA_RXDESC_RING_COUNT, qppe_edma_rxdesc_ring_read);
}

static void
qppe_edma_rxfill_ring_read (qppe_device_t *qd, u32 ring, u32 *v)
{
  edma_reg_fc_threshold_diag_t fc = {
    .as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_FC_THRE (ring)),
  };

  v[0] = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_BA (ring));
  v[1] = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_RING_SIZE (ring)) & 0xffff;
  v[2] = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_BUFFER1_SIZE (ring));
  v[3] = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_RING_EN (ring)) & 1;
  v[4] = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_PROD_IDX (ring)) & 0xffff;
  v[5] = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_CONS_IDX (ring)) & 0xffff;
  v[6] = fc.xon;
  v[7] = fc.xoff;
  v[8] = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_UGT_THRE (ring)) & 0xffff;
  v[9] = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_INT_MASK (ring)) & 1;
  v[10] = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_DISABLE (ring)) & 1;
  v[11] = qppe_edma_reg_rd (qd, EDMA_REG_RXFILL_DISABLE_DONE (ring)) & 1;
}

u8 *
format_qppe_edma_rxfill_rings (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "ring", "base", "size",   "buffer1_undecoded", "en",      "prod",	      "cons",
    "xon",  "xoff", "low_th", "interrupt_mask",	   "disable", "disable_done",
  };

  return qppe_edma_format_rings (s, dev, "EDMA_RXFILL_RINGS", columns, ARRAY_LEN (columns), 1, 0,
				 EDMA_RXFILL_RING_COUNT, qppe_edma_rxfill_ring_read);
}

static void
qppe_edma_txdesc_ring_read (qppe_device_t *qd, u32 ring, u32 *v)
{
  edma_reg_txdesc_control_diag_t ctrl = {
    .as_u32 = qppe_edma_reg_rd (qd, EDMA_REG_TXDESC_CTRL (ring)),
  };

  v[0] = qppe_edma_reg_rd (qd, EDMA_REG_TXDESC_BA (ring));
  v[1] = qppe_edma_reg_rd (qd, EDMA_REG_TXDESC_BA2 (ring));
  v[2] = qppe_edma_reg_rd (qd, EDMA_REG_TXDESC_RING_SIZE (ring)) & 0xffff;
  v[3] = ctrl.enable;
  v[4] = ctrl.fc_group;
  v[5] = ctrl.arb_group;
  v[6] = ctrl.reset;
  v[7] = qppe_edma_reg_rd (qd, EDMA_REG_TXDESC_PROD_IDX (ring)) & 0xffff;
  v[8] = qppe_edma_reg_rd (qd, EDMA_REG_TXDESC_CONS_IDX (ring)) & 0xffff;
}

u8 *
format_qppe_edma_txdesc_rings (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "ring",	"base",	     "secondary_base", "size", "en",
    "fc_group", "arb_group", "reset",	       "prod", "cons",
  };

  return qppe_edma_format_rings (s, dev, "EDMA_TXDESC_RINGS", columns, ARRAY_LEN (columns), 2, 0,
				 EDMA_TXDESC_RING_COUNT, qppe_edma_txdesc_ring_read);
}

static void
qppe_edma_txcmpl_ring_read (qppe_device_t *qd, u32 ring, u32 *v)
{
  u32 threshold = qppe_edma_reg_rd (qd, EDMA_REG_TXCMPL_UGT_THRE (ring));
  u32 interrupt_mask = qppe_edma_reg_rd (qd, EDMA_REG_TX_INT_MASK (ring));

  v[0] = qppe_edma_reg_rd (qd, EDMA_REG_TXCMPL_BA (ring));
  v[1] = qppe_edma_reg_rd (qd, EDMA_REG_TXCMPL_RING_SIZE (ring)) & 0xffff;
  v[2] = qppe_edma_reg_rd (qd, EDMA_REG_TXCMPL_CTRL (ring)) & 1;
  v[3] = qppe_edma_reg_rd (qd, EDMA_REG_TXCMPL_PROD_IDX (ring)) & 0xffff;
  v[4] = qppe_edma_reg_rd (qd, EDMA_REG_TXCMPL_CONS_IDX (ring)) & 0xffff;
  v[5] = threshold & 0xffff;
  v[6] = (threshold >> 16) & 0x3f;
  v[7] = qppe_edma_reg_rd (qd, EDMA_REG_TX_MOD_TIMER (ring)) & 0xffff;
  v[8] = qppe_edma_reg_rd (qd, EDMA_REG_TX_INT_CTRL (ring)) & 3;
  v[9] = interrupt_mask & 1;
  v[10] = (interrupt_mask >> 1) & 1;
}

u8 *
format_qppe_edma_txcmpl_rings (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "ring",   "base",  "size",	    "return_mode", "prod",	  "cons",
    "low_th", "fc_th", "mod_timer", "int_ctrl",	   "packet_mask", "urgent_mask",
  };

  return qppe_edma_format_rings (s, dev, "EDMA_TXCMPL_RINGS", columns, ARRAY_LEN (columns), 1, 0,
				 EDMA_TXCMPL_RING_COUNT, qppe_edma_txcmpl_ring_read);
}

u8 *
format_qppe_edma_ring_queue_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 2, "ring", "Queue IDs");
  for (u32 ring = 0; ring < EDMA_RXDESC_RING_COUNT; ring++)
    {
      u32 first = ring;
      u32 words[EDMA_RING_Q_MAP_WORDS];
      uword *queues = 0;

      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	words[w] = qppe_mmio_read32 (qd, HPPE_REG_RING_Q_MAP_TBL (ring) + sizeof (u32) * w);
      words[EDMA_RING_Q_MAP_WORDS - 1] &= EDMA_RING_Q_MAP_LAST_WORD_MASK;
      while (ring + 1 < EDMA_RXDESC_RING_COUNT)
	{
	  u32 next[EDMA_RING_Q_MAP_WORDS];

	  for (u32 w = 0; w < ARRAY_LEN (next); w++)
	    next[w] = qppe_mmio_read32 (qd, HPPE_REG_RING_Q_MAP_TBL (ring + 1) + sizeof (u32) * w);
	  next[EDMA_RING_Q_MAP_WORDS - 1] &= EDMA_RING_Q_MAP_LAST_WORD_MASK;
	  if (memcmp (words, next, sizeof (words)))
	    break;
	  ring++;
	}
      for (u32 w = 0; w < ARRAY_LEN (words); w++)
	queues = clib_bitmap_set_multiple (queues, 32 * w, words[w], 32);
      if (first == ring)
	table_format_cell (&table, row, 0, "%u", first);
      else
	table_format_cell (&table, row, 0, "%u-%u", first, ring);
      if (clib_bitmap_is_zero (queues))
	table_format_cell (&table, row, 1, "none");
      else
	table_format_cell (&table, row, 1, "%U", format_bitmap_list, queues);
      table_set_cell_align (&table, row, 1, TTAA_LEFT);
      clib_bitmap_free (queues);
      row++;
    }

  s = format (s, "RING_Q_MAP_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static void
qppe_edma_qid2rid_read (qppe_device_t *qd, u32 qid, u32 *v)
{
  u32 word = qppe_edma_reg_rd (qd, EDMA_REG_QID2RID_TABLE (qid));

  v[0] = (word >> ((qid % 4) * 8)) & 0xff;
}

u8 *
format_qppe_edma_qid2rid (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "queue",
    "RX descriptor ring",
  };

  return qppe_edma_format_rings (s, dev, "EDMA_QID2RID", columns, ARRAY_LEN (columns), 0, 0,
				 EDMA_QUEUE_MAP_COUNT, qppe_edma_qid2rid_read);
}

static void
qppe_edma_rxdesc2fill_read (qppe_device_t *qd, u32 ring, u32 *v)
{
  u32 word = qppe_edma_reg_rd (qd, EDMA_REG_RXDESC2FILL_MAP_0 + (ring / 10) * sizeof (u32));

  v[0] = (word >> ((ring % 10) * 3)) & 7;
}

u8 *
format_qppe_edma_rxdesc2fill_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "RX descriptor ring",
    "RX fill ring",
  };

  return qppe_edma_format_rings (s, dev, "EDMA_RXDESC2FILL_MAP", columns, ARRAY_LEN (columns), 0, 0,
				 EDMA_RXDESC_RING_COUNT, qppe_edma_rxdesc2fill_read);
}

static void
qppe_edma_txdesc2cmpl_read (qppe_device_t *qd, u32 ring, u32 *v)
{
  u32 word = qppe_edma_reg_rd (qd, EDMA_REG_TXDESC2CMPL_MAP_0 +
				     (ring / EDMA_TXDESC2CMPL_MAP_RINGS_PER_WORD) * sizeof (u32));

  v[0] = (word >> ((ring % EDMA_TXDESC2CMPL_MAP_RINGS_PER_WORD) * EDMA_TXDESC2CMPL_MAP_RING_BITS)) &
	 0x1f;
}

u8 *
format_qppe_edma_txdesc2cmpl_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  static const char *const columns[] = {
    "TX descriptor ring",
    "TX completion ring",
  };

  return qppe_edma_format_rings (s, dev, "EDMA_TXDESC2CMPL_MAP", columns, ARRAY_LEN (columns), 0, 0,
				 EDMA_TXDESC_RING_COUNT, qppe_edma_txdesc2cmpl_read);
}
