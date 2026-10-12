/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/format_table.h>
#include <qppe.h>

u8 *
format_edma_rx_desc (u8 *s, va_list *args)
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

u8 *
format_edma_rx_sec_desc (u8 *s, va_list *args)
{
  const edma_rx_sec_desc_t *desc = va_arg (*args, const edma_rx_sec_desc_t *);

  return format (s,
		 "timestamp 0x%08x%08x timestamp_valid %u qos_tag 0x%08x flow_idx %u "
		 "flow_idx_valid %u",
		 desc->timestamp_hi, desc->timestamp_lo, desc->timestamp_valid, desc->qos_tag,
		 desc->flow_idx, desc->flow_idx_valid);
}

u8 *
format_qppe_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  qppe_rx_trace_t *t = va_arg (*args, qppe_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 indent = format_get_indent (s);

  s = format (s, "qppe: %U (%u) next-node %U", format_vnet_sw_if_index_name, vnm, t->sw_if_index,
	      t->sw_if_index, format_vlib_next_node_name, vm, node->index, t->next_index);

  s =
    format (s, "\n%Udesc: %U", format_white_space, indent + 2, format_edma_rx_desc, &t->head.desc);
  s = format_word_wrap_last_line (s, 100);
  s = format (s, "\n%Usec_desc: %U", format_white_space, indent + 2, format_edma_rx_sec_desc,
	      &t->head.sec_desc);
  s = format_word_wrap_last_line (s, 100);

  for (u16 i = 0; i < t->n_tail; i++)
    {
      s = format (s, "\n%Utail[%u] desc: %U", format_white_space, indent + 2, i,
		  format_edma_rx_desc, &t->tail[i].desc);
      s = format_word_wrap_last_line (s, 100);
      s = format (s, "\n%Utail[%u] sec_desc: %U", format_white_space, indent + 2, i,
		  format_edma_rx_sec_desc, &t->tail[i].sec_desc);
      s = format_word_wrap_last_line (s, 100);
    }

  return s;
}

u8 *
format_edma_tx_desc (u8 *s, va_list *args)
{
  const edma_tx_desc_t *desc = va_arg (*args, const edma_tx_desc_t *);

  return format (s,
		 "buffer_address 0x%08x%02x more %u service_code %u opaque 0x%08x%08x "
		 "destination_port_id %u destination_type %u data_length %u pool_id %u "
		 "tso_enable %u ip_checksum_enable %u l4_checksum_mode %u advanced_offload %u "
		 "mss %u",
		 desc->buffer_address, desc->buffer_address_hi, desc->more, desc->service_code,
		 desc->opaque_high, desc->opaque_low, desc->destination_port_id,
		 desc->destination_type, desc->data_length, desc->pool_id, desc->tso_enable,
		 desc->ip_checksum_enable, desc->l4_checksum_mode, desc->advanced_offload,
		 desc->mss);
}

u8 *
format_edma_txcmpl_desc (u8 *s, va_list *args)
{
  const edma_txcmpl_desc_t *desc = va_arg (*args, const edma_txcmpl_desc_t *);

  return format (s, "opaque 0x%08x%08x pool_id %u more %u error 0x%x", desc->opaque_high,
		 desc->opaque_low, desc->pool_id, desc->more, desc->error);
}

u8 *
format_qppe_tx_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  qppe_tx_trace_t *t = va_arg (*args, qppe_tx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 indent = format_get_indent (s);

  s = format (s, "qppe: %U tx-queue %u n-descs %u", format_vnet_hw_if_index_name, vnm,
	      t->hw_if_index, t->queue_id, t->n_descs);

  s = format (s, "\n%Udesc: %U", format_white_space, indent + 2, format_edma_tx_desc, &t->desc);
  s = format_word_wrap_last_line (s, 100);

  return s;
}

static u8 *
format_qppe_ring_queue_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 ring, word, row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "EDMA ring", "Word", "Queue IDs");
  for (ring = 0; ring < EDMA_RX_RING_COUNT; ring++)
    for (word = 0; word < EDMA_RING_Q_MAP_WORDS; word++)
      {
	u32 offset = PPE_REG_RING_Q_MAP_TBL (EDMA_RXDESC_RING_START + ring) + word * sizeof (u32);
	u32 value = qppe_mmio_read32 (qd, offset);
	uword *qids;

	if (value == 0)
	  continue;

	qids = clib_bitmap_set_multiple (0, word * 32, value, 32);

	table_format_cell (&table, row, 0, "%u", EDMA_RXDESC_RING_START + ring);
	table_format_cell (&table, row, 1, "%u", word);
	table_format_cell (&table, row, 2, "%U", format_bitmap_list, qids);
	clib_bitmap_free (qids);
	row++;
      }

  u32 indent = format_get_indent (s);
  s = format (s, "PPE ring queue bitmap:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_qid2rid_range (u8 *s, qppe_device_t *qd, u32 start, u32 count, u32 indent)
{
  for (u32 qid = start; qid < start + count; qid += 16)
    {
      s = format_newline (s, indent);
      s = format (s, "%3u:", qid);
      for (u32 i = 0; i < 16 && qid + i < start + count; i++)
	{
	  u32 offset = EDMA_BASE_OFFSET + EDMA_REG_QID2RID_TABLE (qid + i);
	  u32 value = qppe_mmio_read32 (qd, offset);
	  u32 ring = (value >> (((qid + i) % 4) * 8)) & 0xff;

	  s = format (s, " %3u", ring);
	}
    }
  return s;
}

static u8 *
format_qppe_qid2rid (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  indent = format_get_indent (s);
  s = format (s, "EDMA QID2RID (CPU unicast and multicast queues), qid: ring per column:");
  s = format_qppe_qid2rid_range (s, qd, 0, EDMA_RX_QUEUE_ID_COUNT, indent + 2);
  s = format_qppe_qid2rid_range (s, qd, PPE_CPU_MCAST_QUEUE_START, PPE_CPU_MCAST_QUEUE_COUNT,
				 indent + 2);
  return s;
}

static u8 *
format_qppe_ucast_priority_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "profile", "priority", "queue offset");
  /* hardware supports 16 profiles x 16 priorities (256 flat entries); skip
   * a whole profile block only when every one of its 16 rows, including
   * priority 0, reads 0 - priority 0 legitimately maps to queue 0 on a
   * profile that IS configured, so a per-row zero-skip would hide it. */
  for (u32 profile = 0; profile < 16; profile++)
    {
      u32 values[16];
      u8 any_nonzero = 0;

      for (u32 priority = 0; priority < 16; priority++)
	{
	  values[priority] =
	    qppe_mmio_read32 (qd, PPE_REG_UCAST_PRIORITY_MAP_TBL (profile, priority));
	  any_nonzero |= values[priority] != 0;
	}

      if (!any_nonzero)
	continue;

      for (u32 priority = 0; priority < 16; priority++)
	{
	  table_format_cell (&table, row, 0, "%u", profile);
	  table_format_cell (&table, row, 1, "%u", priority);
	  table_format_cell (&table, row, 2, "%u", values[priority]);
	  row++;
	}
    }

  u32 indent = format_get_indent (s);
  s = format (s, "PPE UCAST_PRIORITY_MAP_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_mcast_priority_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "port", "priority", "value");
  /* qppe never writes this table at all, so 0 is unambiguously "never
   * configured" here - no priority-0-is-legitimately-0 caveat like the
   * unicast priority map. */
  for (u32 port_id = 0; port_id < PPE_MAX_PORTS; port_id++)
    for (u32 priority = 0; priority < 16; priority++)
      {
	u32 value = qppe_mmio_read32 (qd, PPE_REG_MCAST_PRIORITY_MAP_TBL (port_id, priority));

	if (value == 0)
	  continue;

	table_format_cell (&table, row, 0, "%u", port_id);
	table_format_cell (&table, row, 1, "%u", priority);
	table_format_cell (&table, row, 2, "0x%08x", value);
	row++;
      }

  u32 indent = format_get_indent (s);
  s = format (s, "PPE MCAST_PRIORITY_MAP_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_mcast_queue_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 cpu_code, row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 2, "CPU code", "Hardware value");
  /* No dedicated valid bit; an all-zero row means this cpu code was
   * never assigned a queue class, i.e. never configured. */
  for (cpu_code = 0; cpu_code < 256; cpu_code++)
    {
      u32 offset = PPE_REG_MCAST_QUEUE_MAP_TBL (cpu_code);
      u32 value = qppe_mmio_read32 (qd, offset);

      if (value == 0)
	continue;

      table_format_cell (&table, row, 0, "%u", cpu_code);
      table_format_cell (&table, row, 1, "0x%08x", value);
      row++;
    }

  u32 indent = format_get_indent (s);
  s = format (s, "PPE multicast CPU-code queue class:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_rxdesc2fill_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 ring, row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 2, "RX descriptor ring", "RX fill ring");
  for (ring = EDMA_RXDESC_RING_START; ring < EDMA_RXDESC_RING_START + EDMA_RX_RING_COUNT; ring++)
    {
      u32 offset = EDMA_BASE_OFFSET + EDMA_REG_RXDESC2FILL_MAP_0 + (ring / 10) * sizeof (u32);
      u32 value = qppe_mmio_read32 (qd, offset);
      u32 fill_ring = (value >> ((ring % 10) * 3)) & 0x7;

      table_format_cell (&table, row, 0, "%u", ring);
      table_format_cell (&table, row, 1, "%u", fill_ring);
      row++;
    }

  u32 indent = format_get_indent (s);
  s = format (s, "EDMA RX descriptor-to-fill map:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_mru_mtu_ctrl_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 22, "idx", "mru", "mru_cmd", "mtu", "mtu_cmd", "rx_cnt_en",
		     "tx_cnt_en", "source_profile", "pcp_qos_group_id", "dscp_qos_group_id",
		     "pcp_res_prec_force", "dscp_res_prec_force", "preheader_res_prec",
		     "pcp_res_prec", "dscp_res_prec", "flow_res_prec", "pre_acl_res_prec",
		     "post_acl_res_prec", "source_filtering_bypass", "source_filtering_mode",
		     "pre_ipo_outer_res_prec", "pre_ipo_inner_res_prec");
  /* only entries 0..PPE_MAX_PORTS are ever written (mainline and qppe both
   * index this 256-entry table by raw physical port number). */
  for (u32 idx = 0; idx < PPE_MAX_PORTS; idx++)
    {
      u32 offset = PPE_REG_MRU_MTU_CTRL_W0 (idx);
      ppe_reg_mru_mtu_ctrl_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, offset) };
      ppe_reg_mru_mtu_ctrl_w1_t w1;
      ppe_reg_mru_mtu_ctrl_w2_t w2;
      u32 pre_ipo_inner_res_prec;

      w1.as_u32 = qppe_mmio_read32 (qd, offset + sizeof (u32));
      w2.as_u32 = qppe_mmio_read32 (qd, offset + 2 * sizeof (u32));
      pre_ipo_inner_res_prec = w1.pre_ipo_inner_res_prec_0 | (w2.pre_ipo_inner_res_prec_1 << 1);

      table_format_cell (&table, row, 0, "%u", idx);
      table_format_cell (&table, row, 1, "%u", w0.mru);
      table_format_cell (&table, row, 2, "%u", w0.mru_cmd);
      table_format_cell (&table, row, 3, "%u", w0.mtu);
      table_format_cell (&table, row, 4, "%u", w0.mtu_cmd);
      table_format_cell (&table, row, 5, "%u", w1.rx_cnt_en);
      table_format_cell (&table, row, 6, "%u", w1.tx_cnt_en);
      table_format_cell (&table, row, 7, "%u", w1.source_profile);
      table_format_cell (&table, row, 8, "%u", w1.pcp_qos_group_id);
      table_format_cell (&table, row, 9, "%u", w1.dscp_qos_group_id);
      table_format_cell (&table, row, 10, "%u", w1.pcp_res_prec_force);
      table_format_cell (&table, row, 11, "%u", w1.dscp_res_prec_force);
      table_format_cell (&table, row, 12, "%u", w1.preheader_res_prec);
      table_format_cell (&table, row, 13, "%u", w1.pcp_res_prec);
      table_format_cell (&table, row, 14, "%u", w1.dscp_res_prec);
      table_format_cell (&table, row, 15, "%u", w1.flow_res_prec);
      table_format_cell (&table, row, 16, "%u", w1.pre_acl_res_prec);
      table_format_cell (&table, row, 17, "%u", w1.post_acl_res_prec);
      table_format_cell (&table, row, 18, "%u", w1.source_filtering_bypass);
      table_format_cell (&table, row, 19, "%u", w1.source_filtering_mode);
      table_format_cell (&table, row, 20, "%u", w1.pre_ipo_outer_res_prec);
      table_format_cell (&table, row, 21, "%u", pre_ipo_inner_res_prec);
      row++;
    }

  u32 indent = format_get_indent (s);
  s = format (s, "PPE MRU_MTU_CTRL_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_mc_mtu_ctrl_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 4, "idx", "mtu", "mtu_cmd", "tx_cnt_en");
  for (u32 idx = 0; idx < PPE_MAX_PORTS; idx++)
    {
      ppe_reg_mc_mtu_ctrl_tbl_t mc = { .as_u32 =
					 qppe_mmio_read32 (qd, PPE_REG_MC_MTU_CTRL_TBL (idx)) };

      table_format_cell (&table, row, 0, "%u", idx);
      table_format_cell (&table, row, 1, "%u", mc.mtu);
      table_format_cell (&table, row, 2, "%u", mc.mtu_cmd);
      table_format_cell (&table, row, 3, "%u", mc.tx_cnt_en);
      row++;
    }

  u32 indent = format_get_indent (s);
  s = format (s, "PPE MC_MTU_CTRL_TBL (this port):");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);

  s = format (s, "platform device %s, device tree node %v", dev->device_id, qd->dt_path);
  s = format_newline (s, indent);
  s = format (s, "register window virtual %p", qd->regs);
  s = format_newline (s, indent);

  if (qd->regs)
    {
      u32 chip_id = qppe_mmio_read32 (qd, 0);
      u32 chip_ver = (chip_id >> 8) & 0xff;
      u32 chip_revision = chip_id & 0xff;
      static const struct
      {
	u8 chip_type;
	const char *chip_name;
      } chip_types[] = {
#define _(type, name) { type, #name },
	foreach_ppe_chip_type
#undef _
      };
      const char *chip_name = "unknown";

      for (u32 i = 0; i < ARRAY_LEN (chip_types); i++)
	if (chip_types[i].chip_type == chip_ver)
	  {
	    chip_name = chip_types[i].chip_name;
	    break;
	  }

      s = format (s, "chip ID 0x%08x (version 0x%02x = %s, revision 0x%02x)", chip_id, chip_ver,
		  chip_name, chip_revision);
      s = format_newline (s, indent);
    }

  s = format (s, "PPE port mux control 0x%08x (XGMAC select 0x%02x, port 5 PCS1 %s)",
	      qd->hw_state.port_mux_control.as_u32, qd->hw_state.port_mux_control.xgmac_select,
	      qd->hw_state.port_mux_control.port5_pcs1_select ? "selected" : "not selected");
  s = format_newline (s, indent);
  s = format (s, "BM shared group 0 config 0x%08x (shared buffer limit %u)",
	      qd->hw_state.bm_shared_group0_config.as_u32,
	      qd->hw_state.bm_shared_group0_config.shared_buffer_limit);
  s = format_newline (s, indent);
  s = format (s, "EDMA version %u (0x%08x)", qd->hw_state.edma_version, qd->hw_state.edma_version);
  s = format_newline (s, indent);
  s = format (s, "EDMA port control 0x%08x (EDMA %s, TX padding %s)",
	      qd->hw_state.edma_port_control.as_u32,
	      qd->hw_state.edma_port_control.edma_enable ? "enabled" : "disabled",
	      qd->hw_state.edma_port_control.tx_padding_enable ? "enabled" : "disabled");

  if (a->debug > 0)
    {
      s = format (s, "\n%UGlobal hardware tables (MMIO)", format_white_space, indent);
      if (qd->hw_initialized && qd->regs)
	{
	  ppe_reg_port_bridge_ctrl_t cpu_bridge_ctrl = {
	    .as_u32 = qppe_mmio_read32 (qd, PPE_REG_PORT_BRIDGE_CTRL (EDMA_CPU_PORT_ID)),
	  };

	  s = format_newline (s, indent);
	  s = format (s, "PPE CPU PORT_BRIDGE_CTRL 0x%08x (isolation 0x%02x, txmac_en=%u)",
		      cpu_bridge_ctrl.as_u32, cpu_bridge_ctrl.port_isolation_bitmap,
		      cpu_bridge_ctrl.txmac_en);
	  s = format_newline (s, indent);

	  /* EDMA ring/queue mapping. */
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_ring_queue_map, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_qid2rid, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_rxdesc2fill_map, dev);

	  /* VSI/XLT ingress classification (vsi.c). */
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_rule_and_action_tbl, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_vsi_tbl, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_vsi_remap_tbl, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_port_vsi_enqueue_map, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_ucast_queue_map_tbl, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_l2_vp_port_tbl, dev);

	  /* CPU-code based multicast queue class, never configured by this
	   * driver. */
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_mcast_queue_map, dev);

	  /* BM/QM admission control (hw.c). */
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_bm_shared_group_cfg, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_bm_port_fc_cfg, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_ac_grp_cfg, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_ac_unicast_queue_cfg, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_ac_multicast_queue_cfg, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_enq_deq_opr, dev);

	  /* Service-code tables (edma.c). */
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_service_tbl, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_in_l2_service_tbl, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_eg_service_tbl, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_tl_service_tbl, dev);

	  /* per-port MRU/MTU and priority-map tables are device-wide hardware
	   * resources (one instance per PPE, not one per VPP port), so they
	   * belong here, not in format_qppe_port_status. */
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_mru_mtu_ctrl_tbl, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_mc_mtu_ctrl_tbl, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_ucast_priority_map, dev);
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_mcast_priority_map, dev);
	}
      else
	s = format (s, "\n%UPPE is not initialized; hardware tables were not read",
		    format_white_space, indent + 2);
    }

  return s;
}

u8 *
format_qppe_rxq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
  qppe_device_t *qd = vnet_dev_get_data (rxq->port->dev);
  u32 indent = format_get_indent (s);

  if (a->debug)
    {
      s = format (s, "EDMA fill-ring-id %u", qr->fill_ring_id);

      /* raw hardware ring position, not a counter: hw_prod/hw_fill_prod are
       * the hardware's own free-running producer indices, read straight
       * from the ring's MMIO registers; desc_cons/fill_prod are software's
       * own tracked position in the same free-running space. A growing gap
       * between the hardware and software sides here means software has
       * stopped draining descriptors the hardware already posted. */
      s = format (
	s, ",\n%Udesc ring: hw_prod %u sw_cons %u, fill ring: hw_prod %u sw_prod %u n_buffers %u",
	format_white_space, indent,
	qppe_mmio_read32 (qd, qr->rxdesc_offset) & EDMA_RX_PROD_CONS_MASK, qr->desc_cons,
	qppe_mmio_read32 (qd, qr->rxfill_prod_offset) & EDMA_RX_PROD_CONS_MASK, qr->fill_prod,
	qr->n_buffers);

      /* read-only probe: EDMA_REG_RX_INT_CTRL (what this driver already
       * writes once at ring setup) is a different address block than the
       * vendor SDK's actual EDMA v1 per-ring interrupt status/mask
       * registers below, which this driver has never touched at all. */
      s = format (
	s, ",\n%Uint_stat 0x%08x int_mask 0x%08x", format_white_space, indent,
	qppe_mmio_read32 (qd, EDMA_BASE_OFFSET + EDMA_REG_RXDESC_INT_STAT (qr->desc_ring_id)),
	qppe_mmio_read32 (qd, EDMA_BASE_OFFSET + EDMA_REG_RXDESC_INT_MASK (qr->desc_ring_id)));

      /* global (not per-ring) EDMA error status/mask - RX_DESC_FIFO_FULL,
       * RX_ERR_BUF_SIZE etc, same base block as MAS_CTRL/PORT_CTRL above
       * which are already confirmed correct. Read-only for now. */
      s = format (s, ",\n%Umisc_int_stat 0x%08x misc_int_mask 0x%08x", format_white_space, indent,
		  qppe_mmio_read32 (qd, EDMA_BASE_OFFSET + EDMA_REG_MISC_INT_STAT),
		  qppe_mmio_read32 (qd, EDMA_BASE_OFFSET + EDMA_REG_MISC_INT_MASK));

      /* per-descriptor-ring HW self-test loopback, never touched by this
       * driver. Read-only for now, to check whether any bit is set. */
      s = format (s, ",\n%Uloopback_ctrl 0x%08x", format_white_space, indent,
		  qppe_mmio_read32 (qd, EDMA_BASE_OFFSET + EDMA_REG_LOOPBACK_CTRL));
    }

  return s;
}

u8 *
format_qppe_txq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_tx_queue_t *txq = va_arg (*args, vnet_dev_tx_queue_t *);
  qppe_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  qppe_device_t *qd = vnet_dev_get_data (txq->port->dev);
  u32 indent = format_get_indent (s);

  if (a->debug > 0 && tq->ring_ids_allocated)
    s = format (s,
		"\n%UEDMA desc ring %u: sw_prod %u hw_cons %u ctrl 0x%08x, completion ring %u: "
		"hw_prod %u sw_cons %u",
		format_white_space, indent, tq->desc_ring_id, tq->prod,
		qppe_mmio_read32 (qd, tq->txdesc_cons_offset) & EDMA_TX_PROD_CONS_MASK,
		qppe_mmio_read32 (qd, EDMA_BASE_OFFSET + EDMA_REG_TXDESC_CTRL (tq->desc_ring_id)),
		tq->cmpl_ring_id,
		qppe_mmio_read32 (qd, tq->txcmpl_prod_offset) & EDMA_TX_PROD_CONS_MASK,
		tq->cmpl_cons);

  return s;
}

u8 *
format_qppe_port_status (u8 *s, va_list *args)
{
  __clib_unused vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  u32 indent = format_get_indent (s);

  s = format (s, "port id %u", port->port_id);
  if (qp->label)
    s = format (s, ", device tree label '%s'", qp->label);
  if (qp->phy_mode)
    s = format (s, ", PHY mode '%s'", qp->phy_mode);
  if (qp->managed)
    s = format (s, ", managed '%s'", qp->managed);

  if (qp->is_xgmac)
    {
      s = format (s, "\n%UXGMAC TX config 0x%08x (speed %u, TX %s)", format_white_space, indent,
		  qp->hw_state.xgmac_tx_config.as_u32, qp->hw_state.xgmac_tx_config.speed,
		  qp->hw_state.xgmac_tx_config.tx_enable ? "enabled" : "disabled");
      s = format (s, "\n%UXGMAC RX config 0x%08x (RX %s)", format_white_space, indent,
		  qp->hw_state.xgmac_rx_config.as_u32,
		  qp->hw_state.xgmac_rx_config.rx_enable ? "enabled" : "disabled");
    }
  else
    s = format (s, "\n%UGMAC enable 0x%08x (TX %s, RX %s)", format_white_space, indent,
		qp->hw_state.gmac_enable.as_u32,
		qp->hw_state.gmac_enable.tx_enable ? "enabled" : "disabled",
		qp->hw_state.gmac_enable.rx_enable ? "enabled" : "disabled");

  s = format (s,
	      "\n%UPORT_BRIDGE_CTRL 0x%08x (new_addr lrn=%u/cmd=%u, station_move lrn=%u/cmd=%u, "
	      "isolation=0x%02x, txmac_en=%u, promisc_en=%u)",
	      format_white_space, indent, qp->hw_state.port_bridge_ctrl.as_u32,
	      qp->hw_state.port_bridge_ctrl.new_addr_lrn_en,
	      qp->hw_state.port_bridge_ctrl.new_addr_fwd_cmd,
	      qp->hw_state.port_bridge_ctrl.station_move_lrn_en,
	      qp->hw_state.port_bridge_ctrl.station_move_fwd_cmd,
	      qp->hw_state.port_bridge_ctrl.port_isolation_bitmap,
	      qp->hw_state.port_bridge_ctrl.txmac_en, qp->hw_state.port_bridge_ctrl.promisc_en);

  return s;
}
