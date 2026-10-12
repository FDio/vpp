/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <qppe.h>

u8 *
format_ppe_edma_rx_metadata (u8 *s, va_list *args)
{
  const ppe_edma_rx_metadata_t *metadata = va_arg (*args, const ppe_edma_rx_metadata_t *);

  return format (s, "0x%08x (PID %u, L3 offset %u)", metadata->as_u32, metadata->pid,
		 metadata->l3_offset);
}

u8 *
format_ppe_edma_rx_desc (u8 *s, va_list *args)
{
  const ppe_edma_rx_desc_t *desc = va_arg (*args, const ppe_edma_rx_desc_t *);

  return format (s,
		 "buffer_address 0x%08x%02x more %u fake_mac %u cpu_code_valid %u "
		 "service_code %u acl_idx_valid %u int_pri %u opaque 0x%08x%08x "
		 "source_port_id %u source_type %u destination_port_id %u destination_type %u "
		 "packet_length %u cpu_code %u data_offset %u l4_checksum_status %u "
		 "l3_checksum_status %u metadata %U",
		 desc->buffer_address, desc->buffer_address_hi, desc->more, desc->fake_mac,
		 desc->cpu_code_valid, desc->service_code, desc->acl_idx_valid, desc->int_pri,
		 desc->opaque_high, desc->opaque_low, desc->source_port_id, desc->source_type,
		 desc->destination_port_id, desc->destination_type, desc->packet_length,
		 desc->cpu_code, desc->data_offset, desc->l4_checksum_status,
		 desc->l3_checksum_status, format_ppe_edma_rx_metadata, &desc->metadata);
}

u8 *
format_ppe_edma_rx_sec_desc (u8 *s, va_list *args)
{
  const ppe_edma_rx_sec_desc_t *desc = va_arg (*args, const ppe_edma_rx_sec_desc_t *);

  return format (s,
		 "timestamp 0x%08x%08x timestamp_valid %u qos_tag 0x%08x flow_idx %u "
		 "flow_idx_valid %u",
		 desc->timestamp_hi, desc->timestamp_lo, desc->timestamp_valid, desc->qos_tag,
		 desc->flow_idx, desc->flow_idx_valid);
}

static u8 *
format_qppe_ring_queue_map (u8 *s, qppe_device_t *qd, u32 indent)
{
  table_t table = {};
  u32 ring, word, row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "EDMA ring", "Word", "Hardware value");
  for (ring = 0; ring < PPE_EDMA_RX_RING_COUNT; ring++)
    for (word = 0; word < PPE_EDMA_RING_Q_MAP_WORDS; word++)
      {
	u32 offset =
	  PPE_REG_RING_Q_MAP_TBL (PPE_EDMA_RXDESC_RING_START + ring) + word * sizeof (u32);
	u32 value = qppe_mmio_read32 (qd, offset);

	table_format_cell (&table, row, 0, "%u", PPE_EDMA_RXDESC_RING_START + ring);
	table_format_cell (&table, row, 1, "%u", word);
	table_format_cell (&table, row, 2, "0x%08x", value);
	row++;
      }

  table_format_title (&table, "PPE ring queue bitmap readback");
  s = format (s, "\n%U%U", format_white_space, indent, format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_qid2rid (u8 *s, qppe_device_t *qd, u32 indent)
{
  table_t table = {};
  u32 qid, row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 6, "First QID", "Hardware value", "Q0 ring", "Q1 ring", "Q2 ring",
		     "Q3 ring");
  for (qid = 0; qid < PPE_EDMA_RX_QUEUE_ID_COUNT; qid += 4)
    {
      u32 offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_QID2RID_TABLE (qid);
      u32 value = qppe_mmio_read32 (qd, offset);

      table_format_cell (&table, row, 0, "%u", qid);
      table_format_cell (&table, row, 1, "0x%08x", value);
      table_format_cell (&table, row, 2, "%u", value & 0xff);
      table_format_cell (&table, row, 3, "%u", (value >> 8) & 0xff);
      table_format_cell (&table, row, 4, "%u", (value >> 16) & 0xff);
      table_format_cell (&table, row, 5, "%u", value >> 24);
      row++;
    }

  for (qid = PPE_CPU_MCAST_QUEUE_START; qid < PPE_CPU_MCAST_QUEUE_START + PPE_CPU_MCAST_QUEUE_COUNT;
       qid += 4)
    {
      u32 offset = PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_QID2RID_TABLE (qid);
      u32 value = qppe_mmio_read32 (qd, offset);

      table_format_cell (&table, row, 0, "%u", qid);
      table_format_cell (&table, row, 1, "0x%08x", value);
      table_format_cell (&table, row, 2, "%u", value & 0xff);
      table_format_cell (&table, row, 3, "%u", (value >> 8) & 0xff);
      table_format_cell (&table, row, 4, "%u", (value >> 16) & 0xff);
      table_format_cell (&table, row, 5, "%u", value >> 24);
      row++;
    }

  table_format_title (&table, "EDMA QID2RID readback (CPU unicast and multicast queues)");
  s = format (s, "\n%U%U", format_white_space, indent, format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_ucast_queue_map (u8 *s, qppe_device_t *qd, u32 indent, u32 n_profiles)
{
  table_t table = {};
  u32 profile, row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 5, "Source profile", "Destination port", "Hardware value",
		     "Mapped profile", "Queue base");
  for (profile = 0; profile < n_profiles; profile++)
    {
      ppe_reg_ucast_queue_map_t value = {
	.as_u32 = qppe_mmio_read32 (qd, PPE_REG_UCAST_QUEUE_MAP_TBL (profile, 0)),
      };

      table_format_cell (&table, row, 0, "%u", profile);
      table_format_cell (&table, row, 1, "0");
      table_format_cell (&table, row, 2, "0x%08x", value.as_u32);
      table_format_cell (&table, row, 3, "%u", value.profile_id);
      table_format_cell (&table, row, 4, "%u", value.queue_id);
      row++;
    }

  table_format_title (&table, "PPE unicast queue base readback");
  s = format (s, "\n%U%U", format_white_space, indent, format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_ucast_priority_map (u8 *s, qppe_device_t *qd, u32 indent, u32 n_profiles)
{
  table_t table = {};
  u32 profile, priority, row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "Profile", "Priority", "Hardware value");
  for (profile = 0; profile < n_profiles; profile++)
    for (priority = 0; priority < 16; priority++)
      {
	u32 offset = PPE_REG_UCAST_PRIORITY_MAP_TBL (profile, priority);
	u32 value = qppe_mmio_read32 (qd, offset);

	table_format_cell (&table, row, 0, "%u", profile);
	table_format_cell (&table, row, 1, "%u", priority);
	table_format_cell (&table, row, 2, "0x%08x", value);
	row++;
      }

  table_format_title (&table, "PPE unicast priority map readback");
  s = format (s, "\n%U%U", format_white_space, indent, format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_mcast_priority_map (u8 *s, vnet_dev_t *dev, qppe_device_t *qd, u32 indent)
{
  table_t table = {};
  u32 priority, row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "Port", "Priority", "Hardware value");
  foreach_vnet_dev_port (port, dev)
    for (priority = 0; priority < 16; priority++)
      {
	u32 offset = PPE_REG_MCAST_PRIORITY_MAP_TBL (port->port_id, priority);
	u32 value = qppe_mmio_read32 (qd, offset);

	table_format_cell (&table, row, 0, "%u", port->port_id);
	table_format_cell (&table, row, 1, "%u", priority);
	table_format_cell (&table, row, 2, "0x%08x", value);
	row++;
      }

  table_format_title (&table, "PPE multicast priority map readback");
  s = format (s, "\n%U%U", format_white_space, indent, format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_mcast_queue_map (u8 *s, qppe_device_t *qd, u32 indent)
{
  table_t table = {};
  u32 cpu_code, row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 2, "CPU code", "Hardware value");
  for (cpu_code = 0; cpu_code < 256; cpu_code++)
    {
      u32 offset = PPE_REG_MCAST_QUEUE_MAP_TBL (cpu_code);
      u32 value = qppe_mmio_read32 (qd, offset);

      table_format_cell (&table, row, 0, "%u", cpu_code);
      table_format_cell (&table, row, 1, "0x%08x", value);
      row++;
    }

  table_format_title (&table, "PPE multicast CPU-code queue class readback");
  s = format (s, "\n%U%U", format_white_space, indent, format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_ucast_hash_map (u8 *s, qppe_device_t *qd, u32 indent, u32 n_profiles)
{
  table_t table = {};
  u32 profile, hash, row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "Profile", "Hash", "Hardware value");
  for (profile = 0; profile < n_profiles; profile++)
    for (hash = 0; hash < 256; hash++)
      {
	u32 offset = PPE_REG_UCAST_HASH_MAP_TBL (profile, hash);
	u32 value = qppe_mmio_read32 (qd, offset);

	table_format_cell (&table, row, 0, "%u", profile);
	table_format_cell (&table, row, 1, "%u", hash);
	table_format_cell (&table, row, 2, "0x%08x", value);
	row++;
      }

  table_format_title (&table, "PPE unicast hash map readback");
  s = format (s, "\n%U%U", format_white_space, indent, format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_rxdesc2fill_map (u8 *s, qppe_device_t *qd, u32 indent)
{
  table_t table = {};
  u32 ring, row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 4, "RX descriptor ring", "Map register", "Hardware value",
		     "RX fill ring");
  for (ring = PPE_EDMA_RXDESC_RING_START;
       ring < PPE_EDMA_RXDESC_RING_START + PPE_EDMA_RX_RING_COUNT; ring++)
    {
      u32 offset =
	PPE_EDMA_BASE_OFFSET + PPE_EDMA_REG_RXDESC2FILL_MAP_0 + (ring / 10) * sizeof (u32);
      u32 value = qppe_mmio_read32 (qd, offset);
      u32 fill_ring = (value >> ((ring % 10) * 3)) & 0x7;

      table_format_cell (&table, row, 0, "%u", ring);
      table_format_cell (&table, row, 1, "0x%x", offset);
      table_format_cell (&table, row, 2, "0x%08x", value);
      table_format_cell (&table, row, 3, "%u", fill_ring);
      row++;
    }

  table_format_title (&table, "EDMA RX descriptor-to-fill map readback");
  s = format (s, "\n%U%U", format_white_space, indent, format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_port_rx_tables (u8 *s, vnet_dev_t *dev, qppe_device_t *qd, u32 indent)
{
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 6, "Port", "MC MTU", "MRU/MTU W0", "MRU/MTU W1", "Source profile",
		     "MRU/MTU W2");
  foreach_vnet_dev_port (port, dev)
    {
      u32 offset = PPE_REG_MRU_MTU_CTRL_W0 (port->port_id);
      ppe_reg_mru_mtu_ctrl_w1_t w1 = {
	.as_u32 = qppe_mmio_read32 (qd, offset + sizeof (u32)),
      };
      u32 mc_mtu = qppe_mmio_read32 (qd, PPE_REG_MC_MTU_CTRL_TBL (port->port_id));
      u32 w0 = qppe_mmio_read32 (qd, offset);
      u32 w2 = qppe_mmio_read32 (qd, offset + 2 * sizeof (u32));

      table_format_cell (&table, row, 0, "%u", port->port_id);
      table_format_cell (&table, row, 1, "0x%08x", mc_mtu);
      table_format_cell (&table, row, 2, "0x%08x", w0);
      table_format_cell (&table, row, 3, "0x%08x", w1.as_u32);
      table_format_cell (&table, row, 4, "%u", w1.source_profile);
      table_format_cell (&table, row, 5, "0x%08x", w2);
      row++;
    }

  table_format_title (&table, "PPE per-port RX frame limit and source profile readback");
  s = format (s, "\n%U%U", format_white_space, indent, format_table, &table);
  table_free (&table);
  return s;
}

static u8 *
format_qppe_vsi_tables (u8 *s, vnet_dev_t *dev, qppe_device_t *qd, u32 indent)
{
  table_t table = {};
  u32 row = 0;

  if (!qd->hw_initialized || !qd->regs)
    return s;

  table_add_hdr_row (&table, 8, "Port", "VSI", "VP", "XLT rule", "XLT action", "VSI_TBL",
		     "Enqueue map", "VP queue map");
  foreach_vnet_dev_port (port, dev)
    {
      u32 vsi = port->port_id;
      u32 vp = PPE_EDMA_VP_BASE + port->port_id;
      u32 xlt_rule = qppe_mmio_read32 (qd, PPE_REG_XLT_RULE_TBL (port->port_id));
      u32 xlt_action = qppe_mmio_read32 (qd, PPE_REG_XLT_ACTION_TBL (port->port_id) + sizeof (u32));
      u32 vsi_tbl = qppe_mmio_read32 (qd, PPE_REG_VSI_TBL_W0 (vsi));
      u32 enqueue_map =
	qppe_mmio_read32 (qd, PPE_REG_PORT_VSI_ENQUEUE_MAP (PPE_EDMA_CPU_PORT_ID, vsi));
      u32 queue_map = qppe_mmio_read32 (qd, PPE_REG_UCAST_QUEUE_MAP_TBL (0, vp));

      table_format_cell (&table, row, 0, "%u", port->port_id);
      table_format_cell (&table, row, 1, "%u", vsi);
      table_format_cell (&table, row, 2, "%u", vp);
      table_format_cell (&table, row, 3, "0x%08x", xlt_rule);
      table_format_cell (&table, row, 4, "0x%08x", xlt_action);
      table_format_cell (&table, row, 5, "0x%08x", vsi_tbl);
      table_format_cell (&table, row, 6, "0x%08x", enqueue_map);
      table_format_cell (&table, row, 7, "0x%08x", queue_map);
      row++;
    }

  table_format_title (&table, "PPE per-port VSI / virtual-port readback");
  s = format (s, "\n%U%U", format_white_space, indent, format_table, &table);
  table_free (&table);

  table = (table_t) {};
  row = 0;
  table_add_hdr_row (&table, 3, "Port", "L2 VP (invalid-VSI fallback)", "dst_info");
  foreach_vnet_dev_port (port, dev)
    {
      ppe_reg_l2_vp_port_tbl_w0_t l2_vp = {
	.as_u32 = qppe_mmio_read32 (qd, PPE_REG_L2_VP_PORT_TBL_W0 (port->port_id)),
      };

      table_format_cell (&table, row, 0, "%u", port->port_id);
      table_format_cell (&table, row, 1, "0x%08x", l2_vp.as_u32);
      table_format_cell (&table, row, 2, "%u", l2_vp.dst_info);
      row++;
    }

  table_format_title (&table, "PPE per-port invalid-VSI fallback readback");
  s = format (s, "\n%U%U", format_white_space, indent, format_table, &table);
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
      u32 n_profiles = clib_min (qd->n_ports, PPE_EDMA_RX_RING_COUNT);

      s = format (s, "\n%UHardware tables (MMIO readback)", format_white_space, indent);
      if (qd->hw_initialized && qd->regs)
	{
	  s = format_qppe_ring_queue_map (s, qd, indent + 2);
	  s = format_qppe_qid2rid (s, qd, indent + 2);
	  s = format_qppe_rxdesc2fill_map (s, qd, indent + 2);
	  s = format_qppe_ucast_queue_map (s, qd, indent + 2, n_profiles);
	  s = format_qppe_ucast_priority_map (s, qd, indent + 2, n_profiles);
	  s = format_qppe_ucast_hash_map (s, qd, indent + 2, n_profiles);
	  s = format_qppe_mcast_priority_map (s, dev, qd, indent + 2);
	  s = format_qppe_mcast_queue_map (s, qd, indent + 2);
	  s = format_qppe_vsi_tables (s, dev, qd, indent + 2);
	  s = format_qppe_port_rx_tables (s, dev, qd, indent + 2);
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

  if (a->debug)
    s = format (s, "EDMA fill-ring-id %u", qr->fill_ring_id);

  return s;
}

u8 *
format_qppe_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
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

  return s;
}
