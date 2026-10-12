/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>
#include <vlib/buffer_funcs.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

static void
qppe_port_table_range (table_t *table, u32 row, u32 first, u32 last)
{
  if (first == last)
    table_format_cell (table, row, 0, "%u", first);
  else
    table_format_cell (table, row, 0, "%u-%u", first, last);
}

static u8 *
format_qppe_port_forward_cmd (u8 *s, va_list *args)
{
  u32 cmd = va_arg (*args, u32);
  const char *const names[] = {
    "forward",
    "drop",
    "copy-to-cpu",
    "redirect-to-cpu",
  };

  if (cmd < ARRAY_LEN (names))
    return format (s, "%s (%u)", names[cmd], cmd);
  return format (s, "Unknown(%u)", cmd);
}

u8 *
format_qppe_port_mru_mtu_ctrl_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);
  const u32 paired_cols[] = {
    5, 7, 8, 10, 16,
  };

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 17, "VP", "MRU", "MRU", "MTU", "MTU", "count en", "source",
		     "QoS Group", "Force Prec", "preheader", "prec", "flow", "pre ACL", "post ACL",
		     "source filter", "source filter", "pre IPO prec");
  table_add_hdr_row (&table, 17, "", "", "cmd", "", "cmd", "RX/TX", "profile", "PCP/DSCP",
		     "PCP/DSCP", "prec", "PCP/DSCP", "prec", "prec", "prec", "bypass", "mode",
		     "outer/inner");
  for (u32 i = 0; i < ARRAY_LEN (paired_cols); i++)
    {
      table_set_cell_align (&table, -2, paired_cols[i], TTAA_CENTER);
      table_set_cell_align (&table, -1, paired_cols[i], TTAA_CENTER);
    }
  for (u32 idx = 0; idx < 256; idx++)
    {
      u32 first = idx;
      u32 offset = HPPE_REG_MRU_MTU_CTRL_W0 (idx);
      ppe_reg_mru_mtu_ctrl_w0_t w0 = { .as_u32 = qppe_mmio_read32 (qd, offset) };
      ppe_reg_mru_mtu_ctrl_w1_t w1;
      ppe_reg_mru_mtu_ctrl_w2_t w2;
      u32 pre_ipo_inner_res_prec;

      w1.as_u32 = qppe_mmio_read32 (qd, offset + sizeof (u32));
      w2.as_u32 = qppe_mmio_read32 (qd, offset + 2 * sizeof (u32));
      w2.reserved_2_31 = 0;
      while (idx + 1 < 256)
	{
	  u32 base = HPPE_REG_MRU_MTU_CTRL_W0 (idx + 1);
	  u32 next[3];

	  for (u32 w = 0; w < ARRAY_LEN (next); w++)
	    next[w] = qppe_mmio_read32 (qd, base + w * sizeof (u32));
	  next[2] &= 3;
	  if (next[0] != w0.as_u32 || next[1] != w1.as_u32 || next[2] != w2.as_u32)
	    break;
	  idx++;
	}
      pre_ipo_inner_res_prec = w1.pre_ipo_inner_res_prec_0 | (w2.pre_ipo_inner_res_prec_1 << 1);

      qppe_port_table_range (&table, row, first, idx);
      table_format_cell (&table, row, 1, "%u", w0.mru);
      table_format_cell (&table, row, 2, "%U", format_qppe_port_forward_cmd, w0.mru_cmd);
      table_format_cell (&table, row, 3, "%u", w0.mtu);
      table_format_cell (&table, row, 4, "%U", format_qppe_port_forward_cmd, w0.mtu_cmd);
      table_format_cell (&table, row, 5, "%u/%u", w1.rx_cnt_en, w1.tx_cnt_en);
      table_format_cell (&table, row, 6, "%u", w1.source_profile);
      table_format_cell (&table, row, 7, "%u/%u", w1.pcp_qos_group_id, w1.dscp_qos_group_id);
      table_format_cell (&table, row, 8, "%u/%u", w1.pcp_res_prec_force, w1.dscp_res_prec_force);
      table_format_cell (&table, row, 9, "%u", w1.preheader_res_prec);
      table_format_cell (&table, row, 10, "%u/%u", w1.pcp_res_prec, w1.dscp_res_prec);
      table_format_cell (&table, row, 11, "%u", w1.flow_res_prec);
      table_format_cell (&table, row, 12, "%u", w1.pre_acl_res_prec);
      table_format_cell (&table, row, 13, "%u", w1.post_acl_res_prec);
      table_format_cell (&table, row, 14, "%u", w1.source_filtering_bypass);
      table_format_cell (&table, row, 15, "%u", w1.source_filtering_mode);
      table_format_cell (&table, row, 16, "%u/%u", w1.pre_ipo_outer_res_prec,
			 pre_ipo_inner_res_prec);
      for (u32 i = 0; i < ARRAY_LEN (paired_cols); i++)
	table_set_cell_align (&table, row, paired_cols[i], TTAA_CENTER);
      row++;
    }

  s = format (s, "MRU_MTU_CTRL_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_port_mc_mtu_ctrl_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 4, "port", "mtu", "mtu_cmd", "tx_cnt_en");
  for (u32 idx = 0; idx < QPPE_MAX_PORTS; idx++)
    {
      u32 first = idx;
      ppe_reg_mc_mtu_ctrl_tbl_t mc = { .as_u32 =
					 qppe_mmio_read32 (qd, HPPE_REG_MC_MTU_CTRL_TBL (idx)) };

      mc.reserved_17_31 = 0;
      while (idx + 1 < QPPE_MAX_PORTS)
	{
	  ppe_reg_mc_mtu_ctrl_tbl_t next = {
	    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_MC_MTU_CTRL_TBL (idx + 1)),
	  };

	  next.reserved_17_31 = 0;
	  if (next.as_u32 != mc.as_u32)
	    break;
	  idx++;
	}
      qppe_port_table_range (&table, row, first, idx);
      table_format_cell (&table, row, 1, "%u", mc.mtu);
      table_format_cell (&table, row, 2, "%U", format_qppe_port_forward_cmd, mc.mtu_cmd);
      table_format_cell (&table, row, 3, "%u", mc.tx_cnt_en);
      row++;
    }

  s = format (s, "MC_MTU_CTRL_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_port_status (u8 *s, va_list *args)
{
  __clib_unused vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  qppe_device_t *qd = vnet_dev_get_data (port->dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  ppe_reg_port_bridge_ctrl_t bridge_ctrl;
  u32 offset;
  u32 indent = format_get_indent (s);

  s = format (s, "port id %u", port->port_id);
  if (qp->label)
    s = format (s, ", device tree label '%s'", qp->label);
  if (qp->phy_mode)
    s = format (s, ", PHY mode '%s'", qp->phy_mode);
  if (qp->managed)
    s = format (s, ", managed '%s'", qp->managed);

  s = format (s, "%U", format_qppe_mac_port_status, port);

  offset = HPPE_REG_PORT_BRIDGE_CTRL (port->port_id);
  bridge_ctrl.as_u32 = qppe_mmio_read32 (qd, offset);
  s = format (s,
	      "\n%UPORT_BRIDGE_CTRL 0x%08x (new_addr lrn=%u/cmd=%u, station_move lrn=%u/cmd=%u, "
	      "isolation=0x%02x, txmac_en=%u, promisc_en=%u)",
	      format_white_space, indent, bridge_ctrl.as_u32, bridge_ctrl.new_addr_lrn_en,
	      bridge_ctrl.new_addr_fwd_cmd, bridge_ctrl.station_move_lrn_en,
	      bridge_ctrl.station_move_fwd_cmd, bridge_ctrl.port_isolation_bitmap,
	      bridge_ctrl.txmac_en, bridge_ctrl.promisc_en);

  return s;
}

static const qppe_reg_field_t ppe_reg_port_mux_control_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_port_mux_control_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_port_tdm_ctrl_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_port_tdm_ctrl_t_fields
#undef _
};
u8 *
format_qppe_port_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s), value;

  if (!qd->regs)
    return s;

  value = qppe_mmio_read32 (qd, APPE_REG_PORT_MUX_CTRL);
  s = format (s, "PORT_MUX_CTRL: 0x%08x", value);
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_qppe_reg_fields, value, ppe_reg_port_mux_control_t_fields,
	      ARRAY_LEN (ppe_reg_port_mux_control_t_fields));
  s = format (s, "\n");
  s = format_newline (s, indent);
  value = qppe_mmio_read32 (qd, HPPE_REG_PORT_TDM_CTRL);
  s = format (s, "PRX_TDM_CTRL: 0x%08x", value);
  s = format_newline (s, indent + 2);
  return format (s, "%U", format_qppe_reg_fields, value, ppe_reg_port_tdm_ctrl_t_fields,
		 ARRAY_LEN (ppe_reg_port_tdm_ctrl_t_fields));
}

u8 *
format_qppe_port_my_mac_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "index", "valid", "MAC");
  for (u32 i = 0; i < QPPE_MAX_PORTS; i++)
    {
      u32 first = i, base = HPPE_REG_MY_MAC_TBL (i);
      ppe_reg_my_mac_tbl_t value;
      vnet_dev_hw_addr_t addr;

      value.val[0] = qppe_mmio_read32 (qd, base);
      value.val[1] = qppe_mmio_read32 (qd, base + sizeof (u32)) & 0x1ffff;
      while (i + 1 < QPPE_MAX_PORTS)
	{
	  u32 next_base = HPPE_REG_MY_MAC_TBL (i + 1);
	  ppe_reg_my_mac_tbl_t next;

	  next.val[0] = qppe_mmio_read32 (qd, next_base);
	  next.val[1] = qppe_mmio_read32 (qd, next_base + sizeof (u32)) & 0x1ffff;
	  if (memcmp (value.val, next.val, sizeof (value.val)))
	    break;
	  i++;
	}
      addr.eth_mac[0] = value.mac_da_1 >> 8;
      addr.eth_mac[1] = value.mac_da_1;
      for (u32 b = 2; b < 6; b++)
	addr.eth_mac[b] = value.mac_da_0 >> (8 * (5 - b));
      qppe_port_table_range (&table, row, first, i);
      table_format_cell (&table, row, 1, "%u", value.valid);
      table_format_cell (&table, row, 2, "%U", format_vnet_dev_hw_addr, &addr);
      row++;
    }
  s = format (s, "MY_MAC_TBL:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_port_forward_fifo (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 5, "port", "source_filtering_bypass", "RX FIFO threshold", "TX xoff",
		     "TX xon");
  for (u32 port = 0; port < QPPE_MAX_PORTS; port++)
    {
      u32 first = port;
      u32 forward = qppe_mmio_read32 (qd, HPPE_REG_PORT_IN_FORWARD (port)) & 1;
      u32 fifo = qppe_mmio_read32 (qd, HPPE_REG_PORT_RX_FIFO_CFG (port)) & 7;
      u32 tx = qppe_mmio_read32 (qd, APPE_REG_PORT_TX_BUFF_THRSH (port)) & 0xffff;

      while (port + 1 < QPPE_MAX_PORTS)
	{
	  u32 next_forward = qppe_mmio_read32 (qd, HPPE_REG_PORT_IN_FORWARD (port + 1)) & 1;
	  u32 next_fifo = qppe_mmio_read32 (qd, HPPE_REG_PORT_RX_FIFO_CFG (port + 1)) & 7;
	  u32 next_tx = qppe_mmio_read32 (qd, APPE_REG_PORT_TX_BUFF_THRSH (port + 1)) & 0xffff;

	  if (next_forward != forward || next_fifo != fifo || next_tx != tx)
	    break;
	  port++;
	}
      qppe_port_table_range (&table, row, first, port);
      table_format_cell (&table, row, 1, "%u", forward);
      table_format_cell (&table, row, 2, "%u", fifo);
      table_format_cell (&table, row, 3, "%u", tx & 0xff);
      table_format_cell (&table, row, 4, "%u", tx >> 8);
      row++;
    }
  s = format (s, "PORT_IN_FORWARD/RX_FIFO_CFG/TX_BUFF_THRSH:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

u8 *
format_qppe_port_tdm (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 6, "slot", "port", "direction", "valid", "secondary valid",
		     "secondary port");
  for (u32 i = 0; i < HPPE_PORT_TDM_ENTRIES; i++)
    {
      u32 first = i;
      ppe_reg_port_tdm_cfg_t value = {
	.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_PORT_TDM_CFG (i)),
      };

      value._reserved0 = value.resv = 0;
      while (i + 1 < HPPE_PORT_TDM_ENTRIES)
	{
	  ppe_reg_port_tdm_cfg_t next = {
	    .as_u32 = qppe_mmio_read32 (qd, HPPE_REG_PORT_TDM_CFG (i + 1)),
	  };

	  next._reserved0 = next.resv = 0;
	  if (next.as_u32 != value.as_u32)
	    break;
	  i++;
	}
      qppe_port_table_range (&table, row, first, i);
      table_format_cell (&table, row, 1, "%u", value.port_num);
      table_format_cell (&table, row, 2, "%u", value.dir);
      table_format_cell (&table, row, 3, "%u", value.valid);
      table_format_cell (&table, row, 4, "%u", value.sec_valid);
      table_format_cell (&table, row, 5, "%u", value.sec_port_num);
      row++;
    }
  s = format (s, "PRX_TDM_CFG:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}
