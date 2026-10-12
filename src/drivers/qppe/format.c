/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

#define foreach_ppe_chip_type                                                                      \
  _ (0x15, HPPE)                                                                                   \
  _ (0x17, MHT)                                                                                    \
  _ (0x20, APPE)                                                                                   \
  _ (0x21, MRPPE)                                                                                  \
  _ (0x30, JHPPE)                                                                                  \
  _ (0x40, HMSPPE)                                                                                 \
  _ (0x50, HTTPPE)
#define HPPE_REG_MCAST_PRIORITY_MAP_TBL(port, priority)                                            \
  (0x800100 + (0x40 * (port)) + (0x4 * (priority)))
#define HPPE_REG_MCAST_QUEUE_MAP_TBL(cpu_code) (0x844000 + (0x10 * (cpu_code)))

/* A u32 port bitmap, shown as a compact list (e.g. "0-2,5") instead of its
 * raw hex value - a %U drop-in for the clib_bitmap_set_multiple/
 * format_bitmap_list/clib_bitmap_free dance repeated at every call site
 * that prints one. */
u8 *
format_qppe_port_bitmap (u8 *s, va_list *args)
{
  u32 port_bitmap = va_arg (*args, u32);
  uword *bitmap = clib_bitmap_set_multiple (0, 0, port_bitmap, 32);

  s = format (s, "%U", format_bitmap_list, bitmap);
  clib_bitmap_free (bitmap);
  return s;
}

static u8 *
format_qppe_ucast_priority_map (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->regs)
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
	    qppe_mmio_read32 (qd, HPPE_REG_UCAST_PRIORITY_MAP_TBL (profile, priority));
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

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 3, "port", "priority", "value");
  /* qppe never writes this table at all, so 0 is unambiguously "never
   * configured" here - no priority-0-is-legitimately-0 caveat like the
   * unicast priority map. */
  for (u32 port_id = 0; port_id < QPPE_MAX_PORTS; port_id++)
    for (u32 priority = 0; priority < 16; priority++)
      {
	u32 value = qppe_mmio_read32 (qd, HPPE_REG_MCAST_PRIORITY_MAP_TBL (port_id, priority));

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

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 2, "CPU code", "Hardware value");
  /* No dedicated valid bit; an all-zero row means this cpu code was
   * never assigned a queue class, i.e. never configured. */
  for (cpu_code = 0; cpu_code < 256; cpu_code++)
    {
      u32 offset = HPPE_REG_MCAST_QUEUE_MAP_TBL (cpu_code);
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
format_qppe_mru_mtu_ctrl_tbl (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0;

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 22, "idx", "mru", "mru_cmd", "mtu", "mtu_cmd", "rx_cnt_en",
		     "tx_cnt_en", "source_profile", "pcp_qos_group_id", "dscp_qos_group_id",
		     "pcp_res_prec_force", "dscp_res_prec_force", "preheader_res_prec",
		     "pcp_res_prec", "dscp_res_prec", "flow_res_prec", "pre_acl_res_prec",
		     "post_acl_res_prec", "source_filtering_bypass", "source_filtering_mode",
		     "pre_ipo_outer_res_prec", "pre_ipo_inner_res_prec");
  /* only entries 0..QPPE_MAX_PORTS are ever written (mainline and qppe both
   * index this 256-entry table by raw physical port number). */
  for (u32 idx = 0; idx < QPPE_MAX_PORTS; idx++)
    {
      u32 offset = HPPE_REG_MRU_MTU_CTRL_W0 (idx);
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

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 4, "idx", "mtu", "mtu_cmd", "tx_cnt_en");
  for (u32 idx = 0; idx < QPPE_MAX_PORTS; idx++)
    {
      ppe_reg_mc_mtu_ctrl_tbl_t mc = { .as_u32 =
					 qppe_mmio_read32 (qd, HPPE_REG_MC_MTU_CTRL_TBL (idx)) };

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
      ppe_reg_port_mux_control_t port_mux_control = {
	.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_PORT_MUX_CONTROL),
      };
      ppe_reg_bm_shared_group_config_t bm_shared_group0_config = {
	.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_BM_SHARED_GROUP0_CONFIG),
      };
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

      s = format (s, "PPE port mux control 0x%08x (XGMAC select 0x%02x, port 5 PCS1 %s)",
		  port_mux_control.as_u32, port_mux_control.xgmac_select,
		  port_mux_control.port5_pcs1_select ? "selected" : "not selected");
      s = format_newline (s, indent);
      s = format (s, "BM shared group 0 config 0x%08x (shared buffer limit %u)",
		  bm_shared_group0_config.as_u32, bm_shared_group0_config.shared_buffer_limit);
    }

  s = format (s, "%U", format_qppe_edma_info, a, dev);

  if (a->debug > 0)
    {
      s = format (s, "\n%UGlobal hardware tables (MMIO)", format_white_space, indent);
      if (qd->regs)
	{
	  /* VSI/XLT ingress classification (vsi.c), FDB (fdb.c), and ACL
	   * (acl.c) tables have their own "show qppe vsi/fdb/acl" commands
	   * (cli.c) and are deliberately not duplicated here. */

	  /* CPU-code based multicast queue class, never configured by this
	   * driver. */
	  s = format_newline (s, indent);
	  s = format (s, "%U", format_qppe_mcast_queue_map, dev);

	  /* BM and AC admission control. */
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

	  /* Service-code tables (edma.c) have their own "show qppe edma"
	   * command (cli.c) and are deliberately not duplicated here. */

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
format_qppe_port_status (u8 *s, va_list *args)
{
  __clib_unused vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  qppe_device_t *qd = vnet_dev_get_data (port->dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  ppe_reg_port_bridge_ctrl_t bridge_ctrl = {};
  ppe_reg_xgmac_tx_config_t xgmac_tx = {};
  ppe_reg_xgmac_rx_config_t xgmac_rx = {};
  ppe_reg_gmac_enable_t gmac_enable = {};
  u32 offset;
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
      offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_TX_CONFIG;
      xgmac_tx.as_u32 = qppe_mmio_read32 (qd, offset);
      offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_RX_CONFIG;
      xgmac_rx.as_u32 = qppe_mmio_read32 (qd, offset);
      s = format (s, "\n%UXGMAC TX config 0x%08x (speed %u, TX %s)", format_white_space, indent,
		  xgmac_tx.as_u32, xgmac_tx.speed, xgmac_tx.tx_enable ? "enabled" : "disabled");
      s = format (s, "\n%UXGMAC RX config 0x%08x (RX %s)", format_white_space, indent,
		  xgmac_rx.as_u32, xgmac_rx.rx_enable ? "enabled" : "disabled");
    }
  else
    {
      offset = PPE_REG_GMAC_ENABLE (port->port_id);
      gmac_enable.as_u32 = qppe_mmio_read32 (qd, offset);
      s = format (s, "\n%UGMAC enable 0x%08x (TX %s, RX %s)", format_white_space, indent,
		  gmac_enable.as_u32, gmac_enable.tx_enable ? "enabled" : "disabled",
		  gmac_enable.rx_enable ? "enabled" : "disabled");
    }

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
