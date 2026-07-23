/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <pp2/pp2.h>
#include <vppinfra/format_table.h>

typedef struct
{
  const char *name;
  const char *mode;
  mvpp2_port_link_info_t link;
  u32 max_rx_frame_size;
  u8 duplex_known : 1;
  u8 loopback : 1;
  u8 rx_pause : 1;
  u8 valid : 1;
} mvpp2_mac_status_t;

typedef struct
{
  u32 n_buffers;
  u32 buffer_size;
  u8 id;
  u8 active : 1;
} mvpp2_bpool_hw_status_t;

static u8 *
format_mvpp2_link_speed (u8 *s, va_list *args)
{
  u32 speed = va_arg (*args, u32);

  if (speed >= 1000000 && speed % 1000000 == 0)
    return format (s, "%uG", speed / 1000000);
  if (speed >= 1000 && speed % 1000 == 0)
    return format (s, "%uM", speed / 1000);
  return format (s, "%uK", speed);
}

static const char *
mvpp2_dsa_mode_name (u32 mode)
{
  switch (mode)
    {
    case 0:
      return "none";
    case 1:
      return "DSA";
    case 2:
      return "EDSA";
    default:
      return "unknown";
    }
}

static const char *
mvpp2_gmac_mode_name (mvpp22_gmac_port_ctrl4_reg_t control)
{
  if (control.ext_pin_gmii_select)
    return "RGMII";
  if (!control.qsgmii_bypass_active)
    return "QSGMII";
  if (control.dp_clock_select)
    return "SGMII-2.5G";
  return "SGMII";
}

static u32
mvpp2_gmac_link_speed (mvpp22_gmac_port_status0_reg_t status)
{
  if (status.gmii_speed)
    return 1000000;
  if (status.mii_speed)
    return 100000;
  return 10000;
}

static void
mvpp2_gmac_status_read (vnet_dev_port_t *port, mvpp2_mac_status_t *status)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_gmac_port_ctrl0_reg_t control0 = {
    .as_u32 = mvpp2_gop_gmac_reg_rd (port->dev, mp->gop_index, PP2_GMAC_PORT_CTRL0_REG),
  };
  mvpp22_gmac_port_ctrl1_reg_t control1 = {
    .as_u32 = mvpp2_gop_gmac_reg_rd (port->dev, mp->gop_index, PP2_GMAC_PORT_CTRL1_REG),
  };
  mvpp22_gmac_port_ctrl4_reg_t control4 = {
    .as_u32 = mvpp2_gop_gmac_reg_rd (port->dev, mp->gop_index, PP2_GMAC_PORT_CTRL4_REG),
  };
  mvpp22_gmac_port_status0_reg_t link = {
    .as_u32 = mvpp2_gop_gmac_reg_rd (port->dev, mp->gop_index, PP2_GMAC_PORT_STATUS0_REG),
  };

  if (!control0.port_enable)
    return;

  *status = (mvpp2_mac_status_t) {
    .name = "GMAC",
    .mode = mvpp2_gmac_mode_name (control4),
    .link = {
      .up = link.link_up,
      .full_duplex = link.full_duplex,
      .speed = mvpp2_gmac_link_speed (link),
    },
    .max_rx_frame_size = control0.frame_size_limit * 2 - MV_ETH_FCS_LEN,
    .duplex_known = 1,
    .loopback = control1.gmii_loopback || control1.pcs_loopback,
    .rx_pause = control4.rx_flow_control_enable,
    .valid = 1,
  };
}

static void
mvpp2_xlg_status_read (vnet_dev_port_t *port, mvpp2_mac_status_t *status)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_xlg_mac_ctrl0_reg_t control0 = {
    .as_u32 = mvpp2_gop_xlg_reg_rd (port->dev, mp->gop_index, PP2_XLG_PORT_MAC_CTRL0_REG),
  };
  mvpp22_xlg_mac_ctrl1_reg_t control1 = {
    .as_u32 = mvpp2_gop_xlg_reg_rd (port->dev, mp->gop_index, PP2_XLG_PORT_MAC_CTRL1_REG),
  };
  mvpp22_xlg_mac_ctrl3_reg_t control3 = {
    .as_u32 = mvpp2_gop_xlg_reg_rd (port->dev, mp->gop_index, PP2_XLG_PORT_MAC_CTRL3_REG),
  };
  const char *mode = "unknown";
  u32 link = mvpp2_gop_xlg_reg_rd (port->dev, mp->gop_index, PP2_XLG_MAC_PORT_STATUS_REG);
  u32 speed;
  int duplex_known;

  if (!control0.port_enable)
    return;

  if (control3.mac_mode == 0)
    {
      mode = "1G";
      speed = 1000000;
      duplex_known = 0;
    }
  else if (control3.mac_mode == 1)
    {
      mode = "10G";
      speed = 10000000;
      duplex_known = 1;
    }
  else
    {
      speed = 0;
      duplex_known = 0;
    }

  *status = (mvpp2_mac_status_t) {
    .name = "XLG",
    .mode = mode,
    .link = {
      .up = !!(link & PP2_XLG_MAC_PORT_STATUS_LINKSTATUS_MASK),
      .full_duplex = duplex_known,
      .speed = speed,
    },
    .max_rx_frame_size = control1.frame_size_limit * 2 - MV_ETH_FCS_LEN,
    .duplex_known = duplex_known,
    .loopback = control1.mac_loopback || control1.xgmii_loopback,
    .rx_pause = control0.rx_flow_control_enable,
    .valid = 1,
  };
}

static void
mvpp2_mac_status_read (vnet_dev_port_t *port, mvpp2_mac_status_t *status)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  if (mp->is_xlg)
    mvpp2_xlg_status_read (port, status);
  else
    mvpp2_gmac_status_read (port, status);
}

static void
mvpp2_bpool_hw_status_read (vnet_dev_t *dev, u8 pool_id, mvpp2_bpool_hw_status_t *status)
{
  mvpp22_bm_pool_ctrl_reg_t control = {
    .as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_CTRL_REG (pool_id)),
  };
  u32 n_buffers;

  n_buffers =
    (mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_PTRS_NUM_REG (pool_id)) & MVPP22_BM_POOL_PTRS_NUM_MASK) +
    (mvpp2_dev_reg_rd (dev, MVPP2_BM_BPPI_PTRS_NUM_REG (pool_id)) & MVPP2_BM_BPPI_PTR_NUM_MASK);

  *status = (mvpp2_bpool_hw_status_t) {
    .id = pool_id,
    .active = control.state,
    .buffer_size = mvpp2_dev_reg_rd (dev, MVPP2_POOL_BUF_SIZE_REG (pool_id)),
    .n_buffers = n_buffers ? n_buffers + 1 : 0,
  };
}

static int
mvpp2_port_bpool_hw_status_read (vnet_dev_port_t *port, mvpp2_bpool_hw_status_t *status)
{
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
      mvpp22_rxq_config_reg_t config = {
	.as_u32 = mvpp2_dev_reg_rd (port->dev, MVPP2_RXQ_CONFIG_REG (rxq->hw_id)),
      };

      mvpp2_bpool_hw_status_read (port->dev, config.short_pool, status);
      return 1;
    }

  return 0;
}

static u8 *
format_mvpp2_bpool_table (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  mvpp22_bm_pool_base_addr_high_reg_t base_high = {
    .as_u32 = mvpp2_dev_reg_rd (dev, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG),
  };
  table_t table = {};
  u32 n_pools = 0;
  u32 pool_id;

  table_add_hdr_row (&table, 8, "Pool", "State", "BPPE address", "Capacity", "Buffer size", "BPPE",
		     "BPPI", "Buffers");

  for (pool_id = 0; pool_id < MVPP2_NUM_BPOOLS; pool_id++)
    {
      mvpp22_bm_pool_ctrl_reg_t control = {
	.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_CTRL_REG (pool_id)),
      };
      u32 base = mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_BASE_ADDR_REG (pool_id));
      u32 size = mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_SIZE_REG (pool_id));
      u32 n_bppe =
	mvpp2_dev_reg_rd (dev, MVPP2_BM_POOL_PTRS_NUM_REG (pool_id)) & MVPP22_BM_POOL_PTRS_NUM_MASK;
      u32 n_bppi =
	mvpp2_dev_reg_rd (dev, MVPP2_BM_BPPI_PTRS_NUM_REG (pool_id)) & MVPP2_BM_BPPI_PTR_NUM_MASK;
      u32 n_buffers = n_bppe + n_bppi;
      u32 buffer_size = mvpp2_dev_reg_rd (dev, MVPP2_POOL_BUF_SIZE_REG (pool_id));
      u64 bppe_addr = (u64) base_high.addr << 32 | base;

      if (!control.state && !base && !size && !buffer_size)
	continue;

      table_format_cell (&table, n_pools, 0, "%u", pool_id);
      table_format_cell (&table, n_pools, 1, "%s", control.state ? "active" : "stopped");
      table_format_cell (&table, n_pools, 2, "0x%010lx", bppe_addr);
      table_format_cell (&table, n_pools, 3, "%u", size);
      table_format_cell (&table, n_pools, 4, "%u", buffer_size);
      table_format_cell (&table, n_pools, 5, "%u", n_bppe);
      table_format_cell (&table, n_pools, 6, "%u", n_bppi);
      table_format_cell (&table, n_pools, 7, "%u", n_buffers ? n_buffers + 1 : 0);
      n_pools++;
    }

  table_format_title (&table, "Buffer pools (%u)", n_pools);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  return s;
}

static u32
mvpp2_parser_tcam_lookup_get (union mv_pp2x_prs_tcam_entry *tcam)
{
  return tcam->byte[HW_BYTE_OFFS (MVPP2_PRS_TCAM_LU_BYTE)];
}

static u32
mvpp2_parser_tcam_port_map_get (union mv_pp2x_prs_tcam_entry *tcam)
{
  u32 enable_off = HW_BYTE_OFFS (MVPP2_PRS_TCAM_EN_OFFS (MVPP2_PRS_TCAM_PORT_BYTE));

  return ~tcam->byte[enable_off] & MVPP2_PRS_PORT_MASK;
}

static void
mvpp2_parser_tcam_data_byte_get (union mv_pp2x_prs_tcam_entry *tcam, u32 offset, u8 *byte, u8 *mask)
{
  *byte = tcam->byte[TCAM_DATA_BYTE (offset)];
  *mask = tcam->byte[TCAM_DATA_MASK (offset)];
}

static const char *
mvpp2_parser_lookup_name (u32 lookup)
{
  switch (lookup)
    {
    case MVPP2_PRS_LU_MH:
      return "MH";
    case MVPP2_PRS_LU_MAC:
      return "MAC";
    case MVPP2_PRS_LU_DSA:
      return "DSA";
    case MVPP2_PRS_LU_VLAN:
      return "VLAN";
    case MVPP2_PRS_LU_VID:
      return "VID";
    case MVPP2_PRS_LU_L2:
      return "L2";
    case MVPP2_PRS_LU_PPPOE:
      return "PPPoE";
    case MVPP2_PRS_LU_IP4:
      return "IPv4";
    case MVPP2_PRS_LU_IP6:
      return "IPv6";
    case MVPP2_PRS_LU_FLOWS:
      return "flows";
    default:
      return "unknown";
    }
}

static int
mvpp2_parser_mac_filter_get (union mv_pp2x_prs_tcam_entry *tcam, eth_addr_t addr)
{
  u8 is_broadcast = 1;
  u8 mask;
  u32 i;

  if (mvpp2_parser_tcam_lookup_get (tcam) != MVPP2_PRS_LU_MAC)
    return 0;

  for (i = 0; i < sizeof (eth_addr_t); i++)
    {
      mvpp2_parser_tcam_data_byte_get (tcam, i, addr + i, &mask);
      if (mask != 0xff)
	return 0;
      is_broadcast &= addr[i] == 0xff;
    }

  return !is_broadcast;
}

static u8
mvpp2_cls_c2_port_get (struct mv_pp2x_cls_c2_entry *c2)
{
  return (c2->tcam.words[4] >> 8) & 0xff;
}

static u8
mvpp2_cls_c2_lookup_get (struct mv_pp2x_cls_c2_entry *c2)
{
  return c2->tcam.words[4] & MVPP2_CLS_C2_HEK_LKP_TYPE_MASK;
}

static const char *
mvpp2_cls_lookup_name (u32 lookup)
{
  switch (lookup)
    {
    case MVPP2_CLS_LKP_HASH:
      return "hash";
    case MVPP2_CLS_LKP_VLAN_PRI:
      return "VLAN priority";
    case MVPP2_CLS_LKP_DSCP_PRI:
      return "DSCP";
    case MVPP2_CLS_LKP_DEFAULT:
      return "default";
    case MVPP2_CLS_LKP_ALL:
      return "all";
    default:
      return "unknown";
    }
}

static mvpp22_cls2_qos_tbl_reg_t
mvpp2_cls_qos_table_read (vnet_dev_port_t *port, u32 select, u32 line)
{
  mvpp22_cls2_dscp_pri_index_reg_t index = {
    .line = line,
    .select = select,
    .table_id = mvpp2_port_id (port),
  };
  mvpp22_cls2_qos_tbl_reg_t data;

  mvpp2_dev_reg_wr (port->dev, MVPP2_CLS2_DSCP_PRI_INDEX_REG, index.as_u32);
  data.as_u32 = mvpp2_dev_reg_rd (port->dev, MVPP2_CLS2_QOS_TBL_REG);
  return data;
}

static void
mvpp2_cls_format_qos_table (table_t *table, vnet_dev_port_t *port, const char *name, u32 select,
			    u32 n_lines, u32 *row)
{
  mvpp22_cls2_qos_tbl_reg_t data;
  mvpp22_cls2_qos_tbl_reg_t next;
  u32 first = 0;
  u32 line;

  ASSERT (n_lines > 0);

  data = mvpp2_cls_qos_table_read (port, select, 0);
  for (line = 1; line <= n_lines; line++)
    {
      if (line < n_lines)
	next = mvpp2_cls_qos_table_read (port, select, line);
      if (line < n_lines && next.as_u32 == data.as_u32)
	continue;

      table_format_cell (table, *row, 0, "%u", mvpp2_port_id (port));
      table_format_cell (table, *row, 1, "%s", name);
      if (first + 1 == line)
	table_format_cell (table, *row, 2, "%u", first);
      else
	table_format_cell (table, *row, 2, "%u-%u", first, line - 1);
      table_format_cell (table, *row, 3, "%u", data.queue);
      table_format_cell (table, *row, 4, "%u", data.color);
      (*row)++;

      if (line < n_lines)
	{
	  first = line;
	  data = next;
	}
    }
}

u8 *
format_mvpp2_parser_tables (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  int level = va_arg (*args, int);
  union mv_pp2x_prs_tcam_entry tcam;
  union mv_pp2x_prs_sram_entry sram;
  table_t parser = {};
  table_t uc = {};
  table_t mc = {};
  u32 indent = format_get_indent (s);
  u32 n_parser = 0;
  u32 n_uc = 0;
  u32 n_mc = 0;
  eth_addr_t addr;
  u32 port_map;
  u32 lookup;
  u32 tid;

  ASSERT (level > 0);

  table_add_hdr_row (&uc, 3, "Index", "Address", "Ports");
  table_add_hdr_row (&mc, 3, "Index", "Address", "Ports");
  if (level > 1)
    table_add_hdr_row (&parser, 5, "Index", "Lookup", "Ports", "TCAM", "SRAM");

  for (tid = 0; tid < MVPP2_PRS_TCAM_SRAM_SIZE; tid++)
    {
      if (mvpp2_parser_hw_entry_read (dev, tid, &tcam, &sram) != VNET_DEV_OK)
	continue;

      port_map = mvpp2_parser_tcam_port_map_get (&tcam);
      if (!port_map)
	continue;

      lookup = mvpp2_parser_tcam_lookup_get (&tcam);
      if (mvpp2_parser_mac_filter_get (&tcam, addr))
	{
	  table_t *table = addr[0] & 1 ? &mc : &uc;
	  u32 *n = addr[0] & 1 ? &n_mc : &n_uc;

	  table_format_cell (table, *n, 0, "%u", tid);
	  table_format_cell (table, *n, 1, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1],
			     addr[2], addr[3], addr[4], addr[5]);
	  table_format_cell (table, *n, 2, "0x%02x", port_map);
	  (*n)++;
	}

      if (level > 1)
	{
	  table_format_cell (&parser, n_parser, 0, "%u", tid);
	  table_format_cell (&parser, n_parser, 1, "%s (%u)", mvpp2_parser_lookup_name (lookup),
			     lookup);
	  table_format_cell (&parser, n_parser, 2, "0x%02x", port_map);
	  table_format_cell (&parser, n_parser, 3, "%08x %08x %08x %08x %08x %08x", tcam.word[0],
			     tcam.word[1], tcam.word[2], tcam.word[3], tcam.word[4], tcam.word[5]);
	  table_format_cell (&parser, n_parser, 4, "%08x %08x %08x %08x", sram.word[0],
			     sram.word[1], sram.word[2], sram.word[3]);
	  n_parser++;
	}
    }

  table_format_title (&uc, "UC filters (%u)", n_uc);
  table_format_title (&mc, "MC filters (%u)", n_mc);
  s = format (s, "%U", format_table, &uc);
  s = format (s, "\n%U%U", format_white_space, indent, format_table, &mc);
  if (level > 1)
    {
      table_format_title (&parser, "Active parser entries (%u)", n_parser);
      s = format (s, "\n%U%U", format_white_space, indent, format_table, &parser);
    }

  table_free (&parser);
  table_free (&uc);
  table_free (&mc);
  return s;
}

u8 *
format_mvpp2_classifier_tables (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  int level = va_arg (*args, int);
  struct mv_pp2x_cls_c2_entry c2 = {};
  table_t c2_table = {};
  table_t qos_table = {};
  u32 indent = format_get_indent (s);
  u32 n_c2 = 0;
  u32 n_qos = 0;
  const char *queue_source;
  u32 port_map;
  u32 lookup;
  u32 queue;
  int index;

  ASSERT (level > 0);

  table_add_hdr_row (&c2_table, 9, "Index", "Ports", "Lookup", "Key", "Queue", "Source", "Color",
		     "RSS", "HWF");
  if (mvpp2_dev_reg_rd (dev, MVPP2_CLS2_TCAM_CTRL_REG))
    for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
      {
	mvpp2_cls_c2_hw_read (dev, index, &c2);
	port_map = mvpp2_cls_c2_port_get (&c2);
	if (c2.inv || !port_map)
	  continue;

	lookup = mvpp2_cls_c2_lookup_get (&c2);
	queue = c2.sram.regs.qos_attr.low_queue |
		(c2.sram.regs.qos_attr.high_queue << MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS);
	if (c2.sram.regs.action_tbl.low_queue_from_table ==
	    c2.sram.regs.action_tbl.high_queue_from_table)
	  queue_source = c2.sram.regs.action_tbl.low_queue_from_table ? "QoS table" : "action";
	else
	  queue_source = "mixed";

	table_format_cell (&c2_table, n_c2, 0, "%u", index);
	table_format_cell (&c2_table, n_c2, 1, "0x%02x", port_map);
	table_format_cell (&c2_table, n_c2, 2, "%s (%u)", mvpp2_cls_lookup_name (lookup), lookup);
	table_format_cell (&c2_table, n_c2, 3, "%08x %08x %08x %08x", c2.tcam.words[0],
			   c2.tcam.words[1], c2.tcam.words[2], c2.tcam.words[3]);
	table_format_cell (&c2_table, n_c2, 4, "%u", queue);
	table_format_cell (&c2_table, n_c2, 5, "%s", queue_source);
	if (c2.sram.regs.action_tbl.color_from_table)
	  table_format_cell (&c2_table, n_c2, 6, "table");
	else
	  table_format_cell (&c2_table, n_c2, 6, "%u", c2.sram.regs.actions.color);
	table_format_cell (&c2_table, n_c2, 7, "%s",
			   c2.sram.regs.rss_attr.rss_enable ? "on" : "off");
	table_format_cell (&c2_table, n_c2, 8, "%08x", c2.sram.regs.hwf_attr);
	n_c2++;
      }

  table_format_title (&c2_table, "Active C2 classifier entries (%u)", n_c2);
  s = format (s, "%U", format_table, &c2_table);

  if (level > 1)
    {
      table_add_hdr_row (&qos_table, 5, "Port", "Table", "Lines", "Queue", "Color");
      foreach_vnet_dev_port (port, dev)
	{
	  mvpp2_cls_format_qos_table (&qos_table, port, "priority", MVPP2_QOS_TBL_SEL_PRI,
				      MVPP2_QOS_TBL_LINE_NUM_PRI, &n_qos);
	  mvpp2_cls_format_qos_table (&qos_table, port, "DSCP", MVPP2_QOS_TBL_SEL_DSCP,
				      MVPP2_QOS_TBL_LINE_NUM_DSCP, &n_qos);
	}
      table_format_title (&qos_table, "QoS classifier tables");
      s = format (s, "\n%U%U", format_white_space, indent, format_table, &qos_table);
    }

  table_free (&c2_table);
  table_free (&qos_table);
  return s;
}

u8 *
format_mvpp2_port_link_info (u8 *s, va_list *args)
{
  mvpp2_port_link_info_t *li = va_arg (*args, mvpp2_port_link_info_t *);
  mvpp2_port_t __clib_unused *mp = va_arg (*args, mvpp2_port_t *);

  s = format (s, "link %s", li->up ? "up" : "down");
  if (li->speed)
    s = format (s, ", %U %s-duplex", format_mvpp2_link_speed, li->speed,
		li->full_duplex ? "full" : "half");

  return s;
}

u8 *
format_mvpp2_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_bpool_hw_status_t bpool;
  mvpp2_mac_status_t mac = {};
  mvpp22_mh_reg_t mh;
  vnet_dev_rv_t filter_rv;
  vnet_dev_rv_t promisc_rv;
  vnet_dev_rv_t rss_rv;
  char ifname[IFNAMSIZ];
  u32 indent = format_get_indent (s);
  u32 n_mc;
  u32 n_uc;
  int promisc;
  int rss;

  mvpp2_port_ifname (port, ifname);
  mvpp2_mac_status_read (port, &mac);
  mh.as_u32 = mvpp2_dev_reg_rd (port->dev, MVPP2_MH_REG (mp->id));
  promisc_rv = mvpp2_parser_get_promisc (port, &promisc);
  filter_rv = mvpp2_parser_get_filter_counts (port, &n_uc, &n_mc);
  rss_rv = mvpp2_cls_rss_is_enabled (port, &rss);

  s = format (s, "netdev %s ifindex %u, GOP %u", ifname[0] ? ifname : "unknown", mp->if_index,
	      mp->gop_index);
  if (mac.valid)
    s = format (s, " %s, mode %s", mac.name, mac.mode);
  else
    s = format (s, ", MAC disabled");

  s = format_newline (s, indent);
  s = format (s, "state: %s %s", mp->is_open ? "open" : "closed",
	      mp->is_enabled ? "enabled" : "disabled");
  if (mac.valid)
    {
      s = format (s, ", link %s", mac.link.up ? "up" : "down");
      if (mac.link.speed)
	{
	  s = format (s, ", %U", format_mvpp2_link_speed, mac.link.speed);
	  if (mac.duplex_known)
	    s = format (s, " %s-duplex", mac.link.full_duplex ? "full" : "half");
	}
    }

  s = format_newline (s, indent);
  s = format (s, "config: promisc %s, rx-pause %s, loopback %s",
	      promisc_rv == VNET_DEV_OK ? promisc ? "on" : "off" : "unknown",
	      mac.valid ? mac.rx_pause ? "on" : "off" : "unknown",
	      mac.valid ? mac.loopback ? "on" : "off" : "unknown");
  if (mac.valid)
    s = format (s, ", max-rx-frame %u", mac.max_rx_frame_size);

  s = format_newline (s, indent);
  s = format (s, "parser: MH %s, DSA %s", mh.mh_enable ? "on" : "off",
	      mvpp2_dsa_mode_name (mh.dsa_mode));
  if (filter_rv == VNET_DEV_OK)
    s = format (s, ", UC filters %u/%u, MC filters %u/%u", n_uc, MVPP2_PORT_MAX_UC_ADDR, n_mc,
		MVPP2_PORT_MAX_MC_ADDR);
  else
    s = format (s, ", filters unavailable");
  s = format (s, ", RSS %s", rss_rv == VNET_DEV_OK ? rss ? "enabled" : "none" : "unknown");

  if (mvpp2_port_bpool_hw_status_read (port, &bpool))
    {
      s = format_newline (s, indent);
      s = format (s, "bpool %u: buffer-size %u buffers %u%s", bpool.id, bpool.buffer_size,
		  bpool.n_buffers, bpool.active ? "" : " stopped");
    }

  return s;
}

u8 *
format_mvpp2_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp22_bm_pool_base_addr_high_reg_t bppe_high;
  const char *version_name;
  u32 classifier;
  u32 indent = format_get_indent (s);
  u32 parser;

  if (!md->pp_base)
    return format (s, "hardware not mapped");

  parser = mvpp2_dev_reg_rd (dev, MVPP2_PRS_TCAM_CTRL_REG);
  classifier = mvpp2_dev_reg_rd (dev, MVPP2_CLS_MODE_REG);

  switch (md->version)
    {
    case MVPP2_VER_PP22:
      version_name = "PPv2.2";
      break;
    case MVPP2_VER_PP23:
      version_name = "PPv2.3";
      break;
    default:
      version_name = "unknown";
      break;
    }

  s = format (s, "packet processor %s", version_name);
  s = format_newline (s, indent);
  s = format (s, "parser TCAM %s, classifier %s",
	      parser & MVPP2_PRS_TCAM_EN_MASK ? "enabled" : "disabled",
	      classifier ? "enabled" : "disabled");

  if (a->debug)
    {
      bppe_high.as_u32 = mvpp2_dev_reg_rd (dev, MVPP22_BM_POOL_BASE_ADDR_HIGH_REG);
      s = format_newline (s, indent);
      s = format (s, "BPPE_A_HIGH 0x%08x: window 0x%02x00000000-0x%02xffffffff, 8-pool mode %s",
		  bppe_high.as_u32, bppe_high.addr, bppe_high.addr,
		  bppe_high.mode_8pool ? "enabled" : "disabled");
      s = format (s, "\n%U%U", format_white_space, indent, format_mvpp2_bpool_table, dev);
      s =
	format (s, "\n%U%U", format_white_space, indent, format_mvpp2_parser_tables, dev, a->debug);
      s = format (s, "\n%U%U", format_white_space, indent, format_mvpp2_classifier_tables, dev,
		  a->debug);
    }

  return s;
}

u8 *
format_mvpp2_rxq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *q = va_arg (*args, vnet_dev_rx_queue_t *);
  mvpp2_rxq_t *rxq = vnet_dev_get_rx_queue_data (q);
  vnet_dev_t *dev = q->port->dev;
  u32 indent = format_get_indent (s);
  mvpp22_rxq_config_reg_t config;
  mvpp22_rxq_status_reg_t status;
  u32 status_update;
  u32 desc_addr, desc_size, desc_index;

  if (!a->debug)
    return s;

  config.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_RXQ_CONFIG_REG (rxq->hw_id));
  status.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_RXQ_STATUS_REG (rxq->hw_id));
  status_update = mvpp2_dev_reg_rd (dev, MVPP2_RXQ_STATUS_UPDATE_REG (rxq->hw_id));
  mvpp2_dev_reg_wr (dev, MVPP2_RXQ_NUM_REG, rxq->hw_id);
  desc_addr = mvpp2_dev_reg_rd (dev, MVPP2_RXQ_DESC_ADDR_REG);
  desc_size = mvpp2_dev_reg_rd (dev, MVPP2_RXQ_DESC_SIZE_REG);
  desc_index = mvpp2_dev_reg_rd (dev, MVPP2_RXQ_INDEX_REG);

  s = format (s, "Hardware queue ID is %u", rxq->hw_id);
  s = format_newline (s, indent + 2);
  s = format (s,
	      "RXQ config 0x%08x: disable %u offset %u short-pool %u long-pool %u "
	      "snoop-size %u snoop-header %u",
	      config.as_u32, config.disable, config.packet_offset, config.short_pool,
	      config.long_pool, config.snoop_pkt_size, config.snoop_buf_hdr);
  s = format_newline (s, indent + 2);
  s = format (s, "RXQ status 0x%08x: occupied %u available %u", status.as_u32, status.occupied,
	      status.available);
  s = format_newline (s, indent + 2);
  s = format (s,
	      "RXQ status-update 0x%08x descriptor-address 0x%08x descriptor-size %u "
	      "index %u",
	      status_update, desc_addr, desc_size, desc_index);
  return s;
}

u8 *
format_mvpp2_txq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_tx_queue_t *q = va_arg (*args, vnet_dev_tx_queue_t *);
  mvpp2_txq_t *txq = vnet_dev_get_tx_queue_data (q);

  if (!a->debug)
    return s;
  return format (s, "Hardware queue ID is %u", txq->hw_id);
}

u8 *
format_mvpp2_rx_desc (u8 *s, va_list *args)

{
  mvpp2_rx_desc_t *d = va_arg (*args, mvpp2_rx_desc_t *);
  u32 indent = format_get_indent (s);
  u32 r32;

#define R(w)
#define _(n, w)                                                                                    \
  r32 = d->status.lo.n;                                                                            \
  if (r32 > 9)                                                                                     \
    s = format (s, "%s %u (0x%x)", #n, r32, r32);                                                  \
  else                                                                                             \
    s = format (s, "%s %u", #n, r32);                                                              \
  if (format_get_indent (s) > 72)                                                                  \
    s = format (s, "\n%U", format_white_space, indent);                                            \
  else                                                                                             \
    s = format (s, " ");

  foreach_mvpp2_rx_desc_status_lo_field;
#undef _

#define _(n, w)                                                                                    \
  r32 = d->status.hi.n;                                                                            \
  if (r32 > 9)                                                                                     \
    s = format (s, "%s %u (0x%x)", #n, r32, r32);                                                  \
  else                                                                                             \
    s = format (s, "%s %u", #n, r32);                                                              \
  if (format_get_indent (s) > 72)                                                                  \
    s = format (s, "\n%U", format_white_space, indent);                                            \
  else                                                                                             \
    s = format (s, " ");

  foreach_mvpp2_rx_desc_status_hi_field;
#undef _

#define _(n, w)                                                                                    \
  r32 = d->n;                                                                                      \
  if (r32 > 9)                                                                                     \
    s = format (s, "%s %u (0x%x)", #n, r32, r32);                                                  \
  else                                                                                             \
    s = format (s, "%s %u", #n, r32);                                                              \
  if (format_get_indent (s) > 72)                                                                  \
    s = format (s, "\n%U", format_white_space, indent);                                            \
  else                                                                                             \
    s = format (s, " ");

#define P(n, w)

  foreach_mvpp2_rx_desc_field;
#undef P

  s = format (s, "buf_phys_ptr 0x%016lx buf_virt_ptr 0x%016lx",
	      ((u64) d->buf_phys_ptr_hi << 32) | d->buf_phys_ptr_lo,
	      ((u64) d->buf_virt_ptr_hi << 32) | d->buf_virt_ptr_lo);
#undef R
#undef _
  return s;
}

u8 *
format_mvpp2_rx_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  mvpp2_rx_trace_t *t = va_arg (*args, mvpp2_rx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 indent = format_get_indent (s);
  mvpp2_rx_desc_t *d = &t->desc;

  if (t->sw_if_index != CLIB_U32_MAX)
    s = format (s, "pp2: %U (%d) next-node %U", format_vnet_sw_if_index_name,
		vnm, t->sw_if_index, t->sw_if_index,
		format_vlib_next_node_name, vm, node->index, t->next_index);
  else
    s = format (s, "pp2: next-node %U", format_vlib_next_node_name, vm,
		node->index, t->next_index);

  s = format (s, "\n%U%U", format_white_space, indent + 2,
	      format_mvpp2_rx_desc, d);

  for (u16 i = 0; i < t->n_buf_hdrs; i++)
    {
      mvpp2_rx_buf_hdr_t *h = t->buf_hdrs + i;

      s = format_newline (s, indent + 2);
      s = format (
	s, "buffer-header[%u]: next-phys 0x%010lx next-dma 0x%010lx bytes %u mc-id %u last %u", i,
	((u64) h->next_phys_addr_high << 32) | h->next_phys_addr,
	((u64) h->next_dma_addr_high << 32) | h->next_dma_addr, h->byte_count, h->info.mc_id,
	h->info.last);
    }

  return s;
}

u8 *
format_mvpp2_tx_desc (u8 *s, va_list *args)
{
  mvpp2_tx_desc_t *d = va_arg (*args, mvpp2_tx_desc_t *);
  u32 index = va_arg (*args, u32);
  u32 indent = format_get_indent (s);

  s = format (s, "desc[%u]: ", index);

#define R(w)
#define _(n, w)                                                                                    \
  s = format (s, "%s %u", #n, d->cmd.n);                                                           \
  if (format_get_indent (s) > 72)                                                                  \
    s = format_newline (s, indent + 2);                                                            \
  else                                                                                             \
    s = format (s, " ");

  foreach_mvpp2_tx_desc_cmd_field;
#undef _

#define _(n, w)                                                                                    \
  s = format (s, "%s %u", #n, d->n);                                                               \
  if (format_get_indent (s) > 72)                                                                  \
    s = format_newline (s, indent + 2);                                                            \
  else                                                                                             \
    s = format (s, " ");
#define P(n, w)

  foreach_mvpp2_tx_desc_field;
#undef P

  s = format (s, "buf_phys_ptr 0x%016lx buf_virt_ptr 0x%016lx",
	      ((u64) d->buf_phys_ptr_hi << 32) | d->buf_phys_ptr_lo,
	      ((u64) d->buf_virt_ptr_hi << 32) | d->buf_virt_ptr_lo);
#undef R
#undef _
  return s;
}

u8 *
format_mvpp2_tx_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  mvpp2_tx_trace_t *t = va_arg (*args, mvpp2_tx_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  u32 indent = format_get_indent (s);

  s = format (s, "pp2: %U (%u) queue %u buffer %u descriptors %u", format_vnet_sw_if_index_name,
	      vnm, t->sw_if_index, t->sw_if_index, t->queue_id, t->buffer_index, t->n_desc);
  for (u16 i = 0; i < t->n_desc; i++)
    {
      s = format_newline (s, indent);
      s = format (s, "%U", format_mvpp2_tx_desc, t->desc + i, i);
    }

  return s;
}
