/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>

#include <pp2/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "gop",
};

static u32
mvpp2_gop_gmac_read (mvpp2_device_t *md, int mac_num, u32 offset)
{
  return mvpp2_reg_read (md->gop_hw_gmac.base, mac_num * md->gop_hw_gmac.obj_size + offset);
}

static void
mvpp2_gop_gmac_write (mvpp2_device_t *md, int mac_num, u32 offset, u32 value)
{
  mvpp2_reg_write (md->gop_hw_gmac.base, mac_num * md->gop_hw_gmac.obj_size + offset, value);
}

static u32
mvpp2_gop_xlg_read (mvpp2_device_t *md, int mac_num, u32 offset)
{
  return mvpp2_reg_read (md->gop_hw_xlg_mac.base, mac_num * md->gop_hw_xlg_mac.obj_size + offset);
}

static void
mvpp2_gop_xlg_write (mvpp2_device_t *md, int mac_num, u32 offset, u32 value)
{
  mvpp2_reg_write (md->gop_hw_xlg_mac.base, mac_num * md->gop_hw_xlg_mac.obj_size + offset, value);
}

static void
mvpp2_gop_gmac_max_rx_size_set (vnet_dev_port_t *port, int max_rx_size)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int mac_num = mp->gop_index;
  u32 reg_val;

  reg_val = mvpp2_gop_gmac_read (md, mac_num, PP2_GMAC_PORT_CTRL0_REG);
  reg_val &= ~PP2_GMAC_PORT_CTRL0_FRAMESIZELIMIT_MASK;
  reg_val |= (((max_rx_size - MV_MH_SIZE) / 2) << PP2_GMAC_PORT_CTRL0_FRAMESIZELIMIT_OFFS);
  mvpp2_gop_gmac_write (md, mac_num, PP2_GMAC_PORT_CTRL0_REG, reg_val);
}

static void
mvpp2_gop_xlg_max_rx_size_set (vnet_dev_port_t *port, int max_rx_size)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int mac_num = mp->gop_index;
  u32 reg_val;

  reg_val = mvpp2_gop_xlg_read (md, mac_num, PP2_XLG_PORT_MAC_CTRL1_REG);
  reg_val &= ~PP2_XLG_MAC_CTRL1_FRAMESIZELIMIT_MASK;
  reg_val |= (((max_rx_size - MV_MH_SIZE) / 2) << PP2_XLG_MAC_CTRL1_FRAMESIZELIMIT_OFFS);
  mvpp2_gop_xlg_write (md, mac_num, PP2_XLG_PORT_MAC_CTRL1_REG, reg_val);
}

void
mvpp2_gop_max_rx_size_set (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int mac_num = mp->gop_index;
  u32 max_rx_size;
  u32 pp2_version;

  /* GOP#0 and GOP#2 (In PP23/CP115) can support both XLG and GMAC;
   * We cannot know that on the fly so always configure both of them;
   * All the rest support only GMAC
   */
  pp2_version = mvpp2_reg_read (mp->hif_base, MVPP2_VER_ID_REG);
  max_rx_size = port->max_rx_frame_size + MV_MH_SIZE + MV_VLAN_TAG_LEN + MV_ETH_FCS_LEN;
  mvpp2_gop_gmac_max_rx_size_set (port, max_rx_size);
  if (mac_num == 0 || (mac_num == 2 && pp2_version == MVPP2_VER_PP23))
    mvpp2_gop_xlg_max_rx_size_set (port, max_rx_size);
}

vnet_dev_rv_t
mvpp2_gop_get_link_info (vnet_dev_port_t *port, struct mvpp2_port_link_info *link_info)
{
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int port_num = mp->gop_index;
  u32 reg_val;
  u32 mac_mode;

  *link_info = (struct mvpp2_port_link_info) {};

  if (!mp->is_xlg)
    {
      reg_val = mvpp2_gop_gmac_read (md, port_num, PP2_GMAC_PORT_STATUS0_REG);
      if (reg_val & PP2_GMAC_PORT_STATUS0_GMIISPEED_MASK)
	link_info->speed = 1000000;
      else if (reg_val & PP2_GMAC_PORT_STATUS0_MIISPEED_MASK)
	link_info->speed = 100000;
      else
	link_info->speed = 10000;
      link_info->up = !!(reg_val & PP2_GMAC_PORT_STATUS0_LINKUP_MASK);
      link_info->full_duplex = !!(reg_val & PP2_GMAC_PORT_STATUS0_FULLDX_MASK);
    }
  else
    {
      reg_val = mvpp2_gop_xlg_read (md, port_num, PP2_XLG_PORT_MAC_CTRL3_REG);
      mac_mode =
	(reg_val & PP2_XLG_MAC_CTRL3_MACMODESELECT_MASK) >> PP2_XLG_MAC_CTRL3_MACMODESELECT_OFFS;
      if (mac_mode == 0)
	{
	  link_info->speed = 1000000;
	}
      else if (mac_mode == 1)
	{
	  link_info->speed = 10000000;
	  link_info->full_duplex = 1;
	}
      else
	return VNET_DEV_OK;
      reg_val = mvpp2_gop_xlg_read (md, port_num, PP2_XLG_MAC_PORT_STATUS_REG);
      link_info->up = !!(reg_val & PP2_XLG_MAC_PORT_STATUS_LINKSTATUS_MASK);
    }

  return VNET_DEV_OK;
}
