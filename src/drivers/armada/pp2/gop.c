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

static void
mvpp2_gop_gmac_max_rx_size_set (vnet_dev_port_t *port, int max_rx_size)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_gmac_port_ctrl0_reg_t control;
  int mac_num = mp->gop_index;

  control.as_u32 = mvpp2_gop_gmac_reg_rd (port->dev, mac_num, PP2_GMAC_PORT_CTRL0_REG);
  control.frame_size_limit = round_pow2 (max_rx_size - MV_MH_SIZE, 2) / 2;
  mvpp2_gop_gmac_reg_wr (port->dev, mac_num, PP2_GMAC_PORT_CTRL0_REG, control.as_u32);
  log_debug (port->dev, "GMAC %u max rx size %u, control %08x", mac_num, max_rx_size,
	     control.as_u32);
}

static void
mvpp2_gop_xlg_max_rx_size_set (vnet_dev_port_t *port, int max_rx_size)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp22_xlg_mac_ctrl1_reg_t control;
  int mac_num = mp->gop_index;

  control.as_u32 = mvpp2_gop_xlg_reg_rd (port->dev, mac_num, PP2_XLG_PORT_MAC_CTRL1_REG);
  control.frame_size_limit = round_pow2 (max_rx_size - MV_MH_SIZE, 2) / 2;
  mvpp2_gop_xlg_reg_wr (port->dev, mac_num, PP2_XLG_PORT_MAC_CTRL1_REG, control.as_u32);
  log_debug (port->dev, "XLG MAC %u max rx size %u, control %08x", mac_num, max_rx_size,
	     control.as_u32);
}

void
mvpp2_gop_max_rx_size_set (vnet_dev_port_t *port, u16 frame_size)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u32 max_rx_size;

  /* GOP#0 and GOP#2 (in PP23/CP115) can support both XLG and GMAC.
   * Configure both MAC blocks when the port has XLG capability.
   */
  max_rx_size = frame_size + MV_MH_SIZE + MV_ETH_FCS_LEN;
  mvpp2_gop_gmac_max_rx_size_set (port, max_rx_size);
  if (mp->has_xlg)
    mvpp2_gop_xlg_max_rx_size_set (port, max_rx_size);
}

void
mvpp2_gop_get_link_info (vnet_dev_port_t *port, mvpp2_port_link_info_t *link_info)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int port_num = mp->gop_index;
  u32 reg_val;
  u32 mac_mode;

  *link_info = (mvpp2_port_link_info_t) {};

  if (!mp->is_xlg)
    {
      mvpp22_gmac_port_status0_reg_t status = {
	.as_u32 = mvpp2_gop_gmac_reg_rd (port->dev, port_num, PP2_GMAC_PORT_STATUS0_REG),
      };

      if (status.gmii_speed)
	link_info->speed = 1000000;
      else if (status.mii_speed)
	link_info->speed = 100000;
      else
	link_info->speed = 10000;
      link_info->up = status.link_up;
      link_info->full_duplex = status.full_duplex;
    }
  else
    {
      reg_val = mvpp2_gop_xlg_reg_rd (port->dev, port_num, PP2_XLG_PORT_MAC_CTRL3_REG);
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
	return;
      reg_val = mvpp2_gop_xlg_reg_rd (port->dev, port_num, PP2_XLG_MAC_PORT_STATUS_REG);
      link_info->up = !!(reg_val & PP2_XLG_MAC_PORT_STATUS_LINKSTATUS_MASK);
    }
}
