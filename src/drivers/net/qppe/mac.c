/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "mac",
};

vnet_dev_rv_t
qppe_mac_set_addr (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  vnet_dev_t *dev = port->dev;
  u32 gmac_addr0 = (addr->eth_mac[5] << 8) | addr->eth_mac[4];
  u32 gmac_addr1 = ((u32) addr->eth_mac[0] << 24) | ((u32) addr->eth_mac[1] << 16) |
		   ((u32) addr->eth_mac[2] << 8) | addr->eth_mac[3];
  u32 xgmac_addr0_high = gmac_addr0 | HPPE_XGMAC_ADDR_ENABLE;
  u32 xgmac_addr0_low = ((u32) addr->eth_mac[3] << 24) | ((u32) addr->eth_mac[2] << 16) |
			((u32) addr->eth_mac[1] << 8) | addr->eth_mac[0];

  qppe_gmac_reg_wr (port, HPPE_GMAC_REG_ADDR0, gmac_addr0);
  qppe_gmac_reg_wr (port, HPPE_GMAC_REG_ADDR1, gmac_addr1);
  qppe_xgmac_reg_wr (port, HPPE_XGMAC_REG_ADDR0_HIGH, xgmac_addr0_high);
  qppe_xgmac_reg_wr (port, HPPE_XGMAC_REG_ADDR0_LOW, xgmac_addr0_low);

  if (qppe_gmac_reg_rd (port, HPPE_GMAC_REG_ADDR0) != gmac_addr0 ||
      qppe_gmac_reg_rd (port, HPPE_GMAC_REG_ADDR1) != gmac_addr1 ||
      qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_ADDR0_HIGH) != xgmac_addr0_high ||
      qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_ADDR0_LOW) != xgmac_addr0_low)
    {
      log_err (dev, "port %u MAC address readback failed at GMAC/XGMAC address registers",
	       port->port_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_mac_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  ppe_reg_xgmac_tx_config_t xgmac_tx;
  ppe_reg_xgmac_rx_config_t xgmac_rx;
  ppe_reg_gmac_enable_t gmac_enable;
  ppe_reg_gmac_speed_t gmac_speed;

  if (qp->is_xgmac)
    {
      xgmac_tx.as_u32 = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_TX_CONFIG);
      xgmac_rx.as_u32 = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_RX_CONFIG);
      if (xgmac_tx.as_u32 == 0xffffffff || xgmac_rx.as_u32 == 0xffffffff)
	{
	  log_err (dev, "MMIO read check failed: port %u XGMAC configuration returned all ones",
		   port->port_id);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }
  else
    {
      gmac_enable.as_u32 = qppe_gmac_reg_rd (port, HPPE_GMAC_REG_ENABLE);
      gmac_speed.as_u32 = qppe_gmac_reg_rd (port, HPPE_GMAC_REG_SPEED);
      if (gmac_enable.as_u32 == 0xffffffff || gmac_speed.as_u32 == 0xffffffff)
	{
	  log_err (dev, "MMIO read check failed: port %u GMAC configuration returned all ones",
		   port->port_id);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }

  if (qp->is_xgmac)
    {
      ppe_reg_xgmac_tx_config_t tx = xgmac_tx;
      ppe_reg_xgmac_rx_config_t rx = xgmac_rx;
      ppe_reg_xgmac_packet_filter_t filter;
      ppe_reg_xgmac_watchdog_timeout_t watchdog;

      tx.tx_enable = 0;
      tx.jabber_disable = 1;
      qppe_xgmac_reg_wr (port, HPPE_XGMAC_REG_TX_CONFIG, tx.as_u32);

      rx.rx_enable = 0;
      rx.giant_packet_size_limit_enable = 1;
      rx.giant_packet_size_limit = HPPE_XGMAC_MAX_FRAME_SIZE;
      rx.crc_strip = 1;
      rx.address_aligned_beats = 1;
      qppe_xgmac_reg_wr (port, HPPE_XGMAC_REG_RX_CONFIG, rx.as_u32);

      filter.as_u32 = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_PACKET_FILTER);
      filter.receive_all = 1;
      filter.promiscuous_mode = 1;
      filter.pass_control_frames = 2;
      qppe_xgmac_reg_wr (port, HPPE_XGMAC_REG_PACKET_FILTER, filter.as_u32);

      watchdog.as_u32 = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_WATCHDOG_TIMEOUT);
      watchdog.programmable_watchdog_enable = 1;
      watchdog.watchdog_timeout = 0xb;
      qppe_xgmac_reg_wr (port, HPPE_XGMAC_REG_WATCHDOG_TIMEOUT, watchdog.as_u32);

      log_debug (dev,
		 "initialized port %u XGMAC: TX 0x%08x, RX 0x%08x, packet filter 0x%08x, "
		 "watchdog 0x%08x",
		 port->port_id, tx.as_u32, rx.as_u32, filter.as_u32, watchdog.as_u32);
    }
  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_mac_link_set (vnet_dev_port_t *port, u32 enable)
{
  vnet_dev_t *dev = port->dev;
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  if (!enable)
    {
      if (qp->is_xgmac)
	{
	  ppe_reg_xgmac_tx_config_t xgmac_tx_config;
	  ppe_reg_xgmac_rx_config_t xgmac_rx_config;

	  xgmac_tx_config.as_u32 = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_TX_CONFIG);
	  xgmac_tx_config.tx_enable = 0;
	  qppe_xgmac_reg_wr (port, HPPE_XGMAC_REG_TX_CONFIG, xgmac_tx_config.as_u32);
	  xgmac_rx_config.as_u32 = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_RX_CONFIG);
	  xgmac_rx_config.rx_enable = 0;
	  qppe_xgmac_reg_wr (port, HPPE_XGMAC_REG_RX_CONFIG, xgmac_rx_config.as_u32);
	}
      else
	{
	  ppe_reg_gmac_enable_t gmac_enable;
	  gmac_enable.as_u32 = qppe_gmac_reg_rd (port, HPPE_GMAC_REG_ENABLE);
	  gmac_enable.rx_enable = 0;
	  gmac_enable.tx_enable = 0;
	  qppe_gmac_reg_wr (port, HPPE_GMAC_REG_ENABLE, gmac_enable.as_u32);
	}
      return VNET_DEV_OK;
    }

  if (qp->is_xgmac)
    {
      ppe_reg_xgmac_tx_config_t tx;
      ppe_reg_xgmac_rx_config_t rx;
      u32 speed;

      switch (qp->phy_speed_mbps)
	{
	case 10000:
	  speed = strcmp (qp->phy_mode, "usxgmii") == 0 ? HPPE_XGMAC_SPEED_10000_USXGMII :
							  HPPE_XGMAC_SPEED_10000;
	  break;
	case 5000:
	  speed = HPPE_XGMAC_SPEED_5000;
	  break;
	case 2500:
	  speed =
	    (strcmp (qp->phy_mode, "usxgmii") == 0 || strcmp (qp->phy_mode, "10g-qxgmii") == 0) ?
	      HPPE_XGMAC_SPEED_2500_USXGMII :
	      HPPE_XGMAC_SPEED_2500;
	  break;
	case 1000:
	case 100:
	case 10:
	  speed = HPPE_XGMAC_SPEED_1000;
	  break;
	default:
	  log_err (dev, "port %u has unsupported XGMAC link speed %u Mbps", port->port_id,
		   qp->phy_speed_mbps);
	  return VNET_DEV_ERR_NOT_SUPPORTED;
	}

      tx.as_u32 = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_TX_CONFIG);
      tx.speed = speed;
      tx.tx_enable = 1;
      qppe_xgmac_reg_wr (port, HPPE_XGMAC_REG_TX_CONFIG, tx.as_u32);
      rx.as_u32 = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_RX_CONFIG);
      rx.rx_enable = 1;
      qppe_xgmac_reg_wr (port, HPPE_XGMAC_REG_RX_CONFIG, rx.as_u32);
      log_debug (dev, "port %u XGMAC link enabled at %u Mbps: TX config 0x%08x, RX config 0x%08x",
		 port->port_id, qp->phy_speed_mbps, tx.as_u32, rx.as_u32);
    }
  else
    {
      ppe_reg_gmac_enable_t enable = {};
      ppe_reg_gmac_speed_t speed = {};

      speed.speed = qp->phy_speed_mbps == 1000 ? 2 : qp->phy_speed_mbps == 100 ? 1 : 0;
      qppe_gmac_reg_wr (port, HPPE_GMAC_REG_SPEED, speed.as_u32);
      enable.rx_enable = 1;
      enable.tx_enable = 1;
      enable.full_duplex = qp->phy_full_duplex;
      qppe_gmac_reg_wr (port, HPPE_GMAC_REG_ENABLE, enable.as_u32);
      log_debug (dev,
		 "port %u GMAC link enabled at %u Mbps, %s duplex: speed 0x%08x, enable "
		 "0x%08x",
		 port->port_id, qp->phy_speed_mbps, qp->phy_full_duplex ? "full" : "half",
		 speed.as_u32, enable.as_u32);
    }

  return VNET_DEV_OK;
}
