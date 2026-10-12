/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <qppe.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "port",
};

vnet_dev_rv_t
qppe_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  log_debug (port->dev, "port %u label %s phy-mode %s managed %s", port->port_id,
	     qp->label ? qp->label : "(none)", qp->phy_mode ? qp->phy_mode : "(unspecified)",
	     qp->managed ? qp->managed : "(unspecified)");
  if (qp->is_xgmac)
    {
      ppe_reg_port_mux_control_t mux = {};
      ppe_reg_xgmac_tx_config_t tx = {};
      ppe_reg_xgmac_rx_config_t rx = {};
      ppe_reg_xgmac_packet_filter_t filter = {};
      ppe_reg_xgmac_watchdog_timeout_t watchdog = {};
      u32 port_select_bit = 1 << (port->port_id - 1);
      u32 base = PPE_REG_XGMAC_BASE (port->port_id);
      u32 offset;

      mux.as_u32 = qppe_mmio_read32 (qd, PPE_REG_PORT_MUX_CONTROL);
      if (!(mux.fields.xgmac_select & port_select_bit))
	{
	  mux.fields.xgmac_select |= port_select_bit;
	  log_debug (dev, "selecting XGMAC mode for port %u in port mux control: 0x%08x",
		     port->port_id, mux.as_u32);
	  qppe_mmio_write32 (qd, PPE_REG_PORT_MUX_CONTROL, mux.as_u32);
	  mux.as_u32 = qppe_mmio_read32 (qd, PPE_REG_PORT_MUX_CONTROL);
	  if (!(mux.fields.xgmac_select & port_select_bit))
	    {
	      log_err (dev, "port %u XGMAC selection did not take effect in port mux control",
		       port->port_id);
	      return VNET_DEV_ERR_INIT_FAILED;
	    }
	  qd->hw_state.port_mux_control = mux;
	}

      offset = base + PPE_XGMAC_REG_TX_CONFIG;
      tx.as_u32 = qppe_mmio_read32 (qd, offset);
      tx.fields.tx_enable = 0;
      tx.fields.jabber_disable = 1;
      qppe_mmio_write32 (qd, offset, tx.as_u32);

      offset = base + PPE_XGMAC_REG_RX_CONFIG;
      rx.as_u32 = qppe_mmio_read32 (qd, offset);
      rx.fields.rx_enable = 0;
      rx.fields.giant_packet_size_limit_enable = 1;
      rx.fields.giant_packet_size_limit = PPE_XGMAC_MAX_FRAME_SIZE;
      rx.fields.crc_strip = 1;
      rx.fields.address_aligned_beats = 1;
      qppe_mmio_write32 (qd, offset, rx.as_u32);

      offset = base + PPE_XGMAC_REG_PACKET_FILTER;
      filter.as_u32 = qppe_mmio_read32 (qd, offset);
      filter.fields.receive_all = 1;
      filter.fields.promiscuous_mode = 1;
      filter.fields.pass_control_frames = 2;
      qppe_mmio_write32 (qd, offset, filter.as_u32);

      offset = base + PPE_XGMAC_REG_WATCHDOG_TIMEOUT;
      watchdog.as_u32 = qppe_mmio_read32 (qd, offset);
      watchdog.fields.programmable_watchdog_enable = 1;
      watchdog.fields.watchdog_timeout = 0xb;
      qppe_mmio_write32 (qd, offset, watchdog.as_u32);

      qp->hw_state.xgmac_tx_config = tx;
      qp->hw_state.xgmac_rx_config = rx;
      log_debug (dev,
		 "initialized port %u XGMAC: TX 0x%08x, RX 0x%08x, packet filter 0x%08x, "
		 "watchdog 0x%08x",
		 port->port_id, tx.as_u32, rx.as_u32, filter.as_u32, watchdog.as_u32);
    }
  rv = qppe_port_counters_init (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  vnet_dev_poll_port_add (vm, port, 3, qppe_port_counters_poll);
  log_debug (port->dev, "port %u hardware counters initialized; polling every 3 seconds",
	     port->port_id);

  return rv;
}

void
qppe_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  vnet_dev_poll_port_remove (vm, port, qppe_port_counters_poll);
  log_debug (port->dev, "port %u label %s", port->port_id, qp->label ? qp->label : "(none)");
}

vnet_dev_rv_t
qppe_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  vnet_dev_rx_queue_t *rxq = 0;
  vnet_dev_rv_t rv;
  int phy_rv;

  log_debug (port->dev, "starting port %u label %s", port->port_id,
	     qp->label ? qp->label : "(none)");

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      {
	rxq = q;
	break;
      }

  if (rxq == 0)
    {
      log_warn (dev, "port %u cannot start: no enabled RX queue", port->port_id);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  if (qp->ethernet_phy_fd >= 0 && !qp->phy_aneg_started)
    {
      phy_rv = vnet_dev_platform_ethernet_phy_start_aneg (qp->ethernet_phy_fd);
      if (phy_rv < 0)
	{
	  log_err (dev, "port %u cannot start Ethernet PHY autonegotiation: %s", port->port_id,
		   strerror (-phy_rv));
	  return VNET_DEV_ERR_INIT_FAILED;
	}
      qp->phy_aneg_started = 1;
      log_debug (dev, "port %u started Ethernet PHY autonegotiation", port->port_id);
    }

  rv = qppe_edma_rx_ring_start (vm, qd->rxq_owner ? qd->rxq_owner : rxq);
  if (rv != VNET_DEV_OK)
    {
      if (qp->phy_aneg_started)
	{
	  phy_rv = vnet_dev_platform_ethernet_phy_stop (qp->ethernet_phy_fd);
	  if (phy_rv < 0)
	    log_warn (dev, "port %u cannot stop Ethernet PHY after RX ring start failed: %s",
		      port->port_id, strerror (-phy_rv));
	  else
	    {
	      qp->phy_aneg_started = 0;
	      qp->phy_state_valid = 0;
	      qp->phy_link_up = 0;
	      qp->phy_speed_mbps = 0;
	      qp->phy_full_duplex = 0;
	    }
	}
      return rv;
    }

  qd->active_rx_ports |= 1 << port->port_id;
  qp->is_enabled = 1;
  qppe_port_apply_link (vm, port);

  return VNET_DEV_OK;
}

void
qppe_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  qppe_rxq_t *qr;
  int rv;

  log_debug (port->dev, "stopping port %u label %s", port->port_id,
	     qp->label ? qp->label : "(none)");

  qp->is_enabled = 0;
  qppe_port_apply_link (vm, port);
  qd->active_rx_ports &= ~(1 << port->port_id);
  if (qp->phy_aneg_started)
    {
      rv = vnet_dev_platform_ethernet_phy_stop (qp->ethernet_phy_fd);

      if (rv < 0)
	log_warn (dev, "port %u cannot stop Ethernet PHY: %s", port->port_id, strerror (-rv));
      else
	{
	  qp->phy_aneg_started = 0;
	  qp->phy_state_valid = 0;
	  qp->phy_link_up = 0;
	  qp->phy_speed_mbps = 0;
	  qp->phy_full_duplex = 0;
	}
    }

  if (qd->active_rx_ports == 0 && qd->rxq_owner)
    {
      qr = vnet_dev_get_rx_queue_data (qd->rxq_owner);
      if (qr->started)
	qppe_edma_rx_ring_stop (qd->rxq_owner);
    }
}

static u32
qppe_port_clock_rate (qppe_port_t *qp)
{
  if (strcmp (qp->phy_mode, "2500base-x") == 0)
    {
      if (qp->phy_speed_mbps == 2500)
	return 312500000;
      if (qp->phy_speed_mbps == 1000)
	return 125000000;
      if (qp->phy_speed_mbps == 100)
	return 25000000;
      if (qp->phy_speed_mbps == 10)
	return 2500000;
      return 0;
    }

  if (qp->phy_speed_mbps == 10000)
    return 312500000;
  if (qp->phy_speed_mbps == 5000)
    return 156250000;
  if (qp->phy_speed_mbps == 2500)
    return 78125000;
  if (qp->phy_speed_mbps == 1000)
    return 125000000;
  if (qp->phy_speed_mbps == 100)
    return 12500000;
  if (qp->phy_speed_mbps == 10)
    return 1250000;
  return 0;
}

void
qppe_port_apply_link (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  u32 offset;

  qp->link_configured = 0;
  if (!qp->is_enabled || !qp->phy_link_up)
    {
      if (qp->is_xgmac)
	{
	  offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_TX_CONFIG;
	  qp->hw_state.xgmac_tx_config.as_u32 = qppe_mmio_read32 (qd, offset);
	  qp->hw_state.xgmac_tx_config.fields.tx_enable = 0;
	  qppe_mmio_write32 (qd, offset, qp->hw_state.xgmac_tx_config.as_u32);
	  offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_RX_CONFIG;
	  qp->hw_state.xgmac_rx_config.as_u32 = qppe_mmio_read32 (qd, offset);
	  qp->hw_state.xgmac_rx_config.fields.rx_enable = 0;
	  qppe_mmio_write32 (qd, offset, qp->hw_state.xgmac_rx_config.as_u32);
	}
      else
	{
	  offset = PPE_REG_GMAC_ENABLE (port->port_id);
	  qp->hw_state.gmac_enable.as_u32 = qppe_mmio_read32 (qd, offset);
	  qp->hw_state.gmac_enable.fields.rx_enable = 0;
	  qp->hw_state.gmac_enable.fields.tx_enable = 0;
	  qppe_mmio_write32 (qd, offset, qp->hw_state.gmac_enable.as_u32);
	}
      log_debug (dev, "port %u MAC disabled: admin %s, link %s", port->port_id,
		 qp->is_enabled ? "up" : "down", qp->phy_link_up ? "up" : "down");
      return;
    }

  if (qp->rx_clock_fd < 0 || qp->tx_clock_fd < 0 || qppe_port_clock_rate (qp) == 0)
    {
      log_err (dev, "port %u link up at %u Mbps but port clock resources or rate are invalid",
	       port->port_id, qp->phy_speed_mbps);
      return;
    }

  {
    u32 rate = qppe_port_clock_rate (qp);
    int rv;

    rv = vnet_dev_platform_clock_set_rate (qp->rx_clock_fd, rate);
    if (rv < 0)
      {
	log_err (dev, "port %u cannot set RX clock to %u Hz: %s", port->port_id, rate,
		 strerror (-rv));
	return;
      }
    rv = vnet_dev_platform_clock_set_rate (qp->tx_clock_fd, rate);
    if (rv < 0)
      {
	log_err (dev, "port %u cannot set TX clock to %u Hz: %s", port->port_id, rate,
		 strerror (-rv));
	return;
      }
  }

  if (qp->is_xgmac)
    {
      ppe_reg_xgmac_tx_config_t tx = {};
      ppe_reg_xgmac_rx_config_t rx = {};
      u32 speed;

      switch (qp->phy_speed_mbps)
	{
	case 10000:
	  speed = strcmp (qp->phy_mode, "usxgmii") == 0 ? PPE_XGMAC_SPEED_10000_USXGMII :
							  PPE_XGMAC_SPEED_10000;
	  break;
	case 5000:
	  speed = PPE_XGMAC_SPEED_5000;
	  break;
	case 2500:
	  speed =
	    (strcmp (qp->phy_mode, "usxgmii") == 0 || strcmp (qp->phy_mode, "10g-qxgmii") == 0) ?
	      PPE_XGMAC_SPEED_2500_USXGMII :
	      PPE_XGMAC_SPEED_2500;
	  break;
	case 1000:
	case 100:
	case 10:
	  speed = PPE_XGMAC_SPEED_1000;
	  break;
	default:
	  log_err (dev, "port %u has unsupported XGMAC link speed %u Mbps", port->port_id,
		   qp->phy_speed_mbps);
	  return;
	}

      offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_TX_CONFIG;
      tx.as_u32 = qppe_mmio_read32 (qd, offset);
      tx.fields.speed = speed;
      tx.fields.tx_enable = 1;
      qppe_mmio_write32 (qd, offset, tx.as_u32);
      qp->hw_state.xgmac_tx_config = tx;
      offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_RX_CONFIG;
      rx.as_u32 = qppe_mmio_read32 (qd, offset);
      rx.fields.rx_enable = 1;
      qppe_mmio_write32 (qd, offset, rx.as_u32);
      qp->hw_state.xgmac_rx_config = rx;
      log_debug (dev, "port %u XGMAC link enabled at %u Mbps: TX config 0x%08x, RX config 0x%08x",
		 port->port_id, qp->phy_speed_mbps, tx.as_u32, rx.as_u32);
    }
  else
    {
      ppe_reg_gmac_enable_t enable = {};
      ppe_reg_gmac_speed_t speed = {};

      speed.fields.speed = qp->phy_speed_mbps == 1000 ? 2 : qp->phy_speed_mbps == 100 ? 1 : 0;
      offset = PPE_REG_GMAC_BASE (port->port_id) + PPE_GMAC_REG_SPEED;
      qppe_mmio_write32 (qd, offset, speed.as_u32);
      offset = PPE_REG_GMAC_ENABLE (port->port_id);
      enable.fields.rx_enable = 1;
      enable.fields.tx_enable = 1;
      enable.fields.full_duplex = qp->phy_full_duplex;
      qppe_mmio_write32 (qd, offset, enable.as_u32);
      qp->hw_state.gmac_speed = speed;
      qp->hw_state.gmac_enable = enable;
      log_debug (dev,
		 "port %u GMAC link enabled at %u Mbps, %s duplex: speed 0x%08x, enable "
		 "0x%08x",
		 port->port_id, qp->phy_speed_mbps, qp->phy_full_duplex ? "full" : "half",
		 speed.as_u32, enable.as_u32);
    }

  qp->link_configured = 1;
}
