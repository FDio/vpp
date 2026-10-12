/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <qppe.h>

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "counters",
};

typedef enum
{
  QPPE_PORT_CTR_RX_BYTES,
  QPPE_PORT_CTR_RX_PACKETS,
  QPPE_PORT_CTR_TX_BYTES,
  QPPE_PORT_CTR_TX_PACKETS,
} qppe_port_counter_id_t;

static vnet_dev_counter_t qppe_port_counters[] = {
  [QPPE_PORT_CTR_RX_BYTES] = VNET_DEV_CTR_RX_BYTES (0),
  [QPPE_PORT_CTR_RX_PACKETS] = VNET_DEV_CTR_RX_PACKETS (0),
  [QPPE_PORT_CTR_TX_BYTES] = VNET_DEV_CTR_TX_BYTES (0),
  [QPPE_PORT_CTR_TX_PACKETS] = VNET_DEV_CTR_TX_PACKETS (0),
};

static u64
qppe_xgmac_counter_read64 (qppe_device_t *qd, u32 base, u32 reg)
{
  u32 low = qppe_mmio_read32 (qd, base + reg);
  u32 high = qppe_mmio_read32 (qd, base + reg + sizeof (u32));

  return ((u64) high << 32) | low;
}

static u64
qppe_gmac_counter_read64 (qppe_device_t *qd, u32 base, u32 reg)
{
  u32 low = qppe_mmio_read32 (qd, base + reg);
  u32 high = qppe_mmio_read32 (qd, base + reg + sizeof (u32));

  return ((u64) high << 32) | low;
}

static u8
qppe_port_uses_xgmac (qppe_port_t *qp)
{
  return qp->phy_mode &&
	 (strcmp (qp->phy_mode, "2500base-x") == 0 || strcmp (qp->phy_mode, "usxgmii") == 0 ||
	  strcmp (qp->phy_mode, "10gbase-r") == 0 || strcmp (qp->phy_mode, "10g-qxgmii") == 0);
}

vnet_dev_rv_t
qppe_port_counters_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  ppe_reg_xgmac_mmc_control_t mmc = {};
  u32 base;
  u32 offset;

  if (!qppe_port_uses_xgmac (qp))
    {
      ppe_reg_gmac_mib_control_t gmac_mib = {};

      base = PPE_REG_GMAC_BASE (port->port_id);
      offset = base + PPE_GMAC_REG_MIB_CONTROL;
      gmac_mib.as_u32 = qppe_mmio_read32 (qd, offset);
      log_debug (dev, "port %u read GMAC MIB control at offset 0x%x: 0x%08x", port->port_id, offset,
		 gmac_mib.as_u32);
      if (gmac_mib.as_u32 == 0xffffffff)
	{
	  log_err (dev, "port %u GMAC MIB control read returned all ones", port->port_id);
	  return VNET_DEV_ERR_INIT_FAILED;
	}

      gmac_mib.fields.enable = 1;
      gmac_mib.fields.reset = 1;
      gmac_mib.fields.read_clear = 1;
      log_debug (dev, "port %u enabling/resetting GMAC read-clear MIB counters: 0x%08x",
		 port->port_id, gmac_mib.as_u32);
      qppe_mmio_write32 (qd, offset, gmac_mib.as_u32);
      gmac_mib.fields.reset = 0;
      qppe_mmio_write32 (qd, offset, gmac_mib.as_u32);
      log_debug (dev, "port %u GMAC MIB counters enabled in read-clear mode", port->port_id);

      vnet_dev_port_add_counters (vm, port, qppe_port_counters, ARRAY_LEN (qppe_port_counters));
      log_debug (dev, "port %u registered %u hardware GMAC MIB counters", port->port_id,
		 ARRAY_LEN (qppe_port_counters));
      return VNET_DEV_OK;
    }

  base = PPE_REG_XGMAC_BASE (port->port_id);
  offset = base + PPE_XGMAC_REG_MMC_CONTROL;

  mmc.as_u32 = qppe_mmio_read32 (qd, offset);
  log_debug (dev, "port %u read XGMAC MMC control at offset 0x%x: 0x%08x", port->port_id, offset,
	     mmc.as_u32);
  if (mmc.as_u32 == 0xffffffff)
    {
      log_err (dev, "port %u XGMAC MMC control read returned all ones", port->port_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  mmc.fields.counter_reset = 1;
  mmc.fields.counter_freeze = 0;
  log_debug (dev, "port %u resetting XGMAC MIB counters with MMC control 0x%08x", port->port_id,
	     mmc.as_u32);
  qppe_mmio_write32 (qd, offset, mmc.as_u32);

  vnet_dev_port_add_counters (vm, port, qppe_port_counters, ARRAY_LEN (qppe_port_counters));
  log_debug (dev, "port %u registered %u hardware XGMAC MIB counters", port->port_id,
	     ARRAY_LEN (qppe_port_counters));

  return VNET_DEV_OK;
}

void
qppe_port_counters_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  vnet_dev_counter_t *counter;
  u32 base;
  u64 rx_bytes;
  u64 rx_packets;
  u64 tx_bytes;
  u64 tx_packets;

  qppe_port_phy_poll (vm, port);

  if (!qppe_port_uses_xgmac (qp))
    {
      base = PPE_REG_GMAC_BASE (port->port_id);
      rx_bytes = qppe_gmac_counter_read64 (qd, base, PPE_GMAC_REG_RX_BYTES_GOOD);
      rx_packets = qppe_mmio_read32 (qd, base + PPE_GMAC_REG_RX_UNICAST) +
		   qppe_mmio_read32 (qd, base + PPE_GMAC_REG_RX_MULTICAST) +
		   qppe_mmio_read32 (qd, base + PPE_GMAC_REG_RX_BROADCAST);
      tx_bytes = qppe_gmac_counter_read64 (qd, base, PPE_GMAC_REG_TX_BYTES);
      tx_packets = qppe_mmio_read32 (qd, base + PPE_GMAC_REG_TX_UNICAST) +
		   qppe_mmio_read32 (qd, base + PPE_GMAC_REG_TX_MULTICAST) +
		   qppe_mmio_read32 (qd, base + PPE_GMAC_REG_TX_BROADCAST);

      counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_PORT_CTR_RX_BYTES);
      vnet_dev_counter_value_add (vm, counter, rx_bytes);
      counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_PORT_CTR_RX_PACKETS);
      vnet_dev_counter_value_add (vm, counter, rx_packets);
      counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_PORT_CTR_TX_BYTES);
      vnet_dev_counter_value_add (vm, counter, tx_bytes);
      counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_PORT_CTR_TX_PACKETS);
      vnet_dev_counter_value_add (vm, counter, tx_packets);

      log_debug (dev,
		 "port %u GMAC read-clear MIB sample: RX %llu packets/%llu bytes, "
		 "TX %llu packets/%llu bytes",
		 port->port_id, rx_packets, rx_bytes, tx_packets, tx_bytes);
      return;
    }

  base = PPE_REG_XGMAC_BASE (port->port_id);
  rx_bytes = qppe_xgmac_counter_read64 (qd, base, PPE_XGMAC_REG_RX_BYTES);
  rx_packets = qppe_xgmac_counter_read64 (qd, base, PPE_XGMAC_REG_RX_UNICAST) +
	       qppe_xgmac_counter_read64 (qd, base, PPE_XGMAC_REG_RX_MULTICAST) +
	       qppe_xgmac_counter_read64 (qd, base, PPE_XGMAC_REG_RX_BROADCAST);
  tx_bytes = qppe_xgmac_counter_read64 (qd, base, PPE_XGMAC_REG_TX_BYTES);
  tx_packets = qppe_xgmac_counter_read64 (qd, base, PPE_XGMAC_REG_TX_PACKETS);

  counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_PORT_CTR_RX_BYTES);
  vnet_dev_counter_value_update (vm, counter, rx_bytes);
  counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_PORT_CTR_RX_PACKETS);
  vnet_dev_counter_value_update (vm, counter, rx_packets);
  counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_PORT_CTR_TX_BYTES);
  vnet_dev_counter_value_update (vm, counter, tx_bytes);
  counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_PORT_CTR_TX_PACKETS);
  vnet_dev_counter_value_update (vm, counter, tx_packets);

  log_debug (dev,
	     "port %u XGMAC MIB sample: RX %llu packets/%llu bytes, TX %llu packets/%llu bytes",
	     port->port_id, rx_packets, rx_bytes, tx_packets, tx_bytes);
}

void
qppe_port_phy_poll (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  vnet_dev_platform_ethernet_phy_state_t state = {};
  int rv;

  if (qp->ethernet_phy_fd < 0 || !qp->phy_aneg_started)
    return;

  rv = vnet_dev_platform_ethernet_phy_get_state (qp->ethernet_phy_fd, &state);
  if (rv < 0)
    {
      log_warn (dev, "port %u cannot read Ethernet PHY state: %s", port->port_id, strerror (-rv));
      return;
    }

  if (qp->phy_state_valid && qp->phy_link_up == state.link &&
      qp->phy_speed_mbps == state.speed_mbps && qp->phy_full_duplex == state.full_duplex)
    {
      if (!qp->is_enabled || !state.link || qp->link_configured)
	return;
      qppe_port_apply_link (vm, port);
      return;
    }

  if (state.link)
    log_notice (dev, "port %u Ethernet PHY link up at %u Mbps, %s duplex, autonegotiation %s",
		port->port_id, state.speed_mbps, state.full_duplex ? "full" : "half",
		state.autoneg ? "enabled" : "disabled");
  else
    log_notice (dev, "port %u Ethernet PHY link down, autonegotiation %s", port->port_id,
		state.autoneg ? "enabled" : "disabled");

  qp->phy_state_valid = 1;
  qp->phy_link_up = state.link;
  qp->phy_speed_mbps = state.speed_mbps;
  qp->phy_full_duplex = state.full_duplex;
  qppe_port_apply_link (vm, port);
}
