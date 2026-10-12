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

#define QPPE_COUNTER_ID_VENDOR(id) id,
#define QPPE_COUNTER_ID_GENERIC(id)
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_ID_##type (QPPE_XGMAC_CTR_RX_##name)
typedef enum
{
  QPPE_XGMAC_CTR_RX_BYTES,
  QPPE_XGMAC_CTR_RX_PACKETS,
  QPPE_XGMAC_CTR_TX_BYTES,
  QPPE_XGMAC_CTR_TX_PACKETS,
  foreach_ppe_xgmac_rx_counter
#undef _
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_ID_##type (QPPE_XGMAC_CTR_TX_##name)
    foreach_ppe_xgmac_tx_counter
} qppe_xgmac_counter_id_t;
#undef _
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_ID_##type (QPPE_GMAC_CTR_RX_##name)
typedef enum
{
  QPPE_GMAC_CTR_RX_BYTES,
  QPPE_GMAC_CTR_RX_PACKETS,
  QPPE_GMAC_CTR_TX_BYTES,
  QPPE_GMAC_CTR_TX_PACKETS,
  foreach_ppe_gmac_rx_counter
#undef _
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_ID_##type (QPPE_GMAC_CTR_TX_##name)
    foreach_ppe_gmac_tx_counter
} qppe_gmac_counter_id_t;
#undef _
#undef QPPE_COUNTER_ID_VENDOR
#undef QPPE_COUNTER_ID_GENERIC

#define QPPE_COUNTER_DESC_VENDOR(index, direction, unit, description)                              \
  VNET_DEV_CTR_VENDOR (index, direction, unit, description),
#define QPPE_COUNTER_DESC_GENERIC(index, direction, unit, description)
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_DESC_##type (QPPE_XGMAC_CTR_RX_##name, RX, unit, description)
static vnet_dev_counter_t qppe_xgmac_port_counters[] = {
  [QPPE_XGMAC_CTR_RX_BYTES] = VNET_DEV_CTR_RX_BYTES (QPPE_XGMAC_CTR_RX_BYTES),
  [QPPE_XGMAC_CTR_RX_PACKETS] = VNET_DEV_CTR_RX_PACKETS (QPPE_XGMAC_CTR_RX_PACKETS),
  [QPPE_XGMAC_CTR_TX_BYTES] = VNET_DEV_CTR_TX_BYTES (QPPE_XGMAC_CTR_TX_BYTES),
  [QPPE_XGMAC_CTR_TX_PACKETS] = VNET_DEV_CTR_TX_PACKETS (QPPE_XGMAC_CTR_TX_PACKETS),
  foreach_ppe_xgmac_rx_counter
#undef _
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_DESC_##type (QPPE_XGMAC_CTR_TX_##name, TX, unit, description)
    foreach_ppe_xgmac_tx_counter
};
#undef _
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_DESC_##type (QPPE_GMAC_CTR_RX_##name, RX, unit, description)
static vnet_dev_counter_t qppe_gmac_port_counters[] = {
  [QPPE_GMAC_CTR_RX_BYTES] = VNET_DEV_CTR_RX_BYTES (QPPE_GMAC_CTR_RX_BYTES),
  [QPPE_GMAC_CTR_RX_PACKETS] = VNET_DEV_CTR_RX_PACKETS (QPPE_GMAC_CTR_RX_PACKETS),
  [QPPE_GMAC_CTR_TX_BYTES] = VNET_DEV_CTR_TX_BYTES (QPPE_GMAC_CTR_TX_BYTES),
  [QPPE_GMAC_CTR_TX_PACKETS] = VNET_DEV_CTR_TX_PACKETS (QPPE_GMAC_CTR_TX_PACKETS),
  foreach_ppe_gmac_rx_counter
#undef _
#define _(offset, name, description, width, type, unit)                                            \
  QPPE_COUNTER_DESC_##type (QPPE_GMAC_CTR_TX_##name, TX, unit, description)
    foreach_ppe_gmac_tx_counter
};
#undef _
#undef QPPE_COUNTER_DESC_VENDOR
#undef QPPE_COUNTER_DESC_GENERIC

typedef enum
{
  QPPE_MIB_COUNTER_TYPE_GENERIC,
  QPPE_MIB_COUNTER_TYPE_VENDOR,
} qppe_mib_counter_type_t;

typedef struct
{
  const char *name;
  u32 reg;
  u16 counter_index;
  u8 width;
  qppe_mib_counter_type_t type;
  vnet_dev_counter_direction_t direction;
  vnet_dev_counter_unit_t unit;
} qppe_mib_counter_t;

#define QPPE_COUNTER_INDEX_VENDOR(mac, direction, name, unit)  QPPE_##mac##_CTR_##direction##_##name
#define QPPE_COUNTER_INDEX_GENERIC(mac, direction, name, unit) QPPE_##mac##_CTR_##direction##_##unit
#define QPPE_COUNTER_TYPE_VENDOR			       QPPE_MIB_COUNTER_TYPE_VENDOR
#define QPPE_COUNTER_TYPE_GENERIC			       QPPE_MIB_COUNTER_TYPE_GENERIC
#define _(reg_offset, counter_name, counter_description, counter_width, counter_type,              \
	  counter_unit)                                                                            \
  {                                                                                                \
    .name = counter_description,                                                                   \
    .reg = reg_offset,                                                                             \
    .counter_index = QPPE_COUNTER_INDEX_##counter_type (XGMAC, RX, counter_name, counter_unit),    \
    .width = counter_width,                                                                        \
    .type = QPPE_COUNTER_TYPE_##counter_type,                                                      \
    .direction = VNET_DEV_CTR_DIR_RX,                                                              \
    .unit = VNET_DEV_CTR_UNIT_##counter_unit,                                                      \
  },
static const qppe_mib_counter_t qppe_xgmac_mib_counters[] = { foreach_ppe_xgmac_rx_counter
#undef _
#define _(reg_offset, counter_name, counter_description, counter_width, counter_type,              \
	  counter_unit)                                                                            \
  {                                                                                                \
    .name = counter_description,                                                                   \
    .reg = reg_offset,                                                                             \
    .counter_index = QPPE_COUNTER_INDEX_##counter_type (XGMAC, TX, counter_name, counter_unit),    \
    .width = counter_width,                                                                        \
    .type = QPPE_COUNTER_TYPE_##counter_type,                                                      \
    .direction = VNET_DEV_CTR_DIR_TX,                                                              \
    .unit = VNET_DEV_CTR_UNIT_##counter_unit,                                                      \
  },
								foreach_ppe_xgmac_tx_counter };
#undef _
#define _(reg_offset, counter_name, counter_description, counter_width, counter_type,              \
	  counter_unit)                                                                            \
  {                                                                                                \
    .name = counter_description,                                                                   \
    .reg = reg_offset,                                                                             \
    .counter_index = QPPE_COUNTER_INDEX_##counter_type (GMAC, RX, counter_name, counter_unit),     \
    .width = counter_width,                                                                        \
    .type = QPPE_COUNTER_TYPE_##counter_type,                                                      \
    .direction = VNET_DEV_CTR_DIR_RX,                                                              \
    .unit = VNET_DEV_CTR_UNIT_##counter_unit,                                                      \
  },
static const qppe_mib_counter_t qppe_gmac_mib_counters[] = { foreach_ppe_gmac_rx_counter
#undef _
#define _(reg_offset, counter_name, counter_description, counter_width, counter_type,              \
	  counter_unit)                                                                            \
  {                                                                                                \
    .name = counter_description,                                                                   \
    .reg = reg_offset,                                                                             \
    .counter_index = QPPE_COUNTER_INDEX_##counter_type (GMAC, TX, counter_name, counter_unit),     \
    .width = counter_width,                                                                        \
    .type = QPPE_COUNTER_TYPE_##counter_type,                                                      \
    .direction = VNET_DEV_CTR_DIR_TX,                                                              \
    .unit = VNET_DEV_CTR_UNIT_##counter_unit,                                                      \
  },
							       foreach_ppe_gmac_tx_counter };
#undef _
#undef QPPE_COUNTER_INDEX_VENDOR
#undef QPPE_COUNTER_INDEX_GENERIC
#undef QPPE_COUNTER_TYPE_VENDOR
#undef QPPE_COUNTER_TYPE_GENERIC

static u64
qppe_mib_counter_read64 (qppe_device_t *qd, u32 base, u32 reg)
{
  u32 low = qppe_mmio_read32 (qd, base + reg);
  u32 high = qppe_mmio_read32 (qd, base + reg + sizeof (u32));

  return ((u64) high << 32) | low;
}

static u64
qppe_mib_counter_read (qppe_device_t *qd, u32 base, u32 reg, u8 width)
{
  if (width == sizeof (u64))
    return qppe_mib_counter_read64 (qd, base, reg);

  return qppe_mmio_read32 (qd, base + reg);
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

      gmac_mib.enable = 1;
      gmac_mib.reset = 1;
      gmac_mib.read_clear = 1;
      log_debug (dev, "port %u enabling/resetting GMAC read-clear MIB counters: 0x%08x",
		 port->port_id, gmac_mib.as_u32);
      qppe_mmio_write32 (qd, offset, gmac_mib.as_u32);
      gmac_mib.reset = 0;
      qppe_mmio_write32 (qd, offset, gmac_mib.as_u32);
      log_debug (dev, "port %u GMAC MIB counters enabled in read-clear mode", port->port_id);

      vnet_dev_port_add_counters (vm, port, qppe_gmac_port_counters,
				  ARRAY_LEN (qppe_gmac_port_counters));
      log_debug (dev, "port %u registered %u hardware GMAC MIB counters", port->port_id,
		 ARRAY_LEN (qppe_gmac_port_counters));
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

  mmc.counter_reset = 1;
  mmc.counter_freeze = 0;
  log_debug (dev, "port %u resetting XGMAC MIB counters with MMC control 0x%08x", port->port_id,
	     mmc.as_u32);
  qppe_mmio_write32 (qd, offset, mmc.as_u32);

  vnet_dev_port_add_counters (vm, port, qppe_xgmac_port_counters,
			      ARRAY_LEN (qppe_xgmac_port_counters));
  log_debug (dev, "port %u registered %u hardware XGMAC MIB counters", port->port_id,
	     ARRAY_LEN (qppe_xgmac_port_counters));

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

  qppe_port_phy_poll (vm, port);

  if (!qppe_port_uses_xgmac (qp))
    {
      u64 rx_bytes = 0;
      u64 rx_packets = 0;
      u64 tx_bytes = 0;
      u64 tx_packets = 0;

      base = PPE_REG_GMAC_BASE (port->port_id);
      FOREACH_ARRAY_ELT (mib_counter, qppe_gmac_mib_counters)
	{
	  u64 value = qppe_mib_counter_read (qd, base, mib_counter->reg, mib_counter->width);

	  counter = vnet_dev_port_get_counter_by_index (vm, port, mib_counter->counter_index);
	  vnet_dev_counter_value_add (vm, counter, value);

	  if (mib_counter->type == QPPE_MIB_COUNTER_TYPE_GENERIC)
	    {
	      if (mib_counter->direction == VNET_DEV_CTR_DIR_RX)
		rx_bytes = value;
	      else
		tx_bytes = value;
	    }
	  else if (mib_counter->direction == VNET_DEV_CTR_DIR_RX &&
		   (mib_counter->counter_index == QPPE_GMAC_CTR_RX_UNICAST ||
		    mib_counter->counter_index == QPPE_GMAC_CTR_RX_MULTICAST ||
		    mib_counter->counter_index == QPPE_GMAC_CTR_RX_BROADCAST))
	    rx_packets += value;
	  else if (mib_counter->direction == VNET_DEV_CTR_DIR_TX &&
		   (mib_counter->counter_index == QPPE_GMAC_CTR_TX_UNICAST ||
		    mib_counter->counter_index == QPPE_GMAC_CTR_TX_MULTICAST ||
		    mib_counter->counter_index == QPPE_GMAC_CTR_TX_BROADCAST))
	    tx_packets += value;
	}

      counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_RX_PACKETS);
      vnet_dev_counter_value_add (vm, counter, rx_packets);
      counter = vnet_dev_port_get_counter_by_index (vm, port, QPPE_GMAC_CTR_TX_PACKETS);
      vnet_dev_counter_value_add (vm, counter, tx_packets);

      if (0)
	log_debug (dev,
		   "port %u GMAC read-clear MIB sample: RX %llu packets/%llu bytes, "
		   "TX %llu packets/%llu bytes",
		   port->port_id, rx_packets, rx_bytes, tx_packets, tx_bytes);
      return;
    }

  base = PPE_REG_XGMAC_BASE (port->port_id);
  {
    u64 rx_bytes = 0;
    u64 rx_packets = 0;
    u64 tx_bytes = 0;
    u64 tx_packets = 0;

    FOREACH_ARRAY_ELT (mib_counter, qppe_xgmac_mib_counters)
      {
	u64 value = qppe_mib_counter_read (qd, base, mib_counter->reg, mib_counter->width);

	counter = vnet_dev_port_get_counter_by_index (vm, port, mib_counter->counter_index);
	vnet_dev_counter_value_update (vm, counter, value);

	if (mib_counter->type == QPPE_MIB_COUNTER_TYPE_GENERIC)
	  {
	    if (mib_counter->direction == VNET_DEV_CTR_DIR_RX &&
		mib_counter->unit == VNET_DEV_CTR_UNIT_BYTES)
	      rx_bytes = value;
	    else if (mib_counter->direction == VNET_DEV_CTR_DIR_RX &&
		     mib_counter->unit == VNET_DEV_CTR_UNIT_PACKETS)
	      rx_packets = value;
	    else if (mib_counter->direction == VNET_DEV_CTR_DIR_TX &&
		     mib_counter->unit == VNET_DEV_CTR_UNIT_BYTES)
	      tx_bytes = value;
	    else if (mib_counter->direction == VNET_DEV_CTR_DIR_TX &&
		     mib_counter->unit == VNET_DEV_CTR_UNIT_PACKETS)
	      tx_packets = value;
	  }
      }

    if (0)
      log_debug (dev,
		 "port %u XGMAC MIB sample: RX %llu packets/%llu bytes, TX %llu packets/%llu bytes",
		 port->port_id, rx_packets, rx_bytes, tx_packets, tx_bytes);
  }
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
