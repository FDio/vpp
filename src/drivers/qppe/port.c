/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>
#include <vlib/buffer_funcs.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

#define QPPE_PORT_RESET_DELAY_US   10000
#define HPPE_REG_MY_MAC_TBL(index) (0x200000 + (0x8 * (index)))
#define APPE_ACL_PRI_PROMISC	   2
#define APPE_PRE_ACL_SECONDARY_ROW(port_id, slot)                                                  \
  ((port_id) * APPE_PRE_ACL_ROWS_PER_PORT + 2 + (slot))
#define APPE_PRE_ACL_PROMISC_ROW(port_id)                                                          \
  ((port_id) * APPE_PRE_ACL_ROWS_PER_PORT + 2 + APPE_PRE_ACL_SECONDARY_MAX + 1)
#define HPPE_MC_MTU_CTRL_TBL_MTU_MASK  0x00003fff
#define HPPE_MRU_MTU_CTRL_W0_MRU_MASK  0x00003fff
#define HPPE_MRU_MTU_CTRL_W0_MTU_MASK  0x3fff0000
#define PPE_XGMAC_REG_PACKET_FILTER    0x8
#define PPE_XGMAC_REG_WATCHDOG_TIMEOUT 0xc
#define PPE_XGMAC_REG_ADDR0_HIGH       0x300
#define PPE_XGMAC_REG_ADDR0_LOW	       0x304
#define PPE_XGMAC_ADDR_ENABLE	       (1u << 31)
#define PPE_GMAC_REG_ADDR0	       0x8
#define PPE_GMAC_REG_ADDR1	       0xc
#define PPE_GMAC_REG_SPEED	       0x4
#define PPE_XGMAC_SPEED_10000	       0
#define PPE_XGMAC_SPEED_10000_USXGMII  4
#define PPE_XGMAC_SPEED_5000	       5
#define PPE_XGMAC_SPEED_2500	       2
#define PPE_XGMAC_SPEED_2500_USXGMII   6
#define PPE_XGMAC_SPEED_1000	       3

VLIB_REGISTER_LOG_CLASS (qppe_log, static) = {
  .class_name = "qppe",
  .subclass_name = "port",
};

static vnet_dev_rv_t
qppe_port_set_max_rx_frame_size (vnet_dev_port_t *port, u16 frame_size)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 offset = HPPE_REG_MC_MTU_CTRL_TBL (port->port_id);
  u32 value = qppe_mmio_read32 (qd, offset);

  value = (value & ~HPPE_MC_MTU_CTRL_TBL_MTU_MASK) | frame_size;
  qppe_mmio_write32 (qd, offset, value);
  if ((qppe_mmio_read32 (qd, offset) & HPPE_MC_MTU_CTRL_TBL_MTU_MASK) != frame_size)
    {
      log_err (dev, "port %u max RX frame size readback failed at offset 0x%x", port->port_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  offset = HPPE_REG_MRU_MTU_CTRL_W0 (port->port_id);
  {
    u32 mru_mtu[3] = {
      qppe_mmio_read32 (qd, offset),
      qppe_mmio_read32 (qd, offset + sizeof (u32)),
      qppe_mmio_read32 (qd, offset + 2 * sizeof (u32)),
    };
    u32 expected = frame_size | (frame_size << 16);
    u32 readback;
    u32 i;

    mru_mtu[0] =
      (mru_mtu[0] & ~(HPPE_MRU_MTU_CTRL_W0_MRU_MASK | HPPE_MRU_MTU_CTRL_W0_MTU_MASK)) | expected;
    for (i = 0; i < ARRAY_LEN (mru_mtu); i++)
      qppe_mmio_write32 (qd, offset + i * sizeof (u32), mru_mtu[i]);

    readback = qppe_mmio_read32 (qd, offset);
    if ((readback & (HPPE_MRU_MTU_CTRL_W0_MRU_MASK | HPPE_MRU_MTU_CTRL_W0_MTU_MASK)) != expected)
      {
	log_err (
	  dev,
	  "port %u max RX frame size readback failed at offset 0x%x: expected 0x%08x, got 0x%08x",
	  port->port_id, offset, expected, readback);
	return VNET_DEV_ERR_INIT_FAILED;
      }
  }

  log_debug (dev, "port %u max RX frame size set to %u", port->port_id, frame_size);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_port_set_primary_mac_addr (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 gmac_base = PPE_REG_GMAC_BASE (port->port_id);
  u32 xgmac_base = PPE_REG_XGMAC_BASE (port->port_id);
  u32 gmac_addr0 = (addr->eth_mac[5] << 8) | addr->eth_mac[4];
  u32 gmac_addr1 = ((u32) addr->eth_mac[0] << 24) | ((u32) addr->eth_mac[1] << 16) |
		   ((u32) addr->eth_mac[2] << 8) | addr->eth_mac[3];
  u32 xgmac_addr0_high = gmac_addr0 | PPE_XGMAC_ADDR_ENABLE;
  u32 xgmac_addr0_low = ((u32) addr->eth_mac[3] << 24) | ((u32) addr->eth_mac[2] << 16) |
			((u32) addr->eth_mac[1] << 8) | addr->eth_mac[0];
  vnet_dev_rv_t rv;

  u32 my_mac_offset = HPPE_REG_MY_MAC_TBL (port->port_id);
  ppe_reg_my_mac_tbl_t my_mac = {
    .mac_da_0 = ((u32) addr->eth_mac[2] << 24) | ((u32) addr->eth_mac[3] << 16) |
		((u32) addr->eth_mac[4] << 8) | addr->eth_mac[5],
    .mac_da_1 = ((u32) addr->eth_mac[0] << 8) | addr->eth_mac[1],
    .valid = 1,
  };

  qppe_mmio_write32 (qd, gmac_base + PPE_GMAC_REG_ADDR0, gmac_addr0);
  qppe_mmio_write32 (qd, gmac_base + PPE_GMAC_REG_ADDR1, gmac_addr1);
  qppe_mmio_write32 (qd, xgmac_base + PPE_XGMAC_REG_ADDR0_HIGH, xgmac_addr0_high);
  qppe_mmio_write32 (qd, xgmac_base + PPE_XGMAC_REG_ADDR0_LOW, xgmac_addr0_low);

  if (qppe_mmio_read32 (qd, gmac_base + PPE_GMAC_REG_ADDR0) != gmac_addr0 ||
      qppe_mmio_read32 (qd, gmac_base + PPE_GMAC_REG_ADDR1) != gmac_addr1 ||
      qppe_mmio_read32 (qd, xgmac_base + PPE_XGMAC_REG_ADDR0_HIGH) != xgmac_addr0_high ||
      qppe_mmio_read32 (qd, xgmac_base + PPE_XGMAC_REG_ADDR0_LOW) != xgmac_addr0_low)
    {
      log_err (dev, "port %u MAC address readback failed at GMAC/XGMAC address registers",
	       port->port_id);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  /* Own MY_MAC_TBL entry (indexed by port_id): what PORT_BRIDGE_CTRL.promisc_en
   * admits against when non-promiscuous, so hardware can drop unicast frames
   * not addressed to us before FDB/VSI forwarding is even consulted - see
   * qppe_port_set_promisc_mode. */
  qppe_mmio_write32 (qd, my_mac_offset, my_mac.val[0]);
  qppe_mmio_write32 (qd, my_mac_offset + 4, my_mac.val[1]);
  if (qppe_mmio_read32 (qd, my_mac_offset) != my_mac.val[0] ||
      qppe_mmio_read32 (qd, my_mac_offset + 4) != my_mac.val[1])
    {
      log_err (dev, "port %u MY_MAC_TBL readback failed at offset 0x%x", port->port_id,
	       my_mac_offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  rv = qppe_fdb_mac_add (port, addr);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = qppe_acl_pre_ipo_port_configure (port, addr);
  if (rv != VNET_DEV_OK)
    return rv;

  log_debug (dev, "port %u PPE MAC address set to %U", port->port_id, format_vnet_dev_hw_addr,
	     addr);
  return VNET_DEV_OK;
}

/* PORT_BRIDGE_CTRL.promisc_en clear drops any unicast frame whose
 * destination doesn't hit this port's MY_MAC_TBL entry (seeded in
 * qppe_port_set_primary_mac_addr) before FDB/VSI forwarding - or the
 * Pre-IPO ACL stage (see acl.c) - is even consulted. That's a blunt,
 * unicast-only, MAC-unaware block that pre-empts Pre-IPO's own per-MAC
 * permit/deny logic rather than complementing it, so this is kept
 * permanently on (hardware promiscuous): Pre-IPO's rules are the real
 * admission-control mechanism now. VPP's own "promiscuous" config is still
 * accepted (no error), it just no longer changes this register. */
static vnet_dev_rv_t
qppe_port_set_promisc_mode (vnet_dev_port_t *port, u8 enabled __clib_unused)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 offset = HPPE_REG_PORT_BRIDGE_CTRL (port->port_id);
  ppe_reg_port_bridge_ctrl_t bridge_ctrl = {};

  bridge_ctrl.as_u32 = qppe_mmio_read32 (qd, offset);
  bridge_ctrl.promisc_en = 1;
  qppe_mmio_write32 (qd, offset, bridge_ctrl.as_u32);
  if (qppe_mmio_read32 (qd, offset) != bridge_ctrl.as_u32)
    {
      log_err (dev, "port %u promiscuous mode readback failed at offset 0x%x", port->port_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  log_debug (dev, "port %u promiscuous mode enabled (permanently, see comment above)",
	     port->port_id);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qppe_port_secondary_mac_add (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  u32 port_bitmap = 1u << port->port_id;
  u32 slot;

  for (slot = 0; slot < APPE_PRE_ACL_SECONDARY_MAX; slot++)
    {
      u32 row = APPE_PRE_ACL_SECONDARY_ROW (port->port_id, slot);
      u32 existing_bitmap;
      vnet_dev_hw_addr_t existing_addr;

      qppe_acl_pre_ipo_read_row (port->dev, row, &existing_bitmap, &existing_addr);
      if (existing_bitmap == 0)
	return qppe_acl_pre_ipo_write_row (port->dev, row, addr, /* exact_match */ 1,
					   APPE_ACL_PRI_PERMIT, HPPE_ACL_ACTION_FWD, port_bitmap);
    }

  log_err (port->dev, "port %u out of Pre-IPO secondary MAC slots (max %u)", port->port_id,
	   APPE_PRE_ACL_SECONDARY_MAX);
  return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
}

static vnet_dev_rv_t
qppe_port_secondary_mac_del (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  u32 slot;

  for (slot = 0; slot < APPE_PRE_ACL_SECONDARY_MAX; slot++)
    {
      u32 row = APPE_PRE_ACL_SECONDARY_ROW (port->port_id, slot);
      u32 existing_bitmap;
      vnet_dev_hw_addr_t existing_addr;

      qppe_acl_pre_ipo_read_row (port->dev, row, &existing_bitmap, &existing_addr);
      if (existing_bitmap != 0 && clib_memcmp (&existing_addr, addr, sizeof (existing_addr)) == 0)
	return qppe_acl_pre_ipo_write_row (port->dev, row, addr, /* exact_match */ 1,
					   APPE_ACL_PRI_PERMIT, HPPE_ACL_ACTION_FWD,
					   /* port_bitmap */ 0);
    }

  log_err (port->dev, "port %u Pre-IPO secondary MAC %U not found to remove", port->port_id,
	   format_vnet_dev_hw_addr, addr);
  return VNET_DEV_ERR_NO_SUCH_ENTRY;
}

vnet_dev_rv_t
qppe_port_cfg_change_validate (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
			       vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_ERR_NOT_SUPPORTED;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      rv = port->started ? VNET_DEV_ERR_PORT_STARTED : VNET_DEV_OK;
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      rv = VNET_DEV_OK;
      break;

    default:
      break;
    }

  return rv;
}

vnet_dev_rv_t
qppe_port_cfg_change (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
		      vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      rv = qppe_port_set_promisc_mode (port, req->promisc);
      if (rv == VNET_DEV_OK)
	{
	  /* The promiscuous override row: a wildcard permit (any MAC, any
	   * protocol) at a higher priority than the Pre-IPO deny row,
	   * enabled only while promiscuous. Leaves the broadcast/primary/
	   * secondary/deny rows this port already has completely
	   * untouched - see the APPE_PRE_ACL_ROWS_PER_PORT layout comment
	   * in qppe.h. */
	  u32 port_bitmap = req->promisc ? 1u << port->port_id : 0;

	  rv = qppe_acl_pre_ipo_write_row (port->dev, APPE_PRE_ACL_PROMISC_ROW (port->port_id),
					   &port->primary_hw_addr, /* exact_match */ 0,
					   APPE_ACL_PRI_PROMISC, HPPE_ACL_ACTION_FWD, port_bitmap);
	}
      break;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      {
	/* port->primary_hw_addr is still the old address here - the generic
	 * framework (vnet_dev_port_cfg_change) only overwrites it with
	 * req->addr after this callback returns. Drop its stale
	 * redirect-to-CPU FDB entry once the new one is live, so it doesn't
	 * linger as a static entry for a MAC this port no longer owns. */
	vnet_dev_hw_addr_t old_addr = port->primary_hw_addr;

	rv = qppe_port_set_primary_mac_addr (port, &req->addr);
	if (rv == VNET_DEV_OK && clib_memcmp (&old_addr, &req->addr, sizeof (old_addr)) != 0)
	  qppe_fdb_mac_del (port, &old_addr);
      }
      break;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      rv = qppe_fdb_mac_add (port, &req->addr);
      if (rv == VNET_DEV_OK)
	rv = qppe_port_secondary_mac_add (port, &req->addr);
      break;

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      rv = qppe_fdb_mac_del (port, &req->addr);
      if (rv == VNET_DEV_OK)
	rv = qppe_port_secondary_mac_del (port, &req->addr);
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
      break;
    }

  return rv;
}

static vnet_dev_rv_t
qppe_port_reset (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;
  char *name;

  if (!qp->reset_names)
    return VNET_DEV_OK;

  log_debug (port->dev, "asserting resets for port %u", port->port_id);
  foreach_clib_dt_property_string (name, qp->reset_names)
    {
      rv = vnet_dev_platform_reset_assert (port->dev, qp->clock_node_name, name);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  vlib_process_suspend (vm, QPPE_PORT_RESET_DELAY_US * 1e-6);

  foreach_clib_dt_property_string (name, qp->reset_names)
    {
      rv = vnet_dev_platform_reset_deassert (port->dev, qp->clock_node_name, name);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  log_debug (port->dev, "deasserted resets for port %u", port->port_id);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
qppe_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  ppe_reg_port_bridge_ctrl_t bridge_ctrl = {};
  ppe_reg_xgmac_tx_config_t xgmac_tx = {};
  ppe_reg_xgmac_rx_config_t xgmac_rx = {};
  ppe_reg_gmac_enable_t gmac_enable = {};
  ppe_reg_gmac_speed_t gmac_speed = {};
  vnet_dev_rv_t rv;
  u32 offset;
  u32 isolation_bitmap;

  rv = qppe_port_reset (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = qppe_port_set_primary_mac_addr (port, &port->primary_hw_addr);
  if (rv != VNET_DEV_OK)
    return rv;

  if (qp->is_xgmac)
    {
      offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_TX_CONFIG;
      xgmac_tx.as_u32 = qppe_mmio_read32 (qd, offset);
      offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_RX_CONFIG;
      xgmac_rx.as_u32 = qppe_mmio_read32 (qd, offset);
      if (xgmac_tx.as_u32 == 0xffffffff || xgmac_rx.as_u32 == 0xffffffff)
	{
	  log_err (dev, "MMIO read check failed: port %u XGMAC configuration returned all ones",
		   port->port_id);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }
  else
    {
      offset = PPE_REG_GMAC_ENABLE (port->port_id);
      gmac_enable.as_u32 = qppe_mmio_read32 (qd, offset);
      offset = PPE_REG_GMAC_BASE (port->port_id) + PPE_GMAC_REG_SPEED;
      gmac_speed.as_u32 = qppe_mmio_read32 (qd, offset);
      if (gmac_enable.as_u32 == 0xffffffff || gmac_speed.as_u32 == 0xffffffff)
	{
	  log_err (dev, "MMIO read check failed: port %u GMAC configuration returned all ones",
		   port->port_id);
	  return VNET_DEV_ERR_INIT_FAILED;
	}
    }

  offset = HPPE_REG_PORT_BRIDGE_CTRL (port->port_id);
  isolation_bitmap =
    (((1u << QPPE_MAX_PORTS) - 1) & ~(1u << EDMA_CPU_PORT_ID) & ~(1u << port->port_id)) |
    (1u << EDMA_CPU_PORT_ID);

  log_debug (port->dev, "port %u label %s phy-mode %s managed %s", port->port_id,
	     qp->label ? qp->label : "(none)", qp->phy_mode ? qp->phy_mode : "(unspecified)",
	     qp->managed ? qp->managed : "(unspecified)");
  bridge_ctrl.as_u32 = qppe_mmio_read32 (qd, offset);
  bridge_ctrl.port_isolation_bitmap = isolation_bitmap;
  /* Permanently on - see qppe_port_set_promisc_mode's comment. */
  bridge_ctrl.promisc_en = 1;
  qppe_mmio_write32 (qd, offset, bridge_ctrl.as_u32);
  if (qppe_mmio_read32 (qd, offset) != bridge_ctrl.as_u32)
    {
      log_err (dev, "port %u isolation bitmap readback failed at offset 0x%x", port->port_id,
	       offset);
      return VNET_DEV_ERR_INIT_FAILED;
    }
  if (qp->is_xgmac)
    {
      ppe_reg_port_mux_control_t mux = {};
      ppe_reg_xgmac_tx_config_t tx = xgmac_tx;
      ppe_reg_xgmac_rx_config_t rx = xgmac_rx;
      ppe_reg_xgmac_packet_filter_t filter = {};
      ppe_reg_xgmac_watchdog_timeout_t watchdog = {};
      u32 port_select_bit = 1 << (port->port_id - 1);
      u32 base = PPE_REG_XGMAC_BASE (port->port_id);
      u32 offset;

      mux.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_PORT_MUX_CONTROL);
      if (!(mux.xgmac_select & port_select_bit))
	{
	  mux.xgmac_select |= port_select_bit;
	  log_debug (dev, "selecting XGMAC mode for port %u in port mux control: 0x%08x",
		     port->port_id, mux.as_u32);
	  qppe_mmio_write32 (qd, HPPE_REG_PORT_MUX_CONTROL, mux.as_u32);
	  mux.as_u32 = qppe_mmio_read32 (qd, HPPE_REG_PORT_MUX_CONTROL);
	  if (!(mux.xgmac_select & port_select_bit))
	    {
	      log_err (dev, "port %u XGMAC selection did not take effect in port mux control",
		       port->port_id);
	      return VNET_DEV_ERR_INIT_FAILED;
	    }
	}

      offset = base + PPE_XGMAC_REG_TX_CONFIG;
      tx.tx_enable = 0;
      tx.jabber_disable = 1;
      qppe_mmio_write32 (qd, offset, tx.as_u32);

      offset = base + PPE_XGMAC_REG_RX_CONFIG;
      rx.rx_enable = 0;
      rx.giant_packet_size_limit_enable = 1;
      rx.giant_packet_size_limit = PPE_XGMAC_MAX_FRAME_SIZE;
      rx.crc_strip = 1;
      rx.address_aligned_beats = 1;
      qppe_mmio_write32 (qd, offset, rx.as_u32);

      /* receive_all always passes every frame up to the PPE for forwarding,
       * which makes promiscuous_mode moot; both stay on so the MAC never
       * drops a frame that PPE forwarding/FDB lookup should decide on. */
      offset = base + PPE_XGMAC_REG_PACKET_FILTER;
      filter.as_u32 = qppe_mmio_read32 (qd, offset);
      filter.receive_all = 1;
      filter.promiscuous_mode = 1;
      filter.pass_control_frames = 2;
      qppe_mmio_write32 (qd, offset, filter.as_u32);

      offset = base + PPE_XGMAC_REG_WATCHDOG_TIMEOUT;
      watchdog.as_u32 = qppe_mmio_read32 (qd, offset);
      watchdog.programmable_watchdog_enable = 1;
      watchdog.watchdog_timeout = 0xb;
      qppe_mmio_write32 (qd, offset, watchdog.as_u32);

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
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  vnet_dev_rx_queue_t *rxq = 0;
  vnet_dev_tx_queue_t *txq = 0;
  vnet_dev_rv_t rv;

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

  foreach_vnet_dev_port_tx_queue (q, port)
    if (q->enabled)
      {
	txq = q;
	break;
      }

  if (txq == 0)
    {
      log_warn (dev, "port %u cannot start: no enabled TX queue", port->port_id);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  rv = qppe_port_set_max_rx_frame_size (port, port->max_rx_frame_size);
  if (rv != VNET_DEV_OK)
    return rv;

  {
    qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (rxq);
    u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
    vlib_buffer_pool_t *buffer_pool = vlib_get_buffer_pool (vm, buffer_pool_index);

    /* a frame bigger than one RX buffer needs the chain-aware (scatter)
     * dequeue path in the RX node instead of the single-descriptor one. */
    qr->multibuf = port->max_rx_frame_size > buffer_pool->data_size;
    log_debug (dev, "port %u max RX frame size %u, RX buffer size %u, multi-buffer RX %s",
	       port->port_id, port->max_rx_frame_size, buffer_pool->data_size,
	       qr->multibuf ? "enabled" : "disabled");
  }

  if (qp->ethernet_phy_name && !qp->phy_aneg_started)
    {
      if (vnet_dev_platform_ethernet_phy_start_aneg (dev, qp->ethernet_phy_node_name,
						     qp->ethernet_phy_name) != VNET_DEV_OK)
	return VNET_DEV_ERR_INIT_FAILED;
      qp->phy_aneg_started = 1;
    }

  rv = qppe_edma_rx_ring_start (vm, rxq);
  if (rv != VNET_DEV_OK)
    {
      if (qp->phy_aneg_started)
	{
	  if (vnet_dev_platform_ethernet_phy_stop (dev, qp->ethernet_phy_node_name,
						   qp->ethernet_phy_name) == VNET_DEV_OK)
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

  /* qppe_port_init only runs once; re-apply here too so starting the port
   * always leaves promisc_en on, regardless of start/stop history. */
  rv = qppe_port_set_promisc_mode (port, port->promisc);
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_rx_ring_stop (rxq);
      if (qp->phy_aneg_started)
	{
	  if (vnet_dev_platform_ethernet_phy_stop (dev, qp->ethernet_phy_node_name,
						   qp->ethernet_phy_name) == VNET_DEV_OK)
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

  rv = qppe_edma_tx_ring_start (vm, txq);
  if (rv != VNET_DEV_OK)
    {
      qppe_edma_rx_ring_stop (rxq);
      if (qp->phy_aneg_started)
	{
	  if (vnet_dev_platform_ethernet_phy_stop (dev, qp->ethernet_phy_node_name,
						   qp->ethernet_phy_name) == VNET_DEV_OK)
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

  qp->is_enabled = 1;
  qppe_port_apply_link (vm, port);

  return VNET_DEV_OK;
}

void
qppe_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  qppe_rxq_t *qr;
  qppe_txq_t *tq;
  vnet_dev_rv_t rv;

  log_debug (port->dev, "stopping port %u label %s", port->port_id,
	     qp->label ? qp->label : "(none)");

  qp->is_enabled = 0;
  qppe_port_apply_link (vm, port);
  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      tq = vnet_dev_get_tx_queue_data (txq);
      if (tq->started)
	qppe_edma_tx_ring_stop (txq);
    }
  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      qr = vnet_dev_get_rx_queue_data (rxq);
      if (qr->started)
	qppe_edma_rx_ring_stop (rxq);
    }

  if (qp->phy_aneg_started)
    {
      rv = vnet_dev_platform_ethernet_phy_stop (dev, qp->ethernet_phy_node_name,
						qp->ethernet_phy_name);
      if (rv == VNET_DEV_OK)
	{
	  qp->phy_aneg_started = 0;
	  qp->phy_state_valid = 0;
	  qp->phy_link_up = 0;
	  qp->phy_speed_mbps = 0;
	  qp->phy_full_duplex = 0;
	}
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
qppe_port_apply_link (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  ppe_reg_port_bridge_ctrl_t port_bridge_ctrl;
  u32 offset;

  qp->link_configured = 0;
  if (!qp->is_enabled || !qp->phy_link_up)
    {
      ppe_reg_port_bridge_ctrl_t port_bridge_ctrl;
      /* Stop the switch core from delivering anything to this port before
       * its MAC is disabled, mirroring the vendor driver's link-down order. */
      offset = HPPE_REG_PORT_BRIDGE_CTRL (port->port_id);
      port_bridge_ctrl.as_u32 = qppe_mmio_read32 (qd, offset);
      port_bridge_ctrl.txmac_en = 0;
      qppe_mmio_write32 (qd, offset, port_bridge_ctrl.as_u32);

      if (qp->is_xgmac)
	{
	  ppe_reg_xgmac_tx_config_t xgmac_tx_config;
	  ppe_reg_xgmac_rx_config_t xgmac_rx_config;

	  offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_TX_CONFIG;
	  xgmac_tx_config.as_u32 = qppe_mmio_read32 (qd, offset);
	  xgmac_tx_config.tx_enable = 0;
	  qppe_mmio_write32 (qd, offset, xgmac_tx_config.as_u32);
	  offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_RX_CONFIG;
	  xgmac_rx_config.as_u32 = qppe_mmio_read32 (qd, offset);
	  xgmac_rx_config.rx_enable = 0;
	  qppe_mmio_write32 (qd, offset, xgmac_rx_config.as_u32);
	}
      else
	{
	  ppe_reg_gmac_enable_t gmac_enable;
	  offset = PPE_REG_GMAC_ENABLE (port->port_id);
	  gmac_enable.as_u32 = qppe_mmio_read32 (qd, offset);
	  gmac_enable.rx_enable = 0;
	  gmac_enable.tx_enable = 0;
	  qppe_mmio_write32 (qd, offset, gmac_enable.as_u32);
	}
      log_debug (dev, "port %u MAC disabled: admin %s, link %s", port->port_id,
		 qp->is_enabled ? "up" : "down", qp->phy_link_up ? "up" : "down");
      vnet_dev_port_state_change (vm, port, (vnet_dev_port_state_changes_t) {
	.change = {
	  .link_state = 1,
	},
	.link_state = 0,
      });
      return;
    }

  if (qp->clock_node_name == 0 || qppe_port_clock_rate (qp) == 0)
    {
      log_err (dev, "port %u link up at %u Mbps but port clock resources or rate are invalid",
	       port->port_id, qp->phy_speed_mbps);
      return;
    }

  {
    u32 rate = qppe_port_clock_rate (qp);
    vnet_dev_rv_t rv;

    rv = vnet_dev_platform_clock_set_rate (dev, qp->clock_node_name, "rx", rate);
    if (rv != VNET_DEV_OK)
      return;
    rv = vnet_dev_platform_clock_set_rate (dev, qp->clock_node_name, "tx", rate);
    if (rv != VNET_DEV_OK)
      return;
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
      tx.speed = speed;
      tx.tx_enable = 1;
      qppe_mmio_write32 (qd, offset, tx.as_u32);
      offset = PPE_REG_XGMAC_BASE (port->port_id) + PPE_XGMAC_REG_RX_CONFIG;
      rx.as_u32 = qppe_mmio_read32 (qd, offset);
      rx.rx_enable = 1;
      qppe_mmio_write32 (qd, offset, rx.as_u32);
      log_debug (dev, "port %u XGMAC link enabled at %u Mbps: TX config 0x%08x, RX config 0x%08x",
		 port->port_id, qp->phy_speed_mbps, tx.as_u32, rx.as_u32);
    }
  else
    {
      ppe_reg_gmac_enable_t enable = {};
      ppe_reg_gmac_speed_t speed = {};

      speed.speed = qp->phy_speed_mbps == 1000 ? 2 : qp->phy_speed_mbps == 100 ? 1 : 0;
      offset = PPE_REG_GMAC_BASE (port->port_id) + PPE_GMAC_REG_SPEED;
      qppe_mmio_write32 (qd, offset, speed.as_u32);
      offset = PPE_REG_GMAC_ENABLE (port->port_id);
      enable.rx_enable = 1;
      enable.tx_enable = 1;
      enable.full_duplex = qp->phy_full_duplex;
      qppe_mmio_write32 (qd, offset, enable.as_u32);
      log_debug (dev,
		 "port %u GMAC link enabled at %u Mbps, %s duplex: speed 0x%08x, enable "
		 "0x%08x",
		 port->port_id, qp->phy_speed_mbps, qp->phy_full_duplex ? "full" : "half",
		 speed.as_u32, enable.as_u32);
    }

  /* Only now that the MAC itself is enabled, let the switch core start
   * delivering frames to this port - mirroring the vendor driver's
   * link-up order. */
  offset = HPPE_REG_PORT_BRIDGE_CTRL (port->port_id);
  port_bridge_ctrl.as_u32 = qppe_mmio_read32 (qd, offset);
  port_bridge_ctrl.txmac_en = 1;
  qppe_mmio_write32 (qd, offset, port_bridge_ctrl.as_u32);

  vnet_dev_port_state_change (vm, port, (vnet_dev_port_state_changes_t) {
    .change = {
      .link_state = 1,
      .link_speed = 1,
      .link_duplex = 1,
    },
    .link_state = 1,
    .link_speed = qp->phy_speed_mbps * 1000,
    .full_duplex = qp->phy_full_duplex,
  });

  qp->link_configured = 1;
}
