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

#define QPPE_PORT_RESET_DELAY_US 10000
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
  const qppe_reg_val_t reg = {
    .off = offset,
    .val = (value & ~HPPE_MC_MTU_CTRL_TBL_MTU_MASK) | frame_size,
    .mask = HPPE_MC_MTU_CTRL_TBL_MTU_MASK,
  };
  vnet_dev_rv_t rv = qppe_mmio_write_validate (dev, &reg, 1);

  if (rv != VNET_DEV_OK)
    return rv;

  offset = HPPE_REG_MRU_MTU_CTRL_W0 (port->port_id);
  {
    u32 mru_mtu[3] = {
      qppe_mmio_read32 (qd, offset),
      qppe_mmio_read32 (qd, offset + sizeof (u32)),
      qppe_mmio_read32 (qd, offset + 2 * sizeof (u32)),
    };
    u32 expected = frame_size | (frame_size << 16);
    u32 readback;

    mru_mtu[0] =
      (mru_mtu[0] & ~(HPPE_MRU_MTU_CTRL_W0_MRU_MASK | HPPE_MRU_MTU_CTRL_W0_MTU_MASK)) | expected;
    for (u32 i = 0; i < ARRAY_LEN (mru_mtu); i++)
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
  vnet_dev_rv_t rv;

  u32 my_mac_offset = HPPE_REG_MY_MAC_TBL (port->port_id);
  ppe_reg_my_mac_tbl_t my_mac = {
    .mac_da_0 = ((u32) addr->eth_mac[2] << 24) | ((u32) addr->eth_mac[3] << 16) |
		((u32) addr->eth_mac[4] << 8) | addr->eth_mac[5],
    .mac_da_1 = ((u32) addr->eth_mac[0] << 8) | addr->eth_mac[1],
    .valid = 1,
  };

  rv = qppe_mac_set_addr (port, addr);
  if (rv != VNET_DEV_OK)
    return rv;

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

static vnet_dev_rv_t
qppe_port_set_promisc_mode (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 offset = HPPE_REG_PORT_BRIDGE_CTRL (port->port_id);
  ppe_reg_port_bridge_ctrl_t bridge_ctrl;

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

static u32
qppe_port_secondary_mac_find_row (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  for (u32 slot = 0; slot < APPE_PRE_ACL_SECONDARY_MAX; slot++)
    {
      u32 row = APPE_PRE_ACL_SECONDARY_ROW (port->port_id, slot);
      u32 existing_bitmap;
      vnet_dev_hw_addr_t existing_addr;

      qppe_acl_pre_ipo_read_row (port->dev, row, &existing_bitmap, &existing_addr);
      if (addr)
	{
	  if (existing_bitmap != 0 &&
	      clib_memcmp (&existing_addr, addr, sizeof (existing_addr)) == 0)
	    return row;
	}
      else if (existing_bitmap == 0)
	return row;
    }

  return ~0;
}

static vnet_dev_rv_t
qppe_port_secondary_mac_add (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  u32 port_bitmap = 1u << port->port_id;
  u32 row = qppe_port_secondary_mac_find_row (port, 0);

  if (row != ~0)
    return qppe_acl_pre_ipo_write_row (port->dev, row, addr, /* exact_match */ 1,
				       APPE_ACL_PRI_PERMIT, HPPE_ACL_ACTION_FWD, port_bitmap);

  log_err (port->dev, "port %u out of Pre-IPO secondary MAC slots (max %u)", port->port_id,
	   APPE_PRE_ACL_SECONDARY_MAX);
  return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
}

static vnet_dev_rv_t
qppe_port_secondary_mac_del (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  u32 row = qppe_port_secondary_mac_find_row (port, addr);

  if (row != ~0)
    return qppe_acl_pre_ipo_write_row (port->dev, row, addr, /* exact_match */ 1,
				       APPE_ACL_PRI_PERMIT, HPPE_ACL_ACTION_FWD,
				       /* port_bitmap */ 0);

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

    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      if (req->rss_config.set_key)
	rv = VNET_DEV_ERR_NOT_SUPPORTED;
      else
	rv = VNET_DEV_OK;
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

    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      rv = qppe_qm_port_queue_map_configure (port, &req->rss_config);
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      rv = qppe_port_set_promisc_mode (port);
      if (rv == VNET_DEV_OK)
	{
	  u32 port_bitmap = req->promisc ? 1u << port->port_id : 0;

	  rv = qppe_acl_pre_ipo_write_row (port->dev, APPE_PRE_ACL_PROMISC_ROW (port->port_id),
					   &port->primary_hw_addr, /* exact_match */ 0,
					   APPE_ACL_PRI_PROMISC, HPPE_ACL_ACTION_FWD, port_bitmap);
	}
      break;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      {
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
  ppe_reg_port_bridge_ctrl_t bridge_ctrl;
  vnet_dev_rv_t rv;
  u32 offset;
  u32 isolation_bitmap;

  rv = qppe_port_reset (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = qppe_port_set_primary_mac_addr (port, &port->primary_hw_addr);
  if (rv != VNET_DEV_OK)
    return rv;

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
      ppe_reg_port_mux_control_t mux;
      u32 port_select_bit = 1u << (7 + port->port_id);

      mux.as_u32 = qppe_mmio_read32 (qd, APPE_REG_PORT_MUX_CTRL);
      if (!(mux.as_u32 & port_select_bit))
	{
	  mux.as_u32 |= port_select_bit;
	  log_debug (dev, "selecting XGMAC mode for port %u in port mux control: 0x%08x",
		     port->port_id, mux.as_u32);
	  qppe_mmio_write32 (qd, APPE_REG_PORT_MUX_CTRL, mux.as_u32);
	  mux.as_u32 = qppe_mmio_read32 (qd, APPE_REG_PORT_MUX_CTRL);
	  if (!(mux.as_u32 & port_select_bit))
	    {
	      log_err (dev, "port %u XGMAC selection did not take effect in port mux control",
		       port->port_id);
	      return VNET_DEV_ERR_INIT_FAILED;
	    }
	}
    }
  rv = qppe_mac_init (port);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = qppe_port_counters_init (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  vnet_dev_poll_port_add (vm, port, 1, qppe_port_phy_poll);
  vnet_dev_poll_port_add (vm, port, 1, qppe_pcs_poll);
  log_debug (port->dev, "port %u hardware counters initialized; PHY polling every second",
	     port->port_id);

  return rv;
}

void
qppe_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  vnet_dev_poll_port_remove (vm, port, qppe_pcs_poll);
  vnet_dev_poll_port_remove (vm, port, qppe_port_phy_poll);
  qppe_pcs_port_deinit (port);
  log_debug (port->dev, "port %u label %s", port->port_id, qp->label ? qp->label : "(none)");
}

static void
qppe_port_phy_stop (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_port_t *qp = vnet_dev_get_port_data (port);

  if (!qp->phy_aneg_started)
    return;

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
  u32 offset, rate;

  qp->link_configured = 0;
  if (!qp->is_enabled || !qp->phy_link_up)
    {
      offset = HPPE_REG_PORT_BRIDGE_CTRL (port->port_id);
      port_bridge_ctrl.as_u32 = qppe_mmio_read32 (qd, offset);
      port_bridge_ctrl.txmac_en = 0;
      qppe_mmio_write32 (qd, offset, port_bridge_ctrl.as_u32);

      qppe_mac_link_set (port, 0);
      log_debug (dev, "port %u MAC disabled: admin %s, link %s", port->port_id,
		 qp->is_enabled ? "up" : "down", qp->phy_link_up ? "up" : "down");
      vnet_dev_port_state_change (
	vm, port, (vnet_dev_port_state_changes_t) { .change.link_state = 1, .link_state = 0 });
      return;
    }

  rate = qp->clock_node_name ? qppe_port_clock_rate (qp) : 0;
  if (rate == 0)
    {
      log_err (dev, "port %u link up at %u Mbps but port clock resources or rate are invalid",
	       port->port_id, qp->phy_speed_mbps);
      return;
    }

  {
    vnet_dev_rv_t rv;

    rv = vnet_dev_platform_clock_set_rate (dev, qp->clock_node_name, "rx", rate);
    if (rv != VNET_DEV_OK)
      return;
    rv = vnet_dev_platform_clock_set_rate (dev, qp->clock_node_name, "tx", rate);
    if (rv != VNET_DEV_OK)
      return;
  }

  if (qppe_mac_link_set (port, 1) != VNET_DEV_OK)
    return;

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

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (q);
      u32 buffer_size = vlib_buffer_get_default_data_size (vm);

      qr->multibuf = port->max_rx_frame_size > buffer_size;
      log_debug (dev, "port %u max RX frame size %u, RX buffer size %u, multi-buffer RX %s",
		 port->port_id, port->max_rx_frame_size, buffer_size,
		 qr->multibuf ? "enabled" : "disabled");
    }

  if (qp->ethernet_phy_name && !qp->phy_aneg_started)
    {
      if (vnet_dev_platform_ethernet_phy_start_aneg (dev, qp->ethernet_phy_node_name,
						     qp->ethernet_phy_name) != VNET_DEV_OK)
	return VNET_DEV_ERR_INIT_FAILED;
      qp->phy_aneg_started = 1;
    }

  if (qp->has_pcs)
    {
      rv = qppe_pcs_port_start (vm, port);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      {
	rv = qppe_edma_rx_ring_start (vm, q);
	if (rv != VNET_DEV_OK)
	  {
	    qppe_edma_rx_ring_stop (q);
	    goto error_rx;
	  }
      }

  rv = qppe_port_set_promisc_mode (port);
  if (rv != VNET_DEV_OK)
    goto error_rx;

  foreach_vnet_dev_port_tx_queue (q, port)
    if (q->enabled)
      {
	rv = qppe_edma_tx_ring_start (vm, q);
	if (rv != VNET_DEV_OK)
	  {
	    qppe_edma_tx_ring_stop (q);
	    goto error_tx;
	  }
      }

  qp->is_enabled = 1;
  qppe_port_apply_link (vm, port);
  vnet_dev_poll_port_add (vm, port, 1, qppe_port_counters_poll);

  return VNET_DEV_OK;

error_tx:
  foreach_vnet_dev_port_tx_queue (q, port)
    {
      qppe_txq_t *tq = vnet_dev_get_tx_queue_data (q);

      if (tq->started)
	qppe_edma_tx_ring_stop (q);
    }
error_rx:
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      qppe_rxq_t *qr = vnet_dev_get_rx_queue_data (q);

      if (qr->started)
	qppe_edma_rx_ring_stop (q);
    }
  qppe_port_phy_stop (port);
  return rv;
}

void
qppe_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  qppe_rxq_t *qr;
  qppe_txq_t *tq;

  log_debug (port->dev, "stopping port %u label %s", port->port_id,
	     qp->label ? qp->label : "(none)");

  vnet_dev_poll_port_remove (vm, port, qppe_port_counters_poll);
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

  qppe_port_phy_stop (port);
}

void
qppe_port_phy_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  vnet_dev_platform_ethernet_phy_state_t state;
  vnet_dev_rv_t rv;

  if (!qp->ethernet_phy_name || !qp->phy_aneg_started)
    return;

  /* On a PCS-managed in-band port (wan, lan2), kdi's ethernet_phy has no
   * PCS and so can never resolve a real in-band link state here - PCS
   * polling (qppe_pcs_poll) is the sole authority for qp->phy_link_up on
   * these ports, matching what phylink's own "managed" property means. */
  if (qp->has_pcs && qp->managed && strcmp (qp->managed, "in-band-status") == 0)
    return;

  rv = vnet_dev_platform_ethernet_phy_get_state (dev, qp->ethernet_phy_node_name,
						 qp->ethernet_phy_name, &state);
  if (rv != VNET_DEV_OK)
    return;

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
