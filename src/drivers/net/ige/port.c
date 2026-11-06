/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <ige.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (ige_log, static) = {
  .class_name = "ige",
  .subclass_name = "port",
};

const u32 link_speeds[8] = {
  [0b000] = 10000,
  [0b001] = 100000,
  [0b010] = 1000000,
  [0b110] = 2500000,
};

static void
ige_port_status_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ige_port_t *ip = vnet_dev_get_port_data (port);
  ige_reg_status_t status;

  ige_reg_rd (dev, IGE_REG_STATUS, &status.as_u32);

  if (ip->last_status.as_u32 != status.as_u32)
    {
      vnet_dev_port_state_changes_t changes = {};

      log_debug (dev, "\n%U", format_ige_reg_diff, IGE_REG_STATUS,
		 ip->last_status.as_u32, status.as_u32);

      if (ip->last_status.link_up != status.link_up)
	{
	  changes.change.link_state = 1;
	  changes.link_state = status.link_up;
	  log_debug (dev, "link state changed to %s",
		     status.link_up ? "up" : "down");
	}

      if (ip->last_status.full_duplex != status.full_duplex)
	{
	  changes.change.link_duplex = 1;
	  changes.full_duplex = status.full_duplex;
	  log_debug (dev, "duplex changed to %s",
		     status.full_duplex ? "full" : "half");
	}

      if (ip->last_status.speed != status.speed ||
	  ip->last_status.speed_2p5 != status.speed_2p5)
	{
	  changes.change.link_speed = 1;
	  changes.link_speed =
	    link_speeds[status.speed_2p5 << 2 | status.speed];
	  if (changes.link_speed)
	    log_debug (dev, "link speed changed to %u Mbps",
		       changes.link_speed / 1000);
	  else
	    log_warn (dev,
		      "device reported unknown speed (speed %u speed_2p5 %u)",
		      status.speed, status.speed_2p5);
	}
      ip->last_status.as_u32 = status.as_u32;
      if (changes.change.any)
	vnet_dev_port_state_change (vm, port, changes);
    }
}

vnet_dev_rv_t
ige_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv;

  log_debug (port->dev, "port %u", port->port_id);

  rv = ige_port_counters_init (vm, port);
  vnet_dev_poll_port_add (vm, port, 1, ige_port_status_poll);
  return rv;
}

vnet_dev_rv_t
ige_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ige_device_t *id = vnet_dev_get_data (port->dev);
  ige_rxq_t *iq;
  ige_txq_t *tq;
  ige_reg_rctl_t rctl;
  ige_reg_tctl_t tctl;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (dev, "port %u", port->port_id);

  ige_reg_rd (dev, IGE_REG_RCTL, &rctl.as_u32);
  if (rctl.rx_enable)
    {
      log_warn (dev, "port %u rx is unexpectedly enabled", port->port_id);
      rctl.rx_enable = 0;
      ige_reg_wr (dev, IGE_REG_RCTL, rctl.as_u32);
    }

  ige_reg_rd (dev, IGE_REG_TCTL, &tctl.as_u32);
  if (tctl.tx_enable)
    {
      log_warn (dev, "port %u tx is unexpectedly enabled", port->port_id);
      tctl.tx_enable = 0;
      ige_reg_wr (dev, IGE_REG_TCTL, tctl.as_u32);
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      const ige_reg_srrctl_t srrctl = {
	.drop_en = 1,
	.desc_type = 1,	  /* advanced, no header */
	.bsizepacket = 2, /* 2k */
			  //.bsizeheader = 2, /* 128 B */
      };

      const ige_reg_rxdctl_t rxdctl = {
	.pthresh = 12,
	.hthresh = 10,
	.wthresh = 1,
	.enable = 1,
      };

      u64 dma_addr;
      u16 q = rxq->queue_id;
      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      dma_addr = vnet_dev_get_dma_addr (vm, dev, iq->descs);
      ige_reg_wr (dev, IGE_REG_RDLEN (q), rxq->size * sizeof (ige_rx_desc_t));
      ige_reg_wr (dev, IGE_REG_RDBAH (q), dma_addr >> 32);
      ige_reg_wr (dev, IGE_REG_RDBAL (q), dma_addr);
      ige_reg_wr (dev, IGE_REG_SRRCTL (q), srrctl.as_u32);
      ige_reg_wr (dev, IGE_REG_RXDCTL (q), rxdctl.as_u32);
      iq->head = 0;
      iq->tail = 0;
      iq->reg_rdt = (u32 *) ((u8 *) id->bar0 + IGE_REG_RDT (q));

      /* Ensure the queue starts with buffers posted. */
      u16 n_posted = ige_rxq_refill_no_wrap (
	vm, iq->buffer_indices, iq->descs, rxq->size,
	vnet_dev_get_rx_queue_buffer_pool_index (rxq), dev->va_dma);

      iq->tail = n_posted;

      if (iq->tail == 0)
	{
	  rv = VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
	  goto error;
	}

      __atomic_store_n (iq->reg_rdt, (u32) iq->tail, __ATOMIC_RELEASE);
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      u64 dma_addr;
      u64 wb_dma;
      u16 q = txq->queue_id;
      ige_reg_txctl_t txctl;

      ige_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
      ASSERT (tq->wb != 0);
      dma_addr = vnet_dev_get_dma_addr (vm, dev, tq->descs);
      wb_dma = vnet_dev_get_dma_addr (vm, dev, tq->wb);

      ige_reg_wr (dev, IGE_REG_TDLEN (q), txq->size * sizeof (ige_tx_desc_t));
      ige_reg_wr (dev, IGE_REG_TDBAH (q), dma_addr >> 32);
      ige_reg_wr (dev, IGE_REG_TDBAL (q), dma_addr);
      ige_reg_wr (dev, IGE_REG_TDWBAH (q), wb_dma >> 32);
      ige_reg_wr (dev, IGE_REG_TDWBAL (q),
		  ((u32) wb_dma & ~0x3u) | IGE_TDWBAL_HEAD_WB_ENABLE);

      *tq->wb = 0;

      tq->head = tq->tail = 0;
      tq->reg_tdt = (u32 *) ((u8 *) id->bar0 + IGE_REG_TDT (q));

      ige_reg_wr (dev, IGE_REG_TDH (q), 0);
      ige_reg_wr (dev, IGE_REG_TDT (q), 0);

      ige_reg_txdctl_t txdctl = {
	.pthresh = 8,
	.hthresh = 1,
	.wthresh = 1,
	.enable = 1,
      };

      ige_reg_wr (dev, IGE_REG_TXDCTL (q), txdctl.as_u32);
      ige_reg_rd (dev, IGE_REG_TXCTL (q), &txctl.as_u32);
      txctl.tx_desc_wb_relax_order_en = 0;
      ige_reg_wr (dev, IGE_REG_TXCTL (q), txctl.as_u32);
    }

  rctl.rx_enable = 1;
  rctl.store_bad_packets = 0;
  rctl.strip_eth_crc = 1;
  rctl.long_pkt_reception_ena = 1;
  rctl.vlan_filter_ena = 0;
  rctl.bcast_accept_mode = 1;
  rctl.discard_pause_frames = 1;
  ige_reg_wr (dev, IGE_REG_RCTL, rctl.as_u32);
  ige_reg_wr (dev, IGE_REG_RLPML, port->max_rx_frame_size);

  tctl.tx_enable = 1;
  tctl.pad_short_pkts = 1;
  ige_reg_wr (dev, IGE_REG_TCTL, tctl.as_u32);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      u16 q = rxq->queue_id;

      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      ige_reg_wr (dev, IGE_REG_RDH (q), 0);
      ige_reg_wr (dev, IGE_REG_RDT (q), iq->tail);
    }

  vnet_dev_poll_port_add (vm, port, 3, ige_port_counter_poll);
  return 0;

error:
  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      iq = vnet_dev_get_rx_queue_data (rxq);
      if (iq->tail)
	{
	  u16 n_buffers = iq->tail - iq->head;
	  u16 mask = rxq->size - 1;
	  u16 start = iq->head & mask;
	  if (n_buffers)
	    vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, start,
						rxq->size, n_buffers);
	}
      iq->head = iq->tail = 0;
    }
  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      tq = vnet_dev_get_tx_queue_data (txq);
      if (tq->tail != tq->head)
	{
	  u16 mask = txq->size - 1;
	  u16 start = tq->head & mask;
	  u16 n_buffers = tq->tail - tq->head;

	  if (n_buffers)
	    vlib_buffer_free_from_ring_no_next (vm, tq->buffer_indices, start,
						txq->size, n_buffers);
	}

      tq->head = tq->tail = 0;
      if (tq->reg_tdt)
	{
	  ige_reg_txdctl_t txdctl = {};
	  ige_reg_wr (dev, IGE_REG_TDT (txq->queue_id), 0);
	  ige_reg_rd (dev, IGE_REG_TXDCTL (txq->queue_id), &txdctl.as_u32);
	  txdctl.enable = 0;
	  ige_reg_wr (dev, IGE_REG_TXDCTL (txq->queue_id), txdctl.as_u32);
	  ige_reg_wr (dev, IGE_REG_TDWBAL (txq->queue_id), 0);
	  ige_reg_wr (dev, IGE_REG_TDWBAH (txq->queue_id), 0);
	}
    }
  return rv;
}

void
ige_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  log_debug (dev, "port %u", port->port_id);
  ige_reg_rctl_t rctl;
  ige_reg_tctl_t tctl;
  vnet_dev_poll_port_remove (vm, port, ige_port_counter_poll);

  ige_reg_rd (dev, IGE_REG_RCTL, &rctl.as_u32);
  rctl.rx_enable = 0;
  ige_reg_wr (dev, IGE_REG_RCTL, rctl.as_u32);

  ige_reg_rd (dev, IGE_REG_TCTL, &tctl.as_u32);
  tctl.tx_enable = 0;
  ige_reg_wr (dev, IGE_REG_TCTL, tctl.as_u32);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      u16 n_buffers = iq->tail - iq->head;
      u16 mask = rxq->size - 1;

      if (n_buffers)
	vlib_buffer_free_from_ring_no_next (
	  vm, iq->buffer_indices, iq->head & mask, rxq->size, n_buffers);

      iq->head = iq->tail = 0;
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      ige_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
      u16 n_buffers = tq->tail - tq->head;
      u16 mask = txq->size - 1;

      if (n_buffers)
	vlib_buffer_free_from_ring_no_next (
	  vm, tq->buffer_indices, tq->head & mask, txq->size, n_buffers);

      tq->head = tq->tail = 0;
      if (tq->reg_tdt)
	{
	  ige_reg_txdctl_t txdctl = {};
	  ige_reg_wr (dev, IGE_REG_TDT (txq->queue_id), 0);
	  ige_reg_rd (dev, IGE_REG_TXDCTL (txq->queue_id), &txdctl.as_u32);
	  txdctl.enable = 0;
	  ige_reg_wr (dev, IGE_REG_TXDCTL (txq->queue_id), txdctl.as_u32);
	  ige_reg_wr (dev, IGE_REG_TDWBAL (txq->queue_id), 0);
	  ige_reg_wr (dev, IGE_REG_TDWBAH (txq->queue_id), 0);
	}
    }
}

static vnet_dev_rv_t
ige_set_promisc_mode (vlib_main_t *vm, vnet_dev_port_t *port, int enabled)
{
  vnet_dev_t *dev = port->dev;
  ige_reg_rctl_t rctl;

  ige_reg_rd (dev, IGE_REG_RCTL, &rctl.as_u32);
  rctl.uc_promisc_ena = enabled;
  rctl.mc_promisc_ena = enabled;
  ige_reg_wr (dev, IGE_REG_RCTL, rctl.as_u32);
  ige_reg_rd (dev, IGE_REG_RCTL, &rctl.as_u32);
  log_debug (dev, "\n %U", format_ige_reg_read, IGE_REG_RCTL, rctl.as_u32);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ige_change_primary_hw_addr (vlib_main_t *vm, vnet_dev_port_t *port,
			    const vnet_dev_hw_addr_t *hw_addr)
{
  vnet_dev_t *dev = port->dev;
  ige_receive_addr_t ra = {
    .av = 1,
  };

  clib_memcpy (ra.hw_addr, hw_addr->eth_mac, sizeof (ra.hw_addr));

  ige_reg_wr (dev, IGE_REG_RAH (0), ra.rah);
  ige_reg_wr (dev, IGE_REG_RAL (0), ra.ral);

  log_debug (dev, "receive addr table:\n%U", format_ige_receive_addr_table,
	     dev);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ige_add_secondary_hw_addr (vlib_main_t *vm, vnet_dev_port_t *port,
			   const vnet_dev_hw_addr_t *hw_addr)
{
  vnet_dev_t *dev = port->dev;
  ige_receive_addr_t ra;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u32 empty_slot = 0;

  for (u32 i = 0; i < 16; i++)
    {
      ige_reg_rd (dev, IGE_REG_RAH (i), &ra.rah);
      ige_reg_rd (dev, IGE_REG_RAL (i), &ra.ral);
      if (memcmp (ra.hw_addr, hw_addr->eth_mac, sizeof (ra.hw_addr)) == 0)
	{
	  log_err (dev, "address %U already exists in table",
		   format_ethernet_address, hw_addr->eth_mac);
	  rv = VNET_DEV_ERR_ALREADY_EXISTS;
	  goto done;
	}
      if (ra.av == 0 && empty_slot == 0 && i > 0)
	empty_slot = i;
    }

  if (empty_slot == 0)
    {
      log_err (dev, "failed to add secondary hw addr %U, table full",
	       format_ethernet_address, hw_addr->eth_mac);
      rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
      goto done;
    }

  ra = (ige_receive_addr_t){ .av = 1 };
  clib_memcpy (ra.hw_addr, hw_addr->eth_mac, sizeof (ra.hw_addr));
  ige_reg_wr (dev, IGE_REG_RAH (empty_slot), ra.rah);
  ige_reg_wr (dev, IGE_REG_RAL (empty_slot), ra.ral);

done:
  log_debug (dev, "receive addr table:\n%U", format_ige_receive_addr_table,
	     dev);
  return rv;
}

static vnet_dev_rv_t
ige_remove_secondary_hw_addr (vlib_main_t *vm, vnet_dev_port_t *port,
			      const vnet_dev_hw_addr_t *hw_addr)
{
  vnet_dev_t *dev = port->dev;
  ige_receive_addr_t ra;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  for (u32 i = 1; i < 16; i++)
    {
      ige_reg_rd (dev, IGE_REG_RAH (i), &ra.rah);
      ige_reg_rd (dev, IGE_REG_RAL (i), &ra.ral);
      if (memcmp (ra.hw_addr, hw_addr->eth_mac, sizeof (ra.hw_addr)) == 0)
	{
	  ige_reg_wr (dev, IGE_REG_RAH (i), 0);
	  ige_reg_wr (dev, IGE_REG_RAL (i), 0);
	  goto done;
	}
    }

  log_err (dev, "failed to remove secondary hw addr %U, not found",
	   format_ethernet_address, hw_addr->eth_mac);
  rv = VNET_DEV_ERR_NOT_FOUND;

done:
  log_debug (dev, "receive addr table:\n%U", format_ige_receive_addr_table,
	     dev);
  return rv;
}

vnet_dev_rv_t
ige_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
			      vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_ERR_NOT_SUPPORTED;
  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      if (port->started)
	rv = VNET_DEV_ERR_PORT_STARTED;
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
ige_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		     vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      break;
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      rv = ige_set_promisc_mode (vm, port, req->promisc);
      break;
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      rv = ige_change_primary_hw_addr (vm, port, &req->addr);
      break;
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      rv = ige_add_secondary_hw_addr (vm, port, &req->addr);
      break;
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      rv = ige_remove_secondary_hw_addr (vm, port, &req->addr);
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
      break;
    }

  return rv;
}
