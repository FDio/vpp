/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/ethernet/ethernet.h>
#include <ice.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "port",
};

static u8
ice_global_reset_done (vnet_dev_t *dev)
{
  ice_reg_glgen_rstat_t r = {
    .as_u32 = ice_reg_read (dev, ICE_GLGEN_RSTAT),
  };
  ice_reg_glnvm_uld_t uld = {
    .as_u32 = ice_reg_read (dev, ICE_GLNVM_ULD),
  };

  return r.devstate == 0 && uld.pcier_done && uld.pcier_done_1 && uld.corer_done &&
	 uld.globr_done && uld.por_done && uld.por_done_1 && uld.pcier_done_2;
}

static vnet_dev_rv_t
ice_wait_global_reset (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_reg_glgen_rstctl_t rstctl = {
    .as_u32 = ice_reg_read (dev, ICE_GLGEN_RSTCTL),
  };
  f64 start = vlib_time_now (vm);
  f64 active_timeout = (rstctl.global_reset_delay + 10) * 0.1;

  while (vlib_time_now (vm) - start < active_timeout)
    {
      ice_reg_glgen_rstat_t rstat = {
	.as_u32 = ice_reg_read (dev, ICE_GLGEN_RSTAT),
      };
      if (rstat.devstate == 0)
	break;
      vlib_process_suspend (vm, 0.1);
    }
  ice_reg_glgen_rstat_t rstat = {
    .as_u32 = ice_reg_read (dev, ICE_GLGEN_RSTAT),
  };
  if (rstat.devstate != 0)
    {
      log_err (dev, "global reset timeout, GLGEN_RSTAT 0x%08x", rstat.as_u32);
      return VNET_DEV_ERR_TIMEOUT;
    }

  start = vlib_time_now (vm);
  while (vlib_time_now (vm) - start < 20.0)
    {
      if (ice_global_reset_done (dev))
	{
	  log_debug (dev, "global reset processes complete");
	  return VNET_DEV_OK;
	}
      vlib_process_suspend (vm, 1e-2);
    }
  log_err (dev, "global reset processes timeout, GLNVM_ULD 0x%08x",
	   ice_reg_read (dev, ICE_GLNVM_ULD));
  return VNET_DEV_ERR_TIMEOUT;
}

static vnet_dev_rv_t
ice_wait_pf_reset (vlib_main_t *vm, vnet_dev_t *dev)
{
  f64 start = vlib_time_now (vm);

  while (vlib_time_now (vm) - start < 5.0)
    {
      ice_reg_pfgen_ctrl_t ctrl = {
	.as_u32 = ice_reg_read (dev, ICE_PFGEN_CTRL),
      };
      if (!ctrl.pf_sw_reset)
	{
	  log_debug (dev, "PF software reset completed");
	  return VNET_DEV_OK;
	}
      vlib_process_suspend (vm, 1e-3);
    }
  log_err (dev, "PF software reset timeout, PFGEN_CTRL 0x%08x", ice_reg_read (dev, ICE_PFGEN_CTRL));
  return VNET_DEV_ERR_TIMEOUT;
}

vnet_dev_rv_t
ice_hw_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_reg_pf_func_rid_t rid;
  ice_reg_rxq_alloc_t rx_alloc;
  ice_reg_txq_alloc_t tx_alloc;
  vnet_dev_rv_t rv;

  if (!ice_global_reset_done (dev))
    {
      log_debug (dev, "global reset in progress");
      if ((rv = ice_wait_global_reset (vm, dev)))
	return rv;
    }
  else
    {
      ice_reg_pfgen_ctrl_t ctrl = {
	.as_u32 = ice_reg_read (dev, ICE_PFGEN_CTRL),
      };
      log_debug (dev, "requesting PF software reset");
      ctrl.pf_sw_reset = 1;
      ice_reg_write (dev, ICE_PFGEN_CTRL, ctrl.as_u32);
      ice_reg_flush (dev);
      if ((rv = ice_wait_pf_reset (vm, dev)))
	return rv;
    }
  if ((rv = ice_aq_start (vm, dev)))
    return rv;

  rid.as_u32 = ice_reg_read (dev, ICE_PF_FUNC_RID);
  id->pf_id = rid.function_number;
  rx_alloc.as_u32 = ice_reg_read (dev, ICE_PFLAN_RX_QALLOC);
  tx_alloc.as_u32 = ice_reg_read (dev, ICE_PFLAN_TX_QALLOC + id->pf_id * sizeof (u32));
  if (!rx_alloc.valid || !tx_alloc.valid || rx_alloc.last_queue < rx_alloc.first_queue ||
      tx_alloc.last_queue < tx_alloc.first_queue)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  id->rxq_base = rx_alloc.first_queue;
  id->txq_base = tx_alloc.first_queue;
  id->rxq_count = rx_alloc.last_queue - rx_alloc.first_queue + 1;
  id->txq_count = tx_alloc.last_queue - tx_alloc.first_queue + 1;
  log_debug (dev, "PF %u queue allocation: RX %u-%u (%u), TX %u-%u (%u)", id->pf_id,
	     rx_alloc.first_queue, rx_alloc.last_queue, id->rxq_count, tx_alloc.first_queue,
	     tx_alloc.last_queue, id->txq_count);

  return ice_aq_configure (vm, dev);
}

void
ice_hw_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_aq_stop (vm, dev);
}

static void
ice_port_status_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  u8 link_up;

  ice_port_counter_poll (vm, port);
  if (ice_aq_get_link_state (vm, port, &link_up))
    return;
  if (link_up != ip->last_link_up)
    {
      vnet_dev_port_state_changes_t changes = {
	.change.link_state = 1,
	.link_state = link_up,
      };
      ip->last_link_up = link_up;
      log_debug (port->dev, "port %u link %s", port->port_id, link_up ? "up" : "down");
      vnet_dev_port_state_change (vm, port, changes);
    }
}

vnet_dev_rv_t
ice_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  return ice_port_counters_init (vm, port);
}

static vnet_dev_rv_t
ice_start_rx_queue (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u16 q = id->rxq_base + rxq->queue_id;
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u32 n =
    vlib_buffer_alloc_from_pool (vm, iq->buffer_indices, rxq->size - ICE_RX_REFILL_BATCH, bpi);

  if (n < ICE_RX_REFILL_BATCH)
    {

      log_debug (dev, "RX queue %u start failed: allocated %u buffers", q, n);
      if (n)
	vlib_buffer_free (vm, iq->buffer_indices, n);
      return VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
    }
  for (u32 i = 0; i < n; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, iq->buffer_indices[i]);
      iq->descs[i].read.pkt_addr = vnet_dev_get_dma_addr (vm, dev, b->data);
    }

  ice_rxq_ctx_t ctx = {
    .base = vnet_dev_get_dma_addr (vm, dev, iq->descs) >> 7,
    .qlen = rxq->size,
    .dbuf = round_pow2 (vnet_dev_get_rx_queue_buffer_data_size (vm, rxq), 128) >> 7,
    .crcstrip = 1,
    .l2tsel = 1,
    .rxmax = rxq->port->max_rx_frame_size,
    .lrxqthresh = 1,
    .prefena = 1,
  };
  ice_reg_write (dev, ICE_QRX_CTRL (q), 0);
  for (u32 i = 0; i < 8; i++)
    ice_reg_write (dev, ICE_QRX_CONTEXT (i, q), ctx.as_u32[i]);

  iq->head = 0;
  iq->tail = n;
  iq->tail_reg = (u32 *) ((u8 *) id->bar0 + ICE_QRX_TAIL (q));
  ice_reg_write (dev, ICE_QRX_TAIL (q), n - 1);
  ice_reg_write (dev, ICE_QRX_CTRL (q), (ice_reg_qrx_ctrl_t) { .enable_request = 1 }.as_u32);
  ice_reg_flush (dev);

  f64 start = vlib_time_now (vm);
  while (vlib_time_now (vm) - start < 0.1)
    {
      ice_reg_qrx_ctrl_t ctrl = {
	.as_u32 = ice_reg_read (dev, ICE_QRX_CTRL (q)),
      };
      if (ctrl.enable_status)
	{
	  iq->ctx = ctx;
	  iq->ctx_valid = 1;
	  log_debug (dev, "RX queue %u started: %u descriptors, %u buffers", q, rxq->size, n);
	  return VNET_DEV_OK;
	}
      vlib_process_suspend (vm, 1e-3);
    }
  return VNET_DEV_ERR_TIMEOUT;
}

static vnet_dev_rv_t
ice_start_tx_queue (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
  u16 q = id->txq_base + txq->queue_id;
  ice_txq_ctx_t ctx = {
    .base = vnet_dev_get_dma_addr (vm, dev, iq->descs) >> 7,
    .port_num = id->lport,
    .pf_num = id->pf_id,
    .vmvf_type = 2,
    .src_vsi = id->vsi_num,
    .qlen = txq->size,
    .tso_ena = 1,
    .tso_qnum = q,
    .legacy_int = 1,
  };

  vnet_dev_rv_t rv = ice_aq_add_txq (vm, txq, &ctx);
  if (rv != VNET_DEV_OK)
    return rv;

  iq->head = iq->tail = 0;
  iq->tail_reg = (u32 *) ((u8 *) id->bar0 + ICE_QTX_COMM_DBELL (q));
  ice_reg_write (dev, ICE_QTX_COMM_DBELL (q), 0);
  id->txq_enabled = 1;
  iq->ctx = ctx;
  iq->ctx_valid = 1;
  log_debug (dev, "TX queue %u started: %u descriptors, VSI %u, parent TEID %u", q, txq->size,
	     id->vsi_num, id->tx_parent_teid);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv;

  log_debug (port->dev, "starting port %u", port->port_id);
  foreach_vnet_dev_port_rx_queue (rxq, port)
    if ((rv = ice_start_rx_queue (vm, rxq)))
      goto error;
  foreach_vnet_dev_port_tx_queue (txq, port)
    if ((rv = ice_start_tx_queue (vm, txq)))
      goto error;
  vnet_dev_poll_port_add (vm, port, 1.0, ice_port_status_poll);
  log_debug (port->dev, "port %u started", port->port_id);
  return VNET_DEV_OK;

error:
  ice_port_stop (vm, port);
  return rv;
}

void
ice_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);

  log_debug (port->dev, "stopping port %u", port->port_id);
  vnet_dev_poll_port_remove (vm, port, ice_port_status_poll);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      u16 q = id->rxq_base + rxq->queue_id;
      ice_reg_write (dev, ICE_QRX_CTRL (q), 0);
      if (iq->tail != iq->head)
	vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, iq->head & (rxq->size - 1),
					    rxq->size, iq->tail - iq->head);
      iq->head = iq->tail = 0;
      iq->ctx_valid = 0;
      log_debug (port->dev, "RX queue %u stopped", q);
    }

  if (id->txq_enabled)
    {
      foreach_vnet_dev_port_tx_queue (txq, port)
	(void) ice_aq_dis_txq (vm, txq);
      id->txq_enabled = 0;
      log_debug (port->dev, "TX queue %u disabled", id->txq_base);
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
      if (iq->tail != iq->head)
	vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, iq->head & (txq->size - 1),
					    txq->size, iq->tail - iq->head);
      iq->head = iq->tail = 0;
      iq->ctx_valid = 0;
    }
  log_debug (port->dev, "port %u stopped", port->port_id);
}

vnet_dev_rv_t
ice_port_cfg_change_validate (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port __clib_unused,
			      vnet_dev_port_cfg_change_req_t *req __clib_unused)
{
  return VNET_DEV_ERR_NOT_SUPPORTED;
}

vnet_dev_rv_t
ice_port_cfg_change (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port __clib_unused,
		     vnet_dev_port_cfg_change_req_t *req __clib_unused)
{
  return VNET_DEV_ERR_NOT_SUPPORTED;
}
