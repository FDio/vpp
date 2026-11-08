/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/sfp.h>
#include <vnet/dev/bus/pci.h>
#include <vppinfra/ring.h>
#include <ice.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "port",
};

void
ice_port_update_link_state (vlib_main_t *vm, vnet_dev_port_t *port, u8 link_up, u32 link_speed)
{
  vnet_dev_port_state_changes_t changes = {};

  if (link_up != port->link_up)
    {
      changes.change.link_state = 1;
      changes.link_state = link_up;
    }

  if (link_speed != port->speed)
    {
      changes.change.link_speed = 1;
      changes.link_speed = link_speed;
    }

  if (!changes.change.any)
    return;

  if (link_up)
    log_debug (port->dev, "port %u link up, speed %U", port->port_id,
	       format_vnet_hw_interface_link_speed, link_speed);
  else
    log_debug (port->dev, "port %u link down", port->port_id);

  vnet_dev_port_state_change (vm, port, changes);
}

static void
ice_port_status_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  u32 link_speed;
  u8 link_up;

  ice_port_counter_poll (vm, port);

  if (ice_aq_get_link_state (vm, port, /* enable_events */ 0, &link_up, &link_speed) == VNET_DEV_OK)
    ice_port_update_link_state (vm, port, link_up, link_speed);
}

static void
ice_rx_msix_handler (vlib_main_t *vm __clib_unused, vnet_dev_t *dev, u16 line)
{
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);
  ice_reg_glint_dyn_ctl_t ctl = {
    .intena = 1,
    .clearpba = 1,
    .interval = ICE_ITR_INTERVAL_US / ICE_ITR_INTERVAL_UNIT_US,
  };

  if (!port || !port->interfaces || !port->rx_node_assigned)
    return;

  ice_reg_write (dev, ICE_GLINT_DYN_CTL (line), ctl.as_u32);
  vlib_node_set_interrupt_pending (vlib_get_main_by_index (line - 1),
				   vnet_dev_get_port_rx_node_index (port));
}

static void
ice_rxq_set_cause_ena (vnet_dev_port_t *port, vnet_dev_rx_queue_t *rxq, int enable)
{
  vnet_dev_t *dev = port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (port);
  u16 q = rxq->queue_id;
  ice_reg_qint_ctl_t ctl = {
    .msix_indx = clib_min (rxq->rx_thread_index + 1, ip->n_rx_vectors),
    .cause_ena = enable,
  };

  log_debug (dev, "port %u rxq %u hw queue %u interrupt %s vec %u thread %u", port->port_id,
	     rxq->queue_id, q, enable ? "enabled" : "disabled", ctl.msix_indx,
	     rxq->rx_thread_index);
  ice_reg_write (dev, ICE_QINT_RQCTL (q), ctl.as_u32);
}

static void
ice_rxq_apply_intr_mode (vnet_dev_port_t *port, vnet_dev_rx_queue_t *rxq, int interrupt_mode)
{
  vnet_dev_t *dev = port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (port);
  u16 vector = clib_min (rxq->rx_thread_index + 1, ip->n_rx_vectors);
  ice_reg_glint_dyn_ctl_t dyn_ctl = {
    .intena = 1,
    .clearpba = 1,
    .interval = ICE_ITR_INTERVAL_US / ICE_ITR_INTERVAL_UNIT_US,
  };
  ice_reg_glint_dyn_ctl_t wb_ctl = {
    .wb_on_itr = 1,
  };

  ice_rxq_set_cause_ena (port, rxq, /* enable */ 1);
  ice_reg_write (dev, ICE_GLINT_DYN_CTL (vector), interrupt_mode ? dyn_ctl.as_u32 : wb_ctl.as_u32);
  log_debug (dev, "port %u rxq %u interrupt mode %sabled", port->port_id, rxq->queue_id,
	     interrupt_mode ? "en" : "dis");
}

static vnet_dev_rv_t
ice_port_cfg_rxq_intr_mode (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req, int enable)
{
  vnet_dev_rx_queue_t *rxq;

  if (!port->started)
    {
      log_debug (port->dev, "port %u RX interrupt cfg deferred while stopped", port->port_id);
      return VNET_DEV_OK;
    }

  if (req->all_queues)
    {
      foreach_vnet_dev_port_rx_queue (q, port)
	ice_rxq_apply_intr_mode (port, q, enable);

      return VNET_DEV_OK;
    }

  rxq = vnet_dev_get_port_rx_queue_by_id (port, req->queue_id);

  if (rxq == 0)
    {
      log_err (port->dev, "port %u RX interrupt configuration: queue %u does not exist",
	       port->port_id, req->queue_id);
      return VNET_DEV_ERR_BUG;
    }

  ice_rxq_apply_intr_mode (port, rxq, enable);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  log_debug (dev, "initializing port %u: lport %u VSI %u RX vecs %u max frame %u", port->port_id,
	     ip->lport, ip->vsi.num, ip->n_rx_vectors, port->max_rx_frame_size);

  if (ip->rx_irq_registered)
    return VNET_DEV_ERR_NOT_READY;

  rv = ice_port_counters_init (vm, port);
  if (rv)
    {
      log_err (dev, "port %u counter initialization failed: %U", port->port_id, format_vnet_dev_rv,
	       rv);
      return rv;
    }

  rv = ice_rss_init (vm, port);
  if (rv)
    {
      log_err (dev, "port %u RSS initialization failed: %U", port->port_id, format_vnet_dev_rv, rv);
      return rv;
    }

  rv = vnet_dev_pci_msix_add_handler (vm, dev, &ice_rx_msix_handler, 1, ip->n_rx_vectors);
  if (rv)
    return rv;

  ip->rx_irq_registered = 1;

  rv = vnet_dev_pci_msix_enable (vm, dev, 1, ip->n_rx_vectors);
  if (rv)
    return rv;

  for (u16 i = 0; i < ip->n_rx_vectors; i++)
    {
      vnet_dev_pci_msix_set_polling_thread (vm, dev, i + 1, i);
      log_debug (dev, "port %u RX vec %u assigned to thread %u", port->port_id, i + 1, i);
      ice_reg_write (dev, ICE_GLINT_ITR0 (i + 1), ICE_RX_ITR0_VALUE);
    }

  /* keep the link down until the port is started */
  return ice_aq_set_link (vm, port, ip->link_speed, 0);
}

void
ice_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  if (!ip->rx_irq_registered)
    return;

  rv = vnet_dev_pci_msix_disable (vm, port->dev, 1, ip->n_rx_vectors);

  if (!rv)
    rv = vnet_dev_pci_msix_remove_handler (vm, port->dev, 1, ip->n_rx_vectors);

  if (rv)
    log_err (port->dev, "port %u RX interrupt cleanup failed: %U", port->port_id,
	     format_vnet_dev_rv, rv);
  else
    ip->rx_irq_registered = 0;
}

static vnet_dev_rv_t
ice_rx_queue_set_enable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, int enable)
{
  vnet_dev_t *dev = rxq->port->dev;
  u16 q = rxq->queue_id;
  ice_reg_qrx_ctrl_t ctrl = {
    .as_u32 = ice_reg_read (dev, ICE_QRX_CTRL (q)),
  };
  f64 start = vlib_time_now (vm);

  ctrl.enable_request = enable;
  ice_reg_write (dev, ICE_QRX_CTRL (q), ctrl.as_u32);
  ice_reg_flush (dev);

  do
    {
      ctrl.as_u32 = ice_reg_read (dev, ICE_QRX_CTRL (q));

      if (ctrl.enable_request == enable && ctrl.enable_status == enable)
	return VNET_DEV_OK;

      vlib_process_suspend (vm, 1e-3);
    }
  while (vlib_time_now (vm) - start < 0.1);

  log_err (dev, "port %u RX queue %u hardware queue %u %s timeout: control 0x%08x",
	   rxq->port->port_id, rxq->queue_id, q, enable ? "enable" : "disable", ctrl.as_u32);
  return VNET_DEV_ERR_TIMEOUT;
}

static vnet_dev_rv_t
ice_start_rx_queue (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u16 q = rxq->queue_id;
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u32 n = rxq->size;
  u32 buffer_size =
    round_down_pow2 (vnet_dev_get_rx_queue_buffer_data_size (vm, rxq), ICE_RX_BUFFER_SIZE_UNIT);
  vnet_dev_rv_t rv;

  buffer_size = clib_min (buffer_size, ICE_RX_BUFFER_SIZE_MAX * ICE_RX_BUFFER_SIZE_UNIT);

  if (!buffer_size || rxq->port->max_rx_frame_size > buffer_size * ICE_RX_DESC_MAX_CHAIN_LENGTH)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  rv = ice_rx_queue_set_enable (vm, rxq, 0);
  if (rv)
    return rv;

  if (iq->tail != iq->head)
    {
      vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, iq->head & (n - 1), n,
					  iq->tail - iq->head);
      iq->head = iq->tail = 0;
    }

  if (!vlib_buffer_strict_alloc_from_pool (vm, iq->buffer_indices, n, bpi))
    {
      log_err (dev,
	       "port %u RX queue %u hardware queue %u: unable to allocate %u "
	       "buffers from pool %u",
	       rxq->port->port_id, rxq->queue_id, q, n, bpi);
      return VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
    }

  for (u32 i = 0; i < n; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, iq->buffer_indices[i]);
      iq->descs[i] = (ice_rx_desc_t) {
	.read.pkt_addr = vnet_dev_get_dma_addr (vm, dev, b->data),
      };
    }

  ice_rxq_ctx_t ctx = {
    .base = vnet_dev_get_dma_addr (vm, dev, iq->descs) >> ICE_QUEUE_BASE_SHIFT,
    .qlen = rxq->size,
    .dbuf = buffer_size >> ICE_RX_BUFFER_SIZE_SHIFT,
    .crcstrip = 1,
    .l2tsel = 1,
    .rxmax = rxq->port->max_rx_frame_size,
    .tphrdesc_ena = 1,
    .tphwdesc_ena = 1,
    .tphdata_ena = 1,
    .tphhead_ena = 1,
    .lrxqthresh = 1,
    .prefena = 1,
  };
  ice_reg_qrxflxp_cntxt_t flxp = {
    .rxdid = ICE_RX_DESC_ID_FLEX_NIC,
    .priority = 3,
  };
  iq->maybe_chained = rxq->port->max_rx_frame_size > buffer_size;
  log_debug (dev,
	     "port %u rxq %u hw queue %u: ring DMA 0x%lx pool %u "
	     "thread %u chained %u context %U",
	     rxq->port->port_id, rxq->queue_id, q, ctx.base << ICE_QUEUE_BASE_SHIFT, bpi,
	     rxq->rx_thread_index, iq->maybe_chained, format_hex_bytes, ctx.as_u32,
	     sizeof (ctx.as_u32));
  ice_reg_write (dev, ICE_QRXFLXP_CNTXT (q), flxp.as_u32);

  for (u32 i = 0; i < ARRAY_LEN (ctx.as_u32); i++)
    ice_reg_write (dev, ICE_QRX_CONTEXT (i, q), ctx.as_u32[i]);

  iq->head = 0;
  iq->tail = n;
  iq->tail_reg = (u32 *) ((u8 *) id->bar0 + ICE_QRX_TAIL (q));
  ice_reg_write (dev, ICE_QRX_TAIL (q), 0);
  ice_reg_write (dev, ICE_QRX_TAIL (q), n - 1);
  ice_reg_write (dev, ICE_QRX_ITR (q), (ice_reg_qrx_itr_t) {}.as_u32);

  rv = ice_rx_queue_set_enable (vm, rxq, 1);
  if (rv)
    return rv;

  log_debug (dev,
	     "rxq %u programmed and started: RXDID %u, %u descs, %u buffers, "
	     "buffer sz %u, max frame %u",
	     q, flxp.rxdid, rxq->size, n, ctx.dbuf << ICE_RX_BUFFER_SIZE_SHIFT, ctx.rxmax);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ice_start_tx_queue (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_port_t *ip = vnet_dev_get_port_data (txq->port);
  ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);
  u16 q = txq->queue_id;
  ice_txq_ctx_t ctx = {
    .base = vnet_dev_get_dma_addr (vm, dev, iq->descs) >> ICE_QUEUE_BASE_SHIFT,
    .port_num = ip->lport,
    .pf_num = id->pf_id,
    .vmvf_type = ICE_TXQ_VMVF_TYPE_PF,
    .src_vsi = ip->vsi.num,
    .tsyn_ena = 1,
    .qlen = txq->size,
    .tso_ena = 1,
    .tso_qnum = q,
    .legacy_int = 1,
  };

  log_debug (dev,
	     "port %u txq %u hw queue %u: ring DMA 0x%lx "
	     "descs %u VSI %u lport %u PF %u TSO %u context %U",
	     txq->port->port_id, txq->queue_id, q, ctx.base << ICE_QUEUE_BASE_SHIFT, txq->size,
	     ip->vsi.num, ip->lport, id->pf_id, ctx.tso_ena, format_hex_bytes, ctx.as_u8,
	     sizeof (ctx.as_u8));

  vnet_dev_rv_t rv = ice_aq_add_txq (vm, txq, &ctx);
  if (rv != VNET_DEV_OK)
    return rv;

  iq->head = iq->tail = 0;
  clib_ring_reset (iq->rs_slots);
  iq->tail_reg = (u32 *) ((u8 *) id->bar0 + ICE_QTX_COMM_DBELL (q));
  ice_reg_write (dev, ICE_QTX_COMM_DBELL (q), 0);
  iq->started = 1;
  log_debug (dev, "txq %u started: %u descs, VSI %u, parent TEID %u", q, txq->size, ip->vsi.num,
	     ip->tx_parent_teid);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  ice_reg_glint_dyn_ctl_t dyn_ctl = {
    .intena = 1,
    .clearpba = 1,
    .interval = ICE_ITR_INTERVAL_US / ICE_ITR_INTERVAL_UNIT_US,
  };

  ice_reg_glint_dyn_ctl_t wb_ctl = {
    .wb_on_itr = 1,
  };

  log_debug (port->dev, "starting port %u", port->port_id);

  rv = ice_aq_set_link (vm, port, ip->link_speed, 1);
  if (rv)
    return rv;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      u16 vector = clib_min (rxq->rx_thread_index + 1, ip->n_rx_vectors);

      ice_rxq_set_cause_ena (port, rxq, /* enable */ 1);
      ice_reg_write (dev, ICE_GLINT_DYN_CTL (vector),
		     rxq->interrupt_mode ? dyn_ctl.as_u32 : wb_ctl.as_u32);
      log_debug (dev, "port %u rxq %u interrupt mode %sabled", port->port_id, rxq->queue_id,
		 rxq->interrupt_mode ? "en" : "dis");

      rv = ice_start_rx_queue (vm, rxq);
      if (rv)
	goto error;
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      rv = ice_start_tx_queue (vm, txq);
      if (rv)
	goto error;
    }

  vnet_dev_poll_port_add (vm, port, 0.5, ice_port_status_poll);
  log_debug (port->dev, "port %u started", port->port_id);
  return VNET_DEV_OK;

error:
  log_err (port->dev, "port %u start failed: %U; stopping configured queues", port->port_id,
	   format_vnet_dev_rv, rv);
  ice_port_stop (vm, port);
  return rv;
}

void
ice_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_reg_glint_dyn_ctl_t wb_ctl = {
    .wb_on_itr = 1,
  };

  log_debug (port->dev, "stopping port %u", port->port_id);
  vnet_dev_poll_port_remove (vm, port, ice_port_status_poll);

  /* disable the link so the link partner sees it going down */
  ice_aq_set_link (vm, port, ip->link_speed, 0);
  vnet_dev_port_state_change (vm, port,
			      (vnet_dev_port_state_changes_t) {
				.change.link_state = 1,
				.change.link_speed = 1,
			      });

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ice_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      u16 vector = clib_min (rxq->rx_thread_index + 1, ip->n_rx_vectors);
      u16 q = rxq->queue_id;

      ice_rxq_set_cause_ena (port, rxq, /* enable */ 0);
      ice_reg_write (dev, ICE_GLINT_DYN_CTL (vector), wb_ctl.as_u32);
      log_debug (dev, "port %u rxq %u interrupt mode disabled", port->port_id, rxq->queue_id);

      if (ice_rx_queue_set_enable (vm, rxq, 0) != VNET_DEV_OK)
	continue;

      if (iq->tail != iq->head)
	vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, iq->head & (rxq->size - 1),
					    rxq->size, iq->tail - iq->head);

      iq->head = iq->tail = 0;
      log_debug (port->dev, "rxq %u stopped", q);
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      ice_txq_t *iq = vnet_dev_get_tx_queue_data (txq);

      if (iq->started)
	{
	  vnet_dev_rv_t rv = ice_aq_dis_txq (vm, txq);

	  if (rv != VNET_DEV_OK)
	    log_err (dev, "port %u TX queue %u disable failed: %U", port->port_id, txq->queue_id,
		     format_vnet_dev_rv, rv);
	}

      if (iq->tail != iq->head)
	vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, iq->head & (txq->size - 1),
					    txq->size, iq->tail - iq->head);

      iq->head = iq->tail = 0;
      iq->started = 0;
    }

  log_debug (port->dev, "port %u stopped", port->port_id);
}

vnet_dev_rv_t
ice_port_cfg_change_validate (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port __clib_unused,
			      vnet_dev_port_cfg_change_req_t *req)
{
  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      return port->started ? VNET_DEV_ERR_PORT_STARTED : VNET_DEV_OK;
    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      return ice_rss_validate_config (port, &req->rss_config);
    case VNET_DEV_PORT_CFG_SET_LINK_SPEED:
      {
	ice_phy_type_low_t low;
	ice_phy_type_high_t high;

	return ice_phy_type_for_speed (req->link_speed, &low, &high);
      }
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      return port->attr.caps.interrupt_mode ? VNET_DEV_OK : VNET_DEV_ERR_NOT_SUPPORTED;
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      return VNET_DEV_OK;
    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
}

vnet_dev_rv_t
ice_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req)
{
  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      return VNET_DEV_OK;
    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      return ice_rss_set_config (vm, port, &req->rss_config);
    case VNET_DEV_PORT_CFG_SET_LINK_SPEED:
      {
	ice_port_t *ip = vnet_dev_get_port_data (port);
	vnet_dev_rv_t rv = ice_aq_set_link (vm, port, req->link_speed, port->started);

	if (rv == VNET_DEV_OK)
	  ip->link_speed = req->link_speed;
	return rv;
      }
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
      return ice_port_cfg_rxq_intr_mode (port, req, /* enable */ 1);
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      return ice_port_cfg_rxq_intr_mode (port, req, /* enable */ 0);
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      return ice_aq_set_promisc (vm, port, req->promisc);
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      return ice_aq_change_primary_mac (vm, port, req->addr.eth_mac);
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      return ice_aq_add_mac_rule (vm, port, req->addr.eth_mac);
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      return ice_aq_remove_mac_rule (vm, port, req->addr.eth_mac);
    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
}

vnet_dev_rv_t
ice_port_get_module_eeprom (vlib_main_t *vm, vnet_dev_port_t *port, void *p)
{
  vnet_dev_port_module_eeprom_req_t *r = p;
  ice_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;
  u8 set_page = 0;

  if (r->bank)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  if (r->offset + r->length > 256)
    return VNET_DEV_ERR_INVALID_ARG;

  if (r->i2c_address == 0x50 && r->offset + r->length > 128)
    {
      u8 header[3];

      rv = ice_aq_sff_eeprom (vm, port->dev, ip->lport, r->i2c_address, 0, 0, 0, header,
			      sizeof (header));
      if (rv)
	return rv;

      if (header[0] == SFP_ID_QSFP || header[0] == SFP_ID_QSFP_PLUS || header[0] == SFP_ID_QSFP28)
	set_page = !(header[2] & (1 << 2));
    }

  if (r->page && !set_page)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  log_debug (port->dev, "port %u lport %u EEPROM read: I2C 0x%02x page %u bank %u off %u len %u",
	     port->port_id, ip->lport, r->i2c_address, r->page, r->bank, r->offset, r->length);

  for (u16 done = 0; done < r->length; done += ICE_AQ_SFF_READ_MAX)
    {
      u8 n = clib_min (r->length - done, ICE_AQ_SFF_READ_MAX);

      rv = ice_aq_sff_eeprom (vm, port->dev, ip->lport, r->i2c_address, r->offset + done, r->page,
			      set_page, r->data + done, n);
      if (rv != VNET_DEV_OK)
	{
	  log_debug (port->dev, "port %u EEPROM read failed at off %u after %u/%u bytes: %U",
		     port->port_id, r->offset + done, done, r->length, format_vnet_dev_rv, rv);
	  return rv;
	}
    }

  log_debug (port->dev, "port %u EEPROM read complete: %u bytes", port->port_id, r->length);
  return VNET_DEV_OK;
}
