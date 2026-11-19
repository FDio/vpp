/* SPDX-License-Identifier: Apache-2.0 */
#include <inline_funcs.h>

VLIB_REGISTER_LOG_CLASS (vnp_log, static) = {
  .class_name = "virtio-net-pci",
  .subclass_name = "port",
};

static void
vnp_rx_handler (vlib_main_t *vm __clib_unused, vnet_dev_t *dev, u16 line)
{
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);

  if (port && port->started && port->rx_node_assigned && line > 0)
    vlib_node_set_interrupt_pending (vlib_get_main_by_index (line - 1),
				     vnet_dev_get_port_rx_node_index (port));
}

static void
vnp_intx_handler (vlib_main_t *vm __clib_unused, vnet_dev_t *dev)
{
  vnp_dev_t *vd = vnet_dev_get_data (dev);
  u8 status = vnp_reg_rd8 (vd->isr);
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);

  if (port && port->started && port->rx_node_assigned && (status & VIRTIO_PCI_ISR_INTR))
    foreach_vnet_dev_port_rx_queue (rxq, port)
      if (rxq->interrupt_mode)
	vlib_node_set_interrupt_pending (vlib_get_main_by_index (rxq->rx_thread_index),
					 vnet_dev_get_port_rx_node_index (port));
}

vnet_dev_rv_t
vnp_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnp_port_t *vp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  if (!port->attr.caps.interrupt_mode)
    return VNET_DEV_OK;

  if (vnet_dev_get_pci_n_msix_interrupts (port->dev) < vlib_get_n_threads () + 1)
    {
      clib_error_t *err;

      rv = vnet_dev_pci_intx_add_handler (vm, port->dev, vnp_intx_handler);
      if (rv)
	return rv;

      vp->irq_registered = vp->use_intx = 1;
      err = vlib_pci_intr_enable (vm, vnet_dev_get_pci_handle (port->dev));
      if (err)
	{
	  clib_error_free (err);
	  return VNET_DEV_ERR_BUS;
	}

      return VNET_DEV_OK;
    }

  rv = vnet_dev_pci_msix_add_handler (vm, port->dev, vnp_rx_handler, 1, vlib_get_n_threads ());
  if (rv)
    return rv;

  vp->irq_registered = 1;
  rv = vnet_dev_pci_msix_enable (vm, port->dev, 1, vlib_get_n_threads ());
  if (rv)
    return rv;

  for (u16 i = 0; i < vlib_get_n_threads (); i++)
    vnet_dev_pci_msix_set_polling_thread (vm, port->dev, i + 1, i);

  return VNET_DEV_OK;
}

void
vnp_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnp_port_t *vp = vnet_dev_get_port_data (port);

  if (vp->irq_registered)
    {
      if (vp->use_intx)
	{
	  clib_error_t *err = vlib_pci_intr_disable (vm, vnet_dev_get_pci_handle (port->dev));
	  if (err)
	    clib_error_free (err);

	  vnet_dev_pci_intx_remove_handler (vm, port->dev);
	  vp->use_intx = 0;
	}
      else
	{
	  vnet_dev_pci_msix_disable (vm, port->dev, 1, vlib_get_n_threads ());
	  vnet_dev_pci_msix_remove_handler (vm, port->dev, 1, vlib_get_n_threads ());
	}

      vp->irq_registered = 0;
    }
}

static void
vnp_port_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnp_dev_t *vd = vnet_dev_get_data (port->dev);
  u8 up = 1;
  vnet_dev_port_state_changes_t changes = {};

  if (vd->features & VIRTIO_NET_F_STATUS_BIT)
    up = vnp_reg_rd16 (&vd->config->status) & VIRTIO_NET_S_LINK_UP;

  if (vnp_reg_rd8 (&vd->common->status) &
      (VIRTIO_CONFIG_STATUS_NEEDS_RESET | VIRTIO_CONFIG_STATUS_FAILED))
    up = 0;

  if (up != port->link_up)
    {
      log_debug (port->dev, "link %s", up ? "up" : "down");
      changes.change.link_state = 1;
      changes.link_state = up;
      vnet_dev_port_state_change (vm, port, changes);
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      vnp_txq_t *q = vnet_dev_get_tx_queue_data (txq);
      u32 invalid;

      vnet_dev_tx_queue_lock_if_needed (txq);
      invalid = vnp_txq_reclaim (vm, q, txq->size);
      vnet_dev_tx_queue_unlock_if_needed (txq);

      if (invalid)
	vlib_error_count (vm, port->interfaces->primary_interface.tx_node_index, VNP_TX_COMPLETION,
			  invalid);
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      vnp_rxq_t *q = vnet_dev_get_rx_queue_data (rxq);

      if (rxq->interrupt_mode && q->n_free)
	vlib_node_set_interrupt_pending (vlib_get_main_by_index (rxq->rx_thread_index),
					 vnet_dev_get_port_rx_node_index (port));
    }
}

vnet_dev_rv_t
vnp_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnp_dev_t *vd = vnet_dev_get_data (port->dev);
  vnp_port_t *vp = vnet_dev_get_port_data (port);
  u16 n_rx = 0, n_tx = 0;
  vnet_dev_rv_t rv = vnp_negotiate (vm, port->dev);

  if (rv)
    return rv;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    vnp_rxq_release (vm, vnet_dev_get_rx_queue_data (rxq), rxq->size);

  foreach_vnet_dev_port_tx_queue (txq, port)
    vnp_txq_release (vm, vnet_dev_get_tx_queue_data (txq), txq->size);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    n_rx++;

  foreach_vnet_dev_port_tx_queue (txq, port)
    n_tx++;

  if (n_rx != n_tx || !n_rx)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  if (vd->control.size)
    {
      rv = vnp_ctlq_start (vm, port->dev, &vd->control);
      if (rv)
	goto error;
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      vnp_rxq_t *q = vnet_dev_get_rx_queue_data (rxq);
      u16 desc_len;

      if (!(vd->features & VIRTIO_NET_F_MRG_RXBUF_BIT) &&
	  vnet_dev_get_rx_queue_buffer_data_size (vm, rxq) <
	    port->max_rx_frame_size - VNET_DEV_ETH_FCS_LEN)
	{
	  rv = VNET_DEV_ERR_NOT_SUPPORTED;
	  goto error;
	}

      desc_len = clib_min (vnet_dev_get_rx_queue_buffer_data_size (vm, rxq) + VIRTIO_NET_HDR_V1_SZ,
			   CLIB_U16_MAX);
      rv = vnp_rxq_start (vm, port->dev, q, rxq->size, desc_len);
      if (rv)
	goto error;

      q->max_len = port->max_rx_frame_size - VNET_DEV_ETH_FCS_LEN;

      if (port->attr.caps.interrupt_mode && !vp->use_intx)
	{
	  vnp_reg_wr16 (&vd->common->queue_msix_vector, (rxq->rx_thread_index + 1));

	  if (vnp_reg_rd16 (&vd->common->queue_msix_vector) == 0xffff)
	    {
	      rv = VNET_DEV_ERR_NOT_SUPPORTED;
	      goto error;
	    }
	}
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      rv = vnp_txq_start (vm, port->dev, vnet_dev_get_tx_queue_data (txq), txq->size);
      if (rv)
	goto error;
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      vnp_rxq_t *q = vnet_dev_get_rx_queue_data (rxq);

      do
	{
	  if (vnp_rxq_refill (vm, rxq))
	    {
	      rv = VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
	      goto error;
	    }
	}
      while (q->n_free);
    }

  vnp_reg_wr8 (&vd->common->status,
	       vnp_reg_rd8 (&vd->common->status) | VIRTIO_CONFIG_STATUS_DRIVER_OK);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    vnp_rxq_publish (vnet_dev_get_rx_queue_data (rxq), rxq->size);

  if (vd->control.size)
    {
      if (vd->features & VIRTIO_NET_F_MQ_BIT)
	{
	  rv = vnp_rss (vm, port, &port->rss_config);
	  if (rv)
	    goto error;
	}

      rv = vnp_filters (vm, port);
      if (rv)
	goto error;
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    vnp_rxq_irq (vm, rxq, rxq->interrupt_mode);

  vnet_dev_poll_port_add (vm, port, 0.5, vnp_port_poll);
  return VNET_DEV_OK;

error:
  if (vnp_reset (vm, port->dev) == VNET_DEV_OK)
    {
      foreach_vnet_dev_port_rx_queue (rxq, port)
	vnp_rxq_release (vm, vnet_dev_get_rx_queue_data (rxq), rxq->size);

      foreach_vnet_dev_port_tx_queue (txq, port)
	vnp_txq_release (vm, vnet_dev_get_tx_queue_data (txq), txq->size);
    }

  return rv;
}

void
vnp_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_poll_port_remove (vm, port, vnp_port_poll);

  if (vnp_reset (vm, port->dev) != VNET_DEV_OK)
    {
      /* the device may still own the buffers, they are released at next start */
      log_err (port->dev, "device reset timeout");
      return;
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    vnp_rxq_release (vm, vnet_dev_get_rx_queue_data (rxq), rxq->size);

  foreach_vnet_dev_port_tx_queue (txq, port)
    vnp_txq_release (vm, vnet_dev_get_tx_queue_data (txq), txq->size);
}

vnet_dev_rv_t
vnp_port_cfg_validate (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
		       vnet_dev_port_cfg_change_req_t *req)
{
  vnp_dev_t *vd = vnet_dev_get_data (port->dev);
  vnp_port_t *vp = vnet_dev_get_port_data (port);

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      return port->attr.caps.interrupt_mode ? VNET_DEV_OK : VNET_DEV_ERR_NOT_SUPPORTED;
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      return port->started ? VNET_DEV_ERR_PORT_STARTED : VNET_DEV_OK;
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      if ((vd->features & VIRTIO_NET_F_CTRL_RX_BIT) &&
	  (vd->features & VIRTIO_NET_F_CTRL_MAC_ADDR_BIT))
	return VNET_DEV_OK;

      return VNET_DEV_ERR_NOT_SUPPORTED;
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      return vd->features & VIRTIO_NET_F_CTRL_RX_BIT ? VNET_DEV_OK : VNET_DEV_ERR_NOT_SUPPORTED;
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      if (!(vd->features & VIRTIO_NET_F_CTRL_RX_BIT))
	return VNET_DEV_ERR_NOT_SUPPORTED;

      if (req->type == VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR && vp->n_macs == 64)
	return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;

      return VNET_DEV_OK;
    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      if (!(vd->features & VIRTIO_NET_F_RSS_BIT) ||
	  (req->rss_config.set_key && req->rss_config.key_len != 40) ||
	  (req->rss_config.set_lut &&
	   (!is_pow2 (req->rss_config.lut_len) || req->rss_config.lut_len > 128 ||
	    req->rss_config.lut_len > vd->config->rss_max_indirection_table_length)))
	return VNET_DEV_ERR_NOT_SUPPORTED;

      if (req->rss_config.set_lut)
	for (u32 i = 0; i < req->rss_config.lut_len; i++)
	  if (!vnet_dev_get_port_rx_queue_by_id (port, req->rss_config.lut[i]))
	    return VNET_DEV_ERR_INVALID_VALUE;

      return VNET_DEV_OK;
    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
}

vnet_dev_rv_t
vnp_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req)
{
  vnp_port_t *vp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      if (port->started)
	foreach_vnet_dev_port_rx_queue (rxq, port)
	  if (req->all_queues || rxq->queue_id == req->queue_id)
	    vnp_rxq_irq (vm, rxq, req->type == VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE);

      return VNET_DEV_OK;
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      return VNET_DEV_OK;
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      if (port->started)
	rv = vnp_control (vm, port->dev, VIRTIO_NET_CTRL_MAC, VIRTIO_NET_CTRL_MAC_ADDR_SET,
			  req->addr.eth_mac, 6);

      return rv;
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      if (port->started)
	{
	  u8 enabled = req->promisc;
	  rv = vnp_control (vm, port->dev, VIRTIO_NET_CTRL_RX, VIRTIO_NET_CTRL_RX_PROMISC, &enabled,
			    1);
	}

      return rv;
    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      if (port->started)
	{
	  vnet_dev_rss_config_t config = port->rss_config;

	  if (req->rss_config.set_key)
	    {
	      clib_memcpy_fast (config.key, req->rss_config.key, 40);
	      config.set_key = 1;
	    }

	  if (req->rss_config.set_lut)
	    {
	      config.lut_len = req->rss_config.lut_len;
	      clib_memcpy_fast (config.lut, req->rss_config.lut,
				config.lut_len * sizeof (config.lut[0]));
	      config.set_lut = 1;
	    }

	  rv = vnp_rss (vm, port, &config);
	}

      return rv;
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      clib_memcpy_fast (vp->macs[vp->n_macs++], req->addr.eth_mac, 6);

      if (port->started)
	rv = vnp_filters (vm, port);

      if (rv)
	vp->n_macs--;

      return rv;
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      for (u32 i = 0; i < vp->n_macs; i++)
	if (ethernet_mac_address_equal (vp->macs[i], req->addr.eth_mac))
	  {
	    u8 saved[6];
	    clib_memcpy_fast (saved, vp->macs[i], 6);
	    clib_memcpy_fast (vp->macs[i], vp->macs[--vp->n_macs], 6);

	    if (port->started)
	      rv = vnp_filters (vm, port);

	    if (rv)
	      {
		clib_memcpy_fast (vp->macs[vp->n_macs++], vp->macs[i], 6);
		clib_memcpy_fast (vp->macs[i], saved, 6);
	      }

	    return rv;
	  }

      return VNET_DEV_ERR_INVALID_VALUE;
    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
}
