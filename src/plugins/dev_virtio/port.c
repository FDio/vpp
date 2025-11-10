/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <dev_virtio/virtio.h>
#include <dev_virtio/pci.h>

VLIB_REGISTER_LOG_CLASS (virtio_log, static) = {
  .class_name = "virtio",
  .subclass_name = "port",
};

void
virtio_msix_n_handler (vlib_main_t *vm, vnet_dev_t *dev, u16 line)
{
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);

  if (port->interfaces == 0)
    {
      log_warning (dev, "port %u not ready", port->port_id);
      return;
    }
  vlib_node_set_interrupt_pending (vlib_get_main_by_index (line),
				   vnet_dev_get_port_rx_node_index (port));
}

static void
virtio_port_status_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  virtio_if_t *vif = virtio_vnet_dev_get_if (dev);
  vnet_dev_port_state_changes_t changes = {};

  if (virtio_pci_is_link_up (vm, vif) & VIRTIO_NET_S_LINK_UP)
    {
      changes.change.link_state = 1;
      changes.link_state = 1;
      vnet_dev_port_state_change (vm, port, changes);
    }
  else
    {
      changes.change.link_state = 1;
      changes.link_state = 0;
      vnet_dev_port_state_change (vm, port, changes);
    }
}

static void
virtio_set_rx_interrupt (virtio_if_t *vif, vnet_virtio_vring_t *vring)
{
  vring->mode = VNET_HW_IF_RX_MODE_INTERRUPT;
  if (vif->is_packed)
    vring->driver_event->flags &= ~VRING_EVENT_F_DISABLE;
  else
    vring->avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
}

static void
virtio_set_rx_polling (virtio_if_t *vif, vnet_virtio_vring_t *vring)
{
  vring->mode = VNET_HW_IF_RX_MODE_POLLING;
  if (vif->is_packed)
    vring->driver_event->flags |= VRING_EVENT_F_DISABLE;
  else
    vring->avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
}

vnet_dev_rv_t
virtio_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  virtio_if_t *vif = virtio_vnet_dev_get_if (dev);

  log_debug (dev, "port %u", port->port_id);

  vif->hw_if_index = port->interfaces->primary_interface.hw_if_index;
  vif->sw_if_index = port->interfaces->primary_interface.sw_if_index;

  for (u32 i = 1; i < vif->n_rx_vectors; i++)
    vnet_dev_pci_msix_set_polling_thread (vm, dev, i + 1, i);

  vnet_dev_poll_port_add (vm, port, 1, virtio_port_status_poll);

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
virtio_enable_disable_queues (vlib_main_t *vm, vnet_dev_port_t *port,
			      int enable)
{
  return VNET_DEV_OK;
}

vnet_dev_rv_t
virtio_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv;
  vnet_dev_t *dev = port->dev;
  virtio_if_t *vif = virtio_vnet_dev_get_if (dev);

  log_debug (dev, "port %u", port->port_id);

  if (virtio_pci_port_start (vm, vif, port))
    return VNET_DEV_ERR_DEVICE_NO_REPLY;

  if (vif->packet_buffering)
    {
      virtio_pre_input_node_enable (vm, vif);
      foreach_vnet_dev_port_tx_queue (txq, port)
	{
	  if (virtio_set_packet_buffering (txq, vif->buffering_size))
	    {
	      log_error (dev,
			 "error encountered during packet buffering init");
	      return VNET_DEV_ERR_INTERNAL;
	    }
	}
    }

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      virtio_rxq_t *vrq = vnet_dev_get_rx_queue_data (q);
      vnet_virtio_vring_t *vring = &vrq->vring;

      if (q->interrupt_mode)
	virtio_set_rx_interrupt (vif, vring);
      else
	virtio_set_rx_polling (vif, vring);
    }

  if ((rv = virtio_enable_disable_queues (vm, port, 1)))
    goto done;

  vif->virtio_pci_func->set_status (vm, vif, VIRTIO_CONFIG_STATUS_DRIVER_OK);
  vif->status = vif->virtio_pci_func->get_status (vm, vif);

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      if ((rv = virtio_rx_queue_start (vm, q)))
	goto done;

  foreach_vnet_dev_port_tx_queue (q, port)
    if ((rv = virtio_tx_queue_start (vm, q)))
      goto done;

  virtio_pci_offloads (vm, vif, vif->gso_enabled, vif->csum_offload_enabled);

  if ((vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ)) &&
      (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MQ)))
    {
      if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_RSS))
	{
	  if (virtio_pci_enable_multiqueue_rss (vm, vif, vif->max_queue_pairs))
	    log_warning (dev, "multiqueue with rss is not set");
	}
      else
	{
	  if (virtio_pci_enable_multiqueue (vm, vif, vif->max_queue_pairs))
	    log_warning (dev, "multiqueue is not set");
	}
    }

done:
  if (rv)
    {
      foreach_vnet_dev_port_rx_queue (q, port)
	virtio_rx_queue_stop (vm, q);
      foreach_vnet_dev_port_tx_queue (q, port)
	virtio_tx_queue_stop (vm, q);
    }
  return rv;
}

void
virtio_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "port %u", port->port_id);

  virtio_enable_disable_queues (vm, port, 0);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    virtio_rx_queue_stop (vm, rxq);

  foreach_vnet_dev_port_tx_queue (txq, port)
    virtio_tx_queue_stop (vm, txq);

  vnet_dev_port_state_change (vm, port,
			      (vnet_dev_port_state_changes_t){
				.change.link_state = 1,
				.change.link_speed = 1,
				.link_speed = 0,
				.link_state = 0,
			      });
}

vnet_dev_rv_t
virtio_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
				 vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  return rv;
}

vnet_dev_rv_t
virtio_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
			vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
  virtio_if_t *vif = virtio_vnet_dev_get_if (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  virtio_rxq_t *vrq;
  vnet_virtio_vring_t *vring;
  u8 enable = 0;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
      enable = 1;
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      if (req->all_queues)
	{
	  foreach_vnet_dev_port_rx_queue (q, port)
	    {
	      vrq = vnet_dev_get_rx_queue_data (q);
	      vring = &vrq->vring;
	      if (enable)
		virtio_set_rx_interrupt (vif, vring);
	      else
		virtio_set_rx_polling (vif, vring);
	    }
	}
      else
	{
	  vnet_dev_rx_queue_t *rxq =
	    vnet_dev_get_port_rx_queue_by_id (port, req->queue_id);

	  if (rxq == 0)
	    return VNET_DEV_ERR_BUG;
	  vrq = vnet_dev_get_rx_queue_data (rxq);
	  vring = &vrq->vring;
	  if (enable)
	    virtio_set_rx_interrupt (vif, vring);
	  else
	    virtio_set_rx_polling (vif, vring);
	}
      break;
    default:
      break;
    }
  return rv;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
