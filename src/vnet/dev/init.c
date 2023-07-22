/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/interface/rx_queue_funcs.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "init",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

vnet_dev_main_t vnet_dev_main;

static void *
_vnet_dev_alloc_with_data (u32 sz, u32 data_sz)
{
  void *p;
  sz += data_sz;
  sz = round_pow2 (sz, CLIB_CACHE_LINE_BYTES);
  p = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  clib_memset (p, 0, sz);
  return p;
}

static void
_vnet_dev_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  if (dev->initialized)
    {
      vnet_dev_process_quit (vm, dev);
      if (dev->ops.device_free)
	dev->ops.device_free (vm, dev);
    }

  if (dev->pci.handle != ~0)
    vlib_pci_device_close (vm, dev->pci.handle);

  vec_free (dev->name);
  vec_free (dev->description);
  pool_free (dev->ports);
  pool_free (dev->periodic_ops);
  pool_put_index (pool_elt_at_index (dm->drivers, dev->driver_index)->devices,
		  dev->index);
}

vnet_dev_rv_t
vnet_dev_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_t *dev = port->dev;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_dev_driver_t *driver =
    pool_elt_at_index (dm->drivers, dev->driver_index);

  if (port->type == VNET_DEV_PORT_TYPE_ETHERNET)
    {
      vnet_sw_interface_t *sw;
      vlib_node_registration_t rx_node_reg = {
	.sibling_of = "device-input",
	.type = VLIB_NODE_TYPE_INPUT,
	.state = VLIB_NODE_STATE_DISABLED,
	.flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
	.node_fn_registrations = port->ops.rx_node_fn->registrations,
      };

      vnet_eth_interface_registration_t eir = {
	.address = port->hw_addr,
	.max_frame_size = 1514,
	.dev_instance = port->dev_instance,
	.dev_class_index = driver->dev_class_index,
      };

      port->rx_node_index = vlib_register_node (
	vm, &rx_node_reg, "%v-port-%u-rx", dev->name, port->port_id);

      ethernet_main_t *em = &ethernet_main;
      ethernet_interface_t *ei;
      pool_get (em->interfaces, ei);
      clib_memcpy (&ei->cb, &eir.cb, sizeof (vnet_eth_if_callbacks_t));
      port->hw_if_index = vnet_register_interface (
	vnm, driver->dev_class_index, port->dev_instance,
	ethernet_hw_interface_class.index, ei - em->interfaces);
      sw = vnet_get_hw_sw_interface (vnm, port->hw_if_index);
      port->sw_if_index = sw->sw_if_index;
      vlib_worker_thread_node_runtime_update ();
    }
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_attach (vlib_main_t *vm, vnet_dev_attach_args_t args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vlib_pci_device_info_t *di = 0;
  vnet_dev_t *dev = 0, **devp = 0;
  vnet_dev_driver_t *driver;
  vnet_dev_driver_registration_t *r;
  vnet_dev_match_t *i;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  clib_error_t *err = 0;
  u32 index;

  di = vlib_pci_get_device_info (vm, &args.pci_addr, &err);
  if (err)
    {
      err = vnet_error (VNET_ERR_UNSUPPORTED, "unable to get device info: %U",
			format_clib_error, err);
      log_err (dev, "pci_get_device_info: %u", format_clib_error, err);
      clib_error_free (err);
      rv = VNET_DEV_ERR_PCI;
      goto done;
    }

  vec_foreach (driver, dm->drivers)
    {
      r = driver->registration;
      for (i = r->match; i->device_id != 0 && i->vendor_id != 0; i++)
	if (i->device_id == di->device_id && i->vendor_id == di->vendor_id)
	  goto found;
    }

  log_err (dev, "driver not available");
  rv = VNET_DEV_ERR_DRIVER_NOT_AVAILABLE;
  goto done;

found:

  dev = _vnet_dev_alloc_with_data (sizeof (vnet_dev_t), r->device_data_sz);
  pool_get (driver->devices, devp);
  devp[0] = dev;
  dev->index = devp - driver->devices;
  dev->bus_type = args.bus_type;
  dev->pci.addr = args.pci_addr;
  dev->pci.handle = ~0;
  dev->ops = r->ops;
  dev->driver_index = driver->index;
  dev->name =
    format (0, "%s-%U", r->name, format_vlib_pci_addr, &dev->pci.addr);
  dev->description = format (0, "%s", i->description);

  log_debug (dev, "found '%s' device %04x:%04x rev 0x%02x bound to '%s'",
	     i->description, di->vendor_id, di->device_id, di->revision,
	     di->driver_name);

  if ((err = vlib_pci_device_open (vm, &args.pci_addr, 0, &dev->pci.handle)))
    {
      log_err (dev, "pci_device_open: %U", format_clib_error, err);
      rv = VNET_DEV_ERR_PCI;
      goto done;
    }

  dev->numa_node = vlib_pci_get_numa_node (vm, dev->pci.handle);

  if (vlib_pci_supports_virtual_addr_dma (vm, dev->pci.handle))
    {
      dev->va_dma = 1;
      log_debug (dev, "device supports VA DMA");
    }

  if (r->bus_master_enable)
    {
      if ((err = vlib_pci_bus_master_enable (vm, dev->pci.handle)))
	{
	  log_err (dev, "pci_bus_master_enable: %U", format_clib_error, err);
	  rv = VNET_DEV_ERR_PCI;
	  goto done;
	}
      log_debug (dev, "bus master enabled");
    }

  if ((rv = vnet_dev_process_create (vm, dev)))
    goto done;

  if (dev->ops.device_init)
    if ((rv = r->ops.device_init (vm, dev)))
      {
	log_err (dev, "device init failed [rv %d]", rv);
	goto done;
      }
  dev->initialized = 1;

  pool_foreach_index (index, dev->ports)
    {
      vnet_dev_port_t *port = pool_elt_at_index (dev->ports, index)[0];
      rv = vnet_dev_port_init (vm, port);
      if (rv != VNET_DEV_OK)
	goto done;
    }

done:
  if (di)
    vlib_pci_free_device_info (di);

  if (err)
    clib_error_free (err);

  if (rv != VNET_DEV_OK)
    {
      if (dev)
	_vnet_dev_free (vm, dev);
    }

  return rv;
}

vnet_dev_rv_t
vnet_dev_detach (vlib_main_t *vm, u32 dev_inst)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_if_t *intf = pool_elt_at_index (dm->interfaces, dev_inst);
  vnet_dev_driver_t *dr = pool_elt_at_index (dm->drivers, intf->driver_index);
  vnet_dev_t *dev = pool_elt_at_index (dr->devices, intf->dev_index)[0];
  log_debug (dev, "detach");
  _vnet_dev_free (vm, dev);
  return VNET_DEV_OK;
}

void
vnet_dev_rx_queue_remove (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;
  log_debug (dev, "rx_queue_remove: queue %u", rxq->queue_id);
  if (port->ops.rx_queue_free)
    port->ops.rx_queue_free (vm, rxq);
  pool_put_index (port->rx_queues, rxq->index);
}

vnet_dev_rv_t
vnet_dev_rx_queue_add (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rx_queue_t *rxq, **qp;
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (dev, "rx_queue_add: port %u", port->port_id);

  rxq = _vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t),
				   port->rx_queue_data_sz);
  pool_get (port->rx_queues, qp);
  qp[0] = rxq;
  rxq->port = port;
  rxq->n_desc = 512;
  rxq->index = qp - port->rx_queues;
  rxq->rx_thread_index = 1;
  rxq->buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, dev->numa_node);

  if (port->ops.rx_queue_alloc)
    rv = port->ops.rx_queue_alloc (vm, rxq);

  if (rv != VNET_DEV_OK)
    vnet_dev_rx_queue_remove (vm, rxq);

  return rv;
}

void
vnet_dev_tx_queue_remove (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;
  log_debug (dev, "tx_queue_remove: queue %u", txq->queue_id);
  if (port->ops.tx_queue_free)
    port->ops.tx_queue_free (vm, txq);
  pool_put_index (port->tx_queues, txq->index);
}

vnet_dev_rv_t
vnet_dev_tx_queue_add (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_tx_queue_t *txq, **qp;
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (dev, "tx_queue_add: port %u", port->port_id);

  txq = _vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t),
				   port->tx_queue_data_sz);
  pool_get (port->tx_queues, qp);
  qp[0] = txq;
  txq->port = port;
  txq->n_desc = 512;
  txq->index = qp - port->tx_queues;
  if (port->ops.tx_queue_alloc)
    rv = port->ops.tx_queue_alloc (vm, txq);

  if (rv != VNET_DEV_OK)
    vnet_dev_tx_queue_remove (vm, txq);

  return rv;
}

void
vnet_dev_port_remove (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  u32 i;
  log_debug (dev, "port_remove: port %u", port->port_id);
  pool_foreach_index (i, port->tx_queues)
    vnet_dev_tx_queue_remove (vm, port->tx_queues[i]);
  pool_foreach_index (i, port->rx_queues)
    vnet_dev_rx_queue_remove (vm, port->rx_queues[i]);
  pool_free (port->rx_queues);
  pool_free (port->tx_queues);
  if (port->ops.free)
    port->ops.free (vm, port);
  pool_put_index (dev->ports, port->index);
  clib_mem_free (port);
}

vnet_dev_rv_t
vnet_dev_port_add (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_port_id_t id,
		   vnet_dev_port_add_args_t args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_port_t **pp, *port;
  vnet_dev_if_t *intf;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  ASSERT (args.type != VNET_DEV_PORT_TYPE_UNKNOWN);

  port = _vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t), args.data_sz);
  pool_get (dev->ports, pp);
  pp[0] = port;
  port->port_id = id;
  port->index = pp - dev->ports;
  port->dev = dev;
  port->type = args.type;
  port->max_rx_queues = args.max_rx_queues ? args.max_rx_queues : 1;
  port->max_tx_queues = args.max_tx_queues ? args.max_tx_queues : 1;
  port->ops = args.ops;
  port->rx_queue_data_sz = args.rx_queue_data_sz;
  port->tx_queue_data_sz = args.tx_queue_data_sz;
  ASSERT (args.max_frame_size);
  port->max_frame_size = args.max_frame_size;
  clib_memcpy (port->hw_addr, args.hw_addr, sizeof (port->hw_addr));

  pool_get (dm->interfaces, intf);
  port->dev_instance = intf - dm->interfaces;
  intf->driver_index = port->dev->driver_index;
  intf->dev_index = port->dev->index;
  intf->port_index = pp - port->dev->ports;

  vnet_dev_rx_queue_add (vm, port);
  vnet_dev_tx_queue_add (vm, port);

  if (port->ops.init)
    rv = port->ops.init (vm, port);
  if (rv != VNET_DEV_OK)
    vnet_dev_port_remove (vm, port);
  return rv;
}

vnet_dev_rv_t
vnet_dev_port_start_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  int start;
  u32 i;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  if (port->started == 0 && port->admin_up && port->link_up)
    start = 1;
  else if (port->started == 1 && (port->admin_up == 0 || port->link_up == 0))
    start = 0;
  else
    {
      log_debug (dev, "port_start_stop: no change");
      return VNET_DEV_OK;
    }

  if (start)
    {
      log_debug (dev, "port_start_stop: starting port %u", port->port_id);
      if ((rv = port->ops.start (vm, port)) != VNET_DEV_OK)
	goto stop;

      pool_foreach_index (i, port->rx_queues)
	{
	  vnet_dev_rx_queue_t *rxq = *pool_elt_at_index (port->rx_queues, i);
	  vnet_dev_mgmt_op_t op = {
	    .action = VNET_DEV_MGMT_OP_ACTION_RX_QUEUE_ASSIGN,
	    .rx_queue = rxq,
	    .thread_index = rxq->rx_thread_index,
	  };
	  vnet_dev_mgmt_add_action (vm, &op, 1);
	  rxq->started = 1;
	}
      port->started = 1;
    }
  else
    {
    stop:
      log_debug (dev, "port_start_stop: stopping port %u", port->port_id);
      port->ops.stop (vm, port);
      pool_foreach_index (i, port->rx_queues)
	{
	  vnet_dev_rx_queue_t *rxq = *pool_elt_at_index (port->rx_queues, i);
	  vnet_dev_mgmt_op_t op = {
	    .action = VNET_DEV_MGMT_OP_ACTION_RX_QUEUE_UNASSIGN,
	    .rx_queue = rxq,
	    .thread_index = rxq->rx_thread_index,
	  };
	  vnet_dev_mgmt_add_action (vm, &op, 1);
	  rxq->started = 0;
	}
      port->started = 0;
    }
  return rv;
}

vnet_dev_rv_t
vnet_dev_port_config_change (vlib_main_t *vm, vnet_dev_port_t *port,
			     vnet_dev_port_config_changes_t changes)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  int start_stop = 0;

  if (port->ops.config_change)
    rv = port->ops.config_change (vm, port);

  if (rv != VNET_DEV_OK)
    return rv;

  if (changes.change.admin_state)
    {
      ASSERT (changes.admin_state != port->admin_up);
      port->admin_up = changes.admin_state;
      log_debug (dev, "port %u admin state changed to %s", port->port_id,
		 port->admin_up ? "up" : "down");
      start_stop = 1;
    }

  if (start_stop)
    vnet_dev_port_start_stop (vm, port);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_dma_mem_alloc (vlib_main_t *vm, vnet_dev_t *dev, u32 size, u32 align,
			void **pp)
{
  clib_error_t *err;
  void *p;

  align = align ? align : CLIB_CACHE_LINE_BYTES;
  size = round_pow2 (size, align);

  p = vlib_physmem_alloc_aligned_on_numa (vm, size, align, dev->numa_node);

  if (p == 0)
    {
      err = vlib_physmem_last_error (vm);
      log_err (dev, "dev_dma_mem_alloc: physmem_alloc_aligned error %U",
	       format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_PHYSMEM_ALLOC;
    }

  if (dev->bus_type == VNET_DEV_BUS_TYPE_PCIE)
    if ((err = vlib_pci_map_dma (vm, dev->pci.handle, p)))
      {
	log_err (dev, "dev_dma_mem_alloc: pci_map_dma: %U", format_clib_error,
		 err);
	clib_error_free (err);
	return VNET_DEV_ERR_PHYSMEM_ALLOC;
      }

  clib_memset (p, 0, size);
  pp[0] = p;
  log_debug (dev,
	     "dev_physmem_alloc: %u bytes of physmem allocated on numa %u at "
	     "address %p, aligned at %u",
	     size, dev->numa_node, p, align);
  return VNET_DEV_OK;
}

void
vnet_dev_dma_mem_free (vlib_main_t *vm, vnet_dev_t *dev, void *p)
{
  if (p)
    vlib_physmem_free (vm, p);
  log_debug (dev, "dev_physmem_free: %p", p);
}

void
vnet_dev_port_state_change (vlib_main_t *vm, vnet_dev_port_t *port,
			    vnet_dev_port_state_changes_t changes)
{
  vnet_main_t *vnm = vnet_get_main ();
  int port_start_stop = 1;
  if (changes.change.link_speed)
    {
      vnet_hw_interface_set_link_speed (vnm, port->hw_if_index,
					changes.link_speed);
      log_debug (port->dev, "port speed changed to %u", changes.link_speed);
    }
  if (changes.change.link_state)
    {
      vnet_hw_interface_set_flags (
	vnm, port->hw_if_index,
	changes.link_state ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
      log_debug (port->dev, "port link state changed to %s",
		 changes.link_state ? "up" : "down");
      port->link_up = changes.change.link_state;
    }

  if (port_start_stop)
    vnet_dev_port_start_stop (vm, port);
}

clib_error_t *
vnet_dev_init (vlib_main_t *vm)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  for (vnet_dev_driver_registration_t *r = dm->registrations; r;
       r = r->next_registration)
    {
      vnet_dev_driver_t *driver;
      vnet_device_class_t *dev_class;
      clib_error_t *vnet_dev_admin_up_down_fn (vnet_main_t *, u32, u32);

      pool_get_zero (dm->drivers, driver);
      driver->registration = r;
      driver->index = driver - dm->drivers;
      dev_class = clib_mem_alloc (sizeof (vnet_device_class_t));
      *dev_class = (vnet_device_class_t){
	.name = r->name,
	.format_device_name = format_vnet_dev_interface_name,
	.format_device = format_vnet_dev_interface_info,
	.admin_up_down_function = vnet_dev_admin_up_down_fn,
      };
      driver->dev_class_index = vnet_register_device_class (vm, dev_class);
      log_debug (0, "driver '%s' registered", r->name);
    }
  return 0;
}

VLIB_INIT_FUNCTION (vnet_dev_init);
