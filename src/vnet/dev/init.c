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

clib_error_t *
vnet_dev_attach (vlib_main_t *vm, vnet_dev_attach_args_t args)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_dev_main_t *dm = &vnet_dev_main;
  vlib_pci_device_info_t *di = 0;
  vnet_dev_t *dev = 0, **devp = 0;
  vnet_dev_driver_t *driver;
  vnet_dev_driver_registration_t *r;
  vnet_dev_match_t *i;
  vnet_dev_rv_t rv;
  clib_error_t *err = 0, *pci_err = 0;
  u32 index;

  di = vlib_pci_get_device_info (vm, &args.pci_addr, &pci_err);
  if (pci_err)
    {
      err = vnet_error (VNET_ERR_UNSUPPORTED, "unable to get device info: %U",
			format_clib_error, pci_err);
      goto done;
    }

  vec_foreach (driver, dm->drivers)
    {
      r = driver->registration;
      for (i = r->match; i->device_id != 0 && i->vendor_id != 0; i++)
	if (i->device_id == di->device_id && i->vendor_id == di->vendor_id)
	  goto found;
    }

  err = vnet_error (VNET_ERR_UNSUPPORTED, "driver not available");
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

  pci_err = vlib_pci_device_open (vm, &args.pci_addr, 0, &dev->pci.handle);
  if (pci_err)
    {
      err = vnet_error (VNET_ERR_BUG, "PCI device open error: %U",
			format_clib_error, pci_err);
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
      if ((pci_err = vlib_pci_bus_master_enable (vm, dev->pci.handle)))
	{
	  err = vnet_error (VNET_ERR_BUG, "unable to enable bus mastering: %U",
			    format_clib_error, pci_err);
	  goto done;
	}
      log_debug (dev, "bus master enabled");
    }

  vnet_dev_process_create (vm, dev);

  if (dev->ops.device_init)
    if ((rv = r->ops.device_init (vm, dev)))
      {
	err =
	  vnet_error (VNET_ERR_INIT_FAILED, "device init failed [rv %d]", rv);
	goto done;
      }
  dev->initialized = 1;

  pool_foreach_index (index, dev->ports)
    {
      vnet_dev_port_t *port = pool_elt_at_index (dev->ports, index)[0];
      if (port->type == VNET_DEV_PORT_TYPE_ETHERNET)
	{
	  vnet_sw_interface_t *sw;
	  vlib_node_registration_t rx_node_reg = {
	    .sibling_of = "dev-input",
	    .type = VLIB_NODE_TYPE_INPUT,
	    .state = VLIB_NODE_STATE_DISABLED,
	    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
	    .function = dev->ops.rx_node_fn
	  };

	  vnet_eth_interface_registration_t eir = {
	    .address = port->hw_addr,
	    .max_frame_size = 1514,
	    .dev_instance = port->dev_instance,
	    .dev_class_index = driver->dev_class_index
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
    }

done:
  if (di)
    vlib_pci_free_device_info (di);

  if (err)
    {
      clib_error_free (pci_err);
      if (dev)
	{
	  log_err (dev, "dev_attach: err: %U", format_clib_error, err);
	  _vnet_dev_free (vm, dev);
	}
    }

  return err;
}

clib_error_t *
vnet_dev_detach (vlib_main_t *vm, u32 dev_inst)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_if_t *intf = pool_elt_at_index (dm->interfaces, dev_inst);
  vnet_dev_driver_t *dr = pool_elt_at_index (dm->drivers, intf->driver_index);
  vnet_dev_t *dev = pool_elt_at_index (dr->devices, intf->dev_index)[0];
  log_debug (dev, "detach");
  _vnet_dev_free (vm, dev);
  return 0;
}

void
vnet_dev_rx_queue_add (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rx_queue_t *rxq, **qp;
  vnet_dev_t *dev = port->dev;
  rxq = _vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t), 0);
  pool_get (port->rx_queues, qp);
  qp[0] = rxq;
  rxq->port = port;
  rxq->n_desc = 512;
  rxq->polling_thread_index = VNET_DEV_THREAD_NOT_ASSIGNED;
  if (dev->ops.rx_queue_alloc)
    dev->ops.rx_queue_alloc (vm, rxq);
}

void
vnet_dev_tx_queue_add (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_tx_queue_t *txq, **qp;
  vnet_dev_t *dev = port->dev;
  txq = _vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t), 0);
  pool_get (port->tx_queues, qp);
  qp[0] = txq;
  txq->port = port;
  txq->n_desc = 512;
  if (dev->ops.tx_queue_alloc)
    dev->ops.tx_queue_alloc (vm, txq);
}

void
vnet_dev_port_add (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_port_id_t id,
		   vnet_dev_port_add_args_t args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_port_t **pp, *port;
  vnet_dev_if_t *intf;

  ASSERT (args.type != VNET_DEV_PORT_TYPE_UNKNOWN);

  port = _vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t), args.data_sz);
  pool_get (dev->ports, pp);
  pp[0] = port;
  port->port_id = id;
  port->dev = dev;
  port->type = args.type;
  port->max_rx_queues = args.max_rx_queues ? args.max_rx_queues : 1;
  port->max_tx_queues = args.max_tx_queues ? args.max_tx_queues : 1;
  clib_memcpy (port->hw_addr, args.hw_addr, sizeof (port->hw_addr));

  pool_get (dm->interfaces, intf);
  port->dev_instance = intf - dm->interfaces;
  intf->driver_index = port->dev->driver_index;
  intf->dev_index = port->dev->index;
  intf->port_index = pp - port->dev->ports;

  vnet_dev_rx_queue_add (vm, port);
  vnet_dev_tx_queue_add (vm, port);

  if (dev->ops.port_init)
    dev->ops.port_init (vm, port);
}

void
vnet_dev_port_state_change (vlib_main_t *vm, vnet_dev_port_t *port,
			    vnet_dev_port_state_changes_t changes)
{
  vnet_main_t *vnm = vnet_get_main ();
  if (changes.link_speed_change)
    {
      vnet_hw_interface_set_link_speed (vnm, port->hw_if_index,
					changes.link_speed);
      log_debug (port->dev, "port speed changed to %u", changes.link_speed);
    }
  if (changes.link_state_change)
    {
      vnet_hw_interface_set_flags (
	vnm, port->hw_if_index,
	changes.link_state ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
      log_debug (port->dev, "port state changed to %s",
		 changes.link_state ? "up" : "down");
    }
}

static uword
dev_input_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return 0;
}

VLIB_REGISTER_NODE (dev_input_node) = {
  .function = dev_input_fn,
  .name = "dev-input",
  .runtime_data_bytes = sizeof (vnet_dev_rx_node_runtime_t),
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_next_nodes = VNET_DEVICE_INPUT_N_NEXT_NODES,
  .next_nodes = VNET_DEVICE_INPUT_NEXT_NODES,
};

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
