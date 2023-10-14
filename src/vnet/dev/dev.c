/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/pool.h"
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/interface/rx_queue_funcs.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U%s" f,                    \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, dev_log.class, "%U%s" f,                  \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)

#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U%s" f,                      \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)

vnet_dev_main_t vnet_dev_main = { .next_rx_queue_thread = 1 };

vnet_dev_bus_t *
vnet_dev_find_device_bus (vlib_main_t *vm, vnet_dev_device_id_t id)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_bus_t *bus;

  pool_foreach (bus, dm->buses)
    {
      int n = strlen (bus->registration->name);
      int l = strlen (id);
      int dl = strlen (VNET_DEV_DEVICE_ID_PREFIX_DELIMITER);

      if (l <= n + dl)
	continue;

      if (strncmp (bus->registration->name, id, n))
	continue;

      if (strncmp (VNET_DEV_DEVICE_ID_PREFIX_DELIMITER, id + n, dl))
	continue;

      return bus;
    }

  return 0;
}

void *
vnet_dev_get_device_info (vlib_main_t *vm, vnet_dev_device_id_t id)
{
  vnet_dev_bus_t *bus;

  bus = vnet_dev_find_device_bus (vm, id);
  if (bus == 0)
    return 0;

  return bus->ops.get_device_info (vm, id);
}

vnet_dev_t *
vnet_dev_alloc (vlib_main_t *vm, vnet_dev_device_id_t id,
		vnet_dev_driver_t *driver)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_t *dev = 0, **devp = 0;

  dev = vnet_dev_alloc_with_data (sizeof (vnet_dev_t),
				  driver->registration->device_data_sz);
  pool_get (dm->devices, devp);
  devp[0] = dev;
  dev->index = devp - dm->devices;
  dev->driver_index = driver->index;
  dev->ops = driver->registration->ops;
  dev->bus_index = driver->bus_index;
  clib_memcpy (dev->device_id, id, sizeof (dev->device_id));
  hash_set (dm->device_index_by_id, dev->device_id, dev->index);

  if ((vnet_dev_process_create (vm, dev)) == VNET_DEV_OK)
    return dev;

  vnet_dev_free (vm, dev);
  return 0;
}

vnet_dev_rv_t
vnet_dev_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_bus_t *bus = pool_elt_at_index (dm->buses, dev->bus_index);
  vnet_dev_rv_t rv;

  vnet_dev_validate (vm, dev);

  if ((rv = bus->ops.device_open (vm, dev)) != VNET_DEV_OK)
    return rv;

  if ((rv = dev->ops.device_init (vm, dev)) != VNET_DEV_OK)
    {
      log_err (dev, "device init failed [rv %d]", rv);
      if (dev->ops.device_deinit)
	dev->ops.device_deinit (vm, dev);
      return rv;
    }

  dev->initialized = 1;
  dev->not_first_init = 1;
  return VNET_DEV_OK;
}

void
vnet_dev_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  ASSERT (dev->initialized == 1);

  if (dev->ops.device_deinit)
    dev->ops.device_deinit (vm, dev);

  pool_foreach_pointer (p, dev->ports)
    vnet_dev_port_remove (vm, p);

  dev->initialized = 0;
}

void
vnet_dev_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_bus_t *bus;

  vnet_dev_validate (vm, dev);

  vec_foreach_pointer (port, dev->ports)
    if (port->started)
      vnet_dev_port_stop (vm, port);

  if (dev->initialized)
    vnet_dev_deinit (vm, dev);

  ASSERT (dev->initialized == 0);

  if (dev->ops.device_free)
    dev->ops.device_free (vm, dev);

  bus = vnet_dev_get_bus (dev);
  if (bus->ops.device_close)
    bus->ops.device_close (vm, dev);

  vnet_dev_process_quit (vm, dev);
  vec_free (dev->description);
  pool_free (dev->ports);
  pool_free (dev->periodic_ops);
  hash_unset (dm->device_index_by_id, dev->device_id);
  pool_put_index (dm->devices, dev->index);
}

vnet_dev_rv_t
vnet_dev_reset (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_rv_t rv;

  ASSERT (dev->initialized == 1);
  vnet_dev_validate (vm, dev);

  if (dev->ops.device_reset == 0)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  if ((rv = dev->ops.device_reset (vm, dev)) != VNET_DEV_OK)
    {
      log_err (dev, "device reset failed [rv %d]", rv);
      return rv;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_dma_mem_alloc (vlib_main_t *vm, vnet_dev_t *dev, u32 size, u32 align,
			void **pp)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_bus_t *bus = pool_elt_at_index (dm->buses, dev->bus_index);
  vnet_dev_rv_t rv;

  vnet_dev_validate (vm, dev);

  rv = bus->ops.dma_mem_alloc_fn (vm, dev, size, align, pp);
  if (rv == VNET_DEV_OK)
    log_debug (
      dev, "dma_mem_alloc: %u bytes va %p dma-addr 0x%lx numa %u align %u",
      size, *pp, vnet_dev_get_dma_addr (vm, dev, *pp), dev->numa_node, align);
  return rv;
}

void
vnet_dev_dma_mem_free (vlib_main_t *vm, vnet_dev_t *dev, void *p)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_bus_t *bus = pool_elt_at_index (dm->buses, dev->bus_index);

  vnet_dev_validate (vm, dev);

  log_debug (dev, "dma_mem_free: %p", p);

  if (p == 0)
    return;

  return bus->ops.dma_mem_free_fn (vm, dev, p);
}

static void
vnet_dev_clear_hw_interface_counters (u32 instance)
{
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (instance);

  log_warn (port->dev, "TODO %s", __func__);
}

static void
vnet_dev_set_interface_next_node (vnet_main_t *vnm, u32 hw_if_index,
				  u32 node_index)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_dev_port_t *port =
    vnet_dev_get_port_from_dev_instance (hw->dev_instance);

  port->intf.rx_next_index =
    node_index == ~0 ? vnet_dev_default_next_index_by_port_type[port->type] :
			     node_index;

  pool_foreach_pointer (rxq, port->rx_queues)
    vnet_dev_rx_queue_rt_request (
      vm, rxq, (vnet_dev_rx_queue_rt_req_t){ .update_next_index = 1 });

  log_warn (port->dev, "TODO %s", __func__);
}

static clib_error_t *
vnet_dev_rx_mode_change_fn (vnet_main_t *vnm, u32 hw_if_index, u32 qid,
			    vnet_hw_if_rx_mode mode)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_dev_port_t *port =
    vnet_dev_get_port_from_dev_instance (hw->dev_instance);

  log_warn (port->dev, "TODO %s", __func__);
  return clib_error_return (0, "not supported");
}

static int
sort_driver_registrations (void *a0, void *a1)
{
  vnet_dev_driver_registration_t **r0 = a0;
  vnet_dev_driver_registration_t **r1 = a1;

  if (r0[0]->priority > r1[0]->priority)
    return -1;
  else if (r0[0]->priority < r1[0]->priority)
    return 1;

  return 0;
}

static clib_error_t *
vnet_dev_main_init (vlib_main_t *vm)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_driver_registration_t **drv = 0;

  dm->device_index_by_id = hash_create_string (0, sizeof (uword));

  for (vnet_dev_bus_registration_t *r = dm->bus_registrations; r;
       r = r->next_registration)
    {
      vnet_dev_bus_t *bus;
      pool_get_zero (dm->buses, bus);
      bus->registration = r;
      bus->index = bus - dm->buses;
      bus->ops = r->ops;
      if (!r->device_data_size ||
	  r->device_data_size > STRUCT_SIZE_OF (vnet_dev_t, bus_data))
	return clib_error_return (
	  0, "bus device data for bus '%s' is too big not specified", r->name);

      log_debug (0, "bus '%s' registered", r->name);
    }

  for (vnet_dev_driver_registration_t *r = dm->driver_registrations; r;
       r = r->next_registration)
    vec_add1 (drv, r);

  vec_sort_with_function (drv, sort_driver_registrations);

  vec_foreach_pointer (r, drv)
    {
      vnet_dev_driver_t *driver;
      vnet_dev_bus_t *bus;
      vnet_device_class_t *dev_class;
      clib_error_t *vnet_dev_admin_up_down_fn (vnet_main_t *, u32, u32);
      int bus_index = -1;

      pool_foreach (bus, dm->buses)
	{
	  if (strcmp (bus->registration->name, r->bus) == 0)
	    {
	      bus_index = bus->index;
	      break;
	    }
	}

      if (bus_index < 0)
	return clib_error_return (0, "unknown bus '%s'", r->bus);

      pool_get_zero (dm->drivers, driver);
      driver->registration = r;
      driver->index = driver - dm->drivers;
      driver->bus_index = bus_index;
      driver->ops = r->ops;
      dev_class = clib_mem_alloc (sizeof (vnet_device_class_t));
      *dev_class = (vnet_device_class_t){
	.name = r->name,
	.format_device_name = format_vnet_dev_interface_name,
	.format_device = format_vnet_dev_interface_info,
	.admin_up_down_function = vnet_dev_admin_up_down_fn,
	.rx_redirect_to_node = vnet_dev_set_interface_next_node,
	.clear_counters = vnet_dev_clear_hw_interface_counters,
	.rx_mode_change_function = vnet_dev_rx_mode_change_fn,
      };
      driver->dev_class_index = vnet_register_device_class (vm, dev_class);
      log_debug (0, "driver '%s' registered on bus '%s'", r->name,
		 bus->registration->name);
    }

  if (dm->startup_config)
    log_debug (0, "startup config: %v", dm->startup_config);

  vec_free (drv);

  return 0;
}

VLIB_INIT_FUNCTION (vnet_dev_main_init);
