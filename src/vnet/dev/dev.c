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
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U%s" f,                      \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)

vnet_dev_main_t vnet_dev_main = { .next_rx_queue_thread = 1 };

void *
_vnet_dev_alloc_with_data (u32 sz, u32 data_sz)
{
  void *p;
  sz += data_sz;
  sz = round_pow2 (sz, CLIB_CACHE_LINE_BYTES);
  p = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  clib_memset (p, 0, sz);
  return p;
}

static __clib_unused void
_vnet_dev_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  foreach_vnet_dev_pool (p, dev->ports)
    vnet_dev_port_remove (vm, p);

  if (dev->initialized)
    {
      vnet_dev_bus_t *bus = pool_elt_at_index (dm->buses, dev->bus_index);

      vnet_dev_process_quit (vm, dev);
      if (dev->ops.device_free)
	dev->ops.device_free (vm, dev);
      if (bus->ops.device_close)
	bus->ops.device_close (vm, dev);
    }

  vec_free (dev->description);
  pool_free (dev->ports);
  pool_free (dev->periodic_ops);
  hash_unset (dm->device_index_by_id, dev->device_id);
  pool_put_index (dm->devices, dev->index);
}

vnet_dev_rv_t
vnet_dev_attach (vlib_main_t *vm, vnet_dev_attach_args_t *args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_t *dev = 0, **devp = 0;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  vnet_dev_bus_t *bus;
  vnet_dev_driver_t *driver;
  void *bus_dev_info = 0;
  u8 *dev_desc = 0;

  if (vnet_dev_by_id (args->device_id))
    return VNET_DEV_ERR_ALREADY_IN_USE;

  pool_foreach (bus, dm->buses)
    {
      int n = strlen (bus->registration->name);

      if (strlen (args->device_id) <= n + 1)
	continue;

      if (strncmp (bus->registration->name, args->device_id, n))
	continue;

      if (strncmp (VNET_DEV_DEVICE_ID_PREFIX_DELIMITER, args->device_id + n,
		   strlen (VNET_DEV_DEVICE_ID_PREFIX_DELIMITER)))
	continue;

      for (u32 i = 0; i < n; i++)
	if (args->device_id[i] != bus->registration->name[i])

	  if (args->device_id[n] != '/')
	    continue;

      if ((bus_dev_info = bus->ops.get_device_info (vm, args->device_id)))
	break;
    }

  if (!bus_dev_info)
    {
      log_err (dev, "invalid or unsupported device id");
      rv = VNET_DEV_ERR_INVALID_DEVICE_ID;
      goto done;
    }

  vec_foreach (driver, dm->drivers)
    {
      if (args->driver_name[0] &&
	  strcmp (args->driver_name, driver->registration->name))
	continue;
      if (driver->ops.probe &&
	  (dev_desc = driver->ops.probe (vm, bus->index, bus_dev_info)))
	break;
    }

  if (!dev_desc)
    {
      log_err (dev, "driver not available for %s", args->device_id);
      rv = VNET_DEV_ERR_DRIVER_NOT_AVAILABLE;
      goto done;
    }

  dev = _vnet_dev_alloc_with_data (sizeof (vnet_dev_t),
				   driver->registration->device_data_sz);
  pool_get (dm->devices, devp);
  devp[0] = dev;
  dev->index = devp - dm->devices;
  dev->bus_index = bus->index;
  dev->driver_index = driver->index;
  dev->ops = driver->registration->ops;
  dev->description = dev_desc;
  clib_memcpy (dev->device_id, args->device_id, sizeof (dev->device_id));
  hash_set (dm->device_index_by_id, dev->device_id, dev->index);

  log_debug (dev, "found '%v'", dev->description);

  if ((rv = bus->ops.device_open (vm, dev)) != VNET_DEV_OK)
    goto done;

  if ((rv = vnet_dev_process_create (vm, dev)) != VNET_DEV_OK)
    goto done;

  if ((rv = dev->ops.device_init (vm, dev)) != VNET_DEV_OK)
    {
      log_err (dev, "device init failed [rv %d]", rv);
      goto done;
    }
  dev->initialized = 1;

done:
  if (bus_dev_info)
    clib_mem_free (bus_dev_info);

  if (rv != VNET_DEV_OK)
    {
      if (dev)
	_vnet_dev_free (vm, dev);
    }
  return rv;
}

vnet_dev_rv_t
vnet_dev_detach (vlib_main_t *vm, vnet_dev_detach_args_t *args)
{
  vnet_dev_t *dev = vnet_dev_by_id (args->device_id);

  log_debug (dev, "detach");

  if (dev == 0)
    return VNET_DEV_ERR_NOT_FOUND;

  _vnet_dev_free (vm, dev);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_dma_mem_alloc (vlib_main_t *vm, vnet_dev_t *dev, u32 size, u32 align,
			void **pp)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_bus_t *bus = pool_elt_at_index (dm->buses, dev->bus_index);
  vnet_dev_rv_t rv;

  rv = bus->ops.dma_mem_alloc_fn (vm, dev, size, align, pp);
  if (rv == VNET_DEV_OK)
    log_debug (dev,
	       "dev_physmem_alloc: %u bytes of physmem allocated on numa %u "
	       "at address %p, aligned at %u",
	       size, dev->numa_node, *pp, align);
  return rv;
}

void
vnet_dev_dma_mem_free (vlib_main_t *vm, vnet_dev_t *dev, void *p)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_bus_t *bus = pool_elt_at_index (dm->buses, dev->bus_index);

  log_debug (dev, "dev_physmem_free: %p", p);
  return bus->ops.dma_mem_free_fn (vm, dev, p);
}

clib_error_t *
vnet_dev_init (vlib_main_t *vm)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

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
    {
      vnet_dev_driver_t *driver;
      vnet_dev_bus_t *bus;
      vnet_device_class_t *dev_class;
      clib_error_t *vnet_dev_admin_up_down_fn (vnet_main_t *, u32, u32);
      int bus_index = -1;

      pool_foreach (bus, dm->buses)
	{
	  if (strcmp (bus->registration->name, r->bus) == 0)
	    bus_index = bus->index;
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
      };
      driver->dev_class_index = vnet_register_device_class (vm, dev_class);
      log_debug (0, "driver '%s' registered", r->name);
    }

  if (dm->startup_config)
    log_debug (0, "startup config: %v", dm->startup_config);

  return 0;
}

VLIB_INIT_FUNCTION (vnet_dev_init);
