/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/pool.h"
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/log.h>
#include <vnet/dev/counters.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
};

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

  if (dev->ops.alloc)
    {
      rv = dev->ops.alloc (vm, dev);
      if (rv != VNET_DEV_OK)
	{
	  log_err (dev, "device init failed [rv %d]", rv);
	  if (dev->ops.deinit)
	    dev->ops.deinit (vm, dev);
	  if (dev->ops.free)
	    dev->ops.free (vm, dev);
	  return rv;
	}
    }

  if ((rv = dev->ops.init (vm, dev)) != VNET_DEV_OK)
    {
      log_err (dev, "device init failed [rv %d]", rv);
      if (dev->ops.deinit)
	dev->ops.deinit (vm, dev);
      if (dev->ops.free)
	dev->ops.free (vm, dev);
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
  vnet_dev_bus_t *bus;

  vnet_dev_validate (vm, dev);

  foreach_vnet_dev_port (p, dev)
    ASSERT (p->interfaces == 0);

  if (dev->ops.deinit)
    dev->ops.deinit (vm, dev);

  bus = vnet_dev_get_bus (dev);
  if (bus->ops.device_close)
    bus->ops.device_close (vm, dev);

  vnet_dev_process_quit (vm, dev);

  dev->initialized = 0;
}

void
vnet_dev_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  vnet_dev_validate (vm, dev);

  ASSERT (dev->initialized == 0);

  foreach_vnet_dev_port (p, dev)
    vnet_dev_port_free (vm, p);

  vec_free (dev->description);
  pool_free (dev->ports);
  pool_free (dev->periodic_ops);
  hash_unset (dm->device_index_by_id, dev->device_id);
  vnet_dev_arg_free (&dev->args);
  pool_put_index (dm->devices, dev->index);
}

vnet_dev_rv_t
vnet_dev_reset (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_rv_t rv;

  ASSERT (dev->initialized == 1);
  vnet_dev_validate (vm, dev);

  if (dev->ops.reset == 0)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  if ((rv = dev->ops.reset (vm, dev)) != VNET_DEV_OK)
    {
      log_err (dev, "device reset failed [rv %d]", rv);
      return rv;
    }

  return VNET_DEV_OK;
}

void
vnet_dev_detach (vlib_main_t *vm, vnet_dev_t *dev)
{
  foreach_vnet_dev_port (p, dev)
    if (p->interfaces)
      vnet_dev_port_if_remove (vm, p);
  vnet_dev_deinit (vm, dev);
  vnet_dev_free (vm, dev);
}

vnet_dev_rv_t
vnet_dev_dma_mem_alloc (vlib_main_t *vm, vnet_dev_t *dev, u32 size, u32 align,
			void **pp)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_bus_t *bus = pool_elt_at_index (dm->buses, dev->bus_index);
  vnet_dev_rv_t rv;

  vnet_dev_validate (vm, dev);

  if (!bus->ops.dma_mem_alloc_fn)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  rv = bus->ops.dma_mem_alloc_fn (vm, dev, size, align, pp);
  if (rv == VNET_DEV_OK)
    log_debug (dev, "%u bytes va %p dma-addr 0x%lx numa %u align %u", size,
	       *pp, vnet_dev_get_dma_addr (vm, dev, *pp), dev->numa_node,
	       align);
  return rv;
}

void
vnet_dev_dma_mem_free (vlib_main_t *vm, vnet_dev_t *dev, void *p)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_bus_t *bus = pool_elt_at_index (dm->buses, dev->bus_index);

  vnet_dev_validate (vm, dev);

  if (p == 0 || !bus->ops.dma_mem_free_fn)
    return;

  return bus->ops.dma_mem_free_fn (vm, dev, p);
}

clib_error_t *
vnet_dev_admin_up_down_fn (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_port_t *p = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u32 is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (is_up && p->started == 0)
    rv = vnet_dev_process_call_port_op (vm, p, vnet_dev_port_start);
  else if (!is_up && p->started)
    rv = vnet_dev_process_call_port_op_no_rv (vm, p, vnet_dev_port_stop);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "failed to change port admin state: %U",
			      format_vnet_dev_rv, rv);

  return 0;
}

static void
vnet_dev_feature_update_cb (u32 sw_if_index, u8 arc_index, u8 is_enable,
			    void *cb)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  vnet_dev_main_t *vdm = &vnet_dev_main;
  vnet_dev_port_t *port;
  vnet_dev_port_interface_t *intf;
  vnet_dev_instance_t *di;
  vnet_hw_interface_t *hw;
  u32 current_config_index = ~0;
  u32 next_index = ~0;
  int update_runtime = 0;

  log_info ("feature_update_cb: starting");

  if (arc_index == vdm->eth_port_rx_feature_arc_index)
    return;

  log_info ("feature_update_cb: new arc index");

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  di = vnet_dev_get_dev_instance (hw->dev_instance);

  if (!di)
    return;

  log_info ("feature_update_cb: instance exists");

  intf = di->is_primary_if ?
	   vnet_dev_port_get_primary_if (di->port) :
	   vnet_dev_port_get_sec_if_by_index (di->port, di->sec_if_index);

  port = di->port;

  if (port == 0 || intf->sw_if_index != sw_if_index)
    return;

  log_debug (port->dev, "feature_update_cb: port exists");

  if (vnet_have_features (arc_index, sw_if_index))
    {
      log_debug (port->dev, "feature_update_cb: intended arc enabled");

      cm = &fm->feature_config_mains[arc_index];
      current_config_index =
	vec_elt (cm->config_index_by_sw_if_index, sw_if_index);
      vnet_get_config_data (&cm->config_main, &current_config_index,
			    &next_index, 0);
      if (intf->feature_arc == 0 || intf->rx_next_index != next_index ||
	  intf->current_config_index != current_config_index)
	{
	  log_debug (port->dev, "feature_update_cb: difference detected");
	  intf->current_config_index = current_config_index;
	  intf->rx_next_index = next_index;
	  intf->feature_arc_index = arc_index;
	  intf->feature_arc = 1;
	  update_runtime = 1;
	}
    }
  else
    {
      log_debug (port->dev, "feature_update_cb: intended arc not enabled");

      if (intf->feature_arc)
	{
	  log_debug (port->dev, "feature_update_cb: arc detected");

	  intf->current_config_index = 0;
	  intf->rx_next_index =
	    intf->redirect_to_node ?
	      intf->redirect_to_node_next_index :
	      vnet_dev_default_next_index_by_port_type[port->attr.type];
	  intf->feature_arc_index = 0;
	  intf->feature_arc = 0;
	  update_runtime = 1;
	}
    }

  if (update_runtime)
    {
      log_debug (port->dev, "feature_update_cb: runtime update needed");

      foreach_vnet_dev_port_rx_queue (rxq, port)
	vnet_dev_rx_queue_rt_request (
	  vm, rxq,
	  (vnet_dev_rx_queue_rt_req_t){ .update_next_index = 1,
					.update_feature_arc = 1 });
      log_debug (port->dev, "runtime update requested due to chgange in "
			    "feature arc configuration");
    }
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
  u32 temp_space_sz = 0;

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
	.mac_addr_change_function = vnet_dev_port_mac_change,
	.mac_addr_add_del_function = vnet_dev_add_del_mac_address,
	.flow_ops_function = vnet_dev_flow_ops_fn,
	.format_flow = format_vnet_dev_flow,
	.set_rss_queues_function = vnet_dev_interface_set_rss_queues,
      };
      driver->dev_class_index = vnet_register_device_class (vm, dev_class);
      log_debug (0, "driver '%s' registered on bus '%s'", r->name,
		 bus->registration->name);

      if (temp_space_sz < r->runtime_temp_space_sz)
	temp_space_sz = r->runtime_temp_space_sz;
    }

  if (dm->startup_config)
    log_debug (0, "startup config: %v", dm->startup_config);

  vec_free (drv);

  if (temp_space_sz > 0)
    {
      const u32 align = CLIB_CACHE_LINE_BYTES;
      u32 sz = round_pow2 (temp_space_sz, align);
      dm->log2_runtime_temp_space_sz =
	get_lowest_set_bit_index (max_pow2 (sz));
      sz = 1 << dm->log2_runtime_temp_space_sz;
      sz *= vlib_get_n_threads ();
      dm->runtime_temp_spaces = clib_mem_alloc_aligned (sz, align);
      clib_memset (dm->runtime_temp_spaces, 0, sz);
      log_debug (0,
		 "requested %u bytes for runtime temp storage, allocated %u "
		 "per thread (total %u)",
		 temp_space_sz, 1 << dm->log2_runtime_temp_space_sz, sz);
    }

  vnet_feature_register (vnet_dev_feature_update_cb, 0);

  return 0;
}

VLIB_INIT_FUNCTION (vnet_dev_main_init);

clib_error_t *
vnet_dev_num_workers_change (vlib_main_t *vm)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  if (dm->log2_runtime_temp_space_sz > 0)
    {
      const u32 align = CLIB_CACHE_LINE_BYTES;
      uword sz =
	(1ULL << dm->log2_runtime_temp_space_sz) * vlib_get_n_threads ();
      if (dm->runtime_temp_spaces)
	clib_mem_free (dm->runtime_temp_spaces);
      dm->runtime_temp_spaces = clib_mem_alloc_aligned (sz, align);
      clib_memset (dm->runtime_temp_spaces, 0, sz);
      log_debug (0, "runtime temp storage resized to %u", sz);
    }

  return 0;
}

VLIB_NUM_WORKERS_CHANGE_FN (vnet_dev_num_workers_change);
