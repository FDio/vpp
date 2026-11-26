/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <string.h>

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <ice.h>

static clib_error_t *
show_ice_phy_cmd_fn (vlib_main_t *vm, __clib_unused cli_ctx_t *ctx)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  pool_foreach_pointer (dev, dm->devices)
    {
      vnet_dev_driver_t *dr = pool_elt_at_index (dm->drivers, dev->driver_index);

      if (strcmp (dr->registration->name, "ice") != 0)
	continue;

      foreach_vnet_dev_port (port, dev)
	{
	  vlib_cli_output (vm, "device '%s' port %u PHY:", dev->device_id, port->port_id);
	  vlib_cli_output (vm, "  %U", format_ice_phy_status, port);
	}
    }

  return 0;
}

VLIB_CLI_COMMAND (show_ice_phy_cmd, static) = {
  .path = "show device driver ice phy",
  .short_help = "Show the PHY status of ice ports",
  .handler = show_ice_phy_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
ice_cli_show (vlib_main_t *vm, vnet_dev_op_with_ptr_t *dump)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  pool_foreach_pointer (dev, dm->devices)
    {
      vnet_dev_driver_t *driver = pool_elt_at_index (dm->drivers, dev->driver_index);
      u8 *s = 0;
      vnet_dev_rv_t rv;

      if (strcmp (driver->registration->name, "ice") != 0)
	continue;

      rv = vnet_dev_process_call_op_with_ptr (vm, dev, dump, &s);
      if (rv)
	{
	  vec_free (s);
	  return clib_error_return (0, "device '%s': %U", dev->device_id, format_vnet_dev_rv, rv);
	}

      vlib_cli_output (vm, "device '%s':\n%v", dev->device_id, s);
      vec_free (s);
    }

  return 0;
}

#define foreach_ice_show_subsystem                                                                 \
  _ (aq, "Show the admin queues of ice devices")                                                   \
  _ (capabilities, "Show the capabilities of ice devices")                                         \
  _ (vsi, "Show the VSIs of ice devices")                                                          \
  _ (rss, "Show the RSS configuration of ice devices")

#define _(name, help)                                                                              \
  static clib_error_t *show_ice_##name##_cmd_fn (vlib_main_t *vm, __clib_unused cli_ctx_t *ctx)    \
  {                                                                                                \
    return ice_cli_show (vm, ice_dump_##name);                                                     \
  }                                                                                                \
  VLIB_CLI_COMMAND (show_ice_##name##_cmd, static) = {                                             \
    .path = "show device driver ice " #name,                                                       \
    .short_help = help,                                                                            \
    .handler = show_ice_##name##_cmd_fn,                                                           \
    .is_mp_safe = 1,                                                                               \
  };
foreach_ice_show_subsystem
#undef _
