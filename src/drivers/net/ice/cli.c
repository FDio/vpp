/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <string.h>

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <ice.h>

static clib_error_t *
show_ice_phy_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		     __clib_unused vlib_cli_command_t *cmd)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);

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
  .short_help = "show device driver ice phy",
  .function = show_ice_phy_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
ice_cli_show (vlib_main_t *vm, unformat_input_t *input, vnet_dev_op_with_ptr_t *dump)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);

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
  _ (aq)                                                                                           \
  _ (capabilities)                                                                                 \
  _ (vsi)                                                                                          \
  _ (rss)

#define _(name)                                                                                    \
  static clib_error_t *show_ice_##name##_cmd_fn (vlib_main_t *vm, unformat_input_t *input,         \
						 __clib_unused vlib_cli_command_t *cmd)            \
  {                                                                                                \
    return ice_cli_show (vm, input, ice_dump_##name);                                              \
  }                                                                                                \
  VLIB_CLI_COMMAND (show_ice_##name##_cmd, static) = {                                             \
    .path = "show device driver ice " #name,                                                       \
    .short_help = "show device driver ice " #name,                                                 \
    .function = show_ice_##name##_cmd_fn,                                                          \
    .is_mp_safe = 1,                                                                               \
  };
foreach_ice_show_subsystem
#undef _
