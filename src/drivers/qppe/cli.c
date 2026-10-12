/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <edma_hw.h>
#include <qppe.h>

#include <string.h>

/* Collects all attached qppe devices, for the "show qppe ..." commands
 * below - there is normally only one, but nothing stops more than one PPE
 * instance from being attached. */
static void
qppe_cli_devices (vnet_dev_t ***devs)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  pool_foreach_pointer (dev, dm->devices)
    {
      vnet_dev_driver_t *dr = pool_elt_at_index (dm->drivers, dev->driver_index);

      if (strcmp (dr->registration->name, "qppe") == 0)
	vec_add1 (*devs, dev);
    }
}

static clib_error_t *
show_qppe_acl_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      __clib_unused vlib_cli_command_t *cmd)
{
  vnet_dev_t **devs = 0;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);

  qppe_cli_devices (&devs);
  vec_foreach_pointer (dev, devs)
    {
      vlib_cli_output (vm, "device '%s':", dev->device_id);
      vlib_cli_output (vm, "  %U", format_qppe_acl_ipo_tbl, dev);
      vlib_cli_output (vm, "  %U", format_qppe_acl_pre_ipo_tbl, dev);
    }
  vec_free (devs);

  return 0;
}

VLIB_CLI_COMMAND (show_qppe_acl_cmd, static) = {
  .path = "show qppe acl",
  .short_help = "show qppe acl",
  .function = show_qppe_acl_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_edma_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		       __clib_unused vlib_cli_command_t *cmd)
{
  vnet_dev_t **devs = 0;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);

  qppe_cli_devices (&devs);
  vec_foreach_pointer (dev, devs)
    {
      vlib_cli_output (vm, "device '%s':", dev->device_id);
      vlib_cli_output (vm, "  %U", format_qppe_edma_service_tbl, dev);
      vlib_cli_output (vm, "  %U", format_qppe_edma_in_l2_service_tbl, dev);
      vlib_cli_output (vm, "  %U", format_qppe_edma_eg_service_tbl, dev);
      vlib_cli_output (vm, "  %U", format_qppe_edma_tl_service_tbl, dev);
      vlib_cli_output (vm, "  %U", format_qppe_edma_uni_drop_cnt_tbl, dev);
    }
  vec_free (devs);

  return 0;
}

VLIB_CLI_COMMAND (show_qppe_edma_cmd, static) = {
  .path = "show qppe edma",
  .short_help = "show qppe edma",
  .function = show_qppe_edma_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_vsi_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      __clib_unused vlib_cli_command_t *cmd)
{
  vnet_dev_t **devs = 0;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);

  qppe_cli_devices (&devs);
  vec_foreach_pointer (dev, devs)
    {
      vlib_cli_output (vm, "device '%s':", dev->device_id);
      vlib_cli_output (vm, "  %U", format_qppe_rule_and_action_tbl, dev);
      vlib_cli_output (vm, "  %U", format_qppe_vsi_tbl, dev);
      vlib_cli_output (vm, "  %U", format_qppe_vsi_remap_tbl, dev);
      vlib_cli_output (vm, "  %U", format_qppe_port_vsi_enqueue_map, dev);
      vlib_cli_output (vm, "  %U", format_qppe_ucast_queue_map_tbl, dev);
      vlib_cli_output (vm, "  %U", format_qppe_l2_vp_port_tbl, dev);
    }
  vec_free (devs);

  return 0;
}

VLIB_CLI_COMMAND (show_qppe_vsi_cmd, static) = {
  .path = "show qppe vsi",
  .short_help = "show qppe vsi",
  .function = show_qppe_vsi_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_fdb_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      __clib_unused vlib_cli_command_t *cmd)
{
  vnet_dev_t **devs = 0;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);

  qppe_cli_devices (&devs);
  vec_foreach_pointer (dev, devs)
    {
      vlib_cli_output (vm, "device '%s':", dev->device_id);
      vlib_cli_output (vm, "  %U", format_qppe_fdb_table, dev);
    }
  vec_free (devs);

  return 0;
}

VLIB_CLI_COMMAND (show_qppe_fdb_cmd, static) = {
  .path = "show qppe fdb",
  .short_help = "show qppe fdb",
  .function = show_qppe_fdb_cmd_fn,
  .is_mp_safe = 1,
};
