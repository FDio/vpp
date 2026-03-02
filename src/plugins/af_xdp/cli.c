/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <af_xdp/af_xdp.h>

static clib_error_t *
af_xdp_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  af_xdp_create_if_args_t args;

  if (!unformat_user (input, unformat_af_xdp_create_if_args, &args))
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  af_xdp_create_if (vm, &args);

  vec_free (args.linux_ifname);
  vec_free (args.name);
  vec_free (args.prog);
  vec_free (args.netns);

  return args.error;
}

VLIB_CLI_COMMAND (af_xdp_create_command, static) = {
  .path = "create interface af_xdp",
  .short_help = "create interface af_xdp <host-if linux-ifname> [name ifname] "
		"[rx-queue-size size] [tx-queue-size size] [num-rx-queues <num|all>] "
		"[prog pathname] [netns ns] [zero-copy|no-zero-copy] [no-syscall-lock] "
		"[multi-buffer|no-multi-buffer]",
  .function = af_xdp_create_command_fn,
};

static clib_error_t *
af_xdp_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == NULL || af_xdp_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not an AVF interface");

  ad = pool_elt_at_index (am->devices, hw->dev_instance);

  af_xdp_delete_if (vm, ad);

  return 0;
}

VLIB_CLI_COMMAND (af_xdp_delete_command, static) = {
  .path = "delete interface af_xdp",
  .short_help = "delete interface af_xdp "
    "{<interface> | sw_if_index <sw_idx>}",
  .function = af_xdp_delete_command_fn,
};

clib_error_t *
af_xdp_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (af_xdp_cli_init);
