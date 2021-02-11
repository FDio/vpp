/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/bihash_8_8.h>

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

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (af_xdp_create_command, static) = {
  .path = "create interface af_xdp",
  .short_help = "create interface af_xdp <host-if linux-ifname> [name ifname] [rx-queue-size size] [tx-queue-size size] [num-rx-queues <num|all>] [prog pathname] [zero-copy|no-zero-copy]",
  .function = af_xdp_create_command_fn,
};
/* *INDENT-ON* */

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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (af_xdp_delete_command, static) = {
  .path = "delete interface af_xdp",
  .short_help = "delete interface af_xdp "
    "{<interface> | sw_if_index <sw_idx>}",
  .function = af_xdp_delete_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
af_xdp_cli_init (vlib_main_t * vm)
{
  af_xdp_main_t *rm = &af_xdp_main;
  clib_bihash_init_8_8 (&rm->bhash, "XDP bhash", 1024, 2 << 20);
  clib_bihash_init_8_16 (&rm->bhashlog, "XDP bhash log", 1024, 256 << 20);
  return 0;
}

VLIB_INIT_FUNCTION (af_xdp_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
