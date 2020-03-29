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

#include <igb/igb.h>

static clib_error_t *
igb_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  igb_create_if_args_t args;
  u32 tmp;

  clib_memset (&args, 0, sizeof (igb_create_if_args_t));

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vlib_pci_addr, &args.addr))
	;
      else if (unformat (line_input, "elog"))
	args.enable_elog = 1;
      else if (unformat (line_input, "rx-queue-size %u", &tmp))
	args.rxq_size = tmp;
      else if (unformat (line_input, "tx-queue-size %u", &tmp))
	args.txq_size = tmp;
      else if (unformat (line_input, "num-rx-queues %u", &tmp))
	args.rxq_num = tmp;
      else if (unformat (line_input, "name %s", &args.name))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  igb_create_if (vm, &args);

  vec_free (args.name);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igb_create_command, static) = {
  .path = "create interface igb",
  .short_help = "create interface igb <pci-address> "
		"[rx-queue-size <size>] [tx-queue-size <size>] "
		"[num-rx-queues <size>]",
  .function = igb_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
igb_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  igb_main_t *am = &igb_main;
  igb_device_t *ad;
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

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
  if (hw == NULL || igb_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not an IGB interface");

  ad = pool_elt_at_index (am->devices, hw->dev_instance);

  igb_delete_if (vm, ad);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igb_delete_command, static) = {
  .path = "delete interface igb",
  .short_help = "delete interface igb "
    "{<interface> | sw_if_index <sw_idx>}",
  .function = igb_delete_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
igb_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (igb_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
