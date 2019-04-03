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

#include <rdma/rdma.h>

static clib_error_t *
rdma_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  rdma_create_if_args_t args;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  clib_memset (&args, 0, sizeof (rdma_create_if_args_t));

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "host-if %s", &args.ifname))
	;
      else if (unformat (line_input, "name %s", &args.name))
	;
      else if (unformat (line_input, "rx-queue-size %u", &args.rxq_size))
	;
      else if (unformat (line_input, "tx-queue-size %u", &args.txq_size))
	;
      else if (unformat (line_input, "num-rx-queues %u", &args.rxq_num))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  rdma_create_if (vm, &args);

  vec_free (args.ifname);
  vec_free (args.name);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (rdma_create_command, static) = {
  .path = "create interface rdma",
  .short_help = "create interface rdma <host-if ifname> [name <name>]"
    " [rx-queue-size <size>] [tx-queue-size <size>]"
    " [num-rx-queues <size>]",
  .function = rdma_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
rdma_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  rdma_main_t *rm = &rdma_main;
  rdma_device_t *rd;
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
  if (hw == NULL || rdma_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not a RDMA interface");

  rd = pool_elt_at_index (rm->devices, hw->dev_instance);

  rdma_delete_if (vm, rd);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (rdma_delete_command, static) = {
  .path = "delete interface rdma",
  .short_help = "delete interface rdma "
    "{<interface> | sw_if_index <sw_idx>}",
  .function = rdma_delete_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
rdma_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (rdma_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
