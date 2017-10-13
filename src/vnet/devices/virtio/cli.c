/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/tap.h>

static clib_error_t *
tap_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *err;
  tap_create_if_args_t args = { 0 };

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &args.name))
	;
      else if (unformat (line_input, "host-ns %s", &args.net_ns))
	;
      else if (unformat (line_input, "rx-ring-size %s", &args.rx_ring_sz))
	;
      else if (unformat (line_input, "tx-ring-size %s", &args.tx_ring_sz))
	;
      else if (unformat (line_input, "hw-addr %U",
			 unformat_ethernet_address, args.hw_addr))
	args.hw_addr_set = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  err = tap_create_if (vm, &args);

  vec_free (args.name);

  return err;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tap_create_command, static) = {
  .path = "create tap",
  .short_help = "create tap [name <if-name>] [hw-addr <mac-address>]"
    "[rx-ring-size <size>] [tx-ring-size <size>] [host-ns <netns>]",
  .function = tap_create_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
tap_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (tap_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
