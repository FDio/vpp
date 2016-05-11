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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>

#include <vnet/devices/netmap/net_netmap.h>
#include <vnet/devices/netmap/netmap.h>

static clib_error_t *
netmap_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 * host_if_name = NULL;
  u8 hwaddr [6];
  u8 * hw_addr_ptr = 0;
  int r;
  u8 is_pipe = 0;
  u8 is_master = 0;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &host_if_name))
	;
      else if (unformat (line_input, "hw-addr %U", unformat_ethernet_address, hwaddr))
	hw_addr_ptr = hwaddr;
      else if (unformat (line_input, "pipe"))
	is_pipe = 1;
      else if (unformat (line_input, "master"))
	is_master = 1;
      else if (unformat (line_input, "slave"))
	is_master = 0;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }
  unformat_free (line_input);

  if (host_if_name == NULL)
      return clib_error_return (0, "missing host interface name");

  r = netmap_create_if(vm, host_if_name, hw_addr_ptr, is_pipe, is_master);

  if (r == VNET_API_ERROR_SYSCALL_ERROR_1)
    return clib_error_return(0, "%s (errno %d)", strerror (errno), errno);

  if (r == VNET_API_ERROR_INVALID_INTERFACE)
    return clib_error_return(0, "Invalid interface name");

  if (r == VNET_API_ERROR_SUBIF_ALREADY_EXISTS)
    return clib_error_return(0, "Interface already exists");

  return 0;
}

VLIB_CLI_COMMAND (netmap_create_command, static) = {
  .path = "create netmap",
  .short_help = "create netmap name [<intf name>|valeXXX:YYY] "
    "[hw-addr <mac>] [pipe] [master|slave]",
  .function = netmap_create_command_fn,
};

static clib_error_t *
netmap_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 * host_if_name = NULL;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &host_if_name))
        ;
      else
        return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }
  unformat_free (line_input);

  if (host_if_name == NULL)
      return clib_error_return (0, "missing host interface name");

  netmap_delete_if(vm, host_if_name);

  return 0;
}

VLIB_CLI_COMMAND (netmap_delete_command, static) = {
  .path = "delete netmap",
  .short_help = "delete netmap name <interface name>",
  .function = netmap_delete_command_fn,
};

clib_error_t *
netmap_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (netmap_cli_init);
