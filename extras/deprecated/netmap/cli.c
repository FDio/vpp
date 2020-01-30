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
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *host_if_name = NULL;
  u8 hwaddr[6];
  u8 *hw_addr_ptr = 0;
  int r;
  u8 is_pipe = 0;
  u8 is_master = 0;
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &host_if_name))
	;
      else
	if (unformat
	    (line_input, "hw-addr %U", unformat_ethernet_address, hwaddr))
	hw_addr_ptr = hwaddr;
      else if (unformat (line_input, "pipe"))
	is_pipe = 1;
      else if (unformat (line_input, "master"))
	is_master = 1;
      else if (unformat (line_input, "slave"))
	is_master = 0;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (host_if_name == NULL)
    {
      error = clib_error_return (0, "missing host interface name");
      goto done;
    }

  r =
    netmap_create_if (vm, host_if_name, hw_addr_ptr, is_pipe, is_master,
		      &sw_if_index);

  if (r == VNET_API_ERROR_SYSCALL_ERROR_1)
    {
      error = clib_error_return (0, "%s (errno %d)", strerror (errno), errno);
      goto done;
    }

  if (r == VNET_API_ERROR_INVALID_INTERFACE)
    {
      error = clib_error_return (0, "Invalid interface name");
      goto done;
    }

  if (r == VNET_API_ERROR_SUBIF_ALREADY_EXISTS)
    {
      error = clib_error_return (0, "Interface already exists");
      goto done;
    }

  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);

done:
  unformat_free (line_input);

  return error;
}

/*?
 * '<em>netmap</em>' is a framework for very fast packet I/O from userspace.
 * '<em>VALE</em>' is an equally fast in-kernel software switch using the
 * netmap API. '<em>netmap</em>' includes '<em>netmap pipes</em>', a shared
 * memory packet transport channel. Together, they provide a high speed
 * user-space interface that allows VPP to patch into a linux namespace, a
 * linux container, or a physical NIC without the use of DPDK. Netmap/VALE
 * generates the '<em>netmap.ko</em>' kernel module that needs to be loaded
 * before netmap interfaces can be created.
 * - https://github.com/luigirizzo/netmap - Netmap/VALE repo.
 * - https://github.com/vpp-dev/netmap - VPP development package for Netmap/VALE,
 * which is a snapshot of the Netmap/VALE repo with minor changes to work
 * with containers and modified kernel drivers to work with NICs.
 *
 * Create a netmap interface that will attach to a linux interface.
 * The interface must already exist. Once created, a new netmap interface
 * will exist in VPP with the name '<em>netmap-<ifname></em>', where
 * '<em><ifname></em>' takes one of two forms:
 * - <b>ifname</b> - Linux interface to bind too.
 * - <b>valeXXX:YYY</b> -
 *   - Where '<em>valeXXX</em>' is an arbitrary name for a VALE
 *     interface that must start with '<em>vale</em>' and is less
 *     than 16 characters.
 *   - Where '<em>YYY</em>' is an existing linux namespace.
 *
 * This command has the following optional parameters:
 *
 * - <b>hw-addr <mac-addr></b> - Optional ethernet address, can be in either
 * X:X:X:X:X:X unix or X.X.X cisco format.
 *
 * - <b>pipe</b> - Optional flag to indicate that a '<em>netmap pipe</em>'
 * instance should be created.
 *
 * - <b>master | slave</b> - Optional flag to indicate whether VPP should
 * be the master or slave of the '<em>netmap pipe</em>'. Only considered
 * if '<em>pipe</em>' is entered. Defaults to '<em>slave</em>' if not entered.
 *
 * @cliexpar
 * Example of how to create a netmap interface tied to the linux
 * namespace '<em>vpp1</em>':
 * @cliexstart{create netmap name vale00:vpp1 hw-addr 02:FE:3F:34:15:9B pipe master}
 * netmap-vale00:vpp1
 * @cliexend
 * Once the netmap interface is created, enable the interface using:
 * @cliexcmd{set interface state netmap-vale00:vpp1 up}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (netmap_create_command, static) = {
  .path = "create netmap",
  .short_help = "create netmap name <ifname>|valeXXX:YYY "
    "[hw-addr <mac-addr>] [pipe] [master|slave]",
  .function = netmap_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
netmap_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *host_if_name = NULL;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &host_if_name))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (host_if_name == NULL)
    {
      error = clib_error_return (0, "missing host interface name");
      goto done;
    }

  netmap_delete_if (vm, host_if_name);

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Delete a netmap interface. Use the '<em><ifname></em>' to identify
 * the netmap interface to be deleted. In VPP, netmap interfaces are
 * named as '<em>netmap-<ifname></em>', where '<em><ifname></em>'
 * takes one of two forms:
 * - <b>ifname</b> - Linux interface to bind too.
 * - <b>valeXXX:YYY</b> -
 *   - Where '<em>valeXXX</em>' is an arbitrary name for a VALE
 *     interface that must start with '<em>vale</em>' and is less
 *     than 16 characters.
 *   - Where '<em>YYY</em>' is an existing linux namespace.
 *
 * @cliexpar
 * Example of how to delete a netmap interface named '<em>netmap-vale00:vpp1</em>':
 * @cliexcmd{delete netmap name vale00:vpp1}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (netmap_delete_command, static) = {
  .path = "delete netmap",
  .short_help = "delete netmap name <ifname>|valeXXX:YYY",
  .function = netmap_delete_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
netmap_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (netmap_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
