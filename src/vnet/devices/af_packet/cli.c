/*
 *------------------------------------------------------------------
 * af_packet.c - linux kernel packet interface
 *
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

#include <fcntl.h>		/* for open */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>		/* for iovec */
#include <netinet/in.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vnet/devices/af_packet/af_packet.h>

/**
 * @file
 * @brief CLI for Host Interface Device Driver.
 *
 * This file contains the source code for CLI for the host interface.
 */

static clib_error_t *
af_packet_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *host_if_name = NULL;
  u8 hwaddr[6];
  u8 *hw_addr_ptr = 0;
  u32 sw_if_index;
  int r;
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

  r = af_packet_create_if (vm, host_if_name, hw_addr_ptr, &sw_if_index);

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
      error = clib_error_return (0, "Interface elready exists");
      goto done;
    }

  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);

done:
  vec_free (host_if_name);
  unformat_free (line_input);

  return error;
}

/*?
 * Create a host interface that will attach to a linux AF_PACKET
 * interface, one side of a veth pair. The veth pair must already
 * exist. Once created, a new host interface will exist in VPP
 * with the name '<em>host-<ifname></em>', where '<em><ifname></em>'
 * is the name of the specified veth pair. Use the
 * '<em>show interface</em>' command to display host interface details.
 *
 * This command has the following optional parameters:
 *
 * - <b>hw-addr <mac-addr></b> - Optional ethernet address, can be in either
 * X:X:X:X:X:X unix or X.X.X cisco format.
 *
 * @cliexpar
 * Example of how to create a host interface tied to one side of an
 * existing linux veth pair named vpp1:
 * @cliexstart{create host-interface name vpp1}
 * host-vpp1
 * @cliexend
 * Once the host interface is created, enable the interface using:
 * @cliexcmd{set interface state host-vpp1 up}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (af_packet_create_command, static) = {
  .path = "create host-interface",
  .short_help = "create host-interface name <ifname> [hw-addr <mac-addr>]",
  .function = af_packet_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
af_packet_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
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

  af_packet_delete_if (vm, host_if_name);

done:
  vec_free (host_if_name);
  unformat_free (line_input);

  return error;
}

/*?
 * Delete a host interface. Use the linux interface name to identify
 * the host interface to be deleted. In VPP, host interfaces are
 * named as '<em>host-<ifname></em>', where '<em><ifname></em>'
 * is the name of the linux interface.
 *
 * @cliexpar
 * Example of how to delete a host interface named host-vpp1:
 * @cliexcmd{delete host-interface name vpp1}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (af_packet_delete_command, static) = {
  .path = "delete host-interface",
  .short_help = "delete host-interface name <ifname>",
  .function = af_packet_delete_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
af_packet_set_l4_cksum_offload_command_fn (vlib_main_t * vm,
					   unformat_input_t * input,
					   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 set = 0;
  clib_error_t *error = NULL;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "on"))
	set = 1;
      else if (unformat (line_input, "off"))
	set = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  af_packet_set_l4_cksum_offload (vm, sw_if_index, set);

done:
  unformat_free (line_input);
  return error;
}

/*?
 * Set TCP/UDP offload checksum calculation. Use interface
 * name to identify the interface to set TCP/UDP offload checksum
 * calculation.
 *
 * @cliexpar
 * Example of how to set TCP/UDP offload checksum calculation on host-vpp0:
 * @cliexcmd{set host-interface l4-cksum-offload host-vpp0 off}
 * @cliexcmd{set host-interface l4-cksum-offload host-vpp0 on}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (af_packet_set_l4_cksum_offload_command, static) = {
  .path = "set host-interface l4-cksum-offload",
  .short_help = "set host-interface l4-cksum-offload <host-if-name> <on|off>",
  .function = af_packet_set_l4_cksum_offload_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
af_packet_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (af_packet_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
