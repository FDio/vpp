/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <udp-echo/udp_echo.h>
#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>

udp_echo_main_t udp_echo_main;

static clib_error_t *
udp_echo_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  udp_echo_main_t *uem = &udp_echo_main;
  u32 port = 0;
  int enable = 1;
  u8 regen_udp_cksum = uem->regen_udp_cksum;
  u8 regen_ip_cksum = uem->regen_ip_cksum;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "port %d", &port))
	;
      else if (unformat (input, "regen-udp-cksum"))
	regen_udp_cksum = 1;
      else if (unformat (input, "regen-ip-cksum"))
	regen_ip_cksum = 1;
      else
	break;
    }

  if (enable && port == 0)
    return clib_error_return (0, "Please specify a port...");

  if (enable)
    {
      if (uem->enabled)
	{
	  if (uem->port == (u16) port)
	    return 0;

	  /* Port changed, unregister old one */
	  udp_unregister_dst_port (vm, uem->port, 1 /* is_ip4 */);
	}

      if (udp_is_valid_dst_port (port, 1 /* is_ip4 */))
	return clib_error_return (0, "Port %d is already in use", port);

      udp_register_dst_port (vm, port, udp_echo_node.index, 1 /* is_ip4 */);
      uem->port = port;
      uem->enabled = 1;
      uem->regen_udp_cksum = regen_udp_cksum;
      uem->regen_ip_cksum = regen_ip_cksum;
    }
  else
    {
      if (uem->enabled)
	{
	  udp_unregister_dst_port (vm, uem->port, 1 /* is_ip4 */);
	  uem->enabled = 0;
	}
    }

  return 0;
}

VLIB_CLI_COMMAND (udp_echo_enable_disable_command, static) = {
  .path = "udp-echo",
  .short_help = "udp-echo [port <port>] [regen-udp-cksum] [regen-ip-cksum] [disable]",
  .function = udp_echo_enable_disable_command_fn,
};

static clib_error_t *
udp_echo_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (udp_echo_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "UDP Echo Plugin",
};
