/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <udp-echo/udp_echo.h>
#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>

udp_echo_main_t udp_echo_main;

static clib_error_t *
udp_echo_enable_disable_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  udp_echo_main_t *uem = &udp_echo_main;
  u32 port = cli_u64 (ctx, "port", 0);
  u32 n_clones = cli_u64 (ctx, "clone", uem->n_clones);
  int enable = !cli_flag (ctx, "disable");
  u8 linearize = uem->linearize || cli_flag (ctx, "linearize");
  u8 regen_udp_cksum = uem->regen_udp_cksum || cli_flag (ctx, "regen-udp-cksum");
  u8 regen_ip_cksum = uem->regen_ip_cksum || cli_flag (ctx, "regen-ip-cksum");

  if (enable && port == 0)
    return clib_error_return (0, "Please specify a port...");

  if (enable)
    {
      if (uem->enabled)
	{
	  if (uem->port == (u16) port)
	    {
	      uem->n_clones = n_clones;
	      uem->linearize = linearize;
	      uem->regen_udp_cksum = regen_udp_cksum;
	      uem->regen_ip_cksum = regen_ip_cksum;
	      return 0;
	    }

	  /* Port changed, unregister old one */
	  udp_unregister_dst_port (vm, uem->port, 1 /* is_ip4 */);
	}

      if (udp_is_valid_dst_port (port, 1 /* is_ip4 */))
	return clib_error_return (0, "Port %d is already in use", port);

      udp_register_dst_port (vm, port, udp_echo_node.index, 1 /* is_ip4 */);
      uem->port = port;
      uem->enabled = 1;
      uem->n_clones = n_clones;
      uem->linearize = linearize;
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
  .short_help = "Enable or disable the UDP echo node on a destination port",
  .args = CLI_ARGS (
    CLI_OPT_KEYWORD ("port", cli_type_u32, .min = 1, .max = 65535, .excludes = "disable",
		     .help = "UDP destination port, required to enable"),
    CLI_OPT_KEYWORD ("clone", cli_type_u32, .max = 4, .excludes = "disable",
		     .help = "number of extra copies of each packet"),
    CLI_FLAG ("linearize", .excludes = "disable", .help = "linearize chained buffers"),
    CLI_FLAG ("regen-udp-cksum", .excludes = "disable", .help = "regenerate the UDP checksum"),
    CLI_FLAG ("regen-ip-cksum", .excludes = "disable", .help = "regenerate the IP checksum"),
    CLI_FLAG ("disable", .help = "stop echoing")),
  .handler = udp_echo_enable_disable_command_fn,
};

static clib_error_t *
udp_echo_init (vlib_main_t *vm)
{
  udp_echo_main.n_clones = 0;
  return 0;
}

VLIB_INIT_FUNCTION (udp_echo_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "UDP Echo Plugin",
};
