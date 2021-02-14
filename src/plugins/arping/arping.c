/*
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
 */

#include <stddef.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <vnet/ip-neighbor/ip4_neighbor.h>
#include <vnet/ip-neighbor/ip6_neighbor.h>
#include <arping/arping.h>

static void
arping_ip4_address (vlib_main_t *vm, u32 sw_if_index, ip4_address_t *addr,
		    u8 garp)
{
  vnet_main_t *vnm = vnet_get_main ();

  if (garp)
    ip4_neighbor_advertise (vm, vnm, sw_if_index, addr);
  else
    ip4_neighbor_probe_dst (sw_if_index, addr);
}

static void
arping_ip6_address (vlib_main_t *vm, u32 sw_if_index, ip6_address_t *addr,
		    u8 garp)
{
  vnet_main_t *vnm = vnet_get_main ();

  if (garp)
    ip6_neighbor_advertise (vm, vnm, sw_if_index, addr);
  else
    ip6_neighbor_probe_dst (sw_if_index, addr);
}

static clib_error_t *
arping_ip_address (vlib_main_t *vm, unformat_input_t *input,
		   vlib_cli_command_t *cmd)
{
  ip4_address_t a4;
  ip6_address_t a6;
  clib_error_t *error = 0;
  u32 arping_repeat = ARPING_DEFAULT_REPEAT;
  u8 arping_ip4 = 0, garp = 0;
  vnet_main_t *vnm = vnet_get_main ();
  f64 arping_interval = ARPING_DEFAULT_INTERVAL;
  u32 sw_if_index = ~0;

  if (unformat (input, "gratuitous"))
    garp = 1;

  if (unformat (input, "%U", unformat_ip4_address, &a4))
    arping_ip4 = 1;
  else if (unformat (input, "%U", unformat_ip6_address, &a6))
    arping_ip4 = 0;
  else
    {
      error = clib_error_return (
	0,
	"expecting IP4/IP6 address `%U'. Usage: arping [gratuitous] <addr> "
	"<intf> [repeat <count>] [interval <secs>]",
	format_unformat_error, input);
      goto done;
    }

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  /* parse the rest of the parameters  in a cycle */
  while (!unformat_eof (input, NULL))
    {
      if (unformat (input, "interval"))
	{
	  if (!unformat (input, "%f", &arping_interval))
	    {
	      error = clib_error_return (
		0, "expecting interval (floating point number) got `%U'",
		format_unformat_error, input);
	      goto done;
	    }
	}
      else if (unformat (input, "repeat"))
	{
	  if (!unformat (input, "%u", &arping_repeat))
	    {
	      error =
		clib_error_return (0, "expecting repeat count but got `%U'",
				   format_unformat_error, input);
	      goto done;
	    }
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  while (arping_repeat > 0)
    {
      if (arping_ip4)
	arping_ip4_address (vm, sw_if_index, &a4, garp);
      else
	arping_ip6_address (vm, sw_if_index, &a6, garp);
      arping_repeat--;
      if (arping_interval > 0.0 && arping_repeat > 0)
	vlib_process_suspend (vm, arping_interval);
    }
done:
  return error;
}

/*?
 * This command sends an ARP_REQUEST or gratuitous ARP to network hosts. The
 * address can be an IPv4 or IPv6 address.
 *
 * @cliexpar
 * @parblock
 * Example of how to send an IPv4 ARP REQUEST
 * @cliexstart{arping 172.16.1.2 GigabitEthernet2/0/0 repeat 2}
 * @cliexend
 *
 * Example of how to send an IPv4 gratuitous ARP
 * @cliexstart{arping gratuitous 172.16.1.20 GigabitEthernet2/0/0 repeat 2}
 * @cliexend
 * @endparblock
?*/
VLIB_CLI_COMMAND (arping_command, static) = {
  .path = "arping",
  .function = arping_ip_address,
  .short_help = "arping [gratuitous] <addr> <interface>"
		" [interval <sec>] [repeat <cnt>]",
  .is_mp_safe = 1,
};

static clib_error_t *
arping_cli_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (arping_cli_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Arping (arping)",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
