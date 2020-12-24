/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vlib/vlib.h>

#include <plugins/linux-cp/lcp_interface.h>

static u32 host_vif;
const static char *host_template = "tap%d";

static clib_error_t *
lcp_add_pair_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  u32 phy_sw_if_index, host_sw_if_index;
  u8 is_add, *host_name;
  vnet_main_t *vnm = vnet_get_main ();

  ++host_vif;
  host_name = format (NULL, host_template, host_vif);
  phy_sw_if_index = host_sw_if_index = ~0;
  is_add = 1;
  lcp_main.test_mode = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "phy %U", unformat_vnet_sw_interface, vnm,
			 &phy_sw_if_index))
	;
      else if (unformat (input, "host %U", unformat_vnet_sw_interface, vnm,
			 &host_sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input:%U", format_unformat_error,
				  input);
    }

  if (phy_sw_if_index == ~0)
    return clib_error_return (0, "ERROR; no phy:%U", format_unformat_error,
			      input);

  lip_host_type_t host_type =
    (vnet_sw_interface_is_p2p (vnm, phy_sw_if_index) ? LCP_ITF_HOST_TUN :
						       LCP_ITF_HOST_TAP);

  int rv;

  if (is_add)
    {
      if (host_sw_if_index == ~0)
	return clib_error_return (0, "ERROR no-host:%U", format_unformat_error,
				  input);

      rv = lcp_itf_pair_add (host_sw_if_index, phy_sw_if_index, host_name,
			     host_vif, host_type, NULL);
    }
  else
    rv = lcp_itf_pair_del (phy_sw_if_index);

  if (rv)
    return clib_error_return (0, "ERROR rv:%d", rv);

  return (NULL);
}

VLIB_CLI_COMMAND (test_time_range_command, static) = {
  .path = "test lcp",
  .short_help = "lcp [add|del] phy <SW_IF_INDEX> host <SW_IF_INDEX>",
  .function = lcp_add_pair_command_fn,
};

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Linux Control Plane - Unit Test",
  .default_disabled = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
