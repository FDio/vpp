/*
 * p2p_ethernet.c: p2p ethernet
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#include <vppinfra/bihash_16_8.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/p2p_ethernet.h>

int
p2p_ethernet_add_del (vlib_main_t * vm, u32 parent_if_index,
		      u8 * client_mac, int is_add)
{
  return 0;
}

static clib_error_t *
vnet_p2p_ethernet_add_del (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();

  int is_add = 1;
  int remote_mac = 0;
  u32 hw_if_index = ~0;
  u8 client_mac[6];

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	;
      else if (unformat (input, "%U", unformat_ethernet_address, &client_mac))
	remote_mac = 1;
      else if (unformat (input, "del"))
	is_add = 0;
      else
	break;
    }

  if (hw_if_index == ~0)
    return clib_error_return (0, "Please specify parent interface ...");
  if (!remote_mac)
    return clib_error_return (0, "Please specify client MAC address ...");

  u32 rv;
  rv = p2p_ethernet_add_del (vm, hw_if_index, client_mac, is_add);
  switch (rv)
    {
    case VNET_API_ERROR_BOND_SLAVE_NOT_ALLOWED:
      return clib_error_return (0,
				"not allowed as parent interface belongs to a BondEthernet interface");
    case -1:
      return clib_error_return (0,
				"p2p ethernet for given parent interface and client mac already exists");
    case -2:
      return clib_error_return (0,
				"couldn't create p2p ethernet subinterface");
    case -3:
      return clib_error_return (0,
				"p2p ethernet for given parent interface and client mac doesn't exist");
    default:
      break;
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (p2p_ethernet_add_del_command, static) =
{
  .path = "p2p_ethernet ",
  .function = vnet_p2p_ethernet_add_del,
  .short_help = "p2p_ethernet <intfc> <mac-address> [del]",};
/* *INDENT-ON* */

static clib_error_t *
p2p_ethernet_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (p2p_ethernet_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
