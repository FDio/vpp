/*
 * ip/ip6_neighbor.c: IP6 neighbor handling
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#include <vnet/ip6-nd/ip6_nd.h>
#include <vnet/ip-neighbor/ip_neighbor.h>

#include <vnet/fib/ip6_fib.h>

static int
ip6_nd_proxy_add_del (u32 sw_if_index, const ip6_address_t * addr, u8 is_del)
{
  /* *INDENT-OFF* */
  u32 fib_index;
  fib_prefix_t pfx = {
    .fp_len = 128,
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_addr = {
      .ip6 = *addr,
    },
  };
  ip46_address_t nh = {
    .ip6 = *addr,
  };
  /* *INDENT-ON* */

  fib_index = ip6_fib_table_get_index_for_sw_if_index (sw_if_index);

  if (~0 == fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  if (is_del)
    {
      fib_table_entry_path_remove (fib_index,
				   &pfx,
				   FIB_SOURCE_IP6_ND_PROXY,
				   DPO_PROTO_IP6,
				   &nh,
				   sw_if_index,
				   ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);
      /* flush the ND cache of this address if it's there */
      ip_neighbor_del (&nh, IP46_TYPE_IP6, sw_if_index);
    }
  else
    {
      fib_table_entry_path_add (fib_index,
				&pfx,
				FIB_SOURCE_IP6_ND_PROXY,
				FIB_ENTRY_FLAG_NONE,
				DPO_PROTO_IP6,
				&nh,
				sw_if_index,
				~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
    }
  return (0);
}

int
ip6_nd_proxy_add (u32 sw_if_index, const ip6_address_t * addr)
{
  return (ip6_nd_proxy_add_del (sw_if_index, addr, 0));
}

int
ip6_nd_proxy_del (u32 sw_if_index, const ip6_address_t * addr)
{
  return (ip6_nd_proxy_add_del (sw_if_index, addr, 1));
}

static clib_error_t *
set_ip6_nd_proxy_cmd (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  ip6_address_t addr;
  u32 sw_if_index;
  u8 is_del = 0;

  if (unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      /* get the rest of the command */
      while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (input, "%U", unformat_ip6_address, &addr))
	    break;
	  else if (unformat (input, "delete") || unformat (input, "del"))
	    is_del = 1;
	  else
	    return (unformat_parse_error (input));
	}
    }

  ip6_nd_proxy_add_del (sw_if_index, &addr, is_del);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ip6_nd_proxy_command, static) =
{
  .path = "set ip6 nd proxy",
  .short_help = "set ip6 nd proxy <interface> [del] <host>",
  .function = set_ip6_nd_proxy_cmd,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
