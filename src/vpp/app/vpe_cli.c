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
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/adj/adj.h>
#include <vnet/fib/fib_table.h>

typedef struct
{
  u8 mac_addr[6];
} mac_addr_t;

static clib_error_t *
virtual_ip_cmd_fn_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  ip46_address_t next_hop, *next_hops;
  fib_route_path_t *rpaths;
  fib_prefix_t prefix;
  u8 mac_addr[6];
  mac_addr_t *mac_addrs = 0;
  u32 sw_if_index;
  u32 i;
  clib_error_t *error = NULL;

  next_hops = NULL;
  rpaths = NULL;
  prefix.fp_len = 32;
  prefix.fp_proto = FIB_PROTOCOL_IP4;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (!unformat (line_input, "%U %U",
		 unformat_ip4_address, &prefix.fp_addr.ip4,
		 unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown input `%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "mac %U",
		    unformat_ethernet_address, &mac_addr))
	{
	  mac_addr_t *ma;
	  vec_add2 (mac_addrs, ma, 1);
	  clib_memcpy (ma, mac_addr, sizeof (mac_addr));
	}
      else if (unformat (line_input, "next-hop %U",
			 unformat_ip4_address, &next_hop.ip4))
	{
	  vec_add1 (next_hops, next_hop);
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (vec_len (mac_addrs) == 0 || vec_len (mac_addrs) != vec_len (next_hops))
    {
      error = clib_error_return (0, "unknown input `%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  /* Create / delete special interface route /32's */

  for (i = 0; i < vec_len (mac_addrs); i++)
    {
      fib_route_path_t *rpath;

      adj_nbr_add_or_lock_w_rewrite (FIB_PROTOCOL_IP4,
				     VNET_LINK_IP4,
				     &next_hops[i],
				     sw_if_index, mac_addrs[i].mac_addr);

      vec_add2 (rpaths, rpath, 1);

      rpath->frp_proto = DPO_PROTO_IP4;
      rpath->frp_addr = next_hops[i];
      rpath->frp_sw_if_index = sw_if_index;
      rpath->frp_fib_index = ~0;
      rpath->frp_weight = 1;
      rpath->frp_label_stack = NULL;
    }

  fib_table_entry_path_add2 (0,	// default FIB table
			     &prefix,
			     FIB_SOURCE_CLI, FIB_ENTRY_FLAG_NONE, rpaths);

done:
  vec_free (mac_addrs);
  vec_free (next_hops);
  vec_free (rpaths);
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (virtual_ip_cmd_fn_command, static) = {
  .path = "ip virtual",
  .short_help = "ip virtual <addr> <interface> [mac <Mi>]+",
  .function = virtual_ip_cmd_fn_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
