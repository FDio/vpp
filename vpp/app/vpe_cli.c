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

typedef struct {
    u8 mac_addr[6];
} mac_addr_t;

static clib_error_t *
virtual_ip_cmd_fn_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, * line_input = &_line_input;
    vnet_main_t * vnm = vnet_get_main();
    ip4_main_t * im = &ip4_main;
    ip_lookup_main_t * lm = &im->lookup_main;
    ip4_address_t ip_addr, next_hop;
    u8 mac_addr[6];
    mac_addr_t *mac_addrs = 0;
    u32 sw_if_index;
    u32 i, f;

    /* Get a line of input. */
    if (! unformat_user (input, unformat_line_input, line_input))
        return 0;

    if (!unformat(line_input, "%U %U", 
                  unformat_ip4_address, &ip_addr,
                  unformat_vnet_sw_interface, vnm, &sw_if_index))
        goto barf;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
	if (unformat (line_input, "mac %U", 
                      unformat_ethernet_address, 
                      &mac_addr))
        {
            mac_addr_t *ma;
            vec_add2 (mac_addrs, ma, 1);
            clib_memcpy(ma, mac_addr, sizeof (mac_addr));
        } else {
        barf:
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, input);
        }
    }
    if (vec_len (mac_addrs) == 0)
        goto barf;

    /* Create / delete special interface route /32's */
    next_hop.as_u32 = 0;

    for (i = 0; i < vec_len(mac_addrs); i++) {
        ip_adjacency_t adj;
        u32 adj_index;
        
        memset(&adj, 0, sizeof(adj));
        adj.lookup_next_index = IP_LOOKUP_NEXT_REWRITE;
        
        vnet_rewrite_for_sw_interface
            (vnm,
             VNET_L3_PACKET_TYPE_IP4,
             sw_if_index,
             ip4_rewrite_node.index,
             &mac_addrs[i],     /* destination address */
             &adj.rewrite_header,
             sizeof (adj.rewrite_data));

        ip_add_adjacency (lm, &adj, 1 /* one adj */,
                          &adj_index);
        
        f = (i + 1 < vec_len(mac_addrs)) ? IP4_ROUTE_FLAG_NOT_LAST_IN_GROUP : 0;
        ip4_add_del_route_next_hop (im,
                                    IP4_ROUTE_FLAG_ADD | f,
                                    &ip_addr,
                                    32 /* insert /32's */,
                                    &next_hop,
                                    sw_if_index,
                                    1 /* weight */, 
                                    adj_index, 
                                    (u32)~0 /* explicit fib index */);
    }

    vec_free (mac_addrs);

    return 0;
}

VLIB_CLI_COMMAND (virtual_ip_cmd_fn_command, static) = {
    .path = "ip virtual",
    .short_help = "ip virtual <addr> <interface> [mac <Mi>]+",
    .function = virtual_ip_cmd_fn_command_fn,
};
