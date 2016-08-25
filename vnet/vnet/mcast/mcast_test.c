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
#include <vnet/mcast/mcast.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ip/ip4.h>
#include <vnet/mcast/mcast.h>

typedef struct {
  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  mcast_main_t * mcast_main;
} mcast_test_main_t;

mcast_test_main_t mcast_test_main;
vlib_node_registration_t mcast_prep_node;
vlib_node_registration_t mcast_recycle_node;

static clib_error_t *
mcast_test_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  /* u8 *rewrite_data; */
  /* mcast_test_main_t * mtm = &mcast_test_main; */
  /* mcast_main_t * mcm = mtm->mcast_main; */
  /* ip_adjacency_t adj; */
  /* u32 adj_index; */
  /* mcast_group_t * g; */
  /* mcast_group_member_t * member; */
  /* unformat_input_t _line_input, * line_input = &_line_input; */
  /* ip4_address_t dst_addr, zero; */
  /* ip4_main_t * im = &ip4_main; */
  /* ip_lookup_main_t * lm = &im->lookup_main; */

  /* /\* Get a line of input. *\/ */
  /* if (! unformat_user (input, unformat_line_input, line_input)) */
  /*   return 0; */

  /* pool_get (mcm->groups, g); */
  /* memset (g, 0, sizeof (*g)); */

  /* while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) */
  /*   { */
  /*     vnet_hw_interface_t *hw; */
  /*     u32 next, sw_if_index; */

  /*     if (unformat (line_input, "%U", unformat_vnet_sw_interface,  */
  /*                   mtm->vnet_main, &sw_if_index))  */
  /*       { */
  /*         vec_add2 (g->members, member, 1); */
  /*         member->tx_sw_if_index = sw_if_index; */
          
  /*         hw = vnet_get_sup_hw_interface (mtm->vnet_main,  */
  /*                                         sw_if_index); */
          
  /*         next = vlib_node_add_next (mtm->vlib_main,  */
  /*                                    mcast_prep_node.index, */
  /*                                    hw->output_node_index); */
          
  /*         /\* Required to be the same next index... *\/ */
  /*         vlib_node_add_next_with_slot (mtm->vlib_main, */
  /*                                       mcast_recycle_node.index, */
  /*                                       hw->output_node_index, next); */
  /*         member->prep_and_recycle_node_next_index = next; */
  /*       } */
  /*     else */
  /*       { */
  /*         return unformat_parse_error (line_input); */
  /*       } */
  /*   } */

  /* if (vec_len (g->members) == 0) */
  /*   { */
  /*     pool_put (mcm->groups, g); */
  /*     vlib_cli_output (vm, "no group members specified"); */
  /*     return 0; */
  /*   } */


  /* adj.lookup_next_index = IP_LOOKUP_NEXT_REWRITE; */
  /* adj.mcast_group_index = g - mcm->groups; */
  /* rewrite_data = format (0, "abcdefg"); */

  /* vnet_rewrite_for_tunnel */
  /*   (mtm->vnet_main, */
  /*    (u32)~0, /\* tx_sw_if_index, we dont know yet *\/ */
  /*    ip4_rewrite_node.index, */
  /*    mcast_prep_node.index, */
  /*    &adj.rewrite_header, */
  /*    rewrite_data, vec_len(rewrite_data)); */

  /* ip_add_adjacency (lm, &adj, 1 /\* one adj *\/, */
  /*                   &adj_index); */
  
  /* dst_addr.as_u32 = clib_host_to_net_u32 (0x0a000002); */
  /* zero.as_u32 = 0; */

  /* ip4_add_del_route_next_hop (im, */
  /*                             IP4_ROUTE_FLAG_ADD, */
  /*                             &dst_addr, */
  /*                             24 /\* mask width *\/, */
  /*                             &zero /\* no next hop *\/, */
                          
  /*                             0, // next hop sw if index */
  /*                             1, // weight */
  /*                             adj_index, */
  /*                             0 /\* explicit fib 0 *\/); */

  return 0;
}

static VLIB_CLI_COMMAND (mcast_test_command) = {
  .path = "test mc",
  .short_help = "test mc",
  .function = mcast_test_command_fn,
};

clib_error_t *mcast_test_init (vlib_main_t *vm)
{
  mcast_test_main_t * mtm = &mcast_test_main;
    
  mtm->vlib_main = vm;
  mtm->vnet_main = vnet_get_main();
  mtm->mcast_main = &mcast_main;

  return 0;
}

VLIB_INIT_FUNCTION (mcast_test_init);
