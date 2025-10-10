/*
 * Copyright (c) 2024 Cisco and/or its affiliates.
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

#include <vnet/ip/reass/ip4_full_reass.h>
#include <vnet/ip/reass/ip6_full_reass.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/ip/reass/ip6_sv_reass.h>
#include <vnet/sfdp/lookup/reass.h>
#include <vnet/sfdp/sfdp.h>

sfdp_reass_main_t sfdp_reass_main;

static clib_error_t *
sfdp_reass_main_init (vlib_main_t *vm)
{
  sfdp_reass_main_t *vrm = &sfdp_reass_main;
  vrm->ip4_sv_reass_next_index =
    ip4_sv_reass_custom_context_register_next_node (
      sfdp_lookup_ip4_node.index);
  vrm->ip6_sv_reass_next_index =
    ip6_sv_reass_custom_context_register_next_node (
      sfdp_lookup_ip6_node.index);
  /*vrm->ip4_full_reass_next_index =
    ip4_full_reass_custom_context_register_next_node (
      sfdp_lookup_ip4_node.index);
  vrm->ip6_full_reass_next_index =
    ip6_full_reass_custom_context_register_next_node (
      sfdp_lookup_ip6_node.index);
  vrm->ip4_full_reass_err_next_index = ip4_full_reass_get_error_next_index ();
  vrm->ip6_full_reass_err_next_index = ip6_full_reass_get_error_next_index
  ();*/
  return 0;
}

/*void
sfdp_ip4_full_reass_custom_context_register_next_node (u16 node_index)
{
  sfdp_reass_main.ip4_full_reass_next_index =
    ip4_full_reass_custom_context_register_next_node (node_index);
}

void
sfdp_ip6_full_reass_custom_context_register_next_node (u16 node_index)
{
  sfdp_reass_main.ip6_full_reass_next_index =
    ip6_full_reass_custom_context_register_next_node (node_index);
}

void
sfdp_ip4_full_reass_custom_context_register_next_err_node (u16 node_index)
{
  sfdp_reass_main.ip4_full_reass_err_next_index =
    ip4_full_reass_custom_context_register_next_node (node_index);
}

void
sfdp_ip6_full_reass_custom_context_register_next_err_node (u16 node_index)
{
  sfdp_reass_main.ip6_full_reass_err_next_index =
    ip6_full_reass_custom_context_register_next_node (node_index);
}
*/
VLIB_INIT_FUNCTION (sfdp_reass_main_init);
