/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/ip/reass/ip4_full_reass.h>
#include <vnet/ip/reass/ip6_full_reass.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/ip/reass/ip6_sv_reass.h>
#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/reass/reass.h>

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
