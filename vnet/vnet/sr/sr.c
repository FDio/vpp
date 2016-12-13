/*
 * sr.c: ipv6 segment routing
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

/**
 * @file
 * @brief Segment Routing initialization
 *
 */

#include <vnet/vnet.h>
#include <vnet/sr/sr.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/dpo.h>

ip6_sr_main_t sr_main;

/**
 * @brief no-op lock function.
 * The lifetime of the SR entry is managed by the control plane
 */
void
sr_dpo_lock (dpo_id_t * dpo)
{
}

/**
 * @brief no-op unlock function.
 * The lifetime of the SR entry is managed by the control plane
 */
void
sr_dpo_unlock (dpo_id_t * dpo)
{
}

static clib_error_t * sr_init (vlib_main_t * vm)
{
  ip6_sr_main_t * sm = &sr_main;
  clib_error_t * error = 0;
  vlib_node_t * ip6_lookup_node, *ip4_lookup_node;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip6_lookup_init)))
    return error;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main();

  ip4_lookup_node = vlib_get_node_by_name (vm, (u8 *)"ip4-lookup");
  ASSERT(ip4_lookup_node);

  ip6_lookup_node = vlib_get_node_by_name (vm, (u8 *)"ip6-lookup");
  ASSERT(ip6_lookup_node);

  /* Add a disposition to ip4_lookup for the sr policy rewrite nodes */
  sm->ip4_lookup_sr_policy_rewrite_encaps_index = 
    vlib_node_add_next (vm, ip4_lookup_node->index, sr_policy_rewrite_encaps_node.index);
  sm->ip4_lookup_sr_policy_rewrite_insert_index = 
    vlib_node_add_next (vm, ip4_lookup_node->index, sr_policy_rewrite_insert_node.index);
  
  /* Add a disposition to ip6_lookup for the sr policy rewrite nodes */
  sm->ip6_lookup_sr_policy_rewrite_encaps_index = 
    vlib_node_add_next (vm, ip6_lookup_node->index, sr_policy_rewrite_encaps_node.index);
  sm->ip6_lookup_sr_policy_rewrite_insert_index = 
    vlib_node_add_next (vm, ip6_lookup_node->index, sr_policy_rewrite_insert_node.index);

#if DPDK > 0 /* Cannot run Spray without DPDK */
  /* Add a disposition to sr_spray for the sr replication */
  sm->ip6_lookup_sr_spray_index = 
    vlib_node_add_next (vm, ip6_lookup_node->index, sr_spray_node.index);
#endif /* DPDK */

  /* Add a disposition to run SR End behaviors (sr_local) */
  sm->ip6_lookup_sr_localsid_index = 
    vlib_node_add_next (vm, ip6_lookup_node->index, sr_localsid_node.index);

  return error;
}

VLIB_INIT_FUNCTION (sr_init);

ip6_sr_main_t * sr_get_main (vlib_main_t * vm)
{
  vlib_call_init_function (vm, sr_init);
  return &sr_main;
}

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/