/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __GBP_POLICY_DPO_H__
#define __GBP_POLICY_DPO_H__

#include <vnet/dpo/dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>

/**
 * @brief
 * The GBP FWD DPO. Used in the L3 path to select the correct EPG uplink
 * based on the source EPG.
 */
typedef struct gbp_policy_dpo_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * The protocol of packets using this DPO
   */
  dpo_proto_t gpd_proto;

  /**
   * SClass
   */
  sclass_t gpd_sclass;

  /**
   * sclass scope
   */
  gbp_scope_t gpd_scope;

  /**
   * output sw_if_index
   */
  u32 gpd_sw_if_index;

  /**
   * number of locks.
   */
  u16 gpd_locks;

  /**
   * Stacked DPO on DVR/ADJ of output interface
   */
  dpo_id_t gpd_dpo;
} gbp_policy_dpo_t;

extern void gbp_policy_dpo_add_or_lock (dpo_proto_t dproto,
					gbp_scope_t scope,
					sclass_t sclass,
					u32 sw_if_index, dpo_id_t * dpo);

extern dpo_type_t gbp_policy_dpo_get_type (void);

extern vlib_node_registration_t ip4_gbp_policy_dpo_node;
extern vlib_node_registration_t ip6_gbp_policy_dpo_node;
extern vlib_node_registration_t gbp_policy_port_node;

/**
 * Types exposed for the Data-plane
 */
extern dpo_type_t gbp_policy_dpo_type;
extern gbp_policy_dpo_t *gbp_policy_dpo_pool;

always_inline gbp_policy_dpo_t *
gbp_policy_dpo_get (index_t index)
{
  return (pool_elt_at_index (gbp_policy_dpo_pool, index));
}

static_always_inline const gbp_policy_dpo_t *
gbp_classify_get_gpd (const ip4_address_t * ip4, const ip6_address_t * ip6,
		      const u32 fib_index)
{
  const gbp_policy_dpo_t *gpd;
  const dpo_id_t *dpo;
  const load_balance_t *lb;
  u32 lbi;

  if (ip4)
    lbi = ip4_fib_forwarding_lookup (fib_index, ip4);
  else if (ip6)
    lbi = ip6_fib_table_fwding_lookup (fib_index, ip6);
  else
    return 0;

  lb = load_balance_get (lbi);
  dpo = load_balance_get_bucket_i (lb, 0);

  if (dpo->dpoi_type != gbp_policy_dpo_type)
    return 0;

  gpd = gbp_policy_dpo_get (dpo->dpoi_index);
  return gpd;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
