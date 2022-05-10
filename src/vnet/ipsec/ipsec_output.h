/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef IPSEC_OUTPUT_H
#define IPSEC_OUTPUT_H

#include <vppinfra/types.h>
#include <vnet/ipsec/ipsec_spd.h>

always_inline ipsec_policy_t *
ipsec4_out_spd_find_flow_cache_entry (ipsec_main_t *im, u8 pr, u32 la, u32 ra,
				      u16 lp, u16 rp)
{
  ipsec_policy_t *p = NULL;
  ipsec4_hash_kv_16_8_t kv_result;
  u64 hash;

  if (PREDICT_FALSE ((pr != IP_PROTOCOL_TCP) && (pr != IP_PROTOCOL_UDP) &&
		     (pr != IP_PROTOCOL_SCTP)))
    {
      lp = 0;
      rp = 0;
    }
  ipsec4_spd_5tuple_t ip4_5tuple = { .ip4_addr = { (ip4_address_t) la,
						   (ip4_address_t) ra },
				     .port = { lp, rp },
				     .proto = pr };

  hash = ipsec4_hash_16_8 (&ip4_5tuple.kv_16_8);
  hash &= (im->ipsec4_out_spd_hash_num_buckets - 1);

  ipsec_spinlock_lock (&im->ipsec4_out_spd_hash_tbl[hash].bucket_lock);
  kv_result = im->ipsec4_out_spd_hash_tbl[hash];
  ipsec_spinlock_unlock (&im->ipsec4_out_spd_hash_tbl[hash].bucket_lock);

  if (ipsec4_hash_key_compare_16_8 ((u64 *) &ip4_5tuple.kv_16_8,
				    (u64 *) &kv_result))
    {
      if (im->epoch_count == ((u32) (kv_result.value & 0xFFFFFFFF)))
	{
	  /* Get the policy based on the index */
	  p =
	    pool_elt_at_index (im->policies, ((u32) (kv_result.value >> 32)));
	}
    }

  return p;
}

always_inline void
ipsec4_out_spd_add_flow_cache_entry (ipsec_main_t *im, u8 pr, u32 la, u32 ra,
				     u16 lp, u16 rp, u32 pol_id)
{
  u64 hash;
  u8 overwrite = 0, stale_overwrite = 0;
  ipsec4_spd_5tuple_t ip4_5tuple = { .ip4_addr = { (ip4_address_t) la,
						   (ip4_address_t) ra },
				     .port = { lp, rp },
				     .proto = pr };

  ip4_5tuple.kv_16_8.value = (((u64) pol_id) << 32) | ((u64) im->epoch_count);

  hash = ipsec4_hash_16_8 (&ip4_5tuple.kv_16_8);
  hash &= (im->ipsec4_out_spd_hash_num_buckets - 1);

  ipsec_spinlock_lock (&im->ipsec4_out_spd_hash_tbl[hash].bucket_lock);
  /* Check if we are overwriting an existing entry so we know
  whether to increment the flow cache counter. Since flow
  cache counter is reset on any policy add/remove, but
  hash table values are not, we also need to check if the entry
  we are overwriting is stale or not. If it's a stale entry
  overwrite, we still want to increment flow cache counter */
  overwrite = (im->ipsec4_out_spd_hash_tbl[hash].value != 0);
  /* Check for stale entry by comparing with current epoch count */
  if (PREDICT_FALSE (overwrite))
    stale_overwrite =
      (im->epoch_count !=
       ((u32) (im->ipsec4_out_spd_hash_tbl[hash].value & 0xFFFFFFFF)));
  clib_memcpy_fast (&im->ipsec4_out_spd_hash_tbl[hash], &ip4_5tuple.kv_16_8,
		    sizeof (ip4_5tuple.kv_16_8));
  ipsec_spinlock_unlock (&im->ipsec4_out_spd_hash_tbl[hash].bucket_lock);

  /* Increment the counter to track active flow cache entries
    when entering a fresh entry or overwriting a stale one */
  if (!overwrite || stale_overwrite)
    clib_atomic_fetch_add_relax (&im->ipsec4_out_spd_flow_cache_entries, 1);

  return;
}

always_inline ipsec_policy_t *
ipsec_output_policy_match (ipsec_spd_t *spd, u8 pr, u32 la, u32 ra, u16 lp,
			   u16 rp, u8 flow_cache_enabled)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  u32 *i;

  if (!spd)
    return 0;

  vec_foreach (i, spd->policies[IPSEC_SPD_POLICY_IP4_OUTBOUND])
    {
      p = pool_elt_at_index (im->policies, *i);
      if (PREDICT_FALSE (p->protocol && (p->protocol != pr)))
	continue;

      if (ra < clib_net_to_host_u32 (p->raddr.start.ip4.as_u32))
	continue;

      if (ra > clib_net_to_host_u32 (p->raddr.stop.ip4.as_u32))
	continue;

      if (la < clib_net_to_host_u32 (p->laddr.start.ip4.as_u32))
	continue;

      if (la > clib_net_to_host_u32 (p->laddr.stop.ip4.as_u32))
	continue;

      if (PREDICT_FALSE ((pr != IP_PROTOCOL_TCP) && (pr != IP_PROTOCOL_UDP) &&
			 (pr != IP_PROTOCOL_SCTP)))
	{
	  lp = 0;
	  rp = 0;
	  goto add_flow_cache;
	}

      if (lp < p->lport.start)
	continue;

      if (lp > p->lport.stop)
	continue;

      if (rp < p->rport.start)
	continue;

      if (rp > p->rport.stop)
	continue;

    add_flow_cache:
      if (flow_cache_enabled)
	{
	  /* Add an Entry in Flow cache */
	  ipsec4_out_spd_add_flow_cache_entry (
	    im, pr, clib_host_to_net_u32 (la), clib_host_to_net_u32 (ra),
	    clib_host_to_net_u16 (lp), clib_host_to_net_u16 (rp), *i);
	}

      return p;
    }
  return 0;
}

#endif /* !IPSEC_OUTPUT_H */
