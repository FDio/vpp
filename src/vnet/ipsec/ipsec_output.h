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
#include <vnet/ipsec/ipsec_spd_fp_lookup.h>

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

always_inline void
ipsec4_out_spd_add_flow_cache_entry_n (ipsec_main_t *im,
				       ipsec4_spd_5tuple_t *ip4_5tuple,
				       u32 pol_id)
{
  u64 hash;
  u8 overwrite = 0, stale_overwrite = 0;

  ip4_5tuple->kv_16_8.value = (((u64) pol_id) << 32) | ((u64) im->epoch_count);

  hash = ipsec4_hash_16_8 (&ip4_5tuple->kv_16_8);
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
  clib_memcpy_fast (&im->ipsec4_out_spd_hash_tbl[hash], &ip4_5tuple->kv_16_8,
		    sizeof (ip4_5tuple->kv_16_8));
  ipsec_spinlock_unlock (&im->ipsec4_out_spd_hash_tbl[hash].bucket_lock);

  /* Increment the counter to track active flow cache entries
    when entering a fresh entry or overwriting a stale one */
  if (!overwrite || stale_overwrite)
    clib_atomic_fetch_add_relax (&im->ipsec4_out_spd_flow_cache_entries, 1);

  return;
}

always_inline void
ipsec_fp_5tuple_from_ip4_range (ipsec_fp_5tuple_t *tuple, u32 la, u32 ra,
				u16 lp, u16 rp, u8 pr)
{
  clib_memset (tuple->l3_zero_pad, 0, sizeof (tuple->l3_zero_pad));
  tuple->laddr.as_u32 = clib_host_to_net_u32 (la);
  tuple->raddr.as_u32 = clib_host_to_net_u32 (ra);

  if (PREDICT_FALSE ((pr != IP_PROTOCOL_TCP) && (pr != IP_PROTOCOL_UDP) &&
		     (pr != IP_PROTOCOL_SCTP)))
    {
      tuple->lport = 0;
      tuple->rport = 0;
    }
  else
    {
      tuple->lport = lp;
      tuple->rport = rp;
    }

  tuple->protocol = pr;
  tuple->is_ipv6 = 0;
}

always_inline void
ipsec_fp_5tuple_from_ip4_range_n (ipsec_fp_5tuple_t *tuples,
				  ipsec4_spd_5tuple_t *ip4_5tuple, u32 n)
{
  u32 n_left = n;
  ipsec_fp_5tuple_t *tuple = tuples;

  while (n_left)
    {
      clib_memset (tuple->l3_zero_pad, 0, sizeof (tuple->l3_zero_pad));
      tuple->laddr.as_u32 =
	clib_host_to_net_u32 (ip4_5tuple->ip4_addr[0].as_u32);
      tuple->raddr.as_u32 =
	clib_host_to_net_u32 (ip4_5tuple->ip4_addr[1].as_u32);
      if (PREDICT_FALSE ((ip4_5tuple->proto != IP_PROTOCOL_TCP) &&
			 (ip4_5tuple->proto != IP_PROTOCOL_UDP) &&
			 (ip4_5tuple->proto != IP_PROTOCOL_SCTP)))
	{
	  tuple->lport = 0;
	  tuple->rport = 0;
	}
      else
	{
	  tuple->lport = ip4_5tuple->port[0];
	  tuple->rport = ip4_5tuple->port[1];
	}
      tuple->protocol = ip4_5tuple->proto;
      tuple->is_ipv6 = 0;
      n_left--;
      tuple++;
    }
}

always_inline int
ipsec_output_policy_match_n (ipsec_spd_t *spd,
			     ipsec4_spd_5tuple_t *ip4_5tuples,
			     ipsec_policy_t **policies, u32 n,
			     u8 flow_cache_enabled)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_policy_t **pp = policies;
  u32 n_left = n;
  ipsec4_spd_5tuple_t *ip4_5tuple = ip4_5tuples;
  u32 policy_ids[n], *policy_id = policy_ids;
  ipsec_fp_5tuple_t tuples[n];
  u32 *i;
  u32 counter = 0;

  if (!spd)
    return 0;

  clib_memset (policies, 0, n * sizeof (ipsec_policy_t *));

  if (im->fp_spd_ipv4_out_is_enabled &&
      PREDICT_TRUE (INDEX_INVALID != spd->fp_spd.ip4_out_lookup_hash_idx))
    {
      ipsec_fp_5tuple_from_ip4_range_n (tuples, ip4_5tuples, n);
      counter += ipsec_fp_out_policy_match_n (&spd->fp_spd, 0, tuples,
					      policies, policy_ids, n);
    }

  while (n_left)
    {
      if (*pp != 0)
	goto next;

      vec_foreach (i, spd->policies[IPSEC_SPD_POLICY_IP4_OUTBOUND])
	{
	  p = pool_elt_at_index (im->policies, *i);
	  if (PREDICT_FALSE (p->protocol &&
			     (p->protocol != ip4_5tuple->proto)))
	    continue;

	  if (ip4_5tuple->ip4_addr[0].as_u32 <
	      clib_net_to_host_u32 (p->raddr.start.ip4.as_u32))
	    continue;

	  if (ip4_5tuple->ip4_addr[1].as_u32 >
	      clib_net_to_host_u32 (p->raddr.stop.ip4.as_u32))
	    continue;

	  if (ip4_5tuple->ip4_addr[0].as_u32 <
	      clib_net_to_host_u32 (p->laddr.start.ip4.as_u32))
	    continue;

	  if (ip4_5tuple->ip4_addr[1].as_u32 >
	      clib_net_to_host_u32 (p->laddr.stop.ip4.as_u32))
	    continue;

	  if (PREDICT_FALSE ((ip4_5tuple->proto != IP_PROTOCOL_TCP) &&
			     (ip4_5tuple->proto != IP_PROTOCOL_UDP) &&
			     (ip4_5tuple->proto != IP_PROTOCOL_SCTP)))
	    {
	      ip4_5tuple->port[0] = 0;
	      ip4_5tuple->port[1] = 0;
	      goto add_policy;
	    }

	  if (ip4_5tuple->port[0] < p->lport.start)
	    continue;

	  if (ip4_5tuple->port[0] > p->lport.stop)
	    continue;

	  if (ip4_5tuple->port[1] < p->rport.start)
	    continue;

	  if (ip4_5tuple->port[1] > p->rport.stop)
	    continue;

	add_policy:
	  *pp = p;
	  *policy_id = *i;
	  counter++;
	  break;
	}

    next:
      n_left--;
      pp++;
      ip4_5tuple++;
      policy_id++;
    }

  if (flow_cache_enabled)
    {
      n_left = n;
      policy_id = policy_ids;
      ip4_5tuple = ip4_5tuples;
      pp = policies;

      while (n_left)
	{
	  if (*pp != NULL)
	    {
	      /* Add an Entry in Flow cache */
	      ipsec4_out_spd_add_flow_cache_entry_n (im, ip4_5tuple,
						     *policy_id);
	    }

	  n_left--;
	  policy_id++;
	  ip4_5tuple++;
	  pp++;
	}
    }

  return counter;
}

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

always_inline ipsec_policy_t *
ipsec_output_policy_match (ipsec_spd_t *spd, u8 pr, u32 la, u32 ra, u16 lp,
			   u16 rp, u8 flow_cache_enabled)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_policy_t *policies[1];
  ipsec_fp_5tuple_t tuples[1];
  u32 fp_policy_ids[1];

  u32 *i;

  if (!spd)
    return 0;

  if (im->fp_spd_ipv4_out_is_enabled &&
      PREDICT_TRUE (INDEX_INVALID != spd->fp_spd.ip4_out_lookup_hash_idx))
    {
      ipsec_fp_5tuple_from_ip4_range (&tuples[0], la, ra, lp, rp, pr);
      ipsec_fp_out_policy_match_n (&spd->fp_spd, 0, tuples, policies,
				   fp_policy_ids, 1);
      p = policies[0];
      i = fp_policy_ids;
      if (PREDICT_FALSE ((pr != IP_PROTOCOL_TCP) && (pr != IP_PROTOCOL_UDP) &&
			 (pr != IP_PROTOCOL_SCTP)))
	{
	  lp = 0;
	  rp = 0;
	}
      goto add_flow_cache;
    }

  vec_foreach (i, spd->policies[IPSEC_SPD_POLICY_IP4_OUTBOUND])
    {
      p = pool_elt_at_index (im->policies, *i);
      if (PREDICT_FALSE ((p->protocol != IPSEC_POLICY_PROTOCOL_ANY) &&
			 (p->protocol != pr)))
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

always_inline uword
ip6_addr_match_range (ip6_address_t *a, ip6_address_t *la, ip6_address_t *ua)
{
  if ((memcmp (a->as_u64, la->as_u64, 2 * sizeof (u64)) >= 0) &&
      (memcmp (a->as_u64, ua->as_u64, 2 * sizeof (u64)) <= 0))
    return 1;
  return 0;
}

always_inline void
ipsec_fp_5tuple_from_ip6_range (ipsec_fp_5tuple_t *tuple, ip6_address_t *la,
				ip6_address_t *ra, u16 lp, u16 rp, u8 pr)

{
  clib_memcpy (&tuple->ip6_laddr, la, sizeof (ip6_address_t));
  clib_memcpy (&tuple->ip6_raddr, ra, sizeof (ip6_address_t));

  tuple->lport = lp;
  tuple->rport = rp;
  tuple->protocol = pr;
  tuple->is_ipv6 = 1;
}

always_inline ipsec_policy_t *
ipsec6_output_policy_match (ipsec_spd_t *spd, ip6_address_t *la,
			    ip6_address_t *ra, u16 lp, u16 rp, u8 pr)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_policy_t *policies[1];
  ipsec_fp_5tuple_t tuples[1];
  u32 fp_policy_ids[1];

  u32 *i;

  if (!spd)
    return 0;

  if (im->fp_spd_ipv6_out_is_enabled &&
      PREDICT_TRUE (INDEX_INVALID != spd->fp_spd.ip6_out_lookup_hash_idx))
    {

      ipsec_fp_5tuple_from_ip6_range (&tuples[0], la, ra, lp, rp, pr);
      ipsec_fp_out_policy_match_n (&spd->fp_spd, 1, tuples, policies,
				   fp_policy_ids, 1);
      p = policies[0];
      i = fp_policy_ids;
      return p;
    }

  vec_foreach (i, spd->policies[IPSEC_SPD_POLICY_IP6_OUTBOUND])
    {
      p = pool_elt_at_index (im->policies, *i);
      if (PREDICT_FALSE ((p->protocol != IPSEC_POLICY_PROTOCOL_ANY) &&
			 (p->protocol != pr)))
	continue;

      if (!ip6_addr_match_range (ra, &p->raddr.start.ip6, &p->raddr.stop.ip6))
	continue;

      if (!ip6_addr_match_range (la, &p->laddr.start.ip6, &p->laddr.stop.ip6))
	continue;

      if (PREDICT_FALSE ((pr != IP_PROTOCOL_TCP) && (pr != IP_PROTOCOL_UDP) &&
			 (pr != IP_PROTOCOL_SCTP)))
	return p;

      if (lp < p->lport.start)
	continue;

      if (lp > p->lport.stop)
	continue;

      if (rp < p->rport.start)
	continue;

      if (rp > p->rport.stop)
	continue;

      return p;
    }

  return 0;
}

#endif /* !IPSEC_OUTPUT_H */
