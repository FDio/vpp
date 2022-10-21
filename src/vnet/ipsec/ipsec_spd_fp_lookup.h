/*
 *------------------------------------------------------------------
 * Copyright (c) 2022 Intel and/or its affiliates.
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

#ifndef IPSEC_SPD_FP_LOOKUP_H
#define IPSEC_SPD_FP_LOOKUP_H

#include <vnet/ipsec/ipsec.h>

static_always_inline int
single_rule_out_match_5tuple (ipsec_policy_t *policy, ipsec_fp_5tuple_t *match)
{
  if (PREDICT_FALSE (policy->is_ipv6 != match->is_ipv6))
    return (0);

  if (PREDICT_FALSE (policy->protocol != IPSEC_POLICY_PROTOCOL_ANY &&
		     (policy->protocol != match->protocol)))
    return (0);

  if (!policy->is_ipv6)
    {
      if (PREDICT_FALSE (
	    clib_net_to_host_u32 (match->laddr.as_u32) <
	    clib_net_to_host_u32 (policy->laddr.start.ip4.as_u32)))
	return (0);

      if (PREDICT_FALSE (clib_net_to_host_u32 (match->laddr.as_u32) >
			 clib_net_to_host_u32 (policy->laddr.stop.ip4.as_u32)))
	return (0);

      if (PREDICT_FALSE (
	    clib_net_to_host_u32 (match->raddr.as_u32) <
	    clib_net_to_host_u32 (policy->raddr.start.ip4.as_u32)))
	return (0);

      if (PREDICT_FALSE (clib_net_to_host_u32 (match->raddr.as_u32) >
			 clib_net_to_host_u32 (policy->raddr.stop.ip4.as_u32)))
	return (0);
    }
  else
    {

      if (ip6_address_compare (&match->ip6_laddr, &policy->laddr.start.ip6) <
	  0)
	return (0);

      if (ip6_address_compare (&policy->laddr.stop.ip6, &match->ip6_laddr) < 0)

	return (0);

      if (ip6_address_compare (&match->ip6_raddr, &policy->raddr.start.ip6) <
	  0)

	return (0);

      if (ip6_address_compare (&policy->raddr.stop.ip6, &match->ip6_raddr) < 0)

	return (0);
    }

  if (PREDICT_FALSE ((match->protocol != IP_PROTOCOL_TCP) &&
		     (match->protocol != IP_PROTOCOL_UDP) &&
		     (match->protocol != IP_PROTOCOL_SCTP)))
    {
      return (1);
    }

  if (match->lport < policy->lport.start)
    return (0);

  if (match->lport > policy->lport.stop)
    return (0);

  if (match->rport < policy->rport.start)
    return (0);

  if (match->rport > policy->rport.stop)
    return (0);

  return (1);
}

static_always_inline int
single_rule_in_match_5tuple (ipsec_policy_t *policy, ipsec_fp_5tuple_t *match)
{

  u32 da = clib_net_to_host_u32 (match->laddr.as_u32);
  u32 sa = clib_net_to_host_u32 (match->raddr.as_u32);

  if (policy->policy == IPSEC_POLICY_ACTION_PROTECT)
    {
      ipsec_sa_t *s = ipsec_sa_get (policy->sa_index);

      if (match->spi != s->spi)
	return (0);

      if (ipsec_sa_is_set_IS_TUNNEL (s))
	{
	  if (da != clib_net_to_host_u32 (s->tunnel.t_dst.ip.ip4.as_u32))
	    return (0);

	  if (sa != clib_net_to_host_u32 (s->tunnel.t_src.ip.ip4.as_u32))
	    return (0);
	}
    }
  else
    {
      if (sa < clib_net_to_host_u32 (policy->raddr.start.ip4.as_u32))
	return (0);

      if (sa > clib_net_to_host_u32 (policy->raddr.stop.ip4.as_u32))
	return (0);

      if (da < clib_net_to_host_u32 (policy->laddr.start.ip4.as_u32))
	return (0);

      if (da > clib_net_to_host_u32 (policy->laddr.stop.ip4.as_u32))
	return (0);
    }
  return (1);
}

static_always_inline u32
ipsec_fp_in_ip6_policy_match_n (void *spd_fp, ipsec_fp_5tuple_t *tuples,
				ipsec_policy_t **policies, u32 n)
{
  u32 last_priority[n];
  u32 i = 0;
  u32 counter = 0;
  ipsec_fp_mask_type_entry_t *mte;
  ipsec_fp_mask_id_t *mti;
  ipsec_fp_5tuple_t *match = tuples;
  ipsec_policy_t *policy;
  u32 n_left = n;
  clib_bihash_kv_40_8_t kv;
  /* result of the lookup */
  clib_bihash_kv_40_8_t result;
  ipsec_fp_lookup_value_t *result_val =
    (ipsec_fp_lookup_value_t *) &result.value;
  u64 *pkey, *pmatch, *pmask;
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_fp_t *pspd_fp = (ipsec_spd_fp_t *) spd_fp;
  ipsec_fp_mask_id_t *mask_type_ids = pspd_fp->fp_mask_ids[match->action];
  clib_bihash_40_8_t *bihash_table = pool_elt_at_index (
    im->fp_ip6_lookup_hashes_pool, pspd_fp->ip6_in_lookup_hash_idx);

  /* clear the list of matched policies pointers */
  clib_memset (policies, 0, n * sizeof (*policies));
  clib_memset (last_priority, 0, n * sizeof (u32));
  n_left = n;
  while (n_left)
    {
      vec_foreach (mti, mask_type_ids)
	{
	  mte = im->fp_mask_types + mti->mask_type_idx;
	  if (mte->mask.action == 0)
	    continue;

	  pmatch = (u64 *) match->kv_40_8.key;
	  pmask = (u64 *) mte->mask.kv_40_8.key;
	  pkey = (u64 *) kv.key;

	  *pkey++ = *pmatch++ & *pmask++;
	  *pkey++ = *pmatch++ & *pmask++;
	  *pkey++ = *pmatch++ & *pmask++;
	  *pkey++ = *pmatch++ & *pmask++;
	  *pkey = *pmatch & *pmask;

	  int res =
	    clib_bihash_search_inline_2_40_8 (bihash_table, &kv, &result);
	  /* lookup the hash by each packet in the burst for this mask. */

	  if (res == 0)
	    {
	      /* There is a hit in the hash table. */
	      /* Find the policy with highest priority. */
	      /* Store the lookup results in a dedicated array. */

	      if (vec_len (result_val->fp_policies_ids) > 1)
		{
		  u32 *policy_id;
		  vec_foreach (policy_id, result_val->fp_policies_ids)
		    {
		      policy = im->policies + *policy_id;

		      if ((last_priority[i] < policy->priority) &&
			  (single_rule_in_match_5tuple (policy, match)))
			{
			  last_priority[i] = policy->priority;
			  if (policies[i] == 0)
			    counter++;
			  policies[i] = policy;
			}
		    }
		}
	      else
		{
		  u32 *policy_id;
		  ASSERT (vec_len (result_val->fp_policies_ids) == 1);
		  policy_id = result_val->fp_policies_ids;
		  policy = im->policies + *policy_id;
		  if ((last_priority[i] < policy->priority) &&
		      (single_rule_in_match_5tuple (policy, match)))
		    {
		      last_priority[i] = policy->priority;
		      if (policies[i] == 0)
			counter++;
		      policies[i] = policy;
		    }
		}
	    }
	}

      i++;
      n_left--;
      match++;
    }
  return counter;
}

static_always_inline u32
ipsec_fp_in_ip4_policy_match_n (void *spd_fp, ipsec_fp_5tuple_t *tuples,
				ipsec_policy_t **policies, u32 n)

{
  u32 last_priority[n];
  u32 i = 0;
  u32 counter = 0;
  ipsec_fp_mask_type_entry_t *mte;
  ipsec_fp_mask_id_t *mti;
  ipsec_fp_5tuple_t *match = tuples;
  ipsec_policy_t *policy;
  u32 n_left = n;
  clib_bihash_kv_16_8_t kv;
  /* result of the lookup */
  clib_bihash_kv_16_8_t result;
  ipsec_fp_lookup_value_t *result_val =
    (ipsec_fp_lookup_value_t *) &result.value;
  u64 *pkey, *pmatch, *pmask;
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_fp_t *pspd_fp = (ipsec_spd_fp_t *) spd_fp;
  ipsec_fp_mask_id_t *mask_type_ids = pspd_fp->fp_mask_ids[match->action];
  clib_bihash_16_8_t *bihash_table = pool_elt_at_index (
    im->fp_ip4_lookup_hashes_pool, pspd_fp->ip4_in_lookup_hash_idx);

  /* clear the list of matched policies pointers */
  clib_memset (policies, 0, n * sizeof (*policies));
  clib_memset (last_priority, 0, n * sizeof (u32));
  n_left = n;
  while (n_left)
    {
      vec_foreach (mti, mask_type_ids)
	{
	  mte = im->fp_mask_types + mti->mask_type_idx;
	  if (mte->mask.action == 0)
	    continue;
	  pmatch = (u64 *) match->kv_16_8.key;
	  pmask = (u64 *) mte->mask.kv_16_8.key;
	  pkey = (u64 *) kv.key;

	  *pkey++ = *pmatch++ & *pmask++;
	  *pkey = *pmatch & *pmask;

	  int res =
	    clib_bihash_search_inline_2_16_8 (bihash_table, &kv, &result);
	  /* lookup the hash by each packet in the burst for this mask. */

	  if (res == 0)
	    {
	      /* There is a hit in the hash table. */
	      /* Find the policy with highest priority. */
	      /* Store the lookup results in a dedicated array. */

	      if (vec_len (result_val->fp_policies_ids) > 1)
		{
		  u32 *policy_id;
		  vec_foreach (policy_id, result_val->fp_policies_ids)
		    {
		      policy = im->policies + *policy_id;

		      if ((last_priority[i] < policy->priority) &&
			  (single_rule_in_match_5tuple (policy, match)))
			{
			  last_priority[i] = policy->priority;
			  if (policies[i] == 0)
			    counter++;
			  policies[i] = policy;
			}
		    }
		}
	      else
		{
		  u32 *policy_id;
		  ASSERT (vec_len (result_val->fp_policies_ids) == 1);
		  policy_id = result_val->fp_policies_ids;
		  policy = im->policies + *policy_id;
		  if ((last_priority[i] < policy->priority) &&
		      (single_rule_in_match_5tuple (policy, match)))
		    {
		      last_priority[i] = policy->priority;
		      if (policies[i] == 0)
			counter++;
		      policies[i] = policy;
		    }
		}
	    }
	}

      i++;
      n_left--;
      match++;
    }
  return counter;
}

/**
 * @brief function handler to perform lookup in fastpath SPD
 * for inbound traffic burst of n packets
 **/

static_always_inline u32
ipsec_fp_in_policy_match_n (void *spd_fp, u8 is_ipv6,
			    ipsec_fp_5tuple_t *tuples,
			    ipsec_policy_t **policies, u32 n)
{
  if (is_ipv6)
    return ipsec_fp_in_ip6_policy_match_n (spd_fp, tuples, policies, n);
  else
    return ipsec_fp_in_ip4_policy_match_n (spd_fp, tuples, policies, n);
}

static_always_inline u32
ipsec_fp_out_ip6_policy_match_n (void *spd_fp, ipsec_fp_5tuple_t *tuples,
				 ipsec_policy_t **policies, u32 *ids, u32 n)

{
  u32 last_priority[n];
  u32 i = 0;
  u32 counter = 0;
  ipsec_fp_mask_type_entry_t *mte;
  ipsec_fp_mask_id_t *mti;
  ipsec_fp_5tuple_t *match = tuples;
  ipsec_policy_t *policy;

  u32 n_left = n;
  clib_bihash_kv_40_8_t kv;
  /* result of the lookup */
  clib_bihash_kv_40_8_t result;
  ipsec_fp_lookup_value_t *result_val =
    (ipsec_fp_lookup_value_t *) &result.value;
  u64 *pkey, *pmatch, *pmask;
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_fp_t *pspd_fp = (ipsec_spd_fp_t *) spd_fp;
  ipsec_fp_mask_id_t *mask_type_ids =
    pspd_fp->fp_mask_ids[IPSEC_SPD_POLICY_IP6_OUTBOUND];
  clib_bihash_40_8_t *bihash_table = pool_elt_at_index (
    im->fp_ip6_lookup_hashes_pool, pspd_fp->ip6_out_lookup_hash_idx);

  /*clear the list of matched policies pointers */
  clib_memset (policies, 0, n * sizeof (*policies));
  clib_memset (last_priority, 0, n * sizeof (u32));
  n_left = n;
  while (n_left)
    {
      vec_foreach (mti, mask_type_ids)
	{
	  mte = im->fp_mask_types + mti->mask_type_idx;
	  if (mte->mask.action != 0)
	    continue;

	  pmatch = (u64 *) match->kv_40_8.key;
	  pmask = (u64 *) mte->mask.kv_40_8.key;
	  pkey = (u64 *) kv.key;

	  *pkey++ = *pmatch++ & *pmask++;
	  *pkey++ = *pmatch++ & *pmask++;
	  *pkey++ = *pmatch++ & *pmask++;
	  *pkey++ = *pmatch++ & *pmask++;
	  *pkey = *pmatch & *pmask;

	  int res =
	    clib_bihash_search_inline_2_40_8 (bihash_table, &kv, &result);
	  /* lookup the hash by each packet in the burst for this mask. */

	  if (res == 0)
	    {
	      /* There is a hit in the hash table. */
	      /* Find the policy with highest priority. */
	      /* Store the lookup results in a dedicated array. */

	      if (vec_len (result_val->fp_policies_ids) > 1)
		{
		  u32 *policy_id;
		  vec_foreach (policy_id, result_val->fp_policies_ids)
		    {
		      policy = im->policies + *policy_id;

		      if (single_rule_out_match_5tuple (policy, match))
			{
			  if (last_priority[i] < policy->priority)
			    {
			      last_priority[i] = policy->priority;
			      if (policies[i] == 0)
				counter++;
			      policies[i] = policy;
			      ids[i] = *policy_id;
			    }
			}
		    }
		}
	      else
		{
		  u32 *policy_id;
		  ASSERT (vec_len (result_val->fp_policies_ids) == 1);
		  policy_id = result_val->fp_policies_ids;
		  policy = im->policies + *policy_id;
		  if (single_rule_out_match_5tuple (policy, match))
		    {
		      if (last_priority[i] < policy->priority)
			{
			  last_priority[i] = policy->priority;
			  if (policies[i] == 0)
			    counter++;
			  policies[i] = policy;
			  ids[i] = *policy_id;
			}
		    }
		}
	    }
	}
      n_left--;
      match++;
      i++;
    }
  return counter;
}

static_always_inline u32
ipsec_fp_out_ip4_policy_match_n (void *spd_fp, ipsec_fp_5tuple_t *tuples,
				 ipsec_policy_t **policies, u32 *ids, u32 n)

{
  u32 last_priority[n];
  u32 i = 0;
  u32 counter = 0;
  ipsec_fp_mask_type_entry_t *mte;
  ipsec_fp_mask_id_t *mti;
  ipsec_fp_5tuple_t *match = tuples;
  ipsec_policy_t *policy;

  u32 n_left = n;
  clib_bihash_kv_16_8_t kv;
  /* result of the lookup */
  clib_bihash_kv_16_8_t result;
  ipsec_fp_lookup_value_t *result_val =
    (ipsec_fp_lookup_value_t *) &result.value;
  u64 *pkey, *pmatch, *pmask;
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_fp_t *pspd_fp = (ipsec_spd_fp_t *) spd_fp;
  ipsec_fp_mask_id_t *mask_type_ids =
    pspd_fp->fp_mask_ids[IPSEC_SPD_POLICY_IP4_OUTBOUND];
  clib_bihash_16_8_t *bihash_table = pool_elt_at_index (
    im->fp_ip4_lookup_hashes_pool, pspd_fp->ip4_out_lookup_hash_idx);

  /* clear the list of matched policies pointers */
  clib_memset (policies, 0, n * sizeof (*policies));
  clib_memset (last_priority, 0, n * sizeof (u32));
  n_left = n;
  while (n_left)
    {
      vec_foreach (mti, mask_type_ids)
	{
	  mte = im->fp_mask_types + mti->mask_type_idx;
	  if (mte->mask.action != 0)
	    continue;

	  pmatch = (u64 *) match->kv_16_8.key;
	  pmask = (u64 *) mte->mask.kv_16_8.key;
	  pkey = (u64 *) kv.key;

	  *pkey++ = *pmatch++ & *pmask++;
	  *pkey = *pmatch & *pmask;

	  int res =
	    clib_bihash_search_inline_2_16_8 (bihash_table, &kv, &result);
	  /* lookup the hash by each packet in the burst for this mask. */

	  if (res == 0)
	    {
	      /* There is a hit in the hash table. */
	      /* Find the policy with highest priority. */
	      /* Store the lookup results in a dedicated array. */

	      if (vec_len (result_val->fp_policies_ids) > 1)
		{
		  u32 *policy_id;
		  vec_foreach (policy_id, result_val->fp_policies_ids)
		    {
		      policy = im->policies + *policy_id;

		      if ((last_priority[i] < policy->priority) &&
			  (single_rule_out_match_5tuple (policy, match)))
			{
			  last_priority[i] = policy->priority;
			  if (policies[i] == 0)
			    counter++;
			  policies[i] = policy;
			  ids[i] = *policy_id;
			}
		    }
		}
	      else
		{
		  u32 *policy_id;
		  ASSERT (vec_len (result_val->fp_policies_ids) == 1);
		  policy_id = result_val->fp_policies_ids;
		  policy = im->policies + *policy_id;
		  if ((last_priority[i] < policy->priority) &&
		      (single_rule_out_match_5tuple (policy, match)))
		    {
		      last_priority[i] = policy->priority;
		      if (policies[i] == 0)
			counter++;
		      policies[i] = policy;
		      ids[i] = *policy_id;
		    }
		}
	    }
	}

      i++;
      n_left--;
      match++;
    }
  return counter;
}

/**
 * @brief function handler to perform lookup in fastpath SPD
 * for outbound traffic burst of n packets
 * returns number of successfully matched policies
 **/

static_always_inline u32
ipsec_fp_out_policy_match_n (void *spd_fp, u8 is_ipv6,
			     ipsec_fp_5tuple_t *tuples,
			     ipsec_policy_t **policies, u32 *ids, u32 n)

{
  if (is_ipv6)
    return ipsec_fp_out_ip6_policy_match_n (spd_fp, tuples, policies, ids, n);
  else
    return ipsec_fp_out_ip4_policy_match_n (spd_fp, tuples, policies, ids, n);
}

#endif /* !IPSEC_SPD_FP_LOOKUP_H */
