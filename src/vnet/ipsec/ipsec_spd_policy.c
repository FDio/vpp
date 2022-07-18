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

#include <vnet/ipsec/ipsec.h>

/**
 * @brief
 * Policy packet & bytes counters
 */
vlib_combined_counter_main_t ipsec_spd_policy_counters = {
  .name = "policy",
  .stat_segment_name = "/net/ipsec/policy",
};

static int
ipsec_spd_entry_sort (void *a1, void *a2)
{
  ipsec_main_t *im = &ipsec_main;
  u32 *id1 = a1;
  u32 *id2 = a2;
  ipsec_policy_t *p1, *p2;

  p1 = pool_elt_at_index (im->policies, *id1);
  p2 = pool_elt_at_index (im->policies, *id2);
  if (p1 && p2)
    return p2->priority - p1->priority;

  return 0;
}

int
ipsec_policy_mk_type (bool is_outbound,
		      bool is_ipv6,
		      ipsec_policy_action_t action,
		      ipsec_spd_policy_type_t * type)
{
  if (is_outbound)
    {
      *type = (is_ipv6 ?
	       IPSEC_SPD_POLICY_IP6_OUTBOUND : IPSEC_SPD_POLICY_IP4_OUTBOUND);
      return (0);
    }
  else
    {
      switch (action)
	{
	case IPSEC_POLICY_ACTION_PROTECT:
	  *type = (is_ipv6 ?
		   IPSEC_SPD_POLICY_IP6_INBOUND_PROTECT :
		   IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT);
	  return (0);
	case IPSEC_POLICY_ACTION_BYPASS:
	  *type = (is_ipv6 ?
		   IPSEC_SPD_POLICY_IP6_INBOUND_BYPASS :
		   IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS);
	  return (0);
	case IPSEC_POLICY_ACTION_DISCARD:
	  *type = (is_ipv6 ?
		   IPSEC_SPD_POLICY_IP6_INBOUND_DISCARD :
		   IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD);
	  return (0);
	case IPSEC_POLICY_ACTION_RESOLVE:
	  break;
	}
    }

  /* Unsupported type */
  return (-1);
}

int
ipsec_add_del_policy (vlib_main_t * vm,
		      ipsec_policy_t * policy, int is_add, u32 * stat_index)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_t *spd = 0;
  ipsec_policy_t *vp;
  u32 spd_index;
  uword *p;

  p = hash_get (im->spd_index_by_spd_id, policy->id);

  if (!p)
    return VNET_API_ERROR_SYSCALL_ERROR_1;

  spd_index = p[0];
  spd = pool_elt_at_index (im->spds, spd_index);
  if (!spd)
    return VNET_API_ERROR_SYSCALL_ERROR_1;

  if (im->output_flow_cache_flag && !policy->is_ipv6 &&
      policy->type == IPSEC_SPD_POLICY_IP4_OUTBOUND)
    {
      /*
       * Flow cache entry is valid only when epoch_count value in control
       * plane and data plane match. Otherwise, flow cache entry is considered
       * stale. To avoid the race condition of using old epoch_count value
       * in data plane after the roll over of epoch_count in control plane,
       * entire flow cache is reset.
       */
      if (im->epoch_count == 0xFFFFFFFF)
	{
	  /* Reset all the entries in flow cache */
	  clib_memset_u8 (im->ipsec4_out_spd_hash_tbl, 0,
			  im->ipsec4_out_spd_hash_num_buckets *
			    (sizeof (*(im->ipsec4_out_spd_hash_tbl))));
	}
      /* Increment epoch counter by 1 */
      clib_atomic_fetch_add_relax (&im->epoch_count, 1);
      /* Reset spd flow cache counter since all old entries are stale */
      clib_atomic_store_relax_n (&im->ipsec4_out_spd_flow_cache_entries, 0);
    }

  if ((policy->type == IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT ||
       policy->type == IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS ||
       policy->type == IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD) &&
      im->input_flow_cache_flag && !policy->is_ipv6)
    {
      /*
       * Flow cache entry is valid only when input_epoch_count value in control
       * plane and data plane match. Otherwise, flow cache entry is considered
       * stale. To avoid the race condition of using old input_epoch_count
       * value in data plane after the roll over of input_epoch_count in
       * control plane, entire flow cache is reset.
       */
      if (im->input_epoch_count == 0xFFFFFFFF)
	{
	  /* Reset all the entries in flow cache */
	  clib_memset_u8 (im->ipsec4_in_spd_hash_tbl, 0,
			  im->ipsec4_in_spd_hash_num_buckets *
			    (sizeof (*(im->ipsec4_in_spd_hash_tbl))));
	}
      /* Increment epoch counter by 1 */
      clib_atomic_fetch_add_relax (&im->input_epoch_count, 1);
      /* Reset spd flow cache counter since all old entries are stale */
      im->ipsec4_in_spd_flow_cache_entries = 0;
    }

  if (is_add)
    {
      u32 policy_index;

      if (policy->policy == IPSEC_POLICY_ACTION_PROTECT)
	{
	  index_t sa_index = ipsec_sa_find_and_lock (policy->sa_id);

	  if (INDEX_INVALID == sa_index)
	    return VNET_API_ERROR_SYSCALL_ERROR_1;
	  policy->sa_index = sa_index;
	}
      else
	policy->sa_index = INDEX_INVALID;

      /**
       * Try adding the policy into fast path SPD first. Only adding to
       * traditional SPD when failed.
       **/
      if ((im->ipv4_fp_spd_is_enabled &&
	   policy->type == IPSEC_SPD_POLICY_IP4_OUTBOUND) ||
	  (im->ipv6_fp_spd_is_enabled &&
	   policy->type == IPSEC_SPD_POLICY_IP6_OUTBOUND))
	return ipsec_fp_add_del_policy ((void *) &spd->fp_spd, policy, 1,
					stat_index);

      pool_get (im->policies, vp);
      clib_memcpy (vp, policy, sizeof (*vp));
      policy_index = vp - im->policies;

      vlib_validate_combined_counter (&ipsec_spd_policy_counters,
				      policy_index);
      vlib_zero_combined_counter (&ipsec_spd_policy_counters, policy_index);
      vec_add1 (spd->policies[policy->type], policy_index);
      vec_sort_with_function (spd->policies[policy->type],
			      ipsec_spd_entry_sort);
      *stat_index = policy_index;
    }
  else
    {
      u32 ii;

      /**
       * Try to delete the policy from the fast path SPD first. Delete from
       * traditional SPD when fp delete fails.
       **/

      if ((im->ipv4_fp_spd_is_enabled &&
	   policy->type == IPSEC_SPD_POLICY_IP4_OUTBOUND) ||
	  (im->ipv6_fp_spd_is_enabled &&
	   policy->type == IPSEC_SPD_POLICY_IP6_OUTBOUND))
	return ipsec_fp_add_del_policy ((void *) &spd->fp_spd, policy, 0,
					stat_index);

      vec_foreach_index (ii, (spd->policies[policy->type]))
      {
	vp = pool_elt_at_index (im->policies,
				spd->policies[policy->type][ii]);
	if (ipsec_policy_is_equal (vp, policy))
	  {
	    vec_delete (spd->policies[policy->type], 1, ii);
	    ipsec_sa_unlock (vp->sa_index);
	    pool_put (im->policies, vp);
	    break;
	  }
      }
    }

  return 0;
}

static_always_inline void
release_mask_type_index (ipsec_main_t *im, u32 mask_type_index)
{
  ipsec_fp_mask_type_entry_t *mte =
    pool_elt_at_index (im->fp_mask_types, mask_type_index);
  mte->refcount--;
  if (mte->refcount == 0)
    {
      /* this entry is not in use anymore */
      ASSERT (clib_memset (mte, 0xae, sizeof (*mte)) == EOK);
      pool_put (im->fp_mask_types, mte);
    }
}

static_always_inline u32
find_mask_type_index (ipsec_main_t *im, ipsec_fp_5tuple_t *mask)
{
  ipsec_fp_mask_type_entry_t *mte;

  pool_foreach (mte, im->fp_mask_types)
    {
      if (memcmp (&mte->mask, mask, sizeof (*mask)) == 0)
	return (mte - im->fp_mask_types);
    }

  return ~0;
}

static_always_inline void
fill_ip6_hash_policy_kv (ipsec_fp_5tuple_t *match, ipsec_fp_5tuple_t *mask,
			 clib_bihash_kv_40_8_t *kv)
{
  ipsec_fp_lookup_value_t *kv_val = (ipsec_fp_lookup_value_t *) &kv->value;
  u64 *pmatch = (u64 *) match->kv_40_8.key;
  u64 *pmask = (u64 *) mask->kv_40_8.key;
  u64 *pkey = (u64 *) kv->key;

  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey = *pmatch & *pmask;

  kv_val->as_u64 = 0;
}

static_always_inline void
fill_ip4_hash_policy_kv (ipsec_fp_5tuple_t *match, ipsec_fp_5tuple_t *mask,
			 clib_bihash_kv_16_8_t *kv)
{
  ipsec_fp_lookup_value_t *kv_val = (ipsec_fp_lookup_value_t *) &kv->value;
  u64 *pmatch = (u64 *) match->kv_16_8.key;
  u64 *pmask = (u64 *) mask->kv_16_8.key;
  u64 *pkey = (u64 *) kv->key;

  *pkey++ = *pmatch++ & *pmask++;
  *pkey = *pmatch & *pmask;

  kv_val->as_u64 = 0;
}

static_always_inline u16
get_highest_set_bit_u16 (u16 x)
{
  x |= x >> 8;
  x |= x >> 4;
  x |= x >> 2;
  x |= x >> 1;
  return x ^= x >> 1;
}

static_always_inline u32
get_highest_set_bit_u32 (u32 x)
{
  x |= x >> 16;
  x |= x >> 8;
  x |= x >> 4;
  x |= x >> 2;
  x |= x >> 1;
  return x ^= x >> 1;
}

static_always_inline u64
mask_out_highest_set_bit_u64 (u64 x)
{
  x |= x >> 32;
  x |= x >> 16;
  x |= x >> 8;
  x |= x >> 4;
  x |= x >> 2;
  x |= x >> 1;
  return ~x;
}

static_always_inline void
ipsec_fp_get_policy_ports_mask (ipsec_policy_t *policy,
				ipsec_fp_5tuple_t *mask)
{
  if (PREDICT_TRUE ((policy->protocol == IP_PROTOCOL_TCP) ||
		    (policy->protocol == IP_PROTOCOL_UDP) ||
		    (policy->protocol == IP_PROTOCOL_SCTP)))
    {
      mask->lport = policy->lport.start ^ policy->lport.stop;
      mask->rport = policy->rport.start ^ policy->rport.stop;

      mask->lport = get_highest_set_bit_u16 (mask->lport);
      mask->lport = ~(mask->lport - 1) & (~mask->lport);

      mask->rport = get_highest_set_bit_u16 (mask->rport);
      mask->rport = ~(mask->rport - 1) & (~mask->rport);
    }
  else
    {
      mask->lport = 0;
      mask->rport = 0;
    }

  mask->protocol = (policy->protocol == IPSEC_POLICY_PROTOCOL_ANY) ? 0 : ~0;
}

static_always_inline void
ipsec_fp_ip4_get_policy_mask (ipsec_policy_t *policy, ipsec_fp_5tuple_t *mask)
{
  u32 *pladdr_start = (u32 *) &policy->laddr.start.ip4;
  u32 *pladdr_stop = (u32 *) &policy->laddr.stop.ip4;
  u32 *plmask = (u32 *) &mask->laddr;
  u32 *praddr_start = (u32 *) &policy->raddr.start.ip4;
  u32 *praddr_stop = (u32 *) &policy->raddr.stop.ip4;
  u32 *prmask = (u32 *) &mask->raddr;

  clib_memset_u8 (mask, 0xff, sizeof (ipsec_fp_5tuple_t));
  clib_memset_u8 (&mask->l3_zero_pad, 0, sizeof (mask->l3_zero_pad));

  /* find bits where start != stop */
  *plmask = *pladdr_start ^ *pladdr_stop;
  *prmask = *praddr_start ^ *praddr_stop;
  /* Find most significant bit set (that is the first position
   * start differs from stop). Mask out everything after that bit and
   * the bit itself. Remember that policy stores start and stop in the net
   * order.
   */
  *plmask = get_highest_set_bit_u32 (clib_net_to_host_u32 (*plmask));
  *plmask = clib_host_to_net_u32 (~(*plmask - 1) & (~*plmask));

  *prmask = get_highest_set_bit_u32 (clib_net_to_host_u32 (*prmask));
  *prmask = clib_host_to_net_u32 (~(*prmask - 1) & (~*prmask));

  if (PREDICT_TRUE ((policy->protocol == IP_PROTOCOL_TCP) ||
		    (policy->protocol == IP_PROTOCOL_UDP) ||
		    (policy->protocol == IP_PROTOCOL_SCTP)))
    {
      mask->lport = policy->lport.start ^ policy->lport.stop;
      mask->rport = policy->rport.start ^ policy->rport.stop;

      mask->lport = get_highest_set_bit_u16 (mask->lport);
      mask->lport = ~(mask->lport - 1) & (~mask->lport);

      mask->rport = get_highest_set_bit_u16 (mask->rport);
      mask->rport = ~(mask->rport - 1) & (~mask->rport);
    }
  else
    {
      mask->lport = 0;
      mask->rport = 0;
    }

  mask->protocol = (policy->protocol == IPSEC_POLICY_PROTOCOL_ANY) ? 0 : ~0;
}

static_always_inline void
ipsec_fp_ip6_get_policy_mask (ipsec_policy_t *policy, ipsec_fp_5tuple_t *mask)
{
  u64 *pladdr_start = (u64 *) &policy->laddr.start;
  u64 *pladdr_stop = (u64 *) &policy->laddr.stop;
  u64 *plmask = (u64 *) &mask->ip6_laddr;
  u64 *praddr_start = (u64 *) &policy->raddr.start;
  u64 *praddr_stop = (u64 *) &policy->raddr.stop;
  u64 *prmask = (u64 *) &mask->ip6_raddr;

  clib_memset_u8 (mask, 0xff, sizeof (ipsec_fp_5tuple_t));

  *plmask = (*pladdr_start++ ^ *pladdr_stop++);

  *prmask = (*praddr_start++ ^ *praddr_stop++);

  /* Find most significant bit set (that is the first position
   * start differs from stop). Mask out everything after that bit and
   * the bit itself. Remember that policy stores start and stop in the net
   * order.
   */
  *plmask = clib_host_to_net_u64 (
    mask_out_highest_set_bit_u64 (clib_net_to_host_u64 (*plmask)));

  if (*plmask++ & clib_host_to_net_u64 (0x1))
    {
      *plmask = (*pladdr_start ^ *pladdr_stop);
      *plmask = clib_host_to_net_u64 (
	mask_out_highest_set_bit_u64 (clib_net_to_host_u64 (*plmask)));
    }
  else
    *plmask = 0;

  *prmask = clib_host_to_net_u64 (
    mask_out_highest_set_bit_u64 (clib_net_to_host_u64 (*prmask)));

  if (*prmask++ & clib_host_to_net_u64 (0x1))
    {
      *prmask = (*pladdr_start ^ *pladdr_stop);
      *prmask = clib_host_to_net_u64 (
	mask_out_highest_set_bit_u64 (clib_net_to_host_u64 (*prmask)));
    }
  else
    *prmask = 0;

  ipsec_fp_get_policy_ports_mask (policy, mask);
}

static_always_inline void
ipsec_fp_get_policy_5tuple (ipsec_policy_t *policy, ipsec_fp_5tuple_t *tuple)
{
  memset (tuple, 0, sizeof (*tuple));
  tuple->is_ipv6 = policy->is_ipv6;
  if (tuple->is_ipv6)
    {
      tuple->ip6_laddr = policy->laddr.start.ip6;
      tuple->ip6_raddr = policy->raddr.start.ip6;
    }
  else
    {
      tuple->laddr = policy->laddr.start.ip4;
      tuple->raddr = policy->raddr.start.ip4;
    }

  tuple->protocol = policy->protocol;

  tuple->lport = policy->lport.start;
  tuple->rport = policy->rport.start;
}

int
ipsec_fp_ip4_add_policy (ipsec_main_t *im, ipsec_spd_fp_t *fp_spd,
			 ipsec_policy_t *policy, u32 *stat_index)
{
  u32 mask_index;
  ipsec_policy_t *vp;
  ipsec_fp_mask_type_entry_t *mte;
  u32 policy_index;
  clib_bihash_kv_16_8_t kv;
  clib_bihash_kv_16_8_t result;
  ipsec_fp_lookup_value_t *result_val =
    (ipsec_fp_lookup_value_t *) &result.value;
  ipsec_fp_lookup_value_t *key_val = (ipsec_fp_lookup_value_t *) &kv.value;

  ipsec_fp_5tuple_t mask, policy_5tuple;
  int res;

  ipsec_fp_ip4_get_policy_mask (policy, &mask);
  pool_get (im->policies, vp);
  policy_index = vp - im->policies;
  vlib_validate_combined_counter (&ipsec_spd_policy_counters, policy_index);
  vlib_zero_combined_counter (&ipsec_spd_policy_counters, policy_index);
  *stat_index = policy_index;
  mask_index = find_mask_type_index (im, &mask);

  if (mask_index == ~0)
    {
      /* mask type not found, we need to create a new entry */
      pool_get (im->fp_mask_types, mte);
      mask_index = mte - im->fp_mask_types;
      mte->refcount = 0;
    }
  else
    mte = im->fp_mask_types + mask_index;

  policy->fp_mask_type_id = mask_index;
  ipsec_fp_get_policy_5tuple (policy, &policy_5tuple);

  fill_ip4_hash_policy_kv (&policy_5tuple, &mask, &kv);

  res = clib_bihash_search_inline_2_16_8 (&fp_spd->fp_ip4_lookup_hash, &kv,
					  &result);
  if (res != 0)
    {
      /* key was not found crate a new entry */
      vec_add1 (key_val->fp_policies_ids, policy_index);
      res = clib_bihash_add_del_16_8 (&fp_spd->fp_ip4_lookup_hash, &kv, 1);
      if (res != 0)
	goto error;
    }
  else
    {

      if (vec_max_len (result_val->fp_policies_ids) !=
	  vec_len (result_val->fp_policies_ids))
	{
	  /* no need to resize */
	  vec_add1 (result_val->fp_policies_ids, policy_index);
	}
      else
	{
	  vec_add1 (result_val->fp_policies_ids, policy_index);

	  res =
	    clib_bihash_add_del_16_8 (&fp_spd->fp_ip4_lookup_hash, &result, 1);

	  if (res != 0)
	    goto error;
	}
    }

  if (mte->refcount == 0)
    {
      clib_memcpy (&mte->mask, &mask, sizeof (mask));
      mte->refcount = 0;
      vec_add1 (fp_spd->fp_mask_types[policy->type], mask_index);
    }

  mte->refcount++;
  vec_add1 (fp_spd->fp_policies[policy->type], policy_index);
  clib_memcpy (vp, policy, sizeof (*vp));

  return 0;

error:
  pool_put (im->policies, vp);
  release_mask_type_index (im, mask_index);
  return -1;
}

int
ipsec_fp_ip6_add_policy (ipsec_main_t *im, ipsec_spd_fp_t *fp_spd,
			 ipsec_policy_t *policy, u32 *stat_index)
{

  u32 mask_index;
  ipsec_policy_t *vp;
  ipsec_fp_mask_type_entry_t *mte;
  u32 policy_index;
  clib_bihash_kv_40_8_t kv;
  clib_bihash_kv_40_8_t result;
  ipsec_fp_lookup_value_t *result_val =
    (ipsec_fp_lookup_value_t *) &result.value;
  ipsec_fp_lookup_value_t *key_val = (ipsec_fp_lookup_value_t *) &kv.value;

  ipsec_fp_5tuple_t mask, policy_5tuple;
  int res;
  ipsec_fp_ip6_get_policy_mask (policy, &mask);

  pool_get (im->policies, vp);
  policy_index = vp - im->policies;
  vlib_validate_combined_counter (&ipsec_spd_policy_counters, policy_index);
  vlib_zero_combined_counter (&ipsec_spd_policy_counters, policy_index);
  *stat_index = policy_index;
  mask_index = find_mask_type_index (im, &mask);

  if (mask_index == ~0)
    {
      /* mask type not found, we need to create a new entry */
      pool_get (im->fp_mask_types, mte);
      mask_index = mte - im->fp_mask_types;
      mte->refcount = 0;
    }
  else
    mte = im->fp_mask_types + mask_index;

  policy->fp_mask_type_id = mask_index;
  ipsec_fp_get_policy_5tuple (policy, &policy_5tuple);

  fill_ip6_hash_policy_kv (&policy_5tuple, &mask, &kv);

  res = clib_bihash_search_inline_2_40_8 (&fp_spd->fp_ip6_lookup_hash, &kv,
					  &result);
  if (res != 0)
    {
      /* key was not found crate a new entry */
      vec_add1 (key_val->fp_policies_ids, policy_index);
      res = clib_bihash_add_del_40_8 (&fp_spd->fp_ip6_lookup_hash, &kv, 1);
      if (res != 0)
	goto error;
    }
  else
    {

      if (vec_max_len (result_val->fp_policies_ids) !=
	  vec_len (result_val->fp_policies_ids))
	{
	  /* no need to resize */
	  vec_add1 (result_val->fp_policies_ids, policy_index);
	}
      else
	{
	  vec_add1 (result_val->fp_policies_ids, policy_index);

	  res =
	    clib_bihash_add_del_40_8 (&fp_spd->fp_ip6_lookup_hash, &result, 1);

	  if (res != 0)
	    goto error;
	}
    }

  if (mte->refcount == 0)
    {
      clib_memcpy (&mte->mask, &mask, sizeof (mask));
      mte->refcount = 0;
      vec_add1 (fp_spd->fp_mask_types[policy->type], mask_index);
    }

  mte->refcount++;
  vec_add1 (fp_spd->fp_policies[policy->type], policy_index);
  clib_memcpy (vp, policy, sizeof (*vp));

  return 0;

error:
  pool_put (im->policies, vp);
  release_mask_type_index (im, mask_index);
  return -1;
}

int
ipsec_fp_ip6_del_policy (ipsec_main_t *im, ipsec_spd_fp_t *fp_spd,
			 ipsec_policy_t *policy)
{
  int res;
  ipsec_fp_5tuple_t mask = { 0 }, policy_5tuple;
  clib_bihash_kv_40_8_t kv;
  clib_bihash_kv_40_8_t result;
  ipsec_fp_lookup_value_t *result_val =
    (ipsec_fp_lookup_value_t *) &result.value;

  ipsec_policy_t *vp;
  u32 ii, iii, imt;

  ipsec_fp_ip6_get_policy_mask (policy, &mask);
  ipsec_fp_get_policy_5tuple (policy, &policy_5tuple);
  fill_ip6_hash_policy_kv (&policy_5tuple, &mask, &kv);
  res = clib_bihash_search_inline_2_40_8 (&fp_spd->fp_ip6_lookup_hash, &kv,
					  &result);
  if (res != 0)
    return -1;

  res = -1;
  vec_foreach_index (ii, result_val->fp_policies_ids)
    {
      vp =
	pool_elt_at_index (im->policies, *(result_val->fp_policies_ids + ii));
      if (ipsec_policy_is_equal (vp, policy))
	{
	  vec_foreach_index (iii, fp_spd->fp_policies[policy->type])
	    {
	      if (*(fp_spd->fp_policies[policy->type] + iii) ==
		  *(result_val->fp_policies_ids + ii))
		{
		  if (vec_len (result_val->fp_policies_ids) == 1)
		    {
		      vec_free (result_val->fp_policies_ids);
		      clib_bihash_add_del_40_8 (&fp_spd->fp_ip6_lookup_hash,
						&result, 0);
		    }
		  else
		    {
		      vec_del1 (result_val->fp_policies_ids, ii);
		    }
		  vec_del1 (fp_spd->fp_policies[policy->type], iii);

		  vec_foreach_index (imt, fp_spd->fp_mask_types[policy->type])
		    {
		      if (*(fp_spd->fp_mask_types[policy->type] + imt) ==
			  vp->fp_mask_type_id)
			{
			  ipsec_fp_mask_type_entry_t *mte = pool_elt_at_index (
			    im->fp_mask_types, vp->fp_mask_type_id);

			  if (mte->refcount == 1)
			    vec_del1 (fp_spd->fp_mask_types[policy->type],
				      imt);
			  break;
			}
		    }

		  res = 0;
		  break;
		}
	    }

	  if (res != 0)
	    continue;
	  else
	    {
	      release_mask_type_index (im, vp->fp_mask_type_id);
	      ipsec_sa_unlock (vp->sa_index);
	      pool_put (im->policies, vp);
	      return 0;
	    }
	}
    }
  return -1;
}

int
ipsec_fp_ip4_del_policy (ipsec_main_t *im, ipsec_spd_fp_t *fp_spd,
			 ipsec_policy_t *policy)
{
  int res;
  ipsec_fp_5tuple_t mask = { 0 }, policy_5tuple;
  clib_bihash_kv_16_8_t kv;
  clib_bihash_kv_16_8_t result;
  ipsec_fp_lookup_value_t *result_val =
    (ipsec_fp_lookup_value_t *) &result.value;

  ipsec_policy_t *vp;
  u32 ii, iii, imt;

  ipsec_fp_ip4_get_policy_mask (policy, &mask);
  ipsec_fp_get_policy_5tuple (policy, &policy_5tuple);
  fill_ip4_hash_policy_kv (&policy_5tuple, &mask, &kv);
  res = clib_bihash_search_inline_2_16_8 (&fp_spd->fp_ip4_lookup_hash, &kv,
					  &result);
  if (res != 0)
    return -1;

  res = -1;
  vec_foreach_index (ii, result_val->fp_policies_ids)
    {
      vp =
	pool_elt_at_index (im->policies, *(result_val->fp_policies_ids + ii));
      if (ipsec_policy_is_equal (vp, policy))
	{
	  vec_foreach_index (iii, fp_spd->fp_policies[policy->type])
	    {
	      if (*(fp_spd->fp_policies[policy->type] + iii) ==
		  *(result_val->fp_policies_ids + ii))
		{
		  if (vec_len (result_val->fp_policies_ids) == 1)
		    {
		      vec_free (result_val->fp_policies_ids);
		      clib_bihash_add_del_16_8 (&fp_spd->fp_ip4_lookup_hash,
						&result, 0);
		    }
		  else
		    {
		      vec_del1 (result_val->fp_policies_ids, ii);
		    }
		  vec_del1 (fp_spd->fp_policies[policy->type], iii);

		  vec_foreach_index (imt, fp_spd->fp_mask_types[policy->type])
		    {
		      if (*(fp_spd->fp_mask_types[policy->type] + imt) ==
			  vp->fp_mask_type_id)
			{
			  ipsec_fp_mask_type_entry_t *mte = pool_elt_at_index (
			    im->fp_mask_types, vp->fp_mask_type_id);

			  if (mte->refcount == 1)
			    vec_del1 (fp_spd->fp_mask_types[policy->type],
				      imt);
			  break;
			}
		    }

		  res = 0;
		  break;
		}
	    }

	  if (res != 0)
	    continue;
	  else
	    {
	      release_mask_type_index (im, vp->fp_mask_type_id);
	      ipsec_sa_unlock (vp->sa_index);
	      pool_put (im->policies, vp);
	      return 0;
	    }
	}
    }
  return -1;
}

int
ipsec_fp_add_del_policy (void *fp_spd, ipsec_policy_t *policy, int is_add,
			 u32 *stat_index)
{
  ipsec_main_t *im = &ipsec_main;

  if (is_add)
    if (policy->is_ipv6)
      return ipsec_fp_ip6_add_policy (im, (ipsec_spd_fp_t *) fp_spd, policy,
				      stat_index);
    else
      return ipsec_fp_ip4_add_policy (im, (ipsec_spd_fp_t *) fp_spd, policy,
				      stat_index);

  else if (policy->is_ipv6)

    return ipsec_fp_ip6_del_policy (im, (ipsec_spd_fp_t *) fp_spd, policy);
  else
    return ipsec_fp_ip4_del_policy (im, (ipsec_spd_fp_t *) fp_spd, policy);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
