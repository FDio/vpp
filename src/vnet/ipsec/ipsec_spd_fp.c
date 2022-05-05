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

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_spd_fp.h>

always_inline void
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
fill_ip6_hash_policy_kv (ipsec_main_t *im, ipsec_fp_5tuple_t *match,
			 ipsec_fp_5tuple_t *mask, clib_bihash_kv_40_8_t *kv)
{
  ipsec_fp_lookup_value_t *kv_val = (ipsec_fp_lookup_value_t *) &kv->value;
  u64 *pmatch = (u64 *) match;
  u64 *pmask = (u64 *) mask;
  u64 *pkey = (u64 *) kv->key;

  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;

  kv_val->as_u64 = 0;
}

static_always_inline void
fill_ip4_hash_policy_kv (ipsec_main_t *im, ipsec_fp_5tuple_t *match,
			 ipsec_fp_5tuple_t *mask, clib_bihash_kv_16_8_t *kv)
{
  ipsec_fp_lookup_value_t *kv_val = (ipsec_fp_lookup_value_t *) &kv->value;
  u64 *pmatch = (u64 *) &match->laddr;
  u64 *pmask = (u64 *) &mask->laddr;
  u64 *pkey = (u64 *) kv->key;

  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;

  kv_val->as_u64 = 0;
}

static_always_inline int
ipsec_fp_get_policy_mask (ipsec_policy_t *policy, ipsec_fp_5tuple_t *mask)
{
  u64 *pladdr_start = (u64 *) &policy->laddr.start;
  u64 *pladdr_stop = (u64 *) &policy->laddr.stop;
  u64 *plmask = (u64 *) &mask->laddr;
  u64 *praddr_start = (u64 *) &policy->raddr.start;
  u64 *praddr_stop = (u64 *) &policy->raddr.stop;
  u64 *prmask = (u64 *) &mask->ip6_raddr;

  /* test if x is not power of 2. The test form is  !((x & (x - 1)) == 0) */
  if (((*pladdr_stop - *pladdr_start + 1) & (*pladdr_stop - *pladdr_start)) &&
      (((*(pladdr_stop + 1) - *(pladdr_start + 1)) + 1) &
       (*(pladdr_stop + 1) - *(pladdr_start + 1))))
    return -1;

  if (((*praddr_stop - *praddr_start + 1) & (*praddr_stop - *praddr_start)) &&
      (((*(praddr_stop + 1) - *(praddr_start + 1)) + 1) &
       (*(praddr_stop + 1) - *(praddr_start + 1))))
    return -1;

  memset (mask, 1, sizeof (ipsec_fp_5tuple_t));

  *plmask++ = ~(*pladdr_start++ ^ *pladdr_stop++);
  *plmask++ = ~(*pladdr_start++ ^ *pladdr_stop++);

  *prmask++ = ~(*praddr_start++ ^ *praddr_stop++);
  *prmask++ = ~(*praddr_start++ ^ *praddr_stop++);

  mask->lport = ~(policy->lport.start ^ policy->lport.stop);
  mask->rport = ~(policy->rport.start ^ policy->rport.stop);
  mask->is_ipv6 = policy->is_ipv6;
  mask->protocol = policy->protocol;
  return 0;
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
  if (!PREDICT_FALSE ((policy->protocol != IP_PROTOCOL_TCP) &&
		      (policy->protocol != IP_PROTOCOL_UDP) &&
		      (policy->protocol != IP_PROTOCOL_SCTP)))
    {
      tuple->lport = policy->lport.start;
      tuple->rport = policy->rport.start;
    }
  else
    {
      tuple->lport = 0;
      tuple->rport = 0;
    }
}

int
ipsec_fp_ip4_add_policy (ipsec_main_t *im, ipsec_spd_fp_t *fp_spd,
			 ipsec_policy_t *policy)
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
  /* u64 hash; */

  if (PREDICT_FALSE (!fp_spd->fp_ip4_lookup_hash_initialized))
    {
      clib_bihash_init_16_8 (
	&fp_spd->fp_ip4_lookup_hash, "SPD_FP ip4 rules lookup bihash",
	im->ipsec4_out_spd_hash_num_buckets,
	im->ipsec4_out_spd_hash_num_buckets * sizeof (ipsec_fp_5tuple_t));
      fp_spd->fp_ip4_lookup_hash_initialized = 1;
    }

  if (ipsec_fp_get_policy_mask (policy, &mask) != 0)
    return -1;

  pool_get (im->policies, vp);

  policy_index = vp - im->policies;
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
  ipsec_fp_get_policy_mask (policy, &mask);
  ipsec_fp_get_policy_5tuple (policy, &policy_5tuple);

  fill_ip4_hash_policy_kv (im, &policy_5tuple, &mask, &kv);

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
			 ipsec_policy_t *policy)
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
  /* u64 hash; */

  if (PREDICT_FALSE (!fp_spd->fp_ip6_lookup_hash_initialized))
    {
      clib_bihash_init_40_8 (
	&fp_spd->fp_ip6_lookup_hash, "SPD_FP ip6 rules lookup bihash",
	im->fp_lookup_hash_buckets, im->fp_lookup_hash_memory);

      fp_spd->fp_ip6_lookup_hash_initialized = 1;
    }

  if (ipsec_fp_get_policy_mask (policy, &mask) != 0)
    return -1;

  pool_get (im->policies, vp);

  policy_index = vp - im->policies;
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
  ipsec_fp_get_policy_mask (policy, &mask);
  ipsec_fp_get_policy_5tuple (policy, &policy_5tuple);

  fill_ip6_hash_policy_kv (im, &policy_5tuple, &mask, &kv);

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
  ipsec_fp_5tuple_t mask, policy_5tuple;
  clib_bihash_kv_40_8_t kv;
  clib_bihash_kv_40_8_t result;
  ipsec_fp_lookup_value_t *result_val =
    (ipsec_fp_lookup_value_t *) &result.value;

  ipsec_policy_t *vp;
  u32 ii, iii, imt;

  ipsec_fp_get_policy_mask (policy, &mask);
  ipsec_fp_get_policy_5tuple (policy, &policy_5tuple);
  fill_ip6_hash_policy_kv (im, &policy_5tuple, &mask, &kv);
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
			  vec_del1 (fp_spd->fp_mask_types[policy->type], imt);
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
  ipsec_fp_5tuple_t mask, policy_5tuple;
  clib_bihash_kv_16_8_t kv;
  clib_bihash_kv_16_8_t result;
  ipsec_fp_lookup_value_t *result_val =
    (ipsec_fp_lookup_value_t *) &result.value;

  ipsec_policy_t *vp;
  u32 ii, iii, imt;

  ipsec_fp_get_policy_mask (policy, &mask);
  ipsec_fp_get_policy_5tuple (policy, &policy_5tuple);
  fill_ip4_hash_policy_kv (im, &policy_5tuple, &mask, &kv);
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
			  vec_del1 (fp_spd->fp_mask_types[policy->type], imt);
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
ipsec_fp_add_del_policy (void *fp_spd, ipsec_policy_t *policy, int is_add)
{
  ipsec_main_t *im = &ipsec_main;

  if (is_add)
    if (policy->is_ipv6)
      return ipsec_fp_ip6_add_policy (im, (ipsec_spd_fp_t *) fp_spd, policy);
    else
      return ipsec_fp_ip4_add_policy (im, (ipsec_spd_fp_t *) fp_spd, policy);

  else if (policy->is_ipv6)

    return ipsec_fp_ip6_del_policy (im, (ipsec_spd_fp_t *) fp_spd, policy);
  else
    return ipsec_fp_ip4_del_policy (im, (ipsec_spd_fp_t *) fp_spd, policy);
}
