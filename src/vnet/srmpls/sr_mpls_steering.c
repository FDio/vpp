/*
 * sr_steering.c: ipv6 segment routing steering into SR policy
 *
 * Copyright (c) 2016 Cisco and/or its affiliates. Licensed under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/**
 * @file
 * @brief Packet steering into SR-MPLS Policies
 *
 * This file is in charge of handling the FIB appropiatly to steer packets
 * through SR Policies as defined in 'sr_mpls_policy.c'. Notice that here
 * we are only doing steering. SR policy application is done in
 * sr_policy_rewrite.c
 *
 * Supports:
 *  - Steering of IPv6 traffic Destination Address based through BSID
 *  - Steering of IPv4 traffic Destination Address based through BSID
 *  - Steering of IPv4 and IPv6 traffic through N,C (SR CP)
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/srmpls/sr_mpls.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/fib/mpls_fib.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#define SRMPLS_TE_OFFSET 50

/**
 * @brief function to sort the colors in descending order
 */
int
sort_color_descent (const u32 * x, u32 * y)
{
  return *y - *x;
}

/********************* Internal (NH, C) labels *******************************/
/**
 * @brief find the corresponding label for (endpoint, color) and lock it
 * endpoint might be NULL or ANY
 * NULL = 0, ANY=~0
 */
u32
find_or_create_internal_label (ip46_address_t endpoint, u32 color)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  uword *color_table, *result_label;

  if (!sm->sr_policies_c2e2eclabel_hash.hash)
    mhash_init (&sm->sr_policies_c2e2eclabel_hash, sizeof (mhash_t),
		sizeof (u32));

  color_table = mhash_get (&sm->sr_policies_c2e2eclabel_hash, &color);
  if (!color_table)
    {
      mhash_t color_t;
      clib_memset (&color_t, 0, sizeof (mhash_t));
      mhash_init (&color_t, sizeof (u32), sizeof (ip46_address_t));
      mhash_set_mem (&sm->sr_policies_c2e2eclabel_hash, &color,
		     (uword *) & color_t, NULL);
      color_table = mhash_get (&sm->sr_policies_c2e2eclabel_hash, &color);
    }

  result_label = mhash_get ((mhash_t *) color_table, &endpoint);

  if (result_label)
    return (u32) * result_label;

  /* Create and set a new internal label */
  u32 *new_internal_label = 0;
  pool_get (sm->ec_labels, new_internal_label);
  *new_internal_label = 0;
  mhash_set ((mhash_t *) color_table, &endpoint,
	     (new_internal_label - sm->ec_labels) + SRMPLS_TE_OFFSET, NULL);

  return (new_internal_label - sm->ec_labels) + SRMPLS_TE_OFFSET;
}

always_inline void
internal_label_lock_co (ip46_address_t endpoint, u32 color, char co_bits)
{
  ip46_address_t zero, any;
  ip46_address_reset (&zero);
  any.as_u64[0] = any.as_u64[1] = (u64) ~ 0;
  switch (co_bits)
    {
    case SR_TE_CO_BITS_10:
      internal_label_lock (endpoint, color);
      internal_label_lock (zero, color);
      internal_label_lock (any, color);
      break;
    case SR_TE_CO_BITS_01:
      internal_label_lock (endpoint, color);
      internal_label_lock (zero, color);
      break;
    case SR_TE_CO_BITS_00:
    case SR_TE_CO_BITS_11:
      internal_label_lock (endpoint, color);
      break;
    }
}

/**
 * @brief lock the label for (NH, C)
 * endpoint might be NULL or ANY
 * NULL = 0, ANY=~0
 */
void
internal_label_lock (ip46_address_t endpoint, u32 color)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  uword *color_table, *result_label;

  if (!sm->sr_policies_c2e2eclabel_hash.hash)
    return;

  color_table = mhash_get (&sm->sr_policies_c2e2eclabel_hash, &color);
  if (!color_table)
    return;

  result_label = mhash_get ((mhash_t *) color_table, &endpoint);

  if (!result_label)
    return;

  /* Lock it */
  u32 *label_lock =
    pool_elt_at_index (sm->ec_labels, *result_label - SRMPLS_TE_OFFSET);
  (*label_lock)++;
}


always_inline void
internal_label_unlock_co (ip46_address_t endpoint, u32 color, char co_bits)
{
  ip46_address_t zero, any;
  ip46_address_reset (&zero);
  any.as_u64[0] = any.as_u64[1] = (u64) ~ 0;
  switch (co_bits)
    {
    case SR_TE_CO_BITS_10:
      internal_label_unlock (endpoint, color);
      internal_label_unlock (zero, color);
      internal_label_unlock (any, color);
      break;
    case SR_TE_CO_BITS_01:
      internal_label_unlock (endpoint, color);
      internal_label_unlock (zero, color);
      break;
    case SR_TE_CO_BITS_00:
    case SR_TE_CO_BITS_11:
      internal_label_unlock (endpoint, color);
      break;
    }
}

/**
 * @brief Release lock on label for (endpoint, color)
 * endpoint might be NULL or ANY
 * NULL = 0, ANY=~0
 */
void
internal_label_unlock (ip46_address_t endpoint, u32 color)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  uword *color_table, *result_label;

  if (!sm->sr_policies_c2e2eclabel_hash.hash)
    return;

  color_table = mhash_get (&sm->sr_policies_c2e2eclabel_hash, &color);
  if (!color_table)
    return;

  result_label = mhash_get ((mhash_t *) color_table, &endpoint);

  if (!result_label)
    return;

  u32 *label_lock =
    pool_elt_at_index (sm->ec_labels, *result_label - SRMPLS_TE_OFFSET);
  (*label_lock)--;

  if (*label_lock == 0)
    {
      pool_put (sm->ec_labels, label_lock);
      mhash_unset ((mhash_t *) color_table, &endpoint, NULL);
      if (mhash_elts ((mhash_t *) color_table) == 0)
	{
	  mhash_free ((mhash_t *) color_table);
	  mhash_unset (&sm->sr_policies_c2e2eclabel_hash, &color, NULL);
	  if (mhash_elts (&sm->sr_policies_c2e2eclabel_hash) == 0)
	    {
	      mhash_free (&sm->sr_policies_c2e2eclabel_hash);
	      sm->sr_policies_c2e2eclabel_hash.hash = NULL;
	      fib_table_unlock (sm->fib_table_EC, FIB_PROTOCOL_MPLS,
				FIB_SOURCE_SR);
	      sm->fib_table_EC = (u32) ~ 0;
	    }
	}
    }
}

/********************* steering computation  *********************************/
/**
 * @brief function to update the FIB
 */
void
compute_sr_te_automated_steering_fib_entry (mpls_sr_steering_policy_t *
					    steer_pl)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  fib_prefix_t pfx = { 0 };

  u32 *internal_labels = 0;
  ip46_address_t zero, any;
  ip46_address_reset (&zero);
  any.as_u64[0] = any.as_u64[1] = (u64) ~ 0;

  u32 *color_i = NULL;
  vec_foreach (color_i, steer_pl->color)
  {
    switch (steer_pl->co_bits)
      {
      case SR_TE_CO_BITS_10:
	vec_add1 (internal_labels,
		  find_or_create_internal_label (steer_pl->next_hop,
						 *color_i));
	vec_add1 (internal_labels,
		  find_or_create_internal_label (zero, *color_i));
	vec_add1 (internal_labels,
		  find_or_create_internal_label (any, *color_i));
	break;
      case SR_TE_CO_BITS_01:
	vec_add1 (internal_labels,
		  find_or_create_internal_label (steer_pl->next_hop,
						 *color_i));
	vec_add1 (internal_labels,
		  find_or_create_internal_label (zero, *color_i));
	break;
      case SR_TE_CO_BITS_00:
      case SR_TE_CO_BITS_11:
	vec_add1 (internal_labels,
		  find_or_create_internal_label (steer_pl->next_hop,
						 *color_i));
	break;
      }
  }

  /* Does hidden FIB already exist? */
  if (sm->fib_table_EC == (u32) ~ 0)
    {
      sm->fib_table_EC = fib_table_create_and_lock (FIB_PROTOCOL_MPLS,
						    FIB_SOURCE_SR,
						    "SR-MPLS Traffic Engineering (NextHop,Color)");

      fib_table_flush (sm->fib_table_EC, FIB_PROTOCOL_MPLS,
		       FIB_SOURCE_SPECIAL);
    }

  /* Add the corresponding FIB entries */
  fib_route_path_t path = {
    .frp_proto = DPO_PROTO_MPLS,
    .frp_eos = MPLS_EOS,
    .frp_sw_if_index = ~0,
    .frp_fib_index = sm->fib_table_EC,
    .frp_weight = 1,
    .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
    .frp_label_stack = 0
  };
  fib_route_path_t *paths = NULL;

  if (steer_pl->classify.traffic_type == SR_STEER_IPV6)
    {
      pfx.fp_proto = FIB_PROTOCOL_IP6;
      pfx.fp_len = steer_pl->classify.mask_width;
      pfx.fp_addr.ip6 = steer_pl->classify.prefix.ip6;
    }
  else if (steer_pl->classify.traffic_type == SR_STEER_IPV4)
    {
      pfx.fp_proto = FIB_PROTOCOL_IP4;
      pfx.fp_len = steer_pl->classify.mask_width;
      pfx.fp_addr.ip4 = steer_pl->classify.prefix.ip4;
    }

  if (steer_pl->vpn_label != (u32) ~ 0)
    {
      fib_mpls_label_t fml = {
	.fml_value = steer_pl->vpn_label,
      };
      vec_add1 (path.frp_label_stack, fml);
      path.frp_eos = MPLS_NON_EOS;
    }

  u32 label_i;
  vec_foreach_index (label_i, internal_labels)
  {
    path.frp_local_label = internal_labels[label_i];
    path.frp_preference = label_i;
    vec_add1 (paths, path);
  }

  /* Finally we must add to FIB IGP to N */
  clib_memcpy (&path.frp_addr, &steer_pl->next_hop,
	       sizeof (steer_pl->next_hop));
  path.frp_preference = vec_len (internal_labels);
  path.frp_label_stack = NULL;

  if (steer_pl->nh_type == SR_STEER_IPV6)
    {
      path.frp_proto = DPO_PROTO_IP6;
      path.frp_fib_index =
	fib_table_find (FIB_PROTOCOL_IP6,
			(steer_pl->classify.fib_table !=
			 (u32) ~ 0 ? steer_pl->classify.fib_table : 0));
    }
  else if (steer_pl->nh_type == SR_STEER_IPV4)
    {
      path.frp_proto = DPO_PROTO_IP4;
      path.frp_fib_index =
	fib_table_find (FIB_PROTOCOL_IP4,
			(steer_pl->classify.fib_table !=
			 (u32) ~ 0 ? steer_pl->classify.fib_table : 0));
    }

  vec_add1 (paths, path);
  if (steer_pl->classify.traffic_type == SR_STEER_IPV6)
    fib_table_entry_update (fib_table_find
			    (FIB_PROTOCOL_IP6,
			     (steer_pl->classify.fib_table !=
			      (u32) ~ 0 ? steer_pl->classify.fib_table : 0)),
			    &pfx, FIB_SOURCE_SR,
			    FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT, paths);
  else if (steer_pl->classify.traffic_type == SR_STEER_IPV4)
    fib_table_entry_update (fib_table_find
			    (FIB_PROTOCOL_IP4,
			     (steer_pl->classify.fib_table !=
			      (u32) ~ 0 ? steer_pl->classify.fib_table : 0)),
			    &pfx, FIB_SOURCE_SR,
			    FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT, paths);

  vec_free (paths);
  paths = NULL;
}

/**
 * @brief Steer traffic L3 traffic through a given SR-MPLS policy
 *
 * @param is_del
 * @param bsid is the bindingSID of the SR Policy (alt to sr_policy_index)
 * @param sr_policy is the index of the SR Policy (alt to bsid)
 * @param table_id is the VRF where to install the FIB entry for the BSID
 * @param prefix is the IPv4/v6 address for L3 traffic type
 * @param mask_width is the mask for L3 traffic type
 * @param traffic_type describes the type of traffic
 * @param next_hop SR TE Next-Hop
 * @param nh_type is the AF of Next-Hop
 * @param color SR TE color
 * @param co_bits SR TE color-only bits
 *
 * @return 0 if correct, else error
 */
int
sr_mpls_steering_policy_add (mpls_label_t bsid, u32 table_id,
			     ip46_address_t * prefix, u32 mask_width,
			     u8 traffic_type, ip46_address_t * next_hop,
			     u8 nh_type, u32 color, char co_bits,
			     mpls_label_t vpn_label)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  sr_mpls_steering_key_t key;
  mpls_sr_steering_policy_t *steer_pl;
  fib_prefix_t pfx = { 0 };

  mpls_sr_policy_t *sr_policy = 0;
  uword *p = 0;

  clib_memset (&key, 0, sizeof (sr_mpls_steering_key_t));

  if (traffic_type != SR_STEER_IPV4 && traffic_type != SR_STEER_IPV6)
    return -1;

  /* Compute the steer policy key */
  key.prefix.as_u64[0] = prefix->as_u64[0];
  key.prefix.as_u64[1] = prefix->as_u64[1];
  key.mask_width = mask_width;
  key.fib_table = (table_id != (u32) ~ 0 ? table_id : 0);
  key.traffic_type = traffic_type;

  /*
   * Search for steering policy. If already exists we are adding a new
   * color.
   */
  if (!sm->sr_steer_policies_hash.hash)
    mhash_init (&sm->sr_steer_policies_hash, sizeof (uword),
		sizeof (sr_mpls_steering_key_t));

  p = mhash_get (&sm->sr_steer_policies_hash, &key);
  if (p)
    {
      steer_pl = pool_elt_at_index (sm->steer_policies, p[0]);
      if (steer_pl->bsid != (u32) ~ 0)
	return -1;		//Means we are rewritting the steering. Not allowed.

      /* Means we are adding a color. Check that NH match. */
      if (ip46_address_cmp (&steer_pl->next_hop, next_hop))
	return -2;
      if (vec_search (steer_pl->color, color) != ~0)
	return -3;
      if (steer_pl->co_bits != co_bits)
	return -4;		/* CO colors should be the same */
      if (steer_pl->vpn_label != vpn_label)
	return -5;		/* VPN label should be the same */

      /* Remove the steering and ReDo it */
      vec_add1 (steer_pl->color, color);
      vec_sort_with_function (steer_pl->color, sort_color_descent);
      compute_sr_te_automated_steering_fib_entry (steer_pl);
      internal_label_lock_co (steer_pl->next_hop, color, steer_pl->co_bits);
      return 0;
    }

  /* Create a new steering policy */
  pool_get (sm->steer_policies, steer_pl);
  clib_memset (steer_pl, 0, sizeof (*steer_pl));
  clib_memcpy (&steer_pl->classify.prefix, prefix, sizeof (ip46_address_t));
  clib_memcpy (&steer_pl->next_hop, next_hop, sizeof (ip46_address_t));
  steer_pl->nh_type = nh_type;
  steer_pl->co_bits = co_bits;
  steer_pl->classify.mask_width = mask_width;
  steer_pl->classify.fib_table = (table_id != (u32) ~ 0 ? table_id : 0);
  steer_pl->classify.traffic_type = traffic_type;
  steer_pl->color = NULL;
  steer_pl->vpn_label = vpn_label;

  /* Create and store key */
  mhash_set (&sm->sr_steer_policies_hash, &key, steer_pl - sm->steer_policies,
	     NULL);

  /* Local steering */
  if (bsid != (u32) ~ 0)
    {
      if (!sm->sr_policies_index_hash)
	sm->sr_policies_index_hash = hash_create (0, sizeof (mpls_label_t));
      steer_pl->bsid = bsid;
      p = hash_get (sm->sr_policies_index_hash, bsid);
      if (!p)
	return -1;
      sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);

      fib_route_path_t path = {
	.frp_proto = DPO_PROTO_MPLS,
	.frp_local_label = sr_policy->bsid,
	.frp_eos = MPLS_EOS,
	.frp_sw_if_index = ~0,
	.frp_fib_index = 0,
	.frp_weight = 1,
	.frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
	.frp_label_stack = 0
      };
      fib_route_path_t *paths = NULL;

      if (steer_pl->vpn_label != (u32) ~ 0)
	{
	  fib_mpls_label_t fml = {
	    .fml_value = steer_pl->vpn_label,
	  };
	  vec_add1 (path.frp_label_stack, fml);
	}

      /* FIB API calls - Recursive route through the BindingSID */
      if (traffic_type == SR_STEER_IPV6)
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	  pfx.fp_len = steer_pl->classify.mask_width;
	  pfx.fp_addr.ip6 = steer_pl->classify.prefix.ip6;
	  path.frp_fib_index = 0;
	  path.frp_preference = 0;
	  vec_add1 (paths, path);
	  fib_table_entry_path_add2 (fib_table_find
				     (FIB_PROTOCOL_IP6,
				      (table_id != (u32) ~ 0 ? table_id : 0)),
				     &pfx, FIB_SOURCE_SR,
				     FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT, paths);
	  vec_free (paths);
	}
      else if (traffic_type == SR_STEER_IPV4)
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	  pfx.fp_len = steer_pl->classify.mask_width;
	  pfx.fp_addr.ip4 = steer_pl->classify.prefix.ip4;
	  path.frp_fib_index = 0;
	  path.frp_preference = 0;
	  vec_add1 (paths, path);
	  fib_table_entry_path_add2 (fib_table_find
				     (FIB_PROTOCOL_IP4,
				      (table_id != (u32) ~ 0 ? table_id : 0)),
				     &pfx, FIB_SOURCE_SR,
				     FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT, paths);
	  vec_free (paths);
	}
    }
  /* Automated steering */
  else
    {
      steer_pl->bsid = (u32) ~ 0;
      vec_add1 (steer_pl->color, color);
      compute_sr_te_automated_steering_fib_entry (steer_pl);
      internal_label_lock_co (steer_pl->next_hop, color, steer_pl->co_bits);
    }
  return 0;
}

/**
 * @brief Delete steering rule for an SR-MPLS policy
 *
 * @param is_del
 * @param bsid is the bindingSID of the SR Policy (alt to sr_policy_index)
 * @param sr_policy is the index of the SR Policy (alt to bsid)
 * @param table_id is the VRF where to install the FIB entry for the BSID
 * @param prefix is the IPv4/v6 address for L3 traffic type
 * @param mask_width is the mask for L3 traffic type
 * @param traffic_type describes the type of traffic
 * @param next_hop SR TE Next-HOP
 * @param nh_type is the AF of Next-Hop
 * @param color SR TE color
 *
 * @return 0 if correct, else error
 */
int
sr_mpls_steering_policy_del (ip46_address_t * prefix, u32 mask_width,
			     u8 traffic_type, u32 table_id, u32 color)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  sr_mpls_steering_key_t key;
  mpls_sr_steering_policy_t *steer_pl;
  fib_prefix_t pfx = { 0 };
  uword *p = 0;

  clib_memset (&key, 0, sizeof (sr_mpls_steering_key_t));

  /* Compute the steer policy key */
  if (traffic_type != SR_STEER_IPV4 && traffic_type != SR_STEER_IPV6)
    return -1;

  key.prefix.as_u64[0] = prefix->as_u64[0];
  key.prefix.as_u64[1] = prefix->as_u64[1];
  key.mask_width = mask_width;
  key.fib_table = (table_id != (u32) ~ 0 ? table_id : 0);
  key.traffic_type = traffic_type;

  if (!sm->sr_steer_policies_hash.hash)
    mhash_init (&sm->sr_steer_policies_hash, sizeof (uword),
		sizeof (sr_mpls_steering_key_t));

  /* Search for the item */
  p = mhash_get (&sm->sr_steer_policies_hash, &key);

  if (!p)
    return -1;

  /* Retrieve Steer Policy function */
  steer_pl = pool_elt_at_index (sm->steer_policies, p[0]);

  if (steer_pl->bsid == (u32) ~ 0)
    {
      /* Remove the color from the color vector */
      vec_del1 (steer_pl->color, vec_search (steer_pl->color, color));

      if (vec_len (steer_pl->color))
	{
	  /* Reorder Colors */
	  vec_sort_with_function (steer_pl->color, sort_color_descent);
	  compute_sr_te_automated_steering_fib_entry (steer_pl);
	  /* Remove all the locks for this ones... */
	  internal_label_unlock_co (steer_pl->next_hop, color,
				    steer_pl->co_bits);
	  return 0;
	}
      else
	{
	  vec_free (steer_pl->color);
	  /* Remove FIB entry */
	  if (steer_pl->classify.traffic_type == SR_STEER_IPV6)
	    {
	      pfx.fp_proto = FIB_PROTOCOL_IP6;
	      pfx.fp_len = steer_pl->classify.mask_width;
	      pfx.fp_addr.ip6 = steer_pl->classify.prefix.ip6;
	      fib_table_entry_delete (fib_table_find
				      (FIB_PROTOCOL_IP6,
				       steer_pl->classify.fib_table), &pfx,
				      FIB_SOURCE_SR);
	    }
	  else if (steer_pl->classify.traffic_type == SR_STEER_IPV4)
	    {
	      pfx.fp_proto = FIB_PROTOCOL_IP4;
	      pfx.fp_len = steer_pl->classify.mask_width;
	      pfx.fp_addr.ip4 = steer_pl->classify.prefix.ip4;
	      fib_table_entry_delete (fib_table_find
				      (FIB_PROTOCOL_IP4,
				       steer_pl->classify.fib_table), &pfx,
				      FIB_SOURCE_SR);
	    }
	  /* Remove all the locks for this ones... */
	  internal_label_unlock_co (steer_pl->next_hop, color,
				    steer_pl->co_bits);
	}
    }
  else				//Remove by BSID
    {
      if (steer_pl->classify.traffic_type == SR_STEER_IPV6)
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	  pfx.fp_len = steer_pl->classify.mask_width;
	  pfx.fp_addr.ip6 = steer_pl->classify.prefix.ip6;
	  fib_table_entry_delete (fib_table_find
				  (FIB_PROTOCOL_IP6,
				   steer_pl->classify.fib_table), &pfx,
				  FIB_SOURCE_SR);
	}
      else if (steer_pl->classify.traffic_type == SR_STEER_IPV4)
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	  pfx.fp_len = steer_pl->classify.mask_width;
	  pfx.fp_addr.ip4 = steer_pl->classify.prefix.ip4;
	  fib_table_entry_delete (fib_table_find
				  (FIB_PROTOCOL_IP4,
				   steer_pl->classify.fib_table), &pfx,
				  FIB_SOURCE_SR);
	}
    }
  /* Delete SR steering policy entry */
  pool_put (sm->steer_policies, steer_pl);
  mhash_unset (&sm->sr_steer_policies_hash, &key, NULL);
  if (mhash_elts (&sm->sr_steer_policies_hash) == 0)
    {
      mhash_free (&sm->sr_steer_policies_hash);
      sm->sr_steer_policies_hash.hash = NULL;
    }
  return 0;
}

static clib_error_t *
sr_mpls_steer_policy_command_fn (vlib_main_t * vm, unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  int is_del = 0;

  ip46_address_t prefix, nh;
  u32 dst_mask_width = 0;
  u8 traffic_type = 0;
  u8 nh_type = 0;
  u32 fib_table = (u32) ~ 0, color = (u32) ~ 0;
  u32 co_bits = 0;

  mpls_label_t bsid, vpn_label = (u32) ~ 0;

  u8 sr_policy_set = 0;

  clib_memset (&prefix, 0, sizeof (ip46_address_t));
  clib_memset (&nh, 0, sizeof (ip46_address_t));

  int rv;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_del = 1;
      else if (!traffic_type
	       && unformat (input, "l3 %U/%d", unformat_ip6_address,
			    &prefix.ip6, &dst_mask_width))
	traffic_type = SR_STEER_IPV6;
      else if (!traffic_type
	       && unformat (input, "l3 %U/%d", unformat_ip4_address,
			    &prefix.ip4, &dst_mask_width))
	traffic_type = SR_STEER_IPV4;
      else if (!sr_policy_set
	       && unformat (input, "via sr policy bsid %U",
			    unformat_mpls_unicast_label, &bsid))
	sr_policy_set = 1;
      else if (!sr_policy_set
	       && unformat (input, "via next-hop %U color %d co %d",
			    unformat_ip4_address, &nh.ip4, &color, &co_bits))
	{
	  sr_policy_set = 1;
	  nh_type = SR_STEER_IPV4;
	}
      else if (!sr_policy_set
	       && unformat (input, "via next-hop %U color %d co %d",
			    unformat_ip6_address, &nh.ip6, &color, &co_bits))
	{
	  sr_policy_set = 1;
	  nh_type = SR_STEER_IPV6;
	}
      else if (fib_table == (u32) ~ 0
	       && unformat (input, "fib-table %d", &fib_table));
      else if (unformat (input, "vpn-label %U",
			 unformat_mpls_unicast_label, &vpn_label));
      else
	break;
    }

  if (!traffic_type)
    return clib_error_return (0, "No L3 traffic specified");
  if (!sr_policy_set)
    return clib_error_return (0, "No SR policy specified");

  /* Make sure that the prefixes are clean */
  if (traffic_type == SR_STEER_IPV4)
    {
      u32 mask =
	(dst_mask_width ? (0xFFFFFFFFu >> (32 - dst_mask_width)) : 0);
      prefix.ip4.as_u32 &= mask;
    }
  else if (traffic_type == SR_STEER_IPV6)
    {
      ip6_address_t mask;
      ip6_address_mask_from_width (&mask, dst_mask_width);
      ip6_address_mask (&prefix.ip6, &mask);
    }

  if (nh_type)
    bsid = (u32) ~ 0;

  if (is_del)
    rv =
      sr_mpls_steering_policy_del (&prefix, dst_mask_width,
				   traffic_type, fib_table, color);

  else
    rv =
      sr_mpls_steering_policy_add (bsid, fib_table, &prefix, dst_mask_width,
				   traffic_type, &nh, nh_type, color, co_bits,
				   vpn_label);

  switch (rv)
    {
    case 0:
      break;
    case 1:
      return 0;
    case -1:
      return clib_error_return (0, "Incorrect API usage.");
    case -2:
      return clib_error_return (0, "The Next-Hop does not match.");
    case -3:
      return clib_error_return (0, "The color already exists.");
    case -4:
      return clib_error_return (0, "The co-bits do not match.");
    case -5:
      return clib_error_return (0, "The VPN-labels do not match.");
    default:
      return clib_error_return (0, "BUG: sr steer policy returns %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(sr_mpls_steer_policy_command, static)=
{
  .path = "sr mpls steer",
    .short_help = "sr mpls steer (del) l3 <ip_addr/mask> "
    "via [sr policy bsid <mpls_label> || next-hop <ip46_addr> color <u32> co <0|1|2|3> ](fib-table <fib_table_index>)(vpn-label 500)",
    .long_help =
    "\tSteer L3 traffic through an existing SR policy.\n"
    "\tExamples:\n"
    "\t\tsr steer l3 2001::/64 via sr_policy bsid 29999\n"
    "\t\tsr steer del l3 2001::/64 via sr_policy bsid 29999\n"
    "\t\tsr steer l3 2001::/64 via next-hop 1.1.1.1 color 1234 co 0\n"
    "\t\tsr steer l3 2001::/64 via next-hop 2001::1 color 1234 co 2 vpn-label 500\n",
    .function = sr_mpls_steer_policy_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_sr_mpls_steering_policies_command_fn (vlib_main_t * vm,
					   unformat_input_t * input,
					   vlib_cli_command_t * cmd)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  mpls_sr_steering_policy_t **steer_policies = 0;
  mpls_sr_steering_policy_t *steer_pl;

  int i;

  vlib_cli_output (vm, "SR MPLS steering policies:");
  /* *INDENT-OFF* */
  pool_foreach(steer_pl, sm->steer_policies, ({
    vec_add1(steer_policies, steer_pl);
  }));
  /* *INDENT-ON* */
  for (i = 0; i < vec_len (steer_policies); i++)
    {
      vlib_cli_output (vm, "==========================");
      steer_pl = steer_policies[i];
      if (steer_pl->classify.traffic_type == SR_STEER_IPV4)
	{
	  vlib_cli_output (vm, "Prefix: %U/%d via:",
			   format_ip4_address,
			   &steer_pl->classify.prefix.ip4,
			   steer_pl->classify.mask_width);
	}
      else if (steer_pl->classify.traffic_type == SR_STEER_IPV6)
	{
	  vlib_cli_output (vm, "Prefix: %U/%d via:",
			   format_ip6_address,
			   &steer_pl->classify.prefix.ip6,
			   steer_pl->classify.mask_width);
	}

      if (steer_pl->bsid != (u32) ~ 0)
	{
	  vlib_cli_output (vm, "· BSID %U",
			   format_mpls_unicast_label, steer_pl->bsid);
	}
      else
	{
	  if (steer_pl->nh_type == SR_STEER_IPV4)
	    {
	      vlib_cli_output (vm, "· Next-hop %U",
			       format_ip4_address, &steer_pl->next_hop.ip4);
	    }
	  else if (steer_pl->nh_type == SR_STEER_IPV6)
	    {
	      vlib_cli_output (vm, "· Next-hop %U",
			       format_ip6_address, &steer_pl->next_hop.ip6);
	    }

	  u32 *color_i = 0;
	  u8 *s = NULL;
	  s = format (s, "[ ");
	  vec_foreach (color_i, steer_pl->color)
	  {
	    s = format (s, "%d, ", *color_i);
	  }
	  s = format (s, "\b\b ]");
	  vlib_cli_output (vm, "· Color %s", s);

	  switch (steer_pl->co_bits)
	    {
	    case SR_TE_CO_BITS_00:
	      vlib_cli_output (vm, "· CO-bits: 00");
	      break;
	    case SR_TE_CO_BITS_01:
	      vlib_cli_output (vm, "· CO-bits: 01");
	      break;
	    case SR_TE_CO_BITS_10:
	      vlib_cli_output (vm, "· CO-bits: 10");
	      break;
	    case SR_TE_CO_BITS_11:
	      vlib_cli_output (vm, "· CO-bits: 11");
	      break;
	    }
	}
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(show_sr_mpls_steering_policies_command, static)=
{
  .path = "show sr mpls steering policies",
    .short_help = "show sr mpls steering policies",
    .function = show_sr_mpls_steering_policies_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
sr_mpls_steering_init (vlib_main_t * vm)
{
  mpls_sr_main_t *sm = &sr_mpls_main;

  /* Init memory for function keys */
  sm->sr_steer_policies_hash.hash = NULL;

  sm->fib_table_EC = (u32) ~ 0;
  sm->ec_labels = 0;

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION(sr_mpls_steering_init);
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
