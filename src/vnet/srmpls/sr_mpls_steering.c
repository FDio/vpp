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

/**
 * @brief function to sort the colors in descending order
 */
int
sort_color_descent (const u32 * x, u32 * y)
{
  return *y - *x;
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
 * @param next_hop SR TE Next-HOP
 * @param color SR TE color
 * @param co_bits SR TE color-only bits
 *
 * @return 0 if correct, else error
 */
int
sr_mpls_steering_policy_add (mpls_label_t bsid, u32 table_id,
			     ip46_address_t * prefix, u32 mask_width,
			     u8 traffic_type, ip46_address_t * next_hop,
			     u32 color, char co_bits)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  sr_mpls_steering_key_t key;
  mpls_sr_steering_policy_t *steer_pl;
  fib_prefix_t pfx = { 0 };

  mpls_sr_policy_t *sr_policy = 0;
  uword *p = 0;

  memset (&key, 0, sizeof (sr_mpls_steering_key_t));

  /* Compute the steer policy key */
  if (traffic_type == SR_STEER_IPV4 || traffic_type == SR_STEER_IPV6)
    {
      key.prefix.as_u64[0] = prefix->as_u64[0];
      key.prefix.as_u64[1] = prefix->as_u64[1];
      key.mask_width = mask_width;
      key.fib_table = (table_id != (u32) ~ 0 ? table_id : 0);
    }
  else
    return -1;

  key.traffic_type = traffic_type;

  /*
   * Search for steering policy. If already exists we are adding a new
   * one.
   */
  p = mhash_get (&sm->sr_steer_policies_hash, &key);
  if (p)
    {
      steer_pl = pool_elt_at_index (sm->steer_policies, p[0]);
      if (steer_pl->bsid != (u32) ~ 0)
	return -1;

      /* Means we are adding a color */
      if (ip46_address_cmp (&steer_pl->next_hop, next_hop))
	return -1;
      if (vec_search (steer_pl->color, color) != (u32) ~ 0)
	return -1;
      if (steer_pl->co_bits != co_bits)
	return -1;

      sr_policy =
	sr_mpls_policy_find_bsid_from_nh_color (next_hop, color, co_bits);
      if (!sr_policy)
	return -2;
      sr_mpls_policy_lock (sr_policy);

      if (color < steer_pl->color[0])
	{
	  /*
	   * Means lower priority. Add color by now. No changes
	   * in FIB
	   */
	  vec_add1 (steer_pl->color, color);
	  vec_sort_with_function (steer_pl->color, sort_color_descent);
	}
      else
	{
	  /*
	   * Means higher prority. Push at index 0 AND change
	   * FIB
	   */
	  vec_insert_elts (steer_pl->color, &color, 1, 0);
	  fib_route_path_t path = {
	    .frp_proto = DPO_PROTO_MPLS,
	    .frp_local_label = sr_policy->bsid,
	    .frp_eos = MPLS_EOS,
	    .frp_sw_if_index = ~0,
	    .frp_fib_index = 0,
	    .frp_weight = 1,
	    .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
	    .frp_label_stack = NULL
	  };
	  fib_route_path_t *paths = NULL;
	  if (traffic_type == SR_STEER_IPV6)
	    {
	      pfx.fp_proto = FIB_PROTOCOL_IP6;
	      pfx.fp_len = steer_pl->classify.mask_width;
	      pfx.fp_addr.ip6 = steer_pl->classify.prefix.ip6;
	      path.frp_fib_index = 0;
	      vec_add1 (paths, path);
	      fib_table_entry_path_add2 (fib_table_find
					 (FIB_PROTOCOL_IP6,
					  (table_id !=
					   (u32) ~ 0 ? table_id : 0)), &pfx,
					 FIB_SOURCE_SR,
					 FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT,
					 paths);
	      vec_free (paths);
	    }
	  else if (traffic_type == SR_STEER_IPV4)
	    {
	      pfx.fp_proto = FIB_PROTOCOL_IP4;
	      pfx.fp_len = steer_pl->classify.mask_width;
	      pfx.fp_addr.ip4 = steer_pl->classify.prefix.ip4;
	      path.frp_fib_index = 0;
	      vec_add1 (paths, path);
	      fib_table_entry_path_add2 (fib_table_find
					 (FIB_PROTOCOL_IP4,
					  (table_id !=
					   (u32) ~ 0 ? table_id : 0)), &pfx,
					 FIB_SOURCE_SR,
					 FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT,
					 paths);
	      vec_free (paths);
	    }
	}
      return 0;
    }
  if (traffic_type != SR_STEER_IPV4 && traffic_type != SR_STEER_IPV6)
    return -1;

  /* Create a new steering policy */
  pool_get (sm->steer_policies, steer_pl);
  memset (steer_pl, 0, sizeof (*steer_pl));

  if (bsid != (u32) ~ 0)
    {
      steer_pl->bsid = bsid;
      p = hash_get (sm->sr_policies_index_hash, bsid);
      if (!p)
	return -1;
      sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);
    }
  else
    {
      steer_pl->bsid = (u32) ~ 0;
      sr_policy =
	sr_mpls_policy_find_bsid_from_nh_color (next_hop, color, co_bits);
      sr_mpls_policy_lock (sr_policy);
    }

  clib_memcpy (&steer_pl->classify.prefix, prefix, sizeof (ip46_address_t));
  clib_memcpy (&steer_pl->next_hop, next_hop, sizeof (ip46_address_t));
  steer_pl->classify.mask_width = mask_width;
  steer_pl->classify.fib_table = (table_id != (u32) ~ 0 ? table_id : 0);
  steer_pl->classify.traffic_type = traffic_type;
  steer_pl->color = NULL;
  if (steer_pl->bsid == (u32) ~ 0)
    vec_add1 (steer_pl->color, color);
  steer_pl->co_bits = co_bits;

  /* Create and store key */
  mhash_set (&sm->sr_steer_policies_hash, &key, steer_pl - sm->steer_policies,
	     NULL);

  fib_route_path_t path = {
    .frp_proto = DPO_PROTO_MPLS,
    .frp_local_label = sr_policy->bsid,
    .frp_eos = MPLS_EOS,
    .frp_sw_if_index = ~0,
    .frp_fib_index = 0,
    .frp_weight = 1,
    .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
    .frp_label_stack = NULL
  };
  fib_route_path_t *paths = NULL;

  /* FIB API calls - Recursive route through the BindingSID */
  if (traffic_type == SR_STEER_IPV6)
    {
      pfx.fp_proto = FIB_PROTOCOL_IP6;
      pfx.fp_len = steer_pl->classify.mask_width;
      pfx.fp_addr.ip6 = steer_pl->classify.prefix.ip6;
      path.frp_fib_index = 0;
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
      vec_add1 (paths, path);
      fib_table_entry_path_add2 (fib_table_find
				 (FIB_PROTOCOL_IP4,
				  (table_id != (u32) ~ 0 ? table_id : 0)),
				 &pfx, FIB_SOURCE_SR,
				 FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT, paths);
      vec_free (paths);
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
 * @param color SR TE color
 * @param co_bits SR TE color-only bits
 *
 * @return 0 if correct, else error
 */
int
sr_mpls_steering_policy_del (mpls_label_t bsid, u32 table_id,
			     ip46_address_t * prefix, u32 mask_width,
			     u8 traffic_type, ip46_address_t * next_hop,
			     u32 color, char co_bits)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  sr_mpls_steering_key_t key;
  mpls_sr_steering_policy_t *steer_pl;
  fib_prefix_t pfx = { 0 };

  mpls_sr_policy_t *sr_policy = 0;
  uword *p = 0;

  memset (&key, 0, sizeof (sr_mpls_steering_key_t));

  /* Compute the steer policy key */
  if (traffic_type == SR_STEER_IPV4 || traffic_type == SR_STEER_IPV6)
    {
      key.prefix.as_u64[0] = prefix->as_u64[0];
      key.prefix.as_u64[1] = prefix->as_u64[1];
      key.mask_width = mask_width;
      key.fib_table = (table_id != (u32) ~ 0 ? table_id : 0);
    }
  else
    return -1;

  key.traffic_type = traffic_type;

  /* Search for the item */
  p = mhash_get (&sm->sr_steer_policies_hash, &key);

  if (!p)
    return -1;

  /* Retrieve Steer Policy function */
  steer_pl = pool_elt_at_index (sm->steer_policies, p[0]);

  if (steer_pl->classify.traffic_type == SR_STEER_IPV6)
    {
      if (steer_pl->bsid == (u32) ~ 0)
	{
	  sr_policy =
	    sr_mpls_policy_find_bsid_from_nh_color (next_hop, color, co_bits);
	  if (!sr_policy)
	    return -2;

	  sr_mpls_policy_unlock (sr_policy);

	  /* Remove the color from the color vector */
	  vec_del1 (steer_pl->color, vec_search (steer_pl->color, color));

	  if (vec_len (steer_pl->color))
	    {
	      /* Reorder Colors */
	      vec_sort_with_function (steer_pl->color, sort_color_descent);
	      /* Retrieve BSID and update FIB entry */
	      sr_policy =
		sr_mpls_policy_find_bsid_from_nh_color (&steer_pl->next_hop,
							steer_pl->color[0],
							steer_pl->co_bits);
	      fib_route_path_t path = {
		.frp_proto = DPO_PROTO_MPLS,
		.frp_local_label = sr_policy->bsid,
		.frp_eos = MPLS_EOS,
		.frp_sw_if_index = ~0,
		.frp_fib_index = 0,
		.frp_weight = 1,
		.frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
		.frp_label_stack = NULL
	      };
	      fib_route_path_t *paths = NULL;
	      pfx.fp_proto = FIB_PROTOCOL_IP6;
	      pfx.fp_len = steer_pl->classify.mask_width;
	      pfx.fp_addr.ip6 = steer_pl->classify.prefix.ip6;
	      path.frp_fib_index = 0;
	      vec_add1 (paths, path);
	      fib_table_entry_path_add2 (fib_table_find
					 (FIB_PROTOCOL_IP6,
					  (table_id !=
					   (u32) ~ 0 ? table_id : 0)), &pfx,
					 FIB_SOURCE_SR,
					 FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT,
					 paths);
	      vec_free (paths);
	      return 0;
	    }
	  else
	    {
	      vec_free (steer_pl->color);
	      /* Remove FIB entry */
	      pfx.fp_proto = FIB_PROTOCOL_IP6;
	      pfx.fp_len = steer_pl->classify.mask_width;
	      pfx.fp_addr.ip6 = steer_pl->classify.prefix.ip6;
	      fib_table_entry_delete (fib_table_find
				      (FIB_PROTOCOL_IP6,
				       steer_pl->classify.fib_table), &pfx,
				      FIB_SOURCE_SR);
	      /* Delete SR steering policy entry */
	      pool_put (sm->steer_policies, steer_pl);
	      mhash_unset (&sm->sr_steer_policies_hash, &key, NULL);
	      return 0;
	    }
	}
      else
	{
	  /* Remove FIB entry */
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	  pfx.fp_len = steer_pl->classify.mask_width;
	  pfx.fp_addr.ip6 = steer_pl->classify.prefix.ip6;
	  fib_table_entry_delete (fib_table_find
				  (FIB_PROTOCOL_IP6,
				   steer_pl->classify.fib_table), &pfx,
				  FIB_SOURCE_SR);
	  /* Delete SR steering policy entry */
	  pool_put (sm->steer_policies, steer_pl);
	  mhash_unset (&sm->sr_steer_policies_hash, &key, NULL);
	  return 0;
	}
    }
  else if (steer_pl->classify.traffic_type == SR_STEER_IPV4)
    {
      if (steer_pl->bsid == (u32) ~ 0)
	{
	  sr_policy =
	    sr_mpls_policy_find_bsid_from_nh_color (next_hop, color, co_bits);
	  if (!sr_policy)
	    return -2;

	  sr_mpls_policy_unlock (sr_policy);

	  /* Remove the color from the color vector */
	  vec_del1 (steer_pl->color, vec_search (steer_pl->color, color));

	  if (vec_len (steer_pl->color))
	    {
	      /* Reorder Colors */
	      vec_sort_with_function (steer_pl->color, sort_color_descent);
	      /* Retrieve BSID and update FIB entry */
	      sr_policy =
		sr_mpls_policy_find_bsid_from_nh_color (&steer_pl->next_hop,
							steer_pl->color[0],
							steer_pl->co_bits);
	      sr_mpls_policy_lock (sr_policy);
	      fib_route_path_t path = {
		.frp_proto = DPO_PROTO_MPLS,
		.frp_local_label = sr_policy->bsid,
		.frp_eos = MPLS_EOS,
		.frp_sw_if_index = ~0,
		.frp_fib_index = 0,
		.frp_weight = 1,
		.frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
		.frp_label_stack = NULL
	      };
	      fib_route_path_t *paths = NULL;
	      pfx.fp_proto = FIB_PROTOCOL_IP4;
	      pfx.fp_len = steer_pl->classify.mask_width;
	      pfx.fp_addr.ip4 = steer_pl->classify.prefix.ip4;
	      path.frp_fib_index = 0;
	      vec_add1 (paths, path);
	      fib_table_entry_path_add2 (fib_table_find
					 (FIB_PROTOCOL_IP4,
					  (table_id !=
					   (u32) ~ 0 ? table_id : 0)), &pfx,
					 FIB_SOURCE_SR,
					 FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT,
					 paths);
	      vec_free (paths);
	      return 0;
	    }
	  else
	    {
	      /* Remove FIB entry */
	      pfx.fp_proto = FIB_PROTOCOL_IP4;
	      pfx.fp_len = steer_pl->classify.mask_width;
	      pfx.fp_addr.ip4 = steer_pl->classify.prefix.ip4;
	      fib_table_entry_delete (fib_table_find
				      (FIB_PROTOCOL_IP4,
				       steer_pl->classify.fib_table), &pfx,
				      FIB_SOURCE_SR);
	      /* Delete SR steering policy entry */
	      pool_put (sm->steer_policies, steer_pl);
	      mhash_unset (&sm->sr_steer_policies_hash, &key, NULL);
	      return 0;
	    }
	}
      else
	{
	  /* Remove FIB entry */
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	  pfx.fp_len = steer_pl->classify.mask_width;
	  pfx.fp_addr.ip4 = steer_pl->classify.prefix.ip4;
	  fib_table_entry_delete (fib_table_find
				  (FIB_PROTOCOL_IP4,
				   steer_pl->classify.fib_table), &pfx,
				  FIB_SOURCE_SR);
	  /* Delete SR steering policy entry */
	  pool_put (sm->steer_policies, steer_pl);
	  mhash_unset (&sm->sr_steer_policies_hash, &key, NULL);
	  return 0;
	}
    }
  return -1;
}

static clib_error_t *
sr_mpls_steer_policy_command_fn (vlib_main_t * vm, unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  int is_del = 0;

  ip46_address_t prefix, nh;
  u32 dst_mask_width = 0;
  u8 traffic_type = 0;
  u32 fib_table = (u32) ~ 0, color = (u32) ~ 0;
  char co_bits = 00;

  mpls_label_t bsid;

  u8 sr_policy_set = 0;

  memset (&prefix, 0, sizeof (ip46_address_t));
  memset (&nh, 0, sizeof (ip46_address_t));

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
	       && unformat (input, "via next-hop %U color %u co %u",
			    unformat_ip46_address, &nh, color, co_bits))
	sr_policy_set = 1;
      else if (fib_table == (u32) ~ 0
	       && unformat (input, "fib-table %d", &fib_table));
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
  if (is_del)
    rv =
      sr_mpls_steering_policy_del (bsid, fib_table, &prefix, dst_mask_width,
				   traffic_type, &nh, color, co_bits);
  else
    rv =
      sr_mpls_steering_policy_add (bsid, fib_table, &prefix, dst_mask_width,
				   traffic_type, &nh, color, co_bits);

  switch (rv)
    {
    case 0:
      break;
    case 1:
      return 0;
    case -1:
      return clib_error_return (0, "Incorrect API usage.");
    case -2:
      return clib_error_return (0,
				"The requested SR policy could not be located. Review the BSID/index.");
    case -3:
      return clib_error_return (0,
				"Unable to do SW redirect. Incorrect interface.");
    case -4:
      return clib_error_return (0,
				"The requested SR steering policy could not be deleted.");
    case -5:
      return clib_error_return (0,
				"The SR policy is not an encapsulation one.");
    default:
      return clib_error_return (0, "BUG: sr steer policy returns %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(sr_mpls_steer_policy_command, static)=
{
	.path = "sr mpls steer",
		.short_help = "sr mpls steer (del) l3 <ip_addr/mask>"
		"via sr policy bsid <mpls_label> (fib-table <fib_table_index>)",
		.long_help =
		"\tSteer L3 traffic through an existing SR policy.\n"
		"\tExamples:\n"
		"\t\tsr steer l3 2001::/64 via sr_policy bsid 29999\n"
		"\t\tsr steer del l3 2001::/64 via sr_policy bsid 29999\n",
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
  vlib_cli_output (vm, "Traffic\t\tSR policy BSID");
  for (i = 0; i < vec_len (steer_policies); i++)
    {
      steer_pl = steer_policies[i];
      if (steer_pl->classify.traffic_type == SR_STEER_IPV4)
	{
	  vlib_cli_output (vm, "L3 %U/%d\t%U",
			   format_ip4_address,
			   &steer_pl->classify.prefix.ip4,
			   steer_pl->classify.mask_width,
			   format_mpls_unicast_label, steer_pl->bsid);
	}
      else if (steer_pl->classify.traffic_type == SR_STEER_IPV6)
	{
	  vlib_cli_output (vm, "L3 %U/%d\t%U",
			   format_ip6_address,
			   &steer_pl->classify.prefix.ip6,
			   steer_pl->classify.mask_width,
			   format_mpls_unicast_label, steer_pl->bsid);
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
  mhash_init (&sm->sr_steer_policies_hash, sizeof (uword),
	      sizeof (sr_mpls_steering_key_t));
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
