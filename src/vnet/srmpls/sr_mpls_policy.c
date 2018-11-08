/*
 * sr_mpls_policy.c: SR-MPLS policies
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
 * @brief SR MPLS policy creation and application
 *
 * Create an SR policy.
 * An SR policy can be either of 'default' type or 'spray' type
 * An SR policy has attached a list of SID lists.
 * In case the SR policy is a default one it will load balance among them.
 * An SR policy has associated a BindingSID.
 * In case any packet arrives with MPLS_label == BindingSID then the SR policy
 * associated to such bindingSID will be applied to such packet.
 * Also, a BSID can be associated with a (Next-Hop, Color)
 *
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/srmpls/sr_mpls.h>
#include <vnet/fib/mpls_fib.h>
#include <vnet/dpo/dpo.h>
#include <vnet/ip/ip.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

mpls_sr_main_t sr_mpls_main;

/***************************  SR LB helper functions **************************/
/**
 * @brief Creates a Segment List and adds it to an SR policy
 *
 * Creates a Segment List and adds it to the SR policy. Notice that the SL are
 * not necessarily unique. Hence there might be two Segment List within the
 * same SR Policy with exactly the same segments and same weight.
 *
 * @param sr_policy is the SR policy where the SL will be added
 * @param sl is a vector of IPv6 addresses composing the Segment List
 * @param weight is the weight of the SegmentList (for load-balancing purposes)
 * @param is_encap represents the mode (SRH insertion vs Encapsulation)
 *
 * @return pointer to the just created segment list
 */
static inline mpls_sr_sl_t *
create_sl (mpls_sr_policy_t * sr_policy, mpls_label_t * sl, u32 weight)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  mpls_sr_sl_t *segment_list;
  u32 ii;

  pool_get (sm->sid_lists, segment_list);
  clib_memset (segment_list, 0, sizeof (*segment_list));

  vec_add1 (sr_policy->segments_lists, segment_list - sm->sid_lists);

  /* Fill in segment list */
  segment_list->weight =
    (weight != (u32) ~ 0 ? weight : SR_SEGMENT_LIST_WEIGHT_DEFAULT);
  segment_list->segments = vec_dup (sl);

  mpls_eos_bit_t eos;
  FOR_EACH_MPLS_EOS_BIT (eos)
  {
    fib_route_path_t path = {
      .frp_proto = DPO_PROTO_MPLS,
      .frp_sw_if_index = ~0,
      .frp_fib_index = 0,
      .frp_weight = segment_list->weight,
      .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
      .frp_label_stack = NULL,
      .frp_local_label = sl[0],
    };

    if (vec_len (sl) > 1)
      {
	vec_validate (path.frp_label_stack, vec_len (sl) - 2);
	for (ii = 1; ii < vec_len (sl); ii++)
	  {
	    path.frp_label_stack[ii - 1].fml_value = sl[ii];
	  }
      }
    else
      {
	/*
	 * add an impliciet NULL label to allow non-eos recursion
	 */
	fib_mpls_label_t lbl = {
	  .fml_value = MPLS_IETF_IMPLICIT_NULL_LABEL,
	};
	vec_add1 (path.frp_label_stack, lbl);
      }

    fib_route_path_t *paths = NULL;
    vec_add1 (paths, path);

    /* *INDENT-OFF* */
    fib_prefix_t pfx = {
        .fp_len = 21,
        .fp_proto = FIB_PROTOCOL_MPLS,
        .fp_label = sr_policy->bsid,
        .fp_eos = eos,
        .fp_payload_proto = DPO_PROTO_MPLS,
    };
    /* *INDENT-ON* */

    fib_table_entry_path_add2 (0,
			       &pfx,
			       FIB_SOURCE_SR,
			       (sr_policy->type == SR_POLICY_TYPE_DEFAULT ?
				FIB_ENTRY_FLAG_NONE :
				FIB_ENTRY_FLAG_MULTICAST), paths);
    vec_free (paths);
  }

  return segment_list;
}

/******************************* SR rewrite API *******************************/
/*
 * Three functions for handling sr policies: -> sr_mpls_policy_add ->
 * sr_mpls_policy_del -> sr_mpls_policy_mod All of them are API. CLI function
 * on sr_policy_command_fn
 */

/**
 * @brief Create a new SR policy
 *
 * @param bsid is the bindingSID of the SR Policy
 * @param segments is a vector of MPLS labels composing the segment list
 * @param behavior is the behavior of the SR policy. (default//spray)
 * @param fib_table is the VRF where to install the FIB entry for the BSID
 * @param weight is the weight of this specific SID list
 *
 * @return 0 if correct, else error
 */
int
sr_mpls_policy_add (mpls_label_t bsid, mpls_label_t * segments,
		    u8 behavior, u32 weight)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  mpls_sr_policy_t *sr_policy = 0;
  uword *p;

  if (!sm->sr_policies_index_hash)
    sm->sr_policies_index_hash = hash_create (0, sizeof (mpls_label_t));

  /* MPLS SR policies cannot be created unless the MPLS table is present */
  if (~0 == fib_table_find (FIB_PROTOCOL_MPLS, MPLS_FIB_DEFAULT_TABLE_ID))
    return (VNET_API_ERROR_NO_SUCH_TABLE);

  /* Search for existing keys (BSID) */
  p = hash_get (sm->sr_policies_index_hash, bsid);
  if (p)
    {
      /* Add SR policy that already exists; complain */
      return -12;
    }
  /* Add an SR policy object */
  pool_get (sm->sr_policies, sr_policy);
  clib_memset (sr_policy, 0, sizeof (*sr_policy));

  /* the first policy needs to lock the MPLS table so it doesn't
   * disappear with policies in it */
  if (1 == pool_elts (sm->sr_policies))
    fib_table_find_or_create_and_lock (FIB_PROTOCOL_MPLS,
				       MPLS_FIB_DEFAULT_TABLE_ID,
				       FIB_SOURCE_SR);
  sr_policy->bsid = bsid;
  sr_policy->type = behavior;
  sr_policy->endpoint_type = 0;
  ip6_address_set_zero (&sr_policy->endpoint.ip6);
  sr_policy->color = (u32) ~ 0;

  /* Copy the key */
  hash_set (sm->sr_policies_index_hash, bsid, sr_policy - sm->sr_policies);

  /* Create a segment list and add the index to the SR policy */
  create_sl (sr_policy, segments, weight);

  return 0;
}

/**
 * @brief Delete a SR policy
 *
 * @param bsid is the bindingSID of the SR Policy
 * @param index is the index of the SR policy
 *
 * @return 0 if correct, else error
 */
int
sr_mpls_policy_del (mpls_label_t bsid)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  mpls_sr_policy_t *sr_policy = 0;
  mpls_sr_sl_t *segment_list;
  mpls_eos_bit_t eos;
  u32 *sl_index;
  uword *p;

  if (!sm->sr_policies_index_hash)
    sm->sr_policies_index_hash = hash_create (0, sizeof (mpls_label_t));

  p = hash_get (sm->sr_policies_index_hash, bsid);
  if (p)
    sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);
  else
    return -1;

  /* Clean SID Lists */
  vec_foreach (sl_index, sr_policy->segments_lists)
  {
    segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);

    fib_route_path_t path = {
      .frp_proto = DPO_PROTO_MPLS,
      .frp_sw_if_index = ~0,
      .frp_fib_index = 0,
      .frp_weight = segment_list->weight,
      .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
      .frp_local_label = segment_list->segments[0],
    };

    vec_add (path.frp_label_stack, segment_list + 1,
	     vec_len (segment_list) - 1);

    fib_route_path_t *paths = NULL;
    vec_add1 (paths, path);

    /* remove each of the MPLS routes */
    FOR_EACH_MPLS_EOS_BIT (eos)
    {
			/* *INDENT-OFF* */
			fib_prefix_t	pfx = {
				.fp_len = 21,
				.fp_proto = FIB_PROTOCOL_MPLS,
				.fp_label = sr_policy->bsid,
				.fp_eos = eos,
				.fp_payload_proto = DPO_PROTO_MPLS,
			};
			/* *INDENT-ON* */

      fib_table_entry_path_remove2 (0, &pfx, FIB_SOURCE_SR, paths);
    }
    vec_free (paths);
    vec_free (segment_list->segments);
    pool_put_index (sm->sid_lists, *sl_index);
  }

  /* If there is still traces of TE, make sure locks are released */
  if (sr_policy->endpoint_type != 0 && sr_policy->color != (u32) ~ 0)
    {
      sr_mpls_policy_assign_endpoint_color (bsid, NULL, 0, (u32) ~ 0);
    }

  /* Remove SR policy entry */
  hash_unset (sm->sr_policies_index_hash, sr_policy->bsid);
  pool_put (sm->sr_policies, sr_policy);

  if (0 == pool_elts (sm->sr_policies))
    fib_table_unlock (MPLS_FIB_DEFAULT_TABLE_ID,
		      FIB_PROTOCOL_MPLS, FIB_SOURCE_SR);

  return 0;
}

/**
 * @brief Modify an existing SR policy
 *
 * The possible modifications are adding a new Segment List, modifying an
 * existing Segment List (modify the weight only) and delete a given
 * Segment List from the SR Policy.
 *
 * @param bsid is the bindingSID of the SR Policy
 * @param fib_table is the VRF where to install the FIB entry for the BSID
 * @param operation is the operation to perform (among the top ones)
 * @param segments is a vector of IPv6 address composing the segment list
 * @param sl_index is the index of the Segment List to modify/delete
 * @param weight is the weight of the sid list. optional.
 *
 * @return 0 ok, >0 index of SL, <0 error
 */
int
sr_mpls_policy_mod (mpls_label_t bsid, u8 operation,
		    mpls_label_t * segments, u32 sl_index, u32 weight)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  mpls_sr_policy_t *sr_policy = 0;
  mpls_sr_sl_t *segment_list;
  u32 *sl_index_iterate;
  uword *p;

  if (!sm->sr_policies_index_hash)
    sm->sr_policies_index_hash = hash_create (0, sizeof (mpls_label_t));

  p = hash_get (sm->sr_policies_index_hash, bsid);
  if (p)
    sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);
  else
    return -1;

  if (operation == 1)
    {				/* Add SR List to an existing SR policy */
      /* Create the new SL */
      segment_list = create_sl (sr_policy, segments, weight);
      return segment_list - sm->sid_lists;
    }
  else if (operation == 2)
    {				/* Delete SR List from an existing SR
				 * policy */
      /* Check that currently there are more than one SID list */
      if (vec_len (sr_policy->segments_lists) == 1)
	return -21;

      /*
       * Check that the SR list does exist and is assigned to the
       * sr policy
       */
      vec_foreach (sl_index_iterate, sr_policy->segments_lists)
	if (*sl_index_iterate == sl_index)
	break;

      if (*sl_index_iterate != sl_index)
	return -22;

      /* Remove the lucky SR list that is being kicked out */
      segment_list = pool_elt_at_index (sm->sid_lists, sl_index);

      mpls_eos_bit_t eos;
      fib_route_path_t path = {
	.frp_proto = DPO_PROTO_MPLS,
	.frp_sw_if_index = ~0,
	.frp_fib_index = 0,
	.frp_weight = segment_list->weight,
	.frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
	.frp_local_label = segment_list->segments[0],
      };

      vec_add (path.frp_label_stack, segment_list + 1,
	       vec_len (segment_list) - 1);

      fib_route_path_t *paths = NULL;
      vec_add1 (paths, path);

      FOR_EACH_MPLS_EOS_BIT (eos)
      {
			/* *INDENT-OFF* */
			fib_prefix_t	pfx = {
				.fp_len = 21,
				.fp_proto = FIB_PROTOCOL_MPLS,
				.fp_label = sr_policy->bsid,
				.fp_eos = eos,
				.fp_payload_proto = DPO_PROTO_MPLS,
			};
			/* *INDENT-ON* */

	fib_table_entry_path_remove2 (0, &pfx, FIB_SOURCE_SR, paths);
      }

      vec_free (paths);
      vec_free (segment_list->segments);
      pool_put_index (sm->sid_lists, sl_index);
      vec_del1 (sr_policy->segments_lists,
		sl_index_iterate - sr_policy->segments_lists);
    }
  else if (operation == 3)
    {				/* Modify the weight of an existing
				 * SR List */
      /* Find the corresponding SL */
      vec_foreach (sl_index_iterate, sr_policy->segments_lists)
	if (*sl_index_iterate == sl_index)
	break;

      if (*sl_index_iterate != sl_index)
	return -32;

      /* Change the weight */
      segment_list = pool_elt_at_index (sm->sid_lists, sl_index);

      /* Update LB */
      mpls_eos_bit_t eos;
      fib_route_path_t path = {
	.frp_proto = DPO_PROTO_MPLS,
	.frp_sw_if_index = ~0,
	.frp_fib_index = 0,
	.frp_weight = segment_list->weight,
	.frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
	.frp_local_label = segment_list->segments[0],
      };

      vec_add (path.frp_label_stack, segment_list + 1,
	       vec_len (segment_list) - 1);

      fib_route_path_t *paths = NULL;
      vec_add1 (paths, path);

      FOR_EACH_MPLS_EOS_BIT (eos)
      {
			/* *INDENT-OFF* */
			fib_prefix_t	pfx = {
				.fp_len = 21,
				.fp_proto = FIB_PROTOCOL_MPLS,
				.fp_label = sr_policy->bsid,
				.fp_eos = eos,
				.fp_payload_proto = DPO_PROTO_MPLS,
			};
			/* *INDENT-ON* */

	fib_table_entry_path_remove2 (0, &pfx, FIB_SOURCE_SR, paths);
      }

      segment_list->weight = weight;

      path.frp_weight = segment_list->weight;

      vec_free (paths);
      paths = NULL;
      vec_add1 (paths, path);

      FOR_EACH_MPLS_EOS_BIT (eos)
      {
			/* *INDENT-OFF* */
			fib_prefix_t	pfx = {
				.fp_len = 21,
				.fp_proto = FIB_PROTOCOL_MPLS,
				.fp_label = sr_policy->bsid,
				.fp_eos = eos,
				.fp_payload_proto = DPO_PROTO_MPLS,
			};
			/* *INDENT-ON* */

	fib_table_entry_path_add2 (0,
				   &pfx,
				   FIB_SOURCE_SR,
				   (sr_policy->type ==
				    SR_POLICY_TYPE_DEFAULT ?
				    FIB_ENTRY_FLAG_NONE :
				    FIB_ENTRY_FLAG_MULTICAST), paths);
      }
    }
  return 0;
}

/**
 * @brief CLI for 'sr mpls policies' command family
 */
static clib_error_t *
sr_mpls_policy_command_fn (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  int rv = -1;
  char is_del = 0, is_add = 0, is_mod = 0;
  char policy_set = 0;
  mpls_label_t bsid, next_label;
  u32 sl_index = (u32) ~ 0;
  u32 weight = (u32) ~ 0;
  mpls_label_t *segments = 0;
  u8 operation = 0;
  u8 is_spray = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!is_add && !is_mod && !is_del && unformat (input, "add"))
	is_add = 1;
      else if (!is_add && !is_mod && !is_del && unformat (input, "del"))
	is_del = 1;
      else if (!is_add && !is_mod && !is_del && unformat (input, "mod"))
	is_mod = 1;
      else if (!policy_set
	       && unformat (input, "bsid %U", unformat_mpls_unicast_label,
			    &bsid))
	policy_set = 1;
      else if (unformat (input, "weight %d", &weight));
      else if (unformat
	       (input, "next %U", unformat_mpls_unicast_label, &next_label))
	{
	  vec_add (segments, &next_label, 1);
	}
      else if (unformat (input, "add sl"))
	operation = 1;
      else if (unformat (input, "del sl index %d", &sl_index))
	operation = 2;
      else if (unformat (input, "mod sl index %d", &sl_index))
	operation = 3;
      else if (unformat (input, "spray"))
	is_spray = 1;
      else
	break;
    }

  if (!is_add && !is_mod && !is_del)
    return clib_error_return (0, "Incorrect CLI");

  if (!policy_set)
    return clib_error_return (0, "No SR policy BSID or index specified");

  if (is_add)
    {
      if (vec_len (segments) == 0)
	return clib_error_return (0, "No Segment List specified");

      rv = sr_mpls_policy_add (bsid, segments,
			       (is_spray ? SR_POLICY_TYPE_SPRAY :
				SR_POLICY_TYPE_DEFAULT), weight);
      vec_free (segments);
    }
  else if (is_del)
    rv = sr_mpls_policy_del (bsid);
  else if (is_mod)
    {
      if (!operation)
	return clib_error_return (0, "No SL modification specified");
      if (operation != 1 && sl_index == (u32) ~ 0)
	return clib_error_return (0, "No Segment List index specified");
      if (operation == 1 && vec_len (segments) == 0)
	return clib_error_return (0, "No Segment List specified");
      if (operation == 3 && weight == (u32) ~ 0)
	return clib_error_return (0, "No new weight for the SL specified");
      rv = sr_mpls_policy_mod (bsid, operation, segments, sl_index, weight);
      vec_free (segments);
    }
  switch (rv)
    {
    case 0:
      break;
    case 1:
      return 0;
    case -12:
      return clib_error_return (0,
				"There is already a FIB entry for the BindingSID address.\n"
				"The SR policy could not be created.");
    case -21:
      return clib_error_return (0,
				"The selected SR policy only contains ONE segment list. "
				"Please remove the SR policy instead");
    case -22:
      return clib_error_return (0,
				"Could not delete the segment list. "
				"It is not associated with that SR policy.");
    case -23:
      return clib_error_return (0,
				"Could not delete the segment list. "
				"It is not associated with that SR policy.");
    case -32:
      return clib_error_return (0,
				"Could not modify the segment list. "
				"The given SL is not associated with such SR policy.");
    case VNET_API_ERROR_NO_SUCH_TABLE:
      return clib_error_return (0, "the Default MPLS table is not present");
    default:
      return clib_error_return (0, "BUG: sr policy returns %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(sr_mpls_policy_command, static)=
{
	.path = "sr mpls policy",
		.short_help = "sr mpls policy [add||del||mod] bsid 2999 "
		"next 10 next 20 next 30 (weight 1) (spray)",
		.long_help = "TBD.\n",
		.function = sr_mpls_policy_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief CLI to display onscreen all the SR MPLS policies
 */
static clib_error_t *
show_sr_mpls_policies_command_fn (vlib_main_t * vm, unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  mpls_sr_sl_t *segment_list = 0;
  mpls_sr_policy_t *sr_policy = 0;
  mpls_sr_policy_t **vec_policies = 0;
  mpls_label_t *label;
  u32 *sl_index;
  u8 *s;
  int i = 0;

  vlib_cli_output (vm, "SR MPLS policies:");

	/* *INDENT-OFF* */
	pool_foreach(sr_policy, sm->sr_policies, {
		vec_add1(vec_policies, sr_policy);
	});
	/* *INDENT-ON* */

  vec_foreach_index (i, vec_policies)
  {
    sr_policy = vec_policies[i];
    vlib_cli_output (vm, "[%u].-\tBSID: %U",
		     (u32) (sr_policy - sm->sr_policies),
		     format_mpls_unicast_label, sr_policy->bsid);
    switch (sr_policy->endpoint_type)
      {
      case SR_STEER_IPV6:
	vlib_cli_output (vm, "\tEndpoint: %U", format_ip6_address,
			 &sr_policy->endpoint.ip6);
	vlib_cli_output (vm, "\tColor: %u", sr_policy->color);
	break;
      case SR_STEER_IPV4:
	vlib_cli_output (vm, "\tEndpoint: %U", format_ip4_address,
			 &sr_policy->endpoint.ip4);
	vlib_cli_output (vm, "\tColor: %u", sr_policy->color);
	break;
      default:
	vlib_cli_output (vm, "\tTE disabled");
      }
    vlib_cli_output (vm, "\tType: %s",
		     (sr_policy->type ==
		      SR_POLICY_TYPE_DEFAULT ? "Default" : "Spray"));
    vlib_cli_output (vm, "\tSegment Lists:");
    vec_foreach (sl_index, sr_policy->segments_lists)
    {
      s = NULL;
      segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);
      s = format (s, "\t[%u].- ", *sl_index);
      s = format (s, "< ");
      vec_foreach (label, segment_list->segments)
      {
	s = format (s, "%U, ", format_mpls_unicast_label, *label);
      }
      s = format (s, "\b\b > ");
      vlib_cli_output (vm, "  %s", s);
    }
    vlib_cli_output (vm, "-----------");
  }
  vec_free (vec_policies);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(show_sr_mpls_policies_command, static)=
{
	.path = "show sr mpls policies",
		.short_help = "show sr mpls policies",
		.function = show_sr_mpls_policies_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief Update the Endpoint,Color tuple of an SR policy
 *
 * @param bsid is the bindingSID of the SR Policy
 * @param endpoint represents the IP46 of the endpoint
 * @param color represents the color (u32)
 *
 * To reset to NULL use ~0 as parameters.
 *
 * @return 0 if correct, else error
 */
int
sr_mpls_policy_assign_endpoint_color (mpls_label_t bsid,
				      ip46_address_t * endpoint,
				      u8 endpoint_type, u32 color)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  mpls_sr_policy_t *sr_policy = 0;
  uword *endpoint_table, *p, *old_value;

  ip46_address_t any;
  any.as_u64[0] = any.as_u64[1] = (u64) ~ 0;

  if (!sm->sr_policies_index_hash)
    sm->sr_policies_index_hash = hash_create (0, sizeof (mpls_label_t));

  p = hash_get (sm->sr_policies_index_hash, bsid);
  if (p)
    sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);
  else
    return -1;

  /* If previous Endpoint, color existed, remove (NH,C) and (ANY,C) */
  if (sr_policy->endpoint_type)
    {
      endpoint_table =
	mhash_get (&sm->sr_policies_c2e2eclabel_hash, &sr_policy->color);
      if (!endpoint_table)
	return -2;
      old_value =
	mhash_get ((mhash_t *) endpoint_table, &sr_policy->endpoint);

      /* CID 180995 This should never be NULL unless the two hash tables
       * get out of sync */
      ASSERT (old_value != NULL);

      fib_prefix_t pfx = { 0 };
      pfx.fp_proto = FIB_PROTOCOL_MPLS;
      pfx.fp_len = 21;
      pfx.fp_label = (u32) * old_value;

      mpls_eos_bit_t eos;
      FOR_EACH_MPLS_EOS_BIT (eos)
      {
	pfx.fp_eos = eos;
	fib_table_entry_path_remove (sm->fib_table_EC,
				     &pfx,
				     FIB_SOURCE_SR,
				     DPO_PROTO_MPLS,
				     NULL,
				     ~0, 0, 1, FIB_ROUTE_PATH_FLAG_NONE);
      }

      old_value = mhash_get ((mhash_t *) endpoint_table, &any);
      pfx.fp_label = (u32) * old_value;

      FOR_EACH_MPLS_EOS_BIT (eos)
      {
	pfx.fp_eos = eos;
	fib_table_entry_path_remove (sm->fib_table_EC,
				     &pfx,
				     FIB_SOURCE_SR,
				     DPO_PROTO_MPLS,
				     NULL,
				     ~0, 0, 1, FIB_ROUTE_PATH_FLAG_NONE);
      }

      /* Release the lock on (NH, Color) and (ANY, Color) */
      internal_label_unlock (sr_policy->endpoint, sr_policy->color);
      internal_label_unlock (any, sr_policy->color);

      /* Reset the values on the SR policy */
      sr_policy->endpoint_type = 0;
      sr_policy->endpoint.as_u64[0] = sr_policy->endpoint.as_u64[1] =
	(u64) ~ 0;
      sr_policy->color = (u32) ~ 0;
    }

  if (endpoint_type)
    {
      sr_policy->endpoint_type = endpoint_type;
      sr_policy->endpoint.as_u64[0] = endpoint->as_u64[0];
      sr_policy->endpoint.as_u64[1] = endpoint->as_u64[1];
      sr_policy->color = color;

      u32 label = find_or_create_internal_label (*endpoint, color);
      internal_label_lock (*endpoint, sr_policy->color);

      /* If FIB doesnt exist, create them */
      if (sm->fib_table_EC == (u32) ~ 0)
	{
	  sm->fib_table_EC = fib_table_create_and_lock (FIB_PROTOCOL_MPLS,
							FIB_SOURCE_SR,
							"SR-MPLS Traffic Engineering (NextHop,Color)");

	  fib_table_flush (sm->fib_table_EC, FIB_PROTOCOL_MPLS,
			   FIB_SOURCE_SPECIAL);
	}

      fib_prefix_t pfx = { 0 };
      pfx.fp_proto = FIB_PROTOCOL_MPLS;
      pfx.fp_len = 21;

      fib_route_path_t path = {
	.frp_proto = DPO_PROTO_MPLS,
	.frp_sw_if_index = ~0,
	.frp_fib_index = 0,
	.frp_weight = 1,
	.frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
	.frp_label_stack = 0
      };
      path.frp_local_label = sr_policy->bsid;

      //Add the entry to ANY,Color
      u32 any_label = find_or_create_internal_label (any, color);
      internal_label_lock (any, sr_policy->color);

      pfx.fp_eos = MPLS_EOS;
      path.frp_eos = MPLS_EOS;

      fib_route_path_t *paths = NULL;
      vec_add1 (paths, path);

      pfx.fp_label = label;
      fib_table_entry_update (sm->fib_table_EC,
			      &pfx,
			      FIB_SOURCE_SR,
			      FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT, paths);

      pfx.fp_label = any_label;
      fib_table_entry_update (sm->fib_table_EC,
			      &pfx,
			      FIB_SOURCE_SR,
			      FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT, paths);

      fib_mpls_label_t fml = {
	.fml_value = MPLS_IETF_IMPLICIT_NULL_LABEL,
      };

      vec_add1 (path.frp_label_stack, fml);
      pfx.fp_eos = MPLS_NON_EOS;
      path.frp_eos = MPLS_NON_EOS;

      paths = NULL;
      vec_add1 (paths, path);

      pfx.fp_label = label;
      fib_table_entry_update (sm->fib_table_EC,
			      &pfx,
			      FIB_SOURCE_SR,
			      FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT, paths);

      pfx.fp_label = any_label;
      fib_table_entry_update (sm->fib_table_EC,
			      &pfx,
			      FIB_SOURCE_SR,
			      FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT, paths);
    }
  return 0;
}

/**
 * @brief CLI to modify the Endpoint,Color of an SR policy
 */
static clib_error_t *
cli_sr_mpls_policy_ec_command_fn (vlib_main_t * vm, unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  ip46_address_t endpoint;
  u32 color = (u32) ~ 0;
  mpls_label_t bsid;
  u8 endpoint_type = 0;
  char clear = 0, color_set = 0, bsid_set = 0;

  clib_memset (&endpoint, 0, sizeof (ip46_address_t));

  int rv;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!endpoint_type
	  && unformat (input, "endpoint %U", unformat_ip6_address,
		       &endpoint.ip6))
	endpoint_type = SR_STEER_IPV6;
      else if (!endpoint_type
	       && unformat (input, "endpoint %U", unformat_ip4_address,
			    &endpoint.ip4))
	endpoint_type = SR_STEER_IPV4;
      else if (!color_set && unformat (input, "color %u", &color))
	color_set = 1;
      else if (!bsid_set
	       && unformat (input, "bsid %U", unformat_mpls_unicast_label,
			    &bsid))
	bsid_set = 1;
      else if (!clear && unformat (input, "clear"))
	clear = 1;
      else
	break;
    }

  if (!bsid_set)
    return clib_error_return (0, "No BSID specified");
  if (!endpoint_type && !clear)
    return clib_error_return (0, "No Endpoint specified");
  if (!color_set && !clear)
    return clib_error_return (0, "No Color set");

  /* In case its a cleanup */
  if (clear)
    {
      ip6_address_set_zero (&endpoint.ip6);
      color = (u32) ~ 0;
    }
  rv =
    sr_mpls_policy_assign_endpoint_color (bsid, &endpoint, endpoint_type,
					  color);

  if (rv)
    clib_error_return (0, "Error on Endpoint,Color");

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(cli_sr_mpls_policy_ec_command, static)=
{
	.path = "sr mpls policy te",
		.short_help = "sr mpls policy te bsid xxxxx endpoint x.x.x.x color 12341234",
		.function = cli_sr_mpls_policy_ec_command_fn,
};
/* *INDENT-ON* */

/********************* SR MPLS Policy initialization ***********************/
/**
 * @brief SR MPLS Policy  initialization
 */
clib_error_t *
sr_mpls_policy_rewrite_init (vlib_main_t * vm)
{
  mpls_sr_main_t *sm = &sr_mpls_main;

  /* Init memory for sr policy keys (bsid <-> ip6_address_t) */
  sm->sr_policies_index_hash = NULL;
  sm->sr_policies_c2e2eclabel_hash.hash = NULL;
  return 0;
}

VLIB_INIT_FUNCTION (sr_mpls_policy_rewrite_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
