/*
 * sr_mpls_policy.c: SR-MPLS policies
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 * @brief SR MPLS policy creation and application
 *
 * Create an SR policy.
 * An SR policy can be either of 'default' type or 'spray' type
 * An SR policy has attached a list of SID lists.
 * In case the SR policy is a default one it will load balance among them.
 * An SR policy has associated a BindingSID.
 * In case any packet arrives with MPLS_label == BindingSID then the SR policy
 * associated to such bindingSID will be applied to such packet.
 *
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/srmpls/sr.h>
#include <vnet/fib/mpls_fib.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/replicate_dpo.h>
#include <vnet/dpo/mpls_label_dpo.h>
#include <vnet/dpo/lookup_dpo.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

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

  pool_get (sm->sid_lists, segment_list);
  memset (segment_list, 0, sizeof (*segment_list));

  vec_add1 (sr_policy->segments_lists, segment_list - sm->sid_lists);

  /* Fill in segment list */
  segment_list->weight = (weight != (u32) ~ 0 ? weight : SR_SEGMENT_LIST_WEIGHT_DEFAULT);
  segment_list->segments = vec_dup (sl);

  /* Create DPO */
  dpo_reset (&segment_list->sl_eos_dpo);
  dpo_reset (&segment_list->sl_neos_dpo);
  dpo_reset (&segment_list->sl_v4_dpo);
  dpo_reset (&segment_list->sl_v6_dpo);

  index_t mldi;
  mldi = mpls_label_dpo_create(sl, MPLS_EOS, 255, 0, DPO_PROTO_MPLS, &sm->mpls_lookup_dpo);
  dpo_set(&segment_list->sl_eos_dpo, DPO_MPLS_LABEL, DPO_PROTO_MPLS, mldi);

  mldi = mpls_label_dpo_create(sl, MPLS_NON_EOS, 255, 0, DPO_PROTO_MPLS, &sm->mpls_lookup_dpo);
  dpo_set(&segment_list->sl_neos_dpo, DPO_MPLS_LABEL, DPO_PROTO_MPLS, mldi);

  mldi = mpls_label_dpo_create(sl, MPLS_EOS, 255, 0, DPO_PROTO_IP4, &sm->mpls_lookup_dpo);
  dpo_set(&segment_list->sl_v4_dpo, DPO_MPLS_LABEL, DPO_PROTO_IP4, mldi);

  mldi = mpls_label_dpo_create(sl, MPLS_EOS, 255, 0, DPO_PROTO_IP6, &sm->mpls_lookup_dpo);
  dpo_set(&segment_list->sl_v6_dpo, DPO_MPLS_LABEL, DPO_PROTO_IP6, mldi);

  return segment_list;
}

/**
 * @brief Updates the Load Balancer after an SR Policy change
 *
 * @param sr_policy is the modified SR Policy
 */
static inline void
update_lb (mpls_sr_policy_t * sr_policy)
{
  flow_hash_config_t fhc;
  u32 *sl_index;
  mpls_sr_main_t *sm = &sr_mpls_main;
  mpls_sr_sl_t *segment_list;
  load_balance_path_t *path_bsid_eos, *path_bsid_neos, *path_bsid_v4, *path_bsid_v6;
  path_bsid_eos = path_bsid_neos = path_bsid_v4 = path_bsid_v6 = 0;
  dpo_id_t reset = DPO_INVALID;

  /* In case LB does not exist, create it */
  if (!dpo_id_is_valid (&sr_policy->bsid_eos_dpo))
  {
    fhc = fib_table_get_flow_hash_config (sr_policy->fib_table,
              dpo_proto_to_fib (DPO_PROTO_MPLS));

    dpo_set (&sr_policy->bsid_eos_dpo, DPO_LOAD_BALANCE,
       DPO_PROTO_MPLS, load_balance_create (0, DPO_PROTO_MPLS, fhc));
    dpo_set (&sr_policy->bsid_neos_dpo, DPO_LOAD_BALANCE,
       DPO_PROTO_MPLS, load_balance_create (0, DPO_PROTO_MPLS, fhc));
    dpo_set (&sr_policy->bsid_v4_dpo, DPO_LOAD_BALANCE,
       DPO_PROTO_MPLS, load_balance_create (0, DPO_PROTO_MPLS, fhc));
    dpo_set (&sr_policy->bsid_v6_dpo, DPO_LOAD_BALANCE,
       DPO_PROTO_MPLS, load_balance_create (0, DPO_PROTO_MPLS, fhc));

    /* Update FIB entry's DPO to point to SR with LB */
    fib_prefix_t pfx = {
      .fp_proto = FIB_PROTOCOL_MPLS,
      .fp_label = sr_policy->bsid,
      .fp_eos = MPLS_EOS,
      .fp_len = 21,
      .fp_payload_proto = DPO_PROTO_MPLS,
    };

    fib_table_entry_special_dpo_update (
      sr_policy->fib_table, 
      &pfx,
      FIB_SOURCE_SR,
      FIB_ENTRY_FLAG_EXCLUSIVE,
      &sr_policy->bsid_eos_dpo);

    pfx.fp_eos = MPLS_NON_EOS;

    fib_table_entry_special_dpo_update (
      sr_policy->fib_table, 
      &pfx,
      FIB_SOURCE_SR,
      FIB_ENTRY_FLAG_EXCLUSIVE,
      &sr_policy->bsid_neos_dpo);

    pfx.fp_eos = MPLS_EOS;
    pfx.fp_payload_proto = DPO_PROTO_IP4;

    fib_table_entry_special_dpo_update (
      sm->fib_table_ip4, 
      &pfx,
      FIB_SOURCE_SR,
      FIB_ENTRY_FLAG_EXCLUSIVE,
      &sr_policy->bsid_v4_dpo);

    pfx.fp_payload_proto = DPO_PROTO_IP6;

    fib_table_entry_special_dpo_update (
      sm->fib_table_ip6, 
      &pfx,
      FIB_SOURCE_SR,
      FIB_ENTRY_FLAG_EXCLUSIVE,
      &sr_policy->bsid_v6_dpo);
  }

  /* Create the LB path vector */
  vec_foreach (sl_index, sr_policy->segments_lists)
  {
    load_balance_path_t path = {
      .path_index = FIB_NODE_INDEX_INVALID,
      .path_dpo = DPO_INVALID,
    };
    segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);
    path.path_weight = segment_list->weight;

    dpo_copy(&path.path_dpo, &segment_list->sl_eos_dpo);
    vec_add1 (path_bsid_eos, path);

    path.path_dpo = reset;
    dpo_copy(&path.path_dpo, &segment_list->sl_neos_dpo);
    vec_add1 (path_bsid_neos, path);

    path.path_dpo = reset;
    dpo_copy(&path.path_dpo, &segment_list->sl_v4_dpo);
    vec_add1 (path_bsid_v4, path);

    path.path_dpo = reset;
    dpo_copy(&path.path_dpo, &segment_list->sl_v6_dpo);
    vec_add1 (path_bsid_v6, path);
  }

  /* Update LB multipath */
  load_balance_multipath_update (&sr_policy->bsid_eos_dpo, path_bsid_eos,
				 LOAD_BALANCE_FLAG_NONE);
  load_balance_multipath_update (&sr_policy->bsid_neos_dpo, path_bsid_neos,
         LOAD_BALANCE_FLAG_NONE);
  load_balance_multipath_update (&sr_policy->bsid_v4_dpo, path_bsid_v4,
         LOAD_BALANCE_FLAG_NONE);
  load_balance_multipath_update (&sr_policy->bsid_v6_dpo, path_bsid_v6,
         LOAD_BALANCE_FLAG_NONE);

  /* Cleanup */
  vec_free (path_bsid_eos);
  vec_free (path_bsid_neos);
  vec_free (path_bsid_v4);
  vec_free (path_bsid_v6);
}

/**
 * @brief Updates the Replicate DPO after an SR MPLS Policy change
 *
 * @param sr_policy is the modified SR MPLS Policy (type spray)
 */
static inline void
update_replicate (mpls_sr_policy_t * sr_policy)
{
  u32 *sl_index;
  mpls_sr_main_t *sm = &sr_mpls_main;
  mpls_sr_sl_t *segment_list;
  load_balance_path_t *path_bsid_eos, *path_bsid_neos, *path_bsid_v4, *path_bsid_v6;
  path_bsid_eos = path_bsid_neos = path_bsid_v4 = path_bsid_v6 = 0;
  dpo_id_t reset = DPO_INVALID;

  /* In case LB does not exist, create it */
  if (!dpo_id_is_valid (&sr_policy->bsid_eos_dpo))
  {
    dpo_set (&sr_policy->bsid_eos_dpo, DPO_REPLICATE,
       DPO_PROTO_MPLS, replicate_create (0, DPO_PROTO_MPLS));
    dpo_set (&sr_policy->bsid_neos_dpo, DPO_REPLICATE,
       DPO_PROTO_MPLS, replicate_create (0, DPO_PROTO_MPLS));
    dpo_set (&sr_policy->bsid_v4_dpo, DPO_REPLICATE,
       DPO_PROTO_MPLS, replicate_create (0, DPO_PROTO_MPLS));
    dpo_set (&sr_policy->bsid_v6_dpo, DPO_REPLICATE,
       DPO_PROTO_MPLS, replicate_create (0, DPO_PROTO_MPLS));

    /* Update FIB entry's DPO to point to SR with Spray */
    fib_prefix_t pfx = {
      .fp_proto = FIB_PROTOCOL_MPLS,
      .fp_label = sr_policy->bsid,
      .fp_eos = MPLS_EOS,
      .fp_len = 21,
      .fp_payload_proto = DPO_PROTO_MPLS,
    };

    fib_table_entry_special_dpo_update (
      sr_policy->fib_table, 
      &pfx,
      FIB_SOURCE_SR,
      FIB_ENTRY_FLAG_EXCLUSIVE,
      &sr_policy->bsid_eos_dpo);

    pfx.fp_eos = MPLS_NON_EOS;

    fib_table_entry_special_dpo_update (
      sr_policy->fib_table, 
      &pfx,
      FIB_SOURCE_SR,
      FIB_ENTRY_FLAG_EXCLUSIVE,
      &sr_policy->bsid_neos_dpo);

    pfx.fp_eos = MPLS_EOS;
    pfx.fp_payload_proto = DPO_PROTO_IP4;

    fib_table_entry_special_dpo_update (
      sm->fib_table_ip4, 
      &pfx,
      FIB_SOURCE_SR,
      FIB_ENTRY_FLAG_EXCLUSIVE,
      &sr_policy->bsid_v4_dpo);

    pfx.fp_payload_proto = DPO_PROTO_IP6;

    fib_table_entry_special_dpo_update (
      sm->fib_table_ip6, 
      &pfx,
      FIB_SOURCE_SR,
      FIB_ENTRY_FLAG_EXCLUSIVE,
      &sr_policy->bsid_v6_dpo);
  }

  /* Create the replicate path vector */
  vec_foreach (sl_index, sr_policy->segments_lists)
  {
    load_balance_path_t path = {
      .path_index = FIB_NODE_INDEX_INVALID,
      .path_dpo = DPO_INVALID,
      .path_weight = 1,
    };
    segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);

    dpo_copy (&path.path_dpo, &segment_list->sl_eos_dpo);
    vec_add1 (path_bsid_eos, path);

    path.path_dpo = reset;
    dpo_copy (&path.path_dpo, &segment_list->sl_neos_dpo);
    vec_add1 (path_bsid_neos, path);

    path.path_dpo = reset;
    dpo_copy (&path.path_dpo, &segment_list->sl_v4_dpo);
    vec_add1 (path_bsid_v4, path);

    path.path_dpo = reset;
    dpo_copy (&path.path_dpo, &segment_list->sl_v6_dpo);
    vec_add1 (path_bsid_v6, path);
  }

  /* Update replicate multipath */
  replicate_multipath_update (&sr_policy->bsid_eos_dpo, path_bsid_eos);
  replicate_multipath_update (&sr_policy->bsid_neos_dpo, path_bsid_neos);
  replicate_multipath_update (&sr_policy->bsid_v4_dpo, path_bsid_v4);
  replicate_multipath_update (&sr_policy->bsid_v6_dpo, path_bsid_v6);
}

/******************************* SR rewrite API *******************************/
/* Three functions for handling sr policies:
 *   -> sr_mpls_policy_add
 *   -> sr_mpls_policy_del
 *   -> sr_mpls_policy_mod
 * All of them are API. CLI function on sr_policy_command_fn                  */

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
	       u8 behavior, u32 fib_table, u32 weight)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  mpls_sr_policy_t *sr_policy = 0;
  uword *p;

  /* Search for existing keys (BSID) */
  p = mhash_get (&sm->sr_policies_index_hash, &bsid);
  if (p)
  {
    /* Add SR policy that already exists; complain */
    return -12;
  }

  /* Search collision in FIB entries */
  /* Explanation: It might be possible that some other entity has already
   * created a route for the BSID. This in theory is impossible, but in
   * practise we could see it. Assert it and scream if needed */
    fib_prefix_t pfx = {
      .fp_len = 20,
      .fp_proto = FIB_PROTOCOL_MPLS,
      .fp_label = bsid,
      .fp_payload_proto = DPO_PROTO_MPLS,
    };

  /* Lookup the FIB index associated to the table selected */
  u32 fib_index = fib_table_find (FIB_PROTOCOL_MPLS, (fib_table != (u32) ~ 0 ? fib_table : 0));
  if (fib_index == ~0)
    return -13;

  /* Lookup whether there exists an entry for the BSID */
  fib_node_index_t fei = fib_table_lookup_exact_match (fib_index, &pfx);
  if (FIB_NODE_INDEX_INVALID != fei)
    return -12;			//There is an entry for such lookup

  /* Add an SR policy object */
  pool_get (sm->sr_policies, sr_policy);
  memset (sr_policy, 0, sizeof (*sr_policy));
  sr_policy->bsid = bsid;
  sr_policy->type = behavior;
  sr_policy->fib_table = (fib_table != (u32) ~ 0 ? fib_table : 0);	//Is default FIB 0 ?

  /* Copy the key */
  mhash_set (&sm->sr_policies_index_hash, &bsid, sr_policy - sm->sr_policies, NULL);

  /* Create a segment list and add the index to the SR policy */
  create_sl (sr_policy, segments, weight);

  /* If the auxiliar FIB tables doesnt exist, create them */
  if (sm->fib_table_ip6 == (u32) ~ 0)
  {
      sm->fib_table_ip6 = fib_table_create_and_lock (FIB_PROTOCOL_MPLS,
                 "SR-MPLS steering of IP6 prefixes through BSIDs");
      sm->fib_table_ip4 = fib_table_create_and_lock (FIB_PROTOCOL_MPLS,
                 "SR-MPLS steering of IP4 prefixes through BSIDs");
  }

  /* Create MPLS FIB entry for the BindingSID attached to the DPO of the LB/REP */
  if (sr_policy->type == SR_POLICY_TYPE_DEFAULT)
    update_lb (sr_policy);
  else if (sr_policy->type == SR_POLICY_TYPE_SPRAY)
    update_replicate (sr_policy);
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
sr_mpls_policy_del (mpls_label_t bsid, u32 index)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  mpls_sr_policy_t *sr_policy = 0;
  mpls_sr_sl_t *segment_list;
  u32 *sl_index;
  uword *p;

  if (bsid)
  {
    p = mhash_get (&sm->sr_policies_index_hash, &bsid);
    if (p)
     sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);
    else
     return -1;
  }
  else
  {
    sr_policy = pool_elt_at_index (sm->sr_policies, index);
    if (!sr_policy)
      return -1;
  }

  /* Remove BindingSID FIB entry */
  fib_prefix_t pfx = {
    .fp_len = 20,
    .fp_proto = FIB_PROTOCOL_MPLS,
    .fp_label = bsid,
    .fp_payload_proto = DPO_PROTO_MPLS,
  };

  fib_table_entry_special_remove (sr_policy->fib_table, &pfx, FIB_SOURCE_SR);

  if (dpo_id_is_valid (&sr_policy->bsid_eos_dpo))
  {
    dpo_reset (&sr_policy->bsid_eos_dpo);
    dpo_reset (&sr_policy->bsid_neos_dpo);
    dpo_reset (&sr_policy->bsid_v4_dpo);
    dpo_reset (&sr_policy->bsid_v6_dpo);
  }

  /* Clean SID Lists */
  vec_foreach (sl_index, sr_policy->segments_lists)
  {
    segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);
    dpo_reset (&segment_list->sl_eos_dpo);
    dpo_reset (&segment_list->sl_neos_dpo);
    dpo_reset (&segment_list->sl_v4_dpo);
    dpo_reset (&segment_list->sl_v6_dpo);
    vec_free (segment_list->segments);
    pool_put_index (sm->sid_lists, *sl_index);
  }

  /* Remove SR policy entry */
  mhash_unset (&sm->sr_policies_index_hash, &sr_policy->bsid, NULL);
  pool_put (sm->sr_policies, sr_policy);

  /* If FIB empty unlock it */
  if (!pool_elts (sm->sr_policies) && !pool_elts (sm->steer_policies))
  {
    fib_table_unlock (sm->fib_table_ip6, FIB_PROTOCOL_MPLS);
    fib_table_unlock (sm->fib_table_ip4, FIB_PROTOCOL_MPLS);
    sm->fib_table_ip6 = (u32) ~ 0;
    sm->fib_table_ip4 = (u32) ~ 0;
  }

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
 * @param index is the index of the SR policy
 * @param fib_table is the VRF where to install the FIB entry for the BSID
 * @param operation is the operation to perform (among the top ones)
 * @param segments is a vector of IPv6 address composing the segment list
 * @param sl_index is the index of the Segment List to modify/delete
 * @param weight is the weight of the sid list. optional.
 *
 * @return 0 if correct, else error
 */
int
sr_mpls_policy_mod (mpls_label_t bsid, u32 index, u32 fib_table,
	       u8 operation, mpls_label_t * segments, u32 sl_index, u32 weight)
{
  mpls_sr_main_t *sm = &sr_mpls_main;
  mpls_sr_policy_t *sr_policy = 0;
  mpls_sr_sl_t *segment_list;
  u32 *sl_index_iterate;
  uword *p;

  if (bsid)
  {
    p = mhash_get (&sm->sr_policies_index_hash, &bsid);
    if (p)
      sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);
    else
      return -1;
  }
  else
  {
    sr_policy = pool_elt_at_index (sm->sr_policies, index);
    if (!sr_policy)
      return -1;
  }

  if (operation == 1)		/* Add SR List to an existing SR policy */
  {
    /* Create the new SL */
    segment_list = create_sl (sr_policy, segments, weight);

    /* Create a new LB DPO */
    if (sr_policy->type == SR_POLICY_TYPE_DEFAULT)
      update_lb (sr_policy);
    else if (sr_policy->type == SR_POLICY_TYPE_SPRAY)
      update_replicate (sr_policy);
  }
  else if (operation == 2)	/* Delete SR List from an existing SR policy */
  {
    /* Check that currently there are more than one SID list */
    if (vec_len (sr_policy->segments_lists) == 1)
      return -21;

    /* Check that the SR list does exist and is assigned to the sr policy */
    vec_foreach (sl_index_iterate, sr_policy->segments_lists)
    if (*sl_index_iterate == sl_index)
      break;

    if (*sl_index_iterate != sl_index)
      return -22;

    /* Remove the lucky SR list that is being kicked out */
    segment_list = pool_elt_at_index (sm->sid_lists, sl_index);
    vec_free (segment_list->segments);
    dpo_reset (&segment_list->sl_eos_dpo);
    dpo_reset (&segment_list->sl_neos_dpo);
    dpo_reset (&segment_list->sl_v4_dpo);
    dpo_reset (&segment_list->sl_v6_dpo);
    pool_put_index (sm->sid_lists, sl_index);
    vec_del1 (sr_policy->segments_lists, sl_index_iterate - sr_policy->segments_lists);

    /* Create a new LB DPO */
    if (sr_policy->type == SR_POLICY_TYPE_DEFAULT)
      update_lb (sr_policy);
    else if (sr_policy->type == SR_POLICY_TYPE_SPRAY)
      update_replicate (sr_policy);
  }
  else if (operation == 3)	/* Modify the weight of an existing SR List */
  {
    /* Find the corresponding SL */
    vec_foreach (sl_index_iterate, sr_policy->segments_lists)
    if (*sl_index_iterate == sl_index)
      break;

    if (*sl_index_iterate != sl_index)
      return -32;

    /* Change the weight */
    segment_list = pool_elt_at_index (sm->sid_lists, sl_index);
    segment_list->weight = weight;

    /* Update LB */
    if (sr_policy->type == SR_POLICY_TYPE_DEFAULT)
      update_lb (sr_policy);
  }
  else				/* Incorrect op. */
    return -1;

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
  u32 sr_policy_index = (u32) ~ 0, sl_index = (u32) ~ 0;
  u32 weight = (u32) ~ 0, fib_table = (u32) ~ 0;
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
    else if (!policy_set && unformat (input, "bsid %U", unformat_mpls_unicast_label, &bsid))
      policy_set = 1;
    else if (!is_add && !policy_set && unformat (input, "index %d", &sr_policy_index))
      policy_set = 1;
    else if (unformat (input, "weight %d", &weight));
    else if (unformat (input, "next %U", unformat_mpls_unicast_label, &next_label))
    {
      vec_add (segments, &next_label, 1);
    }
    else if (unformat (input, "add sl"))
      operation = 1;
    else if (unformat (input, "del sl index %d", &sl_index))
      operation = 2;
    else if (unformat (input, "mod sl index %d", &sl_index))
      operation = 3;
    else if (fib_table == (u32) ~ 0 && unformat (input, "fib-table %d", &fib_table));
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
		  (is_spray ? SR_POLICY_TYPE_SPRAY : SR_POLICY_TYPE_DEFAULT), fib_table, weight);
  }
  else if (is_del)
    rv = sr_mpls_policy_del ((sr_policy_index != (u32) ~ 0 ? (u32)~0 : bsid), sr_policy_index);
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
      rv = sr_mpls_policy_mod ((sr_policy_index != (u32) ~ 0 ? (u32)~0 : bsid),
		    sr_policy_index, fib_table, operation, segments, sl_index, weight);
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
    case -13:
      return clib_error_return (0, "The specified FIB table does not exist.");
    case -21:
      return clib_error_return (0,
  			"The selected SR policy only contains ONE segment list. "
  			"Please remove the SR policy instead");
    case -22:
      return clib_error_return (0,
  			"Could not delete the segment list. "
  			"It is not associated with that SR policy.");
    case -32:
      return clib_error_return (0,
  			"Could not modify the segment list. "
  			"The given SL is not associated with such SR policy.");
    default:
      return clib_error_return (0, "BUG: sr policy returns %d", rv);
  }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (sr_mpls_policy_command, static) = {
  .path = "sr mpls policy",
  .short_help = "sr mpls policy [add||del||mod] bsid 2999 "
    "next 10 next 20 next 30 (weight 1) (fib-table 2) (spray)",
  .long_help =
    "TBD.\n",
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
  pool_foreach  (sr_policy, sm->sr_policies, {vec_add1 (vec_policies, sr_policy); } );
  /* *INDENT-ON* */

  vec_foreach_index (i, vec_policies)
  {
    sr_policy = vec_policies[i];
    vlib_cli_output (vm, "[%u].-\tBSID: %U",
		     (u32) (sr_policy - sm->sr_policies),
		     format_mpls_unicast_label, sr_policy->bsid);
    vlib_cli_output (vm, "\tType: %s",
		     (sr_policy->type ==
		      SR_POLICY_TYPE_DEFAULT ? "Default" : "Spray"));
    vlib_cli_output (vm, "\tFIB table: %u",
		     (sr_policy->fib_table !=
		      (u32) ~ 0 ? sr_policy->fib_table : 0));
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
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_sr_mpls_policies_command, static) = {
  .path = "show sr mpls policies",
  .short_help = "show sr mpls policies",
  .function = show_sr_mpls_policies_command_fn,
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
  mhash_init (&sm->sr_policies_index_hash, sizeof (uword),
	      sizeof (mpls_label_t));

  lookup_dpo_add_or_lock_w_fib_index(0, // Default MPLS FIB
                                   DPO_PROTO_MPLS,
                                   LOOKUP_UNICAST,
                                   LOOKUP_INPUT_DST_ADDR,
                                   LOOKUP_TABLE_FROM_INPUT_INTERFACE,
                                   &sm->mpls_lookup_dpo);

  sm->fib_table_ip6 = (u32) ~ 0;
  sm->fib_table_ip4 = (u32) ~ 0;

  return 0;
}

VLIB_INIT_FUNCTION (sr_mpls_policy_rewrite_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
