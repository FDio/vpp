/*
 * sr_steering.c: ipv6 policy insertion and steering
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
 * @brief SR policy creation and application
 *
 * Create an SR policy. 
 * An SR policy can be either of 'default' type or 'spray' type
 * An SR policy has attached a list of SID lists. 
 * In case the SR policy is a default one it will load balance among them.
 * An SR policy has associated a BindingSID. 
 * In case any packet arrives with IPv6 DA == BindingSID then the SR policy
 * associated to such bindingSID will be applied to such packet.
 *
 * SR policies can be applied either by using IPv6 encapsulation or 
 * SRH insertion. Both methods can be found on this file.
 *
 * Traffic input usually is IPv6 packets. However it is possible to have
 * IPv4 packets or L2 frames. (that are encapsulated into IPv6 with SRH)
 *
 * This file provides the appropiates VPP graph nodes to do any of these 
 * methods.
 *
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/sr/sr.h>
#include <vnet/ip/ip.h>
#include <vnet/sr/sr_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/dpo.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

/**
 * @brief SR policy rewrite trace
 */
typedef struct {
  ip6_address_t src, dst;
} sr_policy_rewrite_trace_t;

/* Graph arcs */
#define foreach_sr_policy_rewrite_next     \
_(IP6_LOOKUP, "ip6-lookup")         \
_(ERROR, "error-drop")

typedef enum {
#define _(s,n) SR_POLICY_REWRITE_NEXT_##s,
  foreach_sr_policy_rewrite_next
#undef _
  SR_POLICY_REWRITE_N_NEXT,
} sr_policy_rewrite_next_t;

/* SR rewrite errors */
#define foreach_sr_policy_rewrite_error                            \
_(INTERNAL_ERROR, "Segment Routing undefined error")        \
_(COUNTER_TOTAL, "SR steered IPv6 packets")                 \
_(COUNTER_ENCAP, "SR: Encaps packets")                      \
_(COUNTER_INSERT, "SR: SRH inserted packets")               \
_(COUNTER_BSID, "SR: BindingSID steered packets")

typedef enum {
#define _(sym,str) SR_POLICY_REWRITE_ERROR_##sym,
  foreach_sr_policy_rewrite_error
#undef _
  SR_POLICY_REWRITE_N_ERROR,
} sr_policy_rewrite_error_t;

static char * sr_policy_rewrite_error_strings[] = {
#define _(sym,string) string,
  foreach_sr_policy_rewrite_error
#undef _
};

/**
 * @brief Dynamically added SR SL DPO type
 */
static dpo_type_t sr_pr_encaps_dpo_type;
static dpo_type_t sr_pr_insert_dpo_type;

/**
 * @brief IPv6 SA for encapsulated packets
 */
static ip6_address_t sr_pr_encaps_src;

/******************* SR rewrite set encaps IPv6 source addr *******************/
/* Note:  This is temporal. We don't know whether to follow this path or
          take the ip address of a loopback interface or even the OIF         */

static clib_error_t * 
set_sr_src_command_fn (vlib_main_t * vm, unformat_input_t * input, 
  vlib_cli_command_t * cmd)
{
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat (input, "addr %U", unformat_ip6_address, &sr_pr_encaps_src))
      return 0;
    else 
      return clib_error_return (0, "No address specified");
  }
  return clib_error_return (0, "No address specified");
}

VLIB_CLI_COMMAND (set_sr_src_command, static) = {
  .path = "set sr encaps source",
  .short_help = "set sr encaps source addr <ip6_addr>",
  .function = set_sr_src_command_fn,
};

/*********************** SR rewrite string computation ************************/
/**
 * @brief SR rewrite string computation for IPv6 encapsulation (inline)
 *
 * @param sl is a vector of IPv6 addresses composing the Segment List
 *
 * @return precomputed rewrite string for encapsulation
 */
static inline u8 *
compute_rewrite_encaps (ip6_address_t *sl)
{
  ip6_header_t *iph;
  ip6_sr_header_t *srh;
  ip6_address_t *addrp, *this_address;
  u32 header_length = 0;
  u8 *rs = NULL;

  header_length = 0;
  header_length += IPv6_DEFAULT_HEADER_LENGTH;
  if (vec_len(sl) > 1)
  {
    header_length += sizeof(ip6_sr_header_t);
    header_length += vec_len(sl)*sizeof(ip6_address_t);
  }

  vec_validate (rs, header_length-1);

  iph = (ip6_header_t *) rs;
  iph->src_address.as_u64[0] = sr_pr_encaps_src.as_u64[0];
  iph->src_address.as_u64[1] = sr_pr_encaps_src.as_u64[1];
  iph->payload_length = header_length - IPv6_DEFAULT_HEADER_LENGTH;
  iph->protocol = IP_PROTOCOL_IPV6;
  iph->hop_limit = IPv6_DEFAULT_HOP_LIMIT;

  if (vec_len(sl) > 1)
  {
    srh = (ip6_sr_header_t *)(iph + 1);
    iph->protocol = IP_PROTOCOL_IPV6_ROUTE;
    srh->protocol = IP_PROTOCOL_IPV6;
    srh->type = ROUTING_HEADER_TYPE_SR;
    srh->segments_left = vec_len(sl) - 1;
    srh->first_segment = vec_len(sl) - 1;
    srh->length = ((sizeof(ip6_sr_header_t)+
                  (vec_len(sl)*sizeof(ip6_address_t)))/8)-1;
    srh->flags = 0x00;
    srh->reserved = 0x00;
    addrp = srh->segments + vec_len(sl) - 1;
    vec_foreach(this_address, sl) 
    {
      clib_memcpy (addrp->as_u8, this_address->as_u8, sizeof(ip6_address_t));
      addrp--;
    }
  }
  iph->dst_address.as_u64[0] = sl->as_u64[0];
  iph->dst_address.as_u64[1] = sl->as_u64[1];
  return rs;
}

/**
 * @brief SR rewrite string computation for SRH insertion (inline)
 *
 * @param sl is a vector of IPv6 addresses composing the Segment List
 *
 * @return precomputed rewrite string for SRH insertion
 */
static inline u8 *
compute_rewrite_insert (ip6_address_t *sl)
{
  ip6_sr_header_t *srh;
  ip6_address_t *addrp, *this_address;
  u32 header_length = 0;
  u8 *rs = NULL;

  header_length = 0;
  header_length += sizeof(ip6_sr_header_t);
  header_length += (vec_len(sl)+1)*sizeof(ip6_address_t);

  vec_validate (rs, header_length-1);

  srh = (ip6_sr_header_t *) rs;
  srh->type = ROUTING_HEADER_TYPE_SR;
  srh->segments_left = vec_len(sl);
  srh->first_segment = vec_len(sl);
  srh->length = ((sizeof(ip6_sr_header_t)+
                ((vec_len(sl)+1)*sizeof(ip6_address_t)))/8)-1;
  srh->flags = IP6_SR_HEADER_FLAG_CLEANUP;
  srh->reserved = 0x00;
  addrp = srh->segments + vec_len(sl);
  vec_foreach(this_address, sl) 
  {
    clib_memcpy (addrp->as_u8, this_address->as_u8, sizeof(ip6_address_t));
    addrp--;
  }
  return rs;
}

/**
 * @brief SR rewrite string computation for SRH insertion with BSID (inline)
 *
 * @param sl is a vector of IPv6 addresses composing the Segment List
 *
 * @return precomputed rewrite string for SRH insertion with BSID
 */
static inline u8 *
compute_rewrite_bsid (ip6_address_t *sl)
{
  ip6_sr_header_t *srh;
  ip6_address_t *addrp, *this_address;
  u32 header_length = 0;
  u8 *rs = NULL;

  header_length = 0;
  header_length += sizeof(ip6_sr_header_t);
  header_length += vec_len(sl)*sizeof(ip6_address_t);

  vec_validate (rs, header_length-1);

  srh = (ip6_sr_header_t *) rs;
  srh->type = ROUTING_HEADER_TYPE_SR;
  srh->segments_left = vec_len(sl);
  srh->first_segment = vec_len(sl);
  srh->length = ((sizeof(ip6_sr_header_t)+
                (vec_len(sl)*sizeof(ip6_address_t)))/8)-1;
  srh->flags = IP6_SR_HEADER_FLAG_CLEANUP;
  srh->reserved = 0x00;
  addrp = srh->segments + vec_len(sl) - 1;
  vec_foreach(this_address, sl) 
  {
    clib_memcpy (addrp->as_u8, this_address->as_u8, sizeof(ip6_address_t));
    addrp--;
  }
  return rs;
}

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
static inline ip6_sr_sl_t *
create_sl (ip6_sr_policy_t *sr_policy, ip6_address_t *sl, u32 weight, u8 is_encap)
{
  ip6_sr_main_t * sm = &sr_main;
  ip6_sr_sl_t *segment_list;

  pool_get (sm->sid_lists, segment_list);
  memset (segment_list, 0, sizeof(*segment_list));

  vec_add1(sr_policy->segments_lists, segment_list - sm->sid_lists);

  /* Fill in segment list */
  segment_list->weight = 
    (weight != (u32)~0 ? weight : SR_SEGMENT_LIST_WEIGHT_DEFAULT);
  segment_list->segments = vec_dup(sl);

  if (is_encap)
  {
    segment_list->rewrite = compute_rewrite_encaps (sl);
    segment_list->rewrite_bsid = segment_list->rewrite;
  }
  else
  {
    segment_list->rewrite = compute_rewrite_insert (sl);
    segment_list->rewrite_bsid = compute_rewrite_bsid (sl);
  }

  /* Create DPO plus entry in IPv6 FIB for the BindingSID*/ 
  dpo_reset (&segment_list->dpo);

  if (is_encap)
    dpo_set ( &segment_list->dpo, sr_pr_encaps_dpo_type, DPO_PROTO_IP6, 
            segment_list - sm->sid_lists );
  else
    dpo_set ( &segment_list->dpo, sr_pr_insert_dpo_type, DPO_PROTO_IP6, 
            segment_list - sm->sid_lists );

  return segment_list;
}

/**
 * @brief Updates the Load Balancer after an SR Policy change
 *
 * @param sr_policy is the modified SR Policy
 */
static inline void
update_lb (ip6_sr_policy_t *sr_policy)
{
  flow_hash_config_t fhc;
  u32 *sl_index;
  ip6_sr_sl_t *segment_list;
  ip6_sr_main_t * sm = &sr_main;
  load_balance_path_t path, *path_vector=0;

  /* In case LB does not exist, create it */
  if (!dpo_id_is_valid(&sr_policy->dpo))
  {
    //WARNING: Argument is fib_table, not fib_index??
    fhc = fib_table_get_flow_hash_config(sr_policy->fib_table,
      dpo_proto_to_fib(DPO_PROTO_IP6));

    dpo_set(&sr_policy->dpo, DPO_LOAD_BALANCE, DPO_PROTO_IP6,
            load_balance_create(0, DPO_PROTO_IP6, fhc));

    /* Update FIB entry's DPO to point to SR without LB*/
    fib_prefix_t pfx = {
      .fp_proto = FIB_PROTOCOL_IP6,
      .fp_len = 128,
      .fp_addr = {
       .ip6 = sr_policy->bsid,
      }
    };
    fib_table_entry_special_dpo_update (
      fib_table_id_find_fib_index(FIB_PROTOCOL_IP6, sr_policy->fib_table), 
      &pfx, 
      FIB_SOURCE_SR, 
      FIB_ENTRY_FLAG_EXCLUSIVE, 
      &sr_policy->dpo);

  }

  /* Create the LB path vector */
  //path_vector = vec_new(load_balance_path_t, vec_len(sr_policy->segments_lists));
  vec_foreach(sl_index, sr_policy->segments_lists)
  {
    segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);
    path.path_dpo = segment_list->dpo;
    path.path_weight = segment_list->weight;
    vec_add1(path_vector, path);
  }

  /* Update LB multipath */
  load_balance_multipath_update(&sr_policy->dpo, path_vector, 
                                LOAD_BALANCE_FLAG_NONE);
  //TODO: REVIEW LB_FLAGS

  /* Cleanup */
  vec_free(path_vector);
}

/******************************* SR rewrite API *******************************/
/* Three functions for handling sr policies:
 *   -> sr_policy_add
 *   -> sr_policy_del
 *   -> sr_policy_mod     
 * All of them are API. CLI function on sr_policy_command_fn                  */

/**
 * @brief Create a new SR policy
 *
 * @param bsid is the bindingSID of the SR Policy
 * @param segments is a vector of IPv6 address composing the segment list
 * @param weight is the weight of the sid list. optional.
 * @param behavior is the behavior of the SR policy. (default//spray)
 * @param fib_table is the VRF where to install the FIB entry for the BSID
 * @param is_encap (bool) whether SR policy should behave as Encap/SRH Insertion
 *
 * @return 0 if correct, else error
 */
int 
sr_policy_add (vlib_main_t * vm, ip6_address_t *bsid, ip6_address_t *segments,
                  u32 weight, u8 behavior, u32 fib_table, u8 is_encap)
{
  ip6_sr_main_t * sm = &sr_main;
  ip6_sr_policy_t *sr_policy = 0;
  ip6_sr_sl_t *segment_list;
  ip6_address_t *key_copy;
  uword *p;

  /* Search for existing keys (BSID) */
  p = hash_get_mem (sm->sr_policy_index_by_key, bsid);
  if (p)
  {
    /* Add SR policy that already exists; complain*/
    return -1;
  }

  /* Search collision in FIB entries */
  /* Explanation: It might be possible that some other entity has already
   * created a route for the BSID. This in theory is impossible, but in
   * practise we could see it. Assert it and scream if needed */
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 128,
    .fp_addr = {
      .ip6 = *bsid,
    }
  };

  /* Lookup the FIB index associated to the table selected */
  u32 fib_index = fib_table_id_find_fib_index (FIB_PROTOCOL_IP6, 
                                              (fib_table!=(u32)~0?fib_table:0));
  if (fib_index == ~0)
    return -13;

  /* Lookup whether there exists an entry for the BSID*/
  fib_node_index_t fei = fib_table_lookup_exact_match (fib_index, &pfx);
  if (FIB_NODE_INDEX_INVALID != fei)
    return -12; //There is an entry for such lookup

  /* Add an SR policy object*/
  pool_get (sm->sr_policies, sr_policy);
  memset (sr_policy, 0, sizeof(*sr_policy));
  clib_memcpy(&sr_policy->bsid, bsid, sizeof(ip6_address_t));
  sr_policy->type = behavior;
  sr_policy->fib_table = (fib_table!=(u32)~0?fib_table:0);  //Is default FIB 0 ?
  sr_policy->is_encap = is_encap;

  /* Copy the key */
  key_copy = vec_new (ip6_address_t, 1);
  clib_memcpy (key_copy, bsid, sizeof(ip6_address_t));
  hash_set_mem (sm->sr_policy_index_by_key, key_copy, sr_policy - sm->sr_policies);

  /* Create a segment list and add the index to the SR policy */
  segment_list = create_sl (sr_policy, segments, weight, is_encap);

  /* Create IPv6 FIB for the BindingSID attached to the DPO of the only SL*/ 
  if(sr_policy->type == SR_POLICY_TYPE_DEFAULT)
    update_lb(sr_policy);
  else if(sr_policy->type == SR_POLICY_TYPE_SPRAY)
  {
    dpo_reset (&sr_policy->dpo);
    dpo_set ( &sr_policy->dpo, sm->sr_pr_spray_dpo_type, DPO_PROTO_IP6, 
            segment_list - sm->sid_lists );
    fib_table_entry_special_dpo_add ( fib_index, 
                                      &pfx, 
                                      FIB_SOURCE_SR, 
                                      FIB_ENTRY_FLAG_EXCLUSIVE, 
                                      &sr_policy->dpo);
  }
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
sr_policy_del (vlib_main_t * vm, ip6_address_t *bsid, u32 index)
{
  ip6_sr_main_t * sm = &sr_main;
  ip6_sr_policy_t *sr_policy = 0;
  ip6_sr_sl_t *segment_list;
  ip6_address_t *key_copy;
  u32 *sl_index;
  uword *p;

  hash_pair_t *hp;
  if(bsid)
  {
    p = hash_get_mem (sm->sr_policy_index_by_key, bsid);
    if(p)
      sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);
    else
      return -1;
  }
  else
  {
    sr_policy = pool_elt_at_index (sm->sr_policies, index);
    if(!sr_policy)
      return -1;
  }

  /* Remove BindingSID FIB entry */
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 128,
    .fp_addr = {
      .ip6 = sr_policy->bsid,
    },
  };  

  fib_table_entry_special_remove (
    fib_table_id_find_fib_index(FIB_PROTOCOL_IP6, sr_policy->fib_table),
    &pfx, FIB_SOURCE_SR);

  if (dpo_id_is_valid(&sr_policy->dpo))
    dpo_reset(&sr_policy->dpo);

  /* Clean SID Lists */
  vec_foreach(sl_index, sr_policy->segments_lists) 
  {
    segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);
    vec_free(segment_list->segments);
    vec_free(segment_list->rewrite);
    vec_free(segment_list->rewrite_bsid);
    pool_put_index (sm->sid_lists, *sl_index);
  }

  /* Remove SR policy entry */
  hp = hash_get_pair (sm->sr_policy_index_by_key, &sr_policy->bsid);
  key_copy = (void *)(hp->key);
  hash_unset_mem (sm->sr_policy_index_by_key, &sr_policy->bsid);
  vec_free (key_copy);
  pool_put (sm->sr_policies, sr_policy);
  
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
 * @param is_encap Mode. Encapsulation or SRH insertion.
 *
 * @return 0 if correct, else error
 */
int 
sr_policy_mod ( vlib_main_t * vm, ip6_address_t *bsid, u32 index, u32 fib_table,
                u8 operation, ip6_address_t *segments, u32 sl_index, u32 weight,
                u8 is_encap)
{
  ip6_sr_main_t * sm = &sr_main;
  ip6_sr_policy_t *sr_policy = 0;
  ip6_sr_sl_t *segment_list;
  u32 *sl_index_iterate;
  uword *p;

  if(bsid)
  {
    p = hash_get_mem (sm->sr_policy_index_by_key, bsid);
    if(p)
      sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);
    else
      return -1;
  }
  else
  {
    sr_policy = pool_elt_at_index (sm->sr_policies, index);
    if(!sr_policy)
      return -1;
  }

  if (operation == 1)       /* Add SR List to an existing SR policy */
  {
    /* Create the new SL */
    segment_list = create_sl (sr_policy, segments, weight, is_encap);
    
    /* Create a new LB DPO */
    if(sr_policy->type == SR_POLICY_TYPE_DEFAULT)
      update_lb(sr_policy);
  }
  else if (operation == 2)  /* Delete SR List from an existing SR policy */
  {
    /* Check that currently there are more than one SID list */
    if (vec_len(sr_policy->segments_lists) == 1)
      return -21;

    /* Check that the SR list does exist and is assigned to the sr policy */
    vec_foreach (sl_index_iterate, sr_policy->segments_lists)
      if(*sl_index_iterate == sl_index)
        break;

    if(*sl_index_iterate != sl_index)
      return -22;

    /* Remove the lucky SR list that is being kicked out */
    segment_list = pool_elt_at_index (sm->sid_lists, sl_index);
    vec_free(segment_list->segments);
    vec_free(segment_list->rewrite);
    vec_free(segment_list->rewrite_bsid);
    pool_put_index (sm->sid_lists, sl_index);
    vec_del1(sr_policy->segments_lists, sl_index_iterate-sr_policy->segments_lists);

    /* Create a new LB DPO */
    if(sr_policy->type == SR_POLICY_TYPE_DEFAULT)
      update_lb(sr_policy);
  }
  else if (operation == 3)  /* Modify the weight of an existing SR List */
  {
    /* Find the corresponding SL*/
    vec_foreach (sl_index_iterate, sr_policy->segments_lists)
      if(*sl_index_iterate == sl_index)
        break;

    if(*sl_index_iterate != sl_index)
      return -32;

    /* Change the weight */
    segment_list = pool_elt_at_index (sm->sid_lists, sl_index);
    segment_list->weight = weight;

    /* Update LB */
    if(sr_policy->type == SR_POLICY_TYPE_DEFAULT)
      update_lb(sr_policy);
  }
  else                      /* Incorrect op. */
    return -1;

  return 0;
} 

/**
 * @brief CLI for 'sr policies' command family
 */
static clib_error_t *
sr_policy_command_fn (vlib_main_t * vm, unformat_input_t * input, 
                      vlib_cli_command_t * cmd)
{
  int rv;
  char is_del = 0, is_add = 0, is_mod = 0;
  char policy_set = 0;
  ip6_address_t bsid, next_address;
  u32 sr_policy_index = (u32)~0, sl_index = (u32)~0;
  u32 weight = (u32)~0, fib_table = (u32)~0;
  ip6_address_t * segments = 0, *this_seg;
  u8 operation = 0;
  char is_encap = 1;
  char is_spray = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
  {
    if (!is_add && !is_mod && !is_del && unformat (input, "add"))
      is_add = 1;
    else if (!is_add && !is_mod && !is_del && unformat (input, "del"))
      is_del = 1;
    else if (!is_add && !is_mod && !is_del && unformat (input, "mod"))
      is_mod = 1;
    else if (!policy_set && unformat (input, "bsid %U", unformat_ip6_address, &bsid))
      policy_set = 1;
    else if (!is_add && !policy_set && unformat (input, "index %d", &sr_policy_index))
      policy_set = 1;
    else if (unformat (input, "weight %d", &weight));
    else if (unformat (input, "next %U", unformat_ip6_address, &next_address))
    {
      vec_add2 (segments, this_seg, 1);
      clib_memcpy (this_seg->as_u8, next_address.as_u8, sizeof (*this_seg));
    }
    else if (unformat (input, "add sl"))
      operation = 1;
    else if (unformat (input, "del sl index %d", &sl_index))
      operation = 2;
    else if (unformat (input, "mod sl index %d", &sl_index))
      operation = 3;
    else if (fib_table == (u32)~0 && unformat (input, "fib-table %d", &fib_table));
    else if (unformat (input, "encap"))
      is_encap = 1;
    else if (unformat (input, "srh"))
      is_encap = 0;
    else if (unformat (input, "spray"))
      is_spray = 1;
    else 
      break;
  }

  if (!policy_set)
    return clib_error_return (0, "No SR policy BSID or index specified");

  if (is_add)
  {
    if (vec_len(segments) == 0)
      return clib_error_return (0, "No Segment List specified");
    rv = sr_policy_add (vm, &bsid, segments, weight,
                       (is_spray?SR_POLICY_TYPE_SPRAY:SR_POLICY_TYPE_DEFAULT),
                        fib_table, is_encap);
  }
  else if (is_del)
    rv = sr_policy_del (vm, (sr_policy_index != (u32)~0 ? NULL : &bsid),
                        sr_policy_index);
  else if (is_mod)
  {
    if (!operation)
      return clib_error_return (0, "No SL modification specified");
    if (operation != 1 && sl_index == (u32)~0)
      return clib_error_return (0, "No Segment List index specified");
    if (operation == 1 && vec_len(segments) == 0)
      return clib_error_return (0, "No Segment List specified");
    if (operation == 3 && weight == (u32)~0)
      return clib_error_return (0, "No new weight for the SL specified");
    rv = sr_policy_mod (vm, (sr_policy_index != (u32)~0 ? NULL : &bsid),
                        sr_policy_index, fib_table, operation, segments, 
                        sl_index, weight, is_encap);
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
      return clib_error_return (0, 
        "The specified FIB table does not exist.");
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
      return clib_error_return (0, "BUG: sr vpn policy returns %d", rv);
  }
  return 0;
}

VLIB_CLI_COMMAND (sr_policy_command, static) = {
  .path = "sr policy",
  .short_help = "sr policy [add||del||mod] [bsid 2001::1||index 5] "
    "next A:: next B:: next C:: (weight 1) (fib-table 2) (encap|srh)",
  .long_help =
    "Available in the near future. TBD. Sorry.\n",
  .function = sr_policy_command_fn,
};

/**
 * @brief CLI to display onscreen all the SR policies
 */
static clib_error_t * 
show_sr_policies_command_fn ( vlib_main_t * vm, unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  ip6_sr_main_t * sm = &sr_main;
  u32 *sl_index;
  ip6_sr_sl_t *segment_list = 0;
  ip6_sr_policy_t *sr_policy = 0;
  ip6_sr_policy_t **vec_policies = 0;
  ip6_address_t *addr;
  u8 * s;
  int i=0;

  vlib_cli_output (vm,"SR policies:");

  pool_foreach  (sr_policy, sm->sr_policies, 
                {vec_add1 (vec_policies, sr_policy); } );

  vec_foreach_index(i,vec_policies)
  {
    sr_policy = vec_policies[i];
    vlib_cli_output (vm, "[%u].-\tBSID: %U", 
                    (u32)(sr_policy-sm->sr_policies), 
                    format_ip6_address, &sr_policy->bsid);
    vlib_cli_output (vm, "\tType: %s", 
          (sr_policy->type == SR_POLICY_TYPE_DEFAULT ? "Default" : "Spray"));
    vlib_cli_output (vm, "\tFIB table: %u", 
          (sr_policy->fib_table != (u32)~0 ? sr_policy->fib_table : 0));
    vlib_cli_output (vm, "\tSegment Lists:");
    vec_foreach(sl_index, sr_policy->segments_lists)
    {
      s = NULL;
      s = format (s, "\t[%u].- ", *sl_index);
      segment_list = pool_elt_at_index(sm->sid_lists, *sl_index);
      s = format (s, "{");
      vec_foreach(addr, segment_list->segments)
      {
        s = format (s, "%U, ", format_ip6_address, addr);
      }
      s = format (s, "\b\b} ");
      s = format (s, "weight: %u", segment_list->weight);
      vlib_cli_output (vm, "  %s", s);
    }
    vlib_cli_output (vm, "-----------");
  }
  return 0;
}

VLIB_CLI_COMMAND (show_sr_policies_command, static) = {
  .path = "show sr policies",
  .short_help = "show sr policies",
  .function = show_sr_policies_command_fn,
};

/*************************** SR rewrite graph node ****************************/
/**
 * @brief Trace for the SR Policy Rewrite graph node
 */
static u8 * format_sr_policy_rewrite_trace (u8 * s, va_list * args)
{
  //TODO
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sr_policy_rewrite_trace_t * t = va_arg (*args, sr_policy_rewrite_trace_t *);

  s = format
  (s, "SR-policy-rewrite: src %U dst %U",
   format_ip6_address, &t->src, format_ip6_address, &t->dst);

  return s;
}

/**
 * @brief Graph node for applying a SR policy into a packet. Encapsulation
 */
static uword
sr_policy_rewrite_encaps (vlib_main_t * vm, vlib_node_runtime_t * node, 
  vlib_frame_t * from_frame)
{
  ip6_sr_main_t * sm = &sr_main;
  u32 n_left_from, next_index, * from, * to_next;
  
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  
  next_index = node->cached_next_index;

  int encap_pkts=0, bsid_pkts=0;
  
  while (n_left_from > 0)
  {
    u32 n_left_to_next;
    
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    /* Quad - Loop */
    while (n_left_from >= 8 && n_left_to_next >= 4)
    {
      u32 bi0, bi1, bi2, bi3;
      vlib_buffer_t *b0, *b1, *b2, *b3;
      u32 next0, next1, next2, next3;
      next0 = next1 = next2 = next3 = SR_POLICY_REWRITE_NEXT_IP6_LOOKUP;
      ip6_header_t * ip0, *ip1, *ip2, *ip3;
      ip6_header_t * ip0_encap, *ip1_encap, *ip2_encap, *ip3_encap;
      ip6_sr_sl_t *sl0, *sl1, *sl2, *sl3;
      u16 new_l0, new_l1, new_l2, new_l3;

      /* Prefetch next iteration. */
      {
        vlib_buffer_t *p4, *p5, *p6, *p7;

        p4 = vlib_get_buffer (vm, from[4]);
        p5 = vlib_get_buffer (vm, from[5]);
        p6 = vlib_get_buffer (vm, from[6]);
        p7 = vlib_get_buffer (vm, from[7]);

        /* Prefetch the buffer header and packet for the N+2 loop iteration */
        vlib_prefetch_buffer_header (p4, LOAD);
        vlib_prefetch_buffer_header (p5, LOAD);
        vlib_prefetch_buffer_header (p6, LOAD);
        vlib_prefetch_buffer_header (p7, LOAD);

        CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
        CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);
        CLIB_PREFETCH (p6->data, CLIB_CACHE_LINE_BYTES, STORE);
        CLIB_PREFETCH (p7->data, CLIB_CACHE_LINE_BYTES, STORE);
      }

      to_next[0] = bi0 = from[0];
      to_next[1] = bi1 = from[1];
      to_next[2] = bi2 = from[2];
      to_next[3] = bi3 = from[3];
      from += 4;
      to_next += 4;
      n_left_from -= 4;
      n_left_to_next -= 4;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);
      b2 = vlib_get_buffer (vm, bi2);
      b3 = vlib_get_buffer (vm, bi3);

      sl0 = pool_elt_at_index (sm->sid_lists, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);
      sl1 = pool_elt_at_index (sm->sid_lists, vnet_buffer(b1)->ip.adj_index[VLIB_TX]);
      sl2 = pool_elt_at_index (sm->sid_lists, vnet_buffer(b2)->ip.adj_index[VLIB_TX]);
      sl3 = pool_elt_at_index (sm->sid_lists, vnet_buffer(b3)->ip.adj_index[VLIB_TX]);

      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >= (vec_len(sl0->rewrite) + b0->current_data));
      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >= (vec_len(sl1->rewrite) + b1->current_data));
      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >= (vec_len(sl2->rewrite) + b2->current_data));
      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >= (vec_len(sl3->rewrite) + b3->current_data));

      ip0 = vlib_buffer_get_current (b0);
      ip1 = vlib_buffer_get_current (b1);
      ip2 = vlib_buffer_get_current (b2);
      ip3 = vlib_buffer_get_current (b3);

      clib_memcpy (((u8 *)ip0) - vec_len(sl0->rewrite), sl0->rewrite, vec_len(sl0->rewrite));
      clib_memcpy (((u8 *)ip1) - vec_len(sl1->rewrite), sl1->rewrite, vec_len(sl1->rewrite));
      clib_memcpy (((u8 *)ip2) - vec_len(sl2->rewrite), sl2->rewrite, vec_len(sl2->rewrite));
      clib_memcpy (((u8 *)ip3) - vec_len(sl3->rewrite), sl3->rewrite, vec_len(sl3->rewrite));

      vlib_buffer_advance(b0, - (word) vec_len(sl0->rewrite));
      vlib_buffer_advance(b1, - (word) vec_len(sl1->rewrite));
      vlib_buffer_advance(b2, - (word) vec_len(sl2->rewrite));
      vlib_buffer_advance(b3, - (word) vec_len(sl3->rewrite));

      ip0_encap = ip0;
      ip1_encap = ip1;
      ip2_encap = ip2;
      ip3_encap = ip3;

      ip0 = vlib_buffer_get_current (b0);
      ip1 = vlib_buffer_get_current (b1);
      ip2 = vlib_buffer_get_current (b2);
      ip3 = vlib_buffer_get_current (b3);

      ip0_encap->hop_limit -= 1;
      ip1_encap->hop_limit -= 1;
      ip2_encap->hop_limit -= 1;
      ip3_encap->hop_limit -= 1;

      new_l0 = ip0->payload_length + sizeof(ip6_header_t) + clib_net_to_host_u16(ip0_encap->payload_length);
      new_l1 = ip1->payload_length + sizeof(ip6_header_t) + clib_net_to_host_u16(ip1_encap->payload_length);
      new_l2 = ip2->payload_length + sizeof(ip6_header_t) + clib_net_to_host_u16(ip2_encap->payload_length);
      new_l3 = ip3->payload_length + sizeof(ip6_header_t) + clib_net_to_host_u16(ip3_encap->payload_length);

      ip0->payload_length = clib_host_to_net_u16(new_l0);
      ip1->payload_length = clib_host_to_net_u16(new_l1);
      ip2->payload_length = clib_host_to_net_u16(new_l2);
      ip3->payload_length = clib_host_to_net_u16(new_l3);

      ip0->ip_version_traffic_class_and_flow_label = ip0_encap->ip_version_traffic_class_and_flow_label;
      ip1->ip_version_traffic_class_and_flow_label = ip1_encap->ip_version_traffic_class_and_flow_label;
      ip2->ip_version_traffic_class_and_flow_label = ip2_encap->ip_version_traffic_class_and_flow_label;
      ip3->ip_version_traffic_class_and_flow_label = ip3_encap->ip_version_traffic_class_and_flow_label;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
      {  
        if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
        {
          sr_policy_rewrite_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
          clib_memcpy (tr->src.as_u8, ip0->src_address.as_u8, sizeof (tr->src.as_u8));
          clib_memcpy (tr->dst.as_u8, ip0->dst_address.as_u8, sizeof (tr->dst.as_u8));
        }

        if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
        {
          sr_policy_rewrite_trace_t *tr = vlib_add_trace (vm, node, b1, sizeof (*tr));
          clib_memcpy (tr->src.as_u8, ip1->src_address.as_u8, sizeof (tr->src.as_u8));
          clib_memcpy (tr->dst.as_u8, ip1->dst_address.as_u8, sizeof (tr->dst.as_u8));
        }

        if (PREDICT_FALSE(b2->flags & VLIB_BUFFER_IS_TRACED))
        {
          sr_policy_rewrite_trace_t *tr = vlib_add_trace (vm, node, b2, sizeof (*tr));
          clib_memcpy (tr->src.as_u8, ip2->src_address.as_u8, sizeof (tr->src.as_u8));
          clib_memcpy (tr->dst.as_u8, ip2->dst_address.as_u8, sizeof (tr->dst.as_u8));
        }

        if (PREDICT_FALSE(b3->flags & VLIB_BUFFER_IS_TRACED))
        {
          sr_policy_rewrite_trace_t *tr = vlib_add_trace (vm, node, b3, sizeof (*tr));
          clib_memcpy (tr->src.as_u8, ip3->src_address.as_u8, sizeof (tr->src.as_u8));
          clib_memcpy (tr->dst.as_u8, ip3->dst_address.as_u8, sizeof (tr->dst.as_u8));
        }
      }
      
      encap_pkts += 4;
      vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next, n_left_to_next, 
        bi0, bi1, bi2, bi3, next0, next1, next2, next3);
    }
    
    /* Single loop for potentially the last three packets */
    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      ip6_header_t * ip0 = 0, *ip0_encap = 0;
      ip6_sr_sl_t *sl0;
      u32 next0 = SR_POLICY_REWRITE_NEXT_IP6_LOOKUP;
      u16 new_l0 = 0;
      
      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;
      b0 = vlib_get_buffer (vm, bi0);
      
      sl0 = pool_elt_at_index (sm->sid_lists, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);

      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >= (vec_len(sl0->rewrite) + b0->current_data));

      ip0 = vlib_buffer_get_current (b0);

      clib_memcpy (((u8 *)ip0) - vec_len(sl0->rewrite), sl0->rewrite, vec_len(sl0->rewrite));
      vlib_buffer_advance(b0, - (word) vec_len(sl0->rewrite));

      ip0_encap = ip0;
      ip0 = vlib_buffer_get_current (b0);

      ip0_encap->hop_limit -= 1;
      new_l0 = ip0->payload_length + sizeof(ip6_header_t) + clib_net_to_host_u16(ip0_encap->payload_length);
      ip0->payload_length = clib_host_to_net_u16(new_l0);
      ip0->ip_version_traffic_class_and_flow_label = ip0_encap->ip_version_traffic_class_and_flow_label;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
          PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED) )
      {
        sr_policy_rewrite_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
        clib_memcpy (tr->src.as_u8, ip0->src_address.as_u8, sizeof (tr->src.as_u8));
        clib_memcpy (tr->dst.as_u8, ip0->dst_address.as_u8, sizeof (tr->dst.as_u8));
      }

      encap_pkts ++;
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, 
        n_left_to_next, bi0, next0);
    }

    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  /* Update counters */
  vlib_node_increment_counter (vm, sr_policy_rewrite_encaps_node.index, 
    SR_POLICY_REWRITE_ERROR_COUNTER_TOTAL, encap_pkts);
  vlib_node_increment_counter (vm, sr_policy_rewrite_encaps_node.index, 
    SR_POLICY_REWRITE_ERROR_COUNTER_BSID, bsid_pkts);

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (sr_policy_rewrite_encaps_node) = {
  .function = sr_policy_rewrite_encaps,
  .name = "sr-policy-rewrite-encaps",
  .vector_size = sizeof (u32),
  .format_trace = format_sr_policy_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SR_POLICY_REWRITE_N_ERROR,
  .error_strings = sr_policy_rewrite_error_strings,
  .n_next_nodes = SR_POLICY_REWRITE_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_POLICY_REWRITE_NEXT_##s] = n,
    foreach_sr_policy_rewrite_next
#undef _
  },
};

/**
 * @brief Graph node for applying a SR policy into a packet. SRH insertion.
 */
static uword
sr_policy_rewrite_insert (vlib_main_t * vm, vlib_node_runtime_t * node, 
  vlib_frame_t * from_frame)
{
  ip6_sr_main_t * sm = &sr_main;
  u32 n_left_from, next_index, * from, * to_next;
  
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  
  next_index = node->cached_next_index;

  int insert_pkts=0, bsid_pkts=0;
  
  while (n_left_from > 0)
  {
    u32 n_left_to_next;
    
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    /* Quad - Loop */
    while (n_left_from >= 8 && n_left_to_next >= 4)
    {
      u32 bi0, bi1, bi2, bi3;
      vlib_buffer_t *b0, *b1, *b2, *b3;
      u32 next0, next1, next2, next3;
      next0 = next1 = next2 = next3 = SR_POLICY_REWRITE_NEXT_IP6_LOOKUP;
      ip6_header_t * ip0, *ip1, *ip2, *ip3;
      ip6_sr_header_t *sr0, *sr1, *sr2, *sr3;
      ip6_sr_sl_t *sl0, *sl1, *sl2, *sl3;
      u16 new_l0, new_l1, new_l2, new_l3;

      /* Prefetch next iteration. */
      {
        vlib_buffer_t *p4, *p5, *p6, *p7;

        p4 = vlib_get_buffer (vm, from[4]);
        p5 = vlib_get_buffer (vm, from[5]);
        p6 = vlib_get_buffer (vm, from[6]);
        p7 = vlib_get_buffer (vm, from[7]);

        /* Prefetch the buffer header and packet for the N+2 loop iteration */
        vlib_prefetch_buffer_header (p4, LOAD);
        vlib_prefetch_buffer_header (p5, LOAD);
        vlib_prefetch_buffer_header (p6, LOAD);
        vlib_prefetch_buffer_header (p7, LOAD);

        CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
        CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);
        CLIB_PREFETCH (p6->data, CLIB_CACHE_LINE_BYTES, STORE);
        CLIB_PREFETCH (p7->data, CLIB_CACHE_LINE_BYTES, STORE);
      }

      to_next[0] = bi0 = from[0];
      to_next[1] = bi1 = from[1];
      to_next[2] = bi2 = from[2];
      to_next[3] = bi3 = from[3];
      from += 4;
      to_next += 4;
      n_left_from -= 4;
      n_left_to_next -= 4;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);
      b2 = vlib_get_buffer (vm, bi2);
      b3 = vlib_get_buffer (vm, bi3);

      sl0 = pool_elt_at_index (sm->sid_lists, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);
      sl1 = pool_elt_at_index (sm->sid_lists, vnet_buffer(b1)->ip.adj_index[VLIB_TX]);
      sl2 = pool_elt_at_index (sm->sid_lists, vnet_buffer(b2)->ip.adj_index[VLIB_TX]);
      sl3 = pool_elt_at_index (sm->sid_lists, vnet_buffer(b3)->ip.adj_index[VLIB_TX]);

      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >= (vec_len(sl0->rewrite) + b0->current_data));
      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >= (vec_len(sl1->rewrite) + b1->current_data));
      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >= (vec_len(sl2->rewrite) + b2->current_data));
      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >= (vec_len(sl3->rewrite) + b3->current_data));

      vlib_buffer_advance(b0, - (word) vec_len(sl0->rewrite));
      vlib_buffer_advance(b1, - (word) vec_len(sl1->rewrite));
      vlib_buffer_advance(b2, - (word) vec_len(sl2->rewrite));
      vlib_buffer_advance(b3, - (word) vec_len(sl3->rewrite));

      ip0 = vlib_buffer_get_current (b0);
      ip1 = vlib_buffer_get_current (b1);
      ip2 = vlib_buffer_get_current (b2);
      ip3 = vlib_buffer_get_current (b3);

      sr0 = (ip6_sr_header_t *)(ip0+1);
      sr1 = (ip6_sr_header_t *)(ip1+1);
      sr2 = (ip6_sr_header_t *)(ip2+1);
      sr3 = (ip6_sr_header_t *)(ip3+1);

      clib_memcpy ((u8 *)ip0, (u8 *)ip0 + vec_len(sl0->rewrite), sizeof(ip6_header_t));
      clib_memcpy ((u8 *)ip1, (u8 *)ip1 + vec_len(sl1->rewrite), sizeof(ip6_header_t));
      clib_memcpy ((u8 *)ip2, (u8 *)ip2 + vec_len(sl2->rewrite), sizeof(ip6_header_t));
      clib_memcpy ((u8 *)ip3, (u8 *)ip3 + vec_len(sl3->rewrite), sizeof(ip6_header_t));

      clib_memcpy (((u8 *)sr0), sl0->rewrite, vec_len(sl0->rewrite));
      clib_memcpy (((u8 *)sr1), sl1->rewrite, vec_len(sl1->rewrite));
      clib_memcpy (((u8 *)sr2), sl2->rewrite, vec_len(sl2->rewrite));
      clib_memcpy (((u8 *)sr3), sl3->rewrite, vec_len(sl3->rewrite));

      ip0->hop_limit -= 1;
      ip1->hop_limit -= 1;
      ip2->hop_limit -= 1;
      ip3->hop_limit -= 1;

      new_l0 =  clib_net_to_host_u16 (ip0->payload_length) + vec_len(sl0->rewrite);
      new_l1 =  clib_net_to_host_u16 (ip1->payload_length) + vec_len(sl1->rewrite);
      new_l2 =  clib_net_to_host_u16 (ip2->payload_length) + vec_len(sl2->rewrite);
      new_l3 =  clib_net_to_host_u16 (ip3->payload_length) + vec_len(sl3->rewrite);

      ip0->payload_length = clib_host_to_net_u16(new_l0);
      ip1->payload_length = clib_host_to_net_u16(new_l1);
      ip2->payload_length = clib_host_to_net_u16(new_l2);
      ip3->payload_length = clib_host_to_net_u16(new_l3);

      sr0->segments->as_u64[0] = ip0->dst_address.as_u64[0];
      sr0->segments->as_u64[1] = ip0->dst_address.as_u64[1];
      sr1->segments->as_u64[0] = ip1->dst_address.as_u64[0];
      sr1->segments->as_u64[1] = ip1->dst_address.as_u64[1];
      sr2->segments->as_u64[0] = ip2->dst_address.as_u64[0];
      sr2->segments->as_u64[1] = ip2->dst_address.as_u64[1];
      sr3->segments->as_u64[0] = ip3->dst_address.as_u64[0];
      sr3->segments->as_u64[1] = ip3->dst_address.as_u64[1];

      ip0->dst_address.as_u64[0] = (sr0->segments + sr0->segments_left)->as_u64[0];
      ip0->dst_address.as_u64[1] = (sr0->segments + sr0->segments_left)->as_u64[1];
      ip1->dst_address.as_u64[0] = (sr1->segments + sr1->segments_left)->as_u64[0];
      ip1->dst_address.as_u64[1] = (sr1->segments + sr1->segments_left)->as_u64[1];
      ip2->dst_address.as_u64[0] = (sr2->segments + sr2->segments_left)->as_u64[0];
      ip2->dst_address.as_u64[1] = (sr2->segments + sr2->segments_left)->as_u64[1];
      ip3->dst_address.as_u64[0] = (sr3->segments + sr3->segments_left)->as_u64[0];
      ip3->dst_address.as_u64[1] = (sr3->segments + sr3->segments_left)->as_u64[1];
      
      insert_pkts += 4;
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
      {  
        if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
        {
          sr_policy_rewrite_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
          clib_memcpy (tr->src.as_u8, ip0->src_address.as_u8, sizeof (tr->src.as_u8));
          clib_memcpy (tr->dst.as_u8, ip0->dst_address.as_u8, sizeof (tr->dst.as_u8));
        }

        if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
        {
          sr_policy_rewrite_trace_t *tr = vlib_add_trace (vm, node, b1, sizeof (*tr));
          clib_memcpy (tr->src.as_u8, ip1->src_address.as_u8, sizeof (tr->src.as_u8));
          clib_memcpy (tr->dst.as_u8, ip1->dst_address.as_u8, sizeof (tr->dst.as_u8));
        }

        if (PREDICT_FALSE(b2->flags & VLIB_BUFFER_IS_TRACED))
        {
          sr_policy_rewrite_trace_t *tr = vlib_add_trace (vm, node, b2, sizeof (*tr));
          clib_memcpy (tr->src.as_u8, ip2->src_address.as_u8, sizeof (tr->src.as_u8));
          clib_memcpy (tr->dst.as_u8, ip2->dst_address.as_u8, sizeof (tr->dst.as_u8));
        }

        if (PREDICT_FALSE(b3->flags & VLIB_BUFFER_IS_TRACED))
        {
          sr_policy_rewrite_trace_t *tr = vlib_add_trace (vm, node, b3, sizeof (*tr));
          clib_memcpy (tr->src.as_u8, ip3->src_address.as_u8, sizeof (tr->src.as_u8));
          clib_memcpy (tr->dst.as_u8, ip3->dst_address.as_u8, sizeof (tr->dst.as_u8));
        }
      }

      vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next, n_left_to_next, 
        bi0, bi1, bi2, bi3, next0, next1, next2, next3);
    }

    /* Single loop for potentially the last three packets */
    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      ip6_header_t * ip0 = 0;
      ip6_sr_header_t *sr0= 0;
      ip6_sr_sl_t *sl0;
      u32 next0 = SR_POLICY_REWRITE_NEXT_IP6_LOOKUP;
      u16 new_l0 = 0;
      
      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;
      b0 = vlib_get_buffer (vm, bi0);
      
      sl0 = pool_elt_at_index (sm->sid_lists, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);

      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >= (vec_len(sl0->rewrite) + b0->current_data));


      vlib_buffer_advance(b0, - (word) vec_len(sl0->rewrite));
      ip0 = vlib_buffer_get_current (b0);
      sr0 = (ip6_sr_header_t *)(ip0+1);

      /* Move IP header */
      clib_memcpy ((u8 *)ip0, (u8 *)ip0 + vec_len(sl0->rewrite), sizeof(ip6_header_t));

      /*Punch in SR header */
      clib_memcpy (((u8 *)sr0), sl0->rewrite, vec_len(sl0->rewrite));

      ip0->hop_limit -= 1;
      new_l0 =  clib_net_to_host_u16 (ip0->payload_length) + vec_len(sl0->rewrite);
      ip0->payload_length = clib_host_to_net_u16(new_l0);

      /* Update last segment */
      sr0->segments->as_u64[0] = ip0->dst_address.as_u64[0];
      sr0->segments->as_u64[1] = ip0->dst_address.as_u64[1];

      /* Update IPv6 DA */
      ip0->dst_address.as_u64[0] = (sr0->segments + sr0->segments_left)->as_u64[0];
      ip0->dst_address.as_u64[1] = (sr0->segments + sr0->segments_left)->as_u64[1];

      if ( PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE) &&
           PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
      {
        sr_policy_rewrite_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
        clib_memcpy (tr->src.as_u8, ip0->src_address.as_u8, sizeof (tr->src.as_u8));
        clib_memcpy (tr->dst.as_u8, ip0->dst_address.as_u8, sizeof (tr->dst.as_u8));
      }

      insert_pkts ++;

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, 
        n_left_to_next, bi0, next0);
    }

    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  /* Update counters */
  vlib_node_increment_counter (vm, sr_policy_rewrite_insert_node.index, 
    SR_POLICY_REWRITE_ERROR_COUNTER_TOTAL, insert_pkts);
  vlib_node_increment_counter (vm, sr_policy_rewrite_insert_node.index, 
    SR_POLICY_REWRITE_ERROR_COUNTER_BSID, bsid_pkts);
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (sr_policy_rewrite_insert_node) = {
  .function = sr_policy_rewrite_insert,
  .name = "sr-policy-rewrite-insert",
  .vector_size = sizeof (u32),
  .format_trace = format_sr_policy_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SR_POLICY_REWRITE_N_ERROR,
  .error_strings = sr_policy_rewrite_error_strings,
  .n_next_nodes = SR_POLICY_REWRITE_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_POLICY_REWRITE_NEXT_##s] = n,
    foreach_sr_policy_rewrite_next
#undef _
  },
};

/*************************** SR Segment Lists DPOs ****************************/
static u8 *
format_sr_segment_list_dpo (u8 * s, va_list * args)
{
  ip6_sr_main_t * sm = &sr_main;
  ip6_address_t *addr;
  ip6_sr_sl_t *sl;

  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);
  s = format (s, "SR: Segment List index:[%d]", index);
  s = format (s, "\n\tSegments:");

  sl = pool_elt_at_index (sm->sid_lists, index);

  s = format (s, "{");
  vec_foreach(addr, sl->segments)
  {
    s = format (s, "%U, ", format_ip6_address, addr);
  }
  s = format (s, "\b\b} - ");
  s = format (s, "Weight: %u", sl->weight);

  return s;
}

const static dpo_vft_t sr_policy_rewrite_vft = {
  .dv_lock = sr_dpo_lock,
  .dv_unlock = sr_dpo_unlock,
  .dv_format = format_sr_segment_list_dpo,
};

const static char *const sr_pr_encaps_ip6_nodes[] = {
  "sr-policy-rewrite-encaps",
  NULL,
};

const static char *const *const sr_pr_encaps_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = sr_pr_encaps_ip6_nodes,
};

const static char *const sr_pr_insert_ip6_nodes[] = {
  "sr-policy-rewrite-insert",
  NULL,
};

const static char *const *const sr_pr_insert_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = sr_pr_insert_ip6_nodes,
};

/********************* SR Policy Rewrite initialization ***********************/
/**
 * @brief SR Policy Rewrite initialization
 */
clib_error_t *sr_policy_rewrite_init (vlib_main_t *vm)
{
  ip6_sr_main_t * sm = &sr_main;

  /* Init memory for sr policy keys (bsid <-> ip6_address_t) */
  sm->sr_policy_index_by_key = hash_create_mem (0, sizeof(ip6_address_t), 
    sizeof(uword));

  /* Init SR VPO DPOs type */
  sr_pr_encaps_dpo_type = 
    dpo_register_new_type (&sr_policy_rewrite_vft, sr_pr_encaps_nodes);

  sr_pr_insert_dpo_type = 
    dpo_register_new_type (&sr_policy_rewrite_vft, sr_pr_insert_nodes);

  /* Register the L2 encaps node used in HW redirect */
  sm->l2_sr_policy_rewrite_index = sr_policy_rewrite_encaps_node.index;

  return 0;
}

VLIB_INIT_FUNCTION(sr_policy_rewrite_init);


/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
