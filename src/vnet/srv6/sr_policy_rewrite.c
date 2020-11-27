/*
 * sr_policy_rewrite.c: ipv6 sr policy creation
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
#include <vnet/srv6/sr.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>
#include <vnet/srv6/sr_packet.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/replicate_dpo.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

/**
 * @brief SR policy rewrite trace
 */
typedef struct
{
  ip6_address_t src, dst;
} sr_policy_rewrite_trace_t;

/* Graph arcs */
#define foreach_sr_policy_rewrite_next     \
_(IP6_LOOKUP, "ip6-lookup")         \
_(ERROR, "error-drop")

typedef enum
{
#define _(s,n) SR_POLICY_REWRITE_NEXT_##s,
  foreach_sr_policy_rewrite_next
#undef _
    SR_POLICY_REWRITE_N_NEXT,
} sr_policy_rewrite_next_t;

/* SR rewrite errors */
#define foreach_sr_policy_rewrite_error                     \
_(INTERNAL_ERROR, "Segment Routing undefined error")        \
_(BSID_ZERO, "BSID with SL = 0")                            \
_(COUNTER_TOTAL, "SR steered IPv6 packets")                 \
_(COUNTER_ENCAP, "SR: Encaps packets")                      \
_(COUNTER_INSERT, "SR: SRH inserted packets")               \
_(COUNTER_BSID, "SR: BindingSID steered packets")

typedef enum
{
#define _(sym,str) SR_POLICY_REWRITE_ERROR_##sym,
  foreach_sr_policy_rewrite_error
#undef _
    SR_POLICY_REWRITE_N_ERROR,
} sr_policy_rewrite_error_t;

static char *sr_policy_rewrite_error_strings[] = {
#define _(sym,string) string,
  foreach_sr_policy_rewrite_error
#undef _
};

/**
 * @brief Dynamically added SR SL DPO type
 */
static dpo_type_t sr_pr_encaps_dpo_type;
static dpo_type_t sr_pr_insert_dpo_type;
static dpo_type_t sr_pr_bsid_encaps_dpo_type;
static dpo_type_t sr_pr_bsid_insert_dpo_type;

/**
 * @brief IPv6 SA for encapsulated packets
 */
static ip6_address_t sr_pr_encaps_src;
static u8 sr_pr_encaps_hop_limit = IPv6_DEFAULT_HOP_LIMIT;

/******************* SR rewrite set encaps IPv6 source addr *******************/
/* Note:  This is temporal. We don't know whether to follow this path or
          take the ip address of a loopback interface or even the OIF         */

void
sr_set_source (ip6_address_t * address)
{
  clib_memcpy_fast (&sr_pr_encaps_src, address, sizeof (sr_pr_encaps_src));
}

ip6_address_t *
sr_get_encaps_source ()
{
  return &sr_pr_encaps_src;
}

static clib_error_t *
set_sr_src_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "addr %U", unformat_ip6_address, &sr_pr_encaps_src))
	return 0;
      else
	return clib_error_return (0, "No address specified");
    }
  return clib_error_return (0, "No address specified");
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_sr_src_command, static) = {
  .path = "set sr encaps source",
  .short_help = "set sr encaps source addr <ip6_addr>",
  .function = set_sr_src_command_fn,
};
/* *INDENT-ON* */

/******************** SR rewrite set encaps IPv6 hop-limit ********************/

void
sr_set_hop_limit (u8 hop_limit)
{
  sr_pr_encaps_hop_limit = hop_limit;
}

u8
sr_get_hop_limit (void)
{
  return sr_pr_encaps_hop_limit;
}

static clib_error_t *
set_sr_hop_limit_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  int hop_limit = sr_get_hop_limit ();

  if (unformat_check_input (input) == UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "No value specified");
  if (!unformat (input, "%d", &hop_limit))
    return clib_error_return (0, "Invalid value");
  if (hop_limit <= 0 || hop_limit > 255)
    return clib_error_return (0, "Value out of range [1-255]");
  sr_pr_encaps_hop_limit = (u8) hop_limit;
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_sr_hop_limit_command, static) = {
  .path = "set sr encaps hop-limit",
  .short_help = "set sr encaps hop-limit <value>",
  .function = set_sr_hop_limit_command_fn,
};
/* *INDENT-ON* */

/*********************** SR rewrite string computation ************************/
/**
 * @brief SR rewrite string computation for IPv6 encapsulation (inline)
 *
 * @param sl is a vector of IPv6 addresses composing the Segment List
 *
 * @return precomputed rewrite string for encapsulation
 */
static inline u8 *
compute_rewrite_encaps (ip6_address_t * sl)
{
  ip6_header_t *iph;
  ip6_sr_header_t *srh;
  ip6_address_t *addrp, *this_address;
  u32 header_length = 0;
  u8 *rs = NULL;

  header_length = 0;
  header_length += IPv6_DEFAULT_HEADER_LENGTH;
  if (vec_len (sl) > 1)
    {
      header_length += sizeof (ip6_sr_header_t);
      header_length += vec_len (sl) * sizeof (ip6_address_t);
    }

  vec_validate (rs, header_length - 1);

  iph = (ip6_header_t *) rs;
  iph->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0 | ((6 & 0xF) << 28));
  iph->src_address.as_u64[0] = sr_pr_encaps_src.as_u64[0];
  iph->src_address.as_u64[1] = sr_pr_encaps_src.as_u64[1];
  iph->payload_length = header_length - IPv6_DEFAULT_HEADER_LENGTH;
  iph->protocol = IP_PROTOCOL_IPV6;
  iph->hop_limit = sr_pr_encaps_hop_limit;

  if (vec_len (sl) > 1)
    {
      srh = (ip6_sr_header_t *) (iph + 1);
      iph->protocol = IP_PROTOCOL_IPV6_ROUTE;
      srh->protocol = IP_PROTOCOL_IPV6;
      srh->type = ROUTING_HEADER_TYPE_SR;
      srh->segments_left = vec_len (sl) - 1;
      srh->last_entry = vec_len (sl) - 1;
      srh->length = ((sizeof (ip6_sr_header_t) +
		      (vec_len (sl) * sizeof (ip6_address_t))) / 8) - 1;
      srh->flags = 0x00;
      srh->tag = 0x0000;
      addrp = srh->segments + vec_len (sl) - 1;
      vec_foreach (this_address, sl)
      {
	clib_memcpy_fast (addrp->as_u8, this_address->as_u8,
			  sizeof (ip6_address_t));
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
compute_rewrite_insert (ip6_address_t * sl)
{
  ip6_sr_header_t *srh;
  ip6_address_t *addrp, *this_address;
  u32 header_length = 0;
  u8 *rs = NULL;

  header_length = 0;
  header_length += sizeof (ip6_sr_header_t);
  header_length += (vec_len (sl) + 1) * sizeof (ip6_address_t);

  vec_validate (rs, header_length - 1);

  srh = (ip6_sr_header_t *) rs;
  srh->type = ROUTING_HEADER_TYPE_SR;
  srh->segments_left = vec_len (sl);
  srh->last_entry = vec_len (sl);
  srh->length = ((sizeof (ip6_sr_header_t) +
		  ((vec_len (sl) + 1) * sizeof (ip6_address_t))) / 8) - 1;
  srh->flags = 0x00;
  srh->tag = 0x0000;
  addrp = srh->segments + vec_len (sl);
  vec_foreach (this_address, sl)
  {
    clib_memcpy_fast (addrp->as_u8, this_address->as_u8,
		      sizeof (ip6_address_t));
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
compute_rewrite_bsid (ip6_address_t * sl)
{
  ip6_sr_header_t *srh;
  ip6_address_t *addrp, *this_address;
  u32 header_length = 0;
  u8 *rs = NULL;

  header_length = 0;
  header_length += sizeof (ip6_sr_header_t);
  header_length += vec_len (sl) * sizeof (ip6_address_t);

  vec_validate (rs, header_length - 1);

  srh = (ip6_sr_header_t *) rs;
  srh->type = ROUTING_HEADER_TYPE_SR;
  srh->segments_left = vec_len (sl) - 1;
  srh->last_entry = vec_len (sl) - 1;
  srh->length = ((sizeof (ip6_sr_header_t) +
		  (vec_len (sl) * sizeof (ip6_address_t))) / 8) - 1;
  srh->flags = 0x00;
  srh->tag = 0x0000;
  addrp = srh->segments + vec_len (sl) - 1;
  vec_foreach (this_address, sl)
  {
    clib_memcpy_fast (addrp->as_u8, this_address->as_u8,
		      sizeof (ip6_address_t));
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
create_sl (ip6_sr_policy_t * sr_policy, ip6_address_t * sl, u32 weight,
	   u8 is_encap)
{
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_sl_t *segment_list;
  sr_policy_fn_registration_t *plugin = 0;

  pool_get (sm->sid_lists, segment_list);
  clib_memset (segment_list, 0, sizeof (*segment_list));

  vec_add1 (sr_policy->segments_lists, segment_list - sm->sid_lists);

  /* Fill in segment list */
  segment_list->weight =
    (weight != (u32) ~ 0 ? weight : SR_SEGMENT_LIST_WEIGHT_DEFAULT);

  segment_list->segments = vec_dup (sl);

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

  if (sr_policy->plugin)
    {
      plugin =
	pool_elt_at_index (sm->policy_plugin_functions,
			   sr_policy->plugin - SR_BEHAVIOR_LAST);

      segment_list->plugin = sr_policy->plugin;
      segment_list->plugin_mem = sr_policy->plugin_mem;

      plugin->creation (sr_policy);
    }

  /* Create DPO */
  dpo_reset (&segment_list->bsid_dpo);
  dpo_reset (&segment_list->ip6_dpo);
  dpo_reset (&segment_list->ip4_dpo);

  if (is_encap)
    {
      if (!sr_policy->plugin)
	{
	  dpo_set (&segment_list->ip6_dpo, sr_pr_encaps_dpo_type,
		   DPO_PROTO_IP6, segment_list - sm->sid_lists);
	  dpo_set (&segment_list->ip4_dpo, sr_pr_encaps_dpo_type,
		   DPO_PROTO_IP4, segment_list - sm->sid_lists);
	  dpo_set (&segment_list->bsid_dpo, sr_pr_bsid_encaps_dpo_type,
		   DPO_PROTO_IP6, segment_list - sm->sid_lists);
	}
      else
	{
	  dpo_set (&segment_list->ip6_dpo, plugin->dpo, DPO_PROTO_IP6,
		   segment_list - sm->sid_lists);
	  dpo_set (&segment_list->ip4_dpo, plugin->dpo, DPO_PROTO_IP4,
		   segment_list - sm->sid_lists);
	  dpo_set (&segment_list->bsid_dpo, plugin->dpo, DPO_PROTO_IP6,
		   segment_list - sm->sid_lists);
	}
    }
  else
    {
      if (!sr_policy->plugin)
	{
	  dpo_set (&segment_list->ip6_dpo, sr_pr_insert_dpo_type,
		   DPO_PROTO_IP6, segment_list - sm->sid_lists);
	  dpo_set (&segment_list->bsid_dpo, sr_pr_bsid_insert_dpo_type,
		   DPO_PROTO_IP6, segment_list - sm->sid_lists);
	}
      else
	{
	  dpo_set (&segment_list->ip6_dpo, plugin->dpo, DPO_PROTO_IP6,
		   segment_list - sm->sid_lists);
	  dpo_set (&segment_list->bsid_dpo, plugin->dpo, DPO_PROTO_IP6,
		   segment_list - sm->sid_lists);
	}
    }

  return segment_list;
}

/**
 * @brief Updates the Load Balancer after an SR Policy change
 *
 * @param sr_policy is the modified SR Policy
 */
static inline void
update_lb (ip6_sr_policy_t * sr_policy)
{
  flow_hash_config_t fhc;
  u32 *sl_index;
  ip6_sr_sl_t *segment_list;
  ip6_sr_main_t *sm = &sr_main;
  load_balance_path_t path;
  path.path_index = FIB_NODE_INDEX_INVALID;
  load_balance_path_t *ip4_path_vector = 0;
  load_balance_path_t *ip6_path_vector = 0;
  load_balance_path_t *b_path_vector = 0;

  /* In case LB does not exist, create it */
  if (!dpo_id_is_valid (&sr_policy->bsid_dpo))
    {
      fib_prefix_t pfx = {
	.fp_proto = FIB_PROTOCOL_IP6,
	.fp_len = 128,
	.fp_addr = {
		    .ip6 = sr_policy->bsid,
		    }
      };

      /* Add FIB entry for BSID */
      fhc = fib_table_get_flow_hash_config (sr_policy->fib_table,
					    FIB_PROTOCOL_IP6);

      dpo_set (&sr_policy->bsid_dpo, DPO_LOAD_BALANCE, DPO_PROTO_IP6,
	       load_balance_create (0, DPO_PROTO_IP6, fhc));

      dpo_set (&sr_policy->ip6_dpo, DPO_LOAD_BALANCE, DPO_PROTO_IP6,
	       load_balance_create (0, DPO_PROTO_IP6, fhc));

      /* Update FIB entry's to point to the LB DPO in the main FIB and hidden one */
      fib_table_entry_special_dpo_update (fib_table_find (FIB_PROTOCOL_IP6,
							  sr_policy->fib_table),
					  &pfx, FIB_SOURCE_SR,
					  FIB_ENTRY_FLAG_EXCLUSIVE,
					  &sr_policy->bsid_dpo);

      fib_table_entry_special_dpo_update (sm->fib_table_ip6,
					  &pfx,
					  FIB_SOURCE_SR,
					  FIB_ENTRY_FLAG_EXCLUSIVE,
					  &sr_policy->ip6_dpo);

      if (sr_policy->is_encap)
	{
	  dpo_set (&sr_policy->ip4_dpo, DPO_LOAD_BALANCE, DPO_PROTO_IP4,
		   load_balance_create (0, DPO_PROTO_IP4, fhc));

	  fib_table_entry_special_dpo_update (sm->fib_table_ip4,
					      &pfx,
					      FIB_SOURCE_SR,
					      FIB_ENTRY_FLAG_EXCLUSIVE,
					      &sr_policy->ip4_dpo);
	}

    }

  /* Create the LB path vector */
  vec_foreach (sl_index, sr_policy->segments_lists)
  {
    segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);
    path.path_dpo = segment_list->bsid_dpo;
    path.path_weight = segment_list->weight;
    vec_add1 (b_path_vector, path);
    path.path_dpo = segment_list->ip6_dpo;
    vec_add1 (ip6_path_vector, path);
    if (sr_policy->is_encap)
      {
	path.path_dpo = segment_list->ip4_dpo;
	vec_add1 (ip4_path_vector, path);
      }
  }

  /* Update LB multipath */
  load_balance_multipath_update (&sr_policy->bsid_dpo, b_path_vector,
				 LOAD_BALANCE_FLAG_NONE);
  load_balance_multipath_update (&sr_policy->ip6_dpo, ip6_path_vector,
				 LOAD_BALANCE_FLAG_NONE);
  if (sr_policy->is_encap)
    load_balance_multipath_update (&sr_policy->ip4_dpo, ip4_path_vector,
				   LOAD_BALANCE_FLAG_NONE);

  /* Cleanup */
  vec_free (b_path_vector);
  vec_free (ip6_path_vector);
  vec_free (ip4_path_vector);
}

/**
 * @brief Updates the Replicate DPO after an SR Policy change
 *
 * @param sr_policy is the modified SR Policy (type spray)
 */
static inline void
update_replicate (ip6_sr_policy_t * sr_policy)
{
  u32 *sl_index;
  ip6_sr_sl_t *segment_list;
  ip6_sr_main_t *sm = &sr_main;
  load_balance_path_t path;
  path.path_index = FIB_NODE_INDEX_INVALID;
  load_balance_path_t *b_path_vector = 0;
  load_balance_path_t *ip6_path_vector = 0;
  load_balance_path_t *ip4_path_vector = 0;

  /* In case LB does not exist, create it */
  if (!dpo_id_is_valid (&sr_policy->bsid_dpo))
    {
      dpo_set (&sr_policy->bsid_dpo, DPO_REPLICATE,
	       DPO_PROTO_IP6, replicate_create (0, DPO_PROTO_IP6));

      dpo_set (&sr_policy->ip6_dpo, DPO_REPLICATE,
	       DPO_PROTO_IP6, replicate_create (0, DPO_PROTO_IP6));

      /* Update FIB entry's DPO to point to SR without LB */
      fib_prefix_t pfx = {
	.fp_proto = FIB_PROTOCOL_IP6,
	.fp_len = 128,
	.fp_addr = {
		    .ip6 = sr_policy->bsid,
		    }
      };
      fib_table_entry_special_dpo_update (fib_table_find (FIB_PROTOCOL_IP6,
							  sr_policy->fib_table),
					  &pfx, FIB_SOURCE_SR,
					  FIB_ENTRY_FLAG_EXCLUSIVE,
					  &sr_policy->bsid_dpo);

      fib_table_entry_special_dpo_update (sm->fib_table_ip6,
					  &pfx,
					  FIB_SOURCE_SR,
					  FIB_ENTRY_FLAG_EXCLUSIVE,
					  &sr_policy->ip6_dpo);

      if (sr_policy->is_encap)
	{
	  dpo_set (&sr_policy->ip4_dpo, DPO_REPLICATE, DPO_PROTO_IP4,
		   replicate_create (0, DPO_PROTO_IP4));

	  fib_table_entry_special_dpo_update (sm->fib_table_ip4,
					      &pfx,
					      FIB_SOURCE_SR,
					      FIB_ENTRY_FLAG_EXCLUSIVE,
					      &sr_policy->ip4_dpo);
	}

    }

  /* Create the replicate path vector */
  path.path_weight = 1;
  vec_foreach (sl_index, sr_policy->segments_lists)
  {
    segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);
    path.path_dpo = segment_list->bsid_dpo;
    vec_add1 (b_path_vector, path);
    path.path_dpo = segment_list->ip6_dpo;
    vec_add1 (ip6_path_vector, path);
    if (sr_policy->is_encap)
      {
	path.path_dpo = segment_list->ip4_dpo;
	vec_add1 (ip4_path_vector, path);
      }
  }

  /* Update replicate multipath */
  replicate_multipath_update (&sr_policy->bsid_dpo, b_path_vector);
  replicate_multipath_update (&sr_policy->ip6_dpo, ip6_path_vector);
  if (sr_policy->is_encap)
    replicate_multipath_update (&sr_policy->ip4_dpo, ip4_path_vector);
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
sr_policy_add (ip6_address_t * bsid, ip6_address_t * segments,
	       u32 weight, u8 behavior, u32 fib_table, u8 is_encap,
	       u16 plugin, void *ls_plugin_mem)
{
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_policy_t *sr_policy = 0;
  uword *p;

  /* Search for existing keys (BSID) */
  p = mhash_get (&sm->sr_policies_index_hash, bsid);
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
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 128,
    .fp_addr = {
		.ip6 = *bsid,
		}
  };

  /* Lookup the FIB index associated to the table selected */
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP6,
				  (fib_table != (u32) ~ 0 ? fib_table : 0));
  if (fib_index == ~0)
    return -13;

  /* Lookup whether there exists an entry for the BSID */
  fib_node_index_t fei = fib_table_lookup_exact_match (fib_index, &pfx);
  if (FIB_NODE_INDEX_INVALID != fei)
    return -12;			//There is an entry for such lookup

  /* Add an SR policy object */
  pool_get (sm->sr_policies, sr_policy);
  clib_memset (sr_policy, 0, sizeof (*sr_policy));
  clib_memcpy_fast (&sr_policy->bsid, bsid, sizeof (ip6_address_t));
  sr_policy->type = behavior;
  sr_policy->fib_table = (fib_table != (u32) ~ 0 ? fib_table : 0);	//Is default FIB 0 ?
  sr_policy->is_encap = is_encap;

  if (plugin)
    {
      sr_policy->plugin = plugin;
      sr_policy->plugin_mem = ls_plugin_mem;
    }

  /* Copy the key */
  mhash_set (&sm->sr_policies_index_hash, bsid, sr_policy - sm->sr_policies,
	     NULL);

  /* Create a segment list and add the index to the SR policy */
  create_sl (sr_policy, segments, weight, is_encap);

  /* If FIB doesnt exist, create them */
  if (sm->fib_table_ip6 == (u32) ~ 0)
    {
      sm->fib_table_ip6 = fib_table_create_and_lock (FIB_PROTOCOL_IP6,
						     FIB_SOURCE_SR,
						     "SRv6 steering of IP6 prefixes through BSIDs");
      sm->fib_table_ip4 = fib_table_create_and_lock (FIB_PROTOCOL_IP6,
						     FIB_SOURCE_SR,
						     "SRv6 steering of IP4 prefixes through BSIDs");
    }

  /* Create IPv6 FIB for the BindingSID attached to the DPO of the only SL */
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
sr_policy_del (ip6_address_t * bsid, u32 index)
{
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_policy_t *sr_policy = 0;
  ip6_sr_sl_t *segment_list;
  u32 *sl_index;
  uword *p;

  if (bsid)
    {
      p = mhash_get (&sm->sr_policies_index_hash, bsid);
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
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 128,
    .fp_addr = {
		.ip6 = sr_policy->bsid,
		}
    ,
  };

  fib_table_entry_special_remove (fib_table_find (FIB_PROTOCOL_IP6,
						  sr_policy->fib_table),
				  &pfx, FIB_SOURCE_SR);

  fib_table_entry_special_remove (sm->fib_table_ip6, &pfx, FIB_SOURCE_SR);

  if (sr_policy->is_encap)
    fib_table_entry_special_remove (sm->fib_table_ip4, &pfx, FIB_SOURCE_SR);

  if (dpo_id_is_valid (&sr_policy->bsid_dpo))
    {
      dpo_reset (&sr_policy->bsid_dpo);
      dpo_reset (&sr_policy->ip4_dpo);
      dpo_reset (&sr_policy->ip6_dpo);
    }

  /* Clean SID Lists */
  vec_foreach (sl_index, sr_policy->segments_lists)
  {
    segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);
    vec_free (segment_list->segments);
    vec_free (segment_list->rewrite);
    if (!sr_policy->is_encap)
      vec_free (segment_list->rewrite_bsid);
    pool_put_index (sm->sid_lists, *sl_index);
  }

  if (sr_policy->plugin)
    {
      sr_policy_fn_registration_t *plugin = 0;

      plugin =
	pool_elt_at_index (sm->policy_plugin_functions,
			   sr_policy->plugin - SR_BEHAVIOR_LAST);

      plugin->removal (sr_policy);
      sr_policy->plugin = 0;
      sr_policy->plugin_mem = NULL;
    }

  /* Remove SR policy entry */
  mhash_unset (&sm->sr_policies_index_hash, &sr_policy->bsid, NULL);
  pool_put (sm->sr_policies, sr_policy);

  /* If FIB empty unlock it */
  if (!pool_elts (sm->sr_policies) && !pool_elts (sm->steer_policies))
    {
      fib_table_unlock (sm->fib_table_ip6, FIB_PROTOCOL_IP6, FIB_SOURCE_SR);
      fib_table_unlock (sm->fib_table_ip4, FIB_PROTOCOL_IP6, FIB_SOURCE_SR);
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
 * @param is_encap Mode. Encapsulation or SRH insertion.
 *
 * @return 0 if correct, else error
 */
int
sr_policy_mod (ip6_address_t * bsid, u32 index, u32 fib_table,
	       u8 operation, ip6_address_t * segments, u32 sl_index,
	       u32 weight)
{
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_policy_t *sr_policy = 0;
  ip6_sr_sl_t *segment_list;
  u32 *sl_index_iterate;
  uword *p;

  if (bsid)
    {
      p = mhash_get (&sm->sr_policies_index_hash, bsid);
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
      segment_list =
	create_sl (sr_policy, segments, weight, sr_policy->is_encap);

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
      vec_free (segment_list->rewrite);
      if (!sr_policy->is_encap)
	vec_free (segment_list->rewrite_bsid);
      pool_put_index (sm->sid_lists, sl_index);
      vec_del1 (sr_policy->segments_lists,
		sl_index_iterate - sr_policy->segments_lists);

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
 * @brief CLI for 'sr policies' command family
 */
static clib_error_t *
sr_policy_command_fn (vlib_main_t * vm, unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  ip6_sr_main_t *sm = &sr_main;
  int rv = -1;
  char is_del = 0, is_add = 0, is_mod = 0;
  char policy_set = 0;
  ip6_address_t bsid, next_address;
  u32 sr_policy_index = (u32) ~ 0, sl_index = (u32) ~ 0;
  u32 weight = (u32) ~ 0, fib_table = (u32) ~ 0;
  ip6_address_t *segments = 0, *this_seg;
  u8 operation = 0;
  char is_encap = 1;
  char is_spray = 0;
  u16 behavior = 0;
  void *ls_plugin_mem = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!is_add && !is_mod && !is_del && unformat (input, "add"))
	is_add = 1;
      else if (!is_add && !is_mod && !is_del && unformat (input, "del"))
	is_del = 1;
      else if (!is_add && !is_mod && !is_del && unformat (input, "mod"))
	is_mod = 1;
      else if (!policy_set
	       && unformat (input, "bsid %U", unformat_ip6_address, &bsid))
	policy_set = 1;
      else if (!is_add && !policy_set
	       && unformat (input, "index %d", &sr_policy_index))
	policy_set = 1;
      else if (unformat (input, "weight %d", &weight));
      else
	if (unformat (input, "next %U", unformat_ip6_address, &next_address))
	{
	  vec_add2 (segments, this_seg, 1);
	  clib_memcpy_fast (this_seg->as_u8, next_address.as_u8,
			    sizeof (*this_seg));
	}
      else if (unformat (input, "add sl"))
	operation = 1;
      else if (unformat (input, "del sl index %d", &sl_index))
	operation = 2;
      else if (unformat (input, "mod sl index %d", &sl_index))
	operation = 3;
      else if (fib_table == (u32) ~ 0
	       && unformat (input, "fib-table %d", &fib_table));
      else if (unformat (input, "encap"))
	is_encap = 1;
      else if (unformat (input, "insert"))
	is_encap = 0;
      else if (unformat (input, "spray"))
	is_spray = 1;
      else if (!behavior && unformat (input, "behavior"))
	{
	  sr_policy_fn_registration_t *plugin = 0, **vec_plugins = 0;
	  sr_policy_fn_registration_t **plugin_it = 0;

	  /* *INDENT-OFF* */
	  pool_foreach (plugin, sm->policy_plugin_functions,
	    {
	      vec_add1 (vec_plugins, plugin);
	    });
	  /* *INDENT-ON* */

	  vec_foreach (plugin_it, vec_plugins)
	  {
	    if (unformat
		(input, "%U", (*plugin_it)->ls_unformat, &ls_plugin_mem))
	      {
		behavior = (*plugin_it)->sr_policy_function_number;
		break;
	      }
	  }

	  if (!behavior)
	    {
	      return clib_error_return (0, "Invalid behavior");
	    }
	}
      else
	break;
    }

  if (!is_add && !is_mod && !is_del)
    return clib_error_return (0, "Incorrect CLI");

  if (!policy_set)
    return clib_error_return (0, "No SR policy BSID or index specified");

  if (is_add)
    {
      if (behavior && vec_len (segments) == 0)
	{
	  vec_add2 (segments, this_seg, 1);
	  clib_memset (this_seg, 0, sizeof (*this_seg));
	}

      if (vec_len (segments) == 0)
	return clib_error_return (0, "No Segment List specified");

      rv = sr_policy_add (&bsid, segments, weight,
			  (is_spray ? SR_POLICY_TYPE_SPRAY :
			   SR_POLICY_TYPE_DEFAULT), fib_table, is_encap,
			  behavior, ls_plugin_mem);

      vec_free (segments);
    }
  else if (is_del)
    rv = sr_policy_del ((sr_policy_index != (u32) ~ 0 ? NULL : &bsid),
			sr_policy_index);
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

      rv = sr_policy_mod ((sr_policy_index != (u32) ~ 0 ? NULL : &bsid),
			  sr_policy_index, fib_table, operation, segments,
			  sl_index, weight);

      if (segments)
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
VLIB_CLI_COMMAND (sr_policy_command, static) = {
  .path = "sr policy",
  .short_help = "sr policy [add||del||mod] [bsid 2001::1||index 5] "
    "next A:: next B:: next C:: (weight 1) (fib-table 2) (encap|insert)",
  .long_help =
    "Manipulation of SR policies.\n"
    "A Segment Routing policy may contain several SID lists. Each SID list has\n"
    "an associated weight (default 1), which will result in wECMP (uECMP).\n"
    "Segment Routing policies might be of type encapsulation or srh insertion\n"
    "Each SR policy will be associated with a unique BindingSID.\n"
    "A BindingSID is a locally allocated SegmentID. For every packet that arrives\n"
    "with IPv6_DA:BSID such traffic will be steered into the SR policy.\n"
    "The add command will create a SR policy with its first segment list (sl)\n"
    "The mod command allows you to add, remove, or modify the existing segment lists\n"
    "within an SR policy.\n"
    "The del command allows you to delete a SR policy along with all its associated\n"
    "SID lists.\n",
  .function = sr_policy_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief CLI to display onscreen all the SR policies
 */
static clib_error_t *
show_sr_policies_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 *sl_index;
  ip6_sr_sl_t *segment_list = 0;
  ip6_sr_policy_t *sr_policy = 0;
  ip6_sr_policy_t **vec_policies = 0;
  ip6_address_t *addr;
  u8 *s;
  int i = 0;

  vlib_cli_output (vm, "SR policies:");

  /* *INDENT-OFF* */
  pool_foreach  (sr_policy, sm->sr_policies,
                {vec_add1 (vec_policies, sr_policy); } );
  /* *INDENT-ON* */

  vec_foreach_index (i, vec_policies)
  {
    sr_policy = vec_policies[i];
    vlib_cli_output (vm, "[%u].-\tBSID: %U",
		     (u32) (sr_policy - sm->sr_policies),
		     format_ip6_address, &sr_policy->bsid);
    vlib_cli_output (vm, "\tBehavior: %s",
		     (sr_policy->is_encap ? "Encapsulation" :
		      "SRH insertion"));
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
      s = format (s, "\t[%u].- ", *sl_index);
      segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);
      s = format (s, "< ");
      vec_foreach (addr, segment_list->segments)
      {
	s = format (s, "%U, ", format_ip6_address, addr);
      }
      s = format (s, "\b\b > ");
      s = format (s, "weight: %u", segment_list->weight);
      vlib_cli_output (vm, "  %v", s);
    }
    vlib_cli_output (vm, "-----------");
  }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_sr_policies_command, static) = {
  .path = "show sr policies",
  .short_help = "show sr policies",
  .function = show_sr_policies_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief CLI to display onscreen the SR encaps source addr
 */
static clib_error_t *
show_sr_encaps_source_command_fn (vlib_main_t * vm, unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "SR encaps source addr = %U", format_ip6_address,
		   sr_get_encaps_source ());

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_sr_encaps_source_command, static) = {
  .path = "show sr encaps source addr",
  .short_help = "show sr encaps source addr",
  .function = show_sr_encaps_source_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief CLI to display onscreen the hop-limit value used for SRv6 encapsulation
 */
static clib_error_t *
show_sr_encaps_hop_limit_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "SR encaps hop-limit = %u", sr_get_hop_limit ());

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_sr_encaps_hop_limit_command, static) = {
  .path = "show sr encaps hop-limit",
  .short_help = "show sr encaps hop-limit",
  .function = show_sr_encaps_hop_limit_command_fn,
};
/* *INDENT-ON* */

/*************************** SR rewrite graph node ****************************/
/**
 * @brief Trace for the SR Policy Rewrite graph node
 */
static u8 *
format_sr_policy_rewrite_trace (u8 * s, va_list * args)
{
  //TODO
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sr_policy_rewrite_trace_t *t = va_arg (*args, sr_policy_rewrite_trace_t *);

  s = format
    (s, "SR-policy-rewrite: src %U dst %U",
     format_ip6_address, &t->src, format_ip6_address, &t->dst);

  return s;
}

/**
 * @brief IPv6 encapsulation processing as per RFC2473
 */
static_always_inline void
encaps_processing_v6 (vlib_node_runtime_t * node,
		      vlib_buffer_t * b0,
		      ip6_header_t * ip0, ip6_header_t * ip0_encap)
{
  u32 new_l0;

  ip0_encap->hop_limit -= 1;
  new_l0 =
    ip0->payload_length + sizeof (ip6_header_t) +
    clib_net_to_host_u16 (ip0_encap->payload_length);
  ip0->payload_length = clib_host_to_net_u16 (new_l0);
  ip0->ip_version_traffic_class_and_flow_label =
    ip0_encap->ip_version_traffic_class_and_flow_label;
}

/**
 * @brief Graph node for applying a SR policy into an IPv6 packet. Encapsulation
 */
static uword
sr_policy_rewrite_encaps (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * from_frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  int encap_pkts = 0, bsid_pkts = 0;

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
	  ip6_header_t *ip0, *ip1, *ip2, *ip3;
	  ip6_header_t *ip0_encap, *ip1_encap, *ip2_encap, *ip3_encap;
	  ip6_sr_sl_t *sl0, *sl1, *sl2, *sl3;

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

	  sl0 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b0)->ip.adj_index);
	  sl1 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b1)->ip.adj_index);
	  sl2 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b2)->ip.adj_index);
	  sl3 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b3)->ip.adj_index);

	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));
	  ASSERT (b1->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl1->rewrite));
	  ASSERT (b2->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl2->rewrite));
	  ASSERT (b3->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl3->rewrite));

	  ip0_encap = vlib_buffer_get_current (b0);
	  ip1_encap = vlib_buffer_get_current (b1);
	  ip2_encap = vlib_buffer_get_current (b2);
	  ip3_encap = vlib_buffer_get_current (b3);

	  clib_memcpy_fast (((u8 *) ip0_encap) - vec_len (sl0->rewrite),
			    sl0->rewrite, vec_len (sl0->rewrite));
	  clib_memcpy_fast (((u8 *) ip1_encap) - vec_len (sl1->rewrite),
			    sl1->rewrite, vec_len (sl1->rewrite));
	  clib_memcpy_fast (((u8 *) ip2_encap) - vec_len (sl2->rewrite),
			    sl2->rewrite, vec_len (sl2->rewrite));
	  clib_memcpy_fast (((u8 *) ip3_encap) - vec_len (sl3->rewrite),
			    sl3->rewrite, vec_len (sl3->rewrite));

	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));
	  vlib_buffer_advance (b1, -(word) vec_len (sl1->rewrite));
	  vlib_buffer_advance (b2, -(word) vec_len (sl2->rewrite));
	  vlib_buffer_advance (b3, -(word) vec_len (sl3->rewrite));

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  ip2 = vlib_buffer_get_current (b2);
	  ip3 = vlib_buffer_get_current (b3);

	  encaps_processing_v6 (node, b0, ip0, ip0_encap);
	  encaps_processing_v6 (node, b1, ip1, ip1_encap);
	  encaps_processing_v6 (node, b2, ip2, ip2_encap);
	  encaps_processing_v6 (node, b3, ip3, ip3_encap);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b1, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip1->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip1->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b2->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b2, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip2->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip2->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b3->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b3, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip3->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip3->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}
	    }

	  encap_pkts += 4;
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      /* Single loop for potentially the last three packets */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0, *ip0_encap = 0;
	  ip6_sr_sl_t *sl0;
	  u32 next0 = SR_POLICY_REWRITE_NEXT_IP6_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);

	  sl0 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b0)->ip.adj_index);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));

	  ip0_encap = vlib_buffer_get_current (b0);

	  clib_memcpy_fast (((u8 *) ip0_encap) - vec_len (sl0->rewrite),
			    sl0->rewrite, vec_len (sl0->rewrite));
	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));

	  ip0 = vlib_buffer_get_current (b0);

	  encaps_processing_v6 (node, b0, ip0, ip0_encap);

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_policy_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				sizeof (tr->src.as_u8));
	      clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				sizeof (tr->dst.as_u8));
	    }

	  encap_pkts++;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, sr_policy_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_TOTAL,
			       encap_pkts);
  vlib_node_increment_counter (vm, sr_policy_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_BSID,
			       bsid_pkts);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_policy_rewrite_encaps_node) = {
  .function = sr_policy_rewrite_encaps,
  .name = "sr-pl-rewrite-encaps",
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
/* *INDENT-ON* */

/**
 * @brief IPv4 encapsulation processing as per RFC2473
 */
static_always_inline void
encaps_processing_v4 (vlib_node_runtime_t * node,
		      vlib_buffer_t * b0,
		      ip6_header_t * ip0, ip4_header_t * ip0_encap)
{
  u32 new_l0;
  ip6_sr_header_t *sr0;

  u32 checksum0;

  /* Inner IPv4: Decrement TTL & update checksum */
  ip0_encap->ttl -= 1;
  checksum0 = ip0_encap->checksum + clib_host_to_net_u16 (0x0100);
  checksum0 += checksum0 >= 0xffff;
  ip0_encap->checksum = checksum0;

  /* Outer IPv6: Update length, FL, proto */
  new_l0 = ip0->payload_length + clib_net_to_host_u16 (ip0_encap->length);
  ip0->payload_length = clib_host_to_net_u16 (new_l0);
  ip0->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0 | ((6 & 0xF) << 28) |
			  ((ip0_encap->tos & 0xFF) << 20));
  if (ip0->protocol == IP_PROTOCOL_IPV6_ROUTE)
    {
      sr0 = (void *) (ip0 + 1);
      sr0->protocol = IP_PROTOCOL_IP_IN_IP;
    }
  else
    ip0->protocol = IP_PROTOCOL_IP_IN_IP;
}

/**
 * @brief Graph node for applying a SR policy into an IPv4 packet. Encapsulation
 */
static uword
sr_policy_rewrite_encaps_v4 (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * from_frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  int encap_pkts = 0, bsid_pkts = 0;

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
	  ip6_header_t *ip0, *ip1, *ip2, *ip3;
	  ip4_header_t *ip0_encap, *ip1_encap, *ip2_encap, *ip3_encap;
	  ip6_sr_sl_t *sl0, *sl1, *sl2, *sl3;

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

	  sl0 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b0)->ip.adj_index);
	  sl1 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b1)->ip.adj_index);
	  sl2 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b2)->ip.adj_index);
	  sl3 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b3)->ip.adj_index);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));
	  ASSERT (b1->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl1->rewrite));
	  ASSERT (b2->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl2->rewrite));
	  ASSERT (b3->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl3->rewrite));

	  ip0_encap = vlib_buffer_get_current (b0);
	  ip1_encap = vlib_buffer_get_current (b1);
	  ip2_encap = vlib_buffer_get_current (b2);
	  ip3_encap = vlib_buffer_get_current (b3);

	  clib_memcpy_fast (((u8 *) ip0_encap) - vec_len (sl0->rewrite),
			    sl0->rewrite, vec_len (sl0->rewrite));
	  clib_memcpy_fast (((u8 *) ip1_encap) - vec_len (sl1->rewrite),
			    sl1->rewrite, vec_len (sl1->rewrite));
	  clib_memcpy_fast (((u8 *) ip2_encap) - vec_len (sl2->rewrite),
			    sl2->rewrite, vec_len (sl2->rewrite));
	  clib_memcpy_fast (((u8 *) ip3_encap) - vec_len (sl3->rewrite),
			    sl3->rewrite, vec_len (sl3->rewrite));

	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));
	  vlib_buffer_advance (b1, -(word) vec_len (sl1->rewrite));
	  vlib_buffer_advance (b2, -(word) vec_len (sl2->rewrite));
	  vlib_buffer_advance (b3, -(word) vec_len (sl3->rewrite));

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  ip2 = vlib_buffer_get_current (b2);
	  ip3 = vlib_buffer_get_current (b3);

	  encaps_processing_v4 (node, b0, ip0, ip0_encap);
	  encaps_processing_v4 (node, b1, ip1, ip1_encap);
	  encaps_processing_v4 (node, b2, ip2, ip2_encap);
	  encaps_processing_v4 (node, b3, ip3, ip3_encap);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b1, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip1->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip1->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b2->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b2, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip2->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip2->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b3->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b3, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip3->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip3->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}
	    }

	  encap_pkts += 4;
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      /* Single loop for potentially the last three packets */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  ip4_header_t *ip0_encap = 0;
	  ip6_sr_sl_t *sl0;
	  u32 next0 = SR_POLICY_REWRITE_NEXT_IP6_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);

	  sl0 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b0)->ip.adj_index);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));

	  ip0_encap = vlib_buffer_get_current (b0);

	  clib_memcpy_fast (((u8 *) ip0_encap) - vec_len (sl0->rewrite),
			    sl0->rewrite, vec_len (sl0->rewrite));
	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));

	  ip0 = vlib_buffer_get_current (b0);

	  encaps_processing_v4 (node, b0, ip0, ip0_encap);

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_policy_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				sizeof (tr->src.as_u8));
	      clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				sizeof (tr->dst.as_u8));
	    }

	  encap_pkts++;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, sr_policy_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_TOTAL,
			       encap_pkts);
  vlib_node_increment_counter (vm, sr_policy_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_BSID,
			       bsid_pkts);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_policy_rewrite_encaps_v4_node) = {
  .function = sr_policy_rewrite_encaps_v4,
  .name = "sr-pl-rewrite-encaps-v4",
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
/* *INDENT-ON* */

always_inline u32
ip_flow_hash (void *data)
{
  ip4_header_t *iph = (ip4_header_t *) data;

  if ((iph->ip_version_and_header_length & 0xF0) == 0x40)
    return ip4_compute_flow_hash (iph, IP_FLOW_HASH_DEFAULT);
  else
    return ip6_compute_flow_hash ((ip6_header_t *) iph, IP_FLOW_HASH_DEFAULT);
}

always_inline u64
mac_to_u64 (u8 * m)
{
  return (*((u64 *) m) & 0xffffffffffff);
}

always_inline u32
l2_flow_hash (vlib_buffer_t * b0)
{
  ethernet_header_t *eh;
  u64 a, b, c;
  uword is_ip, eh_size;
  u16 eh_type;

  eh = vlib_buffer_get_current (b0);
  eh_type = clib_net_to_host_u16 (eh->type);
  eh_size = ethernet_buffer_header_size (b0);

  is_ip = (eh_type == ETHERNET_TYPE_IP4 || eh_type == ETHERNET_TYPE_IP6);

  /* since we have 2 cache lines, use them */
  if (is_ip)
    a = ip_flow_hash ((u8 *) vlib_buffer_get_current (b0) + eh_size);
  else
    a = eh->type;

  b = mac_to_u64 ((u8 *) eh->dst_address);
  c = mac_to_u64 ((u8 *) eh->src_address);
  hash_mix64 (a, b, c);

  return (u32) c;
}

/**
 * @brief Graph node for applying a SR policy into a L2 frame
 */
static uword
sr_policy_rewrite_encaps_l2 (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * from_frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  int encap_pkts = 0, bsid_pkts = 0;

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
	  ethernet_header_t *en0, *en1, *en2, *en3;
	  ip6_header_t *ip0, *ip1, *ip2, *ip3;
	  ip6_sr_header_t *sr0, *sr1, *sr2, *sr3;
	  ip6_sr_policy_t *sp0, *sp1, *sp2, *sp3;
	  ip6_sr_sl_t *sl0, *sl1, *sl2, *sl3;

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

	  sp0 = pool_elt_at_index (sm->sr_policies,
				   sm->sw_iface_sr_policies[vnet_buffer
							    (b0)->sw_if_index
							    [VLIB_RX]]);

	  sp1 = pool_elt_at_index (sm->sr_policies,
				   sm->sw_iface_sr_policies[vnet_buffer
							    (b1)->sw_if_index
							    [VLIB_RX]]);

	  sp2 = pool_elt_at_index (sm->sr_policies,
				   sm->sw_iface_sr_policies[vnet_buffer
							    (b2)->sw_if_index
							    [VLIB_RX]]);

	  sp3 = pool_elt_at_index (sm->sr_policies,
				   sm->sw_iface_sr_policies[vnet_buffer
							    (b3)->sw_if_index
							    [VLIB_RX]]);

	  if (vec_len (sp0->segments_lists) == 1)
	    vnet_buffer (b0)->ip.adj_index = sp0->segments_lists[0];
	  else
	    {
	      vnet_buffer (b0)->ip.flow_hash = l2_flow_hash (b0);
	      vnet_buffer (b0)->ip.adj_index =
		sp0->segments_lists[(vnet_buffer (b0)->ip.flow_hash &
				     (vec_len (sp0->segments_lists) - 1))];
	    }

	  if (vec_len (sp1->segments_lists) == 1)
	    vnet_buffer (b1)->ip.adj_index = sp1->segments_lists[1];
	  else
	    {
	      vnet_buffer (b1)->ip.flow_hash = l2_flow_hash (b1);
	      vnet_buffer (b1)->ip.adj_index =
		sp1->segments_lists[(vnet_buffer (b1)->ip.flow_hash &
				     (vec_len (sp1->segments_lists) - 1))];
	    }

	  if (vec_len (sp2->segments_lists) == 1)
	    vnet_buffer (b2)->ip.adj_index = sp2->segments_lists[2];
	  else
	    {
	      vnet_buffer (b2)->ip.flow_hash = l2_flow_hash (b2);
	      vnet_buffer (b2)->ip.adj_index =
		sp2->segments_lists[(vnet_buffer (b2)->ip.flow_hash &
				     (vec_len (sp2->segments_lists) - 1))];
	    }

	  if (vec_len (sp3->segments_lists) == 1)
	    vnet_buffer (b3)->ip.adj_index = sp3->segments_lists[3];
	  else
	    {
	      vnet_buffer (b3)->ip.flow_hash = l2_flow_hash (b3);
	      vnet_buffer (b3)->ip.adj_index =
		sp3->segments_lists[(vnet_buffer (b3)->ip.flow_hash &
				     (vec_len (sp3->segments_lists) - 1))];
	    }

	  sl0 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b0)->ip.adj_index);
	  sl1 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b1)->ip.adj_index);
	  sl2 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b2)->ip.adj_index);
	  sl3 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b3)->ip.adj_index);

	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));
	  ASSERT (b1->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl1->rewrite));
	  ASSERT (b2->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl2->rewrite));
	  ASSERT (b3->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl3->rewrite));

	  en0 = vlib_buffer_get_current (b0);
	  en1 = vlib_buffer_get_current (b1);
	  en2 = vlib_buffer_get_current (b2);
	  en3 = vlib_buffer_get_current (b3);

	  clib_memcpy_fast (((u8 *) en0) - vec_len (sl0->rewrite),
			    sl0->rewrite, vec_len (sl0->rewrite));
	  clib_memcpy_fast (((u8 *) en1) - vec_len (sl1->rewrite),
			    sl1->rewrite, vec_len (sl1->rewrite));
	  clib_memcpy_fast (((u8 *) en2) - vec_len (sl2->rewrite),
			    sl2->rewrite, vec_len (sl2->rewrite));
	  clib_memcpy_fast (((u8 *) en3) - vec_len (sl3->rewrite),
			    sl3->rewrite, vec_len (sl3->rewrite));

	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));
	  vlib_buffer_advance (b1, -(word) vec_len (sl1->rewrite));
	  vlib_buffer_advance (b2, -(word) vec_len (sl2->rewrite));
	  vlib_buffer_advance (b3, -(word) vec_len (sl3->rewrite));

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  ip2 = vlib_buffer_get_current (b2);
	  ip3 = vlib_buffer_get_current (b3);

	  ip0->payload_length =
	    clib_host_to_net_u16 (b0->current_length - sizeof (ip6_header_t));
	  ip1->payload_length =
	    clib_host_to_net_u16 (b1->current_length - sizeof (ip6_header_t));
	  ip2->payload_length =
	    clib_host_to_net_u16 (b2->current_length - sizeof (ip6_header_t));
	  ip3->payload_length =
	    clib_host_to_net_u16 (b3->current_length - sizeof (ip6_header_t));

	  if (ip0->protocol == IP_PROTOCOL_IPV6_ROUTE)
	    {
	      sr0 = (void *) (ip0 + 1);
	      sr0->protocol = IP_PROTOCOL_IP6_ETHERNET;
	    }
	  else
	    ip0->protocol = IP_PROTOCOL_IP6_ETHERNET;

	  if (ip1->protocol == IP_PROTOCOL_IPV6_ROUTE)
	    {
	      sr1 = (void *) (ip1 + 1);
	      sr1->protocol = IP_PROTOCOL_IP6_ETHERNET;
	    }
	  else
	    ip1->protocol = IP_PROTOCOL_IP6_ETHERNET;

	  if (ip2->protocol == IP_PROTOCOL_IPV6_ROUTE)
	    {
	      sr2 = (void *) (ip2 + 1);
	      sr2->protocol = IP_PROTOCOL_IP6_ETHERNET;
	    }
	  else
	    ip2->protocol = IP_PROTOCOL_IP6_ETHERNET;

	  if (ip3->protocol == IP_PROTOCOL_IPV6_ROUTE)
	    {
	      sr3 = (void *) (ip3 + 1);
	      sr3->protocol = IP_PROTOCOL_IP6_ETHERNET;
	    }
	  else
	    ip3->protocol = IP_PROTOCOL_IP6_ETHERNET;

	  /* Which Traffic class and flow label do I set ? */
	  //ip0->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32(0|((6&0xF)<<28)|((ip0_encap->tos&0xFF)<<20));

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b1, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip1->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip1->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b2->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b2, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip2->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip2->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b3->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b3, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip3->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip3->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}
	    }

	  encap_pkts += 4;
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      /* Single loop for potentially the last three packets */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  ip6_sr_header_t *sr0;
	  ethernet_header_t *en0;
	  ip6_sr_policy_t *sp0;
	  ip6_sr_sl_t *sl0;
	  u32 next0 = SR_POLICY_REWRITE_NEXT_IP6_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);

	  /* Find the SR policy */
	  sp0 = pool_elt_at_index (sm->sr_policies,
				   sm->sw_iface_sr_policies[vnet_buffer
							    (b0)->sw_if_index
							    [VLIB_RX]]);

	  /* In case there is more than one SL, LB among them */
	  if (vec_len (sp0->segments_lists) == 1)
	    vnet_buffer (b0)->ip.adj_index = sp0->segments_lists[0];
	  else
	    {
	      vnet_buffer (b0)->ip.flow_hash = l2_flow_hash (b0);
	      vnet_buffer (b0)->ip.adj_index =
		sp0->segments_lists[(vnet_buffer (b0)->ip.flow_hash &
				     (vec_len (sp0->segments_lists) - 1))];
	    }
	  sl0 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b0)->ip.adj_index);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));

	  en0 = vlib_buffer_get_current (b0);

	  clib_memcpy_fast (((u8 *) en0) - vec_len (sl0->rewrite),
			    sl0->rewrite, vec_len (sl0->rewrite));

	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));

	  ip0 = vlib_buffer_get_current (b0);

	  ip0->payload_length =
	    clib_host_to_net_u16 (b0->current_length - sizeof (ip6_header_t));

	  if (ip0->protocol == IP_PROTOCOL_IPV6_ROUTE)
	    {
	      sr0 = (void *) (ip0 + 1);
	      sr0->protocol = IP_PROTOCOL_IP6_ETHERNET;
	    }
	  else
	    ip0->protocol = IP_PROTOCOL_IP6_ETHERNET;

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_policy_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				sizeof (tr->src.as_u8));
	      clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				sizeof (tr->dst.as_u8));
	    }

	  encap_pkts++;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, sr_policy_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_TOTAL,
			       encap_pkts);
  vlib_node_increment_counter (vm, sr_policy_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_BSID,
			       bsid_pkts);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_policy_rewrite_encaps_l2_node) = {
  .function = sr_policy_rewrite_encaps_l2,
  .name = "sr-pl-rewrite-encaps-l2",
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
/* *INDENT-ON* */

/**
 * @brief Graph node for applying a SR policy into a packet. SRH insertion.
 */
static uword
sr_policy_rewrite_insert (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * from_frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  int insert_pkts = 0, bsid_pkts = 0;

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
	  ip6_header_t *ip0, *ip1, *ip2, *ip3;
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

	  sl0 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b0)->ip.adj_index);
	  sl1 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b1)->ip.adj_index);
	  sl2 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b2)->ip.adj_index);
	  sl3 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b3)->ip.adj_index);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));
	  ASSERT (b1->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl1->rewrite));
	  ASSERT (b2->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl2->rewrite));
	  ASSERT (b3->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl3->rewrite));

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  ip2 = vlib_buffer_get_current (b2);
	  ip3 = vlib_buffer_get_current (b3);

	  if (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	    sr0 =
	      (ip6_sr_header_t *) (((void *) (ip0 + 1)) +
				   ip6_ext_header_len (ip0 + 1));
	  else
	    sr0 = (ip6_sr_header_t *) (ip0 + 1);

	  if (ip1->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	    sr1 =
	      (ip6_sr_header_t *) (((void *) (ip1 + 1)) +
				   ip6_ext_header_len (ip1 + 1));
	  else
	    sr1 = (ip6_sr_header_t *) (ip1 + 1);

	  if (ip2->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	    sr2 =
	      (ip6_sr_header_t *) (((void *) (ip2 + 1)) +
				   ip6_ext_header_len (ip2 + 1));
	  else
	    sr2 = (ip6_sr_header_t *) (ip2 + 1);

	  if (ip3->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	    sr3 =
	      (ip6_sr_header_t *) (((void *) (ip3 + 1)) +
				   ip6_ext_header_len (ip3 + 1));
	  else
	    sr3 = (ip6_sr_header_t *) (ip3 + 1);

	  clib_memcpy_fast ((u8 *) ip0 - vec_len (sl0->rewrite), (u8 *) ip0,
			    (void *) sr0 - (void *) ip0);
	  clib_memcpy_fast ((u8 *) ip1 - vec_len (sl1->rewrite), (u8 *) ip1,
			    (void *) sr1 - (void *) ip1);
	  clib_memcpy_fast ((u8 *) ip2 - vec_len (sl2->rewrite), (u8 *) ip2,
			    (void *) sr2 - (void *) ip2);
	  clib_memcpy_fast ((u8 *) ip3 - vec_len (sl3->rewrite), (u8 *) ip3,
			    (void *) sr3 - (void *) ip3);

	  clib_memcpy_fast (((u8 *) sr0 - vec_len (sl0->rewrite)),
			    sl0->rewrite, vec_len (sl0->rewrite));
	  clib_memcpy_fast (((u8 *) sr1 - vec_len (sl1->rewrite)),
			    sl1->rewrite, vec_len (sl1->rewrite));
	  clib_memcpy_fast (((u8 *) sr2 - vec_len (sl2->rewrite)),
			    sl2->rewrite, vec_len (sl2->rewrite));
	  clib_memcpy_fast (((u8 *) sr3 - vec_len (sl3->rewrite)),
			    sl3->rewrite, vec_len (sl3->rewrite));

	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));
	  vlib_buffer_advance (b1, -(word) vec_len (sl1->rewrite));
	  vlib_buffer_advance (b2, -(word) vec_len (sl2->rewrite));
	  vlib_buffer_advance (b3, -(word) vec_len (sl3->rewrite));

	  ip0 = ((void *) ip0) - vec_len (sl0->rewrite);
	  ip1 = ((void *) ip1) - vec_len (sl1->rewrite);
	  ip2 = ((void *) ip2) - vec_len (sl2->rewrite);
	  ip3 = ((void *) ip3) - vec_len (sl3->rewrite);

	  ip0->hop_limit -= 1;
	  ip1->hop_limit -= 1;
	  ip2->hop_limit -= 1;
	  ip3->hop_limit -= 1;

	  new_l0 =
	    clib_net_to_host_u16 (ip0->payload_length) +
	    vec_len (sl0->rewrite);
	  new_l1 =
	    clib_net_to_host_u16 (ip1->payload_length) +
	    vec_len (sl1->rewrite);
	  new_l2 =
	    clib_net_to_host_u16 (ip2->payload_length) +
	    vec_len (sl2->rewrite);
	  new_l3 =
	    clib_net_to_host_u16 (ip3->payload_length) +
	    vec_len (sl3->rewrite);

	  ip0->payload_length = clib_host_to_net_u16 (new_l0);
	  ip1->payload_length = clib_host_to_net_u16 (new_l1);
	  ip2->payload_length = clib_host_to_net_u16 (new_l2);
	  ip3->payload_length = clib_host_to_net_u16 (new_l3);

	  sr0 = ((void *) sr0) - vec_len (sl0->rewrite);
	  sr1 = ((void *) sr1) - vec_len (sl1->rewrite);
	  sr2 = ((void *) sr2) - vec_len (sl2->rewrite);
	  sr3 = ((void *) sr3) - vec_len (sl3->rewrite);

	  sr0->segments->as_u64[0] = ip0->dst_address.as_u64[0];
	  sr0->segments->as_u64[1] = ip0->dst_address.as_u64[1];
	  sr1->segments->as_u64[0] = ip1->dst_address.as_u64[0];
	  sr1->segments->as_u64[1] = ip1->dst_address.as_u64[1];
	  sr2->segments->as_u64[0] = ip2->dst_address.as_u64[0];
	  sr2->segments->as_u64[1] = ip2->dst_address.as_u64[1];
	  sr3->segments->as_u64[0] = ip3->dst_address.as_u64[0];
	  sr3->segments->as_u64[1] = ip3->dst_address.as_u64[1];

	  ip0->dst_address.as_u64[0] =
	    (sr0->segments + sr0->segments_left)->as_u64[0];
	  ip0->dst_address.as_u64[1] =
	    (sr0->segments + sr0->segments_left)->as_u64[1];
	  ip1->dst_address.as_u64[0] =
	    (sr1->segments + sr1->segments_left)->as_u64[0];
	  ip1->dst_address.as_u64[1] =
	    (sr1->segments + sr1->segments_left)->as_u64[1];
	  ip2->dst_address.as_u64[0] =
	    (sr2->segments + sr2->segments_left)->as_u64[0];
	  ip2->dst_address.as_u64[1] =
	    (sr2->segments + sr2->segments_left)->as_u64[1];
	  ip3->dst_address.as_u64[0] =
	    (sr3->segments + sr3->segments_left)->as_u64[0];
	  ip3->dst_address.as_u64[1] =
	    (sr3->segments + sr3->segments_left)->as_u64[1];

	  ip6_ext_header_t *ip_ext;
	  if (ip0 + 1 == (void *) sr0)
	    {
	      sr0->protocol = ip0->protocol;
	      ip0->protocol = IP_PROTOCOL_IPV6_ROUTE;
	    }
	  else
	    {
	      ip_ext = (void *) (ip0 + 1);
	      sr0->protocol = ip_ext->next_hdr;
	      ip_ext->next_hdr = IP_PROTOCOL_IPV6_ROUTE;
	    }

	  if (ip1 + 1 == (void *) sr1)
	    {
	      sr1->protocol = ip1->protocol;
	      ip1->protocol = IP_PROTOCOL_IPV6_ROUTE;
	    }
	  else
	    {
	      ip_ext = (void *) (ip2 + 1);
	      sr2->protocol = ip_ext->next_hdr;
	      ip_ext->next_hdr = IP_PROTOCOL_IPV6_ROUTE;
	    }

	  if (ip2 + 1 == (void *) sr2)
	    {
	      sr2->protocol = ip2->protocol;
	      ip2->protocol = IP_PROTOCOL_IPV6_ROUTE;
	    }
	  else
	    {
	      ip_ext = (void *) (ip2 + 1);
	      sr2->protocol = ip_ext->next_hdr;
	      ip_ext->next_hdr = IP_PROTOCOL_IPV6_ROUTE;
	    }

	  if (ip3 + 1 == (void *) sr3)
	    {
	      sr3->protocol = ip3->protocol;
	      ip3->protocol = IP_PROTOCOL_IPV6_ROUTE;
	    }
	  else
	    {
	      ip_ext = (void *) (ip3 + 1);
	      sr3->protocol = ip_ext->next_hdr;
	      ip_ext->next_hdr = IP_PROTOCOL_IPV6_ROUTE;
	    }

	  insert_pkts += 4;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b1, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip1->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip1->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b2->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b2, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip2->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip2->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b3->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b3, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip3->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip3->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}
	    }

	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      /* Single loop for potentially the last three packets */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  ip6_sr_header_t *sr0 = 0;
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
	  sl0 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b0)->ip.adj_index);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));

	  ip0 = vlib_buffer_get_current (b0);

	  if (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	    sr0 =
	      (ip6_sr_header_t *) (((void *) (ip0 + 1)) +
				   ip6_ext_header_len (ip0 + 1));
	  else
	    sr0 = (ip6_sr_header_t *) (ip0 + 1);

	  clib_memcpy_fast ((u8 *) ip0 - vec_len (sl0->rewrite), (u8 *) ip0,
			    (void *) sr0 - (void *) ip0);
	  clib_memcpy_fast (((u8 *) sr0 - vec_len (sl0->rewrite)),
			    sl0->rewrite, vec_len (sl0->rewrite));

	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));

	  ip0 = ((void *) ip0) - vec_len (sl0->rewrite);
	  ip0->hop_limit -= 1;
	  new_l0 =
	    clib_net_to_host_u16 (ip0->payload_length) +
	    vec_len (sl0->rewrite);
	  ip0->payload_length = clib_host_to_net_u16 (new_l0);

	  sr0 = ((void *) sr0) - vec_len (sl0->rewrite);
	  sr0->segments->as_u64[0] = ip0->dst_address.as_u64[0];
	  sr0->segments->as_u64[1] = ip0->dst_address.as_u64[1];

	  ip0->dst_address.as_u64[0] =
	    (sr0->segments + sr0->segments_left)->as_u64[0];
	  ip0->dst_address.as_u64[1] =
	    (sr0->segments + sr0->segments_left)->as_u64[1];

	  if (ip0 + 1 == (void *) sr0)
	    {
	      sr0->protocol = ip0->protocol;
	      ip0->protocol = IP_PROTOCOL_IPV6_ROUTE;
	    }
	  else
	    {
	      ip6_ext_header_t *ip_ext = (void *) (ip0 + 1);
	      sr0->protocol = ip_ext->next_hdr;
	      ip_ext->next_hdr = IP_PROTOCOL_IPV6_ROUTE;
	    }

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_policy_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				sizeof (tr->src.as_u8));
	      clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				sizeof (tr->dst.as_u8));
	    }

	  insert_pkts++;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, sr_policy_rewrite_insert_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_TOTAL,
			       insert_pkts);
  vlib_node_increment_counter (vm, sr_policy_rewrite_insert_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_BSID,
			       bsid_pkts);
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_policy_rewrite_insert_node) = {
  .function = sr_policy_rewrite_insert,
  .name = "sr-pl-rewrite-insert",
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
/* *INDENT-ON* */

/**
 * @brief Graph node for applying a SR policy into a packet. BSID - SRH insertion.
 */
static uword
sr_policy_rewrite_b_insert (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * from_frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  int insert_pkts = 0, bsid_pkts = 0;

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
	  ip6_header_t *ip0, *ip1, *ip2, *ip3;
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

	  sl0 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b0)->ip.adj_index);
	  sl1 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b1)->ip.adj_index);
	  sl2 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b2)->ip.adj_index);
	  sl3 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b3)->ip.adj_index);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite_bsid));
	  ASSERT (b1->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl1->rewrite_bsid));
	  ASSERT (b2->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl2->rewrite_bsid));
	  ASSERT (b3->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl3->rewrite_bsid));

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  ip2 = vlib_buffer_get_current (b2);
	  ip3 = vlib_buffer_get_current (b3);

	  if (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	    sr0 =
	      (ip6_sr_header_t *) (((void *) (ip0 + 1)) +
				   ip6_ext_header_len (ip0 + 1));
	  else
	    sr0 = (ip6_sr_header_t *) (ip0 + 1);

	  if (ip1->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	    sr1 =
	      (ip6_sr_header_t *) (((void *) (ip1 + 1)) +
				   ip6_ext_header_len (ip1 + 1));
	  else
	    sr1 = (ip6_sr_header_t *) (ip1 + 1);

	  if (ip2->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	    sr2 =
	      (ip6_sr_header_t *) (((void *) (ip2 + 1)) +
				   ip6_ext_header_len (ip2 + 1));
	  else
	    sr2 = (ip6_sr_header_t *) (ip2 + 1);

	  if (ip3->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	    sr3 =
	      (ip6_sr_header_t *) (((void *) (ip3 + 1)) +
				   ip6_ext_header_len (ip3 + 1));
	  else
	    sr3 = (ip6_sr_header_t *) (ip3 + 1);

	  clib_memcpy_fast ((u8 *) ip0 - vec_len (sl0->rewrite_bsid),
			    (u8 *) ip0, (void *) sr0 - (void *) ip0);
	  clib_memcpy_fast ((u8 *) ip1 - vec_len (sl1->rewrite_bsid),
			    (u8 *) ip1, (void *) sr1 - (void *) ip1);
	  clib_memcpy_fast ((u8 *) ip2 - vec_len (sl2->rewrite_bsid),
			    (u8 *) ip2, (void *) sr2 - (void *) ip2);
	  clib_memcpy_fast ((u8 *) ip3 - vec_len (sl3->rewrite_bsid),
			    (u8 *) ip3, (void *) sr3 - (void *) ip3);

	  clib_memcpy_fast (((u8 *) sr0 - vec_len (sl0->rewrite_bsid)),
			    sl0->rewrite_bsid, vec_len (sl0->rewrite_bsid));
	  clib_memcpy_fast (((u8 *) sr1 - vec_len (sl1->rewrite_bsid)),
			    sl1->rewrite_bsid, vec_len (sl1->rewrite_bsid));
	  clib_memcpy_fast (((u8 *) sr2 - vec_len (sl2->rewrite_bsid)),
			    sl2->rewrite_bsid, vec_len (sl2->rewrite_bsid));
	  clib_memcpy_fast (((u8 *) sr3 - vec_len (sl3->rewrite_bsid)),
			    sl3->rewrite_bsid, vec_len (sl3->rewrite_bsid));

	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite_bsid));
	  vlib_buffer_advance (b1, -(word) vec_len (sl1->rewrite_bsid));
	  vlib_buffer_advance (b2, -(word) vec_len (sl2->rewrite_bsid));
	  vlib_buffer_advance (b3, -(word) vec_len (sl3->rewrite_bsid));

	  ip0 = ((void *) ip0) - vec_len (sl0->rewrite_bsid);
	  ip1 = ((void *) ip1) - vec_len (sl1->rewrite_bsid);
	  ip2 = ((void *) ip2) - vec_len (sl2->rewrite_bsid);
	  ip3 = ((void *) ip3) - vec_len (sl3->rewrite_bsid);

	  ip0->hop_limit -= 1;
	  ip1->hop_limit -= 1;
	  ip2->hop_limit -= 1;
	  ip3->hop_limit -= 1;

	  new_l0 =
	    clib_net_to_host_u16 (ip0->payload_length) +
	    vec_len (sl0->rewrite_bsid);
	  new_l1 =
	    clib_net_to_host_u16 (ip1->payload_length) +
	    vec_len (sl1->rewrite_bsid);
	  new_l2 =
	    clib_net_to_host_u16 (ip2->payload_length) +
	    vec_len (sl2->rewrite_bsid);
	  new_l3 =
	    clib_net_to_host_u16 (ip3->payload_length) +
	    vec_len (sl3->rewrite_bsid);

	  ip0->payload_length = clib_host_to_net_u16 (new_l0);
	  ip1->payload_length = clib_host_to_net_u16 (new_l1);
	  ip2->payload_length = clib_host_to_net_u16 (new_l2);
	  ip3->payload_length = clib_host_to_net_u16 (new_l3);

	  sr0 = ((void *) sr0) - vec_len (sl0->rewrite_bsid);
	  sr1 = ((void *) sr1) - vec_len (sl1->rewrite_bsid);
	  sr2 = ((void *) sr2) - vec_len (sl2->rewrite_bsid);
	  sr3 = ((void *) sr3) - vec_len (sl3->rewrite_bsid);

	  ip0->dst_address.as_u64[0] =
	    (sr0->segments + sr0->segments_left)->as_u64[0];
	  ip0->dst_address.as_u64[1] =
	    (sr0->segments + sr0->segments_left)->as_u64[1];
	  ip1->dst_address.as_u64[0] =
	    (sr1->segments + sr1->segments_left)->as_u64[0];
	  ip1->dst_address.as_u64[1] =
	    (sr1->segments + sr1->segments_left)->as_u64[1];
	  ip2->dst_address.as_u64[0] =
	    (sr2->segments + sr2->segments_left)->as_u64[0];
	  ip2->dst_address.as_u64[1] =
	    (sr2->segments + sr2->segments_left)->as_u64[1];
	  ip3->dst_address.as_u64[0] =
	    (sr3->segments + sr3->segments_left)->as_u64[0];
	  ip3->dst_address.as_u64[1] =
	    (sr3->segments + sr3->segments_left)->as_u64[1];

	  ip6_ext_header_t *ip_ext;
	  if (ip0 + 1 == (void *) sr0)
	    {
	      sr0->protocol = ip0->protocol;
	      ip0->protocol = IP_PROTOCOL_IPV6_ROUTE;
	    }
	  else
	    {
	      ip_ext = (void *) (ip0 + 1);
	      sr0->protocol = ip_ext->next_hdr;
	      ip_ext->next_hdr = IP_PROTOCOL_IPV6_ROUTE;
	    }

	  if (ip1 + 1 == (void *) sr1)
	    {
	      sr1->protocol = ip1->protocol;
	      ip1->protocol = IP_PROTOCOL_IPV6_ROUTE;
	    }
	  else
	    {
	      ip_ext = (void *) (ip2 + 1);
	      sr2->protocol = ip_ext->next_hdr;
	      ip_ext->next_hdr = IP_PROTOCOL_IPV6_ROUTE;
	    }

	  if (ip2 + 1 == (void *) sr2)
	    {
	      sr2->protocol = ip2->protocol;
	      ip2->protocol = IP_PROTOCOL_IPV6_ROUTE;
	    }
	  else
	    {
	      ip_ext = (void *) (ip2 + 1);
	      sr2->protocol = ip_ext->next_hdr;
	      ip_ext->next_hdr = IP_PROTOCOL_IPV6_ROUTE;
	    }

	  if (ip3 + 1 == (void *) sr3)
	    {
	      sr3->protocol = ip3->protocol;
	      ip3->protocol = IP_PROTOCOL_IPV6_ROUTE;
	    }
	  else
	    {
	      ip_ext = (void *) (ip3 + 1);
	      sr3->protocol = ip_ext->next_hdr;
	      ip_ext->next_hdr = IP_PROTOCOL_IPV6_ROUTE;
	    }

	  insert_pkts += 4;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b1, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip1->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip1->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b2->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b2, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip2->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip2->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b3->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b3, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip3->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip3->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}
	    }

	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      /* Single loop for potentially the last three packets */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  ip6_sr_header_t *sr0 = 0;
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
	  sl0 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b0)->ip.adj_index);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite_bsid));

	  ip0 = vlib_buffer_get_current (b0);

	  if (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	    sr0 =
	      (ip6_sr_header_t *) (((void *) (ip0 + 1)) +
				   ip6_ext_header_len (ip0 + 1));
	  else
	    sr0 = (ip6_sr_header_t *) (ip0 + 1);

	  clib_memcpy_fast ((u8 *) ip0 - vec_len (sl0->rewrite_bsid),
			    (u8 *) ip0, (void *) sr0 - (void *) ip0);
	  clib_memcpy_fast (((u8 *) sr0 - vec_len (sl0->rewrite_bsid)),
			    sl0->rewrite_bsid, vec_len (sl0->rewrite_bsid));

	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite_bsid));

	  ip0 = ((void *) ip0) - vec_len (sl0->rewrite_bsid);
	  ip0->hop_limit -= 1;
	  new_l0 =
	    clib_net_to_host_u16 (ip0->payload_length) +
	    vec_len (sl0->rewrite_bsid);
	  ip0->payload_length = clib_host_to_net_u16 (new_l0);

	  sr0 = ((void *) sr0) - vec_len (sl0->rewrite_bsid);

	  ip0->dst_address.as_u64[0] =
	    (sr0->segments + sr0->segments_left)->as_u64[0];
	  ip0->dst_address.as_u64[1] =
	    (sr0->segments + sr0->segments_left)->as_u64[1];

	  if (ip0 + 1 == (void *) sr0)
	    {
	      sr0->protocol = ip0->protocol;
	      ip0->protocol = IP_PROTOCOL_IPV6_ROUTE;
	    }
	  else
	    {
	      ip6_ext_header_t *ip_ext = (void *) (ip0 + 1);
	      sr0->protocol = ip_ext->next_hdr;
	      ip_ext->next_hdr = IP_PROTOCOL_IPV6_ROUTE;
	    }

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_policy_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				sizeof (tr->src.as_u8));
	      clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				sizeof (tr->dst.as_u8));
	    }

	  insert_pkts++;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, sr_policy_rewrite_insert_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_TOTAL,
			       insert_pkts);
  vlib_node_increment_counter (vm, sr_policy_rewrite_insert_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_BSID,
			       bsid_pkts);
  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_policy_rewrite_b_insert_node) = {
  .function = sr_policy_rewrite_b_insert,
  .name = "sr-pl-rewrite-b-insert",
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
/* *INDENT-ON* */

/**
 * @brief Function BSID encapsulation
 */
static_always_inline void
end_bsid_encaps_srh_processing (vlib_node_runtime_t * node,
				vlib_buffer_t * b0,
				ip6_header_t * ip0,
				ip6_sr_header_t * sr0, u32 * next0)
{
  ip6_address_t *new_dst0;

  if (PREDICT_FALSE (!sr0))
    goto error_bsid_encaps;

  if (PREDICT_TRUE (sr0->type == ROUTING_HEADER_TYPE_SR))
    {
      if (PREDICT_TRUE (sr0->segments_left != 0))
	{
	  sr0->segments_left -= 1;
	  new_dst0 = (ip6_address_t *) (sr0->segments);
	  new_dst0 += sr0->segments_left;
	  ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
	  ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];
	  return;
	}
    }

error_bsid_encaps:
  *next0 = SR_POLICY_REWRITE_NEXT_ERROR;
  b0->error = node->errors[SR_POLICY_REWRITE_ERROR_BSID_ZERO];
}

/**
 * @brief Graph node for applying a SR policy BSID - Encapsulation
 */
static uword
sr_policy_rewrite_b_encaps (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * from_frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  int encap_pkts = 0, bsid_pkts = 0;

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
	  ip6_header_t *ip0, *ip1, *ip2, *ip3;
	  ip6_header_t *ip0_encap, *ip1_encap, *ip2_encap, *ip3_encap;
	  ip6_sr_header_t *sr0, *sr1, *sr2, *sr3;
	  ip6_sr_sl_t *sl0, *sl1, *sl2, *sl3;

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

	  sl0 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b0)->ip.adj_index);
	  sl1 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b1)->ip.adj_index);
	  sl2 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b2)->ip.adj_index);
	  sl3 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b3)->ip.adj_index);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));
	  ASSERT (b1->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl1->rewrite));
	  ASSERT (b2->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl2->rewrite));
	  ASSERT (b3->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl3->rewrite));

	  ip0_encap = vlib_buffer_get_current (b0);
	  ip1_encap = vlib_buffer_get_current (b1);
	  ip2_encap = vlib_buffer_get_current (b2);
	  ip3_encap = vlib_buffer_get_current (b3);

	  sr0 =
	    ip6_ext_header_find (vm, b0, ip0_encap, IP_PROTOCOL_IPV6_ROUTE,
				 NULL);
	  sr1 =
	    ip6_ext_header_find (vm, b1, ip1_encap, IP_PROTOCOL_IPV6_ROUTE,
				 NULL);
	  sr2 =
	    ip6_ext_header_find (vm, b2, ip2_encap, IP_PROTOCOL_IPV6_ROUTE,
				 NULL);
	  sr3 =
	    ip6_ext_header_find (vm, b3, ip3_encap, IP_PROTOCOL_IPV6_ROUTE,
				 NULL);

	  end_bsid_encaps_srh_processing (node, b0, ip0_encap, sr0, &next0);
	  end_bsid_encaps_srh_processing (node, b1, ip1_encap, sr1, &next1);
	  end_bsid_encaps_srh_processing (node, b2, ip2_encap, sr2, &next2);
	  end_bsid_encaps_srh_processing (node, b3, ip3_encap, sr3, &next3);

	  clib_memcpy_fast (((u8 *) ip0_encap) - vec_len (sl0->rewrite),
			    sl0->rewrite, vec_len (sl0->rewrite));
	  clib_memcpy_fast (((u8 *) ip1_encap) - vec_len (sl1->rewrite),
			    sl1->rewrite, vec_len (sl1->rewrite));
	  clib_memcpy_fast (((u8 *) ip2_encap) - vec_len (sl2->rewrite),
			    sl2->rewrite, vec_len (sl2->rewrite));
	  clib_memcpy_fast (((u8 *) ip3_encap) - vec_len (sl3->rewrite),
			    sl3->rewrite, vec_len (sl3->rewrite));

	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));
	  vlib_buffer_advance (b1, -(word) vec_len (sl1->rewrite));
	  vlib_buffer_advance (b2, -(word) vec_len (sl2->rewrite));
	  vlib_buffer_advance (b3, -(word) vec_len (sl3->rewrite));

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  ip2 = vlib_buffer_get_current (b2);
	  ip3 = vlib_buffer_get_current (b3);

	  encaps_processing_v6 (node, b0, ip0, ip0_encap);
	  encaps_processing_v6 (node, b1, ip1, ip1_encap);
	  encaps_processing_v6 (node, b2, ip2, ip2_encap);
	  encaps_processing_v6 (node, b3, ip3, ip3_encap);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b1, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip1->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip1->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b2->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b2, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip2->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip2->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}

	      if (PREDICT_FALSE (b3->flags & VLIB_BUFFER_IS_TRACED))
		{
		  sr_policy_rewrite_trace_t *tr =
		    vlib_add_trace (vm, node, b3, sizeof (*tr));
		  clib_memcpy_fast (tr->src.as_u8, ip3->src_address.as_u8,
				    sizeof (tr->src.as_u8));
		  clib_memcpy_fast (tr->dst.as_u8, ip3->dst_address.as_u8,
				    sizeof (tr->dst.as_u8));
		}
	    }

	  encap_pkts += 4;
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      /* Single loop for potentially the last three packets */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0, *ip0_encap = 0;
	  ip6_sr_header_t *sr0;
	  ip6_sr_sl_t *sl0;
	  u32 next0 = SR_POLICY_REWRITE_NEXT_IP6_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);

	  sl0 =
	    pool_elt_at_index (sm->sid_lists, vnet_buffer (b0)->ip.adj_index);
	  ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >=
		  vec_len (sl0->rewrite));

	  ip0_encap = vlib_buffer_get_current (b0);
	  sr0 =
	    ip6_ext_header_find (vm, b0, ip0_encap, IP_PROTOCOL_IPV6_ROUTE,
				 NULL);
	  end_bsid_encaps_srh_processing (node, b0, ip0_encap, sr0, &next0);

	  clib_memcpy_fast (((u8 *) ip0_encap) - vec_len (sl0->rewrite),
			    sl0->rewrite, vec_len (sl0->rewrite));
	  vlib_buffer_advance (b0, -(word) vec_len (sl0->rewrite));

	  ip0 = vlib_buffer_get_current (b0);

	  encaps_processing_v6 (node, b0, ip0, ip0_encap);

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_policy_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				sizeof (tr->src.as_u8));
	      clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				sizeof (tr->dst.as_u8));
	    }

	  encap_pkts++;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, sr_policy_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_TOTAL,
			       encap_pkts);
  vlib_node_increment_counter (vm, sr_policy_rewrite_encaps_node.index,
			       SR_POLICY_REWRITE_ERROR_COUNTER_BSID,
			       bsid_pkts);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sr_policy_rewrite_b_encaps_node) = {
  .function = sr_policy_rewrite_b_encaps,
  .name = "sr-pl-rewrite-b-encaps",
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
/* *INDENT-ON* */

/*************************** SR Policy plugins ******************************/
/**
 * @brief SR Policy plugin registry
 */
int
sr_policy_register_function (vlib_main_t * vm, u8 * fn_name,
			     u8 * keyword_str, u8 * def_str,
			     u8 * params_str, u8 prefix_length,
			     dpo_type_t * dpo,
			     format_function_t * ls_format,
			     unformat_function_t * ls_unformat,
			     sr_p_plugin_callback_t * creation_fn,
			     sr_p_plugin_callback_t * removal_fn)
{
  ip6_sr_main_t *sm = &sr_main;
  uword *p;

  sr_policy_fn_registration_t *plugin;

  /* Did this function exist? If so update it */
  p = hash_get_mem (sm->policy_plugin_functions_by_key, fn_name);
  if (p)
    {
      plugin = pool_elt_at_index (sm->policy_plugin_functions, p[0]);
    }
  /* Else create a new one and set hash key */
  else
    {
      pool_get (sm->policy_plugin_functions, plugin);
      hash_set_mem (sm->policy_plugin_functions_by_key, fn_name,
		    plugin - sm->policy_plugin_functions);
    }

  clib_memset (plugin, 0, sizeof (*plugin));

  plugin->sr_policy_function_number = (plugin - sm->policy_plugin_functions);
  plugin->sr_policy_function_number += SR_BEHAVIOR_LAST;
  plugin->prefix_length = prefix_length;
  plugin->ls_format = ls_format;
  plugin->ls_unformat = ls_unformat;
  plugin->creation = creation_fn;
  plugin->removal = removal_fn;
  clib_memcpy (&plugin->dpo, dpo, sizeof (dpo_type_t));
  plugin->function_name = format (0, "%s%c", fn_name, 0);
  plugin->keyword_str = format (0, "%s%c", keyword_str, 0);
  plugin->def_str = format (0, "%s%c", def_str, 0);
  plugin->params_str = format (0, "%s%c", params_str, 0);

  return plugin->sr_policy_function_number;
}

/**
 * @brief CLI function to 'show' all available SR LocalSID behaviors
 */
static clib_error_t *
show_sr_policy_behaviors_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  ip6_sr_main_t *sm = &sr_main;
  sr_policy_fn_registration_t *plugin;
  sr_policy_fn_registration_t **plugins_vec = 0;
  int i;

  vlib_cli_output (vm, "SR Policy behaviors:\n-----------------------\n\n");

  /* *INDENT-OFF* */
  pool_foreach (plugin, sm->policy_plugin_functions,
    ({ vec_add1 (plugins_vec, plugin); }));
  /* *INDENT-ON* */

  vlib_cli_output (vm, "Plugin behaviors:\n");
  for (i = 0; i < vec_len (plugins_vec); i++)
    {
      plugin = plugins_vec[i];
      vlib_cli_output (vm, "\t%s\t-> %s.\n", plugin->keyword_str,
		       plugin->def_str);
      vlib_cli_output (vm, "\t\tParameters: '%s'\n", plugin->params_str);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_sr_policy_behaviors_command, static) = {
  .path = "show sr policy behaviors",
  .short_help = "show sr policy behaviors",
  .function = show_sr_policy_behaviors_command_fn,
};
/* *INDENT-ON* */

/*************************** SR Segment Lists DPOs ****************************/
static u8 *
format_sr_segment_list_dpo (u8 * s, va_list * args)
{
  ip6_sr_main_t *sm = &sr_main;
  ip6_address_t *addr;
  ip6_sr_sl_t *sl;

  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);
  s = format (s, "SR: Segment List index:[%d]", index);
  s = format (s, "\n\tSegments:");

  sl = pool_elt_at_index (sm->sid_lists, index);

  s = format (s, "< ");
  vec_foreach (addr, sl->segments)
  {
    s = format (s, "%U, ", format_ip6_address, addr);
  }
  s = format (s, "\b\b > - ");
  s = format (s, "Weight: %u", sl->weight);

  return s;
}

const static dpo_vft_t sr_policy_rewrite_vft = {
  .dv_lock = sr_dpo_lock,
  .dv_unlock = sr_dpo_unlock,
  .dv_format = format_sr_segment_list_dpo,
};

const static char *const sr_pr_encaps_ip6_nodes[] = {
  "sr-pl-rewrite-encaps",
  NULL,
};

const static char *const sr_pr_encaps_ip4_nodes[] = {
  "sr-pl-rewrite-encaps-v4",
  NULL,
};

const static char *const *const sr_pr_encaps_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = sr_pr_encaps_ip6_nodes,
  [DPO_PROTO_IP4] = sr_pr_encaps_ip4_nodes,
};

const static char *const sr_pr_insert_ip6_nodes[] = {
  "sr-pl-rewrite-insert",
  NULL,
};

const static char *const *const sr_pr_insert_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = sr_pr_insert_ip6_nodes,
};

const static char *const sr_pr_bsid_insert_ip6_nodes[] = {
  "sr-pl-rewrite-b-insert",
  NULL,
};

const static char *const *const sr_pr_bsid_insert_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = sr_pr_bsid_insert_ip6_nodes,
};

const static char *const sr_pr_bsid_encaps_ip6_nodes[] = {
  "sr-pl-rewrite-b-encaps",
  NULL,
};

const static char *const *const sr_pr_bsid_encaps_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = sr_pr_bsid_encaps_ip6_nodes,
};

/********************* SR Policy Rewrite initialization ***********************/
/**
 * @brief SR Policy Rewrite initialization
 */
clib_error_t *
sr_policy_rewrite_init (vlib_main_t * vm)
{
  ip6_sr_main_t *sm = &sr_main;

  /* Init memory for sr policy keys (bsid <-> ip6_address_t) */
  mhash_init (&sm->sr_policies_index_hash, sizeof (uword),
	      sizeof (ip6_address_t));

  /* Init SR VPO DPOs type */
  sr_pr_encaps_dpo_type =
    dpo_register_new_type (&sr_policy_rewrite_vft, sr_pr_encaps_nodes);

  sr_pr_insert_dpo_type =
    dpo_register_new_type (&sr_policy_rewrite_vft, sr_pr_insert_nodes);

  sr_pr_bsid_encaps_dpo_type =
    dpo_register_new_type (&sr_policy_rewrite_vft, sr_pr_bsid_encaps_nodes);

  sr_pr_bsid_insert_dpo_type =
    dpo_register_new_type (&sr_policy_rewrite_vft, sr_pr_bsid_insert_nodes);

  /* Register the L2 encaps node used in HW redirect */
  sm->l2_sr_policy_rewrite_index = sr_policy_rewrite_encaps_node.index;

  sm->fib_table_ip6 = (u32) ~ 0;
  sm->fib_table_ip4 = (u32) ~ 0;

  return 0;
}

VLIB_INIT_FUNCTION (sr_policy_rewrite_init);


/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
