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
/*
 *------------------------------------------------------------------
 * srv6_mdpol.c
 *------------------------------------------------------------------
 */

#include <vnet/fib/ip6_fib.h>
#include <vnet/srv6/sr.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <srv6-mdpol/srv6_mdpol.h>


/**
 * @brief Dynamically added SR SL DPO type
 */
static dpo_type_t srv6_mdpol_encaps_dpo_type;
static dpo_type_t srv6_mdpol_bsid_encaps_dpo_type;


/* ******************** Static helper functions ******************** */

/**
 * @brief Prepare IPv6 and SR headers for encapsulation
 */
static inline u8 *
prepare_encaps (ip6_address_t * src, ip6_address_t * sids)
{
  u8 *rewrite_str = NULL;

  u8 num_sids = vec_len (sids);

  u32 srh_var_len = num_sids * sizeof (ip6_address_t) +
    sizeof (ip6_srh_tlv_opaque_t);

  u32 srh_len = sizeof (ip6_sr_header_t) + srh_var_len;

  u32 rw_len = IPv6_DEFAULT_HEADER_LENGTH + srh_len;

  vec_validate (rewrite_str, rw_len - 1);

  /* Fill IPv6 header */
  ip6_header_t *iph = (ip6_header_t *) rewrite_str;
  iph->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0 | ((6 & 0xF) << 28));
  iph->src_address = *src;
  iph->dst_address = sids[0];
  iph->payload_length = srh_len;
  iph->protocol = IP_PROTOCOL_IPV6_ROUTE;
  iph->hop_limit = IPv6_DEFAULT_HOP_LIMIT;

  /* Fill fixed SR header */
  ip6_sr_header_t *srh = (ip6_sr_header_t *) (iph + 1);
  srh->protocol = IP_PROTOCOL_IPV6;
  srh->type = ROUTING_HEADER_TYPE_SR;
  srh->segments_left = num_sids - 1;
  srh->first_segment = num_sids - 1;
  srh->length = srh_var_len / 8;
  srh->flags = 0x00;
  srh->reserved = 0x00;

  /* Fill SR header segment list */
  ip6_address_t *this_address;
  ip6_address_t *addrp = srh->segments + srh->first_segment;
  vec_foreach (this_address, sids)
  {
    *addrp = *this_address;
    addrp--;
  }

  /* Fill SR header metadata */
  ip6_srh_tlv_opaque_t *md =
    (ip6_srh_tlv_opaque_t *) (srh->segments + num_sids);
  md->type = SRH_TLV_TYPE_OPAQUE;
  md->length = sizeof (ip6_srh_tlv_opaque_t) - 2;
  memset (md->value, 0, md->length);

  return rewrite_str;
}

/*
 * @brief Add SID-list to an SR policy
 */
static inline void
add_sid_list (ip6_sr_policy_t * sr_policy, ip6_address_t * src,
	      ip6_address_t * sids, u32 weight)
{
  ip6_sr_main_t *sm = &sr_main;

  ip6_sr_sl_t *sid_list;
  pool_get (sm->sid_lists, sid_list);
  memset (sid_list, 0, sizeof *sid_list);

  u8 sid_list_index = sid_list - sm->sid_lists;

  vec_add1 (sr_policy->segments_lists, sid_list_index);

  /* Fill SID-list */
  sid_list->weight =
    (weight != (u32) ~ 0 ? weight : SR_SEGMENT_LIST_WEIGHT_DEFAULT);
  sid_list->segments = vec_dup (sids);

  sid_list->rewrite = prepare_encaps (src, sids);
  sid_list->rewrite_bsid = sid_list->rewrite;

  /* Create DPO */
  dpo_reset (&sid_list->bsid_dpo);
  dpo_reset (&sid_list->ip6_dpo);
  dpo_reset (&sid_list->ip4_dpo);

  dpo_set (&sid_list->ip6_dpo, srv6_mdpol_encaps_dpo_type, DPO_PROTO_IP6,
	   sid_list_index);
  dpo_set (&sid_list->ip4_dpo, srv6_mdpol_encaps_dpo_type, DPO_PROTO_IP4,
	   sid_list_index);
  dpo_set (&sid_list->bsid_dpo, srv6_mdpol_bsid_encaps_dpo_type,
	   DPO_PROTO_IP6, sid_list_index);
}

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

      /* Update FIB entry's to point to the LB DPO in the main FIB and hidden
       * one */
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
  //path_vector = vec_new(load_balance_path_t,
  //    vec_len(sr_policy->segments_lists));
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


/* ******************** API functions ******************** */

/**
 * @brief Add SR policy with metadata copy
 */
int
srv6_mdpol_new (ip6_address_t * bsid, ip6_address_t * src,
		ip6_address_t * sids, u32 weight)
{
  ip6_sr_main_t *sm = &sr_main;

  /* Search for existing keys (BSID) */
  uword *p = mhash_get (&sm->sr_policies_index_hash, bsid);
  if (p)
    return -12;

  /* Search collision in FIB entries */
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 128,
    .fp_addr = {
		.ip6 = *bsid,
		}
  };

  /* Lookup the FIB index associated to the table selected */
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP6, 0);
  if (fib_index == ~0)
    return -13;

  /* Lookup whether there exists an entry for the BSID */
  fib_node_index_t fei = fib_table_lookup_exact_match (fib_index, &pfx);
  if (FIB_NODE_INDEX_INVALID != fei)
    return -12;			//There is an entry for such lookup

  /* Add an SR policy object */
  ip6_sr_policy_t *sr_policy;
  pool_get (sm->sr_policies, sr_policy);
  memset (sr_policy, 0, sizeof (*sr_policy));
  clib_memcpy (&sr_policy->bsid, bsid, sizeof (ip6_address_t));
  sr_policy->type = SR_POLICY_TYPE_DEFAULT;
  sr_policy->fib_table = 0;
  sr_policy->is_encap = 1;

  /* Copy the key */
  mhash_set (&sm->sr_policies_index_hash, bsid, sr_policy - sm->sr_policies,
	     NULL);

  /* Create a segment list and add the index to the SR policy */
  add_sid_list (sr_policy, src, sids, weight);

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
  update_lb (sr_policy);

  return 0;
}

/* Unused */
int
srv6_mdpol_del (ip6_address_t * bsid)
{
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_policy_t *sr_policy = 0;
  ip6_sr_sl_t *segment_list;
  u32 *sl_index;

  uword *p = mhash_get (&sm->sr_policies_index_hash, bsid);
  if (!p)
    return -1;

  sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);

  /* Remove BindingSID FIB entry */
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 128,
    .fp_addr = {
		.ip6 = sr_policy->bsid,
		}
    ,
  };

  fib_table_entry_special_remove (fib_table_find
				  (FIB_PROTOCOL_IP6, sr_policy->fib_table),
				  &pfx, FIB_SOURCE_SR);

  fib_table_entry_special_remove (sm->fib_table_ip6, &pfx, FIB_SOURCE_SR);

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

int
srv6_mdpol_add_list (ip6_address_t * bsid, ip6_address_t * src,
		     ip6_address_t * sids, u32 weight)
{
  ip6_sr_main_t *sm = &sr_main;

  uword *p = mhash_get (&sm->sr_policies_index_hash, bsid);
  if (!p)
    return -1;

  ip6_sr_policy_t *sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);

  /* Create the new SL */
  add_sid_list (sr_policy, src, sids, weight);

  /* Create a new LB DPO */
  update_lb (sr_policy);

  return 0;
}

/* Unused */
int
srv6_mdpol_rem_list (ip6_address_t * bsid, u32 sl_index)
{
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_policy_t *sr_policy = 0;

  uword *p = mhash_get (&sm->sr_policies_index_hash, bsid);
  if (!p)
    return -1;

  sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);

  /* Check that currently there are more than one SID list */
  if (vec_len (sr_policy->segments_lists) == 1)
    return -21;

  /* Check that the SR list does exist and is assigned to the sr policy */
  u32 *sl_index_iterate;
  vec_foreach (sl_index_iterate, sr_policy->segments_lists)
    if (*sl_index_iterate == sl_index)
    break;

  if (*sl_index_iterate != sl_index)
    return -22;

  /* Remove the lucky SR list that is being kicked out */
  ip6_sr_sl_t *segment_list = pool_elt_at_index (sm->sid_lists, sl_index);
  vec_free (segment_list->segments);
  vec_free (segment_list->rewrite);
  if (!sr_policy->is_encap)
    vec_free (segment_list->rewrite_bsid);
  pool_put_index (sm->sid_lists, sl_index);
  vec_del1 (sr_policy->segments_lists,
	    sl_index_iterate - sr_policy->segments_lists);

  /* Create a new LB DPO */
  update_lb (sr_policy);

  return 0;
}

/* Unused */
int
srv6_mdpol_mod_list (ip6_address_t * bsid, u32 sl_index, u32 weight)
{
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_policy_t *sr_policy;
  ip6_sr_sl_t *segment_list;
  u32 *sl_index_iterate;

  uword *p = mhash_get (&sm->sr_policies_index_hash, bsid);
  if (!p)
    return -1;

  sr_policy = pool_elt_at_index (sm->sr_policies, p[0]);

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
  update_lb (sr_policy);

  return 0;
}


/* ******************** CLI commands ******************** */

/**
 * @brief CLI for 'srv6 mdpol' command family
 */

typedef enum
{
  srv6_mdpol_operation_undefined = 0,
  srv6_mdpol_operation_del,
  srv6_mdpol_operation_add_sid_list,
  srv6_mdpol_operation_mod_sid_list,
  srv6_mdpol_operation_rem_sid_list
} srv6_mdpol_operation_t;

static clib_error_t *
srv6_mdpol_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  ip6_address_t *sids = 0, *this_seg;
  ip6_address_t bsid, src_addr, next_address;
  srv6_mdpol_operation_t op = 0;
  u8 src_set = 0;
  u32 sl_index = (u32) ~ 0;
  u32 weight = (u32) ~ 0;

  /* Parse CLI command */
  if (unformat (input, "del"))
    op = srv6_mdpol_operation_del;

  if (!unformat (input, "%U", unformat_ip6_address, &bsid))
    return clib_error_return (0, "Binding-SID missing.");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!op && unformat (input, "add"))
	op = srv6_mdpol_operation_add_sid_list;
      else if (!op && unformat (input, "mod sl index %d", &sl_index))
	op = srv6_mdpol_operation_mod_sid_list;
      else if (!op && unformat (input, "rem sl index %d", &sl_index))
	op = srv6_mdpol_operation_rem_sid_list;
      else if (unformat (input, "source %U", unformat_ip6_address, &src_addr))
	src_set = 1;
      else if (unformat (input, "weight %d", &weight));
      else
	if (unformat (input, "next %U", unformat_ip6_address, &next_address))
	{
	  vec_add2 (sids, this_seg, 1);
	  *this_seg = next_address;
	}
      else
	break;
    }

  int rv;
  switch (op)
    {
    case srv6_mdpol_operation_undefined:
      if (!src_set)
	return clib_error_return (0, "Source address missing.");
      if (vec_len (sids) == 0)
	return clib_error_return (0, "SID-list missing.");
      rv = srv6_mdpol_new (&bsid, &src_addr, sids, weight);
      vec_free (sids);
      break;
    case srv6_mdpol_operation_add_sid_list:
      if (!src_set)
	return clib_error_return (0, "Source address missing.");
      if (vec_len (sids) == 0)
	return clib_error_return (0, "SID-list missing.");
      rv = srv6_mdpol_add_list (&bsid, &src_addr, sids, weight);
      vec_free (sids);
      break;
    default:
      return clib_error_return (0,
				"Unsupported operation. Please use regular SR policy CLI.");
    }

  switch (rv)
    {
    case 0:
    case 1:
      break;
    case -12:
      return clib_error_return (0,
				"There is already a FIB entry for the Binding-SID address.\n"
				"The SR policy could not be created.");
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
VLIB_CLI_COMMAND (srv6_mdpol_command, static) = {
  .path = "srv6 mdpol",
  .short_help = "srv6 mdpol 2001::1 (add) next A:: next B:: (weight 1)",
  .long_help =
    "Add metadata-enabled SR policies and SID-lists.\n"
    "See 'sr policy' for details on generic SR policy manipulations.\n",
  .function = srv6_mdpol_command_fn,
};
/* *INDENT-ON* */


/* ******************** VPP DPOs ******************** */

static u8 *
format_srv6_mdpol_dpo (u8 * s, va_list * args)
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

const static dpo_vft_t srv6_mdpol_vft = {
  .dv_lock = sr_dpo_lock,
  .dv_unlock = sr_dpo_unlock,
  .dv_format = format_srv6_mdpol_dpo,
};

const static char *const srv6_mdpol_encaps_ip6_nodes[] = {
  "srv6-mdpol-rewrite-encaps",
  NULL,
};

const static char *const srv6_mdpol_encaps_ip4_nodes[] = {
  "srv6-mdpol-rewrite-encaps-v4",
  NULL,
};

const static char *const *const srv6_mdpol_encaps_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_mdpol_encaps_ip6_nodes,
  [DPO_PROTO_IP4] = srv6_mdpol_encaps_ip4_nodes,
};

const static char *const srv6_mdpol_bsid_encaps_ip6_nodes[] = {
  "srv6-mdpol-rewrite-b-encaps",
  NULL,
};

const static char *const *const srv6_mdpol_bsid_encaps_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_mdpol_bsid_encaps_ip6_nodes,
};

clib_error_t *
srv6_mdpol_init (vlib_main_t * vm)
{
  /* Init SR VPO DPOs type */
  srv6_mdpol_encaps_dpo_type =
    dpo_register_new_type (&srv6_mdpol_vft, srv6_mdpol_encaps_nodes);

  srv6_mdpol_bsid_encaps_dpo_type =
    dpo_register_new_type (&srv6_mdpol_vft, srv6_mdpol_bsid_encaps_nodes);

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (srv6_mdpol_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Metadata-enable SRv6 policies",
};
/* *INDENT-ON* */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
