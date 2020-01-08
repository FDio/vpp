/*
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

#include <acl2/acl.h>
#include <acl2/public_inlines.h>

#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/l2/l2_input.h>

static vlib_log_class_t acl_logger;

u8 *
format_acl_action (u8 * s, va_list * a)
{
  acl_action_t action = va_arg (*a, int);	// acl_action_t;

  switch (action)
    {
#define _(a,b)                                  \
      case ACL_ACTION_##a:                      \
        return (format(s, "%s", b));
      foreach_acl_action
#undef _
    }
  return (format (s, "unknown"));
}

uword
unformat_acl_action (unformat_input_t * input, va_list * args)
{
  acl_action_t *aa = va_arg (*args, acl_action_t *);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0)
	;
#define _(a,b)                                  \
      else if (unformat (input, b)) {           \
        *aa = ACL_ACTION_##a;                   \
        return (1);                             \
      }
      foreach_acl_action
#undef _
	else
	return (1);
    }

  return (0);

}

acl_list_t *
acl_list_get (index_t acl_index)
{
  acl_main_t *am = &acl_main;

  if (pool_is_free_index (am->acls, acl_index))
    return (NULL);

  return (pool_elt_at_index (am->acls, acl_index));
}

void *
acl_mk_heap (void)
{
  acl_main_t *am = &acl_main;

  if (0 == am->acl_mheap)
    {
      if (0 == am->acl_mheap_size)
	{
	  vlib_thread_main_t *tm = vlib_get_thread_main ();
	  u64 per_worker_slack = 1000000LL;
	  u64 per_worker_size =
	    per_worker_slack +
	    ((u64) am->fa_conn_table_max_entries) * sizeof (fa_session_t);
	  u64 per_worker_size_with_slack = per_worker_slack + per_worker_size;
	  u64 main_slack = 2000000LL;
	  u64 bihash_size = (u64) am->fa_conn_table_hash_memory_size;

	  am->acl_mheap_size =
	    per_worker_size_with_slack * tm->n_vlib_mains + bihash_size +
	    main_slack;
	}
      u64 max_possible = ((uword) ~ 0);
      if (am->acl_mheap_size > max_possible)
	{
	  clib_warning ("ACL heap size requested: %lld, max possible %lld",
			am->acl_mheap_size, max_possible);
	}

      am->acl_mheap = mheap_alloc_with_lock (0 /* use VM */ ,
					     am->acl_mheap_size,
					     1 /* locked */ );
      if (0 == am->acl_mheap)
	{
	  clib_error
	    ("ACL plugin failed to allocate main heap of %U bytes, abort",
	     format_memory_size, am->acl_mheap_size);
	}
    }
  return (am->acl_mheap);
}

int
acl_stats_intf_counters_enable_disable (int enable)
{
  acl_main_t *am = &acl_main;

  am->interface_acl_counters_enabled = enable;

  return (0);;
}

static void
increment_policy_epoch (acl_main_t * am, u32 sw_if_index, int is_input)
{

  /* u32 **ppolicy_epoch_by_swi = */
  /*   is_input ? &am->input_policy_epoch_by_sw_if_index : */
  /*   &am->output_policy_epoch_by_sw_if_index; */
  /* vec_validate (*ppolicy_epoch_by_swi, sw_if_index); */

  /* u32 *p_epoch = vec_elt_at_index ((*ppolicy_epoch_by_swi), sw_if_index); */
  /* *p_epoch = */
  /*   ((1 + *p_epoch) & FA_POLICY_EPOCH_MASK) + */
  /*   (is_input * FA_POLICY_EPOCH_IS_INPUT); */
}

static void
try_increment_acl_policy_epoch (acl_main_t * am, u32 acl_num, int is_input)
{
  /* u32 ***p_swi_vec_by_acl = is_input ? &am->input_sw_if_index_vec_by_acl */
  /*   : &am->output_sw_if_index_vec_by_acl; */
  /* if (acl_num < vec_len (*p_swi_vec_by_acl)) */
  /*   { */
  /*     u32 *p_swi; */
  /*     vec_foreach (p_swi, (*p_swi_vec_by_acl)[acl_num]) */
  /*     { */
  /*       increment_policy_epoch (am, *p_swi, is_input); */
  /*     } */

  /*   } */
}

static void
policy_notify_acl_change (acl_main_t * am, u32 acl_num)
{
  try_increment_acl_policy_epoch (am, acl_num, 0);
  try_increment_acl_policy_epoch (am, acl_num, 1);
}


static void
validate_and_reset_acl_counters (acl_main_t * am, u32 acl_index)
{
  int i;
  /* counters are set as vectors [acl#] pointing to vectors of [acl rule] */
  acl_plugin_counter_lock (am);

  int old_len = vec_len (am->combined_acl_counters);

  vec_validate (am->combined_acl_counters, acl_index);

  for (i = old_len; i < vec_len (am->combined_acl_counters); i++)
    {
      am->combined_acl_counters[i].name = 0;
      /* filled in once only */
      am->combined_acl_counters[i].stat_segment_name = (void *)
	format (0, "/acl2/%d/matches%c", i, 0);
      i32 rule_count = vec_len (am->acls[i].rules);
      /* Validate one extra so we always have at least one counter for an ACL */
      vlib_validate_combined_counter (&am->combined_acl_counters[i],
				      rule_count);
      vlib_clear_combined_counters (&am->combined_acl_counters[i]);
    }

  /* (re)validate for the actual ACL that is getting added/updated */
  i32 rule_count = vec_len (am->acls[acl_index].rules);
  /* Validate one extra so we always have at least one counter for an ACL */
  vlib_validate_combined_counter (&am->combined_acl_counters[acl_index],
				  rule_count);
  vlib_clear_combined_counters (&am->combined_acl_counters[acl_index]);
  acl_plugin_counter_unlock (am);
}

acl_itf_t *
acl_itf_find (u32 sw_if_index, vlib_dir_t dir)
{
  acl_main_t *am = &acl_main;

  if (vec_len (am->interfaces[dir]) <= sw_if_index)
    return (NULL);

  if (INDEX_INVALID == am->interfaces[dir][sw_if_index])
    return (NULL);

  return (pool_elt_at_index (am->itf_pool, am->interfaces[dir][sw_if_index]));
}

static index_t
acl_itf_get_index (const acl_itf_t * aitf)
{
  return (aitf - acl_main.itf_pool);
}

static acl_itf_layer_t
acl_itf_get_layer (u32 sw_if_index)
{
  l2_input_config_t *config;

  config = l2input_intf_config (sw_if_index);

  if (config->bridge || config->xconnect)
    return (ACL_ITF_LAYER_L2);

  return (ACL_ITF_LAYER_L3);
}

acl_itf_t *
acl_itf_create (u32 sw_if_index, vlib_dir_t dir)
{
  acl_main_t *am = &acl_main;

  vec_validate_init_empty (am->interfaces[dir], sw_if_index, INDEX_INVALID);

  if (INDEX_INVALID == am->interfaces[dir][sw_if_index])
    {
      ip_address_family_t af;
      acl_itf_t *aitf;

      pool_get_aligned_zero (am->itf_pool, aitf, CLIB_CACHE_LINE_BYTES);

      aitf->dir = dir;
      aitf->sw_if_index = sw_if_index;
      aitf->layer = acl_itf_get_layer (sw_if_index);

      FOR_EACH_IP_ADDRESS_FAMILY (af)
      {
	aitf->match_set[af] = INDEX_INVALID;
	aitf->match_apps[af] = MATCH_SET_APP_INVALID;
      }

      am->interfaces[dir][sw_if_index] = aitf - am->itf_pool;

      return (aitf);
    }
  return (pool_elt_at_index (am->itf_pool, am->interfaces[dir][sw_if_index]));
}

static u32
acl_itf_acl_find (const acl_itf_t * aitf, u32 acl_index)
{
  u32 index;

  vec_foreach_index (index, aitf->acls)
  {
    if (aitf->acls[index].acl_index == acl_index)
      return (index);
  }

  return (~0);
}

static void
acl_match_list_compile (index_t match_set,
			index_t acl_index,
			u32 prio,
			ip_address_family_t af, acl_match_list_t * aml)
{
  acl_list_t *acl;
  acl_rule_t *ar;
  u8 *name;

  acl = acl_list_get (acl_index);
  name = format (NULL, "acl-%d-%U", acl_index, format_ip_address_family, af);

  match_list_init (&aml->aml_list, name, 0);

  vec_foreach (ar, acl->rules)
  {
    if (match_rule_get_af (&ar->rule) == af)
      {
	vec_add1 (aml->aml_actions, ar->action);
	match_list_push_back (&aml->aml_list, &ar->rule);
      }
  }

  if (match_list_length (&aml->aml_list))
    aml->aml_hdl = match_set_list_add (match_set,
				       &aml->aml_list,
				       prio, aml->aml_actions);
  else
    aml->aml_hdl = MATCH_HANDLE_INVALID;

  vec_free (name);
}

static void
acl_match_list_free (index_t match_set, acl_match_list_t * aml)
{
  if (MATCH_HANDLE_INVALID != aml->aml_hdl)
    match_set_list_del (match_set, &aml->aml_hdl);
  vec_free (aml->aml_actions);
  match_list_free (&aml->aml_list);
}

static void
acl_itf_acl_add (acl_itf_t * aitf, u32 acl_index)
{
  ip_address_family_t af;
  acl_list_hdl_t *ah;

  if (~0 != acl_itf_acl_find (aitf, acl_index))
    return;

  vec_add2 (aitf->acls, ah, 1);

  ah->acl_index = acl_index;

  FOR_EACH_IP_ADDRESS_FAMILY (af)
    acl_match_list_compile (aitf->match_set[af], acl_index,
			    vec_len (aitf->acls), af, &ah->acl_match[af]);

  /* add this interface to the list that this ACL uses */
  if (~0 == vec_search (acl_main.interfaces_by_acl[acl_index],
			aitf->sw_if_index))
    vec_add1 (acl_main.interfaces_by_acl[acl_index],
	      acl_itf_get_index (aitf));
}

static void
acl_itf_acl_remove (acl_itf_t * aitf, u32 acl_index)
{
  ip_address_family_t af;
  acl_list_hdl_t *ah;
  u32 index;

  index = acl_itf_acl_find (aitf, acl_index);

  if (~0 == index)
    return;

  ah = &aitf->acls[index];

  FOR_EACH_IP_ADDRESS_FAMILY (af)
    acl_match_list_free (aitf->match_set[af], &ah->acl_match[af]);

  // delete preserving the order
  vec_delete (aitf->acls, 1, index);

  /* also delete this interface from the list that this ACL uses */
  index =
    vec_search (acl_main.interfaces_by_acl[acl_index], aitf->sw_if_index);
  vec_del1 (acl_main.interfaces_by_acl[acl_index], index);
}

static void
acl_itf_update (index_t itf_index, index_t acl_index)
{
  acl_itf_t *aitf;
  u32 pos;

  aitf = acl_itf_get_i (itf_index);

  pos = acl_itf_acl_find (aitf, acl_index);

  ASSERT (~0 != pos);

  // FIXME
  ASSERT (0);
}

static bool
acl_itf_in_use (const acl_itf_t * aitf)
{
  return (vec_len (aitf->whitelist) || vec_len (aitf->acls));
}

static void
acl_itf_destroy (acl_itf_t * aitf)
{
  acl_main.interfaces[aitf->dir][aitf->sw_if_index] = INDEX_INVALID;
  vec_free (aitf->acls);
  vec_free (aitf->whitelist);
  pool_put (acl_main.itf_pool, aitf);
}

static void
acl_updated (index_t acl_index)
{
  index_t *itf_index;

  /* walk all the interface on which the list is applied and poke them */
  vec_foreach (itf_index, acl_main.interfaces_by_acl[acl_index])
    acl_itf_update (*itf_index, acl_index);
}

int
acl_list_update (index_t * aip, acl_rule_t * rules, u8 * tag)
{
  acl_main_t *am = &acl_main;
  acl_list_t *acl;
  index_t ai;

  ai = *aip;

  if (INDEX_INVALID == ai)
    {
      pool_get_zero (am->acls, acl);
      ai = acl - am->acls;
    }
  else
    {
      if (pool_is_free_index (am->acls, ai))
	return (VNET_API_ERROR_NO_SUCH_ENTRY);

      acl = pool_elt_at_index (am->acls, ai);

      vec_free (acl->rules);
    }

  acl->rules = rules;
  memcpy (acl->tag, tag, sizeof (acl->tag));

  if (am->reclassify_sessions)
    /* a change in an ACLs if they are applied may mean a new policy epoch */
    policy_notify_acl_change (am, ai);

  validate_and_reset_acl_counters (am, ai);
  vec_validate (acl_main.interfaces_by_acl, ai);

  /* notify the interfaces about the ACL changes */
  acl_updated (ai);

  acl_log_info ("update: %U", format_acl, ai, ACL_FORMAT_BRIEF);

  *aip = ai;

  return (0);
}

static int
acl_is_used_by (acl_main_t * am, u32 acl_index)
{
  if (vec_len (am->interfaces_by_acl) < acl_index)
    return (0);

  if (0 != vec_len (am->interfaces_by_acl[acl_index]))
    {
      acl_itf_t *aitf;

      aitf = acl_itf_get_i (am->interfaces_by_acl[acl_index][0]);

      if (VLIB_RX == aitf->dir)
	return (VNET_API_ERROR_ACL_IN_USE_INBOUND);
      else
	return (VNET_API_ERROR_ACL_IN_USE_OUTBOUND);
    }

  return (0);
}

int
acl_list_del (index_t acl_index)
{
  acl_main_t *am = &acl_main;
  acl_list_t *a;
  int rv;

  a = acl_list_get (acl_index);

  if (NULL == a)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  rv = acl_is_used_by (am, acl_index);

  if (rv)
    return rv;

  acl_log_info ("delete: %U", format_acl, acl_index, ACL_FORMAT_BRIEF);

  if (a->rules)
    vec_free (a->rules);
  pool_put (am->acls, a);

  return 0;
}

static void
acl_clear_sessions (acl_main_t * am, u32 sw_if_index)
{
  /* void *oldheap = clib_mem_set_heap (am->vlib_main->heap_base); */
  /* vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index, */
  /*                         ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX, */
  /*                         sw_if_index); */
  /* clib_mem_set_heap (oldheap); */
}

/* *INDENT-OFF* */
const static char * acl_feat_arc[ACL_ITF_N_LAYERS][N_AF][VLIB_N_RX_TX] = {
  [ACL_ITF_LAYER_L2] = {
    [AF_IP4] = {
      [VLIB_RX] = "l2-input-ip4",
      [VLIB_TX] = "l2-output-ip4",
    },
    [AF_IP6] = {
      [VLIB_RX] = "l2-input-ip6",
      [VLIB_TX] = "l2-output-ip6",
    },
  },
  [ACL_ITF_LAYER_L3] = {
    [AF_IP4] = {
      [VLIB_RX] = "ip4-unicast",
      [VLIB_TX] = "ip4-output",
    },
    [AF_IP6] = {
      [VLIB_RX] = "ip6-unicast",
      [VLIB_TX] = "ip6-output",
    },
  },
};
const static char * acl_feat[ACL_ITF_N_LAYERS][N_AF][VLIB_N_RX_TX] = {
  [ACL_ITF_LAYER_L2] = {
    [AF_IP4] = {
      [VLIB_RX] = "acl2-plugin-in-ip4-l2",
      [VLIB_TX] = "acl2-plugin-out-ip4-l2",
    },
    [AF_IP6] = {
      [VLIB_RX] = "acl2-plugin-in-ip6-l2",
      [VLIB_TX] = "acl2-plugin-out-ip6-l2",
    },
  },
  [ACL_ITF_LAYER_L3] = {
    [AF_IP4] = {
      [VLIB_RX] = "acl2-plugin-in-ip4",
      [VLIB_TX] = "acl2-plugin-out-ip4",
    },
    [AF_IP6] = {
      [VLIB_RX] = "acl2-plugin-in-ip6",
      [VLIB_TX] = "acl2-plugin-out-ip6",
    },
  },
};
/* *INDENT-ON* */

static int
acl_interface_acl_enable_disable (acl_itf_t * aitf, int enable)
{
  int rv = 0;

  if (aitf->acl_feat_enabled != enable)
    {
      acl_fa_enable_disable (aitf->sw_if_index, enable);

      if (ACL_ITF_LAYER_L2 == aitf->layer)
	{
	  rv |= vnet_l2_feature_enable_disable
	    (acl_feat_arc[aitf->layer][AF_IP4][aitf->dir],
	     acl_feat[aitf->layer][AF_IP4][aitf->dir],
	     aitf->sw_if_index, enable, 0, 0);
	  rv |= vnet_l2_feature_enable_disable
	    (acl_feat_arc[aitf->layer][AF_IP6][aitf->dir],
	     acl_feat[aitf->layer][AF_IP6][aitf->dir],
	     aitf->sw_if_index, enable, 0, 0);
	}
      else
	{
	  rv |= vnet_feature_enable_disable
	    (acl_feat_arc[aitf->layer][AF_IP4][aitf->dir],
	     acl_feat[aitf->layer][AF_IP4][aitf->dir],
	     aitf->sw_if_index, enable, 0, 0);
	  rv |= vnet_feature_enable_disable
	    (acl_feat_arc[aitf->layer][AF_IP6][aitf->dir],
	     acl_feat[aitf->layer][AF_IP6][aitf->dir],
	     aitf->sw_if_index, enable, 0, 0);
	}
    }
  aitf->acl_feat_enabled = enable;

  return (rv);
}

static int
acl_interface_whitelist_enable_disable (acl_itf_t * aitf, int enable)
{
  int rv = 0;

  if (aitf->whitelist_feat_enabled != enable)
    rv = vnet_l2_feature_enable_disable ("l2-input-nonip",
					 "acl2-plugin-in-nonip-l2",
					 aitf->sw_if_index, enable, 0, 0);

  aitf->whitelist_feat_enabled = enable;

  return rv;
}

int
acl_set_etype_whitelists (acl_main_t * am,
			  u32 sw_if_index, u16 * whiltelists[VLIB_N_RX_TX])
{
  vlib_dir_t dir;
  acl_itf_t *aitf;

  FOREACH_VLIB_DIR (dir)
  {
    vec_validate_init_empty (am->interfaces[dir], sw_if_index, INDEX_INVALID);

    aitf = acl_itf_create (sw_if_index, dir);

    vec_free (aitf->whitelist);

    aitf->whitelist = whiltelists[dir];

    /*
     * enable or disable the feature on the interface
     */
    acl_interface_whitelist_enable_disable (aitf, aitf->whitelist != NULL);

    if (!acl_itf_in_use (aitf))
      acl_itf_destroy (aitf);
  }
  return 0;
}

int
acl_interface_set_inout_acl_list (acl_main_t * am, u32 sw_if_index,
				  vlib_dir_t dir, u32 * vec_acl_list_index,
				  int *may_clear_sessions)
{
  u32 *pacln;
  uword *seen_acl_bitmap = 0;
  uword *old_seen_acl_bitmap = 0;
  uword *change_acl_bitmap = 0;
  acl_list_hdl_t *ahdl;
  u8 *match_name;
  int acln;
  int rv = 0;
  acl_itf_t *aitf;
  ip_address_family_t af;

  acl_log_debug ("set-acl: sw_if_index %d %U acl_vec: [%U]",
		 sw_if_index, format_vlib_rx_tx, dir,
		 format_vec32, vec_acl_list_index, "%d");

  aitf = acl_itf_find (sw_if_index, dir);

  if (NULL == aitf && 0 == vec_len (vec_acl_list_index))
    return (0);

  vec_foreach (pacln, vec_acl_list_index)
  {
    if (acl_is_not_defined (am, *pacln))
      {
	/* ACL is not defined. Can not apply */
	acl_log_warn ("ERROR: ACL %d not defined", *pacln);
	rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	goto done;
      }
    if (clib_bitmap_get (seen_acl_bitmap, *pacln))
      {
	/* ACL being applied twice within the list. error. */
	acl_log_warn ("ERROR: ACL %d being applied twice", *pacln);
	rv = VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
	goto done;
      }
    seen_acl_bitmap = clib_bitmap_set (seen_acl_bitmap, *pacln, 1);
  }

  aitf = acl_itf_create (sw_if_index, dir);

  FOR_EACH_IP_ADDRESS_FAMILY (af)
  {
    if (INDEX_INVALID == aitf->match_set[af])
      {
	match_name = format (NULL, "acl-%U-%U-%U",
			     format_ip_address_family, af,
			     format_vlib_rx_tx, dir,
			     format_vnet_sw_if_index_name, vnet_get_main (),
			     sw_if_index);

	aitf->match_set[af] =
	  match_set_create_and_lock (match_name,
				     MATCH_TYPE_MASK_N_TUPLE,
				     MATCH_BOTH,
				     ip_address_family_to_ether_type (af),
				     NULL);
	// acl_mk_heap ()); FIXME
	vec_free (match_name);
      }
  }

  // clib_bitmap_validate (old_seen_acl_bitmap, vec_len (aitf->acls));

  vec_foreach (ahdl, aitf->acls)
  {
    old_seen_acl_bitmap = clib_bitmap_set (old_seen_acl_bitmap,
					   ahdl->acl_index, 1);
  }
  change_acl_bitmap = clib_bitmap_dup_xor (old_seen_acl_bitmap,
					   seen_acl_bitmap);

  acl_log_debug ("bitmaps: old seen %U new seen %U changed %U",
		 format_bitmap_hex, old_seen_acl_bitmap, format_bitmap_hex,
		 seen_acl_bitmap, format_bitmap_hex, change_acl_bitmap);

  /* *INDENT-OFF* */
  clib_bitmap_foreach(acln, change_acl_bitmap,
  ({
    if (clib_bitmap_get(old_seen_acl_bitmap, acln))
      /* ACL is being removed. */
      acl_itf_acl_remove(aitf, acln);
    else
      /* ACL is being added. */
      acl_itf_acl_add(aitf, acln);
  }));
  /* *INDENT-ON* */

  if (am->reclassify_sessions)
    {
      /* re-applying ACLs means a new policy epoch */
      increment_policy_epoch (am, sw_if_index, dir == VLIB_RX);
    }
  else
    {
      /* if no commonalities between the ACL# -
       * then we should definitely clear the sessions */
      if (may_clear_sessions && *may_clear_sessions
	  && !clib_bitmap_is_zero (change_acl_bitmap))
	{
	  acl_clear_sessions (am, sw_if_index);
	  *may_clear_sessions = 0;
	}
    }

  /* ensure ACL processing is enabled/disabled as needed */
  if (vec_len (aitf->acls))
    {
      /* [re]apply the match-set */
      FOR_EACH_IP_ADDRESS_FAMILY (af)
	match_set_unapply (aitf->match_set[af], &aitf->match_apps[af]);

      FOR_EACH_IP_ADDRESS_FAMILY (af)
	match_set_apply (aitf->match_set[af],
			 MATCH_SEMANTIC_FIRST,
			 (ACL_ITF_LAYER_L2 == aitf->layer ?
			  VNET_LINK_ETHERNET :
			  ip_address_family_to_link_type (af)),
			 match_set_get_itf_tag_flags (aitf->sw_if_index),
			 &aitf->match_apps[af]);


      /* we have ACLs bound to this interface */
      acl_interface_acl_enable_disable (aitf, 1);
    }
  else
    {
      /* no more ACLs bound to this interface */
      acl_interface_acl_enable_disable (aitf, 0);

      FOR_EACH_IP_ADDRESS_FAMILY (af)
      {
	match_set_unapply (aitf->match_set[af], &aitf->match_apps[af]);
	match_set_unlock (&aitf->match_set[af]);
      }
      if (!acl_itf_in_use (aitf))
	acl_itf_destroy (aitf);
    }

done:
  clib_bitmap_free (change_acl_bitmap);
  clib_bitmap_free (seen_acl_bitmap);
  clib_bitmap_free (old_seen_acl_bitmap);
  return rv;
}

static clib_error_t *
acl_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  acl_main_t *am = &acl_main;

  if (0 == is_add)
    {
      int may_clear_sessions = 1;
      vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
				 ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX,
				 sw_if_index);
      /* also unapply any ACLs in case the users did not do so. */
      acl_interface_set_inout_acl_list (am, sw_if_index, VLIB_RX,
					NULL, &may_clear_sessions);
      acl_interface_set_inout_acl_list (am, sw_if_index, VLIB_TX,
					NULL, &may_clear_sessions);
    }
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (acl_sw_interface_add_del);

void
acl_plugin_acl_set_validate_heap (acl_main_t * am, int on)
{
/*   clib_mem_set_heap (acl_set_heap (am)); */
/* #if USE_DLMALLOC == 0 */
/*   mheap_t *h = mheap_header (am->acl_mheap); */
/*   if (on) */
/*     { */
/*       h->flags |= MHEAP_FLAG_VALIDATE; */
/*       h->flags &= ~MHEAP_FLAG_SMALL_OBJECT_CACHE; */
/*       mheap_validate (h); */
/*     } */
/*   else */
/*     { */
/*       h->flags &= ~MHEAP_FLAG_VALIDATE; */
/*       h->flags |= MHEAP_FLAG_SMALL_OBJECT_CACHE; */
/*     } */
/* #endif */
}

void
acl_plugin_acl_set_trace_heap (acl_main_t * am, int on)
{
/*   clib_mem_set_heap (acl_set_heap (am)); */
/* #if USE_DLMALLOC == 0 */
/*   mheap_t *h = mheap_header (am->acl_mheap); */
/*   if (on) */
/*     { */
/*       h->flags |= MHEAP_FLAG_TRACE; */
/*     } */
/*   else */
/*     { */
/*       h->flags &= ~MHEAP_FLAG_TRACE; */
/*     } */
/* #endif */
}

u8 *
format_acl_rule (u8 * s, va_list * args)
{
  acl_rule_t *rule = va_arg (*args, acl_rule_t *);

  s = format (s, "%U => %U",
	      format_acl_action, rule->action,
	      format_match_rule, &rule->rule, 4);

  return (s);
}

u8 *
format_acl (u8 * s, va_list * args)
{
  vlib_combined_counter_main_t *cm;
  acl_format_flag_t flags;
  vlib_counter_t counts;
  index_t acl_index;
  acl_rule_t *rule;
  acl_list_t *acl;
  index_t *ai;

  acl_index = va_arg (*args, index_t);
  flags = va_arg (*args, acl_format_flag_t);
  acl = acl_list_get (acl_index);
  cm = &acl_main.combined_acl_counters[acl_index];

  s = format (s, "[%d]: %s:", acl_index, acl->tag);

  vec_foreach (rule, acl->rules)
  {
    s = format (s, "\n  %U", format_acl_rule, rule);
    vlib_get_combined_counter (cm, rule - acl->rules, &counts);
    s = format (s, "\n   counts:[%lld, %lld]", counts.packets, counts.bytes);
  }

  if (flags & ACL_FORMAT_DETAIL)
    {
      s = format (s, "\n applied-on:");
      vec_foreach (ai, acl_main.interfaces_by_acl[acl_index])
	s = format (s, "\n  [%U]", format_acl_itf, *ai, ACL_FORMAT_BRIEF);
    }

  return (s);
}

static u8 *
format_acl_actions (u8 * s, va_list * args)
{
  acl_action_t *actions = va_arg (*args, acl_action_t *);
  u32 index = va_arg (*args, u32);

  s = format (s, "%U", format_acl_action, actions[index]);

  return (s);
}

static u8 *
format_acl_match_list_hdl (u8 * s, va_list * args)
{
  acl_match_list_t *aml = va_arg (*args, acl_match_list_t *);

  s = format (s, " hdl:%d", aml->aml_hdl);
  s = format (s, "\n        %U",
	      format_match_list_w_action, &aml->aml_list, 10,
	      format_acl_actions, aml->aml_actions);

  return (s);
}

u8 *
format_acl_list_hdl (u8 * s, va_list * args)
{
  acl_list_hdl_t *ah = va_arg (*args, acl_list_hdl_t *);
  ip_address_family_t af;

  s = format (s, "acl:%d", ah->acl_index);
  FOR_EACH_IP_ADDRESS_FAMILY (af)
    s = format (s, "\n      %U:%U",
		format_ip_address_family, af,
		format_acl_match_list_hdl, &ah->acl_match[af]);

  return (s);
}

u8 *
format_acl_itf_layer (u8 * s, va_list * args)
{
  acl_itf_layer_t layer = va_arg (*args, acl_itf_layer_t);

  switch (layer)
    {
    case ACL_ITF_LAYER_L2:
      return (format (s, "l2"));
    case ACL_ITF_LAYER_L3:
      return (format (s, "l3"));
    }
  return (format (s, "unknown"));
}

u8 *
format_acl_itf (u8 * s, va_list * args)
{
  acl_format_flag_t flags;
  acl_list_hdl_t *ah;
  acl_itf_t *aitf;
  index_t ai;

  ai = va_arg (*args, index_t);
  flags = va_arg (*args, acl_format_flag_t);
  aitf = pool_elt_at_index (acl_main.itf_pool, ai);

  s = format (s, "[%d]: %U, %U", ai,
	      format_vnet_sw_if_index_name, vnet_get_main (),
	      aitf->sw_if_index, format_vlib_rx_tx, aitf->dir);

  if (flags & ACL_FORMAT_DETAIL)
    {
      u16 *wl;

      s = format (s, "\n  feats:[acl:%d, whitelist:%d]",
		  aitf->acl_feat_enabled, aitf->whitelist_feat_enabled);
      s = format (s, "\n  layer:%U", format_acl_itf_layer, aitf->layer);
      s = format (s, "\n  acls:");
      vec_foreach (ah, aitf->acls)
	s = format (s, "\n    %U", format_acl_list_hdl, ah);

      s = format (s, "\n  whiltelist:[");
      vec_foreach (wl, aitf->whitelist) s = format (s, "%d", *wl);
      s = format (s, "]");

      s = format (s, "\n  match-set:[%d, %d]",
		  aitf->match_set[AF_IP4], aitf->match_set[AF_IP6]);
    }
  if (flags & ACL_FORMAT_VERBOSE)
    {
      ip_address_family_t af;

      FOR_EACH_IP_ADDRESS_FAMILY (af)
	s = format (s, "\n  %U", format_match_set, aitf->match_set[af]);
    }
  return (s);
}

u8 *
format_acl_sw_if_index (u8 * s, va_list * args)
{
  acl_format_flag_t flags;
  u32 sw_if_index;
  vlib_dir_t dir;

  sw_if_index = va_arg (*args, u32);
  flags = va_arg (*args, acl_format_flag_t);

  FOREACH_VLIB_DIR (dir)
  {
    acl_itf_t *aitf;

    aitf = acl_itf_find (sw_if_index, dir);

    if (aitf)
      {
	s = format (s, "%U", format_acl_itf, acl_itf_get_index (aitf), flags);
      }
  }
  return (s);
}

static void
acl_set_timeout_sec (acl_timeout_e timeout_type, u32 value)
{
  acl_main_t *am = &acl_main;
  clib_time_t *ct = &am->vlib_main->clib_time;

  if (timeout_type < ACL_N_TIMEOUTS)
    {
      am->session_timeout_sec[timeout_type] = value;
    }
  else
    {
      clib_warning ("Unknown timeout type %d", timeout_type);
      return;
    }
  am->session_timeout[timeout_type] =
    (u64) (((f64) value) / ct->seconds_per_clock);
}

static void
acl_set_session_max_entries (u32 value)
{
  acl_main_t *am = &acl_main;
  am->fa_conn_table_max_entries = value;
}

static int
acl_set_skip_ipv6_eh (u32 eh, u32 value)
{
  acl_main_t *am = &acl_main;

  if ((eh < 256) && (value < 2))
    {
      am->fa_ipv6_known_eh_bitmap =
	clib_bitmap_set (am->fa_ipv6_known_eh_bitmap, eh, value);
      return 1;
    }
  else
    return 0;
}

static clib_error_t *
acl_set_aclplugin_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  u32 timeout = 0;
  u32 val = 0;
  u32 eh_val = 0;
  uword memory_size = 0;
  acl_main_t *am = &acl_main;

  if (unformat (input, "skip-ipv6-extension-header %u %u", &eh_val, &val))
    {
      if (!acl_set_skip_ipv6_eh (eh_val, val))
	{
	  error = clib_error_return (0, "expecting eh=0..255, value=0..1");
	}
      goto done;
    }
  if (unformat (input, "use-hash-acl-matching %u", &val))
    {
      am->use_hash_acl_matching = (val != 0);
      goto done;
    }
  if (unformat (input, "l4-match-nonfirst-fragment %u", &val))
    {
      am->l4_match_nonfirst_fragment = (val != 0);
      goto done;
    }
  if (unformat (input, "reclassify-sessions %u", &val))
    {
      am->reclassify_sessions = (val != 0);
      goto done;
    }
  if (unformat (input, "event-trace"))
    {
      if (!unformat (input, "%u", &val))
	{
	  error = clib_error_return (0,
				     "expecting trace level, got `%U`",
				     format_unformat_error, input);
	  goto done;
	}
      else
	{
	  am->trace_acl = val;
	  goto done;
	}
    }
  if (unformat (input, "heap"))
    {
      if (unformat (input, "main"))
	{
	  if (unformat (input, "validate %u", &val))
	    acl_plugin_acl_set_validate_heap (am, val);
	  else if (unformat (input, "trace %u", &val))
	    acl_plugin_acl_set_trace_heap (am, val);
	  goto done;
	}
      else if (unformat (input, "hash"))
	{
	  /* if (unformat (input, "validate %u", &val)) */
	  /*   acl_plugin_hash_acl_set_validate_heap (val); */
	  /* else if (unformat (input, "trace %u", &val)) */
	  /*   acl_plugin_hash_acl_set_trace_heap (val); */
	  goto done;
	}
      goto done;
    }
  if (unformat (input, "session"))
    {
      if (unformat (input, "table"))
	{
	  /* The commands here are for tuning/testing. No user-serviceable parts inside */
	  if (unformat (input, "max-entries"))
	    {
	      if (!unformat (input, "%u", &val))
		{
		  error = clib_error_return (0,
					     "expecting maximum number of entries, got `%U`",
					     format_unformat_error, input);
		  goto done;
		}
	      else
		{
		  acl_set_session_max_entries (val);
		  goto done;
		}
	    }
	  if (unformat (input, "hash-table-buckets"))
	    {
	      if (!unformat (input, "%u", &val))
		{
		  error = clib_error_return (0,
					     "expecting maximum number of hash table buckets, got `%U`",
					     format_unformat_error, input);
		  goto done;
		}
	      else
		{
		  am->fa_conn_table_hash_num_buckets = val;
		  goto done;
		}
	    }
	  if (unformat (input, "hash-table-memory"))
	    {
	      if (!unformat (input, "%U", unformat_memory_size, &memory_size))
		{
		  error = clib_error_return (0,
					     "expecting maximum amount of hash table memory, got `%U`",
					     format_unformat_error, input);
		  goto done;
		}
	      else
		{
		  am->fa_conn_table_hash_memory_size = memory_size;
		  goto done;
		}
	    }
	  if (unformat (input, "event-trace"))
	    {
	      if (!unformat (input, "%u", &val))
		{
		  error = clib_error_return (0,
					     "expecting trace level, got `%U`",
					     format_unformat_error, input);
		  goto done;
		}
	      else
		{
		  am->trace_sessions = val;
		  goto done;
		}
	    }
	  goto done;
	}
      if (unformat (input, "timeout"))
	{
	  if (unformat (input, "udp"))
	    {
	      if (unformat (input, "idle"))
		{
		  if (!unformat (input, "%u", &timeout))
		    {
		      error = clib_error_return (0,
						 "expecting timeout value in seconds, got `%U`",
						 format_unformat_error,
						 input);
		      goto done;
		    }
		  else
		    {
		      acl_set_timeout_sec (ACL_TIMEOUT_UDP_IDLE, timeout);
		      goto done;
		    }
		}
	    }
	  if (unformat (input, "tcp"))
	    {
	      if (unformat (input, "idle"))
		{
		  if (!unformat (input, "%u", &timeout))
		    {
		      error = clib_error_return (0,
						 "expecting timeout value in seconds, got `%U`",
						 format_unformat_error,
						 input);
		      goto done;
		    }
		  else
		    {
		      acl_set_timeout_sec (ACL_TIMEOUT_TCP_IDLE, timeout);
		      goto done;
		    }
		}
	      if (unformat (input, "transient"))
		{
		  if (!unformat (input, "%u", &timeout))
		    {
		      error = clib_error_return (0,
						 "expecting timeout value in seconds, got `%U`",
						 format_unformat_error,
						 input);
		      goto done;
		    }
		  else
		    {
		      acl_set_timeout_sec (ACL_TIMEOUT_TCP_TRANSIENT,
					   timeout);
		      goto done;
		    }
		}
	    }
	  goto done;
	}
    }
done:
  return error;
}

static clib_error_t *
acl_show_aclplugin_macip_acl_fn (vlib_main_t * vm,
				 unformat_input_t *
				 input, vlib_cli_command_t * cmd)
{
  macip_acl_main_t *mm = &macip_acl_main;
  u32 acl_index = ~0;

  (void) unformat (input, "index %u", &acl_index);

  if (~0 != acl_index)
    vlib_cli_output (vm, "%U", format_macip_acl, acl_index);
  else
    {
      u32 ai;
      /* *INDENT-OFF* */
      pool_foreach_index(ai, mm->macip_acls,
      ({
        vlib_cli_output (vm, "%U", format_macip_acl, ai);
      }));
      /* *INDENT-ON* */
    }

  return (NULL);
}

static clib_error_t *
acl_show_aclplugin_macip_interface_fn (vlib_main_t * vm,
				       unformat_input_t *
				       input, vlib_cli_command_t * cmd)
{
  macip_acl_main_t *mm = &macip_acl_main;
  int i;

  for (i = 0; i < vec_len (mm->macip_acl_by_sw_if_index); i++)
    {
      vlib_cli_output (vm, "  sw_if_index %d: %d\n", i,
		       vec_elt (mm->macip_acl_by_sw_if_index, i));
    }
  return (NULL);
}

static clib_error_t *
acl_show_aclplugin_acl_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  acl_main_t *am = &acl_main;
  u32 acl_index = ~0;

  (void) unformat (input, "index %u", &acl_index);

  if (~0 == acl_index)
    {
      /* *INDENT-OFF* */
      pool_foreach_index(acl_index, am->acls,
      ({
        vlib_cli_output (vm, "%U", format_acl, acl_index, ACL_FORMAT_BRIEF);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if (!pool_is_free_index (am->acls, acl_index))
	vlib_cli_output (vm, "%U", format_acl, acl_index, ACL_FORMAT_DETAIL);
      else
	vlib_cli_output (vm, "invalid ACL index:%d", acl_index);
    }

  return (NULL);
}

static clib_error_t *
acl_show_aclplugin_decode_5tuple_fn (vlib_main_t * vm,
				     unformat_input_t *
				     input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  u64 five_tuple[6] = { 0, 0, 0, 0, 0, 0 };

  if (unformat
      (input, "%llx %llx %llx %llx %llx %llx", &five_tuple[0],
       &five_tuple[1], &five_tuple[2], &five_tuple[3], &five_tuple[4],
       &five_tuple[5]))
    vlib_cli_output (vm, "5-tuple structure decode: %U\n\n",
		     format_acl_plugin_5tuple, five_tuple);
  else
    error = clib_error_return (0, "expecting 6 hex integers");
  return error;
}

static clib_error_t *
acl_show_aclplugin_interface_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  acl_main_t *am = &acl_main;
  acl_format_flag_t flags;
  u32 sw_if_index = ~0;
  vlib_dir_t dir;

  (void) unformat (input, "sw_if_index %u", &sw_if_index);
  (void) unformat (input, "%U", unformat_vnet_sw_interface,
		   vnet_get_main (), &sw_if_index);
  int detail = unformat (input, "detail");

  flags = ACL_FORMAT_DETAIL;
  if (detail)
    flags |= ACL_FORMAT_VERBOSE;

  if (~0 != sw_if_index)
    vlib_cli_output (vm, "%U", format_acl_sw_if_index, sw_if_index, flags);
  else
    {
      dir = ((vec_len (am->interfaces[VLIB_RX]) >
	      vec_len (am->interfaces[VLIB_TX])) ? VLIB_RX : VLIB_TX);

      vec_foreach_index (sw_if_index, am->interfaces[dir])
	vlib_cli_output (vm, "%U", format_acl_sw_if_index, sw_if_index,
			 flags);
    }

  return (NULL);
}

static clib_error_t *
acl_show_aclplugin_memory_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;

  vlib_cli_output (vm, "ACL plugin main heap statistics:\n");
  if (am->acl_mheap)
    {
      vlib_cli_output (vm, " %U\n", format_mheap, am->acl_mheap, 1);
    }
  else
    {
      vlib_cli_output (vm, " Not initialized\n");
    }
  vlib_cli_output (vm, "ACL hash lookup support heap statistics:\n");
  if (am->hash_lookup_mheap)
    {
      vlib_cli_output (vm, " %U\n", format_mheap, am->hash_lookup_mheap, 1);
    }
  else
    {
      vlib_cli_output (vm, " Not initialized\n");
    }
  return error;
}

static void
acl_plugin_show_sessions (acl_main_t * am,
			  u32 show_session_thread_id,
			  u32 show_session_session_index)
{
  vlib_main_t *vm = am->vlib_main;
  u16 wk;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;
  vnet_sw_interface_t *swif;
  u64 now = clib_cpu_time_now ();
  u64 clocks_per_second = am->vlib_main->clib_time.clocks_per_second;

  {
    u64 n_adds = am->fa_session_total_adds;
    u64 n_dels = am->fa_session_total_dels;
    u64 n_deact = am->fa_session_total_deactivations;
    vlib_cli_output (vm, "Sessions total: add %lu - del %lu = %lu", n_adds,
		     n_dels, n_adds - n_dels);
    vlib_cli_output (vm, "Sessions active: add %lu - deact %lu = %lu",
		     n_adds, n_deact, n_adds - n_deact);
    vlib_cli_output (vm, "Sessions being purged: deact %lu - del %lu = %lu",
		     n_deact, n_dels, n_deact - n_dels);
  }
  vlib_cli_output (vm, "now: %lu clocks per second: %lu", now,
		   clocks_per_second);
  vlib_cli_output (vm, "\n\nPer-thread data:");
  for (wk = 0; wk < vec_len (am->per_worker_data); wk++)
    {
      acl_fa_per_worker_data_t *pw = &am->per_worker_data[wk];
      vlib_cli_output (vm, "Thread #%d:", wk);
      if (show_session_thread_id == wk
	  && show_session_session_index < pool_len (pw->fa_sessions_pool))
	{
	  vlib_cli_output (vm, "  session index %u:",
			   show_session_session_index);
	  fa_session_t *sess =
	    pw->fa_sessions_pool + show_session_session_index;
	  u64 *m = (u64 *) & sess->info;
	  vlib_cli_output (vm,
			   "    info: %016llx %016llx %016llx %016llx %016llx %016llx",
			   m[0], m[1], m[2], m[3], m[4], m[5]);
	  vlib_cli_output (vm, "    sw_if_index: %u", sess->sw_if_index);
	  vlib_cli_output (vm, "    tcp_flags_seen: %x",
			   sess->tcp_flags_seen.as_u16);
	  vlib_cli_output (vm, "    last active time: %lu",
			   sess->last_active_time);
	  vlib_cli_output (vm, "    thread index: %u", sess->thread_index);
	  vlib_cli_output (vm, "    link enqueue time: %lu",
			   sess->link_enqueue_time);
	  vlib_cli_output (vm, "    link next index: %u",
			   sess->link_next_idx);
	  vlib_cli_output (vm, "    link prev index: %u",
			   sess->link_prev_idx);
	  vlib_cli_output (vm, "    link list id: %u", sess->link_list_id);
	}
      vlib_cli_output (vm, "  connection add/del stats:", wk);
      /* *INDENT-OFF* */
      pool_foreach (swif, im->sw_interfaces,
        ({
          u32 sw_if_index = swif->sw_if_index;
          u64 n_adds =
            (sw_if_index < vec_len (pw->fa_session_adds_by_sw_if_index) ?
             pw->fa_session_adds_by_sw_if_index[sw_if_index] :
             0);
          u64 n_dels =
            (sw_if_index < vec_len (pw->fa_session_dels_by_sw_if_index) ?
             pw->fa_session_dels_by_sw_if_index[sw_if_index] :
             0);
          u64 n_epoch_changes =
            (sw_if_index < vec_len (pw->fa_session_epoch_change_by_sw_if_index) ?
             pw->fa_session_epoch_change_by_sw_if_index[sw_if_index] :
             0);
          vlib_cli_output (vm,
                           "    sw_if_index %d: add %lu - del %lu = %lu; epoch chg: %lu",
                           sw_if_index,
                           n_adds,
                           n_dels,
                           n_adds -
                           n_dels,
                           n_epoch_changes);
        }));
      /* *INDENT-ON* */

      vlib_cli_output (vm, "  connection timeout type lists:", wk);
      u8 tt = 0;
      for (tt = 0; tt < ACL_N_TIMEOUTS; tt++)
	{
	  u32 head_session_index = pw->fa_conn_list_head[tt];
	  vlib_cli_output (vm, "  fa_conn_list_head[%d]: %d", tt,
			   head_session_index);
	  if (~0 != head_session_index)
	    {
	      fa_session_t *sess = pw->fa_sessions_pool + head_session_index;
	      vlib_cli_output (vm, "    last active time: %lu",
			       sess->last_active_time);
	      vlib_cli_output (vm, "    link enqueue time: %lu",
			       sess->link_enqueue_time);
	    }
	}

      vlib_cli_output (vm, "  Next expiry time: %lu", pw->next_expiry_time);
      vlib_cli_output (vm, "  Requeue until time: %lu",
		       pw->requeue_until_time);
      vlib_cli_output (vm, "  Current time wait interval: %lu",
		       pw->current_time_wait_interval);
      vlib_cli_output (vm, "  Count of deleted sessions: %lu",
		       pw->cnt_deleted_sessions);
      vlib_cli_output (vm, "  Delete already deleted: %lu",
		       pw->cnt_already_deleted_sessions);
      vlib_cli_output (vm, "  Session timers restarted: %lu",
		       pw->cnt_session_timer_restarted);
      vlib_cli_output (vm, "  Swipe until this time: %lu",
		       pw->swipe_end_time);
      vlib_cli_output (vm, "  sw_if_index serviced bitmap: %U",
		       format_bitmap_hex, pw->serviced_sw_if_index_bitmap);
      vlib_cli_output (vm, "  pending clear intfc bitmap : %U",
		       format_bitmap_hex,
		       pw->pending_clear_sw_if_index_bitmap);
      vlib_cli_output (vm, "  clear in progress: %u", pw->clear_in_process);
      vlib_cli_output (vm, "  interrupt is pending: %d",
		       pw->interrupt_is_pending);
      vlib_cli_output (vm, "  interrupt is needed: %d",
		       pw->interrupt_is_needed);
      vlib_cli_output (vm, "  interrupt is unwanted: %d",
		       pw->interrupt_is_unwanted);
      vlib_cli_output (vm, "  interrupt generation: %d",
		       pw->interrupt_generation);
      vlib_cli_output (vm, "  received session change requests: %d",
		       pw->rcvd_session_change_requests);
      vlib_cli_output (vm, "  sent session change requests: %d",
		       pw->sent_session_change_requests);
    }
  vlib_cli_output (vm, "\n\nConn cleaner thread counters:");
#define _(cnt, desc) vlib_cli_output(vm, "             %20lu: %s", am->cnt, desc);
  foreach_fa_cleaner_counter;
#undef _
  vlib_cli_output (vm, "Interrupt generation: %d",
		   am->fa_interrupt_generation);
  vlib_cli_output (vm,
		   "Sessions per interval: min %lu max %lu increment: %f ms current: %f ms",
		   am->fa_min_deleted_sessions_per_interval,
		   am->fa_max_deleted_sessions_per_interval,
		   am->fa_cleaner_wait_time_increment * 1000.0,
		   ((f64) am->fa_current_cleaner_timer_wait_interval) *
		   1000.0 / (f64) vm->clib_time.clocks_per_second);
  vlib_cli_output (vm, "Reclassify sessions: %d", am->reclassify_sessions);
}

static clib_error_t *
acl_show_aclplugin_sessions_fn (vlib_main_t * vm,
				unformat_input_t *
				input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;

  u32 show_bihash_verbose = 0;
  u32 show_session_thread_id = ~0;
  u32 show_session_session_index = ~0;
  (void) unformat (input, "thread %u index %u", &show_session_thread_id,
		   &show_session_session_index);
  (void) unformat (input, "verbose %u", &show_bihash_verbose);

  acl_plugin_show_sessions (am, show_session_thread_id,
			    show_session_session_index);
  show_fa_sessions_hash (vm, show_bihash_verbose);
  return error;
}

static clib_error_t *
acl_show_aclplugin_tables_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;

  u32 acl_index = ~0;
  u32 lc_index = ~0;
  int show_acl_hash_info = 0;
  int show_applied_info = 0;
  int show_mask_type = 0;
  int show_bihash = 0;
  u32 show_bihash_verbose = 0;

  if (unformat (input, "acl"))
    {
      show_acl_hash_info = 1;
      /* mask-type is handy to see as well right there */
      show_mask_type = 1;
      unformat (input, "index %u", &acl_index);
    }
  else if (unformat (input, "applied"))
    {
      show_applied_info = 1;
      unformat (input, "lc_index %u", &lc_index);
    }
  else if (unformat (input, "mask"))
    {
      show_mask_type = 1;
    }
  else if (unformat (input, "hash"))
    {
      show_bihash = 1;
      unformat (input, "verbose %u", &show_bihash_verbose);
    }

  if (!
      (show_mask_type || show_acl_hash_info || show_applied_info
       || show_bihash))
    {
      /* if no qualifiers specified, show all */
      show_mask_type = 1;
      show_acl_hash_info = 1;
      show_applied_info = 1;
      show_bihash = 1;
    }
  vlib_cli_output (vm, "Stats counters enabled for interface ACLs: %d",
		   acl_main.interface_acl_counters_enabled);
  /* if (show_mask_type) */
  /*   acl_plugin_show_tables_mask_type (); */
  /* if (show_acl_hash_info) */
  /*   acl_plugin_show_tables_acl_hash_info (acl_index); */
  /* if (show_applied_info) */
  /*   acl_plugin_show_tables_applied_info (lc_index); */
  /* if (show_bihash) */
  /*   acl_plugin_show_tables_bihash (show_bihash_verbose); */

  return error;
}

static clib_error_t *
acl_clear_aclplugin_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;
  vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
			     ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX, ~0);
  return error;
}

static clib_error_t *
acl_add_del_cmd (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  acl_rule_t *rules, *rule;
  acl_action_t aa;
  index_t ai;
  u8 *tag;
  int rv;

  const char *valid_chars = "a-zA-Z0-9_";

  ai = INDEX_INVALID;
  rules = rule = NULL;
  tag = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tag %U", unformat_token, valid_chars, &tag))
	;
      else if (unformat (line_input, "action %U", unformat_acl_action, &aa))
	{
	  vec_add2 (rules, rule, 1);
	  rule->action = aa;
	}
      else
	if (unformat
	    (line_input, "rule %U", unformat_match_rule, &rule->rule))
	;
      else if (unformat (line_input, "index %d", &ai))
	;
      else
	break;
    }

  rv = acl_list_update (&ai, rules, tag);

  if (rv)
    return (clib_error_return (0, "failed"));

  vlib_cli_output (vm, "acl-index: %d", ai);

  unformat_free (line_input);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (aclplugin_set_command, static) = {
    .path = "set acl2-plugin",
    .short_help = "set acl2-plugin session timeout {{udp idle}|tcp {idle|transient}} <seconds>",
    .function = acl_set_aclplugin_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_acl_command, static) = {
    .path = "show acl2-plugin acl",
    .short_help = "show acl2-plugin acl [index N]",
    .function = acl_show_aclplugin_acl_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_decode_5tuple_command, static) = {
    .path = "show acl2-plugin decode 5tuple",
    .short_help = "show acl2-plugin decode 5tuple XXXX XXXX XXXX XXXX XXXX XXXX",
    .function = acl_show_aclplugin_decode_5tuple_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_interface_command, static) = {
    .path = "show acl2-plugin interface",
    .short_help = "show acl2-plugin interface [sw_if_index N] [acl]",
    .function = acl_show_aclplugin_interface_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_memory_command, static) = {
    .path = "show acl2-plugin memory",
    .short_help = "show acl2-plugin memory",
    .function = acl_show_aclplugin_memory_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_sessions_command, static) = {
    .path = "show acl2-plugin sessions",
    .short_help = "show acl2-plugin sessions",
    .function = acl_show_aclplugin_sessions_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_tables_command, static) = {
    .path = "show acl2-plugin tables",
    .short_help = "show acl2-plugin tables [ acl [index N] | applied [ lc_index N ] | mask | hash [verbose N] ]",
    .function = acl_show_aclplugin_tables_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_macip_acl_command, static) = {
    .path = "show acl2-plugin macip acl",
    .short_help = "show acl2-plugin macip acl [index N]",
    .function = acl_show_aclplugin_macip_acl_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_macip_interface_command, static) = {
    .path = "show acl2-plugin macip interface",
    .short_help = "show acl2-plugin macip interface",
    .function = acl_show_aclplugin_macip_interface_fn,
};

VLIB_CLI_COMMAND (aclplugin_clear_command, static) = {
    .path = "clear acl2-plugin sessions",
    .short_help = "clear acl2-plugin sessions",
    .function = acl_clear_aclplugin_fn,
};

VLIB_CLI_COMMAND (aclplugin_add_del_command, static) = {
    .path = "acl2",
    .short_help = "acl2 [del] action <a> rule <r> ...",
    .function = acl_add_del_cmd,
};
/* *INDENT-ON* */

static clib_error_t *
acl_plugin_config (vlib_main_t * vm, unformat_input_t * input)
{
  acl_main_t *am = &acl_main;
  u32 conn_table_hash_buckets;
  uword conn_table_hash_memory_size;
  u32 conn_table_max_entries;
  uword main_heap_size;
  uword hash_heap_size;
  u32 reclassify_sessions;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "connection hash buckets %d", &conn_table_hash_buckets))
	am->fa_conn_table_hash_num_buckets = conn_table_hash_buckets;
      else
	if (unformat
	    (input, "connection hash memory %U", unformat_memory_size,
	     &conn_table_hash_memory_size))
	am->fa_conn_table_hash_memory_size = conn_table_hash_memory_size;
      else if (unformat (input, "connection count max %d",
			 &conn_table_max_entries))
	am->fa_conn_table_max_entries = conn_table_max_entries;
      else
	if (unformat
	    (input, "main heap size %U", unformat_memory_size,
	     &main_heap_size))
	am->acl_mheap_size = main_heap_size;
      else
	if (unformat
	    (input, "hash lookup heap size %U", unformat_memory_size,
	     &hash_heap_size))
	am->hash_lookup_mheap_size = hash_heap_size;
      // FIXME
      /* else if (unformat (input, "hash lookup hash buckets %d", */
      /*                 &hash_lookup_hash_buckets)) */
      /*   am->hash_lookup_hash_buckets = hash_lookup_hash_buckets; */
      /* else */
      /*   if (unformat */
      /*       (input, "hash lookup hash memory %U", unformat_memory_size, */
      /*        &hash_lookup_hash_memory)) */
      /*   am->hash_lookup_hash_memory = hash_lookup_hash_memory; */
      /* else if (unformat (input, "use tuple merge %d", &use_tuple_merge)) */
      /*   am->use_tuple_merge = use_tuple_merge; */
      /* else */
      /*   if (unformat */
      /*       (input, "tuple merge split threshold %d", */
      /*        &tuple_merge_split_threshold)) */
      /*   am->tuple_merge_split_threshold = tuple_merge_split_threshold; */

      else if (unformat (input, "reclassify sessions %d",
			 &reclassify_sessions))
	am->reclassify_sessions = reclassify_sessions;

      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (acl_plugin_config, "acl2-plugin");

static clib_error_t *
acl_init (vlib_main_t * vm)
{
  acl_main_t *am;

  am = &acl_main;
  am->vlib_main = vm;
  am->vnet_main = vnet_get_main ();

  acl_logger = vlib_log_register_class ("acl", "acl");

  am->acl_mheap_size = 0;	/* auto size when initializing */
  am->hash_lookup_mheap_size = ACL_PLUGIN_HASH_LOOKUP_HEAP_SIZE;


  am->session_timeout_sec[ACL_TIMEOUT_TCP_TRANSIENT] =
    TCP_SESSION_TRANSIENT_TIMEOUT_SEC;
  am->session_timeout_sec[ACL_TIMEOUT_TCP_IDLE] =
    TCP_SESSION_IDLE_TIMEOUT_SEC;
  am->session_timeout_sec[ACL_TIMEOUT_UDP_IDLE] =
    UDP_SESSION_IDLE_TIMEOUT_SEC;

  am->fa_conn_table_hash_num_buckets =
    ACL_FA_CONN_TABLE_DEFAULT_HASH_NUM_BUCKETS;
  am->fa_conn_table_hash_memory_size =
    ACL_FA_CONN_TABLE_DEFAULT_HASH_MEMORY_SIZE;
  am->fa_conn_table_max_entries = ACL_FA_CONN_TABLE_DEFAULT_MAX_ENTRIES;
  am->reclassify_sessions = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  am->fa_min_deleted_sessions_per_interval =
    ACL_FA_DEFAULT_MIN_DELETED_SESSIONS_PER_INTERVAL;
  am->fa_max_deleted_sessions_per_interval =
    ACL_FA_DEFAULT_MAX_DELETED_SESSIONS_PER_INTERVAL;
  am->fa_cleaner_wait_time_increment =
    ACL_FA_DEFAULT_CLEANER_WAIT_TIME_INCREMENT;

  vec_validate (am->per_worker_data, tm->n_vlib_mains - 1);
  {
    u16 wk;
    for (wk = 0; wk < vec_len (am->per_worker_data); wk++)
      {
	acl_fa_per_worker_data_t *pw = &am->per_worker_data[wk];
	if (tm->n_vlib_mains > 1)
	  {
	    clib_spinlock_init (&pw->pending_session_change_request_lock);
	  }
	vec_validate (pw->expired,
		      ACL_N_TIMEOUTS *
		      am->fa_max_deleted_sessions_per_interval);
	_vec_len (pw->expired) = 0;
	vec_validate_init_empty (pw->fa_conn_list_head, ACL_N_TIMEOUTS - 1,
				 FA_SESSION_BOGUS_INDEX);
	vec_validate_init_empty (pw->fa_conn_list_tail, ACL_N_TIMEOUTS - 1,
				 FA_SESSION_BOGUS_INDEX);
	vec_validate_init_empty (pw->fa_conn_list_head_expiry_time,
				 ACL_N_TIMEOUTS - 1, ~0ULL);
      }
  }

  am->fa_cleaner_cnt_delete_by_sw_index = 0;
  am->fa_cleaner_cnt_delete_by_sw_index_ok = 0;
  am->fa_cleaner_cnt_unknown_event = 0;
  am->fa_cleaner_cnt_timer_restarted = 0;
  am->fa_cleaner_cnt_wait_with_timeout = 0;


#define _(N, v, s) am->fa_ipv6_known_eh_bitmap = clib_bitmap_set(am->fa_ipv6_known_eh_bitmap, v, 1);
  foreach_acl_eh
#undef _
    am->l4_match_nonfirst_fragment = 1;

  /* use the new fancy hash-based matching */
  am->use_hash_acl_matching = 1;

  am->acl_counter_lock = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
						 CLIB_CACHE_LINE_BYTES);
  am->acl_counter_lock[0] = 0;	/* should be no need */

  return (NULL);
}

VLIB_INIT_FUNCTION (acl_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
