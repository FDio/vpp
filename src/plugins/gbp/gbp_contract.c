/*
 * gbp.h : Group Based Policy
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <plugins/gbp/gbp.h>
#include <plugins/gbp/gbp_bridge_domain.h>
#include <plugins/gbp/gbp_route_domain.h>
#include <plugins/gbp/gbp_policy_dpo.h>

#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/drop_dpo.h>

/**
 * Single contract DB instance
 */
gbp_contract_db_t gbp_contract_db;

gbp_contract_t *gbp_contract_pool;

vlib_log_class_t gc_logger;

fib_node_type_t gbp_next_hop_fib_type;

gbp_rule_t *gbp_rule_pool;
gbp_next_hop_t *gbp_next_hop_pool;

#define GBP_CONTRACT_DBG(...)                           \
    vlib_log_notice (gc_logger, __VA_ARGS__);

/* Adjacency packet/byte counters indexed by adjacency index. */
vlib_combined_counter_main_t gbp_contract_permit_counters = {
  .name = "gbp-contracts-permit",
  .stat_segment_name = "/net/gbp/contract/permit",
};

vlib_combined_counter_main_t gbp_contract_drop_counters = {
  .name = "gbp-contracts-drop",
  .stat_segment_name = "/net/gbp/contract/drop",
};

index_t
gbp_rule_alloc (gbp_rule_action_t action,
		gbp_hash_mode_t hash_mode, index_t * nhs)
{
  gbp_rule_t *gu;

  pool_get_zero (gbp_rule_pool, gu);

  gu->gu_hash_mode = hash_mode;
  gu->gu_nhs = nhs;
  gu->gu_action = action;

  return (gu - gbp_rule_pool);
}

index_t
gbp_next_hop_alloc (const ip46_address_t * ip,
		    index_t grd, const mac_address_t * mac, index_t gbd)
{
  fib_protocol_t fproto;
  gbp_next_hop_t *gnh;

  pool_get_zero (gbp_next_hop_pool, gnh);

  fib_node_init (&gnh->gnh_node, gbp_next_hop_fib_type);

  ip46_address_copy (&gnh->gnh_ip, ip);
  mac_address_copy (&gnh->gnh_mac, mac);

  gnh->gnh_rd = grd;
  gnh->gnh_bd = gbd;

  FOR_EACH_FIB_IP_PROTOCOL (fproto) gnh->gnh_ai[fproto] = INDEX_INVALID;

  return (gnh - gbp_next_hop_pool);
}

static inline gbp_next_hop_t *
gbp_next_hop_get (index_t gui)
{
  return (pool_elt_at_index (gbp_next_hop_pool, gui));
}

static void
gbp_contract_rules_free (index_t * rules)
{
  index_t *gui, *gnhi;

  vec_foreach (gui, rules)
  {
    gbp_policy_node_t pnode;
    fib_protocol_t fproto;
    gbp_next_hop_t *gnh;
    gbp_rule_t *gu;

    gu = gbp_rule_get (*gui);

    FOR_EACH_GBP_POLICY_NODE (pnode)
    {
      FOR_EACH_FIB_IP_PROTOCOL (fproto)
      {
	dpo_reset (&gu->gu_dpo[pnode][fproto]);
	dpo_reset (&gu->gu_dpo[pnode][fproto]);
      }
    }

    vec_foreach (gnhi, gu->gu_nhs)
    {
      fib_protocol_t fproto;

      gnh = gbp_next_hop_get (*gnhi);
      gbp_bridge_domain_unlock (gnh->gnh_bd);
      gbp_route_domain_unlock (gnh->gnh_rd);
      gbp_endpoint_child_remove (gnh->gnh_ge, gnh->gnh_sibling);
      gbp_endpoint_unlock (GBP_ENDPOINT_SRC_RR, gnh->gnh_ge);

      FOR_EACH_FIB_IP_PROTOCOL (fproto)
      {
	adj_unlock (gnh->gnh_ai[fproto]);
      }
    }
  }
  vec_free (rules);
}

static u8 *
format_gbp_next_hop (u8 * s, va_list * args)
{
  index_t gnhi = va_arg (*args, index_t);
  gbp_next_hop_t *gnh;

  gnh = gbp_next_hop_get (gnhi);

  s = format (s, "%U, %U, %U EP:%d",
	      format_mac_address_t, &gnh->gnh_mac,
	      format_gbp_bridge_domain, gnh->gnh_bd,
	      format_ip46_address, &gnh->gnh_ip, IP46_TYPE_ANY, gnh->gnh_ge);

  return (s);
}

static u8 *
format_gbp_rule_action (u8 * s, va_list * args)
{
  gbp_rule_action_t action = va_arg (*args, gbp_rule_action_t);

  switch (action)
    {
#define _(v,a) case GBP_RULE_##v: return (format (s, "%s", a));
      foreach_gbp_rule_action
#undef _
    }

  return (format (s, "unknown"));
}

static u8 *
format_gbp_hash_mode (u8 * s, va_list * args)
{
  gbp_hash_mode_t hash_mode = va_arg (*args, gbp_hash_mode_t);

  switch (hash_mode)
    {
#define _(v,a) case GBP_HASH_MODE_##v: return (format (s, "%s", a));
      foreach_gbp_hash_mode
#undef _
    }

  return (format (s, "unknown"));
}

static u8 *
format_gbp_policy_node (u8 * s, va_list * args)
{
  gbp_policy_node_t action = va_arg (*args, gbp_policy_node_t);

  switch (action)
    {
#define _(v,a) case GBP_POLICY_NODE_##v: return (format (s, "%s", a));
      foreach_gbp_policy_node
#undef _
    }

  return (format (s, "unknown"));
}

static u8 *
format_gbp_rule (u8 * s, va_list * args)
{
  index_t gui = va_arg (*args, index_t);
  gbp_policy_node_t pnode;
  fib_protocol_t fproto;
  gbp_rule_t *gu;
  index_t *gnhi;

  gu = gbp_rule_get (gui);
  s = format (s, "%U", format_gbp_rule_action, gu->gu_action);

  switch (gu->gu_action)
    {
    case GBP_RULE_PERMIT:
    case GBP_RULE_DENY:
      break;
    case GBP_RULE_REDIRECT:
      s = format (s, ", %U", format_gbp_hash_mode, gu->gu_hash_mode);
      break;
    }

  vec_foreach (gnhi, gu->gu_nhs)
  {
    s = format (s, "\n      [%U]", format_gbp_next_hop, *gnhi);
  }

  FOR_EACH_GBP_POLICY_NODE (pnode)
  {
    s = format (s, "\n    policy-%U", format_gbp_policy_node, pnode);

    FOR_EACH_FIB_IP_PROTOCOL (fproto)
    {
      if (dpo_id_is_valid (&gu->gu_dpo[pnode][fproto]))
	{
	  s =
	    format (s, "\n      %U", format_dpo_id,
		    &gu->gu_dpo[pnode][fproto], 8);
	}
    }
  }

  return (s);
}

static void
gbp_contract_mk_adj (gbp_next_hop_t * gnh, fib_protocol_t fproto)
{
  ethernet_header_t *eth;
  gbp_endpoint_t *ge;
  index_t old_ai;
  u8 *rewrite;

  old_ai = gnh->gnh_ai[fproto];
  rewrite = NULL;
  vec_validate (rewrite, sizeof (*eth) - 1);
  eth = (ethernet_header_t *) rewrite;

  GBP_CONTRACT_DBG ("...mk-adj: %U", format_gbp_next_hop,
		    gnh - gbp_next_hop_pool);

  ge = gbp_endpoint_get (gnh->gnh_ge);

  eth->type = clib_host_to_net_u16 ((fproto == FIB_PROTOCOL_IP4 ?
				     ETHERNET_TYPE_IP4 : ETHERNET_TYPE_IP6));
  mac_address_to_bytes (gbp_route_domain_get_local_mac (), eth->src_address);
  mac_address_to_bytes (&gnh->gnh_mac, eth->dst_address);

  gnh->gnh_ai[fproto] =
    adj_nbr_add_or_lock_w_rewrite (fproto,
				   fib_proto_to_link (fproto),
				   &gnh->gnh_ip, ge->ge_fwd.gef_itf, rewrite);

  adj_unlock (old_ai);
}

static flow_hash_config_t
gbp_contract_mk_lb_hp (gbp_hash_mode_t gu_hash_mode)
{
  switch (gu_hash_mode)
    {
    case GBP_HASH_MODE_SRC_IP:
      return IP_FLOW_HASH_SRC_ADDR;
    case GBP_HASH_MODE_DST_IP:
      return IP_FLOW_HASH_DST_ADDR;
    case GBP_HASH_MODE_SYMMETRIC:
      return (IP_FLOW_HASH_SRC_ADDR | IP_FLOW_HASH_DST_ADDR |
	      IP_FLOW_HASH_PROTO | IP_FLOW_HASH_SYMMETRIC);
    }

  return 0;
}

static void
gbp_contract_mk_lb (index_t gui, fib_protocol_t fproto)
{
  load_balance_path_t *paths = NULL;
  gbp_policy_node_t pnode;
  gbp_next_hop_t *gnh;
  dpo_proto_t dproto;
  gbp_rule_t *gu;
  u32 ii;

  u32 policy_nodes[] = {
    [GBP_POLICY_NODE_L2] = gbp_policy_port_node.index,
    [GBP_POLICY_NODE_IP4] = ip4_gbp_policy_dpo_node.index,
    [GBP_POLICY_NODE_IP6] = ip6_gbp_policy_dpo_node.index,
  };

  GBP_CONTRACT_DBG ("..mk-lb: %U", format_gbp_rule, gui);

  gu = gbp_rule_get (gui);
  dproto = fib_proto_to_dpo (fproto);

  if (GBP_RULE_REDIRECT != gu->gu_action)
    return;

  vec_foreach_index (ii, gu->gu_nhs)
  {
    gnh = gbp_next_hop_get (gu->gu_nhs[ii]);

    gbp_contract_mk_adj (gnh, FIB_PROTOCOL_IP4);
    gbp_contract_mk_adj (gnh, FIB_PROTOCOL_IP6);
  }

  FOR_EACH_GBP_POLICY_NODE (pnode)
  {
    vec_validate (paths, vec_len (gu->gu_nhs) - 1);

    vec_foreach_index (ii, gu->gu_nhs)
    {
      gnh = gbp_next_hop_get (gu->gu_nhs[ii]);

      paths[ii].path_index = FIB_NODE_INDEX_INVALID;
      paths[ii].path_weight = 1;
      dpo_set (&paths[ii].path_dpo, DPO_ADJACENCY,
	       dproto, gnh->gnh_ai[fproto]);
    }

    if (!dpo_id_is_valid (&gu->gu_dpo[pnode][fproto]))
      {
	dpo_id_t dpo = DPO_INVALID;

	dpo_set (&dpo, DPO_LOAD_BALANCE, dproto,
		 load_balance_create (vec_len (paths),
				      dproto,
				      gbp_contract_mk_lb_hp
				      (gu->gu_hash_mode)));
	dpo_stack_from_node (policy_nodes[pnode], &gu->gu_dpo[pnode][fproto],
			     &dpo);
	dpo_reset (&dpo);
      }

    load_balance_multipath_update (&gu->gu_dpo[pnode][fproto],
				   paths, LOAD_BALANCE_FLAG_NONE);
    vec_free (paths);
  }
}

static void
gbp_contract_mk_one_lb (index_t gui)
{
  gbp_contract_mk_lb (gui, FIB_PROTOCOL_IP4);
  gbp_contract_mk_lb (gui, FIB_PROTOCOL_IP6);
}

static int
gbp_contract_next_hop_resolve (index_t gui, index_t gnhi)
{
  gbp_bridge_domain_t *gbd;
  gbp_next_hop_t *gnh;
  ip46_address_t *ips;
  int rv;

  ips = NULL;
  gnh = gbp_next_hop_get (gnhi);
  gbd = gbp_bridge_domain_get (gnh->gnh_bd);

  gnh->gnh_gu = gui;
  vec_add1 (ips, gnh->gnh_ip);

  /*
   * source the endpoint this contract needs to forward via.
   * give ofrwarding details via the spine proxy. if this EP is known
   * to us, then since we source here with a low priority, the learned
   * info will take precedenc.
   */
  rv = gbp_endpoint_update_and_lock (GBP_ENDPOINT_SRC_RR,
				     gbd->gb_uu_fwd_sw_if_index,
				     ips,
				     &gnh->gnh_mac,
				     gnh->gnh_bd, gnh->gnh_rd, SCLASS_INVALID,
				     GBP_ENDPOINT_FLAG_NONE, NULL, NULL,
				     &gnh->gnh_ge);

  if (0 == rv)
    {
      gnh->gnh_sibling = gbp_endpoint_child_add (gnh->gnh_ge,
						 gbp_next_hop_fib_type, gnhi);
    }

  GBP_CONTRACT_DBG ("..resolve: %d: %d: %U", gui, gnhi, format_gbp_next_hop,
		    gnhi);

  vec_free (ips);
  return (rv);
}

static void
gbp_contract_rule_resolve (index_t gui)
{
  gbp_rule_t *gu;
  index_t *gnhi;

  gu = gbp_rule_get (gui);

  GBP_CONTRACT_DBG ("..resolve: %U", format_gbp_rule, gui);

  vec_foreach (gnhi, gu->gu_nhs)
  {
    gbp_contract_next_hop_resolve (gui, *gnhi);
  }
}

static void
gbp_contract_resolve (index_t * guis)
{
  index_t *gui;

  vec_foreach (gui, guis)
  {
    gbp_contract_rule_resolve (*gui);
  }
}

static void
gbp_contract_mk_lbs (index_t * guis)
{
  index_t *gui;

  vec_foreach (gui, guis)
  {
    gbp_contract_mk_one_lb (*gui);
  }
}

int
gbp_contract_update (sclass_t sclass,
		     sclass_t dclass,
		     u32 acl_index,
		     index_t * rules,
		     u16 * allowed_ethertypes, u32 * stats_index)
{
  gbp_main_t *gm = &gbp_main;
  u32 *acl_vec = NULL;
  gbp_contract_t *gc;
  index_t gci;
  uword *p;

  gbp_contract_key_t key = {
    .gck_src = sclass,
    .gck_dst = dclass,
  };

  if (~0 == gm->gbp_acl_user_id)
    {
      acl_plugin_exports_init (&gm->acl_plugin);
      gm->gbp_acl_user_id =
	gm->acl_plugin.register_user_module ("GBP ACL", "src-epg", "dst-epg");
    }

  p = hash_get (gbp_contract_db.gc_hash, key.as_u32);
  if (p != NULL)
    {
      gci = p[0];
      gc = gbp_contract_get (gci);
      gbp_contract_rules_free (gc->gc_rules);
      gbp_main.acl_plugin.put_lookup_context_index (gc->gc_lc_index);
      gc->gc_rules = NULL;
      vec_free (gc->gc_allowed_ethertypes);
    }
  else
    {
      pool_get_zero (gbp_contract_pool, gc);
      gc->gc_key = key;
      gci = gc - gbp_contract_pool;
      hash_set (gbp_contract_db.gc_hash, key.as_u32, gci);

      vlib_validate_combined_counter (&gbp_contract_drop_counters, gci);
      vlib_zero_combined_counter (&gbp_contract_drop_counters, gci);
      vlib_validate_combined_counter (&gbp_contract_permit_counters, gci);
      vlib_zero_combined_counter (&gbp_contract_permit_counters, gci);
    }

  GBP_CONTRACT_DBG ("update: %U", format_gbp_contract, gci);

  gc->gc_rules = rules;
  gc->gc_allowed_ethertypes = allowed_ethertypes;
  gbp_contract_resolve (gc->gc_rules);
  gbp_contract_mk_lbs (gc->gc_rules);

  gc->gc_acl_index = acl_index;
  gc->gc_lc_index =
    gm->acl_plugin.get_lookup_context_index (gm->gbp_acl_user_id,
					     sclass, dclass);

  vec_add1 (acl_vec, gc->gc_acl_index);
  gm->acl_plugin.set_acl_vec_for_context (gc->gc_lc_index, acl_vec);
  vec_free (acl_vec);

  *stats_index = gci;

  return (0);
}

int
gbp_contract_delete (sclass_t sclass, sclass_t dclass)
{
  gbp_contract_key_t key = {
    .gck_src = sclass,
    .gck_dst = dclass,
  };
  gbp_contract_t *gc;
  uword *p;

  p = hash_get (gbp_contract_db.gc_hash, key.as_u32);
  if (p != NULL)
    {
      gc = gbp_contract_get (p[0]);

      gbp_contract_rules_free (gc->gc_rules);
      gbp_main.acl_plugin.put_lookup_context_index (gc->gc_lc_index);
      vec_free (gc->gc_allowed_ethertypes);

      hash_unset (gbp_contract_db.gc_hash, key.as_u32);
      pool_put (gbp_contract_pool, gc);

      return (0);
    }

  return (VNET_API_ERROR_NO_SUCH_ENTRY);
}

void
gbp_contract_walk (gbp_contract_cb_t cb, void *ctx)
{
  gbp_contract_t *gc;

  /* *INDENT-OFF* */
  pool_foreach(gc, gbp_contract_pool,
  ({
    if (!cb(gc, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
gbp_contract_cli (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  sclass_t sclass = SCLASS_INVALID, dclass = SCLASS_INVALID;
  u32 acl_index = ~0, stats_index;
  u8 add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	add = 1;
      else if (unformat (input, "del"))
	add = 0;
      else if (unformat (input, "src-epg %d", &sclass))
	;
      else if (unformat (input, "dst-epg %d", &dclass))
	;
      else if (unformat (input, "acl-index %d", &acl_index))
	;
      else
	break;
    }

  if (SCLASS_INVALID == sclass)
    return clib_error_return (0, "Source EPG-ID must be specified");
  if (SCLASS_INVALID == dclass)
    return clib_error_return (0, "Destination EPG-ID must be specified");

  if (add)
    {
      gbp_contract_update (sclass, dclass, acl_index,
			   NULL, NULL, &stats_index);
    }
  else
    {
      gbp_contract_delete (sclass, dclass);
    }

  return (NULL);
}

/*?
 * Configure a GBP Contract
 *
 * @cliexpar
 * @cliexstart{set gbp contract [del] src-epg <ID> dst-epg <ID> acl-index <ACL>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_contract_cli_node, static) =
{
  .path = "gbp contract",
  .short_help =
    "gbp contract [del] src-epg <ID> dst-epg <ID> acl-index <ACL>",
  .function = gbp_contract_cli,
};
/* *INDENT-ON* */

static u8 *
format_gbp_contract_key (u8 * s, va_list * args)
{
  gbp_contract_key_t *gck = va_arg (*args, gbp_contract_key_t *);

  s = format (s, "{%d,%d}", gck->gck_src, gck->gck_dst);

  return (s);
}

u8 *
format_gbp_contract (u8 * s, va_list * args)
{
  index_t gci = va_arg (*args, index_t);
  vlib_counter_t counts;
  gbp_contract_t *gc;
  index_t *gui;
  u16 *et;

  gc = gbp_contract_get (gci);

  s = format (s, "[%d] %U: acl-index:%d",
	      gci, format_gbp_contract_key, &gc->gc_key, gc->gc_acl_index);

  vec_foreach (gui, gc->gc_rules)
  {
    s = format (s, "\n    %d: %U", *gui, format_gbp_rule, *gui);
  }

  s = format (s, "\n    allowed-ethertypes:[");
  vec_foreach (et, gc->gc_allowed_ethertypes)
  {
    int host_et = clib_net_to_host_u16 (*et);
    if (0 != host_et)
      s = format (s, "0x%x, ", host_et);
  }

  vlib_get_combined_counter (&gbp_contract_drop_counters, gci, &counts);
  s = format (s, "\n   drop:[%Ld:%Ld]", counts.packets, counts.bytes);
  vlib_get_combined_counter (&gbp_contract_permit_counters, gci, &counts);
  s = format (s, "\n   permit:[%Ld:%Ld]", counts.packets, counts.bytes);

  s = format (s, "]");

  return (s);
}

static clib_error_t *
gbp_contract_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  gbp_contract_t *gc;
  u32 src, dst;
  index_t gci;

  src = dst = SCLASS_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src %d", &src))
	;
      else if (unformat (input, "dst %d", &dst))
	;
      else
	break;
    }

  vlib_cli_output (vm, "Contracts:");

  /* *INDENT-OFF* */
  pool_foreach (gc, gbp_contract_pool,
  ({
    gci = gc - gbp_contract_pool;

    if (SCLASS_INVALID != src && SCLASS_INVALID != dst)
      {
        if (gc->gc_key.gck_src == src &&
            gc->gc_key.gck_dst == dst)
          vlib_cli_output (vm, "  %U", format_gbp_contract, gci);
      }
    else if (SCLASS_INVALID != src)
      {
        if (gc->gc_key.gck_src == src)
          vlib_cli_output (vm, "  %U", format_gbp_contract, gci);
      }
    else if (SCLASS_INVALID != dst)
      {
        if (gc->gc_key.gck_dst == dst)
          vlib_cli_output (vm, "  %U", format_gbp_contract, gci);
      }
    else
      vlib_cli_output (vm, "  %U", format_gbp_contract, gci);
  }));
  /* *INDENT-ON* */

  return (NULL);
}

/*?
 * Show Group Based Policy Contracts
 *
 * @cliexpar
 * @cliexstart{show gbp contract}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gbp_contract_show_node, static) = {
  .path = "show gbp contract",
  .short_help = "show gbp contract [src <SRC>] [dst <DST>]\n",
  .function = gbp_contract_show,
};
/* *INDENT-ON* */

static fib_node_t *
gbp_next_hop_get_node (fib_node_index_t index)
{
  gbp_next_hop_t *gnh;

  gnh = gbp_next_hop_get (index);

  return (&gnh->gnh_node);
}

static void
gbp_next_hop_last_lock_gone (fib_node_t * node)
{
  ASSERT (0);
}

static gbp_next_hop_t *
gbp_next_hop_from_fib_node (fib_node_t * node)
{
  ASSERT (gbp_next_hop_fib_type == node->fn_type);
  return ((gbp_next_hop_t *) node);
}

static fib_node_back_walk_rc_t
gbp_next_hop_back_walk_notify (fib_node_t * node,
			       fib_node_back_walk_ctx_t * ctx)
{
  gbp_next_hop_t *gnh;

  gnh = gbp_next_hop_from_fib_node (node);

  gbp_contract_mk_one_lb (gnh->gnh_gu);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The FIB path's graph node virtual function table
 */
static const fib_node_vft_t gbp_next_hop_vft = {
  .fnv_get = gbp_next_hop_get_node,
  .fnv_last_lock = gbp_next_hop_last_lock_gone,
  .fnv_back_walk = gbp_next_hop_back_walk_notify,
  // .fnv_mem_show = fib_path_memory_show,
};

static clib_error_t *
gbp_contract_init (vlib_main_t * vm)
{
  gc_logger = vlib_log_register_class ("gbp", "con");
  gbp_next_hop_fib_type = fib_node_register_new_type (&gbp_next_hop_vft);

  return (NULL);
}

VLIB_INIT_FUNCTION (gbp_contract_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
