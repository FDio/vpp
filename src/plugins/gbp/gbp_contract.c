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

#include <vnet/dpo/load_balance.h>

/**
 * Single contract DB instance
 */
gbp_contract_db_t gbp_contract_db;

gbp_contract_t *gbp_contract_pool;

static void
gbp_contract_rules_free (gbp_rule_t * rules)
{
  dpo_proto_t dproto;
  gbp_rule_t *gu;

  vec_foreach (gu, rules)
  {
    FOR_EACH_DPO_PROTO (dproto)
    {
      dpo_reset (&gu->gu_dpo[dproto]);
    }
  }
  vec_free (rules);
}

static void
gbp_contract_mk_adj (const gbp_next_hop_t * nh,
		     dpo_proto_t dproto, load_balance_path_t * path)
{
  gbp_bridge_domain_t *gbd;
  ethernet_header_t *eth;
  fib_protocol_t fproto;
  gbp_endpoint_t *ge;
  u8 *rewrite;

  path->path_index = FIB_NODE_INDEX_INVALID;
  path->path_weight = 1;
  fproto = dpo_proto_to_fib (dproto);

  rewrite = NULL;
  vec_validate (rewrite, sizeof (*eth) - 1);
  eth = (ethernet_header_t *) rewrite;

  gbd = gbp_bridge_domain_get (nh->gnh_bd);
  ge = gbp_endpoint_find_mac (nh->gnh_mac.bytes, gbd->gb_bd_index);

  if (NULL != ge)
    {
      index_t ai;

      eth->type = clib_host_to_net_u16 ((dproto == DPO_PROTO_IP4 ?
					 ETHERNET_TYPE_IP4 :
					 ETHERNET_TYPE_IP6));
      mac_address_to_bytes (gbp_route_domain_get_local_mac (),
			    eth->src_address);
      mac_address_to_bytes (&nh->gnh_mac, eth->dst_address);

      ai = adj_nbr_add_or_lock_w_rewrite (fproto,
					  fib_proto_to_link (fproto),
					  &nh->gnh_ip,
					  ge->ge_sw_if_index, rewrite);

      dpo_set (&path->path_dpo, DPO_ADJACENCY, dproto, ai);

      adj_unlock (ai);
    }
  else
    {
      ASSERT (ge);
    }
}

static index_t
gbp_contract_mk_lb (gbp_rule_t * gu, dpo_proto_t dproto)
{
  load_balance_path_t *paths = NULL;
  gbp_next_hop_t *nhs;
  u32 ii;

  nhs = gu->gu_nh_set.gnhs_nhs;
  vec_validate (paths, vec_len (nhs) - 1);

  vec_foreach_index (ii, nhs)
  {
    gbp_contract_mk_adj (&nhs[ii], dproto, &paths[ii]);
  }

  // FIXME get algo and sticky bit from contract LB algo
  dpo_set (&gu->gu_dpo[dproto],
	   DPO_LOAD_BALANCE,
	   dproto,
	   load_balance_create (vec_len (paths),
				dproto, IP_FLOW_HASH_DEFAULT));

  load_balance_multipath_update (&gu->gu_dpo[dproto],
				 paths, LOAD_BALANCE_FLAG_NONE);

  return (INDEX_INVALID);
}

static void
gbp_contract_mk_lbs (gbp_rule_t * rules)
{
  gbp_rule_t *rule;

  vec_foreach (rule, rules)
  {
    gbp_contract_mk_lb (rule, DPO_PROTO_IP4);
    gbp_contract_mk_lb (rule, DPO_PROTO_IP6);
  }
}

int
gbp_contract_update (epg_id_t src_epg,
		     epg_id_t dst_epg, u32 acl_index, gbp_rule_t * rules)
{
  gbp_main_t *gm = &gbp_main;
  u32 *acl_vec = NULL;
  gbp_contract_t *gc;
  uword *p;

  gbp_contract_key_t key = {
    .gck_src = src_epg,
    .gck_dst = dst_epg,
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
      gc = gbp_contract_get (p[0]);
      gbp_contract_rules_free (gc->gc_rules);
      gbp_main.acl_plugin.put_lookup_context_index (gc->gc_lc_index);
      gc->gc_rules = NULL;
    }
  else
    {
      pool_get_zero (gbp_contract_pool, gc);
      gc->gc_key = key;
      hash_set (gbp_contract_db.gc_hash, key.as_u32, gc - gbp_contract_pool);
    }

  gc->gc_rules = rules;
  gbp_contract_mk_lbs (gc->gc_rules);

  gc->gc_acl_index = acl_index;
  gc->gc_lc_index =
    gm->acl_plugin.get_lookup_context_index (gm->gbp_acl_user_id,
					     src_epg, dst_epg);

  vec_add1 (acl_vec, gc->gc_acl_index);
  gm->acl_plugin.set_acl_vec_for_context (gc->gc_lc_index, acl_vec);
  vec_free (acl_vec);

  return (0);
}

int
gbp_contract_delete (epg_id_t src_epg, epg_id_t dst_epg)
{
  gbp_contract_key_t key = {
    .gck_src = src_epg,
    .gck_dst = dst_epg,
  };
  gbp_contract_t *gc;
  uword *p;

  p = hash_get (gbp_contract_db.gc_hash, key.as_u32);
  if (p != NULL)
    {
      gc = gbp_contract_get (p[0]);

      gbp_contract_rules_free (gc->gc_rules);
      gbp_main.acl_plugin.put_lookup_context_index (gc->gc_lc_index);

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
  epg_id_t src_epg_id = EPG_INVALID, dst_epg_id = EPG_INVALID;
  u32 acl_index = ~0;
  u8 add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	add = 1;
      else if (unformat (input, "del"))
	add = 0;
      else if (unformat (input, "src-epg %d", &src_epg_id))
	;
      else if (unformat (input, "dst-epg %d", &dst_epg_id))
	;
      else if (unformat (input, "acl-index %d", &acl_index))
	;
      else
	break;
    }

  if (EPG_INVALID == src_epg_id)
    return clib_error_return (0, "Source EPG-ID must be specified");
  if (EPG_INVALID == dst_epg_id)
    return clib_error_return (0, "Destination EPG-ID must be specified");

  if (add)
    {
      gbp_contract_update (src_epg_id, dst_epg_id, acl_index, NULL);
    }
  else
    {
      gbp_contract_delete (src_epg_id, dst_epg_id);
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
  gbp_contract_t *gc;

  gc = gbp_contract_get (gci);

  s = format (s, "%U:\n", format_gbp_contract_key, &gc->gc_key);

  return (s);
}

static clib_error_t *
gbp_contract_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t gci;

  vlib_cli_output (vm, "Contracts:");

  /* *INDENT-OFF* */
  pool_foreach_index (gci, gbp_contract_pool,
  ({
    vlib_cli_output (vm, "  [%d] %U", gci, format_gbp_contract, gci);
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
  .short_help = "show gbp contract\n",
  .function = gbp_contract_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
