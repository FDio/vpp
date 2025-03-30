/*
 * Copyright (c) 2024 Cisco and/or its affiliates.
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

#include <vnet/session/session.h>
#include <vnet/ip/ip4_forward.h>
#include <vnet/ip/ip6_forward.h>
#include <vnet/session/session_rules_table.h>
#include <vnet/session/session_sdl.h>

VLIB_REGISTER_LOG_CLASS (session_sdl_log, static) = { .class_name = "session",
						      .subclass_name = "sdl" };

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (session_sdl_log._class, "%s: " fmt, __func__, __VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (session_sdl_log._class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)                                                     \
  vlib_log_err (session_sdl_log._class, fmt, __VA_ARGS__)

static session_sdl_main_t sdl_main;
static session_sdl_main_t *sdlm = &sdl_main;

const static char *const *const session_sdl_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = (const char *const[]){ "ip4-drop", 0 },
  [DPO_PROTO_IP6] = (const char *const[]){ "ip6-drop", 0 },
};

static fib_route_path_t *
session_sdl_fib_create_route_paths (u32 fib_index, dpo_proto_t dpo_proto)
{
  fib_route_path_t *paths = 0;
  fib_route_path_t path = {
    .frp_proto = dpo_proto,
    .frp_flags = FIB_ROUTE_PATH_EXCLUSIVE,
    .frp_fib_index = fib_index,
    .frp_sw_if_index = ~0,
    .frp_weight = 1,
  };
  vec_add1 (paths, path);
  return paths;
}

static void
session_sdl_dpo_lock (dpo_id_t *dpo)
{
}

static void
session_sdl_dpo_unlock (dpo_id_t *dpo)
{
}

static u8 *
format_session_sdl_dpo (u8 *s, va_list *va)
{
  index_t index = va_arg (*va, index_t);

  return format (s, "sdl: [index: %u, deny]", index);
}

static const dpo_vft_t session_sdl_dpo_vft = {
  .dv_lock = session_sdl_dpo_lock,
  .dv_unlock = session_sdl_dpo_unlock,
  .dv_format = format_session_sdl_dpo,
};

static u32
session_sdl_lookup6 (u32 srtg_handle, u32 proto, ip6_address_t *lcl_ip,
		     ip6_address_t *rmt_ip, u16 lcl_port, u16 rmt_port)
{
  session_rules_table_t *srt = srtg_handle_to_srt (srtg_handle, 0);
  session_sdl_block_t *sdlb = &srt->sdl_block;
  index_t lbi;
  const dpo_id_t *dpo;

  if (sdlb->ip6_fib_index == ~0)
    return SESSION_TABLE_INVALID_INDEX;
  lbi = ip6_fib_table_fwding_lookup (sdlb->ip6_fib_index, rmt_ip);
  dpo = load_balance_get_fwd_bucket (load_balance_get (lbi), 0);
  if (dpo->dpoi_type != sdlm->dpo_type)
    return SESSION_TABLE_INVALID_INDEX;
  return (dpo->dpoi_index);
}

static u32
session_sdl_lookup4 (u32 srtg_handle, u32 proto, ip4_address_t *lcl_ip,
		     ip4_address_t *rmt_ip, u16 lcl_port, u16 rmt_port)
{
  session_rules_table_t *srt = srtg_handle_to_srt (srtg_handle, 0);
  session_sdl_block_t *sdlb = &srt->sdl_block;
  index_t lbi;
  const dpo_id_t *dpo;

  if (sdlb->ip_fib_index == ~0)
    return SESSION_TABLE_INVALID_INDEX;
  lbi = ip4_fib_forwarding_lookup (sdlb->ip_fib_index, rmt_ip);
  dpo = load_balance_get_fwd_bucket (load_balance_get (lbi), 0);
  if (dpo->dpoi_type != sdlm->dpo_type)
    return SESSION_TABLE_INVALID_INDEX;
  return (dpo->dpoi_index);
}

typedef struct session_sdl4_fib_show_walk_ctx_t_
{
  fib_node_index_t *ifsw_indicies;
} session_sdl4_fib_show_walk_ctx_t;

static fib_table_walk_rc_t
session_sdl4_fib_show_walk_cb (fib_node_index_t fei, void *arg)
{
  session_sdl4_fib_show_walk_ctx_t *ctx = arg;

  vec_add1 (ctx->ifsw_indicies, fei);

  return (FIB_TABLE_WALK_CONTINUE);
}

typedef struct session_sdl6_fib_show_ctx_t_
{
  fib_node_index_t *entries;
} session_sdl6_fib_show_ctx_t;

static fib_table_walk_rc_t
session_sdl6_fib_table_show_walk (fib_node_index_t fei, void *arg)
{
  session_sdl6_fib_show_ctx_t *ctx = arg;

  vec_add1 (ctx->entries, fei);

  return (FIB_TABLE_WALK_CONTINUE);
}

static void
session_sdl_fib_table_show (u32 fei, ip46_address_t *rmt_ip, u16 fp_len,
			    u32 action_index, u32 fp_proto, u8 *tag,
			    void *args)
{
  vlib_main_t *vm = args;
  u32 type = (fp_proto == FIB_PROTOCOL_IP4) ? IP46_TYPE_IP4 : IP46_TYPE_IP6;

  vlib_cli_output (vm, "[%d] rule: %U/%d action: %d tag %U", fei,
		   format_ip46_address, rmt_ip, type, fp_len, action_index,
		   format_session_rule_tag, tag);
}

static void
session_sdl_cli_dump (vlib_main_t *vm, u32 srtg_handle, u32 proto,
		      u8 fib_proto)
{
  session_rules_table_t *srt = srtg_handle_to_srt (srtg_handle, 0);
  session_sdl_block_t *sdlb = &srt->sdl_block;

  if (fib_proto == FIB_PROTOCOL_IP4)
    {
      vlib_cli_output (vm, "IP4 rules, fib index %d", sdlb->ip_fib_index);
      session_sdl_table_walk4 (srtg_handle, session_sdl_fib_table_show, vm);
    }
  else if (fib_proto == FIB_PROTOCOL_IP6)
    {
      vlib_cli_output (vm, "IP6 rules, fib index %d", sdlb->ip6_fib_index);
      session_sdl_table_walk6 (srtg_handle, session_sdl_fib_table_show, vm);
    }
}

static void
session_sdl4_fib_table_show_one (session_rules_table_t *srt, u32 fib_index,
				 vlib_main_t *vm, ip4_address_t *address,
				 u32 mask_len)
{
  ip4_fib_t *fib;
  fib_node_index_t fei;

  fib = ip4_fib_get (fib_index);
  fei = ip4_fib_table_lookup (fib, address, mask_len);
  if (fei != FIB_NODE_INDEX_INVALID &&
      fib_entry_is_sourced (fei, sdlm->fib_src))
    {
      u8 *tag = session_rules_table_rule_tag (srt, fei, 1);
      fib_entry_t *fib_entry = fib_entry_get (fei);
      fib_prefix_t pfx = fib_entry->fe_prefix;
      index_t lbi = ip4_fib_forwarding_lookup (fib_index, &pfx.fp_addr.ip4);
      const dpo_id_t *dpo =
	load_balance_get_fwd_bucket (load_balance_get (lbi), 0);

      session_sdl_fib_table_show (fei, &pfx.fp_addr, pfx.fp_len,
				  dpo->dpoi_index, FIB_PROTOCOL_IP4, tag, vm);
    }
}

static void
session_sdl6_fib_table_show_one (session_rules_table_t *srt, u32 fib_index,
				 vlib_main_t *vm, ip6_address_t *address,
				 u32 mask_len)
{
  fib_node_index_t fei;

  fei = ip6_fib_table_lookup (fib_index, address, mask_len);
  if (fei != FIB_NODE_INDEX_INVALID &&
      fib_entry_is_sourced (fei, sdlm->fib_src))
    {
      u8 *tag = session_rules_table_rule_tag (srt, fei, 0);
      fib_entry_t *fib_entry = fib_entry_get (fei);
      fib_prefix_t pfx = fib_entry->fe_prefix;
      index_t lbi = ip6_fib_table_fwding_lookup (fib_index, &pfx.fp_addr.ip6);
      const dpo_id_t *dpo =
	load_balance_get_fwd_bucket (load_balance_get (lbi), 0);

      session_sdl_fib_table_show (fei, &pfx.fp_addr, pfx.fp_len,
				  dpo->dpoi_index, FIB_PROTOCOL_IP6, tag, vm);
    }
}

static void
session_sdl_show_rule (vlib_main_t *vm, u32 srtg_handle, u32 proto,
		       ip46_address_t *lcl_ip, u16 lcl_port,
		       ip46_address_t *rmt_ip, u16 rmt_port, u8 is_ip4)
{
  session_rules_table_t *srt = srtg_handle_to_srt (srtg_handle, 0);
  session_sdl_block_t *sdlb;

  sdlb = &srt->sdl_block;
  if (is_ip4)
    session_sdl4_fib_table_show_one (srt, sdlb->ip_fib_index, vm, &rmt_ip->ip4,
				     32);
  else
    session_sdl6_fib_table_show_one (srt, sdlb->ip6_fib_index, vm,
				     &rmt_ip->ip6, 128);
}

static void
session_sdl_table_init (session_table_t *st, u8 fib_proto)
{
  session_rules_table_t *srt;
  session_sdl_block_t *sdlb;
  u8 all = fib_proto > FIB_PROTOCOL_IP6 ? 1 : 0;
  char name[80];
  u32 appns_index;
  app_namespace_t *app_ns;
  session_rules_table_group_t *srtg;

  /* Don't support local table */
  if (st->is_local == 1)
    return;

  appns_index =
    *vec_elt_at_index (st->appns_index, vec_len (st->appns_index) - 1);
  app_ns = app_namespace_get (appns_index);
  srtg = srtg_instance_alloc (st, 0);
  srt = srtg->session_rules;
  sdlb = &srt->sdl_block;

  if (fib_proto == FIB_PROTOCOL_IP4 || all)
    {
      snprintf (name, sizeof (name), "sdl4 %s", app_ns->ns_id);
      sdlb->ip_table_id = ip_table_get_unused_id (FIB_PROTOCOL_IP4);
      sdlb->ip_fib_index = fib_table_find_or_create_and_lock_w_name (
	FIB_PROTOCOL_IP4, sdlb->ip_table_id, sdlm->fib_src, (const u8 *) name);
    }

  if (fib_proto == FIB_PROTOCOL_IP6 || all)
    {
      snprintf (name, sizeof (name), "sdl6 %s", app_ns->ns_id);
      sdlb->ip6_table_id = ip_table_get_unused_id (FIB_PROTOCOL_IP6);
      sdlb->ip6_fib_index = fib_table_find_or_create_and_lock_w_name (
	FIB_PROTOCOL_IP6, sdlb->ip6_table_id, sdlm->fib_src,
	(const u8 *) name);
    }

  srt->rules_by_tag = hash_create_vec (0, sizeof (u8), sizeof (uword));
  srt->tags_by_rules = hash_create (0, sizeof (uword));
}

static void
session_sdl_table_free (session_table_t *st, u8 fib_proto)
{
  session_rules_table_t *srt = srtg_handle_to_srt (st->srtg_handle, 0);
  session_sdl_block_t *sdlb;
  u8 all = fib_proto > FIB_PROTOCOL_IP6 ? 1 : 0;
  u32 fib_index, appns_index = *vec_elt_at_index (st->appns_index, 0);
  app_namespace_t *app_ns = app_namespace_get (appns_index);
  session_sdl_callback_fn_t *cb;

  ASSERT (st->is_local == 0);
  if (st->is_local == 1)
    return;
  sdlb = &srt->sdl_block;
  if ((fib_proto == FIB_PROTOCOL_IP4 || all) && (sdlb->ip_fib_index != ~0))
    {
      fib_index = app_namespace_get_fib_index (app_ns, FIB_PROTOCOL_IP4);
      session_sdl_callback_t args = { .fib_proto = FIB_PROTOCOL_IP4,
				      .fib_index = fib_index };
      vec_foreach (cb, sdlm->sdl_callbacks)
	(*cb) (SESSION_SDL_CALLBACK_TABLE_CLEAN_UP, &args);
      fib_table_flush (sdlb->ip_fib_index, FIB_PROTOCOL_IP4, sdlm->fib_src);
      fib_table_unlock (sdlb->ip_fib_index, FIB_PROTOCOL_IP4, sdlm->fib_src);
    }
  if ((fib_proto == FIB_PROTOCOL_IP6 || all) && (sdlb->ip6_fib_index != ~0))
    {
      fib_index = app_namespace_get_fib_index (app_ns, FIB_PROTOCOL_IP6);
      session_sdl_callback_t args = { .fib_proto = FIB_PROTOCOL_IP6,
				      .fib_index = fib_index };
      vec_foreach (cb, sdlm->sdl_callbacks)
	(*cb) (SESSION_SDL_CALLBACK_TABLE_CLEAN_UP, &args);
      fib_table_flush (sdlb->ip6_fib_index, FIB_PROTOCOL_IP6, sdlm->fib_src);
      fib_table_unlock (sdlb->ip6_fib_index, FIB_PROTOCOL_IP6, sdlm->fib_src);
    }

  hash_free (srt->tags_by_rules);
  hash_free (srt->rules_by_tag);

  srtg_instance_free (st);
}

static session_error_t
session_sdl_add_del (u32 srtg_handle, u32 proto,
		     session_rule_table_add_del_args_t *args)
{
  session_rules_table_t *srt = srtg_handle_to_srt (srtg_handle, 0);
  session_sdl_block_t *sdlb = &srt->sdl_block;
  u32 fib_index;
  dpo_proto_t dpo_proto;
  fib_route_path_t *paths = 0;
  fib_prefix_t pfx = args->rmt;
  session_error_t err = SESSION_E_NONE;
  fib_node_index_t fei;
  int is_ip4;

  fei = session_rules_table_rule_for_tag (srt, args->tag);
  if (args->is_add && fei != SESSION_RULES_TABLE_INVALID_INDEX)
    return SESSION_E_INVALID;

  if (args->rmt.fp_proto == FIB_PROTOCOL_IP4)
    {
      fib_index = sdlb->ip_fib_index;
      dpo_proto = DPO_PROTO_IP4;
      is_ip4 = 1;
    }
  else
    {
      fib_index = sdlb->ip6_fib_index;
      dpo_proto = DPO_PROTO_IP6;
      is_ip4 = 0;
    }

  paths = session_sdl_fib_create_route_paths (fib_index, dpo_proto);
  if (args->is_add)
    {
      fei = fib_table_lookup_exact_match (fib_index, &pfx);
      if (fei != FIB_NODE_INDEX_INVALID)
	{
	  err = SESSION_E_IPINUSE;
	  goto done;
	}
      dpo_set (&paths->dpo, sdlm->dpo_type, dpo_proto, args->action_index);
      fei = fib_table_entry_path_add2 (fib_index, &pfx, sdlm->fib_src,
				       FIB_ENTRY_FLAG_EXCLUSIVE, paths);
      session_rules_table_add_tag (srt, args->tag, fei, is_ip4);
      dpo_reset (&paths->dpo);
    }
  else
    {
      if (fei == SESSION_RULES_TABLE_INVALID_INDEX)
	{
	  fei = fib_table_lookup_exact_match (fib_index, &pfx);

	  if (fei == FIB_NODE_INDEX_INVALID)
	    {
	      err = SESSION_E_NOROUTE;
	      goto done;
	    }
	}

      if (!fib_entry_is_sourced (fei, sdlm->fib_src))
	{
	  err = SESSION_E_NOROUTE;
	  goto done;
	}

      fib_entry_t *fib_entry = fib_entry_get (fei);
      pfx = fib_entry->fe_prefix;
      fib_table_entry_special_remove (fib_index, &pfx, sdlm->fib_src);
      session_rules_table_del_tag (srt, args->tag, is_ip4);
    }
done:
  vec_free (paths);

  return err;
}

static const session_rt_engine_vft_t session_sdl_vft = {
  .backend_engine = RT_BACKEND_ENGINE_SDL,
  .table_lookup4 = session_sdl_lookup4,
  .table_lookup6 = session_sdl_lookup6,
  .table_cli_dump = session_sdl_cli_dump,
  .table_show_rule = session_sdl_show_rule,
  .table_add_del = session_sdl_add_del,
  .table_init = session_sdl_table_init,
  .table_free = session_sdl_table_free,
};

static void
session_sdl_init (void)
{
  if (sdlm->sdl_inited)
    return;

  sdlm->sdl_inited = 1;
  sdlm->fib_src = fib_source_allocate ("session sdl", FIB_SOURCE_PRIORITY_LOW,
				       FIB_SOURCE_BH_SIMPLE);
  sdlm->dpo_type =
    dpo_register_new_type (&session_sdl_dpo_vft, session_sdl_dpo_nodes);
}

static void
session_sdl_app_namespace_walk_cb (app_namespace_t *app_ns, void *ctx)
{
  u32 fib_index, table_index;
  session_table_t *st;

  log_debug ("disable app_ns %s", app_ns->ns_id);

  fib_index = app_namespace_get_fib_index (app_ns, FIB_PROTOCOL_IP4);
  table_index = session_lookup_get_index_for_fib (FIB_PROTOCOL_IP4, fib_index);
  st = session_table_get (table_index);
  if (st)
    session_rules_table_free (st, FIB_PROTOCOL_IP4);

  fib_index = app_namespace_get_fib_index (app_ns, FIB_PROTOCOL_IP6);
  table_index = session_lookup_get_index_for_fib (FIB_PROTOCOL_IP6, fib_index);
  st = session_table_get (table_index);
  if (st)
    session_rules_table_free (st, FIB_PROTOCOL_IP6);
}

clib_error_t *
session_sdl_enable_disable (int enable)
{
  clib_error_t *error = 0;
  session_sdl_callback_fn_t *cb;
  session_sdl_callback_t args;
  session_sdl_callback_fn_t *callbacks;

  if (enable)
    {
      error = session_rule_table_register_engine (&session_sdl_vft);
      if (error)
	{
	  log_err ("error in enabling sdl: %U", format_clib_error, error);
	  return error;
	}
      session_sdl_init ();
    }
  else
    {
      app_namespace_walk (session_sdl_app_namespace_walk_cb, 0);

      error = session_rule_table_deregister_engine (&session_sdl_vft);
      if (error)
	log_err ("error in disabling sdl: %U", format_clib_error, error);

      /*
       * Disabling sdl also disables auto sdl.
       * But first, make a copy of the callbacks since the callback function
       * may delete the callbacks, deregistering.
       */
      callbacks = vec_dup (sdlm->sdl_callbacks);

      clib_memset (&args, 0, sizeof (args));
      vec_foreach (cb, callbacks)
	(*cb) (SESSION_SDL_CALLBACK_CONFIG_DISABLE, &args);
      vec_free (callbacks);
    }

  return error;
}

/*
 * Source Deny List
 */
static clib_error_t *
session_sdl_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  u32 appns_index;
  app_namespace_t *app_ns;
  u32 rmt_plen = 0, action = 0;
  ip46_address_t rmt_ip;
  u8 conn_set = 0;
  u8 fib_proto = -1, is_add = 1, *ns_id = 0;
  u8 *tag = 0;
  int rv;
  session_rule_add_del_args_t args;

  if (session_sdl_is_enabled () == 0)
    {
      vlib_cli_output (vm, "session sdl engine is not enabled");
      unformat_skip_line (input);
      goto done;
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "add"))
	;
      else if (unformat (input, "appns %_%v%_", &ns_id))
	;
      else if (unformat (input, "%U/%d", unformat_ip4_address, &rmt_ip.ip4,
			 &rmt_plen))
	{
	  fib_proto = FIB_PROTOCOL_IP4;
	  conn_set = 1;
	}
      else if (unformat (input, "%U/%d", unformat_ip6_address, &rmt_ip.ip6,
			 &rmt_plen))
	{
	  fib_proto = FIB_PROTOCOL_IP6;
	  conn_set = 1;
	}
      else if (unformat (input, "action %d", &action))
	;
      else if (unformat (input, "tag %_%v%_", &tag))
	;
      else
	{
	  vlib_cli_output (vm, "unknown input `%U'", format_unformat_error,
			   input);
	  goto done;
	}
    }

  if (ns_id)
    {
      app_ns = app_namespace_get_from_id (ns_id);
      if (!app_ns)
	{
	  vlib_cli_output (vm, "namespace %v does not exist", ns_id);
	  goto done;
	}
    }
  else
    app_ns = app_namespace_get_default ();

  appns_index = app_namespace_index (app_ns);

  if (is_add && !conn_set && action == 0)
    {
      vlib_cli_output (vm, "connection and action must be set for add");
      goto done;
    }
  if (!is_add && !tag && !conn_set)
    {
      vlib_cli_output (vm, "connection or tag must be set for delete");
      goto done;
    }
  if (vec_len (tag) > SESSION_RULE_TAG_MAX_LEN)
    {
      vlib_cli_output (vm, "tag too long (max u64)");
      goto done;
    }

  memset (&args, 0, sizeof (args));
  args.transport_proto = TRANSPORT_PROTO_TCP;
  args.table_args.rmt.fp_addr = rmt_ip;
  args.table_args.rmt.fp_len = rmt_plen;
  args.table_args.rmt.fp_proto = fib_proto;
  args.table_args.action_index = action;
  args.table_args.is_add = is_add;
  args.table_args.tag = tag;
  args.appns_index = appns_index;
  args.scope = SESSION_RULE_SCOPE_GLOBAL;

  if ((rv = vnet_session_rule_add_del (&args)))
    vlib_cli_output (vm, "sdl add del returned %d", rv);

done:
  vec_free (ns_id);
  vec_free (tag);
  return 0;
}

VLIB_CLI_COMMAND (session_sdl_command, static) = {
  .path = "session sdl",
  .short_help = "session sdl <add|del> [appns <ns_id>] <rmt-ip/plen> action "
		"<action> [tag <tag>]",
  .function = session_sdl_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_session_sdl_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  u32 fib_index;
  ip46_address_t rmt_ip;
  u8 show_one = 0;
  app_namespace_t *app_ns;
  session_table_t *st;
  u8 *ns_id = 0, fib_proto = FIB_PROTOCOL_IP4;

  session_cli_return_if_not_enabled ();

  clib_memset (&rmt_ip, 0, sizeof (rmt_ip));
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "appns %_%s%_", &ns_id))
	;
      else if (unformat (input, "%U", unformat_ip4_address, &rmt_ip.ip4))
	{
	  fib_proto = FIB_PROTOCOL_IP4;
	  show_one = 1;
	}
      else if (unformat (input, "%U", unformat_ip6_address, &rmt_ip.ip6))
	{
	  fib_proto = FIB_PROTOCOL_IP6;
	  show_one = 1;
	}
      else
	{
	  vec_free (ns_id);
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, input);
	}
    }

  if (ns_id)
    {
      app_ns = app_namespace_get_from_id (ns_id);
      if (!app_ns)
	{
	  vlib_cli_output (vm, "appns %v doesn't exist", ns_id);
	  goto done;
	}
    }
  else
    {
      app_ns = app_namespace_get_default ();
    }

  if (session_sdl_is_enabled () == 0)
    {
      vlib_cli_output (vm, "session sdl engine is not enabled");
      goto done;
    }

  if (show_one)
    {
      fib_index = app_namespace_get_fib_index (app_ns, fib_proto);
      st = session_table_get_for_fib_index (fib_proto, fib_index);
      if (st && (st->srtg_handle != SESSION_SRTG_HANDLE_INVALID))
	session_rules_table_show_rule (vm, st->srtg_handle, 0, &rmt_ip, 0, 0,
				       0, (fib_proto == FIB_PROTOCOL_IP4));
      goto done;
    }

  /* 2 separate session tables for global entries, 1 for ip4 and 1 for ip6 */
  fib_index = app_namespace_get_fib_index (app_ns, FIB_PROTOCOL_IP4);
  st = session_table_get_for_fib_index (FIB_PROTOCOL_IP4, fib_index);
  if (st && (st->srtg_handle != SESSION_SRTG_HANDLE_INVALID))
    session_rules_table_cli_dump (vm, st->srtg_handle, 0, FIB_PROTOCOL_IP4);

  fib_index = app_namespace_get_fib_index (app_ns, FIB_PROTOCOL_IP6);
  st = session_table_get_for_fib_index (FIB_PROTOCOL_IP6, fib_index);
  if (st && (st->srtg_handle != SESSION_SRTG_HANDLE_INVALID))
    session_rules_table_cli_dump (vm, st->srtg_handle, 0, FIB_PROTOCOL_IP6);
done:
  vec_free (ns_id);
  return 0;
}

void
session_sdl_table_walk4 (u32 srtg_handle, session_sdl_table_walk_fn_t fn,
			 void *args)
{
  ip4_fib_t *fib;
  session_sdl4_fib_show_walk_ctx_t ctx = {
    .ifsw_indicies = NULL,
  };
  fib_node_index_t *fei;
  session_rules_table_t *srt = srtg_handle_to_srt (srtg_handle, 0);
  session_sdl_block_t *sdlb = &srt->sdl_block;
  u32 fib_index = sdlb->ip_fib_index;

  if (fib_index == ~0)
    return;
  fib = ip4_fib_get (fib_index);
  ip4_fib_table_walk (fib, session_sdl4_fib_show_walk_cb, &ctx);
  vec_sort_with_function (ctx.ifsw_indicies, fib_entry_cmp_for_sort);

  vec_foreach (fei, ctx.ifsw_indicies)
    {
      if (*fei != FIB_NODE_INDEX_INVALID &&
	  fib_entry_is_sourced (*fei, sdlm->fib_src))
	{
	  u8 *tag = session_rules_table_rule_tag (srt, *fei, 1);
	  fib_entry_t *fib_entry = fib_entry_get (*fei);
	  fib_prefix_t pfx = fib_entry->fe_prefix;
	  index_t lbi =
	    ip4_fib_forwarding_lookup (fib_index, &pfx.fp_addr.ip4);
	  const dpo_id_t *dpo =
	    load_balance_get_fwd_bucket (load_balance_get (lbi), 0);

	  fn (*fei, &pfx.fp_addr, pfx.fp_len, dpo->dpoi_index,
	      FIB_PROTOCOL_IP4, tag, args);
	}
    }

  vec_free (ctx.ifsw_indicies);
}

void
session_sdl_table_walk6 (u32 srtg_handle, session_sdl_table_walk_fn_t fn,
			 void *args)
{
  ip6_fib_t *fib;
  fib_node_index_t *fei;
  session_sdl6_fib_show_ctx_t ctx = {
    .entries = NULL,
  };
  session_rules_table_t *srt = srtg_handle_to_srt (srtg_handle, 0);
  session_sdl_block_t *sdlb = &srt->sdl_block;
  u32 fib_index = sdlb->ip6_fib_index;

  if (fib_index == ~0)
    return;
  fib = ip6_fib_get (fib_index);
  ip6_fib_table_walk (fib->index, session_sdl6_fib_table_show_walk, &ctx);
  vec_sort_with_function (ctx.entries, fib_entry_cmp_for_sort);

  vec_foreach (fei, ctx.entries)
    {
      if (*fei != FIB_NODE_INDEX_INVALID &&
	  fib_entry_is_sourced (*fei, sdlm->fib_src))
	{
	  u8 *tag = session_rules_table_rule_tag (srt, *fei, 0);
	  fib_entry_t *fib_entry = fib_entry_get (*fei);
	  fib_prefix_t pfx = fib_entry->fe_prefix;
	  index_t lbi =
	    ip6_fib_table_fwding_lookup (fib_index, &pfx.fp_addr.ip6);
	  const dpo_id_t *dpo =
	    load_balance_get_fwd_bucket (load_balance_get (lbi), 0);

	  fn (*fei, &pfx.fp_addr, pfx.fp_len, dpo->dpoi_index,
	      FIB_PROTOCOL_IP6, tag, args);
	}
    }

  vec_free (ctx.entries);
}

int
session_sdl_register_callbacks (session_sdl_callback_fn_t cb)
{
  int i;

  vec_foreach_index (i, sdlm->sdl_callbacks)
    {
      if (cb == *vec_elt_at_index (sdlm->sdl_callbacks, i))
	return -1;
    }
  vec_add1 (sdlm->sdl_callbacks, cb);
  return 0;
}

void
session_sdl_deregister_callbacks (session_sdl_callback_fn_t cb)
{
  int i;

  vec_foreach_index (i, sdlm->sdl_callbacks)
    {
      if (cb == *vec_elt_at_index (sdlm->sdl_callbacks, i))
	{
	  vec_del1 (sdlm->sdl_callbacks, i);
	  break;
	}
    }
}

VLIB_CLI_COMMAND (show_session_sdl_command, static) = {
  .path = "show session sdl",
  .short_help = "show session sdl [appns <id> <rmt-ip>]",
  .function = show_session_sdl_command_fn,
  .is_mp_safe = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
