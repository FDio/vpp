/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vnet/session/session.h>
#include <vnet/session/session_sdl.h>
#include <vnet/tcp/tcp_sdl.h>
#include <plugins/auto_sdl/auto_sdl.h>

static auto_sdl_plugin_methods_t auto_sdl_plugin;
static u32 *asdl_fib_index_to_table_index[2];
static auto_sdl_main_t asdl_main;
static auto_sdl_main_t *asdl = &asdl_main;

VLIB_REGISTER_LOG_CLASS (auto_sdl_log, static) = { .class_name = "auto",
						   .subclass_name = "sdl" };

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (auto_sdl_log._class, "%s: " fmt, __func__, __VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (auto_sdl_log._class, fmt, __VA_ARGS__)
#define log_err(fmt, ...) vlib_log_err (auto_sdl_log._class, fmt, __VA_ARGS__)

static auto_sdl_per_fib_t *
auto_sdlb_get_for_fib_index (u32 fib_proto, u32 fib_index, int alloc)
{
  auto_sdl_per_fib_t *asdlb = 0;
#define AUTO_SDL_FIB_INDEX_VALID_MASK 0x80000000

  if (vec_len (asdl_fib_index_to_table_index[fib_proto]) > fib_index)
    {
      if (asdl_fib_index_to_table_index[fib_proto][fib_index] &
	  AUTO_SDL_FIB_INDEX_VALID_MASK)
	asdlb = pool_elt_at_index (
	  asdl->asdl_pool,
	  (asdl_fib_index_to_table_index[fib_proto][fib_index] &
	   ~AUTO_SDL_FIB_INDEX_VALID_MASK));
    }
  if (alloc && !asdlb)
    {
      vec_validate (asdl_fib_index_to_table_index[fib_proto], fib_index);
      pool_get_zero (asdl->asdl_pool, asdlb);
      asdl_fib_index_to_table_index[fib_proto][fib_index] =
	(AUTO_SDL_FIB_INDEX_VALID_MASK | (asdlb - asdl->asdl_pool));
    }

  return asdlb;
}

static void
auto_sdl_add_del (auto_sdl_mapping_t *mapping, u32 is_add)
{
  session_rule_add_del_args_t args;
  session_table_t *st;
  u32 fib_proto = mapping->prefix.fp_proto;

  st = session_table_get_for_fib_index (fib_proto, mapping->fib_index);
  if (st == 0)
    {
      log_err ("Skipping add/del an SDL entry %%U: session table not found"
	       "for FIB index %u",
	       format_ip46_address, &mapping->prefix.fp_addr, IP46_TYPE_ANY,
	       mapping->fib_index);
      return;
    }

  memset (&args, 0, sizeof (args));
  args.transport_proto = TRANSPORT_PROTO_TCP;

  clib_memcpy (&args.table_args.rmt, &mapping->prefix,
	       sizeof (args.table_args.rmt));
  args.table_args.action_index = mapping->action_index;
  args.table_args.is_add = is_add;
  args.table_args.tag = mapping->tag;
  args.appns_index = *vec_elt_at_index (st->appns_index, 0);
  args.scope = SESSION_RULE_SCOPE_GLOBAL;
  log_debug ("%s sdl entry %U, appns_index %d", is_add ? "added" : "deleted",
	     format_ip46_address, &args.table_args.rmt.fp_addr, IP46_TYPE_ANY,
	     args.appns_index);
  vnet_session_rule_add_del (&args);
}

static void
auto_sdl_free_mapping (auto_sdl_mapping_t *mapping)
{
  u32 is_ip6 = (mapping->prefix.fp_proto == FIB_PROTOCOL_IP6) ? 1 : 0;
  auto_sdl_per_fib_t *asdlb = auto_sdlb_get_for_fib_index (
    mapping->prefix.fp_proto, mapping->fib_index, 0);

  if (!asdlb)
    return;
  if (is_ip6)
    hash_unset_mem_free (&asdlb->auto_sdl_fib_pool,
			 &mapping->prefix.fp_addr.ip6);
  else
    hash_unset (asdlb->auto_sdl_fib_pool, mapping->prefix.fp_addr.ip4.as_u32);
  vec_free (mapping->tag);
  pool_put (asdl->auto_sdl_pool, mapping);
}

static void
auto_sdl_cleanup_by_fib_index (u32 fib_proto, u32 fib_index)
{
  hash_pair_t *p;
  auto_sdl_mapping_t *mapping;
  auto_sdl_per_fib_t *asdlb =
    auto_sdlb_get_for_fib_index (fib_proto, fib_index, 0);
  uword *entry_indicies = NULL, *entry;

  if (!asdlb)
    return;
  hash_foreach_pair (p, asdlb->auto_sdl_fib_pool,
		     ({ vec_add1 (entry_indicies, p->value[0]); }));
  /* Block the worker threads trying to access the lock */
  clib_spinlock_lock_if_init (&asdl->spinlock);
  vec_foreach (entry, entry_indicies)
    {
      mapping = pool_elt_at_index (asdl->auto_sdl_pool, *entry);
      auto_sdl_add_del (mapping, 0);
      TW (tw_timer_stop) (&asdl->tw_wheel, mapping->tw_handle);
      auto_sdl_free_mapping (mapping);
    }
  vec_free (entry_indicies);
  hash_free (asdlb->auto_sdl_fib_pool);
  pool_put (asdl->asdl_pool, asdlb);
  asdl_fib_index_to_table_index[fib_proto][fib_index] &=
    ~AUTO_SDL_FIB_INDEX_VALID_MASK;
  clib_spinlock_unlock_if_init (&asdl->spinlock);
}

static void
auto_sdl_process_expired_timer (vlib_main_t *vm, u32 mi)
{
  u32 pool_index = mi & 0x3FFFFFFF;
  auto_sdl_mapping_t *mapping =
    pool_elt_at_index (asdl->auto_sdl_pool, pool_index);
  u32 is_ip6 = (mapping->prefix.fp_proto == FIB_PROTOCOL_IP6) ? 1 : 0;

  if ((mapping->counter >= asdl->threshold) &&
      (clib_atomic_load_relax_n (&mapping->sdl_added) == 0))
    {
      auto_sdl_add_del (mapping, 1);
      mapping->tw_handle =
	TW (tw_timer_start) (&asdl->tw_wheel, mapping - asdl->auto_sdl_pool,
			     is_ip6, asdl->remove_timeout);
      clib_atomic_store_relax_n (&mapping->sdl_added, 1);
    }
  else
    {
      auto_sdl_add_del (mapping, 0);
      auto_sdl_free_mapping (mapping);
    }
}

static uword
auto_sdl_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  u32 *expired = 0;
  f64 period = 1.0;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, period);

      /* currently no signals are expected - just wait for clock */
      (void) vlib_process_get_events (vm, 0);

      expired = TW (tw_timer_expire_timers_vec) (&asdl->tw_wheel,
						 vlib_time_now (vm), expired);
      if (vec_len (expired) > 0)
	{
	  u32 *mi = 0;

	  clib_spinlock_lock_if_init (&asdl->spinlock);
	  vec_foreach (mi, expired)
	    auto_sdl_process_expired_timer (vm, mi[0]);
	  clib_spinlock_unlock_if_init (&asdl->spinlock);
	  vec_set_len (expired, 0);
	}
    }

  /* unreachable */
  return 0;
}

static void
auto_sdl_init (void)
{
  if (asdl->inited)
    return;
  TW (tw_timer_wheel_init) (&asdl->tw_wheel, NULL, 1.0, ~0);
  asdl->pid = vlib_process_create (vlib_get_main (), "auto sdl process",
				   auto_sdl_process, 16);
  asdl->tw_wheel.last_run_time = vlib_time_now (vlib_get_main ());
  if (vlib_get_thread_main ()->n_vlib_mains > 1)
    clib_spinlock_init (&asdl->spinlock);
  asdl->inited = 1;
}

/*
 * May be called by worker thread
 */
static int
auto_sdl_track_prefix (auto_sdl_track_prefix_args_t *args)
{
  auto_sdl_mapping_t *mapping;
  uword *value;
  vlib_main_t *vm = vlib_get_main ();
  u32 is_ip6 = (args->prefix.fp_proto == FIB_PROTOCOL_IP6) ? 1 : 0;
  u32 time_expired;
  auto_sdl_per_fib_t *asdlb =
    auto_sdlb_get_for_fib_index (args->prefix.fp_proto, args->fib_index, 1);

  if (session_sdl_is_enabled () == 0)
    {
      log_err ("Skipping add an auto SDL entry %%U: session sdl not enabled",
	       format_ip46_address, &args->prefix.fp_addr, IP46_TYPE_ANY);
      return -1;
    }
  if (asdlb == 0 || asdl->auto_sdl_enable == 0)
    return -1;

  /* Obtain the lock, preventing main thread from freeing the hash or mapping
   * entries */
  clib_spinlock_lock_if_init (&asdl->spinlock);
  if (is_ip6)
    {
      if (asdlb->auto_sdl_fib_pool == 0)
	asdlb->auto_sdl_fib_pool =
	  hash_create_mem (0, sizeof (ip46_address_t), sizeof (uword));
      value =
	hash_get_mem (asdlb->auto_sdl_fib_pool, &args->prefix.fp_addr.ip6);
    }
  else
    value =
      hash_get (asdlb->auto_sdl_fib_pool, args->prefix.fp_addr.ip4.as_u32);

  if (value)
    {
      mapping = pool_elt_at_index (asdl->auto_sdl_pool, *value);
      mapping->counter++;
      if ((mapping->counter >= asdl->threshold) &&
	  (clib_atomic_load_relax_n (&mapping->sdl_added) == 0))
	TW (tw_timer_update) (&asdl->tw_wheel, mapping->tw_handle, 0);
    }
  else
    {
      pool_get_zero (asdl->auto_sdl_pool, mapping);
      mapping->counter = 1;
      mapping->fib_index = args->fib_index;
      mapping->action_index = args->action_index;
      if (args->tag)
	mapping->tag = vec_dup (args->tag);
      clib_memcpy (&mapping->prefix, &args->prefix, sizeof (mapping->prefix));
      if (is_ip6)
	hash_set_mem_alloc (&asdlb->auto_sdl_fib_pool,
			    &mapping->prefix.fp_addr.ip6,
			    mapping - asdl->auto_sdl_pool);
      else
	hash_set (asdlb->auto_sdl_fib_pool, args->prefix.fp_addr.ip4.as_u32,
		  mapping - asdl->auto_sdl_pool);
      if (mapping->counter >= asdl->threshold)
	time_expired = 1; // 0 interval is not allowed
      else
	time_expired = clib_atomic_load_relax_n (&asdl->remove_timeout);
      mapping->tw_handle = TW (tw_timer_start) (
	&asdl->tw_wheel, mapping - asdl->auto_sdl_pool, is_ip6, time_expired);
    }
  mapping->last_updated = vlib_time_now (vm);
  clib_spinlock_unlock_if_init (&asdl->spinlock);

  return 0;
}

static void
auto_sdl_cleanup (void)
{
  auto_sdl_mapping_t *mapping;
  int i, fib_index;
  auto_sdl_per_fib_t *asdlb;

  /* Block the worker threads trying to access the lock */
  clib_spinlock_lock_if_init (&asdl->spinlock);
  pool_foreach_index (i, asdl->auto_sdl_pool)
    {
      mapping = pool_elt_at_index (asdl->auto_sdl_pool, i);
      auto_sdl_add_del (mapping, 0);
      TW (tw_timer_stop) (&asdl->tw_wheel, mapping->tw_handle);
      auto_sdl_free_mapping (mapping);
    }
  clib_spinlock_unlock_if_init (&asdl->spinlock);

  vec_foreach_index (fib_index,
		     asdl_fib_index_to_table_index[FIB_PROTOCOL_IP4])
    {
      if (asdl_fib_index_to_table_index[FIB_PROTOCOL_IP4][fib_index] &
	  AUTO_SDL_FIB_INDEX_VALID_MASK)
	{
	  asdlb = pool_elt_at_index (
	    asdl->asdl_pool,
	    (asdl_fib_index_to_table_index[FIB_PROTOCOL_IP4][fib_index] &
	     ~AUTO_SDL_FIB_INDEX_VALID_MASK));
	  hash_free (asdlb->auto_sdl_fib_pool);
	  asdl_fib_index_to_table_index[FIB_PROTOCOL_IP4][fib_index] &=
	    ~AUTO_SDL_FIB_INDEX_VALID_MASK;
	  pool_put (asdl->asdl_pool, asdlb);
	}
    }
  vec_foreach_index (fib_index,
		     asdl_fib_index_to_table_index[FIB_PROTOCOL_IP6])
    {
      if (asdl_fib_index_to_table_index[FIB_PROTOCOL_IP6][fib_index] &
	  AUTO_SDL_FIB_INDEX_VALID_MASK)
	{
	  asdlb = pool_elt_at_index (
	    asdl->asdl_pool,
	    (asdl_fib_index_to_table_index[FIB_PROTOCOL_IP6][fib_index] &
	     ~AUTO_SDL_FIB_INDEX_VALID_MASK));
	  hash_free (asdlb->auto_sdl_fib_pool);
	  asdl_fib_index_to_table_index[FIB_PROTOCOL_IP6][fib_index] &=
	    ~AUTO_SDL_FIB_INDEX_VALID_MASK;
	  pool_put (asdl->asdl_pool, asdlb);
	}
    }
}

static void
auto_sdl_callback (int which, session_sdl_callback_t *args)
{
  switch (which)
    {
    case SESSION_SDL_CALLBACK_CONFIG_DISABLE:
      {
	auto_sdl_config_args_t arg = {
	  .enable = 0,
	};
	auto_sdl_config (&arg);
      }
      break;
    case SESSION_SDL_CALLBACK_TABLE_CLEAN_UP:
      auto_sdl_cleanup_by_fib_index (args->fib_proto, args->fib_index);
      break;
    default:
      break;
    }
}

clib_error_t *
auto_sdl_config (auto_sdl_config_args_t *args)
{
  if (args->enable)
    {
      if (session_sdl_register_callbacks (auto_sdl_callback))
	return clib_error_return (0, "error registering sdl callbacks");
      auto_sdl_init ();
      asdl->remove_timeout = args->remove_timeout;
      asdl->threshold = args->threshold;
      tcp_sdl_enable_disable (auto_sdl_track_prefix);
    }
  else
    {
      tcp_sdl_enable_disable (0);

      /* clean up all auto-sdl entries */
      auto_sdl_cleanup ();
      session_sdl_deregister_callbacks (auto_sdl_callback);
    }

  asdl->auto_sdl_enable = args->enable;

  return 0;
}

static clib_error_t *
auto_sdl_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  auto_sdl_config_args_t args = {
    .remove_timeout = AUTO_SDL_REMOVE_TIMEOUT,
    .threshold = AUTO_SDL_THRESHOLD,
    .enable = ~0,
  };

  if (session_sdl_is_enabled () == 0)
    {
      unformat_skip_line (input);
      vlib_cli_output (vm, "session sdl engine is not enabled");
      goto done;
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	args.enable = 1;
      else if (unformat (input, "disable"))
	args.enable = 0;
      else if (unformat (input, "threshold %d", &args.threshold))
	;
      else if (unformat (input, "remove-timeout %d", &args.remove_timeout))
	;
      else
	{
	  vlib_cli_output (vm, "unknown input `%U'", format_unformat_error,
			   input);
	  goto done;
	}
    }

  if (args.enable == ~0)
    {
      vlib_cli_output (vm, "enable/disable must be entered");
      goto done;
    }

  error = auto_sdl_config (&args);
done:
  return error;
}

VLIB_CLI_COMMAND (auto_sdl_enable_disable, static) = {
  .path = "auto-sdl",
  .short_help =
    "auto-sdl <enable|disable> [threshold <n>] [remove-timeout <t>]",
  .function = auto_sdl_command_fn,
  .is_mp_safe = 1,
};

static void
show_auto_sdl_header (vlib_main_t *vm)
{
  vlib_cli_output (vm, "%-43s %-6s %-7s %-9s %-8s %-9s", "Prefix", "Action",
		   "Counter", "FIB Index", "Age Sec.", "TW Handle");
}

static void
show_auto_sdl_map_entry (vlib_main_t *vm, auto_sdl_mapping_t *mapping, f64 now)
{
  vlib_cli_output (vm, "%-43U %-6u %-7u %-9u %-8.2f %-9u", format_fib_prefix,
		   &mapping->prefix, mapping->action_index, mapping->counter,
		   mapping->fib_index, now - mapping->last_updated,
		   mapping->tw_handle);
}

static int
auto_sdl_mapping_ip4_address_compare (ip4_address_t *a1, ip4_address_t *a2)
{
  return ((clib_net_to_host_u32 (a1->data_u32) >
	   clib_net_to_host_u32 (a2->data_u32)) ?
	    1 :
	    -1);
}

static int
auto_sdl_mapping_ip6_address_compare (ip6_address_t *a1, ip6_address_t *a2)
{
  for (int i = 0; i < ARRAY_LEN (a1->as_u16); i++)
    {
      int cmp = (clib_net_to_host_u16 (a1->as_u16[i]) -
		 clib_net_to_host_u16 (a2->as_u16[i]));
      if (cmp != 0)
	return cmp;
    }
  return 0;
}

static int
auto_sdl_map_entry_cmp_for_sort (void *i1, void *i2)
{
  uword *entry1 = i1, *entry2 = i2;
  auto_sdl_mapping_t *mapping1 =
    pool_elt_at_index (asdl->auto_sdl_pool, *entry1);
  auto_sdl_mapping_t *mapping2 =
    pool_elt_at_index (asdl->auto_sdl_pool, *entry2);
  int cmp = 0;

  switch (mapping1->prefix.fp_proto)
    {
    case FIB_PROTOCOL_IP4:
      cmp = auto_sdl_mapping_ip4_address_compare (
	&mapping1->prefix.fp_addr.ip4, &mapping2->prefix.fp_addr.ip4);
      break;
    case FIB_PROTOCOL_IP6:
      cmp = auto_sdl_mapping_ip6_address_compare (
	&mapping1->prefix.fp_addr.ip6, &mapping2->prefix.fp_addr.ip6);
      break;
    case FIB_PROTOCOL_MPLS:
    default:
      ASSERT (0);
      cmp = 0;
      break;
    }

  if (0 == cmp)
    cmp = (mapping1->prefix.fp_len - mapping2->prefix.fp_len);
  return (cmp);
}

static void
show_auto_sdl_hash (vlib_main_t *vm, auto_sdl_per_fib_t *asdlb, f64 now)
{
  hash_pair_t *p;
  auto_sdl_mapping_t *mapping;
  uword *entry_indicies = NULL, *entry;

  if (!asdlb)
    return;
  hash_foreach_pair (p, asdlb->auto_sdl_fib_pool,
		     ({ vec_add1 (entry_indicies, p->value[0]); }));
  vec_sort_with_function (entry_indicies, auto_sdl_map_entry_cmp_for_sort);
  vec_foreach (entry, entry_indicies)
    {
      mapping = pool_elt_at_index (asdl->auto_sdl_pool, *entry);
      show_auto_sdl_map_entry (vm, mapping, now);
    }
  vec_free (entry_indicies);
}

static void
show_auto_sdl (vlib_main_t *vm, app_namespace_t *app_ns)
{
  f64 now = vlib_time_now (vm);
  u32 fib_index;
  auto_sdl_per_fib_t *asdlb;

  show_auto_sdl_header (vm);
  fib_index = app_namespace_get_fib_index (app_ns, FIB_PROTOCOL_IP4);
  asdlb = auto_sdlb_get_for_fib_index (FIB_PROTOCOL_IP4, fib_index, 0);
  show_auto_sdl_hash (vm, asdlb, now);

  fib_index = app_namespace_get_fib_index (app_ns, FIB_PROTOCOL_IP6);
  asdlb = auto_sdlb_get_for_fib_index (FIB_PROTOCOL_IP6, fib_index, 0);
  show_auto_sdl_hash (vm, asdlb, now);
}

static void
show_auto_sdl_one_entry (vlib_main_t *vm, app_namespace_t *app_ns,
			 ip46_address_t *rmt_ip, u32 fib_proto)
{
  auto_sdl_mapping_t *mapping;
  f64 now = vlib_time_now (vm);
  u32 fib_index;
  auto_sdl_per_fib_t *asdlb;
  uword *value = 0;

  show_auto_sdl_header (vm);
  if (fib_proto == FIB_PROTOCOL_IP6)
    {
      fib_index = app_namespace_get_fib_index (app_ns, fib_proto);
      asdlb = auto_sdlb_get_for_fib_index (fib_proto, fib_index, 0);
      if (asdlb)
	value = hash_get_mem (asdlb->auto_sdl_fib_pool, &rmt_ip->ip6);
    }
  else
    {
      fib_index = app_namespace_get_fib_index (app_ns, fib_proto);
      asdlb = auto_sdlb_get_for_fib_index (fib_proto, fib_index, 0);
      if (asdlb)
	value = hash_get (asdlb->auto_sdl_fib_pool, rmt_ip->ip4.as_u32);
    }
  if (value)
    {
      mapping = pool_elt_at_index (asdl->auto_sdl_pool, *value);
      show_auto_sdl_map_entry (vm, mapping, now);
    }
}

static uword
auto_sdl_pool_size (void)
{
  return (pool_elts (asdl->auto_sdl_pool));
}

static clib_error_t *
show_auto_sdl_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  ip46_address_t rmt_ip;
  u8 show_one = 0;
  app_namespace_t *app_ns = 0;
  u8 *ns_id = 0, fib_proto = FIB_PROTOCOL_IP4;
  int summary = 0;

  if (session_sdl_is_enabled () == 0)
    {
      vlib_cli_output (vm, "session sdl engine is not enabled");
      unformat_skip_line (input);
      goto done;
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "appns %_%s%_", &ns_id))
	;
      else if (unformat (input, "%U", unformat_ip4_address, &rmt_ip.ip4))
	show_one = 1;
      else if (unformat (input, "%U", unformat_ip6_address, &rmt_ip.ip6))
	{
	  fib_proto = FIB_PROTOCOL_IP6;
	  show_one = 1;
	}
      else if (unformat (input, "summary"))
	summary = 1;
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
	  vlib_cli_output (vm, "appns %v doesn't exist", ns_id);
	  goto done;
	}
    }
  else
    app_ns = app_namespace_get_default ();

  if (summary)
    vlib_cli_output (vm, "total number of auto-sdl entries: %lu",
		     auto_sdl_pool_size ());
  else if (show_one)
    show_auto_sdl_one_entry (vm, app_ns, &rmt_ip, fib_proto);
  else
    show_auto_sdl (vm, app_ns);

done:
  vec_free (ns_id);
  return 0;
}

VLIB_CLI_COMMAND (show_auto_sdl_command, static) = {
  .path = "show auto-sdl",
  .short_help = "show auto-sdl [appns <id>] [<rmt-ip>]|[summary]",
  .function = show_auto_sdl_command_fn,
  .is_mp_safe = 1,
};

__clib_export clib_error_t *
auto_sdl_plugin_methods_vtable_init (auto_sdl_plugin_methods_t *m)
{
  m->p_asdl_main = asdl;
#define _(name) m->name = auto_sdl_##name;
  foreach_auto_sdl_plugin_exported_method_name
#undef _
    return 0;
}

static clib_error_t *
auto_sdl_plugin_init (vlib_main_t *vm)
{
  clib_error_t *error = 0;

  error = auto_sdl_plugin_exports_init (&auto_sdl_plugin);
  return error;
}

VLIB_INIT_FUNCTION (auto_sdl_plugin_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
