/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#define _GNU_SOURCE
#include <sys/mman.h>

#include <vppinfra/bihash_24_8.h>
/*
 * Not needed because instanciated in ip6_fib.c
 * #include <vppinfra/bihash_template.c>
 */
#undef __included_bihash_template_inlines_h__
#include <vppinfra/bihash_template_inlines.h>

#include <vppinfra/bihash_32_8.h>
#include <vppinfra/bihash_template.c>

#include <vppinfra/bihash_40_8.h>
/*
 * Not needed because instanciated in ip6_forward.c
 * #include <vppinfra/bihash_template.c>
 */
#undef __included_bihash_template_inlines_h__
#include <vppinfra/bihash_template_inlines.h>

#include <vppinfra/bihash_48_8.h>
/*
 * Not needed because instanciated in session_lookup.c
 * #include <vppinfra/bihash_template.c>
 */
#undef __included_bihash_template_inlines_h__
#include <vppinfra/bihash_template_inlines.h>

#include <vppinfra/bihash_56_8.h>
#include <vppinfra/bihash_template.c>

#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/lookup/lookup_inlines.h>
#include <vnet/sfdp/service.h>
#include <vnet/sfdp/timer/timer.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/ip/reass/ip6_sv_reass.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/sfdp/service.h>
#define SFDP_DEFAULT_BITMAP SFDP_SERVICE_MASK (drop)

SFDP_SERVICE_DECLARE (drop)

sfdp_main_t sfdp_main;

static void
sfdp_init_ptd_counters ()
{
  sfdp_main_t *sfdp = &sfdp_main;
#define _(x, y)                                                               \
  u8 *name = format (0, y "%c", 0);                                           \
  u8 *stat_seg_name = format (0, "/sfdp/per_flow_counters/" y "%c", 0);       \
  sfdp->per_session_ctr[SFDP_FLOW_COUNTER_##x].name = (char *) name;          \
  sfdp->per_session_ctr[SFDP_FLOW_COUNTER_##x].stat_segment_name =            \
    (char *) stat_seg_name;                                                   \
  vlib_validate_combined_counter (                                            \
    &sfdp->per_session_ctr[SFDP_FLOW_COUNTER_##x],                            \
    1ULL << (sfdp->log2_sessions + 1));

  foreach_sfdp_flow_counter
#undef _
}

static void
sfdp_init_tenant_counters (sfdp_main_t *sfdp)
{
#define _(x, y, z)                                                            \
  sfdp->tenant_session_ctr[SFDP_TENANT_SESSION_COUNTER_##x].name = y;         \
  sfdp->tenant_session_ctr[SFDP_TENANT_SESSION_COUNTER_##x]                   \
    .stat_segment_name = "/sfdp/per_tenant_counters/" y;                      \
  vlib_validate_simple_counter (                                              \
    &sfdp->tenant_session_ctr[SFDP_TENANT_SESSION_COUNTER_##x],               \
    1ULL << (1 + sfdp->log2_tenants));

  foreach_sfdp_tenant_session_counter
#undef _
#define _(x, y, z)                                                            \
  sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_##x].name = y;               \
  sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_##x].stat_segment_name =     \
    "/sfdp/per_tenant_counters/" y;                                           \
  vlib_validate_combined_counter (                                            \
    &sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_##x],                     \
    1ULL << (1 + sfdp->log2_tenants));

    foreach_sfdp_tenant_data_counter
#undef _
}

static void
sfdp_init_main_if_needed (sfdp_main_t *sfdp)
{
  static u32 done = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  if (done)
    return;
  time_t epoch = time (NULL);
  uword log_n_thread = max_log2 (tm->n_vlib_mains);
  uword template_shift =
    SFDP_SESSION_ID_TOTAL_BITS - SFDP_SESSION_ID_EPOCH_N_BITS - log_n_thread;
  sfdp->session_id_ctr_mask = (((u64) 1 << template_shift) - 1);
  /* initialize per-thread data */
  vec_validate (sfdp->per_thread_data, tm->n_vlib_mains - 1);
  for (int i = 0; i < tm->n_vlib_mains; i++)
    {
      sfdp_per_thread_data_t *ptd =
	vec_elt_at_index (sfdp->per_thread_data, i);
      ptd->expired_sessions = 0;
      ptd->session_id_template = (u64) epoch
				 << (template_shift + log_n_thread);
      ptd->session_id_template |= (u64) i << template_shift;
      ptd->session_freelist = 0;
    }
  if (vlib_num_workers ())
    clib_spinlock_init (&sfdp->session_lock);

  pool_init_fixed (sfdp->sessions, sfdp_num_sessions ());
  sfdp->free_sessions = sfdp_num_sessions ();
  sfdp_init_ptd_counters ();
  pool_init_fixed (sfdp->tenants, 1ULL << sfdp->log2_tenants);

  sfdp_init_tenant_counters (sfdp);

  clib_bihash_init_24_8 (&sfdp->table4, "sfdp ipv4 session table",
			 sfdp_ip4_num_buckets (), sfdp_ip4_mem_size ());
  clib_bihash_init_48_8 (&sfdp->table6, "sfdp ipv6 session table",
			 sfdp_ip6_num_buckets (), sfdp_ip6_mem_size ());
  clib_bihash_init_8_8 (&sfdp->tenant_idx_by_id, "sfdp tenant table",
			sfdp_tenant_num_buckets (), sfdp_tenant_mem_size ());
  clib_bihash_init_8_8 (&sfdp->session_index_by_id, "session idx by id",
			sfdp_ip4_num_buckets (), sfdp_ip4_mem_size ());

  sfdp->icmp4_error_frame_queue_index =
    vlib_frame_queue_main_init (sfdp_lookup_ip4_icmp_node.index, 0);
  sfdp->icmp6_error_frame_queue_index =
    vlib_frame_queue_main_init (sfdp_lookup_ip6_icmp_node.index, 0);

  /* User timer as default if no other has been registered yet. */
  if (!sfdp->expiry_callbacks.expire_or_evict_sessions)
    {
      sfdp_timer_register_as_expiry_module ();
    }

  done = 1;
}

static clib_error_t *
sfdp_init (vlib_main_t *vm)
{
  sfdp_main_t *sfdp = &sfdp_main;
  clib_error_t *err;
#define _(val, default) sfdp->val = sfdp->val ? sfdp->val : default;

  _ (log2_sessions, SFDP_DEFAULT_LOG2_SESSIONS)
  _ (log2_sessions_cache_per_thread,
     SFDP_DEFAULT_LOG2_SESSIONS - SFDP_DEFAULT_LOG2_SESSIONS_CACHE_RATIO)
  _ (log2_tenants, SFDP_DEFAULT_LOG2_TENANTS)
#undef _
  sfdp->no_main = sfdp->no_main && vlib_num_workers ();

  /* sfdp->eviction_sessions_margin came from early_config */
  if ((err = sfdp_set_eviction_sessions_margin (
	 sfdp->eviction_sessions_margin)) != 0)
    return err;

  // vlib_call_init_function (vm, sfdp_service_init);
  return 0;
}

void
sfdp_tenant_clear_counters (sfdp_main_t *sfdp, sfdp_tenant_index_t tenant_idx)
{
#define _(x, y, z)                                                            \
  sfdp->tenant_session_ctr[SFDP_TENANT_SESSION_COUNTER_##x].name = y;         \
  sfdp->tenant_session_ctr[SFDP_TENANT_SESSION_COUNTER_##x]                   \
    .stat_segment_name = "/sfdp/per_tenant_counters/" y;                      \
  vlib_zero_simple_counter (                                                  \
    &sfdp->tenant_session_ctr[SFDP_TENANT_SESSION_COUNTER_##x], tenant_idx);

  foreach_sfdp_tenant_session_counter
#undef _
#define _(x, y, z)                                                            \
  sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_##x].name = y;               \
  sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_##x].stat_segment_name =     \
    "/sfdp/per_tenant_counters/" y;                                           \
  vlib_zero_combined_counter (                                                \
    &sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_##x], tenant_idx);

    foreach_sfdp_tenant_data_counter
#undef _
}

static void
sfdp_tenant_init_timeouts (sfdp_tenant_t *tenant)
{
  for (u32 idx = 0; idx < SFDP_MAX_TIMEOUTS; idx++)
    {
      tenant->timeouts[idx] = sfdp_main.timeouts[idx].val;
    }
}

static void
sfdp_tenant_init_sp_nodes (sfdp_tenant_t *tenant)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_t *node;

#define _(sym, default, str)                                                  \
  node = vlib_get_node_by_name (vm, (u8 *) (default));                        \
  tenant->sp_node_indices[SFDP_SP_NODE_##sym] = node->index;

  foreach_sfdp_sp_node
#undef _
}

clib_error_t *
sfdp_tenant_add_del (sfdp_main_t *sfdp, sfdp_tenant_id_t tenant_id, u32 context_id, u8 is_del)
{
  sfdp_init_main_if_needed (sfdp);
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  clib_error_t *err = 0;
  sfdp_tenant_t *tenant;
  sfdp_tenant_index_t tenant_idx;
  u32 n_tenants = pool_elts (sfdp->tenants);
  if (!is_del)
    {
      if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
	{
	  pool_get (sfdp->tenants, tenant);
	  tenant_idx = tenant - sfdp->tenants;
	  tenant->bitmaps[SFDP_FLOW_FORWARD] = SFDP_DEFAULT_BITMAP;
	  tenant->bitmaps[SFDP_FLOW_REVERSE] = SFDP_DEFAULT_BITMAP;
	  tenant->tenant_id = tenant_id;
	  tenant->context_id = context_id;
	  sfdp_tenant_init_timeouts (tenant);
	  sfdp_tenant_init_sp_nodes (tenant);
	  kv.key = tenant_id;
	  kv.value = tenant_idx;
	  clib_bihash_add_del_8_8 (&sfdp->tenant_idx_by_id, &kv, 1);
	  sfdp_tenant_clear_counters (sfdp, tenant_idx);
	}
      else
	{
	  err = clib_error_return (0,
				   "Can't create tenant with id %d"
				   " (already exists with index %d)",
				   tenant_id, kv.value);
	}
    }
  else
    {
      if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
	{
	  err = clib_error_return (0,
				   "Can't delete tenant with id %d"
				   " (not found)",
				   tenant_id);
	}
      else
	{
	  sfdp_tenant_clear_counters (sfdp, kv.value);
	  pool_put_index (sfdp->tenants, kv.value);
	  clib_bihash_add_del_8_8 (&sfdp->tenant_idx_by_id, &kv, 0);
	  /* TODO: Notify other users of "tenants" (like gw)?
	   * maybe cb list? */
	}
    }
  if (!err && ((n_tenants == 1 && is_del) || (n_tenants == 0 && !is_del)))
    sfdp_enable_disable_expiry (is_del);
  return err;
}

clib_error_t *
sfdp_set_services (sfdp_main_t *sfdp, sfdp_tenant_id_t tenant_id, sfdp_bitmap_t bitmap,
		   u8 direction)
{
  sfdp_init_main_if_needed (sfdp);
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  sfdp_tenant_t *tenant;
  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return clib_error_return (
      0, "Can't assign service map: tenant id %d not found", tenant_id);

  tenant = sfdp_tenant_at_index (sfdp, kv.value);
  tenant->bitmaps[direction] = bitmap;
  return 0;
}

clib_error_t *
sfdp_set_timeout (sfdp_main_t *sfdp, sfdp_tenant_id_t tenant_id, u32 timeout_idx, u32 timeout_val)
{
  sfdp_init_main_if_needed (sfdp);
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  sfdp_tenant_t *tenant;
  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return clib_error_return (
      0, "Can't configure timeout: tenant id %d not found", tenant_id);
  tenant = sfdp_tenant_at_index (sfdp, kv.value);
  tenant->timeouts[timeout_idx] = timeout_val;
  return 0;
}

clib_error_t *
sfdp_set_sp_node (sfdp_main_t *sfdp, sfdp_tenant_id_t tenant_id, u32 sp_index, u32 node_index)
{
  sfdp_init_main_if_needed (sfdp);
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  sfdp_tenant_t *tenant;
  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return clib_error_return (
      0, "Can't configure slow path node: tenant id %d not found", tenant_id);
  tenant = sfdp_tenant_at_index (sfdp, kv.value);
  tenant->sp_node_indices[sp_index] = node_index;
  return 0;
}

clib_error_t *
sfdp_set_icmp_error_node (sfdp_main_t *sfdp, sfdp_tenant_id_t tenant_id, u8 is_ip6, u32 node_index)
{
  sfdp_init_main_if_needed (sfdp);
  vlib_main_t *vm = vlib_get_main ();
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  sfdp_tenant_t *tenant;
  uword next_index;
  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return clib_error_return (
      0, "Can't configure icmp error node: tenant id %d not found", tenant_id);
  tenant = sfdp_tenant_at_index (sfdp, kv.value);
  if (is_ip6)
    {
      next_index =
	vlib_node_add_next (vm, sfdp_lookup_ip6_icmp_node.index, node_index);
      tenant->icmp6_lookup_next = next_index;
    }
  else
    {
      next_index =
	vlib_node_add_next (vm, sfdp_lookup_ip4_icmp_node.index, node_index);
      tenant->icmp4_lookup_next = next_index;
    }
  return 0;
}

static void
sfdp_expire_session_now (sfdp_session_t *session, f64 now)
{
  u16 thread_index = session->owning_thread_index;
  if (thread_index == SFDP_UNBOUND_THREAD_INDEX)
    thread_index = 0;

  sfdp_timer_per_thread_data_t *tptd = sfdp_timer_get_per_thread_data (thread_index);
  sfdp_session_timer_t *timer = SFDP_SESSION_TIMER (session);

  sfdp_session_timer_update_maybe_past (&tptd->wheel, timer, now, 0);
  tptd->current_time = now;
}

clib_error_t *
sfdp_kill_session (sfdp_main_t *sfdp, u32 session_index, u8 is_all)
{
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);
  sfdp_session_t *session;
  uword index;

  if (vec_len (sfdp_timer_main.per_thread_data) == 0)
    return clib_error_return (0, "sfdp timer module is not initialized");

  if (is_all)
    {
      sfdp_foreach_session (sfdp, index, session) { sfdp_expire_session_now (session, now); }
      return 0;
    }

  session = sfdp_session_at_index_if_valid (session_index);
  if (!session)
    return clib_error_return (0, "Session index %u not found", session_index);

  sfdp_expire_session_now (session, now);
  return 0;
}

int
sfdp_create_session (vlib_main_t *vm, vlib_buffer_t *b, u32 context_id,
		     u32 thread_index, u32 tenant_index, u32 *session_index,
		     int is_ipv6)
{
  return sfdp_create_session_with_scope_index (
    vm, b, context_id, thread_index, tenant_index, session_index, 0, is_ipv6);
}

int
sfdp_create_session_with_scope_index (vlib_main_t *vm, vlib_buffer_t *b,
				      u32 context_id, u32 thread_index,
				      u32 tenant_index, u32 *session_index,
				      u32 scope_index, int is_ipv6)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_session_ip4_key_t k4 = {};
  sfdp_session_ip6_key_t k6 = {};
  void *k = is_ipv6 ? (void *) &k6 : (void *) &k4;
  u64 lookup_val = 0, h = 0;
  i16 l4_hdr_offset = 0;
  u8 slow_path = 0;
  sfdp_tenant_t *tenant = sfdp_tenant_at_index (sfdp, tenant_index);
  sfdp_per_thread_data_t *ptd = 0;
  f64 time_now = vlib_time_now (vm);
  u8 bound_to_thread = (u16) thread_index != SFDP_UNBOUND_THREAD_INDEX;

  if (bound_to_thread)
    ptd = vec_elt_at_index (sfdp->per_thread_data, thread_index);

  if (is_ipv6)
    {
      sfdp_calc_key_v6 (b, context_id, k, &lookup_val, &h, &l4_hdr_offset,
			slow_path);
    }
  else
    {
      sfdp_calc_key_v4 (b, context_id, k, &lookup_val, &h, &l4_hdr_offset,
			slow_path);
    }
  int err = sfdp_create_session_inline (sfdp, ptd, tenant, tenant_index,
					thread_index, time_now, k, &h,
					&lookup_val, scope_index, is_ipv6);

  if (bound_to_thread && err == 0)
    {
      *session_index = sfdp_session_index_from_lookup (lookup_val);
      sfdp_notify_new_sessions (sfdp, session_index, 1);
    }
  return err;
}

void
sfdp_normalise_ip4_key (sfdp_session_t *session,
			sfdp_session_ip4_key_t *result, u8 key_idx)
{
  sfdp_session_ip4_key_t *skey = &session->keys[key_idx].key4;
  sfdp_ip4_key_t *key = &skey->ip4_key;
  u8 pseudo_dir = session->pseudo_dir[key_idx];
  u8 proto = session->proto;
  u8 with_port = proto == IP_PROTOCOL_UDP || proto == IP_PROTOCOL_TCP ||
		 proto == IP_PROTOCOL_ICMP;

  result->ip4_key.as_u64x2 = key->as_u64x2;
  result->as_u64 = skey->as_u64;
  if (with_port && pseudo_dir)
    {
      result->ip4_key.ip_addr_lo = key->ip_addr_hi;
      result->ip4_key.port_lo = clib_net_to_host_u16 (key->port_hi);
      result->ip4_key.ip_addr_hi = key->ip_addr_lo;
      result->ip4_key.port_hi = clib_net_to_host_u16 (key->port_lo);
    }
  else
    {
      result->ip4_key.ip_addr_lo = key->ip_addr_lo;
      result->ip4_key.port_lo = clib_net_to_host_u16 (key->port_lo);
      result->ip4_key.ip_addr_hi = key->ip_addr_hi;
      result->ip4_key.port_hi = clib_net_to_host_u16 (key->port_hi);
    }
}

void
sfdp_normalise_ip6_key (sfdp_session_t *session,
			sfdp_session_ip6_key_t *result, u8 key_idx)
{
  sfdp_session_ip6_key_t *skey = &session->keys[key_idx].key6;
  sfdp_ip6_key_t *key = &skey->ip6_key;
  u8 pseudo_dir = session->pseudo_dir[key_idx];
  u8 proto = session->proto;
  u8 with_port = proto == IP_PROTOCOL_UDP || proto == IP_PROTOCOL_TCP ||
		 proto == IP_PROTOCOL_ICMP;

  result->ip6_key.as_u64x4 = key->as_u64x4;
  result->as_u64 = skey->as_u64;
  if (with_port && pseudo_dir)
    {
      result->ip6_key.ip6_addr_lo = key->ip6_addr_hi;
      result->ip6_key.port_lo = clib_net_to_host_u16 (key->port_hi);
      result->ip6_key.ip6_addr_hi = key->ip6_addr_lo;
      result->ip6_key.port_hi = clib_net_to_host_u16 (key->port_lo);
    }
  else
    {
      result->ip6_key.ip6_addr_lo = key->ip6_addr_lo;
      result->ip6_key.port_lo = clib_net_to_host_u16 (key->port_lo);
      result->ip6_key.ip6_addr_hi = key->ip6_addr_hi;
      result->ip6_key.port_hi = clib_net_to_host_u16 (key->port_hi);
    }
}

int
sfdp_bihash_add_del_inline_with_hash_24_8 (clib_bihash_24_8_t *h,
					   clib_bihash_kv_24_8_t *kv, u64 hash,
					   u8 is_add)
{
  return clib_bihash_add_del_inline_with_hash_24_8 (h, kv, hash, is_add, 0, 0,
						    0, 0);
}

int
sfdp_bihash_add_del_inline_with_hash_48_8 (clib_bihash_48_8_t *h,
					   clib_bihash_kv_48_8_t *kv, u64 hash,
					   u8 is_add)
{
  return clib_bihash_add_del_inline_with_hash_48_8 (h, kv, hash, is_add, 0, 0,
						    0, 0);
}

static clib_error_t *
sfdp_config (vlib_main_t *vm, unformat_input_t *input)
{
  sfdp_main_t *sfdp = &sfdp_main;
  u32 eviction_sessions_margin = ~0;
  u8 sessions_cache_specified = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sessions-log2 %u", &sfdp->log2_sessions))
	;
      else if (unformat (input, "sessions-per-thread-cache-log2 %u",
			 &sfdp->log2_sessions_cache_per_thread))
	{
	  sessions_cache_specified = 1;
	}
      else if (unformat (input, "tenants-log2 %u", &sfdp->log2_tenants))
	;
      else if (unformat (input, "eviction-sessions-margin %u",
			 &eviction_sessions_margin))
	;
      else if (unformat (input, "no-main"))
	{
	  /* Disable only if there are workers */
	  if (vlib_num_workers ())
	    sfdp->no_main = 1;
	  else
	    clib_warning ("Ignoring no-main option: no workers");
	}
      else
	{
	  return clib_error_return (0, "Invalid SFDP plugin config");
	}
    }

  if (!sessions_cache_specified)
    {
      if (sfdp->log2_sessions > SFDP_DEFAULT_LOG2_SESSIONS_CACHE_RATIO + 4)
	{
	  sfdp->log2_sessions_cache_per_thread =
	    sfdp->log2_sessions - SFDP_DEFAULT_LOG2_SESSIONS_CACHE_RATIO;
	}
      else
	{
	  /* If the total number of sessions is really small (can happen in
	   * tests) we don't use session caching by default to protect against
	   * exhaustion. */
	  sfdp->log2_sessions_cache_per_thread = 0;
	}
    }

  sfdp->eviction_sessions_margin = eviction_sessions_margin;

  return 0;
}

/* sfdp { [sessions-log2 <n>] [tenants-log2 <n>] [eviction-sessions-margin <n>]
 * } config. */
VLIB_EARLY_CONFIG_FUNCTION (sfdp_config, "sfdp");

VLIB_INIT_FUNCTION (sfdp_init);
