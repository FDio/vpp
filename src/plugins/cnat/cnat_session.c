/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/stats/stats.h>
#include <vnet/ip/ip.h>
#include <cnat/cnat_session.h>
#include <cnat/cnat_translation.h>
#include <cnat/cnat_inline.h>
#include "cnat_log.h"

#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

cnat_bihash_t cnat_session_db;
/* Index into the double vector for deferred backend deletion.
 * Flipped by the scanner at the start of each full scan cycle (i == 0).
 * cnat_ep_trk_delete_notify writes into slot [state ^ 1] (the inactive
 * slot) while the scanner frees from slot [state] (the active slot).
 * Both the scanner and translation update/delete run on the main thread
 * so no locking is needed — the flip is always observed atomically from
 * the same thread. */
bool ep_trk_del_state;
index_t *cnat_ep_trk_idx_deleted[2];

void
cnat_ep_trk_delete_notify (index_t *trk_index)
{
  vec_add1 (cnat_ep_trk_idx_deleted[ep_trk_del_state ^ 1], *trk_index);
}

void (*cnat_free_port_cb) (u32 fib_index, u16 port, ip_protocol_t iproto);

typedef struct cnat_session_walk_ctx_t_
{
  cnat_session_walk_cb_t cb;
  void *ctx;
} cnat_session_walk_ctx_t;

static int
cnat_session_walk_cb (BVT (clib_bihash_kv) * kv, void *arg)
{
  cnat_session_t *session = (cnat_session_t *) kv;
  cnat_session_walk_ctx_t *ctx = arg;

  ctx->cb (session, ctx->ctx);

  return (BIHASH_WALK_CONTINUE);
}

void
cnat_session_walk (cnat_session_walk_cb_t cb, void *ctx)
{
  cnat_session_walk_ctx_t wctx = {
    .cb = cb,
    .ctx = ctx,
  };
  BV (clib_bihash_foreach_key_value_pair) (&cnat_session_db,
					   cnat_session_walk_cb, &wctx);
}

typedef struct cnat_session_purge_walk_t_
{
  cnat_bihash_kv_t *keys;
} cnat_session_purge_walk_ctx_t;

static int
cnat_session_purge_walk (BVT (clib_bihash_kv) * key, void *arg)
{
  cnat_session_purge_walk_ctx_t *ctx = arg;

  vec_add1 (ctx->keys, *key);

  return (BIHASH_WALK_CONTINUE);
}

u8 *
format_cnat_session_location (u8 *s, va_list *args)
{
  u8 location = va_arg (*args, int);
  switch (location)
    {
    case CNAT_LOCATION_INPUT:
      s = format (s, "input");
      break;
    case CNAT_LOCATION_OUTPUT:
      s = format (s, "output");
      break;
    case CNAT_LOCATION_FIB:
      s = format (s, "fib");
      break;
    default:
      s = format (s, "unknown");
      break;
    }
  return (s);
}

u8 *
format_cnat_session_flags (u8 *s, va_list *args)
{
  u32 flags = va_arg (*args, u32);
  if (flags & CNAT_SESSION_FLAG_HAS_CLIENT)
    s = format (s, "client,");
  if (flags & CNAT_SESSION_IS_RETURN)
    s = format (s, "return");
  return (s);
}

u8 *
format_cnat_timestamp (u8 *s, va_list *args)
{
  cnat_timestamp_t *ts = va_arg (*args, cnat_timestamp_t *);
  u32 indent = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  s = format (s, "%Ulast_seen:%u lifetime:%u ref:%u", format_white_space, indent, ts->last_seen,
	      ts->lifetime, ts->ts_session_refcnt);
  for (int i = 0; i < CNAT_N_LOCATIONS * VLIB_N_DIR; i++)
    if ((verbose > 1) || (ts->ts_rw_bm & (1 << i)))
      s = format (s, "\n%U[%U] %U", format_white_space, indent + 2, format_cnat_rewrite_type, i,
		  format_cnat_rewrite, &ts->cts_rewrites[i]);
  return (s);
}

u8 *
format_cnat_session (u8 * s, va_list * args)
{
  cnat_session_t *sess = va_arg (*args, cnat_session_t *);
  int verbose = va_arg (*args, int);
  u32 indent = format_get_indent (s);
  cnat_timestamp_t *ts = NULL;

  ts = cnat_timestamp_get (sess->value.cs_session_index);
  s = format (s, "%U => [%U]\n%Uindex:%d fib:%d\n%U%U", format_cnat_5tuple, &sess->key.cs_5tuple,
	      format_cnat_session_flags, sess->value.cs_flags, format_white_space, indent + 2,
	      sess->value.cs_session_index, sess->key.fib_index, format_white_space, indent + 2,
	      format_cnat_timestamp, ts, indent + 2, verbose);

  return (s);
}

static int
cnat_show_yield (vlib_main_t *vm, f64 *start)
{
  /* yields for 2 clock ticks every 1 tick to avoid blocking the main thread
   * when dumping huge data structures */
  f64 now = vlib_time_now (vm);
  if (now - *start > 11e-6)
    {
      vlib_process_suspend (vm, 21e-6);
      *start = vlib_time_now (vm);
      return 1;
    }

  return 0;
}

typedef struct
{
  vlib_main_t *vm;
  ip46_address_t ip;
  f64 start;
  u32 fib_index;
  u32 flags;
  int verbose;
  int max;
  u16 port;
  ip_protocol_t proto;
  u8 refcount;
} cnat_session_show_cbak_arg_t;

static int
cnat_session_show_cbak (BVT (clib_bihash_kv) * kvp, void *arg)
{
  const cnat_session_t *s = (void *) kvp;
  cnat_session_show_cbak_arg_t *a = arg;

  cnat_show_yield (a->vm, &a->start);

  if (a->fib_index != ~0 && a->fib_index != s->key.fib_index)
    return BIHASH_WALK_CONTINUE;

  if (a->flags && a->flags != (a->flags & s->value.cs_flags))
    return BIHASH_WALK_CONTINUE;

  if (a->proto && a->proto != s->key.cs_5tuple.iproto)
    return BIHASH_WALK_CONTINUE;

  if (a->port && a->port != s->key.cs_5tuple.port[VLIB_RX] &&
      a->port != s->key.cs_5tuple.port[VLIB_TX])
    return BIHASH_WALK_CONTINUE;

  if (!ip46_address_is_zero (&a->ip) &&
      !ip46_address_is_equal (&a->ip, &s->key.cs_5tuple.ip[VLIB_RX]) &&
      !ip46_address_is_equal (&a->ip, &s->key.cs_5tuple.ip[VLIB_TX]))
    return BIHASH_WALK_CONTINUE;

  if (a->refcount)
    {
      const cnat_timestamp_t *ts = cnat_timestamp_get (s->value.cs_session_index);
      if (a->refcount != ts->ts_session_refcnt)
	return BIHASH_WALK_CONTINUE;
    }

  vlib_cli_output (a->vm, "%U\n", format_cnat_session, s, a->verbose);

  if (a->max-- <= 0)
    {
      vlib_cli_output (a->vm, "Please note: only the first entries displayed. "
			      "To display more, specify max.");
      return BIHASH_WALK_STOP;
    }

  return BIHASH_WALK_CONTINUE;
}

static clib_error_t *
cnat_session_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  cnat_session_show_cbak_arg_t arg = {};
  int v;

  arg.vm = vm;
  arg.start = vlib_time_now (vm);
  arg.fib_index = ~0;
  arg.max = 50;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      arg.verbose = clib_max (arg.verbose, 1);
      if (unformat (input, "verbose %d", &v))
	{
	  arg.verbose = v;
	}
      else if (unformat (input, "return"))
	{
	  arg.flags |= CNAT_SESSION_IS_RETURN;
	}
      else if (unformat (input, "ip %U", unformat_ip46_address, &arg.ip, IP46_TYPE_ANY))
	;
      else if (unformat (input, "port %d", &v))
	arg.port = clib_host_to_net_u16 (v);
      else if (unformat (input, "proto %U", unformat_ip_protocol, &arg.proto))
	;
      else if (unformat (input, "ref %d", &v))
	arg.refcount = v;
      else if (unformat (input, "max %d", &arg.max))
	;
      else if (unformat (input, "fib %u", &arg.fib_index))
	;
      else
	{
	  return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
	}
    }

  vlib_cli_output (vm, "CNat Sessions: now:%f\n%U\n", vlib_time_now (vm), BV (format_bihash),
		   &cnat_session_db, 0 /* verbose */);
  if (arg.verbose)
    BV (clib_bihash_foreach_key_value_pair)
  (&cnat_session_db, cnat_session_show_cbak, &arg);

  return (NULL);
}

VLIB_CLI_COMMAND (cnat_session_show_cmd_node, static) = {
  .path = "show cnat session",
  .function = cnat_session_show,
  .short_help = "show cnat session [verbose <N>] [return] [ip <ip>] [port <port>] "
		"[proto <proto>] [ref <ref>] [max <max>]",
  .is_mp_safe = 1,
};

static_always_inline void
cnat_session_free__ (cnat_session_t *session)
{
  cnat_timestamp_mpool_t *ctm = &cnat_timestamps;
  bool is_v6 = !ip46_address_is_ip4 (&session->key.cs_5tuple.ip[VLIB_TX]);

  cnat_log_session_free (session);
  if (session->value.cs_flags & CNAT_SESSION_FLAG_HAS_CLIENT)
    {
      cnat_client_free_by_ip (&session->key.cs_5tuple.ip[VLIB_TX], session->key.fib_index,
			      1 /* is_session */);
    }
  /* Credit the per-VRF session budget back when the non-return (forward) session is freed.
   * The budget was debited once at timestamp alloc, keyed on the forward session's fib_index.
   * Gating on !IS_RETURN ensures we credit exactly once regardless of the order in which
   * the forward and return sessions are reaped by the scanner. */
  if (!(session->value.cs_flags & CNAT_SESSION_IS_RETURN))
    {
      int *sessions_per_vrf = is_v6 ? ctm->sessions_per_vrf_ip6 : ctm->sessions_per_vrf_ip4;
      clib_rwlock_writer_lock (&ctm->ts_lock);
      vec_elt (sessions_per_vrf, session->key.fib_index)++;
      clib_rwlock_writer_unlock (&ctm->ts_lock);
    }
  cnat_timestamp_free (session->value.cs_session_index, is_v6);
}

/* This is call when adding a session that already exists
 * we need to cleanup refcounts to keep things consistant */
void
cnat_session_free_stale_cb (cnat_bihash_kv_t *kv, void *opaque)
{
  cnat_session_t *session = (cnat_session_t *) kv;
  cnat_log_session_overwrite (session);
  cnat_session_free__ (session);
}

void
cnat_session_free (cnat_session_t * session)
{
  cnat_bihash_kv_t *bkey = (cnat_bihash_kv_t *) session;
  cnat_session_free__ (session);
  cnat_bihash_add_del (&cnat_session_db, bkey, 0 /* is_add */);
}

int
cnat_session_purge (void)
{
  /* flush all the session from the DB */
  cnat_session_purge_walk_ctx_t ctx = { };
  cnat_bihash_kv_t *key;

  BV (clib_bihash_foreach_key_value_pair) (&cnat_session_db,
					   cnat_session_purge_walk, &ctx);

  vec_foreach (key, ctx.keys) cnat_session_free ((cnat_session_t *) key);

  vec_free (ctx.keys);

  return (0);
}

void
cnat_reverse_session_free (cnat_session_t *session)
{
  cnat_bihash_kv_t rkey = { 0 }, rvalue;
  cnat_session_t *rsession = (cnat_session_t *) &rkey;
  cnat_timestamp_t *ts;
  int rv;

  ASSERT (session->value.cs_session_index != 0);
  ts = cnat_timestamp_get (session->value.cs_session_index);
  ASSERT (ts != NULL);

  cnat_timestamp_direction_t dir =
    (session->value.cs_flags & CNAT_SESSION_IS_RETURN) ? CNAT_IS_RETURN : CNAT_IS_FWD;

  if (cnat_get_rsession_from_ts (ts, dir, rsession))
    /* no rewrite found, fallback: swap the session's own 5-tuple */
    cnat_5tuple_copy (&rsession->key.cs_5tuple, &session->key.cs_5tuple, 1 /* swap */);

  if (memcmp (&rsession->key, &session->key, sizeof (session->key)) == 0)
    {
      ASSERT (0 && "same session");
      return;
    }

  rv = cnat_bihash_search_i2 (&cnat_session_db, &rkey, &rvalue);
  if (!rv)
    {
      /* other session is in bihash */
      cnat_session_t *rsession = (cnat_session_t *) &rvalue;
      /* if a session was overwritten (eg. because lack of ports), its
       * 5-tuple could have been reused. */
      if (session->value.cs_session_index == rsession->value.cs_session_index)
	cnat_session_free (rsession);
    }
}

static_always_inline bool
cnat_session_is_stale (cnat_session_t *session, f64 start_time)
{
  /* a session is stale if it is non used until expiration or
  if the backend corresponding to the nat session disappeared */
  if (start_time > cnat_timestamp_exp (session->value.cs_session_index))
    {
      return 1;
    }
  cnat_timestamp_t *ts = cnat_timestamp_get (session->value.cs_session_index);
  /* We only do this for sessions that actually use a tracker
   * this part of the scanner only expires sessions that have a tracker marked for
   * delete */
  if (ts->ts_trk_index != CNAT_EP_TRK_INVALID_INDEX)
    {
      cnat_ep_trk_t *trk_;
      trk_ = &cnat_ep_trk_pool[ts->ts_trk_index];
      if (trk_->ct_flags & CNAT_TRK_MARKED_FOR_DELETE)
	/* the backend corresponding to this session is
	 * deleted, delete the session */
	{
	  return 1;
	}
    }
  return 0;
}

u64
cnat_session_scan (vlib_main_t *vm, f64 start_time, int i)
{
  if (!i)
    {
      /* delete confirmed deleted backends from previous scan
       */
      index_t *slot;
      vec_foreach (slot, cnat_ep_trk_idx_deleted[ep_trk_del_state])
	{
	  cnat_ep_trk_t *ep_trk = &cnat_ep_trk_pool[*slot];
	  pool_put (cnat_ep_trk_pool, ep_trk);
	}
      vec_free (cnat_ep_trk_idx_deleted[ep_trk_del_state]);

      /* Promote "pending deletions" to "confirmed".
       * Using two vecs (pending + confirmed) ensures we scan all sessions
       * once more before actually freeing a backend. Prevents deleting while
       * iterating.
       */
      ep_trk_del_state ^= 1;
    }
  BVT (clib_bihash) * h = &cnat_session_db;
  int j, k;

  cnat_log_scanner_start (i);

  if (!h->instantiated)
    goto out;

  for ( /* caller saves starting point */ ; i < h->nbuckets; i++)
    {
      /* allow no more than 100us without a pause */
      if ((vlib_time_now (vm) - start_time) > 10e-5)
	goto out;

      if (i < (h->nbuckets - 3))
	{
	  BVT (clib_bihash_bucket) * b =
	    BV (clib_bihash_get_bucket) (h, i + 3);
	  clib_prefetch_load (b);
	  b = BV (clib_bihash_get_bucket) (h, i + 1);
	  if (!BV (clib_bihash_bucket_is_empty) (b))
	    {
	      BVT (clib_bihash_value) * v =
		BV (clib_bihash_get_value) (h, b->offset);
	      clib_prefetch_load (v);
	    }
	}

      BVT (clib_bihash_bucket) * b = BV (clib_bihash_get_bucket) (h, i);
      if (BV (clib_bihash_bucket_is_empty) (b))
	continue;
      BVT (clib_bihash_value) * v = BV (clib_bihash_get_value) (h, b->offset);
      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
	    {
	      if (BV (clib_bihash_is_free) (&v->kvp[k]))
		continue;

	      cnat_session_t *session = (cnat_session_t *) & v->kvp[k];
	      if (cnat_session_is_stale (session, start_time))
		{
		  /* age it */
		  cnat_log_session_expire (session);
		  cnat_reverse_session_free (session);
		  /* this should be last as deleting the session memset it to
		   * 0xff */
		  cnat_session_free (session);

		  /*
		   * Note: we may have just freed the bucket's backing
		   * storage, so check right here...
		   */
		  if (BV (clib_bihash_bucket_is_empty) (b))
		    goto doublebreak;
		}
	    }
	  v++;
	}
    doublebreak:
      ;
    }

out:
  cnat_log_scanner_stop (i);
  /* if at the end, return 0 to start again */
  return i < h->nbuckets ? i : 0;
}

static void
cnat_sessions_collect_total_fn (vlib_stats_collector_data_t *d)
{
  const cnat_timestamp_mpool_t *ctm = &cnat_timestamps;
  u32 total = 0;
  int i;
  vec_foreach_index (i, ctm->ts_pools)
    total += pool_elts (vec_elt (ctm->ts_pools, i));
  d->entry->value = total;
}

static clib_error_t *
cnat_session_init (vlib_main_t * vm)
{
  cnat_timestamp_mpool_t *ctm = &cnat_timestamps;

  /* 2 sessions per ts, 60% load */
  u32 session_max = 2.4 * (ctm->pool_max << ctm->log2_pool_sz);
  BV (clib_bihash_init)
  (&cnat_session_db, "CNat Session DB", session_max / BIHASH_KVP_PER_PAGE /* buckets */,
   session_max * sizeof (cnat_bihash_kv_t) * 1.2 /* memory */);
  BV (clib_bihash_set_kvp_format_fn) (&cnat_session_db, format_cnat_session);

  vec_validate_init_empty_aligned (ctm->sessions_per_vrf_ip4, CNAT_FIB_TABLE,
				   ctm->max_sessions_per_vrf, CLIB_CACHE_LINE_BYTES);
  vec_validate_init_empty_aligned (ctm->sessions_per_vrf_ip6, CNAT_FIB_TABLE,
				   ctm->max_sessions_per_vrf, CLIB_CACHE_LINE_BYTES);

  vlib_stats_collector_reg_t reg;
  reg.entry_index = vlib_stats_add_gauge ("/cnat/sessions/total");
  reg.collect_fn = cnat_sessions_collect_total_fn;
  vlib_stats_register_collector_fn (&reg);

  return (NULL);
}

VLIB_INIT_FUNCTION (cnat_session_init);

static clib_error_t *
cnat_timestamp_show (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  cnat_timestamp_mpool_t *ctm = &cnat_timestamps;
  f64 start = vlib_time_now (vm);
  cnat_timestamp_t *ts;
  int ts_cnt = 0, cnt;
  int verbose = 0;
  int i, v;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %d", &v))
	verbose = v;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  vec_foreach_index (i, ctm->ts_pools)
    {
      cnat_timestamp_t *ts_pool = vec_elt (ctm->ts_pools, i);
      cnt = pool_elts (ts_pool);
      ts_cnt += cnt;
      vlib_cli_output (vm, "-- Pool %d [%d/%d]", i, cnt, pool_max_len (ts_pool));
      if (!verbose)
	continue;
      pool_foreach (ts, ts_pool)
	{
	  vlib_cli_output (vm, "[%d] %U", ts - ts_pool, format_cnat_timestamp, ts, 0, verbose);
	  if (cnat_show_yield (vm, &start))
	    {
	      /* we must reload the pool as it might have moved */
	      u32 ii = ts - ts_pool;
	      ts_pool = vec_elt (ctm->ts_pools, i);
	      ts = ts_pool + ii;
	    }
	}
    }
  vlib_cli_output (vm, "Total timestamps %d", ts_cnt);
  return (NULL);
}

VLIB_CLI_COMMAND (cnat_timestamp_show_cmd, static) = {
  .path = "show cnat timestamp",
  .function = cnat_timestamp_show,
  .short_help = "show cnat timestamp [verbose <N>]",
  .is_mp_safe = 1,
};
