/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/stats/stats.h>
#include <vnet/ip/ip.h>
#include <cnat/cnat_session.h>
#include <cnat/cnat_inline.h>
#include "cnat_log.h"

#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

cnat_bihash_t cnat_session_db;

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

  s = format (s, "%Ulast_seen:%u lifetime:%u ref:%u", format_white_space, indent, ts->last_seen,
	      ts->lifetime, ts->ts_session_refcnt);
  for (int i = 0; i < CNAT_N_LOCATIONS * VLIB_N_DIR; i++)
    if (ts->ts_rw_bm & (1 << i))
      s = format (s, "\n%U[%U] %U", format_white_space, indent + 2, format_cnat_rewrite_type, i,
		  format_cnat_rewrite, &ts->cts_rewrites[i]);

  return (s);
}

u8 *
format_cnat_session (u8 * s, va_list * args)
{
  cnat_session_t *sess = va_arg (*args, cnat_session_t *);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);
  u32 indent = format_get_indent (s);
  cnat_timestamp_t *ts = NULL;

  ts = cnat_timestamp_get (sess->value.cs_session_index);
  s = format (s, "%U => [%U]\n%U%U", format_cnat_5tuple, &sess->key.cs_5tuple,
	      format_cnat_session_flags, sess->value.cs_flags, format_white_space, indent + 2,
	      format_cnat_timestamp, ts, indent + 2);

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
      if (unformat (input, "verbose"))
	{
	  arg.verbose = 1;
	}
      else if (unformat (input, "return"))
	{
	  arg.verbose = 1;
	  arg.flags |= CNAT_SESSION_IS_RETURN;
	}
      else if (unformat (input, "ip %U", unformat_ip46_address, &arg.ip, IP46_TYPE_ANY))
	{
	  arg.verbose = 1;
	}
      else if (unformat (input, "port %d", &v))
	{
	  arg.verbose = 1;
	  arg.port = clib_host_to_net_u16 (v);
	}
      else if (unformat (input, "proto %U", unformat_ip_protocol, &arg.proto))
	{
	  arg.verbose = 1;
	}
      else if (unformat (input, "ref %d", &v))
	{
	  arg.verbose = 1;
	  arg.refcount = v;
	}
      else if (unformat (input, "max %d", &arg.max))
	{
	  arg.verbose = 1;
	}
      else if (unformat (input, "fib %u", &arg.fib_index))
	{
	  arg.verbose = 1;
	}
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
  .short_help = "show cnat session [verbose] [return] [ip <ip>] [port <port>] "
		"[proto <proto>] [ref <ref>] [max <max>]",
  .is_mp_safe = 1,
};

static_always_inline void
cnat_session_free__ (cnat_session_t *session)
{
  cnat_log_session_free (session);
  if (session->value.cs_flags & CNAT_SESSION_FLAG_HAS_CLIENT)
    {
      cnat_client_free_by_ip (&session->key.cs_5tuple.ip[VLIB_TX], session->key.fib_index,
			      1 /* is_session */);
    }
  cnat_timestamp_free (session->value.cs_session_index,
		       !ip46_address_is_ip4 (&session->key.cs_5tuple.ip[VLIB_TX]) /*is_v6 */);
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

static int
cnat_reverse_session_key (cnat_session_t *rsession, const cnat_timestamp_t *ts,
			  const cnat_session_location_t loc, const cnat_timestamp_direction_t dir,
			  const cnat_timestamp_direction_t rdir)
{
  const cnat_timestamp_rewrite_t *rw, *rrw;
  u8 rw_index = loc + dir;
  u8 rrw_index = loc + rdir;
  u8 rw_bm = (1 << rw_index) | (1 << rrw_index);

  if ((ts->ts_rw_bm & rw_bm) != rw_bm)
    return 0;

  rw = &ts->cts_rewrites[rw_index];
  if (rw->cts_flags & CNAT_TS_RW_FLAG_NO_NAT)
    return 0;

  rrw = &ts->cts_rewrites[rrw_index];

  cnat_5tuple_copy (&rsession->key.cs_5tuple, &rw->tuple, 1);
  rsession->key.fib_index = rrw->fib_index;
  return 1;
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

  /* Go through all the available rewrites for the session we have
   * find the closest to the output or return the input 5tuple */

  /* 1st determine directions to use */
  cnat_timestamp_direction_t dir, rdir;
  if (session->value.cs_flags & CNAT_SESSION_IS_RETURN)
    {
      dir = CNAT_IS_RETURN;
      rdir = CNAT_IS_FWD;
    }
  else
    {
      dir = CNAT_IS_FWD;
      rdir = CNAT_IS_RETURN;
    }

  /* try to find the right rewrite: INPUT > FIB > OUTPUT */
  if (cnat_reverse_session_key (rsession, ts, CNAT_LOCATION_INPUT, dir, rdir))
    ;
  else if (cnat_reverse_session_key (rsession, ts, CNAT_LOCATION_FIB, dir, rdir))
    ;
  else if (cnat_reverse_session_key (rsession, ts, CNAT_LOCATION_OUTPUT, dir, rdir))
    ;
  else
    {
      /* nothing found, try to just swap the 5tuple... */
      cnat_5tuple_copy (&rsession->key.cs_5tuple, &session->key.cs_5tuple, 1 /* swap */);
      rsession->key.fib_index = session->key.fib_index;
    }

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
      /* if a session was overwritten (eg. because lack of ports), it's
       * 5-tuple could have been reused. */
      if (session->value.cs_session_index == rsession->value.cs_session_index)
	cnat_session_free (rsession);
    }
}

u64
cnat_session_scan (vlib_main_t * vm, f64 start_time, int i)
{
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

	      if (start_time > cnat_timestamp_exp (session->value.cs_session_index))
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
  u8 verbose = 0;
  int i;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
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
	  vlib_cli_output (vm, "[%d] %U", ts - ts_pool, format_cnat_timestamp, ts, 0);
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
  .short_help = "show cnat timestamp [verbose]",
  .is_mp_safe = 1,
};
