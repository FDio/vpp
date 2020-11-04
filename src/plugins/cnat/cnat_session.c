/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vnet/ip/ip.h>
#include <cnat/cnat_session.h>
#include <cnat/cnat_inline.h>

#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

cnat_bihash_t cnat_session_db;
void (*cnat_free_port_cb) (u16 port, ip_protocol_t iproto);

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
format_cnat_session (u8 * s, va_list * args)
{
  cnat_session_t *sess = va_arg (*args, cnat_session_t *);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);
  f64 ts = 0;

  if (!cnat_ts_is_free_index (sess->value.cs_ts_index))
    ts = cnat_timestamp_exp (sess->value.cs_ts_index);

  s = format (
    s, "session:[%U;%d -> %U;%d, %U] => %U;%d -> %U;%d %U lb:%d age:%f",
    format_ip46_address, &sess->key.cs_ip[VLIB_RX], IP46_TYPE_ANY,
    clib_host_to_net_u16 (sess->key.cs_port[VLIB_RX]), format_ip46_address,
    &sess->key.cs_ip[VLIB_TX], IP46_TYPE_ANY,
    clib_host_to_net_u16 (sess->key.cs_port[VLIB_TX]), format_ip_protocol,
    sess->key.cs_proto, format_ip46_address, &sess->value.cs_ip[VLIB_RX],
    IP46_TYPE_ANY, clib_host_to_net_u16 (sess->value.cs_port[VLIB_RX]),
    format_ip46_address, &sess->value.cs_ip[VLIB_TX], IP46_TYPE_ANY,
    clib_host_to_net_u16 (sess->value.cs_port[VLIB_TX]),
    format_cnat_session_location, sess->key.cs_loc, sess->value.cs_lbi, ts);

  return (s);
}

static clib_error_t *
cnat_session_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 verbose = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  vlib_cli_output (vm, "CNat Sessions: now:%f\n%U\n",
		   vlib_time_now (vm),
		   BV (format_bihash), &cnat_session_db, verbose);

  return (NULL);
}

VLIB_CLI_COMMAND (cnat_session_show_cmd_node, static) = {
  .path = "show cnat session",
  .function = cnat_session_show,
  .short_help = "show cnat session",
  .is_mp_safe = 1,
};

void
cnat_session_free (cnat_session_t * session)
{
  cnat_bihash_kv_t *bkey = (cnat_bihash_kv_t *) session;
  /* age it */
  if (session->value.flags & CNAT_SESSION_FLAG_ALLOC_PORT)
    cnat_free_port_cb (session->value.cs_port[VLIB_RX],
		       session->key.cs_proto);
  if (!(session->value.flags & CNAT_SESSION_FLAG_NO_CLIENT))
    cnat_client_free_by_ip (&session->key.cs_ip[VLIB_TX], session->key.cs_af);
  cnat_timestamp_free (session->value.cs_ts_index);

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
  cnat_bihash_kv_t bkey, bvalue;
  cnat_session_t *rsession = (cnat_session_t *) &bkey;
  int rv;

  ip46_address_copy (&rsession->key.cs_ip[VLIB_RX],
		     &session->value.cs_ip[VLIB_TX]);
  ip46_address_copy (&rsession->key.cs_ip[VLIB_TX],
		     &session->value.cs_ip[VLIB_RX]);
  rsession->key.cs_proto = session->key.cs_proto;
  rsession->key.cs_loc = session->key.cs_loc == CNAT_LOCATION_OUTPUT ?
			   CNAT_LOCATION_INPUT :
			   CNAT_LOCATION_OUTPUT;
  rsession->key.__cs_pad = 0;
  rsession->key.cs_af = session->key.cs_af;
  rsession->key.cs_port[VLIB_RX] = session->value.cs_port[VLIB_TX];
  rsession->key.cs_port[VLIB_TX] = session->value.cs_port[VLIB_RX];

  rv = cnat_bihash_search_i2 (&cnat_session_db, &bkey, &bvalue);
  if (!rv)
    {
      /* other session is in bihash */
      cnat_session_t *rsession = (cnat_session_t *) &bvalue;
      cnat_session_free (rsession);
    }
}

u64
cnat_session_scan (vlib_main_t * vm, f64 start_time, int i)
{
  BVT (clib_bihash) * h = &cnat_session_db;
  int j, k;

  if (alloc_arena (h) == 0)
    return 0;

  for ( /* caller saves starting point */ ; i < h->nbuckets; i++)
    {
      /* allow no more than 100us without a pause */
      if ((vlib_time_now (vm) - start_time) > 10e-5)
	return (i);

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

	      if (start_time >
		  cnat_timestamp_exp (session->value.cs_ts_index))
		{
		  /* age it */
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

  /* start again */
  return (0);
}

static clib_error_t *
cnat_session_init (vlib_main_t * vm)
{
  cnat_main_t *cm = &cnat_main;
  BV (clib_bihash_init) (&cnat_session_db,
			 "CNat Session DB", cm->session_hash_buckets,
			 cm->session_hash_memory);
  BV (clib_bihash_set_kvp_format_fn) (&cnat_session_db, format_cnat_session);

  cnat_timestamps.next_empty_pool_idx = 0;
  clib_bitmap_alloc (cnat_timestamps.ts_free, 1 << CNAT_TS_MPOOL_BITS);
  clib_bitmap_set_region (cnat_timestamps.ts_free, 0, 1,
			  1 << CNAT_TS_MPOOL_BITS);
  clib_spinlock_init (&cnat_timestamps.ts_lock);

  return (NULL);
}

VLIB_INIT_FUNCTION (cnat_session_init);

static clib_error_t *
cnat_timestamp_show (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  cnat_timestamp_t *ts;
  int ts_cnt = 0, cnt;
  u8 verbose = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  for (int i = 0; i < cnat_timestamps.next_empty_pool_idx; i++)
    {
      cnt = pool_elts (cnat_timestamps.ts_pools[i]);
      ts_cnt += cnt;
      vlib_cli_output (vm, "-- Pool %d [%d/%d]", i, cnt,
		       pool_header (cnat_timestamps.ts_pools[i])->max_elts);
      if (!verbose)
	continue;
      pool_foreach (ts, cnat_timestamps.ts_pools[i])
	vlib_cli_output (vm, "[%d] last_seen:%f lifetime:%u ref:%u",
			 ts - cnat_timestamps.ts_pools[i], ts->last_seen,
			 ts->lifetime, ts->refcnt);
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
