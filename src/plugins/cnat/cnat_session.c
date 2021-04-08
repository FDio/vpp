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
#include <cnat/cnat_translation.h>

cnat_bihash_t cnat_session_db;
void (*cnat_free_port_cb) (u16 port, ip_protocol_t iproto);

typedef struct cnat_session_walk_ctx_t_
{
  cnat_session_walk_cb_t cb;
  void *ctx;
} cnat_session_walk_ctx_t;

always_inline f64
cnat_timestamp_exp (u32 index, u8 *stale_translation)
{
  f64 t;
  cnat_translation_t *ct;
  if (INDEX_INVALID == index)
    return -1;
  clib_rwlock_reader_lock (&cnat_main.ts_lock);
  cnat_timestamp_t *ts = pool_elt_at_index (cnat_timestamps, index);
  t = ts->last_seen + (f64) ts->lifetime;
  *stale_translation = 0;
  if (INDEX_INVALID != ts->ct_index)
    {
      ct = pool_elt_at_index (cnat_translation_pool, ts->ct_index);
      *stale_translation = ct->flags & CNAT_TRANSLATION_WAIT_SESSION_DEL;
    }
  clib_rwlock_reader_unlock (&cnat_main.ts_lock);
  return t;
}

always_inline void
cnat_timestamp_free (u32 index)
{
  if (INDEX_INVALID == index)
    return;
  clib_rwlock_writer_lock (&cnat_main.ts_lock);
  cnat_timestamp_t *ts = pool_elt_at_index (cnat_timestamps, index);
  ts->refcnt--;
  if (0 == ts->refcnt)
    {
      cnat_translation_timestamp_deleted (ts->ct_index);
      pool_put (cnat_timestamps, ts);
    }
  clib_rwlock_writer_unlock (&cnat_main.ts_lock);
}

static int
cnat_session_walk_cb (clib_bihash_kv_40_56_t *kv, void *arg)
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
  cnat_bihash_foreach_kv_pair (&cnat_session_db, cnat_session_walk_cb, &wctx);
}

typedef struct cnat_session_purge_walk_t_
{
  cnat_bihash_kv_t *keys;
} cnat_session_purge_walk_ctx_t;

static int
cnat_session_purge_walk (clib_bihash_kv_40_56_t *key, void *arg)
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
  u8 stale;
  f64 ts = 0;
  if (!pool_is_free_index (cnat_timestamps, sess->value.cs_ts_index))
    ts = cnat_timestamp_exp (sess->value.cs_ts_index, &stale);

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

  vlib_cli_output (vm, "CNat Sessions: now:%f\n%U\n", vlib_time_now (vm),
		   cnat_bihash_format, &cnat_session_db, verbose);

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

  cnat_bihash_foreach_kv_pair (&cnat_session_db, cnat_session_purge_walk,
			       &ctx);

  vec_foreach (key, ctx.keys) cnat_session_free ((cnat_session_t *) key);

  vec_free (ctx.keys);

  return (0);
}

u64
cnat_session_scan (vlib_main_t * vm, f64 start_time, int i)
{
  cnat_bihash_t *h = &cnat_session_db;
  int j, k;
  f64 exp;
  u8 stale_translation;

  /* Don't scan the l2 fib if it hasn't been instantiated yet */
  if (alloc_arena (h) == 0)
    return 0.0;

  for ( /* caller saves starting point */ ; i < h->nbuckets; i++)
    {
      /* allow no more than 100us without a pause */
      if ((vlib_time_now (vm) - start_time) > 10e-5)
	return (i);

      if (i < (h->nbuckets - 3))
	{
	  cnat_bihash_bucket_t *b = cnat_bihash_get_bucket (h, i + 3);
	  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
	  b = cnat_bihash_get_bucket (h, i + 1);
	  if (!cnat_bihash_bucket_is_empty (b))
	    {
	      cnat_bihash_value_t *v = cnat_bihash_get_value (h, b->offset);
	      CLIB_PREFETCH (v, CLIB_CACHE_LINE_BYTES, LOAD);
	    }
	}

      cnat_bihash_bucket_t *b = cnat_bihash_get_bucket (h, i);
      if (cnat_bihash_bucket_is_empty (b))
	continue;
      cnat_bihash_value_t *v = cnat_bihash_get_value (h, b->offset);
      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
	    {
	      if (v->kvp[k].key[0] == ~0ULL && v->kvp[k].value[0] == ~0ULL)
		continue;

	      cnat_session_t *session = (cnat_session_t *) & v->kvp[k];
	      exp = cnat_timestamp_exp (session->value.cs_ts_index,
					&stale_translation);

	      if (start_time > exp || stale_translation)
		{
		  /* age it */
		  cnat_session_free (session);

		  /*
		   * Note: we may have just freed the bucket's backing
		   * storage, so check right here...
		   */
		  if (cnat_bihash_bucket_is_empty (b))
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
  cnat_bihash_init (&cnat_session_db, "CNat Session DB",
		    cm->session_hash_buckets, cm->session_hash_memory);
  cnat_bihash_set_kvp_format (&cnat_session_db, format_cnat_session);

  return (NULL);
}

VLIB_INIT_FUNCTION (cnat_session_init);

static clib_error_t *
cnat_timestamp_show (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  cnat_timestamp_t *ts;
  clib_rwlock_reader_lock (&cnat_main.ts_lock);
  pool_foreach (ts, cnat_timestamps)
    {
      vlib_cli_output (vm, "[%d] last_seen:%f lifetime:%u ref:%u",
		       ts - cnat_timestamps, ts->last_seen, ts->lifetime,
		       ts->refcnt);
    }
  clib_rwlock_reader_unlock (&cnat_main.ts_lock);
  return (NULL);
}

VLIB_CLI_COMMAND (cnat_timestamp_show_cmd, static) = {
  .path = "show cnat timestamp",
  .function = cnat_timestamp_show,
  .short_help = "show cnat timestamp",
  .is_mp_safe = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
