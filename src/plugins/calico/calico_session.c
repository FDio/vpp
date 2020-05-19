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
#include <calico/calico_session.h>

#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>


clib_bihash_40_48_t calico_session_db;


typedef struct calico_session_walk_ctx_t_
{
  calico_session_walk_cb_t cb;
  void *ctx;
} calico_session_walk_ctx_t;

static int
calico_session_walk_cb (BVT (clib_bihash_kv) * kv, void *arg)
{
  calico_session_t *session = (calico_session_t *) kv;
  calico_session_walk_ctx_t *ctx = arg;

  ctx->cb (session, ctx->ctx);

  return (BIHASH_WALK_CONTINUE);
}

void
calico_session_walk (calico_session_walk_cb_t cb, void *ctx)
{
  calico_session_walk_ctx_t wctx = {
    .cb = cb,
    .ctx = ctx,
  };
  BV (clib_bihash_foreach_key_value_pair) (&calico_session_db,
					   calico_session_walk_cb, &wctx);
}

typedef struct calico_session_purge_walk_t_
{
  clib_bihash_kv_40_48_t *keys;
} calico_session_purge_walk_ctx_t;

static int
calico_session_purge_walk (BVT (clib_bihash_kv) * key, void *arg)
{
  calico_session_purge_walk_ctx_t *ctx = arg;

  vec_add1 (ctx->keys, *key);

  return (BIHASH_WALK_CONTINUE);
}

int
calico_session_purge (void)
{
  /* flush all the session from the DB */
  calico_session_purge_walk_ctx_t ctx = { };
  clib_bihash_kv_40_48_t *key;

  BV (clib_bihash_foreach_key_value_pair) (&calico_session_db,
					   calico_session_purge_walk, &ctx);

  vec_foreach (key, ctx.keys)
    BV (clib_bihash_add_del) (&calico_session_db, key, 0);

  vec_free (ctx.keys);

  return (0);
}

u8 *
format_calico_session (u8 * s, va_list * args)
{
  calico_session_t *sess = va_arg (*args, calico_session_t *);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);
  f64 ts = 0;
  if (!pool_is_free_index (calico_timestamps, sess->value.cs_ts_index))
    ts = calico_timestamp_exp (sess->value.cs_ts_index);

  s =
    format (s,
	    "session:[%U;%d -> %U;%d, %U] => %U;%d -> %U;%d lb:%d age:%f",
	    format_ip46_address, &sess->key.cs_ip[VLIB_RX], IP46_TYPE_ANY,
	    clib_host_to_net_u16 (sess->key.cs_port[VLIB_RX]),
	    format_ip46_address, &sess->key.cs_ip[VLIB_TX], IP46_TYPE_ANY,
	    clib_host_to_net_u16 (sess->key.cs_port[VLIB_TX]),
	    format_ip_protocol, sess->key.cs_proto, format_ip46_address,
	    &sess->value.cs_ip[VLIB_RX], IP46_TYPE_ANY,
	    clib_host_to_net_u16 (sess->value.cs_port[VLIB_RX]),
	    format_ip46_address, &sess->value.cs_ip[VLIB_TX], IP46_TYPE_ANY,
	    clib_host_to_net_u16 (sess->value.cs_port[VLIB_TX]),
	    sess->value.cs_lbi, ts);

  return (s);
}

static clib_error_t *
calico_session_show (vlib_main_t * vm,
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

  vlib_cli_output (vm, "Calico Sessions: now:%f\n%U\n",
		   vlib_time_now (vm),
		   BV (format_bihash), &calico_session_db, verbose);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_session_show_cmd_node, static) = {
  .path = "show calico session",
  .function = calico_session_show,
  .short_help = "show calico session",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

u64
calico_session_scan (vlib_main_t * vm, f64 start_time, int i)
{
  BVT (clib_bihash) * h = &calico_session_db;
  int j, k;

  /* Don't scan the l2 fib if it hasn't been instantiated yet */
  if (alloc_arena (h) == 0)
    return 0.0;

  for (i = 0; i < h->nbuckets; i++)
    {
      /* allow no more than 100us without a pause */
      if ((vlib_time_now (vm) - start_time) > 10e-5)
	return (i);

      if (i < (h->nbuckets - 3))
	{
	  BVT (clib_bihash_bucket) * b =
	    BV (clib_bihash_get_bucket) (h, i + 3);
	  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
	  b = BV (clib_bihash_get_bucket) (h, i + 1);
	  if (!BV (clib_bihash_bucket_is_empty) (b))
	    {
	      BVT (clib_bihash_value) * v =
		BV (clib_bihash_get_value) (h, b->offset);
	      CLIB_PREFETCH (v, CLIB_CACHE_LINE_BYTES, LOAD);
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
	      if (v->kvp[k].key[0] == ~0ULL && v->kvp[k].value[0] == ~0ULL)
		continue;

	      calico_session_t *session = (calico_session_t *) & v->kvp[k];

	      if (start_time >
		  calico_timestamp_exp (session->value.cs_ts_index))
		{
		  /* age it */
		  if (session->value.flags & CALICO_SESSION_FLAG_ALLOC_PORT)
		    calico_free_port (session->value.cs_port[VLIB_RX]);
		  if (!(session->value.flags & CALICO_SESSION_FLAG_NO_CLIENT))
		    calico_client_free_by_ip (&session->key.cs_ip[VLIB_TX],
					      session->key.cs_af);
		  calico_timestamp_free (session->value.cs_ts_index);
		  BV (clib_bihash_add_del) (h, &v->kvp[k], 0);

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
calico_session_init (vlib_main_t * vm)
{
  calico_main_t *cm = &calico_main;
  BV (clib_bihash_init) (&calico_session_db,
			 "Calico Session DB", cm->session_hash_buckets,
			 cm->session_hash_memory);
  BV (clib_bihash_set_kvp_format_fn) (&calico_session_db,
				      format_calico_session);

  return (NULL);
}

VLIB_INIT_FUNCTION (calico_session_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
