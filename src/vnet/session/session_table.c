/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vnet/session/session_table.h>
#include <vnet/session/session.h>

/**
 * Pool of session tables
 */
static session_table_t *lookup_tables;

session_table_t *
_get_session_tables (void)
{
  return lookup_tables;
}

session_table_t *
session_table_alloc (void)
{
  session_table_t *slt;
  pool_get_aligned (lookup_tables, slt, CLIB_CACHE_LINE_BYTES);
  clib_memset (slt, 0, sizeof (*slt));
  return slt;
}

u32
session_table_index (session_table_t * slt)
{
  return (slt - lookup_tables);
}

session_table_t *
session_table_get (u32 table_index)
{
  if (pool_is_free_index (lookup_tables, table_index))
    return 0;
  return pool_elt_at_index (lookup_tables, table_index);
}

#define foreach_hash_table_parameter            \
  _(v4,session,buckets,20000)                   \
  _(v4,session,memory,(64<<20))                 \
  _(v6,session,buckets,20000)                   \
  _(v6,session,memory,(64<<20))                 \
  _(v4,halfopen,buckets,20000)                  \
  _(v4,halfopen,memory,(64<<20))                \
  _(v6,halfopen,buckets,20000)                  \
  _(v6,halfopen,memory,(64<<20))

/**
 * Initialize session table hash tables
 *
 * If vpp configured with set of table parameters it uses them,
 * otherwise it uses defaults above.
 */
void
session_table_init (session_table_t * slt, u8 fib_proto)
{
  u8 all = fib_proto > FIB_PROTOCOL_IP6 ? 1 : 0;
  int i;

#define _(af,table,parm,value) 						\
  u32 configured_##af##_##table##_table_##parm = value;
  foreach_hash_table_parameter;
#undef _

#define _(af,table,parm,value)                                          \
  if (session_manager_main.configured_##af##_##table##_table_##parm)    \
    configured_##af##_##table##_table_##parm =                          \
      session_manager_main.configured_##af##_##table##_table_##parm;
  foreach_hash_table_parameter;
#undef _

  if (fib_proto == FIB_PROTOCOL_IP4 || all)
    {
      clib_bihash_init_16_8 (&slt->v4_session_hash, "v4 session table",
			     configured_v4_session_table_buckets,
			     configured_v4_session_table_memory);
      clib_bihash_init_16_8 (&slt->v4_half_open_hash, "v4 half-open table",
			     configured_v4_halfopen_table_buckets,
			     configured_v4_halfopen_table_memory);
    }
  if (fib_proto == FIB_PROTOCOL_IP6 || all)
    {
      clib_bihash_init_48_8 (&slt->v6_session_hash, "v6 session table",
			     configured_v6_session_table_buckets,
			     configured_v6_session_table_memory);
      clib_bihash_init_48_8 (&slt->v6_half_open_hash, "v6 half-open table",
			     configured_v6_halfopen_table_buckets,
			     configured_v6_halfopen_table_memory);
    }

  for (i = 0; i < TRANSPORT_N_PROTO; i++)
    session_rules_table_init (&slt->session_rules[i]);
}

typedef struct _ip4_session_table_walk_ctx_t
{
  ip4_session_table_walk_fn_t fn;
  void *ctx;
} ip4_session_table_walk_ctx_t;

void
ip4_session_table_walk_cb (clib_bihash_kv_16_8_t * kvp, void *arg)
{
  ip4_session_table_walk_ctx_t *ctx = arg;
  ctx->fn (kvp, ctx->ctx);
}

void
ip4_session_table_walk (clib_bihash_16_8_t * hash,
			ip4_session_table_walk_fn_t fn, void *arg)
{
  ip4_session_table_walk_ctx_t ctx = {
    .fn = fn,
    .ctx = arg,
  };
  clib_bihash_foreach_key_value_pair_16_8 (hash, ip4_session_table_walk_cb,
					   &ctx);
}

/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
