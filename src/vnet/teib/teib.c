/*
 * teib.h: next-hop resolution
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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


#include <vnet/teib/teib.h>
#include <vnet/fib/fib_table.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/ip/ip6_ll_table.h>

typedef struct teib_key_t_
{
  ip46_address_t tk_peer;
  u32 tk_sw_if_index;
  fib_protocol_t tk_proto;
} __clib_packed teib_key_t;

struct teib_entry_t_
{
  teib_key_t *te_key;
  fib_prefix_t te_nh;
  u32 te_fib_index;
};

static uword *teib_db[FIB_PROTOCOL_IP_MAX];
static teib_entry_t *teib_pool;
static teib_vft_t *teib_vfts;
static vlib_log_class_t teib_logger;

#define TEIB_NOTIFY(_te, _fn) {                  \
  teib_vft_t *_vft;                              \
  vec_foreach(_vft, teib_vfts) {                 \
    if (_vft->_fn) {                             \
      _vft->_fn(_te);                            \
    }                                            \
  }                                              \
}

#define TEIB_DBG(...)                           \
    vlib_log_debug (teib_logger, __VA_ARGS__);

#define TEIB_INFO(...)                          \
    vlib_log_notice (teib_logger, __VA_ARGS__);

#define TEIB_TE_DBG(_te, _fmt, _args...)                      \
  vlib_log_debug (teib_logger, "[%U]: " _fmt, format_teib_entry, _te - teib_pool, ##_args)
#define TEIB_TE_INFO(_te, _fmt, _args...)                      \
  vlib_log_notice (teib_logger, "[%U]: " _fmt, format_teib_entry, _te - teib_pool, ##_args)

u32
teib_entry_get_sw_if_index (const teib_entry_t * te)
{
  return (te->te_key->tk_sw_if_index);
}

fib_protocol_t
teib_entry_get_proto (const teib_entry_t * te)
{
  return (te->te_key->tk_proto);
}

u32
teib_entry_get_fib_index (const teib_entry_t * te)
{
  return (te->te_fib_index);
}

const ip46_address_t *
teib_entry_get_peer (const teib_entry_t * te)
{
  return (&te->te_key->tk_peer);
}

const fib_prefix_t *
teib_entry_get_nh (const teib_entry_t * te)
{
  return (&te->te_nh);
}

void
teib_entry_adj_stack (const teib_entry_t * te, adj_index_t ai)
{
  adj_midchain_delegate_stack (ai, te->te_fib_index, &te->te_nh);
}

teib_entry_t *
teib_entry_get (index_t tei)
{
  return pool_elt_at_index (teib_pool, tei);
}

teib_entry_t *
teib_entry_find (u32 sw_if_index,
		 fib_protocol_t fproto, const ip46_address_t * peer)
{
  teib_key_t nk = {
    .tk_peer = *peer,
    .tk_proto = fproto,
    .tk_sw_if_index = sw_if_index,
  };
  uword *p;

  p = hash_get_mem (teib_db[fproto], &nk);

  if (NULL != p)
    return teib_entry_get (p[0]);

  return (NULL);
}

static void
teib_adj_fib_add (fib_protocol_t fproto,
		  const ip46_address_t * ip, u32 sw_if_index, u32 fib_index)
{
  if (FIB_PROTOCOL_IP6 == fproto &&
      ip6_address_is_link_local_unicast (&ip->ip6))
    {
      ip6_ll_prefix_t pfx = {
	.ilp_addr = ip->ip6,
	.ilp_sw_if_index = sw_if_index,
      };
      ip6_ll_table_entry_update (&pfx, FIB_ROUTE_PATH_FLAG_NONE);
    }
  else
    {
      fib_prefix_t pfx = {
	.fp_len = (FIB_PROTOCOL_IP4 == fproto ? 32 : 128),
	.fp_proto = fproto,
	.fp_addr = *ip,
      };
      fib_table_entry_path_add (fib_index, &pfx, FIB_SOURCE_ADJ,
				FIB_ENTRY_FLAG_ATTACHED,
				fib_proto_to_dpo (pfx.fp_proto),
				&pfx.fp_addr,
				sw_if_index,
				~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);


      if (1 == hash_elts (teib_db[pfx.fp_proto]))
	fib_table_lock (fib_index, pfx.fp_proto, FIB_SOURCE_ADJ);
    }
}

static void
teib_adj_fib_remove (fib_protocol_t fproto,
		     ip46_address_t * ip, u32 sw_if_index, u32 fib_index)
{
  if (FIB_PROTOCOL_IP6 == fproto &&
      ip6_address_is_link_local_unicast (&ip->ip6))
    {
      ip6_ll_prefix_t pfx = {
	.ilp_addr = ip->ip6,
	.ilp_sw_if_index = sw_if_index,
      };
      ip6_ll_table_entry_delete (&pfx);
    }
  else
    {
      fib_prefix_t pfx = {
	.fp_len = (FIB_PROTOCOL_IP4 == fproto ? 32 : 128),
	.fp_proto = fproto,
	.fp_addr = *ip,
      };

      fib_table_entry_path_remove (fib_index, &pfx, FIB_SOURCE_ADJ,
				   fib_proto_to_dpo (pfx.fp_proto),
				   &pfx.fp_addr,
				   sw_if_index,
				   ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);

      if (0 == hash_elts (teib_db[pfx.fp_proto]))
	fib_table_unlock (fib_index, pfx.fp_proto, FIB_SOURCE_ADJ);
    }
}

int
teib_entry_add (u32 sw_if_index,
		fib_protocol_t fproto,
		const ip46_address_t * peer,
		u32 nh_table_id, const ip46_address_t * nh)
{
  fib_protocol_t nh_proto;
  teib_entry_t *te;
  u32 fib_index;
  index_t tei;

  nh_proto = (ip46_address_is_ip4 (nh) ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);

  fib_index = fib_table_find (nh_proto, nh_table_id);

  if (~0 == fib_index)
    {
      return (VNET_API_ERROR_NO_SUCH_FIB);
    }

  te = teib_entry_find (sw_if_index, fproto, peer);

  if (NULL == te)
    {
      teib_key_t nk = {
	.tk_peer = *peer,
	.tk_proto = fproto,
	.tk_sw_if_index = sw_if_index,
      };
      teib_entry_t *te;
      u32 fib_index;

      fib_index = fib_table_get_index_for_sw_if_index (fproto, sw_if_index);

      pool_get_zero (teib_pool, te);

      tei = te - teib_pool;
      te->te_key = clib_mem_alloc (sizeof (*te->te_key));
      clib_memcpy (te->te_key, &nk, sizeof (*te->te_key));

      ip46_address_copy (&te->te_nh.fp_addr, nh);
      te->te_nh.fp_proto = fproto;
      te->te_nh.fp_len = (te->te_nh.fp_proto == FIB_PROTOCOL_IP4 ? 32 : 128);
      te->te_fib_index = fib_index;

      hash_set_mem (teib_db[fproto], te->te_key, tei);

      /* we how have a /32 in the overlay, add an adj-fib */
      teib_adj_fib_add (te->te_key->tk_proto,
			&te->te_key->tk_peer, sw_if_index, fib_index);

      TEIB_NOTIFY (te, nv_added);
      TEIB_TE_INFO (te, "created");
    }
  else
    {
      TEIB_TE_INFO (te, "exists");
      return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);
    }
  return 0;
}

int
teib_entry_del (u32 sw_if_index,
		fib_protocol_t fproto, const ip46_address_t * peer)
{
  teib_entry_t *te;

  te = teib_entry_find (sw_if_index, fproto, peer);

  if (te != NULL)
    {
      TEIB_TE_INFO (te, "removed");

      u32 fib_index;

      fib_index = fib_table_get_index_for_sw_if_index (fproto, sw_if_index);

      teib_adj_fib_remove (te->te_key->tk_proto,
			   &te->te_key->tk_peer, sw_if_index, fib_index);

      hash_unset_mem (teib_db[fproto], te->te_key);

      TEIB_NOTIFY (te, nv_deleted);

      clib_mem_free (te->te_key);
      pool_put (teib_pool, te);
    }
  else
    {
      TEIB_INFO ("no such entry: %U, %U, %U",
		 format_vnet_sw_if_index_name,
		 vnet_get_main (), sw_if_index,
		 format_fib_protocol, fproto,
		 format_ip46_address, peer, IP46_TYPE_ANY);
      return (VNET_API_ERROR_NO_SUCH_ENTRY);
    }
  return 0;
}

u8 *
format_teib_entry (u8 * s, va_list * args)
{
  index_t tei = va_arg (*args, index_t);
  vnet_main_t *vnm = vnet_get_main ();
  teib_entry_t *te;

  te = teib_entry_get (tei);

  s = format (s, "[%d] ", tei);
  s = format (s, "%U:", format_vnet_sw_if_index_name,
	      vnm, te->te_key->tk_sw_if_index);
  s = format (s, " %U:", format_fib_protocol, te->te_key->tk_proto);
  s = format (s, "%U", format_ip46_address,
	      &te->te_key->tk_peer, IP46_TYPE_ANY);
  s = format (s, " via [%d]:%U",
	      fib_table_get_table_id (te->te_fib_index, te->te_nh.fp_proto),
	      format_fib_prefix, &te->te_nh);

  return (s);
}

void
teib_walk (teib_walk_cb_t fn, void *ctx)
{
  index_t tei;

  /* *INDENT-OFF* */
  pool_foreach_index(tei, teib_pool,
  ({
    fn(tei, ctx);
  }));
  /* *INDENT-ON* */
}

void
teib_walk_itf (u32 sw_if_index, teib_walk_cb_t fn, void *ctx)
{
  index_t tei;

  /* *INDENT-OFF* */
  pool_foreach_index(tei, teib_pool,
  ({
    if (sw_if_index == teib_entry_get_sw_if_index(teib_entry_get(tei)))
      fn(tei, ctx);
  }));
  /* *INDENT-ON* */
}

static void
teib_walk_itf_proto (u32 sw_if_index,
		     fib_protocol_t fproto, teib_walk_cb_t fn, void *ctx)
{
  index_t tei;

  /* *INDENT-OFF* */
  pool_foreach_index(tei, teib_pool,
  ({
    if (sw_if_index == teib_entry_get_sw_if_index(teib_entry_get(tei)) &&
        fproto == teib_entry_get_proto(teib_entry_get(tei)))
      fn(tei, ctx);
  }));
  /* *INDENT-ON* */
}

typedef struct teib_table_bind_ctx_t_
{
  u32 new_fib_index;
  u32 old_fib_index;
} teib_table_bind_ctx_t;

static walk_rc_t
teib_walk_table_bind (index_t tei, void *arg)
{
  teib_table_bind_ctx_t *ctx = arg;
  teib_entry_t *te;

  te = teib_entry_get (tei);

  TEIB_TE_INFO (te, "bind: %d -> %d", ctx->old_fib_index, ctx->new_fib_index);

  teib_adj_fib_remove (te->te_key->tk_proto,
		       &te->te_key->tk_peer,
		       te->te_key->tk_sw_if_index, ctx->old_fib_index);
  teib_adj_fib_add (te->te_key->tk_proto,
		    &te->te_key->tk_peer,
		    te->te_key->tk_sw_if_index, ctx->new_fib_index);

  return (WALK_CONTINUE);
}

static void
teib_table_bind_v4 (ip4_main_t * im,
		    uword opaque,
		    u32 sw_if_index, u32 new_fib_index, u32 old_fib_index)
{
  teib_table_bind_ctx_t ctx = {
    .old_fib_index = old_fib_index,
    .new_fib_index = new_fib_index,
  };

  teib_walk_itf_proto (sw_if_index,
		       FIB_PROTOCOL_IP4, teib_walk_table_bind, &ctx);
}

static void
teib_table_bind_v6 (ip6_main_t * im,
		    uword opaque,
		    u32 sw_if_index, u32 new_fib_index, u32 old_fib_index)
{
  teib_table_bind_ctx_t ctx = {
    .old_fib_index = old_fib_index,
    .new_fib_index = new_fib_index,
  };

  teib_walk_itf_proto (sw_if_index,
		       FIB_PROTOCOL_IP6, teib_walk_table_bind, &ctx);
}

void
teib_register (const teib_vft_t * vft)
{
  vec_add1 (teib_vfts, *vft);
}

static clib_error_t *
teib_init (vlib_main_t * vm)
{
  fib_protocol_t fproto;

  FOR_EACH_FIB_IP_PROTOCOL (fproto)
    teib_db[fproto] = hash_create_mem (0, sizeof (teib_key_t), sizeof (u32));

  ip4_table_bind_callback_t cb4 = {
    .function = teib_table_bind_v4,
  };
  vec_add1 (ip4_main.table_bind_callbacks, cb4);

  ip6_table_bind_callback_t cb6 = {
    .function = teib_table_bind_v6,
  };
  vec_add1 (ip6_main.table_bind_callbacks, cb6);

  teib_logger = vlib_log_register_class ("teib", "teib");

  return (NULL);
}

VLIB_INIT_FUNCTION (teib_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
