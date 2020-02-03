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

typedef struct teib_key_t_
{
  ip46_address_t tk_peer;
  u32 tk_sw_if_index;
} teib_key_t;

struct teib_entry_t_
{
  teib_key_t *te_key;
  fib_prefix_t te_nh;
  u32 te_fib_index;
};

static uword *teib_db;
static teib_entry_t *teib_pool;
static teib_vft_t *teib_vfts;

#define TEIB_NOTIFY(_te, _fn) {                  \
  teib_vft_t *_vft;                              \
  vec_foreach(_vft, teib_vfts) {                 \
    if (_vft->_fn) {                             \
      _vft->_fn(_te);                            \
    }                                            \
  }                                              \
}

u32
teib_entry_get_sw_if_index (const teib_entry_t * te)
{
  return (te->te_key->tk_sw_if_index);
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
teib_entry_find (u32 sw_if_index, const ip46_address_t * peer)
{
  teib_key_t nk = {
    .tk_peer = *peer,
    .tk_sw_if_index = sw_if_index,
  };
  uword *p;

  p = hash_get_mem (teib_db, &nk);

  if (NULL != p)
    return teib_entry_get (p[0]);

  return (NULL);
}

int
teib_entry_add (u32 sw_if_index,
		const ip46_address_t * peer,
		u32 nh_table_id, const ip46_address_t * nh)
{
  fib_protocol_t fproto;
  teib_entry_t *te;
  u32 fib_index;
  index_t tei;

  fproto = (ip46_address_is_ip4 (nh) ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);

  fib_index = fib_table_find (fproto, nh_table_id);

  if (~0 == fib_index)
    {
      return (VNET_API_ERROR_NO_SUCH_FIB);
    }

  te = teib_entry_find (sw_if_index, peer);

  if (NULL == te)
    {
      teib_key_t nk = {
	.tk_peer = *peer,
	.tk_sw_if_index = sw_if_index,
      };
      teib_entry_t *te;

      pool_get_zero (teib_pool, te);

      tei = te - teib_pool;
      te->te_key = clib_mem_alloc (sizeof (*te->te_key));
      clib_memcpy (te->te_key, &nk, sizeof (*te->te_key));

      ip46_address_copy (&te->te_nh.fp_addr, nh);
      te->te_nh.fp_proto = fproto;
      te->te_nh.fp_len = (te->te_nh.fp_proto == FIB_PROTOCOL_IP4 ? 32 : 128);
      te->te_fib_index = fib_index;

      hash_set_mem (teib_db, te->te_key, tei);

      TEIB_NOTIFY (te, nv_added);
    }
  else
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

  return 0;
}

int
teib_entry_del (u32 sw_if_index, const ip46_address_t * peer)
{
  teib_entry_t *te;

  te = teib_entry_find (sw_if_index, peer);

  if (te != NULL)
    {
      hash_unset_mem (teib_db, te->te_key);

      TEIB_NOTIFY (te, nv_deleted);

      clib_mem_free (te->te_key);
      pool_put (teib_pool, te);
    }
  else
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

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
  s = format (s, " %U", format_ip46_address,
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

void
teib_register (const teib_vft_t * vft)
{
  vec_add1 (teib_vfts, *vft);
}

static clib_error_t *
teib_init (vlib_main_t * vm)
{
  teib_db = hash_create_mem (0, sizeof (teib_key_t), sizeof (u32));

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
