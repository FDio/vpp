/*
 * nhrp.h: next-hop resolution
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


#include <vnet/nhrp/nhrp.h>
#include <vnet/fib/fib_table.h>
#include <vnet/adj/adj_midchain.h>

typedef struct nhrp_key_t_
{
  ip46_address_t nk_peer;
  u32 nk_sw_if_index;
} nhrp_key_t;

struct nhrp_entry_t_
{
  nhrp_key_t *ne_key;
  fib_prefix_t ne_nh;
  u32 ne_fib_index;
};

static uword *nhrp_db;
static nhrp_entry_t *nhrp_pool;
static nhrp_vft_t *nhrp_vfts;

#define NHRP_NOTIFY(_ne, _fn) {                 \
  nhrp_vft_t *_vft;                             \
  vec_foreach(_vft, nhrp_vfts) {                \
    if (_vft->_fn) {                             \
      _vft->_fn(_ne);                            \
    }                                           \
  }                                             \
}

u32
nhrp_entry_get_sw_if_index (const nhrp_entry_t * ne)
{
  return (ne->ne_key->nk_sw_if_index);
}

u32
nhrp_entry_get_fib_index (const nhrp_entry_t * ne)
{
  return (ne->ne_fib_index);
}

const ip46_address_t *
nhrp_entry_get_peer (const nhrp_entry_t * ne)
{
  return (&ne->ne_key->nk_peer);
}

const fib_prefix_t *
nhrp_entry_get_nh (const nhrp_entry_t * ne)
{
  return (&ne->ne_nh);
}

void
nhrp_entry_adj_stack (const nhrp_entry_t * ne, adj_index_t ai)
{
  adj_midchain_delegate_stack (ai, ne->ne_fib_index, &ne->ne_nh);
}

static adj_walk_rc_t
nhrp_entry_add_adj_walk (adj_index_t ai, void *ctx)
{
  nhrp_entry_adj_stack (ctx, ai);

  return (ADJ_WALK_RC_CONTINUE);
}

static adj_walk_rc_t
nhrp_entry_del_adj_walk (adj_index_t ai, void *ctx)
{
  adj_midchain_delegate_unstack (ai);

  return (ADJ_WALK_RC_CONTINUE);
}

nhrp_entry_t *
nhrp_entry_get (index_t nei)
{
  return pool_elt_at_index (nhrp_pool, nei);
}

nhrp_entry_t *
nhrp_entry_find (u32 sw_if_index, const ip46_address_t * peer)
{
  nhrp_key_t nk = {
    .nk_peer = *peer,
    .nk_sw_if_index = sw_if_index,
  };
  uword *p;

  p = hash_get_mem (nhrp_db, &nk);

  if (NULL != p)
    return nhrp_entry_get (p[0]);

  return (NULL);
}

int
nhrp_entry_add (u32 sw_if_index,
		const ip46_address_t * peer,
		u32 nh_table_id, const ip46_address_t * nh)
{
  fib_protocol_t fproto;
  nhrp_entry_t *ne;
  u32 fib_index;
  index_t nei;

  fproto = (ip46_address_is_ip4 (nh) ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);

  fib_index = fib_table_find (fproto, nh_table_id);

  if (~0 == fib_index)
    {
      return (VNET_API_ERROR_NO_SUCH_FIB);
    }

  ne = nhrp_entry_find (sw_if_index, peer);

  if (NULL == ne)
    {
      nhrp_key_t nk = {
	.nk_peer = *peer,
	.nk_sw_if_index = sw_if_index,
      };
      nhrp_entry_t *ne;

      pool_get_zero (nhrp_pool, ne);

      nei = ne - nhrp_pool;
      ne->ne_key = clib_mem_alloc (sizeof (*ne->ne_key));
      clib_memcpy (ne->ne_key, &nk, sizeof (*ne->ne_key));

      ip46_address_copy (&ne->ne_nh.fp_addr, nh);
      ne->ne_nh.fp_proto = fproto;
      ne->ne_nh.fp_len = (ne->ne_nh.fp_proto == FIB_PROTOCOL_IP4 ? 32 : 128);
      ne->ne_fib_index = fib_index;

      hash_set_mem (nhrp_db, ne->ne_key, nei);

      adj_nbr_walk_nh (sw_if_index,
		       ne->ne_nh.fp_proto,
		       &ne->ne_key->nk_peer, nhrp_entry_add_adj_walk, ne);

      NHRP_NOTIFY (ne, nv_added);
    }
  else
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

  return 0;
}

int
nhrp_entry_del (u32 sw_if_index, const ip46_address_t * peer)
{
  nhrp_entry_t *ne;

  ne = nhrp_entry_find (sw_if_index, peer);

  if (ne != NULL)
    {
      hash_unset_mem (nhrp_db, ne->ne_key);

      adj_nbr_walk_nh (sw_if_index,
		       ne->ne_nh.fp_proto,
		       &ne->ne_key->nk_peer, nhrp_entry_del_adj_walk, ne);

      NHRP_NOTIFY (ne, nv_deleted);

      clib_mem_free (ne->ne_key);
      pool_put (nhrp_pool, ne);
    }
  else
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

  return 0;
}

u8 *
format_nhrp_entry (u8 * s, va_list * args)
{
  index_t nei = va_arg (*args, index_t);
  vnet_main_t *vnm = vnet_get_main ();
  nhrp_entry_t *ne;

  ne = nhrp_entry_get (nei);

  s = format (s, "[%d] ", nei);
  s = format (s, "%U:", format_vnet_sw_if_index_name,
	      vnm, ne->ne_key->nk_sw_if_index);
  s = format (s, " %U", format_ip46_address,
	      &ne->ne_key->nk_peer, IP46_TYPE_ANY);
  s = format (s, " via [%d]:%U",
	      fib_table_get_table_id (ne->ne_fib_index, ne->ne_nh.fp_proto),
	      format_fib_prefix, &ne->ne_nh);

  return (s);
}

void
nhrp_walk (nhrp_walk_cb_t fn, void *ctx)
{
  index_t nei;

  /* *INDENT-OFF* */
  pool_foreach_index(nei, nhrp_pool,
  ({
    fn(nei, ctx);
  }));
  /* *INDENT-ON* */
}

void
nhrp_walk_itf (u32 sw_if_index, nhrp_walk_cb_t fn, void *ctx)
{
  index_t nei;

  /* *INDENT-OFF* */
  pool_foreach_index(nei, nhrp_pool,
  ({
    if (sw_if_index == nhrp_entry_get_sw_if_index(nhrp_entry_get(nei)))
      fn(nei, ctx);
  }));
  /* *INDENT-ON* */
}

void
nhrp_register (const nhrp_vft_t * vft)
{
  vec_add1 (nhrp_vfts, *vft);
}

static clib_error_t *
nhrp_init (vlib_main_t * vm)
{
  nhrp_db = hash_create_mem (0, sizeof (nhrp_key_t), sizeof (u32));

  return (NULL);
}

VLIB_INIT_FUNCTION (nhrp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
