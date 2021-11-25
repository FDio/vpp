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


#ifndef __CNAT_INLINE_H__
#define __CNAT_INLINE_H__

#include <cnat/cnat_session.h>
#include <cnat/cnat_types.h>
#include <cnat/cnat_bihash.h>

#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

always_inline int
cnat_ts_is_free_index (u32 index)
{
  u32 pidx = index >> (32 - CNAT_TS_MPOOL_BITS);
  index = index & (0xffffffff >> CNAT_TS_MPOOL_BITS);
  return pool_is_free_index (cnat_timestamps.ts_pools[pidx], index);
}

always_inline cnat_timestamp_t *
cnat_timestamp_get (u32 index)
{
  /* 6 top bits for choosing pool */
  u32 pidx = index >> (32 - CNAT_TS_MPOOL_BITS);
  index = index & (0xffffffff >> CNAT_TS_MPOOL_BITS);
  return pool_elt_at_index (cnat_timestamps.ts_pools[pidx], index);
}

always_inline cnat_timestamp_t *
cnat_timestamp_get_if_valid (u32 index)
{
  /* 6 top bits for choosing pool */
  u32 pidx = index >> (32 - CNAT_TS_MPOOL_BITS);
  index = index & (0xffffffff >> CNAT_TS_MPOOL_BITS);
  if (pidx >= cnat_timestamps.next_empty_pool_idx)
    return (NULL);
  if (pool_is_free_index (cnat_timestamps.ts_pools[pidx], index))
    return (NULL);
  return pool_elt_at_index (cnat_timestamps.ts_pools[pidx], index);
}

always_inline index_t
cnat_timestamp_alloc ()
{
  cnat_timestamp_t *ts;
  u32 index, pool_sz;
  uword pidx;

  clib_spinlock_lock (&cnat_timestamps.ts_lock);
  pidx = clib_bitmap_first_set (cnat_timestamps.ts_free);
  pool_sz = 1 << (CNAT_TS_BASE_SIZE + pidx);
  ASSERT (pidx <= cnat_timestamps.next_empty_pool_idx);
  if (pidx == cnat_timestamps.next_empty_pool_idx)
    pool_init_fixed (
      cnat_timestamps.ts_pools[cnat_timestamps.next_empty_pool_idx++],
      pool_sz);
  pool_get_zero (cnat_timestamps.ts_pools[pidx], ts);
  if (pool_elts (cnat_timestamps.ts_pools[pidx]) == pool_sz)
    clib_bitmap_set (cnat_timestamps.ts_free, pidx, 0);
  clib_spinlock_unlock (&cnat_timestamps.ts_lock);

  index = (u32) pidx << (32 - CNAT_TS_MPOOL_BITS);
  ts->index = index | (ts - cnat_timestamps.ts_pools[pidx]);
  return index | (ts - cnat_timestamps.ts_pools[pidx]);
}

always_inline void
cnat_timestamp_destroy (u32 index)
{
  u32 pidx = index >> (32 - CNAT_TS_MPOOL_BITS);
  index = index & (0xffffffff >> CNAT_TS_MPOOL_BITS);
  clib_spinlock_lock (&cnat_timestamps.ts_lock);
  pool_put_index (cnat_timestamps.ts_pools[pidx], index);
  clib_bitmap_set (cnat_timestamps.ts_free, pidx, 1);
  clib_spinlock_unlock (&cnat_timestamps.ts_lock);
}

always_inline u32
cnat_timestamp_new (f64 t)
{
  index_t index = cnat_timestamp_alloc ();
  cnat_timestamp_t *ts = cnat_timestamp_get (index);
  ts->last_seen = t;
  ts->lifetime = cnat_main.session_max_age;
  /* One session as it is created on lookup */
  ts->ts_session_refcnt = 1;
  return index;
}

always_inline cnat_timestamp_t *
cnat_timestamp_update (u32 index, f64 t)
{
  cnat_timestamp_t *ts = cnat_timestamp_get (index);
  ts->last_seen = t;
  return ts;
}

always_inline f64
cnat_timestamp_exp (u32 index)
{
  f64 t;
  cnat_timestamp_t *ts = cnat_timestamp_get_if_valid (index);
  if (NULL == ts)
    return -1;
  t = ts->last_seen + (f64) ts->lifetime;
  return t;
}

always_inline void
cnat_timestamp_rewrite_free (cnat_timestamp_rewrite_t *rw)
{
  if (rw->cts_flags & CNAT_TS_RW_FLAG_HAS_ALLOCATED_PORT)
    cnat_free_port_cb (rw->tuple.port[VLIB_RX], rw->tuple.iproto);
}

always_inline void
cnat_timestamp_free (u32 index)
{
  cnat_timestamp_t *ts = cnat_timestamp_get (index);
  ASSERT (ts);
  if (0 == clib_atomic_sub_fetch (&ts->ts_session_refcnt, 1))
    {
      for (int i = 0; i < CNAT_N_LOCATIONS * VLIB_N_DIR; i++)
	if (ts->ts_rw_bm & (1 << i))
	  cnat_timestamp_rewrite_free (&ts->cts_rewrites[i]);

      cnat_timestamp_destroy (index);
    }
}

static_always_inline void
cnat_lookup_create_or_return (vlib_buffer_t *b, int rv, cnat_bihash_kv_t *bkey,
			      cnat_bihash_kv_t *bvalue, f64 now, u64 hash)
{
  vnet_buffer2 (b)->session.flags = 0;
  cnat_session_t *session = (cnat_session_t *) bvalue;
  if (rv)
    {
      cnat_session_t *ksession = (cnat_session_t *) bkey;
      ksession->value.cs_session_index = cnat_timestamp_new (now);
      ksession->value.cs_flags = 0;
      cnat_bihash_add_del_hash (&cnat_session_db, bkey, hash, 1 /* add */);
      vnet_buffer2 (b)->session.generic_flow_id =
	ksession->value.cs_session_index;
      vnet_buffer2 (b)->session.state = CNAT_LOOKUP_IS_NEW;
    }
  else if (session->key.cs_5tuple.iproto != 0)
    {
      vnet_buffer2 (b)->session.generic_flow_id =
	session->value.cs_session_index;
      vnet_buffer2 (b)->session.state =
	session->value.cs_flags & CNAT_SESSION_IS_RETURN ?
	  CNAT_LOOKUP_IS_RETURN :
	  CNAT_LOOKUP_IS_OK;
      cnat_timestamp_update (session->value.cs_session_index, now);
    }
  else
    {
      vnet_buffer2 (b)->session.generic_flow_id = 0;
      vnet_buffer2 (b)->session.state = CNAT_LOOKUP_IS_ERR;
    }
}

static_always_inline u64
cnat_5tuple_hash (cnat_5tuple_t *t)
{
  u64 hash;
  return cnat_bihash_hash ((cnat_bihash_kv_t *) t);

  if (AF_IP4 == t->af)
    {
      u8 *saddr = ((u8 *) &t->ip4);
      ip4_header_t *ip4 =
	(ip4_header_t *) (saddr -
			  STRUCT_OFFSET_OF (ip4_header_t, src_address));
      t->ip4_proto = t->iproto;
      hash = ip4_compute_flow_hash (ip4, IP_FLOW_HASH_DEFAULT);
      t->ip4_proto = 0;
    }
  else
    {
      u8 *saddr = ((u8 *) &t->ip6);
      ip6_header_t *ip6 =
	(ip6_header_t *) (saddr -
			  STRUCT_OFFSET_OF (ip6_header_t, src_address));
      hash = ip6_compute_flow_hash (ip6, IP_FLOW_HASH_DEFAULT);
    }
  return hash;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
