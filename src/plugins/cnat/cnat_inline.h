/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef __CNAT_INLINE_H__
#define __CNAT_INLINE_H__

#include <cnat/cnat_session.h>
#include <cnat/cnat_types.h>
#include <cnat/cnat_bihash.h>

#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

always_inline cnat_timestamp_t *
cnat_timestamp_get_if_exists (u32 index)
{
  cnat_timestamp_t *ts = NULL;
  u32 pidx;

  /* 6 top bits for choosing pool */
  pidx = index >> (32 - CNAT_TS_MPOOL_BITS);
  index = index & (0xffffffff >> CNAT_TS_MPOOL_BITS);

#if CLIB_DEBUG > 0
  /* lock in debug mode so that we can use the freelist */
  clib_spinlock_lock (&cnat_timestamps.ts_lock);
  if (!pool_is_free_index (cnat_timestamps.ts_pools[pidx], index))
    ts = pool_elt_at_index (cnat_timestamps.ts_pools[pidx], index);
  clib_spinlock_unlock (&cnat_timestamps.ts_lock);
#else
  if (!pool_is_free_index (cnat_timestamps.ts_pools[pidx], index))
    ts = pool_elt_at_index (cnat_timestamps.ts_pools[pidx], index);
#endif

  return ts;
}

always_inline cnat_timestamp_t *
cnat_timestamp_get (u32 index)
{
  cnat_timestamp_t *ts;
  u32 pidx;

  /* 6 top bits for choosing pool */
  pidx = index >> (32 - CNAT_TS_MPOOL_BITS);
  index = index & (0xffffffff >> CNAT_TS_MPOOL_BITS);

#if CLIB_DEBUG > 0
  /* lock in debug mode so that we can use the freelist */
  clib_spinlock_lock (&cnat_timestamps.ts_lock);
  ts = pool_elt_at_index (cnat_timestamps.ts_pools[pidx], index);
  clib_spinlock_unlock (&cnat_timestamps.ts_lock);
#else
  ts = pool_elt_at_index (cnat_timestamps.ts_pools[pidx], index);
#endif

  return ts;
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
  /* Initial number of timestamps for a session
   * this will be incremented when adding the reverse
   * session in cnat_rsession_create */
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
  cnat_timestamp_t *ts = cnat_timestamp_get (index);
  return ts->last_seen + (f64) ts->lifetime;
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
      vnet_buffer2 (b)->session.generic_flow_id = ksession->value.cs_session_index;
      vnet_buffer2 (b)->session.state = CNAT_LOOKUP_IS_NEW;
    }
  else if (session->key.cs_5tuple.iproto != 0)
    {
      vnet_buffer2 (b)->session.generic_flow_id = session->value.cs_session_index;
      vnet_buffer2 (b)->session.state = session->value.cs_flags & CNAT_SESSION_IS_RETURN ?
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
#endif
