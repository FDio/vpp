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
#include "cnat_log.h"

#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

always_inline cnat_timestamp_t *
cnat_timestamp_get_if_exists (u32 index)
{
  cnat_timestamp_mpool_t *ctm = &cnat_timestamps;
  u32 log2_pool_sz = ctm->log2_pool_sz;
  u32 pidx = index >> log2_pool_sz;
  cnat_timestamp_t *ts = 0;

  index = index & ((1 << log2_pool_sz) - 1);

  clib_rwlock_reader_lock (&ctm->ts_lock);
  if (!pool_is_free_index (vec_elt (ctm->ts_pools, pidx), index))
    ts = pool_elt_at_index (vec_elt (ctm->ts_pools, pidx), index);
  clib_rwlock_reader_unlock (&ctm->ts_lock);

  return ts;
}

always_inline cnat_timestamp_t *
cnat_timestamp_get (u32 index)
{
  cnat_timestamp_mpool_t *ctm = &cnat_timestamps;
  u32 log2_pool_sz = ctm->log2_pool_sz;
  u32 pidx = index >> log2_pool_sz;
  cnat_timestamp_t *ts;

  index = index & ((1 << log2_pool_sz) - 1);

  clib_rwlock_reader_lock (&ctm->ts_lock);
  ts = pool_elt_at_index (vec_elt (ctm->ts_pools, pidx), index);
  clib_rwlock_reader_unlock (&ctm->ts_lock);

  return ts;
}

always_inline index_t
cnat_timestamp_alloc (u32 fib_index, bool is_v6)
{
  cnat_timestamp_mpool_t *ctm = &cnat_timestamps;

  u32 log2_pool_sz = ctm->log2_pool_sz;
  u32 pool_sz = 1 << log2_pool_sz;
  cnat_timestamp_t *pool;
  cnat_timestamp_t *ts;
  u32 index;
  u32 pidx;

  clib_rwlock_writer_lock (&ctm->ts_lock);
  vec_validate_init_empty_aligned (ctm->sessions_per_vrf_ip4, fib_index,
				   ctm->max_sessions_per_vrf,
				   CLIB_CACHE_LINE_BYTES);
  vec_validate_init_empty_aligned (ctm->sessions_per_vrf_ip6, fib_index,
				   ctm->max_sessions_per_vrf,
				   CLIB_CACHE_LINE_BYTES);
  int *sessions_per_vrf =
    is_v6 ? ctm->sessions_per_vrf_ip6 : ctm->sessions_per_vrf_ip4;
  if (PREDICT_FALSE (vec_elt (sessions_per_vrf, fib_index) <= 0))
    goto err;

  pidx = clib_bitmap_first_set (ctm->ts_free);
  if (PREDICT_FALSE (pidx >= vec_len (ctm->ts_pools)))
    {
      pidx = vec_len (ctm->ts_pools);
      if (pidx >= ctm->pool_max)
	goto err; /* too many sessions... */
      /* add a new pool */
      vec_validate (ctm->ts_pools, pidx);
      pool_init_fixed (vec_elt (ctm->ts_pools, pidx), pool_sz);
      ctm->ts_free = clib_bitmap_set (ctm->ts_free, pidx, 1);
    }

  pool = vec_elt (ctm->ts_pools, pidx);
  pool_get (pool, ts);
  index = ts - pool;

  if (PREDICT_FALSE (pool_elts (pool) == pool_sz))
    ctm->ts_free = clib_bitmap_set (ctm->ts_free, pidx, 0); /* pool is full */

  vec_elt (sessions_per_vrf, fib_index)--;

  clib_rwlock_writer_unlock (&ctm->ts_lock);

  clib_memset_u8 (ts, 0, sizeof (*ts));

  ts->fib_index = fib_index;
  ASSERT ((u64) index + (pidx << log2_pool_sz) <= CLIB_U32_MAX);
  return index + (pidx << log2_pool_sz);

err:
  clib_rwlock_writer_unlock (&ctm->ts_lock);
  return INDEX_INVALID;
}

always_inline void
cnat_timestamp_destroy (u32 index, bool is_v6)
{
  cnat_timestamp_mpool_t *ctm = &cnat_timestamps;
  int *sessions_per_vrf =
    is_v6 ? ctm->sessions_per_vrf_ip6 : ctm->sessions_per_vrf_ip4;
  u32 log2_pool_sz = ctm->log2_pool_sz;
  u32 pidx = index >> log2_pool_sz;
  cnat_timestamp_t *pool;
  cnat_timestamp_t *ts;

  index = index & ((1 << log2_pool_sz) - 1);

  clib_rwlock_writer_lock (&ctm->ts_lock);
  pool = vec_elt (ctm->ts_pools, pidx);
  ts = pool_elt_at_index (pool, index);
  vec_elt (sessions_per_vrf, ts->fib_index)++;
  pool_put (pool, ts);
  ctm->ts_free = clib_bitmap_set (ctm->ts_free, pidx, 1);
  clib_rwlock_writer_unlock (&ctm->ts_lock);
}

always_inline index_t
cnat_timestamp_new (u32 t, u32 fib_index, bool is_v6)
{
  index_t index = cnat_timestamp_alloc (fib_index, is_v6);
  if (PREDICT_FALSE (INDEX_INVALID == index))
    return INDEX_INVALID; /* alloc failure */
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
cnat_timestamp_update (u32 index, u32 t)
{
  cnat_timestamp_t *ts = cnat_timestamp_get (index);
  ts->last_seen = t;
  return ts;
}

always_inline u32
cnat_timestamp_exp (u32 index)
{
  cnat_timestamp_t *ts = cnat_timestamp_get (index);
  return ts->last_seen + ts->lifetime;
}

always_inline void
cnat_timestamp_rewrite_free (cnat_timestamp_rewrite_t *rw)
{
  if (rw->cts_flags & CNAT_TS_RW_FLAG_HAS_ALLOCATED_PORT)
    cnat_free_port_cb (rw->fib_index, rw->tuple.port[VLIB_RX],
		       rw->tuple.iproto);
}

always_inline void
cnat_timestamp_free (u32 index, bool is_v6)
{
  cnat_timestamp_t *ts = cnat_timestamp_get (index);
  ASSERT (ts);
  if (0 == clib_atomic_sub_fetch (&ts->ts_session_refcnt, 1))
    {
      for (int i = 0; i < CNAT_N_LOCATIONS * VLIB_N_DIR; i++)
	if (ts->ts_rw_bm & (1 << i))
	  cnat_timestamp_rewrite_free (&ts->cts_rewrites[i]);

      cnat_timestamp_destroy (index, is_v6);
    }
}

static_always_inline void
cnat_lookup_create_or_return (vlib_buffer_t *b, int rv, cnat_bihash_kv_t *bkey,
			      cnat_bihash_kv_t *bvalue, u32 now, u64 hash,
			      bool is_v6, bool alloc_if_not_found)
{
  vnet_buffer2 (b)->session.flags = 0;
  cnat_session_t *session = (cnat_session_t *) bvalue;
  if (rv)
    {
      if (!alloc_if_not_found)
	goto err;
      cnat_session_t *ksession = (cnat_session_t *) bkey;
      index_t session_index =
	cnat_timestamp_new (now, ksession->key.fib_index, is_v6);
      ASSERT (
	(session_index < CNAT_MAX_SESSIONS || INDEX_INVALID == session_index));
      if (PREDICT_FALSE (session_index >= CNAT_MAX_SESSIONS))
	goto err; /* too many sessions */
      ksession->value.cs_session_index = session_index;
      ksession->value.cs_flags = 0;
      cnat_bihash_add_del_hash (&cnat_session_db, bkey, hash, 1 /* add */);
      vnet_buffer2 (b)->session.generic_flow_id =
	ksession->value.cs_session_index;
      vnet_buffer2 (b)->session.state = CNAT_LOOKUP_IS_NEW;
      cnat_log_session_create (ksession);
      cnat_timestamp_t *ts = cnat_timestamp_get (session_index);
      // we put the original 5tuple in the rewrite of the session to use it
      // later in the writeback if there is no nat (i.e no actual rewrites) in
      // the case where we have actual rewrites this is going to be overridden
      ts->cts_rewrites[CNAT_LOCATION_INPUT].tuple = ksession->key.cs_5tuple;
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
    goto err;

  return;

err:
  vnet_buffer2 (b)->session.generic_flow_id = 0;
  vnet_buffer2 (b)->session.state = CNAT_LOOKUP_IS_ERR;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
