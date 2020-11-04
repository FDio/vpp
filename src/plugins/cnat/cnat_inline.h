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

#include <cnat/cnat_types.h>

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
  pool_get (cnat_timestamps.ts_pools[pidx], ts);
  if (pool_elts (cnat_timestamps.ts_pools[pidx]) == pool_sz)
    clib_bitmap_set (cnat_timestamps.ts_free, pidx, 0);
  clib_spinlock_unlock (&cnat_timestamps.ts_lock);

  index = (u32) pidx << (32 - CNAT_TS_MPOOL_BITS);
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
  ts->refcnt = CNAT_TIMESTAMP_INIT_REFCNT;
  return index;
}

always_inline void
cnat_timestamp_inc_refcnt (u32 index)
{
  cnat_timestamp_t *ts = cnat_timestamp_get (index);
  clib_atomic_add_fetch (&ts->refcnt, 1);
}

always_inline void
cnat_timestamp_update (u32 index, f64 t)
{
  cnat_timestamp_t *ts = cnat_timestamp_get (index);
  ts->last_seen = t;
}

always_inline void
cnat_timestamp_set_lifetime (u32 index, u16 lifetime)
{
  cnat_timestamp_t *ts = cnat_timestamp_get (index);
  ts->lifetime = lifetime;
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
cnat_timestamp_free (u32 index)
{
  cnat_timestamp_t *ts = cnat_timestamp_get_if_valid (index);
  if (NULL == ts)
    return;
  if (0 == clib_atomic_sub_fetch (&ts->refcnt, 1))
    cnat_timestamp_destroy (index);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
