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

always_inline u32
cnat_timestamp_new (f64 t)
{
  u32 index;
  cnat_timestamp_t *ts;
  clib_rwlock_writer_lock (&cnat_main.ts_lock);
  pool_get (cnat_timestamps, ts);
  ts->last_seen = t;
  ts->lifetime = cnat_main.session_max_age;
  ts->refcnt = CNAT_TIMESTAMP_INIT_REFCNT;
  index = ts - cnat_timestamps;
  clib_rwlock_writer_unlock (&cnat_main.ts_lock);
  return index;
}

always_inline void
cnat_timestamp_inc_refcnt (u32 index)
{
  clib_rwlock_reader_lock (&cnat_main.ts_lock);
  cnat_timestamp_t *ts = pool_elt_at_index (cnat_timestamps, index);
  ts->refcnt++;
  clib_rwlock_reader_unlock (&cnat_main.ts_lock);
}

always_inline void
cnat_timestamp_update (u32 index, f64 t)
{
  clib_rwlock_reader_lock (&cnat_main.ts_lock);
  cnat_timestamp_t *ts = pool_elt_at_index (cnat_timestamps, index);
  ts->last_seen = t;
  clib_rwlock_reader_unlock (&cnat_main.ts_lock);
}

always_inline void
cnat_timestamp_set_lifetime (u32 index, u16 lifetime)
{
  clib_rwlock_reader_lock (&cnat_main.ts_lock);
  cnat_timestamp_t *ts = pool_elt_at_index (cnat_timestamps, index);
  ts->lifetime = lifetime;
  clib_rwlock_reader_unlock (&cnat_main.ts_lock);
}

always_inline f64
cnat_timestamp_exp (u32 index)
{
  f64 t;
  if (INDEX_INVALID == index)
    return -1;
  clib_rwlock_reader_lock (&cnat_main.ts_lock);
  cnat_timestamp_t *ts = pool_elt_at_index (cnat_timestamps, index);
  t = ts->last_seen + (f64) ts->lifetime;
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
    pool_put (cnat_timestamps, ts);
  clib_rwlock_writer_unlock (&cnat_main.ts_lock);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
