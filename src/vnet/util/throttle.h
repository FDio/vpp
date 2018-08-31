/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __THROTTLE_H__
#define __THROTTLE_H__

#include <vlib/vlib.h>
#include <vppinfra/xxhash.h>

/**
 * @brief A throttle
 *  Used in the data plane to decide if a given hash should be throttled,
 *  i.e. that the hash has been seen already 'recently'. Recent is the time
 *  given in the throttle's initialisation.
 */
typedef struct throttle_t_
{
  f64 time;
  uword **bitmaps;
  u64 *seeds;
  f64 *last_seed_change_time;
} throttle_t;

#define THROTTLE_BITS	(512)

extern void throttle_init (throttle_t * t, u32 n_threads, f64 time);

always_inline u64
throttle_seed (throttle_t * t, u32 thread_index, f64 time_now)
{
  if (time_now - t->last_seed_change_time[thread_index] > t->time)
    {
      (void) random_u64 (&t->seeds[thread_index]);
      memset (t->bitmaps[thread_index], 0, THROTTLE_BITS / BITS (u8));

      t->last_seed_change_time[thread_index] = time_now;
    }
  return t->seeds[thread_index];
}

always_inline int
throttle_check (throttle_t * t, u32 thread_index, u64 hash, u64 seed)
{
  int drop;
  uword m;
  u32 w;

  hash = clib_xxhash (hash ^ seed);

  /* Select bit number */
  hash &= THROTTLE_BITS - 1;
  w = hash / BITS (uword);
  m = (uword) 1 << (hash % BITS (uword));

  drop = (t->bitmaps[thread_index][w] & m) != 0;
  t->bitmaps[thread_index][w] |= m;

  return (drop);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
