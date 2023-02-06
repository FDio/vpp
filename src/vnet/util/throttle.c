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

#include <vnet/util/throttle.h>

void
throttle_init (throttle_t * t, u32 n_threads, f64 time)
{
  throttle_init_v2 (t, n_threads, THROTTLE_BITS, time);
}

void
throttle_init_v2 (throttle_t *t, u32 n_threads, u64 buckets, f64 time)
{
  u32 i;

  t->time = time;
  t->buckets = 1 << max_log2 (buckets);
  vec_validate (t->bitmaps, n_threads);
  vec_validate (t->seeds, n_threads);
  vec_validate (t->last_seed_change_time, n_threads);

  for (i = 0; i < n_threads; i++)
    clib_bitmap_alloc (t->bitmaps[i], t->buckets);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
