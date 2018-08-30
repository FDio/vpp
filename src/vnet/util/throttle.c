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
  u32 i;

  t->time = time;
  vec_validate (t->bitmaps, n_threads);
  vec_validate (t->seeds, n_threads);
  vec_validate (t->last_seed_change_time, n_threads);

  for (i = 0; i < n_threads; i++)
    vec_validate (t->bitmaps[i], (THROTTLE_BITS / BITS (uword)) - 1);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
