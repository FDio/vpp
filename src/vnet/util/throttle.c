/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vnet/util/throttle.h>

void
throttle_init (throttle_t *t, u32 n_threads, u32 buckets, f64 time)
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
