/*
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

/*
 * vlib provides lock-free counters but those
 * - Have 16bits per-CPU counter, which may overflow.
 * - Would only increment.
 *
 * This is very similar to vlib counters, but may be used to count reference.
 * Such a counter includes an arbitrary number of counters. Each counter
 * is identified by its index. This is used to aggregate per-cpu memory.
 *
 * Warning:
 *   This reference counter is lock-free but is not race-condition free.
 *   The counting result is approximate and another mechanism needs to be used
 *   in order to ensure that an object may be freed.
 *
 */

#include <vnet/vnet.h>

typedef struct {
  u32 *counters;
  u32 length;
  u32 *reader_lengths;
  CLIB_CACHE_LINE_ALIGN_MARK(o);
} vlib_refcount_per_cpu_t;

typedef struct {
  vlib_refcount_per_cpu_t *per_cpu;
} vlib_refcount_t;

void __vlib_refcount_resize(vlib_refcount_per_cpu_t *per_cpu, u32 size);

static_always_inline
void vlib_refcount_add(vlib_refcount_t *r, u32 thread_index, u32 counter_index, i32 v)
{
  vlib_refcount_per_cpu_t *per_cpu = &r->per_cpu[thread_index];
  if (PREDICT_FALSE(counter_index >= per_cpu->length))
    __vlib_refcount_resize(per_cpu, clib_max(counter_index + 16, per_cpu->length * 2));

  per_cpu->counters[counter_index] += v;
}

u64 vlib_refcount_get(vlib_refcount_t *r, u32 index);

static_always_inline
void vlib_refcount_init(vlib_refcount_t *r)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  r->per_cpu = 0;
  vec_validate (r->per_cpu, tm->n_vlib_mains - 1);
}


