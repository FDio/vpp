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

#include <vnet/util/refcount.h>

void __vlib_refcount_resize(vlib_refcount_per_cpu_t *per_cpu, u32 size)
{
  u32 *new_counter = 0, *old_counter;
  vec_validate(new_counter, size);
  vlib_refcount_lock(per_cpu->counter_lock);
  memcpy(new_counter, per_cpu->counters, vec_len(per_cpu->counters)*4);
  old_counter = per_cpu->counters;
  per_cpu->counters = new_counter;
  vlib_refcount_unlock(per_cpu->counter_lock);
  CLIB_MEMORY_BARRIER();
  vec_free(old_counter);
}

u64 vlib_refcount_get(vlib_refcount_t *r, u32 index)
{
  u64 count = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_thread_index_t thread_index;
  for (thread_index = 0; thread_index < tm->n_vlib_mains; thread_index++) {
    vlib_refcount_lock(r->per_cpu[thread_index].counter_lock);
    if (index < vec_len(r->per_cpu[thread_index].counters))
      {
        count += r->per_cpu[thread_index].counters[index];
      }
    vlib_refcount_unlock(r->per_cpu[thread_index].counter_lock);
  }
  return count;
}

