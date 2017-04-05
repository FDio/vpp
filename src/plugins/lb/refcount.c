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

#include <lb/refcount.h>

void __vlib_refcount_resize(vlib_refcount_per_cpu_t *per_cpu, u32 size)
{
  u32 *new_counter = 0, *old_counter;
  vec_validate(new_counter, size);
  memcpy(new_counter, per_cpu->counters, per_cpu->length);
  old_counter = per_cpu->counters;
  per_cpu->counters = new_counter;
  CLIB_MEMORY_BARRIER();
  per_cpu->length = vec_len(new_counter);
  vec_free(old_counter);
}

u64 vlib_refcount_get(vlib_refcount_t *r, u32 index)
{
  u64 count = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 thread_index;
  for (thread_index = 0; thread_index < tm->n_vlib_mains; thread_index++) {
    if (r->per_cpu[thread_index].length > index)
      count += r->per_cpu[thread_index].counters[index];
  }
  return count;
}

