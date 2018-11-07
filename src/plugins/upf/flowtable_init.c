/*
 * Copyright (c) 2016 Qosmos and/or its affiliates.
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

#include <vnet/plugin/plugin.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/dlist.h>
#include <vppinfra/pool.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>

#include "flowtable.h"

flowtable_main_t flowtable_main;

clib_error_t *
flowtable_timelife_update(flowtable_timeout_type_t type, u16 value)
{
  flowtable_main_t * fm = &flowtable_main;

  if (value > fm->timer_max_lifetime)
    return clib_error_return (0, "value is too big");

  if (type >= FT_TIMEOUT_TYPE_MAX)
    return clib_error_return (0, "unknown timer type");

  fm->timer_lifetime[type] = value;

  return 0;
}

clib_error_t *
flowtable_max_timelife_update(u16 value)
{
  clib_error_t * error = 0;
  flowtable_main_t * fm = &flowtable_main;

  fm->timer_max_lifetime = value;

  return error;
}

static clib_error_t *
flowtable_init_cpu(flowtable_main_t *fm, flowtable_main_per_cpu_t * fmt)
{
  int i;
  flow_entry_t * f;
  clib_error_t * error = 0;

  /* init hashtable */
  BV(clib_bihash_init) (&fmt->flows_ht, "flow hash table",
			FM_NUM_BUCKETS, FM_MEMORY_SIZE);

  /* init timer wheel */
  fmt->time_index = ~0;
  for (i = 0; i < TIMER_MAX_LIFETIME; i++)
    {
      dlist_elt_t * timer_slot;
      pool_get(fmt->timers, timer_slot);

      u32 timer_slot_head_index = timer_slot - fmt->timers;
      clib_dlist_init(fmt->timers, timer_slot_head_index);
      vec_add1(fmt->timer_wheel, timer_slot_head_index);
    }

  /* fill flow entry cache */
  if (pthread_spin_lock(&fm->flows_lock) == 0)
    {
      for (i = 0; i < FLOW_CACHE_SZ; i++)
	{
	  pool_get_aligned(fm->flows, f, CLIB_CACHE_LINE_BYTES);
	  vec_add1(fmt->flow_cache, f - fm->flows);
	}
      fm->flows_cpt += FLOW_CACHE_SZ;

      pthread_spin_unlock(&fm->flows_lock);
    }

  return error;
}

clib_error_t *
flowtable_init(vlib_main_t * vm)
{
  u32 cpu_index;
  clib_error_t * error = 0;
  flowtable_main_t * fm = &flowtable_main;
  vlib_thread_main_t * tm = vlib_get_thread_main();

  fm->vlib_main = vm;

  /* init flow pool */
  fm->flows_max = FM_POOL_COUNT;
  pool_alloc_aligned(fm->flows, fm->flows_max, CLIB_CACHE_LINE_BYTES);
  pthread_spin_init(&fm->flows_lock, PTHREAD_PROCESS_PRIVATE);
  fm->flows_cpt = 0;

  for (flowtable_timeout_type_t i = FT_TIMEOUT_TYPE_UNKNOWN; i < FT_TIMEOUT_TYPE_MAX; i++)
    fm->timer_lifetime[i] = TIMER_DEFAULT_LIFETIME;
  fm->timer_max_lifetime = TIMER_MAX_LIFETIME;

  vec_validate(fm->per_cpu, tm->n_vlib_mains - 1);
  for (cpu_index = 0; cpu_index < tm->n_vlib_mains; cpu_index++)
    {
      error = flowtable_init_cpu(fm, &fm->per_cpu[cpu_index]);
      if (error)
	return error;
    }

  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
