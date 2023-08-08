/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/random.h>
#include <wireguard/wireguard_index_table.h>

u32
wg_index_table_add (vlib_main_t *vm, wg_index_table_t *table,
		    u32 peer_pool_idx, u32 rnd_seed)
{
  u32 key;

  /* TODO: Add a non-repeating 32bit generator to pcg.h and use as singleton. */
  while (1)
    {
      key = random_u32 (&rnd_seed);
      if (hash_get (table->hash, key))
	continue;

      vlib_worker_thread_barrier_sync (vm);
      hash_set (table->hash, key, peer_pool_idx);
      vlib_worker_thread_barrier_release (vm);
      break;
    }
  return key;
}

void
wg_index_table_del (vlib_main_t *vm, wg_index_table_t *table, u32 key)
{
  uword *p;
  p = hash_get (table->hash, key);
  if (p)
    {
      vlib_worker_thread_barrier_sync (vm);
      hash_unset (table->hash, key);
      vlib_worker_thread_barrier_release (vm);
    }
}

u32 *
wg_index_table_lookup (const wg_index_table_t * table, u32 key)
{
  uword *p;

  p = hash_get (table->hash, key);
  return (u32 *) p;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
