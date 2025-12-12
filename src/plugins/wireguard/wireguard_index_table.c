/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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
