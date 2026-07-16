/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vppinfra/random.h>
#include <wireguard/wireguard_index_table.h>

void
wg_index_table_init (wg_index_table_t *table)
{
  clib_bihash_init_8_8 (&table->hash, "wg index table", WG_INDEX_TABLE_NUM_BUCKETS,
			WG_INDEX_TABLE_MEMORY_SIZE);
}

u32
wg_index_table_add (wg_index_table_t *table, u32 peer_pool_idx, u32 rnd_seed)
{
  clib_bihash_kv_8_8_t kv;
  u32 key;

  while (1)
    {
      key = random_u32 (&rnd_seed);
      kv.key = key;
      if (clib_bihash_search_8_8 (&table->hash, &kv, &kv) == 0)
	continue;

      kv.key = key;
      kv.value = peer_pool_idx;
      clib_bihash_add_del_8_8 (&table->hash, &kv, 1 /* is_add */);
      break;
    }
  return key;
}

void
wg_index_table_del (wg_index_table_t *table, u32 key)
{
  clib_bihash_kv_8_8_t kv;

  kv.key = key;
  clib_bihash_add_del_8_8 (&table->hash, &kv, 0 /* is_add */);
}
