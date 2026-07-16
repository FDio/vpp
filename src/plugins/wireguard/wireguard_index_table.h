/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 */

#ifndef __included_wg_index_table_h__
#define __included_wg_index_table_h__

#include <vlib/vlib.h>
#include <vppinfra/types.h>
#include <vppinfra/bihash_8_8.h>

/* Sender-index -> peer pool index map. Written from the main thread (and,
 * on keypair rotation, from the peer's input worker); searched lock-free
 * from all workers in the rx/handoff paths. Each peer holds at most one
 * in-flight handshake index plus three keypair indices. */
#define WG_INDEX_TABLE_NUM_BUCKETS (1 << 13)
#define WG_INDEX_TABLE_MEMORY_SIZE (1 << 22)

typedef struct
{
  clib_bihash_8_8_t hash;
} wg_index_table_t;

void wg_index_table_init (wg_index_table_t *table);
u32 wg_index_table_add (wg_index_table_t *table, u32 peer_pool_idx, u32 rnd_seed);
void wg_index_table_del (wg_index_table_t *table, u32 key);

/* returns the peer pool index, ~0 if not found */
static_always_inline u32
wg_index_table_lookup (wg_index_table_t *table, u32 key)
{
  clib_bihash_kv_8_8_t kv;

  kv.key = key;
  if (clib_bihash_search_inline_8_8 (&table->hash, &kv) < 0)
    return ~0;
  return (u32) kv.value;
}

#endif //__included_wg_index_table_h__
