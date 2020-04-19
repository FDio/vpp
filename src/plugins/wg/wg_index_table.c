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


#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/random.h>
#include <wg/crypto/random.h>
#include <wg/wg_peer.h>
#include <wg/wg_index_table.h>

u32
wg_index_table_add (wg_index_table_t * table, u32 peer_pool_idx)
{
  u32 key;
  uword *p;
  index_table_entry_t *entry;

  while (1)
    {
      key = get_random_u32 ();
      p = hash_get (table->hash, key);
      if (p)
	continue;
      break;
    }

  pool_get (table->entry_pool, entry);

  u32 i = entry - table->entry_pool;
  entry->peer_pool_idx = peer_pool_idx;

  hash_set (table->hash, key, i);

  return key;
}

void
wg_index_table_del (wg_index_table_t * table, u32 key)
{
  uword *p;
  p = hash_get (table->hash, key);
  if (p)
    {
      pool_put_index (table->entry_pool, p[0]);
      hash_unset (table->hash, key);
    }
}

index_table_entry_t *
wg_index_table_lookup (const wg_index_table_t * table, u32 key)
{
  uword *p;
  p = hash_get (table->hash, key);
  if (p)
    {
      return pool_elt_at_index (table->entry_pool, p[0]);
    }
  return 0;
}

void
wg_index_table_add_keypair (wg_index_table_t * table, u32 key,
			    noise_keypair_t * keypair)
{

  index_table_entry_t *entry;
  entry = wg_index_table_lookup (table, key);

  if (entry)
    {
      entry->keypair = keypair;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
