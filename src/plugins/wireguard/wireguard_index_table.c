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
#include <wireguard/wireguard_index_table.h>

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>

u32
wg_index_table_add (wg_index_table_t * table, u32 peer_pool_idx, u32 rnd_seed)
{
  u32 key;

  if (!table->r_hash_table_lock)
    {
      clib_rwlock_init (&table->r_hash_table_lock);
    }

  while (1)
    {
      key = random_u32 (&rnd_seed);
      clib_rwlock_reader_lock (&table->r_hash_table_lock);
      if (hash_get (table->hash, key))
	{
	  clib_rwlock_reader_unlock (&table->r_hash_table_lock);
	  continue;
	}
      clib_rwlock_reader_unlock (&table->r_hash_table_lock);

      clib_rwlock_writer_lock (&table->r_hash_table_lock);
      hash_set (table->hash, key, peer_pool_idx);
      clib_rwlock_writer_unlock (&table->r_hash_table_lock);
      break;
    }
  return key;
}

void
wg_index_table_del (wg_index_table_t * table, u32 key)
{
  uword *p;
  clib_rwlock_reader_lock (&table->r_hash_table_lock);
  p = hash_get (table->hash, key);
  clib_rwlock_reader_unlock (&table->r_hash_table_lock);
  if (p)
    {
      clib_rwlock_writer_lock (&table->r_hash_table_lock);
      hash_unset (table->hash, key);
      clib_rwlock_writer_unlock (&table->r_hash_table_lock);
    }
}

u32 *
wg_index_table_lookup (const wg_index_table_t * table, u32 key)
{
  uword *p;
  clib_rwlock_t *r_tab_lock;
  r_tab_lock = (clib_rwlock_t *) &table->r_hash_table_lock;
  clib_rwlock_reader_lock (r_tab_lock);
  p = hash_get (table->hash, key);
  clib_rwlock_reader_unlock (r_tab_lock);
  return (u32 *) p;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
