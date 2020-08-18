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
#include <wg/wg_index_table.h>

u32
wg_index_table_add (wg_index_table_t * table, u32 peer_pool_idx)
{
  u32 key;

  while (1)
    {
      key = get_random_u32 ();
      if (hash_get (table->hash, key))
	continue;

      hash_set (table->hash, key, peer_pool_idx);
      break;
    }
  return key;
}

void
wg_index_table_del (wg_index_table_t * table, u32 key)
{
  uword *p;
  p = hash_get (table->hash, key);
  if (p)
    hash_unset (table->hash, key);
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
