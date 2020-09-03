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

#ifndef __included_wg_index_table_h__
#define __included_wg_index_table_h__

#include <vppinfra/types.h>

typedef struct
{
  uword *hash;
} wg_index_table_t;

u32 wg_index_table_add (wg_index_table_t * table, u32 peer_pool_idx,
			u32 rnd_seed);
void wg_index_table_del (wg_index_table_t * table, u32 key);
u32 *wg_index_table_lookup (const wg_index_table_t * table, u32 key);

#endif //__included_wg_index_table_h__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
