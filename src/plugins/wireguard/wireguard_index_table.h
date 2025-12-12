/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 */

#ifndef __included_wg_index_table_h__
#define __included_wg_index_table_h__

#include <vlib/vlib.h>
#include <vppinfra/types.h>

typedef struct
{
  uword *hash;
} wg_index_table_t;

u32 wg_index_table_add (vlib_main_t *vm, wg_index_table_t *table,
			u32 peer_pool_idx, u32 rnd_seed);
void wg_index_table_del (vlib_main_t *vm, wg_index_table_t *table, u32 key);
u32 *wg_index_table_lookup (const wg_index_table_t * table, u32 key);

#endif //__included_wg_index_table_h__
