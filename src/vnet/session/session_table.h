/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_SESSION_SESSION_TABLE_H_
#define SRC_VNET_SESSION_SESSION_TABLE_H_

#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_48_8.h>

typedef struct _session_lookup_table
{
  /**
   * Lookup tables for established sessions and listeners
   */
  clib_bihash_16_8_t v4_session_hash;
  clib_bihash_48_8_t v6_session_hash;

  /**
   * Lookup tables for half-open sessions
   */
  clib_bihash_16_8_t v4_half_open_hash;
  clib_bihash_48_8_t v6_half_open_hash;
} session_table_t;

#define SESSION_TABLE_INVALID_INDEX ((u32)~0)
#define SESSION_LOCAL_TABLE_PREFIX ((u32)~0)
#define SESSION_INVALID_INDEX ((u32)~0)
#define SESSION_INVALID_HANDLE ((u64)~0)

typedef int (*ip4_session_table_walk_fn_t) (clib_bihash_kv_16_8_t * kvp,
					    void *ctx);

void ip4_session_table_walk_cb (clib_bihash_kv_16_8_t * kvp, void *arg);
void ip4_session_table_walk (clib_bihash_16_8_t * hash,
			     ip4_session_table_walk_fn_t fn, void *arg);

session_table_t *session_table_alloc (void);
session_table_t *session_table_get (u32 table_index);
u32 session_table_index (session_table_t * slt);
void session_table_init (session_table_t * slt);

#endif /* SRC_VNET_SESSION_SESSION_TABLE_H_ */
/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
