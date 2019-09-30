/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __LCP_ADJ_DELEGATE_H__
#define __LCP_ADJ_DELEGATE_H__

#include <vppinfra/bihash_24_8.h>

typedef struct lcp_adj_key_t_
{
  u32 sw_if_index;
  u8 rewrite[18];
} lcp_adj_key_t;

STATIC_ASSERT (sizeof(lcp_adj_key_t) <= 24, "");

typedef struct lcp_adj_kv_t_
{
  union {
    clib_bihash_kv_24_8_t kv;
    struct {
      lcp_adj_key_t k;
      u64 v;
    };
  };
} lcp_adj_kv_t;

/**
 * The table of adjacencies indexed by the rewrite string
 */
extern BVT(clib_bihash) lcp_adj_tbl;

static_always_inline void
lcp_adj_mk_key (const u8 *rewrite,
                u8 len,
                u32 sw_if_index,
                lcp_adj_key_t *key)
{
  ASSERT(len < sizeof(key->rewrite));
  clib_memcpy_fast (key->rewrite, rewrite, len);
  clib_memset(key->rewrite + len, 0, sizeof(key->rewrite) - len);
  key->sw_if_index = sw_if_index;
}

static_always_inline adj_index_t
lcp_adj_lkup (const u8 *rewrite,
              u8 len,
              u32 sw_if_index)
{
    lcp_adj_kv_t kv;

    lcp_adj_mk_key (rewrite,len, sw_if_index, &kv.k);

    if (BV(clib_bihash_search_inline) (&lcp_adj_tbl, &kv.kv))
        return (kv.v);

    return (ADJ_INDEX_INVALID);
}

#endif
