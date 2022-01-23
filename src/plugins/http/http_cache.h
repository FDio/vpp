/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#ifndef SRC_PLUGINS_HTTP_HTTP_CACHE_H_
#define SRC_PLUGINS_HTTP_HTTP_CACHE_H_

#include <vppinfra/bihash_vec8_8.h>

typedef struct http_cache_entry_
{
  u32 ce_index;
  /** Name of the file */
  u8 *key;
  /** Contents of the file, as a u8 * vector */
  u8 *data;
  /** Last time the cache entry was used */
  f64 last_used;
  /** Cache LRU links */
  u32 next_index;
  u32 prev_index;
  /** Reference count, so we don't recycle while referenced */
  int inuse;
} http_cache_entry_t;

typedef struct http_cache_
{
  /** Pool of cache entries */
  http_cache_entry_t *cache_entries;

  /** Hash table which maps file name to file data */
  BVT (clib_bihash) key_to_data;

  /** Current cache size */
  u64 cache_size;
  /** Max cache size in bytes */
  u64 cache_limit;
  /** Number of cache evictions */
  u64 cache_evictions;

  /** Cache LRU listheads */
  u32 first_index;
  u32 last_index;
} http_cache_t;

int http_cache_add (http_cache_t *hc, u8 *key, u8 *value);
int http_cache_del (http_cache_t *hc, u32 ce_index);
int http_cache_lookup (http_cache_t *hc, u8 *key);

int http_cache_init (http_cache_t *hc, u32 cache_size);
format_function_t format_http_cache_entry;

#endif /* SRC_PLUGINS_HTTP_HTTP_CACHE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
