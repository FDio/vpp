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

#ifndef SRC_PLUGINS_HTTP_STATIC_HTTP_CACHE_H_
#define SRC_PLUGINS_HTTP_STATIC_HTTP_CACHE_H_

#include <vppinfra/bihash_vec8_8.h>

typedef struct hss_cache_entry_
{
  /** Name of the file */
  u8 *filename;
  /** Last modified date, format:
   *  <day-name>, <day> <month> <year> <hour>:<minute>:<second> GMT  */
  u8 *last_modified;
  /** Contents of the file, as a u8 * vector */
  u8 *data;
  /** Last time the cache entry was used */
  f64 last_used;
  /** Cache LRU links */
  u32 next_index;
  u32 prev_index;
  /** Reference count, so we don't recycle while referenced */
  int inuse;
} hss_cache_entry_t;

typedef struct hss_cache_
{
  /** Unified file data cache pool */
  hss_cache_entry_t *cache_pool;
  /** Hash table which maps file name to file data */
  BVT (clib_bihash) name_to_data;

  /** Session pool lock */
  clib_spinlock_t cache_lock;

  /** Current cache size */
  u64 cache_size;
  /** Max cache size in bytes */
  u64 cache_limit;
  /** Number of cache evictions */
  u64 cache_evictions;

  /** Cache LRU listheads */
  u32 first_index;
  u32 last_index;

  u8 debug_level;
} hss_cache_t;

u32 hss_cache_lookup_and_attach (hss_cache_t *hc, u8 *path, u8 **data,
				 u64 *data_len, u8 **last_modified);
u32 hss_cache_add_and_attach (hss_cache_t *hc, u8 *path, u8 **data,
			      u64 *data_len, u8 **last_modified);
void hss_cache_detach_entry (hss_cache_t *hc, u32 ce_index);
u32 hss_cache_clear (hss_cache_t *hc);
void hss_cache_init (hss_cache_t *hc, uword cache_size, u8 debug_level);

u8 *format_hss_cache (u8 *s, va_list *args);

#endif /* SRC_PLUGINS_HTTP_STATIC_HTTP_CACHE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
