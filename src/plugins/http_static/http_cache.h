/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco and/or its affiliates.
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
void hss_cache_free (hss_cache_t *hc);

u8 *format_hss_cache (u8 *s, va_list *args);

#endif /* SRC_PLUGINS_HTTP_STATIC_HTTP_CACHE_H_ */
