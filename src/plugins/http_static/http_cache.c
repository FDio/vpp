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

#include <http_static/http_cache.h>
#include <vppinfra/bihash_template.c>
#include <vppinfra/unix.h>
#include <vlib/vlib.h>

static void
hss_cache_lock (hss_cache_t *hc)
{
  clib_spinlock_lock (&hc->cache_lock);
}

static void
hss_cache_unlock (hss_cache_t *hc)
{
  clib_spinlock_unlock (&hc->cache_lock);
}

/** \brief Sanity-check the forward and reverse LRU lists
 */
static inline void
lru_validate (hss_cache_t *hc)
{
#if CLIB_DEBUG > 0
  f64 last_timestamp;
  u32 index;
  int i;
  hss_cache_entry_t *ce;

  last_timestamp = 1e70;
  for (i = 1, index = hc->first_index; index != ~0;)
    {
      ce = pool_elt_at_index (hc->cache_pool, index);
      /* Timestamps should be smaller (older) as we walk the fwd list */
      if (ce->last_used > last_timestamp)
	{
	  clib_warning ("%d[%d]: last used %.6f, last_timestamp %.6f", index,
			i, ce->last_used, last_timestamp);
	}
      index = ce->next_index;
      last_timestamp = ce->last_used;
      i++;
    }

  last_timestamp = 0.0;
  for (i = 1, index = hc->last_index; index != ~0;)
    {
      ce = pool_elt_at_index (hc->cache_pool, index);
      /* Timestamps should be larger (newer) as we walk the rev list */
      if (ce->last_used < last_timestamp)
	{
	  clib_warning ("%d[%d]: last used %.6f, last_timestamp %.6f", index,
			i, ce->last_used, last_timestamp);
	}
      index = ce->prev_index;
      last_timestamp = ce->last_used;
      i++;
    }
#endif
}

/** \brief Remove a data cache entry from the LRU lists
 */
static inline void
lru_remove (hss_cache_t *hc, hss_cache_entry_t *ce)
{
  hss_cache_entry_t *next_ep, *prev_ep;
  u32 ce_index;

  lru_validate (hc);

  ce_index = ce - hc->cache_pool;

  /* Deal with list heads */
  if (ce_index == hc->first_index)
    hc->first_index = ce->next_index;
  if (ce_index == hc->last_index)
    hc->last_index = ce->prev_index;

  /* Fix next->prev */
  if (ce->next_index != ~0)
    {
      next_ep = pool_elt_at_index (hc->cache_pool, ce->next_index);
      next_ep->prev_index = ce->prev_index;
    }
  /* Fix prev->next */
  if (ce->prev_index != ~0)
    {
      prev_ep = pool_elt_at_index (hc->cache_pool, ce->prev_index);
      prev_ep->next_index = ce->next_index;
    }
  lru_validate (hc);
}

/** \brief Add an entry to the LRU lists, tag w/ supplied timestamp
 */
static inline void
lru_add (hss_cache_t *hc, hss_cache_entry_t *ce, f64 now)
{
  hss_cache_entry_t *next_ce;
  u32 ce_index;

  lru_validate (hc);

  ce_index = ce - hc->cache_pool;

  /*
   * Re-add at the head of the forward LRU list,
   * tail of the reverse LRU list
   */
  if (hc->first_index != ~0)
    {
      next_ce = pool_elt_at_index (hc->cache_pool, hc->first_index);
      next_ce->prev_index = ce_index;
    }

  ce->prev_index = ~0;

  /* ep now the new head of the LRU forward list */
  ce->next_index = hc->first_index;
  hc->first_index = ce_index;

  /* single session case: also the tail of the reverse LRU list */
  if (hc->last_index == ~0)
    hc->last_index = ce_index;
  ce->last_used = now;

  lru_validate (hc);
}

/** \brief Remove and re-add a cache entry from/to the LRU lists
 */
static inline void
lru_update (hss_cache_t *hc, hss_cache_entry_t *ep, f64 now)
{
  lru_remove (hc, ep);
  lru_add (hc, ep, now);
}

static void
hss_cache_attach_entry (hss_cache_t *hc, u32 ce_index, u8 **data,
			u64 *data_len)
{
  hss_cache_entry_t *ce;

  /* Expect ce_index to be validated outside */
  ce = pool_elt_at_index (hc->cache_pool, ce_index);
  ce->inuse++;
  *data = ce->data;
  *data_len = vec_len (ce->data);

  /* Update the cache entry, mark it in-use */
  lru_update (hc, ce, vlib_time_now (vlib_get_main ()));

  if (hc->debug_level > 1)
    clib_warning ("index %d refcnt now %d", ce_index, ce->inuse);
}

/** \brief Detach cache entry from session
 */
void
hss_cache_detach_entry (hss_cache_t *hc, u32 ce_index)
{
  hss_cache_entry_t *ce;

  hss_cache_lock (hc);

  ce = pool_elt_at_index (hc->cache_pool, ce_index);
  ce->inuse--;

  if (hc->debug_level > 1)
    clib_warning ("index %d refcnt now %d", ce_index, ce->inuse);

  hss_cache_unlock (hc);
}

static u32
hss_cache_lookup (hss_cache_t *hc, u8 *path)
{
  BVT (clib_bihash_kv) kv;
  int rv;

  kv.key = (u64) path;
  kv.value = ~0;

  /* Value updated only if lookup succeeds */
  rv = BV (clib_bihash_search) (&hc->name_to_data, &kv, &kv);
  ASSERT (!rv || kv.value == ~0);

  if (hc->debug_level > 1)
    clib_warning ("lookup '%s' %s", kv.key, kv.value == ~0 ? "fail" : "found");

  return kv.value;
}

u32
hss_cache_lookup_and_attach (hss_cache_t *hc, u8 *path, u8 **data,
			     u64 *data_len)
{
  u32 ce_index;

  /* Make sure nobody removes the entry while we look it up */
  hss_cache_lock (hc);

  ce_index = hss_cache_lookup (hc, path);
  if (ce_index != ~0)
    hss_cache_attach_entry (hc, ce_index, data, data_len);

  hss_cache_unlock (hc);

  return ce_index;
}

static void
hss_cache_do_evictions (hss_cache_t *hc)
{
  BVT (clib_bihash_kv) kv;
  hss_cache_entry_t *ce;
  u32 free_index;

  free_index = hc->last_index;

  while (free_index != ~0)
    {
      /* pick the LRU */
      ce = pool_elt_at_index (hc->cache_pool, free_index);
      /* Which could be in use... */
      if (ce->inuse)
	{
	  if (hc->debug_level > 1)
	    clib_warning ("index %d in use refcnt %d", free_index, ce->inuse);
	}
      free_index = ce->prev_index;
      kv.key = (u64) (ce->filename);
      kv.value = ~0ULL;
      if (BV (clib_bihash_add_del) (&hc->name_to_data, &kv, 0 /* is_add */) <
	  0)
	{
	  clib_warning ("LRU delete '%s' FAILED!", ce->filename);
	}
      else if (hc->debug_level > 1)
	clib_warning ("LRU delete '%s' ok", ce->filename);

      lru_remove (hc, ce);
      hc->cache_size -= vec_len (ce->data);
      hc->cache_evictions++;
      vec_free (ce->filename);
      vec_free (ce->data);

      if (hc->debug_level > 1)
	clib_warning ("pool put index %d", ce - hc->cache_pool);

      pool_put (hc->cache_pool, ce);
      if (hc->cache_size < hc->cache_limit)
	break;
    }
}

u32
hss_cache_add_and_attach (hss_cache_t *hc, u8 *path, u8 **data, u64 *data_len)
{
  BVT (clib_bihash_kv) kv;
  hss_cache_entry_t *ce;
  clib_error_t *error;
  u8 *file_data;
  u32 ce_index;

  hss_cache_lock (hc);

  /* Need to recycle one (or more cache) entries? */
  if (hc->cache_size > hc->cache_limit)
    hss_cache_do_evictions (hc);

  /* Read the file */
  error = clib_file_contents ((char *) path, &file_data);
  if (error)
    {
      clib_warning ("Error reading '%s'", path);
      clib_error_report (error);
      return ~0;
    }

  /* Create a cache entry for it */
  pool_get_zero (hc->cache_pool, ce);
  ce->filename = vec_dup (path);
  ce->data = file_data;

  /* Attach cache entry without additional lock */
  ce->inuse++;
  *data = file_data;
  *data_len = vec_len (file_data);
  lru_add (hc, ce, vlib_time_now (vlib_get_main ()));

  hc->cache_size += vec_len (ce->data);
  ce_index = ce - hc->cache_pool;

  if (hc->debug_level > 1)
    clib_warning ("index %d refcnt now %d", ce_index, ce->inuse);

  /* Add to the lookup table */

  kv.key = (u64) vec_dup (path);
  kv.value = ce_index;

  if (hc->debug_level > 1)
    clib_warning ("add '%s' value %lld", kv.key, kv.value);

  if (BV (clib_bihash_add_del) (&hc->name_to_data, &kv, 1 /* is_add */) < 0)
    {
      clib_warning ("BUG: add failed!");
    }

  hss_cache_unlock (hc);

  return ce_index;
}

u32
hss_cache_clear (hss_cache_t *hc)
{
  u32 free_index, busy_items = 0;
  hss_cache_entry_t *ce;
  BVT (clib_bihash_kv) kv;

  hss_cache_lock (hc);

  /* Walk the LRU list to find active entries */
  free_index = hc->last_index;
  while (free_index != ~0)
    {
      ce = pool_elt_at_index (hc->cache_pool, free_index);
      free_index = ce->prev_index;
      /* Which could be in use... */
      if (ce->inuse)
	{
	  busy_items++;
	  free_index = ce->next_index;
	  continue;
	}
      kv.key = (u64) (ce->filename);
      kv.value = ~0ULL;
      if (BV (clib_bihash_add_del) (&hc->name_to_data, &kv, 0 /* is_add */) <
	  0)
	{
	  clib_warning ("BUG: cache clear delete '%s' FAILED!", ce->filename);
	}

      lru_remove (hc, ce);
      hc->cache_size -= vec_len (ce->data);
      hc->cache_evictions++;
      vec_free (ce->filename);
      vec_free (ce->data);
      if (hc->debug_level > 1)
	clib_warning ("pool put index %d", ce - hc->cache_pool);
      pool_put (hc->cache_pool, ce);
      free_index = hc->last_index;
    }

  hss_cache_unlock (hc);

  return busy_items;
}

void
hss_cache_init (hss_cache_t *hc, uword cache_size, u8 debug_level)
{
  clib_spinlock_init (&hc->cache_lock);

  /* Init path-to-cache hash table */
  BV (clib_bihash_init) (&hc->name_to_data, "http cache", 128, 32 << 20);

  hc->cache_limit = cache_size;
  hc->debug_level = debug_level;
  hc->first_index = hc->last_index = ~0;
}

/** \brief format a file cache entry
 */
static u8 *
format_hss_cache_entry (u8 *s, va_list *args)
{
  hss_cache_entry_t *ep = va_arg (*args, hss_cache_entry_t *);
  f64 now = va_arg (*args, f64);

  /* Header */
  if (ep == 0)
    {
      s = format (s, "%40s%12s%20s", "File", "Size", "Age");
      return s;
    }
  s = format (s, "%40s%12lld%20.2f", ep->filename, vec_len (ep->data),
	      now - ep->last_used);
  return s;
}

u8 *
format_hss_cache (u8 *s, va_list *args)
{
  hss_cache_t *hc = va_arg (*args, hss_cache_t *);
  u32 verbose = va_arg (*args, u32);
  hss_cache_entry_t *ce;
  vlib_main_t *vm;
  u32 index;
  f64 now;

  if (verbose == 0)
    {
      s = format (s, "cache size %lld bytes, limit %lld bytes, evictions %lld",
		  hc->cache_size, hc->cache_limit, hc->cache_evictions);
      return s;
    }

  vm = vlib_get_main ();
  now = vlib_time_now (vm);

  s = format (s, "%U\n", format_hss_cache_entry, 0 /* header */, now);

  for (index = hc->first_index; index != ~0;)
    {
      ce = pool_elt_at_index (hc->cache_pool, index);
      index = ce->next_index;
      s = format (s, "%U\n", format_hss_cache_entry, ce, now);
    }

  s = format (s, "%40s%12lld", "Total Size", hc->cache_size);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
