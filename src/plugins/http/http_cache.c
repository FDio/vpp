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

#include <http/http_cache.h>
#include <http/http.h>
#include <vppinfra/bihash_vec8_8.h>

static inline void
lru_validate (http_cache_t *hc)
{
#if CLIB_DEBUG > 0
  f64 last_timestamp;
  u32 index;
  int i;
  http_cache_entry_t *ep;

  last_timestamp = 1e70;
  for (i = 1, index = hc->first_index; index != ~0;)
    {
      ep = pool_elt_at_index (hc->cache_entries, index);
      index = ep->next_index;
      /* Timestamps should be smaller (older) as we walk the fwd list */
      if (ep->last_used > last_timestamp)
	{
	  clib_warning ("%d[%d]: last used %.6f, last_timestamp %.6f",
			ep - hc->cache_entries, i, ep->last_used, last_timestamp);
	}
      last_timestamp = ep->last_used;
      i++;
    }

  last_timestamp = 0.0;
  for (i = 1, index = hc->last_index; index != ~0;)
    {
      ep = pool_elt_at_index (hc->cache_entries, index);
      index = ep->prev_index;
      /* Timestamps should be larger (newer) as we walk the rev list */
      if (ep->last_used < last_timestamp)
	{
	  clib_warning ("%d[%d]: last used %.6f, last_timestamp %.6f",
			ep - hc->cache_entries, i, ep->last_used, last_timestamp);
	}
      last_timestamp = ep->last_used;
      i++;
    }
#endif
}

static inline void
lru_remove (http_cache_t *hc, http_cache_entry_t *ce)
{
  http_cache_entry_t *next_ep, *prev_ep;
  u32 ce_index;

  lru_validate (hc);

  ce_index = ce->ce_index;

  /* Deal with list heads */
  if (ce_index == hc->first_index)
    hc->first_index = ce->next_index;
  if (ce_index == hc->last_index)
    hc->last_index = ce->prev_index;

  /* Fix next->prev */
  if (ce->next_index != ~0)
    {
      next_ep = pool_elt_at_index (hc->cache_entries, ce->next_index);
      next_ep->prev_index = ce->prev_index;
    }
  /* Fix prev->next */
  if (ce->prev_index != ~0)
    {
      prev_ep = pool_elt_at_index (hc->cache_entries, ce->prev_index);
      prev_ep->next_index = ce->next_index;
    }
  lru_validate (hc);
}

static inline void
lru_add (http_cache_t *hc, http_cache_entry_t *ce, f64 now)
{
  http_cache_entry_t *next_ep;
  u32 ce_index;

  lru_validate (hc);

  ce_index = ce->ce_index;

  /*
   * Re-add at the head of the forward LRU list,
   * tail of the reverse LRU list
   */
  if (hc->first_index != ~0)
    {
      next_ep = pool_elt_at_index (hc->cache_entries, hc->first_index);
      next_ep->prev_index = ce_index;
    }

  ce->prev_index = ~0;

  /* ce now the new head of the LRU forward list */
  ce->next_index = hc->first_index;
  hc->first_index = ce_index;

  /* single entry case: also the tail of the reverse LRU list */
  if (hc->last_index == ~0)
    hc->last_index = ce_index;
  ce->last_used = now;

  lru_validate (hc);
}

static inline void
lru_update (http_cache_t *hc, http_cache_entry_t *ep, f64 now)
{
  lru_remove (hc, ep);
  lru_add (hc, ep, now);
}

static inline http_cache_entry_t *
http_cache_entry_alloc (http_cache_t *hc)
{
  http_cache_entry_t *ce;

  pool_get_zero (hc->cache_entries, ce);
  ce->ce_index = ce - hc->cache_entries;
  ce->next_index = ~0;
  ce->prev_index = ~0;
  return ce;
}

static inline void
http_cache_entry_free (http_cache_t *hc, http_cache_entry_t *ce)
{
  pool_put (hc->cache_entries, ce);
}

static inline http_cache_entry_t *
http_cache_entry_get (http_cache_t *hc, u32 ce_index)
{
  if (pool_is_free_index (hc->cache_entries, ce_index))
    return 0;
  return pool_elt_at_index (hc->cache_entries, ce_index);
}

int
http_cache_add (http_cache_t *hc, u8 *key, u8 *value)
{
  BVT (clib_bihash_kv) kv;
  http_cache_entry_t *ce;

  ce = http_cache_entry_alloc (hc);
  ce->key = vec_dup (key);
  ce->data = value;
  //  hs->cache_pool_index = dp - hc->cache_pool;
//  ce->inuse++;
  //  if (hc->debug_level > 1)
  //    clib_warning ("index %d refcnt now %d", hs->cache_pool_index,
  //		  dp->inuse);
//  lru_add (hc, ce, vlib_time_now (vlib_get_main ()));
//  kv.key = (u64) vec_dup (ce->filename);
//  kv.value = ce - hc->cache_pool;
  /* Add to the lookup table */
  //  if (hc->debug_level > 1)
  //    clib_warning ("add '%s' value %lld", kv.key, kv.value);

  if (BV (clib_bihash_add_del) (&hc->key_to_data, &kv, 1 /* is_add */) < 0)
    {
      clib_warning ("BUG: add failed!");
      return -1;
    }
  hc->cache_size += vec_len (ce->data);

  return ce->ce_index;
}

int
http_cache_del (http_cache_t *hc, u32 ce_index)
{
  BVT (clib_bihash_kv) kv;
  http_cache_entry_t *ce;

  ce = http_cache_entry_get (hc, ce_index);

  kv.key = (u64) (ce->key);
  kv.value = ~0ULL;

  if (BV (clib_bihash_add_del) (&hc->key_to_data, &kv, 0 /* is_add */) < 0)
    {
      clib_warning ("Cache delete '%s' FAILED!", kv.key);
      return -1;
    }

  //  if (hsm->debug_level > 1)
  //    clib_warning ("Cache delete '%s' ok", key);

  lru_remove (hc, ce);
  hc->cache_size -= vec_len (ce->data);
  hc->cache_evictions++;
  vec_free (ce->key);
  vec_free (ce->data);
  //  if (hsm->debug_level > 1)
  //    clib_warning ("pool put index %d", ce->entry_index);
  http_cache_entry_free (hc, ce);

  return 0;
}

int
http_cache_lookup (http_cache_t *hc, u8 *key)
{
  BVT (clib_bihash_kv) kv;

  kv.key = (u64) key;
  if (BV (clib_bihash_search) (&hc->key_to_data, &kv, &kv) != 0)
    return -1;

  return kv.value;
}

int
http_cache_attach_entry (http_cache_t *hc, u32 ce_index)
{
  http_cache_entry_t *ce;

  ce = http_cache_entry_get (hc, ce_index);
  if (!ce)
    return -1;

  lru_update (hc, ce, vlib_time_now (vlib_get_main ()));
  ce->inuse++;

  return 0;
}

void
http_cache_detach_entry (http_cache_t *hc, u32 ce_index)
{
  http_cache_entry_t *ce;

  ce = http_cache_entry_get (hc, ce_index);
  if (!ce)
    return;

  ce->inuse -= 1;
  //  if (hc->debug_level > 1)
  //    clib_warning ("index %d refcnt now %d", ce_index, ce->inuse);
}

int
http_cache_init (http_cache_t *hc, u32 cache_size)
{
  hc->cache_size = cache_size;

  BV (clib_bihash_init) (&hc->key_to_data, "http cache", 128, 32 << 20);

  return 0;
}

u8 *
format_http_cache_entry (u8 *s, va_list *args)
{
  http_cache_entry_t *ce = va_arg (*args, http_cache_entry_t *);
  f64 now = va_arg (*args, f64);

  /* Header */
  if (ce == 0)
    {
      s = format (s, "%40s%12s%20s", "File", "Size", "Age");
      return s;
    }
  s = format (s, "%40s%12lld%20.2f", ce->key, vec_len (ce->data),
	      now - ce->last_used);
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
