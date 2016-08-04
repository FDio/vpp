/*
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

/**
 * vppinfra already includes tons of different hash tables.
 * MagLev flow table is a bit different. It has to be very efficient
 * for both writing and reading operations. But it does not need to
 * be 100% reliable (write can fail). It also needs to recycle
 * old entries in a lazy way.
 *
 * This hash table is the most dummy hash table you can do.
 * Fixed total size, fixed bucket size.
 * Advantage is that it could be very efficient (maybe).
 *
 */

#ifndef LB_PLUGIN_LB_LBHASH_H_
#define LB_PLUGIN_LB_LBHASH_H_

#include <vnet/vnet.h>

#define LBHASH_ENTRY_PER_BUCKET_LOG2 2
#define LBHASH_ENTRY_PER_BUCKET (1 << LBHASH_ENTRY_PER_BUCKET_LOG2)
#define LBHASH_ENTRY_PER_BUCKET_MASK (LBHASH_ENTRY_PER_BUCKET - 1)

typedef struct {
  u64 key[5];
  u32 value;
  u32 last_seen;
} lb_hash_entry_t;

typedef struct {
  u32 buckets_mask;
  u32 timeout;
  lb_hash_entry_t entries[];
} lb_hash_t;

#define lb_hash_nbuckets(h) (((h)->buckets_mask >> LBHASH_ENTRY_PER_BUCKET_LOG2) + 1)
#define lb_hash_size(h) ((h)->buckets_mask + LBHASH_ENTRY_PER_BUCKET)

#define lb_hash_foreach_entry(h, e) \
  for (e = (h)->entries; e < h->entries + lb_hash_size(h); e++)

#define lb_hash_foreach_valid_entry(h, e, now) \
    lb_hash_foreach_entry(h, e) \
       if (!clib_u32_loop_gt((now), (e)->last_seen + (h)->timeout))

static_always_inline
lb_hash_t *lb_hash_alloc(u32 buckets, u32 timeout)
{
  if ((!is_pow2(buckets)) ||
      ((buckets << LBHASH_ENTRY_PER_BUCKET_LOG2) == 0))
    return NULL;

  // Allocate 1 more bucket for prefetch
  u32 size = sizeof(lb_hash_t) + ((buckets << LBHASH_ENTRY_PER_BUCKET_LOG2) + 1)* sizeof(lb_hash_entry_t);
  u8 *mem = 0;
  lb_hash_t *h;
  vec_alloc_aligned(mem, size, CLIB_CACHE_LINE_BYTES);
  h = (lb_hash_t *)mem;
  h->buckets_mask = (buckets - 1) << LBHASH_ENTRY_PER_BUCKET_LOG2;
  h->timeout = timeout;
  return h;
}

static_always_inline
void lb_hash_free(lb_hash_t *h)
{
  vec_free(h);
}

#if __SSE4_2__
static_always_inline
u32 lb_hash_crc_u32(u32 data, u32 value)
{
  __asm__ volatile( "crc32l %[data], %[value];"
                    : [value] "+r" (value)
                    : [data] "rm" (data));
  return value;
}

static_always_inline
u32 lb_hash_hash(u64 k[5])
{
  u32 * dp = (u32 *) k;
  u32 value = 0;

  value = lb_hash_crc_u32 (dp[0], value);
  value = lb_hash_crc_u32 (dp[1], value);
  value = lb_hash_crc_u32 (dp[2], value);
  value = lb_hash_crc_u32 (dp[3], value);
  value = lb_hash_crc_u32 (dp[4], value);
  value = lb_hash_crc_u32 (dp[5], value);
  value = lb_hash_crc_u32 (dp[6], value);
  value = lb_hash_crc_u32 (dp[7], value);
  value = lb_hash_crc_u32 (dp[8], value);
  value = lb_hash_crc_u32 (dp[9], value);
  return value;
}
#else
static_always_inline
u32 lb_hash_hash(u64 k[5])
{
  u64 tmp = k[0] ^ k[1] ^ k[2] ^ k[3] ^ k[4];
  return (u32)clib_xxhash (tmp);
}
#endif



static_always_inline
void lb_hash_get(lb_hash_t *h, u64 k[5], u32 hash, u32 time_now, u32 *available_index, u32 *value)
{
  lb_hash_entry_t *e = &h->entries[hash & h->buckets_mask];
  u32 i;
  *value = ~0;
  *available_index = ~0;
  CLIB_PREFETCH (&(e[1]), sizeof(lb_hash_entry_t), STORE);
  for (i=0; i<LBHASH_ENTRY_PER_BUCKET; i++) {
    CLIB_PREFETCH (&(e[i+2]), sizeof(lb_hash_entry_t), STORE); //+2 somehow performs best
    u64 cmp =
        (e[i].key[0] ^ k[0]) |
        (e[i].key[1] ^ k[1]) |
        (e[i].key[2] ^ k[2]) |
        (e[i].key[3] ^ k[3]) |
        (e[i].key[4] ^ k[4]);

    u8 timeouted = clib_u32_loop_gt(time_now, e[i].last_seen + h->timeout);

    *value = (cmp || timeouted)?*value:e[i].value;
    e[i].last_seen = (cmp || timeouted)?e[i].last_seen:time_now;
    *available_index = (timeouted && (*available_index == ~0))?(&e[i] - h->entries):*available_index;

    if (!cmp)
      return;
  }
}

static_always_inline
u32 lb_hash_available_value(lb_hash_t *h, u32 available_index)
{
  return h->entries[available_index].value;
}

static_always_inline
u32 lb_hash_put(lb_hash_t *h, u64 k[5], u32 value, u32 available_index, u32 time_now)
{
  lb_hash_entry_t *e = &h->entries[available_index];
  e->key[0] = k[0];
  e->key[1] = k[1];
  e->key[2] = k[2];
  e->key[3] = k[3];
  e->key[4] = k[4];
  e->value = value;
  e->last_seen = time_now;
  return 0;
}

static_always_inline
u32 lb_hash_elts(lb_hash_t *h, u32 time_now)
{
  u32 tot = 0;
  lb_hash_entry_t *e;
  lb_hash_foreach_valid_entry(h, e, time_now) {
    tot++;
  }
  return tot;
}

#endif /* LB_PLUGIN_LB_LBHASH_H_ */
