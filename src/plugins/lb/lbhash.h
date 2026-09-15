/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2012 Cisco and/or its affiliates.
 */

/**
 * vppinfra already includes tons of different hash tables.
 * MagLev flow table is a bit different. It has to be very efficient
 * for both writing and reading operations. But it does not need to
 * be 100% reliable (write can fail). It also needs to recycle
 * old entries in a lazy way.
 *
 * This hash table is the most trivial hash table you can do.
 * Fixed total size, fixed bucket size.
 * Advantage is that it could be very efficient (maybe).
 *
 */

#ifndef LB_PLUGIN_LB_LBHASH_H_
#define LB_PLUGIN_LB_LBHASH_H_

#include <vnet/vnet.h>
#include <vppinfra/lb_hash_hash.h>
#include <vppinfra/vector.h>

/*
 * @brief Number of entries per bucket.
 */
#define LBHASH_ENTRY_PER_BUCKET 4

/*
 * @brief One bucket contains 4 entries.
 * Each bucket takes one 64B cache line in memory.
 */
typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 hash[LBHASH_ENTRY_PER_BUCKET];
  u32 timeout[LBHASH_ENTRY_PER_BUCKET];
  u32 vip[LBHASH_ENTRY_PER_BUCKET];
  u32 value[LBHASH_ENTRY_PER_BUCKET];
} lb_hash_bucket_t;

typedef struct {
  u32 buckets_mask;
  u32 timeout;
  lb_hash_bucket_t buckets[];
} lb_hash_t;

#define lb_hash_nbuckets(h) (((h)->buckets_mask) + 1)
#define lb_hash_size(h) ((h)->buckets_mask + LBHASH_ENTRY_PER_BUCKET)

#define lb_hash_foreach_bucket(h, bucket) \
  for (bucket = (h)->buckets; \
	bucket < (h)->buckets + lb_hash_nbuckets(h); \
	bucket++)

#define lb_hash_foreach_entry(h, bucket, i) \
    lb_hash_foreach_bucket(h, bucket) \
      for (i = 0; i < LBHASH_ENTRY_PER_BUCKET; i++)

#define lb_hash_foreach_valid_entry(h, bucket, i, now) \
    lb_hash_foreach_entry(h, bucket, i) \
       if (!clib_u32_loop_gt((now), bucket->timeout[i]))

static_always_inline
lb_hash_t *lb_hash_alloc(u32 buckets, u32 timeout)
{
  if (!is_pow2(buckets))
    return NULL;

  // Allocate 1 more bucket for prefetch
  u32 size = ((uword)&((lb_hash_t *)(0))->buckets[0]) +
      sizeof(lb_hash_bucket_t) * (buckets + 1);
  u8 *mem = 0;
  lb_hash_t *h;
  vec_validate_aligned (mem, size - 1, CLIB_CACHE_LINE_BYTES);
  h = (lb_hash_t *)mem;
  h->buckets_mask = (buckets - 1);
  h->timeout = timeout;
  return h;
}

static_always_inline
void lb_hash_free(lb_hash_t *h)
{
  u8 *mem = (u8 *)h;
  vec_free(mem);
}

static_always_inline
void lb_hash_prefetch_bucket(lb_hash_t *ht, u32 hash)
{
  lb_hash_bucket_t *bucket = &ht->buckets[hash & ht->buckets_mask];
  CLIB_PREFETCH(bucket, sizeof(*bucket), READ);
}

static_always_inline
void lb_hash_get(lb_hash_t *ht, u32 hash, u32 vip, u32 time_now,
		 u32 *available_index, u32 *found_value)
{
  lb_hash_bucket_t *bucket = &ht->buckets[hash & ht->buckets_mask];
  *found_value = 0;
  *available_index = ~0;
#ifdef CLIB_HAVE_VEC128_MSB_MASK
  u32x4 time_now4 = u32x4_splat (time_now);
  u32x4 timeout4 = u32x4_load_unaligned (bucket->timeout);
  u32x4 expired = (time_now4 - timeout4) < u32x4_splat (0x7fffffff);
  u32 bitmask = u8x16_msb_mask ((u8x16) expired);

  if (bitmask)
    *available_index = count_trailing_zeros (bitmask) / 4;

  u32x4 live = ~expired;
  u32x4 hash4 = u32x4_load_unaligned (bucket->hash);
  u32x4 vip4 = u32x4_load_unaligned (bucket->vip);
  u32x4 hash_match = hash4 == u32x4_splat (hash);
  u32x4 vip_match = vip4 == u32x4_splat (vip);
  u32x4 match = live & hash_match & vip_match;

  bitmask = u8x16_msb_mask ((u8x16) match);
  if (bitmask)
    {
      u32 found_index = count_trailing_zeros (bitmask) / 4;
      ASSERT (found_index < LBHASH_ENTRY_PER_BUCKET);
      *found_value = bucket->value[found_index];
      bucket->timeout[found_index] = time_now + ht->timeout;
    }
#else
  u32 i;
  for (i = 0; i < LBHASH_ENTRY_PER_BUCKET; i++) {
      u8 cmp = (bucket->hash[i] == hash && bucket->vip[i] == vip);
      u8 timeouted = clib_u32_loop_gt(time_now, bucket->timeout[i]);
      *found_value = (cmp || timeouted)?*found_value:bucket->value[i];
      bucket->timeout[i] = (cmp || timeouted) ? time_now + ht->timeout : bucket->timeout[i];
      *available_index = (timeouted && (*available_index == ~0)) ? i : *available_index;

      if (!cmp)
	return;
  }
#endif
}

static_always_inline u32
lb_hash_available_value (lb_hash_t *h, u32 hash, u32 available_index)
{
  return h->buckets[hash & h->buckets_mask].value[available_index];
}

static_always_inline
void lb_hash_put(lb_hash_t *h, u32 hash, u32 value, u32 vip,
		 u32 available_index, u32 time_now)
{
  lb_hash_bucket_t *bucket = &h->buckets[hash & h->buckets_mask];
  bucket->hash[available_index] = hash;
  bucket->value[available_index] = value;
  bucket->timeout[available_index] = time_now + h->timeout;
  bucket->vip[available_index] = vip;
}

static_always_inline
u32 lb_hash_elts(lb_hash_t *h, u32 time_now)
{
  u32 tot = 0;
  lb_hash_bucket_t *bucket;
  u32 i;
  lb_hash_foreach_valid_entry(h, bucket, i, time_now) {
    tot++;
  }
  return tot;
}

#endif /* LB_PLUGIN_LB_LBHASH_H_ */
