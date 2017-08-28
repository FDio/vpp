/*
 * Copyright (c) 2017 Intel and/or its affiliates.
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

#ifndef KP_PLUGIN_KP_KPHASH_H_
#define KP_PLUGIN_KP_KPHASH_H_

#include <vnet/vnet.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/crc32.h>

/*
 * @brief Number of entries per bucket.
 */
#define KPHASH_ENTRY_PER_BUCKET 4

#define KP_HASH_DO_NOT_USE_SSE_BUCKETS 0

/**
 * 32 bits integer comparison for running values.
 * 1 > 0 is true. But 1 > 0xffffffff also is.
 */
#define clib_u32_loop_gt(a, b) (((u32)(a)) - ((u32)(b)) < 0x7fffffff)

/*
 * @brief One bucket contains 4 entries.
 * Each bucket takes one 64B cache line in memory.
 */
typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 hash[KPHASH_ENTRY_PER_BUCKET];
  u32 timeout[KPHASH_ENTRY_PER_BUCKET];
  u32 vip[KPHASH_ENTRY_PER_BUCKET];
  u32 value[KPHASH_ENTRY_PER_BUCKET];
} kp_hash_bucket_t;

typedef struct {
  u32 buckets_mask;
  u32 timeout;
  kp_hash_bucket_t buckets[];
} kp_hash_t;

#define kp_hash_nbuckets(h) (((h)->buckets_mask) + 1)
#define kp_hash_size(h) ((h)->buckets_mask + KPHASH_ENTRY_PER_BUCKET)

#define kp_hash_foreach_bucket(h, bucket) \
  for (bucket = (h)->buckets; \
	bucket < (h)->buckets + kp_hash_nbuckets(h); \
	bucket++)

#define kp_hash_foreach_entry(h, bucket, i) \
    kp_hash_foreach_bucket(h, bucket) \
      for (i = 0; i < KPHASH_ENTRY_PER_BUCKET; i++)

#define kp_hash_foreach_valid_entry(h, bucket, i, now) \
    kp_hash_foreach_entry(h, bucket, i) \
       if (!clib_u32_loop_gt((now), bucket->timeout[i]))

static_always_inline
kp_hash_t *kp_hash_alloc(u32 buckets, u32 timeout)
{
  if (!is_pow2(buckets))
    return NULL;

  // Allocate 1 more bucket for prefetch
  u32 size = ((u64)&((kp_hash_t *)(0))->buckets[0]) +
      sizeof(kp_hash_bucket_t) * (buckets + 1);
  u8 *mem = 0;
  kp_hash_t *h;
  vec_alloc_aligned(mem, size, CLIB_CACHE_LINE_BYTES);
  h = (kp_hash_t *)mem;
  h->buckets_mask = (buckets - 1);
  h->timeout = timeout;
  return h;
}

static_always_inline
void kp_hash_free(kp_hash_t *h)
{
  u8 *mem = (u8 *)h;
  vec_free(mem);
}

static_always_inline
u32 kp_hash_hash(u64 k0, u64 k1, u64 k2, u64 k3, u64 k4)
{
#ifdef clib_crc32c_uses_intrinsics
  u64 key[5];
  key[0] = k0;
  key[1] = k1;
  key[2] = k2;
  key[3] = k3;
  key[4] = k4;
  return clib_crc32c ((u8 *) key, 40);
#else
  u64 tmp = k0 ^ k1 ^ k2 ^ k3 ^ k4;
  return (u32)clib_xxhash (tmp);
#endif
}

static_always_inline
void kp_hash_prefetch_bucket(kp_hash_t *ht, u32 hash)
{
  kp_hash_bucket_t *bucket = &ht->buckets[hash & ht->buckets_mask];
  CLIB_PREFETCH(bucket, sizeof(*bucket), READ);
}

static_always_inline
void kp_hash_get(kp_hash_t *ht, u32 hash, u32 vip, u32 time_now,
		 u32 *available_index, u32 *found_value)
{
  kp_hash_bucket_t *bucket = &ht->buckets[hash & ht->buckets_mask];
  *found_value = ~0;
  *available_index = ~0;
#if __SSE4_2__ && KP_HASH_DO_NOT_USE_SSE_BUCKETS == 0
  u32 bitmask, found_index;
  __m128i mask;

  // mask[*] = timeout[*] > now
  mask = _mm_cmpgt_epi32(_mm_loadu_si128 ((__m128i *) bucket->timeout),
			 _mm_set1_epi32 (time_now));
  // bitmask[*] = now <= timeout[*/4]
  bitmask = (~_mm_movemask_epi8(mask)) & 0xffff;
  // Get first index with now <= timeout[*], if any.
  *available_index = (bitmask)?__builtin_ctz(bitmask)/4:*available_index;

  // mask[*] = (timeout[*] > now) && (hash[*] == hash)
  mask = _mm_and_si128(mask,
		       _mm_cmpeq_epi32(
			   _mm_loadu_si128 ((__m128i *) bucket->hash),
			   _mm_set1_epi32 (hash)));

  // Load the array of vip values
  // mask[*] = (timeout[*] > now) && (hash[*] == hash) && (vip[*] == vip)
  mask = _mm_and_si128(mask,
		       _mm_cmpeq_epi32(
			   _mm_loadu_si128 ((__m128i *) bucket->vip),
			   _mm_set1_epi32 (vip)));

  // mask[*] = (timeout[*x4] > now) && (hash[*x4] == hash) && (vip[*x4] == vip)
  bitmask = _mm_movemask_epi8(mask);
  // Get first index, if any
  found_index = (bitmask)?__builtin_ctzll(bitmask)/4:0;
  ASSERT(found_index < 4);
  *found_value = (bitmask)?bucket->value[found_index]:*found_value;
  bucket->timeout[found_index] =
      (bitmask)?time_now + ht->timeout:bucket->timeout[found_index];
#else
  u32 i;
  for (i = 0; i < KPHASH_ENTRY_PER_BUCKET; i++) {
      u8 cmp = (bucket->hash[i] == hash && bucket->vip[i] == vip);
      u8 timeouted = clib_u32_loop_gt(time_now, bucket->timeout[i]);
      *found_value = (cmp || timeouted)?*found_value:bucket->value[i];
      bucket->timeout[i] = (cmp || timeouted)?time_now + ht->timeout:bucket->timeout[i];
      *available_index = (timeouted && (*available_index == ~0))?i:*available_index;

      if (!cmp)
	return;
  }
#endif
}

static_always_inline
u32 kp_hash_available_value(kp_hash_t *h, u32 hash, u32 available_index)
{
  return h->buckets[hash & h->buckets_mask].value[available_index];
}

static_always_inline
void kp_hash_put(kp_hash_t *h, u32 hash, u32 value, u32 vip,
		 u32 available_index, u32 time_now)
{
  kp_hash_bucket_t *bucket = &h->buckets[hash & h->buckets_mask];
  bucket->hash[available_index] = hash;
  bucket->value[available_index] = value;
  bucket->timeout[available_index] = time_now + h->timeout;
  bucket->vip[available_index] = vip;
}

static_always_inline
u32 kp_hash_elts(kp_hash_t *h, u32 time_now)
{
  u32 tot = 0;
  kp_hash_bucket_t *bucket;
  u32 i;
  kp_hash_foreach_valid_entry(h, bucket, i, time_now) {
    tot++;
  }
  return tot;
}

#endif /* KP_PLUGIN_KP_KPHASH_H_ */
