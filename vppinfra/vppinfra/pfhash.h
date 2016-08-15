/*
  Copyright (c) 2013 Cisco and/or its affiliates.

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

#ifndef included_clib_pfhash_h
#define included_clib_pfhash_h


#include <vppinfra/clib.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>

#if defined(CLIB_HAVE_VEC128) && ! defined (__ALTIVEC__)

typedef struct
{
  /* 3 x 16 = 48 key bytes */
  union
  {
    u32x4 k_u32x4[3];
    u64 k_u64[6];
  } kb;
  /* 3 x 4 = 12 value bytes */
  u32 values[3];
  u32 pad;
} pfhash_kv_16_t;

typedef struct
{
  /* 5 x 8 = 40 key bytes */
  union
  {
    u64 k_u64[5];
  } kb;

  /* 5 x 4 = 20 value bytes */
  u32 values[5];
  u32 pad;
} pfhash_kv_8_t;

typedef struct
{
  /* 4 x 8 = 32 key bytes */
  union
  {
    u64 k_u64[4];
  } kb;

  /* 4 x 8 = 32 value bytes */
  u64 values[4];
} pfhash_kv_8v8_t;

typedef struct
{
  /* 8 x 4 = 32 key bytes */
  union
  {
    u32x4 k_u32x4[2];
    u32 kb[8];
  } kb;

  /* 8 x 4 = 32 value bytes */
  u32 values[8];
} pfhash_kv_4_t;

typedef union
{
  pfhash_kv_16_t kv16;
  pfhash_kv_8_t kv8;
  pfhash_kv_8v8_t kv8v8;
  pfhash_kv_4_t kv4;
} pfhash_kv_t;

typedef struct
{
  /* Bucket vector */
  u32 *buckets;
#define PFHASH_BUCKET_OVERFLOW (u32)~0

  /* Pool of key/value pairs */
  pfhash_kv_t *kvp;

  /* overflow plain-o-hash */
  uword *overflow_hash;

  /* Pretty-print name */
  u8 *name;

  u32 key_size;
  u32 value_size;

  u32 overflow_count;
  u32 nitems;
  u32 nitems_in_overflow;
} pfhash_t;

void pfhash_init (pfhash_t * p, char *name, u32 key_size, u32 value_size,
		  u32 nbuckets);
void pfhash_free (pfhash_t * p);
u64 pfhash_get (pfhash_t * p, u32 bucket, void *key);
void pfhash_set (pfhash_t * p, u32 bucket, void *key, void *value);
void pfhash_unset (pfhash_t * p, u32 bucket, void *key);

format_function_t format_pfhash;

static inline void
pfhash_prefetch_bucket (pfhash_t * p, u32 bucket)
{
  CLIB_PREFETCH (&p->buckets[bucket], CLIB_CACHE_LINE_BYTES, LOAD);
}

static inline u32
pfhash_read_bucket_prefetch_kv (pfhash_t * p, u32 bucket)
{
  u32 bucket_contents = p->buckets[bucket];
  if (PREDICT_TRUE ((bucket_contents & PFHASH_BUCKET_OVERFLOW) == 0))
    CLIB_PREFETCH (&p->kvp[bucket_contents], CLIB_CACHE_LINE_BYTES, LOAD);
  return bucket_contents;
}

/*
 * pfhash_search_kv_16
 * See if the supplied 16-byte key matches one of three 16-byte (key,value) pairs.
 * Return the indicated value, or ~0 if no match
 *
 * Note: including the overflow test, the fast path is 35 instrs
 * on x86_64. Elves will steal your keyboard in the middle of the night if
 * you "improve" it without checking the generated code!
 */
static inline u32
pfhash_search_kv_16 (pfhash_t * p, u32 bucket_contents, u32x4 * key)
{
  u32x4 diff0, diff1, diff2;
  u32 is_equal0, is_equal1, is_equal2;
  u32 no_match;
  pfhash_kv_16_t *kv;
  u32 rv;

  if (PREDICT_FALSE (bucket_contents == PFHASH_BUCKET_OVERFLOW))
    {
      uword *hp;
      hp = hash_get_mem (p->overflow_hash, key);
      if (hp)
	return hp[0];
      return (u32) ~ 0;
    }

  kv = &p->kvp[bucket_contents].kv16;

  diff0 = u32x4_sub (kv->kb.k_u32x4[0], key[0]);
  diff1 = u32x4_sub (kv->kb.k_u32x4[1], key[0]);
  diff2 = u32x4_sub (kv->kb.k_u32x4[2], key[0]);

  no_match = is_equal0 = (i16) u32x4_zero_byte_mask (diff0);
  is_equal1 = (i16) u32x4_zero_byte_mask (diff1);
  no_match |= is_equal1;
  is_equal2 = (i16) u32x4_zero_byte_mask (diff2);
  no_match |= is_equal2;
  /* If any of the three items matched, no_match will be zero after this line */
  no_match = ~no_match;

  rv = (is_equal0 & kv->values[0])
    | (is_equal1 & kv->values[1]) | (is_equal2 & kv->values[2]) | no_match;

  return rv;
}

static inline u32
pfhash_search_kv_8 (pfhash_t * p, u32 bucket_contents, u64 * key)
{
  pfhash_kv_8_t *kv;
  u32 rv = (u32) ~ 0;

  if (PREDICT_FALSE (bucket_contents == PFHASH_BUCKET_OVERFLOW))
    {
      uword *hp;
      hp = hash_get_mem (p->overflow_hash, key);
      if (hp)
	return hp[0];
      return (u32) ~ 0;
    }

  kv = &p->kvp[bucket_contents].kv8;

  rv = (kv->kb.k_u64[0] == key[0]) ? kv->values[0] : rv;
  rv = (kv->kb.k_u64[1] == key[0]) ? kv->values[1] : rv;
  rv = (kv->kb.k_u64[2] == key[0]) ? kv->values[2] : rv;
  rv = (kv->kb.k_u64[3] == key[0]) ? kv->values[3] : rv;
  rv = (kv->kb.k_u64[4] == key[0]) ? kv->values[4] : rv;

  return rv;
}

static inline u64
pfhash_search_kv_8v8 (pfhash_t * p, u32 bucket_contents, u64 * key)
{
  pfhash_kv_8v8_t *kv;
  u64 rv = (u64) ~ 0;

  if (PREDICT_FALSE (bucket_contents == PFHASH_BUCKET_OVERFLOW))
    {
      uword *hp;
      hp = hash_get_mem (p->overflow_hash, key);
      if (hp)
	return hp[0];
      return (u64) ~ 0;
    }

  kv = &p->kvp[bucket_contents].kv8v8;

  rv = (kv->kb.k_u64[0] == key[0]) ? kv->values[0] : rv;
  rv = (kv->kb.k_u64[1] == key[0]) ? kv->values[1] : rv;
  rv = (kv->kb.k_u64[2] == key[0]) ? kv->values[2] : rv;
  rv = (kv->kb.k_u64[3] == key[0]) ? kv->values[3] : rv;

  return rv;
}

static inline u32
pfhash_search_kv_4 (pfhash_t * p, u32 bucket_contents, u32 * key)
{
  u32x4 vector_key;
  u32x4 is_equal[2];
  u32 zbm[2], winner_index;
  pfhash_kv_4_t *kv;

  if (PREDICT_FALSE (bucket_contents == PFHASH_BUCKET_OVERFLOW))
    {
      uword *hp;
      hp = hash_get_mem (p->overflow_hash, key);
      if (hp)
	return hp[0];
      return (u32) ~ 0;
    }

  kv = &p->kvp[bucket_contents].kv4;

  vector_key = u32x4_splat (key[0]);

  is_equal[0] = u32x4_is_equal (kv->kb.k_u32x4[0], vector_key);
  is_equal[1] = u32x4_is_equal (kv->kb.k_u32x4[1], vector_key);
  zbm[0] = ~u32x4_zero_byte_mask (is_equal[0]) & 0xFFFF;
  zbm[1] = ~u32x4_zero_byte_mask (is_equal[1]) & 0xFFFF;

  if (PREDICT_FALSE ((zbm[0] == 0) && (zbm[1] == 0)))
    return (u32) ~ 0;

  winner_index = min_log2 (zbm[0]) >> 2;
  winner_index = zbm[1] ? (4 + (min_log2 (zbm[1]) >> 2)) : winner_index;

  return kv->values[winner_index];
}

#endif /* CLIB_HAVE_VEC128 */

#endif /* included_clib_pfhash_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
