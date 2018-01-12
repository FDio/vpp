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

#ifndef SRC_VPPINFRA_FLOWHASH_24_16_H_
#define SRC_VPPINFRA_FLOWHASH_24_16_H_

#ifdef __included_flowhash_template_h__
#undef __included_flowhash_template_h__
#endif

#include <vppinfra/clib.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/crc32.h>

typedef struct {
  u64 as_u64[3];
} flowhash_skey_24_16_t;

typedef struct {
  u64 as_u64[3];
} flowhash_lkey_24_16_t;

typedef struct {
  u64 as_u64[2];
} flowhash_value_24_16_t;

#define FLOWHASH_TYPE _24_16
#include <vppinfra/flowhash_template.h>
#undef FLOWHASH_TYPE

static_always_inline
u32 flowhash_hash_24_16(flowhash_lkey_24_16_t *k)
{
#ifdef clib_crc32c_uses_intrinsics
  /* crc32 costs multiple cycles, but multiple operations can be performed
   * in parallel. We can still achieve decent hash properties by splitting
   * the computation in two. */
  u32 val0 = 0;
  u32 val1 = 0;
  val0 = _mm_crc32_u64(val0, k->as_u64[0]);
  val1 = _mm_crc32_u64(val1, k->as_u64[0] >> 32);
  val0 = _mm_crc32_u64(val0, k->as_u64[1]);
  val1 = _mm_crc32_u64(val1, k->as_u64[1] >> 32);
  val0 = _mm_crc32_u64(val0, k->as_u64[2]);
  val1 = _mm_crc32_u64(val1, k->as_u64[2] >> 32);
  return val0 ^ val1;
#else
  u64 val = 0;
  val ^= k->as_u64[0];
  val ^= k->as_u64[1];
  val ^= k->as_u64[2];
  return (u32)clib_xxhash (val);
#endif
}

static_always_inline
u8 flowhash_cmp_key_24_16(flowhash_skey_24_16_t *a,
                          flowhash_lkey_24_16_t *b)
{
  u8 val = 0;
  val |= (a->as_u64[0] != b->as_u64[0]);
  val |= (a->as_u64[1] != b->as_u64[1]);
  val |= (a->as_u64[2] != b->as_u64[2]);
  return val;
}

static_always_inline
void flowhash_cpy_key_24_16(flowhash_skey_24_16_t *dst,
        	                    flowhash_lkey_24_16_t *src)
{
  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
  dst->as_u64[2] = src->as_u64[2];
}

#endif /* SRC_VPPINFRA_FLOWHASH_24_16_H_ */
