/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_vector_avx2_h
#define included_vector_avx2_h

#include <vppinfra/clib.h>
#include <x86intrin.h>

#define foreach_avx2_vec256i \
  _(i,8,32,epi8) _(i,16,16,epi16) _(i,32,8,epi32)  _(i,64,4,epi64x)
#define foreach_avx2_vec256u \
  _(u,8,32,epi8) _(u,16,16,epi16) _(u,32,8,epi32)  _(u,64,4,epi64x)
#define foreach_avx2_vec256f \
  _(f,32,8,ps) _(f,64,4,pd)

/* splat, load_unaligned, store_unaligned, is_all_zero, is_all_equal */
#define _(t, s, c, i) \
static_always_inline t##s##x##c						\
t##s##x##c##_splat (t##s x)						\
{ return (t##s##x##c) _mm256_set1_##i (x); }				\
\
static_always_inline t##s##x##c						\
t##s##x##c##_load_unaligned (void *p)					\
{ return (t##s##x##c) _mm256_loadu_si256 (p); }				\
\
static_always_inline void						\
t##s##x##c##_store_unaligned (t##s##x##c v, void *p)			\
{ _mm256_storeu_si256 ((__m256i *) p, (__m256i) v); }			\
\
static_always_inline int						\
t##s##x##c##_is_all_zero (t##s##x##c x)					\
{ return _mm256_testz_si256 ((__m256i) x, (__m256i) x); }		\
\
static_always_inline int						\
t##s##x##c##_is_all_equal (t##s##x##c v, t##s x)			\
{ return t##s##x##c##_is_all_zero (v != t##s##x##c##_splat (x)); };	\
\

foreach_avx2_vec256i foreach_avx2_vec256u
#undef _
  always_inline u32x8
u32x8_permute (u32x8 v, u32x8 idx)
{
  return (u32x8) _mm256_permutevar8x32_epi32 ((__m256i) v, (__m256i) idx);
}

always_inline u32x4
u32x8_extract_lo (u32x8 v)
{
  return (u32x4) _mm256_extracti128_si256 ((__m256i) v, 0);
}

always_inline u32x4
u32x8_extract_hi (u32x8 v)
{
  return (u32x4) _mm256_extracti128_si256 ((__m256i) v, 1);
}

#endif /* included_vector_avx2_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
