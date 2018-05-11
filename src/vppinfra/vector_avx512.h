/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef included_vector_avx512_h
#define included_vector_avx512_h

#include <vppinfra/clib.h>
#include <x86intrin.h>

/* *INDENT-OFF* */
#define foreach_avx512_vec512i \
  _(i,8,64,epi8) _(i,16,32,epi16) _(i,32,16,epi32)  _(i,64,8,epi64)
#define foreach_avx512_vec512u \
  _(u,8,64,epi8) _(u,16,32,epi16) _(u,32,16,epi32)  _(u,64,8,epi64)
#define foreach_avx512_vec512f \
  _(f,32,8,ps) _(f,64,4,pd)

/* splat, load_unaligned, store_unaligned, is_all_zero, is_equal,
   is_all_equal, is_zero_mask */
#define _(t, s, c, i) \
static_always_inline t##s##x##c						\
t##s##x##c##_splat (t##s x)						\
{ return (t##s##x##c) _mm512_set1_##i (x); }				\
\
static_always_inline t##s##x##c						\
t##s##x##c##_load_unaligned (void *p)					\
{ return (t##s##x##c) _mm512_loadu_si512 (p); }				\
\
static_always_inline void						\
t##s##x##c##_store_unaligned (t##s##x##c v, void *p)			\
{ _mm512_storeu_si512 ((__m512i *) p, (__m512i) v); }			\
\
static_always_inline int						\
t##s##x##c##_is_all_zero (t##s##x##c v)					\
{ return (_mm512_test_epi64_mask ((__m512i) v, (__m512i) v) == 0); }	\
\
static_always_inline int						\
t##s##x##c##_is_equal (t##s##x##c a, t##s##x##c b)			\
{ return t##s##x##c##_is_all_zero (a ^ b); }				\
\
static_always_inline int						\
t##s##x##c##_is_all_equal (t##s##x##c v, t##s x)			\
{ return t##s##x##c##_is_equal (v, t##s##x##c##_splat (x)); }		\
\
static_always_inline u##c						\
t##s##x##c##_is_zero_mask (t##s##x##c v)				\
{ return _mm512_test_##i##_mask ((__m512i) v, (__m512i) v); }		\


foreach_avx512_vec512i foreach_avx512_vec512u
#undef _
/* *INDENT-ON* */

static_always_inline u32
u16x32_msb_mask (u16x32 v)
{
  return (u32) _mm512_movepi16_mask ((__m512i) v);
}

/* _extend_to_ (128 to 512) */
/* *INDENT-OFF* */
#define _(fs,ts,f,t,in) \
static_always_inline t							\
f##_extend_to_##t (f x)							\
{ return (t) _mm##ts##_cvt##in ((__m##fs##i) x); }

_(128, 512, u8x16, u32x16, epu8_epi32)
_(128, 512, u8x16, u64x8, epu8_epi64)
_(128, 512, u16x8, u64x8, epu16_epi64)
_(128, 512, i8x16, i32x16, epi8_epi32)
_(128, 512, i8x16, i64x8, epi8_epi64)
_(128, 512, i16x8, i64x8, epi16_epi64)

_(256, 512, u8x32, u16x32, epu8_epi16)
_(256, 512, u16x16, u32x16, epu16_epi32)
_(256, 512, u32x8, u64x8, epu32_epi64)
_(256, 512, i8x32, i16x32, epi8_epi16)
_(256, 512, i16x16, i32x16, epi16_epi32)
_(256, 512, i32x8, i64x8, epi32_epi64)

#undef _
/* *INDENT-ON* */

#endif /* included_vector_avx512_h */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
