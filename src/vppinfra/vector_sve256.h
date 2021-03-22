/*
 * Copyright (c) 2021 Arm Limited. and/or its affiliates.
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

#ifndef included_vector_sve256_h
#define included_vector_sve256_h

#if __ARM_FEATURE_SVE_BITS != 256
#error incorrect __ARM_FEATURE_SVE_BITS
#endif

#include <vppinfra/clib.h>
#include <vppinfra/vector_svexxx.h>

static_always_inline u32x8
u32x8_hadd (u32x8 v1, u32x8 v2)
{
  u32x8 even = svuzp1_u32 (v1, v2);
  u32x8 odd = svuzp2_u32 (v1, v2);
  u32x8 v = svadd_u32_z (alltrue, even, odd);
  u32x8 idx = { 0, 1, 4, 5, 2, 3, 6, 7 };
  return (u32x8) svtbl_u32 (v, idx);
}

static_always_inline u16x16
u16x16_mask_last (u16x16 v, u8 n_last)
{
  const u16x16 masks[17] = {
    { 0 },
    { -1 },
    { -1, -1 },
    { -1, -1, -1 },
    { -1, -1, -1, -1 },
    { -1, -1, -1, -1, -1 },
    { -1, -1, -1, -1, -1, -1 },
    { -1, -1, -1, -1, -1, -1, -1 },
    { -1, -1, -1, -1, -1, -1, -1, -1 },
    { -1, -1, -1, -1, -1, -1, -1, -1, -1 },
    { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
    { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
    { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
    { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
    { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
    { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
    { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },
  };

  ASSERT (n_last < 17);

  return v & masks[16 - n_last];
}

static_always_inline f32x8
f32x8_from_u32x8 (u32x8 v)
{
  return (f32x8) svcvt_f32_u32_z (alltrue, v);
}

static_always_inline u32x8
u32x8_from_f32x8 (f32x8 v)
{
  return (u32x8) svcvt_u32_f32_z (alltrue, v);
}

static_always_inline u32x8
u32x8_mask_blend (u32x8 a, u32x8 b, int m)
{
  u32x8 v1 = { m & 0x01, m & 0x02, m & 0x04, m & 0x08,
	       m & 0x10, m & 0x20, m & 0x40, m & 0x80 };
  u32x8 v2 = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
  svbool_t pg = svcmpeq_u32 (alltrue, v1, v2);
  return (u32x8) svsel_u32 (pg, b, a);
}

static_always_inline u16x16
u16x16_mask_blend (u16x16 a, u16x16 b, int m)
{
  u16x16 v1 = { m & 0x01, m & 0x02, m & 0x04, m & 0x08, m & 0x10, m & 0x20,
		m & 0x40, m & 0x80, m & 0x01, m & 0x02, m & 0x04, m & 0x08,
		m & 0x10, m & 0x20, m & 0x40, m & 0x80 };
  u16x16 v2 = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
  svbool_t pg = svcmpeq_u16 (alltrue, v1, v2);
  return (u16x16) svsel_u16 (pg, b, a);
}

static_always_inline u64x4
u64x4_gather (void *p0, void *p1, void *p2, void *p3)
{
  u64x4 r = { *(u64 *) p0, *(u64 *) p1, *(u64 *) p2, *(u64 *) p3 };
  return r;
}

static_always_inline u32x8
u32x8_gather (void *p0, void *p1, void *p2, void *p3, void *p4, void *p5,
	      void *p6, void *p7)
{
  u32x8 r = {
    *(u32 *) p0, *(u32 *) p1, *(u32 *) p2, *(u32 *) p3,
    *(u32 *) p4, *(u32 *) p5, *(u32 *) p6, *(u32 *) p7,
  };
  return r;
}

static_always_inline void
u64x4_scatter (u64x4 r, void *p0, void *p1, void *p2, void *p3)
{
  *(u64 *) p0 = r[0];
  *(u64 *) p1 = r[1];
  *(u64 *) p2 = r[2];
  *(u64 *) p3 = r[3];
}

static_always_inline void
u32x8_scatter (u32x8 r, void *p0, void *p1, void *p2, void *p3, void *p4,
	       void *p5, void *p6, void *p7)
{
  *(u32 *) p0 = r[0];
  *(u32 *) p1 = r[1];
  *(u32 *) p2 = r[2];
  *(u32 *) p3 = r[3];
  *(u32 *) p4 = r[4];
  *(u32 *) p5 = r[5];
  *(u32 *) p6 = r[6];
  *(u32 *) p7 = r[7];
}

static_always_inline void
u64x4_scatter_one (u64x4 r, int index, void *p)
{
  *(u64 *) p = r[index];
}

static_always_inline void
u32x8_scatter_one (u32x8 r, int index, void *p)
{
  *(u32 *) p = r[index];
}

/* extract the lowest-indexed half of a vector, and extend each element
 * to double the width */
static_always_inline u32x8
u16x16_extract_extend_lo (u16x16 s)
{
  return svunpklo_u32 (s);
}

/* extract the highest-indexed half of a vector, and extend each element
 * to double the width */
static_always_inline u32x8
u16x16_extract_extend_hi (u16x16 s)
{
  return svunpkhi_u32 (s);
}

/* load 4x u32 elements from address *s, zero-extend each element to u64,
 * and put all the elements into u64xn vector register */
static_always_inline u64x4
u64x4_load_extend_u32 (u32 *s)
{
  return svld1uw_u64 (alltrue, s);
}

#endif /* included_vector_sve256_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
