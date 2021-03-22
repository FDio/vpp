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

#ifndef included_vector_sve128_h
#define included_vector_sve128_h

#if __ARM_FEATURE_SVE_BITS != 128
#error incorrect __ARM_FEATURE_SVE_BITS
#endif

#include <vppinfra/vector_svexxx.h>
#include <arm_neon.h>

#define CLIB_HAVE_VEC128_MSB_MASK

#define CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE
#define CLIB_VEC128_SPLAT_DEFINED

static_always_inline u32x4
u32x4_gather (void *p0, void *p1, void *p2, void *p3)
{
  u32x4 r = { *(u32 *) p0, *(u32 *) p1, *(u32 *) p2, *(u32 *) p3 };
  return r;
}

static_always_inline void
u32x4_scatter (u32x4 r, void *p0, void *p1, void *p2, void *p3)
{
  *(u32 *) p0 = r[0];
  *(u32 *) p1 = r[1];
  *(u32 *) p2 = r[2];
  *(u32 *) p3 = r[3];
}

#endif /* included_vector_sve128_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
