/*
 * Copyright (c) 2020 Arm Limited. and/or its affiliates.
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

#ifndef included_vector_sve_h
#define included_vector_sve_h
#include <arm_sve.h>

#define foreach_vec \
    _(i,int,8) _(i,int,16) _(i,int,32) _(i,int,64) \
    _(u,uint,8) _(u,uint,16) _(u,uint,32) _(u,uint,64) \
    _(f,float,16) _(f,float,32) _(f,float,64)

/* *INDENT-OFF* */
/* Type Definitions */
#define _(t,w,s) \
typedef sv##w##s##_t t##s##xn;

foreach_vec

#undef _

/* predicate type to reflect active elements in scalale vectors */
typedef svbool_t boolxn;
/* *INDENT-ON* */

/* *INDENT-OFF* */
#define foreach_sve_vec_i \
    _(i,8,n,s8) _(i,16,n,s16) _(i,32,n,s32) _(i,64,n,s64)
#define foreach_sve_vec_u \
    _(u,8,n,u8) _(u,16,n,u16) _(u,32,n,u32) _(u,64,n,u64)
#define foreach_sve_vec_f \
                _(f,16,n,f16) _(f,32,n,f32) _(f,64,n,f64)

#define _(t, s, c, i) \
static_always_inline t##s##x##c \
t##s##x##c##_splat (t##s x) \
{ return (t##s##x##c) svdup_n_##i (x); } \
\
static_always_inline t##s##x##c \
t##s##x##c##_load_unaligned (boolxn pg, void *p) \
{ return (t##s##x##c) svld1_##i (pg, (const t##s *) p); } \
\
static_always_inline void \
t##s##x##c##_store_unaligned (boolxn pg, t##s##x##c v, void *p) \
{ svst1_##i (pg, (t##s *)p, v); }

foreach_sve_vec_i foreach_sve_vec_u foreach_sve_vec_f
#undef _

#define _(t, s, c, i) \
static_always_inline t##s##x##c \
t##s##x##c##_add (boolxn pg, t##s##x##c a, t##s##x##c b) \
{ return (t##s##x##c) svadd_##i##_z (pg, a, b); } \
\
static_always_inline t##s##x##c \
t##s##x##c##_sub (boolxn pg, t##s##x##c a, t##s##x##c b) \
{ return (t##s##x##c) svsub_##i##_z (pg, a, b); } \
\
static_always_inline t##s##x##c \
t##s##x##c##_shift_left (boolxn pg, t##s##x##c a, u##s##x##c b) \
{ return (t##s##x##c) svlsl_##i##_z (pg, a, b); } \
\
static_always_inline t##s##x##c \
t##s##x##c##_shift_left_n (boolxn pg, t##s##x##c a, u##s b) \
{ return (t##s##x##c) svlsl_n_##i##_z (pg, a, b); } \

foreach_sve_vec_i foreach_sve_vec_u
#undef _

#define _(t, s, c, i) \
static_always_inline t##s##x##c \
t##s##x##c##_shift_right (boolxn pg, t##s##x##c a, u##s##x##c b) \
{ return (t##s##x##c) svlsr_##i##_z (pg, a, b); } \
\
static_always_inline t##s##x##c \
t##s##x##c##_shift_right_n (boolxn pg, t##s##x##c a, u##s b) \
{ return (t##s##x##c) svlsr_n_##i##_z (pg, a, b); } \

foreach_sve_vec_u
#undef _
/* *INDENT-ON* */

/** \brief Iterate data to be processed in array[0…COUNT] in memory.
    ENO reflects actually number of ESIZE elements could be accommodated
    in vector register. EACTIVE reflects the valid number of elements in
    vector to be processed by BODY in each iteration. For most case, the
    valid number of elements in vector equals ENO, except the last iteration,
    in which valid number of elements equals COUNT%ENO.

    @param I Iterate Index, i.e., Iteration index of data in array
    @param ENO Element Number, i.e., No. of ESIZE bits elements in vector
    @param EACTIVE Active Elements, valid elements in vector this iteration
    @param COUNT Number of element data to be processed in array in memory
    @param ESIZE Element Size, vector element bit width, e.g., 8/16/32/64
    @param BODY The actions to perform on valid vector elements
*/
#define scalable_vector_foreach(I,ENO,EACTIVE,COUNT,ESIZE,BODY) \
do { \
  I = 0; \
  ENO = (i32) (svcntb () / (ESIZE >> 3)); \
  EACTIVE = svwhilelt_b##ESIZE (I, COUNT); \
  while (svptest_first (svptrue_b##ESIZE (), EACTIVE)) { \
    do { BODY; } while (0); \
    I  += ENO; \
    EACTIVE = svwhilelt_b##ESIZE (I, COUNT); \
  } \
} while (0)

/* Load 32-bit values from memory, zero-extend them,
 * and store the results in a vector. */
static_always_inline u64xn
u64xn_load_u32 (boolxn pg, u32 * base)
{
  u64xn r = svld1uw_u64 (pg, base);
  return r;
}

/* Read elements from a vector, truncate them to 32 bits,
 * then store them to memory. */
static_always_inline void
u64xn_store_u32 (boolxn pg, u64xn v, u32 * base)
{
  svst1w_u64 (pg, base, v);
  return;
}

#endif /* included_vector_sve_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
