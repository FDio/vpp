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

#ifndef f16
typedef float16_t f16;
#endif
#define svrevb_s8_z(m, x) (x)
#define svrevb_u8_z(m, x) (x)

/* Below intrinsics are not supported */
#define svdiv_s8_z(pg, op1, op2)  (op1)
#define svdiv_s16_z(pg, op1, op2) (op1)
#define svdiv_u8_z(pg, op1, op2)  (op1)
#define svdiv_u16_z(pg, op1, op2) (op1)

#define foreach_scalable_vec                                                  \
  _ (i, int, 8)                                                               \
  _ (i, int, 16)                                                              \
  _ (i, int, 32)                                                              \
  _ (i, int, 64)                                                              \
  _ (u, uint, 8)                                                              \
  _ (u, uint, 16)                                                             \
  _ (u, uint, 32)                                                             \
  _ (u, uint, 64)                                                             \
  _ (f, float, 16)                                                            \
  _ (f, float, 32)                                                            \
  _ (f, float, 64)

/* Type Definitions */
#define _(t, w, s) typedef sv##w##s##_t t##s##xn;

foreach_scalable_vec

#undef _

  /* Predicate type to reflect active elements in scalale vectors */
  typedef svbool_t boolxn;

#define foreach_sve_vec_i                                                     \
  _ (i, 8, n, s8) _ (i, 16, n, s16) _ (i, 32, n, s32) _ (i, 64, n, s64)
#define foreach_sve_vec_u                                                     \
  _ (u, 8, n, u8) _ (u, 16, n, u16) _ (u, 32, n, u32) _ (u, 64, n, u64)
#define foreach_sve_vec_f _ (f, 16, n, f16) _ (f, 32, n, f32) _ (f, 64, n, f64)

#define _(t, s, c, i)                                                         \
  static_always_inline t##s##x##c t##s##x##c##_splat (t##s x)                 \
  {                                                                           \
    return (t##s##x##c) svdup_n_##i (x);                                      \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_splat_zero (boolxn pg, t##s x) \
  {                                                                           \
    return (t##s##x##c) svdup_n_##i##_z (pg, x);                              \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_load_unaligned (boolxn pg,     \
							       void *p)       \
  {                                                                           \
    return (t##s##x##c) svld1_##i (pg, (const t##s *) p);                     \
  }                                                                           \
                                                                              \
  static_always_inline void t##s##x##c##_store_unaligned (                    \
    boolxn pg, t##s##x##c v, void *p)                                         \
  {                                                                           \
    svst1_##i (pg, (t##s *) p, v);                                            \
  }

foreach_sve_vec_i foreach_sve_vec_u foreach_sve_vec_f
#undef _

#define _(t, s, c, i)                                                         \
  static_always_inline t##s##x##c t##s##x##c##_add (boolxn pg, t##s##x##c a,  \
						    t##s##x##c b)             \
  {                                                                           \
    return (t##s##x##c) svadd_##i##_z (pg, a, b);                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_add_n (boolxn pg,              \
						      t##s##x##c a, t##s b)   \
  {                                                                           \
    return (t##s##x##c) svadd_n_##i##_z (pg, a, b);                           \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_sub (boolxn pg, t##s##x##c a,  \
						    t##s##x##c b)             \
  {                                                                           \
    return (t##s##x##c) svsub_##i##_z (pg, a, b);                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_sub_n (boolxn pg,              \
						      t##s##x##c a, t##s b)   \
  {                                                                           \
    return (t##s##x##c) svsub_n_##i##_z (pg, a, b);                           \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_shift_left (                   \
    boolxn pg, t##s##x##c a, u##s##x##c b)                                    \
  {                                                                           \
    return (t##s##x##c) svlsl_##i##_z (pg, a, b);                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_shift_left_n (                 \
    boolxn pg, t##s##x##c a, u##s b)                                          \
  {                                                                           \
    return (t##s##x##c) svlsl_n_##i##_z (pg, a, b);                           \
  }                                                                           \
                                                                              \
  static_always_inline boolxn t##s##x##c##_elt_mask (i64 a, i64 b)            \
  {                                                                           \
    return svwhilelt_b##s (a, b);                                             \
  }                                                                           \
                                                                              \
  static_always_inline boolxn t##s##x##c##_eltall_mask ()                     \
  {                                                                           \
    return svptrue_b##s ();                                                   \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_and (boolxn pg, t##s##x##c a,  \
						    t##s##x##c b)             \
  {                                                                           \
    return (t##s##x##c) svand_##i##_z (pg, a, b);                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_or (boolxn pg, t##s##x##c a,   \
						   t##s##x##c b)              \
  {                                                                           \
    return (t##s##x##c) svorr_##i##_z (pg, a, b);                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_or_n (boolxn pg, t##s##x##c a, \
						     t##s b)                  \
  {                                                                           \
    return (t##s##x##c) svorr_n_##i##_z (pg, a, b);                           \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_eor (boolxn pg, t##s##x##c a,  \
						    t##s##x##c b)             \
  {                                                                           \
    return (t##s##x##c) sveor_##i##_z (pg, a, b);                             \
  }                                                                           \
                                                                              \
  static_always_inline boolxn t##s##x##c##_equal (boolxn pg, t##s##x##c a,    \
						  t##s##x##c b)               \
  {                                                                           \
    return svcmpeq_##i (pg, a, b);                                            \
  }                                                                           \
                                                                              \
  static_always_inline boolxn t##s##x##c##_unequal (boolxn pg, t##s##x##c a,  \
						    t##s##x##c b)             \
  {                                                                           \
    return svcmpne_##i (pg, a, b);                                            \
  }                                                                           \
                                                                              \
  static_always_inline boolxn t##s##x##c##_great_than (                       \
    boolxn pg, t##s##x##c a, t##s##x##c b)                                    \
  {                                                                           \
    return svcmpgt_##i (pg, a, b);                                            \
  }                                                                           \
                                                                              \
  static_always_inline t##s t##s##x##c##_reduction_or (boolxn pg,             \
						       t##s##x##c a)          \
  {                                                                           \
    return svorv_##i (pg, a);                                                 \
  }                                                                           \
                                                                              \
  static_always_inline int t##s##x##c##_is_all_zero (boolxn pg, t##s##x##c a) \
  {                                                                           \
    return t##s##x##c##_reduction_or (pg, a) == 0;                            \
  }                                                                           \
                                                                              \
  static_always_inline int t##s##x##c##_cla (boolxn pg, boolxn m)             \
  {                                                                           \
    return svcntp_b##s (pg, svbrkb_b_z (pg, svnot_b_z (pg, m)));              \
  }                                                                           \
                                                                              \
  static_always_inline int t##s##x##c##_clz (boolxn pg, boolxn m)             \
  {                                                                           \
    return svcntp_b##s (pg, svbrkb_b_z (pg, m));                              \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_cast_u8xn (u8xn a)             \
  {                                                                           \
    return svreinterpret_##i (a);                                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_cast_u16xn (u16xn a)           \
  {                                                                           \
    return svreinterpret_##i (a);                                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_cast_u32xn (u32xn a)           \
  {                                                                           \
    return svreinterpret_##i (a);                                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_cast_u64xn (u64xn a)           \
  {                                                                           \
    return svreinterpret_##i (a);                                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_cast_i8xn (i8xn a)             \
  {                                                                           \
    return svreinterpret_##i (a);                                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_cast_i16xn (i16xn a)           \
  {                                                                           \
    return svreinterpret_##i (a);                                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_cast_i32xn (i32xn a)           \
  {                                                                           \
    return svreinterpret_##i (a);                                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_cast_i64xn (i64xn a)           \
  {                                                                           \
    return svreinterpret_##i (a);                                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_create_indexes (t##s base,     \
							       t##s step)     \
  {                                                                           \
    return svindex_##i (base, step);                                          \
  }                                                                           \
                                                                              \
  static_always_inline t##s t##s##x##c##_eltmin (boolxn pg, t##s##x##c a)     \
  {                                                                           \
    return svminv_##i (pg, a);                                                \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_byte_swap (boolxn pg,          \
							  t##s##x##c x)       \
  {                                                                           \
    return svrevb_##i##_z (pg, x);                                            \
  }                                                                           \
                                                                              \
  static_always_inline t##64 t##s##x##c##_addsum (boolxn pg, t##s##x##c x)    \
  {                                                                           \
    return svaddv_##i (pg, x);                                                \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_modulo (                       \
    boolxn pg, t##s##x##c a, t##s##x##c b)                                    \
  {                                                                           \
    t##s##x##c div = svdiv_##i##_z (pg, a, b);                                \
    t##s##x##c mul = svmul_##i##_z (pg, div, b);                              \
    return svsub_##i##_z (pg, a, mul);                                        \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_sel (boolxn pg, t##s##x##c a,  \
						    t##s##x##c b)             \
  {                                                                           \
    return svsel_##i (pg, a, b);                                              \
  }

  foreach_sve_vec_i foreach_sve_vec_u
#undef _

#define _(t, s, c, i)                                                         \
  static_always_inline t##s##x##c t##s##x##c##_shift_right (                  \
    boolxn pg, t##s##x##c a, u##s##x##c b)                                    \
  {                                                                           \
    return (t##s##x##c) svlsr_##i##_z (pg, a, b);                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_shift_right_n (                \
    boolxn pg, t##s##x##c a, u##s b)                                          \
  {                                                                           \
    return (t##s##x##c) svlsr_n_##i##_z (pg, a, b);                           \
  }

    foreach_sve_vec_u
#undef _

#undef foreach_sve_vec_i
#undef foreach_sve_vec_u
#define foreach_sve_vec_i                                                     \
  _ (i, 8, n, s8, b)                                                          \
  _ (i, 16, n, s16, h) _ (i, 32, n, s32, w) _ (i, 64, n, s64, d)
#define foreach_sve_vec_u                                                     \
  _ (u, 8, n, u8, b)                                                          \
  _ (u, 16, n, u16, h) _ (u, 32, n, u32, w) _ (u, 64, n, u64, d)

#define _(t, s, c, i, w)                                                      \
  static_always_inline i32 t##s##x##c##_max_elts ()                           \
  {                                                                           \
    return (i32) svcnt##w ();                                                 \
  }                                                                           \
                                                                              \
  static_always_inline i32 t##s##x##c##_active_eno (boolxn pg, boolxn a)      \
  {                                                                           \
    return (i32) svcntp_b##s (pg, a);                                         \
  }                                                                           \
                                                                              \
  static_always_inline void t##s##x##c##_prefetch_vector (boolxn pg,          \
							  u64xn bases)        \
  {                                                                           \
    svprf##w##_gather_u64base (pg, bases, SV_PLDL3KEEP);                      \
  }

      foreach_sve_vec_u
#undef _

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
#define scalable_vector_foreach(I, ENO, EACTIVE, COUNT, ESIZE, BODY)          \
  do                                                                          \
    {                                                                         \
      I = 0;                                                                  \
      ENO = (i32) (svcntb () / (ESIZE >> 3));                                 \
      EACTIVE = svwhilelt_b##ESIZE ((typeof (COUNT)) I, COUNT);               \
      while (svptest_first (svptrue_b##ESIZE (), EACTIVE))                    \
	{                                                                     \
	  do                                                                  \
	    {                                                                 \
	      BODY;                                                           \
	    }                                                                 \
	  while (0);                                                          \
	  I += ENO;                                                           \
	  EACTIVE = svwhilelt_b##ESIZE ((typeof (COUNT)) I, COUNT);           \
	}                                                                     \
    }                                                                         \
  while (0)

/* To save CPU cycles by predict instructions, use unpredicated main loops
 * followed by a predicated tail */
#define scalable_vector_foreach2(I, ENO, EACTIVE, COUNT, ESIZE, BODY)         \
  do                                                                          \
    {                                                                         \
      ENO = (i32) (svcntb () / (ESIZE >> 3));                                 \
      EACTIVE = svptrue_b##ESIZE ();                                          \
      for (I = 0; I + ENO < COUNT; I += ENO)                                  \
	{                                                                     \
	  do                                                                  \
	    {                                                                 \
	      BODY;                                                           \
	    }                                                                 \
	  while (0);                                                          \
	}                                                                     \
      EACTIVE = svwhilelt_b##ESIZE ((typeof (COUNT)) I, COUNT);               \
      do                                                                      \
	{                                                                     \
	  BODY;                                                               \
	}                                                                     \
      while (0);                                                              \
    }                                                                         \
  while (0)

	/* Load 32-bit values from memory, zero-extend them,
	 * and store the results in a vector. */
	static_always_inline u64xn
	u64xn_load_u32 (boolxn pg, u32 *base)
{
  u64xn r = svld1uw_u64 (pg, base);
  return r;
}

/* Load 16-bit values from memory, zero-extend them,
 * and store the results in a vector. */
static_always_inline u64xn
u64xn_load_u16 (boolxn pg, u16 *base)
{
  u64xn r = svld1uh_u64 (pg, base);
  return r;
}

/* Load 8-bit values from memory, zero-extend them,
 * and store the results in a vector. */
static_always_inline u64xn
u64xn_load_u8 (boolxn pg, u8 *base)
{
  u64xn r = svld1ub_u64 (pg, base);
  return r;
}

/* Read elements from a vector, truncate them to 32 bits,
 * then store them to memory. */
static_always_inline void
u64xn_store_u32 (boolxn pg, u64xn v, u32 *base)
{
  svst1w_u64 (pg, base, v);
  return;
}

/* Read elements from a vector, truncate them to 16 bits,
 * then store them to memory. */
static_always_inline void
u64xn_store_u16 (boolxn pg, u64xn v, u16 *base)
{
  svst1h_u64 (pg, base, v);
  return;
}

/* Read elements from a vector, truncate them to 8 bits,
 * then store them to memory. */
static_always_inline void
u64xn_store_u8 (boolxn pg, u64xn v, u8 *base)
{
  svst1b_u64 (pg, base, v);
  return;
}

static_always_inline i64xn
i64xn_gather_offset_i16 (boolxn pg, u64xn bases, i64 offset)
{
  i64xn r = svld1sh_gather_u64base_offset_s64 (pg, bases, offset);
  return r;
}

static_always_inline u64xn
u64xn_gather_offset_u16 (boolxn pg, u64xn bases, i64 offset)
{
  u64xn r = svld1uh_gather_u64base_offset_u64 (pg, bases, offset);
  return r;
}

static_always_inline u64xn
u64xn_gather_offset_u32 (boolxn pg, u64xn bases, i64 offset)
{
  u64xn r = svld1uw_gather_u64base_offset_u64 (pg, bases, offset);
  return r;
}

static_always_inline u64xn
u64xn_gather_offset_u64 (boolxn pg, u64xn bases, i64 offset)
{
  u64xn r = svld1_gather_u64base_offset_u64 (pg, bases, offset);
  return r;
}

static_always_inline void
u64xn_scatter_u8 (boolxn pg, u64xn bases, u64xn data)
{
  svst1b_scatter_u64base_u64 (pg, bases, data);
  return;
}

static_always_inline void
i64xn_scatter_u8 (boolxn pg, u64xn bases, i64xn data)
{
  svst1b_scatter_u64base_s64 (pg, bases, data);
  return;
}

static_always_inline void
u64xn_scatter_u16 (boolxn pg, u64xn bases, u64xn data)
{
  svst1h_scatter_u64base_u64 (pg, bases, data);
  return;
}

static_always_inline void
i64xn_scatter_u16 (boolxn pg, u64xn bases, i64xn data)
{
  svst1h_scatter_u64base_s64 (pg, bases, data);
  return;
}

static_always_inline void
u64xn_scatter_u32 (boolxn pg, u64xn bases, u64xn data)
{
  svst1w_scatter_u64base_u64 (pg, bases, data);
  return;
}

static_always_inline void
i64xn_scatter_u32 (boolxn pg, u64xn bases, i64xn data)
{
  svst1w_scatter_u64base_s64 (pg, bases, data);
  return;
}

/* Perform an AND of two predicate inputs. Setting inactive to zero */
static_always_inline boolxn
boolxn_and (boolxn pg, boolxn a, boolxn b)
{
  return svand_b_z (pg, a, b);
}

/* Return true if any active element is true. */
static_always_inline int
boolxn_anytrue (boolxn pg, boolxn m)
{
  return svptest_any (pg, m);
}

/* Return true if the first active element is true. */
static_always_inline int
boolxn_firsttrue (boolxn pg, boolxn m)
{
  return svptest_first (pg, m);
}

/* Return true if the last active element is true. */
static_always_inline int
boolxn_lasttrue (boolxn pg, boolxn m)
{
  return svptest_last (pg, m);
}

/* Return true if the content in memory a and b is the same */
static_always_inline int
u8xn_memcmp (u8 *a, u8 *b, i32 len)
{
  i32 i, eno;
  boolxn m;
  u8xn av, bv;
  u8 v;
  scalable_vector_foreach2 (i, eno, m, len, 8, ({
			      av = u8xn_load_unaligned (m, a + i);
			      bv = u8xn_load_unaligned (m, b + i);
			      v = u8xn_reduction_or (m, u8xn_eor (m, av, bv));
			      if (v)
				return 0;
			    }));
  return 1;
}

/* Concatenate the active elements of the input vector,
 * filling any remaining elements with zero,
 * and then store active elements into continuous memory */
static_always_inline void
u16xn_compact_store (boolxn m, u16xn r, u16 *addr)
{
  boolxn all_m, lo_m, hi_m;
  u16xn u16allone;
  i32 eno_lo, eno_hi;
  u32xn u32allone, lo, hi, compact_lo, compact_hi;

  all_m = u32xn_eltall_mask ();
  u16allone = u16xn_splat ((u16) ~0);
  u32allone = u32xn_splat ((u16) ~0);
  /* set inactive elements to invalid value 0xFFFF */
  r = svsel_u16 (m, r, u16allone);
  /* convert half low u16 elements to u32 elements */
  lo = svunpklo_u32 (r);
  /* convert half high u16 elements to u32 elements */
  hi = svunpkhi_u32 (r);
  /* elements not equal 0xFFFF are regarded as active elements */
  lo_m = u32xn_unequal (all_m, u32allone, lo);
  hi_m = u32xn_unequal (all_m, u32allone, hi);
  /* compact half low and half high vectors */
  compact_lo = svcompact_u32 (lo_m, lo);
  compact_hi = svcompact_u32 (hi_m, hi);
  /* count active u32-elements in half low and half high vectors */
  eno_lo = u32xn_active_eno (lo_m, lo_m);
  eno_hi = u32xn_active_eno (hi_m, hi_m);
  /* compact store active u32-elements in half low/high vectors,
   * continuously into u16 type memories */
  svst1h_u32 (u32xn_elt_mask (0, eno_lo), addr, compact_lo);
  svst1h_u32 (u32xn_elt_mask (0, eno_hi), addr + eno_lo, compact_hi);
}
#endif /* included_vector_sve_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
