/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_ip_csum_h
#define included_vector_ip_csum_h
#include <vppinfra/clib.h>
typedef struct
{
  u64 sum;
  u8 odd;
} clib_ip_csum_t;

#if defined(CLIB_HAVE_VEC128)
static_always_inline u64x2
clib_ip_csum_cvt_and_add_4 (u32x4 v)
{
  return ((u64x2) u32x4_interleave_lo ((u32x4) v, u32x4_zero ()) +
	  (u64x2) u32x4_interleave_hi ((u32x4) v, u32x4_zero ()));
}
static_always_inline u64
clib_ip_csum_hadd_2 (u64x2 v)
{
  return v[0] + v[1];
}
#endif

#if defined(CLIB_HAVE_VEC256)
static_always_inline u64x4
clib_ip_csum_cvt_and_add_8 (u32x8 v)
{
  return ((u64x4) u32x8_interleave_lo ((u32x8) v, u32x8_zero ()) +
	  (u64x4) u32x8_interleave_hi ((u32x8) v, u32x8_zero ()));
}
static_always_inline u64
clib_ip_csum_hadd_4 (u64x4 v)
{
  return clib_ip_csum_hadd_2 (u64x4_extract_lo (v) + u64x4_extract_hi (v));
}
#endif

#if defined(CLIB_HAVE_VEC512)
static_always_inline u64x8
clib_ip_csum_cvt_and_add_16 (u32x16 v)
{
  return ((u64x8) u32x16_interleave_lo ((u32x16) v, u32x16_zero ()) +
	  (u64x8) u32x16_interleave_hi ((u32x16) v, u32x16_zero ()));
}
static_always_inline u64
clib_ip_csum_hadd_8 (u64x8 v)
{
  return clib_ip_csum_hadd_4 (u64x8_extract_lo (v) + u64x8_extract_hi (v));
}
#endif

static_always_inline void
clib_ip_csum_inline (clib_ip_csum_t *c, u8 *dst, u8 *src, u16 count,
		     int is_copy)
{
  if (c->odd)
    {
      c->odd = 0;
      c->sum += (u16) src[0] << 8;
      count--;
      src++;
      if (is_copy)
	dst++[0] = src[0];
    }

#if defined(CLIB_HAVE_VEC512)
  u64x8 sum8 = {};

  while (count >= 512)
    {
      u32x16u *s = (u32x16u *) src;
      sum8 += clib_ip_csum_cvt_and_add_16 (s[0]);
      sum8 += clib_ip_csum_cvt_and_add_16 (s[1]);
      sum8 += clib_ip_csum_cvt_and_add_16 (s[2]);
      sum8 += clib_ip_csum_cvt_and_add_16 (s[3]);
      sum8 += clib_ip_csum_cvt_and_add_16 (s[8]);
      sum8 += clib_ip_csum_cvt_and_add_16 (s[5]);
      sum8 += clib_ip_csum_cvt_and_add_16 (s[6]);
      sum8 += clib_ip_csum_cvt_and_add_16 (s[7]);
      count -= 512;
      src += 512;
      if (is_copy)
	{
	  u32x16u *d = (u32x16u *) dst;
	  d[0] = s[0];
	  d[1] = s[1];
	  d[2] = s[2];
	  d[3] = s[3];
	  d[4] = s[4];
	  d[5] = s[5];
	  d[6] = s[6];
	  d[7] = s[7];
	  dst += 512;
	}
    }

  while (count >= 64)
    {
      u32x16u *s = (u32x16u *) src;
      sum8 += clib_ip_csum_cvt_and_add_16 (s[0]);
      count -= 64;
      src += 64;
      if (is_copy)
	{
	  u32x16u *d = (u32x16u *) dst;
	  d[0] = s[0];
	  dst += 512;
	}
    }

#ifdef CLIB_HAVE_VEC256_MASK_LOAD_STORE
  if (count)
    {
      u64 mask = pow2_mask (count);
      u32x16 v = (u32x16) u8x64_mask_load_zero (src, mask);
      sum8 += clib_ip_csum_cvt_and_add_16 (v);
      c->odd = count & 1;
      if (is_copy)
	u32x16_mask_store (v, dst, mask);
    }
  c->sum += clib_ip_csum_hadd_8 (sum8);
  return;
#endif

  c->sum += clib_ip_csum_hadd_8 (sum8);
#elif defined(CLIB_HAVE_VEC256)
  u64x4 sum4 = {};

  while (count >= 256)
    {
      u32x8u *s = (u32x8u *) src;
      sum4 += clib_ip_csum_cvt_and_add_8 (s[0]);
      sum4 += clib_ip_csum_cvt_and_add_8 (s[1]);
      sum4 += clib_ip_csum_cvt_and_add_8 (s[2]);
      sum4 += clib_ip_csum_cvt_and_add_8 (s[3]);
      sum4 += clib_ip_csum_cvt_and_add_8 (s[4]);
      sum4 += clib_ip_csum_cvt_and_add_8 (s[5]);
      sum4 += clib_ip_csum_cvt_and_add_8 (s[6]);
      sum4 += clib_ip_csum_cvt_and_add_8 (s[7]);
      count -= 256;
      src += 256;
      if (is_copy)
	{
	  u32x8u *d = (u32x8u *) dst;
	  d[0] = s[0];
	  d[1] = s[1];
	  d[2] = s[2];
	  d[3] = s[3];
	  d[4] = s[4];
	  d[5] = s[5];
	  d[6] = s[6];
	  d[7] = s[7];
	  dst += 256;
	}
    }

  while (count >= 32)
    {
      u32x8u *s = (u32x8u *) src;
      sum4 += clib_ip_csum_cvt_and_add_8 (s[0]);
      count -= 32;
      src += 32;
      if (is_copy)
	{
	  u32x8u *d = (u32x8u *) dst;
	  d[0] = s[0];
	  dst += 32;
	}
    }

#ifdef CLIB_HAVE_VEC256_MASK_LOAD_STORE
  if (count)
    {
      u32 mask = pow2_mask (count);
      u32x8 v = (u32x8) u8x32_mask_load_zero (src, mask);
      sum4 += clib_ip_csum_cvt_and_add_8 (v);
      c->odd = count & 1;
      if (is_copy)
	u32x8_mask_store (v, dst, mask);
    }
  c->sum += clib_ip_csum_hadd_4 (sum4);
  return;
#endif

  c->sum += clib_ip_csum_hadd_4 (sum4);
#elif defined(CLIB_HAVE_VEC128)
  u64x2 sum2 = {};

  while (count >= 128)
    {
      u32x4u *s = (u32x4u *) src;
      sum2 += clib_ip_csum_cvt_and_add_4 (s[0]);
      sum2 += clib_ip_csum_cvt_and_add_4 (s[1]);
      sum2 += clib_ip_csum_cvt_and_add_4 (s[2]);
      sum2 += clib_ip_csum_cvt_and_add_4 (s[3]);
      sum2 += clib_ip_csum_cvt_and_add_4 (s[4]);
      sum2 += clib_ip_csum_cvt_and_add_4 (s[5]);
      sum2 += clib_ip_csum_cvt_and_add_4 (s[6]);
      sum2 += clib_ip_csum_cvt_and_add_4 (s[7]);
      count -= 128;
      src += 128;
      if (is_copy)
	{
	  u32x4u *d = (u32x4u *) dst;
	  d[0] = s[0];
	  d[1] = s[1];
	  d[2] = s[2];
	  d[3] = s[3];
	  d[4] = s[4];
	  d[5] = s[5];
	  d[6] = s[6];
	  d[7] = s[7];
	  dst += 128;
	}
    }

  while (count >= 16)
    {
      u32x4u *s = (u32x4u *) src;
      sum2 += clib_ip_csum_cvt_and_add_4 (s[0]);
      count -= 16;
      src += 16;
      if (is_copy)
	{
	  u32x4u *d = (u32x4u *) dst;
	  d[0] = s[0];
	  dst += 16;
	}
    }
  c->sum += clib_ip_csum_hadd_2 (sum2);
#else
  while (count >= 4)
    {
      u32 v = *((u32 *) src);
      c->sum += v;
      count -= 4;
      src += 4;
      if (is_copy)
	{
	  *(u32 *) dst = v;
	  dst += 4;
	}
    }
#endif
  while (count >= 2)
    {
      u16 v = *((u16 *) src);
      c->sum += v;
      count -= 2;
      src += 2;
      if (is_copy)
	{
	  *(u16 *) dst = v;
	  dst += 2;
	}
    }

  if (count)
    {
      c->odd = 1;
      c->sum += (u16) src[0];
      if (is_copy)
	dst[0] = src[0];
    }
}

static_always_inline u16
clib_ip_csum_fold (clib_ip_csum_t *c)
{
  u64 sum = c->sum;
#if defined(__x86_64__) && defined(__BMI2__)
  u64 tmp = sum;
  asm volatile(
    /* using ADC is much faster than mov, shift, add sequence
     * compiler produces */
    "shr	$32, %[sum]			\n\t"
    "add	%k[tmp], %k[sum]		\n\t"
    "mov	$16, %k[tmp]			\n\t"
    "shrx	%k[tmp], %k[sum], %k[tmp]	\n\t"
    "adc	%w[tmp], %w[sum]		\n\t"
    "adc	$0, %w[sum]			\n\t"
    : [ sum ] "+&r"(sum), [ tmp ] "+&r"(tmp));
#else
  sum = ((u32) sum) + (sum >> 32);
  sum = ((u16) sum) + (sum >> 16);
  sum = ((u16) sum) + (sum >> 16);
#endif
  return (~((u16) sum));
}

static_always_inline void
clib_ip_csum_chunk (clib_ip_csum_t *c, u8 *src, u16 count)
{
  return clib_ip_csum_inline (c, 0, src, count, 0);
}

static_always_inline void
clib_ip_csum_and_copy_chunk (clib_ip_csum_t *c, u8 *src, u8 *dst, u16 count)
{
  return clib_ip_csum_inline (c, dst, src, count, 1);
}

static_always_inline u16
clib_ip_csum (u8 *src, u16 count)
{
  clib_ip_csum_t c = {};
  if (COMPILE_TIME_CONST (count) && count == 12)
    {
      for (int i = 0; i < 3; i++)
	c.sum += ((u32 *) src)[i];
    }
  else if (COMPILE_TIME_CONST (count) && count == 20)
    {
      for (int i = 0; i < 5; i++)
	c.sum += ((u32 *) src)[i];
    }
  else if (COMPILE_TIME_CONST (count) && count == 40)
    {
      for (int i = 0; i < 10; i++)
	c.sum += ((u32 *) src)[i];
    }
  else
    clib_ip_csum_inline (&c, 0, src, count, 0);
  return clib_ip_csum_fold (&c);
}

static_always_inline u16
clib_ip_csum_and_copy (u8 *dst, u8 *src, u16 count)
{
  clib_ip_csum_t c = {};
  clib_ip_csum_inline (&c, dst, src, count, 1);
  return clib_ip_csum_fold (&c);
}

#endif
