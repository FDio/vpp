/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_lookup_common_h__
#define __included_lookup_common_h__
#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#ifdef __SSE4_1__
#define u32x4_insert(v, x, i) (u32x4) _mm_insert_epi32 ((__m128i) (v), x, i)
#else
static_always_inline u32x4
u32x4_insert (u32x4 v, u32 x, int i)
{
  u32x4 tmp = v;
  tmp[i] = x;
  return tmp;
}
#endif

#ifdef __SSE3__
#define u8x8_shuffle(v, i) (u8x8) _mm_shuffle_pi8 ((__m64) (v), (__m64) i)
#elif defined(__clang__)
static_always_inline u8x8
u8x8_shuffle (u8x8 v, u8x8 i)
{
  u8x8 tmp = { 0 };
  u16x8 tmp2;
  tmp[0] = v[i[0] & 0x7];
  tmp[1] = v[i[1] & 0x7];
  tmp[2] = v[i[2] & 0x7];
  tmp[3] = v[i[3] & 0x7];
  tmp[4] = v[i[4] & 0x7];
  tmp[5] = v[i[5] & 0x7];
  tmp[6] = v[i[6] & 0x7];
  tmp[7] = v[i[7] & 0x7];
  tmp2 = __builtin_convertvector (i, u16x8);
  tmp2 &= (u16x8){ 128, 128, 128, 128, 128, 128, 128, 128 };
  tmp2 <<= 1;
  tmp2 -= 1;
  tmp2 = ~tmp2;
  tmp &= __builtin_convertvector (tmp2, u8x8);
  return tmp;
}
#else
#define u8x8_shuffle(v, i) __builtin_shuffle ((u8x8) v, (u8x8) i)
#endif

#ifndef CLIB_HAVE_VEC256
#define u32x8_splat(i) ((u32) (i) & (u32x8){ ~0, ~0, ~0, ~0, ~0, ~0, ~0, ~0 })
#endif

#ifndef SHUFFLE
#if defined(__clang__)
#define SHUFFLE(v1, v2, i) __builtin_shufflevector ((v1), (v2), (i))
#elif defined(__GNUC__)
#define SHUFFLE(v1, v2, i) __builtin_shuffle ((v1), (v2), (i))
#endif
#endif

#define u8x16_SHUFFLE(v1, v2, i)                                              \
  (u8x16) SHUFFLE ((u8x16) (v1), (u8x16) (v2), (u8x16) (i))
#define u32x8_SHUFFLE(v1, v2, i)                                              \
  (u32x8) SHUFFLE ((u32x8) (v1), (u32x8) (v2), (u32x8) (i))

#ifdef __SSE3__
#define u8x16_shuffle_dynamic(v, i)                                           \
  (u8x16) _mm_shuffle_epi8 ((__m128i) v, (__m128i) i)
#elif defined(__clang__)
static_always_inline u8x16
u8x16_shuffle_dynamic (u8x16 v, u8x16 i)
{
  u8x16 tmp = { 0 };
  u16x16 tmp2;
  tmp[0] = v[i[0] & 0xf];
  tmp[1] = v[i[1] & 0xf];
  tmp[2] = v[i[2] & 0xf];
  tmp[3] = v[i[3] & 0xf];
  tmp[4] = v[i[4] & 0xf];
  tmp[5] = v[i[5] & 0xf];
  tmp[6] = v[i[6] & 0xf];
  tmp[7] = v[i[7] & 0xf];
  tmp[8] = v[i[8] & 0xf];
  tmp[9] = v[i[9] & 0xf];
  tmp[10] = v[i[10] & 0xf];
  tmp[11] = v[i[11] & 0xf];
  tmp[12] = v[i[12] & 0xf];
  tmp[13] = v[i[13] & 0xf];
  tmp[14] = v[i[14] & 0xf];
  tmp[15] = v[i[15] & 0xf];
  tmp2 = __builtin_convertvector (i, u16x16);
  tmp2 &= (u16x16){ 128, 128, 128, 128, 128, 128, 128, 128,
		    128, 128, 128, 128, 128, 128, 128, 128 };
  tmp2 <<= 1;
  tmp2 -= tmp2 >> 8;
  tmp2 = ~tmp2;
  tmp &= __builtin_convertvector (tmp2, u8x16);
  return tmp;
}
#else
static_always_inline u8x16
u8x16_shuffle_dynamic (u8x16 v, u8x16 i)
{
  u8x16 tmp = { 0 };
  tmp = __builtin_shuffle (v, i);
  i >>= 7;
  i -= 1;
  tmp &= i;
  return tmp;
}
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpsabi"
#ifdef __AVX2__
#define u32x8_shuffle_dynamic(v, i)                                           \
  (u32x8) _mm256_permutevar8x32_epi32 ((__m256i) v, (__m256i) i)
#elif defined(__clang__)
static_always_inline u32x8
u32x8_shuffle_dynamic (u32x8 v, u32x8 i)
{
  u32x8 tmp = { 0 };
  tmp[0] = v[i[0] & 0x7];
  tmp[1] = v[i[1] & 0x7];
  tmp[2] = v[i[2] & 0x7];
  tmp[3] = v[i[3] & 0x7];
  tmp[4] = v[i[4] & 0x7];
  tmp[5] = v[i[5] & 0x7];
  tmp[6] = v[i[6] & 0x7];
  tmp[7] = v[i[7] & 0x7];
  return tmp;
}
#else
#define u32x8_shuffle_dynamic(v, i) __builtin_shuffle ((u32x8) v, (u32x8) i)
#endif

static_always_inline u32x2
u32x2_insert (u32x2 x, u32 y, uword idx)
{
  u32x2 tmp = x;
  tmp[idx] = y;
  return tmp;
}

static_always_inline u8x8
u8x8_insert (u8x8 x, u8 y, uword idx)
{
  u8x8 tmp = x;
  tmp[idx] = y;
  return tmp;
}
#pragma GCC diagnostic pop
__clib_unused static const u8 l4_mask_bits[256] = {
  [IP_PROTOCOL_ICMP] = 16,     [IP_PROTOCOL_IGMP] = 8,
  [IP_PROTOCOL_ICMP6] = 16,    [IP_PROTOCOL_TCP] = 32,
  [IP_PROTOCOL_UDP] = 32,      [IP_PROTOCOL_IPSEC_ESP] = 32,
  [IP_PROTOCOL_IPSEC_AH] = 32,
};

/* L4 data offset to copy into session */
__clib_unused static const u8 l4_offset_32w[256] = {
  [IP_PROTOCOL_ICMP] = 1, [IP_PROTOCOL_ICMP6] = 1
};

/* TODO: add ICMP, ESP, and AH (+ additional
 * branching or lookup for different
 * shuffling mask) */
__clib_unused static const u64 tcp_udp_bitmask =
  ((1 << IP_PROTOCOL_TCP) | (1 << IP_PROTOCOL_UDP));

#endif /* __included_lookup_common_h__ */