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
/*
  Copyright (c) 2004 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef included_clib_byte_order_h
#define included_clib_byte_order_h

#include <vppinfra/clib.h>

#if (__BYTE_ORDER__)==( __ORDER_LITTLE_ENDIAN__)
#define CLIB_ARCH_IS_BIG_ENDIAN (0)
#define CLIB_ARCH_IS_LITTLE_ENDIAN (1)
#else
/* Default is big endian. */
#define CLIB_ARCH_IS_BIG_ENDIAN (1)
#define CLIB_ARCH_IS_LITTLE_ENDIAN (0)
#endif

/* Big/little endian. */
#define clib_arch_is_big_endian    CLIB_ARCH_IS_BIG_ENDIAN
#define clib_arch_is_little_endian CLIB_ARCH_IS_LITTLE_ENDIAN

always_inline u16
clib_byte_swap_u16 (u16 x)
{
  return __builtin_bswap16 (x);
}

always_inline i16
clib_byte_swap_i16 (i16 x)
{
  return clib_byte_swap_u16 (x);
}

always_inline u32
clib_byte_swap_u32 (u32 x)
{
  return __builtin_bswap32 (x);
}

always_inline i32
clib_byte_swap_i32 (i32 x)
{
  return clib_byte_swap_u32 (x);
}

always_inline u64
clib_byte_swap_u64 (u64 x)
{
  return __builtin_bswap64 (x);
}

always_inline i64
clib_byte_swap_i64 (i64 x)
{
  return clib_byte_swap_u64 (x);
}

#define _(sex,type)						\
/* HOST -> SEX */						\
always_inline type						\
clib_host_to_##sex##_##type (type x)				\
{								\
  if (! clib_arch_is_##sex##_endian)				\
    x = clib_byte_swap_##type (x);				\
  return x;							\
}								\
								\
always_inline type						\
clib_host_to_##sex##_mem_##type (type * x)			\
{								\
  type v = x[0];						\
  return clib_host_to_##sex##_##type (v);			\
}								\
								\
always_inline type						\
clib_host_to_##sex##_unaligned_mem_##type (type * x)		\
{								\
  type v = clib_mem_unaligned (x, type);			\
  return clib_host_to_##sex##_##type (v);			\
}								\
								\
/* SEX -> HOST */						\
always_inline type						\
clib_##sex##_to_host_##type (type x)				\
{ return clib_host_to_##sex##_##type (x); }			\
								\
always_inline type						\
clib_##sex##_to_host_mem_##type (type * x)			\
{ return clib_host_to_##sex##_mem_##type (x); }			\
								\
always_inline type						\
clib_##sex##_to_host_unaligned_mem_##type (type * x)		\
{ return clib_host_to_##sex##_unaligned_mem_##type (x); }

#ifndef __cplusplus
_(little, u16)
_(little, u32)
_(little, u64)
_(little, i16)
_(little, i32)
_(little, i64)
_(big, u16) _(big, u32) _(big, u64) _(big, i16) _(big, i32) _(big, i64)
#endif
#undef _
/* Network "net" alias for "big". */
#define _(type)						\
always_inline type					\
clib_net_to_host_##type (type x)			\
{ return clib_big_to_host_##type (x); }			\
							\
always_inline type					\
clib_net_to_host_mem_##type (type * x)			\
{ return clib_big_to_host_mem_##type (x); }		\
							\
always_inline type					\
clib_net_to_host_unaligned_mem_##type (type * x)	\
{ return clib_big_to_host_unaligned_mem_##type (x); }	\
							\
always_inline type					\
clib_host_to_net_##type (type x)			\
{ return clib_host_to_big_##type (x); }			\
							\
always_inline type					\
clib_host_to_net_mem_##type (type * x)			\
{ return clib_host_to_big_mem_##type (x); }		\
							\
always_inline type					\
clib_host_to_net_unaligned_mem_##type (type * x)	\
{ return clib_host_to_big_unaligned_mem_##type (x); }
#ifndef __cplusplus
  _(u16);
_(i16);
_(u32);
_(i32);
_(u64);
_(i64);
#endif

#undef _

/* Dummy endian swap functions for IEEE floating-point numbers */
/* *INDENT-OFF* */
always_inline f64 clib_net_to_host_f64 (f64 x) { return x; }
always_inline f64 clib_host_to_net_f64 (f64 x) { return x; }
always_inline f32 clib_net_to_host_f32 (f32 x) { return x; }
always_inline f32 clib_host_to_net_f32 (f32 x) { return x; }
/* *INDENT-ON* */

#endif /* included_clib_byte_order_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
