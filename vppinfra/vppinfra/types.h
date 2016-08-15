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
  Copyright (c) 2001-2005 Eliot Dresselhaus

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

#ifndef included_clib_types_h
#define included_clib_types_h

/* Standard CLIB types. */

/* Define signed and unsigned 8, 16, 32, and 64 bit types
   and machine signed/unsigned word for all architectures. */
typedef char i8;
typedef short i16;

/* Avoid conflicts with Linux asm/types.h when __KERNEL__ */
#if defined(CLIB_LINUX_KERNEL)
/* Linux also defines u8/u16/u32/u64 types. */
#include <asm/types.h>
#define CLIB_AVOID_CLASH_WITH_LINUX_TYPES

#else /* ! CLIB_LINUX_KERNEL */

typedef unsigned char u8;
typedef unsigned short u16;
#endif /* ! CLIB_LINUX_KERNEL */

#if defined (__x86_64__)
#ifndef __COVERITY__
typedef int i128 __attribute__ ((mode (TI)));
typedef unsigned int u128 __attribute__ ((mode (TI)));
#endif
#endif

#if (defined(i386) || defined(_mips) || defined(powerpc) || defined (__SPU__) || defined(__sparc__) || defined(__arm__) || defined (__xtensa__) || defined(__TMS320C6X__))
typedef int i32;
typedef long long i64;

#ifndef CLIB_AVOID_CLASH_WITH_LINUX_TYPES
typedef unsigned int u32;
typedef unsigned long long u64;
#endif /* CLIB_AVOID_CLASH_WITH_LINUX_TYPES */

#elif defined(_mips) && __mips == 64
#define log2_uword_bits 6
#define clib_address_bits _MIPS_SZPTR

#elif defined(alpha) || defined(__x86_64__) || defined (__powerpc64__) || defined (__aarch64__)
typedef int i32;
typedef long i64;

#define log2_uword_bits 6
#define clib_address_bits 64

#ifndef CLIB_AVOID_CLASH_WITH_LINUX_TYPES
typedef unsigned int u32;
typedef unsigned long u64;
#endif /* CLIB_AVOID_CLASH_WITH_LINUX_TYPES */

#else
#error "can't define types"
#endif

/* Default to 32 bit machines with 32 bit addresses. */
#ifndef log2_uword_bits
#define log2_uword_bits 5
#endif

/* #ifdef's above define log2_uword_bits. */
#define uword_bits (1 << log2_uword_bits)

#ifndef clib_address_bits
#define clib_address_bits 32
#endif

/* Word types. */
#if uword_bits == 64
/* 64 bit word machines. */
typedef i64 word;
typedef u64 uword;
#else
/* 32 bit word machines. */
typedef i32 word;
typedef u32 uword;
#endif

/* integral type of a pointer (used to cast pointers). */
#if clib_address_bits == 64
typedef u64 clib_address_t;
#else
typedef u32 clib_address_t;
#endif

/* These are needed to convert between pointers and machine words.
   MIPS is currently the only machine that can have different sized
   pointers and machine words (but only when compiling with 64 bit
   registers and 32 bit pointers). */
static inline __attribute__ ((always_inline)) uword
pointer_to_uword (const void *p)
{
  return (uword) (clib_address_t) p;
}

#define uword_to_pointer(u,type) ((type) (clib_address_t) (u))

/* Any type: can be either word or pointer. */
typedef word any;

/* Floating point types. */
typedef double f64;
typedef float f32;

typedef __complex__ float cf32;
typedef __complex__ double cf64;

/* Floating point word size. */
typedef f64 fword;

/* Can be used as either {r,l}value, e.g. these both work
     clib_mem_unaligned (p, u64) = 99
     clib_mem_unaligned (p, u64) += 99 */

#define clib_mem_unaligned(pointer,type) \
  (((struct { CLIB_PACKED (type _data); } *) (pointer))->_data)

/* Access memory with specified alignment depending on align argument.
   As with clib_mem_unaligned, may be used as {r,l}value. */
#define clib_mem_aligned(addr,type,align)		\
  (((struct {						\
       type _data					\
       __attribute__ ((aligned (align), packed));	\
    } *) (addr))->_data)

#endif /* included_clib_types_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
