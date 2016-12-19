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
  Copyright (c) 2005 Eliot Dresselhaus

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

#ifndef included_clib_longjmp_h
#define included_clib_longjmp_h

#include <vppinfra/types.h>

#if defined(__x86_64__)
/* rbx, rbp, r12, r13, r14, r15, eip, rsp */
#define CLIB_ARCH_LONGJMP_REGS 8

#elif defined(i386)
/* ebx, ebp, esi, edi, eip, rsp */
#define CLIB_ARCH_LONGJMP_REGS 6

#elif (defined(__powerpc64__) || defined(__powerpc__))

#ifdef __ALTIVEC__
#define CLIB_POWERPC_ALTIVEC_N_REGS 12
#else
#define CLIB_POWERPC_ALTIVEC_N_REGS 0
#endif

/* r1 r2 link condition+vsave regs 14-31 fp regs 14-31 vector regs 20-31 */
#define CLIB_ARCH_LONGJMP_REGS				\
  (/* r1 lr cr vrsave */				\
   4							\
   /* gp */						\
   + (31 - 14 + 1)					\
   /* fp */						\
   + (sizeof (f64) / sizeof (uword)) * (31 - 14 + 1)	\
   /* vector regs */					\
   + (16 / sizeof (uword)) * CLIB_POWERPC_ALTIVEC_N_REGS)

#elif defined(__SPU__)
/* FIXME */
#define CLIB_ARCH_LONGJMP_REGS (10)

#elif defined(__arm__)

#ifndef __IWMMXT__
/* v1-v6 sl fp sp lr */
#define CLIB_ARCH_LONGJMP_REGS (10)
#else
/* For iwmmxt we save 6 extra 8 byte registers. */
#define CLIB_ARCH_LONGJMP_REGS (10 + (6*2))
#endif

#elif defined(__xtensa__)

/* setjmp/longjmp not supported for the moment. */
#define CLIB_ARCH_LONGJMP_REGS 0

#elif defined(__TMS320C6X__)

/* setjmp/longjmp not supported for the moment. */
#define CLIB_ARCH_LONGJMP_REGS 0

#elif defined(__aarch64__)
#define CLIB_ARCH_LONGJMP_REGS (22)
#else
#error "unknown machine"
#endif

typedef struct
{
  uword regs[CLIB_ARCH_LONGJMP_REGS];
} clib_longjmp_t __attribute__ ((aligned (16)));

/* Return given value to saved context. */
void clib_longjmp (clib_longjmp_t * save, uword return_value);

/* Save context.  Returns given value if jump is not taken;
   otherwise returns value from clib_longjmp if long jump is taken. */
uword clib_setjmp (clib_longjmp_t * save, uword return_value_not_taken);

/* Call function on given stack. */
uword clib_calljmp (uword (*func) (uword func_arg),
		    uword func_arg, void *stack);

#endif /* included_clib_longjmp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
