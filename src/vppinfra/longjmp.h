/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2005 Eliot Dresselhaus
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
#elif defined(_mips) && __mips == 64
#define CLIB_ARCH_LONGJMP_REGS (12)
#elif defined(__riscv)
/* ra, sp, s0-s11, fs0-fs11 */
#define CLIB_ARCH_LONGJMP_REGS (26)
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
