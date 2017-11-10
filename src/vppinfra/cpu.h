/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef included_clib_cpu_h
#define included_clib_cpu_h

#include <vppinfra/format.h>

/*
 * multiarchitecture support. Adding new entry will produce
 * new graph node function variant optimized for specific cpu
 * microarchitecture.
 * Order is important for runtime selection, as 1st match wins...
 */

#if __x86_64__ && CLIB_DEBUG == 0
#define foreach_march_variant(macro, x) \
  macro(avx2,  x, "arch=core-avx2")
#else
#define foreach_march_variant(macro, x)
#endif


#if __GNUC__ > 4  && !__clang__
#define CLIB_CPU_OPTIMIZED __attribute__ ((optimize ("tree-vectorize")))
#else
#define CLIB_CPU_OPTIMIZED
#endif


#define CLIB_MULTIARCH_ARCH_CHECK(arch, fn, tgt)			\
  if (clib_cpu_supports_ ## arch())					\
    return & fn ## _ ##arch;

#define CLIB_MULTIARCH_SELECT_FN(fn,...)                               \
  __VA_ARGS__ void * fn ## _multiarch_select(void)                     \
{                                                                      \
  foreach_march_variant(CLIB_MULTIARCH_ARCH_CHECK, fn)                 \
  return & fn;                                                         \
}

#ifdef CLIB_MULTIARCH_VARIANT
#define __CLIB_MULTIARCH_FN(a,b) a##_##b
#define _CLIB_MULTIARCH_FN(a,b) __CLIB_MULTIARCH_FN(a,b)
#define CLIB_MULTIARCH_FN(fn) _CLIB_MULTIARCH_FN(fn,CLIB_MULTIARCH_VARIANT)
#else
#define CLIB_MULTIARCH_FN(fn) fn
#endif

#define foreach_x86_64_flags \
_ (sse3,     1, ecx, 0)   \
_ (ssse3,    1, ecx, 9)   \
_ (sse41,    1, ecx, 19)  \
_ (sse42,    1, ecx, 20)  \
_ (avx,      1, ecx, 28)  \
_ (avx2,     7, ebx, 5)   \
_ (avx512f,  7, ebx, 16)  \
_ (aes,      1, ecx, 25)  \
_ (sha,      7, ebx, 29)  \
_ (invariant_tsc, 0x80000007, edx, 8)

#if defined(__x86_64__)
#include "cpuid.h"

static inline int
clib_get_cpuid (const u32 lev, u32 * eax, u32 * ebx, u32 * ecx, u32 * edx)
{
  if ((u32) __get_cpuid_max (0x80000000 & lev, 0) < lev)
    return 0;
  if (lev == 7)
    __cpuid_count (lev, 0, *eax, *ebx, *ecx, *edx);
  else
    __cpuid (lev, *eax, *ebx, *ecx, *edx);
  return 1;
}


#define _(flag, func, reg, bit) \
static inline int							\
clib_cpu_supports_ ## flag()						\
{									\
  u32 __attribute__((unused)) eax, ebx = 0, ecx = 0, edx  = 0;		\
  clib_get_cpuid (func, &eax, &ebx, &ecx, &edx);			\
									\
  return ((reg & (1 << bit)) != 0);					\
}
foreach_x86_64_flags
#undef _
#else

#define _(flag, func, reg, bit) \
static inline int clib_cpu_supports_ ## flag() { return 0; }
foreach_x86_64_flags
#undef _
#endif
#endif
  format_function_t format_cpu_uarch;
format_function_t format_cpu_model_name;
format_function_t format_cpu_flags;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
