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
#define CLIB_CPU_OPTIMIZED __attribute__ ((optimize ("O3")))
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

#ifdef CLIB_MARCH_VARIANT
#define __CLIB_MULTIARCH_FN(a,b) a##_##b
#define _CLIB_MULTIARCH_FN(a,b) __CLIB_MULTIARCH_FN(a,b)
#define CLIB_MULTIARCH_FN(fn) _CLIB_MULTIARCH_FN(fn,CLIB_MARCH_VARIANT)
#else
#define CLIB_MULTIARCH_FN(fn) fn
#endif

#define CLIB_MARCH_SFX CLIB_MULTIARCH_FN

#define foreach_x86_64_flags \
_ (sse3,     1, ecx, 0)   \
_ (ssse3,    1, ecx, 9)   \
_ (sse41,    1, ecx, 19)  \
_ (sse42,    1, ecx, 20)  \
_ (avx,      1, ecx, 28)  \
_ (avx2,     7, ebx, 5)   \
_ (avx512f,  7, ebx, 16)  \
_ (x86_aes,  1, ecx, 25)  \
_ (sha,      7, ebx, 29)  \
_ (invariant_tsc, 0x80000007, edx, 8)


#define foreach_aarch64_flags \
_ (fp,          0) \
_ (asimd,       1) \
_ (evtstrm,     2) \
_ (aarch64_aes, 3) \
_ (pmull,       4) \
_ (sha1,        5) \
_ (sha2,        6) \
_ (crc32,       7) \
_ (atomics,     8) \
_ (fphp,        9) \
_ (asimdhp,    10) \
_ (cpuid,      11) \
_ (asimdrdm,   12) \
_ (jscvt,      13) \
_ (fcma,       14) \
_ (lrcpc,      15) \
_ (dcpop,      16) \
_ (sha3,       17) \
_ (sm3,        18) \
_ (sm4,        19) \
_ (asimddp,    20) \
_ (sha512,     21) \
_ (sve,        22)

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
#else /* __x86_64__ */

#define _(flag, func, reg, bit) \
static inline int clib_cpu_supports_ ## flag() { return 0; }
foreach_x86_64_flags
#undef _
#endif /* __x86_64__ */
#if defined(__aarch64__)
#include <sys/auxv.h>
#define _(flag, bit) \
static inline int							\
clib_cpu_supports_ ## flag()						\
{									\
  unsigned long hwcap = getauxval(AT_HWCAP);				\
  return (hwcap & (1 << bit));						\
}
  foreach_aarch64_flags
#undef _
#else /* ! __x86_64__ && !__aarch64__ */
#define _(flag, bit) \
static inline int clib_cpu_supports_ ## flag() { return 0; }
  foreach_aarch64_flags
#undef _
#endif /* __x86_64__, __aarch64__ */
/*
 * aes is the only feature with the same name in both flag lists
 * handle this by prefixing it with the arch name, and handling it
 * with the custom function below
 */
  static inline int
clib_cpu_supports_aes ()
{
#if defined (__aarch64__)
  return clib_cpu_supports_x86_aes ();
#elif defined (__aarch64__)
  return clib_cpu_supports_aarch64_aes ();
#else
  return 0;
#endif
}

static inline int
clib_cpu_march_priority_avx512 ()
{
  if (clib_cpu_supports_avx512f ())
    return 20;
  return -1;
}

static inline int
clib_cpu_march_priority_avx2 ()
{
  if (clib_cpu_supports_avx2 ())
    return 10;
  return -1;
}

#ifdef CLIB_MARCH_VARIANT
#define CLIB_MARCH_FN_PRIORITY() CLIB_MARCH_SFX(clib_cpu_march_priority)()
#else
#define CLIB_MARCH_FN_PRIORITY() 0
#endif
#endif /* included_clib_cpu_h */

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
