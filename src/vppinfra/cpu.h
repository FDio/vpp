/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef included_clib_cpu_h
#define included_clib_cpu_h

#include <sys/syscall.h>
#include <vppinfra/format.h>

#if defined(__x86_64__)
#define foreach_march_variant                                                                      \
  _ (scalar, "Generic (SIMD disabled)")                                                            \
  _ (x86_64_v3, "x86-64-v3")                                                                       \
  _ (x86_64_v4, "x86-64-v4")
#elif defined(__aarch64__)
#define foreach_march_variant                                                 \
  _ (octeontx2, "Marvell Octeon TX2")                                         \
  _ (thunderx2t99, "Marvell ThunderX2 T99")                                   \
  _ (qdf24xx, "Qualcomm CentriqTM 2400")                                      \
  _ (cortexa72, "ARM Cortex-A72")                                             \
  _ (neoversen1, "ARM Neoverse N1")                                           \
  _ (neoversen2, "ARM Neoverse N2")                                           \
  _ (neoversev2, "ARM Neoverse V2")
#else
#define foreach_march_variant
#endif

typedef enum
{
  CLIB_MARCH_VARIANT_TYPE = 0,
#define _(s, n) CLIB_MARCH_VARIANT_TYPE_##s,
  foreach_march_variant
#undef _
    CLIB_MARCH_TYPE_N_VARIANTS
} clib_march_variant_type_t;

#ifdef CLIB_MARCH_VARIANT
#define __CLIB_MULTIARCH_FN(a,b) a##_##b
#define _CLIB_MULTIARCH_FN(a,b) __CLIB_MULTIARCH_FN(a,b)
#define CLIB_MULTIARCH_FN(fn) _CLIB_MULTIARCH_FN(fn,CLIB_MARCH_VARIANT)
#else
#define CLIB_MULTIARCH_FN(fn) fn
#endif

#define CLIB_MARCH_SFX CLIB_MULTIARCH_FN

typedef struct _clib_march_fn_registration
{
  void *function;
  int priority;
  struct _clib_march_fn_registration *next;
  char *name;
} clib_march_fn_registration;

static_always_inline void *
clib_march_select_fn_ptr (clib_march_fn_registration * r)
{
  void *rv = 0;
  int last_prio = -1;

  while (r)
    {
      if (last_prio < r->priority)
	{
	  last_prio = r->priority;
	  rv = r->function;
	}
      r = r->next;
    }
  return rv;
}

#define CLIB_MARCH_FN_POINTER(fn)                                             \
  (__typeof__ (fn) *) clib_march_select_fn_ptr (fn##_march_fn_registrations);

#define CLIB_MARCH_FN_VOID_POINTER(fn)                                        \
  clib_march_select_fn_ptr (fn##_march_fn_registrations);

#define _CLIB_MARCH_FN_REGISTRATION(fn) \
static clib_march_fn_registration \
CLIB_MARCH_SFX(fn##_march_fn_registration) = \
{ \
  .name = CLIB_MARCH_VARIANT_STR \
}; \
\
static void __clib_constructor \
fn##_march_register () \
{ \
  clib_march_fn_registration *r; \
  r = & CLIB_MARCH_SFX (fn##_march_fn_registration); \
  r->priority = CLIB_MARCH_FN_PRIORITY(); \
  r->next = fn##_march_fn_registrations; \
  r->function = CLIB_MARCH_SFX (fn); \
  fn##_march_fn_registrations = r; \
}

#ifdef CLIB_MARCH_VARIANT
#define CLIB_MARCH_FN_REGISTRATION(fn) \
extern clib_march_fn_registration *fn##_march_fn_registrations; \
_CLIB_MARCH_FN_REGISTRATION(fn)
#else
#define CLIB_MARCH_FN_REGISTRATION(fn) \
clib_march_fn_registration *fn##_march_fn_registrations = 0; \
_CLIB_MARCH_FN_REGISTRATION(fn)
#endif
#define foreach_x86_64_flags                                                                       \
  _ (sse3, 1, ecx, 0)                                                                              \
  _ (pclmulqdq, 1, ecx, 1)                                                                         \
  _ (ssse3, 1, ecx, 9)                                                                             \
  _ (sse41, 1, ecx, 19)                                                                            \
  _ (sse42, 1, ecx, 20)                                                                            \
  _ (avx, 1, ecx, 28)                                                                              \
  _ (rdrand, 1, ecx, 30)                                                                           \
  _ (avx2, 7, ebx, 5)                                                                              \
  _ (bmi2, 7, ebx, 8)                                                                              \
  _ (rtm, 7, ebx, 11)                                                                              \
  _ (pqm, 7, ebx, 12)                                                                              \
  _ (pqe, 7, ebx, 15)                                                                              \
  _ (avx512f, 7, ebx, 16)                                                                          \
  _ (rdseed, 7, ebx, 18)                                                                           \
  _ (x86_aes, 1, ecx, 25)                                                                          \
  _ (sha, 7, ebx, 29)                                                                              \
  _ (vaes, 7, ecx, 9)                                                                              \
  _ (vpclmulqdq, 7, ecx, 10)                                                                       \
  _ (avx512_vnni, 7, ecx, 11)                                                                      \
  _ (avx512_bitalg, 7, ecx, 12)                                                                    \
  _ (avx512_vpopcntdq, 7, ecx, 14)                                                                 \
  _ (avx512_vp2intersect, 7, edx, 8)                                                               \
  _ (movdiri, 7, ecx, 27)                                                                          \
  _ (movdir64b, 7, ecx, 28)                                                                        \
  _ (enqcmd, 7, ecx, 29)                                                                           \
  _ (avx512_fp16, 7, edx, 23)                                                                      \
  _ (fma, 1, ecx, 12)                                                                              \
  _ (movbe, 1, ecx, 22)                                                                            \
  _ (popcnt, 1, ecx, 23)                                                                           \
  _ (f16c, 1, ecx, 29)                                                                             \
  _ (bmi1, 7, ebx, 3)                                                                              \
  _ (lzcnt, 0x80000001, ecx, 5)                                                                    \
  _ (avx512dq, 7, ebx, 17)                                                                         \
  _ (avx512cd, 7, ebx, 28)                                                                         \
  _ (avx512bw, 7, ebx, 30)                                                                         \
  _ (avx512vl, 7, ebx, 31)                                                                         \
  _ (cmpxchg16b, 1, ecx, 13)                                                                       \
  _ (lahf_sahf, 0x80000001, ecx, 0)                                                                \
  _ (osxsave, 1, ecx, 27)                                                                          \
  _ (aperfmperf, 0x00000006, ecx, 0)                                                               \
  _ (invariant_tsc, 0x80000007, edx, 8)                                                            \
  _ (monitorx, 0x80000001, ecx, 29)

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

u32 clib_get_current_cpu_id (void);
u32 clib_get_current_numa_node (void);

typedef int (*clib_cpu_supports_func_t) (void);

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
#if defined(__x86_64__)
  return clib_cpu_supports_x86_aes ();
#elif defined (__aarch64__)
  return clib_cpu_supports_aarch64_aes ();
#else
  return 0;
#endif
}

static inline int
clib_cpu_is_amd ()
{
#ifdef __x86_64__
  const char vendor[13] = "AuthenticAMD";
  u32u *v = (u32u *) vendor;
  u32 eax, ebx, ecx, edx;

  if (clib_get_cpuid (0, &eax, &ebx, &ecx, &edx) == 0)
    return 0;

  if (ebx == v[0] && ecx == v[2] && edx == v[1])
    return 1;
#endif

  return 0;
}

static inline int
clib_cpu_is_intel ()
{
#ifdef __x86_64__
  const char vendor[13] = "GenuineIntel";
  u32u *v = (u32u *) vendor;
  u32 eax, ebx, ecx, edx;

  if (clib_get_cpuid (0, &eax, &ebx, &ecx, &edx) == 0)
    return 0;

  if (ebx == v[0] && ecx == v[2] && edx == v[1])
    return 1;
#endif

  return 0;
}

static inline int
clib_cpu_march_priority_x86_64_v4 ()
{
  if (clib_cpu_supports_avx512f () && clib_cpu_supports_avx512bw () &&
      clib_cpu_supports_avx512dq () && clib_cpu_supports_avx512vl () &&
      clib_cpu_supports_avx512cd ())
    return 95;
  return -1;
}

static inline int
clib_cpu_march_priority_x86_64_v3 ()
{
  if (clib_cpu_supports_avx2 () && clib_cpu_supports_bmi2 () && clib_cpu_supports_fma () &&
      clib_cpu_supports_bmi1 () && clib_cpu_supports_movbe () && clib_cpu_supports_lzcnt () &&
      clib_cpu_supports_osxsave ())
    return 45;
  return -1;
}

static inline int
clib_cpu_march_priority_scalar ()
{
  return 1;
}

#define X86_CPU_ARCH_PERF_FUNC 0xA

static inline int
clib_get_pmu_counter_count (u8 *fixed, u8 *general)
{
#if defined(__x86_64__)
  u32 __clib_unused eax = 0, ebx = 0, ecx = 0, edx = 0;
  clib_get_cpuid (X86_CPU_ARCH_PERF_FUNC, &eax, &ebx, &ecx, &edx);

  *general = (eax & 0xFF00) >> 8;
  *fixed = (edx & 0xF);

  return 1;
#else
  return 0;
#endif
}

typedef struct
{
  struct
  {
    u8 implementer;
    u16 part_num;
  } aarch64;
} clib_cpu_info_t;

const clib_cpu_info_t *clib_get_cpu_info ();

/* ARM */
#define AARCH64_CPU_IMPLEMENTER_ARM 0x41
#define AARCH64_CPU_PART_CORTEXA72  0xd08
#define AARCH64_CPU_PART_NEOVERSEN1 0xd0c
#define AARCH64_CPU_PART_NEOVERSEN2 0xd49
#define AARCH64_CPU_PART_NEOVERSEV2 0xd4f

/*cavium */
#define AARCH64_CPU_IMPLEMENTER_CAVIUM      0x43
#define AARCH64_CPU_PART_THUNDERX2          0x0af
#define AARCH64_CPU_PART_OCTEONTX2T96       0x0b2
#define AARCH64_CPU_PART_OCTEONTX2T98       0x0b1

/* Qualcomm */
#define AARCH64_CPU_IMPLEMENTER_QUALCOMM    0x51
#define AARCH64_CPU_PART_QDF24XX            0xc00

static inline int
clib_cpu_march_priority_octeontx2 ()
{
  const clib_cpu_info_t *info = clib_get_cpu_info ();

  if (!info || info->aarch64.implementer != AARCH64_CPU_IMPLEMENTER_CAVIUM)
    return -1;

  if (info->aarch64.part_num == AARCH64_CPU_PART_OCTEONTX2T96 ||
      info->aarch64.part_num == AARCH64_CPU_PART_OCTEONTX2T98)
    return 20;

  return -1;
}

static inline int
clib_cpu_march_priority_thunderx2t99 ()
{
  const clib_cpu_info_t *info = clib_get_cpu_info ();

  if (!info || info->aarch64.implementer != AARCH64_CPU_IMPLEMENTER_CAVIUM)
    return -1;

  if (info->aarch64.part_num == AARCH64_CPU_PART_THUNDERX2)
    return 20;

  return -1;
}

static inline int
clib_cpu_march_priority_qdf24xx ()
{
  const clib_cpu_info_t *info = clib_get_cpu_info ();

  if (!info || info->aarch64.implementer != AARCH64_CPU_IMPLEMENTER_QUALCOMM)
    return -1;

  if (info->aarch64.part_num == AARCH64_CPU_PART_QDF24XX)
    return 20;

  return -1;
}

static inline int
clib_cpu_march_priority_cortexa72 ()
{
  const clib_cpu_info_t *info = clib_get_cpu_info ();

  if (!info || info->aarch64.implementer != AARCH64_CPU_IMPLEMENTER_ARM)
    return -1;

  if (info->aarch64.part_num == AARCH64_CPU_PART_CORTEXA72)
    return 10;

  return -1;
}

static inline int
clib_cpu_march_priority_neoversen1 ()
{
  const clib_cpu_info_t *info = clib_get_cpu_info ();

  if (!info || info->aarch64.implementer != AARCH64_CPU_IMPLEMENTER_ARM)
    return -1;

  if (info->aarch64.part_num == AARCH64_CPU_PART_NEOVERSEN1)
    return 10;

  return -1;
}

static inline int
clib_cpu_march_priority_neoversen2 ()
{
  const clib_cpu_info_t *info = clib_get_cpu_info ();

  if (!info || info->aarch64.implementer != AARCH64_CPU_IMPLEMENTER_ARM)
    return -1;

  if (info->aarch64.part_num == AARCH64_CPU_PART_NEOVERSEN2)
    return 10;

  return -1;
}

static inline int
clib_cpu_march_priority_neoversev2 ()
{
  const clib_cpu_info_t *info = clib_get_cpu_info ();

  if (!info || info->aarch64.implementer != AARCH64_CPU_IMPLEMENTER_ARM)
    return -1;

  if (info->aarch64.part_num == AARCH64_CPU_PART_NEOVERSEV2)
    return 10;

  return -1;
}

#ifdef CLIB_MARCH_VARIANT
#define CLIB_MARCH_FN_PRIORITY() CLIB_MARCH_SFX(clib_cpu_march_priority)()
#else
#define CLIB_MARCH_FN_PRIORITY() 0
#endif
#endif /* included_clib_cpu_h */

#define CLIB_MARCH_FN_CONSTRUCTOR(fn)					\
static void __clib_constructor 						\
CLIB_MARCH_SFX(fn ## _march_constructor) (void)				\
{									\
  if (CLIB_MARCH_FN_PRIORITY() > fn ## _selected_priority)		\
    {									\
      fn ## _selected = & CLIB_MARCH_SFX (fn ## _ma);			\
      fn ## _selected_priority = CLIB_MARCH_FN_PRIORITY();		\
    }									\
}									\

#ifndef CLIB_MARCH_VARIANT
#define CLIB_MARCH_FN(fn, rtype, _args...)                                    \
  static rtype CLIB_MARCH_SFX (fn##_ma) (_args);                              \
  rtype (*fn##_selected) (_args) = &CLIB_MARCH_SFX (fn##_ma);                 \
  int fn##_selected_priority = 0;                                             \
  static inline rtype CLIB_MARCH_SFX (fn##_ma) (_args)
#else
#define CLIB_MARCH_FN(fn, rtype, _args...)                                    \
  static rtype CLIB_MARCH_SFX (fn##_ma) (_args);                              \
  extern rtype (*fn##_selected) (_args);                                      \
  extern int fn##_selected_priority;                                          \
  CLIB_MARCH_FN_CONSTRUCTOR (fn)                                              \
  static rtype CLIB_MARCH_SFX (fn##_ma) (_args)
#endif

#define CLIB_MARCH_FN_SELECT(fn) (* fn ## _selected)

format_function_t format_cpu_uarch;
format_function_t format_cpu_model_name;
format_function_t format_cpu_flags;
format_function_t format_march_variant;
