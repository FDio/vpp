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

#define foreach_aarch64_flags                                                                      \
  _ (fp, AT_HWCAP, 0)                                                                              \
  _ (asimd, AT_HWCAP, 1)                                                                           \
  _ (evtstrm, AT_HWCAP, 2)                                                                         \
  _ (aarch64_aes, AT_HWCAP, 3)                                                                     \
  _ (pmull, AT_HWCAP, 4)                                                                           \
  _ (sha1, AT_HWCAP, 5)                                                                            \
  _ (sha2, AT_HWCAP, 6)                                                                            \
  _ (crc32, AT_HWCAP, 7)                                                                           \
  _ (atomics, AT_HWCAP, 8)                                                                         \
  _ (fphp, AT_HWCAP, 9)                                                                            \
  _ (asimdhp, AT_HWCAP, 10)                                                                        \
  _ (cpuid, AT_HWCAP, 11)                                                                          \
  _ (asimdrdm, AT_HWCAP, 12)                                                                       \
  _ (jscvt, AT_HWCAP, 13)                                                                          \
  _ (fcma, AT_HWCAP, 14)                                                                           \
  _ (lrcpc, AT_HWCAP, 15)                                                                          \
  _ (dcpop, AT_HWCAP, 16)                                                                          \
  _ (sha3, AT_HWCAP, 17)                                                                           \
  _ (sm3, AT_HWCAP, 18)                                                                            \
  _ (sm4, AT_HWCAP, 19)                                                                            \
  _ (asimddp, AT_HWCAP, 20)                                                                        \
  _ (sha512, AT_HWCAP, 21)                                                                         \
  _ (sve, AT_HWCAP, 22)                                                                            \
  _ (asimdfhm, AT_HWCAP, 23)                                                                       \
  _ (dit, AT_HWCAP, 24)                                                                            \
  _ (uscat, AT_HWCAP, 25)                                                                          \
  _ (ilrcpc, AT_HWCAP, 26)                                                                         \
  _ (flagm, AT_HWCAP, 27)                                                                          \
  _ (ssbs, AT_HWCAP, 28)                                                                           \
  _ (sb, AT_HWCAP, 29)                                                                             \
  _ (paca, AT_HWCAP, 30)                                                                           \
  _ (pacg, AT_HWCAP, 31)                                                                           \
  _ (gcs, AT_HWCAP, 32)                                                                            \
  _ (cmpbr, AT_HWCAP, 33)                                                                          \
  _ (fprcvt, AT_HWCAP, 34)                                                                         \
  _ (f8mm8, AT_HWCAP, 35)                                                                          \
  _ (f8mm4, AT_HWCAP, 36)                                                                          \
  _ (sve_f16mm, AT_HWCAP, 37)                                                                      \
  _ (sve_eltperm, AT_HWCAP, 38)                                                                    \
  _ (sve_aes2, AT_HWCAP, 39)                                                                       \
  _ (sve_bfscale, AT_HWCAP, 40)                                                                    \
  _ (sve2p2, AT_HWCAP, 41)                                                                         \
  _ (sme2p2, AT_HWCAP, 42)                                                                         \
  _ (sme_sbitperm, AT_HWCAP, 43)                                                                   \
  _ (sme_aes, AT_HWCAP, 44)                                                                        \
  _ (sme_sfexpa, AT_HWCAP, 45)                                                                     \
  _ (sme_stmop, AT_HWCAP, 46)                                                                      \
  _ (sme_smop4, AT_HWCAP, 47)                                                                      \
  _ (dcpodp, AT_HWCAP2, 0)                                                                         \
  _ (sve2, AT_HWCAP2, 1)                                                                           \
  _ (sveaes, AT_HWCAP2, 2)                                                                         \
  _ (svepmull, AT_HWCAP2, 3)                                                                       \
  _ (svebitperm, AT_HWCAP2, 4)                                                                     \
  _ (svesha3, AT_HWCAP2, 5)                                                                        \
  _ (svesm4, AT_HWCAP2, 6)                                                                         \
  _ (flagm2, AT_HWCAP2, 7)                                                                         \
  _ (frint, AT_HWCAP2, 8)                                                                          \
  _ (svei8mm, AT_HWCAP2, 9)                                                                        \
  _ (svef32mm, AT_HWCAP2, 10)                                                                      \
  _ (svef64mm, AT_HWCAP2, 11)                                                                      \
  _ (svebf16, AT_HWCAP2, 12)                                                                       \
  _ (i8mm, AT_HWCAP2, 13)                                                                          \
  _ (bf16, AT_HWCAP2, 14)                                                                          \
  _ (dgh, AT_HWCAP2, 15)                                                                           \
  _ (rng, AT_HWCAP2, 16)                                                                           \
  _ (bti, AT_HWCAP2, 17)                                                                           \
  _ (mte, AT_HWCAP2, 18)                                                                           \
  _ (ecv, AT_HWCAP2, 19)                                                                           \
  _ (afp, AT_HWCAP2, 20)                                                                           \
  _ (rpres, AT_HWCAP2, 21)                                                                         \
  _ (mte3, AT_HWCAP2, 22)                                                                          \
  _ (sme, AT_HWCAP2, 23)                                                                           \
  _ (sme_i16i64, AT_HWCAP2, 24)                                                                    \
  _ (sme_f64f64, AT_HWCAP2, 25)                                                                    \
  _ (sme_i8i32, AT_HWCAP2, 26)                                                                     \
  _ (sme_f16f32, AT_HWCAP2, 27)                                                                    \
  _ (sme_b16f32, AT_HWCAP2, 28)                                                                    \
  _ (sme_f32f32, AT_HWCAP2, 29)                                                                    \
  _ (sme_fa64, AT_HWCAP2, 30)                                                                      \
  _ (wfxt, AT_HWCAP2, 31)                                                                          \
  _ (ebf16, AT_HWCAP2, 32)                                                                         \
  _ (sve_ebf16, AT_HWCAP2, 33)                                                                     \
  _ (cssc, AT_HWCAP2, 34)                                                                          \
  _ (rprfm, AT_HWCAP2, 35)                                                                         \
  _ (sve2p1, AT_HWCAP2, 36)                                                                        \
  _ (sme2, AT_HWCAP2, 37)                                                                          \
  _ (sme2p1, AT_HWCAP2, 38)                                                                        \
  _ (sme_i16i32, AT_HWCAP2, 39)                                                                    \
  _ (sme_bi32i32, AT_HWCAP2, 40)                                                                   \
  _ (sme_b16b16, AT_HWCAP2, 41)                                                                    \
  _ (sme_f16f16, AT_HWCAP2, 42)                                                                    \
  _ (mops, AT_HWCAP2, 43)                                                                          \
  _ (hbc, AT_HWCAP2, 44)                                                                           \
  _ (sve_b16b16, AT_HWCAP2, 45)                                                                    \
  _ (lrcpc3, AT_HWCAP2, 46)                                                                        \
  _ (lse128, AT_HWCAP2, 47)                                                                        \
  _ (fpmr, AT_HWCAP2, 48)                                                                          \
  _ (lut, AT_HWCAP2, 49)                                                                           \
  _ (faminmax, AT_HWCAP2, 50)                                                                      \
  _ (f8cvt, AT_HWCAP2, 51)                                                                         \
  _ (f8fma, AT_HWCAP2, 52)                                                                         \
  _ (f8dp4, AT_HWCAP2, 53)                                                                         \
  _ (f8dp2, AT_HWCAP2, 54)                                                                         \
  _ (f8e4m3, AT_HWCAP2, 55)                                                                        \
  _ (f8e5m2, AT_HWCAP2, 56)                                                                        \
  _ (sme_lutv2, AT_HWCAP2, 57)                                                                     \
  _ (sme_f8f16, AT_HWCAP2, 58)                                                                     \
  _ (sme_f8f32, AT_HWCAP2, 59)                                                                     \
  _ (sme_sf8fma, AT_HWCAP2, 60)                                                                    \
  _ (sme_sf8dp4, AT_HWCAP2, 61)                                                                    \
  _ (sme_sf8dp2, AT_HWCAP2, 62)                                                                    \
  _ (poe, AT_HWCAP2, 63)

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
#define _(flag, hwcap_at, bit)                                                                     \
  static inline int clib_cpu_supports_##flag ()                                                    \
  {                                                                                                \
    unsigned long hwcap = getauxval (hwcap_at);                                                    \
    return (hwcap & (1UL << bit));                                                                 \
  }
  foreach_aarch64_flags
#undef _
#else /* ! __x86_64__ && !__aarch64__ */
#define _(flag, hwcap_at, bit)                                                                     \
  static inline int clib_cpu_supports_##flag ()                                                    \
  {                                                                                                \
    return 0;                                                                                      \
  }
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
