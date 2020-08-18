/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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

/* *** Normally, it should not be necessary to edit this file. *** */

#ifndef __included_crypto_ecrypt_config_h__
#define __included_crypto_ecrypt_config_h__

/* ------------------------------------------------------------------------- */

/* Guess the endianness of the target architecture. */

/*
 * The LITTLE endian machines:
 */
#if defined(__ultrix)		/* Older MIPS */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(__alpha)		/* Alpha */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(i386)		/* x86 (gcc) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(__i386)		/* x86 (gcc) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(__x86_64)		/* x86_64 (gcc) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(_M_IX86)		/* x86 (MSC, Borland) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(_MSC_VER)		/* x86 (surely MSC) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(__INTEL_COMPILER)	/* x86 (surely Intel compiler icl.exe) */
#define ECRYPT_LITTLE_ENDIAN

/*
 * The BIG endian machines:
 */
#elif defined(__sparc)		/* Newer Sparc's */
#define ECRYPT_BIG_ENDIAN
#elif defined(__powerpc__)	/* PowerPC */
#define ECRYPT_BIG_ENDIAN
#elif defined(__ppc__)		/* PowerPC */
#define ECRYPT_BIG_ENDIAN
#elif defined(__hppa)		/* HP-PA */
#define ECRYPT_BIG_ENDIAN

/*
 * Finally machines with UNKNOWN endianness:
 */
#elif defined (_AIX)		/* RS6000 */
#define ECRYPT_UNKNOWN
#elif defined(__aux)		/* 68K */
#define ECRYPT_UNKNOWN
#elif defined(__dgux)		/* 88K (but P6 in latest boxes) */
#define ECRYPT_UNKNOWN
#elif defined(__sgi)		/* Newer MIPS */
#define ECRYPT_UNKNOWN
#else /* Any other processor */
#define ECRYPT_UNKNOWN
#endif

/* ------------------------------------------------------------------------- */

/*
 * Find minimal-width types to store 8-bit, 16-bit, 32-bit, and 64-bit
 * integers.
 *
 * Note: to enable 64-bit types on 32-bit compilers, it might be
 * necessary to switch from ISO C90 mode to ISO C99 mode (e.g., gcc
 * -std=c99), or to allow compiler-specific extensions.
 */

#include <limits.h>

/* --- check char --- */

#if (UCHAR_MAX / 0xFU > 0xFU)
#ifndef I8T
#define I8T char
#define U8C(v) (v##U)

#if (UCHAR_MAX == 0xFFU)
#define ECRYPT_I8T_IS_BYTE
#endif

#endif

#if (UCHAR_MAX / 0xFFU > 0xFFU)
#ifndef I16T
#define I16T char
#define U16C(v) (v##U)
#endif

#if (UCHAR_MAX / 0xFFFFU > 0xFFFFU)
#ifndef I32T
#define I32T char
#define U32C(v) (v##U)
#endif

#if (UCHAR_MAX / 0xFFFFFFFFU > 0xFFFFFFFFU)
#ifndef I64T
#define I64T char
#define U64C(v) (v##U)
#define ECRYPT_NATIVE64
#endif

#endif
#endif
#endif
#endif

/* --- check short --- */

#if (USHRT_MAX / 0xFU > 0xFU)
#ifndef I8T
#define I8T short
#define U8C(v) (v##U)

#if (USHRT_MAX == 0xFFU)
#define ECRYPT_I8T_IS_BYTE
#endif

#endif

#if (USHRT_MAX / 0xFFU > 0xFFU)
#ifndef I16T
#define I16T short
#define U16C(v) (v##U)
#endif

#if (USHRT_MAX / 0xFFFFU > 0xFFFFU)
#ifndef I32T
#define I32T short
#define U32C(v) (v##U)
#endif

#if (USHRT_MAX / 0xFFFFFFFFU > 0xFFFFFFFFU)
#ifndef I64T
#define I64T short
#define U64C(v) (v##U)
#define ECRYPT_NATIVE64
#endif

#endif
#endif
#endif
#endif

/* --- check int --- */

#if (UINT_MAX / 0xFU > 0xFU)
#ifndef I8T
#define I8T int
#define U8C(v) (v##U)

#if (ULONG_MAX == 0xFFU)
#define ECRYPT_I8T_IS_BYTE
#endif

#endif

#if (UINT_MAX / 0xFFU > 0xFFU)
#ifndef I16T
#define I16T int
#define U16C(v) (v##U)
#endif

#if (UINT_MAX / 0xFFFFU > 0xFFFFU)
#ifndef I32T
#define I32T int
#define U32C(v) (v##U)
#endif

#if (UINT_MAX / 0xFFFFFFFFU > 0xFFFFFFFFU)
#ifndef I64T
#define I64T int
#define U64C(v) (v##U)
#define ECRYPT_NATIVE64
#endif

#endif
#endif
#endif
#endif

/* --- check long --- */

#if (ULONG_MAX / 0xFUL > 0xFUL)
#ifndef I8T
#define I8T long
#define U8C(v) (v##UL)

#if (ULONG_MAX == 0xFFUL)
#define ECRYPT_I8T_IS_BYTE
#endif

#endif

#if (ULONG_MAX / 0xFFUL > 0xFFUL)
#ifndef I16T
#define I16T long
#define U16C(v) (v##UL)
#endif

#if (ULONG_MAX / 0xFFFFUL > 0xFFFFUL)
#ifndef I32T
#define I32T long
#define U32C(v) (v##UL)
#endif

#if (ULONG_MAX / 0xFFFFFFFFUL > 0xFFFFFFFFUL)
#ifndef I64T
#define I64T long
#define U64C(v) (v##UL)
#define ECRYPT_NATIVE64
#endif

#endif
#endif
#endif
#endif

/* --- check long long --- */

#ifdef ULLONG_MAX

#if (ULLONG_MAX / 0xFULL > 0xFULL)
#ifndef I8T
#define I8T long long
#define U8C(v) (v##ULL)

#if (ULLONG_MAX == 0xFFULL)
#define ECRYPT_I8T_IS_BYTE
#endif

#endif

#if (ULLONG_MAX / 0xFFULL > 0xFFULL)
#ifndef I16T
#define I16T long long
#define U16C(v) (v##ULL)
#endif

#if (ULLONG_MAX / 0xFFFFULL > 0xFFFFULL)
#ifndef I32T
#define I32T long long
#define U32C(v) (v##ULL)
#endif

#if (ULLONG_MAX / 0xFFFFFFFFULL > 0xFFFFFFFFULL)
#ifndef I64T
#define I64T long long
#define U64C(v) (v##ULL)
#endif

#endif
#endif
#endif
#endif

#endif

/* --- check __int64 --- */

#if !defined(__STDC__) && defined(_UI64_MAX)

#ifndef I64T
#define I64T __int64
#define U64C(v) (v##ui64)
#endif

#endif

/* --- if platform doesn't announce anything, use most common choices --- */

#ifndef I8T
#define I8T char
#define U8C(v) (v##U)
#endif
#ifndef I16T
#define I16T short
#define U16C(v) (v##U)
#endif
#ifndef I32T
#define I32T int
#define U32C(v) (v##U)
#endif
#ifndef I64T
#define I64T long long
#define U64C(v) (v##ULL)
#endif

/* ------------------------------------------------------------------------- */

/* find the largest type on this platform (used for alignment) */

#if defined(__SSE__) || (defined(_MSC_VER) && (_MSC_VER >= 1300))

#include <xmmintrin.h>
#define MAXT __m128

#elif defined(__MMX__)

#include <mmintrin.h>
#define MAXT __m64

#elif defined(__ALTIVEC__)

#define MAXT __vector int

#else

#define MAXT long

#endif

/* ------------------------------------------------------------------------- */

#endif //__included_crypto_ecrypt_config_h__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
