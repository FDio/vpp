/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus
 */

#ifndef included_error_bootstrap_h
#define included_error_bootstrap_h

/* Bootstrap include so that #include <vppinfra/mem.h> can include e.g.
   <vppinfra/mheap.h> which depends on <vppinfra/vec.h>. */

#include <vppinfra/clib.h>	/* for uword */

enum
{
  CLIB_ERROR_FATAL = 1 << 0,
  CLIB_ERROR_ABORT = 1 << 1,
  CLIB_ERROR_WARNING = 1 << 2,
  CLIB_ERROR_ERRNO_VALID = 1 << 16,
  CLIB_ERROR_NO_RATE_LIMIT = 1 << 17,
};

/* Current function name.  Need (char *) cast to silence gcc4 pointer signedness warning. */
#define clib_error_function ((char *) __func__)

#ifndef CLIB_ASSERT_ENABLE
#define CLIB_ASSERT_ENABLE (CLIB_DEBUG > 0)
#endif

/* Low level error reporting function.
   Code specifies whether to call exit, abort or nothing at
   all (for non-fatal warnings). */
extern void _clib_error (int code, const char *function_name,
			 uword line_number, const char *format, ...);

#define ASSERT(truth)					\
do {							\
  if (CLIB_ASSERT_ENABLE && ! (truth))			\
    {							\
      _clib_error (CLIB_ERROR_ABORT, 0, 0,		\
		   "%s:%d (%s) assertion `%s' fails",	\
		   __FILE__,				\
		   (uword) __LINE__,			\
		   clib_error_function,			\
		   # truth);				\
    }							\
} while (0)

/*
 * This version always generates code, and has a Coverity-specific
 * version to stop Coverity complaining about
 * ALWAYS_ASSERT(p != 0); p->member...
 */

#ifndef __COVERITY__
#define ALWAYS_ASSERT(truth)				\
do {							\
  if (PREDICT_FALSE(!(truth)))                          \
    {							\
      _clib_error (CLIB_ERROR_ABORT, 0, 0,		\
		   "%s:%d (%s) assertion `%s' fails",	\
		   __FILE__,				\
		   (uword) __LINE__,			\
		   clib_error_function,			\
		   # truth);				\
    }							\
} while (0)
#else /* __COVERITY__ */
#define ALWAYS_ASSERT(truth)                    \
do {                                            \
  if (PREDICT_FALSE(!(truth)))                  \
    {                                           \
      abort();                                  \
    }                                           \
} while (0)
#endif /* __COVERITY */

#define STATIC_ASSERT(truth,...) _Static_assert(truth, __VA_ARGS__)

#define STATIC_ASSERT_SIZEOF(d, s) \
  STATIC_ASSERT (sizeof (d) == s, "Size of " #d " must be " # s " bytes")

#define STATIC_ASSERT_SIZEOF_ELT(d, e, s) \
  STATIC_ASSERT (sizeof (((d *)0)->e) == s, "Size of " #d "." #e " must be " # s " bytes")

#define STATIC_ASSERT_OFFSET_OF(s, e, o) \
  STATIC_ASSERT (STRUCT_OFFSET_OF(s,e) == o, "Offset of " #s "." #e " must be " # o)

#define STATIC_ASSERT_FITS_IN(s, e, o) \
  STATIC_ASSERT (STRUCT_OFFSET_OF(s,e) <= (o - sizeof(((s *)0)->e)), \
  #s "." #e " does not fit into " # o " bytes")

/* Assert without allocating memory. */
#define ASSERT_AND_PANIC(truth)			\
do {						\
  if (CLIB_ASSERT_ENABLE && ! (truth))		\
    os_panic ();				\
} while (0)

#endif /* included_error_bootstrap_h */
