/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus
 */

#ifndef included_error_h
#define included_error_h

#include <vppinfra/clib.h>	/* for CLIB_LINUX_KERNEL */
#include <vppinfra/error_bootstrap.h>

#ifdef CLIB_UNIX
#include <errno.h>
#endif

#ifdef CLIB_LINUX_KERNEL
#include <linux/errno.h>
#endif

#include <stdarg.h>
#include <vppinfra/vec.h>

/* Callback functions for error reporting. */
typedef void clib_error_handler_func_t (void *arg, u8 * msg, int msg_len);
void clib_error_register_handler (clib_error_handler_func_t func, void *arg);

#define clib_warning(format,args...) \
  _clib_error (CLIB_ERROR_WARNING, clib_error_function, __LINE__, format, ## args)

#define clib_error(format,args...) \
  _clib_error (CLIB_ERROR_FATAL, clib_error_function, __LINE__, format, ## args)

#define clib_unix_error(format,args...) \
  _clib_error (CLIB_ERROR_FATAL | CLIB_ERROR_ERRNO_VALID, clib_error_function, __LINE__, format, ## args)

#define clib_unix_warning(format,args...) \
  _clib_error (CLIB_ERROR_WARNING | CLIB_ERROR_ERRNO_VALID, clib_error_function, __LINE__, format, ## args)

/* For programming errors and assert. */
#define clib_panic(format,args...) \
  _clib_error (CLIB_ERROR_ABORT, (char *) clib_error_function, __LINE__, format, ## args)

#include <vppinfra/clib_error.h>

#define clib_error_get_code(err) ((err) ? (err)->code : 0)
#define clib_error_set_code(err, c)		\
do {						\
  if (err)					\
    (err)->code = (c);				\
} while (0)

extern void *clib_error_free_vector (clib_error_t * errors);

#define clib_error_free(e) e = clib_error_free_vector(e)

extern clib_error_t *_clib_error_return (clib_error_t *errors, any code,
					 uword flags, const char *where,
					 const char *fmt, ...);

#define clib_error_return_code(e,code,flags,args...) \
  _clib_error_return((e),(code),(flags),(char *)clib_error_function,args)

#define clib_error_create(args...) \
  clib_error_return_code(0,0,0,args)

#define clib_error_return(e,args...) \
  clib_error_return_code(e,0,0,args)

#define clib_error_return_unix(e,args...) \
  clib_error_return_code(e,errno,CLIB_ERROR_ERRNO_VALID,args)

#define clib_error_return_fatal(e,args...) \
  clib_error_return_code(e,0,CLIB_ERROR_FATAL,args)

#define clib_error_return_unix_fatal(e,args...) \
  clib_error_return_code(e,errno,CLIB_ERROR_ERRNO_VALID|CLIB_ERROR_FATAL,args)

extern clib_error_t *_clib_error_report (clib_error_t * errors);

#define clib_error_report(e) do { (e) = _clib_error_report (e); } while (0)

u8 *format_clib_error (u8 * s, va_list * va);

always_inline word
unix_error_is_fatal (word error)
{
#ifdef CLIB_UNIX
  switch (error)
    {
    case EWOULDBLOCK:
    case EINTR:
      return 0;
    }
#endif
  return 1;
}

#define IF_ERROR_IS_FATAL_RETURN_ELSE_FREE(e)			\
do {								\
  if (e)							\
    {								\
      if (unix_error_is_fatal (clib_error_get_code (e)))	\
	return (e);						\
      else							\
	clib_error_free (e);					\
    }								\
} while (0)

#define ERROR_RETURN_IF(x)				\
do {							\
  clib_error_t * _error_return_if = (x);		\
  if (_error_return_if)					\
    return clib_error_return (_error_return_if, 0);	\
} while (0)

#define ERROR_ASSERT(truth)			\
({						\
  clib_error_t * _error_assert = 0;		\
  if (CLIB_DEBUG > 0 && ! (truth))		\
    {						\
      _error_assert = clib_error_return_fatal	\
        (0, "%s:%d (%s) assertion `%s' fails",	\
	 __FILE__,				\
	 (uword) __LINE__,			\
	 clib_error_function,			\
	 # truth);				\
    }						\
  _error_assert;				\
})

/* Assert to remain even if CLIB_DEBUG is set to 0. */
#define CLIB_ERROR_ASSERT(truth)		\
({						\
  clib_error_t * _error_assert = 0;		\
  if (! (truth))				\
    {						\
      _error_assert =				\
        clib_error_return_fatal			\
        (0, "%s:%d (%s) assertion `%s' fails",	\
         __FILE__,				\
	 (uword) __LINE__,			\
	 clib_error_function,			\
	 # truth);				\
    }						\
  _error_assert;				\
})

/*
 * If we're running under Coverity, don't die on
 * failed static assertions.
 */
#ifdef __COVERITY__
#ifndef _Static_assert
#define _Static_assert(x,y)
#endif
#endif

#endif /* included_error_h */
