/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#define _GNU_SOURCE
#include <dlfcn.h>

#include <vppinfra/clib.h>
#include <vppinfra/stack.h>
#include <vppinfra/error.h>

#if HAVE_LIBUNWIND == 1

#define UNW_LOCAL_ONLY
#include <libunwind.h>

static __thread unw_cursor_t cursor;
static __thread unw_context_t context;

#endif /* HAVE_LIBUNWIND */

__clib_export int
clib_stack_frame_get_raw (void **sf, int n, int skip)
{
#if HAVE_LIBUNWIND == 1
  void *sf__[20];
  int n__;

  /* Also skip current frame. */
  skip++;
  n__ = unw_backtrace (sf__, clib_min (ARRAY_LEN (sf__), n + skip));

  if (n__ <= skip)
    return 0;
  else if (n__ - skip < n)
    n = n__ - skip;

  clib_memcpy_fast (&sf[0], &sf__[skip], n * sizeof (sf[0]));
  return n;
#else  /* HAVE_LIBUNWIND */
  return 0;
#endif /* HAVE_LIBUNWIND */
}

__clib_export clib_stack_frame_t *
clib_stack_frame_get (clib_stack_frame_t *sf)
{
#if HAVE_LIBUNWIND == 1
  Dl_info info = {};

  if (sf->index == 0)
    {
      if (unw_getcontext (&context) < 0)
	{
	  clib_warning ("libunwind: cannot get local machine state\n");
	  return 0;
	}
      if (unw_init_local (&cursor, &context) < 0)
	{
	  clib_warning (
	    "libunwind: cannot initialize cursor for local unwinding\n");
	  return 0;
	}
      if (unw_step (&cursor) < 1)
	return 0;
    }
  else if (unw_step (&cursor) < 1)
    return 0;

  if (unw_get_reg (&cursor, UNW_REG_IP, &sf->ip))
    {
      clib_warning ("libunwind: cannot read IP\n");
      return 0;
    }

  if (unw_get_reg (&cursor, UNW_REG_SP, &sf->sp))
    {
      clib_warning ("libunwind: cannot read SP\n");
      return 0;
    }

  int r = unw_get_proc_name (&cursor, sf->name, sizeof (sf->name), &sf->offset);
  if (r == -UNW_ENOMEM)
    memcpy (sf->name + sizeof (sf->name) - 4, "...", 4);
  else if (r < 0)
    sf->name[0] = sf->offset = 0;

  sf->is_signal_frame = unw_is_signal_frame (&cursor) ? 1 : 0;

  if (dladdr ((void *) sf->ip, &info))
    sf->file_name = info.dli_fname;
  else
    sf->file_name = 0;

  sf->index++;
  return sf;
#else
  return 0;
#endif
}
