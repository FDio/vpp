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

typedef struct
{
  unw_cursor_t cursor;
  unw_context_t context;
} libunwind_data_t;

STATIC_ASSERT (sizeof (libunwind_data_t) <
		 sizeof (((clib_stack_frame_t *) 0)->private_data),
	       "clib_stack_frame_t private_data size must be increased");
STATIC_ASSERT (__alignof__(libunwind_data_t) <=
		 __alignof__(((clib_stack_frame_t *) 0)->private_data),
	       "clib_stack_frame_t private_data alignment must be increased");

#endif

__clib_export clib_stack_frame_t *
clib_stack_frame_get (clib_stack_frame_t *sf)
{
#if HAVE_LIBUNWIND == 1
  Dl_info info = {};
  libunwind_data_t *ud = (libunwind_data_t *) sf->private_data;

  if (sf->index == 0)
    {
      if (unw_getcontext (&ud->context) < 0)
	{
	  clib_warning ("libunwind: cannot get local machine state\n");
	  return 0;
	}
      if (unw_init_local (&ud->cursor, &ud->context) < 0)
	{
	  clib_warning (
	    "libunwind: cannot initialize cursor for local unwinding\n");
	  return 0;
	}
      if (unw_step (&ud->cursor) < 1)
	return 0;
    }
  else if (unw_step (&ud->cursor) < 1)
    return 0;

  if (unw_get_reg (&ud->cursor, UNW_REG_IP, &sf->pc))
    {
      clib_warning ("libunwind: cannot read IP\n");
      return 0;
    }

  if (unw_get_proc_name (&ud->cursor, sf->name, sizeof (sf->name),
			 &sf->offset) < 0)
    sf->name[0] = sf->offset = 0;

  sf->is_signal_frame = unw_is_signal_frame (&ud->cursor) ? 1 : 0;

  if (dladdr ((void *) sf->pc, &info))
    sf->file_name = info.dli_fname;
  else
    sf->file_name = 0;

  sf->index++;
  return sf;
#else
  return 0;
#endif
}
