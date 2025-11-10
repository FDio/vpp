/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/internal.h>

#include <stdarg.h>

#include <vppinfra/format.h>

void
vlua_log_set_callback (vlua_handle_t handle, vlua_log_callback_t cb)
{
  if (handle)
    handle->log_cb = cb;
}

void
vlua_log_message (vlua_handle_t handle, vlua_log_level_t level,
		  const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);

  if (handle && handle->log_cb)
    {
      va_list copy;
      va_copy (copy, va);
      handle->log_cb (handle, level, fmt, &copy);
      va_end (copy);
    }
  else
    {
      u8 *msg = va_format (0, fmt, &va);
      msg = format (msg, "%c", 0);
      clib_warning ("vlua[%u]: %s", level, msg ? (const char *) msg : "<log>");
      vec_free (msg);
    }

  va_end (va);
}
