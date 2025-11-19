/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/internal.h>

#include <stdarg.h>

#include <vppinfra/format.h>

static void
vlua_log_message_va (vlua_handle_t h, vlua_log_level_t level, const char *fmt,
		     va_list *va)
{
  if (h && h->log_cb)
    {
      va_list copy;
      va_copy (copy, *va);
      h->log_cb (h, level, fmt, &copy);
      va_end (copy);
    }
  else
    {
      u8 *msg = va_format (0, fmt, va);
      msg = format (msg, "%c", 0);
      clib_warning ("vlua[%u]: %s", level, msg ? (const char *) msg : "<log>");
      vec_free (msg);
    }
}

__clib_export void
vlua_log_message (vlua_handle_t h, vlua_log_level_t level, const char *fmt,
		  ...)
{
  va_list va;
  va_start (va, fmt);
  vlua_log_message_va (h, level, fmt, &va);
  va_end (va);
}

__clib_export void
vlua_log_debug (vlua_handle_t h, const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  vlua_log_message_va (h, VLUA_LOG_LEVEL_DEBUG, fmt, &va);
  va_end (va);
}

__clib_export void
vlua_log_info (vlua_handle_t h, const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  vlua_log_message_va (h, VLUA_LOG_LEVEL_INFO, fmt, &va);
  va_end (va);
}

__clib_export void
vlua_log_warn (vlua_handle_t h, const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  vlua_log_message_va (h, VLUA_LOG_LEVEL_WARN, fmt, &va);
  va_end (va);
}

__clib_export void
vlua_log_err (vlua_handle_t h, const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  vlua_log_message_va (h, VLUA_LOG_LEVEL_ERR, fmt, &va);
  va_end (va);
}
