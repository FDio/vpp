/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/internal.h>

#include <vppinfra/vec.h>
#include <vppinfra/format.h>

u8 *
vlua_format_table_path (u8 *s, va_list *args)
{
  vlua_table_handle_t th = va_arg (*args, vlua_table_handle_t);
  vlua_table_handle_t *stack = 0;
  u8 *path = 0;

  if (th == 0)
    return format (s, "%s", "<table>");

  for (vlua_table_handle_t current = th; current; current = current->parent)
    vec_add1 (stack, current);

  for (int i = vec_len (stack) - 1; i >= 0; --i)
    {
      vlua_table_handle_t node = stack[i];
      if (node == 0 || node->name == 0 || node->name[0] == 0)
	continue;

      if (vec_len (path))
	path = format (path, "%c", '.');

      path = format (path, "%s", node->name);
    }

  if (vec_len (path) == 0)
    path = format (path, "%s", "<table>");

  s = format (s, "%v", path);
  vec_free (path);
  vec_free (stack);
  return s;
}
