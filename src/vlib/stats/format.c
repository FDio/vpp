/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

u8 *
format_vlib_stats_symlink (u8 *s, va_list *args)
{
  char *input = va_arg (*args, char *);
  char *modified_input = vec_dup (input);
  int i;
  u8 *result;

  for (i = 0; i < strlen (modified_input); i++)
    if (modified_input[i] == '/')
      modified_input[i] = '_';

  result = format (s, "%s", modified_input);
  vec_free (modified_input);
  return result;
}
