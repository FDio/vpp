/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

u8 *
format_vlib_stats_symlink (u8 *s, va_list *args)
{
  u8 *input = va_arg (*args, u8 *);

  for (int i = 0; i < vec_len (input); i++)
    if (input[i] == '/')
      vec_add1 (s, '_');
    else
      vec_add1 (s, input[i]);

  return s;
}
