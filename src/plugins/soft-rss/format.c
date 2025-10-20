/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <soft-rss/soft_rss.h>
#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/vec.h>
#include <vnet/interface.h>

u8 *
format_soft_rss_if (u8 *s, va_list *args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  u32 sw_if_index = va_arg (*args, u32);
  const soft_rss_rt_data_t *rt = va_arg (*args, const soft_rss_rt_data_t *);
  u32 table_size = ((u32) rt->reta_mask) + 1;
  clib_thread_index_t threads[ARRAY_LEN (rt->reta)];
  u32 n_threads = 0;

  if (table_size > ARRAY_LEN (rt->reta))
    table_size = ARRAY_LEN (rt->reta);

  for (u32 i = 0; i < table_size; i++)
    {
      clib_thread_index_t thread = rt->reta[i];
      u32 j;

      for (j = 0; j < n_threads; j++)
	if (threads[j] == thread)
	  break;

      if (j == n_threads)
	threads[n_threads++] = thread;
    }

  u8 *thread_str = 0;
  for (u32 i = 0; i < n_threads; i++)
    thread_str = format (thread_str, "%s%u", i ? " " : "", threads[i]);

  s = format (s, "%U:\n", format_vnet_sw_if_index_name, vnm, sw_if_index);
  s = format (s, "  status: %s\n", rt->enabled ? "enabled" : "disabled");
  s = format (s, "  match-offset: %u\n", rt->match_offset);
  s = format (s, "  reta size: %u\n", table_size);
  if (thread_str)
    s = format (s, "  threads: %v\n", thread_str);
  else
    s = format (s, "  threads: (none)\n");
  s = format (s, "  reta:\n%U", format_hexdump_u16, rt->reta, table_size);

  vec_free (thread_str);
  return s;
}

u8 *
format_soft_rss_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  soft_rss_trace_t *t = va_arg (*args, soft_rss_trace_t *);

  s = format (s, "soft-rss: sw_if_index %u, next %u", t->sw_if_index,
	      t->next_index);
  return s;
}
