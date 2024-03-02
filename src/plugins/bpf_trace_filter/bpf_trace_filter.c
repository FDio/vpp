/*
 *------------------------------------------------------------------
 * Copyright (c) 2023 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <bpf_trace_filter/bpf_trace_filter.h>

clib_error_t *
bpf_trace_filter_init (vlib_main_t *vm)
{
  bpf_trace_filter_main_t *btm = &bpf_trace_filter_main;
  btm->pcap = pcap_open_dead (DLT_EN10MB, 65535);

  return 0;
}

int vnet_is_packet_traced (vlib_buffer_t *b, u32 classify_table_index,
			   int func);

u8 *
format_bpf_trace_filter (u8 *s, va_list *a)
{
  bpf_trace_filter_main_t *btm = va_arg (*a, bpf_trace_filter_main_t *);
  struct bpf_insn *insn;

  if (!btm->prog_set)
    return format (s, "bpf trace filter is not set");

  insn = btm->prog.bf_insns;
  for (int i = 0; i < btm->prog.bf_len; insn++, i++)
    s = format (s, "%s\n", bpf_image (insn, i));

  return s;
}

clib_error_t *
bpf_trace_filter_set_unset (const char *bpf_expr, u8 is_del, u8 optimize)
{
  bpf_trace_filter_main_t *btm = &bpf_trace_filter_main;
  if (is_del)
    {
      if (btm->prog_set)
	{
	  btm->prog_set = 0;
	  pcap_freecode (&btm->prog);
	}
    }
  else if (bpf_expr)
    {
      if (btm->prog_set)
	pcap_freecode (&btm->prog);
      btm->prog_set = 0;
      if (pcap_compile (btm->pcap, &btm->prog, (char *) bpf_expr, optimize,
			PCAP_NETMASK_UNKNOWN))
	{
	  return clib_error_return (0, "Failed pcap_compile of %s", bpf_expr);
	}
      btm->prog_set = 1;
    }
  return 0;
};

int
bpf_is_packet_traced (vlib_buffer_t *b, u32 classify_table_index, int func)
{
  bpf_trace_filter_main_t *bfm = &bpf_trace_filter_main;
  struct pcap_pkthdr phdr = { 0 };
  int res;
  int res1;

  if (classify_table_index != ~0 &&
      (res1 = vnet_is_packet_traced (b, classify_table_index, 0)) != 1)
    return res1;

  if (!bfm->prog_set)
    return 1;

  phdr.caplen = b->current_length;
  phdr.len = b->current_length;
  res = pcap_offline_filter (&bfm->prog, &phdr, vlib_buffer_get_current (b));
  return res != 0;
}

VLIB_REGISTER_TRACE_FILTER_FUNCTION (bpf_trace_filter_fn, static) = {
  .name = "bpf_trace_filter",
  .description = "bpf based trace filter",
  .priority = 10,
  .function = bpf_is_packet_traced
};

VLIB_INIT_FUNCTION (bpf_trace_filter_init);
bpf_trace_filter_main_t bpf_trace_filter_main;
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
