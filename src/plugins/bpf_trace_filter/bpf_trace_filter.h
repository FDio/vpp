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

#ifndef _BPF_TRACE_FILTER_H_
#define _BPF_TRACE_FILTER_H_
#include <vlib/vlib.h>
#include <pcap.h>
typedef struct
{
  pcap_t *pcap;
  u16 msg_id_base;
  u8 prog_set;
  struct bpf_program prog;
} bpf_trace_filter_main_t;

extern bpf_trace_filter_main_t bpf_trace_filter_main;
clib_error_t *bpf_trace_filter_set_unset (const char *bpf_expr, u8 is_del,
					  u8 optimize);
u8 *format_bpf_trace_filter (u8 *s, va_list *a);
#endif /* _BPF_TRACE_FILTER_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */