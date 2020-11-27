/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 */

#include <vnet/vnet.h>
#include <perfmon/perfmon.h>
#include <perfmon/ia32_core/ia32_core.h>

static u8 *
format_ipc_header (u8 * s, va_list * args)
{
  __clib_unused perfmon_bundle_t *b = va_arg (*args, perfmon_bundle_t *);
  s = format (s, "%10s", "pkt/call");
  s = format (s, "%10s", "IPC");
  s = format (s, "%10s", "clk/pkt");
  s = format (s, "%10s", "inst/pkt");
  return s;
}

static u8 *
format_ipc_node (u8 * s, va_list * args)
{
  __clib_unused perfmon_bundle_t *b = va_arg (*args, perfmon_bundle_t *);
  perfmon_node_counters_t *nc = va_arg (*args, perfmon_node_counters_t *);
  s = format (s, "%10.2f", (f64) nc->n_packets / nc->n_calls);
  s = format (s, "%10.2f", (f64) nc->event_ctr[0] / nc->event_ctr[1]);
  s = format (s, "%10.2f", (f64) nc->event_ctr[1] / nc->n_packets);
  s = format (s, "%10.2f", (f64) nc->event_ctr[0] / nc->n_packets);
  return s;
}

PERFMON2_REGISTER_BUNDLE (ipc) = {
  .name = "ipc",
  .description = "instructions/packet, cycles/packet and IPC",
  .source = "intel-ia32-core",
  .type = PERFMON2_BUNDLE_TYPE_NODE,
  .events[0] = IA32_CORE_E_INST_RETIRED_ANY_P,
  .events[1] = IA32_CORE_E_CPU_CLK_UNHALTED_THREAD_P,
  .events[2] = IA32_CORE_E_CPU_CLK_UNHALTED_REF_TSC,
  .n_events = 3,
  .format_header = format_ipc_header,
  .format_node = format_ipc_node,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
