/*
 * Copyright (c) 2020 Intel and/or its affiliates.
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
#include <perfmon/perf_events.h>

#define foreach_perf_sw_counter                                               \
  _ (CPU_CLOCK, "cpu-clocks")                                                 \
  _ (TASK_CLOCK, "task-clocks")                                               \
  _ (PAGE_FAULTS, "page-faults")                                              \
  _ (CONTEXT_SWITCHES, "context-switches")                                    \
  _ (CPU_MIGRATIONS, "cpu_migrations")                                        \
  _ (PAGE_FAULTS_MIN, "page-faults-min")                                      \
  _ (PAGE_FAULTS_MAJ, "page-faults-maj")                                      \
  _ (ALIGNMENT_FAULTS, "alignment-faults")                                    \
  _ (EMULATION_FAULTS, "emulation-faults")                                    \
  _ (DUMMY, "dummy")                                                          \
  _ (BPF_OUTPUT, "bdf-output")

typedef enum
{
#define _(n, s) n,
  foreach_perf_sw_counter
#undef _
} linux_sw_events;

static perf_event_t linux_events[] = {
#define _(n, s)                                                               \
  {                                                                           \
    .source_name = "software",                                                \
    .source = PERF_SOURCE_SOFTWARE,                                           \
    .config = PERF_COUNT_SW_##n,                                              \
    .name = s,                                                                \
    .description = s,                                                         \
  },
  foreach_perf_sw_counter
#undef _
};

PERF_REGISTER_EVENTS (kernel) = {
  .name = "linux",
  .events = linux_events,
  .n_events = ARRAY_LEN (linux_events),
};
