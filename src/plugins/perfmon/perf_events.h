/*
 * Copyright (c) 2022 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 1* distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __perf_events_h
#define __perf_events_h

#include <linux/perf_event.h>

/* indicates that type value should be read from the Kernel */
typedef enum
{
  PERF_SOURCE_SOFTWARE = PERF_TYPE_SOFTWARE,
  PERF_SOURCE_CPU = PERF_TYPE_RAW,
  PERF_SOURCE_OTHER = ((u32) -1),
} perf_e_event_source_t;

typedef enum
{
  PERF_COUNTER_TYPE_GENERAL,
  PERF_COUNTER_TYPE_FIXED,
  PERF_COUNTER_TYPE_PSEUDO,
  PERF_COUNTER_TYPE_MAX,
} perf_e_counter_type_t;

#define PERF_REGISTER_EVENTS(x)                                               \
  perf_events_registration_t x;                                               \
  static void __perf_add_events_registration_##x (void)                       \
    __attribute__ ((__constructor__));                                        \
  static void __perf_add_events_registration_##x (void)                       \
  {                                                                           \
    x.next_events = perf_event_main.events_registrations;                     \
    perf_event_main.events_registrations = &x;                                \
  }                                                                           \
  perf_events_registration_t x

typedef struct
{
  int type;
  int cpu;
  pid_t pid;
  char *name;
} perf_event_source_t;

typedef struct
{
  perf_e_event_source_t source; /* enum perf_type_id clone */
  perf_e_counter_type_t counter_type;
  u64 config;
  format_function_t *format_config;
  char *name;
  char *description;
  char *long_description;
  char *source_name;
  u16 pmc_mask;
  u32 exclude_kernel : 1;
} perf_event_t;

typedef struct
{
  clib_cpu_supports_func_t check_feature;
  u8 expected_result : 1;
} perf_uarch_features_t;

typedef struct _perf_events_registration
{
  char *name;

  perf_event_t *events;
  u32 n_events;

  perf_uarch_features_t *uarch_features;
  u32 n_uarch_features;

  struct _perf_events_registration *next_events;
} perf_events_registration_t;

typedef struct
{
  perf_events_registration_t *events_registrations;
  uword *event_by_name;
  uword *event_source_by_name;
} perf_event_main_t;

perf_event_t *perf_query_event (const char *event_name);
perf_event_source_t *perf_query_event_sources (perf_event_t *);

extern perf_event_main_t perf_event_main;

clib_error_t *perf_event_init (vlib_main_t *vm);

#endif
