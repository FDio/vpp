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

#ifndef __perfmon_perfmon_h
#define __perfmon_perfmon_h

#include <linux/perf_event.h>
#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vlib/vlib.h>

#define PERF_MAX_EVENTS 7 /* 3 fixed and 4 programmable */

typedef enum
{
  PERFMON_BUNDLE_TYPE_UNKNOWN,
  PERFMON_BUNDLE_TYPE_NODE,
  PERFMON_BUNDLE_TYPE_THREAD,
  PERFMON_BUNDLE_TYPE_SYSTEM,
} perfmon_bundle_type_t;

typedef struct
{
  u32 type_from_instance : 1;
  u32 exclude_kernel : 1;
  union
  {
    u32 type;
    u32 instance_type;
  };
  u64 config;
  char *name;
  char *description;
} perfmon_event_t;

typedef struct
{
  u32 type;
  int cpu;
  pid_t pid;
  char *name;
} perfmon_instance_t;

typedef struct
{
  char *name;
  perfmon_instance_t *instances;
} perfmon_instance_type_t;

struct perfmon_source;
vlib_node_function_t perfmon_dispatch_wrapper;

typedef clib_error_t *(perfmon_source_init_fn_t) (vlib_main_t *vm,
						  struct perfmon_source *);
typedef struct perfmon_source
{
  char *name;
  char *description;
  struct perfmon_source *next;
  perfmon_event_t *events;
  u32 n_events;
  perfmon_instance_type_t *instances_by_type;
  format_function_t *format_config;
  perfmon_source_init_fn_t *init_fn;
} perfmon_source_t;

struct perfmon_bundle;
typedef clib_error_t *(perfmon_bundle_init_fn_t) (vlib_main_t *vm,
						  struct perfmon_bundle *);
typedef struct perfmon_bundle
{
  char *name;
  char *description;
  char *source;
  char *footer;
  perfmon_bundle_type_t type;
  u32 events[PERF_MAX_EVENTS];
  u32 n_events;

  perfmon_bundle_init_fn_t *init_fn;

  char **column_headers;
  char **raw_column_headers;
  format_function_t *format_fn;

  /* do not set manually */
  perfmon_source_t *src;
  struct perfmon_bundle *next;
} perfmon_bundle_t;

typedef struct
{
  u64 nr;
  u64 time_enabled;
  u64 time_running;
  u64 value[PERF_MAX_EVENTS];
} perfmon_reading_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 n_calls;
  u64 n_packets;
  u64 value[PERF_MAX_EVENTS];
} perfmon_node_stats_t;

typedef struct
{
  u8 n_events;
  u16 n_nodes;
  perfmon_node_stats_t *node_stats;
  struct perf_event_mmap_page *mmap_pages[PERF_MAX_EVENTS];
} perfmon_thread_runtime_t;

typedef struct
{
  perfmon_thread_runtime_t *thread_runtimes;
  perfmon_bundle_t *bundles;
  uword *bundle_by_name;
  perfmon_source_t *sources;
  uword *source_by_name;
  perfmon_bundle_t *active_bundle;
  int is_running;
  f64 sample_time;
  int *group_fds;
  int *fds_to_close;
  perfmon_instance_type_t *default_instance_type;
  perfmon_instance_type_t *active_instance_type;
} perfmon_main_t;

extern perfmon_main_t perfmon_main;

#define PERFMON_REGISTER_SOURCE(x)                                            \
  perfmon_source_t __perfmon_source_##x;                                      \
  static void __clib_constructor __perfmon_source_registration_##x (void)     \
  {                                                                           \
    perfmon_main_t *pm = &perfmon_main;                                       \
    __perfmon_source_##x.next = pm->sources;                                  \
    pm->sources = &__perfmon_source_##x;                                      \
  }                                                                           \
  perfmon_source_t __perfmon_source_##x

#define PERFMON_REGISTER_BUNDLE(x)                                            \
  perfmon_bundle_t __perfmon_bundle_##x;                                      \
  static void __clib_constructor __perfmon_bundle_registration_##x (void)     \
  {                                                                           \
    perfmon_main_t *pm = &perfmon_main;                                       \
    __perfmon_bundle_##x.next = pm->bundles;                                  \
    pm->bundles = &__perfmon_bundle_##x;                                      \
  }                                                                           \
  perfmon_bundle_t __perfmon_bundle_##x

void perfmon_reset (vlib_main_t *vm);
clib_error_t *perfmon_start (vlib_main_t *vm, perfmon_bundle_t *);
clib_error_t *perfmon_stop (vlib_main_t *vm);

#define PERFMON_STRINGS(...)                                                  \
  (char *[]) { __VA_ARGS__, 0 }

#endif
