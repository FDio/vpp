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

#define PERF_MAX_EVENTS 7	/* 3 fixed and 4 programmable */

typedef enum
{
  PERFMON_BUNDLE_TYPE_UNKNOWN,
  PERFMON_BUNDLE_TYPE_NODE,
  PERFMON_BUNDLE_TYPE_THREAD,
  PERFMON_BUNDLE_TYPE_SYSTEM,
} perfmon_bundle_type_t;

typedef struct
{
  u32 type_from_instance:1;
  u32 exclude_kernel:1;
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

typedef clib_error_t *(perfmon_source_init_fn_t) (vlib_main_t * vm,
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
typedef clib_error_t *(perfmon_bundle_init_fn_t) (vlib_main_t * vm,
						  struct perfmon_bundle *);
typedef struct perfmon_bundle
{
  char *name;
  char *description;
  char *source;
  perfmon_bundle_type_t type;
  u32 events[PERF_MAX_EVENTS];
  u32 n_events;

  perfmon_bundle_init_fn_t *init_fn;

  format_function_t *format_header;
  format_function_t *format_footer;
  format_function_t *format_thread;
  format_function_t *format_node;
  format_function_t *format_reading;

  /* do not set manually */
  perfmon_source_t *src;
  struct perfmon_bundle *next;
} perfmon_bundle_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline);
  u8 n_events;
  u64 *counters;
  int pmc_index[PERF_MAX_EVENTS];
  u64 node_pre_counters[PERF_MAX_EVENTS];
  struct perf_event_mmap_page *mmap_pages[PERF_MAX_EVENTS];
  int group_fd;
} perfmon_thread_t;

typedef struct
{
  perfmon_thread_t *threads;
  perfmon_bundle_t *bundles;
  uword *bundle_by_name;
  perfmon_source_t *sources;
  uword *source_by_name;
  perfmon_bundle_t *active_bundle;
  int is_running;
  int *group_fds;
  int *fds_to_close;
  perfmon_instance_type_t *default_instance_type;
  perfmon_instance_type_t *active_instance_type;;
} perfmon_main_t;

extern perfmon_main_t perfmon_main;

#define PERFMON_REGISTER_SOURCE(x)                                           \
  perfmon_source_t __perfmon_source_##x;                                     \
static void __clib_constructor                                               \
__perfmon_source_registration_##x (void)                                     \
{                                                                            \
  perfmon_main_t * pm = &perfmon_main;                                       \
  __perfmon_source_##x.next = pm->sources;                                   \
  pm->sources = & __perfmon_source_##x;                                      \
}                                                                            \
perfmon_source_t __perfmon_source_##x

#define PERFMON_REGISTER_BUNDLE(x)                                           \
  perfmon_bundle_t __perfmon_bundle_##x;                                     \
static void __clib_constructor                                               \
__perfmon_bundle_registration_##x (void)                                     \
{                                                                            \
  perfmon_main_t * pm = &perfmon_main;                                       \
  __perfmon_bundle_##x.next = pm->bundles;                                   \
  pm->bundles = & __perfmon_bundle_##x;                                      \
}                                                                            \
perfmon_bundle_t __perfmon_bundle_##x


void perfmon_reset (vlib_main_t * vm);
clib_error_t *perfmon_set (vlib_main_t * vm, perfmon_bundle_t *);
clib_error_t *perfmon_start (vlib_main_t * vm);
clib_error_t *perfmon_stop (vlib_main_t * vm);

typedef struct
{
  u64 n_calls;
  u64 n_packets;
  u64 value[0];
} __clib_aligned (8) perfmon_node_counters_t;

typedef struct {
  u64 nr;
  u64 time_enabled;
  u64 time_running;
  u64 value[PERF_MAX_EVENTS];
} perfmon_reading_t;

static_always_inline perfmon_node_counters_t *
perfmon_get_node_counters (perfmon_thread_t * pt, u32 node_index)
{
  return (perfmon_node_counters_t *) (pt->counters +
				      node_index * (pt->n_events + 2));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
