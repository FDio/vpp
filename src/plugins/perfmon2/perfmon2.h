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

#ifndef __perfmon2_perfmon2_h
#define __perfmon2_perfmon2_h

#define PERF_MAX_EVENTS 7	/* 3 fixed and 4 programmable */

typedef enum
{
  PERFMON2_BUNDLE_TYPE_UNKNOWN,
  PERFMON2_BUNDLE_TYPE_NODE,
  PERFMON2_BUNDLE_TYPE_THREAD,
  PERFMON2_BUNDLE_TYPE_SYSTEM,
} perfmon2_bundle_type_t;

typedef struct
{
  u32 type;
  u64 config;
  char *name;
  char *description;
} perfmon2_event_t;

typedef struct perfmon2_source
{
  char *name;
  char *description;
  struct perfmon2_source *next;
  perfmon2_event_t *events;
  u32 n_events;
  format_function_t *format_config;
} perfmon2_source_t;

typedef struct perfmon2_bundle
{
  char *name;
  char *description;
  char *source;
  perfmon2_bundle_type_t type;
  u32 events[PERF_MAX_EVENTS];
  u32 n_events;

  format_function_t *format_header;
  format_function_t *format_footer;
  format_function_t *format_thread;
  format_function_t *format_node;

  /* do not set manually */
  perfmon2_source_t *src;
  struct perfmon2_bundle *next;
} perfmon2_bundle_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline);
  u8 n_events;
  u64 *counters;
  int pmc_index[PERF_MAX_EVENTS];
  u64 node_pre_counters[PERF_MAX_EVENTS];
  struct perf_event_mmap_page *mmap_pages[PERF_MAX_EVENTS];
  int *fds;
} perfmon2_thread_t;

typedef struct
{
  perfmon2_thread_t *threads;
  perfmon2_bundle_t *bundles;
  uword *bundle_by_name;
  perfmon2_source_t *sources;
  uword *source_by_name;
  perfmon2_bundle_t *active_bundle;
  int is_running;
} perfmon2_main_t;

extern perfmon2_main_t perfmon2_main;

#define PERFMON2_REGISTER_SOURCE(x)                                          \
  perfmon2_source_t __perfmon2_source_##x;                                   \
static void __clib_constructor                                               \
__perfmon2_source_registration_##x (void)                                    \
{                                                                            \
  perfmon2_main_t * pm = &perfmon2_main;                                     \
  __perfmon2_source_##x.next = pm->sources;                                  \
  pm->sources = & __perfmon2_source_##x;                                     \
}                                                                            \
perfmon2_source_t __perfmon2_source_##x

#define PERFMON2_REGISTER_BUNDLE(x)                                          \
  perfmon2_bundle_t __perfmon2_bundle_##x;                                   \
static void __clib_constructor                                               \
__perfmon2_bundle_registration_##x (void)                                    \
{                                                                            \
  perfmon2_main_t * pm = &perfmon2_main;                                     \
  __perfmon2_bundle_##x.next = pm->bundles;                                  \
  pm->bundles = & __perfmon2_bundle_##x;                                     \
}                                                                            \
perfmon2_bundle_t __perfmon2_bundle_##x

#endif

clib_error_t *perfmon2_start (vlib_main_t * vm);
clib_error_t *perfmon2_stop (vlib_main_t * vm);

typedef struct
{
  u64 n_calls;
  u64 n_packets;
  u64 event_ctr[0];
} perfmon2_node_counters_t;

static_always_inline perfmon2_node_counters_t *
perfmon2_get_node_counters (perfmon2_thread_t *pt, u32 node_index)
{
  return (perfmon2_node_counters_t *) (pt->counters +
    node_index * (pt->n_events + 2));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
