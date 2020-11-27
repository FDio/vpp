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
} perfmon2_event_t;

typedef struct perfmon2_source
{
  char *name;
  char *description;
  struct perfmon2_source *next;
  perfmon2_event_t *events;
  u32 n_events;
} perfmon2_source_t;

typedef struct perfmon2_bundle
{
  char *name;
  char *description;
  char *source;
  perfmon2_bundle_type_t type;

  /* do not set manually */
  perfmon2_source_t *src;
  struct perfmon2_bundle *next;
} perfmon2_bundle_t;

typedef struct
{
  u64 n_packets;
  u64 n_reads;
  u64 counters[PERF_MAX_EVENTS];
} perfmon2_node_counters_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline);
  u8 n_events;
  struct perf_event_mmap_page *mmap_pages[PERF_MAX_EVENTS];
  int pmc_index[PERF_MAX_EVENTS];
  u64 node_pre_counters[PERF_MAX_EVENTS];
  perfmon2_node_counters_t *node_counters;
} perfmon2_thread_t;

typedef struct
{
  u64 *config_by_event_index;
  format_function_t *format_event_name;
  format_function_t *format_event_details;
  format_function_t *format_event_description;
} perfmon2_platform_t;

typedef struct
{
  perfmon2_thread_t *threads;
  int group_fd;
  perfmon2_platform_t *platform;
  perfmon2_bundle_t *bundles;
  uword *bundle_by_name;
  perfmon2_source_t *sources;
  uword *source_by_name;
} perfmon2_main_t;

extern perfmon2_main_t perfmon2_main;
extern perfmon2_platform_t perfmon2_platform_intel;

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
