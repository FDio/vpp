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

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <linux/limits.h>
#include <sys/ioctl.h>

#include <perfmon/perfmon.h>
#include <perfmon/perf_events.h>

perfmon_main_t perfmon_main;

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Performance Monitor",
};

VLIB_REGISTER_LOG_CLASS (if_default_log, static) = {
  .class_name = "perfmon",
};

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (if_default_log.class, fmt, __VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (if_default_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...) vlib_log_err (if_default_log.class, fmt, __VA_ARGS__)

void
perfmon_reset (vlib_main_t *vm)
{
  perfmon_main_t *pm = &perfmon_main;
  uword page_size = clib_mem_get_page_size ();

  if (pm->is_running)
    for (int i = 0; i < vlib_get_n_threads (); i++)
      vlib_node_set_dispatch_wrapper (vlib_get_main_by_index (i), 0);

  for (int i = 0; i < vec_len (pm->fds_to_close); i++)
    close (pm->fds_to_close[i]);
  vec_free (pm->fds_to_close);
  vec_free (pm->group_fds);

  for (int i = 0; i < vec_len (pm->thread_runtimes); i++)
    {
      perfmon_thread_runtime_t *tr = vec_elt_at_index (pm->thread_runtimes, i);
      vec_free (tr->node_stats);
      for (int j = 0; j < PERF_MAX_EVENTS; j++)
	if (tr->mmap_pages[j])
	  munmap (tr->mmap_pages[j], page_size);
    }
  vec_free (pm->thread_runtimes);

  pm->is_running = 0;
  pm->active_sources = 0;
  pm->active_bundle = 0;
}

static clib_error_t *
perfmon_set (vlib_main_t *vm, perfmon_bundle_t *b)
{
  clib_error_t *err = 0;
  perfmon_main_t *pm = &perfmon_main;
  int is_node = 0;
  int n_nodes = vec_len (vm->node_main.nodes);
  uword page_size = clib_mem_get_page_size ();
  perf_event_t *e;
  perf_event_source_t *s;

  perfmon_reset (vm);

  ASSERT (b->n_events);

  if (b->active_type == PERFMON_BUNDLE_TYPE_NODE)
    is_node = 1;

  e = perf_query_event (b->events[0]);
  s = perf_query_event_sources (e);

  if (!s)
    {
      err = clib_error_return (0, "could not find event source %s for %s",
			       e->source_name, e->name);
      goto error;
    }

  pm->active_sources = s;

  for (int i = 1; i < b->n_events; i++)
    {
      perf_event_t *p = perf_query_event (b->events[i]);
      if (e->source != p->source ||
	  clib_strcmp (e->source_name, p->source_name) != 0)
	{
	  err = clib_error_return (
	    0, "cannot have multiple event sources in a bundle %s", b->name);
	  goto error;
	}
    }

  if (is_node)
    vec_validate (pm->thread_runtimes, vec_len (s) - 1);

  /* for each event source */
  for (int i = 0; i < vec_len (s); i++)
    {
      vec_validate (pm->group_fds, i);
      pm->group_fds[i] = -1;

      /* for each event */
      for (int j = 0; j < b->n_events; j++)
	{
	  int fd;
	  perf_event_t *e = perf_query_event (b->events[j]);
	  struct perf_event_attr pe = {
	    .size = sizeof (struct perf_event_attr),
	    .type = e->source,
	    .config = e->config,
	    .exclude_kernel = e->exclude_kernel,
	    .read_format =
	      (PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED |
	       PERF_FORMAT_TOTAL_TIME_RUNNING),
	    .disabled = 1,
	  };

	  log_debug ("perf_event_open pe.type=%u pe.config=0x%x pid=%d "
		     "cpu=%d group_fd=%d",
		     pe.type, pe.config, s[i].pid, s[i].cpu, pm->group_fds[i]);
	  fd = syscall (__NR_perf_event_open, &pe, s[i].pid, s[i].cpu,
			pm->group_fds[i], 0);

	  if (fd == -1)
	    {
	      err = clib_error_return_unix (0, "perf_event_open");
	      goto error;
	    }

	  vec_add1 (pm->fds_to_close, fd);

	  if (pm->group_fds[i] == -1)
	    pm->group_fds[i] = fd;

	  if (is_node)
	    {
	      perfmon_thread_runtime_t *tr;
	      tr = vec_elt_at_index (pm->thread_runtimes, i);
	      tr->mmap_pages[j] =
		mmap (0, page_size, PROT_READ, MAP_SHARED, fd, 0);

	      if (tr->mmap_pages[j] == MAP_FAILED)
		{
		  err = clib_error_return_unix (0, "mmap");
		  goto error;
		}
	    }
	}

      if (is_node)
	{
	  perfmon_thread_runtime_t *rt;
	  rt = vec_elt_at_index (pm->thread_runtimes, i);
	  rt->bundle = b;
	  rt->n_events = b->n_events;
	  rt->n_nodes = n_nodes;
	  rt->preserve_samples = b->preserve_samples;
	  vec_validate_aligned (rt->node_stats, n_nodes - 1,
				CLIB_CACHE_LINE_BYTES);
	}
    }

  pm->active_bundle = b;

error:
  if (err)
    {
      log_err ("%U", format_clib_error, err);
      perfmon_reset (vm);
    }
  return err;
}

static_always_inline u32
perfmon_mmap_read_index (const struct perf_event_mmap_page *mmap_page)
{
  u32 idx;
  u32 seq;

  /* See documentation in /usr/include/linux/perf_event.h, for more details
   * but the 2 main important things are:
   *  1) if seq != mmap_page->lock, it means the kernel is currently updating
   *     the user page and we need to read it again
   *  2) if idx == 0, it means the perf event is currently turned off and we
   *     just need to read the kernel-updated 'offset', otherwise we must also
   *     add the current hw value (hence rdmpc) */
  do
    {
      seq = mmap_page->lock;
      CLIB_COMPILER_BARRIER ();

      idx = mmap_page->index;

      CLIB_COMPILER_BARRIER ();
    }
  while (mmap_page->lock != seq);

  return idx;
}

clib_error_t *
perfmon_start (vlib_main_t *vm, perfmon_bundle_t *b)
{
  clib_error_t *err = 0;
  perfmon_main_t *pm = &perfmon_main;
  int n_groups;

  if (pm->is_running == 1)
    return clib_error_return (0, "already running");

  if ((err = perfmon_set (vm, b)) != 0)
    return err;

  n_groups = vec_len (pm->group_fds);

  for (int i = 0; i < n_groups; i++)
    {
      if (ioctl (pm->group_fds[i], PERF_EVENT_IOC_ENABLE,
		 PERF_IOC_FLAG_GROUP) == -1)
	{
	  perfmon_reset (vm);
	  return clib_error_return_unix (0, "ioctl(PERF_EVENT_IOC_ENABLE)");
	}
    }
  if (b->active_type == PERFMON_BUNDLE_TYPE_NODE)
    {
      for (int i = 0; i < vec_len (pm->thread_runtimes); i++)
	{
	  perfmon_thread_runtime_t *tr;
	  tr = vec_elt_at_index (pm->thread_runtimes, i);

	  for (int j = 0; j < b->n_events; j++)
	    {
	      tr->indexes[j] = perfmon_mmap_read_index (tr->mmap_pages[j]);

	      /* if a zero index is returned generate error */
	      if (!tr->indexes[j])
		{
		  perfmon_reset (vm);
		  return clib_error_return (0, "invalid rdpmc index");
		}
	    }
	}

      for (int i = 0; i < vlib_get_n_threads (); i++)
	vlib_node_set_dispatch_wrapper (
	  vlib_get_main_by_index (i), perfmon_dispatch_wrappers[b->n_events]);
    }
  pm->sample_time = vlib_time_now (vm);
  pm->is_running = 1;

  return 0;
}

clib_error_t *
perfmon_stop (vlib_main_t *vm)
{
  perfmon_main_t *pm = &perfmon_main;
  int n_groups = vec_len (pm->group_fds);

  if (pm->is_running != 1)
    return clib_error_return (0, "not running");

  if (pm->active_bundle->active_type == PERFMON_BUNDLE_TYPE_NODE)
    {
      for (int i = 0; i < vlib_get_n_threads (); i++)
	vlib_node_set_dispatch_wrapper (vlib_get_main_by_index (i), 0);
    }

  for (int i = 0; i < n_groups; i++)
    {
      if (ioctl (pm->group_fds[i], PERF_EVENT_IOC_DISABLE,
		 PERF_IOC_FLAG_GROUP) == -1)
	{
	  perfmon_reset (vm);
	  return clib_error_return_unix (0, "ioctl(PERF_EVENT_IOC_DISABLE)");
	}
    }

  pm->is_running = 0;
  pm->sample_time = vlib_time_now (vm) - pm->sample_time;
  return 0;
}

static_always_inline u8
do_events_exist (perfmon_bundle_t *b)
{
  /* how many does the bundle require */
  for (u16 i = 0; i < b->n_events; i++)
    {
      perf_event_t *e = perf_query_event (b->events[i]);
      if (!e)
	return 0;
    }

  return 1;
}

static_always_inline u8
is_enough_counters (perfmon_bundle_t *b)
{
  u8 bl[PERF_COUNTER_TYPE_MAX];
  u8 cpu[PERF_COUNTER_TYPE_MAX];

  clib_memset (&bl, 0, sizeof (bl));
  clib_memset (&cpu, 0, sizeof (cpu));

  /* how many does this uarch support */
  if (!clib_get_pmu_counter_count (&cpu[PERF_COUNTER_TYPE_FIXED],
				   &cpu[PERF_COUNTER_TYPE_GENERAL]))
    return 0;

  /* how many does the bundle require */
  for (u16 i = 0; i < b->n_events; i++)
    {
      perf_event_t *e = perf_query_event (b->events[i]);
      bl[e->counter_type]++;
    }

  /* consciously ignoring pseudo events here */
  return cpu[PERF_COUNTER_TYPE_GENERAL] >= bl[PERF_COUNTER_TYPE_GENERAL] &&
	 cpu[PERF_COUNTER_TYPE_FIXED] >= bl[PERF_COUNTER_TYPE_FIXED];
}

static_always_inline u8
is_bundle_supported (perfmon_bundle_t *b)
{
  perfmon_cpu_supports_t *supports = b->cpu_supports;

  if (!do_events_exist (b))
    return 0;

  if (!is_enough_counters (b))
    return 0;

  if (!b->cpu_supports)
    return 1;

  for (int i = 0; i < b->n_cpu_supports; ++i)
    if (supports[i].cpu_supports ())
      return 1;

  return 0;
}

static clib_error_t *
perfmon_init (vlib_main_t *vm)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_bundle_t *b = pm->bundles;
  clib_error_t *err;

  if ((err = perf_event_init (vm)))
    return err;

  pm->bundle_by_name = hash_create_string (0, sizeof (uword));
  while (b)
    {
      clib_error_t *err;

      if (!is_bundle_supported (b))
	{
	  log_debug ("skipping bundle '%s' - not supported", b->name);
	  b = b->next;
	  continue;
	}

      if (b->init_fn && ((err = (b->init_fn) (vm, b))))
	{
	  log_warn ("skipping bundle '%s' - %U", b->name, format_clib_error,
		    err);
	  clib_error_free (err);
	  b = b->next;
	  continue;
	}

      if (hash_get_mem (pm->bundle_by_name, b->name) != 0)
	clib_panic ("duplicate bundle name '%s'", b->name);

      hash_set_mem (pm->bundle_by_name, b->name, b);
      log_debug ("bundle '%s' registered", b->name);

      b = b->next;
    }

  return 0;
}

VLIB_INIT_FUNCTION (perfmon_init);
