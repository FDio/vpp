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

#include "vppinfra/error.h"
#include "vppinfra/string.h"
#include "vppinfra/vec_bootstrap.h"
#include <vnet/vnet.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <linux/limits.h>
#include <sys/ioctl.h>
#include <vpp/stats/stat_segment.h>

#include <perfmon/perfmon.h>

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
  if (pm->default_instance_type)
    {
      perfmon_instance_type_t *it = pm->default_instance_type;
      for (int i = 0; i < vec_len (it->instances); i++)
	vec_free (it->instances[i].name);
      vec_free (it->instances);
      vec_free (pm->default_instance_type);
    }

  for (int i = 0; i < vec_len (pm->thread_runtimes); i++)
    {
      perfmon_thread_runtime_t *tr = vec_elt_at_index (pm->thread_runtimes, i);
      vec_free (tr->node_stats);
      for (int j = 0; j < PERF_MAX_EVENTS; j++)
	if (tr->mmap_pages[j])
	  munmap (tr->mmap_pages, page_size);
    }
  vec_free (pm->thread_runtimes);

  pm->is_running = 0;
  pm->active_instance_type = 0;
  pm->active_bundle = 0;
}

static clib_error_t *
perfmon_set (vlib_main_t *vm, perfmon_bundle_t *b)
{
  clib_error_t *err = 0;
  perfmon_main_t *pm = &perfmon_main;
  perfmon_source_t *s;
  int is_node;
  int n_nodes = vec_len (vm->node_main.nodes);
  uword page_size = clib_mem_get_page_size ();
  u32 instance_type = 0;
  perfmon_event_t *e;
  perfmon_instance_type_t *it = 0;

  perfmon_reset (vm);

  s = b->src;
  ASSERT (b->n_events);

  is_node = (b->active_type == PERFMON_BUNDLE_TYPE_NODE);

  if (b->active_type != PERFMON_BUNDLE_TYPE_SYSTEM)
    {
      vec_add2 (pm->default_instance_type, it, 1);
      it->name = is_node ? "Thread/Node" : "Thread";
      for (int i = 0; i < vlib_get_n_threads (); i++)
	{
	  vlib_worker_thread_t *w = vlib_worker_threads + i;
	  perfmon_instance_t *in;
	  vec_add2 (it->instances, in, 1);
	  in->cpu = w->cpu_id;
	  in->pid = w->lwp;
	  in->name = (char *) format (0, "%s (%u)%c", w->name, i, 0);
	}
      vec_validate (pm->thread_runtimes, vlib_get_n_threads () - 1);
    }
  else
    {
      e = s->events + b->events[0];

      if (e->type_from_instance)
	{
	  instance_type = e->instance_type;
	  for (int i = 1; i < b->n_events; i++)
	    {
	      e = s->events + b->events[i];
	      ASSERT (e->type_from_instance == 1 &&
		      e->instance_type == instance_type);
	    }
	}
      it = vec_elt_at_index (s->instances_by_type, instance_type);
    }

  pm->active_instance_type = it;

  for (int i = 0; i < vec_len (it->instances); i++)
    {
      perfmon_instance_t *in = vec_elt_at_index (it->instances, i);

      vec_validate (pm->group_fds, i);
      pm->group_fds[i] = -1;

      for (int j = 0; j < b->n_events; j++)
	{
	  int fd;
	  perfmon_event_t *e = s->events + b->events[j];
	  struct perf_event_attr pe = {
	    .size = sizeof (struct perf_event_attr),
	    .type = e->type_from_instance ? in->type : e->type,
	    .config = e->config,
	    .exclude_kernel = e->exclude_kernel,
	    .read_format =
	      (PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED |
	       PERF_FORMAT_TOTAL_TIME_RUNNING),
	    .disabled = 1,
	  };

	  log_debug ("perf_event_open pe.type=%u pe.config=0x%x pid=%d "
		     "cpu=%d group_fd=%d",
		     pe.type, pe.config, in->pid, in->cpu, pm->group_fds[i]);
	  fd = syscall (__NR_perf_event_open, &pe, in->pid, in->cpu,
			pm->group_fds[i], 0);

	  if (fd == -1)
	    {
	      err = clib_error_return_unix (0, "perf_event_open");
	      goto error;
	    }

	  vec_add1 (pm->fds_to_close, fd);

	  if (pm->group_fds[i] == -1)
	    pm->group_fds[i] = fd;

	  if (b->active_type == PERFMON_BUNDLE_TYPE_NODE)
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

      /* we record node_stats for nodes & threads types */
      if (b->active_type != PERFMON_BUNDLE_TYPE_SYSTEM)
	{
	  perfmon_thread_runtime_t *rt;
	  rt = vec_elt_at_index (pm->thread_runtimes, i);
	  rt->bundle = b;
	  rt->n_events = b->offset_type == PERFMON_OFFSET_TYPE_MMAP ?
			   b->n_events :
			   b->n_metrics;
	  rt->n_nodes = n_nodes;
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

clib_error_t *
perfmon_start (vlib_main_t *vm, perfmon_bundle_t *b)
{
  clib_error_t *err = 0;
  perfmon_main_t *pm = &perfmon_main;
  int n_groups;
  vlib_node_function_t *fn, *funcs[PERFMON_OFFSET_TYPE_MAX];
#define _(type, pfunc) funcs[type] = pfunc;

  foreach_perfmon_offset_type
#undef _

    if (pm->is_running == 1) return clib_error_return (0, "already running");

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

  switch (b->active_type)
    {
    case PERFMON_BUNDLE_TYPE_NODE:
      fn = funcs[b->offset_type];
      break;
    case PERFMON_BUNDLE_TYPE_THREAD:
      fn = perfmon_dispatch_wrapper_stats;
      break;
    default:
      fn = 0;
      break;
    }

  for (int i = 0; i < vlib_get_n_threads () && fn; i++)
    vlib_node_set_dispatch_wrapper (vlib_get_main_by_index (i), fn);

  pm->sample_time = vlib_time_now (vm);
  pm->is_running = 1;

  /* enable the stats segement */
  if (b->active_type != PERFMON_BUNDLE_TYPE_NODE)
    stat_segment_poll_state (b->stats_index, true);

  return 0;
}

clib_error_t *
perfmon_stop (vlib_main_t *vm)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_bundle_t *b = pm->active_bundle;
  int n_groups = vec_len (pm->group_fds);

  if (pm->is_running != 1)
    return clib_error_return (0, "not running");

  /* enable the stats segement */
  if (b->active_type != PERFMON_BUNDLE_TYPE_NODE)
    stat_segment_poll_state (b->stats_index, false);

  for (int i = 0; i < vlib_get_n_threads (); i++)
    vlib_node_set_dispatch_wrapper (vlib_get_main_by_index (i), 0);

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

static void
perfmon_bundle_stats_update_fn (stat_segment_directory_entry_t *e, u32 index)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_bundle_t *b = pm->active_bundle;
  u32 n_instances;
  counter_t **counters = e->data;
  perfmon_stats_t thread_stats, *ss = &thread_stats;
  counter_t *cb;
  perfmon_instance_type_t *it = pm->active_instance_type;
  u16 active_nodes = 0;

  /* if perfmon is no running, no active bundle or the active bundle is node */
  if (!pm->is_running || !b)
    return;

  ASSERT (b->active_type != PERFMON_BUNDLE_TYPE_NODE);

  n_instances = vec_len (it->instances);

  for (int i = 0; i < n_instances; i++)
    {
      clib_memset_u8 (ss, 0, sizeof (perfmon_stats_t));
      cb = counters[i];

      if (read (pm->group_fds[i], ss, (b->n_events + 3) * sizeof (u64)) == -1)
	clib_unix_error ("read");

      /* if the bundle type is thread */
      if (b->active_type == PERFMON_BUNDLE_TYPE_THREAD)
	{
	  perfmon_thread_runtime_t *tr =
	    vec_elt_at_index (pm->thread_runtimes, i);

	  ss->n_calls = ss->n_packets = 0;
	  for (int j = 0; j < tr->n_nodes; j++)
	    {
	      ss->n_calls += tr->node_stats[j].n_calls;
	      ss->n_packets += tr->node_stats[j].n_packets;
	      if (tr->node_stats[j].n_calls)
		active_nodes++;
	    }

	  if (ss->n_calls)
	    {
	      ss->n_calls /= active_nodes;
	      ss->n_packets /= active_nodes;
	    }
	}

      ASSERT (b->update_fn);

      for (int i = 0; i < b->n_column_headers; i++)
	cb[i] = b->update_fn (ss, i);
    }
}

static clib_error_t *
perfmon_init (vlib_main_t *vm)
{
  stat_segment_main_t *sm = &stat_segment_main;
  perfmon_main_t *pm = &perfmon_main;
  perfmon_source_t *s = pm->sources;
  perfmon_bundle_t *b = pm->bundles;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int n_threads = tm->n_vlib_mains;

  pm->source_by_name = hash_create_string (0, sizeof (uword));

  while (s)
    {
      clib_error_t *err;
      if (hash_get_mem (pm->source_by_name, s->name) != 0)
	clib_panic ("duplicate source name '%s'", s->name);
      if (s->init_fn && ((err = (s->init_fn) (vm, s))))
	{
	  log_warn ("skipping source '%s' - %U", s->name, format_clib_error,
		    err);
	  clib_error_free (err);
	  s = s->next;
	  continue;
	}

      hash_set_mem (pm->source_by_name, s->name, s);
      log_debug ("source '%s' regisrtered", s->name);
      s = s->next;
    }

  pm->bundle_by_name = hash_create_string (0, sizeof (uword));
  while (b)
    {
      clib_error_t *err;
      uword *p;

      if (hash_get_mem (pm->bundle_by_name, b->name) != 0)
	clib_panic ("duplicate bundle name '%s'", b->name);

      if ((p = hash_get_mem (pm->source_by_name, b->source)) == 0)
	{
	  log_debug ("missing source '%s', skipping bundle '%s'", b->source,
		     b->name);
	  b = b->next;
	  continue;
	}

      b->src = (perfmon_source_t *) p[0];
      if (b->init_fn && ((err = (b->init_fn) (vm, b))))
	{
	  log_warn ("skipping bundle '%s' - %U", b->name, format_clib_error,
		    err);
	  clib_error_free (err);
	  b = b->next;
	  continue;
	}

      hash_set_mem (pm->bundle_by_name, b->name, b);

      /* if the bundle supports thread mode, create a stats segment*/
      if (b->type_flags != PERFMON_BUNDLE_TYPE_NODE_FLAG)
	{
	  /* Perf counters provider */
	  u8 *sd = format (0, "/perfmon/%s%c", (char *) b->name, 0);
	  u32 perfmon_vector_index =
	    stat_segment_new_entry (sd, STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE);

	  vlib_stat_segment_lock ();
	  stat_segment_directory_entry_t *ep =
	    &sm->directory_vector[perfmon_vector_index];
	  ep->data = stat_validate_counter_vector3 (ep->data, n_threads - 1,
						    b->n_column_headers - 1);

	  void *oldheap = clib_mem_set_heap (sm->heap);
	  for (int i = 0; i < b->n_column_headers; i++)
	    {
	      u8 *p, *s, *symlink = vec_dup (sd);

	      s = format (0, "%s", b->column_headers[i]);
	      vec_foreach (p, s)
		{
		  /* rationalize names for symlinks */
		  switch (*p)
		    {
		    case '/':
		    case ' ':
		      *p = '_';
		      break;
		    }
		}
	      symlink = format (symlink, "/%s%c", s, 0);

	      vlib_stats_register_symlink (oldheap, symlink,
					   perfmon_vector_index, i, 0);
	      vec_free (symlink);
	      vec_free (s);
	    }

	  clib_mem_set_heap (oldheap);
	  vlib_stat_segment_unlock ();

	  ASSERT (!(perfmon_vector_index == ~0));

	  b->stats_index = stat_segment_poll_add (
	    perfmon_vector_index, perfmon_bundle_stats_update_fn, -1, 10,
	    false);
	}

      log_debug ("bundle '%s' regisrtered", b->name);

      b = b->next;
    }

  return 0;
}

VLIB_INIT_FUNCTION (perfmon_init);
