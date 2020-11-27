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
#include <vpp/app/version.h>
#include <linux/limits.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>

#include <perfmon/perfmon.h>

perfmon_main_t perfmon_main;

/* *INDENT-OFF* */
VLIB_REGISTER_LOG_CLASS (if_default_log, static) = {
  .class_name = "perfmon",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};
/* *INDENT-ON* */

#define log_debug(fmt,...) vlib_log_debug(if_default_log.class, fmt, __VA_ARGS__)
#define log_warn(fmt,...) vlib_log_warn(if_default_log.class, fmt, __VA_ARGS__)
#define log_err(fmt,...) vlib_log_err(if_default_log.class, fmt, __VA_ARGS__)

static_always_inline void
perfmon_read_pmcs (perfmon_thread_t * pt, u64 * counters)
{
  switch (pt->n_events)
    {
    case 7:
      counters[6] = _rdpmc (pt->pmc_index[6]);
    case 6:
      counters[5] = _rdpmc (pt->pmc_index[5]);
    case 5:
      counters[4] = _rdpmc (pt->pmc_index[4]);
    case 4:
      counters[3] = _rdpmc (pt->pmc_index[3]);
    case 3:
      counters[2] = _rdpmc (pt->pmc_index[2]);
    case 2:
      counters[1] = _rdpmc (pt->pmc_index[1]);
    case 1:
      counters[0] = _rdpmc (pt->pmc_index[0]);
      break;
    default:
      return;
    }
}

static inline int
perfmon_calc_pmc_index (perfmon_thread_t * pt, int i)
{
  return (int) (pt->mmap_pages[i]->index + pt->mmap_pages[i]->offset);
}

static void
perfmon_pre_dispatch_cb (vlib_main_t * vm, vlib_node_runtime_t * node)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_thread_t *pt = vec_elt_at_index (pm->threads, vm->thread_index);

  switch (pt->n_events)
    {
    case 7:
      pt->pmc_index[6] = perfmon_calc_pmc_index (pt, 6);
    case 6:
      pt->pmc_index[5] = perfmon_calc_pmc_index (pt, 5);
    case 5:
      pt->pmc_index[4] = perfmon_calc_pmc_index (pt, 4);
    case 4:
      pt->pmc_index[3] = perfmon_calc_pmc_index (pt, 3);
    case 3:
      pt->pmc_index[2] = perfmon_calc_pmc_index (pt, 2);
    case 2:
      pt->pmc_index[1] = perfmon_calc_pmc_index (pt, 1);
    case 1:
      pt->pmc_index[0] = perfmon_calc_pmc_index (pt, 0);
      break;
    default:
      return;
    }

  perfmon_read_pmcs (pt, pt->node_pre_counters);
}

static void
perfmon_post_dispatch_cb (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame, uword n)
{
  perfmon_node_counters_t *nc;
  perfmon_main_t *pm = &perfmon_main;
  perfmon_thread_t *pt = vec_elt_at_index (pm->threads, vm->thread_index);
  u64 c[PERF_MAX_EVENTS];
  perfmon_read_pmcs (pt, c);

  if (n == 0)
    return;

  nc = perfmon_get_node_counters (pt, node->node_index);
  nc->n_calls += 1;
  nc->n_packets += n;

  for (int i = 0; i < pt->n_events; i++)
    nc->value[i] += c[i] - pt->node_pre_counters[i];
}

void
vlib_node_add_pre_dispatch_cb (vlib_main_t * vm,
			       vlib_node_pre_dispatch_cb_fn_t * cb)
{
  vec_add1 (vm->pre_dispatch_cb_fn, cb);
}

void
vlib_node_add_post_dispatch_cb (vlib_main_t * vm,
				vlib_node_post_dispatch_cb_fn_t * cb)
{
  vec_add1 (vm->post_dispatch_cb_fn, cb);
}

void
vlib_node_del_pre_dispatch_cb (vlib_main_t * vm,
			       vlib_node_pre_dispatch_cb_fn_t * cb)
{
  for (int i = vec_len (vm->pre_dispatch_cb_fn) - 1; i >= 0; i--)
    if (vm->pre_dispatch_cb_fn[i] == cb)
      vec_del1 (vm->pre_dispatch_cb_fn, i);
}

void
vlib_node_del_post_dispatch_cb (vlib_main_t * vm,
				vlib_node_post_dispatch_cb_fn_t * cb)
{
  for (int i = vec_len (vm->post_dispatch_cb_fn) - 1; i >= 0; i--)
    if (vm->post_dispatch_cb_fn[i] == cb)
      vec_del1 (vm->post_dispatch_cb_fn, i);
}


void
perfmon_reset (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;
  pm->is_running = 0;
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
  pm->active_instance_type = 0;
  pm->active_bundle = 0;
#if 0
  for (int j = 0; j < b->n_events; j++)
    {
      if (b->type == PERFMON_BUNDLE_TYPE_NODE &&
	  pt->mmap_pages[j] != MAP_FAILED)
	munmap (pt->mmap_pages[j], clib_mem_get_page_size ());
    }
#endif
}

clib_error_t *
perfmon_set (vlib_main_t * vm, perfmon_bundle_t * b)
{
  clib_error_t *err = 0;
  perfmon_main_t *pm = &perfmon_main;
  perfmon_source_t *s;
  int is_node = 0;
  u32 instance_type = 0;
  perfmon_event_t *e;
  perfmon_instance_type_t *it = 0;

  perfmon_reset (vm);

  s = b->src;
  ASSERT (b->n_events);

  if (b->type == PERFMON_BUNDLE_TYPE_NODE)
    is_node = 1;

  if (s->instances_by_type == 0)
    {
      vec_add2 (pm->default_instance_type, it, 1);
      it->name = "Thread";
      for (int i = 0; i < vec_len (vlib_mains); i++)
	{
	  vlib_worker_thread_t *w = vlib_worker_threads + i;
	  perfmon_instance_t *in;
	  vec_add2 (it->instances, in, 1);
	  in->cpu = w->cpu_id;
	  in->pid = w->lwp;
	  in->name = (char *) format (0, "%u (%s)%c", i, w->name, 0);
	}
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
	    .read_format = (PERF_FORMAT_GROUP |
			    PERF_FORMAT_TOTAL_TIME_ENABLED |
			    PERF_FORMAT_TOTAL_TIME_RUNNING),
	    .disabled = 1,
	  };

	  log_debug ("perf_event_open pe.type = 0x%x pe.config=0x%x pid=%d "
		     "cpu=%d group_fd=%d", pe.type, pe.config,
		     in->pid, in->cpu, pm->group_fds[i]);
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
	}
    }

#if 0
  u32 n_threads = vec_len (vlib_mains);
  u32 n_counters, alloc_sz;
  n_counters = b->n_events + 2;
  if (is_node)
    n_counters *= vec_len (vm->node_main.nodes);

  alloc_sz = round_pow2 (n_counters * sizeof (u64), CLIB_CACHE_LINE_BYTES);

  if (b->type == PERFMON_BUNDLE_TYPE_SYSTEM)
    n_threads = 1;

  vec_validate_aligned (pm->threads, n_threads - 1, CLIB_CACHE_LINE_BYTES);

  for (int i = 0; i < n_threads; i++)
    {
      perfmon_thread_t *pt = vec_elt_at_index (pm->threads, i);
      vlib_worker_thread_t *w = vlib_worker_threads + i;
      pt->n_events = b->n_events;
      pt->group_fd = -1;

      for (int j = 0; j < b->n_events; j++)
	{
	  int fd;

	  if (pt->counters && clib_mem_size (pt->counters) < alloc_sz)
	    {
	      clib_mem_free (pt->counters);
	      pt->counters = 0;
	    }

	  if (pt->counters == 0)
	    pt->counters = clib_mem_alloc_aligned (alloc_sz,
						   CLIB_CACHE_LINE_BYTES);

	  if (pt->counters == 0)
	    {
	      err = clib_error_return (0, "failed to alloc %u bytes of "
				       "memory", alloc_sz);
	      goto error;
	    }

	  clib_memset_u8 (pt->counters, 0, alloc_sz);



	  if (b->type == PERFMON_BUNDLE_TYPE_NODE)
	    {
	      pt->mmap_pages[j] = mmap (0, clib_mem_get_page_size (),
					PROT_READ, MAP_SHARED, fd, 0);

	      if (pt->mmap_pages[j] == MAP_FAILED)
		{
		  err = clib_error_return_unix (0, "mmap");
		  goto error;
		}
	    }
	}
    }
#endif

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
perfmon_start (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;
  int n_groups = vec_len (pm->group_fds);

  if (n_groups == 0)
    return clib_error_return (0, "no bundle configured");

  if (pm->is_running == 1)
    return clib_error_return (0, "already running");

  for (int i = 0; i < n_groups; i++)
    {
      if (ioctl (pm->group_fds[i], PERF_EVENT_IOC_ENABLE,
		 PERF_IOC_FLAG_GROUP) == -1)
	{
	  perfmon_reset (vm);
	  return clib_error_return_unix (0, "ioctl(PERF_EVENT_IOC_ENABLE)");
	}
    }
  if (pm->active_bundle->type == PERFMON_BUNDLE_TYPE_NODE)
    {
      vlib_node_add_pre_dispatch_cb (vm, perfmon_pre_dispatch_cb);
      vlib_node_add_post_dispatch_cb (vm, perfmon_post_dispatch_cb);
    }
  pm->is_running = 1;
  return 0;
}

clib_error_t *
perfmon_stop (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;
  int n_groups = vec_len (pm->group_fds);

  if (pm->is_running != 1)
    return clib_error_return (0, "not running");

  if (pm->active_bundle->type == PERFMON_BUNDLE_TYPE_NODE)
    {
      vlib_node_del_pre_dispatch_cb (vm, perfmon_pre_dispatch_cb);
      vlib_node_del_post_dispatch_cb (vm, perfmon_post_dispatch_cb);
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
  return 0;
}

static clib_error_t *
perfmon_init (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_source_t *s = pm->sources;
  perfmon_bundle_t *b = pm->bundles;

  pm->source_by_name = hash_create_string (0, sizeof (uword));
  while (s)
    {
      clib_error_t *err;
      if (hash_get_mem (pm->source_by_name, s->name) != 0)
	clib_panic ("duplicate source name '%s'", s->name);
      if (s->init_fn && ((err = (s->init_fn) (vm, s))))
	{
	  log_warn ("skipping source '%s' - %U", s->name,
		    format_clib_error, err);
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
	  log_debug ("missing source '%s', skipping bundle '%s'",
		     b->source, b->name);
	  b = b->next;
	  continue;
	}

      b->src = (perfmon_source_t *) p[0];
      if (b->init_fn && ((err = (b->init_fn) (vm, b))))
	{
	  log_warn ("skipping bundle '%s' - %U", b->name,
		    format_clib_error, err);
	  clib_error_free (err);
	  b = b->next;
	  continue;
	}

      hash_set_mem (pm->bundle_by_name, b->name, b);
      log_debug ("bundle '%s' regisrtered", b->name);

      b = b->next;
    }

  return 0;
}

VLIB_INIT_FUNCTION (perfmon_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
