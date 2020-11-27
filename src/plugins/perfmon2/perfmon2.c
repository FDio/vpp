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
#include <perfmon/perfmon_intel.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <linux/limits.h>
#include <sys/ioctl.h>

#include <perfmon2/perfmon2.h>
#include <perfmon2/intel.h>

perfmon2_main_t perfmon2_main;

/* *INDENT-OFF* */
VLIB_REGISTER_LOG_CLASS (if_default_log, static) = {
  .class_name = "perfmon2",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};
/* *INDENT-ON* */

#define log_debug(fmt,...) vlib_log_debug(if_default_log.class, fmt, __VA_ARGS__)
#define log_err(fmt,...) vlib_log_err(if_default_log.class, fmt, __VA_ARGS__)

static_always_inline void
perfmon2_read_pmcs (perfmon2_thread_t * pt, u64 * counters)
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
perfmon2_calc_pmc_index (perfmon2_thread_t * pt, int i)
{
  return (int) (pt->mmap_pages[i]->index + pt->mmap_pages[i]->offset);
}

static void
perfmon2_pre_dispatch_cb (vlib_main_t * vm, vlib_node_runtime_t * node)
{
  perfmon2_main_t *pm = &perfmon2_main;
  perfmon2_thread_t *pt = vec_elt_at_index (pm->threads, vm->thread_index);

  switch (pt->n_events)
    {
    case 7:
      pt->pmc_index[6] = perfmon2_calc_pmc_index (pt, 6);
    case 6:
      pt->pmc_index[5] = perfmon2_calc_pmc_index (pt, 5);
    case 5:
      pt->pmc_index[4] = perfmon2_calc_pmc_index (pt, 4);
    case 4:
      pt->pmc_index[3] = perfmon2_calc_pmc_index (pt, 3);
    case 3:
      pt->pmc_index[2] = perfmon2_calc_pmc_index (pt, 2);
    case 2:
      pt->pmc_index[1] = perfmon2_calc_pmc_index (pt, 1);
    case 1:
      pt->pmc_index[0] = perfmon2_calc_pmc_index (pt, 0);
      break;
    default:
      return;
    }

  perfmon2_read_pmcs (pt, pt->node_pre_counters);
}

static void
perfmon2_post_dispatch_cb (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * frame, uword n)
{
  perfmon2_node_counters_t *nc;
  perfmon2_main_t *pm = &perfmon2_main;
  perfmon2_thread_t *pt = vec_elt_at_index (pm->threads, vm->thread_index);
  u64 c[PERF_MAX_EVENTS];
  perfmon2_read_pmcs (pt, c);

  nc = perfmon2_get_node_counters (pt, node->node_index);
  nc->n_calls += 1;
  nc->n_packets += n;

  for (int i = 0; i < pt->n_events; i++)
    nc->event_ctr[i] += c[i] - pt->node_pre_counters[i];

#if 0
  if (nc->n_calls % 100 == 0)
    {
       fformat (stderr, "%s: thread %u node %u\n", __func__,
		vm->thread_index, node->node_index);
       fformat (stderr, "n_calls %lu\n", nc->n_calls);
       fformat (stderr, "n_packets %lu\n", nc->n_packets);
       for (int i = 0; i < pt->n_events; i++)
         fformat (stderr, "event %u: %lu (+ %lu)\n", i, nc->event_ctr[i],
		  c[i] - pt->node_pre_counters[i]);
    }
#endif
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


clib_error_t *
perfmon2_start (vlib_main_t * vm)
{
  clib_error_t *err = 0;
  perfmon2_main_t *pm = &perfmon2_main;
  perfmon2_bundle_t *b;
  perfmon2_source_t *s;
  u32 n_threads = vec_len (vlib_mains);
  u32 n_counters, alloc_sz;

  if (pm->active_bundle == 0)
    return clib_error_return (0, "please select bundle first");

  if (pm->is_running)
    return clib_error_return (0, "already running");

  b = pm->active_bundle;
  s = b->src;
  ASSERT (b->n_events);

  n_counters = b->n_events + 2;
  if (b->type == PERFMON2_BUNDLE_TYPE_NODE)
    n_counters *= vec_len (vm->node_main.nodes);

  alloc_sz = round_pow2 (n_counters * sizeof (u64), CLIB_CACHE_LINE_BYTES);

  if (b->type == PERFMON2_BUNDLE_TYPE_SYSTEM)
    n_threads = 1;

  vec_validate_aligned (pm->threads, n_threads - 1, CLIB_CACHE_LINE_BYTES);

  for (int i = 0; i < n_threads; i++)
    {
      perfmon2_thread_t *pt = vec_elt_at_index (pm->threads, i);
      vlib_worker_thread_t *w = vlib_worker_threads + i;
      pt->n_events = b->n_events;
      vec_validate (pt->fds, b->n_events);
      pt->fds[0] = -1;


      for (int j = 0; j < b->n_events; j++)
	{
	  perfmon2_event_t *e = s->events + b->events[j];
	  struct perf_event_attr pe = {
	    .size = sizeof (struct perf_event_attr),
	    .type = e->type,
	    .config = e->config,
	    .disabled = 1,
	    .exclude_kernel = 1,
	    .exclude_hv = 1,
	  };

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

	  log_debug ("cpu %u thread %u (%u) event %u  set to %s "
		     "(type %u config %lu)", w->cpu_id, i,
		     w->lwp, j, e->name, e->type, e->config);

	  pt->fds[j] = syscall (__NR_perf_event_open, &pe, w->lwp,
				w->cpu_id, pt->fds[0], 0);

	  log_debug ("fd %d", pt->fds[j]);

	  if (pt->fds[j] == -1)
	    {
	      err = clib_error_return_unix (0, "perf_event_open");
	      goto error;
	    }

	  if (b->type == PERFMON2_BUNDLE_TYPE_NODE)
	    {
	      pt->mmap_pages[j] = mmap (0, clib_mem_get_page_size (),
					PROT_READ, MAP_SHARED, pt->fds[j], 0);

	      if (pt->mmap_pages[j] == MAP_FAILED)
		{
		  err = clib_error_return_unix (0, "mmap");
		  goto error;
		}
	    }
	}
    }
  for (int i = 0; i < n_threads; i++)
    {
      perfmon2_thread_t *pt = vec_elt_at_index (pm->threads, i);
	  log_debug ("fd %d", pt->fds[0]);

      if (ioctl (pt->fds[0], PERF_EVENT_IOC_ENABLE,
		 PERF_IOC_FLAG_GROUP) == -1)
	{
	  err = clib_error_return_unix (0, "ioctl(PERF_EVENT_IOC_ENABLE)");
	  goto error;
	}
    }

  if (b->type != PERFMON2_BUNDLE_TYPE_NODE)
    {
      for (int i = 0; i < n_threads; i++)
	{
	  perfmon2_thread_t *pt = vec_elt_at_index (pm->threads, i);
	  for (int j = 0; j < b->n_events; j++)
	    {
	      u64 data;
	      if (read (pt->fds[j], &data, sizeof (data)) < 0)
		{
		  err = clib_error_return_unix (0, "read");
		  goto error;
		}
	      log_debug ("thread %u event %u data %lx", i, j, data);
	    }
	}
    }
#if 0

  for (int i = 0; i < ev->n_events; i++)
    {
      log_debug ("event %u: %U (%U) hw counter id 0x%x", i,
		 pm->platform->format_event_name, ev->code[i],
		 pm->platform->format_event_details, ev->code[i],
		 perfmon2_calc_pmc_index (pt, i));
    }
#endif
  pm->is_running = 1;
  vlib_node_add_pre_dispatch_cb (vm, perfmon2_pre_dispatch_cb);
  vlib_node_add_post_dispatch_cb (vm, perfmon2_post_dispatch_cb);
error:
  if (err)
    {
      log_err ("%U", format_clib_error, err);
    }
  return err;
}

clib_error_t *
perfmon2_stop (vlib_main_t * vm)
{
  perfmon2_main_t *pm = &perfmon2_main;
  clib_error_t *err = 0;
  perfmon2_bundle_t *b = pm->active_bundle;
  u32 n_threads = vec_len (vlib_mains);

  if (pm->is_running != 1)
    return clib_error_return (0, "not running");

  if (b->type == PERFMON2_BUNDLE_TYPE_SYSTEM)
    n_threads = 1;

  vlib_node_del_pre_dispatch_cb (vm, perfmon2_pre_dispatch_cb);
  vlib_node_del_post_dispatch_cb (vm, perfmon2_post_dispatch_cb);

  for (int i = 0; i < n_threads; i++)
    {
      perfmon2_thread_t *pt = vec_elt_at_index (pm->threads, i);
      if (ioctl (pt->fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) ==
	  -1)
	err = clib_error_return_unix (err, "ioctl(PERF_EVENT_IOC_DISABLE)");

      if (b->type != PERFMON2_BUNDLE_TYPE_NODE)
	{
	  for (int j = 0; j < b->n_events; j++)
	    {
	      u64 data;
	      if (read (pt->fds[j], &data, sizeof (data)) < 0)
		{
		  err = clib_error_return_unix (0, "read");
		  goto error;
		}
	      log_debug ("thread %u event %u data %lx", i, j, data);
	    }
	}

      for (int j = 0; j < b->n_events; j++)
	{
	  if (b->type == PERFMON2_BUNDLE_TYPE_NODE &&
	      pt->mmap_pages[j] != MAP_FAILED)
	    munmap (pt->mmap_pages[j], clib_mem_get_page_size ());
	  close (pt->fds[j]);
	}
    }

  pm->is_running = 0;
error:
  if (err)
    log_err ("%U", format_clib_error, err);
  return err;
}

static clib_error_t *
perfmon2_init (vlib_main_t * vm)
{
  perfmon2_main_t *pm = &perfmon2_main;
  perfmon2_source_t *s = pm->sources;
  perfmon2_bundle_t *b = pm->bundles;

  pm->source_by_name = hash_create_string (0, sizeof (uword));
  while (s)
    {
      if (hash_get_mem (pm->source_by_name, s->name) != 0)
	clib_panic ("duplicate source name '%s'", s->name);
      hash_set_mem (pm->source_by_name, s->name, s);
      log_debug ("source '%s' regisrtered", s->name);
      s = s->next;
    }

  pm->bundle_by_name = hash_create_string (0, sizeof (uword));
  while (b)
    {
      uword *p;
      if (hash_get_mem (pm->bundle_by_name, b->name) != 0)
	clib_panic ("duplicate bundle name '%s'", b->name);

      if ((p = hash_get_mem (pm->source_by_name, b->source)))
	{
	  b->src = (perfmon2_source_t *) p[0];
	  hash_set_mem (pm->bundle_by_name, b->name, b);
	  log_debug ("bundle '%s' regisrtered", b->name);
	}
      else
	log_debug ("missing source '%s', skipping bundle '%s'",
		   b->source, b->name);

      b = b->next;
    }

#if 0
  perfmon2_data_init (vm);
  perfmon2_event_start (vm, &events);

  return 0;
#endif
  return 0;
}

VLIB_INIT_FUNCTION (perfmon2_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
