/*
 * perfmon_periodic.c - skeleton plug-in periodic function
 *
 * Copyright (c) <current-year> <your-organization>
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

#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include <perfmon/perfmon.h>
#include <asm/unistd.h>
#include <sys/ioctl.h>

/* "not in glibc" */
static long
perf_event_open (struct perf_event_attr *hw_event, pid_t pid, int cpu,
		 int group_fd, unsigned long flags)
{
  int ret;

  ret = syscall (__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
  return ret;
}

static void
read_current_perf_counters (vlib_node_runtime_perf_callback_data_t * data,
			    vlib_node_runtime_perf_callback_args_t * args)
{
  int i;
  perfmon_main_t *pm = &perfmon_main;
  perfmon_thread_t *pt = data->u[0].v;
  u64 c[2] = { 0, 0 };
  u64 *cc;

  if (PREDICT_FALSE (args->call_type == VLIB_NODE_RUNTIME_PERF_RESET))
    return;

  if (args->call_type == VLIB_NODE_RUNTIME_PERF_BEFORE)
    cc = pt->c;
  else
    cc = c;

  for (i = 0; i < pm->n_active; i++)
    {
      if (pt->rdpmc_indices[i] != ~0)
	cc[i] = clib_rdpmc ((int) pt->rdpmc_indices[i]);
      else
	{
	  u64 sw_value;
	  int read_result;
	  if ((read_result = read (pt->pm_fds[i], &sw_value,
				   sizeof (sw_value))) != sizeof (sw_value))
	    {
	      clib_unix_warning
		("counter read returned %d, expected %d",
		 read_result, sizeof (sw_value));
	      clib_callback_data_enable_disable
		(&args->vm->vlib_node_runtime_perf_callbacks,
		 read_current_perf_counters, 0 /* enable */ );
	      return;
	    }
	  cc[i] = sw_value;
	}
    }

  if (args->call_type == VLIB_NODE_RUNTIME_PERF_AFTER)
    {
      u32 node_index = args->node->node_index;
      vec_validate (pt->counters, node_index);
      pt->counters[node_index].ticks[0] += c[0] - pt->c[0];
      pt->counters[node_index].ticks[1] += c[1] - pt->c[1];
      pt->counters[node_index].vectors += args->packets;
    }
}

static void
clear_counters (perfmon_main_t * pm)
{
  int j;
  vlib_main_t *vm = pm->vlib_main;
  vlib_main_t *stat_vm;
  perfmon_thread_t *pt;
  u32 len;


  vlib_worker_thread_barrier_sync (vm);

  for (j = 0; j < vec_len (vlib_mains); j++)
    {
      stat_vm = vlib_mains[j];
      if (stat_vm == 0)
	continue;

      pt = pm->threads[j];
      len = vec_len (pt->counters);
      if (!len)
	continue;

      clib_memset (pt->counters, 0, len * sizeof (pt->counters[0]));
    }
  vlib_worker_thread_barrier_release (vm);
}

static void
enable_current_events (perfmon_main_t * pm)
{
  struct perf_event_attr pe;
  int fd;
  struct perf_event_mmap_page *p = 0;
  perfmon_event_config_t *c;
  vlib_main_t *vm = vlib_get_main ();
  u32 my_thread_index = vm->thread_index;
  perfmon_thread_t *pt = pm->threads[my_thread_index];
  u32 index;
  int i, limit = 1;
  int cpu;
  vlib_node_runtime_perf_callback_data_t cbdata = { 0 };
  cbdata.fp = read_current_perf_counters;
  cbdata.u[0].v = pt;
  cbdata.u[1].v = vm;

  if ((pm->current_event + 1) < vec_len (pm->single_events_to_collect))
    limit = 2;

  for (i = 0; i < limit; i++)
    {
      c = vec_elt_at_index (pm->single_events_to_collect,
			    pm->current_event + i);

      memset (&pe, 0, sizeof (struct perf_event_attr));
      pe.type = c->pe_type;
      pe.size = sizeof (struct perf_event_attr);
      pe.config = c->pe_config;
      pe.disabled = 1;
      pe.pinned = 1;
      /*
       * Note: excluding the kernel makes the
       * (software) context-switch counter read 0...
       */
      if (pe.type != PERF_TYPE_SOFTWARE)
	{
	  /* Exclude kernel and hypervisor */
	  pe.exclude_kernel = 1;
	  pe.exclude_hv = 1;
	}

      cpu = vm->cpu_id;

      fd = perf_event_open (&pe, 0, cpu, -1, 0);
      if (fd == -1)
	{
	  clib_unix_warning ("event open: type %d config %d", c->pe_type,
			     c->pe_config);
	  return;
	}

      if (pe.type != PERF_TYPE_SOFTWARE)
	{
	  p = mmap (0, pm->page_size, PROT_READ, MAP_SHARED, fd, 0);
	  if (p == MAP_FAILED)
	    {
	      clib_unix_warning ("mmap");
	      close (fd);
	      return;
	    }
	  CLIB_MEM_UNPOISON (p, pm->page_size);
	}
      else
	p = 0;

      if (ioctl (fd, PERF_EVENT_IOC_RESET, 0) < 0)
	clib_unix_warning ("reset ioctl");

      if (ioctl (fd, PERF_EVENT_IOC_ENABLE, 0) < 0)
	clib_unix_warning ("enable ioctl");

      pt->perf_event_pages[i] = (void *) p;
      pt->pm_fds[i] = fd;
    }

  /*
   * Hardware events must be all opened and enabled before aquiring
   * pmc indices, otherwise the pmc indices might be out-dated.
   */
  for (i = 0; i < limit; i++)
    {
      p = (struct perf_event_mmap_page *) pt->perf_event_pages[i];

      /*
       * Software event counters - and others not capable of being
       * read via the "rdpmc" instruction - will be read
       * by system calls.
       */
      if (p == 0 || p->cap_user_rdpmc == 0)
	index = ~0;
      else
	index = p->index - 1;

      pt->rdpmc_indices[i] = index;
    }

  pm->n_active = i;
  /* Enable the main loop counter snapshot mechanism */
  clib_callback_data_add (&vm->vlib_node_runtime_perf_callbacks, cbdata);
}

static void
disable_events (perfmon_main_t * pm)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 my_thread_index = vm->thread_index;
  perfmon_thread_t *pt = pm->threads[my_thread_index];
  int i;

  /* Stop main loop collection */
  clib_callback_data_remove (&vm->vlib_node_runtime_perf_callbacks,
			     read_current_perf_counters);

  for (i = 0; i < pm->n_active; i++)
    {
      if (pt->pm_fds[i] == 0)
	continue;

      if (ioctl (pt->pm_fds[i], PERF_EVENT_IOC_DISABLE, 0) < 0)
	clib_unix_warning ("disable ioctl");

      if (pt->perf_event_pages[i])
	{
	  if (munmap (pt->perf_event_pages[i], pm->page_size) < 0)
	    clib_unix_warning ("munmap");
	  pt->perf_event_pages[i] = 0;
	}

      (void) close (pt->pm_fds[i]);
      pt->pm_fds[i] = 0;
    }
}

static void
worker_thread_start_event (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;

  clib_callback_enable_disable (vm->worker_thread_main_loop_callbacks,
				vm->worker_thread_main_loop_callback_tmp,
				vm->worker_thread_main_loop_callback_lock,
				worker_thread_start_event, 0 /* disable */ );
  enable_current_events (pm);
}

static void
worker_thread_stop_event (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;
  clib_callback_enable_disable (vm->worker_thread_main_loop_callbacks,
				vm->worker_thread_main_loop_callback_tmp,
				vm->worker_thread_main_loop_callback_lock,
				worker_thread_stop_event, 0 /* disable */ );
  disable_events (pm);
}

static void
start_event (perfmon_main_t * pm, f64 now, uword event_data)
{
  int i;
  int last_set;
  int all = 0;
  pm->current_event = 0;

  if (vec_len (pm->single_events_to_collect) == 0)
    {
      pm->state = PERFMON_STATE_OFF;
      return;
    }

  last_set = clib_bitmap_last_set (pm->thread_bitmap);
  all = (last_set == ~0);

  pm->state = PERFMON_STATE_RUNNING;
  clear_counters (pm);

  /* Start collection on thread 0? */
  if (all || clib_bitmap_get (pm->thread_bitmap, 0))
    {
      /* Start collection on this thread */
      enable_current_events (pm);
    }

  /* And also on worker threads */
  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      if (vlib_mains[i] == 0)
	continue;

      if (all || clib_bitmap_get (pm->thread_bitmap, i))
	clib_callback_enable_disable
	  (vlib_mains[i]->worker_thread_main_loop_callbacks,
	   vlib_mains[i]->worker_thread_main_loop_callback_tmp,
	   vlib_mains[i]->worker_thread_main_loop_callback_lock,
	   (void *) worker_thread_start_event, 1 /* enable */ );
    }
}

void
scrape_and_clear_counters (perfmon_main_t * pm)
{
  int i, j, k;
  vlib_main_t *vm = pm->vlib_main;
  vlib_main_t *stat_vm;
  vlib_node_main_t *nm;
  perfmon_counters_t *ctr;
  perfmon_counters_t *ctrs;
  perfmon_counters_t **ctr_dups = 0;
  perfmon_thread_t *pt;
  perfmon_capture_t *c;
  perfmon_event_config_t *current_event;
  uword *p;
  u8 *counter_name;
  u32 len;

  /* snapshoot the nodes, including pm counters */
  vlib_worker_thread_barrier_sync (vm);

  for (j = 0; j < vec_len (vlib_mains); j++)
    {
      stat_vm = vlib_mains[j];
      if (stat_vm == 0)
	continue;

      pt = pm->threads[j];
      len = vec_len (pt->counters);
      ctrs = 0;
      if (len)
	{
	  vec_validate (ctrs, len - 1);
	  clib_memcpy (ctrs, pt->counters, len * sizeof (pt->counters[0]));
	  clib_memset (pt->counters, 0, len * sizeof (pt->counters[0]));
	}
      vec_add1 (ctr_dups, ctrs);
    }

  vlib_worker_thread_barrier_release (vm);

  for (j = 0; j < vec_len (vlib_mains); j++)
    {
      stat_vm = vlib_mains[j];
      if (stat_vm == 0)
	continue;

      pt = pm->threads[j];
      ctrs = ctr_dups[j];

      for (i = 0; i < vec_len (ctrs); i++)
	{
	  u8 *capture_name;

	  ctr = &ctrs[i];
	  nm = &stat_vm->node_main;

	  if (ctr->ticks[0] == 0 && ctr->ticks[1] == 0)
	    continue;

	  for (k = 0; k < 2; k++)
	    {
	      /*
	       * We collect 2 counters at once, except for the
	       * last counter when the user asks for an odd number of
	       * counters
	       */
	      if ((pm->current_event + k)
		  >= vec_len (pm->single_events_to_collect))
		break;

	      capture_name = format (0, "t%d-%v%c", j, nm->nodes[i]->name, 0);

	      p = hash_get_mem (pm->capture_by_thread_and_node_name,
				capture_name);

	      if (p == 0)
		{
		  pool_get (pm->capture_pool, c);
		  memset (c, 0, sizeof (*c));
		  c->thread_and_node_name = capture_name;
		  hash_set_mem (pm->capture_by_thread_and_node_name,
				capture_name, c - pm->capture_pool);
		}
	      else
		{
		  c = pool_elt_at_index (pm->capture_pool, p[0]);
		  vec_free (capture_name);
		}

	      /* Snapshoot counters, etc. into the capture */
	      current_event = pm->single_events_to_collect
		+ pm->current_event + k;
	      counter_name = (u8 *) current_event->name;

	      vec_add1 (c->counter_names, counter_name);
	      vec_add1 (c->counter_values, ctr->ticks[k]);
	      vec_add1 (c->vectors_this_counter, ctr->vectors);
	    }
	}
      vec_free (ctrs);
    }
  vec_free (ctr_dups);
}

static void
handle_timeout (vlib_main_t * vm, perfmon_main_t * pm, f64 now)
{
  int i;
  int last_set, all;

  last_set = clib_bitmap_last_set (pm->thread_bitmap);
  all = (last_set == ~0);

  if (all || clib_bitmap_get (pm->thread_bitmap, 0))
    disable_events (pm);

  /* And also on worker threads */
  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      if (vlib_mains[i] == 0)
	continue;
      if (all || clib_bitmap_get (pm->thread_bitmap, i))
	clib_callback_enable_disable
	  (vlib_mains[i]->worker_thread_main_loop_callbacks,
	   vlib_mains[i]->worker_thread_main_loop_callback_tmp,
	   vlib_mains[i]->worker_thread_main_loop_callback_lock,
	   (void *) worker_thread_stop_event, 1 /* enable */ );
    }

  /* Make sure workers have stopped collection */
  if (i > 1)
    {
      f64 deadman = vlib_time_now (vm) + 1.0;

      for (i = 1; i < vec_len (vlib_mains); i++)
	{
	  /* Has the worker actually stopped collecting data? */
	  while (clib_callback_data_is_set
		 (&vm->vlib_node_runtime_perf_callbacks,
		  read_current_perf_counters))
	    {
	      if (vlib_time_now (vm) > deadman)
		{
		  clib_warning ("Thread %d deadman timeout!", i);
		  break;
		}
	      vlib_process_suspend (pm->vlib_main, 1e-3);
	    }
	}
    }
  scrape_and_clear_counters (pm);
  pm->current_event += pm->n_active;
  if (pm->current_event >= vec_len (pm->single_events_to_collect))
    {
      pm->current_event = 0;
      pm->state = PERFMON_STATE_OFF;
      return;
    }

  if (all || clib_bitmap_get (pm->thread_bitmap, 0))
    enable_current_events (pm);

  /* And also on worker threads */
  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      if (vlib_mains[i] == 0)
	continue;
      if (all || clib_bitmap_get (pm->thread_bitmap, i))
	clib_callback_enable_disable
	  (vlib_mains[i]->worker_thread_main_loop_callbacks,
	   vlib_mains[i]->worker_thread_main_loop_callback_tmp,
	   vlib_mains[i]->worker_thread_main_loop_callback_lock,
	   worker_thread_start_event, 0 /* disable */ );
    }
}

static uword
perfmon_periodic_process (vlib_main_t * vm,
			  vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  perfmon_main_t *pm = &perfmon_main;
  f64 now;
  uword *event_data = 0;
  uword event_type;
  int i;

  while (1)
    {
      if (pm->state == PERFMON_STATE_RUNNING)
	vlib_process_wait_for_event_or_clock (vm, pm->timeout_interval);
      else
	vlib_process_wait_for_event (vm);

      now = vlib_time_now (vm);

      event_type = vlib_process_get_events (vm, (uword **) & event_data);

      switch (event_type)
	{
	case PERFMON_START:
	  for (i = 0; i < vec_len (event_data); i++)
	    start_event (pm, now, event_data[i]);
	  break;

	  /* Handle timeout */
	case ~0:
	  handle_timeout (vm, pm, now);
	  break;

	default:
	  clib_warning ("Unexpected event %d", event_type);
	  break;
	}
      vec_reset_length (event_data);
    }
  return 0;			/* or not */
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (perfmon_periodic_node) =
{
  .function = perfmon_periodic_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "perfmon-periodic-process",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
