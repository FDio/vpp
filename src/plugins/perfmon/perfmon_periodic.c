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

static long
perf_event_open (struct perf_event_attr *hw_event, pid_t pid, int cpu,
		 int group_fd, unsigned long flags)
{
  int ret;

  ret = syscall (__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
  return ret;
}

int
perfmon_test_event (char *name, int pe_type, unsigned long pe_config)
{
  struct perf_event_attr pe;
  int fd;
  //perfmon_event_config_t *c;

  memset (&pe, 0, sizeof (struct perf_event_attr));
  pe.type = pe_type;
  pe.size = sizeof (struct perf_event_attr);
  pe.config = pe_config;
  pe.disabled = 1;
  pe.pinned = 1;

  fd = perf_event_open (&pe, 0, -1, -1, 0);
  if (fd == -1)
    {
      clib_unix_warning ("event open: type %d config %d", pe_type, pe_config);
      return -1;
    }

  close (fd);
  return 0;
}

static u64
read_current_perf_counter (vlib_main_t * vm)
{
  if (vm->perf_counter_id)
    return clib_rdpmc (vm->perf_counter_id);
  else
    {
      u64 sw_value;
      if (read (vm->perf_counter_fd, &sw_value, sizeof (sw_value)) !=
	  sizeof (sw_value))
	{
	  clib_unix_warning ("counter read failed, disable collection...");
	  vm->vlib_node_runtime_perf_counter_cb = 0;
	  return 0ULL;
	}
      return sw_value;
    }
}

static void
clear_counters (perfmon_main_t * pm)
{
  int i, j;
  vlib_main_t *vm = pm->vlib_main;
  vlib_main_t *stat_vm;
  vlib_node_main_t *nm;
  vlib_node_t *n;

  vlib_worker_thread_barrier_sync (vm);

  for (j = 0; j < vec_len (vlib_mains); j++)
    {
      stat_vm = vlib_mains[j];
      if (stat_vm == 0)
	continue;

      nm = &stat_vm->node_main;

      /* Clear the node runtime perfmon counters */
      for (i = 0; i < vec_len (nm->nodes); i++)
	{
	  n = nm->nodes[i];
	  vlib_node_sync_stats (stat_vm, n);
	}

      /* And clear the node perfmon counters */
      for (i = 0; i < vec_len (nm->nodes); i++)
	{
	  n = nm->nodes[i];
	  n->stats_total.perf_counter_ticks = 0;
	  n->stats_total.perf_counter_vectors = 0;
	  n->stats_last_clear.perf_counter_ticks = 0;
	  n->stats_last_clear.perf_counter_vectors = 0;
	}
    }
  vlib_worker_thread_barrier_release (vm);
}

static void
enable_current_event (perfmon_main_t * pm)
{
  struct perf_event_attr pe;
  int fd;
  struct perf_event_mmap_page *p = 0;
  perfmon_event_config_t *c;
  vlib_main_t *vm = vlib_get_main ();
  u32 my_thread_index = vm->thread_index;

  c = vec_elt_at_index (pm->events_to_collect, pm->current_event);

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

  fd = perf_event_open (&pe, 0, -1, -1, 0);
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
    }

  if (ioctl (fd, PERF_EVENT_IOC_RESET, 0) < 0)
    clib_unix_warning ("reset ioctl");

  if (ioctl (fd, PERF_EVENT_IOC_ENABLE, 0) < 0)
    clib_unix_warning ("enable ioctl");

  /*
   * Software event counters - and others not capable of being
   * read via the "rdpmc" instruction - will be read
   * by system calls.
   */
  if (pe.type == PERF_TYPE_SOFTWARE || p->cap_user_rdpmc == 0)
    pm->rdpmc_indices[my_thread_index] = 0;
  else				/* use rdpmc instrs */
    pm->rdpmc_indices[my_thread_index] = p->index - 1;
  pm->perf_event_pages[my_thread_index] = (void *) p;

  pm->pm_fds[my_thread_index] = fd;

  /* Enable the main loop counter snapshot mechanism */
  vm->perf_counter_id = pm->rdpmc_indices[my_thread_index];
  vm->perf_counter_fd = fd;
  vm->vlib_node_runtime_perf_counter_cb = read_current_perf_counter;
}

static void
disable_event (perfmon_main_t * pm)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 my_thread_index = vm->thread_index;

  if (pm->pm_fds[my_thread_index] == 0)
    return;

  /* Stop main loop collection */
  vm->vlib_node_runtime_perf_counter_cb = 0;

  if (ioctl (pm->pm_fds[my_thread_index], PERF_EVENT_IOC_DISABLE, 0) < 0)
    clib_unix_warning ("disable ioctl");

  if (pm->perf_event_pages[my_thread_index])
    if (munmap (pm->perf_event_pages[my_thread_index], pm->page_size) < 0)
      clib_unix_warning ("munmap");

  (void) close (pm->pm_fds[my_thread_index]);
  pm->pm_fds[my_thread_index] = 0;
}

static void
worker_thread_start_event (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;

  enable_current_event (pm);
  vm->worker_thread_main_loop_callback = 0;
}

static void
worker_thread_stop_event (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;
  disable_event (pm);
  vm->worker_thread_main_loop_callback = 0;
}

static void
start_event (perfmon_main_t * pm, f64 now, uword event_data)
{
  int i;
  pm->current_event = 0;
  if (vec_len (pm->events_to_collect) == 0)
    {
      pm->state = PERFMON_STATE_OFF;
      return;
    }
  pm->state = PERFMON_STATE_RUNNING;
  clear_counters (pm);

  /* Start collection on this thread */
  enable_current_event (pm);

  /* And also on worker threads */
  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      if (vlib_mains[i] == 0)
	continue;
      vlib_mains[i]->worker_thread_main_loop_callback = (void *)
	worker_thread_start_event;
    }
}

void
scrape_and_clear_counters (perfmon_main_t * pm)
{
  int i, j;
  vlib_main_t *vm = pm->vlib_main;
  vlib_main_t *stat_vm;
  vlib_node_main_t *nm;
  vlib_node_t ***node_dups = 0;
  vlib_node_t **nodes;
  vlib_node_t *n;
  perfmon_capture_t *c;
  perfmon_event_config_t *current_event;
  uword *p;
  u8 *counter_name;
  u64 counter_value;
  u64 vectors_this_counter;

  /* snapshoot the nodes, including pm counters */
  vlib_worker_thread_barrier_sync (vm);

  for (j = 0; j < vec_len (vlib_mains); j++)
    {
      stat_vm = vlib_mains[j];
      if (stat_vm == 0)
	continue;

      nm = &stat_vm->node_main;

      for (i = 0; i < vec_len (nm->nodes); i++)
	{
	  n = nm->nodes[i];
	  vlib_node_sync_stats (stat_vm, n);
	}

      nodes = 0;
      vec_validate (nodes, vec_len (nm->nodes) - 1);
      vec_add1 (node_dups, nodes);

      /* Snapshoot and clear the per-node perfmon counters */
      for (i = 0; i < vec_len (nm->nodes); i++)
	{
	  n = nm->nodes[i];
	  nodes[i] = clib_mem_alloc (sizeof (*n));
	  clib_memcpy_fast (nodes[i], n, sizeof (*n));
	  n->stats_total.perf_counter_ticks = 0;
	  n->stats_total.perf_counter_vectors = 0;
	  n->stats_last_clear.perf_counter_ticks = 0;
	  n->stats_last_clear.perf_counter_vectors = 0;
	}
    }

  vlib_worker_thread_barrier_release (vm);

  current_event = pm->events_to_collect + pm->current_event;

  for (j = 0; j < vec_len (vlib_mains); j++)
    {
      stat_vm = vlib_mains[j];
      if (stat_vm == 0)
	continue;

      nodes = node_dups[j];

      for (i = 0; i < vec_len (nodes); i++)
	{
	  u8 *capture_name;

	  n = nodes[i];
	  if (n->stats_total.perf_counter_ticks == 0)
	    {
	      clib_mem_free (n);
	      continue;
	    }

	  capture_name = format (0, "t%d-%v%c", j, n->name, 0);

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
	    c = pool_elt_at_index (pm->capture_pool, p[0]);

	  /* Snapshoot counters, etc. into the capture */
	  counter_name = (u8 *) current_event->name;
	  counter_value = n->stats_total.perf_counter_ticks -
	    n->stats_last_clear.perf_counter_ticks;
	  vectors_this_counter = n->stats_total.perf_counter_vectors -
	    n->stats_last_clear.perf_counter_vectors;

	  vec_add1 (c->counter_names, counter_name);
	  vec_add1 (c->counter_values, counter_value);
	  vec_add1 (c->vectors_this_counter, vectors_this_counter);
	  clib_mem_free (n);
	}
      vec_free (nodes);
    }
  vec_free (node_dups);
}

static void
handle_timeout (perfmon_main_t * pm, f64 now)
{
  int i;
  disable_event (pm);

  /* And also on worker threads */
  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      if (vlib_mains[i] == 0)
	continue;
      vlib_mains[i]->worker_thread_main_loop_callback = (void *)
	worker_thread_stop_event;
    }

  /* Short delay to make sure workers have stopped collection */
  if (i > 1)
    vlib_process_suspend (pm->vlib_main, 1e-3);
  scrape_and_clear_counters (pm);
  pm->current_event++;
  if (pm->current_event >= vec_len (pm->events_to_collect))
    {
      pm->current_event = 0;
      pm->state = PERFMON_STATE_OFF;
      return;
    }
  enable_current_event (pm);

  /* And also on worker threads */
  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      if (vlib_mains[i] == 0)
	continue;
      vlib_mains[i]->worker_thread_main_loop_callback = (void *)
	worker_thread_start_event;
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
	  handle_timeout (pm, now);
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
