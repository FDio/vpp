/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#define _GNU_SOURCE

#include <signal.h>
#include <math.h>
#include <vppinfra/format.h>
#include <vppinfra/time_range.h>
#include <vppinfra/interrupt.h>
#include <vppinfra/linux/sysfs.h>
#include <vlib/vlib.h>

#include <vlib/threads.h>

#include <vlib/stat_weak_inlines.h>

u32
vl (void *p)
{
  return vec_len (p);
}

vlib_worker_thread_t *vlib_worker_threads;
vlib_thread_main_t vlib_thread_main;

/*
 * Barrier tracing can be enabled on a normal build to collect information
 * on barrier use, including timings and call stacks.  Deliberately not
 * keyed off CLIB_DEBUG, because that can add significant overhead which
 * imapacts observed timings.
 */

static inline void
barrier_trace_sync (f64 t_entry, f64 t_open, f64 t_closed)
{
  if (!vlib_worker_threads->barrier_elog_enabled)
    return;

  ELOG_TYPE_DECLARE (e) = {
    .format = "bar-trace-%s-#%d",
    .format_args = "T4i4",
  };

  struct
  {
    u32 caller, count, t_entry, t_open, t_closed;
  } *ed = 0;

  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
  ed->count = (int) vlib_worker_threads[0].barrier_sync_count;
  ed->caller = elog_string (&vlib_global_main.elog_main,
			    (char *) vlib_worker_threads[0].barrier_caller);
  ed->t_entry = (int) (1000000.0 * t_entry);
  ed->t_open = (int) (1000000.0 * t_open);
  ed->t_closed = (int) (1000000.0 * t_closed);
}

static inline void
barrier_trace_sync_rec (f64 t_entry)
{
  if (!vlib_worker_threads->barrier_elog_enabled)
    return;

  ELOG_TYPE_DECLARE (e) = {
    .format = "bar-syncrec-%s-#%d",
    .format_args = "T4i4",
  };

  struct
  {
    u32 caller, depth;
  } *ed = 0;

  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
  ed->depth = (int) vlib_worker_threads[0].recursion_level - 1;
  ed->caller = elog_string (&vlib_global_main.elog_main,
			    (char *) vlib_worker_threads[0].barrier_caller);
}

static inline void
barrier_trace_release_rec (f64 t_entry)
{
  if (!vlib_worker_threads->barrier_elog_enabled)
    return;

  ELOG_TYPE_DECLARE (e) = {
    .format = "bar-relrrec-#%d",
    .format_args = "i4",
  };

  struct
  {
    u32 depth;
  } *ed = 0;

  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
  ed->depth = (int) vlib_worker_threads[0].recursion_level;
}

static inline void
barrier_trace_release (f64 t_entry, f64 t_closed_total, f64 t_update_main)
{
  if (!vlib_worker_threads->barrier_elog_enabled)
    return;

  ELOG_TYPE_DECLARE (e) = {
    .format = "bar-rel-#%d-e%d-u%d-t%d",
    .format_args = "i4i4i4i4",
  };

  struct
  {
    u32 count, t_entry, t_update_main, t_closed_total;
  } *ed = 0;

  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
  ed->t_entry = (int) (1000000.0 * t_entry);
  ed->t_update_main = (int) (1000000.0 * t_update_main);
  ed->t_closed_total = (int) (1000000.0 * t_closed_total);
  ed->count = (int) vlib_worker_threads[0].barrier_sync_count;

  /* Reset context for next trace */
  vlib_worker_threads[0].barrier_context = NULL;
}

uword
os_get_nthreads (void)
{
  return vec_len (vlib_thread_stacks);
}

void
vlib_set_thread_name (char *name)
{
  int pthread_setname_np (pthread_t __target_thread, const char *__name);
  int rv;
  pthread_t thread = pthread_self ();

  if (thread)
    {
      rv = pthread_setname_np (thread, name);
      if (rv)
	clib_warning ("pthread_setname_np returned %d", rv);
    }
}

static int
sort_registrations_by_no_clone (void *a0, void *a1)
{
  vlib_thread_registration_t **tr0 = a0;
  vlib_thread_registration_t **tr1 = a1;

  return ((i32) ((*tr0)->no_data_structure_clone)
	  - ((i32) ((*tr1)->no_data_structure_clone)));
}

static uword *
clib_sysfs_list_to_bitmap (char *filename)
{
  FILE *fp;
  uword *r = 0;

  fp = fopen (filename, "r");

  if (fp != NULL)
    {
      u8 *buffer = 0;
      vec_validate (buffer, 256 - 1);
      if (fgets ((char *) buffer, 256, fp))
	{
	  unformat_input_t in;
	  unformat_init_string (&in, (char *) buffer,
				strlen ((char *) buffer));
	  if (unformat (&in, "%U", unformat_bitmap_list, &r) != 1)
	    clib_warning ("unformat_bitmap_list failed");
	  unformat_free (&in);
	}
      vec_free (buffer);
      fclose (fp);
    }
  return r;
}


/* Called early in the init sequence */

clib_error_t *
vlib_thread_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = &vlib_thread_main;
  vlib_worker_thread_t *w;
  vlib_thread_registration_t *tr;
  u32 n_vlib_mains = 1;
  u32 first_index = 1;
  u32 i;
  uword *avail_cpu;

  /* get bitmaps of active cpu cores and sockets */
  tm->cpu_core_bitmap =
    clib_sysfs_list_to_bitmap ("/sys/devices/system/cpu/online");
  tm->cpu_socket_bitmap =
    clib_sysfs_list_to_bitmap ("/sys/devices/system/node/online");

  avail_cpu = clib_bitmap_dup (tm->cpu_core_bitmap);

  /* skip cores */
  for (i = 0; i < tm->skip_cores; i++)
    {
      uword c = clib_bitmap_first_set (avail_cpu);
      if (c == ~0)
	return clib_error_return (0, "no available cpus to skip");

      avail_cpu = clib_bitmap_set (avail_cpu, c, 0);
    }

  /* grab cpu for main thread */
  if (tm->main_lcore == ~0)
    {
      /* if main-lcore is not set, we try to use lcore 1 */
      if (clib_bitmap_get (avail_cpu, 1))
	tm->main_lcore = 1;
      else
	tm->main_lcore = clib_bitmap_first_set (avail_cpu);
      if (tm->main_lcore == (u8) ~ 0)
	return clib_error_return (0, "no available cpus to be used for the"
				  " main thread");
    }
  else
    {
      if (clib_bitmap_get (avail_cpu, tm->main_lcore) == 0)
	return clib_error_return (0, "cpu %u is not available to be used"
				  " for the main thread", tm->main_lcore);
    }
  avail_cpu = clib_bitmap_set (avail_cpu, tm->main_lcore, 0);

  /* assume that there is socket 0 only if there is no data from sysfs */
  if (!tm->cpu_socket_bitmap)
    tm->cpu_socket_bitmap = clib_bitmap_set (0, 0, 1);

  /* pin main thread to main_lcore  */
  if (tm->cb.vlib_thread_set_lcore_cb)
    {
      tm->cb.vlib_thread_set_lcore_cb (0, tm->main_lcore);
    }
  else
    {
      cpu_set_t cpuset;
      CPU_ZERO (&cpuset);
      CPU_SET (tm->main_lcore, &cpuset);
      pthread_setaffinity_np (pthread_self (), sizeof (cpu_set_t), &cpuset);
    }

  /* Set up thread 0 */
  vec_validate_aligned (vlib_worker_threads, 0, CLIB_CACHE_LINE_BYTES);
  _vec_len (vlib_worker_threads) = 1;
  w = vlib_worker_threads;
  w->thread_mheap = clib_mem_get_heap ();
  w->thread_stack = vlib_thread_stacks[0];
  w->cpu_id = tm->main_lcore;
  w->lwp = syscall (SYS_gettid);
  w->thread_id = pthread_self ();
  tm->n_vlib_mains = 1;

  vlib_get_thread_core_numa (w, w->cpu_id);

  if (tm->sched_policy != ~0)
    {
      struct sched_param sched_param;
      if (!sched_getparam (w->lwp, &sched_param))
	{
	  if (tm->sched_priority != ~0)
	    sched_param.sched_priority = tm->sched_priority;
	  sched_setscheduler (w->lwp, tm->sched_policy, &sched_param);
	}
    }

  /* assign threads to cores and set n_vlib_mains */
  tr = tm->next;

  while (tr)
    {
      vec_add1 (tm->registrations, tr);
      tr = tr->next;
    }

  vec_sort_with_function (tm->registrations, sort_registrations_by_no_clone);

  for (i = 0; i < vec_len (tm->registrations); i++)
    {
      int j;
      tr = tm->registrations[i];
      tr->first_index = first_index;
      first_index += tr->count;
      n_vlib_mains += (tr->no_data_structure_clone == 0) ? tr->count : 0;

      /* construct coremask */
      if (tr->use_pthreads || !tr->count)
	continue;

      if (tr->coremask)
	{
	  uword c;
          /* *INDENT-OFF* */
          clib_bitmap_foreach (c, tr->coremask)  {
            if (clib_bitmap_get(avail_cpu, c) == 0)
              return clib_error_return (0, "cpu %u is not available to be used"
                                        " for the '%s' thread",c, tr->name);

            avail_cpu = clib_bitmap_set(avail_cpu, c, 0);
          }
          /* *INDENT-ON* */
	}
      else
	{
	  for (j = 0; j < tr->count; j++)
	    {
	      /* Do not use CPU 0 by default - leave it to the host and IRQs */
	      uword avail_c0 = clib_bitmap_get (avail_cpu, 0);
	      avail_cpu = clib_bitmap_set (avail_cpu, 0, 0);

	      uword c = clib_bitmap_first_set (avail_cpu);
	      /* Use CPU 0 as a last resort */
	      if (c == ~0 && avail_c0)
		{
		  c = 0;
		  avail_c0 = 0;
		}

	      if (c == ~0)
		return clib_error_return (0,
					  "no available cpus to be used for"
					  " the '%s' thread", tr->name);

	      avail_cpu = clib_bitmap_set (avail_cpu, 0, avail_c0);
	      avail_cpu = clib_bitmap_set (avail_cpu, c, 0);
	      tr->coremask = clib_bitmap_set (tr->coremask, c, 1);
	    }
	}
    }

  clib_bitmap_free (avail_cpu);

  tm->n_vlib_mains = n_vlib_mains;

  /*
   * Allocate the remaining worker threads, and thread stack vector slots
   * from now on, calls to os_get_nthreads() will return the correct
   * answer.
   */
  vec_validate_aligned (vlib_worker_threads, first_index - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_validate (vlib_thread_stacks, vec_len (vlib_worker_threads) - 1);
  return 0;
}

vlib_frame_queue_t *
vlib_frame_queue_alloc (int nelts)
{
  vlib_frame_queue_t *fq;

  fq = clib_mem_alloc_aligned (sizeof (*fq), CLIB_CACHE_LINE_BYTES);
  clib_memset (fq, 0, sizeof (*fq));
  fq->nelts = nelts;
  fq->vector_threshold = 128;	// packets
  vec_validate_aligned (fq->elts, nelts - 1, CLIB_CACHE_LINE_BYTES);

  if (1)
    {
      if (((uword) & fq->tail) & (CLIB_CACHE_LINE_BYTES - 1))
	fformat (stderr, "WARNING: fq->tail unaligned\n");
      if (((uword) & fq->head) & (CLIB_CACHE_LINE_BYTES - 1))
	fformat (stderr, "WARNING: fq->head unaligned\n");
      if (((uword) fq->elts) & (CLIB_CACHE_LINE_BYTES - 1))
	fformat (stderr, "WARNING: fq->elts unaligned\n");

      if (sizeof (fq->elts[0]) % CLIB_CACHE_LINE_BYTES)
	fformat (stderr, "WARNING: fq->elts[0] size %d\n",
		 sizeof (fq->elts[0]));
      if (nelts & (nelts - 1))
	{
	  fformat (stderr, "FATAL: nelts MUST be a power of 2\n");
	  abort ();
	}
    }

  return (fq);
}

void vl_msg_api_handler_no_free (void *) __attribute__ ((weak));
void
vl_msg_api_handler_no_free (void *v)
{
}

/* Turned off, save as reference material... */
#if 0
static inline int
vlib_frame_queue_dequeue_internal (int thread_id,
				   vlib_main_t * vm, vlib_node_main_t * nm)
{
  vlib_frame_queue_t *fq = vlib_frame_queues[thread_id];
  vlib_frame_queue_elt_t *elt;
  vlib_frame_t *f;
  vlib_pending_frame_t *p;
  vlib_node_runtime_t *r;
  u32 node_runtime_index;
  int msg_type;
  u64 before;
  int processed = 0;

  ASSERT (vm == vlib_mains[thread_id]);

  while (1)
    {
      if (fq->head == fq->tail)
	return processed;

      elt = fq->elts + ((fq->head + 1) & (fq->nelts - 1));

      if (!elt->valid)
	return processed;

      before = clib_cpu_time_now ();

      f = elt->frame;
      node_runtime_index = elt->node_runtime_index;
      msg_type = elt->msg_type;

      switch (msg_type)
	{
	case VLIB_FRAME_QUEUE_ELT_FREE_BUFFERS:
	  vlib_buffer_free (vm, vlib_frame_vector_args (f), f->n_vectors);
	  /* note fallthrough... */
	case VLIB_FRAME_QUEUE_ELT_FREE_FRAME:
	  r = vec_elt_at_index (nm->nodes_by_type[VLIB_NODE_TYPE_INTERNAL],
				node_runtime_index);
	  vlib_frame_free (vm, r, f);
	  break;
	case VLIB_FRAME_QUEUE_ELT_DISPATCH_FRAME:
	  vec_add2 (vm->node_main.pending_frames, p, 1);
	  f->flags |= (VLIB_FRAME_PENDING | VLIB_FRAME_FREE_AFTER_DISPATCH);
	  p->node_runtime_index = elt->node_runtime_index;
	  p->frame_index = vlib_frame_index (vm, f);
	  p->next_frame_index = VLIB_PENDING_FRAME_NO_NEXT_FRAME;
	  fq->dequeue_vectors += (u64) f->n_vectors;
	  break;
	case VLIB_FRAME_QUEUE_ELT_API_MSG:
	  vl_msg_api_handler_no_free (f);
	  break;
	default:
	  clib_warning ("bogus frame queue message, type %d", msg_type);
	  break;
	}
      elt->valid = 0;
      fq->dequeues++;
      fq->dequeue_ticks += clib_cpu_time_now () - before;
      CLIB_MEMORY_BARRIER ();
      fq->head++;
      processed++;
    }
  ASSERT (0);
  return processed;
}

int
vlib_frame_queue_dequeue (int thread_id,
			  vlib_main_t * vm, vlib_node_main_t * nm)
{
  return vlib_frame_queue_dequeue_internal (thread_id, vm, nm);
}

int
vlib_frame_queue_enqueue (vlib_main_t * vm, u32 node_runtime_index,
			  u32 frame_queue_index, vlib_frame_t * frame,
			  vlib_frame_queue_msg_type_t type)
{
  vlib_frame_queue_t *fq = vlib_frame_queues[frame_queue_index];
  vlib_frame_queue_elt_t *elt;
  u32 save_count;
  u64 new_tail;
  u64 before = clib_cpu_time_now ();

  ASSERT (fq);

  new_tail = clib_atomic_add_fetch (&fq->tail, 1);

  /* Wait until a ring slot is available */
  while (new_tail >= fq->head + fq->nelts)
    {
      f64 b4 = vlib_time_now_ticks (vm, before);
      vlib_worker_thread_barrier_check (vm, b4);
      /* Bad idea. Dequeue -> enqueue -> dequeue -> trouble */
      // vlib_frame_queue_dequeue (vm->thread_index, vm, nm);
    }

  elt = fq->elts + (new_tail & (fq->nelts - 1));

  /* this would be very bad... */
  while (elt->valid)
    {
    }

  /* Once we enqueue the frame, frame->n_vectors is owned elsewhere... */
  save_count = frame->n_vectors;

  elt->frame = frame;
  elt->node_runtime_index = node_runtime_index;
  elt->msg_type = type;
  CLIB_MEMORY_BARRIER ();
  elt->valid = 1;

  return save_count;
}
#endif /* 0 */

/* To be called by vlib worker threads upon startup */
void
vlib_worker_thread_init (vlib_worker_thread_t * w)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  /*
   * Note: disabling signals in worker threads as follows
   * prevents the api post-mortem dump scheme from working
   * {
   *    sigset_t s;
   *    sigfillset (&s);
   *    pthread_sigmask (SIG_SETMASK, &s, 0);
   *  }
   */

  clib_mem_set_heap (w->thread_mheap);

  if (vec_len (tm->thread_prefix) && w->registration->short_name)
    {
      w->name = format (0, "%v_%s_%d%c", tm->thread_prefix,
			w->registration->short_name, w->instance_id, '\0');
      vlib_set_thread_name ((char *) w->name);
    }

  if (!w->registration->use_pthreads)
    {

      /* Initial barrier sync, for both worker and i/o threads */
      clib_atomic_fetch_add (vlib_worker_threads->workers_at_barrier, 1);

      while (*vlib_worker_threads->wait_at_barrier)
	;

      clib_atomic_fetch_add (vlib_worker_threads->workers_at_barrier, -1);
    }
}

void *
vlib_worker_thread_bootstrap_fn (void *arg)
{
  void *rv;
  vlib_worker_thread_t *w = arg;

  w->lwp = syscall (SYS_gettid);
  w->thread_id = pthread_self ();

  __os_thread_index = w - vlib_worker_threads;

  vlib_process_start_switch_stack (vlib_mains[__os_thread_index], 0);
  rv = (void *) clib_calljmp
    ((uword (*)(uword)) w->thread_function,
     (uword) arg, w->thread_stack + VLIB_THREAD_STACK_SIZE);
  /* NOTREACHED, we hope */
  return rv;
}

void
vlib_get_thread_core_numa (vlib_worker_thread_t * w, unsigned cpu_id)
{
  const char *sys_cpu_path = "/sys/devices/system/cpu/cpu";
  const char *sys_node_path = "/sys/devices/system/node/node";
  clib_bitmap_t *nbmp = 0, *cbmp = 0;
  u32 node;
  u8 *p = 0;
  int core_id = -1, numa_id = -1;

  p = format (p, "%s%u/topology/core_id%c", sys_cpu_path, cpu_id, 0);
  clib_sysfs_read ((char *) p, "%d", &core_id);
  vec_reset_length (p);

  /* *INDENT-OFF* */
  clib_sysfs_read ("/sys/devices/system/node/online", "%U",
        unformat_bitmap_list, &nbmp);
  clib_bitmap_foreach (node, nbmp)  {
    p = format (p, "%s%u/cpulist%c", sys_node_path, node, 0);
    clib_sysfs_read ((char *) p, "%U", unformat_bitmap_list, &cbmp);
    if (clib_bitmap_get (cbmp, cpu_id))
      numa_id = node;
    vec_reset_length (cbmp);
    vec_reset_length (p);
  }
  /* *INDENT-ON* */
  vec_free (nbmp);
  vec_free (cbmp);
  vec_free (p);

  w->core_id = core_id;
  w->numa_id = numa_id;
}

static clib_error_t *
vlib_launch_thread_int (void *fp, vlib_worker_thread_t * w, unsigned cpu_id)
{
  clib_mem_main_t *mm = &clib_mem_main;
  vlib_thread_main_t *tm = &vlib_thread_main;
  void *(*fp_arg) (void *) = fp;
  void *numa_heap;

  w->cpu_id = cpu_id;
  vlib_get_thread_core_numa (w, cpu_id);

  /* Set up NUMA-bound heap if indicated */
  if (mm->per_numa_mheaps[w->numa_id] == 0)
    {
      /* If the user requested a NUMA heap, create it... */
      if (tm->numa_heap_size)
	{
	  clib_mem_set_numa_affinity (w->numa_id, 1 /* force */ );
	  numa_heap = clib_mem_create_heap (0 /* DIY */ , tm->numa_heap_size,
					    1 /* is_locked */ ,
					    "numa %u heap", w->numa_id);
	  clib_mem_set_default_numa_affinity ();
	  mm->per_numa_mheaps[w->numa_id] = numa_heap;
	}
      else
	{
	  /* Or, use the main heap */
	  mm->per_numa_mheaps[w->numa_id] = w->thread_mheap;
	}
    }

  if (tm->cb.vlib_launch_thread_cb && !w->registration->use_pthreads)
    return tm->cb.vlib_launch_thread_cb (fp, (void *) w, cpu_id);
  else
    {
      pthread_t worker;
      cpu_set_t cpuset;
      CPU_ZERO (&cpuset);
      CPU_SET (cpu_id, &cpuset);

      if (pthread_create (&worker, NULL /* attr */ , fp_arg, (void *) w))
	return clib_error_return_unix (0, "pthread_create");

      if (pthread_setaffinity_np (worker, sizeof (cpu_set_t), &cpuset))
	return clib_error_return_unix (0, "pthread_setaffinity_np");

      return 0;
    }
}

static clib_error_t *
start_workers (vlib_main_t * vm)
{
  int i, j;
  vlib_worker_thread_t *w;
  vlib_main_t *vm_clone;
  void *oldheap;
  vlib_thread_main_t *tm = &vlib_thread_main;
  vlib_thread_registration_t *tr;
  vlib_node_runtime_t *rt;
  u32 n_vlib_mains = tm->n_vlib_mains;
  u32 worker_thread_index;
  clib_mem_heap_t *main_heap = clib_mem_get_per_cpu_heap ();

  vec_reset_length (vlib_worker_threads);

  /* Set up the main thread */
  vec_add2_aligned (vlib_worker_threads, w, 1, CLIB_CACHE_LINE_BYTES);
  w->elog_track.name = "main thread";
  elog_track_register (&vm->elog_main, &w->elog_track);

  if (vec_len (tm->thread_prefix))
    {
      w->name = format (0, "%v_main%c", tm->thread_prefix, '\0');
      vlib_set_thread_name ((char *) w->name);
    }

  vm->elog_main.lock =
    clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES, CLIB_CACHE_LINE_BYTES);
  vm->elog_main.lock[0] = 0;

  clib_callback_data_init (&vm->vlib_node_runtime_perf_callbacks,
			   &vm->worker_thread_main_loop_callback_lock);

  /* Replace hand-crafted length-1 vector with a real vector */
  vlib_mains = 0;

  vec_validate_aligned (vlib_mains, n_vlib_mains - 1, CLIB_CACHE_LINE_BYTES);
  _vec_len (vlib_mains) = 0;
  vec_add1_aligned (vlib_mains, vm, CLIB_CACHE_LINE_BYTES);

  if (n_vlib_mains > 1)
    {
      vlib_worker_threads->wait_at_barrier =
	clib_mem_alloc_aligned (sizeof (u32), CLIB_CACHE_LINE_BYTES);
      vlib_worker_threads->workers_at_barrier =
	clib_mem_alloc_aligned (sizeof (u32), CLIB_CACHE_LINE_BYTES);

      vlib_worker_threads->node_reforks_required =
	clib_mem_alloc_aligned (sizeof (u32), CLIB_CACHE_LINE_BYTES);

      /* We'll need the rpc vector lock... */
      clib_spinlock_init (&vm->pending_rpc_lock);

      /* Ask for an initial barrier sync */
      *vlib_worker_threads->workers_at_barrier = 0;
      *vlib_worker_threads->wait_at_barrier = 1;

      /* Without update or refork */
      *vlib_worker_threads->node_reforks_required = 0;
      vm->need_vlib_worker_thread_node_runtime_update = 0;

      /* init timing */
      vm->barrier_epoch = 0;
      vm->barrier_no_close_before = 0;

      worker_thread_index = 1;
      clib_spinlock_init (&vm->worker_thread_main_loop_callback_lock);

      for (i = 0; i < vec_len (tm->registrations); i++)
	{
	  vlib_node_main_t *nm, *nm_clone;
	  int k;

	  tr = tm->registrations[i];

	  if (tr->count == 0)
	    continue;

	  for (k = 0; k < tr->count; k++)
	    {
	      vlib_node_t *n;

	      vec_add2 (vlib_worker_threads, w, 1);
	      /* Currently unused, may not really work */
	      if (tr->mheap_size)
		w->thread_mheap = clib_mem_create_heap (0, tr->mheap_size,
							/* unlocked */ 0,
							"%s%d heap",
							tr->name, k);
	      else
		w->thread_mheap = main_heap;

	      w->thread_stack =
		vlib_thread_stack_init (w - vlib_worker_threads);
	      w->thread_function = tr->function;
	      w->thread_function_arg = w;
	      w->instance_id = k;
	      w->registration = tr;

	      w->elog_track.name =
		(char *) format (0, "%s %d", tr->name, k + 1);
	      vec_add1 (w->elog_track.name, 0);
	      elog_track_register (&vm->elog_main, &w->elog_track);

	      if (tr->no_data_structure_clone)
		continue;

	      /* Fork vlib_global_main et al. Look for bugs here */
	      oldheap = clib_mem_set_heap (w->thread_mheap);

	      vm_clone = clib_mem_alloc_aligned (sizeof (*vm_clone),
						 CLIB_CACHE_LINE_BYTES);
	      clib_memcpy (vm_clone, vlib_mains[0], sizeof (*vm_clone));

	      vm_clone->thread_index = worker_thread_index;
	      vm_clone->heap_base = w->thread_mheap;
	      vm_clone->heap_aligned_base = (void *)
		(((uword) w->thread_mheap) & ~(VLIB_FRAME_ALIGN - 1));
	      vm_clone->init_functions_called =
		hash_create (0, /* value bytes */ 0);
	      vm_clone->pending_rpc_requests = 0;
	      vec_validate (vm_clone->pending_rpc_requests, 0);
	      _vec_len (vm_clone->pending_rpc_requests) = 0;
	      clib_memset (&vm_clone->random_buffer, 0,
			   sizeof (vm_clone->random_buffer));
	      clib_spinlock_init
		(&vm_clone->worker_thread_main_loop_callback_lock);
	      clib_callback_data_init
		(&vm_clone->vlib_node_runtime_perf_callbacks,
		 &vm_clone->worker_thread_main_loop_callback_lock);

	      nm = &vlib_mains[0]->node_main;
	      nm_clone = &vm_clone->node_main;
	      /* fork next frames array, preserving node runtime indices */
	      nm_clone->next_frames = vec_dup_aligned (nm->next_frames,
						       CLIB_CACHE_LINE_BYTES);
	      for (j = 0; j < vec_len (nm_clone->next_frames); j++)
		{
		  vlib_next_frame_t *nf = &nm_clone->next_frames[j];
		  u32 save_node_runtime_index;
		  u32 save_flags;

		  save_node_runtime_index = nf->node_runtime_index;
		  save_flags = nf->flags & VLIB_FRAME_NO_FREE_AFTER_DISPATCH;
		  vlib_next_frame_init (nf);
		  nf->node_runtime_index = save_node_runtime_index;
		  nf->flags = save_flags;
		}

	      /* fork the frame dispatch queue */
	      nm_clone->pending_frames = 0;
	      vec_validate (nm_clone->pending_frames, 10);
	      _vec_len (nm_clone->pending_frames) = 0;

	      /* fork nodes */
	      nm_clone->nodes = 0;

	      /* Allocate all nodes in single block for speed */
	      n = clib_mem_alloc_no_fail (vec_len (nm->nodes) * sizeof (*n));

	      for (j = 0; j < vec_len (nm->nodes); j++)
		{
		  clib_memcpy (n, nm->nodes[j], sizeof (*n));
		  /* none of the copied nodes have enqueue rights given out */
		  n->owner_node_index = VLIB_INVALID_NODE_INDEX;
		  clib_memset (&n->stats_total, 0, sizeof (n->stats_total));
		  clib_memset (&n->stats_last_clear, 0,
			       sizeof (n->stats_last_clear));
		  vec_add1 (nm_clone->nodes, n);
		  n++;
		}
	      nm_clone->nodes_by_type[VLIB_NODE_TYPE_INTERNAL] =
		vec_dup_aligned (nm->nodes_by_type[VLIB_NODE_TYPE_INTERNAL],
				 CLIB_CACHE_LINE_BYTES);
	      vec_foreach (rt,
			   nm_clone->nodes_by_type[VLIB_NODE_TYPE_INTERNAL])
	      {
		vlib_node_t *n = vlib_get_node (vm, rt->node_index);
		rt->thread_index = vm_clone->thread_index;
		/* copy initial runtime_data from node */
		if (n->runtime_data && n->runtime_data_bytes > 0)
		  clib_memcpy (rt->runtime_data, n->runtime_data,
			       clib_min (VLIB_NODE_RUNTIME_DATA_SIZE,
					 n->runtime_data_bytes));
	      }

	      nm_clone->nodes_by_type[VLIB_NODE_TYPE_INPUT] =
		vec_dup_aligned (nm->nodes_by_type[VLIB_NODE_TYPE_INPUT],
				 CLIB_CACHE_LINE_BYTES);
	      clib_interrupt_init (
		&nm_clone->interrupts,
		vec_len (nm_clone->nodes_by_type[VLIB_NODE_TYPE_INPUT]));
	      vec_foreach (rt, nm_clone->nodes_by_type[VLIB_NODE_TYPE_INPUT])
	      {
		vlib_node_t *n = vlib_get_node (vm, rt->node_index);
		rt->thread_index = vm_clone->thread_index;
		/* copy initial runtime_data from node */
		if (n->runtime_data && n->runtime_data_bytes > 0)
		  clib_memcpy (rt->runtime_data, n->runtime_data,
			       clib_min (VLIB_NODE_RUNTIME_DATA_SIZE,
					 n->runtime_data_bytes));
	      }

	      nm_clone->nodes_by_type[VLIB_NODE_TYPE_PRE_INPUT] =
		vec_dup_aligned (nm->nodes_by_type[VLIB_NODE_TYPE_PRE_INPUT],
				 CLIB_CACHE_LINE_BYTES);
	      vec_foreach (rt,
			   nm_clone->nodes_by_type[VLIB_NODE_TYPE_PRE_INPUT])
	      {
		vlib_node_t *n = vlib_get_node (vm, rt->node_index);
		rt->thread_index = vm_clone->thread_index;
		/* copy initial runtime_data from node */
		if (n->runtime_data && n->runtime_data_bytes > 0)
		  clib_memcpy (rt->runtime_data, n->runtime_data,
			       clib_min (VLIB_NODE_RUNTIME_DATA_SIZE,
					 n->runtime_data_bytes));
	      }

	      nm_clone->processes = vec_dup_aligned (nm->processes,
						     CLIB_CACHE_LINE_BYTES);

	      /* Create per-thread frame freelist */
	      nm_clone->frame_sizes = vec_new (vlib_frame_size_t, 1);
#ifdef VLIB_SUPPORTS_ARBITRARY_SCALAR_SIZES
	      nm_clone->frame_size_hash = hash_create (0, sizeof (uword));
#endif
	      nm_clone->node_by_error = nm->node_by_error;

	      /* Packet trace buffers are guaranteed to be empty, nothing to do here */

	      clib_mem_set_heap (oldheap);
	      vec_add1_aligned (vlib_mains, vm_clone, CLIB_CACHE_LINE_BYTES);

	      /* Switch to the stats segment ... */
	      void *oldheap = vlib_stats_push_heap (0);
	      vm_clone->error_main.counters = vec_dup_aligned
		(vlib_mains[0]->error_main.counters, CLIB_CACHE_LINE_BYTES);
	      vlib_stats_pop_heap2 (vm_clone->error_main.counters,
				    worker_thread_index, oldheap, 1);

	      vm_clone->error_main.counters_last_clear = vec_dup_aligned
		(vlib_mains[0]->error_main.counters_last_clear,
		 CLIB_CACHE_LINE_BYTES);

	      worker_thread_index++;
	    }
	}
    }
  else
    {
      /* only have non-data-structure copy threads to create... */
      for (i = 0; i < vec_len (tm->registrations); i++)
	{
	  tr = tm->registrations[i];

	  for (j = 0; j < tr->count; j++)
	    {
	      vec_add2 (vlib_worker_threads, w, 1);
	      if (tr->mheap_size)
		{
		  w->thread_mheap = clib_mem_create_heap (0, tr->mheap_size,
							  /* locked */ 0,
							  "%s%d heap",
							  tr->name, j);
		}
	      else
		w->thread_mheap = main_heap;
	      w->thread_stack =
		vlib_thread_stack_init (w - vlib_worker_threads);
	      w->thread_function = tr->function;
	      w->thread_function_arg = w;
	      w->instance_id = j;
	      w->elog_track.name =
		(char *) format (0, "%s %d", tr->name, j + 1);
	      w->registration = tr;
	      vec_add1 (w->elog_track.name, 0);
	      elog_track_register (&vm->elog_main, &w->elog_track);
	    }
	}
    }

  worker_thread_index = 1;

  for (i = 0; i < vec_len (tm->registrations); i++)
    {
      clib_error_t *err;
      int j;

      tr = tm->registrations[i];

      if (tr->use_pthreads || tm->use_pthreads)
	{
	  for (j = 0; j < tr->count; j++)
	    {
	      w = vlib_worker_threads + worker_thread_index++;
	      err = vlib_launch_thread_int (vlib_worker_thread_bootstrap_fn,
					    w, 0);
	      if (err)
		clib_error_report (err);
	    }
	}
      else
	{
	  uword c;
          /* *INDENT-OFF* */
          clib_bitmap_foreach (c, tr->coremask)  {
            w = vlib_worker_threads + worker_thread_index++;
	    err = vlib_launch_thread_int (vlib_worker_thread_bootstrap_fn,
					  w, c);
	    if (err)
	      clib_error_report (err);
          }
          /* *INDENT-ON* */
	}
    }
  vlib_worker_thread_barrier_sync (vm);
  vlib_worker_thread_barrier_release (vm);
  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (start_workers);


static inline void
worker_thread_node_runtime_update_internal (void)
{
  int i, j;
  vlib_main_t *vm;
  vlib_node_main_t *nm, *nm_clone;
  vlib_main_t *vm_clone;
  vlib_node_runtime_t *rt;

  ASSERT (vlib_get_thread_index () == 0);

  vm = vlib_mains[0];
  nm = &vm->node_main;

  ASSERT (*vlib_worker_threads->wait_at_barrier == 1);

  /*
   * Scrape all runtime stats, so we don't lose node runtime(s) with
   * pending counts, or throw away worker / io thread counts.
   */
  for (j = 0; j < vec_len (nm->nodes); j++)
    {
      vlib_node_t *n;
      n = nm->nodes[j];
      vlib_node_sync_stats (vm, n);
    }

  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      vlib_node_t *n;

      vm_clone = vlib_mains[i];
      nm_clone = &vm_clone->node_main;

      for (j = 0; j < vec_len (nm_clone->nodes); j++)
	{
	  n = nm_clone->nodes[j];

	  rt = vlib_node_get_runtime (vm_clone, n->index);
	  vlib_node_runtime_sync_stats (vm_clone, rt, 0, 0, 0);
	}
    }

  /* Per-worker clone rebuilds are now done on each thread */
}


void
vlib_worker_thread_node_refork (void)
{
  vlib_main_t *vm, *vm_clone;
  vlib_node_main_t *nm, *nm_clone;
  vlib_node_t **old_nodes_clone;
  vlib_node_runtime_t *rt, *old_rt;

  vlib_node_t *new_n_clone;

  int j;

  vm = vlib_mains[0];
  nm = &vm->node_main;
  vm_clone = vlib_get_main ();
  nm_clone = &vm_clone->node_main;

  /* Re-clone error heap */
  u64 *old_counters = vm_clone->error_main.counters;
  u64 *old_counters_all_clear = vm_clone->error_main.counters_last_clear;

  clib_memcpy_fast (&vm_clone->error_main, &vm->error_main,
		    sizeof (vm->error_main));
  j = vec_len (vm->error_main.counters) - 1;

  /* Switch to the stats segment ... */
  void *oldheap = vlib_stats_push_heap (0);
  vec_validate_aligned (old_counters, j, CLIB_CACHE_LINE_BYTES);
  vm_clone->error_main.counters = old_counters;
  vlib_stats_pop_heap2 (vm_clone->error_main.counters, vm_clone->thread_index,
			oldheap, 0);

  vec_validate_aligned (old_counters_all_clear, j, CLIB_CACHE_LINE_BYTES);
  vm_clone->error_main.counters_last_clear = old_counters_all_clear;

  nm_clone = &vm_clone->node_main;
  vec_free (nm_clone->next_frames);
  nm_clone->next_frames = vec_dup_aligned (nm->next_frames,
					   CLIB_CACHE_LINE_BYTES);

  for (j = 0; j < vec_len (nm_clone->next_frames); j++)
    {
      vlib_next_frame_t *nf = &nm_clone->next_frames[j];
      u32 save_node_runtime_index;
      u32 save_flags;

      save_node_runtime_index = nf->node_runtime_index;
      save_flags = nf->flags & VLIB_FRAME_NO_FREE_AFTER_DISPATCH;
      vlib_next_frame_init (nf);
      nf->node_runtime_index = save_node_runtime_index;
      nf->flags = save_flags;
    }

  old_nodes_clone = nm_clone->nodes;
  nm_clone->nodes = 0;

  /* re-fork nodes */

  /* Allocate all nodes in single block for speed */
  new_n_clone =
    clib_mem_alloc_no_fail (vec_len (nm->nodes) * sizeof (*new_n_clone));
  for (j = 0; j < vec_len (nm->nodes); j++)
    {
      vlib_node_t *new_n = nm->nodes[j];

      clib_memcpy_fast (new_n_clone, new_n, sizeof (*new_n));
      /* none of the copied nodes have enqueue rights given out */
      new_n_clone->owner_node_index = VLIB_INVALID_NODE_INDEX;

      if (j >= vec_len (old_nodes_clone))
	{
	  /* new node, set to zero */
	  clib_memset (&new_n_clone->stats_total, 0,
		       sizeof (new_n_clone->stats_total));
	  clib_memset (&new_n_clone->stats_last_clear, 0,
		       sizeof (new_n_clone->stats_last_clear));
	}
      else
	{
	  vlib_node_t *old_n_clone = old_nodes_clone[j];
	  /* Copy stats if the old data is valid */
	  clib_memcpy_fast (&new_n_clone->stats_total,
			    &old_n_clone->stats_total,
			    sizeof (new_n_clone->stats_total));
	  clib_memcpy_fast (&new_n_clone->stats_last_clear,
			    &old_n_clone->stats_last_clear,
			    sizeof (new_n_clone->stats_last_clear));

	  /* keep previous node state */
	  new_n_clone->state = old_n_clone->state;
	}
      vec_add1 (nm_clone->nodes, new_n_clone);
      new_n_clone++;
    }
  /* Free the old node clones */
  clib_mem_free (old_nodes_clone[0]);

  vec_free (old_nodes_clone);


  /* re-clone internal nodes */
  old_rt = nm_clone->nodes_by_type[VLIB_NODE_TYPE_INTERNAL];
  nm_clone->nodes_by_type[VLIB_NODE_TYPE_INTERNAL] =
    vec_dup_aligned (nm->nodes_by_type[VLIB_NODE_TYPE_INTERNAL],
		     CLIB_CACHE_LINE_BYTES);

  vec_foreach (rt, nm_clone->nodes_by_type[VLIB_NODE_TYPE_INTERNAL])
  {
    vlib_node_t *n = vlib_get_node (vm, rt->node_index);
    rt->thread_index = vm_clone->thread_index;
    /* copy runtime_data, will be overwritten later for existing rt */
    if (n->runtime_data && n->runtime_data_bytes > 0)
      clib_memcpy_fast (rt->runtime_data, n->runtime_data,
			clib_min (VLIB_NODE_RUNTIME_DATA_SIZE,
				  n->runtime_data_bytes));
  }

  for (j = 0; j < vec_len (old_rt); j++)
    {
      rt = vlib_node_get_runtime (vm_clone, old_rt[j].node_index);
      rt->state = old_rt[j].state;
      clib_memcpy_fast (rt->runtime_data, old_rt[j].runtime_data,
			VLIB_NODE_RUNTIME_DATA_SIZE);
    }

  vec_free (old_rt);

  /* re-clone input nodes */
  old_rt = nm_clone->nodes_by_type[VLIB_NODE_TYPE_INPUT];
  nm_clone->nodes_by_type[VLIB_NODE_TYPE_INPUT] =
    vec_dup_aligned (nm->nodes_by_type[VLIB_NODE_TYPE_INPUT],
		     CLIB_CACHE_LINE_BYTES);
  clib_interrupt_resize (
    &nm_clone->interrupts,
    vec_len (nm_clone->nodes_by_type[VLIB_NODE_TYPE_INPUT]));

  vec_foreach (rt, nm_clone->nodes_by_type[VLIB_NODE_TYPE_INPUT])
  {
    vlib_node_t *n = vlib_get_node (vm, rt->node_index);
    rt->thread_index = vm_clone->thread_index;
    /* copy runtime_data, will be overwritten later for existing rt */
    if (n->runtime_data && n->runtime_data_bytes > 0)
      clib_memcpy_fast (rt->runtime_data, n->runtime_data,
			clib_min (VLIB_NODE_RUNTIME_DATA_SIZE,
				  n->runtime_data_bytes));
  }

  for (j = 0; j < vec_len (old_rt); j++)
    {
      rt = vlib_node_get_runtime (vm_clone, old_rt[j].node_index);
      rt->state = old_rt[j].state;
      clib_memcpy_fast (rt->runtime_data, old_rt[j].runtime_data,
			VLIB_NODE_RUNTIME_DATA_SIZE);
    }

  vec_free (old_rt);

  /* re-clone pre-input nodes */
  old_rt = nm_clone->nodes_by_type[VLIB_NODE_TYPE_PRE_INPUT];
  nm_clone->nodes_by_type[VLIB_NODE_TYPE_PRE_INPUT] =
    vec_dup_aligned (nm->nodes_by_type[VLIB_NODE_TYPE_PRE_INPUT],
		     CLIB_CACHE_LINE_BYTES);

  vec_foreach (rt, nm_clone->nodes_by_type[VLIB_NODE_TYPE_PRE_INPUT])
  {
    vlib_node_t *n = vlib_get_node (vm, rt->node_index);
    rt->thread_index = vm_clone->thread_index;
    /* copy runtime_data, will be overwritten later for existing rt */
    if (n->runtime_data && n->runtime_data_bytes > 0)
      clib_memcpy_fast (rt->runtime_data, n->runtime_data,
			clib_min (VLIB_NODE_RUNTIME_DATA_SIZE,
				  n->runtime_data_bytes));
  }

  for (j = 0; j < vec_len (old_rt); j++)
    {
      rt = vlib_node_get_runtime (vm_clone, old_rt[j].node_index);
      rt->state = old_rt[j].state;
      clib_memcpy_fast (rt->runtime_data, old_rt[j].runtime_data,
			VLIB_NODE_RUNTIME_DATA_SIZE);
    }

  vec_free (old_rt);

  nm_clone->processes = vec_dup_aligned (nm->processes,
					 CLIB_CACHE_LINE_BYTES);
  nm_clone->node_by_error = nm->node_by_error;
}

void
vlib_worker_thread_node_runtime_update (void)
{
  /*
   * Make a note that we need to do a node runtime update
   * prior to releasing the barrier.
   */
  vlib_global_main.need_vlib_worker_thread_node_runtime_update = 1;
}

u32
unformat_sched_policy (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = SCHED_POLICY_##f;
  foreach_sched_policy
#undef _
    else
    return 0;
  return 1;
}

static clib_error_t *
cpu_config (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_thread_registration_t *tr;
  uword *p;
  vlib_thread_main_t *tm = &vlib_thread_main;
  u8 *name;
  uword *bitmap;
  u32 count;

  tm->thread_registrations_by_name = hash_create_string (0, sizeof (uword));

  tm->n_thread_stacks = 1;	/* account for main thread */
  tm->sched_policy = ~0;
  tm->sched_priority = ~0;
  tm->main_lcore = ~0;

  tr = tm->next;

  while (tr)
    {
      hash_set_mem (tm->thread_registrations_by_name, tr->name, (uword) tr);
      tr = tr->next;
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "use-pthreads"))
	tm->use_pthreads = 1;
      else if (unformat (input, "thread-prefix %v", &tm->thread_prefix))
	;
      else if (unformat (input, "main-core %u", &tm->main_lcore))
	;
      else if (unformat (input, "skip-cores %u", &tm->skip_cores))
	;
      else if (unformat (input, "numa-heap-size %U",
			 unformat_memory_size, &tm->numa_heap_size))
	;
      else if (unformat (input, "coremask-%s %U", &name,
			 unformat_bitmap_mask, &bitmap) ||
	       unformat (input, "corelist-%s %U", &name,
			 unformat_bitmap_list, &bitmap))
	{
	  p = hash_get_mem (tm->thread_registrations_by_name, name);
	  if (p == 0)
	    return clib_error_return (0, "no such thread type '%s'", name);

	  tr = (vlib_thread_registration_t *) p[0];

	  if (tr->use_pthreads)
	    return clib_error_return (0,
				      "corelist cannot be set for '%s' threads",
				      name);
	  if (tr->count)
	    return clib_error_return
	      (0, "core placement of '%s' threads is already configured",
	       name);

	  tr->coremask = bitmap;
	  tr->count = clib_bitmap_count_set_bits (tr->coremask);
	}
      else
	if (unformat
	    (input, "scheduler-policy %U", unformat_sched_policy,
	     &tm->sched_policy))
	;
      else if (unformat (input, "scheduler-priority %u", &tm->sched_priority))
	;
      else if (unformat (input, "%s %u", &name, &count))
	{
	  p = hash_get_mem (tm->thread_registrations_by_name, name);
	  if (p == 0)
	    return clib_error_return (0, "no such thread type 3 '%s'", name);

	  tr = (vlib_thread_registration_t *) p[0];

	  if (tr->fixed_count)
	    return clib_error_return
	      (0, "number of '%s' threads not configurable", name);
	  if (tr->count)
	    return clib_error_return
	      (0, "number of '%s' threads is already configured", name);

	  tr->count = count;
	}
      else
	break;
    }

  if (tm->sched_priority != ~0)
    {
      if (tm->sched_policy == SCHED_FIFO || tm->sched_policy == SCHED_RR)
	{
	  u32 prio_max = sched_get_priority_max (tm->sched_policy);
	  u32 prio_min = sched_get_priority_min (tm->sched_policy);
	  if (tm->sched_priority > prio_max)
	    tm->sched_priority = prio_max;
	  if (tm->sched_priority < prio_min)
	    tm->sched_priority = prio_min;
	}
      else
	{
	  return clib_error_return
	    (0,
	     "scheduling priority (%d) is not allowed for `normal` scheduling policy",
	     tm->sched_priority);
	}
    }
  tr = tm->next;

  if (!tm->thread_prefix)
    tm->thread_prefix = format (0, "vpp");

  while (tr)
    {
      tm->n_thread_stacks += tr->count;
      tm->n_pthreads += tr->count * tr->use_pthreads;
      tm->n_threads += tr->count * (tr->use_pthreads == 0);
      tr = tr->next;
    }

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (cpu_config, "cpu");

void vnet_main_fixup (vlib_fork_fixup_t which) __attribute__ ((weak));
void
vnet_main_fixup (vlib_fork_fixup_t which)
{
}

void
vlib_worker_thread_fork_fixup (vlib_fork_fixup_t which)
{
  vlib_main_t *vm = vlib_get_main ();

  if (vlib_mains == 0)
    return;

  ASSERT (vlib_get_thread_index () == 0);
  vlib_worker_thread_barrier_sync (vm);

  switch (which)
    {
    case VLIB_WORKER_THREAD_FORK_FIXUP_NEW_SW_IF_INDEX:
      vnet_main_fixup (VLIB_WORKER_THREAD_FORK_FIXUP_NEW_SW_IF_INDEX);
      break;

    default:
      ASSERT (0);
    }
  vlib_worker_thread_barrier_release (vm);
}

  /*
   * Enforce minimum open time to minimize packet loss due to Rx overflow,
   * based on a test based heuristic that barrier should be open for at least
   * 3 time as long as it is closed (with an upper bound of 1ms because by that
   *  point it is probably too late to make a difference)
   */

#ifndef BARRIER_MINIMUM_OPEN_LIMIT
#define BARRIER_MINIMUM_OPEN_LIMIT 0.001
#endif

#ifndef BARRIER_MINIMUM_OPEN_FACTOR
#define BARRIER_MINIMUM_OPEN_FACTOR 3
#endif

void
vlib_worker_thread_initial_barrier_sync_and_release (vlib_main_t * vm)
{
  f64 deadline;
  f64 now = vlib_time_now (vm);
  u32 count = vec_len (vlib_mains) - 1;

  /* No worker threads? */
  if (count == 0)
    return;

  deadline = now + BARRIER_SYNC_TIMEOUT;
  *vlib_worker_threads->wait_at_barrier = 1;
  while (*vlib_worker_threads->workers_at_barrier != count)
    {
      if ((now = vlib_time_now (vm)) > deadline)
	{
	  fformat (stderr, "%s: worker thread deadlock\n", __FUNCTION__);
	  os_panic ();
	}
      CLIB_PAUSE ();
    }
  *vlib_worker_threads->wait_at_barrier = 0;
}

/**
 * Return true if the wroker thread barrier is held
 */
u8
vlib_worker_thread_barrier_held (void)
{
  if (vec_len (vlib_mains) < 2)
    return (1);

  return (*vlib_worker_threads->wait_at_barrier == 1);
}

void
vlib_worker_thread_barrier_sync_int (vlib_main_t * vm, const char *func_name)
{
  f64 deadline;
  f64 now;
  f64 t_entry;
  f64 t_open;
  f64 t_closed;
  f64 max_vector_rate;
  u32 count;
  int i;

  if (vec_len (vlib_mains) < 2)
    return;

  ASSERT (vlib_get_thread_index () == 0);

  vlib_worker_threads[0].barrier_caller = func_name;
  count = vec_len (vlib_mains) - 1;

  /* Record entry relative to last close */
  now = vlib_time_now (vm);
  t_entry = now - vm->barrier_epoch;

  /* Tolerate recursive calls */
  if (++vlib_worker_threads[0].recursion_level > 1)
    {
      barrier_trace_sync_rec (t_entry);
      return;
    }

  if (PREDICT_FALSE (vec_len (vm->barrier_perf_callbacks) != 0))
    clib_call_callbacks (vm->barrier_perf_callbacks, vm,
			 vm->clib_time.last_cpu_time, 0 /* enter */ );

  /*
   * Need data to decide if we're working hard enough to honor
   * the barrier hold-down timer.
   */
  max_vector_rate = 0.0;
  for (i = 1; i < vec_len (vlib_mains); i++)
    max_vector_rate =
      clib_max (max_vector_rate,
		(f64) vlib_last_vectors_per_main_loop (vlib_mains[i]));

  vlib_worker_threads[0].barrier_sync_count++;

  /* Enforce minimum barrier open time to minimize packet loss */
  ASSERT (vm->barrier_no_close_before <= (now + BARRIER_MINIMUM_OPEN_LIMIT));

  /*
   * If any worker thread seems busy, which we define
   * as a vector rate above 10, we enforce the barrier hold-down timer
   */
  if (max_vector_rate > 10.0)
    {
      while (1)
	{
	  now = vlib_time_now (vm);
	  /* Barrier hold-down timer expired? */
	  if (now >= vm->barrier_no_close_before)
	    break;
	  if ((vm->barrier_no_close_before - now)
	      > (2.0 * BARRIER_MINIMUM_OPEN_LIMIT))
	    {
	      clib_warning
		("clock change: would have waited for %.4f seconds",
		 (vm->barrier_no_close_before - now));
	      break;
	    }
	}
    }
  /* Record time of closure */
  t_open = now - vm->barrier_epoch;
  vm->barrier_epoch = now;

  deadline = now + BARRIER_SYNC_TIMEOUT;

  *vlib_worker_threads->wait_at_barrier = 1;
  while (*vlib_worker_threads->workers_at_barrier != count)
    {
      if ((now = vlib_time_now (vm)) > deadline)
	{
	  fformat (stderr, "%s: worker thread deadlock\n", __FUNCTION__);
	  os_panic ();
	}
    }

  t_closed = now - vm->barrier_epoch;

  barrier_trace_sync (t_entry, t_open, t_closed);

}

void
vlib_worker_thread_barrier_release (vlib_main_t * vm)
{
  f64 deadline;
  f64 now;
  f64 minimum_open;
  f64 t_entry;
  f64 t_closed_total;
  f64 t_update_main = 0.0;
  int refork_needed = 0;

  if (vec_len (vlib_mains) < 2)
    return;

  ASSERT (vlib_get_thread_index () == 0);


  now = vlib_time_now (vm);
  t_entry = now - vm->barrier_epoch;

  if (--vlib_worker_threads[0].recursion_level > 0)
    {
      barrier_trace_release_rec (t_entry);
      return;
    }

  /* Update (all) node runtimes before releasing the barrier, if needed */
  if (vm->need_vlib_worker_thread_node_runtime_update)
    {
      /*
       * Lock stat segment here, so we's safe when
       * rebuilding the stat segment node clones from the
       * stat thread...
       */
      vlib_stat_segment_lock ();

      /* Do stats elements on main thread */
      worker_thread_node_runtime_update_internal ();
      vm->need_vlib_worker_thread_node_runtime_update = 0;

      /* Do per thread rebuilds in parallel */
      refork_needed = 1;
      clib_atomic_fetch_add (vlib_worker_threads->node_reforks_required,
			     (vec_len (vlib_mains) - 1));
      now = vlib_time_now (vm);
      t_update_main = now - vm->barrier_epoch;
    }

  deadline = now + BARRIER_SYNC_TIMEOUT;

  /*
   * Note when we let go of the barrier.
   * Workers can use this to derive a reasonably accurate
   * time offset. See vlib_time_now(...)
   */
  vm->time_last_barrier_release = vlib_time_now (vm);
  CLIB_MEMORY_STORE_BARRIER ();

  *vlib_worker_threads->wait_at_barrier = 0;

  while (*vlib_worker_threads->workers_at_barrier > 0)
    {
      if ((now = vlib_time_now (vm)) > deadline)
	{
	  fformat (stderr, "%s: worker thread deadlock\n", __FUNCTION__);
	  os_panic ();
	}
    }

  /* Wait for reforks before continuing */
  if (refork_needed)
    {
      now = vlib_time_now (vm);

      deadline = now + BARRIER_SYNC_TIMEOUT;

      while (*vlib_worker_threads->node_reforks_required > 0)
	{
	  if ((now = vlib_time_now (vm)) > deadline)
	    {
	      fformat (stderr, "%s: worker thread refork deadlock\n",
		       __FUNCTION__);
	      os_panic ();
	    }
	}
      vlib_stat_segment_unlock ();
    }

  t_closed_total = now - vm->barrier_epoch;

  minimum_open = t_closed_total * BARRIER_MINIMUM_OPEN_FACTOR;

  if (minimum_open > BARRIER_MINIMUM_OPEN_LIMIT)
    {
      minimum_open = BARRIER_MINIMUM_OPEN_LIMIT;
    }

  vm->barrier_no_close_before = now + minimum_open;

  /* Record barrier epoch (used to enforce minimum open time) */
  vm->barrier_epoch = now;

  barrier_trace_release (t_entry, t_closed_total, t_update_main);

  if (PREDICT_FALSE (vec_len (vm->barrier_perf_callbacks) != 0))
    clib_call_callbacks (vm->barrier_perf_callbacks, vm,
			 vm->clib_time.last_cpu_time, 1 /* leave */ );
}

/**
 * Wait until each of the workers has been once around the track
 */
void
vlib_worker_wait_one_loop (void)
{
  ASSERT (vlib_get_thread_index () == 0);

  if (vec_len (vlib_mains) < 2)
    return;

  if (vlib_worker_thread_barrier_held ())
    return;

  u32 *counts = 0;
  u32 ii;

  vec_validate (counts, vec_len (vlib_mains) - 1);

  /* record the current loop counts */
  vec_foreach_index (ii, vlib_mains)
    counts[ii] = vlib_mains[ii]->main_loop_count;

  /* spin until each changes, apart from the main thread, or we'd be
   * a while */
  for (ii = 1; ii < vec_len (counts); ii++)
    {
      while (counts[ii] == vlib_mains[ii]->main_loop_count)
	CLIB_PAUSE ();
    }

  vec_free (counts);
  return;
}

/*
 * Check the frame queue to see if any frames are available.
 * If so, pull the packets off the frames and put them to
 * the handoff node.
 */
int
vlib_frame_queue_dequeue (vlib_main_t * vm, vlib_frame_queue_main_t * fqm)
{
  u32 thread_id = vm->thread_index;
  vlib_frame_queue_t *fq = fqm->vlib_frame_queues[thread_id];
  vlib_frame_queue_elt_t *elt;
  u32 *from, *to;
  vlib_frame_t *f;
  int msg_type;
  int processed = 0;
  u32 n_left_to_node;
  u32 vectors = 0;

  ASSERT (fq);
  ASSERT (vm == vlib_mains[thread_id]);

  if (PREDICT_FALSE (fqm->node_index == ~0))
    return 0;
  /*
   * Gather trace data for frame queues
   */
  if (PREDICT_FALSE (fq->trace))
    {
      frame_queue_trace_t *fqt;
      frame_queue_nelt_counter_t *fqh;
      u32 elix;

      fqt = &fqm->frame_queue_traces[thread_id];

      fqt->nelts = fq->nelts;
      fqt->head = fq->head;
      fqt->head_hint = fq->head_hint;
      fqt->tail = fq->tail;
      fqt->threshold = fq->vector_threshold;
      fqt->n_in_use = fqt->tail - fqt->head;
      if (fqt->n_in_use >= fqt->nelts)
	{
	  // if beyond max then use max
	  fqt->n_in_use = fqt->nelts - 1;
	}

      /* Record the number of elements in use in the histogram */
      fqh = &fqm->frame_queue_histogram[thread_id];
      fqh->count[fqt->n_in_use]++;

      /* Record a snapshot of the elements in use */
      for (elix = 0; elix < fqt->nelts; elix++)
	{
	  elt = fq->elts + ((fq->head + 1 + elix) & (fq->nelts - 1));
	  if (1 || elt->valid)
	    {
	      fqt->n_vectors[elix] = elt->n_vectors;
	    }
	}
      fqt->written = 1;
    }

  while (1)
    {
      vlib_buffer_t *b;
      if (fq->head == fq->tail)
	{
	  fq->head_hint = fq->head;
	  return processed;
	}

      elt = fq->elts + ((fq->head + 1) & (fq->nelts - 1));

      if (!elt->valid)
	{
	  fq->head_hint = fq->head;
	  return processed;
	}

      from = elt->buffer_index;
      msg_type = elt->msg_type;

      ASSERT (msg_type == VLIB_FRAME_QUEUE_ELT_DISPATCH_FRAME);
      ASSERT (elt->n_vectors <= VLIB_FRAME_SIZE);

      f = vlib_get_frame_to_node (vm, fqm->node_index);

      /* If the first vector is traced, set the frame trace flag */
      b = vlib_get_buffer (vm, from[0]);
      if (b->flags & VLIB_BUFFER_IS_TRACED)
	f->frame_flags |= VLIB_NODE_FLAG_TRACE;

      to = vlib_frame_vector_args (f);

      n_left_to_node = elt->n_vectors;

      while (n_left_to_node >= 4)
	{
	  to[0] = from[0];
	  to[1] = from[1];
	  to[2] = from[2];
	  to[3] = from[3];
	  to += 4;
	  from += 4;
	  n_left_to_node -= 4;
	}

      while (n_left_to_node > 0)
	{
	  to[0] = from[0];
	  to++;
	  from++;
	  n_left_to_node--;
	}

      vectors += elt->n_vectors;
      f->n_vectors = elt->n_vectors;
      vlib_put_frame_to_node (vm, fqm->node_index, f);

      elt->valid = 0;
      elt->n_vectors = 0;
      elt->msg_type = 0xfefefefe;
      CLIB_MEMORY_BARRIER ();
      fq->head++;
      processed++;

      /*
       * Limit the number of packets pushed into the graph
       */
      if (vectors >= fq->vector_threshold)
	{
	  fq->head_hint = fq->head;
	  return processed;
	}
    }
  ASSERT (0);
  return processed;
}

void
vlib_worker_thread_fn (void *arg)
{
  vlib_worker_thread_t *w = (vlib_worker_thread_t *) arg;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *e;

  vlib_process_finish_switch_stack (vm);

  ASSERT (vm->thread_index == vlib_get_thread_index ());

  vlib_worker_thread_init (w);
  clib_time_init (&vm->clib_time);
  clib_mem_set_heap (w->thread_mheap);

  e = vlib_call_init_exit_functions_no_sort
    (vm, &vm->worker_init_function_registrations, 1 /* call_once */ );
  if (e)
    clib_error_report (e);

  /* Wait until the dpdk init sequence is complete */
  while (tm->extern_thread_mgmt && tm->worker_thread_release == 0)
    vlib_worker_thread_barrier_check ();

  vlib_worker_loop (vm);
}

/* *INDENT-OFF* */
VLIB_REGISTER_THREAD (worker_thread_reg, static) = {
  .name = "workers",
  .short_name = "wk",
  .function = vlib_worker_thread_fn,
};
/* *INDENT-ON* */

u32
vlib_frame_queue_main_init (u32 node_index, u32 frame_queue_nelts)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm;
  vlib_frame_queue_t *fq;
  int i;
  u32 num_threads;

  if (frame_queue_nelts == 0)
    frame_queue_nelts = FRAME_QUEUE_MAX_NELTS;

  num_threads = 1 /* main thread */  + tm->n_threads;
  ASSERT (frame_queue_nelts >= 8 + num_threads);

  vec_add2 (tm->frame_queue_mains, fqm, 1);

  fqm->node_index = node_index;
  fqm->frame_queue_nelts = frame_queue_nelts;
  fqm->queue_hi_thresh = frame_queue_nelts - num_threads;

  vec_validate (fqm->vlib_frame_queues, tm->n_vlib_mains - 1);
  vec_validate (fqm->per_thread_data, tm->n_vlib_mains - 1);
  _vec_len (fqm->vlib_frame_queues) = 0;
  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      vlib_frame_queue_per_thread_data_t *ptd;
      fq = vlib_frame_queue_alloc (frame_queue_nelts);
      vec_add1 (fqm->vlib_frame_queues, fq);

      ptd = vec_elt_at_index (fqm->per_thread_data, i);
      vec_validate (ptd->handoff_queue_elt_by_thread_index,
		    tm->n_vlib_mains - 1);
      vec_validate_init_empty (ptd->congested_handoff_queue_by_thread_index,
			       tm->n_vlib_mains - 1,
			       (vlib_frame_queue_t *) (~0));
    }

  return (fqm - tm->frame_queue_mains);
}

int
vlib_thread_cb_register (struct vlib_main_t *vm, vlib_thread_callbacks_t * cb)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  if (tm->extern_thread_mgmt)
    return -1;

  tm->cb.vlib_launch_thread_cb = cb->vlib_launch_thread_cb;
  tm->extern_thread_mgmt = 1;
  return 0;
}

void
vlib_process_signal_event_mt_helper (vlib_process_signal_event_mt_args_t *
				     args)
{
  ASSERT (vlib_get_thread_index () == 0);
  vlib_process_signal_event (vlib_get_main (), args->node_index,
			     args->type_opaque, args->data);
}

void *rpc_call_main_thread_cb_fn;

void
vlib_rpc_call_main_thread (void *callback, u8 * args, u32 arg_size)
{
  if (rpc_call_main_thread_cb_fn)
    {
      void (*fp) (void *, u8 *, u32) = rpc_call_main_thread_cb_fn;
      (*fp) (callback, args, arg_size);
    }
  else
    clib_warning ("BUG: rpc_call_main_thread_cb_fn NULL!");
}

clib_error_t *
threads_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (threads_init);


static clib_error_t *
show_clock_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int i;
  int verbose = 0;
  clib_timebase_t _tb, *tb = &_tb;

  (void) unformat (input, "verbose %=", &verbose, 1);

  clib_timebase_init (tb, 0 /* GMT */ , CLIB_TIMEBASE_DAYLIGHT_NONE,
		      &vm->clib_time);

  vlib_cli_output (vm, "%U, %U GMT", format_clib_time, &vm->clib_time,
		   verbose, format_clib_timebase_time,
		   clib_timebase_now (tb));

  if (vec_len (vlib_mains) == 1)
    return 0;

  vlib_cli_output (vm, "Time last barrier release %.9f",
		   vm->time_last_barrier_release);

  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      if (vlib_mains[i] == 0)
	continue;

      vlib_cli_output (vm, "%d: %U", i, format_clib_time,
		       &vlib_mains[i]->clib_time, verbose);

      vlib_cli_output (vm, "Thread %d offset %.9f error %.9f", i,
		       vlib_mains[i]->time_offset,
		       vm->time_last_barrier_release -
		       vlib_mains[i]->time_last_barrier_release);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (f_command, static) =
{
  .path = "show clock",
  .short_help = "show clock",
  .function = show_clock_command_fn,
};
/* *INDENT-ON* */

vlib_thread_main_t *
vlib_get_thread_main_not_inline (void)
{
  return vlib_get_thread_main ();
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
