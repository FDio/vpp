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
#include <signal.h>
#include <math.h>
#include <vppinfra/format.h>
#include <vlib/vlib.h>

#include <vlib/threads.h>
#include <vlib/unix/physmem.h>

#include <vlib/unix/cj.h>

#if DPDK==1
#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#endif
DECLARE_CJ_GLOBAL_LOG;

#define FRAME_QUEUE_NELTS 32


#if DPDK==1
/*
 *  Weak definitions of DPDK symbols used in this file.
 *  Needed for linking test programs without DPDK libs.
 */
unsigned __thread      __attribute__((weak)) RTE_PER_LCORE(_lcore_id);
struct lcore_config    __attribute__((weak)) lcore_config[];
unsigned               __attribute__((weak)) rte_socket_id();
int                    __attribute__((weak)) rte_eal_remote_launch();
#endif
u32 vl(void *p)
{
  return vec_len (p);
}

void debug_hex_bytes (u8 *s, u32 n)
{
    fformat (stderr, "%U\n", format_hex_bytes, s, n);
}

vlib_thread_main_t vlib_thread_main;

uword
os_get_cpu_number (void)
{
  void * sp;
  uword n;
  u32 len;

  len = vec_len (vlib_thread_stacks);
  if (len == 0)
    return 0;

  /* Get any old stack address. */
  sp = &sp;

  n = ((uword)sp - (uword)vlib_thread_stacks[0])
      >> VLIB_LOG2_THREAD_STACK_SIZE;

  /* "processes" have their own stacks, and they always run in thread 0 */
  n = n >= len ? 0 : n;

  return n;
}

void
vlib_set_thread_name (char *name)
{
  int pthread_setname_np (pthread_t __target_thread, const char *__name);
  pthread_t thread = pthread_self();

  if (thread) 
    pthread_setname_np(thread, name);
}

static int sort_registrations_by_no_clone  (void *a0, void * a1)
{ 
  vlib_thread_registration_t ** tr0 = a0;
  vlib_thread_registration_t ** tr1 = a1;

  return ((i32)((*tr0)->no_data_structure_clone) 
          - ((i32)((*tr1)->no_data_structure_clone)));
}

static uword *
vlib_sysfs_list_to_bitmap(char * filename)
{
  FILE *fp;
  uword *r = 0;

  fp = fopen (filename, "r");

  if (fp != NULL)
    {
      u8 * buffer = 0;
      vec_validate (buffer, 256-1);
      if (fgets ((char *)buffer, 256, fp))
        {
          unformat_input_t in;
          unformat_init_string (&in, (char *) buffer, strlen ((char *) buffer));
          unformat(&in, "%U", unformat_bitmap_list, &r);
          unformat_free (&in);
        }
      vec_free(buffer);
      fclose(fp);
    }
  return r;
}


/* Called early in the init sequence */

clib_error_t *
vlib_thread_init (vlib_main_t * vm)
{
  vlib_thread_main_t * tm = &vlib_thread_main;
  vlib_worker_thread_t * w;
  vlib_thread_registration_t * tr;
  u32 n_vlib_mains = 1;
  u32 first_index = 1;
  u32 i;
  uword * avail_cpu;

  /* get bitmaps of active cpu cores and sockets */
  tm->cpu_core_bitmap =
    vlib_sysfs_list_to_bitmap("/sys/devices/system/cpu/online");
  tm->cpu_socket_bitmap =
    vlib_sysfs_list_to_bitmap("/sys/devices/system/node/online");

  avail_cpu = clib_bitmap_dup(tm->cpu_core_bitmap);

  /* skip cores */
  for (i=0; i < tm->skip_cores; i++)
    {
      uword c = clib_bitmap_first_set(avail_cpu);
      if (c == ~0)
        return clib_error_return (0, "no available cpus to skip");

      avail_cpu = clib_bitmap_set(avail_cpu, c, 0);
    }

  /* grab cpu for main thread */
  if (!tm->main_lcore)
    {
      tm->main_lcore = clib_bitmap_first_set(avail_cpu);
      if (tm->main_lcore == (u8) ~0)
        return clib_error_return (0, "no available cpus to be used for the"
                                  " main thread");
    }
  else
    {
      if (clib_bitmap_get(avail_cpu, tm->main_lcore) == 0)
        return clib_error_return (0, "cpu %u is not available to be used"
                                  " for the main thread", tm->main_lcore);
    }
  avail_cpu = clib_bitmap_set(avail_cpu, tm->main_lcore, 0);

  /* assume that there is socket 0 only if there is no data from sysfs */
  if (!tm->cpu_socket_bitmap)
    tm->cpu_socket_bitmap = clib_bitmap_set(0, 0, 1);

  /* as many threads as stacks... */
  vec_validate_aligned (vlib_worker_threads, vec_len(vlib_thread_stacks)-1,
                        CLIB_CACHE_LINE_BYTES);

  /* Preallocate thread 0 */
  _vec_len(vlib_worker_threads) = 1;
  w = vlib_worker_threads;
  w->thread_mheap = clib_mem_get_heap();
  w->thread_stack = vlib_thread_stacks[0];
  w->dpdk_lcore_id = -1;
  w->lwp = syscall(SYS_gettid);
  tm->n_vlib_mains = 1;

  /* assign threads to cores and set n_vlib_mains */
  tr = tm->next;

  while (tr)
    {
      vec_add1 (tm->registrations, tr);
      tr = tr->next;
    }

  vec_sort_with_function
    (tm->registrations, sort_registrations_by_no_clone);

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
          clib_bitmap_foreach (c, tr->coremask, ({
            if (clib_bitmap_get(avail_cpu, c) == 0)
              return clib_error_return (0, "cpu %u is not available to be used"
                                        " for the '%s' thread",c, tr->name);

            avail_cpu = clib_bitmap_set(avail_cpu, c, 0);
          }));

        }
      else
        {
          for (j=0; j < tr->count; j++)
            {
              uword c = clib_bitmap_first_set(avail_cpu);
              if (c == ~0)
              return clib_error_return (0, "no available cpus to be used for"
                                        " the '%s' thread", tr->name);

              avail_cpu = clib_bitmap_set(avail_cpu, c, 0);
              tr->coremask = clib_bitmap_set(tr->coremask, c, 1);
            }
        }
    }

  clib_bitmap_free(avail_cpu);

  tm->n_vlib_mains = n_vlib_mains;

  vec_validate_aligned (vlib_worker_threads, first_index-1,
                        CLIB_CACHE_LINE_BYTES);


  tm->efd.enabled = VLIB_EFD_DISABLED;
  tm->efd.queue_hi_thresh = ((VLIB_EFD_DEF_WORKER_HI_THRESH_PCT *
                              FRAME_QUEUE_NELTS)/100);
  return 0;
}

vlib_worker_thread_t *
vlib_alloc_thread (vlib_main_t * vm)
{
  vlib_worker_thread_t * w;

  if (vec_len(vlib_worker_threads) >= vec_len (vlib_thread_stacks))
    {
      clib_warning ("out of worker threads... Quitting...");
      exit(1);
    }
  vec_add2 (vlib_worker_threads, w, 1);
  w->thread_stack = vlib_thread_stacks[w - vlib_worker_threads];
  return w;
}

vlib_frame_queue_t * vlib_frame_queue_alloc (int nelts)
{
  vlib_frame_queue_t * fq;

  fq = clib_mem_alloc_aligned(sizeof (*fq), CLIB_CACHE_LINE_BYTES);
  memset (fq, 0, sizeof (*fq));
  fq->nelts = nelts;
  fq->vector_threshold = 128; // packets
  vec_validate_aligned (fq->elts, nelts-1, CLIB_CACHE_LINE_BYTES);

  if (1)
  {
    if (((uword)&fq->tail) & (CLIB_CACHE_LINE_BYTES - 1))
      fformat(stderr, "WARNING: fq->tail unaligned\n");
    if (((uword)&fq->head) & (CLIB_CACHE_LINE_BYTES - 1))
      fformat(stderr, "WARNING: fq->head unaligned\n");
    if (((uword)fq->elts) & (CLIB_CACHE_LINE_BYTES - 1))
      fformat(stderr, "WARNING: fq->elts unaligned\n");
    
    if (sizeof (fq->elts[0]) % CLIB_CACHE_LINE_BYTES)
      fformat(stderr, "WARNING: fq->elts[0] size %d\n", 
              sizeof (fq->elts[0]));
    if (nelts & (nelts -1))
      {
        fformat (stderr, "FATAL: nelts MUST be a power of 2\n");
        abort();
      }
  }
  
  return (fq);
}

void vl_msg_api_handler_no_free (void *) __attribute__ ((weak));
void vl_msg_api_handler_no_free (void *v) { }

/* Turned off, save as reference material... */
#if 0
static inline int vlib_frame_queue_dequeue_internal (int thread_id, 
                                                      vlib_main_t *vm, 
                                                      vlib_node_main_t *nm)
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
  
  ASSERT(vm == vlib_mains[thread_id]);

  while (1)
    {
      if (fq->head == fq->tail)
        return processed;

      elt = fq->elts + ((fq->head+1) & (fq->nelts-1));

      if (!elt->valid)
        return processed;

      before = clib_cpu_time_now();

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
      fq->dequeue_ticks += clib_cpu_time_now() - before;
      CLIB_MEMORY_BARRIER();
      fq->head++;
      processed++;
    }
  ASSERT(0);
  return processed;
}

int vlib_frame_queue_dequeue (int thread_id, 
                               vlib_main_t *vm, 
                               vlib_node_main_t *nm)
{
  return vlib_frame_queue_dequeue_internal (thread_id, vm, nm);
}

int vlib_frame_queue_enqueue (vlib_main_t *vm, u32 node_runtime_index,
                              u32 frame_queue_index, vlib_frame_t *frame,
                              vlib_frame_queue_msg_type_t type)
{
  vlib_frame_queue_t *fq = vlib_frame_queues[frame_queue_index];
  vlib_frame_queue_elt_t *elt;
  u32 save_count;
  u64 new_tail;
  u64 before = clib_cpu_time_now();
  
  ASSERT (fq);

  new_tail = __sync_add_and_fetch (&fq->tail, 1);

  /* Wait until a ring slot is available */
  while (new_tail >= fq->head + fq->nelts)
    {
      f64 b4 = vlib_time_now_ticks (vm, before);
      vlib_worker_thread_barrier_check (vm, b4);
      /* Bad idea. Dequeue -> enqueue -> dequeue -> trouble */
      // vlib_frame_queue_dequeue (vm->cpu_index, vm, nm);
    }

  elt = fq->elts + (new_tail & (fq->nelts-1));

  /* this would be very bad... */
  while (elt->valid) 
    {
    }

  /* Once we enqueue the frame, frame->n_vectors is owned elsewhere... */
  save_count = frame->n_vectors;

  elt->frame = frame;
  elt->node_runtime_index = node_runtime_index;
  elt->msg_type = type;
  CLIB_MEMORY_BARRIER();
  elt->valid = 1;

  return save_count;
}
#endif /* 0 */

/* To be called by vlib worker threads upon startup */
void vlib_worker_thread_init (vlib_worker_thread_t * w)
{
  vlib_thread_main_t *tm = vlib_get_thread_main();
  
  /* worker threads wants no signals. */
  {
    sigset_t s;
    sigfillset (&s);
    pthread_sigmask (SIG_SETMASK, &s, 0);
  }

  clib_mem_set_heap (w->thread_mheap);

  if (vec_len(tm->thread_prefix) && w->registration->short_name)
    {
      w->name = format(0, "%v_%s_%d%c", tm->thread_prefix,
                                        w->registration->short_name,
                                        w->instance_id,
                                        '\0');
      vlib_set_thread_name((char *)w->name);
    }

  if (!w->registration->use_pthreads)
    {

      /* Initial barrier sync, for both worker and i/o threads */
      clib_smp_atomic_add (vlib_worker_threads->workers_at_barrier, 1);

      while (*vlib_worker_threads->wait_at_barrier)
          ;

      clib_smp_atomic_add (vlib_worker_threads->workers_at_barrier, -1);
    }
}

void *vlib_worker_thread_bootstrap_fn (void *arg)
{
  void *rv;
  vlib_worker_thread_t *w = arg;
  
  w->lwp = syscall(SYS_gettid);
  w->dpdk_lcore_id = -1;
#if DPDK==1
  if (w->registration && !w->registration->use_pthreads &&
      rte_socket_id) /* do we really have dpdk linked */
    {
      unsigned lcore = rte_lcore_id();
      lcore = lcore < RTE_MAX_LCORE ? lcore : -1;
      w->dpdk_lcore_id = lcore;
    }
#endif

  rv = (void *) clib_calljmp 
      ((uword (*)(uword)) w->thread_function, 
       (uword) arg, w->thread_stack + VLIB_THREAD_STACK_SIZE);
  /* NOTREACHED, we hope */
  return rv;
}

static int
vlib_launch_thread (void *fp, vlib_worker_thread_t *w, unsigned lcore_id)
{
  pthread_t dummy;
  void *(*fp_arg)(void *) = fp;

#if DPDK==1
  if (!w->registration->use_pthreads)
    if (rte_eal_remote_launch) /* do we have dpdk linked */
      return rte_eal_remote_launch (fp, (void *)w, lcore_id);
    else
      return -1;
  else
#endif
    return pthread_create (&dummy, NULL /* attr */, fp_arg, (void *)w);
}

static clib_error_t * start_workers (vlib_main_t * vm)
{
  int i, j;
  vlib_worker_thread_t *w;
  vlib_main_t *vm_clone;
  void *oldheap;
  vlib_frame_queue_t *fq;
  vlib_thread_main_t * tm = &vlib_thread_main;
  vlib_thread_registration_t * tr; 
  vlib_node_runtime_t * rt;
  u32 n_vlib_mains = tm->n_vlib_mains;
  u32 worker_thread_index;

  vec_reset_length (vlib_worker_threads);

  /* Set up the main thread */
  vec_add2_aligned (vlib_worker_threads, w, 1, CLIB_CACHE_LINE_BYTES);
  w->elog_track.name = "main thread";
  elog_track_register (&vm->elog_main, &w->elog_track);

  if (vec_len(tm->thread_prefix))
    {
      w->name = format(0, "%v_main%c", tm->thread_prefix, '\0');
      vlib_set_thread_name((char *)w->name);
    }

#if DPDK==1
  w->dpdk_lcore_id = -1;
  if (rte_socket_id) /* do we really have dpdk linked */
    {
      unsigned lcore = rte_lcore_id();
      w->dpdk_lcore_id = lcore < RTE_MAX_LCORE ? lcore : -1;;
    }
#endif

  if (n_vlib_mains > 1)
    {
      u8 * heap = clib_mem_get_per_cpu_heap();
      mheap_t * h = mheap_header (heap);
      
      /* make the main heap thread-safe */
      h->flags |= MHEAP_FLAG_THREAD_SAFE;
      
      /* Make the event-log MP-safe */
      vm->elog_main.lock = 
        clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES, 
                                CLIB_CACHE_LINE_BYTES);
  
      vm->elog_main.lock[0] = 0;

      vec_validate (vlib_mains, tm->n_vlib_mains - 1);
      _vec_len (vlib_mains) = 0;
      vec_add1 (vlib_mains, vm);

      vec_validate (vlib_frame_queues, tm->n_vlib_mains - 1);
      _vec_len (vlib_frame_queues) = 0;
      fq = vlib_frame_queue_alloc (FRAME_QUEUE_NELTS);
      vec_add1 (vlib_frame_queues, fq);

      vlib_worker_threads->wait_at_barrier = 
        clib_mem_alloc_aligned (sizeof (u32), CLIB_CACHE_LINE_BYTES);
      vlib_worker_threads->workers_at_barrier =
        clib_mem_alloc_aligned (sizeof (u32), CLIB_CACHE_LINE_BYTES);

      /* Ask for an initial barrier sync */
      *vlib_worker_threads->workers_at_barrier = 0;
      *vlib_worker_threads->wait_at_barrier = 1;

      worker_thread_index = 1;

      for (i = 0; i < vec_len(tm->registrations); i++)
        {
          vlib_node_main_t *nm, *nm_clone;
          vlib_buffer_main_t *bm_clone;
          vlib_buffer_free_list_t *fl_clone, *fl_orig;
          vlib_buffer_free_list_t *orig_freelist_pool;
          int k;

          tr = tm->registrations[i];

          if (tr->count == 0)
            continue;

          for (k = 0; k < tr->count; k++)
          {
            vec_add2 (vlib_worker_threads, w, 1);
            /* 
             * Share the main heap which is now thread-safe.
             *
             * To allocate separate heaps, code:
             * mheap_alloc (0 / * use VM * /, tr->mheap_size);
             */
            w->thread_mheap = heap;
            w->thread_stack = vlib_thread_stacks[w - vlib_worker_threads];
            w->thread_function = tr->function;
            w->thread_function_arg = w;
            w->instance_id = k;
            w->registration = tr; 
            
            w->elog_track.name = 
                (char *) format (0, "%s %d", tr->name, k+1);
            vec_add1 (w->elog_track.name, 0);
            elog_track_register (&vm->elog_main, &w->elog_track);
            
            if (tr->no_data_structure_clone)
              continue;

            /* Allocate "to-worker-N" frame queue */
            fq = vlib_frame_queue_alloc (FRAME_QUEUE_NELTS);
            vec_validate (vlib_frame_queues, worker_thread_index);
            vlib_frame_queues[worker_thread_index] = fq;

            /* Fork vlib_global_main et al. Look for bugs here */
            oldheap = clib_mem_set_heap (w->thread_mheap);

            vm_clone = clib_mem_alloc (sizeof (*vm_clone));
            memcpy (vm_clone, vlib_mains[0], sizeof (*vm_clone));

            vm_clone->cpu_index = worker_thread_index;
            vm_clone->heap_base = w->thread_mheap;
            vm_clone->mbuf_alloc_list = 0;
            memset (&vm_clone->random_buffer, 0, sizeof (vm_clone->random_buffer));

            nm = &vlib_mains[0]->node_main;
            nm_clone = &vm_clone->node_main;
            /* fork next frames array, preserving node runtime indices */
            nm_clone->next_frames = vec_dup (nm->next_frames);
            for (j = 0; j < vec_len (nm_clone->next_frames); j++)
              {
                vlib_next_frame_t *nf = &nm_clone->next_frames[j];
                u32 save_node_runtime_index;

                save_node_runtime_index = nf->node_runtime_index;
                vlib_next_frame_init (nf);
                nf->node_runtime_index = save_node_runtime_index;
              }

            /* fork the frame dispatch queue */
            nm_clone->pending_frames = 0;
            vec_validate (nm_clone->pending_frames, 10); /* $$$$$?????? */
            _vec_len (nm_clone->pending_frames) = 0;

            /* fork nodes */
            nm_clone->nodes = 0;
            for (j = 0; j < vec_len (nm->nodes); j++) 
              {
                vlib_node_t *n;
                n = clib_mem_alloc_no_fail (sizeof(*n));
                memcpy (n, nm->nodes[j], sizeof (*n));
                /* none of the copied nodes have enqueue rights given out */
                n->owner_node_index = VLIB_INVALID_NODE_INDEX;
                memset (&n->stats_total, 0, sizeof (n->stats_total));
                memset (&n->stats_last_clear, 0, sizeof (n->stats_last_clear));
                vec_add1 (nm_clone->nodes, n);
              }
            nm_clone->nodes_by_type[VLIB_NODE_TYPE_INTERNAL] =
              vec_dup (nm->nodes_by_type[VLIB_NODE_TYPE_INTERNAL]);

            nm_clone->nodes_by_type[VLIB_NODE_TYPE_INPUT] =
              vec_dup (nm->nodes_by_type[VLIB_NODE_TYPE_INPUT]);
            vec_foreach(rt, nm_clone->nodes_by_type[VLIB_NODE_TYPE_INPUT])
              rt->cpu_index = vm_clone->cpu_index;

            nm_clone->processes = vec_dup (nm->processes);

            /* zap the (per worker) frame freelists, etc */
            nm_clone->frame_sizes = 0;
            nm_clone->frame_size_hash = 0;

            /* Packet trace buffers are guaranteed to be empty, nothing to do here */

            clib_mem_set_heap (oldheap);
            vec_add1 (vlib_mains, vm_clone);

            unix_physmem_init (vm_clone, 0 /* physmem not required */);

	    vm_clone->error_main.counters =
	      vec_dup(vlib_mains[0]->error_main.counters);
	    vm_clone->error_main.counters_last_clear =
	      vec_dup(vlib_mains[0]->error_main.counters_last_clear);

            /* Fork the vlib_buffer_main_t free lists, etc. */
            bm_clone = vec_dup (vm_clone->buffer_main);
            vm_clone->buffer_main = bm_clone;

            orig_freelist_pool = bm_clone->buffer_free_list_pool;
            bm_clone->buffer_free_list_pool = 0;

            pool_foreach (fl_orig, orig_freelist_pool,
                          ({
                            pool_get_aligned (bm_clone->buffer_free_list_pool, 
                                              fl_clone, CLIB_CACHE_LINE_BYTES);
                            ASSERT (fl_orig - orig_freelist_pool 
                                    == fl_clone - bm_clone->buffer_free_list_pool);

                            fl_clone[0] = fl_orig[0];
                            fl_clone->aligned_buffers = 0;
                            fl_clone->unaligned_buffers = 0;
                            fl_clone->n_alloc = 0;
                          }));

            worker_thread_index++;
          }
        }
    }
  else
    {
      /* only have non-data-structure copy threads to create... */
      for (i = 0; i < vec_len(tm->registrations); i++)
        {
          tr = tm->registrations[i];

          for (j = 0; j < tr->count; j++)
            {
              vec_add2 (vlib_worker_threads, w, 1);
              w->thread_mheap = mheap_alloc (0 /* use VM */, tr->mheap_size);
              w->thread_stack = vlib_thread_stacks[w - vlib_worker_threads];
              w->thread_function = tr->function;
              w->thread_function_arg = w;
              w->instance_id = j;
              w->elog_track.name = 
                  (char *) format (0, "%s %d", tr->name, j+1);
              w->registration = tr;
              vec_add1 (w->elog_track.name, 0);
              elog_track_register (&vm->elog_main, &w->elog_track);
            }
        }
    }

  worker_thread_index = 1;

  for (i = 0; i < vec_len (tm->registrations); i++)
    {
      int j;

      tr = tm->registrations[i];

      if (tr->use_pthreads || tm->use_pthreads)
        {
          for (j = 0; j < tr->count; j++)
            {
              w = vlib_worker_threads + worker_thread_index++;
              if (vlib_launch_thread (vlib_worker_thread_bootstrap_fn, w, 0) < 0)
                clib_warning ("Couldn't start '%s' pthread ", tr->name);
            }
        }
      else
        {
            uword c;
            clib_bitmap_foreach (c, tr->coremask, ({
              w = vlib_worker_threads + worker_thread_index++;
              if (vlib_launch_thread (vlib_worker_thread_bootstrap_fn, w, c) < 0)
                clib_warning ("Couldn't start DPDK lcore %d", c);

            }));
        }
    }
  vlib_worker_thread_barrier_sync(vm);
  vlib_worker_thread_barrier_release(vm);
  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (start_workers);

void vlib_worker_thread_node_runtime_update(void)
{
  int i, j;
  vlib_worker_thread_t *w;
  vlib_main_t *vm;
  vlib_node_main_t *nm, *nm_clone;
  vlib_node_t ** old_nodes_clone;
  vlib_main_t *vm_clone;
  vlib_node_runtime_t * rt, * old_rt;
  void *oldheap;
  never_inline void
    vlib_node_runtime_sync_stats (vlib_main_t * vm,
                                  vlib_node_runtime_t * r,
                                  uword n_calls,
                                  uword n_vectors,
                                  uword n_clocks);
  
  ASSERT (os_get_cpu_number() == 0);

  if (vec_len (vlib_mains) == 0)
    return;

  vm = vlib_mains[0];
  nm = &vm->node_main;

  ASSERT (os_get_cpu_number() == 0);
  ASSERT (*vlib_worker_threads->wait_at_barrier == 1);

  /* 
   * Scrape all runtime stats, so we don't lose node runtime(s) with
   * pending counts, or throw away worker / io thread counts.
   */
  for (j = 0; j < vec_len (nm->nodes); j++) 
    {
      vlib_node_t * n;
      n = nm->nodes[j];
      vlib_node_sync_stats (vm, n);
    }

  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      vlib_node_t * n;
      
      vm_clone = vlib_mains[i];
      nm_clone = &vm_clone->node_main;

      for (j = 0; j < vec_len (nm_clone->nodes); j++) 
        {
          n = nm_clone->nodes[j];

          rt = vlib_node_get_runtime (vm_clone, n->index);
          vlib_node_runtime_sync_stats (vm_clone, rt, 0, 0, 0);
        }
    }

  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      vlib_node_runtime_t * rt;
      w = vlib_worker_threads + i;
      oldheap = clib_mem_set_heap (w->thread_mheap);

      vm_clone = vlib_mains[i];

      /* Re-clone error heap */
      u64 * old_counters = vm_clone->error_main.counters;
      u64 * old_counters_all_clear = vm_clone->error_main.counters_last_clear;
      memcpy (&vm_clone->error_main, &vm->error_main, sizeof (vm->error_main));
      j = vec_len(vm->error_main.counters) - 1;
      vec_validate_aligned(old_counters, j, CLIB_CACHE_LINE_BYTES);
      vec_validate_aligned(old_counters_all_clear, j, CLIB_CACHE_LINE_BYTES);
      vm_clone->error_main.counters = old_counters;
      vm_clone->error_main.counters_last_clear = old_counters_all_clear;

      nm_clone = &vm_clone->node_main;
      vec_free (nm_clone->next_frames);
      nm_clone->next_frames = vec_dup (nm->next_frames);

      for (j = 0; j < vec_len (nm_clone->next_frames); j++)
        {
          vlib_next_frame_t *nf = &nm_clone->next_frames[j];
          u32 save_node_runtime_index;

          save_node_runtime_index = nf->node_runtime_index;
          vlib_next_frame_init (nf);
          nf->node_runtime_index = save_node_runtime_index;
        }

      old_nodes_clone = nm_clone->nodes;
      nm_clone->nodes = 0;

      /* re-fork nodes */
      for (j = 0; j < vec_len (nm->nodes); j++) {
        vlib_node_t *old_n_clone;
        vlib_node_t *new_n, *new_n_clone;

        new_n = nm->nodes[j];
        old_n_clone = old_nodes_clone[j];

        new_n_clone = clib_mem_alloc_no_fail (sizeof(*new_n_clone));
        memcpy (new_n_clone, new_n, sizeof (*new_n));
        /* none of the copied nodes have enqueue rights given out */
        new_n_clone->owner_node_index = VLIB_INVALID_NODE_INDEX;

        if (j >= vec_len (old_nodes_clone))
          {
            /* new node, set to zero */
            memset (&new_n_clone->stats_total, 0, 
                    sizeof (new_n_clone->stats_total));
            memset (&new_n_clone->stats_last_clear, 0, 
                    sizeof (new_n_clone->stats_last_clear));
          }
        else
          {
            /* Copy stats if the old data is valid */
            memcpy (&new_n_clone->stats_total, 
                    &old_n_clone->stats_total,
                    sizeof (new_n_clone->stats_total));
            memcpy (&new_n_clone->stats_last_clear, 
                    &old_n_clone->stats_last_clear,
                    sizeof (new_n_clone->stats_last_clear));

            /* keep previous node state */
            new_n_clone->state = old_n_clone->state;
          }
        vec_add1 (nm_clone->nodes, new_n_clone);
      }
      /* Free the old node clone */
      for (j = 0; j < vec_len(old_nodes_clone); j++)
        clib_mem_free (old_nodes_clone[j]);
      vec_free (old_nodes_clone);
      
      vec_free (nm_clone->nodes_by_type[VLIB_NODE_TYPE_INTERNAL]);

      nm_clone->nodes_by_type[VLIB_NODE_TYPE_INTERNAL] =
          vec_dup (nm->nodes_by_type[VLIB_NODE_TYPE_INTERNAL]);

      /* clone input node runtime */
      old_rt = nm_clone->nodes_by_type[VLIB_NODE_TYPE_INPUT];

      nm_clone->nodes_by_type[VLIB_NODE_TYPE_INPUT] =
        vec_dup (nm->nodes_by_type[VLIB_NODE_TYPE_INPUT]);

      vec_foreach(rt, nm_clone->nodes_by_type[VLIB_NODE_TYPE_INPUT])
        {
          rt->cpu_index = vm_clone->cpu_index;
        }

      for (j=0; j < vec_len(old_rt); j++)
        {
          rt = vlib_node_get_runtime (vm_clone, old_rt[j].node_index);
          rt->state = old_rt[j].state;
        }

      vec_free(old_rt);

      nm_clone->processes = vec_dup (nm->processes);

      clib_mem_set_heap (oldheap);

      // vnet_main_fork_fixup (i);
    }
}

static clib_error_t *
cpu_config (vlib_main_t * vm, unformat_input_t * input)
{
  vlib_thread_registration_t *tr;
  uword * p;
  vlib_thread_main_t * tm = &vlib_thread_main;
  u8 * name;
  u64 coremask;
  uword * bitmap;
  u32 count;

  tm->thread_registrations_by_name = hash_create_string (0, sizeof (uword));
  tm->n_thread_stacks = 1;      /* account for main thread */

  tr = tm->next;

  while (tr)
    {
      hash_set_mem (tm->thread_registrations_by_name, tr->name, (uword)tr);
      tr = tr->next;
    }

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "main-thread-io"))
        tm->main_thread_is_io_node = 1;
      else if (unformat (input, "use-pthreads"))
        tm->use_pthreads = 1;
      else if (unformat (input, "thread-prefix %v", &tm->thread_prefix))
          ;
      else if (unformat (input, "main-core %u", &tm->main_lcore))
          ;
      else if (unformat (input, "skip-cores %u", &tm->skip_cores))
          ;
      else if (unformat (input, "coremask-%s %llx", &name, &coremask))
        {
          p = hash_get_mem (tm->thread_registrations_by_name, name);
          if (p == 0)
            return clib_error_return (0, "no such thread type '%s'", name);

          tr = (vlib_thread_registration_t *)p[0];

          if  (tr->use_pthreads)
            return clib_error_return (0, "coremask cannot be set for '%s' threads",
                                      name);

          tr->coremask = clib_bitmap_set_multiple 
            (tr->coremask, 0, coremask, BITS(coremask));
          tr->count = clib_bitmap_count_set_bits (tr->coremask);
        }
      else if (unformat (input, "corelist-%s %U", &name, unformat_bitmap_list,
               &bitmap))
        {
          p = hash_get_mem (tm->thread_registrations_by_name, name);
          if (p == 0)
            return clib_error_return (0, "no such thread type '%s'", name);

          tr = (vlib_thread_registration_t *)p[0];

          if  (tr->use_pthreads)
            return clib_error_return (0, "corelist cannot be set for '%s' threads",
                                      name);

          tr->coremask = bitmap;
          tr->count = clib_bitmap_count_set_bits (tr->coremask);
        }
      else if (unformat (input, "%s %u", &name, &count))
        {
          p = hash_get_mem (tm->thread_registrations_by_name, name);
          if (p == 0)
              return clib_error_return (0, "no such thread type '%s'", name);
                                        
          tr = (vlib_thread_registration_t *)p[0];
          if (tr->fixed_count)
            return clib_error_return 
              (0, "number of %s threads not configurable", tr->name);
          tr->count = count;
        }
      else 
        break;
    }

  tr = tm->next;

  if (!tm->thread_prefix)
    tm->thread_prefix = format(0, "vpp");

  while (tr)
    {
      tm->n_thread_stacks += tr->count;
      tm->n_pthreads += tr->count * tr->use_pthreads;
      tm->n_eal_threads += tr->count * (tr->use_pthreads == 0);
      tr = tr->next;
    }

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (cpu_config, "cpu");

#if !defined (__x86_64__) && !defined (__aarch64__) && !defined (__powerpc64__)
void __sync_fetch_and_add_8 (void)
{
  fformat(stderr, "%s called\n", __FUNCTION__);
  abort();
}
void __sync_add_and_fetch_8 (void)
{
  fformat(stderr, "%s called\n", __FUNCTION__);
  abort();
}
#endif

void vnet_main_fixup (vlib_fork_fixup_t which) __attribute__ ((weak));
void vnet_main_fixup (vlib_fork_fixup_t which) { }

void vlib_worker_thread_fork_fixup (vlib_fork_fixup_t which)
{
  vlib_main_t * vm = vlib_get_main();

  if (vlib_mains == 0)
    return;

  ASSERT(os_get_cpu_number() == 0);
  vlib_worker_thread_barrier_sync(vm);

  switch (which)
    {
    case VLIB_WORKER_THREAD_FORK_FIXUP_NEW_SW_IF_INDEX:
      vnet_main_fixup (VLIB_WORKER_THREAD_FORK_FIXUP_NEW_SW_IF_INDEX);
      break;

    default:
      ASSERT(0);
    }
  vlib_worker_thread_barrier_release(vm);
}

void vlib_worker_thread_barrier_sync(vlib_main_t *vm)
{
  f64 deadline;
  u32 count;
  
  if (!vlib_mains)
      return;

  count = vec_len (vlib_mains) - 1;

  /* Tolerate recursive calls */
  if (++vlib_worker_threads[0].recursion_level > 1)
      return;

  ASSERT (os_get_cpu_number() == 0);

  deadline = vlib_time_now (vm) + BARRIER_SYNC_TIMEOUT;

  *vlib_worker_threads->wait_at_barrier = 1;
  while (*vlib_worker_threads->workers_at_barrier != count)
    {
      if (vlib_time_now(vm) > deadline)
        {
          fformat(stderr, "%s: worker thread deadlock\n", __FUNCTION__);
          os_panic();
        }
    }
}

void vlib_worker_thread_barrier_release(vlib_main_t * vm)
{
  f64 deadline;

  if (!vlib_mains)
      return;

  if (--vlib_worker_threads[0].recursion_level > 0)
    return;

  deadline = vlib_time_now (vm) + BARRIER_SYNC_TIMEOUT;

  *vlib_worker_threads->wait_at_barrier = 0;

  while (*vlib_worker_threads->workers_at_barrier > 0)
    {
      if (vlib_time_now(vm) > deadline)
        {
          fformat(stderr, "%s: worker thread deadlock\n", __FUNCTION__);
          os_panic();
        }
    }
}

static clib_error_t *
show_threads_fn (vlib_main_t * vm,
       unformat_input_t * input,
       vlib_cli_command_t * cmd)
{
  vlib_worker_thread_t * w;
  int i;

  vlib_cli_output (vm, "%-7s%-20s%-12s%-8s%-7s%-7s%-7s%-10s",
                   "ID", "Name", "Type", "LWP",
                   "lcore", "Core", "Socket", "State");

#if !defined(__powerpc64__)
  for (i = 0; i < vec_len(vlib_worker_threads); i++)
    {
      w = vlib_worker_threads + i;
      u8 * line = NULL;

      line = format(line, "%-7d%-20s%-12s%-8d",
                    i,
                    w->name ? w->name : (u8 *) "",
                    w->registration ? w->registration->name : "",
                    w->lwp);

      int lcore = w->dpdk_lcore_id;
      if (lcore > -1)
        {
          line = format(line, "%-7u%-7u%-7u",
                        lcore,
                        lcore_config[lcore].core_id,
                        lcore_config[lcore].socket_id);

          switch(lcore_config[lcore].state)
            {
              case WAIT:
                line = format(line, "wait");
                break;
              case RUNNING:
                line = format(line, "running");
                break;
              case FINISHED:
                line = format(line, "finished");
                break;
              default:
                line = format(line, "unknown");
            }
        }

      vlib_cli_output(vm, "%v", line);
      vec_free(line);
    }
#endif

  return 0;
}


VLIB_CLI_COMMAND (show_threads_command, static) = {
  .path = "show threads",
  .short_help = "Show threads",
  .function = show_threads_fn,
};
