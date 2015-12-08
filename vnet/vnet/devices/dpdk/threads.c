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
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <signal.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/dpdk/dpdk.h>

#include <vlibmemory/api.h>
#include <vlibmemory/vl_memory_msg_enum.h> /* enumerate all vlib messages */

#define vl_typedefs             /* define message structures */
#include <vlibmemory/vl_memory_api_h.h> 
#undef vl_typedefs

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vlibmemory/vl_memory_api_h.h> 
#undef vl_printfun

vlib_thread_main_t vlib_thread_main;

frame_queue_trace_t *frame_queue_traces;

/*
 * Check the frame queue to see if any frames are available.
 * If so, pull the packets off the frames and put them to 
 * the handoff node.
 */
static inline int vlib_frame_queue_dequeue_internal (vlib_main_t *vm)
{
  u32 thread_id = vm->cpu_index;
  vlib_frame_queue_t *fq = vlib_frame_queues[thread_id];
  vlib_frame_queue_elt_t *elt;
  u32 * from, * to;
  vlib_frame_t * f;
  int msg_type;
  int processed = 0;
  u32 n_left_to_node;
  u32 vectors = 0;

  ASSERT (fq);
  ASSERT(vm == vlib_mains[thread_id]);

  /*
   * Gather trace data for frame queues
   */
  if (PREDICT_FALSE(fq->trace))
    {
      frame_queue_trace_t *fqt;
      u32 elix;
   
      fqt = &frame_queue_traces[thread_id];
      fqt->nelts = fq->nelts;
      fqt->head = fq->head;
      fqt->head_hint = fq->head_hint;
      fqt->tail = fq->tail;
      fqt->threshold = fq->vector_threshold;
      fqt->n_in_use = fqt->tail - fqt->head;
      if (fqt->n_in_use > fqt->nelts){
        fqt->n_in_use = 0;
      }

      for (elix=0; elix<fqt->nelts; elix++) {
        elt = fq->elts + ((fq->head+1 + elix) & (fq->nelts-1));
        if (1 || elt->valid) 
          {
            fqt->n_vectors[elix] = elt->n_vectors;
          }
      }
      fqt->written = 1;
    }

  while (1)
    {
      if (fq->head == fq->tail)
        {
          fq->head_hint = fq->head;
          return processed;
        }
      
      elt = fq->elts + ((fq->head+1) & (fq->nelts-1));
      
      if (!elt->valid)
        {
          fq->head_hint = fq->head;
          return processed;
        }

      from = elt->buffer_index;
      msg_type = elt->msg_type;

      ASSERT (msg_type == VLIB_FRAME_QUEUE_ELT_DISPATCH_FRAME);
      ASSERT (elt->n_vectors <= VLIB_FRAME_SIZE);

      f = vlib_get_frame_to_node 
          (vm, 1 ? handoff_dispatch_node.index : ethernet_input_node.index);

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
      vlib_put_frame_to_node 
          (vm, 1 ? handoff_dispatch_node.index : ethernet_input_node.index, f);

      elt->valid = 0;
      elt->n_vectors = 0;
      elt->msg_type = 0xfefefefe;
      CLIB_MEMORY_BARRIER();
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
  ASSERT(0);
  return processed;
}

int dpdk_frame_queue_dequeue (vlib_main_t *vm) 
{
  return vlib_frame_queue_dequeue_internal (vm);
}

/*
 * dpdk_worker_thread - Contains the main loop of a worker thread.
 *
 * w
 *     Information for the current thread
 * io_name
 *     The name of thread performing dpdk device IO (if any). If there are no
 *     instances of that thread, then the current thread will do dpdk device
 *     polling. Ports will be divided among instances of the current thread.
 * callback
 *     If not null, this function will be called once during each main loop.
 */
static_always_inline void
dpdk_worker_thread_internal (vlib_main_t *vm,
                             dpdk_worker_thread_callback_t callback,
                             int have_io_threads)
{
  vlib_node_main_t * nm = &vm->node_main;
  u64 cpu_time_now = clib_cpu_time_now ();

  while (1)
    {
      vlib_worker_thread_barrier_check ();

      vlib_frame_queue_dequeue_internal (vm);

      /* Invoke callback if supplied */
      if (PREDICT_FALSE(callback != NULL))
          callback(vm);

      if (!have_io_threads)
        {
          vlib_node_runtime_t * n;
          vec_foreach (n, nm->nodes_by_type[VLIB_NODE_TYPE_INPUT])
            {
              cpu_time_now = dispatch_node (vm, n, VLIB_NODE_TYPE_INPUT,
                                            VLIB_NODE_STATE_POLLING, /* frame */ 0,
                                            cpu_time_now);
            }

        }

      if (_vec_len (nm->pending_frames))
        {
          int i;
          cpu_time_now = clib_cpu_time_now ();
          for (i = 0; i < _vec_len (nm->pending_frames); i++) {
            vlib_pending_frame_t *p;

            p = nm->pending_frames + i;

            cpu_time_now = dispatch_pending_node (vm, p, cpu_time_now);
          }
          _vec_len (nm->pending_frames) = 0;
        }
      vlib_increment_main_loop_counter (vm);

      /* Record time stamp in case there are no enabled nodes and above
         calls do not update time stamp. */
      cpu_time_now = clib_cpu_time_now ();
    }
}

void dpdk_worker_thread (vlib_worker_thread_t * w,
                         char *io_name,
                         dpdk_worker_thread_callback_t callback)
{
  vlib_main_t *vm;
  uword * p;
  vlib_thread_main_t * tm = vlib_get_thread_main();
  vlib_thread_registration_t * tr;
  dpdk_main_t * dm = &dpdk_main;

  vm = vlib_get_main();

  ASSERT(vm->cpu_index == os_get_cpu_number());

  clib_time_init (&vm->clib_time);
  clib_mem_set_heap (w->thread_mheap);

  /* Wait until the dpdk init sequence is complete */
  while (dm->io_thread_release == 0)
    vlib_worker_thread_barrier_check ();

  /* any I/O threads? */
  p = hash_get_mem (tm->thread_registrations_by_name, io_name);
  tr = (vlib_thread_registration_t *)p[0];

  if (tr && tr->count > 0)
    dpdk_worker_thread_internal(vm, callback, /* have_io_threads */ 1);
  else
    dpdk_worker_thread_internal(vm, callback, /* have_io_threads */ 0);
}

void dpdk_worker_thread_fn (void * arg)
{
  vlib_worker_thread_t *w = (vlib_worker_thread_t *) arg;
  vlib_worker_thread_init (w);
  dpdk_worker_thread (w, "io", 0);
}

#if VIRL == 0
VLIB_REGISTER_THREAD (worker_thread_reg, static) = {
  .name = "workers",
  .short_name = "wk",
  .function = dpdk_worker_thread_fn,
  .mheap_size = 256<<20,
};
#endif

void dpdk_io_thread_fn (void * arg)
{
  vlib_worker_thread_t *w = (vlib_worker_thread_t *) arg;
  vlib_worker_thread_init (w);
  dpdk_io_thread (w, 0, 0, "workers", 0);
}

#if VIRL == 0
VLIB_REGISTER_THREAD (io_thread_reg, static) = {
  .name = "io",
  .short_name = "io",
  .function = dpdk_io_thread_fn,
  .mheap_size = 256<<20,
};
#endif

static void vl_api_rpc_call_t_handler (vl_api_rpc_call_t * mp)
{
  vl_api_rpc_reply_t * rmp;
  int (*fp)(void *);
  i32 rv = 0;
  vlib_main_t * vm = vlib_get_main();

  if (mp->function == 0)
    {
      rv = -1;
      clib_warning ("rpc NULL function pointer");
    }
  
  else
    {
      if (mp->need_barrier_sync)
        vlib_worker_thread_barrier_sync (vm);

      fp = (void *)(mp->function);
      rv = (*fp)(mp->data);

      if (mp->need_barrier_sync)
        vlib_worker_thread_barrier_release (vm);
    }

  if (mp->send_reply)
    {
      unix_shared_memory_queue_t * q =
        vl_api_client_index_to_input_queue (mp->client_index);
      if (q)
        {
          rmp = vl_msg_api_alloc_as_if_client (sizeof (*rmp));
          rmp->_vl_msg_id = ntohs (VL_API_RPC_REPLY);
          rmp->context = mp->context;
          rmp->retval = rv;
          vl_msg_api_send_shmem (q, (u8 *)&rmp);
        }
    }
  if (mp->multicast)
    {
      clib_warning ("multicast not yet implemented...");
    }
}

static void vl_api_rpc_reply_t_handler (vl_api_rpc_reply_t * mp)
{ clib_warning ("unimplemented"); }

void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length)
{
  vl_api_rpc_call_t * mp;
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;

  mp = vl_msg_api_alloc_as_if_client (sizeof (*mp) + data_length);
  memset (mp, 0, sizeof (*mp));
  memcpy (mp->data, data, data_length);
  mp->_vl_msg_id = ntohs (VL_API_RPC_CALL);
  mp->function = (u64)fp;
  mp->need_barrier_sync = 1;
  
  /* Use the "normal" control-plane mechanism for the main thread */
  vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *)&mp);
}


#define foreach_rpc_api_msg                     \
_(RPC_CALL,rpc_call)                            \
_(RPC_REPLY,rpc_reply)

static clib_error_t *
rpc_api_hookup (vlib_main_t *vm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_noop_handler,			\
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 0 /* do not trace */); 
    foreach_rpc_api_msg;
#undef _
    return 0;
}

VLIB_API_INIT_FUNCTION(rpc_api_hookup);
