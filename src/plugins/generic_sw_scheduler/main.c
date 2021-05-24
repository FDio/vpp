/*
 * Copyright (c) 2021 Intel and/or its affiliates.
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

/**
 * Generic scheduler engine
 *                              _____________________
 * producer thread -(enqueue)-> | sw scheduler queue | --
 *                              ----------------------   \
 *                                 ^  ^                  |
 * worker thread A -(update flag---/  |                  |
 * worker thread B -(update flag)----/                   |
 *                                                       |
 * consumer thread <-(dequeue)--------------------------/
 *
 * Operation model:
 * 1. Producer thread enqueue: write and updates its own queue head.
 * 2. Worker threads dequeue: scans each producers' queue and update first data
 *    with flag == READY, update the flag to WIP to claim the data. The buffers
 *    in the data are then enqueued to distribute next node (handled by infra).
 *    The data pointer is also pushed to the thread's pending queue.
 * 3. Worker threads enqueue: assumption is made the data works in FIFO manner,
 *    The buffers enqueued first shall fit the first data in the pending queue,
 *    dequeue the data pointer and mark the flag to "DONE".
 * 4. Consumer dequeue: every consumer thread is assigned one or more
 * producer's queues. Find the first one with flag as "DONE" and push the
 * buffers to aggregate next node (handled by infra), and update the flag as
 * "IDLE" and update tail.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vppinfra/bitmap.h>
#include <vpp/app/version.h>

#include <vnet/scheduler/scheduler.h>

#define GEN_SW_SCHED_QUEUE_SIZE 64
#define GEN_SW_SCHED_QUEUE_MASK (GEN_SW_SCHED_QUEUE_SIZE - 1)
#define GEN_SW_SCHED_NB_BUFFERS 64

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define GEN_SW_SCHED_FLAG_IDLE	0x0
#define GEN_SW_SCHED_FLAG_READY 0x1
#define GEN_SW_SCHED_FLAG_WIP	0x2
#define GEN_SW_SCHED_FLAG_DONE	0x3
#define GEN_SW_SCHED_FLAG_MASK	0x3
  u8 flag;
  u16 n_buffers;
  u8 offset;
  u32 buffers[GEN_SW_SCHED_NB_BUFFERS];
  u16 nexts[GEN_SW_SCHED_NB_BUFFERS];
} gen_sw_scheduler_data_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 head;
  u32 tail;
  gen_sw_scheduler_data_t data[GEN_SW_SCHED_QUEUE_SIZE];
} gen_sw_scheduler_queue_t;

typedef struct
{
  u32 head;
  u32 tail;
  gen_sw_scheduler_data_t *d[GEN_SW_SCHED_QUEUE_SIZE];
} gen_sw_scheduler_pending_queue_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  gen_sw_scheduler_queue_t queue;
  gen_sw_scheduler_queue_t **working_queues;
  gen_sw_scheduler_queue_t **consumer_queues;
  gen_sw_scheduler_pending_queue_t *pending;
} gen_sw_scheduler_per_thread_data_t;

typedef struct
{
  u32 scheduler_engine_index;
  gen_sw_scheduler_per_thread_data_t *per_thread_data;
} gen_sw_scheduler_main_t;

gen_sw_scheduler_main_t gen_scheduler_main;

/**
 * Enqueue handler for generic scheduler
 *
 * If the event type is distribute, then enqueue to its own queue.
 * If the event type is aggregate, the data shall be dequeued by same
 *   thread prior to this point.
 *
 */
static_always_inline u32
enqueue_as_producer (vlib_main_t *vm, u32 *buffers, u16 *nexts, u32 n_buffers)
{
  gen_sw_scheduler_main_t *gsm = &gen_scheduler_main;
  gen_sw_scheduler_per_thread_data_t *ptd =
    gsm->per_thread_data + vm->thread_index;
  gen_sw_scheduler_data_t *d;
  gen_sw_scheduler_queue_t *q = &ptd->queue;
  u32 head = q->head;
  u32 n_left = n_buffers;

  while (n_left)
    {
      u32 n_to_enq;

      if (n_left > GEN_SW_SCHED_NB_BUFFERS)
	{
	  d = q->data + ((head + 1) & GEN_SW_SCHED_QUEUE_MASK);
	  CLIB_PREFETCH (d, CLIB_CACHE_LINE_BYTES, STORE);
	}

      d = q->data + (head & GEN_SW_SCHED_QUEUE_MASK);

      /* queue is full */
      if (d->flag != GEN_SW_SCHED_FLAG_IDLE)
	break;

      n_to_enq = clib_min (n_left, GEN_SW_SCHED_NB_BUFFERS);
      clib_memcpy_fast (d->buffers, buffers, n_to_enq * sizeof (u32));
      clib_memcpy_fast (d->nexts, nexts, n_to_enq * sizeof (u16));
      buffers += n_to_enq;
      nexts += n_to_enq;
      d->n_buffers = n_to_enq;
      d->flag = GEN_SW_SCHED_FLAG_READY;

      head++;
      n_left -= n_to_enq;
    }

  if (head != q->head)
    {
      CLIB_MEMORY_STORE_BARRIER ();
      q->head = head;
    }

  return n_buffers - n_left;
}

static_always_inline u32
enqueue_as_worker (vlib_main_t *vm, u32 *buffers, u16 *nexts, u32 n_buffers)
{
  gen_sw_scheduler_main_t *gsm = &gen_scheduler_main;
  gen_sw_scheduler_per_thread_data_t *ptd =
    gsm->per_thread_data + vm->thread_index;
  gen_sw_scheduler_pending_queue_t *pq = ptd->pending;
  u32 tail = pq->tail;
  u32 n_left = n_buffers;
  u32 n_enqd = 0;

  while (n_left)
    {
      gen_sw_scheduler_data_t *d = pq->d[tail & GEN_SW_SCHED_QUEUE_MASK];
      u32 n_to_deq;

      n_to_deq = clib_min (n_left, d->n_buffers - d->offset);
      /* update new next index for aggregate next node */
      clib_memcpy_fast (d->nexts + d->offset, nexts + n_enqd,
			n_to_deq * sizeof (u16));
      n_left -= n_to_deq;
      n_enqd += n_to_deq;

      /* all buffers in a data is in place */
      if (d->offset + n_to_deq == d->n_buffers)
	{
	  d->offset = 0;
	  pq->d[(tail & GEN_SW_SCHED_QUEUE_MASK)] = 0;
	  tail++;
	  d->flag = GEN_SW_SCHED_FLAG_DONE;
	}
      else
	{
	  d->offset += n_to_deq;
	  break;
	}
    }

  pq->tail = tail;

  return n_buffers - n_left;
}

static_always_inline u32
dequeue_as_worker (vlib_main_t *vm, u32 *buffers, u16 *nexts,
		   u32 max_n_buffers)
{
  gen_sw_scheduler_main_t *gsm = &gen_scheduler_main;
  gen_sw_scheduler_per_thread_data_t *ptd =
    gsm->per_thread_data + vm->thread_index;
  gen_sw_scheduler_queue_t **q;
  gen_sw_scheduler_pending_queue_t *pq = ptd->pending;

  for (q = ptd->working_queues; q < vec_end (ptd->working_queues); q++)
    {
      gen_sw_scheduler_data_t *d;
      u32 i;
      u32 tail = q[0]->tail;
      u32 head = q[0]->head;

      for (i = tail;
	   i < head && (pq->head - pq->tail != GEN_SW_SCHED_QUEUE_SIZE); i++)
	{
	  d = &q[0]->data[i & GEN_SW_SCHED_QUEUE_MASK];
	  if (clib_atomic_bool_cmp_and_swap (&d->flag, GEN_SW_SCHED_FLAG_READY,
					     GEN_SW_SCHED_FLAG_WIP))
	    {
	      ASSERT (d->n_buffers < max_n_buffers);

	      pq->d[pq->head & GEN_SW_SCHED_QUEUE_MASK] = d;

	      clib_memcpy_fast (buffers, d->buffers,
				sizeof (u32) * d->n_buffers);
	      clib_memcpy_fast (nexts, d->nexts, sizeof (u16) * d->n_buffers);

	      pq->head++;

	      return d->n_buffers;
	    }
	}
    }

  return 0;
}

static_always_inline u32
dequeue_as_consumer (vlib_main_t *vm, u32 *buffers, u16 *nexts,
		     u32 max_n_buffers)
{
  gen_sw_scheduler_main_t *gsm = &gen_scheduler_main;
  gen_sw_scheduler_per_thread_data_t *ptd =
    gsm->per_thread_data + vm->thread_index;
  gen_sw_scheduler_queue_t **cq;
  u32 n_buffers = 0;

  for (cq = ptd->consumer_queues;
       cq < vec_end (ptd->consumer_queues) && n_buffers < max_n_buffers; cq++)
    {
      gen_sw_scheduler_queue_t *q = cq[0];
      gen_sw_scheduler_data_t *d;
      u32 head = q->head;
      u32 tail = q->tail;

      if (head == tail)
	continue;

      while (tail != head && n_buffers < max_n_buffers)
	{
	  if (head - tail > 1)
	    {
	      d = q->data + ((tail + 1) & GEN_SW_SCHED_QUEUE_MASK);
	      CLIB_PREFETCH (d, CLIB_CACHE_LINE_BYTES, LOAD);
	    }
	  d = q->data + (tail & GEN_SW_SCHED_QUEUE_MASK);
	  if (d->flag != GEN_SW_SCHED_FLAG_DONE ||
	      (n_buffers + d->n_buffers > max_n_buffers))
	    break;

	  clib_memcpy_fast (buffers, d->buffers, sizeof (u32) * d->n_buffers);
	  clib_memcpy_fast (nexts, d->nexts, sizeof (u16) * d->n_buffers);

	  buffers += d->n_buffers;
	  nexts += d->n_buffers;
	  n_buffers += d->n_buffers;
	  tail++;
	  CLIB_MEMORY_STORE_BARRIER ();
	  d->flag = GEN_SW_SCHED_FLAG_IDLE;
	}

      if (tail != q->tail)
	{
	  CLIB_MEMORY_STORE_BARRIER ();
	  q->tail = tail;
	}
    }

  return n_buffers;
}

static_always_inline vnet_scheduler_thread_state_hint_t
set_thread_state (vlib_main_t *vm,
		  vnet_scheduler_thread_state_hint_t state_flags)
{
  vnet_scheduler_main_t *sm = &scheduler_main;
  gen_sw_scheduler_main_t *gsm = &gen_scheduler_main;
  gen_sw_scheduler_per_thread_data_t *ptd =
    gsm->per_thread_data + vm->thread_index;
  u32 i;

  if (state_flags & VNET_SCHEDULER_THREAD_STATE_WORKER_ENABLE)
    {
      vec_reset_length (ptd->working_queues);
      clib_bitmap_foreach (i, sm->producer_thread_indices)
	{
	  vec_add1 (ptd->working_queues, &gsm->per_thread_data[i].queue);
	}

      if (!ptd->pending)
	{
	  gen_sw_scheduler_pending_queue_t *pending;
	  pending = clib_mem_alloc_aligned_no_fail (sizeof (*pending),
						    CLIB_CACHE_LINE_BYTES);
	  memset (pending, 0, sizeof (*pending));
	  ptd->pending = pending;
	}

      state_flags &= ~VNET_SCHEDULER_THREAD_STATE_WORKER_ENABLE;
    }

  if (state_flags & VNET_SCHEDULER_THREAD_STATE_WORKER_DISABLE)
    {
      /* worker thread indice needs to be removed.
       * in case pending queue not empty, clearing worker role flag
       * still prevents the dequeue operation. */
      vec_reset_length (ptd->working_queues);

      if (!ptd->pending)
	{
	  state_flags &= ~VNET_SCHEDULER_THREAD_STATE_WORKER_DISABLE;
	}
      else if (ptd->pending->head == ptd->pending->tail)
	{
	  state_flags &= ~VNET_SCHEDULER_THREAD_STATE_WORKER_DISABLE;
	}

      /* else: pending queue not drained, not clear the flag */
    }

  /* consumer role needs to be updated */
  if (state_flags & VNET_SCHEDULER_THREAD_STATE_CONSUMER_ENABLE)
    {
      clib_bitmap_t *pti = sm->producer_thread_indices;
      clib_bitmap_t *cti = sm->consumer_thread_indices;
      u32 n_pros_per_cons =
	clib_bitmap_count_set_bits (pti) / clib_bitmap_count_set_bits (cti);
      u32 i, j, k = 0, self = ptd - gsm->per_thread_data;

      j = clib_bitmap_first_set (cti);

      vec_reset_length (ptd->consumer_queues);

      clib_bitmap_foreach (i, pti)
	{
	  if (j == self)
	    vec_add1 (ptd->consumer_queues, &gsm->per_thread_data[i].queue);

	  k++;
	  if (k == n_pros_per_cons)
	    {
	      k = 0;
	      j = clib_bitmap_next_set (cti, j + 1);
	    }
	}

      state_flags &= ~VNET_SCHEDULER_THREAD_STATE_CONSUMER_ENABLE;
    }

  if (state_flags & VNET_SCHEDULER_THREAD_STATE_CONSUMER_DISABLE)
    {
      /* clear the consumer role, trust the change role handler has done
       * excessive check. */
      state_flags &= ~VNET_SCHEDULER_THREAD_STATE_CONSUMER_DISABLE;
    }

  return state_flags;
}

static int
gen_scheduler_change_role (vlib_main_t *vm,
			   clib_bitmap_t *producer_thread_indices,
			   clib_bitmap_t *worker_thread_indices,
			   clib_bitmap_t *consumer_thread_indices)
{
  return 0;
}

clib_error_t *
gen_sw_scheduler_init (vlib_main_t *vm)
{
  gen_sw_scheduler_main_t *gsm = &gen_scheduler_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 ei;

  vec_validate_aligned (gsm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  ei = vnet_scheduler_register_engine (
    vm, "gen-sw-sched", "generic software scheduler engine", 80,
    enqueue_as_producer, enqueue_as_worker, dequeue_as_worker,
    dequeue_as_consumer, set_thread_state, gen_scheduler_change_role);
  gsm->scheduler_engine_index = ei;

  return 0;
}

VLIB_INIT_FUNCTION (gen_sw_scheduler_init) = {
  .runs_after = VLIB_INITS ("vnet_scheduler_init"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Generic SW Scheduler Engine plugin",
};

static clib_error_t *
show_gen_scheduler_depth_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  gen_sw_scheduler_main_t *gsm = &gen_scheduler_main;
  vnet_scheduler_main_t *sm = &scheduler_main;
  u32 i;

  if (unformat_user (input, unformat_line_input, line_input))
    unformat_free (line_input);

  clib_bitmap_foreach (i, sm->producer_thread_indices)
    {
      gen_sw_scheduler_per_thread_data_t *ptd = gsm->per_thread_data + i;
      u32 used = ptd->queue.head - ptd->queue.tail;

      vlib_cli_output (vm,
		       "Thread %02u: %02u of %02u queue entry free "
		       "(%.02f%% full)",
		       i, GEN_SW_SCHED_QUEUE_SIZE - used,
		       GEN_SW_SCHED_QUEUE_SIZE,
		       ((float) used / GEN_SW_SCHED_QUEUE_SIZE) * 100);
    }
  return 0;
}

VLIB_CLI_COMMAND (show_scheduler_engines_command, static) = {
  .path = "show gen scheduler engine depth",
  .short_help = "show gen scheduler engine queue depth information",
  .function = show_gen_scheduler_depth_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
