/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <math.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/tcp/tcp.h>
#include <vppinfra/elog.h>
#include <vnet/session/application.h>
#include <vnet/session/session_debug.h>
#include <vlibmemory/unix_shared_memory_queue.h>

vlib_node_registration_t session_queue_node;

typedef struct
{
  u32 session_index;
  u32 server_thread_index;
} session_queue_trace_t;

/* packet trace format function */
static u8 *
format_session_queue_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  session_queue_trace_t *t = va_arg (*args, session_queue_trace_t *);

  s = format (s, "SESSION_QUEUE: session index %d, server thread index %d",
	      t->session_index, t->server_thread_index);
  return s;
}

vlib_node_registration_t session_queue_node;

#define foreach_session_queue_error		\
_(TX, "Packets transmitted")                  	\
_(TIMER, "Timer events")			\
_(NO_BUFFER, "Out of buffers")

typedef enum
{
#define _(sym,str) SESSION_QUEUE_ERROR_##sym,
  foreach_session_queue_error
#undef _
    SESSION_QUEUE_N_ERROR,
} session_queue_error_t;

static char *session_queue_error_strings[] = {
#define _(sym,string) string,
  foreach_session_queue_error
#undef _
};

static u32 session_type_to_next[] = {
  SESSION_QUEUE_NEXT_TCP_IP4_OUTPUT,
  SESSION_QUEUE_NEXT_IP4_LOOKUP,
  SESSION_QUEUE_NEXT_TCP_IP6_OUTPUT,
  SESSION_QUEUE_NEXT_IP6_LOOKUP,
};

always_inline void
session_tx_fifo_chain_tail (session_manager_main_t * smm, vlib_main_t * vm,
			    u8 thread_index, svm_fifo_t * fifo,
			    vlib_buffer_t * b0, u32 bi0, u8 n_bufs_per_seg,
			    u32 left_from_seg, u32 * left_to_snd0,
			    u16 * n_bufs, u32 * tx_offset, u16 deq_per_buf,
			    u8 peek_data)
{
  vlib_buffer_t *chain_b0, *prev_b0;
  u32 chain_bi0, to_deq;
  u16 len_to_deq0, n_bytes_read;
  u8 *data0, j;

  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  b0->total_length_not_including_first_buffer = 0;

  chain_bi0 = bi0;
  chain_b0 = b0;
  to_deq = left_from_seg;
  for (j = 1; j < n_bufs_per_seg; j++)
    {
      prev_b0 = chain_b0;
      len_to_deq0 = clib_min (to_deq, deq_per_buf);

      *n_bufs -= 1;
      chain_bi0 = smm->tx_buffers[thread_index][*n_bufs];
      _vec_len (smm->tx_buffers[thread_index]) = *n_bufs;

      chain_b0 = vlib_get_buffer (vm, chain_bi0);
      chain_b0->current_data = 0;
      data0 = vlib_buffer_get_current (chain_b0);
      if (peek_data)
	{
	  n_bytes_read = svm_fifo_peek (fifo, *tx_offset, len_to_deq0, data0);
	  *tx_offset += n_bytes_read;
	}
      else
	{
	  n_bytes_read = svm_fifo_dequeue_nowait (fifo, len_to_deq0, data0);
	}
      ASSERT (n_bytes_read == len_to_deq0);
      chain_b0->current_length = n_bytes_read;
      b0->total_length_not_including_first_buffer += chain_b0->current_length;

      /* update previous buffer */
      prev_b0->next_buffer = chain_bi0;
      prev_b0->flags |= VLIB_BUFFER_NEXT_PRESENT;

      /* update current buffer */
      chain_b0->next_buffer = 0;

      to_deq -= n_bytes_read;
      if (to_deq == 0)
	break;
    }
  ASSERT (to_deq == 0
	  && b0->total_length_not_including_first_buffer == left_from_seg);
  *left_to_snd0 -= left_from_seg;
}

always_inline int
session_tx_fifo_read_and_snd_i (vlib_main_t * vm, vlib_node_runtime_t * node,
				session_manager_main_t * smm,
				session_fifo_event_t * e0,
				stream_session_t * s0, u32 thread_index,
				int *n_tx_packets, u8 peek_data)
{
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 left_to_snd0, max_len_to_snd0, len_to_deq0, snd_space0;
  u32 n_bufs_per_evt, n_frames_per_evt, n_bufs_per_frame;
  transport_connection_t *tc0;
  transport_proto_vft_t *transport_vft;
  u32 next_index, next0, *to_next, n_left_to_next, bi0;
  vlib_buffer_t *b0;
  u32 tx_offset = 0, max_dequeue0, n_bytes_per_seg, left_for_seg;
  u16 snd_mss0, n_bufs_per_seg, n_bufs;
  u8 *data0;
  int i, n_bytes_read;
  u32 n_bytes_per_buf, deq_per_buf, deq_per_first_buf;
  u32 buffers_allocated, buffers_allocated_this_call;

  next_index = next0 = session_type_to_next[s0->session_type];

  transport_vft = session_get_transport_vft (s0->session_type);
  tc0 = transport_vft->get_connection (s0->connection_index, thread_index);

  /* Make sure we have space to send and there's something to dequeue */
  snd_mss0 = transport_vft->send_mss (tc0);
  snd_space0 = transport_vft->send_space (tc0);

  /* Can't make any progress */
  if (snd_space0 == 0 || snd_mss0 == 0)
    {
      vec_add1 (smm->pending_event_vector[thread_index], *e0);
      return 0;
    }

  /* Check how much we can pull. */
  max_dequeue0 = svm_fifo_max_dequeue (s0->server_tx_fifo);

  if (peek_data)
    {
      /* Offset in rx fifo from where to peek data */
      tx_offset = transport_vft->tx_fifo_offset (tc0);
      if (PREDICT_FALSE (tx_offset >= max_dequeue0))
	max_dequeue0 = 0;
      else
	max_dequeue0 -= tx_offset;
    }

  /* Nothing to read return */
  if (max_dequeue0 == 0)
    {
      svm_fifo_unset_event (s0->server_tx_fifo);
      return 0;
    }

  /* Ensure we're not writing more than transport window allows */
  if (max_dequeue0 < snd_space0)
    {
      /* Constrained by tx queue. Try to send only fully formed segments */
      max_len_to_snd0 = (max_dequeue0 > snd_mss0) ?
	max_dequeue0 - max_dequeue0 % snd_mss0 : max_dequeue0;
      /* TODO Nagle ? */
    }
  else
    {
      /* Expectation is that snd_space0 is already a multiple of snd_mss */
      max_len_to_snd0 = snd_space0;
    }

  n_bytes_per_buf = vlib_buffer_free_list_buffer_size
    (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
  ASSERT (n_bytes_per_buf > MAX_HDRS_LEN);
  n_bytes_per_seg = MAX_HDRS_LEN + snd_mss0;
  n_bufs_per_seg = ceil ((double) n_bytes_per_seg / n_bytes_per_buf);
  n_bufs_per_evt = ceil ((double) max_len_to_snd0 / n_bytes_per_seg);
  n_frames_per_evt = ceil ((double) n_bufs_per_evt / VLIB_FRAME_SIZE);
  n_bufs_per_frame = n_bufs_per_seg * VLIB_FRAME_SIZE;

  deq_per_buf = clib_min (snd_mss0, n_bytes_per_buf);
  deq_per_first_buf = clib_min (snd_mss0, n_bytes_per_buf - MAX_HDRS_LEN);

  n_bufs = vec_len (smm->tx_buffers[thread_index]);
  left_to_snd0 = max_len_to_snd0;
  for (i = 0; i < n_frames_per_evt; i++)
    {
      /* Make sure we have at least one full frame of buffers ready */
      if (PREDICT_FALSE (n_bufs < n_bufs_per_frame))
	{
	  vec_validate (smm->tx_buffers[thread_index],
			n_bufs + n_bufs_per_frame - 1);
	  buffers_allocated = 0;
	  do
	    {
	      buffers_allocated_this_call = vlib_buffer_alloc (vm,
							       &smm->tx_buffers
							       [thread_index]
							       [n_bufs +
								buffers_allocated],
							       n_bufs_per_frame
							       -
							       buffers_allocated);
	      buffers_allocated += buffers_allocated_this_call;
	    }
	  while (buffers_allocated_this_call > 0
		 && ((buffers_allocated + n_bufs < n_bufs_per_frame)));

	  n_bufs += buffers_allocated;
	  _vec_len (smm->tx_buffers[thread_index]) = n_bufs;

	  if (PREDICT_FALSE (n_bufs < n_bufs_per_frame))
	    {
	      vec_add1 (smm->pending_event_vector[thread_index], *e0);
	      return -1;
	    }
	  ASSERT (n_bufs >= n_bufs_per_frame);
	}
      /* Allow enqueuing of a new event */
      svm_fifo_unset_event (s0->server_tx_fifo);

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (left_to_snd0 && n_left_to_next)
	{
	  /*
	   * Handle first buffer in chain separately
	   */

	  /* Get free buffer */
	  ASSERT (n_bufs >= 1);
	  bi0 = smm->tx_buffers[thread_index][--n_bufs];
	  _vec_len (smm->tx_buffers[thread_index]) = n_bufs;

	  /* usual speculation, or the enqueue_x1 macro will barf */
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  b0->error = 0;
	  b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  b0->current_data = 0;
	  b0->total_length_not_including_first_buffer = 0;

	  len_to_deq0 = clib_min (left_to_snd0, deq_per_first_buf);
	  data0 = vlib_buffer_make_headroom (b0, MAX_HDRS_LEN);
	  if (peek_data)
	    {
	      n_bytes_read = svm_fifo_peek (s0->server_tx_fifo, tx_offset,
					    len_to_deq0, data0);
	      if (n_bytes_read <= 0)
		goto dequeue_fail;
	      /* Keep track of progress locally, transport is also supposed to
	       * increment it independently when pushing the header */
	      tx_offset += n_bytes_read;
	    }
	  else
	    {
	      n_bytes_read = svm_fifo_dequeue_nowait (s0->server_tx_fifo,
						      len_to_deq0, data0);
	      if (n_bytes_read <= 0)
		goto dequeue_fail;
	    }

	  b0->current_length = n_bytes_read;

	  left_to_snd0 -= n_bytes_read;
	  *n_tx_packets = *n_tx_packets + 1;

	  /*
	   * Fill in the remaining buffers in the chain, if any
	   */
	  if (PREDICT_FALSE (n_bufs_per_seg > 1 && left_to_snd0))
	    {
	      left_for_seg = clib_min (snd_mss0 - n_bytes_read, left_to_snd0);
	      session_tx_fifo_chain_tail (smm, vm, thread_index,
					  s0->server_tx_fifo, b0, bi0,
					  n_bufs_per_seg, left_for_seg,
					  &left_to_snd0, &n_bufs, &tx_offset,
					  deq_per_buf, peek_data);
	    }

	  /* Ask transport to push header after current_length and
	   * total_length_not_including_first_buffer are updated */
	  transport_vft->push_header (tc0, b0);

	  /* *INDENT-OFF* */
	  SESSION_EVT_DBG(SESSION_EVT_DEQ, s0, ({
	      ed->data[0] = e0->event_id;
	      ed->data[1] = max_dequeue0;
	      ed->data[2] = len_to_deq0;
	      ed->data[3] = left_to_snd0;
	  }));
	  /* *INDENT-ON* */

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
	  if (VLIB_BUFFER_TRACE_TRAJECTORY)
	    b0->pre_data[1] = 3;

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      session_queue_trace_t *t0;
	      vlib_trace_buffer (vm, node, next_index, b0,
				 1 /* follow_chain */ );
	      vlib_set_trace_count (vm, node, --n_trace);
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      t0->session_index = s0->session_index;
	      t0->server_thread_index = s0->thread_index;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* If we couldn't dequeue all bytes mark as partially read */
  if (max_len_to_snd0 < max_dequeue0)
    {
      /* If we don't already have new event */
      if (svm_fifo_set_event (s0->server_tx_fifo))
	{
	  vec_add1 (smm->pending_event_vector[thread_index], *e0);
	}
    }
  return 0;

dequeue_fail:
  /*
   * Can't read from fifo. If we don't already have an event, save as partially
   * read, return buff to free list and return
   */
  clib_warning ("dequeue fail");

  if (svm_fifo_set_event (s0->server_tx_fifo))
    {
      vec_add1 (smm->pending_event_vector[thread_index], *e0);
    }
  vlib_put_next_frame (vm, node, next_index, n_left_to_next + 1);
  _vec_len (smm->tx_buffers[thread_index]) += 1;

  return 0;
}

int
session_tx_fifo_peek_and_snd (vlib_main_t * vm, vlib_node_runtime_t * node,
			      session_manager_main_t * smm,
			      session_fifo_event_t * e0,
			      stream_session_t * s0, u32 thread_index,
			      int *n_tx_pkts)
{
  return session_tx_fifo_read_and_snd_i (vm, node, smm, e0, s0, thread_index,
					 n_tx_pkts, 1);
}

int
session_tx_fifo_dequeue_and_snd (vlib_main_t * vm, vlib_node_runtime_t * node,
				 session_manager_main_t * smm,
				 session_fifo_event_t * e0,
				 stream_session_t * s0, u32 thread_index,
				 int *n_tx_pkts)
{
  return session_tx_fifo_read_and_snd_i (vm, node, smm, e0, s0, thread_index,
					 n_tx_pkts, 0);
}

always_inline stream_session_t *
session_event_get_session (session_fifo_event_t * e, u8 thread_index)
{
  return stream_session_get_if_valid (e->fifo->master_session_index,
				      thread_index);
}

void
dump_thread_0_event_queue (void)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  vlib_main_t *vm = &vlib_global_main;
  u32 my_thread_index = vm->thread_index;
  session_fifo_event_t _e, *e = &_e;
  stream_session_t *s0;
  int i, index;
  i8 *headp;

  unix_shared_memory_queue_t *q;
  q = smm->vpp_event_queues[my_thread_index];

  index = q->head;

  for (i = 0; i < q->cursize; i++)
    {
      headp = (i8 *) (&q->data[0] + q->elsize * index);
      clib_memcpy (e, headp, q->elsize);

      switch (e->event_type)
	{
	case FIFO_EVENT_APP_TX:
	  s0 = session_event_get_session (e, my_thread_index);
	  fformat (stdout, "[%04d] TX session %d\n", i, s0->session_index);
	  break;

	case FIFO_EVENT_DISCONNECT:
	  s0 = stream_session_get_from_handle (e->session_handle);
	  fformat (stdout, "[%04d] disconnect session %d\n", i,
		   s0->session_index);
	  break;

	case FIFO_EVENT_BUILTIN_RX:
	  s0 = session_event_get_session (e, my_thread_index);
	  fformat (stdout, "[%04d] builtin_rx %d\n", i, s0->session_index);
	  break;

	case FIFO_EVENT_RPC:
	  fformat (stdout, "[%04d] RPC call %llx with %llx\n",
		   i, (u64) (e->rpc_args.fp), (u64) (e->rpc_args.arg));
	  break;

	default:
	  fformat (stdout, "[%04d] unhandled event type %d\n",
		   i, e->event_type);
	  break;
	}

      index++;

      if (index == q->maxsize)
	index = 0;
    }
}

static u8
session_node_cmp_event (session_fifo_event_t * e, svm_fifo_t * f)
{
  stream_session_t *s;
  switch (e->event_type)
    {
    case FIFO_EVENT_APP_RX:
    case FIFO_EVENT_APP_TX:
    case FIFO_EVENT_BUILTIN_RX:
      if (e->fifo == f)
	return 1;
      break;
    case FIFO_EVENT_DISCONNECT:
      break;
    case FIFO_EVENT_RPC:
      s = stream_session_get_from_handle (e->session_handle);
      if (!s)
	{
	  clib_warning ("session has event but doesn't exist!");
	  break;
	}
      if (s->server_rx_fifo == f || s->server_tx_fifo == f)
	return 1;
      break;
    default:
      break;
    }
  return 0;
}

u8
session_node_lookup_fifo_event (svm_fifo_t * f, session_fifo_event_t * e)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  unix_shared_memory_queue_t *q;
  session_fifo_event_t *pending_event_vector, *evt;
  int i, index, found = 0;
  i8 *headp;
  u8 thread_index;

  ASSERT (e);
  thread_index = f->master_thread_index;
  /*
   * Search evt queue
   */
  q = smm->vpp_event_queues[thread_index];
  index = q->head;
  for (i = 0; i < q->cursize; i++)
    {
      headp = (i8 *) (&q->data[0] + q->elsize * index);
      clib_memcpy (e, headp, q->elsize);
      found = session_node_cmp_event (e, f);
      if (found)
	break;
      if (++index == q->maxsize)
	index = 0;
    }
  /*
   * Search pending events vector
   */
  pending_event_vector = smm->pending_event_vector[thread_index];
  vec_foreach (evt, pending_event_vector)
  {
    found = session_node_cmp_event (evt, f);
    if (found)
      {
	clib_memcpy (e, evt, sizeof (*evt));
	break;
      }
  }
  return found;
}

static uword
session_queue_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  session_fifo_event_t *my_pending_event_vector, *e;
  session_fifo_event_t *my_fifo_events;
  u32 n_to_dequeue, n_events;
  unix_shared_memory_queue_t *q;
  application_t *app;
  int n_tx_packets = 0;
  u32 my_thread_index = vm->thread_index;
  int i, rv;
  f64 now = vlib_time_now (vm);
  void (*fp) (void *);

  SESSION_EVT_DBG (SESSION_EVT_POLL_GAP_TRACK, smm, my_thread_index);

  /*
   *  Update TCP time
   */
  tcp_update_time (now, my_thread_index);

  /*
   * Get vpp queue events
   */
  q = smm->vpp_event_queues[my_thread_index];
  if (PREDICT_FALSE (q == 0))
    return 0;

  my_fifo_events = smm->free_event_vector[my_thread_index];

  /* min number of events we can dequeue without blocking */
  n_to_dequeue = q->cursize;
  my_pending_event_vector = smm->pending_event_vector[my_thread_index];

  if (n_to_dequeue == 0 && vec_len (my_pending_event_vector) == 0)
    return 0;

  SESSION_EVT_DBG (SESSION_EVT_DEQ_NODE, 0);

  /*
   * If we didn't manage to process previous events try going
   * over them again without dequeuing new ones.
   */
  /* XXX: Block senders to sessions that can't keep up */
  if (0 && vec_len (my_pending_event_vector) >= 100)
    {
      clib_warning ("too many fifo events unsolved");
      goto skip_dequeue;
    }

  /* See you in the next life, don't be late */
  if (pthread_mutex_trylock (&q->mutex))
    return 0;

  for (i = 0; i < n_to_dequeue; i++)
    {
      vec_add2 (my_fifo_events, e, 1);
      unix_shared_memory_queue_sub_raw (q, (u8 *) e);
    }

  /* The other side of the connection is not polling */
  if (q->cursize < (q->maxsize / 8))
    (void) pthread_cond_broadcast (&q->condvar);
  pthread_mutex_unlock (&q->mutex);

  vec_append (my_fifo_events, my_pending_event_vector);

  _vec_len (my_pending_event_vector) = 0;
  smm->pending_event_vector[my_thread_index] = my_pending_event_vector;

skip_dequeue:
  n_events = vec_len (my_fifo_events);
  for (i = 0; i < n_events; i++)
    {
      stream_session_t *s0;	/* $$$ prefetch 1 ahead maybe */
      session_fifo_event_t *e0;

      e0 = &my_fifo_events[i];

      switch (e0->event_type)
	{
	case FIFO_EVENT_APP_TX:
	  s0 = session_event_get_session (e0, my_thread_index);

	  if (PREDICT_FALSE (!s0))
	    {
	      clib_warning ("It's dead, Jim!");
	      continue;
	    }
	  /* Can retransmit for closed sessions but can't do anything if
	   * session is not ready or closed */
	  if (PREDICT_FALSE (s0->session_state < SESSION_STATE_READY))
	    continue;
	  /* Spray packets in per session type frames, since they go to
	   * different nodes */
	  rv = (smm->session_tx_fns[s0->session_type]) (vm, node, smm, e0, s0,
							my_thread_index,
							&n_tx_packets);
	  /* Out of buffers */
	  if (PREDICT_FALSE (rv < 0))
	    {
	      vlib_node_increment_counter (vm, node->node_index,
					   SESSION_QUEUE_ERROR_NO_BUFFER, 1);
	      continue;
	    }
	  break;
	case FIFO_EVENT_DISCONNECT:
	  s0 = stream_session_get_from_handle (e0->session_handle);
	  stream_session_disconnect (s0);
	  break;
	case FIFO_EVENT_BUILTIN_RX:
	  s0 = session_event_get_session (e0, my_thread_index);
	  if (PREDICT_FALSE (!s0))
	    continue;
	  svm_fifo_unset_event (s0->server_rx_fifo);
	  app = application_get (s0->app_index);
	  app->cb_fns.builtin_server_rx_callback (s0);
	  break;
	case FIFO_EVENT_RPC:
	  fp = e0->rpc_args.fp;
	  (*fp) (e0->rpc_args.arg);
	  break;

	default:
	  clib_warning ("unhandled event type %d", e0->event_type);
	}
    }

  _vec_len (my_fifo_events) = 0;
  smm->free_event_vector[my_thread_index] = my_fifo_events;

  vlib_node_increment_counter (vm, session_queue_node.index,
			       SESSION_QUEUE_ERROR_TX, n_tx_packets);

  SESSION_EVT_DBG (SESSION_EVT_DEQ_NODE, 1);

  return n_tx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (session_queue_node) =
{
  .function = session_queue_node_fn,
  .name = "session-queue",
  .format_trace = format_session_queue_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .n_errors = ARRAY_LEN (session_queue_error_strings),
  .error_strings = session_queue_error_strings,
  .n_next_nodes = SESSION_QUEUE_N_NEXT,
  .state = VLIB_NODE_STATE_DISABLED,
  .next_nodes =
  {
      [SESSION_QUEUE_NEXT_DROP] = "error-drop",
      [SESSION_QUEUE_NEXT_IP4_LOOKUP] = "ip4-lookup",
      [SESSION_QUEUE_NEXT_IP6_LOOKUP] = "ip6-lookup",
      [SESSION_QUEUE_NEXT_TCP_IP4_OUTPUT] = "tcp4-output",
      [SESSION_QUEUE_NEXT_TCP_IP6_OUTPUT] = "tcp6-output",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
