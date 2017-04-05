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
_(TIMER, "Timer events")

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

always_inline int
session_tx_fifo_read_and_snd_i (vlib_main_t * vm, vlib_node_runtime_t * node,
				session_manager_main_t * smm,
				session_fifo_event_t * e0,
				stream_session_t * s0, u32 thread_index,
				int *n_tx_packets, u8 peek_data)
{
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 left_to_snd0, max_len_to_snd0, len_to_deq0, n_bufs, snd_space0;
  u32 n_frame_bytes, n_frames_per_evt;
  transport_connection_t *tc0;
  transport_proto_vft_t *transport_vft;
  u32 next_index, next0, *to_next, n_left_to_next, bi0;
  vlib_buffer_t *b0;
  u32 rx_offset = 0, max_dequeue0;
  u16 snd_mss0;
  u8 *data0;
  int i, n_bytes_read;

  next_index = next0 = session_type_to_next[s0->session_type];

  transport_vft = session_get_transport_vft (s0->session_type);
  tc0 = transport_vft->get_connection (s0->connection_index, thread_index);

  /* Make sure we have space to send and there's something to dequeue */
  snd_space0 = transport_vft->send_space (tc0);
  snd_mss0 = transport_vft->send_mss (tc0);

  /* Can't make any progress */
  if (snd_space0 == 0 || snd_mss0 == 0)
    {
      vec_add1 (smm->evts_partially_read[thread_index], *e0);
      return 0;
    }

  if (peek_data)
    {
      /* Offset in rx fifo from where to peek data  */
      rx_offset = transport_vft->tx_fifo_offset (tc0);
    }

  /* Check how much we can pull. If buffering, subtract the offset */
  max_dequeue0 = svm_fifo_max_dequeue (s0->server_tx_fifo) - rx_offset;

  /* Allow enqueuing of a new event */
  svm_fifo_unset_event (s0->server_tx_fifo);

  /* Nothing to read return */
  if (max_dequeue0 == 0)
    return 0;

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
      max_len_to_snd0 = snd_space0;
    }

  n_frame_bytes = snd_mss0 * VLIB_FRAME_SIZE;
  n_frames_per_evt = ceil ((double) max_len_to_snd0 / n_frame_bytes);

  n_bufs = vec_len (smm->tx_buffers[thread_index]);
  left_to_snd0 = max_len_to_snd0;
  for (i = 0; i < n_frames_per_evt; i++)
    {
      /* Make sure we have at least one full frame of buffers ready */
      if (PREDICT_FALSE (n_bufs < VLIB_FRAME_SIZE))
	{
	  vec_validate (smm->tx_buffers[thread_index],
			n_bufs + VLIB_FRAME_SIZE - 1);
	  n_bufs +=
	    vlib_buffer_alloc (vm, &smm->tx_buffers[thread_index][n_bufs],
			       VLIB_FRAME_SIZE);

	  /* buffer shortage
	   * XXX 0.9 because when debugging we might not get a full frame */
	  if (PREDICT_FALSE (n_bufs < 0.9 * VLIB_FRAME_SIZE))
	    {
	      if (svm_fifo_set_event (s0->server_tx_fifo))
		{
		  vec_add1 (smm->evts_partially_read[thread_index], *e0);
		}
	      return -1;
	    }

	  _vec_len (smm->tx_buffers[thread_index]) = n_bufs;
	}

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (left_to_snd0 && n_left_to_next)
	{
	  /* Get free buffer */
	  n_bufs--;
	  bi0 = smm->tx_buffers[thread_index][n_bufs];
	  _vec_len (smm->tx_buffers[thread_index]) = n_bufs;

	  b0 = vlib_get_buffer (vm, bi0);
	  b0->error = 0;
	  b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID
	    | VNET_BUFFER_LOCALLY_ORIGINATED;
	  b0->current_data = 0;

	  /* RX on the local interface. tx in default fib */
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  /* usual speculation, or the enqueue_x1 macro will barf */
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
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

	  len_to_deq0 = (left_to_snd0 < snd_mss0) ? left_to_snd0 : snd_mss0;

	  /* *INDENT-OFF* */
	  SESSION_EVT_DBG(SESSION_EVT_DEQ, s0, ({
	      ed->data[0] = e0->event_id;
	      ed->data[1] = max_dequeue0;
	      ed->data[2] = len_to_deq0;
	      ed->data[3] = left_to_snd0;
	  }));
	  /* *INDENT-ON* */

	  /* Make room for headers */
	  data0 = vlib_buffer_make_headroom (b0, MAX_HDRS_LEN);

	  /* Dequeue the data
	   * TODO 1) peek instead of dequeue
	   *      2) buffer chains */
	  if (peek_data)
	    {
	      n_bytes_read = svm_fifo_peek (s0->server_tx_fifo, s0->pid,
					    rx_offset, len_to_deq0, data0);
	      if (n_bytes_read <= 0)
		goto dequeue_fail;

	      /* Keep track of progress locally, transport is also supposed to
	       * increment it independently when pushing the header */
	      rx_offset += n_bytes_read;
	    }
	  else
	    {
	      n_bytes_read = svm_fifo_dequeue_nowait (s0->server_tx_fifo,
						      s0->pid, len_to_deq0,
						      data0);
	      if (n_bytes_read <= 0)
		goto dequeue_fail;
	    }

	  b0->current_length = n_bytes_read;

	  /* Ask transport to push header */
	  transport_vft->push_header (tc0, b0);

	  left_to_snd0 -= n_bytes_read;
	  *n_tx_packets = *n_tx_packets + 1;

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
	  vec_add1 (smm->evts_partially_read[thread_index], *e0);
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
      vec_add1 (smm->evts_partially_read[thread_index], *e0);
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

static uword
session_queue_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  session_fifo_event_t *my_fifo_events, *e;
  u32 n_to_dequeue, n_events;
  unix_shared_memory_queue_t *q;
  application_t *app;
  int n_tx_packets = 0;
  u32 my_thread_index = vm->thread_index;
  int i, rv;
  f64 now = vlib_time_now (vm);

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

  /* min number of events we can dequeue without blocking */
  n_to_dequeue = q->cursize;
  my_fifo_events = smm->fifo_events[my_thread_index];

  if (n_to_dequeue == 0 && vec_len (my_fifo_events) == 0)
    return 0;

  SESSION_EVT_DBG (SESSION_EVT_DEQ_NODE, 0);

  /*
   * If we didn't manage to process previous events try going
   * over them again without dequeuing new ones.
   */
  /* XXX: Block senders to sessions that can't keep up */
  if (vec_len (my_fifo_events) >= 100)
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

  smm->fifo_events[my_thread_index] = my_fifo_events;

skip_dequeue:
  n_events = vec_len (my_fifo_events);
  for (i = 0; i < n_events; i++)
    {
      svm_fifo_t *f0;		/* $$$ prefetch 1 ahead maybe */
      stream_session_t *s0;
      u32 session_index0;
      session_fifo_event_t *e0;

      e0 = &my_fifo_events[i];
      f0 = e0->fifo;
      session_index0 = f0->server_session_index;

      /* $$$ add multiple event queues, per vpp worker thread */
      ASSERT (f0->server_thread_index == my_thread_index);

      s0 = stream_session_get_if_valid (session_index0, my_thread_index);

      if (CLIB_DEBUG && !s0)
	{
	  clib_warning ("It's dead, Jim!");
	  continue;
	}

      if (PREDICT_FALSE (s0->session_state == SESSION_STATE_CLOSED))
	continue;

      ASSERT (s0->thread_index == my_thread_index);

      switch (e0->event_type)
	{
	case FIFO_EVENT_SERVER_TX:
	  /* Spray packets in per session type frames, since they go to
	   * different nodes */
	  rv = (smm->session_tx_fns[s0->session_type]) (vm, node, smm, e0, s0,
							my_thread_index,
							&n_tx_packets);
	  /* Out of buffers */
	  if (rv < 0)
	    goto done;

	  break;
	case FIFO_EVENT_SERVER_EXIT:
	  stream_session_disconnect (s0);
	  break;
	case FIFO_EVENT_BUILTIN_RX:
	  svm_fifo_unset_event (s0->server_rx_fifo);
	  /* Get session's server */
	  app = application_get (s0->app_index);
	  app->cb_fns.builtin_server_rx_callback (s0);
	  break;
	default:
	  clib_warning ("unhandled event type %d", e0->event_type);
	}
    }

done:

  /* Couldn't process all events. Probably out of buffers */
  if (PREDICT_FALSE (i < n_events))
    {
      session_fifo_event_t *partially_read =
	smm->evts_partially_read[my_thread_index];
      vec_add (partially_read, &my_fifo_events[i], n_events - i);
      vec_free (my_fifo_events);
      smm->fifo_events[my_thread_index] = partially_read;
      smm->evts_partially_read[my_thread_index] = 0;
    }
  else
    {
      vec_free (smm->fifo_events[my_thread_index]);
      smm->fifo_events[my_thread_index] =
	smm->evts_partially_read[my_thread_index];
      smm->evts_partially_read[my_thread_index] = 0;
    }

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
