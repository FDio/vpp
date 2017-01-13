/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>

#include <vnet/uri/uri.h>
#include <vnet/tcp/tcp.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>
#include <vlibmemory/unix_shared_memory_queue.h>

#include <vnet/ip/udp_packet.h>
#include <vnet/lisp-cp/packets.h>

vlib_node_registration_t uri_queue_node;

typedef struct
{
  u32 session_index;
  u32 server_thread_index;
} uri_queue_trace_t;

/* packet trace format function */
static u8 *
format_uri_queue_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  uri_queue_trace_t *t = va_arg (*args, uri_queue_trace_t *);

  s = format (s, "URI_QUEUE: session index %d, server thread index %d",
	      t->session_index, t->server_thread_index);
  return s;
}

vlib_node_registration_t uri_queue_node;

#define foreach_uri_queue_error                 \
_(TX, "Packets transmitted")                    \
_(TIMER, "Timer events")

typedef enum
{
#define _(sym,str) URI_QUEUE_ERROR_##sym,
  foreach_uri_queue_error
#undef _
    URI_QUEUE_N_ERROR,
} uri_queue_error_t;

static char *uri_queue_error_strings[] = {
#define _(sym,string) string,
  foreach_uri_queue_error
#undef _
};

#define N_FREE_BUFFERS  32

#define get_free_buffer_index(ssm, bidx)                                \
do {                                                                    \
  if (PREDICT_FALSE(vec_len (my_tx_buffers) == 0))                      \
    {                                                                   \
      u32 n_free_buffers = N_FREE_BUFFERS;                              \
      vec_validate (my_tx_buffers, n_free_buffers - 1);                 \
      _vec_len(my_tx_buffers) = vlib_buffer_alloc_from_free_list (      \
          ssm->vlib_main, my_tx_buffers, n_free_buffers,                \
          VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);                         \
      /* buffer shortage */                                             \
      if (PREDICT_FALSE (vec_len (my_tx_buffers) == 0))                 \
        return 0;                                                       \
      ssm->tx_buffers[my_thread_index] = my_tx_buffers;                 \
    }                                                                   \
  *bidx = my_tx_buffers[_vec_len (my_tx_buffers)-1];                    \
  _vec_len (my_tx_buffers) -= 1;                                        \
} while (0)

static uword
uri_queue_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * frame)
{
  stream_server_main_t *ssm = &stream_server_main;
  u32 n_left_to_next, *to_next;
  u32 next_index;
  u32 *my_tx_buffers = 0;
  fifo_event_t *my_fifo_events, *e;
  u32 n_to_dequeue;
  unix_shared_memory_queue_t *q;
  int n_tx_packets = 0;
  u32 my_thread_index = vm->cpu_index;
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 next0;
  int i;

  /* Update TCP time */
  tcp_update_time (vlib_time_now (vm));

  q = ssm->vpp_event_queues[my_thread_index];
  if (PREDICT_FALSE (q == 0))
    return 0;

  /* min number of events we can dequeue without blocking */
  n_to_dequeue = q->cursize;
  if (n_to_dequeue == 0)
    return 0;

  my_fifo_events = ssm->fifo_events[my_thread_index];

  /* See you in the next life, don't be late */
  if (pthread_mutex_trylock (&q->mutex))
    return 0;

  vec_reset_length (my_fifo_events);
  for (i = 0; i < n_to_dequeue; i++)
    {
      vec_add2 (my_fifo_events, e, 1);
      unix_shared_memory_queue_sub_raw (q, (u8 *) e);
    }

  /* The other side of the connection is not polling */
  if (q->cursize < (q->maxsize / 8))
    (void) pthread_cond_broadcast (&q->condvar);
  pthread_mutex_unlock (&q->mutex);

  ssm->fifo_events[my_thread_index] = my_fifo_events;

  next_index = node->cached_next_index;
  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

  for (i = 0; i < n_to_dequeue; i++)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      svm_fifo_t *f0;		/* $$$ prefetch 1 ahead maybe */
      stream_session_t *s0;
      u32 server_session_index0, server_thread_index0;
      fifo_event_t *e0;
      transport_connection_t *tc0;
      transport_proto_vft_t *transport_vft;
      u32 len_to_snd0, len_to_deq0, max_dequeue0;
      u16 snd_mss0;
      u8 *data0;

      e0 = &my_fifo_events[i];
      f0 = e0->fifo;
      server_session_index0 = f0->server_session_index;
      server_thread_index0 = f0->server_thread_index;

      /* $$$ add multiple event queues, per vpp worker thread */
      ASSERT (server_thread_index0 == my_thread_index);

      s0 = pool_elt_at_index (ssm->sessions[f0->server_thread_index],
			      server_session_index0);

      ASSERT (s0->session_thread_index == my_thread_index);

      transport_vft = uri_get_transport (s0->session_type);
      tc0 = transport_vft->get_connection (s0->connection_index,
					   s0->session_thread_index);

      /* Make sure there's something to dequeue */
      max_dequeue0 = svm_fifo_max_dequeue (s0->server_tx_fifo);
      if (max_dequeue0 == 0)
	continue;

      /* TODO decide how much to read  */
      len_to_snd0 = e->enqueue_length;	/* max_dequeue0 */

      /* Get the maximum segment size for this transport */
      snd_mss0 = transport_vft->send_mss (tc0);

      /* TODO check if transport is willing to send len_to_snd0 bytes (Nagle) */

      switch (e0->event_type)
	{
	case FIFO_EVENT_SERVER_TX:

	  while (len_to_snd0)
	    {
	      /* Get buffer. Allocate if needed */
	      get_free_buffer_index (ssm, &bi0);
	      b0 = vlib_get_buffer (vm, bi0);
	      b0->error = 0;
	      b0->flags = VNET_BUFFER_LOCALLY_ORIGINATED;

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
		  uri_queue_trace_t *t0;
		  vlib_trace_buffer (vm, node, next_index, b0,
				     1 /* follow_chain */ );
		  n_trace--;
		  t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
		  t0->session_index = s0->session_index;
		  t0->server_thread_index = s0->session_thread_index;
		}

	      if (1)
		{
		  ELOG_TYPE_DECLARE (e) =
		  {
		  .format = "evt-dequeue: id %d length %d",.format_args =
		      "i4i4",};
		  struct
		  {
		    u32 data[2];
		  } *ed;
		  ed = ELOG_DATA (&vm->elog_main, e);
		  ed->data[0] = e0->event_id;
		  ed->data[1] = e0->enqueue_length;
		}

	      len_to_deq0 = (len_to_snd0 < snd_mss0) ? len_to_snd0 : snd_mss0;

	      /* Make room for headers */
	      data0 = vlib_buffer_make_headroom (b0, MAX_HDRS_LEN);

	      /* Dequeue the data TODO peek instead of dequeue */
	      if (svm_fifo_dequeue_nowait2
		  (s0->server_tx_fifo, 0, len_to_deq0, data0) <= 0)
		{
		  next0 = URI_QUEUE_NEXT_DROP;
		  goto done;
		}
	      b0->current_length = len_to_deq0;

	      /* Ask transport to push header */
	      next0 = transport_vft->push_header (tc0, b0);

	      len_to_snd0 -= len_to_deq0;
	      n_tx_packets++;

	    done:
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next,
					       bi0, next0);
	      if (n_left_to_next == 0)
		{
		  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
		  vlib_get_next_frame (vm, node, next_index, to_next,
				       n_left_to_next);
		}
	    }
	  break;

	default:
	  clib_warning ("unhandled event type %d", e0->event_type);
	}
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vlib_node_increment_counter (vm, uri_queue_node.index,
			       URI_QUEUE_ERROR_TX, n_tx_packets);

  return n_tx_packets;
}

VLIB_REGISTER_NODE (uri_queue_node) =
{
  .function = uri_queue_node_fn,.name = "uri-queue",.format_trace =
    format_uri_queue_trace,.type = VLIB_NODE_TYPE_INPUT,.n_errors =
    ARRAY_LEN (uri_queue_error_strings),.error_strings =
    uri_queue_error_strings,.n_next_nodes = URI_QUEUE_N_NEXT,
    /* .state = VLIB_NODE_STATE_DISABLED, enable on-demand? */
    /* edit / add dispositions here */
    .next_nodes =
  {
  [URI_QUEUE_NEXT_DROP] = "error-drop",
      [URI_QUEUE_NEXT_IP4_LOOKUP] = "ip4-lookup",
      [URI_QUEUE_NEXT_IP6_LOOKUP] = "ip6-lookup",
      [URI_QUEUE_NEXT_TCP_IP4_OUTPUT] = "tcp4-output",
      [URI_QUEUE_NEXT_TCP_IP6_OUTPUT] = "tcp6-output",}
,};

/* Uses stream_server_main_t, currently no init routine */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
