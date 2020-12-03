/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
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

#include <vlibmemory/api.h>
#include <vlib/vlib.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/session/session.h>

static char *udp_error_strings[] = {
#define udp_error(n,s) s,
#include "udp_error.def"
#undef udp_error
};

typedef struct
{
  u32 connection;
  u32 disposition;
  u32 thread_index;
} udp_input_trace_t;

/* packet trace format function */
static u8 *
format_udp_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  udp_input_trace_t *t = va_arg (*args, udp_input_trace_t *);

  s = format (s, "UDP_INPUT: connection %d, disposition %d, thread %d",
	      t->connection, t->disposition, t->thread_index);
  return s;
}

#define foreach_udp_input_next			\
  _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) UDP_INPUT_NEXT_##s,
  foreach_udp_input_next
#undef _
    UDP_INPUT_N_NEXT,
} udp_input_next_t;

always_inline void
udp_input_inc_counter (vlib_main_t * vm, u8 is_ip4, u8 evt, u8 val)
{
  if (is_ip4)
    vlib_node_increment_counter (vm, udp4_input_node.index, evt, val);
  else
    vlib_node_increment_counter (vm, udp6_input_node.index, evt, val);
}

#define udp_store_err_counters(vm, is_ip4, cnts)			\
{									\
  int i;								\
  for (i = 0; i < UDP_N_ERROR; i++)					\
    if (cnts[i])							\
      udp_input_inc_counter(vm, is_ip4, i, cnts[i]);			\
}

#define udp_inc_err_counter(cnts, err, val)				\
{									\
  cnts[err] += val;							\
}

static void
udp_trace_buffer (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_buffer_t * b, session_t * s, u16 error0)
{
  udp_input_trace_t *t;

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_IS_TRACED)))
    return;

  t = vlib_add_trace (vm, node, b, sizeof (*t));
  t->connection = s ? s->connection_index : ~0;
  t->disposition = error0;
  t->thread_index = s ? s->thread_index : vm->thread_index;
}

static udp_connection_t *
udp_connection_accept (udp_connection_t * listener, session_dgram_hdr_t * hdr,
		       u32 thread_index)
{
  udp_connection_t *uc;

  uc = udp_connection_alloc (thread_index);
  ip_copy (&uc->c_lcl_ip, &hdr->lcl_ip, hdr->is_ip4);
  ip_copy (&uc->c_rmt_ip, &hdr->rmt_ip, hdr->is_ip4);
  uc->c_lcl_port = hdr->lcl_port;
  uc->c_rmt_port = hdr->rmt_port;
  uc->c_is_ip4 = hdr->is_ip4;
  uc->c_fib_index = listener->c_fib_index;
  uc->mss = listener->mss;
  uc->flags |= UDP_CONN_F_CONNECTED;

  if (session_dgram_accept (&uc->connection, listener->c_s_index,
			    listener->c_thread_index))
    {
      udp_connection_free (uc);
      return 0;
    }
  udp_connection_share_port (clib_net_to_host_u16
			     (uc->c_lcl_port), uc->c_is_ip4);
  return uc;
}

static void
udp_connection_enqueue (udp_connection_t * uc0, session_t * s0,
			session_dgram_hdr_t * hdr0, u32 thread_index,
			vlib_buffer_t * b, u8 queue_event, u32 * error0)
{
  int wrote0;

  if (!(uc0->flags & UDP_CONN_F_CONNECTED))
    clib_spinlock_lock (&uc0->rx_lock);

  if (svm_fifo_max_enqueue_prod (s0->rx_fifo)
      < hdr0->data_length + sizeof (session_dgram_hdr_t))
    {
      *error0 = UDP_ERROR_FIFO_FULL;
      goto unlock_rx_lock;
    }

  /* If session is owned by another thread and rx event needed,
   * enqueue event now while we still have the peeker lock */
  if (s0->thread_index != thread_index)
    {
      wrote0 = session_enqueue_dgram_connection (s0, hdr0, b,
						 TRANSPORT_PROTO_UDP,
						 /* queue event */ 0);
      if (queue_event && !svm_fifo_has_event (s0->rx_fifo))
	session_enqueue_notify (s0);
    }
  else
    {
      wrote0 = session_enqueue_dgram_connection (s0, hdr0, b,
						 TRANSPORT_PROTO_UDP,
						 queue_event);
    }
  ASSERT (wrote0 > 0);

unlock_rx_lock:

  if (!(uc0->flags & UDP_CONN_F_CONNECTED))
    clib_spinlock_unlock (&uc0->rx_lock);
}

always_inline session_t *
udp_parse_and_lookup_buffer (vlib_buffer_t * b, session_dgram_hdr_t * hdr,
			     u8 is_ip4)
{
  udp_header_t *udp;
  u32 fib_index;
  session_t *s;

  /* udp_local hands us a pointer to the udp data */
  udp = (udp_header_t *) (vlib_buffer_get_current (b) - sizeof (*udp));
  fib_index = vnet_buffer (b)->ip.fib_index;

  hdr->data_offset = 0;
  hdr->lcl_port = udp->dst_port;
  hdr->rmt_port = udp->src_port;
  hdr->is_ip4 = is_ip4;

  if (is_ip4)
    {
      ip4_header_t *ip4;

      /* TODO: must fix once udp_local does ip options correctly */
      ip4 = (ip4_header_t *) (((u8 *) udp) - sizeof (*ip4));
      ip_set (&hdr->lcl_ip, &ip4->dst_address, 1);
      ip_set (&hdr->rmt_ip, &ip4->src_address, 1);
      hdr->data_length = clib_net_to_host_u16 (ip4->length);
      hdr->data_length -= sizeof (ip4_header_t) + sizeof (udp_header_t);
      s = session_lookup_safe4 (fib_index, &ip4->dst_address,
				&ip4->src_address, udp->dst_port,
				udp->src_port, TRANSPORT_PROTO_UDP);
    }
  else
    {
      ip6_header_t *ip60;

      ip60 = (ip6_header_t *) (((u8 *) udp) - sizeof (*ip60));
      ip_set (&hdr->lcl_ip, &ip60->dst_address, 0);
      ip_set (&hdr->rmt_ip, &ip60->src_address, 0);
      hdr->data_length = clib_net_to_host_u16 (ip60->payload_length);
      hdr->data_length -= sizeof (udp_header_t);
      s = session_lookup_safe6 (fib_index, &ip60->dst_address,
				&ip60->src_address, udp->dst_port,
				udp->src_port, TRANSPORT_PROTO_UDP);
    }

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    b->current_length = hdr->data_length;
  else
    b->total_length_not_including_first_buffer = hdr->data_length
      - b->current_length;

  return s;
}

always_inline uword
udp46_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * frame, u8 is_ip4)
{
  u32 n_left_from, *from, errors, *first_buffer;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 err_counters[UDP_N_ERROR] = { 0 };
  u32 thread_index = vm->thread_index;

  from = first_buffer = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;

  while (n_left_from > 0)
    {
      u32 error0 = UDP_ERROR_ENQUEUED;
      session_dgram_hdr_t hdr0;
      udp_connection_t *uc0;
      session_t *s0;

      s0 = udp_parse_and_lookup_buffer (b[0], &hdr0, is_ip4);
      if (PREDICT_FALSE (!s0))
	{
	  error0 = UDP_ERROR_NO_LISTENER;
	  goto done;
	}

      /*
       * If session exists pool peeker lock is taken at this point unless
       * the session is already on the right thread or is a listener
       */

      if (s0->session_state == SESSION_STATE_OPENED)
	{
	  u8 queue_event = 1;
	  uc0 = udp_connection_from_transport (session_get_transport (s0));
	  if (uc0->flags & UDP_CONN_F_CONNECTED)
	    {
	      if (s0->thread_index != thread_index)
		{
		  /*
		   * Clone the transport. It will be cleaned up with the
		   * session once we notify the session layer.
		   */
		  uc0 = udp_connection_clone_safe (s0->connection_index,
						   s0->thread_index);
		  ASSERT (s0->session_index == uc0->c_s_index);

		  /*
		   * Drop the peeker lock on pool resize and ask session
		   * layer for a new session.
		   */
		  session_pool_remove_peeker (s0->thread_index);
		  session_dgram_connect_notify (&uc0->connection,
						s0->thread_index, &s0);
		  queue_event = 0;
		}
	      else
		s0->session_state = SESSION_STATE_READY;
	    }
	  else
	    {
	      session_pool_remove_peeker (s0->thread_index);
	    }
	  udp_connection_enqueue (uc0, s0, &hdr0, thread_index, b[0],
				  queue_event, &error0);
	}
      else if (s0->session_state == SESSION_STATE_READY)
	{
	  uc0 = udp_connection_from_transport (session_get_transport (s0));
	  udp_connection_enqueue (uc0, s0, &hdr0, thread_index, b[0], 1,
				  &error0);
	}
      else if (s0->session_state == SESSION_STATE_LISTENING)
	{
	  uc0 = udp_connection_from_transport (session_get_transport (s0));
	  if (uc0->flags & UDP_CONN_F_CONNECTED)
	    {
	      uc0 = udp_connection_accept (uc0, &hdr0, thread_index);
	      if (!uc0)
		{
		  error0 = UDP_ERROR_CREATE_SESSION;
		  goto done;
		}
	      s0 = session_get (uc0->c_s_index, uc0->c_thread_index);
	      error0 = UDP_ERROR_ACCEPT;
	    }
	  udp_connection_enqueue (uc0, s0, &hdr0, thread_index, b[0], 1,
				  &error0);
	}
      else
	{
	  error0 = UDP_ERROR_NOT_READY;
	  session_pool_remove_peeker (s0->thread_index);
	}

    done:
      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	udp_trace_buffer (vm, node, b[0], s0, error0);

      b += 1;
      n_left_from -= 1;

      udp_inc_err_counter (err_counters, error0, 1);
    }

  vlib_buffer_free (vm, first_buffer, frame->n_vectors);
  errors = session_main_flush_enqueue_events (TRANSPORT_PROTO_UDP,
					      thread_index);
  err_counters[UDP_ERROR_MQ_FULL] = errors;
  udp_store_err_counters (vm, is_ip4, err_counters);
  return frame->n_vectors;
}

static uword
udp4_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  return udp46_input_inline (vm, node, frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (udp4_input_node) =
{
  .function = udp4_input,
  .name = "udp4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_udp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (udp_error_strings),
  .error_strings = udp_error_strings,
  .n_next_nodes = UDP_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [UDP_INPUT_NEXT_##s] = n,
      foreach_udp_input_next
#undef _
  },
};
/* *INDENT-ON* */

static uword
udp6_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  return udp46_input_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (udp6_input_node) =
{
  .function = udp6_input,
  .name = "udp6-input",
  .vector_size = sizeof (u32),
  .format_trace = format_udp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (udp_error_strings),
  .error_strings = udp_error_strings,
  .n_next_nodes = UDP_INPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [UDP_INPUT_NEXT_##s] = n,
      foreach_udp_input_next
#undef _
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
