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
#include <vnet/pg/pg.h>
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
      u32 fib_index0, data_len;
      u32 error0 = UDP_ERROR_ENQUEUED;
      udp_header_t *udp0;
      ip4_header_t *ip40;
      ip6_header_t *ip60;
      u8 *data0;
      session_t *s0;
      udp_connection_t *uc0, *child0, *new_uc0;
      transport_connection_t *tc0;
      int wrote0;
      void *rmt_addr, *lcl_addr;
      session_dgram_hdr_t hdr0;
      u8 queue_event = 1;

      /* udp_local hands us a pointer to the udp data */
      data0 = vlib_buffer_get_current (b[0]);
      udp0 = (udp_header_t *) (data0 - sizeof (*udp0));
      fib_index0 = vnet_buffer (b[0])->ip.fib_index;

      if (is_ip4)
	{
	  /* TODO: must fix once udp_local does ip options correctly */
	  ip40 = (ip4_header_t *) (((u8 *) udp0) - sizeof (*ip40));
	  s0 = session_lookup_safe4 (fib_index0, &ip40->dst_address,
				     &ip40->src_address, udp0->dst_port,
				     udp0->src_port, TRANSPORT_PROTO_UDP);
	  lcl_addr = &ip40->dst_address;
	  rmt_addr = &ip40->src_address;
	  data_len = clib_net_to_host_u16 (ip40->length);
	  data_len -= sizeof (ip4_header_t) + sizeof (udp_header_t);
	}
      else
	{
	  ip60 = (ip6_header_t *) (((u8 *) udp0) - sizeof (*ip60));
	  s0 = session_lookup_safe6 (fib_index0, &ip60->dst_address,
				     &ip60->src_address, udp0->dst_port,
				     udp0->src_port, TRANSPORT_PROTO_UDP);
	  lcl_addr = &ip60->dst_address;
	  rmt_addr = &ip60->src_address;
	  data_len = clib_net_to_host_u16 (ip60->payload_length);
	  data_len -= sizeof (udp_header_t);
	}

      if (PREDICT_FALSE (!s0))
	{
	  error0 = UDP_ERROR_NO_LISTENER;
	  goto trace0;
	}

      if (s0->session_state == SESSION_STATE_OPENED)
	{
	  /* TODO optimization: move cl session to right thread
	   * However, since such a move would affect the session handle,
	   * which we pass 'raw' to the app, we'd also have notify the
	   * app of the change or change the way we pass handles to apps.
	   */
	  tc0 = session_get_transport (s0);
	  uc0 = udp_get_connection_from_transport (tc0);
	  if (uc0->flags & UDP_CONN_F_CONNECTED)
	    {
	      if (s0->thread_index != vlib_get_thread_index ())
		{
		  /*
		   * Clone the transport. It will be cleaned up with the
		   * session once we notify the session layer.
		   */
		  new_uc0 =
		    udp_connection_clone_safe (s0->connection_index,
					       s0->thread_index);
		  ASSERT (s0->session_index == new_uc0->c_s_index);

		  /*
		   * Drop the 'lock' on pool resize
		   */
		  session_pool_remove_peeker (s0->thread_index);
		  session_dgram_connect_notify (&new_uc0->connection,
						s0->thread_index, &s0);
		  tc0 = &new_uc0->connection;
		  uc0 = new_uc0;
		  queue_event = 0;
		}
	      else
		s0->session_state = SESSION_STATE_READY;
	    }
	}
      else if (s0->session_state == SESSION_STATE_READY)
	{
	  tc0 = session_get_transport (s0);
	  uc0 = udp_get_connection_from_transport (tc0);
	}
      else if (s0->session_state == SESSION_STATE_LISTENING)
	{
	  tc0 = listen_session_get_transport (s0);
	  uc0 = udp_get_connection_from_transport (tc0);
	  if (uc0->flags & UDP_CONN_F_CONNECTED)
	    {
	      child0 = udp_connection_alloc (thread_index);
	      if (is_ip4)
		{
		  ip_set (&child0->c_lcl_ip, &ip40->dst_address, 1);
		  ip_set (&child0->c_rmt_ip, &ip40->src_address, 1);
		}
	      else
		{
		  ip_set (&child0->c_lcl_ip, &ip60->dst_address, 0);
		  ip_set (&child0->c_rmt_ip, &ip60->src_address, 0);
		}
	      child0->c_lcl_port = udp0->dst_port;
	      child0->c_rmt_port = udp0->src_port;
	      child0->c_is_ip4 = is_ip4;
	      child0->c_fib_index = tc0->fib_index;
	      child0->mss = uc0->mss;
	      child0->flags |= UDP_CONN_F_CONNECTED;

	      if (session_stream_accept (&child0->connection,
					 tc0->s_index, tc0->thread_index, 1))
		{
		  error0 = UDP_ERROR_CREATE_SESSION;
		  goto trace0;
		}
	      s0 = session_get (child0->c_s_index, child0->c_thread_index);
	      s0->session_state = SESSION_STATE_READY;
	      tc0 = &child0->connection;
	      uc0 = udp_get_connection_from_transport (tc0);
	      udp_connection_share_port (clib_net_to_host_u16
					 (uc0->c_lcl_port), uc0->c_is_ip4);
	      error0 = UDP_ERROR_LISTENER;
	    }
	}
      else
	{
	  error0 = UDP_ERROR_NOT_READY;
	  goto trace0;
	}


      if (svm_fifo_max_enqueue_prod (s0->rx_fifo)
	  < data_len + sizeof (session_dgram_hdr_t))
	{
	  error0 = UDP_ERROR_FIFO_FULL;
	  goto trace0;
	}

      hdr0.data_length = data_len;
      if (PREDICT_TRUE (!(b[0]->flags & VLIB_BUFFER_NEXT_PRESENT)))
	b[0]->current_length = data_len;
      else
	b[0]->total_length_not_including_first_buffer = data_len
	  - b[0]->current_length;

      hdr0.data_offset = 0;
      ip_set (&hdr0.lcl_ip, lcl_addr, is_ip4);
      ip_set (&hdr0.rmt_ip, rmt_addr, is_ip4);
      hdr0.lcl_port = udp0->dst_port;
      hdr0.rmt_port = udp0->src_port;
      hdr0.is_ip4 = is_ip4;

      clib_spinlock_lock (&uc0->rx_lock);
      /* If session is owned by another thread and rx event needed,
       * enqueue event now while we still have the peeker lock */
      if (s0->thread_index != thread_index)
	{
	  wrote0 = session_enqueue_dgram_connection (s0, &hdr0, b[0],
						     TRANSPORT_PROTO_UDP,
						     /* queue event */ 0);
	  if (queue_event && !svm_fifo_has_event (s0->rx_fifo))
	    session_enqueue_notify (s0);
	}
      else
	{
	  wrote0 = session_enqueue_dgram_connection (s0, &hdr0, b[0],
						     TRANSPORT_PROTO_UDP,
						     queue_event);
	}
      clib_spinlock_unlock (&uc0->rx_lock);
      ASSERT (wrote0 > 0);

      if (s0->session_state != SESSION_STATE_LISTENING)
	session_pool_remove_peeker (s0->thread_index);

    trace0:

      b[0]->error = node->errors[error0];

      b += 1;
      n_left_from -= 1;

      udp_inc_err_counter (err_counters, error0, 1);

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  udp_input_trace_t *t = vlib_add_trace (vm, node, b[0],
						 sizeof (*t));

	  t->connection = s0 ? s0->connection_index : ~0;
	  t->disposition = error0;
	  t->thread_index = thread_index;
	}
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
