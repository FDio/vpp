/*
 * Copyright (c) 2017 SUSE LLC.
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
#include <vppinfra/sparse_vec.h>
#include <vnet/sctp/sctp.h>
#include <vnet/sctp/sctp_packet.h>
#include <vnet/session/session.h>
#include <math.h>

static char *sctp_error_strings[] = {
#define sctp_error(n,s) s,
#include <vnet/sctp/sctp_error.def>
#undef sctp_error
};

/* All SCTP nodes have the same outgoing arcs */
#define foreach_sctp_state_next                  \
  _ (DROP, "error-drop")                        \
  _ (SCTP4_OUTPUT, "sctp4-output")                \
  _ (SCTP6_OUTPUT, "sctp6-output")

typedef enum _sctp_established_next
{
#define _(s,n) SCTP_ESTABLISHED_NEXT_##s,
  foreach_sctp_state_next
#undef _
    SCTP_ESTABLISHED_N_NEXT,
} sctp_established_next_t;

typedef enum _sctp_rcv_process_next
{
#define _(s,n) SCTP_RCV_PROCESS_NEXT_##s,
  foreach_sctp_state_next
#undef _
    SCTP_RCV_PROCESS_N_NEXT,
} sctp_rcv_process_next_t;

typedef enum _sctp_syn_sent_next
{
#define _(s,n) SCTP_SYN_SENT_NEXT_##s,
  foreach_sctp_state_next
#undef _
    SCTP_SYN_SENT_N_NEXT,
} sctp_syn_sent_next_t;

typedef enum _sctp_listen_next
{
#define _(s,n) SCTP_LISTEN_NEXT_##s,
  foreach_sctp_state_next
#undef _
    SCTP_LISTEN_N_NEXT,
} sctp_listen_next_t;

/* Generic, state independent indices */
typedef enum _sctp_state_next
{
#define _(s,n) SCTP_NEXT_##s,
  foreach_sctp_state_next
#undef _
    SCTP_STATE_N_NEXT,
} sctp_state_next_t;

vlib_node_registration_t sctp4_input_node;
vlib_node_registration_t sctp6_input_node;

static u8
sctp_lookup_is_valid (sctp_connection_t * tc, sctp_header_t * hdr)
{
  if (!tc)
    return 1;

  u8 is_valid = (tc->c_lcl_port == hdr->dst_port
		 && (tc->state == SCTP_STATE_ESTABLISHED
		     || tc->c_rmt_port == hdr->src_port));

  return is_valid;
}

always_inline sctp_packet_t *
sctp_packet (vlib_buffer_t * b)
{
  ASSERT ((signed) b->current_data >= (signed) -VLIB_BUFFER_PRE_DATA_SIZE);
  return (sctp_packet_t *) (b->data + b->current_data
			    + vnet_buffer (b)->sctp.hdr_offset);
}

always_inline sctp_header_t *
sctp_header (vlib_buffer_t * b)
{
  ASSERT ((signed) b->current_data >= (signed) -VLIB_BUFFER_PRE_DATA_SIZE);
  return (sctp_header_t *) (b->data + b->current_data
			    + vnet_buffer (b)->sctp.hdr_offset);
}

/**
 * Lookup transport connection
 */
static sctp_connection_t *
sctp_lookup_connection (u32 fib_index, vlib_buffer_t * b, u8 thread_index,
			u8 is_ip4)
{
  sctp_header_t *sctp;
  transport_connection_t *tconn;
  sctp_connection_t *tc;
  if (is_ip4)
    {
      ip4_header_t *ip4;
      ip4 = vlib_buffer_get_current (b);
      sctp = ip4_next_header (ip4);
      tconn = session_lookup_connection_wt4 (fib_index,
					     &ip4->dst_address,
					     &ip4->src_address,
					     sctp->dst_port,
					     sctp->src_port,
					     TRANSPORT_PROTO_SCTP,
					     thread_index);
      tc = sctp_get_connection_from_transport (tconn);
      ASSERT (sctp_lookup_is_valid (tc, sctp));
    }
  else
    {
      ip6_header_t *ip6;
      ip6 = vlib_buffer_get_current (b);
      sctp = ip6_next_header (ip6);
      tconn = session_lookup_connection_wt6 (fib_index,
					     &ip6->dst_address,
					     &ip6->src_address,
					     sctp->dst_port,
					     sctp->src_port,
					     TRANSPORT_PROTO_SCTP,
					     thread_index);
      tc = sctp_get_connection_from_transport (tconn);
      ASSERT (sctp_lookup_is_valid (tc, sctp));
    }
  return tc;
}

typedef struct
{
  sctp_header_t sctp_header;
  sctp_connection_t sctp_connection;
} sctp_rx_trace_t;

#define sctp_next_output(is_ip4) (is_ip4 ? SCTP_NEXT_SCTP4_OUTPUT          \
                                        : SCTP_NEXT_SCTP6_OUTPUT)

always_inline uword
sctp46_listen_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->thread_index;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  sctp_rx_trace_t *t0;
	  sctp_header_t *th0 = 0;
	  sctp_connection_t *lc0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  sctp_connection_t *child0;
	  u32 error0 = SCTP_ERROR_INITS_RCVD, next0 = SCTP_LISTEN_NEXT_DROP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  lc0 = sctp_listener_get (vnet_buffer (b0)->sctp.connection_index);

	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      th0 = ip4_next_header (ip40);
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      th0 = ip6_next_header (ip60);
	    }

	  child0 =
	    sctp_lookup_connection (lc0->c_fib_index, b0, my_thread_index,
				    is_ip4);
	  if (PREDICT_FALSE (child0->state != SCTP_STATE_CLOSED))
	    {
	      error0 = SCTP_ERROR_CREATE_EXISTS;
	      goto drop;
	    }

	  /* Create child session and send INIT-ACK */
	  child0 = sctp_connection_new (my_thread_index);
	  child0->c_lcl_port = th0->dst_port;
	  child0->c_rmt_port = th0->src_port;
	  child0->c_is_ip4 = is_ip4;

	  if (is_ip4)
	    {
	      child0->c_lcl_ip4.as_u32 = ip40->dst_address.as_u32;
	      child0->c_rmt_ip4.as_u32 = ip40->src_address.as_u32;
	    }
	  else
	    {
	      clib_memcpy (&child0->c_lcl_ip6, &ip60->dst_address,
			   sizeof (ip6_address_t));
	      clib_memcpy (&child0->c_rmt_ip6, &ip60->src_address,
			   sizeof (ip6_address_t));
	    }

	  child0->irs = vnet_buffer (b0)->sctp.seq_number;
	  child0->rcv_nxt = vnet_buffer (b0)->sctp.seq_number + 1;
	  child0->rcv_las = child0->rcv_nxt;

	  sctp_connection_init_vars (child0);

	  if (stream_session_accept (&child0->connection, lc0->c_s_index,
				     0 /* notify */ ))
	    {
	      clib_warning ("session accept fail");
	      sctp_connection_cleanup (child0);
	      error0 = SCTP_ERROR_CREATE_SESSION_FAIL;
	      goto drop;
	    }

	  /* Reuse buffer to make init-ack and send */
	  sctp_make_initack (child0, b0);
	  next0 = sctp_next_output (is_ip4);

	drop:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      clib_memcpy (&t0->sctp_header, th0, sizeof (t0->sctp_header));
	      clib_memcpy (&t0->sctp_connection, lc0,
			   sizeof (t0->sctp_connection));
	    }

	  b0->error = node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

static uword
sctp4_listen (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame)
{
  return sctp46_listen_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
sctp6_listen (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame)
{
  return sctp46_listen_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

u8 *
format_sctp_rx_trace_short (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sctp_rx_trace_t *t = va_arg (*args, sctp_rx_trace_t *);

  s = format (s, "%d -> %d (%U)",
	      clib_net_to_host_u16 (t->sctp_header.src_port),
	      clib_net_to_host_u16 (t->sctp_header.dst_port),
	      format_sctp_state, t->sctp_connection.state);

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp4_listen_node) =
{
  .function = sctp4_listen,
  .name = "sctp4-listen",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_LISTEN_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_LISTEN_NEXT_##s] = n,
    foreach_sctp_state_next
#undef _
  },
  .format_trace = format_sctp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp4_listen_node, sctp4_listen);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp6_listen_node) =
{
  .function = sctp6_listen,
  .name = "sctp6-listen",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_LISTEN_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_LISTEN_NEXT_##s] = n,
    foreach_sctp_state_next
#undef _
  },
  .format_trace = format_sctp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp6_listen_node, sctp6_listen);

vlib_node_registration_t sctp4_input_node;
vlib_node_registration_t sctp6_input_node;









/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
