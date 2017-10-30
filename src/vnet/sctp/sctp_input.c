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

typedef enum _sctp_init_phase_next
{
#define _(s,n) SCTP_INIT_PHASE_NEXT_##s,
  foreach_sctp_state_next
#undef _
    SCTP_INIT_PHASE_N_NEXT,
} sctp_init_phase_next_t;

typedef enum _sctp_established_phase_next
{
#define _(s,n) SCTP_ESTABLISHED_PHASE_NEXT_##s,
  foreach_sctp_state_next
#undef _
    SCTP_ESTABLISHED_PHASE_N_NEXT,
} sctp_established_phase_next_t;

typedef enum _sctp_shutdown_phase_next
{
#define _(s,n) SCTP_SHUTDOWN_PHASE_NEXT_##s,
  foreach_sctp_state_next
#undef _
    SCTP_SHUTDOWN_PHASE_N_NEXT,
} sctp_shutdown_phase_next_t;

/* Generic, state independent indices */
typedef enum _sctp_state_next
{
#define _(s,n) SCTP_NEXT_##s,
  foreach_sctp_state_next
#undef _
    SCTP_STATE_N_NEXT,
} sctp_state_next_t;

typedef enum _sctp_input_next
{
  SCTP_INPUT_NEXT_DROP,
  SCTP_INPUT_NEXT_INIT_PHASE,
  SCTP_INPUT_NEXT_ESTABLISHED_PHASE,
  SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
  SCTP_INPUT_N_NEXT
} sctp_input_next_t;

#define foreach_sctp4_input_next                 \
  _ (DROP, "error-drop")                         \
  _ (INIT_PHASE, "sctp4-init")                   \
  _ (ESTABLISHED_PHASE, "sctp4-established")     \
  _ (SHUTDOWN_PHASE, "sctp4-shutdown")

#define foreach_sctp6_input_next                 \
  _ (DROP, "error-drop")                         \
  _ (INIT_PHASE, "sctp4-init")                   \
  _ (ESTABLISHED_PHASE, "sctp4-established")     \
  _ (SHUTDOWN_PHASE, "sctp4-shutdown")

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

vlib_node_registration_t sctp4_init_phase_node;
vlib_node_registration_t sctp6_init_phase_node;

always_inline void
sctp_handle_init (sctp_header_t * th0, sctp_chunks_common_hdr_t * chunk_hdr,
		  sctp_connection_t * child0, vlib_buffer_t * b0)
{
  sctp_init_chunk_t *init_chunk = (sctp_init_chunk_t *) (th0);
  ip4_address_t *ip4_addr = 0;
  ip6_address_t *ip6_addr = 0;
  u32 initiate_tag = init_chunk->initiate_tag;
  char hostname[FQDN_MAX_LENGTH];
  /*
   * If the length specified in the INIT message is bigger than the size in bytes of our structure it means that
   * optional parameters have been sent with the INIT chunk and we need to parse them.
   */
  if (clib_net_to_host_u16 (chunk_hdr->length) > sizeof (sctp_init_chunk_t))
    {
      u16 current_bytes = sizeof (sctp_init_chunk_t);
      while (current_bytes < clib_net_to_host_u16 (chunk_hdr->length))
	{
	  sctp_optional_parameters_hdr_t *opt_params_hdr =
	    (sctp_optional_parameters_hdr_t *) init_chunk
	    + sizeof (sctp_init_chunk_t);
	  switch (clib_net_to_host_u16 (opt_params_hdr->type))
	    {
	    case IPV4_ADDRESS_TYPE:
	      {
		sctp_ipv4_address_t *ipv4 =
		  (sctp_ipv4_address_t *) opt_params_hdr;
		clib_memcpy (ip4_addr, &ipv4->address,
			     sizeof (ip4_address_t));
		break;
	      }
	    case IPV6_ADDRESS_TYPE:
	      {
		sctp_ipv6_address_t *ipv6 =
		  (sctp_ipv6_address_t *) opt_params_hdr;
		clib_memcpy (ip6_addr, &ipv6->address,
			     sizeof (ip6_address_t));
		break;
	      }
	    case COOKIE_PRESERVATIVE_TYPE:
	      {
		sctp_cookie_preservative_t *cookie_pres =
		  (sctp_cookie_preservative_t *) opt_params_hdr;
		child0->life_span_inc = cookie_pres->life_span_inc;
		break;
	      }
	    case HOSTNAME_ADDRESS_TYPE:
	      {
		sctp_hostname_address_t *hostname_addr =
		  (sctp_hostname_address_t *) opt_params_hdr;
		clib_memcpy (hostname, hostname_addr->hostname,
			     FQDN_MAX_LENGTH);
		break;
	      }
	    case SUPPORTED_ADDRESS_TYPES:
	      {
		/* TODO */
		break;
	      }
	    }
	  current_bytes += clib_net_to_host_u16 (opt_params_hdr->length);
	}
    }
  /* Reuse buffer to make init-ack and send */
  sctp_make_initack (child0, b0, initiate_tag, ip4_addr, ip6_addr);
}

always_inline uword
sctp46_init_phase_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
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
	  sctp_chunks_common_hdr_t *chunk_hdr = 0;
	  sctp_connection_t *lc0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  sctp_connection_t *child0;
	  u32 error0 = SCTP_ERROR_INITS_RCVD, next0 =
	    SCTP_INIT_PHASE_NEXT_DROP;

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

	  chunk_hdr =
	    (sctp_chunks_common_hdr_t *) (th0 + sctp_header_bytes ());

	  switch (clib_net_to_host_u16 (chunk_hdr->type))
	    {
	      /* Received a INIT chunk; as per protocol, do not change connection state nor allocate any resources */
	    case INIT:
	      {
		sctp_handle_init (th0, chunk_hdr, child0, b0);
		break;
	      }

	    case INIT_ACK:
	      break;
	    case ABORT:
	      break;
	    }

	  if (stream_session_accept (&child0->connection, lc0->c_s_index,
				     0 /* notify */ ))
	    {
	      clib_warning ("session accept fail");
	      sctp_connection_cleanup (child0);
	      error0 = SCTP_ERROR_CREATE_SESSION_FAIL;
	      goto drop;
	    }

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
sctp4_init_phase (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  return sctp46_init_phase_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
sctp6_init_phase (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  return sctp46_init_phase_inline (vm, node, from_frame, 0 /* is_ip4 */ );
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
VLIB_REGISTER_NODE (sctp4_init_phase_node) =
{
  .function = sctp4_init_phase,
  .name = "sctp4-init",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_INIT_PHASE_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_INIT_PHASE_NEXT_##s] = n,
    foreach_sctp_state_next
#undef _
  },
  .format_trace = format_sctp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp4_init_phase_node, sctp4_init_phase);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp6_init_phase_node) =
{
  .function = sctp6_init_phase,
  .name = "sctp6-init",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_INIT_PHASE_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_INIT_PHASE_NEXT_##s] = n,
    foreach_sctp_state_next
#undef _
  },
  .format_trace = format_sctp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp6_init_phase_node, sctp6_init_phase);

vlib_node_registration_t sctp4_established_phase_process_node;
vlib_node_registration_t sctp6_established_phase_process_node;

always_inline uword
sctp46_established_phase_inline (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame, int is_ip4)
{
  /*
     sctp_main_t *tm = vnet_get_sctp_main ();
     u32 n_left_from, next_index, *from, *to_next;
     u32 my_thread_index = vm->thread_index;
     u32 errors = 0;

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
     sctp_header_t *sctp0 = 0;
     sctp_connection_t *tc0;
     u32 next0 = SCTP_RCV_PROCESS_NEXT_DROP, error0 =
     SCTP_ERROR_ENQUEUED;

     bi0 = from[0];
     to_next[0] = bi0;
     from += 1;
     to_next += 1;
     n_left_from -= 1;
     n_left_to_next -= 1;

     b0 = vlib_get_buffer (vm, bi0);
     tc0 = sctp_connection_get (vnet_buffer (b0)->tcp.connection_index,
     my_thread_index);
     if (PREDICT_FALSE (tc0 == 0))
     {
     error0 = SCTP_ERROR_INVALID_CONNECTION;
     goto drop;
     }

     sctp0 = sctp_buffer_hdr (b0);
     switch (tc0->state)
     {
     case SCTP_STATE_CLOSED:
     goto drop;
     case SCTP_STATE_COOKIE_WAIT:
     goto drop;
     }
     drop:
     b0->error = error0 ? node->errors[error0] : 0;

     if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
     {
     sctp_rx_trace_t *t0 =
     vlib_add_trace (vm, node, b0, sizeof (*t0));
     // sctp_set_rx_trace_data (t0, tc0, tcp0, b0, is_ip4);
     }

     vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
     n_left_to_next, bi0, next0);
     }
     vlib_put_next_frame (vm, node, next_index, n_left_to_next);

     }
     errors = session_manager_flush_enqueue_events (TRANSPORT_PROTO_SCTP,
     my_thread_index);

     sctp_node_inc_counter (vm, is_ip4, sctp4_rcv_process_node.index,
     sctp6_rcv_process_node.index,
     SCTP_ERROR_EVENT_FIFO_FULL, errors);
   */
  return from_frame->n_vectors;
}

static uword
sctp4_established_phase (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame)
{
  return sctp46_established_phase_inline (vm, node, from_frame,
					  1 /* is_ip4 */ );
}

static uword
sctp6_established_phase (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame)
{
  return sctp46_established_phase_inline (vm, node, from_frame,
					  0 /* is_ip4 */ );
}

u8 *
format_sctp_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sctp_rx_trace_t *t = va_arg (*args, sctp_rx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%U\n%U%U",
	      format_sctp_header, &t->sctp_header, 128,
	      format_white_space, indent,
	      format_sctp_connection, &t->sctp_connection, 1);

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp4_established_phase_process_node) =
{
  .function = sctp4_established_phase,
  .name = "sctp4-established",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_ESTABLISHED_PHASE_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_ESTABLISHED_PHASE_NEXT_##s] = n,
    foreach_sctp_state_next
#undef _
  },
  .format_trace = format_sctp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp4_established_phase_process_node,
			      sctp4_established_phase);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp6_established_phase_process_node) =
{
  .function = sctp6_established_phase,
  .name = "sctp6-established",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_ESTABLISHED_PHASE_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_ESTABLISHED_PHASE_NEXT_##s] = n,
    foreach_sctp_state_next
#undef _
  },
  .format_trace = format_sctp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp6_established_phase_process_node,
			      sctp6_established_phase);


/*
 * This is the function executed first for the SCTP graph.
 * It takes care of doing the initial message parsing and
 * dispatch to the specialized function.
 */
always_inline uword
sctp46_input_dispatcher (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->thread_index;
  sctp_main_t *tm = vnet_get_sctp_main ();

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;
  sctp_set_time_now (my_thread_index);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  int n_advance_bytes0, n_data_bytes0;
	  u32 bi0, fib_index0;
	  vlib_buffer_t *b0;
	  sctp_header_t *sctp0 = 0;
	  sctp_chunks_common_hdr_t *sctp_chunkhdr0 = 0;
	  sctp_connection_t *tc0;
	  transport_connection_t *tconn;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  u32 error0 = SCTP_ERROR_NO_LISTENER, next0 = SCTP_INPUT_NEXT_DROP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  vnet_buffer (b0)->tcp.flags = 0;
	  fib_index0 = vnet_buffer (b0)->ip.fib_index;

	  /* Checksum computed by ipx_local no need to compute again */

	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      sctp0 = ip4_next_header (ip40);
	      sctp_chunkhdr0 =
		(sctp_chunks_common_hdr_t *) (sctp0 + sctp_header_bytes ());
	      n_advance_bytes0 =
		(ip4_header_bytes (ip40) + sctp_header_bytes ());
	      n_data_bytes0 =
		clib_net_to_host_u16 (ip40->length) - n_advance_bytes0;
	      tconn =
		session_lookup_connection_wt4 (fib_index0, &ip40->dst_address,
					       &ip40->src_address,
					       sctp0->dst_port,
					       sctp0->src_port,
					       TRANSPORT_PROTO_SCTP,
					       my_thread_index);
	      tc0 = sctp_get_connection_from_transport (tconn);
	      ASSERT (sctp_lookup_is_valid (tc0, sctp0));
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      sctp0 = ip6_next_header (ip60);
	      sctp_chunkhdr0 =
		(sctp_chunks_common_hdr_t *) (sctp0 + sctp_header_bytes ());
	      n_advance_bytes0 = sctp_header_bytes ();
	      n_data_bytes0 =
		clib_net_to_host_u16 (ip60->payload_length) -
		n_advance_bytes0;
	      n_advance_bytes0 += sizeof (ip60[0]);
	      tconn = session_lookup_connection_wt6 (fib_index0,
						     &ip60->dst_address,
						     &ip60->src_address,
						     sctp0->dst_port,
						     sctp0->src_port,
						     TRANSPORT_PROTO_SCTP,
						     my_thread_index);
	      tc0 = sctp_get_connection_from_transport (tconn);
	      ASSERT (sctp_lookup_is_valid (tc0, sctp0));
	    }

	  /* Length check */
	  if (PREDICT_FALSE (n_advance_bytes0 < 0))
	    {
	      error0 = SCTP_ERROR_LENGTH;
	      goto done;
	    }

	  /* Session exists */
	  if (PREDICT_TRUE (0 != tc0))
	    {
	      /* Save connection index */
	      vnet_buffer (b0)->sctp.connection_index = tc0->c_c_index;

	      vnet_buffer (b0)->sctp.hdr_offset =
		(u8 *) sctp0 - (u8 *) vlib_buffer_get_current (b0);
	      vnet_buffer (b0)->sctp.data_offset = n_advance_bytes0;
	      vnet_buffer (b0)->sctp.data_len = n_data_bytes0;

	      next0 =
		tm->dispatch_table[tc0->state][sctp_chunkhdr0->type].next;
	      error0 =
		tm->dispatch_table[tc0->state][sctp_chunkhdr0->type].error;

	    }
	  else
	    {
	      /* Send reset */
	      next0 = SCTP_INPUT_NEXT_DROP;
	      error0 = SCTP_ERROR_NO_LISTENER;
	    }

	done:
	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sctp_rx_trace_t *t0 =
		vlib_add_trace (vm, node, b0, sizeof (*t0));
	      // sctp_set_rx_trace_data (t0, tc0, sctp0, b0, is_ip4);
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static uword
sctp4_input_dispatcher (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * from_frame)
{
  return sctp46_input_dispatcher (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
sctp6_input_dispatcher (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * from_frame)
{
  return sctp46_input_dispatcher (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp4_input_node) =
{
  .function = sctp4_input_dispatcher,
  .name = "sctp4-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_INPUT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_INPUT_NEXT_##s] = n,
    foreach_sctp4_input_next
#undef _
  },
  .format_buffer = format_sctp_header,
  .format_trace = format_sctp_rx_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp4_input_node, sctp4_input_dispatcher);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp6_input_node) =
{
  .function = sctp6_input_dispatcher,
  .name = "sctp6-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_INPUT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_INPUT_NEXT_##s] = n,
    foreach_sctp6_input_next
#undef _
  },
  .format_buffer = format_sctp_header,
  .format_trace = format_sctp_rx_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp6_input_node, sctp6_input_dispatcher);

vlib_node_registration_t sctp4_input_node;
vlib_node_registration_t sctp6_input_node;

static void
sctp_dispatch_table_init (sctp_main_t * tm)
{
  int i, j;
  for (i = 0; i < ARRAY_LEN (tm->dispatch_table); i++)
    for (j = 0; j < ARRAY_LEN (tm->dispatch_table[i]); j++)
      {
	tm->dispatch_table[i][j].next = SCTP_INPUT_NEXT_DROP;
	tm->dispatch_table[i][j].error = SCTP_ERROR_DISPATCH;
      }

#define _(t,f,n,e)                                           	\
do {                                                       	\
    tm->dispatch_table[SCTP_STATE_##t][f].next = (n);         	\
    tm->dispatch_table[SCTP_STATE_##t][f].error = (e);        	\
} while (0)

  _(CLOSED, INIT, SCTP_INPUT_NEXT_INIT_PHASE, SCTP_ERROR_NONE);
  _(CLOSED, ABORT, SCTP_INPUT_NEXT_INIT_PHASE, SCTP_ERROR_NONE);
  _(CLOSED, COOKIE_ECHO, SCTP_INPUT_NEXT_ESTABLISHED_PHASE, SCTP_ERROR_NONE);
  _(COOKIE_WAIT, INIT_ACK, SCTP_INPUT_NEXT_INIT_PHASE, SCTP_ERROR_NONE);
  _(COOKIE_ECHOED, COOKIE_ACK, SCTP_INPUT_NEXT_ESTABLISHED_PHASE,
    SCTP_ERROR_NONE);
  _(ESTABLISHED, SHUTDOWN, SCTP_INPUT_NEXT_SHUTDOWN_PHASE, SCTP_ERROR_NONE);
  _(SHUTDOWN_SENT, SHUTDOWN, SCTP_INPUT_NEXT_SHUTDOWN_PHASE, SCTP_ERROR_NONE);
  _(SHUTDOWN_SENT, SHUTDOWN_ACK, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_RECEIVED, SHUTDOWN_ACK, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_ACK_SENT, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);

#undef _
}

clib_error_t *
sctp_input_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;
  sctp_main_t *tm = vnet_get_sctp_main ();

  if ((error = vlib_call_init_function (vm, sctp_init)))
    return error;

  /* Initialize dispatch table. */
  sctp_dispatch_table_init (tm);

  return error;
}

VLIB_INIT_FUNCTION (sctp_input_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
