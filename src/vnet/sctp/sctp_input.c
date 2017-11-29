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
#include <vnet/sctp/sctp_debug.h>
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
sctp_lookup_is_valid (sctp_connection_t * sctp_conn, sctp_header_t * sctp_hdr)
{
  if (!sctp_conn)
    return 1;

  u8 is_valid = (sctp_conn->c_lcl_port == sctp_hdr->dst_port
		 && (sctp_conn->state == SCTP_STATE_ESTABLISHED
		     || sctp_conn->c_rmt_port == sctp_hdr->src_port));

  return is_valid;
}

/**
 * Lookup transport connection
 */
static sctp_connection_t *
sctp_lookup_connection (u32 fib_index, vlib_buffer_t * b, u8 thread_index,
			u8 is_ip4)
{
  sctp_header_t *sctp_hdr;
  transport_connection_t *tconn;
  sctp_connection_t *sctp_conn;
  u8 is_filtered;
  if (is_ip4)
    {
      ip4_header_t *ip4_hdr;
      ip4_hdr = vlib_buffer_get_current (b);
      sctp_hdr = ip4_next_header (ip4_hdr);
      tconn = session_lookup_connection_wt4 (fib_index,
					     &ip4_hdr->dst_address,
					     &ip4_hdr->src_address,
					     sctp_hdr->dst_port,
					     sctp_hdr->src_port,
					     TRANSPORT_PROTO_SCTP,
					     thread_index, &is_filtered);
      sctp_conn = sctp_get_connection_from_transport (tconn);
      ASSERT (sctp_lookup_is_valid (sctp_conn, sctp_hdr));
    }
  else
    {
      ip6_header_t *ip6_hdr;
      ip6_hdr = vlib_buffer_get_current (b);
      sctp_hdr = ip6_next_header (ip6_hdr);
      tconn = session_lookup_connection_wt6 (fib_index,
					     &ip6_hdr->dst_address,
					     &ip6_hdr->src_address,
					     sctp_hdr->dst_port,
					     sctp_hdr->src_port,
					     TRANSPORT_PROTO_SCTP,
					     thread_index, &is_filtered);
      sctp_conn = sctp_get_connection_from_transport (tconn);
      ASSERT (sctp_lookup_is_valid (sctp_conn, sctp_hdr));
    }
  return sctp_conn;
}

typedef struct
{
  sctp_header_t sctp_header;
  sctp_connection_t sctp_connection;
} sctp_rx_trace_t;

#define sctp_next_output(is_ip4) (is_ip4 ? SCTP_NEXT_SCTP4_OUTPUT          \
                                        : SCTP_NEXT_SCTP6_OUTPUT)


void
sctp_set_rx_trace_data (sctp_rx_trace_t * rx_trace,
			sctp_connection_t * sctp_conn,
			sctp_header_t * sctp_hdr, vlib_buffer_t * b0,
			u8 is_ip4)
{
  if (sctp_conn)
    {
      clib_memcpy (&rx_trace->sctp_connection, sctp_conn,
		   sizeof (rx_trace->sctp_connection));
    }
  else
    {
      sctp_hdr = sctp_buffer_hdr (b0);
    }
  clib_memcpy (&rx_trace->sctp_header, sctp_hdr,
	       sizeof (rx_trace->sctp_header));
}

always_inline u16
sctp_calculate_implied_length (ip4_header_t * ip4_hdr, ip6_header_t * ip6_hdr,
			       int is_ip4)
{
  u16 sctp_implied_packet_length = 0;

  if (is_ip4)
    sctp_implied_packet_length =
      clib_net_to_host_u16 (ip4_hdr->length) - ip4_header_bytes (ip4_hdr);
  else
    sctp_implied_packet_length =
      clib_net_to_host_u16 (ip6_hdr->payload_length) - sizeof (ip6_hdr);

  return sctp_implied_packet_length;
}

always_inline u8
sctp_is_bundling (u16 sctp_implied_length,
		  sctp_chunks_common_hdr_t * sctp_common_hdr)
{
  if (sctp_implied_length !=
      sizeof (sctp_header_t) + vnet_sctp_get_chunk_length (sctp_common_hdr))
    return 1;
  return 0;
}

vlib_node_registration_t sctp4_init_phase_node;
vlib_node_registration_t sctp6_init_phase_node;

always_inline u16
sctp_handle_init (sctp_header_t * sctp_hdr,
		  sctp_chunks_common_hdr_t * sctp_chunk_hdr,
		  sctp_connection_t * sctp_conn, vlib_buffer_t * b0,
		  u16 sctp_implied_length)
{
  sctp_init_chunk_t *init_chunk = (sctp_init_chunk_t *) (sctp_hdr);
  ip4_address_t *ip4_addr = 0;
  ip6_address_t *ip6_addr = 0;
  char hostname[FQDN_MAX_LENGTH];

  /* Check the current state of the connection
   *
   * The logic required by the RFC4960 Section 5.2.2 is already taken care of
   * in the code below and by the "sctp_prepare_initack_chunk" function.
   * However, for debugging purposes it is nice to have a message printed out
   * for these corner-case scenarios.
   */
  if (sctp_conn->state != SCTP_STATE_CLOSED)
    {				/* UNEXPECTED scenario */
      switch (sctp_conn->state)
	{
	case SCTP_STATE_COOKIE_WAIT:	/* TODO */
	  SCTP_DBG ("Received INIT chunk while in COOKIE_WAIT state");
	  break;
	case SCTP_STATE_COOKIE_ECHOED:	/* TODO */
	  SCTP_DBG ("Received INIT chunk while in COOKIE_ECHOED state");
	  break;
	}
    }

  if (sctp_hdr->verification_tag != 0x0)
    return SCTP_ERROR_INVALID_TAG_FOR_INIT;

  /*
   * It is not possible to bundle any other CHUNK with the INIT chunk
   */
  if (sctp_is_bundling (sctp_implied_length, &init_chunk->chunk_hdr))
    return SCTP_ERROR_BUNDLING_VIOLATION;

  /* Save the INITIATE_TAG of the remote peer for this connection:
   * it MUST be used for the VERIFICATION_TAG parameter in the SCTP HEADER */
  sctp_conn->remote_tag = init_chunk->initiate_tag;
  /*
   * If the length specified in the INIT message is bigger than the size in bytes of our structure it means that
   * optional parameters have been sent with the INIT chunk and we need to parse them.
   */
  if (clib_net_to_host_u16 (sctp_chunk_hdr->length) >
      sizeof (sctp_init_chunk_t))
    {
      /* There are optional parameters in the INIT chunk */
      u16 pointer_offset = sizeof (sctp_init_chunk_t);
      while (pointer_offset < clib_net_to_host_u16 (sctp_chunk_hdr->length))
	{
	  sctp_opt_params_hdr_t *opt_params_hdr =
	    (sctp_opt_params_hdr_t *) init_chunk + pointer_offset;

	  switch (clib_net_to_host_u16 (opt_params_hdr->type))
	    {
	    case SCTP_IPV4_ADDRESS_TYPE:
	      {
		sctp_ipv4_addr_param_t *ipv4 =
		  (sctp_ipv4_addr_param_t *) opt_params_hdr;
		clib_memcpy (ip4_addr, &ipv4->address,
			     sizeof (ip4_address_t));
		break;
	      }
	    case SCTP_IPV6_ADDRESS_TYPE:
	      {
		sctp_ipv6_addr_param_t *ipv6 =
		  (sctp_ipv6_addr_param_t *) opt_params_hdr;
		clib_memcpy (ip6_addr, &ipv6->address,
			     sizeof (ip6_address_t));
		break;
	      }
	    case SCTP_COOKIE_PRESERVATIVE_TYPE:
	      {
		sctp_cookie_preservative_param_t *cookie_pres =
		  (sctp_cookie_preservative_param_t *) opt_params_hdr;
		sctp_conn->life_span_inc = cookie_pres->life_span_inc;
		break;
	      }
	    case SCTP_HOSTNAME_ADDRESS_TYPE:
	      {
		sctp_hostname_param_t *hostname_addr =
		  (sctp_hostname_param_t *) opt_params_hdr;
		clib_memcpy (hostname, hostname_addr->hostname,
			     FQDN_MAX_LENGTH);
		break;
	      }
	    case SCTP_SUPPORTED_ADDRESS_TYPES:
	      {
		/* TODO */
		break;
	      }
	    }
	  pointer_offset += clib_net_to_host_u16 (opt_params_hdr->length);
	}
    }
  /* Reuse buffer to make init-ack and send */
  sctp_prepare_initack_chunk (sctp_conn, b0, ip4_addr, ip6_addr);

  return SCTP_ERROR_NONE;
}

always_inline u16
sctp_handle_init_ack (sctp_header_t * sctp_hdr,
		      sctp_chunks_common_hdr_t * sctp_chunk_hdr,
		      sctp_connection_t * sctp_conn, vlib_buffer_t * b0,
		      u16 sctp_implied_length)
{
  sctp_init_ack_chunk_t *init_ack_chunk =
    (sctp_init_ack_chunk_t *) (sctp_hdr);
  ip4_address_t *ip4_addr = 0;
  ip6_address_t *ip6_addr = 0;
  sctp_state_cookie_param_t *state_cookie = 0;

  char hostname[FQDN_MAX_LENGTH];

  /* Stop the T1_INIT timer  */
  sctp_timer_reset (sctp_conn, SCTP_TIMER_T1_INIT);

  /* Check that the LOCALLY generated tag is being used by the REMOTE peer as the verification tag */
  if (sctp_conn->local_tag != init_ack_chunk->sctp_hdr.verification_tag)
    {
      return SCTP_ERROR_INVALID_TAG;
    }

  /*
   * It is not possible to bundle any other CHUNK with the INIT chunk
   */
  if (sctp_is_bundling (sctp_implied_length, &init_ack_chunk->chunk_hdr))
    return SCTP_ERROR_BUNDLING_VIOLATION;

  /* remote_tag to be placed in the VERIFICATION_TAG field of the COOKIE_ECHO chunk */
  sctp_conn->remote_tag = init_ack_chunk->initiate_tag;

  if (clib_net_to_host_u16 (sctp_chunk_hdr->length) >
      sizeof (sctp_init_ack_chunk_t))
    /* There are optional parameters in the INIT ACK chunk */
    {
      u16 pointer_offset = sizeof (sctp_init_ack_chunk_t);
      while (pointer_offset < clib_net_to_host_u16 (sctp_chunk_hdr->length))
	{
	  sctp_opt_params_hdr_t *opt_params_hdr =
	    (sctp_opt_params_hdr_t *) init_ack_chunk + pointer_offset;

	  switch (clib_net_to_host_u16 (opt_params_hdr->type))
	    {
	    case SCTP_IPV4_ADDRESS_TYPE:
	      {
		sctp_ipv4_addr_param_t *ipv4 =
		  (sctp_ipv4_addr_param_t *) opt_params_hdr;
		clib_memcpy (ip4_addr, &ipv4->address,
			     sizeof (ip4_address_t));
		break;
	      }
	    case SCTP_IPV6_ADDRESS_TYPE:
	      {
		sctp_ipv6_addr_param_t *ipv6 =
		  (sctp_ipv6_addr_param_t *) opt_params_hdr;
		clib_memcpy (ip6_addr, &ipv6->address,
			     sizeof (ip6_address_t));
		break;
	      }
	    case SCTP_STATE_COOKIE_TYPE:
	      {
		sctp_state_cookie_param_t *state_cookie_param =
		  (sctp_state_cookie_param_t *) opt_params_hdr;
		clib_memcpy (state_cookie, state_cookie_param,
			     sizeof (sctp_state_cookie_param_t));
		break;
	      }
	    case SCTP_HOSTNAME_ADDRESS_TYPE:
	      {
		sctp_hostname_param_t *hostname_addr =
		  (sctp_hostname_param_t *) opt_params_hdr;
		clib_memcpy (hostname, hostname_addr->hostname,
			     FQDN_MAX_LENGTH);
		break;
	      }
	    case SCTP_UNRECOGNIZED_TYPE:
	      {
		/* TODO */
		break;
	      }
	    }
	  pointer_offset += clib_net_to_host_u16 (opt_params_hdr->length);
	}
    }

  sctp_prepare_cookie_echo_chunk (sctp_conn, b0, state_cookie);

  /* Start the T1_COOKIE timer */
  sctp_timer_set (sctp_conn, SCTP_TIMER_T1_COOKIE, SCTP_RTO_INIT);

  /* Change state */
  sctp_conn->state = SCTP_STATE_COOKIE_ECHOED;

  return SCTP_ERROR_NONE;
}

always_inline u16
sctp_handle_cookie_echo (sctp_header_t * sctp_hdr,
			 sctp_chunks_common_hdr_t * sctp_chunk_hdr,
			 sctp_connection_t * sctp_conn, vlib_buffer_t * b0)
{

  /* Build TCB */

  sctp_prepare_cookie_ack_chunk (sctp_conn, b0);

  /* Change state */
  sctp_conn->state = SCTP_STATE_ESTABLISHED;

  return SCTP_ERROR_NONE;

}

always_inline u16
sctp_handle_cookie_ack (sctp_header_t * sctp_hdr,
			sctp_chunks_common_hdr_t * sctp_chunk_hdr,
			sctp_connection_t * sctp_conn, vlib_buffer_t * b0)
{

  /* Stop T1_COOKIE timer */
  sctp_timer_reset (sctp_conn, SCTP_TIMER_T1_COOKIE);

  /* Change state */
  sctp_conn->state = SCTP_STATE_ESTABLISHED;

  return SCTP_ERROR_NONE;

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
	  sctp_rx_trace_t *sctp_trace;
	  sctp_header_t *sctp_hdr = 0;
	  sctp_chunks_common_hdr_t *sctp_chunk_hdr = 0;
	  sctp_connection_t *sctp_listener;
	  ip4_header_t *ip4_hdr;
	  ip6_header_t *ip6_hdr;
	  sctp_connection_t *sctp_conn;
	  u16 sctp_implied_length = 0;
	  u16 error0 = SCTP_ERROR_NONE, next0 = SCTP_INIT_PHASE_NEXT_DROP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sctp_listener =
	    sctp_listener_get (vnet_buffer (b0)->sctp.connection_index);

	  if (is_ip4)
	    {
	      ip4_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip4_next_header (ip4_hdr);
	    }
	  else
	    {
	      ip6_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip6_next_header (ip6_hdr);
	    }

	  sctp_conn =
	    sctp_lookup_connection (sctp_listener->c_fib_index, b0,
				    my_thread_index, is_ip4);

	  if (PREDICT_FALSE (sctp_conn->state != SCTP_STATE_CLOSED))
	    {
	      error0 = SCTP_ERROR_CREATE_EXISTS;
	      goto drop;
	    }

	  /* Create child session and send INIT-ACK */
	  sctp_conn = sctp_connection_new (my_thread_index);
	  sctp_conn->c_lcl_port = sctp_hdr->dst_port;
	  sctp_conn->c_rmt_port = sctp_hdr->src_port;
	  sctp_conn->c_is_ip4 = is_ip4;

	  if (is_ip4)
	    {
	      sctp_conn->c_lcl_ip4.as_u32 = ip4_hdr->dst_address.as_u32;
	      sctp_conn->c_rmt_ip4.as_u32 = ip4_hdr->src_address.as_u32;
	    }
	  else
	    {
	      clib_memcpy (&sctp_conn->c_lcl_ip6, &ip6_hdr->dst_address,
			   sizeof (ip6_address_t));
	      clib_memcpy (&sctp_conn->c_rmt_ip6, &ip6_hdr->src_address,
			   sizeof (ip6_address_t));
	    }

	  sctp_conn->irs = vnet_buffer (b0)->sctp.seq_number;
	  sctp_conn->rcv_nxt = vnet_buffer (b0)->sctp.seq_number + 1;
	  sctp_conn->rcv_las = sctp_conn->rcv_nxt;

	  sctp_connection_init_vars (sctp_conn);

	  sctp_chunk_hdr =
	    (sctp_chunks_common_hdr_t *) (sctp_hdr + sctp_header_bytes ());

	  sctp_implied_length =
	    sctp_calculate_implied_length (ip4_hdr, ip6_hdr, is_ip4);

	  switch (clib_net_to_host_u16 (sctp_chunk_hdr->type))
	    {
	      /* Received a INIT chunk; as per protocol, do not change connection state nor allocate any resources */
	    case INIT:
	      error0 =
		sctp_handle_init (sctp_hdr, sctp_chunk_hdr, sctp_conn, b0,
				  sctp_implied_length);
	      next0 = sctp_next_output (is_ip4);
	      break;

	    case INIT_ACK:
	      error0 =
		sctp_handle_init_ack (sctp_hdr, sctp_chunk_hdr, sctp_conn,
				      b0, sctp_implied_length);
	      next0 = sctp_next_output (is_ip4);
	      break;

	    case COOKIE_ECHO:
	      error0 =
		sctp_handle_cookie_echo (sctp_hdr, sctp_chunk_hdr, sctp_conn,
					 b0);
	      next0 = sctp_next_output (is_ip4);
	      break;

	    case COOKIE_ACK:
	      error0 =
		sctp_handle_cookie_ack (sctp_hdr, sctp_chunk_hdr, sctp_conn,
					b0);
	      next0 = sctp_next_output (is_ip4);
	      break;

	    case ABORT:
	      /* TODO */
	      break;

	      /* Reception of a DATA chunk whilst in the CLOSED state is called
	       * "Out of the Blue" packet and handling of the chunk needs special treatment
	       * as per RFC4960 section 8.4
	       */
	    case DATA:
	      /* TODO */
	      break;

	      /* All UNEXPECTED scenarios (wrong chunk received per state-machine)
	       * are handled by the input-dispatcher function using the table-lookup
	       * hence we should never get to the "default" case below.
	       */
	    default:
	      error0 = SCTP_ERROR_UNKOWN_CHUNK;
	      next0 = SCTP_NEXT_DROP;
	      goto drop;
	    }

	  if (error0 != SCTP_ERROR_NONE)
	    {
	      clib_warning ("error while parsing chunk");
	      sctp_connection_cleanup (sctp_conn);
	      next0 = SCTP_NEXT_DROP;
	      goto drop;
	    }
	  if (stream_session_accept
	      (&sctp_conn->connection, sctp_listener->c_s_index,
	       0 /* notify */ ))
	    {
	      clib_warning ("session accept fail");
	      sctp_connection_cleanup (sctp_conn);
	      error0 = SCTP_ERROR_CREATE_SESSION_FAIL;
	      next0 = SCTP_NEXT_DROP;
	      goto drop;
	    }

	drop:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sctp_trace =
		vlib_add_trace (vm, node, b0, sizeof (*sctp_trace));
	      clib_memcpy (&sctp_trace->sctp_header, sctp_hdr,
			   sizeof (sctp_trace->sctp_header));
	      clib_memcpy (&sctp_trace->sctp_connection, sctp_listener,
			   sizeof (sctp_trace->sctp_connection));
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

vlib_node_registration_t sctp4_shutdown_phase_node;
vlib_node_registration_t sctp6_shutdown_phase_node;

always_inline uword
sctp46_shutdown_phase_inline (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * from_frame, int is_ip4)
{
  /*
   * DATA chunks can still be transmitted/received in the SHUTDOWN-PENDING
   * and SHUTDOWN-SENT states (as per RFC4960 Section 6)
   */
  return from_frame->n_vectors;

}

static uword
sctp4_shutdown_phase (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * from_frame)
{
  return sctp46_shutdown_phase_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
sctp6_shutdown_phase (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * from_frame)
{
  return sctp46_shutdown_phase_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp4_shutdown_phase_node) =
{
  .function = sctp4_shutdown_phase,
  .name = "sctp4-shutdown",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_SHUTDOWN_PHASE_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_SHUTDOWN_PHASE_NEXT_##s] = n,
    foreach_sctp_state_next
#undef _
  },
  .format_trace = format_sctp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp4_shutdown_phase_node,
			      sctp4_shutdown_phase);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp6_shutdown_phase_node) =
{
  .function = sctp6_shutdown_phase,
  .name = "sctp6-shutdown",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_SHUTDOWN_PHASE_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_SHUTDOWN_PHASE_NEXT_##s] = n,
    foreach_sctp_state_next
#undef _
  },
  .format_trace = format_sctp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp6_shutdown_phase_node,
			      sctp6_shutdown_phase);

vlib_node_registration_t sctp4_established_phase_node;
vlib_node_registration_t sctp6_established_phase_node;

always_inline u16
sctp_handle_data (sctp_header_t * sctp_hdr,
		  sctp_chunks_common_hdr_t * sctp_chunk_hdr,
		  sctp_connection_t * sctp_conn, vlib_buffer_t * b0)
{
  return SCTP_ERROR_NONE;
}

always_inline u16
sctp_handle_sack (sctp_header_t * sctp_hdr,
		  sctp_chunks_common_hdr_t * sctp_chunk_hdr,
		  sctp_connection_t * sctp_conn, vlib_buffer_t * b0)
{
  return SCTP_ERROR_NONE;
}

always_inline u16
sctp_handle_heartbeat (sctp_header_t * sctp_hdr,
		       sctp_chunks_common_hdr_t * chunk_hdr,
		       sctp_connection_t * sctp_conn, vlib_buffer_t * b0)
{
  return SCTP_ERROR_NONE;
}

always_inline u16
sctp_handle_heartbeat_ack (sctp_header_t * sctp_hdr,
			   sctp_chunks_common_hdr_t * chunk_hdr,
			   sctp_connection_t * sctp_conn, vlib_buffer_t * b0)
{
  return SCTP_ERROR_NONE;
}

always_inline void
sctp_node_inc_counter (vlib_main_t * vm, u32 tcp4_node, u32 tcp6_node,
		       u8 is_ip4, u8 evt, u8 val)
{
  if (PREDICT_TRUE (!val))
    return;

  if (is_ip4)
    vlib_node_increment_counter (vm, tcp4_node, evt, val);
  else
    vlib_node_increment_counter (vm, tcp6_node, evt, val);
}

always_inline uword
sctp46_established_phase_inline (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame, int is_ip4)
{

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
	  sctp_header_t *sctp_hdr = 0;
	  ip4_header_t *ip4_hdr;
	  ip6_header_t *ip6_hdr;
	  sctp_connection_t *sctp_connection;
	  u32 next0 = SCTP_ESTABLISHED_PHASE_NEXT_DROP, error0 =
	    SCTP_ERROR_ENQUEUED;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  if (is_ip4)
	    {
	      ip4_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip4_next_header (ip4_hdr);
	    }
	  else
	    {
	      ip6_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip6_next_header (ip6_hdr);
	    }

	  sctp_connection =
	    sctp_connection_get (vnet_buffer (b0)->tcp.connection_index,
				 my_thread_index);
	  if (PREDICT_FALSE (sctp_connection == 0)
	      || sctp_connection->state != SCTP_STATE_ESTABLISHED)
	    {
	      error0 = SCTP_ERROR_INVALID_CONNECTION;
	      goto drop;
	    }

	  sctp_chunks_common_hdr_t *chunk_hdr =
	    (sctp_chunks_common_hdr_t *) (sctp_hdr + sctp_header_bytes ());

	  switch (clib_net_to_host_u16 (chunk_hdr->type))
	    {
	    case DATA:
	      error0 =
		sctp_handle_data (sctp_hdr, chunk_hdr, sctp_connection, b0);
	      next0 = sctp_next_output (is_ip4);
	      break;

	    case SACK:
	      error0 =
		sctp_handle_sack (sctp_hdr, chunk_hdr, sctp_connection, b0);
	      next0 = sctp_next_output (is_ip4);
	      break;

	    case HEARTBEAT:
	      error0 =
		sctp_handle_heartbeat (sctp_hdr, chunk_hdr, sctp_connection,
				       b0);
	      next0 = sctp_next_output (is_ip4);
	      break;

	    case HEARTBEAT_ACK:
	      error0 =
		sctp_handle_heartbeat_ack (sctp_hdr, chunk_hdr,
					   sctp_connection, b0);
	      next0 = sctp_next_output (is_ip4);
	      break;

	      /* All UNEXPECTED scenarios (wrong chunk received per state-machine)
	       * are handled by the input-dispatcher function using the table-lookup
	       * hence we should never get to the "default" case below.
	       */
	    default:
	      error0 = SCTP_ERROR_UNKOWN_CHUNK;
	      next0 = SCTP_NEXT_DROP;
	      goto drop;
	    }

	drop:
	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sctp_rx_trace_t *t0 =
		vlib_add_trace (vm, node, b0, sizeof (*t0));
	      sctp_set_rx_trace_data (t0, sctp_connection, sctp_hdr, b0,
				      is_ip4);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

    }
  errors = session_manager_flush_enqueue_events (TRANSPORT_PROTO_SCTP,
						 my_thread_index);

  sctp_node_inc_counter (vm, is_ip4, sctp4_established_phase_node.index,
			 sctp6_established_phase_node.index,
			 SCTP_ERROR_EVENT_FIFO_FULL, errors);

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
VLIB_REGISTER_NODE (sctp4_established_phase_node) =
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

VLIB_NODE_FUNCTION_MULTIARCH (sctp4_established_phase_node,
			      sctp4_established_phase);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp6_established_phase_node) =
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

VLIB_NODE_FUNCTION_MULTIARCH (sctp6_established_phase_node,
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
  u8 is_filtered;
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
	  sctp_header_t *sctp_hdr = 0;
	  sctp_chunks_common_hdr_t *sctp_chunk_hdr = 0;
	  sctp_connection_t *sctp_conn;
	  transport_connection_t *tconn;
	  ip4_header_t *ip4_hdr;
	  ip6_header_t *ip6_hdr;
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
	      ip4_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip4_next_header (ip4_hdr);
	      sctp_chunk_hdr =
		(sctp_chunks_common_hdr_t *) (sctp_hdr +
					      sctp_header_bytes ());
	      n_advance_bytes0 =
		(ip4_header_bytes (ip4_hdr) + sctp_header_bytes ());
	      n_data_bytes0 =
		clib_net_to_host_u16 (ip4_hdr->length) - n_advance_bytes0;
	      tconn =
		session_lookup_connection_wt4 (fib_index0,
					       &ip4_hdr->dst_address,
					       &ip4_hdr->src_address,
					       sctp_hdr->dst_port,
					       sctp_hdr->src_port,
					       TRANSPORT_PROTO_SCTP,
					       my_thread_index, &is_filtered);
	      sctp_conn = sctp_get_connection_from_transport (tconn);
	      ASSERT (sctp_lookup_is_valid (sctp_conn, sctp_hdr));
	    }
	  else
	    {
	      ip6_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip6_next_header (ip6_hdr);
	      sctp_chunk_hdr =
		(sctp_chunks_common_hdr_t *) (sctp_hdr +
					      sctp_header_bytes ());
	      n_advance_bytes0 = sctp_header_bytes ();
	      n_data_bytes0 =
		clib_net_to_host_u16 (ip6_hdr->payload_length) -
		n_advance_bytes0;
	      n_advance_bytes0 += sizeof (ip6_hdr[0]);
	      tconn = session_lookup_connection_wt6 (fib_index0,
						     &ip6_hdr->dst_address,
						     &ip6_hdr->src_address,
						     sctp_hdr->dst_port,
						     sctp_hdr->src_port,
						     TRANSPORT_PROTO_SCTP,
						     my_thread_index,
						     &is_filtered);
	      sctp_conn = sctp_get_connection_from_transport (tconn);
	      ASSERT (sctp_lookup_is_valid (sctp_conn, sctp_hdr));
	    }

	  /* Length check */
	  if (PREDICT_FALSE (n_advance_bytes0 < 0))
	    {
	      error0 = SCTP_ERROR_LENGTH;
	      goto done;
	    }

	  /* Session exists */
	  if (PREDICT_TRUE (0 != sctp_conn))
	    {
	      /* Save connection index */
	      vnet_buffer (b0)->sctp.connection_index = sctp_conn->c_c_index;

	      vnet_buffer (b0)->sctp.hdr_offset =
		(u8 *) sctp_hdr - (u8 *) vlib_buffer_get_current (b0);
	      vnet_buffer (b0)->sctp.data_offset = n_advance_bytes0;
	      vnet_buffer (b0)->sctp.data_len = n_data_bytes0;

	      next0 =
		tm->dispatch_table[sctp_conn->state][sctp_chunk_hdr->
						     type].next;
	      error0 =
		tm->dispatch_table[sctp_conn->state][sctp_chunk_hdr->
						     type].error;

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
	      sctp_set_rx_trace_data (t0, sctp_conn, sctp_hdr, b0, is_ip4);
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

  /*
   * SCTP STATE-MACHINE states:
   *
   * _(CLOSED, "CLOSED")                         \
   * _(COOKIE_WAIT, "COOKIE_WAIT")               \
   * _(COOKIE_ECHOED, "COOKIE_ECHOED")           \
   * _(ESTABLISHED, "ESTABLISHED")               \
   * _(SHUTDOWN_PENDING, "SHUTDOWN_PENDING")     \
   * _(SHUTDOWN_SENT, "SHUTDOWN_SENT")           \
   * _(SHUTDOWN_RECEIVED, "SHUTDOWN_RECEIVED")   \
   * _(SHUTDOWN_ACK_SENT, "SHUTDOWN_ACK_SENT")
   */
  _(CLOSED, DATA, SCTP_INPUT_NEXT_INIT_PHASE, SCTP_ERROR_NONE);	/* UNEXPECTED DATA chunk which requires special handling */
  _(CLOSED, INIT, SCTP_INPUT_NEXT_INIT_PHASE, SCTP_ERROR_NONE);
  _(CLOSED, INIT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED INIT_ACK chunk */
  _(CLOSED, SACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SACK_CHUNK_VIOLATION);	/* UNEXPECTED SACK chunk */
  _(CLOSED, HEARTBEAT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT chunk */
  _(CLOSED, HEARTBEAT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_ACK_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT_ACK chunk */
  _(CLOSED, ABORT, SCTP_INPUT_NEXT_INIT_PHASE, SCTP_ERROR_NONE);
  _(CLOSED, SHUTDOWN, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN chunk */
  _(CLOSED, SHUTDOWN_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_ACK_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN_ACK chunk */
  _(CLOSED, OPERATION_ERROR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_OPERATION_ERROR_VIOLATION);	/* UNEXPECTED OPERATION_ERROR chunk */
  _(CLOSED, COOKIE_ECHO, SCTP_INPUT_NEXT_INIT_PHASE, SCTP_ERROR_NONE);
  _(CLOSED, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(CLOSED, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(CLOSED, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(CLOSED, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */

  _(COOKIE_WAIT, DATA, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_NONE);
  _(COOKIE_WAIT, INIT, SCTP_INPUT_NEXT_INIT_PHASE, SCTP_ERROR_NONE);	/* UNEXPECTED INIT chunk which requires special handling */
  _(COOKIE_WAIT, INIT_ACK, SCTP_INPUT_NEXT_INIT_PHASE, SCTP_ERROR_NONE);
  _(COOKIE_WAIT, SACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SACK_CHUNK_VIOLATION);	/* UNEXPECTED SACK chunk */
  _(COOKIE_WAIT, HEARTBEAT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT chunk */
  _(COOKIE_WAIT, HEARTBEAT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_ACK_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT_ACK chunk */
  _(COOKIE_WAIT, ABORT, SCTP_INPUT_NEXT_INIT_PHASE, SCTP_ERROR_NONE);
  _(COOKIE_WAIT, SHUTDOWN, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN chunk */
  _(COOKIE_WAIT, SHUTDOWN_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_ACK_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN_ACK chunk */
  _(COOKIE_WAIT, OPERATION_ERROR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_OPERATION_ERROR_VIOLATION);	/* UNEXPECTED OPERATION_ERROR chunk */
  _(COOKIE_WAIT, COOKIE_ECHO, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_COOKIE_ECHO_VIOLATION);	/* UNEXPECTED COOKIE_ECHO chunk */
  _(COOKIE_WAIT, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(COOKIE_WAIT, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(COOKIE_WAIT, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(COOKIE_WAIT, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */

  _(COOKIE_ECHOED, DATA, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_NONE);
  _(COOKIE_ECHOED, INIT, SCTP_INPUT_NEXT_INIT_PHASE, SCTP_ERROR_NONE);	/* UNEXPECTED INIT chunk which requires special handling */
  _(COOKIE_ECHOED, INIT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED INIT_ACK chunk */
  _(COOKIE_ECHOED, SACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SACK_CHUNK_VIOLATION);	/* UNEXPECTED SACK chunk */
  _(COOKIE_ECHOED, HEARTBEAT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT chunk */
  _(COOKIE_ECHOED, HEARTBEAT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_ACK_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT_ACK chunk */
  _(COOKIE_ECHOED, ABORT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ABORT_CHUNK_VIOLATION);	/* UNEXPECTED ABORT chunk */
  _(COOKIE_ECHOED, SHUTDOWN, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN chunk */
  _(COOKIE_ECHOED, SHUTDOWN_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_ACK_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN_ACK chunk */
  _(COOKIE_ECHOED, OPERATION_ERROR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_OPERATION_ERROR_VIOLATION);	/* UNEXPECTED OPERATION_ERROR chunk */
  _(COOKIE_ECHOED, COOKIE_ECHO, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_COOKIE_ECHO_VIOLATION);	/* UNEXPECTED COOKIE_ECHO chunk */
  _(COOKIE_ECHOED, COOKIE_ACK, SCTP_INPUT_NEXT_INIT_PHASE, SCTP_ERROR_NONE);
  _(COOKIE_ECHOED, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(COOKIE_ECHOED, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(COOKIE_ECHOED, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */

  _(ESTABLISHED, DATA, SCTP_INPUT_NEXT_ESTABLISHED_PHASE, SCTP_ERROR_NONE);
  _(ESTABLISHED, INIT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_INIT_CHUNK_VIOLATION);	/* UNEXPECTED INIT chunk */
  _(ESTABLISHED, INIT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED INIT_ACK chunk */
  _(ESTABLISHED, SACK, SCTP_INPUT_NEXT_ESTABLISHED_PHASE, SCTP_ERROR_NONE);
  _(ESTABLISHED, HEARTBEAT, SCTP_INPUT_NEXT_ESTABLISHED_PHASE,
    SCTP_ERROR_NONE);
  _(ESTABLISHED, HEARTBEAT_ACK, SCTP_INPUT_NEXT_ESTABLISHED_PHASE,
    SCTP_ERROR_NONE);
  _(ESTABLISHED, ABORT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ABORT_CHUNK_VIOLATION);	/* UNEXPECTED ABORT chunk */
  _(ESTABLISHED, SHUTDOWN, SCTP_INPUT_NEXT_SHUTDOWN_PHASE, SCTP_ERROR_NONE);
  _(ESTABLISHED, SHUTDOWN_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_ACK_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN_ACK chunk */
  _(ESTABLISHED, OPERATION_ERROR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_OPERATION_ERROR_VIOLATION);	/* UNEXPECTED OPERATION_ERROR chunk */
  _(ESTABLISHED, COOKIE_ECHO, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_COOKIE_ECHO_VIOLATION);	/* UNEXPECTED COOKIE_ECHO chunk */
  _(ESTABLISHED, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(ESTABLISHED, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(ESTABLISHED, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(ESTABLISHED, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */

  _(SHUTDOWN_PENDING, DATA, SCTP_INPUT_NEXT_SHUTDOWN_PHASE, SCTP_ERROR_NONE);
  _(SHUTDOWN_PENDING, INIT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_INIT_CHUNK_VIOLATION);	/* UNEXPECTED INIT chunk */
  _(SHUTDOWN_PENDING, INIT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED INIT_ACK chunk */
  _(SHUTDOWN_PENDING, SACK, SCTP_INPUT_NEXT_ESTABLISHED_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_PENDING, HEARTBEAT, SCTP_INPUT_NEXT_ESTABLISHED_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_PENDING, HEARTBEAT_ACK, SCTP_INPUT_NEXT_ESTABLISHED_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_PENDING, ABORT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ABORT_CHUNK_VIOLATION);	/* UNEXPECTED ABORT chunk */
  _(SHUTDOWN_PENDING, SHUTDOWN, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_PENDING, SHUTDOWN_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_ACK_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN_ACK chunk */
  _(SHUTDOWN_PENDING, OPERATION_ERROR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_OPERATION_ERROR_VIOLATION);	/* UNEXPECTED OPERATION_ERROR chunk */
  _(SHUTDOWN_PENDING, COOKIE_ECHO, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_COOKIE_ECHO_VIOLATION);	/* UNEXPECTED COOKIE_ECHO chunk */
  _(SHUTDOWN_PENDING, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(SHUTDOWN_PENDING, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(SHUTDOWN_PENDING, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(SHUTDOWN_PENDING, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */

  _(SHUTDOWN_SENT, DATA, SCTP_INPUT_NEXT_SHUTDOWN_PHASE, SCTP_ERROR_NONE);
  _(SHUTDOWN_SENT, INIT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_INIT_CHUNK_VIOLATION);	/* UNEXPECTED INIT chunk */
  _(SHUTDOWN_SENT, INIT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED INIT_ACK chunk */
  _(SHUTDOWN_SENT, SACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SACK_CHUNK_VIOLATION);	/* UNEXPECTED SACK chunk */
  _(SHUTDOWN_SENT, HEARTBEAT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT chunk */
  _(SHUTDOWN_SENT, HEARTBEAT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_ACK_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT_ACK chunk */
  _(SHUTDOWN_SENT, ABORT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ABORT_CHUNK_VIOLATION);	/* UNEXPECTED ABORT chunk */
  _(SHUTDOWN_SENT, SHUTDOWN, SCTP_INPUT_NEXT_SHUTDOWN_PHASE, SCTP_ERROR_NONE);
  _(SHUTDOWN_SENT, SHUTDOWN_ACK, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_SENT, COOKIE_ECHO, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_COOKIE_ECHO_VIOLATION);	/* UNEXPECTED COOKIE_ECHO chunk */
  _(SHUTDOWN_SENT, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(SHUTDOWN_SENT, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(SHUTDOWN_SENT, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(SHUTDOWN_SENT, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */

  _(SHUTDOWN_RECEIVED, DATA, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_DATA_CHUNK_VIOLATION);	/* UNEXPECTED DATA chunk */
  _(SHUTDOWN_RECEIVED, INIT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_INIT_CHUNK_VIOLATION);	/* UNEXPECTED INIT chunk */
  _(SHUTDOWN_RECEIVED, INIT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED INIT_ACK chunk */
  _(SHUTDOWN_RECEIVED, SACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SACK_CHUNK_VIOLATION);	/* UNEXPECTED INIT chunk */
  _(SHUTDOWN_RECEIVED, HEARTBEAT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT chunk */
  _(SHUTDOWN_RECEIVED, HEARTBEAT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_ACK_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT_ACK chunk */
  _(SHUTDOWN_RECEIVED, ABORT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ABORT_CHUNK_VIOLATION);	/* UNEXPECTED ABORT chunk */
  _(SHUTDOWN_RECEIVED, SHUTDOWN, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN chunk */
  _(SHUTDOWN_RECEIVED, SHUTDOWN_ACK, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_RECEIVED, COOKIE_ECHO, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_COOKIE_ECHO_VIOLATION);	/* UNEXPECTED COOKIE_ECHO chunk */
  _(SHUTDOWN_RECEIVED, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(SHUTDOWN_RECEIVED, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(SHUTDOWN_RECEIVED, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(SHUTDOWN_RECEIVED, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */

  _(SHUTDOWN_ACK_SENT, DATA, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_DATA_CHUNK_VIOLATION);	/* UNEXPECTED DATA chunk */
  _(SHUTDOWN_ACK_SENT, INIT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_INIT_CHUNK_VIOLATION);	/* UNEXPECTED INIT chunk */
  _(SHUTDOWN_ACK_SENT, INIT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED INIT_ACK chunk */
  _(SHUTDOWN_ACK_SENT, SACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SACK_CHUNK_VIOLATION);	/* UNEXPECTED INIT chunk */
  _(SHUTDOWN_ACK_SENT, HEARTBEAT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT chunk */
  _(SHUTDOWN_ACK_SENT, HEARTBEAT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_ACK_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT_ACK chunk */
  _(SHUTDOWN_ACK_SENT, ABORT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ABORT_CHUNK_VIOLATION);	/* UNEXPECTED ABORT chunk */
  _(SHUTDOWN_ACK_SENT, SHUTDOWN, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN chunk */
  _(SHUTDOWN_ACK_SENT, SHUTDOWN_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_ACK_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN_ACK chunk */
  _(SHUTDOWN_ACK_SENT, COOKIE_ECHO, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_COOKIE_ECHO_VIOLATION);	/* UNEXPECTED COOKIE_ECHO chunk */
  _(SHUTDOWN_ACK_SENT, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(SHUTDOWN_ACK_SENT, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(SHUTDOWN_ACK_SENT, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(SHUTDOWN_ACK_SENT, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);

  /* TODO: Handle COOKIE ECHO when a TCB Exists */

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
