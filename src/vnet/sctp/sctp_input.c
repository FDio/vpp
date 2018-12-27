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
  _ (DROP4, "ip4-drop")                         \
  _ (DROP6, "ip6-drop")                         \
  _ (SCTP4_OUTPUT, "sctp4-output")                \
  _ (SCTP6_OUTPUT, "sctp6-output")

typedef enum _sctp_established_phase_next
{
#define _(s,n) SCTP_ESTABLISHED_PHASE_NEXT_##s,
  foreach_sctp_state_next
#undef _
    SCTP_ESTABLISHED_PHASE_N_NEXT,
} sctp_established_phase_next_t;

typedef enum _sctp_rcv_phase_next
{
#define _(s,n) SCTP_RCV_PHASE_NEXT_##s,
  foreach_sctp_state_next
#undef _
    SCTP_RCV_PHASE_N_NEXT,
} sctp_rcv_phase_next_t;

typedef enum _sctp_listen_phase_next
{
#define _(s,n) SCTP_LISTEN_PHASE_NEXT_##s,
  foreach_sctp_state_next
#undef _
    SCTP_LISTEN_PHASE_N_NEXT,
} sctp_listen_phase_next_t;

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
  SCTP_INPUT_NEXT_LISTEN_PHASE,
  SCTP_INPUT_NEXT_RCV_PHASE,
  SCTP_INPUT_NEXT_ESTABLISHED_PHASE,
  SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
  SCTP_INPUT_NEXT_PUNT_PHASE,
  SCTP_INPUT_N_NEXT
} sctp_input_next_t;

char *
phase_to_string (u8 phase)
{
  switch (phase)
    {
    case SCTP_INPUT_NEXT_DROP:
      return "SCTP_INPUT_NEXT_DROP";
    case SCTP_INPUT_NEXT_LISTEN_PHASE:
      return "SCTP_INPUT_NEXT_LISTEN_PHASE";
    case SCTP_INPUT_NEXT_RCV_PHASE:
      return "SCTP_INPUT_NEXT_RCV_PHASE";
    case SCTP_INPUT_NEXT_ESTABLISHED_PHASE:
      return "SCTP_INPUT_NEXT_ESTABLISHED_PHASE";
    case SCTP_INPUT_NEXT_SHUTDOWN_PHASE:
      return "SCTP_INPUT_NEXT_SHUTDOWN_PHASE";
    case SCTP_INPUT_NEXT_PUNT_PHASE:
      return "SCTP_INPUT_NEXT_PUNT_PHASE";
    }
  return NULL;
}

#define foreach_sctp4_input_next                 \
  _ (DROP, "error-drop")                         \
  _ (RCV_PHASE, "sctp4-rcv")                    \
  _ (LISTEN_PHASE, "sctp4-listen")     	 \
  _ (ESTABLISHED_PHASE, "sctp4-established")     	 \
  _ (SHUTDOWN_PHASE, "sctp4-shutdown")	\
  _ (PUNT_PHASE, "ip4-punt")


#define foreach_sctp6_input_next                 \
  _ (DROP, "error-drop")                         \
  _ (RCV_PHASE, "sctp6-rcv")                    \
  _ (LISTEN_PHASE, "sctp6-listen")     	 \
  _ (ESTABLISHED_PHASE, "sctp6-established")     	 \
  _ (SHUTDOWN_PHASE, "sctp6-shutdown")		\
  _ (PUNT_PHASE, "ip6-punt")

static u8
sctp_lookup_is_valid (transport_connection_t * trans_conn,
		      sctp_header_t * sctp_hdr)
{
  sctp_connection_t *sctp_conn =
    sctp_get_connection_from_transport (trans_conn);

  if (!sctp_conn)
    return 1;

  u8 is_valid = (trans_conn->lcl_port == sctp_hdr->dst_port
		 && (sctp_conn->state == SCTP_STATE_CLOSED
		     || trans_conn->rmt_port == sctp_hdr->src_port));

  return is_valid;
}

/**
 * Lookup transport connection
 */
static sctp_connection_t *
sctp_lookup_connection (u32 fib_index, vlib_buffer_t * b, u8 thread_index,
			u8 is_ip4)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  sctp_header_t *sctp_hdr;
  transport_connection_t *trans_conn;
  sctp_connection_t *sctp_conn;
  u8 is_filtered, i;
  if (is_ip4)
    {
      ip4_header_t *ip4_hdr;
      ip4_hdr = vlib_buffer_get_current (b);
      sctp_hdr = ip4_next_header (ip4_hdr);
      trans_conn = session_lookup_connection_wt4 (fib_index,
						  &ip4_hdr->dst_address,
						  &ip4_hdr->src_address,
						  sctp_hdr->dst_port,
						  sctp_hdr->src_port,
						  TRANSPORT_PROTO_SCTP,
						  thread_index, &is_filtered);
      if (trans_conn == 0)	/* Not primary connection */
	{
	  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
	    {
	      if ((tm->connections[thread_index]->sub_conn[i].
		   connection.lcl_ip.ip4.as_u32 ==
		   ip4_hdr->dst_address.as_u32)
		  && (tm->connections[thread_index]->sub_conn[i].
		      connection.rmt_ip.ip4.as_u32 ==
		      ip4_hdr->src_address.as_u32))
		{
		  trans_conn =
		    &tm->connections[thread_index]->sub_conn[i].connection;
		  break;
		}
	    }
	}
      ASSERT (trans_conn != 0);
      ASSERT (sctp_lookup_is_valid (trans_conn, sctp_hdr));
    }
  else
    {
      ip6_header_t *ip6_hdr;
      ip6_hdr = vlib_buffer_get_current (b);
      sctp_hdr = ip6_next_header (ip6_hdr);
      trans_conn = session_lookup_connection_wt6 (fib_index,
						  &ip6_hdr->dst_address,
						  &ip6_hdr->src_address,
						  sctp_hdr->dst_port,
						  sctp_hdr->src_port,
						  TRANSPORT_PROTO_SCTP,
						  thread_index, &is_filtered);
      if (trans_conn == 0)	/* Not primary connection */
	{
	  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
	    {
	      if ((tm->connections[thread_index]->sub_conn[i].
		   connection.lcl_ip.ip6.as_u64[0] ==
		   ip6_hdr->dst_address.as_u64[0]
		   && tm->connections[thread_index]->sub_conn[i].
		   connection.lcl_ip.ip6.as_u64[1] ==
		   ip6_hdr->dst_address.as_u64[1])
		  && (tm->connections[thread_index]->sub_conn[i].
		      connection.rmt_ip.ip6.as_u64[0] ==
		      ip6_hdr->src_address.as_u64[0]
		      && tm->connections[thread_index]->
		      sub_conn[i].connection.rmt_ip.ip6.as_u64[1] ==
		      ip6_hdr->src_address.as_u64[1]))
		{
		  trans_conn =
		    &tm->connections[thread_index]->sub_conn[i].connection;
		  break;
		}
	    }
	}
      ASSERT (trans_conn != 0);
      ASSERT (sctp_lookup_is_valid (trans_conn, sctp_hdr));
    }
  sctp_conn = sctp_get_connection_from_transport (trans_conn);
  return sctp_conn;
}

typedef struct
{
  sctp_header_t sctp_header;
  sctp_connection_t sctp_connection;
} sctp_rx_trace_t;

#define sctp_next_output(is_ip4) (is_ip4 ? SCTP_NEXT_SCTP4_OUTPUT          \
                                        : SCTP_NEXT_SCTP6_OUTPUT)

#define sctp_next_drop(is_ip4) (is_ip4 ? SCTP_NEXT_DROP4                  \
                                      : SCTP_NEXT_DROP6)

void
sctp_set_rx_trace_data (sctp_rx_trace_t * rx_trace,
			sctp_connection_t * sctp_conn,
			sctp_header_t * sctp_hdr, vlib_buffer_t * b0,
			u8 is_ip4)
{
  if (sctp_conn)
    {
      clib_memcpy_fast (&rx_trace->sctp_connection, sctp_conn,
			sizeof (rx_trace->sctp_connection));
    }
  else
    {
      sctp_hdr = sctp_buffer_hdr (b0);
    }
  clib_memcpy_fast (&rx_trace->sctp_header, sctp_hdr,
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

always_inline u16
sctp_handle_operation_err (sctp_header_t * sctp_hdr,
			   sctp_connection_t * sctp_conn, u8 idx,
			   vlib_buffer_t * b, u16 * next0)
{
  sctp_operation_error_t *op_err = (sctp_operation_error_t *) sctp_hdr;

  /* Check that the LOCALLY generated tag is being used by the REMOTE peer as the verification tag */
  if (sctp_conn->local_tag != sctp_hdr->verification_tag)
    {
      return SCTP_ERROR_INVALID_TAG;
    }

  if (clib_net_to_host_u16 (op_err->err_causes[0].param_hdr.type) ==
      STALE_COOKIE_ERROR)
    {
      if (sctp_conn->state != SCTP_STATE_COOKIE_ECHOED)
	*next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);
      else
	{
	  sctp_connection_cleanup (sctp_conn);

	  session_transport_closing_notify (&sctp_conn->
					    sub_conn[idx].connection);
	}
    }

  return SCTP_ERROR_NONE;
}

always_inline u16
sctp_handle_init (sctp_header_t * sctp_hdr,
		  sctp_chunks_common_hdr_t * sctp_chunk_hdr,
		  sctp_connection_t * sctp_conn, vlib_buffer_t * b0,
		  u16 sctp_implied_length)
{
  sctp_init_chunk_t *init_chunk = (sctp_init_chunk_t *) (sctp_hdr);
  ip4_address_t ip4_addr;
  ip6_address_t ip6_addr;
  u8 add_ip4 = 0;
  u8 add_ip6 = 0;
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
	case SCTP_STATE_COOKIE_WAIT:
	  SCTP_ADV_DBG ("Received INIT chunk while in COOKIE_WAIT state");
	  sctp_prepare_initack_chunk_for_collision (sctp_conn,
						    SCTP_PRIMARY_PATH_IDX,
						    b0, &ip4_addr, &ip6_addr);
	  return SCTP_ERROR_NONE;
	case SCTP_STATE_COOKIE_ECHOED:
	case SCTP_STATE_SHUTDOWN_ACK_SENT:
	  SCTP_ADV_DBG ("Received INIT chunk while in COOKIE_ECHOED state");
	  if (sctp_conn->forming_association_changed == 0)
	    sctp_prepare_initack_chunk_for_collision (sctp_conn,
						      SCTP_PRIMARY_PATH_IDX,
						      b0, &ip4_addr,
						      &ip6_addr);
	  else
	    sctp_prepare_abort_for_collision (sctp_conn,
					      SCTP_PRIMARY_PATH_IDX, b0,
					      &ip4_addr, &ip6_addr);
	  return SCTP_ERROR_NONE;
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
  sctp_conn->remote_initial_tsn =
    clib_net_to_host_u32 (init_chunk->initial_tsn);
  sctp_conn->last_rcvd_tsn = sctp_conn->remote_initial_tsn;
  sctp_conn->next_tsn_expected = sctp_conn->remote_initial_tsn + 1;
  SCTP_CONN_TRACKING_DBG ("sctp_conn->remote_initial_tsn = %u",
			  sctp_conn->remote_initial_tsn);

  sctp_conn->peer_rwnd = clib_net_to_host_u32 (init_chunk->a_rwnd);
  /*
   * If the length specified in the INIT message is bigger than the size in bytes of our structure it means that
   * optional parameters have been sent with the INIT chunk and we need to parse them.
   */
  u16 length = vnet_sctp_get_chunk_length (sctp_chunk_hdr);
  if (length > sizeof (sctp_init_chunk_t))
    {
      /* There are optional parameters in the INIT chunk */
      u16 pointer_offset = sizeof (sctp_init_chunk_t);
      while (pointer_offset < length)
	{
	  sctp_opt_params_hdr_t *opt_params_hdr =
	    (sctp_opt_params_hdr_t *) init_chunk + pointer_offset;

	  switch (clib_net_to_host_u16 (opt_params_hdr->type))
	    {
	    case SCTP_IPV4_ADDRESS_TYPE:
	      {
		sctp_ipv4_addr_param_t *ipv4 =
		  (sctp_ipv4_addr_param_t *) opt_params_hdr;
		clib_memcpy_fast (&ip4_addr, &ipv4->address,
				  sizeof (ip4_address_t));

		if (sctp_sub_connection_add_ip4 (vlib_get_main (),
						 &sctp_conn->sub_conn
						 [SCTP_PRIMARY_PATH_IDX].connection.
						 lcl_ip.ip4,
						 &ipv4->address) ==
		    SCTP_ERROR_NONE)
		  add_ip4 = 1;

		break;
	      }
	    case SCTP_IPV6_ADDRESS_TYPE:
	      {
		sctp_ipv6_addr_param_t *ipv6 =
		  (sctp_ipv6_addr_param_t *) opt_params_hdr;
		clib_memcpy_fast (&ip6_addr, &ipv6->address,
				  sizeof (ip6_address_t));

		if (sctp_sub_connection_add_ip6 (vlib_get_main (),
						 &sctp_conn->sub_conn
						 [SCTP_PRIMARY_PATH_IDX].connection.
						 lcl_ip.ip6,
						 &ipv6->address) ==
		    SCTP_ERROR_NONE)
		  add_ip6 = 1;

		break;
	      }
	    case SCTP_COOKIE_PRESERVATIVE_TYPE:
	      {
		sctp_cookie_preservative_param_t *cookie_pres =
		  (sctp_cookie_preservative_param_t *) opt_params_hdr;
		sctp_conn->peer_cookie_life_span_increment =
		  cookie_pres->life_span_inc;
		break;
	      }
	    case SCTP_HOSTNAME_ADDRESS_TYPE:
	      {
		sctp_hostname_param_t *hostname_addr =
		  (sctp_hostname_param_t *) opt_params_hdr;
		clib_memcpy_fast (hostname, hostname_addr->hostname,
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
  sctp_prepare_initack_chunk (sctp_conn, SCTP_PRIMARY_PATH_IDX, b0, &ip4_addr,
			      add_ip4, &ip6_addr, add_ip6);
  return SCTP_ERROR_NONE;
}

always_inline u16
sctp_is_valid_init_ack (sctp_header_t * sctp_hdr,
			sctp_chunks_common_hdr_t * sctp_chunk_hdr,
			sctp_connection_t * sctp_conn, vlib_buffer_t * b0,
			u16 sctp_implied_length)
{
  sctp_init_ack_chunk_t *init_ack_chunk =
    (sctp_init_ack_chunk_t *) (sctp_hdr);

  /* Check that the LOCALLY generated tag is being used by the REMOTE peer as the verification tag */
  if (sctp_conn->local_tag != init_ack_chunk->sctp_hdr.verification_tag)
    {
      return SCTP_ERROR_INVALID_TAG;
    }

  /*
   * It is not possible to bundle any other CHUNK with the INIT_ACK chunk
   */
  if (sctp_is_bundling (sctp_implied_length, &init_ack_chunk->chunk_hdr))
    return SCTP_ERROR_BUNDLING_VIOLATION;

  return SCTP_ERROR_NONE;
}

always_inline u16
sctp_handle_init_ack (sctp_header_t * sctp_hdr,
		      sctp_chunks_common_hdr_t * sctp_chunk_hdr,
		      sctp_connection_t * sctp_conn, u8 idx,
		      vlib_buffer_t * b0, u16 sctp_implied_length)
{
  sctp_init_ack_chunk_t *init_ack_chunk =
    (sctp_init_ack_chunk_t *) (sctp_hdr);

  char hostname[FQDN_MAX_LENGTH];

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

  /* Stop the T1_INIT timer */
  sctp_timer_reset (sctp_conn, idx, SCTP_TIMER_T1_INIT);

  sctp_calculate_rto (sctp_conn, idx);

  /* remote_tag to be placed in the VERIFICATION_TAG field of the COOKIE_ECHO chunk */
  sctp_conn->remote_tag = init_ack_chunk->initiate_tag;
  sctp_conn->remote_initial_tsn =
    clib_net_to_host_u32 (init_ack_chunk->initial_tsn);
  sctp_conn->last_rcvd_tsn = sctp_conn->remote_initial_tsn;
  sctp_conn->next_tsn_expected = sctp_conn->remote_initial_tsn + 1;
  SCTP_CONN_TRACKING_DBG ("sctp_conn->remote_initial_tsn = %u",
			  sctp_conn->remote_initial_tsn);
  sctp_conn->peer_rwnd = clib_net_to_host_u32 (init_ack_chunk->a_rwnd);

  u16 length = vnet_sctp_get_chunk_length (sctp_chunk_hdr);

  if (length > sizeof (sctp_init_ack_chunk_t))
    /*
     * There are optional parameters in the INIT ACK chunk
     */
    {
      u16 pointer_offset = sizeof (sctp_init_ack_chunk_t);

      while (pointer_offset < length)
	{
	  sctp_opt_params_hdr_t *opt_params_hdr =
	    (sctp_opt_params_hdr_t *) ((char *) init_ack_chunk +
				       pointer_offset);

	  switch (clib_net_to_host_u16 (opt_params_hdr->type))
	    {
	    case SCTP_IPV4_ADDRESS_TYPE:
	      {
		sctp_ipv4_addr_param_t *ipv4 =
		  (sctp_ipv4_addr_param_t *) opt_params_hdr;

		sctp_sub_connection_add_ip4 (vlib_get_main (),
					     &sctp_conn->sub_conn
					     [SCTP_PRIMARY_PATH_IDX].connection.
					     lcl_ip.ip4, &ipv4->address);

		break;
	      }
	    case SCTP_IPV6_ADDRESS_TYPE:
	      {
		sctp_ipv6_addr_param_t *ipv6 =
		  (sctp_ipv6_addr_param_t *) opt_params_hdr;

		sctp_sub_connection_add_ip6 (vlib_get_main (),
					     &sctp_conn->sub_conn
					     [SCTP_PRIMARY_PATH_IDX].connection.
					     lcl_ip.ip6, &ipv6->address);

		break;
	      }
	    case SCTP_STATE_COOKIE_TYPE:
	      {
		sctp_state_cookie_param_t *state_cookie_param =
		  (sctp_state_cookie_param_t *) opt_params_hdr;

		clib_memcpy_fast (&(sctp_conn->cookie_param),
				  state_cookie_param,
				  sizeof (sctp_state_cookie_param_t));

		break;
	      }
	    case SCTP_HOSTNAME_ADDRESS_TYPE:
	      {
		sctp_hostname_param_t *hostname_addr =
		  (sctp_hostname_param_t *) opt_params_hdr;
		clib_memcpy_fast (hostname, hostname_addr->hostname,
				  FQDN_MAX_LENGTH);
		break;
	      }
	    case SCTP_UNRECOGNIZED_TYPE:
	      {
		break;
	      }
	    }
	  u16 increment = clib_net_to_host_u16 (opt_params_hdr->length);
	  /* This indicates something really bad happened */
	  if (increment == 0)
	    {
	      return SCTP_ERROR_INVALID_TAG;
	    }
	  pointer_offset += increment;
	}
    }

  sctp_prepare_cookie_echo_chunk (sctp_conn, idx, b0, 1);

  /* Start the T1_COOKIE timer */
  sctp_timer_set (sctp_conn, idx,
		  SCTP_TIMER_T1_COOKIE, sctp_conn->sub_conn[idx].RTO);

  return SCTP_ERROR_NONE;
}

/** Enqueue data out-of-order for delivery to application */
always_inline int
sctp_session_enqueue_data_ooo (sctp_connection_t * sctp_conn,
			       vlib_buffer_t * b, u16 data_len, u8 conn_idx)
{
  int written, error = SCTP_ERROR_ENQUEUED;

  written =
    session_enqueue_stream_connection (&sctp_conn->
				       sub_conn[conn_idx].connection, b, 0,
				       1 /* queue event */ ,
				       0);

  /* Update next_tsn_expected */
  if (PREDICT_TRUE (written == data_len))
    {
      sctp_conn->next_tsn_expected += written;

      SCTP_ADV_DBG ("CONN = %u, WRITTEN [%u] == DATA_LEN [%d]",
		    sctp_conn->sub_conn[conn_idx].connection.c_index,
		    written, data_len);
    }
  /* If more data written than expected, account for out-of-order bytes. */
  else if (written > data_len)
    {
      sctp_conn->next_tsn_expected += written;

      SCTP_ADV_DBG ("CONN = %u, WRITTEN [%u] > DATA_LEN [%d]",
		    sctp_conn->sub_conn[conn_idx].connection.c_index,
		    written, data_len);
    }
  else if (written > 0)
    {
      /* We've written something but FIFO is probably full now */
      sctp_conn->next_tsn_expected += written;

      error = SCTP_ERROR_PARTIALLY_ENQUEUED;

      SCTP_ADV_DBG
	("CONN = %u, WRITTEN [%u] > 0 (SCTP_ERROR_PARTIALLY_ENQUEUED)",
	 sctp_conn->sub_conn[conn_idx].connection.c_index, written);
    }
  else
    {
      SCTP_ADV_DBG ("CONN = %u, WRITTEN == 0 (SCTP_ERROR_FIFO_FULL)",
		    sctp_conn->sub_conn[conn_idx].connection.c_index);

      return SCTP_ERROR_FIFO_FULL;
    }

  /* TODO: Update out_of_order_map & SACK list */

  return error;
}

/** Enqueue data for delivery to application */
always_inline int
sctp_session_enqueue_data (sctp_connection_t * sctp_conn, vlib_buffer_t * b,
			   u16 data_len, u8 conn_idx)
{
  int written, error = SCTP_ERROR_ENQUEUED;

  written =
    session_enqueue_stream_connection (&sctp_conn->
				       sub_conn[conn_idx].connection, b, 0,
				       1 /* queue event */ ,
				       1);

  /* Update next_tsn_expected */
  if (PREDICT_TRUE (written == data_len))
    {
      sctp_conn->next_tsn_expected += written;

      SCTP_ADV_DBG ("CONN = %u, WRITTEN [%u] == DATA_LEN [%d]",
		    sctp_conn->sub_conn[conn_idx].connection.c_index,
		    written, data_len);
    }
  /* If more data written than expected, account for out-of-order bytes. */
  else if (written > data_len)
    {
      sctp_conn->next_tsn_expected += written;

      SCTP_ADV_DBG ("CONN = %u, WRITTEN [%u] > DATA_LEN [%d]",
		    sctp_conn->sub_conn[conn_idx].connection.c_index,
		    written, data_len);
    }
  else if (written > 0)
    {
      /* We've written something but FIFO is probably full now */
      sctp_conn->next_tsn_expected += written;

      error = SCTP_ERROR_PARTIALLY_ENQUEUED;

      SCTP_ADV_DBG
	("CONN = %u, WRITTEN [%u] > 0 (SCTP_ERROR_PARTIALLY_ENQUEUED)",
	 sctp_conn->sub_conn[conn_idx].connection.c_index, written);
    }
  else
    {
      SCTP_ADV_DBG ("CONN = %u, WRITTEN == 0 (SCTP_ERROR_FIFO_FULL)",
		    sctp_conn->sub_conn[conn_idx].connection.c_index);

      return SCTP_ERROR_FIFO_FULL;
    }

  return error;
}

always_inline u8
sctp_is_sack_delayable (sctp_connection_t * sctp_conn, u8 idx, u8 is_gapping)
{
  if (sctp_conn->conn_config.never_delay_sack)
    {
      SCTP_CONN_TRACKING_DBG ("sctp_conn->conn_config.never_delay_sack = ON");
      return 0;
    }

  /* Section 4.4 of the RFC4960 */
  if (sctp_conn->state == SCTP_STATE_SHUTDOWN_SENT)
    {
      SCTP_CONN_TRACKING_DBG ("sctp_conn->state = %s; SACK not delayable",
			      sctp_state_to_string (sctp_conn->state));
      return 0;
    }

  if (is_gapping)
    {
      SCTP_CONN_TRACKING_DBG
	("gapping != 0: CONN_INDEX = %u, sctp_conn->ack_state = %u",
	 sctp_conn->sub_conn[idx].connection.c_index, sctp_conn->ack_state);
      return 0;
    }

  sctp_conn->ack_state += 1;
  if (sctp_conn->ack_state >= MAX_ENQUEABLE_SACKS)
    {
      SCTP_CONN_TRACKING_DBG
	("sctp_conn->ack_state >= MAX_ENQUEABLE_SACKS: CONN_INDEX = %u, sctp_conn->ack_state = %u",
	 sctp_conn->sub_conn[idx].connection.c_index, sctp_conn->ack_state);
      return 0;
    }

  return 1;
}

always_inline void
sctp_is_connection_gapping (sctp_connection_t * sctp_conn, u32 tsn,
			    u8 * gapping)
{
  if (sctp_conn->next_tsn_expected != tsn)	// It means data transmission is GAPPING
    {
      SCTP_CONN_TRACKING_DBG
	("GAPPING: CONN_INDEX = %u, sctp_conn->next_tsn_expected = %u, tsn = %u, diff = %u",
	 sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].connection.c_index,
	 sctp_conn->next_tsn_expected, tsn,
	 sctp_conn->next_tsn_expected - tsn);

      *gapping = 1;
    }
}

always_inline u16
sctp_handle_data (sctp_payload_data_chunk_t * sctp_data_chunk,
		  sctp_connection_t * sctp_conn, u8 idx, vlib_buffer_t * b,
		  u16 * next0)
{
  u32 error = 0, n_data_bytes;
  u8 is_gapping = 0;

  /* Check that the LOCALLY generated tag is being used by the REMOTE peer as the verification tag */
  if (sctp_conn->local_tag != sctp_data_chunk->sctp_hdr.verification_tag)
    {
      *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);
      sctp_conn->sub_conn[idx].enqueue_state = SCTP_ERROR_INVALID_TAG;
      return sctp_conn->sub_conn[idx].enqueue_state;
    }

  vnet_buffer (b)->sctp.sid = sctp_data_chunk->stream_id;
  vnet_buffer (b)->sctp.ssn = sctp_data_chunk->stream_seq;

  u32 tsn = clib_net_to_host_u32 (sctp_data_chunk->tsn);

  vlib_buffer_advance (b, vnet_buffer (b)->sctp.data_offset);
  u32 chunk_len = vnet_sctp_get_chunk_length (&sctp_data_chunk->chunk_hdr) -
    (sizeof (sctp_payload_data_chunk_t) - sizeof (sctp_header_t));

  ASSERT (vnet_buffer (b)->sctp.data_len);
  ASSERT (chunk_len);

  /* Padding was added: see RFC 4096 section 3.3.1 */
  if (vnet_buffer (b)->sctp.data_len > chunk_len)
    {
      /* Let's change the data_len to the right amount calculated here now.
       * We cannot do that in the generic sctp46_input_dispatcher node since
       * that is common to all CHUNKS handling.
       */
      vnet_buffer (b)->sctp.data_len = chunk_len;
      /* We need to change b->current_length so that downstream calls to
       * session_enqueue_stream_connection (called by sctp_session_enqueue_data)
       * push the correct amount of data to be enqueued.
       */
      b->current_length = chunk_len;
    }
  n_data_bytes = vnet_buffer (b)->sctp.data_len;

  sctp_is_connection_gapping (sctp_conn, tsn, &is_gapping);

  sctp_conn->last_rcvd_tsn = tsn;

  SCTP_ADV_DBG ("POINTER_WITH_DATA = %p", b->data);

  u8 bbit = vnet_sctp_get_bbit (&sctp_data_chunk->chunk_hdr);
  u8 ebit = vnet_sctp_get_ebit (&sctp_data_chunk->chunk_hdr);

  if (bbit == 1 && ebit == 1)	/* Unfragmented message */
    {
      /* In order data, enqueue. Fifo figures out by itself if any out-of-order
       * segments can be enqueued after fifo tail offset changes. */
      if (PREDICT_FALSE (is_gapping == 1))
	error =
	  sctp_session_enqueue_data_ooo (sctp_conn, b, n_data_bytes, idx);
      else
	error = sctp_session_enqueue_data (sctp_conn, b, n_data_bytes, idx);
    }
  else if (bbit == 1 && ebit == 0)	/* First piece of a fragmented user message */
    {
      error = sctp_session_enqueue_data (sctp_conn, b, n_data_bytes, idx);
    }
  else if (bbit == 0 && ebit == 1)	/* Last piece of a fragmented user message */
    {
      if (PREDICT_FALSE (is_gapping == 1))
	error =
	  sctp_session_enqueue_data_ooo (sctp_conn, b, n_data_bytes, idx);
      else
	error = sctp_session_enqueue_data (sctp_conn, b, n_data_bytes, idx);
    }
  else				/* Middle piece of a fragmented user message */
    {
      if (PREDICT_FALSE (is_gapping == 1))
	error =
	  sctp_session_enqueue_data_ooo (sctp_conn, b, n_data_bytes, idx);
      else
	error = sctp_session_enqueue_data (sctp_conn, b, n_data_bytes, idx);
    }
  sctp_conn->last_rcvd_tsn = tsn;

  SCTP_ADV_DBG ("POINTER_WITH_DATA = %p", b->data);

  if (!sctp_is_sack_delayable (sctp_conn, idx, is_gapping))
    {
      *next0 = sctp_next_output (sctp_conn->sub_conn[idx].c_is_ip4);
      sctp_prepare_sack_chunk (sctp_conn, idx, b);
    }
  else
    *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);

  sctp_conn->sub_conn[idx].enqueue_state = error;

  return error;
}

always_inline u16
sctp_handle_cookie_echo (sctp_header_t * sctp_hdr,
			 sctp_chunks_common_hdr_t * sctp_chunk_hdr,
			 sctp_connection_t * sctp_conn, u8 idx,
			 vlib_buffer_t * b0, u16 * next0)
{
  u64 now = sctp_time_now ();

  sctp_cookie_echo_chunk_t *cookie_echo =
    (sctp_cookie_echo_chunk_t *) sctp_hdr;

  /* Check that the LOCALLY generated tag is being used by the REMOTE peer as the verification tag */
  if (sctp_conn->local_tag != sctp_hdr->verification_tag)
    {
      *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);
      return SCTP_ERROR_INVALID_TAG;
    }

  sctp_calculate_rto (sctp_conn, idx);

  u64 creation_time =
    clib_net_to_host_u64 (cookie_echo->cookie.creation_time);
  u64 cookie_lifespan =
    clib_net_to_host_u32 (cookie_echo->cookie.cookie_lifespan);

  if (now > creation_time + cookie_lifespan)
    {
      SCTP_DBG ("now (%u) > creation_time (%u) + cookie_lifespan (%u)",
		now, creation_time, cookie_lifespan);
      return SCTP_ERROR_COOKIE_ECHO_VIOLATION;
    }

  sctp_prepare_cookie_ack_chunk (sctp_conn, idx, b0);

  /* Change state */
  sctp_conn->state = SCTP_STATE_ESTABLISHED;
  sctp_conn->sub_conn[idx].state = SCTP_SUBCONN_STATE_UP;
  *next0 = sctp_next_output (sctp_conn->sub_conn[idx].c_is_ip4);

  sctp_timer_set (sctp_conn, idx, SCTP_TIMER_T4_HEARTBEAT,
		  sctp_conn->sub_conn[idx].RTO);

  stream_session_accept_notify (&sctp_conn->sub_conn[idx].connection);

  return SCTP_ERROR_NONE;

}

always_inline u16
sctp_handle_cookie_ack (sctp_header_t * sctp_hdr,
			sctp_chunks_common_hdr_t * sctp_chunk_hdr,
			sctp_connection_t * sctp_conn, u8 idx,
			vlib_buffer_t * b0, u16 * next0)
{
  /* Check that the LOCALLY generated tag is being used by the REMOTE peer as the verification tag */
  if (sctp_conn->local_tag != sctp_hdr->verification_tag)
    {
      *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);
      return SCTP_ERROR_INVALID_TAG;
    }

  sctp_calculate_rto (sctp_conn, idx);

  sctp_timer_reset (sctp_conn, idx, SCTP_TIMER_T1_COOKIE);
  /* Change state */
  sctp_conn->state = SCTP_STATE_ESTABLISHED;
  sctp_conn->sub_conn[idx].state = SCTP_SUBCONN_STATE_UP;

  *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);

  sctp_timer_set (sctp_conn, idx, SCTP_TIMER_T4_HEARTBEAT,
		  sctp_conn->sub_conn[idx].RTO);

  stream_session_accept_notify (&sctp_conn->sub_conn[idx].connection);

  return SCTP_ERROR_NONE;

}

always_inline uword
sctp46_rcv_phase_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame, int is_ip4)
{
  sctp_main_t *tm = vnet_get_sctp_main ();

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
	  sctp_header_t *sctp_hdr = 0;
	  sctp_chunks_common_hdr_t *sctp_chunk_hdr = 0;
	  ip4_header_t *ip4_hdr = 0;
	  ip6_header_t *ip6_hdr = 0;
	  sctp_connection_t *sctp_conn, *new_sctp_conn;
	  u16 sctp_implied_length = 0;
	  u16 error0 = SCTP_ERROR_NONE, next0 = sctp_next_drop (is_ip4);
	  u8 idx;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* If we are in SCTP_COOKIE_WAIT_STATE then the connection
	   * will come from the half-open connections pool.
	   */
	  sctp_conn =
	    sctp_half_open_connection_get (vnet_buffer (b0)->
					   sctp.connection_index);

	  if (PREDICT_FALSE (sctp_conn == 0))
	    {
	      SCTP_ADV_DBG
		("sctp_conn == NULL; return SCTP_ERROR_INVALID_CONNECTION");
	      error0 = SCTP_ERROR_INVALID_CONNECTION;
	      goto drop;
	    }
	  if (is_ip4)
	    {
	      ip4_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip4_next_header (ip4_hdr);
	      idx = sctp_sub_conn_id_via_ip4h (sctp_conn, ip4_hdr);
	    }
	  else
	    {
	      ip6_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip6_next_header (ip6_hdr);
	      idx = sctp_sub_conn_id_via_ip6h (sctp_conn, ip6_hdr);
	    }

	  sctp_conn->sub_conn[idx].subconn_idx = idx;
	  sctp_full_hdr_t *full_hdr = (sctp_full_hdr_t *) sctp_hdr;

	  sctp_chunk_hdr =
	    (sctp_chunks_common_hdr_t *) (&full_hdr->common_hdr);

	  sctp_implied_length =
	    sctp_calculate_implied_length (ip4_hdr, ip6_hdr, is_ip4);

	  u8 chunk_type = vnet_sctp_get_chunk_type (&full_hdr->common_hdr);

	  switch (chunk_type)
	    {
	    case INIT_ACK:
	      error0 =
		sctp_is_valid_init_ack (sctp_hdr, sctp_chunk_hdr, sctp_conn,
					b0, sctp_implied_length);

	      if (error0 == SCTP_ERROR_NONE)
		{
		  pool_get (tm->connections[my_thread_index], new_sctp_conn);
		  clib_memcpy_fast (new_sctp_conn, sctp_conn,
				    sizeof (*new_sctp_conn));
		  new_sctp_conn->sub_conn[idx].c_c_index =
		    new_sctp_conn - tm->connections[my_thread_index];
		  new_sctp_conn->sub_conn[idx].c_thread_index =
		    my_thread_index;
		  new_sctp_conn->sub_conn[idx].PMTU =
		    sctp_conn->sub_conn[idx].PMTU;
		  new_sctp_conn->sub_conn[idx].subconn_idx = idx;

		  if (sctp_half_open_connection_cleanup (sctp_conn))
		    {
		      SCTP_DBG
			("Cannot cleanup half-open connection; not the owning thread");
		    }

		  sctp_connection_timers_init (new_sctp_conn);

		  sctp_init_cwnd (new_sctp_conn);

		  error0 =
		    sctp_handle_init_ack (sctp_hdr, sctp_chunk_hdr,
					  new_sctp_conn, idx, b0,
					  sctp_implied_length);

		  if (session_stream_connect_notify
		      (&new_sctp_conn->sub_conn[idx].connection, 0))
		    {
		      SCTP_DBG
			("conn_index = %u: session_stream_connect_notify error; cleaning up connection",
			 new_sctp_conn->sub_conn[idx].connection.c_index);
		      sctp_connection_cleanup (new_sctp_conn);
		      goto drop;
		    }
		  next0 = sctp_next_output (is_ip4);
		}
	      break;

	    case OPERATION_ERROR:
	      error0 =
		sctp_handle_operation_err (sctp_hdr, sctp_conn, idx, b0,
					   &next0);
	      break;

	      /* All UNEXPECTED scenarios (wrong chunk received per state-machine)
	       * are handled by the input-dispatcher function using the table-lookup
	       * hence we should never get to the "default" case below.
	       */
	    default:
	      error0 = SCTP_ERROR_UNKNOWN_CHUNK;
	      next0 = sctp_next_drop (is_ip4);
	      goto drop;
	    }

	  if (error0 != SCTP_ERROR_NONE)
	    {
	      clib_warning ("error while parsing chunk");
	      sctp_connection_cleanup (sctp_conn);
	      next0 = sctp_next_drop (is_ip4);
	      goto drop;
	    }

	drop:
	  b0->error = node->errors[error0];
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
sctp4_rcv_phase (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vlib_frame_t * from_frame)
{
  return sctp46_rcv_phase_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
sctp6_rcv_phase (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vlib_frame_t * from_frame)
{
  return sctp46_rcv_phase_inline (vm, node, from_frame, 0 /* is_ip4 */ );
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
VLIB_REGISTER_NODE (sctp4_rcv_phase_node) =
{
  .function = sctp4_rcv_phase,
  .name = "sctp4-rcv",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_RCV_PHASE_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_RCV_PHASE_NEXT_##s] = n,
    foreach_sctp_state_next
#undef _
  },
  .format_trace = format_sctp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp4_rcv_phase_node, sctp4_rcv_phase);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp6_init_phase_node) =
{
  .function = sctp6_rcv_phase,
  .name = "sctp6-rcv",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_RCV_PHASE_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_RCV_PHASE_NEXT_##s] = n,
    foreach_sctp_state_next
#undef _
  },
  .format_trace = format_sctp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp6_init_phase_node, sctp6_rcv_phase);

vlib_node_registration_t sctp4_shutdown_phase_node;
vlib_node_registration_t sctp6_shutdown_phase_node;

always_inline u16
sctp_handle_shutdown (sctp_header_t * sctp_hdr,
		      sctp_chunks_common_hdr_t * sctp_chunk_hdr,
		      sctp_connection_t * sctp_conn, u8 idx,
		      vlib_buffer_t * b0, u16 sctp_implied_length,
		      u16 * next0)
{
  sctp_shutdown_association_chunk_t *shutdown_chunk =
    (sctp_shutdown_association_chunk_t *) (sctp_hdr);

  /* Check that the LOCALLY generated tag is being used by the REMOTE peer as the verification tag */
  if (sctp_conn->local_tag != sctp_hdr->verification_tag)
    {
      *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);
      return SCTP_ERROR_INVALID_TAG;
    }

  /*
   * It is not possible to bundle any other CHUNK with the SHUTDOWN chunk
   */
  if (sctp_is_bundling (sctp_implied_length, &shutdown_chunk->chunk_hdr))
    return SCTP_ERROR_BUNDLING_VIOLATION;

  switch (sctp_conn->state)
    {
    case SCTP_STATE_ESTABLISHED:
      if (sctp_check_outstanding_data_chunks (sctp_conn) == 0)
	sctp_conn->state = SCTP_STATE_SHUTDOWN_RECEIVED;
      sctp_send_shutdown_ack (sctp_conn, idx, b0);
      break;

    case SCTP_STATE_SHUTDOWN_SENT:
      sctp_send_shutdown_ack (sctp_conn, idx, b0);
      break;
    }

  *next0 = sctp_next_output (sctp_conn->sub_conn[idx].c_is_ip4);

  return SCTP_ERROR_NONE;
}

always_inline u16
sctp_handle_shutdown_ack (sctp_header_t * sctp_hdr,
			  sctp_chunks_common_hdr_t * sctp_chunk_hdr,
			  sctp_connection_t * sctp_conn, u8 idx,
			  vlib_buffer_t * b0, u16 sctp_implied_length,
			  u16 * next0)
{
  sctp_shutdown_ack_chunk_t *shutdown_ack_chunk =
    (sctp_shutdown_ack_chunk_t *) (sctp_hdr);

  /* Check that the LOCALLY generated tag is being used by the REMOTE peer as the verification tag */
  if (sctp_conn->local_tag != sctp_hdr->verification_tag)
    {
      *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);
      return SCTP_ERROR_INVALID_TAG;
    }

  /*
   * It is not possible to bundle any other CHUNK with the SHUTDOWN chunk
   */
  if (sctp_is_bundling (sctp_implied_length, &shutdown_ack_chunk->chunk_hdr))
    return SCTP_ERROR_BUNDLING_VIOLATION;

  /* Whether we are in SCTP_STATE_SHUTDOWN_SENT or SCTP_STATE_SHUTDOWN_ACK_SENT
   * the reception of a SHUTDOWN_ACK chunk leads to the same actions:
   * - STOP T2_SHUTDOWN timer
   * - SEND SHUTDOWN_COMPLETE chunk
   */
  sctp_timer_reset (sctp_conn, SCTP_PRIMARY_PATH_IDX, SCTP_TIMER_T2_SHUTDOWN);

  sctp_send_shutdown_complete (sctp_conn, idx, b0);

  *next0 = sctp_next_output (sctp_conn->sub_conn[idx].c_is_ip4);

  return SCTP_ERROR_NONE;
}

always_inline u16
sctp_handle_shutdown_complete (sctp_header_t * sctp_hdr,
			       sctp_chunks_common_hdr_t * sctp_chunk_hdr,
			       sctp_connection_t * sctp_conn, u8 idx,
			       vlib_buffer_t * b0, u16 sctp_implied_length,
			       u16 * next0)
{
  sctp_shutdown_complete_chunk_t *shutdown_complete =
    (sctp_shutdown_complete_chunk_t *) (sctp_hdr);

  /* Check that the LOCALLY generated tag is being used by the REMOTE peer as the verification tag */
  if (sctp_conn->local_tag != sctp_hdr->verification_tag)
    {
      *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);
      return SCTP_ERROR_INVALID_TAG;
    }

  /*
   * It is not possible to bundle any other CHUNK with the SHUTDOWN chunk
   */
  if (sctp_is_bundling (sctp_implied_length, &shutdown_complete->chunk_hdr))
    return SCTP_ERROR_BUNDLING_VIOLATION;

  sctp_timer_reset (sctp_conn, idx, SCTP_TIMER_T2_SHUTDOWN);

  session_transport_closing_notify (&sctp_conn->sub_conn[idx].connection);

  sctp_conn->state = SCTP_STATE_CLOSED;

  *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);

  return SCTP_ERROR_NONE;
}

always_inline uword
sctp46_shutdown_phase_inline (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
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
	  ip4_header_t *ip4_hdr = 0;
	  ip6_header_t *ip6_hdr = 0;
	  sctp_connection_t *sctp_conn;
	  u16 sctp_implied_length = 0;
	  u16 error0 = SCTP_ERROR_NONE, next0 = SCTP_RCV_PHASE_N_NEXT;
	  u8 idx = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sctp_conn =
	    sctp_connection_get (vnet_buffer (b0)->sctp.connection_index,
				 my_thread_index);

	  if (PREDICT_FALSE (sctp_conn == 0))
	    {
	      SCTP_DBG
		("sctp_conn == NULL; return SCTP_ERROR_INVALID_CONNECTION");
	      error0 = SCTP_ERROR_INVALID_CONNECTION;
	      goto drop;
	    }

	  if (is_ip4)
	    {
	      ip4_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip4_next_header (ip4_hdr);
	      idx = sctp_sub_conn_id_via_ip4h (sctp_conn, ip4_hdr);
	    }
	  else
	    {
	      ip6_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip6_next_header (ip6_hdr);
	      idx = sctp_sub_conn_id_via_ip6h (sctp_conn, ip6_hdr);
	    }

	  sctp_full_hdr_t *full_hdr = (sctp_full_hdr_t *) sctp_hdr;
	  sctp_chunk_hdr = &full_hdr->common_hdr;

	  sctp_implied_length =
	    sctp_calculate_implied_length (ip4_hdr, ip6_hdr, is_ip4);

	  u8 chunk_type = vnet_sctp_get_chunk_type (sctp_chunk_hdr);
	  switch (chunk_type)
	    {
	    case SHUTDOWN:
	      error0 =
		sctp_handle_shutdown (sctp_hdr, sctp_chunk_hdr, sctp_conn,
				      idx, b0, sctp_implied_length, &next0);
	      break;

	    case SHUTDOWN_ACK:
	      error0 =
		sctp_handle_shutdown_ack (sctp_hdr, sctp_chunk_hdr, sctp_conn,
					  idx, b0, sctp_implied_length,
					  &next0);
	      break;

	    case SHUTDOWN_COMPLETE:
	      error0 =
		sctp_handle_shutdown_complete (sctp_hdr, sctp_chunk_hdr,
					       sctp_conn, idx, b0,
					       sctp_implied_length, &next0);

	      sctp_connection_cleanup (sctp_conn);
	      break;

	      /*
	       * DATA chunks can still be transmitted/received in the SHUTDOWN-PENDING
	       * and SHUTDOWN-SENT states (as per RFC4960 Section 6)
	       */
	    case DATA:
	      error0 =
		sctp_handle_data ((sctp_payload_data_chunk_t *) sctp_hdr,
				  sctp_conn, idx, b0, &next0);
	      break;

	    case OPERATION_ERROR:
	      error0 =
		sctp_handle_operation_err (sctp_hdr, sctp_conn, idx, b0,
					   &next0);
	      break;

	    case COOKIE_ECHO:	/* Cookie Received While Shutting Down */
	      sctp_prepare_operation_error (sctp_conn, idx, b0,
					    COOKIE_RECEIVED_WHILE_SHUTTING_DOWN);
	      error0 = SCTP_ERROR_NONE;
	      next0 = sctp_next_output (is_ip4);
	      break;
	      /* All UNEXPECTED scenarios (wrong chunk received per state-machine)
	       * are handled by the input-dispatcher function using the table-lookup
	       * hence we should never get to the "default" case below.
	       */
	    default:
	      error0 = SCTP_ERROR_UNKNOWN_CHUNK;
	      next0 = sctp_next_drop (is_ip4);
	      goto drop;
	    }

	  if (error0 != SCTP_ERROR_NONE)
	    {
	      clib_warning ("error while parsing chunk");
	      sctp_connection_cleanup (sctp_conn);
	      next0 = sctp_next_drop (is_ip4);
	      goto drop;
	    }

	drop:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sctp_trace =
		vlib_add_trace (vm, node, b0, sizeof (*sctp_trace));

	      if (sctp_hdr != NULL)
		clib_memcpy_fast (&sctp_trace->sctp_header, sctp_hdr,
				  sizeof (sctp_trace->sctp_header));

	      if (sctp_conn != NULL)
		clib_memcpy_fast (&sctp_trace->sctp_connection, sctp_conn,
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

vlib_node_registration_t sctp4_listen_phase_node;
vlib_node_registration_t sctp6_listen_phase_node;

vlib_node_registration_t sctp4_established_phase_node;
vlib_node_registration_t sctp6_established_phase_node;

always_inline u16
sctp_handle_sack (sctp_selective_ack_chunk_t * sack_chunk,
		  sctp_connection_t * sctp_conn, u8 idx, vlib_buffer_t * b0,
		  u16 * next0)
{

  /* Check that the LOCALLY generated tag is being used by the REMOTE peer as the verification tag */
  if (sctp_conn->local_tag != sack_chunk->sctp_hdr.verification_tag)
    {
      *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);
      return SCTP_ERROR_INVALID_TAG;
    }

  sctp_conn->sub_conn[idx].state = SCTP_SUBCONN_SACK_RECEIVED;

  sctp_conn->sub_conn[idx].last_seen = sctp_time_now ();

  /* Section 7.2.2; point (2) */
  if (sctp_conn->sub_conn[idx].cwnd > sctp_conn->sub_conn[idx].ssthresh)
    sctp_conn->sub_conn[idx].partially_acked_bytes =
      sctp_conn->next_tsn - sack_chunk->cumulative_tsn_ack;

  /* Section 7.2.2; point (5) */
  if (sctp_conn->next_tsn - sack_chunk->cumulative_tsn_ack == 0)
    sctp_conn->sub_conn[idx].partially_acked_bytes = 0;

  sctp_conn->last_unacked_tsn = sack_chunk->cumulative_tsn_ack;

  sctp_calculate_rto (sctp_conn, idx);

  sctp_timer_update (sctp_conn, idx, SCTP_TIMER_T3_RXTX,
		     sctp_conn->sub_conn[idx].RTO);

  sctp_conn->sub_conn[idx].RTO_pending = 0;

  *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);

  return SCTP_ERROR_NONE;
}

always_inline u16
sctp_handle_heartbeat (sctp_hb_req_chunk_t * sctp_hb_chunk,
		       sctp_connection_t * sctp_conn, u8 idx,
		       vlib_buffer_t * b0, u16 * next0)
{
  /* Check that the LOCALLY generated tag is being used by the REMOTE peer as the verification tag */
  if (sctp_conn->local_tag != sctp_hb_chunk->sctp_hdr.verification_tag)
    {
      *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);
      return SCTP_ERROR_INVALID_TAG;
    }

  sctp_prepare_heartbeat_ack_chunk (sctp_conn, idx, b0);

  *next0 = sctp_next_output (sctp_conn->sub_conn[idx].connection.is_ip4);

  return SCTP_ERROR_NONE;
}

always_inline u16
sctp_handle_heartbeat_ack (sctp_hb_ack_chunk_t * sctp_hb_ack_chunk,
			   sctp_connection_t * sctp_conn, u8 idx,
			   vlib_buffer_t * b0, u16 * next0)
{
  sctp_conn->sub_conn[idx].last_seen = sctp_time_now ();

  sctp_conn->sub_conn[idx].unacknowledged_hb -= 1;

  sctp_timer_update (sctp_conn, idx, SCTP_TIMER_T4_HEARTBEAT,
		     sctp_conn->sub_conn[idx].RTO);

  *next0 = sctp_next_drop (sctp_conn->sub_conn[idx].c_is_ip4);

  return SCTP_ERROR_NONE;
}

always_inline void
sctp_node_inc_counter (vlib_main_t * vm, u32 sctp4_node, u32 sctp6_node,
		       u8 is_ip4, u8 evt, u8 val)
{
  if (PREDICT_TRUE (!val))
    return;

  if (is_ip4)
    vlib_node_increment_counter (vm, sctp4_node, evt, val);
  else
    vlib_node_increment_counter (vm, sctp6_node, evt, val);
}

always_inline uword
sctp46_listen_process_inline (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
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
	  sctp_header_t *sctp_hdr = 0;
	  ip4_header_t *ip4_hdr;
	  ip6_header_t *ip6_hdr;
	  sctp_connection_t *child_conn;
	  sctp_connection_t *sctp_listener;
	  u16 next0 = sctp_next_drop (is_ip4), error0 = SCTP_ERROR_ENQUEUED;

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

	  child_conn =
	    sctp_lookup_connection (sctp_listener->sub_conn
				    [SCTP_PRIMARY_PATH_IDX].c_fib_index, b0,
				    my_thread_index, is_ip4);

	  if (PREDICT_FALSE (child_conn->state != SCTP_STATE_CLOSED))
	    {
	      SCTP_DBG
		("conn_index = %u: child_conn->state != SCTP_STATE_CLOSED.... STATE=%s",
		 child_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].
		 connection.c_index,
		 sctp_state_to_string (child_conn->state));
	      error0 = SCTP_ERROR_CREATE_EXISTS;
	      goto drop;
	    }

	  /* Create child session and send SYN-ACK */
	  child_conn = sctp_connection_new (my_thread_index);
	  child_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].subconn_idx =
	    SCTP_PRIMARY_PATH_IDX;
	  child_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].c_lcl_port =
	    sctp_hdr->dst_port;
	  child_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].c_rmt_port =
	    sctp_hdr->src_port;
	  child_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].c_is_ip4 = is_ip4;
	  child_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].connection.proto =
	    sctp_listener->sub_conn[SCTP_PRIMARY_PATH_IDX].connection.proto;
	  child_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].PMTU =
	    sctp_listener->sub_conn[SCTP_PRIMARY_PATH_IDX].PMTU;
	  child_conn->state = SCTP_STATE_CLOSED;
	  child_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].connection.fib_index =
	    sctp_listener->sub_conn[SCTP_PRIMARY_PATH_IDX].
	    connection.fib_index;

	  if (is_ip4)
	    {
	      child_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].c_lcl_ip4.as_u32 =
		ip4_hdr->dst_address.as_u32;
	      child_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].c_rmt_ip4.as_u32 =
		ip4_hdr->src_address.as_u32;
	    }
	  else
	    {
	      clib_memcpy_fast (&child_conn->
				sub_conn[SCTP_PRIMARY_PATH_IDX].c_lcl_ip6,
				&ip6_hdr->dst_address,
				sizeof (ip6_address_t));
	      clib_memcpy_fast (&child_conn->
				sub_conn[SCTP_PRIMARY_PATH_IDX].c_rmt_ip6,
				&ip6_hdr->src_address,
				sizeof (ip6_address_t));
	    }

	  sctp_full_hdr_t *full_hdr = (sctp_full_hdr_t *) sctp_hdr;
	  sctp_chunks_common_hdr_t *sctp_chunk_hdr = &full_hdr->common_hdr;

	  u8 chunk_type = vnet_sctp_get_chunk_type (sctp_chunk_hdr);
	  if (chunk_type != INIT && chunk_type != DATA
	      && chunk_type != OPERATION_ERROR)
	    {
	      SCTP_DBG
		("conn_index = %u: chunk_type != INIT... chunk_type=%s",
		 child_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].
		 connection.c_index, sctp_chunk_to_string (chunk_type));

	      error0 = SCTP_ERROR_UNKNOWN_CHUNK;
	      next0 = sctp_next_drop (is_ip4);
	      goto drop;
	    }

	  u16 sctp_implied_length =
	    sctp_calculate_implied_length (ip4_hdr, ip6_hdr, is_ip4);

	  switch (chunk_type)
	    {
	    case INIT:
	      sctp_connection_timers_init (child_conn);

	      sctp_init_snd_vars (child_conn);

	      sctp_init_cwnd (child_conn);

	      error0 =
		sctp_handle_init (sctp_hdr, sctp_chunk_hdr, child_conn, b0,
				  sctp_implied_length);

	      if (error0 == SCTP_ERROR_NONE)
		{
		  if (stream_session_accept
		      (&child_conn->
		       sub_conn[SCTP_PRIMARY_PATH_IDX].connection,
		       sctp_listener->
		       sub_conn[SCTP_PRIMARY_PATH_IDX].c_s_index, 0))
		    {
		      clib_warning ("session accept fail");
		      sctp_connection_cleanup (child_conn);
		      error0 = SCTP_ERROR_CREATE_SESSION_FAIL;
		      goto drop;
		    }
		  next0 = sctp_next_output (is_ip4);
		}
	      break;

	      /* Reception of a DATA chunk whilst in the CLOSED state is called
	       * "Out of the Blue" packet and handling of the chunk needs special treatment
	       * as per RFC4960 section 8.4
	       */
	    case DATA:
	      break;

	    case OPERATION_ERROR:
	      error0 =
		sctp_handle_operation_err (sctp_hdr, child_conn,
					   SCTP_PRIMARY_PATH_IDX, b0, &next0);
	      break;
	    }

	drop:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sctp_rx_trace_t *t0 =
		vlib_add_trace (vm, node, b0, sizeof (*t0));
	      clib_memcpy_fast (&t0->sctp_header, sctp_hdr,
				sizeof (t0->sctp_header));
	      clib_memcpy_fast (&t0->sctp_connection, sctp_listener,
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
sctp4_listen_phase (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame)
{
  return sctp46_listen_process_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
sctp6_listen_phase (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame)
{
  return sctp46_listen_process_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

always_inline uword
sctp46_established_phase_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->thread_index, errors = 0;

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
	  sctp_chunks_common_hdr_t *sctp_chunk_hdr = 0;
	  ip4_header_t *ip4_hdr = 0;
	  ip6_header_t *ip6_hdr = 0;
	  sctp_connection_t *sctp_conn;
	  u16 error0 = SCTP_ERROR_ENQUEUED, next0 =
	    SCTP_ESTABLISHED_PHASE_N_NEXT;
	  u8 idx;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sctp_conn =
	    sctp_connection_get (vnet_buffer (b0)->sctp.connection_index,
				 my_thread_index);

	  if (PREDICT_FALSE (sctp_conn == 0))
	    {
	      SCTP_DBG
		("sctp_conn == NULL; return SCTP_ERROR_INVALID_CONNECTION");
	      error0 = SCTP_ERROR_INVALID_CONNECTION;
	      goto done;
	    }
	  if (is_ip4)
	    {
	      ip4_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip4_next_header (ip4_hdr);
	      idx = sctp_sub_conn_id_via_ip4h (sctp_conn, ip4_hdr);
	    }
	  else
	    {
	      ip6_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip6_next_header (ip6_hdr);
	      idx = sctp_sub_conn_id_via_ip6h (sctp_conn, ip6_hdr);
	    }

	  sctp_conn->sub_conn[idx].subconn_idx = idx;

	  sctp_full_hdr_t *full_hdr = (sctp_full_hdr_t *) sctp_hdr;
	  sctp_chunk_hdr =
	    (sctp_chunks_common_hdr_t *) (&full_hdr->common_hdr);

	  u8 chunk_type = vnet_sctp_get_chunk_type (&full_hdr->common_hdr);

	  switch (chunk_type)
	    {
	    case COOKIE_ECHO:
	      error0 =
		sctp_handle_cookie_echo (sctp_hdr, sctp_chunk_hdr, sctp_conn,
					 idx, b0, &next0);
	      break;

	    case COOKIE_ACK:
	      error0 =
		sctp_handle_cookie_ack (sctp_hdr, sctp_chunk_hdr, sctp_conn,
					idx, b0, &next0);
	      break;

	    case SACK:
	      error0 =
		sctp_handle_sack ((sctp_selective_ack_chunk_t *) sctp_hdr,
				  sctp_conn, idx, b0, &next0);
	      break;

	    case HEARTBEAT:
	      error0 =
		sctp_handle_heartbeat ((sctp_hb_req_chunk_t *) sctp_hdr,
				       sctp_conn, idx, b0, &next0);
	      break;

	    case HEARTBEAT_ACK:
	      error0 =
		sctp_handle_heartbeat_ack ((sctp_hb_ack_chunk_t *) sctp_hdr,
					   sctp_conn, idx, b0, &next0);
	      break;

	    case DATA:
	      error0 =
		sctp_handle_data ((sctp_payload_data_chunk_t *) sctp_hdr,
				  sctp_conn, idx, b0, &next0);
	      break;

	    case OPERATION_ERROR:
	      error0 =
		sctp_handle_operation_err (sctp_hdr, sctp_conn, idx, b0,
					   &next0);
	      break;

	      /* All UNEXPECTED scenarios (wrong chunk received per state-machine)
	       * are handled by the input-dispatcher function using the table-lookup
	       * hence we should never get to the "default" case below.
	       */
	    default:
	      error0 = SCTP_ERROR_UNKNOWN_CHUNK;
	      next0 = sctp_next_drop (is_ip4);
	      goto done;
	    }

	done:
	  b0->error = node->errors[error0];
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

  errors = session_manager_flush_enqueue_events (TRANSPORT_PROTO_SCTP,
						 my_thread_index);

  sctp_node_inc_counter (vm, is_ip4, sctp4_established_phase_node.index,
			 sctp6_established_phase_node.index,
			 SCTP_ERROR_EVENT_FIFO_FULL, errors);
  sctp_flush_frame_to_output (vm, my_thread_index, is_ip4);

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
VLIB_REGISTER_NODE (sctp4_listen_phase_node) =
{
  .function = sctp4_listen_phase,
  .name = "sctp4-listen",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_LISTEN_PHASE_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_LISTEN_PHASE_NEXT_##s] = n,
    foreach_sctp_state_next
#undef _
  },
  .format_trace = format_sctp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp4_listen_phase_node, sctp4_listen_phase);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp6_listen_phase_node) =
{
  .function = sctp6_listen_phase,
  .name = "sctp6-listen",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_LISTEN_PHASE_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_LISTEN_PHASE_NEXT_##s] = n,
    foreach_sctp_state_next
#undef _
  },
  .format_trace = format_sctp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sctp6_listen_phase_node, sctp6_listen_phase);

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
  .n_next_nodes = SCTP_LISTEN_PHASE_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [SCTP_LISTEN_PHASE_NEXT_##s] = n,
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
	  transport_connection_t *trans_conn;
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
	  vnet_buffer (b0)->sctp.flags = 0;
	  fib_index0 = vnet_buffer (b0)->ip.fib_index;

	  /* Checksum computed by ipx_local no need to compute again */

	  if (is_ip4)
	    {
	      ip4_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip4_next_header (ip4_hdr);

	      sctp_full_hdr_t *full_hdr = (sctp_full_hdr_t *) sctp_hdr;
	      sctp_chunk_hdr = &full_hdr->common_hdr;

	      n_advance_bytes0 =
		(ip4_header_bytes (ip4_hdr) +
		 sizeof (sctp_payload_data_chunk_t));
	      n_data_bytes0 =
		clib_net_to_host_u16 (ip4_hdr->length) - n_advance_bytes0;

	      trans_conn = session_lookup_connection_wt4 (fib_index0,
							  &ip4_hdr->dst_address,
							  &ip4_hdr->src_address,
							  sctp_hdr->dst_port,
							  sctp_hdr->src_port,
							  TRANSPORT_PROTO_SCTP,
							  my_thread_index,
							  &is_filtered);
	    }
	  else
	    {
	      ip6_hdr = vlib_buffer_get_current (b0);
	      sctp_hdr = ip6_next_header (ip6_hdr);

	      sctp_full_hdr_t *full_hdr = (sctp_full_hdr_t *) sctp_hdr;
	      sctp_chunk_hdr = &full_hdr->common_hdr;

	      n_advance_bytes0 = sctp_header_bytes ();
	      n_data_bytes0 =
		clib_net_to_host_u16 (ip6_hdr->payload_length) -
		n_advance_bytes0;
	      n_advance_bytes0 += sizeof (ip6_hdr[0]);

	      trans_conn = session_lookup_connection_wt6 (fib_index0,
							  &ip6_hdr->dst_address,
							  &ip6_hdr->src_address,
							  sctp_hdr->dst_port,
							  sctp_hdr->src_port,
							  TRANSPORT_PROTO_SCTP,
							  my_thread_index,
							  &is_filtered);
	    }

	  /* Length check */
	  if (PREDICT_FALSE (n_advance_bytes0 < 0))
	    {
	      error0 = SCTP_ERROR_LENGTH;
	      goto done;
	    }

	  sctp_conn = sctp_get_connection_from_transport (trans_conn);
	  vnet_sctp_common_hdr_params_net_to_host (sctp_chunk_hdr);

	  u8 chunk_type = vnet_sctp_get_chunk_type (sctp_chunk_hdr);
	  if (chunk_type >= UNKNOWN)
	    {
	      clib_warning
		("Received an unrecognized chunk; sending back OPERATION_ERROR chunk");

	      sctp_prepare_operation_error (sctp_conn, SCTP_PRIMARY_PATH_IDX,
					    b0, UNRECOGNIZED_CHUNK_TYPE);

	      error0 = SCTP_ERROR_UNKNOWN_CHUNK;
	      next0 = sctp_next_output (is_ip4);
	      goto done;
	    }

	  vnet_buffer (b0)->sctp.hdr_offset =
	    (u8 *) sctp_hdr - (u8 *) vlib_buffer_get_current (b0);

	  /* Session exists */
	  if (PREDICT_TRUE (0 != sctp_conn))
	    {
	      /* Save connection index */
	      vnet_buffer (b0)->sctp.connection_index = trans_conn->c_index;
	      vnet_buffer (b0)->sctp.data_offset = n_advance_bytes0;
	      vnet_buffer (b0)->sctp.data_len = n_data_bytes0;

	      next0 = tm->dispatch_table[sctp_conn->state][chunk_type].next;
	      error0 = tm->dispatch_table[sctp_conn->state][chunk_type].error;

	      SCTP_DBG_STATE_MACHINE
		("S_INDEX = %u, C_INDEX = %u, TRANS_CONN = %p, SCTP_CONN = %p, CURRENT_CONNECTION_STATE = %s,"
		 "CHUNK_TYPE_RECEIVED = %s " "NEXT_PHASE = %s",
		 sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].
		 connection.s_index,
		 sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].
		 connection.c_index, trans_conn, sctp_conn,
		 sctp_state_to_string (sctp_conn->state),
		 sctp_chunk_to_string (chunk_type), phase_to_string (next0));

	      if (chunk_type == DATA)
		SCTP_ADV_DBG ("n_advance_bytes0 = %u, n_data_bytes0 = %u",
			      n_advance_bytes0, n_data_bytes0);

	    }
	  else
	    {
	      if (is_filtered)
		{
		  next0 = SCTP_INPUT_NEXT_DROP;
		  error0 = SCTP_ERROR_FILTERED;
		}
	      else if ((is_ip4 && tm->punt_unknown4) ||
		       (!is_ip4 && tm->punt_unknown6))
		{
		  next0 = SCTP_INPUT_NEXT_PUNT_PHASE;
		  error0 = SCTP_ERROR_PUNT;
		}
	      else
		{
		  next0 = SCTP_INPUT_NEXT_DROP;
		  error0 = SCTP_ERROR_NO_LISTENER;
		}
	      SCTP_DBG_STATE_MACHINE ("sctp_conn == NULL, NEXT_PHASE = %s",
				      phase_to_string (next0));
	      sctp_conn = 0;
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
  //_(CLOSED, DATA, SCTP_INPUT_NEXT_LISTEN_PHASE, SCTP_ERROR_NONE);     /* UNEXPECTED DATA chunk which requires special handling */
  _(CLOSED, INIT, SCTP_INPUT_NEXT_LISTEN_PHASE, SCTP_ERROR_NONE);
  _(CLOSED, INIT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED INIT_ACK chunk */
  _(CLOSED, SACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SACK_CHUNK_VIOLATION);	/* UNEXPECTED SACK chunk */
  _(CLOSED, HEARTBEAT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT chunk */
  _(CLOSED, HEARTBEAT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_ACK_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT_ACK chunk */
  _(CLOSED, ABORT, SCTP_INPUT_NEXT_RCV_PHASE, SCTP_ERROR_NONE);
  _(CLOSED, SHUTDOWN, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN chunk */
  _(CLOSED, SHUTDOWN_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_ACK_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN_ACK chunk */
  _(CLOSED, OPERATION_ERROR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_OPERATION_ERROR_VIOLATION);	/* UNEXPECTED OPERATION_ERROR chunk */
  _(CLOSED, COOKIE_ECHO, SCTP_INPUT_NEXT_ESTABLISHED_PHASE, SCTP_ERROR_NONE);
  _(CLOSED, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(CLOSED, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(CLOSED, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(CLOSED, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */
  _(CLOSED, OPERATION_ERROR, SCTP_INPUT_NEXT_LISTEN_PHASE, SCTP_ERROR_NONE);

  _(COOKIE_WAIT, DATA, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_NONE);	/* UNEXPECTED DATA chunk which requires special handling */
  _(COOKIE_WAIT, INIT, SCTP_INPUT_NEXT_RCV_PHASE, SCTP_ERROR_NONE);	/* UNEXPECTED INIT chunk which requires special handling */
  _(COOKIE_WAIT, INIT_ACK, SCTP_INPUT_NEXT_RCV_PHASE, SCTP_ERROR_NONE);
  _(COOKIE_WAIT, SACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SACK_CHUNK_VIOLATION);	/* UNEXPECTED SACK chunk */
  _(COOKIE_WAIT, HEARTBEAT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT chunk */
  _(COOKIE_WAIT, HEARTBEAT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_ACK_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT_ACK chunk */
  _(COOKIE_WAIT, ABORT, SCTP_INPUT_NEXT_RCV_PHASE, SCTP_ERROR_NONE);
  _(COOKIE_WAIT, SHUTDOWN, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN chunk */
  _(COOKIE_WAIT, SHUTDOWN_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_ACK_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN_ACK chunk */
  _(COOKIE_WAIT, OPERATION_ERROR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_OPERATION_ERROR_VIOLATION);	/* UNEXPECTED OPERATION_ERROR chunk */
  _(COOKIE_WAIT, COOKIE_ECHO, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_COOKIE_ECHO_VIOLATION);	/* UNEXPECTED COOKIE_ECHO chunk */
  _(COOKIE_WAIT, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(COOKIE_WAIT, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(COOKIE_WAIT, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(COOKIE_WAIT, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */
  _(COOKIE_WAIT, OPERATION_ERROR, SCTP_INPUT_NEXT_LISTEN_PHASE,
    SCTP_ERROR_NONE);

  _(COOKIE_ECHOED, DATA, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_NONE);
  _(COOKIE_ECHOED, INIT, SCTP_INPUT_NEXT_RCV_PHASE, SCTP_ERROR_NONE);	/* UNEXPECTED INIT chunk which requires special handling */
  _(COOKIE_ECHOED, INIT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED INIT_ACK chunk */
  _(COOKIE_ECHOED, SACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SACK_CHUNK_VIOLATION);	/* UNEXPECTED SACK chunk */
  _(COOKIE_ECHOED, HEARTBEAT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT chunk */
  _(COOKIE_ECHOED, HEARTBEAT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_ACK_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT_ACK chunk */
  _(COOKIE_ECHOED, ABORT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ABORT_CHUNK_VIOLATION);	/* UNEXPECTED ABORT chunk */
  _(COOKIE_ECHOED, SHUTDOWN, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN chunk */
  _(COOKIE_ECHOED, SHUTDOWN_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_ACK_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN_ACK chunk */
  _(COOKIE_ECHOED, OPERATION_ERROR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_OPERATION_ERROR_VIOLATION);	/* UNEXPECTED OPERATION_ERROR chunk */
  _(COOKIE_ECHOED, COOKIE_ECHO, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_COOKIE_ECHO_VIOLATION);	/* UNEXPECTED COOKIE_ECHO chunk */
  _(COOKIE_ECHOED, COOKIE_ACK, SCTP_INPUT_NEXT_ESTABLISHED_PHASE,
    SCTP_ERROR_NONE);
  _(COOKIE_ECHOED, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(COOKIE_ECHOED, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(COOKIE_ECHOED, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */
  _(COOKIE_ECHOED, OPERATION_ERROR, SCTP_INPUT_NEXT_LISTEN_PHASE,
    SCTP_ERROR_NONE);

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
  _(ESTABLISHED, OPERATION_ERROR, SCTP_INPUT_NEXT_LISTEN_PHASE,
    SCTP_ERROR_NONE);

  _(SHUTDOWN_PENDING, DATA, SCTP_INPUT_NEXT_SHUTDOWN_PHASE, SCTP_ERROR_NONE);
  _(SHUTDOWN_PENDING, INIT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_INIT_CHUNK_VIOLATION);	/* UNEXPECTED INIT chunk */
  _(SHUTDOWN_PENDING, INIT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED INIT_ACK chunk */
  _(SHUTDOWN_PENDING, SACK, SCTP_INPUT_NEXT_LISTEN_PHASE, SCTP_ERROR_NONE);
  _(SHUTDOWN_PENDING, HEARTBEAT, SCTP_INPUT_NEXT_LISTEN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_PENDING, HEARTBEAT_ACK, SCTP_INPUT_NEXT_LISTEN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_PENDING, ABORT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ABORT_CHUNK_VIOLATION);	/* UNEXPECTED ABORT chunk */
  _(SHUTDOWN_PENDING, SHUTDOWN, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_PENDING, SHUTDOWN_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_ACK_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN_ACK chunk */
  _(SHUTDOWN_PENDING, OPERATION_ERROR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_OPERATION_ERROR_VIOLATION);	/* UNEXPECTED OPERATION_ERROR chunk */
  _(SHUTDOWN_PENDING, COOKIE_ECHO, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_PENDING, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(SHUTDOWN_PENDING, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(SHUTDOWN_PENDING, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(SHUTDOWN_PENDING, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */
  _(SHUTDOWN_PENDING, OPERATION_ERROR, SCTP_INPUT_NEXT_LISTEN_PHASE,
    SCTP_ERROR_NONE);

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
  _(SHUTDOWN_SENT, COOKIE_ECHO, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_SENT, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(SHUTDOWN_SENT, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(SHUTDOWN_SENT, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(SHUTDOWN_SENT, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */
  _(SHUTDOWN_SENT, OPERATION_ERROR, SCTP_INPUT_NEXT_LISTEN_PHASE,
    SCTP_ERROR_NONE);

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
  _(SHUTDOWN_RECEIVED, COOKIE_ECHO, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_RECEIVED, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(SHUTDOWN_RECEIVED, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(SHUTDOWN_RECEIVED, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(SHUTDOWN_RECEIVED, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_COMPLETE_VIOLATION);	/* UNEXPECTED SHUTDOWN_COMPLETE chunk */
  _(SHUTDOWN_RECEIVED, OPERATION_ERROR, SCTP_INPUT_NEXT_LISTEN_PHASE,
    SCTP_ERROR_NONE);

  _(SHUTDOWN_ACK_SENT, DATA, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_DATA_CHUNK_VIOLATION);	/* UNEXPECTED DATA chunk */
  _(SHUTDOWN_ACK_SENT, INIT, SCTP_INPUT_NEXT_RCV_PHASE, SCTP_ERROR_NONE);	/* UNEXPECTED INIT chunk */
  _(SHUTDOWN_ACK_SENT, INIT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED INIT_ACK chunk */
  _(SHUTDOWN_ACK_SENT, SACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SACK_CHUNK_VIOLATION);	/* UNEXPECTED INIT chunk */
  _(SHUTDOWN_ACK_SENT, HEARTBEAT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT chunk */
  _(SHUTDOWN_ACK_SENT, HEARTBEAT_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_HEARTBEAT_ACK_CHUNK_VIOLATION);	/* UNEXPECTED HEARTBEAT_ACK chunk */
  _(SHUTDOWN_ACK_SENT, ABORT, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ABORT_CHUNK_VIOLATION);	/* UNEXPECTED ABORT chunk */
  _(SHUTDOWN_ACK_SENT, SHUTDOWN, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN chunk */
  _(SHUTDOWN_ACK_SENT, SHUTDOWN_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_SHUTDOWN_ACK_CHUNK_VIOLATION);	/* UNEXPECTED SHUTDOWN_ACK chunk */
  _(SHUTDOWN_ACK_SENT, COOKIE_ECHO, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_ACK_SENT, COOKIE_ACK, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ACK_DUP);	/* UNEXPECTED COOKIE_ACK chunk */
  _(SHUTDOWN_ACK_SENT, ECNE, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_ECNE_VIOLATION);	/* UNEXPECTED ECNE chunk */
  _(SHUTDOWN_ACK_SENT, CWR, SCTP_INPUT_NEXT_DROP, SCTP_ERROR_CWR_VIOLATION);	/* UNEXPECTED CWR chunk */
  _(SHUTDOWN_ACK_SENT, SHUTDOWN_COMPLETE, SCTP_INPUT_NEXT_SHUTDOWN_PHASE,
    SCTP_ERROR_NONE);
  _(SHUTDOWN_ACK_SENT, OPERATION_ERROR, SCTP_INPUT_NEXT_LISTEN_PHASE,
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
