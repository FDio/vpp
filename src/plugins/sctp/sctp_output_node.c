/*
 * Copyright (c) 2018 SUSE LLC.
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
#include <sctp/sctp.h>
#include <sctp/sctp_debug.h>
#include <vppinfra/random.h>
#include <openssl/hmac.h>

u32
ip6_sctp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
			   ip6_header_t * ip0, int *bogus_lengthp);

u32
ip4_sctp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
			   ip4_header_t * ip0);

#define foreach_sctp4_output_next              	\
  _ (DROP, "error-drop")                        \
  _ (IP_LOOKUP, "ip4-lookup")

#define foreach_sctp6_output_next              	\
  _ (DROP, "error-drop")                        \
  _ (IP_LOOKUP, "ip6-lookup")

static char *sctp_error_strings[] = {
#define sctp_error(n,s) s,
#include <sctp/sctp_error.def>
#undef sctp_error
};

typedef enum _sctp_output_next
{
  SCTP_OUTPUT_NEXT_DROP,
  SCTP_OUTPUT_NEXT_IP_LOOKUP,
  SCTP_OUTPUT_N_NEXT
} sctp_output_next_t;

typedef struct
{
  sctp_header_t sctp_header;
  sctp_connection_t sctp_connection;
} sctp_tx_trace_t;

always_inline u8
sctp_is_retransmitting (sctp_connection_t * sctp_conn, u8 idx)
{
  return sctp_conn->sub_conn[idx].is_retransmitting;
}

always_inline uword
sctp46_output_inline (vlib_main_t * vm,
		      vlib_node_runtime_t * node,
		      vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->thread_index;

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
	  u32 bi0;
	  vlib_buffer_t *b0;
	  sctp_header_t *sctp_hdr = 0;
	  sctp_connection_t *sctp_conn;
	  sctp_tx_trace_t *t0;
	  sctp_header_t *th0 = 0;
	  u32 error0 = SCTP_ERROR_PKTS_SENT, next0 =
	    SCTP_OUTPUT_NEXT_IP_LOOKUP;

#if SCTP_DEBUG_STATE_MACHINE
	  u16 packet_length = 0;
#endif

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sctp_conn =
	    sctp_connection_get (sctp_buffer_opaque (b0)->
				 sctp.connection_index, my_thread_index);

	  if (PREDICT_FALSE (sctp_conn == 0))
	    {
	      error0 = SCTP_ERROR_INVALID_CONNECTION;
	      next0 = SCTP_OUTPUT_NEXT_DROP;
	      goto done;
	    }

	  u8 idx = sctp_buffer_opaque (b0)->sctp.subconn_idx;

	  th0 = vlib_buffer_get_current (b0);

	  if (is_ip4)
	    {
	      ip4_header_t *iph4 = vlib_buffer_push_ip4 (vm,
							 b0,
							 &sctp_conn->sub_conn
							 [idx].connection.
							 lcl_ip.ip4,
							 &sctp_conn->
							 sub_conn
							 [idx].connection.
							 rmt_ip.ip4,
							 IP_PROTOCOL_SCTP, 1);

	      u32 checksum = ip4_sctp_compute_checksum (vm, b0, iph4);

	      sctp_hdr = ip4_next_header (iph4);
	      sctp_hdr->checksum = checksum;

	      vnet_buffer (b0)->l4_hdr_offset = (u8 *) th0 - b0->data;

#if SCTP_DEBUG_STATE_MACHINE
	      packet_length = clib_net_to_host_u16 (iph4->length);
#endif
	    }
	  else
	    {
	      ip6_header_t *iph6 = vlib_buffer_push_ip6 (vm,
							 b0,
							 &sctp_conn->sub_conn
							 [idx].
							 connection.lcl_ip.
							 ip6,
							 &sctp_conn->sub_conn
							 [idx].
							 connection.rmt_ip.
							 ip6,
							 IP_PROTOCOL_SCTP);

	      int bogus = ~0;
	      u32 checksum = ip6_sctp_compute_checksum (vm, b0, iph6, &bogus);
	      ASSERT (!bogus);

	      sctp_hdr = ip6_next_header (iph6);
	      sctp_hdr->checksum = checksum;

	      vnet_buffer (b0)->l3_hdr_offset = (u8 *) iph6 - b0->data;
	      vnet_buffer (b0)->l4_hdr_offset = (u8 *) th0 - b0->data;

#if SCTP_DEBUG_STATE_MACHINE
	      packet_length = clib_net_to_host_u16 (iph6->payload_length);
#endif
	    }

	  sctp_full_hdr_t *full_hdr = (sctp_full_hdr_t *) sctp_hdr;
	  u8 chunk_type = vnet_sctp_get_chunk_type (&full_hdr->common_hdr);
	  if (chunk_type >= UNKNOWN)
	    {
	      clib_warning
		("Trying to send an unrecognized chunk... something is really bad.");
	      error0 = SCTP_ERROR_UNKNOWN_CHUNK;
	      next0 = SCTP_OUTPUT_NEXT_DROP;
	      goto done;
	    }

#if SCTP_DEBUG_STATE_MACHINE
	  u8 is_valid =
	    (sctp_conn->sub_conn[idx].connection.lcl_port ==
	     sctp_hdr->src_port
	     || sctp_conn->sub_conn[idx].connection.lcl_port ==
	     sctp_hdr->dst_port)
	    && (sctp_conn->sub_conn[idx].connection.rmt_port ==
		sctp_hdr->dst_port
		|| sctp_conn->sub_conn[idx].connection.rmt_port ==
		sctp_hdr->src_port);

	  if (!is_valid)
	    {
	      SCTP_DBG_STATE_MACHINE ("BUFFER IS INCORRECT: conn_index = %u, "
				      "packet_length = %u, "
				      "chunk_type = %u [%s], "
				      "connection.lcl_port = %u, sctp_hdr->src_port = %u, "
				      "connection.rmt_port = %u, sctp_hdr->dst_port = %u",
				      sctp_conn->sub_conn[idx].
				      connection.c_index, packet_length,
				      chunk_type,
				      sctp_chunk_to_string (chunk_type),
				      sctp_conn->sub_conn[idx].
				      connection.lcl_port, sctp_hdr->src_port,
				      sctp_conn->sub_conn[idx].
				      connection.rmt_port,
				      sctp_hdr->dst_port);

	      error0 = SCTP_ERROR_UNKNOWN_CHUNK;
	      next0 = SCTP_OUTPUT_NEXT_DROP;
	      goto done;
	    }
#endif
	  SCTP_DBG_STATE_MACHINE
	    ("SESSION_INDEX = %u, CONN_INDEX = %u, CURR_CONN_STATE = %u (%s), "
	     "CHUNK_TYPE = %s, " "SRC_PORT = %u, DST_PORT = %u",
	     sctp_conn->sub_conn[idx].connection.s_index,
	     sctp_conn->sub_conn[idx].connection.c_index,
	     sctp_conn->state, sctp_state_to_string (sctp_conn->state),
	     sctp_chunk_to_string (chunk_type), full_hdr->hdr.src_port,
	     full_hdr->hdr.dst_port);

	  /* Let's make sure the state-machine does not send anything crazy */
#if SCTP_DEBUG_STATE_MACHINE
	  if (sctp_validate_output_state_machine (sctp_conn, chunk_type) != 0)
	    {
	      SCTP_DBG_STATE_MACHINE
		("Sending the wrong chunk (%s) based on state-machine status (%s)",
		 sctp_chunk_to_string (chunk_type),
		 sctp_state_to_string (sctp_conn->state));

	      error0 = SCTP_ERROR_UNKNOWN_CHUNK;
	      next0 = SCTP_OUTPUT_NEXT_DROP;
	      goto done;

	    }
#endif

	  /* Karn's algorithm: RTT measurements MUST NOT be made using
	   * packets that were retransmitted
	   */
	  if (!sctp_is_retransmitting (sctp_conn, idx))
	    {
	      /* Measure RTT with this */
	      if (chunk_type == DATA
		  && sctp_conn->sub_conn[idx].RTO_pending == 0)
		{
		  sctp_conn->sub_conn[idx].RTO_pending = 1;
		  sctp_conn->sub_conn[idx].rtt_ts = sctp_time_now ();
		}
	      else
		sctp_conn->sub_conn[idx].rtt_ts = sctp_time_now ();
	    }

	  /* Let's take care of TIMERS */
	  switch (chunk_type)
	    {
	    case COOKIE_ECHO:
	      {
		sctp_conn->state = SCTP_STATE_COOKIE_ECHOED;
		break;
	      }
	    case DATA:
	      {
		SCTP_ADV_DBG_OUTPUT ("PACKET_LENGTH = %u", packet_length);

		sctp_timer_update (sctp_conn, idx, SCTP_TIMER_T3_RXTX,
				   sctp_conn->sub_conn[idx].RTO);
		break;
	      }
	    case SHUTDOWN:
	      {
		/* Start the SCTP_TIMER_T2_SHUTDOWN timer */
		sctp_timer_set (sctp_conn, idx, SCTP_TIMER_T2_SHUTDOWN,
				sctp_conn->sub_conn[idx].RTO);
		sctp_conn->state = SCTP_STATE_SHUTDOWN_SENT;
		break;
	      }
	    case SHUTDOWN_ACK:
	      {
		/* Start the SCTP_TIMER_T2_SHUTDOWN timer */
		sctp_timer_set (sctp_conn, idx, SCTP_TIMER_T2_SHUTDOWN,
				sctp_conn->sub_conn[idx].RTO);
		sctp_conn->state = SCTP_STATE_SHUTDOWN_ACK_SENT;
		break;
	      }
	    case SHUTDOWN_COMPLETE:
	      {
		sctp_conn->state = SCTP_STATE_CLOSED;
		break;
	      }
	    }

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
	    sctp_conn->sub_conn[idx].c_fib_index;

	  b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

	  SCTP_DBG_STATE_MACHINE
	    ("SESSION_INDEX = %u, CONNECTION_INDEX = %u, " "NEW_STATE = %s, "
	     "CHUNK_SENT = %s", sctp_conn->sub_conn[idx].connection.s_index,
	     sctp_conn->sub_conn[idx].connection.c_index,
	     sctp_state_to_string (sctp_conn->state),
	     sctp_chunk_to_string (chunk_type));

	  vnet_sctp_common_hdr_params_host_to_net (&full_hdr->common_hdr);

	done:
	  b0->error = node->errors[error0];
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      if (th0)
		{
		  clib_memcpy_fast (&t0->sctp_header, th0,
				    sizeof (t0->sctp_header));
		}
	      else
		{
		  clib_memset (&t0->sctp_header, 0, sizeof (t0->sctp_header));
		}
	      clib_memcpy_fast (&t0->sctp_connection, sctp_conn,
				sizeof (t0->sctp_connection));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (sctp4_output_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return sctp46_output_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

VLIB_NODE_FN (sctp6_output_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return sctp46_output_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp4_output_node) =
{
    .name = "sctp4-output",
    /* Takes a vector of packets. */
    .vector_size = sizeof (u32),
    .n_errors = SCTP_N_ERROR,
    .error_strings = sctp_error_strings,
    .n_next_nodes = SCTP_OUTPUT_N_NEXT,
    .next_nodes = {
#define _(s,n) [SCTP_OUTPUT_NEXT_##s] = n,
    foreach_sctp4_output_next
#undef _
    },
    .format_buffer = format_sctp_header,
    .format_trace = format_sctp_tx_trace,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sctp6_output_node) =
{
  .name = "sctp6-output",
    /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = SCTP_N_ERROR,
  .error_strings = sctp_error_strings,
  .n_next_nodes = SCTP_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [SCTP_OUTPUT_NEXT_##s] = n,
    foreach_sctp6_output_next
#undef _
  },
  .format_buffer = format_sctp_header,
  .format_trace = format_sctp_tx_trace,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
