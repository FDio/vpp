/*
 * Copyright (c) 2024 Cisco and/or its affiliates.
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
#include <vppinfra/error.h>
#include <pvti/pvti.h>
#include <pvti/pvti_if.h>
#include <pvti/input.h>

always_inline void
pvti_enqueue_rx_bi_to_next_and_trace (vlib_main_t *vm,
				      vlib_node_runtime_t *node,
				      pvti_per_thread_data_t *ptd, u32 bi0,
				      u16 next0)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

  if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next0, b0,
				       /* follow_chain */ 0)))
    {
      pvti_input_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
      t->next_index = next0;
      t->trace_type = PVTI_INPUT_TRACE_decap;
      clib_memcpy (t->packet_data, vlib_buffer_get_current (b0),
		   sizeof (t->packet_data));
    }
  vec_add1 (ptd->pending_rx_buffers, bi0);
  vec_add1 (ptd->pending_rx_nexts, next0);
}

always_inline pvti_rx_peer_t *
pvti_try_find_or_create_rx_peer (pvti_per_thread_data_t *ptd,
				 vlib_buffer_t *b0, bool is_ip6)
{
  pvti_rx_peer_t *peer;

  ip_address_t remote_ip = { 0 };
  u16 remote_port;
  if (is_ip6)
    {
      pvti_ip6_encap_header_t *h0 =
	((pvti_ip6_encap_header_t *) vlib_buffer_get_current (b0)) - 1;
      ip_address_set (&remote_ip, &h0->ip6.src_address, AF_IP6);
      remote_port = clib_net_to_host_u16 (h0->udp.src_port);
    }
  else
    {
      pvti_ip4_encap_header_t *h0 =
	((pvti_ip4_encap_header_t *) vlib_buffer_get_current (b0)) - 1;
      ip_address_set (&remote_ip, &h0->ip4.src_address, AF_IP4);
      remote_port = clib_net_to_host_u16 (h0->udp.src_port);
    }

  pool_foreach (peer, ptd->rx_peers)
    {
      if (peer->remote_port == remote_port &&
	  0 == ip_address_cmp (&remote_ip, &peer->remote_ip))
	{
	  if (peer->deleted)
	    {
	      // The peer has been marked as deleted - wipe it.
	      clib_memset (peer, 0xca, sizeof (*peer));
	      pool_put (ptd->rx_peers, peer);
	      continue;
	    }
	  return peer;
	}
    }

  index_t pvti_if_index0 =
    pvti_if_find_by_remote_ip_and_port (&remote_ip, remote_port);
  if (INDEX_INVALID == pvti_if_index0)
    {
      // no suitable interface found, bail
      return 0;
    }
  pvti_if_t *pvti_if0 = pvti_if_get (pvti_if_index0);

  pvti_rx_peer_t new_peer = {
    .local_ip = pvti_if0->local_ip,
    .local_port = pvti_if0->local_port,
    .remote_ip = remote_ip,
    .remote_port = remote_port,
    .pvti_if_index = pvti_if_index0,
    .rx_streams = { { 0 } },
  };
  pvti_rx_peer_t *rx_new_peer;
  pool_get (ptd->rx_peers, rx_new_peer);
  *rx_new_peer = new_peer;

  int i;
  for (i = 0; i < MAX_RX_STREAMS; i++)
    {
      rx_new_peer->rx_streams[i].rx_bi0 = INDEX_INVALID;
      rx_new_peer->rx_streams[i].rx_bi0_first = INDEX_INVALID;
      rx_new_peer->rx_streams[i].rx_next0 = 0;
    }

  return rx_new_peer;
}

always_inline u16
pvti_input_node_common (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame, bool is_ip6)
{
  u32 n_left_from, *from;
  pvti_chunk_header_t *chunks[MAX_CHUNKS];
  u32 pkts_processed = 0;
  u32 pkts_decapsulated = 0;
  u32 decap_failed_no_buffers = 0;

  pvti_main_t *pvm = &pvti_main;

  clib_thread_index_t thread_index = vlib_get_thread_index ();
  pvti_per_thread_data_t *ptd =
    vec_elt_at_index (pvm->per_thread_data[is_ip6], thread_index);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0 = PVTI_INPUT_NEXT_DROP;
      u32 sw_if_index0;
      u8 true_chunk_count = 0;
      u8 max_chunk_count;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      pvti_ip4_encap_header_t *h0 =
	((pvti_ip4_encap_header_t *) vlib_buffer_get_current (b0)) - 1;
      pvti_rx_peer_t *pvti_rx_peer0 =
	pvti_try_find_or_create_rx_peer (ptd, b0, is_ip6);
      if (!pvti_rx_peer0)
	{
	  b0->error = node->errors[PVTI_INPUT_ERROR_PEER];
	  goto drop_and_maybe_trace;
	}

      b0 = vlib_get_buffer (vm, bi0);
      pvti_packet_header_t *pvti0 = vlib_buffer_get_current (b0);
      u8 stream_index = pvti0->stream_index;
      max_chunk_count =
	pvti0->chunk_count < MAX_CHUNKS ? pvti0->chunk_count : MAX_CHUNKS;
      u16 pvti_packet_header_sz0 =
	pvti0->pad_bytes + offsetof (pvti_packet_header_t, pad);
      if (b0->current_length < pvti_packet_header_sz0)
	{
	  b0->error = node->errors[PVTI_INPUT_ERROR_PACKET_TOO_SHORT];
	  goto drop_and_maybe_trace;
	}
      vlib_buffer_advance (b0, pvti_packet_header_sz0);

      if (max_chunk_count == 0)
	{
	  b0->error = node->errors[PVTI_INPUT_ERROR_NOCHUNKS];
	  goto drop_and_maybe_trace;
	}
      if (pvti0->reass_chunk_count > max_chunk_count)
	{
	  b0->error = node->errors[PVTI_INPUT_ERROR_TOOMANYREASS];
	  goto drop_and_maybe_trace;
	}
      pvti_per_rx_stream_data_t *rx_stream0 =
	&pvti_rx_peer0->rx_streams[stream_index];

      u32 new_seq0 = clib_net_to_host_u32 (pvti0->seq);
      if (new_seq0 == rx_stream0->last_rx_seq + 1)
	{
	  /* Sequence# matches, we can attempt adding the leading chunks to
	   * reassembly */
	  rx_stream0->last_rx_seq = new_seq0;

	  while ((b0->current_length > 0) &&
		 true_chunk_count < pvti0->reass_chunk_count)
	    {
	      /* attempt to either incorporate the first chunk into
	       * reassembly or skip it. */
	      pvti_chunk_header_t *pvc0 = vlib_buffer_get_current (b0);
	      const u16 chunk_payload_length =
		clib_net_to_host_u16 (pvc0->total_chunk_length) -
		sizeof (*pvc0);
	      vlib_buffer_advance (b0, sizeof (*pvc0));

	      if (rx_stream0->rx_bi0 == INDEX_INVALID)
		{
		  clib_warning (
		    "RX internal error: not-first chunk but no wip block");
		}
	      else
		{

		  vlib_buffer_t *rb0 =
		    vlib_get_buffer (vm, rx_stream0->rx_bi0);
		  u16 allowed_length =
		    PVTI_RX_MAX_LENGTH - rb0->current_length;
		  if (allowed_length > chunk_payload_length)
		    {
		      // simple case - there is space in the buffer to fit
		      // the whole chunk
		      void *tail =
			vlib_buffer_put_uninit (rb0, chunk_payload_length);
		      clib_memcpy (tail, vlib_buffer_get_current (b0),
				   chunk_payload_length);
		    }
		  else
		    {
		      // The current chunk can not fit - need to make two
		      // copies, one into the current buffer, and one into
		      // a newly allocated chained buffer.
		      void *tail =
			vlib_buffer_put_uninit (rb0, allowed_length);
		      clib_memcpy (tail, vlib_buffer_get_current (b0),
				   allowed_length);
		      u16 remaining_payload_length =
			chunk_payload_length - allowed_length;
		      u32 nrbi0 = pvti_get_new_buffer (vm);
		      if (INDEX_INVALID == nrbi0)
			{
			  ASSERT (0); // FIXME what the recovery is
				      // supposed to look like ?
			}
		      else
			{
			  // link up the new buffer and copy the remainder
			  // there
			  vlib_buffer_t *nrb0 = vlib_get_buffer (vm, nrbi0);
			  rb0->flags |= VLIB_BUFFER_NEXT_PRESENT;
			  rb0->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
			  rb0->next_buffer = nrbi0;
			  rx_stream0->rx_bi0 = nrbi0;
			  void *tail = vlib_buffer_put_uninit (
			    nrb0, remaining_payload_length);
			  clib_memcpy (tail,
				       vlib_buffer_get_current (b0) +
					 allowed_length,
				       remaining_payload_length);
			}
		    }
		  pvti_rx_peer0->rx_streams[stream_index]
		    .rx_received_inner_length += chunk_payload_length;
		  if (pvti_rx_peer0->rx_streams[stream_index]
			.rx_received_inner_length ==
		      pvti_rx_peer0->rx_streams[stream_index]
			.rx_expected_inner_length)
		    {
		      next0 = rx_stream0->rx_next0;
		      pvti_enqueue_rx_bi_to_next_and_trace (
			vm, node, ptd, rx_stream0->rx_bi0_first, next0);
		      pkts_decapsulated += 1;

		      // clean out the current reassemly state
		      rx_stream0->rx_bi0 = INDEX_INVALID;
		      rx_stream0->rx_bi0_first = INDEX_INVALID;
		      pvti_rx_peer0->rx_streams[stream_index]
			.rx_received_inner_length = 0;
		      pvti_rx_peer0->rx_streams[stream_index]
			.rx_expected_inner_length = 0;
		      rx_stream0->rx_next0 = 0;
		    }
		}
	      chunks[true_chunk_count] = pvc0;
	      true_chunk_count += 1;
	      vlib_buffer_advance (b0, chunk_payload_length);
	    }
	}
      else
	{
	  /* Sequence does not match, skip the reassembly chunks and reset
	   * the reassembly state */

	  while ((b0->current_length > 0) &&
		 true_chunk_count < pvti0->reass_chunk_count)
	    {
	      /* skip the reassembly chunks */
	      pvti_chunk_header_t *pvc0 = vlib_buffer_get_current (b0);
	      chunks[true_chunk_count] = pvc0;
	      true_chunk_count += 1;
	      vlib_buffer_advance (
		b0, clib_net_to_host_u16 (pvc0->total_chunk_length));
	    }
	  // FIXME: discard the current reassembly state, reset the seq#
	  if (rx_stream0->rx_bi0_first != INDEX_INVALID)
	    {
	      clib_warning ("RX PVTI: discard chunk being reassembled");
	      vlib_buffer_free_one (vm, rx_stream0->rx_bi0_first);
	      rx_stream0->rx_bi0 = INDEX_INVALID;
	      rx_stream0->rx_bi0_first = INDEX_INVALID;
	      rx_stream0->rx_received_inner_length = 0;
	      rx_stream0->rx_expected_inner_length = 0;
	      rx_stream0->rx_next0 = 0;
	    }
	}

      while ((b0->current_length > 0) && true_chunk_count < max_chunk_count)
	{
	  if (b0->current_length < sizeof (pvti_chunk_header_t))
	    {
	      clib_warning ("RX ERR: length too short for a chunk");
	      break;
	    }
	  pvti_chunk_header_t *pvc0 = vlib_buffer_get_current (b0);
	  chunks[true_chunk_count] = pvc0;
	  true_chunk_count += 1;
	  u16 total_chunk_length =
	    clib_net_to_host_u16 (pvc0->total_chunk_length);
	  if (b0->current_length < total_chunk_length)
	    {
	      clib_warning ("RX ERR: length 0x%x too big for a chunk",
			    true_chunk_count);
	      break;
	    }
	  u8 *pkt = (u8 *) (pvc0 + 1);
	  u16 inner_length;
	  if (rx_stream0->rx_bi0_first != INDEX_INVALID)
	    {
	      vlib_buffer_free_one (vm, rx_stream0->rx_bi0_first);
	      rx_stream0->rx_bi0 = INDEX_INVALID;
	      rx_stream0->rx_bi0_first = INDEX_INVALID;
	      rx_stream0->rx_received_inner_length = 0;
	      rx_stream0->rx_expected_inner_length = 0;
	      rx_stream0->rx_next0 = 0;
	    }

	  switch (*pkt & 0xf0)
	    {
	    case 0x40:
	      next0 = PVTI_INPUT_NEXT_IP4_INPUT;
	      inner_length = clib_net_to_host_u16 (*((u16 *) (pkt + 2)));
	      break;
	    case 0x60:
	      next0 = PVTI_INPUT_NEXT_IP6_INPUT;
	      inner_length = clib_net_to_host_u16 (*((u16 *) (pkt + 4))) +
			     sizeof (ip6_header_t);
	      break;
	    default:
	      next0 = PVTI_INPUT_NEXT_DROP;
	      vlib_buffer_advance (b0, total_chunk_length);
	      continue;
	    }
	  vlib_buffer_advance (b0, sizeof (pvti_chunk_header_t));

	  if (inner_length + sizeof (pvti_chunk_header_t) > total_chunk_length)
	    {
	      /* FIXME: the packet size is larger than the chunk -> it's a
	       * first fragment */
	      // enqueue the chunk and finish packet processing.
	      // There must be no active reassembly.
	      ASSERT (rx_stream0->rx_bi0_first == INDEX_INVALID);
	      rx_stream0->rx_next0 = next0;
	      rx_stream0->rx_bi0 = bi0;
	      rx_stream0->rx_bi0_first = bi0;
	      rx_stream0->rx_expected_inner_length = inner_length;
	      rx_stream0->rx_received_inner_length =
		total_chunk_length - sizeof (pvti_chunk_header_t);
	      rx_stream0->last_rx_seq = new_seq0;
	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
				 (b0->flags & VLIB_BUFFER_IS_TRACED)))
		{
		  pvti_input_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->next_index = ~0;
		  t->trace_type = PVTI_INPUT_TRACE_enqueue;
		  clib_memcpy (t->packet_data, vlib_buffer_get_current (b0),
			       sizeof (t->packet_data));
		}
	      goto continue_outer;
	    }

	  u32 nbi0 = pvti_get_new_buffer (vm);
	  if (INDEX_INVALID == nbi0)
	    {
	      decap_failed_no_buffers += 1;
	      continue;
	    };
	  vlib_buffer_t *nb0 = vlib_get_buffer (vm, nbi0);
	  pvti_if_t *pvti_if0 = pvti_if_get (pvti_rx_peer0->pvti_if_index);
	  vnet_buffer (nb0)->sw_if_index[VLIB_RX] = pvti_if0->sw_if_index;
	  void *new_packet = vlib_buffer_put_uninit (nb0, inner_length);
	  clib_memcpy (new_packet, pvc0 + 1, inner_length);
	  vlib_buffer_advance (b0, inner_length);

	  pvti_enqueue_rx_bi_to_next_and_trace (vm, node, ptd, nbi0, next0);
	  pkts_decapsulated += 1;
	}
      /* we have processed all the chunks from the buffer, but the buffer
       * remains. Free it. */
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  pvti_input_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->next_index = ~0;
	  t->trace_type = PVTI_INPUT_TRACE_free;
	  t->seq = clib_net_to_host_u32 (pvti0->seq);
	  t->chunk_count = pvti0->chunk_count;
	  u8 chunk_count =
	    pvti0->chunk_count < MAX_CHUNKS ? pvti0->chunk_count : MAX_CHUNKS;
	  for (int i = 0; i < chunk_count; i++)
	    {
	      t->chunks[i].total_chunk_length =
		clib_net_to_host_u16 (chunks[i]->total_chunk_length);
	    }
	  clib_memcpy (t->packet_data, vlib_buffer_get_current (b0),
		       sizeof (t->packet_data));
	}
      vlib_buffer_free_one (vm, bi0);

    continue_outer:
      pkts_processed += 1;
      continue;

    drop_and_maybe_trace:
      next0 = PVTI_INPUT_NEXT_DROP;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  int i;
	  pvti_input_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->trace_type = PVTI_INPUT_TRACE_drop;
	  t->next_index = next0;
	  t->remote_ip.ip.ip4 = h0->ip4.src_address;
	  t->remote_ip.version = AF_IP4;
	  t->local_port = h0->udp.dst_port;
	  t->remote_port = h0->udp.src_port;
	  if (!pvti_rx_peer0)
	    {
	      t->seq = 0xdeaddead;
	    }
	  else
	    {
	      t->seq = clib_net_to_host_u32 (pvti0->seq);
	      t->chunk_count = pvti0->chunk_count;
	      u8 chunk_count = pvti0->chunk_count < MAX_CHUNKS ?
				 pvti0->chunk_count :
				 MAX_CHUNKS;
	      for (i = 0; i < chunk_count; i++)
		{
		  t->chunks[i].total_chunk_length =
		    clib_net_to_host_u16 (chunks[i]->total_chunk_length);
		}
	    }
	}

      pkts_processed += 1;
      vec_add1 (ptd->pending_rx_buffers, bi0);
      vec_add1 (ptd->pending_rx_nexts, next0);
    }

  vlib_buffer_enqueue_to_next_vec (vm, node, &ptd->pending_rx_buffers,
				   &ptd->pending_rx_nexts,
				   vec_len (ptd->pending_rx_nexts));
  vec_reset_length (ptd->pending_rx_buffers);
  vec_reset_length (ptd->pending_rx_nexts);

  vlib_node_increment_counter (vm, node->node_index,
			       PVTI_INPUT_ERROR_PROCESSED, pkts_processed);
  vlib_node_increment_counter (
    vm, node->node_index, PVTI_INPUT_ERROR_DECAPSULATED, pkts_decapsulated);
  vlib_node_increment_counter (vm, node->node_index,
			       PVTI_INPUT_ERROR_NO_BUFFERS,
			       decap_failed_no_buffers);
  return frame->n_vectors;
}

VLIB_NODE_FN (pvti4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return pvti_input_node_common (vm, node, frame, 0);
}

VLIB_NODE_FN (pvti6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return pvti_input_node_common (vm, node, frame, 1);
}
