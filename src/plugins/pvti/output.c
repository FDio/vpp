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
#include <pvti/output.h>

static_always_inline u32
ip6_vtcfl (u8 stream_index)
{
  u32 vtcfl = 0x6 << 28;
  vtcfl |= stream_index;

  return (clib_host_to_net_u32 (vtcfl));
}

always_inline vlib_buffer_t *
pvti_alloc_new_tx_buffer (vlib_main_t *vm)
{
  u32 bi0 = INDEX_INVALID;
  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    {
      return 0;
    }
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  b0->current_data = 0;
  b0->current_length = 0;
  return b0;
}

always_inline bool
pvti_find_or_try_create_tx_peer (vlib_main_t *vm, pvti_per_thread_data_t *ptd,
				 pvti_if_t *pvti_if0, ip_address_t *remote_ip,
				 u16 remote_port, u32 *out_index)
{

  pvti_tx_peer_t *peer;
  pool_foreach (peer, ptd->tx_peers)
    {
      if (peer->remote_port == remote_port &&
	  0 == ip_address_cmp (remote_ip, &peer->remote_ip))
	{
	  if (peer->deleted)
	    {
	      // Bad luck, the peer has been deleted.
	      u32 boi0 = vlib_get_buffer_index (vm, peer->bo0);
	      if (peer->bo0)
		{
		  vlib_buffer_free (vm, &boi0, 1);
		}
	      clib_memset (peer, 0xca, sizeof (*peer));
	      pool_put (ptd->tx_peers, peer);
	      continue;
	    }
	  *out_index = peer - ptd->tx_peers;
	  return 1;
	}
    }

  ip_address_family_t dst_ver = ip_addr_version (&pvti_if0->remote_ip);

  u16 pvti_encap_overhead = (dst_ver == AF_IP6) ?
			      sizeof (pvti_ip6_encap_header_t) :
			      sizeof (pvti_ip4_encap_header_t);

  u16 pvti_packet_overhead =
    pvti_encap_overhead + sizeof (pvti_packet_header_t) + PVTI_ALIGN_BYTES;

  ASSERT (pvti_if0->underlay_mtu > pvti_packet_overhead);

  u32 bo0_max_current_length = pvti_if0->underlay_mtu - pvti_packet_overhead;

  vlib_buffer_t *bo0 = pvti_alloc_new_tx_buffer (vm);

  if (!bo0)
    {
      return 0;
    }

  pvti_tx_peer_t new_peer = {
    .local_ip = pvti_if0->local_ip,
    .remote_ip = *remote_ip,
    .local_port = pvti_if0->local_port,
    .remote_port = remote_port,
    .underlay_mtu = pvti_if0->underlay_mtu,
    .underlay_fib_index = pvti_if0->underlay_fib_index,
    .bo0_max_current_length = bo0_max_current_length,
    .pvti_if_index = pvti_if_get_index (pvti_if0),
    .deleted = 0,
    .bo0 = bo0,
    .chunk_count = 0,
    .reass_chunk_count = 0,
    .current_tx_seq = 42,
  };

  pvti_tx_peer_t *tx_new_peer;
  pool_get (ptd->tx_peers, tx_new_peer);

  *tx_new_peer = new_peer;
  *out_index = tx_new_peer - ptd->tx_peers;
  return 1;
}

always_inline bool
pvti_try_get_tx_peer_index (vlib_main_t *vm, pvti_per_thread_data_t *ptd,
			    pvti_if_t *pvti_if0, vlib_buffer_t *b0,
			    bool is_ip6, u32 *out_index)
{
  if (pvti_if0->peer_address_from_payload)
    {
      ip_address_t remote_ip = { 0 };
      if (is_ip6)
	{
	  ip6_header_t *ip6 = vlib_buffer_get_current (b0);
	  ip_address_set (&remote_ip, &ip6->dst_address, AF_IP6);
	}
      else
	{
	  ip4_header_t *ip4 = vlib_buffer_get_current (b0);
	  ip_address_set (&remote_ip, &ip4->dst_address, AF_IP4);
	}
      return pvti_find_or_try_create_tx_peer (
	vm, ptd, pvti_if0, &remote_ip, pvti_if0->remote_port, out_index);
    }
  else
    {
      return pvti_find_or_try_create_tx_peer (
	vm, ptd, pvti_if0, &pvti_if0->remote_ip, pvti_if0->remote_port,
	out_index);
    }
  /* not reached */
}

always_inline void
pvti_finalize_chunk (pvti_tx_peer_t *tx_peer,
		     pvti_chunk_header_t *chunk_header, u8 *tail,
		     bool is_reassembly_chunk)
{
  clib_memset (chunk_header, 0xab, sizeof (pvti_chunk_header_t));
  chunk_header->total_chunk_length =
    clib_host_to_net_u16 (tail - (u8 *) chunk_header);
  tx_peer->chunk_count++;
  if (is_reassembly_chunk)
    {
      tx_peer->reass_chunk_count++;
    }
}

always_inline pvti_output_next_t
encap_pvti_buffer_ip46 (vlib_main_t *vm, vlib_node_runtime_t *node,
			pvti_tx_peer_t *tx_peer, int is_ip6)
{
  ip_address_family_t src_ver = ip_addr_version (&tx_peer->local_ip);
  ip_address_family_t dst_ver = ip_addr_version (&tx_peer->remote_ip);
  u8 stream_index = 0;

  ASSERT (src_ver == dst_ver);
  bool is_ip6_encap = (AF_IP6 == src_ver);

  vlib_buffer_t *b0 = tx_peer->bo0;
  vlib_buffer_advance (b0,
		       -(sizeof (pvti_packet_header_t) + PVTI_ALIGN_BYTES));

  pvti_packet_header_t *pvti0 = vlib_buffer_get_current (b0);
  clib_memset (pvti0, 0xca, sizeof (*pvti0) + PVTI_ALIGN_BYTES);
  pvti0->pad_bytes = PVTI_ALIGN_BYTES;

  pvti0->seq = clib_host_to_net_u32 (tx_peer->current_tx_seq);
  pvti0->stream_index = stream_index;
  pvti0->reass_chunk_count = tx_peer->reass_chunk_count;
  pvti0->chunk_count = tx_peer->chunk_count;
  pvti0->mandatory_flags_mask = 0;
  pvti0->flags_value = 0;

  if (is_ip6_encap)
    {
      vlib_buffer_advance (b0, -(sizeof (pvti_ip6_encap_header_t)));
      if (b0->current_data < -VLIB_BUFFER_PRE_DATA_SIZE)
	{
	  // undo the change
	  vlib_buffer_advance (b0, (sizeof (pvti_ip6_encap_header_t)));
	  b0->error = node->errors[PVTI_OUTPUT_ERROR_NO_PRE_SPACE];
	  return PVTI_OUTPUT_NEXT_DROP;
	}
      pvti_ip6_encap_header_t *ve = vlib_buffer_get_current (b0);

      ve->udp.src_port = clib_host_to_net_u16 (tx_peer->local_port);
      ve->udp.dst_port = clib_host_to_net_u16 (tx_peer->remote_port);
      ve->udp.length = clib_host_to_net_u16 (
	b0->current_length - offsetof (pvti_ip6_encap_header_t, udp));
      ve->udp.checksum = 0;

      ve->ip6.ip_version_traffic_class_and_flow_label =
	ip6_vtcfl (stream_index);
      ve->ip6.payload_length = ve->udp.length;
      ve->ip6.protocol = 17;
      ve->ip6.hop_limit = 128;
      ip_address_copy_addr (&ve->ip6.src_address, &tx_peer->local_ip);
      ip_address_copy_addr (&ve->ip6.dst_address, &tx_peer->remote_ip);
    }
  else
    {
      vlib_buffer_advance (b0, -(sizeof (pvti_ip4_encap_header_t)));
      if (b0->current_data < -VLIB_BUFFER_PRE_DATA_SIZE)
	{
	  // undo the change
	  vlib_buffer_advance (b0, (sizeof (pvti_ip4_encap_header_t)));
	  b0->error = node->errors[PVTI_OUTPUT_ERROR_NO_PRE_SPACE];
	  return PVTI_OUTPUT_NEXT_DROP;
	}
      pvti_ip4_encap_header_t *ve = vlib_buffer_get_current (b0);

      ve->udp.src_port = clib_host_to_net_u16 (tx_peer->local_port);
      ve->udp.dst_port = clib_host_to_net_u16 (tx_peer->remote_port);
      ve->udp.length = clib_host_to_net_u16 (
	b0->current_length - offsetof (pvti_ip4_encap_header_t, udp));
      ve->udp.checksum = 0;

      ve->ip4.ip_version_and_header_length = 0x45;
      ve->ip4.tos = 0;
      ve->ip4.length = clib_host_to_net_u16 (b0->current_length);
      ve->ip4.fragment_id =
	clib_host_to_net_u16 (tx_peer->current_tx_seq & 0xffff);
      ve->ip4.flags_and_fragment_offset = 0;
      ve->ip4.ttl = 128;
      ve->ip4.protocol = 17;

      ve->ip4.dst_address.as_u32 = ip_addr_v4 (&tx_peer->remote_ip).data_u32;
      ve->ip4.src_address.as_u32 = ip_addr_v4 (&tx_peer->local_ip).data_u32;
      ve->ip4.checksum = ip4_header_checksum (&ve->ip4);
    }

  // This is important, if not reset, causes a crash
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = tx_peer->underlay_fib_index;

  // vnet_buffer (b0)->oflags |= VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
  return is_ip6_encap ? PVTI_OUTPUT_NEXT_IP6_LOOKUP :
			PVTI_OUTPUT_NEXT_IP4_LOOKUP;
}

always_inline void
pvti_enqueue_tx_and_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
			   pvti_per_thread_data_t *ptd, vlib_buffer_t *b0,
			   u16 next0, u8 stream_index, pvti_tx_peer_t *tx_peer)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
		     tx_peer->is_bo0_traced))
    {
      if (PREDICT_TRUE (
	    vlib_trace_buffer (vm, node, next0, b0, /* follow_chain */ 0)))
	{

	  pvti_output_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->next_index = next0;
	  t->underlay_mtu = tx_peer->underlay_mtu;
	  t->stream_index = stream_index;
	  t->trace_type = 1;
	  t->bi0_max_current_length = tx_peer->bo0_max_current_length;
	  t->tx_seq = tx_peer->current_tx_seq;
	  clib_memcpy (t->packet_data, vlib_buffer_get_current (b0),
		       sizeof (t->packet_data));
	}
    }
  u32 bi0 = vlib_get_buffer_index (vm, b0);
  vec_add1 (ptd->pending_tx_buffers, bi0);
  vec_add1 (ptd->pending_tx_nexts, next0);
}

always_inline void
pvti_enqueue_tx_drop_and_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
				pvti_per_thread_data_t *ptd, vlib_buffer_t *b0,
				u8 stream_index)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
		     (b0->flags & VLIB_BUFFER_IS_TRACED)))
    {
      pvti_output_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
      t->next_index = PVTI_OUTPUT_NEXT_DROP;
      t->stream_index = stream_index;
      t->trace_type = 0;
      clib_memcpy (t->packet_data, vlib_buffer_get_current (b0),
		   sizeof (t->packet_data));
    }
  u32 bi0 = vlib_get_buffer_index (vm, b0);
  vec_add1 (ptd->pending_tx_buffers, bi0);
  vec_add1 (ptd->pending_tx_nexts, PVTI_OUTPUT_NEXT_DROP);
}

always_inline bool
pvti_flush_peer_and_recharge (vlib_main_t *vm, vlib_node_runtime_t *node,
			      pvti_per_thread_data_t *ptd, u32 tx_peer_index,
			      u8 stream_index, const bool is_ip6)
{
  pvti_tx_peer_t *tx_peer = pool_elt_at_index (ptd->tx_peers, tx_peer_index);
  u16 next0 = encap_pvti_buffer_ip46 (vm, node, tx_peer, is_ip6);

  pvti_enqueue_tx_and_trace (vm, node, ptd, tx_peer->bo0, next0, stream_index,
			     tx_peer);

  tx_peer->bo0 = pvti_alloc_new_tx_buffer (vm);
  tx_peer->reass_chunk_count = 0;
  tx_peer->chunk_count = 0;
  tx_peer->current_tx_seq++;

  return 1;
}

always_inline u16
pvti_output_node_common (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, const bool is_ip6)
{
  pvti_main_t *pvm = &pvti_main;

  u32 n_left_from, *from;
  u32 pkts_encapsulated = 0;
  u32 pkts_processed = 0;
  u32 pkts_chopped = 0;
  u32 pkts_overflow = 0;
  u32 pkts_overflow_cantfit = 0;

  bool is_node_traced = (node->flags & VLIB_NODE_FLAG_TRACE) ? 1 : 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  u8 stream_index = pvti_get_stream_index (is_ip6);

  clib_thread_index_t thread_index = vlib_get_thread_index ();
  pvti_per_thread_data_t *ptd =
    vec_elt_at_index (pvm->per_thread_data[is_ip6], thread_index);

  vlib_buffer_t *ibufs[VLIB_FRAME_SIZE], **ib = ibufs;

  vlib_get_buffers (vm, from, ibufs, n_left_from);

  n_left_from = frame->n_vectors;
  while (1 && n_left_from > 0)
    {
      n_left_from -= 1;
      vlib_buffer_t *b0 = ib[0];
      ib++;
      u32 bi0 = vlib_get_buffer_index (vm, b0);
      bool is_b0_traced =
	is_node_traced && ((b0->flags & VLIB_BUFFER_IS_TRACED) ? 1 : 0);
      pkts_processed += 1;

      u32 sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
      u32 pvti_index0 = pvti_if_find_by_sw_if_index (sw_if_index0);
      if (pvti_index0 == INDEX_INVALID)
	{
	  b0->error = node->errors[PVTI_OUTPUT_ERROR_PEER];
	  pvti_enqueue_tx_drop_and_trace (vm, node, ptd, b0, stream_index);
	  continue;
	}
      pvti_if_t *pvti_if0 = pvti_if_get (pvti_index0);
      u32 tx_peer_index;
      if (!pvti_try_get_tx_peer_index (vm, ptd, pvti_if0, b0, is_ip6,
				       &tx_peer_index))
	{
	  b0->error = node->errors[PVTI_OUTPUT_ERROR_MAKE_PEER];
	  pvti_enqueue_tx_drop_and_trace (vm, node, ptd, b0, stream_index);
	  continue;
	}
      pvti_tx_peer_t *tx_peer = &ptd->tx_peers[tx_peer_index];

      u32 b0_len = vlib_buffer_length_in_chain (vm, b0);
      u32 total_chunk_len = sizeof (pvti_chunk_header_t) + b0_len;

      if (tx_peer->bo0_max_current_length >=
	  tx_peer->bo0->current_length + total_chunk_len)
	{
	  /* Happy case, we can fit the entire new chunk */
	  pvti_chunk_header_t *chunk_header = vlib_buffer_put_uninit (
	    tx_peer->bo0, sizeof (pvti_chunk_header_t));
	  u8 *tail = vlib_buffer_put_uninit (tx_peer->bo0, b0_len);
	  vlib_buffer_t *b0_curr;
	  b0_curr = b0;
	  while (b0_len > 0)
	    {
	      clib_memcpy (tail, vlib_buffer_get_current (b0_curr),
			   b0_curr->current_length);
	      tail += b0_curr->current_length;
	      b0_len -= b0_curr->current_length;
	      ASSERT ((b0_len == 0) ||
		      (b0_curr->flags & VLIB_BUFFER_NEXT_PRESENT));
	      if (b0_curr->flags & VLIB_BUFFER_NEXT_PRESENT)
		{
		  b0_curr = vlib_get_buffer (vm, b0_curr->next_buffer);
		}
	    }
	  tx_peer->is_bo0_traced |= is_b0_traced;
	  pvti_finalize_chunk (tx_peer, chunk_header, tail, false);
	}
      else
	{
	  bool is_reassembly = false;
	  /* FIXME: here, flush a packet if we want to avoid fragmenting it */
#define PVTI_TINY_PACKET_SZ 20
	  int threshold_len =
	    sizeof (pvti_chunk_header_t) + PVTI_TINY_PACKET_SZ;

	  /* Can we fit anything meaningful into bo0 ? if not - flush */
	  if (tx_peer->bo0_max_current_length <=
	      tx_peer->bo0->current_length + threshold_len)
	    {
	      if (!pvti_flush_peer_and_recharge (vm, node, ptd, tx_peer_index,
						 stream_index, is_ip6))
		{
		  b0->error = node->errors[PVTI_OUTPUT_ERROR_RECHARGE0];
		  pvti_enqueue_tx_drop_and_trace (vm, node, ptd, b0,
						  stream_index);
		  continue;
		}
	      pkts_encapsulated += 1;
	    }

	  pvti_chunk_header_t *chunk_header = vlib_buffer_put_uninit (
	    tx_peer->bo0, sizeof (pvti_chunk_header_t));

	  u8 *tail;
	  vlib_buffer_t *b0_curr;
	  /* append the chained buffers  and flush as necessary */
	  b0_curr = b0;

	  int curr_b0_start_offset = 0;

	  while (b0_len > 0)
	    {
	      ASSERT (tx_peer->bo0_max_current_length >
		      tx_peer->bo0->current_length);
	      int copy_len =
		clib_min (b0_curr->current_length - curr_b0_start_offset,
			  tx_peer->bo0_max_current_length -
			    tx_peer->bo0->current_length);
	      tail = vlib_buffer_put_uninit (tx_peer->bo0, copy_len);
	      clib_memcpy (tail,
			   (u8 *) vlib_buffer_get_current (b0_curr) +
			     curr_b0_start_offset,
			   copy_len);
	      tail += copy_len;
	      b0_len -= copy_len;
	      // Advance the start offset or reset it if we copied the entire
	      // block
	      curr_b0_start_offset =
		curr_b0_start_offset + copy_len == b0_curr->current_length ?
		  0 :
		  curr_b0_start_offset + copy_len;
	      ASSERT ((b0_len == 0) || (curr_b0_start_offset > 0) ||
		      (b0_curr->flags & VLIB_BUFFER_NEXT_PRESENT));
	      if (curr_b0_start_offset > 0)
		{
		  pvti_finalize_chunk (tx_peer, chunk_header, tail,
				       is_reassembly);
		  tx_peer->is_bo0_traced |= is_b0_traced;
		  if (!pvti_flush_peer_and_recharge (
			vm, node, ptd, tx_peer_index, stream_index, is_ip6))
		    {
		      b0->error = node->errors[PVTI_OUTPUT_ERROR_RECHARGE1];
		      pvti_enqueue_tx_drop_and_trace (vm, node, ptd, b0,
						      stream_index);
		      continue;
		    }
		  pkts_encapsulated += 1;
		  /* next chunk(s) will be reassembly until the next block */
		  is_reassembly = true;
		  chunk_header = vlib_buffer_put_uninit (
		    tx_peer->bo0, sizeof (pvti_chunk_header_t));
		}
	      else
		{
		  if ((b0_curr->flags & VLIB_BUFFER_NEXT_PRESENT))
		    {
		      b0_curr = vlib_get_buffer (vm, b0_curr->next_buffer);
		    }
		  else
		    {
		      pvti_finalize_chunk (tx_peer, chunk_header, tail,
					   is_reassembly);
		      tx_peer->is_bo0_traced |= is_b0_traced;
		    }
		}
	    }
	}
      vlib_buffer_free_one (vm, bi0);
    }

  int i;
  for (i = 0; i < vec_len (ptd->tx_peers); i++)
    {
      if (ptd->tx_peers[i].chunk_count)
	{
	  pvti_flush_peer_and_recharge (vm, node, ptd, i, stream_index,
					is_ip6);
	  pkts_encapsulated += 1;
	}
    }

  vlib_buffer_enqueue_to_next_vec (vm, node, &ptd->pending_tx_buffers,
				   &ptd->pending_tx_nexts,
				   vec_len (ptd->pending_tx_nexts));
  vec_reset_length (ptd->pending_tx_buffers);
  vec_reset_length (ptd->pending_tx_nexts);

  vlib_node_increment_counter (
    vm, node->node_index, PVTI_OUTPUT_ERROR_ENCAPSULATED, pkts_encapsulated);
  vlib_node_increment_counter (vm, node->node_index,
			       PVTI_OUTPUT_ERROR_PROCESSED, pkts_processed);
  vlib_node_increment_counter (vm, node->node_index, PVTI_OUTPUT_ERROR_CHOPPED,
			       pkts_chopped);
  vlib_node_increment_counter (vm, node->node_index,
			       PVTI_OUTPUT_ERROR_OVERFLOW, pkts_overflow);
  vlib_node_increment_counter (vm, node->node_index,
			       PVTI_OUTPUT_ERROR_OVERFLOW_CANTFIT,
			       pkts_overflow_cantfit);
  return frame->n_vectors;
}

VLIB_NODE_FN (pvti4_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return pvti_output_node_common (vm, node, frame, 0);
}

VLIB_NODE_FN (pvti6_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return pvti_output_node_common (vm, node, frame, 1);
}
