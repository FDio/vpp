
/*
 *
 * Copyright (c) <current-year> <your-organization>
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

#pragma GCC diagnostic ignored "-Wunused-variable"

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u16 underlay_mtu;
  u16 bi0_max_current_length;
  u8 stream_index;
  u8 trace_type;
  u8 packet_data[64];
} pvti_output_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_pvti_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pvti_output_trace_t *t = va_arg (*args, pvti_output_trace_t *);

  u32 indent = format_get_indent (s);
  s = format (s,
	      "PVTI-OUT(%d): sw_if_index %d, next index %d underlay_mtu %d "
	      "stream_index %d bi0_max_current_length %d",
	      t->trace_type, t->sw_if_index, t->next_index, t->underlay_mtu,
	      t->stream_index, t->bi0_max_current_length);
  s = format (s, "\n%U%U", format_white_space, indent,
	      format_ip_adjacency_packet_data, t->packet_data,
	      sizeof (t->packet_data));

  return s;
}

vlib_node_registration_t pvti_output_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_pvti_output_error                                             \
  _ (NONE, "No error")                                                        \
  _ (PROCESSED, "Packets processed")                                          \
  _ (ENCAPSULATED, "Packets encapsulated")                                    \
  _ (PEER, "No peer found")                                                   \
  _ (NO_PRE_SPACE, "Not enought pre-data space")                              \
  _ (CHOPPED, "Packets chopped")                                              \
  _ (OVERFLOW, "Packets overflowed")                                          \
  _ (OVERFLOW_CANTFIT, "Packets overflowed and cant fit excess")

typedef enum
{
#define _(sym, str) PVTI_OUTPUT_ERROR_##sym,
  foreach_pvti_output_error
#undef _
    PVTI_OUTPUT_N_ERROR,
} pvti_output_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *pvti_output_error_strings[] = {
#define _(sym, string) string,
  foreach_pvti_output_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  PVTI_OUTPUT_NEXT_DROP,
  PVTI_OUTPUT_NEXT_INTERFACE_OUTPUT,
  PVTI_OUTPUT_NEXT_IP4_LOOKUP,
  PVTI_OUTPUT_NEXT_IP6_LOOKUP,
  PVTI_OUTPUT_N_NEXT,
} pvti_output_next_t;

static_always_inline u32
ip6_vtcfl (u8 stream_index)
{
  u32 vtcfl = 0x6 << 28;
  vtcfl |= stream_index;

  return (clib_host_to_net_u32 (vtcfl));
}

always_inline pvti_output_next_t
encapsulate_pvti_buffer_ip46 (vlib_main_t *vm, vlib_node_runtime_t *node,
			      pvti_if_t *pvti_if0, u8 stream_index, int is_ip6)
{
  ip_address_family_t src_ver = ip_addr_version (&pvti_if0->local_ip);
  ip_address_family_t dst_ver = ip_addr_version (&pvti_if0->remote_ip);

  ASSERT (src_ver == dst_ver);
  bool is_ip6_encap = (AF_IP6 == src_ver);

  u32 bi0 = pvti_if0->tx_streams[stream_index].bi0;

  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  pvti_packet_header_t *pvti0 = vlib_buffer_get_current (b0);
  pvti0->seq =
    clib_host_to_net_u32 (pvti_if0->tx_streams[stream_index].current_tx_seq++);
  pvti0->stream_index = stream_index;
  pvti0->reass_chunk_count =
    pvti_if0->tx_streams[stream_index].reass_chunk_count;
  pvti0->chunk_count = pvti_if0->tx_streams[stream_index].chunk_count;
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

      ve->udp.src_port = clib_host_to_net_u16 (pvti_if0->local_port);
      ve->udp.dst_port = clib_host_to_net_u16 (pvti_if0->remote_port);
      ve->udp.length = clib_host_to_net_u16 (
	b0->current_length - offsetof (pvti_ip6_encap_header_t, udp));
      ve->udp.checksum = 0;

      ve->ip6.ip_version_traffic_class_and_flow_label =
	ip6_vtcfl (stream_index);
      ve->ip6.payload_length = ve->udp.length;
      ve->ip6.protocol = 17;
      ve->ip6.hop_limit = 128;
      ip_address_copy_addr (&ve->ip6.src_address, &pvti_if0->local_ip);
      ip_address_copy_addr (&ve->ip6.dst_address, &pvti_if0->remote_ip);
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

      ve->udp.src_port = clib_host_to_net_u16 (pvti_if0->local_port);
      ve->udp.dst_port = clib_host_to_net_u16 (pvti_if0->remote_port);
      ve->udp.length = clib_host_to_net_u16 (
	b0->current_length - offsetof (pvti_ip4_encap_header_t, udp));
      ve->udp.checksum = 0;

      ve->ip4.ip_version_and_header_length = 0x45;
      ve->ip4.tos = 0;
      ve->ip4.length = clib_host_to_net_u16 (b0->current_length);
      ve->ip4.fragment_id = clib_host_to_net_u16 (
	(pvti_if0->tx_streams[stream_index].current_tx_seq & 0xffff) - 1);
      ve->ip4.flags_and_fragment_offset = 0;
      ve->ip4.ttl = 128;
      ve->ip4.protocol = 17;

      ve->ip4.dst_address.as_u32 = ip_addr_v4 (&pvti_if0->remote_ip).data_u32;
      ve->ip4.src_address.as_u32 = ip_addr_v4 (&pvti_if0->local_ip).data_u32;
      ve->ip4.checksum = ip4_header_checksum (&ve->ip4);
    }

  // This is important, if not reset, causes a crash
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = pvti_if0->underlay_fib_index;

  // vnet_buffer (b0)->oflags |= VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
  return is_ip6_encap ? PVTI_OUTPUT_NEXT_IP6_LOOKUP :
			PVTI_OUTPUT_NEXT_IP4_LOOKUP;
}

always_inline int
start_new_pvti_buffer (vlib_main_t *vm, pvti_if_t *pvti_if0, u8 stream_index,
		       u32 bi0, int first_frag)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  // clib_warning ("buffer %p current_data: %d", b0, b0->current_data);

  b0->current_data += -(sizeof (pvti_packet_header_t) + PVTI_ALIGN_BYTES);
  if (b0->current_data < -VLIB_BUFFER_PRE_DATA_SIZE)
    {
      // undo the change
      b0->current_data += sizeof (pvti_packet_header_t) + PVTI_ALIGN_BYTES;
      return 0;
    }
  // finalize the length change
  b0->current_length += sizeof (pvti_packet_header_t) + PVTI_ALIGN_BYTES;

  pvti_packet_header_t *pvti0 = vlib_buffer_get_current (b0);
  clib_memset (pvti0, 0xca, sizeof (*pvti0) + PVTI_ALIGN_BYTES);
  pvti0->pad_bytes = PVTI_ALIGN_BYTES;

  // store the buffer index and current length - this "consumes"
  // the current buffer. Multibuffer packets are dealt with
  // in the end of processing cycle.
  pvti_if0->tx_streams[stream_index].bi0 = bi0;
  /* the buffer always has at least one chunk */
  pvti_if0->tx_streams[stream_index].chunk_count = 1;
  pvti_if0->tx_streams[stream_index].reass_chunk_count = first_frag ? 1 : 0;

  ip_address_family_t dst_ver = ip_addr_version (&pvti_if0->remote_ip);
  u16 pvti_encap_overhead = (dst_ver == AF_IP6) ?
			      sizeof (pvti_ip6_encap_header_t) :
			      sizeof (pvti_ip4_encap_header_t);
  /* PVTI blocks are created starting with packet header, so it is part of
   * bi0_max_current_length. */
  u16 pvti_packet_overhead =
    pvti_encap_overhead; // + sizeof (pvti_packet_header_t) + PVTI_ALIGN_BYTES;
  ASSERT (pvti_if0->underlay_mtu > pvti_packet_overhead);
  pvti_if0->tx_streams[stream_index].bi0_max_current_length =
    pvti_if0->underlay_mtu - pvti_packet_overhead;
  return 1;
}

/* attempt to get a new buffer either from buffers stashed
   for reuse within pvti, or allocate a new buffer */
#ifdef REMOVED_XXX
always_inline u32
pvti_get_new_buffer (vlib_main_t *vm, pvti_if_t *pvti_if0, u8 stream_index)
{
  u32 bi0 = INDEX_INVALID;
  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    {
      return INDEX_INVALID;
    }
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  b0->current_data = 0;
  b0->current_length = 0;
  return bi0;
}
#endif

/* chop off the excess portion of a chunk in b0 into buffer indexed nbi0
 */
always_inline void
pvti_chop_chunk (vlib_main_t *vm, vlib_buffer_t *b0, pvti_chunk_header_t *pvc0,
		 u32 nbi0, u16 chop_size)
{
  vlib_buffer_t *nb0 = vlib_get_buffer (vm, nbi0);
  vlib_buffer_advance (nb0, -(sizeof (pvti_chunk_header_t)));
  pvti_chunk_header_t *npvc0 = vlib_buffer_get_current (nb0);
  clib_memset (npvc0, 0xac, sizeof (*npvc0));

  npvc0->flags = ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) ? CHUNK_FLAGS_MB : 0);

  // Mark the current chunk accordingly.
  pvc0->flags |= CHUNK_FLAGS_MF;

  pvc0->total_chunk_length = clib_host_to_net_u16 (
    clib_net_to_host_u16 (pvc0->total_chunk_length) - chop_size);
  b0->current_length -= chop_size;
  nb0->current_length += chop_size;
  clib_memcpy (nb0->data, &b0->data[b0->current_data + b0->current_length],
	       chop_size);
  npvc0->total_chunk_length = clib_host_to_net_u16 (nb0->current_length);
  if (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b0->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
      nb0->flags |= VLIB_BUFFER_NEXT_PRESENT;
      nb0->next_buffer = b0->next_buffer;
      b0->next_buffer = ~0;
    }
  if (b0->flags & VLIB_BUFFER_IS_TRACED)
    {
      nb0->flags |= VLIB_BUFFER_IS_TRACED;
    }
}

always_inline void
pvti_append_partial_chunk (vlib_main_t *vm, vlib_buffer_t *vb0,
			   vlib_buffer_t *b0, u16 append_length)
{
  pvti_chunk_header_t *pvc0;
  void *tail = vlib_buffer_put_uninit (vb0, append_length);
  clib_memcpy (tail, vlib_buffer_get_current (b0), append_length);
  // store the new excess length
  pvc0 = tail;
  pvc0->total_chunk_length = clib_host_to_net_u16 (append_length);
  pvc0->flags |= CHUNK_FLAGS_MF;

  // advance the buffer to cover the excess length, and
  // add some space for the newly made chunk buffer
  vlib_buffer_advance (b0, append_length);
  vlib_buffer_advance (b0, -(sizeof (pvti_chunk_header_t)));

  // prepare the new chunk header in the b0
  pvc0 = vlib_buffer_get_current (b0);
  clib_memset (pvc0, 0xaa, sizeof (*pvc0));
  pvc0->total_chunk_length = clib_host_to_net_u16 (b0->current_length);
  pvc0->flags = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) ? CHUNK_FLAGS_MB : 0;
}

always_inline u16
pvti_output_node_common (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, bool is_ip6)
{
  // pvti_main_t *pvm = &pvti_main;

  u32 n_left_from, *from, *to_next;
  pvti_output_next_t next_index;
  u32 pkts_encapsulated = 0;
  u32 pkts_processed = 0;
  u32 pkts_chopped = 0;
  u32 pkts_overflow = 0;
  u32 pkts_overflow_cantfit = 0;
  u32 encap_failed_no_buffers = 0;

  u32 *vti_ifs_with_packets = 0;
  u32 vti_ifs_i = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u16 underlay_mtu = 0;
  u16 n_bufs;
  u8 stream_index = pvti_get_stream_index (is_ip6);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  int need_redo_packet = 0;
	  int is_first_frag = 0;
	  int is_chained_buf = 0;
	  u32 redo_bi0 = ~0;
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = PVTI_OUTPUT_NEXT_DROP;
	  u32 sw_if_index0;
	  u32 pvti_index0;
	  // ethernet_header_t *en0;
	  // ip4_header_t *ip40;
	  ip4_header_t *ip4h0;
	  u16 wip0_chunk_length = 12345;

	  next0 = PVTI_OUTPUT_NEXT_DROP;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  vlib_buffer_chain_linearize (vm, b0);

	  pkts_processed += 1;

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = 42;

	  pvti_index0 = pvti_if_find_by_sw_if_index (sw_if_index0);
	  if (pvti_index0 == INDEX_INVALID)
	    {
	      b0->error = node->errors[PVTI_OUTPUT_ERROR_PEER];
	      next0 = PVTI_OUTPUT_NEXT_DROP;
	      goto trace_out;
	    }

	redo_chained_buffer:
	  { /* some compilers seem unappy with variable definition after label
	     */
	  }
	  pvti_chunk_header_t *pvc0 =
	    vlib_buffer_push_uninit (b0, sizeof (pvti_chunk_header_t));
	  clib_memset (pvc0, 0xab, sizeof (*pvc0));
	  wip0_chunk_length = b0->current_length;
	  pvc0->total_chunk_length = clib_host_to_net_u16 (b0->current_length);
	  // Optimistically assume that we have buffer = chunk, thus
	  // CHUNK_FLAGS_MF = 0
	  pvc0->flags =
	    (b0->flags & VLIB_BUFFER_NEXT_PRESENT) ? CHUNK_FLAGS_MB : 0;

	  pvti_if_t *pvti_if0 = pvti_if_get (pvti_index0);
	  underlay_mtu = pvti_if0->underlay_mtu;

	redo_packet:
	  if (need_redo_packet)
	    {
	      bi0 = redo_bi0;
	      b0 = vlib_get_buffer (vm, bi0);
	      pvc0 = vlib_buffer_get_current (b0);
	      wip0_chunk_length = b0->current_length;
	      need_redo_packet = 0;
	    }
	  if (pvti_if0->tx_streams[stream_index].bi0 == INDEX_INVALID)
	    {
	      if (!start_new_pvti_buffer (vm, pvti_if0, stream_index, bi0,
					  is_first_frag || is_chained_buf))
		{
		  b0->error = node->errors[PVTI_OUTPUT_ERROR_NO_PRE_SPACE];
		  next0 = PVTI_OUTPUT_NEXT_DROP;
		  goto trace_out;
		}
	      is_first_frag = 0;
	      is_chained_buf = 0;
	      vec_add1 (vti_ifs_with_packets, pvti_index0);
	      if (wip0_chunk_length + 19 >
		  pvti_if0->tx_streams[stream_index].bi0_max_current_length)
		{
		  /* we already are over the limit on the first packet. Chop it
		   * up. */
		  u16 excess_length =
		    wip0_chunk_length + 19 -
		    pvti_if0->tx_streams[stream_index].bi0_max_current_length;
		  u32 nbi0 = pvti_get_new_buffer (vm, pvti_if0, stream_index);
		  if (INDEX_INVALID == nbi0)
		    {
		      encap_failed_no_buffers += 1;
		      next0 = PVTI_OUTPUT_NEXT_DROP;
		    }
		  else
		    {
		      pvti_chop_chunk (vm, b0, pvc0, nbi0, excess_length);
		      pkts_chopped += 1;

		      // send the first fragment already
		      next0 = encapsulate_pvti_buffer_ip46 (
			vm, node, pvti_if0, stream_index, is_ip6);

		      u32 xbi0 = pvti_if0->tx_streams[stream_index].bi0;
		      to_next[0] = xbi0;

#define TRIGGER_PVTI_PACKET_REDO(_i0, _frag)                                  \
  pvti_if0->tx_streams[stream_index].bi0 = INDEX_INVALID;                     \
  redo_bi0 = _i0;                                                             \
  need_redo_packet = 1;                                                       \
  is_first_frag = _frag;

		      TRIGGER_PVTI_PACKET_REDO (nbi0, 1);

		      bi0 = xbi0;
		      b0 = vlib_get_buffer (vm, bi0);
		      goto trace_out;
		    }
		}
	      else
		{
		  // NOTE: the bi0 buffer is not sent at this point.
		  // We have just noted it in the pvti_if0 structure,
		  // so as to attempt to coalesce some more packets
		  // from the vector onto it.
		  // For chained buffers, we need to break up the chain add the
		  // next buffer.
		  if (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
		    {
		      // Break up the buffer chain and redo the next buffer -
		      // nonfirst packet
		      bi0 = b0->next_buffer;
		      b0->next_buffer = ~0;
		      b0->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
		      b0 = vlib_get_buffer (vm, bi0);
		      is_chained_buf = 1;
		      goto redo_chained_buffer;
		    }

		  continue;
		}
	    }
	  else
	    // Attempt to append the WIP chunk to the existing buffer
	    {
	      vlib_buffer_t *vb0 =
		vlib_get_buffer (vm, pvti_if0->tx_streams[stream_index].bi0);
	      u16 potential_new_length =
		wip0_chunk_length + vb0->current_length;

	      if (potential_new_length >
		  pvti_if0->tx_streams[stream_index].bi0_max_current_length)
		{
		  pkts_overflow += 1;
		  if (wip0_chunk_length > pvti_if0->tx_streams[stream_index]
					    .bi0_max_current_length)
		    {
		      // This new chunk is too large even for a single packet,
		      // and we are trying to coalesce with an already existing
		      // chunk. See if we can fit the excess part of it here.
		      // Splitting into two chunks requires an additional chunk
		      // header. So we add it to excess length

		      u16 excess_length = wip0_chunk_length -
					  pvti_if0->tx_streams[stream_index]
					    .bi0_max_current_length +
					  sizeof (pvti_chunk_header_t);

		      u16 available_space = pvti_if0->tx_streams[stream_index]
					      .bi0_max_current_length -
					    vb0->current_length;

		      if (excess_length + vb0->current_length +
			    sizeof (pvti_chunk_header_t) <
			  pvti_if0->tx_streams[stream_index]
			    .bi0_max_current_length)
			{
			  // We can fit the excess length here, so chop
			  // *beginning* of the new packet

			  // See if we can chop more
			  if (available_space > excess_length)
			    {
			      excess_length = available_space;
			    }

			  pvti_append_partial_chunk (vm, vb0, b0,
						     excess_length);

			  /* the old packet should be now full, we can send it
			   * out
			   */
			  pvti_if0->tx_streams[stream_index].chunk_count += 1;
			  pvti_if0->tx_streams[stream_index]
			    .reass_chunk_count += is_chained_buf;
			  is_chained_buf = 0;

			  next0 = encapsulate_pvti_buffer_ip46 (
			    vm, node, pvti_if0, stream_index, is_ip6);
			  u32 xbi0 = pvti_if0->tx_streams[stream_index].bi0;
			  to_next[0] = xbi0;

			  TRIGGER_PVTI_PACKET_REDO (bi0,
						    1 /* is_first_frag */);

			  bi0 = xbi0;
			  b0 = vlib_get_buffer (vm, bi0);
			  goto trace_out;
			}
		      else
			{
			  /*
			  Can not fit the excess length here.
			  send the currently built packet, and redo the first
			  part.
			  */
			  pkts_overflow_cantfit += 1;

			  next0 = encapsulate_pvti_buffer_ip46 (
			    vm, node, pvti_if0, stream_index, is_ip6);
			  u32 xbi0 = pvti_if0->tx_streams[stream_index].bi0;
			  to_next[0] = xbi0;

			  TRIGGER_PVTI_PACKET_REDO (bi0,
						    0 /* is_first_frag */);

			  bi0 = xbi0;
			  b0 = vlib_get_buffer (vm, bi0);
			  goto trace_out;
			}
		    }
		  else
		    {
		      /* we can not append the new chunk without fragmenting
		      it, but it will fit into a new packet. There is two
		      options here: 1) send the chunks in the process of
		      assembly and then start the next chunk in a separate
		      packet. 2) chop off the part that can fit, and queue the
		      remaining part.

		      The (1) will heuristically minimize the state spread
		      across multiple packets, whereas (2) will allow to gain
		      slightly better PPS efficiency... Tricky to say which one
		      is better, so let's have both.
		      */

		      if (0)
			{
			  // Send the pending chunk and encap the packet
			  next0 = encapsulate_pvti_buffer_ip46 (
			    vm, node, pvti_if0, stream_index, is_ip6);
			  u32 xbi0 = pvti_if0->tx_streams[stream_index].bi0;
			  to_next[0] = xbi0;
			  start_new_pvti_buffer (
			    vm, pvti_if0, stream_index, bi0,
			    is_chained_buf /* first_frag */);
			  is_chained_buf = 0;
			  vec_add1 (vti_ifs_with_packets, pvti_index0);
			  bi0 = xbi0;
			  b0 = vlib_get_buffer (vm, bi0);
			  goto trace_out;
			}
		      else
			{
			  /* add a piece of the new packet here to fill the
			   * length, queue the remainder */
			  u16 append_length =
			    pvti_if0->tx_streams[stream_index]
			      .bi0_max_current_length -
			    vb0->current_length;

			  // append_length -= 100;

			  pvti_append_partial_chunk (vm, vb0, b0,
						     append_length);

			  /* the old packet should be now full, we can send it
			   * out
			   */
			  pvti_if0->tx_streams[stream_index].chunk_count += 1;
			  pvti_if0->tx_streams[stream_index]
			    .reass_chunk_count += is_chained_buf;
			  is_chained_buf = 0;

			  next0 = encapsulate_pvti_buffer_ip46 (
			    vm, node, pvti_if0, stream_index, is_ip6);
			  u32 xbi0 = pvti_if0->tx_streams[stream_index].bi0;
			  to_next[0] = xbi0;
			  start_new_pvti_buffer (vm, pvti_if0, stream_index,
						 bi0, 1 /* first_frag */);
			  vec_add1 (vti_ifs_with_packets, pvti_index0);
			  bi0 = xbi0;
			  b0 = vlib_get_buffer (vm, bi0);
			  goto trace_out;
			}
		    }
		}
	      else
		{
		  // Happy case: we can append the new packet entirely
		  // So as a reward we get a buffer that we can reuse.

		  void *tail =
		    vlib_buffer_put_uninit (vb0, b0->current_length);
		  clib_memcpy (tail, vlib_buffer_get_current (b0),
			       b0->current_length);
		  pvti_if0->tx_streams[stream_index].chunk_count += 1;
		  pvti_if0->tx_streams[stream_index].reass_chunk_count +=
		    is_chained_buf;
		  is_chained_buf = 0;
		  if (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
		    {
		      // Break up the buffer chain and redo the next buffer -
		      // nonfirst packet
		      bi0 = b0->next_buffer;
		      b0->next_buffer = ~0;
		      b0->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
		      b0 = vlib_get_buffer (vm, bi0);
		      // goto redo_chained_buffer;
		    }

                  vlib_buffer_free_one (vm, bi0);

		  continue;
		}
	    }

	  /*
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  * Send pkt back out the RX interface *
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;
	  */
	  pkts_encapsulated += 1;

	  // FIXME: how do we trace the packets that are coalesced ?
	  // FIXME: how do we trace the packets that have been split ?

	trace_out:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      pvti_output_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	      t->underlay_mtu = underlay_mtu;
	      t->stream_index = stream_index;
	      t->trace_type = 2;
	      t->bi0_max_current_length =
		pvti_if0->tx_streams[stream_index].bi0_max_current_length;
	      clib_memcpy (t->packet_data, vlib_buffer_get_current (b0),
			   sizeof (t->packet_data));
	    }

	  to_next += 1;
	  n_left_to_next -= 1;
	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	  if (need_redo_packet)
	    {
	      goto redo_packet;
	    }
	}

      // enqueue the pending packets
      while (vti_ifs_i < vec_len (vti_ifs_with_packets) && n_left_to_next > 0)
	{
	  pvti_if_t *pvti_if0 =
	    pvti_if_get (vec_elt (vti_ifs_with_packets, vti_ifs_i));
	  if (pvti_if0->tx_streams[stream_index].bi0 != INDEX_INVALID)
	    {
	      u32 next0 = PVTI_OUTPUT_NEXT_DROP;
	      u32 bi0 = pvti_if0->tx_streams[stream_index].bi0;
	      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

	      next0 = encapsulate_pvti_buffer_ip46 (vm, node, pvti_if0,
						    stream_index, is_ip6);

	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
				 (b0->flags & VLIB_BUFFER_IS_TRACED)))
		{
		  pvti_output_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->next_index = next0;
		  t->underlay_mtu = underlay_mtu;
		  t->stream_index = stream_index;
		  t->trace_type = 3;
		  t->bi0_max_current_length =
		    pvti_if0->tx_streams[stream_index].bi0_max_current_length;
		  clib_memcpy (t->packet_data, vlib_buffer_get_current (b0),
			       sizeof (t->packet_data));
		}

	      to_next[0] = pvti_if0->tx_streams[stream_index].bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	      pvti_if0->tx_streams[stream_index].bi0 = INDEX_INVALID;
	    }

	  vti_ifs_i += 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

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

#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (pvti4_output_node) =
{
  .name = "pvti4-output",
  .vector_size = sizeof (u32),
  .format_trace = format_pvti_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(pvti_output_error_strings),
  .error_strings = pvti_output_error_strings,

  .n_next_nodes = PVTI_OUTPUT_N_NEXT,

  .next_nodes = {
        [PVTI_OUTPUT_NEXT_DROP] = "error-drop",
        [PVTI_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
        [PVTI_OUTPUT_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [PVTI_OUTPUT_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },

};
VLIB_REGISTER_NODE (pvti6_output_node) =
{
  .name = "pvti6-output",
  .vector_size = sizeof (u32),
  .format_trace = format_pvti_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(pvti_output_error_strings),
  .error_strings = pvti_output_error_strings,

  .n_next_nodes = PVTI_OUTPUT_N_NEXT,

  .next_nodes = {
        [PVTI_OUTPUT_NEXT_DROP] = "error-drop",
        [PVTI_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
        [PVTI_OUTPUT_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [PVTI_OUTPUT_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },

};
#endif /* CLIB_MARCH_VARIANT */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
