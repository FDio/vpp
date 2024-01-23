
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
} pvti_output_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_pvti_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pvti_output_trace_t *t = va_arg (*args, pvti_output_trace_t *);

  s = format (s, "PVTI-OUT: sw_if_index %d, next index %d", t->sw_if_index,
	      t->next_index);
  return s;
}

vlib_node_registration_t pvti_output_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_pvti_output_error                                             \
  _ (NONE, "No error")                                                        \
  _ (PROCESSED, "Packets processed")                                          \
  _ (ENCAPSULATED, "Packets encapsulated")                                    \
  _ (PEER, "No peer found")                                                   \
  _ (NO_PRE_SPACE, "Not enought pre-data space")

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
  PVTI_OUTPUT_NEXT_IP_LOOKUP,
  PVTI_OUTPUT_N_NEXT,
} pvti_output_next_t;

always_inline void
encapsulate_pvti_buffer_ip4 (vlib_main_t *vm, pvti_if_t *pvti_if0)
{
  ASSERT (AF_IP4 == ip_addr_version (&pvti_if0->local_ip));
  ASSERT (AF_IP4 == ip_addr_version (&pvti_if0->remote_ip));

  u32 bi0 = pvti_if0->bi0;

  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  pvti_packet_header_t *pvti0 = vlib_buffer_get_current (b0);
  pvti0->seq = clib_host_to_net_u32(pvti_if0->current_tx_seq++);
  pvti0->chunk_count = pvti_if0->ip4_chunk_count;

  vlib_buffer_advance (b0, -(sizeof (pvti_ip4_encap_header_t)));
  pvti_ip4_encap_header_t *ve = vlib_buffer_get_current (b0);

  ve->udp.src_port = clib_host_to_net_u16(pvti_if0->local_port);
  ve->udp.dst_port = clib_host_to_net_u16(pvti_if0->remote_port);
  ve->udp.length = clib_host_to_net_u16(
    b0->current_length - offsetof (pvti_ip4_encap_header_t, udp));
  ve->udp.checksum = 0;

  ve->ip4.ip_version_and_header_length = 0x45;
  ve->ip4.tos = 0;
  ve->ip4.length = clib_host_to_net_u16(b0->current_length);
  ve->ip4.fragment_id = 0x42;
  ve->ip4.flags_and_fragment_offset = 0;
  ve->ip4.ttl = 128;
  ve->ip4.protocol = 17;

  ve->ip4.dst_address.as_u32 = ip_addr_v4 (&pvti_if0->remote_ip).data_u32;
  ve->ip4.src_address.as_u32 = ip_addr_v4 (&pvti_if0->local_ip).data_u32;
  ve->ip4.checksum = ip4_header_checksum(&ve->ip4);

  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;
  // vnet_buffer (b0)->oflags |= VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
}

always_inline int
start_new_pvti_buffer (vlib_main_t *vm, pvti_if_t *pvti_if0, u32 bi0, int first_frag)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  clib_warning("buffer %p current_data: %d", b0, b0->current_data);
  vlib_buffer_advance (b0,
		       -(sizeof (pvti_packet_header_t) + PVTI_ALIGN_BYTES));
  if ((signed) b0->current_data < (signed) -VLIB_BUFFER_PRE_DATA_SIZE) {
      return 0;
  }
  pvti_packet_header_t *pvti0 = vlib_buffer_get_current (b0);
  clib_memset(pvti0, 0xca, sizeof(*pvti0)+ PVTI_ALIGN_BYTES);
  pvti0->pad_bytes = PVTI_ALIGN_BYTES;
  // store the buffer index and current length - this "consumes"
  // the current buffer. FIXME: multibuffer packets
  pvti_if0->bi0 = bi0;
  /* the buffer always has at least one chunk */
  pvti_if0->ip4_chunk_count = 1;
  pvti_if0->ip4_flags = first_frag ? PVTI_FIRST_IS_FRAG : 0;

  // FIXME - any good place to take it from ?
  pvti_if0->bi0_max_current_length = 1500 - 20 - 8;
  return 1;
}

/* attempt to get a new buffer either from buffers stashed
   for reuse within pvti, or allocate a new buffer */
always_inline u32
pvti_get_new_buffer (vlib_main_t *vm, pvti_if_t *pvti_if0)
{
  if (vec_len (pvti_if0->bi_store) > 0)
    {
      u32 bi0 = vec_pop (pvti_if0->bi_store);
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      b0->current_data = 0;
      b0->current_length = 0;
      return bi0;
    }
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

/* chop off the excess portion of a chunk in b0 into buffer indexed nbi0
 */
always_inline void
pvti_chop_chunk (vlib_main_t *vm, vlib_buffer_t *b0, pvti_chunk_header_t *pvc0, u32 nbi0, u16 chop_size)
{
  vlib_buffer_t *nb0 = vlib_get_buffer (vm, nbi0);
  vlib_buffer_advance (nb0, -(sizeof (pvti_chunk_header_t)));
  pvti_chunk_header_t *npvc0 = vlib_buffer_get_current (nb0);
  clib_memset(npvc0, 0xaa, sizeof(*npvc0));

  pvc0->total_chunk_length = clib_host_to_net_u16(clib_net_to_host_u16(pvc0->total_chunk_length) - chop_size);
  b0->current_length -= chop_size;
  nb0->current_length += chop_size;
  clib_memcpy(nb0->data, &b0->data[b0->current_data+b0->current_length], chop_size);
  npvc0->total_chunk_length = clib_host_to_net_u16(nb0->current_length);
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
  u32 encap_failed_no_buffers = 0;

  u32 *vti_ifs_with_packets = 0;
  u32 vti_ifs_i = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = PVTI_OUTPUT_NEXT_DROP;
	  u32 sw_if_index0;
	  u32 pvti_index0;
	  // ethernet_header_t *en0;
	  // ip4_header_t *ip40;
	  ip4_header_t *ip4h0;

	  next0 = PVTI_OUTPUT_NEXT_IP_LOOKUP;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  pkts_processed += 1;

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  pvti_index0 = pvti_if_find_by_sw_if_index (sw_if_index0);
	  if (pvti_index0 == INDEX_INVALID)
	    {
	      b0->error = node->errors[PVTI_OUTPUT_ERROR_PEER];
              next0 = PVTI_OUTPUT_NEXT_DROP;
	      goto trace_out;
	    }

	  vlib_buffer_advance (b0, -(sizeof (pvti_chunk_header_t)));
	  pvti_chunk_header_t *pvc0 = vlib_buffer_get_current (b0);
          clib_memset(pvc0, 0xaa, sizeof(*pvc0));
	  pvc0->total_chunk_length = clib_host_to_net_u16(b0->current_length);

	  pvti_if_t *pvti_if0 = pvti_if_get (pvti_index0);
          redo_packet:
	  if (pvti_if0->bi0 == INDEX_INVALID)
	    {
	      if (!start_new_pvti_buffer (vm, pvti_if0, bi0, 0 /* first_frag */)) {
	          b0->error = node->errors[PVTI_OUTPUT_ERROR_NO_PRE_SPACE];
                  next0 = PVTI_OUTPUT_NEXT_DROP;
	          goto trace_out;
              }
	      vec_add1 (vti_ifs_with_packets, pvti_index0);
	      if (clib_net_to_host_u16(pvc0->total_chunk_length) > pvti_if0->bi0_max_current_length)
		{
		  /* we already are over the limit on the first packet. Chop it
		   * up. */
		  u16 excess_length = clib_net_to_host_u16(pvc0->total_chunk_length) -
				      pvti_if0->bi0_max_current_length;
		  u32 nbi0 = pvti_get_new_buffer (vm, pvti_if0);
		  if (INDEX_INVALID == nbi0)
		    {
		      encap_failed_no_buffers += 1;
		      next0 = PVTI_OUTPUT_NEXT_DROP;
		    }
		  else
		    {
		      pvti_chop_chunk (vm, b0, pvc0, nbi0, excess_length);
		      // send the first fragment already
		      encapsulate_pvti_buffer_ip4 (vm, pvti_if0);
                      u32 xbi0 = pvti_if0->bi0;
		      to_next[0] = xbi0;
		      start_new_pvti_buffer (vm, pvti_if0, nbi0, 1 /* first_frag */);
                      bi0 = xbi0;
                      b0 = vlib_get_buffer(vm, bi0);
                      goto trace_out;
		    }
		} else {
	           // NOTE: the bi0 buffer is not sent at this point.
                   continue;
                }
	    }
	  else
	    {
	      vlib_buffer_t *vb0 = vlib_get_buffer (vm, pvti_if0->bi0);
	      u16 potential_new_length =
		clib_net_to_host_u16(pvc0->total_chunk_length) + vb0->current_length;

	      if (potential_new_length > pvti_if0->bi0_max_current_length)
		{
		  if (clib_net_to_host_u16(pvc0->total_chunk_length) >
		      pvti_if0->bi0_max_current_length)
		    {
		      // This new chunk is too large even for a single packet.
		      // See if we can fit the excess part of it.
		      u16 excess_length = clib_net_to_host_u16(pvc0->total_chunk_length) -
					  pvti_if0->bi0_max_current_length;
		      if (excess_length + vb0->current_length +
			    sizeof (pvti_chunk_header_t) <
			  pvti_if0->bi0_max_current_length)
			{
			  // We can fit the excess length here, so chop if from
			  // *beginning* of the new packet.
			  void *tail =
			    vlib_buffer_put_uninit (vb0, excess_length);
			  clib_memcpy (tail, vlib_buffer_get_current (b0),
				       excess_length);
			  // advance the buffer to cover the excess length, and
			  // add some space for the newly made chunk buffer
			  vlib_buffer_advance (b0, excess_length);
			  vlib_buffer_advance (
			    b0, -(sizeof (pvti_chunk_header_t)));
			  pvc0 = vlib_buffer_get_current (b0);
                          clib_memset(pvc0, 0xaa, sizeof(*pvc0));
			  pvc0->total_chunk_length = clib_host_to_net_u16(b0->current_length);
			  /* the old packet should be now full, we can send it
			   * out
			   */
			  encapsulate_pvti_buffer_ip4 (vm, pvti_if0);
                          u32 xbi0 = pvti_if0->bi0;
			  to_next[0] = xbi0;
			  start_new_pvti_buffer (vm, pvti_if0, bi0, 1 /* first_frag */);
                          bi0 = xbi0;
                          b0 = vlib_get_buffer(vm, bi0);
                          goto trace_out;
			} else {
                          /*
                          FIXME: can not fit the excess length here. Need to send the
                          currently built packet, and the first part.
                          */
                          to_next[0] = pvti_if0->bi0;
                          to_next += 1;
                          n_left_to_next -= 1;
                          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                                           to_next, n_left_to_next,
                                                           pvti_if0->bi0, next0);
                          /* FIXME: no tracing ^^^^^ ! */

                          pvti_if0->bi0 = INDEX_INVALID;
                          goto redo_packet;

                        }
		    }
		  else
		    {
		      // Send the pending chunk and encap the packet
		      /*
		       FIXME: another option here is to chop the packet "to
		       size" to fit it exactly - but this will double the
		       probability of loss, since it will be now spread across
		       two packets. Avoid it. */
		      encapsulate_pvti_buffer_ip4 (vm, pvti_if0);
                      u32 xbi0 = pvti_if0->bi0;
		      to_next[0] = xbi0;
		      start_new_pvti_buffer (vm, pvti_if0, bi0, 0 /* first_frag */);
		      vec_add1 (vti_ifs_with_packets, pvti_index0);
                      bi0 = xbi0;
                      b0 = vlib_get_buffer(vm, bi0);
                      goto trace_out;
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
                  pvti_if0->ip4_chunk_count += 1;
		  // store the index in the temp space in case we need a buffer
		  // shortly.
		  vec_add1 (pvti_if0->bi_store, bi0);
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
	    }

	  to_next += 1;
	  n_left_to_next -= 1;
	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      // enqueue the pending packets
      while (vti_ifs_i < vec_len (vti_ifs_with_packets) && n_left_to_next > 0)
	{
	  pvti_if_t *pvti_if0 =
	    pvti_if_get (vec_elt (vti_ifs_with_packets, vti_ifs_i));
	  if (pvti_if0->bi0 != INDEX_INVALID)
	    {
	      u32 next0 = PVTI_OUTPUT_NEXT_IP_LOOKUP;
	      u32 bi0 = pvti_if0->bi0;
	      encapsulate_pvti_buffer_ip4 (vm, pvti_if0);
	      to_next[0] = pvti_if0->bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	      pvti_if0->bi0 = INDEX_INVALID;
	    }

	  vti_ifs_i += 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (
    vm, node->node_index, PVTI_OUTPUT_ERROR_ENCAPSULATED, pkts_encapsulated);
  vlib_node_increment_counter (vm, node->node_index,
			       PVTI_OUTPUT_ERROR_PROCESSED, pkts_processed);
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
        [PVTI_OUTPUT_NEXT_IP_LOOKUP] = "ip4-lookup",
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
        [PVTI_OUTPUT_NEXT_IP_LOOKUP] = "ip6-lookup",
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
