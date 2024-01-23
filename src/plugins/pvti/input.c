/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
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

typedef struct
{
  u16 total_chunk_length;
} pvti_input_chunk_t;

#define MAX_CHUNKS 32

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  ip_address_t remote_ip;
  u16 remote_port;
  u16 local_port;
  u32 seq;
  u8 chunk_count;
  pvti_input_chunk_t chunks[MAX_CHUNKS];
} pvti_input_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_pvti_input_trace (u8 *s, va_list *args)
{
  int i;
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pvti_input_trace_t *t = va_arg (*args, pvti_input_trace_t *);

  s = format (s, "PVTI-IN: sw_if_index %d, next index %d, chunkcnt: %d\n",
	      t->sw_if_index, t->next_index, t->chunk_count);
  s = format (s, "  src %U sport %d dport %d\n", format_ip_address,
	      &t->remote_ip, t->remote_port, t->local_port);
  s = format (s, "  seq: %d, chunk_count: %d\n", t->seq, t->chunk_count);
  u16 max = t->chunk_count > MAX_CHUNKS ? MAX_CHUNKS : t->chunk_count;
  for (i = 0; i < max; i++)
    {
      s = format (s, "    %02d: sz %d\n", i, t->chunks[i].total_chunk_length);
    }
  return s;
}

vlib_node_registration_t pvti4_input_node;
vlib_node_registration_t pvti6_input_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_pvti_input_error                                              \
  _ (PROCESSED, "PVTI tunnel packets processed")                              \
  _ (PEER, "Could not find a peer")                                           \
  _ (NOCHUNKS, "Packet has no chunks")                                        \
  _ (TOOMANYREASS, "Packet has more reassembly chunks than total")

typedef enum
{
#define _(sym, str) PVTI_INPUT_ERROR_##sym,
  foreach_pvti_input_error
#undef _
    PVTI_INPUT_N_ERROR,
} pvti_input_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *pvti_input_error_strings[] = {
#define _(sym, string) string,
  foreach_pvti_input_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  PVTI_INPUT_NEXT_DROP,
  PVTI_INPUT_NEXT_IP4_INPUT,
  PVTI_INPUT_NEXT_IP6_INPUT,
  PVTI_INPUT_NEXT_PUNT,
  PVTI_INPUT_N_NEXT,
} pvti_input_next_t;

always_inline u16
pvti_input_node_common (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame, bool is_ip6)
{
  u32 n_left_from, *from, *to_next;
  pvti_input_next_t next_index;
  pvti_chunk_header_t *chunks[MAX_CHUNKS];
  u32 pkts_processed = 0;
  u32 decap_failed_no_buffers = 0;

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
	  u32 next0 = PVTI_INPUT_NEXT_DROP;
	  u32 sw_if_index0;
	  u8 true_chunk_count = 0;
	  u8 max_chunk_count;
	  u32 pvti_index0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  pvti_ip4_encap_header_t *h0 =
	    ((pvti_ip4_encap_header_t *) vlib_buffer_get_current (b0)) - 1;
	  pvti_index0 = pvti_if_find_by_remote_ip4_and_port (
	    &h0->ip4.src_address, clib_net_to_host_u16 (h0->udp.src_port));
	  if (pvti_index0 == INDEX_INVALID)
	    {
	      b0->error = node->errors[PVTI_INPUT_ERROR_PEER];
	      next0 = PVTI_INPUT_NEXT_DROP;
	      goto trace_out;
	    }
	  pvti_if_t *pvti_if0 = pvti_if_get (pvti_index0);

	  b0 = vlib_get_buffer (vm, bi0);
	  pvti_packet_header_t *pvti0 = vlib_buffer_get_current (b0);
	  max_chunk_count =
	    pvti0->chunk_count < MAX_CHUNKS ? pvti0->chunk_count : MAX_CHUNKS;
	  vlib_buffer_advance (b0, pvti0->pad_bytes +
				     offsetof (pvti_packet_header_t, pad));

	  if (max_chunk_count == 0)
	    {
	      b0->error = node->errors[PVTI_INPUT_ERROR_NOCHUNKS];
	      next0 = PVTI_INPUT_NEXT_DROP;
	      goto trace_out;
	    }
	  if (pvti0->reass_chunk_count > max_chunk_count)
	    {
	      b0->error = node->errors[PVTI_INPUT_ERROR_TOOMANYREASS];
	      next0 = PVTI_INPUT_NEXT_DROP;
	      goto trace_out;
	    }

	  u32 new_seq0 = clib_net_to_host_u32 (pvti0->seq);
	  if (new_seq0 == pvti_if0->last_rx_seq + 1)
	    {
	      /* Sequence# matches, we can attempt adding the leading chunks to
	       * reassembly */

	      while ((b0->current_length > 0) &&
		     true_chunk_count < pvti0->reass_chunk_count)
		{
		  /* attempt to either incorporate the first chunk into
		   * reassembly or skip it. */
		  pvti_chunk_header_t *pvc0 = vlib_buffer_get_current (b0);
		  chunks[true_chunk_count] = pvc0;
		  true_chunk_count += 1;
		  vlib_buffer_advance (
		    b0, clib_net_to_host_u16 (pvc0->total_chunk_length));
		}
	    }
	  else
	    {
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
	    }

	  while ((b0->current_length > 0) &&
		 true_chunk_count < max_chunk_count)
	    {
	      pvti_chunk_header_t *pvc0 = vlib_buffer_get_current (b0);
	      chunks[true_chunk_count] = pvc0;
	      true_chunk_count += 1;
	      u16 total_chunk_length =
		clib_net_to_host_u16 (pvc0->total_chunk_length);
	      vlib_buffer_advance (b0, total_chunk_length);
	      u8 *pkt = (u8 *) (pvc0 + 1);
	      u16 inner_length;

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
		  continue;
		}

	      if (inner_length + sizeof (pvti_chunk_header_t) >
		  total_chunk_length)
		{
		  /* FIXME: the packet size is larger than the chunk -> it's a
		   * first fragment */
		  // enqueue the chunk and finish packet processing.
		  pvti_if0->rx_bi0 = bi0;
		  goto next_packet_no_recycle;
		}
	      if (n_left_to_next == 0)
		{
		  vlib_get_next_frame (vm, node, next_index, to_next,
				       n_left_to_next);
		}

	      u32 nbi0 = pvti_get_new_buffer (vm, pvti_if0);
	      if (INDEX_INVALID == nbi0)
		{
		  decap_failed_no_buffers += 1;
		  continue;
		};
	      vlib_buffer_t *nb0 = vlib_get_buffer (vm, nbi0);
	      vnet_buffer (nb0)->sw_if_index[VLIB_RX] = pvti_if0->sw_if_index;
	      if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next0, nb0,
						   /* follow_chain */ 0)))
		{
		  /* empty for now */
		}

	      void *new_packet = vlib_buffer_put_uninit (nb0, inner_length);
	      clib_memcpy (new_packet, pvc0 + 1, inner_length);

	      to_next[0] = nbi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, nbi0, next0);
	    }
	  /* we have processed all the chunks from the buffer, but the buffer
	   * remains. Recycle it. */
	  vec_add1 (pvti_if0->bi_store, bi0);
	next_packet_no_recycle:
	  continue;

	trace_out:

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      int i;
	      pvti_input_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->seq = clib_net_to_host_u32 (pvti0->seq);
	      t->remote_ip.ip.ip4 = h0->ip4.src_address;
	      t->remote_ip.version = AF_IP4;
	      t->local_port = h0->udp.dst_port;
	      t->remote_port = h0->udp.src_port;
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

	  pkts_processed += 1;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       PVTI_INPUT_ERROR_PROCESSED, pkts_processed);
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

#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (pvti4_input_node) = 
{
  .name = "pvti4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_pvti_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(pvti_input_error_strings),
  .error_strings = pvti_input_error_strings,

  .n_next_nodes = PVTI_INPUT_N_NEXT,

  .next_nodes = {
        [PVTI_INPUT_NEXT_DROP] = "error-drop",
        [PVTI_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
        [PVTI_INPUT_NEXT_IP6_INPUT] = "ip6-input",
        [PVTI_INPUT_NEXT_PUNT] = "error-punt",
  },

};
VLIB_REGISTER_NODE (pvti6_input_node) = 
{
  .name = "pvti6-input",
  .vector_size = sizeof (u32),
  .format_trace = format_pvti_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(pvti_input_error_strings),
  .error_strings = pvti_input_error_strings,

  .n_next_nodes = PVTI_INPUT_N_NEXT,

  .next_nodes = {
        [PVTI_INPUT_NEXT_DROP] = "error-drop",
        [PVTI_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
        [PVTI_INPUT_NEXT_IP6_INPUT] = "ip6-input",
        [PVTI_INPUT_NEXT_PUNT] = "error-punt",
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
