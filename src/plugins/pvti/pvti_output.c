
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
  u8 new_src_mac[6];
  u8 new_dst_mac[6];
} pvti_output_trace_t;

#ifndef CLIB_MARCH_VARIANT
static u8 *
my_format_mac_address (u8 *s, va_list *args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3],
		 a[4], a[5]);
}

/* packet trace format function */
static u8 *
format_pvti_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pvti_output_trace_t *t = va_arg (*args, pvti_output_trace_t *);

  s = format (s, "PVTI-IN: sw_if_index %d, next index %d\n", t->sw_if_index,
	      t->next_index);
  s = format (s, "  new src %U -> new dst %U", my_format_mac_address,
	      t->new_src_mac, my_format_mac_address, t->new_dst_mac);
  return s;
}

vlib_node_registration_t pvti_output_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_pvti_output_error                                             \
  _ (NONE, "No error")                                                        \
  _ (PROCESSED, "Packets processed")                                          \
  _ (ENCAPSULATED, "Packets encapsulated")                                    \
  _ (PEER, "No peer found")

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
  vlib_buffer_advance (b0, -(sizeof (pvti_ip4_encap_header_t)));
  pvti_ip4_encap_header_t *ve = vlib_buffer_get_current (b0);

  ve->ip4.dst_address.as_u32 = ip_addr_v4 (&pvti_if0->remote_ip).data_u32;
  // clib_host_to_net_u32 (0xc0a80102);
  ve->ip4.src_address.as_u32 = ip_addr_v4 (&pvti_if0->local_ip).data_u32;
  // clib_host_to_net_u32 (0xc0a80101);
  ve->ip4.ttl = 128;
  ve->ip4.ip_version_and_header_length = 0x45;
  ve->ip4.protocol = 0;

  ve->udp.src_port = pvti_if0->local_port;
  ve->udp.dst_port = pvti_if0->remote_port;
  ve->udp.length =
    b0->current_length - offsetof (pvti_ip4_encap_header_t, udp);
  ve->udp.checksum = 0;

  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;
  vnet_buffer (b0)->oflags |= VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
}

always_inline void
start_new_pvti_buffer (vlib_main_t *vm, pvti_if_t *pvti_if0, u32 bi0)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  vlib_buffer_advance (b0,
		       -(sizeof (pvti_packet_header_t) + PVTI_ALIGN_BYTES));
  pvti_packet_header_t *pvti0 = vlib_buffer_get_current (b0);
  // store the buffer index and current length - this "consumes"
  // the current buffer. FIXME: multibuffer packets
  pvti_if0->bi0 = bi0;
  // FIXME - any good place to take it from ?
  pvti_if0->bi0_max_current_length = 1500;
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
	  /*
	   * Direct from the driver, we should be at offset 0
	   * aka at &b0->data[0]
	   */
	  ASSERT (b0->current_data == 0);

	  pkts_processed += 1;

	  // ip40 = vlib_buffer_get_current (b0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  pvti_index0 = pvti_if_find_by_sw_if_index (sw_if_index0);
	  if (pvti_index0 == INDEX_INVALID)
	    {
	      b0->error = node->errors[PVTI_OUTPUT_ERROR_PEER];
	      goto trace_out;
	    }

	  vlib_buffer_advance (b0, -(sizeof (pvti_chunk_header_t)));
	  pvti_chunk_header_t *pvc0 = vlib_buffer_get_current (b0);
	  pvc0->total_chunk_length = b0->current_length;

	  pvti_if_t *pvti_if0 = pvti_if_get (pvti_index0);
	  if (pvti_if0->bi0 == INDEX_INVALID)
	    {
	      start_new_pvti_buffer (vm, pvti_if0, bi0);
	      vec_add1 (vti_ifs_with_packets, pvti_index0);
	      continue;
	      // NOTE: this buffer is not sent at this point.
	    }
	  else
	    {
	      vlib_buffer_t *vb0 = vlib_get_buffer (vm, pvti_if0->bi0);
	      u16 remaining_length =
		pvti_if0->bi0_max_current_length - vb0->current_length;
	      if (remaining_length < pvc0->total_chunk_length)
		{
		  encapsulate_pvti_buffer_ip4 (vm, pvti_if0);
		  to_next[0] = pvti_if0->bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  vlib_validate_buffer_enqueue_x1 (
		    vm, node, next_index, to_next, n_left_to_next, bi0, next0);
		  start_new_pvti_buffer (vm, pvti_if0, bi0);
		  vec_add1 (vti_ifs_with_packets, pvti_index0);
		  continue;
		  // NOTE: this buffer is not sent now
		}
	      void *tail = vlib_buffer_put_uninit (vb0, b0->current_length);
	      clib_memcpy (tail, vlib_buffer_get_current (b0),
			   b0->current_length);
	      // store the index in the temp space in case we need a buffer
	      // shortly.
	      vec_add1 (pvti_if0->bi_store, bi0);
	      continue;
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
