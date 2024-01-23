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
  u32 next_index;
  u32 sw_if_index;
  ip_address_t remote_ip;
  u16 remote_port;
  u16 local_port;
  u32 seq;
} pvti_bypass_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_pvti_bypass_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pvti_bypass_trace_t *t = va_arg (*args, pvti_bypass_trace_t *);

  s = format (s, "PVTI-BYPASS: sw_if_index %d, next index %d\n",
	      t->sw_if_index, t->next_index);
  s = format (s, "  src %U sport %d dport %d\n", format_ip_address,
	      &t->remote_ip, t->remote_port, t->local_port);
  s = format (s, "  seq: %d", t->seq);
  return s;
}

vlib_node_registration_t pvti4_bypass_node;
vlib_node_registration_t pvti6_bypass_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_pvti_bypass_error                                             \
  _ (PROCESSED, "PVTI bypass tunnel packets processed")

typedef enum
{
#define _(sym, str) PVTI_BYPASS_ERROR_##sym,
  foreach_pvti_bypass_error
#undef _
    PVTI_BYPASS_N_ERROR,
} pvti_bypass_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *pvti_bypass_error_strings[] = {
#define _(sym, string) string,
  foreach_pvti_bypass_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  PVTI_BYPASS_NEXT_DROP,
  PVTI_BYPASS_NEXT_PVTI_INPUT,
  PVTI_BYPASS_N_NEXT,
} pvti_bypass_next_t;

always_inline u16
pvti_bypass_node_common (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, bool is_ip6)
{
  u32 n_left_from, *from, *to_next;
  pvti_bypass_next_t next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_input_node.index);

  u32 pkts_processed = 0;
  // free buffer pools are per-worker,
  // and tx stream index is determined from worker.

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 sw_if_index0 = 0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  udp_header_t *udp0;
	  u32 bi0, ip_len0, udp_len0, flags0, next0;
	  u8 error0, good_udp0, proto0;
	  i32 len_diff0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* setup the packet for the next feature */
	  vnet_feature_next (&next0, b0);

	  if (is_ip6)
	    {
	      ip60 = vlib_buffer_get_current (b0);
	    }
	  else
	    {
	      ip40 = vlib_buffer_get_current (b0);
	    }

	  if (is_ip6)
	    {
	      proto0 = ip60->protocol;
	    }
	  else
	    {
	      /* Treat IP frag packets as "experimental" protocol for now */
	      proto0 = ip4_is_fragment (ip40) ? 0xfe : ip40->protocol;
	    }

	  /* Process packet 0 */
	  if (proto0 != IP_PROTOCOL_UDP)
	    goto exit; /* not UDP packet */

	  if (is_ip6)
	    udp0 = ip6_next_header (ip60);
	  else
	    udp0 = ip4_next_header (ip40);

	  /* FIXME: look up the destination ip and port here */
	  u32 pvti_index0 = pvti_if_find_by_remote_ip4_and_port (
	    &ip40->src_address, clib_net_to_host_u16 (udp0->src_port));
	  if (pvti_index0 == INDEX_INVALID)
	    goto exit;

	  flags0 = b0->flags;
	  good_udp0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum.
	   */
	  good_udp0 |= udp0->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip6)
	    ip_len0 = clib_net_to_host_u16 (ip60->payload_length);
	  else
	    ip_len0 = clib_net_to_host_u16 (ip40->length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);
	  len_diff0 = ip_len0 - udp_len0;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp0))
	    {
	      if (is_ip6)
		flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);
	      else
		flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
	      good_udp0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
	    }

	  if (is_ip6)
	    {
	      error0 = good_udp0 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP6_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error0 = good_udp0 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP4_ERROR_UDP_LENGTH;
	    }

	  next0 = error0 ? PVTI_BYPASS_NEXT_DROP : PVTI_BYPASS_NEXT_PVTI_INPUT;
	  b0->error = error0 ? error_node->errors[error0] : 0;

	  /* pvtiX-input node expect current at PVTI header */
	  if (is_ip6)
	    vlib_buffer_advance (b0, sizeof (ip6_header_t) +
				       sizeof (udp_header_t));
	  else
	    vlib_buffer_advance (b0, sizeof (ip4_header_t) +
				       sizeof (udp_header_t));
	exit:

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      pvti_bypass_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->seq = 0; // clib_net_to_host_u32 (pvti0->seq);
	      if (is_ip6)
		{
		}
	      else
		{
		  t->remote_ip.ip.ip4 = ip40->src_address;
		  t->remote_ip.version = AF_IP4;
		}
	      // t->local_port = h0->udp.dst_port;
	      // t->remote_port = h0->udp.src_port;
	    }

	  pkts_processed += 1;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       PVTI_BYPASS_ERROR_PROCESSED, pkts_processed);
  return frame->n_vectors;
}

VLIB_NODE_FN (pvti4_bypass_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return pvti_bypass_node_common (vm, node, frame, 0);
}

VLIB_NODE_FN (pvti6_bypass_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return pvti_bypass_node_common (vm, node, frame, 1);
}

#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (pvti4_bypass_node) = 
{
  .name = "ip4-pvti-bypass",
  .vector_size = sizeof (u32),
  .format_trace = format_pvti_bypass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(pvti_bypass_error_strings),
  .error_strings = pvti_bypass_error_strings,

  .n_next_nodes = PVTI_BYPASS_N_NEXT,

  .next_nodes = {
        [PVTI_BYPASS_NEXT_DROP] = "error-drop",
        [PVTI_BYPASS_NEXT_PVTI_INPUT] = "pvti4-input",
  },

};

VLIB_REGISTER_NODE (pvti6_bypass_node) = 
{
  .name = "ip6-pvti-bypass",
  .vector_size = sizeof (u32),
  .format_trace = format_pvti_bypass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(pvti_bypass_error_strings),
  .error_strings = pvti_bypass_error_strings,

  .n_next_nodes = PVTI_BYPASS_N_NEXT,

  .next_nodes = {
        [PVTI_BYPASS_NEXT_DROP] = "error-drop",
        [PVTI_BYPASS_NEXT_PVTI_INPUT] = "pvti6-input",
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
