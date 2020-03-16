/*
 * Copyright (c) 2020 Travelping GmbH
 *
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

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/upf_proxy.h>

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)				\
  do { } while (0)
#endif

typedef enum
{
  UPF_INPUT_NEXT_DROP,
  UPF_INPUT_NEXT_UPF_FORWARD,
  UPF_INPUT_N_NEXT,
} upf_input_next_t;

/* Statistics (not all errors) */
#define foreach_upf_input_error				\
  _(LENGTH, "inconsistent ip/tcp lengths")			\
  _(NO_LISTENER, "no redirect server available")		\
  _(INPUT, "good packets input")				\
  _(OPTIONS, "Could not parse options")				\
  _(CREATE_SESSION_FAIL, "Sessions couldn't be allocated")

static char *upf_input_error_strings[] = {
#define _(sym,string) string,
  foreach_upf_input_error
#undef _
};

typedef enum
{
#define _(sym,str) UPF_INPUT_ERROR_##sym,
  foreach_upf_input_error
#undef _
    UPF_INPUT_N_ERROR,
} upf_input_error_t;

typedef struct
{
  u32 session_index;
  u64 cp_seid;
  u32 pdr_id;
  u32 far_id;
  u8 packet_data[64 - 1 * sizeof (u32)];
}
upf_input_trace_t;

static u8 *
format_upf_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_input_trace_t *t = va_arg (*args, upf_input_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session%d cp-seid 0x%016" PRIx64 " pdr %d far %d\n%U%U",
	      t->session_index, t->cp_seid, t->pdr_id, t->far_id,
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static_always_inline void
upf_vnet_buffer_l3_hdr_offset_is_current (vlib_buffer_t * b)
{
  vnet_buffer (b)->l3_hdr_offset = b->current_data;
  b->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
}

static uword
upf_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	   vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  upf_main_t *gtm = &upf_main;
  vnet_main_t *vnm = gtm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 thread_index = vlib_get_thread_index ();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u32 sw_if_index = 0;
  u32 next = 0;
  upf_session_t *sess = NULL;
  u32 sidx = 0;
  u32 len;
  struct rules *active;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b;
      u32 error;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  upf_pdr_t *pdr = NULL;
	  upf_far_t *far = NULL;

	  bi = from[0];
	  to_next[0] = bi;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b = vlib_get_buffer (vm, bi);

	  /* Get next node index and adj index from tunnel next_dpo */
	  sidx = upf_buffer_opaque (b)->gtpu.session_index;
	  sess = pool_elt_at_index (gtm->sessions, sidx);

	  error = 0;
	  next = UPF_INPUT_NEXT_UPF_FORWARD;
	  active = pfcp_get_rules (sess, PFCP_ACTIVE);

	  if (PREDICT_TRUE (upf_buffer_opaque (b)->gtpu.pdr_idx != ~0))
	    {
	      pdr = active->pdr + upf_buffer_opaque (b)->gtpu.pdr_idx;
	      far = pfcp_get_far_by_id (active, pdr->far_id);
	    }

	  upf_debug ("IP hdr: %U", format_ip4_header,
		     vlib_buffer_get_current (b));
	  upf_debug ("PDR Idx: %u, PDR: %p, FAR: %p",
		     upf_buffer_opaque (b)->gtpu.pdr_idx, pdr, far);
	  if (PREDICT_FALSE (!pdr) || PREDICT_FALSE (!far))
	    goto stats;

	  upf_debug ("PDR OHR: %u", pdr->outer_header_removal);

	  /* Outer Header Removal */
	  switch (pdr->outer_header_removal)
	    {
	    case OUTER_HEADER_REMOVAL_GTP_IP4:	/* GTP-U/UDP/IPv4 */
	      if (PREDICT_FALSE
		  ((upf_buffer_opaque (b)->gtpu.flags & BUFFER_HDR_MASK) !=
		   BUFFER_GTP_UDP_IP4))
		{
		  next = UPF_INPUT_NEXT_DROP;
		  // error = UPF_INPUT_ERROR_INVALID_OUTER_HEADER;
		  goto trace;
		}
	      vlib_buffer_advance (b,
				   upf_buffer_opaque (b)->gtpu.data_offset);
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      break;

	    case OUTER_HEADER_REMOVAL_GTP_IP6:	/* GTP-U/UDP/IPv6 */
	      if (PREDICT_FALSE
		  ((upf_buffer_opaque (b)->gtpu.flags & BUFFER_HDR_MASK) !=
		   BUFFER_GTP_UDP_IP6))
		{
		  next = UPF_INPUT_NEXT_DROP;
		  // error = UPF_INPUT_ERROR_INVALID_OUTER_HEADER;
		  goto trace;
		}
	      vlib_buffer_advance (b,
				   upf_buffer_opaque (b)->gtpu.data_offset);
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      break;

	    case OUTER_HEADER_REMOVAL_UDP_IP4:	/* UDP/IPv4 */
	      if (PREDICT_FALSE
		  ((upf_buffer_opaque (b)->gtpu.flags & BUFFER_HDR_MASK) !=
		   BUFFER_UDP_IP4))
		{
		  next = UPF_INPUT_NEXT_DROP;
		  // error = UPF_INPUT_ERROR_INVALID_OUTER_HEADER;
		  goto trace;
		}
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      vlib_buffer_advance (b,
				   sizeof (ip4_header_t) +
				   sizeof (udp_header_t));
	      break;

	    case OUTER_HEADER_REMOVAL_UDP_IP6:	/* UDP/IPv6 */
	      if (PREDICT_FALSE
		  ((upf_buffer_opaque (b)->gtpu.flags & BUFFER_HDR_MASK) !=
		   BUFFER_UDP_IP6))
		{
		  next = UPF_INPUT_NEXT_DROP;
		  // error = UPF_INPUT_ERROR_INVALID_OUTER_HEADER;
		  goto trace;
		}
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      vlib_buffer_advance (b,
				   sizeof (ip6_header_t) +
				   sizeof (udp_header_t));
	      break;

	    case OUTER_HEADER_REMOVAL_GTP:	/* GTP-U/UDP/IP */
	      switch (upf_buffer_opaque (b)->gtpu.flags & BUFFER_HDR_MASK)
		{
		case BUFFER_GTP_UDP_IP4:
		case BUFFER_GTP_UDP_IP6:
		  vlib_buffer_advance (b,
				       upf_buffer_opaque (b)->
				       gtpu.data_offset);
		  upf_vnet_buffer_l3_hdr_offset_is_current (b);
		  break;

		default:
		  next = UPF_INPUT_NEXT_DROP;
		  // error = UPF_INPUT_ERROR_INVALID_OUTER_HEADER;
		  goto trace;
		}
	      break;

	    default:
	      upf_vnet_buffer_l3_hdr_offset_is_current (b);
	      break;
	    }

	stats:
	  len = vlib_buffer_length_in_chain (vm, b);
	  stats_n_packets += 1;
	  stats_n_bytes += len;

	  /* Batch stats increment on the same gtpu tunnel so counter is not
	     incremented per packet. Note stats are still incremented for deleted
	     and admin-down tunnel where packets are dropped. It is not worthwhile
	     to check for this rare case and affect normal path performance. */
	  if (PREDICT_FALSE (sw_if_index != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len;
	      stats_sw_if_index = sw_if_index;
	    }

	trace:
	  b->error = error ? node->errors[error] : 0;

	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      upf_input_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->session_index = sidx;
	      tr->cp_seid = sess->cp_seid;
	      tr->pdr_id = pdr ? pdr->id : ~0;
	      tr->far_id = far ? far->id : ~0;
	      clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
			   sizeof (tr->packet_data));
	    }
	  upf_debug ("Next: %u, Error: %u", next, error);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi, next);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (upf_ip4_input_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * from_frame)
{
  return upf_input (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (upf_ip6_input_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * from_frame)
{
  return upf_input (vm, node, from_frame, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip4_input_node) = {
  .name = "upf-ip4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_input_error_strings),
  .error_strings = upf_input_error_strings,
  .n_next_nodes = UPF_INPUT_N_NEXT,
  .next_nodes = {
    [UPF_INPUT_NEXT_DROP]        = "error-drop",
    [UPF_INPUT_NEXT_UPF_FORWARD] = "upf-ip4-forward",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (upf_ip6_input_node) = {
  .name = "upf-ip6-input",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_input_error_strings),
  .error_strings = upf_input_error_strings,
  .n_next_nodes = UPF_INPUT_N_NEXT,
  .next_nodes = {
    [UPF_INPUT_NEXT_DROP]        = "error-drop",
    [UPF_INPUT_NEXT_UPF_FORWARD] = "upf-ip6-forward",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
