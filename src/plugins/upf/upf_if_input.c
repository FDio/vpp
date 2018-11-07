/*
 * Copyright (c) 2018 Travelping GmbH
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

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#include <rte_config.h>
#include <rte_common.h>
#include <rte_acl.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>

#if CLIB_DEBUG > 0
#define gtp_debug clib_warning
#else
#define gtp_debug(...)				\
  do { } while (0)
#endif

/* Statistics (not all errors) */
#define foreach_upf_if_input_error    \
_(IF_INPUT, "good packets if_input")

static char * upf_if_input_error_strings[] = {
#define _(sym,string) string,
  foreach_upf_if_input_error
#undef _
};

typedef enum {
#define _(sym,str) UPF_IF_INPUT_ERROR_##sym,
    foreach_upf_if_input_error
#undef _
    UPF_IF_INPUT_N_ERROR,
} upf_if_input_error_t;

#define foreach_upf_if_input_next		\
  _(DROP, "error-drop")				\
  _(IP4_CLASSIFY, "upf-ip4-flow-process")		\
  _(IP6_CLASSIFY, "upf-ip6-flow-process")

typedef enum {
#define _(s,n) UPF_IF_INPUT_NEXT_##s,
  foreach_upf_if_input_next
#undef _
  UPF_IF_INPUT_N_NEXT,
} upf_if_input_next_t;

typedef struct {
  u32 session_index;
  u64 cp_seid;
  u8 packet_data[64 - 1 * sizeof (u32)];
} upf_if_input_trace_t;

u8 * format_upf_if_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_if_input_trace_t * t
    = va_arg (*args, upf_if_input_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session%d seid %d \n%U%U",
	      t->session_index, t->cp_seid,
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static uword
upf_if_input (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  upf_main_t * gtm = &upf_main;
  vnet_main_t * vnm = gtm->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 thread_index = vlib_get_thread_index();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u32 sw_if_index = 0;
  u32 next = 0;
  u32 sidx = 0;
  u8 intf_type = ~0;
  u32 len;
  ip4_header_t *ip4;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_buffer_t * b;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  bi = from[0];
	  to_next[0] = bi;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b = vlib_get_buffer (vm, bi);

	  /* Get next node index and adj index from tunnel next_dpo */
	  sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_TX];
	  sidx = gtm->session_index_by_sw_if_index[sw_if_index];
	  intf_type = gtm->intf_type_by_sw_if_index[vnet_buffer(b)->sw_if_index[VLIB_RX]];

	  gtp_debug("HW If: %p, Session %d",
		    vnet_get_sup_hw_interface (vnm, sw_if_index), sidx);

	  vnet_buffer (b)->gtpu.session_index = sidx;
	  vnet_buffer (b)->gtpu.data_offset = 0;
	  vnet_buffer (b)->gtpu.src_intf = intf_type;
	  vnet_buffer (b)->gtpu.teid = 0;
	  ip4 = (ip4_header_t *)vlib_buffer_get_current(b);

	  if ((ip4->ip_version_and_header_length & 0xF0) == 0x40)
	    {
	      next = UPF_IF_INPUT_NEXT_IP4_CLASSIFY;
	      vnet_buffer (b)->gtpu.flags = BUFFER_HAS_IP4_HDR;
	    }
	  else
	    {
	      next = UPF_IF_INPUT_NEXT_IP6_CLASSIFY;
	      vnet_buffer (b)->gtpu.flags = BUFFER_HAS_IP6_HDR;
	    }

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

	  if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      upf_session_t * sess = pool_elt_at_index (gtm->sessions, sidx);
	      upf_if_input_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->session_index = sidx;
	      tr->cp_seid = sess->cp_seid;
	      clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
			   sizeof (tr->packet_data));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi, next);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (upf_if_input_node) = {
  .function = upf_if_input,
  .name = "upf-if-input",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_if_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_if_input_error_strings),
  .error_strings = upf_if_input_error_strings,
  .n_next_nodes = UPF_IF_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [UPF_IF_INPUT_NEXT_##s] = n,
    foreach_upf_if_input_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (upf_if_input_node, upf_if_input)

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
