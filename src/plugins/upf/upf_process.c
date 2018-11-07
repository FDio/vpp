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

#include <inttypes.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ethernet/ethernet.h>

#include <upf/upf.h>
#include <upf/upf_pfcp.h>
#include <upf/upf_http_redirect_server.h>

#if CLIB_DEBUG > 0
#define gtp_debug clib_warning
#else
#define gtp_debug(...)				\
  do { } while (0)
#endif

/* Statistics (not all errors) */
#define foreach_upf_process_error		\
  _(PROCESS, "good packets process")

static char * upf_process_error_strings[] = {
#define _(sym,string) string,
  foreach_upf_process_error
#undef _
};

typedef enum {
#define _(sym,str) UPF_PROCESS_ERROR_##sym,
  foreach_upf_process_error
#undef _
  UPF_PROCESS_N_ERROR,
} upf_process_error_t;

typedef struct {
  u32 session_index;
  u64 cp_seid;
  u32 pdr_id;
  u32 far_id;
  u8 packet_data[64 - 1 * sizeof (u32)];
} upf_process_trace_t;

u8 * format_upf_process_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  upf_process_trace_t * t
    = va_arg (*args, upf_process_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "upf_session%d cp-seid 0x%016" PRIx64 " pdr %d far %d\n%U%U",
	      t->session_index, t->cp_seid, t->pdr_id, t->far_id,
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static uword
upf_process (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame, int is_ip4)
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
  upf_session_t * sess = NULL;
  u32 sidx = 0;
  u32 len;
  struct rules *active;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      upf_pdr_t * pdr = NULL;
      upf_far_t * far = NULL;
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
	  sidx = vnet_buffer (b)->gtpu.session_index;
	  sess = pool_elt_at_index (gtm->sessions, sidx);

	  next = UPF_PROCESS_NEXT_DROP;
	  active = sx_get_rules(sess, SX_ACTIVE);

	  if (PREDICT_TRUE (vnet_buffer (b)->gtpu.pdr_idx != ~0))
	    {
	      pdr = active->pdr + vnet_buffer (b)->gtpu.pdr_idx;
	      far = sx_get_far_by_id(active, pdr->far_id);
	    }

	  if (PREDICT_TRUE (pdr != 0))
	    {
	      /* Outer Header Removal */
	      switch (pdr->outer_header_removal)
		{
		case 0:			/* GTP-U/UDP/IPv4 */
		  if (PREDICT_FALSE ((vnet_buffer (b)->gtpu.flags & BUFFER_HDR_MASK) !=
				     BUFFER_GTP_UDP_IP4))
		    {
		      next = UPF_PROCESS_NEXT_DROP;
		      // error = UPF_PROCESS_ERROR_INVALID_OUTER_HEADER;
		      goto trace;
		    }
		  vlib_buffer_advance (b, vnet_buffer (b)->gtpu.data_offset);
		  break;

		case 1:			/* GTP-U/UDP/IPv6 */
		  if (PREDICT_FALSE ((vnet_buffer (b)->gtpu.flags & BUFFER_HDR_MASK) !=
				     BUFFER_GTP_UDP_IP6))
		    {
		      next = UPF_PROCESS_NEXT_DROP;
		      // error = UPF_PROCESS_ERROR_INVALID_OUTER_HEADER;
		      goto trace;
		    }
		  vlib_buffer_advance (b, vnet_buffer (b)->gtpu.data_offset);
		  break;

		case 2:			/* UDP/IPv4 */
		  if (PREDICT_FALSE ((vnet_buffer (b)->gtpu.flags & BUFFER_HDR_MASK) !=
				     BUFFER_UDP_IP4))
		    {
		      next = UPF_PROCESS_NEXT_DROP;
		      // error = UPF_PROCESS_ERROR_INVALID_OUTER_HEADER;
		      goto trace;
		    }
		  vlib_buffer_advance (b, sizeof(ip4_header_t) + sizeof(udp_header_t));
		  break;

		case 3:			/* UDP/IPv6 */
		  if (PREDICT_FALSE ((vnet_buffer (b)->gtpu.flags & BUFFER_HDR_MASK) !=
				     BUFFER_UDP_IP6))
		    {
		      next = UPF_PROCESS_NEXT_DROP;
		      // error = UPF_PROCESS_ERROR_INVALID_OUTER_HEADER;
		      goto trace;
		    }
		  vlib_buffer_advance (b, sizeof(ip6_header_t) + sizeof(udp_header_t));
		  break;
		}

	      if (PREDICT_TRUE (far->apply_action & FAR_FORWARD))
		{
		  if (far->forward.flags & FAR_F_OUTER_HEADER_CREATION)
		    {
		      if (far->forward.outer_header_creation.description
			  & OUTER_HEADER_CREATION_GTP_IP4)
			{
			  next = UPF_PROCESS_NEXT_GTP_IP4_ENCAP;
			}
		      else if (far->forward.outer_header_creation.description
			       & OUTER_HEADER_CREATION_GTP_IP6)
			{
			  next = UPF_PROCESS_NEXT_GTP_IP6_ENCAP;
			}
		      else if (far->forward.outer_header_creation.description
			       & OUTER_HEADER_CREATION_UDP_IP4)
			{
			  next = UPF_PROCESS_NEXT_DROP;
			  // error = UPF_PROCESS_ERROR_NOT_YET;
			  goto trace;
			}
		      else if (far->forward.outer_header_creation.description
			       & OUTER_HEADER_CREATION_UDP_IP6)
			{
			  next = UPF_PROCESS_NEXT_DROP;
			  // error = UPF_PROCESS_ERROR_NOT_YET;
			  goto trace;
			}
		    }
		  else if (far->forward.flags & FAR_F_REDIRECT_INFORMATION)
		    {
		      u32 fib_index = is_ip4 ?
			ip4_fib_table_get_index_for_sw_if_index(far->forward.dst_sw_if_index) :
			ip6_fib_table_get_index_for_sw_if_index(far->forward.dst_sw_if_index);

		      vnet_buffer (b)->sw_if_index[VLIB_TX] = far->forward.dst_sw_if_index;
		      vnet_buffer2 (b)->gtpu.session_index = sidx;
		      vnet_buffer2 (b)->gtpu.far_index = (far - active->far) | 0x80000000;
		      vnet_buffer2 (b)->connection_index =
			upf_http_redirect_session(fib_index, 1);
		      next = UPF_PROCESS_NEXT_IP_LOCAL;
		    }
		  else
		    {
		      if (is_ip4)
			{
			  b->flags &= ~(VNET_BUFFER_F_OFFLOAD_TCP_CKSUM |
					VNET_BUFFER_F_OFFLOAD_UDP_CKSUM |
					VNET_BUFFER_F_OFFLOAD_IP_CKSUM);
			  vnet_buffer (b)->sw_if_index[VLIB_TX] =
			    ip4_fib_table_get_index_for_sw_if_index(far->forward.dst_sw_if_index);
			}
		      else
			{
			  b->flags &= ~(VNET_BUFFER_F_OFFLOAD_TCP_CKSUM |
					VNET_BUFFER_F_OFFLOAD_UDP_CKSUM);
			  vnet_buffer (b)->sw_if_index[VLIB_TX] =
			    ip6_fib_table_get_index_for_sw_if_index(far->forward.dst_sw_if_index);
			}
		      next = UPF_PROCESS_NEXT_IP_INPUT;
		    }
		}
	      else if (far->apply_action & FAR_BUFFER)
		{
		  next = UPF_PROCESS_NEXT_DROP;
		  // error = UPF_PROCESS_ERROR_NOT_YET;
		}
	      else
		{
		  next = UPF_PROCESS_NEXT_DROP;
		}

#define IS_DL(_pdr, _far)						\
	      ((_pdr)->pdi.src_intf == SRC_INTF_CORE || (_far)->forward.dst_intf == DST_INTF_ACCESS)
#define IS_UL(_pdr, _far)						\
	      ((_pdr)->pdi.src_intf == SRC_INTF_ACCESS || (_far)->forward.dst_intf == DST_INTF_CORE)

	      clib_warning("pdr: %d, far: %d\n", pdr->id, far->id);
	      next = process_urrs(vm, sess, active, pdr, b,
				  IS_DL(pdr, far), IS_UL(pdr, far), next);

#undef IS_DL
#undef IS_UL
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

	trace:
	  if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      upf_process_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->session_index = sidx;
	      tr->cp_seid = sess->cp_seid;
	      tr->pdr_id = pdr ? pdr->id : ~0;
	      tr->far_id = far ? far->id : ~0;
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

static uword
upf_ip4_process (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  return upf_process(vm, node, from_frame, /* is_ip4 */ 1);
}

static uword
upf_ip6_process (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  return upf_process(vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (upf_ip4_process_node) = {
  .function = upf_ip4_process,
  .name = "upf-ip4-process",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_process_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_process_error_strings),
  .error_strings = upf_process_error_strings,
  .n_next_nodes = UPF_PROCESS_N_NEXT,
  .next_nodes = {
    [UPF_PROCESS_NEXT_DROP]          = "error-drop",
    [UPF_PROCESS_NEXT_GTP_IP4_ENCAP] = "upf4-encap",
    [UPF_PROCESS_NEXT_GTP_IP6_ENCAP] = "upf6-encap",
    [UPF_PROCESS_NEXT_IP_INPUT]      = "ip4-input",
    [UPF_PROCESS_NEXT_IP_LOCAL]      = "ip4-local",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (upf_ip4_process_node, upf_ip4_process)

VLIB_REGISTER_NODE (upf_ip6_process_node) = {
  .function = upf_ip6_process,
  .name = "upf-ip6-process",
  .vector_size = sizeof (u32),
  .format_trace = format_upf_process_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(upf_process_error_strings),
  .error_strings = upf_process_error_strings,
  .n_next_nodes = UPF_PROCESS_N_NEXT,
  .next_nodes = {
    [UPF_PROCESS_NEXT_DROP]          = "error-drop",
    [UPF_PROCESS_NEXT_GTP_IP4_ENCAP] = "upf4-encap",
    [UPF_PROCESS_NEXT_GTP_IP6_ENCAP] = "upf6-encap",
    [UPF_PROCESS_NEXT_IP_INPUT]      = "ip6-input",
    [UPF_PROCESS_NEXT_IP_LOCAL]      = "ip6-local",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (upf_ip6_process_node, upf_ip6_process)

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
