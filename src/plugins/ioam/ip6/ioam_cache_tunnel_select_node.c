/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
/*
 * ioam_cache_tunnel_select_node.c
 * This file implements anycast server selection using ioam data
 * attached to anycast service selection.
 * Anycast service is reachable via multiple servers reachable
 * over SR tunnels.
 * Works with TCP Anycast application.
 * Cache entry is created when TCP SYN is received for anycast destination.
 * Response TCP SYN ACKs for anycast service is compared and selected
 * response is forwarded.
 * The functionality is introduced via graph nodes that are hooked into
 * vnet graph via classifier configs like below:
 *
 * Enable anycast service selection:
 * set ioam ip6 sr-tunnel-select oneway
 *
 * Enable following classifier on the anycast service client facing interface
 * e.g. anycast service is db06::06 then:
 * classify session acl-hit-next ip6-node ip6-add-syn-hop-by-hop table-index 0 match l3
 * ip6 dst db06::06 ioam-encap anycast
 *
 * Enable following classifier on the interfaces facing the server of anycast service:
 * classify session acl-hit-next ip6-node ip6-lookup table-index 0 match l3
 *            ip6 src db06::06 ioam-decap anycast
 *
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr.h>
#include <ioam/ip6/ioam_cache.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/ip/ip6_hop_by_hop_packet.h>

typedef struct
{
  u32 next_index;
  u32 flow_label;
} cache_ts_trace_t;

/* packet trace format function */
static u8 *
format_cache_ts_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cache_ts_trace_t *t = va_arg (*args, cache_ts_trace_t *);

  s = format (s, "CACHE: flow_label %d, next index %d",
	      t->flow_label, t->next_index);
  return s;
}

#define foreach_cache_ts_error \
_(RECORDED, "ip6 iOAM headers cached")

typedef enum
{
#define _(sym,str) CACHE_TS_ERROR_##sym,
  foreach_cache_ts_error
#undef _
    CACHE_TS_N_ERROR,
} cache_ts_error_t;

static char *cache_ts_error_strings[] = {
#define _(sym,string) string,
  foreach_cache_ts_error
#undef _
};

typedef enum
{
  IOAM_CACHE_TS_NEXT_POP_HBYH,
  IOAM_CACHE_TS_ERROR_NEXT_DROP,
  IOAM_CACHE_TS_N_NEXT,
} cache_ts_next_t;

static uword
ip6_ioam_cache_ts_node_fn (vlib_main_t * vm,
			   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  u32 n_left_from, *from, *to_next;
  cache_ts_next_t next_index;
  u32 recorded = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      // TODO: dual loop
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *p0;
	  u32 next0 = IOAM_CACHE_TS_NEXT_POP_HBYH;
	  ip6_header_t *ip0;
	  ip6_hop_by_hop_header_t *hbh0, *hbh_cmp;
	  tcp_header_t *tcp0;
	  u32 tcp_offset0;
	  u32 cache_ts_index = 0;
	  u8 cache_thread_id = 0;
	  int result = 0;
	  int skip = 0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  if (IP_PROTOCOL_TCP ==
	      ip6_locate_header (p0, ip0, IP_PROTOCOL_TCP, &tcp_offset0))
	    {
	      tcp0 = (tcp_header_t *) ((u8 *) ip0 + tcp_offset0);
	      if ((tcp0->flags & TCP_FLAG_SYN) == TCP_FLAG_SYN &&
		  (tcp0->flags & TCP_FLAG_ACK) == TCP_FLAG_ACK)
		{
		  /* Look up and compare */
		  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);

		  if (0 == ioam_cache_ts_lookup (ip0,
						 hbh0->protocol,
						 clib_net_to_host_u16
						 (tcp0->src_port),
						 clib_net_to_host_u16
						 (tcp0->dst_port),
						 clib_net_to_host_u32
						 (tcp0->ack_number), &hbh_cmp,
						 &cache_ts_index,
						 &cache_thread_id, 1))
		    {
		      /* response seen */
		      result = -1;
		      if (hbh_cmp)
			result =
			  ip6_ioam_analyse_compare_path_delay (hbh0, hbh_cmp,
							       cm->criteria_oneway);
		      if (result >= 0)
			{
			  /* current syn/ack is worse than the earlier: Drop */
			  next0 = IOAM_CACHE_TS_ERROR_NEXT_DROP;
			  /* Check if all responses are received or time has exceeded
			     send cached response if yes */
			  ioam_cache_ts_check_and_send (cache_thread_id,
							cache_ts_index);
			}
		      else
			{
			  /* Update cache with this buffer */
			  /* If successfully updated then skip sending it */
			  if (0 ==
			      (result =
			       ioam_cache_ts_update (cache_thread_id,
						     cache_ts_index, bi0,
						     hbh0)))
			    {
			      skip = 1;
			    }
			  else
			    next0 = IOAM_CACHE_TS_ERROR_NEXT_DROP;
			}
		    }
		  else
		    {
		      next0 = IOAM_CACHE_TS_ERROR_NEXT_DROP;
		    }
		}
	      else if ((tcp0->flags & TCP_FLAG_RST) == TCP_FLAG_RST)
		{
		  /* Look up and compare */
		  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
		  if (0 == ioam_cache_ts_lookup (ip0, hbh0->protocol, clib_net_to_host_u16 (tcp0->src_port), clib_net_to_host_u16 (tcp0->dst_port), clib_net_to_host_u32 (tcp0->ack_number), &hbh_cmp, &cache_ts_index, &cache_thread_id, 1))	//response seen
		    {
		      next0 = IOAM_CACHE_TS_ERROR_NEXT_DROP;
		      if (hbh_cmp)
			ioam_cache_ts_check_and_send (cache_thread_id,
						      cache_ts_index);
		    }

		}
	    }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (p0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  cache_ts_trace_t *t =
		    vlib_add_trace (vm, node, p0, sizeof (*t));
		  t->flow_label =
		    clib_net_to_host_u32
		    (ip0->ip_version_traffic_class_and_flow_label);
		  t->next_index = next0;
		}
	    }
	  /* verify speculative enqueue, maybe switch current next frame */
	  if (!skip)
	    {
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next,
					       bi0, next0);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, ioam_cache_ts_node.index,
			       CACHE_TS_ERROR_RECORDED, recorded);
  return frame->n_vectors;
}

/*
 * Node for IP6 iOAM header cache
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ioam_cache_ts_node) =
{
  .function = ip6_ioam_cache_ts_node_fn,
  .name = "ip6-ioam-tunnel-select",
  .vector_size = sizeof (u32),
  .format_trace = format_cache_ts_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (cache_ts_error_strings),
  .error_strings = cache_ts_error_strings,
  .n_next_nodes = IOAM_CACHE_TS_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [IOAM_CACHE_TS_NEXT_POP_HBYH] = "ip6-pop-hop-by-hop",
    [IOAM_CACHE_TS_ERROR_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

typedef struct
{
  u32 next_index;
} ip6_reset_ts_hbh_trace_t;

/* packet trace format function */
static u8 *
format_ip6_reset_ts_hbh_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_reset_ts_hbh_trace_t *t = va_arg (*args,
					ip6_reset_ts_hbh_trace_t *);

  s =
    format (s, "IP6_IOAM_RESET_TUNNEL_SELECT_HBH: next index %d",
	    t->next_index);
  return s;
}

vlib_node_registration_t ip6_reset_ts_hbh_node;

#define foreach_ip6_reset_ts_hbh_error \
_(PROCESSED, "iOAM Syn/Ack Pkts processed") \
_(SAVED, "iOAM Syn Pkts state saved") \
_(REMOVED, "iOAM Syn/Ack Pkts state removed")

typedef enum
{
#define _(sym,str) IP6_RESET_TS_HBH_ERROR_##sym,
  foreach_ip6_reset_ts_hbh_error
#undef _
    IP6_RESET_TS_HBH_N_ERROR,
} ip6_reset_ts_hbh_error_t;

static char *ip6_reset_ts_hbh_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_reset_ts_hbh_error
#undef _
};

#define foreach_ip6_ioam_cache_ts_input_next    \
  _(IP6_LOOKUP, "ip6-lookup")                   \
  _(DROP, "error-drop")

typedef enum
{
#define _(s,n) IP6_IOAM_CACHE_TS_INPUT_NEXT_##s,
  foreach_ip6_ioam_cache_ts_input_next
#undef _
    IP6_IOAM_CACHE_TS_INPUT_N_NEXT,
} ip6_ioam_cache_ts_input_next_t;


static uword
ip6_reset_ts_hbh_node_fn (vlib_main_t * vm,
			  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  u32 n_left_from, *from, *to_next;
  ip_lookup_next_t next_index;
  u32 processed = 0, cache_ts_added = 0;
  u64 now;
  u8 *rewrite = cm->rewrite;
  u32 rewrite_length = vec_len (rewrite);
  ioam_e2e_cache_option_t *e2e = 0;
  u8 no_of_responses = cm->wait_for_responses;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      now = vlib_time_now (vm);
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  ip6_header_t *ip0, *ip1;
	  tcp_header_t *tcp0, *tcp1;
	  u32 tcp_offset0, tcp_offset1;
	  ip6_hop_by_hop_header_t *hbh0, *hbh1;
	  u64 *copy_src0, *copy_dst0, *copy_src1, *copy_dst1;
	  u16 new_l0, new_l1;
	  u32 pool_index0 = 0, pool_index1 = 0;

	  next0 = next1 = IP6_IOAM_CACHE_TS_INPUT_NEXT_IP6_LOOKUP;
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }


	  /* speculatively enqueue b0 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);

	  if (IP_PROTOCOL_TCP !=
	      ip6_locate_header (b0, ip0, IP_PROTOCOL_TCP, &tcp_offset0))
	    {
	      goto NEXT00;
	    }
	  tcp0 = (tcp_header_t *) ((u8 *) ip0 + tcp_offset0);
	  if ((tcp0->flags & TCP_FLAG_SYN) == TCP_FLAG_SYN &&
	      (tcp0->flags & TCP_FLAG_ACK) == 0)
	    {
	      if (no_of_responses > 0)
		{
		  /* Create TS select entry */
		  if (0 == ioam_cache_ts_add (ip0,
					      clib_net_to_host_u16
					      (tcp0->src_port),
					      clib_net_to_host_u16
					      (tcp0->dst_port),
					      clib_net_to_host_u32
					      (tcp0->seq_number) + 1,
					      no_of_responses, now,
					      vm->thread_index, &pool_index0))
		    {
		      cache_ts_added++;
		    }
		}
	      copy_dst0 = (u64 *) (((u8 *) ip0) - rewrite_length);
	      copy_src0 = (u64 *) ip0;

	      copy_dst0[0] = copy_src0[0];
	      copy_dst0[1] = copy_src0[1];
	      copy_dst0[2] = copy_src0[2];
	      copy_dst0[3] = copy_src0[3];
	      copy_dst0[4] = copy_src0[4];

	      vlib_buffer_advance (b0, -(word) rewrite_length);
	      ip0 = vlib_buffer_get_current (b0);

	      hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
	      /* $$$ tune, rewrite_length is a multiple of 8 */
	      clib_memcpy (hbh0, rewrite, rewrite_length);
	      e2e =
		(ioam_e2e_cache_option_t *) ((u8 *) hbh0 +
					     cm->rewrite_pool_index_offset);
	      e2e->pool_id = (u8) vm->thread_index;
	      e2e->pool_index = pool_index0;
	      ioam_e2e_id_rewrite_handler ((ioam_e2e_id_option_t *)
					   ((u8 *) e2e +
					    sizeof (ioam_e2e_cache_option_t)),
					   &cm->sr_localsid_ts);
	      /* Patch the protocol chain, insert the h-b-h (type 0) header */
	      hbh0->protocol = ip0->protocol;
	      ip0->protocol = 0;
	      new_l0 =
		clib_net_to_host_u16 (ip0->payload_length) + rewrite_length;
	      ip0->payload_length = clib_host_to_net_u16 (new_l0);
	      processed++;
	    }

	NEXT00:
	  if (IP_PROTOCOL_TCP !=
	      ip6_locate_header (b1, ip1, IP_PROTOCOL_TCP, &tcp_offset1))
	    {
	      goto TRACE00;
	    }
	  tcp1 = (tcp_header_t *) ((u8 *) ip1 + tcp_offset1);
	  if ((tcp1->flags & TCP_FLAG_SYN) == TCP_FLAG_SYN &&
	      (tcp1->flags & TCP_FLAG_ACK) == 0)
	    {
	      if (no_of_responses > 0)
		{
		  /* Create TS select entry */
		  if (0 == ioam_cache_ts_add (ip1,
					      clib_net_to_host_u16
					      (tcp1->src_port),
					      clib_net_to_host_u16
					      (tcp1->dst_port),
					      clib_net_to_host_u32
					      (tcp1->seq_number) + 1,
					      no_of_responses, now,
					      vm->thread_index, &pool_index1))
		    {
		      cache_ts_added++;
		    }
		}

	      copy_dst1 = (u64 *) (((u8 *) ip1) - rewrite_length);
	      copy_src1 = (u64 *) ip1;

	      copy_dst1[0] = copy_src1[0];
	      copy_dst1[1] = copy_src1[1];
	      copy_dst1[2] = copy_src1[2];
	      copy_dst1[3] = copy_src1[3];
	      copy_dst1[4] = copy_src1[4];

	      vlib_buffer_advance (b1, -(word) rewrite_length);
	      ip1 = vlib_buffer_get_current (b1);

	      hbh1 = (ip6_hop_by_hop_header_t *) (ip1 + 1);
	      /* $$$ tune, rewrite_length is a multiple of 8 */
	      clib_memcpy (hbh1, rewrite, rewrite_length);
	      e2e =
		(ioam_e2e_cache_option_t *) ((u8 *) hbh1 +
					     cm->rewrite_pool_index_offset);
	      e2e->pool_id = (u8) vm->thread_index;
	      e2e->pool_index = pool_index1;
	      ioam_e2e_id_rewrite_handler ((ioam_e2e_id_option_t *)
					   ((u8 *) e2e +
					    sizeof (ioam_e2e_cache_option_t)),
					   &cm->sr_localsid_ts);
	      /* Patch the protocol chain, insert the h-b-h (type 0) header */
	      hbh1->protocol = ip1->protocol;
	      ip1->protocol = 0;
	      new_l1 =
		clib_net_to_host_u16 (ip1->payload_length) + rewrite_length;
	      ip1->payload_length = clib_host_to_net_u16 (new_l1);
	      processed++;
	    }

	TRACE00:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ip6_reset_ts_hbh_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->next_index = next0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ip6_reset_ts_hbh_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->next_index = next1;
		}

	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  ip6_header_t *ip0;
	  tcp_header_t *tcp0;
	  u32 tcp_offset0;
	  ip6_hop_by_hop_header_t *hbh0;
	  u64 *copy_src0, *copy_dst0;
	  u16 new_l0;
	  u32 pool_index0 = 0;

	  next0 = IP6_IOAM_CACHE_TS_INPUT_NEXT_IP6_LOOKUP;
	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  ip0 = vlib_buffer_get_current (b0);
	  if (IP_PROTOCOL_TCP !=
	      ip6_locate_header (b0, ip0, IP_PROTOCOL_TCP, &tcp_offset0))
	    {
	      goto TRACE0;
	    }
	  tcp0 = (tcp_header_t *) ((u8 *) ip0 + tcp_offset0);
	  if ((tcp0->flags & TCP_FLAG_SYN) == TCP_FLAG_SYN &&
	      (tcp0->flags & TCP_FLAG_ACK) == 0)
	    {
	      if (no_of_responses > 0)
		{
		  /* Create TS select entry */
		  if (0 == ioam_cache_ts_add (ip0,
					      clib_net_to_host_u16
					      (tcp0->src_port),
					      clib_net_to_host_u16
					      (tcp0->dst_port),
					      clib_net_to_host_u32
					      (tcp0->seq_number) + 1,
					      no_of_responses, now,
					      vm->thread_index, &pool_index0))
		    {
		      cache_ts_added++;
		    }
		}
	      copy_dst0 = (u64 *) (((u8 *) ip0) - rewrite_length);
	      copy_src0 = (u64 *) ip0;

	      copy_dst0[0] = copy_src0[0];
	      copy_dst0[1] = copy_src0[1];
	      copy_dst0[2] = copy_src0[2];
	      copy_dst0[3] = copy_src0[3];
	      copy_dst0[4] = copy_src0[4];

	      vlib_buffer_advance (b0, -(word) rewrite_length);
	      ip0 = vlib_buffer_get_current (b0);

	      hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
	      /* $$$ tune, rewrite_length is a multiple of 8 */
	      clib_memcpy (hbh0, rewrite, rewrite_length);
	      e2e =
		(ioam_e2e_cache_option_t *) ((u8 *) hbh0 +
					     cm->rewrite_pool_index_offset);
	      e2e->pool_id = (u8) vm->thread_index;
	      e2e->pool_index = pool_index0;
	      ioam_e2e_id_rewrite_handler ((ioam_e2e_id_option_t *)
					   ((u8 *) e2e +
					    sizeof (ioam_e2e_cache_option_t)),
					   &cm->sr_localsid_ts);
	      /* Patch the protocol chain, insert the h-b-h (type 0) header */
	      hbh0->protocol = ip0->protocol;
	      ip0->protocol = 0;
	      new_l0 =
		clib_net_to_host_u16 (ip0->payload_length) + rewrite_length;
	      ip0->payload_length = clib_host_to_net_u16 (new_l0);
	      processed++;
	    }
	TRACE0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      ip6_reset_ts_hbh_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ip6_reset_ts_hbh_node.index,
			       IP6_RESET_TS_HBH_ERROR_PROCESSED, processed);
  vlib_node_increment_counter (vm, ip6_reset_ts_hbh_node.index,
			       IP6_RESET_TS_HBH_ERROR_SAVED, cache_ts_added);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_reset_ts_hbh_node) =
{
  .function = ip6_reset_ts_hbh_node_fn,
  .name = "ip6-add-syn-hop-by-hop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_reset_ts_hbh_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ip6_reset_ts_hbh_error_strings),
  .error_strings =  ip6_reset_ts_hbh_error_strings,
  /* See ip/lookup.h */
  .n_next_nodes = IP6_IOAM_CACHE_TS_INPUT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [IP6_IOAM_CACHE_TS_INPUT_NEXT_##s] = n,
    foreach_ip6_ioam_cache_ts_input_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_reset_ts_hbh_node, ip6_reset_ts_hbh_node_fn)
/* *INDENT-ON* */

vlib_node_registration_t ioam_cache_ts_timer_tick_node;

typedef struct
{
  u32 thread_index;
} ioam_cache_ts_timer_tick_trace_t;

/* packet trace format function */
static u8 *
format_ioam_cache_ts_timer_tick_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ioam_cache_ts_timer_tick_trace_t *t =
    va_arg (*args, ioam_cache_ts_timer_tick_trace_t *);

  s = format (s, "IOAM_CACHE_TS_TIMER_TICK: thread index %d",
	      t->thread_index);
  return s;
}

#define foreach_ioam_cache_ts_timer_tick_error                 \
  _(TIMER, "Timer events")

typedef enum
{
#define _(sym,str) IOAM_CACHE_TS_TIMER_TICK_ERROR_##sym,
  foreach_ioam_cache_ts_timer_tick_error
#undef _
    IOAM_CACHE_TS_TIMER_TICK_N_ERROR,
} ioam_cache_ts_timer_tick_error_t;

static char *ioam_cache_ts_timer_tick_error_strings[] = {
#define _(sym,string) string,
  foreach_ioam_cache_ts_timer_tick_error
#undef _
};

void
ioam_cache_ts_timer_node_enable (vlib_main_t * vm, u8 enable)
{
  vlib_node_set_state (vm, ioam_cache_ts_timer_tick_node.index,
		       enable ==
		       0 ? VLIB_NODE_STATE_DISABLED :
		       VLIB_NODE_STATE_POLLING);
}

void
expired_cache_ts_timer_callback (u32 * expired_timers)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  int i;
  u32 pool_index;
  u32 thread_index = vlib_get_thread_index ();
  u32 count = 0;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      /* Get pool index and pool id */
      pool_index = expired_timers[i] & 0x0FFFFFFF;

      /* Handle expiration */
      ioam_cache_ts_send (thread_index, pool_index);
      count++;
    }
  vlib_node_increment_counter (cm->vlib_main,
			       ioam_cache_ts_timer_tick_node.index,
			       IOAM_CACHE_TS_TIMER_TICK_ERROR_TIMER, count);
}

static uword
ioam_cache_ts_timer_tick_node_fn (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * f)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  u32 my_thread_index = vlib_get_thread_index ();
  struct timespec ts, tsrem;

  tw_timer_expire_timers_16t_2w_512sl (&cm->timer_wheels[my_thread_index],
				       vlib_time_now (vm));
  ts.tv_sec = 0;
  ts.tv_nsec = 1000 * 1000 * IOAM_CACHE_TS_TICK;
  while (nanosleep (&ts, &tsrem) < 0)
    {
      ts = tsrem;
    }

  return 0;
}
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ioam_cache_ts_timer_tick_node) = {
  .function = ioam_cache_ts_timer_tick_node_fn,
  .name = "ioam-cache-ts-timer-tick",
  .format_trace = format_ioam_cache_ts_timer_tick_trace,
  .type = VLIB_NODE_TYPE_INPUT,

  .n_errors = ARRAY_LEN(ioam_cache_ts_timer_tick_error_strings),
  .error_strings = ioam_cache_ts_timer_tick_error_strings,

  .n_next_nodes = 1,

  .state = VLIB_NODE_STATE_DISABLED,

  /* edit / add dispositions here */
  .next_nodes = {
    [0] = "error-drop",
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
