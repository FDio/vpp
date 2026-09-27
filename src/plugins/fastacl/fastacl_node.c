/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vlib/buffer_node.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/udp/udp_packet.h>
#include <fastacl/fastacl.h>
#include <fastacl/fastacl_format.h>

#ifndef CLIB_MARCH_VARIANT
static u8 *
format_fastacl_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  fastacl_trace_t *t = va_arg (*args, fastacl_trace_t *);

  if (t->rule_index == ~0u)
    return format (s, "fastacl: no match, next %u", t->next_index);
  return format (s, "fastacl: rule %u (order %u) action %s next %u pkts %llu", t->rule_index,
		 t->rule_order, fastacl_action_type_name (t->action_type), t->next_index,
		 t->pkt_count);
}
#endif

#ifndef CLIB_MARCH_VARIANT
static char *fastacl_error_strings[] = {
#define _(sym, str) str,
  foreach_fastacl_error
#undef _
};
#endif

static_always_inline u8
fastacl_compute_frag_flags (int mf, u16 frag_off)
{
  u8 flags = 0;
  if (mf || frag_off)
    flags |= FASTACL_FRAG_ISF;
  if (mf && !frag_off)
    flags |= FASTACL_FRAG_FF;
  if (!mf && frag_off)
    flags |= FASTACL_FRAG_LF;
  return flags;
}

static_always_inline void
fastacl_sample_psample (fastacl_main_t *fsm, vlib_buffer_t *b0, u32 pkt_bytes, u32 rule_index,
			const fastacl_rule_t *rule, fastacl_per_worker_t *per_worker,
			u32 *n_sampled, u32 *n_sample_fail)
{
  u32 ratio = rule->action.sample_ratio;
  if (PREDICT_TRUE (ratio == 0) || !fsm->psample_enabled)
    return;
  if (PREDICT_FALSE (rule_index >= vec_len (per_worker->rule_sample_credit)))
    return;

  if (++per_worker->rule_sample_credit[rule_index] < ratio)
    return;
  per_worker->rule_sample_credit[rule_index] = 0;

  u8 *data = vlib_buffer_get_current (b0);
  u32 len = b0->current_length;
  u32 back = 0;

  if (b0->current_data >= (i16) sizeof (ethernet_header_t))
    {
      back = sizeof (ethernet_header_t);
      data -= back;
      len += back;
    }

  u32 iif = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  u32 origsize = pkt_bytes + back;

  if (PREDICT_FALSE (fastacl_psample_send (&per_worker->psample, rule->action.sample_group, ratio,
					   iif, origsize, data, len) < 0))
    {
      per_worker->rule_sample_missed[rule_index]++;
      (*n_sample_fail)++;
      return;
    }
  per_worker->rule_sample_count[rule_index]++;
  (*n_sampled)++;
}

static_always_inline int
fastacl_apply_rule (fastacl_main_t *fsm, u32 rule_index, u8 action_type, int is_traced,
		    vlib_main_t *vm, u32 pkt_bytes, ip4_header_t *pkt_ip, int is_ip6,
		    u32 *n_matched, u32 *n_dropped, u32 *trace_rule_index, u32 *trace_rule_order,
		    u8 *trace_action_type, fastacl_per_worker_t *per_worker)
{

  if (PREDICT_TRUE (fsm->rule_stats_enabled) && PREDICT_TRUE (rule_index < fsm->rule_counter_len))
    vlib_increment_combined_counter (&fsm->rule_counters, vm->thread_index, rule_index, 1,
				     pkt_bytes);
  (*n_matched)++;
  *trace_rule_index = rule_index;
  *trace_action_type = action_type;

  if (PREDICT_TRUE (action_type == FASTACL_ACTION_TYPE_DROP && !is_traced))
    {
      (*n_dropped)++;
      return 1;
    }

  fastacl_rule_t *rule = pool_elt_at_index (fsm->rules, rule_index);
  *trace_rule_order = rule->order;

  switch (action_type)
    {
    case FASTACL_ACTION_TYPE_DROP:
      (*n_dropped)++;
      return 1;

    default:
      return 0;
    }
}

static_always_inline void
fastacl_record_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b0,
		      fastacl_main_t *fsm, u32 rule_index, u32 rule_order, u8 action_type,
		      u32 next_index)
{
  fastacl_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
  t->rule_index = rule_index;
  t->rule_order = rule_order;
  t->action_type = action_type;
  t->next_index = next_index;
  t->pkt_count = (rule_index != ~0u) ? pool_elt_at_index (fsm->rules, rule_index)->packet_count : 0;
}

static_always_inline void
fastacl_parse_ip4 (fastacl_parsed_t *p, ip4_header_t *ip4, u16 avail)
{
  u16 frag_off = ip4_get_fragment_offset (ip4);
  int mf = !!ip4_get_fragment_more (ip4);
  int df =
    !!(ip4->flags_and_fragment_offset & clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT));
  u16 claimed = clib_net_to_host_u16 (ip4->length);
  u16 ip_bytes = ip4_header_bytes (ip4);

  p->pkt_proto = ip4->protocol;
  p->pkt_len = clib_min (claimed, avail);
  p->pkt_dscp = ip4_header_get_dscp (ip4);
  p->pkt_frag_flags = fastacl_compute_frag_flags (mf, frag_off);
  if (df)
    p->pkt_frag_flags |= FASTACL_FRAG_DF;

  p->l4 = (frag_off == 0 && ip_bytes >= sizeof (ip4_header_t) && ip_bytes < p->pkt_len) ?
	    (u8 *) ip4 + ip_bytes :
	    NULL;
}

static_always_inline void
fastacl_parse_ip6 (fastacl_parsed_t *p, vlib_buffer_t *b, ip6_header_t *ip6, u16 avail)
{
  ip6_ext_hdr_chain_t chain;
  u16 claimed = clib_net_to_host_u16 (ip6->payload_length) + (u16) sizeof (ip6_header_t);

  p->is_ip6 = 1;
  p->pkt_dscp = ip6_dscp_network_order (ip6);
  p->pkt_len = clib_min (claimed, avail);
  p->pkt_proto = ip6->protocol;

  int last = ip6_ext_header_walk (b, ip6, IP_PROTOCOL_IPV6_FRAGMENTATION, &chain);
  if (last < 0)
    return;

  if (chain.eh[last].protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
    {
      ip6_frag_hdr_t *fh = (ip6_frag_hdr_t *) ((u8 *) ip6 + chain.eh[last].offset);
      u16 frag_off = ip6_frag_hdr_offset (fh);

      p->pkt_frag_flags = fastacl_compute_frag_flags (ip6_frag_hdr_more (fh), frag_off);

      if (frag_off != 0)
	{
	  p->pkt_proto = IP_PROTOCOL_IPV6_FRAGMENTATION;
	  return;
	}
    }

  u32 l4_offset = chain.eh[chain.length - 1].offset;

  p->pkt_proto = chain.eh[chain.length - 1].protocol;
  if (l4_offset < p->pkt_len)
    p->l4 = (u8 *) ip6 + l4_offset;
}

static_always_inline void
fastacl_parse_packet (vlib_buffer_t *b, fastacl_parsed_t *p, u16 l2_ofs)
{
  ip4_header_t *ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b) + l2_ofs);
  u8 version = (ip0->ip_version_and_header_length >> 4);
  u16 avail = (b->current_length > l2_ofs) ? (u16) (b->current_length - l2_ofs) : 0;

  clib_memset (p, 0, sizeof (*p));
  p->ip0 = ip0;

  if (PREDICT_FALSE (avail < sizeof (ip4_header_t)))
    {
      p->unparseable = 1;
      return;
    }

  if (PREDICT_TRUE (version == 4))
    fastacl_parse_ip4 (p, ip0, avail);
  else if (version == 6)
    fastacl_parse_ip6 (p, b, (ip6_header_t *) ip0, avail);
  else
    {
      p->unparseable = 1;
      return;
    }

  p->l4_bytes = p->l4 ? (u16) (p->pkt_len - (u16) ((u8 *) p->l4 - (u8 *) p->ip0)) : 0;

  if ((p->pkt_proto == IP_PROTOCOL_TCP || p->pkt_proto == IP_PROTOCOL_UDP) &&
      p->l4_bytes >= FASTACL_L4_PORTS_BYTES)
    {
      udp_header_t *udp = (udp_header_t *) p->l4;
      p->l4_src_port = clib_net_to_host_u16 (udp->src_port);
      p->l4_dst_port = clib_net_to_host_u16 (udp->dst_port);
    }
}

static_always_inline u32
fastacl_classify_one (fastacl_main_t *fsm, const fastacl_parsed_t *p, u8 *action_out)
{
  if (PREDICT_FALSE (p->is_ip6))
    {
      ip6_header_t *ip6 = (ip6_header_t *) p->ip0;
      return fastacl_tss_lookup_ip6 (fsm, ip6, p->pkt_proto, p->l4_src_port, p->l4_dst_port, p->l4,
				     p->l4_bytes, p->pkt_len, p->pkt_dscp, p->pkt_frag_flags,
				     action_out);
    }

  return fastacl_tss_lookup_ip4 (fsm, p->ip0, p->pkt_proto, p->l4_src_port, p->l4_dst_port, p->l4,
				 p->l4_bytes, p->pkt_len, p->pkt_dscp, p->pkt_frag_flags,
				 action_out);
}

static_always_inline uword
fastacl_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, int is_l2)
{
  fastacl_main_t *fsm = &fastacl_main;
  fastacl_per_worker_t *per_worker = &fsm->per_worker[vm->thread_index];
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 n_matched = 0, n_dropped = 0, n_passed = 0, n_unparseable = 0;
  u32 n_sampled = 0, n_sample_fail = 0;
  u64 n_bytes_processed = 0, n_bytes_dropped = 0;

  vlib_get_buffers (vm, from, bufs, n_left);

  fastacl_parsed_t p_cur, p_next;
  if (n_left > 0)
    fastacl_parse_packet (b[0], &p_cur, is_l2 ? vnet_buffer (b[0])->l2.l2_len : 0);

  while (n_left > 0)
    {

      if (PREDICT_TRUE (n_left >= 5))
	{
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  CLIB_PREFETCH (b[4]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	}

      u16 next0;
      vnet_feature_next_u16 (&next0, b[0]);

      if (PREDICT_TRUE (n_left >= 2))
	{
	  fastacl_parse_packet (b[1], &p_next, is_l2 ? vnet_buffer (b[1])->l2.l2_len : 0);
	  if (PREDICT_TRUE (!p_next.unparseable))
	    {
	      if (PREDICT_FALSE (p_next.is_ip6))
		fastacl_tss_prefetch_ip6 (fsm, (ip6_header_t *) p_next.ip0, p_next.pkt_proto);
	      else
		fastacl_tss_prefetch_ip4 (fsm, p_next.ip0, p_next.pkt_proto, p_next.pkt_len);
	    }
	}

      u32 trace_ri = ~0u, trace_order = 0;
      u8 trace_action = 0;

      u32 b0_bytes = vlib_buffer_length_in_chain (vm, b[0]);
      int is_traced = (b[0]->flags & VLIB_BUFFER_IS_TRACED) != 0;

      if (PREDICT_FALSE (p_cur.unparseable))
	n_unparseable++;
      else
	{
	  u8 action_type = 0;
	  u32 ri = fastacl_classify_one (fsm, &p_cur, &action_type);
	  if (ri != ~0u)
	    {
	      if (PREDICT_FALSE (fsm->n_sample_rules != 0))
		{
		  fastacl_rule_t *sr = pool_elt_at_index (fsm->rules, ri);
		  fastacl_sample_psample (fsm, b[0], b0_bytes, ri, sr, per_worker, &n_sampled,
					  &n_sample_fail);
		}
	      if (fastacl_apply_rule (fsm, ri, action_type, is_traced, vm, b0_bytes, p_cur.ip0,
				      p_cur.is_ip6, &n_matched, &n_dropped, &trace_ri, &trace_order,
				      &trace_action, per_worker))
		{
		  next0 = FASTACL_NEXT_DROP;
		  b[0]->error = node->errors[FASTACL_ERROR_DROPPED];
		}
	    }
	  else
	    n_passed++;
	}

      if (PREDICT_FALSE (is_traced))
	fastacl_record_trace (vm, node, b[0], fsm, trace_ri, trace_order, trace_action, next0);

      n_bytes_processed += b0_bytes;
      if (next0 == FASTACL_NEXT_DROP)
	n_bytes_dropped += b0_bytes;

      next[0] = next0;

      p_cur = p_next;
      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  per_worker->total_processed += frame->n_vectors;
  per_worker->total_dropped += n_dropped;
  per_worker->total_bytes_processed += n_bytes_processed;
  per_worker->total_bytes_dropped += n_bytes_dropped;

  vlib_node_increment_counter (vm, node->node_index, FASTACL_ERROR_MATCHED, n_matched);
  vlib_node_increment_counter (vm, node->node_index, FASTACL_ERROR_PASSED, n_passed);
  vlib_node_increment_counter (vm, node->node_index, FASTACL_ERROR_UNPARSEABLE, n_unparseable);
  vlib_node_increment_counter (vm, node->node_index, FASTACL_ERROR_SAMPLED, n_sampled);
  vlib_node_increment_counter (vm, node->node_index, FASTACL_ERROR_SAMPLE_FAIL, n_sample_fail);

  return frame->n_vectors;
}

VLIB_NODE_FN (fastacl_filter_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return fastacl_node_inline (vm, node, frame, 0);
}

VLIB_NODE_FN (fastacl_filter_l2_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return fastacl_node_inline (vm, node, frame, 1);
}

#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (fastacl_filter_node) = {
  .name = "fastacl-filter",
  .vector_size = sizeof (u32),
  .format_trace = format_fastacl_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = FASTACL_N_ERROR,
  .error_strings = fastacl_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [FASTACL_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (fastacl_filter_l2_node) = {
  .name = "fastacl-filter-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_fastacl_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = FASTACL_N_ERROR,
  .error_strings = fastacl_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [FASTACL_NEXT_DROP] = "error-drop",
  },
};
#endif
