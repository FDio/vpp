/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

/*
 * ttl_fixup_node.c - Two-phase TTL/Hop-Limit fixup feature node.
 *
 * INPUT nodes (ip4/ip6-unicast, ip4/ip6-multicast on source interface):
 *   Set VNET_BUFFER_F_LOCALLY_ORIGINATED so ip4/ip6-rewrite skips TTL
 *   decrement. This is essential for TTL=1 protocols.
 *
 * OUTPUT nodes (ip4-output, ip6-output on destination interface):
 *   Decrement TTL/hop-limit post-rewrite for packets that originated
 *   from a source interface. This restores normal router-hop behaviour
 *   for traffic which does not require transparent forwarding.
 *
 * The ip4/ip6-output feature arc runs AFTER ip4/ip6-rewrite (which
 * already skipped TTL decrement due to VNET_BUFFER_F_LOCALLY_ORIGINATED).
 * The output node identifies source packets via the input_enabled
 * bitmap and decrements TTL, effectively undoing the TTL preservation.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/icmp4.h>
#include <vnet/ip/icmp6.h>
#include <vnet/feature/feature.h>
#include <ttl_fixup_plugin/ttl_fixup.h>
#include <ttl_fixup_plugin/ttl_fixup.api_enum.h>

/* ================================================================
 *  Trace structures
 * ================================================================ */

typedef struct
{
  u32 sw_if_index;
} ttl_fixup_trace_t;

static u8 *
format_ttl_fixup_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ttl_fixup_trace_t *t = va_arg (*args, ttl_fixup_trace_t *);

  s = format (s, "ttl-fixup: sw_if_index %u, locally-originated flag set", t->sw_if_index);
  return s;
}

typedef struct
{
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
  u8 decremented;
} ttl_fixup_output_trace_t;

static u8 *
format_ttl_fixup_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ttl_fixup_output_trace_t *t = va_arg (*args, ttl_fixup_output_trace_t *);

  s = format (s, "ttl-fixup-out: rx_sw_if_index %u tx_sw_if_index %u %s", t->rx_sw_if_index,
	      t->tx_sw_if_index, t->decremented ? "TTL decremented" : "no-op");
  return s;
}

/* ================================================================
 *  Next-node enums
 * ================================================================ */

typedef enum
{
  TTL_FIXUP_NEXT_DROP,
  TTL_FIXUP_N_NEXT,
} ttl_fixup_next_t;

typedef enum
{
  TTL_FIXUP_OUT_NEXT_DROP,
  TTL_FIXUP_OUT_NEXT_ICMP_ERROR,
  TTL_FIXUP_OUT_N_NEXT,
} ttl_fixup_out_next_t;

/* ================================================================
 *  INPUT inline — set LOCALLY_ORIGINATED flag on all packets
 * ================================================================ */

always_inline uword
ttl_fixup_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left, *from;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  b = bufs;
  next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left >= 4)
    {
      if (PREDICT_TRUE (n_left >= 8))
	{
	  vlib_prefetch_buffer_header (b[4], STORE);
	  vlib_prefetch_buffer_header (b[5], STORE);
	  vlib_prefetch_buffer_header (b[6], STORE);
	  vlib_prefetch_buffer_header (b[7], STORE);
	}

      b[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      b[1]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      b[2]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      b[3]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

      vnet_feature_next_u16 (&next[0], b[0]);
      vnet_feature_next_u16 (&next[1], b[1]);
      vnet_feature_next_u16 (&next[2], b[2]);
      vnet_feature_next_u16 (&next[3], b[3]);

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  for (int i = 0; i < 4; i++)
	    {
	      if (b[i]->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ttl_fixup_trace_t *t = vlib_add_trace (vm, node, b[i], sizeof (*t));
		  t->sw_if_index = vnet_buffer (b[i])->sw_if_index[VLIB_RX];
		}
	    }
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      b[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      vnet_feature_next_u16 (&next[0], b[0]);

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  ttl_fixup_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	}

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index, TTL_FIXUP_ERROR_TTL_PRESERVED,
			       frame->n_vectors);

  return frame->n_vectors;
}

/* ================================================================
 *  OUTPUT inline — decrement TTL for packets from source interfaces.
 *  Source packets are identified via the input_enabled bitmap.
 *  Runs on ip4-output / ip6-output arc AFTER ip4/ip6-rewrite.
 *  At this point the L2 rewrite header has been prepended;
 *  the IP header starts at current_data + save_rewrite_length.
 * ================================================================ */

always_inline uword
ttl_fixup_output_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
			 int is_ip6)
{
  ttl_fixup_main_t *tfm = &ttl_fixup_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left, *from;
  u32 n_decremented = 0, n_exceeded = 0;
  u32 input_len = vec_len (tfm->input_enabled);
  u32 output_len = vec_len (tfm->output_enabled);

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  b = bufs;
  next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      u32 rx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      u32 tx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
      u8 did_decrement = 0;

      vnet_feature_next_u16 (&next[0], b[0]);

      /* Decrement TTL only for packets coming from an interface with input TTL-fixup enabled
       * (source) and leaving via an interface with output TTL-fixup enabled (destination) */
      if (rx_sw_if_index < input_len && tfm->input_enabled[rx_sw_if_index] &&
	  tx_sw_if_index < output_len && tfm->output_enabled[tx_sw_if_index])
	{
	  u16 rw_len = vnet_buffer (b[0])->ip.save_rewrite_length;

	  /* This packet has completed TTL-fixup processing. */
	  b[0]->flags &= ~VNET_BUFFER_F_LOCALLY_ORIGINATED;

	  if (is_ip6)
	    {
	      ip6_header_t *ip6 = (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b[0]) + rw_len);

	      if (PREDICT_TRUE (ip6->hop_limit > 1))
		{
		  ip6->hop_limit -= 1;
		  did_decrement = 1;
		  n_decremented++;
		}
	      else
		{
		  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = (u32) ~0;
		  icmp6_error_set_vnet_buffer (b[0], ICMP6_time_exceeded,
					       ICMP6_time_exceeded_ttl_exceeded_in_transit, 0);
		  next[0] = TTL_FIXUP_OUT_NEXT_ICMP_ERROR;
		  n_exceeded++;
		  goto trace;
		}
	    }
	  else
	    {
	      ip4_header_t *ip4 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b[0]) + rw_len);

	      if (PREDICT_TRUE (ip4->ttl > 1))
		{
		  u32 checksum;

		  ip4->ttl -= 1;
		  checksum = ip4->checksum + clib_host_to_net_u16 (0x0100);
		  checksum += checksum >= 0xffff;
		  ip4->checksum = checksum;
		  did_decrement = 1;
		  n_decremented++;
		}
	      else
		{
		  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = (u32) ~0;
		  icmp4_error_set_vnet_buffer (b[0], ICMP4_time_exceeded,
					       ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
		  next[0] = TTL_FIXUP_OUT_NEXT_ICMP_ERROR;
		  n_exceeded++;
		  goto trace;
		}
	    }
	}

    trace:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  ttl_fixup_output_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->rx_sw_if_index = rx_sw_if_index;
	  t->tx_sw_if_index = tx_sw_if_index;
	  t->decremented = did_decrement;
	}

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  if (n_decremented)
    vlib_node_increment_counter (vm, node->node_index, TTL_FIXUP_ERROR_TTL_DECREMENTED,
				 n_decremented);
  if (n_exceeded)
    vlib_node_increment_counter (vm, node->node_index, TTL_FIXUP_ERROR_TTL_EXCEEDED, n_exceeded);

  return frame->n_vectors;
}

/* ================================================================
 *  INPUT node registrations
 * ================================================================ */

/* --- IPv4 unicast --- */

VLIB_NODE_FN (ttl_fixup_ip4_in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ttl_fixup_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (ttl_fixup_ip4_in_node) = {
  .name = "ttl-fixup-ip4-in",
  .vector_size = sizeof (u32),
  .format_trace = format_ttl_fixup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = TTL_FIXUP_N_ERROR,
  .error_counters = ttl_fixup_error_counters,
  .n_next_nodes = TTL_FIXUP_N_NEXT,
  .next_nodes = {
    [TTL_FIXUP_NEXT_DROP] = "error-drop",
  },
};

/* --- IPv6 unicast --- */

VLIB_NODE_FN (ttl_fixup_ip6_in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ttl_fixup_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (ttl_fixup_ip6_in_node) = {
  .name = "ttl-fixup-ip6-in",
  .vector_size = sizeof (u32),
  .format_trace = format_ttl_fixup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = TTL_FIXUP_N_ERROR,
  .error_counters = ttl_fixup_error_counters,
  .n_next_nodes = TTL_FIXUP_N_NEXT,
  .next_nodes = {
    [TTL_FIXUP_NEXT_DROP] = "error-drop",
  },
};

/* --- IPv4 multicast --- */

VLIB_NODE_FN (ttl_fixup_ip4_mcast_in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ttl_fixup_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (ttl_fixup_ip4_mcast_in_node) = {
  .name = "ttl-fixup-ip4-mcast-in",
  .vector_size = sizeof (u32),
  .format_trace = format_ttl_fixup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = TTL_FIXUP_N_ERROR,
  .error_counters = ttl_fixup_error_counters,
  .n_next_nodes = TTL_FIXUP_N_NEXT,
  .next_nodes = {
    [TTL_FIXUP_NEXT_DROP] = "error-drop",
  },
};

/* --- IPv6 multicast --- */

VLIB_NODE_FN (ttl_fixup_ip6_mcast_in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ttl_fixup_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (ttl_fixup_ip6_mcast_in_node) = {
  .name = "ttl-fixup-ip6-mcast-in",
  .vector_size = sizeof (u32),
  .format_trace = format_ttl_fixup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = TTL_FIXUP_N_ERROR,
  .error_counters = ttl_fixup_error_counters,
  .n_next_nodes = TTL_FIXUP_N_NEXT,
  .next_nodes = {
    [TTL_FIXUP_NEXT_DROP] = "error-drop",
  },
};

/* ================================================================
 *  OUTPUT node registrations
 * ================================================================ */

/* --- IPv4 output --- */

VLIB_NODE_FN (ttl_fixup_ip4_out_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ttl_fixup_output_inline (vm, node, frame, 0 /* is_ip6 */);
}

VLIB_REGISTER_NODE (ttl_fixup_ip4_out_node) = {
  .name = "ttl-fixup-ip4-out",
  .vector_size = sizeof (u32),
  .format_trace = format_ttl_fixup_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = TTL_FIXUP_N_ERROR,
  .error_counters = ttl_fixup_error_counters,
  .n_next_nodes = TTL_FIXUP_OUT_N_NEXT,
  .next_nodes = {
    [TTL_FIXUP_OUT_NEXT_DROP] = "error-drop",
    [TTL_FIXUP_OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },
};

/* --- IPv6 output --- */

VLIB_NODE_FN (ttl_fixup_ip6_out_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ttl_fixup_output_inline (vm, node, frame, 1 /* is_ip6 */);
}

VLIB_REGISTER_NODE (ttl_fixup_ip6_out_node) = {
  .name = "ttl-fixup-ip6-out",
  .vector_size = sizeof (u32),
  .format_trace = format_ttl_fixup_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = TTL_FIXUP_N_ERROR,
  .error_counters = ttl_fixup_error_counters,
  .n_next_nodes = TTL_FIXUP_OUT_N_NEXT,
  .next_nodes = {
    [TTL_FIXUP_OUT_NEXT_DROP] = "error-drop",
    [TTL_FIXUP_OUT_NEXT_ICMP_ERROR] = "ip6-icmp-error",
  },
};

/* ================================================================
 *  Feature arc registrations — INPUT
 * ================================================================ */

VNET_FEATURE_INIT (ttl_fixup_ip4_in_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ttl-fixup-ip4-in",
  .runs_before = VNET_FEATURES ("ip4-flow-classify"),
};

VNET_FEATURE_INIT (ttl_fixup_ip6_in_feat, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ttl-fixup-ip6-in",
  .runs_before = VNET_FEATURES ("ip6-flow-classify"),
};

VNET_FEATURE_INIT (ttl_fixup_ip4_mcast_in_feat, static) = {
  .arc_name = "ip4-multicast",
  .node_name = "ttl-fixup-ip4-mcast-in",
  .runs_before = VNET_FEATURES ("ip4-mfib-forward-lookup"),
};

VNET_FEATURE_INIT (ttl_fixup_ip6_mcast_in_feat, static) = {
  .arc_name = "ip6-multicast",
  .node_name = "ttl-fixup-ip6-mcast-in",
  .runs_before = VNET_FEATURES ("ip6-mfib-forward-lookup"),
};

/* ================================================================
 *  Feature arc registrations — OUTPUT
 * ================================================================ */

VNET_FEATURE_INIT (ttl_fixup_ip4_out_feat, static) = {
  .arc_name = "ip4-output",
  .node_name = "ttl-fixup-ip4-out",
  .runs_before = VNET_FEATURES ("ip4-source-and-port-range-check-tx"),
};

VNET_FEATURE_INIT (ttl_fixup_ip6_out_feat, static) = {
  .arc_name = "ip6-output",
  .node_name = "ttl-fixup-ip6-out",
  .runs_before = VNET_FEATURES ("ip6-outacl"),
};
