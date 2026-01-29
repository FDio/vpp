/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/service.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <sfdp_services/session_stats/session_stats.h>

#define foreach_sfdp_session_stats_error _ (COUNTED, "packets counted")

typedef enum
{
#define _(sym, str) SFDP_SESSION_STATS_ERROR_##sym,
  foreach_sfdp_session_stats_error
#undef _
    SFDP_SESSION_STATS_N_ERROR,
} sfdp_session_stats_error_t;

static char *sfdp_session_stats_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_session_stats_error
#undef _
};

typedef struct
{
  u32 flow_id;
  u64 packets_fwd;
  u64 packets_rev;
  u64 bytes_fwd;
  u64 bytes_rev;
} sfdp_session_stats_trace_t;

static u8 *
format_sfdp_session_stats_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  sfdp_session_stats_trace_t *t = va_arg (*args, sfdp_session_stats_trace_t *);

  s = format (s,
	      "sfdp-session-stats: flow-id %u (session %u, %s)\n"
	      "  packets: fwd=%llu rev=%llu, bytes: fwd=%llu rev=%llu",
	      t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward", t->packets_fwd,
	      t->packets_rev, t->bytes_fwd, t->bytes_rev);
  return s;
}

/* TODO - add further inline comments on how each session statistic is computed */
static_always_inline void
sfdp_session_stats_process_tcp (vlib_main_t *vm, vlib_buffer_t *b,
				sfdp_session_stats_entry_t *stats, sfdp_session_t *session,
				u8 direction, u32 l3_len)
{
  u8 *data = vlib_buffer_get_current (b);
  tcp_header_t *tcph;
  u32 tcp_hlen, payload_len;
  u8 ack_dir = 1 - direction;

  /* Get TCP header based on IP type */
  if (session->type == SFDP_SESSION_TYPE_IP4)
    tcph = (tcp_header_t *) (data + sizeof (ip4_header_t));
  else
    tcph = (tcp_header_t *) (data + sizeof (ip6_header_t));

  tcp_hlen = tcp_header_bytes (tcph);
  u8 flags = tcph->flags;
  u32 seq = clib_net_to_host_u32 (tcph->seq_number);
  u32 ack = clib_net_to_host_u32 (tcph->ack_number);
  u16 win = clib_net_to_host_u16 (tcph->window);

  /* Compute payload length */
  if (session->type == SFDP_SESSION_TYPE_IP4)
    {
      u32 l4_off = sizeof (ip4_header_t);
      payload_len = (l3_len > (l4_off + tcp_hlen)) ? (l3_len - l4_off - tcp_hlen) : 0;
    }
  else
    {
      u32 l4_off = sizeof (ip6_header_t);
      payload_len = (l3_len > (l4_off + tcp_hlen)) ? (l3_len - l4_off - tcp_hlen) : 0;
    }

  /* Track SYN/FIN/RST flags */
  if (flags & TCP_FLAG_SYN)
    {
      stats->tcp.syn_packets++;

      /* Parse MSS from SYN options if not already set */
      if (stats->tcp.mss == 0)
	{
	  const u8 *opt = (const u8 *) tcph + sizeof (tcp_header_t);
	  const u8 *end = (const u8 *) tcph + tcp_hlen;
	  while (opt + 1 < end)
	    {
	      u8 kind = opt[0];
	      if (kind == 0) /* EOL */
		break;
	      if (kind == 1) /* NOP */
		{
		  opt += 1;
		  continue;
		}
	      if (opt + 2 > end)
		break;
	      u8 len = opt[1];
	      if (len < 2 || opt + len > end)
		break;
	      if (kind == 2 && len == 4) /* MSS option */
		{
		  stats->tcp.mss = (opt[2] << 8) | opt[3];
		  break;
		}
	      opt += len;
	    }
	}

      /* Track SYN-ACK for handshake completion */
      if ((flags & TCP_FLAG_ACK) && !stats->tcp.handshake_complete)
	{
	  /* SYN-ACK seen, waiting for final ACK */
	}
    }

  if (flags & TCP_FLAG_FIN)
    stats->tcp.fin_packets++;

  if (flags & TCP_FLAG_RST)
    stats->tcp.rst_packets++;

  /* Track TCP ECN flags (ECE and CWR) for congestion notification */
  if (flags & TCP_FLAG_ECE)
    stats->tcp.ece_packets++;

  if (flags & TCP_FLAG_CWR)
    stats->tcp.cwr_packets++;

  /* Track ACK for handshake completion and RTT */
  if ((flags & TCP_FLAG_ACK) && !(flags & TCP_FLAG_SYN) && !stats->tcp.handshake_complete)
    {
      /* First pure ACK after a SYN-ACK means handshake is complete */
      stats->tcp.handshake_complete = 1;
    }

  /* RTT measurement: when we get an ACK, check if it acknowledges data
   * we sent and use the time delta for RTT */
  if ((flags & TCP_FLAG_ACK) && stats->rtt_probe_tick_us[ack_dir] != 0)
    {
      if (seq_geq (ack, stats->last_data_seq[ack_dir]))
	{
	  u32 now_us = sfdp_session_stats_now_ticks_us (vm);
	  f64 sample =
	    sfdp_session_stats_delta_s_from_ticks (now_us, stats->rtt_probe_tick_us[ack_dir]);
	  sfdp_session_stats_update_rtt (&stats->rtt[ack_dir], sample);
	  stats->rtt_probe_tick_us[ack_dir] = 0;
	}
    }

  /* Zero-window tracking per direction */
  if (win == 0 && !stats->in_zero_window[direction])
    {
      stats->tcp.zero_window_events[direction]++;
      stats->in_zero_window[direction] = 1;
    }
  else if (win > 0 && stats->in_zero_window[direction])
    {
      stats->in_zero_window[direction] = 0;
    }

  /* Sequence tracking for retransmission detection */
  if (payload_len > 0)
    {
      u32 end_seq = seq + payload_len;

      if (stats->last_seq_valid[direction])
	{
	  /* Check for retransmission or overlap */
	  if (seq_leq (end_seq, stats->end_seq_max[direction]))
	    {
	      /* Complete retransmission */
	      stats->tcp.retransmissions[direction]++;
	    }
	  else if (seq_lt (seq, stats->end_seq_max[direction]) &&
		   seq_gt (end_seq, stats->end_seq_max[direction]))
	    {
	      /* Partial overlap */
	      stats->tcp.partial_overlaps[direction]++;
	    }
	  /* TODO: Implement out-of-order detection logic
	   * Out-of-order: seq > end_seq_max (gap in sequence space)
	   * Increment stats->tcp.out_of_order[direction]++ when detected */
	}

      /* Update tracking state */
      if (!stats->last_seq_valid[direction] || seq_gt (end_seq, stats->end_seq_max[direction]))
	{
	  stats->end_seq_max[direction] = end_seq;
	}
      stats->tcp.last_seq[direction] = seq + payload_len;
      stats->last_seq_valid[direction] = 1;

      /* Setup RTT probe for this data */
      stats->last_data_seq[direction] = end_seq;
      stats->rtt_probe_tick_us[direction] = sfdp_session_stats_now_ticks_us (vm);
    }

  /* Track last ACK for dupack detection per direction */
  if (flags & TCP_FLAG_ACK)
    {
      if (stats->tcp.last_ack[ack_dir] == ack && stats->end_seq_max[ack_dir] > ack)
	{
	  /* Duplicate ACK detected - count in the direction being ACKed */
	  stats->tcp.dupack_like[ack_dir]++;
	}
      stats->tcp.last_ack[ack_dir] = ack;
    }
}

/*
 * Process single packet and update all statistics
 */
static_always_inline void
sfdp_session_stats_process_packet (vlib_main_t *vm, vlib_buffer_t *b,
				   sfdp_session_stats_main_t *ssm, f64 now)
{
  u32 session_idx = sfdp_session_from_flow_index (b->flow_id);
  u8 direction = sfdp_direction_from_flow_index (b->flow_id);
  sfdp_session_stats_entry_t *stats;
  sfdp_session_t *session;
  u32 pkt_len = vlib_buffer_length_in_chain (vm, b);
  u8 *data = vlib_buffer_get_current (b);
  u8 ttl_value = 0;
  u32 l3_len = 0;

  if (PREDICT_FALSE (session_idx >= vec_len (ssm->stats)))
    return;

  stats = vec_elt_at_index (ssm->stats, session_idx);
  session = sfdp_session_at_index (session_idx);

  /* Validate session version - prevents updating stale stats if session
   * was deleted and index reused while packet was in the pipeline */
  if (PREDICT_FALSE (stats->version != session->session_version))
    return;

  /* Update basic counters */
  stats->packets[direction]++;
  stats->bytes[direction] += pkt_len;

  /* Update timestamps */
  if (PREDICT_FALSE (stats->first_seen == 0))
    stats->first_seen = now;
  stats->last_seen = now;

  /* Extract TTL and ECN from IP header */
  ip_ecn_t ecn_bits = IP_ECN_NON_ECN;
  if (session->type == SFDP_SESSION_TYPE_IP4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) data;
      ttl_value = ip4->ttl;
      l3_len = clib_net_to_host_u16 (ip4->length);
      ecn_bits = ip4_header_get_ecn (ip4);
    }
  else if (session->type == SFDP_SESSION_TYPE_IP6)
    {
      ip6_header_t *ip6 = (ip6_header_t *) data;
      ttl_value = ip6->hop_limit;
      l3_len = clib_net_to_host_u16 (ip6->payload_length) + sizeof (ip6_header_t);
      ecn_bits = ip6_ecn_network_order (ip6);
    }

  /* Update TTL statistics */
  sfdp_session_stats_update_ttl (&stats->ttl[direction], ttl_value);

  /* TCP-specific processing */
  if (session->proto == IP_PROTOCOL_TCP)
    {
      /* Track ECN bits from IP header for TCP sessions */
      if (ecn_bits == IP_ECN_ECT_0 || ecn_bits == IP_ECN_ECT_1)
	stats->tcp.ecn_ect_packets++;
      else if (ecn_bits == IP_ECN_CE)
	stats->tcp.ecn_ce_packets++;

      sfdp_session_stats_process_tcp (vm, b, stats, session, direction, l3_len);
    }
}

VLIB_NODE_FN (sfdp_session_stats_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  f64 now = vlib_time_now (vm);

  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_counted = 0;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left >= 4)
    {
      /* Prefetch next iteration */
      if (n_left >= 8)
	{
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);
	  vlib_prefetch_buffer_header (b[6], LOAD);
	  vlib_prefetch_buffer_header (b[7], LOAD);
	}

      /* Process 4 packets */
      for (int i = 0; i < 4; i++)
	{
	  u32 session_idx = sfdp_session_from_flow_index (b[i]->flow_id);

	  if (PREDICT_TRUE (session_idx < vec_len (ssm->stats)))
	    {
	      sfdp_session_stats_process_packet (vm, b[i], ssm, now);
	      n_counted++;
	    }

	  /* Next service in chain */
	  sfdp_next (b[i], &to_next[i]);
	}

      b += 4;
      to_next += 4;
      n_left -= 4;
    }

  while (n_left)
    {
      u32 session_idx = sfdp_session_from_flow_index (b[0]->flow_id);

      if (PREDICT_TRUE (session_idx < vec_len (ssm->stats)))
	{
	  sfdp_session_stats_process_packet (vm, b[0], ssm, now);
	  n_counted++;
	}

      /* Next service in chain */
      sfdp_next (b[0], to_next);

      b++;
      to_next++;
      n_left--;
    }

  vlib_node_increment_counter (vm, node->node_index, SFDP_SESSION_STATS_ERROR_COUNTED, n_counted);

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      n_left = frame->n_vectors;
      b = bufs;
      for (int i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sfdp_session_stats_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	      u32 session_idx = sfdp_session_from_flow_index (b[0]->flow_id);
	      sfdp_session_stats_entry_t *stats;

	      t->flow_id = b[0]->flow_id;
	      if (session_idx < vec_len (ssm->stats))
		{
		  stats = vec_elt_at_index (ssm->stats, session_idx);
		  t->packets_fwd = stats->packets[SFDP_FLOW_FORWARD];
		  t->packets_rev = stats->packets[SFDP_FLOW_REVERSE];
		  t->bytes_fwd = stats->bytes[SFDP_FLOW_FORWARD];
		  t->bytes_rev = stats->bytes[SFDP_FLOW_REVERSE];
		}
	      b++;
	    }
	  else
	    break;
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (sfdp_session_stats_node) = {
  .name = "sfdp-session-stats",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_session_stats_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_session_stats_error_strings),
  .error_strings = sfdp_session_stats_error_strings,
};

SFDP_SERVICE_DEFINE (session_stats) = {
  .node_name = "sfdp-session-stats",
  .runs_before = SFDP_SERVICES (0),
  .runs_after = SFDP_SERVICES ("sfdp-drop", "sfdp-l4-lifecycle"),
  .is_terminal = 0,
};
