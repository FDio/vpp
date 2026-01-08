// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

/**
 * @file session_quality.c
 * @brief Common session quality analysis implementation
 */

#include <vnet/session_quality/session_quality.h>
#include <vnet/tcp/tcp_packet.h>
#include <math.h>

/* ---- TCP Flag Processing ---- */

void
session_quality_tcp_process_flags (session_quality_tcp_data_t *tcp, u8 flags,
				   u8 dir, u8 ack_dir, tcp_header_t *th,
				   u32 tcp_hlen)
{
  if (flags & TCP_FLAG_SYN)
    {
      if (tcp->syn_packets)
	tcp->syn_retx++;
      tcp->syn_packets++;

      if ((flags & TCP_FLAG_ACK) && !tcp->handshake_ok)
	{
	  /* SYN-ACK: robust SYN RTT calculation using explicit SYN timestamps
	   */
	  if (tcp->syn_timestamp_us[ack_dir] != 0)
	    {
	      u32 now_us = session_quality_now_ticks_us ();
	      tcp->syn_rtt = session_quality_delta_s_from_ticks (
		now_us, tcp->syn_timestamp_us[ack_dir]);
	    }
	}

      if (!(flags & TCP_FLAG_ACK))
	{
	  /* Pure SYN: explicitly timestamp for robust RTT calculation */
	  tcp->syn_timestamp_us[dir] = session_quality_now_ticks_us ();
	}

      /* Parse MSS from SYN options if needed */
      if (tcp->mss == 0)
	{
	  const u8 *opt = (const u8 *) th + sizeof (tcp_header_t);
	  const u8 *end = (const u8 *) th + tcp_hlen;
	  while (opt + 1 < end)
	    {
	      u8 kind = opt[0];
	      if (kind == 0)
		break; /* EOL */
	      if (kind == 1)
		{
		  opt += 1;
		  continue;
		} /* NOP */
	      if (opt + 2 > end)
		break;
	      u8 len = opt[1];
	      if (len < 2 || opt + len > end)
		break;
	      if (kind == 2 && len == 4)
		{ /* MSS */
		  tcp->mss = (opt[2] << 8) | opt[3];
		  break;
		}
	      opt += len;
	    }
	}
    }

  if ((flags & TCP_FLAG_ACK) && !(flags & TCP_FLAG_SYN) && !tcp->handshake_ok)
    {
      /* First pure ACK following SYN-ACK finalizes 3WHS */
      tcp->handshake_ok = 1;
    }

  if (flags & TCP_FLAG_FIN)
    tcp->fin_packets++;
  if (flags & TCP_FLAG_RST)
    tcp->rst_packets++;
}

/* ---- ECN Processing ---- */

void
session_quality_tcp_process_ecn (session_quality_tcp_data_t *tcp, u8 flags,
				 u32 ecn)
{
  /* Track ECN flags for debugging */
  if (flags & TCP_FLAG_ECE)
    {
      tcp->ece_seen++;
      if (ecn == 3)
	tcp->ece_with_ce++;
      else
	tcp->ece_without_ce++;
    }
  if (flags & TCP_FLAG_CWR)
    tcp->cwr_seen++;

  /* Track CE marks in 64-bit sliding window with O(1) rolling popcount */
  u64 outgoing_bit = 1ULL << tcp->ce_mark_index;
  u64 incoming_bit = (ecn == 3) ? (1ULL << tcp->ce_mark_index) : 0;

  /* Update popcount: subtract outgoing bit, add incoming bit */
  if (tcp->ce_mark_bitset & outgoing_bit)
    tcp->ce_mark_popcnt--;
  if (incoming_bit)
    tcp->ce_mark_popcnt++;

  /* Update bitset: clear outgoing bit, set incoming bit */
  tcp->ce_mark_bitset = (tcp->ce_mark_bitset & ~outgoing_bit) | incoming_bit;
  tcp->ce_mark_index = (tcp->ce_mark_index + 1) % 64;
}

/* ---- Zero Window Processing ---- */

void
session_quality_tcp_process_zero_window (session_quality_tcp_data_t *tcp,
					 u16 win, u8 dir)
{
  if (win == 0 && !tcp->in_zero_window[dir])
    {
      tcp->zero_window_events++;
      tcp->in_zero_window[dir] = 1;
      tcp->stall_start_tick_us[dir] = session_quality_now_ticks_us ();
    }
  else if (win > 0 && tcp->in_zero_window[dir])
    {
      tcp->in_zero_window[dir] = 0;
      if (tcp->stall_start_tick_us[dir] != 0)
	{
	  u32 now_us = session_quality_now_ticks_us ();
	  tcp->stall_time_accum[dir] += session_quality_delta_s_from_ticks (
	    now_us, tcp->stall_start_tick_us[dir]);
	  tcp->stall_start_tick_us[dir] = 0;
	}
    }
}

/* ---- ACK Processing ---- */

void
session_quality_tcp_process_ack (session_quality_tcp_data_t *tcp, u8 flags,
				 u32 ack, u8 ack_dir)
{
  if (!(flags & TCP_FLAG_ACK))
    return;

  /* Track ACK advancement for reorder detection */
  if (ack != 0)
    {
      if (seq_gt (ack, tcp->last_ack[ack_dir]))
	{
	  /* ACK advanced - reset stall counter */
	  tcp->ack_stall_count[ack_dir] = 0;
	  tcp->last_ack[ack_dir] = ack;
	}
      else if (seq_leq (ack, tcp->last_ack[ack_dir]))
	{
	  /* ACK did not advance - increment stall counter */
	  tcp->ack_stall_count[ack_dir]++;
	}
    }

  /* RTT calculation */
  if (tcp->rtt_probe_tick_us[ack_dir] != 0)
    {
      if (seq_geq (ack, tcp->last_data_seq[ack_dir]))
	{
	  u32 now_us = session_quality_now_ticks_us ();
	  f64 sample = session_quality_delta_s_from_ticks (
	    now_us, tcp->rtt_probe_tick_us[ack_dir]);
	  if (sample >= 0 && sample < 60.0)
	    session_quality_tcp_rtt_update (tcp, sample, ack_dir);
	  tcp->rtt_probe_tick_us[ack_dir] = 0;
	}
      else
	{
	  /* DupACK detection */
	  if (ack == tcp->last_ack[ack_dir] && tcp->end_seq_max[ack_dir] > ack)
	    {
	      tcp->dupack_like++;
	    }
	}
    }
}

/* ---- Main TCP Packet Processing ---- */

void
session_quality_tcp_on_packet (vlib_buffer_t *b, u8 dir, tcp_header_t *th,
			       session_quality_data_t *data, f64 now)
{
  session_quality_tcp_data_t *tcp = &data->tcp_data;

  u32 tcp_hlen = tcp_header_bytes (th);
  tcp->packets++;
  const u8 ack_dir = 1 - dir;
  const u32 seq = clib_net_to_host_u32 (th->seq_number);
  const u32 ack = clib_net_to_host_u32 (th->ack_number);
  const u16 win = clib_net_to_host_u16 (th->window);
  const u8 flags = th->flags;

  /* Parse IP header for ECN, TTL, and DSCP */
  u32 l3_len = 0;
  u32 ecn = 0;
  u8 ttl = 0;
  u32 dscp = 0;
  session_quality_parse_ip_header (b, &l3_len, &ecn, &ttl, &dscp);

  const u32 l4_off = vnet_buffer (b)->l4_hdr_offset;
  const u32 payload_len =
    (l3_len > (l4_off + tcp_hlen)) ? (l3_len - l4_off - tcp_hlen) : 0;

  /* Update CE density EMA for every packet */
  session_quality_ema_update (&tcp->ema_ce_rate, SESSION_QUALITY_EMA_ALPHA_CE,
			      (ecn == 3) ? 1.0 : 0.0);

  /* Fast-path: Handle non-data packets (pure ACKs, control packets) */
  if (payload_len == 0)
    {
      session_quality_tcp_process_flags (tcp, flags, dir, ack_dir, th,
					 tcp_hlen);
      session_quality_tcp_process_ecn (tcp, flags, ecn);
      session_quality_tcp_process_zero_window (tcp, win, dir);
      session_quality_tcp_process_ack (tcp, flags, ack, ack_dir);
      return;
    }

  /* Data path: Handle packets with payload */
  tcp->data_packets++;

  /* Process TCP state */
  session_quality_tcp_process_flags (tcp, flags, dir, ack_dir, th, tcp_hlen);
  session_quality_tcp_process_ecn (tcp, flags, ecn);
  session_quality_tcp_process_zero_window (tcp, win, dir);
  session_quality_tcp_process_ack (tcp, flags, ack, ack_dir);

  /* Segment size analysis */
#if SESSION_QUALITY_TCP_SEGMENT_ANALYSIS_ENABLED
  if (tcp->mss && payload_len > 0)
    {
      tcp->seg_size_history[tcp->seg_size_index] = (u16) payload_len;
      tcp->seg_size_index = (tcp->seg_size_index + 1) % 16;
      if (tcp->seg_size_count < 16)
	tcp->seg_size_count++;

      u32 size_flag = 0;
      if (payload_len < tcp->mss / 4)
	size_flag = 1; // Small
      else if (payload_len < tcp->mss / 2)
	size_flag = 2; // Medium
      else
	size_flag = 3; // Large

      tcp->seg_size_flags = (tcp->seg_size_flags << 2) | size_flag;

      if (payload_len < tcp->mss / 4)
	{
	  if (tcp->idle_packet_count < 3)
	    {
	      tcp->idle_packet_count++;
	      session_quality_ema_update (
		&tcp->ema_small_seg, SESSION_QUALITY_EMA_ALPHA_DEFAULT, 0.0);
	    }
	  else
	    {
	      tcp->atypical_seg_sizes++;
	      session_quality_ema_update (
		&tcp->ema_small_seg, SESSION_QUALITY_EMA_ALPHA_DEFAULT, 1.0);
	    }
	}
      else
	{
	  tcp->idle_packet_count = 0;
	  session_quality_ema_update (&tcp->ema_small_seg,
				      SESSION_QUALITY_EMA_ALPHA_DEFAULT, 0.0);
	}
    }
#endif

  /* Retransmit / reorder detection */
  const u32 end_seq = seq + payload_len;
  f64 ema_sample_retrans = 0.0;
  f64 ema_sample_overlap = 0.0;
  f64 ema_sample_reorder = 0.0;

  if (tcp->last_seq_valid[dir])
    {
      if (seq_leq (end_seq, tcp->end_seq_max[dir]))
	{
	  /* Complete retransmission/overlap */
	  tcp->retransmissions++;
	  ema_sample_retrans = 1.0;
	  ema_sample_overlap = 1.0;
	}
      else if (seq_lt (seq, tcp->end_seq_max[dir]) &&
	       seq_gt (end_seq, tcp->end_seq_max[dir]))
	{
	  /* Partial overlap */
	  tcp->partial_overlaps++;
	  ema_sample_overlap = 1.0;
	}
      else if (seq_lt (seq, tcp->end_seq_max[dir]))
	{
	  /* Potential reordering */
	  if (tcp->ack_stall_count[ack_dir] >= 3)
	    {
	      tcp->reorder_events++;
	      ema_sample_reorder = 1.0;
	    }
	}
    }

  /* Update EMAs */
  session_quality_ema_update (
    &tcp->ema_retrans, SESSION_QUALITY_EMA_ALPHA_DEFAULT, ema_sample_retrans);
  session_quality_ema_update (
    &tcp->ema_overlap, SESSION_QUALITY_EMA_ALPHA_DEFAULT, ema_sample_overlap);
  session_quality_ema_update (
    &tcp->ema_reorder, SESSION_QUALITY_EMA_ALPHA_DEFAULT, ema_sample_reorder);

  /* Update sequence tracking */
  if (!tcp->last_seq_valid[dir] || seq_gt (end_seq, tcp->end_seq_max[dir]))
    tcp->end_seq_max[dir] = end_seq;
  tcp->last_seq[dir] = end_seq;
  tcp->last_seq_valid[dir] = 1;

  /* Save send time for RTT via ACK on reverse dir */
  tcp->last_data_seq[dir] = seq + payload_len - 1;
  tcp->rtt_probe_tick_us[dir] = session_quality_now_ticks_us ();

  /* Detect idle periods for Nagle/delayed-ACK handling */
  if (tcp->last_data_tick_us[dir] != 0)
    {
      u32 now_us = session_quality_now_ticks_us ();
      f64 time_since_last = session_quality_delta_s_from_ticks (
	now_us, tcp->last_data_tick_us[dir]);
      if (time_since_last > 0.1)
	{
	  tcp->idle_packet_count = 0;
	}
    }
  tcp->last_data_tick_us[dir] = session_quality_now_ticks_us ();

#if SESSION_QUALITY_TCP_TTFB_ENABLED
  /* TTFB tracking */
  if (!tcp->ttfb_valid && payload_len > 0)
    {
      if (tcp->data_packets > 1 && !tcp->ttfb_valid)
	{
	  if (tcp->rtt_probe_tick_us[ack_dir] != 0)
	    {
	      u32 now_us = session_quality_now_ticks_us ();
	      tcp->ttfb = session_quality_delta_s_from_ticks (
		now_us, tcp->rtt_probe_tick_us[ack_dir]);
	      tcp->ttfb_valid = 1;
	    }
	}
    }
#endif
}

/* ---- TCP Penalty Application ---- */

void
session_quality_tcp_apply_penalties (session_quality_data_t *data, u8 is_tcp)
{
  if (!is_tcp)
    return;

  session_quality_tcp_data_t *tcp = &data->tcp_data;

  f64 rtt_sd = session_quality_tcp_rtt_stddev (tcp, 0);
  f64 rtt_sd_in = session_quality_tcp_rtt_stddev (tcp, 1);

  f64 loss_penalty = 0.0;
  f64 reorder_penalty = 0.0;
  f64 stall_penalty = 0.0;
  f64 handshake_penalty = 0.0;
  f64 closure_penalty = 0.0;
  f64 ecn_penalty = 0.0;

  f64 norm = (f64) clib_max (1u, tcp->data_packets);

  /* Loss / retrans */
  f64 loss_penalty_count =
    clib_min (40.0, (tcp->retransmissions / norm) * 200.0);
  f64 loss_penalty_ema = clib_min (40.0, tcp->ema_retrans * 200.0);
  loss_penalty = clib_max (loss_penalty_count, loss_penalty_ema);

  /* Reordering and overlaps */
  reorder_penalty = clib_min (20.0, tcp->ema_reorder * 100.0);
  reorder_penalty += clib_min (10.0, tcp->ema_overlap * 50.0);

  /* Stalls */
  stall_penalty = clib_min (
    25.0, (tcp->stall_time_accum[0] + tcp->stall_time_accum[1]) * 10.0);

  /* Handshake / closure */
  if (!tcp->handshake_ok && tcp->syn_packets > 0)
    handshake_penalty += 10.0;
  if (tcp->syn_retx > 0)
    handshake_penalty += clib_min (15.0, tcp->syn_retx * 5.0);
  if (tcp->syn_rtt > 0 && tcp->syn_rtt > 1.0)
    handshake_penalty += clib_min (10.0, (tcp->syn_rtt - 1.0) * 5.0);
  if (tcp->rst_packets > 0 && tcp->fin_packets == 0)
    closure_penalty += 10.0;

  /* ECN penalty */
  if (tcp->ema_ce_rate > 0.0)
    {
      if (tcp->ema_ce_rate > 0.1)
	ecn_penalty = clib_min (20.0, tcp->ema_ce_rate * 100.0);
    }
  else if (tcp->ce_mark_popcnt > 0)
    {
      f64 ce_rate = (f64) tcp->ce_mark_popcnt / 64.0;
      if (ce_rate > 0.1)
	ecn_penalty = clib_min (20.0, ce_rate * 100.0);
    }

  /* RTT variability penalties */
  f64 rtt_relative_variability_fwd = 0.0;
  f64 rtt_relative_variability_rev = 0.0;

  if (tcp->rtt_mean[0] > 0.001)
    rtt_relative_variability_fwd = rtt_sd / tcp->rtt_mean[0];
  if (tcp->rtt_mean[1] > 0.001)
    rtt_relative_variability_rev = rtt_sd_in / tcp->rtt_mean[1];

  /* Asymmetric path penalty */
  f64 asymmetric_penalty = 0.0;
  if (tcp->rtt_mean[0] > 0.001 && tcp->rtt_mean[1] > 0.001)
    {
      f64 rtt_ratio = clib_max (tcp->rtt_mean[0], tcp->rtt_mean[1]) /
		      clib_min (tcp->rtt_mean[0], tcp->rtt_mean[1]);
      if (rtt_ratio > 2.0)
	asymmetric_penalty = clib_min (10.0, (rtt_ratio - 2.0) * 5.0);
    }

  /* Apply penalties to quality scores */

  /* Congestion */
  f64 cong_delta = loss_penalty + ecn_penalty +
		   clib_min (10.0, rtt_relative_variability_fwd * 100.0) +
		   asymmetric_penalty;
  data->q_congestion = clib_max (0.0, data->q_congestion - cong_delta);

  /* Stability */
  f64 stab_delta = clib_min (15.0, rtt_relative_variability_fwd * 150.0) +
		   clib_min (10.0, rtt_relative_variability_rev * 100.0);
  data->q_stability = clib_max (0.0, data->q_stability - stab_delta);

  /* Continuity */
  f64 cont_delta = reorder_penalty + stall_penalty;
  data->q_continuity = clib_max (0.0, data->q_continuity - cont_delta);

  /* Delivery */
  f64 deliv_delta = handshake_penalty + closure_penalty;
  data->q_delivery = clib_max (0.0, data->q_delivery - deliv_delta);

  /* Packetization */
#if SESSION_QUALITY_TCP_SEGMENT_ANALYSIS_ENABLED
  if (tcp->mss)
    {
      f64 small_frac = tcp->ema_small_seg;
      if (small_frac > 0.3)
	{
	  f64 pz_delta = clib_min (15.0, (small_frac - 0.3) * 50.0);
	  data->q_packetization =
	    clib_max (0.0, data->q_packetization - pz_delta);
	}
    }
#endif
}

/* ---- Quality Score Computation ---- */

void
session_quality_compute_scores (session_quality_data_t *data, u8 is_tcp,
				u32 icmp_unreach, u32 icmp_frag_needed,
				u32 icmp_ttl_expired, u32 icmp_packet_too_big,
				u32 packets_fwd, u32 packets_rev,
				u64 bytes_fwd, u64 bytes_rev)
{
  /* Compute derived statistics */
  data->ttl_stddev[0] =
    session_quality_welford_stddev (data->ttl_m2[0], data->ttl_count[0]);
  data->ttl_stddev[1] =
    session_quality_welford_stddev (data->ttl_m2[1], data->ttl_count[1]);
  data->iat_stddev =
    session_quality_welford_stddev (data->iat_m2, data->iat_count);
  data->iat_cv =
    (data->iat_mean > 0) ? data->iat_stddev / data->iat_mean : 0.0;

  /* Compute quality components */
  data->q_stability = session_quality_compute_stability (data->iat_cv);
  data->q_congestion = session_quality_compute_congestion (
    data->ecn_ce, data->ecn_ect, data->ttl_stddev[0], data->ttl_stddev[1]);
  data->q_continuity = session_quality_compute_continuity (
    data->burst_count, data->idle_periods, data->frames_touched);
  data->q_delivery = session_quality_compute_delivery (
    icmp_unreach, icmp_frag_needed, icmp_ttl_expired, icmp_packet_too_big);
  data->q_packetization = session_quality_compute_packetization (
    packets_fwd + packets_rev, bytes_fwd + bytes_rev, data->tiny_packets,
    data->dscp_changes);

  /* Apply TCP-specific penalties if applicable */
  session_quality_tcp_apply_penalties (data, is_tcp);

  /* Compute weighted quality score (0-100) */
  data->quality_score =
    (data->q_stability * 0.40) + (data->q_congestion * 0.25) +
    (data->q_continuity * 0.20) + (data->q_delivery * 0.10) +
    (data->q_packetization * 0.05);
}
