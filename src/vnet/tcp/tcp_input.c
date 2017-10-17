/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vppinfra/sparse_vec.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/tcp/tcp.h>
#include <vnet/session/session.h>
#include <math.h>

static char *tcp_error_strings[] = {
#define tcp_error(n,s) s,
#include <vnet/tcp/tcp_error.def>
#undef tcp_error
};

/* All TCP nodes have the same outgoing arcs */
#define foreach_tcp_state_next                  \
  _ (DROP, "error-drop")                        \
  _ (TCP4_OUTPUT, "tcp4-output")                \
  _ (TCP6_OUTPUT, "tcp6-output")

typedef enum _tcp_established_next
{
#define _(s,n) TCP_ESTABLISHED_NEXT_##s,
  foreach_tcp_state_next
#undef _
    TCP_ESTABLISHED_N_NEXT,
} tcp_established_next_t;

typedef enum _tcp_rcv_process_next
{
#define _(s,n) TCP_RCV_PROCESS_NEXT_##s,
  foreach_tcp_state_next
#undef _
    TCP_RCV_PROCESS_N_NEXT,
} tcp_rcv_process_next_t;

typedef enum _tcp_syn_sent_next
{
#define _(s,n) TCP_SYN_SENT_NEXT_##s,
  foreach_tcp_state_next
#undef _
    TCP_SYN_SENT_N_NEXT,
} tcp_syn_sent_next_t;

typedef enum _tcp_listen_next
{
#define _(s,n) TCP_LISTEN_NEXT_##s,
  foreach_tcp_state_next
#undef _
    TCP_LISTEN_N_NEXT,
} tcp_listen_next_t;

/* Generic, state independent indices */
typedef enum _tcp_state_next
{
#define _(s,n) TCP_NEXT_##s,
  foreach_tcp_state_next
#undef _
    TCP_STATE_N_NEXT,
} tcp_state_next_t;

#define tcp_next_output(is_ip4) (is_ip4 ? TCP_NEXT_TCP4_OUTPUT          \
                                        : TCP_NEXT_TCP6_OUTPUT)

vlib_node_registration_t tcp4_established_node;
vlib_node_registration_t tcp6_established_node;

/**
 * Validate segment sequence number. As per RFC793:
 *
 * Segment Receive Test
 *      Length  Window
 *      ------- -------  -------------------------------------------
 *      0       0       SEG.SEQ = RCV.NXT
 *      0       >0      RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
 *      >0      0       not acceptable
 *      >0      >0      RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
 *                      or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
 *
 * This ultimately consists in checking if segment falls within the window.
 * The one important difference compared to RFC793 is that we use rcv_las,
 * or the rcv_nxt at last ack sent instead of rcv_nxt since that's the
 * peer's reference when computing our receive window.
 *
 * This:
 *  seq_leq (end_seq, tc->rcv_las + tc->rcv_wnd) && seq_geq (seq, tc->rcv_las)
 * however, is too strict when we have retransmits. Instead we just check that
 * the seq is not beyond the right edge and that the end of the segment is not
 * less than the left edge.
 *
 * N.B. rcv_nxt and rcv_wnd are both updated in this node if acks are sent, so
 * use rcv_nxt in the right edge window test instead of rcv_las.
 *
 */
always_inline u8
tcp_segment_in_rcv_wnd (tcp_connection_t * tc, u32 seq, u32 end_seq)
{
  return (seq_geq (end_seq, tc->rcv_las)
	  && seq_leq (seq, tc->rcv_nxt + tc->rcv_wnd));
}

/**
 * Parse TCP header options.
 *
 * @param th TCP header
 * @param to TCP options data structure to be populated
 * @return -1 if parsing failed
 */
int
tcp_options_parse (tcp_header_t * th, tcp_options_t * to)
{
  const u8 *data;
  u8 opt_len, opts_len, kind;
  int j;
  sack_block_t b;

  opts_len = (tcp_doff (th) << 2) - sizeof (tcp_header_t);
  data = (const u8 *) (th + 1);

  /* Zero out all flags but those set in SYN */
  to->flags &= (TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_WSCALE);

  for (; opts_len > 0; opts_len -= opt_len, data += opt_len)
    {
      kind = data[0];

      /* Get options length */
      if (kind == TCP_OPTION_EOL)
	break;
      else if (kind == TCP_OPTION_NOOP)
	{
	  opt_len = 1;
	  continue;
	}
      else
	{
	  /* broken options */
	  if (opts_len < 2)
	    return -1;
	  opt_len = data[1];

	  /* weird option length */
	  if (opt_len < 2 || opt_len > opts_len)
	    return -1;
	}

      /* Parse options */
      switch (kind)
	{
	case TCP_OPTION_MSS:
	  if ((opt_len == TCP_OPTION_LEN_MSS) && tcp_syn (th))
	    {
	      to->flags |= TCP_OPTS_FLAG_MSS;
	      to->mss = clib_net_to_host_u16 (*(u16 *) (data + 2));
	    }
	  break;
	case TCP_OPTION_WINDOW_SCALE:
	  if ((opt_len == TCP_OPTION_LEN_WINDOW_SCALE) && tcp_syn (th))
	    {
	      to->flags |= TCP_OPTS_FLAG_WSCALE;
	      to->wscale = data[2];
	      if (to->wscale > TCP_MAX_WND_SCALE)
		{
		  clib_warning ("Illegal window scaling value: %d",
				to->wscale);
		  to->wscale = TCP_MAX_WND_SCALE;
		}
	    }
	  break;
	case TCP_OPTION_TIMESTAMP:
	  if (opt_len == TCP_OPTION_LEN_TIMESTAMP)
	    {
	      to->flags |= TCP_OPTS_FLAG_TSTAMP;
	      to->tsval = clib_net_to_host_u32 (*(u32 *) (data + 2));
	      to->tsecr = clib_net_to_host_u32 (*(u32 *) (data + 6));
	    }
	  break;
	case TCP_OPTION_SACK_PERMITTED:
	  if (opt_len == TCP_OPTION_LEN_SACK_PERMITTED && tcp_syn (th))
	    to->flags |= TCP_OPTS_FLAG_SACK_PERMITTED;
	  break;
	case TCP_OPTION_SACK_BLOCK:
	  /* If SACK permitted was not advertised or a SYN, break */
	  if ((to->flags & TCP_OPTS_FLAG_SACK_PERMITTED) == 0 || tcp_syn (th))
	    break;

	  /* If too short or not correctly formatted, break */
	  if (opt_len < 10 || ((opt_len - 2) % TCP_OPTION_LEN_SACK_BLOCK))
	    break;

	  to->flags |= TCP_OPTS_FLAG_SACK;
	  to->n_sack_blocks = (opt_len - 2) / TCP_OPTION_LEN_SACK_BLOCK;
	  vec_reset_length (to->sacks);
	  for (j = 0; j < to->n_sack_blocks; j++)
	    {
	      b.start = clib_net_to_host_u32 (*(u32 *) (data + 2 + 8 * j));
	      b.end = clib_net_to_host_u32 (*(u32 *) (data + 6 + 8 * j));
	      vec_add1 (to->sacks, b);
	    }
	  break;
	default:
	  /* Nothing to see here */
	  continue;
	}
    }
  return 0;
}

/**
 * RFC1323: Check against wrapped sequence numbers (PAWS). If we have
 * timestamp to echo and it's less than tsval_recent, drop segment
 * but still send an ACK in order to retain TCP's mechanism for detecting
 * and recovering from half-open connections
 *
 * Or at least that's what the theory says. It seems that this might not work
 * very well with packet reordering and fast retransmit. XXX
 */
always_inline int
tcp_segment_check_paws (tcp_connection_t * tc)
{
  return tcp_opts_tstamp (&tc->rcv_opts) && tc->tsval_recent
    && timestamp_lt (tc->rcv_opts.tsval, tc->tsval_recent);
}

/**
 * Update tsval recent
 */
always_inline void
tcp_update_timestamp (tcp_connection_t * tc, u32 seq, u32 seq_end)
{
  /*
   * RFC1323: If Last.ACK.sent falls within the range of sequence numbers
   * of an incoming segment:
   *    SEG.SEQ <= Last.ACK.sent < SEG.SEQ + SEG.LEN
   * then the TSval from the segment is copied to TS.Recent;
   * otherwise, the TSval is ignored.
   */
  if (tcp_opts_tstamp (&tc->rcv_opts) && seq_leq (seq, tc->rcv_las)
      && seq_leq (tc->rcv_las, seq_end))
    {
      ASSERT (timestamp_leq (tc->tsval_recent, tc->rcv_opts.tsval));
      tc->tsval_recent = tc->rcv_opts.tsval;
      tc->tsval_recent_age = tcp_time_now ();
    }
}

/**
 * Validate incoming segment as per RFC793 p. 69 and RFC1323 p. 19
 *
 * It first verifies if segment has a wrapped sequence number (PAWS) and then
 * does the processing associated to the first four steps (ignoring security
 * and precedence): sequence number, rst bit and syn bit checks.
 *
 * @return 0 if segments passes validation.
 */
static int
tcp_segment_validate (vlib_main_t * vm, tcp_connection_t * tc0,
		      vlib_buffer_t * b0, tcp_header_t * th0, u32 * next0)
{
  if (PREDICT_FALSE (!tcp_ack (th0) && !tcp_rst (th0) && !tcp_syn (th0)))
    return -1;

  if (PREDICT_FALSE (tcp_options_parse (th0, &tc0->rcv_opts)))
    {
      clib_warning ("options parse error");
      return -1;
    }

  if (tcp_segment_check_paws (tc0))
    {
      if (CLIB_DEBUG > 2)
	{
	  clib_warning ("paws failed\n%U", format_tcp_connection, tc0, 2);
	  clib_warning ("seq %u seq_end %u ack %u",
			vnet_buffer (b0)->tcp.seq_number - tc0->irs,
			vnet_buffer (b0)->tcp.seq_end - tc0->irs,
			vnet_buffer (b0)->tcp.ack_number - tc0->iss);
	}
      TCP_EVT_DBG (TCP_EVT_PAWS_FAIL, tc0, vnet_buffer (b0)->tcp.seq_number,
		   vnet_buffer (b0)->tcp.seq_end);

      /* If it just so happens that a segment updates tsval_recent for a
       * segment over 24 days old, invalidate tsval_recent. */
      if (timestamp_lt (tc0->tsval_recent_age + TCP_PAWS_IDLE,
			tcp_time_now ()))
	{
	  /* Age isn't reset until we get a valid tsval (bsd inspired) */
	  tc0->tsval_recent = 0;
	  clib_warning ("paws failed - really old segment. REALLY?");
	}
      else
	{
	  /* Drop after ack if not rst */
	  if (!tcp_rst (th0))
	    {
	      tcp_make_ack (tc0, b0);
	      *next0 = tcp_next_output (tc0->c_is_ip4);
	      TCP_EVT_DBG (TCP_EVT_DUPACK_SENT, tc0);
	      return -1;
	    }
	}
    }

  /* 1st: check sequence number */
  if (!tcp_segment_in_rcv_wnd (tc0, vnet_buffer (b0)->tcp.seq_number,
			       vnet_buffer (b0)->tcp.seq_end))
    {
      /* If our window is 0 and the packet is in sequence, let it pass
       * through for ack processing. It should be dropped later.*/
      if (tc0->rcv_wnd == 0
	  && tc0->rcv_nxt == vnet_buffer (b0)->tcp.seq_number)
	{
	  /* TODO Should segment be tagged?  */
	}
      else
	{
	  /* If not RST, send dup ack */
	  if (!tcp_rst (th0))
	    {
	      tcp_make_ack (tc0, b0);
	      *next0 = tcp_next_output (tc0->c_is_ip4);
	      TCP_EVT_DBG (TCP_EVT_DUPACK_SENT, tc0);
	    }
	  return -1;
	}
    }

  /* 2nd: check the RST bit */
  if (tcp_rst (th0))
    {
      tcp_connection_reset (tc0);
      return -1;
    }

  /* 3rd: check security and precedence (skip) */

  /* 4th: check the SYN bit */
  if (tcp_syn (th0))
    {
      /* TODO implement RFC 5961 */
      if (tc0->state == TCP_STATE_SYN_RCVD)
	{
	  tcp_make_synack (tc0, b0);
	  TCP_EVT_DBG (TCP_EVT_SYN_RCVD, tc0, 0);
	}
      else
	{
	  tcp_make_ack (tc0, b0);
	  TCP_EVT_DBG (TCP_EVT_SYNACK_RCVD, tc0);
	}
      *next0 = tcp_next_output (tc0->c_is_ip4);
      return -1;
    }

  /* If segment in window, save timestamp */
  tcp_update_timestamp (tc0, vnet_buffer (b0)->tcp.seq_number,
			vnet_buffer (b0)->tcp.seq_end);
  return 0;
}

always_inline int
tcp_rcv_ack_is_acceptable (tcp_connection_t * tc0, vlib_buffer_t * tb0)
{
  /* SND.UNA =< SEG.ACK =< SND.NXT */
  return (seq_leq (tc0->snd_una, vnet_buffer (tb0)->tcp.ack_number)
	  && seq_leq (vnet_buffer (tb0)->tcp.ack_number, tc0->snd_nxt));
}

/**
 * Compute smoothed RTT as per VJ's '88 SIGCOMM and RFC6298
 *
 * Note that although the original article, srtt and rttvar are scaled
 * to minimize round-off errors, here we don't. Instead, we rely on
 * better precision time measurements.
 *
 * TODO support us rtt resolution
 */
static void
tcp_estimate_rtt (tcp_connection_t * tc, u32 mrtt)
{
  int err, diff;

  if (tc->srtt != 0)
    {
      err = mrtt - tc->srtt;

      /* XXX Drop in RTT results in RTTVAR increase and bigger RTO.
       * The increase should be bound */
      tc->srtt = clib_max ((int) tc->srtt + (err >> 3), 1);
      diff = (clib_abs (err) - (int) tc->rttvar) >> 2;
      tc->rttvar = clib_max ((int) tc->rttvar + diff, 1);
    }
  else
    {
      /* First measurement. */
      tc->srtt = mrtt;
      tc->rttvar = mrtt >> 1;
    }
}

void
tcp_update_rto (tcp_connection_t * tc)
{
  tc->rto = clib_min (tc->srtt + (tc->rttvar << 2), TCP_RTO_MAX);
  tc->rto = clib_max (tc->rto, TCP_RTO_MIN);
}

/**
 * Update RTT estimate and RTO timer
 *
 * Measure RTT: We have two sources of RTT measurements: TSOPT and ACK
 * timing. Middle boxes are known to fiddle with TCP options so we
 * should give higher priority to ACK timing.
 *
 * This should be called only if previously sent bytes have been acked.
 *
 * return 1 if valid rtt 0 otherwise
 */
static int
tcp_update_rtt (tcp_connection_t * tc, u32 ack)
{
  u32 mrtt = 0;

  /* Karn's rule, part 1. Don't use retransmitted segments to estimate
   * RTT because they're ambiguous. */
  if (tcp_in_cong_recovery (tc) || tc->sack_sb.sacked_bytes)
    goto done;

  if (tc->rtt_ts && seq_geq (ack, tc->rtt_seq))
    {
      mrtt = tcp_time_now () - tc->rtt_ts;
    }
  /* As per RFC7323 TSecr can be used for RTTM only if the segment advances
   * snd_una, i.e., the left side of the send window:
   * seq_lt (tc->snd_una, ack). This is a condition for calling update_rtt */
  else if (tcp_opts_tstamp (&tc->rcv_opts) && tc->rcv_opts.tsecr)
    {
      mrtt = tcp_time_now () - tc->rcv_opts.tsecr;
    }

  /* Ignore dubious measurements */
  if (mrtt == 0 || mrtt > TCP_RTT_MAX)
    goto done;

  tcp_estimate_rtt (tc, mrtt);

done:

  /* Allow measuring of a new RTT */
  tc->rtt_ts = 0;

  /* If we got here something must've been ACKed so make sure boff is 0,
   * even if mrrt is not valid since we update the rto lower */
  tc->rto_boff = 0;
  tcp_update_rto (tc);

  return 0;
}

/**
 * Dequeue bytes that have been acked and while at it update RTT estimates.
 */
static void
tcp_dequeue_acked (tcp_connection_t * tc, u32 ack)
{
  /* Dequeue the newly ACKed add SACKed bytes */
  stream_session_dequeue_drop (&tc->connection,
			       tc->bytes_acked + tc->sack_sb.snd_una_adv);

  tcp_validate_txf_size (tc, tc->snd_una_max - tc->snd_una);

  /* Update rtt and rto */
  tcp_update_rtt (tc, ack);

  /* If everything has been acked, stop retransmit timer
   * otherwise update. */
  tcp_retransmit_timer_update (tc);
}

/**
 * Check if duplicate ack as per RFC5681 Sec. 2
 */
static u8
tcp_ack_is_dupack (tcp_connection_t * tc, vlib_buffer_t * b, u32 prev_snd_wnd,
		   u32 prev_snd_una)
{
  return ((vnet_buffer (b)->tcp.ack_number == prev_snd_una)
	  && seq_gt (tc->snd_una_max, tc->snd_una)
	  && (vnet_buffer (b)->tcp.seq_end == vnet_buffer (b)->tcp.seq_number)
	  && (prev_snd_wnd == tc->snd_wnd));
}

/**
 * Checks if ack is a congestion control event.
 */
static u8
tcp_ack_is_cc_event (tcp_connection_t * tc, vlib_buffer_t * b,
		     u32 prev_snd_wnd, u32 prev_snd_una, u8 * is_dack)
{
  /* Check if ack is duplicate. Per RFC 6675, ACKs that SACK new data are
   * defined to be 'duplicate' */
  *is_dack = tc->sack_sb.last_sacked_bytes
    || tcp_ack_is_dupack (tc, b, prev_snd_wnd, prev_snd_una);

  return ((*is_dack || tcp_in_cong_recovery (tc)) && !tcp_is_lost_fin (tc));
}

void
scoreboard_remove_hole (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  sack_scoreboard_hole_t *next, *prev;

  if (hole->next != TCP_INVALID_SACK_HOLE_INDEX)
    {
      next = pool_elt_at_index (sb->holes, hole->next);
      next->prev = hole->prev;
    }
  else
    {
      sb->tail = hole->prev;
    }

  if (hole->prev != TCP_INVALID_SACK_HOLE_INDEX)
    {
      prev = pool_elt_at_index (sb->holes, hole->prev);
      prev->next = hole->next;
    }
  else
    {
      sb->head = hole->next;
    }

  if (scoreboard_hole_index (sb, hole) == sb->cur_rxt_hole)
    sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;

  /* Poison the entry */
  if (CLIB_DEBUG > 0)
    memset (hole, 0xfe, sizeof (*hole));

  pool_put (sb->holes, hole);
}

sack_scoreboard_hole_t *
scoreboard_insert_hole (sack_scoreboard_t * sb, u32 prev_index,
			u32 start, u32 end)
{
  sack_scoreboard_hole_t *hole, *next, *prev;
  u32 hole_index;

  pool_get (sb->holes, hole);
  memset (hole, 0, sizeof (*hole));

  hole->start = start;
  hole->end = end;
  hole_index = scoreboard_hole_index (sb, hole);

  prev = scoreboard_get_hole (sb, prev_index);
  if (prev)
    {
      hole->prev = prev_index;
      hole->next = prev->next;

      if ((next = scoreboard_next_hole (sb, hole)))
	next->prev = hole_index;
      else
	sb->tail = hole_index;

      prev->next = hole_index;
    }
  else
    {
      sb->head = hole_index;
      hole->prev = TCP_INVALID_SACK_HOLE_INDEX;
      hole->next = TCP_INVALID_SACK_HOLE_INDEX;
    }

  return hole;
}

void
scoreboard_update_bytes (tcp_connection_t * tc, sack_scoreboard_t * sb)
{
  sack_scoreboard_hole_t *hole, *prev;
  u32 bytes = 0, blks = 0;

  sb->lost_bytes = 0;
  sb->sacked_bytes = 0;
  hole = scoreboard_last_hole (sb);
  if (!hole)
    return;

  if (seq_gt (sb->high_sacked, hole->end))
    {
      bytes = sb->high_sacked - hole->end;
      blks = 1;
    }

  while ((prev = scoreboard_prev_hole (sb, hole))
	 && (bytes < (TCP_DUPACK_THRESHOLD - 1) * tc->snd_mss
	     && blks < TCP_DUPACK_THRESHOLD))
    {
      bytes += hole->start - prev->end;
      blks++;
      hole = prev;
    }

  while (hole)
    {
      sb->lost_bytes += scoreboard_hole_bytes (hole);
      hole->is_lost = 1;
      prev = hole;
      hole = scoreboard_prev_hole (sb, hole);
      if (hole)
	bytes += prev->start - hole->end;
    }
  sb->sacked_bytes = bytes;
}

/**
 * Figure out the next hole to retransmit
 *
 * Follows logic proposed in RFC6675 Sec. 4, NextSeg()
 */
sack_scoreboard_hole_t *
scoreboard_next_rxt_hole (sack_scoreboard_t * sb,
			  sack_scoreboard_hole_t * start,
			  u8 have_sent_1_smss,
			  u8 * can_rescue, u8 * snd_limited)
{
  sack_scoreboard_hole_t *hole = 0;

  hole = start ? start : scoreboard_first_hole (sb);
  while (hole && seq_leq (hole->end, sb->high_rxt) && hole->is_lost)
    hole = scoreboard_next_hole (sb, hole);

  /* Nothing, return */
  if (!hole)
    {
      sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
      return 0;
    }

  /* Rule (1): if higher than rxt, less than high_sacked and lost */
  if (hole->is_lost && seq_lt (hole->start, sb->high_sacked))
    {
      sb->cur_rxt_hole = scoreboard_hole_index (sb, hole);
    }
  else
    {
      /* Rule (2): output takes care of transmitting new data */
      if (!have_sent_1_smss)
	{
	  hole = 0;
	  sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
	}
      /* Rule (3): if hole not lost */
      else if (seq_lt (hole->start, sb->high_sacked))
	{
	  *snd_limited = 1;
	  sb->cur_rxt_hole = scoreboard_hole_index (sb, hole);
	}
      /* Rule (4): if hole beyond high_sacked */
      else
	{
	  ASSERT (seq_geq (hole->start, sb->high_sacked));
	  *snd_limited = 1;
	  *can_rescue = 1;
	  /* HighRxt MUST NOT be updated */
	  return 0;
	}
    }

  if (hole && seq_lt (sb->high_rxt, hole->start))
    sb->high_rxt = hole->start;

  return hole;
}

void
scoreboard_init_high_rxt (sack_scoreboard_t * sb, u32 seq)
{
  sack_scoreboard_hole_t *hole;
  hole = scoreboard_first_hole (sb);
  if (hole)
    {
      seq = seq_gt (seq, hole->start) ? seq : hole->start;
      sb->cur_rxt_hole = sb->head;
    }
  sb->high_rxt = seq;
}

/**
 * Test that scoreboard is sane after recovery
 *
 * Returns 1 if scoreboard is empty or if first hole beyond
 * snd_una.
 */
u8
tcp_scoreboard_is_sane_post_recovery (tcp_connection_t * tc)
{
  sack_scoreboard_hole_t *hole;
  hole = scoreboard_first_hole (&tc->sack_sb);
  return (!hole || seq_geq (hole->start, tc->snd_una));
}

void
tcp_rcv_sacks (tcp_connection_t * tc, u32 ack)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t *blk, tmp;
  sack_scoreboard_hole_t *hole, *next_hole, *last_hole;
  u32 blk_index = 0, old_sacked_bytes, hole_index;
  int i, j;

  sb->last_sacked_bytes = 0;
  sb->snd_una_adv = 0;
  old_sacked_bytes = sb->sacked_bytes;
  sb->last_bytes_delivered = 0;

  if (!tcp_opts_sack (&tc->rcv_opts)
      && sb->head == TCP_INVALID_SACK_HOLE_INDEX)
    return;

  /* Remove invalid blocks */
  blk = tc->rcv_opts.sacks;
  while (blk < vec_end (tc->rcv_opts.sacks))
    {
      if (seq_lt (blk->start, blk->end)
	  && seq_gt (blk->start, tc->snd_una)
	  && seq_gt (blk->start, ack) && seq_leq (blk->end, tc->snd_una_max))
	{
	  blk++;
	  continue;
	}
      vec_del1 (tc->rcv_opts.sacks, blk - tc->rcv_opts.sacks);
    }

  /* Add block for cumulative ack */
  if (seq_gt (ack, tc->snd_una))
    {
      tmp.start = tc->snd_una;
      tmp.end = ack;
      vec_add1 (tc->rcv_opts.sacks, tmp);
    }

  if (vec_len (tc->rcv_opts.sacks) == 0)
    return;

  tcp_scoreboard_trace_add (tc, ack);

  /* Make sure blocks are ordered */
  for (i = 0; i < vec_len (tc->rcv_opts.sacks); i++)
    for (j = i + 1; j < vec_len (tc->rcv_opts.sacks); j++)
      if (seq_lt (tc->rcv_opts.sacks[j].start, tc->rcv_opts.sacks[i].start))
	{
	  tmp = tc->rcv_opts.sacks[i];
	  tc->rcv_opts.sacks[i] = tc->rcv_opts.sacks[j];
	  tc->rcv_opts.sacks[j] = tmp;
	}

  if (sb->head == TCP_INVALID_SACK_HOLE_INDEX)
    {
      /* If no holes, insert the first that covers all outstanding bytes */
      last_hole = scoreboard_insert_hole (sb, TCP_INVALID_SACK_HOLE_INDEX,
					  tc->snd_una, tc->snd_una_max);
      sb->tail = scoreboard_hole_index (sb, last_hole);
      tmp = tc->rcv_opts.sacks[vec_len (tc->rcv_opts.sacks) - 1];
      sb->high_sacked = tmp.end;
    }
  else
    {
      /* If we have holes but snd_una_max is beyond the last hole, update
       * last hole end */
      tmp = tc->rcv_opts.sacks[vec_len (tc->rcv_opts.sacks) - 1];
      last_hole = scoreboard_last_hole (sb);
      if (seq_gt (tc->snd_una_max, last_hole->end))
	{
	  if (seq_geq (last_hole->start, sb->high_sacked))
	    {
	      last_hole->end = tc->snd_una_max;
	    }
	  /* New hole after high sacked block */
	  else if (seq_lt (sb->high_sacked, tc->snd_una_max))
	    {
	      scoreboard_insert_hole (sb, sb->tail, sb->high_sacked,
				      tc->snd_una_max);
	    }
	}
      /* Keep track of max byte sacked for when the last hole
       * is acked */
      if (seq_gt (tmp.end, sb->high_sacked))
	sb->high_sacked = tmp.end;
    }

  /* Walk the holes with the SACK blocks */
  hole = pool_elt_at_index (sb->holes, sb->head);
  while (hole && blk_index < vec_len (tc->rcv_opts.sacks))
    {
      blk = &tc->rcv_opts.sacks[blk_index];
      if (seq_leq (blk->start, hole->start))
	{
	  /* Block covers hole. Remove hole */
	  if (seq_geq (blk->end, hole->end))
	    {
	      next_hole = scoreboard_next_hole (sb, hole);

	      /* Byte accounting: snd_una needs to be advanced */
	      if (blk->end == ack)
		{
		  if (next_hole)
		    {
		      if (seq_lt (ack, next_hole->start))
			sb->snd_una_adv = next_hole->start - ack;
		      sb->last_bytes_delivered +=
			next_hole->start - hole->end;
		    }
		  else
		    {
		      ASSERT (seq_geq (sb->high_sacked, ack));
		      sb->snd_una_adv = sb->high_sacked - ack;
		      sb->last_bytes_delivered += sb->high_sacked - hole->end;
		    }
		}

	      scoreboard_remove_hole (sb, hole);
	      hole = next_hole;
	    }
	  /* Partial 'head' overlap */
	  else
	    {
	      if (seq_gt (blk->end, hole->start))
		{
		  hole->start = blk->end;
		}
	      blk_index++;
	    }
	}
      else
	{
	  /* Hole must be split */
	  if (seq_lt (blk->end, hole->end))
	    {
	      hole_index = scoreboard_hole_index (sb, hole);
	      next_hole = scoreboard_insert_hole (sb, hole_index, blk->end,
						  hole->end);

	      /* Pool might've moved */
	      hole = scoreboard_get_hole (sb, hole_index);
	      hole->end = blk->start;
	      blk_index++;
	      ASSERT (hole->next == scoreboard_hole_index (sb, next_hole));
	    }
	  else if (seq_lt (blk->start, hole->end))
	    {
	      hole->end = blk->start;
	    }
	  hole = scoreboard_next_hole (sb, hole);
	}
    }

  scoreboard_update_bytes (tc, sb);
  sb->last_sacked_bytes = sb->sacked_bytes
    - (old_sacked_bytes - sb->last_bytes_delivered);
  ASSERT (sb->last_sacked_bytes <= sb->sacked_bytes);
  ASSERT (sb->sacked_bytes == 0
	  || sb->sacked_bytes < tc->snd_una_max - seq_max (tc->snd_una, ack));
  ASSERT (sb->last_sacked_bytes + sb->lost_bytes <= tc->snd_una_max
	  - seq_max (tc->snd_una, ack));
  ASSERT (sb->head == TCP_INVALID_SACK_HOLE_INDEX || tcp_in_recovery (tc)
	  || sb->holes[sb->head].start == ack + sb->snd_una_adv);
}

/**
 * Try to update snd_wnd based on feedback received from peer.
 *
 * If successful, and new window is 'effectively' 0, activate persist
 * timer.
 */
static void
tcp_update_snd_wnd (tcp_connection_t * tc, u32 seq, u32 ack, u32 snd_wnd)
{
  /* If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
   * SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK */
  if (seq_lt (tc->snd_wl1, seq)
      || (tc->snd_wl1 == seq && seq_leq (tc->snd_wl2, ack)))
    {
      tc->snd_wnd = snd_wnd;
      tc->snd_wl1 = seq;
      tc->snd_wl2 = ack;
      TCP_EVT_DBG (TCP_EVT_SND_WND, tc);

      if (tc->snd_wnd < tc->snd_mss)
	{
	  /* Set persist timer if not set and we just got 0 wnd */
	  if (!tcp_timer_is_active (tc, TCP_TIMER_PERSIST)
	      && !tcp_timer_is_active (tc, TCP_TIMER_RETRANSMIT))
	    tcp_persist_timer_set (tc);
	}
      else
	{
	  tcp_persist_timer_reset (tc);
	  if (!tcp_in_recovery (tc) && tc->rto_boff > 0)
	    {
	      tc->rto_boff = 0;
	      tcp_update_rto (tc);
	    }
	}
    }
}

void
tcp_cc_init_congestion (tcp_connection_t * tc)
{
  tcp_fastrecovery_on (tc);
  tc->snd_congestion = tc->snd_una_max;
  tc->cc_algo->congestion (tc);
  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 4);
}

static void
tcp_cc_recovery_exit (tcp_connection_t * tc)
{
  /* Deflate rto */
  tc->rto_boff = 0;
  tcp_update_rto (tc);
  tc->snd_rxt_ts = 0;
  tc->snd_nxt = tc->snd_una_max;
  tcp_recovery_off (tc);
  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 3);
}

void
tcp_cc_fastrecovery_exit (tcp_connection_t * tc)
{
  tc->cc_algo->recovered (tc);
  tc->snd_rxt_bytes = 0;
  tc->rcv_dupacks = 0;
  tc->snd_nxt = tc->snd_una_max;
  tcp_fastrecovery_off (tc);
  tcp_fastrecovery_1_smss_off (tc);
  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 3);
}

static void
tcp_cc_congestion_undo (tcp_connection_t * tc)
{
  tc->cwnd = tc->prev_cwnd;
  tc->ssthresh = tc->prev_ssthresh;
  tc->snd_nxt = tc->snd_una_max;
  tc->rcv_dupacks = 0;
  if (tcp_in_recovery (tc))
    tcp_cc_recovery_exit (tc);
  ASSERT (tc->rto_boff == 0);
  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 5);
  /* TODO extend for fastrecovery */
}

static u8
tcp_cc_is_spurious_retransmit (tcp_connection_t * tc)
{
  return (tcp_in_recovery (tc) && tc->rto_boff == 1
	  && tc->snd_rxt_ts
	  && tcp_opts_tstamp (&tc->rcv_opts)
	  && timestamp_lt (tc->rcv_opts.tsecr, tc->snd_rxt_ts));
}

int
tcp_cc_recover (tcp_connection_t * tc)
{
  ASSERT (tcp_in_cong_recovery (tc));
  if (tcp_cc_is_spurious_retransmit (tc))
    {
      tcp_cc_congestion_undo (tc);
      return 1;
    }

  if (tcp_in_recovery (tc))
    tcp_cc_recovery_exit (tc);
  else if (tcp_in_fastrecovery (tc))
    tcp_cc_fastrecovery_exit (tc);

  ASSERT (tc->rto_boff == 0);
  ASSERT (!tcp_in_cong_recovery (tc));
  ASSERT (tcp_scoreboard_is_sane_post_recovery (tc));
  return 0;
}

static void
tcp_cc_update (tcp_connection_t * tc, vlib_buffer_t * b)
{
  ASSERT (!tcp_in_cong_recovery (tc) || tcp_is_lost_fin (tc));

  /* Congestion avoidance */
  tc->cc_algo->rcv_ack (tc);
  tc->tsecr_last_ack = tc->rcv_opts.tsecr;

  /* If a cumulative ack, make sure dupacks is 0 */
  tc->rcv_dupacks = 0;

  /* When dupacks hits the threshold we only enter fast retransmit if
   * cumulative ack covers more than snd_congestion. Should snd_una
   * wrap this test may fail under otherwise valid circumstances.
   * Therefore, proactively update snd_congestion when wrap detected. */
  if (PREDICT_FALSE
      (seq_leq (tc->snd_congestion, tc->snd_una - tc->bytes_acked)
       && seq_gt (tc->snd_congestion, tc->snd_una)))
    tc->snd_congestion = tc->snd_una - 1;
}

static u8
tcp_should_fastrecover_sack (tcp_connection_t * tc)
{
  return (TCP_DUPACK_THRESHOLD - 1) * tc->snd_mss < tc->sack_sb.sacked_bytes;
}

static u8
tcp_should_fastrecover (tcp_connection_t * tc)
{
  return (tc->rcv_dupacks == TCP_DUPACK_THRESHOLD
	  || tcp_should_fastrecover_sack (tc));
}

/**
 * One function to rule them all ... and in the darkness bind them
 */
static void
tcp_cc_handle_event (tcp_connection_t * tc, u32 is_dack)
{
  u32 rxt_delivered;

  /*
   * Duplicate ACK. Check if we should enter fast recovery, or if already in
   * it account for the bytes that left the network.
   */
  if (is_dack)
    {
      ASSERT (tc->snd_una != tc->snd_una_max
	      || tc->sack_sb.last_sacked_bytes);

      tc->rcv_dupacks++;

      if (tc->rcv_dupacks > TCP_DUPACK_THRESHOLD && !tc->bytes_acked)
	{
	  ASSERT (tcp_in_fastrecovery (tc));
	  /* Pure duplicate ack. If some data got acked, it's handled lower */
	  tc->cc_algo->rcv_cong_ack (tc, TCP_CC_DUPACK);
	  return;
	}
      else if (tcp_should_fastrecover (tc))
	{
	  /* Things are already bad */
	  if (tcp_in_cong_recovery (tc))
	    {
	      tc->rcv_dupacks = 0;
	      goto partial_ack_test;
	    }

	  /* If of of the two conditions lower hold, reset dupacks because
	   * we're probably after timeout (RFC6582 heuristics).
	   * If Cumulative ack does not cover more than congestion threshold,
	   * and:
	   * 1) The following doesn't hold: The congestion window is greater
	   *    than SMSS bytes and the difference between highest_ack
	   *    and prev_highest_ack is at most 4*SMSS bytes
	   * 2) Echoed timestamp in the last non-dup ack does not equal the
	   *    stored timestamp
	   */
	  if (seq_leq (tc->snd_una, tc->snd_congestion)
	      && ((!(tc->cwnd > tc->snd_mss
		     && tc->bytes_acked <= 4 * tc->snd_mss))
		  || (tc->rcv_opts.tsecr != tc->tsecr_last_ack)))
	    {
	      tc->rcv_dupacks = 0;
	      return;
	    }

	  tcp_cc_init_congestion (tc);
	  tc->cc_algo->rcv_cong_ack (tc, TCP_CC_DUPACK);

	  /* The first segment MUST be retransmitted */
	  tcp_retransmit_first_unacked (tc);

	  /* Post retransmit update cwnd to ssthresh and account for the
	   * three segments that have left the network and should've been
	   * buffered at the receiver XXX */
	  tc->cwnd = tc->ssthresh + tc->rcv_dupacks * tc->snd_mss;
	  ASSERT (tc->cwnd >= tc->snd_mss);

	  /* If cwnd allows, send more data */
	  if (tcp_opts_sack_permitted (&tc->rcv_opts))
	    {
	      scoreboard_init_high_rxt (&tc->sack_sb,
					tc->snd_una + tc->snd_mss);
	      tcp_fast_retransmit_sack (tc);
	    }
	  else
	    {
	      tcp_fast_retransmit_no_sack (tc);
	    }

	  return;
	}
      else if (!tc->bytes_acked
	       || (tc->bytes_acked && !tcp_in_cong_recovery (tc)))
	{
	  tc->cc_algo->rcv_cong_ack (tc, TCP_CC_DUPACK);
	  return;
	}
      else
	goto partial_ack;
    }

partial_ack_test:

  if (!tc->bytes_acked)
    return;

partial_ack:
  /*
   * Legitimate ACK. 1) See if we can exit recovery
   */
  /* XXX limit this only to first partial ack? */
  tcp_retransmit_timer_update (tc);

  if (seq_geq (tc->snd_una, tc->snd_congestion))
    {
      /* If spurious return, we've already updated everything */
      if (tcp_cc_recover (tc))
	{
	  tc->tsecr_last_ack = tc->rcv_opts.tsecr;
	  return;
	}

      tc->snd_nxt = tc->snd_una_max;

      /* Treat as congestion avoidance ack */
      tc->cc_algo->rcv_ack (tc);
      tc->tsecr_last_ack = tc->rcv_opts.tsecr;
      return;
    }

  /*
   * Legitimate ACK. 2) If PARTIAL ACK try to retransmit
   */
  TCP_EVT_DBG (TCP_EVT_CC_PACK, tc);

  /* RFC6675: If the incoming ACK is a cumulative acknowledgment,
   * reset dupacks to 0 */
  tc->rcv_dupacks = 0;

  tcp_retransmit_first_unacked (tc);

  /* Post RTO timeout don't try anything fancy */
  if (tcp_in_recovery (tc))
    return;

  /* Remove retransmitted bytes that have been delivered */
  ASSERT (tc->bytes_acked + tc->sack_sb.snd_una_adv
	  >= tc->sack_sb.last_bytes_delivered
	  || (tc->flags & TCP_CONN_FINSNT));

  if (seq_lt (tc->snd_una, tc->sack_sb.high_rxt))
    {
      /* If we have sacks and we haven't gotten an ack beyond high_rxt,
       * remove sacked bytes delivered */
      rxt_delivered = tc->bytes_acked + tc->sack_sb.snd_una_adv
	- tc->sack_sb.last_bytes_delivered;
      ASSERT (tc->snd_rxt_bytes >= rxt_delivered);
      tc->snd_rxt_bytes -= rxt_delivered;
    }
  else
    {
      /* Either all retransmitted holes have been acked, or we're
       * "in the blind" and retransmitting segment by segment */
      tc->snd_rxt_bytes = 0;
    }

  tc->cc_algo->rcv_cong_ack (tc, TCP_CC_PARTIALACK);

  /*
   * Since this was a partial ack, try to retransmit some more data
   */
  tcp_fast_retransmit (tc);
}

void
tcp_cc_init (tcp_connection_t * tc)
{
  tc->cc_algo = tcp_cc_algo_get (TCP_CC_NEWRENO);
  tc->cc_algo->init (tc);
}

/**
 * Process incoming ACK
 */
static int
tcp_rcv_ack (tcp_connection_t * tc, vlib_buffer_t * b,
	     tcp_header_t * th, u32 * next, u32 * error)
{
  u32 prev_snd_wnd, prev_snd_una;
  u8 is_dack;

  TCP_EVT_DBG (TCP_EVT_CC_STAT, tc);

  /* If the ACK acks something not yet sent (SEG.ACK > SND.NXT) */
  if (PREDICT_FALSE (seq_gt (vnet_buffer (b)->tcp.ack_number, tc->snd_nxt)))
    {
      /* If we have outstanding data and this is within the window, accept it,
       * probably retransmit has timed out. Otherwise ACK segment and then
       * drop it */
      if (seq_gt (vnet_buffer (b)->tcp.ack_number, tc->snd_una_max))
	{
	  tcp_make_ack (tc, b);
	  *next = tcp_next_output (tc->c_is_ip4);
	  *error = TCP_ERROR_ACK_INVALID;
	  TCP_EVT_DBG (TCP_EVT_ACK_RCV_ERR, tc, 0,
		       vnet_buffer (b)->tcp.ack_number);
	  return -1;
	}

      TCP_EVT_DBG (TCP_EVT_ACK_RCV_ERR, tc, 2,
		   vnet_buffer (b)->tcp.ack_number);

      tc->snd_nxt = vnet_buffer (b)->tcp.ack_number;
      *error = TCP_ERROR_ACK_FUTURE;
    }

  /* If old ACK, probably it's an old dupack */
  if (PREDICT_FALSE (seq_lt (vnet_buffer (b)->tcp.ack_number, tc->snd_una)))
    {
      *error = TCP_ERROR_ACK_OLD;
      TCP_EVT_DBG (TCP_EVT_ACK_RCV_ERR, tc, 1,
		   vnet_buffer (b)->tcp.ack_number);
      if (tcp_in_fastrecovery (tc) && tc->rcv_dupacks == TCP_DUPACK_THRESHOLD)
	{
	  TCP_EVT_DBG (TCP_EVT_DUPACK_RCVD, tc);
	  tcp_cc_handle_event (tc, 1);
	}
      /* Don't drop yet */
      return 0;
    }

  /*
   * Looks okay, process feedback
   */

  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    tcp_rcv_sacks (tc, vnet_buffer (b)->tcp.ack_number);

  prev_snd_wnd = tc->snd_wnd;
  prev_snd_una = tc->snd_una;
  tcp_update_snd_wnd (tc, vnet_buffer (b)->tcp.seq_number,
		      vnet_buffer (b)->tcp.ack_number,
		      clib_net_to_host_u16 (th->window) << tc->snd_wscale);
  tc->bytes_acked = vnet_buffer (b)->tcp.ack_number - tc->snd_una;
  tc->snd_una = vnet_buffer (b)->tcp.ack_number + tc->sack_sb.snd_una_adv;
  tcp_validate_txf_size (tc, tc->bytes_acked);

  if (tc->bytes_acked)
    tcp_dequeue_acked (tc, vnet_buffer (b)->tcp.ack_number);

  TCP_EVT_DBG (TCP_EVT_ACK_RCVD, tc);

  /*
   * Check if we have congestion event
   */

  if (tcp_ack_is_cc_event (tc, b, prev_snd_wnd, prev_snd_una, &is_dack))
    {
      tcp_cc_handle_event (tc, is_dack);
      if (!tcp_in_cong_recovery (tc))
	return 0;
      *error = TCP_ERROR_ACK_DUP;
      TCP_EVT_DBG (TCP_EVT_DUPACK_RCVD, tc, 1);
      return vnet_buffer (b)->tcp.data_len ? 0 : -1;
    }

  /*
   * Update congestion control (slow start/congestion avoidance)
   */
  tcp_cc_update (tc, b);

  return 0;
}

static u8
tcp_sack_vector_is_sane (sack_block_t * sacks)
{
  int i;
  for (i = 1; i < vec_len (sacks); i++)
    {
      if (sacks[i - 1].end == sacks[i].start)
	return 0;
    }
  return 1;
}

/**
 * Build SACK list as per RFC2018.
 *
 * Makes sure the first block contains the segment that generated the current
 * ACK and the following ones are the ones most recently reported in SACK
 * blocks.
 *
 * @param tc TCP connection for which the SACK list is updated
 * @param start Start sequence number of the newest SACK block
 * @param end End sequence of the newest SACK block
 */
void
tcp_update_sack_list (tcp_connection_t * tc, u32 start, u32 end)
{
  sack_block_t *new_list = 0, *block = 0;
  int i;

  /* If the first segment is ooo add it to the list. Last write might've moved
   * rcv_nxt over the first segment. */
  if (seq_lt (tc->rcv_nxt, start))
    {
      vec_add2 (new_list, block, 1);
      block->start = start;
      block->end = end;
    }

  /* Find the blocks still worth keeping. */
  for (i = 0; i < vec_len (tc->snd_sacks); i++)
    {
      /* Discard if rcv_nxt advanced beyond current block */
      if (seq_leq (tc->snd_sacks[i].start, tc->rcv_nxt))
	continue;

      /* Merge or drop if segment overlapped by the new segment */
      if (block && (seq_geq (tc->snd_sacks[i].end, new_list[0].start)
		    && seq_leq (tc->snd_sacks[i].start, new_list[0].end)))
	{
	  if (seq_lt (tc->snd_sacks[i].start, new_list[0].start))
	    new_list[0].start = tc->snd_sacks[i].start;
	  if (seq_lt (new_list[0].end, tc->snd_sacks[i].end))
	    new_list[0].end = tc->snd_sacks[i].end;
	  continue;
	}

      /* Save to new SACK list if we have space. */
      if (vec_len (new_list) < TCP_MAX_SACK_BLOCKS)
	{
	  vec_add1 (new_list, tc->snd_sacks[i]);
	}
      else
	{
	  clib_warning ("sack discarded");
	}
    }

  ASSERT (vec_len (new_list) <= TCP_MAX_SACK_BLOCKS);

  /* Replace old vector with new one */
  vec_free (tc->snd_sacks);
  tc->snd_sacks = new_list;

  /* Segments should not 'touch' */
  ASSERT (tcp_sack_vector_is_sane (tc->snd_sacks));
}

/** Enqueue data for delivery to application */
always_inline int
tcp_session_enqueue_data (tcp_connection_t * tc, vlib_buffer_t * b,
			  u16 data_len)
{
  int written, error = TCP_ERROR_ENQUEUED;

  ASSERT (seq_geq (vnet_buffer (b)->tcp.seq_number, tc->rcv_nxt));

  /* Pure ACK. Update rcv_nxt and be done. */
  if (PREDICT_FALSE (data_len == 0))
    {
      return TCP_ERROR_PURE_ACK;
    }

  written = session_enqueue_stream_connection (&tc->connection, b, 0,
					       1 /* queue event */ , 1);

  TCP_EVT_DBG (TCP_EVT_INPUT, tc, 0, data_len, written);

  /* Update rcv_nxt */
  if (PREDICT_TRUE (written == data_len))
    {
      tc->rcv_nxt += written;
    }
  /* If more data written than expected, account for out-of-order bytes. */
  else if (written > data_len)
    {
      tc->rcv_nxt += written;

      /* Send ACK confirming the update */
      tc->flags |= TCP_CONN_SNDACK;
    }
  else if (written > 0)
    {
      /* We've written something but FIFO is probably full now */
      tc->rcv_nxt += written;

      /* Depending on how fast the app is, all remaining buffers in burst will
       * not be enqueued. Inform peer */
      tc->flags |= TCP_CONN_SNDACK;

      error = TCP_ERROR_PARTIALLY_ENQUEUED;
    }
  else
    {
      tc->flags |= TCP_CONN_SNDACK;
      return TCP_ERROR_FIFO_FULL;
    }

  /* Update SACK list if need be */
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    {
      /* Remove SACK blocks that have been delivered */
      tcp_update_sack_list (tc, tc->rcv_nxt, tc->rcv_nxt);
    }

  return error;
}

/** Enqueue out-of-order data */
always_inline int
tcp_session_enqueue_ooo (tcp_connection_t * tc, vlib_buffer_t * b,
			 u16 data_len)
{
  stream_session_t *s0;
  int rv, offset;

  ASSERT (seq_gt (vnet_buffer (b)->tcp.seq_number, tc->rcv_nxt));

  /* Pure ACK. Do nothing */
  if (PREDICT_FALSE (data_len == 0))
    {
      return TCP_ERROR_PURE_ACK;
    }

  /* Enqueue out-of-order data with relative offset */
  rv = session_enqueue_stream_connection (&tc->connection, b,
					  vnet_buffer (b)->tcp.seq_number -
					  tc->rcv_nxt, 0 /* queue event */ ,
					  0);

  /* Nothing written */
  if (rv)
    {
      TCP_EVT_DBG (TCP_EVT_INPUT, tc, 1, data_len, 0);
      return TCP_ERROR_FIFO_FULL;
    }

  TCP_EVT_DBG (TCP_EVT_INPUT, tc, 1, data_len, data_len);

  /* Update SACK list if in use */
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    {
      ooo_segment_t *newest;
      u32 start, end;

      s0 = session_get (tc->c_s_index, tc->c_thread_index);

      /* Get the newest segment from the fifo */
      newest = svm_fifo_newest_ooo_segment (s0->server_rx_fifo);
      if (newest)
	{
	  offset = ooo_segment_offset (s0->server_rx_fifo, newest);
	  ASSERT (offset <= vnet_buffer (b)->tcp.seq_number - tc->rcv_nxt);
	  start = tc->rcv_nxt + offset;
	  end = start + ooo_segment_length (s0->server_rx_fifo, newest);
	  tcp_update_sack_list (tc, start, end);
	  svm_fifo_newest_ooo_segment_reset (s0->server_rx_fifo);
	}
    }

  return TCP_ERROR_ENQUEUED;
}

/**
 * Check if ACK could be delayed. If ack can be delayed, it should return
 * true for a full frame. If we're always acking return 0.
 */
always_inline int
tcp_can_delack (tcp_connection_t * tc)
{
  /* Send ack if ... */
  if (TCP_ALWAYS_ACK
      /* just sent a rcv wnd 0 */
      || (tc->flags & TCP_CONN_SENT_RCV_WND0) != 0
      /* constrained to send ack */
      || (tc->flags & TCP_CONN_SNDACK) != 0
      /* we're almost out of tx wnd */
      || tcp_available_snd_space (tc) < 4 * tc->snd_mss)
    return 0;

  return 1;
}

static int
tcp_buffer_discard_bytes (vlib_buffer_t * b, u32 n_bytes_to_drop)
{
  u32 discard, first = b->current_length;
  vlib_main_t *vm = vlib_get_main ();

  /* Handle multi-buffer segments */
  if (n_bytes_to_drop > b->current_length)
    {
      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	return -1;
      do
	{
	  discard = clib_min (n_bytes_to_drop, b->current_length);
	  vlib_buffer_advance (b, discard);
	  b = vlib_get_buffer (vm, b->next_buffer);
	  n_bytes_to_drop -= discard;
	}
      while (n_bytes_to_drop);
      if (n_bytes_to_drop > first)
	b->total_length_not_including_first_buffer -= n_bytes_to_drop - first;
    }
  else
    vlib_buffer_advance (b, n_bytes_to_drop);
  vnet_buffer (b)->tcp.data_len -= n_bytes_to_drop;
  return 0;
}

static int
tcp_segment_rcv (tcp_main_t * tm, tcp_connection_t * tc, vlib_buffer_t * b,
		 u32 * next0)
{
  u32 error = 0, n_bytes_to_drop, n_data_bytes;

  vlib_buffer_advance (b, vnet_buffer (b)->tcp.data_offset);
  n_data_bytes = vnet_buffer (b)->tcp.data_len;
  ASSERT (n_data_bytes);

  /* Handle out-of-order data */
  if (PREDICT_FALSE (vnet_buffer (b)->tcp.seq_number != tc->rcv_nxt))
    {
      /* Old sequence numbers allowed through because they overlapped
       * the rx window */
      if (seq_lt (vnet_buffer (b)->tcp.seq_number, tc->rcv_nxt))
	{
	  error = TCP_ERROR_SEGMENT_OLD;
	  *next0 = TCP_NEXT_DROP;

	  /* Completely in the past (possible retransmit) */
	  if (seq_leq (vnet_buffer (b)->tcp.seq_end, tc->rcv_nxt))
	    {
	      /* Ack retransmissions since we may not have any data to send */
	      tcp_make_ack (tc, b);
	      *next0 = tcp_next_output (tc->c_is_ip4);
	      goto done;
	    }

	  /* Chop off the bytes in the past */
	  n_bytes_to_drop = tc->rcv_nxt - vnet_buffer (b)->tcp.seq_number;
	  n_data_bytes -= n_bytes_to_drop;
	  vnet_buffer (b)->tcp.seq_number = tc->rcv_nxt;
	  if (tcp_buffer_discard_bytes (b, n_bytes_to_drop))
	    goto done;

	  goto in_order;
	}

      error = tcp_session_enqueue_ooo (tc, b, n_data_bytes);

      /* N.B. Should not filter burst of dupacks. Two issues 1) dupacks open
       * cwnd on remote peer when congested 2) acks leaving should have the
       * latest rcv_wnd since the burst may eaten up all of it, so only the
       * old ones could be filtered.
       */

      /* RFC2581: Send DUPACK for fast retransmit */
      tcp_make_ack (tc, b);
      *next0 = tcp_next_output (tc->c_is_ip4);

      /* Mark as DUPACK. We may filter these in output if
       * the burst fills the holes. */
      if (n_data_bytes)
	vnet_buffer (b)->tcp.flags = TCP_BUF_FLAG_DUPACK;

      TCP_EVT_DBG (TCP_EVT_DUPACK_SENT, tc);
      goto done;
    }

in_order:

  /* In order data, enqueue. Fifo figures out by itself if any out-of-order
   * segments can be enqueued after fifo tail offset changes. */
  error = tcp_session_enqueue_data (tc, b, n_data_bytes);

  /* Check if ACK can be delayed */
  if (tcp_can_delack (tc))
    {
      if (!tcp_timer_is_active (tc, TCP_TIMER_DELACK))
	tcp_timer_set (tc, TCP_TIMER_DELACK, TCP_DELACK_TIME);
      goto done;
    }

  *next0 = tcp_next_output (tc->c_is_ip4);
  tcp_make_ack (tc, b);

done:
  return error;
}

typedef struct
{
  tcp_header_t tcp_header;
  tcp_connection_t tcp_connection;
} tcp_rx_trace_t;

u8 *
format_tcp_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tcp_rx_trace_t *t = va_arg (*args, tcp_rx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%U\n%U%U",
	      format_tcp_header, &t->tcp_header, 128,
	      format_white_space, indent,
	      format_tcp_connection, &t->tcp_connection, 1);

  return s;
}

u8 *
format_tcp_rx_trace_short (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tcp_rx_trace_t *t = va_arg (*args, tcp_rx_trace_t *);

  s = format (s, "%d -> %d (%U)",
	      clib_net_to_host_u16 (t->tcp_header.src_port),
	      clib_net_to_host_u16 (t->tcp_header.dst_port), format_tcp_state,
	      t->tcp_connection.state);

  return s;
}

void
tcp_set_rx_trace_data (tcp_rx_trace_t * t0, tcp_connection_t * tc0,
		       tcp_header_t * th0, vlib_buffer_t * b0, u8 is_ip4)
{
  if (tc0)
    {
      clib_memcpy (&t0->tcp_connection, tc0, sizeof (t0->tcp_connection));
    }
  else
    {
      th0 = tcp_buffer_hdr (b0);
    }
  clib_memcpy (&t0->tcp_header, th0, sizeof (t0->tcp_header));
}

always_inline void
tcp_node_inc_counter (vlib_main_t * vm, u32 tcp4_node, u32 tcp6_node,
		      u8 is_ip4, u8 evt, u8 val)
{
  if (PREDICT_TRUE (!val))
    return;

  if (is_ip4)
    vlib_node_increment_counter (vm, tcp4_node, evt, val);
  else
    vlib_node_increment_counter (vm, tcp6_node, evt, val);
}

always_inline uword
tcp46_established_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->thread_index, errors = 0;
  tcp_main_t *tm = vnet_get_tcp_main ();
  u8 is_fin = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  tcp_header_t *th0 = 0;
	  tcp_connection_t *tc0;
	  u32 next0 = TCP_ESTABLISHED_NEXT_DROP, error0 = TCP_ERROR_ENQUEUED;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  tc0 = tcp_connection_get (vnet_buffer (b0)->tcp.connection_index,
				    my_thread_index);

	  if (PREDICT_FALSE (tc0 == 0))
	    {
	      error0 = TCP_ERROR_INVALID_CONNECTION;
	      goto done;
	    }

	  th0 = tcp_buffer_hdr (b0);
	  /* N.B. buffer is rewritten if segment is ooo. Thus, th0 becomes a
	   * dangling reference. */
	  is_fin = tcp_is_fin (th0);

	  /* SYNs, FINs and data consume sequence numbers */
	  vnet_buffer (b0)->tcp.seq_end = vnet_buffer (b0)->tcp.seq_number
	    + tcp_is_syn (th0) + is_fin + vnet_buffer (b0)->tcp.data_len;

	  /* TODO header prediction fast path */

	  /* 1-4: check SEQ, RST, SYN */
	  if (PREDICT_FALSE (tcp_segment_validate (vm, tc0, b0, th0, &next0)))
	    {
	      error0 = TCP_ERROR_SEGMENT_INVALID;
	      TCP_EVT_DBG (TCP_EVT_SEG_INVALID, tc0,
			   vnet_buffer (b0)->tcp.seq_number,
			   vnet_buffer (b0)->tcp.seq_end);
	      goto done;
	    }

	  /* 5: check the ACK field  */
	  if (tcp_rcv_ack (tc0, b0, th0, &next0, &error0))
	    goto done;

	  /* 6: check the URG bit TODO */

	  /* 7: process the segment text */
	  if (vnet_buffer (b0)->tcp.data_len)
	    error0 = tcp_segment_rcv (tm, tc0, b0, &next0);

	  /* 8: check the FIN bit */
	  if (PREDICT_FALSE (is_fin))
	    {
	      /* Enter CLOSE-WAIT and notify session. To avoid lingering
	       * in CLOSE-WAIT, set timer (reuse WAITCLOSE). */
	      /* Account for the FIN if nothing else was received */
	      if (vnet_buffer (b0)->tcp.data_len == 0)
		tc0->rcv_nxt += 1;
	      tcp_make_ack (tc0, b0);
	      next0 = tcp_next_output (tc0->c_is_ip4);
	      tc0->state = TCP_STATE_CLOSE_WAIT;
	      stream_session_disconnect_notify (&tc0->connection);
	      tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_CLOSEWAIT_TIME);
	      TCP_EVT_DBG (TCP_EVT_FIN_RCVD, tc0);
	    }

	done:
	  b0->error = node->errors[error0];
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      tcp_rx_trace_t *t0 =
		vlib_add_trace (vm, node, b0, sizeof (*t0));
	      tcp_set_rx_trace_data (t0, tc0, th0, b0, is_ip4);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  errors = session_manager_flush_enqueue_events (TRANSPORT_PROTO_TCP,
						 my_thread_index);
  tcp_node_inc_counter (vm, is_ip4, tcp4_established_node.index,
			tcp6_established_node.index,
			TCP_ERROR_EVENT_FIFO_FULL, errors);
  tcp_flush_frame_to_output (vm, my_thread_index, is_ip4);

  return from_frame->n_vectors;
}

static uword
tcp4_established (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  return tcp46_established_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
tcp6_established (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  return tcp46_established_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_established_node) =
{
  .function = tcp4_established,
  .name = "tcp4-established",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_ESTABLISHED_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_ESTABLISHED_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_established_node, tcp4_established);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_established_node) =
{
  .function = tcp6_established,
  .name = "tcp6-established",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_ESTABLISHED_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_ESTABLISHED_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */


VLIB_NODE_FUNCTION_MULTIARCH (tcp6_established_node, tcp6_established);

vlib_node_registration_t tcp4_syn_sent_node;
vlib_node_registration_t tcp6_syn_sent_node;

static u8
tcp_lookup_is_valid (tcp_connection_t * tc, tcp_header_t * hdr)
{
  transport_connection_t *tmp = 0;
  u64 handle;

  if (!tc)
    return 1;

  u8 is_valid = (tc->c_lcl_port == hdr->dst_port
		 && (tc->state == TCP_STATE_LISTEN
		     || tc->c_rmt_port == hdr->src_port));

  if (!is_valid)
    {
      handle = session_lookup_half_open_handle (&tc->connection);
      tmp = session_lookup_half_open_connection (handle & 0xFFFFFFFF,
						 tc->c_proto, tc->c_is_ip4);

      if (tmp)
	{
	  if (tmp->lcl_port == hdr->dst_port
	      && tmp->rmt_port == hdr->src_port)
	    {
	      TCP_DBG ("half-open is valid!");
	    }
	}
    }
  return is_valid;
}

/**
 * Lookup transport connection
 */
static tcp_connection_t *
tcp_lookup_connection (u32 fib_index, vlib_buffer_t * b, u8 thread_index,
		       u8 is_ip4)
{
  tcp_header_t *tcp;
  transport_connection_t *tconn;
  tcp_connection_t *tc;
  if (is_ip4)
    {
      ip4_header_t *ip4;
      ip4 = vlib_buffer_get_current (b);
      tcp = ip4_next_header (ip4);
      tconn = session_lookup_connection_wt4 (fib_index,
					     &ip4->dst_address,
					     &ip4->src_address,
					     tcp->dst_port,
					     tcp->src_port,
					     TRANSPORT_PROTO_TCP,
					     thread_index);
      tc = tcp_get_connection_from_transport (tconn);
      ASSERT (tcp_lookup_is_valid (tc, tcp));
    }
  else
    {
      ip6_header_t *ip6;
      ip6 = vlib_buffer_get_current (b);
      tcp = ip6_next_header (ip6);
      tconn = session_lookup_connection_wt6 (fib_index,
					     &ip6->dst_address,
					     &ip6->src_address,
					     tcp->dst_port,
					     tcp->src_port,
					     TRANSPORT_PROTO_TCP,
					     thread_index);
      tc = tcp_get_connection_from_transport (tconn);
      ASSERT (tcp_lookup_is_valid (tc, tcp));
    }
  return tc;
}

always_inline uword
tcp46_syn_sent_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * from_frame, int is_ip4)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->thread_index, errors = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, ack0, seq0;
	  vlib_buffer_t *b0;
	  tcp_rx_trace_t *t0;
	  tcp_header_t *tcp0 = 0;
	  tcp_connection_t *tc0;
	  tcp_connection_t *new_tc0;
	  u32 next0 = TCP_SYN_SENT_NEXT_DROP, error0 = TCP_ERROR_ENQUEUED;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  tc0 =
	    tcp_half_open_connection_get (vnet_buffer (b0)->
					  tcp.connection_index);
	  if (PREDICT_FALSE (tc0 == 0))
	    {
	      error0 = TCP_ERROR_INVALID_CONNECTION;
	      goto drop;
	    }

	  /* Half-open completed recently but the connection was't removed
	   * yet by the owning thread */
	  if (PREDICT_FALSE (tc0->flags & TCP_CONN_HALF_OPEN_DONE))
	    {
	      /* Make sure the connection actually exists */
	      ASSERT (tcp_lookup_connection (tc0->c_fib_index, b0,
					     my_thread_index, is_ip4));
	      goto drop;
	    }

	  ack0 = vnet_buffer (b0)->tcp.ack_number;
	  seq0 = vnet_buffer (b0)->tcp.seq_number;
	  tcp0 = tcp_buffer_hdr (b0);

	  /* Crude check to see if the connection handle does not match
	   * the packet. Probably connection just switched to established */
	  if (PREDICT_FALSE (tcp0->dst_port != tc0->c_lcl_port
			     || tcp0->src_port != tc0->c_rmt_port))
	    goto drop;

	  if (PREDICT_FALSE
	      (!tcp_ack (tcp0) && !tcp_rst (tcp0) && !tcp_syn (tcp0)))
	    goto drop;

	  /* SYNs, FINs and data consume sequence numbers */
	  vnet_buffer (b0)->tcp.seq_end = seq0 + tcp_is_syn (tcp0)
	    + tcp_is_fin (tcp0) + vnet_buffer (b0)->tcp.data_len;

	  /*
	   *  1. check the ACK bit
	   */

	  /*
	   *   If the ACK bit is set
	   *     If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless
	   *     the RST bit is set, if so drop the segment and return)
	   *       <SEQ=SEG.ACK><CTL=RST>
	   *     and discard the segment.  Return.
	   *     If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
	   */
	  if (tcp_ack (tcp0))
	    {
	      if (seq_leq (ack0, tc0->iss) || seq_gt (ack0, tc0->snd_nxt))
		{
		  clib_warning ("ack not in rcv wnd");
		  if (!tcp_rst (tcp0))
		    tcp_send_reset_w_pkt (tc0, b0, is_ip4);
		  goto drop;
		}

	      /* Make sure ACK is valid */
	      if (seq_gt (tc0->snd_una, ack0))
		{
		  clib_warning ("ack invalid");
		  goto drop;
		}
	    }

	  /*
	   * 2. check the RST bit
	   */

	  if (tcp_rst (tcp0))
	    {
	      /* If ACK is acceptable, signal client that peer is not
	       * willing to accept connection and drop connection*/
	      if (tcp_ack (tcp0))
		tcp_connection_reset (tc0);
	      goto drop;
	    }

	  /*
	   * 3. check the security and precedence (skipped)
	   */

	  /*
	   * 4. check the SYN bit
	   */

	  /* No SYN flag. Drop. */
	  if (!tcp_syn (tcp0))
	    {
	      clib_warning ("not synack");
	      goto drop;
	    }

	  /* Parse options */
	  if (tcp_options_parse (tcp0, &tc0->rcv_opts))
	    {
	      clib_warning ("options parse fail");
	      goto drop;
	    }

	  /* Valid SYN or SYN-ACK. Move connection from half-open pool to
	   * current thread pool. */
	  pool_get (tm->connections[my_thread_index], new_tc0);
	  clib_memcpy (new_tc0, tc0, sizeof (*new_tc0));
	  new_tc0->c_c_index = new_tc0 - tm->connections[my_thread_index];
	  new_tc0->c_thread_index = my_thread_index;
	  new_tc0->rcv_nxt = vnet_buffer (b0)->tcp.seq_end;
	  new_tc0->irs = seq0;
	  new_tc0->timers[TCP_TIMER_ESTABLISH] = TCP_TIMER_HANDLE_INVALID;
	  new_tc0->timers[TCP_TIMER_RETRANSMIT_SYN] =
	    TCP_TIMER_HANDLE_INVALID;

	  /* If this is not the owning thread, wait for syn retransmit to
	   * expire and cleanup then */
	  if (tcp_half_open_connection_cleanup (tc0))
	    tc0->flags |= TCP_CONN_HALF_OPEN_DONE;

	  if (tcp_opts_tstamp (&new_tc0->rcv_opts))
	    {
	      new_tc0->tsval_recent = new_tc0->rcv_opts.tsval;
	      new_tc0->tsval_recent_age = tcp_time_now ();
	    }

	  if (tcp_opts_wscale (&new_tc0->rcv_opts))
	    new_tc0->snd_wscale = new_tc0->rcv_opts.wscale;

	  /* RFC1323: SYN and SYN-ACK wnd not scaled */
	  new_tc0->snd_wnd = clib_net_to_host_u16 (tcp0->window);
	  new_tc0->snd_wl1 = seq0;
	  new_tc0->snd_wl2 = ack0;

	  tcp_connection_init_vars (new_tc0);

	  /* SYN-ACK: See if we can switch to ESTABLISHED state */
	  if (PREDICT_TRUE (tcp_ack (tcp0)))
	    {
	      /* Our SYN is ACKed: we have iss < ack = snd_una */

	      /* TODO Dequeue acknowledged segments if we support Fast Open */
	      new_tc0->snd_una = ack0;
	      new_tc0->state = TCP_STATE_ESTABLISHED;

	      /* Make sure las is initialized for the wnd computation */
	      new_tc0->rcv_las = new_tc0->rcv_nxt;

	      /* Notify app that we have connection. If session layer can't
	       * allocate session send reset */
	      if (session_stream_connect_notify (&new_tc0->connection, 0))
		{
		  clib_warning ("connect notify fail");
		  tcp_send_reset_w_pkt (new_tc0, b0, is_ip4);
		  tcp_connection_cleanup (new_tc0);
		  goto drop;
		}

	      /* Make sure after data segment processing ACK is sent */
	      new_tc0->flags |= TCP_CONN_SNDACK;

	      /* Update rtt with the syn-ack sample */
	      tcp_update_rtt (new_tc0, vnet_buffer (b0)->tcp.ack_number);
	      TCP_EVT_DBG (TCP_EVT_SYNACK_RCVD, new_tc0);
	    }
	  /* SYN: Simultaneous open. Change state to SYN-RCVD and send SYN-ACK */
	  else
	    {
	      new_tc0->state = TCP_STATE_SYN_RCVD;

	      /* Notify app that we have connection */
	      if (session_stream_connect_notify (&new_tc0->connection, 0))
		{
		  tcp_connection_cleanup (new_tc0);
		  tcp_send_reset_w_pkt (tc0, b0, is_ip4);
		  TCP_EVT_DBG (TCP_EVT_RST_SENT, tc0);
		  goto drop;
		}

	      tc0->rtt_ts = 0;
	      tcp_init_snd_vars (tc0);
	      tcp_make_synack (new_tc0, b0);
	      next0 = tcp_next_output (is_ip4);

	      goto drop;
	    }

	  /* Read data, if any */
	  if (PREDICT_FALSE (vnet_buffer (b0)->tcp.data_len))
	    {
	      ASSERT (0);
	      error0 = tcp_segment_rcv (tm, new_tc0, b0, &next0);
	      if (error0 == TCP_ERROR_PURE_ACK)
		error0 = TCP_ERROR_SYN_ACKS_RCVD;
	    }
	  else
	    {
	      tcp_make_ack (new_tc0, b0);
	      next0 = tcp_next_output (new_tc0->c_is_ip4);
	    }

	drop:

	  b0->error = error0 ? node->errors[error0] : 0;
	  if (PREDICT_FALSE
	      ((b0->flags & VLIB_BUFFER_IS_TRACED) && tcp0 != 0))
	    {
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      clib_memcpy (&t0->tcp_header, tcp0, sizeof (t0->tcp_header));
	      clib_memcpy (&t0->tcp_connection, tc0,
			   sizeof (t0->tcp_connection));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  errors = session_manager_flush_enqueue_events (TRANSPORT_PROTO_TCP,
						 my_thread_index);
  tcp_node_inc_counter (vm, is_ip4, tcp4_syn_sent_node.index,
			tcp6_syn_sent_node.index,
			TCP_ERROR_EVENT_FIFO_FULL, errors);
  return from_frame->n_vectors;
}

static uword
tcp4_syn_sent (vlib_main_t * vm, vlib_node_runtime_t * node,
	       vlib_frame_t * from_frame)
{
  return tcp46_syn_sent_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
tcp6_syn_sent_rcv (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * from_frame)
{
  return tcp46_syn_sent_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_syn_sent_node) =
{
  .function = tcp4_syn_sent,
  .name = "tcp4-syn-sent",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_SYN_SENT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_SYN_SENT_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_syn_sent_node, tcp4_syn_sent);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_syn_sent_node) =
{
  .function = tcp6_syn_sent_rcv,
  .name = "tcp6-syn-sent",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_SYN_SENT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_SYN_SENT_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_syn_sent_node, tcp6_syn_sent_rcv);

vlib_node_registration_t tcp4_rcv_process_node;
vlib_node_registration_t tcp6_rcv_process_node;

/**
 * Handles reception for all states except LISTEN, SYN-SENT and ESTABLISHED
 * as per RFC793 p. 64
 */
always_inline uword
tcp46_rcv_process_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * from_frame, int is_ip4)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->thread_index, errors = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  tcp_header_t *tcp0 = 0;
	  tcp_connection_t *tc0;
	  u32 next0 = TCP_RCV_PROCESS_NEXT_DROP, error0 = TCP_ERROR_ENQUEUED;
	  u8 is_fin0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  tc0 = tcp_connection_get (vnet_buffer (b0)->tcp.connection_index,
				    my_thread_index);
	  if (PREDICT_FALSE (tc0 == 0))
	    {
	      error0 = TCP_ERROR_INVALID_CONNECTION;
	      goto drop;
	    }

	  tcp0 = tcp_buffer_hdr (b0);
	  is_fin0 = tcp_is_fin (tcp0);

	  /* SYNs, FINs and data consume sequence numbers */
	  vnet_buffer (b0)->tcp.seq_end = vnet_buffer (b0)->tcp.seq_number
	    + tcp_is_syn (tcp0) + is_fin0 + vnet_buffer (b0)->tcp.data_len;

	  if (CLIB_DEBUG)
	    {
	      tcp_connection_t *tmp;
	      tmp =
		tcp_lookup_connection (tc0->c_fib_index, b0, my_thread_index,
				       is_ip4);
	      if (tmp->state != tc0->state)
		{
		  clib_warning ("state changed");
		  ASSERT (0);
		  goto drop;
		}
	    }

	  /*
	   * Special treatment for CLOSED
	   */
	  switch (tc0->state)
	    {
	    case TCP_STATE_CLOSED:
	      goto drop;
	      break;
	    }

	  /*
	   * For all other states (except LISTEN)
	   */

	  /* 1-4: check SEQ, RST, SYN */
	  if (PREDICT_FALSE (tcp_segment_validate (vm, tc0, b0, tcp0,
						   &next0)))
	    {
	      error0 = TCP_ERROR_SEGMENT_INVALID;
	      goto drop;
	    }

	  /* 5: check the ACK field  */
	  switch (tc0->state)
	    {
	    case TCP_STATE_SYN_RCVD:
	      /*
	       * If the segment acknowledgment is not acceptable, form a
	       * reset segment,
	       *  <SEQ=SEG.ACK><CTL=RST>
	       * and send it.
	       */
	      if (!tcp_rcv_ack_is_acceptable (tc0, b0))
		{
		  TCP_DBG ("connection not accepted");
		  tcp_send_reset_w_pkt (tc0, b0, is_ip4);
		  goto drop;
		}

	      /* Update rtt and rto */
	      tcp_update_rtt (tc0, vnet_buffer (b0)->tcp.ack_number);

	      /* Switch state to ESTABLISHED */
	      tc0->state = TCP_STATE_ESTABLISHED;

	      /* Initialize session variables */
	      tc0->snd_una = vnet_buffer (b0)->tcp.ack_number;
	      tc0->snd_wnd = clib_net_to_host_u16 (tcp0->window)
		<< tc0->rcv_opts.wscale;
	      tc0->snd_wl1 = vnet_buffer (b0)->tcp.seq_number;
	      tc0->snd_wl2 = vnet_buffer (b0)->tcp.ack_number;
	      stream_session_accept_notify (&tc0->connection);

	      /* Reset SYN-ACK retransmit and SYN_RCV establish timers */
	      tcp_retransmit_timer_reset (tc0);
	      tcp_timer_reset (tc0, TCP_TIMER_ESTABLISH);
	      TCP_EVT_DBG (TCP_EVT_STATE_CHANGE, tc0);
	      break;
	    case TCP_STATE_ESTABLISHED:
	      /* We can get packets in established state here because they
	       * were enqueued before state change */
	      if (tcp_rcv_ack (tc0, b0, tcp0, &next0, &error0))
		goto drop;

	      break;
	    case TCP_STATE_FIN_WAIT_1:
	      /* In addition to the processing for the ESTABLISHED state, if
	       * our FIN is now acknowledged then enter FIN-WAIT-2 and
	       * continue processing in that state. */
	      if (tcp_rcv_ack (tc0, b0, tcp0, &next0, &error0))
		goto drop;

	      /* Still have to send the FIN */
	      if (tc0->flags & TCP_CONN_FINPNDG)
		{
		  /* TX fifo finally drained */
		  if (!stream_session_tx_fifo_max_dequeue (&tc0->connection))
		    tcp_send_fin (tc0);
		}
	      /* If FIN is ACKed */
	      else if (tc0->snd_una == tc0->snd_una_max)
		{
		  tc0->state = TCP_STATE_FIN_WAIT_2;
		  TCP_EVT_DBG (TCP_EVT_STATE_CHANGE, tc0);

		  /* Stop all retransmit timers because we have nothing more
		   * to send. Enable waitclose though because we're willing to
		   * wait for peer's FIN but not indefinitely. */
		  tcp_connection_timers_reset (tc0);
		  tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_2MSL_TIME);
		}
	      break;
	    case TCP_STATE_FIN_WAIT_2:
	      /* In addition to the processing for the ESTABLISHED state, if
	       * the retransmission queue is empty, the user's CLOSE can be
	       * acknowledged ("ok") but do not delete the TCB. */
	      if (tcp_rcv_ack (tc0, b0, tcp0, &next0, &error0))
		goto drop;
	      break;
	    case TCP_STATE_CLOSE_WAIT:
	      /* Do the same processing as for the ESTABLISHED state. */
	      if (tcp_rcv_ack (tc0, b0, tcp0, &next0, &error0))
		goto drop;
	      break;
	    case TCP_STATE_CLOSING:
	      /* In addition to the processing for the ESTABLISHED state, if
	       * the ACK acknowledges our FIN then enter the TIME-WAIT state,
	       * otherwise ignore the segment. */
	      if (tcp_rcv_ack (tc0, b0, tcp0, &next0, &error0))
		goto drop;

	      tc0->state = TCP_STATE_TIME_WAIT;
	      TCP_EVT_DBG (TCP_EVT_STATE_CHANGE, tc0);
	      tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_TIMEWAIT_TIME);
	      goto drop;

	      break;
	    case TCP_STATE_LAST_ACK:
	      /* The only thing that [should] arrive in this state is an
	       * acknowledgment of our FIN. If our FIN is now acknowledged,
	       * delete the TCB, enter the CLOSED state, and return. */

	      if (!tcp_rcv_ack_is_acceptable (tc0, b0))
		{
		  error0 = TCP_ERROR_ACK_INVALID;
		  goto drop;
		}

	      tc0->snd_una = vnet_buffer (b0)->tcp.ack_number;
	      /* Apparently our ACK for the peer's FIN was lost */
	      if (is_fin0 && tc0->snd_una != tc0->snd_una_max)
		{
		  tcp_send_fin (tc0);
		  goto drop;
		}

	      tc0->state = TCP_STATE_CLOSED;
	      TCP_EVT_DBG (TCP_EVT_STATE_CHANGE, tc0);
	      tcp_connection_timers_reset (tc0);

	      /* Don't delete the connection/session yet. Instead, wait a
	       * reasonable amount of time until the pipes are cleared. In
	       * particular, this makes sure that we won't have dead sessions
	       * when processing events on the tx path */
	      tcp_timer_set (tc0, TCP_TIMER_WAITCLOSE, TCP_CLEANUP_TIME);

	      goto drop;

	      break;
	    case TCP_STATE_TIME_WAIT:
	      /* The only thing that can arrive in this state is a
	       * retransmission of the remote FIN. Acknowledge it, and restart
	       * the 2 MSL timeout. */

	      if (tcp_rcv_ack (tc0, b0, tcp0, &next0, &error0))
		goto drop;

	      tcp_make_ack (tc0, b0);
	      next0 = tcp_next_output (is_ip4);
	      tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_TIMEWAIT_TIME);

	      goto drop;

	      break;
	    default:
	      ASSERT (0);
	    }

	  /* 6: check the URG bit TODO */

	  /* 7: process the segment text */
	  switch (tc0->state)
	    {
	    case TCP_STATE_ESTABLISHED:
	    case TCP_STATE_FIN_WAIT_1:
	    case TCP_STATE_FIN_WAIT_2:
	      if (vnet_buffer (b0)->tcp.data_len)
		error0 = tcp_segment_rcv (tm, tc0, b0, &next0);
	      else if (is_fin0)
		tc0->rcv_nxt += 1;
	      break;
	    case TCP_STATE_CLOSE_WAIT:
	    case TCP_STATE_CLOSING:
	    case TCP_STATE_LAST_ACK:
	    case TCP_STATE_TIME_WAIT:
	      /* This should not occur, since a FIN has been received from the
	       * remote side.  Ignore the segment text. */
	      break;
	    }

	  /* 8: check the FIN bit */
	  if (!is_fin0)
	    goto drop;

	  switch (tc0->state)
	    {
	    case TCP_STATE_ESTABLISHED:
	    case TCP_STATE_SYN_RCVD:
	      /* Send FIN-ACK notify app and enter CLOSE-WAIT */
	      tcp_connection_timers_reset (tc0);
	      tcp_make_fin (tc0, b0);
	      tc0->snd_nxt += 1;
	      next0 = tcp_next_output (tc0->c_is_ip4);
	      stream_session_disconnect_notify (&tc0->connection);
	      tc0->state = TCP_STATE_CLOSE_WAIT;
	      TCP_EVT_DBG (TCP_EVT_STATE_CHANGE, tc0);
	      break;
	    case TCP_STATE_CLOSE_WAIT:
	    case TCP_STATE_CLOSING:
	    case TCP_STATE_LAST_ACK:
	      /* move along .. */
	      break;
	    case TCP_STATE_FIN_WAIT_1:
	      tc0->state = TCP_STATE_CLOSING;
	      tcp_make_ack (tc0, b0);
	      next0 = tcp_next_output (is_ip4);
	      TCP_EVT_DBG (TCP_EVT_STATE_CHANGE, tc0);
	      /* Wait for ACK but not forever */
	      tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_2MSL_TIME);
	      break;
	    case TCP_STATE_FIN_WAIT_2:
	      /* Got FIN, send ACK! Be more aggressive with resource cleanup */
	      tc0->state = TCP_STATE_TIME_WAIT;
	      tcp_connection_timers_reset (tc0);
	      tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_TIMEWAIT_TIME);
	      tcp_make_ack (tc0, b0);
	      next0 = tcp_next_output (is_ip4);
	      TCP_EVT_DBG (TCP_EVT_STATE_CHANGE, tc0);
	      break;
	    case TCP_STATE_TIME_WAIT:
	      /* Remain in the TIME-WAIT state. Restart the time-wait
	       * timeout.
	       */
	      tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_TIMEWAIT_TIME);
	      break;
	    }
	  TCP_EVT_DBG (TCP_EVT_FIN_RCVD, tc0);

	drop:
	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      tcp_rx_trace_t *t0 =
		vlib_add_trace (vm, node, b0, sizeof (*t0));
	      tcp_set_rx_trace_data (t0, tc0, tcp0, b0, is_ip4);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  errors = session_manager_flush_enqueue_events (TRANSPORT_PROTO_TCP,
						 my_thread_index);
  tcp_node_inc_counter (vm, is_ip4, tcp4_rcv_process_node.index,
			tcp6_rcv_process_node.index,
			TCP_ERROR_EVENT_FIFO_FULL, errors);

  return from_frame->n_vectors;
}

static uword
tcp4_rcv_process (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  return tcp46_rcv_process_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
tcp6_rcv_process (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * from_frame)
{
  return tcp46_rcv_process_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_rcv_process_node) =
{
  .function = tcp4_rcv_process,
  .name = "tcp4-rcv-process",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_RCV_PROCESS_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_RCV_PROCESS_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_rcv_process_node, tcp4_rcv_process);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_rcv_process_node) =
{
  .function = tcp6_rcv_process,
  .name = "tcp6-rcv-process",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_RCV_PROCESS_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_RCV_PROCESS_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_rcv_process_node, tcp6_rcv_process);

vlib_node_registration_t tcp4_listen_node;
vlib_node_registration_t tcp6_listen_node;

/**
 * LISTEN state processing as per RFC 793 p. 65
 */
always_inline uword
tcp46_listen_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->thread_index;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  tcp_rx_trace_t *t0;
	  tcp_header_t *th0 = 0;
	  tcp_connection_t *lc0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  tcp_connection_t *child0;
	  u32 error0 = TCP_ERROR_SYNS_RCVD, next0 = TCP_LISTEN_NEXT_DROP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  lc0 = tcp_listener_get (vnet_buffer (b0)->tcp.connection_index);

	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      th0 = ip4_next_header (ip40);
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      th0 = ip6_next_header (ip60);
	    }

	  /* Create child session. For syn-flood protection use filter */

	  /* 1. first check for an RST: handled in dispatch */
	  /* if (tcp_rst (th0))
	     goto drop; */

	  /* 2. second check for an ACK: handled in dispatch */
	  /* if (tcp_ack (th0))
	     {
	     tcp_send_reset (b0, is_ip4);
	     goto drop;
	     } */

	  /* 3. check for a SYN (did that already) */

	  /* Make sure connection wasn't just created */
	  child0 =
	    tcp_lookup_connection (lc0->c_fib_index, b0, my_thread_index,
				   is_ip4);
	  if (PREDICT_FALSE (child0->state != TCP_STATE_LISTEN))
	    {
	      error0 = TCP_ERROR_CREATE_EXISTS;
	      goto drop;
	    }

	  /* Create child session and send SYN-ACK */
	  child0 = tcp_connection_new (my_thread_index);
	  child0->c_lcl_port = th0->dst_port;
	  child0->c_rmt_port = th0->src_port;
	  child0->c_is_ip4 = is_ip4;
	  child0->state = TCP_STATE_SYN_RCVD;

	  if (is_ip4)
	    {
	      child0->c_lcl_ip4.as_u32 = ip40->dst_address.as_u32;
	      child0->c_rmt_ip4.as_u32 = ip40->src_address.as_u32;
	    }
	  else
	    {
	      clib_memcpy (&child0->c_lcl_ip6, &ip60->dst_address,
			   sizeof (ip6_address_t));
	      clib_memcpy (&child0->c_rmt_ip6, &ip60->src_address,
			   sizeof (ip6_address_t));
	    }

	  if (stream_session_accept (&child0->connection, lc0->c_s_index,
				     0 /* notify */ ))
	    {
	      clib_warning ("session accept fail");
	      tcp_connection_cleanup (child0);
	      error0 = TCP_ERROR_CREATE_SESSION_FAIL;
	      goto drop;
	    }

	  if (tcp_options_parse (th0, &child0->rcv_opts))
	    {
	      clib_warning ("options parse fail");
	      goto drop;
	    }

	  child0->irs = vnet_buffer (b0)->tcp.seq_number;
	  child0->rcv_nxt = vnet_buffer (b0)->tcp.seq_number + 1;
	  child0->rcv_las = child0->rcv_nxt;

	  /* RFC1323: TSval timestamps sent on {SYN} and {SYN,ACK}
	   * segments are used to initialize PAWS. */
	  if (tcp_opts_tstamp (&child0->rcv_opts))
	    {
	      child0->tsval_recent = child0->rcv_opts.tsval;
	      child0->tsval_recent_age = tcp_time_now ();
	    }

	  if (tcp_opts_wscale (&child0->rcv_opts))
	    child0->snd_wscale = child0->rcv_opts.wscale;

	  child0->snd_wnd = clib_net_to_host_u16 (th0->window)
	    << child0->snd_wscale;
	  child0->snd_wl1 = vnet_buffer (b0)->tcp.seq_number;
	  child0->snd_wl2 = vnet_buffer (b0)->tcp.ack_number;

	  tcp_connection_init_vars (child0);
	  TCP_EVT_DBG (TCP_EVT_SYN_RCVD, child0, 1);

	  /* Reuse buffer to make syn-ack and send */
	  tcp_make_synack (child0, b0);
	  next0 = tcp_next_output (is_ip4);
	  tcp_timer_set (child0, TCP_TIMER_ESTABLISH, TCP_SYN_RCVD_TIME);

	drop:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      clib_memcpy (&t0->tcp_header, th0, sizeof (t0->tcp_header));
	      clib_memcpy (&t0->tcp_connection, lc0,
			   sizeof (t0->tcp_connection));
	    }

	  b0->error = node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

static uword
tcp4_listen (vlib_main_t * vm, vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame)
{
  return tcp46_listen_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
tcp6_listen (vlib_main_t * vm, vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame)
{
  return tcp46_listen_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_listen_node) =
{
  .function = tcp4_listen,
  .name = "tcp4-listen",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_LISTEN_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_LISTEN_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_listen_node, tcp4_listen);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_listen_node) =
{
  .function = tcp6_listen,
  .name = "tcp6-listen",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_LISTEN_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_LISTEN_NEXT_##s] = n,
    foreach_tcp_state_next
#undef _
  },
  .format_trace = format_tcp_rx_trace_short,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_listen_node, tcp6_listen);

vlib_node_registration_t tcp4_input_node;
vlib_node_registration_t tcp6_input_node;

typedef enum _tcp_input_next
{
  TCP_INPUT_NEXT_DROP,
  TCP_INPUT_NEXT_LISTEN,
  TCP_INPUT_NEXT_RCV_PROCESS,
  TCP_INPUT_NEXT_SYN_SENT,
  TCP_INPUT_NEXT_ESTABLISHED,
  TCP_INPUT_NEXT_RESET,
  TCP_INPUT_NEXT_PUNT,
  TCP_INPUT_N_NEXT
} tcp_input_next_t;

#define foreach_tcp4_input_next                 \
  _ (DROP, "error-drop")                        \
  _ (LISTEN, "tcp4-listen")                     \
  _ (RCV_PROCESS, "tcp4-rcv-process")           \
  _ (SYN_SENT, "tcp4-syn-sent")                 \
  _ (ESTABLISHED, "tcp4-established")		\
  _ (RESET, "tcp4-reset")			\
  _ (PUNT, "error-punt")

#define foreach_tcp6_input_next                 \
  _ (DROP, "error-drop")                        \
  _ (LISTEN, "tcp6-listen")                     \
  _ (RCV_PROCESS, "tcp6-rcv-process")           \
  _ (SYN_SENT, "tcp6-syn-sent")                 \
  _ (ESTABLISHED, "tcp6-established")		\
  _ (RESET, "tcp6-reset")			\
  _ (PUNT, "error-punt")

#define filter_flags (TCP_FLAG_SYN|TCP_FLAG_ACK|TCP_FLAG_RST|TCP_FLAG_FIN)

always_inline uword
tcp46_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->thread_index;
  tcp_main_t *tm = vnet_get_tcp_main ();

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;
  tcp_set_time_now (my_thread_index);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  int n_advance_bytes0, n_data_bytes0;
	  u32 bi0, fib_index0;
	  vlib_buffer_t *b0;
	  tcp_header_t *tcp0 = 0;
	  tcp_connection_t *tc0;
	  transport_connection_t *tconn;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  u32 error0 = TCP_ERROR_NO_LISTENER, next0 = TCP_INPUT_NEXT_DROP;
	  u8 flags0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  vnet_buffer (b0)->tcp.flags = 0;
	  fib_index0 = vnet_buffer (b0)->ip.fib_index;

	  /* Checksum computed by ipx_local no need to compute again */

	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      tcp0 = ip4_next_header (ip40);
	      n_advance_bytes0 = (ip4_header_bytes (ip40)
				  + tcp_header_bytes (tcp0));
	      n_data_bytes0 = clib_net_to_host_u16 (ip40->length)
		- n_advance_bytes0;
	      tconn = session_lookup_connection_wt4 (fib_index0,
						     &ip40->dst_address,
						     &ip40->src_address,
						     tcp0->dst_port,
						     tcp0->src_port,
						     TRANSPORT_PROTO_TCP,
						     my_thread_index);
	      tc0 = tcp_get_connection_from_transport (tconn);
	      ASSERT (tcp_lookup_is_valid (tc0, tcp0));
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      tcp0 = ip6_next_header (ip60);
	      n_advance_bytes0 = tcp_header_bytes (tcp0);
	      n_data_bytes0 = clib_net_to_host_u16 (ip60->payload_length)
		- n_advance_bytes0;
	      n_advance_bytes0 += sizeof (ip60[0]);
	      tconn = session_lookup_connection_wt6 (fib_index0,
						     &ip60->dst_address,
						     &ip60->src_address,
						     tcp0->dst_port,
						     tcp0->src_port,
						     TRANSPORT_PROTO_TCP,
						     my_thread_index);
	      tc0 = tcp_get_connection_from_transport (tconn);
	      ASSERT (tcp_lookup_is_valid (tc0, tcp0));
	    }

	  /* Length check */
	  if (PREDICT_FALSE (n_advance_bytes0 < 0))
	    {
	      error0 = TCP_ERROR_LENGTH;
	      goto done;
	    }

	  /* Session exists */
	  if (PREDICT_TRUE (0 != tc0))
	    {
	      /* Save connection index */
	      vnet_buffer (b0)->tcp.connection_index = tc0->c_c_index;
	      vnet_buffer (b0)->tcp.seq_number =
		clib_net_to_host_u32 (tcp0->seq_number);
	      vnet_buffer (b0)->tcp.ack_number =
		clib_net_to_host_u32 (tcp0->ack_number);

	      vnet_buffer (b0)->tcp.hdr_offset = (u8 *) tcp0
		- (u8 *) vlib_buffer_get_current (b0);
	      vnet_buffer (b0)->tcp.data_offset = n_advance_bytes0;
	      vnet_buffer (b0)->tcp.data_len = n_data_bytes0;

	      flags0 = tcp0->flags & filter_flags;
	      next0 = tm->dispatch_table[tc0->state][flags0].next;
	      error0 = tm->dispatch_table[tc0->state][flags0].error;

	      if (PREDICT_FALSE (error0 == TCP_ERROR_DISPATCH
				 || next0 == TCP_INPUT_NEXT_RESET))
		{
		  /* Overload tcp flags to store state */
		  tcp_state_t state0 = tc0->state;
		  vnet_buffer (b0)->tcp.flags = tc0->state;

		  if (error0 == TCP_ERROR_DISPATCH)
		    clib_warning ("disp error state %U flags %U",
				  format_tcp_state, state0, format_tcp_flags,
				  (int) flags0);
		}
	    }
	  else
	    {
	      if ((is_ip4 && tm->punt_unknown4) ||
		  (!is_ip4 && tm->punt_unknown6))
		{
		  next0 = TCP_INPUT_NEXT_PUNT;
		  error0 = TCP_ERROR_PUNT;
		}
	      else
		{
		  /* Send reset */
		  next0 = TCP_INPUT_NEXT_RESET;
		  error0 = TCP_ERROR_NO_LISTENER;
		}
	    }

	done:
	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      tcp_rx_trace_t *t0 =
		vlib_add_trace (vm, node, b0, sizeof (*t0));
	      tcp_set_rx_trace_data (t0, tc0, tcp0, b0, is_ip4);
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static uword
tcp4_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * from_frame)
{
  return tcp46_input_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

static uword
tcp6_input (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * from_frame)
{
  return tcp46_input_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp4_input_node) =
{
  .function = tcp4_input,
  .name = "tcp4-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_INPUT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_INPUT_NEXT_##s] = n,
    foreach_tcp4_input_next
#undef _
  },
  .format_buffer = format_tcp_header,
  .format_trace = format_tcp_rx_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp4_input_node, tcp4_input);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (tcp6_input_node) =
{
  .function = tcp6_input,
  .name = "tcp6-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = TCP_N_ERROR,
  .error_strings = tcp_error_strings,
  .n_next_nodes = TCP_INPUT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [TCP_INPUT_NEXT_##s] = n,
    foreach_tcp6_input_next
#undef _
  },
  .format_buffer = format_tcp_header,
  .format_trace = format_tcp_rx_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (tcp6_input_node, tcp6_input);

static void
tcp_dispatch_table_init (tcp_main_t * tm)
{
  int i, j;
  for (i = 0; i < ARRAY_LEN (tm->dispatch_table); i++)
    for (j = 0; j < ARRAY_LEN (tm->dispatch_table[i]); j++)
      {
	tm->dispatch_table[i][j].next = TCP_INPUT_NEXT_DROP;
	tm->dispatch_table[i][j].error = TCP_ERROR_DISPATCH;
      }

#define _(t,f,n,e)                                           	\
do {                                                       	\
    tm->dispatch_table[TCP_STATE_##t][f].next = (n);         	\
    tm->dispatch_table[TCP_STATE_##t][f].error = (e);        	\
} while (0)

  /* SYNs for new connections -> tcp-listen. */
  _(LISTEN, TCP_FLAG_SYN, TCP_INPUT_NEXT_LISTEN, TCP_ERROR_NONE);
  _(LISTEN, TCP_FLAG_ACK, TCP_INPUT_NEXT_RESET, TCP_ERROR_NONE);
  _(LISTEN, TCP_FLAG_RST, TCP_INPUT_NEXT_DROP, TCP_ERROR_NONE);
  _(LISTEN, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RESET,
    TCP_ERROR_NONE);
  /* ACK for for a SYN-ACK -> tcp-rcv-process. */
  _(SYN_RCVD, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(SYN_RCVD, TCP_FLAG_SYN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  /* SYN-ACK for a SYN */
  _(SYN_SENT, TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_INPUT_NEXT_SYN_SENT,
    TCP_ERROR_NONE);
  _(SYN_SENT, TCP_FLAG_ACK, TCP_INPUT_NEXT_SYN_SENT, TCP_ERROR_NONE);
  _(SYN_SENT, TCP_FLAG_RST, TCP_INPUT_NEXT_SYN_SENT, TCP_ERROR_NONE);
  _(SYN_SENT, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_SYN_SENT,
    TCP_ERROR_NONE);
  /* ACK for for established connection -> tcp-established. */
  _(ESTABLISHED, TCP_FLAG_ACK, TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  /* FIN for for established connection -> tcp-established. */
  _(ESTABLISHED, TCP_FLAG_FIN, TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_ESTABLISHED,
    TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_RST, TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_RST | TCP_FLAG_ACK, TCP_INPUT_NEXT_ESTABLISHED,
    TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_SYN, TCP_INPUT_NEXT_ESTABLISHED, TCP_ERROR_NONE);
  _(ESTABLISHED, TCP_FLAG_SYN | TCP_FLAG_ACK, TCP_INPUT_NEXT_ESTABLISHED,
    TCP_ERROR_NONE);
  /* ACK or FIN-ACK to our FIN */
  _(FIN_WAIT_1, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_ACK | TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  /* FIN in reply to our FIN from the other side */
  _(FIN_WAIT_1, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  /* FIN confirming that the peer (app) has closed */
  _(FIN_WAIT_2, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_2, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_2, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(CLOSE_WAIT, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSE_WAIT, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(TIME_WAIT, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(TIME_WAIT, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(TIME_WAIT, TCP_FLAG_RST, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(TIME_WAIT, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(CLOSED, TCP_FLAG_ACK, TCP_INPUT_NEXT_DROP, TCP_ERROR_CONNECTION_CLOSED);
  _(CLOSED, TCP_FLAG_RST, TCP_INPUT_NEXT_DROP, TCP_ERROR_CONNECTION_CLOSED);
  _(CLOSED, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_DROP,
    TCP_ERROR_CONNECTION_CLOSED);
#undef _
}

clib_error_t *
tcp_input_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;
  tcp_main_t *tm = vnet_get_tcp_main ();

  if ((error = vlib_call_init_function (vm, tcp_init)))
    return error;

  /* Initialize dispatch table. */
  tcp_dispatch_table_init (tm);

  return error;
}

VLIB_INIT_FUNCTION (tcp_input_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
