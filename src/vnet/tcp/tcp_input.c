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

void
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
	opt_len = 1;
      else
	{
	  /* broken options */
	  if (opts_len < 2)
	    break;
	  opt_len = data[1];

	  /* weird option length */
	  if (opt_len < 2 || opt_len > opts_len)
	    break;
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
	      b.start = clib_net_to_host_u32 (*(u32 *) (data + 2 + 4 * j));
	      b.end = clib_net_to_host_u32 (*(u32 *) (data + 6 + 4 * j));
	      vec_add1 (to->sacks, b);
	    }
	  break;
	default:
	  /* Nothing to see here */
	  continue;
	}
    }
}

always_inline int
tcp_segment_check_paws (tcp_connection_t * tc)
{
  return tcp_opts_tstamp (&tc->opt) && tc->tsval_recent
    && timestamp_lt (tc->opt.tsval, tc->tsval_recent);
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
  u8 paws_failed;

  if (PREDICT_FALSE (!tcp_ack (th0) && !tcp_rst (th0) && !tcp_syn (th0)))
    return -1;

  tcp_options_parse (th0, &tc0->opt);

  /* RFC1323: Check against wrapped sequence numbers (PAWS). If we have
   * timestamp to echo and it's less than tsval_recent, drop segment
   * but still send an ACK in order to retain TCP's mechanism for detecting
   * and recovering from half-open connections */
  paws_failed = tcp_segment_check_paws (tc0);
  if (paws_failed)
    {
      clib_warning ("paws failed");

      /* If it just so happens that a segment updates tsval_recent for a
       * segment over 24 days old, invalidate tsval_recent. */
      if (timestamp_lt (tc0->tsval_recent_age + TCP_PAWS_IDLE,
			tcp_time_now ()))
	{
	  /* Age isn't reset until we get a valid tsval (bsd inspired) */
	  tc0->tsval_recent = 0;
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
      tcp_send_reset (b0, tc0->c_is_ip4);
      return -1;
    }

  /* If PAWS passed and segment in window, save timestamp */
  if (!paws_failed)
    {
      tc0->tsval_recent = tc0->opt.tsval;
      tc0->tsval_recent_age = tcp_time_now ();
    }

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
  int err;

  if (tc->srtt != 0)
    {
      err = mrtt - tc->srtt;
      tc->srtt += err >> 3;

      /* XXX Drop in RTT results in RTTVAR increase and bigger RTO.
       * The increase should be bound */
      tc->rttvar += ((int) clib_abs (err) - (int) tc->rttvar) >> 2;
    }
  else
    {
      /* First measurement. */
      tc->srtt = mrtt;
      tc->rttvar = mrtt >> 1;
    }
}

/** Update RTT estimate and RTO timer
 *
 * Measure RTT: We have two sources of RTT measurements: TSOPT and ACK
 * timing. Middle boxes are known to fiddle with TCP options so we
 * should give higher priority to ACK timing.
 *
 * return 1 if valid rtt 0 otherwise
 */
static int
tcp_update_rtt (tcp_connection_t * tc, u32 ack)
{
  u32 mrtt = 0;

  /* Karn's rule, part 1. Don't use retransmitted segments to estimate
   * RTT because they're ambiguous. */
  if (tc->rtt_seq && seq_gt (ack, tc->rtt_seq) && !tc->rto_boff)
    {
      mrtt = tcp_time_now () - tc->rtt_ts;
    }

  /* As per RFC7323 TSecr can be used for RTTM only if the segment advances
   * snd_una, i.e., the left side of the send window:
   * seq_lt (tc->snd_una, ack). Note: last condition could be dropped, we don't
   * try to update rtt for dupacks */
  else if (tcp_opts_tstamp (&tc->opt) && tc->opt.tsecr && tc->bytes_acked)
    {
      mrtt = tcp_time_now () - tc->opt.tsecr;
    }

  /* Ignore dubious measurements */
  if (mrtt == 0 || mrtt > TCP_RTT_MAX)
    return 0;

  tcp_estimate_rtt (tc, mrtt);

  tc->rto = clib_min (tc->srtt + (tc->rttvar << 2), TCP_RTO_MAX);

  /* Allow measuring of RTT and make sure boff is 0 */
  tc->rtt_seq = 0;
  tc->rto_boff = 0;

  return 1;
}

/**
 * Dequeue bytes that have been acked and while at it update RTT estimates.
 */
static void
tcp_dequeue_acked (tcp_connection_t * tc, u32 ack)
{
  /* Dequeue the newly ACKed bytes */
  stream_session_dequeue_drop (&tc->connection, tc->bytes_acked);

  /* Update rtt and rto */
  tcp_update_rtt (tc, ack);
}

/**
 * Check if dupack as per RFC5681 Sec. 2
 *
 * This works only if called before updating snd_wnd.
 * */
always_inline u8
tcp_ack_is_dupack (tcp_connection_t * tc, vlib_buffer_t * b, u32 new_snd_wnd)
{
  return ((vnet_buffer (b)->tcp.ack_number == tc->snd_una)
	  && seq_gt (tc->snd_una_max, tc->snd_una)
	  && (vnet_buffer (b)->tcp.seq_end == vnet_buffer (b)->tcp.seq_number)
	  && (new_snd_wnd == tc->snd_wnd));
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

  if (hole->prev != TCP_INVALID_SACK_HOLE_INDEX)
    {
      prev = pool_elt_at_index (sb->holes, hole->prev);
      prev->next = hole->next;
    }
  else
    {
      sb->head = hole->next;
    }

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
  hole_index = hole - sb->holes;

  prev = scoreboard_get_hole (sb, prev_index);
  if (prev)
    {
      hole->prev = prev - sb->holes;
      hole->next = prev->next;

      if ((next = scoreboard_next_hole (sb, hole)))
	next->prev = hole_index;

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
tcp_rcv_sacks (tcp_connection_t * tc, u32 ack)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t *blk, tmp;
  sack_scoreboard_hole_t *hole, *next_hole, *last_hole, *new_hole;
  u32 blk_index = 0, old_sacked_bytes, hole_index;
  int i, j;

  sb->last_sacked_bytes = 0;
  sb->snd_una_adv = 0;
  old_sacked_bytes = sb->sacked_bytes;

  if (!tcp_opts_sack (&tc->opt) && sb->head == TCP_INVALID_SACK_HOLE_INDEX)
    return;

  /* Remove invalid blocks */
  blk = tc->opt.sacks;
  while (blk < vec_end (tc->opt.sacks))
    {
      if (seq_lt (blk->start, blk->end)
	  && seq_gt (blk->start, tc->snd_una)
	  && seq_gt (blk->start, ack) && seq_leq (blk->end, tc->snd_nxt))
	{
	  blk++;
	  continue;
	}
      vec_del1 (tc->opt.sacks, blk - tc->opt.sacks);
    }

  /* Add block for cumulative ack */
  if (seq_gt (ack, tc->snd_una))
    {
      tmp.start = tc->snd_una;
      tmp.end = ack;
      vec_add1 (tc->opt.sacks, tmp);
    }

  if (vec_len (tc->opt.sacks) == 0)
    return;

  /* Make sure blocks are ordered */
  for (i = 0; i < vec_len (tc->opt.sacks); i++)
    for (j = i + 1; j < vec_len (tc->opt.sacks); j++)
      if (seq_lt (tc->opt.sacks[j].start, tc->opt.sacks[i].start))
	{
	  tmp = tc->opt.sacks[i];
	  tc->opt.sacks[i] = tc->opt.sacks[j];
	  tc->opt.sacks[j] = tmp;
	}

  if (sb->head == TCP_INVALID_SACK_HOLE_INDEX)
    {
      /* If no holes, insert the first that covers all outstanding bytes */
      last_hole = scoreboard_insert_hole (sb, TCP_INVALID_SACK_HOLE_INDEX,
					  tc->snd_una, tc->snd_una_max);
      sb->tail = scoreboard_hole_index (sb, last_hole);
    }
  else
    {
      /* If we have holes but snd_una_max is beyond the last hole, update
       * last hole end */
      tmp = tc->opt.sacks[vec_len (tc->opt.sacks) - 1];
      last_hole = scoreboard_last_hole (sb);
      if (seq_gt (tc->snd_una_max, sb->max_byte_sacked)
	  && seq_gt (tc->snd_una_max, last_hole->end))
	last_hole->end = tc->snd_una_max;
    }

  /* Walk the holes with the SACK blocks */
  hole = pool_elt_at_index (sb->holes, sb->head);
  while (hole && blk_index < vec_len (tc->opt.sacks))
    {
      blk = &tc->opt.sacks[blk_index];

      if (seq_leq (blk->start, hole->start))
	{
	  /* Block covers hole. Remove hole */
	  if (seq_geq (blk->end, hole->end))
	    {
	      next_hole = scoreboard_next_hole (sb, hole);

	      /* Byte accounting */
	      if (seq_leq (hole->end, ack))
		{
		  /* Bytes lost because snd_wnd left edge advances */
		  if (next_hole && seq_leq (next_hole->start, ack))
		    sb->sacked_bytes -= next_hole->start - hole->end;
		  else
		    sb->sacked_bytes -= ack - hole->end;
		}
	      else
		{
		  sb->sacked_bytes += scoreboard_hole_bytes (hole);
		}

	      /* snd_una needs to be advanced */
	      if (seq_geq (ack, hole->end))
		{
		  if (next_hole && seq_lt (ack, next_hole->start))
		    sb->snd_una_adv = next_hole->start - ack;
		  else
		    sb->snd_una_adv = sb->max_byte_sacked - ack;

		  /* all these can be delivered */
		  sb->sacked_bytes -= sb->snd_una_adv;
		}

	      /* About to remove last hole */
	      if (hole == last_hole)
		{
		  sb->tail = hole->prev;
		  last_hole = scoreboard_last_hole (sb);
		  /* keep track of max byte sacked in case the last hole
		   * is acked */
		  if (seq_gt (hole->end, sb->max_byte_sacked))
		    sb->max_byte_sacked = hole->end;
		}
	      scoreboard_remove_hole (sb, hole);
	      hole = next_hole;
	    }
	  /* Partial 'head' overlap */
	  else
	    {
	      if (seq_gt (blk->end, hole->start))
		{
		  sb->sacked_bytes += blk->end - hole->start;
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
	      sb->sacked_bytes += blk->end - blk->start;
	      hole_index = scoreboard_hole_index (sb, hole);
	      new_hole = scoreboard_insert_hole (sb, hole_index, blk->end,
						 hole->end);

	      /* Pool might've moved */
	      hole = scoreboard_get_hole (sb, hole_index);
	      hole->end = blk->start;

	      /* New or split of tail */
	      if ((last_hole->end == new_hole->end)
		  || seq_lt (last_hole->end, new_hole->start))
		{
		  last_hole = new_hole;
		  sb->tail = scoreboard_hole_index (sb, new_hole);
		}

	      blk_index++;
	      hole = scoreboard_next_hole (sb, hole);
	    }
	  else
	    {
	      sb->sacked_bytes += hole->end - blk->start;
	      hole->end = blk->start;
	      hole = scoreboard_next_hole (sb, hole);
	    }
	}
    }

  sb->last_sacked_bytes = sb->sacked_bytes + sb->snd_una_adv
    - old_sacked_bytes;
}

/** Update snd_wnd
 *
 * If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), set
 * SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK */
static void
tcp_update_snd_wnd (tcp_connection_t * tc, u32 seq, u32 ack, u32 snd_wnd)
{
  if (seq_lt (tc->snd_wl1, seq)
      || (tc->snd_wl1 == seq && seq_leq (tc->snd_wl2, ack)))
    {
      tc->snd_wnd = snd_wnd;
      tc->snd_wl1 = seq;
      tc->snd_wl2 = ack;
      TCP_EVT_DBG (TCP_EVT_SND_WND, tc);

      /* Set probe timer if we just got 0 wnd */
      if (tc->snd_wnd < tc->snd_mss
	  && !tcp_timer_is_active (tc, TCP_TIMER_PERSIST))
	tcp_persist_timer_set (tc);
      else
	tcp_persist_timer_reset (tc);
    }
}

void
tcp_cc_congestion (tcp_connection_t * tc)
{
  tc->snd_congestion = tc->snd_nxt;
  tc->cc_algo->congestion (tc);
  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 4);
}

void
tcp_cc_recover (tcp_connection_t * tc)
{
  /* TODO: check if time to recover was small. It might be that RTO popped
   * too soon.
   */

  tc->cc_algo->recovered (tc);

  tc->rtx_bytes = 0;
  tc->rcv_dupacks = 0;
  tc->snd_nxt = tc->snd_una;

  tc->cc_algo->rcv_ack (tc);
  tc->tsecr_last_ack = tc->opt.tsecr;

  tcp_cong_recovery_off (tc);

  TCP_EVT_DBG (TCP_EVT_CC_EVT, tc, 3);
}

static void
tcp_cc_rcv_ack (tcp_connection_t * tc, vlib_buffer_t * b)
{
  u8 partial_ack;

  if (tcp_in_cong_recovery (tc))
    {
      partial_ack = seq_lt (tc->snd_una, tc->snd_congestion);
      if (!partial_ack)
	{
	  /* Clear retransmitted bytes. */
	  tcp_cc_recover (tc);
	}
      else
	{
	  TCP_EVT_DBG (TCP_EVT_CC_PACK, tc);

	  /* Clear retransmitted bytes. XXX should we clear all? */
	  tc->rtx_bytes = 0;
	  tc->cc_algo->rcv_cong_ack (tc, TCP_CC_PARTIALACK);

	  /* In case snd_nxt is still in the past and output tries to
	   * shove some new bytes */
	  tc->snd_nxt = tc->snd_una_max;

	  /* XXX need proper RFC6675 support */
	  if (tc->sack_sb.last_sacked_bytes && !tcp_in_recovery (tc))
	    {
	      tcp_fast_retransmit (tc);
	    }
	  else
	    {
	      /* Retransmit first unacked segment */
	      tcp_retransmit_first_unacked (tc);
	    }
	}
    }
  else
    {
      tc->cc_algo->rcv_ack (tc);
      tc->tsecr_last_ack = tc->opt.tsecr;
      tc->rcv_dupacks = 0;
    }
}

static void
tcp_cc_rcv_dupack (tcp_connection_t * tc, u32 ack)
{
//  ASSERT (seq_geq(tc->snd_una, ack));

  tc->rcv_dupacks++;
  if (tc->rcv_dupacks == TCP_DUPACK_THRESHOLD)
    {
      /* RFC6582 NewReno heuristic to avoid multiple fast retransmits */
      if (tc->opt.tsecr != tc->tsecr_last_ack)
	{
	  tc->rcv_dupacks = 0;
	  return;
	}

      tcp_fastrecovery_on (tc);

      /* Handle congestion and dupack */
      tcp_cc_congestion (tc);
      tc->cc_algo->rcv_cong_ack (tc, TCP_CC_DUPACK);

      tcp_fast_retransmit (tc);

      /* Post retransmit update cwnd to ssthresh and account for the
       * three segments that have left the network and should've been
       * buffered at the receiver */
      tc->cwnd = tc->ssthresh + TCP_DUPACK_THRESHOLD * tc->snd_mss;
    }
  else if (tc->rcv_dupacks > TCP_DUPACK_THRESHOLD)
    {
      ASSERT (tcp_in_fastrecovery (tc));

      tc->cc_algo->rcv_cong_ack (tc, TCP_CC_DUPACK);
    }
}

void
tcp_cc_init (tcp_connection_t * tc)
{
  tc->cc_algo = tcp_cc_algo_get (TCP_CC_NEWRENO);
  tc->cc_algo->init (tc);
}

static int
tcp_rcv_ack (tcp_connection_t * tc, vlib_buffer_t * b,
	     tcp_header_t * th, u32 * next, u32 * error)
{
  u32 new_snd_wnd;

  /* If the ACK acks something not yet sent (SEG.ACK > SND.NXT) */
  if (seq_gt (vnet_buffer (b)->tcp.ack_number, tc->snd_nxt))
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
  if (seq_lt (vnet_buffer (b)->tcp.ack_number, tc->snd_una))
    {
      *error = TCP_ERROR_ACK_OLD;
      TCP_EVT_DBG (TCP_EVT_ACK_RCV_ERR, tc, 1,
		   vnet_buffer (b)->tcp.ack_number);
      if (tcp_in_fastrecovery (tc) && tc->rcv_dupacks == TCP_DUPACK_THRESHOLD)
	{
	  TCP_EVT_DBG (TCP_EVT_DUPACK_RCVD, tc);
	  tcp_cc_rcv_dupack (tc, vnet_buffer (b)->tcp.ack_number);
	}
      return -1;
    }

  if (tcp_opts_sack_permitted (&tc->opt))
    tcp_rcv_sacks (tc, vnet_buffer (b)->tcp.ack_number);

  new_snd_wnd = clib_net_to_host_u16 (th->window) << tc->snd_wscale;

  if (tcp_ack_is_dupack (tc, b, new_snd_wnd))
    {
      TCP_EVT_DBG (TCP_EVT_DUPACK_RCVD, tc, 1);
      tcp_cc_rcv_dupack (tc, vnet_buffer (b)->tcp.ack_number);
      *error = TCP_ERROR_ACK_DUP;
      return -1;
    }

  /*
   * Valid ACK
   */

  tc->bytes_acked = vnet_buffer (b)->tcp.ack_number - tc->snd_una;
  tc->snd_una = vnet_buffer (b)->tcp.ack_number + tc->sack_sb.snd_una_adv;

  /* Dequeue ACKed data and update RTT */
  tcp_dequeue_acked (tc, vnet_buffer (b)->tcp.ack_number);
  tcp_update_snd_wnd (tc, vnet_buffer (b)->tcp.seq_number,
		      vnet_buffer (b)->tcp.ack_number, new_snd_wnd);

  /* If some of our sent bytes have been acked, update cc and retransmit
   * timer. */
  if (tc->bytes_acked)
    {
      TCP_EVT_DBG (TCP_EVT_ACK_RCVD, tc);

      /* Updates congestion control (slow start/congestion avoidance) */
      tcp_cc_rcv_ack (tc, b);

      /* If everything has been acked, stop retransmit timer
       * otherwise update */
      if (tc->snd_una == tc->snd_una_max)
	tcp_retransmit_timer_reset (tc);
      else
	tcp_retransmit_timer_update (tc);
    }

  return 0;
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
static void
tcp_update_sack_list (tcp_connection_t * tc, u32 start, u32 end)
{
  sack_block_t *new_list = 0, block;
  int i;

  /* If the first segment is ooo add it to the list. Last write might've moved
   * rcv_nxt over the first segment. */
  if (seq_lt (tc->rcv_nxt, start))
    {
      block.start = start;
      block.end = end;
      vec_add1 (new_list, block);
    }

  /* Find the blocks still worth keeping. */
  for (i = 0; i < vec_len (tc->snd_sacks); i++)
    {
      /* Discard if:
       * 1) rcv_nxt advanced beyond current block OR
       * 2) Segment overlapped by the first segment, i.e., it has been merged
       *    into it.*/
      if (seq_leq (tc->snd_sacks[i].start, tc->rcv_nxt)
	  || seq_leq (tc->snd_sacks[i].start, end))
	continue;

      /* Save to new SACK list. */
      vec_add1 (new_list, tc->snd_sacks[i]);
    }

  ASSERT (vec_len (new_list) < TCP_MAX_SACK_BLOCKS);

  /* Replace old vector with new one */
  vec_free (tc->snd_sacks);
  tc->snd_sacks = new_list;
}

/** Enqueue data for delivery to application */
always_inline int
tcp_session_enqueue_data (tcp_connection_t * tc, vlib_buffer_t * b,
			  u16 data_len)
{
  int written;

  /* Pure ACK. Update rcv_nxt and be done. */
  if (PREDICT_FALSE (data_len == 0))
    {
      tc->rcv_nxt = vnet_buffer (b)->tcp.seq_end;
      return TCP_ERROR_PURE_ACK;
    }

  written = stream_session_enqueue_data (&tc->connection,
					 vlib_buffer_get_current (b),
					 data_len, 1 /* queue event */ );

  TCP_EVT_DBG (TCP_EVT_INPUT, tc, 0, data_len, written);

  /* Update rcv_nxt */
  if (PREDICT_TRUE (written == data_len))
    {
      tc->rcv_nxt = vnet_buffer (b)->tcp.seq_end;
    }
  /* If more data written than expected, account for out-of-order bytes. */
  else if (written > data_len)
    {
      tc->rcv_nxt = vnet_buffer (b)->tcp.seq_end + written - data_len;

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

      return TCP_ERROR_PARTIALLY_ENQUEUED;
    }
  else
    {
      tc->flags |= TCP_CONN_SNDACK;
      return TCP_ERROR_FIFO_FULL;
    }

  /* Update SACK list if need be */
  if (tcp_opts_sack_permitted (&tc->opt))
    {
      /* Remove SACK blocks that have been delivered */
      tcp_update_sack_list (tc, tc->rcv_nxt, tc->rcv_nxt);
    }

  return TCP_ERROR_ENQUEUED;
}

/** Enqueue out-of-order data */
always_inline int
tcp_session_enqueue_ooo (tcp_connection_t * tc, vlib_buffer_t * b,
			 u16 data_len)
{
  stream_session_t *s0;
  u32 offset;
  int rv;

  /* Pure ACK. Do nothing */
  if (PREDICT_FALSE (data_len == 0))
    {
      return TCP_ERROR_PURE_ACK;
    }

  s0 = stream_session_get (tc->c_s_index, tc->c_thread_index);
  offset = vnet_buffer (b)->tcp.seq_number - tc->irs;

  clib_warning ("ooo: offset %d len %d", offset, data_len);

  rv = svm_fifo_enqueue_with_offset (s0->server_rx_fifo, s0->pid, offset,
				     data_len, vlib_buffer_get_current (b));

  /* Nothing written */
  if (rv)
    {
      TCP_EVT_DBG (TCP_EVT_INPUT, tc, 1, data_len, 0);
      return TCP_ERROR_FIFO_FULL;
    }

  TCP_EVT_DBG (TCP_EVT_INPUT, tc, 1, data_len, data_len);

  /* Update SACK list if in use */
  if (tcp_opts_sack_permitted (&tc->opt))
    {
      ooo_segment_t *newest;
      u32 start, end;

      /* Get the newest segment from the fifo */
      newest = svm_fifo_newest_ooo_segment (s0->server_rx_fifo);
      start = ooo_segment_offset (s0->server_rx_fifo, newest);
      end = ooo_segment_end_offset (s0->server_rx_fifo, newest);

      tcp_update_sack_list (tc, start, end);
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
      || tcp_available_snd_space (tc) < 2 * tc->snd_mss)
    return 0;

  return 1;
}

static int
tcp_segment_rcv (tcp_main_t * tm, tcp_connection_t * tc, vlib_buffer_t * b,
		 u16 n_data_bytes, u32 * next0)
{
  u32 error = 0;

  /* Handle out-of-order data */
  if (PREDICT_FALSE (vnet_buffer (b)->tcp.seq_number != tc->rcv_nxt))
    {
      /* Old sequence numbers allowed through because they overlapped
       * the rx window */

      if (seq_lt (vnet_buffer (b)->tcp.seq_number, tc->rcv_nxt))
	{
	  error = TCP_ERROR_SEGMENT_OLD;
	  *next0 = TCP_NEXT_DROP;
	  goto done;
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

  /* In order data, enqueue. Fifo figures out by itself if any out-of-order
   * segments can be enqueued after fifo tail offset changes. */
  error = tcp_session_enqueue_data (tc, b, n_data_bytes);

  if (n_data_bytes == 0)
    {
      *next0 = TCP_NEXT_DROP;
      goto done;
    }

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
  uword indent = format_get_indent (s);

  s = format (s, "%U\n%U%U",
	      format_tcp_header, &t->tcp_header, 128,
	      format_white_space, indent,
	      format_tcp_connection_verbose, &t->tcp_connection);

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
	      &t->tcp_connection.state);

  return s;
}

always_inline void
tcp_established_inc_counter (vlib_main_t * vm, u8 is_ip4, u8 evt, u8 val)
{
  if (PREDICT_TRUE (!val))
    return;

  if (is_ip4)
    vlib_node_increment_counter (vm, tcp4_established_node.index, evt, val);
  else
    vlib_node_increment_counter (vm, tcp6_established_node.index, evt, val);
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
	  tcp_rx_trace_t *t0;
	  tcp_header_t *th0 = 0;
	  tcp_connection_t *tc0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  u32 n_advance_bytes0, n_data_bytes0;
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

	  /* Checksum computed by ipx_local no need to compute again */

	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      th0 = ip4_next_header (ip40);
	      n_advance_bytes0 = (ip4_header_bytes (ip40)
				  + tcp_header_bytes (th0));
	      n_data_bytes0 = clib_net_to_host_u16 (ip40->length)
		- n_advance_bytes0;
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      th0 = ip6_next_header (ip60);
	      n_advance_bytes0 = tcp_header_bytes (th0);
	      n_data_bytes0 = clib_net_to_host_u16 (ip60->payload_length)
		- n_advance_bytes0;
	      n_advance_bytes0 += sizeof (ip60[0]);
	    }

	  is_fin = (th0->flags & TCP_FLAG_FIN) != 0;

	  /* SYNs, FINs and data consume sequence numbers */
	  vnet_buffer (b0)->tcp.seq_end = vnet_buffer (b0)->tcp.seq_number
	    + tcp_is_syn (th0) + is_fin + n_data_bytes0;

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
	    {
	      goto done;
	    }

	  /* 6: check the URG bit TODO */

	  /* 7: process the segment text */

	  vlib_buffer_advance (b0, n_advance_bytes0);
	  error0 = tcp_segment_rcv (tm, tc0, b0, n_data_bytes0, &next0);

	  /* N.B. buffer is rewritten if segment is ooo. Thus, th0 becomes a
	   * dangling reference. */

	  /* 8: check the FIN bit */
	  if (is_fin)
	    {
	      /* Enter CLOSE-WAIT and notify session. Don't send ACK, instead
	       * wait for session to call close. To avoid lingering
	       * in CLOSE-WAIT, set timer (reuse WAITCLOSE). */
	      tc0->state = TCP_STATE_CLOSE_WAIT;
	      TCP_EVT_DBG (TCP_EVT_FIN_RCVD, tc0);
	      stream_session_disconnect_notify (&tc0->connection);
	      tcp_timer_set (tc0, TCP_TIMER_WAITCLOSE, TCP_CLOSEWAIT_TIME);
	    }

	done:
	  b0->error = node->errors[error0];
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      clib_memcpy (&t0->tcp_header, th0, sizeof (t0->tcp_header));
	      clib_memcpy (&t0->tcp_connection, tc0,
			   sizeof (t0->tcp_connection));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  errors = session_manager_flush_enqueue_events (my_thread_index);
  tcp_established_inc_counter (vm, is_ip4, TCP_ERROR_EVENT_FIFO_FULL, errors);

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

always_inline uword
tcp46_syn_sent_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * from_frame, int is_ip4)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u32 n_left_from, next_index, *from, *to_next;
  u32 my_thread_index = vm->thread_index, errors = 0;
  u8 sst = is_ip4 ? SESSION_TYPE_IP4_TCP : SESSION_TYPE_IP6_TCP;

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
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  u32 n_advance_bytes0, n_data_bytes0;
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

	  ack0 = vnet_buffer (b0)->tcp.ack_number;
	  seq0 = vnet_buffer (b0)->tcp.seq_number;

	  /* Checksum computed by ipx_local no need to compute again */

	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      tcp0 = ip4_next_header (ip40);
	      n_advance_bytes0 = (ip4_header_bytes (ip40)
				  + tcp_header_bytes (tcp0));
	      n_data_bytes0 = clib_net_to_host_u16 (ip40->length)
		- n_advance_bytes0;
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      tcp0 = ip6_next_header (ip60);
	      n_advance_bytes0 = tcp_header_bytes (tcp0);
	      n_data_bytes0 = clib_net_to_host_u16 (ip60->payload_length)
		- n_advance_bytes0;
	      n_advance_bytes0 += sizeof (ip60[0]);
	    }

	  if (PREDICT_FALSE
	      (!tcp_ack (tcp0) && !tcp_rst (tcp0) && !tcp_syn (tcp0)))
	    goto drop;

	  /* SYNs, FINs and data consume sequence numbers */
	  vnet_buffer (b0)->tcp.seq_end = seq0 + tcp_is_syn (tcp0)
	    + tcp_is_fin (tcp0) + n_data_bytes0;

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
	      if (ack0 <= tc0->iss || ack0 > tc0->snd_nxt)
		{
		  if (!tcp_rst (tcp0))
		    tcp_send_reset (b0, is_ip4);

		  goto drop;
		}

	      /* Make sure ACK is valid */
	      if (tc0->snd_una > ack0)
		goto drop;
	    }

	  /*
	   * 2. check the RST bit
	   */

	  if (tcp_rst (tcp0))
	    {
	      /* If ACK is acceptable, signal client that peer is not
	       * willing to accept connection and drop connection*/
	      if (tcp_ack (tcp0))
		{
		  stream_session_connect_notify (&tc0->connection, sst,
						 1 /* fail */ );
		  tcp_connection_cleanup (tc0);
		}
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
	    goto drop;

	  /* Stop connection establishment and retransmit timers */
	  tcp_timer_reset (tc0, TCP_TIMER_ESTABLISH);
	  tcp_timer_reset (tc0, TCP_TIMER_RETRANSMIT_SYN);

	  /* Valid SYN or SYN-ACK. Move connection from half-open pool to
	   * current thread pool. */
	  pool_get (tm->connections[my_thread_index], new_tc0);
	  clib_memcpy (new_tc0, tc0, sizeof (*new_tc0));

	  new_tc0->c_thread_index = my_thread_index;

	  /* Cleanup half-open connection XXX lock */
	  pool_put (tm->half_open_connections, tc0);

	  new_tc0->rcv_nxt = vnet_buffer (b0)->tcp.seq_end;
	  new_tc0->irs = seq0;

	  /* Parse options */
	  tcp_options_parse (tcp0, &new_tc0->opt);

	  if (tcp_opts_tstamp (&new_tc0->opt))
	    {
	      new_tc0->tsval_recent = new_tc0->opt.tsval;
	      new_tc0->tsval_recent_age = tcp_time_now ();
	    }

	  if (tcp_opts_wscale (&new_tc0->opt))
	    new_tc0->snd_wscale = new_tc0->opt.wscale;

	  /* No scaling */
	  new_tc0->snd_wnd = clib_net_to_host_u16 (tcp0->window);
	  new_tc0->snd_wl1 = seq0;
	  new_tc0->snd_wl2 = ack0;

	  tcp_connection_init_vars (new_tc0);

	  /* SYN-ACK: See if we can switch to ESTABLISHED state */
	  if (tcp_ack (tcp0))
	    {
	      /* Our SYN is ACKed: we have iss < ack = snd_una */

	      /* TODO Dequeue acknowledged segments if we support Fast Open */
	      new_tc0->snd_una = ack0;
	      new_tc0->state = TCP_STATE_ESTABLISHED;

	      /* Make sure las is initialized for the wnd computation */
	      new_tc0->rcv_las = new_tc0->rcv_nxt;

	      /* Notify app that we have connection */
	      stream_session_connect_notify (&new_tc0->connection, sst, 0);

	      /* Make sure after data segment processing ACK is sent */
	      new_tc0->flags |= TCP_CONN_SNDACK;
	    }
	  /* SYN: Simultaneous open. Change state to SYN-RCVD and send SYN-ACK */
	  else
	    {
	      new_tc0->state = TCP_STATE_SYN_RCVD;

	      /* Notify app that we have connection */
	      stream_session_connect_notify (&new_tc0->connection, sst, 0);

	      tcp_make_synack (new_tc0, b0);
	      next0 = tcp_next_output (is_ip4);

	      goto drop;
	    }

	  /* Read data, if any */
	  if (n_data_bytes0)
	    {
	      error0 =
		tcp_segment_rcv (tm, new_tc0, b0, n_data_bytes0, &next0);
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
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
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

  errors = session_manager_flush_enqueue_events (my_thread_index);
  if (errors)
    {
      if (is_ip4)
	vlib_node_increment_counter (vm, tcp4_established_node.index,
				     TCP_ERROR_EVENT_FIFO_FULL, errors);
      else
	vlib_node_increment_counter (vm, tcp6_established_node.index,
				     TCP_ERROR_EVENT_FIFO_FULL, errors);
    }

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
	  tcp_rx_trace_t *t0;
	  tcp_header_t *tcp0 = 0;
	  tcp_connection_t *tc0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  u32 n_advance_bytes0, n_data_bytes0;
	  u32 next0 = TCP_RCV_PROCESS_NEXT_DROP, error0 = TCP_ERROR_ENQUEUED;

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

	  /* Checksum computed by ipx_local no need to compute again */

	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      tcp0 = ip4_next_header (ip40);
	      n_advance_bytes0 = (ip4_header_bytes (ip40)
				  + tcp_header_bytes (tcp0));
	      n_data_bytes0 = clib_net_to_host_u16 (ip40->length)
		- n_advance_bytes0;
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      tcp0 = ip6_next_header (ip60);
	      n_advance_bytes0 = tcp_header_bytes (tcp0);
	      n_data_bytes0 = clib_net_to_host_u16 (ip60->payload_length)
		- n_advance_bytes0;
	      n_advance_bytes0 += sizeof (ip60[0]);
	    }

	  /* SYNs, FINs and data consume sequence numbers */
	  vnet_buffer (b0)->tcp.seq_end = vnet_buffer (b0)->tcp.seq_number
	    + tcp_is_syn (tcp0) + tcp_is_fin (tcp0) + n_data_bytes0;

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
	  if (PREDICT_FALSE
	      (tcp_segment_validate (vm, tc0, b0, tcp0, &next0)))
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
		  tcp_send_reset (b0, is_ip4);
		  goto drop;
		}
	      /* Switch state to ESTABLISHED */
	      tc0->state = TCP_STATE_ESTABLISHED;

	      /* Initialize session variables */
	      tc0->snd_una = vnet_buffer (b0)->tcp.ack_number;
	      tc0->snd_wnd = clib_net_to_host_u16 (tcp0->window)
		<< tc0->opt.wscale;
	      tc0->snd_wl1 = vnet_buffer (b0)->tcp.seq_number;
	      tc0->snd_wl2 = vnet_buffer (b0)->tcp.ack_number;

	      /* Shoulder tap the server */
	      stream_session_accept_notify (&tc0->connection);

	      /* Reset SYN-ACK retransmit timer */
	      tcp_retransmit_timer_reset (tc0);
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

	      /* If FIN is ACKed */
	      if (tc0->snd_una == tc0->snd_una_max)
		{
		  tc0->state = TCP_STATE_FIN_WAIT_2;
		  /* Stop all timers, 2MSL will be set lower */
		  tcp_connection_timers_reset (tc0);
		}
	      break;
	    case TCP_STATE_FIN_WAIT_2:
	      /* In addition to the processing for the ESTABLISHED state, if
	       * the retransmission queue is empty, the user's CLOSE can be
	       * acknowledged ("ok") but do not delete the TCB. */
	      if (tcp_rcv_ack (tc0, b0, tcp0, &next0, &error0))
		goto drop;
	      /* check if rtx queue is empty and ack CLOSE TODO */
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

	      /* XXX test that send queue empty */
	      tc0->state = TCP_STATE_TIME_WAIT;
	      goto drop;

	      break;
	    case TCP_STATE_LAST_ACK:
	      /* The only thing that can arrive in this state is an
	       * acknowledgment of our FIN. If our FIN is now acknowledged,
	       * delete the TCB, enter the CLOSED state, and return. */

	      if (!tcp_rcv_ack_is_acceptable (tc0, b0))
		goto drop;

	      tc0->state = TCP_STATE_CLOSED;

	      /* Don't delete the connection/session yet. Instead, wait a
	       * reasonable amount of time until the pipes are cleared. In
	       * particular, this makes sure that we won't have dead sessions
	       * when processing events on the tx path */
	      tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_CLEANUP_TIME);

	      /* Stop retransmit */
	      tcp_retransmit_timer_reset (tc0);

	      goto drop;

	      break;
	    case TCP_STATE_TIME_WAIT:
	      /* The only thing that can arrive in this state is a
	       * retransmission of the remote FIN. Acknowledge it, and restart
	       * the 2 MSL timeout. */

	      /* TODO */
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
	      vlib_buffer_advance (b0, n_advance_bytes0);
	      error0 = tcp_segment_rcv (tm, tc0, b0, n_data_bytes0, &next0);
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
	  if (!tcp_fin (tcp0))
	    goto drop;

	  switch (tc0->state)
	    {
	    case TCP_STATE_ESTABLISHED:
	    case TCP_STATE_SYN_RCVD:
	      /* Send FIN-ACK notify app and enter CLOSE-WAIT */
	      tcp_connection_timers_reset (tc0);
	      tcp_make_fin (tc0, b0);
	      next0 = tcp_next_output (tc0->c_is_ip4);
	      stream_session_disconnect_notify (&tc0->connection);
	      tc0->state = TCP_STATE_CLOSE_WAIT;
	      break;
	    case TCP_STATE_CLOSE_WAIT:
	    case TCP_STATE_CLOSING:
	    case TCP_STATE_LAST_ACK:
	      /* move along .. */
	      break;
	    case TCP_STATE_FIN_WAIT_1:
	      tc0->state = TCP_STATE_TIME_WAIT;
	      tcp_connection_timers_reset (tc0);
	      tcp_timer_set (tc0, TCP_TIMER_WAITCLOSE, TCP_2MSL_TIME);
	      break;
	    case TCP_STATE_FIN_WAIT_2:
	      /* Got FIN, send ACK! */
	      tc0->state = TCP_STATE_TIME_WAIT;
	      tcp_timer_set (tc0, TCP_TIMER_WAITCLOSE, TCP_CLOSEWAIT_TIME);
	      tcp_make_ack (tc0, b0);
	      next0 = tcp_next_output (is_ip4);
	      break;
	    case TCP_STATE_TIME_WAIT:
	      /* Remain in the TIME-WAIT state. Restart the 2 MSL time-wait
	       * timeout.
	       */
	      tcp_timer_update (tc0, TCP_TIMER_WAITCLOSE, TCP_2MSL_TIME);
	      break;
	    }
	  TCP_EVT_DBG (TCP_EVT_FIN_RCVD, tc0);

	  b0->error = error0 ? node->errors[error0] : 0;

	drop:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
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

  errors = session_manager_flush_enqueue_events (my_thread_index);
  if (errors)
    {
      if (is_ip4)
	vlib_node_increment_counter (vm, tcp4_established_node.index,
				     TCP_ERROR_EVENT_FIFO_FULL, errors);
      else
	vlib_node_increment_counter (vm, tcp6_established_node.index,
				     TCP_ERROR_EVENT_FIFO_FULL, errors);
    }

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
  tcp_main_t *tm = vnet_get_tcp_main ();
  u8 sst = is_ip4 ? SESSION_TYPE_IP4_TCP : SESSION_TYPE_IP6_TCP;

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

	  /* 1. first check for an RST */
	  if (tcp_rst (th0))
	    goto drop;

	  /* 2. second check for an ACK */
	  if (tcp_ack (th0))
	    {
	      tcp_send_reset (b0, is_ip4);
	      goto drop;
	    }

	  /* 3. check for a SYN (did that already) */

	  /* Create child session and send SYN-ACK */
	  pool_get (tm->connections[my_thread_index], child0);
	  memset (child0, 0, sizeof (*child0));

	  child0->c_c_index = child0 - tm->connections[my_thread_index];
	  child0->c_lcl_port = lc0->c_lcl_port;
	  child0->c_rmt_port = th0->src_port;
	  child0->c_is_ip4 = is_ip4;
	  child0->c_thread_index = my_thread_index;

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

	  if (stream_session_accept (&child0->connection, lc0->c_s_index, sst,
				     0 /* notify */ ))
	    {
	      error0 = TCP_ERROR_CREATE_SESSION_FAIL;
	      goto drop;
	    }

	  tcp_options_parse (th0, &child0->opt);

	  child0->irs = vnet_buffer (b0)->tcp.seq_number;
	  child0->rcv_nxt = vnet_buffer (b0)->tcp.seq_number + 1;
	  child0->rcv_las = child0->rcv_nxt;
	  child0->state = TCP_STATE_SYN_RCVD;

	  /* RFC1323: TSval timestamps sent on {SYN} and {SYN,ACK}
	   * segments are used to initialize PAWS. */
	  if (tcp_opts_tstamp (&child0->opt))
	    {
	      child0->tsval_recent = child0->opt.tsval;
	      child0->tsval_recent_age = tcp_time_now ();
	    }

	  if (tcp_opts_wscale (&child0->opt))
	    child0->snd_wscale = child0->opt.wscale;

	  /* No scaling */
	  child0->snd_wnd = clib_net_to_host_u16 (th0->window);
	  child0->snd_wl1 = vnet_buffer (b0)->tcp.seq_number;
	  child0->snd_wl2 = vnet_buffer (b0)->tcp.ack_number;

	  tcp_connection_init_vars (child0);

	  TCP_EVT_DBG (TCP_EVT_SYN_RCVD, child0);

	  /* Reuse buffer to make syn-ack and send */
	  tcp_make_synack (child0, b0);
	  next0 = tcp_next_output (is_ip4);

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
  TCP_INPUT_N_NEXT
} tcp_input_next_t;

#define foreach_tcp4_input_next                 \
  _ (DROP, "error-drop")                        \
  _ (LISTEN, "tcp4-listen")                     \
  _ (RCV_PROCESS, "tcp4-rcv-process")           \
  _ (SYN_SENT, "tcp4-syn-sent")                 \
  _ (ESTABLISHED, "tcp4-established")		\
  _ (RESET, "tcp4-reset")

#define foreach_tcp6_input_next                 \
  _ (DROP, "error-drop")                        \
  _ (LISTEN, "tcp6-listen")                     \
  _ (RCV_PROCESS, "tcp6-rcv-process")           \
  _ (SYN_SENT, "tcp6-syn-sent")                 \
  _ (ESTABLISHED, "tcp6-established")		\
  _ (RESET, "tcp6-reset")

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

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  tcp_rx_trace_t *t0;
	  tcp_header_t *tcp0 = 0;
	  tcp_connection_t *tc0;
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

	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      tcp0 = ip4_next_header (ip40);

	      /* lookup session */
	      tc0 =
		(tcp_connection_t *)
		stream_session_lookup_transport4 (&ip40->dst_address,
						  &ip40->src_address,
						  tcp0->dst_port,
						  tcp0->src_port,
						  SESSION_TYPE_IP4_TCP,
						  my_thread_index);
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      tcp0 = ip6_next_header (ip60);
	      tc0 =
		(tcp_connection_t *)
		stream_session_lookup_transport6 (&ip60->src_address,
						  &ip60->dst_address,
						  tcp0->src_port,
						  tcp0->dst_port,
						  SESSION_TYPE_IP6_TCP,
						  my_thread_index);
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

	      flags0 = tcp0->flags & filter_flags;
	      next0 = tm->dispatch_table[tc0->state][flags0].next;
	      error0 = tm->dispatch_table[tc0->state][flags0].error;

	      if (PREDICT_FALSE (error0 == TCP_ERROR_DISPATCH))
		{
		  tcp_state_t state0 = tc0->state;
		  /* Overload tcp flags to store state */
		  vnet_buffer (b0)->tcp.flags = tc0->state;
		  clib_warning ("disp error state %U flags %U",
				format_tcp_state, &state0,
				format_tcp_flags, flags0);
		}
	    }
	  else
	    {
	      /* Send reset */
	      next0 = TCP_INPUT_NEXT_RESET;
	      error0 = TCP_ERROR_NO_LISTENER;
	    }

	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
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
  /* ACK for for a SYN-ACK -> tcp-rcv-process. */
  _(SYN_RCVD, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
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
  /* ACK or FIN-ACK to our FIN */
  _(FIN_WAIT_1, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_1, TCP_FLAG_ACK | TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  /* FIN in reply to our FIN from the other side */
  _(FIN_WAIT_1, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  /* FIN confirming that the peer (app) has closed */
  _(FIN_WAIT_2, TCP_FLAG_FIN, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
  _(FIN_WAIT_2, TCP_FLAG_FIN | TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS,
    TCP_ERROR_NONE);
  _(LAST_ACK, TCP_FLAG_ACK, TCP_INPUT_NEXT_RCV_PROCESS, TCP_ERROR_NONE);
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
