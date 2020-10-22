#include <vnet/tcp/tcp_rack.h>
#include <vnet/tcp/tcp_inlines.h>

void tcp_rack_init (tcp_connection_t * tc)
{
  clib_memset (&tc->rack, 0, sizeof (tcp_rack_t));
  clib_memset (&tc->tlp, 0, sizeof (tcp_tlp_t));
  tc->rack.reo_wnd_mult = 1;
  tc->rack.minrtt_window_size = tcp_cfg.minrtt_window_size;
  vec_validate(tc->rack.rtt_window, tc->rack.minrtt_window_size - 1);
  tc->tlp.max_ack_delay = tcp_cfg.delack_time;
  tlp_init (tc);
}

/* Section 6.1 */
void rack_transmit_data (tcp_connection_t * tc, tcp_bt_sample_t * bts)
{
  bts->tx_time = tcp_time_now_us (tc->c_thread_index);
  bts->flags &= ~TCP_BTS_IS_LOST;
  tlp_schedule_loss_probe (tc);
}
void rack_retransmit_data (tcp_connection_t * tc, tcp_bt_sample_t * bts)
{
  bts->flags |= TCP_BTS_IS_RXT;
  rack_transmit_data (tc, bts);
}

f64 rack_get_minrtt_from_window(tcp_connection_t * tc)
{
  int i;
  f64 min = tc->rack.rtt_window[0];
  for(i=1; i<tc->rack.minrtt_window_size; i++)
    {
      if(tc->rack.rtt_window[i] == 0)
        break;
      if(tc->rack.rtt_window[i] < min)
        min = tc->rack.rtt_window[i];
    }
  return min;
}

void rack_update_minrtt_window (tcp_connection_t * tc, f64 rtt)
{
  int i;
  u8 not_filled = 0;
  for(i=0; i<tc->rack.minrtt_window_size; i++)
    {
      if(0 == tc->rack.rtt_window[i])
      { /* fill up the window if not filled completely */
        tc->rack.rtt_window[i] = rtt;
        not_filled = 1;
      }
    }

  if (not_filled)
    return;

  /* slide the window */
  if(tc->rack.minrtt_window_size)
    {
      for(i=0; i<tc->rack.minrtt_window_size-1; i++)
	{
	  tc->rack.rtt_window[i] = tc->rack.rtt_window[i+1];
	}
      tc->rack.rtt_window[tc->rack.minrtt_window_size-1] = rtt;
    }
}


/* Section 6.2 - Step 1 */
void rack_update_min_rtt (tcp_connection_t * tc, u32 ack)
{
  tcp_rack_t *rack = &tc->rack;
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts = bt_lookup_seq (bt, ack);
  f64 rtt;

  if (!bts)
    {
      if (bt && bt->head != TCP_BTS_INVALID_INDEX && tc->snd_una <= ack)
        clib_warning ("something is wrong: unexpected bts==NULL. ack=%u, snd_una=%u. TODO fix if this happens", ack, tc->snd_una);

      return;
    }

  rtt = tcp_time_now_us (tc->c_thread_index) - bts->tx_time;

  rack_update_minrtt_window (tc, rtt);
  rack->rtt = rtt;

  /*get min rtt from last few RTTs and not a global minimum*/
  rack->min_rtt = rack_get_minrtt_from_window(tc);

  rack->rtt_seq = tc->snd_nxt;
}

/* Section 6.2 - Step 2 (1) */
static u8 rack_sent_after (f64 t1, u32 seq1, f64 t2, u32 seq2)
{
  if (t1 > t2)
    return 1;
  else if (t1 == t2 && seq1 > seq2)
    return 1;
  return 0;
}

/* Section 6.2 - Step 2 (2) - loop with bts */
/* This should be called for each segment which is newly ACKed/SACKed.
 *     -- this function is called in the loop of tcp_rcv_sacks()
 *     -- rack_rcv_ack () will be called after the loop
 */
void rack_update_state (tcp_connection_t * tc, tcp_bt_sample_t * bts)
{
  tcp_rack_t *rack = &tc->rack;
  f64 rtt = tcp_time_now_us (tc->c_thread_index) - bts->tx_time;

  if (bts->flags & TCP_BTS_IS_RXT)
    {
      if (tc->tsecr_last_ack < bts->tx_time)
        return;
      if (rtt < rack->min_rtt)
        return;
    }

  rack->rtt = rtt;
  if (rack_sent_after (bts->tx_time, bts->max_seq,
                       rack->xmit_ts, rack->end_seq))
    {
      rack->xmit_ts = bts->tx_time;
      rack->end_seq = bts->max_seq;
    }
  clib_warning ("tc=%p, rtt=%u, xmit_ts=%u, end_seq=%u", tc, rack->rtt, rack->xmit_ts, rack->end_seq);
}

/* Section 6.2 - Step 3 - loop with bts */
/* This should be called for each segment which is newly ACKed/SACKed.
 *     -- this function is called in the loop of tcp_rcv_sacks()
 *     -- rack_rcv_ack () will be called after the loop
 *
 * TODO consider : Can we make equivalent decision without looping bts?
 * Because we will loop bts to detect loss, maybe we can rely on simplified
 * logic to detect reordering. But if we loose the reordering-detection condition,
 * we may need to have an unnecessary loop of bts for loss detection.
 * Probrably, we should put reordering-detection and loss-detection in a same loop.
 */

u8 rack_detect_reordering (tcp_connection_t * tc,  char* file, int line)
{
  tcp_rack_t *rack = &tc->rack;
  sack_scoreboard_t *sb = &tc->sack_sb;
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts;

  bts = bt_get_sample (bt, bt->head);
  while (bts && !rack->reordering_seen)
    {
      rack_detect_reordering_i (tc, sb, bts);
      bts = bt_next_sample (bt, bts);
    }

  return rack->reordering_seen;
}

void rack_detect_reordering_i (tcp_connection_t * tc, sack_scoreboard_t * sb, tcp_bt_sample_t * bts)
{
  tcp_rack_t *rack = &tc->rack;
  rack->fack = sb->high_sacked;

  /* Note: rack->fack can be 0 */

  /* TODO check
   * RFC says [Segment.retransmitted is FALSE] is needed condition, but it may prevent re-retransmission
   */
#if 0
  if (!rack->reordering_seen && bts && bts->max_seq < rack->fack && !(bts->flags & TCP_BTS_IS_RXT) && !(bts->flags & TCP_BTS_IS_SACKED))
#else
  if (!rack->reordering_seen && bts && bts->max_seq < rack->fack && !(bts->flags & TCP_BTS_IS_SACKED))
#endif
    {
      rack->reordering_seen = 1;
    }
}

/* Section 6.2 - Step 4 */
/* To be called after rack_detect_reordering(), which update rack->reordering_seen
 */
void rack_update_reo_wnd (tcp_connection_t * tc)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  tcp_rack_t *rack = &tc->rack;
  u32 snd_mss = tc->snd_mss;
  f64 srtt = tc->srtt * TCP_TICK;

  /* DSACK is not supported, so DSACK related code is omitted */

  /* sb->reorder = TCP_DUPACK_THRESHOLD */
  u32 dup_thresh = sb->reorder * snd_mss;

  if (!rack->reordering_seen)
    {
      /* TODO optimize the if-condition
       * it is described as IETF documentation for now, just for clarity
       */
      if (tcp_in_cong_recovery (tc))
        {
          rack->reo_wnd = 0;
          return;
        }
      else if (sb->sacked_bytes >= dup_thresh)
        {
          rack->reo_wnd = 0;
          return;
        }
    }

#if 1
    rack->reo_wnd = clib_min (rack->min_rtt / 4.0, srtt);
#else
    /* rack->reo_wnd_mult is always 1, where DSACK is not supported */
    rack->reo_wnd = clib_min (rack->min_rtt / 4.0 * rack->reo_wnd_mult, srtt);
#endif
}

/* Section 6.2 - Step 5 */
/* rack_detect_loss_and_arm_timer() is called when
 *   - an ACK is received			-- tcp_rcv_sacks()
 *   - RACK reordering timer expires		-- this timer is optional
 */

/* Section 6.2 - Step 5 (1) - loop with bts and take the max */
static f64 rack_detect_loss_i (tcp_connection_t * tc, tcp_bt_sample_t * bts)
{
  tcp_rack_t *rack = &tc->rack;
  f64 timeout = 0;
  f64 now = tcp_time_now_us (tc->c_thread_index);

  /* TODO It can be refined for improvement :
   * "an implementation can choose to check only
   * segments that have been sent before RACK.xmit_ts"
   */
  if (!(bts->flags & TCP_BTS_IS_SACKED) &&
      rack_sent_after(rack->xmit_ts, rack->end_seq,
                      bts->tx_time, bts->max_seq))
    {
      f64 remaining = bts->tx_time + rack->rtt + rack->reo_wnd - now;
      if (remaining <= 0)
        {
          bts->flags |= TCP_BTS_IS_LOST;
          rack->lost_bytes += bts->max_seq - bts->min_seq;
	}
      else
        {
	  timeout = remaining;
	}
    }
  return timeout;
}

/* Section 6.2 - Step 5 (2) */
static void rack_set_reo_timer (tcp_connection_t * tc, f64 timeout)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);

#if 1 /* TODO is this correct? */
  if (tcp_in_cong_recovery (tc))
    {
      /* respect recovery by non-RACK methods */
      tcp_retransmit_timer_update (&wrk->timer_wheel, tc);
      return;
    }
#endif

  /* no need to set REO timer if there's no in flight byte */
  if (tc->snd_una == tc->snd_nxt && tcp_timer_is_active (tc, TCP_TIMER_REORDER))
    {
      tcp_reordering_timer_reset (&wrk->timer_wheel, tc);
      return;
    }

  if(!tcp_timer_is_active (tc, TCP_TIMER_REORDER))
    {
      tcp_reordering_timer_set (&wrk->timer_wheel, tc, timeout);
    }
}

void rack_reo_timeout_handler (tcp_connection_t * tc)
{
  if (rack_detect_reordering (tc, __FILE__, __LINE__))
    {
      ASSERT (tcp_in_cong_recovery (tc));

      /* This will (indirectly) call
       *   tcp_session_custom_tx()
       *   -> tcp_do_retransmit()
       *   -> rack_detect_loss_and_arm_timer()
       */
      tcp_program_retransmit (tc);
    }
  else
    {
      /* no reordering detected so no loss */
    }
}

int rack_detect_loss_and_arm_timer (tcp_worker_ctx_t * wrk, tcp_connection_t * tc, u32 burst_size)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts, *next;
  f64 timeout = 0;
  u32 to_send, n_bytes, total = 0;
  u32 rxt = 0;
  u8 aborted = 0;

  /* TODO probably we need to update this */
  tcp_worker_stats_inc (wrk, tr_events, 1);

  /* this will be used to calculate tcp_flight_size() */
  tc->rack.lost_bytes = 0;

  bts = bt_get_sample (bt, bt->head);
  while (bts && rxt < burst_size)
    {
      next = bt_next_sample (bt, bts);
      if (bts->flags & TCP_BTS_IS_SACKED)
        {
          bts = next;
          continue;
        }

      timeout = clib_max (rack_detect_loss_i (tc, bts), timeout);
      if (bts->flags & TCP_BTS_IS_LOST)
        {
          to_send = bts->max_seq - bts->min_seq;
          n_bytes = tcp_retransmit_bts (wrk, tc, bts);
          if (!n_bytes)
            {
              // short on buffers, schedule a quick retry
              // TODO consider : maybe REO timeout handler is more suitable
              if(!tcp_timer_is_active (tc, TCP_TIMER_REORDER) && !tcp_timer_is_active (tc, TCP_TIMER_TLP))
                tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT, 1);
              aborted = 1;
              break;
	    }

          tcp_worker_stats_inc (wrk, rack_retransmit, 1);

          total += n_bytes;
          rxt += 1;

          if (n_bytes < to_send)
	    {
              aborted = 0;
              break;
            }

          rack_retransmit_data (tc, bts);
        }

      bts = next;
    }

  if (total > 0)
    {
      tlp_init (tc);
      tc->bytes_retrans += total;
      tc->segs_retrans += rxt;
      tcp_worker_stats_inc (wrk, rxt_segs, rxt);
    }

  if (!aborted && (rxt < burst_size))
    {
      /* segments to be retransmitted are all retranmitted */
      tc->rack.reordering_seen = 0;
    }

  if (timeout)
    rack_set_reo_timer (tc, timeout);
  else if (aborted)
    {
      /* quick retry */
      ASSERT (tcp_in_cong_recovery (tc));
      tcp_program_retransmit (tc);
    }
  else if (rxt > 0)
    tlp_schedule_loss_probe (tc);

  return rxt;
}

/* Section 6.3 */
/* Implemented in tcp_timer_retransmit_handler() */


/* Section 7.1 */
/* to be called when 
 *   - initiating a connection,		--- tcp_connection_alloc () / tcp_connection_alloc_w_base ()
 *   - fast recovery,			--- tcp_cc_init_congestion ()
 *   - RTO recovery.			--- tcp_cc_init_rxt_timeout ()
 */
void tlp_init (tcp_connection_t * tc)
{
  tcp_tlp_t *tlp = &tc->tlp;
  tlp->end_seq = 0;
  tlp->is_retrans = 0;

  /* TODO check : do we need to reset TLP timer? */
}

/* Section 7.2 */
static f64 tlp_calc_PTO (tcp_connection_t * tc)
{
  tcp_tlp_t *tlp = &tc->tlp;
  f64 now = tcp_time_now_us (tc->c_thread_index);
  f64 rto_expiration_at = tc->expire_at[TCP_TIMER_RETRANSMIT];
  f64 pto;
  f64 srtt = tc->srtt * TCP_TICK;

  if (tc->srtt)
    {
      pto = 2 * srtt;

      /* TODO Should implement something to set tlp->max_ack_delay.
       * Otherwise, this is meaningless.
       * See Section 9.4
       */
      if (tcp_flight_size (tc) <= tc->snd_mss)
        pto += tlp->max_ack_delay * TCP_TIMER_TICK;
    }
  else
    pto = 1.0;

  /* PTO is equal to or sooner than RTO */
  if (rto_expiration_at != 0 && now + pto > rto_expiration_at)
    {
      pto = clib_max (0, rto_expiration_at - now);
    }

  return pto;
}

// to be called at any xmit/rxt		-- tcp_session_push_header (), and so on
void tlp_schedule_loss_probe (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);

  if (!(tc->flags & TCP_CONN_RACK_APPLIED))
    return;

  if (tcp_in_cong_recovery (tc))
    {
      /* respect non-RACK non-TLP recovery methods */
      tcp_retransmit_timer_update (&wrk->timer_wheel, tc);
      return;
    }

  f64 tlp_timeout = tlp_calc_PTO (tc);

  if (!tcp_timer_is_active (tc, TCP_TIMER_TLP))
    {
      tlp_timeout = clib_max (tlp_timeout, 0.000001);
      tcp_tlp_timer_set (&wrk->timer_wheel, tc, tlp_timeout);
    }
  /* TODO if is_active, do we need to update? */
}

/* Section 7.3 */
static void tlp_send_probe (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  tcp_tlp_t *tlp = &tc->tlp;
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts = NULL;
  u32 offset, unsent;

  ASSERT (tc->flags & TCP_CONN_RACK_APPLIED);

  if (tlp->end_seq == 0)
    {
      offset = tc->snd_nxt - tc->snd_una;
      unsent = transport_max_tx_dequeue (&tc->connection) - offset;
      tlp->is_retrans = 0;

      if (unsent > 0 && unsent <= tc->snd_wnd)
        {
          u32 burst_bytes = transport_connection_tx_pacer_burst (&tc->connection);
          u32 burst_size = burst_bytes / tc->snd_mss;
          u32 last_seq = tc->snd_nxt;

          if (tcp_transmit_unsent (wrk, tc, burst_size) > 0)
            {
              /* assuming bts corresponds to the segments just sent now */
              bts = bt_lookup_seq (bt, last_seq);
              rack_transmit_data (tc, bts);
              tlp->end_seq = tc->snd_nxt;
              tcp_worker_stats_inc (wrk, tlp_sent, 1);

            }
        }
      else
        {
          if (tc->snd_nxt == tc->snd_una)
            return;

          bts = bt_lookup_seq (bt, tc->snd_nxt - 1);

          if (tcp_retransmit_bts (wrk, tc, bts) > 0)
            {
              tlp->is_retrans = 1;
              rack_retransmit_data (tc, bts);
              tlp->end_seq = tc->snd_nxt;
              tcp_worker_stats_inc (wrk, tlp_sent, 1);

            }
        }
    }

  /* Section 7.3
   *   After attempting to send a loss probe, regardless of whether a loss
   *   probe was sent, the sender MUST re-arm the RTO timer, not the PTO
   *   timer, if FlightSize is not zero.
   */
  if (tcp_flight_size (tc) > 0)
    {
      tcp_reordering_timer_reset (&wrk->timer_wheel, tc);
      tcp_tlp_timer_reset (&wrk->timer_wheel, tc);
      tcp_retransmit_timer_update (&wrk->timer_wheel, tc);
    }
  else
    tlp_schedule_loss_probe (tc);
}

void tlp_timeout_handler (tcp_connection_t * tc)
{
  tlp_send_probe (tc);
}

/* Section 7.4.2 */
/* This should be called for ACK, and also for dup-ACK as well */
/* TODO check if this is really correct.
 * The term 'SEG.ACK' in the document is ambiguous
 */
void tlp_process_ack (tcp_connection_t * tc, u32 ack)
{
  tcp_tlp_t *tlp = &tc->tlp;
  if (tlp->end_seq != 0 && ack >= tlp->end_seq)
    {
      if (!tlp->is_retrans)
        tlp->end_seq = 0;
#if 0
      else if (ACK has a DSACK option matching TLP.end_seq)
        tlp->end_seq = 0;
#endif
      else if (ack > tlp->end_seq)
        tlp->end_seq = 0;
#if 0
      else if (ACK is a DUPACK without any SACK option)
        tlp->end_seq = 0;
#endif
    }
}

