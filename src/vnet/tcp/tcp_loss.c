/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>

void
tcp_loss_enter_recovery (tcp_connection_t *tc)
{
  ASSERT (!tcp_in_cong_recovery (tc));

  tcp_fastrecovery_on (tc);
  tcp_dsack_recovery_init (tc);
  tc->snd_congestion = tc->snd_nxt;
  tc->cwnd_acc_bytes = 0;
  tc->rxt_delivered = 0;
  tc->prr_delivered = 0;
  tc->prev_prr_delivered = 0;
  tc->prr_start = tc->snd_una;
  tc->prev_ssthresh = tc->ssthresh;
  tc->prev_cwnd = tc->cwnd;
  tc->snd_rxt_ts = tcp_tstamp (tc);

  tc->snd_rxt_bytes = 0;
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    tcp_sack_init_rxt (tc, tc->snd_una);
  else
    tcp_fastrecovery_first_on (tc);

  tcp_cc_congestion (tc);

  if (!tcp_opts_sack_permitted (&tc->rcv_opts))
    tc->cwnd += TCP_DUPACK_THRESHOLD * tc->snd_mss;

  tc->fr_occurences += 1;
  TCP_EVT (TCP_EVT_CC_EVT, tc, 4);

  tcp_connection_tx_pacer_reset (tc, tc->cwnd, 0 /* start bucket */);
  tcp_program_retransmit (tc);
}

void
tcp_loss_on_ack (tcp_connection_t *tc, tcp_ack_ctx_t *ac)
{
  ASSERT (ac->ack_flags & TCP_ACK_F_DETECT_LOSS);
  ASSERT (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER);

  tcp_bt_loss_on_ack (tc, ac);
}

void
tcp_loss_on_rto (tcp_connection_t *tc)
{
  u32 n_bytes;
  u8 head_overlaps_rxt = 0, head_was_rxt = 0, sack_reneged = 0;

  TCP_EVT (TCP_EVT_CC_EVT, tc, 6);

  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    {
      n_bytes = clib_min (tc->snd_mss, tc->snd_nxt - tc->snd_una);

      /* Snapshot before reneging handling can reset high_rxt. */
      head_was_rxt =
	tcp_in_cong_recovery (tc) && seq_geq (tc->sack_sb.high_rxt, tc->snd_una + n_bytes);
      head_overlaps_rxt = tcp_in_cong_recovery (tc) && seq_gt (tc->sack_sb.high_rxt, tc->snd_una);

      sack_reneged = tcp_sack_handle_reneging (tc);
      tcp_sack_rxt_mark_lost (tc);

      if (head_was_rxt)
	{
	  /* rxt_delivered is aggregate state and can already include part of the range below
	   * high_rxt. Retire no more than the retransmitted bytes still accounted in flight */
	  ASSERT (tc->rxt_delivered <= tc->snd_rxt_bytes);
	  n_bytes = clib_min (n_bytes, tc->snd_rxt_bytes - tc->rxt_delivered);
	  tc->rxt_delivered += n_bytes;
	}
    }

  /* Advance the recovery point to snd_nxt on every rto (RFC 6675) */
  tc->snd_congestion = tc->snd_nxt;

  /* An RTO exits the RFC 7661 non-validated phase */
  tc->cwnd_limited_seq = tc->snd_nxt;

  /* State snapshotted once per congestion event, when the event starts. If we
   * are already in congestion recovery these were taken on entry and must not
   * be overwritten */
  if (!tcp_in_cong_recovery (tc))
    {
      tcp_dsack_recovery_init (tc);
      tc->prev_ssthresh = tc->ssthresh;
      tc->prev_cwnd = tc->cwnd;
      /* Record timestamp. Eifel detection algorithm RFC3522 */
      tc->snd_rxt_ts = tcp_tstamp (tc);
      tcp_cc_congestion (tc);
    }

  if (head_overlaps_rxt || sack_reneged)
    tc->sack_sb.flags |= TCP_DSACK_INELIGIBLE;

  tcp_recovery_on (tc);

  /* Fresh timeout after progress. rto_boff can be cleared mid-recovery by
   * acks that make some progress (tcp_update_rtt), so this is not necessarily
   * the first timeout of the congestion event. */
  if (!tc->rto_boff)
    {
      tc->rtt_ts = 0;
      tc->cwnd_acc_bytes = 0;
      tc->tr_occurences += 1;
      tc->sack_sb.reorder = TCP_DUPACK_THRESHOLD;
    }

  tcp_cc_loss (tc);
}
