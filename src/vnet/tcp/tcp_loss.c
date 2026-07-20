/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>

void
tcp_loss_recovery_enter (tcp_connection_t *tc)
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

  tcp_loss_recovery_backend_init (tc);
  tcp_cc_congestion (tc);

  if (!tcp_opts_sack_permitted (&tc->rcv_opts))
    tc->cwnd += TCP_DUPACK_THRESHOLD * tc->snd_mss;

  tc->fr_occurences += 1;
  TCP_EVT (TCP_EVT_CC_EVT, tc, 4);

  tcp_connection_tx_pacer_reset (tc, tc->cwnd, 0 /* start bucket */);
  tcp_program_retransmit (tc);
}

void
tcp_loss_on_rto (tcp_connection_t *tc)
{
  u8 sack_reneged, head_overlaps_rxt;

  TCP_EVT (TCP_EVT_CC_EVT, tc, 6);
  head_overlaps_rxt = tcp_loss_prepare_rto (tc, &sack_reneged);

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
  tcp_loss_recovery_backend_sync (tc);

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
