/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>

static void
tcp_cc_init_congestion (tcp_connection_t *tc)
{
  tcp_fastrecovery_on (tc);
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
    scoreboard_init_rxt (&tc->sack_sb, tc->snd_una);
  else
    tcp_fastrecovery_first_on (tc);

  tcp_cc_congestion (tc);

  if (!tcp_opts_sack_permitted (&tc->rcv_opts))
    tc->cwnd += TCP_DUPACK_THRESHOLD * tc->snd_mss;

  tc->fr_occurences += 1;
  TCP_EVT (TCP_EVT_CC_EVT, tc, 4);
}

void
tcp_cc_enter_recovery (tcp_connection_t *tc)
{
  ASSERT (!tcp_in_cong_recovery (tc));

  tcp_cc_init_congestion (tc);
  tcp_connection_tx_pacer_reset (tc, tc->cwnd, 0 /* start bucket */);
  tcp_program_retransmit (tc);
}
