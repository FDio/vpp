/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_LOSS_H_
#define SRC_VNET_TCP_TCP_LOSS_H_

#include <vnet/tcp/tcp_types.h>

void tcp_loss_on_ack (tcp_connection_t *tc, tcp_ack_ctx_t *ac);
void tcp_loss_on_rto (tcp_connection_t *tc);
void tcp_loss_enter_recovery (tcp_connection_t *tc);

/* Eifel spurious-retransmit detection (RFC 3522 Sec. 3.2). Spurious if the ACK
 * echoes a timestamp older than the first retransmit and leaves part of the
 * flight outstanding. A full-flight ACK remains ambiguous and requires
 * D-SACK evidence. */
static inline u8
tcp_loss_is_eifel_spurious (tcp_connection_t *tc, tcp_ack_ctx_t *ac)
{
  ASSERT (tcp_in_cong_recovery (tc) && ac->bytes_acked);
  return (tc->snd_rxt_ts && seq_lt (tc->snd_una, tc->snd_congestion) &&
	  tcp_opts_tstamp (&tc->rcv_opts) && timestamp_lt (tc->rcv_opts.tsecr, tc->snd_rxt_ts));
}

static_always_inline u8
tcp_loss_default_should_enter_recovery (tcp_connection_t *tc, tcp_ack_ctx_t *ac, u8 has_sack)
{
  if (!has_sack && seq_leq (tc->snd_una, tc->snd_congestion) &&
      ((!(tc->cwnd > tc->snd_mss && ac->bytes_acked <= 4 * tc->snd_mss)) ||
       (tc->rcv_opts.tsecr != tc->tsecr_last_ack)))
    {
      /* RFC 6582 heuristic: this duplicate ACK probably followed an RTO. */
      tc->rcv_dupacks = 0;
      return 0;
    }

  return tc->sack_sb.lost_bytes || tc->rcv_dupacks >= tc->sack_sb.reorder;
}

static_always_inline u8
tcp_loss_should_enter_recovery (tcp_connection_t *tc, tcp_ack_ctx_t *ac, u8 has_sack)
{
  if (PREDICT_FALSE (!(ac->ack_flags & TCP_ACK_F_DUPACK)))
    return 0;

  return tcp_loss_default_should_enter_recovery (tc, ac, has_sack);
}

static_always_inline u8
tcp_loss_should_reenter_recovery (tcp_connection_t *tc, tcp_ack_ctx_t *ac, u8 has_sack)
{
  return tcp_loss_default_should_enter_recovery (tc, ac, has_sack);
}

#endif /* SRC_VNET_TCP_TCP_LOSS_H_ */
