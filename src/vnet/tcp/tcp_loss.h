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

#endif /* SRC_VNET_TCP_TCP_LOSS_H_ */
