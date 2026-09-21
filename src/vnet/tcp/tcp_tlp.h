/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_TLP_H_
#define SRC_VNET_TCP_TCP_TLP_H_

#include <vnet/tcp/tcp_rack.h>

always_inline u8
tcp_tlp_is_pending (tcp_connection_t *tc)
{
  return !!(tc->flags & TCP_CONN_TLP_PENDING);
}

void tcp_tlp_recovery_init (tcp_connection_t *tc);
void tcp_tlp_retransmit_disarm_rtt (tcp_connection_t *tc, u32 start, u32 end);
void tcp_tlp_process_ack (tcp_connection_t *tc, u32 ack, tcp_ack_ctx_t *ac);
u8 tcp_tlp_dsack_matches (tcp_connection_t *tc, const sack_block_t *dsack);
u8 tcp_tlp_new_data_fits_cwnd (tcp_connection_t *tc, u32 n_bytes);
u32 tcp_tlp_pto_ticks (tcp_connection_t *tc);
u8 tcp_tlp_retransmit_timer_expired (tcp_connection_t *tc);
void tcp_tlp_send_probe (tcp_connection_t *tc);

#endif /* SRC_VNET_TCP_TCP_TLP_H_ */
