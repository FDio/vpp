/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_TLP_H_
#define SRC_VNET_TCP_TCP_TLP_H_

#include <vnet/tcp/tcp_rack.h>

always_inline u8
tcp_tlp_is_in_flight (tcp_connection_t *tc)
{
  return !!(tc->flags & TCP_CONN_TLP_IN_FLIGHT);
}

void tcp_tlp_recovery_init (tcp_connection_t *tc);
void tcp_tlp_process_ack (tcp_connection_t *tc, tcp_ack_ctx_t *ac, u8 is_dupack);
u8 tcp_tlp_dsack_matches (tcp_connection_t *tc, const sack_block_t *dsack);
u8 tcp_tlp_retransmit_timer_expired (tcp_connection_t *tc);
void tcp_tlp_send_probe (tcp_connection_t *tc);

#endif /* SRC_VNET_TCP_TCP_TLP_H_ */
