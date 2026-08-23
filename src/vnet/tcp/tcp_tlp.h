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
  return tcp_rack_enabled (tc) && !!(tcp_rack_get_state (tc)->flags & TCP_RACK_F_TLP_IN_FLIGHT);
}

void tcp_tlp_recovery_init (tcp_connection_t *tc);
void tcp_tlp_process_ack (tcp_connection_t *tc, u32 ack, tcp_ack_ctx_t *ac, u8 is_repeated);
u8 tcp_tlp_dsack_matches (tcp_connection_t *tc, const sack_block_t *dsack);
u64 tcp_tlp_pto_deadline (tcp_connection_t *tc, u64 now);
u8 tcp_tlp_retransmit_timer_expired (tcp_connection_t *tc);
void tcp_tlp_send_probe (tcp_connection_t *tc);

#endif /* SRC_VNET_TCP_TCP_TLP_H_ */
