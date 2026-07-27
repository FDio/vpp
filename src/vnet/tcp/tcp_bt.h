/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

/*
 * Rate estimation
 */

#ifndef SRC_VNET_TCP_TCP_BT_H_
#define SRC_VNET_TCP_TCP_BT_H_

#include <vnet/tcp/tcp_types.h>

typedef struct tcp_bt_rxt_range_
{
  u32 start;
  u32 end;
  u8 is_lost;
} tcp_bt_rxt_range_t;

/**
 * Byte tracker initialize
 *
 * @param tc	connection for which the byte tracker should be allocated and
 * 		initialized
 */
void tcp_bt_init (tcp_connection_t * tc);
/**
 * Byte tracker cleanup
 *
 * @param tc	connection for which the byte tracker should be cleaned up
 */
void tcp_bt_cleanup (tcp_connection_t * tc);
/**
 * Flush byte tracker samples
 *
 * @param tc	tcp connection for which samples should be flushed
 */
void tcp_bt_flush_samples (tcp_connection_t * tc);
/**
 * Track a tcp tx burst
 *
 * @param tc	tcp connection
 */
void tcp_bt_track_tx (tcp_connection_t * tc, u32 len);
/**
 * Track a tcp retransmission
 *
 * @param tc	tcp connection
 * @param start	start sequence number
 * @param end	end sequence number
 */
void tcp_bt_track_rxt (tcp_connection_t * tc, u32 start, u32 end);
/**
 * Apply prepared cumulative ACK and SACK ranges
 *
 * @param tc		tcp connection
 * @param ack		effective cumulative ACK
 * @param high_sacked	highest sequence covered by prepared ranges
 * @param rs		ACK-local result
 */
void tcp_bt_apply_sacks (tcp_connection_t *tc, u32 ack, u32 high_sacked, tcp_rate_sample_t *rs);
void tcp_bt_dsack_recovery_start (tcp_connection_t *tc);
void tcp_bt_dsack_recovery_done (tcp_connection_t *tc);
u8 tcp_bt_dsack_has_history (tcp_connection_t *tc);
tcp_ack_flag_t tcp_bt_dsack_update (tcp_connection_t *tc, u32 packet_ack, const sack_block_t *dsack,
				    u8 had_sack_history);
void tcp_bt_recompute_sack_loss (tcp_connection_t *tc);
void tcp_bt_init_rxt (tcp_connection_t *tc, u32 snd_una);
void tcp_bt_rxt_mark_lost (tcp_connection_t *tc);
u8 tcp_bt_check_sack_reneging (tcp_connection_t *tc);
u8 tcp_bt_is_sane_post_recovery (tcp_connection_t *tc);
u8 tcp_bt_next_rxt_range (tcp_connection_t *tc, u8 have_unsent, u8 *can_rescue, u8 *snd_limited,
			  tcp_bt_rxt_range_t *range);
u8 tcp_bt_last_rxt_range (tcp_connection_t *tc, tcp_bt_rxt_range_t *range);
/**
 * Generate a delivery rate sample from recently acked bytes
 *
 * @param tc	tcp connection
 * @param rs	resulting rate sample
 */
void tcp_bt_sample_delivery_rate (tcp_connection_t * tc,
				  tcp_rate_sample_t * rs);
/**
 * Check if sample to be generated is app limited
 *
 * @param tc	tcp connection
 */
void tcp_bt_check_app_limited (tcp_connection_t * tc);
/**
 * Check if the byte tracker is in sane state
 *
 * Should be used only for testing
 *
 * @param bt	byte tracker
 */
int tcp_bt_is_sane (tcp_byte_tracker_t * bt);

format_function_t format_tcp_bt;

#endif /* SRC_VNET_TCP_TCP_BT_H_ */
