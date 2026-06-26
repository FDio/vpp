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
 * @return	active retransmission bytes replaced by the new copy
 */
u32 tcp_bt_track_rxt (tcp_connection_t *tc, u32 start, u32 end);

/** Mark a byte-tracker sample lost and retire its active retransmission copy. */
u32 tcp_bt_sample_mark_lost (tcp_connection_t *tc, tcp_bt_sample_t *bts);

/** Derive recovery retransmission delivery from byte-tracker state. */
void tcp_bt_sync_rxt_delivery (tcp_connection_t *tc);
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

typedef void (*tcp_bt_walk_fn_t) (tcp_connection_t *tc, tcp_bt_sample_t *bts, void *opaque);

/** Visit byte-tracker samples overlapping [start, end). */
void tcp_bt_walk_range (tcp_connection_t *tc, u32 start, u32 end, tcp_bt_walk_fn_t fn,
			void *opaque);

/** Split the sample at seq. */
void tcp_bt_split_at (tcp_connection_t *tc, u32 seq);

format_function_t format_tcp_bt;

#endif /* SRC_VNET_TCP_TCP_BT_H_ */
