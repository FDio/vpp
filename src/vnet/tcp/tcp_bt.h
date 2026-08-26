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
__clib_export void tcp_bt_init (tcp_connection_t *tc);

/** Initialize a byte tracker with contiguous private extension storage. */
__clib_export void tcp_bt_init_opaque (tcp_connection_t *tc, uword opaque_size);

static_always_inline void *
tcp_bt_opaque (tcp_connection_t *tc)
{
  ASSERT (tc->bt != 0);
  return tc->bt + 1;
}

static_always_inline tcp_bt_tx_order_t *
tcp_bt_tx_order (tcp_connection_t *tc)
{
  ASSERT (tc->bt != 0);
  return &tc->bt->tx_order;
}

/* Compare transmissions by send time, then ending sequence. */
static_always_inline u8
tcp_bt_tx_sent_after (f64 ts, u32 end_seq, f64 other_ts, u32 other_end)
{
  return ts != other_ts ? ts > other_ts : seq_gt (end_seq, other_end);
}

/** Explicitly remove a sample from the transmit-order index. No-op if inactive. */
__clib_export void tcp_bt_tx_order_remove (tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts);

/**
 * Byte tracker cleanup
 *
 * @param tc	connection for which the byte tracker should be cleaned up
 */
__clib_export void tcp_bt_cleanup (tcp_connection_t *tc);
/**
 * Enable or disable byte tracking
 *
 * The tracker can only change state when no data is in flight, because
 * enabling it cannot reconstruct samples for data already transmitted and
 * disabling it would discard samples still needed by acknowledgments.
 *
 * @param tc	connection whose tracker state should change
 * @param enable	non-zero to enable byte tracking
 * @return	0 on success, -1 if data is in flight or RACK requires tracking
 */
__clib_export int tcp_bt_enable (tcp_connection_t *tc, u8 enable);
/**
 * Flush byte tracker samples
 *
 * @param tc	tcp connection for which samples should be flushed
 */
__clib_export void tcp_bt_flush_samples (tcp_connection_t *tc);
/**
 * Track a tcp tx burst
 *
 * @param tc	tcp connection
 */
__clib_export void tcp_bt_track_tx (tcp_connection_t *tc, u32 len);
/**
 * Track a tcp retransmission
 *
 * @param tc	tcp connection
 * @param start	start sequence number
 * @param end	end sequence number
 */
__clib_export void tcp_bt_track_rxt (tcp_connection_t *tc, u32 start, u32 end);

/** Split the byte-tracker sample containing seq, if seq is an interior point. */
__clib_export void tcp_bt_split_at (tcp_connection_t *tc, u32 seq);

/** Rewind retransmission selection to the sample containing seq. */
__clib_export void tcp_bt_rxt_rewind (tcp_connection_t *tc, u32 seq);

/**
 * Apply cumulative ACK and prepared SACK ranges to the byte tracker
 *
 * @param tc		tcp connection
 * @param ack		effective cumulative ACK
 * @param high_sacked	highest sequence covered by prepared ranges
 * @param ac		ACK-local result
 */
void tcp_bt_apply_ack (tcp_connection_t *tc, u32 ack, u32 high_sacked, tcp_ack_ctx_t *ac);
void tcp_bt_loss_on_ack (tcp_connection_t *tc, tcp_ack_ctx_t *ac);
void tcp_bt_dsack_recovery_init (tcp_connection_t *tc);
__clib_export void tcp_bt_dsack_recovery_clear (tcp_connection_t *tc);
__clib_export u32 tcp_bt_dsack_mark_duplicate (tcp_connection_t *tc, u32 start, u32 end);
__clib_export void tcp_bt_recompute_sack_loss (tcp_connection_t *tc);
__clib_export void tcp_bt_init_rxt (tcp_connection_t *tc, u32 snd_una);
__clib_export void tcp_bt_rxt_mark_lost (tcp_connection_t *tc);
/** Handle SACK reneging and optionally restore formerly SACKed samples to the
 * transmit-order index. Consumers that immediately classify all restored
 * samples can leave them unlinked. */
__clib_export u8 tcp_bt_handle_sack_reneging (tcp_connection_t *tc, u8 restore_tx_order);
__clib_export u8 tcp_bt_is_sane_post_recovery (tcp_connection_t *tc);
__clib_export u8 tcp_bt_next_rxt_range (tcp_connection_t *tc, u8 have_unsent, u8 *can_rescue,
					u8 *snd_limited, tcp_rxt_range_t *range);
__clib_export u8 tcp_bt_last_rxt_range (tcp_connection_t *tc, tcp_rxt_range_t *range);
/**
 * Check if sample to be generated is app limited
 *
 * @param tc	tcp connection
 */
__clib_export void tcp_bt_check_app_limited (tcp_connection_t *tc);
/**
 * Check if the byte tracker is in sane state
 *
 * Should be used only for testing
 *
 * @param bt	byte tracker
 */
__clib_export int tcp_bt_is_sane (tcp_byte_tracker_t *bt);

__clib_export format_function_t format_tcp_bt;
format_function_t format_tcp_bt_stats;

#endif /* SRC_VNET_TCP_TCP_BT_H_ */
