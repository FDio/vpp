/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_session_deferred_io_h__
#define __included_session_deferred_io_h__

#include <vnet/session/session_types.h>
#include <svm/svm_fifo.h>

/* All operations must run on the session's owning thread. */

typedef svm_fifo_seg_t session_deferred_rx_segment_t;

typedef struct session_deferred_rx_worker_ session_deferred_rx_worker_t;

typedef struct
{
  const session_deferred_rx_segment_t *segments;
  u32 n_segments;
  u32 data_len;
  u32 owner_thread_index;
} session_deferred_rx_batch_t;

/**
 * Enable or disable deferred RX copying for a session.
 *
 * Enabling deferred RX lets a built-in application inspect staged TCP RX data
 * before it is copied into the RX FIFO. Deferred segments may remain pending
 * after an RX callback returns, but the application must eventually acquire,
 * flush, or discard them on the session's owning thread. Staged and acquired
 * descriptors share a per-worker limit; data is copied into the FIFO when the
 * limit prevents a new buffer from being staged.
 */
int session_set_deferred_rx (session_t *s, u8 enable);

/**
 * Return a read-only view of the ordered payload segments currently deferred
 * for a session.
 *
 * The descriptor storage and payload buffers are owned by the session layer.
 * The descriptor view remains valid only until deferred state changes or more
 * RX data is staged. Applications leaving segments pending across dispatches
 * must call this function again instead of retaining the returned view.
 */
const session_deferred_rx_segment_t *session_get_deferred_rx_segments (session_t *s, u32 *n_segs);

/**
 * Acquire all currently deferred payload segments.
 *
 * The segments are removed from the RX FIFO's logical producer state and
 * their descriptor storage and backing buffers become owned by @p batch. This
 * consumes the stream bytes for transport RX-window accounting. The returned
 * segment view remains valid until the batch is released, including if the
 * session is subsequently closed.
 *
 * Returns the number of acquired bytes, zero if no data is deferred, or a
 * FIFO error. @p batch must be zero-initialized or previously released, and
 * must be released on the session's owning thread before it is reused.
 */
int session_acquire_deferred_rx_segments (session_t *s, session_deferred_rx_batch_t *batch);

/**
 * Release an acquired batch of deferred RX segments.
 *
 * Transport accounting was completed when the batch was acquired; releasing
 * it only returns the backing buffers. The batch is cleared before this
 * function returns.
 */
void session_release_deferred_rx_segments (session_deferred_rx_batch_t *batch);

/** Remove retained deferred RX roots from a vector of buffer indices. */
u32 session_deferred_rx_compact_buffer_indices (session_deferred_rx_worker_t *deferred_wrk,
						u32 *buffer_indices, u32 n_buffers);

/** Copy all remaining deferred payload into the RX FIFO. */
int session_flush_deferred_rx (session_t *s);

/** Discard all remaining deferred payload without copying it to the RX FIFO. */
int session_discard_deferred_rx (session_t *s);

#endif /* __included_session_deferred_io_h__ */
