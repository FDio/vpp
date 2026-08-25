/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_session_deferred_io_h__
#define __included_session_deferred_io_h__

#include <vnet/session/session_types.h>
#include <svm/svm_fifo.h>
#include <vlib/vlib.h>

/* All operations must run on the session's owning thread. */

/* Default maximum number of deferred RX descriptors held by a worker.
 * Override at startup with session { deferred-rx-max-segs <count> }. */
#define SESSION_DEFERRED_RX_MAX_SEGS 64

typedef svm_fifo_seg_t session_deferred_rx_segment_t;

typedef struct
{
  svm_fifo_async_seg_t **free_seg_vecs;
  u32 *held_buffers;
  u32 n_segs;
  u32 max_segs;
} session_deferred_io_ctx_t;

/** Session-layer helpers for staging deferred RX data. */
u8 session_deferred_rx_enqueue_or_flush (session_t *s, transport_connection_t *tc, vlib_buffer_t *b,
					 u8 queue_event, u8 is_in_order, int *enqueued);

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
 * after an RX callback returns. Before closing the session, the application
 * must flush or discard staged segments and release all acquired batches on
 * the session's owning thread. Staged and acquired descriptors share a
 * per-worker limit; data is copied into the FIFO when the limit prevents a new
 * buffer from being staged.
 */
int session_set_deferred_rx (session_t *s, u8 enable);

/**
 * Return a read-only view of the ordered payload segments currently deferred
 * for a session.
 *
 * The descriptor storage and payload buffers are owned by the session layer.
 * Applications should use data and len; opaque is reserved for buffer cleanup.
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
 * segment view remains valid until the batch is released.
 *
 * Returns the number of acquired bytes, zero if no data is deferred, or a
 * FIFO error. @p batch must be zero-initialized or previously released, and
 * must be released on the session's owning thread before it is reused or the
 * session is closed.
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

/** Remove retained deferred RX roots from a frame in processing order. */
u32 session_deferred_rx_compact_buffer_indices (session_deferred_io_ctx_t *deferred_ctx,
						u32 *buffer_indices, u32 n_buffers);

/** Copy all remaining deferred payload into the RX FIFO.
 * Returns a FIFO error without changing pending segments if chunk allocation
 * fails. */
int session_flush_deferred_rx (session_t *s);

/** Discard all remaining deferred payload without copying it to the RX FIFO. */
int session_discard_deferred_rx (session_t *s);

#endif /* __included_session_deferred_io_h__ */
