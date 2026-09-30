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

/* Default maximum number of retained RX buffer segments per worker.
 * Override at startup with session { deferred-rx-max-segs <count> }. */
#define SESSION_DEFERRED_RX_MAX_SEGS (2 * VLIB_FRAME_SIZE)

typedef svm_fifo_async_seg_t session_deferred_rx_segment_t;

typedef struct
{
  u32 *held_buffers;
  u32 n_segs;
  u32 max_segs;
} session_deferred_io_ctx_t;

/** Session-layer helpers for staging deferred RX data. */
__clib_export u8 session_deferred_rx_enqueue_or_seal (session_t *s, transport_connection_t *tc,
						      vlib_buffer_t *b, u8 queue_event,
						      u8 is_in_order, int *enqueued);

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
 * Enabling deferred RX lets a built-in application read TCP RX data directly
 * from retained packet buffers. The buffer-backed bytes count toward FIFO
 * occupancy. While a prefix is pending, the application must use the deferred
 * segment APIs; generic FIFO data reads are unsupported while a prefix is
 * pending. The TCP receive path seals the FIFO before ordinary writes.
 * Applications using chunk access or writing directly after an unsealed
 * acquisition must call svm_fifo_seal_async() first.
 * The first write that cannot retain another buffer seals the prefix, and
 * subsequent bytes use ordinary FIFO chunks. Before closing the session, the
 * application must flush or discard the prefix and release all acquired
 * batches on the session's owning thread. Staged and acquired segments
 * share a per-worker limit.
 */
__clib_export int session_set_deferred_rx (session_t *s, u8 enable);

/**
 * Return the head of the linked payload segments currently deferred for a
 * session. Walk the list using segment->next.
 *
 * The segment nodes live in retained buffer metadata and are owned by the
 * session layer.
 * Applications should use data and len; opaque is reserved for buffer cleanup.
 * The list view remains valid only until deferred state changes or more
 * RX data is staged. Applications leaving segments pending across dispatches
 * must call this function again instead of retaining the returned view.
 */
__clib_export const session_deferred_rx_segment_t *session_get_deferred_rx_segments (session_t *s,
										     u32 *n_segs);

/**
 * Acquire all currently deferred payload segments.
 *
 * The FIFO head advances past the buffer-backed prefix. Any normal chunk
 * suffix remains readable. The linked nodes and backing buffers become
 * owned by @p batch; the returned view remains valid until batch release.
 *
 * Returns the number of acquired bytes, zero if no data is deferred, or a
 * FIFO error. @p batch must be zero-initialized or previously released, and
 * must be released on the session's owning thread before it is reused or the
 * session is closed.
 */
__clib_export int session_acquire_deferred_rx_segments (session_t *s,
							session_deferred_rx_batch_t *batch);

/**
 * Release an acquired batch of deferred RX segments.
 *
 * Transport accounting was completed when the batch was acquired; releasing
 * it only returns the backing buffers. The batch is cleared before this
 * function returns.
 */
__clib_export void session_release_deferred_rx_segments (session_deferred_rx_batch_t *batch);

/** Remove retained deferred RX roots from a frame in processing order. */
__clib_export u32 session_deferred_rx_compact_buffer_indices (
  session_deferred_io_ctx_t *deferred_ctx, u32 *buffer_indices, u32 n_buffers);

/** Copy the remaining buffer-backed prefix into normal chunks.
 * The FIFO head and tail do not move. Returns a FIFO error without changing
 * pending buffer segments if chunk allocation fails. */
__clib_export int session_flush_deferred_rx (session_t *s);

/** Discard all remaining deferred payload without copying it to the RX FIFO. */
__clib_export int session_discard_deferred_rx (session_t *s);

#endif /* __included_session_deferred_io_h__ */
