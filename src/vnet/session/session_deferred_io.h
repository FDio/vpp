/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_session_deferred_io_h__
#define __included_session_deferred_io_h__

#include <vnet/session/session_types.h>
#include <svm/svm_fifo.h>
#include <vlib/vlib.h>

/* Deferred IO (dio): stream bytes held outside fifo chunks, e.g., retained RX
 * buffers, until consumed or copied into chunks.
 * All operations must run on the session's owning thread. */

/* Default maximum number of retained RX buffer segments per worker.
 * Override at startup with session { deferred-rx-max-segs <count> }. */
#define SESSION_DIO_RX_MAX_SEGS (2 * VLIB_FRAME_SIZE)

typedef svm_fifo_async_seg_t session_dio_segment_t;

typedef struct
{
  u32 *held_buffers;
  u32 n_segs;
  u32 max_segs;
} session_dio_ctx_t;

/** Exclude retained roots from buffer_indices and return the number left to
 * free. The caller clears the worker's pending flag. */
__clib_export u32 session_dio_rx_compact_buffer_indices (session_dio_ctx_t *ctx,
							 u32 *buffer_indices, u32 n_buffers);

/** Return 1 with *enqueued set, or seal for normal writes and return 0. */
__clib_export u8 session_dio_rx_enqueue_or_seal (session_t *s, transport_connection_t *tc,
						 vlib_buffer_t *b, u8 queue_event, u8 is_in_order,
						 int *enqueued);

typedef struct
{
  const session_dio_segment_t *segments;
  svm_fifo_t *fifo; /**< owns any fifo-owned segments */
  u32 n_segments;
  u32 data_len;
  u32 owner_thread_index;
} session_dio_rx_batch_t;

/**
 * Enable or disable deferred RX for a built-in TCP session.
 *
 * Retained bytes count toward FIFO occupancy and require the deferred
 * segment APIs. Buffers that cannot be retained, e.g., over the limit or
 * shared, are copied into fifo-owned segments and the prefix stays unsealed.
 * Out-of-order data seals it and later writes go into chunks.
 * Acquire or flush the prefix before chunk access (including
 * svm_fifo_max_read_chunk() and svm_fifo_dequeue_drop_all()). After an
 * unsealed acquisition, call svm_fifo_seal_async() before chunk access or
 * direct writes.
 *
 * Flush or discard the prefix and release all batches before closing.
 * Pending and acquired buffer segments share a per-worker limit; copied
 * segments do not count toward it.
 */
__clib_export int session_dio_rx_enable_disable (session_t *s, u8 enable);

/**
 * Borrow the linked deferred segment list; walk it with segment->next.
 *
 * The session owns the segments and buffers; use data and len, leaving opaque
 * for cleanup. The view expires when deferred state changes or more RX data
 * is staged; fetch it again across dispatches.
 */
__clib_export const session_dio_segment_t *session_dio_rx_get_segments (session_t *s, u32 *n_segs);

/**
 * Acquire the deferred prefix, advancing FIFO head and preserving any suffix.
 *
 * Ownership of the segments and buffers passes to @p batch until release.
 * @p batch must be zero-initialized or released; release it before reuse or
 * session close.
 *
 * Return acquired bytes, zero if none, or a FIFO error.
 */
__clib_export int session_dio_rx_acquire (session_t *s, session_dio_rx_batch_t *batch);

/** Free the batch's buffers and clear it. Transport accounting occurs on acquisition. */
__clib_export void session_dio_rx_release (session_dio_rx_batch_t *batch);

/** Copy the deferred prefix into normal chunks without moving head or tail.
 * Allocation failure returns a FIFO error and leaves the prefix intact. */
__clib_export int session_dio_rx_flush (session_t *s);

/** Discard all remaining deferred payload without copying it to the rx fifo. */
__clib_export int session_dio_rx_discard (session_t *s);

#endif /* __included_session_deferred_io_h__ */
