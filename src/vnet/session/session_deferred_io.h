/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_session_deferred_io_h__
#define __included_session_deferred_io_h__

#include <vnet/session/session_types.h>
#include <svm/svm_fifo.h>
#include <vlib/vlib.h>

/* Deferred IO (dio): stream bytes held outside fifo chunks, e.g., retained
 * RX packets or buffers apps enqueue for TX, until consumed or copied into
 * chunks. All operations must run on the session's owning thread. */

/* Default maximum number of retained buffer segments per worker and direction.
 * Override at startup with session { deferred-rx-max-segs <count> } and
 * session { deferred-tx-max-segs <count> }. */
#define SESSION_DIO_RX_MAX_SEGS (2 * VLIB_FRAME_SIZE)
#define SESSION_DIO_TX_MAX_SEGS (2 * VLIB_FRAME_SIZE)

typedef svm_fifo_async_seg_t session_dio_segment_t;

typedef struct
{
  u32 *held_buffers;
  svm_fifo_seg_t *copy_segs; /**< scratch for copying chains */
  u32 n_rx_segs;
  u32 max_rx_segs;
  u32 n_tx_segs;
  u32 max_tx_segs;
} session_dio_ctx_t;

/** Exclude retained roots from buffer_indices and return the number left to
 * free. The caller clears the worker's pending flag. */
__clib_export u32 session_dio_rx_compact_buffer_indices (session_dio_ctx_t *ctx,
							 u32 *buffer_indices, u32 n_buffers);

/** Enqueue in-order data. Return 1 with *enqueued set, or seal for normal
 * writes and return 0. */
__clib_export u8 session_dio_rx_enqueue_or_seal (session_t *s, transport_connection_t *tc,
						 vlib_buffer_t *b, u8 queue_event, int *enqueued);

/** Seal the prefix before out-of-order data is written into chunks. */
static inline void
session_dio_rx_seal (session_t *s)
{
  if (svm_fifo_async_needs_seal (s->rx_fifo))
    svm_fifo_seal_async (s->rx_fifo);
}

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

/**
 * Enable or disable deferred TX for a built-in TCP session.
 *
 * Once enabled, write the tx fifo only with the deferred TX enqueue APIs.
 * Retained buffers stay in the fifo until acknowledged; others are copied into
 * fifo-owned segments, so the stream never needs sealing. Disabling copies
 * pending bytes into normal chunks. Retained buffers share a per-worker limit.
 *
 * Workers with dma send all peek transport sessions through deferred TX, so
 * the flag is set without the app enabling it and stays set on disable. Those
 * apps keep writing normally unless they use the deferred TX enqueue APIs.
 */
__clib_export int session_dio_tx_enable_disable (session_t *s, u8 enable);

/**
 * Append a buffer chain to the tx stream.
 *
 * On success the session owns the chain: it is retained until acknowledged, or
 * copied and freed if it cannot be, e.g., over the limit or shared. Segment
 * metadata lives in opaque2, so leave it alone. Return bytes enqueued, or zero
 * or a FIFO error, e.g., if the chain does not fit, with the caller still
 * owning the chain.
 */
__clib_export int session_dio_tx_enqueue_buffer (session_t *s, vlib_buffer_t *b);

/** Copy bytes into the tx stream. Writes what fits, like svm_fifo_enqueue(). */
__clib_export int session_dio_tx_enqueue (session_t *s, const u8 *data, u32 len);

/** Drop acknowledged bytes and release their buffers. Used by transports. */
__clib_export int session_dio_tx_dequeue_drop (session_t *s, u32 len);

#endif /* __included_session_deferred_io_h__ */
