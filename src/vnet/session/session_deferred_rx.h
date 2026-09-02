/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_session_deferred_rx_h__
#define __included_session_deferred_rx_h__

#include <vnet/session/session_types.h>
#include <svm/svm_fifo.h>

/* All operations must run on the session's owning thread. */

/* The opaque value is owned by the session layer.  The experimental take API
 * below allows a built-in application to retain it until release. */
typedef svm_fifo_async_seg_t session_deferred_rx_segment_t;

/**
 * Enable or disable deferred RX copying for a session.
 *
 * Enabling deferred RX transfers ownership of staged RX data to the built-in
 * application. Before returning from each RX callback, the application must
 * consume, flush, or discard all deferred segments.
 */
int session_set_deferred_rx (session_t *s, u8 enable);

/**
 * Return the ordered payload segments currently deferred for a session.
 *
 * The returned storage is owned by the session layer and remains valid until
 * deferred data is consumed, flushed, discarded, or more RX data is staged.
 */
session_deferred_rx_segment_t *session_get_deferred_rx_segments (session_t *s, u32 *n_segs);

/**
 * Consume the first @p n_segs deferred payload segments without copying them
 * to the RX FIFO. Returns the number of bytes consumed or a FIFO error. The
 * application should notify the transport of released RX space as it does
 * after consuming data from the RX FIFO.
 */
int session_consume_deferred_rx_segments (session_t *s, u32 n_segs);

/**
 * Take ownership of all currently deferred payload segments.
 *
 * Unlike session_consume_deferred_rx_segments(), this does not release the
 * opaque buffer references.  The caller must copy the segment descriptors and
 * valid opaque values before returning from the RX callback, then release the
 * references on the owning worker with session_release_deferred_rx_buffers().
 * Partial takes are deliberately not supported by this measurement API.
 */
int session_take_deferred_rx_segments (session_t *s, u32 n_segs);

/** Release buffer references previously retained by a successful take. */
void session_release_deferred_rx_buffers (u32 thread_index, const u32 *buffer_refs,
					  u32 n_buffer_refs);

/** Copy all remaining deferred payload into the RX FIFO. */
int session_flush_deferred_rx (session_t *s);

/** Discard all remaining deferred payload without copying it to the RX FIFO. */
int session_discard_deferred_rx (session_t *s);

#endif /* __included_session_deferred_rx_h__ */
