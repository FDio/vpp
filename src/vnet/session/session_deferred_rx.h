/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_session_deferred_rx_h__
#define __included_session_deferred_rx_h__

#include <vnet/session/session_types.h>
#include <svm/svm_fifo.h>

/* All operations must run on the session's owning thread. */

typedef svm_fifo_seg_t session_deferred_rx_segment_t;

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

/** Copy all remaining deferred payload into the RX FIFO. */
int session_flush_deferred_rx (session_t *s);

/** Discard all remaining deferred payload without copying it to the RX FIFO. */
int session_discard_deferred_rx (session_t *s);

#endif /* __included_session_deferred_rx_h__ */
