/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/session/session_deferred_io.h>
#include <vnet/buffer.h>

/* Retained buffers keep their segment in opaque2. TCP RX is finished with it
 * when it hands payload to the session, and apps give it up when they enqueue
 * TX buffers. Keep VLIB's next_buffer link intact for chains and buffer free. */
STATIC_ASSERT (sizeof (((vnet_buffer_opaque2_t *) 0)->unused) >= sizeof (svm_fifo_async_seg_t),
	       "deferred segment metadata must fit");
STATIC_ASSERT (STRUCT_OFFSET_OF (vnet_buffer_opaque2_t, unused) % 8 == 0,
	       "deferred segment metadata must be aligned");

#define SESSION_DIO_FREE_BATCH 64

static_always_inline svm_fifo_async_seg_t *
session_dio_seg (vlib_buffer_t *b)
{
  return (svm_fifo_async_seg_t *) vnet_buffer2 (b)->unused;
}

/* Link a chain's data buffers into f as segments charged to the n_used budget.
 * The last data segment carries the root, which frees the whole chain. Return
 * bytes staged, or a FIFO error with nothing staged. */
static_always_inline int
session_dio_stage_chain (vlib_main_t *vm, svm_fifo_t *f, vlib_buffer_t *b, u32 *n_used,
			 u32 max_used)
{
  svm_fifo_async_seg_t *seg;
  vlib_buffer_t *cur = b;
  u32 bi, left, len = 0, n_segs = 0;
  u8 first_seg = 1;
  int rv;

  /* Validate and size the whole chain before staging any of it. */
  while (1)
    {
      if (PREDICT_FALSE (cur->ref_count != 1))
	return SVM_FIFO_EINVAL;

      len += cur->current_length;
      n_segs += cur->current_length != 0;
      if (PREDICT_TRUE (!(cur->flags & VLIB_BUFFER_NEXT_PRESENT)))
	break;
      cur = vlib_get_buffer (vm, cur->next_buffer);
    }

  if (!len)
    return 0;

  if (PREDICT_FALSE (*n_used >= max_used || n_segs > max_used - *n_used))
    return SVM_FIFO_EFULL;

  if (PREDICT_FALSE (svm_fifo_max_enqueue_prod (f) < len))
    return SVM_FIFO_EFULL;

  bi = vlib_get_buffer_index (vm, b);
  left = len;
  cur = b;
  while (1)
    {
      if (cur->current_length)
	{
	  left -= cur->current_length;
	  seg = session_dio_seg (cur);
	  *seg = (svm_fifo_async_seg_t) {
	    .data = vlib_buffer_get_current (cur),
	    .len = cur->current_length,
	    .opaque = left ? SVM_FIFO_ASYNC_OPAQUE_INVALID : bi,
	  };
	  rv = svm_fifo_enqueue_async_segment (f, seg);
	  if (PREDICT_FALSE (first_seg && rv < 0))
	    return rv;

	  ASSERT (rv == seg->len);
	  first_seg = 0;
	}

      if (PREDICT_TRUE (!(cur->flags & VLIB_BUFFER_NEXT_PRESENT)))
	break;
      cur = vlib_get_buffer (vm, cur->next_buffer);
    }

  ASSERT (left == 0);
  *n_used += n_segs;

  return len;
}

/* Copy a chain into fifo-owned segments. Return bytes copied, short only with
 * allow_partial, or a FIFO error with nothing copied. */
static int
session_dio_copy_chain (session_dio_ctx_t *ctx, vlib_main_t *vm, svm_fifo_t *f, vlib_buffer_t *b,
			u8 allow_partial)
{
  svm_fifo_seg_t *seg;

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    {
      svm_fifo_seg_t one = { .data = vlib_buffer_get_current (b), .len = b->current_length };
      return one.len ? svm_fifo_enqueue_async_copy_segments (f, &one, 1, allow_partial) : 0;
    }

  vec_reset_length (ctx->copy_segs);
  while (1)
    {
      if (b->current_length)
	{
	  vec_add2 (ctx->copy_segs, seg, 1);
	  seg->data = vlib_buffer_get_current (b);
	  seg->len = b->current_length;
	}

      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;
      b = vlib_get_buffer (vm, b->next_buffer);
    }

  if (!vec_len (ctx->copy_segs))
    return 0;

  return svm_fifo_enqueue_async_copy_segments (f, ctx->copy_segs, vec_len (ctx->copy_segs),
					       allow_partial);
}

/* Free the segments' buffers and fifo-owned storage, and return the buffer
 * segments to the n_used budget. */
static void
session_dio_free_segments (session_worker_t *wrk, svm_fifo_t *f, svm_fifo_async_seg_t *segs,
			   u32 n_segs, u32 *n_used)
{
  u32 refs[SESSION_DIO_FREE_BATCH], i = 0, n_refs = 0, n_buf_segs = 0;
  svm_fifo_async_seg_t *seg, *next;

  for (seg = segs; seg; seg = next)
    {
      next = seg->next;
      i++;
      if (svm_fifo_async_segment_is_fifo_owned (seg))
	{
	  svm_fifo_async_free_segment (f, seg);
	  continue;
	}
      n_buf_segs++;
      if (seg->opaque != SVM_FIFO_ASYNC_OPAQUE_INVALID)
	{
	  refs[n_refs++] = seg->opaque;
	  if (n_refs == ARRAY_LEN (refs))
	    {
	      vlib_buffer_free (wrk->vm, refs, n_refs);
	      n_refs = 0;
	    }
	}
    }

  ASSERT (i == n_segs);
  ASSERT (*n_used >= n_buf_segs);
  *n_used -= n_buf_segs;
  if (n_refs)
    vlib_buffer_free (wrk->vm, refs, n_refs);
}

static int
session_dio_flush_fifo (session_t *s, svm_fifo_t *f, u8 is_tx)
{
  session_worker_t *wrk;
  svm_fifo_async_seg_t *segs;
  u32 n_segs, n_committed;
  int rv;

  n_segs = svm_fifo_n_async_segments (f);
  if (!n_segs)
    return 0;

  rv = svm_fifo_commit_async_segments (f, &segs, &n_committed);
  if (PREDICT_FALSE (rv < 0))
    return rv;

  ASSERT (n_committed == n_segs);
  wrk = session_main_get_worker (s->thread_index);
  session_dio_free_segments (wrk, f, segs, n_segs,
			     is_tx ? &wrk->dio.n_tx_segs : &wrk->dio.n_rx_segs);

  return rv;
}

/* Deferred io is for built-in TCP apps. Prepare the fifo's async state. */
static int
session_dio_prepare_fifo (session_t *s, svm_fifo_t *f)
{
  app_worker_t *app_wrk = app_worker_get_if_valid (s->app_wrk_index);

  if (!f || session_get_transport_proto (s) != TRANSPORT_PROTO_TCP || !app_wrk ||
      !app_worker_application_is_builtin (app_wrk))
    return SVM_FIFO_EINVAL;

  return svm_fifo_prepare_async (f);
}

/*
 * RX
 */

static_always_inline int
session_dio_rx_stage_buffer (session_worker_t *wrk, session_t *s, vlib_buffer_t *b)
{
  session_dio_ctx_t *ctx = &wrk->dio;
  int rv;

  rv = session_dio_stage_chain (wrk->vm, s->rx_fifo, b, &ctx->n_rx_segs, ctx->max_rx_segs);
  if (rv > 0)
    {
      vec_add1 (ctx->held_buffers, vlib_get_buffer_index (wrk->vm, b));
      wrk->flags |= SESSION_WRK_F_DIO_RX_PENDING;
    }

  return rv;
}

static_always_inline void
session_dio_rx_queue_event (session_worker_t *wrk, session_t *s, transport_connection_t *tc)
{
  if (s->flags & SESSION_F_RX_EVT)
    return;

  s->flags |= SESSION_F_RX_EVT;
  vec_add1 (wrk->session_to_enqueue[tc->proto], session_handle (s));
}

__clib_noinline u8
session_dio_rx_enqueue_or_seal (session_t *s, transport_connection_t *tc, vlib_buffer_t *b,
				u8 queue_event, int *enqueued)
{
  svm_fifo_async_state_t *state = s->rx_fifo->async_state;
  session_worker_t *wrk;
  int rv;

  ASSERT ((s->flags & SESSION_F_DEFERRED_RX) && enqueued);

  /* Extend an unsealed prefix, or start one once normal data drains.
   * Use normal chunks after app close, including late TCP FIN-WAIT data. */
  if (!(s->flags & SESSION_F_APP_CLOSED) && queue_event && !svm_fifo_has_ooo_data (s->rx_fifo) &&
      ((state && state->active && !state->sealed) || !svm_fifo_max_dequeue_prod (s->rx_fifo)))
    {
      ASSERT (s->thread_index == vlib_get_thread_index ());
      wrk = session_main_get_worker (s->thread_index);
      rv = session_dio_rx_stage_buffer (wrk, s, b);
      /* Copy what cannot be retained into fifo-owned segments, which keeps the
       * prefix unsealed. */
      if (PREDICT_FALSE (rv < 0))
	rv = session_dio_copy_chain (&wrk->dio, wrk->vm, s->rx_fifo, b, 1 /* allow_partial */);
      if (rv >= 0)
	{
	  if (rv)
	    session_dio_rx_queue_event (wrk, s, tc);
	  session_fifo_tuning (s, s->rx_fifo, SESSION_FT_ACTION_ENQUEUED, 0);
	  *enqueued = rv;
	  return 1;
	}
    }

  /* Seal the prefix; this and later packets in this run use normal chunks. */
  session_dio_rx_seal (s);

  return 0;
}

__clib_noinline u32
session_dio_rx_compact_buffer_indices (session_dio_ctx_t *ctx, u32 *buffer_indices, u32 n_buffers)
{
  u32 *held = ctx->held_buffers;
  u32 i, n_held = vec_len (held), n_to_free = 0, next_held = 0;

  ASSERT (n_held && n_held <= n_buffers);

  /* Held roots are an in-order subset of the frame, so equal counts mean the
   * whole frame is retained. */
  if (n_held == n_buffers)
    {
      ASSERT (!clib_memcmp (held, buffer_indices, n_buffers * sizeof (u32)));
      vec_reset_length (ctx->held_buffers);
      return 0;
    }

  /* Staged roots are recorded in the order of the input frame. */
  for (i = 0; i < n_buffers; i++)
    {
      if (next_held < n_held && buffer_indices[i] == held[next_held])
	{
	  next_held++;
	  continue;
	}

      buffer_indices[n_to_free++] = buffer_indices[i];
    }

  ASSERT (next_held == n_held);
  vec_reset_length (ctx->held_buffers);

  return n_to_free;
}

static void
session_dio_rx_notify_transport (session_t *s, u32 n_bytes)
{
  svm_fifo_t *f = s->rx_fifo;

  if (svm_fifo_needs_deq_ntf (f, n_bytes))
    {
      svm_fifo_clear_deq_ntf (f);
      session_program_transport_io_evt (s->handle, SESSION_IO_EVT_RX);
    }
}

int
session_dio_rx_flush (session_t *s)
{
  ASSERT (s->thread_index == vlib_get_thread_index ());
  return session_dio_flush_fifo (s, s->rx_fifo, 0 /* is_tx */);
}

int
session_dio_rx_enable_disable (session_t *s, u8 enable)
{
  session_worker_t *wrk;
  int rv;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  if (enable)
    {
      rv = session_dio_prepare_fifo (s, s->rx_fifo);
      if (rv < 0)
	return rv;

      wrk = session_main_get_worker (s->thread_index);
      if (!wrk->dio.held_buffers)
	{
	  vec_validate (wrk->dio.held_buffers, VLIB_FRAME_SIZE - 1);
	  vec_reset_length (wrk->dio.held_buffers);
	}

      s->flags |= SESSION_F_DEFERRED_RX;
      return 0;
    }

  rv = session_dio_rx_flush (s);
  if (rv >= 0)
    {
      svm_fifo_seal_async (s->rx_fifo);
      s->flags &= ~SESSION_F_DEFERRED_RX;
    }

  return rv < 0 ? rv : 0;
}

const session_dio_segment_t *
session_dio_rx_get_segments (session_t *s, u32 *n_segs)
{
  ASSERT (s->thread_index == vlib_get_thread_index () && n_segs);
  *n_segs = svm_fifo_n_async_segments (s->rx_fifo);
  return *n_segs ? s->rx_fifo->async_state->head : 0;
}

int
session_dio_rx_acquire (session_t *s, session_dio_rx_batch_t *batch)
{
  svm_fifo_async_seg_t *segs;
  u32 n_segs;
  int rv;

  ASSERT (batch && s->thread_index == vlib_get_thread_index () && s->flags & SESSION_F_DEFERRED_RX);
  if (PREDICT_FALSE (batch->segments != 0))
    return SVM_FIFO_EINVAL;

  clib_memset (batch, 0, sizeof (*batch));

  rv = svm_fifo_acquire_async_segments (s->rx_fifo, &segs, &n_segs);
  if (rv <= 0)
    return rv;

  batch->segments = segs;
  batch->fifo = s->rx_fifo;
  batch->n_segments = n_segs;
  batch->data_len = rv;
  batch->owner_thread_index = s->thread_index;

  session_dio_rx_notify_transport (s, rv);
  return rv;
}

void
session_dio_rx_release (session_dio_rx_batch_t *batch)
{
  session_worker_t *wrk;

  ASSERT (batch != 0);
  if (!batch->segments)
    return;

  ASSERT (batch->owner_thread_index == vlib_get_thread_index ());
  wrk = session_main_get_worker (batch->owner_thread_index);
  session_dio_free_segments (wrk, batch->fifo, (svm_fifo_async_seg_t *) batch->segments,
			     batch->n_segments, &wrk->dio.n_rx_segs);
  clib_memset (batch, 0, sizeof (*batch));
}

int
session_dio_rx_discard (session_t *s)
{
  session_worker_t *wrk = session_main_get_worker (s->thread_index);
  svm_fifo_async_seg_t *segs;
  u32 n_segs;
  int rv;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  rv = svm_fifo_acquire_async_segments (s->rx_fifo, &segs, &n_segs);
  if (rv <= 0)
    return rv;

  session_dio_free_segments (wrk, s->rx_fifo, segs, n_segs, &wrk->dio.n_rx_segs);
  session_dio_rx_notify_transport (s, rv);
  return rv;
}

/*
 * TX
 */

int
session_dio_tx_enable_disable (session_t *s, u8 enable)
{
  int rv;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  if (enable)
    {
      rv = session_dio_prepare_fifo (s, s->tx_fifo);
      if (rv < 0)
	return rv;

      s->flags |= SESSION_F_DEFERRED_TX;
      return 0;
    }

  rv = session_dio_flush_fifo (s, s->tx_fifo, 1 /* is_tx */);
  if (rv >= 0)
    {
      svm_fifo_seal_async (s->tx_fifo);
      /* Dma workers send every peek session through deferred io */
      if (!session_main_get_worker (s->thread_index)->dma_enabled)
	s->flags &= ~SESSION_F_DEFERRED_TX;
    }

  return rv < 0 ? rv : 0;
}

int
session_dio_tx_enqueue_buffer (session_t *s, vlib_buffer_t *b)
{
  session_worker_t *wrk = session_main_get_worker (s->thread_index);
  session_dio_ctx_t *ctx = &wrk->dio;
  u32 bi, len;
  int rv;

  ASSERT (s->thread_index == vlib_get_thread_index () && (s->flags & SESSION_F_DEFERRED_TX));

  len = vlib_buffer_length_in_chain (wrk->vm, b);
  if (PREDICT_FALSE (!len))
    return 0;

  if (PREDICT_FALSE (svm_fifo_max_enqueue_prod (s->tx_fifo) < len))
    return SVM_FIFO_EFULL;

  rv = session_dio_stage_chain (wrk->vm, s->tx_fifo, b, &ctx->n_tx_segs, ctx->max_tx_segs);
  if (PREDICT_TRUE (rv >= 0))
    return rv;

  /* Copy what cannot be retained, then release the chain */
  rv = session_dio_copy_chain (ctx, wrk->vm, s->tx_fifo, b, 0 /* allow_partial */);
  if (rv > 0)
    {
      bi = vlib_get_buffer_index (wrk->vm, b);
      vlib_buffer_free (wrk->vm, &bi, 1);
    }

  return rv;
}

int
session_dio_tx_enqueue (session_t *s, const u8 *data, u32 len)
{
  ASSERT (s->thread_index == vlib_get_thread_index () && (s->flags & SESSION_F_DEFERRED_TX));
  return svm_fifo_enqueue_async_copy (s->tx_fifo, data, len);
}

int
session_dio_tx_dequeue_drop (session_t *s, u32 len)
{
  svm_fifo_async_seg_t *segs;
  session_worker_t *wrk;
  u32 n_segs;
  int rv;

  rv = svm_fifo_async_dequeue_drop (s->tx_fifo, len, &segs, &n_segs);
  if (n_segs)
    {
      wrk = session_main_get_worker (s->thread_index);
      session_dio_free_segments (wrk, s->tx_fifo, segs, n_segs, &wrk->dio.n_tx_segs);
    }

  return rv;
}
