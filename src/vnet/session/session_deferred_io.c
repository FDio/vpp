/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/session/session_deferred_io.h>

session_deferred_rx_worker_t *
session_deferred_rx_worker_get (session_worker_t *wrk)
{
  session_deferred_rx_worker_t *deferred_wrk;

  if (wrk->deferred_rx)
    return wrk->deferred_rx;

  deferred_wrk = clib_mem_alloc_or_null (sizeof (*deferred_wrk));
  if (!deferred_wrk)
    return 0;
  clib_memset (deferred_wrk, 0, sizeof (*deferred_wrk));
  wrk->deferred_rx = deferred_wrk;
  return deferred_wrk;
}

static_always_inline int
session_deferred_rx_stage_buffer (session_t *s, transport_connection_t *tc, vlib_buffer_t *b)
{
  session_deferred_rx_worker_t *deferred_wrk;
  session_worker_t *wrk;
  svm_fifo_async_seg_t seg;
  vlib_buffer_t *cur;
  u32 bi, left, n_segs = 0;
  u32 len = 0;
  int rv;

  wrk = session_main_get_worker (s->thread_index);
  deferred_wrk = wrk->deferred_rx;
  if (PREDICT_FALSE (!deferred_wrk))
    {
      deferred_wrk = session_deferred_rx_worker_get (wrk);
      if (!deferred_wrk)
	return SVM_FIFO_EGROW;
    }
  ASSERT (s->thread_index == vlib_get_thread_index ());
  cur = b;

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    {
      if (!b->current_length)
	return 0;
      if (PREDICT_FALSE (deferred_wrk->n_segs >= SESSION_DEFERRED_RX_MAX_SEGS))
	return SVM_FIFO_EFULL;

      seg = (svm_fifo_async_seg_t){
	.data = vlib_buffer_get_current (b),
	.len = b->current_length,
	.opaque = vlib_get_buffer_index (wrk->vm, b),
      };
      rv = svm_fifo_enqueue_async_segment (s->rx_fifo, &seg);
      if (rv < 0)
	return rv;
      deferred_wrk->n_segs++;
      goto enqueue_event;
    }

  do
    {
      len += cur->current_length;
      n_segs += cur->current_length != 0;

      if (!(cur->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;
      cur = vlib_get_buffer (wrk->vm, cur->next_buffer);
    }
  while (1);

  if (!len)
    return 0;
  if (PREDICT_FALSE (deferred_wrk->n_segs + n_segs > SESSION_DEFERRED_RX_MAX_SEGS))
    return SVM_FIFO_EFULL;

  rv = svm_fifo_reserve_async (s->rx_fifo, len);
  if (rv < 0)
    return rv;

  bi = vlib_get_buffer_index (wrk->vm, b);
  left = len;
  cur = b;
  do
    {
      if (cur->current_length)
	{
	  left -= cur->current_length;
	  seg = (svm_fifo_async_seg_t){
	    .data = vlib_buffer_get_current (cur),
	    .len = cur->current_length,
	    .opaque = left ? SVM_FIFO_ASYNC_OPAQUE_INVALID : bi,
	  };
	  svm_fifo_add_async_segment (s->rx_fifo, &seg);
	}

      if (!(cur->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;
      cur = vlib_get_buffer (wrk->vm, cur->next_buffer);
    }
  while (1);
  ASSERT (left == 0);
  deferred_wrk->n_segs += n_segs;

enqueue_event:
  vec_add1 (deferred_wrk->held_buffers, vlib_get_buffer_index (wrk->vm, b));

  if (!(s->flags & SESSION_F_RX_EVT))
    {
      s->flags |= SESSION_F_RX_EVT;
      vec_add1 (wrk->session_to_enqueue[tc->proto], session_handle (s));
    }

  return rv;
}

__clib_noinline u8
session_deferred_rx_enqueue_or_flush (session_t *s, transport_connection_t *tc, vlib_buffer_t *b,
				      u8 queue_event, u8 is_in_order, int *enqueued)
{
  int rv;

  ASSERT (s->flags & SESSION_F_DEFERRED_RX);
  ASSERT (enqueued != 0);

  /* Do not let deferred data overtake readable or out-of-order data that is
   * already owned by the FIFO. */
  if (is_in_order && queue_event && svm_fifo_max_dequeue_prod (s->rx_fifo) == 0 &&
      !svm_fifo_has_ooo_data (s->rx_fifo))
    {
      rv = session_deferred_rx_stage_buffer (s, tc, b);
      if (rv >= 0)
	{
	  *enqueued = rv;
	  return 1;
	}
    }

  /* Non-eligible enqueues are barriers for pending deferred writes. */
  rv = session_flush_deferred_rx (s);
  ASSERT (rv >= 0);
  return 0;
}

static svm_fifo_async_seg_t *
session_deferred_rx_get_free_seg_vec (session_deferred_rx_worker_t *deferred_wrk)
{
  svm_fifo_async_seg_t *segs;

  if (!vec_len (deferred_wrk->free_seg_vecs))
    return 0;

  segs = vec_pop (deferred_wrk->free_seg_vecs);
  ASSERT (!vec_len (segs));
  return segs;
}

static void
session_deferred_rx_put_free_seg_vec (session_deferred_rx_worker_t *deferred_wrk,
				      svm_fifo_async_seg_t *segs)
{
  vec_reset_length (segs);
  vec_add1 (deferred_wrk->free_seg_vecs, segs);
}

static void
session_deferred_rx_free_segment_buffers (vlib_main_t *vm, svm_fifo_async_seg_t *segs, u32 n_segs)
{
  u32 *refs, i, n_refs = 0;

  refs = (u32 *) segs;
  for (i = 0; i < n_segs; i++)
    if (segs[i].opaque != SVM_FIFO_ASYNC_OPAQUE_INVALID)
      refs[n_refs++] = segs[i].opaque;

  if (n_refs)
    vlib_buffer_free (vm, refs, n_refs);
}

__clib_noinline u32
session_deferred_rx_compact_buffer_indices (session_deferred_rx_worker_t *deferred_wrk,
					    u32 *buffer_indices, u32 n_buffers)
{
  u32 *held = deferred_wrk->held_buffers;
  u32 i, n_to_free = 0;
  u32 *bi;

  ASSERT (vec_len (held));

  vec_foreach (bi, held)
    {
      for (i = 0; i < n_buffers; i++)
	if (buffer_indices[i] == *bi)
	  {
	    buffer_indices[i] = VLIB_BUFFER_INVALID_INDEX;
	    break;
	  }
      ASSERT (i < n_buffers);
    }

  for (i = 0; i < n_buffers; i++)
    if (buffer_indices[i] != VLIB_BUFFER_INVALID_INDEX)
      buffer_indices[n_to_free++] = buffer_indices[i];

  vec_reset_length (deferred_wrk->held_buffers);
  return n_to_free;
}

static void
session_deferred_rx_notify_transport (session_t *s, u32 n_bytes)
{
  svm_fifo_t *f = s->rx_fifo;

  if (svm_fifo_needs_deq_ntf (f, n_bytes))
    {
      svm_fifo_clear_deq_ntf (f);
      session_program_transport_io_evt (s->handle, SESSION_IO_EVT_RX);
    }
}

int
session_flush_deferred_rx_fifo (svm_fifo_t *f)
{
  svm_fifo_async_state_t *state = f->async_state;
  session_deferred_rx_worker_t *deferred_wrk;
  session_worker_t *wrk;
  u32 *refs, n_refs;
  u32 n_segs;
  int rv;

  if (PREDICT_TRUE (!state))
    return 0;

  if (!vec_len (state->segs))
    {
      ASSERT (state->tail == SVM_FIFO_ASYNC_TAIL_INVALID);
      return 0;
    }

  n_segs = vec_len (state->segs);
  rv = svm_fifo_commit_async_segments (f, &refs, &n_refs);
  ASSERT (rv >= 0);
  if (PREDICT_FALSE (rv < 0))
    return rv;

  if (n_refs)
    vlib_buffer_free (vlib_get_main_by_index (f->master_thread_index), refs, n_refs);
  svm_fifo_clear_async_segments (f);
  wrk = session_main_get_worker (f->master_thread_index);
  deferred_wrk = wrk->deferred_rx;
  ASSERT (deferred_wrk && deferred_wrk->n_segs >= n_segs);
  deferred_wrk->n_segs -= n_segs;
  return rv;
}

void
session_cleanup_deferred_rx_fifo (svm_fifo_t *f)
{
  svm_fifo_async_state_t *state = f->async_state;
  session_deferred_rx_worker_t *deferred_wrk;
  session_worker_t *wrk;
  u32 n_segs;

  if (!state || !(n_segs = vec_len (state->segs)))
    return;

  ASSERT (state->tail != SVM_FIFO_ASYNC_TAIL_INVALID);
  wrk = session_main_get_worker (f->master_thread_index);
  deferred_wrk = wrk->deferred_rx;
  ASSERT (deferred_wrk && deferred_wrk->n_segs >= n_segs);
  session_deferred_rx_free_segment_buffers (wrk->vm, state->segs, n_segs);
  deferred_wrk->n_segs -= n_segs;
  state->tail = SVM_FIFO_ASYNC_TAIL_INVALID;
  vec_reset_length (state->segs);
}

int
session_flush_deferred_rx (session_t *s)
{
  ASSERT (s->thread_index == vlib_get_thread_index ());
  return session_flush_deferred_rx_fifo (s->rx_fifo);
}

int
session_set_deferred_rx (session_t *s, u8 enable)
{
  app_worker_t *app_wrk;
  int rv;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  if (enable)
    {
      app_wrk = app_worker_get_if_valid (s->app_wrk_index);
      if (!s->rx_fifo || session_get_transport_proto (s) != TRANSPORT_PROTO_TCP || !app_wrk ||
	  !app_worker_application_is_builtin (app_wrk))
	return SVM_FIFO_EINVAL;
      s->flags |= SESSION_F_DEFERRED_RX;
      return 0;
    }

  rv = session_flush_deferred_rx (s);
  if (rv >= 0)
    s->flags &= ~SESSION_F_DEFERRED_RX;
  return rv < 0 ? rv : 0;
}

const session_deferred_rx_segment_t *
session_get_deferred_rx_segments (session_t *s, u32 *n_segs)
{
  svm_fifo_async_state_t *state;

  ASSERT (s->thread_index == vlib_get_thread_index ());
  ASSERT (n_segs != 0);
  state = s->rx_fifo->async_state;
  *n_segs = state ? vec_len (state->segs) : 0;
  return state ? (const session_deferred_rx_segment_t *) state->segs : 0;
}

int
session_acquire_deferred_rx_segments (session_t *s, session_deferred_rx_batch_t *batch)
{
  svm_fifo_async_state_t *state;
  session_deferred_rx_worker_t *deferred_wrk;
  session_worker_t *wrk;
  svm_fifo_async_seg_t *segs;
  u32 n_bytes = 0, n_segs, i;

  ASSERT (s->thread_index == vlib_get_thread_index ());
  ASSERT (s->flags & SESSION_F_DEFERRED_RX);
  ASSERT (batch != 0);
  if (PREDICT_FALSE (batch->segments != 0))
    return SVM_FIFO_EINVAL;
  clib_memset (batch, 0, sizeof (*batch));

  state = s->rx_fifo->async_state;
  if (!state || !(n_segs = vec_len (state->segs)))
    return 0;

  ASSERT (state->tail != SVM_FIFO_ASYNC_TAIL_INVALID);
  segs = state->segs;
  for (i = 0; i < n_segs; i++)
    n_bytes += segs[i].len;
  ASSERT (n_bytes == (u32) state->tail - s->rx_fifo->shr->tail);

  wrk = session_main_get_worker (s->thread_index);
  deferred_wrk = wrk->deferred_rx;
  ASSERT (deferred_wrk != 0);
  batch->segments = (const session_deferred_rx_segment_t *) segs;
  batch->n_segments = n_segs;
  batch->data_len = n_bytes;
  batch->owner_thread_index = s->thread_index;
  state->segs = session_deferred_rx_get_free_seg_vec (deferred_wrk);
  state->tail = SVM_FIFO_ASYNC_TAIL_INVALID;

  session_deferred_rx_notify_transport (s, n_bytes);
  return n_bytes;
}

void
session_release_deferred_rx_segments (session_deferred_rx_batch_t *batch)
{
  svm_fifo_async_seg_t *segs;
  session_deferred_rx_worker_t *deferred_wrk;
  session_worker_t *wrk;

  ASSERT (batch != 0);
  if (!batch->segments)
    return;

  ASSERT (batch->owner_thread_index == vlib_get_thread_index ());
  segs = (svm_fifo_async_seg_t *) batch->segments;
  ASSERT (vec_len (segs) == batch->n_segments);

  wrk = session_main_get_worker (batch->owner_thread_index);
  deferred_wrk = wrk->deferred_rx;
  ASSERT (deferred_wrk && deferred_wrk->n_segs >= batch->n_segments);
  deferred_wrk->n_segs -= batch->n_segments;
  session_deferred_rx_free_segment_buffers (wrk->vm, segs, batch->n_segments);
  session_deferred_rx_put_free_seg_vec (deferred_wrk, segs);
  clib_memset (batch, 0, sizeof (*batch));
}

int
session_discard_deferred_rx (session_t *s)
{
  svm_fifo_async_state_t *state;
  session_deferred_rx_worker_t *deferred_wrk;
  session_worker_t *wrk;
  svm_fifo_async_seg_t *segs;
  u32 i, n_bytes = 0, n_segs;

  ASSERT (s->thread_index == vlib_get_thread_index ());
  state = s->rx_fifo->async_state;
  if (!state || !(n_segs = vec_len (state->segs)))
    return 0;

  ASSERT (state->tail != SVM_FIFO_ASYNC_TAIL_INVALID);
  segs = state->segs;
  for (i = 0; i < n_segs; i++)
    n_bytes += segs[i].len;
  ASSERT (n_bytes == (u32) state->tail - s->rx_fifo->shr->tail);

  wrk = session_main_get_worker (s->thread_index);
  deferred_wrk = wrk->deferred_rx;
  ASSERT (deferred_wrk && deferred_wrk->n_segs >= n_segs);
  session_deferred_rx_free_segment_buffers (wrk->vm, segs, n_segs);
  deferred_wrk->n_segs -= n_segs;
  state->tail = SVM_FIFO_ASYNC_TAIL_INVALID;
  vec_reset_length (state->segs);
  session_deferred_rx_notify_transport (s, n_bytes);
  return n_bytes;
}
