/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/session/session.h>
#include <vnet/session/session_deferred_rx.h>

int
session_flush_deferred_rx_fifo (svm_fifo_t *f)
{
  svm_fifo_async_state_t *state = f->async_state;
  vlib_main_t *vm;
  u32 *refs, n_refs;
  int rv;

  if (PREDICT_TRUE (!state))
    return 0;

  if (!vec_len (state->segs))
    {
      ASSERT (state->tail == SVM_FIFO_ASYNC_TAIL_INVALID);
      return 0;
    }

  rv = svm_fifo_commit_async_segments (f, &refs, &n_refs);
  ASSERT (rv >= 0);
  if (PREDICT_FALSE (rv < 0))
    return rv;

  if (n_refs)
    {
      vm = vlib_get_main ();
      vlib_buffer_free (vm, refs, n_refs);
    }
  svm_fifo_clear_async_segments (f);
  return rv;
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
  int rv;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  if (enable)
    {
      s->flags |= SESSION_F_DEFERRED_RX;
      return 0;
    }

  rv = session_flush_deferred_rx (s);
  if (rv >= 0)
    s->flags &= ~SESSION_F_DEFERRED_RX;
  return rv < 0 ? rv : 0;
}

session_deferred_rx_segment_t *
session_get_deferred_rx_segments (session_t *s, u32 *n_segs)
{
  svm_fifo_async_state_t *state;

  ASSERT (s->thread_index == vlib_get_thread_index ());
  ASSERT (n_segs != 0);
  state = s->rx_fifo->async_state;
  *n_segs = state ? vec_len (state->segs) : 0;
  return state ? (session_deferred_rx_segment_t *) state->segs : 0;
}

int
session_consume_deferred_rx_segments (session_t *s, u32 n_segs)
{
  svm_fifo_async_state_t *state;
  svm_fifo_async_seg_t *segs;
  u32 *refs, i, n_bytes = 0, n_refs = 0;
  vlib_main_t *vm;

  ASSERT (s->thread_index == vlib_get_thread_index ());
  state = s->rx_fifo->async_state;
  if (!state)
    return n_segs ? SVM_FIFO_EINVAL : 0;
  if (n_segs > vec_len (state->segs))
    return SVM_FIFO_EINVAL;
  if (!n_segs)
    return 0;

  ASSERT (state->tail != SVM_FIFO_ASYNC_TAIL_INVALID);
  segs = state->segs;
  refs = (u32 *) segs;
  for (i = 0; i < n_segs; i++)
    {
      n_bytes += segs[i].len;
      if (segs[i].opaque != SVM_FIFO_ASYNC_OPAQUE_INVALID)
	refs[n_refs++] = segs[i].opaque;
    }

  if (n_refs)
    {
      vm = vlib_get_main ();
      vlib_buffer_free (vm, refs, n_refs);
    }

  if (n_segs == vec_len (state->segs))
    {
      state->tail = SVM_FIFO_ASYNC_TAIL_INVALID;
      vec_reset_length (state->segs);
    }
  else
    {
      state->tail = (u32) state->tail - n_bytes;
      vec_delete (state->segs, n_segs, 0);
    }

  return n_bytes;
}

int
session_discard_deferred_rx (session_t *s)
{
  svm_fifo_async_state_t *state;

  ASSERT (s->thread_index == vlib_get_thread_index ());
  state = s->rx_fifo->async_state;
  return session_consume_deferred_rx_segments (s, state ? vec_len (state->segs) : 0);
}
