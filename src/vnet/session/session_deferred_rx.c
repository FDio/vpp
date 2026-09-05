/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/session/session.h>
#include <vnet/session/session_deferred_rx.h>

#define SESSION_DEFERRED_RX_N_BUFFER_POOLS 256

typedef struct
{
  u64 current_buffers;
  u64 peak_buffers;
  u64 admission_fallbacks;
  u64 shared_available_low;
  u64 samples;
} session_deferred_rx_pool_state_t;

static session_deferred_rx_pool_state_t
  session_deferred_rx_pool_states[SESSION_DEFERRED_RX_N_BUFFER_POOLS];

static_always_inline u32
session_deferred_rx_pool_reserve (vlib_buffer_pool_t *bp)
{
  u32 cache_reserve;

  /* Preserve one complete per-thread cache refill in the shared pool. */
  cache_reserve = vec_len (bp->threads) * VLIB_BUFFER_POOL_PER_THREAD_CACHE_SZ;
  return clib_min (cache_reserve, bp->n_buffers / 2);
}

static void
session_deferred_rx_atomic_max (u64 *value, u64 candidate)
{
  u64 old = clib_atomic_load_relax_n (value);

  while (candidate > old && !__atomic_compare_exchange_n (value, &old, candidate, 1,
							  __ATOMIC_RELAXED, __ATOMIC_RELAXED))
    ;
}

static void
session_deferred_rx_atomic_min (u64 *value, u64 candidate)
{
  u64 old = clib_atomic_load_relax_n (value);

  while (candidate < old && !__atomic_compare_exchange_n (value, &old, candidate, 1,
							  __ATOMIC_RELAXED, __ATOMIC_RELAXED))
    ;
}

static int
session_deferred_rx_count_buffer_chain (vlib_main_t *vm, u32 bi, u8 *pool_index, u32 *n_buffers)
{
  vlib_buffer_t *b;

  do
    {
      b = vlib_get_buffer (vm, bi);
      if (*pool_index == (u8) ~0)
	*pool_index = b->buffer_pool_index;
      else if (*pool_index != b->buffer_pool_index)
	return -1;
      (*n_buffers)++;
      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;
      bi = b->next_buffer;
    }
  while (1);
  return 0;
}

static int
session_deferred_rx_pool_acquire (vlib_main_t *vm, u8 pool_index, u32 n_buffers)
{
  session_deferred_rx_pool_state_t *state;
  vlib_buffer_pool_t *bp;
  u64 current, peak;
  u32 reserve, shared_available;

  bp = vlib_get_buffer_pool (vm, pool_index);
  state = &session_deferred_rx_pool_states[pool_index];
  reserve = session_deferred_rx_pool_reserve (bp);

  /* Taking the buffer-pool lock here would serialize every application RX
   * event with buffer cache refills. The availability sample is therefore a
   * conservative low-watermark rather than an atomic allocation reserve. */
  shared_available = clib_atomic_load_relax_n (&bp->n_avail);
  if (PREDICT_FALSE (shared_available < reserve))
    goto fallback;

  current = clib_atomic_load_relax_n (&state->current_buffers);
  do
    {
      if (PREDICT_FALSE (current + n_buffers > bp->n_buffers - reserve))
	goto fallback;
      peak = current + n_buffers;
    }
  while (!__atomic_compare_exchange_n (&state->current_buffers, &current, peak, 1, __ATOMIC_RELAXED,
				       __ATOMIC_RELAXED));

  if (!clib_atomic_fetch_add_relax (&state->samples, 1))
    clib_atomic_store_relax_n (&state->shared_available_low, shared_available);
  else
    session_deferred_rx_atomic_min (&state->shared_available_low, shared_available);
  session_deferred_rx_atomic_max (&state->peak_buffers, peak);
  return 0;

fallback:
  clib_atomic_fetch_add_relax (&state->admission_fallbacks, 1);
  if (!clib_atomic_fetch_add_relax (&state->samples, 1))
    clib_atomic_store_relax_n (&state->shared_available_low, shared_available);
  else
    session_deferred_rx_atomic_min (&state->shared_available_low, shared_available);
  return SVM_FIFO_EFULL;
}

static void
session_deferred_rx_pool_release (u8 pool_index, u32 n_buffers)
{
  session_deferred_rx_pool_state_t *state;
  u64 old;

  state = &session_deferred_rx_pool_states[pool_index];
  old = clib_atomic_fetch_sub_relax (&state->current_buffers, n_buffers);
  ASSERT (old >= n_buffers);
}

int
session_get_deferred_rx_pool_stats (u8 pool_index, session_deferred_rx_pool_stats_t *stats)
{
  session_deferred_rx_pool_state_t *state;
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_pool_t *bp;

  if (!stats || pool_index >= vec_len (vm->buffer_main->buffer_pools))
    return -1;

  bp = vlib_get_buffer_pool (vm, pool_index);
  state = &session_deferred_rx_pool_states[pool_index];
  *stats = (session_deferred_rx_pool_stats_t){
    .current_buffers = clib_atomic_load_relax_n (&state->current_buffers),
    .peak_buffers = clib_atomic_load_relax_n (&state->peak_buffers),
    .admission_fallbacks = clib_atomic_load_relax_n (&state->admission_fallbacks),
    .shared_available_low = clib_atomic_load_relax_n (&state->shared_available_low),
    .samples = clib_atomic_load_relax_n (&state->samples),
    .total_buffers = bp->n_buffers,
    .reserve_buffers = session_deferred_rx_pool_reserve (bp),
  };
  return 0;
}

int
session_reset_deferred_rx_pool_stats (u8 pool_index)
{
  session_deferred_rx_pool_state_t *state;
  vlib_main_t *vm = vlib_get_main ();

  if (pool_index >= vec_len (vm->buffer_main->buffer_pools))
    return -1;
  state = &session_deferred_rx_pool_states[pool_index];
  if (clib_atomic_load_relax_n (&state->current_buffers))
    return -1;

  clib_atomic_store_relax_n (&state->peak_buffers, 0);
  clib_atomic_store_relax_n (&state->admission_fallbacks, 0);
  clib_atomic_store_relax_n (&state->shared_available_low, 0);
  clib_atomic_store_relax_n (&state->samples, 0);
  return 0;
}

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
session_take_deferred_rx_segments (session_t *s, u32 n_segs)
{
  svm_fifo_async_state_t *state;
  svm_fifo_async_seg_t *segs;
  vlib_main_t *vm;
  u32 i, n_buffers = 0, n_bytes = 0;
  u8 pool_index = (u8) ~0;

  ASSERT (s->thread_index == vlib_get_thread_index ());
  state = s->rx_fifo->async_state;
  if (!state)
    return n_segs ? SVM_FIFO_EINVAL : 0;
  if (!n_segs)
    return 0;

  /* A full-batch take keeps the ownership transition atomic and is all that
   * is needed to measure the application integration. */
  if (n_segs != vec_len (state->segs))
    return SVM_FIFO_EINVAL;

  ASSERT (state->tail != SVM_FIFO_ASYNC_TAIL_INVALID);
  segs = state->segs;
  vm = vlib_get_main ();
  for (i = 0; i < n_segs; i++)
    {
      n_bytes += segs[i].len;
      if (segs[i].opaque != SVM_FIFO_ASYNC_OPAQUE_INVALID &&
	  session_deferred_rx_count_buffer_chain (vm, segs[i].opaque, &pool_index, &n_buffers))
	return SVM_FIFO_EINVAL;
    }

  if (!n_buffers)
    return SVM_FIFO_EINVAL;
  if (session_deferred_rx_pool_acquire (vm, pool_index, n_buffers))
    return SVM_FIFO_EFULL;

  state->tail = SVM_FIFO_ASYNC_TAIL_INVALID;
  vec_reset_length (state->segs);

  session_fifo_tuning (s, s->rx_fifo, SESSION_FT_ACTION_DEQUEUED, n_bytes);
  if (svm_fifo_needs_deq_ntf (s->rx_fifo, n_bytes))
    {
      svm_fifo_clear_deq_ntf (s->rx_fifo);
      session_program_transport_io_evt (s->handle, SESSION_IO_EVT_RX);
    }

  return n_bytes;
}

void
session_release_deferred_rx_buffers (u32 thread_index, const u32 *buffer_refs, u32 n_buffer_refs)
{
  session_worker_t *wrk;
  u32 i, n_buffers;
  u8 pool_index;
  int rv;

  ASSERT (thread_index == vlib_get_thread_index ());
  if (!n_buffer_refs)
    return;

  wrk = session_main_get_worker (thread_index);
  for (i = 0; i < n_buffer_refs; i++)
    {
      n_buffers = 0;
      pool_index = (u8) ~0;
      rv =
	session_deferred_rx_count_buffer_chain (wrk->vm, buffer_refs[i], &pool_index, &n_buffers);
      ASSERT (!rv);
      if (PREDICT_FALSE (rv))
	return;
      session_deferred_rx_pool_release (pool_index, n_buffers);
    }
  vlib_buffer_free (wrk->vm, (u32 *) buffer_refs, n_buffer_refs);
}

int
session_discard_deferred_rx (session_t *s)
{
  svm_fifo_async_state_t *state;

  ASSERT (s->thread_index == vlib_get_thread_index ());
  state = s->rx_fifo->async_state;
  return session_consume_deferred_rx_segments (s, state ? vec_len (state->segs) : 0);
}
