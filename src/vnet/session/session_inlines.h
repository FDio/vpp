/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_session_inlines_h__
#define __included_session_inlines_h__

#include <vnet/session/session_types.h>
#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/buffer.h>

always_inline void
session_program_io_event (app_worker_t *app_wrk, session_t *s,
			  session_evt_type_t et, u8 is_cl)
{
  if (is_cl)
    {
      /* Special events for connectionless sessions */
      et += SESSION_IO_EVT_BUILTIN_RX - SESSION_IO_EVT_RX;

      ASSERT (s->thread_index == 0 || et == SESSION_IO_EVT_TX_MAIN);
      session_event_t evt = {
	.event_type = et,
	.session_handle = session_handle (s),
      };

      app_worker_add_event_custom (app_wrk, vlib_get_thread_index (), &evt);
    }
  else
    {
      app_worker_add_event (app_wrk, s, et);
    }
}

static inline int
session_notify_subscribers (u32 app_index, session_t *s, svm_fifo_t *f,
			    session_evt_type_t evt_type)
{
  app_worker_t *app_wrk;
  application_t *app;
  u8 is_cl;
  int i;

  app = application_get (app_index);
  if (!app)
    return -1;

  is_cl = s->thread_index != vlib_get_thread_index ();
  for (i = 0; i < f->shr->n_subscribers; i++)
    {
      app_wrk = application_get_worker (app, f->shr->subscribers[i]);
      if (!app_wrk)
	continue;
      session_program_io_event (app_wrk, s, evt_type, is_cl ? 1 : 0);
    }

  return 0;
}

always_inline int
session_enqueue_notify_inline (session_t *s, u8 is_cl)
{
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (PREDICT_FALSE (!app_wrk))
    return -1;

  session_program_io_event (app_wrk, s, SESSION_IO_EVT_RX, is_cl);

  if (PREDICT_FALSE (svm_fifo_n_subscribers (s->rx_fifo)))
    return session_notify_subscribers (app_wrk->app_index, s, s->rx_fifo,
				       SESSION_IO_EVT_RX);

  return 0;
}

always_inline int
session_enqueue_notify (session_t *s)
{
  return session_enqueue_notify_inline (s, 0 /* is_cl */);
}

always_inline int
session_enqueue_notify_cl (session_t *s)
{
  return session_enqueue_notify_inline (s, 1 /* is_cl */);
}

always_inline int
session_dequeue_notify (session_t *s)
{
  app_worker_t *app_wrk;
  u8 is_cl;

  /* Unset as soon as event is requested */
  svm_fifo_clear_deq_ntf (s->tx_fifo);

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (PREDICT_FALSE (!app_wrk))
    return -1;

  is_cl = s->session_state == SESSION_STATE_LISTENING ||
	  s->session_state == SESSION_STATE_OPENED;
  session_program_io_event (app_wrk, s, SESSION_IO_EVT_TX, is_cl ? 1 : 0);

  if (PREDICT_FALSE (svm_fifo_n_subscribers (s->tx_fifo)))
    return session_notify_subscribers (app_wrk->app_index, s, s->tx_fifo,
				       SESSION_IO_EVT_TX);

  return 0;
}

static inline void
session_fifo_tuning (session_t *s, svm_fifo_t *f, session_ft_action_t act,
		     u32 len)
{
  if (s->flags & SESSION_F_CUSTOM_FIFO_TUNING)
    {
      app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
      app_worker_session_fifo_tuning (app_wrk, s, f, act, len);
      if (CLIB_ASSERT_ENABLE)
	{
	  segment_manager_t *sm;
	  sm = segment_manager_get (f->segment_manager);
	  ASSERT (f->shr->size >= 4096);
	  ASSERT (f->shr->size <= sm->max_fifo_size);
	}
    }
}

/**
 * Discards bytes from buffer chain
 *
 * It discards n_bytes_to_drop starting at first buffer after chain_b
 */
always_inline void
session_enqueue_discard_chain_bytes (vlib_main_t *vm, vlib_buffer_t *b,
				     vlib_buffer_t **chain_b,
				     u32 n_bytes_to_drop)
{
  vlib_buffer_t *next = *chain_b;
  u32 to_drop = n_bytes_to_drop;
  ASSERT (b->flags & VLIB_BUFFER_NEXT_PRESENT);
  while (to_drop && (next->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      next = vlib_get_buffer (vm, next->next_buffer);
      if (next->current_length > to_drop)
	{
	  vlib_buffer_advance (next, to_drop);
	  to_drop = 0;
	}
      else
	{
	  to_drop -= next->current_length;
	  next->current_length = 0;
	}
    }
  *chain_b = next;

  if (to_drop == 0)
    b->total_length_not_including_first_buffer -= n_bytes_to_drop;
}

/**
 * Enqueue buffer chain tail
 */
always_inline int
session_enqueue_chain_tail (session_t *s, vlib_buffer_t *b, u32 offset,
			    u8 is_in_order)
{
  vlib_buffer_t *chain_b;
  u32 chain_bi, len, diff;
  vlib_main_t *vm = vlib_get_main ();
  u8 *data;
  u32 written = 0;
  int rv = 0;

  if (is_in_order && offset)
    {
      diff = offset - b->current_length;
      if (diff > b->total_length_not_including_first_buffer)
	return 0;
      chain_b = b;
      session_enqueue_discard_chain_bytes (vm, b, &chain_b, diff);
      chain_bi = vlib_get_buffer_index (vm, chain_b);
    }
  else
    chain_bi = b->next_buffer;

  do
    {
      chain_b = vlib_get_buffer (vm, chain_bi);
      data = vlib_buffer_get_current (chain_b);
      len = chain_b->current_length;
      if (!len)
	continue;
      if (is_in_order)
	{
	  rv = svm_fifo_enqueue (s->rx_fifo, len, data);
	  if (rv == len)
	    {
	      written += rv;
	    }
	  else if (rv < len)
	    {
	      return (rv > 0) ? (written + rv) : written;
	    }
	  else if (rv > len)
	    {
	      written += rv;

	      /* written more than what was left in chain */
	      if (written > b->total_length_not_including_first_buffer)
		return written;

	      /* drop the bytes that have already been delivered */
	      session_enqueue_discard_chain_bytes (vm, b, &chain_b, rv - len);
	    }
	}
      else
	{
	  rv = svm_fifo_enqueue_with_offset (s->rx_fifo, offset, len, data);
	  if (rv)
	    {
	      clib_warning ("failed to enqueue multi-buffer seg");
	      return -1;
	    }
	  offset += len;
	}
    }
  while ((chain_bi = (chain_b->flags & VLIB_BUFFER_NEXT_PRESENT) ?
		       chain_b->next_buffer :
		       0));

  if (is_in_order)
    return written;

  return 0;
}

/*
 * Enqueue data for delivery to app. If requested, it queues app notification
 * event for later delivery.
 *
 * @param tc Transport connection which is to be enqueued data
 * @param b Buffer to be enqueued
 * @param offset Offset at which to start enqueueing if out-of-order
 * @param queue_event Flag to indicate if peer is to be notified or if event
 *                    is to be queued. The former is useful when more data is
 *                    enqueued and only one event is to be generated.
 * @param is_in_order Flag to indicate if data is in order
 * @return Number of bytes enqueued or a negative value if enqueueing failed.
 */
always_inline int
session_enqueue_stream_connection (transport_connection_t *tc,
				   vlib_buffer_t *b, u32 offset,
				   u8 queue_event, u8 is_in_order)
{
  session_t *s;
  int enqueued = 0, rv, in_order_off;

  s = session_get (tc->s_index, tc->thread_index);

  if (is_in_order)
    {
      enqueued = svm_fifo_enqueue (s->rx_fifo, b->current_length,
				   vlib_buffer_get_current (b));
      if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) &&
			 enqueued >= 0))
	{
	  in_order_off = enqueued > b->current_length ? enqueued : 0;
	  rv = session_enqueue_chain_tail (s, b, in_order_off, 1);
	  if (rv > 0)
	    enqueued += rv;
	}
      // ASSERT (enqueued == vlib_buffer_length_in_chain (vlib_get_main(), b));
    }
  else
    {
      rv = svm_fifo_enqueue_with_offset (s->rx_fifo, offset, b->current_length,
					 vlib_buffer_get_current (b));
      if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) && !rv))
	session_enqueue_chain_tail (s, b, offset + b->current_length, 0);
      /* if something was enqueued, report even this as success for ooo
       * segment handling */
      return rv;
    }

  if (queue_event)
    {
      /* Queue RX event on this fifo. Eventually these will need to be
       * flushed by calling @ref session_main_flush_enqueue_events () */
      if (!(s->flags & SESSION_F_RX_EVT))
	{
	  session_worker_t *wrk = session_main_get_worker (s->thread_index);
	  ASSERT (s->thread_index == vlib_get_thread_index ());
	  s->flags |= SESSION_F_RX_EVT;
	  vec_add1 (wrk->session_to_enqueue[tc->proto], session_handle (s));
	}

      session_fifo_tuning (s, s->rx_fifo, SESSION_FT_ACTION_ENQUEUED, 0);
    }

  return enqueued;
}

always_inline int
session_enqueue_dgram_connection_inline (session_t *s,
					 session_dgram_hdr_t *hdr,
					 vlib_buffer_t *b, u8 proto,
					 u8 queue_event, u32 is_cl)
{
  int rv;

  ASSERT (svm_fifo_max_enqueue_prod (s->rx_fifo) >=
	  b->current_length + sizeof (*hdr));

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    {
      svm_fifo_seg_t segs[2] = { { (u8 *) hdr, sizeof (*hdr) },
				 { vlib_buffer_get_current (b),
				   b->current_length } };

      rv =
	svm_fifo_enqueue_segments (s->rx_fifo, segs, 2, 0 /* allow_partial */);
    }
  else
    {
      vlib_main_t *vm = vlib_get_main ();
      svm_fifo_seg_t *segs = 0, *seg;
      vlib_buffer_t *it = b;
      u32 n_segs = 1;

      vec_add2 (segs, seg, 1);
      seg->data = (u8 *) hdr;
      seg->len = sizeof (*hdr);
      while (it)
	{
	  vec_add2 (segs, seg, 1);
	  seg->data = vlib_buffer_get_current (it);
	  seg->len = it->current_length;
	  n_segs++;
	  if (!(it->flags & VLIB_BUFFER_NEXT_PRESENT))
	    break;
	  it = vlib_get_buffer (vm, it->next_buffer);
	}
      rv = svm_fifo_enqueue_segments (s->rx_fifo, segs, n_segs,
				      0 /* allow partial */);
      vec_free (segs);
    }

  if (queue_event && rv > 0)
    {
      /* Queue RX event on this fifo. Eventually these will need to be
       * flushed by calling @ref session_main_flush_enqueue_events () */
      if (!(s->flags & SESSION_F_RX_EVT))
	{
	  u32 thread_index =
	    is_cl ? vlib_get_thread_index () : s->thread_index;
	  session_worker_t *wrk = session_main_get_worker (thread_index);
	  ASSERT (s->thread_index == vlib_get_thread_index () || is_cl);
	  s->flags |= SESSION_F_RX_EVT;
	  vec_add1 (wrk->session_to_enqueue[proto], session_handle (s));
	}

      session_fifo_tuning (s, s->rx_fifo, SESSION_FT_ACTION_ENQUEUED, 0);
    }
  return rv > 0 ? rv : 0;
}

always_inline int
session_enqueue_dgram_connection (session_t *s, session_dgram_hdr_t *hdr,
				  vlib_buffer_t *b, u8 proto, u8 queue_event)
{
  return session_enqueue_dgram_connection_inline (s, hdr, b, proto,
						  queue_event, 0 /* is_cl */);
}

always_inline int
session_enqueue_dgram_connection2 (session_t *s, session_dgram_hdr_t *hdr,
				   vlib_buffer_t *b, u8 proto, u8 queue_event)
{
  return session_enqueue_dgram_connection_inline (s, hdr, b, proto,
						  queue_event, 1 /* is_cl */);
}

always_inline int
session_enqueue_dgram_connection_cl (session_t *s, session_dgram_hdr_t *hdr,
				     vlib_buffer_t *b, u8 proto,
				     u8 queue_event)
{
  session_t *awls;

  awls = app_listener_select_wrk_cl_session (s, hdr);
  return session_enqueue_dgram_connection_inline (awls, hdr, b, proto,
						  queue_event, 1 /* is_cl */);
}

/**
 * Flushes queue of sessions that are to be notified of new data
 * enqueued events.
 *
 * @param transport_proto transport protocol for which queue to be flushed
 * @param thread_index Thread index for which the flush is to be performed.
 * @return 0 on success or a positive number indicating the number of
 *         failures due to API queue being full.
 */
always_inline void
session_main_flush_enqueue_events (transport_proto_t transport_proto,
				   u32 thread_index)
{
  session_worker_t *wrk = session_main_get_worker (thread_index);
  session_handle_t *handles;
  session_t *s;
  u32 i, is_cl;

  handles = wrk->session_to_enqueue[transport_proto];

  for (i = 0; i < vec_len (handles); i++)
    {
      s = session_get_from_handle (handles[i]);
      session_fifo_tuning (s, s->rx_fifo, SESSION_FT_ACTION_ENQUEUED,
			   0 /* TODO/not needed */);
      is_cl =
	s->thread_index != thread_index || (s->flags & SESSION_F_IS_CLESS);
      if (!is_cl)
	session_enqueue_notify_inline (s, 0);
      else
	session_enqueue_notify_inline (s, 1);
    }

  vec_reset_length (handles);
  wrk->session_to_enqueue[transport_proto] = handles;
}

always_inline u32
session_tx_fifo_dequeue_drop (transport_connection_t *tc, u32 max_bytes)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  u32 rv;

  rv = svm_fifo_dequeue_drop (s->tx_fifo, max_bytes);
  session_fifo_tuning (s, s->tx_fifo, SESSION_FT_ACTION_DEQUEUED, rv);

  if (svm_fifo_needs_deq_ntf (s->tx_fifo, max_bytes))
    session_dequeue_notify (s);

  return rv;
}

#endif /* __included_session_inlines_h__ */