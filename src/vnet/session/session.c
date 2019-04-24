/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @file
 * @brief Session and session manager
 */

#include <vnet/session/session.h>
#include <vnet/session/session_debug.h>
#include <vnet/session/application.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>

session_main_t session_main;

static inline int
session_send_evt_to_thread (void *data, void *args, u32 thread_index,
			    session_evt_type_t evt_type)
{
  session_event_t *evt;
  svm_msg_q_msg_t msg;
  svm_msg_q_t *mq;
  u32 tries = 0, max_tries;

  mq = session_main_get_vpp_event_queue (thread_index);
  while (svm_msg_q_try_lock (mq))
    {
      max_tries = vlib_get_current_process (vlib_get_main ())? 1e6 : 3;
      if (tries++ == max_tries)
	{
	  SESSION_DBG ("failed to enqueue evt");
	  return -1;
	}
    }
  if (PREDICT_FALSE (svm_msg_q_ring_is_full (mq, SESSION_MQ_IO_EVT_RING)))
    {
      svm_msg_q_unlock (mq);
      return -2;
    }
  msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
  if (PREDICT_FALSE (svm_msg_q_msg_is_invalid (&msg)))
    {
      svm_msg_q_unlock (mq);
      return -2;
    }
  evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
  evt->event_type = evt_type;
  switch (evt_type)
    {
    case SESSION_CTRL_EVT_RPC:
      evt->rpc_args.fp = data;
      evt->rpc_args.arg = args;
      break;
    case SESSION_IO_EVT_TX:
    case SESSION_IO_EVT_TX_FLUSH:
    case SESSION_IO_EVT_BUILTIN_RX:
      evt->session_index = *(u32 *) data;
      break;
    case SESSION_IO_EVT_BUILTIN_TX:
    case SESSION_CTRL_EVT_CLOSE:
      evt->session_handle = session_handle ((session_t *) data);
      break;
    default:
      clib_warning ("evt unhandled!");
      svm_msg_q_unlock (mq);
      return -1;
    }

  svm_msg_q_add_and_unlock (mq, &msg);
  return 0;
}

int
session_send_io_evt_to_thread (svm_fifo_t * f, session_evt_type_t evt_type)
{
  return session_send_evt_to_thread (&f->master_session_index, 0,
				     f->master_thread_index, evt_type);
}

int
session_send_io_evt_to_thread_custom (void *data, u32 thread_index,
				      session_evt_type_t evt_type)
{
  return session_send_evt_to_thread (data, 0, thread_index, evt_type);
}

int
session_send_ctrl_evt_to_thread (session_t * s, session_evt_type_t evt_type)
{
  /* only event supported for now is disconnect */
  ASSERT (evt_type == SESSION_CTRL_EVT_CLOSE);
  return session_send_evt_to_thread (s, 0, s->thread_index,
				     SESSION_CTRL_EVT_CLOSE);
}

void
session_send_rpc_evt_to_thread_force (u32 thread_index, void *fp,
				      void *rpc_args)
{
  session_send_evt_to_thread (fp, rpc_args, thread_index,
			      SESSION_CTRL_EVT_RPC);
}

void
session_send_rpc_evt_to_thread (u32 thread_index, void *fp, void *rpc_args)
{
  if (thread_index != vlib_get_thread_index ())
    session_send_rpc_evt_to_thread_force (thread_index, fp, rpc_args);
  else
    {
      void (*fnp) (void *) = fp;
      fnp (rpc_args);
    }
}

static void
session_program_transport_close (session_t * s)
{
  u32 thread_index = vlib_get_thread_index ();
  session_worker_t *wrk;
  session_event_t *evt;

  /* If we are in the handler thread, or being called with the worker barrier
   * held, just append a new event to pending disconnects vector. */
  if (vlib_thread_is_main_w_barrier () || thread_index == s->thread_index)
    {
      wrk = session_main_get_worker (s->thread_index);
      vec_add2 (wrk->pending_disconnects, evt, 1);
      clib_memset (evt, 0, sizeof (*evt));
      evt->session_handle = session_handle (s);
      evt->event_type = SESSION_CTRL_EVT_CLOSE;
    }
  else
    session_send_ctrl_evt_to_thread (s, SESSION_CTRL_EVT_CLOSE);
}

session_t *
session_alloc (u32 thread_index)
{
  session_worker_t *wrk = &session_main.wrk[thread_index];
  session_t *s;
  u8 will_expand = 0;
  pool_get_aligned_will_expand (wrk->sessions, will_expand,
				CLIB_CACHE_LINE_BYTES);
  /* If we have peekers, let them finish */
  if (PREDICT_FALSE (will_expand && vlib_num_workers ()))
    {
      clib_rwlock_writer_lock (&wrk->peekers_rw_locks);
      pool_get_aligned (wrk->sessions, s, CLIB_CACHE_LINE_BYTES);
      clib_rwlock_writer_unlock (&wrk->peekers_rw_locks);
    }
  else
    {
      pool_get_aligned (wrk->sessions, s, CLIB_CACHE_LINE_BYTES);
    }
  clib_memset (s, 0, sizeof (*s));
  s->session_index = s - wrk->sessions;
  s->thread_index = thread_index;
  return s;
}

void
session_free (session_t * s)
{
  if (CLIB_DEBUG)
    {
      u8 thread_index = s->thread_index;
      clib_memset (s, 0xFA, sizeof (*s));
      pool_put (session_main.wrk[thread_index].sessions, s);
      return;
    }
  SESSION_EVT_DBG (SESSION_EVT_FREE, s);
  pool_put (session_main.wrk[s->thread_index].sessions, s);
}

void
session_free_w_fifos (session_t * s)
{
  segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
  session_free (s);
}

/**
 * Cleans up session and lookup table.
 *
 * Transport connection must still be valid.
 */
static void
session_delete (session_t * s)
{
  int rv;

  /* Delete from the main lookup table. */
  if ((rv = session_lookup_del_session (s)))
    clib_warning ("hash delete error, rv %d", rv);

  session_free_w_fifos (s);
}

static session_t *
session_alloc_for_connection (transport_connection_t * tc)
{
  session_t *s;
  u32 thread_index = tc->thread_index;

  ASSERT (thread_index == vlib_get_thread_index ()
	  || transport_protocol_is_cl (tc->proto));

  s = session_alloc (thread_index);
  s->session_type = session_type_from_proto_and_ip (tc->proto, tc->is_ip4);
  s->session_state = SESSION_STATE_CLOSED;

  /* Attach transport to session and vice versa */
  s->connection_index = tc->c_index;
  tc->s_index = s->session_index;
  return s;
}

/**
 * Discards bytes from buffer chain
 *
 * It discards n_bytes_to_drop starting at first buffer after chain_b
 */
always_inline void
session_enqueue_discard_chain_bytes (vlib_main_t * vm, vlib_buffer_t * b,
				     vlib_buffer_t ** chain_b,
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
session_enqueue_chain_tail (session_t * s, vlib_buffer_t * b,
			    u32 offset, u8 is_in_order)
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
	  rv = svm_fifo_enqueue_nowait (s->rx_fifo, len, data);
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
  while ((chain_bi = (chain_b->flags & VLIB_BUFFER_NEXT_PRESENT)
	  ? chain_b->next_buffer : 0));

  if (is_in_order)
    return written;

  return 0;
}

/*
 * Enqueue data for delivery to session peer. Does not notify peer of enqueue
 * event but on request can queue notification events for later delivery by
 * calling stream_server_flush_enqueue_events().
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
int
session_enqueue_stream_connection (transport_connection_t * tc,
				   vlib_buffer_t * b, u32 offset,
				   u8 queue_event, u8 is_in_order)
{
  session_t *s;
  int enqueued = 0, rv, in_order_off;

  s = session_get (tc->s_index, tc->thread_index);

  if (is_in_order)
    {
      enqueued = svm_fifo_enqueue_nowait (s->rx_fifo,
					  b->current_length,
					  vlib_buffer_get_current (b));
      if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT)
			 && enqueued >= 0))
	{
	  in_order_off = enqueued > b->current_length ? enqueued : 0;
	  rv = session_enqueue_chain_tail (s, b, in_order_off, 1);
	  if (rv > 0)
	    enqueued += rv;
	}
    }
  else
    {
      rv = svm_fifo_enqueue_with_offset (s->rx_fifo, offset,
					 b->current_length,
					 vlib_buffer_get_current (b));
      if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) && !rv))
	session_enqueue_chain_tail (s, b, offset + b->current_length, 0);
      /* if something was enqueued, report even this as success for ooo
       * segment handling */
      return rv;
    }

  if (queue_event)
    {
      /* Queue RX event on this fifo. Eventually these will need to be flushed
       * by calling stream_server_flush_enqueue_events () */
      session_worker_t *wrk;

      wrk = session_main_get_worker (s->thread_index);
      if (!(s->flags & SESSION_F_RX_EVT))
	{
	  s->flags |= SESSION_F_RX_EVT;
	  vec_add1 (wrk->session_to_enqueue[tc->proto], s->session_index);
	}
    }

  return enqueued;
}

int
session_enqueue_dgram_connection (session_t * s,
				  session_dgram_hdr_t * hdr,
				  vlib_buffer_t * b, u8 proto, u8 queue_event)
{
  int enqueued = 0, rv, in_order_off;

  ASSERT (svm_fifo_max_enqueue_prod (s->rx_fifo)
	  >= b->current_length + sizeof (*hdr));

  svm_fifo_enqueue_nowait (s->rx_fifo, sizeof (session_dgram_hdr_t),
			   (u8 *) hdr);
  enqueued = svm_fifo_enqueue_nowait (s->rx_fifo, b->current_length,
				      vlib_buffer_get_current (b));
  if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) && enqueued >= 0))
    {
      in_order_off = enqueued > b->current_length ? enqueued : 0;
      rv = session_enqueue_chain_tail (s, b, in_order_off, 1);
      if (rv > 0)
	enqueued += rv;
    }
  if (queue_event)
    {
      /* Queue RX event on this fifo. Eventually these will need to be flushed
       * by calling stream_server_flush_enqueue_events () */
      session_worker_t *wrk;

      wrk = session_main_get_worker (s->thread_index);
      if (!(s->flags & SESSION_F_RX_EVT))
	{
	  s->flags |= SESSION_F_RX_EVT;
	  vec_add1 (wrk->session_to_enqueue[proto], s->session_index);
	}
    }
  return enqueued;
}

int
session_tx_fifo_peek_bytes (transport_connection_t * tc, u8 * buffer,
			    u32 offset, u32 max_bytes)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_peek (s->tx_fifo, offset, max_bytes, buffer);
}

u32
session_tx_fifo_dequeue_drop (transport_connection_t * tc, u32 max_bytes)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_dequeue_drop (s->tx_fifo, max_bytes);
}

static inline int
session_notify_subscribers (u32 app_index, session_t * s,
			    svm_fifo_t * f, session_evt_type_t evt_type)
{
  app_worker_t *app_wrk;
  application_t *app;
  int i;

  app = application_get (app_index);
  if (!app)
    return -1;

  for (i = 0; i < f->n_subscribers; i++)
    {
      app_wrk = application_get_worker (app, f->subscribers[i]);
      if (!app_wrk)
	continue;
      if (app_worker_lock_and_send_event (app_wrk, s, evt_type))
	return -1;
    }

  return 0;
}

/**
 * Notify session peer that new data has been enqueued.
 *
 * @param s 	Stream session for which the event is to be generated.
 * @param lock 	Flag to indicate if call should lock message queue.
 *
 * @return 0 on success or negative number if failed to send notification.
 */
static inline int
session_enqueue_notify_inline (session_t * s)
{
  app_worker_t *app_wrk;
  u32 session_index;
  u8 n_subscribers;

  session_index = s->session_index;
  n_subscribers = svm_fifo_n_subscribers (s->rx_fifo);

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (PREDICT_FALSE (!app_wrk))
    {
      SESSION_DBG ("invalid s->app_index = %d", s->app_wrk_index);
      return 0;
    }

  /* *INDENT-OFF* */
  SESSION_EVT_DBG(SESSION_EVT_ENQ, s, ({
      ed->data[0] = SESSION_IO_EVT_RX;
      ed->data[1] = svm_fifo_max_dequeue_prod (s->rx_fifo);
  }));
  /* *INDENT-ON* */

  s->flags &= ~SESSION_F_RX_EVT;
  if (PREDICT_FALSE (app_worker_lock_and_send_event (app_wrk, s,
						     SESSION_IO_EVT_RX)))
    return -1;

  if (PREDICT_FALSE (n_subscribers))
    {
      s = session_get (session_index, vlib_get_thread_index ());
      return session_notify_subscribers (app_wrk->app_index, s,
					 s->rx_fifo, SESSION_IO_EVT_RX);
    }

  return 0;
}

int
session_enqueue_notify (session_t * s)
{
  return session_enqueue_notify_inline (s);
}

int
session_dequeue_notify (session_t * s)
{
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (PREDICT_FALSE (!app_wrk))
    return -1;

  if (PREDICT_FALSE (app_worker_lock_and_send_event (app_wrk, s,
						     SESSION_IO_EVT_TX)))
    return -1;

  if (PREDICT_FALSE (s->tx_fifo->n_subscribers))
    return session_notify_subscribers (app_wrk->app_index, s,
				       s->tx_fifo, SESSION_IO_EVT_TX);

  svm_fifo_clear_tx_ntf (s->tx_fifo);

  return 0;
}

/**
 * Flushes queue of sessions that are to be notified of new data
 * enqueued events.
 *
 * @param thread_index Thread index for which the flush is to be performed.
 * @return 0 on success or a positive number indicating the number of
 *         failures due to API queue being full.
 */
int
session_main_flush_enqueue_events (u8 transport_proto, u32 thread_index)
{
  session_worker_t *wrk = session_main_get_worker (thread_index);
  session_t *s;
  int i, errors = 0;
  u32 *indices;

  indices = wrk->session_to_enqueue[transport_proto];

  for (i = 0; i < vec_len (indices); i++)
    {
      s = session_get_if_valid (indices[i], thread_index);
      if (PREDICT_FALSE (!s))
	{
	  errors++;
	  continue;
	}

      if (PREDICT_FALSE (session_enqueue_notify_inline (s)))
	errors++;
    }

  vec_reset_length (indices);
  wrk->session_to_enqueue[transport_proto] = indices;

  return errors;
}

int
session_main_flush_all_enqueue_events (u8 transport_proto)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  int i, errors = 0;
  for (i = 0; i < 1 + vtm->n_threads; i++)
    errors += session_main_flush_enqueue_events (transport_proto, i);
  return errors;
}

int
session_stream_connect_notify (transport_connection_t * tc, u8 is_fail)
{
  u32 opaque = 0, new_ti, new_si;
  app_worker_t *app_wrk;
  session_t *s = 0;
  u64 ho_handle;

  /*
   * Find connection handle and cleanup half-open table
   */
  ho_handle = session_lookup_half_open_handle (tc);
  if (ho_handle == HALF_OPEN_LOOKUP_INVALID_VALUE)
    {
      SESSION_DBG ("half-open was removed!");
      return -1;
    }
  session_lookup_del_half_open (tc);

  /* Get the app's index from the handle we stored when opening connection
   * and the opaque (api_context for external apps) from transport session
   * index */
  app_wrk = app_worker_get_if_valid (ho_handle >> 32);
  if (!app_wrk)
    return -1;

  opaque = tc->s_index;

  if (is_fail)
    return app_worker_connect_notify (app_wrk, s, opaque);

  s = session_alloc_for_connection (tc);
  s->session_state = SESSION_STATE_CONNECTING;
  s->app_wrk_index = app_wrk->wrk_index;
  new_si = s->session_index;
  new_ti = s->thread_index;

  if (app_worker_init_connected (app_wrk, s))
    {
      session_free (s);
      app_worker_connect_notify (app_wrk, 0, opaque);
      return -1;
    }

  if (app_worker_connect_notify (app_wrk, s, opaque))
    {
      s = session_get (new_si, new_ti);
      session_free_w_fifos (s);
      return -1;
    }

  s = session_get (new_si, new_ti);
  s->session_state = SESSION_STATE_READY;
  session_lookup_add_connection (tc, session_handle (s));

  return 0;
}

typedef struct _session_switch_pool_args
{
  u32 session_index;
  u32 thread_index;
  u32 new_thread_index;
  u32 new_session_index;
} session_switch_pool_args_t;

static void
session_switch_pool (void *cb_args)
{
  session_switch_pool_args_t *args = (session_switch_pool_args_t *) cb_args;
  session_t *s;
  ASSERT (args->thread_index == vlib_get_thread_index ());
  s = session_get (args->session_index, args->thread_index);
  s->tx_fifo->master_session_index = args->new_session_index;
  s->tx_fifo->master_thread_index = args->new_thread_index;
  transport_cleanup (session_get_transport_proto (s), s->connection_index,
		     s->thread_index);
  session_free (s);
  clib_mem_free (cb_args);
}

/**
 * Move dgram session to the right thread
 */
int
session_dgram_connect_notify (transport_connection_t * tc,
			      u32 old_thread_index, session_t ** new_session)
{
  session_t *new_s;
  session_switch_pool_args_t *rpc_args;

  /*
   * Clone half-open session to the right thread.
   */
  new_s = session_clone_safe (tc->s_index, old_thread_index);
  new_s->connection_index = tc->c_index;
  new_s->rx_fifo->master_session_index = new_s->session_index;
  new_s->rx_fifo->master_thread_index = new_s->thread_index;
  new_s->session_state = SESSION_STATE_READY;
  session_lookup_add_connection (tc, session_handle (new_s));

  /*
   * Ask thread owning the old session to clean it up and make us the tx
   * fifo owner
   */
  rpc_args = clib_mem_alloc (sizeof (*rpc_args));
  rpc_args->new_session_index = new_s->session_index;
  rpc_args->new_thread_index = new_s->thread_index;
  rpc_args->session_index = tc->s_index;
  rpc_args->thread_index = old_thread_index;
  session_send_rpc_evt_to_thread (rpc_args->thread_index, session_switch_pool,
				  rpc_args);

  tc->s_index = new_s->session_index;
  new_s->connection_index = tc->c_index;
  *new_session = new_s;
  return 0;
}

/**
 * Notification from transport that connection is being closed.
 *
 * A disconnect is sent to application but state is not removed. Once
 * disconnect is acknowledged by application, session disconnect is called.
 * Ultimately this leads to close being called on transport (passive close).
 */
void
session_transport_closing_notify (transport_connection_t * tc)
{
  app_worker_t *app_wrk;
  session_t *s;

  s = session_get (tc->s_index, tc->thread_index);
  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    return;
  s->session_state = SESSION_STATE_TRANSPORT_CLOSING;
  app_wrk = app_worker_get (s->app_wrk_index);
  app_worker_close_notify (app_wrk, s);
}

/**
 * Notification from transport that connection is being deleted
 *
 * This removes the session if it is still valid. It should be called only on
 * previously fully established sessions. For instance failed connects should
 * call stream_session_connect_notify and indicate that the connect has
 * failed.
 */
void
session_transport_delete_notify (transport_connection_t * tc)
{
  session_t *s;

  /* App might've been removed already */
  if (!(s = session_get_if_valid (tc->s_index, tc->thread_index)))
    return;

  /* Make sure we don't try to send anything more */
  svm_fifo_dequeue_drop_all (s->tx_fifo);

  switch (s->session_state)
    {
    case SESSION_STATE_CREATED:
      /* Session was created but accept notification was not yet sent to the
       * app. Cleanup everything. */
      session_lookup_del_session (s);
      session_free_w_fifos (s);
      break;
    case SESSION_STATE_ACCEPTING:
    case SESSION_STATE_TRANSPORT_CLOSING:
      /* If transport finishes or times out before we get a reply
       * from the app, mark transport as closed and wait for reply
       * before removing the session. Cleanup session table in advance
       * because transport will soon be closed and closed sessions
       * are assumed to have been removed from the lookup table */
      session_lookup_del_session (s);
      s->session_state = SESSION_STATE_TRANSPORT_CLOSED;
      break;
    case SESSION_STATE_CLOSING:
    case SESSION_STATE_CLOSED_WAITING:
      /* Cleanup lookup table as transport needs to still be valid.
       * Program transport close to ensure that all session events
       * have been cleaned up. Once transport close is called, the
       * session is just removed because both transport and app have
       * confirmed the close*/
      session_lookup_del_session (s);
      s->session_state = SESSION_STATE_TRANSPORT_CLOSED;
      session_program_transport_close (s);
      break;
    case SESSION_STATE_TRANSPORT_CLOSED:
      break;
    case SESSION_STATE_CLOSED:
      session_delete (s);
      break;
    default:
      clib_warning ("session state %u", s->session_state);
      session_delete (s);
      break;
    }
}

/**
 * Notification from transport that session can be closed
 *
 * Should be called by transport only if it was closed with non-empty
 * tx fifo and once it decides to begin the closing procedure prior to
 * issuing a delete notify. This gives the chance to the session layer
 * to cleanup any outstanding events.
 */
void
session_transport_closed_notify (transport_connection_t * tc)
{
  session_t *s;

  if (!(s = session_get_if_valid (tc->s_index, tc->thread_index)))
    return;

  /* If app close has not been received or has not yet resulted in
   * a transport close, only mark the session transport as closed */
  if (s->session_state <= SESSION_STATE_CLOSING)
    {
      session_lookup_del_session (s);
      s->session_state = SESSION_STATE_TRANSPORT_CLOSED;
    }
  else
    s->session_state = SESSION_STATE_CLOSED;
}

/**
 * Notify application that connection has been reset.
 */
void
session_transport_reset_notify (transport_connection_t * tc)
{
  app_worker_t *app_wrk;
  session_t *s;

  s = session_get (tc->s_index, tc->thread_index);
  svm_fifo_dequeue_drop_all (s->tx_fifo);
  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    return;
  s->session_state = SESSION_STATE_TRANSPORT_CLOSING;
  app_wrk = app_worker_get (s->app_wrk_index);
  app_worker_reset_notify (app_wrk, s);
}

int
session_stream_accept_notify (transport_connection_t * tc)
{
  app_worker_t *app_wrk;
  session_t *s;

  s = session_get (tc->s_index, tc->thread_index);
  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (!app_wrk)
    return -1;
  s->session_state = SESSION_STATE_ACCEPTING;
  return app_worker_accept_notify (app_wrk, s);
}

/**
 * Accept a stream session. Optionally ping the server by callback.
 */
int
session_stream_accept (transport_connection_t * tc, u32 listener_index,
		       u8 notify)
{
  session_t *s;
  int rv;

  s = session_alloc_for_connection (tc);
  s->listener_index = listener_index;
  s->session_state = SESSION_STATE_CREATED;

  if ((rv = app_worker_init_accepted (s)))
    return rv;

  session_lookup_add_connection (tc, session_handle (s));

  /* Shoulder-tap the server */
  if (notify)
    {
      app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
      return app_worker_accept_notify (app_wrk, s);
    }

  return 0;
}

int
session_open_cl (u32 app_wrk_index, session_endpoint_t * rmt, u32 opaque)
{
  transport_connection_t *tc;
  transport_endpoint_cfg_t *tep;
  app_worker_t *app_wrk;
  session_handle_t sh;
  session_t *s;
  int rv;

  tep = session_endpoint_to_transport_cfg (rmt);
  rv = transport_connect (rmt->transport_proto, tep);
  if (rv < 0)
    {
      SESSION_DBG ("Transport failed to open connection.");
      return VNET_API_ERROR_SESSION_CONNECT;
    }

  tc = transport_get_half_open (rmt->transport_proto, (u32) rv);

  /* For dgram type of service, allocate session and fifos now */
  app_wrk = app_worker_get (app_wrk_index);
  s = session_alloc_for_connection (tc);
  s->app_wrk_index = app_wrk->wrk_index;
  s->session_state = SESSION_STATE_OPENED;
  if (app_worker_init_connected (app_wrk, s))
    {
      session_free (s);
      return -1;
    }

  sh = session_handle (s);
  session_lookup_add_connection (tc, sh);

  return app_worker_connect_notify (app_wrk, s, opaque);
}

int
session_open_vc (u32 app_wrk_index, session_endpoint_t * rmt, u32 opaque)
{
  transport_connection_t *tc;
  transport_endpoint_cfg_t *tep;
  u64 handle;
  int rv;

  tep = session_endpoint_to_transport_cfg (rmt);
  rv = transport_connect (rmt->transport_proto, tep);
  if (rv < 0)
    {
      SESSION_DBG ("Transport failed to open connection.");
      return VNET_API_ERROR_SESSION_CONNECT;
    }

  tc = transport_get_half_open (rmt->transport_proto, (u32) rv);

  /* If transport offers a stream service, only allocate session once the
   * connection has been established.
   * Add connection to half-open table and save app and tc index. The
   * latter is needed to help establish the connection while the former
   * is needed when the connect notify comes and we have to notify the
   * external app
   */
  handle = (((u64) app_wrk_index) << 32) | (u64) tc->c_index;
  session_lookup_add_half_open (tc, handle);

  /* Store api_context (opaque) for when the reply comes. Not the nicest
   * thing but better than allocating a separate half-open pool.
   */
  tc->s_index = opaque;
  return 0;
}

int
session_open_app (u32 app_wrk_index, session_endpoint_t * rmt, u32 opaque)
{
  session_endpoint_cfg_t *sep = (session_endpoint_cfg_t *) rmt;
  transport_endpoint_cfg_t *tep_cfg = session_endpoint_to_transport_cfg (sep);

  sep->app_wrk_index = app_wrk_index;
  sep->opaque = opaque;

  return transport_connect (rmt->transport_proto, tep_cfg);
}

typedef int (*session_open_service_fn) (u32, session_endpoint_t *, u32);

/* *INDENT-OFF* */
static session_open_service_fn session_open_srv_fns[TRANSPORT_N_SERVICES] = {
  session_open_vc,
  session_open_cl,
  session_open_app,
};
/* *INDENT-ON* */

/**
 * Ask transport to open connection to remote transport endpoint.
 *
 * Stores handle for matching request with reply since the call can be
 * asynchronous. For instance, for TCP the 3-way handshake must complete
 * before reply comes. Session is only created once connection is established.
 *
 * @param app_index Index of the application requesting the connect
 * @param st Session type requested.
 * @param tep Remote transport endpoint
 * @param opaque Opaque data (typically, api_context) the application expects
 * 		 on open completion.
 */
int
session_open (u32 app_wrk_index, session_endpoint_t * rmt, u32 opaque)
{
  transport_service_type_t tst;
  tst = transport_protocol_service_type (rmt->transport_proto);
  return session_open_srv_fns[tst] (app_wrk_index, rmt, opaque);
}

/**
 * Ask transport to listen on session endpoint.
 *
 * @param s Session for which listen will be called. Note that unlike
 * 	    established sessions, listen sessions are not associated to a
 * 	    thread.
 * @param sep Local endpoint to be listened on.
 */
int
session_listen (session_t * ls, session_endpoint_cfg_t * sep)
{
  transport_endpoint_t *tep;
  u32 tc_index, s_index;

  /* Transport bind/listen */
  tep = session_endpoint_to_transport (sep);
  s_index = ls->session_index;
  tc_index = transport_start_listen (session_get_transport_proto (ls),
				     s_index, tep);

  if (tc_index == (u32) ~ 0)
    return -1;

  /* Attach transport to session. Lookup tables are populated by the app
   * worker because local tables (for ct sessions) are not backed by a fib */
  ls = listen_session_get (s_index);
  ls->connection_index = tc_index;

  return 0;
}

/**
 * Ask transport to stop listening on local transport endpoint.
 *
 * @param s Session to stop listening on. It must be in state LISTENING.
 */
int
session_stop_listen (session_t * s)
{
  transport_proto_t tp = session_get_transport_proto (s);
  transport_connection_t *tc;

  if (s->session_state != SESSION_STATE_LISTENING)
    return -1;

  tc = transport_get_listener (tp, s->connection_index);
  if (!tc)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  session_lookup_del_connection (tc);
  transport_stop_listen (tp, s->connection_index);
  return 0;
}

/**
 * Initialize session closing procedure.
 *
 * Request is always sent to session node to ensure that all outstanding
 * requests are served before transport is notified.
 */
void
session_close (session_t * s)
{
  if (!s)
    return;

  if (s->session_state >= SESSION_STATE_CLOSING)
    {
      /* Session will only be removed once both app and transport
       * acknowledge the close */
      if (s->session_state == SESSION_STATE_TRANSPORT_CLOSED)
	session_program_transport_close (s);

      /* Session already closed. Clear the tx fifo */
      if (s->session_state == SESSION_STATE_CLOSED)
	svm_fifo_dequeue_drop_all (s->tx_fifo);
      return;
    }

  s->session_state = SESSION_STATE_CLOSING;
  session_program_transport_close (s);
}

/**
 * Notify transport the session can be disconnected. This should eventually
 * result in a delete notification that allows us to cleanup session state.
 * Called for both active/passive disconnects.
 *
 * Must be called from the session's thread.
 */
void
session_transport_close (session_t * s)
{
  /* If transport is already closed, just free the session */
  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSED)
    {
      session_free_w_fifos (s);
      return;
    }

  /* If tx queue wasn't drained, change state to closed waiting for transport.
   * This way, the transport, if it so wishes, can continue to try sending the
   * outstanding data (in closed state it cannot). It MUST however at one
   * point, either after sending everything or after a timeout, call delete
   * notify. This will finally lead to the complete cleanup of the session.
   */
  if (svm_fifo_max_dequeue_cons (s->tx_fifo))
    s->session_state = SESSION_STATE_CLOSED_WAITING;
  else
    s->session_state = SESSION_STATE_CLOSED;

  transport_close (session_get_transport_proto (s), s->connection_index,
		   s->thread_index);
}

/**
 * Cleanup transport and session state.
 *
 * Notify transport of the cleanup and free the session. This should
 * be called only if transport reported some error and is already
 * closed.
 */
void
session_transport_cleanup (session_t * s)
{
  s->session_state = SESSION_STATE_CLOSED;

  /* Delete from main lookup table before we axe the the transport */
  session_lookup_del_session (s);
  transport_cleanup (session_get_transport_proto (s), s->connection_index,
		     s->thread_index);
  /* Since we called cleanup, no delete notification will come. So, make
   * sure the session is properly freed. */
  session_free_w_fifos (s);
}

/**
 * Allocate event queues in the shared-memory segment
 *
 * That can either be a newly created memfd segment, that will need to be
 * mapped by all stack users, or the binary api's svm region. The latter is
 * assumed to be already mapped. NOTE that this assumption DOES NOT hold if
 * api clients bootstrap shm api over sockets (i.e. use memfd segments) and
 * vpp uses api svm region for event queues.
 */
void
session_vpp_event_queues_allocate (session_main_t * smm)
{
  u32 evt_q_length = 2048, evt_size = sizeof (session_event_t);
  ssvm_private_t *eqs = &smm->evt_qs_segment;
  api_main_t *am = &api_main;
  uword eqs_size = 64 << 20;
  pid_t vpp_pid = getpid ();
  void *oldheap;
  int i;

  if (smm->configured_event_queue_length)
    evt_q_length = smm->configured_event_queue_length;

  if (smm->evt_qs_use_memfd_seg)
    {
      if (smm->evt_qs_segment_size)
	eqs_size = smm->evt_qs_segment_size;

      eqs->ssvm_size = eqs_size;
      eqs->i_am_master = 1;
      eqs->my_pid = vpp_pid;
      eqs->name = format (0, "%s%c", "evt-qs-segment", 0);
      eqs->requested_va = smm->session_baseva;

      if (ssvm_master_init (eqs, SSVM_SEGMENT_MEMFD))
	{
	  clib_warning ("failed to initialize queue segment");
	  return;
	}
    }

  if (smm->evt_qs_use_memfd_seg)
    oldheap = ssvm_push_heap (eqs->sh);
  else
    oldheap = svm_push_data_heap (am->vlib_rp);

  for (i = 0; i < vec_len (smm->wrk); i++)
    {
      svm_msg_q_cfg_t _cfg, *cfg = &_cfg;
      svm_msg_q_ring_cfg_t rc[SESSION_MQ_N_RINGS] = {
	{evt_q_length, evt_size, 0}
	,
	{evt_q_length >> 1, 256, 0}
      };
      cfg->consumer_pid = 0;
      cfg->n_rings = 2;
      cfg->q_nitems = evt_q_length;
      cfg->ring_cfgs = rc;
      smm->wrk[i].vpp_event_queue = svm_msg_q_alloc (cfg);
      if (smm->evt_qs_use_memfd_seg)
	{
	  if (svm_msg_q_alloc_consumer_eventfd (smm->wrk[i].vpp_event_queue))
	    clib_warning ("eventfd returned");
	}
    }

  if (smm->evt_qs_use_memfd_seg)
    ssvm_pop_heap (oldheap);
  else
    svm_pop_heap (oldheap);
}

ssvm_private_t *
session_main_get_evt_q_segment (void)
{
  session_main_t *smm = &session_main;
  if (smm->evt_qs_use_memfd_seg)
    return &smm->evt_qs_segment;
  return 0;
}

u64
session_segment_handle (session_t * s)
{
  svm_fifo_t *f;

  if (!s->rx_fifo)
    return SESSION_INVALID_HANDLE;

  f = s->rx_fifo;
  return segment_manager_make_segment_handle (f->segment_manager,
					      f->segment_index);
}

/* *INDENT-OFF* */
static session_fifo_rx_fn *session_tx_fns[TRANSPORT_TX_N_FNS] = {
    session_tx_fifo_peek_and_snd,
    session_tx_fifo_dequeue_and_snd,
    session_tx_fifo_dequeue_internal,
    session_tx_fifo_dequeue_and_snd
};
/* *INDENT-ON* */

/**
 * Initialize session layer for given transport proto and ip version
 *
 * Allocates per session type (transport proto + ip version) data structures
 * and adds arc from session queue node to session type output node.
 */
void
session_register_transport (transport_proto_t transport_proto,
			    const transport_proto_vft_t * vft, u8 is_ip4,
			    u32 output_node)
{
  session_main_t *smm = &session_main;
  session_type_t session_type;
  u32 next_index = ~0;

  session_type = session_type_from_proto_and_ip (transport_proto, is_ip4);

  vec_validate (smm->session_type_to_next, session_type);
  vec_validate (smm->session_tx_fns, session_type);

  /* *INDENT-OFF* */
  if (output_node != ~0)
    {
      foreach_vlib_main (({
          next_index = vlib_node_add_next (this_vlib_main,
                                           session_queue_node.index,
                                           output_node);
      }));
    }
  /* *INDENT-ON* */

  smm->session_type_to_next[session_type] = next_index;
  smm->session_tx_fns[session_type] = session_tx_fns[vft->tx_type];
}

transport_connection_t *
session_get_transport (session_t * s)
{
  if (s->session_state != SESSION_STATE_LISTENING)
    return transport_get_connection (session_get_transport_proto (s),
				     s->connection_index, s->thread_index);
  else
    return transport_get_listener (session_get_transport_proto (s),
				   s->connection_index);
}

void
session_get_endpoint (session_t * s, transport_endpoint_t * tep, u8 is_lcl)
{
  if (s->session_state != SESSION_STATE_LISTENING)
    return transport_get_endpoint (session_get_transport_proto (s),
				   s->connection_index, s->thread_index, tep,
				   is_lcl);
  else
    return transport_get_listener_endpoint (session_get_transport_proto (s),
					    s->connection_index, tep, is_lcl);
}

transport_connection_t *
listen_session_get_transport (session_t * s)
{
  return transport_get_listener (session_get_transport_proto (s),
				 s->connection_index);
}

void
session_flush_frames_main_thread (vlib_main_t * vm)
{
  ASSERT (vlib_get_thread_index () == 0);
  vlib_process_signal_event_mt (vm, session_queue_process_node.index,
				SESSION_Q_PROCESS_FLUSH_FRAMES, 0);
}

static clib_error_t *
session_manager_main_enable (vlib_main_t * vm)
{
  segment_manager_main_init_args_t _sm_args = { 0 }, *sm_args = &_sm_args;
  session_main_t *smm = &session_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads, preallocated_sessions_per_worker;
  session_worker_t *wrk;
  int i;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  if (num_threads < 1)
    return clib_error_return (0, "n_thread_stacks not set");

  /* Allocate cache line aligned worker contexts */
  vec_validate_aligned (smm->wrk, num_threads - 1, CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < num_threads; i++)
    {
      wrk = &smm->wrk[i];
      vec_validate (wrk->free_event_vector, 128);
      _vec_len (wrk->free_event_vector) = 0;
      vec_validate (wrk->pending_event_vector, 128);
      _vec_len (wrk->pending_event_vector) = 0;
      vec_validate (wrk->pending_disconnects, 128);
      _vec_len (wrk->pending_disconnects) = 0;
      vec_validate (wrk->postponed_event_vector, 128);
      _vec_len (wrk->postponed_event_vector) = 0;

      wrk->last_vlib_time = vlib_time_now (vlib_mains[i]);
      wrk->dispatch_period = 500e-6;

      if (num_threads > 1)
	clib_rwlock_init (&smm->wrk[i].peekers_rw_locks);
    }

#if SESSION_DEBUG
  vec_validate (smm->last_event_poll_by_thread, num_threads - 1);
#endif

  /* Allocate vpp event queues segment and queue */
  session_vpp_event_queues_allocate (smm);

  /* Initialize fifo segment main baseva and timeout */
  sm_args->baseva = smm->session_baseva + smm->evt_qs_segment_size;
  sm_args->size = smm->session_va_space_size;
  segment_manager_main_init (sm_args);

  /* Preallocate sessions */
  if (smm->preallocated_sessions)
    {
      if (num_threads == 1)
	{
	  pool_init_fixed (smm->wrk[0].sessions, smm->preallocated_sessions);
	}
      else
	{
	  int j;
	  preallocated_sessions_per_worker =
	    (1.1 * (f64) smm->preallocated_sessions /
	     (f64) (num_threads - 1));

	  for (j = 1; j < num_threads; j++)
	    {
	      pool_init_fixed (smm->wrk[j].sessions,
			       preallocated_sessions_per_worker);
	    }
	}
    }

  session_lookup_init ();
  app_namespaces_init ();
  transport_init ();

  smm->is_enabled = 1;

  /* Enable transports */
  transport_enable_disable (vm, 1);
  transport_init_tx_pacers_period ();
  return 0;
}

void
session_node_enable_disable (u8 is_en)
{
  u8 state = is_en ? VLIB_NODE_STATE_POLLING : VLIB_NODE_STATE_DISABLED;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u8 have_workers = vtm->n_threads != 0;

  /* *INDENT-OFF* */
  foreach_vlib_main (({
    if (have_workers && ii == 0)
      {
	vlib_node_set_state (this_vlib_main, session_queue_process_node.index,
	                     state);
	if (is_en)
	  {
	    vlib_node_t *n = vlib_get_node (this_vlib_main,
	                                    session_queue_process_node.index);
	    vlib_start_process (this_vlib_main, n->runtime_index);
	  }
	else
	  {
	    vlib_process_signal_event_mt (this_vlib_main,
	                                  session_queue_process_node.index,
	                                  SESSION_Q_PROCESS_STOP, 0);
	  }

	continue;
      }
    vlib_node_set_state (this_vlib_main, session_queue_node.index,
                         state);
  }));
  /* *INDENT-ON* */
}

clib_error_t *
vnet_session_enable_disable (vlib_main_t * vm, u8 is_en)
{
  clib_error_t *error = 0;
  if (is_en)
    {
      if (session_main.is_enabled)
	return 0;

      session_node_enable_disable (is_en);
      error = session_manager_main_enable (vm);
    }
  else
    {
      session_main.is_enabled = 0;
      session_node_enable_disable (is_en);
    }

  return error;
}

clib_error_t *
session_manager_main_init (vlib_main_t * vm)
{
  session_main_t *smm = &session_main;
  smm->session_baseva = HIGH_SEGMENT_BASEVA;
#if (HIGH_SEGMENT_BASEVA > (4ULL << 30))
  smm->session_va_space_size = 128ULL << 30;
  smm->evt_qs_segment_size = 64 << 20;
#else
  smm->session_va_space_size = 128 << 20;
  smm->evt_qs_segment_size = 1 << 20;
#endif
  smm->is_enabled = 0;
  return 0;
}

VLIB_INIT_FUNCTION (session_manager_main_init);

static clib_error_t *
session_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  session_main_t *smm = &session_main;
  u32 nitems;
  uword tmp;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "event-queue-length %d", &nitems))
	{
	  if (nitems >= 2048)
	    smm->configured_event_queue_length = nitems;
	  else
	    clib_warning ("event queue length %d too small, ignored", nitems);
	}
      else if (unformat (input, "preallocated-sessions %d",
			 &smm->preallocated_sessions))
	;
      else if (unformat (input, "v4-session-table-buckets %d",
			 &smm->configured_v4_session_table_buckets))
	;
      else if (unformat (input, "v4-halfopen-table-buckets %d",
			 &smm->configured_v4_halfopen_table_buckets))
	;
      else if (unformat (input, "v6-session-table-buckets %d",
			 &smm->configured_v6_session_table_buckets))
	;
      else if (unformat (input, "v6-halfopen-table-buckets %d",
			 &smm->configured_v6_halfopen_table_buckets))
	;
      else if (unformat (input, "v4-session-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->configured_v4_session_table_memory = tmp;
	}
      else if (unformat (input, "v4-halfopen-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->configured_v4_halfopen_table_memory = tmp;
	}
      else if (unformat (input, "v6-session-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->configured_v6_session_table_memory = tmp;
	}
      else if (unformat (input, "v6-halfopen-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->configured_v6_halfopen_table_memory = tmp;
	}
      else if (unformat (input, "local-endpoints-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->local_endpoints_table_memory = tmp;
	}
      else if (unformat (input, "local-endpoints-table-buckets %d",
			 &smm->local_endpoints_table_buckets))
	;
      else if (unformat (input, "evt_qs_memfd_seg"))
	smm->evt_qs_use_memfd_seg = 1;
      else if (unformat (input, "evt_qs_seg_size %U", unformat_memory_size,
			 &smm->evt_qs_segment_size))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (session_config_fn, "session");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
