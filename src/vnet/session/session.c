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

#include <vnet/plugin/plugin.h>
#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>
#include <vlib/stats/stats.h>
#include <vlib/dma/dma.h>
#include <vnet/session/session_rules_table.h>

session_main_t session_main;

typedef enum
{
  SESSION_EVT_RPC,
  SESSION_EVT_IO,
  SESSION_EVT_SESSION,
} session_evt_family_t;

static inline int
session_send_evt_to_thread (void *data, void *args,
			    clib_thread_index_t thread_index,
			    session_evt_type_t evt_type,
			    session_evt_family_t family)
{
  session_worker_t *wrk = session_main_get_worker (thread_index);
  session_event_t *evt;
  svm_msg_q_msg_t msg;
  svm_msg_q_t *mq;

  mq = wrk->vpp_event_queue;
  if (PREDICT_FALSE (svm_msg_q_lock (mq)))
    return -1;
  if (PREDICT_FALSE (svm_msg_q_or_ring_is_full (mq, SESSION_MQ_IO_EVT_RING)))
    {
      svm_msg_q_unlock (mq);
      return -2;
    }
  switch (family)
    {
    case SESSION_EVT_RPC:
      ASSERT (evt_type == SESSION_CTRL_EVT_RPC);
      msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
      evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
      evt->rpc_args.fp = data;
      evt->rpc_args.arg = args;
      break;
    case SESSION_EVT_IO:
      ASSERT (evt_type == SESSION_IO_EVT_RX || evt_type == SESSION_IO_EVT_TX ||
	      evt_type == SESSION_IO_EVT_TX_FLUSH ||
	      evt_type == SESSION_IO_EVT_BUILTIN_RX);
      msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
      evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
      evt->session_index = *(u32 *) data;
      break;
    case SESSION_EVT_SESSION:
      ASSERT (evt_type == SESSION_CTRL_EVT_CLOSE ||
	      evt_type == SESSION_CTRL_EVT_HALF_CLOSE ||
	      evt_type == SESSION_CTRL_EVT_RESET);
      msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
      evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
      evt->session_handle = session_handle ((session_t *) data);
      break;
    default:
      ASSERT (0);
      clib_warning ("evt unhandled!");
      svm_msg_q_unlock (mq);
      return -1;
    }
  evt->event_type = evt_type;

  svm_msg_q_add_and_unlock (mq, &msg);

  if (PREDICT_FALSE (wrk->state == SESSION_WRK_INTERRUPT))
    vlib_node_set_interrupt_pending (wrk->vm, session_queue_node.index);

  return 0;
}

/* Deprecated, use session_program_* functions */
int
session_send_io_evt_to_thread (svm_fifo_t * f, session_evt_type_t evt_type)
{
  return session_send_evt_to_thread (&f->vpp_session_index, 0,
				     f->master_thread_index, evt_type,
				     SESSION_EVT_IO);
}

/* Deprecated, use session_program_* functions */
int
session_send_io_evt_to_thread_custom (void *data,
				      clib_thread_index_t thread_index,
				      session_evt_type_t evt_type)
{
  return session_send_evt_to_thread (data, 0, thread_index, evt_type,
				     SESSION_EVT_IO);
}

int
session_program_tx_io_evt (session_handle_tu_t sh, session_evt_type_t evt_type)
{
  return session_send_evt_to_thread ((void *) &sh.session_index, 0,
				     (u32) sh.thread_index, evt_type,
				     SESSION_EVT_IO);
}

int
session_program_rx_io_evt (session_handle_tu_t sh)
{
  if (sh.thread_index == vlib_get_thread_index ())
    {
      session_t *s = session_get_from_handle (sh);
      return session_enqueue_notify (s);
    }
  else
    {
      return session_send_evt_to_thread (
	(void *) &sh.session_index, 0, (u32) sh.thread_index,
	SESSION_IO_EVT_BUILTIN_RX, SESSION_EVT_IO);
    }
}

int
session_program_transport_io_evt (session_handle_tu_t sh,
				  session_evt_type_t evt_type)
{
  return session_send_evt_to_thread ((void *) &sh.session_index, 0,
				     (u32) sh.thread_index, evt_type,
				     SESSION_EVT_IO);
}

int
session_send_ctrl_evt_to_thread (session_t * s, session_evt_type_t evt_type)
{
  /* only events supported are disconnect, shutdown and reset */
  return session_send_evt_to_thread (s, 0, s->thread_index, evt_type,
				     SESSION_EVT_SESSION);
}

void
session_send_rpc_evt_to_thread_force (clib_thread_index_t thread_index,
				      void *fp, void *rpc_args)
{
  session_send_evt_to_thread (fp, rpc_args, thread_index, SESSION_CTRL_EVT_RPC,
			      SESSION_EVT_RPC);
}

void
session_send_rpc_evt_to_thread (clib_thread_index_t thread_index, void *fp,
				void *rpc_args)
{
  if (thread_index != vlib_get_thread_index ())
    session_send_rpc_evt_to_thread_force (thread_index, fp, rpc_args);
  else
    {
      void (*fnp) (void *) = fp;
      fnp (rpc_args);
    }
}

void
session_add_self_custom_tx_evt (transport_connection_t * tc, u8 has_prio)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);

  ASSERT (s->thread_index == vlib_get_thread_index ());
  ASSERT (s->session_state != SESSION_STATE_TRANSPORT_DELETED);

  if (!(s->flags & SESSION_F_CUSTOM_TX))
    {
      s->flags |= SESSION_F_CUSTOM_TX;
      if (svm_fifo_set_event (s->tx_fifo)
	  || transport_connection_is_descheduled (tc))
	{
	  session_evt_elt_t *elt;
	  session_worker_t *wrk;

	  wrk = session_main_get_worker (tc->thread_index);
	  if (has_prio)
	    elt = session_evt_alloc_new (wrk);
	  else
	    elt = session_evt_alloc_old (wrk);
	  elt->evt.session_index = tc->s_index;
	  elt->evt.event_type = SESSION_IO_EVT_TX;
	  tc->flags &= ~TRANSPORT_CONNECTION_F_DESCHED;

	  if (PREDICT_FALSE (wrk->state == SESSION_WRK_INTERRUPT))
	    vlib_node_set_interrupt_pending (wrk->vm,
					     session_queue_node.index);
	}
    }
}

void
sesssion_reschedule_tx (transport_connection_t * tc)
{
  session_worker_t *wrk = session_main_get_worker (tc->thread_index);
  session_evt_elt_t *elt;

  ASSERT (tc->thread_index == vlib_get_thread_index ());

  elt = session_evt_alloc_new (wrk);
  elt->evt.session_index = tc->s_index;
  elt->evt.event_type = SESSION_IO_EVT_TX;

  if (PREDICT_FALSE (wrk->state == SESSION_WRK_INTERRUPT))
    vlib_node_set_interrupt_pending (wrk->vm, session_queue_node.index);
}

static void
session_program_transport_ctrl_evt (session_t * s, session_evt_type_t evt)
{
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  session_evt_elt_t *elt;
  session_worker_t *wrk;

  /* If we are in the handler thread, or being called with the worker barrier
   * held, just append a new event to pending disconnects vector. */
  if (vlib_thread_is_main_w_barrier () || thread_index == s->thread_index)
    {
      wrk = session_main_get_worker (s->thread_index);
      elt = session_evt_alloc_ctrl (wrk);
      clib_memset (&elt->evt, 0, sizeof (session_event_t));
      elt->evt.session_handle = session_handle (s);
      elt->evt.event_type = evt;

      if (PREDICT_FALSE (wrk->state == SESSION_WRK_INTERRUPT))
	vlib_node_set_interrupt_pending (wrk->vm, session_queue_node.index);
    }
  else
    session_send_ctrl_evt_to_thread (s, evt);
}

session_t *
session_alloc (clib_thread_index_t thread_index)
{
  session_worker_t *wrk = &session_main.wrk[thread_index];
  session_t *s;

  pool_get_aligned_safe (wrk->sessions, s, CLIB_CACHE_LINE_BYTES);
  clib_memset (s, 0, sizeof (*s));
  s->session_index = s - wrk->sessions;
  s->thread_index = thread_index;
  s->al_index = APP_INVALID_INDEX;

  return s;
}

void
session_free (session_t * s)
{
  session_worker_t *wrk = &session_main.wrk[s->thread_index];

  SESSION_EVT (SESSION_EVT_FREE, s);
  if (CLIB_DEBUG)
    clib_memset (s, 0xFA, sizeof (*s));
  pool_put (wrk->sessions, s);
}

u8
session_is_valid (u32 si, u8 thread_index)
{
  session_t *s;
  transport_connection_t *tc;

  s = pool_elt_at_index (session_main.wrk[thread_index].sessions, si);

  if (s->thread_index != thread_index || s->session_index != si)
    return 0;

  if (s->session_state == SESSION_STATE_TRANSPORT_DELETED
      || s->session_state <= SESSION_STATE_LISTENING)
    return 1;

  if ((s->session_state == SESSION_STATE_CONNECTING ||
       s->session_state == SESSION_STATE_TRANSPORT_CLOSED) &&
      (s->flags & SESSION_F_HALF_OPEN))
    return 1;

  tc = session_get_transport (s);
  if (s->connection_index != tc->c_index ||
      s->thread_index != tc->thread_index || tc->s_index != si)
    return 0;

  return 1;
}

void
session_cleanup (session_t *s)
{
  segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
  session_free (s);
}

static void
session_cleanup_notify (session_t * s, session_cleanup_ntf_t ntf)
{
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (PREDICT_FALSE (!app_wrk))
    {
      if (ntf == SESSION_CLEANUP_TRANSPORT)
	return;

      session_cleanup (s);
      return;
    }
  app_worker_cleanup_notify (app_wrk, s, ntf);
}

static void
session_cleanup_notify_custom (session_t *s, session_cleanup_ntf_t ntf,
			       transport_cleanup_cb_fn cb_fn)
{
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (PREDICT_FALSE (!app_wrk))
    {
      if (ntf == SESSION_CLEANUP_TRANSPORT)
	{
	  transport_cleanup_cb (cb_fn, session_get_transport (s));
	  return;
	}

      session_cleanup (s);
      return;
    }
  app_worker_cleanup_notify_custom (app_wrk, s, ntf, cb_fn);
}

void
session_program_cleanup (session_t *s)
{
  ASSERT (s->session_state == SESSION_STATE_TRANSPORT_DELETED);
  session_cleanup_notify (s, SESSION_CLEANUP_SESSION);
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
    clib_warning ("session %u hash delete rv %d", s->session_index, rv);

  session_program_cleanup (s);
}

void
session_cleanup_half_open (session_handle_t ho_handle)
{
  session_t *ho = session_get_from_handle (ho_handle);

  /* App transports can migrate their half-opens */
  if (ho->flags & SESSION_F_IS_MIGRATING)
    {
      /* Session still migrating, move to closed state to signal that the
       * session should be removed. */
      if (ho->connection_index == ~0)
	{
	  session_set_state (ho, SESSION_STATE_CLOSED);
	  return;
	}
      /* Migrated transports are no longer half-opens */
      transport_cleanup (session_get_transport_proto (ho),
			 ho->connection_index, ho->al_index /* overloaded */);
    }
  else if (ho->session_state != SESSION_STATE_TRANSPORT_DELETED)
    {
      /* Cleanup half-open session lookup table if need be */
      if (ho->session_state != SESSION_STATE_TRANSPORT_CLOSED)
	{
	  transport_connection_t *tc;
	  tc = transport_get_half_open (session_get_transport_proto (ho),
					ho->connection_index);
	  if (tc && !(tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
	    session_lookup_del_half_open (tc);
	}
      transport_cleanup_half_open (session_get_transport_proto (ho),
				   ho->connection_index);
    }
  session_free (ho);
}

static void
session_half_open_free (session_t *ho)
{
  app_worker_t *app_wrk;

  ASSERT (vlib_get_thread_index () <= transport_cl_thread ());
  app_wrk = app_worker_get_if_valid (ho->app_wrk_index);
  if (app_wrk)
    app_worker_del_half_open (app_wrk, ho);
  else
    session_free (ho);
}

static void
session_half_open_free_rpc (void *args)
{
  session_t *ho = ho_session_get (pointer_to_uword (args));
  session_half_open_free (ho);
}

void
session_half_open_delete_notify (transport_connection_t *tc)
{
  session_t *ho = ho_session_get (tc->s_index);

  /* Cleanup half-open lookup table if need be */
  if (ho->session_state != SESSION_STATE_TRANSPORT_CLOSED)
    {
      if (!(tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
	session_lookup_del_half_open (tc);
    }
  session_set_state (ho, SESSION_STATE_TRANSPORT_DELETED);

  /* Notification from ctrl thread accepted without rpc */
  if (tc->thread_index == transport_cl_thread ())
    {
      session_half_open_free (ho);
    }
  else
    {
      void *args = uword_to_pointer ((uword) tc->s_index, void *);
      session_send_rpc_evt_to_thread_force (transport_cl_thread (),
					    session_half_open_free_rpc, args);
    }
}

void
session_half_open_migrate_notify (transport_connection_t *tc)
{
  session_t *ho;

  /* Support half-open migrations only for transports with no lookup */
  ASSERT (tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP);

  ho = ho_session_get (tc->s_index);
  ho->flags |= SESSION_F_IS_MIGRATING;
  ho->connection_index = ~0;
}

int
session_half_open_migrated_notify (transport_connection_t *tc)
{
  session_t *ho;

  ho = ho_session_get (tc->s_index);

  /* App probably detached so the half-open must be cleaned up */
  if (ho->session_state == SESSION_STATE_CLOSED)
    {
      session_half_open_delete_notify (tc);
      return -1;
    }
  ho->connection_index = tc->c_index;
  /* Overload al_index for half-open with new thread */
  ho->al_index = tc->thread_index;
  return 0;
}

session_t *
session_alloc_for_connection (transport_connection_t * tc)
{
  session_t *s;
  clib_thread_index_t thread_index = tc->thread_index;

  ASSERT (thread_index == vlib_get_thread_index ()
	  || transport_protocol_is_cl (tc->proto));

  s = session_alloc (thread_index);
  s->session_type = session_type_from_proto_and_ip (tc->proto, tc->is_ip4);
  session_set_state (s, SESSION_STATE_CLOSED);

  /* Attach transport to session and vice versa */
  s->connection_index = tc->c_index;
  tc->s_index = s->session_index;
  return s;
}

static session_t *
session_alloc_for_stream (session_handle_t parent_handle)
{
  session_t *s, *ps;
  clib_thread_index_t thread_index =
    session_thread_from_handle (parent_handle);

  ASSERT (thread_index == vlib_get_thread_index ());

  ps = session_get_from_handle (parent_handle);
  s = session_alloc (thread_index);
  s->listener_handle = SESSION_INVALID_HANDLE;
  s->session_type = ps->session_type;
  session_set_state (s, SESSION_STATE_CLOSED);

  return s;
}

session_t *
session_alloc_for_half_open (transport_connection_t *tc)
{
  session_t *s;

  s = ho_session_alloc ();
  s->session_type = session_type_from_proto_and_ip (tc->proto, tc->is_ip4);
  s->connection_index = tc->c_index;
  tc->s_index = s->session_index;
  return s;
}

void
session_fifo_tuning (session_t * s, svm_fifo_t * f,
		     session_ft_action_t act, u32 len)
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

void
session_wrk_program_app_wrk_evts (session_worker_t *wrk, u32 app_wrk_index)
{
  u8 need_interrupt;

  ASSERT ((wrk - session_main.wrk) == vlib_get_thread_index ());
  need_interrupt = clib_bitmap_is_zero (wrk->app_wrks_pending_ntf);
  wrk->app_wrks_pending_ntf =
    clib_bitmap_set (wrk->app_wrks_pending_ntf, app_wrk_index, 1);

  if (need_interrupt)
    vlib_node_set_interrupt_pending (wrk->vm, session_input_node.index);
}

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

int
session_enqueue_notify (session_t *s)
{
  return session_enqueue_notify_inline (s, 0 /* is_cl */);
}

int
session_enqueue_notify_cl (session_t *s)
{
  return session_enqueue_notify_inline (s, 1 /* is_cl */);
}

int
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

/**
 * Flushes queue of sessions that are to be notified of new data
 * enqueued events.
 *
 * @param transport_proto transport protocol for which queue to be flushed
 * @param thread_index Thread index for which the flush is to be performed.
 * @return 0 on success or a positive number indicating the number of
 *         failures due to API queue being full.
 */
void
session_main_flush_enqueue_events (transport_proto_t transport_proto,
				   clib_thread_index_t thread_index)
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

int
session_enqueue_dgram_connection_cl (session_t *s, session_dgram_hdr_t *hdr,
				     vlib_buffer_t *b, u8 proto,
				     u8 queue_event)
{
  session_t *awls;

  awls = app_listener_select_wrk_cl_session (s, hdr);
  return session_enqueue_dgram_connection_inline (awls, hdr, b, proto,
						  queue_event, 1 /* is_cl */);
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
  u32 rv;

  rv = svm_fifo_dequeue_drop (s->tx_fifo, max_bytes);
  session_fifo_tuning (s, s->tx_fifo, SESSION_FT_ACTION_DEQUEUED, rv);

  if (svm_fifo_needs_deq_ntf (s->tx_fifo, max_bytes))
    session_dequeue_notify (s);

  return rv;
}

int
session_stream_connect_notify (transport_connection_t * tc,
			       session_error_t err)
{
  u32 opaque = 0, new_ti, new_si;
  app_worker_t *app_wrk;
  session_t *s = 0, *ho;

  /*
   * Cleanup half-open table
   */
  session_lookup_del_half_open (tc);

  ho = ho_session_get (tc->s_index);
  session_set_state (ho, SESSION_STATE_TRANSPORT_CLOSED);
  opaque = ho->opaque;
  app_wrk = app_worker_get_if_valid (ho->app_wrk_index);
  if (!app_wrk)
    return -1;

  if (err)
    return app_worker_connect_notify (app_wrk, s, err, opaque);

  s = session_alloc_for_connection (tc);
  session_set_state (s, SESSION_STATE_CONNECTING);
  s->app_wrk_index = app_wrk->wrk_index;
  s->listener_handle = SESSION_INVALID_HANDLE;
  s->opaque = opaque;
  new_si = s->session_index;
  new_ti = s->thread_index;

  if ((err = app_worker_init_connected (app_wrk, s)))
    {
      session_free (s);
      app_worker_connect_notify (app_wrk, 0, err, opaque);
      return -1;
    }

  s = session_get (new_si, new_ti);
  session_set_state (s, SESSION_STATE_READY);
  session_lookup_add_connection (tc, session_handle (s));

  if (app_worker_connect_notify (app_wrk, s, SESSION_E_NONE, opaque))
    {
      session_lookup_del_connection (tc);
      /* Avoid notifying app about rejected session cleanup */
      s = session_get (new_si, new_ti);
      segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
      session_free (s);
      return -1;
    }

  return 0;
}

static void
session_switch_pool_closed_rpc (void *arg)
{
  session_handle_t sh;
  session_t *s;

  sh = pointer_to_uword (arg);
  s = session_get_from_handle_if_valid (sh);
  if (!s)
    return;

  transport_cleanup (session_get_transport_proto (s), s->connection_index,
		     s->thread_index);
  session_cleanup (s);
}

typedef struct _session_switch_pool_args
{
  u32 session_index;
  clib_thread_index_t thread_index;
  u32 new_thread_index;
  u32 new_session_index;
} session_switch_pool_args_t;

/**
 * Notify old thread of the session pool switch
 */
static void
session_switch_pool (void *cb_args)
{
  session_switch_pool_args_t *args = (session_switch_pool_args_t *) cb_args;
  session_handle_t new_sh;
  segment_manager_t *sm;
  app_worker_t *app_wrk;
  session_t *s;

  ASSERT (args->thread_index == vlib_get_thread_index ());
  s = session_get (args->session_index, args->thread_index);
  new_sh =
    session_make_handle (args->new_session_index, args->new_thread_index);

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (!app_wrk)
    goto app_closed;

  if (!(s->flags & SESSION_F_PROXY))
    {
      if (svm_fifo_max_dequeue (s->tx_fifo))
	session_program_tx_io_evt (new_sh, SESSION_IO_EVT_TX);
      /* Cleanup fifo segment slice state for fifos */
      sm = app_worker_get_connect_segment_manager (app_wrk);
      segment_manager_detach_fifo (sm, &s->rx_fifo);
      segment_manager_detach_fifo (sm, &s->tx_fifo);
    }

  /* Check if session closed during migration */
  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    goto app_closed;

  app_worker_migrate_notify (app_wrk, s, new_sh);

  clib_mem_free (cb_args);
  return;

app_closed:
  /* Session closed during migration. Clean everything up */
  session_send_rpc_evt_to_thread (args->new_thread_index,
				  session_switch_pool_closed_rpc,
				  uword_to_pointer (new_sh, void *));
  transport_cleanup (session_get_transport_proto (s), s->connection_index,
		     s->thread_index);
  session_cleanup (s);
  clib_mem_free (cb_args);
}

/**
 * Move dgram session to the right thread
 */
int
session_dgram_connect_notify (transport_connection_t *tc,
			      session_handle_tu_t osh, session_t **new_session)
{
  session_t *new_s;
  session_switch_pool_args_t *rpc_args;
  segment_manager_t *sm;
  app_worker_t *app_wrk;

  /*
   * Clone half-open session to the right thread.
   */
  new_s = session_clone_safe (tc->s_index, osh.thread_index);
  new_s->connection_index = tc->c_index;
  new_s->listener_handle = SESSION_INVALID_HANDLE;
  session_set_state (new_s, SESSION_STATE_READY);
  new_s->flags |= SESSION_F_IS_MIGRATING;

  if (!(tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
    session_lookup_add_connection (tc, session_handle (new_s));

  app_wrk = app_worker_get_if_valid (new_s->app_wrk_index);
  if (app_wrk && !(new_s->flags & SESSION_F_PROXY))
    {
      /* New set of fifos attached to the same shared memory */
      sm = app_worker_get_connect_segment_manager (app_wrk);
      segment_manager_attach_fifo (sm, &new_s->rx_fifo, new_s);
      segment_manager_attach_fifo (sm, &new_s->tx_fifo, new_s);
    }

  /*
   * Ask thread owning the old session to clean it up and make us the tx
   * fifo owner
   */
  rpc_args = clib_mem_alloc (sizeof (*rpc_args));
  rpc_args->new_session_index = new_s->session_index;
  rpc_args->new_thread_index = new_s->thread_index;
  rpc_args->session_index = tc->s_index;
  rpc_args->thread_index = osh.thread_index;
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

  /* Wait for reply from app before sending notification as the
   * accept might be rejected */
  if (s->session_state == SESSION_STATE_ACCEPTING)
    {
      session_set_state (s, SESSION_STATE_TRANSPORT_CLOSING);
      return;
    }

  session_set_state (s, SESSION_STATE_TRANSPORT_CLOSING);
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

  switch (s->session_state)
    {
    case SESSION_STATE_CREATED:
      /* Session was created but accept notification was not yet sent to the
       * app. Cleanup everything. */
      session_lookup_del_session (s);
      segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
      session_free (s);
      break;
    case SESSION_STATE_ACCEPTING:
    case SESSION_STATE_TRANSPORT_CLOSING:
    case SESSION_STATE_CLOSING:
    case SESSION_STATE_TRANSPORT_CLOSED:
      /* If transport finishes or times out before we get a reply
       * from the app, mark transport as closed and wait for reply
       * before removing the session. Cleanup session table in advance
       * because transport will soon be closed and closed sessions
       * are assumed to have been removed from the lookup table */
      session_lookup_del_session (s);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify (s, SESSION_CLEANUP_TRANSPORT);
      break;
    case SESSION_STATE_APP_CLOSED:
      /* Cleanup lookup table as transport needs to still be valid.
       * Program transport close to ensure that all session events
       * have been cleaned up. Once transport close is called, the
       * session is just removed because both transport and app have
       * confirmed the close*/
      session_lookup_del_session (s);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify (s, SESSION_CLEANUP_TRANSPORT);
      session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_CLOSE);
      break;
    case SESSION_STATE_TRANSPORT_DELETED:
      break;
    case SESSION_STATE_CLOSED:
      session_cleanup_notify (s, SESSION_CLEANUP_TRANSPORT);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_delete (s);
      break;
    default:
      clib_warning ("session %u state %u", s->session_index, s->session_state);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify (s, SESSION_CLEANUP_TRANSPORT);
      session_delete (s);
      break;
    }
}

/**
 * Request from transport to program connection deletion
 *
 * Similar to session_transport_delete_notify just that transport
 * is asking session layer to delete the transport connection after
 * it delievers notifications to app. Must be used if transport
 * stats are to be collected.
 */
void
session_transport_delete_request (transport_connection_t *tc,
				  transport_cleanup_cb_fn cb_fn)
{
  session_t *s;

  /* App might've been removed already */
  if (!(s = session_get_if_valid (tc->s_index, tc->thread_index)))
    {
      transport_cleanup_cb (cb_fn, tc);
      return;
    }

  switch (s->session_state)
    {
    case SESSION_STATE_CREATED:
      /* Session was created but accept notification was not yet sent to the
       * app. Cleanup everything. */
      session_lookup_del_session (s);
      segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
      transport_cleanup_cb (cb_fn, tc);
      session_free (s);
      break;
    case SESSION_STATE_ACCEPTING:
    case SESSION_STATE_TRANSPORT_CLOSING:
    case SESSION_STATE_CLOSING:
    case SESSION_STATE_TRANSPORT_CLOSED:
      /* If transport finishes or times out before we get a reply
       * from the app, mark transport as closed and wait for reply
       * before removing the session. Cleanup session table in advance
       * because transport will soon be closed and closed sessions
       * are assumed to have been removed from the lookup table */
      session_lookup_del_session (s);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify_custom (s, SESSION_CLEANUP_TRANSPORT, cb_fn);
      break;
    case SESSION_STATE_APP_CLOSED:
      /* Cleanup lookup table as transport needs to still be valid.
       * Program transport close to ensure that all session events
       * have been cleaned up. Once transport close is called, the
       * session is just removed because both transport and app have
       * confirmed the close*/
      session_lookup_del_session (s);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify_custom (s, SESSION_CLEANUP_TRANSPORT, cb_fn);
      session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_CLOSE);
      break;
    case SESSION_STATE_TRANSPORT_DELETED:
      transport_cleanup_cb (cb_fn, tc);
      break;
    case SESSION_STATE_CLOSED:
      session_cleanup_notify_custom (s, SESSION_CLEANUP_TRANSPORT, cb_fn);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_delete (s);
      break;
    default:
      clib_warning ("session %u state %u", s->session_index, s->session_state);
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify_custom (s, SESSION_CLEANUP_TRANSPORT, cb_fn);
      session_delete (s);
      break;
    }
}

/**
 * Notification from transport that it is closed
 *
 * Should be called by transport, prior to calling delete notify, once it
 * knows that no more data will be exchanged. This could serve as an
 * early acknowledgment of an active close especially if transport delete
 * can be delayed a long time, e.g., tcp time-wait.
 */
void
session_transport_closed_notify (transport_connection_t * tc)
{
  app_worker_t *app_wrk;
  session_t *s;

  if (!(s = session_get_if_valid (tc->s_index, tc->thread_index)))
    return;

  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSED)
    return;

  /* Transport thinks that app requested close but it actually didn't.
   * Can happen for tcp:
   * 1)if fin and rst are received in close succession.
   * 2)if app shutdown the connection.  */
  if (s->session_state == SESSION_STATE_READY)
    {
      session_transport_closing_notify (tc);
      session_set_state (s, SESSION_STATE_TRANSPORT_CLOSED);
    }
  /* If app close has not been received or has not yet resulted in
   * a transport close, only mark the session transport as closed */
  else if (s->session_state <= SESSION_STATE_CLOSING)
    session_set_state (s, SESSION_STATE_TRANSPORT_CLOSED);
  /* If app also closed, switch to closed */
  else if (s->session_state == SESSION_STATE_APP_CLOSED)
    session_set_state (s, SESSION_STATE_CLOSED);

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (app_wrk)
    app_worker_transport_closed_notify (app_wrk, s);
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
  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    return;
  if (s->session_state == SESSION_STATE_ACCEPTING)
    {
      session_set_state (s, SESSION_STATE_TRANSPORT_CLOSING);
      return;
    }
  session_set_state (s, SESSION_STATE_TRANSPORT_CLOSING);
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
  if (s->session_state != SESSION_STATE_CREATED)
    return 0;
  session_set_state (s, SESSION_STATE_ACCEPTING);
  if (app_worker_accept_notify (app_wrk, s))
    {
      /* On transport delete, no notifications should be sent. Unless, the
       * accept is retried and successful. */
      session_set_state (s, SESSION_STATE_CREATED);
      return -1;
    }
  return 0;
}

/**
 * Accept a stream session. Optionally ping the server by callback.
 */
int
session_stream_accept (transport_connection_t *tc, u32 listener_index,
		       clib_thread_index_t thread_index, u8 notify)
{
  session_t *s;
  int rv;

  s = session_alloc_for_connection (tc);
  s->listener_handle = ((u64) thread_index << 32) | (u64) listener_index;
  session_set_state (s, SESSION_STATE_CREATED);

  if ((rv = app_worker_init_accepted (s)))
    {
      session_free (s);
      return rv;
    }

  session_lookup_add_connection (tc, session_handle (s));

  /* Shoulder-tap the server */
  if (notify)
    {
      app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
      if ((rv = app_worker_accept_notify (app_wrk, s)))
	{
	  session_lookup_del_session (s);
	  segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
	  session_free (s);
	  return rv;
	}
    }

  return 0;
}

int
session_dgram_accept (transport_connection_t *tc, u32 listener_index,
		      clib_thread_index_t thread_index)
{
  app_worker_t *app_wrk;
  session_t *s;
  int rv;

  s = session_alloc_for_connection (tc);
  s->listener_handle = ((u64) thread_index << 32) | (u64) listener_index;

  if ((rv = app_worker_init_accepted (s)))
    {
      session_free (s);
      return rv;
    }

  session_lookup_add_connection (tc, session_handle (s));
  session_set_state (s, SESSION_STATE_ACCEPTING);

  app_wrk = app_worker_get (s->app_wrk_index);
  if ((rv = app_worker_accept_notify (app_wrk, s)))
    {
      session_lookup_del_session (s);
      segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
      session_free (s);
      return rv;
    }

  return 0;
}

int
session_open_cl (session_endpoint_cfg_t *rmt, session_handle_t *rsh)
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
      return rv;
    }

  tc = transport_get_half_open (rmt->transport_proto, (u32) rv);

  /* For dgram type of service, allocate session and fifos now */
  app_wrk = app_worker_get (rmt->app_wrk_index);
  s = session_alloc_for_connection (tc);
  s->app_wrk_index = app_wrk->wrk_index;
  s->opaque = rmt->opaque;
  session_set_state (s, SESSION_STATE_OPENED);
  if (transport_connection_is_cless (tc))
    s->flags |= SESSION_F_IS_CLESS;
  if (app_worker_init_connected (app_wrk, s))
    {
      session_free (s);
      return -1;
    }

  sh = session_handle (s);
  *rsh = sh;

  session_lookup_add_connection (tc, sh);
  return app_worker_connect_notify (app_wrk, s, SESSION_E_NONE, rmt->opaque);
}

int
session_open_vc (session_endpoint_cfg_t *rmt, session_handle_t *rsh)
{
  transport_connection_t *tc;
  transport_endpoint_cfg_t *tep;
  app_worker_t *app_wrk;
  session_t *ho;
  int rv;

  tep = session_endpoint_to_transport_cfg (rmt);
  rv = transport_connect (rmt->transport_proto, tep);
  if (rv < 0)
    {
      SESSION_DBG ("Transport failed to open connection.");
      return rv;
    }

  tc = transport_get_half_open (rmt->transport_proto, (u32) rv);

  app_wrk = app_worker_get (rmt->app_wrk_index);

  /* If transport offers a vc service, only allocate established
   * session once the connection has been established.
   * In the meantime allocate half-open session for tracking purposes
   * associate half-open connection to it and add session to app-worker
   * half-open table. These are needed to allocate the established
   * session on transport notification, and to cleanup the half-open
   * session if the app detaches before connection establishment.
   */
  ho = session_alloc_for_half_open (tc);
  ho->app_wrk_index = app_wrk->wrk_index;
  ho->ho_index = app_worker_add_half_open (app_wrk, session_handle (ho));
  ho->opaque = rmt->opaque;
  *rsh = session_handle (ho);

  if (!(tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
    session_lookup_add_half_open (tc, tc->c_index);

  return 0;
}

int
session_open_app (session_endpoint_cfg_t *rmt, session_handle_t *rsh)
{
  transport_endpoint_cfg_t *tep_cfg = session_endpoint_to_transport_cfg (rmt);

  /* Not supported for now */
  *rsh = SESSION_INVALID_HANDLE;
  return transport_connect (rmt->transport_proto, tep_cfg);
}

typedef int (*session_open_service_fn) (session_endpoint_cfg_t *,
					session_handle_t *);

static session_open_service_fn session_open_srv_fns[TRANSPORT_N_SERVICES] = {
  session_open_vc,
  session_open_cl,
  session_open_app,
};

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
session_open (session_endpoint_cfg_t *rmt, session_handle_t *rsh)
{
  transport_service_type_t tst;
  tst = transport_protocol_service_type (rmt->transport_proto);
  return session_open_srv_fns[tst](rmt, rsh);
}

/**
 * Ask transport to open stream on existing connection.
 */
int
session_open_stream (session_endpoint_cfg_t *sep, session_handle_t *rsh)
{
  transport_connection_t *tc;
  transport_endpoint_cfg_t *tep;
  app_worker_t *app_wrk;
  session_t *s;
  u32 conn_index;
  int rv;

  app_wrk = app_worker_get (sep->app_wrk_index);
  tep = session_endpoint_to_transport_cfg (sep);

  /* allocate session and fifos now */
  s = session_alloc_for_stream (sep->parent_handle);
  s->app_wrk_index = app_wrk->wrk_index;
  s->opaque = sep->opaque;
  s->flags |= SESSION_F_STREAM;
  if ((rv = app_worker_init_connected (app_wrk, s)))
    {
      session_free (s);
      if (app_worker_application_is_builtin (app_wrk))
	return rv;
      return app_worker_connect_notify (app_wrk, 0, rv, sep->opaque);
    }

  rv = transport_connect_stream (sep->transport_proto, tep, s, &conn_index);
  if (rv < 0)
    {
      SESSION_DBG ("Transport failed to open stream.");
      segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
      session_free (s);
      if (app_worker_application_is_builtin (app_wrk))
	return rv;
      return app_worker_connect_notify (app_wrk, 0, rv, sep->opaque);
    }

  session_set_state (s, SESSION_STATE_READY);

  tc =
    transport_get_connection (sep->transport_proto, conn_index,
			      session_thread_from_handle (sep->parent_handle));

  /* Attach transport to session and vice versa */
  s->connection_index = tc->c_index;
  tc->s_index = s->session_index;
  *rsh = session_handle (s);

  /* builtin apps are synchronous */
  if (app_worker_application_is_builtin (app_wrk))
    {
      s->flags |= SESSION_F_RX_READY;
      return SESSION_E_NONE;
    }

  return app_worker_connect_notify (app_wrk, s, SESSION_E_NONE, sep->opaque);
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
  transport_endpoint_cfg_t *tep;
  int tc_index;
  u32 s_index;

  /* Transport bind/listen */
  tep = session_endpoint_to_transport_cfg (sep);
  s_index = ls->session_index;
  tc_index = transport_start_listen (session_get_transport_proto (ls),
				     s_index, tep);

  if (tc_index < 0)
    return tc_index;

  /* Attach transport to session. Lookup tables are populated by the app
   * worker because local tables (for ct sessions) are not backed by a fib */
  ls = listen_session_get (s_index);
  ls->connection_index = tc_index;
  ls->opaque = sep->opaque;
  if (transport_connection_is_cless (session_get_transport (ls)))
    ls->flags |= SESSION_F_IS_CLESS;

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
    return SESSION_E_NOLISTEN;

  tc = transport_get_listener (tp, s->connection_index);

  /* If no transport, assume everything was cleaned up already */
  if (!tc)
    return SESSION_E_NONE;

  if (!(tc->flags & TRANSPORT_CONNECTION_F_NO_LOOKUP))
    session_lookup_del_connection (tc);

  transport_stop_listen (tp, s->connection_index);
  return 0;
}

/**
 * Initialize session half-closing procedure.
 *
 * Note that half-closing will not change the state of the session.
 */
void
session_half_close (session_t *s)
{
  if (!s)
    return;

  session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_HALF_CLOSE);
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
  if (!s || (s->flags & SESSION_F_APP_CLOSED))
    return;

  /* Transports can close and delete their state independent of app closes
   * and transport initiated state transitions can hide app closes. Instead
   * of extending the state machine to support separate tracking of app and
   * transport initiated closes, use a flag. */
  s->flags |= SESSION_F_APP_CLOSED;

  /* Disable fifo tuning when app closes */
  s->flags &= ~SESSION_F_CUSTOM_FIFO_TUNING;

  if (s->session_state >= SESSION_STATE_CLOSING)
    {
      /* Session will only be removed once both app and transport
       * acknowledge the close */
      if (s->session_state == SESSION_STATE_TRANSPORT_CLOSED
	  || s->session_state == SESSION_STATE_TRANSPORT_DELETED)
	session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_CLOSE);
      return;
    }

  /* App closed so stop propagating dequeue notifications.
   * App might disconnect session before connected, in this case,
   * tx_fifo may not be setup yet, so clear only it's inited. */
  if (s->tx_fifo)
    svm_fifo_clear_deq_ntf (s->tx_fifo);
  session_set_state (s, SESSION_STATE_CLOSING);
  session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_CLOSE);
}

/**
 * Force a close without waiting for data to be flushed
 */
void
session_reset (session_t * s)
{
  if (s->session_state >= SESSION_STATE_CLOSING)
    return;
  /* Drop all outstanding tx data
   * App might disconnect session before connected, in this case,
   * tx_fifo may not be setup yet, so clear only it's inited. */
  if (s->tx_fifo)
    svm_fifo_dequeue_drop_all (s->tx_fifo);
  session_set_state (s, SESSION_STATE_CLOSING);
  session_program_transport_ctrl_evt (s, SESSION_CTRL_EVT_RESET);
}

void
session_detach_app (session_t *s)
{
  if (s->session_state < SESSION_STATE_TRANSPORT_CLOSING)
    {
      session_close (s);
    }
  else if (s->session_state < SESSION_STATE_TRANSPORT_DELETED)
    {
      transport_connection_t *tc;

      /* Transport is closing but it's not yet deleted. Confirm close and
       * subsequently detach transport from session and enqueue a session
       * cleanup notification. Transport closed and cleanup notifications are
       * going to be dropped by session layer apis */
      transport_close (session_get_transport_proto (s), s->connection_index,
		       s->thread_index);
      tc = session_get_transport (s);
      tc->s_index = SESSION_INVALID_INDEX;
      session_set_state (s, SESSION_STATE_TRANSPORT_DELETED);
      session_cleanup_notify (s, SESSION_CLEANUP_SESSION);
    }
  else
    {
      session_cleanup_notify (s, SESSION_CLEANUP_SESSION);
    }

  s->flags |= SESSION_F_APP_CLOSED;
  s->app_wrk_index = APP_INVALID_INDEX;
}

/**
 * Notify transport the session can be half-disconnected.
 *
 * Must be called from the session's thread.
 */
void
session_transport_half_close (session_t *s)
{
  /* Only READY session can be half-closed */
  if (s->session_state != SESSION_STATE_READY)
    {
      return;
    }

  transport_half_close (session_get_transport_proto (s), s->connection_index,
			s->thread_index);
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
  if (s->session_state >= SESSION_STATE_APP_CLOSED)
    {
      if (s->session_state == SESSION_STATE_TRANSPORT_CLOSED)
	session_set_state (s, SESSION_STATE_CLOSED);
      /* If transport is already deleted, just free the session. Half-opens
       * expected to be already cleaning up at this point */
      else if (s->session_state >= SESSION_STATE_TRANSPORT_DELETED &&
	       !(s->flags & SESSION_F_HALF_OPEN))
	session_program_cleanup (s);
      return;
    }

  /* If the tx queue wasn't drained, the transport can continue to try
   * sending the outstanding data (in closed state it cannot). It MUST however
   * at one point, either after sending everything or after a timeout, call
   * delete notify. This will finally lead to the complete cleanup of the
   * session.
   */
  session_set_state (s, SESSION_STATE_APP_CLOSED);

  transport_close (session_get_transport_proto (s), s->connection_index,
		   s->thread_index);
}

/**
 * Force transport close
 */
void
session_transport_reset (session_t * s)
{
  if (s->session_state >= SESSION_STATE_APP_CLOSED)
    {
      if (s->session_state == SESSION_STATE_TRANSPORT_CLOSED)
	session_set_state (s, SESSION_STATE_CLOSED);
      else if (s->session_state >= SESSION_STATE_TRANSPORT_DELETED &&
	       !(s->flags & SESSION_F_HALF_OPEN))
	session_program_cleanup (s);
      return;
    }

  session_set_state (s, SESSION_STATE_APP_CLOSED);
  transport_reset (session_get_transport_proto (s), s->connection_index,
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
  /* Delete from main lookup table before we axe the the transport */
  session_lookup_del_session (s);
  if (s->session_state != SESSION_STATE_TRANSPORT_DELETED)
    transport_cleanup (session_get_transport_proto (s), s->connection_index,
		       s->thread_index);
  /* Since we called cleanup, no delete notification will come. So, make
   * sure the session is properly freed. */
  segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
  session_free (s);
}

/**
 * Allocate worker mqs in share-able segment
 *
 * That can only be a newly created memfd segment, that must be mapped
 * by all apps/stack users unless private rx mqs are enabled.
 */
void
session_vpp_wrk_mqs_alloc (session_main_t *smm)
{
  u32 mq_q_length = 2048, evt_size = sizeof (session_event_t);
  fifo_segment_t *mqs_seg = &smm->wrk_mqs_segment;
  svm_msg_q_cfg_t _cfg, *cfg = &_cfg;
  uword mqs_seg_size;
  int i;

  mq_q_length = clib_max (mq_q_length, smm->configured_wrk_mq_length);

  svm_msg_q_ring_cfg_t rc[SESSION_MQ_N_RINGS] = {
    { mq_q_length, evt_size, 0 }, { mq_q_length >> 1, 256, 0 }
  };
  cfg->consumer_pid = 0;
  cfg->n_rings = 2;
  cfg->q_nitems = mq_q_length;
  cfg->ring_cfgs = rc;

  /*
   * Compute mqs segment size based on rings config and leave space
   * for passing extended configuration messages, i.e., data allocated
   * outside of the rings. If provided with a config value, accept it
   * if larger than minimum size.
   */
  mqs_seg_size = svm_msg_q_size_to_alloc (cfg) * vec_len (smm->wrk);
  mqs_seg_size = mqs_seg_size + (1 << 20);
  mqs_seg_size = clib_max (mqs_seg_size, smm->wrk_mqs_segment_size);

  mqs_seg->ssvm.ssvm_size = mqs_seg_size;
  mqs_seg->ssvm.my_pid = getpid ();
  mqs_seg->ssvm.name = format (0, "%s%c", "session: wrk-mqs-segment", 0);

  if (ssvm_server_init (&mqs_seg->ssvm, SSVM_SEGMENT_MEMFD))
    {
      clib_warning ("failed to initialize queue segment");
      return;
    }

  fifo_segment_init (mqs_seg);

  /* Special fifo segment that's filled only with mqs */
  mqs_seg->h->n_mqs = vec_len (smm->wrk);

  for (i = 0; i < vec_len (smm->wrk); i++)
    smm->wrk[i].vpp_event_queue = fifo_segment_msg_q_alloc (mqs_seg, i, cfg);
}

fifo_segment_t *
session_main_get_wrk_mqs_segment (void)
{
  return &session_main.wrk_mqs_segment;
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

void
session_get_original_dst (transport_endpoint_t *i2o_src,
			  transport_endpoint_t *i2o_dst,
			  transport_proto_t transport_proto, u32 *original_dst,
			  u16 *original_dst_port)
{
  session_main_t *smm = vnet_get_session_main ();
  ip_protocol_t proto =
    (transport_proto == TRANSPORT_PROTO_TCP ? IPPROTO_TCP : IPPROTO_UDP);
  if (!smm->original_dst_lookup || !i2o_dst->is_ip4)
    return;
  smm->original_dst_lookup (&i2o_src->ip.ip4, i2o_src->port, &i2o_dst->ip.ip4,
			    i2o_dst->port, proto, original_dst,
			    original_dst_port);
}

static session_fifo_rx_fn *session_tx_fns[TRANSPORT_TX_N_FNS] = {
    session_tx_fifo_peek_and_snd,
    session_tx_fifo_dequeue_and_snd,
    session_tx_fifo_dequeue_internal,
    session_tx_fifo_dequeue_and_snd
};

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

  if (output_node != ~0)
    next_index = vlib_node_add_next (vlib_get_main (),
				     session_queue_node.index, output_node);

  smm->session_type_to_next[session_type] = next_index;
  smm->session_tx_fns[session_type] =
    session_tx_fns[vft->transport_options.tx_type];
}

void
session_register_update_time_fn (session_update_time_fn fn, u8 is_add)
{
  session_main_t *smm = &session_main;
  session_update_time_fn *fi;
  u32 fi_pos = ~0;
  u8 found = 0;

  vec_foreach (fi, smm->update_time_fns)
    {
      if (*fi == fn)
	{
	  fi_pos = fi - smm->update_time_fns;
	  found = 1;
	  break;
	}
    }

  if (is_add)
    {
      if (found)
	{
	  clib_warning ("update time fn %p already registered", fn);
	  return;
	}
      vec_add1 (smm->update_time_fns, fn);
    }
  else
    {
      if (found)
	vec_del1 (smm->update_time_fns, fi_pos);
    }
}

transport_proto_t
session_add_transport_proto (void)
{
  session_main_t *smm = &session_main;
  session_worker_t *wrk;
  u32 thread;

  smm->last_transport_proto_type += 1;

  for (thread = 0; thread < vec_len (smm->wrk); thread++)
    {
      wrk = session_main_get_worker (thread);
      vec_validate (wrk->session_to_enqueue, smm->last_transport_proto_type);
    }

  return smm->last_transport_proto_type;
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

int
session_transport_attribute (session_t *s, u8 is_get,
			     transport_endpt_attr_t *attr)
{
  if (s->session_state < SESSION_STATE_READY)
    return -1;

  return transport_connection_attribute (session_get_transport_proto (s),
					 s->connection_index, s->thread_index,
					 is_get, attr);
}

transport_connection_t *
listen_session_get_transport (session_t * s)
{
  return transport_get_listener (session_get_transport_proto (s),
				 s->connection_index);
}

void
session_queue_run_on_main_thread (vlib_main_t * vm)
{
  ASSERT (vlib_get_thread_index () == 0);
  vlib_node_set_interrupt_pending (vm, session_queue_node.index);
}

static void
session_stats_collector_fn (vlib_stats_collector_data_t *d)
{
  u32 i, n_workers, n_wrk_sessions, n_sessions = 0;
  session_main_t *smm = &session_main;
  session_worker_t *wrk;
  counter_t **counters;
  counter_t *cb;

  n_workers = vec_len (smm->wrk);
  vlib_stats_validate (d->entry_index, 0, n_workers - 1);
  counters = d->entry->data;
  cb = counters[0];

  for (i = 0; i < vec_len (smm->wrk); i++)
    {
      wrk = session_main_get_worker (i);
      n_wrk_sessions = pool_elts (wrk->sessions);
      cb[i] = n_wrk_sessions;
      n_sessions += n_wrk_sessions;
    }

  vlib_stats_set_gauge (d->private_data, n_sessions);
  vlib_stats_set_gauge (smm->stats_seg_idx.tp_port_alloc_max_tries,
			transport_port_alloc_max_tries ());
}

static void
session_stats_collector_init (void)
{
  session_main_t *smm = &session_main;
  vlib_stats_collector_reg_t reg = {};

  reg.entry_index =
    vlib_stats_add_counter_vector ("/sys/session/sessions_per_worker");
  reg.private_data = vlib_stats_add_gauge ("/sys/session/sessions_total");
  reg.collect_fn = session_stats_collector_fn;
  vlib_stats_register_collector_fn (&reg);
  vlib_stats_validate (reg.entry_index, 0, vlib_get_n_threads ());

  smm->stats_seg_idx.tp_port_alloc_max_tries =
    vlib_stats_add_gauge ("/sys/session/transport_port_alloc_max_tries");
  vlib_stats_set_gauge (smm->stats_seg_idx.tp_port_alloc_max_tries, 0);
}

static clib_error_t *
session_manager_main_enable (vlib_main_t *vm,
			     session_rt_engine_type_t rt_engine_type)
{
  session_main_t *smm = &session_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads, preallocated_sessions_per_worker;
  session_worker_t *wrk;
  int i;

  if (session_rt_backend_enable_disable (rt_engine_type))
    return clib_error_return (0, "error on enable backend engine");

  /* We only initialize once and do not de-initialized on disable */
  if (smm->is_initialized)
    goto done;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  if (num_threads < 1)
    return clib_error_return (0, "n_thread_stacks not set");

  /* Allocate cache line aligned worker contexts */
  vec_validate_aligned (smm->wrk, num_threads - 1, CLIB_CACHE_LINE_BYTES);
  clib_spinlock_init (&session_main.pool_realloc_lock);

  for (i = 0; i < num_threads; i++)
    {
      wrk = &smm->wrk[i];
      wrk->ctrl_head = clib_llist_make_head (wrk->event_elts, evt_list);
      wrk->new_head = clib_llist_make_head (wrk->event_elts, evt_list);
      wrk->old_head = clib_llist_make_head (wrk->event_elts, evt_list);
      wrk->pending_connects = clib_llist_make_head (wrk->event_elts, evt_list);
      wrk->evts_pending_main =
	clib_llist_make_head (wrk->event_elts, evt_list);
      wrk->vm = vlib_get_main_by_index (i);
      wrk->last_vlib_time = vlib_time_now (vm);
      wrk->last_vlib_us_time = wrk->last_vlib_time * CLIB_US_TIME_FREQ;
      wrk->timerfd = -1;
      vec_validate (wrk->session_to_enqueue, smm->last_transport_proto_type);

      if (!smm->no_adaptive && smm->use_private_rx_mqs)
	session_wrk_enable_adaptive_mode (wrk);
    }

  /* Allocate vpp event queues segment and queue */
  session_vpp_wrk_mqs_alloc (smm);

  /* Initialize segment manager properties */
  segment_manager_main_init (smm->no_dump_segments);

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
  session_stats_collector_init ();
  smm->is_initialized = 1;

done:

  smm->is_enabled = 1;

  /* Enable transports */
  transport_enable_disable (vm, 1);
  session_debug_init ();

  return 0;
}

static void
session_manager_main_disable (vlib_main_t *vm,
			      session_rt_engine_type_t rt_engine_type)
{
  transport_enable_disable (vm, 0 /* is_en */ );
  session_rt_backend_enable_disable (rt_engine_type);
}

/* in this new callback, cookie hint the index */
void
session_dma_completion_cb (vlib_main_t *vm, struct vlib_dma_batch *batch)
{
  session_worker_t *wrk;
  wrk = session_main_get_worker (vm->thread_index);
  session_dma_transfer *dma_transfer;

  dma_transfer = &wrk->dma_trans[wrk->trans_head];
  vec_add (wrk->pending_tx_buffers, dma_transfer->pending_tx_buffers,
	   vec_len (dma_transfer->pending_tx_buffers));
  vec_add (wrk->pending_tx_nexts, dma_transfer->pending_tx_nexts,
	   vec_len (dma_transfer->pending_tx_nexts));
  vec_reset_length (dma_transfer->pending_tx_buffers);
  vec_reset_length (dma_transfer->pending_tx_nexts);
  wrk->trans_head++;
  if (wrk->trans_head == wrk->trans_size)
    wrk->trans_head = 0;
  return;
}

static void
session_prepare_dma_args (vlib_dma_config_t *args)
{
  args->max_batches = 16;
  args->max_transfers = DMA_TRANS_SIZE;
  args->max_transfer_size = 65536;
  args->features = 0;
  args->sw_fallback = 1;
  args->barrier_before_last = 1;
  args->callback_fn = session_dma_completion_cb;
}

static void
session_node_enable_dma (u8 is_en, int n_vlibs)
{
  vlib_dma_config_t args;
  session_prepare_dma_args (&args);
  session_worker_t *wrk;
  vlib_main_t *vm;

  int config_index = -1;

  if (is_en)
    {
      vm = vlib_get_main_by_index (0);
      config_index = vlib_dma_config_add (vm, &args);
    }
  else
    {
      vm = vlib_get_main_by_index (0);
      wrk = session_main_get_worker (0);
      if (wrk->config_index >= 0)
	vlib_dma_config_del (vm, wrk->config_index);
    }
  int i;
  for (i = 0; i < n_vlibs; i++)
    {
      vm = vlib_get_main_by_index (i);
      wrk = session_main_get_worker (vm->thread_index);
      wrk->config_index = config_index;
      if (is_en)
	{
	  if (config_index >= 0)
	    wrk->dma_enabled = true;
	  wrk->dma_trans = (session_dma_transfer *) clib_mem_alloc (
	    sizeof (session_dma_transfer) * DMA_TRANS_SIZE);
	  bzero (wrk->dma_trans,
		 sizeof (session_dma_transfer) * DMA_TRANS_SIZE);
	}
      else
	{
	  if (wrk->dma_trans)
	    clib_mem_free (wrk->dma_trans);
	}
      wrk->trans_head = 0;
      wrk->trans_tail = 0;
      wrk->trans_size = DMA_TRANS_SIZE;
    }
}

static void
session_main_start_q_process (vlib_main_t *vm, vlib_node_state_t state)
{
  vlib_node_t *n;

  vlib_node_set_state (vm, session_queue_process_node.index, state);
  n = vlib_get_node (vm, session_queue_process_node.index);
  vlib_start_process (vm, n->runtime_index);
}

void
session_node_enable_disable (u8 is_en)
{
  u8 mstate = is_en ? VLIB_NODE_STATE_INTERRUPT : VLIB_NODE_STATE_DISABLED;
  u8 state = is_en ? VLIB_NODE_STATE_POLLING : VLIB_NODE_STATE_DISABLED;
  session_main_t *sm = &session_main;
  vlib_main_t *vm;
  int n_vlibs, i;

  n_vlibs = vlib_get_n_threads ();
  for (i = 0; i < n_vlibs; i++)
    {
      vm = vlib_get_main_by_index (i);
      /* main thread with workers and not polling */
      if (i == 0 && n_vlibs > 1)
	{
	  vlib_node_set_state (vm, session_queue_node.index, mstate);
	  if (is_en)
	    {
	      session_main_get_worker (0)->state = SESSION_WRK_INTERRUPT;
	      session_main_start_q_process (vm, state);
	    }
	  else
	    {
	      vlib_process_signal_event_mt (vm,
					    session_queue_process_node.index,
					    SESSION_Q_PROCESS_STOP, 0);
	    }
	  if (!sm->poll_main)
	    continue;
	}
      vlib_node_set_state (vm, session_input_node.index, mstate);
      vlib_node_set_state (vm, session_queue_node.index, state);
    }

  if (sm->use_private_rx_mqs)
    application_enable_rx_mqs_nodes (is_en);

  if (sm->dma_enabled)
    session_node_enable_dma (is_en, n_vlibs);
}

clib_error_t *
vnet_session_enable_disable (vlib_main_t *vm,
			     session_enable_disable_args_t *args)
{
  clib_error_t *error = 0;

  if (args->is_en)
    {
      if (session_main.is_enabled)
	return 0;

      error = session_manager_main_enable (vm, args->rt_engine_type);
      session_node_enable_disable (1);
    }
  else
    {
      session_main.is_enabled = 0;
      session_manager_main_disable (vm, args->rt_engine_type);
      session_node_enable_disable (0);
    }

  return error;
}

clib_error_t *
session_main_init (vlib_main_t * vm)
{
  session_main_t *smm = &session_main;

  smm->is_enabled = 0;
  smm->session_enable_asap = 0;
  smm->poll_main = 0;
  smm->use_private_rx_mqs = 0;
  smm->no_adaptive = 0;
  smm->last_transport_proto_type = TRANSPORT_PROTO_HTTP;
  smm->port_allocator_min_src_port = 1024;
  smm->port_allocator_max_src_port = 65535;

  /* default enable app socket api */
  (void) appns_sapi_enable_disable (1 /* is_enable */);

  return 0;
}

static clib_error_t *
session_main_loop_init (vlib_main_t * vm)
{
  session_main_t *smm = &session_main;

  if (smm->session_enable_asap)
    {
      session_enable_disable_args_t args = { .is_en = 1,
					     .rt_engine_type =
					       smm->rt_engine_type };

      vlib_worker_thread_barrier_sync (vm);
      vnet_session_enable_disable (vm, &args);
      vlib_worker_thread_barrier_release (vm);
    }
  return 0;
}

VLIB_INIT_FUNCTION (session_main_init);
VLIB_MAIN_LOOP_ENTER_FUNCTION (session_main_loop_init);

static clib_error_t *
session_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  session_main_t *smm = &session_main;
  u32 nitems;
  uword tmp;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "wrk-mq-length %d", &nitems))
	{
	  if (nitems >= 2048)
	    smm->configured_wrk_mq_length = nitems;
	  else
	    clib_warning ("event queue length %d too small, ignored", nitems);
	}
      else if (unformat (input, "wrk-mqs-segment-size %U",
			 unformat_memory_size, &smm->wrk_mqs_segment_size))
	;
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
      else if (unformat (input, "min-src-port %d", &tmp))
	smm->port_allocator_min_src_port = tmp;
      else if (unformat (input, "max-src-port %d", &tmp))
	smm->port_allocator_max_src_port = tmp;
      else if (unformat (input, "enable rt-backend rule-table"))
	{
	  smm->rt_engine_type = RT_BACKEND_ENGINE_RULE_TABLE;
	  smm->session_enable_asap = 1;
	}
      else if (unformat (input, "enable rt-backend sdl"))
	{
	  smm->rt_engine_type = RT_BACKEND_ENGINE_SDL;
	  smm->session_enable_asap = 1;
	}
      else if (unformat (input, "enable"))
	{
	  /* enable session without rt-backend */
	  smm->rt_engine_type = RT_BACKEND_ENGINE_NONE;
	  smm->session_enable_asap = 1;
	}
      else if (unformat (input, "poll-main"))
	smm->poll_main = 1;
      else if (unformat (input, "use-private-rx-mqs"))
	smm->use_private_rx_mqs = 1;
      else if (unformat (input, "no-adaptive"))
	smm->no_adaptive = 1;
      else if (unformat (input, "use-dma"))
	smm->dma_enabled = 1;
      else if (unformat (input, "nat44-original-dst-enable"))
	{
	  smm->original_dst_lookup = vlib_get_plugin_symbol (
	    "nat_plugin.so", "nat44_original_dst_lookup");
	}
      else if (unformat (input, "no-dump-segments"))
	smm->no_dump_segments = 1;
      /*
       * Deprecated but maintained for compatibility
       */
      else if (unformat (input, "use-app-socket-api"))
	;
      else if (unformat (input, "use-bapi-socket-api"))
	{
	  clib_warning (
	    "App attachment using binary-api is deprecated in favor "
	    "of socket api. Support for bapi may be removed in the future.");
	  (void) appns_sapi_enable_disable (0 /* is_enable */);
	}
      else if (unformat (input, "evt_qs_memfd_seg"))
	;
      else if (unformat (input, "segment-baseva 0x%lx", &tmp))
	;
      else if (unformat (input, "evt_qs_seg_size %U", unformat_memory_size,
			 &smm->wrk_mqs_segment_size))
	;
      else if (unformat (input, "event-queue-length %d", &nitems))
	{
	  if (nitems >= 2048)
	    smm->configured_wrk_mq_length = nitems;
	  else
	    clib_warning ("event queue length %d too small, ignored", nitems);
	}
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
