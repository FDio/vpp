/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>

/**
 * Pool of workers associated to apps
 */
static app_worker_t *app_workers;

app_worker_t *
app_worker_alloc (application_t * app)
{
  app_worker_t *app_wrk;
  pool_get (app_workers, app_wrk);
  clib_memset (app_wrk, 0, sizeof (*app_wrk));
  app_wrk->wrk_index = app_wrk - app_workers;
  app_wrk->app_index = app->app_index;
  app_wrk->wrk_map_index = ~0;
  app_wrk->connects_seg_manager = APP_INVALID_SEGMENT_MANAGER_INDEX;
  app_wrk->first_segment_manager = APP_INVALID_SEGMENT_MANAGER_INDEX;
  APP_DBG ("New app %v worker %u", app_get_name (app), app_wrk->wrk_index);
  return app_wrk;
}

app_worker_t *
app_worker_get (u32 wrk_index)
{
  return pool_elt_at_index (app_workers, wrk_index);
}

app_worker_t *
app_worker_get_if_valid (u32 wrk_index)
{
  if (pool_is_free_index (app_workers, wrk_index))
    return 0;
  return pool_elt_at_index (app_workers, wrk_index);
}

void
app_worker_free (app_worker_t * app_wrk)
{
  application_t *app = application_get (app_wrk->app_index);
  vnet_unlisten_args_t _a, *a = &_a;
  u64 handle, *handles = 0;
  segment_manager_t *sm;
  u32 sm_index;
  int i;
  app_listener_t *al;
  session_t *ls;

  /*
   *  Listener cleanup
   */

  /* *INDENT-OFF* */
  hash_foreach (handle, sm_index, app_wrk->listeners_table, ({
    ls = listen_session_get_from_handle (handle);
    al = app_listener_get (app, ls->al_index);
    vec_add1 (handles, app_listener_handle (al));
    sm = segment_manager_get (sm_index);
    sm->app_wrk_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (handles); i++)
    {
      a->app_index = app->app_index;
      a->wrk_map_index = app_wrk->wrk_map_index;
      a->handle = handles[i];
      /* seg manager is removed when unbind completes */
      (void) vnet_unlisten (a);
    }

  /*
   * Connects segment manager cleanup
   */

  if (app_wrk->connects_seg_manager != APP_INVALID_SEGMENT_MANAGER_INDEX)
    {
      sm = segment_manager_get (app_wrk->connects_seg_manager);
      sm->app_wrk_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
      sm->first_is_protected = 0;
      segment_manager_init_free (sm);
    }

  /* If first segment manager is used by a listener */
  if (app_wrk->first_segment_manager != APP_INVALID_SEGMENT_MANAGER_INDEX
      && app_wrk->first_segment_manager != app_wrk->connects_seg_manager)
    {
      sm = segment_manager_get (app_wrk->first_segment_manager);
      sm->first_is_protected = 0;
      sm->app_wrk_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
      /* .. and has no fifos, e.g. it might be used for redirected sessions,
       * remove it */
      if (!segment_manager_has_fifos (sm))
	segment_manager_free (sm);
    }

  pool_put (app_workers, app_wrk);
  if (CLIB_DEBUG)
    clib_memset (app_wrk, 0xfe, sizeof (*app_wrk));
}

application_t *
app_worker_get_app (u32 wrk_index)
{
  app_worker_t *app_wrk;
  app_wrk = app_worker_get_if_valid (wrk_index);
  if (!app_wrk)
    return 0;
  return application_get_if_valid (app_wrk->app_index);
}

static segment_manager_t *
app_worker_alloc_segment_manager (app_worker_t * app_wrk)
{
  segment_manager_t *sm = 0;

  /* If the first segment manager is not in use, don't allocate a new one */
  if (app_wrk->first_segment_manager != APP_INVALID_SEGMENT_MANAGER_INDEX
      && app_wrk->first_segment_manager_in_use == 0)
    {
      sm = segment_manager_get (app_wrk->first_segment_manager);
      app_wrk->first_segment_manager_in_use = 1;
      return sm;
    }

  sm = segment_manager_alloc ();
  sm->app_wrk_index = app_wrk->wrk_index;

  return sm;
}

static int
app_worker_alloc_session_fifos (segment_manager_t * sm, session_t * s)
{
  svm_fifo_t *rx_fifo = 0, *tx_fifo = 0;
  int rv;

  if ((rv = segment_manager_alloc_session_fifos (sm, &rx_fifo, &tx_fifo)))
    return rv;

  rx_fifo->master_session_index = s->session_index;
  rx_fifo->master_thread_index = s->thread_index;

  tx_fifo->master_session_index = s->session_index;
  tx_fifo->master_thread_index = s->thread_index;

  s->rx_fifo = rx_fifo;
  s->tx_fifo = tx_fifo;
  return 0;
}

int
app_worker_init_listener (app_worker_t * app_wrk, session_t * ls)
{
  segment_manager_t *sm;

  /* Allocate segment manager. All sessions derived out of a listen session
   * have fifos allocated by the same segment manager. */
  if (!(sm = app_worker_alloc_segment_manager (app_wrk)))
    return -1;

  /* Keep track of the segment manager for the listener or this worker */
  hash_set (app_wrk->listeners_table, listen_session_get_handle (ls),
	    segment_manager_index (sm));

  if (session_transport_service_type (ls) == TRANSPORT_SERVICE_CL)
    {
      if (!ls->rx_fifo && app_worker_alloc_session_fifos (sm, ls))
	return -1;
    }
  return 0;
}

int
app_worker_start_listen (app_worker_t * app_wrk,
			 app_listener_t * app_listener)
{
  session_t *ls;

  if (clib_bitmap_get (app_listener->workers, app_wrk->wrk_map_index))
    return VNET_API_ERROR_ADDRESS_IN_USE;

  app_listener->workers = clib_bitmap_set (app_listener->workers,
					   app_wrk->wrk_map_index, 1);

  if (app_listener->session_index != SESSION_INVALID_INDEX)
    {
      ls = session_get (app_listener->session_index, 0);
      if (app_worker_init_listener (app_wrk, ls))
	return -1;
    }

  if (app_listener->local_index != SESSION_INVALID_INDEX)
    {
      ls = session_get (app_listener->local_index, 0);
      if (app_worker_init_listener (app_wrk, ls))
	return -1;
    }

  return 0;
}

static void
app_worker_stop_listen_session (app_worker_t * app_wrk, session_t * ls)
{
  session_handle_t handle;
  segment_manager_t *sm;
  uword *sm_indexp;

  handle = listen_session_get_handle (ls);
  sm_indexp = hash_get (app_wrk->listeners_table, handle);
  if (PREDICT_FALSE (!sm_indexp))
    return;

  sm = segment_manager_get (*sm_indexp);
  if (app_wrk->first_segment_manager == *sm_indexp)
    {
      /* Delete sessions but don't remove segment manager */
      app_wrk->first_segment_manager_in_use = 0;
      segment_manager_del_sessions (sm);
    }
  else
    {
      segment_manager_init_free (sm);
    }
  hash_unset (app_wrk->listeners_table, handle);
}

int
app_worker_stop_listen (app_worker_t * app_wrk, app_listener_t * al)
{
  session_t *ls;

  if (!clib_bitmap_get (al->workers, app_wrk->wrk_map_index))
    return 0;

  if (al->session_index != SESSION_INVALID_INDEX)
    {
      ls = listen_session_get (al->session_index);
      app_worker_stop_listen_session (app_wrk, ls);
    }

  if (al->local_index != SESSION_INVALID_INDEX)
    {
      ls = listen_session_get (al->local_index);
      app_worker_stop_listen_session (app_wrk, ls);
    }

  clib_bitmap_set_no_check (al->workers, app_wrk->wrk_map_index, 0);
  if (clib_bitmap_is_zero (al->workers))
    app_listener_cleanup (al);

  return 0;
}

int
app_worker_init_accepted (session_t * s)
{
  app_worker_t *app_wrk;
  segment_manager_t *sm;
  session_t *listener;

  listener = listen_session_get (s->listener_index);
  app_wrk = application_listener_select_worker (listener);
  s->app_wrk_index = app_wrk->wrk_index;

  sm = app_worker_get_listen_segment_manager (app_wrk, listener);
  if (app_worker_alloc_session_fifos (sm, s))
    return -1;

  return 0;
}

int
app_worker_accept_notify (app_worker_t * app_wrk, session_t * s)
{
  application_t *app = application_get (app_wrk->app_index);
  return app->cb_fns.session_accept_callback (s);
}

int
app_worker_init_connected (app_worker_t * app_wrk, session_t * s)
{
  application_t *app = application_get (app_wrk->app_index);
  segment_manager_t *sm;

  /* Allocate fifos for session, unless the app is a builtin proxy */
  if (!application_is_builtin_proxy (app))
    {
      sm = app_worker_get_connect_segment_manager (app_wrk);
      if (app_worker_alloc_session_fifos (sm, s))
	return -1;
    }
  return 0;
}

int
app_worker_connect_notify (app_worker_t * app_wrk, session_t * s, u32 opaque)
{
  application_t *app = application_get (app_wrk->app_index);
  return app->cb_fns.session_connected_callback (app_wrk->wrk_index, opaque,
						 s, s == 0 /* is_fail */ );
}

int
app_worker_close_notify (app_worker_t * app_wrk, session_t * s)
{
  application_t *app = application_get (app_wrk->app_index);
  app->cb_fns.session_disconnect_callback (s);
  return 0;
}

int
app_worker_reset_notify (app_worker_t * app_wrk, session_t * s)
{
  application_t *app = application_get (app_wrk->app_index);
  app->cb_fns.session_reset_callback (s);
  return 0;
}

int
app_worker_builtin_rx (app_worker_t * app_wrk, session_t * s)
{
  application_t *app = application_get (app_wrk->app_index);
  app->cb_fns.builtin_app_rx_callback (s);
  return 0;
}

int
app_worker_own_session (app_worker_t * app_wrk, session_t * s)
{
  segment_manager_t *sm;
  svm_fifo_t *rxf, *txf;

  if (s->session_state == SESSION_STATE_LISTENING)
    return application_change_listener_owner (s, app_wrk);

  s->app_wrk_index = app_wrk->wrk_index;

  rxf = s->rx_fifo;
  txf = s->tx_fifo;

  if (!rxf || !txf)
    return 0;

  s->rx_fifo = 0;
  s->tx_fifo = 0;

  sm = app_worker_get_or_alloc_connect_segment_manager (app_wrk);
  if (app_worker_alloc_session_fifos (sm, s))
    return -1;

  if (!svm_fifo_is_empty_cons (rxf))
    svm_fifo_clone (s->rx_fifo, rxf);

  if (!svm_fifo_is_empty_cons (txf))
    svm_fifo_clone (s->tx_fifo, txf);

  segment_manager_dealloc_fifos (rxf, txf);

  return 0;
}

int
app_worker_connect_session (app_worker_t * app, session_endpoint_t * sep,
			    u32 api_context)
{
  int rv;

  /* Make sure we have a segment manager for connects */
  app_worker_alloc_connects_segment_manager (app);

  if ((rv = session_open (app->wrk_index, sep, api_context)))
    return rv;

  return 0;
}

int
app_worker_alloc_connects_segment_manager (app_worker_t * app_wrk)
{
  segment_manager_t *sm;

  if (app_wrk->connects_seg_manager == APP_INVALID_SEGMENT_MANAGER_INDEX)
    {
      sm = app_worker_alloc_segment_manager (app_wrk);
      if (sm == 0)
	return -1;
      app_wrk->connects_seg_manager = segment_manager_index (sm);
    }
  return 0;
}

segment_manager_t *
app_worker_get_connect_segment_manager (app_worker_t * app)
{
  ASSERT (app->connects_seg_manager != (u32) ~ 0);
  return segment_manager_get (app->connects_seg_manager);
}

segment_manager_t *
app_worker_get_or_alloc_connect_segment_manager (app_worker_t * app_wrk)
{
  if (app_wrk->connects_seg_manager == (u32) ~ 0)
    app_worker_alloc_connects_segment_manager (app_wrk);
  return segment_manager_get (app_wrk->connects_seg_manager);
}

segment_manager_t *
app_worker_get_listen_segment_manager (app_worker_t * app,
				       session_t * listener)
{
  uword *smp;
  smp = hash_get (app->listeners_table, listen_session_get_handle (listener));
  ASSERT (smp != 0);
  return segment_manager_get (*smp);
}

session_t *
app_worker_first_listener (app_worker_t * app_wrk, u8 fib_proto,
			   u8 transport_proto)
{
  session_t *listener;
  u64 handle;
  u32 sm_index;
  u8 sst;

  sst = session_type_from_proto_and_ip (transport_proto,
					fib_proto == FIB_PROTOCOL_IP4);

  /* *INDENT-OFF* */
   hash_foreach (handle, sm_index, app_wrk->listeners_table, ({
     listener = listen_session_get_from_handle (handle);
     if (listener->session_type == sst
	 && !(listener->flags & SESSION_F_PROXY))
       return listener;
   }));
  /* *INDENT-ON* */

  return 0;
}

session_t *
app_worker_proxy_listener (app_worker_t * app_wrk, u8 fib_proto,
			   u8 transport_proto)
{
  session_t *listener;
  u64 handle;
  u32 sm_index;
  u8 sst;

  sst = session_type_from_proto_and_ip (transport_proto,
					fib_proto == FIB_PROTOCOL_IP4);

  /* *INDENT-OFF* */
   hash_foreach (handle, sm_index, app_wrk->listeners_table, ({
     listener = listen_session_get_from_handle (handle);
     if (listener->session_type == sst && (listener->flags & SESSION_F_PROXY))
       return listener;
   }));
  /* *INDENT-ON* */

  return 0;
}

/**
 * Send an API message to the external app, to map new segment
 */
int
app_worker_add_segment_notify (app_worker_t * app_wrk, u64 segment_handle)
{
  application_t *app = application_get (app_wrk->app_index);
  return app->cb_fns.add_segment_callback (app_wrk->api_client_index,
					   segment_handle);
}

int
app_worker_del_segment_notify (app_worker_t * app_wrk, u64 segment_handle)
{
  application_t *app = application_get (app_wrk->app_index);
  return app->cb_fns.del_segment_callback (app_wrk->api_client_index,
					   segment_handle);
}

static inline u8
app_worker_application_is_builtin (app_worker_t * app_wrk)
{
  return app_wrk->app_is_builtin;
}

static inline int
app_enqueue_evt (svm_msg_q_t * mq, svm_msg_q_msg_t * msg, u8 lock)
{
  if (PREDICT_FALSE (svm_msg_q_is_full (mq)))
    {
      clib_warning ("evt q full");
      svm_msg_q_free_msg (mq, msg);
      if (lock)
	svm_msg_q_unlock (mq);
      return -1;
    }

  if (lock)
    {
      svm_msg_q_add_and_unlock (mq, msg);
      return 0;
    }

  /* Even when not locking the ring, we must wait for queue mutex */
  if (svm_msg_q_add (mq, msg, SVM_Q_WAIT))
    {
      clib_warning ("msg q add returned");
      return -1;
    }
  return 0;
}

static inline int
app_send_io_evt_rx (app_worker_t * app_wrk, session_t * s, u8 lock)
{
  session_event_t *evt;
  svm_msg_q_msg_t msg;
  svm_msg_q_t *mq;

  if (PREDICT_FALSE (s->session_state != SESSION_STATE_READY
		     && s->session_state != SESSION_STATE_LISTENING))
    return 0;

  if (app_worker_application_is_builtin (app_wrk))
    return app_worker_builtin_rx (app_wrk, s);

  if (svm_fifo_has_event (s->rx_fifo))
    return 0;

  mq = app_wrk->event_queue;
  if (lock)
    svm_msg_q_lock (mq);

  if (PREDICT_FALSE (svm_msg_q_ring_is_full (mq, SESSION_MQ_IO_EVT_RING)))
    {
      clib_warning ("evt q rings full");
      if (lock)
	svm_msg_q_unlock (mq);
      return -1;
    }

  msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
  ASSERT (!svm_msg_q_msg_is_invalid (&msg));

  evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
  evt->session_index = s->rx_fifo->client_session_index;
  evt->event_type = SESSION_IO_EVT_RX;

  (void) svm_fifo_set_event (s->rx_fifo);

  if (app_enqueue_evt (mq, &msg, lock))
    return -1;
  return 0;
}

static inline int
app_send_io_evt_tx (app_worker_t * app_wrk, session_t * s, u8 lock)
{
  svm_msg_q_t *mq;
  session_event_t *evt;
  svm_msg_q_msg_t msg;

  if (app_worker_application_is_builtin (app_wrk))
    return 0;

  mq = app_wrk->event_queue;
  if (lock)
    svm_msg_q_lock (mq);

  if (PREDICT_FALSE (svm_msg_q_ring_is_full (mq, SESSION_MQ_IO_EVT_RING)))
    {
      clib_warning ("evt q rings full");
      if (lock)
	svm_msg_q_unlock (mq);
      return -1;
    }

  msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
  ASSERT (!svm_msg_q_msg_is_invalid (&msg));

  evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
  evt->event_type = SESSION_IO_EVT_TX;
  evt->session_index = s->tx_fifo->client_session_index;

  return app_enqueue_evt (mq, &msg, lock);
}

/* *INDENT-OFF* */
typedef int (app_send_evt_handler_fn) (app_worker_t *app,
				       session_t *s,
				       u8 lock);
static app_send_evt_handler_fn * const app_send_evt_handler_fns[2] = {
    app_send_io_evt_rx,
    app_send_io_evt_tx,
};
/* *INDENT-ON* */

/**
 * Send event to application
 *
 * Logic from queue perspective is non-blocking. If there's
 * not enough space to enqueue a message, we return.
 */
int
app_worker_send_event (app_worker_t * app, session_t * s, u8 evt_type)
{
  ASSERT (app && evt_type <= SESSION_IO_EVT_TX);
  return app_send_evt_handler_fns[evt_type] (app, s, 0 /* lock */ );
}

/**
 * Send event to application
 *
 * Logic from queue perspective is blocking. However, if queue is full,
 * we return.
 */
int
app_worker_lock_and_send_event (app_worker_t * app, session_t * s,
				u8 evt_type)
{
  return app_send_evt_handler_fns[evt_type] (app, s, 1 /* lock */ );
}

u8 *
format_app_worker_listener (u8 * s, va_list * args)
{
  app_worker_t *app_wrk = va_arg (*args, app_worker_t *);
  u64 handle = va_arg (*args, u64);
  u32 sm_index = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  session_t *listener;
  const u8 *app_name;
  u8 *str;

  if (!app_wrk)
    {
      if (verbose)
	s = format (s, "%-40s%-25s%=10s%-15s%-15s%-10s", "Connection", "App",
		    "Wrk", "API Client", "ListenerID", "SegManager");
      else
	s = format (s, "%-40s%-25s%=10s", "Connection", "App", "Wrk");

      return s;
    }

  app_name = application_name_from_index (app_wrk->app_index);
  listener = listen_session_get_from_handle (handle);
  str = format (0, "%U", format_session, listener, verbose);

  if (verbose)
    {
      char buf[32];
      sprintf (buf, "%u(%u)", app_wrk->wrk_map_index, app_wrk->wrk_index);
      s = format (s, "%-40s%-25s%=10s%-15u%-15u%-10u", str, app_name,
		  buf, app_wrk->api_client_index, handle, sm_index);
    }
  else
    s = format (s, "%-40s%-25s%=10u", str, app_name, app_wrk->wrk_map_index);

  return s;
}

u8 *
format_app_worker (u8 * s, va_list * args)
{
  app_worker_t *app_wrk = va_arg (*args, app_worker_t *);
  u32 indent = 1;

  s = format (s, "%U wrk-index %u app-index %u map-index %u "
	      "api-client-index %d\n", format_white_space, indent,
	      app_wrk->wrk_index, app_wrk->app_index, app_wrk->wrk_map_index,
	      app_wrk->api_client_index);
  return s;
}

void
app_worker_format_connects (app_worker_t * app_wrk, int verbose)
{
  segment_manager_t *sm;

  /* Header */
  if (!app_wrk)
    {
      segment_manager_format_sessions (0, verbose);
      return;
    }

  if (app_wrk->connects_seg_manager == (u32) ~ 0)
    return;

  sm = segment_manager_get (app_wrk->connects_seg_manager);
  segment_manager_format_sessions (sm, verbose);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
