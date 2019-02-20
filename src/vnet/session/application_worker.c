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

static inline u64
application_client_local_connect_key (local_session_t * ls)
{
  return (((u64) ls->app_wrk_index) << 32 | (u64) ls->session_index);
}

static inline void
application_client_local_connect_key_parse (u64 key, u32 * app_wrk_index,
					    u32 * session_index)
{
  *app_wrk_index = key >> 32;
  *session_index = key & 0xFFFFFFFF;
}

local_session_t *
app_worker_local_session_alloc (app_worker_t * app_wrk)
{
  local_session_t *s;
  pool_get (app_wrk->local_sessions, s);
  clib_memset (s, 0, sizeof (*s));
  s->app_wrk_index = app_wrk->wrk_index;
  s->session_index = s - app_wrk->local_sessions;
  s->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_NONE, 0);
  return s;
}

void
app_worker_local_session_free (app_worker_t * app_wrk, local_session_t * s)
{
  pool_put (app_wrk->local_sessions, s);
  if (CLIB_DEBUG)
    clib_memset (s, 0xfc, sizeof (*s));
}

local_session_t *
app_worker_get_local_session (app_worker_t * app_wrk, u32 session_index)
{
  if (pool_is_free_index (app_wrk->local_sessions, session_index))
    return 0;
  return pool_elt_at_index (app_wrk->local_sessions, session_index);
}

local_session_t *
app_worker_get_local_session_from_handle (session_handle_t handle)
{
  app_worker_t *server_wrk;
  u32 session_index, server_wrk_index;
  local_session_parse_handle (handle, &server_wrk_index, &session_index);
  server_wrk = app_worker_get_if_valid (server_wrk_index);
  if (!server_wrk)
    return 0;
  return app_worker_get_local_session (server_wrk, session_index);
}

void
app_worker_local_sessions_free (app_worker_t * app_wrk)
{
  u32 index, server_wrk_index, session_index;
  u64 handle, *handles = 0;
  app_worker_t *server_wrk;
  segment_manager_t *sm;
  local_session_t *ls;
  int i;

  /*
   * Local sessions
   */
  if (app_wrk->local_sessions)
    {
      /* *INDENT-OFF* */
      pool_foreach (ls, app_wrk->local_sessions, ({
	app_worker_local_session_disconnect (app_wrk->wrk_index, ls);
      }));
      /* *INDENT-ON* */
    }

  /*
   * Local connects
   */
  vec_reset_length (handles);
  /* *INDENT-OFF* */
  hash_foreach (handle, index, app_wrk->local_connects, ({
    vec_add1 (handles, handle);
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (handles); i++)
    {
      application_client_local_connect_key_parse (handles[i],
						  &server_wrk_index,
						  &session_index);
      server_wrk = app_worker_get_if_valid (server_wrk_index);
      if (server_wrk)
	{
	  ls = app_worker_get_local_session (server_wrk, session_index);
	  app_worker_local_session_disconnect (app_wrk->wrk_index, ls);
	}
    }

  sm = segment_manager_get (app_wrk->local_segment_manager);
  sm->app_wrk_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
  segment_manager_del (sm);
}

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
  app_wrk->local_segment_manager = APP_INVALID_SEGMENT_MANAGER_INDEX;
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
      segment_manager_init_del (sm);
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
	segment_manager_del (sm);
    }

  /*
   * Local sessions
   */
  app_worker_local_sessions_free (app_wrk);

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

  sm = segment_manager_new ();
  sm->app_wrk_index = app_wrk->wrk_index;

  return sm;
}

int
app_worker_start_listen (app_worker_t * app_wrk,
			 app_listener_t * app_listener)
{
  segment_manager_t *sm;
  session_t *ls;

  if (clib_bitmap_get (app_listener->workers, app_wrk->wrk_map_index))
    return VNET_API_ERROR_ADDRESS_IN_USE;

  app_listener->workers = clib_bitmap_set (app_listener->workers,
					   app_wrk->wrk_map_index, 1);

  if (app_listener->session_index == SESSION_INVALID_INDEX)
    return 0;

  ls = session_get (app_listener->session_index, 0);

  /* Allocate segment manager. All sessions derived out of a listen session
   * have fifos allocated by the same segment manager. */
  if (!(sm = app_worker_alloc_segment_manager (app_wrk)))
    return -1;

  /* Keep track of the segment manager for the listener or this worker */
  hash_set (app_wrk->listeners_table, listen_session_get_handle (ls),
	    segment_manager_index (sm));

  if (session_transport_service_type (ls) == TRANSPORT_SERVICE_CL)
    {
      if (!ls->rx_fifo && session_alloc_fifos (sm, ls))
	return -1;
    }
  return 0;
}

int
app_worker_stop_listen (app_worker_t * app_wrk, app_listener_t * al)
{
  session_handle_t handle;
  segment_manager_t *sm;
  uword *sm_indexp;

  if (!clib_bitmap_get (al->workers, app_wrk->wrk_map_index))
    return 0;

  if (al->session_index != SESSION_INVALID_INDEX)
    {
      session_t *ls;

      ls = listen_session_get (al->session_index);
      handle = listen_session_get_handle (ls);

      sm_indexp = hash_get (app_wrk->listeners_table, handle);
      if (PREDICT_FALSE (!sm_indexp))
	{
	  clib_warning ("listener handle was removed %llu!", handle);
	  return -1;
	}

      sm = segment_manager_get (*sm_indexp);
      if (app_wrk->first_segment_manager == *sm_indexp)
	{
	  /* Delete sessions but don't remove segment manager */
	  app_wrk->first_segment_manager_in_use = 0;
	  segment_manager_del_sessions (sm);
	}
      else
	{
	  segment_manager_init_del (sm);
	}
      hash_unset (app_wrk->listeners_table, handle);
    }

  if (al->local_index != SESSION_INVALID_INDEX)
    {
      local_session_t *ll, *ls;
      application_t *app;

      app = application_get (app_wrk->app_index);
      ll = application_get_local_listen_session (app, al->local_index);

      /* *INDENT-OFF* */
      pool_foreach (ls, app_wrk->local_sessions, ({
        if (ls->listener_index == ll->session_index)
          app_worker_local_session_disconnect (app_wrk->app_index, ls);
      }));
      /* *INDENT-ON* */
    }

  clib_bitmap_set_no_check (al->workers, app_wrk->wrk_map_index, 0);
  if (clib_bitmap_is_zero (al->workers))
    app_listener_cleanup (al);

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
  if (session_alloc_fifos (sm, s))
    return -1;

  if (!svm_fifo_is_empty (rxf))
    {
      clib_memcpy_fast (s->rx_fifo->data, rxf->data, rxf->nitems);
      s->rx_fifo->head = rxf->head;
      s->rx_fifo->tail = rxf->tail;
      s->rx_fifo->cursize = rxf->cursize;
    }

  if (!svm_fifo_is_empty (txf))
    {
      clib_memcpy_fast (s->tx_fifo->data, txf->data, txf->nitems);
      s->tx_fifo->head = txf->head;
      s->tx_fifo->tail = txf->tail;
      s->tx_fifo->cursize = txf->cursize;
    }

  segment_manager_dealloc_fifos (rxf->segment_index, rxf, txf);

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
	 && listener->enqueue_epoch != SESSION_PROXY_LISTENER_INDEX)
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
     if (listener->session_type == sst
	 && listener->enqueue_epoch == SESSION_PROXY_LISTENER_INDEX)
       return listener;
   }));
  /* *INDENT-ON* */

  return 0;
}

/**
 * Send an API message to the external app, to map new segment
 */
int
app_worker_add_segment_notify (u32 app_wrk_index, u64 segment_handle)
{
  app_worker_t *app_wrk = app_worker_get (app_wrk_index);
  application_t *app = application_get (app_wrk->app_index);
  return app->cb_fns.add_segment_callback (app_wrk->api_client_index,
					   segment_handle);
}

u8
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
    {
      /* Session is closed so app will never clean up. Flush rx fifo */
      if (s->session_state == SESSION_STATE_CLOSED)
	svm_fifo_dequeue_drop_all (s->rx_fifo);
      return 0;
    }

  if (app_worker_application_is_builtin (app_wrk))
    {
      application_t *app = application_get (app_wrk->app_index);
      return app->cb_fns.builtin_app_rx_callback (s);
    }

  if (svm_fifo_has_event (s->rx_fifo) || svm_fifo_is_empty (s->rx_fifo))
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
  evt->fifo = s->rx_fifo;
  evt->event_type = FIFO_EVENT_APP_RX;

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
  evt->event_type = FIFO_EVENT_APP_TX;
  evt->fifo = s->tx_fifo;

  return app_enqueue_evt (mq, &msg, lock);
}

/* *INDENT-OFF* */
typedef int (app_send_evt_handler_fn) (app_worker_t *app,
				       session_t *s,
				       u8 lock);
static app_send_evt_handler_fn * const app_send_evt_handler_fns[3] = {
    app_send_io_evt_rx,
    0,
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
  ASSERT (app && evt_type <= FIFO_EVENT_APP_TX);
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

segment_manager_t *
app_worker_get_local_segment_manager (app_worker_t * app_worker)
{
  return segment_manager_get (app_worker->local_segment_manager);
}

segment_manager_t *
app_worker_get_local_segment_manager_w_session (app_worker_t * app_wrk,
						local_session_t * ls)
{
  session_t *listener;
  if (application_local_session_listener_has_transport (ls))
    {
      listener = listen_session_get (ls->listener_index);
      return app_worker_get_listen_segment_manager (app_wrk, listener);
    }
  return segment_manager_get (app_wrk->local_segment_manager);
}

int
app_worker_local_session_cleanup (app_worker_t * client_wrk,
				  app_worker_t * server_wrk,
				  local_session_t * ls)
{
  svm_fifo_segment_private_t *seg;
  session_t *listener;
  segment_manager_t *sm;
  u64 client_key;
  u8 has_transport;

  /* Retrieve listener transport type as it is the one that decides where
   * the fifos are allocated */
  has_transport = application_local_session_listener_has_transport (ls);
  if (!has_transport)
    sm = app_worker_get_local_segment_manager_w_session (server_wrk, ls);
  else
    {
      listener = listen_session_get (ls->listener_index);
      sm = app_worker_get_listen_segment_manager (server_wrk, listener);
    }

  seg = segment_manager_get_segment (sm, ls->svm_segment_index);
  if (client_wrk)
    {
      client_key = application_client_local_connect_key (ls);
      hash_unset (client_wrk->local_connects, client_key);
    }

  if (!has_transport)
    {
      application_t *server = application_get (server_wrk->app_index);
      u64 segment_handle = segment_manager_segment_handle (sm, seg);
      server->cb_fns.del_segment_callback (server_wrk->api_client_index,
					   segment_handle);
      if (client_wrk)
	{
	  application_t *client = application_get (client_wrk->app_index);
	  client->cb_fns.del_segment_callback (client_wrk->api_client_index,
					       segment_handle);
	}
      segment_manager_del_segment (sm, seg);
    }

  app_worker_local_session_free (server_wrk, ls);

  return 0;
}

static void
application_local_session_fix_eventds (svm_msg_q_t * sq, svm_msg_q_t * cq)
{
  int fd;

  /*
   * segment manager initializes only the producer eventds, since vpp is
   * typically the producer. But for local sessions, we also pass to the
   * apps the mqs they listen on for events from peer apps, so they are also
   * consumer fds.
   */
  fd = svm_msg_q_get_producer_eventfd (sq);
  svm_msg_q_set_consumer_eventfd (sq, fd);
  fd = svm_msg_q_get_producer_eventfd (cq);
  svm_msg_q_set_consumer_eventfd (cq, fd);
}

int
app_worker_local_session_connect (app_worker_t * client_wrk,
				  app_worker_t * server_wrk,
				  local_session_t * ll, u32 opaque)
{
  u32 seg_size, evt_q_sz, evt_q_elts, margin = 16 << 10;
  u32 round_rx_fifo_sz, round_tx_fifo_sz, sm_index;
  segment_manager_properties_t *props, *cprops;
  int rv, has_transport, seg_index;
  svm_fifo_segment_private_t *seg;
  application_t *server, *client;
  segment_manager_t *sm;
  local_session_t *ls;
  svm_msg_q_t *sq, *cq;
  u64 segment_handle;

  ls = app_worker_local_session_alloc (server_wrk);
  server = application_get (server_wrk->app_index);
  client = application_get (client_wrk->app_index);

  props = application_segment_manager_properties (server);
  cprops = application_segment_manager_properties (client);
  evt_q_elts = props->evt_q_size + cprops->evt_q_size;
  evt_q_sz = segment_manager_evt_q_expected_size (evt_q_elts);
  round_rx_fifo_sz = 1 << max_log2 (props->rx_fifo_size);
  round_tx_fifo_sz = 1 << max_log2 (props->tx_fifo_size);
  seg_size = round_rx_fifo_sz + round_tx_fifo_sz + evt_q_sz + margin;

  has_transport = session_has_transport ((session_t *) ll);
  if (!has_transport)
    {
      /* Local sessions don't have backing transport */
      ls->port = ll->port;
      sm = app_worker_get_local_segment_manager (server_wrk);
    }
  else
    {
      session_t *sl = (session_t *) ll;
      transport_connection_t *tc;
      tc = listen_session_get_transport (sl);
      ls->port = tc->lcl_port;
      sm = app_worker_get_listen_segment_manager (server_wrk, sl);
    }

  seg_index = segment_manager_add_segment (sm, seg_size);
  if (seg_index < 0)
    {
      clib_warning ("failed to add new cut-through segment");
      return seg_index;
    }
  seg = segment_manager_get_segment_w_lock (sm, seg_index);
  sq = segment_manager_alloc_queue (seg, props);
  cq = segment_manager_alloc_queue (seg, cprops);

  if (props->use_mq_eventfd)
    application_local_session_fix_eventds (sq, cq);

  ls->server_evt_q = pointer_to_uword (sq);
  ls->client_evt_q = pointer_to_uword (cq);
  rv = segment_manager_try_alloc_fifos (seg, props->rx_fifo_size,
					props->tx_fifo_size,
					&ls->rx_fifo, &ls->tx_fifo);
  if (rv)
    {
      clib_warning ("failed to add fifos in cut-through segment");
      segment_manager_segment_reader_unlock (sm);
      goto failed;
    }
  sm_index = segment_manager_index (sm);
  ls->rx_fifo->ct_session_index = ls->session_index;
  ls->tx_fifo->ct_session_index = ls->session_index;
  ls->rx_fifo->segment_manager = sm_index;
  ls->tx_fifo->segment_manager = sm_index;
  ls->rx_fifo->segment_index = seg_index;
  ls->tx_fifo->segment_index = seg_index;
  ls->svm_segment_index = seg_index;
  ls->listener_index = ll->session_index;
  ls->client_wrk_index = client_wrk->wrk_index;
  ls->client_opaque = opaque;
  ls->listener_session_type = ll->session_type;
  ls->session_state = SESSION_STATE_READY;

  segment_handle = segment_manager_segment_handle (sm, seg);
  if ((rv = server->cb_fns.add_segment_callback (server_wrk->api_client_index,
						 segment_handle)))
    {
      clib_warning ("failed to notify server of new segment");
      segment_manager_segment_reader_unlock (sm);
      goto failed;
    }
  segment_manager_segment_reader_unlock (sm);
  if ((rv = server->cb_fns.session_accept_callback ((session_t *) ls)))
    {
      clib_warning ("failed to send accept cut-through notify to server");
      goto failed;
    }
  if (server->flags & APP_OPTIONS_FLAGS_IS_BUILTIN)
    app_worker_local_session_connect_notify (ls);

  return 0;

failed:
  if (!has_transport)
    segment_manager_del_segment (sm, seg);
  return rv;
}

int
app_worker_local_session_connect_notify (local_session_t * ls)
{
  svm_fifo_segment_private_t *seg;
  app_worker_t *client_wrk, *server_wrk;
  segment_manager_t *sm;
  application_t *client;
  int rv, is_fail = 0;
  u64 segment_handle;
  u64 client_key;

  client_wrk = app_worker_get (ls->client_wrk_index);
  server_wrk = app_worker_get (ls->app_wrk_index);
  client = application_get (client_wrk->app_index);

  sm = app_worker_get_local_segment_manager_w_session (server_wrk, ls);
  seg = segment_manager_get_segment_w_lock (sm, ls->svm_segment_index);
  segment_handle = segment_manager_segment_handle (sm, seg);
  if ((rv = client->cb_fns.add_segment_callback (client_wrk->api_client_index,
						 segment_handle)))
    {
      clib_warning ("failed to notify client %u of new segment",
		    ls->client_wrk_index);
      segment_manager_segment_reader_unlock (sm);
      app_worker_local_session_disconnect (ls->client_wrk_index, ls);
      is_fail = 1;
    }
  else
    {
      segment_manager_segment_reader_unlock (sm);
    }

  client->cb_fns.session_connected_callback (client_wrk->wrk_index,
					     ls->client_opaque,
					     (session_t *) ls, is_fail);

  client_key = application_client_local_connect_key (ls);
  hash_set (client_wrk->local_connects, client_key, client_key);
  return 0;
}

int
app_worker_local_session_disconnect (u32 app_index, local_session_t * ls)
{
  app_worker_t *client_wrk, *server_wrk;
  u8 is_server = 0, is_client = 0;
  application_t *app;

  app = application_get_if_valid (app_index);
  if (!app)
    return 0;

  client_wrk = app_worker_get_if_valid (ls->client_wrk_index);
  server_wrk = app_worker_get (ls->app_wrk_index);

  if (server_wrk->app_index == app_index)
    is_server = 1;
  else if (client_wrk && client_wrk->app_index == app_index)
    is_client = 1;

  if (!is_server && !is_client)
    {
      clib_warning ("app %u is neither client nor server for session 0x%lx",
		    app_index, application_local_session_handle (ls));
      return VNET_API_ERROR_INVALID_VALUE;
    }

  if (ls->session_state == SESSION_STATE_CLOSED)
    return app_worker_local_session_cleanup (client_wrk, server_wrk, ls);

  if (app_index == ls->client_wrk_index)
    {
      mq_send_local_session_disconnected_cb (ls->app_wrk_index, ls);
    }
  else
    {
      if (!client_wrk)
	{
	  return app_worker_local_session_cleanup (client_wrk, server_wrk,
						   ls);
	}
      else if (ls->session_state < SESSION_STATE_READY)
	{
	  application_t *client = application_get (client_wrk->app_index);
	  client->cb_fns.session_connected_callback (client_wrk->wrk_index,
						     ls->client_opaque,
						     (session_t *) ls,
						     1 /* is_fail */ );
	  ls->session_state = SESSION_STATE_CLOSED;
	  return app_worker_local_session_cleanup (client_wrk, server_wrk,
						   ls);
	}
      else
	{
	  mq_send_local_session_disconnected_cb (client_wrk->wrk_index, ls);
	}
    }

  ls->session_state = SESSION_STATE_CLOSED;

  return 0;
}

int
app_worker_local_session_disconnect_w_index (u32 app_wrk_index, u32 ls_index)
{
  app_worker_t *app_wrk;
  local_session_t *ls;
  app_wrk = app_worker_get (app_wrk_index);
  ls = app_worker_get_local_session (app_wrk, ls_index);
  return app_worker_local_session_disconnect (app_wrk_index, ls);
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
  str = format (0, "%U", format_stream_session, listener, verbose);

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
  svm_fifo_segment_private_t *fifo_segment;
  vlib_main_t *vm = vlib_get_main ();
  segment_manager_t *sm;
  const u8 *app_name;
  u8 *s = 0;

  /* Header */
  if (!app_wrk)
    {
      if (verbose)
	vlib_cli_output (vm, "%-40s%-20s%-15s%-10s", "Connection", "App",
			 "API Client", "SegManager");
      else
	vlib_cli_output (vm, "%-40s%-20s", "Connection", "App");
      return;
    }

  if (app_wrk->connects_seg_manager == (u32) ~ 0)
    return;

  app_name = application_name_from_index (app_wrk->app_index);

  /* Across all fifo segments */
  sm = segment_manager_get (app_wrk->connects_seg_manager);

  /* *INDENT-OFF* */
  segment_manager_foreach_segment_w_lock (fifo_segment, sm, ({
    svm_fifo_t *fifo;
    u8 *str;

    fifo = svm_fifo_segment_get_fifo_list (fifo_segment);
    while (fifo)
      {
        u32 session_index, thread_index;
        session_t *session;

        session_index = fifo->master_session_index;
        thread_index = fifo->master_thread_index;

        session = session_get (session_index, thread_index);
        str = format (0, "%U", format_stream_session, session, verbose);

        if (verbose)
          s = format (s, "%-40s%-20s%-15u%-10u", str, app_name,
                      app_wrk->api_client_index, app_wrk->connects_seg_manager);
        else
          s = format (s, "%-40s%-20s", str, app_name);

        vlib_cli_output (vm, "%v", s);
        vec_reset_length (s);
        vec_free (str);

        fifo = fifo->next;
      }
    vec_free (s);
  }));
  /* *INDENT-ON* */
}

void
app_worker_format_local_sessions (app_worker_t * app_wrk, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  app_worker_t *client_wrk;
  local_session_t *ls;
  transport_proto_t tp;
  u8 *conn = 0;

  /* Header */
  if (app_wrk == 0)
    {
      vlib_cli_output (vm, "%-40s%-15s%-20s", "Connection", "ServerApp",
		       "ClientApp");
      return;
    }

  if (!pool_elts (app_wrk->local_sessions)
      && !pool_elts (app_wrk->local_connects))
    return;

  /* *INDENT-OFF* */
  pool_foreach (ls, app_wrk->local_sessions, ({
    tp = session_type_transport_proto(ls->listener_session_type);
    conn = format (0, "[L][%U] *:%u", format_transport_proto_short, tp,
                   ls->port);
    client_wrk = app_worker_get (ls->client_wrk_index);
    vlib_cli_output (vm, "%-40v%-15u%-20u", conn, ls->app_index,
                     client_wrk->app_index);
    vec_reset_length (conn);
  }));
  /* *INDENT-ON* */

  vec_free (conn);
}

void
app_worker_format_local_connects (app_worker_t * app, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 app_wrk_index, session_index;
  app_worker_t *server_wrk;
  local_session_t *ls;
  u64 client_key;
  u64 value;

  /* Header */
  if (app == 0)
    {
      if (verbose)
	vlib_cli_output (vm, "%-40s%-15s%-20s%-10s", "Connection", "App",
			 "Peer App", "SegManager");
      else
	vlib_cli_output (vm, "%-40s%-15s%-20s", "Connection", "App",
			 "Peer App");
      return;
    }

  if (!app->local_connects)
    return;

  /* *INDENT-OFF* */
  hash_foreach (client_key, value, app->local_connects, ({
    application_client_local_connect_key_parse (client_key, &app_wrk_index,
                                                &session_index);
    server_wrk = app_worker_get (app_wrk_index);
    ls = app_worker_get_local_session (server_wrk, session_index);
    vlib_cli_output (vm, "%-40s%-15s%-20s", "TODO", ls->app_wrk_index,
                     ls->client_wrk_index);
  }));
  /* *INDENT-ON* */
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
