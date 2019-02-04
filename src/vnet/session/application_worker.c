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

app_worker_t *
app_worker_alloc (application_t * app)
{
  app_worker_t *app_wrk;
  pool_get (app_main.workers, app_wrk);
  clib_memset (app_wrk, 0, sizeof (*app_wrk));
  app_wrk->wrk_index = app_wrk - app_main.workers;
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
  return pool_elt_at_index (app_main.workers, wrk_index);
}

app_worker_t *
app_worker_get_if_valid (u32 wrk_index)
{
  if (pool_is_free_index (app_main.workers, wrk_index))
    return 0;
  return pool_elt_at_index (app_main.workers, wrk_index);
}

void
app_worker_free (app_worker_t * app_wrk)
{
  application_t *app = application_get (app_wrk->app_index);
  vnet_unbind_args_t _a, *a = &_a;
  u64 handle, *handles = 0;
  segment_manager_t *sm;
  u32 sm_index;
  int i;

  /*
   *  Listener cleanup
   */

  /* *INDENT-OFF* */
  hash_foreach (handle, sm_index, app_wrk->listeners_table,
  ({
    vec_add1 (handles, handle);
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
      vnet_unbind (a);
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

  pool_put (app_main.workers, app_wrk);
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
app_worker_start_listen (app_worker_t * app_wrk, session_t * ls)
{
  segment_manager_t *sm;

  /* Allocate segment manager. All sessions derived out of a listen session
   * have fifos allocated by the same segment manager. */
  if (!(sm = app_worker_alloc_segment_manager (app_wrk)))
    return -1;

  /* Add to app's listener table. Useful to find all child listeners
   * when app goes down, although, just for unbinding this is not needed */
  hash_set (app_wrk->listeners_table, listen_session_get_handle (ls),
	    segment_manager_index (sm));

  if (!ls->rx_fifo
      && session_transport_service_type (ls) == TRANSPORT_SERVICE_CL)
    {
      if (session_alloc_fifos (sm, ls))
	return -1;
    }
  return 0;
}

int
app_worker_stop_listen (app_worker_t * app_wrk, session_handle_t handle)
{
  segment_manager_t *sm;
  uword *sm_indexp;

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
app_worker_open_session (app_worker_t * app, session_endpoint_t * sep,
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

  if (svm_fifo_has_event (s->rx_fifo)
      || svm_fifo_is_empty (s->rx_fifo))
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
