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

#include <math.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/elog.h>
#include <vnet/session/transport.h>
#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/application_local.h>
#include <vnet/session/session_debug.h>
#include <svm/queue.h>
#include <sys/timerfd.h>

static inline void
session_wrk_send_evt_to_main (session_worker_t *wrk, session_evt_elt_t *elt)
{
  session_evt_elt_t *he;
  uword thread_index;
  u8 is_empty;

  thread_index = wrk->vm->thread_index;
  he = clib_llist_elt (wrk->event_elts, wrk->evts_pending_main);
  is_empty = clib_llist_is_empty (wrk->event_elts, evt_list, he);
  clib_llist_add_tail (wrk->event_elts, evt_list, elt, he);
  if (is_empty)
    session_send_rpc_evt_to_thread (0, session_wrk_handle_evts_main_rpc,
				    uword_to_pointer (thread_index, void *));
}

#define app_check_thread_and_barrier(_wrk, _elt)                              \
  if (!vlib_thread_is_main_w_barrier ())                                      \
    {                                                                         \
      session_wrk_send_evt_to_main (wrk, elt);                                \
      return;                                                                 \
    }

static void
session_wrk_timerfd_update (session_worker_t *wrk, u64 time_ns)
{
  struct itimerspec its;

  its.it_value.tv_sec = 0;
  its.it_value.tv_nsec = time_ns;
  its.it_interval.tv_sec = 0;
  its.it_interval.tv_nsec = its.it_value.tv_nsec;

  if (timerfd_settime (wrk->timerfd, 0, &its, NULL) == -1)
    clib_warning ("timerfd_settime");
}

always_inline u64
session_wrk_tfd_timeout (session_wrk_state_t state, u32 thread_index)
{
  if (state == SESSION_WRK_INTERRUPT)
    return thread_index ? 1e6 : vlib_num_workers () ? 5e8 : 1e6;
  else if (state == SESSION_WRK_IDLE)
    return thread_index ? 1e8 : vlib_num_workers () ? 5e8 : 1e8;
  else
    return 0;
}

static inline void
session_wrk_set_state (session_worker_t *wrk, session_wrk_state_t state)
{
  u64 time_ns;

  wrk->state = state;
  if (wrk->timerfd == -1)
    return;
  time_ns = session_wrk_tfd_timeout (state, wrk->vm->thread_index);
  session_wrk_timerfd_update (wrk, time_ns);
}

static transport_endpt_ext_cfg_t *
session_mq_get_ext_config (application_t *app, uword offset)
{
  svm_fifo_chunk_t *c;
  fifo_segment_t *fs;

  fs = application_get_rx_mqs_segment (app);
  c = fs_chunk_ptr (fs->h, offset);
  return (transport_endpt_ext_cfg_t *) c->data;
}

static void
session_mq_free_ext_config (application_t *app, uword offset)
{
  svm_fifo_chunk_t *c;
  fifo_segment_t *fs;

  fs = application_get_rx_mqs_segment (app);
  c = fs_chunk_ptr (fs->h, offset);
  fifo_segment_collect_chunk (fs, 0 /* only one slice */, c);
}

static void
session_mq_listen_handler (session_worker_t *wrk, session_evt_elt_t *elt)
{
  vnet_listen_args_t _a, *a = &_a;
  session_listen_msg_t *mp;
  app_worker_t *app_wrk;
  application_t *app;
  int rv;

  app_check_thread_and_barrier (wrk, elt);

  mp = session_evt_ctrl_data (wrk, elt);
  app = application_lookup (mp->client_index);
  if (!app)
    return;

  clib_memset (a, 0, sizeof (*a));
  a->sep.is_ip4 = mp->is_ip4;
  ip_copy (&a->sep.ip, &mp->ip, mp->is_ip4);
  a->sep.port = mp->port;
  a->sep.fib_index = mp->vrf;
  a->sep.sw_if_index = ENDPOINT_INVALID_INDEX;
  a->sep.transport_proto = mp->proto;
  a->app_index = app->app_index;
  a->wrk_map_index = mp->wrk_index;
  a->sep_ext.transport_flags = mp->flags;

  if (mp->ext_config)
    a->sep_ext.ext_cfg = session_mq_get_ext_config (app, mp->ext_config);

  if ((rv = vnet_listen (a)))
    clib_warning ("listen returned: %U", format_session_error, rv);

  app_wrk = application_get_worker (app, mp->wrk_index);
  mq_send_session_bound_cb (app_wrk->wrk_index, mp->context, a->handle, rv);

  if (mp->ext_config)
    session_mq_free_ext_config (app, mp->ext_config);
}

static void
session_mq_listen_uri_handler (session_worker_t *wrk, session_evt_elt_t *elt)
{
  vnet_listen_args_t _a, *a = &_a;
  session_listen_uri_msg_t *mp;
  app_worker_t *app_wrk;
  application_t *app;
  int rv;

  app_check_thread_and_barrier (wrk, elt);

  mp = session_evt_ctrl_data (wrk, elt);
  app = application_lookup (mp->client_index);
  if (!app)
    return;

  clib_memset (a, 0, sizeof (*a));
  a->uri = (char *) mp->uri;
  a->app_index = app->app_index;
  rv = vnet_bind_uri (a);

  app_wrk = application_get_worker (app, 0);
  mq_send_session_bound_cb (app_wrk->wrk_index, mp->context, a->handle, rv);
}

static void
session_mq_connect_one (session_connect_msg_t *mp)
{
  vnet_connect_args_t _a, *a = &_a;
  app_worker_t *app_wrk;
  application_t *app;
  int rv;

  app = application_lookup (mp->client_index);
  if (!app)
    return;

  clib_memset (a, 0, sizeof (*a));
  a->sep.is_ip4 = mp->is_ip4;
  clib_memcpy_fast (&a->sep.ip, &mp->ip, sizeof (mp->ip));
  a->sep.port = mp->port;
  a->sep.transport_proto = mp->proto;
  a->sep.peer.fib_index = mp->vrf;
  a->sep.dscp = mp->dscp;
  clib_memcpy_fast (&a->sep.peer.ip, &mp->lcl_ip, sizeof (mp->lcl_ip));
  if (mp->is_ip4)
    {
      ip46_address_mask_ip4 (&a->sep.ip);
      ip46_address_mask_ip4 (&a->sep.peer.ip);
    }
  a->sep.peer.port = mp->lcl_port;
  a->sep.peer.sw_if_index = ENDPOINT_INVALID_INDEX;
  a->sep_ext.parent_handle = mp->parent_handle;
  a->sep_ext.transport_flags = mp->flags;
  a->api_context = mp->context;
  a->app_index = app->app_index;
  a->wrk_map_index = mp->wrk_index;

  if (mp->ext_config)
    a->sep_ext.ext_cfg = session_mq_get_ext_config (app, mp->ext_config);

  if ((rv = vnet_connect (a)))
    {
      clib_warning ("connect returned: %U", format_session_error, rv);
      app_wrk = application_get_worker (app, mp->wrk_index);
      mq_send_session_connected_cb (app_wrk->wrk_index, mp->context, 0, rv);
    }

  if (mp->ext_config)
    session_mq_free_ext_config (app, mp->ext_config);
}

static void
session_mq_handle_connects_rpc (void *arg)
{
  u32 max_connects = 32, n_connects = 0;
  vlib_main_t *vm = vlib_get_main ();
  session_evt_elt_t *he, *elt, *next;
  session_worker_t *fwrk, *wrk;

  ASSERT (vlib_get_thread_index () == 0);

  /* Pending connects on linked list pertaining to first worker */
  fwrk = session_main_get_worker (1);
  if (!fwrk->n_pending_connects)
    goto update_state;

  vlib_worker_thread_barrier_sync (vm);

  he = clib_llist_elt (fwrk->event_elts, fwrk->pending_connects);
  elt = clib_llist_next (fwrk->event_elts, evt_list, he);

  /* Avoid holding the barrier for too long */
  while (n_connects < max_connects && elt != he)
    {
      next = clib_llist_next (fwrk->event_elts, evt_list, elt);
      clib_llist_remove (fwrk->event_elts, evt_list, elt);
      session_mq_connect_one (session_evt_ctrl_data (fwrk, elt));
      session_evt_ctrl_data_free (fwrk, elt);
      clib_llist_put (fwrk->event_elts, elt);
      elt = next;
      n_connects += 1;
    }

  /* Decrement with worker barrier */
  fwrk->n_pending_connects -= n_connects;

  vlib_worker_thread_barrier_release (vm);

update_state:

  /* Switch worker to poll mode if it was in interrupt mode and had work or
   * back to interrupt if threshold of loops without a connect is passed.
   * While in poll mode, reprogram connects rpc */
  wrk = session_main_get_worker (0);
  if (wrk->state != SESSION_WRK_POLLING)
    {
      if (n_connects)
	{
	  session_wrk_set_state (wrk, SESSION_WRK_POLLING);
	  vlib_node_set_state (vm, session_queue_node.index,
			       VLIB_NODE_STATE_POLLING);
	  wrk->no_connect_loops = 0;
	}
    }
  else
    {
      if (!n_connects)
	{
	  if (++wrk->no_connect_loops > 1e5)
	    {
	      session_wrk_set_state (wrk, SESSION_WRK_INTERRUPT);
	      vlib_node_set_state (vm, session_queue_node.index,
				   VLIB_NODE_STATE_INTERRUPT);
	    }
	}
      else
	wrk->no_connect_loops = 0;
    }

  if (wrk->state == SESSION_WRK_POLLING)
    {
      elt = session_evt_alloc_ctrl (wrk);
      elt->evt.event_type = SESSION_CTRL_EVT_RPC;
      elt->evt.rpc_args.fp = session_mq_handle_connects_rpc;
    }
}

static void
session_mq_connect_handler (session_worker_t *wrk, session_evt_elt_t *elt)
{
  u32 thread_index = wrk - session_main.wrk;
  session_evt_elt_t *he;

  /* No workers, so just deal with the connect now */
  if (PREDICT_FALSE (!thread_index))
    {
      session_mq_connect_one (session_evt_ctrl_data (wrk, elt));
      return;
    }

  if (PREDICT_FALSE (thread_index != 1))
    {
      clib_warning ("Connect on wrong thread. Dropping");
      return;
    }

  /* Add to pending list to be handled by main thread */
  he = clib_llist_elt (wrk->event_elts, wrk->pending_connects);
  clib_llist_add_tail (wrk->event_elts, evt_list, elt, he);

  /* Decremented with worker barrier */
  wrk->n_pending_connects += 1;
  if (wrk->n_pending_connects == 1)
    {
      vlib_node_set_interrupt_pending (vlib_get_main_by_index (0),
				       session_queue_node.index);
      session_send_rpc_evt_to_thread (0, session_mq_handle_connects_rpc, 0);
    }
}

static void
session_mq_connect_uri_handler (session_worker_t *wrk, session_evt_elt_t *elt)
{
  vnet_connect_args_t _a, *a = &_a;
  session_connect_uri_msg_t *mp;
  app_worker_t *app_wrk;
  application_t *app;
  int rv;

  app_check_thread_and_barrier (wrk, elt);

  mp = session_evt_ctrl_data (wrk, elt);
  app = application_lookup (mp->client_index);
  if (!app)
    return;

  clib_memset (a, 0, sizeof (*a));
  a->uri = (char *) mp->uri;
  a->api_context = mp->context;
  a->app_index = app->app_index;
  if ((rv = vnet_connect_uri (a)))
    {
      clib_warning ("connect_uri returned: %d", rv);
      app_wrk = application_get_worker (app, 0 /* default wrk only */ );
      mq_send_session_connected_cb (app_wrk->wrk_index, mp->context, 0, rv);
    }
}

static void
session_mq_shutdown_handler (void *data)
{
  session_shutdown_msg_t *mp = (session_shutdown_msg_t *) data;
  vnet_shutdown_args_t _a, *a = &_a;
  application_t *app;

  app = application_lookup (mp->client_index);
  if (!app)
    return;

  a->app_index = app->app_index;
  a->handle = mp->handle;
  vnet_shutdown_session (a);
}

static void
session_mq_disconnect_handler (void *data)
{
  session_disconnect_msg_t *mp = (session_disconnect_msg_t *) data;
  vnet_disconnect_args_t _a, *a = &_a;
  application_t *app;

  app = application_lookup (mp->client_index);
  if (!app)
    return;

  a->app_index = app->app_index;
  a->handle = mp->handle;
  vnet_disconnect_session (a);
}

static void
app_mq_detach_handler (session_worker_t *wrk, session_evt_elt_t *elt)
{
  vnet_app_detach_args_t _a, *a = &_a;
  session_app_detach_msg_t *mp;
  application_t *app;

  app_check_thread_and_barrier (wrk, elt);

  mp = session_evt_ctrl_data (wrk, elt);
  app = application_lookup (mp->client_index);
  if (!app)
    return;

  a->app_index = app->app_index;
  a->api_client_index = mp->client_index;
  vnet_application_detach (a);
}

static void
session_mq_unlisten_handler (session_worker_t *wrk, session_evt_elt_t *elt)
{
  vnet_unlisten_args_t _a, *a = &_a;
  session_unlisten_msg_t *mp;
  app_worker_t *app_wrk;
  session_handle_t sh;
  application_t *app;
  int rv;

  app_check_thread_and_barrier (wrk, elt);

  mp = session_evt_ctrl_data (wrk, elt);
  sh = mp->handle;

  app = application_lookup (mp->client_index);
  if (!app)
    return;

  clib_memset (a, 0, sizeof (*a));
  a->app_index = app->app_index;
  a->handle = sh;
  a->wrk_map_index = mp->wrk_index;

  if ((rv = vnet_unlisten (a)))
    clib_warning ("unlisten returned: %d", rv);

  app_wrk = application_get_worker (app, a->wrk_map_index);
  if (!app_wrk)
    return;

  mq_send_unlisten_reply (app_wrk, sh, mp->context, rv);
}

static void
session_mq_accepted_reply_handler (session_worker_t *wrk,
				   session_evt_elt_t *elt)
{
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  session_accepted_reply_msg_t *mp;
  session_state_t old_state;
  app_worker_t *app_wrk;
  session_t *s;

  mp = session_evt_ctrl_data (wrk, elt);

  /* Mail this back from the main thread. We're not polling in main
   * thread so we're using other workers for notifications. */
  if (session_thread_from_handle (mp->handle) == 0 && vlib_num_workers () &&
      vlib_get_thread_index () != 0)
    {
      session_wrk_send_evt_to_main (wrk, elt);
      return;
    }

  s = session_get_from_handle_if_valid (mp->handle);
  if (!s)
    return;

  app_wrk = app_worker_get (s->app_wrk_index);
  if (app_wrk->app_index != mp->context)
    {
      clib_warning ("app doesn't own session");
      return;
    }

  /* Server isn't interested, disconnect the session */
  if (mp->retval)
    {
      a->app_index = mp->context;
      a->handle = mp->handle;
      vnet_disconnect_session (a);
      return;
    }

  /* Special handling for cut-through sessions */
  if (!session_has_transport (s))
    {
      s->session_state = SESSION_STATE_READY;
      ct_session_connect_notify (s, SESSION_E_NONE);
      return;
    }

  old_state = s->session_state;
  s->session_state = SESSION_STATE_READY;

  if (!svm_fifo_is_empty_prod (s->rx_fifo))
    app_worker_lock_and_send_event (app_wrk, s, SESSION_IO_EVT_RX);

  /* Closed while waiting for app to reply. Resend disconnect */
  if (old_state >= SESSION_STATE_TRANSPORT_CLOSING)
    {
      app_worker_close_notify (app_wrk, s);
      s->session_state = old_state;
      return;
    }
}

static void
session_mq_reset_reply_handler (void *data)
{
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  session_reset_reply_msg_t *mp;
  app_worker_t *app_wrk;
  session_t *s;
  application_t *app;
  u32 index, thread_index;

  mp = (session_reset_reply_msg_t *) data;
  app = application_lookup (mp->context);
  if (!app)
    return;

  session_parse_handle (mp->handle, &index, &thread_index);
  s = session_get_if_valid (index, thread_index);

  /* No session or not the right session */
  if (!s || s->session_state < SESSION_STATE_TRANSPORT_CLOSING)
    return;

  app_wrk = app_worker_get (s->app_wrk_index);
  if (!app_wrk || app_wrk->app_index != app->app_index)
    {
      clib_warning ("App %u does not own handle 0x%lx!", app->app_index,
		    mp->handle);
      return;
    }

  /* Client objected to resetting the session, log and continue */
  if (mp->retval)
    {
      clib_warning ("client retval %d", mp->retval);
      return;
    }

  /* This comes as a response to a reset, transport only waiting for
   * confirmation to remove connection state, no need to disconnect */
  a->handle = mp->handle;
  a->app_index = app->app_index;
  vnet_disconnect_session (a);
}

static void
session_mq_disconnected_handler (void *data)
{
  session_disconnected_reply_msg_t *rmp;
  vnet_disconnect_args_t _a, *a = &_a;
  svm_msg_q_msg_t _msg, *msg = &_msg;
  session_disconnected_msg_t *mp;
  app_worker_t *app_wrk;
  session_event_t *evt;
  session_t *s;
  application_t *app;
  int rv = 0;

  mp = (session_disconnected_msg_t *) data;
  if (!(s = session_get_from_handle_if_valid (mp->handle)))
    {
      clib_warning ("could not disconnect handle %llu", mp->handle);
      return;
    }
  app_wrk = app_worker_get (s->app_wrk_index);
  app = application_lookup (mp->client_index);
  if (!(app_wrk && app && app->app_index == app_wrk->app_index))
    {
      clib_warning ("could not disconnect session: %llu app: %u",
		    mp->handle, mp->client_index);
      return;
    }

  a->handle = mp->handle;
  a->app_index = app_wrk->wrk_index;
  rv = vnet_disconnect_session (a);

  svm_msg_q_lock_and_alloc_msg_w_ring (app_wrk->event_queue,
				       SESSION_MQ_CTRL_EVT_RING,
				       SVM_Q_WAIT, msg);
  evt = svm_msg_q_msg_data (app_wrk->event_queue, msg);
  clib_memset (evt, 0, sizeof (*evt));
  evt->event_type = SESSION_CTRL_EVT_DISCONNECTED_REPLY;
  rmp = (session_disconnected_reply_msg_t *) evt->data;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  rmp->retval = rv;
  svm_msg_q_add_and_unlock (app_wrk->event_queue, msg);
}

static void
session_mq_disconnected_reply_handler (void *data)
{
  session_disconnected_reply_msg_t *mp;
  vnet_disconnect_args_t _a, *a = &_a;
  application_t *app;

  mp = (session_disconnected_reply_msg_t *) data;

  /* Client objected to disconnecting the session, log and continue */
  if (mp->retval)
    {
      clib_warning ("client retval %d", mp->retval);
      return;
    }

  /* Disconnect has been confirmed. Confirm close to transport */
  app = application_lookup (mp->context);
  if (app)
    {
      a->handle = mp->handle;
      a->app_index = app->app_index;
      vnet_disconnect_session (a);
    }
}

static void
session_mq_worker_update_handler (void *data)
{
  session_worker_update_msg_t *mp = (session_worker_update_msg_t *) data;
  session_worker_update_reply_msg_t *rmp;
  svm_msg_q_msg_t _msg, *msg = &_msg;
  app_worker_t *app_wrk;
  u32 owner_app_wrk_map;
  session_event_t *evt;
  session_t *s;
  application_t *app;

  app = application_lookup (mp->client_index);
  if (!app)
    return;
  if (!(s = session_get_from_handle_if_valid (mp->handle)))
    {
      clib_warning ("invalid handle %llu", mp->handle);
      return;
    }
  app_wrk = app_worker_get (s->app_wrk_index);
  if (app_wrk->app_index != app->app_index)
    {
      clib_warning ("app %u does not own session %llu", app->app_index,
		    mp->handle);
      return;
    }
  owner_app_wrk_map = app_wrk->wrk_map_index;
  app_wrk = application_get_worker (app, mp->wrk_index);

  /* This needs to come from the new owner */
  if (mp->req_wrk_index == owner_app_wrk_map)
    {
      session_req_worker_update_msg_t *wump;

      svm_msg_q_lock_and_alloc_msg_w_ring (app_wrk->event_queue,
					   SESSION_MQ_CTRL_EVT_RING,
					   SVM_Q_WAIT, msg);
      evt = svm_msg_q_msg_data (app_wrk->event_queue, msg);
      clib_memset (evt, 0, sizeof (*evt));
      evt->event_type = SESSION_CTRL_EVT_REQ_WORKER_UPDATE;
      wump = (session_req_worker_update_msg_t *) evt->data;
      wump->session_handle = mp->handle;
      svm_msg_q_add_and_unlock (app_wrk->event_queue, msg);
      return;
    }

  app_worker_own_session (app_wrk, s);

  /*
   * Send reply
   */
  svm_msg_q_lock_and_alloc_msg_w_ring (app_wrk->event_queue,
				       SESSION_MQ_CTRL_EVT_RING,
				       SVM_Q_WAIT, msg);
  evt = svm_msg_q_msg_data (app_wrk->event_queue, msg);
  clib_memset (evt, 0, sizeof (*evt));
  evt->event_type = SESSION_CTRL_EVT_WORKER_UPDATE_REPLY;
  rmp = (session_worker_update_reply_msg_t *) evt->data;
  rmp->handle = mp->handle;
  if (s->rx_fifo)
    rmp->rx_fifo = fifo_segment_fifo_offset (s->rx_fifo);
  if (s->tx_fifo)
    rmp->tx_fifo = fifo_segment_fifo_offset (s->tx_fifo);
  rmp->segment_handle = session_segment_handle (s);
  svm_msg_q_add_and_unlock (app_wrk->event_queue, msg);

  /*
   * Retransmit messages that may have been lost
   */
  if (s->tx_fifo && !svm_fifo_is_empty (s->tx_fifo))
    session_send_io_evt_to_thread (s->tx_fifo, SESSION_IO_EVT_TX);

  if (s->rx_fifo && !svm_fifo_is_empty (s->rx_fifo))
    app_worker_lock_and_send_event (app_wrk, s, SESSION_IO_EVT_RX);

  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    app_worker_close_notify (app_wrk, s);
}

static void
session_mq_app_wrk_rpc_handler (void *data)
{
  session_app_wrk_rpc_msg_t *mp = (session_app_wrk_rpc_msg_t *) data;
  svm_msg_q_msg_t _msg, *msg = &_msg;
  session_app_wrk_rpc_msg_t *rmp;
  app_worker_t *app_wrk;
  session_event_t *evt;
  application_t *app;

  app = application_lookup (mp->client_index);
  if (!app)
    return;

  app_wrk = application_get_worker (app, mp->wrk_index);

  svm_msg_q_lock_and_alloc_msg_w_ring (app_wrk->event_queue,
				       SESSION_MQ_CTRL_EVT_RING, SVM_Q_WAIT,
				       msg);
  evt = svm_msg_q_msg_data (app_wrk->event_queue, msg);
  clib_memset (evt, 0, sizeof (*evt));
  evt->event_type = SESSION_CTRL_EVT_APP_WRK_RPC;
  rmp = (session_app_wrk_rpc_msg_t *) evt->data;
  clib_memcpy (rmp->data, mp->data, sizeof (mp->data));
  svm_msg_q_add_and_unlock (app_wrk->event_queue, msg);
}

static void
session_mq_transport_attr_handler (void *data)
{
  session_transport_attr_msg_t *mp = (session_transport_attr_msg_t *) data;
  session_transport_attr_reply_msg_t *rmp;
  svm_msg_q_msg_t _msg, *msg = &_msg;
  app_worker_t *app_wrk;
  session_event_t *evt;
  application_t *app;
  session_t *s;
  int rv;

  app = application_lookup (mp->client_index);
  if (!app)
    return;

  if (!(s = session_get_from_handle_if_valid (mp->handle)))
    {
      clib_warning ("invalid handle %llu", mp->handle);
      return;
    }
  app_wrk = app_worker_get (s->app_wrk_index);
  if (app_wrk->app_index != app->app_index)
    {
      clib_warning ("app %u does not own session %llu", app->app_index,
		    mp->handle);
      return;
    }

  rv = session_transport_attribute (s, mp->is_get, &mp->attr);

  svm_msg_q_lock_and_alloc_msg_w_ring (
    app_wrk->event_queue, SESSION_MQ_CTRL_EVT_RING, SVM_Q_WAIT, msg);
  evt = svm_msg_q_msg_data (app_wrk->event_queue, msg);
  clib_memset (evt, 0, sizeof (*evt));
  evt->event_type = SESSION_CTRL_EVT_TRANSPORT_ATTR_REPLY;
  rmp = (session_transport_attr_reply_msg_t *) evt->data;
  rmp->handle = mp->handle;
  rmp->retval = rv;
  rmp->is_get = mp->is_get;
  if (!rv && mp->is_get)
    rmp->attr = mp->attr;
  svm_msg_q_add_and_unlock (app_wrk->event_queue, msg);
}

void
session_wrk_handle_evts_main_rpc (void *args)
{
  vlib_main_t *vm = vlib_get_main ();
  clib_llist_index_t ei, next_ei;
  session_evt_elt_t *he, *elt;
  session_worker_t *fwrk;
  u32 thread_index;

  vlib_worker_thread_barrier_sync (vm);

  thread_index = pointer_to_uword (args);
  fwrk = session_main_get_worker (thread_index);

  he = clib_llist_elt (fwrk->event_elts, fwrk->evts_pending_main);
  ei = clib_llist_next_index (he, evt_list);

  while (ei != fwrk->evts_pending_main)
    {
      elt = clib_llist_elt (fwrk->event_elts, ei);
      next_ei = clib_llist_next_index (elt, evt_list);
      clib_llist_remove (fwrk->event_elts, evt_list, elt);
      switch (elt->evt.event_type)
	{
	case SESSION_CTRL_EVT_LISTEN:
	  session_mq_listen_handler (fwrk, elt);
	  break;
	case SESSION_CTRL_EVT_UNLISTEN:
	  session_mq_unlisten_handler (fwrk, elt);
	  break;
	case SESSION_CTRL_EVT_APP_DETACH:
	  app_mq_detach_handler (fwrk, elt);
	  break;
	case SESSION_CTRL_EVT_CONNECT_URI:
	  session_mq_connect_uri_handler (fwrk, elt);
	  break;
	case SESSION_CTRL_EVT_ACCEPTED_REPLY:
	  session_mq_accepted_reply_handler (fwrk, elt);
	  break;
	default:
	  clib_warning ("unhandled %u", elt->evt.event_type);
	  ALWAYS_ASSERT (0);
	  break;
	}

      /* Regrab element in case pool moved */
      elt = clib_llist_elt (fwrk->event_elts, ei);
      session_evt_ctrl_data_free (fwrk, elt);
      clib_llist_put (fwrk->event_elts, elt);
      ei = next_ei;
    }

  vlib_worker_thread_barrier_release (vm);
}

vlib_node_registration_t session_queue_node;

typedef struct
{
  u32 session_index;
  u32 server_thread_index;
} session_queue_trace_t;

/* packet trace format function */
static u8 *
format_session_queue_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  session_queue_trace_t *t = va_arg (*args, session_queue_trace_t *);

  s = format (s, "session index %d thread index %d",
	      t->session_index, t->server_thread_index);
  return s;
}

#define foreach_session_queue_error                                           \
  _ (TX, tx, INFO, "Packets transmitted")                                     \
  _ (TIMER, timer, INFO, "Timer events")                                      \
  _ (NO_BUFFER, no_buffer, ERROR, "Out of buffers")

typedef enum
{
#define _(f, n, s, d) SESSION_QUEUE_ERROR_##f,
  foreach_session_queue_error
#undef _
    SESSION_QUEUE_N_ERROR,
} session_queue_error_t;

static vlib_error_desc_t session_error_counters[] = {
#define _(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
  foreach_session_queue_error
#undef _
};

enum
{
  SESSION_TX_NO_BUFFERS = -2,
  SESSION_TX_NO_DATA,
  SESSION_TX_OK
};

static void
session_tx_trace_frame (vlib_main_t *vm, vlib_node_runtime_t *node,
			u32 next_index, vlib_buffer_t **bufs, u16 n_segs,
			session_t *s, u32 n_trace)
{
  vlib_buffer_t **b = bufs;

  while (n_trace && n_segs)
    {
      if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next_index, b[0],
					   1 /* follow_chain */)))
	{
	  session_queue_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->session_index = s->session_index;
	  t->server_thread_index = s->thread_index;
	  n_trace--;
	}
      b++;
      n_segs--;
    }
  vlib_set_trace_count (vm, node, n_trace);
}

always_inline void
session_tx_fifo_chain_tail (vlib_main_t * vm, session_tx_context_t * ctx,
			    vlib_buffer_t * b, u16 * n_bufs, u8 peek_data)
{
  vlib_buffer_t *chain_b, *prev_b;
  u32 chain_bi0, to_deq, left_from_seg;
  u16 len_to_deq, n_bytes_read;
  u8 *data, j;

  b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  b->total_length_not_including_first_buffer = 0;

  chain_b = b;
  left_from_seg = clib_min (ctx->sp.snd_mss - b->current_length,
			    ctx->left_to_snd);
  to_deq = left_from_seg;
  for (j = 1; j < ctx->n_bufs_per_seg; j++)
    {
      prev_b = chain_b;
      len_to_deq = clib_min (to_deq, ctx->deq_per_buf);

      *n_bufs -= 1;
      chain_bi0 = ctx->tx_buffers[*n_bufs];
      chain_b = vlib_get_buffer (vm, chain_bi0);
      chain_b->current_data = 0;
      data = vlib_buffer_get_current (chain_b);
      if (peek_data)
	{
	  n_bytes_read = svm_fifo_peek (ctx->s->tx_fifo,
					ctx->sp.tx_offset, len_to_deq, data);
	  ctx->sp.tx_offset += n_bytes_read;
	}
      else
	{
	  if (ctx->transport_vft->transport_options.tx_type ==
	      TRANSPORT_TX_DGRAM)
	    {
	      svm_fifo_t *f = ctx->s->tx_fifo;
	      session_dgram_hdr_t *hdr = &ctx->hdr;
	      u16 deq_now;
	      u32 offset;

	      deq_now = clib_min (hdr->data_length - hdr->data_offset,
				  len_to_deq);
	      offset = hdr->data_offset + SESSION_CONN_HDR_LEN;
	      n_bytes_read = svm_fifo_peek (f, offset, deq_now, data);
	      ASSERT (n_bytes_read > 0);

	      hdr->data_offset += n_bytes_read;
	      if (hdr->data_offset == hdr->data_length)
		{
		  offset = hdr->data_length + SESSION_CONN_HDR_LEN;
		  svm_fifo_dequeue_drop (f, offset);
		  if (ctx->left_to_snd > n_bytes_read)
		    svm_fifo_peek (ctx->s->tx_fifo, 0, sizeof (ctx->hdr),
				   (u8 *) & ctx->hdr);
		}
	      else if (ctx->left_to_snd == n_bytes_read)
		svm_fifo_overwrite_head (ctx->s->tx_fifo, (u8 *) & ctx->hdr,
					 sizeof (session_dgram_pre_hdr_t));
	    }
	  else
	    n_bytes_read = svm_fifo_dequeue (ctx->s->tx_fifo,
					     len_to_deq, data);
	}
      ASSERT (n_bytes_read == len_to_deq);
      chain_b->current_length = n_bytes_read;
      b->total_length_not_including_first_buffer += chain_b->current_length;

      /* update previous buffer */
      prev_b->next_buffer = chain_bi0;
      prev_b->flags |= VLIB_BUFFER_NEXT_PRESENT;

      /* update current buffer */
      chain_b->next_buffer = 0;

      to_deq -= n_bytes_read;
      if (to_deq == 0)
	break;
    }
  ASSERT (to_deq == 0
	  && b->total_length_not_including_first_buffer == left_from_seg);
  ctx->left_to_snd -= left_from_seg;
}

always_inline void
session_tx_fill_buffer (vlib_main_t * vm, session_tx_context_t * ctx,
			vlib_buffer_t * b, u16 * n_bufs, u8 peek_data)
{
  u32 len_to_deq;
  u8 *data0;
  int n_bytes_read;

  /*
   * Start with the first buffer in chain
   */
  b->error = 0;
  b->flags = VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->current_data = 0;

  data0 = vlib_buffer_make_headroom (b, TRANSPORT_MAX_HDRS_LEN);
  len_to_deq = clib_min (ctx->left_to_snd, ctx->deq_per_first_buf);

  if (peek_data)
    {
      n_bytes_read = svm_fifo_peek (ctx->s->tx_fifo, ctx->sp.tx_offset,
				    len_to_deq, data0);
      ASSERT (n_bytes_read > 0);
      /* Keep track of progress locally, transport is also supposed to
       * increment it independently when pushing the header */
      ctx->sp.tx_offset += n_bytes_read;
    }
  else
    {
      if (ctx->transport_vft->transport_options.tx_type == TRANSPORT_TX_DGRAM)
	{
	  session_dgram_hdr_t *hdr = &ctx->hdr;
	  svm_fifo_t *f = ctx->s->tx_fifo;
	  u16 deq_now;
	  u32 offset;

	  ASSERT (hdr->data_length > hdr->data_offset);
	  deq_now = clib_min (hdr->data_length - hdr->data_offset,
			      len_to_deq);
	  offset = hdr->data_offset + SESSION_CONN_HDR_LEN;
	  n_bytes_read = svm_fifo_peek (f, offset, deq_now, data0);
	  ASSERT (n_bytes_read > 0);

	  if (transport_connection_is_cless (ctx->tc))
	    {
	      ip_copy (&ctx->tc->rmt_ip, &hdr->rmt_ip, ctx->tc->is_ip4);
	      ctx->tc->rmt_port = hdr->rmt_port;
	    }
	  hdr->data_offset += n_bytes_read;
	  if (hdr->data_offset == hdr->data_length)
	    {
	      offset = hdr->data_length + SESSION_CONN_HDR_LEN;
	      svm_fifo_dequeue_drop (f, offset);
	      if (ctx->left_to_snd > n_bytes_read)
		svm_fifo_peek (ctx->s->tx_fifo, 0, sizeof (ctx->hdr),
			       (u8 *) & ctx->hdr);
	    }
	  else if (ctx->left_to_snd == n_bytes_read)
	    svm_fifo_overwrite_head (ctx->s->tx_fifo, (u8 *) & ctx->hdr,
				     sizeof (session_dgram_pre_hdr_t));
	}
      else
	{
	  n_bytes_read = svm_fifo_dequeue (ctx->s->tx_fifo,
					   len_to_deq, data0);
	  ASSERT (n_bytes_read > 0);
	}
    }
  b->current_length = n_bytes_read;
  ctx->left_to_snd -= n_bytes_read;

  /*
   * Fill in the remaining buffers in the chain, if any
   */
  if (PREDICT_FALSE (ctx->n_bufs_per_seg > 1 && ctx->left_to_snd))
    session_tx_fifo_chain_tail (vm, ctx, b, n_bufs, peek_data);
}

always_inline u8
session_tx_not_ready (session_t * s, u8 peek_data)
{
  if (peek_data)
    {
      if (PREDICT_TRUE (s->session_state == SESSION_STATE_READY))
	return 0;
      /* Can retransmit for closed sessions but can't send new data if
       * session is not ready or closed */
      else if (s->session_state < SESSION_STATE_READY)
	{
	  /* Allow accepting session to send custom packets.
	   * For instance, tcp want to send acks in established, but
	   * the app has not called accept() yet */
	  if (s->session_state == SESSION_STATE_ACCEPTING &&
	      (s->flags & SESSION_F_CUSTOM_TX))
	    return 0;
	  return 1;
	}
      else if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSED)
	{
	  /* Allow closed transports to still send custom packets.
	   * For instance, tcp may want to send acks in time-wait. */
	  if (s->session_state != SESSION_STATE_TRANSPORT_DELETED
	      && (s->flags & SESSION_F_CUSTOM_TX))
	    return 0;
	  return 2;
	}
    }
  return 0;
}

always_inline transport_connection_t *
session_tx_get_transport (session_tx_context_t * ctx, u8 peek_data)
{
  if (peek_data)
    {
      return ctx->transport_vft->get_connection (ctx->s->connection_index,
						 ctx->s->thread_index);
    }
  else
    {
      if (ctx->s->session_state == SESSION_STATE_LISTENING)
	return ctx->transport_vft->get_listener (ctx->s->connection_index);
      else
	{
	  return ctx->transport_vft->get_connection (ctx->s->connection_index,
						     ctx->s->thread_index);
	}
    }
}

always_inline void
session_tx_set_dequeue_params (vlib_main_t * vm, session_tx_context_t * ctx,
			       u32 max_segs, u8 peek_data)
{
  u32 n_bytes_per_buf, n_bytes_per_seg;

  n_bytes_per_buf = vlib_buffer_get_default_data_size (vm);
  ctx->max_dequeue = svm_fifo_max_dequeue_cons (ctx->s->tx_fifo);

  if (peek_data)
    {
      /* Offset in rx fifo from where to peek data */
      if (PREDICT_FALSE (ctx->sp.tx_offset >= ctx->max_dequeue))
	{
	  ctx->max_len_to_snd = 0;
	  return;
	}
      ctx->max_dequeue -= ctx->sp.tx_offset;
    }
  else
    {
      if (ctx->transport_vft->transport_options.tx_type == TRANSPORT_TX_DGRAM)
	{
	  u32 len, chain_limit;

	  if (ctx->max_dequeue <= sizeof (ctx->hdr))
	    {
	      ctx->max_len_to_snd = 0;
	      return;
	    }

	  svm_fifo_peek (ctx->s->tx_fifo, 0, sizeof (ctx->hdr),
			 (u8 *) & ctx->hdr);
	  ASSERT (ctx->hdr.data_length > ctx->hdr.data_offset);
	  len = ctx->hdr.data_length - ctx->hdr.data_offset;

	  /* Process multiple dgrams if smaller than min (buf_space, mss).
	   * This avoids handling multiple dgrams if they require buffer
	   * chains */
	  chain_limit = clib_min (n_bytes_per_buf - TRANSPORT_MAX_HDRS_LEN,
				  ctx->sp.snd_mss);
	  if (ctx->hdr.data_length <= chain_limit)
	    {
	      u32 first_dgram_len, dgram_len, offset, max_offset;
	      session_dgram_hdr_t hdr;

	      ctx->sp.snd_mss = clib_min (ctx->sp.snd_mss, len);
	      offset = ctx->hdr.data_length + sizeof (session_dgram_hdr_t);
	      first_dgram_len = len;
	      max_offset = clib_min (ctx->max_dequeue, 16 << 10);

	      while (offset < max_offset)
		{
		  svm_fifo_peek (ctx->s->tx_fifo, offset, sizeof (ctx->hdr),
				 (u8 *) & hdr);
		  ASSERT (hdr.data_length > hdr.data_offset);
		  dgram_len = hdr.data_length - hdr.data_offset;
		  if (len + dgram_len > ctx->max_dequeue
		      || first_dgram_len != dgram_len)
		    break;
		  len += dgram_len;
		  offset += sizeof (hdr) + hdr.data_length;
		}
	    }

	  ctx->max_dequeue = len;
	}
    }
  ASSERT (ctx->max_dequeue > 0);

  /* Ensure we're not writing more than transport window allows */
  if (ctx->max_dequeue < ctx->sp.snd_space)
    {
      /* Constrained by tx queue. Try to send only fully formed segments */
      ctx->max_len_to_snd = (ctx->max_dequeue > ctx->sp.snd_mss) ?
	(ctx->max_dequeue - (ctx->max_dequeue % ctx->sp.snd_mss)) :
	ctx->max_dequeue;
      /* TODO Nagle ? */
    }
  else
    {
      /* Expectation is that snd_space0 is already a multiple of snd_mss */
      ctx->max_len_to_snd = ctx->sp.snd_space;
    }

  /* Check if we're tx constrained by the node */
  ctx->n_segs_per_evt = ceil ((f64) ctx->max_len_to_snd / ctx->sp.snd_mss);
  if (ctx->n_segs_per_evt > max_segs)
    {
      ctx->n_segs_per_evt = max_segs;
      ctx->max_len_to_snd = max_segs * ctx->sp.snd_mss;
    }

  ASSERT (n_bytes_per_buf > TRANSPORT_MAX_HDRS_LEN);
  if (ctx->n_segs_per_evt > 1)
    {
      u32 n_bytes_last_seg, n_bufs_last_seg;

      n_bytes_per_seg = TRANSPORT_MAX_HDRS_LEN + ctx->sp.snd_mss;
      n_bytes_last_seg = TRANSPORT_MAX_HDRS_LEN + ctx->max_len_to_snd
	- ((ctx->n_segs_per_evt - 1) * ctx->sp.snd_mss);
      ctx->n_bufs_per_seg = ceil ((f64) n_bytes_per_seg / n_bytes_per_buf);
      n_bufs_last_seg = ceil ((f64) n_bytes_last_seg / n_bytes_per_buf);
      ctx->n_bufs_needed = ((ctx->n_segs_per_evt - 1) * ctx->n_bufs_per_seg)
	+ n_bufs_last_seg;
    }
  else
    {
      n_bytes_per_seg = TRANSPORT_MAX_HDRS_LEN + ctx->max_len_to_snd;
      ctx->n_bufs_per_seg = ceil ((f64) n_bytes_per_seg / n_bytes_per_buf);
      ctx->n_bufs_needed = ctx->n_bufs_per_seg;
    }

  ctx->deq_per_buf = clib_min (ctx->sp.snd_mss, n_bytes_per_buf);
  ctx->deq_per_first_buf = clib_min (ctx->sp.snd_mss,
				     n_bytes_per_buf -
				     TRANSPORT_MAX_HDRS_LEN);
}

always_inline void
session_tx_maybe_reschedule (session_worker_t * wrk,
			     session_tx_context_t * ctx,
			     session_evt_elt_t * elt)
{
  session_t *s = ctx->s;

  svm_fifo_unset_event (s->tx_fifo);
  if (svm_fifo_max_dequeue_cons (s->tx_fifo) > ctx->sp.tx_offset)
    {
      if (svm_fifo_set_event (s->tx_fifo))
	session_evt_add_head_old (wrk, elt);
    }
  else
    {
      transport_connection_deschedule (ctx->tc);
    }
}

always_inline int
session_tx_fifo_read_and_snd_i (session_worker_t * wrk,
				vlib_node_runtime_t * node,
				session_evt_elt_t * elt,
				int *n_tx_packets, u8 peek_data)
{
  u32 n_trace, n_left, pbi, next_index, max_burst;
  session_tx_context_t *ctx = &wrk->ctx;
  session_main_t *smm = &session_main;
  session_event_t *e = &elt->evt;
  vlib_main_t *vm = wrk->vm;
  transport_proto_t tp;
  vlib_buffer_t *pb;
  u16 n_bufs, rv;

  if (PREDICT_FALSE ((rv = session_tx_not_ready (ctx->s, peek_data))))
    {
      if (rv < 2)
	session_evt_add_old (wrk, elt);
      return SESSION_TX_NO_DATA;
    }

  next_index = smm->session_type_to_next[ctx->s->session_type];
  max_burst = SESSION_NODE_FRAME_SIZE - *n_tx_packets;

  tp = session_get_transport_proto (ctx->s);
  ctx->transport_vft = transport_protocol_get_vft (tp);
  ctx->tc = session_tx_get_transport (ctx, peek_data);

  if (PREDICT_FALSE (e->event_type == SESSION_IO_EVT_TX_FLUSH))
    {
      if (ctx->transport_vft->flush_data)
	ctx->transport_vft->flush_data (ctx->tc);
      e->event_type = SESSION_IO_EVT_TX;
    }

  if (ctx->s->flags & SESSION_F_CUSTOM_TX)
    {
      u32 n_custom_tx;
      ctx->s->flags &= ~SESSION_F_CUSTOM_TX;
      ctx->sp.max_burst_size = max_burst;
      n_custom_tx = ctx->transport_vft->custom_tx (ctx->tc, &ctx->sp);
      *n_tx_packets += n_custom_tx;
      if (PREDICT_FALSE
	  (ctx->s->session_state >= SESSION_STATE_TRANSPORT_CLOSED))
	return SESSION_TX_OK;
      max_burst -= n_custom_tx;
      if (!max_burst || (ctx->s->flags & SESSION_F_CUSTOM_TX))
	{
	  session_evt_add_old (wrk, elt);
	  return SESSION_TX_OK;
	}
    }

  /* Connection previously descheduled because it had no data to send.
   * Clear descheduled flag and reset pacer if in use */
  if (transport_connection_is_descheduled (ctx->tc))
    transport_connection_clear_descheduled (ctx->tc);

  transport_connection_snd_params (ctx->tc, &ctx->sp);

  if (!ctx->sp.snd_space)
    {
      /* If the deschedule flag was set, remove session from scheduler.
       * Transport is responsible for rescheduling this session. */
      if (ctx->sp.flags & TRANSPORT_SND_F_DESCHED)
	transport_connection_deschedule (ctx->tc);
      /* Request to postpone the session, e.g., zero-wnd and transport
       * is not currently probing */
      else if (ctx->sp.flags & TRANSPORT_SND_F_POSTPONE)
	session_evt_add_old (wrk, elt);
      /* This flow queue is "empty" so it should be re-evaluated before
       * the ones that have data to send. */
      else
	session_evt_add_head_old (wrk, elt);

      return SESSION_TX_NO_DATA;
    }

  if (transport_connection_is_tx_paced (ctx->tc))
    {
      u32 snd_space = transport_connection_tx_pacer_burst (ctx->tc);
      if (snd_space < TRANSPORT_PACER_MIN_BURST)
	{
	  session_evt_add_head_old (wrk, elt);
	  return SESSION_TX_NO_DATA;
	}
      snd_space = clib_min (ctx->sp.snd_space, snd_space);
      ctx->sp.snd_space = snd_space >= ctx->sp.snd_mss ?
	snd_space - snd_space % ctx->sp.snd_mss : snd_space;
    }

  /* Check how much we can pull. */
  session_tx_set_dequeue_params (vm, ctx, max_burst, peek_data);

  if (PREDICT_FALSE (!ctx->max_len_to_snd))
    {
      transport_connection_tx_pacer_reset_bucket (ctx->tc, 0);
      session_tx_maybe_reschedule (wrk, ctx, elt);
      return SESSION_TX_NO_DATA;
    }

  vec_validate_aligned (ctx->tx_buffers, ctx->n_bufs_needed - 1,
			CLIB_CACHE_LINE_BYTES);
  n_bufs = vlib_buffer_alloc (vm, ctx->tx_buffers, ctx->n_bufs_needed);
  if (PREDICT_FALSE (n_bufs < ctx->n_bufs_needed))
    {
      if (n_bufs)
	vlib_buffer_free (vm, ctx->tx_buffers, n_bufs);
      session_evt_add_head_old (wrk, elt);
      vlib_node_increment_counter (wrk->vm, node->node_index,
				   SESSION_QUEUE_ERROR_NO_BUFFER, 1);
      return SESSION_TX_NO_BUFFERS;
    }

  if (transport_connection_is_tx_paced (ctx->tc))
    transport_connection_tx_pacer_update_bytes (ctx->tc, ctx->max_len_to_snd);

  ctx->left_to_snd = ctx->max_len_to_snd;
  n_left = ctx->n_segs_per_evt;

  vec_validate (ctx->transport_pending_bufs, n_left);

  while (n_left >= 4)
    {
      vlib_buffer_t *b0, *b1;
      u32 bi0, bi1;

      pbi = ctx->tx_buffers[n_bufs - 3];
      pb = vlib_get_buffer (vm, pbi);
      vlib_prefetch_buffer_header (pb, STORE);
      pbi = ctx->tx_buffers[n_bufs - 4];
      pb = vlib_get_buffer (vm, pbi);
      vlib_prefetch_buffer_header (pb, STORE);

      bi0 = ctx->tx_buffers[--n_bufs];
      bi1 = ctx->tx_buffers[--n_bufs];

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      session_tx_fill_buffer (vm, ctx, b0, &n_bufs, peek_data);
      session_tx_fill_buffer (vm, ctx, b1, &n_bufs, peek_data);

      ctx->transport_pending_bufs[ctx->n_segs_per_evt - n_left] = b0;
      ctx->transport_pending_bufs[ctx->n_segs_per_evt - n_left + 1] = b1;
      n_left -= 2;

      vec_add1 (wrk->pending_tx_buffers, bi0);
      vec_add1 (wrk->pending_tx_buffers, bi1);
      vec_add1 (wrk->pending_tx_nexts, next_index);
      vec_add1 (wrk->pending_tx_nexts, next_index);
    }
  while (n_left)
    {
      vlib_buffer_t *b0;
      u32 bi0;

      if (n_left > 1)
	{
	  pbi = ctx->tx_buffers[n_bufs - 2];
	  pb = vlib_get_buffer (vm, pbi);
	  vlib_prefetch_buffer_header (pb, STORE);
	}

      bi0 = ctx->tx_buffers[--n_bufs];
      b0 = vlib_get_buffer (vm, bi0);
      session_tx_fill_buffer (vm, ctx, b0, &n_bufs, peek_data);

      ctx->transport_pending_bufs[ctx->n_segs_per_evt - n_left] = b0;
      n_left -= 1;

      vec_add1 (wrk->pending_tx_buffers, bi0);
      vec_add1 (wrk->pending_tx_nexts, next_index);
    }

  /* Ask transport to push headers */
  ctx->transport_vft->push_header (ctx->tc, ctx->transport_pending_bufs,
				   ctx->n_segs_per_evt);

  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node)) > 0))
    session_tx_trace_frame (vm, node, next_index, ctx->transport_pending_bufs,
			    ctx->n_segs_per_evt, ctx->s, n_trace);

  if (PREDICT_FALSE (n_bufs))
    vlib_buffer_free (vm, ctx->tx_buffers, n_bufs);

  *n_tx_packets += ctx->n_segs_per_evt;

  SESSION_EVT (SESSION_EVT_DEQ, ctx->s, ctx->max_len_to_snd, ctx->max_dequeue,
	       ctx->s->tx_fifo->has_event, wrk->last_vlib_time);

  ASSERT (ctx->left_to_snd == 0);

  /* If we couldn't dequeue all bytes reschedule as old flow. Otherwise,
   * check if application enqueued more data and reschedule accordingly */
  if (ctx->max_len_to_snd < ctx->max_dequeue)
    session_evt_add_old (wrk, elt);
  else
    session_tx_maybe_reschedule (wrk, ctx, elt);

  if (!peek_data)
    {
      u32 n_dequeued = ctx->max_len_to_snd;
      if (ctx->transport_vft->transport_options.tx_type == TRANSPORT_TX_DGRAM)
	n_dequeued += ctx->n_segs_per_evt * SESSION_CONN_HDR_LEN;
      if (svm_fifo_needs_deq_ntf (ctx->s->tx_fifo, n_dequeued))
	session_dequeue_notify (ctx->s);
    }
  return SESSION_TX_OK;
}

int
session_tx_fifo_peek_and_snd (session_worker_t * wrk,
			      vlib_node_runtime_t * node,
			      session_evt_elt_t * e, int *n_tx_packets)
{
  return session_tx_fifo_read_and_snd_i (wrk, node, e, n_tx_packets, 1);
}

int
session_tx_fifo_dequeue_and_snd (session_worker_t * wrk,
				 vlib_node_runtime_t * node,
				 session_evt_elt_t * e, int *n_tx_packets)
{
  return session_tx_fifo_read_and_snd_i (wrk, node, e, n_tx_packets, 0);
}

int
session_tx_fifo_dequeue_internal (session_worker_t * wrk,
				  vlib_node_runtime_t * node,
				  session_evt_elt_t * elt, int *n_tx_packets)
{
  transport_send_params_t *sp = &wrk->ctx.sp;
  session_t *s = wrk->ctx.s;
  u32 n_packets;

  if (PREDICT_FALSE (s->session_state >= SESSION_STATE_TRANSPORT_CLOSED))
    return 0;

  /* Clear custom-tx flag used to request reschedule for tx */
  s->flags &= ~SESSION_F_CUSTOM_TX;

  sp->flags = 0;
  sp->bytes_dequeued = 0;
  sp->max_burst_size = clib_min (SESSION_NODE_FRAME_SIZE - *n_tx_packets,
				 TRANSPORT_PACER_MAX_BURST_PKTS);

  n_packets = transport_custom_tx (session_get_transport_proto (s), s, sp);
  *n_tx_packets += n_packets;

  if (s->flags & SESSION_F_CUSTOM_TX)
    {
      session_evt_add_old (wrk, elt);
    }
  else if (!(sp->flags & TRANSPORT_SND_F_DESCHED))
    {
      svm_fifo_unset_event (s->tx_fifo);
      if (svm_fifo_max_dequeue_cons (s->tx_fifo))
	if (svm_fifo_set_event (s->tx_fifo))
	  session_evt_add_head_old (wrk, elt);
    }

  if (sp->bytes_dequeued &&
      svm_fifo_needs_deq_ntf (s->tx_fifo, sp->bytes_dequeued))
    session_dequeue_notify (s);

  return n_packets;
}

always_inline session_t *
session_event_get_session (session_worker_t * wrk, session_event_t * e)
{
  if (PREDICT_FALSE (pool_is_free_index (wrk->sessions, e->session_index)))
    return 0;

  ASSERT (session_is_valid (e->session_index, wrk->vm->thread_index));
  return pool_elt_at_index (wrk->sessions, e->session_index);
}

always_inline void
session_event_dispatch_ctrl (session_worker_t * wrk, session_evt_elt_t * elt)
{
  clib_llist_index_t ei;
  void (*fp) (void *);
  session_event_t *e;
  session_t *s;

  ei = clib_llist_entry_index (wrk->event_elts, elt);
  e = &elt->evt;

  switch (e->event_type)
    {
    case SESSION_CTRL_EVT_RPC:
      fp = e->rpc_args.fp;
      (*fp) (e->rpc_args.arg);
      break;
    case SESSION_CTRL_EVT_HALF_CLOSE:
      s = session_get_from_handle_if_valid (e->session_handle);
      if (PREDICT_FALSE (!s))
	break;
      session_transport_half_close (s);
      break;
    case SESSION_CTRL_EVT_CLOSE:
      s = session_get_from_handle_if_valid (e->session_handle);
      if (PREDICT_FALSE (!s))
	break;
      session_transport_close (s);
      break;
    case SESSION_CTRL_EVT_RESET:
      s = session_get_from_handle_if_valid (e->session_handle);
      if (PREDICT_FALSE (!s))
	break;
      session_transport_reset (s);
      break;
    case SESSION_CTRL_EVT_LISTEN:
      session_mq_listen_handler (wrk, elt);
      break;
    case SESSION_CTRL_EVT_LISTEN_URI:
      session_mq_listen_uri_handler (wrk, elt);
      break;
    case SESSION_CTRL_EVT_UNLISTEN:
      session_mq_unlisten_handler (wrk, elt);
      break;
    case SESSION_CTRL_EVT_CONNECT:
      session_mq_connect_handler (wrk, elt);
      break;
    case SESSION_CTRL_EVT_CONNECT_URI:
      session_mq_connect_uri_handler (wrk, elt);
      break;
    case SESSION_CTRL_EVT_SHUTDOWN:
      session_mq_shutdown_handler (session_evt_ctrl_data (wrk, elt));
      break;
    case SESSION_CTRL_EVT_DISCONNECT:
      session_mq_disconnect_handler (session_evt_ctrl_data (wrk, elt));
      break;
    case SESSION_CTRL_EVT_DISCONNECTED:
      session_mq_disconnected_handler (session_evt_ctrl_data (wrk, elt));
      break;
    case SESSION_CTRL_EVT_ACCEPTED_REPLY:
      session_mq_accepted_reply_handler (wrk, elt);
      break;
    case SESSION_CTRL_EVT_DISCONNECTED_REPLY:
      session_mq_disconnected_reply_handler (session_evt_ctrl_data (wrk,
								    elt));
      break;
    case SESSION_CTRL_EVT_RESET_REPLY:
      session_mq_reset_reply_handler (session_evt_ctrl_data (wrk, elt));
      break;
    case SESSION_CTRL_EVT_WORKER_UPDATE:
      session_mq_worker_update_handler (session_evt_ctrl_data (wrk, elt));
      break;
    case SESSION_CTRL_EVT_APP_DETACH:
      app_mq_detach_handler (wrk, elt);
      break;
    case SESSION_CTRL_EVT_APP_WRK_RPC:
      session_mq_app_wrk_rpc_handler (session_evt_ctrl_data (wrk, elt));
      break;
    case SESSION_CTRL_EVT_TRANSPORT_ATTR:
      session_mq_transport_attr_handler (session_evt_ctrl_data (wrk, elt));
      break;
    default:
      clib_warning ("unhandled event type %d", e->event_type);
    }

  /* Regrab elements in case pool moved */
  elt = clib_llist_elt (wrk->event_elts, ei);
  if (!clib_llist_elt_is_linked (elt, evt_list))
    {
      e = &elt->evt;
      if (e->event_type >= SESSION_CTRL_EVT_BOUND)
	session_evt_ctrl_data_free (wrk, elt);
      clib_llist_put (wrk->event_elts, elt);
    }
  SESSION_EVT (SESSION_EVT_COUNTS, CNT_CTRL_EVTS, 1, wrk);
}

always_inline void
session_event_dispatch_io (session_worker_t * wrk, vlib_node_runtime_t * node,
			   session_evt_elt_t * elt, int *n_tx_packets)
{
  session_main_t *smm = &session_main;
  app_worker_t *app_wrk;
  clib_llist_index_t ei;
  session_event_t *e;
  session_t *s;

  ei = clib_llist_entry_index (wrk->event_elts, elt);
  e = &elt->evt;

  switch (e->event_type)
    {
    case SESSION_IO_EVT_TX_FLUSH:
    case SESSION_IO_EVT_TX:
      s = session_event_get_session (wrk, e);
      if (PREDICT_FALSE (!s))
	break;
      CLIB_PREFETCH (s->tx_fifo, sizeof (*(s->tx_fifo)), LOAD);
      wrk->ctx.s = s;
      /* Spray packets in per session type frames, since they go to
       * different nodes */
      (smm->session_tx_fns[s->session_type]) (wrk, node, elt, n_tx_packets);
      break;
    case SESSION_IO_EVT_RX:
      s = session_event_get_session (wrk, e);
      if (!s)
	break;
      transport_app_rx_evt (session_get_transport_proto (s),
			    s->connection_index, s->thread_index);
      break;
    case SESSION_IO_EVT_BUILTIN_RX:
      s = session_event_get_session (wrk, e);
      if (PREDICT_FALSE (!s || s->session_state >= SESSION_STATE_CLOSING))
	break;
      svm_fifo_unset_event (s->rx_fifo);
      app_wrk = app_worker_get (s->app_wrk_index);
      app_worker_builtin_rx (app_wrk, s);
      break;
    case SESSION_IO_EVT_BUILTIN_TX:
      s = session_get_from_handle_if_valid (e->session_handle);
      wrk->ctx.s = s;
      if (PREDICT_TRUE (s != 0))
	session_tx_fifo_dequeue_internal (wrk, node, elt, n_tx_packets);
      break;
    default:
      clib_warning ("unhandled event type %d", e->event_type);
    }

  SESSION_EVT (SESSION_IO_EVT_COUNTS, e->event_type, 1, wrk);

  /* Regrab elements in case pool moved */
  elt = clib_llist_elt (wrk->event_elts, ei);
  if (!clib_llist_elt_is_linked (elt, evt_list))
    clib_llist_put (wrk->event_elts, elt);
}

/* *INDENT-OFF* */
static const u32 session_evt_msg_sizes[] = {
#define _(symc, sym) 							\
  [SESSION_CTRL_EVT_ ## symc] = sizeof (session_ ## sym ##_msg_t),
  foreach_session_ctrl_evt
#undef _
};
/* *INDENT-ON* */

always_inline void
session_update_time_subscribers (session_main_t *smm, clib_time_type_t now,
				 u32 thread_index)
{
  session_update_time_fn *fn;

  vec_foreach (fn, smm->update_time_fns)
    (*fn) (now, thread_index);
}

always_inline void
session_evt_add_to_list (session_worker_t * wrk, session_event_t * evt)
{
  session_evt_elt_t *elt;

  if (evt->event_type >= SESSION_CTRL_EVT_RPC)
    {
      elt = session_evt_alloc_ctrl (wrk);
      if (evt->event_type >= SESSION_CTRL_EVT_BOUND)
	{
	  elt->evt.ctrl_data_index = session_evt_ctrl_data_alloc (wrk);
	  elt->evt.event_type = evt->event_type;
	  clib_memcpy_fast (session_evt_ctrl_data (wrk, elt), evt->data,
			    session_evt_msg_sizes[evt->event_type]);
	}
      else
	{
	  /* Internal control events fit into io events footprint */
	  clib_memcpy_fast (&elt->evt, evt, sizeof (elt->evt));
	}
    }
  else
    {
      elt = session_evt_alloc_new (wrk);
      clib_memcpy_fast (&elt->evt, evt, sizeof (elt->evt));
    }
}

static void
session_flush_pending_tx_buffers (session_worker_t * wrk,
				  vlib_node_runtime_t * node)
{
  vlib_buffer_enqueue_to_next_vec (wrk->vm, node, &wrk->pending_tx_buffers,
				   &wrk->pending_tx_nexts,
				   vec_len (wrk->pending_tx_nexts));
  vec_reset_length (wrk->pending_tx_buffers);
  vec_reset_length (wrk->pending_tx_nexts);
}

int
session_wrk_handle_mq (session_worker_t *wrk, svm_msg_q_t *mq)
{
  svm_msg_q_msg_t _msg, *msg = &_msg;
  u32 i, n_to_dequeue = 0;
  session_event_t *evt;

  n_to_dequeue = svm_msg_q_size (mq);
  for (i = 0; i < n_to_dequeue; i++)
    {
      svm_msg_q_sub_raw (mq, msg);
      evt = svm_msg_q_msg_data (mq, msg);
      session_evt_add_to_list (wrk, evt);
      svm_msg_q_free_msg (mq, msg);
    }

  return n_to_dequeue;
}

static void
session_wrk_update_state (session_worker_t *wrk)
{
  vlib_main_t *vm = wrk->vm;

  if (wrk->state == SESSION_WRK_POLLING)
    {
      if (clib_llist_elts (wrk->event_elts) == 4 &&
	  vlib_last_vectors_per_main_loop (vm) < 1)
	{
	  session_wrk_set_state (wrk, SESSION_WRK_INTERRUPT);
	  vlib_node_set_state (vm, session_queue_node.index,
			       VLIB_NODE_STATE_INTERRUPT);
	}
    }
  else if (wrk->state == SESSION_WRK_INTERRUPT)
    {
      if (clib_llist_elts (wrk->event_elts) > 4 ||
	  vlib_last_vectors_per_main_loop (vm) > 1)
	{
	  session_wrk_set_state (wrk, SESSION_WRK_POLLING);
	  vlib_node_set_state (vm, session_queue_node.index,
			       VLIB_NODE_STATE_POLLING);
	}
      else if (PREDICT_FALSE (!pool_elts (wrk->sessions)))
	{
	  session_wrk_set_state (wrk, SESSION_WRK_IDLE);
	}
    }
  else
    {
      if (clib_llist_elts (wrk->event_elts))
	{
	  session_wrk_set_state (wrk, SESSION_WRK_INTERRUPT);
	}
    }
}

static uword
session_queue_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  u32 thread_index = vm->thread_index, __clib_unused n_evts;
  session_evt_elt_t *elt, *ctrl_he, *new_he, *old_he;
  session_main_t *smm = vnet_get_session_main ();
  session_worker_t *wrk = &smm->wrk[thread_index];
  clib_llist_index_t ei, next_ei, old_ti;
  int n_tx_packets;

  SESSION_EVT (SESSION_EVT_DISPATCH_START, wrk);

  session_wrk_update_time (wrk, vlib_time_now (vm));

  /*
   *  Update transport time
   */
  session_update_time_subscribers (smm, wrk->last_vlib_time, thread_index);
  n_tx_packets = vec_len (wrk->pending_tx_buffers);
  SESSION_EVT (SESSION_EVT_DSP_CNTRS, UPDATE_TIME, wrk);

  /*
   *  Dequeue new internal mq events
   */

  n_evts = session_wrk_handle_mq (wrk, wrk->vpp_event_queue);
  SESSION_EVT (SESSION_EVT_DSP_CNTRS, MQ_DEQ, wrk, n_evts);

  /*
   * Handle control events
   */

  ei = wrk->ctrl_head;
  ctrl_he = clib_llist_elt (wrk->event_elts, ei);
  next_ei = clib_llist_next_index (ctrl_he, evt_list);
  old_ti = clib_llist_prev_index (ctrl_he, evt_list);
  while (ei != old_ti)
    {
      ei = next_ei;
      elt = clib_llist_elt (wrk->event_elts, next_ei);
      next_ei = clib_llist_next_index (elt, evt_list);
      clib_llist_remove (wrk->event_elts, evt_list, elt);
      session_event_dispatch_ctrl (wrk, elt);
    }

  SESSION_EVT (SESSION_EVT_DSP_CNTRS, CTRL_EVTS, wrk);

  /*
   * Handle the new io events.
   */

  new_he = clib_llist_elt (wrk->event_elts, wrk->new_head);
  old_he = clib_llist_elt (wrk->event_elts, wrk->old_head);
  old_ti = clib_llist_prev_index (old_he, evt_list);

  ei = clib_llist_next_index (new_he, evt_list);
  while (ei != wrk->new_head && n_tx_packets < SESSION_NODE_FRAME_SIZE)
    {
      elt = clib_llist_elt (wrk->event_elts, ei);
      ei = clib_llist_next_index (elt, evt_list);
      clib_llist_remove (wrk->event_elts, evt_list, elt);
      session_event_dispatch_io (wrk, node, elt, &n_tx_packets);
    }

  SESSION_EVT (SESSION_EVT_DSP_CNTRS, NEW_IO_EVTS, wrk);

  /*
   * Handle the old io events, if we had any prior to processing the new ones
   */

  if (old_ti != wrk->old_head)
    {
      old_he = clib_llist_elt (wrk->event_elts, wrk->old_head);
      ei = clib_llist_next_index (old_he, evt_list);

      while (n_tx_packets < SESSION_NODE_FRAME_SIZE)
	{
	  elt = clib_llist_elt (wrk->event_elts, ei);
	  next_ei = clib_llist_next_index (elt, evt_list);
	  clib_llist_remove (wrk->event_elts, evt_list, elt);

	  session_event_dispatch_io (wrk, node, elt, &n_tx_packets);

	  if (ei == old_ti)
	    break;

	  ei = next_ei;
	};
    }

  SESSION_EVT (SESSION_EVT_DSP_CNTRS, OLD_IO_EVTS, wrk);

  if (vec_len (wrk->pending_tx_buffers))
    session_flush_pending_tx_buffers (wrk, node);

  vlib_node_increment_counter (vm, session_queue_node.index,
			       SESSION_QUEUE_ERROR_TX, n_tx_packets);

  SESSION_EVT (SESSION_EVT_DISPATCH_END, wrk, n_tx_packets);

  if (wrk->flags & SESSION_WRK_F_ADAPTIVE)
    session_wrk_update_state (wrk);

  return n_tx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (session_queue_node) = {
  .function = session_queue_node_fn,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .name = "session-queue",
  .format_trace = format_session_queue_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .n_errors = SESSION_QUEUE_N_ERROR,
  .error_counters = session_error_counters,
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */

static clib_error_t *
session_wrk_tfd_read_ready (clib_file_t *cf)
{
  session_worker_t *wrk = session_main_get_worker (cf->private_data);
  u64 buf;
  int rv;

  vlib_node_set_interrupt_pending (wrk->vm, session_queue_node.index);
  rv = read (wrk->timerfd, &buf, sizeof (buf));
  if (rv < 0 && errno != EAGAIN)
    clib_unix_warning ("failed");
  return 0;
}

static clib_error_t *
session_wrk_tfd_write_ready (clib_file_t *cf)
{
  return 0;
}

void
session_wrk_enable_adaptive_mode (session_worker_t *wrk)
{
  u32 thread_index = wrk->vm->thread_index;
  clib_file_t template = { 0 };

  if ((wrk->timerfd = timerfd_create (CLOCK_MONOTONIC, TFD_NONBLOCK)) < 0)
    clib_warning ("timerfd_create");

  template.read_function = session_wrk_tfd_read_ready;
  template.write_function = session_wrk_tfd_write_ready;
  template.file_descriptor = wrk->timerfd;
  template.private_data = thread_index;
  template.polling_thread_index = thread_index;
  template.description = format (0, "session-wrk-tfd-%u", thread_index);

  wrk->timerfd_file = clib_file_add (&file_main, &template);
  wrk->flags |= SESSION_WRK_F_ADAPTIVE;
}

static clib_error_t *
session_queue_exit (vlib_main_t * vm)
{
  if (vlib_get_n_threads () < 2)
    return 0;

  /*
   * Shut off (especially) worker-thread session nodes.
   * Otherwise, vpp can crash as the main thread unmaps the
   * API segment.
   */
  vlib_worker_thread_barrier_sync (vm);
  session_node_enable_disable (0 /* is_enable */ );
  vlib_worker_thread_barrier_release (vm);
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (session_queue_exit);

static uword
session_queue_run_on_main (vlib_main_t * vm)
{
  vlib_node_runtime_t *node;

  node = vlib_node_get_runtime (vm, session_queue_node.index);
  return session_queue_node_fn (vm, node, 0);
}

static uword
session_queue_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		       vlib_frame_t * f)
{
  uword *event_data = 0;
  f64 timeout = 1.0;
  uword event_type;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      event_type = vlib_process_get_events (vm, (uword **) & event_data);

      switch (event_type)
	{
	case SESSION_Q_PROCESS_RUN_ON_MAIN:
	  /* Run session queue node on main thread */
	  session_queue_run_on_main (vm);
	  break;
	case SESSION_Q_PROCESS_STOP:
	  vlib_node_set_state (vm, session_queue_process_node.index,
			       VLIB_NODE_STATE_DISABLED);
	  timeout = 100000.0;
	  break;
	case ~0:
	  /* Timed out. Run on main to ensure all events are handled */
	  session_queue_run_on_main (vm);
	  break;
	}
      vec_reset_length (event_data);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (session_queue_process_node) =
{
  .function = session_queue_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "session-queue-process",
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */

static_always_inline uword
session_queue_pre_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  session_main_t *sm = &session_main;
  if (!sm->wrk[0].vpp_event_queue)
    return 0;
  node = vlib_node_get_runtime (vm, session_queue_node.index);
  return session_queue_node_fn (vm, node, frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (session_queue_pre_input_node) =
{
  .function = session_queue_pre_input_inline,
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .name = "session-queue-main",
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
