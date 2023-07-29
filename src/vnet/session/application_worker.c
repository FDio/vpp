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
  clib_spinlock_init (&app_wrk->detached_seg_managers_lock);
  clib_spinlock_init (&app_wrk->postponed_mq_msgs_lock);
  vec_validate (app_wrk->wrk_evts, vlib_num_workers ());
  vec_validate (app_wrk->wrk_mq_congested, vlib_num_workers ());
  vec_validate (app_wrk->pending_mq_msgs, vlib_num_workers ());
  APP_DBG ("New app %v worker %u", app->name, app_wrk->wrk_index);
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
  u64 handle, *handles = 0, *sm_indices = 0;
  segment_manager_t *sm;
  session_handle_t *sh;
  session_t *ls;
  u32 sm_index;
  int i;

  /*
   * Cleanup vpp wrk events
   */
  app_worker_del_all_events (app_wrk);
  for (i = 0; i < vec_len (app_wrk->wrk_evts); i++)
    clib_fifo_free (app_wrk->wrk_evts[i]);

  vec_free (app_wrk->wrk_evts);
  vec_free (app_wrk->wrk_mq_congested);

  /*
   *  Listener cleanup
   */

  hash_foreach (handle, sm_index, app_wrk->listeners_table, ({
    ls = listen_session_get_from_handle (handle);
    vec_add1 (handles, app_listen_session_handle (ls));
    vec_add1 (sm_indices, sm_index);
    sm = segment_manager_get (sm_index);
  }));

  for (i = 0; i < vec_len (handles); i++)
    {
      /* Cleanup listener */
      a->app_index = app->app_index;
      a->wrk_map_index = app_wrk->wrk_map_index;
      a->handle = handles[i];
      (void) vnet_unlisten (a);

      sm = segment_manager_get_if_valid (sm_indices[i]);
      if (sm && !segment_manager_app_detached (sm))
	{
	  sm->first_is_protected = 0;
	  segment_manager_init_free (sm);
	}
    }
  vec_reset_length (handles);
  vec_free (sm_indices);
  hash_free (app_wrk->listeners_table);

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

  /*
   * Half-open cleanup
   */

  pool_foreach (sh, app_wrk->half_open_table)
    session_cleanup_half_open (*sh);

  pool_free (app_wrk->half_open_table);

  /*
   * Detached listener segment managers cleanup
   */
  for (i = 0; i < vec_len (app_wrk->detached_seg_managers); i++)
    {
      sm = segment_manager_get (app_wrk->detached_seg_managers[i]);
      segment_manager_init_free (sm);
    }
  vec_free (app_wrk->detached_seg_managers);
  clib_spinlock_free (&app_wrk->detached_seg_managers_lock);

  // XXX remove
  clib_fifo_free (app_wrk->postponed_mq_msgs);
  clib_spinlock_free (&app_wrk->postponed_mq_msgs_lock);

  if (CLIB_DEBUG)
    clib_memset (app_wrk, 0xfe, sizeof (*app_wrk));
  pool_put (app_workers, app_wrk);
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
  segment_manager_t *sm;

  sm = segment_manager_alloc ();
  sm->app_wrk_index = app_wrk->wrk_index;
  segment_manager_init (sm);
  return sm;
}

static int
app_worker_alloc_session_fifos (segment_manager_t * sm, session_t * s)
{
  svm_fifo_t *rx_fifo = 0, *tx_fifo = 0;
  int rv;

  if ((rv = segment_manager_alloc_session_fifos (sm, s->thread_index,
						 &rx_fifo, &tx_fifo)))
    return rv;

  rx_fifo->shr->master_session_index = s->session_index;
  rx_fifo->master_thread_index = s->thread_index;

  tx_fifo->shr->master_session_index = s->session_index;
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
    return SESSION_E_ALLOC;

  /* Once the first segment is mapped, don't remove it until unlisten */
  sm->first_is_protected = 1;

  /* Keep track of the segment manager for the listener or this worker */
  hash_set (app_wrk->listeners_table, listen_session_get_handle (ls),
	    segment_manager_index (sm));

  if (transport_connection_is_cless (session_get_transport (ls)))
    {
      if (ls->rx_fifo)
	return SESSION_E_NOSUPPORT;
      return app_worker_alloc_session_fifos (sm, ls);
    }
  return 0;
}

session_error_t
app_worker_start_listen (app_worker_t *app_wrk, app_listener_t *app_listener)
{
  session_t *ls;
  int rv;

  if (clib_bitmap_get (app_listener->workers, app_wrk->wrk_map_index))
    return SESSION_E_ALREADY_LISTENING;

  app_listener->workers = clib_bitmap_set (app_listener->workers,
					   app_wrk->wrk_map_index, 1);

  if (app_listener->session_index != SESSION_INVALID_INDEX)
    {
      ls = session_get (app_listener->session_index, 0);
      if ((rv = app_worker_init_listener (app_wrk, ls)))
	return rv;
    }

  if (app_listener->local_index != SESSION_INVALID_INDEX)
    {
      ls = session_get (app_listener->local_index, 0);
      if ((rv = app_worker_init_listener (app_wrk, ls)))
	return rv;
    }

  return 0;
}

static void
app_worker_add_detached_sm (app_worker_t * app_wrk, u32 sm_index)
{
  vec_add1 (app_wrk->detached_seg_managers, sm_index);
}

void
app_worker_del_detached_sm (app_worker_t * app_wrk, u32 sm_index)
{
  u32 i;

  clib_spinlock_lock (&app_wrk->detached_seg_managers_lock);
  for (i = 0; i < vec_len (app_wrk->detached_seg_managers); i++)
    {
      if (app_wrk->detached_seg_managers[i] == sm_index)
	{
	  vec_del1 (app_wrk->detached_seg_managers, i);
	  break;
	}
    }
  clib_spinlock_unlock (&app_wrk->detached_seg_managers_lock);
}

static void
app_worker_stop_listen_session (app_worker_t * app_wrk, session_t * ls)
{
  session_handle_t handle;
  segment_manager_t *sm;
  uword *sm_indexp;
  session_state_t *states = 0;

  handle = listen_session_get_handle (ls);
  sm_indexp = hash_get (app_wrk->listeners_table, handle);
  if (PREDICT_FALSE (!sm_indexp))
    return;

  /* Dealloc fifos, if any (dgram listeners) */
  if (ls->rx_fifo)
    {
      segment_manager_dealloc_fifos (ls->rx_fifo, ls->tx_fifo);
      ls->tx_fifo = ls->rx_fifo = 0;
    }

  /* Try to cleanup segment manager */
  sm = segment_manager_get (*sm_indexp);
  if (sm)
    {
      sm->first_is_protected = 0;
      segment_manager_app_detach (sm);
      if (!segment_manager_has_fifos (sm))
	{
	  /* Empty segment manager, cleanup it up */
	  segment_manager_free (sm);
	}
      else
	{
	  /* Delete sessions in CREATED state */
	  vec_add1 (states, SESSION_STATE_CREATED);
	  segment_manager_del_sessions_filter (sm, states);
	  vec_free (states);

	  /* Track segment manager in case app detaches and all the
	   * outstanding sessions need to be closed */
	  app_worker_add_detached_sm (app_wrk, *sm_indexp);
	  sm->flags |= SEG_MANAGER_F_DETACHED_LISTENER;
	}
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
  application_t *app;

  listener = listen_session_get_from_handle (s->listener_handle);
  app_wrk = application_listener_select_worker (listener);
  if (PREDICT_FALSE (app_worker_mq_is_congested (app_wrk)))
    return -1;

  s->app_wrk_index = app_wrk->wrk_index;
  app = application_get (app_wrk->app_index);
  if (app->cb_fns.fifo_tuning_callback)
    s->flags |= SESSION_F_CUSTOM_FIFO_TUNING;

  sm = app_worker_get_listen_segment_manager (app_wrk, listener);
  if (app_worker_alloc_session_fifos (sm, s))
    return -1;

  return 0;
}

int
app_worker_listened_notify (app_worker_t *app_wrk, session_handle_t alsh,
			    u32 opaque, session_error_t err)
{
  session_event_t evt;

  evt.event_type = SESSION_CTRL_EVT_BOUND;
  evt.session_handle = alsh;
  evt.as_u64[1] = (u64) opaque << 32 | err;

  app_worker_add_event_custom (app_wrk, 0 /* thread index */, &evt);

  return 0;
}

int
app_worker_unlisten_reply (app_worker_t *app_wrk, session_handle_t sh,
			   u32 opaque, session_error_t err)
{
  session_event_t evt = {};

  evt.event_type = SESSION_CTRL_EVT_UNLISTEN_REPLY;
  evt.session_handle = sh;
  evt.as_u64[1] = (u64) opaque << 32 | (u32) err;

  app_worker_add_event_custom (app_wrk, 0 /* thread index */, &evt);
  return 0;
}

int
app_worker_accept_notify (app_worker_t * app_wrk, session_t * s)
{
  app_worker_add_event (app_wrk, s, SESSION_CTRL_EVT_ACCEPTED);
  return 0;
}

int
app_worker_init_connected (app_worker_t * app_wrk, session_t * s)
{
  application_t *app = application_get (app_wrk->app_index);
  segment_manager_t *sm;

  if (app->cb_fns.fifo_tuning_callback)
    s->flags |= SESSION_F_CUSTOM_FIFO_TUNING;

  /* Allocate fifos for session, unless the app is a builtin proxy */
  if (application_is_builtin_proxy (app))
    return 0;

  sm = app_worker_get_connect_segment_manager (app_wrk);
  return app_worker_alloc_session_fifos (sm, s);
}

int
app_worker_connect_notify (app_worker_t * app_wrk, session_t * s,
			   session_error_t err, u32 opaque)
{
  session_event_t evt = {};
  u32 thread_index;

  evt.event_type = SESSION_CTRL_EVT_CONNECTED;
  evt.session_index = s ? s->session_index : ~0;
  evt.as_u64[1] = (u64) opaque << 32 | (u32) err;
  thread_index = s ? s->thread_index : vlib_get_thread_index ();

  app_worker_add_event_custom (app_wrk, thread_index, &evt);
  return 0;
}

int
app_worker_add_half_open (app_worker_t *app_wrk, session_handle_t sh)
{
  session_handle_t *shp;

  ASSERT (session_vlib_thread_is_cl_thread ());
  pool_get (app_wrk->half_open_table, shp);
  *shp = sh;

  return (shp - app_wrk->half_open_table);
}

// XXX NO EVENT
int
app_worker_del_half_open (app_worker_t *app_wrk, session_t *s)
{
  app_worker_add_event (app_wrk, s, SESSION_CTRL_EVT_HALF_CLEANUP);
  return 0;
}

int
app_worker_close_notify (app_worker_t * app_wrk, session_t * s)
{
  app_worker_add_event (app_wrk, s, SESSION_CTRL_EVT_DISCONNECTED);
  return 0;
}

// XXX NO EVENT
int
app_worker_transport_closed_notify (app_worker_t * app_wrk, session_t * s)
{
  app_worker_add_event (app_wrk, s, SESSION_CTRL_EVT_TRANSPORT_CLOSED);
  return 0;
}

int
app_worker_reset_notify (app_worker_t * app_wrk, session_t * s)
{
  app_worker_add_event (app_wrk, s, SESSION_CTRL_EVT_RESET);
  return 0;
}

int
app_worker_cleanup_notify (app_worker_t * app_wrk, session_t * s,
			   session_cleanup_ntf_t ntf)
{
  session_event_t evt;

  evt.event_type = SESSION_CTRL_EVT_CLEANUP;
  evt.as_u64[0] = (u64) ntf << 32 | s->session_index;
  evt.as_u64[1] = pointer_to_uword (session_cleanup);

  app_worker_add_event_custom (app_wrk, s->thread_index, &evt);

  return 0;
}

int
app_worker_cleanup_notify_custom (app_worker_t *app_wrk, session_t *s,
				  session_cleanup_ntf_t ntf,
				  void (*cleanup_cb) (session_t *s))
{
  session_event_t evt;

  evt.event_type = SESSION_CTRL_EVT_CLEANUP;
  evt.as_u64[0] = (u64) ntf << 32 | s->session_index;
  evt.as_u64[1] = pointer_to_uword (cleanup_cb);

  app_worker_add_event_custom (app_wrk, s->thread_index, &evt);

  return 0;
}

int
app_worker_builtin_rx (app_worker_t *app_wrk, session_t *s)
{
  app_worker_add_event (app_wrk, s, SESSION_IO_EVT_RX);
  return 0;
}

// /* TODO remove*/
// int
// app_worker_builtin_tx (app_worker_t * app_wrk, session_t * s)
// {
//   //   app_worker_add_event (app_wrk, s, SESSION_IO_EVT_BUILTIN_TX);
//   return 0;
// }

int
app_worker_migrate_notify (app_worker_t * app_wrk, session_t * s,
			   session_handle_t new_sh)
{
  session_event_t evt;

  evt.event_type = SESSION_CTRL_EVT_MIGRATED;
  evt.session_index = s->session_index;
  evt.as_u64[1] = new_sh;

  app_worker_add_event_custom (app_wrk, s->thread_index, &evt);
  return 0;
}

int
app_worker_own_session (app_worker_t * app_wrk, session_t * s)
{
  segment_manager_t *sm;
  svm_fifo_t *rxf, *txf;
  int rv;

  if (s->session_state == SESSION_STATE_LISTENING)
    return application_change_listener_owner (s, app_wrk);

  s->app_wrk_index = app_wrk->wrk_index;

  rxf = s->rx_fifo;
  txf = s->tx_fifo;

  if (!rxf || !txf)
    return 0;

  s->rx_fifo = 0;
  s->tx_fifo = 0;

  sm = app_worker_get_connect_segment_manager (app_wrk);
  if ((rv = app_worker_alloc_session_fifos (sm, s)))
    return rv;

  if (!svm_fifo_is_empty_cons (rxf))
    svm_fifo_clone (s->rx_fifo, rxf);

  if (!svm_fifo_is_empty_cons (txf))
    svm_fifo_clone (s->tx_fifo, txf);

  segment_manager_dealloc_fifos (rxf, txf);

  return 0;
}

int
app_worker_connect_session (app_worker_t *app_wrk, session_endpoint_cfg_t *sep,
			    session_handle_t *rsh)
{
  if (PREDICT_FALSE (app_worker_mq_is_congested (app_wrk)))
    return SESSION_E_REFUSED;

  sep->app_wrk_index = app_wrk->wrk_index;

  return session_open (sep, rsh);
}

int
app_worker_session_fifo_tuning (app_worker_t * app_wrk, session_t * s,
				svm_fifo_t * f,
				session_ft_action_t act, u32 len)
{
  application_t *app = application_get (app_wrk->app_index);
  return app->cb_fns.fifo_tuning_callback (s, f, act, len);
}

segment_manager_t *
app_worker_get_connect_segment_manager (app_worker_t * app)
{
  ASSERT (app->connects_seg_manager != (u32) ~ 0);
  return segment_manager_get (app->connects_seg_manager);
}

segment_manager_t *
app_worker_get_listen_segment_manager (app_worker_t * app,
				       session_t * listener)
{
  uword *smp;
  smp = hash_get (app->listeners_table, listen_session_get_handle (listener));
  ALWAYS_ASSERT (smp != 0);
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
  session_event_t evt;

  evt.event_type = SESSION_CTRL_EVT_APP_ADD_SEGMENT;
  evt.as_u64[1] = segment_handle;

  app_worker_add_event_custom (app_wrk, vlib_get_thread_index (), &evt);

  return 0;
}

int
app_worker_del_segment_notify (app_worker_t * app_wrk, u64 segment_handle)
{
  session_event_t evt;

  evt.event_type = SESSION_CTRL_EVT_APP_DEL_SEGMENT;
  evt.as_u64[1] = segment_handle;

  app_worker_add_event_custom (app_wrk, vlib_get_thread_index (), &evt);

  return 0;
}

static int
app_wrk_send_fd (app_worker_t *app_wrk, int fd)
{
  if (!appns_sapi_enabled ())
    {
      vl_api_registration_t *reg;
      clib_error_t *error;

      reg =
	vl_mem_api_client_index_to_registration (app_wrk->api_client_index);
      if (!reg)
	{
	  clib_warning ("no api registration for client: %u",
			app_wrk->api_client_index);
	  return -1;
	}

      if (vl_api_registration_file_index (reg) == VL_API_INVALID_FI)
	return -1;

      error = vl_api_send_fd_msg (reg, &fd, 1);
      if (error)
	{
	  clib_error_report (error);
	  return -1;
	}

      return 0;
    }

  app_sapi_msg_t smsg = { 0 };
  app_namespace_t *app_ns;
  clib_error_t *error;
  application_t *app;
  clib_socket_t *cs;
  u32 cs_index;

  app = application_get (app_wrk->app_index);
  app_ns = app_namespace_get (app->ns_index);
  cs_index = appns_sapi_handle_sock_index (app_wrk->api_client_index);
  cs = appns_sapi_get_socket (app_ns, cs_index);
  if (PREDICT_FALSE (!cs))
    return -1;

  /* There's no payload for the message only the type */
  smsg.type = APP_SAPI_MSG_TYPE_SEND_FDS;
  error = clib_socket_sendmsg (cs, &smsg, sizeof (smsg), &fd, 1);
  if (error)
    {
      clib_error_report (error);
      return -1;
    }

  return 0;
}

// static int
// mq_try_lock_and_alloc_msg (svm_msg_q_t *mq, session_mq_rings_e ring,
// 			   svm_msg_q_msg_t *msg)
// {
//   int rv, n_try = 0;

//   while (n_try < 75)
//     {
//       rv = svm_msg_q_lock_and_alloc_msg_w_ring (mq, ring, SVM_Q_NOWAIT,
//       msg); if (!rv)
// 	return 0;
//       /*
//        * Break the loop if mq is full, usually this is because the
//        * app has crashed or is hanging on somewhere.
//        */
//       if (rv != -1)
// 	break;
//       n_try += 1;
//       usleep (1);
//     }

//   return -1;
// }

void
app_worker_add_event (app_worker_t *app_wrk, session_t *s,
		      session_evt_type_t evt_type)
{
  session_event_t *evt;

  ASSERT (s->thread_index == vlib_get_thread_index ());
  clib_fifo_add2 (app_wrk->wrk_evts[s->thread_index], evt);
  evt->session_index = s->session_index;
  evt->event_type = evt_type;
  evt->postponed = 0;

  /* First event for this app_wrk. Schedule it for handling in session input */
  if (clib_fifo_elts (app_wrk->wrk_evts[s->thread_index]) == 1)
    {
      session_worker_t *wrk = session_main_get_worker (s->thread_index);
      session_wrk_program_app_wrk_evts (wrk, app_wrk->wrk_index);
    }
}

void
app_worker_add_event_custom (app_worker_t *app_wrk, u32 thread_index,
			     session_event_t *evt)
{
  clib_fifo_add1 (app_wrk->wrk_evts[thread_index], *evt);

  /* First event for this app_wrk. Schedule it for handling in session input */
  if (clib_fifo_elts (app_wrk->wrk_evts[thread_index]) == 1)
    {
      session_worker_t *wrk = session_main_get_worker (thread_index);
      session_wrk_program_app_wrk_evts (wrk, app_wrk->wrk_index);
    }
}

typedef union app_wrk_mq_rpc_args_
{
  struct
  {
    u32 thread_index;
    u32 app_wrk_index;
  };
  uword as_uword;
} app_wrk_mq_rpc_ags_t;

// static int
// app_wrk_handle_mq_postponed_msgs (void *arg)
// {
//   svm_msg_q_msg_t _mq_msg, *mq_msg = &_mq_msg;
//   app_wrk_postponed_msg_t *pm;
//   app_wrk_mq_rpc_ags_t args;
//   u32 max_msg, n_msg = 0;
//   app_worker_t *app_wrk;
//   session_event_t *evt;
//   svm_msg_q_t *mq;

//   args.as_uword = pointer_to_uword (arg);
//   app_wrk = app_worker_get_if_valid (args.app_wrk_index);
//   if (!app_wrk)
//     return 0;

//   mq = app_wrk->event_queue;

//   clib_spinlock_lock (&app_wrk->postponed_mq_msgs_lock);

//   max_msg = clib_min (32, clib_fifo_elts (app_wrk->postponed_mq_msgs));

//   while (n_msg < max_msg)
//     {
//       pm = clib_fifo_head (app_wrk->postponed_mq_msgs);
//       if (mq_try_lock_and_alloc_msg (mq, pm->ring, mq_msg))
// 	break;

//       evt = svm_msg_q_msg_data (mq, mq_msg);
//       clib_memset (evt, 0, sizeof (*evt));
//       evt->event_type = pm->event_type;
//       clib_memcpy_fast (evt->data, pm->data, pm->len);

//       if (pm->fd != -1)
// 	app_wrk_send_fd (app_wrk, pm->fd);

//       svm_msg_q_add_and_unlock (mq, mq_msg);

//       clib_fifo_advance_head (app_wrk->postponed_mq_msgs, 1);
//       n_msg += 1;
//     }

//   if (!clib_fifo_elts (app_wrk->postponed_mq_msgs))
//     {
//       app_wrk->mq_congested = 0;
//     }
//   else
//     {
//       session_send_rpc_evt_to_thread_force (
// 	args.thread_index, app_wrk_handle_mq_postponed_msgs,
// 	uword_to_pointer (args.as_uword, void *));
//     }

//   clib_spinlock_unlock (&app_wrk->postponed_mq_msgs_lock);

//   return 0;
// }

// static void
// app_wrk_add_mq_postponed_msg (app_worker_t *app_wrk, session_mq_rings_e
// ring, 			      u8 evt_type, void *msg, u32 msg_len, int
// fd)
// {
//   app_wrk_postponed_msg_t *pm;

//   clib_spinlock_lock (&app_wrk->postponed_mq_msgs_lock);

//   app_wrk->mq_congested = 1;

//   clib_fifo_add2 (app_wrk->postponed_mq_msgs, pm);
//   clib_memcpy_fast (pm->data, msg, msg_len);
//   pm->event_type = evt_type;
//   pm->ring = ring;
//   pm->len = msg_len;
//   pm->fd = fd;

//   if (clib_fifo_elts (app_wrk->postponed_mq_msgs) == 1)
//     {
//       app_wrk_mq_rpc_ags_t args = { .thread_index = vlib_get_thread_index
//       (),
// 				    .app_wrk_index = app_wrk->wrk_index };

//       session_send_rpc_evt_to_thread_force (
// 	args.thread_index, app_wrk_handle_mq_postponed_msgs,
// 	uword_to_pointer (args.as_uword, void *));
//     }

//   clib_spinlock_unlock (&app_wrk->postponed_mq_msgs_lock);
// }

always_inline void
app_wrk_send_ctrl_evt_inline (app_worker_t *app_wrk, u8 evt_type, void *msg,
			      u32 msg_len, int fd)
{
  svm_msg_q_msg_t _mq_msg, *mq_msg = &_mq_msg;
  svm_msg_q_t *mq = app_wrk->event_queue;
  session_event_t *evt;
  //   int rv;

  //   if (PREDICT_FALSE (app_worker_mq_is_congested (app_wrk)))
  //     goto handle_congestion;

  //   rv = mq_try_lock_and_alloc_msg (mq, SESSION_MQ_CTRL_EVT_RING, mq_msg);
  //   if (PREDICT_FALSE (rv))
  //     goto handle_congestion;
  ASSERT (!svm_msg_q_or_ring_is_full (mq, SESSION_MQ_CTRL_EVT_RING));
  *mq_msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_CTRL_EVT_RING);

  evt = svm_msg_q_msg_data (mq, mq_msg);
  clib_memset (evt, 0, sizeof (*evt));
  evt->event_type = evt_type;
  clib_memcpy_fast (evt->data, msg, msg_len);

  if (fd != -1)
    app_wrk_send_fd (app_wrk, fd);

  //   svm_msg_q_add_and_unlock (mq, mq_msg);
  svm_msg_q_add_raw (mq, mq_msg);

  return;

  // handle_congestion:

  //   app_wrk_add_mq_postponed_msg (app_wrk, SESSION_MQ_CTRL_EVT_RING,
  //   evt_type,
  // 				msg, msg_len, fd);
}

void
app_wrk_send_ctrl_evt_fd (app_worker_t *app_wrk, u8 evt_type, void *msg,
			  u32 msg_len, int fd)
{
  app_wrk_send_ctrl_evt_inline (app_wrk, evt_type, msg, msg_len, fd);
}

void
app_wrk_send_ctrl_evt (app_worker_t *app_wrk, u8 evt_type, void *msg,
		       u32 msg_len)
{
  app_wrk_send_ctrl_evt_inline (app_wrk, evt_type, msg, msg_len, -1);
}

app_wrk_postponed_msg_t *
app_wrk_reserve_msg (app_worker_t *app_wrk, u32 thread_index)
{
  app_wrk_postponed_msg_t *pm;

  clib_fifo_add2 (app_wrk->postponed_mq_msgs[thread_index], pm);
  return pm;
  //   clib_memcpy_fast (pm->data, msg, msg_len);
  //   pm->event_type = evt_type;
  //   pm->ring = ring;
  //   pm->len = msg_len;
  //   pm->fd = fd;

  //   if (clib_fifo_elts (app_wrk->postponed_mq_msgs) == 1)
  //     {
  //       app_wrk_mq_rpc_ags_t args = { .thread_index = vlib_get_thread_index
  //       (),
  // 				    .app_wrk_index = app_wrk->wrk_index };

  //       session_send_rpc_evt_to_thread_force (
  // 	args.thread_index, app_wrk_handle_mq_postponed_msgs,
  // 	uword_to_pointer (args.as_uword, void *));
  //     }
}

int
app_wrk_program_ctrl_msg (app_worker_t *app_wrk, app_wrk_reserved_msg_t msg)
{
}

u8
app_worker_mq_wrk_is_congested (app_worker_t *app_wrk, u32 thread_index)
{
  return app_wrk->wrk_mq_congested[thread_index] > 0;
}

void
app_worker_set_mq_wrk_congested (app_worker_t *app_wrk, u32 thread_index)
{
  clib_warning ("marking mq as congested?!");
  os_panic ();
  clib_atomic_fetch_add_relax (&app_wrk->mq_congested, 1);
  ASSERT (thread_index == vlib_get_thread_index ());
  app_wrk->wrk_mq_congested[thread_index] = 1;
}

void
app_worker_unset_wrk_mq_congested (app_worker_t *app_wrk, u32 thread_index)
{
  clib_atomic_fetch_sub_relax (&app_wrk->mq_congested, 1);
  ASSERT (thread_index == vlib_get_thread_index ());
  app_wrk->wrk_mq_congested[thread_index] = 0;
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
	s = format (s, "%-" SESSION_CLI_ID_LEN "s%-25s%-10s%-15s%-15s%-10s",
		    "Connection", "App", "Wrk", "API Client", "ListenerID",
		    "SegManager");
      else
	s = format (s, "%-" SESSION_CLI_ID_LEN "s%-25s%-10s", "Connection",
		    "App", "Wrk");

      return s;
    }

  app_name = application_name_from_index (app_wrk->app_index);
  listener = listen_session_get_from_handle (handle);
  str = format (0, "%U", format_session, listener, verbose);

  if (verbose)
    {
      u8 *buf;
      buf = format (0, "%u(%u)", app_wrk->wrk_map_index, app_wrk->wrk_index);
      s = format (s, "%-" SESSION_CLI_ID_LEN "v%-25v%-10v%-15u%-15u%-10u", str,
		  app_name, buf, app_wrk->api_client_index, handle, sm_index);
      vec_free (buf);
    }
  else
    s = format (s, "%-" SESSION_CLI_ID_LEN "v%-25v%=10u", str, app_name,
		app_wrk->wrk_map_index);

  vec_free (str);

  return s;
}

u8 *
format_app_worker (u8 * s, va_list * args)
{
  app_worker_t *app_wrk = va_arg (*args, app_worker_t *);
  u32 indent = 1;

  s = format (s,
	      "%U wrk-index %u app-index %u map-index %u "
	      "api-client-index %d mq-cong %u\n",
	      format_white_space, indent, app_wrk->wrk_index,
	      app_wrk->app_index, app_wrk->wrk_map_index,
	      app_wrk->api_client_index, app_wrk->mq_congested);
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
