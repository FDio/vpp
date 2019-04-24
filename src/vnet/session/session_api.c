/*
 * Copyright (c) 2015-2019 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/application_local.h>
#include <vnet/session/session_rules_table.h>
#include <vnet/session/session_table.h>
#include <vnet/session/session.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_session_api_msg                                         \
_(MAP_ANOTHER_SEGMENT_REPLY, map_another_segment_reply)                 \
_(APPLICATION_ATTACH, application_attach)				\
_(APPLICATION_DETACH, application_detach)				\
_(BIND_URI, bind_uri)                                                   \
_(UNBIND_URI, unbind_uri)                                               \
_(CONNECT_URI, connect_uri)                                             \
_(DISCONNECT_SESSION, disconnect_session)                               \
_(DISCONNECT_SESSION_REPLY, disconnect_session_reply)                   \
_(BIND_SOCK, bind_sock)							\
_(UNBIND_SOCK, unbind_sock)                                             \
_(CONNECT_SOCK, connect_sock)                                          	\
_(SESSION_ENABLE_DISABLE, session_enable_disable)                   	\
_(APP_NAMESPACE_ADD_DEL, app_namespace_add_del)				\
_(SESSION_RULE_ADD_DEL, session_rule_add_del)				\
_(SESSION_RULES_DUMP, session_rules_dump)				\
_(APPLICATION_TLS_CERT_ADD, application_tls_cert_add)			\
_(APPLICATION_TLS_KEY_ADD, application_tls_key_add)			\
_(APP_WORKER_ADD_DEL, app_worker_add_del)				\

static int
session_send_fds (vl_api_registration_t * reg, int fds[], int n_fds)
{
  clib_error_t *error;
  if (vl_api_registration_file_index (reg) == VL_API_INVALID_FI)
    {
      clib_warning ("can't send memfd fd");
      return -1;
    }
  error = vl_api_send_fd_msg (reg, fds, n_fds);
  if (error)
    {
      clib_error_report (error);
      return -1;
    }
  return 0;
}

static int
send_add_segment_callback (u32 api_client_index, u64 segment_handle)
{
  int fds[SESSION_N_FD_TYPE], n_fds = 0;
  vl_api_map_another_segment_t *mp;
  vl_api_registration_t *reg;
  fifo_segment_t *fs;
  ssvm_private_t *sp;
  u8 fd_flags = 0;

  reg = vl_mem_api_client_index_to_registration (api_client_index);
  if (!reg)
    {
      clib_warning ("no api registration for client: %u", api_client_index);
      return -1;
    }

  fs = segment_manager_get_segment_w_handle (segment_handle);
  sp = &fs->ssvm;
  if (ssvm_type (sp) == SSVM_SEGMENT_MEMFD)
    {
      if (vl_api_registration_file_index (reg) == VL_API_INVALID_FI)
	{
	  clib_warning ("can't send memfd fd");
	  return -1;
	}

      fd_flags |= SESSION_FD_F_MEMFD_SEGMENT;
      fds[n_fds] = sp->fd;
      n_fds += 1;
    }

  mp = vl_mem_api_alloc_as_if_client_w_reg (reg, sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_MAP_ANOTHER_SEGMENT);
  mp->segment_size = sp->ssvm_size;
  mp->fd_flags = fd_flags;
  mp->segment_handle = clib_host_to_net_u64 (segment_handle);
  strncpy ((char *) mp->segment_name, (char *) sp->name,
	   sizeof (mp->segment_name) - 1);

  vl_msg_api_send_shmem (reg->vl_input_queue, (u8 *) & mp);

  if (n_fds)
    return session_send_fds (reg, fds, n_fds);

  return 0;
}

static int
send_del_segment_callback (u32 api_client_index, u64 segment_handle)
{
  vl_api_unmap_segment_t *mp;
  vl_api_registration_t *reg;

  reg = vl_mem_api_client_index_to_registration (api_client_index);
  if (!reg)
    {
      clib_warning ("no registration: %u", api_client_index);
      return -1;
    }

  mp = vl_mem_api_alloc_as_if_client_w_reg (reg, sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_UNMAP_SEGMENT);
  mp->segment_handle = clib_host_to_net_u64 (segment_handle);
  vl_msg_api_send_shmem (reg->vl_input_queue, (u8 *) & mp);

  return 0;
}

static int
mq_try_lock_and_alloc_msg (svm_msg_q_t * app_mq, svm_msg_q_msg_t * msg)
{
  int rv;
  u8 try = 0;
  while (try < 100)
    {
      rv = svm_msg_q_lock_and_alloc_msg_w_ring (app_mq,
						SESSION_MQ_CTRL_EVT_RING,
						SVM_Q_NOWAIT, msg);
      if (!rv)
	return 0;
      try++;
      usleep (1);
    }
  clib_warning ("failed to alloc msg");
  return -1;
}

static int
mq_send_session_accepted_cb (session_t * s)
{
  app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
  svm_msg_q_msg_t _msg, *msg = &_msg;
  svm_msg_q_t *vpp_queue, *app_mq;
  session_t *listener;
  session_accepted_msg_t *mp;
  session_event_t *evt;
  application_t *app;
  app_listener_t *al;

  app = application_get (app_wrk->app_index);
  app_mq = app_wrk->event_queue;
  if (mq_try_lock_and_alloc_msg (app_mq, msg))
    return -1;

  evt = svm_msg_q_msg_data (app_mq, msg);
  clib_memset (evt, 0, sizeof (*evt));
  evt->event_type = SESSION_CTRL_EVT_ACCEPTED;
  mp = (session_accepted_msg_t *) evt->data;
  clib_memset (mp, 0, sizeof (*mp));
  mp->context = app->app_index;
  mp->server_rx_fifo = pointer_to_uword (s->rx_fifo);
  mp->server_tx_fifo = pointer_to_uword (s->tx_fifo);
  mp->segment_handle = session_segment_handle (s);

  if (session_has_transport (s))
    {
      listener = listen_session_get (s->listener_index);
      al = app_listener_get (app, listener->al_index);
      mp->listener_handle = app_listener_handle (al);
      if (application_is_proxy (app))
	{
	  listener =
	    app_worker_first_listener (app_wrk, session_get_fib_proto (s),
				       session_get_transport_proto (s));
	  if (listener)
	    mp->listener_handle = listen_session_get_handle (listener);
	}
      vpp_queue = session_main_get_vpp_event_queue (s->thread_index);
      mp->vpp_event_queue_address = pointer_to_uword (vpp_queue);
      mp->handle = session_handle (s);

      session_get_endpoint (s, &mp->rmt, 0 /* is_lcl */ );
    }
  else
    {
      ct_connection_t *ct;

      ct = (ct_connection_t *) session_get_transport (s);
      listener = listen_session_get (s->listener_index);
      al = app_listener_get (app, listener->al_index);
      mp->listener_handle = app_listener_handle (al);
      mp->rmt.is_ip4 = session_type_is_ip4 (listener->session_type);
      mp->rmt.port = ct->c_rmt_port;
      mp->handle = session_handle (s);
      vpp_queue = session_main_get_vpp_event_queue (0);
      mp->vpp_event_queue_address = pointer_to_uword (vpp_queue);
    }
  svm_msg_q_add_and_unlock (app_mq, msg);

  return 0;
}

static inline void
mq_send_session_close_evt (app_worker_t * app_wrk, session_handle_t sh,
			   session_evt_type_t evt_type)
{
  svm_msg_q_msg_t _msg, *msg = &_msg;
  session_disconnected_msg_t *mp;
  svm_msg_q_t *app_mq;
  session_event_t *evt;

  app_mq = app_wrk->event_queue;
  if (mq_try_lock_and_alloc_msg (app_mq, msg))
    return;
  evt = svm_msg_q_msg_data (app_mq, msg);
  clib_memset (evt, 0, sizeof (*evt));
  evt->event_type = evt_type;
  mp = (session_disconnected_msg_t *) evt->data;
  mp->handle = sh;
  mp->context = app_wrk->api_client_index;
  svm_msg_q_add_and_unlock (app_mq, msg);
}

static inline void
mq_notify_close_subscribers (u32 app_index, session_handle_t sh,
			     svm_fifo_t * f, session_evt_type_t evt_type)
{
  app_worker_t *app_wrk;
  application_t *app;
  int i;

  app = application_get (app_index);
  if (!app)
    return;

  for (i = 0; i < f->n_subscribers; i++)
    {
      if (!(app_wrk = application_get_worker (app, f->subscribers[i])))
	continue;
      mq_send_session_close_evt (app_wrk, sh, SESSION_CTRL_EVT_DISCONNECTED);
    }
}

static void
mq_send_session_disconnected_cb (session_t * s)
{
  app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
  session_handle_t sh = session_handle (s);

  mq_send_session_close_evt (app_wrk, session_handle (s),
			     SESSION_CTRL_EVT_DISCONNECTED);

  if (svm_fifo_n_subscribers (s->rx_fifo))
    mq_notify_close_subscribers (app_wrk->app_index, sh, s->rx_fifo,
				 SESSION_CTRL_EVT_DISCONNECTED);
}

static void
mq_send_session_reset_cb (session_t * s)
{
  app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
  session_handle_t sh = session_handle (s);

  mq_send_session_close_evt (app_wrk, sh, SESSION_CTRL_EVT_RESET);

  if (svm_fifo_n_subscribers (s->rx_fifo))
    mq_notify_close_subscribers (app_wrk->app_index, sh, s->rx_fifo,
				 SESSION_CTRL_EVT_RESET);
}

static int
mq_send_session_connected_cb (u32 app_wrk_index, u32 api_context,
			      session_t * s, u8 is_fail)
{
  svm_msg_q_msg_t _msg, *msg = &_msg;
  session_connected_msg_t *mp;
  svm_msg_q_t *vpp_mq, *app_mq;
  transport_connection_t *tc;
  app_worker_t *app_wrk;
  session_event_t *evt;

  app_wrk = app_worker_get (app_wrk_index);
  app_mq = app_wrk->event_queue;
  if (!app_mq)
    {
      clib_warning ("app %u with api index: %u not attached",
		    app_wrk->app_index, app_wrk->api_client_index);
      return -1;
    }

  if (mq_try_lock_and_alloc_msg (app_mq, msg))
    return -1;

  evt = svm_msg_q_msg_data (app_mq, msg);
  clib_memset (evt, 0, sizeof (*evt));
  evt->event_type = SESSION_CTRL_EVT_CONNECTED;
  mp = (session_connected_msg_t *) evt->data;
  clib_memset (mp, 0, sizeof (*mp));
  mp->context = api_context;

  if (is_fail)
    goto done;

  if (session_has_transport (s))
    {
      tc = session_get_transport (s);
      if (!tc)
	{
	  is_fail = 1;
	  goto done;
	}

      vpp_mq = session_main_get_vpp_event_queue (s->thread_index);
      mp->handle = session_handle (s);
      mp->vpp_event_queue_address = pointer_to_uword (vpp_mq);

      session_get_endpoint (s, &mp->lcl, 1 /* is_lcl */ );

      mp->server_rx_fifo = pointer_to_uword (s->rx_fifo);
      mp->server_tx_fifo = pointer_to_uword (s->tx_fifo);
      mp->segment_handle = session_segment_handle (s);
    }
  else
    {
      ct_connection_t *cct;
      session_t *ss;

      cct = (ct_connection_t *) session_get_transport (s);
      mp->handle = session_handle (s);
      mp->lcl.port = cct->c_lcl_port;
      mp->lcl.is_ip4 = cct->c_is_ip4;
      vpp_mq = session_main_get_vpp_event_queue (0);
      mp->vpp_event_queue_address = pointer_to_uword (vpp_mq);
      mp->server_rx_fifo = pointer_to_uword (s->rx_fifo);
      mp->server_tx_fifo = pointer_to_uword (s->tx_fifo);
      mp->segment_handle = session_segment_handle (s);
      ss = ct_session_get_peer (s);
      mp->ct_rx_fifo = pointer_to_uword (ss->tx_fifo);
      mp->ct_tx_fifo = pointer_to_uword (ss->rx_fifo);
      mp->ct_segment_handle = session_segment_handle (ss);
    }

done:
  mp->retval = is_fail ?
    clib_host_to_net_u32 (VNET_API_ERROR_SESSION_CONNECT) : 0;

  svm_msg_q_add_and_unlock (app_mq, msg);
  return 0;
}

static int
mq_send_session_bound_cb (u32 app_wrk_index, u32 api_context,
			  session_handle_t handle, int rv)
{
  svm_msg_q_msg_t _msg, *msg = &_msg;
  svm_msg_q_t *app_mq, *vpp_evt_q;
  transport_connection_t *tc;
  session_bound_msg_t *mp;
  app_worker_t *app_wrk;
  session_event_t *evt;
  app_listener_t *al;
  session_t *ls = 0;
  app_wrk = app_worker_get (app_wrk_index);
  app_mq = app_wrk->event_queue;
  if (!app_mq)
    {
      clib_warning ("app %u with api index: %u not attached",
		    app_wrk->app_index, app_wrk->api_client_index);
      return -1;
    }

  if (mq_try_lock_and_alloc_msg (app_mq, msg))
    return -1;

  evt = svm_msg_q_msg_data (app_mq, msg);
  clib_memset (evt, 0, sizeof (*evt));
  evt->event_type = SESSION_CTRL_EVT_BOUND;
  mp = (session_bound_msg_t *) evt->data;
  mp->context = api_context;

  if (rv)
    goto done;

  mp->handle = handle;
  al = app_listener_get_w_handle (handle);
  if (al->session_index != SESSION_INVALID_INDEX)
    ls = app_listener_get_session (al);
  else
    ls = app_listener_get_local_session (al);
  tc = listen_session_get_transport (ls);
  mp->lcl_port = tc->lcl_port;
  mp->lcl_is_ip4 = tc->is_ip4;
  clib_memcpy_fast (mp->lcl_ip, &tc->lcl_ip, sizeof (tc->lcl_ip));

  vpp_evt_q = session_main_get_vpp_event_queue (0);
  mp->vpp_evt_q = pointer_to_uword (vpp_evt_q);

  if (session_transport_service_type (ls) == TRANSPORT_SERVICE_CL)
    {
      mp->rx_fifo = pointer_to_uword (ls->rx_fifo);
      mp->tx_fifo = pointer_to_uword (ls->tx_fifo);
    }

done:
  mp->retval = rv;
  svm_msg_q_add_and_unlock (app_mq, msg);
  return 0;
}

static session_cb_vft_t session_mq_cb_vft = {
  .session_accept_callback = mq_send_session_accepted_cb,
  .session_disconnect_callback = mq_send_session_disconnected_cb,
  .session_connected_callback = mq_send_session_connected_cb,
  .session_reset_callback = mq_send_session_reset_cb,
  .add_segment_callback = send_add_segment_callback,
  .del_segment_callback = send_del_segment_callback,
};

static void
vl_api_session_enable_disable_t_handler (vl_api_session_enable_disable_t * mp)
{
  vl_api_session_enable_disable_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;

  vnet_session_enable_disable (vm, mp->is_enable);
  REPLY_MACRO (VL_API_SESSION_ENABLE_DISABLE_REPLY);
}

static void
vl_api_application_attach_t_handler (vl_api_application_attach_t * mp)
{
  int rv = 0, fds[SESSION_N_FD_TYPE], n_fds = 0;
  vl_api_application_attach_reply_t *rmp;
  ssvm_private_t *segp, *evt_q_segment;
  vnet_app_attach_args_t _a, *a = &_a;
  vl_api_registration_t *reg;
  u8 fd_flags = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  STATIC_ASSERT (sizeof (u64) * APP_OPTIONS_N_OPTIONS <=
		 sizeof (mp->options),
		 "Out of options, fix api message definition");

  clib_memset (a, 0, sizeof (*a));
  a->api_client_index = mp->client_index;
  a->options = mp->options;
  a->session_cb_vft = &session_mq_cb_vft;
  if (mp->namespace_id_len > 64)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  if (mp->namespace_id_len)
    {
      vec_validate (a->namespace_id, mp->namespace_id_len - 1);
      clib_memcpy_fast (a->namespace_id, mp->namespace_id,
			mp->namespace_id_len);
    }

  if ((rv = vnet_application_attach (a)))
    {
      clib_warning ("attach returned: %d", rv);
      vec_free (a->namespace_id);
      goto done;
    }
  vec_free (a->namespace_id);

  /* Send event queues segment */
  if ((evt_q_segment = session_main_get_evt_q_segment ()))
    {
      fd_flags |= SESSION_FD_F_VPP_MQ_SEGMENT;
      fds[n_fds] = evt_q_segment->fd;
      n_fds += 1;
    }
  /* Send fifo segment fd if needed */
  if (ssvm_type (a->segment) == SSVM_SEGMENT_MEMFD)
    {
      fd_flags |= SESSION_FD_F_MEMFD_SEGMENT;
      fds[n_fds] = a->segment->fd;
      n_fds += 1;
    }
  if (a->options[APP_OPTIONS_FLAGS] & APP_OPTIONS_FLAGS_EVT_MQ_USE_EVENTFD)
    {
      fd_flags |= SESSION_FD_F_MQ_EVENTFD;
      fds[n_fds] = svm_msg_q_get_producer_eventfd (a->app_evt_q);
      n_fds += 1;
    }

done:

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_APPLICATION_ATTACH_REPLY, ({
    if (!rv)
      {
	segp = a->segment;
	rmp->app_index = clib_host_to_net_u32 (a->app_index);
	rmp->segment_name_length = 0;
	rmp->segment_size = segp->ssvm_size;
	if (vec_len (segp->name))
	  {
	    memcpy (rmp->segment_name, segp->name, vec_len (segp->name));
	    rmp->segment_name_length = vec_len (segp->name);
	  }
	rmp->app_event_queue_address = pointer_to_uword (a->app_evt_q);
	rmp->n_fds = n_fds;
	rmp->fd_flags = fd_flags;
	rmp->segment_handle = clib_host_to_net_u64 (a->segment_handle);
      }
  }));
  /* *INDENT-ON* */

  if (n_fds)
    session_send_fds (reg, fds, n_fds);
}

static void
vl_api_application_detach_t_handler (vl_api_application_detach_t * mp)
{
  vl_api_application_detach_reply_t *rmp;
  int rv = VNET_API_ERROR_INVALID_VALUE_2;
  vnet_app_detach_args_t _a, *a = &_a;
  application_t *app;

  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      a->app_index = app->app_index;
      a->api_client_index = mp->client_index;
      rv = vnet_application_detach (a);
    }

done:
  REPLY_MACRO (VL_API_APPLICATION_DETACH_REPLY);
}

static void
vl_api_bind_uri_t_handler (vl_api_bind_uri_t * mp)
{
  vl_api_bind_uri_reply_t *rmp;
  vnet_listen_args_t _a, *a = &_a;
  application_t *app = 0;
  app_worker_t *app_wrk;
  int rv;

  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      clib_memset (a, 0, sizeof (*a));
      a->uri = (char *) mp->uri;
      a->app_index = app->app_index;
      rv = vnet_bind_uri (a);
    }
  else
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

done:

  REPLY_MACRO (VL_API_BIND_URI_REPLY);

  if (app)
    {
      app_wrk = application_get_worker (app, 0);
      mq_send_session_bound_cb (app_wrk->wrk_index, mp->context, a->handle,
				rv);
    }
}

static void
vl_api_unbind_uri_t_handler (vl_api_unbind_uri_t * mp)
{
  vl_api_unbind_uri_reply_t *rmp;
  application_t *app;
  vnet_unlisten_args_t _a, *a = &_a;
  int rv;

  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      a->uri = (char *) mp->uri;
      a->app_index = app->app_index;
      rv = vnet_unbind_uri (a);
    }
  else
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

done:
  REPLY_MACRO (VL_API_UNBIND_URI_REPLY);
}

static void
vl_api_connect_uri_t_handler (vl_api_connect_uri_t * mp)
{
  vl_api_connect_uri_reply_t *rmp;
  vnet_connect_args_t _a, *a = &_a;
  application_t *app;
  int rv = 0;

  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      clib_memset (a, 0, sizeof (*a));
      a->uri = (char *) mp->uri;
      a->api_context = mp->context;
      a->app_index = app->app_index;
      if ((rv = vnet_connect_uri (a)))
	clib_warning ("connect_uri returned: %d", rv);
    }
  else
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  /*
   * Don't reply to stream (tcp) connects. The reply will come once
   * the connection is established. In case of the redirects, the reply
   * will come from the server app.
   */
  if (rv == 0)
    return;

done:
  REPLY_MACRO (VL_API_CONNECT_URI_REPLY);
}

static void
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  vl_api_disconnect_session_reply_t *rmp;
  vnet_disconnect_args_t _a, *a = &_a;
  application_t *app;
  int rv = 0;

  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      a->handle = mp->handle;
      a->app_index = app->app_index;
      rv = vnet_disconnect_session (a);
    }
  else
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

done:
  REPLY_MACRO2 (VL_API_DISCONNECT_SESSION_REPLY, rmp->handle = mp->handle);
}

static void
vl_api_disconnect_session_reply_t_handler (vl_api_disconnect_session_reply_t *
					   mp)
{
  vnet_disconnect_args_t _a, *a = &_a;
  application_t *app;

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
vl_api_map_another_segment_reply_t_handler (vl_api_map_another_segment_reply_t
					    * mp)
{
  clib_warning ("not implemented");
}

static void
vl_api_bind_sock_t_handler (vl_api_bind_sock_t * mp)
{
  vnet_listen_args_t _a, *a = &_a;
  vl_api_bind_sock_reply_t *rmp;
  application_t *app = 0;
  app_worker_t *app_wrk;
  ip46_address_t *ip46;
  int rv = 0;

  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (!app)
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
      goto done;
    }

  ip46 = (ip46_address_t *) mp->ip;
  clib_memset (a, 0, sizeof (*a));
  a->sep.is_ip4 = mp->is_ip4;
  a->sep.ip = *ip46;
  a->sep.port = mp->port;
  a->sep.fib_index = mp->vrf;
  a->sep.sw_if_index = ENDPOINT_INVALID_INDEX;
  a->sep.transport_proto = mp->proto;
  a->app_index = app->app_index;
  a->wrk_map_index = mp->wrk_index;

  if ((rv = vnet_listen (a)))
    clib_warning ("listen returned: %d", rv);

done:
  /* Actual reply sent only over mq */
  REPLY_MACRO (VL_API_BIND_SOCK_REPLY);

  if (app)
    {
      app_wrk = application_get_worker (app, mp->wrk_index);
      mq_send_session_bound_cb (app_wrk->wrk_index, mp->context, a->handle,
				rv);
    }
}

static void
vl_api_unbind_sock_t_handler (vl_api_unbind_sock_t * mp)
{
  vl_api_unbind_sock_reply_t *rmp;
  vnet_unlisten_args_t _a, *a = &_a;
  app_worker_t *app_wrk;
  application_t *app = 0;
  int rv = 0;

  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      a->app_index = app->app_index;
      a->handle = mp->handle;
      a->wrk_map_index = mp->wrk_index;
      if ((rv = vnet_unlisten (a)))
	clib_warning ("unlisten returned: %d", rv);
    }

done:
  REPLY_MACRO (VL_API_UNBIND_SOCK_REPLY);

  /*
   * Send reply over msg queue
   */
  svm_msg_q_msg_t _msg, *msg = &_msg;
  session_unlisten_reply_msg_t *ump;
  svm_msg_q_t *app_mq;
  session_event_t *evt;

  if (!app)
    return;

  app_wrk = application_get_worker (app, a->wrk_map_index);
  if (!app_wrk)
    return;

  app_mq = app_wrk->event_queue;
  if (mq_try_lock_and_alloc_msg (app_mq, msg))
    return;

  evt = svm_msg_q_msg_data (app_mq, msg);
  clib_memset (evt, 0, sizeof (*evt));
  evt->event_type = SESSION_CTRL_EVT_UNLISTEN_REPLY;
  ump = (session_unlisten_reply_msg_t *) evt->data;
  ump->context = mp->context;
  ump->handle = mp->handle;
  ump->retval = rv;
  svm_msg_q_add_and_unlock (app_mq, msg);
}

static void
vl_api_connect_sock_t_handler (vl_api_connect_sock_t * mp)
{
  vl_api_connect_sock_reply_t *rmp;
  vnet_connect_args_t _a, *a = &_a;
  application_t *app = 0;
  int rv = 0;

  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  app = application_lookup (mp->client_index);
  if (app)
    {
      svm_queue_t *client_q;
      ip46_address_t *ip46 = (ip46_address_t *) mp->ip;

      clib_memset (a, 0, sizeof (*a));
      client_q = vl_api_client_index_to_input_queue (mp->client_index);
      mp->client_queue_address = pointer_to_uword (client_q);
      a->sep.is_ip4 = mp->is_ip4;
      a->sep.ip = *ip46;
      a->sep.port = mp->port;
      a->sep.transport_proto = mp->proto;
      a->sep.peer.fib_index = mp->vrf;
      a->sep.peer.sw_if_index = ENDPOINT_INVALID_INDEX;
      if (mp->hostname_len)
	{
	  vec_validate (a->sep_ext.hostname, mp->hostname_len - 1);
	  clib_memcpy_fast (a->sep_ext.hostname, mp->hostname,
			    mp->hostname_len);
	}
      a->api_context = mp->context;
      a->app_index = app->app_index;
      a->wrk_map_index = mp->wrk_index;
      if ((rv = vnet_connect (a)))
	clib_warning ("connect returned: %u", rv);
      vec_free (a->sep_ext.hostname);
    }
  else
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  if (rv == 0)
    return;

  /* Got some error, relay it */

done:
  REPLY_MACRO (VL_API_CONNECT_SOCK_REPLY);

  if (app)
    {
      app_worker_t *app_wrk = application_get_worker (app, mp->wrk_index);
      mq_send_session_connected_cb (app_wrk->wrk_index, mp->context, 0, 1);
    }
}

static void
vl_api_app_worker_add_del_t_handler (vl_api_app_worker_add_del_t * mp)
{
  int rv = 0, fds[SESSION_N_FD_TYPE], n_fds = 0;
  vl_api_app_worker_add_del_reply_t *rmp;
  vl_api_registration_t *reg;
  application_t *app;
  u8 fd_flags = 0;

  if (!session_main_is_enabled ())
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  app = application_get_if_valid (clib_net_to_host_u32 (mp->app_index));
  if (!app)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  vnet_app_worker_add_del_args_t args = {
    .app_index = app->app_index,
    .wrk_map_index = clib_net_to_host_u32 (mp->wrk_index),
    .api_client_index = mp->client_index,
    .is_add = mp->is_add
  };
  rv = vnet_app_worker_add_del (&args);
  if (rv)
    {
      clib_warning ("app worker add/del returned: %d", rv);
      goto done;
    }

  if (!mp->is_add)
    goto done;

  /* Send fifo segment fd if needed */
  if (ssvm_type (args.segment) == SSVM_SEGMENT_MEMFD)
    {
      fd_flags |= SESSION_FD_F_MEMFD_SEGMENT;
      fds[n_fds] = args.segment->fd;
      n_fds += 1;
    }
  if (application_segment_manager_properties (app)->use_mq_eventfd)
    {
      fd_flags |= SESSION_FD_F_MQ_EVENTFD;
      fds[n_fds] = svm_msg_q_get_producer_eventfd (args.evt_q);
      n_fds += 1;
    }

  /* *INDENT-OFF* */
done:
  REPLY_MACRO2 (VL_API_APP_WORKER_ADD_DEL_REPLY, ({
    rmp->is_add = mp->is_add;
    rmp->wrk_index = clib_host_to_net_u32 (args.wrk_map_index);
    rmp->segment_handle = clib_host_to_net_u64 (args.segment_handle);
    if (!rv && mp->is_add)
      {
	if (vec_len (args.segment->name))
	  {
	    memcpy (rmp->segment_name, args.segment->name,
	            vec_len (args.segment->name));
	    rmp->segment_name_length = vec_len (args.segment->name);
	  }
	rmp->app_event_queue_address = pointer_to_uword (args.evt_q);
	rmp->n_fds = n_fds;
	rmp->fd_flags = fd_flags;
      }
  }));
  /* *INDENT-ON* */

  if (n_fds)
    session_send_fds (reg, fds, n_fds);
}

static void
vl_api_app_namespace_add_del_t_handler (vl_api_app_namespace_add_del_t * mp)
{
  vl_api_app_namespace_add_del_reply_t *rmp;
  u32 appns_index = 0;
  u8 *ns_id = 0;
  int rv = 0;
  if (!session_main_is_enabled ())
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  if (mp->namespace_id_len > ARRAY_LEN (mp->namespace_id))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  vec_validate (ns_id, mp->namespace_id_len - 1);
  clib_memcpy_fast (ns_id, mp->namespace_id, mp->namespace_id_len);
  vnet_app_namespace_add_del_args_t args = {
    .ns_id = ns_id,
    .secret = clib_net_to_host_u64 (mp->secret),
    .sw_if_index = clib_net_to_host_u32 (mp->sw_if_index),
    .ip4_fib_id = clib_net_to_host_u32 (mp->ip4_fib_id),
    .ip6_fib_id = clib_net_to_host_u32 (mp->ip6_fib_id),
    .is_add = 1
  };
  rv = vnet_app_namespace_add_del (&args);
  if (!rv)
    {
      appns_index = app_namespace_index_from_id (ns_id);
      if (appns_index == APP_NAMESPACE_INVALID_INDEX)
	{
	  clib_warning ("app ns lookup failed");
	  rv = VNET_API_ERROR_UNSPECIFIED;
	}
    }
  vec_free (ns_id);

  /* *INDENT-OFF* */
done:
  REPLY_MACRO2 (VL_API_APP_NAMESPACE_ADD_DEL_REPLY, ({
    if (!rv)
      rmp->appns_index = clib_host_to_net_u32 (appns_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_session_rule_add_del_t_handler (vl_api_session_rule_add_del_t * mp)
{
  vl_api_session_rule_add_del_reply_t *rmp;
  session_rule_add_del_args_t args;
  session_rule_table_add_del_args_t *table_args = &args.table_args;
  u8 fib_proto;
  int rv = 0;

  clib_memset (&args, 0, sizeof (args));
  fib_proto = mp->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;

  table_args->lcl.fp_len = mp->lcl_plen;
  table_args->lcl.fp_proto = fib_proto;
  table_args->rmt.fp_len = mp->rmt_plen;
  table_args->rmt.fp_proto = fib_proto;
  table_args->lcl_port = mp->lcl_port;
  table_args->rmt_port = mp->rmt_port;
  table_args->action_index = clib_net_to_host_u32 (mp->action_index);
  table_args->is_add = mp->is_add;
  mp->tag[sizeof (mp->tag) - 1] = 0;
  table_args->tag = format (0, "%s", mp->tag);
  args.appns_index = clib_net_to_host_u32 (mp->appns_index);
  args.scope = mp->scope;
  args.transport_proto = mp->transport_proto;

  clib_memset (&table_args->lcl.fp_addr, 0, sizeof (table_args->lcl.fp_addr));
  clib_memset (&table_args->rmt.fp_addr, 0, sizeof (table_args->rmt.fp_addr));
  ip_set (&table_args->lcl.fp_addr, mp->lcl_ip, mp->is_ip4);
  ip_set (&table_args->rmt.fp_addr, mp->rmt_ip, mp->is_ip4);
  rv = vnet_session_rule_add_del (&args);
  if (rv)
    clib_warning ("rule add del returned: %d", rv);
  vec_free (table_args->tag);
  REPLY_MACRO (VL_API_SESSION_RULE_ADD_DEL_REPLY);
}

static void
send_session_rule_details4 (mma_rule_16_t * rule, u8 is_local,
			    u8 transport_proto, u32 appns_index, u8 * tag,
			    vl_api_registration_t * reg, u32 context)
{
  vl_api_session_rules_details_t *rmp = 0;
  session_mask_or_match_4_t *match =
    (session_mask_or_match_4_t *) & rule->match;
  session_mask_or_match_4_t *mask =
    (session_mask_or_match_4_t *) & rule->mask;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SESSION_RULES_DETAILS);
  rmp->context = context;

  rmp->is_ip4 = 1;
  clib_memcpy_fast (rmp->lcl_ip, &match->lcl_ip, sizeof (match->lcl_ip));
  clib_memcpy_fast (rmp->rmt_ip, &match->rmt_ip, sizeof (match->rmt_ip));
  rmp->lcl_plen = ip4_mask_to_preflen (&mask->lcl_ip);
  rmp->rmt_plen = ip4_mask_to_preflen (&mask->rmt_ip);
  rmp->lcl_port = match->lcl_port;
  rmp->rmt_port = match->rmt_port;
  rmp->action_index = clib_host_to_net_u32 (rule->action_index);
  rmp->scope =
    is_local ? SESSION_RULE_SCOPE_LOCAL : SESSION_RULE_SCOPE_GLOBAL;
  rmp->transport_proto = transport_proto;
  rmp->appns_index = clib_host_to_net_u32 (appns_index);
  if (tag)
    {
      clib_memcpy_fast (rmp->tag, tag, vec_len (tag));
      rmp->tag[vec_len (tag)] = 0;
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_session_rule_details6 (mma_rule_40_t * rule, u8 is_local,
			    u8 transport_proto, u32 appns_index, u8 * tag,
			    vl_api_registration_t * reg, u32 context)
{
  vl_api_session_rules_details_t *rmp = 0;
  session_mask_or_match_6_t *match =
    (session_mask_or_match_6_t *) & rule->match;
  session_mask_or_match_6_t *mask =
    (session_mask_or_match_6_t *) & rule->mask;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SESSION_RULES_DETAILS);
  rmp->context = context;

  rmp->is_ip4 = 0;
  clib_memcpy_fast (rmp->lcl_ip, &match->lcl_ip, sizeof (match->lcl_ip));
  clib_memcpy_fast (rmp->rmt_ip, &match->rmt_ip, sizeof (match->rmt_ip));
  rmp->lcl_plen = ip6_mask_to_preflen (&mask->lcl_ip);
  rmp->rmt_plen = ip6_mask_to_preflen (&mask->rmt_ip);
  rmp->lcl_port = match->lcl_port;
  rmp->rmt_port = match->rmt_port;
  rmp->action_index = clib_host_to_net_u32 (rule->action_index);
  rmp->scope =
    is_local ? SESSION_RULE_SCOPE_LOCAL : SESSION_RULE_SCOPE_GLOBAL;
  rmp->transport_proto = transport_proto;
  rmp->appns_index = clib_host_to_net_u32 (appns_index);
  if (tag)
    {
      clib_memcpy_fast (rmp->tag, tag, vec_len (tag));
      rmp->tag[vec_len (tag)] = 0;
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_session_rules_table_details (session_rules_table_t * srt, u8 fib_proto,
				  u8 tp, u8 is_local, u32 appns_index,
				  vl_api_registration_t * reg, u32 context)
{
  mma_rule_16_t *rule16;
  mma_rule_40_t *rule40;
  mma_rules_table_16_t *srt16;
  mma_rules_table_40_t *srt40;
  u32 ri;

  if (is_local || fib_proto == FIB_PROTOCOL_IP4)
    {
      u8 *tag = 0;
      /* *INDENT-OFF* */
      srt16 = &srt->session_rules_tables_16;
      pool_foreach (rule16, srt16->rules, ({
	ri = mma_rules_table_rule_index_16 (srt16, rule16);
	tag = session_rules_table_rule_tag (srt, ri, 1);
        send_session_rule_details4 (rule16, is_local, tp, appns_index, tag,
                                    reg, context);
      }));
      /* *INDENT-ON* */
    }
  if (is_local || fib_proto == FIB_PROTOCOL_IP6)
    {
      u8 *tag = 0;
      /* *INDENT-OFF* */
      srt40 = &srt->session_rules_tables_40;
      pool_foreach (rule40, srt40->rules, ({
	ri = mma_rules_table_rule_index_40 (srt40, rule40);
	tag = session_rules_table_rule_tag (srt, ri, 1);
        send_session_rule_details6 (rule40, is_local, tp, appns_index, tag,
                                    reg, context);
      }));
      /* *INDENT-ON* */
    }
}

static void
vl_api_session_rules_dump_t_handler (vl_api_one_map_server_dump_t * mp)
{
  vl_api_registration_t *reg;
  session_table_t *st;
  u8 tp;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  session_table_foreach (st, ({
    for (tp = 0; tp < TRANSPORT_N_PROTO; tp++)
      {
        send_session_rules_table_details (&st->session_rules[tp],
                                          st->active_fib_proto, tp,
                                          st->is_local, st->appns_index, reg,
                                          mp->context);
      }
  }));
  /* *INDENT-ON* */
}

static void
vl_api_application_tls_cert_add_t_handler (vl_api_application_tls_cert_add_t *
					   mp)
{
  vl_api_app_namespace_add_del_reply_t *rmp;
  vnet_app_add_tls_cert_args_t _a, *a = &_a;
  clib_error_t *error;
  application_t *app;
  u32 cert_len;
  int rv = 0;
  if (!session_main_is_enabled ())
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }
  if (!(app = application_lookup (mp->client_index)))
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
      goto done;
    }
  clib_memset (a, 0, sizeof (*a));
  a->app_index = app->app_index;
  cert_len = clib_net_to_host_u16 (mp->cert_len);
  if (cert_len > 10000)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  vec_validate (a->cert, cert_len);
  clib_memcpy_fast (a->cert, mp->cert, cert_len);
  if ((error = vnet_app_add_tls_cert (a)))
    {
      rv = clib_error_get_code (error);
      clib_error_report (error);
    }
  vec_free (a->cert);
done:
  REPLY_MACRO (VL_API_APPLICATION_TLS_CERT_ADD_REPLY);
}

static void
vl_api_application_tls_key_add_t_handler (vl_api_application_tls_key_add_t *
					  mp)
{
  vl_api_app_namespace_add_del_reply_t *rmp;
  vnet_app_add_tls_key_args_t _a, *a = &_a;
  clib_error_t *error;
  application_t *app;
  u32 key_len;
  int rv = 0;
  if (!session_main_is_enabled ())
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }
  if (!(app = application_lookup (mp->client_index)))
    {
      rv = VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
      goto done;
    }
  clib_memset (a, 0, sizeof (*a));
  a->app_index = app->app_index;
  key_len = clib_net_to_host_u16 (mp->key_len);
  if (key_len > 10000)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  vec_validate (a->key, key_len);
  clib_memcpy_fast (a->key, mp->key, key_len);
  if ((error = vnet_app_add_tls_key (a)))
    {
      rv = clib_error_get_code (error);
      clib_error_report (error);
    }
  vec_free (a->key);
done:
  REPLY_MACRO (VL_API_APPLICATION_TLS_KEY_ADD_REPLY);
}

static clib_error_t *
application_reaper_cb (u32 client_index)
{
  application_t *app = application_lookup (client_index);
  vnet_app_detach_args_t _a, *a = &_a;
  if (app)
    {
      a->app_index = app->app_index;
      a->api_client_index = client_index;
      vnet_application_detach (a);
    }
  return 0;
}

VL_MSG_API_REAPER_FUNCTION (application_reaper_cb);

#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_session;
#undef _
}

/*
 * session_api_hookup
 * Add uri's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../open-repo/vlib/memclnt_vlib.c:memclnt_process()
 */
static clib_error_t *
session_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_session_api_msg;
#undef _

  /*
   * Messages which bounce off the data-plane to
   * an API client. Simply tells the message handling infra not
   * to free the message.
   *
   * Bounced message handlers MUST NOT block the data plane
   */
  am->message_bounce[VL_API_CONNECT_URI] = 1;
  am->message_bounce[VL_API_CONNECT_SOCK] = 1;

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (session_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
