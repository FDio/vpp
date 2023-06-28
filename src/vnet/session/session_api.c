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
#include <vnet/ip/ip_types_api.h>

#include <vnet/format_fns.h>
#include <vnet/session/session.api_enum.h>
#include <vnet/session/session.api_types.h>

#define REPLY_MSG_ID_BASE session_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static transport_proto_t
api_session_transport_proto_decode (const vl_api_transport_proto_t * api_tp)
{
  switch (*api_tp)
    {
    case TRANSPORT_PROTO_API_TCP:
      return TRANSPORT_PROTO_TCP;
    case TRANSPORT_PROTO_API_UDP:
      return TRANSPORT_PROTO_UDP;
    case TRANSPORT_PROTO_API_TLS:
      return TRANSPORT_PROTO_TLS;
    case TRANSPORT_PROTO_API_QUIC:
      return TRANSPORT_PROTO_QUIC;
    default:
      return TRANSPORT_PROTO_NONE;
    }
}

static vl_api_transport_proto_t
api_session_transport_proto_encode (const transport_proto_t tp)
{
  switch (tp)
    {
    case TRANSPORT_PROTO_TCP:
      return TRANSPORT_PROTO_API_TCP;
    case TRANSPORT_PROTO_UDP:
      return TRANSPORT_PROTO_API_UDP;
    case TRANSPORT_PROTO_TLS:
      return TRANSPORT_PROTO_API_TLS;
    case TRANSPORT_PROTO_QUIC:
      return TRANSPORT_PROTO_API_QUIC;
    default:
      return TRANSPORT_PROTO_API_NONE;
    }
}

static int
session_send_fds (vl_api_registration_t * reg, int fds[], int n_fds)
{
  clib_error_t *error;
  if (vl_api_registration_file_index (reg) == VL_API_INVALID_FI)
    return SESSION_E_BAPI_NO_FD;
  error = vl_api_send_fd_msg (reg, fds, n_fds);
  if (error)
    {
      clib_error_report (error);
      return SESSION_E_BAPI_SEND_FD;
    }
  return 0;
}

static int
mq_send_session_accepted_cb (session_t * s)
{
  app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
  session_accepted_msg_t m = { 0 };
  fifo_segment_t *eq_seg;
  session_t *listener;
  application_t *app;

  app = application_get (app_wrk->app_index);

  m.context = app->app_index;
  m.server_rx_fifo = fifo_segment_fifo_offset (s->rx_fifo);
  m.server_tx_fifo = fifo_segment_fifo_offset (s->tx_fifo);
  m.segment_handle = session_segment_handle (s);
  m.flags = s->flags;

  eq_seg = application_get_rx_mqs_segment (app);

  if (session_has_transport (s))
    {
      listener = listen_session_get_from_handle (s->listener_handle);
      m.listener_handle = app_listen_session_handle (listener);
      if (application_is_proxy (app))
	{
	  listener =
	    app_worker_first_listener (app_wrk, session_get_fib_proto (s),
				       session_get_transport_proto (s));
	  if (listener)
	    m.listener_handle = listen_session_get_handle (listener);
	}
      m.vpp_event_queue_address =
	fifo_segment_msg_q_offset (eq_seg, s->thread_index);
      m.mq_index = s->thread_index;
      m.handle = session_handle (s);

      session_get_endpoint (s, &m.rmt, 0 /* is_lcl */);
      session_get_endpoint (s, &m.lcl, 1 /* is_lcl */);
    }
  else
    {
      ct_connection_t *ct;

      ct = (ct_connection_t *) session_get_transport (s);
      listener = listen_session_get_from_handle (s->listener_handle);
      m.listener_handle = app_listen_session_handle (listener);
      m.rmt.is_ip4 = session_type_is_ip4 (listener->session_type);
      m.rmt.port = ct->c_rmt_port;
      m.lcl.port = ct->c_lcl_port;
      m.handle = session_handle (s);
      m.vpp_event_queue_address =
	fifo_segment_msg_q_offset (eq_seg, s->thread_index);
      m.mq_index = s->thread_index;
    }

  if (application_original_dst_is_enabled (app))
    {
      session_get_original_dst (&m.lcl, &m.rmt,
				session_get_transport_proto (s),
				&m.original_dst_ip4, &m.original_dst_port);
    }

  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_ACCEPTED, &m, sizeof (m));

  return 0;
}

static inline void
mq_send_session_close_evt (app_worker_t * app_wrk, session_handle_t sh,
			   session_evt_type_t evt_type)
{
  session_disconnected_msg_t m = { 0 };

  m.handle = sh;
  m.context = app_wrk->api_client_index;

  app_wrk_send_ctrl_evt (app_wrk, evt_type, &m, sizeof (m));
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

  for (i = 0; i < f->shr->n_subscribers; i++)
    {
      if (!(app_wrk = application_get_worker (app, f->shr->subscribers[i])))
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

int
mq_send_session_connected_cb (u32 app_wrk_index, u32 api_context,
			      session_t * s, session_error_t err)
{
  session_connected_msg_t m = { 0 };
  transport_connection_t *tc;
  fifo_segment_t *eq_seg;
  app_worker_t *app_wrk;
  application_t *app;

  app_wrk = app_worker_get (app_wrk_index);

  m.context = api_context;
  m.retval = err;

  if (err)
    goto snd_msg;

  app = application_get (app_wrk->app_index);
  eq_seg = application_get_rx_mqs_segment (app);

  if (session_has_transport (s))
    {
      tc = session_get_transport (s);
      if (!tc)
	{
	  clib_warning ("failed to retrieve transport!");
	  m.retval = SESSION_E_REFUSED;
	  goto snd_msg;
	}

      m.handle = session_handle (s);
      m.vpp_event_queue_address =
	fifo_segment_msg_q_offset (eq_seg, s->thread_index);

      session_get_endpoint (s, &m.lcl, 1 /* is_lcl */);

      m.server_rx_fifo = fifo_segment_fifo_offset (s->rx_fifo);
      m.server_tx_fifo = fifo_segment_fifo_offset (s->tx_fifo);
      m.segment_handle = session_segment_handle (s);
      m.mq_index = s->thread_index;
    }
  else
    {
      ct_connection_t *cct;
      session_t *ss;

      cct = (ct_connection_t *) session_get_transport (s);
      m.handle = session_handle (s);
      m.lcl.port = cct->c_lcl_port;
      m.lcl.is_ip4 = cct->c_is_ip4;
      m.vpp_event_queue_address =
	fifo_segment_msg_q_offset (eq_seg, s->thread_index);
      m.server_rx_fifo = fifo_segment_fifo_offset (s->rx_fifo);
      m.server_tx_fifo = fifo_segment_fifo_offset (s->tx_fifo);
      m.segment_handle = session_segment_handle (s);
      ss = ct_session_get_peer (s);
      m.ct_rx_fifo = fifo_segment_fifo_offset (ss->tx_fifo);
      m.ct_tx_fifo = fifo_segment_fifo_offset (ss->rx_fifo);
      m.ct_segment_handle = session_segment_handle (ss);
      m.mq_index = s->thread_index;
    }

  /* Setup client session index in advance, in case data arrives
   * before the app processes message and updates it */
  s->rx_fifo->shr->client_session_index = api_context;
  s->tx_fifo->shr->client_session_index = api_context;

snd_msg:

  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_CONNECTED, &m, sizeof (m));

  return 0;
}

int
mq_send_session_bound_cb (u32 app_wrk_index, u32 api_context,
			  session_handle_t handle, int rv)
{
  session_bound_msg_t m = { 0 };
  transport_endpoint_t tep;
  fifo_segment_t *eq_seg;
  app_worker_t *app_wrk;
  application_t *app;
  app_listener_t *al;
  session_t *ls = 0;

  app_wrk = app_worker_get (app_wrk_index);

  m.context = api_context;
  m.retval = rv;

  if (rv)
    goto snd_msg;

  m.handle = handle;
  al = app_listener_get_w_handle (handle);
  if (al->session_index != SESSION_INVALID_INDEX)
    ls = app_listener_get_session (al);
  else
    ls = app_listener_get_local_session (al);

  session_get_endpoint (ls, &tep, 1 /* is_lcl */);
  m.lcl_port = tep.port;
  m.lcl_is_ip4 = tep.is_ip4;
  clib_memcpy_fast (m.lcl_ip, &tep.ip, sizeof (tep.ip));
  app = application_get (app_wrk->app_index);
  eq_seg = application_get_rx_mqs_segment (app);
  m.vpp_evt_q = fifo_segment_msg_q_offset (eq_seg, ls->thread_index);
  m.mq_index = ls->thread_index;

  if (session_transport_service_type (ls) == TRANSPORT_SERVICE_CL &&
      ls->rx_fifo)
    {
      m.mq_index = transport_cl_thread ();
      m.vpp_evt_q = fifo_segment_msg_q_offset (eq_seg, m.mq_index);
      m.rx_fifo = fifo_segment_fifo_offset (ls->rx_fifo);
      m.tx_fifo = fifo_segment_fifo_offset (ls->tx_fifo);
      m.segment_handle = session_segment_handle (ls);
    }

snd_msg:

  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_BOUND, &m, sizeof (m));

  return 0;
}

void
mq_send_unlisten_reply (app_worker_t * app_wrk, session_handle_t sh,
			u32 context, int rv)
{
  session_unlisten_reply_msg_t m = { 0 };

  m.context = context;
  m.handle = sh;
  m.retval = rv;
  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_UNLISTEN_REPLY, &m,
			 sizeof (m));
}

static void
mq_send_session_migrate_cb (session_t * s, session_handle_t new_sh)
{
  session_migrated_msg_t m = { 0 };
  fifo_segment_t *eq_seg;
  app_worker_t *app_wrk;
  application_t *app;
  u32 thread_index;

  thread_index = session_thread_from_handle (new_sh);
  app_wrk = app_worker_get (s->app_wrk_index);
  app = application_get (app_wrk->app_index);
  eq_seg = application_get_rx_mqs_segment (app);

  m.handle = session_handle (s);
  m.new_handle = new_sh;
  m.vpp_thread_index = thread_index;
  m.vpp_evt_q = fifo_segment_msg_q_offset (eq_seg, thread_index);
  m.segment_handle = SESSION_INVALID_HANDLE;

  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_MIGRATED, &m, sizeof (m));
}

static int
mq_send_add_segment_cb (u32 app_wrk_index, u64 segment_handle)
{
  session_app_add_segment_msg_t m = { 0 };
  vl_api_registration_t *reg;
  app_worker_t *app_wrk;
  fifo_segment_t *fs;
  ssvm_private_t *sp;
  u8 fd_flags = 0;

  app_wrk = app_worker_get (app_wrk_index);

  reg = vl_mem_api_client_index_to_registration (app_wrk->api_client_index);
  if (!reg)
    {
      clib_warning ("no api registration for client: %u",
		    app_wrk->api_client_index);
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
    }

  m.segment_size = sp->ssvm_size;
  m.fd_flags = fd_flags;
  m.segment_handle = segment_handle;
  strncpy ((char *) m.segment_name, (char *) sp->name,
	   sizeof (m.segment_name) - 1);

  app_wrk_send_ctrl_evt_fd (app_wrk, SESSION_CTRL_EVT_APP_ADD_SEGMENT, &m,
			    sizeof (m), sp->fd);

  return 0;
}

static int
mq_send_del_segment_cb (u32 app_wrk_index, u64 segment_handle)
{
  session_app_del_segment_msg_t m = { 0 };
  vl_api_registration_t *reg;
  app_worker_t *app_wrk;

  app_wrk = app_worker_get (app_wrk_index);
  reg = vl_mem_api_client_index_to_registration (app_wrk->api_client_index);
  if (!reg)
    {
      clib_warning ("no registration: %u", app_wrk->api_client_index);
      return -1;
    }

  m.segment_handle = segment_handle;

  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_APP_DEL_SEGMENT, &m,
			 sizeof (m));

  return 0;
}

static void
mq_send_session_cleanup_cb (session_t * s, session_cleanup_ntf_t ntf)
{
  session_cleanup_msg_t m = { 0 };
  app_worker_t *app_wrk;

  /* Propagate transport cleanup notifications only if app didn't close */
  if (ntf == SESSION_CLEANUP_TRANSPORT
      && s->session_state != SESSION_STATE_TRANSPORT_DELETED)
    return;

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (!app_wrk)
    return;

  m.handle = session_handle (s);
  m.type = ntf;

  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_CLEANUP, &m, sizeof (m));
}

static session_cb_vft_t session_mq_cb_vft = {
  .session_accept_callback = mq_send_session_accepted_cb,
  .session_disconnect_callback = mq_send_session_disconnected_cb,
  .session_connected_callback = mq_send_session_connected_cb,
  .session_reset_callback = mq_send_session_reset_cb,
  .session_migrate_callback = mq_send_session_migrate_cb,
  .session_cleanup_callback = mq_send_session_cleanup_cb,
  .add_segment_callback = mq_send_add_segment_cb,
  .del_segment_callback = mq_send_del_segment_cb,
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
vl_api_session_sapi_enable_disable_t_handler (
  vl_api_session_sapi_enable_disable_t *mp)
{
  vl_api_session_sapi_enable_disable_reply_t *rmp;
  int rv = 0;

  rv = appns_sapi_enable_disable (mp->is_enable);
  REPLY_MACRO (VL_API_SESSION_SAPI_ENABLE_DISABLE_REPLY);
}

static void
vl_api_app_attach_t_handler (vl_api_app_attach_t * mp)
{
  int rv = 0, *fds = 0, n_fds = 0, n_workers, i;
  fifo_segment_t *segp, *rx_mqs_seg = 0;
  vnet_app_attach_args_t _a, *a = &_a;
  vl_api_app_attach_reply_t *rmp;
  u8 fd_flags = 0, ctrl_thread;
  vl_api_registration_t *reg;
  svm_msg_q_t *rx_mq;
  application_t *app;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  n_workers = vlib_num_workers ();
  if (!session_main_is_enabled () || appns_sapi_enabled ())
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }
  /* Only support binary api with socket transport */
  if (vl_api_registration_file_index (reg) == VL_API_INVALID_FI)
    {
      rv = VNET_API_ERROR_APP_UNSUPPORTED_CFG;
      goto done;
    }

  STATIC_ASSERT (sizeof (u64) * APP_OPTIONS_N_OPTIONS <=
		 sizeof (mp->options),
		 "Out of options, fix api message definition");

  clib_memset (a, 0, sizeof (*a));
  a->api_client_index = mp->client_index;
  a->options = mp->options;
  a->session_cb_vft = &session_mq_cb_vft;
  a->namespace_id = vl_api_from_api_to_new_vec (mp, &mp->namespace_id);

  if ((rv = vnet_application_attach (a)))
    {
      clib_warning ("attach returned: %U", format_session_error, rv);
      rv = VNET_API_ERROR_UNSPECIFIED;
      vec_free (a->namespace_id);
      goto done;
    }
  vec_free (a->namespace_id);

  vec_validate (fds, 3 /* segs + tx evtfd */ + n_workers);

  /* Send rx mqs segment */
  app = application_get (a->app_index);
  rx_mqs_seg = application_get_rx_mqs_segment (app);

  fd_flags |= SESSION_FD_F_VPP_MQ_SEGMENT;
  fds[n_fds] = rx_mqs_seg->ssvm.fd;
  n_fds += 1;

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
      fds[n_fds] = svm_msg_q_get_eventfd (a->app_evt_q);
      n_fds += 1;
    }

  if (application_use_private_rx_mqs ())
    {
      fd_flags |= SESSION_FD_F_VPP_MQ_EVENTFD;
      for (i = 0; i < n_workers + 1; i++)
	{
	  rx_mq = application_rx_mq_get (app, i);
	  fds[n_fds] = svm_msg_q_get_eventfd (rx_mq);
	  n_fds += 1;
	}
    }

done:
  /* *INDENT-OFF* */
  REPLY_MACRO3 (
    VL_API_APP_ATTACH_REPLY,
    ((!rv) ? vec_len (((fifo_segment_t *) a->segment)->ssvm.name) : 0), ({
      if (!rv)
	{
	  ctrl_thread = n_workers ? 1 : 0;
	  segp = (fifo_segment_t *) a->segment;
	  rmp->app_index = clib_host_to_net_u32 (a->app_index);
	  rmp->app_mq = fifo_segment_msg_q_offset (segp, 0);
	  rmp->vpp_ctrl_mq =
	    fifo_segment_msg_q_offset (rx_mqs_seg, ctrl_thread);
	  rmp->vpp_ctrl_mq_thread = ctrl_thread;
	  rmp->n_fds = n_fds;
	  rmp->fd_flags = fd_flags;
	  if (vec_len (segp->ssvm.name))
	    {
	      vl_api_vec_to_api_string (segp->ssvm.name, &rmp->segment_name);
	    }
	  rmp->segment_size = segp->ssvm.ssvm_size;
	  rmp->segment_handle = clib_host_to_net_u64 (a->segment_handle);
	}
    }));
  /* *INDENT-ON* */

  if (n_fds)
    session_send_fds (reg, fds, n_fds);
  vec_free (fds);
}

static void
vl_api_app_worker_add_del_t_handler (vl_api_app_worker_add_del_t * mp)
{
  int rv = 0, fds[SESSION_N_FD_TYPE], n_fds = 0;
  vl_api_app_worker_add_del_reply_t *rmp;
  vl_api_registration_t *reg;
  application_t *app;
  u8 fd_flags = 0;

  if (!session_main_is_enabled () || appns_sapi_enabled ())
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
      clib_warning ("app worker add/del returned: %U", format_session_error,
		    rv);
      rv = VNET_API_ERROR_UNSPECIFIED;
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
      fds[n_fds] = svm_msg_q_get_eventfd (args.evt_q);
      n_fds += 1;
    }

  /* *INDENT-OFF* */
done:
  REPLY_MACRO3 (
    VL_API_APP_WORKER_ADD_DEL_REPLY,
    ((!rv && mp->is_add) ? vec_len (args.segment->name) : 0), ({
      rmp->is_add = mp->is_add;
      rmp->wrk_index = clib_host_to_net_u32 (args.wrk_map_index);
      rmp->segment_handle = clib_host_to_net_u64 (args.segment_handle);
      if (!rv && mp->is_add)
	{
	  rmp->app_event_queue_address =
	    fifo_segment_msg_q_offset ((fifo_segment_t *) args.segment, 0);
	  rmp->n_fds = n_fds;
	  rmp->fd_flags = fd_flags;
	  if (vec_len (args.segment->name))
	    {
	      vl_api_vec_to_api_string (args.segment->name,
					&rmp->segment_name);
	    }
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

  if (!session_main_is_enabled () || appns_sapi_enabled ())
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
      if (rv)
	{
	  clib_warning ("vnet_application_detach: %U", format_session_error,
			rv);
	  rv = VNET_API_ERROR_UNSPECIFIED;
	}
    }

done:
  REPLY_MACRO (VL_API_APPLICATION_DETACH_REPLY);
}

static void
vl_api_app_namespace_add_del_t_handler (vl_api_app_namespace_add_del_t * mp)
{
  vl_api_app_namespace_add_del_reply_t *rmp;
  u32 appns_index = 0;
  u8 *ns_id = 0;
  int rv = 0;
  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  ns_id = vl_api_from_api_to_new_vec (mp, &mp->namespace_id);

  vnet_app_namespace_add_del_args_t args = {
    .ns_id = ns_id,
    .sock_name = 0,
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
vl_api_app_namespace_add_del_v2_t_handler (
  vl_api_app_namespace_add_del_v2_t *mp)
{
  vl_api_app_namespace_add_del_v2_reply_t *rmp;
  u8 *ns_id = 0;
  u32 appns_index = 0;
  int rv = 0;

  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  mp->namespace_id[sizeof (mp->namespace_id) - 1] = 0;
  ns_id = format (0, "%s", &mp->namespace_id);

  vnet_app_namespace_add_del_args_t args = {
    .ns_id = ns_id,
    .sock_name = 0,
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
	  clib_warning ("app ns lookup failed id:%s", ns_id);
	  rv = VNET_API_ERROR_UNSPECIFIED;
	}
    }
  vec_free (ns_id);

done:
  REPLY_MACRO2 (VL_API_APP_NAMESPACE_ADD_DEL_V2_REPLY, ({
		  if (!rv)
		    rmp->appns_index = clib_host_to_net_u32 (appns_index);
		}));
}

static void
vl_api_app_namespace_add_del_v4_t_handler (
  vl_api_app_namespace_add_del_v4_t *mp)
{
  vl_api_app_namespace_add_del_v4_reply_t *rmp;
  u8 *ns_id = 0, *sock_name = 0;
  u32 appns_index = 0;
  int rv = 0;
  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }
  mp->namespace_id[sizeof (mp->namespace_id) - 1] = 0;
  ns_id = format (0, "%s", &mp->namespace_id);
  sock_name = vl_api_from_api_to_new_vec (mp, &mp->sock_name);
  vnet_app_namespace_add_del_args_t args = {
    .ns_id = ns_id,
    .sock_name = sock_name,
    .secret = clib_net_to_host_u64 (mp->secret),
    .sw_if_index = clib_net_to_host_u32 (mp->sw_if_index),
    .ip4_fib_id = clib_net_to_host_u32 (mp->ip4_fib_id),
    .ip6_fib_id = clib_net_to_host_u32 (mp->ip6_fib_id),
    .is_add = mp->is_add,
  };
  rv = vnet_app_namespace_add_del (&args);
  if (!rv && mp->is_add)
    {
      appns_index = app_namespace_index_from_id (ns_id);
      if (appns_index == APP_NAMESPACE_INVALID_INDEX)
	{
	  clib_warning ("app ns lookup failed id:%s", ns_id);
	  rv = VNET_API_ERROR_UNSPECIFIED;
	}
    }
  vec_free (ns_id);
  vec_free (sock_name);
done:
  REPLY_MACRO2 (VL_API_APP_NAMESPACE_ADD_DEL_V4_REPLY, ({
		  if (!rv)
		    rmp->appns_index = clib_host_to_net_u32 (appns_index);
		}));
}

static void
vl_api_app_namespace_add_del_v3_t_handler (
  vl_api_app_namespace_add_del_v3_t *mp)
{
  vl_api_app_namespace_add_del_v3_reply_t *rmp;
  u8 *ns_id = 0, *sock_name = 0, *api_sock_name = 0;
  u32 appns_index = 0;
  int rv = 0;
  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }
  mp->namespace_id[sizeof (mp->namespace_id) - 1] = 0;
  ns_id = format (0, "%s", &mp->namespace_id);
  api_sock_name = vl_api_from_api_to_new_vec (mp, &mp->sock_name);
  mp->netns[sizeof (mp->netns) - 1] = 0;
  if (strlen ((char *) mp->netns) != 0)
    {
      sock_name =
	format (0, "abstract:%v,netns_name=%s", api_sock_name, &mp->netns);
    }
  else
    {
      sock_name = api_sock_name;
      api_sock_name = 0; // for vec_free
    }

  vnet_app_namespace_add_del_args_t args = {
    .ns_id = ns_id,
    .sock_name = sock_name,
    .secret = clib_net_to_host_u64 (mp->secret),
    .sw_if_index = clib_net_to_host_u32 (mp->sw_if_index),
    .ip4_fib_id = clib_net_to_host_u32 (mp->ip4_fib_id),
    .ip6_fib_id = clib_net_to_host_u32 (mp->ip6_fib_id),
    .is_add = mp->is_add,
  };
  rv = vnet_app_namespace_add_del (&args);
  if (!rv && mp->is_add)
    {
      appns_index = app_namespace_index_from_id (ns_id);
      if (appns_index == APP_NAMESPACE_INVALID_INDEX)
	{
	  clib_warning ("app ns lookup failed id:%s", ns_id);
	  rv = VNET_API_ERROR_UNSPECIFIED;
	}
    }
  vec_free (ns_id);
  vec_free (sock_name);
  vec_free (api_sock_name);
done:
  REPLY_MACRO2 (VL_API_APP_NAMESPACE_ADD_DEL_V3_REPLY, ({
		  if (!rv)
		    rmp->appns_index = clib_host_to_net_u32 (appns_index);
		}));
}

static void
vl_api_session_rule_add_del_t_handler (vl_api_session_rule_add_del_t * mp)
{
  vl_api_session_rule_add_del_reply_t *rmp;
  session_rule_add_del_args_t args;
  session_rule_table_add_del_args_t *table_args = &args.table_args;
  int rv = 0;

  clib_memset (&args, 0, sizeof (args));

  ip_prefix_decode (&mp->lcl, &table_args->lcl);
  ip_prefix_decode (&mp->rmt, &table_args->rmt);

  table_args->lcl_port = mp->lcl_port;
  table_args->rmt_port = mp->rmt_port;
  table_args->action_index = clib_net_to_host_u32 (mp->action_index);
  table_args->is_add = mp->is_add;
  mp->tag[sizeof (mp->tag) - 1] = 0;
  table_args->tag = format (0, "%s", mp->tag);
  args.appns_index = clib_net_to_host_u32 (mp->appns_index);
  args.scope = mp->scope;
  args.transport_proto =
    api_session_transport_proto_decode (&mp->transport_proto) ==
    TRANSPORT_PROTO_UDP ? 1 : 0;

  rv = vnet_session_rule_add_del (&args);
  if (rv)
    {
      clib_warning ("rule add del returned: %U", format_session_error, rv);
      rv = VNET_API_ERROR_UNSPECIFIED;
    }
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
  fib_prefix_t lcl, rmt;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SESSION_RULES_DETAILS);
  rmp->context = context;

  clib_memset (&lcl, 0, sizeof (lcl));
  clib_memset (&rmt, 0, sizeof (rmt));
  ip_set (&lcl.fp_addr, &match->lcl_ip, 1);
  ip_set (&rmt.fp_addr, &match->rmt_ip, 1);
  lcl.fp_len = ip4_mask_to_preflen (&mask->lcl_ip);
  rmt.fp_len = ip4_mask_to_preflen (&mask->rmt_ip);

  ip_prefix_encode (&lcl, &rmp->lcl);
  ip_prefix_encode (&rmt, &rmp->rmt);
  rmp->lcl_port = match->lcl_port;
  rmp->rmt_port = match->rmt_port;
  rmp->action_index = clib_host_to_net_u32 (rule->action_index);
  rmp->scope =
    is_local ? SESSION_RULE_SCOPE_API_LOCAL : SESSION_RULE_SCOPE_API_GLOBAL;
  rmp->transport_proto = api_session_transport_proto_encode (transport_proto);
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
  fib_prefix_t lcl, rmt;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SESSION_RULES_DETAILS);
  rmp->context = context;

  clib_memset (&lcl, 0, sizeof (lcl));
  clib_memset (&rmt, 0, sizeof (rmt));
  ip_set (&lcl.fp_addr, &match->lcl_ip, 0);
  ip_set (&rmt.fp_addr, &match->rmt_ip, 0);
  lcl.fp_len = ip6_mask_to_preflen (&mask->lcl_ip);
  rmt.fp_len = ip6_mask_to_preflen (&mask->rmt_ip);

  ip_prefix_encode (&lcl, &rmp->lcl);
  ip_prefix_encode (&rmt, &rmp->rmt);
  rmp->lcl_port = match->lcl_port;
  rmp->rmt_port = match->rmt_port;
  rmp->action_index = clib_host_to_net_u32 (rule->action_index);
  rmp->scope =
    is_local ? SESSION_RULE_SCOPE_API_LOCAL : SESSION_RULE_SCOPE_API_GLOBAL;
  rmp->transport_proto = api_session_transport_proto_encode (transport_proto);
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
      pool_foreach (rule16, srt16->rules)  {
	ri = mma_rules_table_rule_index_16 (srt16, rule16);
	tag = session_rules_table_rule_tag (srt, ri, 1);
        send_session_rule_details4 (rule16, is_local, tp, appns_index, tag,
                                    reg, context);
      }
      /* *INDENT-ON* */
    }
  if (is_local || fib_proto == FIB_PROTOCOL_IP6)
    {
      u8 *tag = 0;
      /* *INDENT-OFF* */
      srt40 = &srt->session_rules_tables_40;
      pool_foreach (rule40, srt40->rules)  {
	ri = mma_rules_table_rule_index_40 (srt40, rule40);
	tag = session_rules_table_rule_tag (srt, ri, 1);
        send_session_rule_details6 (rule40, is_local, tp, appns_index, tag,
                                    reg, context);
      }
      /* *INDENT-ON* */
    }
}

static void
vl_api_session_rules_dump_t_handler (vl_api_session_rules_dump_t * mp)
{
  vl_api_registration_t *reg;
  session_table_t *st;
  u8 tp;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  session_table_foreach (st, ({
    for (tp = 0; tp < TRANSPORT_N_PROTOS; tp++)
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
vl_api_app_add_cert_key_pair_t_handler (vl_api_app_add_cert_key_pair_t * mp)
{
  vl_api_app_add_cert_key_pair_reply_t *rmp;
  vnet_app_add_cert_key_pair_args_t _a, *a = &_a;
  u32 certkey_len, key_len, cert_len;
  int rv = 0;
  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  cert_len = clib_net_to_host_u16 (mp->cert_len);
  if (cert_len > 10000)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  certkey_len = clib_net_to_host_u16 (mp->certkey_len);
  if (certkey_len < cert_len)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  key_len = certkey_len - cert_len;
  if (key_len > 10000)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));
  a->cert = mp->certkey;
  a->key = mp->certkey + cert_len;
  a->cert_len = cert_len;
  a->key_len = key_len;
  rv = vnet_app_add_cert_key_pair (a);

done:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_APP_ADD_CERT_KEY_PAIR_REPLY, ({
    if (!rv)
      rmp->index = clib_host_to_net_u32 (a->index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_app_del_cert_key_pair_t_handler (vl_api_app_del_cert_key_pair_t * mp)
{
  vl_api_app_del_cert_key_pair_reply_t *rmp;
  u32 ckpair_index;
  int rv = 0;
  if (session_main_is_enabled () == 0)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }
  ckpair_index = clib_net_to_host_u32 (mp->index);
  rv = vnet_app_del_cert_key_pair (ckpair_index);
  if (rv)
    {
      clib_warning ("vnet_app_del_cert_key_pair: %U", format_session_error,
		    rv);
      rv = VNET_API_ERROR_UNSPECIFIED;
    }

done:
  REPLY_MACRO (VL_API_APP_DEL_CERT_KEY_PAIR_REPLY);
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

/*
 * Socket api functions
 */

static int
mq_send_add_segment_sapi_cb (u32 app_wrk_index, u64 segment_handle)
{
  session_app_add_segment_msg_t m = { 0 };
  app_worker_t *app_wrk;
  fifo_segment_t *fs;
  ssvm_private_t *sp;
  u8 fd_flags = 0;

  app_wrk = app_worker_get (app_wrk_index);

  fs = segment_manager_get_segment_w_handle (segment_handle);
  sp = &fs->ssvm;
  ASSERT (ssvm_type (sp) == SSVM_SEGMENT_MEMFD);

  fd_flags |= SESSION_FD_F_MEMFD_SEGMENT;

  m.segment_size = sp->ssvm_size;
  m.fd_flags = fd_flags;
  m.segment_handle = segment_handle;
  strncpy ((char *) m.segment_name, (char *) sp->name,
	   sizeof (m.segment_name) - 1);

  app_wrk_send_ctrl_evt_fd (app_wrk, SESSION_CTRL_EVT_APP_ADD_SEGMENT, &m,
			    sizeof (m), sp->fd);

  return 0;
}

static int
mq_send_del_segment_sapi_cb (u32 app_wrk_index, u64 segment_handle)
{
  session_app_del_segment_msg_t m = { 0 };
  app_worker_t *app_wrk;

  app_wrk = app_worker_get (app_wrk_index);

  m.segment_handle = segment_handle;

  app_wrk_send_ctrl_evt (app_wrk, SESSION_CTRL_EVT_APP_DEL_SEGMENT, &m,
			 sizeof (m));

  return 0;
}

static session_cb_vft_t session_mq_sapi_cb_vft = {
  .session_accept_callback = mq_send_session_accepted_cb,
  .session_disconnect_callback = mq_send_session_disconnected_cb,
  .session_connected_callback = mq_send_session_connected_cb,
  .session_reset_callback = mq_send_session_reset_cb,
  .session_migrate_callback = mq_send_session_migrate_cb,
  .session_cleanup_callback = mq_send_session_cleanup_cb,
  .add_segment_callback = mq_send_add_segment_sapi_cb,
  .del_segment_callback = mq_send_del_segment_sapi_cb,
};

static void
session_api_attach_handler (app_namespace_t * app_ns, clib_socket_t * cs,
			    app_sapi_attach_msg_t * mp)
{
  int rv = 0, *fds = 0, n_fds = 0, i, n_workers;
  vnet_app_attach_args_t _a, *a = &_a;
  app_sapi_attach_reply_msg_t *rmp;
  u8 fd_flags = 0, ctrl_thread;
  app_ns_api_handle_t *handle;
  fifo_segment_t *rx_mqs_seg;
  app_sapi_msg_t msg = { 0 };
  app_worker_t *app_wrk;
  application_t *app;
  svm_msg_q_t *rx_mq;

  /* Make sure name is null terminated */
  mp->name[63] = 0;

  clib_memset (a, 0, sizeof (*a));
  a->api_client_index = appns_sapi_socket_handle (app_ns, cs);
  a->name = format (0, "%s", (char *) mp->name);
  a->options = mp->options;
  a->session_cb_vft = &session_mq_sapi_cb_vft;
  a->use_sock_api = 1;
  a->options[APP_OPTIONS_NAMESPACE] = app_namespace_index (app_ns);

  if ((rv = vnet_application_attach (a)))
    {
      clib_warning ("attach returned: %d", rv);
      goto done;
    }

  n_workers = vlib_num_workers ();
  vec_validate (fds, 3 /* segs + tx evtfd */ + n_workers);

  /* Send event queues segment */
  app = application_get (a->app_index);
  rx_mqs_seg = application_get_rx_mqs_segment (app);

  fd_flags |= SESSION_FD_F_VPP_MQ_SEGMENT;
  fds[n_fds] = rx_mqs_seg->ssvm.fd;
  n_fds += 1;

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
      fds[n_fds] = svm_msg_q_get_eventfd (a->app_evt_q);
      n_fds += 1;
    }

  if (application_use_private_rx_mqs ())
    {
      fd_flags |= SESSION_FD_F_VPP_MQ_EVENTFD;
      for (i = 0; i < n_workers + 1; i++)
	{
	  rx_mq = application_rx_mq_get (app, i);
	  fds[n_fds] = svm_msg_q_get_eventfd (rx_mq);
	  n_fds += 1;
	}
    }

done:

  msg.type = APP_SAPI_MSG_TYPE_ATTACH_REPLY;
  rmp = &msg.attach_reply;
  rmp->retval = rv;
  if (!rv)
    {
      ctrl_thread = n_workers ? 1 : 0;
      rmp->app_index = a->app_index;
      rmp->app_mq =
	fifo_segment_msg_q_offset ((fifo_segment_t *) a->segment, 0);
      rmp->vpp_ctrl_mq = fifo_segment_msg_q_offset (rx_mqs_seg, ctrl_thread);
      rmp->vpp_ctrl_mq_thread = ctrl_thread;
      rmp->n_fds = n_fds;
      rmp->fd_flags = fd_flags;
      /* No segment name and size since we only support memfds
       * in this configuration */
      rmp->segment_handle = a->segment_handle;
      rmp->api_client_handle = a->api_client_index;

      /* Update app index for socket */
      handle = (app_ns_api_handle_t *) & cs->private_data;
      app_wrk = application_get_worker (app, 0);
      handle->aah_app_wrk_index = app_wrk->wrk_index;
    }

  clib_socket_sendmsg (cs, &msg, sizeof (msg), fds, n_fds);
  vec_free (a->name);
  vec_free (fds);
}

void
sapi_socket_close_w_handle (u32 api_handle)
{
  app_namespace_t *app_ns = app_namespace_get (api_handle >> 16);
  u16 sock_index = api_handle & 0xffff;
  app_ns_api_handle_t *handle;
  clib_socket_t *cs;
  clib_file_t *cf;

  cs = appns_sapi_get_socket (app_ns, sock_index);
  if (!cs)
    return;

  handle = (app_ns_api_handle_t *) & cs->private_data;
  cf = clib_file_get (&file_main, handle->aah_file_index);
  clib_file_del (&file_main, cf);

  clib_socket_close (cs);
  appns_sapi_free_socket (app_ns, cs);
}

static void
sapi_add_del_worker_handler (app_namespace_t * app_ns,
			     clib_socket_t * cs,
			     app_sapi_worker_add_del_msg_t * mp)
{
  int rv = 0, fds[SESSION_N_FD_TYPE], n_fds = 0;
  app_sapi_worker_add_del_reply_msg_t *rmp;
  app_ns_api_handle_t *handle;
  app_sapi_msg_t msg = { 0 };
  app_worker_t *app_wrk;
  u32 sapi_handle = -1;
  application_t *app;
  u8 fd_flags = 0;

  app = application_get_if_valid (mp->app_index);
  if (!app)
    {
      rv = SESSION_E_INVALID;
      goto done;
    }

  sapi_handle = appns_sapi_socket_handle (app_ns, cs);

  vnet_app_worker_add_del_args_t args = {
    .app_index = app->app_index,
    .wrk_map_index = mp->wrk_index,
    .api_client_index = sapi_handle,
    .is_add = mp->is_add
  };
  rv = vnet_app_worker_add_del (&args);
  if (rv)
    {
      clib_warning ("app worker add/del returned: %U", format_session_error,
		    rv);
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
      fds[n_fds] = svm_msg_q_get_eventfd (args.evt_q);
      n_fds += 1;
    }

done:

  msg.type = APP_SAPI_MSG_TYPE_ADD_DEL_WORKER_REPLY;
  rmp = &msg.worker_add_del_reply;
  rmp->retval = rv;
  rmp->is_add = mp->is_add;
  rmp->api_client_handle = sapi_handle;
  rmp->wrk_index = args.wrk_map_index;
  rmp->segment_handle = args.segment_handle;
  if (!rv && mp->is_add)
    {
      /* No segment name and size. This supports only memfds */
      rmp->app_event_queue_address =
	fifo_segment_msg_q_offset ((fifo_segment_t *) args.segment, 0);
      rmp->n_fds = n_fds;
      rmp->fd_flags = fd_flags;

      /* Update app index for socket */
      handle = (app_ns_api_handle_t *) & cs->private_data;
      app_wrk = application_get_worker (app, args.wrk_map_index);
      handle->aah_app_wrk_index = app_wrk->wrk_index;
    }

  clib_socket_sendmsg (cs, &msg, sizeof (msg), fds, n_fds);
}

/* This is a workaround for the case when session layer starts reading
 * the socket before the client actualy sends the data
 */
static clib_error_t *
sapi_socket_receive_wait (clib_socket_t *cs, u8 *msg, u32 msg_len)
{
  clib_error_t *err;
  int n_tries = 5;

  while (1)
    {
      err = clib_socket_recvmsg (cs, msg, msg_len, 0, 0);
      if (!err)
	break;

      if (!n_tries)
	return err;

      n_tries--;
      usleep (1);
    }

  return err;
}

static void
sapi_add_del_cert_key_handler (app_namespace_t *app_ns, clib_socket_t *cs,
			       app_sapi_cert_key_add_del_msg_t *mp)
{
  vnet_app_add_cert_key_pair_args_t _a, *a = &_a;
  app_sapi_cert_key_add_del_reply_msg_t *rmp;
  app_sapi_msg_t msg = { 0 };
  int rv = 0;

  if (mp->is_add)
    {
      const u32 max_certkey_len = 2e4, max_cert_len = 1e4, max_key_len = 1e4;
      clib_error_t *err;
      u8 *certkey = 0;
      u32 key_len;

      if (mp->certkey_len > max_certkey_len)
	{
	  rv = SESSION_E_INVALID;
	  goto send_reply;
	}

      vec_validate (certkey, mp->certkey_len - 1);

      err = sapi_socket_receive_wait (cs, certkey, mp->certkey_len);
      if (err)
	{
	  clib_error_report (err);
	  rv = SESSION_E_INVALID;
	  goto send_reply;
	}

      if (mp->cert_len > max_cert_len)
	{
	  rv = SESSION_E_INVALID;
	  goto send_reply;
	}

      if (mp->certkey_len < mp->cert_len)
	{
	  rv = SESSION_E_INVALID;
	  goto send_reply;
	}

      key_len = mp->certkey_len - mp->cert_len;
      if (key_len > max_key_len)
	{
	  rv = SESSION_E_INVALID;
	  goto send_reply;
	}

      clib_memset (a, 0, sizeof (*a));
      a->cert = certkey;
      a->key = certkey + mp->cert_len;
      a->cert_len = mp->cert_len;
      a->key_len = key_len;
      rv = vnet_app_add_cert_key_pair (a);

      vec_free (certkey);
    }
  else
    {
      rv = vnet_app_del_cert_key_pair (mp->index);
    }

send_reply:

  msg.type = APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY_REPLY;
  rmp = &msg.cert_key_add_del_reply;
  rmp->retval = rv;
  rmp->context = mp->context;
  if (!rv && mp->is_add)
    rmp->index = a->index;

  clib_socket_sendmsg (cs, &msg, sizeof (msg), 0, 0);
}

static void
sapi_socket_detach (app_namespace_t * app_ns, clib_socket_t * cs)
{
  app_ns_api_handle_t *handle;
  app_worker_t *app_wrk;
  u32 api_client_handle;

  api_client_handle = appns_sapi_socket_handle (app_ns, cs);

  /* Cleanup everything because app worker closed socket or crashed */
  handle = (app_ns_api_handle_t *) & cs->private_data;
  app_wrk = app_worker_get_if_valid (handle->aah_app_wrk_index);
  if (!app_wrk)
    return;

  vnet_app_worker_add_del_args_t args = {
    .app_index = app_wrk->app_index,
    .wrk_map_index = app_wrk->wrk_map_index,
    .api_client_index = api_client_handle,
    .is_add = 0
  };
  /* Send rpc to main thread for worker barrier */
  vlib_rpc_call_main_thread (vnet_app_worker_add_del, (u8 *) & args,
			     sizeof (args));
}

static clib_error_t *
sapi_sock_read_ready (clib_file_t * cf)
{
  app_ns_api_handle_t *handle = (app_ns_api_handle_t *) & cf->private_data;
  vlib_main_t *vm = vlib_get_main ();
  app_sapi_msg_t msg = { 0 };
  app_namespace_t *app_ns;
  clib_error_t *err = 0;
  clib_socket_t *cs;

  app_ns = app_namespace_get (handle->aah_app_ns_index);
  cs = appns_sapi_get_socket (app_ns, handle->aah_sock_index);
  if (!cs)
    goto error;

  err = clib_socket_recvmsg (cs, &msg, sizeof (msg), 0, 0);
  if (err)
    {
      clib_error_free (err);
      sapi_socket_detach (app_ns, cs);
      goto error;
    }

  handle = (app_ns_api_handle_t *) & cs->private_data;

  vlib_worker_thread_barrier_sync (vm);

  switch (msg.type)
    {
    case APP_SAPI_MSG_TYPE_ATTACH:
      session_api_attach_handler (app_ns, cs, &msg.attach);
      break;
    case APP_SAPI_MSG_TYPE_ADD_DEL_WORKER:
      sapi_add_del_worker_handler (app_ns, cs, &msg.worker_add_del);
      break;
    case APP_SAPI_MSG_TYPE_ADD_DEL_CERT_KEY:
      sapi_add_del_cert_key_handler (app_ns, cs, &msg.cert_key_add_del);
      break;
    default:
      clib_warning ("app wrk %u unknown message type: %u",
		    handle->aah_app_wrk_index, msg.type);
      break;
    }

  vlib_worker_thread_barrier_release (vm);

error:
  return 0;
}

static clib_error_t *
sapi_sock_write_ready (clib_file_t * cf)
{
  app_ns_api_handle_t *handle = (app_ns_api_handle_t *) & cf->private_data;
  clib_warning ("called for app ns %u", handle->aah_app_ns_index);
  return 0;
}

static clib_error_t *
sapi_sock_error (clib_file_t * cf)
{
  app_ns_api_handle_t *handle = (app_ns_api_handle_t *) & cf->private_data;
  app_namespace_t *app_ns;
  clib_socket_t *cs;

  app_ns = app_namespace_get (handle->aah_app_ns_index);
  cs = appns_sapi_get_socket (app_ns, handle->aah_sock_index);
  if (!cs)
    return 0;

  sapi_socket_detach (app_ns, cs);
  return 0;
}

static clib_error_t *
sapi_sock_accept_ready (clib_file_t * scf)
{
  app_ns_api_handle_t handle = *(app_ns_api_handle_t *) & scf->private_data;
  app_namespace_t *app_ns;
  clib_file_t cf = { 0 };
  clib_error_t *err = 0;
  clib_socket_t *ccs, *scs;

  /* Listener files point to namespace */
  app_ns = app_namespace_get (handle.aah_app_ns_index);

  /*
   * Initialize client socket
   */
  ccs = appns_sapi_alloc_socket (app_ns);

  /* Grab server socket after client is initialized  */
  scs = appns_sapi_get_socket (app_ns, handle.aah_sock_index);
  if (!scs)
    goto error;

  err = clib_socket_accept (scs, ccs);
  if (err)
    {
      clib_error_report (err);
      goto error;
    }

  cf.read_function = sapi_sock_read_ready;
  cf.write_function = sapi_sock_write_ready;
  cf.error_function = sapi_sock_error;
  cf.file_descriptor = ccs->fd;
  /* File points to app namespace and socket */
  handle.aah_sock_index = appns_sapi_socket_index (app_ns, ccs);
  cf.private_data = handle.as_u64;
  cf.description = format (0, "app sock conn fd: %d", ccs->fd);

  /* Poll until we get an attach message. Socket points to file and
   * application that owns the socket */
  handle.aah_app_wrk_index = APP_INVALID_INDEX;
  handle.aah_file_index = clib_file_add (&file_main, &cf);
  ccs->private_data = handle.as_u64;

  return err;

error:
  appns_sapi_free_socket (app_ns, ccs);
  return err;
}

void
appns_sapi_del_ns_socket (app_namespace_t *app_ns)
{
  app_ns_api_handle_t *handle;
  clib_socket_t *cs;

  pool_foreach (cs, app_ns->app_sockets)
    {
      handle = (app_ns_api_handle_t *) &cs->private_data;
      clib_file_del_by_index (&file_main, handle->aah_file_index);

      clib_socket_close (cs);
      clib_socket_free (cs);
    }
  pool_free (app_ns->app_sockets);
}

int
appns_sapi_add_ns_socket (app_namespace_t * app_ns)
{
  char *subdir = "/app_ns_sockets/";
  app_ns_api_handle_t *handle;
  clib_file_t cf = { 0 };
  struct stat file_stat;
  clib_error_t *err;
  clib_socket_t *cs;
  char dir[4096];

  snprintf (dir, sizeof (dir), "%s%s", vlib_unix_get_runtime_dir (), subdir);

  if (!app_ns->sock_name)
    app_ns->sock_name = format (0, "%s%v%c", dir, app_ns->ns_id, 0);

  /*
   * Create and initialize socket to listen on
   */
  cs = appns_sapi_alloc_socket (app_ns);
  cs->config = (char *) vec_dup (app_ns->sock_name);
  cs->flags = CLIB_SOCKET_F_IS_SERVER |
    CLIB_SOCKET_F_ALLOW_GROUP_WRITE |
    CLIB_SOCKET_F_SEQPACKET | CLIB_SOCKET_F_PASSCRED;

  if (clib_socket_prefix_get_type (cs->config) == CLIB_SOCKET_TYPE_UNIX)
    {
      err = vlib_unix_recursive_mkdir ((char *) dir);
      if (err)
	{
	  clib_error_report (err);
	  return SESSION_E_SYSCALL;
	}
    }

  if ((err = clib_socket_init (cs)))
    {
      clib_error_report (err);
      return -1;
    }

  if (clib_socket_prefix_get_type (cs->config) == CLIB_SOCKET_TYPE_UNIX &&
      stat ((char *) app_ns->sock_name, &file_stat) == -1)
    return -1;

  /*
   * Start polling it
   */
  cf.read_function = sapi_sock_accept_ready;
  cf.file_descriptor = cs->fd;
  /* File points to namespace */
  handle = (app_ns_api_handle_t *) & cf.private_data;
  handle->aah_app_ns_index = app_namespace_index (app_ns);
  handle->aah_sock_index = appns_sapi_socket_index (app_ns, cs);
  cf.description = format (0, "app sock listener: %s", app_ns->sock_name);

  /* Socket points to clib file index */
  handle = (app_ns_api_handle_t *) & cs->private_data;
  handle->aah_file_index = clib_file_add (&file_main, &cf);
  handle->aah_app_wrk_index = APP_INVALID_INDEX;

  return 0;
}

#include <vnet/session/session.api.c>
static clib_error_t *
session_api_hookup (vlib_main_t *vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

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
