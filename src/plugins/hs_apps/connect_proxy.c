/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <http/http.h>
#include <http/http_header_names.h>
#include <vnet/tcp/tcp.h>

#define TCP_MSS 1460

#define CP_DEBUG 0

#if CP_DEBUG
#define CP_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define CP_DBG(_fmt, _args...)
#endif

typedef enum
{
  CP_AO_CONNECTION_NA,
  CP_AO_CONNECTION_ESTABLISHING,
  CP_AO_CONNECTION_ESTABLISHED,
  CP_AO_CONNECTION_ERROR,
  CP_AO_CONNECTION_DISCONNECTED,
} cp_ao_connection_status_t;

typedef struct
{
  u32 session_index;
  u32 server_thread_index;
  http_header_t *resp_headers;
  session_handle_t vpp_server_handle;
  session_handle_t vpp_ao_handle;
  http_uri_t target_uri;
  volatile cp_ao_connection_status_t ao_connection_status;
  volatile int server_disconnected;
  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;
} cp_session_t;

typedef struct
{
  vlib_main_t *vlib_main;
  u32 server_app_index;
  u32 ao_client_app_index;
  u32 ckpair_index;
  u8 *server_uri;

  /* shared session pool, each end might be on different thread */
  cp_session_t *sessions;
  clib_spinlock_t sessions_lock;
} cp_main_t;

static cp_main_t cp_main;

static int
cp_transport_needs_crypto (transport_proto_t proto)
{
  return proto == TRANSPORT_PROTO_TLS || proto == TRANSPORT_PROTO_DTLS ||
	 proto == TRANSPORT_PROTO_QUIC;
}

static cp_session_t *
cp_session_alloc ()
{
  cp_main_t *cpm = &cp_main;
  cp_session_t *cps;

  pool_get_zero (cpm->sessions, cps);
  cps->session_index = cps - cpm->sessions;

  return cps;
}

static void
cp_session_free (cp_session_t *cps)
{
  cp_main_t *cpm = &cp_main;

  if (CLIB_DEBUG > 0)
    clib_memset (cps, 0xFE, sizeof (*cps));

  pool_put (cpm->sessions, cps);
}

static inline cp_session_t *
cp_session_get (u32 session_index)
{
  cp_main_t *cpm = &cp_main;
  return pool_elt_at_index (cpm->sessions, session_index);
}

static inline cp_session_t *
cp_session_get_if_valid (u32 session_index)
{
  cp_main_t *cpm = &cp_main;

  if (pool_is_free_index (cpm->sessions, session_index))
    return 0;
  return pool_elt_at_index (cpm->sessions, session_index);
}

static void
cp_session_postponed_free_rpc (void *arg)
{
  uword session_index = pointer_to_uword (arg);
  cp_main_t *cpm = &cp_main;
  cp_session_t *cps;

  clib_spinlock_lock_if_init (&cpm->sessions_lock);

  cps = cp_session_get (session_index);
  segment_manager_dealloc_fifos (cps->server_rx_fifo, cps->server_tx_fifo);
  cp_session_free (cps);

  clib_spinlock_unlock_if_init (&cpm->sessions_lock);
}

static void
cp_session_postponed_free (cp_session_t *cps)
{
  session_send_rpc_evt_to_thread (
    cps->server_thread_index, cp_session_postponed_free_rpc,
    uword_to_pointer (cps->session_index, void *));
}

static void
cp_delete_session (session_t *s, u8 is_active_open)
{
  cp_main_t *cpm = &cp_main;
  cp_session_t *cps;

  clib_spinlock_lock_if_init (&cpm->sessions_lock);
  cps = cp_session_get (s->opaque);

  if (is_active_open)
    {
      cps->vpp_ao_handle = SESSION_INVALID_HANDLE;

      cps->server_rx_fifo->master_thread_index = cps->server_thread_index;

      if (cps->vpp_server_handle == SESSION_INVALID_HANDLE)
	{
	  ASSERT (s->rx_fifo->refcnt == 1);
	  /* each side of the proxy on different threads */
	  if (cps->server_thread_index != s->thread_index)
	    {
	      s->rx_fifo = 0;
	      s->tx_fifo = 0;
	      cp_session_postponed_free (cps);
	    }
	  else
	    cp_session_free (cps);
	}
    }
  else
    {
      cps->vpp_server_handle = SESSION_INVALID_HANDLE;
      if (cps->vpp_ao_handle == SESSION_INVALID_HANDLE)
	{
	  if (cps->ao_connection_status != CP_AO_CONNECTION_ESTABLISHING)
	    cp_session_free (cps);
	}
    }

  clib_spinlock_unlock_if_init (&cpm->sessions_lock);
}

static void
cp_try_close_session (session_t *s, u8 is_active_open)
{
  cp_main_t *cpm = &cp_main;
  cp_session_t *cps;
  vnet_disconnect_args_t _a, *a = &_a;

  clib_spinlock_lock_if_init (&cpm->sessions_lock);
  cps = cp_session_get (s->opaque);

  if (is_active_open)
    {
      a->handle = cps->vpp_ao_handle;
      a->app_index = cpm->ao_client_app_index;
      vnet_disconnect_session (a);
      cps->ao_connection_status = CP_AO_CONNECTION_DISCONNECTED;

      if (!cps->server_disconnected)
	{
	  ASSERT (cps->vpp_server_handle != SESSION_INVALID_HANDLE);
	  a->handle = cps->vpp_server_handle;
	  a->app_index = cpm->server_app_index;
	  vnet_disconnect_session (a);
	  cps->server_disconnected = 1;
	}
    }
  else
    {
      a->handle = cps->vpp_server_handle;
      a->app_index = cpm->server_app_index;
      vnet_disconnect_session (a);
      cps->server_disconnected = 1;

      if (cps->ao_connection_status != CP_AO_CONNECTION_DISCONNECTED &&
	  cps->ao_connection_status != CP_AO_CONNECTION_ESTABLISHING)
	{
	  if (cps->vpp_ao_handle != SESSION_INVALID_HANDLE)
	    {
	      a->handle = cps->vpp_ao_handle;
	      a->app_index = cpm->ao_client_app_index;
	      vnet_disconnect_session (a);
	    }
	  cps->ao_connection_status = CP_AO_CONNECTION_DISCONNECTED;
	}
    }

  clib_spinlock_unlock_if_init (&cpm->sessions_lock);
}

static int
cp_server_session_accept_cb (session_t *s)
{
  cp_main_t *cpm = &cp_main;
  cp_session_t *cps;

  clib_spinlock_lock_if_init (&cpm->sessions_lock);

  cps = cp_session_alloc ();
  cps->vpp_server_handle = session_handle (s);
  cps->vpp_ao_handle = SESSION_INVALID_HANDLE;
  cps->server_thread_index = s->thread_index;

  s->opaque = cps->session_index;
  CP_DBG ("cp session index %x", s->opaque);

  clib_spinlock_unlock_if_init (&cpm->sessions_lock);

  s->session_state = SESSION_STATE_READY;

  return 0;
}

static void
cp_server_session_cleanup_cb (session_t *s, session_cleanup_ntf_t ntf)
{
  CP_DBG ("cp session index %x, ntf %d", s->opaque, ntf);

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  cp_delete_session (s, 0);
}

static void
cp_server_session_disconnect_cb (session_t *s)
{
  CP_DBG ("cp session index %x", s->opaque);
  cp_try_close_session (s, 0);
}

static void
cp_server_session_reset_cb (session_t *s)
{
  CP_DBG ("cp session index %x", s->opaque);
  cp_try_close_session (s, 0);
}

static int
cp_server_session_connected_cb (u32 app_wrk_index, u32 opaque, session_t *s,
				session_error_t code)
{
  CP_DBG ("called...");
  return -1;
}

static int
cp_server_add_segment_cb (u32 app_wrk_index, u64 segment_handle)
{
  CP_DBG ("called...");
  return 0;
}

static int
cp_server_del_segment_cb (u32 app_wrk_index, u64 segment_handle)
{
  CP_DBG ("called...");
  return 0;
}

static void
cp_send_http_resp (session_t *s, cp_session_t *cps, http_status_code_t sc)
{
  http_msg_t msg;
  int rv;
  u8 *headers_buf = 0;

  if (vec_len (cps->resp_headers))
    {
      headers_buf = http_serialize_headers (cps->resp_headers);
      vec_free (cps->resp_headers);
      msg.data.len = msg.data.headers_len = vec_len (headers_buf);
    }
  else
    msg.data.len = msg.data.headers_len = 0;

  msg.type = HTTP_MSG_REPLY;
  msg.code = sc;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.headers_offset = 0;
  msg.data.body_len = 0;
  msg.data.body_offset = 0;
  rv = svm_fifo_enqueue (s->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));
  if (msg.data.headers_len)
    {
      rv = svm_fifo_enqueue (s->tx_fifo, vec_len (headers_buf), headers_buf);
      ASSERT (rv == vec_len (headers_buf));
      vec_free (headers_buf);
    }

  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
}

static void
cp_target_connect_rpc (void *args)
{
  cp_main_t *cpm = &cp_main;
  u32 cp_session_index = (u32) pointer_to_uword (args);
  cp_session_t *cps;
  session_endpoint_cfg_t target_sep = SESSION_ENDPOINT_CFG_NULL;
  vnet_connect_args_t _a, *a = &_a;
  int rv;

  CP_DBG ("cp session index %x", cp_session_index);

  clib_spinlock_lock_if_init (&cpm->sessions_lock);

  cps = cp_session_get (cp_session_index);

  target_sep.is_ip4 = cps->target_uri.is_ip4;
  target_sep.ip = cps->target_uri.ip;
  target_sep.port = cps->target_uri.port;
  target_sep.transport_proto = TRANSPORT_PROTO_TCP;

  clib_memset (a, 0, sizeof (*a));
  clib_memcpy (&a->sep_ext, &target_sep, sizeof (target_sep));
  a->api_context = cps->session_index;
  a->app_index = cpm->ao_client_app_index;

  clib_spinlock_unlock_if_init (&cpm->sessions_lock);

  if ((rv = vnet_connect (a)))
    clib_warning (0, "connect returned: %U", format_session_error, rv);
}

static int
cp_server_rx_cb (session_t *s)
{
  http_msg_t msg;
  cp_main_t *cpm = &cp_main;
  cp_session_t *cps;
  svm_fifo_t *ao_tx_fifo;
  int rv;

  CP_DBG ("cp session index %x", s->opaque);

  clib_spinlock_lock_if_init (&cpm->sessions_lock);

  cps = cp_session_get (s->opaque);

  if (PREDICT_TRUE (cps->vpp_ao_handle != SESSION_INVALID_HANDLE))
    {
      CP_DBG ("received data from client");
      clib_spinlock_unlock_if_init (&cpm->sessions_lock);
      ao_tx_fifo = s->rx_fifo;
      /* Send event for active open tx fifo */
      if (svm_fifo_set_event (ao_tx_fifo))
	{
	  u32 ao_thread_index = ao_tx_fifo->master_thread_index;
	  u32 ao_session_index = ao_tx_fifo->shr->master_session_index;
	  if (session_send_io_evt_to_thread_custom (
		&ao_session_index, ao_thread_index, SESSION_IO_EVT_TX))
	    clib_warning ("failed to enqueue tx evt");
	}

      if (svm_fifo_max_enqueue (ao_tx_fifo) <= TCP_MSS)
	{
	  svm_fifo_add_want_deq_ntf (ao_tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
	  return 0;
	}
    }
  else
    {
      CP_DBG ("going to open connection with target");
      u8 *target_buf = 0;
      http_status_code_t sc;

      rv = svm_fifo_dequeue (s->rx_fifo, sizeof (msg), (u8 *) &msg);
      ASSERT (rv == sizeof (msg));

      if (msg.type != HTTP_MSG_REQUEST)
	{
	  sc = HTTP_STATUS_INTERNAL_ERROR;
	  goto error;
	}
      if (msg.method_type != HTTP_REQ_CONNECT)
	{
	  http_add_header (&cps->resp_headers,
			   http_header_name_token (HTTP_HEADER_ALLOW),
			   http_token_lit ("CONNECT"));
	  sc = HTTP_STATUS_METHOD_NOT_ALLOWED;
	  goto error;
	}

      if (msg.data.target_form != HTTP_TARGET_AUTHORITY_FORM ||
	  msg.data.target_path_len == 0)
	{
	  sc = HTTP_STATUS_BAD_REQUEST;
	  goto error;
	}

      /* read target uri */
      target_buf = vec_new (u8, msg.data.target_path_len);
      rv = svm_fifo_peek (s->rx_fifo, msg.data.target_path_offset,
			  msg.data.target_path_len, target_buf);
      ASSERT (rv == msg.data.target_path_len);
      svm_fifo_dequeue_drop (s->rx_fifo, msg.data.len);
      rv = http_parse_authority_form_target (target_buf, &cps->target_uri);
      vec_free (target_buf);
      if (rv)
	{
	  sc = HTTP_STATUS_BAD_REQUEST;
	  goto error;
	}

      cps->ao_connection_status = CP_AO_CONNECTION_ESTABLISHING;
      cps->server_rx_fifo = s->rx_fifo;
      cps->server_tx_fifo = s->tx_fifo;
      clib_spinlock_unlock_if_init (&cpm->sessions_lock);

      session_send_rpc_evt_to_thread_force (
	transport_cl_thread (), cp_target_connect_rpc,
	uword_to_pointer (cps->session_index, void *));
      return 0;

    error:
      cp_send_http_resp (s, cps, sc);
      svm_fifo_dequeue_drop_all (s->rx_fifo);
      clib_spinlock_unlock_if_init (&cpm->sessions_lock);
    }
  return 0;
}

static void
cp_force_ack (void *handlep)
{
  transport_connection_t *tc;
  session_t *s;

  s = session_get_from_handle (pointer_to_uword (handlep));
  if (session_get_transport_proto (s) != TRANSPORT_PROTO_TCP)
    return;
  tc = session_get_transport (s);
  tcp_send_ack ((tcp_connection_t *) tc);
}

static int
cp_server_tx_cb (session_t *s)
{
  u32 min_free;
  cp_main_t *cpm = &cp_main;
  cp_session_t *cps;

  CP_DBG ("cp session index %x", s->opaque);

  min_free = clib_min (svm_fifo_size (s->tx_fifo) >> 3, 128 << 10);
  if (svm_fifo_max_enqueue (s->tx_fifo) < min_free)
    {
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  clib_spinlock_lock_if_init (&cpm->sessions_lock);

  cps = cp_session_get (s->opaque);

  if (cps->vpp_ao_handle == SESSION_INVALID_HANDLE)
    goto unlock;

  /* Force ack on active open side to update rcv wnd. Make sure it's done on
   * the right thread */
  void *arg = uword_to_pointer (cps->vpp_ao_handle, void *);
  session_send_rpc_evt_to_thread (cps->server_rx_fifo->master_thread_index,
				  cp_force_ack, arg);

unlock:
  clib_spinlock_unlock_if_init (&cpm->sessions_lock);
  return 0;
}

static session_cb_vft_t cp_server_session_cb_vft = {
  .session_accept_callback = cp_server_session_accept_cb,
  .session_cleanup_callback = cp_server_session_cleanup_cb,
  .session_disconnect_callback = cp_server_session_disconnect_cb,
  .session_reset_callback = cp_server_session_reset_cb,
  .session_connected_callback = cp_server_session_connected_cb,
  .add_segment_callback = cp_server_add_segment_cb,
  .del_segment_callback = cp_server_del_segment_cb,
  .builtin_app_rx_callback = cp_server_rx_cb,
  .builtin_app_tx_callback = cp_server_tx_cb,
};

static clib_error_t *
cp_server_attach ()
{
  cp_main_t *cpm = &cp_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  clib_error_t *err = 0;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = APP_INVALID_INDEX;
  a->name = format (0, "http-connect-proxy-server");
  a->session_cb_vft = &cp_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_TLS_ENGINE] = CRYPTO_ENGINE_OPENSSL;
  /* TODO configurable */
  a->options[APP_OPTIONS_SEGMENT_SIZE] = 512 << 20;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 512 << 20;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = 64 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = 64 << 10;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 0;

  if ((rv = vnet_application_attach (a)))
    err =
      clib_error_return (0, "attach returned: %U", format_session_error, rv);

  cpm->server_app_index = a->app_index;
  vec_free (a->name);

  return err;
}

static void
cp_server_detach ()
{
  vnet_app_detach_args_t _a, *a = &_a;
  cp_main_t *cpm = &cp_main;
  int rv;

  a->app_index = cpm->server_app_index;
  a->api_client_index = APP_INVALID_INDEX;
  if ((rv = vnet_application_detach (a)))
    clib_warning ("server detach failed: %U", format_session_error, rv);

  cpm->server_app_index = APP_INVALID_INDEX;
}

static clib_error_t *
cp_server_listen ()
{
  cp_main_t *cpm = &cp_main;
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  vnet_listen_args_t _a, *a = &_a;
  u8 need_crypto;
  clib_error_t *err = 0;
  int rv;

  CP_DBG ("server URI %s", cpm->server_uri);
  if ((rv = parse_uri ((char *) cpm->server_uri, &sep)))
    return clib_error_return (0, "parse URI failed: %U", format_session_error,
			      rv);

  clib_memset (a, 0, sizeof (*a));
  a->app_index = cpm->server_app_index;

  need_crypto = cp_transport_needs_crypto (sep.transport_proto);
  sep.transport_proto = TRANSPORT_PROTO_HTTP;
  clib_memcpy (&a->sep_ext, &sep, sizeof (sep));

  if (need_crypto)
    {
      CP_DBG ("need crypto");
      session_endpoint_alloc_ext_cfg (&a->sep_ext,
				      TRANSPORT_ENDPT_EXT_CFG_CRYPTO);
      a->sep_ext.ext_cfg->crypto.ckpair_index = cpm->ckpair_index;
    }

  if ((rv = vnet_listen (a)))
    err =
      clib_error_return (0, "listen returned: %U", format_session_error, rv);

  if (need_crypto)
    clib_mem_free (a->sep_ext.ext_cfg);

  return err;
}

static void
cp_send_connect_response (cp_session_t *cps)
{
  session_t *s;
  http_status_code_t sc =
    (cps->ao_connection_status == CP_AO_CONNECTION_ESTABLISHED) ?
      HTTP_STATUS_OK :
      HTTP_STATUS_BAD_GATEWAY;
  s = session_get_from_handle (cps->vpp_server_handle);
  cp_send_http_resp (s, cps, sc);
}

static void
cp_send_connect_response_rpc (void *arg)
{
  uword session_index = pointer_to_uword (arg);
  cp_main_t *cpm = &cp_main;
  cp_session_t *cps;

  clib_spinlock_lock_if_init (&cpm->sessions_lock);

  cps = cp_session_get (session_index);
  cp_send_connect_response (cps);

  clib_spinlock_unlock_if_init (&cpm->sessions_lock);
}

static int
cp_ao_session_connected_cb (u32 app_wrk_index, u32 opaque, session_t *s,
			    session_error_t err)
{
  cp_main_t *cpm = &cp_main;
  cp_session_t *cps;

  CP_DBG ("cp session index %x", opaque);

  clib_spinlock_lock_if_init (&cpm->sessions_lock);

  cps = cp_session_get (opaque);

  if (err)
    {
      clib_warning ("connection failed: %U", format_session_error, err);
      cps->ao_connection_status = CP_AO_CONNECTION_ERROR;
    }
  else
    {
      CP_DBG ("connection established");
      cps->ao_connection_status = CP_AO_CONNECTION_ESTABLISHED;
      cps->vpp_ao_handle = session_handle (s);
    }

  /* server session was already closed */
  if (cps->server_disconnected)
    {
      /* setup everything for the cleanup notification */
      cps->ao_connection_status = CP_AO_CONNECTION_DISCONNECTED;
      clib_spinlock_unlock_if_init (&cpm->sessions_lock);
      return -1;
    }

  s->opaque = opaque;

  clib_spinlock_unlock_if_init (&cpm->sessions_lock);

  /* each side of the proxy on different threads */
  if (cps->server_thread_index != s->thread_index)
    session_send_rpc_evt_to_thread (
      cps->server_thread_index, cp_send_connect_response_rpc,
      uword_to_pointer (cps->session_index, void *));
  else
    cp_send_connect_response (cps);

  return 0;
}

static int
cp_ao_session_accept_cb (session_t *s)
{
  CP_DBG ("called...");
  return 0;
}

static void
cp_ao_session_reset_cb (session_t *s)
{
  CP_DBG ("cp session index %x", s->opaque);
  cp_try_close_session (s, 1);
}

static void
cp_ao_session_cleanup_cb (session_t *s, session_cleanup_ntf_t ntf)
{
  CP_DBG ("cp session index %x, ntf %d", s->opaque, ntf);

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  cp_delete_session (s, 1);
}

static void
cp_ao_session_disconnect_cb (session_t *s)
{
  CP_DBG ("cp session index %x", s->opaque);
  cp_try_close_session (s, 1);
}

static int
cp_ao_tx_cb (session_t *s)
{
  cp_main_t *cpm = &cp_main;
  cp_session_t *cps;
  u32 min_free;

  CP_DBG ("cp session index %x", s->opaque);

  min_free = clib_min (svm_fifo_size (s->tx_fifo) >> 3, 128 << 10);
  if (svm_fifo_max_enqueue (s->tx_fifo) < min_free)
    {
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  clib_spinlock_lock_if_init (&cpm->sessions_lock);

  cps = cp_session_get_if_valid (s->opaque);
  if (!cps)
    goto unlock;

  if (cps->vpp_server_handle == SESSION_INVALID_HANDLE)
    goto unlock;

  /* notify HTTP transport */
  CP_DBG ("notify HTTP transport");
  session_t *po = session_get_from_handle (cps->vpp_server_handle);
  session_send_io_evt_to_thread_custom (&po->session_index, po->thread_index,
					SESSION_IO_EVT_RX);

unlock:
  clib_spinlock_unlock_if_init (&cpm->sessions_lock);
  return 0;
}

static int
cp_ao_rx_cb (session_t *s)
{
  svm_fifo_t *server_tx_fifo;

  CP_DBG ("cp session index %x", s->opaque);

  server_tx_fifo = s->rx_fifo;

  /* Send event for server tx fifo */
  if (svm_fifo_set_event (server_tx_fifo))
    {
      u8 thread_index = server_tx_fifo->master_thread_index;
      u32 session_index = server_tx_fifo->shr->master_session_index;
      return session_send_io_evt_to_thread_custom (
	&session_index, thread_index, SESSION_IO_EVT_TX);
    }

  if (svm_fifo_max_enqueue (server_tx_fifo) <= TCP_MSS)
    svm_fifo_add_want_deq_ntf (server_tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  return 0;
}

static int
cp_ao_alloc_session_fifos (session_t *s)
{
  cp_main_t *cpm = &cp_main;
  cp_session_t *cps;
  svm_fifo_t *rxf, *txf;

  CP_DBG ("cp session index %x", s->opaque);

  clib_spinlock_lock_if_init (&cpm->sessions_lock);

  cps = cp_session_get (s->opaque);

  txf = cps->server_rx_fifo;
  rxf = cps->server_tx_fifo;

  /*
   * Reset the active-open tx-fifo master indices so the active-open session
   * will receive data, etc.
   */
  txf->shr->master_session_index = s->session_index;
  txf->master_thread_index = s->thread_index;

  /*
   * Account for the active-open session's use of the fifos
   * so they won't disappear until the last session which uses
   * them disappears
   */
  rxf->refcnt++;
  txf->refcnt++;

  clib_spinlock_unlock_if_init (&cpm->sessions_lock);

  s->rx_fifo = rxf;
  s->tx_fifo = txf;

  return 0;
}

static session_cb_vft_t cp_ao_client_session_cb_vft = {
  .session_connected_callback = cp_ao_session_connected_cb,
  .session_accept_callback = cp_ao_session_accept_cb,
  .session_cleanup_callback = cp_ao_session_cleanup_cb,
  .session_disconnect_callback = cp_ao_session_disconnect_cb,
  .session_reset_callback = cp_ao_session_reset_cb,
  .builtin_app_rx_callback = cp_ao_rx_cb,
  .builtin_app_tx_callback = cp_ao_tx_cb,
  .proxy_alloc_session_fifos = cp_ao_alloc_session_fifos,
};

static clib_error_t *
cp_ao_client_attach ()
{
  cp_main_t *cpm = &cp_main;
  vnet_app_attach_args_t _a, *a = &_a;
  clib_error_t *err = 0;
  u64 options[18];
  int rv;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = APP_INVALID_INDEX;
  a->name = format (0, "http-connect-proxy-ao-client");
  a->session_cb_vft = &cp_ao_client_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_IS_BUILTIN | APP_OPTIONS_FLAGS_IS_PROXY;
  /* TODO configurable */
  a->options[APP_OPTIONS_SEGMENT_SIZE] = 512 << 20;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = 64 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = 64 << 10;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 0;

  if ((rv = vnet_application_attach (a)))
    err =
      clib_error_return (0, "attach returned: %U", format_session_error, rv);

  cpm->ao_client_app_index = a->app_index;
  vec_free (a->name);

  return err;
}

static void
cp_add_ckpair ()
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  cp_main_t *cpm = &cp_main;

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);

  cpm->ckpair_index = ck_pair->index;
}

static clib_error_t *
cp_create ()
{
  cp_main_t *cpm = &cp_main;
  clib_error_t *err;

  if (vlib_num_workers ())
    clib_spinlock_init (&cpm->sessions_lock);

  cp_add_ckpair ();

  if ((err = cp_server_attach ()))
    {
      return clib_error_return (0, "%U", format_clib_error, err);
    }

  if ((err = cp_server_listen ()))
    {
      cp_server_detach ();
      return clib_error_return (0, "%U", format_clib_error, err);
    }

  if ((err = cp_ao_client_attach ()))
    {
      cp_server_detach ();
      return clib_error_return (0, "%U", format_clib_error, err);
    }

  return 0;
}

static clib_error_t *
cp_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  cp_main_t *cpm = &cp_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *err = 0;
  u8 *uri = 0;

  if (cpm->server_app_index != APP_INVALID_INDEX)
    return clib_error_return (0, "http connect proxy already running");

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected required arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "uri %s", &cpm->server_uri))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vnet_session_enable_disable (vm, &args);

  err = cp_create ();

done:
  unformat_free (line_input);
  vec_free (uri);
  return err;
}

VLIB_CLI_COMMAND (cp_create_command, static) = {
  .path = "http connect proxy",
  .short_help = "http connect proxy [uri <uri>]",
  .function = cp_create_command_fn,
};

static clib_error_t *
cp_main_init (vlib_main_t *vm)
{
  cp_main_t *cpm = &cp_main;

  cpm->server_app_index = APP_INVALID_INDEX;
  cpm->ao_client_app_index = APP_INVALID_INDEX;
  cpm->vlib_main = vm;
  return 0;
}

VLIB_INIT_FUNCTION (cp_main_init);
