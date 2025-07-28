/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <http/http.h>
#include <http/http_status_codes.h>
#include <vnet/tls/tls_types.h>
#include <vnet/tcp/tcp.h>

#define TCP_MSS 1460

#define foreach_proxy_client_session_state                                    \
  _ (CONNECTING, "connecting")                                                \
  _ (ESTABLISHED, "established")                                              \
  _ (CLOSED, "closed")

typedef enum
{
#define _(sym, str) PROXY_CLIENT_SESSION_##sym,
  foreach_proxy_client_session_state
#undef _
} proxy_client_session_state_t;

#define foreach_proxy_client_session_flags                                    \
  _ (IS_PARENT)                                                               \
  _ (IS_UDP)                                                                  \
  _ (TUN_DISCONNECTED)                                                        \
  _ (LISTENER_DISCONNECTED)

typedef enum
{
#define _(sym) PROXY_CLIENT_SESSION_F_BIT_##sym,
  foreach_proxy_client_session_flags
#undef _
} proxy_client_session_flags_bit_t;

typedef enum
{
#define _(sym)                                                                \
  PROXY_CLIENT_SESSION_F_##sym = 1 << PROXY_CLIENT_SESSION_F_BIT_##sym,
  foreach_proxy_client_session_flags
#undef _
} proxy_client_session_flags_t;

typedef struct
{
  u32 session_index;
  proxy_client_session_state_t state;
  proxy_client_session_flags_t flags;
  session_handle_t listener_session_handle;
  session_handle_t tunnel_session_handle;
} proxy_client_session_t;

typedef struct
{
  u32 tunnel_app_index;
  u32 listener_app_index;
  u32 ckpair_index;
  session_endpoint_cfg_t proxy_server_sep;
  session_endpoint_cfg_t listener_sep;
  http_headers_ctx_t capsule_proto_header;
  u8 *capsule_proto_header_buf;
  proxy_client_session_t *sessions;
  u32 parent_session_index;
  u64 parent_session_handle;
  u8 *rx_buf;
} proxy_client_main_t;

proxy_client_main_t proxy_client_main;

#define PROXY_CLIENT_DEBUG 1

#if PROXY_CLIENT_DEBUG
#define PC_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define PC_DBG(_fmt, _args...)
#endif

static proxy_client_session_t *
pc_session_alloc ()
{
  proxy_client_main_t *pcm = &proxy_client_main;
  proxy_client_session_t *ps;

  pool_get_zero (pcm->sessions, ps);
  ps->session_index = ps - pcm->sessions;
  ps->tunnel_session_handle = SESSION_INVALID_HANDLE;
  ps->listener_session_handle = SESSION_INVALID_HANDLE;

  return ps;
}

static void
pc_session_free (proxy_client_session_t *ps)
{
  proxy_client_main_t *pcm = &proxy_client_main;

  pool_put (pcm->sessions, ps);
}

static proxy_client_session_t *
pc_session_get (u32 s_index)
{
  proxy_client_main_t *pcm = &proxy_client_main;

  if (pool_is_free_index (pcm->sessions, s_index))
    return 0;
  return pool_elt_at_index (pcm->sessions, s_index);
}

static void
pc_delete_session (session_t *s, u8 is_tun)
{
  proxy_client_session_t *ps;

  PC_DBG ("session %u (is tun %u)", s->opaque, is_tun);
  ps = pc_session_get (s->opaque);
  ASSERT (ps);
  pc_session_free (ps);
}

static void
pc_session_close_tun (proxy_client_session_t *ps)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  session_error_t rv;

  a->handle = ps->tunnel_session_handle;
  a->app_index = pcm->tunnel_app_index;
  rv = vnet_disconnect_session (a);
  if (rv)
    clib_warning ("disconnect returned: %U", format_session_error, rv);
  ps->flags |= PROXY_CLIENT_SESSION_F_TUN_DISCONNECTED;
}

static void
pc_session_close_listener (proxy_client_session_t *ps)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  session_error_t rv;

  a->handle = ps->listener_session_handle;
  a->app_index = pcm->listener_app_index;
  rv = vnet_disconnect_session (a);
  if (rv)
    clib_warning ("disconnect returned: %U", format_session_error, rv);
  ps->flags |= PROXY_CLIENT_SESSION_F_LISTENER_DISCONNECTED;
}

static void
pc_close_session (session_t *s, u8 is_tun)
{
  proxy_client_session_t *ps;

  PC_DBG ("session %u (is tun %u)", s->opaque, is_tun);
  ps = pc_session_get (s->opaque);
  ASSERT (ps);

  if (is_tun)
    {
      pc_session_close_tun (ps);
      if (ps->flags & PROXY_CLIENT_SESSION_F_IS_PARENT)
	return;
      if (!(ps->flags & PROXY_CLIENT_SESSION_F_LISTENER_DISCONNECTED))
	{
	  ASSERT (ps->tunnel_session_handle != SESSION_INVALID_HANDLE);
	  pc_session_close_listener (ps);
	}
    }
  else
    {
      pc_session_close_listener (ps);
      if (!(ps->flags & PROXY_CLIENT_SESSION_F_TUN_DISCONNECTED))
	{
	  if (ps->tunnel_session_handle != SESSION_INVALID_HANDLE)
	    pc_session_close_tun (ps);
	  ps->flags |= PROXY_CLIENT_SESSION_F_TUN_DISCONNECTED;
	}
    }
}

static int
pc_listen ()
{
  proxy_client_main_t *pcm = &proxy_client_main;
  vnet_listen_args_t _a, *a = &_a;
  session_error_t rv;

  clib_memset (a, 0, sizeof (*a));
  a->app_index = pcm->listener_app_index;
  clib_memcpy (&a->sep_ext, &pcm->listener_sep, sizeof (pcm->listener_sep));
  /* Make sure listener is marked connected for transports like udp */
  a->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
  if ((rv = vnet_listen (a)))
    {
      clib_warning ("listen returned: %U", format_session_error, rv);
      return -1;
    }
  PC_DBG ("listener started");
  return 0;
}

static void
pc_connect_stream_rpc (void *rpc_args)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  vnet_connect_args_t _a, *a = &_a;
  u32 session_index = pointer_to_uword (rpc_args);
  session_error_t rv;

  clib_memset (a, 0, sizeof (*a));
  clib_memcpy (&a->sep_ext, &pcm->proxy_server_sep,
	       sizeof (pcm->proxy_server_sep));
  a->sep_ext.parent_handle = pcm->parent_session_handle;
  a->app_index = pcm->tunnel_app_index;
  a->api_context = session_index;

  rv = vnet_connect (a);
  if (rv)
    clib_warning ("connect returned: %U", format_session_error, rv);
}

static void
pc_connect_stream (u32 session_index)
{
  session_send_rpc_evt_to_thread_force (
    transport_cl_thread (), pc_connect_stream_rpc,
    uword_to_pointer (session_index, void *));
}

static int
pc_write_http_connect_udp_req (svm_fifo_t *f, transport_connection_t *tc)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  u8 *target;
  http_msg_t msg;
  int rv;

  target =
    format (0, "/.well-known/masque/udp/%U/%u/", format_ip46_address,
	    &tc->lcl_ip, tc->is_ip4, clib_net_to_host_u16 (tc->lcl_port));
  PC_DBG ("opening UDP tunnel to: %U:%u", format_ip46_address, &tc->lcl_ip,
	  tc->is_ip4, clib_net_to_host_u16 (tc->lcl_port));
  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = HTTP_REQ_CONNECT;
  msg.data.upgrade_proto = HTTP_UPGRADE_PROTO_CONNECT_UDP;
  msg.data.target_path_offset = 0;
  msg.data.target_path_len = vec_len (target);
  msg.data.headers_offset = msg.data.target_path_len;
  msg.data.headers_len = pcm->capsule_proto_header.tail_offset;
  msg.data.body_len = 0;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = msg.data.target_path_len + msg.data.headers_len;

  svm_fifo_seg_t segs[3] = { { (u8 *) &msg, sizeof (msg) },
			     { target, msg.data.target_path_len },
			     { pcm->capsule_proto_header_buf,
			       msg.data.headers_len } };
  rv = svm_fifo_enqueue_segments (f, segs, 3, 0);
  vec_free (target);
  if (rv < (sizeof (msg) + msg.data.len))
    {
      clib_warning ("enqueue failed: %d", rv);
      return -1;
    }

  return 0;
}

static int
pc_write_http_connect_req (svm_fifo_t *f, transport_connection_t *tc)
{
  u8 *target = 0;
  http_msg_t msg;
  int rv;

  target = format (0, "%U:%u", format_ip46_address, &tc->lcl_ip, tc->is_ip4,
		   clib_net_to_host_u16 (tc->lcl_port));
  PC_DBG ("opening TCP tunnel to: %v", target);

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = HTTP_REQ_CONNECT;
  msg.data.upgrade_proto = HTTP_UPGRADE_PROTO_NA;
  msg.data.target_path_offset = 0;
  msg.data.target_path_len = vec_len (target);
  msg.data.headers_len = 0;
  msg.data.body_len = 0;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = msg.data.target_path_len;

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) },
			     { target, msg.data.target_path_len } };
  rv = svm_fifo_enqueue_segments (f, segs, 2, 0);
  vec_free (target);
  if (rv < (sizeof (msg) + msg.data.len))
    {
      clib_warning ("enqueue failed: %d", rv);
      return -1;
    }

  return 0;
}

static int
pc_read_http_connect_resp (session_t *s, proxy_client_session_t *ps)
{
  http_msg_t msg;
  http_version_t http_version;
  int rv;

  rv = svm_fifo_dequeue (s->rx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));
  ASSERT (msg.type == HTTP_MSG_REPLY);
  /* drop everything up to body */
  svm_fifo_dequeue_drop (s->rx_fifo, msg.data.body_offset);
  http_version = http_session_get_version (s);
  PC_DBG ("response: %U %U", format_http_version, http_version,
	  format_http_status_code, msg.code);
  if (http_status_code_str[msg.code][0] != '2')
    return -1;

  ps->state = PROXY_CLIENT_SESSION_ESTABLISHED;

  return 0;
}

static int
tun_session_connected_callback (u32 app_index, u32 session_index, session_t *s,
				session_error_t err)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  proxy_client_session_t *ps;

  if (err)
    {
      clib_warning ("connect error: %U", format_session_error, err);
      return -1;
    }

  if (pcm->parent_session_index == SESSION_INVALID_INDEX)
    {
      PC_DBG ("parent session connected");
      ps = pc_session_alloc ();
      ps->tunnel_session_handle = session_handle (s);
      ps->flags |= PROXY_CLIENT_SESSION_F_IS_PARENT;
      s->opaque = ps->session_index;
      pcm->parent_session_index = ps->session_index;
      pcm->parent_session_handle = session_handle (s);
      return pc_listen ();
    }

  PC_DBG ("stream for session %u opened", session_index);
  ps = pc_session_get (session_index);
  if (!ps)
    return -1;

  ps->tunnel_session_handle = session_handle (s);

  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);

  return 0;
}

static void
tun_session_disconnect_callback (session_t *s)
{
  pc_close_session (s, 1);
}

static void
tun_session_transport_closed_callback (session_t *s)
{
  PC_DBG ("transport closed");
}

static void
tun_session_reset_callback (session_t *s)
{
  pc_close_session (s, 1);
}

static int
tun_rx_callback (session_t *s)
{
  proxy_client_session_t *ps;
  svm_fifo_t *tun_tx_fifo;

  PC_DBG ("session %u", s->opaque);
  ps = pc_session_get (s->opaque);
  ASSERT (ps);
  if (ps->state == PROXY_CLIENT_SESSION_CONNECTING)
    return pc_read_http_connect_resp (s, ps);

  tun_tx_fifo = s->rx_fifo;

  if (svm_fifo_set_event (tun_tx_fifo))
    session_program_tx_io_evt (tun_tx_fifo->vpp_sh, SESSION_IO_EVT_TX);

  if (svm_fifo_max_enqueue (tun_tx_fifo) <= TCP_MSS)
    svm_fifo_add_want_deq_ntf (tun_tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  return 0;
}

static int
tun_tx_callback (session_t *s)
{
  proxy_client_session_t *ps;
  u32 min_free;

  PC_DBG ("session %u", s->opaque);
  min_free = clib_min (svm_fifo_size (s->tx_fifo) >> 3, 128 << 10);
  if (svm_fifo_max_enqueue (s->tx_fifo) < min_free)
    {
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  ps = pc_session_get (s->opaque);
  ASSERT (ps);

  if (ps->state < PROXY_CLIENT_SESSION_ESTABLISHED)
    return 0;

  /* force ack on listener side to update rcv wnd */
  if (ps->flags & PROXY_CLIENT_SESSION_F_IS_UDP)
    return 0;
  tcp_send_ack ((tcp_connection_t *) session_get_transport (
    session_get_from_handle (ps->listener_session_handle)));
  return 0;
}

static void
tun_session_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  pc_delete_session (s, 1);
}

static int
tun_alloc_session_fifos (session_t *s)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  proxy_client_session_t *ps;
  session_t *ls;
  svm_fifo_t *rx_fifo = 0, *tx_fifo = 0;
  int rv;

  PC_DBG ("session %u alloc fifos", s->opaque);
  ps = pc_session_get (s->opaque);
  if (!ps)
    {
      PC_DBG ("connection session");
      app_worker_t *app_wrk = app_worker_get (pcm->tunnel_app_index);
      segment_manager_t *sm = app_worker_get_connect_segment_manager (app_wrk);
      if ((rv = segment_manager_alloc_session_fifos (sm, s->thread_index,
						     &rx_fifo, &tx_fifo)))
	return rv;
      rx_fifo->shr->master_session_index = s->session_index;
      rx_fifo->vpp_sh = s->handle;
    }
  else
    {
      PC_DBG ("tunnel stream session");
      ls = session_get_from_handle (ps->listener_session_handle);
      tx_fifo = ls->rx_fifo;
      rx_fifo = ls->tx_fifo;
      rx_fifo->refcnt++;
      tx_fifo->refcnt++;
    }

  tx_fifo->shr->master_session_index = s->session_index;
  tx_fifo->vpp_sh = s->handle;
  s->rx_fifo = rx_fifo;
  s->tx_fifo = tx_fifo;
  return 0;
}

static session_cb_vft_t tun_session_cb_vft = {
  .session_connected_callback = tun_session_connected_callback,
  .session_disconnect_callback = tun_session_disconnect_callback,
  .session_transport_closed_callback = tun_session_transport_closed_callback,
  .session_reset_callback = tun_session_reset_callback,
  .builtin_app_rx_callback = tun_rx_callback,
  .builtin_app_tx_callback = tun_tx_callback,
  .session_cleanup_callback = tun_session_cleanup_callback,
  .proxy_alloc_session_fifos = tun_alloc_session_fifos,
};

static int
listener_accept_callback (session_t *s)
{
  proxy_client_session_t *ps;

  ps = pc_session_alloc ();
  ps->state = PROXY_CLIENT_SESSION_CONNECTING;
  ps->listener_session_handle = session_handle (s);
  if (session_get_transport_proto (s) == TRANSPORT_PROTO_UDP)
    ps->flags |= PROXY_CLIENT_SESSION_F_IS_UDP;
  s->opaque = ps->session_index;
  s->session_state = SESSION_STATE_READY;

  PC_DBG ("going to open stream for new session %u", ps->session_index);
  pc_connect_stream (ps->session_index);

  return 0;
}

static void
listener_session_disconnect_callback (session_t *s)
{
  pc_close_session (s, 0);
}

static void
listener_session_reset_callback (session_t *s)
{
  pc_close_session (s, 0);
}

static int
listener_rx_callback (session_t *s)
{
  proxy_client_session_t *ps;
  svm_fifo_t *tun_tx_fifo;

  PC_DBG ("session %u", s->opaque);
  ps = pc_session_get (s->opaque);
  if (!ps)
    return -1;

  if (ps->state < PROXY_CLIENT_SESSION_ESTABLISHED)
    return 0;

  tun_tx_fifo = s->rx_fifo;
  if (svm_fifo_set_event (tun_tx_fifo))
    session_program_tx_io_evt (ps->tunnel_session_handle, SESSION_IO_EVT_TX);

  if (svm_fifo_max_enqueue (tun_tx_fifo) <= TCP_MSS)
    svm_fifo_add_want_deq_ntf (tun_tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  return 0;
}

static int
listener_tx_callback (session_t *s)
{
  proxy_client_session_t *ps;
  u32 min_free;

  PC_DBG ("session %u", s->opaque);
  min_free = clib_min (svm_fifo_size (s->tx_fifo) >> 3, 128 << 10);
  if (svm_fifo_max_enqueue (s->tx_fifo) < min_free)
    {
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  ps = pc_session_get (s->opaque);
  ASSERT (ps);

  if (ps->state < PROXY_CLIENT_SESSION_ESTABLISHED)
    return 0;

  /* notify http transport */
  session_program_transport_io_evt (ps->tunnel_session_handle,
				    SESSION_IO_EVT_RX);
  return 0;
}

static void
listener_session_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  pc_delete_session (s, 0);
}

static int
listener_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static int
listener_write_early_data (session_t *s)
{
  transport_proto_t tp;
  transport_connection_t *tc;
  int rv;

  tp = session_get_transport_proto (s);
  tc = session_get_transport (s);
  switch (tp)
    {
    case TRANSPORT_PROTO_TCP:
      rv = pc_write_http_connect_req (s->rx_fifo, tc);
      break;
    case TRANSPORT_PROTO_UDP:
      rv = pc_write_http_connect_udp_req (s->rx_fifo, tc);
      break;
    default:
      clib_warning ("unsupported protocol %U", format_transport_proto, tp);
      return -1;
    }
  if (rv)
    return -1;

  return 0;
}

static session_cb_vft_t listener_session_cb_vft = {
  .session_accept_callback = listener_accept_callback,
  .session_disconnect_callback = listener_session_disconnect_callback,
  .session_reset_callback = listener_session_reset_callback,
  .builtin_app_rx_callback = listener_rx_callback,
  .builtin_app_tx_callback = listener_tx_callback,
  .session_cleanup_callback = listener_session_cleanup_callback,
  .add_segment_callback = listener_add_segment_callback,
  .proxy_write_early_data = listener_write_early_data,
};

static void
pc_connect_rpc (void *rpc_args)
{
  vnet_connect_args_t *a = rpc_args;
  session_error_t rv;

  rv = vnet_connect (a);
  if (rv)
    clib_warning ("connect returned: %U", format_session_error, rv);

  session_endpoint_free_ext_cfgs (&a->sep_ext);
  vec_free (a);
}

static void
pc_connect ()
{
  proxy_client_main_t *pcm = &proxy_client_main;
  vnet_connect_args_t *a = 0;
  transport_endpt_ext_cfg_t *ext_cfg;
  transport_endpt_cfg_http_t http_cfg = { 120, HTTP_UDP_TUNNEL_DGRAM, 0 };

  vec_validate (a, 0);
  clib_memset (a, 0, sizeof (a[0]));
  clib_memcpy (&a->sep_ext, &pcm->proxy_server_sep,
	       sizeof (pcm->proxy_server_sep));
  a->app_index = pcm->tunnel_app_index;

  if (pcm->proxy_server_sep.flags & SESSION_ENDPT_CFG_F_SECURE)
    {
      ext_cfg = session_endpoint_add_ext_cfg (
	&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
	sizeof (transport_endpt_crypto_cfg_t));
      ext_cfg->crypto.ckpair_index = pcm->ckpair_index;
      ext_cfg->crypto.alpn_protos[0] = TLS_ALPN_PROTO_HTTP_2;
    }
  else
    http_cfg.flags |= HTTP_ENDPT_CFG_F_HTTP2_PRIOR_KNOWLEDGE;

  ext_cfg = session_endpoint_add_ext_cfg (
    &a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (http_cfg));
  clib_memcpy (ext_cfg->data, &http_cfg, sizeof (http_cfg));

  session_send_rpc_evt_to_thread_force (transport_cl_thread (), pc_connect_rpc,
					a);
}

static clib_error_t *
pc_attach_client ()
{
  proxy_client_main_t *pcm = &proxy_client_main;
  vnet_app_attach_args_t _a, *a = &_a;
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  u64 options[18];
  session_error_t rv;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = APP_INVALID_INDEX;
  a->name = format (0, "proxy_client");
  a->session_cb_vft = &tun_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = 128 << 20;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = 32 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = 32 << 10;
  a->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_IS_BUILTIN | APP_OPTIONS_FLAGS_IS_PROXY;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 0;
  a->options[APP_OPTIONS_TLS_ENGINE] = CRYPTO_ENGINE_OPENSSL;

  if ((rv = vnet_application_attach (a)))
    return clib_error_return (0, "attach returned: %U", format_session_error,
			      rv);

  pcm->tunnel_app_index = a->app_index;
  vec_free (a->name);

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  pcm->ckpair_index = ck_pair->index;

  return 0;
}

static clib_error_t *
pc_attach_listener ()
{
  proxy_client_main_t *pcm = &proxy_client_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[18];
  session_error_t rv;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = APP_INVALID_INDEX;
  a->name = format (0, "proxy_listener");
  a->session_cb_vft = &listener_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = 128 << 20;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = 32 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = 32 << 10;
  a->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_IS_BUILTIN | APP_OPTIONS_FLAGS_IS_PROXY;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 0;

  if ((rv = vnet_application_attach (a)))
    return clib_error_return (0, "attach returned: %U", format_session_error,
			      rv);

  pcm->listener_app_index = a->app_index;
  vec_free (a->name);

  return 0;
}

static clib_error_t *
proxy_client_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  clib_error_t *err = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *server_uri = 0, *listener_uri = 0;
  session_error_t rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "server-uri %s", &server_uri))
	;
      else if (unformat (line_input, "listener %s", &listener_uri))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!server_uri)
    {
      err = clib_error_return (0, "server-uri not provided");
      goto done;
    }
  if ((rv = parse_uri ((char *) server_uri, &pcm->proxy_server_sep)))
    {
      err = clib_error_return (0, "server-uri parse error: %U",
			       format_session_error, rv);
      goto done;
    }

  if (!listener_uri)
    {
      err = clib_error_return (0, "target uri not provided");
      goto done;
    }
  if ((rv = parse_uri ((char *) listener_uri, &pcm->listener_sep)))
    {
      err = clib_error_return (0, "target uri parse error: %U",
			       format_session_error, rv);
      goto done;
    }

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, &args);
  vlib_worker_thread_barrier_release (vm);

  err = pc_attach_client ();
  if (err)
    goto done;

  err = pc_attach_listener ();
  if (err)
    goto done;

  pc_connect ();

done:
  vec_free (server_uri);
  vec_free (listener_uri);
  return err;
}

VLIB_CLI_COMMAND (proxy_client_command, static) = {
  .path = "test proxy client",
  .short_help = "server-uri <http[s]://ip:port> listener <tcp|udp://ip:port>",
  .function = proxy_client_command_fn,
};

clib_error_t *
proxy_client_main_init (vlib_main_t *vm)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  session_endpoint_cfg_t sep_null = SESSION_ENDPOINT_CFG_NULL;

  pcm->tunnel_app_index = APP_INVALID_INDEX;
  pcm->listener_app_index = APP_INVALID_INDEX;
  pcm->proxy_server_sep = sep_null;
  pcm->parent_session_handle = SESSION_INVALID_HANDLE;
  pcm->parent_session_index = SESSION_INVALID_INDEX;

  vec_validate (pcm->capsule_proto_header_buf, 10);
  http_init_headers_ctx (&pcm->capsule_proto_header,
			 pcm->capsule_proto_header_buf,
			 vec_len (pcm->capsule_proto_header_buf));
  http_add_header (&pcm->capsule_proto_header, HTTP_HEADER_CAPSULE_PROTOCOL,
		   http_token_lit (HTTP_BOOLEAN_TRUE));

  return 0;
}

VLIB_INIT_FUNCTION (proxy_client_main_init);
