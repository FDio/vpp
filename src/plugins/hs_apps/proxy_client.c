/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <http/http.h>
#include <http/http_status_codes.h>
#include <vnet/tls/tls_types.h>

typedef struct
{
  u32 tunnel_app_index;
  u32 listener_app_index;
  u32 ckpair_index;
  session_endpoint_cfg_t proxy_server_sep;
  session_endpoint_cfg_t listener_sep;
  http_headers_ctx_t capsule_proto_header;
  u8 *capsule_proto_header_buf;
} proxy_client_main_t;

proxy_client_main_t proxy_client_main;

#define PROXY_CLIENT_DEBUG 1

#if PROXY_CLIENT_DEBUG
#define PC_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define PC_DBG(_fmt, _args...)
#endif

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

  return 0;
}

static int
pc_send_http_connect_udp_req (session_t *s, transport_connection_t *tc)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  u8 *target = 0;
  http_msg_t msg;
  int rv;

  target = format (0, "/.well-known/masque/udp/%U/%u/", format_ip46_address,
		   &pcm->listener_sep.ip, pcm->listener_sep.is_ip4,
		   clib_net_to_host_u16 (pcm->listener_sep.port));

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
  rv = svm_fifo_enqueue_segments (s->tx_fifo, segs, 3, 0);
  vec_free (target);
  if (rv < (sizeof (msg) + msg.data.len))
    {
      clib_warning ("enqueue failed: %d", rv);
      return -1;
    }

  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);

  return 0;
}

static int
pc_send_http_connect_req (session_t *s, transport_connection_t *tc)
{
  u8 *target = 0;
  http_msg_t msg;
  int rv;

  target = format (0, "%U:%u", format_ip46_address, &tc->rmt_ip, tc->is_ip4,
		   clib_net_to_host_u16 (tc->rmt_port));
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
  rv = svm_fifo_enqueue_segments (s->tx_fifo, segs, 2, 0);
  vec_free (target);
  if (rv < (sizeof (msg) + msg.data.len))
    {
      clib_warning ("enqueue failed: %d", rv);
      return -1;
    }

  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);

  return 0;
}

static int
pc_read_http_connect_resp (session_t *s)
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
  return 0;
}

static int
tun_session_connected_callback (u32 app_index, u32 opaque, session_t *s,
				session_error_t err)
{
  if (err)
    {
      clib_warning ("connect error: %U", format_session_error, err);
      return -1;
    }

  PC_DBG ("session connected");
  return pc_listen ();
}

static void
tun_session_disconnect_callback (session_t *s)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  session_error_t rv;

  PC_DBG ("session disconnect");
  a->handle = session_handle (s);
  a->app_index = pcm->tunnel_app_index;
  rv = vnet_disconnect_session (a);
  if (rv)
    clib_warning ("disconnect returned: %U", format_session_error, rv);
}

static void
tun_session_transport_closed_callback (session_t *s)
{
  PC_DBG ("transport closed");
}

static void
tun_session_reset_callback (session_t *s)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  session_error_t rv;

  PC_DBG ("session reset");
  a->handle = session_handle (s);
  a->app_index = pcm->tunnel_app_index;
  rv = vnet_disconnect_session (a);
  if (rv)
    clib_warning ("disconnect returned: %U", format_session_error, rv);
}

static int
tun_rx_callback (session_t *s)
{
  u32 max_deq;

  max_deq = svm_fifo_max_dequeue_cons (s->rx_fifo);
  if (max_deq == 0)
    {
      PC_DBG ("no data to dequeue");
      return 1;
    }

  return pc_read_http_connect_resp (s);
}

static int
tun_tx_callback (session_t *s)
{
  PC_DBG ("called");
  return 0;
}

static session_cb_vft_t tun_session_cb_vft = {
  .session_connected_callback = tun_session_connected_callback,
  .session_disconnect_callback = tun_session_disconnect_callback,
  .session_transport_closed_callback = tun_session_transport_closed_callback,
  .session_reset_callback = tun_session_reset_callback,
  .builtin_app_rx_callback = tun_rx_callback,
  .builtin_app_tx_callback = tun_tx_callback,
};

static int
listener_accept_callback (session_t *s)
{
  transport_proto_t tp = session_get_transport_proto (s);
  transport_connection_t *tc;
  int rv;

  tc = session_get_transport (s);

  if (tp == TRANSPORT_PROTO_TCP)
    rv = pc_send_http_connect_req (s, tc);
  else if (tp == TRANSPORT_PROTO_UDP)
    rv = pc_send_http_connect_udp_req (s, tc);
  else
    return -1;

  if (rv)
    return rv;

  s->session_state = SESSION_STATE_READY;

  return 0;
}

static int
listener_rx_callback (session_t *s)
{
  PC_DBG ("called");
  return 0;
}

static int
listener_tx_callback (session_t *s)
{
  PC_DBG ("called");
  return 0;
}

static int
listener_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static session_cb_vft_t listener_session_cb_vft = {
  .session_accept_callback = listener_accept_callback,
  .builtin_app_rx_callback = listener_rx_callback,
  .builtin_app_tx_callback = listener_tx_callback,
  .add_segment_callback = listener_add_segment_callback,
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
  transport_endpt_cfg_http_t http_cfg = { 120, 0, 0 };

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
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
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
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
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

  vec_validate (pcm->capsule_proto_header_buf, 10);
  http_init_headers_ctx (&pcm->capsule_proto_header,
			 pcm->capsule_proto_header_buf,
			 vec_len (pcm->capsule_proto_header_buf));
  http_add_header (&pcm->capsule_proto_header, HTTP_HEADER_CAPSULE_PROTOCOL,
		   http_token_lit (HTTP_BOOLEAN_TRUE));

  return 0;
}

VLIB_INIT_FUNCTION (proxy_client_main_init);
