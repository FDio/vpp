/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <http/http.h>
#include <http/http_status_codes.h>

typedef struct
{
  u32 app_index;
  u32 ckpair_index;
  session_endpoint_cfg_t proxy_server_sep;
  session_endpoint_cfg_t target_sep;
} proxy_client_main_t;

proxy_client_main_t proxy_client_main;

static int
pc_send_http_connect_req (session_t *s)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  u8 *target = 0;
  http_msg_t msg;
  int rv;

  target = format (0, "%U:%u", format_ip46_address, &pcm->target_sep.ip,
		   pcm->target_sep.is_ip4,
		   clib_net_to_host_u16 (pcm->target_sep.port));

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = HTTP_REQ_CONNECT;
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
  clib_warning ("response: %U %U", format_http_version, http_version,
		format_http_status_code, msg.code);
  return 0;
}

static int
pc_session_connected_callback (u32 app_index, u32 opaque, session_t *s,
			       session_error_t err)
{
  proxy_client_main_t *pcm = &proxy_client_main;

  if (err)
    {
      clib_warning ("connect error: %U", format_session_error, err);
      return -1;
    }

  if (pcm->target_sep.transport_proto == TRANSPORT_PROTO_TCP)
    return pc_send_http_connect_req (s);
  else
    return -1;
}

static void
pc_session_disconnect_callback (session_t *s)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  session_error_t rv;

  clib_warning ("session disconnect");
  a->handle = session_handle (s);
  a->app_index = pcm->app_index;
  rv = vnet_disconnect_session (a);
  if (rv)
    clib_warning ("disconnect returned: %U", format_session_error, rv);
}

static void
pc_session_transport_closed_callback (session_t *s)
{
  clib_warning ("transport closed");
}

static void
pc_session_reset_callback (session_t *s)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  session_error_t rv;

  clib_warning ("session reset");
  a->handle = session_handle (s);
  a->app_index = pcm->app_index;
  rv = vnet_disconnect_session (a);
  if (rv)
    clib_warning ("disconnect returned: %U", format_session_error, rv);
}

static int
pc_rx_callback (session_t *s)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  u32 max_deq;

  max_deq = svm_fifo_max_dequeue_cons (s->rx_fifo);
  if (max_deq == 0)
    {
      clib_warning ("no data to dequeue");
      return 1;
    }

  if (pcm->target_sep.transport_proto == TRANSPORT_PROTO_TCP)
    return pc_read_http_connect_resp (s);
  else
    return -1;
}

static int
pc_tx_callback (session_t *s)
{
  return 0;
}

static session_cb_vft_t pc_session_cb_vft = {
  .session_connected_callback = pc_session_connected_callback,
  .session_disconnect_callback = pc_session_disconnect_callback,
  .session_transport_closed_callback = pc_session_transport_closed_callback,
  .session_reset_callback = pc_session_reset_callback,
  .builtin_app_rx_callback = pc_rx_callback,
  .builtin_app_tx_callback = pc_tx_callback,
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
  transport_endpt_cfg_http_t http_cfg = {
    120, 0, HTTP_ENDPT_CFG_F_HTTP2_PRIOR_KNOWLEDGE
  };

  vec_validate (a, 0);
  clib_memset (a, 0, sizeof (a[0]));
  clib_memcpy (&a->sep_ext, &pcm->proxy_server_sep,
	       sizeof (pcm->proxy_server_sep));
  a->app_index = pcm->app_index;

  ext_cfg = session_endpoint_add_ext_cfg (
    &a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (http_cfg));
  clib_memcpy (ext_cfg->data, &http_cfg, sizeof (http_cfg));

  session_send_rpc_evt_to_thread_force (transport_cl_thread (), pc_connect_rpc,
					a);
}

static clib_error_t *
pc_attach ()
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
  a->session_cb_vft = &pc_session_cb_vft;
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

  pcm->app_index = a->app_index;
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
proxy_client_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  clib_error_t *err = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *server_uri = 0, *target_uri = 0;
  session_error_t rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "server-uri %s", &server_uri))
	;
      else if (unformat (line_input, "target %s", &target_uri))
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

  if (!target_uri)
    {
      err = clib_error_return (0, "target uri not provided");
      goto done;
    }
  if ((rv = parse_uri ((char *) target_uri, &pcm->target_sep)))
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

  err = pc_attach ();
  if (err)
    goto done;

  pc_connect ();

done:
  vec_free (server_uri);
  vec_free (target_uri);
  return err;
}

VLIB_CLI_COMMAND (proxy_client_command, static) = {
  .path = "test proxy client",
  .short_help = "server-uri <scheme://ip:port>",
  .function = proxy_client_command_fn,
};

clib_error_t *
proxy_client_main_init (vlib_main_t *vm)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  session_endpoint_cfg_t sep_null = SESSION_ENDPOINT_CFG_NULL;

  pcm->app_index = APP_INVALID_INDEX;
  pcm->proxy_server_sep = sep_null;
  return 0;
}

VLIB_INIT_FUNCTION (proxy_client_main_init);
