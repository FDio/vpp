/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>

typedef struct
{
  u32 app_index;
  u32 listener_handle;
  u8 *uri;
  u32 tls_engine;
  u32 ckpair_index;
  u8 alpn_protos[4];
  vlib_main_t *vlib_main;
} alpn_server_main_t;

alpn_server_main_t alpn_server_main;

static int
as_ts_rx_callback (session_t *ts)
{
  clib_warning ("called...");
  return -1;
}

static int
as_ts_tx_callback (session_t *ts)
{
  clib_warning ("called...");
  return -1;
}

static int
as_ts_accept_callback (session_t *ts)
{
  tls_alpn_proto_t alpn_proto;

  ts->session_state = SESSION_STATE_READY;

  alpn_proto = transport_get_alpn_selected (
    session_get_transport_proto (ts), ts->connection_index, ts->thread_index);
  clib_warning ("ALPN selected: %U", format_tls_alpn_proto, alpn_proto);

  return 0;
}

static int
as_ts_connected_callback (u32 app_index, u32 api_context, session_t *s,
			  session_error_t err)
{
  clib_warning ("called...");
  return -1;
}

static void
as_ts_disconnect_callback (session_t *s)
{
  alpn_server_main_t *sm = &alpn_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = sm->app_index;
  vnet_disconnect_session (a);
}

static void
as_ts_reset_callback (session_t *s)
{
  alpn_server_main_t *sm = &alpn_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = sm->app_index;
  vnet_disconnect_session (a);
}

static void
as_ts_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  return;
}

static int
as_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static int
as_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static session_cb_vft_t as_session_cb_vft = {
  .session_accept_callback = as_ts_accept_callback,
  .session_disconnect_callback = as_ts_disconnect_callback,
  .session_connected_callback = as_ts_connected_callback,
  .add_segment_callback = as_add_segment_callback,
  .del_segment_callback = as_del_segment_callback,
  .builtin_app_rx_callback = as_ts_rx_callback,
  .builtin_app_tx_callback = as_ts_tx_callback,
  .session_reset_callback = as_ts_reset_callback,
  .session_cleanup_callback = as_ts_cleanup_callback,
};

static int
as_attach ()
{
  alpn_server_main_t *sm = &alpn_server_main;
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = ~0;
  a->name = format (0, "test_alpn_server");
  a->session_cb_vft = &as_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = 128 << 20;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = 8 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 0;
  a->options[APP_OPTIONS_TLS_ENGINE] = sm->tls_engine;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      return -1;
    }

  vec_free (a->name);
  sm->app_index = a->app_index;

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  sm->ckpair_index = ck_pair->index;

  return 0;
}

static int
as_listen ()
{
  alpn_server_main_t *sm = &alpn_server_main;
  vnet_listen_args_t _a, *a = &_a;
  transport_endpt_ext_cfg_t *ext_cfg;
  char *uri;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->app_index = sm->app_index;

  uri = (char *) sm->uri;
  ASSERT (uri);

  if (parse_uri (uri, &a->sep_ext))
    return -1;

  ext_cfg =
    session_endpoint_add_ext_cfg (&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
				  sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.ckpair_index = sm->ckpair_index;
  clib_memcpy (ext_cfg->crypto.alpn_protos, sm->alpn_protos, 4);

  rv = vnet_listen (a);
  if (rv == 0)
    {
      sm->listener_handle = a->handle;
    }

  session_endpoint_free_ext_cfgs (&a->sep_ext);

  return rv;
}

static clib_error_t *
alpn_server_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  alpn_server_main_t *sm = &alpn_server_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  sm->tls_engine = CRYPTO_ENGINE_OPENSSL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected URI");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "uri %_%v%_", &sm->uri))
	;
      else if (unformat (line_input, "tls-engine %d", &sm->tls_engine))
	;
      else if (unformat (line_input, "alpn-proto1 %d", &sm->alpn_protos[0]))
	;
      else if (unformat (line_input, "alpn-proto2 %d", &sm->alpn_protos[1]))
	;
      else if (unformat (line_input, "alpn-proto3 %d", &sm->alpn_protos[2]))
	;
      else if (unformat (line_input, "alpn-proto4 %d", &sm->alpn_protos[3]))
	;
      else
	{
	  error = clib_error_return (0, "failed: unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vnet_session_enable_disable (vm, &args);

  if (as_attach ())
    {
      error = clib_error_return (0, "attach failed");
      goto done;
    }
  if (as_listen ())
    {
      error = clib_error_return (0, "lsiten failed");
      goto done;
    }

  vlib_cli_output (vm, "server started");

done:
  vec_free (sm->uri);
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (alpn_server_create_command, static) = {
  .path = "test alpn server",
  .short_help = "test alpn server uri <tls://ip/port> [tls-engine %d]",
  .function = alpn_server_create_command_fn,
};

clib_error_t *
alpn_server_main_init (vlib_main_t *vm)
{
  alpn_server_main_t *sm = &alpn_server_main;
  sm->vlib_main = vm;
  return 0;
}

VLIB_INIT_FUNCTION (alpn_server_main_init);
