/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>

typedef struct
{
  u32 app_index;
  u8 *uri;
  u32 tls_engine;
  u32 ckpair_index;
  u32 cli_node_index;
  session_endpoint_cfg_t connect_sep;
  tls_alpn_proto_t alpn_proto_selected;
  u8 alpn_protos[4];
  vlib_main_t *vlib_main;
} alpn_client_main_t;

typedef enum
{
  AC_CLI_TEST_DONE = 1,
  AC_CLI_CONNECT_FAILED,
} ac_cli_signal_t;

alpn_client_main_t alpn_client_main;

static int
ac_ts_rx_callback (session_t *ts)
{
  clib_warning ("called...");
  return -1;
}

static int
ac_ts_tx_callback (session_t *ts)
{
  clib_warning ("called...");
  return -1;
}

static int
ac_ts_accept_callback (session_t *ts)
{
  clib_warning ("called...");
  return -1;
}

static int
ac_ts_connected_callback (u32 app_index, u32 api_context, session_t *s,
			  session_error_t err)
{
  alpn_client_main_t *cm = &alpn_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  if (err)
    {
      vlib_process_signal_event_mt (cm->vlib_main, cm->cli_node_index,
				    AC_CLI_CONNECT_FAILED, err);
      return -1;
    }

  cm->alpn_proto_selected = transport_get_alpn_selected (
    session_get_transport_proto (s), s->connection_index, s->thread_index);

  a->handle = session_handle (s);
  a->app_index = cm->app_index;
  vnet_disconnect_session (a);

  vlib_process_signal_event_mt (cm->vlib_main, cm->cli_node_index,
				AC_CLI_TEST_DONE, 0);

  return 0;
}

static void
ac_ts_disconnect_callback (session_t *s)
{
  alpn_client_main_t *cm = &alpn_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = cm->app_index;
  vnet_disconnect_session (a);
}

static void
ac_ts_reset_callback (session_t *s)
{
  alpn_client_main_t *cm = &alpn_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = cm->app_index;
  vnet_disconnect_session (a);
}

static void
ac_ts_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  return;
}

static int
ac_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static int
ac_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static session_cb_vft_t ac_session_cb_vft = {
  .session_accept_callback = ac_ts_accept_callback,
  .session_disconnect_callback = ac_ts_disconnect_callback,
  .session_connected_callback = ac_ts_connected_callback,
  .add_segment_callback = ac_add_segment_callback,
  .del_segment_callback = ac_del_segment_callback,
  .builtin_app_rx_callback = ac_ts_rx_callback,
  .builtin_app_tx_callback = ac_ts_tx_callback,
  .session_reset_callback = ac_ts_reset_callback,
  .session_cleanup_callback = ac_ts_cleanup_callback,
};

static int
ac_attach ()
{
  alpn_client_main_t *cm = &alpn_client_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[18];
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = ~0;
  a->name = format (0, "test_alpn_client");
  a->session_cb_vft = &ac_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = 128 << 20;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = 8 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 0;
  a->options[APP_OPTIONS_TLS_ENGINE] = cm->tls_engine;

  if (vnet_application_attach (a))
    return -1;

  cm->app_index = a->app_index;
  vec_free (a->name);

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  cm->ckpair_index = ck_pair->index;

  return 0;
}

static int
ac_connect_rpc (void *rpc_args)
{
  vnet_connect_args_t *a = rpc_args;
  int rv;

  rv = vnet_connect (a);
  if (rv)
    clib_warning (0, "connect returned: %U", format_session_error, rv);

  session_endpoint_free_ext_cfgs (&a->sep_ext);
  vec_free (a);

  return rv;
}

static void
ac_program_connect (vnet_connect_args_t *a)
{
  session_send_rpc_evt_to_thread_force (transport_cl_thread (), ac_connect_rpc,
					a);
}

static void
ac_connect ()
{
  alpn_client_main_t *cm = &alpn_client_main;
  vnet_connect_args_t *a = 0;
  transport_endpt_ext_cfg_t *ext_cfg;

  vec_validate (a, 0);
  clib_memset (a, 0, sizeof (a[0]));

  clib_memcpy (&a->sep_ext, &cm->connect_sep, sizeof (cm->connect_sep));
  a->app_index = cm->app_index;

  ext_cfg =
    session_endpoint_add_ext_cfg (&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
				  sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.ckpair_index = cm->ckpair_index;
  clib_memcpy (ext_cfg->crypto.alpn_protos, cm->alpn_protos, 4);

  ac_program_connect (a);
}

static clib_error_t *
ac_run (vlib_main_t *vm)
{
  alpn_client_main_t *cm = &alpn_client_main;
  uword event_type, *event_data = 0;
  clib_error_t *error = 0;

  if (ac_attach ())
    return clib_error_return (0, "attach failed");

  ac_connect ();

  vlib_process_wait_for_event_or_clock (vm, 10);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      error = clib_error_return (0, "timeout");
      break;
    case AC_CLI_TEST_DONE:
      vlib_cli_output (vm, "ALPN selected: %U", format_tls_alpn_proto,
		       cm->alpn_proto_selected);
      break;
    case AC_CLI_CONNECT_FAILED:
      error = clib_error_return (0, "connect error %U", format_session_error,
				 event_data[0]);
      break;
    default:
      error = clib_error_return (0, "unexpected event %d", event_type);
      break;
    }

  vec_free (event_data);
  return error;
}

static int
ac_detach ()
{
  alpn_client_main_t *cm = &alpn_client_main;
  vnet_app_detach_args_t _da, *da = &_da;
  int rv;

  if (cm->app_index == APP_INVALID_INDEX)
    return 0;

  da->app_index = cm->app_index;
  da->api_client_index = ~0;
  rv = vnet_application_detach (da);
  cm->app_index = APP_INVALID_INDEX;

  return rv;
}

static clib_error_t *
alpn_client_run_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  alpn_client_main_t *cm = &alpn_client_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  cm->tls_engine = CRYPTO_ENGINE_OPENSSL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected URI");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "uri %_%v%_", &cm->uri))
	;
      else if (unformat (line_input, "tls-engine %d", &cm->tls_engine))
	;
      else if (unformat (line_input, "alpn-proto1 %d", &cm->alpn_protos[0]))
	;
      else if (unformat (line_input, "alpn-proto2 %d", &cm->alpn_protos[1]))
	;
      else if (unformat (line_input, "alpn-proto3 %d", &cm->alpn_protos[2]))
	;
      else if (unformat (line_input, "alpn-proto4 %d", &cm->alpn_protos[3]))
	;
      else
	{
	  error = clib_error_return (0, "failed: unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  cm->cli_node_index = vlib_get_current_process (vm)->node_runtime.node_index;

  if (cm->uri == 0)
    {
      error = clib_error_return (0, "uri not defined");
      goto done;
    }

  if (parse_uri ((char *) cm->uri, &cm->connect_sep))
    {
      error = clib_error_return (0, "invalid uri");
      goto done;
    }

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, &args);
  vlib_worker_thread_barrier_release (vm);

  error = ac_run (vm);

  if (ac_detach ())
    {
      if (!error)
	error = clib_error_return (0, "detach failed");
      else
	clib_warning ("detach failed");
    }

done:
  vec_free (cm->uri);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (alpn_client_run_command, static) = {
  .path = "test alpn client",
  .short_help = "test alpn client [uri <tls://ip/port>] [tls-engine %d]",
  .function = alpn_client_run_command_fn,
};

clib_error_t *
alpn_client_main_init (vlib_main_t *vm)
{
  alpn_client_main_t *cm = &alpn_client_main;
  cm->vlib_main = vm;
  cm->app_index = APP_INVALID_INDEX;
  return 0;
}

VLIB_INIT_FUNCTION (alpn_client_main_init);
