/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <vnet/tcp/tcp.h>
#include <unittest/session/test_session_helpers.h>

#define TLS_TEST_I(_cond, _comment, _args...)                                                      \
  ({                                                                                               \
    int _evald = (_cond);                                                                          \
    if (!(_evald))                                                                                 \
      fformat (stderr, "FAIL:%d: " _comment "\n", __LINE__, ##_args);                              \
    else                                                                                           \
      fformat (stderr, "PASS:%d: " _comment "\n", __LINE__, ##_args);                              \
    _evald;                                                                                        \
  })

#define TLS_TEST(_cond, _comment, _args...)                                                        \
  do                                                                                               \
    {                                                                                              \
      if (!TLS_TEST_I (_cond, _comment, ##_args))                                                  \
	return 1;                                                                                  \
    }                                                                                              \
  while (0)

#define TLS_TEST_DBG(_comment, _args...) fformat (stderr, _comment "\n", ##_args);

static int
tls_test_detach_pending (vlib_main_t *vm, unformat_input_t *input)
{
  u64 options[APP_OPTIONS_N_OPTIONS], placeholder_secret = 1234;
  u32 server_index, client_index, sw_if_index[2], tries = 0, timewait_time;
  u16 placeholder_server_port = 1234, placeholder_client_port = 5678;
  session_endpoint_cfg_t server_sep = SESSION_ENDPOINT_CFG_NULL;
  session_endpoint_cfg_t client_sep = SESSION_ENDPOINT_CFG_NULL;
  u32 client_vrf = 0, server_vrf = 1;
  transport_endpt_ext_cfg_t *ext_cfg;
  transport_connection_t *tc;
  session_handle_t ts_handle;
  ip4_address_t intf_addr[2];
  u8 *appns_id;
  int error;

  TLS_TEST_DBG ("tls_test_detach_pending");
  session_test_reset_placeholder_state ();

  /* Create the loopbacks */
  intf_addr[0].as_u32 = clib_host_to_net_u32 (0x05050505);
  session_create_lookpback (client_vrf, &sw_if_index[0], &intf_addr[0]);
  intf_addr[1].as_u32 = clib_host_to_net_u32 (0x06060606);
  session_create_lookpback (server_vrf, &sw_if_index[1], &intf_addr[1]);
  session_add_del_route_via_lookup_in_table (client_vrf, server_vrf, &intf_addr[1], 32,
					     1 /* is_add */);
  session_add_del_route_via_lookup_in_table (server_vrf, client_vrf, &intf_addr[0], 32,
					     1 /* is_add */);

  /* Insert namespace */
  appns_id = format (0, "appns_server");
  vnet_app_namespace_add_del_args_t ns_args = { .ns_id = appns_id,
						.secret = placeholder_secret,
						.sw_if_index = sw_if_index[1],
						.ip4_fib_id = 0,
						.is_add = 1 };
  error = vnet_app_namespace_add_del (&ns_args);
  TLS_TEST ((error == 0), "app ns insertion should succeed: %d", error);

  /* Attach client/server */
  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "tls_test_client"),
  };

  error = vnet_application_attach (&attach_args);
  TLS_TEST ((error == 0), "client app attached: %U", format_session_error, error);
  client_index = attach_args.app_index;
  vec_free (attach_args.name);

  attach_args.name = format (0, "tls_test_server");
  attach_args.namespace_id = appns_id;
  attach_args.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 32 << 20;
  attach_args.options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret;
  error = vnet_application_attach (&attach_args);
  TLS_TEST ((error == 0), "server app attached: %U", format_session_error, error);
  vec_free (attach_args.name);
  server_index = attach_args.app_index;

  /* Tcp listener that never replies, so tls handshakes do not complete */
  server_sep.is_ip4 = 1;
  server_sep.port = placeholder_server_port;
  vnet_listen_args_t bind_args = {
    .sep_ext = server_sep,
    .app_index = server_index,
  };
  error = vnet_listen (&bind_args);
  TLS_TEST ((error == 0), "server is listening");

  /* Tls connect with fixed 5-tuple */
  client_sep.is_ip4 = 1;
  client_sep.ip.ip4.as_u32 = intf_addr[1].as_u32;
  client_sep.port = placeholder_server_port;
  client_sep.peer.is_ip4 = 1;
  client_sep.peer.ip.ip4.as_u32 = intf_addr[0].as_u32;
  client_sep.peer.port = placeholder_client_port;
  client_sep.transport_proto = TRANSPORT_PROTO_TLS;

  vnet_connect_args_t connect_args = {
    .sep_ext = client_sep,
    .app_index = client_index,
  };
  ext_cfg = session_endpoint_add_ext_cfg (&connect_args.sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
					  sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.tls_profile_index = ~0;
  ext_cfg->crypto.owner_app_wrk_index = ENDPOINT_INVALID_INDEX;
  error = vnet_connect (&connect_args);
  session_endpoint_free_ext_cfgs (&connect_args.sep_ext);
  if (error == SESSION_E_NOCRYPTOENG)
    {
      TLS_TEST_DBG ("no tls engine, skipping");
      goto cleanup;
    }
  TLS_TEST ((error == 0), "tls connect: %U", format_session_error, error);

  /* Wait for the server to accept the tcp connection */
  while (placeholder_accept == 0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  TLS_TEST ((accepted_session_index != ~0), "tcp connection is accepted");
  TLS_TEST ((connected_session_index == ~0), "tls handshake is pending");

  tc = session_lookup_connection4 (0 /* client fib */, &intf_addr[0], &intf_addr[1],
				   placeholder_client_port, placeholder_server_port,
				   TRANSPORT_PROTO_TCP);
  TLS_TEST ((tc != 0), "tls tcp session exists");
  ts_handle = session_make_handle (tc->s_index, tc->thread_index);

  /* App gives up on the connect. Tls should close its tcp session. Shorten time-wait to avoid
   * waiting for the default */
  timewait_time = tcp_cfg.timewait_time;
  tcp_cfg.timewait_time = 100e-3 / TCP_TIMER_TICK;

  vnet_app_detach_args_t detach_args = {
    .app_index = client_index,
    .api_client_index = ~0,
  };
  error = vnet_application_detach (&detach_args);
  client_index = ~0;

  tries = 0;
  while ((accepted_session_index != ~0 || session_get_from_handle_if_valid (ts_handle)) &&
	 ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  tcp_cfg.timewait_time = timewait_time;

  TLS_TEST ((error == 0), "client app detached");
  TLS_TEST ((accepted_session_index == ~0), "server session is cleaned up");
  TLS_TEST ((session_get_from_handle_if_valid (ts_handle) == 0), "tls tcp session is cleaned up");
  TLS_TEST ((app_session_error == 0), "no unexpected app session notifications");

cleanup:
  if (client_index != ~0)
    {
      vnet_app_detach_args_t client_detach = {
	.app_index = client_index,
	.api_client_index = ~0,
      };
      vnet_application_detach (&client_detach);
    }
  vnet_app_detach_args_t server_detach = {
    .app_index = server_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&server_detach);

  ns_args.is_add = 0;
  error = vnet_app_namespace_add_del (&ns_args);
  TLS_TEST ((error == 0), "app ns delete should succeed: %d", error);

  /* Allow cleanup to finish */
  vlib_process_suspend (vm, 100e-3);

  session_add_del_route_via_lookup_in_table (client_vrf, server_vrf, &intf_addr[1], 32,
					     0 /* is_add */);
  session_add_del_route_via_lookup_in_table (server_vrf, client_vrf, &intf_addr[0], 32,
					     0 /* is_add */);

  session_delete_loopback (sw_if_index[0]);
  session_delete_loopback (sw_if_index[1]);

  vec_free (appns_id);

  return 0;
}

static clib_error_t *
tls_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd_arg)
{
  int res = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "detach-pending"))
	res = tls_test_detach_pending (vm, input);
      else if (unformat (input, "all"))
	{
	  if ((res = tls_test_detach_pending (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "TLS unit test failed");

  vlib_cli_output (vm, "SUCCESS");
  return 0;
}

/* Not a function of "test tls", it would also handle the errors of the test tls client and
 * server commands */
VLIB_CLI_COMMAND (tls_test_command, static) = {
  .path = "test tls unit",
  .short_help = "test tls unit [detach-pending|all]",
  .function = tls_test,
};
