/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vnet/session/application_namespace.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <vnet/session/session_rules_table.h>

#define SESSION_TEST_I(_cond, _comment, _args...)		\
({								\
  int _evald = (_cond);						\
  if (!(_evald)) {						\
    fformat(stderr, "FAIL:%d: " _comment "\n",			\
	    __LINE__, ##_args);					\
  } else {							\
    fformat(stderr, "PASS:%d: " _comment "\n",			\
	    __LINE__, ##_args);					\
  }								\
  _evald;							\
})

#define SESSION_TEST(_cond, _comment, _args...)			\
{								\
    if (!SESSION_TEST_I(_cond, _comment, ##_args)) {		\
	return 1;                                               \
    }								\
}

void
dummy_session_reset_callback (stream_session_t * s)
{
  clib_warning ("called...");
}

int
dummy_session_connected_callback (u32 app_index, u32 api_context,
				  stream_session_t * s, u8 is_fail)
{
  clib_warning ("called...");
  return -1;
}

int
dummy_add_segment_callback (u32 client_index, const u8 * seg_name,
			    u32 seg_size)
{
  clib_warning ("called...");
  return -1;
}

int
dummy_redirect_connect_callback (u32 client_index, void *mp)
{
  return VNET_API_ERROR_SESSION_REDIRECT;
}

void
dummy_session_disconnect_callback (stream_session_t * s)
{
  clib_warning ("called...");
}

int
dummy_session_accept_callback (stream_session_t * s)
{
  clib_warning ("called...");
  return -1;
}

int
dummy_server_rx_callback (stream_session_t * s)
{
  clib_warning ("called...");
  return -1;
}

/* *INDENT-OFF* */
static session_cb_vft_t dummy_session_cbs = {
  .session_reset_callback = dummy_session_reset_callback,
  .session_connected_callback = dummy_session_connected_callback,
  .session_accept_callback = dummy_session_accept_callback,
  .session_disconnect_callback = dummy_session_disconnect_callback,
  .builtin_server_rx_callback = dummy_server_rx_callback,
  .redirect_connect_callback = dummy_redirect_connect_callback,
};
/* *INDENT-ON* */

static int
session_test_basic (vlib_main_t * vm, unformat_input_t * input)
{
  session_endpoint_t server_sep = SESSION_ENDPOINT_NULL;
  u64 options[SESSION_OPTIONS_N_OPTIONS], bind4_handle, bind6_handle;
  u8 segment_name[128];
  clib_error_t *error = 0;
  u32 server_index;

  memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_ACCEPT_REDIRECT;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .segment_name = segment_name,
  };

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "app attached");
  server_index = attach_args.app_index;

  server_sep.is_ip4 = 1;
  vnet_bind_args_t bind_args = {
    .sep = server_sep,
    .app_index = 0,
  };

  bind_args.app_index = server_index;
  error = vnet_bind (&bind_args);
  SESSION_TEST ((error == 0), "server bind4 should work");
  bind4_handle = bind_args.handle;

  error = vnet_bind (&bind_args);
  SESSION_TEST ((error != 0), "double server bind4 should not work");

  bind_args.sep.is_ip4 = 0;
  error = vnet_bind (&bind_args);
  SESSION_TEST ((error == 0), "server bind6 should work");
  bind6_handle = bind_args.handle;

  error = vnet_bind (&bind_args);
  SESSION_TEST ((error != 0), "double server bind6 should not work");

  vnet_unbind_args_t unbind_args = {
    .handle = bind4_handle,
    .app_index = server_index,
  };
  error = vnet_unbind (&unbind_args);
  SESSION_TEST ((error == 0), "unbind4 should work");

  unbind_args.handle = bind6_handle;
  error = vnet_unbind (&unbind_args);
  SESSION_TEST ((error == 0), "unbind6 should work");

  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
  };
  vnet_application_detach (&detach_args);
  return 0;
}

static int
session_test_namespace (vlib_main_t * vm, unformat_input_t * input)
{
  u64 options[SESSION_OPTIONS_N_OPTIONS], dummy_secret = 1234;
  u32 server_index, server_st_index, server_local_st_index;
  u32 dummy_port = 1234, local_listener, client_index;
  u32 dummy_api_context = 4321, dummy_client_api_index = 1234;
  u32 dummy_server_api_index = ~0, sw_if_index = 0;
  session_endpoint_t server_sep = SESSION_ENDPOINT_NULL;
  session_endpoint_t client_sep = SESSION_ENDPOINT_NULL;
  session_endpoint_t intf_sep = SESSION_ENDPOINT_NULL;
  clib_error_t *error = 0;
  u8 *ns_id = format (0, "appns1"), intf_mac[6];
  app_namespace_t *app_ns;
  u8 segment_name[128];
  application_t *server;
  stream_session_t *s;
  int code;

  server_sep.is_ip4 = 1;
  server_sep.port = dummy_port;
  client_sep.is_ip4 = 1;
  client_sep.port = dummy_port;
  memset (options, 0, sizeof (options));
  memset (intf_mac, 0, sizeof (intf_mac));

  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_ACCEPT_REDIRECT;
  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .segment_name = segment_name,
  };

  vnet_bind_args_t bind_args = {
    .sep = server_sep,
    .app_index = 0,
  };

  vnet_connect_args_t connect_args = {
    .sep = client_sep,
    .app_index = 0,
    .api_context = 0,
  };

  vnet_unbind_args_t unbind_args = {
    .handle = bind_args.handle,
    .app_index = 0,
  };

  vnet_app_detach_args_t detach_args = {
    .app_index = 0,
  };

  ip4_address_t intf_addr = {
    .as_u32 = clib_host_to_net_u32 (0x06000105),
  };

  intf_sep.ip.ip4 = intf_addr;
  intf_sep.is_ip4 = 1;
  intf_sep.port = dummy_port;

  /*
   * Insert namespace and lookup
   */

  vnet_app_namespace_add_del_args_t ns_args = {
    .ns_id = ns_id,
    .secret = dummy_secret,
    .sw_if_index = APP_NAMESPACE_INVALID_INDEX,
    .is_add = 1
  };
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d",
		clib_error_get_code (error));

  app_ns = app_namespace_get_from_id (ns_id);
  SESSION_TEST ((app_ns != 0), "should find ns %v status", ns_id);
  SESSION_TEST ((app_ns->ns_secret == dummy_secret), "secret should be %d",
		dummy_secret);
  SESSION_TEST ((app_ns->sw_if_index == APP_NAMESPACE_INVALID_INDEX),
		"sw_if_index should be invalid");

  /*
   * Try application attach with wrong secret
   */

  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_NAMESPACE_SECRET] = dummy_secret - 1;
  attach_args.namespace_id = ns_id;
  attach_args.api_client_index = dummy_server_api_index;

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error != 0), "app attachment should fail");
  code = clib_error_get_code (error);
  SESSION_TEST ((code == VNET_API_ERROR_APP_WRONG_NS_SECRET),
		"code should be wrong ns secret: %d", code);

  /*
   * Attach server with global default scope
   */
  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_NAMESPACE_SECRET] = 0;
  attach_args.namespace_id = 0;
  attach_args.api_client_index = dummy_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");
  server_index = attach_args.app_index;
  server = application_get (server_index);
  SESSION_TEST ((server->ns_index == 0),
		"server should be in the default ns");

  bind_args.app_index = server_index;
  error = vnet_bind (&bind_args);
  SESSION_TEST ((error == 0), "server bind should work");

  server_st_index = application_session_table (server, FIB_PROTOCOL_IP4);
  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s != 0), "listener should exist in global table");
  SESSION_TEST ((s->app_index == server_index), "app_index should be that of "
		"the server");
  server_local_st_index = application_local_session_table (server);
  SESSION_TEST ((server_local_st_index == APP_INVALID_INDEX),
		"server shouldn't have access to local table");

  unbind_args.app_index = server_index;
  unbind_args.handle = bind_args.handle;
  error = vnet_unbind (&unbind_args);
  SESSION_TEST ((error == 0), "unbind should work");

  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s == 0), "listener should not exist in global table");

  detach_args.app_index = server_index;
  vnet_application_detach (&detach_args);

  /*
   * Attach server with local and global scope
   */
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_NAMESPACE_SECRET] = dummy_secret;
  attach_args.namespace_id = ns_id;
  attach_args.api_client_index = dummy_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");
  server_index = attach_args.app_index;
  server = application_get (server_index);
  SESSION_TEST ((server->ns_index == app_namespace_index (app_ns)),
		"server should be in the right ns");

  bind_args.app_index = server_index;
  error = vnet_bind (&bind_args);
  SESSION_TEST ((error == 0), "bind should work");
  server_st_index = application_session_table (server, FIB_PROTOCOL_IP4);
  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s != 0), "listener should exist in global table");
  SESSION_TEST ((s->app_index == server_index), "app_index should be that of "
		"the server");
  server_local_st_index = application_local_session_table (server);
  local_listener =
    session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((local_listener != SESSION_INVALID_INDEX),
		"listener should exist in local table");

  /*
   * Try client connect with 1) local scope 2) global scope
   */
  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  attach_args.api_client_index = dummy_client_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "client attachment should work");
  client_index = attach_args.app_index;
  connect_args.api_context = dummy_api_context;
  connect_args.app_index = client_index;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "client connect should return error code");
  code = clib_error_get_code (error);
  SESSION_TEST ((code == VNET_API_ERROR_INVALID_VALUE),
		"error code should be invalid value (zero ip)");
  connect_args.sep.ip.ip4.as_u8[0] = 127;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "client connect should return error code");
  code = clib_error_get_code (error);
  SESSION_TEST ((code == VNET_API_ERROR_SESSION_REDIRECT),
		"error code should be redirect");
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  attach_args.api_client_index = dummy_client_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "client attachment should work");
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "client connect should return error code");
  code = clib_error_get_code (error);
  SESSION_TEST ((code == VNET_API_ERROR_SESSION_CONNECT),
		"error code should be connect (nothing in local scope)");
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  /*
   * Unbind and detach server and then re-attach with local scope only
   */
  unbind_args.handle = bind_args.handle;
  unbind_args.app_index = server_index;
  error = vnet_unbind (&unbind_args);
  SESSION_TEST ((error == 0), "unbind should work");

  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s == 0), "listener should not exist in global table");
  local_listener =
    session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((s == 0), "listener should not exist in local table");

  detach_args.app_index = server_index;
  vnet_application_detach (&detach_args);

  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  attach_args.api_client_index = dummy_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "app attachment should work");
  server_index = attach_args.app_index;
  server = application_get (server_index);
  SESSION_TEST ((server->ns_index == app_namespace_index (app_ns)),
		"app should be in the right ns");

  bind_args.app_index = server_index;
  error = vnet_bind (&bind_args);
  SESSION_TEST ((error == 0), "bind should work");

  server_st_index = application_session_table (server, FIB_PROTOCOL_IP4);
  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s == 0), "listener should not exist in global table");
  server_local_st_index = application_local_session_table (server);
  local_listener =
    session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((local_listener != SESSION_INVALID_INDEX),
		"listener should exist in local table");

  unbind_args.handle = bind_args.handle;
  error = vnet_unbind (&unbind_args);
  SESSION_TEST ((error == 0), "unbind should work");

  local_listener =
    session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((local_listener == SESSION_INVALID_INDEX),
		"listener should not exist in local table");

  /*
   * Client attach + connect in default ns with local scope
   */
  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  attach_args.namespace_id = 0;
  attach_args.api_client_index = dummy_client_api_index;
  vnet_application_attach (&attach_args);
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "client connect should return error code");
  code = clib_error_get_code (error);
  SESSION_TEST ((code == VNET_API_ERROR_SESSION_CONNECT),
		"error code should be connect (not in same ns)");
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  /*
   * Detach server
   */
  detach_args.app_index = server_index;
  vnet_application_detach (&detach_args);

  /*
   * Create loopback interface
   */
  if (vnet_create_loopback_interface (&sw_if_index, intf_mac, 0, 0))
    {
      clib_warning ("couldn't create loopback. stopping the test!");
      return 0;
    }
  vnet_sw_interface_set_flags (vnet_get_main (), sw_if_index,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  ip4_add_del_interface_address (vlib_get_main (), sw_if_index, &intf_addr,
				 24, 0);

  /*
   * Update namespace
   */
  ns_args.sw_if_index = sw_if_index;
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d",
		clib_error_get_code (error));

  /*
   * Attach server with local and global scope
   */
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_NAMESPACE_SECRET] = dummy_secret;
  attach_args.namespace_id = ns_id;
  attach_args.api_client_index = dummy_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");
  server_index = attach_args.app_index;

  bind_args.app_index = server_index;
  error = vnet_bind (&bind_args);
  server_st_index = application_session_table (server, FIB_PROTOCOL_IP4);
  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s == 0), "zero listener should not exist in global table");

  s = session_lookup_listener (server_st_index, &intf_sep);
  SESSION_TEST ((s != 0), "intf listener should exist in global table");
  SESSION_TEST ((s->app_index == server_index), "app_index should be that of "
		"the server");
  server_local_st_index = application_local_session_table (server);
  local_listener =
    session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((local_listener != SESSION_INVALID_INDEX),
		"zero listener should exist in local table");
  detach_args.app_index = server_index;
  vnet_application_detach (&detach_args);

  /*
   * Cleanup
   */
  vec_free (ns_id);
  vnet_delete_loopback_interface (sw_if_index);
  return 0;
}

static int
session_test_rule_table (vlib_main_t * vm, unformat_input_t * input)
{
  session_rules_table_t _srt, *srt = &_srt;
  u16 lcl_port = 1234, rmt_port = 4321;
  u32 action_index = 1, res;
  ip4_address_t lcl_lkup, rmt_lkup;
  clib_error_t *error;
  int verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  memset (srt, 0, sizeof (*srt));
  session_rules_table_init (srt);

  ip4_address_t lcl_ip = {
    .as_u32 = clib_host_to_net_u32 (0x01020304),
  };
  ip4_address_t rmt_ip = {
    .as_u32 = clib_host_to_net_u32 (0x05060708),
  };
  ip4_address_t lcl_ip2 = {
    .as_u32 = clib_host_to_net_u32 (0x02020202),
  };
  ip4_address_t rmt_ip2 = {
    .as_u32 = clib_host_to_net_u32 (0x06060606),
  };
  ip4_address_t lcl_ip3 = {
    .as_u32 = clib_host_to_net_u32 (0x03030303),
  };
  ip4_address_t rmt_ip3 = {
    .as_u32 = clib_host_to_net_u32 (0x07070707),
  };
  fib_prefix_t lcl_pref = {
    .fp_addr.ip4.as_u32 = lcl_ip.as_u32,
    .fp_len = 16,
    .fp_proto = FIB_PROTOCOL_IP4,
  };
  fib_prefix_t rmt_pref = {
    .fp_addr.ip4.as_u32 = rmt_ip.as_u32,
    .fp_len = 16,
    .fp_proto = FIB_PROTOCOL_IP4,
  };

  session_rule_table_add_del_args_t args = {
    .lcl = lcl_pref,
    .rmt = rmt_pref,
    .lcl_port = lcl_port,
    .rmt_port = rmt_port,
    .action_index = action_index++,
    .is_add = 1,
  };
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/16 1234 5.6.7.8/16 4321 action %d",
		action_index - 1);

  res =
    session_rules_table_lookup4 (srt, &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 1),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should " "be 1: %d",
		res);

  /*
   * Add 1.2.3.4/24 1234 5.6.7.8/16 4321 and 1.2.3.4/24 1234 5.6.7.8/24 4321
   */
  args.lcl.fp_addr.ip4 = lcl_ip;
  args.lcl.fp_len = 24;
  args.action_index = action_index++;
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/24 1234 5.6.7.8/16 4321 action %d",
		action_index - 1);
  args.rmt.fp_addr.ip4 = rmt_ip;
  args.rmt.fp_len = 24;
  args.action_index = action_index++;
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/24 1234 5.6.7.8/24 4321 action %d",
		action_index - 1);

  /*
   * Add 2.2.2.2/24 1234 6.6.6.6/16 4321 and 3.3.3.3/24 1234 7.7.7.7/16 4321
   */
  args.lcl.fp_addr.ip4 = lcl_ip2;
  args.lcl.fp_len = 24;
  args.rmt.fp_addr.ip4 = rmt_ip2;
  args.rmt.fp_len = 16;
  args.action_index = action_index++;
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "Add 2.2.2.2/24 1234 6.6.6.6/16 4321 action %d",
		action_index - 1);
  args.lcl.fp_addr.ip4 = lcl_ip3;
  args.rmt.fp_addr.ip4 = rmt_ip3;
  args.action_index = action_index++;
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "Add 3.3.3.3/24 1234 7.7.7.7/16 4321 action %d",
		action_index - 1);

  /*
   * Add again 3.3.3.3/24 1234 7.7.7.7/16 4321
   */
  args.lcl.fp_addr.ip4 = lcl_ip3;
  args.rmt.fp_addr.ip4 = rmt_ip3;
  args.action_index = action_index++;
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "overwrite 3.3.3.3/24 1234 7.7.7.7/16 4321 "
		"action %d", action_index - 1);

  /*
   * Lookup 1.2.3.4/32 1234 5.6.7.8/32 4321, 1.2.2.4/32 1234 5.6.7.9/32 4321
   * and  3.3.3.3 1234 7.7.7.7 4321
   */
  res =
    session_rules_table_lookup4 (srt, &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 3),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321 action " "should be 3: %d",
		res);

  lcl_lkup.as_u32 = clib_host_to_net_u32 (0x01020204);
  rmt_lkup.as_u32 = clib_host_to_net_u32 (0x05060709);
  res =
    session_rules_table_lookup4 (srt, &lcl_lkup,
				 &rmt_lkup, lcl_port, rmt_port);
  SESSION_TEST ((res == 1),
		"Lookup 1.2.2.4 1234 5.6.7.9 4321, action " "should be 1: %d",
		res);

  res =
    session_rules_table_lookup4 (srt, &lcl_ip3, &rmt_ip3, lcl_port, rmt_port);
  SESSION_TEST ((res == 6),
		"Lookup 3.3.3.3 1234 7.7.7.7 4321, action "
		"should be 6 (updated): %d", res);

  /*
   * Add 1.2.3.4/24 * 5.6.7.8/24 *
   * Lookup 1.2.3.4 1234 5.6.7.8 4321 and 1.2.3.4 1235 5.6.7.8 4321
   */
  args.lcl.fp_addr.ip4 = lcl_ip;
  args.rmt.fp_addr.ip4 = rmt_ip;
  args.lcl.fp_len = 24;
  args.rmt.fp_len = 24;
  args.lcl_port = 0;
  args.rmt_port = 0;
  args.action_index = action_index++;
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/24 * 5.6.7.8/24 * action %d",
		action_index - 1);
  res =
    session_rules_table_lookup4 (srt, &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 7),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should"
		" be 7 (lpm dst): %d", res);
  res =
    session_rules_table_lookup4 (srt, &lcl_ip, &rmt_ip,
				 lcl_port + 1, rmt_port);
  SESSION_TEST ((res == 7),
		"Lookup 1.2.3.4 1235 5.6.7.8 4321, action should " "be 7: %d",
		res);

  /*
   * Del 1.2.3.4/24 * 5.6.7.8/24 *
   * Add 1.2.3.4/16 * 5.6.7.8/16 * and 1.2.3.4/24 1235 5.6.7.8/24 4321
   * Lookup 1.2.3.4 1234 5.6.7.8 4321, 1.2.3.4 1235 5.6.7.8 4321 and
   * 1.2.3.4 1235 5.6.7.8 4322
   */
  args.is_add = 0;
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/24 * 5.6.7.8/24 *");

  args.lcl.fp_addr.ip4 = lcl_ip;
  args.rmt.fp_addr.ip4 = rmt_ip;
  args.lcl.fp_len = 16;
  args.rmt.fp_len = 16;
  args.lcl_port = 0;
  args.rmt_port = 0;
  args.action_index = action_index++;
  args.is_add = 1;
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/16 * 5.6.7.8/16 * action %d",
		action_index - 1);

  args.lcl.fp_addr.ip4 = lcl_ip;
  args.rmt.fp_addr.ip4 = rmt_ip;
  args.lcl.fp_len = 24;
  args.rmt.fp_len = 24;
  args.lcl_port = lcl_port + 1;
  args.rmt_port = rmt_port;
  args.action_index = action_index++;
  args.is_add = 1;
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/24 1235 5.6.7.8/24 4321 action %d",
		action_index - 1);

  if (verbose)
    session_rules_table_cli_dump (vm, srt, FIB_PROTOCOL_IP4);

  res =
    session_rules_table_lookup4 (srt, &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 3),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should " "be 3: %d",
		res);
  res =
    session_rules_table_lookup4 (srt, &lcl_ip, &rmt_ip,
				 lcl_port + 1, rmt_port);
  SESSION_TEST ((res == 9),
		"Lookup 1.2.3.4 1235 5.6.7.8 4321, action should " "be 9: %d",
		res);
  res =
    session_rules_table_lookup4 (srt, &lcl_ip, &rmt_ip,
				 lcl_port + 1, rmt_port + 1);
  SESSION_TEST ((res == 8),
		"Lookup 1.2.3.4 1235 5.6.7.8 4322, action should " "be 8: %d",
		res);

  /*
   * Delete 1.2.0.0/16 1234 5.6.0.0/16 4321 and 1.2.0.0/16 * 5.6.0.0/16 *
   * Lookup 1.2.3.4 1234 5.6.7.8 4321
   */
  args.lcl_port = 1234;
  args.rmt_port = 4321;
  args.lcl.fp_len = 16;
  args.rmt.fp_len = 16;
  args.is_add = 0;
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "Del 1.2.0.0/16 1234 5.6.0.0/16 4321");
  res =
    session_rules_table_lookup4 (srt, &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 3),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should " "be 3: %d",
		res);

  args.lcl_port = 0;
  args.rmt_port = 0;
  args.is_add = 0;
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "Del 1.2.0.0/16 * 5.6.0.0/16 *");
  res =
    session_rules_table_lookup4 (srt, &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 3),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should " "be 3: %d",
		res);

  /*
   * Delete 1.2.3.4/24 1234 5.6.7.5/24
   */
  args.lcl.fp_addr.ip4 = lcl_ip;
  args.rmt.fp_addr.ip4 = rmt_ip;
  args.lcl.fp_len = 24;
  args.rmt.fp_len = 24;
  args.lcl_port = 1234;
  args.rmt_port = 4321;
  args.is_add = 0;
  error = session_rules_table_add_del (srt, &args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/24 1234 5.6.7.5/24");
  res =
    session_rules_table_lookup4 (srt, &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 2), "Action should be 2: %d", res);

  return 0;
}

static int
session_test_rules (vlib_main_t * vm, unformat_input_t * input)
{
  session_endpoint_t server_sep = SESSION_ENDPOINT_NULL;
  u64 options[SESSION_OPTIONS_N_OPTIONS];
  u16 lcl_port = 1234, rmt_port = 4321;
  u32 server_index, app_index;
  u32 dummy_server_api_index = ~0;
  transport_connection_t *tc;
  u32 dummy_port = 1111;
  clib_error_t *error = 0;
  u8 segment_name[128];
  stream_session_t *listener, *s;
  app_namespace_t *default_ns = app_namespace_get_default ();
  u32 local_ns_index = default_ns->local_table_index;
  int verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  server_sep.is_ip4 = 1;
  server_sep.port = dummy_port;
  memset (options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .segment_name = segment_name,
  };

  vnet_bind_args_t bind_args = {
    .sep = server_sep,
    .app_index = 0,
  };

  /*
   * Attach server with global and local default scope
   */
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_ACCEPT_REDIRECT;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  attach_args.namespace_id = 0;
  attach_args.api_client_index = dummy_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attached");
  server_index = attach_args.app_index;

  bind_args.app_index = server_index;
  error = vnet_bind (&bind_args);
  SESSION_TEST ((error == 0), "server bound to %U/%d", format_ip46_address,
		&server_sep.ip, 1, server_sep.port);
  listener = listen_session_get_from_handle (bind_args.handle);
  ip4_address_t lcl_ip = {
    .as_u32 = clib_host_to_net_u32 (0x01020304),
  };
  ip4_address_t rmt_ip = {
    .as_u32 = clib_host_to_net_u32 (0x05060708),
  };
  fib_prefix_t lcl_pref = {
    .fp_addr.ip4.as_u32 = lcl_ip.as_u32,
    .fp_len = 16,
    .fp_proto = FIB_PROTOCOL_IP4,
  };
  fib_prefix_t rmt_pref = {
    .fp_addr.ip4.as_u32 = rmt_ip.as_u32,
    .fp_len = 16,
    .fp_proto = FIB_PROTOCOL_IP4,
  };

  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc == 0), "optimized lookup should not work (port)");

  /*
   * Add 1.2.3.4/16 1234 5.6.7.8/16 4321 action server_index
   */
  session_rule_add_del_args_t args = {
    .table_args.lcl = lcl_pref,
    .table_args.rmt = rmt_pref,
    .table_args.lcl_port = lcl_port,
    .table_args.rmt_port = rmt_port,
    .table_args.action_index = server_index,
    .table_args.is_add = 1,
    .appns_index = 0,
  };
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/16 1234 5.6.7.8/16 4321 action %d",
		args.table_args.action_index);

  tc = session_lookup_connection4 (0, &lcl_pref.fp_addr.ip4,
				   &rmt_pref.fp_addr.ip4, lcl_port, rmt_port,
				   TRANSPORT_PROTO_TCP);
  SESSION_TEST ((tc->c_index == listener->connection_index),
		"optimized lookup should return the listener");
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc->c_index == listener->connection_index),
		"lookup should return the listener");
  s = session_lookup_safe4 (0, &lcl_pref.fp_addr.ip4, &rmt_pref.fp_addr.ip4,
			    lcl_port, rmt_port, TRANSPORT_PROTO_TCP);
  SESSION_TEST ((s->connection_index == listener->connection_index),
		"safe lookup should return the listener");
  session_endpoint_t sep = {
    .ip = rmt_pref.fp_addr,
    .is_ip4 = 1,
    .port = rmt_port,
    .transport_proto = TRANSPORT_PROTO_TCP,
  };
  app_index = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((app_index != server_index), "local session endpoint lookup "
		"should not work (global scope)");

  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port + 1,
				      rmt_port, TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc == 0),
		"optimized lookup for wrong lcl port + 1 should not work");

  /*
   * Add 1.2.3.4/16 * 5.6.7.8/16 4321
   */
  args.table_args.lcl_port = 0;
  args.scope = SESSION_RULE_SCOPE_LOCAL | SESSION_RULE_SCOPE_GLOBAL;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/16 * 5.6.7.8/16 4321 action %d",
		args.table_args.action_index);
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port + 1,
				      rmt_port, TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc->c_index == listener->connection_index),
		"optimized lookup for lcl port + 1 should work");
  app_index = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((app_index == server_index), "local session endpoint lookup "
		"should work (lcl ip was zeroed)");

  /*
   * Add deny rule 1.2.3.4/32 1234 5.6.7.8/32 4321 action -2 (drop)
   */
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 32;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 32;
  args.table_args.action_index = SESSION_RULES_TABLE_ACTION_DROP;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/32 1234 5.6.7.8/32 4321 action %d",
		args.table_args.action_index);

  if (verbose)
    {
      session_lookup_dump_rules_table (0, FIB_PROTOCOL_IP4,
				       TRANSPORT_PROTO_TCP);
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }

  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc == 0), "lookup for 1.2.3.4/32 1234 5.6.7.8/16 4321 "
		"should fail (deny rule)");
  app_index = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((app_index == APP_DROP_INDEX), "lookup for 1.2.3.4/32 1234 "
		"5.6.7.8/16 4321 in local table should return deny");
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc == 0),
		"lookup for 1.2.3.4/32 1234 5.6.7.8/16 4321 should not work");
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port + 1,
				      rmt_port, TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc->c_index == listener->connection_index),
		"lookup 1.2.3.4/32 123*5* 5.6.7.8/16 4321 should work");

  /*
   * Add local scope rule for 0/0 * 5.6.7.8/16 4321 action server_index
   */
  args.table_args.lcl_port = 0;
  args.table_args.lcl.fp_len = 0;
  args.table_args.rmt.fp_len = 16;
  args.table_args.action_index = -1;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add * * 5.6.7.8/16 4321 action %d",
		args.table_args.action_index);

  if (verbose)
    {
      session_lookup_dump_rules_table (0, FIB_PROTOCOL_IP4,
				       TRANSPORT_PROTO_TCP);
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }

  app_index = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((app_index == APP_DROP_INDEX),
		"local session endpoint lookup " "should return deny");

  /*
   * Delete 1.2.3.4/32 1234 5.6.7.8/32 4321 deny
   */
  args.table_args.is_add = 0;
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 32;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 32;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/32 1234 5.6.7.8/32 4321 deny");

  app_index = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((app_index == APP_INVALID_INDEX),
		"local session endpoint lookup should return invalid");

  /*
   * Delete 0/0 * 5.6.7.8/16 4321, 1.2.3.4/16 * 5.6.7.8/16 4321 and
   * 1.2.3.4/16 1234 5.6.7.8/16 4321
   */
  args.table_args.is_add = 0;
  args.table_args.lcl_port = 0;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 0;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 16;
  args.table_args.rmt_port = 4321;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 0/0 * 5.6.7.8/16 4321");
  app_index = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((app_index != server_index), "local session endpoint lookup "
		"should not work (removed)");

  args.table_args.is_add = 0;
  args.table_args.lcl = lcl_pref;

  args.table_args.is_add = 0;
  args.table_args.lcl_port = 0;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 16;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 16;
  args.table_args.rmt_port = 4321;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/16 * 5.6.7.8/16 4321");
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port + 1,
				      rmt_port, TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc == 0),
		"lookup 1.2.3.4/32 123*5* 5.6.7.8/16 4321 should not "
		"work (del)");

  args.table_args.is_add = 0;
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 16;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 16;
  args.table_args.rmt_port = 4321;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/16 1234 5.6.7.8/16 4321");
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc == 0), "lookup 1.2.3.4/32 1234 5.6.7.8/16 4321 should "
		"not work (del + deny)");

  SESSION_TEST ((error == 0), "Del 1.2.3.4/32 1234 5.6.7.8/32 4321 deny");
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc == 0), "lookup 1.2.3.4/32 1234 5.6.7.8/16 4321 should"
		" not work (no-rule)");

  /*
   * Test tags. Add/del rule with tag
   */
  args.table_args.is_add = 1;
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 16;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 16;
  args.table_args.rmt_port = 4321;
  args.table_args.tag = format (0, "test_rule");
  args.table_args.action_index = server_index;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/16 1234 5.6.7.8/16 4321 deny "
		"tag test_rule");
  if (verbose)
    {
      session_lookup_dump_rules_table (0, FIB_PROTOCOL_IP4,
				       TRANSPORT_PROTO_TCP);
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc->c_index == listener->connection_index),
		"lookup 1.2.3.4/32 1234 5.6.7.8/16 4321 should work");

  args.table_args.is_add = 0;
  args.table_args.lcl_port += 1;
  error = vnet_session_rule_add_del (&args);
  if (verbose)
    {
      session_lookup_dump_rules_table (0, FIB_PROTOCOL_IP4,
				       TRANSPORT_PROTO_TCP);
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }
  SESSION_TEST ((error == 0), "Del 1.2.3.4/32 1234 5.6.7.8/32 4321 deny "
		"tag test_rule");
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc == 0), "lookup 1.2.3.4/32 1234 5.6.7.8/16 4321 should not"
		" work (del)");
  vec_free (args.table_args.tag);
  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
  };
  vnet_application_detach (&detach_args);
  return 0;
}

static int
session_test_proxy (vlib_main_t * vm, unformat_input_t * input)
{
  u64 options[SESSION_OPTIONS_N_OPTIONS];
  char *show_listeners = "sh session listeners tcp verbose";
  char *show_local_listeners = "sh app ns table default";
  unformat_input_t tmp_input;
  u32 server_index, app_index;
  u32 dummy_server_api_index = ~0, sw_if_index = 0;
  clib_error_t *error = 0;
  u8 segment_name[128], intf_mac[6], sst;
  stream_session_t *s;
  transport_connection_t *tc;
  u16 lcl_port = 1234, rmt_port = 4321;
  app_namespace_t *app_ns;
  int verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  ip4_address_t lcl_ip = {
    .as_u32 = clib_host_to_net_u32 (0x01020304),
  };
  ip4_address_t rmt_ip = {
    .as_u32 = clib_host_to_net_u32 (0x05060708),
  };
  fib_prefix_t rmt_pref = {
    .fp_addr.ip4.as_u32 = rmt_ip.as_u32,
    .fp_len = 16,
    .fp_proto = FIB_PROTOCOL_IP4,
  };
  session_endpoint_t sep = {
    .ip = rmt_pref.fp_addr,
    .is_ip4 = 1,
    .port = rmt_port,
    .transport_proto = TRANSPORT_PROTO_TCP,
  };

  /*
   * Create loopback interface
   */
  memset (intf_mac, 0, sizeof (intf_mac));
  if (vnet_create_loopback_interface (&sw_if_index, intf_mac, 0, 0))
    {
      clib_warning ("couldn't create loopback. stopping the test!");
      return 0;
    }
  vnet_sw_interface_set_flags (vnet_get_main (), sw_if_index,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  ip4_add_del_interface_address (vlib_get_main (), sw_if_index, &lcl_ip,
				 24, 0);

  app_ns = app_namespace_get_default ();
  app_ns->sw_if_index = sw_if_index;

  memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_ACCEPT_REDIRECT;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_PROXY;
  options[APP_OPTIONS_PROXY_TRANSPORT] = 1 << TRANSPORT_PROTO_TCP;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .segment_name = segment_name,
  };

  attach_args.api_client_index = dummy_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");
  server_index = attach_args.app_index;

  if (verbose)
    {
      unformat_init_string (&tmp_input, show_listeners,
			    strlen (show_listeners));
      vlib_cli_input (vm, &tmp_input, 0, 0);
      unformat_init_string (&tmp_input, show_local_listeners,
			    strlen (show_local_listeners));
      vlib_cli_input (vm, &tmp_input, 0, 0);
    }

  tc = session_lookup_connection_wt4 (0, &lcl_ip, &rmt_ip, lcl_port, rmt_port,
				      TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc != 0), "lookup 1.2.3.4 1234 5.6.7.8 4321 should be "
		"successful");
  sst = session_type_from_proto_and_ip (TRANSPORT_PROTO_TCP, 1);
  s = listen_session_get (sst, tc->s_index);
  SESSION_TEST ((s->app_index == server_index), "lookup should return the"
		" server");

  tc = session_lookup_connection_wt4 (0, &rmt_ip, &rmt_ip, lcl_port, rmt_port,
				      TRANSPORT_PROTO_TCP, 0);
  SESSION_TEST ((tc == 0), "lookup 5.6.7.8 1234 5.6.7.8 4321 should"
		" not work");

  app_index = session_lookup_local_endpoint (app_ns->local_table_index, &sep);
  SESSION_TEST ((app_index == server_index), "local session endpoint lookup"
		" should work");

  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
  };
  vnet_application_detach (&detach_args);

  if (verbose)
    {
      unformat_init_string (&tmp_input, show_listeners,
			    strlen (show_listeners));
      vlib_cli_input (vm, &tmp_input, 0, 0);
      unformat_init_string (&tmp_input, show_local_listeners,
			    strlen (show_local_listeners));
      vlib_cli_input (vm, &tmp_input, 0, 0);
    }

  app_index = session_lookup_local_endpoint (app_ns->local_table_index, &sep);
  SESSION_TEST ((app_index == SESSION_RULES_TABLE_INVALID_INDEX),
		"local session endpoint lookup should not work after detach");
  unformat_free (&tmp_input);
  return 0;
}

static clib_error_t *
session_test (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  int res = 0;

  vnet_session_enable_disable (vm, 1);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "basic"))
	res = session_test_basic (vm, input);
      else if (unformat (input, "namespace"))
	res = session_test_namespace (vm, input);
      else if (unformat (input, "rules-table"))
	res = session_test_rule_table (vm, input);
      else if (unformat (input, "rules"))
	res = session_test_rules (vm, input);
      else if (unformat (input, "proxy"))
	res = session_test_proxy (vm, input);
      else if (unformat (input, "all"))
	{
	  if ((res = session_test_basic (vm, input)))
	    goto done;
	  if ((res = session_test_namespace (vm, input)))
	    goto done;
	  if ((res = session_test_rule_table (vm, input)))
	    goto done;
	  if ((res = session_test_rules (vm, input)))
	    goto done;
	  if ((res = session_test_proxy (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "Session unit test failed");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tcp_test_command, static) =
{
  .path = "test session",
  .short_help = "internal session unit tests",
  .function = session_test,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
