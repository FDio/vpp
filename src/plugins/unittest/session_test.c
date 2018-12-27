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
#include <vnet/tcp/tcp.h>

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

volatile u32 connected_session_index = ~0;
volatile u32 connected_session_thread = ~0;
int
dummy_session_connected_callback (u32 app_index, u32 api_context,
				  stream_session_t * s, u8 is_fail)
{
  if (s)
    {
      connected_session_index = s->session_index;
      connected_session_thread = s->thread_index;
    }
  return 0;
}

static u32 dummy_segment_count;

int
dummy_add_segment_callback (u32 client_index, u64 segment_handle)
{
  dummy_segment_count = 1;
  return 0;
}

int
dummy_del_segment_callback (u32 client_index, u64 segment_handle)
{
  dummy_segment_count = 0;
  return 0;
}

void
dummy_session_disconnect_callback (stream_session_t * s)
{
  clib_warning ("called...");
}

static u32 dummy_accept;
volatile u32 accepted_session_index;
volatile u32 accepted_session_thread;

int
dummy_session_accept_callback (stream_session_t * s)
{
  dummy_accept = 1;
  accepted_session_index = s->session_index;
  accepted_session_thread = s->thread_index;
  s->session_state = SESSION_STATE_READY;
  return 0;
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
  .builtin_app_rx_callback = dummy_server_rx_callback,
  .add_segment_callback = dummy_add_segment_callback,
  .del_segment_callback = dummy_del_segment_callback,
};
/* *INDENT-ON* */

static int
session_create_lookpback (u32 table_id, u32 * sw_if_index,
			  ip4_address_t * intf_addr)
{
  u8 intf_mac[6];

  clib_memset (intf_mac, 0, sizeof (intf_mac));

  if (vnet_create_loopback_interface (sw_if_index, intf_mac, 0, 0))
    {
      clib_warning ("couldn't create loopback. stopping the test!");
      return -1;
    }

  if (table_id != 0)
    {
      ip_table_create (FIB_PROTOCOL_IP4, table_id, 0, 0);
      ip_table_bind (FIB_PROTOCOL_IP4, *sw_if_index, table_id, 0);
    }

  vnet_sw_interface_set_flags (vnet_get_main (), *sw_if_index,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  if (ip4_add_del_interface_address (vlib_get_main (), *sw_if_index,
				     intf_addr, 24, 0))
    {
      clib_warning ("couldn't assign loopback ip %U", format_ip4_address,
		    intf_addr);
      return -1;
    }

  return 0;
}

static void
session_delete_loopback (u32 sw_if_index)
{
  /* fails spectacularly  */
  /* vnet_delete_loopback_interface (sw_if_index); */
}

static int
session_test_basic (vlib_main_t * vm, unformat_input_t * input)
{
  session_endpoint_t server_sep = SESSION_ENDPOINT_NULL;
  u64 options[APP_OPTIONS_N_OPTIONS], bind4_handle, bind6_handle;
  clib_error_t *error = 0;
  u32 server_index;

  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .name = format (0, "session_test"),
  };

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "app attached");
  server_index = attach_args.app_index;
  vec_free (attach_args.name);

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
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);
  return 0;
}

static void
session_add_del_route_via_lookup_in_table (u32 in_table_id, u32 via_table_id,
					   ip4_address_t * ip, u8 mask,
					   u8 is_add)
{
  fib_route_path_t *rpaths = 0, *rpath;
  u32 in_fib_index, via_fib_index;

  fib_prefix_t prefix = {
    .fp_addr.ip4.as_u32 = ip->as_u32,
    .fp_len = mask,
    .fp_proto = FIB_PROTOCOL_IP4,
  };

  via_fib_index = fib_table_find (FIB_PROTOCOL_IP4, via_table_id);
  if (via_fib_index == ~0)
    {
      clib_warning ("couldn't resolve via table id to index");
      return;
    }
  in_fib_index = fib_table_find (FIB_PROTOCOL_IP4, in_table_id);
  if (in_fib_index == ~0)
    {
      clib_warning ("couldn't resolve in table id to index");
      return;
    }

  vec_add2 (rpaths, rpath, 1);
  clib_memset (rpath, 0, sizeof (*rpath));
  rpath->frp_weight = 1;
  rpath->frp_fib_index = via_fib_index;
  rpath->frp_proto = DPO_PROTO_IP4;
  rpath->frp_sw_if_index = ~0;
  rpath->frp_flags |= FIB_ROUTE_PATH_DEAG;

  if (is_add)
    fib_table_entry_path_add2 (in_fib_index, &prefix, FIB_SOURCE_CLI,
			       FIB_ENTRY_FLAG_NONE, rpath);
  else
    fib_table_entry_path_remove2 (in_fib_index, &prefix, FIB_SOURCE_CLI,
				  rpath);
  vec_free (rpaths);
}

static int
session_test_endpoint_cfg (vlib_main_t * vm, unformat_input_t * input)
{
  session_endpoint_cfg_t client_sep = SESSION_ENDPOINT_CFG_NULL;
  u32 server_index, client_index, sw_if_index[2], tries = 0;
  u64 options[APP_OPTIONS_N_OPTIONS], dummy_secret = 1234;
  u16 dummy_server_port = 1234, dummy_client_port = 5678;
  session_endpoint_t server_sep = SESSION_ENDPOINT_NULL;
  ip4_address_t intf_addr[3];
  transport_connection_t *tc;
  stream_session_t *s;
  clib_error_t *error;
  u8 *appns_id;

  /*
   * Create the loopbacks
   */
  intf_addr[0].as_u32 = clib_host_to_net_u32 (0x01010101),
    session_create_lookpback (0, &sw_if_index[0], &intf_addr[0]);

  intf_addr[1].as_u32 = clib_host_to_net_u32 (0x02020202),
    session_create_lookpback (1, &sw_if_index[1], &intf_addr[1]);

  session_add_del_route_via_lookup_in_table (0, 1, &intf_addr[1], 32,
					     1 /* is_add */ );
  session_add_del_route_via_lookup_in_table (1, 0, &intf_addr[0], 32,
					     1 /* is_add */ );

  /*
   * Insert namespace
   */
  appns_id = format (0, "appns1");
  vnet_app_namespace_add_del_args_t ns_args = {
    .ns_id = appns_id,
    .secret = dummy_secret,
    .sw_if_index = sw_if_index[1],
    .ip4_fib_id = 0,
    .is_add = 1
  };
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d",
		clib_error_get_code (error));

  /*
   * Attach client/server
   */
  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .name = format (0, "session_test_client"),
  };

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "client app attached");
  client_index = attach_args.app_index;
  vec_free (attach_args.name);

  attach_args.name = format (0, "session_test_server");
  attach_args.namespace_id = appns_id;
  attach_args.options[APP_OPTIONS_NAMESPACE_SECRET] = dummy_secret;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server app attached: %U", format_clib_error,
		error);
  vec_free (attach_args.name);
  server_index = attach_args.app_index;

  server_sep.is_ip4 = 1;
  server_sep.port = dummy_server_port;
  vnet_bind_args_t bind_args = {
    .sep = server_sep,
    .app_index = server_index,
  };
  error = vnet_bind (&bind_args);
  SESSION_TEST ((error == 0), "server bind should work");

  /*
   * Connect and force lcl ip
   */
  client_sep.is_ip4 = 1;
  client_sep.ip.ip4.as_u32 = clib_host_to_net_u32 (0x02020202);
  client_sep.port = dummy_server_port;
  client_sep.peer.is_ip4 = 1;
  client_sep.peer.ip.ip4.as_u32 = clib_host_to_net_u32 (0x01010101);
  client_sep.peer.port = dummy_client_port;
  client_sep.transport_proto = TRANSPORT_PROTO_TCP;

  vnet_connect_args_t connect_args = {
    .sep_ext = client_sep,
    .app_index = client_index,
  };

  connected_session_index = connected_session_thread = ~0;
  accepted_session_index = accepted_session_thread = ~0;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error == 0), "connect should work");

  /* wait for stuff to happen */
  while ((connected_session_index == ~0
	  || vec_len (tcp_main.wrk_ctx[0].pending_acks)) && ++tries < 100)
    vlib_process_suspend (vm, 100e-3);
  clib_warning ("waited %.1f seconds for connections", tries / 10.0);
  SESSION_TEST ((connected_session_index != ~0), "session should exist");
  SESSION_TEST ((connected_session_thread != ~0), "thread should exist");
  SESSION_TEST ((accepted_session_index != ~0), "session should exist");
  SESSION_TEST ((accepted_session_thread != ~0), "thread should exist");
  s = session_get (connected_session_index, connected_session_thread);
  tc = session_get_transport (s);
  SESSION_TEST ((tc != 0), "transport should exist");
  SESSION_TEST ((memcmp (&tc->lcl_ip, &client_sep.peer.ip,
			 sizeof (tc->lcl_ip)) == 0), "ips should be equal");
  SESSION_TEST ((tc->lcl_port == dummy_client_port), "ports should be equal");

  /* These sessions, because of the way they're established are pinned to
   * main thread, even when we have workers and we avoid polling main thread,
   * i.e., we can't cleanup pending disconnects, so force cleanup for both
   */
  session_transport_cleanup (s);
  s = session_get (accepted_session_index, accepted_session_thread);
  session_transport_cleanup (s);

  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  /* Allow the disconnects to finish before removing the routes. */
  vlib_process_suspend (vm, 10e-3);

  session_add_del_route_via_lookup_in_table (0, 1, &intf_addr[1], 32,
					     0 /* is_add */ );
  session_add_del_route_via_lookup_in_table (1, 0, &intf_addr[0], 32,
					     0 /* is_add */ );

  session_delete_loopback (sw_if_index[0]);
  session_delete_loopback (sw_if_index[1]);
  return 0;
}

static int
session_test_namespace (vlib_main_t * vm, unformat_input_t * input)
{
  u64 options[APP_OPTIONS_N_OPTIONS], dummy_secret = 1234;
  u32 server_index, server_st_index, server_local_st_index;
  u32 dummy_port = 1234, client_index, server_wrk_index;
  u32 dummy_api_context = 4321, dummy_client_api_index = ~0;
  u32 dummy_server_api_index = ~0, sw_if_index = 0;
  session_endpoint_t server_sep = SESSION_ENDPOINT_NULL;
  session_endpoint_t client_sep = SESSION_ENDPOINT_NULL;
  session_endpoint_t intf_sep = SESSION_ENDPOINT_NULL;
  clib_error_t *error = 0;
  u8 *ns_id = format (0, "appns1");
  app_namespace_t *app_ns;
  application_t *server;
  stream_session_t *s;
  u64 handle;
  int code;

  server_sep.is_ip4 = 1;
  server_sep.port = dummy_port;
  client_sep.is_ip4 = 1;
  client_sep.port = dummy_port;
  clib_memset (options, 0, sizeof (options));

  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .name = format (0, "session_test"),
  };

  vnet_bind_args_t bind_args = {
    .sep = server_sep,
    .app_index = 0,
  };

  vnet_connect_args_t connect_args = {
    .app_index = 0,
    .api_context = 0,
  };
  clib_memcpy (&connect_args.sep, &client_sep, sizeof (client_sep));

  vnet_unbind_args_t unbind_args = {
    .handle = bind_args.handle,
    .app_index = 0,
  };

  vnet_app_detach_args_t detach_args = {
    .app_index = 0,
    .api_client_index = ~0,
  };

  ip4_address_t intf_addr = {
    .as_u32 = clib_host_to_net_u32 (0x07000105),
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
  server_wrk_index = application_get_default_worker (server)->wrk_index;
  SESSION_TEST ((server->ns_index == 0),
		"server should be in the default ns");

  bind_args.app_index = server_index;
  error = vnet_bind (&bind_args);
  SESSION_TEST ((error == 0), "server bind should work");

  server_st_index = application_session_table (server, FIB_PROTOCOL_IP4);
  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s != 0), "listener should exist in global table");
  SESSION_TEST ((s->app_wrk_index == server_wrk_index), "app_index should be"
		" that of the server");
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
  server_wrk_index = application_get_default_worker (server)->wrk_index;
  SESSION_TEST ((server->ns_index == app_namespace_index (app_ns)),
		"server should be in the right ns");

  bind_args.app_index = server_index;
  error = vnet_bind (&bind_args);
  SESSION_TEST ((error == 0), "bind should work");
  server_st_index = application_session_table (server, FIB_PROTOCOL_IP4);
  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s != 0), "listener should exist in global table");
  SESSION_TEST ((s->app_wrk_index == server_wrk_index), "app_index should be"
		" that of the server");
  server_local_st_index = application_local_session_table (server);
  handle = session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((handle != SESSION_INVALID_HANDLE),
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
  SESSION_TEST ((dummy_segment_count == 0),
		"shouldn't have received request to map new segment");
  connect_args.sep.ip.ip4.as_u8[0] = 127;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error == 0), "client connect should not return error code");
  code = clib_error_get_code (error);
  SESSION_TEST ((dummy_segment_count == 1),
		"should've received request to map new segment");
  SESSION_TEST ((dummy_accept == 1), "should've received accept request");
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
  handle = session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((handle == SESSION_INVALID_HANDLE),
		"listener should not exist in local table");

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
  handle = session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((handle != SESSION_INVALID_HANDLE),
		"listener should exist in local table");

  unbind_args.handle = bind_args.handle;
  error = vnet_unbind (&unbind_args);
  SESSION_TEST ((error == 0), "unbind should work");

  handle = session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((handle == SESSION_INVALID_HANDLE),
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
  session_create_lookpback (0, &sw_if_index, &intf_addr);

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
  server = application_get (server_index);
  server_wrk_index = application_get_default_worker (server)->wrk_index;

  bind_args.app_index = server_index;
  error = vnet_bind (&bind_args);
  server_st_index = application_session_table (server, FIB_PROTOCOL_IP4);
  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s == 0), "zero listener should not exist in global table");

  s = session_lookup_listener (server_st_index, &intf_sep);
  SESSION_TEST ((s != 0), "intf listener should exist in global table");
  SESSION_TEST ((s->app_wrk_index == server_wrk_index), "app_index should be "
		"that of the server");
  server_local_st_index = application_local_session_table (server);
  handle = session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((handle != SESSION_INVALID_HANDLE),
		"zero listener should exist in local table");
  detach_args.app_index = server_index;
  vnet_application_detach (&detach_args);

  /*
   * Cleanup
   */
  vec_free (attach_args.name);
  vec_free (ns_id);
  session_delete_loopback (sw_if_index);
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

  clib_memset (srt, 0, sizeof (*srt));
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
  u64 options[APP_OPTIONS_N_OPTIONS];
  u16 lcl_port = 1234, rmt_port = 4321;
  u32 server_index, server_index2;
  u32 dummy_server_api_index = ~0;
  transport_connection_t *tc;
  u32 dummy_port = 1111;
  clib_error_t *error = 0;
  u8 is_filtered = 0, *ns_id = format (0, "appns1");
  stream_session_t *listener, *s;
  app_namespace_t *default_ns = app_namespace_get_default ();
  u32 local_ns_index = default_ns->local_table_index;
  int verbose = 0, rv;
  app_namespace_t *app_ns;
  u64 handle;

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
  clib_memset (options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &dummy_session_cbs,
    .name = format (0, "session_test"),
  };

  vnet_bind_args_t bind_args = {
    .sep = server_sep,
    .app_index = 0,
  };

  /*
   * Attach server with global and local default scope
   */
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
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
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
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
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
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
  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle != server_index), "local session endpoint lookup "
		"should not work (global scope)");

  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port + 1,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
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
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc->c_index == listener->connection_index),
		"optimized lookup for lcl port + 1 should work");
  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == server_index), "local session endpoint lookup "
		"should work (lcl ip was zeroed)");

  /*
   * Add deny rule 1.2.3.4/32 1234 5.6.7.8/32 4321 action -2 (drop)
   */
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 30;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 30;
  args.table_args.action_index = SESSION_RULES_TABLE_ACTION_DROP;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/30 1234 5.6.7.8/30 4321 action %d",
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
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc == 0), "lookup for 1.2.3.4/32 1234 5.6.7.8/16 4321 "
		"should fail (deny rule)");
  SESSION_TEST ((is_filtered == 1), "lookup should be filtered (deny)");

  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_DROP_HANDLE), "lookup for 1.2.3.4/32 1234 "
		"5.6.7.8/16 4321 in local table should return deny");

  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port + 1,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc->c_index == listener->connection_index),
		"lookup 1.2.3.4/32 123*5* 5.6.7.8/16 4321 should work");

  /*
   * "Mask" deny rule with more specific allow:
   * Add allow rule 1.2.3.4/32 1234 5.6.7.8/32 4321 action -3 (allow)
   */
  args.table_args.is_add = 1;
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 32;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 32;
  args.table_args.action_index = SESSION_RULES_TABLE_ACTION_ALLOW;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add masking rule 1.2.3.4/30 1234 5.6.7.8/32 "
		"4321 action %d", args.table_args.action_index);

  is_filtered = 0;
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc == 0), "lookup for 1.2.3.4/32 1234 5.6.7.8/16 4321 "
		"should fail (allow without app)");
  SESSION_TEST ((is_filtered == 0), "lookup should NOT be filtered");

  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_INVALID_HANDLE), "lookup for 1.2.3.4/32 "
		"1234 5.6.7.8/32 4321 in local table should return invalid");

  if (verbose)
    {
      vlib_cli_output (vm, "Local rules");
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }

  sep.ip.ip4.as_u32 += 1 << 24;
  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_DROP_HANDLE), "lookup for 1.2.3.4/32 1234"
		" 5.6.7.9/32 4321 in local table should return deny");

  vnet_connect_args_t connect_args = {
    .app_index = attach_args.app_index,
    .api_context = 0,
  };
  clib_memcpy (&connect_args.sep, &sep, sizeof (sep));

  /* Try connecting */
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "connect should fail");
  rv = clib_error_get_code (error);
  SESSION_TEST ((rv == VNET_API_ERROR_APP_CONNECT_FILTERED),
		"connect should be filtered");

  sep.ip.ip4.as_u32 -= 1 << 24;

  /*
   * Delete masking rule: 1.2.3.4/32 1234 5.6.7.8/32 4321 allow
   */
  args.table_args.is_add = 0;
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 32;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 32;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/32 1234 5.6.7.8/32 4321 allow");


  /*
   * Add local scope rule for 0/0 * 5.6.7.8/16 4321 action server_index
   */
  args.table_args.is_add = 1;
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

  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_DROP_HANDLE),
		"local session endpoint lookup should return deny");

  /*
   * Delete 1.2.3.4/32 1234 5.6.7.8/32 4321 deny
   */
  args.table_args.is_add = 0;
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 30;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 30;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/32 1234 5.6.7.8/32 4321 deny");

  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_INVALID_HANDLE),
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
  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle != server_index), "local session endpoint lookup "
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
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
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
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc == 0), "lookup 1.2.3.4/32 1234 5.6.7.8/16 4321 should "
		"not work (del + deny)");

  SESSION_TEST ((error == 0), "Del 1.2.3.4/32 1234 5.6.7.8/32 4321 deny");
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc == 0), "lookup 1.2.3.4/32 1234 5.6.7.8/16 4321 should"
		" not work (no-rule)");

  /*
   * Test tags. Add/overwrite/del rule with tag
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
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc->c_index == listener->connection_index),
		"lookup 1.2.3.4/32 1234 5.6.7.8/16 4321 should work");

  vec_free (args.table_args.tag);
  args.table_args.lcl_port = 1234;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 16;
  args.table_args.tag = format (0, "test_rule_overwrite");
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0),
		"Overwrite 1.2.3.4/16 1234 5.6.7.8/16 4321 deny tag test_rule"
		" should work");
  if (verbose)
    {
      session_lookup_dump_rules_table (0, FIB_PROTOCOL_IP4,
				       TRANSPORT_PROTO_TCP);
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }

  args.table_args.is_add = 0;
  args.table_args.lcl_port += 1;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/32 1234 5.6.7.8/32 4321 deny "
		"tag %v", args.table_args.tag);
  if (verbose)
    {
      session_lookup_dump_rules_table (0, FIB_PROTOCOL_IP4,
				       TRANSPORT_PROTO_TCP);
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }
  tc = session_lookup_connection_wt4 (0, &lcl_pref.fp_addr.ip4,
				      &rmt_pref.fp_addr.ip4, lcl_port,
				      rmt_port, TRANSPORT_PROTO_TCP, 0,
				      &is_filtered);
  SESSION_TEST ((tc == 0), "lookup 1.2.3.4/32 1234 5.6.7.8/32 4321 should not"
		" work (del)");


  /*
   * Test local rules with multiple namespaces
   */

  /*
   * Add deny rule 1.2.3.4/32 1234 5.6.7.8/32 0 action -2 (drop)
   */
  args.table_args.is_add = 1;
  args.table_args.lcl_port = 1234;
  args.table_args.rmt_port = 0;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 32;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 32;
  args.table_args.action_index = SESSION_RULES_TABLE_ACTION_DROP;
  args.table_args.tag = 0;
  args.scope = SESSION_RULE_SCOPE_LOCAL;
  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/32 1234 5.6.7.8/32 4321 action %d",
		args.table_args.action_index);
  /*
   * Add 'white' rule 1.2.3.4/32 1234 5.6.7.8/32 4321 action -2 (drop)
   */
  args.table_args.is_add = 1;
  args.table_args.lcl_port = 1234;
  args.table_args.rmt_port = 4321;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 32;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 32;
  args.table_args.action_index = SESSION_RULES_TABLE_ACTION_ALLOW;
  error = vnet_session_rule_add_del (&args);

  if (verbose)
    {
      session_lookup_dump_local_rules_table (local_ns_index, FIB_PROTOCOL_IP4,
					     TRANSPORT_PROTO_TCP);
    }

  vnet_app_namespace_add_del_args_t ns_args = {
    .ns_id = ns_id,
    .secret = 0,
    .sw_if_index = APP_NAMESPACE_INVALID_INDEX,
    .is_add = 1
  };
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d",
		clib_error_get_code (error));
  app_ns = app_namespace_get_from_id (ns_id);

  attach_args.namespace_id = ns_id;
  attach_args.api_client_index = dummy_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server2 attached");
  server_index2 = attach_args.app_index;

  /*
   * Add deny rule 1.2.3.4/32 1234 5.6.7.8/32 0 action -2 (drop)
   */
  args.table_args.lcl_port = 1234;
  args.table_args.rmt_port = 0;
  args.table_args.lcl.fp_addr.ip4 = lcl_ip;
  args.table_args.lcl.fp_len = 32;
  args.table_args.rmt.fp_addr.ip4 = rmt_ip;
  args.table_args.rmt.fp_len = 32;
  args.table_args.action_index = SESSION_RULES_TABLE_ACTION_DROP;
  args.appns_index = app_namespace_index (app_ns);

  error = vnet_session_rule_add_del (&args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/32 1234 5.6.7.8/32 4321 action %d "
		"in test namespace", args.table_args.action_index);
  /*
   * Lookup default namespace
   */
  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_INVALID_HANDLE),
		"lookup for 1.2.3.4/32 1234 5.6.7.8/32 4321 in local table "
		"should return allow (invalid)");

  sep.port += 1;
  handle = session_lookup_local_endpoint (local_ns_index, &sep);
  SESSION_TEST ((handle == SESSION_DROP_HANDLE), "lookup for 1.2.3.4/32 1234 "
		"5.6.7.8/16 432*2* in local table should return deny");


  connect_args.app_index = server_index;
  clib_memcpy (&connect_args.sep, &sep, sizeof (sep));

  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "connect should fail");
  rv = clib_error_get_code (error);
  SESSION_TEST ((rv == VNET_API_ERROR_APP_CONNECT_FILTERED),
		"connect should be filtered");

  /*
   * Lookup test namespace
   */
  handle = session_lookup_local_endpoint (app_ns->local_table_index, &sep);
  SESSION_TEST ((handle == SESSION_DROP_HANDLE), "lookup for 1.2.3.4/32 1234 "
		"5.6.7.8/16 4321 in local table should return deny");

  connect_args.app_index = server_index;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "connect should fail");
  rv = clib_error_get_code (error);
  SESSION_TEST ((rv == VNET_API_ERROR_APP_CONNECT_FILTERED),
		"connect should be filtered");

  args.table_args.is_add = 0;
  vnet_session_rule_add_del (&args);

  args.appns_index = 0;
  args.table_args.is_add = 0;
  vnet_session_rule_add_del (&args);

  args.table_args.rmt_port = 4321;
  vnet_session_rule_add_del (&args);
  /*
   * Final Cleanup
   */
  vec_free (args.table_args.tag);
  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);

  detach_args.app_index = server_index2;
  vnet_application_detach (&detach_args);

  vec_free (ns_id);
  vec_free (attach_args.name);
  return 0;
}

static int
session_test_proxy (vlib_main_t * vm, unformat_input_t * input)
{
  u64 options[APP_OPTIONS_N_OPTIONS];
  char *show_listeners = "sh session listeners tcp verbose";
  char *show_local_listeners = "sh app ns table default";
  unformat_input_t tmp_input;
  u32 server_index, app_index;
  u32 dummy_server_api_index = ~0, sw_if_index = 0;
  clib_error_t *error = 0;
  u8 is_filtered = 0;
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
  session_create_lookpback (0, &sw_if_index, &lcl_ip);

  app_ns = app_namespace_get_default ();
  app_ns->sw_if_index = sw_if_index;

  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
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
    .name = format (0, "session_test"),
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
				      TRANSPORT_PROTO_TCP, 0, &is_filtered);
  SESSION_TEST ((tc != 0), "lookup 1.2.3.4 1234 5.6.7.8 4321 should be "
		"successful");
  s = listen_session_get (tc->s_index);
  SESSION_TEST ((s->app_index == server_index), "lookup should return"
		" the server");

  tc = session_lookup_connection_wt4 (0, &rmt_ip, &rmt_ip, lcl_port, rmt_port,
				      TRANSPORT_PROTO_TCP, 0, &is_filtered);
  SESSION_TEST ((tc == 0), "lookup 5.6.7.8 1234 5.6.7.8 4321 should"
		" not work");

  app_index = session_lookup_local_endpoint (app_ns->local_table_index, &sep);
  SESSION_TEST ((app_index == server_index), "local session endpoint lookup"
		" should work");

  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
    .api_client_index = ~0,
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
  if (verbose)
    unformat_free (&tmp_input);
  vec_free (attach_args.name);
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
      else if (unformat (input, "endpt-cfg"))
	res = session_test_endpoint_cfg (vm, input);
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
	  if ((res = session_test_endpoint_cfg (vm, input)))
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
