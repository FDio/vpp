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

#include <arpa/inet.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <vnet/session/transport.h>
#include <sys/epoll.h>
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

#define SESSION_TEST(_cond, _comment, _args...)                               \
  do                                                                          \
    {                                                                         \
      if (!SESSION_TEST_I (_cond, _comment, ##_args))                         \
	{                                                                     \
	  return 1;                                                           \
	}                                                                     \
    }                                                                         \
  while (0)

#define ST_DBG(_comment, _args...)				\
    fformat(stderr,  _comment "\n",  ##_args);			\

void
placeholder_session_reset_callback (session_t * s)
{
  clib_warning ("called...");
}

volatile u32 connected_session_index = ~0;
volatile u32 connected_session_thread = ~0;
static u32 placeholder_accept;
volatile u32 accepted_session_index;
volatile u32 accepted_session_thread;
volatile int app_session_error = 0;

int
placeholder_session_connected_callback (u32 app_index, u32 api_context,
					session_t * s, session_error_t err)
{
  if (s)
    {
      connected_session_index = s->session_index;
      connected_session_thread = s->thread_index;
    }
  return 0;
}

static u32 placeholder_segment_count;

int
placeholder_add_segment_callback (u32 client_index, u64 segment_handle)
{
  placeholder_segment_count = 1;
  return 0;
}

int
placeholder_del_segment_callback (u32 client_index, u64 segment_handle)
{
  placeholder_segment_count = 0;
  return 0;
}

void
placeholder_session_disconnect_callback (session_t * s)
{
  if (!(s->session_index == connected_session_index &&
	s->thread_index == connected_session_thread) &&
      !(s->session_index == accepted_session_index &&
	s->thread_index == accepted_session_thread))
    {
      clib_warning (0, "unexpected disconnect s %u thread %u",
		    s->session_index, s->thread_index);
      app_session_error = 1;
    }
  vnet_disconnect_args_t da = {
    .handle = session_handle (s),
    .app_index = app_worker_get (s->app_wrk_index)->app_index
  };
  vnet_disconnect_session (&da);
}

int
placeholder_session_accept_callback (session_t * s)
{
  placeholder_accept = 1;
  accepted_session_index = s->session_index;
  accepted_session_thread = s->thread_index;
  s->session_state = SESSION_STATE_READY;
  return 0;
}

int
placeholder_server_rx_callback (session_t * s)
{
  clib_warning ("called...");
  return -1;
}

void
placeholder_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  if (s->session_index == connected_session_index &&
      s->thread_index == connected_session_thread)
    {
      connected_session_index = ~0;
      connected_session_thread = ~0;
    }
  else if (s->session_index == accepted_session_index &&
	   s->thread_index == accepted_session_thread)
    {
      accepted_session_index = ~0;
      accepted_session_thread = ~0;
    }
  else
    {
      clib_warning (0, "unexpected cleanup s %u thread %u", s->session_index,
		    s->thread_index);
      app_session_error = 1;
    }
}

static session_cb_vft_t placeholder_session_cbs = {
  .session_reset_callback = placeholder_session_reset_callback,
  .session_connected_callback = placeholder_session_connected_callback,
  .session_accept_callback = placeholder_session_accept_callback,
  .session_disconnect_callback = placeholder_session_disconnect_callback,
  .builtin_app_rx_callback = placeholder_server_rx_callback,
  .session_cleanup_callback = placeholder_cleanup_callback,
  .add_segment_callback = placeholder_add_segment_callback,
  .del_segment_callback = placeholder_del_segment_callback,
};

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
      ip_table_create (FIB_PROTOCOL_IP4, table_id, 0 /* is_api */,
		       1 /* create_mfib */, 0);
      ip_table_bind (FIB_PROTOCOL_IP4, *sw_if_index, table_id);
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

  vnet_sw_interface_set_flags (vnet_get_main (), sw_if_index, 0);
}

static int
session_test_basic (vlib_main_t * vm, unformat_input_t * input)
{
  session_endpoint_cfg_t server_sep = SESSION_ENDPOINT_CFG_NULL;
  u64 options[APP_OPTIONS_N_OPTIONS], bind4_handle, bind6_handle;
  u32 server_index;
  int error = 0;

  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "session_test"),
  };

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "app attached");
  server_index = attach_args.app_index;
  vec_free (attach_args.name);

  server_sep.is_ip4 = 1;
  vnet_listen_args_t bind_args = {
    .sep_ext = server_sep,
    .app_index = 0,
    .wrk_map_index = 0,
  };

  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "server bind4 should work");
  bind4_handle = bind_args.handle;

  error = vnet_listen (&bind_args);
  SESSION_TEST ((error != 0), "double server bind4 should not work");

  bind_args.sep.is_ip4 = 0;
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "server bind6 should work");
  bind6_handle = bind_args.handle;

  error = vnet_listen (&bind_args);
  SESSION_TEST ((error != 0), "double server bind6 should not work");

  vnet_unlisten_args_t unbind_args = {
    .handle = bind4_handle,
    .app_index = server_index,
  };
  error = vnet_unlisten (&unbind_args);
  SESSION_TEST ((error == 0), "unbind4 should work");

  unbind_args.handle = bind6_handle;
  error = vnet_unlisten (&unbind_args);
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
  u64 options[APP_OPTIONS_N_OPTIONS], placeholder_secret = 1234;
  u16 placeholder_server_port = 1234, placeholder_client_port = 5678;
  session_endpoint_cfg_t server_sep = SESSION_ENDPOINT_CFG_NULL;
  u32 client_vrf = 0, server_vrf = 1;
  ip4_address_t intf_addr[3];
  transport_connection_t *tc;
  session_t *s;
  u8 *appns_id;
  int error;

  /*
   * Create the loopbacks
   */
  intf_addr[0].as_u32 = clib_host_to_net_u32 (0x01010101);
  session_create_lookpback (client_vrf, &sw_if_index[0], &intf_addr[0]);

  intf_addr[1].as_u32 = clib_host_to_net_u32 (0x02020202);
  session_create_lookpback (server_vrf, &sw_if_index[1], &intf_addr[1]);

  session_add_del_route_via_lookup_in_table (
    client_vrf, server_vrf, &intf_addr[1], 32, 1 /* is_add */);
  session_add_del_route_via_lookup_in_table (
    server_vrf, client_vrf, &intf_addr[0], 32, 1 /* is_add */);

  /*
   * Insert namespace
   */
  appns_id = format (0, "appns_server");
  vnet_app_namespace_add_del_args_t ns_args = {
    .ns_id = appns_id,
    .secret = placeholder_secret,
    .sw_if_index = sw_if_index[1], /* server interface*/
    .ip4_fib_id = 0,		   /* sw_if_index takes precedence */
    .is_add = 1
  };
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d", error);

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
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "session_test_client"),
  };

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "client app attached");
  client_index = attach_args.app_index;
  vec_free (attach_args.name);

  attach_args.name = format (0, "session_test_server");
  attach_args.namespace_id = appns_id;
  /* Allow server to allocate another segment for listens. Needed
   * because by default we do not allow segment additions */
  attach_args.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 32 << 20;
  attach_args.options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server app attached: %U", format_clib_error,
		error);
  vec_free (attach_args.name);
  server_index = attach_args.app_index;

  server_sep.is_ip4 = 1;
  server_sep.port = placeholder_server_port;
  vnet_listen_args_t bind_args = {
    .sep_ext = server_sep,
    .app_index = server_index,
  };
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "server bind should work");

  /*
   * Connect and force lcl ip
   */
  client_sep.is_ip4 = 1;
  client_sep.ip.ip4.as_u32 = intf_addr[1].as_u32;
  client_sep.port = placeholder_server_port;
  client_sep.peer.is_ip4 = 1;
  client_sep.peer.ip.ip4.as_u32 = intf_addr[0].as_u32;
  client_sep.peer.port = placeholder_client_port;
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
  while (connected_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  while (accepted_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

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
  SESSION_TEST ((tc->lcl_port == placeholder_client_port),
		"ports should be equal");

  /* Disconnect server session, should lead to faster port cleanup on client */
  vnet_disconnect_args_t disconnect_args = {
    .handle =
      session_make_handle (accepted_session_index, accepted_session_thread),
    .app_index = server_index,
  };

  error = vnet_disconnect_session (&disconnect_args);
  SESSION_TEST ((error == 0), "disconnect should work");

  /* wait for stuff to happen */
  tries = 0;
  while (connected_session_index != ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  /* Active closes take longer to cleanup, don't wait */

  clib_warning ("waited %.1f seconds for disconnect", tries / 10.0);
  SESSION_TEST ((connected_session_index == ~0), "session should not exist");
  SESSION_TEST ((connected_session_thread == ~0), "thread should not exist");
  SESSION_TEST (transport_port_local_in_use () == 0,
		"port should be cleaned up");
  SESSION_TEST ((app_session_error == 0), "no app session errors");

  /* Start cleanup by detaching apps */
  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  ns_args.is_add = 0;
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns delete should succeed: %d", error);

  /* Allow the disconnects to finish before removing the routes. */
  vlib_process_suspend (vm, 10e-3);

  session_add_del_route_via_lookup_in_table (
    client_vrf, server_vrf, &intf_addr[1], 32, 0 /* is_add */);
  session_add_del_route_via_lookup_in_table (
    server_vrf, client_vrf, &intf_addr[0], 32, 0 /* is_add */);

  session_delete_loopback (sw_if_index[0]);
  session_delete_loopback (sw_if_index[1]);

  /*
   * Redo the test but with client in the non-default namespace
   */

  /* Create the loopbacks */
  client_vrf = 1;
  server_vrf = 0;
  session_create_lookpback (client_vrf, &sw_if_index[0], &intf_addr[0]);
  session_create_lookpback (server_vrf, &sw_if_index[1], &intf_addr[1]);

  session_add_del_route_via_lookup_in_table (
    client_vrf, server_vrf, &intf_addr[1], 32, 1 /* is_add */);
  session_add_del_route_via_lookup_in_table (
    server_vrf, client_vrf, &intf_addr[0], 32, 1 /* is_add */);

  /* Insert new client namespace */
  vec_free (appns_id);
  appns_id = format (0, "appns_client");
  ns_args.ns_id = appns_id;
  ns_args.sw_if_index = sw_if_index[0]; /* client interface*/
  ns_args.is_add = 1;

  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %U",
		format_session_error, error);

  /* Attach client */
  attach_args.name = format (0, "session_test_client");
  attach_args.namespace_id = appns_id;
  attach_args.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 0;
  attach_args.options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret;
  attach_args.api_client_index = ~0;

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "client app attached: %U", format_session_error,
		error);
  client_index = attach_args.app_index;
  vec_free (attach_args.name);

  /* Attach server */
  attach_args.name = format (0, "session_test_server");
  attach_args.namespace_id = 0;
  attach_args.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 32 << 20;
  attach_args.options[APP_OPTIONS_NAMESPACE_SECRET] = 0;
  attach_args.api_client_index = ~0;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server app attached: %U", format_session_error,
		error);
  vec_free (attach_args.name);
  server_index = attach_args.app_index;

  /* Bind server */
  clib_memset (&server_sep, 0, sizeof (server_sep));
  server_sep.is_ip4 = 1;
  server_sep.port = placeholder_server_port;
  bind_args.sep_ext = server_sep;
  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "server bind should work: %U",
		format_session_error, error);

  /* Connect client */
  connected_session_index = connected_session_thread = ~0;
  accepted_session_index = accepted_session_thread = ~0;
  clib_memset (&client_sep, 0, sizeof (client_sep));
  client_sep.is_ip4 = 1;
  client_sep.ip.ip4.as_u32 = intf_addr[1].as_u32;
  client_sep.port = placeholder_server_port;
  client_sep.peer.is_ip4 = 1;
  client_sep.peer.ip.ip4.as_u32 = intf_addr[0].as_u32;
  client_sep.peer.port = placeholder_client_port;
  client_sep.transport_proto = TRANSPORT_PROTO_TCP;

  connect_args.sep_ext = client_sep;
  connect_args.app_index = client_index;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error == 0), "connect should work");

  /* wait for stuff to happen */
  while (connected_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  while (accepted_session_index == ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  clib_warning ("waited %.1f seconds for connections", tries / 10.0);
  SESSION_TEST ((connected_session_index != ~0), "session should exist");
  SESSION_TEST ((connected_session_thread != ~0), "thread should exist");
  SESSION_TEST ((accepted_session_index != ~0), "session should exist");
  SESSION_TEST ((accepted_session_thread != ~0), "thread should exist");
  s = session_get (connected_session_index, connected_session_thread);
  tc = session_get_transport (s);
  SESSION_TEST ((tc != 0), "transport should exist");
  SESSION_TEST (
    (memcmp (&tc->lcl_ip, &client_sep.peer.ip, sizeof (tc->lcl_ip)) == 0),
    "ips should be equal");
  SESSION_TEST ((tc->lcl_port == placeholder_client_port),
		"ports should be equal");

  /* Disconnect server session, for faster port cleanup on client */
  disconnect_args.app_index = server_index;
  disconnect_args.handle =
    session_make_handle (accepted_session_index, accepted_session_thread);

  error = vnet_disconnect_session (&disconnect_args);
  SESSION_TEST ((error == 0), "disconnect should work");

  /* wait for stuff to happen */
  tries = 0;
  while (connected_session_index != ~0 && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  /* Active closes take longer to cleanup, don't wait */

  clib_warning ("waited %.1f seconds for disconnect", tries / 10.0);
  SESSION_TEST ((connected_session_index == ~0), "session should not exist");
  SESSION_TEST ((connected_session_thread == ~0), "thread should not exist");
  SESSION_TEST ((app_session_error == 0), "no app session errors");
  SESSION_TEST (transport_port_local_in_use () == 0,
		"port should be cleaned up");

  /* Start cleanup by detaching apps */
  detach_args.app_index = server_index;
  vnet_application_detach (&detach_args);
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  ns_args.is_add = 0;
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns delete should succeed: %d", error);

  /* Allow the disconnects to finish before removing the routes. */
  vlib_process_suspend (vm, 10e-3);

  session_add_del_route_via_lookup_in_table (
    client_vrf, server_vrf, &intf_addr[1], 32, 0 /* is_add */);
  session_add_del_route_via_lookup_in_table (
    server_vrf, client_vrf, &intf_addr[0], 32, 0 /* is_add */);

  session_delete_loopback (sw_if_index[0]);
  session_delete_loopback (sw_if_index[1]);

  return 0;
}

static int
session_test_namespace (vlib_main_t * vm, unformat_input_t * input)
{
  u64 options[APP_OPTIONS_N_OPTIONS], placeholder_secret = 1234, tries;
  u32 server_index, server_st_index, server_local_st_index;
  u32 placeholder_port = 1234, client_index, server_wrk_index;
  u32 placeholder_api_context = 4321, placeholder_client_api_index = ~0;
  u32 placeholder_server_api_index = ~0, sw_if_index = 0;
  session_endpoint_t server_sep = SESSION_ENDPOINT_NULL;
  session_endpoint_t client_sep = SESSION_ENDPOINT_NULL;
  session_endpoint_t intf_sep = SESSION_ENDPOINT_NULL;
  u8 *ns_id, *server_name, *client_name;
  app_namespace_t *app_ns;
  application_t *server;
  session_t *s;
  u64 handle;
  int error = 0;

  /* Make sure segment count and accept are reset before starting test
   * in case tests are ran multiple times */
  placeholder_segment_count = 0;
  placeholder_accept = 0;

  ns_id = format (0, "appns1");
  server_name = format (0, "session_test");
  client_name = format (0, "session_test_client");

  server_sep.is_ip4 = 1;
  server_sep.port = placeholder_port;
  client_sep.is_ip4 = 1;
  client_sep.port = placeholder_port;
  clib_memset (options, 0, sizeof (options));

  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = server_name,
  };

  vnet_listen_args_t bind_args = {
    .sep = server_sep,
    .app_index = 0,
  };

  vnet_connect_args_t connect_args = {
    .app_index = 0,
    .api_context = 0,
  };
  clib_memcpy (&connect_args.sep, &client_sep, sizeof (client_sep));

  vnet_unlisten_args_t unbind_args = {
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
  intf_sep.port = placeholder_port;

  /*
   * Insert namespace and lookup
   */

  vnet_app_namespace_add_del_args_t ns_args = {
    .ns_id = ns_id,
    .secret = placeholder_secret,
    .sw_if_index = APP_NAMESPACE_INVALID_INDEX,
    .is_add = 1
  };
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d", error);

  app_ns = app_namespace_get_from_id (ns_id);
  SESSION_TEST ((app_ns != 0), "should find ns %v status", ns_id);
  SESSION_TEST ((app_ns->ns_secret == placeholder_secret),
		"secret should be %d", placeholder_secret);
  SESSION_TEST ((app_ns->sw_if_index == APP_NAMESPACE_INVALID_INDEX),
		"sw_if_index should be invalid");

  /*
   * Try application attach with wrong secret
   */

  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret - 1;
  attach_args.namespace_id = ns_id;
  attach_args.api_client_index = placeholder_server_api_index;

  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error != 0), "app attachment should fail");
  SESSION_TEST ((error == SESSION_E_WRONG_NS_SECRET),
		"code should be wrong ns secret: %d", error);

  /*
   * Attach server with global default scope
   */
  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_NAMESPACE_SECRET] = 0;
  attach_args.namespace_id = 0;
  attach_args.api_client_index = placeholder_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");
  server_index = attach_args.app_index;
  server = application_get (server_index);
  server_wrk_index = application_get_default_worker (server)->wrk_index;
  SESSION_TEST ((server->ns_index == 0),
		"server should be in the default ns");

  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
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
  error = vnet_unlisten (&unbind_args);
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
  options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret;
  attach_args.namespace_id = ns_id;
  attach_args.api_client_index = placeholder_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");
  server_index = attach_args.app_index;
  server = application_get (server_index);
  server_wrk_index = application_get_default_worker (server)->wrk_index;
  SESSION_TEST ((server->ns_index == app_namespace_index (app_ns)),
		"server should be in the right ns");

  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
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
  attach_args.name = client_name;
  attach_args.api_client_index = placeholder_client_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "client attachment should work");
  client_index = attach_args.app_index;
  connect_args.api_context = placeholder_api_context;
  connect_args.app_index = client_index;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "client connect should return error code");
  SESSION_TEST ((error == SESSION_E_INVALID_RMT_IP),
		"error code should be invalid value (zero ip)");
  SESSION_TEST ((placeholder_segment_count == 0),
		"shouldn't have received request to map new segment");
  connect_args.sep.ip.ip4.as_u8[0] = 127;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error == 0), "client connect should not return error code");

  /* wait for accept */
  tries = 0;
  while (!placeholder_accept && ++tries < 100)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 100e-3);
      vlib_worker_thread_barrier_sync (vm);
    }

  SESSION_TEST ((placeholder_segment_count == 1),
		"should've received request to map new segment");
  SESSION_TEST ((placeholder_accept == 1),
		"should've received accept request");
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  options[APP_OPTIONS_FLAGS] &= ~APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  attach_args.api_client_index = placeholder_client_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "client attachment should work");
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "client connect should return error code");
  SESSION_TEST ((error == SESSION_E_NOINTF),
		"error code should be connect (nothing in local scope)");
  detach_args.app_index = client_index;
  vnet_application_detach (&detach_args);

  /*
   * Unbind and detach server and then re-attach with local scope only
   */
  unbind_args.handle = bind_args.handle;
  unbind_args.app_index = server_index;
  error = vnet_unlisten (&unbind_args);
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
  attach_args.api_client_index = placeholder_server_api_index;
  attach_args.name = server_name;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "app attachment should work");
  server_index = attach_args.app_index;
  server = application_get (server_index);
  SESSION_TEST ((server->ns_index == app_namespace_index (app_ns)),
		"app should be in the right ns");

  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "bind should work");

  server_st_index = application_session_table (server, FIB_PROTOCOL_IP4);
  s = session_lookup_listener (server_st_index, &server_sep);
  SESSION_TEST ((s == 0), "listener should not exist in global table");
  server_local_st_index = application_local_session_table (server);
  handle = session_lookup_local_endpoint (server_local_st_index, &server_sep);
  SESSION_TEST ((handle != SESSION_INVALID_HANDLE),
		"listener should exist in local table");

  unbind_args.handle = bind_args.handle;
  error = vnet_unlisten (&unbind_args);
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
  attach_args.api_client_index = placeholder_client_api_index;
  attach_args.name = client_name;
  vnet_application_attach (&attach_args);
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "client connect should return error code");
  SESSION_TEST ((error == SESSION_E_NOROUTE),
		"error code should be noroute (not in same ns)");
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
   * Update namespace with interface
   */
  ns_args.sw_if_index = sw_if_index;
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d", error);

  /*
   * Attach server with local and global scope
   */
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_NAMESPACE_SECRET] = placeholder_secret;
  attach_args.namespace_id = ns_id;
  attach_args.api_client_index = placeholder_server_api_index;
  attach_args.name = server_name;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");
  server_index = attach_args.app_index;
  server = application_get (server_index);
  server_wrk_index = application_get_default_worker (server)->wrk_index;

  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
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

  ns_args.is_add = 0;
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns delete should succeed: %d", error);

  /*
   * Cleanup
   */
  vec_free (server_name);
  vec_free (client_name);
  vec_free (ns_id);
  session_delete_loopback (sw_if_index);
  return 0;
}

static void
session_test_disable_rt_backend_engine (vlib_main_t *vm)
{
  session_enable_disable_args_t args = { .is_en = 0,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_DISABLE };
  vnet_session_enable_disable (vm, &args);
}

static void
session_test_enable_rule_table_engine (vlib_main_t *vm)
{
  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vnet_session_enable_disable (vm, &args);
}

static void
session_test_enable_sdl_engine (vlib_main_t *vm)
{
  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_SDL };
  vnet_session_enable_disable (vm, &args);
}

static int
session_test_rule_table (vlib_main_t * vm, unformat_input_t * input)
{
  session_table_t *st = session_table_alloc ();
  u16 lcl_port = 1234, rmt_port = 4321;
  u32 action_index = 1, res;
  ip4_address_t lcl_lkup, rmt_lkup;
  int verbose = 0, error;

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

  session_test_disable_rt_backend_engine (vm);
  session_test_enable_rule_table_engine (vm);

  session_table_init (st, FIB_PROTOCOL_MAX);
  vec_add1 (st->appns_index,
	    app_namespace_index (app_namespace_get_default ()));
  session_rules_table_init (st, FIB_PROTOCOL_MAX);

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
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/16 1234 5.6.7.8/16 4321 action %d",
		action_index - 1);

  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 1),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should " "be 1: %d",
		res);

  /*
   * Add 1.2.3.4/24 1234 5.6.7.8/16 4321 and 1.2.3.4/24 1234 5.6.7.8/24 4321
   */
  args.lcl.fp_addr.ip4 = lcl_ip;
  args.lcl.fp_len = 24;
  args.action_index = action_index++;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/24 1234 5.6.7.8/16 4321 action %d",
		action_index - 1);
  args.rmt.fp_addr.ip4 = rmt_ip;
  args.rmt.fp_len = 24;
  args.action_index = action_index++;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
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
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 2.2.2.2/24 1234 6.6.6.6/16 4321 action %d",
		action_index - 1);
  args.lcl.fp_addr.ip4 = lcl_ip3;
  args.rmt.fp_addr.ip4 = rmt_ip3;
  args.action_index = action_index++;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 3.3.3.3/24 1234 7.7.7.7/16 4321 action %d",
		action_index - 1);

  /*
   * Add again 3.3.3.3/24 1234 7.7.7.7/16 4321
   */
  args.lcl.fp_addr.ip4 = lcl_ip3;
  args.rmt.fp_addr.ip4 = rmt_ip3;
  args.action_index = action_index++;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "overwrite 3.3.3.3/24 1234 7.7.7.7/16 4321 "
		"action %d", action_index - 1);

  /*
   * Lookup 1.2.3.4/32 1234 5.6.7.8/32 4321, 1.2.2.4/32 1234 5.6.7.9/32 4321
   * and  3.3.3.3 1234 7.7.7.7 4321
   */
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 3),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321 action " "should be 3: %d",
		res);

  lcl_lkup.as_u32 = clib_host_to_net_u32 (0x01020204);
  rmt_lkup.as_u32 = clib_host_to_net_u32 (0x05060709);
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_lkup, &rmt_lkup, lcl_port, rmt_port);
  SESSION_TEST ((res == 1),
		"Lookup 1.2.2.4 1234 5.6.7.9 4321, action " "should be 1: %d",
		res);

  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip3, &rmt_ip3, lcl_port, rmt_port);
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
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/24 * 5.6.7.8/24 * action %d",
		action_index - 1);
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 7),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should"
		" be 7 (lpm dst): %d", res);
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port + 1, rmt_port);
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
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/24 * 5.6.7.8/24 *");

  args.lcl.fp_addr.ip4 = lcl_ip;
  args.rmt.fp_addr.ip4 = rmt_ip;
  args.lcl.fp_len = 16;
  args.rmt.fp_len = 16;
  args.lcl_port = 0;
  args.rmt_port = 0;
  args.action_index = action_index++;
  args.is_add = 1;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
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
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add 1.2.3.4/24 1235 5.6.7.8/24 4321 action %d",
		action_index - 1);

  if (verbose)
    session_rules_table_cli_dump (vm, st->srtg_handle, TRANSPORT_PROTO_TCP,
				  FIB_PROTOCOL_IP4);

  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 3),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should " "be 3: %d",
		res);
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port + 1, rmt_port);
  SESSION_TEST ((res == 9),
		"Lookup 1.2.3.4 1235 5.6.7.8 4321, action should " "be 9: %d",
		res);
  res =
    session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP, &lcl_ip,
				 &rmt_ip, lcl_port + 1, rmt_port + 1);
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
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del 1.2.0.0/16 1234 5.6.0.0/16 4321");
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 3),
		"Lookup 1.2.3.4 1234 5.6.7.8 4321, action should " "be 3: %d",
		res);

  args.lcl_port = 0;
  args.rmt_port = 0;
  args.is_add = 0;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del 1.2.0.0/16 * 5.6.0.0/16 *");
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
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
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del 1.2.3.4/24 1234 5.6.7.5/24");
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == 2), "Action should be 2: %d", res);

  session_table_free (st, FIB_PROTOCOL_MAX);

  return 0;
}

static int
session_test_rules (vlib_main_t * vm, unformat_input_t * input)
{
  session_endpoint_t server_sep = SESSION_ENDPOINT_NULL;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u16 lcl_port = 1234, rmt_port = 4321;
  u32 server_index, server_index2;
  u32 placeholder_server_api_index = ~0;
  transport_connection_t *tc;
  u32 placeholder_port = 1111;
  u8 is_filtered = 0, *ns_id = format (0, "appns1");
  session_t *listener, *s;
  app_namespace_t *default_ns = app_namespace_get_default ();
  u32 local_ns_index = default_ns->local_table_index;
  int verbose = 0;
  app_namespace_t *app_ns;
  app_listener_t *al;
  int error = 0;
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

  session_test_disable_rt_backend_engine (vm);
  session_test_enable_rule_table_engine (vm);

  server_sep.is_ip4 = 1;
  server_sep.port = placeholder_port;
  clib_memset (options, 0, sizeof (options));

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "session_test"),
  };

  vnet_listen_args_t bind_args = {
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
  attach_args.api_client_index = placeholder_server_api_index;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attached");
  server_index = attach_args.app_index;

  bind_args.app_index = server_index;
  error = vnet_listen (&bind_args);
  SESSION_TEST ((error == 0), "server bound to %U/%d", format_ip46_address,
		&server_sep.ip, 1, server_sep.port);
  al = app_listener_get_w_handle (bind_args.handle);
  listener = app_listener_get_session (al);
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
  SESSION_TEST ((is_filtered == SESSION_LOOKUP_RESULT_FILTERED),
		"lookup should be filtered (deny)");

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
  SESSION_TEST ((error == SESSION_E_FILTERED), "connect should be filtered");

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
  SESSION_TEST ((error == 0), "app ns insertion should succeed: %d", error);
  app_ns = app_namespace_get_from_id (ns_id);

  attach_args.namespace_id = ns_id;
  attach_args.api_client_index = placeholder_server_api_index;
  vec_free (attach_args.name);
  attach_args.name = format (0, "server_test2");
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
  SESSION_TEST ((error == SESSION_E_FILTERED), "connect should be filtered");

  /*
   * Lookup test namespace
   */
  handle = session_lookup_local_endpoint (app_ns->local_table_index, &sep);
  SESSION_TEST ((handle == SESSION_DROP_HANDLE), "lookup for 1.2.3.4/32 1234 "
		"5.6.7.8/16 4321 in local table should return deny");

  connect_args.app_index = server_index;
  error = vnet_connect (&connect_args);
  SESSION_TEST ((error != 0), "connect should fail");
  SESSION_TEST ((error == SESSION_E_FILTERED), "connect should be filtered");

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

  ns_args.is_add = 0;
  error = vnet_app_namespace_add_del (&ns_args);
  SESSION_TEST ((error == 0), "app ns delete should succeed: %d", error);

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
  u32 placeholder_server_api_index = ~0, sw_if_index = 0;
  u8 is_filtered = 0;
  session_t *s;
  transport_connection_t *tc;
  u16 lcl_port = 1234, rmt_port = 4321;
  app_namespace_t *app_ns;
  int verbose = 0, error = 0;
  app_listener_t *al;

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
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "session_test"),
  };

  attach_args.api_client_index = placeholder_server_api_index;
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
  al = app_listener_get (s->al_index);
  SESSION_TEST ((al->app_index == server_index), "lookup should return"
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
  session_delete_loopback (sw_if_index);

  /* Revert default appns sw_if_index */
  app_ns = app_namespace_get_default ();
  app_ns->sw_if_index = ~0;

  return 0;
}

static inline void
wait_for_event (svm_msg_q_t * mq, int fd, int epfd, u8 use_eventfd)
{
  if (!use_eventfd)
    {
      svm_msg_q_wait (mq, SVM_MQ_WAIT_EMPTY);
    }
  else
    {
      int __clib_unused n_read, rv;
      struct epoll_event ep_evt;
      u64 buf;

      while (1)
	{
	  rv = epoll_wait (epfd, &ep_evt, 1, -1);
	  if (rv < 0)
	    {
	      ST_DBG ("epoll error");
	      exit (1);
	    }
	  else if (rv > 0 && (ep_evt.events & EPOLLIN))
	    {
	      n_read = read (fd, &buf, sizeof (buf));
	    }
	  else
	    continue;

	  if (!svm_msg_q_is_empty (mq))
	    break;
	}
    }
}

/* Used to be part of application_worker.c prior to adding support for
 * async rx
 */
static int
test_mq_try_lock_and_alloc_msg (svm_msg_q_t *mq, session_mq_rings_e ring,
				svm_msg_q_msg_t *msg)
{
  int rv, n_try = 0;

  while (n_try < 75)
    {
      rv = svm_msg_q_lock_and_alloc_msg_w_ring (mq, ring, SVM_Q_NOWAIT, msg);
      if (!rv)
	return 0;
      /*
       * Break the loop if mq is full, usually this is because the
       * app has crashed or is hanging on somewhere.
       */
      if (rv != -1)
	break;
      n_try += 1;
      usleep (1);
    }

  return -1;
}

/* Used to be part of application_worker.c prior to adding support for
 * async rx and was used for delivering io events over mq
 * NB: removed handling of mq congestion
 */
static inline int
test_app_send_io_evt_rx (app_worker_t *app_wrk, session_t *s)
{
  svm_msg_q_msg_t _mq_msg = { 0 }, *mq_msg = &_mq_msg;
  session_event_t *evt;
  svm_msg_q_t *mq;
  u32 app_session;
  int rv;

  if (app_worker_application_is_builtin (app_wrk))
    return app_worker_rx_notify (app_wrk, s);

  if (svm_fifo_has_event (s->rx_fifo))
    return 0;

  app_session = s->rx_fifo->app_session_index;
  mq = app_wrk->event_queue;

  rv = test_mq_try_lock_and_alloc_msg (mq, SESSION_MQ_IO_EVT_RING, mq_msg);

  if (PREDICT_FALSE (rv))
    {
      clib_warning ("failed to alloc mq message");
      return -1;
    }

  evt = svm_msg_q_msg_data (mq, mq_msg);
  evt->event_type = SESSION_IO_EVT_RX;
  evt->session_index = app_session;

  (void) svm_fifo_set_event (s->rx_fifo);

  svm_msg_q_add_and_unlock (mq, mq_msg);

  return 0;
}

static int
session_test_mq_speed (vlib_main_t * vm, unformat_input_t * input)
{
  int error, __clib_unused verbose, use_eventfd = 0;
  u64 i, n_test_msgs = 1 << 10, *counter;
  u64 options[APP_OPTIONS_N_OPTIONS];
  int epfd = -1, rv, prod_fd = -1;
  svm_fifo_t *rx_fifo, *tx_fifo;
  vl_api_registration_t *reg;
  struct epoll_event ep_evt;
  u32 app_index, api_index;
  app_worker_t *app_wrk;
  segment_manager_t *sm;
  svm_msg_q_msg_t msg;
  application_t *app;
  svm_msg_q_t *mq;
  f64 start, diff;
  svm_queue_t *q;
  session_t s;
  pid_t pid;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "%d", &n_test_msgs))
	;
      else if (unformat (input, "use-eventfd"))
	use_eventfd = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  q = clib_mem_alloc (sizeof (*q));
  api_index = vl_api_memclnt_create_internal ("session_mq_test_api", q);

  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_EVT_QUEUE_SIZE] = 2048;

  reg = vl_api_client_index_to_registration (api_index);
  /* Shut up coverity */
  if (reg == 0)
    abort ();

  vnet_app_attach_args_t attach_args = {
    .api_client_index = api_index,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "session_mq_test"),
  };
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "server attachment should work");

  app_index = attach_args.app_index;

  app = application_get (app_index);
  app_wrk = application_get_worker (app, 0);
  mq = app_wrk->event_queue;
  if (use_eventfd)
    {
      svm_msg_q_alloc_eventfd (mq);
      prod_fd = svm_msg_q_get_eventfd (mq);
      SESSION_TEST (prod_fd != -1, "mq producer eventd valid %u", prod_fd);
    }

  sm = app_worker_get_connect_segment_manager (app_wrk);
  segment_manager_alloc_session_fifos (sm, 0, &rx_fifo, &tx_fifo);
  s.rx_fifo = rx_fifo;
  s.tx_fifo = tx_fifo;
  s.session_state = SESSION_STATE_READY;
  counter = (u64 *) f_head_cptr (rx_fifo)->data;
  start = vlib_time_now (vm);

  pid = fork ();
  if (pid < 0)
    SESSION_TEST (0, "fork failed");

  if (pid == 0)
    {
      if (use_eventfd)
	{
	  epfd = epoll_create1 (0);
	  SESSION_TEST (epfd != -1, "epfd created");
	  ep_evt.events = EPOLLIN;
	  ep_evt.data.u64 = prod_fd;
	  rv = epoll_ctl (epfd, EPOLL_CTL_ADD, prod_fd, &ep_evt);
	  SESSION_TEST (rv == 0, "epoll returned %d", rv);
	}

      for (i = 0; i < n_test_msgs; i++)
	{
	  wait_for_event (mq, prod_fd, epfd, use_eventfd);
	  svm_msg_q_sub_raw (mq, &msg);
	  svm_msg_q_free_msg (mq, &msg);
	  svm_msg_q_unlock (mq);
	  *counter = *counter + 1;
	  svm_fifo_unset_event (rx_fifo);
	}
      exit (0);
    }
  else
    {
      ST_DBG ("client pid %u", pid);
      for (i = 0; i < n_test_msgs; i++)
	{
	  while (svm_fifo_has_event (rx_fifo))
	    ;
	  test_app_send_io_evt_rx (app_wrk, &s);
	}
    }

  diff = vlib_time_now (vm) - start;
  ST_DBG ("done %u events in %.2f sec: %f evts/s", *counter,
	  diff, *counter / diff);

  vnet_app_detach_args_t detach_args = {
    .app_index = app_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);
  return 0;
}

static int
session_test_mq_basic (vlib_main_t * vm, unformat_input_t * input)
{
  svm_msg_q_cfg_t _cfg, *cfg = &_cfg;
  svm_msg_q_msg_t msg1, msg2, msg[12];
  int __clib_unused verbose, i, rv;
  svm_msg_q_shared_t *smq;
  svm_msg_q_ring_t *ring;
  svm_msg_q_t _mq = { 0 }, *mq = &_mq;
  u8 *rings_ptr;

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

  svm_msg_q_ring_cfg_t rc[2] = { {8, 8, 0}
  , {8, 16, 0}
  };
  cfg->consumer_pid = ~0;
  cfg->n_rings = 2;
  cfg->q_nitems = 16;
  cfg->ring_cfgs = rc;

  smq = svm_msg_q_alloc (cfg);
  svm_msg_q_attach (mq, smq);
  SESSION_TEST (smq != 0, "svm_msg_q_alloc");
  SESSION_TEST (vec_len (mq->rings) == 2, "ring allocation");
  rings_ptr = (u8 *) mq->rings[0].shr->data;
  vec_foreach (ring, mq->rings)
  {
    SESSION_TEST (ring->shr->data == rings_ptr, "ring data");
    rings_ptr += (uword) ring->nitems * ring->elsize;
    rings_ptr += sizeof (svm_msg_q_ring_shared_t);
  }

  msg1 = svm_msg_q_alloc_msg (mq, 8);
  rv = (mq->rings[0].shr->cursize != 1 || msg1.ring_index != 0 ||
	msg1.elt_index != 0);
  SESSION_TEST (rv == 0, "msg alloc1");

  msg2 = svm_msg_q_alloc_msg (mq, 15);
  rv = (mq->rings[1].shr->cursize != 1 || msg2.ring_index != 1 ||
	msg2.elt_index != 0);
  SESSION_TEST (rv == 0, "msg alloc2");

  svm_msg_q_free_msg (mq, &msg1);
  SESSION_TEST (mq->rings[0].shr->cursize == 0, "free msg");

  for (i = 0; i < 12; i++)
    {
      msg[i] = svm_msg_q_alloc_msg (mq, 7);
      *(u32 *) svm_msg_q_msg_data (mq, &msg[i]) = i;
    }

  rv = (mq->rings[0].shr->cursize != 8 || mq->rings[1].shr->cursize != 5);
  SESSION_TEST (rv == 0, "msg alloc3");

  *(u32 *) svm_msg_q_msg_data (mq, &msg2) = 123;
  svm_msg_q_add (mq, &msg2, SVM_Q_NOWAIT);
  for (i = 0; i < 12; i++)
    svm_msg_q_add (mq, &msg[i], SVM_Q_NOWAIT);

  rv = svm_msg_q_sub (mq, &msg2, SVM_Q_NOWAIT, 0);
  SESSION_TEST (rv == 0, "dequeue1");

  SESSION_TEST (msg2.ring_index == 1 && msg2.elt_index == 0,
		"dequeue1 result");
  rv = (*(u32 *) svm_msg_q_msg_data (mq, &msg2) == 123);
  SESSION_TEST (rv, "dequeue 1 data");

  svm_msg_q_free_msg (mq, &msg2);

  for (i = 0; i < 12; i++)
    {
      if (svm_msg_q_sub (mq, &msg[i], SVM_Q_NOWAIT, 0))
	SESSION_TEST (0, "dequeue2");
      if (i < 8)
	{
	  if (msg[i].ring_index != 0 || msg[i].elt_index != (i + 1) % 8)
	    SESSION_TEST (0, "dequeue2 result2");
	}
      else
	{
	  if (msg[i].ring_index != 1 || msg[i].elt_index != (i - 8) + 1)
	    SESSION_TEST (0, "dequeue2 result3");
	}
      if (*(u32 *) svm_msg_q_msg_data (mq, &msg[i]) != i)
	SESSION_TEST (0, "dequeue2 wrong data");
      svm_msg_q_free_msg (mq, &msg[i]);
    }
  rv = (mq->rings[0].shr->cursize == 0 && mq->rings[1].shr->cursize == 0);
  SESSION_TEST (rv, "post dequeue");

  return 0;
}

static f32
session_get_memory_usage (void)
{
  clib_mem_heap_t *heap = clib_mem_get_per_cpu_heap ();
  u8 *s = 0;
  char *ss;
  f32 used = 0.0;

  s = format (s, "%U\n", format_clib_mem_heap, heap, 0);
  ss = strstr ((char *) s, "used:");
  if (ss)
    {
      if (sscanf (ss, "used: %f", &used) != 1)
	clib_warning ("invalid 'used' value");
    }
  else
    clib_warning ("substring 'used:' not found from show memory");
  vec_free (s);
  return (used);
}

static int
session_test_enable_disable (vlib_main_t *vm, unformat_input_t *input)
{
  u32 iteration = 100, i, n_sessions = 0;
  uword was_enabled;
  f32 was_using, now_using;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "repeat %d", &iteration))
	;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  for (int thread_index = 0; thread_index <= vlib_num_workers ();
       thread_index++)
    n_sessions += pool_elts (session_main.wrk[thread_index].sessions);

  was_enabled = clib_mem_trace_enable_disable (0);
  /* warm up */
  for (i = 0; i < 10; i++)
    {
      session_test_disable_rt_backend_engine (vm);
      session_test_enable_sdl_engine (vm);
      session_test_disable_rt_backend_engine (vm);
      session_test_enable_rule_table_engine (vm);
    }
  was_using = session_get_memory_usage ();

  for (i = 0; i < iteration; i++)
    {
      session_test_disable_rt_backend_engine (vm);
      session_test_enable_sdl_engine (vm);
      session_test_disable_rt_backend_engine (vm);
      session_test_enable_rule_table_engine (vm);
    }
  now_using = session_get_memory_usage ();

  clib_mem_trace_enable_disable (was_enabled);
  if (n_sessions)
    SESSION_TEST ((now_using < was_using + (1 << 15)),
		  "was using %.2fM, now using %.2fM", was_using, now_using);
  else
    SESSION_TEST ((was_using == now_using), "was using %.2fM, now using %.2fM",
		  was_using, now_using);

  return 0;
}

static int
session_test_sdl (vlib_main_t *vm, unformat_input_t *input)
{
  session_table_t *st = session_table_alloc ();
  u16 lcl_port = 0, rmt_port = 0;
  u32 action_index = 1, res;
  int verbose = 0, error;
  ip4_address_t rmt_ip;
  const char ip_str_1234[] = "1.2.3.4";
  inet_pton (AF_INET, ip_str_1234, &rmt_ip);
  ip4_address_t lcl_ip = {
    .as_u32 = clib_host_to_net_u32 (0x0),
  };
  ip6_address_t lcl_ip6 = {
    .as_u64 = { 0, 0 },
  };
  fib_prefix_t rmt_pref = {
    .fp_addr.ip4.as_u32 = rmt_ip.as_u32,
    .fp_len = 16,
    .fp_proto = FIB_PROTOCOL_IP4,
  };
  fib_prefix_t lcl_pref = {
    .fp_addr.ip4.as_u32 = lcl_ip.as_u32,
    .fp_len = 0,
    .fp_proto = 0,
  };
  session_rule_table_add_del_args_t args = {
    .lcl = lcl_pref,
    .rmt = rmt_pref,
    .lcl_port = lcl_port,
    .rmt_port = rmt_port,
    .action_index = action_index++,
    .is_add = 1,
  };
  const char ip_str_1200[] = "1.2.0.0";
  const char ip_str_1230[] = "1.2.3.0";
  const char ip_str_1111[] = "1.1.1.1";
  const char ip6_str[] = "2501:0db8:85a3:0000:0000:8a2e:0371:1";
  const char ip6_str2[] = "2501:0db8:85a3:0000:0000:8a2e:0372:1";

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

  session_test_disable_rt_backend_engine (vm);
  session_test_enable_sdl_engine (vm);

  session_table_init (st, FIB_PROTOCOL_MAX);
  vec_add1 (st->appns_index,
	    app_namespace_index (app_namespace_get_default ()));
  session_rules_table_init (st, FIB_PROTOCOL_MAX);

  /* Add 1.2.0.0/16 */
  args.rmt.fp_len = 16;
  inet_pton (AF_INET, ip_str_1200, &args.rmt.fp_addr.ip4.as_u32);
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add %s/%d action %d", ip_str_1200,
		args.rmt.fp_len, action_index - 1);

  /* Lookup 1.2.3.4 */
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == action_index - 1),
		"Lookup %s, action should "
		"be 1: %d",
		ip_str_1234, action_index - 1);

  /*
   * Add 1.2.3.0/24
   */
  args.rmt.fp_len = 24;
  inet_pton (AF_INET, ip_str_1230, &args.rmt.fp_addr.ip4.as_u32);
  args.action_index = action_index++;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add %s/%d action %d", ip_str_1230,
		args.rmt.fp_len, action_index - 1);

  /* Lookup 1.2.3.4 */
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == action_index - 1),
		"Lookup %s, action should "
		"be 2: %d",
		ip_str_1234, action_index - 1);

  /* look up 1.1.1.1, should be -1 (invalid index) */
  inet_pton (AF_INET, ip_str_1111, &rmt_ip);
  res = session_rules_table_lookup4 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip, &rmt_ip, lcl_port, rmt_port);
  SESSION_TEST ((res == SESSION_TABLE_INVALID_INDEX),
		"Lookup %s, action should "
		"be -1: %d",
		ip_str_1111, res);

  /* Add again 1.2.0.0/16, should be rejected */
  args.rmt.fp_len = 16;
  inet_pton (AF_INET, ip_str_1200, &args.rmt.fp_addr.ip4.as_u32);
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == SESSION_E_IPINUSE), "Add %s/%d action %d",
		ip_str_1200, args.rmt.fp_len, error);
  /*
   * Add 0.0.0.0/0, should get an error
   */
  args.rmt.fp_len = 0;
  args.rmt.fp_addr.ip4.as_u32 = 0;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == SESSION_E_IPINUSE), "Add 0.0.0.0/%d action %d",
		args.rmt.fp_len, error);

  /* delete 0.0.0.0 should be rejected */
  args.is_add = 0;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == SESSION_E_NOROUTE), "Del 0.0.0.0/%d action %d",
		args.rmt.fp_len, error);
  if (verbose)
    session_rules_table_cli_dump (vm, st->srtg_handle, TRANSPORT_PROTO_TCP,
				  FIB_PROTOCOL_IP4);

  /*
   * Clean up
   * Delete 1.2.0.0/16
   * Delete 1.2.3.0/24
   */
  inet_pton (AF_INET, ip_str_1200, &args.rmt.fp_addr.ip4.as_u32);
  args.rmt.fp_len = 16;
  args.is_add = 0;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del %s/%d should 0: %d", ip_str_1200,
		args.rmt.fp_len, error);

  inet_pton (AF_INET, ip_str_1230, &args.rmt.fp_addr.ip4.as_u32);
  args.rmt.fp_len = 24;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Del %s/%d, should be 0: %d", ip_str_1230,
		args.rmt.fp_len, error);
  if (verbose)
    session_rules_table_cli_dump (vm, st->srtg_handle, TRANSPORT_PROTO_TCP,
				  FIB_PROTOCOL_IP4);

  /* ip6 tests */

  /*
   * Add ip6 2001:0db8:85a3:0000:0000:8a2e:0371:1/124
   */
  ip6_address_t lcl_lkup;
  inet_pton (AF_INET6, ip6_str, &args.rmt.fp_addr.ip6);
  args.rmt.fp_len = 124;
  args.rmt.fp_proto = FIB_PROTOCOL_IP6;
  args.action_index = action_index++;
  args.is_add = 1;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "Add %s/%d action %d", ip6_str, args.rmt.fp_len,
		action_index - 1);
  if (verbose)
    session_rules_table_cli_dump (vm, st->srtg_handle, TRANSPORT_PROTO_TCP,
				  FIB_PROTOCOL_IP6);

  /* Lookup 2001:0db8:85a3:0000:0000:8a2e:0371:1 */
  res = session_rules_table_lookup6 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip6, &args.rmt.fp_addr.ip6, lcl_port,
				     rmt_port);
  SESSION_TEST ((res == action_index - 1),
		"Lookup %s action should "
		"be 3: %d",
		ip6_str, action_index - 1);

  /* Lookup 2001:0db8:85a3:0000:0000:8a2e:0372:1 */
  inet_pton (AF_INET6, ip6_str2, &lcl_lkup);
  res = session_rules_table_lookup6 (st->srtg_handle, TRANSPORT_PROTO_TCP,
				     &lcl_ip6, &lcl_lkup, lcl_port, rmt_port);
  SESSION_TEST ((res == SESSION_TABLE_INVALID_INDEX),
		"Lookup %s action should "
		"be -1: %d",
		ip6_str2, res);

  /*
   * del ip6 2001:0db8:85a3:0000:0000:8a2e:0371:1/124
   */
  args.is_add = 0;
  args.rmt.fp_len = 124;
  error =
    session_rules_table_add_del (st->srtg_handle, TRANSPORT_PROTO_TCP, &args);
  SESSION_TEST ((error == 0), "del %s/%d, should be 0: %d", ip6_str,
		args.rmt.fp_len, error);
  if (verbose)
    session_rules_table_cli_dump (vm, st->srtg_handle, TRANSPORT_PROTO_TCP,
				  FIB_PROTOCOL_IP6);

  session_table_free (st, FIB_PROTOCOL_MAX);

  return 0;
}

static int
session_test_ext_cfg (vlib_main_t *vm, unformat_input_t *input)
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  transport_endpt_ext_cfg_t *ext_cfg;

  ext_cfg = session_endpoint_add_ext_cfg (&sep, TRANSPORT_ENDPT_EXT_CFG_HTTP,
					  sizeof (ext_cfg->opaque));
  ext_cfg->opaque = 60;

  ext_cfg =
    session_endpoint_add_ext_cfg (&sep, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
				  sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.ckpair_index = 1;

  ext_cfg = session_endpoint_add_ext_cfg (&sep, TRANSPORT_ENDPT_EXT_CFG_NONE,
					  sizeof (ext_cfg->opaque));
  ext_cfg->opaque = 345;

  ext_cfg = session_endpoint_get_ext_cfg (&sep, TRANSPORT_ENDPT_EXT_CFG_HTTP);
  SESSION_TEST ((ext_cfg != 0),
		"TRANSPORT_ENDPT_EXT_CFG_HTTP should be present");
  SESSION_TEST ((ext_cfg->opaque == 60),
		"TRANSPORT_ENDPT_EXT_CFG_HTTP opaque value should be 60: %u",
		ext_cfg->opaque);
  ext_cfg =
    session_endpoint_get_ext_cfg (&sep, TRANSPORT_ENDPT_EXT_CFG_CRYPTO);
  SESSION_TEST ((ext_cfg != 0),
		"TRANSPORT_ENDPT_EXT_CFG_CRYPTO should be present");
  SESSION_TEST (
    (ext_cfg->crypto.ckpair_index == 1),
    "TRANSPORT_ENDPT_EXT_CFG_HTTP ckpair_index value should be 1: %u",
    ext_cfg->crypto.ckpair_index);
  ext_cfg = session_endpoint_get_ext_cfg (&sep, TRANSPORT_ENDPT_EXT_CFG_NONE);
  SESSION_TEST ((ext_cfg != 0),
		"TRANSPORT_ENDPT_EXT_CFG_NONE should be present");
  SESSION_TEST ((ext_cfg->opaque == 345),
		"TRANSPORT_ENDPT_EXT_CFG_HTTP opaque value should be 345: %u",
		ext_cfg->opaque);
  session_endpoint_free_ext_cfgs (&sep);

  return 0;
}

static clib_error_t *
session_test (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  int res = 0;

  session_test_enable_rule_table_engine (vm);

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
      else if (unformat (input, "mq-speed"))
	res = session_test_mq_speed (vm, input);
      else if (unformat (input, "mq-basic"))
	res = session_test_mq_basic (vm, input);
      else if (unformat (input, "enable-disable"))
	res = session_test_enable_disable (vm, input);
      else if (unformat (input, "sdl"))
	res = session_test_sdl (vm, input);
      else if (unformat (input, "ext-cfg"))
	res = session_test_ext_cfg (vm, input);
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
	  if ((res = session_test_mq_speed (vm, input)))
	    goto done;
	  if ((res = session_test_mq_basic (vm, input)))
	    goto done;
	  if ((res = session_test_sdl (vm, input)))
	    goto done;
	  if ((res = session_test_ext_cfg (vm, input)))
	    goto done;
	  if ((res = session_test_enable_disable (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "Session unit test failed");

  vlib_cli_output (vm, "SUCCESS");
  return 0;
}

VLIB_CLI_COMMAND (session_test_command, static) = {
  .path = "test session",
  .short_help = "internal session unit tests",
  .function = session_test,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
