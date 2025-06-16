/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/udp/udp.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>

#define UDP_TEST_I(_cond, _comment, _args...)                                 \
  ({                                                                          \
    int _evald = (_cond);                                                     \
    if (!(_evald))                                                            \
      {                                                                       \
	fformat (stderr, "FAIL:%d: " _comment "\n", __LINE__, ##_args);       \
      }                                                                       \
    else                                                                      \
      {                                                                       \
	fformat (stderr, "PASS:%d: " _comment "\n", __LINE__, ##_args);       \
      }                                                                       \
    _evald;                                                                   \
  })

#define UDP_TEST(_cond, _comment, _args...)                                   \
  {                                                                           \
    if (!UDP_TEST_I (_cond, _comment, ##_args))                               \
      {                                                                       \
	return 1;                                                             \
      }                                                                       \
  }

int
udp_test_connected_callback (u32 app_index, u32 api_context, session_t *s,
			     session_error_t err)
{
  return 0;
}

int
udp_test_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

int
udp_test_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

int
udp_test_accept_callback (session_t *s)
{
  clib_warning ("called...");
  return 0;
}

int
udp_test_server_rx_callback (session_t *s)
{
  clib_warning ("called...");
  return -1;
}

void
udp_test_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  clib_warning ("called...");
}

void
udp_test_disconnect_callback (session_t *s)
{
  vnet_disconnect_args_t da = {
    .handle = session_handle (s),
    .app_index = app_worker_get (s->app_wrk_index)->app_index
  };
  vnet_disconnect_session (&da);
}

void
udp_test_reset_callback (session_t *s)
{
  clib_warning ("called...");
}

static session_cb_vft_t udp_test_session_cbs = {
  .session_connected_callback = udp_test_connected_callback,
  .session_accept_callback = udp_test_accept_callback,
  .session_disconnect_callback = udp_test_disconnect_callback,
  .session_reset_callback = udp_test_reset_callback,
  .session_cleanup_callback = udp_test_cleanup_callback,
  .builtin_app_rx_callback = udp_test_server_rx_callback,
  .add_segment_callback = udp_test_add_segment_callback,
  .del_segment_callback = udp_test_del_segment_callback,
};

static int
udp_create_lookpback (u32 table_id, u32 *sw_if_index, ip4_address_t *intf_addr)
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

  if (ip4_add_del_interface_address (vlib_get_main (), *sw_if_index, intf_addr,
				     24, 0))
    {
      clib_warning ("couldn't assign loopback ip %U", format_ip4_address,
		    intf_addr);
      return -1;
    }

  return 0;
}

static void
udp_delete_loopback (u32 sw_if_index)
{
  /* loopback interface deletion fails */
  /* vnet_delete_loopback_interface (sw_if_index); */

  vnet_sw_interface_set_flags (vnet_get_main (), sw_if_index, 0);
}

#define UDP_TEST_NO_RESULT 1e6
static volatile int udp_test_connect_rpc_result = UDP_TEST_NO_RESULT;

static void
udp_test_connect_rpc (void *args)
{
  vnet_connect_args_t *a = (vnet_connect_args_t *) args;
  udp_test_connect_rpc_result = vnet_connect (a);
  clib_mem_free (a);
}

static session_error_t
udp_test_do_connect (vlib_main_t *vm, vnet_connect_args_t *args)
{
  if (vlib_num_workers ())
    {
      vnet_connect_args_t *rpc_args = clib_mem_alloc (sizeof (*args));
      clib_memcpy_fast (rpc_args, args, sizeof (*args));
      session_send_rpc_evt_to_thread (transport_cl_thread (),
				      udp_test_connect_rpc, rpc_args);

      while (udp_test_connect_rpc_result == UDP_TEST_NO_RESULT)
	{
	  vlib_worker_thread_barrier_release (vm);
	  vlib_process_suspend (vm, 100e-3);
	  vlib_worker_thread_barrier_sync (vm);
	}
      return udp_test_connect_rpc_result;
    }
  else
    {
      return vnet_connect (args);
    }
}

static int
udp_test_binds (vlib_main_t *vm, unformat_input_t *input)
{
  session_endpoint_cfg_t server_sep1 = SESSION_ENDPOINT_CFG_NULL;
  session_endpoint_cfg_t server_sep2 = SESSION_ENDPOINT_CFG_NULL;
  u64 options[APP_OPTIONS_N_OPTIONS];
  session_error_t error;
  u32 server_index;
  u16 port = 1234;
  int rv = 0;

  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 16 << 20;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &udp_test_session_cbs,
    .name = format (0, "udp_test"),
  };

  error = vnet_application_attach (&attach_args);
  UDP_TEST ((error == 0), "app attached");
  server_index = attach_args.app_index;
  vec_free (attach_args.name);

  /* Set up first IP address (20.1.1.1) */
  server_sep1.is_ip4 = 1;
  server_sep1.ip.ip4.as_u32 = clib_host_to_net_u32 (0x14010101);
  udp_create_lookpback (0, &server_sep1.sw_if_index,
			(ip4_address_t *) &server_sep1.ip.ip4);
  server_sep1.port = clib_host_to_net_u16 (port);
  server_sep1.is_ip4 = 1;
  server_sep1.transport_proto = TRANSPORT_PROTO_UDP;

  vnet_listen_args_t bind_args1 = {
    .sep_ext = server_sep1,
    .app_index = server_index,
    .wrk_map_index = 0,
  };

  /* Set up second IP address (21.1.1.1) */
  server_sep2.ip.ip4.as_u32 = clib_host_to_net_u32 (0x15020202);
  udp_create_lookpback (0, &server_sep2.sw_if_index,
			(ip4_address_t *) &server_sep2.ip.ip4);
  server_sep2.port = clib_host_to_net_u16 (port);
  server_sep2.is_ip4 = 1;
  server_sep2.transport_proto = TRANSPORT_PROTO_UDP;

  vnet_listen_args_t bind_args2 = {
    .sep_ext = server_sep2,
    .app_index = server_index,
    .wrk_map_index = 0,
  };

  /* Test server1 ip:port bind */
  error = vnet_listen (&bind_args1);
  UDP_TEST ((error == 0), "server1 bind should work: %U", format_session_error,
	    error);

  /* Subsequent bind to same ip1:port pair should fail */
  error = vnet_listen (&bind_args1);
  UDP_TEST ((error == SESSION_E_ALREADY_LISTENING),
	    "second server1 bind should fail: %U", format_session_error,
	    error);

  /* Try connecting using server1 as lcl ip1:port */
  vnet_connect_args_t connect_args = {
    .sep_ext = server_sep2,
    .app_index = server_index,
  };
  connect_args.sep_ext.peer.ip = server_sep1.ip;
  connect_args.sep_ext.peer.port = server_sep1.port;
  connect_args.sep_ext.peer.is_ip4 = 1;
  error = udp_test_do_connect (vm, &connect_args);
  UDP_TEST ((error == 0), "connect using lcl ip1:port should work: %U",
	    format_session_error, error);

  /* Test server2 bind ip2:port */
  error = vnet_listen (&bind_args2);
  UDP_TEST ((error == 0), "server2 bind should work: %U", format_session_error,
	    error);

  /* Start cleanup by detaching */
  vnet_app_detach_args_t detach_args = {
    .app_index = server_index,
    .api_client_index = ~0,
  };
  vnet_application_detach (&detach_args);

  /* Cleanup loopbacks */
  udp_delete_loopback (server_sep1.sw_if_index);
  udp_delete_loopback (server_sep2.sw_if_index);

  return rv;
}

static clib_error_t *
udp_test (vlib_main_t *vm, unformat_input_t *input,
	  vlib_cli_command_t *cmd_arg)
{
  int res = 0;
  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };

  vnet_session_enable_disable (vm, &args);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "binds"))
	{
	  res = udp_test_binds (vm, input);
	}
      else if (unformat (input, "all"))
	{
	  if ((res = udp_test_binds (vm, input)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "UDP unit test failed");

  vlib_cli_output (vm, "SUCCESS");
  return 0;
}

VLIB_CLI_COMMAND (udp_test_command, static) = {
  .path = "test udp",
  .short_help = "internal udp unit tests",
  .function = udp_test,
};