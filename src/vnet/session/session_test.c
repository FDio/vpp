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
  clib_warning ("called...");
  return -1;
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
  .builtin_server_rx_callback = dummy_server_rx_callback
};
/* *INDENT-ON* */

static int
session_test_namespace (vlib_main_t * vm, unformat_input_t * input)
{
  clib_error_t *error = 0;
  u8 *ns_id = format (0, "appns1");
  app_namespace_t *app_ns;
  u8 segment_name[128];
  u64 options[SESSION_OPTIONS_N_OPTIONS], dummy_secret = 1234;
  u32 app_index;
  int code;

  /*
   * Test insertion and lookup
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
  memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_BUILTIN_APP;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_NAMESPACE_SECRET] = dummy_secret - 1;

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = ns_id,
    .session_cb_vft = &dummy_session_cbs,
    .segment_name = segment_name,
  };
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error != 0), "app attachment should fail");
  code = clib_error_get_code (error);
  SESSION_TEST ((code == VNET_API_ERROR_APP_WRONG_NS_SECRET),
		"code should be wrong ns secret: %d", code);

  /*
   * Proper attach + bind
   */
  options[APP_OPTIONS_NAMESPACE_SECRET] = dummy_secret;
  error = vnet_application_attach (&attach_args);
  SESSION_TEST ((error == 0), "app attachment should work");

  app_index = attach_args.app_index;
  vnet_bind_args_t bind_args = {
    .sep = SESSION_ENDPOINT_NULL,
    .app_index = app_index,
  };

  error = vnet_bind (&bind_args);
  SESSION_TEST ((error == 0), "bind should work");

  vec_free (ns_id);
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
      if (unformat (input, "namespace"))
	{
	  res = session_test_namespace (vm, input);
	}
      else
	break;
    }

  if (res)
    return clib_error_return (0, "TCP unit test failed");
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
