/*
* Copyright (c) 2015-2017 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>

int
builtin_session_accept_callback (stream_session_t * s)
{
  clib_warning ("called...");
  s->session_state = SESSION_STATE_READY;
  return 0;
}

void
builtin_session_disconnect_callback (stream_session_t * s)
{
  clib_warning ("called...");
}

int
builtin_session_connected_callback (u32 client_index,
				    stream_session_t * s, u8 is_fail)
{
  clib_warning ("called...");
  return -1;
}

int
builtin_add_segment_callback (u32 client_index,
			      const u8 * seg_name, u32 seg_size)
{
  clib_warning ("called...");
  return -1;
}

int
builtin_redirect_connect_callback (u32 client_index, void *mp)
{
  clib_warning ("called...");
  return -1;
}

int
builtin_server_rx_callback (stream_session_t * s)
{
  clib_warning ("called...");
  return 0;
}

static session_cb_vft_t builtin_session_cb_vft = {
  .session_accept_callback = builtin_session_accept_callback,
  .session_disconnect_callback = builtin_session_disconnect_callback,
  .session_connected_callback = builtin_session_connected_callback,
  .add_segment_callback = builtin_add_segment_callback,
  .redirect_connect_callback = builtin_redirect_connect_callback,
  .builtin_server_rx_callback = builtin_server_rx_callback
};

static int
server_create (vlib_main_t * vm)
{
  vnet_bind_args_t _a, *a = &_a;
  u64 options[SESSION_OPTIONS_N_OPTIONS];
  char segment_name[128];

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  a->uri = "tcp://0.0.0.0/80";
  a->api_client_index = ~0;
  a->session_cb_vft = &builtin_session_cb_vft;
  a->options = options;
  a->options[SESSION_OPTIONS_SEGMENT_SIZE] = 256 << 10;
  a->options[SESSION_OPTIONS_RX_FIFO_SIZE] = 64 << 10;
  a->options[SESSION_OPTIONS_TX_FIFO_SIZE] = 64 << 10;
  a->segment_name = segment_name;
  a->segment_name_length = ARRAY_LEN (segment_name);

  return vnet_bind_uri (a);
}

static clib_error_t *
server_create_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int rv;
#if 0
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "whatever %d", &whatever))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
#endif

  rv = server_create (vm);
  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "server_create returned %d", rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (server_create_command, static) =
{
.path = "test server",.short_help = "test server",.function =
    server_create_command_fn,};

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
