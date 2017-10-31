/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/** @file
    udp builtin server
*/

#include <vnet/udp/udp.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

/** per-worker built-in server copy buffers */
u8 **copy_buffers;

static int
builtin_session_create_callback (stream_session_t * s)
{
  /* Simple version: declare session ready-to-go... */
  s->session_state = SESSION_STATE_READY;
  return 0;
}

static void
builtin_session_disconnect_callback (stream_session_t * s)
{
  stream_session_disconnect (s);
}

static int
builtin_server_rx_callback (stream_session_t * s)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  u32 this_transfer, max_deq, max_enq;
  int actual_transfer;
  u8 *my_copy_buffer;
  session_fifo_event_t evt;
  unix_shared_memory_queue_t *q;

  my_copy_buffer = copy_buffers[s->thread_index];
  rx_fifo = s->server_rx_fifo;
  tx_fifo = s->server_tx_fifo;

  max_deq = svm_fifo_max_dequeue (rx_fifo);
  max_enq = svm_fifo_max_enqueue (tx_fifo);
  this_transfer = max_enq < max_deq ? max_enq : max_deq;

  vec_validate (my_copy_buffer, this_transfer - 1);
  _vec_len (my_copy_buffer) = this_transfer;

  actual_transfer = svm_fifo_dequeue_nowait (rx_fifo, this_transfer,
					     my_copy_buffer);
  ASSERT (actual_transfer == this_transfer);
  actual_transfer = svm_fifo_enqueue_nowait (tx_fifo, this_transfer,
					     my_copy_buffer);
  ASSERT (actual_transfer == this_transfer);

  copy_buffers[s->thread_index] = my_copy_buffer;

  if (svm_fifo_set_event (tx_fifo))
    {
      /* Fabricate TX event, send to ourselves */
      evt.fifo = tx_fifo;
      evt.event_type = FIFO_EVENT_APP_TX;
      q = session_manager_get_vpp_event_queue (s->thread_index);
      unix_shared_memory_queue_add (q, (u8 *) & evt,
				    0 /* do wait for mutex */ );
    }

  return 0;
}

/* *INDENT-OFF* */
static session_cb_vft_t builtin_server = {
    .session_accept_callback = builtin_session_create_callback,
    .session_disconnect_callback = builtin_session_disconnect_callback,
    .builtin_server_rx_callback = builtin_server_rx_callback
};
/* *INDENT-ON* */

static int
attach_builtin_uri_server ()
{
  vnet_app_attach_args_t _a, *a = &_a;
  u8 segment_name[128];
  u32 segment_name_length;
  u64 options[16];

  segment_name_length = ARRAY_LEN (segment_name);

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  a->api_client_index = ~0;
  a->segment_name = segment_name;
  a->segment_name_length = segment_name_length;
  a->session_cb_vft = &builtin_server;

  options[SESSION_OPTIONS_ACCEPT_COOKIE] = 0x12345678;
  options[SESSION_OPTIONS_SEGMENT_SIZE] = (2 << 30);	/*$$$$ config / arg */
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 1024;

  a->options = options;

  if (vnet_application_attach (a))
    return -1;
  return 0;
}

static int
bind_builtin_uri_server (u8 * uri)
{
  vnet_bind_args_t _a, *a = &_a;
  int rv;

  rv = attach_builtin_uri_server ();
  if (rv)
    return rv;

  memset (a, 0, sizeof (*a));
  a->uri = (char *) uri;
  a->app_index = ~0;		/* built-in server */

  rv = vnet_bind_uri (a);

  return rv;
}

static int
unbind_builtin_uri_server (u8 * uri)
{
  vnet_unbind_args_t _a, *a = &_a;

  a->app_index = ~0;
  a->uri = (char *) uri;

  return vnet_unbind_uri (a);
}

static clib_error_t *
builtin_server_init (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  vec_validate (copy_buffers, num_threads - 1);
  return 0;
}

VLIB_INIT_FUNCTION (builtin_server_init);

static clib_error_t *
builtin_uri_bind_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  u8 *uri = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "uri %s", &uri))
	;
      else
	break;
    }

  if (uri == 0)
    return clib_error_return (0, "uri to bind not specified...");

  rv = bind_builtin_uri_server (uri);

  vec_free (uri);

  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "bind_uri_server returned %d", rv);
      break;
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (builtin_uri_bind_command, static) =
{
  .path = "builtin uri bind",
  .short_help = "builtin uri bind",
  .function = builtin_uri_bind_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
builtin_uri_unbind_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  u8 *uri = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "uri %s", &uri))
	;
      else
	break;
    }

  if (uri == 0)
    return clib_error_return (0, "uri to unbind not specified...");

  rv = unbind_builtin_uri_server (uri);

  vec_free (uri);

  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "unbind_uri_server returned %d", rv);
      break;
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (builtin_uri_unbind_command, static) =
{
  .path = "builtin uri unbind",
  .short_help = "builtin uri unbind",
  .function = builtin_uri_unbind_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
