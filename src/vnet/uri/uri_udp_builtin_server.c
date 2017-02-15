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

#include "uri.h"
#include <vnet/ip/udp.h>

static int builtin_session_create_callback 
(application_t * ss, stream_session_t * s,
 unix_shared_memory_queue_t * vpp_event_queue)
{
  /* Simple version: declare session ready-to-go... */
  s->session_state = SESSION_STATE_READY;
  return 0;
}

static int builtin_session_clear_callback (session_manager_main_t * ssm, 
                                           application_t * ss,
                                           stream_session_t * s)
{
  stream_session_delete (ssm, s);
  return 0;
}

static int builtin_server_rx_callback (session_manager_main_t * ssm, 
                                       application_t * ss,
                                       stream_session_t * s)
{
  svm_fifo_t * rx_fifo, * tx_fifo;
  u32 this_transfer;
  int actual_transfer;
  u8 * my_copy_buffer;
  fifo_event_t evt;
  unix_shared_memory_queue_t *q;

  my_copy_buffer = ssm->copy_buffers [s->session_thread_index];
  rx_fifo = s->server_rx_fifo;
  tx_fifo = s->server_tx_fifo;

  this_transfer = svm_fifo_max_enqueue (tx_fifo) 
    < svm_fifo_max_dequeue (rx_fifo) ?
    svm_fifo_max_enqueue (tx_fifo) : svm_fifo_max_dequeue(rx_fifo);

  vec_validate (my_copy_buffer, this_transfer - 1);
  _vec_len (my_copy_buffer) = this_transfer;

  actual_transfer = svm_fifo_dequeue_nowait2 (rx_fifo, 0, this_transfer,
                                              my_copy_buffer);
  ASSERT (actual_transfer == this_transfer);
  actual_transfer = svm_fifo_enqueue_nowait2 (tx_fifo, 0, this_transfer,
                                              my_copy_buffer);
                                              
  ssm->copy_buffers [s->session_thread_index] = my_copy_buffer;

  /* Fabricate TX event, send to ourselves */
  evt.fifo = tx_fifo;
  evt.event_type = FIFO_EVENT_SERVER_TX;
  /* $$$$ for event logging */
  evt.enqueue_length = actual_transfer;
  evt.event_id = 0;
  q = ssm->vpp_event_queues[s->session_thread_index];
  unix_shared_memory_queue_add (q, (u8 *)&evt, 0 /* do wait for mutex */);

  return 0;
}

static int
bind_builtin_uri_server (u8 * uri)
{
  vnet_bind_uri_args_t _a, *a = & _a;
  char segment_name[128];
  u32 segment_name_length;
  int rv;

  segment_name_length = ARRAY_LEN(segment_name);

  memset (a, 0, sizeof (*a));

  a->uri = (char *) uri;
  a->api_client_index = ~0; /* built-in server */
  a->accept_cookie = 0x12345678;
  a->segment_size = (2<<30); /*$$$$ config / arg */
  a->options = 0; /*$$$$ eventually */
  a->segment_name = segment_name;
  a->segment_name_length = segment_name_length;
  a->send_session_create_callback = builtin_session_create_callback;
  a->send_session_clear_callback = builtin_session_clear_callback;
  a->builtin_server_rx_callback = builtin_server_rx_callback;

  rv = vnet_bind_uri (a);

  return rv;
}

static int unbind_builtin_uri_server (u8 * uri)
{
  int rv;

  rv = vnet_unbind_uri ((char *)uri, ~0 /* client_index */);

  return rv;
}

static clib_error_t *
builtin_uri_bind_command_fn (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  u8 * uri = 0;
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
    
    vec_free(uri);
    
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
  u8 * uri = 0;
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
    
    vec_free(uri);

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
