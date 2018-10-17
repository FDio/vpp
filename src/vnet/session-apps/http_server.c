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
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>

typedef enum
{
  EVENT_WAKEUP = 1,
} http_process_event_t;

typedef struct
{
  u64 session_handle;
  u64 node_index;
  u8 *data;
} http_server_args;

typedef struct
{
  u8 **rx_buf;
  svm_msg_q_t **vpp_queue;
  u64 byte_index;

  uword *handler_by_get_request;

  u32 *free_http_cli_process_node_indices;

  /* Sever's event queue */
  svm_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  u32 app_index;

  /* process node index for evnt scheduling */
  u32 node_index;

  u32 prealloc_fifos;
  u32 private_segment_size;
  u32 fifo_size;
  u8 *uri;
  vlib_main_t *vlib_main;
} http_server_main_t;

http_server_main_t http_server_main;

static void
free_http_process (http_server_args * args)
{
  vlib_node_runtime_t *rt;
  vlib_main_t *vm = &vlib_global_main;
  http_server_main_t *hsm = &http_server_main;
  vlib_node_t *n;
  u32 node_index;
  http_server_args **save_args;

  node_index = args->node_index;
  ASSERT (node_index != 0);

  n = vlib_get_node (vm, node_index);
  rt = vlib_node_get_runtime (vm, n->index);
  save_args = vlib_node_get_runtime_data (vm, n->index);

  /* Reset process session pointer */
  clib_mem_free (*save_args);
  *save_args = 0;

  /* Turn off the process node */
  vlib_node_set_state (vm, rt->node_index, VLIB_NODE_STATE_DISABLED);

  /* add node index to the freelist */
  vec_add1 (hsm->free_http_cli_process_node_indices, node_index);
}

/* *INDENT-OFF* */
static const char *http_response =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Expires: Mon, 11 Jan 1970 10:10:10 GMT\r\n"
    "Connection: keep-alive \r\n"
    "Pragma: no-cache\r\n"
    "Content-Length: %d\r\n\r\n%s";

static const char *http_error_template =
    "HTTP/1.1 %s\r\n"
    "Content-Type: text/html\r\n"
    "Expires: Mon, 11 Jan 1970 10:10:10 GMT\r\n"
    "Connection: close\r\n"
    "Pragma: no-cache\r\n"
    "Content-Length: 0\r\n\r\n";

/* Header, including incantation to suppress favicon.ico requests */
static const char *html_header_template =
    "<html><head><title>%v</title></head>"
    "<link rel=\"icon\" href=\"data:,\">"
    "<body><pre>";

static const char *html_footer =
    "</pre></body></html>\r\n";

static const char *html_header_static =
    "<html><head><title>static reply</title></head>"
    "<link rel=\"icon\" href=\"data:,\">"
    "<body><pre>hello</pre></body></html>\r\n";
/* *INDENT-ON* */

static u8 *static_http;

static void
http_cli_output (uword arg, u8 * buffer, uword buffer_bytes)
{
  u8 **output_vecp = (u8 **) arg;
  u8 *output_vec;
  u32 offset;

  output_vec = *output_vecp;

  offset = vec_len (output_vec);
  vec_validate (output_vec, offset + buffer_bytes - 1);
  clib_memcpy (output_vec + offset, buffer, buffer_bytes);

  *output_vecp = output_vec;
}

void
send_data (stream_session_t * s, u8 * data)
{
  u32 offset, bytes_to_send;
  f64 delay = 10e-3;
  http_server_main_t *hsm = &http_server_main;
  vlib_main_t *vm = hsm->vlib_main;
  f64 last_sent_timer = vlib_time_now (vm);

  bytes_to_send = vec_len (data);
  offset = 0;

  while (bytes_to_send > 0)
    {
      int actual_transfer;

      actual_transfer = svm_fifo_enqueue_nowait
	(s->server_tx_fifo, bytes_to_send, data + offset);

      /* Made any progress? */
      if (actual_transfer <= 0)
	{
	  vlib_process_suspend (vm, delay);
	  /* 10s deadman timer */
	  if (vlib_time_now (vm) > last_sent_timer + 10.0)
	    {
	      /* $$$$ FC: reset transport session here? */
	      break;
	    }
	  /* Exponential backoff, within reason */
	  if (delay < 1.0)
	    delay = delay * 2.0;
	}
      else
	{
	  last_sent_timer = vlib_time_now (vm);
	  offset += actual_transfer;
	  bytes_to_send -= actual_transfer;

	  if (svm_fifo_set_event (s->server_tx_fifo))
	    session_send_io_evt_to_thread (s->server_tx_fifo,
					   FIFO_EVENT_APP_TX);
	  delay = 10e-3;
	}
    }
}

static void
send_error (stream_session_t * s, char *str)
{
  u8 *data;

  data = format (0, http_error_template, str);
  send_data (s, data);
  vec_free (data);
}

static uword
http_cli_process (vlib_main_t * vm,
		  vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  http_server_main_t *hsm = &http_server_main;
  u8 *request = 0, *reply = 0;
  http_server_args **save_args;
  http_server_args *args;
  stream_session_t *s;
  unformat_input_t input;
  int i;
  u8 *http = 0, *html = 0;

  save_args = vlib_node_get_runtime_data (hsm->vlib_main, rt->node_index);
  args = *save_args;
  s = session_get_from_handle (args->session_handle);
  ASSERT (s);

  request = (u8 *) (void *) (args->data);
  if (vec_len (request) < 7)
    {
      send_error (s, "400 Bad Request");
      goto out;
    }

  for (i = 0; i < vec_len (request) - 4; i++)
    {
      if (request[i] == 'G' &&
	  request[i + 1] == 'E' &&
	  request[i + 2] == 'T' && request[i + 3] == ' ')
	goto found;
    }
bad_request:
  send_error (s, "400 Bad Request");
  goto out;

found:
  /* Lose "GET " */
  vec_delete (request, i + 5, 0);

  /* Replace slashes with spaces, stop at the end of the path */
  i = 0;
  while (1)
    {
      if (request[i] == '/')
	request[i] = ' ';
      else if (request[i] == ' ')
	{
	  /* vlib_cli_input is vector-based, no need for a NULL */
	  _vec_len (request) = i;
	  break;
	}
      i++;
      /* Should never happen */
      if (i == vec_len (request))
	goto bad_request;
    }

  /* Generate the html header */
  html = format (0, html_header_template, request /* title */ );

  /* Run the command */
  unformat_init_vector (&input, request);
  vlib_cli_input (vm, &input, http_cli_output, (uword) & reply);
  unformat_free (&input);
  request = 0;

  /* Generate the html page */
  html = format (html, "%v", reply);
  html = format (html, html_footer);
  /* And the http reply */
  http = format (0, http_response, vec_len (html), html);

  /* Send it */
  send_data (s, http);

out:
  /* Cleanup */
  vec_free (request);
  vec_free (reply);
  vec_free (html);
  vec_free (http);

  free_http_process (args);
  return (0);
}

static void
alloc_http_process (http_server_args * args)
{
  char *name;
  vlib_node_t *n;
  http_server_main_t *hsm = &http_server_main;
  vlib_main_t *vm = hsm->vlib_main;
  uword l = vec_len (hsm->free_http_cli_process_node_indices);
  http_server_args **save_args;

  if (vec_len (hsm->free_http_cli_process_node_indices) > 0)
    {
      n = vlib_get_node (vm, hsm->free_http_cli_process_node_indices[l - 1]);
      vlib_node_set_state (vm, n->index, VLIB_NODE_STATE_POLLING);
      _vec_len (hsm->free_http_cli_process_node_indices) = l - 1;
    }
  else
    {
      static vlib_node_registration_t r = {
	.function = http_cli_process,
	.type = VLIB_NODE_TYPE_PROCESS,
	.process_log2_n_stack_bytes = 16,
	.runtime_data_bytes = sizeof (void *),
      };

      name = (char *) format (0, "http-cli-%d", l);
      r.name = name;
      vlib_register_node (vm, &r);
      vec_free (name);

      n = vlib_get_node (vm, r.index);
    }

  /* Save the node index in the args. It won't be zero. */
  args->node_index = n->index;

  /* Save the args (pointer) in the node runtime */
  save_args = vlib_node_get_runtime_data (vm, n->index);
  *save_args = args;

  vlib_start_process (vm, n->runtime_index);
}

static void
alloc_http_process_callback (void *cb_args)
{
  alloc_http_process ((http_server_args *) cb_args);
}

static int
session_rx_request (stream_session_t * s)
{
  http_server_main_t *hsm = &http_server_main;
  svm_fifo_t *rx_fifo;
  u32 max_dequeue;
  int actual_transfer;

  rx_fifo = s->server_rx_fifo;
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  svm_fifo_unset_event (rx_fifo);
  if (PREDICT_FALSE (max_dequeue == 0))
    return -1;

  vec_validate (hsm->rx_buf[s->thread_index], max_dequeue - 1);
  _vec_len (hsm->rx_buf[s->thread_index]) = max_dequeue;

  actual_transfer = svm_fifo_dequeue_nowait (rx_fifo, max_dequeue,
					     hsm->rx_buf[s->thread_index]);
  ASSERT (actual_transfer > 0);
  _vec_len (hsm->rx_buf[s->thread_index]) = actual_transfer;
  return 0;
}

static int
http_server_rx_callback (stream_session_t * s)
{
  http_server_main_t *hsm = &http_server_main;
  http_server_args *args;
  int rv;

  rv = session_rx_request (s);
  if (rv)
    return rv;

  /* send the command to a new/recycled vlib process */
  args = clib_mem_alloc (sizeof (*args));
  args->data = vec_dup (hsm->rx_buf[s->thread_index]);
  args->session_handle = session_handle (s);

  /* Send an RPC request via the thread-0 input node */
  if (vlib_get_thread_index () != 0)
    session_send_rpc_evt_to_thread (0, alloc_http_process_callback, args);
  else
    alloc_http_process (args);
  return 0;
}

static int
http_server_rx_callback_static (stream_session_t * s)
{
  http_server_main_t *hsm = &http_server_main;
  u8 *request = 0;
  int i;
  int rv;

  rv = session_rx_request (s);
  if (rv)
    return rv;

  request = hsm->rx_buf[s->thread_index];
  if (vec_len (request) < 7)
    {
      send_error (s, "400 Bad Request");
      goto out;
    }

  for (i = 0; i < vec_len (request) - 4; i++)
    {
      if (request[i] == 'G' &&
	  request[i + 1] == 'E' &&
	  request[i + 2] == 'T' && request[i + 3] == ' ')
	goto found;
    }
  send_error (s, "400 Bad Request");
  goto out;

found:

  /* Send it */
  send_data (s, static_http);

out:
  /* Cleanup */
  vec_free (request);
  hsm->rx_buf[s->thread_index] = request;
  return 0;
}

static int
http_server_session_accept_callback (stream_session_t * s)
{
  http_server_main_t *bsm = &http_server_main;

  bsm->vpp_queue[s->thread_index] =
    session_manager_get_vpp_event_queue (s->thread_index);
  s->session_state = SESSION_STATE_READY;
  bsm->byte_index = 0;
  return 0;
}

static void
http_server_session_disconnect_callback (stream_session_t * s)
{
  http_server_main_t *bsm = &http_server_main;
  vnet_disconnect_args_t _a, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = bsm->app_index;
  vnet_disconnect_session (a);
}

static void
http_server_session_reset_callback (stream_session_t * s)
{
  clib_warning ("called.. ");
  stream_session_cleanup (s);
}

static int
http_server_session_connected_callback (u32 app_index, u32 api_context,
					stream_session_t * s, u8 is_fail)
{
  clib_warning ("called...");
  return -1;
}

static int
http_server_add_segment_callback (u32 client_index, const ssvm_private_t * sp)
{
  clib_warning ("called...");
  return -1;
}

static session_cb_vft_t http_server_session_cb_vft = {
  .session_accept_callback = http_server_session_accept_callback,
  .session_disconnect_callback = http_server_session_disconnect_callback,
  .session_connected_callback = http_server_session_connected_callback,
  .add_segment_callback = http_server_add_segment_callback,
  .builtin_app_rx_callback = http_server_rx_callback,
  .session_reset_callback = http_server_session_reset_callback
};

/* Abuse VPP's input queue */
static int
create_api_loopback (vlib_main_t * vm)
{
  http_server_main_t *hsm = &http_server_main;
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr;

  shmem_hdr = am->shmem_hdr;
  hsm->vl_input_queue = shmem_hdr->vl_input_queue;
  hsm->my_client_index =
    vl_api_memclnt_create_internal ("http_server", hsm->vl_input_queue);
  return 0;
}

static int
server_attach ()
{
  vnet_app_add_tls_cert_args_t _a_cert, *a_cert = &_a_cert;
  vnet_app_add_tls_key_args_t _a_key, *a_key = &_a_key;
  http_server_main_t *hsm = &http_server_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;
  u32 segment_size = 128 << 20;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  if (hsm->private_segment_size)
    segment_size = hsm->private_segment_size;

  a->api_client_index = hsm->my_client_index;
  a->session_cb_vft = &http_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 32 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = hsm->prealloc_fifos;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  hsm->app_index = a->app_index;

  clib_memset (a_cert, 0, sizeof (*a_cert));
  a_cert->app_index = a->app_index;
  vec_validate (a_cert->cert, test_srv_crt_rsa_len);
  clib_memcpy (a_cert->cert, test_srv_crt_rsa, test_srv_crt_rsa_len);
  vnet_app_add_tls_cert (a_cert);

  clib_memset (a_key, 0, sizeof (*a_key));
  a_key->app_index = a->app_index;
  vec_validate (a_key->key, test_srv_key_rsa_len);
  clib_memcpy (a_key->key, test_srv_key_rsa, test_srv_key_rsa_len);
  vnet_app_add_tls_key (a_key);

  return 0;
}

static int
http_server_listen ()
{
  http_server_main_t *hsm = &http_server_main;
  vnet_bind_args_t _a, *a = &_a;
  clib_memset (a, 0, sizeof (*a));
  a->app_index = hsm->app_index;
  a->uri = "tcp://0.0.0.0/80";
  if (hsm->uri)
    a->uri = (char *) hsm->uri;
  return vnet_bind_uri (a);
}

static int
http_server_create (vlib_main_t * vm)
{
  http_server_main_t *hsm = &http_server_main;
  u32 num_threads;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();

  ASSERT (hsm->my_client_index == (u32) ~ 0);
  if (create_api_loopback (vm))
    return -1;

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (http_server_main.vpp_queue, num_threads - 1);

  if (server_attach ())
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  if (http_server_listen ())
    {
      clib_warning ("failed to start listening");
      return -1;
    }
  return 0;
}

static clib_error_t *
http_server_create_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  http_server_main_t *hsm = &http_server_main;
  int rv, is_static = 0;
  u64 seg_size;
  u8 *html;

  hsm->prealloc_fifos = 0;
  hsm->private_segment_size = 0;
  hsm->fifo_size = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "static"))
	is_static = 1;
      else if (unformat (input, "prealloc-fifos %d", &hsm->prealloc_fifos))
	;
      else if (unformat (input, "private-segment-size %U",
			 unformat_memory_size, &seg_size))
	{
	  if (seg_size >= 0x100000000ULL)
	    {
	      vlib_cli_output (vm, "private segment size %llu, too large",
			       seg_size);
	      return 0;
	    }
	  hsm->private_segment_size = seg_size;
	}
      else if (unformat (input, "fifo-size %d", &hsm->fifo_size))
	hsm->fifo_size <<= 10;
      else if (unformat (input, "uri %s", &hsm->uri))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  if (hsm->my_client_index != (u32) ~ 0)
    return clib_error_return (0, "test http server is already running");

  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );

  if (is_static)
    {
      http_server_session_cb_vft.builtin_app_rx_callback =
	http_server_rx_callback_static;
      html = format (0, html_header_static);
      static_http = format (0, http_response, vec_len (html), html);
    }
  rv = http_server_create (vm);
  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "server_create returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (http_server_create_command, static) =
{
  .path = "test http server",
  .short_help = "test http server",
  .function = http_server_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
http_server_main_init (vlib_main_t * vm)
{
  http_server_main_t *hsm = &http_server_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;

  hsm->my_client_index = ~0;
  hsm->vlib_main = vm;
  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (hsm->rx_buf, num_threads - 1);
  return 0;
}

VLIB_INIT_FUNCTION (http_server_main_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
