/*
* Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <http/http.h>

typedef struct
{
  u32 hs_index;
  u32 thread_index;
  u64 node_index;
  u8 *buf;
} hcs_cli_args_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 session_index;
  u32 thread_index;
  u8 *tx_buf;
  u32 tx_offset;
  u32 vpp_session_index;
} hcs_session_t;

typedef struct
{
  hcs_session_t **sessions;
  u32 *free_http_cli_process_node_indices;
  u32 app_index;

  /* Cert key pair for tls */
  u32 ckpair_index;

  u32 prealloc_fifos;
  u32 private_segment_size;
  u32 fifo_size;
  u8 *uri;
  vlib_main_t *vlib_main;
} hcs_main_t;

static hcs_main_t hcs_main;

static hcs_session_t *
hcs_session_alloc (u32 thread_index)
{
  hcs_main_t *hcm = &hcs_main;
  hcs_session_t *hs;
  pool_get (hcm->sessions[thread_index], hs);
  memset (hs, 0, sizeof (*hs));
  hs->session_index = hs - hcm->sessions[thread_index];
  hs->thread_index = thread_index;
  return hs;
}

static hcs_session_t *
hcs_session_get (u32 thread_index, u32 hs_index)
{
  hcs_main_t *hcm = &hcs_main;
  if (pool_is_free_index (hcm->sessions[thread_index], hs_index))
    return 0;
  return pool_elt_at_index (hcm->sessions[thread_index], hs_index);
}

static void
hcs_session_free (hcs_session_t *hs)
{
  hcs_main_t *hcm = &hcs_main;
  u32 thread = hs->thread_index;
  if (CLIB_DEBUG)
    memset (hs, 0xfa, sizeof (*hs));
  pool_put (hcm->sessions[thread], hs);
}

static void
hcs_cli_process_free (hcs_cli_args_t *args)
{
  vlib_main_t *vm = vlib_get_first_main ();
  hcs_main_t *hcm = &hcs_main;
  hcs_cli_args_t **save_args;
  vlib_node_runtime_t *rt;
  vlib_node_t *n;
  u32 node_index;

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
  vec_add1 (hcm->free_http_cli_process_node_indices, node_index);
}

/* Header, including incantation to suppress favicon.ico requests */
static const char *html_header_template =
    "<html><head><title>%v</title></head>"
    "<link rel=\"icon\" href=\"data:,\">"
    "<body><pre>";

static const char *html_footer =
    "</pre></body></html>\r\n";

static void
hcs_cli_output (uword arg, u8 *buffer, uword buffer_bytes)
{
  u8 **output_vecp = (u8 **) arg;
  u8 *output_vec;
  u32 offset;

  output_vec = *output_vecp;

  offset = vec_len (output_vec);
  vec_validate (output_vec, offset + buffer_bytes - 1);
  clib_memcpy_fast (output_vec + offset, buffer, buffer_bytes);

  *output_vecp = output_vec;
}

static void
start_send_data (hcs_session_t *hs, http_status_code_t status)
{
  http_msg_t msg;
  session_t *ts;
  int rv;

  msg.type = HTTP_MSG_REPLY;
  msg.code = status;
  msg.content_type = HTTP_CONTENT_TEXT_HTML;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = vec_len (hs->tx_buf);

  ts = session_get (hs->vpp_session_index, hs->thread_index);
  rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (!msg.data.len)
    goto done;

  rv = svm_fifo_enqueue (ts->tx_fifo, vec_len (hs->tx_buf), hs->tx_buf);

  if (rv != vec_len (hs->tx_buf))
    {
      hs->tx_offset = rv;
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }
  else
    {
      vec_free (hs->tx_buf);
    }

done:

  if (svm_fifo_set_event (ts->tx_fifo))
    session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);
}

static void
send_data_to_http (void *rpc_args)
{
  hcs_cli_args_t *args = (hcs_cli_args_t *) rpc_args;
  hcs_session_t *hs;

  hs = hcs_session_get (args->thread_index, args->hs_index);
  if (!hs)
    {
      vec_free (args->buf);
      goto cleanup;
    }

  hs->tx_buf = args->buf;
  start_send_data (hs, HTTP_STATUS_OK);

cleanup:

  clib_mem_free (rpc_args);
}

static uword
hcs_cli_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  u8 *request = 0, *reply = 0, *html = 0;
  hcs_cli_args_t *args, *rpc_args;
  hcs_main_t *hcm = &hcs_main;
  hcs_cli_args_t **save_args;
  unformat_input_t input;
  int i;

  save_args = vlib_node_get_runtime_data (hcm->vlib_main, rt->node_index);
  args = *save_args;

  request = args->buf;

  /* Replace slashes with spaces, stop at the end of the path */
  i = 0;
  while (i < vec_len (request))
    {
      if (request[i] == '/')
	request[i] = ' ';
      else if (request[i] == ' ')
	{
	  /* vlib_cli_input is vector-based, no need for a NULL */
	  vec_set_len (request, i);
	  break;
	}
      i++;
    }

  /* Generate the html header */
  html = format (0, html_header_template, request /* title */ );

  /* Run the command */
  unformat_init_vector (&input, vec_dup (request));
  vlib_cli_input (vm, &input, hcs_cli_output, (uword) &reply);
  unformat_free (&input);
  request = 0;

  /* Generate the html page */
  html = format (html, "%v", reply);
  html = format (html, html_footer);

  /* Send it */
  rpc_args = clib_mem_alloc (sizeof (*args));
  clib_memcpy_fast (rpc_args, args, sizeof (*args));
  rpc_args->buf = html;

  session_send_rpc_evt_to_thread_force (args->thread_index, send_data_to_http,
					rpc_args);

  vec_free (reply);
  vec_free (args->buf);
  hcs_cli_process_free (args);

  return (0);
}

static void
alloc_cli_process (hcs_cli_args_t *args)
{
  hcs_main_t *hcm = &hcs_main;
  vlib_main_t *vm = hcm->vlib_main;
  hcs_cli_args_t **save_args;
  vlib_node_t *n;
  uword l;

  l = vec_len (hcm->free_http_cli_process_node_indices);
  if (l > 0)
    {
      n = vlib_get_node (vm, hcm->free_http_cli_process_node_indices[l - 1]);
      vlib_node_set_state (vm, n->index, VLIB_NODE_STATE_POLLING);
      vec_set_len (hcm->free_http_cli_process_node_indices, l - 1);
    }
  else
    {
      static vlib_node_registration_t r = {
	.function = hcs_cli_process,
	.type = VLIB_NODE_TYPE_PROCESS,
	.process_log2_n_stack_bytes = 16,
	.runtime_data_bytes = sizeof (void *),
      };

      vlib_register_node (vm, &r, "http-cli-%d", l);

      n = vlib_get_node (vm, r.index);
    }

  /* Save the node index in the args. It won't be zero. */
  args->node_index = n->index;

  /* Save the args (pointer) in the node runtime */
  save_args = vlib_node_get_runtime_data (vm, n->index);
  *save_args = clib_mem_alloc (sizeof (*args));
  clib_memcpy_fast (*save_args, args, sizeof (*args));

  vlib_start_process (vm, n->runtime_index);
}

static void
alloc_cli_process_callback (void *cb_args)
{
  alloc_cli_process ((hcs_cli_args_t *) cb_args);
}

static int
hcs_ts_rx_callback (session_t *ts)
{
  hcs_cli_args_t args = {};
  hcs_session_t *hs;
  http_msg_t msg;
  int rv;

  hs = hcs_session_get (ts->thread_index, ts->opaque);

  /* Read the http message header */
  rv = svm_fifo_dequeue (ts->rx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.type != HTTP_MSG_REQUEST || msg.method_type != HTTP_REQ_GET)
    {
      hs->tx_buf = 0;
      start_send_data (hs, HTTP_STATUS_METHOD_NOT_ALLOWED);
      return 0;
    }

  /* send the command to a new/recycled vlib process */
  vec_validate (args.buf, msg.data.len - 1);
  rv = svm_fifo_dequeue (ts->rx_fifo, msg.data.len, args.buf);
  ASSERT (rv == msg.data.len);
  vec_set_len (args.buf, rv);

  args.hs_index = hs->session_index;
  args.thread_index = ts->thread_index;

  /* Send RPC request to main thread */
  if (vlib_get_thread_index () != 0)
    vlib_rpc_call_main_thread (alloc_cli_process_callback, (u8 *) &args,
			       sizeof (args));
  else
    alloc_cli_process (&args);
  return 0;
}

static int
hcs_ts_tx_callback (session_t *ts)
{
  hcs_session_t *hs;
  u32 to_send;
  int rv;

  hs = hcs_session_get (ts->thread_index, ts->opaque);
  if (!hs || !hs->tx_buf)
    return 0;

  to_send = vec_len (hs->tx_buf) - hs->tx_offset;
  rv = svm_fifo_enqueue (ts->tx_fifo, to_send, hs->tx_buf + hs->tx_offset);

  if (rv <= 0)
    {
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  if (rv < to_send)
    {
      hs->tx_offset += rv;
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }
  else
    {
      vec_free (hs->tx_buf);
    }

  if (svm_fifo_set_event (ts->tx_fifo))
    session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);

  return 0;
}

static int
hcs_ts_accept_callback (session_t *ts)
{
  hcs_session_t *hs;

  hs = hcs_session_alloc (ts->thread_index);
  hs->vpp_session_index = ts->session_index;

  ts->opaque = hs->session_index;
  ts->session_state = SESSION_STATE_READY;

  return 0;
}

static int
hcs_ts_connected_callback (u32 app_index, u32 api_context, session_t *s,
			   session_error_t err)
{
  clib_warning ("called...");
  return -1;
}

static void
hcs_ts_disconnect_callback (session_t *s)
{
  hcs_main_t *hcm = &hcs_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = hcm->app_index;
  vnet_disconnect_session (a);
}

static void
hcs_ts_reset_callback (session_t *s)
{
  hcs_main_t *hcm = &hcs_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = hcm->app_index;
  vnet_disconnect_session (a);
}

static void
hcs_ts_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  hcs_session_t *hs;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  hs = hcs_session_get (s->thread_index, s->opaque);
  if (!hs)
    return;

  vec_free (hs->tx_buf);
  hcs_session_free (hs);
}

static int
hcs_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static int
hcs_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static session_cb_vft_t hcs_session_cb_vft = {
  .session_accept_callback = hcs_ts_accept_callback,
  .session_disconnect_callback = hcs_ts_disconnect_callback,
  .session_connected_callback = hcs_ts_connected_callback,
  .add_segment_callback = hcs_add_segment_callback,
  .del_segment_callback = hcs_del_segment_callback,
  .builtin_app_rx_callback = hcs_ts_rx_callback,
  .builtin_app_tx_callback = hcs_ts_tx_callback,
  .session_reset_callback = hcs_ts_reset_callback,
  .session_cleanup_callback = hcs_ts_cleanup_callback,
};

static int
hcs_attach ()
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  hcs_main_t *hcm = &hcs_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;
  u32 segment_size = 128 << 20;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  if (hcm->private_segment_size)
    segment_size = hcm->private_segment_size;

  a->api_client_index = ~0;
  a->name = format (0, "http_cli_server");
  a->session_cb_vft = &hcs_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] =
    hcm->fifo_size ? hcm->fifo_size : 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] =
    hcm->fifo_size ? hcm->fifo_size : 32 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = hcm->prealloc_fifos;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      clib_warning ("failed to attach server");
      return -1;
    }
  vec_free (a->name);
  hcm->app_index = a->app_index;

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  hcm->ckpair_index = ck_pair->index;

  return 0;
}

static int
hcs_transport_needs_crypto (transport_proto_t proto)
{
  return proto == TRANSPORT_PROTO_TLS || proto == TRANSPORT_PROTO_DTLS ||
	 proto == TRANSPORT_PROTO_QUIC;
}

static int
hcs_listen ()
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  hcs_main_t *hcm = &hcs_main;
  vnet_listen_args_t _a, *a = &_a;
  char *uri = "tcp://0.0.0.0/80";
  u8 need_crypto;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->app_index = hcm->app_index;

  if (hcm->uri)
    uri = (char *) hcm->uri;

  if (parse_uri (uri, &sep))
    return -1;

  need_crypto = hcs_transport_needs_crypto (sep.transport_proto);

  sep.transport_proto = TRANSPORT_PROTO_HTTP;
  clib_memcpy (&a->sep_ext, &sep, sizeof (sep));

  if (need_crypto)
    {
      session_endpoint_alloc_ext_cfg (&a->sep_ext,
				      TRANSPORT_ENDPT_EXT_CFG_CRYPTO);
      a->sep_ext.ext_cfg->crypto.ckpair_index = hcm->ckpair_index;
    }

  rv = vnet_listen (a);

  if (need_crypto)
    clib_mem_free (a->sep_ext.ext_cfg);

  return rv;
}

static int
hcs_create (vlib_main_t *vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  hcs_main_t *hcm = &hcs_main;
  u32 num_threads;

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (hcm->sessions, num_threads - 1);

  if (hcs_attach ())
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  if (hcs_listen ())
    {
      clib_warning ("failed to start listening");
      return -1;
    }

  return 0;
}

static clib_error_t *
hcs_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  hcs_main_t *hcm = &hcs_main;
  u64 seg_size;
  int rv;

  hcm->prealloc_fifos = 0;
  hcm->private_segment_size = 0;
  hcm->fifo_size = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    goto start_server;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "prealloc-fifos %d", &hcm->prealloc_fifos))
	;
      else if (unformat (line_input, "private-segment-size %U",
			 unformat_memory_size, &seg_size))
	hcm->private_segment_size = seg_size;
      else if (unformat (line_input, "fifo-size %d", &hcm->fifo_size))
	hcm->fifo_size <<= 10;
      else if (unformat (line_input, "uri %s", &hcm->uri))
	;
      else
	{
	  unformat_free (line_input);
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, line_input);
	}
    }

  unformat_free (line_input);

start_server:

  if (hcm->app_index != (u32) ~0)
    return clib_error_return (0, "test http server is already running");

  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );

  rv = hcs_create (vm);
  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "server_create returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (hcs_create_command, static) = {
  .path = "http cli server",
  .short_help = "http cli server [uri <uri>] [fifo-size <nbytes>] "
		"[private-segment-size <nMG>] [prealloc-fifos <n>]",
  .function = hcs_create_command_fn,
};

static clib_error_t *
hcs_main_init (vlib_main_t *vm)
{
  hcs_main_t *hcs = &hcs_main;

  hcs->app_index = ~0;
  hcs->vlib_main = vm;
  return 0;
}

VLIB_INIT_FUNCTION (hcs_main_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
