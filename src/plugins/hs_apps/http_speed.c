/*
* Copyright (c) 2022 Cisco and/or its affiliates.
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

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 session_index;
  u32 thread_index;
  u8 *tx_buf;
  u32 tx_offset;
  u32 vpp_session_index;
} hs_session_t;

typedef struct hs_main_
{
  hs_session_t **sessions;
  u32 app_index;

  u32 ckpair_index;

  /*
   * Configs
   */
  u8 *uri;
  u32 fifo_size;
  u64 private_segment_size;
} hs_main_t;

static hs_main_t hs_main;

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
hc_add_segment_callback (u32 client_index, u64 segment_handle)
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
  .add_segment_callback = hc_add_segment_callback,
  .del_segment_callback = hcs_del_segment_callback,
  .builtin_app_rx_callback = hcs_ts_rx_callback,
  .builtin_app_tx_callback = hcs_ts_tx_callback,
  .session_reset_callback = hcs_ts_reset_callback,
  .session_cleanup_callback = hcs_ts_cleanup_callback,
};

static int
hs_attach (hs_main_t *hm)
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;
  u32 segment_size = 128 << 20;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  if (hm->private_segment_size)
    segment_size = hm->private_segment_size;

  a->api_client_index = ~0;
  a->name = format (0, "http_cli_server");
  a->session_cb_vft = &hcs_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] =
    hm->fifo_size ? hm->fifo_size : 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] =
    hm->fifo_size ? hm->fifo_size : 32 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      clib_warning ("failed to attach server");
      return -1;
    }
  vec_free (a->name);
  hm->app_index = a->app_index;

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  hm->ckpair_index = ck_pair->index;

  return 0;
}

static int
hs_create (vlib_main_t *vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  hs_main_t *hm = &hs_main;
  u32 num_threads;

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (hm->sessions, num_threads - 1);

  if (hs_attach ())
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  if (hs_listen ())
    {
      clib_warning ("failed to start listening");
      return -1;
    }

  return 0;
}

static clib_error_t *
hs_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  hs_main_t *hsm = &hs_main;
  u64 mem_size;
  clib_error_t *error = 0;
  int rv;

  hsm->private_segment_size = 0;
  hsm->fifo_size = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    goto start_server;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "private-segment-size %U", unformat_memory_size,
	            &mem_size))
	hsm->private_segment_size = mem_size;
      else if (unformat (line_input, "fifo-size %U", unformat_memory_size,
	                 &mem_size))
	hsm->fifo_size = mem_size;
      else if (unformat (line_input, "uri %s", &hsm->uri))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, line_input);
	  break;
	}
    }

  unformat_free (line_input);

  if (error)
    return error;

start_server:

  if (hsm->app_index != (u32) ~0)
    return clib_error_return (0, "http speed is already running");

  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );

  rv = hs_create (vm);

  return 0;
}


VLIB_CLI_COMMAND (http_speed_command, static) = {
  .path = "http speed",
  .short_help = "http speed [uri <uri>] [fifo-size <nbytes>] "
		"[segment-size <nMG>] [prealloc-fifos <n>]",
  .function = hs_create_command_fn,
};

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/

