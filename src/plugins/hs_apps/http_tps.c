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

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <http/http.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 session_index;
  u32 thread_index;
  u64 data_len;
  u64 data_offset;
  u32 vpp_session_index;
} hts_session_t;

typedef struct hs_main_
{
  hts_session_t **sessions;
  u32 app_index;

  u32 ckpair_index;
  u8 *test_data;

  /*
   * Configs
   */
  u8 *uri;
  u32 fifo_size;
  u64 segment_size;
  u8 debug_level;
  u8 no_zc;
} hts_main_t;

static hts_main_t hts_main;

static hts_session_t *
hts_session_alloc (u32 thread_index)
{
  hts_main_t *htm = &hts_main;
  hts_session_t *hs;

  pool_get_zero (htm->sessions[thread_index], hs);
  hs->session_index = hs - htm->sessions[thread_index];
  hs->thread_index = thread_index;

  return hs;
}

static hts_session_t *
hts_session_get (u32 thread_index, u32 hts_index)
{
  hts_main_t *htm = &hts_main;

  if (pool_is_free_index (htm->sessions[thread_index], hts_index))
    return 0;

  return pool_elt_at_index (htm->sessions[thread_index], hts_index);
}

static void
hts_session_free (hts_session_t *hs)
{
  hts_main_t *htm = &hts_main;
  u32 thread = hs->thread_index;

  if (CLIB_DEBUG)
    clib_memset (hs, 0xfa, sizeof (*hs));

  pool_put (htm->sessions[thread], hs);
}

static void
hts_session_tx_zc (hts_session_t *hs, session_t *ts)
{
  u32 to_send, space;
  u64 max_send;
  int rv;

  rv = svm_fifo_fill_chunk_list (ts->tx_fifo);
  if (rv < 0)
    {
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return;
    }

  max_send = hs->data_len - hs->data_offset;
  space = svm_fifo_max_enqueue (ts->tx_fifo);
  ASSERT (space != 0);
  to_send = clib_min (space, max_send);

  svm_fifo_enqueue_nocopy (ts->tx_fifo, to_send);

  hs->data_offset += to_send;

  if (to_send < max_send)
    svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  if (svm_fifo_set_event (ts->tx_fifo))
    session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);
}

static void
hts_session_tx_no_zc (hts_session_t *hs, session_t *ts)
{
  u32 n_segs, buf_offset, buf_left;
  u64 max_send = 32 << 10, left;
  hts_main_t *htm = &hts_main;
  svm_fifo_seg_t seg[2];
  int sent;

  left = hs->data_len - hs->data_offset;
  max_send = clib_min (left, max_send);
  buf_offset = hs->data_offset % vec_len (htm->test_data);
  buf_left = vec_len (htm->test_data) - buf_offset;

  if (buf_left < max_send)
    {
      seg[0].data = htm->test_data + buf_offset;
      seg[0].len = buf_left;
      seg[1].data = htm->test_data;
      seg[1].len = max_send - buf_left;
      n_segs = 2;
    }
  else
    {
      seg[0].data = htm->test_data + buf_offset;
      seg[0].len = max_send;
      n_segs = 1;
    }

  sent = svm_fifo_enqueue_segments (ts->tx_fifo, seg, n_segs,
				    1 /* allow partial */);

  if (sent <= 0)
    {
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return;
    }

  hs->data_offset += sent;

  if (sent < left)
    svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  if (svm_fifo_set_event (ts->tx_fifo))
    session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);
}

static inline void
hts_session_tx (hts_session_t *hs, session_t *ts)
{
  hts_main_t *htm = &hts_main;

  if (!htm->no_zc)
    hts_session_tx_zc (hs, ts);
  else
    hts_session_tx_no_zc (hs, ts);
}

static void
hts_start_send_data (hts_session_t *hs, http_status_code_t status)
{
  http_msg_t msg;
  session_t *ts;
  int rv;

  msg.type = HTTP_MSG_REPLY;
  msg.code = status;
  msg.content_type = HTTP_CONTENT_TEXT_HTML;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = hs->data_len;

  ts = session_get (hs->vpp_session_index, hs->thread_index);
  rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (!msg.data.len)
    {
      if (svm_fifo_set_event (ts->tx_fifo))
	session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);
      return;
    }

  hts_session_tx (hs, ts);
}

static int
try_test_file (hts_session_t *hs, u8 *request)
{
  char *test_str = "test_file";
  hts_main_t *htm = &hts_main;
  unformat_input_t input;
  uword file_size;
  int rc = 0;

  if (memcmp (request, test_str, clib_strnlen (test_str, 9)))
    return -1;

  unformat_init_vector (&input, vec_dup (request));
  if (!unformat (&input, "test_file_%U", unformat_memory_size, &file_size))
    {
      rc = -1;
      goto done;
    }

  if (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      rc = -1;
      goto done;
    }

  if (htm->debug_level)
    clib_warning ("Requested file size %U", format_memory_size, file_size);

  hs->data_len = file_size;

  hts_start_send_data (hs, HTTP_STATUS_OK);

done:
  unformat_free (&input);

  return rc;
}

static int
hts_ts_rx_callback (session_t *ts)
{
  hts_session_t *hs;
  u8 *request = 0;
  http_msg_t msg;
  int rv;

  hs = hts_session_get (ts->thread_index, ts->opaque);

  /* Read the http message header */
  rv = svm_fifo_dequeue (ts->rx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.type != HTTP_MSG_REQUEST || msg.method_type != HTTP_REQ_GET)
    {
      hts_start_send_data (hs, HTTP_STATUS_METHOD_NOT_ALLOWED);
      goto done;
    }

  if (!msg.data.len)
    {
      hts_start_send_data (hs, HTTP_STATUS_BAD_REQUEST);
      goto done;
    }

  vec_validate (request, msg.data.len - 1);
  rv = svm_fifo_dequeue (ts->rx_fifo, msg.data.len, request);

  if (try_test_file (hs, request))
    hts_start_send_data (hs, HTTP_STATUS_NOT_FOUND);

done:

  return 0;
}

static int
hs_ts_tx_callback (session_t *ts)
{
  hts_session_t *hs;

  hs = hts_session_get (ts->thread_index, ts->opaque);
  if (!hs)
    return 0;

  hts_session_tx (hs, ts);

  return 0;
}

static int
hts_ts_accept_callback (session_t *ts)
{
  hts_session_t *hs;

  hs = hts_session_alloc (ts->thread_index);
  hs->vpp_session_index = ts->session_index;

  ts->opaque = hs->session_index;
  ts->session_state = SESSION_STATE_READY;

  return 0;
}

static int
hts_ts_connected_callback (u32 app_index, u32 api_context, session_t *s,
			   session_error_t err)
{
  clib_warning ("called...");
  return -1;
}

static void
hts_ts_disconnect_callback (session_t *s)
{
  hts_main_t *htm = &hts_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = htm->app_index;
  vnet_disconnect_session (a);
}

static void
hts_ts_reset_callback (session_t *s)
{
  hts_main_t *htm = &hts_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = htm->app_index;
  vnet_disconnect_session (a);
}

static void
hts_ts_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  hts_session_t *hs;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  hs = hts_session_get (s->thread_index, s->opaque);
  if (!hs)
    return;

  hts_session_free (hs);
}

static int
hts_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static int
hts_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static session_cb_vft_t hs_session_cb_vft = {
  .session_accept_callback = hts_ts_accept_callback,
  .session_disconnect_callback = hts_ts_disconnect_callback,
  .session_connected_callback = hts_ts_connected_callback,
  .add_segment_callback = hts_add_segment_callback,
  .del_segment_callback = hts_del_segment_callback,
  .builtin_app_rx_callback = hts_ts_rx_callback,
  .builtin_app_tx_callback = hs_ts_tx_callback,
  .session_reset_callback = hts_ts_reset_callback,
  .session_cleanup_callback = hts_ts_cleanup_callback,
};

static int
hts_attach (hts_main_t *hm)
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = ~0;
  a->name = format (0, "http_tps");
  a->session_cb_vft = &hs_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = hm->segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = hm->segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = hm->fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = hm->fifo_size;
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
hts_transport_needs_crypto (transport_proto_t proto)
{
  return proto == TRANSPORT_PROTO_TLS || proto == TRANSPORT_PROTO_DTLS ||
	 proto == TRANSPORT_PROTO_QUIC;
}

static int
hts_listen (hts_main_t *htm)
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  vnet_listen_args_t _a, *a = &_a;
  char *uri = "tcp://0.0.0.0/80";
  u8 need_crypto;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->app_index = htm->app_index;

  if (htm->uri)
    uri = (char *) htm->uri;

  if (parse_uri (uri, &sep))
    return -1;

  need_crypto = hts_transport_needs_crypto (sep.transport_proto);

  sep.transport_proto = TRANSPORT_PROTO_HTTP;
  clib_memcpy (&a->sep_ext, &sep, sizeof (sep));

  if (need_crypto)
    {
      session_endpoint_alloc_ext_cfg (&a->sep_ext,
				      TRANSPORT_ENDPT_EXT_CFG_CRYPTO);
      a->sep_ext.ext_cfg->crypto.ckpair_index = htm->ckpair_index;
    }

  rv = vnet_listen (a);

  if (need_crypto)
    clib_mem_free (a->sep_ext.ext_cfg);

  return rv;
}

static int
hts_create (vlib_main_t *vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  hts_main_t *htm = &hts_main;
  u32 num_threads;

  num_threads = 1 /* main thread */ + vtm->n_threads;
  vec_validate (htm->sessions, num_threads - 1);

  if (htm->no_zc)
    vec_validate (htm->test_data, (64 << 10) - 1);

  if (hts_attach (htm))
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  if (hts_listen (htm))
    {
      clib_warning ("failed to start listening");
      return -1;
    }

  return 0;
}

static clib_error_t *
hts_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  hts_main_t *htm = &hts_main;
  clib_error_t *error = 0;
  u64 mem_size;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    goto start_server;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "private-segment-size %U",
		    unformat_memory_size, &mem_size))
	htm->segment_size = mem_size;
      else if (unformat (line_input, "fifo-size %U", unformat_memory_size,
			 &mem_size))
	htm->fifo_size = mem_size;
      else if (unformat (line_input, "uri %s", &htm->uri))
	;
      else if (unformat (line_input, "no-zc"))
	htm->no_zc = 1;
      else if (unformat (line_input, "debug"))
	htm->debug_level = 1;
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

  if (htm->app_index != (u32) ~0)
    return clib_error_return (0, "http tps is already running");

  vnet_session_enable_disable (vm, 1 /* is_enable */);

  if (hts_create (vm))
    return clib_error_return (0, "http tps create failed");

  return 0;
}

VLIB_CLI_COMMAND (http_tps_command, static) = {
  .path = "http tps",
  .short_help = "http tps [uri <uri>] [fifo-size <nbytes>] "
		"[segment-size <nMG>] [prealloc-fifos <n>] [debug] [no-zc]",
  .function = hts_create_command_fn,
};

static clib_error_t *
hs_main_init (vlib_main_t *vm)
{
  hts_main_t *htm = &hts_main;

  htm->app_index = ~0;
  htm->segment_size = 128 << 20;
  htm->fifo_size = 64 << 10;

  return 0;
}

VLIB_INIT_FUNCTION (hs_main_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
