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
#include <http/http_content_types.h>

#define HTS_RX_BUF_SIZE (64 << 10)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 session_index;
  clib_thread_index_t thread_index;
  u64 data_len;
  u64 data_offset;
  u32 vpp_session_index;
  u64 left_recv;
  u64 total_recv;
  union
  {
    /** threshold after which connection is closed */
    f64 close_threshold;
    /** rate at which accepted sessions are marked for random close */
    u32 close_rate;
  };
  u8 *uri;
  u8 *rx_buf;
  http_headers_ctx_t resp_headers;
  u8 *resp_headers_buf;
} hts_session_t;

typedef struct hts_listen_cfg_
{
  u8 *uri;
  u32 vrf;
  f64 rnd_close;
  u8 is_del;
} hts_listen_cfg_t;

typedef struct hs_main_
{
  hts_session_t **sessions;
  u32 app_index;

  u32 ckpair_index;
  u8 *test_data;

  /** Hash table of listener uris to handles */
  uword *uri_to_handle;

  /*
   * Configs
   */
  u8 *uri;
  u32 fifo_size;
  u64 segment_size;
  u8 debug_level;
  u8 no_zc;
  u8 *default_uri;
  u32 seed;
} hts_main_t;

static hts_main_t hts_main;

static hts_session_t *
hts_session_alloc (clib_thread_index_t thread_index)
{
  hts_main_t *htm = &hts_main;
  hts_session_t *hs;

  pool_get_zero (htm->sessions[thread_index], hs);
  hs->session_index = hs - htm->sessions[thread_index];
  hs->thread_index = thread_index;
  vec_validate (hs->resp_headers_buf, 255);

  return hs;
}

static hts_session_t *
hts_session_get (clib_thread_index_t thread_index, u32 hts_index)
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

  if (htm->debug_level > 0)
    clib_warning ("Freeing session %u", hs->session_index);

  vec_free (hs->rx_buf);
  vec_free (hs->resp_headers_buf);

  if (CLIB_DEBUG)
    clib_memset (hs, 0xfa, sizeof (*hs));

  pool_put (htm->sessions[thread], hs);
}

static void
hts_disconnect_transport (hts_session_t *hs)
{
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  hts_main_t *htm = &hts_main;
  session_t *ts;

  if (htm->debug_level > 0)
    clib_warning ("Actively closing session %u", hs->session_index);

  ts = session_get (hs->vpp_session_index, hs->thread_index);
  a->handle = session_handle (ts);
  a->app_index = htm->app_index;
  vnet_disconnect_session (a);
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
    session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX);
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

  clib_warning ("sent %u", sent);
  if (sent <= 0)
    {
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return;
    }

  hs->data_offset += sent;

  if (sent < left)
    svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  if (svm_fifo_set_event (ts->tx_fifo))
    session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX);
}

static inline void
hts_session_tx (hts_session_t *hs, session_t *ts)
{
  hts_main_t *htm = &hts_main;
  clib_warning ("BBBBBBBBBB");

  if (!htm->no_zc)
    hts_session_tx_zc (hs, ts);
  else
    hts_session_tx_no_zc (hs, ts);

  if (hs->close_threshold > 0)
    {
      if ((f64) hs->data_offset / hs->data_len > hs->close_threshold)
	hts_disconnect_transport (hs);
    }
}

static void
hts_start_send_data (hts_session_t *hs, http_status_code_t status)
{
  http_msg_t msg;
  session_t *ts;
  u32 n_segs = 1;
  svm_fifo_seg_t seg[2];
  int rv;

  msg.data.headers_offset = 0;
  msg.data.headers_len = 0;

  if (hs->resp_headers.tail_offset)
    {
      msg.data.headers_len = hs->resp_headers.tail_offset;
      seg[1].data = hs->resp_headers_buf;
      seg[1].len = msg.data.headers_len;
      n_segs = 2;
    }

  msg.type = HTTP_MSG_REPLY;
  msg.code = status;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.body_len = hs->data_len;
  msg.data.body_offset = msg.data.headers_len;
  msg.data.len = msg.data.body_len + msg.data.headers_len;
  seg[0].data = (u8 *) &msg;
  seg[0].len = sizeof (msg);

  ts = session_get (hs->vpp_session_index, hs->thread_index);
  rv = svm_fifo_enqueue_segments (ts->tx_fifo, seg, n_segs,
				  0 /* allow partial */);
  ASSERT (rv == (sizeof (msg) + msg.data.headers_len));

  if (!msg.data.body_len)
    {
      if (svm_fifo_set_event (ts->tx_fifo))
	session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX);
      return;
    }

  hts_session_tx (hs, ts);
}

static int
try_test_file (hts_session_t *hs, u8 *target)
{
  char *test_str = "test_file";
  hts_main_t *htm = &hts_main;
  unformat_input_t input;
  uword file_size;
  int rc = 0;

  if (memcmp (target, test_str, clib_strnlen (test_str, 9)))
    return -1;

  unformat_init_vector (&input, vec_dup (target));
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
  hs->data_offset = 0;

  if (hs->close_threshold > 0)
    {
      /* Disconnect if the header is already enough to fill the quota */
      if ((f64) 30 / hs->data_len > hs->close_threshold)
	{
	  hts_disconnect_transport (hs);
	  goto done;
	}
    }

  http_add_header (&hs->resp_headers, HTTP_HEADER_CONTENT_TYPE,
		   http_content_type_token (HTTP_CONTENT_APP_OCTET_STREAM));

  hts_start_send_data (hs, HTTP_STATUS_OK);

done:
  unformat_free (&input);

  return rc;
}

static inline void
hts_session_rx_body (hts_session_t *hs, session_t *ts)
{
  hts_main_t *htm = &hts_main;
  u32 n_deq;
  int rv;

  n_deq = svm_fifo_max_dequeue (ts->rx_fifo);
  if (!htm->no_zc)
    {
      svm_fifo_dequeue_drop_all (ts->rx_fifo);
    }
  else
    {
      n_deq = clib_min (n_deq, HTS_RX_BUF_SIZE);
      rv = svm_fifo_dequeue (ts->rx_fifo, n_deq, hs->rx_buf);
      ASSERT (rv == n_deq);
    }
  hs->left_recv -= n_deq;
  if (svm_fifo_needs_deq_ntf (ts->rx_fifo, n_deq))
    {
      svm_fifo_clear_deq_ntf (ts->rx_fifo);
      session_program_transport_io_evt (ts->handle, SESSION_IO_EVT_RX);
    }

  if (hs->close_threshold > 0)
    {
      if ((f64) (hs->total_recv - hs->left_recv) / hs->total_recv >
	  hs->close_threshold)
	hts_disconnect_transport (hs);
    }

  if (hs->left_recv == 0)
    {
      hts_start_send_data (hs, HTTP_STATUS_OK);
      vec_free (hs->rx_buf);
    }
}

static int
hts_ts_rx_callback (session_t *ts)
{
  hts_main_t *htm = &hts_main;
  hts_session_t *hs;
  u8 *target = 0;
  http_msg_t msg;
  int rv;

  hs = hts_session_get (ts->thread_index, ts->opaque);

  if (hs->left_recv == 0)
    {
      hs->data_len = 0;
      hs->rx_buf = 0;
      http_init_headers_ctx (&hs->resp_headers, hs->resp_headers_buf,
			     vec_len (hs->resp_headers_buf));
      /* Read the http message header */
      rv = svm_fifo_dequeue (ts->rx_fifo, sizeof (msg), (u8 *) &msg);
      ASSERT (rv == sizeof (msg));

      if (msg.type != HTTP_MSG_REQUEST)
	{
	  hts_start_send_data (hs, HTTP_STATUS_INTERNAL_ERROR);
	  goto done;
	}
      if (msg.method_type != HTTP_REQ_GET && msg.method_type != HTTP_REQ_POST)
	{
	  http_add_header (&hs->resp_headers, HTTP_HEADER_ALLOW,
			   http_token_lit ("GET, POST"));
	  hts_start_send_data (hs, HTTP_STATUS_METHOD_NOT_ALLOWED);
	  goto done;
	}

      if (msg.data.target_path_len == 0)
	{
	  hts_start_send_data (hs, HTTP_STATUS_BAD_REQUEST);
	  goto done;
	}

      vec_validate (target, msg.data.target_path_len - 1);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.target_path_offset,
			  msg.data.target_path_len, target);
      ASSERT (rv == msg.data.target_path_len);

      if (htm->debug_level)
	clib_warning ("%s request target: %v",
		      msg.method_type == HTTP_REQ_GET ? "GET" : "POST",
		      target);

      if (msg.method_type == HTTP_REQ_GET)
	{
	  if (try_test_file (hs, target))
	    hts_start_send_data (hs, HTTP_STATUS_NOT_FOUND);
	  vec_free (target);
	}
      else
	{
	  vec_free (target);
	  if (!msg.data.body_len)
	    {
	      hts_start_send_data (hs, HTTP_STATUS_BAD_REQUEST);
	      goto done;
	    }
	  /* drop everything up to body */
	  svm_fifo_dequeue_drop (ts->rx_fifo, msg.data.body_offset);
	  hs->left_recv = msg.data.body_len;
	  hs->total_recv = msg.data.body_len;
	  if (htm->no_zc)
	    vec_validate (hs->rx_buf, HTS_RX_BUF_SIZE - 1);
	  hts_session_rx_body (hs, ts);
	  return 0;
	}

    done:
      svm_fifo_dequeue_drop (ts->rx_fifo, msg.data.len);
    }
  else
    hts_session_rx_body (hs, ts);

  return 0;
}

static int
hs_ts_tx_callback (session_t *ts)
{
  hts_session_t *hs;

  clib_warning ("AAAAAAAAAA");
  hs = hts_session_get (ts->thread_index, ts->opaque);
  if (!hs)
    return 0;

  hts_session_tx (hs, ts);

  return 0;
}

static int
hts_ts_accept_callback (session_t *ts)
{
  hts_main_t *htm = &hts_main;
  hts_session_t *hs, *lhs;
  session_t *ls;

  hs = hts_session_alloc (ts->thread_index);
  hs->vpp_session_index = ts->session_index;
  hs->left_recv = 0;

  ts->opaque = hs->session_index;
  ts->session_state = SESSION_STATE_READY;

  /* Check if listener configured for random closes */
  ls = listen_session_get_from_handle (ts->listener_handle);
  lhs = hts_session_get (0, ls->opaque);

  if (lhs->close_rate)
    {
      /* overload listener's data_offset as session counter */
      u32 cnt = __atomic_add_fetch (&lhs->data_offset, 1, __ATOMIC_RELEASE);
      if ((cnt % lhs->close_rate) == 0)
	hs->close_threshold = random_f64 (&htm->seed);
    }

  if (htm->debug_level > 0)
    clib_warning ("Accepted session %u close threshold %.2f", ts->opaque,
		  hs->close_threshold);

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
hts_ts_disconnect_callback (session_t *ts)
{
  hts_main_t *htm = &hts_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  if (htm->debug_level > 0)
    clib_warning ("Transport closing session %u", ts->opaque);

  a->handle = session_handle (ts);
  a->app_index = htm->app_index;
  vnet_disconnect_session (a);
}

static void
hts_ts_reset_callback (session_t *ts)
{
  hts_main_t *htm = &hts_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  if (htm->debug_level > 0)
    clib_warning ("Transport reset session %u", ts->opaque);

  a->handle = session_handle (ts);
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
hts_start_listen (hts_main_t *htm, session_endpoint_cfg_t *sep, u8 *uri,
		  f64 rnd_close)
{
  vnet_listen_args_t _a, *a = &_a;
  u8 need_crypto;
  hts_session_t *hls;
  session_t *ls;
  clib_thread_index_t thread_index = 0;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->app_index = htm->app_index;

  need_crypto = hts_transport_needs_crypto (sep->transport_proto);

  sep->transport_proto = TRANSPORT_PROTO_HTTP;
  clib_memcpy (&a->sep_ext, sep, sizeof (*sep));

  if (need_crypto)
    {
      transport_endpt_ext_cfg_t *ext_cfg = session_endpoint_add_ext_cfg (
	&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
	sizeof (transport_endpt_crypto_cfg_t));
      ext_cfg->crypto.ckpair_index = htm->ckpair_index;
    }

  rv = vnet_listen (a);

  if (need_crypto)
    session_endpoint_free_ext_cfgs (&a->sep_ext);

  if (rv)
    return rv;

  hls = hts_session_alloc (thread_index);
  hls->uri = vec_dup (uri);
  hls->close_rate = (f64) 1 / rnd_close;
  ls = listen_session_get_from_handle (a->handle);
  hls->vpp_session_index = ls->session_index;
  hash_set_mem (htm->uri_to_handle, hls->uri, hls->session_index);

  /* opaque holds index of hls, which is used in `hts_ts_accept_callback`
   * to get back the pointer to hls */
  ls->opaque = hls - htm->sessions[thread_index];

  return 0;
}

static int
hts_stop_listen (hts_main_t *htm, u32 hls_index)
{
  hts_session_t *hls;
  session_t *ls;

  hls = hts_session_get (0, hls_index);
  ls = listen_session_get (hls->vpp_session_index);

  vnet_unlisten_args_t ua = {
    .handle = listen_session_get_handle (ls),
    .app_index = htm->app_index,
    .wrk_map_index = 0 /* default wrk */
  };

  hash_unset_mem (htm->uri_to_handle, hls->uri);

  if (vnet_unlisten (&ua))
    return -1;

  vec_free (hls->uri);
  hts_session_free (hls);

  return 0;
}

static clib_error_t *
hts_listen (hts_main_t *htm, hts_listen_cfg_t *lcfg)
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  clib_error_t *error = 0;
  u8 *uri, *uri_key;
  uword *p;
  int rv;

  uri = lcfg->uri ? lcfg->uri : htm->default_uri;
  uri_key = format (0, "vrf%u-%s", lcfg->vrf, uri);
  p = hash_get_mem (htm->uri_to_handle, uri_key);

  if (lcfg->is_del)
    {
      if (!p)
	error = clib_error_return (0, "not listening on %v", uri);
      else if (hts_stop_listen (htm, p[0]))
	error = clib_error_return (0, "failed to unlisten");
      goto done;
    }

  if (p)
    {
      error = clib_error_return (0, "already listening %v", uri);
      goto done;
    }

  if (parse_uri ((char *) uri, &sep))
    {
      error = clib_error_return (0, "failed to parse uri %v", uri);
      goto done;
    }

  if (lcfg->vrf)
    {
      fib_protocol_t fp;
      u32 fib_index;

      fp = sep.is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
      fib_index = fib_table_find (fp, lcfg->vrf);
      if (fib_index == ~0)
	{
	  error = clib_error_return (0, "no such vrf %u", lcfg->vrf);
	  goto done;
	}
      sep.fib_index = fib_index;
    }

  if ((rv = hts_start_listen (htm, &sep, uri_key, lcfg->rnd_close)))
    {
      error = clib_error_return (0, "failed to listen on %v: %U", uri,
				 format_session_error, rv);
    }

done:

  vec_free (uri_key);
  return error;
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

  htm->default_uri = format (0, "tcp://0.0.0.0/80%c", 0);
  htm->uri_to_handle = hash_create_vec (0, sizeof (u8), sizeof (uword));

  return 0;
}

static clib_error_t *
hts_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  hts_main_t *htm = &hts_main;
  hts_listen_cfg_t lcfg = {};
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
      else if (unformat (line_input, "no-zc"))
	htm->no_zc = 1;
      else if (unformat (line_input, "debug"))
	htm->debug_level = 1;
      else if (unformat (line_input, "vrf %u", &lcfg.vrf))
	;
      else if (unformat (line_input, "uri %s", &lcfg.uri))
	;
      else if (unformat (line_input, "rnd-close %f", &lcfg.rnd_close))
	{
	  if (lcfg.rnd_close > 1.0)
	    {
	      error = clib_error_return (0, "invalid rnd close value %f",
					 lcfg.rnd_close);
	      break;
	    }
	}
      else if (unformat (line_input, "del"))
	lcfg.is_del = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }

  unformat_free (line_input);

  if (error)
    goto done;

start_server:

  if (htm->app_index == (u32) ~0)
    {
      session_enable_disable_args_t args = { .is_en = 1,
					     .rt_engine_type =
					       RT_BACKEND_ENGINE_RULE_TABLE };
      vnet_session_enable_disable (vm, &args);

      if (hts_create (vm))
	{
	  error = clib_error_return (0, "http tps create failed");
	  goto done;
	}
    }

  error = hts_listen (htm, &lcfg);

done:

  vec_free (lcfg.uri);
  return error;
}

VLIB_CLI_COMMAND (http_tps_command, static) = {
  .path = "http tps",
  .short_help = "http tps [uri <uri>] [fifo-size <nbytes>] "
		"[segment-size <nMG>] [prealloc-fifos <n>] [debug] [no-zc] "
		"[del]",
  .function = hts_create_command_fn,
};

static clib_error_t *
hts_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  hts_main_t *htm = &hts_main;
  clib_error_t *error = 0;
  u8 do_listeners = 0;
  hts_session_t **sessions;
  u32 n_listeners = 0, n_sessions = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    goto no_input;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "listeners"))
	do_listeners = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }

  if (error)
    return error;

no_input:

  if (htm->app_index == ~0)
    {
      vlib_cli_output (vm, "http tps not enabled");
      goto done;
    }

  if (do_listeners)
    {
      uword handle;
      u8 *s = 0, *uri;

      /* clang-format off */
      hash_foreach (uri, handle, htm->uri_to_handle, ({
	s = format (s, "%-30v%lx\n", uri, handle);
      }));
      /* clang-format on */

      if (s)
	{
	  vlib_cli_output (vm, "%-29s%s", "URI", "Index");
	  vlib_cli_output (vm, "%v", s);
	  vec_free (s);
	}
      goto done;
    }

  n_listeners = hash_elts (htm->uri_to_handle);
  vec_foreach (sessions, htm->sessions)
    n_sessions += pool_elts (*sessions);

  vlib_cli_output (vm, " app index: %u\n listeners: %u\n sesions: %u",
		   htm->app_index, n_listeners, n_sessions - n_listeners);

done:
  return 0;
}

VLIB_CLI_COMMAND (show_http_tps_command, static) = {
  .path = "show http tps",
  .short_help = "http tps [listeners]",
  .function = hts_show_command_fn,
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
