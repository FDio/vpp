/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco and/or its affiliates.
 */

#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <http/http.h>
#include <http/http_content_types.h>
#include <http/http_status_codes.h>

#define HCC_DEBUG 0

#if HCC_DEBUG
#define HCC_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define HCC_DBG(_fmt, _args...)
#endif

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 session_index;
  clib_thread_index_t thread_index;
  u32 rx_offset;
  u32 vpp_session_index;
  u64 to_recv;
  u8 is_closed;
} hcc_session_t;

typedef struct
{
  hcc_session_t *sessions;
  clib_thread_index_t thread_index;
} hcc_worker_t;

typedef struct
{
  hcc_worker_t *wrk;
  u32 app_index;

  u32 prealloc_fifos;
  u32 private_segment_size;
  u32 fifo_size;
  u8 *uri;
  u8 *http_query;
  session_endpoint_cfg_t connect_sep;

  u8 test_client_attached;
  vlib_main_t *vlib_main;
  u32 cli_node_index;
  u8 *http_response;
  u8 *appns_id;
  u64 appns_secret;
  u32 ckpair_index;
  u8 need_crypto;
  u8 use_http3;
} hcc_main_t;

typedef enum
{
  HCC_REPLY_RECEIVED = 100,
  HCC_TRANSPORT_CLOSED,
  HCC_CONNECT_FAILED,
} hcc_cli_signal_t;

static hcc_main_t hcc_main;

static hcc_worker_t *
hcc_worker_get (clib_thread_index_t thread_index)
{
  return vec_elt_at_index (hcc_main.wrk, thread_index);
}

static hcc_session_t *
hcc_session_alloc (hcc_worker_t *wrk)
{
  hcc_session_t *hs;
  pool_get_zero (wrk->sessions, hs);
  hs->session_index = hs - wrk->sessions;
  hs->thread_index = wrk->thread_index;
  return hs;
}

static hcc_session_t *
hcc_session_get (u32 hs_index, clib_thread_index_t thread_index)
{
  hcc_worker_t *wrk = hcc_worker_get (thread_index);
  return pool_elt_at_index (wrk->sessions, hs_index);
}

static void
hcc_ho_session_free (u32 hs_index)
{
  hcc_worker_t *wrk = hcc_worker_get (0);
  pool_put_index (wrk->sessions, hs_index);
}

static int
hcc_ts_accept_callback (session_t *ts)
{
  clib_warning ("bug");
  return -1;
}

static void
hcc_ts_disconnect_callback (session_t *s)
{
  hcc_main_t *hcm = &hcc_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = hcm->app_index;
  vnet_disconnect_session (a);
}

static int
hcc_ts_connected_callback (u32 app_index, u32 hc_index, session_t *as,
			   session_error_t err)
{
  hcc_main_t *hcm = &hcc_main;
  hcc_session_t *hs, *new_hs;
  hcc_worker_t *wrk;
  http_msg_t msg;
  u8 *headers_buf = 0;
  u32 new_hs_index;
  int rv;
  http_headers_ctx_t headers;

  HCC_DBG ("ho hc_index: %d", hc_index);

  if (err)
    {
      clib_warning ("connected error: hc_index(%d): %U", hc_index,
		    format_session_error, err);
      vlib_process_signal_event_mt (hcm->vlib_main, hcm->cli_node_index,
				    HCC_CONNECT_FAILED, 0);
      return -1;
    }

  hs = hcc_session_get (hc_index, 0);
  wrk = hcc_worker_get (as->thread_index);
  new_hs = hcc_session_alloc (wrk);
  new_hs_index = new_hs->session_index;
  clib_memcpy_fast (new_hs, hs, sizeof (*hs));
  new_hs->session_index = new_hs_index;
  new_hs->thread_index = as->thread_index;
  new_hs->vpp_session_index = as->session_index;
  HCC_DBG ("new hc_index: %d", new_hs->session_index);
  as->opaque = new_hs_index;

  vec_validate (headers_buf, 63);
  http_init_headers_ctx (&headers, headers_buf, vec_len (headers_buf));
  http_add_header (&headers, HTTP_HEADER_ACCEPT,
		   http_content_type_token (HTTP_CONTENT_TEXT_HTML));

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = HTTP_REQ_GET;
  /* request target */
  msg.data.target_path_offset = 0;
  /* request target len must be without null termination */
  msg.data.target_path_len = strlen ((char *) hcm->http_query);
  /* custom headers */
  msg.data.headers_offset = msg.data.target_path_len;
  msg.data.headers_len = headers.tail_offset;
  /* request body */
  msg.data.body_len = 0;
  /* data type and total length */
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len =
    msg.data.target_path_len + msg.data.headers_len + msg.data.body_len;

  svm_fifo_seg_t segs[3] = { { (u8 *) &msg, sizeof (msg) },
			     { hcm->http_query, msg.data.target_path_len },
			     { headers_buf, msg.data.headers_len } };

  rv = svm_fifo_enqueue_segments (as->tx_fifo, segs, 3, 0 /* allow partial */);
  vec_free (headers_buf);
  if (rv < 0 || rv != sizeof (msg) + msg.data.len)
    {
      clib_warning ("failed app enqueue");
      return -1;
    }

  if (svm_fifo_set_event (as->tx_fifo))
    session_program_tx_io_evt (as->handle, SESSION_IO_EVT_TX);

  return 0;
}

static void
hcc_ts_reset_callback (session_t *s)
{
  hcc_main_t *hcm = &hcc_main;
  hcc_session_t *hs;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  hs = hcc_session_get (s->opaque, s->thread_index);
  hs->is_closed = 1;

  a->handle = session_handle (s);
  a->app_index = hcm->app_index;
  vnet_disconnect_session (a);
}

static int
hcc_ts_tx_callback (session_t *ts)
{
  clib_warning ("bug");
  return -1;
}

static void
hcc_session_disconnect (session_t *s)
{
  hcc_main_t *hcm = &hcc_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  a->handle = session_handle (s);
  a->app_index = hcm->app_index;
  vnet_disconnect_session (a);
}

static int
hcc_ts_rx_callback (session_t *ts)
{
  hcc_main_t *hcm = &hcc_main;
  hcc_session_t *hs;
  http_msg_t msg;
  int rv;

  hs = hcc_session_get (ts->opaque, ts->thread_index);

  if (hs->is_closed)
    {
      clib_warning ("session is closed");
      return 0;
    }

  if (hs->to_recv == 0)
    {
      /* read the http message header */
      rv = svm_fifo_dequeue (ts->rx_fifo, sizeof (msg), (u8 *) &msg);
      ASSERT (rv == sizeof (msg));

      if (msg.type != HTTP_MSG_REPLY)
	{
	  clib_warning ("unexpected msg type %d", msg.type);
	  return 0;
	}
      /* drop everything up to body */
      svm_fifo_dequeue_drop (ts->rx_fifo, msg.data.body_offset);
      hs->to_recv = msg.data.body_len;
      if (msg.code != HTTP_STATUS_OK && hs->to_recv == 0)
	{
	  hcm->http_response = format (0, "request failed, response code: %U",
				       format_http_status_code, msg.code);
	  goto done;
	}
      vec_validate (hcm->http_response, msg.data.body_len - 1);
      vec_reset_length (hcm->http_response);
    }

  u32 max_deq = svm_fifo_max_dequeue (ts->rx_fifo);
  if (!max_deq)
    goto done;

  u32 n_deq = clib_min (hs->to_recv, max_deq);
  u64 curr = vec_len (hcm->http_response);
  rv = svm_fifo_dequeue (ts->rx_fifo, n_deq, hcm->http_response + curr);
  if (rv < 0)
    {
      clib_warning ("app dequeue(n=%d) failed; rv = %d", n_deq, rv);
      return -1;
    }

  if (rv != n_deq)
    return -1;

  if (svm_fifo_needs_deq_ntf (ts->rx_fifo, n_deq))
    {
      svm_fifo_clear_deq_ntf (ts->rx_fifo);
      session_program_transport_io_evt (ts->handle, SESSION_IO_EVT_RX);
    }

  vec_set_len (hcm->http_response, curr + n_deq);
  ASSERT (hs->to_recv >= rv);
  hs->to_recv -= rv;
  HCC_DBG ("app rcvd %d, remains %llu", rv, hs->to_recv);

done:
  if (hs->to_recv == 0)
    {
      HCC_DBG ("all data received, going to disconnect");
      hcc_session_disconnect (ts);
      vlib_process_signal_event_mt (hcm->vlib_main, hcm->cli_node_index,
				    HCC_REPLY_RECEIVED, 0);
    }

  return 0;
}

static void
hcc_ts_transport_closed (session_t *s)
{
  hcc_main_t *hcm = &hcc_main;

  HCC_DBG ("transport closed");

  vlib_process_signal_event_mt (hcm->vlib_main, hcm->cli_node_index,
				HCC_TRANSPORT_CLOSED, 0);
}

static void
hcc_ho_cleanup_callback (session_t *ts)
{
  HCC_DBG ("ho hc_index: %d:", ts->opaque);
  hcc_ho_session_free (ts->opaque);
}

static int
hcc_add_segment_callback (u32 app_index, u64 segment_handle)
{
  return 0;
}

static int
hcc_del_segment_callback (u32 app_index, u64 segment_handle)
{
  return 0;
}

static session_cb_vft_t hcc_session_cb_vft = {
  .session_accept_callback = hcc_ts_accept_callback,
  .session_disconnect_callback = hcc_ts_disconnect_callback,
  .session_connected_callback = hcc_ts_connected_callback,
  .builtin_app_rx_callback = hcc_ts_rx_callback,
  .builtin_app_tx_callback = hcc_ts_tx_callback,
  .session_reset_callback = hcc_ts_reset_callback,
  .session_transport_closed_callback = hcc_ts_transport_closed,
  .half_open_cleanup_callback = hcc_ho_cleanup_callback,
  .add_segment_callback = hcc_add_segment_callback,
  .del_segment_callback = hcc_del_segment_callback,
};

static clib_error_t *
hcc_attach ()
{
  hcc_main_t *hcm = &hcc_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[18];
  u32 segment_size = 128 << 20;
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  int rv;

  if (hcm->private_segment_size)
    segment_size = hcm->private_segment_size;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = ~0;
  a->name = format (0, "http_cli_client");
  a->session_cb_vft = &hcc_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] =
    hcm->fifo_size ? hcm->fifo_size : 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] =
    hcm->fifo_size ? hcm->fifo_size : 32 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = hcm->prealloc_fifos;
  a->options[APP_OPTIONS_TLS_ENGINE] = CRYPTO_ENGINE_OPENSSL;
  if (hcm->appns_id)
    {
      a->namespace_id = hcm->appns_id;
      a->options[APP_OPTIONS_NAMESPACE_SECRET] = hcm->appns_secret;
    }

  if ((rv = vnet_application_attach (a)))
    return clib_error_return (0, "attach returned %d", rv);

  hcm->app_index = a->app_index;
  vec_free (a->name);
  hcm->test_client_attached = 1;

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
hcc_connect_rpc (void *rpc_args)
{
  vnet_connect_args_t *a = rpc_args;
  int rv;

  rv = vnet_connect (a);
  if (rv)
    clib_warning ("connect returned: %U", format_session_error, rv);

  session_endpoint_free_ext_cfgs (&a->sep_ext);
  vec_free (a);
  return rv;
}

static void
hcc_program_connect (vnet_connect_args_t *a)
{
  session_send_rpc_evt_to_thread_force (transport_cl_thread (),
					hcc_connect_rpc, a);
}

static clib_error_t *
hcc_connect ()
{
  vnet_connect_args_t *a = 0;
  hcc_main_t *hcm = &hcc_main;
  hcc_worker_t *wrk;
  hcc_session_t *hs;
  transport_endpt_ext_cfg_t *ext_cfg;

  vec_validate (a, 0);
  clib_memset (a, 0, sizeof (a[0]));

  clib_memcpy (&a->sep_ext, &hcm->connect_sep, sizeof (hcm->connect_sep));
  a->app_index = hcm->app_index;

  /* set http (response) timeout to 10 seconds */
  transport_endpt_cfg_http_t http_cfg = { 10, 0 };
  ext_cfg = session_endpoint_add_ext_cfg (
    &a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (http_cfg));
  clib_memcpy (ext_cfg->data, &http_cfg, sizeof (http_cfg));

  if (hcm->need_crypto)
    {
      ext_cfg = session_endpoint_add_ext_cfg (
	&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
	sizeof (transport_endpt_crypto_cfg_t));
      ext_cfg->crypto.ckpair_index = hcm->ckpair_index;
      if (hcm->use_http3)
	ext_cfg->crypto.alpn_protos[0] = TLS_ALPN_PROTO_HTTP_3;
    }

  /* allocate http session on main thread */
  wrk = hcc_worker_get (0);
  hs = hcc_session_alloc (wrk);
  a->api_context = hs->session_index;

  hcc_program_connect (a);
  return 0;
}

static clib_error_t *
hcc_run (vlib_main_t *vm, int print_output)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  hcc_main_t *hcm = &hcc_main;
  uword event_type, *event_data = 0;
  u32 num_threads;
  clib_error_t *err = 0;
  hcc_worker_t *wrk;

  num_threads = 1 /* main thread */ + vtm->n_threads;
  vec_validate (hcm->wrk, num_threads - 1);
  vec_foreach (wrk, hcm->wrk)
    {
      wrk->thread_index = wrk - hcm->wrk;
    }

  if ((err = hcc_attach ()))
    {
      return clib_error_return (0, "http client attach: %U", format_clib_error,
				err);
    }

  if ((err = hcc_connect ()))
    {
      return clib_error_return (0, "http client connect: %U",
				format_clib_error, err);
    }

  vlib_process_wait_for_event_or_clock (vm, 10);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      err = clib_error_return (0, "timeout");
      goto cleanup;

    case HCC_REPLY_RECEIVED:
      if (print_output)
	vlib_cli_output (vm, "%v", hcm->http_response);
      break;
    case HCC_TRANSPORT_CLOSED:
      err = clib_error_return (0, "error, transport closed");
      break;
    case HCC_CONNECT_FAILED:
      err = clib_error_return (0, "failed to connect");
      break;
    default:
      err = clib_error_return (0, "unexpected event %d", event_type);
      break;
    }

cleanup:
  vec_free (event_data);
  return err;
}

static int
hcc_detach ()
{
  hcc_main_t *hcm = &hcc_main;
  vnet_app_detach_args_t _da, *da = &_da;
  int rv;

  if (!hcm->test_client_attached)
    return 0;

  da->app_index = hcm->app_index;
  da->api_client_index = ~0;
  rv = vnet_application_detach (da);
  hcm->test_client_attached = 0;
  hcm->app_index = ~0;

  return rv;
}

static void
hcc_worker_cleanup (hcc_worker_t *wrk)
{
  pool_free (wrk->sessions);
}

static void
hcc_cleanup ()
{
  hcc_main_t *hcm = &hcc_main;
  hcc_worker_t *wrk;

  vec_foreach (wrk, hcm->wrk)
    hcc_worker_cleanup (wrk);

  vec_free (hcm->uri);
  vec_free (hcm->http_query);
  vec_free (hcm->http_response);
  vec_free (hcm->appns_id);
  vec_free (hcm->wrk);
}

static clib_error_t *
hcc_command_fn (vlib_main_t *vm, unformat_input_t *input,
		vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  hcc_main_t *hcm = &hcc_main;
  u64 seg_size;
  u8 *appns_id = 0;
  clib_error_t *err = 0;
  int rv, print_output = 1;

  hcm->prealloc_fifos = 0;
  hcm->private_segment_size = 0;
  hcm->fifo_size = 0;
  hcm->use_http3 = 0;

  if (hcm->test_client_attached)
    return clib_error_return (0, "failed: already running!");

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected URI");

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
      else if (unformat (line_input, "no-output"))
	print_output = 0;
      else if (unformat (line_input, "appns %_%v%_", &appns_id))
	;
      else if (unformat (line_input, "secret %lu", &hcm->appns_secret))
	;
      else if (unformat (line_input, "http3"))
	hcm->use_http3 = 1;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  hcm->appns_id = appns_id;
  hcm->cli_node_index = vlib_get_current_process (vm)->node_runtime.node_index;

  if (!hcm->uri)
    {
      err = clib_error_return (0, "URI not defined");
      goto done;
    }

  if ((rv = parse_target ((char **) &hcm->uri, (char **) &hcm->http_query)))
    {
      err = clib_error_return (0, "target parse error: %U",
			       format_session_error, rv);
      goto done;
    }

  if ((rv = parse_uri ((char *) hcm->uri, &hcm->connect_sep)))
    {
      err = clib_error_return (0, "Uri parse error: %d", rv);
      goto done;
    }
  hcm->need_crypto = hcm->connect_sep.flags & SESSION_ENDPT_CFG_F_SECURE;

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, &args);
  vlib_worker_thread_barrier_release (vm);

  err = hcc_run (vm, print_output);

  if (hcc_detach ())
    {
      /* don't override last error */
      if (!err)
	err = clib_error_return (0, "failed: app detach");
      clib_warning ("WARNING: app detach failed...");
    }

done:
  hcc_cleanup ();
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (hcc_command, static) = {
  .path = "http cli client",
  .short_help =
    "[appns <app-ns> secret <appns-secret>] uri http[s]://<ip-addr>/<target> "
    "[no-output] [http3]",
  .function = hcc_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
hcc_main_init (vlib_main_t *vm)
{
  hcc_main_t *hcm = &hcc_main;
  session_endpoint_cfg_t sep_null = SESSION_ENDPOINT_CFG_NULL;

  hcm->app_index = ~0;
  hcm->vlib_main = vm;
  hcm->connect_sep = sep_null;
  return 0;
}

VLIB_INIT_FUNCTION (hcc_main_init);
