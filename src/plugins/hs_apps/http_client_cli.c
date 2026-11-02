/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco and/or its affiliates.
 */

#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <http/http.h>
#include <http/http_content_types.h>
#include <http/http_status_codes.h>
#include <vppinfra/unix.h>

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
  u64 tx_offset;
  u8 have_reply;
  u8 is_closed;
  u8 tx_eof;
  u8 tx_pending;
  u8 rx_streaming;
  http_status_code_t status;
} hcc_session_t;

typedef struct
{
  u8 *name;
  u8 *value;
} hcc_header_t;

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
  u8 *body;
  u8 *headers_buf;
  u32 headers_len;
  hcc_header_t *custom_headers;
  http_req_method_t method;
  u8 use_ptr;
  u8 no_headers;
  u8 stream;
  u8 close_after_tx;
  u8 eof_after_drain;
  f64 tx_delay;
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
  HCC_REQUEST_FAILED,
  HCC_TX_READY,
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

static int
hcc_send_body (session_t *s, hcc_session_t *hs)
{
  hcc_main_t *hcm = &hcc_main;
  u64 left = vec_len (hcm->body) - hs->tx_offset;
  int rv;

  if (left)
    {
      rv = svm_fifo_enqueue (s->tx_fifo, left, hcm->body + hs->tx_offset);
      if (rv > 0)
	hs->tx_offset += rv;
      if (hs->tx_offset < vec_len (hcm->body))
	svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }

  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);

  if (hcm->stream && !hs->tx_eof && hs->tx_offset == vec_len (hcm->body))
    {
      if (hcm->eof_after_drain && svm_fifo_max_dequeue (s->tx_fifo))
	svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      else
	{
	  hs->tx_eof = 1;
	  if (hcm->close_after_tx)
	    {
	      vnet_disconnect_args_t a = { .handle = s->handle, .app_index = hcm->app_index };
	      vnet_disconnect_session (&a);
	    }
	  else
	    {
	      vnet_shutdown_args_t a = { .handle = s->handle, .app_index = hcm->app_index };
	      vnet_shutdown_session (&a);
	    }
	}
    }
  return 0;
}

static int
hcc_ts_connected_callback (u32 app_index, u32 hc_index, session_t *as, session_error_t err)
{
  hcc_main_t *hcm = &hcc_main;
  hcc_session_t *hs, *new_hs;
  hcc_worker_t *wrk;
  http_msg_t msg = {};
  u32 new_hs_index, n_segs, expected;
  uword target, headers, body;
  int rv;

  HCC_DBG ("ho hc_index: %d", hc_index);

  if (err)
    {
      clib_warning ("connected error: hc_index(%d): %U", hc_index, format_session_error, err);
      vlib_process_signal_event_mt (hcm->vlib_main, hcm->cli_node_index, HCC_CONNECT_FAILED, 0);
      return -1;
    }

  wrk = hcc_worker_get (as->thread_index);
  new_hs = hcc_session_alloc (wrk);
  new_hs_index = new_hs->session_index;
  /* Refetch hs after the alloc: hcc_session_alloc() may have grown and
   * reallocated the same pool that hs points into, invalidating it. */
  hs = hcc_session_get (hc_index, 0);
  clib_memcpy_fast (new_hs, hs, sizeof (*hs));
  new_hs->session_index = new_hs_index;
  new_hs->thread_index = as->thread_index;
  new_hs->vpp_session_index = as->session_index;
  HCC_DBG ("new hc_index: %d", new_hs->session_index);
  as->opaque = new_hs_index;

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = hcm->method;
  /* request target */
  msg.data.target_path_offset = 0;
  /* request target len must be without null termination */
  msg.data.target_path_len = strlen ((char *) hcm->http_query);
  /* custom headers */
  msg.data.headers_offset = msg.data.target_path_len;
  msg.data.headers_len = hcm->headers_len;
  /* request body */
  msg.data.body_len = hcm->stream ? 0 : vec_len (hcm->body);
  msg.data.body_offset = msg.data.headers_offset + msg.data.headers_len;
  /* data type and total length */
  msg.data.type = hcm->stream  ? HTTP_MSG_DATA_STREAMING :
		  hcm->use_ptr ? HTTP_MSG_DATA_PTR :
				 HTTP_MSG_DATA_INLINE;
  msg.data.len = msg.data.target_path_len + msg.data.headers_len + msg.data.body_len;

  svm_fifo_seg_t segs[4] = { { (u8 *) &msg, sizeof (msg) } };
  n_segs = 1;
  expected = sizeof (msg);
  if (hcm->use_ptr)
    {
      target = pointer_to_uword (hcm->http_query);
      headers = pointer_to_uword (hcm->headers_buf);
      body = pointer_to_uword (hcm->body);
      segs[n_segs++] = (svm_fifo_seg_t) { (u8 *) &target, sizeof (target) };
      if (msg.data.headers_len)
	segs[n_segs++] = (svm_fifo_seg_t) { (u8 *) &headers, sizeof (headers) };
      if (msg.data.body_len)
	segs[n_segs++] = (svm_fifo_seg_t) { (u8 *) &body, sizeof (body) };
      expected += (n_segs - 1) * sizeof (uword);
    }
  else
    {
      segs[n_segs++] = (svm_fifo_seg_t) { hcm->http_query, msg.data.target_path_len };
      if (msg.data.headers_len)
	segs[n_segs++] = (svm_fifo_seg_t) { hcm->headers_buf, msg.data.headers_len };
      expected += msg.data.target_path_len + msg.data.headers_len;
    }

  rv = svm_fifo_enqueue_segments (as->tx_fifo, segs, n_segs, 0 /* allow partial */);
  if (rv != expected)
    {
      clib_warning ("failed app enqueue");
      new_hs->is_closed = 1;
      vlib_process_signal_event_mt (hcm->vlib_main, hcm->cli_node_index, HCC_REQUEST_FAILED, 0);
      return -1;
    }

  if (hcm->use_ptr)
    new_hs->tx_offset = vec_len (hcm->body);
  return hcc_send_body (as, new_hs);
}

static void
hcc_ts_reset_callback (session_t *s)
{
  hcc_main_t *hcm = &hcc_main;
  hcc_session_t *hs;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  hs = hcc_session_get (s->opaque, s->thread_index);
  if (!hs->is_closed)
    vlib_process_signal_event_mt (hcm->vlib_main, hcm->cli_node_index, HCC_TRANSPORT_CLOSED, 0);
  hs->is_closed = 1;

  a->handle = session_handle (s);
  a->app_index = hcm->app_index;
  vnet_disconnect_session (a);
}

static int
hcc_ts_tx_callback (session_t *ts)
{
  hcc_main_t *hcm = &hcc_main;
  hcc_session_t *hs = hcc_session_get (ts->opaque, ts->thread_index);
  if (hs->is_closed || hs->tx_eof)
    return 0;
  if (hcm->tx_delay)
    {
      if (!hs->tx_pending)
	{
	  hs->tx_pending = 1;
	  vlib_process_signal_event_mt (hcm->vlib_main, hcm->cli_node_index, HCC_TX_READY,
					ts->handle);
	}
      return 0;
    }
  return hcc_send_body (ts, hs);
}

static void
hcc_send_body_rpc (void *arg)
{
  session_t *s = session_get_from_handle_if_valid (pointer_to_uword (arg));
  hcc_session_t *hs;

  if (!s || s->app_wrk_index == APP_INVALID_INDEX)
    return;
  hs = hcc_session_get (s->opaque, s->thread_index);
  hs->tx_pending = 0;
  if (!hs->is_closed && !hs->tx_eof)
    hcc_send_body (s, hs);
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

static void
hcc_response_complete (session_t *s, hcc_session_t *hs)
{
  hcc_main_t *hcm = &hcc_main;

  if (!vec_len (hcm->http_response) && hs->status != HTTP_STATUS_OK)
    hcm->http_response = format (hcm->http_response, "request failed, response code: %U",
				 format_http_status_code, hs->status);
  hs->is_closed = 1;
  HCC_DBG ("all data received, going to disconnect");
  hcc_session_disconnect (s);
  vlib_process_signal_event_mt (hcm->vlib_main, hcm->cli_node_index, HCC_REPLY_RECEIVED, 0);
}

static void
hcc_ts_disconnect_callback (session_t *s)
{
  hcc_main_t *hcm = &hcc_main;
  hcc_session_t *hs = hcc_session_get (s->opaque, s->thread_index);
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  if (hs->rx_streaming)
    {
      hcc_response_complete (s, hs);
      return;
    }
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

  if (!hs->have_reply)
    {
      if (!svm_fifo_max_dequeue (ts->rx_fifo))
	return 0;
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
      hs->have_reply = 1;
      hs->tx_eof = 1;
      hs->rx_streaming = msg.data.type == HTTP_MSG_DATA_STREAMING;
      hs->status = msg.code;
      vec_reset_length (hcm->http_response);
    }

  u32 max_deq = svm_fifo_max_dequeue (ts->rx_fifo);
  if (!max_deq)
    goto done;

  u32 n_deq = hs->rx_streaming ? max_deq : clib_min (hs->to_recv, max_deq);
  u8 *data;
  vec_add2 (hcm->http_response, data, n_deq);
  rv = svm_fifo_dequeue (ts->rx_fifo, n_deq, data);
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

  if (!hs->rx_streaming)
    {
      ASSERT (hs->to_recv >= rv);
      hs->to_recv -= rv;
    }
  HCC_DBG ("app rcvd %d, remains %llu", rv, hs->to_recv);

done:
  if (!hs->rx_streaming && hs->to_recv == 0)
    hcc_response_complete (ts, hs);

  return 0;
}

static void
hcc_ts_transport_closed (session_t *s)
{
  hcc_main_t *hcm = &hcc_main;
  hcc_session_t *hs = hcc_session_get (s->opaque, s->thread_index);

  HCC_DBG ("transport closed");

  if (!hs->is_closed)
    {
      hs->is_closed = 1;
      vlib_process_signal_event_mt (hcm->vlib_main, hcm->cli_node_index, HCC_TRANSPORT_CLOSED, 0);
    }
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
  hcc_main_t *hcm = &hcc_main;
  vnet_connect_args_t *a = rpc_args;
  int rv;

  rv = vnet_connect (a);
  if (rv)
    {
      clib_warning ("connect returned: %U", format_session_error, rv);
      hcc_ho_session_free (a->api_context);
      vlib_process_signal_event_mt (hcm->vlib_main, hcm->cli_node_index, HCC_CONNECT_FAILED, 0);
    }

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

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 10);
      event_type = vlib_process_get_events (vm, &event_data);
      if (event_type != HCC_TX_READY)
	break;
      vlib_process_suspend (vm, hcm->tx_delay);
      for (u32 i = 0; i < vec_len (event_data); i++)
	session_send_rpc_evt_to_thread_force (session_thread_from_handle (event_data[i]),
					      hcc_send_body_rpc,
					      uword_to_pointer (event_data[i], void *));
      vec_reset_length (event_data);
    }
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
    case HCC_REQUEST_FAILED:
      err = clib_error_return (0, "request metadata does not fit in TX FIFO");
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
  vnet_app_del_cert_key_pair (hcm->ckpair_index);

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
  hcc_header_t *header;

  vec_foreach (wrk, hcm->wrk)
    hcc_worker_cleanup (wrk);

  vec_free (hcm->uri);
  vec_free (hcm->http_query);
  vec_free (hcm->http_response);
  vec_free (hcm->appns_id);
  vec_free (hcm->wrk);
  vec_free (hcm->body);
  vec_free (hcm->headers_buf);
  vec_foreach (header, hcm->custom_headers)
    {
      vec_free (header->name);
      vec_free (header->value);
    }
  vec_free (hcm->custom_headers);
}

static clib_error_t *
hcc_command_fn (vlib_main_t *vm, unformat_input_t *input,
		vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  hcc_main_t *hcm = &hcc_main;
  u64 seg_size;
  u8 *appns_id = 0;
  u8 *path = 0, *name = 0, *value = 0;
  hcc_header_t *header;
  http_headers_ctx_t headers;
  u32 headers_size = 64;
  clib_error_t *err = 0;
  int rv, print_output = 1;

  if (hcm->test_client_attached)
    return clib_error_return (0, "failed: already running!");

  hcm->prealloc_fifos = 0;
  hcm->private_segment_size = 0;
  hcm->fifo_size = 0;
  hcm->use_http3 = 0;
  hcm->method = HTTP_REQ_GET;
  hcm->use_ptr = 0;
  hcm->no_headers = 0;
  hcm->stream = 0;
  hcm->close_after_tx = 0;
  hcm->eof_after_drain = 0;
  hcm->tx_delay = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected URI");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "prealloc-fifos %d", &hcm->prealloc_fifos))
	;
      else if (unformat (line_input, "private-segment-size %U", unformat_memory_size, &seg_size))
	hcm->private_segment_size = seg_size;
      else if (unformat (line_input, "fifo-size %d", &hcm->fifo_size))
	hcm->fifo_size <<= 10;
      else if (unformat (line_input, "uri %s", &hcm->uri))
	;
      else if (unformat (line_input, "method get"))
	hcm->method = HTTP_REQ_GET;
      else if (unformat (line_input, "method post"))
	hcm->method = HTTP_REQ_POST;
      else if (unformat (line_input, "method put"))
	hcm->method = HTTP_REQ_PUT;
      else if (unformat (line_input, "data %v", &hcm->body))
	;
      else if (unformat (line_input, "file %s", &path))
	;
      else if (unformat (line_input, "use-ptr"))
	hcm->use_ptr = 1;
      else if (unformat (line_input, "stream"))
	hcm->stream = 1;
      else if (unformat (line_input, "close-after-tx"))
	hcm->close_after_tx = 1;
      else if (unformat (line_input, "eof-after-drain"))
	hcm->eof_after_drain = 1;
      else if (unformat (line_input, "tx-delay %f", &hcm->tx_delay))
	;
      else if (unformat (line_input, "no-headers"))
	hcm->no_headers = 1;
      else if (unformat (line_input, "header %v:%v", &name, &value))
	{
	  vec_add2 (hcm->custom_headers, header, 1);
	  header->name = name;
	  header->value = value;
	}
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

  if ((hcm->stream && (hcm->use_ptr || hcm->use_http3)) || hcm->tx_delay < 0 ||
      ((hcm->close_after_tx || hcm->eof_after_drain || hcm->tx_delay) && !hcm->stream))
    {
      err = clib_error_return (0, "stream requires inline HTTP/1 data; TX controls require stream");
      goto done;
    }

  if (!hcm->uri)
    {
      err = clib_error_return (0, "URI not defined");
      goto done;
    }

  if (path)
    {
      if (hcm->body)
	{
	  err = clib_error_return (0, "use either data or file");
	  goto done;
	}
      err = clib_file_contents ((char *) path, &hcm->body);
      if (err)
	goto done;
    }

  vec_foreach (header, hcm->custom_headers)
    headers_size +=
      2 * sizeof (http_custom_token_t) + vec_len (header->name) + vec_len (header->value);
  vec_validate (hcm->headers_buf, headers_size - 1);
  http_init_headers_ctx (&headers, hcm->headers_buf, vec_len (hcm->headers_buf));
  if (!hcm->no_headers)
    http_add_header (&headers, HTTP_HEADER_ACCEPT,
		     http_content_type_token (HTTP_CONTENT_TEXT_HTML));
  vec_foreach (header, hcm->custom_headers)
    http_add_custom_header (&headers, (char *) header->name, vec_len (header->name),
			    (char *) header->value, vec_len (header->value));
  hcm->headers_len = headers.tail_offset;

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
  vec_free (path);
  hcc_cleanup ();
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (hcc_command, static) = {
  .path = "http cli client",
  .short_help = "[appns <app-ns> secret <appns-secret>] uri http[s]://<ip-addr>/<target> "
		"[method get|post|put] [data <payload> | file <path>] [use-ptr] "
		"[stream [close-after-tx] [eof-after-drain] [tx-delay <seconds>]] "
		"[header <Name:Value>] [no-headers] [fifo-size <KiB>] [no-output] [http3]",
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
