/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <http/http.h>
#include <http/http_content_types.h>
#include <http/http_status_codes.h>
#include <vppinfra/unix.h>

typedef struct
{
  u64 req_per_wrk;
  u64 request_count;
  f64 start, end;
  f64 elapsed_time;
} hc_stats_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 session_index;
  clib_thread_index_t thread_index;
  u64 to_recv;
  u8 is_closed;
  hc_stats_t stats;
  u64 data_offset;
  u8 *resp_headers;
  u8 *http_response;
  u8 *response_status;
} hc_session_t;

typedef struct
{
  hc_session_t *sessions;
  clib_thread_index_t thread_index;
  vlib_main_t *vlib_main;
  u8 *headers_buf;
  http_headers_ctx_t req_headers;
  http_msg_t msg;
  u32 session_index;
  bool has_common_headers;
} hc_worker_t;

typedef struct
{
  u8 *name;
  u8 *value;
} hc_http_header_t;

typedef struct
{
  u32 app_index;
  u32 cli_node_index;
  u8 attached;
  u8 *uri;
  session_endpoint_cfg_t connect_sep;
  u8 *target;
  u8 *data;
  hc_worker_t *wrk;
  hc_http_header_t *custom_header;
  u8 is_file;
  u8 use_ptr;
  u8 *filename;
  bool verbose;
  f64 timeout;
  http_req_method_t req_method;
  u64 repeat_count;
  f64 duration;
  bool repeat;
  bool multi_session;
  u32 done_count;
  u32 connected_counter;
  u32 worker_index;
  u32 max_sessions;
  u32 private_segment_size;
  u32 prealloc_fifos;
  u32 fifo_size;
  u8 *appns_id;
  u64 appns_secret;
  clib_spinlock_t lock;
  bool was_transport_closed;
  u32 ckpair_index;
} hc_main_t;

typedef enum
{
  HC_CONNECT_FAILED = 1,
  HC_TRANSPORT_CLOSED,
  HC_REPLY_RECEIVED,
  HC_GENERIC_ERR,
  HC_REPEAT_DONE,
} hc_cli_signal_t;

static hc_main_t hc_main;
static hc_stats_t hc_stats;

static inline hc_worker_t *
hc_worker_get (clib_thread_index_t thread_index)
{
  return &hc_main.wrk[thread_index];
}

static inline hc_session_t *
hc_session_get (u32 session_index, clib_thread_index_t thread_index)
{
  hc_worker_t *wrk = hc_worker_get (thread_index);
  wrk->vlib_main = vlib_get_main_by_index (thread_index);
  return pool_elt_at_index (wrk->sessions, session_index);
}

static hc_session_t *
hc_session_alloc (hc_worker_t *wrk)
{
  hc_session_t *s;

  pool_get_zero (wrk->sessions, s);
  s->session_index = s - wrk->sessions;
  s->thread_index = wrk->thread_index;

  return s;
}

static int
hc_request (session_t *s, hc_worker_t *wrk, hc_session_t *hc_session,
	    session_error_t err)
{
  hc_main_t *hcm = &hc_main;
  u64 to_send;
  u32 n_enq;
  u8 n_segs;
  int rv;

  if (hcm->use_ptr)
    {
      uword target = pointer_to_uword (hcm->target);
      uword headers = pointer_to_uword (wrk->headers_buf);
      uword body = pointer_to_uword (hcm->data);
      svm_fifo_seg_t segs[4] = {
	{ (u8 *) &wrk->msg, sizeof (wrk->msg) },
	{ (u8 *) &target, sizeof (target) },
	{ (u8 *) &headers, sizeof (headers) },
	{ (u8 *) &body, sizeof (body) },
      };

      n_segs = (hcm->req_method == HTTP_REQ_GET) ? 3 : 4;
      rv = svm_fifo_enqueue_segments (s->tx_fifo, segs, n_segs,
				      0 /* allow partial */);
      if (hcm->req_method == HTTP_REQ_POST)
	ASSERT (rv == (sizeof (wrk->msg) + sizeof (target) + sizeof (headers) +
		       sizeof (body)));
      else
	ASSERT (rv ==
		(sizeof (wrk->msg) + sizeof (target) + sizeof (headers)));
      goto done;
    }

  rv = svm_fifo_enqueue (s->tx_fifo, sizeof (wrk->msg), (u8 *) &wrk->msg);
  ASSERT (rv == sizeof (wrk->msg));

  rv = svm_fifo_enqueue (s->tx_fifo, vec_len (hcm->target), hcm->target);
  ASSERT (rv == vec_len (hcm->target));

  rv = svm_fifo_enqueue (s->tx_fifo, wrk->req_headers.tail_offset,
			 wrk->headers_buf);
  ASSERT (rv == wrk->req_headers.tail_offset);

  if (hcm->req_method == HTTP_REQ_POST)
    {
      to_send = vec_len (hcm->data);
      n_enq = clib_min (svm_fifo_size (s->tx_fifo), to_send);

      rv = svm_fifo_enqueue (s->tx_fifo, n_enq, hcm->data);
      if (rv < to_send)
	{
	  hc_session->data_offset = (rv > 0) ? rv : 0;
	  svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
	}
    }

done:
  if (svm_fifo_set_event (s->tx_fifo))
    {
      session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
    }
  return 0;
}

static int
hc_session_connected_callback (u32 app_index, u32 hc_session_index,
			       session_t *s, session_error_t err)
{
  hc_main_t *hcm = &hc_main;
  hc_worker_t *wrk;
  hc_session_t *hc_session;
  hc_http_header_t *header;

  if (err)
    {
      clib_warning ("hc_session_index[%d] connected error: %U",
		    hc_session_index, format_session_error, err);
      vlib_process_signal_event_mt (vlib_get_main (), hcm->cli_node_index,
				    HC_CONNECT_FAILED, 0);
      return -1;
    }

  wrk = hc_worker_get (s->thread_index);
  hc_session = hc_session_alloc (wrk);
  clib_spinlock_lock_if_init (&hcm->lock);
  hcm->connected_counter++;
  clib_spinlock_unlock_if_init (&hcm->lock);

  hc_session->thread_index = s->thread_index;
  s->opaque = hc_session->session_index;
  wrk->session_index = hc_session->session_index;

  if (hcm->multi_session)
    {
      hc_session->stats.req_per_wrk = hcm->repeat_count / hcm->max_sessions;
      clib_spinlock_lock_if_init (&hcm->lock);
      /* add remaining requests to the first connected session */
      if (hcm->connected_counter == 1)
	{
	  hc_session->stats.req_per_wrk +=
	    hcm->repeat_count % hcm->max_sessions;
	}
      clib_spinlock_unlock_if_init (&hcm->lock);
    }
  else
    {
      hc_session->stats.req_per_wrk = hcm->repeat_count;
      hcm->worker_index = s->thread_index;
    }

  if (!wrk->has_common_headers)
    {
      wrk->has_common_headers = true;
      if (hcm->req_method == HTTP_REQ_POST)
	{
	  if (hcm->is_file)
	    http_add_header (
	      &wrk->req_headers, HTTP_HEADER_CONTENT_TYPE,
	      http_content_type_token (HTTP_CONTENT_APP_OCTET_STREAM));
	  else
	    http_add_header (&wrk->req_headers, HTTP_HEADER_CONTENT_TYPE,
			     http_content_type_token (
			       HTTP_CONTENT_APP_X_WWW_FORM_URLENCODED));
	}
      http_add_header (&wrk->req_headers, HTTP_HEADER_ACCEPT, "*", 1);

      vec_foreach (header, hcm->custom_header)
	http_add_custom_header (&wrk->req_headers, (const char *) header->name,
				vec_len (header->name),
				(const char *) header->value,
				vec_len (header->value));

      wrk->msg.method_type = hcm->req_method;
      if (hcm->req_method == HTTP_REQ_POST)
	wrk->msg.data.body_len = vec_len (hcm->data);
      else
	wrk->msg.data.body_len = 0;

      wrk->msg.type = HTTP_MSG_REQUEST;
      /* request target */
      wrk->msg.data.target_path_len = vec_len (hcm->target);
      /* custom headers */
      wrk->msg.data.headers_len = wrk->req_headers.tail_offset;
      /* total length */
      wrk->msg.data.len = wrk->msg.data.target_path_len +
			  wrk->msg.data.headers_len + wrk->msg.data.body_len;

      if (hcm->use_ptr)
	{
	  wrk->msg.data.type = HTTP_MSG_DATA_PTR;
	}
      else
	{
	  wrk->msg.data.type = HTTP_MSG_DATA_INLINE;
	  wrk->msg.data.target_path_offset = 0;
	  wrk->msg.data.headers_offset = wrk->msg.data.target_path_len;
	  wrk->msg.data.body_offset =
	    wrk->msg.data.headers_offset + wrk->msg.data.headers_len;
	}
    }

  if (hcm->repeat)
    hc_session->stats.start =
      vlib_time_now (vlib_get_main_by_index (s->thread_index));

  return hc_request (s, wrk, hc_session, err);
}

static void
hc_session_disconnect_callback (session_t *s)
{
  hc_main_t *hcm = &hc_main;
  HTTP_DBG (1, "disconnecting");
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  int rv;
  a->handle = session_handle (s);
  a->app_index = hcm->app_index;
  if ((rv = vnet_disconnect_session (a)))
    clib_warning ("warning: disconnect returned: %U", format_session_error,
		  rv);
  clib_spinlock_lock_if_init (&hcm->lock);
  hcm->done_count++;
  clib_spinlock_unlock_if_init (&hcm->lock);
}

static void
hc_session_transport_closed_callback (session_t *s)
{
  hc_main_t *hcm = &hc_main;
  hc_worker_t *wrk = hc_worker_get (s->thread_index);

  clib_spinlock_lock_if_init (&hcm->lock);
  if (s->session_state == SESSION_STATE_TRANSPORT_CLOSED)
    {
      hcm->was_transport_closed = true;
    }

  /* send an event when all sessions are closed */
  if (hcm->done_count >= hcm->max_sessions)
    {
      if (hcm->was_transport_closed)
	{
	  vlib_process_signal_event_mt (wrk->vlib_main, hcm->cli_node_index,
					HC_TRANSPORT_CLOSED, 0);
	}
      else
	{
	  vlib_process_signal_event_mt (wrk->vlib_main, hcm->cli_node_index,
					HC_REPEAT_DONE, 0);
	}
    }
  clib_spinlock_unlock_if_init (&hcm->lock);
}

static void
hc_session_reset_callback (session_t *s)
{
  hc_main_t *hcm = &hc_main;
  hc_session_t *hc_session;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  int rv;

  hc_session = hc_session_get (s->opaque, s->thread_index);
  hc_session->is_closed = 1;

  a->handle = session_handle (s);
  a->app_index = hcm->app_index;
  if ((rv = vnet_disconnect_session (a)))
    clib_warning ("warning: disconnect returned: %U", format_session_error,
		  rv);
}

static int
hc_rx_callback (session_t *s)
{
  hc_main_t *hcm = &hc_main;
  hc_worker_t *wrk = hc_worker_get (s->thread_index);
  hc_session_t *hc_session = hc_session_get (s->opaque, s->thread_index);
  http_msg_t msg;
  int rv;
  u32 max_deq;
  session_error_t session_err = 0;
  int send_err = 0;

  if (hc_session->is_closed)
    {
      clib_warning ("hc_session_index[%d] is closed", s->opaque);
      return -1;
    }

  max_deq = svm_fifo_max_dequeue_cons (s->rx_fifo);
  if (PREDICT_FALSE (max_deq == 0))
    goto done;

  if (hc_session->to_recv == 0)
    {
      rv = svm_fifo_dequeue (s->rx_fifo, sizeof (msg), (u8 *) &msg);
      ASSERT (rv == sizeof (msg));

      if (msg.type != HTTP_MSG_REPLY)
	{
	  clib_warning ("unexpected msg type %d", msg.type);
	  vlib_process_signal_event_mt (wrk->vlib_main, hcm->cli_node_index,
					HC_GENERIC_ERR, 0);
	  return -1;
	}

      if (msg.data.headers_len)
	{

	  if (!hcm->repeat)
	    hc_session->response_status =
	      format (0, "%U", format_http_status_code, msg.code);

	  svm_fifo_dequeue_drop (s->rx_fifo, msg.data.headers_offset);

	  vec_validate (hc_session->resp_headers, msg.data.headers_len - 1);
	  vec_set_len (hc_session->resp_headers, msg.data.headers_len);
	  rv = svm_fifo_dequeue (s->rx_fifo, msg.data.headers_len,
				 hc_session->resp_headers);

	  ASSERT (rv == msg.data.headers_len);
	  HTTP_DBG (1, (char *) format (0, "%v", hc_session->resp_headers));
	  msg.data.body_offset -=
	    msg.data.headers_len + msg.data.headers_offset;
	}

      if (msg.data.body_len == 0)
	{
	  svm_fifo_dequeue_drop_all (s->rx_fifo);
	  goto done;
	}

      /* drop everything up to body */
      svm_fifo_dequeue_drop (s->rx_fifo, msg.data.body_offset);
      hc_session->to_recv = msg.data.body_len;
      if (msg.code != HTTP_STATUS_OK && hc_session->to_recv == 0)
	{
	  goto done;
	}
      vec_validate (hc_session->http_response, msg.data.body_len - 1);
      vec_reset_length (hc_session->http_response);
    }

  max_deq = svm_fifo_max_dequeue (s->rx_fifo);
  if (!max_deq)
    {
      goto done;
    }
  u32 n_deq = clib_min (hc_session->to_recv, max_deq);
  u32 curr = vec_len (hc_session->http_response);
  rv = svm_fifo_dequeue (s->rx_fifo, n_deq, hc_session->http_response + curr);
  if (rv < 0)
    {
      clib_warning ("app dequeue(n=%d) failed; rv = %d", n_deq, rv);
      vlib_process_signal_event_mt (wrk->vlib_main, hcm->cli_node_index,
				    HC_GENERIC_ERR, 0);
      return -1;
    }

  ASSERT (rv == n_deq);
  vec_set_len (hc_session->http_response, curr + n_deq);
  ASSERT (hc_session->to_recv >= rv);
  hc_session->to_recv -= rv;

done:
  if (hc_session->to_recv == 0)
    {
      if (hcm->repeat)
	{
	  hc_session->stats.request_count++;
	  hc_session->stats.end = vlib_time_now (wrk->vlib_main);
	  hc_session->stats.elapsed_time =
	    hc_session->stats.end - hc_session->stats.start;

	  if (hc_session->stats.elapsed_time >= hcm->duration &&
	      hc_session->stats.request_count >= hc_session->stats.req_per_wrk)
	    {
	      hc_session_disconnect_callback (s);
	    }
	  else
	    {
	      send_err = hc_request (s, wrk, hc_session, session_err);
	      if (send_err)
		clib_warning ("failed to send request, error %d", send_err);
	    }
	}
      else
	{
	  vlib_process_signal_event_mt (wrk->vlib_main, hcm->cli_node_index,
					HC_REPLY_RECEIVED, 0);
	  hc_session_disconnect_callback (s);
	}
    }
  return 0;
}

static int
hc_tx_callback (session_t *s)
{
  hc_main_t *hcm = &hc_main;
  hc_session_t *hc_session = hc_session_get (s->opaque, s->thread_index);
  u64 to_send;
  int rv;

  to_send = vec_len (hcm->data) - hc_session->data_offset;
  rv = svm_fifo_enqueue (s->tx_fifo, to_send,
			 hcm->data + hc_session->data_offset);

  if (rv <= 0)
    {
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  if (rv < to_send)
    {
      hc_session->data_offset += rv;
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }

  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);

  return 0;
}

static session_cb_vft_t hc_session_cb_vft = {
  .session_connected_callback = hc_session_connected_callback,
  .session_disconnect_callback = hc_session_disconnect_callback,
  .session_transport_closed_callback = hc_session_transport_closed_callback,
  .session_reset_callback = hc_session_reset_callback,
  .builtin_app_rx_callback = hc_rx_callback,
  .builtin_app_tx_callback = hc_tx_callback,
};

static clib_error_t *
hc_attach ()
{
  hc_main_t *hcm = &hc_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[18];
  u32 segment_size = 128 << 20;
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  int rv;

  if (hcm->private_segment_size)
    segment_size = hcm->private_segment_size;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = APP_INVALID_INDEX;
  a->name = format (0, "http_client");
  a->session_cb_vft = &hc_session_cb_vft;
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
    return clib_error_return (0, "attach returned: %U", format_session_error,
			      rv);

  hcm->app_index = a->app_index;
  vec_free (a->name);
  hcm->attached = 1;

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
hc_connect_rpc (void *rpc_args)
{
  vnet_connect_args_t *a = rpc_args;
  int rv = ~0;
  hc_main_t *hcm = &hc_main;

  for (u32 i = 0; i < hcm->max_sessions; i++)
    {
      rv = vnet_connect (a);
      if (rv > 0)
	clib_warning (0, "connect returned: %U", format_session_error, rv);
    }

  session_endpoint_free_ext_cfgs (&a->sep_ext);
  vec_free (a);

  return rv;
}

static void
hc_connect ()
{
  hc_main_t *hcm = &hc_main;
  vnet_connect_args_t *a = 0;
  transport_endpt_ext_cfg_t *ext_cfg;
  transport_endpt_cfg_http_t http_cfg = { (u32) hcm->timeout, 0 };
  vec_validate (a, 0);
  clib_memset (a, 0, sizeof (a[0]));
  clib_memcpy (&a->sep_ext, &hcm->connect_sep, sizeof (hcm->connect_sep));
  a->app_index = hcm->app_index;

  ext_cfg = session_endpoint_add_ext_cfg (
    &a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (http_cfg));
  clib_memcpy (ext_cfg->data, &http_cfg, sizeof (http_cfg));

  if (hcm->connect_sep.flags & SESSION_ENDPT_CFG_F_SECURE)
    {
      ext_cfg = session_endpoint_add_ext_cfg (
	&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
	sizeof (transport_endpt_crypto_cfg_t));
      ext_cfg->crypto.ckpair_index = hcm->ckpair_index;
    }

  session_send_rpc_evt_to_thread_force (transport_cl_thread (), hc_connect_rpc,
					a);
}

static void
hc_get_repeat_stats (vlib_main_t *vm)
{
  hc_main_t *hcm = &hc_main;
  hc_worker_t *wrk;
  hc_session_t *hc_session;

  if (hcm->repeat)
    {
      vec_foreach (wrk, hcm->wrk)
	{
	  vec_foreach (hc_session, wrk->sessions)
	    {
	      hc_stats.request_count += hc_session->stats.request_count;
	      hc_session->stats.request_count = 0;
	      if (hc_stats.elapsed_time < hc_session->stats.elapsed_time)
		{
		  hc_stats.elapsed_time = hc_session->stats.elapsed_time;
		  hc_session->stats.elapsed_time = 0;
		}
	    }
	}
      vlib_cli_output (vm,
		       "< %d request(s) in %.6fs\n< avg latency "
		       "%.4fms\n< %.2f req/sec",
		       hc_stats.request_count, hc_stats.elapsed_time,
		       (hc_stats.elapsed_time / hc_stats.request_count) * 1000,
		       hc_stats.request_count / hc_stats.elapsed_time);
    }
}

static clib_error_t *
hc_get_event (vlib_main_t *vm)
{
  hc_main_t *hcm = &hc_main;
  uword event_type, *event_data = 0;
  clib_error_t *err = NULL;
  FILE *file_ptr;
  u64 event_timeout;
  hc_worker_t *wrk;
  hc_session_t *hc_session;

  event_timeout = hcm->timeout ? hcm->timeout : 10;
  if (event_timeout == hcm->duration)
    event_timeout += 5;
  vlib_process_wait_for_event_or_clock (vm, event_timeout);
  event_type = vlib_process_get_events (vm, &event_data);

  switch (event_type)
    {
    case ~0:
      hc_get_repeat_stats (vm);
      err = clib_error_return (0, "error: timeout");
      break;
    case HC_CONNECT_FAILED:
      hc_get_repeat_stats (vm);
      err = clib_error_return (0, "error: failed to connect");
      break;
    case HC_TRANSPORT_CLOSED:
      hc_get_repeat_stats (vm);
      err = clib_error_return (0, "error: transport closed");
      break;
    case HC_GENERIC_ERR:
      hc_get_repeat_stats (vm);
      err = clib_error_return (0, "error: unknown");
      break;
    case HC_REPLY_RECEIVED:
      if (hcm->filename)
	{
	  wrk = hc_worker_get (hcm->worker_index);
	  hc_session = hc_session_get (wrk->session_index, wrk->thread_index);
	  file_ptr =
	    fopen ((char *) format (0, "/tmp/%v", hcm->filename), "a");
	  if (file_ptr == NULL)
	    {
	      vlib_cli_output (vm, "couldn't open file %v", hcm->filename);
	    }
	  else
	    {
	      fprintf (file_ptr, "< %s\n< %s\n< %s",
		       hc_session->response_status, hc_session->resp_headers,
		       hc_session->http_response);
	      fclose (file_ptr);
	      vlib_cli_output (vm, "file saved (/tmp/%v)", hcm->filename);
	    }
	}
      if (hcm->verbose)
	{
	  wrk = hc_worker_get (hcm->worker_index);
	  hc_session = hc_session_get (wrk->session_index, wrk->thread_index);
	  vlib_cli_output (vm, "< %v\n< %v\n%v", hc_session->response_status,
			   hc_session->resp_headers,
			   hc_session->http_response);
	}
      break;
    case HC_REPEAT_DONE:
      hc_get_repeat_stats (vm);
      break;
    default:
      hc_get_repeat_stats (vm);
      err = clib_error_return (0, "error: unexpected event %d", event_type);
      break;
    }

  vec_free (event_data);
  return err;
}

static clib_error_t *
hc_run (vlib_main_t *vm)
{
  hc_main_t *hcm = &hc_main;
  u32 num_threads;
  hc_worker_t *wrk;
  clib_error_t *err;

  num_threads = 1 /* main thread */ + vlib_num_workers ();
  if (vlib_num_workers ())
    clib_spinlock_init (&hcm->lock);
  vec_validate (hcm->wrk, num_threads - 1);
  vec_foreach (wrk, hcm->wrk)
    {
      wrk->has_common_headers = false;
      wrk->thread_index = wrk - hcm->wrk;
      /* 4k for headers should be enough */
      vec_validate (wrk->headers_buf, 4095);
      http_init_headers_ctx (&wrk->req_headers, wrk->headers_buf,
			     vec_len (wrk->headers_buf));
    }

  if ((err = hc_attach ()))
    return clib_error_return (0, "http client attach: %U", format_clib_error,
			      err);

  hc_connect ();

  return hc_get_event (vm);
}

static int
hc_detach ()
{
  hc_main_t *hcm = &hc_main;
  vnet_app_detach_args_t _da, *da = &_da;
  int rv;

  if (!hcm->attached)
    return 0;

  da->app_index = hcm->app_index;
  da->api_client_index = APP_INVALID_INDEX;
  rv = vnet_application_detach (da);
  hcm->attached = 0;
  hcm->app_index = APP_INVALID_INDEX;

  return rv;
}

static void
hc_worker_cleanup (hc_worker_t *wrk)
{
  hc_session_t *hc_session;
  HTTP_DBG (1, "worker and worker sessions cleanup");

  vec_free (wrk->headers_buf);
  vec_foreach (hc_session, wrk->sessions)
    {
      vec_free (hc_session->resp_headers);
      vec_free (hc_session->http_response);
      vec_free (hc_session->response_status);
    }
  pool_free (wrk->sessions);
}

static void
hc_cleanup ()
{
  HTTP_DBG (1, "cleanup");
  hc_main_t *hcm = &hc_main;
  hc_worker_t *wrk;
  hc_http_header_t *header;

  vec_foreach (wrk, hcm->wrk)
    hc_worker_cleanup (wrk);

  vec_free (hcm->uri);
  vec_free (hcm->target);
  vec_free (hcm->data);
  vec_free (hcm->wrk);
  vec_free (hcm->filename);
  vec_free (hcm->appns_id);
  vec_foreach (header, hcm->custom_header)
    {
      vec_free (header->name);
      vec_free (header->value);
    }
  vec_free (hcm->custom_header);
}

static clib_error_t *
hc_command_fn (vlib_main_t *vm, unformat_input_t *input,
	       vlib_cli_command_t *cmd)
{
  hc_main_t *hcm = &hc_main;
  clib_error_t *err = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  u64 mem_size;
  u8 *appns_id = 0;
  u8 *path = 0;
  u8 *file_data;
  hc_http_header_t new_header;
  u8 *name;
  u8 *value;
  int rv;
  hcm->timeout = 10;
  hcm->repeat_count = 0;
  hcm->duration = 0;
  hcm->repeat = false;
  hcm->multi_session = false;
  hcm->done_count = 0;
  hcm->connected_counter = 0;
  hcm->max_sessions = 1;
  hcm->prealloc_fifos = 0;
  hcm->private_segment_size = 0;
  hcm->fifo_size = 0;
  hcm->was_transport_closed = false;
  hc_stats.request_count = 0;
  hc_stats.elapsed_time = 0;

  if (hcm->attached)
    return clib_error_return (0, "failed: already running!");

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected required arguments");

  hcm->req_method =
    (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) &&
	unformat (line_input, "post") ?
      HTTP_REQ_POST :
      HTTP_REQ_GET;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "uri %s", &hcm->uri))
	;
      else if (unformat (line_input, "data %v", &hcm->data))
	hcm->is_file = 0;
      else if (unformat (line_input, "file %s", &path))
	hcm->is_file = 1;
      else if (unformat (line_input, "use-ptr"))
	hcm->use_ptr = 1;
      else if (unformat (line_input, "save-to %s", &hcm->filename))
	{
	  if (strstr ((char *) hcm->filename, "..") ||
	      strchr ((char *) hcm->filename, '/'))
	    {
	      err = clib_error_return (
		0, "illegal characters in filename '%v'", hcm->filename);
	      goto done;
	    }
	}
      else if (unformat (line_input, "header %v:%v", &name, &value))
	{
	  new_header.name = name;
	  new_header.value = value;
	  vec_add1 (hcm->custom_header, new_header);
	}
      else if (unformat (line_input, "verbose"))
	hcm->verbose = true;
      else if (unformat (line_input, "timeout %f", &hcm->timeout))
	;
      else if (unformat (line_input, "repeat %d", &hcm->repeat_count))
	{
	  hcm->repeat = true;
	}
      else if (unformat (line_input, "duration %f", &hcm->duration))
	hcm->repeat = true;
      else if (unformat (line_input, "sessions %d", &hcm->max_sessions))
	{
	  hcm->multi_session = true;
	  if (hcm->max_sessions <= 1)
	    {
	      err = clib_error_return (0, "sessions must be > 1");
	      goto done;
	    }
	}
      else if (unformat (line_input, "prealloc-fifos %d",
			 &hcm->prealloc_fifos))
	;
      else if (unformat (line_input, "private-segment-size %U",
			 unformat_memory_size, &mem_size))
	hcm->private_segment_size = mem_size;
      else if (unformat (line_input, "fifo-size %U", unformat_memory_size,
			 &mem_size))
	hcm->fifo_size = mem_size;
      else if (unformat (line_input, "appns %_%v%_", &appns_id))
	;
      else if (unformat (line_input, "secret %lu", &hcm->appns_secret))
	;

      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!hcm->uri)
    {
      err = clib_error_return (0, "URI not defined");
      goto done;
    }

  if (!hcm->data && hcm->req_method == HTTP_REQ_POST)
    {
      if (path)
	{
	  err = clib_file_contents ((char *) path, &file_data);
	  if (err)
	    goto done;
	  hcm->data = file_data;
	}
      else
	{
	  err = clib_error_return (0, "data not defined");
	  goto done;
	}
    }

  if (hcm->duration && hcm->repeat_count)
    {
      err = clib_error_return (
	0, "combining duration and repeat is not supported");
      goto done;
    }

  if (hcm->multi_session && !hcm->repeat)
    {
      err = clib_error_return (
	0, "multiple sessions are only supported with request repeating");
      goto done;
    }

  if ((rv = parse_target ((char **) &hcm->uri, (char **) &hcm->target)))
    {
      err = clib_error_return (0, "target parse error: %U",
			       format_session_error, rv);
      goto done;
    }

  if ((rv = parse_uri ((char *) hcm->uri, &hcm->connect_sep)))
    {
      err =
	clib_error_return (0, "URI parse error: %U", format_session_error, rv);
      goto done;
    }

  if (hcm->duration >= hcm->timeout)
    {
      hcm->timeout = hcm->duration + 10;
    }
  hcm->appns_id = appns_id;

  if (hcm->repeat)
    vlib_cli_output (vm, "Running, please wait...");

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, &args);
  vlib_worker_thread_barrier_release (vm);

  hcm->cli_node_index = vlib_get_current_process (vm)->node_runtime.node_index;
  err = hc_run (vm);

  if ((rv = hc_detach ()))
    {
      /* don't override last error */
      if (!err)
	err = clib_error_return (0, "detach returned: %U",
				 format_session_error, rv);
      else
	clib_warning ("warning: detach returned: %U", format_session_error,
		      rv);
    }

done:
  vec_free (path);
  hc_cleanup ();
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (hc_command, static) = {
  .path = "http client",
  .short_help =
    "[post] uri http://<ip-addr>/<origin-form> "
    "[data <form-urlencoded> | file <file-path>] [use-ptr] "
    "[save-to <filename>] [header <Key:Value>] [verbose] "
    "[timeout <seconds> (default = 10)] [repeat <count> | duration <seconds>] "
    "[sessions <# of sessions>] [appns <app-ns> secret <appns-secret>] "
    "[fifo-size <nM|G>] [private-segment-size <nM|G>] [prealloc-fifos <n>]",
  .function = hc_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
hc_main_init ()
{
  hc_main_t *hcm = &hc_main;
  hcm->app_index = APP_INVALID_INDEX;
  return 0;
}

VLIB_INIT_FUNCTION (hc_main_init);
