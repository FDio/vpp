/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <http/http.h>
#include <http/http_header_names.h>
#include <http/http_content_types.h>
#include <http/http_status_codes.h>
#include <vppinfra/unix.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 session_index;
  u32 thread_index;
  u32 vpp_session_index;
  u64 to_recv;
  u8 is_closed;
} hc_session_t;

typedef struct
{
  hc_session_t *sessions;
  u32 thread_index;
  vlib_main_t *vlib_main;
} hc_worker_t;

typedef struct
{
  u32 app_index;
  u32 cli_node_index;
  u8 attached;
  u8 *uri;
  session_endpoint_cfg_t connect_sep;
  u8 *target;
  u8 *headers_buf;
  u8 *data;
  u64 data_offset;
  hc_worker_t *wrk;
  u8 *resp_headers;
  u8 *http_response;
  u8 *response_status;
  http_header_ht_t *custom_header;
  u8 is_file;
  u8 use_ptr;
  u8 *filename;
  bool verbose;
  f64 timeout;
  http_req_method_t req_method;
} hc_main_t;

typedef enum
{
  HC_CONNECT_FAILED = 1,
  HC_TRANSPORT_CLOSED,
  HC_REPLY_RECEIVED,
} hc_cli_signal_t;

static hc_main_t hc_main;

static inline hc_worker_t *
hc_worker_get (u32 thread_index)
{
  return &hc_main.wrk[thread_index];
}

static inline hc_session_t *
hc_session_get (u32 session_index, u32 thread_index)
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
hc_session_connected_callback (u32 app_index, u32 hc_session_index,
			       session_t *s, session_error_t err)
{
  hc_main_t *hcm = &hc_main;
  hc_session_t *hc_session, *new_hc_session;
  hc_worker_t *wrk;
  http_msg_t msg;
  u64 to_send;
  u32 n_enq;
  u8 n_segs;
  int rv;
  http_header_ht_t *header;
  http_header_t *req_headers = 0;

  if (err)
    {
      clib_warning ("hc_session_index[%d] connected error: %U",
		    hc_session_index, format_session_error, err);
      vlib_process_signal_event_mt (hcm->wrk->vlib_main, hcm->cli_node_index,
				    HC_CONNECT_FAILED, 0);
      return -1;
    }

  hc_session = hc_session_get (hc_session_index, 0);
  wrk = hc_worker_get (s->thread_index);
  new_hc_session = hc_session_alloc (wrk);
  clib_memcpy_fast (new_hc_session, hc_session, sizeof (*hc_session));
  hc_session->vpp_session_index = s->session_index;

  if (hcm->req_method == HTTP_REQ_POST)
    {
      if (hcm->is_file)
	http_add_header (
	  &req_headers, http_header_name_token (HTTP_HEADER_CONTENT_TYPE),
	  http_content_type_token (HTTP_CONTENT_APP_OCTET_STREAM));
      else
	http_add_header (
	  &req_headers, http_header_name_token (HTTP_HEADER_CONTENT_TYPE),
	  http_content_type_token (HTTP_CONTENT_APP_X_WWW_FORM_URLENCODED));
    }

  vec_foreach (header, hcm->custom_header)
    http_add_header (&req_headers, (const char *) header->name,
		     vec_len (header->name), (const char *) header->value,
		     vec_len (header->value));

  hcm->headers_buf = http_serialize_headers (req_headers);
  vec_free (req_headers);

  msg.method_type = hcm->req_method;
  if (hcm->req_method == HTTP_REQ_POST)
    msg.data.body_len = vec_len (hcm->data);
  else
    msg.data.body_len = 0;

  msg.type = HTTP_MSG_REQUEST;
  /* request target */
  msg.data.target_form = HTTP_TARGET_ORIGIN_FORM;
  msg.data.target_path_len = vec_len (hcm->target);
  /* custom headers */
  msg.data.headers_len = vec_len (hcm->headers_buf);
  /* total length */
  msg.data.len =
    msg.data.target_path_len + msg.data.headers_len + msg.data.body_len;

  if (hcm->use_ptr)
    {
      uword target = pointer_to_uword (hcm->target);
      uword headers = pointer_to_uword (hcm->headers_buf);
      uword body = pointer_to_uword (hcm->data);
      msg.data.type = HTTP_MSG_DATA_PTR;
      svm_fifo_seg_t segs[4] = {
	{ (u8 *) &msg, sizeof (msg) },
	{ (u8 *) &target, sizeof (target) },
	{ (u8 *) &headers, sizeof (headers) },
	{ (u8 *) &body, sizeof (body) },
      };

      n_segs = (hcm->req_method == HTTP_REQ_GET) ? 3 : 4;
      rv = svm_fifo_enqueue_segments (s->tx_fifo, segs, n_segs,
				      0 /* allow partial */);
      if (hcm->req_method == HTTP_REQ_POST)
	ASSERT (rv == (sizeof (msg) + sizeof (target) + sizeof (headers) +
		       sizeof (body)));
      else
	ASSERT (rv == (sizeof (msg) + sizeof (target) + sizeof (headers)));
      goto done;
    }

  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.target_path_offset = 0;
  msg.data.headers_offset = msg.data.target_path_len;
  msg.data.body_offset = msg.data.headers_offset + msg.data.headers_len;

  rv = svm_fifo_enqueue (s->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  rv = svm_fifo_enqueue (s->tx_fifo, vec_len (hcm->target), hcm->target);
  ASSERT (rv == vec_len (hcm->target));

  rv = svm_fifo_enqueue (s->tx_fifo, vec_len (hcm->headers_buf),
			 hcm->headers_buf);
  ASSERT (rv == msg.data.headers_len);

  if (hcm->req_method == HTTP_REQ_POST)
    {
      to_send = vec_len (hcm->data);
      n_enq = clib_min (svm_fifo_size (s->tx_fifo), to_send);

      rv = svm_fifo_enqueue (s->tx_fifo, n_enq, hcm->data);
      if (rv < to_send)
	{
	  hcm->data_offset = (rv > 0) ? rv : 0;
	  svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
	}
    }

done:
  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);

  return 0;
}

static void
hc_session_disconnect_callback (session_t *s)
{
  hc_main_t *hcm = &hc_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  int rv;

  a->handle = session_handle (s);
  a->app_index = hcm->app_index;
  if ((rv = vnet_disconnect_session (a)))
    clib_warning ("warning: disconnect returned: %U", format_session_error,
		  rv);
}

static void
hc_session_transport_closed_callback (session_t *s)
{
  hc_main_t *hcm = &hc_main;
  vlib_process_signal_event_mt (hcm->wrk->vlib_main, hcm->cli_node_index,
				HC_TRANSPORT_CLOSED, 0);
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
  hc_session_t *hc_session;
  http_msg_t msg;
  int rv;

  hc_session = hc_session_get (s->opaque, s->thread_index);

  if (hc_session->is_closed)
    {
      clib_warning ("hc_session_index[%d] is closed", s->opaque);
      return -1;
    }

  if (hc_session->to_recv == 0)
    {
      rv = svm_fifo_dequeue (s->rx_fifo, sizeof (msg), (u8 *) &msg);
      ASSERT (rv == sizeof (msg));

      if (msg.type != HTTP_MSG_REPLY)
	{
	  clib_warning ("unexpected msg type %d", msg.type);
	  return -1;
	}

      if (msg.data.headers_len)
	{
	  http_header_table_t *ht;
	  vec_validate (hcm->resp_headers, msg.data.headers_len - 1);
	  rv = svm_fifo_peek (s->rx_fifo, msg.data.headers_offset,
			      msg.data.headers_len, hcm->resp_headers);

	  ASSERT (rv == msg.data.headers_len);
	  HTTP_DBG (1, (char *) hcm->resp_headers);

	  if (http_parse_headers (hcm->resp_headers, &ht))
	    {
	      clib_warning ("invalid headers received");
	      return -1;
	    }
	  http_free_header_table (ht);

	  hcm->response_status =
	    format (0, "%U", format_http_status_code, msg.code);
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
      vec_validate (hcm->http_response, msg.data.body_len - 1);
      vec_reset_length (hcm->http_response);
    }

  u32 max_deq = svm_fifo_max_dequeue (s->rx_fifo);

  u32 n_deq = clib_min (hc_session->to_recv, max_deq);
  u32 curr = vec_len (hcm->http_response);
  rv = svm_fifo_dequeue (s->rx_fifo, n_deq, hcm->http_response + curr);
  if (rv < 0)
    {
      clib_warning ("app dequeue(n=%d) failed; rv = %d", n_deq, rv);
      return -1;
    }

  ASSERT (rv == n_deq);
  vec_set_len (hcm->http_response, curr + n_deq);
  ASSERT (hc_session->to_recv >= rv);
  hc_session->to_recv -= rv;

done:
  if (hc_session->to_recv == 0)
    {
      hc_session_disconnect_callback (s);
      vlib_process_signal_event_mt (hcm->wrk->vlib_main, hcm->cli_node_index,
				    HC_REPLY_RECEIVED, 0);
    }

  return 0;
}

static int
hc_tx_callback (session_t *s)
{
  hc_main_t *hcm = &hc_main;
  u64 to_send;
  int rv;

  to_send = vec_len (hcm->data) - hcm->data_offset;
  rv = svm_fifo_enqueue (s->tx_fifo, to_send, hcm->data + hcm->data_offset);

  if (rv <= 0)
    {
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  if (rv < to_send)
    {
      hcm->data_offset += rv;
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
  int rv;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = APP_INVALID_INDEX;
  a->name = format (0, "http_client");
  a->session_cb_vft = &hc_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;

  if ((rv = vnet_application_attach (a)))
    return clib_error_return (0, "attach returned: %U", format_session_error,
			      rv);

  hcm->app_index = a->app_index;
  vec_free (a->name);
  hcm->attached = 1;

  return 0;
}

static int
hc_connect_rpc (void *rpc_args)
{
  vnet_connect_args_t *a = rpc_args;
  int rv;

  rv = vnet_connect (a);
  if (rv > 0)
    clib_warning (0, "connect returned: %U", format_session_error, rv);

  vec_free (a);
  return rv;
}

static void
hc_connect ()
{
  hc_main_t *hcm = &hc_main;
  vnet_connect_args_t *a = 0;
  hc_worker_t *wrk;
  hc_session_t *hc_session;

  vec_validate (a, 0);
  clib_memset (a, 0, sizeof (a[0]));

  clib_memcpy (&a->sep_ext, &hcm->connect_sep, sizeof (hcm->connect_sep));
  a->app_index = hcm->app_index;

  /* allocate http session on main thread */
  wrk = hc_worker_get (0);
  hc_session = hc_session_alloc (wrk);
  a->api_context = hc_session->session_index;

  session_send_rpc_evt_to_thread_force (transport_cl_thread (), hc_connect_rpc,
					a);
}

static clib_error_t *
hc_run (vlib_main_t *vm)
{
  hc_main_t *hcm = &hc_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;
  hc_worker_t *wrk;
  uword event_type, *event_data = 0;
  clib_error_t *err;
  FILE *file_ptr;

  num_threads = 1 /* main thread */ + vtm->n_threads;
  vec_validate (hcm->wrk, num_threads);
  vec_foreach (wrk, hcm->wrk)
    wrk->thread_index = wrk - hcm->wrk;

  if ((err = hc_attach ()))
    return clib_error_return (0, "http client attach: %U", format_clib_error,
			      err);

  hc_connect ();

  vlib_process_wait_for_event_or_clock (vm, hcm->timeout);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      err = clib_error_return (0, "error: timeout");
      break;
    case HC_CONNECT_FAILED:
      err = clib_error_return (0, "error: failed to connect");
      break;
    case HC_TRANSPORT_CLOSED:
      err = clib_error_return (0, "error: transport closed");
      break;
    case HC_REPLY_RECEIVED:
      if (hcm->filename)
	{
	  file_ptr =
	    fopen ((char *) format (0, "/tmp/%v", hcm->filename), "w");
	  if (file_ptr == NULL)
	    {
	      vlib_cli_output (vm, "couldn't open file %v", hcm->filename);
	    }
	  else
	    {
	      fprintf (file_ptr, "< %s\n< %s\n< %s", hcm->response_status,
		       hcm->resp_headers, hcm->http_response);
	      fclose (file_ptr);
	      vlib_cli_output (vm, "file saved (/tmp/%v)", hcm->filename);
	    }
	}
      if (hcm->verbose)
	vlib_cli_output (vm, "< %v\n< %v", hcm->response_status,
			 hcm->resp_headers);
      vlib_cli_output (vm, "<\n%v", hcm->http_response);

      break;
    default:
      err = clib_error_return (0, "error: unexpected event %d", event_type);
      break;
    }

  vec_free (event_data);
  return err;
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
hcc_worker_cleanup (hc_worker_t *wrk)
{
  pool_free (wrk->sessions);
}

static void
hc_cleanup ()
{
  hc_main_t *hcm = &hc_main;
  hc_worker_t *wrk;
  http_header_ht_t *header;

  vec_foreach (wrk, hcm->wrk)
    hcc_worker_cleanup (wrk);

  vec_free (hcm->uri);
  vec_free (hcm->target);
  vec_free (hcm->headers_buf);
  vec_free (hcm->data);
  vec_free (hcm->resp_headers);
  vec_free (hcm->http_response);
  vec_free (hcm->response_status);
  vec_free (hcm->wrk);
  vec_free (hcm->filename);
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
  u8 *path = 0;
  u8 *file_data;
  http_header_ht_t new_header;
  u8 *name;
  u8 *value;
  int rv;
  hcm->timeout = 10;

  if (hcm->attached)
    return clib_error_return (0, "failed: already running!");

  hcm->use_ptr = 0;

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
      else if (unformat (line_input, "target %s", &hcm->target))
	;
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
  if (!hcm->target)
    {
      err = clib_error_return (0, "target not defined");
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

  if ((rv = parse_uri ((char *) hcm->uri, &hcm->connect_sep)))
    {
      err =
	clib_error_return (0, "URI parse error: %U", format_session_error, rv);
      goto done;
    }

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
  .short_help = "[post] uri http://<ip-addr> target <origin-form> "
		"[data <form-urlencoded> | file <file-path>] [use-ptr] "
		"[save-to <filename>] [header <Key:Value>] [verbose] "
		"[timeout <seconds> (default = 10)]",
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
