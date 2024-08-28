/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <http/http.h>
#include <http/http_header_names.h>
#include <http/http_content_types.h>
#include <vppinfra/unix.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 session_index;
  u32 thread_index;
  u32 vpp_session_index;
  u8 is_closed;
} hsp_session_t;

typedef struct
{
  hsp_session_t *sessions;
  u32 thread_index;
} hsp_worker_t;

typedef struct
{
  u32 app_index;
  vlib_main_t *vlib_main;
  u32 cli_node_index;
  u8 attached;
  u8 *uri;
  session_endpoint_cfg_t connect_sep;
  u8 *target;
  u8 *headers_buf;
  u8 *data;
  u32 data_offset;
  hsp_worker_t *wrk;
  u8 *http_response;
  u8 is_file;
  u8 use_ptr;
  bool is_post;
} hsp_main_t;

typedef enum
{
  HSP_CONNECT_FAILED = 1,
  HSP_TRANSPORT_CLOSED,
  HSP_REPLY_RECEIVED,
} hsp_cli_signal_t;

static hsp_main_t hsp_main;

static inline hsp_worker_t *
hsp_worker_get (u32 thread_index)
{
  return &hsp_main.wrk[thread_index];
}

static inline hsp_session_t *
hsp_session_get (u32 session_index, u32 thread_index)
{
  hsp_worker_t *wrk = hsp_worker_get (thread_index);
  return pool_elt_at_index (wrk->sessions, session_index);
}

static hsp_session_t *
hsp_session_alloc (hsp_worker_t *wrk)
{
  hsp_session_t *s;

  pool_get_zero (wrk->sessions, s);
  s->session_index = s - wrk->sessions;
  s->thread_index = wrk->thread_index;

  return s;
}

static int
hsp_session_connected_callback (u32 app_index, u32 hsp_session_index,
				session_t *s, session_error_t err)
{
  hsp_main_t *hspm = &hsp_main;
  hsp_session_t *hsp_session, *new_hsp_session;
  hsp_worker_t *wrk;
  http_header_t *headers = 0;
  http_msg_t msg;
  int rv;

  if (err)
    {
      clib_warning ("hsp_session_index[%d] connected error: %U",
		    hsp_session_index, format_session_error, err);
      vlib_process_signal_event_mt (hspm->vlib_main, hspm->cli_node_index,
				    HSP_CONNECT_FAILED, 0);
      return -1;
    }

  hsp_session = hsp_session_get (hsp_session_index, 0);
  wrk = hsp_worker_get (s->thread_index);
  new_hsp_session = hsp_session_alloc (wrk);
  clib_memcpy_fast (new_hsp_session, hsp_session, sizeof (*hsp_session));
  hsp_session->vpp_session_index = s->session_index;

  if (hspm->is_file && hspm->is_post)
    {
      http_add_header (
	&headers, http_header_name_token (HTTP_HEADER_CONTENT_TYPE),
	http_content_type_token (HTTP_CONTENT_APP_OCTET_STREAM));
    }
  else
    {
      http_add_header (
	&headers, http_header_name_token (HTTP_HEADER_CONTENT_TYPE),
	http_content_type_token (HTTP_CONTENT_APP_X_WWW_FORM_URLENCODED));
    }
  hspm->headers_buf = http_serialize_headers (headers);
  vec_free (headers);

  if (hspm->is_post)
    {
      msg.method_type = HTTP_REQ_POST;
      /* request body */
      msg.data.body_len = vec_len (hspm->data);
    }
  else
    {
      msg.method_type = HTTP_REQ_GET;
      msg.data.type = HTTP_MSG_DATA_INLINE;
      msg.data.body_len = 0;
    }

  msg.type = HTTP_MSG_REQUEST;
  /* request target */
  msg.data.target_form = HTTP_TARGET_ORIGIN_FORM;
  msg.data.target_path_len = vec_len (hspm->target);
  /* custom headers */
  msg.data.headers_len = vec_len (hspm->headers_buf);
  /* total length */
  msg.data.len =
    msg.data.target_path_len + msg.data.headers_len + msg.data.body_len;

  if (hspm->use_ptr)
    {
      uword target = pointer_to_uword (hspm->target);
      uword headers = pointer_to_uword (hspm->headers_buf);
      uword body = pointer_to_uword (hspm->data);
      msg.data.type = HTTP_MSG_DATA_PTR;
      svm_fifo_seg_t segs[4] = {
	{ (u8 *) &msg, sizeof (msg) },
	{ (u8 *) &target, sizeof (target) },
	{ (u8 *) &headers, sizeof (headers) },
	{ (u8 *) &body, sizeof (body) },
      };

      rv =
	svm_fifo_enqueue_segments (s->tx_fifo, segs, 4, 0 /* allow partial */);
      ASSERT (rv == (sizeof (msg) + sizeof (target) + sizeof (headers) +
		     sizeof (body)));
      goto done;
    }

  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.target_path_offset = 0;
  msg.data.headers_offset = msg.data.target_path_len;
  msg.data.body_offset = msg.data.headers_offset + msg.data.headers_len;

  rv = svm_fifo_enqueue (s->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  rv = svm_fifo_enqueue (s->tx_fifo, vec_len (hspm->target), hspm->target);
  ASSERT (rv == vec_len (hspm->target));

  rv = svm_fifo_enqueue (s->tx_fifo, vec_len (hspm->headers_buf),
			 hspm->headers_buf);
  ASSERT (rv == msg.data.headers_len);

  rv = svm_fifo_enqueue (s->tx_fifo, vec_len (hspm->data), hspm->data);
  if (rv != vec_len (hspm->data))
    {
      hspm->data_offset = (rv > 0) ? rv : 0;
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }

done:
  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);

  return 0;
}

static void
hsp_session_disconnect_callback (session_t *s)
{
  hsp_main_t *hspm = &hsp_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  int rv;

  a->handle = session_handle (s);
  a->app_index = hspm->app_index;
  if ((rv = vnet_disconnect_session (a)))
    clib_warning ("warning: disconnect returned: %U", format_session_error,
		  rv);
}

static void
hsp_session_transport_closed_callback (session_t *s)
{
  hsp_main_t *hspm = &hsp_main;

  vlib_process_signal_event_mt (hspm->vlib_main, hspm->cli_node_index,
				HSP_TRANSPORT_CLOSED, 0);
}

static void
hsp_session_reset_callback (session_t *s)
{
  hsp_main_t *hspm = &hsp_main;
  hsp_session_t *hsp_session;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  int rv;

  hsp_session = hsp_session_get (s->opaque, s->thread_index);
  hsp_session->is_closed = 1;

  a->handle = session_handle (s);
  a->app_index = hspm->app_index;
  if ((rv = vnet_disconnect_session (a)))
    clib_warning ("warning: disconnect returned: %U", format_session_error,
		  rv);
}

static int
hsp_rx_callback (session_t *s)
{
  hsp_main_t *hspm = &hsp_main;
  hsp_session_t *hsp_session;
  http_msg_t msg;
  int rv;

  hsp_session = hsp_session_get (s->opaque, s->thread_index);

  if (hsp_session->is_closed)
    {
      clib_warning ("hsp_session_index[%d] is closed", s->opaque);
      return -1;
    }

  rv = svm_fifo_dequeue (s->rx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.type != HTTP_MSG_REPLY)
    {
      clib_warning ("unexpected msg type %d", msg.type);
      return -1;
    }

  svm_fifo_dequeue_drop_all (s->rx_fifo);

  if (msg.code == HTTP_STATUS_OK)
    hspm->http_response = format (0, "request success");
  else
    hspm->http_response = format (0, "request failed");

  hsp_session_disconnect_callback (s);
  vlib_process_signal_event_mt (hspm->vlib_main, hspm->cli_node_index,
				HSP_REPLY_RECEIVED, 0);
  return 0;
}

static int
hsp_tx_callback (session_t *s)
{
  hsp_main_t *hspm = &hsp_main;
  u32 to_send;
  int rv;

  to_send = vec_len (hspm->data) - hspm->data_offset;
  rv = svm_fifo_enqueue (s->tx_fifo, to_send, hspm->data + hspm->data_offset);

  if (rv <= 0)
    {
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  if (rv < to_send)
    {
      hspm->data_offset += rv;
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }

  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);

  return 0;
}

static session_cb_vft_t hsp_session_cb_vft = {
  .session_connected_callback = hsp_session_connected_callback,
  .session_disconnect_callback = hsp_session_disconnect_callback,
  .session_transport_closed_callback = hsp_session_transport_closed_callback,
  .session_reset_callback = hsp_session_reset_callback,
  .builtin_app_rx_callback = hsp_rx_callback,
  .builtin_app_tx_callback = hsp_tx_callback,
};

static clib_error_t *
hsp_attach ()
{
  hsp_main_t *hspm = &hsp_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[18];
  int rv;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = APP_INVALID_INDEX;
  a->name = format (0, "http_simple_client");
  a->session_cb_vft = &hsp_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;

  if ((rv = vnet_application_attach (a)))
    return clib_error_return (0, "attach returned: %U", format_session_error,
			      rv);

  hspm->app_index = a->app_index;
  vec_free (a->name);
  hspm->attached = 1;

  return 0;
}

static int
hsp_connect_rpc (void *rpc_args)
{
  vnet_connect_args_t *a = rpc_args;
  int rv;

  rv = vnet_connect (a);
  if (rv)
    clib_warning (0, "connect returned: %U", format_session_error, rv);

  vec_free (a);
  return rv;
}

static void
hsp_connect ()
{
  hsp_main_t *hspm = &hsp_main;
  vnet_connect_args_t *a = 0;
  hsp_worker_t *wrk;
  hsp_session_t *hsp_session;

  vec_validate (a, 0);
  clib_memset (a, 0, sizeof (a[0]));

  clib_memcpy (&a->sep_ext, &hspm->connect_sep, sizeof (hspm->connect_sep));
  a->app_index = hspm->app_index;

  /* allocate http session on main thread */
  wrk = hsp_worker_get (0);
  hsp_session = hsp_session_alloc (wrk);
  a->api_context = hsp_session->session_index;

  session_send_rpc_evt_to_thread_force (transport_cl_thread (),
					hsp_connect_rpc, a);
}

static clib_error_t *
hsp_run (vlib_main_t *vm)
{
  hsp_main_t *hspm = &hsp_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;
  hsp_worker_t *wrk;
  uword event_type, *event_data = 0;
  clib_error_t *err;

  num_threads = 1 /* main thread */ + vtm->n_threads;
  vec_validate (hspm->wrk, num_threads);
  vec_foreach (wrk, hspm->wrk)
    wrk->thread_index = wrk - hspm->wrk;

  if ((err = hsp_attach ()))
    return clib_error_return (0, "http simple post attach: %U",
			      format_clib_error, err);

  hsp_connect ();

  vlib_process_wait_for_event_or_clock (vm, 10);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      err = clib_error_return (0, "error: timeout");
      break;
    case HSP_CONNECT_FAILED:
      err = clib_error_return (0, "error: failed to connect");
      break;
    case HSP_TRANSPORT_CLOSED:
      err = clib_error_return (0, "error: transport closed");
      break;
    case HSP_REPLY_RECEIVED:
      vlib_cli_output (vm, "%v", hspm->http_response);
      break;
    default:
      err = clib_error_return (0, "error: unexpected event %d", event_type);
      break;
    }

  vec_free (event_data);
  return err;
}

static int
hsp_detach ()
{
  hsp_main_t *hspm = &hsp_main;
  vnet_app_detach_args_t _da, *da = &_da;
  int rv;

  if (!hspm->attached)
    return 0;

  da->app_index = hspm->app_index;
  da->api_client_index = APP_INVALID_INDEX;
  rv = vnet_application_detach (da);
  hspm->attached = 0;
  hspm->app_index = APP_INVALID_INDEX;

  return rv;
}

static void
hcc_worker_cleanup (hsp_worker_t *wrk)
{
  pool_free (wrk->sessions);
}

static void
hsp_cleanup ()
{
  hsp_main_t *hspm = &hsp_main;
  hsp_worker_t *wrk;

  vec_foreach (wrk, hspm->wrk)
    hcc_worker_cleanup (wrk);

  vec_free (hspm->uri);
  vec_free (hspm->target);
  vec_free (hspm->headers_buf);
  vec_free (hspm->data);
  vec_free (hspm->http_response);
  vec_free (hspm->wrk);
}

static clib_error_t *
hsp_command_fn (vlib_main_t *vm, unformat_input_t *input,
		vlib_cli_command_t *cmd)
{
  hsp_main_t *hspm = &hsp_main;
  clib_error_t *err = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *path = 0;
  u8 *file_data;
  int rv;

  if (hspm->attached)
    return clib_error_return (0, "failed: already running!");

  hspm->use_ptr = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected required arguments");

  hspm->is_post =
    (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) &&
    unformat (line_input, "post");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "uri %s", &hspm->uri))
	;
      else if (unformat (line_input, "data %v", &hspm->data))
	hspm->is_file = 0;
      else if (unformat (line_input, "target %s", &hspm->target))
	;
      else if (unformat (line_input, "file %s", &path))
	hspm->is_file = 1;
      else if (unformat (line_input, "use-ptr"))
	hspm->use_ptr = 1;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!hspm->uri)
    {
      err = clib_error_return (0, "URI not defined");
      goto done;
    }
  if (!hspm->target)
    {
      err = clib_error_return (0, "target not defined");
      goto done;
    }
  if (!hspm->data && hspm->is_post)
    {
      if (path)
	{
	  err = clib_file_contents ((char *) path, &file_data);
	  if (err)
	    goto done;
	  hspm->data = file_data;
	}
      else
	{
	  err = clib_error_return (0, "data not defined");
	  goto done;
	}
    }

  if ((rv = parse_uri ((char *) hspm->uri, &hspm->connect_sep)))
    {
      err =
	clib_error_return (0, "URI parse error: %U", format_session_error, rv);
      goto done;
    }

  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */);
  vlib_worker_thread_barrier_release (vm);

  hspm->cli_node_index =
    vlib_get_current_process (vm)->node_runtime.node_index;

  err = hsp_run (vm);

  if ((rv = hsp_detach ()))
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
  hsp_cleanup ();
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (hsp_command, static) = {
  .path = "http client",
  .short_help = "[post] uri http://<ip-addr> target <origin-form> "
		"[data <form-urlencoded> | file <file-path>] [use-ptr]",
  .function = hsp_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
hsp_main_init (vlib_main_t *vm)
{
  hsp_main_t *hspm = &hsp_main;

  hspm->app_index = APP_INVALID_INDEX;
  hspm->vlib_main = vm;
  return 0;
}

VLIB_INIT_FUNCTION (hsp_main_init);