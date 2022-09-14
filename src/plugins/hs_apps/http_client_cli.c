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
#include <hs_apps/http_cli.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 session_index;
  u32 thread_index;
  u32 rx_offset;
  u32 vpp_session_index;
  u32 to_recv;
  u8 is_closed;
} hcc_session_t;

typedef struct
{
  hcc_session_t *sessions;
  u8 *rx_buf;
  u32 thread_index;
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
} hcc_main_t;

typedef enum
{
  HCC_REPLY_RECEIVED = 100,
} hcc_cli_signal_t;

static hcc_main_t hcc_main;

static hcc_worker_t *
hcc_worker_get (u32 thread_index)
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
hcc_session_get (u32 hs_index, u32 thread_index)
{
  hcc_worker_t *wrk = hcc_worker_get (thread_index);
  return pool_elt_at_index (wrk->sessions, hs_index);
}

static void
hcc_session_free (u32 thread_index, hcc_session_t *hs)
{
  hcc_worker_t *wrk = hcc_worker_get (thread_index);
  pool_put (wrk->sessions, hs);
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
  int rv;

  if (err)
    {
      clib_warning ("connected error: hc_index(%d): %U", hc_index,
		    format_session_error, err);
      return -1;
    }

  // TODO delete half open session once the support is added in http layer
  hs = hcc_session_get (hc_index, 0);
  wrk = hcc_worker_get (as->thread_index);
  new_hs = hcc_session_alloc (wrk);
  clib_memcpy_fast (new_hs, hs, sizeof (*hs));

  hs->vpp_session_index = as->session_index;

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = HTTP_REQ_GET;
  msg.content_type = HTTP_CONTENT_TEXT_HTML;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = vec_len (hcm->http_query);

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) },
			     { hcm->http_query, vec_len (hcm->http_query) } };

  rv = svm_fifo_enqueue_segments (as->tx_fifo, segs, 2, 0 /* allow partial */);
  if (rv < 0 || rv != sizeof (msg) + vec_len (hcm->http_query))
    {
      clib_warning ("failed app enqueue");
      return -1;
    }

  if (svm_fifo_set_event (as->tx_fifo))
    session_send_io_evt_to_thread (as->tx_fifo, SESSION_IO_EVT_TX);

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

  if (!hs->to_recv)
    {
      rv = svm_fifo_dequeue (ts->rx_fifo, sizeof (msg), (u8 *) &msg);
      ASSERT (rv == sizeof (msg));

      if (msg.type != HTTP_MSG_REPLY || msg.code != HTTP_STATUS_OK)
	{
	  clib_warning ("unexpected msg type %d", msg.type);
	  return 0;
	}
      vec_validate (hcm->http_response, msg.data.len - 1);
      vec_reset_length (hcm->http_response);
      hs->to_recv = msg.data.len;
    }

  u32 max_deq = svm_fifo_max_dequeue (ts->rx_fifo);

  u32 n_deq = clib_min (hs->to_recv, max_deq);
  u32 curr = vec_len (hcm->http_response);
  rv = svm_fifo_dequeue (ts->rx_fifo, n_deq, hcm->http_response + curr);
  if (rv < 0)
    {
      clib_warning ("app dequeue failed");
      return -1;
    }

  if (rv != n_deq)
    return -1;

  vec_set_len (hcm->http_response, curr + n_deq);
  ASSERT (hs->to_recv >= rv);
  hs->to_recv -= rv;

  if (hs->to_recv == 0)
    {
      hcc_session_disconnect (ts);
      vlib_process_signal_event_mt (hcm->vlib_main, hcm->cli_node_index,
				    HCC_REPLY_RECEIVED, 0);
    }

  return 0;
}

static void
hcc_ts_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  hcc_session_t *hs;

  hs = hcc_session_get (s->thread_index, s->opaque);
  if (!hs)
    return;

  hcc_session_free (s->thread_index, hs);
}

static session_cb_vft_t hcc_session_cb_vft = {
  .session_accept_callback = hcc_ts_accept_callback,
  .session_disconnect_callback = hcc_ts_disconnect_callback,
  .session_connected_callback = hcc_ts_connected_callback,
  .builtin_app_rx_callback = hcc_ts_rx_callback,
  .builtin_app_tx_callback = hcc_ts_tx_callback,
  .session_reset_callback = hcc_ts_reset_callback,
  .session_cleanup_callback = hcc_ts_cleanup_callback,
};

static clib_error_t *
hcc_attach ()
{
  hcc_main_t *hcm = &hcc_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[18];
  u32 segment_size = 128 << 20;
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

  if ((rv = vnet_application_attach (a)))
    return clib_error_return (0, "attach returned %d", rv);

  hcm->app_index = a->app_index;
  vec_free (a->name);
  hcm->test_client_attached = 1;
  return 0;
}

static clib_error_t *
hcc_connect ()
{
  vnet_connect_args_t _a = {}, *a = &_a;
  hcc_main_t *hcm = &hcc_main;
  hcc_worker_t *wrk;
  hcc_session_t *hs;

  clib_memcpy (&a->sep_ext, &hcm->connect_sep, sizeof (hcm->connect_sep));
  a->app_index = hcm->app_index;

  /* allocate http session on main thread */
  wrk = hcc_worker_get (0);
  hs = hcc_session_alloc (wrk);
  a->api_context = hs->session_index;

  int rv = vnet_connect (a);

  if (rv)
    return clib_error_return (0, "connect returned: %U", format_session_error,
			      rv);
  return 0;
}

static clib_error_t *
hcc_run (vlib_main_t *vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  hcc_main_t *hcm = &hcc_main;
  uword event_type, *event_data = 0;
  u32 num_threads;
  clib_error_t *err = 0;
  hcc_worker_t *wrk;

  num_threads = 1 /* main thread */ + vtm->n_threads;
  vec_validate (hcm->wrk, num_threads);
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
      vlib_cli_output (vm, "%v", hcm->http_response);
      vec_free (hcm->http_response);
      break;
    default:
      clib_error_return (0, "unexpected event %d", event_type);
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

static clib_error_t *
hcc_command_fn (vlib_main_t *vm, unformat_input_t *input,
		vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  hcc_main_t *hcm = &hcc_main;
  u64 seg_size;
  clib_error_t *err = 0;
  int rv;

  hcm->prealloc_fifos = 0;
  hcm->private_segment_size = 0;
  hcm->fifo_size = 0;

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
      else if (unformat (line_input, "query %s", &hcm->http_query))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  hcm->cli_node_index = vlib_get_current_process (vm)->node_runtime.node_index;

  if (!hcm->uri)
    {
      err = clib_error_return (0, "URI not defined");
      goto done;
    }

  if ((rv = parse_uri ((char *) hcm->uri, &hcm->connect_sep)))
    {
      err = clib_error_return (0, "Uri parse error: %d", rv);
      goto done;
    }

  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */);

  err = hcc_run (vm);

  if (hcc_detach ())
    {
      /* don't override last error */
      if (!err)
	err = clib_error_return (0, "failed: app detach");
      clib_warning ("WARNING: app detach failed...");
    }

done:
  vec_free (hcm->uri);
  vec_free (hcm->http_query);
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (hcc_command, static) = {
  .path = "http cli client",
  .short_help = "uri http://<ip-addr> query <query-string>",
  .function = hcc_command_fn,
};

static clib_error_t *
hcc_main_init (vlib_main_t *vm)
{
  hcc_main_t *hcm = &hcc_main;

  hcm->app_index = ~0;
  hcm->vlib_main = vm;
  return 0;
}

VLIB_INIT_FUNCTION (hcc_main_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
