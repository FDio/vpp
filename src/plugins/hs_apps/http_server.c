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

#include <vnet/vnet.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>
#include <http/http.h>

typedef enum
{
  EVENT_WAKEUP = 1,
} http_process_event_t;

typedef struct
{
  u32 hs_index;
  u32 thread_index;
  u64 node_index;
  u8 *buf;
} http_server_args;

typedef enum
{
  HTTP_STATE_CLOSED,
  HTTP_STATE_ESTABLISHED,
  HTTP_STATE_OK_SENT,
} http_session_state_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define _(type, name) type name;
  foreach_app_session_field
#undef _
  u32 thread_index;
  u8 *rx_buf;
  u8 *tx_buf;
  u32 tx_offset;
  u32 vpp_session_index;
  u64 vpp_session_handle;
  u32 timer_handle;
  http_msg_t msg;
} http_session_t;

typedef struct
{
  http_session_t **sessions;
  clib_rwlock_t sessions_lock;
  u32 **session_to_http_session;

  svm_msg_q_t **vpp_queue;

  uword *handler_by_get_request;

  u32 *free_http_cli_process_node_indices;

  /* Sever's event queue */
  svm_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  u32 app_index;

  /* process node index for evnt scheduling */
  u32 node_index;

  /* Cert key pair for tls */
  u32 ckpair_index;

  //  tw_timer_wheel_2t_1w_2048sl_t tw;
  //  clib_spinlock_t tw_lock;

  u32 prealloc_fifos;
  u32 private_segment_size;
  u32 fifo_size;
  u8 *uri;
  u32 is_static;
  vlib_main_t *vlib_main;
} http_server_main_t;

http_server_main_t http_server_main;

// static void
// http_server_sessions_reader_lock (void)
//{
//  clib_rwlock_reader_lock (&http_server_main.sessions_lock);
//}
//
// static void
// http_server_sessions_reader_unlock (void)
//{
//  clib_rwlock_reader_unlock (&http_server_main.sessions_lock);
//}

// static void
// http_server_sessions_writer_lock (void)
//{
//  clib_rwlock_writer_lock (&http_server_main.sessions_lock);
//}
//
// static void
// http_server_sessions_writer_unlock (void)
//{
//  clib_rwlock_writer_unlock (&http_server_main.sessions_lock);
//}

static http_session_t *
http_server_session_alloc (u32 thread_index)
{
  http_server_main_t *hsm = &http_server_main;
  http_session_t *hs;
  pool_get (hsm->sessions[thread_index], hs);
  memset (hs, 0, sizeof (*hs));
  hs->session_index = hs - hsm->sessions[thread_index];
  hs->thread_index = thread_index;
  hs->timer_handle = ~0;
  return hs;
}

static http_session_t *
http_server_session_get (u32 thread_index, u32 hs_index)
{
  http_server_main_t *hsm = &http_server_main;
  if (pool_is_free_index (hsm->sessions[thread_index], hs_index))
    return 0;
  return pool_elt_at_index (hsm->sessions[thread_index], hs_index);
}

static void
http_server_session_free (http_session_t * hs)
{
  http_server_main_t *hsm = &http_server_main;
  u32 thread = hs->thread_index;
  if (CLIB_DEBUG)
    memset (hs, 0xfa, sizeof (*hs));
  pool_put (hsm->sessions[thread], hs);
}

// static void
// http_server_session_lookup_add (u32 thread_index, u32 s_index, u32 hs_index)
//{
//  http_server_main_t *hsm = &http_server_main;
//  vec_validate (hsm->session_to_http_session[thread_index], s_index);
//  hsm->session_to_http_session[thread_index][s_index] = hs_index;
//}

// static void
// http_server_session_lookup_del (u32 thread_index, u32 s_index)
//{
//  http_server_main_t *hsm = &http_server_main;
//  hsm->session_to_http_session[thread_index][s_index] = ~0;
//}
//
// static http_session_t *
// http_server_session_lookup (u32 thread_index, u32 s_index)
//{
//  http_server_main_t *hsm = &http_server_main;
//  u32 hs_index;
//
//  if (s_index < vec_len (hsm->session_to_http_session[thread_index]))
//    {
//      hs_index = hsm->session_to_http_session[thread_index][s_index];
//      return http_server_session_get (thread_index, hs_index);
//    }
//  return 0;
//}

// static void
// http_server_session_timer_start (http_session_t * hs)
//{
//  u32 hs_handle;
//  hs_handle = hs->thread_index << 24 | hs->session_index;
//  clib_spinlock_lock (&http_server_main.tw_lock);
//  hs->timer_handle = tw_timer_start_2t_1w_2048sl (&http_server_main.tw,
//						  hs_handle, 0, 60);
//  clib_spinlock_unlock (&http_server_main.tw_lock);
//}

// static void
// http_server_session_timer_stop (http_session_t * hs)
//{
//  if (hs->timer_handle == ~0)
//    return;
//  clib_spinlock_lock (&http_server_main.tw_lock);
//  tw_timer_stop_2t_1w_2048sl (&http_server_main.tw, hs->timer_handle);
//  clib_spinlock_unlock (&http_server_main.tw_lock);
//}

// static void
// http_server_session_disconnect (http_session_t * hs)
//{
//  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
//  a->handle = hs->vpp_session_handle;
//  a->app_index = http_server_main.app_index;
//  vnet_disconnect_session (a);
//}

static void
http_process_free (http_server_args * args)
{
  vlib_node_runtime_t *rt;
  vlib_main_t *vm = vlib_get_first_main ();
  http_server_main_t *hsm = &http_server_main;
  vlib_node_t *n;
  u32 node_index;
  http_server_args **save_args;

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
  vec_add1 (hsm->free_http_cli_process_node_indices, node_index);
}

/* *INDENT-OFF* */
// static const char *http_ok =
//    "HTTP/1.1 200 OK\r\n";
//
// static const char *http_response =
//    "Content-Type: text/html\r\n"
//    "Expires: Mon, 11 Jan 1970 10:10:10 GMT\r\n"
//    "Connection: close \r\n"
//    "Pragma: no-cache\r\n"
//    "Content-Length: %d\r\n\r\n%v";

// static const char *http_error_template =
//    "HTTP/1.1 %s\r\n"
//    "Content-Type: text/html\r\n"
//    "Expires: Mon, 11 Jan 1970 10:10:10 GMT\r\n"
//    "Connection: close\r\n"
//    "Pragma: no-cache\r\n"
//    "Content-Length: 0\r\n\r\n";

/* Header, including incantation to suppress favicon.ico requests */
static const char *html_header_template =
    "<html><head><title>%v</title></head>"
    "<link rel=\"icon\" href=\"data:,\">"
    "<body><pre>";

static const char *html_footer =
    "</pre></body></html>\r\n";

static const char *html_header_static =
    "<html><head><title>static reply</title></head>"
    "<link rel=\"icon\" href=\"data:,\">"
    "<body><pre>hello</pre></body></html>\r\n";
/* *INDENT-ON* */

// static u8 *static_http;
// static u8 *static_ok;

static void
http_cli_output (uword arg, u8 * buffer, uword buffer_bytes)
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

void
send_data (void *rpc_args)
{
  http_server_args *args = (http_server_args *) rpc_args;
  http_session_t *hs;
  http_msg_t msg;
  session_t *ts;
  int rv;

  hs = http_server_session_get (args->thread_index, args->hs_index);
  if (!hs)
    {
      clib_warning ("no hs");
      vec_free (args->buf);
      goto cleanup;
    }

  msg.type = HTTP_MSG_REPLY;
  msg.data.content_type = HTTP_CONTENT_TEXT_HTML;
  msg.data.len = vec_len (args->buf);

  ts = session_get (hs->vpp_session_index, hs->thread_index);
  rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  rv = svm_fifo_enqueue (ts->tx_fifo, vec_len (args->buf), args->buf);

  clib_warning ("enqueued %u out of %u", rv, vec_len (args->buf));
  if (rv != vec_len (args->buf))
    {
      hs->tx_buf = args->buf;
      hs->tx_offset = rv;
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }
  else
    {
      vec_free (args->buf);
    }

  if (svm_fifo_set_event (ts->tx_fifo))
    session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);

cleanup:

  clib_mem_free (rpc_args);

  //  u8 * data;
  //  http_server_main_t *hsm = &http_server_main;
  //  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  //  vlib_main_t *vm = vlib_get_main ();
  //  f64 last_sent_timer = vlib_time_now (vm);
  //  u32 offset, bytes_to_send;
  //  f64 delay = 10e-3;
  //
  //  bytes_to_send = vec_len (data);
  //  offset = 0;
  //
  //  while (bytes_to_send > 0)
  //    {
  //      int actual_transfer;
  //
  //      actual_transfer = svm_fifo_enqueue
  //	(hs->tx_fifo, bytes_to_send, data + offset);
  //
  //      /* Made any progress? */
  //      if (actual_transfer <= 0)
  //	{
  ////	  http_server_sessions_reader_unlock ();
  //	  vlib_process_suspend (vm, delay);
  ////	  http_server_sessions_reader_lock ();
  //
  //	  /* 10s deadman timer */
  //	  if (vlib_time_now (vm) > last_sent_timer + 10.0)
  //	    {
  //	      a->handle = hs->vpp_session_handle;
  //	      a->app_index = hsm->app_index;
  //	      vnet_disconnect_session (a);
  //	      break;
  //	    }
  //	  /* Exponential backoff, within reason */
  //	  if (delay < 1.0)
  //	    delay = delay * 2.0;
  //	}
  //      else
  //	{
  //	  last_sent_timer = vlib_time_now (vm);
  //	  offset += actual_transfer;
  //	  bytes_to_send -= actual_transfer;
  //
  //	  if (svm_fifo_set_event (hs->tx_fifo))
  //	    session_send_io_evt_to_thread (hs->tx_fifo,
  //					   SESSION_IO_EVT_TX_FLUSH);
  //	  delay = 10e-3;
  //	}
  //    }
}

// static void
// send_error (http_session_t * hs, char *str)
//{
//  u8 *data;
//
//  data = format (0, http_error_template, str);
//  send_data (hs, data);
//  vec_free (data);
//}

static uword
http_cli_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		  vlib_frame_t * f)
{
  u8 *request = 0, *reply = 0, *html = 0;
  http_server_main_t *hsm = &http_server_main;
  http_server_args **save_args;
  http_server_args *args, *rpc_args;
  unformat_input_t input;
  //  http_session_t *hs;
  int i;

  save_args = vlib_node_get_runtime_data (hsm->vlib_main, rt->node_index);
  args = *save_args;

  //  http_server_sessions_reader_lock ();

  //  hs = http_server_session_get (args->thread_index, args->hs_index);
  //  ASSERT (hs);

  request = args->buf;
  //  if (vec_len (request) < 7)
  //    {
  //      send_error (hs, "400 Bad Request");
  //      goto out;
  //    }
  //
  //  for (i = 0; i < vec_len (request) - 4; i++)
  //    {
  //      if (request[i] == 'G' &&
  //	  request[i + 1] == 'E' &&
  //	  request[i + 2] == 'T' && request[i + 3] == ' ')
  //	goto found;
  //    }
  // bad_request:
  //  send_error (hs, "400 Bad Request");
  //  goto out;

  // found:
  //  /* Lose "GET " */
  //  vec_delete (request, i + 5, 0);

  /* Replace slashes with spaces, stop at the end of the path */
  i = 0;
  while (1)
    {
      if (request[i] == '/')
	request[i] = ' ';
      else if (request[i] == ' ')
	{
	  /* vlib_cli_input is vector-based, no need for a NULL */
	  _vec_len (request) = i;
	  break;
	}
      i++;
      /* Should never happen */
      if (i == vec_len (request))
	{
	  char *msg = "Bad CLI";
	  vec_validate_init_c_string (html, msg, strlen (msg));
	  goto send;
	}
    }

  /* Generate the html header */
  html = format (0, html_header_template, request /* title */ );

  /* Run the command */
  unformat_init_vector (&input, vec_dup (request));
  vlib_cli_input (vm, &input, http_cli_output, (uword) & reply);
  unformat_free (&input);
  request = 0;

  /* Generate the html page */
  html = format (html, "%v", reply);
  html = format (html, html_footer);
  /* And the http reply */
  //  http = format (0, http_ok);
  //  http = format (http, http_response, vec_len (html), html);

send:

  /* Send it */
  rpc_args = clib_mem_alloc (sizeof (*args));
  clib_memcpy_fast (rpc_args, args, sizeof (*args));
  rpc_args->buf = html;

  session_send_rpc_evt_to_thread_force (args->thread_index, send_data,
					rpc_args);

  // out:
  /* Cleanup */
  //  http_server_sessions_reader_unlock ();
  vec_free (reply);
  //  vec_free (html);
  //  vec_free (http);
  vec_free (args->buf);

  http_process_free (args);
  return (0);
}

static void
alloc_http_process (http_server_args * args)
{
  char *name;
  vlib_node_t *n;
  http_server_main_t *hsm = &http_server_main;
  vlib_main_t *vm = hsm->vlib_main;
  uword l = vec_len (hsm->free_http_cli_process_node_indices);
  http_server_args **save_args;

  if (vec_len (hsm->free_http_cli_process_node_indices) > 0)
    {
      n = vlib_get_node (vm, hsm->free_http_cli_process_node_indices[l - 1]);
      vlib_node_set_state (vm, n->index, VLIB_NODE_STATE_POLLING);
      _vec_len (hsm->free_http_cli_process_node_indices) = l - 1;
    }
  else
    {
      static vlib_node_registration_t r = {
	.function = http_cli_process,
	.type = VLIB_NODE_TYPE_PROCESS,
	.process_log2_n_stack_bytes = 16,
	.runtime_data_bytes = sizeof (void *),
      };

      name = (char *) format (0, "http-cli-%d", l);
      r.name = name;
      vlib_register_node (vm, &r);
      vec_free (name);

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
alloc_http_process_callback (void *cb_args)
{
  alloc_http_process ((http_server_args *) cb_args);
}

// static int
// session_rx_request (http_session_t * hs)
//{
//  u32 max_dequeue, cursize;
//  int n_read;
//
//  cursize = vec_len (hs->rx_buf);
//  max_dequeue = svm_fifo_max_dequeue_cons (hs->rx_fifo);
//  if (PREDICT_FALSE (max_dequeue == 0))
//    return -1;
//
//  vec_validate (hs->rx_buf, cursize + max_dequeue - 1);
//  n_read = app_recv_stream_raw (hs->rx_fifo, hs->rx_buf + cursize,
//				max_dequeue, 0, 0 /* peek */ );
//  ASSERT (n_read == max_dequeue);
//  if (svm_fifo_is_empty_cons (hs->rx_fifo))
//    svm_fifo_unset_event (hs->rx_fifo);
//
//  _vec_len (hs->rx_buf) = cursize + n_read;
//  return 0;
//}

static int
http_server_rx_callback (session_t * s)
{
  http_server_args args = {};
  http_session_t *hs;
  int rv;

  //  http_server_sessions_reader_lock ();
  //
  //  hs = http_server_session_lookup (s->thread_index, s->session_index);
  //  if (!hs || hs->session_state != HTTP_STATE_ESTABLISHED)
  //    return -1;

  hs = http_server_session_get (s->thread_index, s->opaque);

  rv = svm_fifo_dequeue (s->rx_fifo, sizeof (hs->msg), (u8 *) &hs->msg);
  ASSERT (rv == sizeof (hs->msg));
  //  rv = session_rx_request (hs);
  //  if (rv)
  //    return rv;

  /* send the command to a new/recycled vlib process */
  vec_validate (args.buf, hs->msg.data.len - 1);
  rv = svm_fifo_dequeue (s->rx_fifo, hs->msg.data.len, args.buf);
  ASSERT (rv == hs->msg.data.len);
  vec_set_len (args.buf, rv);

  args.hs_index = hs->session_index;
  args.thread_index = s->thread_index;

  //  http_server_sessions_reader_unlock ();

  /* Send RPC request to main thread */
  if (vlib_get_thread_index () != 0)
    vlib_rpc_call_main_thread (alloc_http_process_callback, (u8 *) & args,
			       sizeof (args));
  else
    alloc_http_process (&args);
  return 0;
}

static int
http_server_tx_callback (session_t *ts)
{
  http_session_t *hs;
  u32 to_send;
  int rv;

  clib_warning ("hit");
  hs = http_server_session_get (ts->thread_index, ts->opaque);
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
      clib_warning ("enq %u offset %u", rv, hs->tx_offset);
    }
  else
    {
      vec_free (hs->tx_buf);
      clib_warning ("done");
      //      os_panic ();
    }

  if (svm_fifo_set_event (ts->tx_fifo))
    session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);

  return 0;
}

// static int
// http_server_rx_callback_static (session_t * s)
//{
//  http_session_t *hs;
//  u32 request_len;
//  u8 *request = 0;
//  int i, rv;
//
//  hs = http_server_session_lookup (s->thread_index, s->session_index);
//  if (!hs || hs->session_state == HTTP_STATE_CLOSED)
//    return 0;
//
//  /* ok 200 was sent */
//  if (hs->session_state == HTTP_STATE_OK_SENT)
//    goto send_data;
//
//  rv = session_rx_request (hs);
//  if (rv)
//    goto wait_for_data;
//
//  request = hs->rx_buf;
//  request_len = vec_len (request);
//  if (vec_len (request) < 7)
//    {
//      send_error (hs, "400 Bad Request");
//      goto close_session;
//    }
//
//  for (i = 0; i < request_len - 4; i++)
//    {
//      if (request[i] == 'G' &&
//	  request[i + 1] == 'E' &&
//	  request[i + 2] == 'T' && request[i + 3] == ' ')
//	goto find_end;
//    }
//  send_error (hs, "400 Bad Request");
//  goto close_session;
//
// find_end:
//
//  /* check for the end sequence: /r/n/r/n */
//  if (request[request_len - 1] != 0xa || request[request_len - 3] != 0xa
//      || request[request_len - 2] != 0xd || request[request_len - 4] != 0xd)
//    goto wait_for_data;
//
//  /* send 200 OK first */
//  send_data (hs, static_ok);
//  hs->session_state = HTTP_STATE_OK_SENT;
//  goto postpone;
//
// send_data:
//  send_data (hs, static_http);
//
// close_session:
//  http_server_session_disconnect (hs);
//  return 0;
//
// postpone:
//  (void) svm_fifo_set_event (hs->rx_fifo);
//  session_send_io_evt_to_thread (hs->rx_fifo, SESSION_IO_EVT_BUILTIN_RX);
//  return 0;
//
// wait_for_data:
//  return 0;
//}

static int
http_server_session_accept_callback (session_t *ts)
{
  //  http_server_main_t *hsm = &http_server_main;
  http_session_t *hs;

  //  hsm->vpp_queue[s->thread_index] =
  //    session_main_get_vpp_event_queue (s->thread_index);

  //  if (!hsm->is_static)
  //    http_server_sessions_writer_lock ();

  hs = http_server_session_alloc (ts->thread_index);
  ts->opaque = hs->session_index;
  //  http_server_session_lookup_add (s->thread_index, s->session_index,
  //				  hs->session_index);
  hs->rx_fifo = ts->rx_fifo;
  hs->tx_fifo = ts->tx_fifo;
  hs->vpp_session_index = ts->session_index;
  hs->vpp_session_handle = session_handle (ts);
  hs->session_state = HTTP_STATE_ESTABLISHED;
  //  http_server_session_timer_start (hs);

  //  if (!hsm->is_static)
  //    http_server_sessions_writer_unlock ();

  ts->session_state = SESSION_STATE_READY;
  return 0;
}

static void
http_server_session_disconnect_callback (session_t * s)
{
  http_server_main_t *hsm = &http_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = hsm->app_index;
  vnet_disconnect_session (a);
}

static void
http_server_session_reset_callback (session_t * s)
{
  http_server_main_t *hsm = &http_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = hsm->app_index;
  vnet_disconnect_session (a);
}

static int
http_server_session_connected_callback (u32 app_index, u32 api_context,
					session_t * s, session_error_t err)
{
  clib_warning ("called...");
  return -1;
}

static int
http_server_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static void
http_server_cleanup_callback (session_t * s, session_cleanup_ntf_t ntf)
{
  //  http_server_main_t *hsm = &http_server_main;
  http_session_t *hs;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  //  if (!hsm->is_static)
  //    http_server_sessions_writer_lock ();

  hs = http_server_session_get (s->thread_index, s->opaque);
  if (!hs)
    return;

  //  http_server_session_lookup_del (hs->thread_index, hs->vpp_session_index);
  vec_free (hs->rx_buf);
  //  http_server_session_timer_stop (hs);
  http_server_session_free (hs);

  // done:

  //  if (!hsm->is_static)
  //    http_server_sessions_writer_unlock ();
}

static session_cb_vft_t http_server_session_cb_vft = {
  .session_accept_callback = http_server_session_accept_callback,
  .session_disconnect_callback = http_server_session_disconnect_callback,
  .session_connected_callback = http_server_session_connected_callback,
  .add_segment_callback = http_server_add_segment_callback,
  .builtin_app_rx_callback = http_server_rx_callback,
  .builtin_app_tx_callback = http_server_tx_callback,
  .session_reset_callback = http_server_session_reset_callback,
  .session_cleanup_callback = http_server_cleanup_callback,
};

static int
http_server_attach ()
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  http_server_main_t *hsm = &http_server_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;
  u32 segment_size = 128 << 20;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  if (hsm->private_segment_size)
    segment_size = hsm->private_segment_size;

  a->api_client_index = ~0;
  a->name = format (0, "test_http_server");
  a->session_cb_vft = &http_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 4 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = hsm->prealloc_fifos;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      clib_warning ("failed to attach server");
      return -1;
    }
  vec_free (a->name);
  hsm->app_index = a->app_index;

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  hsm->ckpair_index = ck_pair->index;

  return 0;
}

static int
http_transport_needs_crypto (transport_proto_t proto)
{
  return proto == TRANSPORT_PROTO_TLS || proto == TRANSPORT_PROTO_DTLS ||
	 proto == TRANSPORT_PROTO_QUIC;
}

static int
http_server_listen ()
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  http_server_main_t *hsm = &http_server_main;
  vnet_listen_args_t _a, *a = &_a;
  char *uri = "tcp://0.0.0.0/80";
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->app_index = hsm->app_index;

  if (hsm->uri)
    uri = (char *) hsm->uri;

  if (parse_uri (uri, &sep))
    return -1;

  sep.transport_proto = TRANSPORT_PROTO_HTTP;

  clib_memcpy (&a->sep_ext, &sep, sizeof (sep));
  if (http_transport_needs_crypto (a->sep_ext.transport_proto))
    {
      session_endpoint_alloc_ext_cfg (&a->sep_ext,
				      TRANSPORT_ENDPT_EXT_CFG_CRYPTO);
      a->sep_ext.ext_cfg->crypto.ckpair_index = hsm->ckpair_index;
    }

  rv = vnet_listen (a);
  if (a->sep_ext.ext_cfg)
    clib_mem_free (a->sep_ext.ext_cfg);
  return rv;
}

// static void
// http_server_session_close_cb (void *hs_handlep)
//{
//  http_session_t *hs;
//  uword hs_handle;
//  hs_handle = pointer_to_uword (hs_handlep);
//  hs = http_server_session_get (hs_handle >> 24, hs_handle & 0x00FFFFFF);
//  if (!hs)
//    return;
//  hs->timer_handle = ~0;
//  http_server_session_disconnect (hs);
//}

// static void
// http_expired_timers_dispatch (u32 * expired_timers)
//{
//  u32 hs_handle;
//  int i;
//
//  for (i = 0; i < vec_len (expired_timers); i++)
//    {
//      /* Get session handle. The first bit is the timer id */
//      hs_handle = expired_timers[i] & 0x7FFFFFFF;
//      session_send_rpc_evt_to_thread (hs_handle >> 24,
//				      http_server_session_close_cb,
//				      uword_to_pointer (hs_handle, void *));
//    }
//}

// static uword
// http_server_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
//		     vlib_frame_t * f)
//{
//  http_server_main_t *hsm = &http_server_main;
//  f64 now, timeout = 1.0;
//  uword *event_data = 0;
//  uword __clib_unused event_type;
//
//  while (1)
//    {
//      vlib_process_wait_for_event_or_clock (vm, timeout);
//      now = vlib_time_now (vm);
//      event_type = vlib_process_get_events (vm, (uword **) & event_data);
//
//      /* expire timers */
//      clib_spinlock_lock (&http_server_main.tw_lock);
//      tw_timer_expire_timers_2t_1w_2048sl (&hsm->tw, now);
//      clib_spinlock_unlock (&http_server_main.tw_lock);
//
//      vec_reset_length (event_data);
//    }
//  return 0;
//}
//
// VLIB_REGISTER_NODE (http_server_process_node) =
//{
//  .function = http_server_process,
//  .type = VLIB_NODE_TYPE_PROCESS,
//  .name = "http-server-process",
//  .state = VLIB_NODE_STATE_DISABLED,
//};

static int
http_server_create (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  http_server_main_t *hsm = &http_server_main;
  u32 num_threads;
  //  vlib_node_t *n;

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (hsm->vpp_queue, num_threads - 1);
  vec_validate (hsm->sessions, num_threads - 1);
  vec_validate (hsm->session_to_http_session, num_threads - 1);

  clib_rwlock_init (&hsm->sessions_lock);
  //  clib_spinlock_init (&hsm->tw_lock);

  if (http_server_attach ())
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  if (http_server_listen ())
    {
      clib_warning ("failed to start listening");
      return -1;
    }

  //  /* Init timer wheel and process */
  //  tw_timer_wheel_init_2t_1w_2048sl (&hsm->tw, http_expired_timers_dispatch,
  //				    1 /* timer interval */ , ~0);
  //  vlib_node_set_state (vm, http_server_process_node.index,
  //		       VLIB_NODE_STATE_POLLING);
  //  n = vlib_get_node (vm, http_server_process_node.index);
  //  vlib_start_process (vm, n->runtime_index);

  return 0;
}

static clib_error_t *
http_server_create_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  http_server_main_t *hsm = &http_server_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u64 seg_size;
  u8 *html;
  int rv;

  hsm->prealloc_fifos = 0;
  hsm->private_segment_size = 0;
  hsm->fifo_size = 0;
  hsm->is_static = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    goto start_server;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "static"))
	hsm->is_static = 1;
      else
	if (unformat (line_input, "prealloc-fifos %d", &hsm->prealloc_fifos))
	;
      else if (unformat (line_input, "private-segment-size %U",
			 unformat_memory_size, &seg_size))
	{
	  if (seg_size >= 0x100000000ULL)
	    {
	      vlib_cli_output (vm, "private segment size %llu, too large",
			       seg_size);
	      return 0;
	    }
	  hsm->private_segment_size = seg_size;
	}
      else if (unformat (line_input, "fifo-size %d", &hsm->fifo_size))
	hsm->fifo_size <<= 10;
      else if (unformat (line_input, "uri %s", &hsm->uri))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

start_server:

  if (hsm->my_client_index != (u32) ~ 0)
    return clib_error_return (0, "test http server is already running");

  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );

  if (hsm->is_static)
    {
      //      http_server_session_cb_vft.builtin_app_rx_callback =
      //	http_server_rx_callback_static;
      html = format (0, html_header_static);
      //      static_http = format (0, http_response, vec_len (html), html);
      //      static_ok = format (0, http_ok);
    }
  rv = http_server_create (vm);
  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "server_create returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (http_server_create_command, static) =
{
  .path = "test http server",
  .short_help = "test http server",
  .function = http_server_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
http_server_main_init (vlib_main_t * vm)
{
  http_server_main_t *hsm = &http_server_main;

  hsm->my_client_index = ~0;
  hsm->vlib_main = vm;
  return 0;
}

VLIB_INIT_FUNCTION (http_server_main_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
