/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <http/http.h>
#include <http/http_header_names.h>
#include <http/http_content_types.h>
#include <http/http_status_codes.h>
#include <vppinfra/unix.h>

#define foreach_hc_s_flag                                                     \
  _ (1, IS_CLOSED)                                                            \
  _ (2, PRINTABLE_BODY)                                                       \
  _ (4, CHUNKED_BODY)                                                         \
  _ (8, IS_PARENT)

typedef enum hc_s_flag_
{
#define _(n, s) HC_S_FLAG_##s = n,
  foreach_hc_s_flag
#undef _
} hc_s_flags;

typedef struct
{
  u64 max_req;
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
  u8 session_flags;
  hc_stats_t stats;
  u64 data_offset;
  u64 body_recv;
  http_header_table_t resp_headers;
  u8 *http_response;
  u8 *response_status;
  FILE *file_ptr;
  union
  {
    u32 child_count;
    u32 parent_index;
  };
  u32 http_session_index;
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
  u64 reqs_per_session;
  u64 reqs_remainder;
  f64 duration;
  bool repeat;
  bool multi_session;
  u32 done_count;
  u32 connected_counter;
  u32 worker_index;
  u32 max_sessions;
  u32 max_streams;
  u32 private_segment_size;
  u32 prealloc_fifos;
  u32 fifo_size;
  u32 rx_fifo_size;
  u8 *appns_id;
  u64 appns_secret;
  clib_spinlock_t lock;
  bool was_transport_closed;
  u32 ckpair_index;
  u64 max_body_size;
  http_version_t http_version;
} hc_main_t;

typedef enum
{
  HC_CONNECT_FAILED = 1,
  HC_TRANSPORT_CLOSED,
  HC_REPLY_RECEIVED,
  HC_GENERIC_ERR,
  HC_FOPEN_FAILED,
  HC_REPEAT_DONE,
  HC_MAX_STREAMS_HIT,
} hc_cli_signal_t;

#define mime_printable_max_len 35
const char mime_printable[][mime_printable_max_len] = {
  "text/\0",
  "application/json\0",
  "application/javascript\0",
  "application/x-yaml\0",
  "application/x-www-form-urlencoded\0",
  "application/xml\0",
  "application/x-sh\0",
  "application/x-tex\0",
  "application/x-javascript\0",
  "application/x-powershell\0"
};
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
  return pool_elt_at_index (wrk->sessions, session_index);
}

static hc_session_t *
hc_session_alloc (hc_worker_t *wrk)
{
  hc_session_t *s;

  pool_get_zero (wrk->sessions, s);
  s->session_index = s - wrk->sessions;
  s->thread_index = wrk->thread_index;
  HTTP_DBG (1, "[%u]%u", s->thread_index, s->session_index);

  return s;
}

static int
hc_request (session_t *s, hc_worker_t *wrk, hc_session_t *hc_session)
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

  rv =
    svm_fifo_enqueue (s->tx_fifo, wrk->msg.data.target_path_len, hcm->target);
  ASSERT (rv == wrk->msg.data.target_path_len);

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
hc_connect_streams (u64 parent_handle, u32 parent_index)
{
  hc_main_t *hcm = &hc_main;
  vnet_connect_args_t _a, *a = &_a;
  hc_worker_t *wrk;
  hc_session_t *hs;
  u32 i;
  int rv;
  session_t *s;

  clib_memset (a, 0, sizeof (*a));
  clib_memcpy (&a->sep_ext, &hcm->connect_sep, sizeof (hcm->connect_sep));
  a->sep_ext.parent_handle = parent_handle;
  a->app_index = hcm->app_index;

  wrk = hc_worker_get (session_thread_from_handle (parent_handle));

  for (i = 0; i < (hcm->max_streams - 1); i++)
    {
      hs = hc_session_alloc (wrk);
      hs->parent_index = parent_index;
      a->api_context = hs->session_index;

      rv = vnet_connect_stream (a);
      if (rv)
	{
	  clib_warning (0, "connect returned: %U", format_session_error, rv);
	  if (rv == SESSION_E_MAX_STREAMS_HIT)
	    vlib_process_signal_event_mt (
	      vlib_get_main (), hcm->cli_node_index, HC_MAX_STREAMS_HIT, 0);
	  else
	    vlib_process_signal_event_mt (
	      vlib_get_main (), hcm->cli_node_index, HC_CONNECT_FAILED, 0);
	  return -1;
	}
      s = session_get_from_handle (a->sh);
      hs->http_session_index = s->session_index;
      hs->stats.max_req = hcm->reqs_per_session;
      hs->stats.start = vlib_time_now (wrk->vlib_main);
      if (hc_request (s, wrk, hs))
	return -1;
    }

  return 0;
}

static int
hc_session_connected_callback (u32 app_index, u32 ho_index, session_t *s,
			       session_error_t err)
{
  hc_main_t *hcm = &hc_main;
  hc_worker_t *wrk;
  hc_session_t *hc_session, *ho_session;
  hc_http_header_t *header;
  http_version_t http_version;
  u8 *f = 0;
  u32 s_index;

  if (err)
    {
      clib_warning ("connected error: %U", format_session_error, err);
      vlib_process_signal_event_mt (vlib_get_main (), hcm->cli_node_index,
				    HC_CONNECT_FAILED, 0);
      return -1;
    }

  ho_session = hc_session_get (ho_index, transport_cl_thread ());
  wrk = hc_worker_get (s->thread_index);
  hc_session = hc_session_alloc (wrk);
  s_index = hc_session->session_index;
  clib_memcpy_fast (hc_session, ho_session, sizeof (*hc_session));
  hc_session->session_index = s_index;
  hc_session->thread_index = s->thread_index;
  hc_session->http_session_index = s->session_index;

  clib_spinlock_lock_if_init (&hcm->lock);
  hcm->connected_counter++;
  clib_spinlock_unlock_if_init (&hcm->lock);

  hc_session->body_recv = 0;
  s->opaque = hc_session->session_index;
  wrk->session_index = hc_session->session_index;

  if (hcm->multi_session)
    {
      hc_session->stats.max_req = hcm->reqs_per_session;
      clib_spinlock_lock_if_init (&hcm->lock);
      /* add remaining requests to the first connected session */
      if (hcm->connected_counter == 1)
	{
	  hc_session->stats.max_req += hcm->reqs_remainder;
	}
      clib_spinlock_unlock_if_init (&hcm->lock);
    }
  else
    {
      hc_session->stats.max_req = hcm->reqs_per_session;
      hcm->worker_index = s->thread_index;
    }
  if (hcm->filename)
    {
      f = format (0, "/tmp/%s%c", hcm->filename, 0);
      hc_session->file_ptr = fopen ((char *) f, "w");
      vec_free (f);
      if (hc_session->file_ptr == NULL)
	{
	  vlib_process_signal_event_mt (wrk->vlib_main, hcm->cli_node_index,
					HC_FOPEN_FAILED, 0);
	  return -1;
	}
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
      /* request target len must be without null termination */
      wrk->msg.data.target_path_len = strlen ((char *) hcm->target);
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

  hc_session->stats.start = vlib_time_now (wrk->vlib_main);

  if (hc_request (s, wrk, hc_session))
    return -1;

  http_version = http_session_get_version (s);
  if (http_version == HTTP_VERSION_2 && hcm->max_streams > 1)
    {
      ASSERT (hc_session->session_flags & HC_S_FLAG_IS_PARENT);
      HTTP_DBG (1, "parent connected, going to open %u streams",
		hcm->max_streams - 1);
      hc_session->child_count = hcm->max_streams - 1;
      if (hc_connect_streams (session_handle (s), hc_session->session_index))
	return -1;
    }

  return 0;
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

  HTTP_DBG (1, "transport closed");
  clib_spinlock_lock_if_init (&hcm->lock);
  if (s->session_state == SESSION_STATE_TRANSPORT_CLOSED)
    {
      hcm->was_transport_closed = true;
    }

  /* send an event when all sessions are closed */
  if (hcm->done_count >= (hcm->max_sessions * hcm->max_streams))
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
  hc_worker_t *wrk = hc_worker_get (s->thread_index);
  int rv;

  HTTP_DBG (1, "transport reset");
  vlib_process_signal_event_mt (wrk->vlib_main, hcm->cli_node_index,
				HC_TRANSPORT_CLOSED, 0);
  hc_session = hc_session_get (s->opaque, s->thread_index);
  hc_session->session_flags |= HC_S_FLAG_IS_CLOSED;

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
  int send_err = 0;
  http_version_t http_version;

  if (hc_session->session_flags & HC_S_FLAG_IS_CLOSED)
    {
      clib_warning ("hc_session_index[%d] is closed", s->opaque);
      return -1;
    }

  max_deq = svm_fifo_max_dequeue_cons (s->rx_fifo);
  if (PREDICT_FALSE (max_deq == 0))
    {
      HTTP_DBG (1, "no data to deq");
      return 0;
    }

  if (hc_session->to_recv == 0)
    {
      http_reset_header_table (&hc_session->resp_headers);
      rv = svm_fifo_dequeue (s->rx_fifo, sizeof (msg), (u8 *) &msg);
      ASSERT (rv == sizeof (msg));

      if (msg.type != HTTP_MSG_REPLY)
	{
	  clib_warning ("unexpected msg type %d", msg.type);
	  vlib_process_signal_event_mt (wrk->vlib_main, hcm->cli_node_index,
					HC_GENERIC_ERR, 0);
	  return -1;
	}

      HTTP_DBG (1, "hc_session_index[%u]%u %U content-length: %lu",
		s->thread_index, s->opaque, format_http_status_code, msg.code,
		msg.data.body_len);

      if (msg.data.headers_len)
	{
	  http_init_header_table_buf (&hc_session->resp_headers, msg);

	  if (!hcm->repeat)
	    {
	      http_version = http_session_get_version (s);
	      hc_session->response_status =
		format (0, "%U %U", format_http_version, http_version,
			format_http_status_code, msg.code);
	    }

	  svm_fifo_dequeue_drop (s->rx_fifo, msg.data.headers_offset);

	  rv = svm_fifo_dequeue (s->rx_fifo, msg.data.headers_len,
				 hc_session->resp_headers.buf);
	  ASSERT (rv == msg.data.headers_len);
	  msg.data.body_offset -=
	    msg.data.headers_len + msg.data.headers_offset;

	  http_build_header_table (&hc_session->resp_headers, msg);
	  HTTP_DBG (2, "%U", format_hash,
		    hc_session->resp_headers.value_by_name);
	  const http_token_t *content_type = http_get_header (
	    &hc_session->resp_headers,
	    http_header_name_token (HTTP_HEADER_CONTENT_TYPE));
	  if (content_type)
	    {
	      for (u8 i = 0; i < sizeof (mime_printable) /
				   (sizeof (char) * mime_printable_max_len);
		   i++)
		{
		  u8 mime_len =
		    clib_strnlen (mime_printable[i], mime_printable_max_len);
		  if (content_type->len >= mime_len &&
		      clib_strncmp (content_type->base, mime_printable[i],
				    mime_len) == 0)
		    {
		      hc_session->session_flags |= HC_S_FLAG_PRINTABLE_BODY;
		      break;
		    }
		}
	    }
	}

      if (msg.data.body_len == 0)
	{
	  svm_fifo_dequeue_drop_all (s->rx_fifo);
	  /* we don't need to print warning about binary content */
	  hc_session->session_flags |= HC_S_FLAG_PRINTABLE_BODY;
	  goto done;
	}

      /* drop everything up to body */
      svm_fifo_dequeue_drop (s->rx_fifo, msg.data.body_offset);
      hc_session->to_recv = msg.data.body_len;
      if (msg.code != HTTP_STATUS_OK && hc_session->to_recv == 0)
	{
	  goto done;
	}

      if (msg.data.body_len > hcm->max_body_size || hcm->filename)
	hc_session->session_flags |= HC_S_FLAG_CHUNKED_BODY;
      vec_validate (hc_session->http_response,
		    (hc_session->session_flags & HC_S_FLAG_CHUNKED_BODY ?
		       hcm->rx_fifo_size - 1 :
		       msg.data.body_len - 1));
      vec_reset_length (hc_session->http_response);
    }

  max_deq = (svm_fifo_max_dequeue (s->rx_fifo) > hcm->max_body_size ?
	       hcm->rx_fifo_size :
	       svm_fifo_max_dequeue (s->rx_fifo));
  if (!max_deq)
    {
      HTTP_DBG (1, "body not yet received");
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
  if (svm_fifo_needs_deq_ntf (s->rx_fifo, n_deq))
    {
      svm_fifo_clear_deq_ntf (s->rx_fifo);
      session_program_transport_io_evt (s->handle, SESSION_IO_EVT_RX);
    }
  if (!(hc_session->session_flags & HC_S_FLAG_CHUNKED_BODY))
    vec_set_len (hc_session->http_response, curr + n_deq);
  ASSERT (hc_session->to_recv >= rv);
  hc_session->to_recv -= rv;
  hc_session->body_recv += rv;
  HTTP_DBG (1, "read %u, left to recv %u", n_deq, hc_session->to_recv);
  if (hcm->filename)
    {
      if (hc_session->file_ptr == NULL)
	{
	  vlib_process_signal_event_mt (wrk->vlib_main, hcm->cli_node_index,
					HC_FOPEN_FAILED, 0);
	  goto done;
	}
      fwrite (hc_session->http_response, sizeof (u8), rv,
	      hc_session->file_ptr);
    }

done:
  if (hc_session->to_recv == 0)
    {
      hc_session->stats.end = vlib_time_now (wrk->vlib_main);
      hc_session->stats.elapsed_time =
	hc_session->stats.end - hc_session->stats.start;
      if (hcm->repeat)
	{
	  hc_session->stats.request_count++;

	  if (hc_session->stats.elapsed_time >= hcm->duration &&
	      hc_session->stats.request_count >= hc_session->stats.max_req)
	    {
	      HTTP_DBG (1, "repeat done");
	      if (hc_session->session_flags & HC_S_FLAG_IS_PARENT)
		{
		  /* parent must be closed last */
		  if (hc_session->child_count != 0)
		    hc_session->session_flags |= HC_S_FLAG_IS_CLOSED;
		  else
		    hc_session_disconnect_callback (s);
		}
	      else
		{
		  hc_session_disconnect_callback (s);
		  hc_session_t *parent = hc_session_get (
		    hc_session->parent_index, hc_session->thread_index);
		  parent->child_count--;
		  if (parent->child_count == 0 &&
		      parent->session_flags & HC_S_FLAG_IS_CLOSED)
		    hc_session_disconnect_callback (session_get (
		      parent->http_session_index, parent->thread_index));
		}
	    }
	  else
	    {
	      HTTP_DBG (1, "doing another repeat");
	      send_err = hc_request (s, wrk, hc_session);
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

static void
hc_ho_cleanup_callback (session_t *s)
{
  HTTP_DBG (1, "ho index %u", s->opaque);
  hc_worker_t *wrk = hc_worker_get (transport_cl_thread ());
  pool_put_index (wrk->sessions, s->opaque);
}

static session_cb_vft_t hc_session_cb_vft = {
  .session_connected_callback = hc_session_connected_callback,
  .session_disconnect_callback = hc_session_disconnect_callback,
  .session_transport_closed_callback = hc_session_transport_closed_callback,
  .session_reset_callback = hc_session_reset_callback,
  .builtin_app_rx_callback = hc_rx_callback,
  .builtin_app_tx_callback = hc_tx_callback,
  .half_open_cleanup_callback = hc_ho_cleanup_callback,
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
    hcm->fifo_size ? hcm->fifo_size : 32 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] =
    hcm->fifo_size ? hcm->fifo_size : 32 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = hcm->prealloc_fifos;
  a->options[APP_OPTIONS_TLS_ENGINE] = CRYPTO_ENGINE_OPENSSL;
  hcm->rx_fifo_size = a->options[APP_OPTIONS_RX_FIFO_SIZE];
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

static void
hc_connect_rpc (void *rpc_args)
{
  vnet_connect_args_t *a = rpc_args;
  int rv = ~0;
  hc_main_t *hcm = &hc_main;
  hc_worker_t *wrk;
  hc_session_t *ho_hs;

  for (u32 i = 0; i < hcm->max_sessions; i++)
    {
      /* allocate half-open session */
      wrk = hc_worker_get (transport_cl_thread ());
      ho_hs = hc_session_alloc (wrk);
      ho_hs->session_flags |= HC_S_FLAG_IS_PARENT;
      a->api_context = ho_hs->session_index;

      rv = vnet_connect (a);
      if (rv)
	clib_warning (0, "connect returned: %U", format_session_error, rv);
    }

  session_endpoint_free_ext_cfgs (&a->sep_ext);
  vec_free (a);
}

static void
hc_connect ()
{
  hc_main_t *hcm = &hc_main;
  vnet_connect_args_t *a = 0;
  transport_endpt_ext_cfg_t *ext_cfg;
  transport_endpt_cfg_http_t http_cfg = { (u32) hcm->timeout, 0, 0 };

  vec_validate (a, 0);
  clib_memset (a, 0, sizeof (a[0]));
  clib_memcpy (&a->sep_ext, &hcm->connect_sep, sizeof (hcm->connect_sep));
  a->app_index = hcm->app_index;

  if (hcm->connect_sep.flags & SESSION_ENDPT_CFG_F_SECURE)
    {
      ext_cfg = session_endpoint_add_ext_cfg (
	&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
	sizeof (transport_endpt_crypto_cfg_t));
      ext_cfg->crypto.ckpair_index = hcm->ckpair_index;
      switch (hcm->http_version)
	{
	case HTTP_VERSION_1:
	  ext_cfg->crypto.alpn_protos[0] = TLS_ALPN_PROTO_HTTP_1_1;
	  break;
	case HTTP_VERSION_2:
	  ext_cfg->crypto.alpn_protos[0] = TLS_ALPN_PROTO_HTTP_2;
	  break;
	default:
	  break;
	}
    }
  else
    {
      if (hcm->http_version == HTTP_VERSION_2)
	http_cfg.flags |= HTTP_ENDPT_CFG_F_HTTP2_PRIOR_KNOWLEDGE;
    }

  ext_cfg = session_endpoint_add_ext_cfg (
    &a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (http_cfg));
  clib_memcpy (ext_cfg->data, &http_cfg, sizeof (http_cfg));

  session_send_rpc_evt_to_thread_force (transport_cl_thread (), hc_connect_rpc,
					a);
}

static void
hc_get_req_stats (vlib_main_t *vm)
{
  hc_main_t *hcm = &hc_main;

  if (hcm->repeat || hcm->verbose)
    {
      hc_worker_t *wrk;
      hc_session_t *hc_session;
      vec_foreach (wrk, hcm->wrk)
	{
	  pool_foreach (hc_session, wrk->sessions)
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

      if (hcm->repeat)
	{
	  vlib_cli_output (vm,
			   "* %d request(s) in %.6fs\n"
			   "* avg latency %.4fms\n"
			   "* %.2f req/sec",
			   hc_stats.request_count, hc_stats.elapsed_time,
			   (hc_stats.elapsed_time / hc_stats.request_count) *
			     1000,
			   hc_stats.request_count / hc_stats.elapsed_time);
	}
      else
	{
	  vlib_cli_output (vm, "* latency: %.4fms",
			   hc_stats.elapsed_time * 1000);
	}
    }
}

static clib_error_t *
hc_get_event (vlib_main_t *vm)
{
  hc_main_t *hcm = &hc_main;
  uword event_type, *event_data = 0;
  clib_error_t *err = NULL;
  u64 event_timeout;
  hc_worker_t *wrk;
  hc_session_t *hc_session;

  event_timeout = hcm->timeout ? hcm->timeout : 10;
  if (event_timeout == hcm->duration)
    event_timeout += 5;
  vlib_process_wait_for_event_or_clock (vm, event_timeout);
  event_type = vlib_process_get_events (vm, &event_data);
  hc_get_req_stats (vm);

  switch (event_type)
    {
    case ~0:
      err = clib_error_return (0, "error: timeout");
      break;
    case HC_CONNECT_FAILED:
      err = clib_error_return (0, "error: failed to connect");
      break;
    case HC_MAX_STREAMS_HIT:
      err = clib_error_return (0, "error: max streams hit");
      break;
    case HC_TRANSPORT_CLOSED:
      err = clib_error_return (0, "error: transport closed");
      break;
    case HC_GENERIC_ERR:
      err = clib_error_return (0, "error: unknown");
      break;
    case HC_FOPEN_FAILED:
      err = clib_error_return (0, "* couldn't open file %v", hcm->filename);
      break;
    case HC_REPLY_RECEIVED:
      if (hcm->filename)
	{
	  wrk = hc_worker_get (hcm->worker_index);
	  hc_session = hc_session_get (wrk->session_index, wrk->thread_index);
	  vlib_cli_output (vm, "< %v\n%U\n* %u bytes saved to file (/tmp/%s)",
			   hc_session->response_status,
			   format_http_header_table, &hc_session->resp_headers,
			   "< ", hc_session->body_recv, hcm->filename);
	  fclose (hc_session->file_ptr);
	}
      else if (hcm->verbose)
	{
	  wrk = hc_worker_get (hcm->worker_index);
	  hc_session = hc_session_get (wrk->session_index, wrk->thread_index);
	  vlib_cli_output (vm, "< %v\n%U\n", hc_session->response_status,
			   format_http_header_table, &hc_session->resp_headers,
			   "< ");
	  /* if the body was read in chunks and not saved to file - that
	     means we've hit the response body size limit */
	  if (hc_session->session_flags & HC_S_FLAG_CHUNKED_BODY)
	    vlib_cli_output (
	      vm, "* response body over limit, read total %llu bytes",
	      hc_session->body_recv);
	  else
	    {
	      if (hc_session->session_flags & HC_S_FLAG_PRINTABLE_BODY)
		vlib_cli_output (vm, "%v", hc_session->http_response);
	      else
		vlib_cli_output (vm,
				 "* binary file, not printing!\n* consider "
				 "saving to file with the 'file' option");
	    }
	}
      break;
    case HC_REPEAT_DONE:
      break;
    default:
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
      wrk->vlib_main = vlib_get_main_by_index (wrk->thread_index);
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
  pool_foreach (hc_session, wrk->sessions)
    {
      http_free_header_table (&hc_session->resp_headers);
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
  u64 mem_size, repeat_count = 0;
  u8 *appns_id = 0;
  u8 *path = 0;
  u8 *file_data;
  hc_http_header_t new_header;
  u8 *name;
  u8 *value;
  int rv;
  hcm->timeout = 10;
  hcm->duration = 0;
  hcm->repeat = false;
  hcm->multi_session = false;
  hcm->done_count = 0;
  hcm->connected_counter = 0;
  hcm->max_sessions = 1;
  hcm->max_streams = 1;
  hcm->prealloc_fifos = 0;
  hcm->private_segment_size = 0;
  hcm->fifo_size = 0;
  hcm->was_transport_closed = false;
  hcm->verbose = false;
  hcm->http_version = HTTP_VERSION_NA;
  /* default max - 64MB */
  hcm->max_body_size = 64 << 20;
  hc_stats.request_count = 0;
  hc_stats.elapsed_time = 0;
  vec_free (hcm->filename);

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
      else if (unformat (line_input, "repeat %d", &repeat_count))
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
      else if (unformat (line_input, "streams %d", &hcm->max_streams))
	{
	  if (hcm->max_streams <= 1)
	    {
	      err = clib_error_return (0, "streams must be > 1");
	      goto done;
	    }
	}
      else if (unformat (line_input, "prealloc-fifos %d",
			 &hcm->prealloc_fifos))
	;
      else if (unformat (line_input, "max-body-size %U", unformat_memory_size,
			 &hcm->max_body_size))
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
      else if (unformat (line_input, "http1"))
	hcm->http_version = HTTP_VERSION_1;
      else if (unformat (line_input, "http2"))
	hcm->http_version = HTTP_VERSION_2;
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

  if (hcm->duration && repeat_count)
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

  if (hcm->max_streams > 1 && !hcm->repeat)
    {
      err = clib_error_return (
	0, "multiple streams are only supported with request repeating");
      goto done;
    }

  if (repeat_count)
    {
      hcm->reqs_per_session =
	repeat_count / (hcm->max_sessions * hcm->max_streams);
      hcm->reqs_remainder =
	repeat_count % (hcm->max_sessions * hcm->max_streams);
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
    vlib_cli_output (vm, "* Running, please wait...");

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
    "[fifo-size <nM|G>] [private-segment-size <nM|G>] [prealloc-fifos <n>]"
    "[max-body-size <nM|G>] [http1|http2]",
  .function = hc_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
hc_main_init (vlib_main_t __clib_unused *vm)
{
  hc_main_t *hcm = &hc_main;
  session_endpoint_cfg_t sep_null = SESSION_ENDPOINT_CFG_NULL;

  hcm->app_index = APP_INVALID_INDEX;
  hcm->connect_sep = sep_null;
  return 0;
}

VLIB_INIT_FUNCTION (hc_main_init);
