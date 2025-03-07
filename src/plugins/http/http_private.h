/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP_PRIVATE_H_
#define SRC_PLUGINS_HTTP_HTTP_PRIVATE_H_

#include <vppinfra/time_range.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <vnet/session/transport.h>
#include <http/http.h>
#include <http/http_buffer.h>

#define HTTP_FIFO_THRESH (16 << 10)

typedef u32 http_conn_handle_t;

typedef struct http_conn_id_
{
  union
  {
    session_handle_t app_session_handle;
    u32 parent_app_api_ctx;
  };
  session_handle_t tc_session_handle;
  u32 parent_app_wrk_index;
} http_conn_id_t;

STATIC_ASSERT (sizeof (http_conn_id_t) <= TRANSPORT_CONN_ID_LEN,
	       "ctx id must be less than TRANSPORT_CONN_ID_LEN");

#define foreach_http_conn_state                                               \
  _ (LISTEN, "LISTEN")                                                        \
  _ (CONNECTING, "CONNECTING")                                                \
  _ (ESTABLISHED, "ESTABLISHED")                                              \
  _ (TRANSPORT_CLOSED, "TRANSPORT-CLOSED")                                    \
  _ (APP_CLOSED, "APP-CLOSED")                                                \
  _ (CLOSED, "CLOSED")

typedef enum http_conn_state_
{
#define _(s, str) HTTP_CONN_STATE_##s,
  foreach_http_conn_state
#undef _
} http_conn_state_t;

#define foreach_http_req_state                                                \
  _ (0, IDLE, "idle")                                                         \
  _ (1, WAIT_APP_METHOD, "wait app method")                                   \
  _ (2, WAIT_TRANSPORT_REPLY, "wait transport reply")                         \
  _ (3, TRANSPORT_IO_MORE_DATA, "transport io more data")                     \
  _ (4, WAIT_TRANSPORT_METHOD, "wait transport method")                       \
  _ (5, WAIT_APP_REPLY, "wait app reply")                                     \
  _ (6, APP_IO_MORE_DATA, "app io more data")                                 \
  _ (7, TUNNEL, "tunnel")                                                     \
  _ (8, UDP_TUNNEL, "udp tunnel")

typedef enum http_req_state_
{
#define _(n, s, str) HTTP_REQ_STATE_##s = n,
  foreach_http_req_state
#undef _
    HTTP_REQ_N_STATES
} http_req_state_t;

typedef enum http_target_form_
{
  HTTP_TARGET_ORIGIN_FORM,
  HTTP_TARGET_ABSOLUTE_FORM,
  HTTP_TARGET_AUTHORITY_FORM,
  HTTP_TARGET_ASTERISK_FORM
} http_target_form_t;

typedef enum http_version_
{
  HTTP_VERSION_1,
  HTTP_VERSION_2,
  HTTP_VERSION_3,
  HTTP_VERSION_NA = 7,
} http_version_t;

typedef struct http_req_
{
  /* in case of multiplexing we have app session for each stream */
  session_handle_t app_session_handle;
  u32 as_fifo_offset; /* for peek */

  http_req_state_t state; /* state-machine state */

  http_buffer_t tx_buf; /* message body from app to be sent */

  /*
   * for parsing of incoming message from transport
   */
  u32 rx_buf_offset;	/* current offset during parsing */
  u32 control_data_len; /* start line + headers + empty line */

  union
  {
    u64 to_recv; /* remaining bytes of body to receive from transport */
    u64 to_skip; /* remaining bytes of capsule to skip */
  };

  u8 is_tunnel;

  /*
   * parsed metadata for app
   */
  union
  {
    http_status_code_t status_code;
    http_req_method_t method;
  };

  http_target_form_t target_form;
  u8 *target;
  http_url_scheme_t scheme;
  u32 target_authority_offset;
  u32 target_authority_len;
  u32 target_path_offset;
  u32 target_path_len;
  u32 target_query_offset;
  u32 target_query_len;

  u32 headers_offset;
  u32 headers_len;

  u32 body_offset;
  u64 body_len;

  http_field_line_t *headers;
  uword content_len_header_index;
  uword connection_header_index;
  uword upgrade_header_index;
  uword host_header_index;

  http_upgrade_proto_t upgrade_proto;
} http_req_t;

typedef struct http_tc_
{
  union
  {
    transport_connection_t connection;
    http_conn_id_t c_http_conn_id;
  };
#define h_tc_session_handle c_http_conn_id.tc_session_handle
#define h_pa_wrk_index	    c_http_conn_id.parent_app_wrk_index
#define h_pa_session_handle c_http_conn_id.app_session_handle
#define h_pa_app_api_ctx    c_http_conn_id.parent_app_api_ctx
#define h_hc_index	    connection.c_index

  http_version_t version;
  http_conn_state_t state;
  u32 timer_handle;
  u32 timeout;
  u8 pending_timer;
  u8 *app_name;
  u8 *host;
  u8 is_server;
  http_udp_tunnel_mode_t udp_tunnel_mode;

  void *req_pool; /* multiplexing => request per stream */

  void *opaque; /* version specific data */
} http_conn_t;

typedef struct http_worker_
{
  http_conn_t *conn_pool;
} http_worker_t;

typedef struct http_main_
{
  http_worker_t *wrk;
  http_conn_t *listener_pool;
  http_conn_t *ho_conn_pool;
  u32 app_index;

  u8 **rx_bufs;
  u8 **tx_bufs;
  u8 **app_header_lists;

  clib_timebase_t timebase;

  http_status_code_t *sc_by_u16;
  /*
   * Runtime config
   */
  u8 is_init;

  /*
   * Config
   */
  u64 first_seg_size;
  u64 add_seg_size;
  u32 fifo_size;
} http_main_t;

typedef struct http_engine_vft_
{
  const char *name;
  void (*app_tx_callback) (http_conn_t *hc, transport_send_params_t *sp);
  void (*app_rx_evt_callback) (http_conn_t *hc);
  void (*app_close_callback) (http_conn_t *hc);
  void (*app_reset_callback) (http_conn_t *hc);
  void (*transport_rx_callback) (http_conn_t *hc);
  void (*transport_close_callback) (http_conn_t *hc);
  void (*conn_cleanup_callback) (http_conn_t *hc);
  void (*enable_callback) (void);			    /* optional */
  uword (*unformat_cfg_callback) (unformat_input_t *input); /* optional */
} http_engine_vft_t;

void http_register_engine (const http_engine_vft_t *vft,
			   http_version_t version);

/* HTTP state machine result */
typedef enum http_sm_result_t_
{
  HTTP_SM_STOP = 0,
  HTTP_SM_CONTINUE = 1,
  HTTP_SM_ERROR = -1,
} http_sm_result_t;

typedef http_sm_result_t (*http_sm_handler) (http_conn_t *hc, http_req_t *req,
					     transport_send_params_t *sp);

#define expect_char(c)                                                        \
  if (*p++ != c)                                                              \
    {                                                                         \
      clib_warning ("unexpected character");                                  \
      return -1;                                                              \
    }

#define parse_int(val, mul)                                                   \
  do                                                                          \
    {                                                                         \
      if (!isdigit (*p))                                                      \
	{                                                                     \
	  clib_warning ("expected digit");                                    \
	  return -1;                                                          \
	}                                                                     \
      val += mul * (*p++ - '0');                                              \
    }                                                                         \
  while (0)

#define http_field_line_value_token(_fl, _req, _rx_buf)                       \
  (const char *) ((_rx_buf) + (_req)->headers_offset + (_fl)->value_offset),  \
    (_fl)->value_len

u8 *format_http_req_state (u8 *s, va_list *va);
u8 *format_http_conn_state (u8 *s, va_list *args);
u8 *format_http_time_now (u8 *s, va_list *args);

/**
 * @brief Find the first occurrence of the string in the vector.
 *
 * @param vec The vector to be scanned.
 * @param offset Search offset in the vector.
 * @param num Maximum number of characters to be searched if non-zero.
 * @param str The string to be searched.
 *
 * @return @c -1 if the string is not found within the vector; index otherwise.
 */
int http_v_find_index (u8 *vec, u32 offset, u32 num, char *str);

/**
 * Disconnect HTTP connection.
 *
 * @param hc HTTP connection to disconnect.
 */
void http_disconnect_transport (http_conn_t *hc);

/**
 * Convert numeric representation of status code to @c http_status_code_t.
 *
 * @param status_code Status code within the range of 100 to 599, inclusive.
 *
 * @return Registered status code or in case of unrecognized status code as
 * equivalent to the x00 status code of that class.
 */
http_status_code_t http_sc_by_u16 (u16 status_code);

/**
 * Read header list sent by app.
 *
 * @param hc  HTTP connection.
 * @param msg HTTP msg sent by app.
 *
 * @return Pointer to the header list.
 *
 * @note For immediate processing, not for buffering.
 */
u8 *http_get_app_header_list (http_conn_t *hc, http_msg_t *msg);

/**
 * Get pre-allocated TX buffer/vector.
 *
 * @param hc HTTP connection.
 *
 * @return Pointer to the vector.
 *
 * @note Vector length is reset to zero, use as temporary storage.
 */
u8 *http_get_tx_buf (http_conn_t *hc);

/**
 * Get pre-allocated RX buffer/vector.
 *
 * @param hc HTTP connection.
 *
 * @return Pointer to the vector.
 *
 * @note Vector length is reset to zero, use as temporary storage.
 */
u8 *http_get_rx_buf (http_conn_t *hc);

/**
 * Read request target path sent by app.
 *
 * @param hc  HTTP connection.
 * @param msg HTTP msg sent by app.
 *
 * @return Pointer to the target path.
 *
 * @note Valid only with request lifetime.
 */
u8 *http_get_app_target (http_req_t *req, http_msg_t *msg);

/**
 * Initialize per-request HTTP TX buffer.
 *
 * @param req HTTP request.
 * @param msg HTTP msg sent by app.
 *
 * @note Use for streaming of body sent by app.
 */
void http_req_tx_buffer_init (http_req_t *req, http_msg_t *msg);

/**
 * Change state of given HTTP request.
 *
 * @param req   HTTP request.
 * @param state New state.
 */
always_inline void
http_req_state_change (http_req_t *req, http_req_state_t state)
{
  HTTP_DBG (1, "changing http req state: %U -> %U", format_http_req_state,
	    req->state, format_http_req_state, state);
  ASSERT (req->state != HTTP_REQ_STATE_TUNNEL);
  req->state = state;
}

/**
 * Send RX event to the app worker.
 *
 * @param req HTTP request.
 */
always_inline void
http_app_worker_rx_notify (http_req_t *req)
{
  session_t *as;
  app_worker_t *app_wrk;

  as = session_get_from_handle (req->app_session_handle);
  app_wrk = app_worker_get_if_valid (as->app_wrk_index);
  if (app_wrk)
    app_worker_rx_notify (app_wrk, as);
}

/**
 * Get underlying transport protocol of the HTTP connection.
 *
 * @param hc HTTP connection.
 *
 * @return Transport protocol, @ref transport_proto_t.
 */
always_inline transport_proto_t
http_get_transport_proto (http_conn_t *hc)
{
  return session_get_transport_proto (
    session_get_from_handle (hc->h_tc_session_handle));
}

/**
 * Read HTTP msg sent by app.
 *
 * @param req HTTP request.
 * @param msg HTTP msq will be stored here.
 */
always_inline void
http_get_app_msg (http_req_t *req, http_msg_t *msg)
{
  session_t *as;
  int rv;

  as = session_get_from_handle (req->app_session_handle);
  rv = svm_fifo_dequeue (as->tx_fifo, sizeof (*msg), (u8 *) msg);
  ASSERT (rv == sizeof (*msg));
}

/* Abstraction of app session fifo operations */

always_inline void
http_io_as_want_deq_ntf (http_req_t *req)
{
  session_t *as = session_get_from_handle (req->app_session_handle);
  svm_fifo_add_want_deq_ntf (as->rx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
}

always_inline u32
http_io_as_max_write (http_req_t *req)
{
  session_t *as = session_get_from_handle (req->app_session_handle);
  return svm_fifo_max_enqueue_prod (as->rx_fifo);
}

always_inline u32
http_io_as_max_read (http_req_t *req)
{
  session_t *as = session_get_from_handle (req->app_session_handle);
  return svm_fifo_max_dequeue_cons (as->tx_fifo);
}

always_inline u32
http_io_as_write_segs (http_req_t *req, const svm_fifo_seg_t segs[],
		       u32 n_segs)
{
  int n_written;
  session_t *as = session_get_from_handle (req->app_session_handle);
  n_written = svm_fifo_enqueue_segments (as->rx_fifo, segs, n_segs, 0);
  ASSERT (n_written > 0);
  return (u32) n_written;
}

always_inline u32
http_io_as_read (http_req_t *req, u8 *buf, u32 len, u8 peek)
{
  int n_read;
  session_t *as = session_get_from_handle (req->app_session_handle);

  if (peek)
    {
      n_read = svm_fifo_peek (as->tx_fifo, req->as_fifo_offset, len, buf);
      ASSERT (n_read > 0);
      req->as_fifo_offset += len;
      return (u32) n_read;
    }

  n_read = svm_fifo_dequeue (as->tx_fifo, len, buf);
  ASSERT (n_read == len);
  return (u32) n_read;
}

always_inline void
http_io_as_read_segs (http_req_t *req, svm_fifo_seg_t *segs, u32 *n_segs,
		      u32 max_bytes)
{
  int n_read;
  session_t *as = session_get_from_handle (req->app_session_handle);
  n_read = svm_fifo_segments (as->tx_fifo, 0, segs, n_segs, max_bytes);
  ASSERT (n_read > 0);
}

always_inline void
http_io_as_drain (http_req_t *req, u32 len)
{
  session_t *as = session_get_from_handle (req->app_session_handle);
  svm_fifo_dequeue_drop (as->tx_fifo, len);
  req->as_fifo_offset = 0;
}

always_inline void
http_io_as_drain_all (http_req_t *req)
{
  session_t *as = session_get_from_handle (req->app_session_handle);
  svm_fifo_dequeue_drop_all (as->tx_fifo);
  req->as_fifo_offset = 0;
}

/* Abstraction of transport session fifo operations */

always_inline u32
http_io_ts_max_read (http_conn_t *hc)
{
  session_t *ts = session_get_from_handle (hc->h_tc_session_handle);
  return svm_fifo_max_dequeue_cons (ts->rx_fifo);
}

always_inline u32
http_io_ts_max_write (http_conn_t *hc, transport_send_params_t *sp)
{
  session_t *ts = session_get_from_handle (hc->h_tc_session_handle);
  return clib_min (svm_fifo_max_enqueue_prod (ts->tx_fifo),
		   sp->max_burst_size);
}

always_inline u32
http_io_ts_read (http_conn_t *hc, u8 *buf, u32 len, u8 peek)
{
  int n_read;
  session_t *ts = session_get_from_handle (hc->h_tc_session_handle);

  if (peek)
    {
      n_read = svm_fifo_peek (ts->rx_fifo, 0, len, buf);
      ASSERT (n_read > 0);
      return (u32) n_read;
    }

  n_read = svm_fifo_dequeue (ts->rx_fifo, len, buf);
  ASSERT (n_read == len);
  return (u32) n_read;
}

always_inline void
http_io_ts_read_segs (http_conn_t *hc, svm_fifo_seg_t *segs, u32 *n_segs,
		      u32 max_bytes)
{
  int n_read;
  session_t *ts = session_get_from_handle (hc->h_tc_session_handle);
  n_read = svm_fifo_segments (ts->rx_fifo, 0, segs, n_segs, max_bytes);
  ASSERT (n_read > 0);
}

always_inline void
http_io_ts_drain (http_conn_t *hc, u32 len)
{
  session_t *ts = session_get_from_handle (hc->h_tc_session_handle);
  svm_fifo_dequeue_drop (ts->rx_fifo, len);
}

always_inline void
http_io_ts_drain_all (http_conn_t *hc)
{
  session_t *ts = session_get_from_handle (hc->h_tc_session_handle);
  svm_fifo_dequeue_drop_all (ts->rx_fifo);
}

always_inline void
http_io_ts_after_read (http_conn_t *hc, u8 clear_evt)
{
  session_t *ts = session_get_from_handle (hc->h_tc_session_handle);
  if (clear_evt)
    {
      if (svm_fifo_is_empty_cons (ts->rx_fifo))
	svm_fifo_unset_event (ts->rx_fifo);
    }
  else
    {
      if (svm_fifo_max_dequeue_cons (ts->rx_fifo))
	session_program_rx_io_evt (hc->h_tc_session_handle);
    }
}

always_inline void
http_io_ts_write (http_conn_t *hc, u8 *data, u32 len,
		  transport_send_params_t *sp)
{
  int n_written;
  session_t *ts = session_get_from_handle (hc->h_tc_session_handle);

  n_written = svm_fifo_enqueue (ts->tx_fifo, len, data);
  ASSERT (n_written == len);
  if (sp)
    {
      ASSERT (sp->max_burst_size >= len);
      sp->bytes_dequeued += len;
      sp->max_burst_size -= len;
    }
}

always_inline u32
http_io_ts_write_segs (http_conn_t *hc, const svm_fifo_seg_t segs[],
		       u32 n_segs, transport_send_params_t *sp)
{
  int n_written;
  session_t *ts = session_get_from_handle (hc->h_tc_session_handle);
  n_written = svm_fifo_enqueue_segments (ts->tx_fifo, segs, n_segs, 0);
  ASSERT (n_written > 0);
  sp->bytes_dequeued += n_written;
  sp->max_burst_size -= n_written;
  return (u32) n_written;
}

always_inline void
http_io_ts_after_write (http_conn_t *hc, transport_send_params_t *sp, u8 flush,
			u8 written)
{
  session_t *ts = session_get_from_handle (hc->h_tc_session_handle);

  if (!flush)
    {
      if (written && svm_fifo_set_event (ts->tx_fifo))
	session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX);

      if (sp && (svm_fifo_max_enqueue (ts->tx_fifo) < HTTP_FIFO_THRESH))
	{
	  /* Deschedule http session and wait for deq notification if
	   * underlying ts tx fifo almost full */
	  svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
	  transport_connection_deschedule (&hc->connection);
	  sp->flags |= TRANSPORT_SND_F_DESCHED;
	}
    }
  else
    {
      if (written && svm_fifo_set_event (ts->tx_fifo))
	session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX_FLUSH);
    }
}

#endif /* SRC_PLUGINS_HTTP_HTTP_PRIVATE_H_ */
