/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP_PRIVATE_H_
#define SRC_PLUGINS_HTTP_HTTP_PRIVATE_H_

#include <vppinfra/time_range.h>
#include <vnet/session/session.h>
#include <vnet/session/transport.h>
#include <http/http.h>
#include <http/http_buffer.h>

#define HTTP_FIFO_THRESH (16 << 10)

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
  _ (LISTEN, "listen")                                                        \
  _ (CONNECTING, "connecting")                                                \
  _ (ESTABLISHED, "established")                                              \
  _ (TRANSPORT_CLOSED, "transport-closed")                                    \
  _ (APP_CLOSED, "app-closed")                                                \
  _ (CLOSED, "closed")

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

typedef struct http_req_
{
  http_req_state_t state; /* state-machine state */

  http_buffer_t tx_buf; /* message body from app to be sent */

  /*
   * for parsing of incoming message from transport
   */
  u8 *rx_buf;		/* this should hold at least control data */
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

  http_conn_state_t state;
  u32 timer_handle;
  u32 timeout;
  u8 pending_timer;
  u8 *app_name;
  u8 *host;
  u8 is_server;
  http_udp_tunnel_mode_t udp_tunnel_mode;

  http_req_t req;
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
  u8 debug_level;
  u8 is_init;

  /*
   * Config
   */
  u64 first_seg_size;
  u64 add_seg_size;
  u32 fifo_size;
} http_main_t;

typedef enum http_version_
{
  HTTP_VERSION_1,
  HTTP_VERSION_2,
  HTTP_VERSION_3,
} http_version_t;

typedef struct http_engine_vft_
{
  void (*app_tx_callback) (http_conn_t *hc, transport_send_params_t *sp);
  void (*app_rx_evt_callback) (http_conn_t *hc);
  void (*transport_rx_callback) (http_conn_t *hc);
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

typedef http_sm_result_t (*http_sm_handler) (http_conn_t *,
					     transport_send_params_t *sp);

static const http_buffer_type_t msg_to_buf_type[] = {
  [HTTP_MSG_DATA_INLINE] = HTTP_BUFFER_FIFO,
  [HTTP_MSG_DATA_PTR] = HTTP_BUFFER_PTR,
};

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

#define http_field_line_value_token(_fl, _req)                                \
  (const char *) ((_req)->rx_buf + (_req)->headers_offset +                   \
		  (_fl)->value_offset),                                       \
    (_fl)->value_len

#define http_req_state_change(_hc, _state)                                    \
  do                                                                          \
    {                                                                         \
      HTTP_DBG (1, "changing http req state: %U -> %U",                       \
		format_http_req_state, (_hc)->req.state,                      \
		format_http_req_state, _state);                               \
      ASSERT ((_hc)->req.state != HTTP_REQ_STATE_TUNNEL);                     \
      (_hc)->req.state = _state;                                              \
    }                                                                         \
  while (0)

u8 *format_http_req_state (u8 *s, va_list *va);
u8 *format_http_conn_state (u8 *s, va_list *args);
u8 *format_http_time_now (u8 *s, va_list *args);
u32 http_send_data (http_conn_t *hc, u8 *data, u32 length);
int http_read_message (http_conn_t *hc);
void http_read_message_drop (http_conn_t *hc, u32 len);
void http_read_message_drop_all (http_conn_t *hc);
void http_disconnect_transport (http_conn_t *hc);
int v_find_index (u8 *vec, u32 offset, u32 num, char *str);
http_status_code_t http_sc_by_u16 (u16 status_code);
u8 *http_get_app_header_list_buf (http_conn_t *hc);
u8 *http_get_tx_buf (http_conn_t *hc);
u8 *http_get_rx_buf (http_conn_t *hc);

#endif /* SRC_PLUGINS_HTTP_HTTP_PRIVATE_H_ */
