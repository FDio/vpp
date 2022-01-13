/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#ifndef SRC_PLUGINS_HTTP_HTTP_H_
#define SRC_PLUGINS_HTTP_HTTP_H_

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <vppinfra/time_range.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>

#define HTTP_DEBUG 0

#if HTTP_DEBUG
#define HTTP_DBG(_lvl, _fmt, _args...)                                        \
  if (_lvl <= HTTP_DEBUG)                                                     \
  clib_warning (_fmt, ##_args)
#else
#define HTTP_DBG(_lvl, _fmt, _args...)
#endif

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

typedef enum http_state_
{
  HTTP_CONN_STATE_CONNECTING,
  HTTP_CONN_STATE_ESTABLISHED,
  HTTP_CONN_STATE_TRANSPORT_CLOSED,
  HTTP_CONN_STATE_CLOSED
} http_conn_state_t;

typedef enum http_req_state_
{
  HTTP_REQ_STATE_WAIT_METHOD,
  HTTP_REQ_STATE_WAIT_APP,
  //  HTTP_REQ_STATE_OK_SENT,
  HTTP_REQ_STATE_SEND_MORE_DATA,
  HTTP_REQ_N_STATES,
} http_req_state_t;

typedef enum http_req_method_
{
  HTTP_REQ_GET = 0,
  HTTP_REQ_POST,
} http_req_method_t;

typedef enum http_msg_type_
{
  HTTP_MSG_REQUEST,
  HTTP_MSG_REPLY
} http_msg_type_t;

typedef enum http_content_type_
{
  HTTP_CONTENT_TEXT_HTML,
  HTTP_CONTENT_TEXT_CSS,
  HTTP_CONTENT_TEXT_JS,
  HTTP_CONTENT_TEXT_JSON
} http_content_type_t;

typedef struct http_msg_data_
{
  http_content_type_t content_type;
  u32 len;
  u32 offset;
  u8 data[0];
} http_msg_data_t;

typedef struct http_msg_
{
  http_msg_type_t type;
  http_req_method_t method_type;
  http_msg_data_t data;
} http_msg_t;

typedef struct http_buffer_
{
  svm_fifo_seg_t *segs;
  u32 len;
  u32 cur_seg;
  u32 offset;
} http_buffer_t;

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
#define h_hc_index	    connection.c_index

  http_conn_state_t state;
  u32 timer_handle;

  /*
   * Current request
   */
  http_req_state_t req_state;
  http_req_method_t method;
  u8 *rx_buf;
  u32 rx_buf_offset;

  http_buffer_t tx_buf;
  //  u8 *tx_buf;
  u32 tx_buf_len;
  u32 tx_buf_offset;

  u8 *path;
} http_tc_t;

typedef struct http_worker_
{
  http_tc_t *conn_pool;
} http_worker_t;

typedef struct http_main_
{
  http_worker_t *wrk;
  http_tc_t *listener_ctx_pool;
  u32 app_index;
  clib_rwlock_t half_open_rwlock;

  tw_timer_wheel_2t_1w_2048sl_t tw;
  clib_spinlock_t tw_lock;
  clib_timebase_t timebase;

  /*
   * Runtime config
   */
  u8 debug_level;

  /*
   * Config
   */
  u64 first_seg_size;
  u32 fifo_size;
} http_main_t;

#endif /* SRC_PLUGINS_HTTP_HTTP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
