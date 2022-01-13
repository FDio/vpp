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

typedef struct http_cxt_id_
{
  union
  {
    session_handle_t app_session_handle;
    u32 parent_app_api_ctx;
  };
  session_handle_t tc_session_handle;
  u32 parent_app_wrk_index;
  u32 http_ctx;
  u32 listener_ctx_index;
  u8 udp_is_ip4;
} http_ctx_id_t;

STATIC_ASSERT (sizeof (http_ctx_id_t) <= TRANSPORT_CONN_ID_LEN,
	       "ctx id must be less than TRANSPORT_CONN_ID_LEN");

typedef struct http_tc_
{
  union
  {
    transport_connection_t connection;
    http_ctx_id_t c_http_ctx_id;
  };
#define h_tc_session_handle c_http_ctx_id.tc_session_handle
#define h_pa_wrk_index c_http_ctx_id.parent_app_wrk_index
#define h_pa_session_handle c_http_ctx_id.app_session_handle
#define h_ctx_handle connection.c_index
} http_tc_t;

typedef struct http_main_
{
  http_tc_t **ctx_pool;
  http_tc_t *listener_ctx_pool;
  u32 app_index;
  clib_rwlock_t half_open_rwlock;
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
