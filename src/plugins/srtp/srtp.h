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

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>

#include <srtp2/srtp.h>

#ifndef SRC_PLUGINS_SRTP_SRTP_H_
#define SRC_PLUGINS_SRTP_SRTP_H_

#define SRTP_DEBUG 1

#if SRTP_DEBUG
#define SRTP_DBG(_lvl, _fmt, _args...)                                        \
  if (_lvl <= SRTP_DEBUG)                                                     \
  clib_warning (_fmt, ##_args)
#else
#define SRTP_DBG(_lvl, _fmt, _args...)
#endif

typedef struct srtp_cxt_id_
{
  union
  {
    session_handle_t app_session_handle;
    u32 parent_app_api_ctx;
  };
  session_handle_t srtp_session_handle;
  u32 parent_app_wrk_index;
  u32 srtp_ctx;
  u32 listener_ctx_index;
  u8 udp_is_ip4;
} srtp_ctx_id_t;

STATIC_ASSERT (sizeof (srtp_ctx_id_t) <= TRANSPORT_CONN_ID_LEN,
	       "ctx id must be less than TRANSPORT_CONN_ID_LEN");

#define SRTP_MAX_KEYLEN 46 /**< libsrtp AES 256 key len with salt */

typedef struct transport_endpt_cfg_srtp_policy
{
  u32 ssrc_type;
  u32 ssrc_value;
  u32 window_size;
  u8 allow_repeat_tx;
  u8 key_len;
  u8 key[SRTP_MAX_KEYLEN];
} transport_endpt_cfg_srtp_policy_t;

typedef struct transport_endpt_cfg_srtp
{
  transport_endpt_cfg_srtp_policy_t policies[2];
} transport_endpt_cfg_srtp_t;

typedef struct srtp_ctx_
{
  union
  {
    transport_connection_t connection;
    srtp_ctx_id_t c_srtp_ctx_id;
  };
#define parent_app_wrk_index c_srtp_ctx_id.parent_app_wrk_index
#define app_session_handle   c_srtp_ctx_id.app_session_handle
#define srtp_session_handle  c_srtp_ctx_id.srtp_session_handle
#define listener_ctx_index   c_srtp_ctx_id.listener_ctx_index
#define udp_is_ip4	     c_srtp_ctx_id.udp_is_ip4
#define srtp_ctx_engine	     c_srtp_ctx_id.srtp_engine_id
#define srtp_ssl_ctx	     c_srtp_ctx_id.ssl_ctx
#define srtp_ctx_handle	     c_c_index
  /* Temporary storage for session open opaque. Overwritten once
   * underlying tcp connection is established */
#define parent_app_api_context c_srtp_ctx_id.parent_app_api_ctx

  u8 is_passive_close;
  u8 resume;
  u8 app_closed;
  u8 no_app_session;
  u8 is_migrated;
  srtp_t srtp_ctx;
  srtp_policy_t srtp_policy[2];
} srtp_tc_t;

typedef struct srtp_main_
{
  srtp_tc_t **ctx_pool;
  srtp_tc_t *listener_ctx_pool;
  u32 app_index;
  clib_rwlock_t half_open_rwlock;
  /*
   * Config
   */
  u64 first_seg_size;
  u32 fifo_size;
} srtp_main_t;

#endif /* SRC_PLUGINS_SRTP_SRTP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
