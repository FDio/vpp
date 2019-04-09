/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __included_quic_h__
#define __included_quic_h__

#include <vnet/session/application_interface.h>

#include <vppinfra/lock.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

#include <quicly.h>
#include <quicly/streambuf.h>


#define QUIC_DEBUG                0
#define QUIC_DEBUG_LEVEL_CLIENT   0
#define QUIC_DEBUG_LEVEL_SERVER   0

#define QUIC_DEFAULT_CA_CERT_PATH        "/etc/ssl/certs/ca-certificates.crt"

#define QUIC_TIMER_HANDLE_INVALID ((u32) ~0)

#define QUIC_TSTAMP_RESOLUTION  0.001	/* QUIC tick resolution (1ms) */


#if QUIC_DEBUG
#define QUIC_DBG(_lvl, _fmt, _args...)           \
  if (_lvl <= QUIC_DEBUG)                \
    clib_warning (_fmt, ##_args)
#else
#define QUIC_DBG(_lvl, _fmt, _args...)
#endif

#define QUIC_CONN_STATE_HANDSHAKE 0
#define QUIC_CONN_STATE_READY     1

enum quic_session_type_t
{
  QUIC_SESSION_TYPE_QUIC = 0,
  QUIC_SESSION_TYPE_STREAM = 1,
  QUIC_SESSION_TYPE_LISTEN = INT32_MAX,
};


/* *INDENT-OFF* */
typedef CLIB_PACKED (struct quic_ctx_id_
{
  u32 parent_app_wrk_id;
  u32 parent_app_id;
  union {
    CLIB_PACKED (struct {
      session_handle_t quic_session_handle; // TODO: remove
      session_handle_t udp_session_handle;
      quicly_conn_t *conn;
      u32 listener_ctx_id;
      u8 udp_is_ip4;
    });
    CLIB_PACKED (struct {
      session_handle_t stream_session_handle; // TODO: remove
      quicly_stream_t *stream;
      u32 quic_connection_ctx_id;
    });
  };
  u8 is_stream;
}) quic_ctx_id_t;
/* *INDENT-ON* */

STATIC_ASSERT (sizeof (quic_ctx_id_t) <= 42, "ctx id must be less than 42");

// This structure is used to implement the concept of VPP connection for QUIC.
// We create one per connection and one per stream.
typedef struct quic_ctx_
{
  union
  {
    transport_connection_t connection;
    quic_ctx_id_t c_quic_ctx_id;
  };
  u8 *srv_hostname;
  u32 client_opaque;
  u32 timer_handle;
  u8 conn_state;
  u8 is_listener;
} quic_ctx_t;

typedef struct quic_stream_data_
{
  quicly_streambuf_t streambuf;
  u32 ctx_id;
} quic_stream_data_t;

typedef struct quic_worker_ctx_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 time_now;					/**< worker time */
  tw_timer_wheel_1t_3w_1024sl_ov_t timer_wheel;	   /**< worker timer wheel */
} quic_worker_ctx_t;

typedef struct quic_main_
{
  u32 app_index;
  quic_ctx_t **ctx_pool;
  quic_worker_ctx_t *wrk_ctx;
  f64 tstamp_ticks_per_clock;

  /*
   * Config
   */
  quicly_context_t quicly_ctx;
  ptls_handshake_properties_t hs_properties;
  quicly_cid_plaintext_t next_cid;
  u8 use_test_cert_in_ca;
  char *ca_cert_path;
} quic_main_t;

#endif /* __included_quic_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
