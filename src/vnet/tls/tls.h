/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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


#include <vnet/session/application_interface.h>
#include <vppinfra/lock.h>

#ifndef SRC_VNET_TLS_TLS_H_
#define SRC_VNET_TLS_TLS_H_

#define TLS_DEBUG 		0
#define TLS_DEBUG_LEVEL_CLIENT 	0
#define TLS_DEBUG_LEVEL_SERVER 	0

#define TLS_CHUNK_SIZE 		(1 << 14)
#define TLS_CA_CERT_PATH	"/etc/ssl/certs/ca-certificates.crt"

#if TLS_DEBUG
#define TLS_DBG(_lvl, _fmt, _args...) 			\
  if (_lvl <= TLS_DEBUG) 				\
    clib_warning (_fmt, ##_args)
#else
#define TLS_DBG(_lvl, _fmt, _args...)
#endif

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct tls_cxt_id_
{
  u32 parent_app_index;
  session_handle_t app_session_handle;
  session_handle_t tls_session_handle;
  u32 ssl_ctx;
  u32 listener_ctx_index;
  u8 tcp_is_ip4;
  u8 tls_engine_id;
}) tls_ctx_id_t;
/* *INDENT-ON* */

STATIC_ASSERT (sizeof (tls_ctx_id_t) <= 42, "ctx id must be less than 42");

typedef struct tls_ctx_
{
  union
  {
    transport_connection_t connection;
    tls_ctx_id_t c_tls_ctx_id;
  };
#define parent_app_index c_tls_ctx_id.parent_app_index
#define app_session_handle c_tls_ctx_id.app_session_handle
#define tls_session_handle c_tls_ctx_id.tls_session_handle
#define listener_ctx_index c_tls_ctx_id.listener_ctx_index
#define tcp_is_ip4 c_tls_ctx_id.tcp_is_ip4
#define tls_ctx_engine c_tls_ctx_id.tls_engine_id
#define tls_ssl_ctx c_tls_ctx_id.ssl_ctx
#define tls_ctx_handle c_c_index
  /* Temporary storage for session open opaque. Overwritten once
   * underlying tcp connection is established */
#define parent_app_api_context c_s_index

  u8 is_passive_close;
  u8 resume;
  u8 *srv_hostname;
} tls_ctx_t;

typedef struct tls_main_
{
  u32 app_index;
  tls_ctx_t *listener_ctx_pool;
  tls_ctx_t *half_open_ctx_pool;
  clib_rwlock_t half_open_rwlock;
  u8 **rx_bufs;
  u8 **tx_bufs;

  /*
   * Config
   */
  u8 use_test_cert_in_ca;
  char *ca_cert_path;
} tls_main_t;

typedef struct tls_engine_vft_
{
  u32 (*ctx_alloc) (void);
  void (*ctx_free) (tls_ctx_t * ctx);
  tls_ctx_t *(*ctx_get) (u32 ctx_index);
  tls_ctx_t *(*ctx_get_w_thread) (u32 ctx_index, u8 thread_index);
  int (*ctx_init_client) (tls_ctx_t * ctx);
  int (*ctx_init_server) (tls_ctx_t * ctx);
  int (*ctx_read) (tls_ctx_t * ctx, stream_session_t * tls_session);
  int (*ctx_write) (tls_ctx_t * ctx, stream_session_t * app_session);
    u8 (*ctx_handshake_is_over) (tls_ctx_t * ctx);
  int (*ctx_start_listen) (tls_ctx_t * ctx);
  int (*ctx_stop_listen) (tls_ctx_t * ctx);
} tls_engine_vft_t;

typedef enum tls_engine_type_
{
  TLS_ENGINE_NONE,
  TLS_ENGINE_MBEDTLS,
  TLS_ENGINE_OPENSSL,
  TLS_N_ENGINES
} tls_engine_type_t;

tls_main_t *vnet_tls_get_main (void);
void tls_register_engine (const tls_engine_vft_t * vft,
			  tls_engine_type_t type);
int tls_add_vpp_q_rx_evt (stream_session_t * s);
int tls_add_vpp_q_tx_evt (stream_session_t * s);
int tls_add_vpp_q_builtin_tx_evt (stream_session_t * s);
int tls_add_vpp_q_builtin_rx_evt (stream_session_t * s);
int tls_notify_app_accept (tls_ctx_t * ctx);
int tls_notify_app_connected (tls_ctx_t * ctx, u8 is_failed);
void tls_notify_app_enqueue (tls_ctx_t * ctx, stream_session_t * app_session);
#endif /* SRC_VNET_TLS_TLS_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
