/*
 * Copyright (c) 2018 SUSE LLC.
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

u8 quic_configure();
void quic_api_reference (void);

#if QUIC_DEBUG
#define QUIC_DBG(_lvl, _fmt, _args...) 			\
  if (_lvl <= QUIC_DEBUG) 				\
    clib_warning (_fmt, ##_args)
#else
#define QUIC_DBG(_fmt, _args...)
#endif

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct quic_cxt_id_
{
  u32 quic_parent_app_index;
  session_handle_t quic_app_session_handle;
  session_handle_t quic_session_handle;
  u32 quic_listener_ctx_index;
  u8 quic_udp_is_ip4;
  u8 quic_engine_id;
}) quic_ctx_id_t;
/* *INDENT-ON* */

typedef struct quic_ctx_
{
  union
  {
    transport_connection_t connection;
    quic_ctx_id_t c_quic_ctx_id;
  };

#define quic_parent_app_index c_quic_ctx_id.quic_parent_app_index
#define quic_app_session_handle c_quic_ctx_id.quic_app_session_handle
#define quic_session_handle c_quic_ctx_id.quic_session_handle
#define quic_listener_ctx_index c_quic_ctx_id.quic_listener_ctx_index
#define quic_udp_is_ip4 c_quic_ctx_id.quic_udp_is_ip4
#define quic_ctx_engine c_quic_ctx_id.quic_engine_id
#define quic_ctx_handle c_c_index
#define quic_parent_app_api_context c_s_index

  u8 is_passive_close;
  u8 *srv_hostname;
} quic_ctx_t;

typedef struct
{
  u32 app_index;
  quic_ctx_t *listener_ctx_pool;
  quic_ctx_t *half_open_ctx_pool;
  clib_rwlock_t half_open_rwlock;
  u8 **rx_bufs;
  u8 **tx_bufs;

} quic_main_t;

typedef struct quic_engine_vft_
{
  u32 (*ctx_alloc) (void);
  void (*ctx_free) (quic_ctx_t * ctx);
  quic_ctx_t *(*ctx_get) (u32 ctx_index);
  quic_ctx_t *(*ctx_get_w_thread) (u32 ctx_index, u8 thread_index);
  int (*ctx_init_client) (quic_ctx_t * ctx);
  int (*ctx_init_server) (quic_ctx_t * ctx);
  int (*ctx_read) (quic_ctx_t * ctx, stream_session_t * quic_session);
  int (*ctx_write) (quic_ctx_t * ctx, stream_session_t * app_session);
    u8 (*ctx_handshake_is_over) (quic_ctx_t * ctx);
} quic_engine_vft_t;

typedef enum quic_engine_type_
{
  QUIC_ENGINE_NONE = 0x00000000,
  QUIC_ENGINE_TLS = 0x00000001,
  QUIC_ENGINE_OTHER,
  QUIC_N_ENGINES
} quic_engine_type_t;

extern quic_main_t quic_main;
