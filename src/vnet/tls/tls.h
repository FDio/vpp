/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018-2019 Cisco and/or its affiliates.
 */

#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <vppinfra/lock.h>

#ifndef SRC_VNET_TLS_TLS_H_
#define SRC_VNET_TLS_TLS_H_

#define TLS_DEBUG		0
#define TLS_DEBUG_LEVEL_CLIENT 	0
#define TLS_DEBUG_LEVEL_SERVER 	0

#define TLS_CHUNK_SIZE 		(1 << 14)
#define TLS_CA_CERT_PATH	"/etc/ssl/certs/ca-certificates.crt"

#define TLS_INVALID_HANDLE    ~0
#define TLS_IDX_MASK	      0x00FFFFFF
#define TLS_ENGINE_TYPE_SHIFT 28

#if TLS_DEBUG
#define TLS_DBG(_lvl, _fmt, _args...) 			\
  if (_lvl <= TLS_DEBUG) 				\
    clib_warning (_fmt, ##_args)
#else
#define TLS_DBG(_lvl, _fmt, _args...)
#endif

#define foreach_ssl_async_evt_type                                            \
  _ (INIT, "SSL_in_init async event")                                         \
  _ (RD, "Read async event")                                                  \
  _ (WR, "Write async event")                                                 \
  _ (MAX, "Maximum async event")

typedef enum ssl_async_evt_type_
{
#define _(sym, str) SSL_ASYNC_EVT_##sym,
  foreach_ssl_async_evt_type
#undef _
} ssl_async_evt_type_t;

typedef struct tls_cxt_id_
{
  session_handle_t app_session_handle;
  session_handle_t tls_session_handle;
  void *migrate_ctx;
  u32 parent_app_wrk_index;
  u32 ssl_ctx;
  union
  {
    u32 listener_ctx_index;
    u32 parent_app_api_ctx;
  };
  u8 tcp_is_ip4;
  u8 tls_engine_id;
} tls_ctx_id_t;

STATIC_ASSERT (sizeof (tls_ctx_id_t) <= TRANSPORT_CONN_ID_LEN,
	       "ctx id must be less than TRANSPORT_CONN_ID_LEN");

#define foreach_tls_conn_flags                                                \
  _ (HO_DONE, "ho-done")                                                      \
  _ (PASSIVE_CLOSE, "passive-close")                                          \
  _ (APP_CLOSED, "app-closed")                                                \
  _ (MIGRATED, "migrated")                                                    \
  _ (NO_APP_SESSION, "no-app-session")                                        \
  _ (RESUME, "resume")                                                        \
  _ (HS_DONE, "handshake-done")                                               \
  _ (ASYNC_RD, "async-read")                                                  \
  _ (SHUTDOWN_TRANSPORT, "shutdown-transport")                                \
  _ (ASYNC_CERT, "async-cert")

typedef enum tls_conn_flags_bit_
{
#define _(sym, str) TLS_CONN_F_BIT_##sym,
  foreach_tls_conn_flags
#undef _
} tls_conn_flags_bit_t;

typedef enum tls_conn_flags_
{
#define _(sym, str) TLS_CONN_F_##sym = 1 << TLS_CONN_F_BIT_##sym,
  foreach_tls_conn_flags
#undef _
} __clib_packed tls_conn_flags_t;

typedef struct tls_ctx_
{
  union
  {
    transport_connection_t connection;
    tls_ctx_id_t c_tls_ctx_id;
  };
#define parent_app_wrk_index c_tls_ctx_id.parent_app_wrk_index
#define app_session_handle c_tls_ctx_id.app_session_handle
#define tls_session_handle c_tls_ctx_id.tls_session_handle
#define listener_ctx_index c_tls_ctx_id.listener_ctx_index
#define tcp_is_ip4 c_tls_ctx_id.tcp_is_ip4
#define tls_ctx_engine c_tls_ctx_id.tls_engine_id
#define tls_ssl_ctx c_tls_ctx_id.ssl_ctx
#define tls_ctx_handle c_c_index
  /* Temporary storage for session open opaque. Overwritten once
   * underlying tcp connection is established */
#define parent_app_api_context c_tls_ctx_id.parent_app_api_ctx
#define migration_ctx	       c_tls_ctx_id.migrate_ctx

  u32 ts_app_index;
  tls_conn_flags_t flags;
  u8 *srv_hostname;
  u32 ckpair_index;
  u32 ca_trust_index;
  transport_proto_t tls_type;
  u8 *alpn_list;
  tls_alpn_proto_t alpn_selected;
  tls_verify_cfg_t verify_cfg;
  u32 app_wrk_connect_index;
} tls_ctx_t;

typedef struct tls_main_
{
  u32 app_index;
  tls_ctx_t *listener_ctx_pool;
  u32 *postponed_ho_free;
  u32 *ho_free_list;
  u8 **rx_bufs;
  u8 **tx_bufs;

  /*
   * Config
   */
  u8 use_test_cert_in_ca;
  char *ca_cert_path;
  u64 first_seg_size;
  u64 add_seg_size;
  u32 fifo_size;
} tls_main_t;

typedef struct tls_engine_vft_
{
  u32 (*ctx_alloc) (void);
  u32 (*ctx_alloc_w_thread) (clib_thread_index_t thread_index);
  void (*ctx_free) (tls_ctx_t * ctx);
  void *(*ctx_detach) (tls_ctx_t *ctx);
  u32 (*ctx_attach) (clib_thread_index_t thread_index, void *ctx);
  tls_ctx_t *(*ctx_get) (u32 ctx_index);
  tls_ctx_t *(*ctx_get_w_thread) (u32 ctx_index, u8 thread_index);
  int (*ctx_init_client) (tls_ctx_t * ctx);
  int (*ctx_init_server) (tls_ctx_t * ctx);
  int (*ctx_read) (tls_ctx_t * ctx, session_t * tls_session);
  int (*ctx_write) (tls_ctx_t *ctx, session_t *app_session,
		    transport_send_params_t *sp);
  int (*ctx_start_listen) (tls_ctx_t * ctx);
  int (*ctx_stop_listen) (tls_ctx_t * ctx);
  int (*ctx_transport_close) (tls_ctx_t * ctx);
  int (*ctx_transport_reset) (tls_ctx_t *ctx);
  int (*ctx_app_close) (tls_ctx_t * ctx);
  int (*ctx_attribute) (tls_ctx_t *ctx, u8 is_get,
			transport_endpt_attr_t *attr);
  int (*ctx_reinit_cachain) (void);
} tls_engine_vft_t;

extern tls_engine_vft_t *tls_vfts;

tls_main_t *vnet_tls_get_main (void);
void tls_register_engine (const tls_engine_vft_t * vft,
			  crypto_engine_type_t type);
int tls_add_vpp_q_rx_evt (session_t * s);
int tls_add_vpp_q_tx_evt (session_t * s);
int tls_add_vpp_q_builtin_tx_evt (session_t * s);
int tls_add_vpp_q_builtin_rx_evt (session_t * s);
int tls_notify_app_accept (tls_ctx_t * ctx);
int tls_notify_app_connected (tls_ctx_t * ctx, session_error_t err);
void tls_notify_app_enqueue (tls_ctx_t * ctx, session_t * app_session);
void tls_notify_app_io_error (tls_ctx_t *ctx);
void tls_disconnect_transport (tls_ctx_t * ctx);
void tls_shutdown_transport (tls_ctx_t *ctx);

void tls_add_postponed_ho_cleanups (u32 ho_index);
void tls_flush_postponed_ho_cleanups ();

#endif /* SRC_VNET_TLS_TLS_H_ */
