/*
 * Copyright (c) 2025 Cisco and/or its affiliates.
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

#include <vppinfra/clib.h>
#include <vppinfra/lock.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>
#include <vppinfra/bihash_16_8.h>

#include <vnet/crypto/crypto.h>

// TODO: Remove once all quicly code is refactored out of this file.
#include <quicly.h>

/* QUIC log levels
 * 1 - errors
 * 2 - connection/stream events
 * 3 - packet events
 * 4 - timer events
 **/

#define QUIC_DEBUG               0
#define QUIC_TSTAMP_RESOLUTION  0.001	/* QUIC tick resolution (1ms) */
#define QUIC_TIMER_HANDLE_INVALID ((u32) ~0)
#define QUIC_SESSION_INVALID ((u32) ~0 - 1)
#define QUIC_MAX_PACKET_SIZE 1280

#define QUIC_INT_MAX  0x3FFFFFFFFFFFFFFF
#define QUIC_DEFAULT_FIFO_SIZE (64 << 10)
#define QUIC_SEND_PACKET_VEC_SIZE 16
#define QUIC_IV_LEN 17

#define QUIC_MAX_COALESCED_PACKET 4

#define QUIC_RCV_MAX_PACKETS 16

#define QUIC_DEFAULT_CONN_TIMEOUT (30 * 1000)	/* 30 seconds */

/* error codes */
#define QUIC_ERROR_FULL_FIFO 0xff10
#define QUIC_APP_ERROR_CLOSE_NOTIFY QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0)
#define QUIC_APP_ALLOCATION_ERROR QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x1)
#define QUIC_APP_ACCEPT_NOTIFY_ERROR QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x2)
#define QUIC_APP_CONNECT_NOTIFY_ERROR QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x3)

#define QUIC_DECRYPT_PACKET_OK 0
#define QUIC_DECRYPT_PACKET_NOTOFFLOADED 1
#define QUIC_DECRYPT_PACKET_ERROR 2

#if QUIC_DEBUG
#define QUIC_DBG(_lvl, _fmt, _args...)   \
  if (_lvl <= QUIC_DEBUG)                \
    clib_warning (_fmt, ##_args)
#else
#define QUIC_DBG(_lvl, _fmt, _args...)
#endif

#if CLIB_ASSERT_ENABLE
#define QUIC_ASSERT(truth) ASSERT (truth)
#else
#define QUIC_ASSERT(truth)                        \
  do {                                            \
    if (PREDICT_FALSE (! (truth)))                \
      QUIC_ERR ("ASSERT(%s) failed", # truth);    \
  } while (0)
#endif

#define QUIC_ERR(_fmt, _args...)                \
  do {                                          \
    clib_warning ("QUIC-ERR: " _fmt, ##_args);  \
  } while (0)

typedef enum quic_lib_type_
{
  QUIC_LIB_NONE,
  QUIC_LIB_QUICLY,
  QUIC_LIB_OPENSSL,
  QUIC_LIB_LAST = QUIC_LIB_OPENSSL,
} quic_lib_type_t;

static_always_inline char *
quic_lib_type_str (quic_lib_type_t lib_type)
{
  switch (lib_type)
    {
    case QUIC_LIB_NONE:
      return ("QUIC_LIB_NONE");
    case QUIC_LIB_QUICLY:
      return ("QUIC_LIB_QUICLY");
    case QUIC_LIB_OPENSSL:
      return ("QUIC_LIB_OPENSSL");
    default:
      return ("UNKNOWN");
    }
}
extern vlib_node_registration_t quic_input_node;

typedef enum
{
#define quic_error(n,s) QUIC_ERROR_##n,
#include <plugins/quic/quic_error.def>
#undef quic_error
  QUIC_N_ERROR,
} quic_error_t;

typedef enum quic_ctx_conn_state_
{
  QUIC_CONN_STATE_OPENED,
  QUIC_CONN_STATE_HANDSHAKE,
  QUIC_CONN_STATE_READY,
  QUIC_CONN_STATE_PASSIVE_CLOSING,
  QUIC_CONN_STATE_PASSIVE_CLOSING_APP_CLOSED,
  QUIC_CONN_STATE_PASSIVE_CLOSING_QUIC_CLOSED,
  QUIC_CONN_STATE_ACTIVE_CLOSING,
} quic_ctx_conn_state_t;

typedef enum quic_packet_type_
{
  QUIC_PACKET_TYPE_NONE,
  QUIC_PACKET_TYPE_RECEIVE,
  QUIC_PACKET_TYPE_MIGRATE,
  QUIC_PACKET_TYPE_ACCEPT,
  QUIC_PACKET_TYPE_RESET,
  QUIC_PACKET_TYPE_DROP,
} quic_packet_type_t;

typedef enum quic_ctx_flags_
{
  QUIC_F_IS_STREAM = (1 << 0),
  QUIC_F_IS_LISTENER = (1 << 1),
} quic_ctx_flags_t;

typedef enum quic_cc_type
{
  QUIC_CC_RENO,
  QUIC_CC_CUBIC,
} quic_cc_type_t;

/* This structure is used to implement the concept of VPP connection for QUIC.
 * We create one per connection and one per stream. */
typedef struct quic_ctx_
{
  union
  {
    transport_connection_t connection;
    struct
    {	      /** QUIC ctx case */
      void *conn;
      u32 listener_ctx_id;
      u32 client_opaque;
      u8 *srv_hostname;
      u8 conn_state;
      u8 udp_is_ip4;
      u8 _qctx_end_marker;	/* Leave this at the end */
    };
    struct
    {	      /** STREAM ctx case */
      void *stream;
      u64 bytes_written;
      u32 quic_connection_ctx_id;
      u8 _sctx_end_marker;	/* Leave this at the end */
    };
  };
  session_handle_t udp_session_handle;
  u32 timer_handle;
  u32 parent_app_wrk_id;
  u32 parent_app_id;
  u32 ckpair_index;
  u32 crypto_engine;
  u32 crypto_context_index;
  u8 flags;

  struct
  {
    ptls_cipher_context_t *hp_ctx;
    ptls_aead_context_t *aead_ctx;
  } ingress_keys;
  int key_phase_ingress;
  ip46_address_t rmt_ip;
  ip46_address_t lcl_ip;

} quic_ctx_t;

/* Make sure our custom fields don't overlap with the fields we use in
   .connection
*/
STATIC_ASSERT (offsetof (quic_ctx_t, _qctx_end_marker) <=
	       TRANSPORT_CONN_ID_LEN,
	       "connection data must be less than TRANSPORT_CONN_ID_LEN bytes");
STATIC_ASSERT (offsetof (quic_ctx_t, _sctx_end_marker) <=
	       TRANSPORT_CONN_ID_LEN,
	       "connection data must be less than TRANSPORT_CONN_ID_LEN bytes");

/* single-entry session cache */
typedef struct quic_session_cache_
{
  ptls_encrypt_ticket_t super;
  uint8_t id[32];
  ptls_iovec_t data;
} quic_session_cache_t;

typedef struct quic_stream_data_
{
  u32 ctx_id;
  u32 thread_index;
  u32 app_rx_data_len;		/**< bytes received, to be read by external app */
  u32 app_tx_data_len;		/**< bytes sent */
} quic_stream_data_t;

typedef struct quic_worker_ctx_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  int64_t time_now;				   /**< worker time */
  tw_timer_wheel_1t_3w_1024sl_ov_t timer_wheel;	   /**< worker timer wheel */
  quicly_cid_plaintext_t next_cid;
  crypto_context_t *crypto_ctx_pool;		/**< per thread pool of crypto contexes */
  clib_bihash_24_8_t crypto_context_hash;	/**< per thread [params:crypto_ctx_index] hash */
} quic_worker_ctx_t;

typedef struct quic_rx_packet_ctx_
{
  quicly_decoded_packet_t packet;
  u8 data[QUIC_MAX_PACKET_SIZE];
  u32 ctx_index;
  u32 thread_index;
  union
  {
    struct sockaddr sa;
    struct sockaddr_in6 sa6;
  };
  socklen_t salen;
  u8 ptype;
  session_dgram_hdr_t ph;
} quic_rx_packet_ctx_t;

typedef struct quic_main_
{
  u32 app_index;
  quic_ctx_t **ctx_pool;
  quic_worker_ctx_t *wrk_ctx;
  clib_bihash_16_8_t connection_hash;	/**< quic connection id -> conn handle */
  f64 tstamp_ticks_per_clock;

  ptls_cipher_suite_t ***quic_ciphers;	/**< available ciphers by crypto engine */
  uword *available_crypto_engines;	/**< Bitmap for registered engines */
  u8 default_crypto_engine;		/**< Used if you do connect with CRYPTO_ENGINE_NONE (0) */
  u64 max_packets_per_key;		/**< number of packets that can be sent without a key update */
  u8 default_quic_cc;

  ptls_handshake_properties_t hs_properties;
  quic_session_cache_t session_cache;

  u32 udp_fifo_size;
  u32 udp_fifo_prealloc;
  u32 connection_timeout;

  u8 vnet_crypto_enabled;
  u32 *per_thread_crypto_key_indices;
  quic_lib_type_t lib_type;
} quic_main_t;

extern int64_t quic_get_thread_time (u8 thread_index);
extern quic_main_t *get_quic_main (void);
extern u32 quic_ctx_alloc (u32 thread_index);
extern quic_ctx_t *quic_ctx_get (u32 ctx_index, u32 thread_index);
extern void quic_ctx_free (quic_ctx_t * ctx);
extern void quic_check_quic_session_connected (quic_ctx_t *ctx);
extern void quic_increment_counter (u8 evt, u8 val);
extern int quic_acquire_crypto_context (quic_ctx_t * ctx);

static_always_inline int
quic_ctx_is_stream (quic_ctx_t * ctx)
{
  return (ctx->flags & QUIC_F_IS_STREAM);
}

static_always_inline void
quic_build_sockaddr (struct sockaddr *sa, socklen_t *salen,
		     ip46_address_t *addr, u16 port, u8 is_ip4)
{
  if (is_ip4)
    {
      struct sockaddr_in *sa4 = (struct sockaddr_in *) sa;
      sa4->sin_family = AF_INET;
      sa4->sin_port = port;
      sa4->sin_addr.s_addr = addr->ip4.as_u32;
      *salen = sizeof (struct sockaddr_in);
    }
  else
    {
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) sa;
      sa6->sin6_family = AF_INET6;
      sa6->sin6_port = port;
      clib_memcpy (&sa6->sin6_addr, &addr->ip6, 16);
      *salen = sizeof (struct sockaddr_in6);
    }
}

static_always_inline int64_t
quic_get_time (void)
{
  u8 thread_index = vlib_get_thread_index ();
  return quic_get_thread_time (thread_index);
}

static_always_inline quic_ctx_t *
quic_ctx_get_if_valid (u32 ctx_index, u32 thread_index)
{
  if (pool_is_free_index (get_quic_main()->ctx_pool[thread_index], ctx_index))
    return 0;
  return pool_elt_at_index (get_quic_main()->ctx_pool[thread_index], ctx_index);
}

static_always_inline crypto_context_t *
quic_crypto_context_get (u32 cr_index, u32 thread_index)
{
  quic_main_t *qm = get_quic_main ();
  ASSERT (cr_index >> 24 == thread_index);
  return pool_elt_at_index (qm->wrk_ctx[thread_index].crypto_ctx_pool,
			    cr_index & 0x00ffffff);
}

static_always_inline void
quic_make_connection_key (clib_bihash_kv_16_8_t *kv,
			  const quicly_cid_plaintext_t *id)
{
  kv->key[0] = ((u64) id->master_id) << 32 | (u64) id->thread_id;
  kv->key[1] = id->node_id;
}

static_always_inline void
quic_disconnect_transport (quic_ctx_t * ctx)
{
  quic_main_t *qm = get_quic_main ();

  QUIC_DBG (2, "Disconnecting transport 0x%lx", ctx->udp_session_handle);
  vnet_disconnect_args_t a = {
    .handle = ctx->udp_session_handle,
    .app_index = qm->app_index,
  };

  if (vnet_disconnect_session (&a))
    clib_warning ("UDP session 0x%lx disconnect errored",
		  ctx->udp_session_handle);
}
typedef enum quic_session_connected_
{
  QUIC_SESSION_CONNECTED_NONE,
  QUIC_SESSION_CONNECTED_CLIENT,
  QUIC_SESSION_CONNECTED_SERVER,  
} quic_session_connected_t;

typedef struct quic_lib_vft_
{
  int (*init_crypto_context) (crypto_context_t *crctx, quic_ctx_t *ctx);
  void (*crypto_context_make_key_from_crctx) (clib_bihash_kv_24_8_t *kv, crypto_context_t *crctx);
  void (*crypto_decrypt_packet) (quic_ctx_t *qctx, quic_rx_packet_ctx_t *pctx);
  void (*crypto_encrypt_packet) (struct st_quicly_crypto_engine_t *engine,
			    quicly_conn_t *conn,
			    ptls_cipher_context_t *header_protect_ctx,
			    ptls_aead_context_t *packet_protect_ctx,
			    ptls_iovec_t datagram, size_t first_byte_at,
			    size_t payload_from, uint64_t packet_number,
			    int coalesced);
  void (*accept_connection) (quic_rx_packet_ctx_t * pctx);
  void (*receive_connection) (void *arg);
  int (*reset_connection) (u64 udp_session_handle,
				  quic_rx_packet_ctx_t *pctx);
  int (*connect) (quic_ctx_t * ctx, u32 ctx_index, u32 thread_index, struct sockaddr *sa);
  quic_session_connected_t (*is_session_connected) (quic_ctx_t * ctx);
  int (*connect_stream) (void * conn, void ** quic_stream, quic_stream_data_t ** quic_stream_data, u8 is_unidir);
  int (*stream_tx) (quic_ctx_t * ctx, session_t * stream_session);
  void (*reset_stream) (void * quic_stream, int error);
  void (*connection_delete) (quic_ctx_t * ctx);
  u8 * (*format_connection_stats) (u8 * s, va_list * args);
  u8 * (*format_stream_ctx_stream_id) (u8 * s, va_list * args);
  u8 * (*format_stream_connection) (u8 * s, va_list * args);
  void (*ack_rx_data) (session_t * stream_session);
  quic_ctx_t *(*get_conn_ctx) (void *conn);
  void (*store_conn_ctx) (void * conn, quic_ctx_t * ctx);
  int (*send_packets) (quic_ctx_t * ctx);
  int (*process_one_rx_packet) (u64 udp_session_handle, svm_fifo_t *f,
			    u32 fifo_offset, quic_rx_packet_ctx_t *pctx);
  int (*receive_a_packet) (quic_ctx_t *ctx, quic_rx_packet_ctx_t *pctx);
  void (*proto_on_close) (u32 ctx_index, u32 thread_index);
} quic_lib_vft_t;

extern quic_lib_vft_t *quic_vfts;
extern void quic_register_lib_type (const quic_lib_vft_t *vft,
			       quic_lib_type_t type);

static_always_inline void
quic_stop_ctx_timer (quic_ctx_t * ctx)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  quic_main_t *qm = get_quic_main();

  if (ctx->timer_handle == QUIC_TIMER_HANDLE_INVALID)
    return;
  tw = &qm->wrk_ctx[ctx->c_thread_index].timer_wheel;
  tw_timer_stop_1t_3w_1024sl_ov (tw, ctx->timer_handle);
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  QUIC_DBG (4, "Stopping timer for ctx %u", ctx->c_c_index);
}

#endif /* __included_quic_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
