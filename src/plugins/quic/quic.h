/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_h__
#define __included_quic_h__

#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>

#include <vppinfra/clib.h>
#include <vppinfra/lock.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>
#include <vppinfra/bihash_16_8.h>

#include <vnet/crypto/crypto.h>

/* QUIC log levels
 * 1 - errors
 * 2 - connection/stream events
 * 3 - packet events
 * 4 - timer events
 **/

#define QUIC_DEBUG		  0
#define QUIC_TSTAMP_RESOLUTION  0.001	/* QUIC tick resolution (1ms) */
#define QUIC_TIMER_HANDLE_INVALID ((u32) ~0)
#define QUIC_SESSION_INVALID ((u32) ~0 - 1)
#define QUIC_MAX_PACKET_SIZE 1280

#define QUIC_INT_MAX  0x3FFFFFFFFFFFFFFF
#define QUIC_DEFAULT_FIFO_SIZE (64 << 10)
#define QUIC_SEND_PACKET_VEC_SIZE 16

#define QUIC_MAX_COALESCED_PACKET 4

#define QUIC_RCV_MAX_PACKETS 16

#define QUIC_DEFAULT_CONN_TIMEOUT (30 * 1000)	/* 30 seconds */

#define QUIC_DECRYPT_PACKET_OK 0
#define QUIC_DECRYPT_PACKET_NOTOFFLOADED 1
#define QUIC_DECRYPT_PACKET_ERROR 2

#define DEFAULT_MAX_PACKETS_PER_KEY	     16777216
#define QUIC_CRYPTO_CTX_POOL_PER_THREAD_SIZE 256

#if QUIC_DEBUG
#define QUIC_DBG(_lvl, _fmt, _args...)   \
  if (_lvl <= QUIC_DEBUG)                \
    clib_warning (_fmt, ##_args)
#else
#define QUIC_DBG(_lvl, _fmt, _args...)
#endif

#if CLIB_ASSERT_ENABLE
#define QUIC_ASSERT(truth) ASSERT ((truth))
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

typedef enum quic_engine_type_
{
  QUIC_ENGINE_NONE,
  QUIC_ENGINE_QUICLY,
  QUIC_ENGINE_OPENSSL,
  QUIC_ENGINE_LAST = QUIC_ENGINE_OPENSSL,
} quic_engine_type_t;

static_always_inline char *
quic_engine_type_str (quic_engine_type_t engine_type)
{
  switch (engine_type)
    {
    case QUIC_ENGINE_NONE:
      return ("QUIC_ENGINE_NONE");
    case QUIC_ENGINE_QUICLY:
      return ("QUIC_ENGINE_QUICLY");
    case QUIC_ENGINE_OPENSSL:
      return ("QUIC_ENGINE_OPENSSL");
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
    void *hp_ctx;
    void *aead_ctx;
  } ingress_keys;
  int key_phase_ingress;
  ip46_address_t rmt_ip;
  u16 rmt_port;
  ip46_address_t lcl_ip;
  u16 lcl_port;

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

typedef struct quic_stream_data_
{
  u32 ctx_id;
  u32 thread_index;
  u32 app_rx_data_len;		/**< bytes received, to be read by external app */
  u32 app_tx_data_len;		/**< bytes sent */
} quic_stream_data_t;

typedef struct quic_stats_
{
  u64 num_bytes_sent;
  u64 num_bytes_received;
  u64 num_packets_sent;
  u64 num_packets_received;
  u64 num_packets_ack_received;
  u64 num_packets_lost;
  u64 rtt_smoothed;
  u64 rtt_minimum;
  u64 rtt_variance;
} quic_stats_t;

#define foreach_quic_rx_pkt_ctx_field                                         \
  _ (u32, ctx_index)                                                          \
  _ (u32, thread_index)                                                       \
  _ (u8, ptype)

typedef struct quic_rx_packet_ctx_
{
#define _(type, name) type name;
  foreach_quic_rx_pkt_ctx_field
#undef _
    u8 padding[1024 * 128]; // FIXME: remove hardcoded size
} quic_rx_packet_ctx_t;

typedef struct quic_worker_ctx_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  int64_t time_now;
  tw_timer_wheel_1t_3w_1024sl_ov_t timer_wheel;
  crypto_context_t *crypto_ctx_pool;
} quic_worker_ctx_t;

typedef struct quic_main_
{
  vlib_node_registration_t *quic_input_node;
  u32 app_index;
  quic_ctx_t **ctx_pool;
  quic_worker_ctx_t *wrk_ctx;

  u8 default_crypto_engine; /**< Used if you do connect with CRYPTO_ENGINE_NONE
			       (0) */
  u64 max_packets_per_key;  /**< number of packets that can be sent without a
			       key update */
  u8 default_quic_cc;

  u32 udp_fifo_size;
  u32 udp_fifo_prealloc;
  u32 connection_timeout;
  int num_threads;
  quic_engine_type_t engine_type;
  u8 engine_is_initialized[QUIC_ENGINE_LAST + 1];
} quic_main_t;

extern quic_main_t quic_main;

static_always_inline u32
quic_ctx_alloc (quic_main_t *qm, u32 thread_index)
{
  quic_ctx_t *ctx;

  pool_get_aligned_safe (qm->ctx_pool[thread_index], ctx,
			 CLIB_CACHE_LINE_BYTES);

  clib_memset (ctx, 0, sizeof (quic_ctx_t));
  ctx->c_thread_index = thread_index;
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  QUIC_DBG (3, "Allocated quic_ctx %u on thread %u",
	    ctx - qm->ctx_pool[thread_index], thread_index);
  return ctx - qm->ctx_pool[thread_index];
}

static_always_inline void
quic_ctx_free (quic_main_t *qm, quic_ctx_t *ctx)
{
  QUIC_DBG (2, "Free ctx %u %x", ctx->c_thread_index, ctx->c_c_index);
  u32 thread_index = ctx->c_thread_index;
  QUIC_ASSERT (ctx->timer_handle == QUIC_TIMER_HANDLE_INVALID);
  if (CLIB_DEBUG)
    clib_memset (ctx, 0xfb, sizeof (*ctx));
  pool_put (qm->ctx_pool[thread_index], ctx);
}

static_always_inline void
quic_increment_counter (quic_main_t *qm, u8 evt, u8 val)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_increment_counter (vm, qm->quic_input_node->index, evt, val);
}

static_always_inline int
quic_ctx_is_stream (quic_ctx_t *ctx)
{
  return (ctx->flags & QUIC_F_IS_STREAM);
}

static_always_inline int
quic_ctx_is_listener (quic_ctx_t *ctx)
{
  return (ctx->flags & QUIC_F_IS_LISTENER);
}

static_always_inline int
quic_ctx_is_conn (quic_ctx_t *ctx)
{
  return !(quic_ctx_is_listener (ctx) || quic_ctx_is_stream (ctx));
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

typedef enum quic_session_connected_
{
  QUIC_SESSION_CONNECTED_NONE,
  QUIC_SESSION_CONNECTED_CLIENT,
  QUIC_SESSION_CONNECTED_SERVER,
} quic_session_connected_t;

// TODO: Define appropriate QUIC return values for quic_engine_vft functions!
typedef struct quic_engine_vft_
{
  void (*engine_init) (quic_main_t *qm);
  int (*app_cert_key_pair_delete) (app_cert_key_pair_t *ckpair);
  int (*crypto_context_acquire) (quic_ctx_t *ctx);
  void (*crypto_context_release) (u32 crypto_context_index, u8 thread_index);
  int (*connect) (quic_ctx_t *ctx, u32 ctx_index, u32 thread_index,
		  struct sockaddr *sa);
  int (*connect_stream) (void *conn, void **quic_stream,
			 quic_stream_data_t **quic_stream_data, u8 is_unidir);
  void (*connect_stream_error_reset) (void *quic_stream);
  void (*connection_receive) (quic_ctx_t *temp_ctx);
  void (*connection_get_stats) (void *conn, quic_stats_t *conn_stats);
  int (*udp_session_rx_packets) (session_t *udp_session);
  void (*ack_rx_data) (session_t *stream_session);
  int (*stream_tx) (quic_ctx_t *ctx, session_t *stream_session);
  int (*send_packets) (quic_ctx_t *ctx);
  u8 *(*format_connection_stats) (u8 *s, va_list *args);
  u8 *(*format_stream_connection) (u8 *s, va_list *args);
  u8 *(*format_stream_ctx_stream_id) (u8 *s, va_list *args);
  void (*proto_on_close) (u32 ctx_index, u32 thread_index);
} quic_engine_vft_t;

extern quic_engine_vft_t *quic_engine_vfts;
extern void quic_register_engine (const quic_engine_vft_t *vft,
				  quic_engine_type_t engine_type);
typedef void (*quic_register_engine_fn) (const quic_engine_vft_t *vft,
					 quic_engine_type_t engine_type);

static_always_inline void
quic_stop_ctx_timer (quic_main_t *qm, quic_ctx_t *ctx)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;

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
