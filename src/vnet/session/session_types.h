/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_SESSION_SESSION_TYPES_H_
#define SRC_VNET_SESSION_SESSION_TYPES_H_

#include <svm/svm_fifo.h>
#include <vnet/session/transport_types.h>

#define SESSION_INVALID_INDEX ((u32)~0)
#define SESSION_INVALID_HANDLE ((u64)~0)
#define SESSION_CTRL_MSG_MAX_SIZE 84

#define foreach_session_endpoint_fields				\
  foreach_transport_endpoint_cfg_fields				\
  _(u8, transport_proto)					\

typedef struct _session_endpoint
{
#define _(type, name) type name;
  foreach_session_endpoint_fields
#undef _
} session_endpoint_t;

typedef struct _session_endpoint_cfg
{
#define _(type, name) type name;
  foreach_session_endpoint_fields
#undef _
  u32 app_wrk_index;
  u32 opaque;
  u32 ns_index;
  u8 original_tp;
  u8 *hostname;
  u64 parent_handle;
  u32 ckpair_index;
  u8 crypto_engine;
  u8 flags;
} session_endpoint_cfg_t;

#define SESSION_IP46_ZERO			\
{						\
    .ip6 = {					\
	{ 0, 0, },				\
    },						\
}

#define TRANSPORT_ENDPOINT_NULL			\
{						\
  .sw_if_index = ENDPOINT_INVALID_INDEX,	\
  .ip = SESSION_IP46_ZERO,			\
  .fib_index = ENDPOINT_INVALID_INDEX,		\
  .is_ip4 = 0,					\
  .port = 0,					\
}
#define SESSION_ENDPOINT_NULL 			\
{						\
  .sw_if_index = ENDPOINT_INVALID_INDEX,	\
  .ip = SESSION_IP46_ZERO,			\
  .fib_index = ENDPOINT_INVALID_INDEX,		\
  .is_ip4 = 0,					\
  .port = 0,					\
  .peer = TRANSPORT_ENDPOINT_NULL,		\
  .transport_proto = 0,				\
}
#define SESSION_ENDPOINT_CFG_NULL 		\
{						\
  .sw_if_index = ENDPOINT_INVALID_INDEX,	\
  .ip = SESSION_IP46_ZERO,			\
  .fib_index = ENDPOINT_INVALID_INDEX,		\
  .is_ip4 = 0,					\
  .port = 0,					\
  .peer = TRANSPORT_ENDPOINT_NULL,		\
  .transport_proto = 0,				\
  .app_wrk_index = ENDPOINT_INVALID_INDEX,	\
  .opaque = ENDPOINT_INVALID_INDEX,		\
  .hostname = 0,				\
  .parent_handle = SESSION_INVALID_HANDLE,	\
  .ckpair_index = 0				\
}

#define session_endpoint_to_transport(_sep) ((transport_endpoint_t *)_sep)
#define session_endpoint_to_transport_cfg(_sep)		\
  ((transport_endpoint_cfg_t *)_sep)

always_inline u8
session_endpoint_fib_proto (session_endpoint_t * sep)
{
  return sep->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
}

static inline u8
session_endpoint_is_local (session_endpoint_t * sep)
{
  return (ip_is_zero (&sep->ip, sep->is_ip4)
	  || ip_is_local_host (&sep->ip, sep->is_ip4));
}

static inline u8
session_endpoint_is_zero (session_endpoint_t * sep)
{
  return ip_is_zero (&sep->ip, sep->is_ip4);
}

typedef u8 session_type_t;
typedef u64 session_handle_t;

typedef enum
{
  SESSION_CLEANUP_TRANSPORT,
  SESSION_CLEANUP_SESSION,
} session_cleanup_ntf_t;

/*
 * Session states
 */
#define foreach_session_state				\
  _(CREATED, "created")					\
  _(LISTENING, "listening")				\
  _(CONNECTING, "connecting")				\
  _(ACCEPTING, "accepting")				\
  _(READY, "ready")					\
  _(OPENED, "opened")					\
  _(TRANSPORT_CLOSING, "transport-closing")		\
  _(CLOSING, "closing")					\
  _(APP_CLOSED, "app-closed")				\
  _(TRANSPORT_CLOSED, "transport-closed")		\
  _(CLOSED, "closed")					\
  _(TRANSPORT_DELETED, "transport-deleted")		\

typedef enum
{
#define _(sym, str) SESSION_STATE_ ## sym,
  foreach_session_state
#undef _
    SESSION_N_STATES,
} session_state_t;

#define foreach_session_flag				\
  _(RX_EVT, "rx-event")					\
  _(PROXY, "proxy")					\
  _(CUSTOM_TX, "custom-tx")				\
  _(IS_MIGRATING, "migrating")				\
  _(UNIDIRECTIONAL, "unidirectional")			\

typedef enum session_flags_bits_
{
#define _(sym, str) SESSION_F_BIT_ ## sym,
  foreach_session_flag
#undef _
  SESSION_N_FLAGS
} session_flag_bits_t;

typedef enum session_flags_
{
#define _(sym, str) SESSION_F_ ## sym = 1 << SESSION_F_BIT_ ## sym,
  foreach_session_flag
#undef _
} session_flags_t;

typedef struct session_
{
  /** Pointers to rx/tx buffers. Once allocated, these do not move */
  svm_fifo_t *rx_fifo;
  svm_fifo_t *tx_fifo;

  /** Type built from transport and network protocol types */
  session_type_t session_type;

  /** State in session layer state machine. See @ref session_state_t */
  volatile u8 session_state;

  /** Index in thread pool where session was allocated */
  u32 session_index;

  /** Index of the app worker that owns the session */
  u32 app_wrk_index;

  /** Index of the thread that allocated the session */
  u8 thread_index;

  /** Session flags. See @ref session_flags_t */
  u32 flags;

  /** Index of the transport connection associated to the session */
  u32 connection_index;

  /** Index of application that owns the listener. Set only if a listener */
  u32 app_index;

  union
  {
    /** Parent listener session index if the result of an accept */
    session_handle_t listener_handle;

    /** App listener index in app's listener pool if a listener */
    u32 al_index;
  };

  /** Opaque, for general use */
  u32 opaque;

    CLIB_CACHE_LINE_ALIGN_MARK (pad);
} session_t;

always_inline session_type_t
session_type_from_proto_and_ip (transport_proto_t proto, u8 is_ip4)
{
  return (proto << 1 | is_ip4);
}

always_inline transport_proto_t
session_type_transport_proto (session_type_t st)
{
  return (st >> 1);
}

always_inline u8
session_type_is_ip4 (session_type_t st)
{
  return (st & 1);
}

always_inline transport_proto_t
session_get_transport_proto (session_t * s)
{
  return (s->session_type >> 1);
}

always_inline fib_protocol_t
session_get_fib_proto (session_t * s)
{
  u8 is_ip4 = s->session_type & 1;
  return (is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);
}

always_inline u8
session_has_transport (session_t * s)
{
  return (session_get_transport_proto (s) != TRANSPORT_PROTO_NONE);
}

static inline transport_service_type_t
session_transport_service_type (session_t * s)
{
  transport_proto_t tp;
  tp = session_get_transport_proto (s);
  return transport_protocol_service_type (tp);
}

static inline transport_tx_fn_type_t
session_transport_tx_fn_type (session_t * s)
{
  transport_proto_t tp;
  tp = session_get_transport_proto (s);
  return transport_protocol_tx_fn_type (tp);
}

static inline u8
session_tx_is_dgram (session_t * s)
{
  return (session_transport_tx_fn_type (s) == TRANSPORT_TX_DGRAM);
}

always_inline session_handle_t
session_handle (session_t * s)
{
  return ((u64) s->thread_index << 32) | (u64) s->session_index;
}

always_inline u32
session_index_from_handle (session_handle_t handle)
{
  return handle & 0xFFFFFFFF;
}

always_inline u32
session_thread_from_handle (session_handle_t handle)
{
  return handle >> 32;
}

always_inline void
session_parse_handle (session_handle_t handle, u32 * index,
		      u32 * thread_index)
{
  *index = session_index_from_handle (handle);
  *thread_index = session_thread_from_handle (handle);
}

static inline session_handle_t
session_make_handle (u32 session_index, u32 thread_index)
{
  return (((u64) thread_index << 32) | (u64) session_index);
}

typedef enum
{
  SESSION_IO_EVT_RX,
  SESSION_IO_EVT_TX,
  SESSION_IO_EVT_TX_FLUSH,
  SESSION_IO_EVT_BUILTIN_RX,
  SESSION_IO_EVT_BUILTIN_TX,
  SESSION_CTRL_EVT_RPC,
  SESSION_CTRL_EVT_CLOSE,
  SESSION_CTRL_EVT_RESET,
  SESSION_CTRL_EVT_BOUND,
  SESSION_CTRL_EVT_UNLISTEN_REPLY,
  SESSION_CTRL_EVT_ACCEPTED,
  SESSION_CTRL_EVT_ACCEPTED_REPLY,
  SESSION_CTRL_EVT_CONNECTED,
  SESSION_CTRL_EVT_DISCONNECTED,
  SESSION_CTRL_EVT_DISCONNECTED_REPLY,
  SESSION_CTRL_EVT_RESET_REPLY,
  SESSION_CTRL_EVT_REQ_WORKER_UPDATE,
  SESSION_CTRL_EVT_WORKER_UPDATE,
  SESSION_CTRL_EVT_WORKER_UPDATE_REPLY,
  SESSION_CTRL_EVT_DISCONNECT,
  SESSION_CTRL_EVT_CONNECT,
  SESSION_CTRL_EVT_CONNECT_URI,
  SESSION_CTRL_EVT_LISTEN,
  SESSION_CTRL_EVT_LISTEN_URI,
  SESSION_CTRL_EVT_UNLISTEN,
  SESSION_CTRL_EVT_APP_DETACH,
  SESSION_CTRL_EVT_APP_ADD_SEGMENT,
  SESSION_CTRL_EVT_APP_DEL_SEGMENT,
  SESSION_CTRL_EVT_MIGRATED,
} session_evt_type_t;

#define foreach_session_ctrl_evt				\
  _(LISTEN, listen)						\
  _(LISTEN_URI, listen_uri)					\
  _(BOUND, bound)						\
  _(UNLISTEN, unlisten)						\
  _(UNLISTEN_REPLY, unlisten_reply)				\
  _(ACCEPTED, accepted)						\
  _(ACCEPTED_REPLY, accepted_reply)				\
  _(CONNECT, connect)						\
  _(CONNECT_URI, connect_uri)					\
  _(CONNECTED, connected)					\
  _(DISCONNECT, disconnect)					\
  _(DISCONNECTED, disconnected)					\
  _(DISCONNECTED_REPLY, disconnected_reply)			\
  _(RESET_REPLY, reset_reply)					\
  _(REQ_WORKER_UPDATE, req_worker_update)			\
  _(WORKER_UPDATE, worker_update)				\
  _(WORKER_UPDATE_REPLY, worker_update_reply)			\
  _(APP_DETACH, app_detach)					\
  _(APP_ADD_SEGMENT, app_add_segment)				\
  _(APP_DEL_SEGMENT, app_del_segment)				\

/* Deprecated and will be removed. Use types above */
#define FIFO_EVENT_APP_RX SESSION_IO_EVT_RX
#define FIFO_EVENT_APP_TX SESSION_IO_EVT_TX
#define FIFO_EVENT_DISCONNECT SESSION_CTRL_EVT_CLOSE
#define FIFO_EVENT_BUILTIN_RX SESSION_IO_EVT_BUILTIN_RX
#define FIFO_EVENT_BUILTIN_TX SESSION_IO_EVT_BUILTIN_TX

typedef enum
{
  SESSION_MQ_IO_EVT_RING,
  SESSION_MQ_CTRL_EVT_RING,
  SESSION_MQ_N_RINGS
} session_mq_rings_e;

typedef struct
{
  void *fp;
  void *arg;
} session_rpc_args_t;

typedef struct
{
  u8 event_type;
  u8 postponed;
  union
  {
    u32 session_index;
    session_handle_t session_handle;
    session_rpc_args_t rpc_args;
    u32 ctrl_data_index;
    struct
    {
      u8 data[0];
    };
  };
} __clib_packed session_event_t;

#define SESSION_MSG_NULL { }

typedef struct session_dgram_pre_hdr_
{
  u32 data_length;
  u32 data_offset;
} session_dgram_pre_hdr_t;

typedef struct session_dgram_header_
{
  u32 data_length;
  u32 data_offset;
  ip46_address_t rmt_ip;
  ip46_address_t lcl_ip;
  u16 rmt_port;
  u16 lcl_port;
  u8 is_ip4;
} __clib_packed session_dgram_hdr_t;

#define SESSION_CONN_ID_LEN 37
#define SESSION_CONN_HDR_LEN 45

STATIC_ASSERT (sizeof (session_dgram_hdr_t) == (SESSION_CONN_ID_LEN + 8),
	       "session conn id wrong length");
#endif /* SRC_VNET_SESSION_SESSION_TYPES_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
