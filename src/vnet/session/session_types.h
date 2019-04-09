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

#define SESSION_LISTENER_PREFIX		0x5FFFFFFF

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
  u64 transport_opts;
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

/*
 * Session states
 */
typedef enum
{
  SESSION_STATE_CREATED,
  SESSION_STATE_LISTENING,
  SESSION_STATE_CONNECTING,
  SESSION_STATE_ACCEPTING,
  SESSION_STATE_READY,
  SESSION_STATE_OPENED,
  SESSION_STATE_TRANSPORT_CLOSING,
  SESSION_STATE_CLOSING,
  SESSION_STATE_CLOSED_WAITING,
  SESSION_STATE_TRANSPORT_CLOSED,
  SESSION_STATE_CLOSED,
  SESSION_STATE_N_STATES,
} session_state_t;

typedef enum session_flags_
{
  SESSION_F_RX_EVT = 1,
  SESSION_F_PROXY = (1 << 1),
  SESSION_F_QUIC_STREAM = (1 << 2),
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
    u32 listener_index;

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

typedef enum
{
  SESSION_IO_EVT_RX,
  SESSION_IO_EVT_TX,
  SESSION_IO_EVT_TX_FLUSH,
  SESSION_IO_EVT_BUILTIN_RX,
  SESSION_IO_EVT_BUILTIN_TX,
  SESSION_CTRL_EVT_RPC,
  SESSION_CTRL_EVT_CLOSE,
  SESSION_CTRL_EVT_BOUND,
  SESSION_CTRL_EVT_UNLISTEN_REPLY,
  SESSION_CTRL_EVT_ACCEPTED,
  SESSION_CTRL_EVT_ACCEPTED_REPLY,
  SESSION_CTRL_EVT_CONNECTED,
  SESSION_CTRL_EVT_CONNECTED_REPLY,
  SESSION_CTRL_EVT_DISCONNECTED,
  SESSION_CTRL_EVT_DISCONNECTED_REPLY,
  SESSION_CTRL_EVT_RESET,
  SESSION_CTRL_EVT_RESET_REPLY,
  SESSION_CTRL_EVT_REQ_WORKER_UPDATE,
  SESSION_CTRL_EVT_WORKER_UPDATE,
  SESSION_CTRL_EVT_WORKER_UPDATE_REPLY,
} session_evt_type_t;

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
