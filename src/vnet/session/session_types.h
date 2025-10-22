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
#define SESSION_CTRL_MSG_MAX_SIZE 86
#define SESSION_CTRL_MSG_TX_MAX_SIZE 160
#define SESSION_NODE_FRAME_SIZE 128

typedef u8 session_type_t;
typedef u64 session_handle_t;

typedef union session_handle_tu_
{
  session_handle_t handle;
  struct
  {
    u32 session_index;
    u32 thread_index;
  };
} __attribute__ ((__transparent_union__)) session_handle_tu_t;

#define foreach_session_endpoint_fields				\
  foreach_transport_endpoint_cfg_fields				\
  _(u8, transport_proto)					\

typedef struct _session_endpoint
{
#define _(type, name) type name;
  foreach_session_endpoint_fields
#undef _
} session_endpoint_t;

#define foreach_session_endpoint_cfg_flags                                    \
  _ (PROXY_LISTEN, "proxy listener")                                          \
  _ (SECURE, "secure")

typedef enum session_endpoint_cfg_flags_bits_
{
#define _(sym, str) SESSION_ENDPT_CFG_F_BIT_##sym,
  foreach_session_endpoint_cfg_flags
#undef _
} __clib_packed session_endpoint_cfg_flags_bits_t;

typedef enum session_endpoint_cfg_flags_
{
#define _(sym, str)                                                           \
  SESSION_ENDPT_CFG_F_##sym = 1 << SESSION_ENDPT_CFG_F_BIT_##sym,
  foreach_session_endpoint_cfg_flags
#undef _
} __clib_packed session_endpoint_cfg_flags_t;

typedef struct _session_endpoint_cfg
{
#define _(type, name) type name;
  foreach_session_endpoint_fields
#undef _
  u32 app_wrk_index;
  u32 opaque;
  u32 ns_index;
  u8 original_tp;
  u64 parent_handle;
  session_endpoint_cfg_flags_t flags;
  transport_endpt_ext_cfgs_t ext_cfgs;
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
#define SESSION_ENDPOINT_CFG_NULL                                             \
  {                                                                           \
    .sw_if_index = ENDPOINT_INVALID_INDEX, .ip = SESSION_IP46_ZERO,           \
    .fib_index = ENDPOINT_INVALID_INDEX, .is_ip4 = 0, .port = 0,              \
    .peer = TRANSPORT_ENDPOINT_NULL, .transport_proto = 0,                    \
    .app_wrk_index = ENDPOINT_INVALID_INDEX,                                  \
    .opaque = ENDPOINT_INVALID_INDEX,                                         \
    .parent_handle = SESSION_INVALID_HANDLE,                                  \
    .ext_cfgs = TRANSPORT_ENDPT_EXT_CFGS_NULL,                                \
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

typedef enum
{
  SESSION_CLEANUP_TRANSPORT,
  SESSION_CLEANUP_SESSION,
} session_cleanup_ntf_t;

typedef enum session_ft_action_
{
  SESSION_FT_ACTION_ENQUEUED,
  SESSION_FT_ACTION_DEQUEUED,
  SESSION_FT_ACTION_N_ACTIONS
} session_ft_action_t;

/*
 * Session states
 */
#define foreach_session_state                                                 \
  _ (CREATED, "created")                                                      \
  _ (LISTENING, "listening")                                                  \
  _ (CONNECTING, "connecting")                                                \
  _ (ACCEPTING, "accepting")                                                  \
  _ (READY, "ready")                                                          \
  _ (OPENED, "opened")                                                        \
  _ (TRANSPORT_CLOSING, "transport-closing")                                  \
  _ (CLOSING, "closing")                                                      \
  _ (APP_CLOSED, "app-closed")                                                \
  _ (TRANSPORT_CLOSED, "transport-closed")                                    \
  _ (CLOSED, "closed")                                                        \
  _ (TRANSPORT_DELETED, "transport-deleted")

typedef enum
{
#define _(sym, str) SESSION_STATE_ ## sym,
  foreach_session_state
#undef _
    SESSION_N_STATES,
} __clib_packed session_state_t;

#define foreach_session_flag                                                  \
  _ (RX_EVT, "rx-event")                                                      \
  _ (PROXY, "proxy")                                                          \
  _ (CUSTOM_TX, "custom-tx")                                                  \
  _ (IS_MIGRATING, "migrating")                                               \
  _ (UNIDIRECTIONAL, "unidirectional")                                        \
  _ (CUSTOM_FIFO_TUNING, "custom-fifo-tuning")                                \
  _ (HALF_OPEN, "half-open")                                                  \
  _ (APP_CLOSED, "app-closed")                                                \
  _ (IS_CLESS, "connectionless")                                              \
  _ (RX_READY, "rx-ready")                                                    \
  _ (TPT_INIT_CLOSE, "transport-init-close")

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

  union
  {
    session_handle_t handle;
    struct
    {
      /** Index in thread pool where session was allocated */
      u32 session_index;

      /** Index of the thread that allocated the session */
      clib_thread_index_t thread_index;
    };
  };

  /** Type built from transport and network protocol types */
  session_type_t session_type;

  /** State in session layer state machine. See @ref session_state_t */
  volatile session_state_t session_state;

  /** Index of the app worker that owns the session */
  u32 app_wrk_index;

  /** Session flags. See @ref session_flags_t */
  session_flags_t flags;

  /** Index of the transport connection associated to the session */
  u32 connection_index;

  /** App listener index in app's listener pool if a listener */
  u32 al_index;

  union
  {
    /** Parent listener session index if the result of an accept */
    session_handle_t listener_handle;

    /** Index in app worker's half-open table if a half-open */
    u32 ho_index;
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
  return (session_get_transport_proto (s) != TRANSPORT_PROTO_CT);
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
  return s->handle;
}

always_inline u32
session_index_from_handle (session_handle_tu_t handle)
{
  return handle.session_index;
}

always_inline u32
session_thread_from_handle (session_handle_tu_t handle)
{
  return handle.thread_index;
}

always_inline void
session_parse_handle (session_handle_tu_t handle, u32 *index,
		      u32 *thread_index)
{
  *index = handle.session_index;
  *thread_index = handle.thread_index;
}

static inline session_handle_t
session_make_handle (u32 session_index, u32 data)
{
  return ((session_handle_tu_t){ .session_index = session_index,
				 .thread_index = data })
    .handle;
}

typedef enum
{
  SESSION_IO_EVT_RX,
  SESSION_IO_EVT_TX,
  SESSION_IO_EVT_TX_FLUSH,
  SESSION_IO_EVT_BUILTIN_RX,
  SESSION_IO_EVT_TX_MAIN,
  SESSION_CTRL_EVT_RPC,
  SESSION_CTRL_EVT_HALF_CLOSE,
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
  SESSION_CTRL_EVT_SHUTDOWN,
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
  SESSION_CTRL_EVT_CLEANUP,
  SESSION_CTRL_EVT_APP_WRK_RPC,
  SESSION_CTRL_EVT_TRANSPORT_ATTR,
  SESSION_CTRL_EVT_TRANSPORT_ATTR_REPLY,
  SESSION_CTRL_EVT_TRANSPORT_CLOSED,
  SESSION_CTRL_EVT_HALF_CLEANUP,
} session_evt_type_t;

#define foreach_session_ctrl_evt                                              \
  _ (LISTEN, listen)                                                          \
  _ (LISTEN_URI, listen_uri)                                                  \
  _ (BOUND, bound)                                                            \
  _ (UNLISTEN, unlisten)                                                      \
  _ (UNLISTEN_REPLY, unlisten_reply)                                          \
  _ (ACCEPTED, accepted)                                                      \
  _ (ACCEPTED_REPLY, accepted_reply)                                          \
  _ (CONNECT, connect)                                                        \
  _ (CONNECT_URI, connect_uri)                                                \
  _ (CONNECTED, connected)                                                    \
  _ (SHUTDOWN, shutdown)                                                      \
  _ (DISCONNECT, disconnect)                                                  \
  _ (DISCONNECTED, disconnected)                                              \
  _ (DISCONNECTED_REPLY, disconnected_reply)                                  \
  _ (RESET_REPLY, reset_reply)                                                \
  _ (REQ_WORKER_UPDATE, req_worker_update)                                    \
  _ (WORKER_UPDATE, worker_update)                                            \
  _ (WORKER_UPDATE_REPLY, worker_update_reply)                                \
  _ (APP_DETACH, app_detach)                                                  \
  _ (APP_ADD_SEGMENT, app_add_segment)                                        \
  _ (APP_DEL_SEGMENT, app_del_segment)                                        \
  _ (MIGRATED, migrated)                                                      \
  _ (CLEANUP, cleanup)                                                        \
  _ (APP_WRK_RPC, app_wrk_rpc)                                                \
  _ (TRANSPORT_ATTR, transport_attr)                                          \
  _ (TRANSPORT_ATTR_REPLY, transport_attr_reply)                              \
/* Deprecated and will be removed. Use types above */
#define FIFO_EVENT_APP_RX SESSION_IO_EVT_RX
#define FIFO_EVENT_APP_TX SESSION_IO_EVT_TX
#define FIFO_EVENT_DISCONNECT SESSION_CTRL_EVT_CLOSE
#define FIFO_EVENT_BUILTIN_RX SESSION_IO_EVT_BUILTIN_RX

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
    u64 as_u64[2];
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
  u16 gso_size;
} __clib_packed session_dgram_hdr_t;

#define SESSION_CONN_ID_LEN 37
#define SESSION_CONN_HDR_LEN 47
STATIC_ASSERT (sizeof (session_dgram_hdr_t) == (SESSION_CONN_ID_LEN + 10),
	       "session conn id wrong length");

#define foreach_session_error                                                 \
  _ (NONE, "no error")                                                        \
  _ (UNKNOWN, "generic/unknown error")                                        \
  _ (REFUSED, "refused")                                                      \
  _ (TIMEDOUT, "timedout")                                                    \
  _ (ALLOC, "obj/memory allocation error")                                    \
  _ (OWNER, "object not owned by application")                                \
  _ (NOROUTE, "no route")                                                     \
  _ (NOINTF, "no resolving interface")                                        \
  _ (NOIP, "no ip for lcl interface")                                         \
  _ (NOPORT, "no lcl port")                                                   \
  _ (NOSUPPORT, "not supported")                                              \
  _ (NOLISTEN, "not listening")                                               \
  _ (NOSESSION, "session does not exist")                                     \
  _ (NOAPP, "app not attached")                                               \
  _ (APP_ATTACHED, "app already attached")                                    \
  _ (PORTINUSE, "lcl port in use")                                            \
  _ (IPINUSE, "ip in use")                                                    \
  _ (ALREADY_LISTENING, "ip port pair already listened on")                   \
  _ (ADDR_NOT_IN_USE, "address not in use")                                   \
  _ (INVALID, "invalid value")                                                \
  _ (INVALID_RMT_IP, "invalid remote ip")                                     \
  _ (INVALID_APPWRK, "invalid app worker")                                    \
  _ (INVALID_NS, "invalid namespace")                                         \
  _ (SEG_NO_SPACE, "Couldn't allocate a fifo pair")                           \
  _ (SEG_NO_SPACE2, "Created segment, couldn't allocate a fifo pair")         \
  _ (SEG_CREATE, "Couldn't create a new segment")                             \
  _ (FILTERED, "session filtered")                                            \
  _ (SCOPE, "scope not supported")                                            \
  _ (BAPI_NO_FD, "bapi doesn't have a socket fd")                             \
  _ (BAPI_SEND_FD, "couldn't send fd over bapi socket fd")                    \
  _ (BAPI_NO_REG, "app bapi registration not found")                          \
  _ (MQ_MSG_ALLOC, "failed to alloc mq msg")                                  \
  _ (TLS_HANDSHAKE, "failed tls handshake")                                   \
  _ (EVENTFD_ALLOC, "failed to alloc eventfd")                                \
  _ (NOEXTCFG, "no extended transport config")                                \
  _ (NOCRYPTOENG, "no crypto engine")                                         \
  _ (NOCRYPTOCKP, "cert key pair not found ")                                 \
  _ (LOCAL_CONNECT, "could not connect with local scope")                     \
  _ (WRONG_NS_SECRET, "wrong ns secret")                                      \
  _ (SYSCALL, "system call error")                                            \
  _ (TRANSPORT_NO_REG, "transport was not registered")                        \
  _ (MAX_STREAMS_HIT, "max streams hit")

typedef enum session_error_p_
{
#define _(sym, str) SESSION_EP_##sym,
  foreach_session_error
#undef _
  SESSION_N_ERRORS
} session_error_p_t;

typedef enum session_error_
{
#define _(sym, str) SESSION_E_##sym = -SESSION_EP_##sym,
  foreach_session_error
#undef _
} session_error_t;

#define SESSION_CLI_ID_LEN "60"
#define SESSION_CLI_STATE_LEN "15"

/* Maintained for compatibility. Will be deprecated */
#define SESSION_ERROR_SEG_CREATE SESSION_E_SEG_CREATE
#define SESSION_ERROR_NO_SPACE SESSION_E_SEG_NO_SPACE
#define SESSION_ERROR_NEW_SEG_NO_SPACE SESSION_E_SEG_NO_SPACE2

#endif /* SRC_VNET_SESSION_SESSION_TYPES_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
