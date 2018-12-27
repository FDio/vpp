/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_SESSION_STREAM_SESSION_H_
#define SRC_VNET_SESSION_STREAM_SESSION_H_

#include <svm/svm_fifo.h>
#include <vnet/session/transport.h>

typedef u8 session_type_t;

/*
 * Application session state
 */
typedef enum
{
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
} stream_session_state_t;

typedef struct generic_session_
{
  svm_fifo_t *rx_fifo;		/**< rx fifo */
  svm_fifo_t *tx_fifo;		/**< tx fifo */
  session_type_t session_type;	/**< session type */
  volatile u8 session_state;	/**< session state */
  u32 session_index;		/**< index in owning pool */
} generic_session_t;

typedef struct _stream_session_t
{
  /** fifo pointers. Once allocated, these do not move */
  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;

  /** Type */
  session_type_t session_type;

  /** State */
  volatile u8 session_state;

  /** Session index in per_thread pool */
  u32 session_index;

  /** App worker pool index */
  u32 app_wrk_index;

  u8 thread_index;

  /** To avoid n**2 "one event per frame" check */
  u64 enqueue_epoch;

  /** svm segment index where fifos were allocated */
  u32 svm_segment_index;

  /** Transport specific */
  u32 connection_index;

  union
  {
    /** Parent listener session if the result of an accept */
    u32 listener_index;

    /** Application index if a listener */
    u32 app_index;
  };

  union
  {
    /** Transport app index for apps acting as transports */
    u32 t_app_index;

    /** Index in listener app's listener db */
    u32 listener_db_index;

    /** Opaque, for general use */
    u32 opaque;
  };

    CLIB_CACHE_LINE_ALIGN_MARK (pad);
} stream_session_t;

typedef struct local_session_
{
  /** fifo pointers. Once allocated, these do not move */
  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;

  /** Type */
  session_type_t session_type;

  /** State */
  volatile u8 session_state;

  /** Session index */
  u32 session_index;

  /** Server index */
  u32 app_wrk_index;

  /** Port for connection. Overlaps thread_index/enqueue_epoch */
  u16 port;

  /** Partly overlaps enqueue_epoch */
  u8 pad_epoch[7];

  /** Segment index where fifos were allocated */
  u32 svm_segment_index;

  /** Transport listener index. Overlaps connection index */
  u32 transport_listener_index;

  union
  {
    u32 listener_index;
    u32 app_index;
  };

  u32 listener_db_index;

  /** Has transport embedded when listener not purely local */
  session_type_t listener_session_type;

  /**
   * Client data
   */
  u32 client_wrk_index;
  u32 client_opaque;

  u64 server_evt_q;
  u64 client_evt_q;

    CLIB_CACHE_LINE_ALIGN_MARK (pad);
} local_session_t;

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
  u8 *hostname;
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

#endif /* SRC_VNET_SESSION_STREAM_SESSION_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
