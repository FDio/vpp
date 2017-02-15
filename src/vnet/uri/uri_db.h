/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef __included_uri_db_h__
#define __included_uri_db_h__

#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_48_8.h>
#include <vlibmemory/unix_shared_memory_queue.h>
#include <vlibmemory/api.h>
#include <vppinfra/sparse_vec.h>
#include <svm/svm_fifo_segment.h>
#include <vnet/uri/udp_session.h>
#include <vnet/uri/transport.h>

/** @file
    URI-related database
    
    Session lookup key; (src-ip, dst-ip, src-port, dst-port, tcp/udp)
    Value: (owner thread index << 32 | session_index);

    it's probably a bad idea to hang onto buffers waiting for the
    server to accept the connection. Be optimistic, set up, and
    be willing to flush the work.
*/

typedef enum 
{
  FIFO_EVENT_SERVER_RX,
  FIFO_EVENT_SERVER_TX,
  FIFO_EVENT_TIMEOUT,
  FIFO_EVENT_SERVER_EXIT,
} fifo_event_type_t;

/* Event queue input node static next indices */
typedef enum {
  URI_QUEUE_NEXT_DROP,
  URI_QUEUE_NEXT_TCP_IP4_OUTPUT,
  URI_QUEUE_NEXT_IP4_LOOKUP,
  URI_QUEUE_NEXT_TCP_IP6_OUTPUT,
  URI_QUEUE_NEXT_IP6_LOOKUP,
  URI_QUEUE_N_NEXT,
} uri_queue_next_t;

#define foreach_uri_session_type                \
  _(IP4_TCP, ip4_tcp)                           \
  _(IP4_UDP, ip4_udp)                           \
  _(IP6_TCP, ip6_tcp)                           \
  _(IP6_UDP, ip6_udp)                           \
  _(FIFO, fifo)

typedef enum
{
#define _(A, a) SESSION_TYPE_##A,
  foreach_uri_session_type
#undef _
  SESSION_TYPE_N_TYPES,
} stream_session_type_t;

/* 
 * Application session state
 */
typedef enum
{
  SESSION_STATE_LISTENING,
  SESSION_STATE_CONNECTING,
  SESSION_STATE_READY,
  SESSION_STATE_N_STATES,
} stream_session_state_t;

typedef CLIB_PACKED(struct
{
  svm_fifo_t * fifo;
  u8 event_type;
  /* $$$$ for event logging */
  u16 event_id;
  u32 enqueue_length;
}) fifo_event_t;

typedef struct _stream_session_t
{
  /** Type */
  u8 session_type;

  /** State */
  u8 session_state;

  /** Session index in per_thread pool */
  u32 session_index;

  /** Transport specific */
  u32 connection_index;

  u8 session_thread_index;

  /** Application specific */
  u32 pid;

  /** fifo pointers. Once allocated, these do not move */
  svm_fifo_t * server_rx_fifo;
  svm_fifo_t * server_tx_fifo;

  /** To avoid n**2 "one event per frame" check */
  u8 enqueue_epoch;

  /** used during unbind processing */
  u8 is_deleted;

  /** stream server pool index */
  u32 server_index;

  /** svm segment index */
  u32 server_segment_index;
} stream_session_t;

typedef enum
{
  APP_SERVER,
  APP_CLIENT
} application_type_t;

typedef struct _session_manager
{
  /** segments mapped by this server */
  u32 *segment_indices;

  /** Session fifo sizes. They are provided for binds and take default
   * values for connects */
  u32 rx_fifo_size;
  u32 tx_fifo_size;

  /** Configured additional segment size */
  u32 add_segment_size;

  /** Flag that indicates if additional segments should be created */
  u8 add_segment;
} session_manager_t;

typedef struct _application application_t;
typedef struct _session_manager_main session_manager_main_t;

typedef int
(*app_add_segment_cb) (application_t *server, const u8 *seg_name,
                       u32 seg_size);
typedef int
(*app_session_accept_cb) (application_t *server, stream_session_t *new_session,
                          unix_shared_memory_queue_t *vpp_event_queue);
typedef void
(*app_session_delete_cb) (session_manager_main_t *smm,
                          stream_session_t *session);
typedef void
(*app_session_clear_cb) (session_manager_main_t *smm, application_t *server,
                         stream_session_t *session);
typedef void
(*app_builtin_server_rx_cb) (session_manager_main_t *smm,
                             application_t *server, stream_session_t *session);
typedef int
(*app_session_connected_cb) (application_t *client, stream_session_t *s,
                             unix_shared_memory_queue_t * vpp_event_queue,
                             u8 code);

struct _application
{
  /** Flags */
  u32 flags;

  /** Application listens for events on this svm queue */
  unix_shared_memory_queue_t *event_queue;

  /** Index in server pool */
  u32 server_index;

  /** Stream session type */
  u8 session_type;

  /* Stream server mode: accept or connect */
  u8 mode;

  u32 session_manager_index;

  /*
   * Bind/Listen specific
   */

  /** Binary API connection index, ~0 if internal */
  u32 api_client_index;
  
  /** Accept cookie, for multiple session flavors ($$$ maybe) */
  u32 accept_cookie;

  /** Index of the listen session */
  u32 listen_session_index;

  /*
   * Callbacks: shoulder-taps for the server/client
   */

  /** Notify server of new segment */
  app_add_segment_cb add_segment_callback;

  /** Notify server of newly accepted session */
  app_session_accept_cb session_accept_callback;

  /* Rejected session callback */
  app_session_delete_cb session_delete_callback;

  /* Existing session delete callback */
  app_session_clear_cb session_clear_callback;

  /* Direct RX callback, for built-in servers */
  app_builtin_server_rx_cb builtin_server_rx_callback;

  /* Connection request callback */
  app_session_connected_cb session_connected_callback;
};

typedef clib_bihash_kv_16_8_t session_kv4_t;
typedef clib_bihash_kv_48_8_t session_kv6_t;

typedef int
(session_fifo_rx_fn) (vlib_main_t *vm, vlib_node_runtime_t *node,
                      session_manager_main_t *smm, fifo_event_t *e0,
                      stream_session_t *s0, u32 thread_index, int *n_tx_pkts);

typedef struct _session_manager_main
{
  /** Lookup tables for established sessions and listeners */
  clib_bihash_16_8_t v4_session_hash;
  clib_bihash_48_8_t v6_session_hash;

  /** Lookup tables for half-open sessions */
  clib_bihash_16_8_t v4_half_open_hash;
  clib_bihash_48_8_t v6_half_open_hash;

  /** Per worker thread session pools */
  stream_session_t **sessions;
  
  /** Pool of listen sessions. Same type as stream sessions to ease lookups */
  stream_session_t *listen_sessions[SESSION_TYPE_N_TYPES];

  /* Application pool */
  application_t *applications;

  /** Sparse vector to map dst port to stream server  */
  u16 * stream_server_by_dst_port[SESSION_TYPE_N_TYPES];

  /** per-worker enqueue epoch counters */
  u8 * current_enqueue_epoch;

  /** Per-worker thread vector of sessions to enqueue */
  u32 **session_indices_to_enqueue_by_thread;

  /** per-worker tx buffer free lists */
  u32 ** tx_buffers;

  /** Per worker-thread vector of partially read events */
  fifo_event_t **evts_partially_read;

  /** per-worker active event vectors */
  fifo_event_t ** fifo_events;

  /** per-worker built-in server copy buffers */
  u8 **copy_buffers;

  /** vpp fifo event queue */
  unix_shared_memory_queue_t **vpp_event_queues;

  /** Unique segment name counter */
  u32 unique_segment_name_counter;

  /* Connection manager used by incoming connects */
  u32 connect_manager_index[SESSION_TYPE_N_TYPES];

  session_manager_t *session_managers;

  session_fifo_rx_fn *session_rx_fns[SESSION_TYPE_N_TYPES];

  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

} session_manager_main_t;

extern session_manager_main_t session_manager_main;
extern vlib_node_registration_t udp4_uri_input_node;
extern vlib_node_registration_t tcp4_uri_input_node;
extern vlib_node_registration_t tcp6_uri_input_node;

always_inline session_manager_t *
application_get_session_manager (session_manager_main_t *smm, application_t *app)
{
  return pool_elt_at_index(smm->session_managers, app->session_manager_index);
}

always_inline session_manager_t *
connect_session_manager_get (session_manager_main_t *smm,
                             stream_session_type_t session_type)
{
  return pool_elt_at_index(smm->session_managers,
                           smm->connect_manager_index[session_type]);
}

void
session_manager_get_segment_info (u32 index, u8 **name, u32 *size);

int
stream_session_accept (transport_connection_t *tc, u32 listener_index, u8 sst,
                       u8 notify);

void
stream_session_delete (session_manager_main_t *smm, stream_session_t * s);

stream_session_t *
stream_session_lookup_listener4 (ip4_address_t * lcl, u16 lcl_port, u8 proto);
stream_session_t *
stream_session_lookup4 (ip4_address_t * lcl, ip4_address_t * rmt, u16 lcl_port,
                        u16 rmt_port, u8 proto, u32 my_thread_index);
stream_session_t *
stream_session_lookup_listener6 (ip6_address_t * lcl, u16 lcl_port, u8 proto);
stream_session_t *
stream_session_lookup6 (ip6_address_t * lcl, ip6_address_t * rmt, u16 lcl_port,
                        u16 rmt_port, u8 , u32 my_thread_index);

transport_connection_t *
stream_session_lookup_transport4 (session_manager_main_t *smm,
                                  ip4_address_t * lcl, ip4_address_t * rmt,
                                  u16 lcl_port, u16 rmt_port, u8 proto,
                                  u32 my_thread_index);
transport_connection_t *
stream_session_lookup_transport6 (session_manager_main_t *smm,
                                  ip6_address_t * lcl, ip6_address_t * rmt,
                                  u16 lcl_port, u16 rmt_port, u8 proto,
                                  u32 my_thread_index);

always_inline stream_session_t *
stream_session_get_tsi (u64 ti_and_si, u32 thread_index)
{
  ASSERT ((u32)(ti_and_si >> 32) == thread_index);
  return pool_elt_at_index (session_manager_main.sessions[thread_index],
                          ti_and_si & 0xFFFFFFFFULL);
}

always_inline stream_session_t *
stream_session_get (u64 si, u32 thread_index)
{
  return pool_elt_at_index(session_manager_main.sessions[thread_index], si);
}

int
stream_session_enqueue_data (transport_connection_t *tc, u8 *data, u16 len,
                             u8 queue_event);
u32
stream_session_peek_bytes (transport_connection_t *tc, u8 *buffer, u32 offset,
                           u32 max_bytes);
u32
stream_session_dequeue_drop (transport_connection_t *tc, u32 max_bytes);

int
stream_session_enqueue_notify (stream_session_t *s, u8 block);

void
stream_session_connect_notify (transport_connection_t *tc, u8 sst, u8 code);
void
stream_session_accept_notify (transport_connection_t *tc);
void
stream_session_reset_notify (transport_connection_t *tc);

always_inline session_manager_main_t *
vnet_get_session_manager_main ()
{
  return &session_manager_main;
}

int
session_manager_flush_enqueue_events (u32 my_thread_index);

#define HALF_OPEN_LOOKUP_INVALID_VALUE ((u64)~0)
#define INVALID_INDEX ((u32)~0)

extern session_fifo_rx_fn session_fifo_rx_peek;
extern session_fifo_rx_fn session_fifo_rx_dequeue;

void
uri_register_transport (u8 type, const transport_proto_vft_t *vft);

transport_proto_vft_t *
uri_get_transport (u8 type);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __included_uri_db_h__ */
