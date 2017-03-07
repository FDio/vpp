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
#ifndef __included_session_h__
#define __included_session_h__

#include <vnet/session/transport.h>
#include <vlibmemory/unix_shared_memory_queue.h>
#include <vlibmemory/api.h>
#include <vppinfra/sparse_vec.h>
#include <svm/svm_fifo_segment.h>

#define HALF_OPEN_LOOKUP_INVALID_VALUE ((u64)~0)
#define INVALID_INDEX ((u32)~0)

/* TODO decide how much since we have pre-data as well */
#define MAX_HDRS_LEN    100	/* Max number of bytes for headers */

typedef enum
{
  FIFO_EVENT_SERVER_RX,
  FIFO_EVENT_SERVER_TX,
  FIFO_EVENT_TIMEOUT,
  FIFO_EVENT_SERVER_EXIT,
} fifo_event_type_t;

#define foreach_session_input_error                                         \
_(NO_SESSION, "No session drops")                                       \
_(NO_LISTENER, "No listener for dst port drops")                        \
_(ENQUEUED, "Packets pushed into rx fifo")                              \
_(NOT_READY, "Session not ready packets")                               \
_(FIFO_FULL, "Packets dropped for lack of rx fifo space")               \
_(EVENT_FIFO_FULL, "Events not sent for lack of event fifo space")      \
_(API_QUEUE_FULL, "Sessions not created for lack of API queue space")   \
_(NEW_SEG_NO_SPACE, "Created segment, couldn't allocate a fifo pair")   \
_(NO_SPACE, "Couldn't allocate a fifo pair")

typedef enum
{
#define _(sym,str) SESSION_ERROR_##sym,
  foreach_session_input_error
#undef _
    SESSION_N_ERROR,
} session_error_t;

/* Event queue input node static next indices */
typedef enum
{
  SESSION_QUEUE_NEXT_DROP,
  SESSION_QUEUE_NEXT_TCP_IP4_OUTPUT,
  SESSION_QUEUE_NEXT_IP4_LOOKUP,
  SESSION_QUEUE_NEXT_TCP_IP6_OUTPUT,
  SESSION_QUEUE_NEXT_IP6_LOOKUP,
  SESSION_QUEUE_N_NEXT,
} session_queue_next_t;

#define foreach_session_type                    \
  _(IP4_TCP, ip4_tcp)                           \
  _(IP4_UDP, ip4_udp)                           \
  _(IP6_TCP, ip6_tcp)                           \
  _(IP6_UDP, ip6_udp)

typedef enum
{
#define _(A, a) SESSION_TYPE_##A,
  foreach_session_type
#undef _
    SESSION_N_TYPES,
} session_type_t;

/*
 * Application session state
 */
typedef enum
{
  SESSION_STATE_LISTENING,
  SESSION_STATE_CONNECTING,
  SESSION_STATE_READY,
  SESSION_STATE_CLOSED,
  SESSION_STATE_N_STATES,
} stream_session_state_t;

typedef CLIB_PACKED (struct
		     {
		     svm_fifo_t * fifo;
		     u8 event_type;
		     /* $$$$ for event logging */
		     u16 event_id;
		     u32 enqueue_length;
		     }) session_fifo_event_t;

typedef struct _stream_session_t
{
  /** fifo pointers. Once allocated, these do not move */
  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;

  /** Type */
  u8 session_type;

  /** State */
  u8 session_state;

  u8 thread_index;

  /** used during unbind processing */
  u8 is_deleted;

  /** To avoid n**2 "one event per frame" check */
  u8 enqueue_epoch;

  /** Session index in per_thread pool */
  u32 session_index;

  /** Transport specific */
  u32 connection_index;

  /** Application specific */
  u32 pid;

  /** stream server pool index */
  u32 app_index;

  /** svm segment index */
  u32 server_segment_index;
} stream_session_t;

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

/* Forward definition */
typedef struct _session_manager_main session_manager_main_t;

typedef int
  (session_fifo_rx_fn) (vlib_main_t * vm, vlib_node_runtime_t * node,
			session_manager_main_t * smm,
			session_fifo_event_t * e0, stream_session_t * s0,
			u32 thread_index, int *n_tx_pkts);

extern session_fifo_rx_fn session_tx_fifo_peek_and_snd;
extern session_fifo_rx_fn session_tx_fifo_dequeue_and_snd;

struct _session_manager_main
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
  stream_session_t *listen_sessions[SESSION_N_TYPES];

  /** Sparse vector to map dst port to stream server  */
  u16 *stream_server_by_dst_port[SESSION_N_TYPES];

  /** per-worker enqueue epoch counters */
  u8 *current_enqueue_epoch;

  /** Per-worker thread vector of sessions to enqueue */
  u32 **session_indices_to_enqueue_by_thread;

  /** per-worker tx buffer free lists */
  u32 **tx_buffers;

  /** Per worker-thread vector of partially read events */
  session_fifo_event_t **evts_partially_read;

  /** per-worker active event vectors */
  session_fifo_event_t **fifo_events;

  /** vpp fifo event queue */
  unix_shared_memory_queue_t **vpp_event_queues;

  /** Unique segment name counter */
  u32 unique_segment_name_counter;

  /* Connection manager used by incoming connects */
  u32 connect_manager_index[SESSION_N_TYPES];

  session_manager_t *session_managers;

  /** Per transport rx function that can either dequeue or peek */
  session_fifo_rx_fn *session_tx_fns[SESSION_N_TYPES];

  u8 is_enabled;

  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
};

extern session_manager_main_t session_manager_main;
extern vlib_node_registration_t session_queue_node;

/*
 * Session manager function
 */
always_inline session_manager_main_t *
vnet_get_session_manager_main ()
{
  return &session_manager_main;
}

always_inline session_manager_t *
session_manager_get (u32 index)
{
  return pool_elt_at_index (session_manager_main.session_managers, index);
}

always_inline unix_shared_memory_queue_t *
session_manager_get_vpp_event_queue (u32 thread_index)
{
  return session_manager_main.vpp_event_queues[thread_index];
}

always_inline session_manager_t *
connects_session_manager_get (session_manager_main_t * smm,
			      session_type_t session_type)
{
  return pool_elt_at_index (smm->session_managers,
			    smm->connect_manager_index[session_type]);
}

void session_manager_get_segment_info (u32 index, u8 ** name, u32 * size);
int session_manager_flush_enqueue_events (u32 thread_index);
int
session_manager_add_first_segment (session_manager_main_t * smm,
				   session_manager_t * sm, u32 segment_size,
				   u8 ** segment_name);
void
session_manager_del (session_manager_main_t * smm, session_manager_t * sm);
void
connects_session_manager_init (session_manager_main_t * smm, u8 session_type);

/*
 * Stream session functions
 */

stream_session_t *stream_session_lookup_listener4 (ip4_address_t * lcl,
						   u16 lcl_port, u8 proto);
stream_session_t *stream_session_lookup4 (ip4_address_t * lcl,
					  ip4_address_t * rmt, u16 lcl_port,
					  u16 rmt_port, u8 proto,
					  u32 thread_index);
stream_session_t *stream_session_lookup_listener6 (ip6_address_t * lcl,
						   u16 lcl_port, u8 proto);
stream_session_t *stream_session_lookup6 (ip6_address_t * lcl,
					  ip6_address_t * rmt, u16 lcl_port,
					  u16 rmt_port, u8, u32 thread_index);
transport_connection_t
  * stream_session_lookup_transport4 (ip4_address_t * lcl,
				      ip4_address_t * rmt, u16 lcl_port,
				      u16 rmt_port, u8 proto,
				      u32 thread_index);
transport_connection_t
  * stream_session_lookup_transport6 (ip6_address_t * lcl,
				      ip6_address_t * rmt, u16 lcl_port,
				      u16 rmt_port, u8 proto,
				      u32 thread_index);
stream_session_t *stream_session_lookup_listener (ip46_address_t * lcl,
						  u16 lcl_port, u8 proto);

always_inline stream_session_t *
stream_session_get_tsi (u64 ti_and_si, u32 thread_index)
{
  ASSERT ((u32) (ti_and_si >> 32) == thread_index);
  return pool_elt_at_index (session_manager_main.sessions[thread_index],
			    ti_and_si & 0xFFFFFFFFULL);
}

always_inline stream_session_t *
stream_session_get (u64 si, u32 thread_index)
{
  return pool_elt_at_index (session_manager_main.sessions[thread_index], si);
}

always_inline stream_session_t *
stream_session_get_if_valid (u64 si, u32 thread_index)
{
  if (thread_index >= vec_len (session_manager_main.sessions))
    return 0;

  if (pool_is_free_index (session_manager_main.sessions[thread_index], si))
    return 0;

  return pool_elt_at_index (session_manager_main.sessions[thread_index], si);
}

always_inline stream_session_t *
stream_session_listener_get (u8 sst, u64 si)
{
  return pool_elt_at_index (session_manager_main.listen_sessions[sst], si);
}

always_inline u32
stream_session_get_index (stream_session_t * s)
{
  if (s->session_state == SESSION_STATE_LISTENING)
    return s - session_manager_main.listen_sessions[s->session_type];

  return s - session_manager_main.sessions[s->thread_index];
}

always_inline u32
stream_session_max_enqueue (transport_connection_t * tc)
{
  stream_session_t *s = stream_session_get (tc->s_index, tc->thread_index);
  return svm_fifo_max_enqueue (s->server_rx_fifo);
}

always_inline u32
stream_session_fifo_size (transport_connection_t * tc)
{
  stream_session_t *s = stream_session_get (tc->s_index, tc->thread_index);
  return s->server_rx_fifo->nitems;
}


int
stream_session_enqueue_data (transport_connection_t * tc, u8 * data, u16 len,
			     u8 queue_event);
u32
stream_session_peek_bytes (transport_connection_t * tc, u8 * buffer,
			   u32 offset, u32 max_bytes);
u32 stream_session_dequeue_drop (transport_connection_t * tc, u32 max_bytes);

void
stream_session_connect_notify (transport_connection_t * tc, u8 sst,
			       u8 is_fail);

void stream_session_accept_notify (transport_connection_t * tc);
void stream_session_disconnect_notify (transport_connection_t * tc);
void stream_session_delete_notify (transport_connection_t * tc);
void stream_session_reset_notify (transport_connection_t * tc);
int
stream_session_accept (transport_connection_t * tc, u32 listener_index,
		       u8 sst, u8 notify);
int stream_session_open (u8 sst, ip46_address_t * addr,
			 u16 port_host_byte_order, u32 api_client_index);
void stream_session_disconnect (stream_session_t * s);
void stream_session_cleanup (stream_session_t * s);
int
stream_session_start_listen (u32 server_index, ip46_address_t * ip, u16 port);
void stream_session_stop_listen (u32 server_index);

u8 *format_stream_session (u8 * s, va_list * args);

void session_register_transport (u8 type, const transport_proto_vft_t * vft);
transport_proto_vft_t *session_get_transport_vft (u8 type);

clib_error_t *vnet_session_enable_disable (vlib_main_t * vm, u8 is_en);

#endif /* __included_session_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
