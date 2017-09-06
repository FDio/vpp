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

#include <vnet/session/stream_session.h>
#include <vnet/session/session_lookup.h>
#include <vnet/session/transport_interface.h>
#include <vlibmemory/unix_shared_memory_queue.h>
#include <vnet/session/session_debug.h>
#include <vnet/session/segment_manager.h>

#define HALF_OPEN_LOOKUP_INVALID_VALUE ((u64)~0)
#define INVALID_INDEX ((u32)~0)

/* TODO decide how much since we have pre-data as well */
#define MAX_HDRS_LEN    100	/* Max number of bytes for headers */

typedef enum
{
  FIFO_EVENT_APP_RX,
  FIFO_EVENT_APP_TX,
  FIFO_EVENT_TIMEOUT,
  FIFO_EVENT_DISCONNECT,
  FIFO_EVENT_BUILTIN_RX,
  FIFO_EVENT_RPC,
} fifo_event_type_t;

static inline const char *
fifo_event_type_str (fifo_event_type_t et)
{
  switch (et)
    {
    case FIFO_EVENT_APP_RX:
      return "FIFO_EVENT_APP_RX";
    case FIFO_EVENT_APP_TX:
      return "FIFO_EVENT_APP_TX";
    case FIFO_EVENT_TIMEOUT:
      return "FIFO_EVENT_TIMEOUT";
    case FIFO_EVENT_DISCONNECT:
      return "FIFO_EVENT_DISCONNECT";
    case FIFO_EVENT_BUILTIN_RX:
      return "FIFO_EVENT_BUILTIN_RX";
    case FIFO_EVENT_RPC:
      return "FIFO_EVENT_RPC";
    default:
      return "UNKNOWN FIFO EVENT";
    }
}

#define foreach_session_input_error                                    	\
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

typedef struct
{
  void *fp;
  void *arg;
} rpc_args_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  union
    {
      svm_fifo_t * fifo;
      u64 session_handle;
      rpc_args_t rpc_args;
    };
  u8 event_type;
  u16 event_id;
}) session_fifo_event_t;
/* *INDENT-ON* */

/* Forward definition */
typedef struct _session_manager_main session_manager_main_t;

typedef int
  (session_fifo_rx_fn) (vlib_main_t * vm, vlib_node_runtime_t * node,
			session_manager_main_t * smm,
			session_fifo_event_t * e0, stream_session_t * s0,
			u32 thread_index, int *n_tx_pkts);

extern session_fifo_rx_fn session_tx_fifo_peek_and_snd;
extern session_fifo_rx_fn session_tx_fifo_dequeue_and_snd;

u8 session_node_lookup_fifo_event (svm_fifo_t * f, session_fifo_event_t * e);

struct _session_manager_main
{
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
  session_fifo_event_t **free_event_vector;

  /** per-worker active event vectors */
  session_fifo_event_t **pending_event_vector;

  /** vpp fifo event queue */
  unix_shared_memory_queue_t **vpp_event_queues;

  /** vpp fifo event queue configured length */
  u32 configured_event_queue_length;

  /** session table size parameters */
  u32 configured_v4_session_table_buckets;
  u32 configured_v4_session_table_memory;
  u32 configured_v4_halfopen_table_buckets;
  u32 configured_v4_halfopen_table_memory;
  u32 configured_v6_session_table_buckets;
  u32 configured_v6_session_table_memory;
  u32 configured_v6_halfopen_table_buckets;
  u32 configured_v6_halfopen_table_memory;

  /** Unique segment name counter */
  u32 unique_segment_name_counter;

  /** Per transport rx function that can either dequeue or peek */
  session_fifo_rx_fn *session_tx_fns[SESSION_N_TYPES];

  /** Session manager is enabled */
  u8 is_enabled;

  /** Preallocate session config parameter */
  u32 preallocated_sessions;

#if SESSION_DBG
  /**
   * last event poll time by thread
   * Debug only. Will cause false cache-line sharing as-is
   */
  f64 *last_event_poll_by_thread;
#endif

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

always_inline u8
stream_session_is_valid (u32 si, u8 thread_index)
{
  stream_session_t *s;
  s = pool_elt_at_index (session_manager_main.sessions[thread_index], si);
  if (s->thread_index != thread_index || s->session_index != si
      /* || s->server_rx_fifo->master_session_index != si
         || s->server_tx_fifo->master_session_index != si
         || s->server_rx_fifo->master_thread_index != thread_index
         || s->server_tx_fifo->master_thread_index != thread_index */ )
    return 0;
  return 1;
}

always_inline stream_session_t *
stream_session_get (u32 si, u32 thread_index)
{
  ASSERT (stream_session_is_valid (si, thread_index));
  return pool_elt_at_index (session_manager_main.sessions[thread_index], si);
}

always_inline stream_session_t *
stream_session_get_if_valid (u64 si, u32 thread_index)
{
  if (thread_index >= vec_len (session_manager_main.sessions))
    return 0;

  if (pool_is_free_index (session_manager_main.sessions[thread_index], si))
    return 0;

  ASSERT (stream_session_is_valid (si, thread_index));
  return pool_elt_at_index (session_manager_main.sessions[thread_index], si);
}

always_inline u64
stream_session_handle (stream_session_t * s)
{
  return ((u64) s->thread_index << 32) | (u64) s->session_index;
}

always_inline u32
stream_session_index_from_handle (u64 handle)
{
  return handle & 0xFFFFFFFF;
}

always_inline u32
stream_session_thread_from_handle (u64 handle)
{
  return handle >> 32;
}

always_inline void
stream_session_parse_handle (u64 handle, u32 * index, u32 * thread_index)
{
  *index = stream_session_index_from_handle (handle);
  *thread_index = stream_session_thread_from_handle (handle);
}

always_inline stream_session_t *
stream_session_get_from_handle (u64 handle)
{
  session_manager_main_t *smm = &session_manager_main;
  return pool_elt_at_index (smm->sessions[stream_session_thread_from_handle
					  (handle)],
			    stream_session_index_from_handle (handle));
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
stream_session_max_rx_enqueue (transport_connection_t * tc)
{
  stream_session_t *s = stream_session_get (tc->s_index, tc->thread_index);
  return svm_fifo_max_enqueue (s->server_rx_fifo);
}

always_inline u32
stream_session_rx_fifo_size (transport_connection_t * tc)
{
  stream_session_t *s = stream_session_get (tc->s_index, tc->thread_index);
  return s->server_rx_fifo->nitems;
}

u32 stream_session_tx_fifo_max_dequeue (transport_connection_t * tc);

int
stream_session_enqueue_data (transport_connection_t * tc, vlib_buffer_t * b,
			     u32 offset, u8 queue_event, u8 is_in_order);
int
stream_session_peek_bytes (transport_connection_t * tc, u8 * buffer,
			   u32 offset, u32 max_bytes);
u32 stream_session_dequeue_drop (transport_connection_t * tc, u32 max_bytes);

int stream_session_connect_notify (transport_connection_t * tc, u8 is_fail);
void stream_session_init_fifos_pointers (transport_connection_t * tc,
					 u32 rx_pointer, u32 tx_pointer);

void stream_session_accept_notify (transport_connection_t * tc);
void stream_session_disconnect_notify (transport_connection_t * tc);
void stream_session_delete_notify (transport_connection_t * tc);
void stream_session_reset_notify (transport_connection_t * tc);
int
stream_session_accept (transport_connection_t * tc, u32 listener_index,
		       u8 sst, u8 notify);
int
stream_session_open (u32 app_index, session_type_t st,
		     transport_endpoint_t * tep,
		     transport_connection_t ** tc);
int stream_session_listen (stream_session_t * s, transport_endpoint_t * tep);
int stream_session_stop_listen (stream_session_t * s);
void stream_session_disconnect (stream_session_t * s);
void stream_session_cleanup (stream_session_t * s);
void session_send_session_evt_to_thread (u64 session_handle,
					 fifo_event_type_t evt_type,
					 u32 thread_index);

u8 *format_stream_session (u8 * s, va_list * args);
uword unformat_stream_session (unformat_input_t * input, va_list * args);
uword unformat_transport_connection (unformat_input_t * input,
				     va_list * args);

int
send_session_connected_callback (u32 app_index, u32 api_context,
				 stream_session_t * s, u8 is_fail);


clib_error_t *vnet_session_enable_disable (vlib_main_t * vm, u8 is_en);

always_inline unix_shared_memory_queue_t *
session_manager_get_vpp_event_queue (u32 thread_index)
{
  return session_manager_main.vpp_event_queues[thread_index];
}

int session_manager_flush_enqueue_events (u32 thread_index);

always_inline u64
listen_session_get_handle (stream_session_t * s)
{
  ASSERT (s->session_state == SESSION_STATE_LISTENING);
  return ((u64) s->session_type << 32) | s->session_index;
}

always_inline stream_session_t *
listen_session_get_from_handle (u64 handle)
{
  session_manager_main_t *smm = &session_manager_main;
  stream_session_t *s;
  u32 type, index;
  type = handle >> 32;
  index = handle & 0xFFFFFFFF;

  if (pool_is_free_index (smm->listen_sessions[type], index))
    return 0;

  s = pool_elt_at_index (smm->listen_sessions[type], index);
  ASSERT (s->session_state == SESSION_STATE_LISTENING);
  return s;
}

always_inline stream_session_t *
listen_session_new (session_type_t type)
{
  stream_session_t *s;
  pool_get_aligned (session_manager_main.listen_sessions[type], s,
		    CLIB_CACHE_LINE_BYTES);
  memset (s, 0, sizeof (*s));

  s->session_type = type;
  s->session_state = SESSION_STATE_LISTENING;
  s->session_index = s - session_manager_main.listen_sessions[type];

  return s;
}

always_inline stream_session_t *
listen_session_get (session_type_t type, u32 index)
{
  return pool_elt_at_index (session_manager_main.listen_sessions[type],
			    index);
}

always_inline void
listen_session_del (stream_session_t * s)
{
  pool_put (session_manager_main.listen_sessions[s->session_type], s);
}

always_inline stream_session_t *
session_manager_get_listener (u8 type, u32 index)
{
  return pool_elt_at_index (session_manager_main.listen_sessions[type],
			    index);
}

always_inline void
session_manager_set_transport_rx_fn (u8 type, u8 is_peek)
{
  /* If an offset function is provided, then peek instead of dequeue */
  session_manager_main.session_tx_fns[type] = (is_peek) ?
    session_tx_fifo_peek_and_snd : session_tx_fifo_dequeue_and_snd;
}

session_type_t
session_type_from_proto_and_ip (transport_proto_t proto, u8 is_ip4);

always_inline u8
session_manager_is_enabled ()
{
  return session_manager_main.is_enabled == 1;
}

#endif /* __included_session_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
