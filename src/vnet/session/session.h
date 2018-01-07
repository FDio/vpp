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
#include <vnet/session/session_debug.h>
#include <vnet/session/segment_manager.h>
#include <svm/queue.h>

#define HALF_OPEN_LOOKUP_INVALID_VALUE ((u64)~0)
#define INVALID_INDEX ((u32)~0)
#define SESSION_PROXY_LISTENER_INDEX ((u32)~0 - 1)

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
  u8 postponed;
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

  /** Per worker-thread count of threads peeking into the session pool */
  u32 *session_peekers;

  /** Per worker-thread rw peekers locks */
  clib_spinlock_t *peekers_readers_locks;
  clib_spinlock_t *peekers_write_locks;

  /** Pool of listen sessions. Same type as stream sessions to ease lookups */
  stream_session_t **listen_sessions;

  /** Per-proto, per-worker enqueue epoch counters */
  u32 *current_enqueue_epoch[TRANSPORT_N_PROTO];

  /** Per-proto, per-worker thread vector of sessions to enqueue */
  u32 **session_to_enqueue[TRANSPORT_N_PROTO];

  /** per-worker tx buffer free lists */
  u32 **tx_buffers;

  /** Per worker-thread vector of partially read events */
  session_fifo_event_t **free_event_vector;

  /** per-worker active event vectors */
  session_fifo_event_t **pending_event_vector;

  /** per-worker postponed disconnects */
  session_fifo_event_t **pending_disconnects;

  /** vpp fifo event queue */
  svm_queue_t **vpp_event_queues;

  /** Unique segment name counter */
  u32 unique_segment_name_counter;

  /** Per transport rx function that can either dequeue or peek */
  session_fifo_rx_fn **session_tx_fns;

  /** Per session type output nodes. Could optimize to group nodes by
   * fib but lookup would then require session type parsing in session node.
   * Trade memory for speed, for now */
  u32 *session_type_to_next;

  /** Session manager is enabled */
  u8 is_enabled;

  /** vpp fifo event queue configured length */
  u32 configured_event_queue_length;

  /*
   * Config parameters
   */

  /** session table size parameters */
  u32 configured_v4_session_table_buckets;
  u32 configured_v4_session_table_memory;
  u32 configured_v4_halfopen_table_buckets;
  u32 configured_v4_halfopen_table_memory;
  u32 configured_v6_session_table_buckets;
  u32 configured_v6_session_table_memory;
  u32 configured_v6_halfopen_table_buckets;
  u32 configured_v6_halfopen_table_memory;

  /** Transport table (preallocation) size parameters */
  u32 local_endpoints_table_memory;
  u32 local_endpoints_table_buckets;

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

stream_session_t *session_alloc (u32 thread_index);

always_inline stream_session_t *
session_get (u32 si, u32 thread_index)
{
  ASSERT (stream_session_is_valid (si, thread_index));
  return pool_elt_at_index (session_manager_main.sessions[thread_index], si);
}

always_inline stream_session_t *
session_get_if_valid (u64 si, u32 thread_index)
{
  if (thread_index >= vec_len (session_manager_main.sessions))
    return 0;

  if (pool_is_free_index (session_manager_main.sessions[thread_index], si))
    return 0;

  ASSERT (stream_session_is_valid (si, thread_index));
  return pool_elt_at_index (session_manager_main.sessions[thread_index], si);
}

always_inline u64
session_handle (stream_session_t * s)
{
  return ((u64) s->thread_index << 32) | (u64) s->session_index;
}

always_inline u32
session_index_from_handle (u64 handle)
{
  return handle & 0xFFFFFFFF;
}

always_inline u32
session_thread_from_handle (u64 handle)
{
  return handle >> 32;
}

always_inline void
session_parse_handle (u64 handle, u32 * index, u32 * thread_index)
{
  *index = session_index_from_handle (handle);
  *thread_index = session_thread_from_handle (handle);
}

always_inline stream_session_t *
session_get_from_handle (u64 handle)
{
  session_manager_main_t *smm = &session_manager_main;
  return
    pool_elt_at_index (smm->sessions[session_thread_from_handle (handle)],
		       session_index_from_handle (handle));
}

always_inline transport_proto_t
session_get_transport_proto (stream_session_t * s)
{
  return (s->session_type >> 1);
}

always_inline session_type_t
session_type_from_proto_and_ip (transport_proto_t proto, u8 is_ip4)
{
  return (proto << 1 | is_ip4);
}

/**
 * Acquires a lock that blocks a session pool from expanding.
 *
 * This is typically used for safely peeking into other threads'
 * pools in order to clone elements. Lock should be dropped as soon
 * as possible by calling @ref session_pool_remove_peeker.
 *
 * NOTE: Avoid using pool_elt_at_index while the lock is held because
 * it may lead to free elt bitmap expansion/contraction!
 */
always_inline void
session_pool_add_peeker (u32 thread_index)
{
  session_manager_main_t *smm = &session_manager_main;
  if (thread_index == vlib_get_thread_index ())
    return;
  clib_spinlock_lock_if_init (&smm->peekers_readers_locks[thread_index]);
  smm->session_peekers[thread_index] += 1;
  if (smm->session_peekers[thread_index] == 1)
    clib_spinlock_lock_if_init (&smm->peekers_write_locks[thread_index]);
  clib_spinlock_unlock_if_init (&smm->peekers_readers_locks[thread_index]);
}

always_inline void
session_pool_remove_peeker (u32 thread_index)
{
  session_manager_main_t *smm = &session_manager_main;
  if (thread_index == vlib_get_thread_index ())
    return;
  ASSERT (session_manager_main.session_peekers[thread_index] > 0);
  clib_spinlock_lock_if_init (&smm->peekers_readers_locks[thread_index]);
  smm->session_peekers[thread_index] -= 1;
  if (smm->session_peekers[thread_index] == 0)
    clib_spinlock_unlock_if_init (&smm->peekers_write_locks[thread_index]);
  clib_spinlock_unlock_if_init (&smm->peekers_readers_locks[thread_index]);
}

/**
 * Get session from handle and 'lock' pool resize if not in same thread
 *
 * Caller should drop the peek 'lock' as soon as possible.
 */
always_inline stream_session_t *
session_get_from_handle_safe (u64 handle)
{
  session_manager_main_t *smm = &session_manager_main;
  u32 thread_index = session_thread_from_handle (handle);
  if (thread_index == vlib_get_thread_index ())
    {
      return pool_elt_at_index (smm->sessions[thread_index],
				session_index_from_handle (handle));
    }
  else
    {
      session_pool_add_peeker (thread_index);
      /* Don't use pool_elt_at index. See @ref session_pool_add_peeker */
      return smm->sessions[thread_index] + session_index_from_handle (handle);
    }
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
  stream_session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_max_enqueue (s->server_rx_fifo);
}

always_inline u32
stream_session_rx_fifo_size (transport_connection_t * tc)
{
  stream_session_t *s = session_get (tc->s_index, tc->thread_index);
  return s->server_rx_fifo->nitems;
}

always_inline u32
session_get_index (stream_session_t * s)
{
  return (s - session_manager_main.sessions[s->thread_index]);
}

always_inline stream_session_t *
session_clone_safe (u32 session_index, u32 thread_index)
{
  stream_session_t *old_s, *new_s;
  u32 current_thread_index = vlib_get_thread_index ();

  /* If during the memcpy pool is reallocated AND the memory allocator
   * decides to give the old chunk of memory to somebody in a hurry to
   * scribble something on it, we have a problem. So add this thread as
   * a session pool peeker.
   */
  session_pool_add_peeker (thread_index);
  new_s = session_alloc (current_thread_index);
  old_s = session_manager_main.sessions[thread_index] + session_index;
  clib_memcpy (new_s, old_s, sizeof (*new_s));
  session_pool_remove_peeker (thread_index);
  new_s->thread_index = current_thread_index;
  new_s->session_index = session_get_index (new_s);
  return new_s;
}

transport_connection_t *session_get_transport (stream_session_t * s);

u32 stream_session_tx_fifo_max_dequeue (transport_connection_t * tc);

stream_session_t *session_alloc (u32 thread_index);
int
session_enqueue_stream_connection (transport_connection_t * tc,
				   vlib_buffer_t * b, u32 offset,
				   u8 queue_event, u8 is_in_order);
int session_enqueue_dgram_connection (stream_session_t * s, vlib_buffer_t * b,
				      u8 proto, u8 queue_event);
int stream_session_peek_bytes (transport_connection_t * tc, u8 * buffer,
			       u32 offset, u32 max_bytes);
u32 stream_session_dequeue_drop (transport_connection_t * tc, u32 max_bytes);

int session_stream_connect_notify (transport_connection_t * tc, u8 is_fail);
int session_dgram_connect_notify (transport_connection_t * tc,
				  u32 old_thread_index,
				  stream_session_t ** new_session);
void stream_session_init_fifos_pointers (transport_connection_t * tc,
					 u32 rx_pointer, u32 tx_pointer);

void stream_session_accept_notify (transport_connection_t * tc);
void stream_session_disconnect_notify (transport_connection_t * tc);
void stream_session_delete_notify (transport_connection_t * tc);
void stream_session_reset_notify (transport_connection_t * tc);
int stream_session_accept (transport_connection_t * tc, u32 listener_index,
			   u8 notify);
int session_open (u32 app_index, session_endpoint_t * tep, u32 opaque);
int stream_session_listen (stream_session_t * s, session_endpoint_t * tep);
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

void session_register_transport (transport_proto_t transport_proto,
				 const transport_proto_vft_t * vft, u8 is_ip4,
				 u32 output_node);

clib_error_t *vnet_session_enable_disable (vlib_main_t * vm, u8 is_en);

always_inline svm_queue_t *
session_manager_get_vpp_event_queue (u32 thread_index)
{
  return session_manager_main.vpp_event_queues[thread_index];
}

int session_manager_flush_enqueue_events (u8 proto, u32 thread_index);

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

transport_connection_t *listen_session_get_transport (stream_session_t * s);

int
listen_session_get_local_session_endpoint (stream_session_t * listener,
					   session_endpoint_t * sep);

always_inline stream_session_t *
session_manager_get_listener (u8 session_type, u32 index)
{
  return
    pool_elt_at_index (session_manager_main.listen_sessions[session_type],
		       index);
}

/**
 * Set peek or dequeue function for given session type
 *
 * Reliable transport protocols will probably want to use a peek function
 */
always_inline void
session_manager_set_transport_rx_fn (session_type_t type, u8 is_peek)
{
  session_manager_main.session_tx_fns[type] = (is_peek) ?
    session_tx_fifo_peek_and_snd : session_tx_fifo_dequeue_and_snd;
}

always_inline u8
session_manager_is_enabled ()
{
  return session_manager_main.is_enabled == 1;
}

#define session_cli_return_if_not_enabled()				\
do {									\
    if (!session_manager_main.is_enabled)				\
      return clib_error_return(0, "session layer is not enabled");	\
} while (0)

void session_node_enable_disable (u8 is_en);

#endif /* __included_session_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
