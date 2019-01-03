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
#define SESSION_PROXY_LISTENER_INDEX ((u8)~0 - 1)
#define SESSION_LOCAL_HANDLE_PREFIX 0x7FFFFFFF

/* TODO decide how much since we have pre-data as well */
#define MAX_HDRS_LEN    100	/* Max number of bytes for headers */

typedef enum
{
  FIFO_EVENT_APP_RX,
  SESSION_IO_EVT_CT_RX,
  FIFO_EVENT_APP_TX,
  SESSION_IO_EVT_CT_TX,
  SESSION_IO_EVT_TX_FLUSH,
  FIFO_EVENT_DISCONNECT,
  FIFO_EVENT_BUILTIN_RX,
  FIFO_EVENT_BUILTIN_TX,
  FIFO_EVENT_RPC,
  SESSION_CTRL_EVT_BOUND,
  SESSION_CTRL_EVT_ACCEPTED,
  SESSION_CTRL_EVT_ACCEPTED_REPLY,
  SESSION_CTRL_EVT_CONNECTED,
  SESSION_CTRL_EVT_CONNECTED_REPLY,
  SESSION_CTRL_EVT_DISCONNECTED,
  SESSION_CTRL_EVT_DISCONNECTED_REPLY,
  SESSION_CTRL_EVT_RESET,
  SESSION_CTRL_EVT_RESET_REPLY,
  SESSION_CTRL_EVT_WORKER_UPDATE,
} session_evt_type_t;

static inline const char *
fifo_event_type_str (session_evt_type_t et)
{
  switch (et)
    {
    case FIFO_EVENT_APP_RX:
      return "FIFO_EVENT_APP_RX";
    case FIFO_EVENT_APP_TX:
      return "FIFO_EVENT_APP_TX";
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

typedef enum
{
  SESSION_MQ_IO_EVT_RING,
  SESSION_MQ_CTRL_EVT_RING,
  SESSION_MQ_N_RINGS
} session_mq_rings_e;

#define foreach_session_input_error                                    	\
_(NO_SESSION, "No session drops")                                       \
_(NO_LISTENER, "No listener for dst port drops")                        \
_(ENQUEUED, "Packets pushed into rx fifo")                              \
_(NOT_READY, "Session not ready packets")                               \
_(FIFO_FULL, "Packets dropped for lack of rx fifo space")               \
_(EVENT_FIFO_FULL, "Events not sent for lack of event fifo space")      \
_(API_QUEUE_FULL, "Sessions not created for lack of API queue space")   \
_(NEW_SEG_NO_SPACE, "Created segment, couldn't allocate a fifo pair")   \
_(NO_SPACE, "Couldn't allocate a fifo pair")				\
_(SEG_CREATE, "Couldn't create a new segment")

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
} session_rpc_args_t;

typedef u64 session_handle_t;

/* *INDENT-OFF* */
typedef struct
{
  u8 event_type;
  u8 postponed;
  union
  {
    svm_fifo_t *fifo;
    session_handle_t session_handle;
    session_rpc_args_t rpc_args;
    struct
    {
      u8 data[0];
    };
  };
} __clib_packed session_event_t;
/* *INDENT-ON* */

#define SESSION_MSG_NULL { }

typedef struct session_dgram_pre_hdr_
{
  u32 data_length;
  u32 data_offset;
} session_dgram_pre_hdr_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct session_dgram_header_
{
  u32 data_length;
  u32 data_offset;
  ip46_address_t rmt_ip;
  ip46_address_t lcl_ip;
  u16 rmt_port;
  u16 lcl_port;
  u8 is_ip4;
}) session_dgram_hdr_t;
/* *INDENT-ON* */

#define SESSION_CONN_ID_LEN 37
#define SESSION_CONN_HDR_LEN 45

STATIC_ASSERT (sizeof (session_dgram_hdr_t) == (SESSION_CONN_ID_LEN + 8),
	       "session conn id wrong length");

typedef struct session_tx_context_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  stream_session_t *s;
  transport_proto_vft_t *transport_vft;
  transport_connection_t *tc;
  vlib_buffer_t *b;
  u32 max_dequeue;
  u32 snd_space;
  u32 left_to_snd;
  u32 tx_offset;
  u32 max_len_to_snd;
  u16 deq_per_first_buf;
  u16 deq_per_buf;
  u16 snd_mss;
  u16 n_segs_per_evt;
  u8 n_bufs_per_seg;
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  session_dgram_hdr_t hdr;
} session_tx_context_t;

/* Forward definition */
typedef struct _session_manager_main session_manager_main_t;

typedef int
  (session_fifo_rx_fn) (vlib_main_t * vm, vlib_node_runtime_t * node,
			session_event_t * e0, stream_session_t * s0,
			int *n_tx_pkts);

extern session_fifo_rx_fn session_tx_fifo_peek_and_snd;
extern session_fifo_rx_fn session_tx_fifo_dequeue_and_snd;
extern session_fifo_rx_fn session_tx_fifo_dequeue_internal;

u8 session_node_lookup_fifo_event (svm_fifo_t * f, session_event_t * e);

typedef struct session_manager_worker_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /** Worker session pool */
  stream_session_t *sessions;

  /** vpp event message queue for worker */
  svm_msg_q_t *vpp_event_queue;

  /** Our approximation of a "complete" dispatch loop period */
  f64 dispatch_period;

  /** vlib_time_now last time around the track */
  f64 last_vlib_time;

  /** Per-proto enqueue epoch counters */
  u64 current_enqueue_epoch[TRANSPORT_N_PROTO];

  /** Per-proto vector of sessions to enqueue */
  u32 *session_to_enqueue[TRANSPORT_N_PROTO];

  /** Context for session tx */
  session_tx_context_t ctx;

  /** Vector of tx buffer free lists */
  u32 *tx_buffers;

  /** Vector of partially read events */
  session_event_t *free_event_vector;

  /** Vector of active event vectors */
  session_event_t *pending_event_vector;

  /** Vector of postponed disconnects */
  session_event_t *pending_disconnects;

  /** Vector of postponed events */
  session_event_t *postponed_event_vector;

  /** Peekers rw lock */
  clib_rwlock_t peekers_rw_locks;

  u32 last_tx_packets;

} session_manager_worker_t;

struct _session_manager_main
{
  /** Worker contexts */
  session_manager_worker_t *wrk;

  /** Event queues memfd segment initialized only if so configured */
  ssvm_private_t evt_qs_segment;

  /** Unique segment name counter */
  u32 unique_segment_name_counter;

  /** Per transport rx function that can either dequeue or peek */
  session_fifo_rx_fn **session_tx_fns;

  /** Per session type output nodes. Could optimize to group nodes by
   * fib but lookup would then require session type parsing in session node.
   * Trade memory for speed, for now */
  u32 *session_type_to_next;

  /*
   * Config parameters
   */

  /** Session manager is enabled */
  u8 is_enabled;

  /** vpp fifo event queue configured length */
  u32 configured_event_queue_length;

  /** Session ssvm segment configs*/
  uword session_baseva;
  uword session_va_space_size;
  u32 evt_qs_segment_size;
  u8 evt_qs_use_memfd_seg;

  /** Session table size parameters */
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

#if SESSION_DEBUG
  /**
   * last event poll time by thread
   * Debug only. Will cause false cache-line sharing as-is
   */
  f64 *last_event_poll_by_thread;
#endif

};

extern session_manager_main_t session_manager_main;
extern vlib_node_registration_t session_queue_node;
extern vlib_node_registration_t session_queue_process_node;

#define SESSION_Q_PROCESS_FLUSH_FRAMES	1
#define SESSION_Q_PROCESS_STOP		2

/*
 * Session manager function
 */
always_inline session_manager_main_t *
vnet_get_session_manager_main ()
{
  return &session_manager_main;
}

always_inline session_manager_worker_t *
session_manager_get_worker (u32 thread_index)
{
  return &session_manager_main.wrk[thread_index];
}

always_inline u8
stream_session_is_valid (u32 si, u8 thread_index)
{
  stream_session_t *s;
  s = pool_elt_at_index (session_manager_main.wrk[thread_index].sessions, si);
  if (s->thread_index != thread_index || s->session_index != si
      /* || s->server_rx_fifo->master_session_index != si
         || s->server_tx_fifo->master_session_index != si
         || s->server_rx_fifo->master_thread_index != thread_index
         || s->server_tx_fifo->master_thread_index != thread_index */ )
    return 0;
  return 1;
}

stream_session_t *session_alloc (u32 thread_index);
int session_alloc_fifos (segment_manager_t * sm, stream_session_t * s);
void session_free (stream_session_t * s);
void session_free_w_fifos (stream_session_t * s);

always_inline stream_session_t *
session_get (u32 si, u32 thread_index)
{
  ASSERT (stream_session_is_valid (si, thread_index));
  return pool_elt_at_index (session_manager_main.wrk[thread_index].sessions,
			    si);
}

always_inline stream_session_t *
session_get_if_valid (u64 si, u32 thread_index)
{
  if (thread_index >= vec_len (session_manager_main.wrk))
    return 0;

  if (pool_is_free_index (session_manager_main.wrk[thread_index].sessions,
			  si))
    return 0;

  ASSERT (stream_session_is_valid (si, thread_index));
  return pool_elt_at_index (session_manager_main.wrk[thread_index].sessions,
			    si);
}

always_inline session_handle_t
session_handle (stream_session_t * s)
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

always_inline stream_session_t *
session_get_from_handle (session_handle_t handle)
{
  session_manager_main_t *smm = &session_manager_main;
  u32 session_index, thread_index;
  session_parse_handle (handle, &session_index, &thread_index);
  return pool_elt_at_index (smm->wrk[thread_index].sessions, session_index);
}

always_inline stream_session_t *
session_get_from_handle_if_valid (session_handle_t handle)
{
  u32 session_index, thread_index;
  session_parse_handle (handle, &session_index, &thread_index);
  return session_get_if_valid (session_index, thread_index);
}

always_inline u8
session_handle_is_local (session_handle_t handle)
{
  if ((handle >> 32) == SESSION_LOCAL_HANDLE_PREFIX)
    return 1;
  return 0;
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
session_get_transport_proto (stream_session_t * s)
{
  return (s->session_type >> 1);
}

always_inline fib_protocol_t
session_get_fib_proto (stream_session_t * s)
{
  u8 is_ip4 = s->session_type & 1;
  return (is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);
}

always_inline session_type_t
session_type_from_proto_and_ip (transport_proto_t proto, u8 is_ip4)
{
  return (proto << 1 | is_ip4);
}

always_inline u64
session_segment_handle (stream_session_t * s)
{
  svm_fifo_t *f = s->server_rx_fifo;
  return segment_manager_make_segment_handle (f->segment_manager,
					      f->segment_index);
}

always_inline u8
session_has_transport (stream_session_t * s)
{
  return (session_get_transport_proto (s) != TRANSPORT_PROTO_NONE);
}

transport_service_type_t session_transport_service_type (stream_session_t *);
transport_tx_fn_type_t session_transport_tx_fn_type (stream_session_t *);
u8 session_tx_is_dgram (stream_session_t * s);

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
  session_manager_worker_t *wrk = &session_manager_main.wrk[thread_index];
  if (thread_index == vlib_get_thread_index ())
    return;
  clib_rwlock_reader_lock (&wrk->peekers_rw_locks);
}

always_inline void
session_pool_remove_peeker (u32 thread_index)
{
  session_manager_worker_t *wrk = &session_manager_main.wrk[thread_index];
  if (thread_index == vlib_get_thread_index ())
    return;
  clib_rwlock_reader_unlock (&wrk->peekers_rw_locks);
}

/**
 * Get session from handle and 'lock' pool resize if not in same thread
 *
 * Caller should drop the peek 'lock' as soon as possible.
 */
always_inline stream_session_t *
session_get_from_handle_safe (u64 handle)
{
  u32 thread_index = session_thread_from_handle (handle);
  session_manager_worker_t *wrk = &session_manager_main.wrk[thread_index];

  if (thread_index == vlib_get_thread_index ())
    {
      return pool_elt_at_index (wrk->sessions,
				session_index_from_handle (handle));
    }
  else
    {
      session_pool_add_peeker (thread_index);
      /* Don't use pool_elt_at index. See @ref session_pool_add_peeker */
      return wrk->sessions + session_index_from_handle (handle);
    }
}

always_inline u32
transport_max_rx_enqueue (transport_connection_t * tc)
{
  stream_session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_max_enqueue (s->server_rx_fifo);
}

always_inline u32
transport_max_tx_dequeue (transport_connection_t * tc)
{
  stream_session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_max_dequeue (s->server_tx_fifo);
}

always_inline u32
transport_rx_fifo_size (transport_connection_t * tc)
{
  stream_session_t *s = session_get (tc->s_index, tc->thread_index);
  return s->server_rx_fifo->nitems;
}

always_inline u32
transport_tx_fifo_size (transport_connection_t * tc)
{
  stream_session_t *s = session_get (tc->s_index, tc->thread_index);
  return s->server_tx_fifo->nitems;
}

always_inline u8
transport_rx_fifo_has_ooo_data (transport_connection_t * tc)
{
  stream_session_t *s = session_get (tc->c_index, tc->thread_index);
  return svm_fifo_has_ooo_data (s->server_rx_fifo);
}

always_inline f64
transport_dispatch_period (u32 thread_index)
{
  return session_manager_main.wrk[thread_index].dispatch_period;
}

always_inline f64
transport_time_now (u32 thread_index)
{
  return session_manager_main.wrk[thread_index].last_vlib_time;
}

always_inline u32
session_get_index (stream_session_t * s)
{
  return (s - session_manager_main.wrk[s->thread_index].sessions);
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
  old_s = session_manager_main.wrk[thread_index].sessions + session_index;
  clib_memcpy_fast (new_s, old_s, sizeof (*new_s));
  session_pool_remove_peeker (thread_index);
  new_s->thread_index = current_thread_index;
  new_s->session_index = session_get_index (new_s);
  return new_s;
}

transport_connection_t *session_get_transport (stream_session_t * s);

u32 session_tx_fifo_max_dequeue (transport_connection_t * tc);

int
session_enqueue_stream_connection (transport_connection_t * tc,
				   vlib_buffer_t * b, u32 offset,
				   u8 queue_event, u8 is_in_order);
int session_enqueue_dgram_connection (stream_session_t * s,
				      session_dgram_hdr_t * hdr,
				      vlib_buffer_t * b, u8 proto,
				      u8 queue_event);
int stream_session_peek_bytes (transport_connection_t * tc, u8 * buffer,
			       u32 offset, u32 max_bytes);
u32 stream_session_dequeue_drop (transport_connection_t * tc, u32 max_bytes);

int session_stream_connect_notify (transport_connection_t * tc, u8 is_fail);
int session_dgram_connect_notify (transport_connection_t * tc,
				  u32 old_thread_index,
				  stream_session_t ** new_session);
int session_dequeue_notify (stream_session_t * s);
void stream_session_init_fifos_pointers (transport_connection_t * tc,
					 u32 rx_pointer, u32 tx_pointer);

int stream_session_accept_notify (transport_connection_t * tc);
void session_transport_closing_notify (transport_connection_t * tc);
void session_transport_delete_notify (transport_connection_t * tc);
void session_transport_closed_notify (transport_connection_t * tc);
void session_transport_reset_notify (transport_connection_t * tc);
int stream_session_accept (transport_connection_t * tc, u32 listener_index,
			   u8 notify);
int session_open (u32 app_index, session_endpoint_t * tep, u32 opaque);
int session_listen (stream_session_t * s, session_endpoint_cfg_t * sep);
int session_stop_listen (stream_session_t * s);
void session_close (stream_session_t * s);
void session_transport_close (stream_session_t * s);
void session_transport_cleanup (stream_session_t * s);
int session_send_io_evt_to_thread (svm_fifo_t * f,
				   session_evt_type_t evt_type);
int session_send_io_evt_to_thread_custom (void *data, u32 thread_index,
					  session_evt_type_t evt_type);
void session_send_rpc_evt_to_thread (u32 thread_index, void *fp,
				     void *rpc_args);

ssvm_private_t *session_manager_get_evt_q_segment (void);

u8 *format_stream_session (u8 * s, va_list * args);
uword unformat_stream_session (unformat_input_t * input, va_list * args);
uword unformat_transport_connection (unformat_input_t * input,
				     va_list * args);

void session_register_transport (transport_proto_t transport_proto,
				 const transport_proto_vft_t * vft, u8 is_ip4,
				 u32 output_node);

always_inline void
transport_add_tx_event (transport_connection_t * tc)
{
  stream_session_t *s = session_get (tc->s_index, tc->thread_index);
  if (svm_fifo_has_event (s->server_tx_fifo))
    return;
  session_send_io_evt_to_thread (s->server_tx_fifo, FIFO_EVENT_APP_TX);
}

clib_error_t *vnet_session_enable_disable (vlib_main_t * vm, u8 is_en);

always_inline svm_msg_q_t *
session_manager_get_vpp_event_queue (u32 thread_index)
{
  return session_manager_main.wrk[thread_index].vpp_event_queue;
}

int session_manager_flush_enqueue_events (u8 proto, u32 thread_index);
int session_manager_flush_all_enqueue_events (u8 transport_proto);

always_inline u64
listen_session_get_handle (stream_session_t * s)
{
  ASSERT (s->session_state == SESSION_STATE_LISTENING);
  return session_handle (s);
}

always_inline stream_session_t *
listen_session_get_from_handle (session_handle_t handle)
{
  return session_get_from_handle (handle);
}

always_inline void
listen_session_parse_handle (session_handle_t handle, u32 * index,
			     u32 * thread_index)
{
  session_parse_handle (handle, index, thread_index);
}

always_inline stream_session_t *
listen_session_new (u8 thread_index, session_type_t type)
{
  stream_session_t *s;
  s = session_alloc (thread_index);
  s->session_type = type;
  s->session_state = SESSION_STATE_LISTENING;
  return s;
}

always_inline stream_session_t *
listen_session_get (u32 index)
{
  return session_get (index, 0);
}

always_inline void
listen_session_del (stream_session_t * s)
{
  session_free (s);
}

transport_connection_t *listen_session_get_transport (stream_session_t * s);

int
listen_session_get_local_session_endpoint (stream_session_t * listener,
					   session_endpoint_t * sep);

void session_flush_frames_main_thread (vlib_main_t * vm);

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
