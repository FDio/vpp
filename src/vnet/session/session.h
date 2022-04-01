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
#ifndef __included_session_h__
#define __included_session_h__

#include <vppinfra/llist.h>
#include <vnet/session/session_types.h>
#include <vnet/session/session_lookup.h>
#include <vnet/session/session_debug.h>
#include <svm/message_queue.h>
#include <svm/fifo_segment.h>

#define foreach_session_input_error                                    	\
_(NO_SESSION, "No session drops")                                       \
_(NO_LISTENER, "No listener for dst port drops")                        \
_(ENQUEUED, "Packets pushed into rx fifo")                              \
_(NOT_READY, "Session not ready packets")                               \
_(FIFO_FULL, "Packets dropped for lack of rx fifo space")               \
_(EVENT_FIFO_FULL, "Events not sent for lack of event fifo space")      \
_(API_QUEUE_FULL, "Sessions not created for lack of API queue space")   \

typedef enum
{
#define _(sym,str) SESSION_ERROR_##sym,
  foreach_session_input_error
#undef _
    SESSION_N_ERROR,
} session_input_error_t;

typedef struct session_tx_context_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  session_t *s;
  transport_proto_vft_t *transport_vft;
  transport_connection_t *tc;
  transport_send_params_t sp;
  u32 max_dequeue;
  u32 left_to_snd;
  u32 max_len_to_snd;
  u16 deq_per_first_buf;
  u16 deq_per_buf;
  u16 n_segs_per_evt;
  u16 n_bufs_needed;
  u8 n_bufs_per_seg;
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  session_dgram_hdr_t hdr;

  /** Vector of tx buffer free lists */
  u32 *tx_buffers;
  vlib_buffer_t **transport_pending_bufs;
} session_tx_context_t;

typedef struct session_evt_elt
{
  clib_llist_anchor_t evt_list;
  session_event_t evt;
} session_evt_elt_t;

typedef struct session_ctrl_evt_data_
{
  u8 data[SESSION_CTRL_MSG_MAX_SIZE];
} session_evt_ctrl_data_t;

typedef enum session_wrk_state_
{
  SESSION_WRK_POLLING,
  SESSION_WRK_INTERRUPT,
  SESSION_WRK_IDLE,
} __clib_packed session_wrk_state_t;

typedef enum session_wrk_flags_
{
  SESSION_WRK_F_ADAPTIVE = 1 << 0,
} __clib_packed session_wrk_flag_t;

typedef struct session_worker_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /** Worker session pool */
  session_t *sessions;

  /** vpp event message queue for worker */
  svm_msg_q_t *vpp_event_queue;

  /** vlib_time_now last time around the track */
  clib_time_type_t last_vlib_time;

  /** vlib_time_now rounded to us precision and as u64 */
  clib_us_time_t last_vlib_us_time;

  /** Convenience pointer to this worker's vlib_main */
  vlib_main_t *vm;

  /** Per-proto vector of sessions to enqueue */
  u32 **session_to_enqueue;

  /** Timerfd used to periodically signal wrk session queue node */
  int timerfd;

  /** Worker flags */
  session_wrk_flag_t flags;

  /** Worker state */
  session_wrk_state_t state;

  /** Context for session tx */
  session_tx_context_t ctx;

  /** Pool of session event list elements */
  session_evt_elt_t *event_elts;

  /** Pool of ctrl events data buffers */
  session_evt_ctrl_data_t *ctrl_evts_data;

  /** Head of control events list */
  clib_llist_index_t ctrl_head;

  /** Head of list of elements */
  clib_llist_index_t new_head;

  /** Head of list of pending events */
  clib_llist_index_t old_head;

  /** Vector of buffers to be sent */
  u32 *pending_tx_buffers;

  /** Vector of nexts for the pending tx buffers */
  u16 *pending_tx_nexts;

  /** Clib file for timerfd. Used only if adaptive mode is on */
  uword timerfd_file;

  /** List of pending connects for first worker */
  clib_llist_index_t pending_connects;

  /** Flag that is set if main thread signaled to handle connects */
  u32 n_pending_connects;

  /** Main thread loops in poll mode without a connect */
  u32 no_connect_loops;

  /** List head for first worker evts pending handling on main */
  clib_llist_index_t evts_pending_main;

#if SESSION_DEBUG
  /** last event poll time by thread */
  clib_time_type_t last_event_poll;
#endif
} session_worker_t;

typedef int (session_fifo_rx_fn) (session_worker_t * wrk,
				  vlib_node_runtime_t * node,
				  session_evt_elt_t * e, int *n_tx_packets);

extern session_fifo_rx_fn session_tx_fifo_peek_and_snd;
extern session_fifo_rx_fn session_tx_fifo_dequeue_and_snd;
extern session_fifo_rx_fn session_tx_fifo_dequeue_internal;

u8 session_node_lookup_fifo_event (svm_fifo_t * f, session_event_t * e);

typedef void (*session_update_time_fn) (f64 time_now, u8 thread_index);

typedef struct session_main_
{
  /** Worker contexts */
  session_worker_t *wrk;

  /** Vector of transport update time functions */
  session_update_time_fn *update_time_fns;

  /** Event queues memfd segment */
  fifo_segment_t wrk_mqs_segment;

  /** Unique segment name counter */
  u32 unique_segment_name_counter;

  /** Per transport rx function that can either dequeue or peek */
  session_fifo_rx_fn **session_tx_fns;

  /** Per session type output nodes. Could optimize to group nodes by
   * fib but lookup would then require session type parsing in session node.
   * Trade memory for speed, for now */
  u32 *session_type_to_next;

  /** Thread for cl and ho that rely on cl allocs */
  u32 transport_cl_thread;

  transport_proto_t last_transport_proto_type;

  /** Number of workers at pool realloc barrier */
  volatile u32 pool_realloc_at_barrier;

  /** Number of workers doing reallocs */
  volatile u32 pool_realloc_doing_work;

  /** Lock to synchronize parallel forced reallocs */
  clib_spinlock_t pool_realloc_lock;

  /*
   * Config parameters
   */

  /** Session manager is enabled */
  u8 is_enabled;

  /** Session manager initialized (not necessarily enabled) */
  u8 is_initialized;

  /** Enable session manager at startup */
  u8 session_enable_asap;

  /** Poll session node in main thread */
  u8 poll_main;

  /** Allocate private rx mqs for external apps */
  u8 use_private_rx_mqs;

  /** Do not enable session queue node adaptive mode */
  u8 no_adaptive;

  /** vpp fifo event queue configured length */
  u32 configured_wrk_mq_length;

  /** Session ssvm segment configs*/
  uword wrk_mqs_segment_size;

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

  u16 msg_id_base;
} session_main_t;

extern session_main_t session_main;
extern vlib_node_registration_t session_queue_node;
extern vlib_node_registration_t session_queue_process_node;
extern vlib_node_registration_t session_queue_pre_input_node;

typedef enum session_q_process_evt_
{
  SESSION_Q_PROCESS_RUN_ON_MAIN = 1,
  SESSION_Q_PROCESS_STOP
} session_q_process_evt_t;

#define TRANSPORT_PROTO_INVALID (session_main.last_transport_proto_type + 1)
#define TRANSPORT_N_PROTOS (session_main.last_transport_proto_type + 1)

static inline void
session_evt_add_old (session_worker_t * wrk, session_evt_elt_t * elt)
{
  clib_llist_add_tail (wrk->event_elts, evt_list, elt,
		       clib_llist_elt (wrk->event_elts, wrk->old_head));
}

static inline void
session_evt_add_head_old (session_worker_t * wrk, session_evt_elt_t * elt)
{
  clib_llist_add (wrk->event_elts, evt_list, elt,
		  clib_llist_elt (wrk->event_elts, wrk->old_head));
}


static inline u32
session_evt_ctrl_data_alloc (session_worker_t * wrk)
{
  session_evt_ctrl_data_t *data;
  pool_get (wrk->ctrl_evts_data, data);
  return (data - wrk->ctrl_evts_data);
}

static inline session_evt_elt_t *
session_evt_alloc_ctrl (session_worker_t * wrk)
{
  session_evt_elt_t *elt;
  clib_llist_get (wrk->event_elts, elt);
  clib_llist_add_tail (wrk->event_elts, evt_list, elt,
		       clib_llist_elt (wrk->event_elts, wrk->ctrl_head));
  return elt;
}

static inline void *
session_evt_ctrl_data (session_worker_t * wrk, session_evt_elt_t * elt)
{
  return (void *) (pool_elt_at_index (wrk->ctrl_evts_data,
				      elt->evt.ctrl_data_index));
}

static inline void
session_evt_ctrl_data_free (session_worker_t * wrk, session_evt_elt_t * elt)
{
  ASSERT (elt->evt.event_type > SESSION_IO_EVT_BUILTIN_TX);
  pool_put_index (wrk->ctrl_evts_data, elt->evt.ctrl_data_index);
}

static inline session_evt_elt_t *
session_evt_alloc_new (session_worker_t * wrk)
{
  session_evt_elt_t *elt;
  clib_llist_get (wrk->event_elts, elt);
  clib_llist_add_tail (wrk->event_elts, evt_list, elt,
		       clib_llist_elt (wrk->event_elts, wrk->new_head));
  return elt;
}

static inline session_evt_elt_t *
session_evt_alloc_old (session_worker_t * wrk)
{
  session_evt_elt_t *elt;
  clib_llist_get (wrk->event_elts, elt);
  clib_llist_add_tail (wrk->event_elts, evt_list, elt,
		       clib_llist_elt (wrk->event_elts, wrk->old_head));
  return elt;
}

int session_wrk_handle_mq (session_worker_t *wrk, svm_msg_q_t *mq);

session_t *session_alloc (u32 thread_index);
void session_free (session_t * s);
void session_free_w_fifos (session_t * s);
void session_cleanup_half_open (session_handle_t ho_handle);
u8 session_is_valid (u32 si, u8 thread_index);

always_inline session_t *
session_get (u32 si, u32 thread_index)
{
  ASSERT (session_is_valid (si, thread_index));
  return pool_elt_at_index (session_main.wrk[thread_index].sessions, si);
}

always_inline session_t *
session_get_if_valid (u64 si, u32 thread_index)
{
  if (thread_index >= vec_len (session_main.wrk))
    return 0;

  if (pool_is_free_index (session_main.wrk[thread_index].sessions, si))
    return 0;

  ASSERT (session_is_valid (si, thread_index));
  return pool_elt_at_index (session_main.wrk[thread_index].sessions, si);
}

always_inline session_t *
session_get_from_handle (session_handle_t handle)
{
  session_main_t *smm = &session_main;
  u32 session_index, thread_index;
  session_parse_handle (handle, &session_index, &thread_index);
  return pool_elt_at_index (smm->wrk[thread_index].sessions, session_index);
}

always_inline session_t *
session_get_from_handle_if_valid (session_handle_t handle)
{
  u32 session_index, thread_index;
  session_parse_handle (handle, &session_index, &thread_index);
  return session_get_if_valid (session_index, thread_index);
}

u64 session_segment_handle (session_t * s);

/**
 * Get session from handle and avoid pool validation if no same thread
 *
 * Peekers are fine because pool grows with barrier (see @ref session_alloc)
 */
always_inline session_t *
session_get_from_handle_safe (u64 handle)
{
  u32 thread_index = session_thread_from_handle (handle);
  session_worker_t *wrk = &session_main.wrk[thread_index];

  if (thread_index == vlib_get_thread_index ())
    {
      return pool_elt_at_index (wrk->sessions,
				session_index_from_handle (handle));
    }
  else
    {
      /* Don't use pool_elt_at index to avoid pool bitmap reallocs */
      return wrk->sessions + session_index_from_handle (handle);
    }
}

always_inline session_t *
session_clone_safe (u32 session_index, u32 thread_index)
{
  u32 current_thread_index = vlib_get_thread_index (), new_index;
  session_t *old_s, *new_s;

  new_s = session_alloc (current_thread_index);
  new_index = new_s->session_index;
  /* Session pools are reallocated with barrier (see @ref session_alloc) */
  old_s = session_main.wrk[thread_index].sessions + session_index;
  clib_memcpy_fast (new_s, old_s, sizeof (*new_s));
  new_s->thread_index = current_thread_index;
  new_s->session_index = new_index;
  return new_s;
}

int session_open (session_endpoint_cfg_t *sep, session_handle_t *rsh);
int session_listen (session_t * s, session_endpoint_cfg_t * sep);
int session_stop_listen (session_t * s);
void session_half_close (session_t *s);
void session_close (session_t * s);
void session_reset (session_t * s);
void session_transport_half_close (session_t *s);
void session_transport_close (session_t * s);
void session_transport_reset (session_t * s);
void session_transport_cleanup (session_t * s);
int session_send_io_evt_to_thread (svm_fifo_t * f,
				   session_evt_type_t evt_type);
int session_enqueue_notify (session_t * s);
int session_dequeue_notify (session_t * s);
int session_send_io_evt_to_thread_custom (void *data, u32 thread_index,
					  session_evt_type_t evt_type);
void session_send_rpc_evt_to_thread (u32 thread_index, void *fp,
				     void *rpc_args);
void session_send_rpc_evt_to_thread_force (u32 thread_index, void *fp,
					   void *rpc_args);
void session_add_self_custom_tx_evt (transport_connection_t * tc,
				     u8 has_prio);
void sesssion_reschedule_tx (transport_connection_t * tc);
transport_connection_t *session_get_transport (session_t * s);
void session_get_endpoint (session_t * s, transport_endpoint_t * tep,
			   u8 is_lcl);
int session_transport_attribute (session_t *s, u8 is_get,
				 transport_endpt_attr_t *attr);

u8 *format_session (u8 * s, va_list * args);
uword unformat_session (unformat_input_t * input, va_list * args);
uword unformat_transport_connection (unformat_input_t * input,
				     va_list * args);

/*
 * Interface to transport protos
 */

int session_enqueue_stream_connection (transport_connection_t * tc,
				       vlib_buffer_t * b, u32 offset,
				       u8 queue_event, u8 is_in_order);
int session_enqueue_dgram_connection (session_t * s,
				      session_dgram_hdr_t * hdr,
				      vlib_buffer_t * b, u8 proto,
				      u8 queue_event);
int session_stream_connect_notify (transport_connection_t * tc,
				   session_error_t err);
int session_dgram_connect_notify (transport_connection_t * tc,
				  u32 old_thread_index,
				  session_t ** new_session);
int session_stream_accept_notify (transport_connection_t * tc);
void session_transport_closing_notify (transport_connection_t * tc);
void session_transport_delete_notify (transport_connection_t * tc);
void session_half_open_delete_notify (transport_connection_t *tc);
void session_half_open_migrate_notify (transport_connection_t *tc);
int session_half_open_migrated_notify (transport_connection_t *tc);
void session_transport_closed_notify (transport_connection_t * tc);
void session_transport_reset_notify (transport_connection_t * tc);
int session_stream_accept (transport_connection_t * tc, u32 listener_index,
			   u32 thread_index, u8 notify);
int session_dgram_accept (transport_connection_t * tc, u32 listener_index,
			  u32 thread_index);
/**
 * Initialize session layer for given transport proto and ip version
 *
 * Allocates per session type (transport proto + ip version) data structures
 * and adds arc from session queue node to session type output node.
 *
 * @param transport_proto 	transport proto to be registered
 * @param vft			virtual function table for transport
 * @param is_ip4		flag that indicates if transports uses ipv4
 * 				as underlying network layer
 * @param output_node		output node for transport
 */
void session_register_transport (transport_proto_t transport_proto,
				 const transport_proto_vft_t * vft, u8 is_ip4,
				 u32 output_node);
transport_proto_t session_add_transport_proto (void);
void session_register_update_time_fn (session_update_time_fn fn, u8 is_add);
int session_tx_fifo_peek_bytes (transport_connection_t * tc, u8 * buffer,
				u32 offset, u32 max_bytes);
u32 session_tx_fifo_dequeue_drop (transport_connection_t * tc, u32 max_bytes);

always_inline u32
transport_max_rx_enqueue (transport_connection_t * tc)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_max_enqueue_prod (s->rx_fifo);
}

always_inline u32
transport_max_tx_dequeue (transport_connection_t * tc)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_max_dequeue_cons (s->tx_fifo);
}

always_inline u32
transport_max_rx_dequeue (transport_connection_t * tc)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_max_dequeue (s->rx_fifo);
}

always_inline u32
transport_rx_fifo_size (transport_connection_t * tc)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_size (s->rx_fifo);
}

always_inline u32
transport_tx_fifo_size (transport_connection_t * tc)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_size (s->tx_fifo);
}

always_inline u8
transport_rx_fifo_has_ooo_data (transport_connection_t * tc)
{
  session_t *s = session_get (tc->c_index, tc->thread_index);
  return svm_fifo_has_ooo_data (s->rx_fifo);
}

always_inline void
transport_rx_fifo_req_deq_ntf (transport_connection_t *tc)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  svm_fifo_add_want_deq_ntf (s->rx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
}

always_inline clib_time_type_t
transport_time_now (u32 thread_index)
{
  return session_main.wrk[thread_index].last_vlib_time;
}

always_inline clib_us_time_t
transport_us_time_now (u32 thread_index)
{
  return session_main.wrk[thread_index].last_vlib_us_time;
}

always_inline clib_time_type_t
transport_seconds_per_loop (u32 thread_index)
{
  return session_main.wrk[thread_index].vm->seconds_per_loop;
}

always_inline void
transport_add_tx_event (transport_connection_t * tc)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  if (svm_fifo_has_event (s->tx_fifo))
    return;
  session_send_io_evt_to_thread (s->tx_fifo, SESSION_IO_EVT_TX);
}

always_inline u32
transport_cl_thread (void)
{
  return session_main.transport_cl_thread;
}

/*
 * Listen sessions
 */

always_inline u64
listen_session_get_handle (session_t * s)
{
  ASSERT (s->session_state == SESSION_STATE_LISTENING ||
	  session_get_transport_proto (s) == TRANSPORT_PROTO_QUIC);
  return session_handle (s);
}

always_inline session_t *
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

always_inline session_t *
listen_session_alloc (u8 thread_index, session_type_t type)
{
  session_t *s;
  s = session_alloc (thread_index);
  s->session_type = type;
  s->session_state = SESSION_STATE_LISTENING;
  return s;
}

always_inline session_t *
listen_session_get (u32 ls_index)
{
  return session_get (ls_index, 0);
}

always_inline void
listen_session_free (session_t * s)
{
  ASSERT (!s->rx_fifo);
  session_free (s);
}

always_inline session_t *
ho_session_alloc (void)
{
  session_t *s;
  ASSERT (vlib_get_thread_index () == 0);
  s = session_alloc (0);
  s->session_state = SESSION_STATE_CONNECTING;
  s->flags |= SESSION_F_HALF_OPEN;
  /* Not ideal. Half-opens are only allocated from main with worker barrier
   * but can be cleaned up, i.e., session_half_open_free, from main without
   * a barrier. In debug images, the free_bitmap can grow while workers peek
   * the sessions pool, e.g., session_half_open_migrate_notify, and as a
   * result crash while validating the session. To avoid this, grow the bitmap
   * now. */
  if (CLIB_DEBUG)
    {
      session_t *sp = session_main.wrk[0].sessions;
      clib_bitmap_validate (pool_header (sp)->free_bitmap, s->session_index);
    }
  return s;
}

always_inline session_t *
ho_session_get (u32 ho_index)
{
  return session_get (ho_index, 0 /* half-open thread */);
}

always_inline void
ho_session_free (session_t *s)
{
  ASSERT (!s->rx_fifo && s->thread_index == 0);
  session_free (s);
}

transport_connection_t *listen_session_get_transport (session_t * s);

/*
 * Session layer functions
 */

always_inline session_main_t *
vnet_get_session_main ()
{
  return &session_main;
}

always_inline session_worker_t *
session_main_get_worker (u32 thread_index)
{
  return &session_main.wrk[thread_index];
}

static inline session_worker_t *
session_main_get_worker_if_valid (u32 thread_index)
{
  if (thread_index > vec_len (session_main.wrk))
    return 0;
  return &session_main.wrk[thread_index];
}

always_inline svm_msg_q_t *
session_main_get_vpp_event_queue (u32 thread_index)
{
  return session_main.wrk[thread_index].vpp_event_queue;
}

always_inline u8
session_main_is_enabled ()
{
  return session_main.is_enabled == 1;
}

#define session_cli_return_if_not_enabled()				\
do {									\
    if (!session_main.is_enabled)					\
      return clib_error_return (0, "session layer is not enabled");	\
} while (0)

int session_main_flush_enqueue_events (u8 proto, u32 thread_index);
int session_main_flush_all_enqueue_events (u8 transport_proto);
void session_queue_run_on_main_thread (vlib_main_t * vm);

/**
 * Add session node pending buffer with custom node
 *
 * @param thread_index 	worker thread expected to send the buffer
 * @param bi		buffer index
 * @param next_node	next node edge index for buffer. Edge to next node
 * 			must exist
 */
always_inline void
session_add_pending_tx_buffer (u32 thread_index, u32 bi, u32 next_node)
{
  session_worker_t *wrk = session_main_get_worker (thread_index);
  vec_add1 (wrk->pending_tx_buffers, bi);
  vec_add1 (wrk->pending_tx_nexts, next_node);
  if (PREDICT_FALSE (wrk->state == SESSION_WRK_INTERRUPT))
    vlib_node_set_interrupt_pending (wrk->vm, session_queue_node.index);
}

always_inline void
session_wrk_update_time (session_worker_t *wrk, f64 now)
{
  wrk->last_vlib_time = now;
  wrk->last_vlib_us_time = wrk->last_vlib_time * CLIB_US_TIME_FREQ;
}

void session_wrk_enable_adaptive_mode (session_worker_t *wrk);
fifo_segment_t *session_main_get_wrk_mqs_segment (void);
void session_node_enable_disable (u8 is_en);
clib_error_t *vnet_session_enable_disable (vlib_main_t * vm, u8 is_en);
void session_wrk_handle_evts_main_rpc ();

session_t *session_alloc_for_connection (transport_connection_t * tc);
session_t *session_alloc_for_half_open (transport_connection_t *tc);

typedef void (pool_safe_realloc_rpc_fn) (void *rpc_args);

typedef struct
{
  u8 ph[STRUCT_OFFSET_OF (pool_header_t, max_elts) + 4];
  u32 flag;
} pool_safe_realloc_header_t;

STATIC_ASSERT_SIZEOF (pool_safe_realloc_header_t, sizeof (pool_header_t));

#define POOL_REALLOC_SAFE_ELT_THRESH 32

#define pool_realloc_flag(PH)                                                 \
  ((pool_safe_realloc_header_t *) pool_header (PH))->flag

typedef struct pool_realloc_rpc_args_
{
  void **pool;
  uword elt_size;
  uword align;
} pool_realloc_rpc_args_t;

always_inline void
pool_program_safe_realloc_rpc (void *args)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 free_elts, max_elts, n_alloc;
  pool_realloc_rpc_args_t *pra;

  ASSERT (vlib_get_thread_index () == 0);
  pra = (pool_realloc_rpc_args_t *) args;

  vlib_worker_thread_barrier_sync (vm);

  free_elts = _pool_free_elts (*pra->pool, pra->elt_size);
  if (free_elts < POOL_REALLOC_SAFE_ELT_THRESH)
    {
      max_elts = _vec_max_len (*pra->pool, pra->elt_size);
      n_alloc = clib_max (2 * max_elts, POOL_REALLOC_SAFE_ELT_THRESH);
      _pool_alloc (pra->pool, free_elts + n_alloc, pra->align, 0,
		   pra->elt_size);
    }
  pool_realloc_flag (*pra->pool) = 0;
  clib_mem_free (args);

  vlib_worker_thread_barrier_release (vm);
}

always_inline void
pool_program_safe_realloc (void **p, u32 elt_size, u32 align)
{
  pool_realloc_rpc_args_t *pra;

  /* Reuse pad as a realloc flag */
  if (pool_realloc_flag (*p))
    return;

  pra = clib_mem_alloc (sizeof (*pra));
  pra->pool = p;
  pra->elt_size = elt_size;
  pra->align = align;
  pool_realloc_flag (*p) = 1;

  session_send_rpc_evt_to_thread (0 /* thread index */,
				  pool_program_safe_realloc_rpc, pra);
}

#define pool_needs_realloc(P)                                                 \
  ((!P) ||                                                                    \
   (vec_len (pool_header (P)->free_indices) < POOL_REALLOC_SAFE_ELT_THRESH && \
    pool_free_elts (P) < POOL_REALLOC_SAFE_ELT_THRESH))

#define pool_get_aligned_safe(P, E, align)                                    \
  do                                                                          \
    {                                                                         \
      if (PREDICT_FALSE (pool_needs_realloc (P)))                             \
	{                                                                     \
	  if (PREDICT_FALSE (!(P)))                                           \
	    {                                                                 \
	      pool_alloc_aligned (P, POOL_REALLOC_SAFE_ELT_THRESH, align);    \
	    }                                                                 \
	  else if (PREDICT_FALSE (!pool_free_elts (P)))                       \
	    {                                                                 \
	      vlib_workers_sync ();                                           \
	      pool_alloc_aligned (P, pool_max_len (P), align);                \
	      vlib_workers_continue ();                                       \
	      ALWAYS_ASSERT (pool_free_elts (P) > 0);                         \
	    }                                                                 \
	  else                                                                \
	    {                                                                 \
	      pool_program_safe_realloc ((void **) &(P), sizeof ((P)[0]),     \
					 _vec_align (P, align));              \
	    }                                                                 \
	}                                                                     \
      pool_get_aligned (P, E, align);                                         \
    }                                                                         \
  while (0)

#endif /* __included_session_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
