/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this
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

#ifndef SRC_VCL_VCL_PRIVATE_H_
#define SRC_VCL_VCL_PRIVATE_H_

#include <vnet/session/application_interface.h>
#include <vcl/vppcom.h>
#include <vcl/vcl_debug.h>

#if (CLIB_DEBUG > 0)
/* Set VPPCOM_DEBUG_INIT 2 for connection debug,
 *                       3 for read/write debug output
 * or
 *    export VCL_DEBUG=<#> to set dynamically.
 */
#define VPPCOM_DEBUG_INIT 1
#else
#define VPPCOM_DEBUG_INIT 0
#endif

#define VPPCOM_DEBUG vcm->debug

extern __thread uword __vcl_worker_index;

static inline void
vcl_set_worker_index (uword wrk_index)
{
  __vcl_worker_index = wrk_index;
}

static inline uword
vcl_get_worker_index (void)
{
  return __vcl_worker_index;
}

/*
 * VPPCOM Private definitions and functions.
 */
typedef enum
{
  STATE_APP_START,
  STATE_APP_CONN_VPP,
  STATE_APP_ENABLED,
  STATE_APP_ATTACHED,
  STATE_APP_ADDING_WORKER,
  STATE_APP_FAILED,
  STATE_APP_READY
} app_state_t;

typedef enum
{
  STATE_START = 0x01,
  STATE_CONNECT = 0x02,
  STATE_LISTEN = 0x04,
  STATE_ACCEPT = 0x08,
  STATE_VPP_CLOSING = 0x10,
  STATE_DISCONNECT = 0x20,
  STATE_FAILED = 0x40,
  STATE_UPDATED = 0x80,
} session_state_t;

#define SERVER_STATE_OPEN  (STATE_ACCEPT|STATE_VPP_CLOSING)
#define CLIENT_STATE_OPEN  (STATE_CONNECT|STATE_VPP_CLOSING)
#define STATE_OPEN (SERVER_STATE_OPEN | CLIENT_STATE_OPEN)

typedef struct epoll_event vppcom_epoll_event_t;

typedef struct
{
  u32 next_sh;
  u32 prev_sh;
  u32 vep_sh;
  vppcom_epoll_event_t ev;
#define VEP_DEFAULT_ET_MASK  (EPOLLIN|EPOLLOUT)
#define VEP_UNSUPPORTED_EVENTS (EPOLLONESHOT|EPOLLEXCLUSIVE)
  u32 et_mask;
} vppcom_epoll_t;

typedef struct
{
  u8 is_ip4;
  ip46_address_t ip46;
} vppcom_ip46_t;

#define VCL_ACCEPTED_F_CLOSED 	(1 << 0)
#define VCL_ACCEPTED_F_RESET 	(1 << 1)

typedef struct vcl_session_msg
{
  u32 next;
  union
  {
    session_accepted_msg_t accepted_msg;
  };
  u32 flags;
} vcl_session_msg_t;

enum
{
  VCL_SESS_ATTR_SERVER,
  VCL_SESS_ATTR_CUT_THRU,
  VCL_SESS_ATTR_VEP,
  VCL_SESS_ATTR_VEP_SESSION,
  VCL_SESS_ATTR_LISTEN,		// SOL_SOCKET,SO_ACCEPTCONN
  VCL_SESS_ATTR_NONBLOCK,	// fcntl,O_NONBLOCK
  VCL_SESS_ATTR_REUSEADDR,	// SOL_SOCKET,SO_REUSEADDR
  VCL_SESS_ATTR_REUSEPORT,	// SOL_SOCKET,SO_REUSEPORT
  VCL_SESS_ATTR_BROADCAST,	// SOL_SOCKET,SO_BROADCAST
  VCL_SESS_ATTR_V6ONLY,		// SOL_TCP,IPV6_V6ONLY
  VCL_SESS_ATTR_KEEPALIVE,	// SOL_SOCKET,SO_KEEPALIVE
  VCL_SESS_ATTR_TCP_NODELAY,	// SOL_TCP,TCP_NODELAY
  VCL_SESS_ATTR_TCP_KEEPIDLE,	// SOL_TCP,TCP_KEEPIDLE
  VCL_SESS_ATTR_TCP_KEEPINTVL,	// SOL_TCP,TCP_KEEPINTVL
  VCL_SESS_ATTR_MAX
} vppcom_session_attr_t;

#define VCL_SESS_ATTR_SET(ATTR, VAL)            \
do {                                            \
  (ATTR) |= 1 << (VAL);                         \
 } while (0)

#define VCL_SESS_ATTR_CLR(ATTR, VAL)            \
do {                                            \
  (ATTR) &= ~(1 << (VAL));                      \
 } while (0)

#define VCL_SESS_ATTR_TEST(ATTR, VAL)           \
  ((ATTR) & (1 << (VAL)) ? 1 : 0)

typedef struct vcl_shared_session_
{
  u32 ss_index;
  u32 *workers;
  u32 session_index;
} vcl_shared_session_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define _(type, name) type name;
  foreach_app_session_field
#undef _
  u32 sndbuf_size;		// VPP-TBD: Hack until support setsockopt(SO_SNDBUF)
  u32 rcvbuf_size;		// VPP-TBD: Hack until support setsockopt(SO_RCVBUF)
  u32 user_mss;			// VPP-TBD: Hack until support setsockopt(TCP_MAXSEG)
  u8 *segment_name;
  u32 sm_seg_index;
  u32 client_context;
  u64 vpp_handle;
  u32 vpp_thread_index;

  /* Socket configuration state */
  u8 is_vep;
  u8 is_vep_session;
  u8 has_rx_evt;
  u32 attr;
  u32 wait_cont_idx;
  vppcom_epoll_t vep;
  int libc_epfd;
  svm_msg_q_t *our_evt_q;
  u64 options[16];
  vcl_session_msg_t *accept_evts_fifo;
  u32 shared_index;
#if VCL_ELOG
  elog_track_t elog_track;
#endif
} vcl_session_t;

typedef struct vppcom_cfg_t_
{
  uword heapsize;
  u32 max_workers;
  u32 vpp_api_q_length;
  uword segment_baseva;
  u32 segment_size;
  u32 add_segment_size;
  u32 preallocated_fifo_pairs;
  u32 rx_fifo_size;
  u32 tx_fifo_size;
  u32 event_queue_size;
  u32 listen_queue_size;
  u8 app_proxy_transport_tcp;
  u8 app_proxy_transport_udp;
  u8 app_scope_local;
  u8 app_scope_global;
  u8 *namespace_id;
  u64 namespace_secret;
  u8 use_mq_eventfd;
  f64 app_timeout;
  f64 session_timeout;
  f64 accept_timeout;
  u32 event_ring_size;
  char *event_log_path;
  u8 *vpp_api_filename;
  u8 *vpp_api_socket_name;
} vppcom_cfg_t;

void vppcom_cfg (vppcom_cfg_t * vcl_cfg);

typedef struct vcl_cut_through_registration_
{
  svm_msg_q_t *mq;
  svm_msg_q_t *peer_mq;
  u32 sid;
  u32 epoll_evt_conn_index;	/*< mq evt connection index part of
				   the mqs evtfd epoll (if used) */
} vcl_cut_through_registration_t;

typedef struct vcl_mq_evt_conn_
{
  svm_msg_q_t *mq;
  int mq_fd;
} vcl_mq_evt_conn_t;

typedef struct vcl_worker_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Session pool */
  vcl_session_t *sessions;

  /** Worker/thread index in current process */
  u32 wrk_index;

  /** Worker index in vpp*/
  u32 vpp_wrk_index;

  /** API client handle */
  u32 my_client_index;

  /** State of the connection, shared between msg RX thread and main thread */
  volatile app_state_t wrk_state;

  /** VPP binary api input queue */
  svm_queue_t *vl_input_queue;

  /** Message queues epoll fd. Initialized only if using mqs with eventfds */
  int mqs_epfd;

  /** Pool of event message queue event connections */
  vcl_mq_evt_conn_t *mq_evt_conns;

  /** Per worker buffer for receiving mq epoll events */
  struct epoll_event *mq_events;

  /** Hash table for disconnect processing */
  uword *session_index_by_vpp_handles;

  /** Select bitmaps */
  clib_bitmap_t *rd_bitmap;
  clib_bitmap_t *wr_bitmap;
  clib_bitmap_t *ex_bitmap;

  /** Our event message queue */
  svm_msg_q_t *app_event_queue;

  /** VPP workers event message queues */
  svm_msg_q_t **vpp_event_queues;

  /** For deadman timers */
  clib_time_t clib_time;

  /** Pool of cut through registrations */
  vcl_cut_through_registration_t *cut_through_registrations;

  /** Lock for accessing ct registration pool */
  clib_spinlock_t ct_registration_lock;

  /** Cut-through registration by mq address hash table */
  uword *ct_registration_by_mq;

  /** Vector acting as buffer for mq messages */
  svm_msg_q_msg_t *mq_msg_vector;

  /** Vector of unhandled events */
  session_event_t *unhandled_evts_vector;

  u32 *pending_session_wrk_updates;

  /** Used also as a thread stop key buffer */
  pthread_t thread_id;

  /** Current pid, may be different from main_pid if forked child */
  pid_t current_pid;

  u32 forked_child;

} vcl_worker_t;

typedef struct vppcom_main_t_
{
  u8 is_init;
  u32 debug;
  pthread_t main_cpu;

  /** Main process pid */
  pid_t main_pid;

  /** App's index in vpp. It's used by vpp to identify the app */
  u32 app_index;

  /** State of the connection, shared between msg RX thread and main thread */
  volatile app_state_t app_state;

  u8 *app_name;

  /** VCL configuration */
  vppcom_cfg_t cfg;

  volatile u32 forking;

  /** Workers */
  vcl_worker_t *workers;

  /** Lock to protect worker registrations */
  clib_spinlock_t workers_lock;

  /** Pool of shared sessions */
  vcl_shared_session_t *shared_sessions;

  /** Lock to protect segment hash table */
  clib_rwlock_t segment_table_lock;

  /** Mapped segments table */
  uword *segment_table;

  svm_fifo_segment_main_t segment_main;

#ifdef VCL_ELOG
  /* VPP Event-logger */
  elog_main_t elog_main;
  elog_track_t elog_track;
#endif

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;

} vppcom_main_t;

extern vppcom_main_t *vcm;

#define VCL_INVALID_SESSION_INDEX ((u32)~0)
#define VCL_INVALID_SEGMENT_INDEX ((u32)~0)
#define VCL_INVALID_SEGMENT_HANDLE ((u64)~0)

static inline vcl_session_t *
vcl_session_alloc (vcl_worker_t * wrk)
{
  vcl_session_t *s;
  pool_get (wrk->sessions, s);
  memset (s, 0, sizeof (*s));
  s->session_index = s - wrk->sessions;
  s->shared_index = ~0;
  return s;
}

static inline void
vcl_session_free (vcl_worker_t * wrk, vcl_session_t * s)
{
  pool_put (wrk->sessions, s);
}

static inline vcl_session_t *
vcl_session_get (vcl_worker_t * wrk, u32 session_index)
{
  if (pool_is_free_index (wrk->sessions, session_index))
    return 0;
  return pool_elt_at_index (wrk->sessions, session_index);
}

static inline int
vcl_session_handle (vcl_session_t * s)
{
  ASSERT (s->session_index < 2 << 24);
  return (vcl_get_worker_index () << 24 | s->session_index);
}

static inline void
vcl_session_handle_parse (u32 handle, u32 * wrk_index, u32 * session_index)
{
  *wrk_index = handle >> 24;
  *session_index = handle & 0xFFFFFF;
}

static inline vcl_session_t *
vcl_session_get_w_handle (vcl_worker_t * wrk, u32 session_handle)
{
  u32 session_index, wrk_index;
  vcl_session_handle_parse (session_handle, &wrk_index, &session_index);
  ASSERT (wrk_index == wrk->wrk_index);
  return vcl_session_get (wrk, session_index);
}

static inline vcl_session_t *
vcl_session_get_w_vpp_handle (vcl_worker_t * wrk, u64 vpp_handle)
{
  uword *p;
  if ((p = hash_get (wrk->session_index_by_vpp_handles, vpp_handle)))
    return vcl_session_get (wrk, (u32) p[0]);
  return 0;
}

static inline u32
vcl_session_index_from_vpp_handle (vcl_worker_t * wrk, u64 vpp_handle)
{
  uword *p;
  if ((p = hash_get (wrk->session_index_by_vpp_handles, vpp_handle)))
    return p[0];
  return VCL_INVALID_SESSION_INDEX;
}

static inline void
vcl_session_table_add_vpp_handle (vcl_worker_t * wrk, u64 handle, u32 value)
{
  hash_set (wrk->session_index_by_vpp_handles, handle, value);
}

static inline void
vcl_session_table_del_vpp_handle (vcl_worker_t * wrk, u64 vpp_handle)
{
  hash_unset (wrk->session_index_by_vpp_handles, vpp_handle);
}

static inline uword *
vcl_session_table_lookup_vpp_handle (vcl_worker_t * wrk, u64 handle)
{
  return hash_get (wrk->session_index_by_vpp_handles, handle);
}

static inline void
vcl_session_table_add_listener (vcl_worker_t * wrk, u64 listener_handle,
				u32 value)
{
  /* Session and listener handles have different formats. The latter has
   * the thread index in the upper 32 bits while the former has the session
   * type. Knowing that, for listeners we just flip the MSB to 1 */
  listener_handle |= 1ULL << 63;
  hash_set (wrk->session_index_by_vpp_handles, listener_handle, value);
}

static inline void
vcl_session_table_del_listener (vcl_worker_t * wrk, u64 listener_handle)
{
  listener_handle |= 1ULL << 63;
  hash_unset (wrk->session_index_by_vpp_handles, listener_handle);
}

static inline vcl_session_t *
vcl_session_table_lookup_listener (vcl_worker_t * wrk, u64 listener_handle)
{
  uword *p;
  u64 handle = listener_handle | (1ULL << 63);
  vcl_session_t *session;

  p = hash_get (wrk->session_index_by_vpp_handles, handle);
  if (!p)
    {
      clib_warning ("VCL<%d>: couldn't find listen session: unknown vpp "
		    "listener handle %llx", getpid (), listener_handle);
      return 0;
    }
  if (pool_is_free_index (wrk->sessions, p[0]))
    {
      VDBG (1, "VCL<%d>: invalid listen session, sid (%u)", getpid (), p[0]);
      return 0;
    }

  session = pool_elt_at_index (wrk->sessions, p[0]);
  ASSERT (session->session_state & STATE_LISTEN);
  return session;
}

const char *vppcom_session_state_str (session_state_t state);

static inline u8
vcl_session_is_ct (vcl_session_t * s)
{
  return (s->our_evt_q != 0);
}

/*
 * Helpers
 */
int vcl_wait_for_app_state_change (app_state_t app_state);
vcl_cut_through_registration_t
  * vcl_ct_registration_lock_and_alloc (vcl_worker_t * wrk);
void vcl_ct_registration_del (vcl_worker_t * wrk,
			      vcl_cut_through_registration_t * ctr);
u32 vcl_ct_registration_index (vcl_worker_t * wrk,
			       vcl_cut_through_registration_t * ctr);
void vcl_ct_registration_lock (vcl_worker_t * wrk);
void vcl_ct_registration_unlock (vcl_worker_t * wrk);
vcl_cut_through_registration_t
  * vcl_ct_registration_lock_and_lookup (vcl_worker_t * wrk, uword mq_addr);
void vcl_ct_registration_lookup_add (vcl_worker_t * wrk, uword mq_addr,
				     u32 ctr_index);
void vcl_ct_registration_lookup_del (vcl_worker_t * wrk, uword mq_addr);
vcl_mq_evt_conn_t *vcl_mq_evt_conn_alloc (vcl_worker_t * wrk);
u32 vcl_mq_evt_conn_index (vcl_worker_t * wrk, vcl_mq_evt_conn_t * mqc);
vcl_mq_evt_conn_t *vcl_mq_evt_conn_get (vcl_worker_t * wrk, u32 mq_conn_idx);
int vcl_mq_epoll_add_evfd (vcl_worker_t * wrk, svm_msg_q_t * mq);
int vcl_mq_epoll_del_evfd (vcl_worker_t * wrk, u32 mqc_index);

vcl_worker_t *vcl_worker_alloc_and_init (void);
void vcl_worker_cleanup (vcl_worker_t * wrk, u8 notify_vpp);
int vcl_worker_register_with_vpp (void);
int vcl_worker_set_bapi (void);
void vcl_worker_share_sessions (vcl_worker_t * parent_wrk);
int vcl_worker_unshare_session (vcl_worker_t * wrk, vcl_session_t * s);
int vcl_session_get_refcnt (vcl_session_t * s);

void vcl_segment_table_add (u64 segment_handle, u32 svm_segment_index);
u32 vcl_segment_table_lookup (u64 segment_handle);
void vcl_segment_table_del (u64 segment_handle);

static inline vcl_worker_t *
vcl_worker_get (u32 wrk_index)
{
  return pool_elt_at_index (vcm->workers, wrk_index);
}

static inline vcl_worker_t *
vcl_worker_get_if_valid (u32 wrk_index)
{
  if (pool_is_free_index (vcm->workers, wrk_index))
    return 0;
  return pool_elt_at_index (vcm->workers, wrk_index);
}

static inline vcl_worker_t *
vcl_worker_get_current (void)
{
  return vcl_worker_get (vcl_get_worker_index ());
}

static inline svm_msg_q_t *
vcl_session_vpp_evt_q (vcl_worker_t * wrk, vcl_session_t * s)
{
  if (vcl_session_is_ct (s))
    return wrk->vpp_event_queues[0];
  else
    return wrk->vpp_event_queues[s->vpp_thread_index];
}

void vcl_send_session_worker_update (vcl_worker_t *wrk, vcl_session_t *s,
                                     u32 wrk_index);
/*
 * VCL Binary API
 */
int vppcom_connect_to_vpp (char *app_name);
void vppcom_init_error_string_table (void);
void vppcom_send_session_enable_disable (u8 is_enable);
void vppcom_app_send_attach (void);
void vppcom_app_send_detach (void);
void vppcom_send_connect_sock (vcl_session_t * session);
void vppcom_send_disconnect_session (u64 vpp_handle);
void vppcom_send_bind_sock (vcl_session_t * session);
void vppcom_send_unbind_sock (u64 vpp_handle);
void vppcom_api_hookup (void);
void vcl_send_app_worker_add_del (u8 is_add);
void vcl_send_child_worker_del (vcl_worker_t * wrk);

u32 vcl_max_nsid_len (void);

u8 *format_api_error (u8 * s, va_list * args);

#endif /* SRC_VCL_VCL_PRIVATE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
