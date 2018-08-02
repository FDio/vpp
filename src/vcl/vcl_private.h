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
#include <vcl/vcl_event.h>
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

/*
 * VPPCOM Private definitions and functions.
 */
typedef enum
{
  STATE_APP_START,
  STATE_APP_CONN_VPP,
  STATE_APP_ENABLED,
  STATE_APP_ATTACHED,
} app_state_t;

typedef enum
{
  STATE_START = 0x01,
  STATE_CONNECT = 0x02,
  STATE_LISTEN = 0x04,
  STATE_ACCEPT = 0x08,
  STATE_CLOSE_ON_EMPTY = 0x10,
  STATE_DISCONNECT = 0x20,
  STATE_FAILED = 0x40
} session_state_t;

#define SERVER_STATE_OPEN  (STATE_ACCEPT|STATE_CLOSE_ON_EMPTY)
#define CLIENT_STATE_OPEN  (STATE_CONNECT|STATE_CLOSE_ON_EMPTY)
#define STATE_OPEN (SERVER_STATE_OPEN | CLIENT_STATE_OPEN)

typedef struct epoll_event vppcom_epoll_event_t;

typedef struct
{
  u32 next_sid;
  u32 prev_sid;
  u32 vep_idx;
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

typedef struct vcl_session_msg
{
  u32 next;
  union
  {
    session_accepted_msg_t accepted_msg;
  };
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

typedef struct
{
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

  /* Socket configuration state */
  u8 is_vep;
  u8 is_vep_session;
  u32 attr;
  u32 wait_cont_idx;
  vppcom_epoll_t vep;
  int libc_epfd;
  svm_msg_q_t *our_evt_q;
  u64 options[16];
  vce_event_handler_reg_t *poll_reg;
  vcl_session_msg_t *accept_evts_fifo;
#if VCL_ELOG
  elog_track_t elog_track;
#endif
} vcl_session_t;

typedef struct vppcom_cfg_t_
{
  u64 heapsize;
  u32 vpp_api_q_length;
  u64 segment_baseva;
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

typedef struct vppcom_main_t_
{
  u8 init;
  u32 debug;
  int main_cpu;

  /* FIFO for accepted connections - used in epoll/select */
  clib_spinlock_t session_fifo_lockp;
  u32 *client_session_index_fifo;

  /* vpp input queue */
  svm_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;
  /* Session pool */
  clib_spinlock_t sessions_lockp;
  vcl_session_t *sessions;

  /** Message queues epoll fd. Initialized only if using mqs with eventfds */
  int mqs_epfd;

  /** Pool of event message queue event connections */
  vcl_mq_evt_conn_t *mq_evt_conns;

  /** Per worker buffer for receiving mq epoll events */
  struct epoll_event *mq_events;

  /* Hash table for disconnect processing */
  uword *session_index_by_vpp_handles;

  /* Select bitmaps */
  clib_bitmap_t *rd_bitmap;
  clib_bitmap_t *wr_bitmap;
  clib_bitmap_t *ex_bitmap;

  /* Our event queue */
  svm_msg_q_t *app_event_queue;

  svm_msg_q_t **vpp_event_queues;

  /* unique segment name counter */
  u32 unique_segment_index;

  /* For deadman timers */
  clib_time_t clib_time;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile app_state_t app_state;

  vppcom_cfg_t cfg;

  /* Event thread */
  vce_event_thread_t event_thread;

  /* IO thread */
  vppcom_session_io_thread_t session_io_thread;

  /* pool of ctrl msgs */
  vcl_session_msg_t *ctrl_evt_pool;

  /** Pool of cut through registrations */
  vcl_cut_through_registration_t *cut_through_registrations;

  /** Lock for accessing ct registration pool */
  clib_spinlock_t ct_registration_lock;

  /** Cut-through registration by mq address hash table */
  uword *ct_registration_by_mq;

  svm_msg_q_msg_t *mq_msg_vector;

  /** Flag indicating that a new segment is being mounted */
  volatile u32 mounting_segment;

#ifdef VCL_ELOG
  /* VPP Event-logger */
  elog_main_t elog_main;
  elog_track_t elog_track;
#endif

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;
} vppcom_main_t;

extern vppcom_main_t *vcm;

#define VCL_SESSION_LOCK_AND_GET(I, S)                          \
do {                                                            \
  clib_spinlock_lock (&vcm->sessions_lockp);                    \
  rv = vppcom_session_at_index (I, S);                          \
  if (PREDICT_FALSE (rv))                                       \
    {                                                           \
      clib_spinlock_unlock (&vcm->sessions_lockp);              \
      clib_warning ("VCL<%d>: ERROR: Invalid ##I (%u)!",        \
                    getpid (), I);                              \
      goto done;                                                \
    }                                                           \
} while (0)

#define VCL_SESSION_LOCK() clib_spinlock_lock (&(vcm->sessions_lockp))
#define VCL_SESSION_UNLOCK() clib_spinlock_unlock (&(vcm->sessions_lockp))

#define VCL_IO_SESSIONS_LOCK() \
  clib_spinlock_lock (&(vcm->session_io_thread.io_sessions_lockp))
#define VCL_IO_SESSIONS_UNLOCK() \
  clib_spinlock_unlock (&(vcm->session_io_thread.io_sessions_lockp))

#define VCL_ACCEPT_FIFO_LOCK() clib_spinlock_lock (&(vcm->session_fifo_lockp))
#define VCL_ACCEPT_FIFO_UNLOCK() \
  clib_spinlock_unlock (&(vcm->session_fifo_lockp))

#define VCL_EVENTS_LOCK() \
  clib_spinlock_lock (&(vcm->event_thread.events_lockp))
#define VCL_EVENTS_UNLOCK() \
  clib_spinlock_unlock (&(vcm->event_thread.events_lockp))

#define VCL_INVALID_SESSION_INDEX ((u32)~0)

static inline vcl_session_t *
vcl_session_alloc (void)
{
  vcl_session_t *s;
  pool_get (vcm->sessions, s);
  memset (s, 0, sizeof (*s));
  return s;
}

static inline void
vcl_session_free (vcl_session_t * s)
{
  pool_put (vcm->sessions, s);
}

static inline vcl_session_t *
vcl_session_get (u32 session_index)
{
  if (pool_is_free_index (vcm->sessions, session_index))
    return 0;
  return pool_elt_at_index (vcm->sessions, session_index);
}

static inline u32
vcl_session_index (vcl_session_t * s)
{
  return (s - vcm->sessions);
}

static inline vcl_session_t *
vcl_session_get_w_handle (u64 handle)
{
  uword *p;
  if ((p = hash_get (vcm->session_index_by_vpp_handles, handle)))
    return vcl_session_get ((u32) p[0]);
  return 0;
}

static inline u32
vcl_session_get_index_from_handle (u64 handle)
{
  uword *p;
  if ((p = hash_get (vcm->session_index_by_vpp_handles, handle)))
    return p[0];
  return VCL_INVALID_SESSION_INDEX;
}

static inline u8
vcl_session_is_ct (vcl_session_t * s)
{
  return (s->our_evt_q != 0);
}

static inline int
vppcom_session_at_index (u32 session_index, vcl_session_t * volatile *sess)
{
  /* Assumes that caller has acquired spinlock: vcm->sessions_lockp */
  if (PREDICT_FALSE ((session_index == ~0) ||
		     pool_is_free_index (vcm->sessions, session_index)))
    {
      clib_warning ("VCL<%d>: invalid session, sid (%u) has been closed!",
		    getpid (), session_index);
      return VPPCOM_EBADFD;
    }
  *sess = pool_elt_at_index (vcm->sessions, session_index);
  return VPPCOM_OK;
}

static inline void
vppcom_session_table_add_listener (u64 listener_handle, u32 value)
{
  /* Session and listener handles have different formats. The latter has
   * the thread index in the upper 32 bits while the former has the session
   * type. Knowing that, for listeners we just flip the MSB to 1 */
  listener_handle |= 1ULL << 63;
  hash_set (vcm->session_index_by_vpp_handles, listener_handle, value);
}

static inline vcl_session_t *
vppcom_session_table_lookup_listener (u64 listener_handle)
{
  uword *p;
  u64 handle = listener_handle | (1ULL << 63);
  vcl_session_t *session;

  p = hash_get (vcm->session_index_by_vpp_handles, handle);
  if (!p)
    {
      clib_warning ("VCL<%d>: couldn't find listen session: unknown vpp "
		    "listener handle %llx", getpid (), listener_handle);
      return 0;
    }
  if (pool_is_free_index (vcm->sessions, p[0]))
    {
      VDBG (1, "VCL<%d>: invalid listen session, sid (%u)", getpid (), p[0]);
      return 0;
    }

  session = pool_elt_at_index (vcm->sessions, p[0]);
  ASSERT (session->session_state & STATE_LISTEN);
  return session;
}

const char *vppcom_session_state_str (session_state_t state);

/*
 * Helpers
 */
vcl_cut_through_registration_t *vcl_ct_registration_lock_and_alloc (void);
void vcl_ct_registration_del (vcl_cut_through_registration_t * ctr);
u32 vcl_ct_registration_index (vcl_cut_through_registration_t * ctr);
void vcl_ct_registration_unlock (void);
vcl_cut_through_registration_t *vcl_ct_registration_get (u32 ctr_index);
vcl_cut_through_registration_t *vcl_ct_registration_lock_and_lookup (uword);
void vcl_ct_registration_lookup_add (uword mq_addr, u32 ctr_index);
void vcl_ct_registration_lookup_del (uword mq_addr);
vcl_mq_evt_conn_t *vcl_mq_evt_conn_alloc (void);
u32 vcl_mq_evt_conn_index (vcl_mq_evt_conn_t * mqc);
vcl_mq_evt_conn_t *vcl_mq_evt_conn_get (u32 mq_conn_idx);
int vcl_mq_epoll_add_evfd (svm_msg_q_t * mq);
int vcl_mq_epoll_del_evfd (u32 mqc_index);

/*
 * VCL Binary API
 */
int vppcom_connect_to_vpp (char *app_name);
void vppcom_init_error_string_table (void);
void vppcom_send_session_enable_disable (u8 is_enable);
void vppcom_app_send_attach (void);
void vppcom_app_send_detach (void);
void vppcom_send_connect_sock (vcl_session_t * session, u32 session_index);
void vppcom_send_disconnect_session_reply (u64 vpp_handle, u32 session_index,
					   int rv);
void vppcom_send_disconnect_session (u64 vpp_handle, u32 session_index);
void vppcom_send_bind_sock (vcl_session_t * session, u32 session_index);
void vppcom_send_unbind_sock (u64 vpp_handle);
void vppcom_api_hookup (void);
void vppcom_send_accept_session_reply (u64 handle, u32 context, int retval);

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
