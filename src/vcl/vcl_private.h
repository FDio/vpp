/*
 * Copyright (c) 2018-2019 Cisco and/or its affiliates.
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
#define VCL_EP_SAPIFD_EVT ((u32) ~0)
#define VCL_EP_PIPEFD_EVT ((u32) (~0 - 1))

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
  STATE_APP_ADDING_TLS_DATA,
  STATE_APP_FAILED,
  STATE_APP_READY
} vcl_bapi_app_state_t;

typedef enum vcl_session_state_
{
  VCL_STATE_CLOSED,
  VCL_STATE_LISTEN,
  VCL_STATE_READY,
  VCL_STATE_VPP_CLOSING,
  VCL_STATE_DISCONNECT,
  VCL_STATE_DETACHED,
  VCL_STATE_UPDATED,
} vcl_session_state_t;

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
  u32 lt_next;
  u32 lt_prev;
} vppcom_epoll_t;

/* Select uses the vcl_si_set as if a clib_bitmap. Make sure they are the
 * same size */
STATIC_ASSERT (sizeof (clib_bitmap_t) == sizeof (vcl_si_set),
	       "vppcom bitmap size mismatch");

typedef struct
{
  u8 is_ip4;
  ip46_address_t ip46;
} vppcom_ip46_t;

#define VCL_ACCEPTED_F_CLOSED 	(1 << 0)
#define VCL_ACCEPTED_F_RESET 	(1 << 1)

typedef struct vcl_session_msg
{
  union
  {
    session_accepted_msg_t accepted_msg;
  };
  u32 flags;
} vcl_session_msg_t;

typedef enum
{
  VCL_SESS_ATTR_SERVER,
  VCL_SESS_ATTR_CUT_THRU,
  VCL_SESS_ATTR_VEP,
  VCL_SESS_ATTR_VEP_SESSION,
  VCL_SESS_ATTR_LISTEN,	       // SOL_SOCKET,SO_ACCEPTCONN
  VCL_SESS_ATTR_NONBLOCK,      // fcntl,O_NONBLOCK
  VCL_SESS_ATTR_REUSEADDR,     // SOL_SOCKET,SO_REUSEADDR
  VCL_SESS_ATTR_REUSEPORT,     // SOL_SOCKET,SO_REUSEPORT
  VCL_SESS_ATTR_BROADCAST,     // SOL_SOCKET,SO_BROADCAST
  VCL_SESS_ATTR_V6ONLY,	       // SOL_TCP,IPV6_V6ONLY
  VCL_SESS_ATTR_KEEPALIVE,     // SOL_SOCKET,SO_KEEPALIVE
  VCL_SESS_ATTR_TCP_NODELAY,   // SOL_TCP,TCP_NODELAY
  VCL_SESS_ATTR_TCP_KEEPIDLE,  // SOL_TCP,TCP_KEEPIDLE
  VCL_SESS_ATTR_TCP_KEEPINTVL, // SOL_TCP,TCP_KEEPINTVL
  VCL_SESS_ATTR_IP_PKTINFO,    /* IPPROTO_IP, IP_PKTINFO */
  VCL_SESS_ATTR_MAX
} vppcom_session_attr_t;

typedef enum vcl_session_flags_
{
  VCL_SESSION_F_CONNECTED = 1 << 0,
  VCL_SESSION_F_IS_VEP = 1 << 1,
  VCL_SESSION_F_IS_VEP_SESSION = 1 << 2,
  VCL_SESSION_F_HAS_RX_EVT = 1 << 3,
  VCL_SESSION_F_RD_SHUTDOWN = 1 << 4,
  VCL_SESSION_F_WR_SHUTDOWN = 1 << 5,
  VCL_SESSION_F_PENDING_DISCONNECT = 1 << 6,
  VCL_SESSION_F_PENDING_FREE = 1 << 7,
  VCL_SESSION_F_PENDING_LISTEN = 1 << 8,
  VCL_SESSION_F_APP_CLOSING = 1 << 9,
  VCL_SESSION_F_LISTEN_NO_MQ = 1 << 10,
} __clib_packed vcl_session_flags_t;

typedef enum vcl_worker_wait_
{
  VCL_WRK_WAIT_CTRL,
  VCL_WRK_WAIT_IO_RX,
  VCL_WRK_WAIT_IO_TX,
} vcl_worker_wait_type_t;

typedef struct vcl_session_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

#define _(type, name) type name;
  foreach_app_session_field
#undef _
  vcl_session_flags_t flags;	/**< see @ref vcl_session_flags_t */
  u32 rx_bytes_pending;		/**< bytes rx-ed as segs but not yet freed */

  svm_fifo_t *ct_rx_fifo;
  svm_fifo_t *ct_tx_fifo;
  vcl_session_msg_t *accept_evts_fifo;

  session_handle_t vpp_handle;
  session_handle_t parent_handle;
  u32 listener_index;		/**< index of parent listener (if any) */
  int n_accepted_sessions;	/**< sessions accepted by this listener */
  vppcom_epoll_t vep;		/**< epoll context */
  u32 attributes;		/**< see @ref vppcom_session_attr_t */
  u32 vrf;
  u16 gso_size;

  u32 sndbuf_size;		// VPP-TBD: Hack until support setsockopt(SO_SNDBUF)
  u32 rcvbuf_size;		// VPP-TBD: Hack until support setsockopt(SO_RCVBUF)

  transport_endpt_ext_cfg_t *ext_config;
  u8 dscp;

  i32 vpp_error;

#if (VCL_ELOG > 0)
  elog_track_t elog_track;
#endif

  transport_endpt_attr_t *tep_attrs; /**< vector of attributes */
} vcl_session_t;

/* vppcom_cfg_t is now defined in vppcom.h public header */

/* Internal VCL configuration structure with VPP types and char* strings */
typedef struct vcl_cfg_t_
{
  uword heapsize;
  u32 max_workers;
  uword segment_baseva;
  uword segment_size;
  uword add_segment_size;
  u32 preallocated_fifo_pairs;
  u32 rx_fifo_size;
  u32 tx_fifo_size;
  u32 event_queue_size;
  u8 app_proxy_transport_tcp;
  u8 app_proxy_transport_udp;
  u8 app_scope_local;
  u8 app_scope_global;
  u8 *namespace_id; /**< namespace id string */
  u64 namespace_secret;
  u8 use_mq_eventfd;
  f64 app_timeout;
  f64 session_timeout;
  char *event_log_path;
  u8 *vpp_app_socket_api;   /**< app socket api socket file name */
  u8 *vpp_bapi_socket_name; /**< bapi socket transport socket name */
  u32 tls_engine;
  u8 mt_wrk_supported;
  u8 huge_page;
  u8 app_original_dst;
} vcl_cfg_t;

void vppcom_cfg (vcl_cfg_t *vcl_cfg);
void vppcom_cfg_init (vcl_cfg_t *vcl_cfg);
void vcl_cfg_parse_heapsize (char *conf_fname);

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

typedef void (*vcl_worker_wait_mq_fn) (u32 vcl_sh);
typedef struct vcl_worker_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Session pool */
  vcl_session_t *sessions;

  /** Worker/thread index in current process */
  u32 wrk_index;

  /** Worker index in vpp*/
  u32 vpp_wrk_index;

  /**
   * Generic api client handle. When binary api is in used, it stores
   * the "client_index" and when socket api is use, it stores the sapi
   * client handle */
  u32 api_client_handle;

  /** VPP binary api input queue */
  svm_queue_t *vl_input_queue;

  /** VPP mq to be used for exchanging control messages */
  svm_msg_q_t *ctrl_mq;

  /** Message queues epoll fd. Initialized only if using mqs with eventfds */
  int mqs_epfd;

  /** Pool of event message queue event connections */
  vcl_mq_evt_conn_t *mq_evt_conns;

  /** Per worker buffer for receiving mq epoll events */
  struct epoll_event *mq_events;

  /** Next session to be lt polled */
  u32 ep_lt_current;

  /** Hash table for disconnect processing */
  uword *session_index_by_vpp_handles;

  /** Select bitmaps */
  clib_bitmap_t *rd_bitmap;
  clib_bitmap_t *wr_bitmap;
  clib_bitmap_t *ex_bitmap;

  /** Our event message queue */
  svm_msg_q_t *app_event_queue;

  /** For deadman timers */
  clib_time_t clib_time;

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

  clib_socket_t app_api_sock;
  socket_client_main_t bapi_sock_ctx;
  api_main_t bapi_api_ctx;
  memory_client_main_t bapi_mem_ctx;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile vcl_bapi_app_state_t bapi_app_state;
  volatile uword bapi_return;

  u8 session_attr_op;
  int session_attr_op_rv;
  transport_endpt_attr_t session_attr_rv;

  volatile int rpc_done;

  /* functions to be called pre/post wait if vcl managed by vls */
  vcl_worker_wait_mq_fn pre_wait_fn;
  vcl_worker_wait_mq_fn post_wait_fn;

  /* mq_epfd signal pipes when wrk detached from vpp */
  int detached_pipefds[2];
} vcl_worker_t;

STATIC_ASSERT (sizeof (session_disconnected_msg_t) <= 16,
	       "disconnected must fit in session_event_t");
STATIC_ASSERT (sizeof (session_reset_msg_t) <= 16,
	       "disconnected must fit in session_event_t");

typedef void (vcl_rpc_fn_t) (void *args);

typedef struct vppcom_main_t_
{
  u8 is_init;
  u32 debug;
  pthread_t main_cpu;

  /** Main process pid */
  pid_t main_pid;

  /** App's index in vpp. It's used by vpp to identify the app */
  u32 app_index;

  u8 *app_name;

  /** VCL configuration */
  vcl_cfg_t cfg;

  volatile u32 forking;

  /** Workers */
  vcl_worker_t *workers;

  /** Lock to protect worker registrations */
  clib_spinlock_t workers_lock;

  /** Lock to protect segment hash table */
  clib_rwlock_t segment_table_lock;

  /** Mapped segments table */
  uword *segment_table;

  /** Control mq obtained from attach */
  svm_msg_q_t *ctrl_mq;

  fifo_segment_main_t segment_main;

  vcl_rpc_fn_t *wrk_rpc_fn;

  /*
   * Pointers to libc epoll fns to avoid loops when ldp is on
   */
  int (*vcl_epoll_create1) (int flags);
  int (*vcl_epoll_ctl) (int epfd, int op, int fd, struct epoll_event *event);
  int (*vcl_epoll_wait) (int epfd, struct epoll_event *events, int maxevents,
			 int timeout);

  clib_spinlock_t reattach_lock;
  /** Counter to determine order of execution of `vcl_api_retry_attach`
   * function by multiple workers */
  int reattach_count;

  /*
   * Binary api context
   */

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;

#if (VCL_ELOG > 0)
  /* VPP Event-logger */
  elog_main_t elog_main;
  elog_track_t elog_track;
#endif

} vppcom_main_t;

extern vppcom_main_t *vcm;
extern vppcom_main_t _vppcom_main;

#define VCL_INVALID_SESSION_INDEX ((u32)~0)
#define VCL_INVALID_SESSION_HANDLE ((u64)~0)
#define VCL_INVALID_SEGMENT_INDEX ((u32)~0)
#define VCL_INVALID_SEGMENT_HANDLE ((u64)~0)

void vcl_session_detach_fifos (vcl_session_t *s);

static inline vcl_session_t *
vcl_session_alloc (vcl_worker_t * wrk)
{
  vcl_session_t *s;
  pool_get (wrk->sessions, s);
  memset (s, 0, sizeof (*s));
  s->session_index = s - wrk->sessions;
  s->listener_index = VCL_INVALID_SESSION_INDEX;
  return s;
}

static inline void
vcl_session_free (vcl_worker_t * wrk, vcl_session_t * s)
{
  /* Debug level set to 1 to avoid debug messages while ldp is cleaning up */
  VDBG (1, "session %u [0x%llx] removed", s->session_index, s->vpp_handle);
  vcl_session_detach_fifos (s);
  if (s->ext_config)
    clib_mem_free (s->ext_config);
  vec_free (s->tep_attrs);
  pool_put (wrk->sessions, s);
}

static inline vcl_session_t *
vcl_session_get (vcl_worker_t * wrk, u32 session_index)
{
  if (pool_is_free_index (wrk->sessions, session_index))
    return 0;
  return pool_elt_at_index (wrk->sessions, session_index);
}

static inline vcl_session_handle_t
vcl_session_handle_from_wrk_session_index (u32 session_index, u32 wrk_index)
{
  ASSERT (session_index < 2 << 24);
  return (wrk_index << 24 | session_index);
}

static inline vcl_session_handle_t
vcl_session_handle_from_index (u32 session_index)
{
  ASSERT (session_index < 2 << 24);
  return (vcl_get_worker_index () << 24 | session_index);
}

static inline vcl_session_handle_t
vcl_session_handle (vcl_session_t * s)
{
  return vcl_session_handle_from_index (s->session_index);
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
  hash_set (wrk->session_index_by_vpp_handles, listener_handle, value);
}

static inline void
vcl_session_table_del_listener (vcl_worker_t * wrk, u64 listener_handle)
{
  hash_unset (wrk->session_index_by_vpp_handles, listener_handle);
}

static inline int
vcl_session_is_connectable_listener (vcl_worker_t * wrk,
				     vcl_session_t * session)
{
  /* Tell if we session_handle is a QUIC session.
   * We can be in the following cases :
   * Listen session <- QUIC session <- Stream session
   * QUIC session <- Stream session
   */
  vcl_session_t *ls;
  if (session->session_type != VPPCOM_PROTO_QUIC)
    return 0;
  if (session->listener_index == VCL_INVALID_SESSION_INDEX)
    return !(session->session_state == VCL_STATE_LISTEN);
  ls = vcl_session_get_w_handle (wrk, session->listener_index);
  if (!ls)
    return VPPCOM_EBADFD;
  return ls->session_state == VCL_STATE_LISTEN;
}

static inline vcl_session_t *
vcl_session_table_lookup_listener (vcl_worker_t * wrk, u64 handle)
{
  uword *p;
  vcl_session_t *s;

  p = hash_get (wrk->session_index_by_vpp_handles, handle);
  if (!p)
    {
      VDBG (0, "could not find listen session: unknown vpp listener handle"
	    " %llx", handle);
      return 0;
    }
  s = vcl_session_get (wrk, p[0]);
  if (!s)
    {
      VDBG (1, "invalid listen session index (%u)", p[0]);
      return 0;
    }

  if (s->session_state == VCL_STATE_DISCONNECT)
    {
      VDBG (0, "listen session [0x%llx] is closing", s->vpp_handle);
      return 0;
    }

  ASSERT (s->session_state == VCL_STATE_LISTEN ||
	  vcl_session_is_connectable_listener (wrk, s));
  return s;
}

static inline u8
vcl_session_is_ct (vcl_session_t * s)
{
  return (s->ct_tx_fifo != 0);
}

static inline u8
vcl_session_is_cl (vcl_session_t * s)
{
  if (s->session_type == VPPCOM_PROTO_UDP)
    return !(s->flags & VCL_SESSION_F_CONNECTED);
  return 0;
}

static inline u8
vcl_session_has_crypto (vcl_session_t *s)
{
  return (s->session_type == VPPCOM_PROTO_TLS ||
	  s->session_type == VPPCOM_PROTO_QUIC ||
	  s->session_type == VPPCOM_PROTO_DTLS);
}

static inline u8
vcl_session_is_ready (vcl_session_t * s)
{
  return (s->session_state == VCL_STATE_READY
	  || s->session_state == VCL_STATE_VPP_CLOSING);
}

static inline u8
vcl_session_is_open (vcl_session_t * s)
{
  return ((vcl_session_is_ready (s))
	  || (s->session_state == VCL_STATE_LISTEN && vcl_session_is_cl (s)));
}

static inline u8
vcl_session_is_closing (vcl_session_t * s)
{
  return (s->session_state == VCL_STATE_VPP_CLOSING
	  || s->session_state == VCL_STATE_DISCONNECT);
}

static inline u8
vcl_session_is_closed (vcl_session_t * s)
{
  return (!s || (s->session_state == VCL_STATE_CLOSED));
}

static inline int
vcl_session_closing_error (vcl_session_t * s)
{
  /* Return 0 on closing sockets */
  return s->session_state == VCL_STATE_DISCONNECT ? VPPCOM_ECONNRESET : 0;
}

static inline int
vcl_session_closed_error (vcl_session_t * s)
{
  return s->session_state == VCL_STATE_DISCONNECT
    ? VPPCOM_ECONNRESET : VPPCOM_ENOTCONN;
}

static inline void
vcl_ip_copy_from_ep (ip46_address_t * ip, vppcom_endpt_t * ep)
{
  if (ep->is_ip4)
    clib_memcpy_fast (&ip->ip4, ep->ip, sizeof (ip4_address_t));
  else
    clib_memcpy_fast (&ip->ip6, ep->ip, sizeof (ip6_address_t));
}

static inline void
vcl_ip_copy_to_ep (ip46_address_t * ip, vppcom_endpt_t * ep, u8 is_ip4)
{
  ep->is_ip4 = is_ip4;
  if (is_ip4)
    clib_memcpy_fast (ep->ip, &ip->ip4, sizeof (ip4_address_t));
  else
    clib_memcpy_fast (ep->ip, &ip->ip6, sizeof (ip6_address_t));
}

static inline int
vcl_proto_is_dgram (uint8_t proto)
{
  return proto == VPPCOM_PROTO_UDP || proto == VPPCOM_PROTO_DTLS ||
	 proto == VPPCOM_PROTO_SRTP;
}

static inline u8
vcl_session_has_attr (vcl_session_t * s, u8 attr)
{
  return (s->attributes & (1 << attr)) ? 1 : 0;
}

static inline void
vcl_session_set_attr (vcl_session_t * s, u8 attr)
{
  s->attributes |= 1 << attr;
}

static inline void
vcl_session_clear_attr (vcl_session_t * s, u8 attr)
{
  s->attributes &= ~(1 << attr);
}

static inline transport_endpt_attr_t *
vcl_session_tep_attr_get (vcl_session_t *s, transport_endpt_attr_type_t at)
{
  transport_endpt_attr_t *tepa;
  vec_foreach (tepa, s->tep_attrs)
    {
      if (tepa->type == at)
	return tepa;
    }
  return 0;
}

static inline session_evt_type_t
vcl_session_dgram_tx_evt (vcl_session_t *s, session_evt_type_t et)
{
  return (s->flags & VCL_SESSION_F_CONNECTED) ? et : SESSION_IO_EVT_TX_MAIN;
}

static inline void
vcl_session_add_want_deq_ntf (vcl_session_t *s, svm_fifo_deq_ntf_t evt)
{
  svm_fifo_t *txf = vcl_session_is_ct (s) ? s->ct_tx_fifo : s->tx_fifo;
  if (txf)
    {
      svm_fifo_add_want_deq_ntf (txf, evt);
      /* Request tx notification only if 3% of fifo is empty */
      svm_fifo_set_deq_thresh (txf, 0.03 * svm_fifo_size (txf));
    }
}

static inline void
vcl_session_del_want_deq_ntf (vcl_session_t *s, svm_fifo_deq_ntf_t evt)
{
  svm_fifo_t *txf = vcl_session_is_ct (s) ? s->ct_tx_fifo : s->tx_fifo;
  if (txf)
    svm_fifo_del_want_deq_ntf (txf, evt);
}

/*
 * Helpers
 */
vcl_mq_evt_conn_t *vcl_mq_evt_conn_alloc (vcl_worker_t * wrk);
u32 vcl_mq_evt_conn_index (vcl_worker_t * wrk, vcl_mq_evt_conn_t * mqc);
vcl_mq_evt_conn_t *vcl_mq_evt_conn_get (vcl_worker_t * wrk, u32 mq_conn_idx);
int vcl_mq_epoll_add_evfd (vcl_worker_t * wrk, svm_msg_q_t * mq);
int vcl_mq_epoll_del_evfd (vcl_worker_t * wrk, u32 mqc_index);

vcl_worker_t *vcl_worker_alloc_and_init (void);
void vcl_worker_cleanup (vcl_worker_t * wrk, u8 notify_vpp);
int vcl_worker_register_with_vpp (void);
svm_msg_q_t *vcl_worker_ctrl_mq (vcl_worker_t * wrk);

void vcl_flush_mq_events (void);
int vcl_session_cleanup (vcl_worker_t * wrk, vcl_session_t * session,
			 vcl_session_handle_t sh, u8 do_disconnect);

void vcl_segment_table_add (u64 segment_handle, u32 svm_segment_index);
u32 vcl_segment_table_lookup (u64 segment_handle);
void vcl_segment_table_del (u64 segment_handle);

int vcl_session_read_ready (vcl_session_t * session);
int vcl_session_read_ready2 (vcl_session_t *s);
int vcl_session_write_ready (vcl_session_t * session);
int vcl_session_alloc_ext_cfg (vcl_session_t *s,
			       transport_endpt_ext_cfg_type_t type, u32 len);

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

static inline u8
vcl_n_workers (void)
{
  return pool_elts (vcm->workers);
}

static inline u64
vcl_vpp_worker_segment_handle (u32 wrk_index)
{
  return (VCL_INVALID_SEGMENT_HANDLE - wrk_index - 1);
}

void vcl_send_session_worker_update (vcl_worker_t * wrk, vcl_session_t * s,
				     u32 wrk_index);
int vcl_send_worker_rpc (u32 dst_wrk_index, void *data, u32 data_len);

int vcl_segment_attach (u64 segment_handle, char *name,
			ssvm_segment_type_t type, int fd);
void vcl_segment_detach (u64 segment_handle);
void vcl_segment_detach_segments (u32 *seg_indices);
void vcl_send_session_listen (vcl_worker_t *wrk, vcl_session_t *s);
void vcl_send_session_unlisten (vcl_worker_t * wrk, vcl_session_t * s);

int vcl_segment_attach_session (uword segment_handle, uword rxf_offset,
				uword txf_offset, uword mq_offset,
				u32 mq_index, u8 is_ct, vcl_session_t *s);
int vcl_segment_attach_mq (uword segment_handle, uword mq_offset, u32 mq_index,
			   svm_msg_q_t **mq);
int vcl_segment_discover_mqs (uword segment_handle, int *fds, u32 n_fds);
svm_fifo_chunk_t *vcl_segment_alloc_chunk (uword segment_handle,
					   u32 slice_index, u32 size,
					   uword *offset);
int vcl_session_share_fifos (vcl_session_t *s, svm_fifo_t *rxf,
			     svm_fifo_t *txf);
void vcl_worker_detach_sessions (vcl_worker_t *wrk);
void vcl_worker_set_wait_mq_fns (vcl_worker_wait_mq_fn pre_wait,
				 vcl_worker_wait_mq_fn post_wait);

void vcl_worker_detached_start_signal_mq (vcl_worker_t *wrk);
void vcl_worker_detached_signal_mq (vcl_worker_t *wrk);
void vcl_worker_detached_stop_signal_mq (vcl_worker_t *wrk);

void vcl_init_epoll_fns (void);

/*
 * VCL Binary API
 */
#if defined(VCL_BAPI_ENABLED)
int vcl_bapi_attach (void);
int vcl_bapi_app_worker_add (void);
void vcl_bapi_app_worker_del (vcl_worker_t * wrk);
void vcl_bapi_disconnect_from_vpp (void);
int vcl_bapi_recv_fds (vcl_worker_t * wrk, int *fds, int n_fds);
int vcl_bapi_add_cert_key_pair (vppcom_cert_key_pair_t *ckpair);
int vcl_bapi_del_cert_key_pair (u32 ckpair_index);
u32 vcl_bapi_max_nsid_len (void);
int vcl_bapi_worker_set (void);
#endif

/*
 * VCL Socket API
 */
int vcl_sapi_attach (void);
int vcl_sapi_app_worker_add (void);
void vcl_sapi_app_worker_del (vcl_worker_t * wrk);
void vcl_sapi_detach (vcl_worker_t * wrk);
int vcl_sapi_recv_fds (vcl_worker_t * wrk, int *fds, int n_fds);
int vcl_sapi_add_cert_key_pair (vppcom_cert_key_pair_t *ckpair);
int vcl_sapi_del_cert_key_pair (u32 ckpair_index);

static inline int
vcl_api_attach (void)
{
  if (vcm->cfg.vpp_app_socket_api)
    return vcl_sapi_attach ();
#if VCL_BAPI_ENABLED
  return vcl_bapi_attach ();
#else
  return -1;
#endif
}

static inline int
vcl_api_recv_fd (vcl_worker_t *wrk, int *fds, int n_fds)
{
  if (vcm->cfg.vpp_app_socket_api)
    return vcl_sapi_recv_fds (wrk, fds, n_fds);

#if VCL_BAPI_ENABLED
  return vcl_bapi_recv_fds (wrk, fds, n_fds);
#else
  return -1;
#endif
}

static inline void
vcl_api_detach (vcl_worker_t *wrk)
{
  if (vcm->cfg.vpp_app_socket_api)
    return vcl_sapi_detach (wrk);

#if VCL_BAPI_ENABLED
  vcl_bapi_disconnect_from_vpp ();
#endif
}

static inline int
vcl_api_add_cert_key_pair (vppcom_cert_key_pair_t *ckpair)
{
  if (vcm->cfg.vpp_app_socket_api)
    return vcl_sapi_add_cert_key_pair (ckpair);

#if VCL_BAPI_ENABLED
  return vcl_bapi_add_cert_key_pair (ckpair);
#else
  return -1;
#endif
}

static inline int
vcl_api_app_worker_add (void)
{
  if (vcm->cfg.vpp_app_socket_api)
    return vcl_sapi_app_worker_add ();

#if VCL_BAPI_ENABLED
  return vcl_bapi_app_worker_add ();
#else
  return -1;
#endif
}

static inline void
vcl_api_app_worker_del (vcl_worker_t *wrk)
{
  if (wrk->api_client_handle == ~0)
    return;

  if (vcm->cfg.vpp_app_socket_api)
    return vcl_sapi_app_worker_del (wrk);

#if VCL_BAPI_ENABLED
  vcl_bapi_app_worker_del (wrk);
#endif
}

static inline int
vcl_api_del_cert_key_pair (uint32_t ckpair_index)
{
  if (vcm->cfg.vpp_app_socket_api)
    return vcl_sapi_del_cert_key_pair (ckpair_index);

#if VCL_BAPI_ENABLED
  return vcl_bapi_del_cert_key_pair (ckpair_index);
#else
  return -1;
#endif
}

/*
 * Utility functions
 */
const char *vcl_session_state_str (vcl_session_state_t state);
u8 *vcl_format_ip4_address (u8 *s, va_list *args);
u8 *vcl_format_ip6_address (u8 *s, va_list *args);
u8 *vcl_format_ip46_address (u8 *s, va_list *args);

/*
 * Heap management
 */
void vcl_heap_alloc (void);

#endif /* SRC_VCL_VCL_PRIVATE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
