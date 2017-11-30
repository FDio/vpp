/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <svm/svm_fifo_segment.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>
#include <vnet/session/application_interface.h>
#include <vcl/vppcom.h>
#include <vlib/unix/unix.h>
#include <vppinfra/vec_bootstrap.h>

#define vl_typedefs		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

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

typedef struct
{
  volatile session_state_t state;

  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;
  u8 *segment_name;
  u32 sm_seg_index;
  u32 client_context;
  u64 vpp_handle;
  unix_shared_memory_queue_t *vpp_event_queue;

  /* Socket configuration state */
  /* TBD: covert 'is_*' vars to bit in u8 flags; */
  u8 is_server;
  u8 is_listen;
  u8 is_cut_thru;
  u8 is_nonblocking;
  u8 is_vep;
  u8 is_vep_session;
  u32 wait_cont_idx;
  vppcom_epoll_t vep;
  u32 vrf;
  vppcom_ip46_t lcl_addr;
  vppcom_ip46_t peer_addr;
  u16 lcl_port;			// network order
  u16 peer_port;		// network order
  u8 proto;
  u64 client_queue_address;
  u64 options[16];
} session_t;

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
  f64 app_timeout;
  f64 session_timeout;
  f64 accept_timeout;
} vppcom_cfg_t;

typedef struct vppcom_main_t_
{
  u8 init;
  u32 debug;
  u32 *client_session_index_fifo;
  int main_cpu;

  /* vpe input queue */
  unix_shared_memory_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  /* Session pool */
  clib_spinlock_t sessions_lockp;
  session_t *sessions;

  /* Hash table for disconnect processing */
  uword *session_index_by_vpp_handles;

  /* Select bitmaps */
  clib_bitmap_t *rd_bitmap;
  clib_bitmap_t *wr_bitmap;
  clib_bitmap_t *ex_bitmap;

  /* Our event queue */
  unix_shared_memory_queue_t *app_event_queue;

  /* unique segment name counter */
  u32 unique_segment_index;

  /* For deadman timers */
  clib_time_t clib_time;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile app_state_t app_state;

  vppcom_cfg_t cfg;

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;
} vppcom_main_t;

/* NOTE: _vppcom_main is only used until the heap is allocated.
 *       Do not access it directly -- use vcm which will point to
 *       the heap allocated copy after init.
 */
static vppcom_main_t _vppcom_main = {
  .debug = VPPCOM_DEBUG_INIT,
  .my_client_index = ~0
};

static vppcom_main_t *vcm = &_vppcom_main;

#define VCL_LOCK_AND_GET_SESSION(I, S)                  \
do {                                                    \
  clib_spinlock_lock (&vcm->sessions_lockp);            \
  rv = vppcom_session_at_index (I, S);                  \
  if (PREDICT_FALSE (rv))                               \
    {                                                   \
      clib_spinlock_unlock (&vcm->sessions_lockp);      \
      clib_warning ("[%s] ERROR: Invalid ##I (%u)!",    \
                    getpid (), I);                      \
      goto done;                                        \
    }                                                   \
} while (0)

static const char *
vppcom_app_state_str (app_state_t state)
{
  char *st;

  switch (state)
    {
    case STATE_APP_START:
      st = "STATE_APP_START";
      break;

    case STATE_APP_CONN_VPP:
      st = "STATE_APP_CONN_VPP";
      break;

    case STATE_APP_ENABLED:
      st = "STATE_APP_ENABLED";
      break;

    case STATE_APP_ATTACHED:
      st = "STATE_APP_ATTACHED";
      break;

    default:
      st = "UNKNOWN_APP_STATE";
      break;
    }

  return st;
}

static const char *
vppcom_session_state_str (session_state_t state)
{
  char *st;

  switch (state)
    {
    case STATE_START:
      st = "STATE_START";
      break;

    case STATE_CONNECT:
      st = "STATE_CONNECT";
      break;

    case STATE_LISTEN:
      st = "STATE_LISTEN";
      break;

    case STATE_ACCEPT:
      st = "STATE_ACCEPT";
      break;

    case STATE_CLOSE_ON_EMPTY:
      st = "STATE_CLOSE_ON_EMPTY";
      break;

    case STATE_DISCONNECT:
      st = "STATE_DISCONNECT";
      break;

    case STATE_FAILED:
      st = "STATE_FAILED";
      break;

    default:
      st = "UNKNOWN_STATE";
      break;
    }

  return st;
}

/*
 * VPPCOM Utility Functions
 */
static inline int
vppcom_session_at_index (u32 session_index, session_t * volatile *sess)
{
  /* Assumes that caller has acquired spinlock: vcm->sessions_lockp */
  if (PREDICT_FALSE ((session_index == ~0) ||
		     pool_is_free_index (vcm->sessions, session_index)))
    {
      clib_warning ("[%d] invalid session, sid (%u) has been closed!",
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

static inline session_t *
vppcom_session_table_lookup_listener (u64 listener_handle)
{
  uword *p;
  u64 handle = listener_handle | (1ULL << 63);
  session_t *session;

  p = hash_get (vcm->session_index_by_vpp_handles, handle);
  if (!p)
    {
      clib_warning ("[%d] couldn't find listen session: unknown vpp "
		    "listener handle %llx", getpid (), listener_handle);
      return 0;
    }
  if (pool_is_free_index (vcm->sessions, p[0]))
    {
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] invalid listen session, sid (%u)", getpid (),
		      p[0]);
      return 0;
    }

  session = pool_elt_at_index (vcm->sessions, p[0]);
  ASSERT (session->is_listen);
  return session;
}

static inline void
vppcom_session_table_del_listener (u64 listener_handle)
{
  listener_handle |= 1ULL << 63;
  hash_unset (vcm->session_index_by_vpp_handles, listener_handle);
}

static int
vppcom_connect_to_vpp (char *app_name)
{
  api_main_t *am = &api_main;

  if (VPPCOM_DEBUG > 0)
    printf ("\nConnecting to VPP api...");
  if (vl_client_connect_to_vlib ("/vpe-api", app_name,
				 vcm->cfg.vpp_api_q_length) < 0)
    {
      clib_warning ("[%d] connect to vpp (%s) failed!", getpid (), app_name);
      return VPPCOM_ECONNREFUSED;
    }

  vcm->vl_input_queue = am->shmem_hdr->vl_input_queue;
  vcm->my_client_index = am->my_client_index;
  if (VPPCOM_DEBUG > 0)
    printf (" connected!\n");

  vcm->app_state = STATE_APP_CONN_VPP;
  return VPPCOM_OK;
}

static u8 *
format_api_error (u8 * s, va_list * args)
{
  i32 error = va_arg (*args, u32);
  uword *p;

  p = hash_get (vcm->error_string_by_error_number, -error);

  if (p)
    s = format (s, "%s (%d)", p[0], error);
  else
    s = format (s, "%d", error);
  return s;
}

static void
vppcom_init_error_string_table (void)
{
  vcm->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n,v,s) hash_set (vcm->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (vcm->error_string_by_error_number, 99, "Misc");
}

static inline int
vppcom_wait_for_app_state_change (app_state_t app_state)
{
  f64 timeout = clib_time_now (&vcm->clib_time) + vcm->cfg.app_timeout;

  while (clib_time_now (&vcm->clib_time) < timeout)
    {
      if (vcm->app_state == app_state)
	return VPPCOM_OK;
    }
  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] timeout waiting for state %s (%d)", getpid (),
		  vppcom_app_state_str (app_state), app_state);
  return VPPCOM_ETIMEDOUT;
}

static inline int
vppcom_wait_for_session_state_change (u32 session_index,
				      session_state_t state,
				      f64 wait_for_time)
{
  f64 timeout = clib_time_now (&vcm->clib_time) + wait_for_time;
  session_t *volatile session;
  int rv;

  do
    {
      clib_spinlock_lock (&vcm->sessions_lockp);
      rv = vppcom_session_at_index (session_index, &session);
      if (PREDICT_FALSE (rv))
	{
	  clib_spinlock_unlock (&vcm->sessions_lockp);
	  return rv;
	}
      if (session->state == state)
	{
	  clib_spinlock_unlock (&vcm->sessions_lockp);
	  return VPPCOM_OK;
	}
      if (session->state == STATE_FAILED)
	{
	  clib_spinlock_unlock (&vcm->sessions_lockp);
	  return VPPCOM_ECONNREFUSED;
	}

      clib_spinlock_unlock (&vcm->sessions_lockp);
    }
  while (clib_time_now (&vcm->clib_time) < timeout);

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] timeout waiting for state 0x%x (%s)", getpid (),
		  state, vppcom_session_state_str (state));
  return VPPCOM_ETIMEDOUT;
}

static inline int
vppcom_wait_for_client_session_index (f64 wait_for_time)
{
  f64 timeout = clib_time_now (&vcm->clib_time) + wait_for_time;

  do
    {
      if (clib_fifo_elts (vcm->client_session_index_fifo))
	return VPPCOM_OK;
    }
  while (clib_time_now (&vcm->clib_time) < timeout);

  if (wait_for_time == 0)
    return VPPCOM_EAGAIN;

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] timeout waiting for client_session_index", getpid ());
  return VPPCOM_ETIMEDOUT;
}

/*
 * VPP-API message functions
 */
static void
vppcom_send_session_enable_disable (u8 is_enable)
{
  vl_api_session_enable_disable_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_SESSION_ENABLE_DISABLE);
  bmp->client_index = vcm->my_client_index;
  bmp->context = htonl (0xfeedface);
  bmp->is_enable = is_enable;
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & bmp);
}

static int
vppcom_app_session_enable (void)
{
  int rv;

  if (vcm->app_state != STATE_APP_ENABLED)
    {
      vppcom_send_session_enable_disable (1 /* is_enabled == TRUE */ );
      rv = vppcom_wait_for_app_state_change (STATE_APP_ENABLED);
      if (PREDICT_FALSE (rv))
	{
	  if (VPPCOM_DEBUG > 0)
	    clib_warning ("[%d] application session enable timed out! "
			  "returning %d (%s)",
			  getpid (), rv, vppcom_retval_str (rv));
	  return rv;
	}
    }
  return VPPCOM_OK;
}

static void
  vl_api_session_enable_disable_reply_t_handler
  (vl_api_session_enable_disable_reply_t * mp)
{
  if (mp->retval)
    {
      clib_warning ("[%d] session_enable_disable failed: %U", getpid (),
		    format_api_error, ntohl (mp->retval));
    }
  else
    vcm->app_state = STATE_APP_ENABLED;
}

static void
vppcom_app_send_attach (void)
{
  vl_api_application_attach_t *bmp;
  u8 nsid_len = vec_len (vcm->cfg.namespace_id);
  u8 app_is_proxy = (vcm->cfg.app_proxy_transport_tcp ||
		     vcm->cfg.app_proxy_transport_udp);

  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_ATTACH);
  bmp->client_index = vcm->my_client_index;
  bmp->context = htonl (0xfeedface);
  bmp->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_ACCEPT_REDIRECT | APP_OPTIONS_FLAGS_ADD_SEGMENT |
    (vcm->cfg.app_scope_local ? APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE : 0) |
    (vcm->cfg.app_scope_global ? APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE : 0) |
    (app_is_proxy ? APP_OPTIONS_FLAGS_IS_PROXY : 0);
  bmp->options[APP_OPTIONS_PROXY_TRANSPORT] =
    (vcm->cfg.app_proxy_transport_tcp ? 1 << TRANSPORT_PROTO_TCP : 0) |
    (vcm->cfg.app_proxy_transport_udp ? 1 << TRANSPORT_PROTO_UDP : 0);
  bmp->options[SESSION_OPTIONS_SEGMENT_SIZE] = vcm->cfg.segment_size;
  bmp->options[SESSION_OPTIONS_ADD_SEGMENT_SIZE] = vcm->cfg.add_segment_size;
  bmp->options[SESSION_OPTIONS_RX_FIFO_SIZE] = vcm->cfg.rx_fifo_size;
  bmp->options[SESSION_OPTIONS_TX_FIFO_SIZE] = vcm->cfg.tx_fifo_size;
  if (nsid_len)
    {
      bmp->namespace_id_len = nsid_len;
      clib_memcpy (bmp->namespace_id, vcm->cfg.namespace_id, nsid_len);
      bmp->options[APP_OPTIONS_NAMESPACE_SECRET] = vcm->cfg.namespace_secret;
    }
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & bmp);
}

static int
vppcom_app_attach (void)
{
  int rv;

  vppcom_app_send_attach ();
  rv = vppcom_wait_for_app_state_change (STATE_APP_ATTACHED);
  if (PREDICT_FALSE (rv))
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] application attach timed out! returning %d (%s)",
		      getpid (), rv, vppcom_retval_str (rv));
      return rv;
    }
  return VPPCOM_OK;
}

static void
vppcom_app_detach (void)
{
  vl_api_application_detach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_DETACH);
  bmp->client_index = vcm->my_client_index;
  bmp->context = htonl (0xfeedface);
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & bmp);
}

static void
vl_api_application_attach_reply_t_handler (vl_api_application_attach_reply_t *
					   mp)
{
  static svm_fifo_segment_create_args_t _a;
  svm_fifo_segment_create_args_t *a = &_a;
  int rv;

  memset (a, 0, sizeof (*a));
  if (mp->retval)
    {
      clib_warning ("[%d] attach failed: %U", getpid (),
		    format_api_error, ntohl (mp->retval));
      return;
    }

  if (mp->segment_name_length == 0)
    {
      clib_warning ("[%d] segment_name_length zero", getpid ());
      return;
    }

  a->segment_name = (char *) mp->segment_name;
  a->segment_size = mp->segment_size;

  ASSERT (mp->app_event_queue_address);

  /* Attach to the segment vpp created */
  rv = svm_fifo_segment_attach (a);
  vec_reset_length (a->new_segment_indices);
  if (PREDICT_FALSE (rv))
    {
      clib_warning ("[%d] svm_fifo_segment_attach ('%s') failed", getpid (),
		    mp->segment_name);
      return;
    }

  vcm->app_event_queue =
    uword_to_pointer (mp->app_event_queue_address,
		      unix_shared_memory_queue_t *);

  vcm->app_state = STATE_APP_ATTACHED;
}

static void
vl_api_application_detach_reply_t_handler (vl_api_application_detach_reply_t *
					   mp)
{
  if (mp->retval)
    clib_warning ("[%d] detach failed: %U", getpid (), format_api_error,
		  ntohl (mp->retval));

  vcm->app_state = STATE_APP_ENABLED;
}

static void
vl_api_disconnect_session_reply_t_handler (vl_api_disconnect_session_reply_t *
					   mp)
{
  if (mp->retval)
    clib_warning ("[%d] vpp handle 0x%llx: disconnect session failed: %U",
		  getpid (), mp->handle, format_api_error,
		  ntohl (mp->retval));
}

static void
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t * mp)
{
  static svm_fifo_segment_create_args_t _a;
  svm_fifo_segment_create_args_t *a = &_a;
  int rv;

  memset (a, 0, sizeof (*a));
  a->segment_name = (char *) mp->segment_name;
  a->segment_size = mp->segment_size;
  /* Attach to the segment vpp created */
  rv = svm_fifo_segment_attach (a);
  vec_reset_length (a->new_segment_indices);
  if (PREDICT_FALSE (rv))
    {
      clib_warning ("[%d] svm_fifo_segment_attach ('%s') failed",
		    getpid (), mp->segment_name);
      return;
    }
  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] mapped new segment '%s' size %d", getpid (),
		  mp->segment_name, mp->segment_size);
}

static void
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  uword *p;

  p = hash_get (vcm->session_index_by_vpp_handles, mp->handle);
  if (p)
    {
      int rv;
      session_t *session = 0;
      u32 session_index = p[0];

      VCL_LOCK_AND_GET_SESSION (session_index, &session);
      session->state = STATE_CLOSE_ON_EMPTY;

      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
		      "setting state to 0x%x (%s)",
		      getpid (), mp->handle, session_index, session->state,
		      vppcom_session_state_str (session->state));
      clib_spinlock_unlock (&vcm->sessions_lockp);
      return;

    done:
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
		      "session lookup failed!",
		      getpid (), mp->handle, session_index);
    }
  else
    clib_warning ("[%d] vpp handle 0x%llx: session lookup by "
		  "handle failed!", getpid (), mp->handle);
}

static void
vl_api_reset_session_t_handler (vl_api_reset_session_t * mp)
{
  session_t *session = 0;
  vl_api_reset_session_reply_t *rmp;
  uword *p;
  int rv = 0;

  p = hash_get (vcm->session_index_by_vpp_handles, mp->handle);
  if (p)
    {
      int rval;
      clib_spinlock_lock (&vcm->sessions_lockp);
      rval = vppcom_session_at_index (p[0], &session);
      if (PREDICT_FALSE (rval))
	{
	  rv = VNET_API_ERROR_INVALID_VALUE_2;
	  clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: "
			"session lookup failed! returning %d %U",
			getpid (), mp->handle, p[0],
			rv, format_api_error, rv);
	}
      else
	{
	  /* TBD: should this disconnect immediately and
	   * flush the fifos?
	   */
	  session->state = STATE_CLOSE_ON_EMPTY;

	  if (VPPCOM_DEBUG > 1)
	    clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
			  "state set to %d (%s)!", getpid (),
			  mp->handle, p[0], session->state,
			  vppcom_session_state_str (session->state));
	}
      clib_spinlock_unlock (&vcm->sessions_lockp);
    }
  else
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      clib_warning ("[%d] ERROR: vpp handle 0x%llx: session lookup "
		    "failed! returning %d %U",
		    getpid (), mp->handle, rv, format_api_error, rv);
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_RESET_SESSION_REPLY);
  rmp->retval = htonl (rv);
  rmp->handle = mp->handle;
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & rmp);
}

static void
vl_api_connect_session_reply_t_handler (vl_api_connect_session_reply_t * mp)
{
  session_t *session = 0;
  u32 session_index;
  svm_fifo_t *rx_fifo, *tx_fifo;
  u8 is_cut_thru = 0;
  int rv;

  session_index = mp->context;
  VCL_LOCK_AND_GET_SESSION (session_index, &session);
done:
  if (mp->retval)
    {
      clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: "
		    "connect failed! %U",
		    getpid (), mp->handle, session_index,
		    format_api_error, ntohl (mp->retval));
      if (rv == VPPCOM_OK)
	{
	  session->state = STATE_FAILED;
	  session->vpp_handle = mp->handle;
	}
      else
	{
	  clib_warning ("[%s] ERROR: vpp handle 0x%llx, sid %u: "
			"Invalid session index (%u)!",
			getpid (), mp->handle, session_index);
	}
      goto done_unlock;
    }

  if (rv)
    goto done_unlock;

  /* We've been redirected */
  if (mp->segment_name_length > 0)
    {
      static svm_fifo_segment_create_args_t _a;
      svm_fifo_segment_create_args_t *a = &_a;

      is_cut_thru = 1;
      memset (a, 0, sizeof (*a));
      a->segment_name = (char *) mp->segment_name;
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] cut-thru segment: %s\n",
		      getpid (), a->segment_name);

      rv = svm_fifo_segment_attach (a);
      vec_reset_length (a->new_segment_indices);
      if (PREDICT_FALSE (rv))
	{
	  clib_warning ("[%d] sm_fifo_segment_attach ('%s') failed",
			getpid (), a->segment_name);
	  goto done_unlock;
	}
    }

  /*
   * Setup session
   */
  session->is_cut_thru = is_cut_thru;
  session->vpp_event_queue = uword_to_pointer (mp->vpp_event_queue_address,
					       unix_shared_memory_queue_t *);

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->server_rx_fifo = rx_fifo;
  session->server_tx_fifo = tx_fifo;
  session->vpp_handle = mp->handle;
  session->lcl_addr.is_ip4 = mp->is_ip4;
  clib_memcpy (&session->lcl_addr.ip46, mp->lcl_ip,
	       sizeof (session->peer_addr.ip46));
  session->lcl_port = mp->lcl_port;
  session->state = STATE_CONNECT;

  /* Add it to lookup table */
  hash_set (vcm->session_index_by_vpp_handles, mp->handle, session_index);

  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] vpp handle 0x%llx, sid %u: connect succeeded!"
		  " session_rx_fifo %p, refcnt %d,"
		  " session_tx_fifo %p, refcnt %d",
		  getpid (), mp->handle, session_index,
		  session->server_rx_fifo,
		  session->server_rx_fifo->refcnt,
		  session->server_tx_fifo, session->server_tx_fifo->refcnt);
done_unlock:
  clib_spinlock_unlock (&vcm->sessions_lockp);
}

static void
vppcom_send_connect_sock (session_t * session, u32 session_index)
{
  vl_api_connect_sock_t *cmp;

  /* Assumes caller as acquired the spinlock: vcm->sessions_lockp */
  session->is_server = 0;
  cmp = vl_msg_api_alloc (sizeof (*cmp));
  memset (cmp, 0, sizeof (*cmp));
  cmp->_vl_msg_id = ntohs (VL_API_CONNECT_SOCK);
  cmp->client_index = vcm->my_client_index;
  cmp->context = session_index;

  cmp->vrf = session->vrf;
  cmp->is_ip4 = session->peer_addr.is_ip4;
  clib_memcpy (cmp->ip, &session->peer_addr.ip46, sizeof (cmp->ip));
  cmp->port = session->peer_port;
  cmp->proto = session->proto;
  clib_memcpy (cmp->options, session->options, sizeof (cmp->options));
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & cmp);
}

static inline void
vppcom_send_disconnect_session_reply (u64 vpp_handle, u32 session_index,
				      int rv)
{
  vl_api_disconnect_session_reply_t *rmp;

  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] vpp handle 0x%llx, sid %u: sending disconnect msg",
		  getpid (), vpp_handle, session_index);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION_REPLY);
  rmp->retval = htonl (rv);
  rmp->handle = vpp_handle;
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & rmp);
}

static inline void
vppcom_send_disconnect_session (u64 vpp_handle, u32 session_index)
{
  vl_api_disconnect_session_t *dmp;

  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] vpp handle 0x%llx, sid %u: sending disconnect msg",
		  getpid (), vpp_handle, session_index);

  dmp = vl_msg_api_alloc (sizeof (*dmp));
  memset (dmp, 0, sizeof (*dmp));
  dmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION);
  dmp->client_index = vcm->my_client_index;
  dmp->handle = vpp_handle;
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & dmp);
}

static void
vl_api_bind_sock_reply_t_handler (vl_api_bind_sock_reply_t * mp)
{
  session_t *session = 0;
  u32 session_index = mp->context;
  int rv;

  VCL_LOCK_AND_GET_SESSION (session_index, &session);
done:
  if (mp->retval)
    {
      clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: bind failed: %U",
		    getpid (), mp->handle, session_index, format_api_error,
		    ntohl (mp->retval));
      rv = vppcom_session_at_index (session_index, &session);
      if (rv == VPPCOM_OK)
	{
	  session->state = STATE_FAILED;
	  session->vpp_handle = mp->handle;
	}
      else
	{
	  clib_warning ("[%s] ERROR: vpp handle 0x%llx, sid %u: "
			"Invalid session index (%u)!",
			getpid (), mp->handle, session_index);
	}
      goto done_unlock;
    }

  session->vpp_handle = mp->handle;
  session->lcl_addr.is_ip4 = mp->lcl_is_ip4;
  clib_memcpy (&session->lcl_addr.ip46, mp->lcl_ip,
	       sizeof (session->peer_addr.ip46));
  session->lcl_port = mp->lcl_port;
  vppcom_session_table_add_listener (mp->handle, session_index);
  session->is_listen = 1;
  session->state = STATE_LISTEN;

  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] vpp handle 0x%llx, sid %u: bind succeeded!",
		  getpid (), mp->handle, mp->context);
done_unlock:
  clib_spinlock_unlock (&vcm->sessions_lockp);
}

static void
vl_api_unbind_sock_reply_t_handler (vl_api_unbind_sock_reply_t * mp)
{
  if (mp->retval)
    clib_warning ("[%d] ERROR: sid %u: unbind failed: %U",
		  getpid (), mp->context, format_api_error,
		  ntohl (mp->retval));

  else if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] sid %u: unbind succeeded!", getpid (), mp->context);
}

u8 *
format_ip4_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

u8 *
format_ip6_address (u8 * s, va_list * args)
{
  ip6_address_t *a = va_arg (*args, ip6_address_t *);
  u32 i, i_max_n_zero, max_n_zeros, i_first_zero, n_zeros, last_double_colon;

  i_max_n_zero = ARRAY_LEN (a->as_u16);
  max_n_zeros = 0;
  i_first_zero = i_max_n_zero;
  n_zeros = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      u32 is_zero = a->as_u16[i] == 0;
      if (is_zero && i_first_zero >= ARRAY_LEN (a->as_u16))
	{
	  i_first_zero = i;
	  n_zeros = 0;
	}
      n_zeros += is_zero;
      if ((!is_zero && n_zeros > max_n_zeros)
	  || (i + 1 >= ARRAY_LEN (a->as_u16) && n_zeros > max_n_zeros))
	{
	  i_max_n_zero = i_first_zero;
	  max_n_zeros = n_zeros;
	  i_first_zero = ARRAY_LEN (a->as_u16);
	  n_zeros = 0;
	}
    }

  last_double_colon = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      if (i == i_max_n_zero && max_n_zeros > 1)
	{
	  s = format (s, "::");
	  i += max_n_zeros - 1;
	  last_double_colon = 1;
	}
      else
	{
	  s = format (s, "%s%x",
		      (last_double_colon || i == 0) ? "" : ":",
		      clib_net_to_host_u16 (a->as_u16[i]));
	  last_double_colon = 0;
	}
    }

  return s;
}

/* Format an IP46 address. */
u8 *
format_ip46_address (u8 * s, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  int is_ip4 = 1;

  switch (type)
    {
    case IP46_TYPE_ANY:
      is_ip4 = ip46_address_is_ip4 (ip46);
      break;
    case IP46_TYPE_IP4:
      is_ip4 = 1;
      break;
    case IP46_TYPE_IP6:
      is_ip4 = 0;
      break;
    }

  return is_ip4 ?
    format (s, "%U", format_ip4_address, &ip46->ip4) :
    format (s, "%U", format_ip6_address, &ip46->ip6);
}

static inline void
vppcom_send_accept_session_reply (u64 handle, u32 context, int retval)
{
  vl_api_accept_session_reply_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ACCEPT_SESSION_REPLY);
  rmp->retval = htonl (retval);
  rmp->context = context;
  rmp->handle = handle;
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & rmp);
}

static void
vl_api_accept_session_t_handler (vl_api_accept_session_t * mp)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  session_t *session, *listen_session;
  u32 session_index;

  clib_spinlock_lock (&vcm->sessions_lockp);
  if (!clib_fifo_free_elts (vcm->client_session_index_fifo))
    {
      clib_warning ("[%d] client session queue is full!", getpid ());
      vppcom_send_accept_session_reply (mp->handle, mp->context,
					VNET_API_ERROR_QUEUE_FULL);
      clib_spinlock_unlock (&vcm->sessions_lockp);
      return;
    }

  listen_session = vppcom_session_table_lookup_listener (mp->listener_handle);
  if (!listen_session)
    {
      clib_warning ("[%d] ERROR: couldn't find listen session: unknown vpp "
		    "listener handle %llx", getpid (), mp->listener_handle);
      clib_spinlock_unlock (&vcm->sessions_lockp);
      return;
    }

  /* Allocate local session and set it up */
  pool_get (vcm->sessions, session);
  memset (session, 0, sizeof (*session));
  session_index = session - vcm->sessions;

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->vpp_handle = mp->handle;
  session->client_context = mp->context;
  session->server_rx_fifo = rx_fifo;
  session->server_tx_fifo = tx_fifo;
  session->vpp_event_queue = uword_to_pointer (mp->vpp_event_queue_address,
					       unix_shared_memory_queue_t *);
  session->state = STATE_ACCEPT;
  session->is_cut_thru = 0;
  session->is_server = 1;
  session->peer_port = mp->port;
  session->peer_addr.is_ip4 = mp->is_ip4;
  clib_memcpy (&session->peer_addr.ip46, mp->ip,
	       sizeof (session->peer_addr.ip46));

  /* Add it to lookup table */
  hash_set (vcm->session_index_by_vpp_handles, mp->handle, session_index);
  session->lcl_port = listen_session->lcl_port;
  session->lcl_addr = listen_session->lcl_addr;

  /* TBD: move client_session_index_fifo into listener session */
  clib_fifo_add1 (vcm->client_session_index_fifo, session_index);

  clib_spinlock_unlock (&vcm->sessions_lockp);

  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] vpp handle 0x%llx, sid %u: client accept "
		  "request from %s address %U port %d queue %p!", getpid (),
		  mp->handle, session_index, mp->is_ip4 ? "IPv4" : "IPv6",
		  format_ip46_address, &mp->ip, mp->is_ip4,
		  clib_net_to_host_u16 (mp->port), session->vpp_event_queue);
}

static void
vppcom_send_connect_session_reply (session_t * session, u32 session_index,
				   u64 vpp_handle, u32 context, int retval)
{
  vl_api_connect_session_reply_t *rmp;
  u32 len;
  unix_shared_memory_queue_t *client_q;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_CONNECT_SESSION_REPLY);

  if (!session)
    {
      rmp->context = context;
      rmp->handle = vpp_handle;
      rmp->retval = htonl (retval);
      vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & rmp);
      return;
    }

  rmp->context = session->client_context;
  rmp->retval = htonl (retval);
  rmp->handle = session->vpp_handle;
  rmp->server_rx_fifo = pointer_to_uword (session->server_rx_fifo);
  rmp->server_tx_fifo = pointer_to_uword (session->server_tx_fifo);
  rmp->vpp_event_queue_address = pointer_to_uword (session->vpp_event_queue);
  rmp->segment_size = vcm->cfg.segment_size;
  len = vec_len (session->segment_name);
  rmp->segment_name_length = clib_min (len, sizeof (rmp->segment_name));
  clib_memcpy (rmp->segment_name, session->segment_name,
	       rmp->segment_name_length - 1);
  clib_memcpy (rmp->lcl_ip, session->peer_addr.ip46.as_u8,
	       sizeof (rmp->lcl_ip));
  rmp->is_ip4 = session->peer_addr.is_ip4;
  rmp->lcl_port = session->peer_port;
  client_q = uword_to_pointer (session->client_queue_address,
			       unix_shared_memory_queue_t *);
  ASSERT (client_q);
  vl_msg_api_send_shmem (client_q, (u8 *) & rmp);
}

/*
 * Acting as server for redirected connect requests
 */
static void
vl_api_connect_sock_t_handler (vl_api_connect_sock_t * mp)
{
  u32 session_index;
  session_t *session = 0;

  clib_spinlock_lock (&vcm->sessions_lockp);
  if (!clib_fifo_free_elts (vcm->client_session_index_fifo))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);

      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] client session queue is full!", getpid ());

      /* TBD: Fix api to include vpp handle */
      vppcom_send_connect_session_reply (0 /* session */ , 0 /* sid */ ,
					 0 /* handle */ , mp->context,
					 VNET_API_ERROR_QUEUE_FULL);
      return;
    }

  pool_get (vcm->sessions, session);
  memset (session, 0, sizeof (*session));
  session_index = session - vcm->sessions;

  session->client_context = mp->context;
  session->vpp_handle = session_index;
  session->client_queue_address = mp->client_queue_address;
  session->is_cut_thru = 1;
  session->is_server = 1;
  session->lcl_port = mp->port;
  session->lcl_addr.is_ip4 = mp->is_ip4;
  clib_memcpy (&session->lcl_addr.ip46, mp->ip,
	       sizeof (session->lcl_addr.ip46));

  /* TBD: missing peer info in api msg.
   */
  session->peer_addr.is_ip4 = mp->is_ip4;
  ASSERT (session->lcl_addr.is_ip4 == session->peer_addr.is_ip4);

  session->state = STATE_ACCEPT;
  clib_fifo_add1 (vcm->client_session_index_fifo, session_index);
  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] sid %u: Got a cut-thru connect request! "
		  "clib_fifo_elts %u!\n", getpid (), session_index,
		  clib_fifo_elts (vcm->client_session_index_fifo));
  clib_spinlock_unlock (&vcm->sessions_lockp);
}

static void
vppcom_send_bind_sock (session_t * session, u32 session_index)
{
  vl_api_bind_sock_t *bmp;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  session->is_server = 1;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_BIND_SOCK);
  bmp->client_index = vcm->my_client_index;
  bmp->context = session_index;
  bmp->vrf = session->vrf;
  bmp->is_ip4 = session->lcl_addr.is_ip4;
  clib_memcpy (bmp->ip, &session->lcl_addr.ip46, sizeof (bmp->ip));
  bmp->port = session->lcl_port;
  bmp->proto = session->proto;
  clib_memcpy (bmp->options, session->options, sizeof (bmp->options));
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & bmp);
}

static void
vppcom_send_unbind_sock (u64 vpp_handle)
{
  vl_api_unbind_sock_t *ump;

  ump = vl_msg_api_alloc (sizeof (*ump));
  memset (ump, 0, sizeof (*ump));

  ump->_vl_msg_id = ntohs (VL_API_UNBIND_SOCK);
  ump->client_index = vcm->my_client_index;
  ump->handle = vpp_handle;
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & ump);
}

static int
vppcom_session_unbind (u32 session_index)
{
  session_t *session = 0;
  int rv;
  u64 vpp_handle;

  VCL_LOCK_AND_GET_SESSION (session_index, &session);

  vpp_handle = session->vpp_handle;
  vppcom_session_table_del_listener (vpp_handle);
  session->vpp_handle = ~0;
  session->state = STATE_DISCONNECT;

  clib_spinlock_unlock (&vcm->sessions_lockp);

  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
		  "sending unbind msg! new state 0x%x (%s)",
		  getpid (), vpp_handle, session_index,
		  session->state, vppcom_session_state_str (session->state));

  vppcom_send_unbind_sock (vpp_handle);

done:
  return rv;
}

static inline int
vppcom_session_disconnect (u32 session_index)
{
  int rv;
  session_t *session;
  u8 is_cut_thru, is_listen, is_server;
  u64 vpp_handle;
  session_state_t state;

  VCL_LOCK_AND_GET_SESSION (session_index, &session);

  vpp_handle = session->vpp_handle;
  is_server = session->is_server;
  is_listen = session->is_listen;
  is_cut_thru = session->is_cut_thru;
  state = session->state;
  clib_spinlock_unlock (&vcm->sessions_lockp);

  if (VPPCOM_DEBUG > 1)
    {
      clib_warning ("[%d] vpp handle 0x%llx, sid %u: %s state 0x%x (%s), "
		    "is_cut_thru %d, is_listen %d",
		    getpid (), vpp_handle, session_index,
		    is_server ? "server" : "client",
		    state, vppcom_session_state_str (state),
		    is_cut_thru, is_listen);
    }

  if (PREDICT_FALSE (is_listen))
    {
      clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: "
		    "Cannot disconnect a listen socket!",
		    getpid (), vpp_handle, session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  /* Through the VPP host stack...
   */
  else if (!is_cut_thru)
    {
      /* The peer has already initiated the close,
       * so send the disconnect session reply.
       */
      if (state & STATE_CLOSE_ON_EMPTY)
	{
	  vppcom_send_disconnect_session_reply (vpp_handle,
						session_index, 0 /* rv */ );
	  if (VPPCOM_DEBUG > 1)
	    clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
			  "sending disconnect REPLY...",
			  getpid (), vpp_handle, session_index);
	}

      /* Otherwise, send a disconnect session msg...
       */
      else
	{
	  if (VPPCOM_DEBUG > 1)
	    clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
			  "sending disconnect...",
			  getpid (), vpp_handle, session_index);

	  vppcom_send_disconnect_session (vpp_handle, session_index);
	}
    }

  /* Cut-thru connections...
   *
   *   server: free fifos and segment allocated during connect/redirect
   *   client: no cleanup required
   */
  else
    {
      if (is_server)
	{
	  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
	  svm_fifo_segment_private_t *seg;

	  VCL_LOCK_AND_GET_SESSION (session_index, &session);

	  if (VPPCOM_DEBUG > 1)
	    clib_warning ("[%d] sid %d: freeing cut-thru fifos in "
			  "sm_seg_index %d! "
			  " server_rx_fifo %p, refcnt = %d"
			  " server_tx_fifo %p, refcnt = %d",
			  getpid (), session_index, session->sm_seg_index,
			  session->server_rx_fifo,
			  session->server_rx_fifo->refcnt,
			  session->server_tx_fifo,
			  session->server_tx_fifo->refcnt);

	  seg = vec_elt_at_index (sm->segments, session->sm_seg_index);
	  svm_fifo_segment_free_fifo (seg, session->server_rx_fifo,
				      FIFO_SEGMENT_RX_FREELIST);
	  svm_fifo_segment_free_fifo (seg, session->server_tx_fifo,
				      FIFO_SEGMENT_TX_FREELIST);
	  svm_fifo_segment_delete (seg);

	  /* TBD: Send cut-thru disconnect event to client */

	  clib_spinlock_unlock (&vcm->sessions_lockp);
	}
      else
	{
	  /* TBD: Send cut-thru disconnect event to server */
	}
    }

done:
  return rv;
}

#define foreach_sock_msg                                        \
_(SESSION_ENABLE_DISABLE_REPLY, session_enable_disable_reply)   \
_(BIND_SOCK_REPLY, bind_sock_reply)                             \
_(UNBIND_SOCK_REPLY, unbind_sock_reply)                         \
_(ACCEPT_SESSION, accept_session)                               \
_(CONNECT_SOCK, connect_sock)                                   \
_(CONNECT_SESSION_REPLY, connect_session_reply)                 \
_(DISCONNECT_SESSION, disconnect_session)                       \
_(DISCONNECT_SESSION_REPLY, disconnect_session_reply)           \
_(RESET_SESSION, reset_session)                                 \
_(APPLICATION_ATTACH_REPLY, application_attach_reply)           \
_(APPLICATION_DETACH_REPLY, application_detach_reply)           \
_(MAP_ANOTHER_SEGMENT, map_another_segment)

static void
vppcom_api_hookup (void)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_sock_msg;
#undef _
}

static void
vppcom_cfg_init (vppcom_cfg_t * vcl_cfg)
{
  ASSERT (vcl_cfg);

  vcl_cfg->heapsize = (256ULL << 20);
  vcl_cfg->vpp_api_q_length = 1024;
  vcl_cfg->segment_baseva = 0x200000000ULL;
  vcl_cfg->segment_size = (256 << 20);
  vcl_cfg->add_segment_size = (128 << 20);
  vcl_cfg->preallocated_fifo_pairs = 8;
  vcl_cfg->rx_fifo_size = (1 << 20);
  vcl_cfg->tx_fifo_size = (1 << 20);
  vcl_cfg->event_queue_size = 2048;
  vcl_cfg->listen_queue_size = CLIB_CACHE_LINE_BYTES / sizeof (u32);
  vcl_cfg->app_timeout = 10 * 60.0;
  vcl_cfg->session_timeout = 10 * 60.0;
  vcl_cfg->accept_timeout = 60.0;
}

static void
vppcom_cfg_heapsize (char *conf_fname)
{
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;
  FILE *fp;
  char inbuf[4096];
  int argc = 1;
  char **argv = NULL;
  char *arg = NULL;
  char *p;
  int i;
  u8 *sizep;
  u32 size;
  void *vcl_mem;
  void *heap;

  fp = fopen (conf_fname, "r");
  if (fp == NULL)
    {
      if (VPPCOM_DEBUG > 0)
	fprintf (stderr, "open configuration file '%s' failed\n", conf_fname);
      goto defaulted;
    }
  argv = calloc (1, sizeof (char *));
  if (argv == NULL)
    goto defaulted;

  while (1)
    {
      if (fgets (inbuf, 4096, fp) == 0)
	break;
      p = strtok (inbuf, " \t\n");
      while (p != NULL)
	{
	  if (*p == '#')
	    break;
	  argc++;
	  char **tmp = realloc (argv, argc * sizeof (char *));
	  if (tmp == NULL)
	    goto defaulted;
	  argv = tmp;
	  arg = strndup (p, 1024);
	  if (arg == NULL)
	    goto defaulted;
	  argv[argc - 1] = arg;
	  p = strtok (NULL, " \t\n");
	}
    }

  fclose (fp);
  fp = NULL;

  char **tmp = realloc (argv, (argc + 1) * sizeof (char *));
  if (tmp == NULL)
    goto defaulted;
  argv = tmp;
  argv[argc] = NULL;

  /*
   * Look for and parse the "heapsize" config parameter.
   * Manual since none of the clib infra has been bootstrapped yet.
   *
   * Format: heapsize <nn>[mM][gG]
   */

  for (i = 1; i < (argc - 1); i++)
    {
      if (!strncmp (argv[i], "heapsize", 8))
	{
	  sizep = (u8 *) argv[i + 1];
	  size = 0;
	  while (*sizep >= '0' && *sizep <= '9')
	    {
	      size *= 10;
	      size += *sizep++ - '0';
	    }
	  if (size == 0)
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] parse error '%s %s', "
			      "using default heapsize %lld (0x%llx)",
			      getpid (), argv[i], argv[i + 1],
			      vcl_cfg->heapsize, vcl_cfg->heapsize);
	      goto defaulted;
	    }

	  if (*sizep == 'g' || *sizep == 'G')
	    vcl_cfg->heapsize = size << 30;
	  else if (*sizep == 'm' || *sizep == 'M')
	    vcl_cfg->heapsize = size << 20;
	  else
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] parse error '%s %s', "
			      "using default heapsize %lld (0x%llx)",
			      getpid (), argv[i], argv[i + 1],
			      vcl_cfg->heapsize, vcl_cfg->heapsize);
	      goto defaulted;
	    }
	}
    }

defaulted:
  if (fp != NULL)
    fclose (fp);
  if (argv != NULL)
    free (argv);

  vcl_mem = mmap (0, vcl_cfg->heapsize, PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (vcl_mem == MAP_FAILED)
    {
      clib_unix_error ("[%d] ERROR: mmap(0, %lld == 0x%llx, "
		       "PROT_READ | PROT_WRITE,MAP_SHARED | MAP_ANONYMOUS, "
		       "-1, 0) failed!",
		       getpid (), vcl_cfg->heapsize, vcl_cfg->heapsize);
      return;
    }
  heap = clib_mem_init (vcl_mem, vcl_cfg->heapsize);
  if (!heap)
    {
      clib_warning ("[%d] ERROR: clib_mem_init() failed!", getpid ());
      return;
    }
  vcl_mem = clib_mem_alloc (sizeof (_vppcom_main));
  if (!vcl_mem)
    {
      clib_warning ("[%d] ERROR: clib_mem_alloc() failed!", getpid ());
      return;
    }

  clib_memcpy (vcl_mem, &_vppcom_main, sizeof (_vppcom_main));
  vcm = vcl_mem;

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] allocated VCL heap = %p, size %lld (0x%llx)",
		  getpid (), heap, vcl_cfg->heapsize, vcl_cfg->heapsize);
}

static void
vppcom_cfg_read (char *conf_fname)
{
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;
  int fd;
  unformat_input_t _input, *input = &_input;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 vc_cfg_input = 0;
  u8 *chroot_path;
  struct stat s;
  u32 uid, gid, q_len;

  fd = open (conf_fname, O_RDONLY);
  if (fd < 0)
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] open configuration file '%s' failed!",
		      getpid (), conf_fname);
      goto file_done;
    }

  if (fstat (fd, &s) < 0)
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] failed to stat `%s'", getpid (), conf_fname);
      goto file_done;
    }

  if (!(S_ISREG (s.st_mode) || S_ISLNK (s.st_mode)))
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] not a regular file `%s'", getpid (), conf_fname);
      goto file_done;
    }

  unformat_init_clib_file (input, fd);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      (void) unformat_user (input, unformat_line_input, line_input);
      unformat_skip_white_space (line_input);

      if (unformat (line_input, "vcl {"))
	{
	  vc_cfg_input = 1;
	  continue;
	}

      if (vc_cfg_input)
	{
	  if (unformat (line_input, "heapsize %s", &chroot_path))
	    {
	      vec_terminate_c_string (chroot_path);
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured heapsize %s, "
			      "actual heapsize %lld (0x%llx)",
			      getpid (), chroot_path, vcl_cfg->heapsize,
			      vcl_cfg->heapsize);
	      vec_free (chroot_path);
	    }
	  else if (unformat (line_input, "api-prefix %s", &chroot_path))
	    {
	      vec_terminate_c_string (chroot_path);
	      vl_set_memory_root_path ((char *) chroot_path);
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured api-prefix %s",
			      getpid (), chroot_path);
	      chroot_path = 0;	/* Don't vec_free() it! */
	    }
	  else if (unformat (line_input, "vpp-api-q-length %d", &q_len))
	    {
	      if (q_len < vcl_cfg->vpp_api_q_length)
		{
		  clib_warning ("[%d] ERROR: configured vpp-api-q-length "
				"(%u) is too small! Using default: %u ",
				getpid (), q_len, vcl_cfg->vpp_api_q_length);
		}
	      else
		{
		  vcl_cfg->vpp_api_q_length = q_len;

		  if (VPPCOM_DEBUG > 0)
		    clib_warning ("[%d] configured vpp-api-q-length %u",
				  getpid (), vcl_cfg->vpp_api_q_length);
		}
	    }
	  else if (unformat (line_input, "uid %d", &uid))
	    {
	      vl_set_memory_uid (uid);
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured uid %d", getpid (), uid);
	    }
	  else if (unformat (line_input, "gid %d", &gid))
	    {
	      vl_set_memory_gid (gid);
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured gid %d", getpid (), gid);
	    }
	  else if (unformat (line_input, "segment-baseva 0x%lx",
			     &vcl_cfg->segment_baseva))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured segment_baseva 0x%lx",
			      getpid (), vcl_cfg->segment_baseva);
	    }
	  else if (unformat (line_input, "segment-size 0x%lx",
			     &vcl_cfg->segment_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured segment_size 0x%lx (%ld)",
			      getpid (), vcl_cfg->segment_size,
			      vcl_cfg->segment_size);
	    }
	  else if (unformat (line_input, "segment-size %ld",
			     &vcl_cfg->segment_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured segment_size %ld (0x%lx)",
			      getpid (), vcl_cfg->segment_size,
			      vcl_cfg->segment_size);
	    }
	  else if (unformat (line_input, "add-segment-size 0x%lx",
			     &vcl_cfg->add_segment_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning
		  ("[%d] configured add_segment_size 0x%lx (%ld)",
		   getpid (), vcl_cfg->add_segment_size,
		   vcl_cfg->add_segment_size);
	    }
	  else if (unformat (line_input, "add-segment-size %ld",
			     &vcl_cfg->add_segment_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning
		  ("[%d] configured add_segment_size %ld (0x%lx)",
		   getpid (), vcl_cfg->add_segment_size,
		   vcl_cfg->add_segment_size);
	    }
	  else if (unformat (line_input, "preallocated-fifo-pairs %d",
			     &vcl_cfg->preallocated_fifo_pairs))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured preallocated_fifo_pairs "
			      "%d (0x%x)", getpid (),
			      vcl_cfg->preallocated_fifo_pairs,
			      vcl_cfg->preallocated_fifo_pairs);
	    }
	  else if (unformat (line_input, "rx-fifo-size 0x%lx",
			     &vcl_cfg->rx_fifo_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured rx_fifo_size 0x%lx (%ld)",
			      getpid (), vcl_cfg->rx_fifo_size,
			      vcl_cfg->rx_fifo_size);
	    }
	  else if (unformat (line_input, "rx-fifo-size %ld",
			     &vcl_cfg->rx_fifo_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured rx_fifo_size %ld (0x%lx)",
			      getpid (), vcl_cfg->rx_fifo_size,
			      vcl_cfg->rx_fifo_size);
	    }
	  else if (unformat (line_input, "tx-fifo-size 0x%lx",
			     &vcl_cfg->tx_fifo_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured tx_fifo_size 0x%lx (%ld)",
			      getpid (), vcl_cfg->tx_fifo_size,
			      vcl_cfg->tx_fifo_size);
	    }
	  else if (unformat (line_input, "tx-fifo-size %ld",
			     &vcl_cfg->tx_fifo_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured tx_fifo_size %ld (0x%lx)",
			      getpid (), vcl_cfg->tx_fifo_size,
			      vcl_cfg->tx_fifo_size);
	    }
	  else if (unformat (line_input, "event-queue-size 0x%lx",
			     &vcl_cfg->event_queue_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured event_queue_size 0x%lx (%ld)",
			      getpid (), vcl_cfg->event_queue_size,
			      vcl_cfg->event_queue_size);
	    }
	  else if (unformat (line_input, "event-queue-size %ld",
			     &vcl_cfg->event_queue_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured event_queue_size %ld (0x%lx)",
			      getpid (), vcl_cfg->event_queue_size,
			      vcl_cfg->event_queue_size);
	    }
	  else if (unformat (line_input, "listen-queue-size 0x%lx",
			     &vcl_cfg->listen_queue_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured listen_queue_size 0x%lx (%ld)",
			      getpid (), vcl_cfg->listen_queue_size,
			      vcl_cfg->listen_queue_size);
	    }
	  else if (unformat (line_input, "listen-queue-size %ld",
			     &vcl_cfg->listen_queue_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured listen_queue_size %ld (0x%lx)",
			      getpid (), vcl_cfg->listen_queue_size,
			      vcl_cfg->listen_queue_size);
	    }
	  else if (unformat (line_input, "app-timeout %f",
			     &vcl_cfg->app_timeout))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured app_timeout %f",
			      getpid (), vcl_cfg->app_timeout);
	    }
	  else if (unformat (line_input, "session-timeout %f",
			     &vcl_cfg->session_timeout))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured session_timeout %f",
			      getpid (), vcl_cfg->session_timeout);
	    }
	  else if (unformat (line_input, "accept-timeout %f",
			     &vcl_cfg->accept_timeout))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured accept_timeout %f",
			      getpid (), vcl_cfg->accept_timeout);
	    }
	  else if (unformat (line_input, "app-proxy-transport-tcp"))
	    {
	      vcl_cfg->app_proxy_transport_tcp = 1;
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured app_proxy_transport_tcp (%d)",
			      getpid (), vcl_cfg->app_proxy_transport_tcp);
	    }
	  else if (unformat (line_input, "app-proxy-transport-udp"))
	    {
	      vcl_cfg->app_proxy_transport_udp = 1;
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured app_proxy_transport_udp (%d)",
			      getpid (), vcl_cfg->app_proxy_transport_udp);
	    }
	  else if (unformat (line_input, "app-scope-local"))
	    {
	      vcl_cfg->app_scope_local = 1;
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured app_scope_local (%d)",
			      getpid (), vcl_cfg->app_scope_local);
	    }
	  else if (unformat (line_input, "app-scope-global"))
	    {
	      vcl_cfg->app_scope_global = 1;
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured app_scope_global (%d)",
			      getpid (), vcl_cfg->app_scope_global);
	    }
	  else if (unformat (line_input, "namespace-secret %lu",
			     &vcl_cfg->namespace_secret))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning
		  ("[%d] configured namespace_secret %lu (0x%lx)",
		   getpid (), vcl_cfg->namespace_secret,
		   vcl_cfg->namespace_secret);
	    }
	  else if (unformat (line_input, "namespace-id %v",
			     &vcl_cfg->namespace_id))
	    {
	      vl_api_application_attach_t *mp;
	      u32 max_nsid_vec_len = sizeof (mp->namespace_id) - 1;
	      u32 nsid_vec_len = vec_len (vcl_cfg->namespace_id);
	      if (nsid_vec_len > max_nsid_vec_len)
		{
		  _vec_len (vcl_cfg->namespace_id) = max_nsid_vec_len;
		  if (VPPCOM_DEBUG > 0)
		    clib_warning ("[%d] configured namespace_id is too long,"
				  " truncated to %d characters!", getpid (),
				  max_nsid_vec_len);
		}

	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured namespace_id %v",
			      getpid (), vcl_cfg->namespace_id);
	    }
	  else if (unformat (line_input, "}"))
	    {
	      vc_cfg_input = 0;
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] completed parsing vppcom config!",
			      getpid ());
	      goto input_done;
	    }
	  else
	    {
	      if (line_input->buffer[line_input->index] != '#')
		{
		  clib_warning ("[%d] Unknown vppcom config option: '%s'",
				getpid (), (char *)
				&line_input->buffer[line_input->index]);
		}
	    }
	}
    }

input_done:
  unformat_free (input);

file_done:
  if (fd >= 0)
    close (fd);
}

/*
 * VPPCOM Public API functions
 */
int
vppcom_app_create (char *app_name)
{
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;
  u8 *heap;
  mheap_t *h;
  int rv;

  if (!vcm->init)
    {
      char *conf_fname;
      char *env_var_str;

      vcm->init = 1;
      vppcom_cfg_init (vcl_cfg);
      env_var_str = getenv (VPPCOM_ENV_DEBUG);
      if (env_var_str)
	{
	  u32 tmp;
	  if (sscanf (env_var_str, "%u", &tmp) != 1)
	    clib_warning ("[%d] Invalid debug level specified in "
			  "the environment variable "
			  VPPCOM_ENV_DEBUG
			  " (%s)!\n", getpid (), env_var_str);
	  else
	    {
	      vcm->debug = tmp;
	      clib_warning ("[%d] configured debug level (%u) from "
			    VPPCOM_ENV_DEBUG "!", getpid (), vcm->debug);
	    }
	}
      conf_fname = getenv (VPPCOM_ENV_CONF);
      if (!conf_fname)
	{
	  conf_fname = VPPCOM_CONF_DEFAULT;
	  if (VPPCOM_DEBUG > 0)
	    clib_warning ("[%d] getenv '%s' failed!", getpid (),
			  VPPCOM_ENV_CONF);
	}
      vppcom_cfg_heapsize (conf_fname);
      clib_fifo_validate (vcm->client_session_index_fifo,
			  vcm->cfg.listen_queue_size);
      vppcom_cfg_read (conf_fname);
      env_var_str = getenv (VPPCOM_ENV_APP_NAMESPACE_ID);
      if (env_var_str)
	{
	  u32 ns_id_vec_len = strlen (env_var_str);

	  vec_reset_length (vcm->cfg.namespace_id);
	  vec_validate (vcm->cfg.namespace_id, ns_id_vec_len - 1);
	  clib_memcpy (vcm->cfg.namespace_id, env_var_str, ns_id_vec_len);

	  if (VPPCOM_DEBUG > 0)
	    clib_warning ("[%d] configured namespace_id (%v) from "
			  VPPCOM_ENV_APP_NAMESPACE_ID "!", getpid (),
			  vcm->cfg.namespace_id);
	}
      env_var_str = getenv (VPPCOM_ENV_APP_NAMESPACE_SECRET);
      if (env_var_str)
	{
	  u64 tmp;
	  if (sscanf (env_var_str, "%lu", &tmp) != 1)
	    clib_warning ("[%d] Invalid namespace secret specified in "
			  "the environment variable "
			  VPPCOM_ENV_APP_NAMESPACE_SECRET
			  " (%s)!\n", getpid (), env_var_str);
	  else
	    {
	      vcm->cfg.namespace_secret = tmp;
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured namespace secret (%lu) from "
			      VPPCOM_ENV_APP_NAMESPACE_ID "!", getpid (),
			      vcm->cfg.namespace_secret);
	    }
	}
      if (getenv (VPPCOM_ENV_APP_PROXY_TRANSPORT_TCP))
	{
	  vcm->cfg.app_proxy_transport_tcp = 1;
	  if (VPPCOM_DEBUG > 0)
	    clib_warning ("[%d] configured app_proxy_transport_tcp (%u) from "
			  VPPCOM_ENV_APP_PROXY_TRANSPORT_TCP "!", getpid (),
			  vcm->cfg.app_proxy_transport_tcp);
	}
      if (getenv (VPPCOM_ENV_APP_PROXY_TRANSPORT_UDP))
	{
	  vcm->cfg.app_proxy_transport_udp = 1;
	  if (VPPCOM_DEBUG > 0)
	    clib_warning ("[%d] configured app_proxy_transport_udp (%u) from "
			  VPPCOM_ENV_APP_PROXY_TRANSPORT_UDP "!", getpid (),
			  vcm->cfg.app_proxy_transport_udp);
	}
      if (getenv (VPPCOM_ENV_APP_SCOPE_LOCAL))
	{
	  vcm->cfg.app_scope_local = 1;
	  if (VPPCOM_DEBUG > 0)
	    clib_warning ("[%d] configured app_scope_local (%u) from "
			  VPPCOM_ENV_APP_SCOPE_LOCAL "!", getpid (),
			  vcm->cfg.app_scope_local);
	}
      if (getenv (VPPCOM_ENV_APP_SCOPE_GLOBAL))
	{
	  vcm->cfg.app_scope_global = 1;
	  if (VPPCOM_DEBUG > 0)
	    clib_warning ("[%d] configured app_scope_global (%u) from "
			  VPPCOM_ENV_APP_SCOPE_GLOBAL "!", getpid (),
			  vcm->cfg.app_scope_global);
	}

      vcm->main_cpu = os_get_thread_index ();
      heap = clib_mem_get_per_cpu_heap ();
      h = mheap_header (heap);

      /* make the main heap thread-safe */
      h->flags |= MHEAP_FLAG_THREAD_SAFE;

      vcm->session_index_by_vpp_handles = hash_create (0, sizeof (uword));

      clib_time_init (&vcm->clib_time);
      vppcom_init_error_string_table ();
      svm_fifo_segment_init (vcl_cfg->segment_baseva,
			     20 /* timeout in secs */ );
      clib_spinlock_init (&vcm->sessions_lockp);
      vppcom_api_hookup ();
    }

  if (vcm->my_client_index == ~0)
    {
      vcm->app_state = STATE_APP_START;
      rv = vppcom_connect_to_vpp (app_name);
      if (rv)
	{
	  clib_warning ("[%d] ERROR: couldn't connect to VPP!", getpid ());
	  return rv;
	}

      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] sending session enable", getpid ());

      rv = vppcom_app_session_enable ();
      if (rv)
	{
	  clib_warning ("[%d] ERROR: vppcom_app_session_enable() failed!",
			getpid ());
	  return rv;
	}

      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] sending app attach", getpid ());

      rv = vppcom_app_attach ();
      if (rv)
	{
	  clib_warning ("[%d] ERROR: vppcom_app_attach() failed!", getpid ());
	  return rv;
	}

      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] app_name '%s', my_client_index %d (0x%x)",
		      getpid (), app_name, vcm->my_client_index,
		      vcm->my_client_index);
    }

  return VPPCOM_OK;
}

void
vppcom_app_destroy (void)
{
  int rv;

  if (vcm->my_client_index == ~0)
    return;

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] detaching from VPP, my_client_index %d (0x%x)",
		  getpid (), vcm->my_client_index, vcm->my_client_index);

  vppcom_app_detach ();
  rv = vppcom_wait_for_app_state_change (STATE_APP_ENABLED);
  if (PREDICT_FALSE (rv))
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] application detach timed out! returning %d (%s)",
		      getpid (), rv, vppcom_retval_str (rv));
    }
  vl_client_disconnect_from_vlib ();
  vcm->my_client_index = ~0;
  vcm->app_state = STATE_APP_START;
}

int
vppcom_session_create (u32 vrf, u8 proto, u8 is_nonblocking)
{
  session_t *session;
  u32 session_index;

  clib_spinlock_lock (&vcm->sessions_lockp);
  pool_get (vcm->sessions, session);
  memset (session, 0, sizeof (*session));
  session_index = session - vcm->sessions;

  session->vrf = vrf;
  session->proto = proto;
  session->state = STATE_START;
  session->is_nonblocking = is_nonblocking ? 1 : 0;
  session->vpp_handle = ~0;
  clib_spinlock_unlock (&vcm->sessions_lockp);

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] sid %u", getpid (), session_index);

  return (int) session_index;
}

int
vppcom_session_close (uint32_t session_index)
{
  session_t *session = 0;
  int rv;
  u8 is_listen;
  u8 is_vep;
  u8 is_vep_session;
  u32 next_sid;
  u32 vep_idx;
  u64 vpp_handle;
  uword *p;
  session_state_t state;

  VCL_LOCK_AND_GET_SESSION (session_index, &session);
  is_listen = session->is_listen;
  is_vep = session->is_vep;
  is_vep_session = session->is_vep_session;
  next_sid = session->vep.next_sid;
  vep_idx = session->vep.vep_idx;
  state = session->state;
  vpp_handle = session->vpp_handle;
  clib_spinlock_unlock (&vcm->sessions_lockp);

  if (VPPCOM_DEBUG > 0)
    {
      if (is_vep)
	clib_warning ("[%d] vep_idx %u / sid %u: closing epoll session...",
		      getpid (), session_index, session_index);
      else
	clib_warning ("[%d] vpp handle 0x%llx, sid %d: closing session...",
		      getpid (), vpp_handle, session_index);
    }

  if (is_vep)
    {
      while (next_sid != ~0)
	{
	  rv = vppcom_epoll_ctl (session_index, EPOLL_CTL_DEL, next_sid, 0);
	  if ((VPPCOM_DEBUG > 0) && PREDICT_FALSE (rv < 0))
	    clib_warning ("[%d] vpp handle 0x%llx, sid %u: EPOLL_CTL_DEL "
			  "vep_idx %u failed! rv %d (%s)", getpid (),
			  vpp_handle, next_sid, vep_idx,
			  rv, vppcom_retval_str (rv));

	  VCL_LOCK_AND_GET_SESSION (session_index, &session);
	  next_sid = session->vep.next_sid;
	  clib_spinlock_unlock (&vcm->sessions_lockp);
	}
    }
  else
    {
      if (is_vep_session)
	{
	  rv = vppcom_epoll_ctl (vep_idx, EPOLL_CTL_DEL, session_index, 0);
	  if ((VPPCOM_DEBUG > 0) && (rv < 0))
	    clib_warning ("[%d] vpp handle 0x%llx, sid %u: EPOLL_CTL_DEL "
			  "vep_idx %u failed! rv %d (%s)",
			  getpid (), vpp_handle, session_index,
			  vep_idx, rv, vppcom_retval_str (rv));
	}

      if (is_listen)
	{
	  if (state == STATE_LISTEN)
	    {
	      rv = vppcom_session_unbind (session_index);
	      if (PREDICT_FALSE (rv < 0))
		{
		  if (VPPCOM_DEBUG > 0)
		    clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
				  "listener unbind failed! rv %d (%s)",
				  getpid (), vpp_handle, session_index,
				  rv, vppcom_retval_str (rv));
		}
	    }
	}

      else if (state & (CLIENT_STATE_OPEN | SERVER_STATE_OPEN))
	{
	  rv = vppcom_session_disconnect (session_index);
	  if (PREDICT_FALSE (rv < 0))
	    clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: "
			  "session disconnect failed! rv %d (%s)",
			  getpid (), vpp_handle, session_index,
			  rv, vppcom_retval_str (rv));
	}
    }

  VCL_LOCK_AND_GET_SESSION (session_index, &session);
  vpp_handle = session->vpp_handle;
  if (vpp_handle != ~0)
    {
      p = hash_get (vcm->session_index_by_vpp_handles, vpp_handle);
      if (p)
	hash_unset (vcm->session_index_by_vpp_handles, vpp_handle);
    }
  pool_put_index (vcm->sessions, session_index);
  clib_spinlock_unlock (&vcm->sessions_lockp);

  if (VPPCOM_DEBUG > 0)
    {
      if (is_vep)
	clib_warning ("[%d] vep_idx %u / sid %u: epoll session removed.",
		      getpid (), session_index, session_index);
      else
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: session removed.",
		      getpid (), vpp_handle, session_index);
    }
done:
  return rv;
}

int
vppcom_session_bind (uint32_t session_index, vppcom_endpt_t * ep)
{
  session_t *session = 0;
  int rv;

  if (!ep || !ep->ip)
    return VPPCOM_EINVAL;

  VCL_LOCK_AND_GET_SESSION (session_index, &session);

  if (session->is_vep)
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      clib_warning ("[%d] ERROR: sid %u: cannot bind to an epoll session!",
		    getpid (), session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  session->vrf = ep->vrf;
  session->lcl_addr.is_ip4 = ep->is_ip4;
  session->lcl_addr.ip46 = to_ip46 (!ep->is_ip4, ep->ip);
  session->lcl_port = ep->port;

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] sid %u: binding to local %s address %U "
		  "port %u, proto %s", getpid (), session_index,
		  session->lcl_addr.is_ip4 ? "IPv4" : "IPv6",
		  format_ip46_address, &session->lcl_addr.ip46,
		  session->lcl_addr.is_ip4,
		  clib_net_to_host_u16 (session->lcl_port),
		  session->proto ? "UDP" : "TCP");

  clib_spinlock_unlock (&vcm->sessions_lockp);
done:
  return rv;
}

int
vppcom_session_listen (uint32_t listen_session_index, uint32_t q_len)
{
  session_t *listen_session = 0;
  u64 listen_vpp_handle;
  int rv, retval;

  VCL_LOCK_AND_GET_SESSION (listen_session_index, &listen_session);

  if (listen_session->is_vep)
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      clib_warning ("[%d] ERROR: sid %u: cannot listen on an "
		    "epoll session!", getpid (), listen_session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  listen_vpp_handle = listen_session->vpp_handle;
  if (listen_session->is_listen)
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
		      "already in listen state!",
		      getpid (), listen_vpp_handle, listen_session_index);
      rv = VPPCOM_OK;
      goto done;
    }

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] vpp handle 0x%llx, sid %u: sending bind request...",
		  getpid (), listen_vpp_handle, listen_session_index);

  vppcom_send_bind_sock (listen_session, listen_session_index);
  clib_spinlock_unlock (&vcm->sessions_lockp);
  retval =
    vppcom_wait_for_session_state_change (listen_session_index, STATE_LISTEN,
					  vcm->cfg.session_timeout);

  VCL_LOCK_AND_GET_SESSION (listen_session_index, &listen_session);
  if (PREDICT_FALSE (retval))
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: bind failed! "
		      "returning %d (%s)", getpid (),
		      listen_session->vpp_handle, listen_session_index,
		      retval, vppcom_retval_str (retval));
      clib_spinlock_unlock (&vcm->sessions_lockp);
      rv = retval;
      goto done;
    }

  clib_fifo_validate (vcm->client_session_index_fifo, q_len);
  clib_spinlock_unlock (&vcm->sessions_lockp);
done:
  return rv;
}

int
vppcom_session_accept (uint32_t listen_session_index, vppcom_endpt_t * ep,
		       uint32_t flags, double wait_for_time)
{
  session_t *listen_session = 0;
  session_t *client_session = 0;
  u32 client_session_index = ~0;
  int rv;
  f64 wait_for;
  char *cut_thru_str;
  u64 listen_vpp_handle;

  VCL_LOCK_AND_GET_SESSION (listen_session_index, &listen_session);

  if (listen_session->is_vep)
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      clib_warning ("[%d] ERROR: sid %u: cannot accept on an "
		    "epoll session!", getpid (), listen_session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  listen_vpp_handle = listen_session->vpp_handle;
  if (listen_session->state != STATE_LISTEN)
    {
      clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: "
		    "not in listen state! state 0x%x (%s)", getpid (),
		    listen_vpp_handle, listen_session_index,
		    listen_session->state,
		    vppcom_session_state_str (listen_session->state));
      clib_spinlock_unlock (&vcm->sessions_lockp);
      rv = VPPCOM_EBADFD;
      goto done;
    }
  wait_for = ((listen_session->is_nonblocking) ? 0 :
	      (wait_for_time < 0) ? vcm->cfg.accept_timeout : wait_for_time);

  clib_spinlock_unlock (&vcm->sessions_lockp);

  while (1)
    {
      rv = vppcom_wait_for_client_session_index (wait_for);
      if (rv)
	{
	  if ((VPPCOM_DEBUG > 0))
	    clib_warning ("[%d] vpp handle 0x%llx, sid %u: accept failed! "
			  "returning %d (%s)", getpid (),
			  listen_vpp_handle, listen_session_index,
			  rv, vppcom_retval_str (rv));
	  if ((wait_for == 0) || (wait_for_time > 0))
	    goto done;
	}
      else
	break;
    }

  clib_spinlock_lock (&vcm->sessions_lockp);
  clib_fifo_sub1 (vcm->client_session_index_fifo, client_session_index);
  rv = vppcom_session_at_index (client_session_index, &client_session);
  if (PREDICT_FALSE (rv))
    {
      rv = VPPCOM_ECONNABORTED;
      clib_warning ("[%d] vpp handle 0x%llx, sid %u: client sid %u "
		    "lookup failed! returning %d (%s)", getpid (),
		    listen_vpp_handle, listen_session_index,
		    client_session_index, rv, vppcom_retval_str (rv));
      goto done;
    }

  client_session->is_nonblocking = (flags & O_NONBLOCK) ? 1 : 0;
  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] vpp handle 0x%llx, sid %u: Got a client request! "
		  "vpp handle 0x%llx, sid %u, flags %d, is_nonblocking %u",
		  getpid (), listen_vpp_handle, listen_session_index,
		  client_session->vpp_handle, client_session_index,
		  flags, client_session->is_nonblocking);

  ep->vrf = client_session->vrf;
  ep->is_cut_thru = client_session->is_cut_thru;
  ep->is_ip4 = client_session->peer_addr.is_ip4;
  ep->port = client_session->peer_port;
  if (client_session->peer_addr.is_ip4)
    clib_memcpy (ep->ip, &client_session->peer_addr.ip46.ip4,
		 sizeof (ip4_address_t));
  else
    clib_memcpy (ep->ip, &client_session->peer_addr.ip46.ip6,
		 sizeof (ip6_address_t));

  if (client_session->is_server && client_session->is_cut_thru)
    {
      static svm_fifo_segment_create_args_t _a;
      svm_fifo_segment_create_args_t *a = &_a;
      svm_fifo_segment_private_t *seg;

      cut_thru_str = " cut-thru ";

      /* Create the segment */
      memset (a, 0, sizeof (*a));
      a->segment_name = (char *)
	format ((u8 *) a->segment_name, "%d:segment%d%c",
		getpid (), vcm->unique_segment_index++, 0);
      a->segment_size = vcm->cfg.segment_size;
      a->preallocated_fifo_pairs = vcm->cfg.preallocated_fifo_pairs;
      a->rx_fifo_size = vcm->cfg.rx_fifo_size;
      a->tx_fifo_size = vcm->cfg.tx_fifo_size;

      rv = svm_fifo_segment_create (a);
      if (PREDICT_FALSE (rv))
	{
	  clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: "
			"client sid %u svm_fifo_segment_create ('%s') "
			"failed! rv %d", getpid (), listen_vpp_handle,
			listen_session_index, client_session_index,
			a->segment_name, rv);
	  vec_reset_length (a->new_segment_indices);
	  rv = VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
	  vppcom_send_connect_session_reply (client_session,
					     client_session_index,
					     client_session->vpp_handle,
					     client_session->client_context,
					     rv);
	  clib_spinlock_unlock (&vcm->sessions_lockp);
	  rv = VPPCOM_ENOMEM;
	  goto done;
	}

      client_session->segment_name = vec_dup ((u8 *) a->segment_name);
      client_session->sm_seg_index = a->new_segment_indices[0];
      vec_free (a->new_segment_indices);

      seg = svm_fifo_segment_get_segment (client_session->sm_seg_index);
      client_session->server_rx_fifo =
	svm_fifo_segment_alloc_fifo (seg, vcm->cfg.rx_fifo_size,
				     FIFO_SEGMENT_RX_FREELIST);
      if (PREDICT_FALSE (!client_session->server_rx_fifo))
	{
	  svm_fifo_segment_delete (seg);
	  clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: "
			"client sid %u rx fifo alloc failed! "
			"size %ld (0x%lx)", getpid (), listen_vpp_handle,
			listen_session_index, client_session_index,
			vcm->cfg.rx_fifo_size, vcm->cfg.rx_fifo_size);
	  rv = VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
	  vppcom_send_connect_session_reply (client_session,
					     client_session_index,
					     client_session->vpp_handle,
					     client_session->client_context,
					     rv);
	  clib_spinlock_unlock (&vcm->sessions_lockp);
	  rv = VPPCOM_ENOMEM;
	  goto done;
	}
      client_session->server_rx_fifo->master_session_index =
	client_session_index;

      client_session->server_tx_fifo =
	svm_fifo_segment_alloc_fifo (seg, vcm->cfg.tx_fifo_size,
				     FIFO_SEGMENT_TX_FREELIST);
      if (PREDICT_FALSE (!client_session->server_tx_fifo))
	{
	  svm_fifo_segment_delete (seg);
	  clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: "
			"client sid %u tx fifo alloc failed! "
			"size %ld (0x%lx)", getpid (), listen_vpp_handle,
			listen_session_index, client_session_index,
			vcm->cfg.tx_fifo_size, vcm->cfg.tx_fifo_size);
	  rv = VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
	  vppcom_send_connect_session_reply (client_session,
					     client_session_index,
					     client_session->vpp_handle,
					     client_session->client_context,
					     rv);
	  clib_spinlock_unlock (&vcm->sessions_lockp);
	  rv = VPPCOM_ENOMEM;
	  goto done;
	}
      client_session->server_tx_fifo->master_session_index =
	client_session_index;

      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: client sid %u "
		      "created segment '%s', rx_fifo %p, tx_fifo %p",
		      getpid (), listen_vpp_handle, listen_session_index,
		      client_session_index, client_session->segment_name,
		      client_session->server_rx_fifo,
		      client_session->server_tx_fifo);

#ifdef CUT_THRU_EVENT_QUEUE	/* TBD */
      {
	void *oldheap;
	ssvm_shared_header_t *sh = seg->ssvm.sh;

	ssvm_lock_non_recursive (sh, 1);
	oldheap = ssvm_push_heap (sh);
	event_q = client_session->vpp_event_queue =
	  unix_shared_memory_queue_init (vcm->cfg.event_queue_size,
					 sizeof (session_fifo_event_t),
					 getpid (), 0 /* signal not sent */ );
	ssvm_pop_heap (oldheap);
	ssvm_unlock_non_recursive (sh);
      }
#endif
      vppcom_send_connect_session_reply (client_session,
					 client_session_index,
					 client_session->vpp_handle,
					 client_session->client_context,
					 0 /* retval OK */ );
    }
  else
    {
      cut_thru_str = " ";
      vppcom_send_accept_session_reply (client_session->vpp_handle,
					client_session->client_context,
					0 /* retval OK */ );
    }

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] vpp handle 0x%llx, sid %u: accepted vpp handle "
		  "0x%llx, sid %u%sconnection to local %s address "
		  "%U port %u", getpid (), listen_vpp_handle,
		  listen_session_index, client_session->vpp_handle,
		  client_session_index, cut_thru_str,
		  client_session->lcl_addr.is_ip4 ? "IPv4" : "IPv6",
		  format_ip46_address, &client_session->lcl_addr.ip46,
		  client_session->lcl_addr.is_ip4,
		  clib_net_to_host_u16 (client_session->lcl_port));

  clib_spinlock_unlock (&vcm->sessions_lockp);
  rv = (int) client_session_index;
done:
  return rv;
}

int
vppcom_session_connect (uint32_t session_index, vppcom_endpt_t * server_ep)
{
  session_t *session = 0;
  int rv, retval = VPPCOM_OK;
  u64 vpp_handle = ~0;

  VCL_LOCK_AND_GET_SESSION (session_index, &session);

  if (PREDICT_FALSE (session->is_vep))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      clib_warning ("[%d] ERROR: sid %u: cannot connect on an epoll session!",
		    getpid (), session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  vpp_handle = session->vpp_handle;
  if (PREDICT_FALSE (session->is_server))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: is in use "
		    "as a server session!", getpid (), vpp_handle,
		    session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  if (PREDICT_FALSE (session->state & CLIENT_STATE_OPEN))
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: session already "
		      "connected to %s %U port %d proto %s, state 0x%x (%s)",
		      getpid (), vpp_handle, session_index,
		      session->peer_addr.is_ip4 ? "IPv4" : "IPv6",
		      format_ip46_address,
		      &session->peer_addr.ip46, session->peer_addr.is_ip4,
		      clib_net_to_host_u16 (session->peer_port),
		      session->proto ? "UDP" : "TCP", session->state,
		      vppcom_session_state_str (session->state));

      clib_spinlock_unlock (&vcm->sessions_lockp);
      goto done;
    }

  session->vrf = server_ep->vrf;
  session->peer_addr.is_ip4 = server_ep->is_ip4;
  session->peer_addr.ip46 = to_ip46 (!server_ep->is_ip4, server_ep->ip);
  session->peer_port = server_ep->port;

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] vpp handle 0x%llx, sid %u: connecting to server "
		  "%s %U port %d proto %s",
		  getpid (), vpp_handle, session_index,
		  session->peer_addr.is_ip4 ? "IPv4" : "IPv6",
		  format_ip46_address,
		  &session->peer_addr.ip46, session->peer_addr.is_ip4,
		  clib_net_to_host_u16 (session->peer_port),
		  session->proto ? "UDP" : "TCP");

  vppcom_send_connect_sock (session, session_index);
  clib_spinlock_unlock (&vcm->sessions_lockp);

  retval =
    vppcom_wait_for_session_state_change (session_index, STATE_CONNECT,
					  vcm->cfg.session_timeout);

  VCL_LOCK_AND_GET_SESSION (session_index, &session);
  vpp_handle = session->vpp_handle;
  clib_spinlock_unlock (&vcm->sessions_lockp);

done:
  if (PREDICT_FALSE (retval))
    {
      rv = retval;
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: connect failed! "
		      "returning %d (%s)", getpid (), vpp_handle,
		      session_index, rv, vppcom_retval_str (rv));
    }
  else if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] vpp handle 0x%llx, sid %u: connected!",
		  getpid (), vpp_handle, session_index);

  return rv;
}

static inline int
vppcom_session_read_internal (uint32_t session_index, void *buf, int n,
			      u8 peek)
{
  session_t *session = 0;
  svm_fifo_t *rx_fifo;
  int n_read = 0;
  int rv;
  char *fifo_str;
  u32 poll_et;
  session_state_t state;
  u8 is_server;
  u8 is_nonblocking;
  u64 vpp_handle;

  ASSERT (buf);

  VCL_LOCK_AND_GET_SESSION (session_index, &session);

  if (PREDICT_FALSE (session->is_vep))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      clib_warning ("[%d] ERROR: sid %u: cannot read from an epoll session!",
		    getpid (), session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  vpp_handle = session->vpp_handle;
  is_server = session->is_server;
  is_nonblocking = session->is_nonblocking;
  state = session->state;
  if (PREDICT_FALSE (!(state & (SERVER_STATE_OPEN | CLIENT_STATE_OPEN))))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      rv = ((state == STATE_DISCONNECT) ?
	    VPPCOM_ECONNRESET : VPPCOM_ENOTCONN);

      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: %s session is "
		      "not open! state 0x%x (%s), returning %d (%s)",
		      getpid (), vpp_handle, session_index,
		      is_server ? "server" : "client", state,
		      vppcom_session_state_str (state),
		      rv, vppcom_retval_str (rv));
      goto done;
    }

  rx_fifo = ((!session->is_cut_thru || is_server) ?
	     session->server_rx_fifo : session->server_tx_fifo);
  fifo_str = ((!session->is_cut_thru || is_server) ?
	      "server_rx_fifo" : "server_tx_fifo");
  clib_spinlock_unlock (&vcm->sessions_lockp);

  do
    {
      if (peek)
	n_read = svm_fifo_peek (rx_fifo, 0, n, buf);
      else
	n_read = svm_fifo_dequeue_nowait (rx_fifo, n, buf);
    }
  while (!is_nonblocking && (n_read <= 0));

  if (n_read <= 0)
    {
      VCL_LOCK_AND_GET_SESSION (session_index, &session);

      poll_et = (((EPOLLET | EPOLLIN) & session->vep.ev.events) ==
		 (EPOLLET | EPOLLIN));
      if (poll_et)
	session->vep.et_mask |= EPOLLIN;

      if (state == STATE_CLOSE_ON_EMPTY)
	{
	  session_state_t new_state = STATE_DISCONNECT;
	  rv = VPPCOM_ECONNRESET;

	  if (VPPCOM_DEBUG > 1)
	    {
	      clib_warning ("[%d] vpp handle 0x%llx, sid %u: Empty fifo "
			    "with %s session state 0x%x (%s)!"
			    "  Setting state to 0x%x (%s), returning %d (%s)",
			    getpid (), vpp_handle, session_index,
			    is_server ? "server" : "client",
			    state, vppcom_session_state_str (state),
			    new_state, vppcom_session_state_str (new_state),
			    rv, vppcom_retval_str (rv));
	    }

	  session->state = new_state;
	}
      else
	rv = VPPCOM_EAGAIN;

      clib_spinlock_unlock (&vcm->sessions_lockp);
    }
  else
    rv = n_read;

  if (VPPCOM_DEBUG > 2)
    {
      if (rv > 0)
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: read %d bytes "
		      "from %s (%p)", getpid (), vpp_handle,
		      session_index, n_read, fifo_str, rx_fifo);
      else
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: nothing read! "
		      "returning %d (%s)", getpid (), vpp_handle,
		      session_index, rv, vppcom_retval_str (rv));
    }
done:
  return rv;
}

int
vppcom_session_read (uint32_t session_index, void *buf, int n)
{
  return (vppcom_session_read_internal (session_index, buf, n, 0));
}

static int
vppcom_session_peek (uint32_t session_index, void *buf, int n)
{
  return (vppcom_session_read_internal (session_index, buf, n, 1));
}

static inline int
vppcom_session_read_ready (session_t * session, u32 session_index)
{
  svm_fifo_t *rx_fifo = 0;
  int ready = 0;
  u32 poll_et;
  int rv;
  u8 is_server = session->is_server;
  session_state_t state = session->state;
  u64 vpp_handle = session->vpp_handle;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  if (PREDICT_FALSE (session->is_vep))
    {
      clib_warning ("[%d] ERROR: sid %u: cannot read from an "
		    "epoll session!", getpid (), session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  if (session->is_listen)
    ready = clib_fifo_elts (vcm->client_session_index_fifo);
  else
    {
      if (!(state & (SERVER_STATE_OPEN | CLIENT_STATE_OPEN | STATE_LISTEN)))
	{
	  rv = ((state == STATE_DISCONNECT) ? VPPCOM_ECONNRESET :
		VPPCOM_ENOTCONN);

	  if (VPPCOM_DEBUG > 1)
	    clib_warning ("[%d] vpp handle 0x%llx, sid %u: %s session is "
			  "not open! state 0x%x (%s), returning %d (%s)",
			  getpid (), vpp_handle, session_index,
			  is_server ? "server" : "client",
			  state, vppcom_session_state_str (state),
			  rv, vppcom_retval_str (rv));
	  goto done;
	}

      rx_fifo = ((!session->is_cut_thru || is_server) ?
		 session->server_rx_fifo : session->server_tx_fifo);

      ready = svm_fifo_max_dequeue (rx_fifo);
    }

  if (ready == 0)
    {
      poll_et =
	((EPOLLET | EPOLLIN) & session->vep.ev.events) == (EPOLLET | EPOLLIN);
      if (poll_et)
	session->vep.et_mask |= EPOLLIN;

      if (state == STATE_CLOSE_ON_EMPTY)
	{
	  rv = VPPCOM_ECONNRESET;
	  session_state_t new_state = STATE_DISCONNECT;

	  if (VPPCOM_DEBUG > 1)
	    {
	      clib_warning ("[%d] vpp handle 0x%llx, sid %u: Empty fifo with"
			    " %s session state 0x%x (%s)! Setting state to "
			    "0x%x (%s), returning %d (%s)",
			    getpid (), session_index, vpp_handle,
			    is_server ? "server" : "client",
			    state, vppcom_session_state_str (state),
			    new_state, vppcom_session_state_str (new_state),
			    rv, vppcom_retval_str (rv));
	    }
	  session->state = new_state;
	  goto done;
	}
    }
  rv = ready;

  if (vcm->app_event_queue->cursize &&
      !pthread_mutex_trylock (&vcm->app_event_queue->mutex))
    {
      u32 i, n_to_dequeue = vcm->app_event_queue->cursize;
      session_fifo_event_t e;

      for (i = 0; i < n_to_dequeue; i++)
	unix_shared_memory_queue_sub_raw (vcm->app_event_queue, (u8 *) & e);

      pthread_mutex_unlock (&vcm->app_event_queue->mutex);
    }

done:
  return rv;
}

int
vppcom_session_write (uint32_t session_index, void *buf, int n)
{
  session_t *session = 0;
  svm_fifo_t *tx_fifo;
  unix_shared_memory_queue_t *q;
  session_fifo_event_t evt;
  int rv, n_write;
  char *fifo_str;
  u32 poll_et;
  u8 is_server;
  u8 is_nonblocking;
  session_state_t state;
  u64 vpp_handle;

  ASSERT (buf);

  VCL_LOCK_AND_GET_SESSION (session_index, &session);

  if (PREDICT_FALSE (session->is_vep))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: "
		    "cannot write to an epoll session!",
		    getpid (), session->vpp_handle, session_index);

      rv = VPPCOM_EBADFD;
      goto done;
    }

  is_server = session->is_server;
  is_nonblocking = session->is_nonblocking;
  vpp_handle = session->vpp_handle;
  state = session->state;
  if (!(state & (SERVER_STATE_OPEN | CLIENT_STATE_OPEN)))
    {
      rv = ((state == STATE_DISCONNECT) ? VPPCOM_ECONNRESET :
	    VPPCOM_ENOTCONN);

      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
		      "%s session is not open! state 0x%x (%s)",
		      getpid (), vpp_handle, session_index,
		      is_server ? "server" : "client", state,
		      vppcom_session_state_str (state));
      goto done;
    }

  tx_fifo = ((!session->is_cut_thru || is_server) ?
	     session->server_tx_fifo : session->server_rx_fifo);
  fifo_str = ((!session->is_cut_thru || is_server) ?
	      "server_tx_fifo" : "server_rx_fifo");
  clib_spinlock_unlock (&vcm->sessions_lockp);

  do
    {
      n_write = svm_fifo_enqueue_nowait (tx_fifo, n, buf);
    }
  while (!is_nonblocking && (n_write <= 0));

  /* If event wasn't set, add one */
  if (!session->is_cut_thru && (n_write > 0) && svm_fifo_set_event (tx_fifo))
    {
      /* Fabricate TX event, send to vpp */
      evt.fifo = tx_fifo;
      evt.event_type = FIFO_EVENT_APP_TX;

      VCL_LOCK_AND_GET_SESSION (session_index, &session);
      q = session->vpp_event_queue;
      ASSERT (q);
      unix_shared_memory_queue_add (q, (u8 *) & evt,
				    0 /* do wait for mutex */ );
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
		      "added FIFO_EVENT_APP_TX to "
		      "vpp_event_q %p, n_write %d", getpid (),
		      vpp_handle, session_index, q, n_write);
    }

  if (n_write <= 0)
    {
      VCL_LOCK_AND_GET_SESSION (session_index, &session);

      poll_et = (((EPOLLET | EPOLLOUT) & session->vep.ev.events) ==
		 (EPOLLET | EPOLLOUT));
      if (poll_et)
	session->vep.et_mask |= EPOLLOUT;

      if (state == STATE_CLOSE_ON_EMPTY)
	{
	  session_state_t new_state = STATE_DISCONNECT;
	  rv = VPPCOM_ECONNRESET;

	  if (VPPCOM_DEBUG > 1)
	    {
	      clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
			    "Empty fifo with %s session state 0x%x (%s)!"
			    "  Setting state to 0x%x (%s), returning %d (%s)",
			    getpid (), vpp_handle, session_index,
			    is_server ? "server" : "client",
			    state, vppcom_session_state_str (state),
			    new_state, vppcom_session_state_str (new_state),
			    rv, vppcom_retval_str (rv));
	    }

	  session->state = new_state;
	}
      else
	rv = VPPCOM_EAGAIN;

      clib_spinlock_unlock (&vcm->sessions_lockp);
    }
  else
    rv = n_write;

  if (VPPCOM_DEBUG > 2)
    {
      if (n_write <= 0)
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
		      "FIFO-FULL %s (%p)", getpid (), vpp_handle,
		      session_index, fifo_str, tx_fifo);
      else
	clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
		      "wrote %d bytes to %s (%p)", getpid (), vpp_handle,
		      session_index, n_write, fifo_str, tx_fifo);
    }
done:
  return rv;
}

static inline int
vppcom_session_write_ready (session_t * session, u32 session_index)
{
  svm_fifo_t *tx_fifo;
  char *fifo_str;
  int ready;
  u32 poll_et;
  int rv;
  u8 is_server = session->is_server;
  session_state_t state = session->state;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  if (PREDICT_FALSE (session->is_vep))
    {
      clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: "
		    "cannot write to an epoll session!",
		    getpid (), session->vpp_handle, session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  if (PREDICT_FALSE (session->is_listen))
    {
      clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: "
		    "cannot write to a listen session!",
		    getpid (), session->vpp_handle, session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  if (!(state & (SERVER_STATE_OPEN | CLIENT_STATE_OPEN)))
    {
      session_state_t state = session->state;

      rv = ((state == STATE_DISCONNECT) ? VPPCOM_ECONNRESET :
	    VPPCOM_ENOTCONN);

      clib_warning ("[%d] ERROR: vpp handle 0x%llx, sid %u: "
		    "%s session is not open! state 0x%x (%s), "
		    "returning %d (%s)", getpid (), session->vpp_handle,
		    session_index, is_server ? "server" : "client",
		    state, vppcom_session_state_str (state),
		    rv, vppcom_retval_str (rv));
      goto done;
    }

  tx_fifo = ((!session->is_cut_thru || session->is_server) ?
	     session->server_tx_fifo : session->server_rx_fifo);
  fifo_str = ((!session->is_cut_thru || session->is_server) ?
	      "server_tx_fifo" : "server_rx_fifo");

  ready = svm_fifo_max_enqueue (tx_fifo);

  if (VPPCOM_DEBUG > 3)
    clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
		  "peek %s (%p), ready = %d", getpid (),
		  session->vpp_handle, session_index,
		  fifo_str, tx_fifo, ready);

  if (ready == 0)
    {
      poll_et = (((EPOLLET | EPOLLOUT) & session->vep.ev.events) ==
		 (EPOLLET | EPOLLOUT));
      if (poll_et)
	session->vep.et_mask |= EPOLLOUT;

      if (state == STATE_CLOSE_ON_EMPTY)
	{
	  rv = VPPCOM_ECONNRESET;
	  session_state_t new_state = STATE_DISCONNECT;

	  if (VPPCOM_DEBUG > 1)
	    {
	      clib_warning ("[%d] vpp handle 0x%llx, sid %u: "
			    "Empty fifo with %s session "
			    "state 0x%x (%s)! Setting state to 0x%x (%s), "
			    "returning %d (%s)", getpid (),
			    session->vpp_handle, session_index,
			    is_server ? "server" : "client",
			    state, vppcom_session_state_str (state),
			    new_state, vppcom_session_state_str (new_state),
			    rv, vppcom_retval_str (rv));
	    }
	  session->state = new_state;
	  goto done;
	}
    }
  rv = ready;
done:
  return rv;
}

int
vppcom_select (unsigned long n_bits, unsigned long *read_map,
	       unsigned long *write_map, unsigned long *except_map,
	       double time_to_wait)
{
  u32 session_index;
  session_t *session = 0;
  int rv, bits_set = 0;
  f64 timeout = clib_time_now (&vcm->clib_time) + time_to_wait;
  u32 minbits = clib_max (n_bits, BITS (uword));

  ASSERT (sizeof (clib_bitmap_t) == sizeof (long int));

  if (n_bits && read_map)
    {
      clib_bitmap_validate (vcm->rd_bitmap, minbits);
      clib_memcpy (vcm->rd_bitmap, read_map, vec_len (vcm->rd_bitmap));
      memset (read_map, 0, vec_len (vcm->rd_bitmap));
    }
  if (n_bits && write_map)
    {
      clib_bitmap_validate (vcm->wr_bitmap, minbits);
      clib_memcpy (vcm->wr_bitmap, write_map, vec_len (vcm->wr_bitmap));
      memset (write_map, 0, vec_len (vcm->wr_bitmap));
    }
  if (n_bits && except_map)
    {
      clib_bitmap_validate (vcm->ex_bitmap, minbits);
      clib_memcpy (vcm->ex_bitmap, except_map, vec_len (vcm->ex_bitmap));
      memset (except_map, 0, vec_len (vcm->ex_bitmap));
    }

  do
    {
      /* *INDENT-OFF* */
      if (n_bits)
        {
          if (read_map)
            {
              clib_bitmap_foreach (session_index, vcm->rd_bitmap,
                ({
                  clib_spinlock_lock (&vcm->sessions_lockp);
                  rv = vppcom_session_at_index (session_index, &session);
                  if (rv < 0)
                    {
                      clib_spinlock_unlock (&vcm->sessions_lockp);
                      if (VPPCOM_DEBUG > 1)
                        clib_warning ("[%d] session %d specified in "
                                      "read_map is closed.", getpid (),
                                      session_index);
                      bits_set = VPPCOM_EBADFD;
                      goto select_done;
                    }

                  rv = vppcom_session_read_ready (session, session_index);
                  clib_spinlock_unlock (&vcm->sessions_lockp);
                  if (except_map && vcm->ex_bitmap &&
                      clib_bitmap_get (vcm->ex_bitmap, session_index) &&
                      (rv < 0))
                    {
                      // TBD: clib_warning
                      clib_bitmap_set_no_check (except_map, session_index, 1);
                      bits_set++;
                    }
                  else if (rv > 0)
                    {
                      // TBD: clib_warning
                      clib_bitmap_set_no_check (read_map, session_index, 1);
                      bits_set++;
                    }
                }));
            }

          if (write_map)
            {
              clib_bitmap_foreach (session_index, vcm->wr_bitmap,
                ({
                  clib_spinlock_lock (&vcm->sessions_lockp);
                  rv = vppcom_session_at_index (session_index, &session);
                  if (rv < 0)
                    {
                      clib_spinlock_unlock (&vcm->sessions_lockp);
                      if (VPPCOM_DEBUG > 0)
                        clib_warning ("[%d] session %d specified in "
                                      "write_map is closed.", getpid (),
                                      session_index);
                      bits_set = VPPCOM_EBADFD;
                      goto select_done;
                    }

                  rv = vppcom_session_write_ready (session, session_index);
                  clib_spinlock_unlock (&vcm->sessions_lockp);
                  if (write_map && (rv > 0))
                    {
                      // TBD: clib_warning
                      clib_bitmap_set_no_check (write_map, session_index, 1);
                      bits_set++;
                    }
                }));
            }

          if (except_map)
            {
              clib_bitmap_foreach (session_index, vcm->ex_bitmap,
                ({
                  clib_spinlock_lock (&vcm->sessions_lockp);
                  rv = vppcom_session_at_index (session_index, &session);
                  if (rv < 0)
                    {
                      clib_spinlock_unlock (&vcm->sessions_lockp);
                      if (VPPCOM_DEBUG > 1)
                        clib_warning ("[%d] session %d specified in "
                                      "except_map is closed.", getpid (),
                                      session_index);
                      bits_set = VPPCOM_EBADFD;
                      goto select_done;
                    }

                  rv = vppcom_session_read_ready (session, session_index);
                  clib_spinlock_unlock (&vcm->sessions_lockp);
                  if (rv < 0)
                    {
                      // TBD: clib_warning
                      clib_bitmap_set_no_check (except_map, session_index, 1);
                      bits_set++;
                    }
                }));
            }
        }
      /* *INDENT-ON* */
    }
  while (clib_time_now (&vcm->clib_time) < timeout);

select_done:
  return (bits_set);
}

static inline void
vep_verify_epoll_chain (u32 vep_idx)
{
  session_t *session;
  vppcom_epoll_t *vep;
  int rv;
  u32 sid = vep_idx;

  if (VPPCOM_DEBUG <= 1)
    return;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  rv = vppcom_session_at_index (vep_idx, &session);
  if (PREDICT_FALSE (rv))
    {
      clib_warning ("[%d] ERROR: Invalid vep_idx (%u)!", getpid (), vep_idx);
      goto done;
    }
  if (PREDICT_FALSE (!session->is_vep))
    {
      clib_warning ("[%d] ERROR: vep_idx (%u) is not a vep!", getpid (),
		    vep_idx);
      goto done;
    }
  vep = &session->vep;
  clib_warning ("[%d] vep_idx (%u): Dumping epoll chain\n"
		"{\n"
		"   is_vep         = %u\n"
		"   is_vep_session = %u\n"
		"   next_sid       = 0x%x (%u)\n"
		"   wait_cont_idx  = 0x%x (%u)\n"
		"}\n", getpid (), vep_idx,
		session->is_vep, session->is_vep_session,
		vep->next_sid, vep->next_sid,
		session->wait_cont_idx, session->wait_cont_idx);

  for (sid = vep->next_sid; sid != ~0; sid = vep->next_sid)
    {
      rv = vppcom_session_at_index (sid, &session);
      if (PREDICT_FALSE (rv))
	{
	  clib_warning ("[%d] ERROR: Invalid sid (%u)!", getpid (), sid);
	  goto done;
	}
      if (PREDICT_FALSE (session->is_vep))
	clib_warning ("[%d] ERROR: sid (%u) is a vep!", getpid (), vep_idx);
      else if (PREDICT_FALSE (!session->is_vep_session))
	{
	  clib_warning ("[%d] ERROR: session (%u) is not a vep session!",
			getpid (), sid);
	  goto done;
	}
      vep = &session->vep;
      if (PREDICT_FALSE (vep->vep_idx != vep_idx))
	clib_warning ("[%d] ERROR: session (%u) vep_idx (%u) != "
		      "vep_idx (%u)!", getpid (),
		      sid, session->vep.vep_idx, vep_idx);
      if (session->is_vep_session)
	{
	  clib_warning ("vep_idx[%u]: sid 0x%x (%u)\n"
			"{\n"
			"   next_sid       = 0x%x (%u)\n"
			"   prev_sid       = 0x%x (%u)\n"
			"   vep_idx        = 0x%x (%u)\n"
			"   ev.events      = 0x%x\n"
			"   ev.data.u64    = 0x%llx\n"
			"   et_mask        = 0x%x\n"
			"}\n",
			vep_idx, sid, sid,
			vep->next_sid, vep->next_sid,
			vep->prev_sid, vep->prev_sid,
			vep->vep_idx, vep->vep_idx,
			vep->ev.events, vep->ev.data.u64, vep->et_mask);
	}
    }

done:
  clib_warning ("[%d] vep_idx (%u): Dump complete!\n", getpid (), vep_idx);
}

int
vppcom_epoll_create (void)
{
  session_t *vep_session;
  u32 vep_idx;

  clib_spinlock_lock (&vcm->sessions_lockp);
  pool_get (vcm->sessions, vep_session);
  memset (vep_session, 0, sizeof (*vep_session));
  vep_idx = vep_session - vcm->sessions;

  vep_session->is_vep = 1;
  vep_session->vep.vep_idx = ~0;
  vep_session->vep.next_sid = ~0;
  vep_session->vep.prev_sid = ~0;
  vep_session->wait_cont_idx = ~0;
  vep_session->vpp_handle = ~0;
  clib_spinlock_unlock (&vcm->sessions_lockp);

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] Created vep_idx %u / sid %u!",
		  getpid (), vep_idx, vep_idx);

  return (vep_idx);
}

int
vppcom_epoll_ctl (uint32_t vep_idx, int op, uint32_t session_index,
		  struct epoll_event *event)
{
  session_t *vep_session;
  session_t *session;
  int rv;

  if (vep_idx == session_index)
    {
      clib_warning ("[%d] ERROR: vep_idx == session_index (%u)!",
		    getpid (), vep_idx);
      return VPPCOM_EINVAL;
    }

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (vep_idx, &vep_session);
  if (PREDICT_FALSE (rv))
    {
      clib_warning ("[%d] ERROR: Invalid vep_idx (%u)!", vep_idx);
      goto done;
    }
  if (PREDICT_FALSE (!vep_session->is_vep))
    {
      clib_warning ("[%d] ERROR: vep_idx (%u) is not a vep!",
		    getpid (), vep_idx);
      rv = VPPCOM_EINVAL;
      goto done;
    }

  ASSERT (vep_session->vep.vep_idx == ~0);
  ASSERT (vep_session->vep.prev_sid == ~0);

  rv = vppcom_session_at_index (session_index, &session);
  if (PREDICT_FALSE (rv))
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] ERROR: Invalid session_index (%u)!",
		      getpid (), session_index);
      goto done;
    }
  if (PREDICT_FALSE (session->is_vep))
    {
      clib_warning ("ERROR: session_index (%u) is a vep!", vep_idx);
      rv = VPPCOM_EINVAL;
      goto done;
    }

  switch (op)
    {
    case EPOLL_CTL_ADD:
      if (PREDICT_FALSE (!event))
	{
	  clib_warning ("[%d] ERROR: EPOLL_CTL_ADD: NULL pointer to "
			"epoll_event structure!", getpid ());
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      if (vep_session->vep.next_sid != ~0)
	{
	  session_t *next_session;
	  rv = vppcom_session_at_index (vep_session->vep.next_sid,
					&next_session);
	  if (PREDICT_FALSE (rv))
	    {
	      clib_warning ("[%d] ERROR: EPOLL_CTL_ADD: Invalid "
			    "vep.next_sid (%u) on vep_idx (%u)!",
			    getpid (), vep_session->vep.next_sid, vep_idx);
	      goto done;
	    }
	  ASSERT (next_session->vep.prev_sid == vep_idx);
	  next_session->vep.prev_sid = session_index;
	}
      session->vep.next_sid = vep_session->vep.next_sid;
      session->vep.prev_sid = vep_idx;
      session->vep.vep_idx = vep_idx;
      session->vep.et_mask = VEP_DEFAULT_ET_MASK;
      session->vep.ev = *event;
      session->is_vep = 0;
      session->is_vep_session = 1;
      vep_session->vep.next_sid = session_index;
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] EPOLL_CTL_ADD: vep_idx %u, sid %u, events 0x%x,"
		      " data 0x%llx!", getpid (), vep_idx, session_index,
		      event->events, event->data.u64);
      break;

    case EPOLL_CTL_MOD:
      if (PREDICT_FALSE (!event))
	{
	  clib_warning ("[%d] ERROR: EPOLL_CTL_MOD: NULL pointer to "
			"epoll_event structure!", getpid ());
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      else if (PREDICT_FALSE (!session->is_vep_session))
	{
	  clib_warning ("[%d] ERROR: sid %u EPOLL_CTL_MOD: "
			"not a vep session!", getpid (), session_index);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      else if (PREDICT_FALSE (session->vep.vep_idx != vep_idx))
	{
	  clib_warning ("[%d] ERROR: sid %u EPOLL_CTL_MOD: "
			"vep_idx (%u) != vep_idx (%u)!",
			getpid (), session_index,
			session->vep.vep_idx, vep_idx);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      session->vep.et_mask = VEP_DEFAULT_ET_MASK;
      session->vep.ev = *event;
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] EPOLL_CTL_MOD: vep_idx %u, sid %u, events 0x%x,"
		      " data 0x%llx!", getpid (), vep_idx, session_index,
		      event->events, event->data.u64);
      break;

    case EPOLL_CTL_DEL:
      if (PREDICT_FALSE (!session->is_vep_session))
	{
	  clib_warning ("[%d] ERROR: sid %u EPOLL_CTL_DEL: "
			"not a vep session!", getpid (), session_index);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      else if (PREDICT_FALSE (session->vep.vep_idx != vep_idx))
	{
	  clib_warning ("[%d] ERROR: sid %u EPOLL_CTL_DEL: "
			"vep_idx (%u) != vep_idx (%u)!",
			getpid (), session_index,
			session->vep.vep_idx, vep_idx);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}

      vep_session->wait_cont_idx =
	(vep_session->wait_cont_idx == session_index) ?
	session->vep.next_sid : vep_session->wait_cont_idx;

      if (session->vep.prev_sid == vep_idx)
	vep_session->vep.next_sid = session->vep.next_sid;
      else
	{
	  session_t *prev_session;
	  rv = vppcom_session_at_index (session->vep.prev_sid, &prev_session);
	  if (PREDICT_FALSE (rv))
	    {
	      clib_warning ("[%d] ERROR: EPOLL_CTL_DEL: Invalid "
			    "vep.prev_sid (%u) on sid (%u)!",
			    getpid (), session->vep.prev_sid, session_index);
	      goto done;
	    }
	  ASSERT (prev_session->vep.next_sid == session_index);
	  prev_session->vep.next_sid = session->vep.next_sid;
	}
      if (session->vep.next_sid != ~0)
	{
	  session_t *next_session;
	  rv = vppcom_session_at_index (session->vep.next_sid, &next_session);
	  if (PREDICT_FALSE (rv))
	    {
	      clib_warning ("[%d] ERROR: EPOLL_CTL_DEL: Invalid "
			    "vep.next_sid (%u) on sid (%u)!",
			    getpid (), session->vep.next_sid, session_index);
	      goto done;
	    }
	  ASSERT (next_session->vep.prev_sid == session_index);
	  next_session->vep.prev_sid = session->vep.prev_sid;
	}

      memset (&session->vep, 0, sizeof (session->vep));
      session->vep.next_sid = ~0;
      session->vep.prev_sid = ~0;
      session->vep.vep_idx = ~0;
      session->is_vep_session = 0;
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] EPOLL_CTL_DEL: vep_idx %u, sid %u!",
		      getpid (), vep_idx, session_index);
      break;

    default:
      clib_warning ("[%d] ERROR: Invalid operation (%d)!", getpid (), op);
      rv = VPPCOM_EINVAL;
    }

  vep_verify_epoll_chain (vep_idx);

done:
  clib_spinlock_unlock (&vcm->sessions_lockp);
  return rv;
}

int
vppcom_epoll_wait (uint32_t vep_idx, struct epoll_event *events,
		   int maxevents, double wait_for_time)
{
  session_t *vep_session;
  int rv;
  f64 timeout = clib_time_now (&vcm->clib_time) + wait_for_time;
  u32 keep_trying = 1;
  int num_ev = 0;
  u32 vep_next_sid, wait_cont_idx;
  u8 is_vep;

  if (PREDICT_FALSE (maxevents <= 0))
    {
      clib_warning ("[%d] ERROR: Invalid maxevents (%d)!",
		    getpid (), maxevents);
      return VPPCOM_EINVAL;
    }
  memset (events, 0, sizeof (*events) * maxevents);

  VCL_LOCK_AND_GET_SESSION (vep_idx, &vep_session);
  vep_next_sid = vep_session->vep.next_sid;
  is_vep = vep_session->is_vep;
  wait_cont_idx = vep_session->wait_cont_idx;
  clib_spinlock_unlock (&vcm->sessions_lockp);

  if (PREDICT_FALSE (!is_vep))
    {
      clib_warning ("[%d] ERROR: vep_idx (%u) is not a vep!",
		    getpid (), vep_idx);
      rv = VPPCOM_EINVAL;
      goto done;
    }
  if (PREDICT_FALSE (vep_next_sid == ~0))
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] WARNING: vep_idx (%u) is empty!",
		      getpid (), vep_idx);
      goto done;
    }

  do
    {
      u32 sid;
      u32 next_sid = ~0;
      session_t *session;

      for (sid = (wait_cont_idx == ~0) ? vep_next_sid : wait_cont_idx;
	   sid != ~0; sid = next_sid)
	{
	  u32 session_events, et_mask, clear_et_mask, session_vep_idx;
	  u8 add_event, is_vep_session;
	  int ready;
	  u64 session_ev_data;

	  VCL_LOCK_AND_GET_SESSION (sid, &session);
	  next_sid = session->vep.next_sid;
	  session_events = session->vep.ev.events;
	  et_mask = session->vep.et_mask;
	  is_vep = session->is_vep;
	  is_vep_session = session->is_vep_session;
	  session_vep_idx = session->vep.vep_idx;
	  session_ev_data = session->vep.ev.data.u64;
	  clib_spinlock_unlock (&vcm->sessions_lockp);

	  if (PREDICT_FALSE (is_vep))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] ERROR: sid (%u) is a vep!",
			      getpid (), vep_idx);
	      rv = VPPCOM_EINVAL;
	      goto done;
	    }
	  if (PREDICT_FALSE (!is_vep_session))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] ERROR: session (%u) is not "
			      "a vep session!", getpid (), sid);
	      rv = VPPCOM_EINVAL;
	      goto done;
	    }
	  if (PREDICT_FALSE (session_vep_idx != vep_idx))
	    {
	      clib_warning ("[%d] ERROR: session (%u) "
			    "vep_idx (%u) != vep_idx (%u)!",
			    getpid (), sid, session->vep.vep_idx, vep_idx);
	      rv = VPPCOM_EINVAL;
	      goto done;
	    }

	  add_event = clear_et_mask = 0;

	  if (EPOLLIN & session_events)
	    {
	      VCL_LOCK_AND_GET_SESSION (sid, &session);
	      ready = vppcom_session_read_ready (session, sid);
	      clib_spinlock_unlock (&vcm->sessions_lockp);
	      if ((ready > 0) && (EPOLLIN & et_mask))
		{
		  add_event = 1;
		  events[num_ev].events |= EPOLLIN;
		  if (((EPOLLET | EPOLLIN) & session_events) ==
		      (EPOLLET | EPOLLIN))
		    clear_et_mask |= EPOLLIN;
		}
	      else if (ready < 0)
		{
		  add_event = 1;
		  switch (ready)
		    {
		    case VPPCOM_ECONNRESET:
		      events[num_ev].events |= EPOLLHUP | EPOLLRDHUP;
		      break;

		    default:
		      events[num_ev].events |= EPOLLERR;
		      break;
		    }
		}
	    }

	  if (EPOLLOUT & session_events)
	    {
	      VCL_LOCK_AND_GET_SESSION (sid, &session);
	      ready = vppcom_session_write_ready (session, sid);
	      clib_spinlock_unlock (&vcm->sessions_lockp);
	      if ((ready > 0) && (EPOLLOUT & et_mask))
		{
		  add_event = 1;
		  events[num_ev].events |= EPOLLOUT;
		  if (((EPOLLET | EPOLLOUT) & session_events) ==
		      (EPOLLET | EPOLLOUT))
		    clear_et_mask |= EPOLLOUT;
		}
	      else if (ready < 0)
		{
		  add_event = 1;
		  switch (ready)
		    {
		    case VPPCOM_ECONNRESET:
		      events[num_ev].events |= EPOLLHUP;
		      break;

		    default:
		      events[num_ev].events |= EPOLLERR;
		      break;
		    }
		}
	    }

	  if (add_event)
	    {
	      events[num_ev].data.u64 = session_ev_data;
	      if (EPOLLONESHOT & session_events)
		{
		  VCL_LOCK_AND_GET_SESSION (sid, &session);
		  session->vep.ev.events = 0;
		  clib_spinlock_unlock (&vcm->sessions_lockp);
		}
	      num_ev++;
	      if (num_ev == maxevents)
		{
		  VCL_LOCK_AND_GET_SESSION (vep_idx, &vep_session);
		  vep_session->wait_cont_idx = next_sid;
		  clib_spinlock_unlock (&vcm->sessions_lockp);
		  goto done;
		}
	    }
	  if (wait_cont_idx != ~0)
	    {
	      if (next_sid == ~0)
		next_sid = vep_next_sid;
	      else if (next_sid == wait_cont_idx)
		next_sid = ~0;
	    }
	}
      if (wait_for_time != -1)
	keep_trying = (clib_time_now (&vcm->clib_time) <= timeout) ? 1 : 0;
    }
  while ((num_ev == 0) && keep_trying);

  if (wait_cont_idx != ~0)
    {
      VCL_LOCK_AND_GET_SESSION (vep_idx, &vep_session);
      vep_session->wait_cont_idx = ~0;
      clib_spinlock_unlock (&vcm->sessions_lockp);
    }
done:
  return (rv != VPPCOM_OK) ? rv : num_ev;
}

int
vppcom_session_attr (uint32_t session_index, uint32_t op,
		     void *buffer, uint32_t * buflen)
{
  session_t *session;
  int rv = VPPCOM_OK;
  u32 *flags = buffer;
  vppcom_endpt_t *ep = buffer;

  VCL_LOCK_AND_GET_SESSION (session_index, &session);
  switch (op)
    {
    case VPPCOM_ATTR_GET_NREAD:
      rv = vppcom_session_read_ready (session, session_index);
      if (VPPCOM_DEBUG > 2)
	clib_warning ("[%d] VPPCOM_ATTR_GET_NREAD: sid %u, nread = %d",
		      getpid (), rv);
      break;

    case VPPCOM_ATTR_GET_NWRITE:
      rv = vppcom_session_write_ready (session, session_index);
      if (VPPCOM_DEBUG > 2)
	clib_warning ("[%d] VPPCOM_ATTR_GET_NWRITE: sid %u, nwrite = %d",
		      getpid (), session_index, rv);
      break;

    case VPPCOM_ATTR_GET_FLAGS:
      if (buffer && buflen && (*buflen >= sizeof (*flags)))
	{
	  *flags = O_RDWR | ((session->is_nonblocking) ? O_NONBLOCK : 0);
	  *buflen = sizeof (*flags);
	  if (VPPCOM_DEBUG > 2)
	    clib_warning ("[%d] VPPCOM_ATTR_GET_FLAGS: sid %u, "
			  "flags = 0x%08x, is_nonblocking = %u", getpid (),
			  session_index, *flags, session->is_nonblocking);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_FLAGS:
      if (buffer && buflen && (*buflen >= sizeof (*flags)))
	{
	  session->is_nonblocking = (*flags & O_NONBLOCK) ? 1 : 0;
	  if (VPPCOM_DEBUG > 2)
	    clib_warning ("[%d] VPPCOM_ATTR_SET_FLAGS: sid %u, "
			  "flags = 0x%08x, is_nonblocking = %u",
			  getpid (), session_index, *flags,
			  session->is_nonblocking);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_PEER_ADDR:
      if (buffer && buflen && (*buflen >= sizeof (*ep)))
	{
	  ep->vrf = session->vrf;
	  ep->is_ip4 = session->peer_addr.is_ip4;
	  ep->port = session->peer_port;
	  if (session->peer_addr.is_ip4)
	    clib_memcpy (ep->ip, &session->peer_addr.ip46.ip4,
			 sizeof (ip4_address_t));
	  else
	    clib_memcpy (ep->ip, &session->peer_addr.ip46.ip6,
			 sizeof (ip6_address_t));
	  *buflen = sizeof (*ep);
	  if (VPPCOM_DEBUG > 1)
	    clib_warning ("[%d] VPPCOM_ATTR_GET_PEER_ADDR: sid %u, is_ip4 = "
			  "%u, addr = %U, port %u", getpid (),
			  session_index, ep->is_ip4, format_ip46_address,
			  &session->peer_addr.ip46, ep->is_ip4,
			  clib_net_to_host_u16 (ep->port));
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_LCL_ADDR:
      if (buffer && buflen && (*buflen >= sizeof (*ep)))
	{
	  ep->vrf = session->vrf;
	  ep->is_ip4 = session->lcl_addr.is_ip4;
	  ep->port = session->lcl_port;
	  if (session->lcl_addr.is_ip4)
	    clib_memcpy (ep->ip, &session->lcl_addr.ip46.ip4,
			 sizeof (ip4_address_t));
	  else
	    clib_memcpy (ep->ip, &session->lcl_addr.ip46.ip6,
			 sizeof (ip6_address_t));
	  *buflen = sizeof (*ep);
	  if (VPPCOM_DEBUG > 1)
	    clib_warning ("[%d] VPPCOM_ATTR_GET_LCL_ADDR: sid %u, is_ip4 = "
			  "%u, addr = %U port %d", getpid (),
			  session_index, ep->is_ip4, format_ip46_address,
			  &session->lcl_addr.ip46, ep->is_ip4,
			  clib_net_to_host_u16 (ep->port));
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_REUSEADDR:
      break;

    case VPPCOM_ATTR_SET_BROADCAST:
      break;

    case VPPCOM_ATTR_SET_V6ONLY:
      break;

    case VPPCOM_ATTR_SET_KEEPALIVE:
      break;

    case VPPCOM_ATTR_SET_TCP_KEEPIDLE:
      break;

    case VPPCOM_ATTR_SET_TCP_KEEPINTVL:
      break;

    default:
      rv = VPPCOM_EINVAL;
      break;
    }

done:
  clib_spinlock_unlock (&vcm->sessions_lockp);
  return rv;
}

int
vppcom_session_recvfrom (uint32_t session_index, void *buffer,
			 uint32_t buflen, int flags, vppcom_endpt_t * ep)
{
  int rv = VPPCOM_OK;
  session_t *session = 0;

  if (ep)
    {
      clib_spinlock_lock (&vcm->sessions_lockp);
      rv = vppcom_session_at_index (session_index, &session);
      if (PREDICT_FALSE (rv))
	{
	  clib_spinlock_unlock (&vcm->sessions_lockp);
	  if (VPPCOM_DEBUG > 0)
	    clib_warning ("[%d] invalid session, sid (%u) has been closed!",
			  getpid (), session_index);
	  rv = VPPCOM_EBADFD;
	  clib_spinlock_unlock (&vcm->sessions_lockp);
	  goto done;
	}
      ep->vrf = session->vrf;
      ep->is_ip4 = session->peer_addr.is_ip4;
      ep->port = session->peer_port;
      if (session->peer_addr.is_ip4)
	clib_memcpy (ep->ip, &session->peer_addr.ip46.ip4,
		     sizeof (ip4_address_t));
      else
	clib_memcpy (ep->ip, &session->peer_addr.ip46.ip6,
		     sizeof (ip6_address_t));
      clib_spinlock_unlock (&vcm->sessions_lockp);
    }

  if (flags == 0)
    rv = vppcom_session_read (session_index, buffer, buflen);
  else if (flags & MSG_PEEK)
    rv = vppcom_session_peek (session_index, buffer, buflen);
  else
    {
      clib_warning ("[%d] Unsupport flags for recvfrom %d", getpid (), flags);
      rv = VPPCOM_EAFNOSUPPORT;
    }

done:
  return rv;
}

int
vppcom_session_sendto (uint32_t session_index, void *buffer,
		       uint32_t buflen, int flags, vppcom_endpt_t * ep)
{
  if (!buffer)
    return VPPCOM_EINVAL;

  if (ep)
    {
      // TBD
      return VPPCOM_EINVAL;
    }

  if (flags)
    {
      // TBD check the flags and do the right thing
      if (VPPCOM_DEBUG > 2)
	clib_warning ("[%d] handling flags 0x%u (%d) not implemented yet.",
		      getpid (), flags, flags);
    }

  return (vppcom_session_write (session_index, buffer, buflen));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
