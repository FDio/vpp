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
#include <uri/vppcom.h>
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
/* Set VPPCOM_DEBUG 2 for connection debug, 3 for read/write debug output */
#define VPPCOM_DEBUG 1
#else
#define VPPCOM_DEBUG 0
#endif

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
  STATE_START,
  STATE_CONNECT,
  STATE_LISTEN,
  STATE_ACCEPT,
  STATE_DISCONNECT,
  STATE_FAILED
} session_state_t;

typedef struct
{
  volatile session_state_t state;

  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;
  u32 sm_seg_index;
  u64 vpp_session_handle;
  unix_shared_memory_queue_t *vpp_event_queue;

  /* Socket configuration state */
  u8 is_server;
  u8 is_listen;
  u8 is_cut_thru;
  u8 is_nonblocking;
  u32 vrf;
  u8 is_ip4;
  u8 ip[16];
  u16 port;
  u8 proto;
  u64 client_queue_address;
  u64 options[16];
} session_t;

typedef struct vppcom_cfg_t_
{
  u64 heapsize;
  u64 segment_baseva;
  u32 segment_size;
  u32 add_segment_size;
  u32 preallocated_fifo_pairs;
  u32 rx_fifo_size;
  u32 tx_fifo_size;
  u32 event_queue_size;
  u32 listen_queue_size;
  f64 app_timeout;
  f64 session_timeout;
  f64 accept_timeout;
} vppcom_cfg_t;

typedef struct vppcom_main_t_
{
  u8 init;
  u32 *client_session_index_fifo;
  volatile u32 bind_session_index;
  u32 tx_event_id;
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

  pid_t my_pid;

  /* For deadman timers */
  clib_time_t clib_time;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile app_state_t app_state;

  vppcom_cfg_t cfg;

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;
} vppcom_main_t;

vppcom_main_t vppcom_main = {.my_client_index = ~0 };

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
  vppcom_main_t *vcm = &vppcom_main;

  /* Assumes that caller has acquired spinlock: vcm->sessions_lockp */
  if (PREDICT_FALSE ((session_index == ~0) ||
		     pool_is_free_index (vcm->sessions, session_index)))
    {
      clib_warning ("[%d] invalid session, sid (%d) has been closed!",
		    vcm->my_pid, session_index);
      return VPPCOM_EBADFD;
    }
  *sess = pool_elt_at_index (vcm->sessions, session_index);
  return VPPCOM_OK;
}

static int
vppcom_connect_to_vpp (char *app_name)
{
  api_main_t *am = &api_main;
  vppcom_main_t *vcm = &vppcom_main;

  if (VPPCOM_DEBUG > 0)
    printf ("\nConnecting to VPP api...");
  if (vl_client_connect_to_vlib ("/vpe-api", app_name, 32) < 0)
    {
      clib_warning ("[%d] connect to vpp (%s) failed!",
		    vcm->my_pid, app_name);
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
  vppcom_main_t *vcm = &vppcom_main;
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
  vppcom_main_t *vcm = &vppcom_main;

  vcm->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n,v,s) hash_set (vcm->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (vcm->error_string_by_error_number, 99, "Misc");
}

static inline int
vppcom_wait_for_app_state_change (app_state_t app_state)
{
  vppcom_main_t *vcm = &vppcom_main;
  f64 timeout = clib_time_now (&vcm->clib_time) + vcm->cfg.app_timeout;

  while (clib_time_now (&vcm->clib_time) < timeout)
    {
      if (vcm->app_state == app_state)
	return VPPCOM_OK;
    }
  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] timeout waiting for state %s (%d)", vcm->my_pid,
		  vppcom_app_state_str (app_state), app_state);
  return VPPCOM_ETIMEDOUT;
}

static inline int
vppcom_wait_for_session_state_change (u32 session_index,
				      session_state_t state,
				      f64 wait_for_time)
{
  vppcom_main_t *vcm = &vppcom_main;
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
      clib_spinlock_unlock (&vcm->sessions_lockp);
    }
  while (clib_time_now (&vcm->clib_time) < timeout);

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] timeout waiting for state %s (%d)", vcm->my_pid,
		  vppcom_session_state_str (state), state);
  return VPPCOM_ETIMEDOUT;
}

static inline int
vppcom_wait_for_client_session_index (f64 wait_for_time)
{
  vppcom_main_t *vcm = &vppcom_main;
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
    clib_warning ("[%d] timeout waiting for client_session_index",
		  vcm->my_pid);
  return VPPCOM_ETIMEDOUT;
}

/*
 * VPP-API message functions
 */
static void
vppcom_send_session_enable_disable (u8 is_enable)
{
  vppcom_main_t *vcm = &vppcom_main;
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
  vppcom_main_t *vcm = &vppcom_main;
  int rv;

  if (vcm->app_state != STATE_APP_ENABLED)
    {
      vppcom_send_session_enable_disable (1 /* is_enabled == TRUE */ );
      rv = vppcom_wait_for_app_state_change (STATE_APP_ENABLED);
      if (PREDICT_FALSE (rv))
	{
	  if (VPPCOM_DEBUG > 0)
	    clib_warning ("[%d] Session enable timed out, rv = %s (%d)",
			  vcm->my_pid, vppcom_retval_str (rv), rv);
	  return rv;
	}
    }
  return VPPCOM_OK;
}

static void
  vl_api_session_enable_disable_reply_t_handler
  (vl_api_session_enable_disable_reply_t * mp)
{
  vppcom_main_t *vcm = &vppcom_main;

  if (mp->retval)
    {
      clib_warning ("[%d] session_enable_disable failed: %U", vcm->my_pid,
		    format_api_error, ntohl (mp->retval));
    }
  else
    vcm->app_state = STATE_APP_ENABLED;
}

static void
vppcom_app_send_attach (void)
{
  vppcom_main_t *vcm = &vppcom_main;
  vl_api_application_attach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_ATTACH);
  bmp->client_index = vcm->my_client_index;
  bmp->context = htonl (0xfeedface);
  bmp->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_USE_FIFO | APP_OPTIONS_FLAGS_ADD_SEGMENT;
  bmp->options[SESSION_OPTIONS_SEGMENT_SIZE] = vcm->cfg.segment_size;
  bmp->options[SESSION_OPTIONS_ADD_SEGMENT_SIZE] = vcm->cfg.add_segment_size;
  bmp->options[SESSION_OPTIONS_RX_FIFO_SIZE] = vcm->cfg.rx_fifo_size;
  bmp->options[SESSION_OPTIONS_TX_FIFO_SIZE] = vcm->cfg.tx_fifo_size;
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & bmp);
}

static int
vppcom_app_attach (void)
{
  vppcom_main_t *vcm = &vppcom_main;
  int rv;

  vppcom_app_send_attach ();
  rv = vppcom_wait_for_app_state_change (STATE_APP_ATTACHED);
  if (PREDICT_FALSE (rv))
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] application attach timed out, rv = %s (%d)",
		      vcm->my_pid, vppcom_retval_str (rv), rv);
      return rv;
    }
  return VPPCOM_OK;
}

static void
vppcom_app_detach (void)
{
  vppcom_main_t *vcm = &vppcom_main;
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
  vppcom_main_t *vcm = &vppcom_main;
  static svm_fifo_segment_create_args_t _a;
  svm_fifo_segment_create_args_t *a = &_a;
  int rv;

  memset (a, 0, sizeof (*a));
  if (mp->retval)
    {
      clib_warning ("[%d] attach failed: %U", vcm->my_pid,
		    format_api_error, ntohl (mp->retval));
      return;
    }

  if (mp->segment_name_length == 0)
    {
      clib_warning ("[%d] segment_name_length zero", vcm->my_pid);
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
      clib_warning ("[%d] svm_fifo_segment_attach ('%s') failed", vcm->my_pid,
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
  vppcom_main_t *vcm = &vppcom_main;

  if (mp->retval)
    clib_warning ("[%d] detach failed: %U", vcm->my_pid, format_api_error,
		  ntohl (mp->retval));

  vcm->app_state = STATE_APP_ENABLED;
}

static void
vl_api_disconnect_session_reply_t_handler (vl_api_disconnect_session_reply_t *
					   mp)
{
  vppcom_main_t *vcm = &vppcom_main;
  uword *p;

  p = hash_get (vcm->session_index_by_vpp_handles, mp->handle);
  if (p)
    {
      session_t *session = 0;
      int rv;
      clib_spinlock_lock (&vcm->sessions_lockp);
      rv = vppcom_session_at_index (p[0], &session);
      if (PREDICT_FALSE (rv))
	{
	  if (VPPCOM_DEBUG > 1)
	    clib_warning ("[%d] invalid session, sid (%d) has been closed!",
			  vcm->my_pid, p[0]);
	}
      hash_unset (vcm->session_index_by_vpp_handles, mp->handle);
      session->state = STATE_DISCONNECT;
      clib_spinlock_unlock (&vcm->sessions_lockp);
    }
  else
    {
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] couldn't find session key %llx", vcm->my_pid,
		      mp->handle);
    }

  if (mp->retval)
    clib_warning ("[%d] disconnect_session failed: %U", vcm->my_pid,
		  format_api_error, ntohl (mp->retval));
}

static void
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t * mp)
{
  vppcom_main_t *vcm = &vppcom_main;
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
		    vcm->my_pid, mp->segment_name);
      return;
    }
  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] mapped new segment '%s' size %d", vcm->my_pid,
		  mp->segment_name, mp->segment_size);
}

static void
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  vppcom_main_t *vcm = &vppcom_main;
  session_t *session = 0;
  vl_api_disconnect_session_reply_t *rmp;
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
	  if (VPPCOM_DEBUG > 1)
	    clib_warning ("[%d] invalid session, sid (%d) has been closed!",
			  vcm->my_pid, p[0]);
	}
      else
	pool_put (vcm->sessions, session);
      clib_spinlock_unlock (&vcm->sessions_lockp);
      hash_unset (vcm->session_index_by_vpp_handles, mp->handle);
    }
  else
    {
      clib_warning ("[%d] couldn't find session key %llx", vcm->my_pid,
		    mp->handle);
      rv = -11;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION_REPLY);
  rmp->retval = htonl (rv);
  rmp->handle = mp->handle;
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & rmp);
}

static void
vl_api_reset_session_t_handler (vl_api_reset_session_t * mp)
{
  vppcom_main_t *vcm = &vppcom_main;
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
	  if (VPPCOM_DEBUG > 1)
	    clib_warning ("[%d] invalid session, sid (%d) has been closed!",
			  vcm->my_pid, p[0]);
	}
      else
	pool_put (vcm->sessions, session);
      clib_spinlock_unlock (&vcm->sessions_lockp);
      hash_unset (vcm->session_index_by_vpp_handles, mp->handle);
    }
  else
    {
      clib_warning ("[%d] couldn't find session key %llx", vcm->my_pid,
		    mp->handle);
      rv = -11;
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
  vppcom_main_t *vcm = &vppcom_main;
  session_t *session;
  u32 session_index;
  svm_fifo_t *rx_fifo, *tx_fifo;
  u8 is_cut_thru = 0;
  int rv;

  if (mp->retval)
    {
      clib_warning ("[%d] connect failed: %U", vcm->my_pid, format_api_error,
		    ntohl (mp->retval));
      return;
    }

  session_index = mp->context;
  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] session_index = %d 0x%08x", vcm->my_pid,
		  session_index, session_index);

  clib_spinlock_lock (&vcm->sessions_lockp);
  if (pool_is_free_index (vcm->sessions, session_index))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] invalid session, sid %d is closed!",
		      vcm->my_pid, session_index);
      return;
    }

  /* We've been redirected */
  if (mp->segment_name_length > 0)
    {
      static svm_fifo_segment_create_args_t _a;
      svm_fifo_segment_create_args_t *a = &_a;

      is_cut_thru = 1;
      memset (a, 0, sizeof (*a));
      a->segment_name = (char *) mp->segment_name;
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] cut-thru segment: %s", vcm->my_pid,
		      a->segment_name);
      rv = svm_fifo_segment_attach (a);
      vec_reset_length (a->new_segment_indices);
      if (PREDICT_FALSE (rv))
	{
	  clib_warning ("[%d] sm_fifo_segment_attach ('%s') failed",
			vcm->my_pid, a->segment_name);
	  return;
	}
    }

  /*
   * Setup session
   */
  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] client sid %d", vcm->my_pid, session_index);

  session = pool_elt_at_index (vcm->sessions, session_index);
  session->is_cut_thru = is_cut_thru;
  session->vpp_event_queue = uword_to_pointer (mp->vpp_event_queue_address,
					       unix_shared_memory_queue_t *);

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->server_rx_fifo = rx_fifo;
  session->server_tx_fifo = tx_fifo;
  session->vpp_session_handle = mp->handle;
  session->state = STATE_CONNECT;

  /* Add it to lookup table */
  hash_set (vcm->session_index_by_vpp_handles, mp->handle, session_index);
  clib_spinlock_unlock (&vcm->sessions_lockp);
}

static void
vppcom_send_connect_sock (session_t * session, u32 session_index)
{
  vppcom_main_t *vcm = &vppcom_main;
  vl_api_connect_sock_t *cmp;

  /* Assumes caller as acquired the spinlock: vcm->sessions_lockp */
  session->is_server = 0;
  cmp = vl_msg_api_alloc (sizeof (*cmp));
  memset (cmp, 0, sizeof (*cmp));
  cmp->_vl_msg_id = ntohs (VL_API_CONNECT_SOCK);
  cmp->client_index = vcm->my_client_index;
  cmp->context = session_index;

  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] session_index = %d 0x%08x",
		  vcm->my_pid, session_index, session_index);

  cmp->vrf = session->vrf;
  cmp->is_ip4 = session->is_ip4;
  clib_memcpy (cmp->ip, session->ip, sizeof (cmp->ip));
  cmp->port = session->port;
  cmp->proto = session->proto;
  clib_memcpy (cmp->options, session->options, sizeof (cmp->options));
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & cmp);
}

static int
vppcom_send_disconnect (u32 session_index)
{
  vppcom_main_t *vcm = &vppcom_main;
  vl_api_disconnect_session_t *dmp;
  session_t *session = 0;
  int rv;

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (session_index, &session);
  if (PREDICT_FALSE (rv))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] invalid session, sid (%d) has been closed!",
		      vcm->my_pid, session_index);
      return rv;
    }

  dmp = vl_msg_api_alloc (sizeof (*dmp));
  memset (dmp, 0, sizeof (*dmp));
  dmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION);
  dmp->client_index = vcm->my_client_index;
  dmp->handle = session->vpp_session_handle;
  clib_spinlock_unlock (&vcm->sessions_lockp);
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & dmp);
  return VPPCOM_OK;
}

static void
vl_api_bind_sock_reply_t_handler (vl_api_bind_sock_reply_t * mp)
{
  vppcom_main_t *vcm = &vppcom_main;
  session_t *session = 0;
  int rv;

  if (mp->retval)
    clib_warning ("[%d] bind failed: %U", vcm->my_pid, format_api_error,
		  ntohl (mp->retval));

  ASSERT (vcm->bind_session_index != ~0);

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (vcm->bind_session_index, &session);
  if (rv == VPPCOM_OK)
    {
      session->vpp_session_handle = mp->handle;
      hash_set (vcm->session_index_by_vpp_handles, mp->handle,
		vcm->bind_session_index);
      session->state = mp->retval ? STATE_FAILED : STATE_LISTEN;
      vcm->bind_session_index = ~0;
    }
  clib_spinlock_unlock (&vcm->sessions_lockp);
}

static void
vl_api_unbind_sock_reply_t_handler (vl_api_unbind_sock_reply_t * mp)
{
  vppcom_main_t *vcm = &vppcom_main;
  session_t *session = 0;
  int rv;

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (vcm->bind_session_index, &session);
  if (rv == VPPCOM_OK)
    {
      if ((VPPCOM_DEBUG > 1) && (mp->retval))
	clib_warning ("[%d] unbind failed: %U", vcm->my_pid, format_api_error,
		      ntohl (mp->retval));

      vcm->bind_session_index = ~0;
      session->state = STATE_START;
    }
  clib_spinlock_unlock (&vcm->sessions_lockp);
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

static void
vl_api_accept_session_t_handler (vl_api_accept_session_t * mp)
{
  vppcom_main_t *vcm = &vppcom_main;
  vl_api_accept_session_reply_t *rmp;
  svm_fifo_t *rx_fifo, *tx_fifo;
  session_t *session;
  u32 session_index;
  int rv = 0;

  if (!clib_fifo_free_elts (vcm->client_session_index_fifo))
    {
      clib_warning ("[%d] client session queue is full!", vcm->my_pid);
      rv = VNET_API_ERROR_QUEUE_FULL;
      goto send_reply;
    }

  if (VPPCOM_DEBUG > 1)
    {
      u8 *ip_str = format (0, "%U", format_ip46_address, &mp->ip, mp->is_ip4);
      clib_warning ("[%d] accepted session from: %s:%d", vcm->my_pid, ip_str,
		    clib_net_to_host_u16 (mp->port));
      vec_free (ip_str);
    }

  clib_spinlock_lock (&vcm->sessions_lockp);
  /* Allocate local session and set it up */
  pool_get (vcm->sessions, session);
  memset (session, 0, sizeof (*session));
  session_index = session - vcm->sessions;

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->server_rx_fifo = rx_fifo;
  session->server_tx_fifo = tx_fifo;
  session->vpp_event_queue = uword_to_pointer (mp->vpp_event_queue_address,
					       unix_shared_memory_queue_t *);
  session->state = STATE_ACCEPT;
  session->is_cut_thru = 0;
  session->is_server = 1;
  session->port = ntohs (mp->port);
  session->is_ip4 = mp->is_ip4;
  clib_memcpy (session->ip, mp->ip, sizeof (session->ip));
  clib_spinlock_unlock (&vcm->sessions_lockp);

  /* Add it to lookup table */
  hash_set (vcm->session_index_by_vpp_handles, mp->handle, session_index);

  clib_fifo_add1 (vcm->client_session_index_fifo, session_index);

  /*
   * Send accept reply to vpp
   */
send_reply:
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ACCEPT_SESSION_REPLY);
  rmp->retval = htonl (rv);
  rmp->handle = mp->handle;
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & rmp);
}

/*
 * Acting as server for redirected connect requests
 */
static void
vl_api_connect_sock_t_handler (vl_api_connect_sock_t * mp)
{
  static svm_fifo_segment_create_args_t _a;
  svm_fifo_segment_create_args_t *a = &_a;
  vppcom_main_t *vcm = &vppcom_main;
  u32 session_index;
  svm_fifo_segment_private_t *seg;
  unix_shared_memory_queue_t *client_q;
  vl_api_connect_session_reply_t *rmp;
  session_t *session = 0;
  int rv = 0;
  svm_fifo_t *rx_fifo;
  svm_fifo_t *tx_fifo;
  unix_shared_memory_queue_t *event_q = 0;

  if (!clib_fifo_free_elts (vcm->client_session_index_fifo))
    {
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] client session queue is full!", vcm->my_pid);
      rv = VNET_API_ERROR_QUEUE_FULL;
      goto send_reply;
    }

  /* Create the segment */
  memset (a, 0, sizeof (*a));
  a->segment_name = (char *) format ((u8 *) a->segment_name, "%d:segment%d%c",
				     vcm->my_pid, vcm->unique_segment_index++,
				     0);
  a->segment_size = vcm->cfg.segment_size;
  a->preallocated_fifo_pairs = vcm->cfg.preallocated_fifo_pairs;
  a->rx_fifo_size = vcm->cfg.rx_fifo_size;
  a->tx_fifo_size = vcm->cfg.tx_fifo_size;

  rv = svm_fifo_segment_create (a);
  if (PREDICT_FALSE (rv))
    {
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] svm_fifo_segment_create ('%s') failed",
		      vcm->my_pid, a->segment_name);
      vec_reset_length (a->new_segment_indices);
      rv = VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
      goto send_reply;
    }

  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] created segment '%s'", vcm->my_pid, a->segment_name);

  clib_spinlock_lock (&vcm->sessions_lockp);
  pool_get (vcm->sessions, session);
  memset (session, 0, sizeof (*session));
  session_index = session - vcm->sessions;

  session->sm_seg_index = a->new_segment_indices[0];
  vec_reset_length (a->new_segment_indices);

  seg = svm_fifo_segment_get_segment (session->sm_seg_index);
  rx_fifo = session->server_rx_fifo =
    svm_fifo_segment_alloc_fifo (seg, vcm->cfg.rx_fifo_size,
				 FIFO_SEGMENT_RX_FREELIST);
  if (PREDICT_FALSE (!session->server_rx_fifo))
    {
      svm_fifo_segment_delete (seg);
      clib_warning ("[%d] rx fifo alloc failed, size %ld (0x%lx)",
		    vcm->my_pid, vcm->cfg.rx_fifo_size,
		    vcm->cfg.rx_fifo_size);
      rv = VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
      clib_spinlock_unlock (&vcm->sessions_lockp);
      goto send_reply;
    }

  tx_fifo = session->server_tx_fifo =
    svm_fifo_segment_alloc_fifo (seg, vcm->cfg.tx_fifo_size,
				 FIFO_SEGMENT_TX_FREELIST);
  if (PREDICT_FALSE (!session->server_tx_fifo))
    {
      svm_fifo_segment_delete (seg);
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] tx fifo alloc failed, size %ld (0x%lx)",
		      vcm->my_pid, vcm->cfg.tx_fifo_size,
		      vcm->cfg.tx_fifo_size);
      rv = VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
      clib_spinlock_unlock (&vcm->sessions_lockp);
      goto send_reply;
    }

  session->server_rx_fifo->master_session_index = session_index;
  session->server_tx_fifo->master_session_index = session_index;
  session->client_queue_address = mp->client_queue_address;
  session->is_cut_thru = 1;
  session->is_server = 1;
  session->is_ip4 = mp->is_ip4;
  session->port = mp->port;
  {
    void *oldheap;
    ssvm_shared_header_t *sh = seg->ssvm.sh;

    ssvm_lock_non_recursive (sh, 1);
    oldheap = ssvm_push_heap (sh);
    event_q = session->vpp_event_queue =
      unix_shared_memory_queue_init (vcm->cfg.event_queue_size,
				     sizeof (session_fifo_event_t),
				     vcm->my_pid, 0 /* signal not sent */ );
    ssvm_pop_heap (oldheap);
    ssvm_unlock_non_recursive (sh);
  }
  clib_memcpy (session->ip, mp->ip, sizeof (session->ip));

  session->state = STATE_ACCEPT;
  if (VPPCOM_DEBUG > 1)
    clib_warning ("[%d] Connected cut-thru to client: sid %d",
		  vcm->my_pid, session_index);
  clib_spinlock_unlock (&vcm->sessions_lockp);
  clib_fifo_add1 (vcm->client_session_index_fifo, session_index);

send_reply:
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id = ntohs (VL_API_CONNECT_SESSION_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  rmp->segment_name_length = vec_len (a->segment_name);
  clib_memcpy (rmp->segment_name, a->segment_name, vec_len (a->segment_name));
  vec_reset_length (a->segment_name);

  if (event_q)
    {
      rmp->vpp_event_queue_address = pointer_to_uword (event_q);
      rmp->server_rx_fifo = pointer_to_uword (rx_fifo);
      rmp->server_tx_fifo = pointer_to_uword (tx_fifo);
    }
  client_q =
    uword_to_pointer (mp->client_queue_address, unix_shared_memory_queue_t *);

  ASSERT (client_q);
  vl_msg_api_send_shmem (client_q, (u8 *) & rmp);
}

static void
vppcom_send_bind_sock (session_t * session)
{
  vppcom_main_t *vcm = &vppcom_main;
  vl_api_bind_sock_t *bmp;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  session->is_server = 1;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_BIND_SOCK);
  bmp->client_index = vcm->my_client_index;
  bmp->context = htonl (0xfeedface);
  bmp->vrf = session->vrf;
  bmp->is_ip4 = session->is_ip4;
  clib_memcpy (bmp->ip, session->ip, sizeof (bmp->ip));
  bmp->port = session->port;
  bmp->proto = session->proto;
  clib_memcpy (bmp->options, session->options, sizeof (bmp->options));
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & bmp);
}

static void
vppcom_send_unbind_sock (u32 session_index)
{
  vppcom_main_t *vcm = &vppcom_main;
  vl_api_unbind_sock_t *ump;
  session_t *session = 0;
  int rv;

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (session_index, &session);
  if (PREDICT_FALSE (rv))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] invalid session, sid (%d) has been closed!",
		      vcm->my_pid, session_index);
      return;
    }

  ump = vl_msg_api_alloc (sizeof (*ump));
  memset (ump, 0, sizeof (*ump));

  ump->_vl_msg_id = ntohs (VL_API_UNBIND_SOCK);
  ump->client_index = vcm->my_client_index;
  ump->handle = session->vpp_session_handle;
  clib_spinlock_unlock (&vcm->sessions_lockp);
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & ump);
}

static int
vppcom_session_unbind_cut_thru (session_t * session)
{
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
  svm_fifo_segment_private_t *seg;
  int rv = VPPCOM_OK;

  seg = vec_elt_at_index (sm->segments, session->sm_seg_index);
  svm_fifo_segment_free_fifo (seg, session->server_rx_fifo,
			      FIFO_SEGMENT_RX_FREELIST);
  svm_fifo_segment_free_fifo (seg, session->server_tx_fifo,
			      FIFO_SEGMENT_TX_FREELIST);
  svm_fifo_segment_delete (seg);

  return rv;
}

static int
vppcom_session_unbind (u32 session_index)
{
  vppcom_main_t *vcm = &vppcom_main;
  int rv;

  clib_spinlock_lock (&vcm->sessions_lockp);
  if (PREDICT_FALSE (pool_is_free_index (vcm->sessions, session_index)))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 1)
	clib_warning ("[%d] invalid session, sid (%d) has been closed!",
		      vcm->my_pid, session_index);
      return VPPCOM_EBADFD;
    }
  clib_spinlock_unlock (&vcm->sessions_lockp);

  vcm->bind_session_index = session_index;
  vppcom_send_unbind_sock (session_index);
  rv = vppcom_wait_for_session_state_change (session_index, STATE_START,
					     vcm->cfg.session_timeout);
  if (PREDICT_FALSE (rv))
    {
      vcm->bind_session_index = ~0;
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] server unbind timed out, rv = %s (%d)",
		      vcm->my_pid, vppcom_retval_str (rv), rv);
      return rv;
    }
  return VPPCOM_OK;
}

static int
vppcom_session_disconnect (u32 session_index)
{
  vppcom_main_t *vcm = &vppcom_main;
  int rv;

  rv = vppcom_send_disconnect (session_index);
  if (PREDICT_FALSE (rv))
    return rv;

  rv = vppcom_wait_for_session_state_change (session_index, STATE_DISCONNECT,
					     vcm->cfg.session_timeout);
  if (PREDICT_FALSE (rv))
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] client disconnect timed out, rv = %s (%d)",
		      vcm->my_pid, vppcom_retval_str (rv), rv);
      return rv;
    }
  return VPPCOM_OK;
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
  vppcom_main_t *vcm = &vppcom_main;
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
			      vcm->my_pid, argv[i], argv[i + 1],
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
			      vcm->my_pid, argv[i], argv[i + 1],
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
  if (!clib_mem_init (0, vcl_cfg->heapsize))
    clib_warning ("[%d] vppcom heap allocation failure!", vcm->my_pid);
  else if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] allocated vppcom heapsize %lld (0x%llx)",
		  vcm->my_pid, vcl_cfg->heapsize, vcl_cfg->heapsize);
}

static void
vppcom_cfg_read (char *conf_fname)
{
  vppcom_main_t *vcm = &vppcom_main;
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;
  int fd;
  unformat_input_t _input, *input = &_input;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 vc_cfg_input = 0;
  u8 *chroot_path;
  struct stat s;
  u32 uid, gid;

  fd = open (conf_fname, O_RDONLY);
  if (fd < 0)
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] open configuration file '%s' failed!",
		      vcm->my_pid, conf_fname);
      goto file_done;
    }

  if (fstat (fd, &s) < 0)
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] failed to stat `%s'", vcm->my_pid, conf_fname);
      goto file_done;
    }

  if (!(S_ISREG (s.st_mode) || S_ISLNK (s.st_mode)))
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] not a regular file `%s'", vcm->my_pid,
		      conf_fname);
      goto file_done;
    }

  unformat_init_unix_file (input, fd);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      unformat_user (input, unformat_line_input, line_input);
      unformat_skip_white_space (line_input);

      if (unformat (line_input, "vppcom {"))
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
			      vcm->my_pid, chroot_path, vcl_cfg->heapsize,
			      vcl_cfg->heapsize);
	      vec_free (chroot_path);
	    }
	  else if (unformat (line_input, "api-prefix %s", &chroot_path))
	    {
	      vec_terminate_c_string (chroot_path);
	      vl_set_memory_root_path ((char *) chroot_path);
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured api-prefix %s",
			      vcm->my_pid, chroot_path);
	      chroot_path = 0;	/* Don't vec_free() it! */
	    }
	  else if (unformat (line_input, "uid %d", &uid))
	    {
	      vl_set_memory_uid (uid);
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured uid %d", vcm->my_pid, uid);
	    }
	  else if (unformat (line_input, "gid %d", &gid))
	    {
	      vl_set_memory_gid (gid);
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured gid %d", vcm->my_pid, gid);
	    }
	  else if (unformat (line_input, "segment-baseva 0x%llx",
			     &vcl_cfg->segment_baseva))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured segment_baseva 0x%llx",
			      vcm->my_pid, vcl_cfg->segment_baseva);
	    }
	  else if (unformat (line_input, "segment-size 0x%lx",
			     &vcl_cfg->segment_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured segment_size 0x%lx (%ld)",
			      vcm->my_pid, vcl_cfg->segment_size,
			      vcl_cfg->segment_size);
	    }
	  else if (unformat (line_input, "segment-size %ld",
			     &vcl_cfg->segment_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured segment_size %ld (0x%lx)",
			      vcm->my_pid, vcl_cfg->segment_size,
			      vcl_cfg->segment_size);
	    }
	  else if (unformat (line_input, "add-segment-size 0x%lx",
			     &vcl_cfg->add_segment_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning
		  ("[%d] configured add_segment_size 0x%lx (%ld)",
		   vcm->my_pid, vcl_cfg->add_segment_size,
		   vcl_cfg->add_segment_size);
	    }
	  else if (unformat (line_input, "add-segment-size %ld",
			     &vcl_cfg->add_segment_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning
		  ("[%d] configured add_segment_size %ld (0x%lx)",
		   vcm->my_pid, vcl_cfg->add_segment_size,
		   vcl_cfg->add_segment_size);
	    }
	  else if (unformat (line_input, "preallocated-fifo-pairs %d",
			     &vcl_cfg->preallocated_fifo_pairs))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured preallocated_fifo_pairs "
			      "%d (0x%x)", vcm->my_pid,
			      vcl_cfg->preallocated_fifo_pairs,
			      vcl_cfg->preallocated_fifo_pairs);
	    }
	  else if (unformat (line_input, "rx-fifo-size 0x%lx",
			     &vcl_cfg->rx_fifo_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured rx_fifo_size 0x%lx (%ld)",
			      vcm->my_pid, vcl_cfg->rx_fifo_size,
			      vcl_cfg->rx_fifo_size);
	    }
	  else if (unformat (line_input, "rx-fifo-size %ld",
			     &vcl_cfg->rx_fifo_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured rx_fifo_size %ld (0x%lx)",
			      vcm->my_pid, vcl_cfg->rx_fifo_size,
			      vcl_cfg->rx_fifo_size);
	    }
	  else if (unformat (line_input, "tx-fifo-size 0x%lx",
			     &vcl_cfg->tx_fifo_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured tx_fifo_size 0x%lx (%ld)",
			      vcm->my_pid, vcl_cfg->tx_fifo_size,
			      vcl_cfg->tx_fifo_size);
	    }
	  else if (unformat (line_input, "tx-fifo-size %ld",
			     &vcl_cfg->tx_fifo_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured tx_fifo_size %ld (0x%lx)",
			      vcm->my_pid, vcl_cfg->tx_fifo_size,
			      vcl_cfg->tx_fifo_size);
	    }
	  else if (unformat (line_input, "event-queue-size 0x%lx",
			     &vcl_cfg->event_queue_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured event_queue_size 0x%lx (%ld)",
			      vcm->my_pid, vcl_cfg->event_queue_size,
			      vcl_cfg->event_queue_size);
	    }
	  else if (unformat (line_input, "event-queue-size %ld",
			     &vcl_cfg->event_queue_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured event_queue_size %ld (0x%lx)",
			      vcm->my_pid, vcl_cfg->event_queue_size,
			      vcl_cfg->event_queue_size);
	    }
	  else if (unformat (line_input, "listen-queue-size 0x%lx",
			     &vcl_cfg->listen_queue_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured listen_queue_size 0x%lx (%ld)",
			      vcm->my_pid, vcl_cfg->listen_queue_size,
			      vcl_cfg->listen_queue_size);
	    }
	  else if (unformat (line_input, "listen-queue-size %ld",
			     &vcl_cfg->listen_queue_size))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured listen_queue_size %ld (0x%lx)",
			      vcm->my_pid, vcl_cfg->listen_queue_size,
			      vcl_cfg->listen_queue_size);
	    }
	  else if (unformat (line_input, "app-timeout %f",
			     &vcl_cfg->app_timeout))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured app_timeout %f",
			      vcm->my_pid, vcl_cfg->app_timeout);
	    }
	  else if (unformat (line_input, "session-timeout %f",
			     &vcl_cfg->session_timeout))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured session_timeout %f",
			      vcm->my_pid, vcl_cfg->session_timeout);
	    }
	  else if (unformat (line_input, "accept-timeout %f",
			     &vcl_cfg->accept_timeout))
	    {
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] configured accept_timeout %f",
			      vcm->my_pid, vcl_cfg->accept_timeout);
	    }
	  else if (unformat (line_input, "}"))
	    {
	      vc_cfg_input = 0;
	      if (VPPCOM_DEBUG > 0)
		clib_warning ("[%d] completed parsing vppcom config!",
			      vcm->my_pid);
	      goto input_done;
	    }
	  else
	    {
	      if (line_input->buffer[line_input->index] != '#')
		{
		  clib_warning ("[%d] Unknown vppcom config option: '%s'",
				vcm->my_pid, (char *)
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
  vppcom_main_t *vcm = &vppcom_main;
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;
  u8 *heap;
  mheap_t *h;
  int rv;

  if (!vcm->init)
    {
      char *conf_fname;

      vcm->init = 1;
      vcm->my_pid = getpid ();
      clib_fifo_validate (vcm->client_session_index_fifo,
			  vcm->cfg.listen_queue_size);
      vppcom_cfg_init (vcl_cfg);
      conf_fname = getenv (VPPCOM_CONF_ENV);
      if (!conf_fname)
	{
	  conf_fname = VPPCOM_CONF_DEFAULT;
	  if (VPPCOM_DEBUG > 0)
	    clib_warning ("[%d] getenv '%s' failed!", vcm->my_pid,
			  VPPCOM_CONF_ENV);
	}
      vppcom_cfg_heapsize (conf_fname);
      vppcom_cfg_read (conf_fname);
      vcm->bind_session_index = ~0;
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
	  clib_warning ("[%s] couldn't connect to VPP.", vcm->my_pid);
	  return rv;
	}

      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] sending session enable", vcm->my_pid);

      rv = vppcom_app_session_enable ();
      if (rv)
	{
	  clib_warning ("[%d] vppcom_app_session_enable() failed!",
			vcm->my_pid);
	  return rv;
	}

      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] sending app attach", vcm->my_pid);

      rv = vppcom_app_attach ();
      if (rv)
	{
	  clib_warning ("[%d] vppcom_app_attach() failed!", vcm->my_pid);
	  return rv;
	}
    }

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] app_name '%s', my_client_index %d (0x%x)",
		  vcm->my_pid, app_name, vcm->my_client_index,
		  vcm->my_client_index);

  return VPPCOM_OK;
}

void
vppcom_app_destroy (void)
{
  vppcom_main_t *vcm = &vppcom_main;
  int rv;

  if (vcm->my_client_index == ~0)
    return;

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] detaching from VPP, my_client_index %d (0x%x)",
		  vcm->my_pid, vcm->my_client_index, vcm->my_client_index);

  vppcom_app_detach ();
  rv = vppcom_wait_for_app_state_change (STATE_APP_ENABLED);
  if (PREDICT_FALSE (rv))
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] application detach timed out, rv = %s (%d)",
		      vcm->my_pid, vppcom_retval_str (rv), rv);
    }
  vl_client_disconnect_from_vlib ();
  vcm->my_client_index = ~0;
  vcm->app_state = STATE_APP_START;
}

int
vppcom_session_create (u32 vrf, u8 proto, u8 is_nonblocking)
{
  vppcom_main_t *vcm = &vppcom_main;
  session_t *session;
  u32 session_index;

  clib_spinlock_lock (&vcm->sessions_lockp);
  pool_get (vcm->sessions, session);
  session_index = session - vcm->sessions;

  session->vrf = vrf;
  session->proto = proto;
  session->state = STATE_START;
  session->is_nonblocking = is_nonblocking;
  clib_spinlock_unlock (&vcm->sessions_lockp);

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] sid %d", vcm->my_pid, session_index);

  return (int) session_index;
}

int
vppcom_session_close (uint32_t session_index)
{
  vppcom_main_t *vcm = &vppcom_main;
  session_t *session = 0;
  int rv;

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (session_index, &session);
  if (PREDICT_FALSE (rv))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] invalid session, sid (%d) has been closed!",
		      vcm->my_pid, session_index);
      return rv;
    }
  clib_spinlock_unlock (&vcm->sessions_lockp);

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] sid %d", vcm->my_pid, session_index);

  if (session->is_cut_thru)
    {
      if (session->is_server)
	{
	  rv = vppcom_session_unbind_cut_thru (session);
	  if ((VPPCOM_DEBUG > 0) && (rv < 0))
	    clib_warning ("[%d] unbind cut-thru (session %d) failed, "
			  "rv = %s (%d)",
			  vcm->my_pid, session_index,
			  vppcom_retval_str (rv), rv);
	}
    }
  else if (session->is_server)
    {
      rv = vppcom_session_unbind (session_index);
      if ((VPPCOM_DEBUG > 0) && (rv < 0))
	clib_warning ("[%d] unbind (session %d) failed, rv = %s (%d)",
		      vcm->my_pid, session_index, vppcom_retval_str (rv), rv);
    }
  else
    {
      rv = vppcom_session_disconnect (session_index);
      if ((VPPCOM_DEBUG > 0) && (rv < 0))
	clib_warning ("[%d] disconnect (session %d) failed, rv = %s (%d)",
		      vcm->my_pid, session_index, vppcom_retval_str (rv), rv);
    }
  if (rv < 0)
    return rv;

  clib_spinlock_lock (&vcm->sessions_lockp);
  pool_put_index (vcm->sessions, session_index);
  clib_spinlock_unlock (&vcm->sessions_lockp);
  return rv;
}

int
vppcom_session_bind (uint32_t session_index, vppcom_endpt_t * ep)
{
  vppcom_main_t *vcm = &vppcom_main;
  session_t *session = 0;
  int rv;
  ip46_address_t *ip46;

  if (!ep || !ep->ip)
    return VPPCOM_EINVAL;

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (session_index, &session);
  if (PREDICT_FALSE (rv))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] invalid session, sid (%d) has been closed!",
		      vcm->my_pid, session_index);
      return rv;
    }

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] sid %d", vcm->my_pid, session_index);

  session->vrf = ep->vrf;
  session->is_ip4 = ep->is_ip4;
  memset (session->ip, 0, sizeof (session->ip));
  ip46 = (ip46_address_t *) session->ip;
  *ip46 = to_ip46 (!ep->is_ip4, ep->ip);
  session->port = ep->port;

  clib_spinlock_unlock (&vcm->sessions_lockp);
  return VPPCOM_OK;
}

int
vppcom_session_listen (uint32_t listen_session_index, uint32_t q_len)
{
  vppcom_main_t *vcm = &vppcom_main;
  session_t *listen_session = 0;
  int rv;

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (listen_session_index, &listen_session);
  if (PREDICT_FALSE (rv))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] invalid session, sid (%d) has been closed!",
		      vcm->my_pid, listen_session_index);
      return rv;
    }

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] sid %d", vcm->my_pid, listen_session_index);

  ASSERT (vcm->bind_session_index == ~0);
  vcm->bind_session_index = listen_session_index;
  vppcom_send_bind_sock (listen_session);
  clib_spinlock_unlock (&vcm->sessions_lockp);
  rv =
    vppcom_wait_for_session_state_change (listen_session_index, STATE_LISTEN,
					  vcm->cfg.session_timeout);
  if (PREDICT_FALSE (rv))
    {
      vcm->bind_session_index = ~0;
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] server listen timed out, rv = %d (%d)",
		      vcm->my_pid, vppcom_retval_str (rv), rv);
      return rv;
    }

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (listen_session_index, &listen_session);
  if (PREDICT_FALSE (rv))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] invalid session, sid (%d) has been closed!",
		      vcm->my_pid, listen_session_index);
      return rv;
    }
  listen_session->is_listen = 1;
  clib_spinlock_unlock (&vcm->sessions_lockp);
  clib_fifo_validate (vcm->client_session_index_fifo, q_len);

  return VPPCOM_OK;
}

int
vppcom_session_accept (uint32_t listen_session_index, vppcom_endpt_t * ep,
		       double wait_for_time)
{
  vppcom_main_t *vcm = &vppcom_main;
  session_t *listen_session = 0;
  session_t *client_session = 0;
  u32 client_session_index;
  int rv;
  f64 wait_for;

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (listen_session_index, &listen_session);
  if (PREDICT_FALSE (rv))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] invalid session, sid (%d) has been closed!",
		      vcm->my_pid, listen_session_index);
      return rv;
    }

  if (listen_session->state != STATE_LISTEN)
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] session not in listen state, state = %s",
		      vcm->my_pid,
		      vppcom_session_state_str (listen_session->state));
      return VPPCOM_EBADFD;
    }
  wait_for = listen_session->is_nonblocking ? 0 :
    (wait_for_time < 0) ? vcm->cfg.accept_timeout : wait_for_time;

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] sid %d: %s (%d)", vcm->my_pid,
		  listen_session_index,
		  vppcom_session_state_str (listen_session->state),
		  listen_session->state);
  clib_spinlock_unlock (&vcm->sessions_lockp);

  while (1)
    {
      rv = vppcom_wait_for_client_session_index (wait_for);
      if (rv)
	{
	  if ((VPPCOM_DEBUG > 0))
	    clib_warning ("[%d] sid %d, accept timed out, rv = %s (%d)",
			  vcm->my_pid, listen_session_index,
			  vppcom_retval_str (rv), rv);
	  if ((wait_for == 0) || (wait_for_time > 0))
	    return rv;
	}
      else
	break;
    }

  clib_fifo_sub1 (vcm->client_session_index_fifo, client_session_index);

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (client_session_index, &client_session);
  ASSERT (rv == VPPCOM_OK);
  ASSERT (client_session->is_ip4 == listen_session->is_ip4);

  if (VPPCOM_DEBUG > 0)
    clib_warning ("[%d] Got a request: client sid %d", vcm->my_pid,
		  client_session_index);

  ep->vrf = client_session->vrf;
  ep->is_cut_thru = client_session->is_cut_thru;
  ep->is_ip4 = client_session->is_ip4;
  ep->port = client_session->port;
  if (client_session->is_ip4)
    clib_memcpy (ep->ip, client_session->ip, sizeof (ip4_address_t));
  else
    clib_memcpy (ep->ip, client_session->ip, sizeof (ip6_address_t));
  clib_spinlock_unlock (&vcm->sessions_lockp);
  return (int) client_session_index;
}

int
vppcom_session_connect (uint32_t session_index, vppcom_endpt_t * server_ep)
{
  vppcom_main_t *vcm = &vppcom_main;
  session_t *session = 0;
  int rv;
  ip46_address_t *ip46;

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (session_index, &session);
  if (PREDICT_FALSE (rv))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] invalid session, sid (%d) has been closed!",
		      vcm->my_pid, session_index);
      return rv;
    }

  if (session->state == STATE_CONNECT)
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] session, sid (%d) already connected!",
		      vcm->my_pid, session_index);
      return VPPCOM_OK;
    }

  session->vrf = server_ep->vrf;
  session->is_ip4 = server_ep->is_ip4;
  memset (session->ip, 0, sizeof (session->ip));
  ip46 = (ip46_address_t *) session->ip;
  *ip46 = to_ip46 (!server_ep->is_ip4, server_ep->ip);
  session->port = server_ep->port;

  if (VPPCOM_DEBUG > 0)
    {
      u8 *ip_str = format (0, "%U", format_ip46_address,
			   &session->ip, session->is_ip4);
      clib_warning ("[%d] connect sid %d to %s server port %d",
		    vcm->my_pid, session_index, ip_str,
		    clib_net_to_host_u16 (session->port));
      vec_free (ip_str);
    }

  vppcom_send_connect_sock (session, session_index);
  clib_spinlock_unlock (&vcm->sessions_lockp);
  rv = vppcom_wait_for_session_state_change (session_index, STATE_CONNECT,
					     vcm->cfg.session_timeout);
  if (PREDICT_FALSE (rv))
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] connect timed out, rv = %s (%d)",
		      vcm->my_pid, vppcom_retval_str (rv), rv);
      return rv;
    }
  return VPPCOM_OK;
}

int
vppcom_session_read (uint32_t session_index, void *buf, int n)
{
  vppcom_main_t *vcm = &vppcom_main;
  session_t *session = 0;
  svm_fifo_t *rx_fifo;
  int n_read = 0;
  int rv;
  int max_dequeue;
  char *fifo_str;

  ASSERT (buf);

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (session_index, &session);
  if (PREDICT_FALSE (rv))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] invalid session, sid (%d) has been closed!",
		      vcm->my_pid, session_index);
      return rv;
    }

  if (session->state == STATE_DISCONNECT)
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] sid (%d) has been closed by remote peer!",
		      vcm->my_pid, session_index);
      return VPPCOM_ECONNRESET;
    }

  rx_fifo = ((!session->is_cut_thru || session->is_server) ?
	     session->server_rx_fifo : session->server_tx_fifo);
  fifo_str = ((!session->is_cut_thru || session->is_server) ?
	      "server_rx_fifo" : "server_tx_fifo");
  clib_spinlock_unlock (&vcm->sessions_lockp);

  max_dequeue = (int) svm_fifo_max_dequeue (rx_fifo);
  n_read = svm_fifo_dequeue_nowait (rx_fifo, clib_min (n, max_dequeue), buf);

  if (VPPCOM_DEBUG > 2)
    clib_warning ("[%d] sid %d, read %d bytes from %s (%p)", vcm->my_pid,
		  session_index, n_read, fifo_str, rx_fifo);

  return (n_read <= 0) ? VPPCOM_EAGAIN : n_read;
}

static inline int
vppcom_session_read_ready (session_t * session, u32 session_index)
{
  vppcom_main_t *vcm = &vppcom_main;
  svm_fifo_t *rx_fifo;
  int ready = 0;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  if (session->state == STATE_DISCONNECT)
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] sid (%d) has been closed by remote peer!",
		      vcm->my_pid, session_index);
      return VPPCOM_ECONNRESET;
    }

  if (session->is_listen)
    ready = clib_fifo_elts (vcm->client_session_index_fifo);
  else
    {
      rx_fifo = ((!session->is_cut_thru || session->is_server) ?
		 session->server_rx_fifo : session->server_tx_fifo);

      ready = svm_fifo_max_dequeue (rx_fifo);
    }

  if (VPPCOM_DEBUG > 3)
    clib_warning ("[%d] sid %d, peek %s (%p), ready = %d", vcm->my_pid,
		  session_index,
		  session->is_server ? "server_rx_fifo" : "server_tx_fifo",
		  rx_fifo, ready);
  return ready;
}

int
vppcom_session_write (uint32_t session_index, void *buf, int n)
{
  vppcom_main_t *vcm = &vppcom_main;
  session_t *session = 0;
  svm_fifo_t *tx_fifo;
  unix_shared_memory_queue_t *q;
  session_fifo_event_t evt;
  int rv;
  char *fifo_str;
  u8 is_nonblocking;

  ASSERT (buf);

  clib_spinlock_lock (&vcm->sessions_lockp);
  rv = vppcom_session_at_index (session_index, &session);
  if (PREDICT_FALSE (rv))
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] invalid session, sid (%d) has been closed!",
		      vcm->my_pid, session_index);
      return rv;
    }

  if (session->state == STATE_DISCONNECT)
    {
      clib_spinlock_unlock (&vcm->sessions_lockp);
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] sid (%d) has been closed by remote peer!",
		      vcm->my_pid, session_index);
      return VPPCOM_ECONNRESET;
    }

  tx_fifo = ((!session->is_cut_thru || session->is_server) ?
	     session->server_tx_fifo : session->server_rx_fifo);
  fifo_str = ((!session->is_cut_thru || session->is_server) ?
	      "server_tx_fifo" : "server_rx_fifo");

  is_nonblocking = session->is_nonblocking;
  clib_spinlock_unlock (&vcm->sessions_lockp);

  do
    {
      rv = svm_fifo_enqueue_nowait (tx_fifo, n, buf);
    }
  while (!is_nonblocking && (rv <= 0));

  /* If event wasn't set, add one */
  if (!session->is_cut_thru && (rv > 0) && svm_fifo_set_event (tx_fifo))
    {
      int rval;

      /* Fabricate TX event, send to vpp */
      evt.fifo = tx_fifo;
      evt.event_type = FIFO_EVENT_APP_TX;
      evt.event_id = vcm->tx_event_id++;

      clib_spinlock_lock (&vcm->sessions_lockp);
      rval = vppcom_session_at_index (session_index, &session);
      if (PREDICT_FALSE (rval))
	{
	  clib_spinlock_unlock (&vcm->sessions_lockp);
	  if (VPPCOM_DEBUG > 1)
	    clib_warning ("[%d] invalid session, sid (%d) has been closed!",
			  vcm->my_pid, session_index);
	  return rval;
	}
      q = session->vpp_event_queue;
      clib_spinlock_unlock (&vcm->sessions_lockp);
      ASSERT (q);
      unix_shared_memory_queue_add (q, (u8 *) & evt,
				    0 /* do wait for mutex */ );
    }

  if (VPPCOM_DEBUG > 2)
    clib_warning ("[%d] sid %d, wrote %d bytes to %s (%p)", vcm->my_pid,
		  session_index, rv, fifo_str, tx_fifo);

  return rv;
}

static inline int
vppcom_session_write_ready (session_t * session, u32 session_index)
{
  vppcom_main_t *vcm = &vppcom_main;
  svm_fifo_t *tx_fifo;
  char *fifo_str;
  int rv;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  if (session->state == STATE_DISCONNECT)
    {
      if (VPPCOM_DEBUG > 0)
	clib_warning ("[%d] sid (%d) has been closed by remote peer!",
		      vcm->my_pid, session_index);
      return VPPCOM_ECONNRESET;
    }

  tx_fifo = ((!session->is_cut_thru || session->is_server) ?
	     session->server_tx_fifo : session->server_rx_fifo);
  fifo_str = ((!session->is_cut_thru || session->is_server) ?
	      "server_tx_fifo" : "server_rx_fifo");

  rv = svm_fifo_max_enqueue (tx_fifo);

  if (VPPCOM_DEBUG > 3)
    clib_warning ("[%d] sid %d, peek %s (%p), ready = %d", vcm->my_pid,
		  session_index, fifo_str, tx_fifo, rv);
  return rv;
}

int
vppcom_select (unsigned long n_bits, unsigned long *read_map,
	       unsigned long *write_map, unsigned long *except_map,
	       double time_to_wait)
{
  vppcom_main_t *vcm = &vppcom_main;
  u32 session_index;
  session_t *session = 0;
  int rv, bits_set = 0;
  f64 timeout = clib_time_now (&vcm->clib_time) + time_to_wait;
  u32 minbits = clib_max (n_bits, BITS (uword));

  ASSERT (sizeof (clib_bitmap_t) == sizeof (long int));

  if (read_map)
    {
      clib_bitmap_validate (vcm->rd_bitmap, minbits);
      clib_memcpy (vcm->rd_bitmap, read_map, vec_len (vcm->rd_bitmap));
      memset (read_map, 0, vec_len (vcm->rd_bitmap));
    }
  if (write_map)
    {
      clib_bitmap_validate (vcm->wr_bitmap, minbits);
      clib_memcpy (vcm->wr_bitmap, write_map, vec_len (vcm->wr_bitmap));
      memset (write_map, 0, vec_len (vcm->wr_bitmap));
    }
  if (except_map)
    {
      clib_bitmap_validate (vcm->ex_bitmap, minbits);
      clib_memcpy (vcm->ex_bitmap, except_map, vec_len (vcm->ex_bitmap));
      memset (except_map, 0, vec_len (vcm->ex_bitmap));
    }

  do
    {
      /* *INDENT-OFF* */
      clib_bitmap_foreach (session_index, vcm->rd_bitmap,
        ({
          clib_spinlock_lock (&vcm->sessions_lockp);
          rv = vppcom_session_at_index (session_index, &session);
          if (rv < 0)
            {
              clib_spinlock_unlock (&vcm->sessions_lockp);
              if (VPPCOM_DEBUG > 1)
                clib_warning ("[%d] session %d specified in "
                              "read_map is closed.", vcm->my_pid,
                              session_index);
              bits_set = VPPCOM_EBADFD;
              goto select_done;
            }

          rv = vppcom_session_read_ready (session, session_index);
          clib_spinlock_unlock (&vcm->sessions_lockp);
          if (vcm->ex_bitmap &&
              clib_bitmap_get (vcm->ex_bitmap, session_index) && (rv < 0))
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

      clib_bitmap_foreach (session_index, vcm->wr_bitmap,
        ({
          clib_spinlock_lock (&vcm->sessions_lockp);
          rv = vppcom_session_at_index (session_index, &session);
          if (rv < 0)
            {
              clib_spinlock_unlock (&vcm->sessions_lockp);
              if (VPPCOM_DEBUG > 0)
                clib_warning ("[%d] session %d specified in "
                              "write_map is closed.", vcm->my_pid,
                              session_index);
              bits_set = VPPCOM_EBADFD;
              goto select_done;
            }

          rv = vppcom_session_write_ready (session, session_index);
          clib_spinlock_unlock (&vcm->sessions_lockp);
          if (rv > 0)
            {
              // TBD: clib_warning
              clib_bitmap_set_no_check (write_map, session_index, 1);
              bits_set++;
            }
        }));

      clib_bitmap_foreach (session_index, vcm->ex_bitmap,
        ({
          clib_spinlock_lock (&vcm->sessions_lockp);
          rv = vppcom_session_at_index (session_index, &session);
          if (rv < 0)
            {
              clib_spinlock_unlock (&vcm->sessions_lockp);
              if (VPPCOM_DEBUG > 1)
                clib_warning ("[%d] session %d specified in "
                              "except_map is closed.", vcm->my_pid,
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
      /* *INDENT-ON* */
    }
  while (clib_time_now (&vcm->clib_time) < timeout);

select_done:
  return (bits_set);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
