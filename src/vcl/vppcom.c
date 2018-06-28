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
#include <svm/svm_fifo_segment.h>
#include <vcl/vppcom.h>
#include <vcl/vcl_event.h>
#include <vcl/vcl_debug.h>
#include <vcl/vcl_private.h>

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

const char *
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

/*
 * VPPCOM Utility Functions
 */

static inline void
vppcom_session_table_del_listener (u64 listener_handle)
{
  listener_handle |= 1ULL << 63;
  hash_unset (vcm->session_index_by_vpp_handles, listener_handle);
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
  VDBG (0, "VCL<%d>: timeout waiting for state %s (%d)", getpid (),
	vppcom_app_state_str (app_state), app_state);
  vcl_evt (VCL_EVT_SESSION_TIMEOUT, vcm, app_state);

  return VPPCOM_ETIMEDOUT;
}

static inline int
vppcom_wait_for_session_state_change (u32 session_index,
				      session_state_t state,
				      f64 wait_for_time)
{
  f64 timeout = clib_time_now (&vcm->clib_time) + wait_for_time;
  vcl_session_t *volatile session;
  int rv;

  do
    {
      VCL_SESSION_LOCK ();
      rv = vppcom_session_at_index (session_index, &session);
      if (PREDICT_FALSE (rv))
	{
	  VCL_SESSION_UNLOCK ();
	  return rv;
	}
      if (session->session_state & state)
	{
	  VCL_SESSION_UNLOCK ();
	  return VPPCOM_OK;
	}
      if (session->session_state & STATE_FAILED)
	{
	  VCL_SESSION_UNLOCK ();
	  return VPPCOM_ECONNREFUSED;
	}

      VCL_SESSION_UNLOCK ();
    }
  while (clib_time_now (&vcm->clib_time) < timeout);

  VDBG (0, "VCL<%d>: timeout waiting for state 0x%x (%s)", getpid (), state,
	vppcom_session_state_str (state));
  vcl_evt (VCL_EVT_SESSION_TIMEOUT, session, session_state);

  return VPPCOM_ETIMEDOUT;
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
	  VDBG (0, "VCL<%d>: application session enable timed out! "
		"returning %d (%s)", getpid (), rv, vppcom_retval_str (rv));
	  return rv;
	}
    }
  return VPPCOM_OK;
}

static int
vppcom_app_attach (void)
{
  int rv;

  vppcom_app_send_attach ();
  rv = vppcom_wait_for_app_state_change (STATE_APP_ATTACHED);
  if (PREDICT_FALSE (rv))
    {
      VDBG (0, "VCL<%d>: application attach timed out! returning %d (%s)",
	    getpid (), rv, vppcom_retval_str (rv));
      return rv;
    }

  return VPPCOM_OK;
}

static int
vppcom_session_unbind (u32 session_index)
{
  vcl_session_t *session = 0;
  int rv;
  u64 vpp_handle;

  VCL_SESSION_LOCK_AND_GET (session_index, &session);

  vpp_handle = session->vpp_handle;
  vppcom_session_table_del_listener (vpp_handle);
  session->vpp_handle = ~0;
  session->session_state = STATE_DISCONNECT;

  VCL_SESSION_UNLOCK ();

  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: sending unbind msg! new state"
	" 0x%x (%s)", getpid (), vpp_handle, session_index, STATE_DISCONNECT,
	vppcom_session_state_str (STATE_DISCONNECT));
  vcl_evt (VCL_EVT_UNBIND, session);
  vppcom_send_unbind_sock (vpp_handle);

done:
  return rv;
}

static int
vppcom_session_disconnect (u32 session_index)
{
  int rv;
  vcl_session_t *session;
  u64 vpp_handle;
  session_state_t state;

  VCL_SESSION_LOCK_AND_GET (session_index, &session);

  vpp_handle = session->vpp_handle;
  state = session->session_state;
  VCL_SESSION_UNLOCK ();

  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u state 0x%x (%s)", getpid (),
	vpp_handle, session_index, state, vppcom_session_state_str (state));

  if (PREDICT_FALSE (state & STATE_LISTEN))
    {
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "Cannot disconnect a listen socket!",
		    getpid (), vpp_handle, session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  /* The peer has already initiated the close,
   * so send the disconnect session reply.
   */
  if (state & STATE_CLOSE_ON_EMPTY)
    {
      //XXX alagalah - Check and drain here?
      vppcom_send_disconnect_session_reply (vpp_handle,
					    session_index, 0 /* rv */ );
      VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: sending disconnect "
	    "REPLY...", getpid (), vpp_handle, session_index);
    }

  /* Otherwise, send a disconnect session msg...
   */
  else
    {
      VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: sending disconnect...",
	    getpid (), vpp_handle, session_index);

      vppcom_send_disconnect_session (vpp_handle, session_index);
    }

done:
  return rv;
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
      vcm->init = 1;
      clib_spinlock_init (&vcm->session_fifo_lockp);
      clib_fifo_validate (vcm->client_session_index_fifo,
			  vcm->cfg.listen_queue_size);
      clib_spinlock_init (&vcm->sessions_lockp);

      vppcom_cfg (&vcm->cfg);

      vcm->main_cpu = os_get_thread_index ();
      heap = clib_mem_get_per_cpu_heap ();
      h = mheap_header (heap);
      /* make the main heap thread-safe */
      h->flags |= MHEAP_FLAG_THREAD_SAFE;

      vcm->session_index_by_vpp_handles = hash_create (0, sizeof (uword));

      clib_time_init (&vcm->clib_time);
      vppcom_init_error_string_table ();
      svm_fifo_segment_main_init (vcl_cfg->segment_baseva,
				  20 /* timeout in secs */ );
    }

  if (vcm->my_client_index == ~0)
    {
      /* API hookup and connect to VPP */
      vppcom_api_hookup ();
      vcl_elog_init (vcm);
      vcm->app_state = STATE_APP_START;
      rv = vppcom_connect_to_vpp (app_name);
      if (rv)
	{
	  clib_warning ("VCL<%d>: ERROR: couldn't connect to VPP!",
			getpid ());
	  return rv;
	}

      /* State event handling thread */

      rv = vce_start_event_thread (&(vcm->event_thread), 20);

      VDBG (0, "VCL<%d>: sending session enable", getpid ());

      rv = vppcom_app_session_enable ();
      if (rv)
	{
	  clib_warning ("VCL<%d>: ERROR: vppcom_app_session_enable() "
			"failed!", getpid ());
	  return rv;
	}

      VDBG (0, "VCL<%d>: sending app attach", getpid ());

      rv = vppcom_app_attach ();
      if (rv)
	{
	  clib_warning ("VCL<%d>: ERROR: vppcom_app_attach() failed!",
			getpid ());
	  return rv;
	}

      VDBG (0, "VCL<%d>: app_name '%s', my_client_index %d (0x%x)",
	    getpid (), app_name, vcm->my_client_index, vcm->my_client_index);
    }

  return VPPCOM_OK;
}

void
vppcom_app_destroy (void)
{
  int rv;
  f64 orig_app_timeout;

  if (vcm->my_client_index == ~0)
    return;

  VDBG (0, "VCL<%d>: detaching from VPP, my_client_index %d (0x%x)",
	getpid (), vcm->my_client_index, vcm->my_client_index);
  vcl_evt (VCL_EVT_DETACH, vcm);

  vppcom_app_send_detach ();
  orig_app_timeout = vcm->cfg.app_timeout;
  vcm->cfg.app_timeout = 2.0;
  rv = vppcom_wait_for_app_state_change (STATE_APP_ENABLED);
  vcm->cfg.app_timeout = orig_app_timeout;
  if (PREDICT_FALSE (rv))
    VDBG (0, "VCL<%d>: application detach timed out! returning %d (%s)",
	  getpid (), rv, vppcom_retval_str (rv));

  vcl_elog_stop (vcm);
  vl_client_disconnect_from_vlib ();
  vcm->my_client_index = ~0;
  vcm->app_state = STATE_APP_START;
}

int
vppcom_session_create (u8 proto, u8 is_nonblocking)
{
  vcl_session_t *session;
  u32 session_index;

  VCL_SESSION_LOCK ();
  pool_get (vcm->sessions, session);
  memset (session, 0, sizeof (*session));
  session_index = session - vcm->sessions;

  session->session_type = proto;
  session->session_state = STATE_START;
  session->vpp_handle = ~0;

  if (is_nonblocking)
    VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_NONBLOCK);
  else
    VCL_SESS_ATTR_CLR (session->attr, VCL_SESS_ATTR_NONBLOCK);

  vcl_evt (VCL_EVT_CREATE, session, session_type, session->session_state,
	   is_nonblocking, session_index);

  VCL_SESSION_UNLOCK ();

  VDBG (0, "VCL<%d>: sid %u", getpid (), session_index);

  return (int) session_index;
}

int
vppcom_session_close (uint32_t session_index)
{
  vcl_session_t *session = 0;
  int rv;
  u8 is_vep;
  u8 is_vep_session;
  u32 next_sid;
  u32 vep_idx;
  u64 vpp_handle;
  uword *p;
  session_state_t state;

  VCL_SESSION_LOCK_AND_GET (session_index, &session);
  is_vep = session->is_vep;
  is_vep_session = session->is_vep_session;
  next_sid = session->vep.next_sid;
  vep_idx = session->vep.vep_idx;
  state = session->session_state;
  vpp_handle = session->vpp_handle;
  VCL_SESSION_UNLOCK ();

  if (VPPCOM_DEBUG > 0)
    {
      if (is_vep)
	clib_warning ("VCL<%d>: vep_idx %u / sid %u: "
		      "closing epoll session...",
		      getpid (), session_index, session_index);
      else
	clib_warning ("VCL<%d>: vpp handle 0x%llx, sid %d: "
		      "closing session...",
		      getpid (), vpp_handle, session_index);
    }

  if (is_vep)
    {
      while (next_sid != ~0)
	{
	  rv = vppcom_epoll_ctl (session_index, EPOLL_CTL_DEL, next_sid, 0);
	  if (PREDICT_FALSE (rv < 0))
	    VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: EPOLL_CTL_DEL "
		  "vep_idx %u failed! rv %d (%s)",
		  getpid (), vpp_handle, next_sid, vep_idx,
		  rv, vppcom_retval_str (rv));

	  VCL_SESSION_LOCK_AND_GET (session_index, &session);
	  next_sid = session->vep.next_sid;
	  VCL_SESSION_UNLOCK ();
	}
    }
  else
    {
      if (is_vep_session)
	{
	  rv = vppcom_epoll_ctl (vep_idx, EPOLL_CTL_DEL, session_index, 0);
	  if (rv < 0)
	    VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: EPOLL_CTL_DEL "
		  "vep_idx %u failed! rv %d (%s)",
		  getpid (), vpp_handle, session_index,
		  vep_idx, rv, vppcom_retval_str (rv));
	}

      if (state & STATE_LISTEN)
	{
	  rv = vppcom_session_unbind (session_index);
	  if (PREDICT_FALSE (rv < 0))
	    VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: listener unbind "
		  "failed! rv %d (%s)",
		  getpid (), vpp_handle, session_index,
		  rv, vppcom_retval_str (rv));
	}

      else if (state & (CLIENT_STATE_OPEN | SERVER_STATE_OPEN))
	{
	  rv = vppcom_session_disconnect (session_index);
	  if (PREDICT_FALSE (rv < 0))
	    clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
			  "session disconnect failed! rv %d (%s)",
			  getpid (), vpp_handle, session_index,
			  rv, vppcom_retval_str (rv));
	}
    }

  VCL_SESSION_LOCK_AND_GET (session_index, &session);
  vpp_handle = session->vpp_handle;
  if (vpp_handle != ~0)
    {
      p = hash_get (vcm->session_index_by_vpp_handles, vpp_handle);
      if (p)
	hash_unset (vcm->session_index_by_vpp_handles, vpp_handle);
    }
  pool_put_index (vcm->sessions, session_index);

  VCL_SESSION_UNLOCK ();

  if (VPPCOM_DEBUG > 0)
    {
      if (is_vep)
	clib_warning ("VCL<%d>: vep_idx %u / sid %u: epoll session removed.",
		      getpid (), session_index, session_index);
      else
	clib_warning ("VCL<%d>: vpp handle 0x%llx, sid %u: session removed.",
		      getpid (), vpp_handle, session_index);
    }
done:

  vcl_evt (VCL_EVT_CLOSE, session, rv);

  return rv;
}

int
vppcom_session_bind (uint32_t session_index, vppcom_endpt_t * ep)
{
  vcl_session_t *session = 0;
  int rv;

  if (!ep || !ep->ip)
    return VPPCOM_EINVAL;

  VCL_SESSION_LOCK_AND_GET (session_index, &session);

  if (session->is_vep)
    {
      VCL_SESSION_UNLOCK ();
      clib_warning ("VCL<%d>: ERROR: sid %u: cannot "
		    "bind to an epoll session!", getpid (), session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  session->transport.is_ip4 = ep->is_ip4;
  session->transport.lcl_ip = to_ip46 (ep->is_ip4 ? IP46_TYPE_IP4 :
				       IP46_TYPE_IP6, ep->ip);
  session->transport.lcl_port = ep->port;

  VDBG (0, "VCL<%d>: sid %u: binding to local %s address %U port %u, "
	"proto %s", getpid (), session_index,
	session->transport.is_ip4 ? "IPv4" : "IPv6",
	format_ip46_address, &session->transport.lcl_ip,
	session->transport.is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
	clib_net_to_host_u16 (session->transport.lcl_port),
	session->session_type ? "UDP" : "TCP");
  vcl_evt (VCL_EVT_BIND, session);
  VCL_SESSION_UNLOCK ();
done:
  return rv;
}

int
vppcom_session_listen (uint32_t listen_session_index, uint32_t q_len)
{
  vcl_session_t *listen_session = 0;
  u64 listen_vpp_handle;
  int rv, retval;

  if (q_len == 0 || q_len == ~0)
    q_len = vcm->cfg.listen_queue_size;

  VCL_SESSION_LOCK_AND_GET (listen_session_index, &listen_session);

  if (listen_session->is_vep)
    {
      VCL_SESSION_UNLOCK ();
      clib_warning ("VCL<%d>: ERROR: sid %u: cannot listen on an "
		    "epoll session!", getpid (), listen_session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  listen_vpp_handle = listen_session->vpp_handle;
  if (listen_session->session_state & STATE_LISTEN)
    {
      VCL_SESSION_UNLOCK ();
      VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: already in listen state!",
	    getpid (), listen_vpp_handle, listen_session_index);
      rv = VPPCOM_OK;
      goto done;
    }

  VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: sending VPP bind+listen "
	"request...", getpid (), listen_vpp_handle, listen_session_index);

  vppcom_send_bind_sock (listen_session, listen_session_index);
  VCL_SESSION_UNLOCK ();
  retval =
    vppcom_wait_for_session_state_change (listen_session_index, STATE_LISTEN,
					  vcm->cfg.session_timeout);

  VCL_SESSION_LOCK_AND_GET (listen_session_index, &listen_session);
  if (PREDICT_FALSE (retval))
    {
      VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: bind+listen failed! "
	    "returning %d (%s)", getpid (), listen_session->vpp_handle,
	    listen_session_index, retval, vppcom_retval_str (retval));
      VCL_SESSION_UNLOCK ();
      rv = retval;
      goto done;
    }

  VCL_ACCEPT_FIFO_LOCK ();
  clib_fifo_validate (vcm->client_session_index_fifo, q_len);
  VCL_ACCEPT_FIFO_UNLOCK ();

  VCL_SESSION_UNLOCK ();

done:
  return rv;
}

int
validate_args_session_accept_ (vcl_session_t * listen_session)
{
  u32 listen_session_index = listen_session - vcm->sessions;

  /* Input validation - expects spinlock on sessions_lockp */
  if (listen_session->is_vep)
    {
      clib_warning ("VCL<%d>: ERROR: sid %u: cannot accept on an "
		    "epoll session!", getpid (), listen_session_index);
      return VPPCOM_EBADFD;
    }

  if (listen_session->session_state != STATE_LISTEN)
    {
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "not in listen state! state 0x%x (%s)", getpid (),
		    listen_session->vpp_handle, listen_session_index,
		    listen_session->session_state,
		    vppcom_session_state_str (listen_session->session_state));
      return VPPCOM_EBADFD;
    }
  return VPPCOM_OK;
}

int
vppcom_session_accept (uint32_t listen_session_index, vppcom_endpt_t * ep,
		       uint32_t flags)
{
  vcl_session_t *listen_session = 0;
  vcl_session_t *client_session = 0;
  u32 client_session_index = ~0;
  int rv;
  u64 listen_vpp_handle;
  vce_event_handler_reg_t *reg;
  vce_event_t *ev;
  vce_event_connect_request_t *result;
  struct timespec ts;
  struct timeval tv;
  int millisecond_timeout = 1;
  int hours_timeout = 20 * 60 * 60;

  VCL_SESSION_LOCK_AND_GET (listen_session_index, &listen_session);
  listen_vpp_handle = listen_session->vpp_handle;	// For debugging

  rv = validate_args_session_accept_ (listen_session);
  if (rv)
    {
      VCL_SESSION_UNLOCK ();
      goto done;
    }

  /* Using an aggressive timer of 1ms and a generous timer of
   * 20 hours, we can implement a blocking and non-blocking listener
   * as both event and time driven */
  gettimeofday (&tv, NULL);
  ts.tv_nsec = (tv.tv_usec * 1000) + (1000 * millisecond_timeout);
  ts.tv_sec = tv.tv_sec;

  /* Predict that the Listener is blocking more often than not */
  if (PREDICT_TRUE (!VCL_SESS_ATTR_TEST (listen_session->attr,
					 VCL_SESS_ATTR_NONBLOCK)))
    ts.tv_sec += hours_timeout;

  VCL_SESSION_UNLOCK ();

  /* Register handler for connect_request event on listen_session_index */
  vce_event_key_t evk;
  evk.session_index = listen_session_index;
  evk.eid = VCL_EVENT_CONNECT_REQ_ACCEPTED;
  reg = vce_register_handler (&vcm->event_thread, &evk,
			      vce_connect_request_handler_fn, 0);
  VCL_EVENTS_LOCK ();
  ev = vce_get_event_from_index (&vcm->event_thread, reg->ev_idx);
  pthread_mutex_lock (&reg->handler_lock);
  while (!ev)
    {
      VCL_EVENTS_UNLOCK ();
      rv = pthread_cond_timedwait (&reg->handler_cond,
				   &reg->handler_lock, &ts);
      if (rv == ETIMEDOUT)
	{
	  rv = VPPCOM_EAGAIN;
	  goto cleanup;
	}
      VCL_EVENTS_LOCK ();
      ev = vce_get_event_from_index (&vcm->event_thread, reg->ev_idx);
    }
  result = vce_get_event_data (ev, sizeof (*result));
  client_session_index = result->accepted_session_index;
  VCL_EVENTS_UNLOCK ();

  /* Remove from the FIFO used to service epoll */
  VCL_ACCEPT_FIFO_LOCK ();
  if (clib_fifo_elts (vcm->client_session_index_fifo))
    {
      u32 tmp_client_session_index;
      clib_fifo_sub1 (vcm->client_session_index_fifo,
		      tmp_client_session_index);
      /* It wasn't ours... put it back ... */
      if (tmp_client_session_index != client_session_index)
	clib_fifo_add1 (vcm->client_session_index_fifo,
			tmp_client_session_index);
    }
  VCL_ACCEPT_FIFO_UNLOCK ();

  VCL_SESSION_LOCK ();

  rv = vppcom_session_at_index (client_session_index, &client_session);
  if (PREDICT_FALSE (rv))
    {
      rv = VPPCOM_ECONNABORTED;
      clib_warning ("VCL<%d>: vpp handle 0x%llx, sid %u: client sid %u "
		    "lookup failed! returning %d (%s)", getpid (),
		    listen_vpp_handle, listen_session_index,
		    client_session_index, rv, vppcom_retval_str (rv));
      goto cleanup;
    }

  if (flags & O_NONBLOCK)
    VCL_SESS_ATTR_SET (client_session->attr, VCL_SESS_ATTR_NONBLOCK);
  else
    VCL_SESS_ATTR_CLR (client_session->attr, VCL_SESS_ATTR_NONBLOCK);

  VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: Got a client request! "
	"vpp handle 0x%llx, sid %u, flags %d, is_nonblocking %u",
	getpid (), listen_vpp_handle, listen_session_index,
	client_session->vpp_handle, client_session_index,
	flags, VCL_SESS_ATTR_TEST (client_session->attr,
				   VCL_SESS_ATTR_NONBLOCK));

  if (ep)
    {
      ep->is_ip4 = client_session->transport.is_ip4;
      ep->port = client_session->transport.rmt_port;
      if (client_session->transport.is_ip4)
	clib_memcpy (ep->ip, &client_session->transport.rmt_ip.ip4,
		     sizeof (ip4_address_t));
      else
	clib_memcpy (ep->ip, &client_session->transport.rmt_ip.ip6,
		     sizeof (ip6_address_t));
    }

  vppcom_send_accept_session_reply (client_session->vpp_handle,
				    client_session->client_context,
				    0 /* retval OK */ );

  VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: accepted vpp handle 0x%llx,"
	" sid %u connection from peer %s address %U port %u to local %s address"
	" %U port %u",
	getpid (), listen_vpp_handle,
	listen_session_index, client_session->vpp_handle,
	client_session_index,
	client_session->transport.is_ip4 ? "IPv4" : "IPv6",
	format_ip46_address, &client_session->transport.rmt_ip,
	client_session->transport.is_ip4 ?
	IP46_TYPE_IP4 : IP46_TYPE_IP6,
	clib_net_to_host_u16 (client_session->transport.rmt_port),
	client_session->transport.is_ip4 ? "IPv4" : "IPv6",
	format_ip46_address, &client_session->transport.lcl_ip,
	client_session->transport.is_ip4 ?
	IP46_TYPE_IP4 : IP46_TYPE_IP6,
	clib_net_to_host_u16 (client_session->transport.lcl_port));
  vcl_evt (VCL_EVT_ACCEPT, client_session, listen_session,
	   client_session_index);
  VCL_SESSION_UNLOCK ();

  rv = (int) client_session_index;
  vce_clear_event (&vcm->event_thread, reg->ev_idx);
  if (vcm->session_io_thread.io_sessions_lockp)
    {
      /* Throw this new accepted session index into the rx poll thread pool */
      VCL_IO_SESSIONS_LOCK ();
      u32 *active_session_index;
      pool_get (vcm->session_io_thread.active_session_indexes,
		active_session_index);
      *active_session_index = client_session_index;
      VCL_IO_SESSIONS_UNLOCK ();
    }
cleanup:
  vce_unregister_handler (&vcm->event_thread, reg);
  pthread_mutex_unlock (&reg->handler_lock);

done:
  return rv;
}

int
vppcom_session_connect (uint32_t session_index, vppcom_endpt_t * server_ep)
{
  vcl_session_t *session = 0;
  u64 vpp_handle = 0;
  int rv, retval = VPPCOM_OK;

  VCL_SESSION_LOCK_AND_GET (session_index, &session);

  if (PREDICT_FALSE (session->is_vep))
    {
      VCL_SESSION_UNLOCK ();
      clib_warning ("VCL<%d>: ERROR: sid %u: cannot "
		    "connect on an epoll session!", getpid (), session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  if (PREDICT_FALSE (session->session_state & CLIENT_STATE_OPEN))
    {
      VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: session already "
	    "connected to %s %U port %d proto %s, state 0x%x (%s)",
	    getpid (), session->vpp_handle, session_index,
	    session->transport.is_ip4 ? "IPv4" : "IPv6",
	    format_ip46_address,
	    &session->transport.rmt_ip, session->transport.is_ip4 ?
	    IP46_TYPE_IP4 : IP46_TYPE_IP6,
	    clib_net_to_host_u16 (session->transport.rmt_port),
	    session->session_type ? "UDP" : "TCP", session->session_state,
	    vppcom_session_state_str (session->session_state));

      VCL_SESSION_UNLOCK ();
      goto done;
    }

  session->transport.is_ip4 = server_ep->is_ip4;
  if (session->transport.is_ip4)
    clib_memcpy (&session->transport.rmt_ip.ip4, server_ep->ip,
		 sizeof (ip4_address_t));
  else
    clib_memcpy (&session->transport.rmt_ip.ip6, server_ep->ip,
		 sizeof (ip6_address_t));
  session->transport.rmt_port = server_ep->port;

  VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: connecting to server %s %U "
	"port %d proto %s",
	getpid (), session->vpp_handle, session_index,
	session->transport.is_ip4 ? "IPv4" : "IPv6",
	format_ip46_address,
	&session->transport.rmt_ip, session->transport.is_ip4 ?
	IP46_TYPE_IP4 : IP46_TYPE_IP6,
	clib_net_to_host_u16 (session->transport.rmt_port),
	session->session_type ? "UDP" : "TCP");

  vppcom_send_connect_sock (session, session_index);
  VCL_SESSION_UNLOCK ();

  retval =
    vppcom_wait_for_session_state_change (session_index, STATE_CONNECT,
					  vcm->cfg.session_timeout);

  VCL_SESSION_LOCK_AND_GET (session_index, &session);
  vpp_handle = session->vpp_handle;
  VCL_SESSION_UNLOCK ();

done:
  if (PREDICT_FALSE (retval))
    {
      rv = retval;
      if (VPPCOM_DEBUG > 0)
	{
	  if (session)
	    clib_warning ("VCL<%d>: vpp handle 0x%llx, sid %u: connect "
			  "failed! returning %d (%s)", getpid (), vpp_handle,
			  session_index, rv, vppcom_retval_str (rv));
	  else
	    clib_warning ("VCL<%d>: no session for sid %u: connect failed! "
			  "returning %d (%s)", getpid (),
			  session_index, rv, vppcom_retval_str (rv));
	}
    }
  else
    VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: connected!",
	  getpid (), vpp_handle, session_index);

  return rv;
}

static inline int
vppcom_session_read_internal (uint32_t session_index, void *buf, int n,
			      u8 peek)
{
  vcl_session_t *session = 0;
  svm_fifo_t *rx_fifo;
  int n_read = 0;
  int rv;
  int is_nonblocking;

  u64 vpp_handle;
  u32 poll_et;
  session_state_t state;

  ASSERT (buf);

  VCL_SESSION_LOCK_AND_GET (session_index, &session);

  is_nonblocking = VCL_SESS_ATTR_TEST (session->attr, VCL_SESS_ATTR_NONBLOCK);
  rx_fifo = session->rx_fifo;
  state = session->session_state;
  vpp_handle = session->vpp_handle;

  if (PREDICT_FALSE (session->is_vep))
    {
      VCL_SESSION_UNLOCK ();
      clib_warning ("VCL<%d>: ERROR: sid %u: cannot "
		    "read from an epoll session!", getpid (), session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  if (PREDICT_FALSE (!(state & (SERVER_STATE_OPEN | CLIENT_STATE_OPEN))))
    {
      VCL_SESSION_UNLOCK ();
      rv = ((state & STATE_DISCONNECT) ? VPPCOM_ECONNRESET : VPPCOM_ENOTCONN);

      VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: %s session is not open! "
	    "state 0x%x (%s), returning %d (%s)",
	    getpid (), vpp_handle, session_index, state,
	    vppcom_session_state_str (state), rv, vppcom_retval_str (rv));
      goto done;
    }

  VCL_SESSION_UNLOCK ();

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
      VCL_SESSION_LOCK_AND_GET (session_index, &session);

      poll_et = (((EPOLLET | EPOLLIN) & session->vep.ev.events) ==
		 (EPOLLET | EPOLLIN));
      if (poll_et)
	session->vep.et_mask |= EPOLLIN;

      if (state & STATE_CLOSE_ON_EMPTY)
	{
	  rv = VPPCOM_ECONNRESET;

	  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: Empty fifo with "
		"session state 0x%x (%s)! Setting state to 0x%x (%s), "
		"returning %d (%s)",
		getpid (), session->vpp_handle, session_index,
		state, vppcom_session_state_str (state),
		STATE_DISCONNECT,
		vppcom_session_state_str (STATE_DISCONNECT), rv,
		vppcom_retval_str (rv));

	  session->session_state = STATE_DISCONNECT;
	}
      else
	rv = VPPCOM_EAGAIN;

      VCL_SESSION_UNLOCK ();
    }
  else
    rv = n_read;

  if (VPPCOM_DEBUG > 2)
    {
      if (rv > 0)
	clib_warning ("VCL<%d>: vpp handle 0x%llx, sid %u: read %d bytes "
		      "from (%p)", getpid (), vpp_handle,
		      session_index, n_read, rx_fifo);
      else
	clib_warning ("VCL<%d>: vpp handle 0x%llx, sid %u: nothing read! "
		      "returning %d (%s)", getpid (), vpp_handle,
		      session_index, rv, vppcom_retval_str (rv));
    }
done:
  return rv;
}

int
vppcom_session_read (uint32_t session_index, void *buf, size_t n)
{
  return (vppcom_session_read_internal (session_index, buf, n, 0));
}

static int
vppcom_session_peek (uint32_t session_index, void *buf, int n)
{
  return (vppcom_session_read_internal (session_index, buf, n, 1));
}

static inline int
vppcom_session_read_ready (vcl_session_t * session, u32 session_index)
{
  int ready = 0;
  u32 poll_et;
  int rv;
  session_state_t state = session->session_state;
  u64 vpp_handle = session->vpp_handle;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  if (PREDICT_FALSE (session->is_vep))
    {
      clib_warning ("VCL<%d>: ERROR: sid %u: cannot read from an "
		    "epoll session!", getpid (), session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  if (session->session_state & STATE_LISTEN)
    {
      VCL_ACCEPT_FIFO_LOCK ();
      ready = clib_fifo_elts (vcm->client_session_index_fifo);
      VCL_ACCEPT_FIFO_UNLOCK ();
    }
  else
    {
      if (!(state & (SERVER_STATE_OPEN | CLIENT_STATE_OPEN | STATE_LISTEN)))
	{
	  rv = ((state & STATE_DISCONNECT) ? VPPCOM_ECONNRESET :
		VPPCOM_ENOTCONN);

	  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: session is not open!"
		" state 0x%x (%s), returning %d (%s)",
		getpid (), vpp_handle, session_index,
		state, vppcom_session_state_str (state),
		rv, vppcom_retval_str (rv));
	  goto done;
	}

      ready = svm_fifo_max_dequeue (session->rx_fifo);
    }

  if (ready == 0)
    {
      poll_et =
	((EPOLLET | EPOLLIN) & session->vep.ev.events) == (EPOLLET | EPOLLIN);
      if (poll_et)
	session->vep.et_mask |= EPOLLIN;

      if (state & STATE_CLOSE_ON_EMPTY)
	{
	  rv = VPPCOM_ECONNRESET;

	  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: Empty fifo with "
		"session state 0x%x (%s)! Setting state to 0x%x (%s), "
		"returning %d (%s)",
		getpid (), session_index, vpp_handle,
		state, vppcom_session_state_str (state),
		STATE_DISCONNECT,
		vppcom_session_state_str (STATE_DISCONNECT), rv,
		vppcom_retval_str (rv));
	  session->session_state = STATE_DISCONNECT;
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
	svm_queue_sub_raw (vcm->app_event_queue, (u8 *) & e);

      pthread_mutex_unlock (&vcm->app_event_queue->mutex);
    }
done:
  return rv;
}

int
vppcom_session_write (uint32_t session_index, void *buf, size_t n)
{
  vcl_session_t *session = 0;
  svm_fifo_t *tx_fifo = 0;
  svm_queue_t *q;
  session_fifo_event_t evt;
  session_state_t state;
  int rv, n_write, is_nonblocking;
  u32 poll_et;
  u64 vpp_handle;

  ASSERT (buf);

  VCL_SESSION_LOCK_AND_GET (session_index, &session);

  tx_fifo = session->tx_fifo;
  is_nonblocking = VCL_SESS_ATTR_TEST (session->attr, VCL_SESS_ATTR_NONBLOCK);
  vpp_handle = session->vpp_handle;
  state = session->session_state;

  if (PREDICT_FALSE (session->is_vep))
    {
      VCL_SESSION_UNLOCK ();
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "cannot write to an epoll session!",
		    getpid (), vpp_handle, session_index);

      rv = VPPCOM_EBADFD;
      goto done;
    }

  if (!(session->session_state & (SERVER_STATE_OPEN | CLIENT_STATE_OPEN)))
    {
      rv =
	((session->session_state & STATE_DISCONNECT) ? VPPCOM_ECONNRESET :
	 VPPCOM_ENOTCONN);

      VCL_SESSION_UNLOCK ();
      VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: session is not open! "
	    "state 0x%x (%s)",
	    getpid (), vpp_handle, session_index,
	    state, vppcom_session_state_str (state));
      goto done;
    }

  VCL_SESSION_UNLOCK ();

  do
    {
      n_write = svm_fifo_enqueue_nowait (tx_fifo, n, (void *) buf);
    }
  while (!is_nonblocking && (n_write <= 0));

  /* If event wasn't set, add one
   *
   * To reduce context switching, can check if an
   * event is already there for this event_key, but for now
   * this will suffice. */

  if ((n_write > 0) && svm_fifo_set_event (tx_fifo))
    {
      /* Fabricate TX event, send to vpp */
      evt.fifo = tx_fifo;
      evt.event_type = FIFO_EVENT_APP_TX;

      VCL_SESSION_LOCK_AND_GET (session_index, &session);
      q = session->vpp_evt_q;
      ASSERT (q);
      svm_queue_add (q, (u8 *) & evt, 0 /* do wait for mutex */ );
      VCL_SESSION_UNLOCK ();
      VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: added FIFO_EVENT_APP_TX "
	    "to vpp_event_q %p, n_write %d", getpid (),
	    vpp_handle, session_index, q, n_write);
    }

  if (n_write <= 0)
    {
      VCL_SESSION_LOCK_AND_GET (session_index, &session);

      poll_et = (((EPOLLET | EPOLLOUT) & session->vep.ev.events) ==
		 (EPOLLET | EPOLLOUT));
      if (poll_et)
	session->vep.et_mask |= EPOLLOUT;

      if (session->session_state & STATE_CLOSE_ON_EMPTY)
	{
	  rv = VPPCOM_ECONNRESET;

	  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: Empty fifo with "
		"session state 0x%x (%s)! Setting state to 0x%x (%s), "
		"returning %d (%s)",
		getpid (), session->vpp_handle, session_index,
		session->session_state,
		vppcom_session_state_str (session->session_state),
		STATE_DISCONNECT,
		vppcom_session_state_str (STATE_DISCONNECT), rv,
		vppcom_retval_str (rv));

	  session->session_state = STATE_DISCONNECT;
	}
      else
	rv = VPPCOM_EAGAIN;

      VCL_SESSION_UNLOCK ();
    }
  else
    rv = n_write;

  if (VPPCOM_DEBUG > 2)
    {
      if (n_write <= 0)
	clib_warning ("VCL<%d>: vpp handle 0x%llx, sid %u: "
		      "FIFO-FULL (%p)", getpid (), vpp_handle,
		      session_index, tx_fifo);
      else
	clib_warning ("VCL<%d>: vpp handle 0x%llx, sid %u: "
		      "wrote %d bytes tx-fifo: (%p)", getpid (),
		      vpp_handle, session_index, n_write, tx_fifo);
    }
done:
  return rv;
}

static inline int
vppcom_session_write_ready (vcl_session_t * session, u32 session_index)
{
  int ready;
  u32 poll_et;
  int rv;

  ASSERT (session);

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  if (PREDICT_FALSE (session->is_vep))
    {
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "cannot write to an epoll session!",
		    getpid (), session->vpp_handle, session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  if (PREDICT_FALSE (session->session_state & STATE_LISTEN))
    {
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "cannot write to a listen session!",
		    getpid (), session->vpp_handle, session_index);
      rv = VPPCOM_EBADFD;
      goto done;
    }

  if (!(session->session_state & (SERVER_STATE_OPEN | CLIENT_STATE_OPEN)))
    {
      session_state_t state = session->session_state;

      rv = ((state & STATE_DISCONNECT) ? VPPCOM_ECONNRESET : VPPCOM_ENOTCONN);

      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "session is not open! state 0x%x (%s), "
		    "returning %d (%s)", getpid (), session->vpp_handle,
		    session_index,
		    state, vppcom_session_state_str (state),
		    rv, vppcom_retval_str (rv));
      goto done;
    }

  ready = svm_fifo_max_enqueue (session->tx_fifo);

  VDBG (3, "VCL<%d>: vpp handle 0x%llx, sid %u: peek %s (%p), ready = %d",
	getpid (), session->vpp_handle, session_index, session->tx_fifo,
	ready);

  if (ready == 0)
    {
      poll_et = (((EPOLLET | EPOLLOUT) & session->vep.ev.events) ==
		 (EPOLLET | EPOLLOUT));
      if (poll_et)
	session->vep.et_mask |= EPOLLOUT;

      if (session->session_state & STATE_CLOSE_ON_EMPTY)
	{
	  rv = VPPCOM_ECONNRESET;

	  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: Empty fifo with "
		"session state 0x%x (%s)! Setting state to 0x%x (%s), "
		"returning %d (%s)", getpid (),
		session->vpp_handle, session_index,
		session->session_state,
		vppcom_session_state_str (session->session_state),
		STATE_DISCONNECT,
		vppcom_session_state_str (STATE_DISCONNECT), rv,
		vppcom_retval_str (rv));
	  session->session_state = STATE_DISCONNECT;
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
  vcl_session_t *session = 0;
  int rv, bits_set = 0;
  f64 timeout = clib_time_now (&vcm->clib_time) + time_to_wait;
  u32 minbits = clib_max (n_bits, BITS (uword));

  ASSERT (sizeof (clib_bitmap_t) == sizeof (long int));

  if (n_bits && read_map)
    {
      clib_bitmap_validate (vcm->rd_bitmap, minbits);
      clib_memcpy (vcm->rd_bitmap, read_map,
		   vec_len (vcm->rd_bitmap) * sizeof (clib_bitmap_t));
      memset (read_map, 0, vec_len (vcm->rd_bitmap) * sizeof (clib_bitmap_t));
    }
  if (n_bits && write_map)
    {
      clib_bitmap_validate (vcm->wr_bitmap, minbits);
      clib_memcpy (vcm->wr_bitmap, write_map,
		   vec_len (vcm->wr_bitmap) * sizeof (clib_bitmap_t));
      memset (write_map, 0,
	      vec_len (vcm->wr_bitmap) * sizeof (clib_bitmap_t));
    }
  if (n_bits && except_map)
    {
      clib_bitmap_validate (vcm->ex_bitmap, minbits);
      clib_memcpy (vcm->ex_bitmap, except_map,
		   vec_len (vcm->ex_bitmap) * sizeof (clib_bitmap_t));
      memset (except_map, 0,
	      vec_len (vcm->ex_bitmap) * sizeof (clib_bitmap_t));
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
                  VCL_SESSION_LOCK();
                  rv = vppcom_session_at_index (session_index, &session);
                  if (rv < 0)
                    {
                      VCL_SESSION_UNLOCK();
                      VDBG (1, "VCL<%d>: session %d specified in read_map is"
                	  " closed.", getpid (),
                                      session_index);
                      bits_set = VPPCOM_EBADFD;
                      goto select_done;
                    }
                  if (session->session_state & STATE_LISTEN)
                    {
                      vce_event_handler_reg_t *reg = 0;
                      vce_event_key_t evk;

                      /* Check if handler already registered for this
                       * event.
                       * If not, register handler for connect_request event
                       * on listen_session_index
                       */
                      evk.session_index = session_index;
                      evk.eid = VCL_EVENT_CONNECT_REQ_ACCEPTED;
                      reg = vce_get_event_handler (&vcm->event_thread, &evk);
                      if (!reg)
                        reg = vce_register_handler (&vcm->event_thread, &evk,
                                    vce_poll_wait_connect_request_handler_fn,
						    0 /* No callback args */);
                      rv = vppcom_session_read_ready (session, session_index);
                      if (rv > 0)
                        {
                          vce_unregister_handler (&vcm->event_thread, reg);
                        }
                    }
                  else
                    rv = vppcom_session_read_ready (session, session_index);
                  VCL_SESSION_UNLOCK();
                  if (except_map && vcm->ex_bitmap &&
                      clib_bitmap_get (vcm->ex_bitmap, session_index) &&
                      (rv < 0))
                    {
                      clib_bitmap_set_no_check (except_map, session_index, 1);
                      bits_set++;
                    }
                  else if (rv > 0)
                    {
                      clib_bitmap_set_no_check (read_map, session_index, 1);
                      bits_set++;
                    }
                }));
            }

          if (write_map)
            {
              clib_bitmap_foreach (session_index, vcm->wr_bitmap,
                ({
                  VCL_SESSION_LOCK();
                  rv = vppcom_session_at_index (session_index, &session);
                  if (rv < 0)
                    {
                      VCL_SESSION_UNLOCK();
                      VDBG (0, "VCL<%d>: session %d specified in "
                                      "write_map is closed.", getpid (),
                                      session_index);
                      bits_set = VPPCOM_EBADFD;
                      goto select_done;
                    }

                  rv = vppcom_session_write_ready (session, session_index);
                  VCL_SESSION_UNLOCK();
                  if (write_map && (rv > 0))
                    {
                      clib_bitmap_set_no_check (write_map, session_index, 1);
                      bits_set++;
                    }
                }));
            }

          if (except_map)
            {
              clib_bitmap_foreach (session_index, vcm->ex_bitmap,
                ({
                  VCL_SESSION_LOCK();
                  rv = vppcom_session_at_index (session_index, &session);
                  if (rv < 0)
                    {
                      VCL_SESSION_UNLOCK();
                      VDBG (1, "VCL<%d>: session %d specified in except_map "
                	  "is closed.", getpid (),
                                      session_index);
                      bits_set = VPPCOM_EBADFD;
                      goto select_done;
                    }

                  rv = vppcom_session_read_ready (session, session_index);
                  VCL_SESSION_UNLOCK();
                  if (rv < 0)
                    {
                      clib_bitmap_set_no_check (except_map, session_index, 1);
                      bits_set++;
                    }
                }));
            }
        }
      /* *INDENT-ON* */
    }
  while ((time_to_wait == -1) || (clib_time_now (&vcm->clib_time) < timeout));

select_done:
  return (bits_set);
}

static inline void
vep_verify_epoll_chain (u32 vep_idx)
{
  vcl_session_t *session;
  vppcom_epoll_t *vep;
  int rv;
  u32 sid = vep_idx;

  if (VPPCOM_DEBUG <= 1)
    return;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  rv = vppcom_session_at_index (vep_idx, &session);
  if (PREDICT_FALSE (rv))
    {
      clib_warning ("VCL<%d>: ERROR: Invalid vep_idx (%u)!",
		    getpid (), vep_idx);
      goto done;
    }
  if (PREDICT_FALSE (!session->is_vep))
    {
      clib_warning ("VCL<%d>: ERROR: vep_idx (%u) is not a vep!",
		    getpid (), vep_idx);
      goto done;
    }
  vep = &session->vep;
  clib_warning ("VCL<%d>: vep_idx (%u): Dumping epoll chain\n"
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
	  clib_warning ("VCL<%d>: ERROR: Invalid sid (%u)!", getpid (), sid);
	  goto done;
	}
      if (PREDICT_FALSE (session->is_vep))
	clib_warning ("VCL<%d>: ERROR: sid (%u) is a vep!",
		      getpid (), vep_idx);
      else if (PREDICT_FALSE (!session->is_vep_session))
	{
	  clib_warning ("VCL<%d>: ERROR: session (%u) "
			"is not a vep session!", getpid (), sid);
	  goto done;
	}
      vep = &session->vep;
      if (PREDICT_FALSE (vep->vep_idx != vep_idx))
	clib_warning ("VCL<%d>: ERROR: session (%u) vep_idx (%u) != "
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
  clib_warning ("VCL<%d>: vep_idx (%u): Dump complete!\n",
		getpid (), vep_idx);
}

int
vppcom_epoll_create (void)
{
  vcl_session_t *vep_session;
  u32 vep_idx;

  VCL_SESSION_LOCK ();
  pool_get (vcm->sessions, vep_session);
  memset (vep_session, 0, sizeof (*vep_session));
  vep_idx = vep_session - vcm->sessions;

  vep_session->is_vep = 1;
  vep_session->vep.vep_idx = ~0;
  vep_session->vep.next_sid = ~0;
  vep_session->vep.prev_sid = ~0;
  vep_session->wait_cont_idx = ~0;
  vep_session->vpp_handle = ~0;
  vep_session->poll_reg = 0;

  vcl_evt (VCL_EVT_EPOLL_CREATE, vep_session, vep_idx);
  VCL_SESSION_UNLOCK ();

  VDBG (0, "VCL<%d>: Created vep_idx %u / sid %u!",
	getpid (), vep_idx, vep_idx);

  return (vep_idx);
}

int
vppcom_epoll_ctl (uint32_t vep_idx, int op, uint32_t session_index,
		  struct epoll_event *event)
{
  vcl_session_t *vep_session;
  vcl_session_t *session;
  int rv;

  if (vep_idx == session_index)
    {
      clib_warning ("VCL<%d>: ERROR: vep_idx == session_index (%u)!",
		    getpid (), vep_idx);
      return VPPCOM_EINVAL;
    }

  VCL_SESSION_LOCK ();
  rv = vppcom_session_at_index (vep_idx, &vep_session);
  if (PREDICT_FALSE (rv))
    {
      clib_warning ("VCL<%d>: ERROR: Invalid vep_idx (%u)!", vep_idx);
      goto done;
    }
  if (PREDICT_FALSE (!vep_session->is_vep))
    {
      clib_warning ("VCL<%d>: ERROR: vep_idx (%u) is not a vep!",
		    getpid (), vep_idx);
      rv = VPPCOM_EINVAL;
      goto done;
    }

  ASSERT (vep_session->vep.vep_idx == ~0);
  ASSERT (vep_session->vep.prev_sid == ~0);

  rv = vppcom_session_at_index (session_index, &session);
  if (PREDICT_FALSE (rv))
    {
      VDBG (0, "VCL<%d>: ERROR: Invalid session_index (%u)!",
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
	  clib_warning ("VCL<%d>: ERROR: EPOLL_CTL_ADD: NULL pointer to "
			"epoll_event structure!", getpid ());
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      if (vep_session->vep.next_sid != ~0)
	{
	  vcl_session_t *next_session;
	  rv = vppcom_session_at_index (vep_session->vep.next_sid,
					&next_session);
	  if (PREDICT_FALSE (rv))
	    {
	      clib_warning ("VCL<%d>: ERROR: EPOLL_CTL_ADD: Invalid "
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

      /* VCL Event Register handler */
      if (session->session_state & STATE_LISTEN)
	{
	  /* Register handler for connect_request event on listen_session_index */
	  vce_event_key_t evk;
	  evk.session_index = session_index;
	  evk.eid = VCL_EVENT_CONNECT_REQ_ACCEPTED;
	  vep_session->poll_reg =
	    vce_register_handler (&vcm->event_thread, &evk,
				  vce_poll_wait_connect_request_handler_fn,
				  0 /* No callback args */ );
	}
      VDBG (1, "VCL<%d>: EPOLL_CTL_ADD: vep_idx %u, "
	    "sid %u, events 0x%x, data 0x%llx!",
	    getpid (), vep_idx, session_index,
	    event->events, event->data.u64);
      vcl_evt (VCL_EVT_EPOLL_CTLADD, session, event->events, event->data.u64);
      break;

    case EPOLL_CTL_MOD:
      if (PREDICT_FALSE (!event))
	{
	  clib_warning ("VCL<%d>: ERROR: EPOLL_CTL_MOD: NULL pointer to "
			"epoll_event structure!", getpid ());
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      else if (PREDICT_FALSE (!session->is_vep_session))
	{
	  clib_warning ("VCL<%d>: ERROR: sid %u EPOLL_CTL_MOD: "
			"not a vep session!", getpid (), session_index);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      else if (PREDICT_FALSE (session->vep.vep_idx != vep_idx))
	{
	  clib_warning ("VCL<%d>: ERROR: sid %u EPOLL_CTL_MOD: "
			"vep_idx (%u) != vep_idx (%u)!",
			getpid (), session_index,
			session->vep.vep_idx, vep_idx);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      session->vep.et_mask = VEP_DEFAULT_ET_MASK;
      session->vep.ev = *event;
      VDBG (1, "VCL<%d>: EPOLL_CTL_MOD: vep_idx %u, sid %u, events 0x%x,"
	    " data 0x%llx!", getpid (), vep_idx, session_index, event->events,
	    event->data.u64);
      break;

    case EPOLL_CTL_DEL:
      if (PREDICT_FALSE (!session->is_vep_session))
	{
	  clib_warning ("VCL<%d>: ERROR: sid %u EPOLL_CTL_DEL: "
			"not a vep session!", getpid (), session_index);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      else if (PREDICT_FALSE (session->vep.vep_idx != vep_idx))
	{
	  clib_warning ("VCL<%d>: ERROR: sid %u EPOLL_CTL_DEL: "
			"vep_idx (%u) != vep_idx (%u)!",
			getpid (), session_index,
			session->vep.vep_idx, vep_idx);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}

      /* VCL Event Un-register handler */
      if ((session->session_state & STATE_LISTEN) && vep_session->poll_reg)
	{
	  (void) vce_unregister_handler (&vcm->event_thread,
					 vep_session->poll_reg);
	}

      vep_session->wait_cont_idx =
	(vep_session->wait_cont_idx == session_index) ?
	session->vep.next_sid : vep_session->wait_cont_idx;

      if (session->vep.prev_sid == vep_idx)
	vep_session->vep.next_sid = session->vep.next_sid;
      else
	{
	  vcl_session_t *prev_session;
	  rv = vppcom_session_at_index (session->vep.prev_sid, &prev_session);
	  if (PREDICT_FALSE (rv))
	    {
	      clib_warning ("VCL<%d>: ERROR: EPOLL_CTL_DEL: Invalid "
			    "vep.prev_sid (%u) on sid (%u)!",
			    getpid (), session->vep.prev_sid, session_index);
	      goto done;
	    }
	  ASSERT (prev_session->vep.next_sid == session_index);
	  prev_session->vep.next_sid = session->vep.next_sid;
	}
      if (session->vep.next_sid != ~0)
	{
	  vcl_session_t *next_session;
	  rv = vppcom_session_at_index (session->vep.next_sid, &next_session);
	  if (PREDICT_FALSE (rv))
	    {
	      clib_warning ("VCL<%d>: ERROR: EPOLL_CTL_DEL: Invalid "
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
      VDBG (1, "VCL<%d>: EPOLL_CTL_DEL: vep_idx %u, sid %u!",
	    getpid (), vep_idx, session_index);
      vcl_evt (VCL_EVT_EPOLL_CTLDEL, session, vep_idx);
      break;

    default:
      clib_warning ("VCL<%d>: ERROR: Invalid operation (%d)!", getpid (), op);
      rv = VPPCOM_EINVAL;
    }

  vep_verify_epoll_chain (vep_idx);

done:
  VCL_SESSION_UNLOCK ();
  return rv;
}

int
vppcom_epoll_wait (uint32_t vep_idx, struct epoll_event *events,
		   int maxevents, double wait_for_time)
{
  vcl_session_t *vep_session;
  int rv;
  f64 timeout = clib_time_now (&vcm->clib_time) + wait_for_time;
  u32 keep_trying = 1;
  int num_ev = 0;
  u32 vep_next_sid, wait_cont_idx;
  u8 is_vep;

  if (PREDICT_FALSE (maxevents <= 0))
    {
      clib_warning ("VCL<%d>: ERROR: Invalid maxevents (%d)!",
		    getpid (), maxevents);
      return VPPCOM_EINVAL;
    }
  memset (events, 0, sizeof (*events) * maxevents);

  VCL_SESSION_LOCK_AND_GET (vep_idx, &vep_session);
  vep_next_sid = vep_session->vep.next_sid;
  is_vep = vep_session->is_vep;
  wait_cont_idx = vep_session->wait_cont_idx;
  VCL_SESSION_UNLOCK ();

  if (PREDICT_FALSE (!is_vep))
    {
      clib_warning ("VCL<%d>: ERROR: vep_idx (%u) is not a vep!",
		    getpid (), vep_idx);
      rv = VPPCOM_EINVAL;
      goto done;
    }
  if (PREDICT_FALSE (vep_next_sid == ~0))
    {
      VDBG (1, "VCL<%d>: WARNING: vep_idx (%u) is empty!",
	    getpid (), vep_idx);
      goto done;
    }

  do
    {
      u32 sid;
      u32 next_sid = ~0;
      vcl_session_t *session;

      for (sid = (wait_cont_idx == ~0) ? vep_next_sid : wait_cont_idx;
	   sid != ~0; sid = next_sid)
	{
	  u32 session_events, et_mask, clear_et_mask, session_vep_idx;
	  u8 add_event, is_vep_session;
	  int ready;
	  u64 session_ev_data;

	  VCL_SESSION_LOCK_AND_GET (sid, &session);
	  next_sid = session->vep.next_sid;
	  session_events = session->vep.ev.events;
	  et_mask = session->vep.et_mask;
	  is_vep = session->is_vep;
	  is_vep_session = session->is_vep_session;
	  session_vep_idx = session->vep.vep_idx;
	  session_ev_data = session->vep.ev.data.u64;

	  VCL_SESSION_UNLOCK ();

	  if (PREDICT_FALSE (is_vep))
	    {
	      VDBG (0, "VCL<%d>: ERROR: sid (%u) is a vep!",
		    getpid (), vep_idx);
	      rv = VPPCOM_EINVAL;
	      goto done;
	    }
	  if (PREDICT_FALSE (!is_vep_session))
	    {
	      VDBG (0, "VCL<%d>: ERROR: session (%u) is not "
		    "a vep session!", getpid (), sid);
	      rv = VPPCOM_EINVAL;
	      goto done;
	    }
	  if (PREDICT_FALSE (session_vep_idx != vep_idx))
	    {
	      clib_warning ("VCL<%d>: ERROR: session (%u) "
			    "vep_idx (%u) != vep_idx (%u)!",
			    getpid (), sid, session_vep_idx, vep_idx);
	      rv = VPPCOM_EINVAL;
	      goto done;
	    }

	  add_event = clear_et_mask = 0;

	  if (EPOLLIN & session_events)
	    {
	      VCL_SESSION_LOCK_AND_GET (sid, &session);
	      ready = vppcom_session_read_ready (session, sid);
	      VCL_SESSION_UNLOCK ();
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
	      VCL_SESSION_LOCK_AND_GET (sid, &session);
	      ready = vppcom_session_write_ready (session, sid);
	      VCL_SESSION_UNLOCK ();
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
		  VCL_SESSION_LOCK_AND_GET (sid, &session);
		  session->vep.ev.events = 0;
		  VCL_SESSION_UNLOCK ();
		}
	      num_ev++;
	      if (num_ev == maxevents)
		{
		  VCL_SESSION_LOCK_AND_GET (vep_idx, &vep_session);
		  vep_session->wait_cont_idx = next_sid;
		  VCL_SESSION_UNLOCK ();
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
      VCL_SESSION_LOCK_AND_GET (vep_idx, &vep_session);
      vep_session->wait_cont_idx = ~0;
      VCL_SESSION_UNLOCK ();
    }
done:
  return (rv != VPPCOM_OK) ? rv : num_ev;
}

int
vppcom_session_attr (uint32_t session_index, uint32_t op,
		     void *buffer, uint32_t * buflen)
{
  vcl_session_t *session;
  int rv = VPPCOM_OK;
  u32 *flags = buffer;
  vppcom_endpt_t *ep = buffer;

  VCL_SESSION_LOCK_AND_GET (session_index, &session);

  ASSERT (session);

  switch (op)
    {
    case VPPCOM_ATTR_GET_NREAD:
      rv = vppcom_session_read_ready (session, session_index);
      VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_NREAD: sid %u, nread = %d",
	    getpid (), rv);
      break;

    case VPPCOM_ATTR_GET_NWRITE:
      rv = vppcom_session_write_ready (session, session_index);
      VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_NWRITE: sid %u, nwrite = %d",
	    getpid (), session_index, rv);
      break;

    case VPPCOM_ATTR_GET_FLAGS:
      if (PREDICT_TRUE (buffer && buflen && (*buflen >= sizeof (*flags))))
	{
	  *flags = O_RDWR | (VCL_SESS_ATTR_TEST (session->attr,
						 VCL_SESS_ATTR_NONBLOCK));
	  *buflen = sizeof (*flags);
	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_FLAGS: sid %u, flags = 0x%08x, "
		"is_nonblocking = %u", getpid (),
		session_index, *flags,
		VCL_SESS_ATTR_TEST (session->attr, VCL_SESS_ATTR_NONBLOCK));
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_FLAGS:
      if (PREDICT_TRUE (buffer && buflen && (*buflen == sizeof (*flags))))
	{
	  if (*flags & O_NONBLOCK)
	    VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_NONBLOCK);
	  else
	    VCL_SESS_ATTR_CLR (session->attr, VCL_SESS_ATTR_NONBLOCK);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_FLAGS: sid %u, flags = 0x%08x,"
		" is_nonblocking = %u",
		getpid (), session_index, *flags,
		VCL_SESS_ATTR_TEST (session->attr, VCL_SESS_ATTR_NONBLOCK));
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_PEER_ADDR:
      if (PREDICT_TRUE (buffer && buflen &&
			(*buflen >= sizeof (*ep)) && ep->ip))
	{
	  ep->is_ip4 = session->transport.is_ip4;
	  ep->port = session->transport.rmt_port;
	  if (session->transport.is_ip4)
	    clib_memcpy (ep->ip, &session->transport.rmt_ip.ip4,
			 sizeof (ip4_address_t));
	  else
	    clib_memcpy (ep->ip, &session->transport.rmt_ip.ip6,
			 sizeof (ip6_address_t));
	  *buflen = sizeof (*ep);
	  VDBG (1, "VCL<%d>: VPPCOM_ATTR_GET_PEER_ADDR: sid %u, is_ip4 = %u, "
		"addr = %U, port %u", getpid (),
		session_index, ep->is_ip4, format_ip46_address,
		&session->transport.rmt_ip,
		ep->is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
		clib_net_to_host_u16 (ep->port));
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_LCL_ADDR:
      if (PREDICT_TRUE (buffer && buflen &&
			(*buflen >= sizeof (*ep)) && ep->ip))
	{
	  ep->is_ip4 = session->transport.is_ip4;
	  ep->port = session->transport.lcl_port;
	  if (session->transport.is_ip4)
	    clib_memcpy (ep->ip, &session->transport.lcl_ip.ip4,
			 sizeof (ip4_address_t));
	  else
	    clib_memcpy (ep->ip, &session->transport.lcl_ip.ip6,
			 sizeof (ip6_address_t));
	  *buflen = sizeof (*ep);
	  VDBG (1, "VCL<%d>: VPPCOM_ATTR_GET_LCL_ADDR: sid %u, is_ip4 = %u,"
		" addr = %U port %d", getpid (),
		session_index, ep->is_ip4, format_ip46_address,
		&session->transport.lcl_ip,
		ep->is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
		clib_net_to_host_u16 (ep->port));
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_LIBC_EPFD:
      rv = session->libc_epfd;
      VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_LIBC_EPFD: libc_epfd %d",
	    getpid (), rv);
      break;

    case VPPCOM_ATTR_SET_LIBC_EPFD:
      if (PREDICT_TRUE (buffer && buflen &&
			(*buflen == sizeof (session->libc_epfd))))
	{
	  session->libc_epfd = *(int *) buffer;
	  *buflen = sizeof (session->libc_epfd);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_LIBC_EPFD: libc_epfd %d, "
		"buflen %d", getpid (), session->libc_epfd, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_PROTOCOL:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  *(int *) buffer = session->session_type;
	  *buflen = sizeof (int);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_PROTOCOL: %d (%s), buflen %d",
		getpid (), *(int *) buffer, *(int *) buffer ? "UDP" : "TCP",
		*buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_LISTEN:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  *(int *) buffer = VCL_SESS_ATTR_TEST (session->attr,
						VCL_SESS_ATTR_LISTEN);
	  *buflen = sizeof (int);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_LISTEN: %d, buflen %d",
		getpid (), *(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_ERROR:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  *(int *) buffer = 0;
	  *buflen = sizeof (int);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_ERROR: %d, buflen %d, #VPP-TBD#",
		getpid (), *(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_TX_FIFO_LEN:
      if (buffer && buflen && (*buflen >= sizeof (u32)))
	{

	  /* VPP-TBD */
	  *(size_t *) buffer = (session->sndbuf_size ? session->sndbuf_size :
				session->tx_fifo ? session->tx_fifo->nitems :
				vcm->cfg.tx_fifo_size);
	  *buflen = sizeof (u32);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_TX_FIFO_LEN: %u (0x%x), "
		"buflen %d, #VPP-TBD#", getpid (),
		*(size_t *) buffer, *(size_t *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_TX_FIFO_LEN:
      if (buffer && buflen && (*buflen == sizeof (u32)))
	{
	  /* VPP-TBD */
	  session->sndbuf_size = *(u32 *) buffer;
	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_TX_FIFO_LEN: %u (0x%x), "
		"buflen %d, #VPP-TBD#", getpid (),
		session->sndbuf_size, session->sndbuf_size, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_RX_FIFO_LEN:
      if (buffer && buflen && (*buflen >= sizeof (u32)))
	{

	  /* VPP-TBD */
	  *(size_t *) buffer = (session->rcvbuf_size ? session->rcvbuf_size :
				session->rx_fifo ? session->rx_fifo->nitems :
				vcm->cfg.rx_fifo_size);
	  *buflen = sizeof (u32);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_RX_FIFO_LEN: %u (0x%x), "
		"buflen %d, #VPP-TBD#", getpid (),
		*(size_t *) buffer, *(size_t *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_RX_FIFO_LEN:
      if (buffer && buflen && (*buflen == sizeof (u32)))
	{
	  /* VPP-TBD */
	  session->rcvbuf_size = *(u32 *) buffer;
	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_RX_FIFO_LEN: %u (0x%x), "
		"buflen %d, #VPP-TBD#", getpid (),
		session->sndbuf_size, session->sndbuf_size, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_REUSEADDR:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = VCL_SESS_ATTR_TEST (session->attr,
						VCL_SESS_ATTR_REUSEADDR);
	  *buflen = sizeof (int);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_REUSEADDR: %d, "
		"buflen %d, #VPP-TBD#", getpid (), *(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_REUSEADDR:
      if (buffer && buflen && (*buflen == sizeof (int)) &&
	  !VCL_SESS_ATTR_TEST (session->attr, VCL_SESS_ATTR_LISTEN))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_REUSEADDR);
	  else
	    VCL_SESS_ATTR_CLR (session->attr, VCL_SESS_ATTR_REUSEADDR);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_REUSEADDR: %d, buflen %d,"
		" #VPP-TBD#", getpid (),
		VCL_SESS_ATTR_TEST (session->attr,
				    VCL_SESS_ATTR_REUSEADDR), *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_REUSEPORT:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = VCL_SESS_ATTR_TEST (session->attr,
						VCL_SESS_ATTR_REUSEPORT);
	  *buflen = sizeof (int);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_REUSEPORT: %d, buflen %d,"
		" #VPP-TBD#", getpid (), *(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_REUSEPORT:
      if (buffer && buflen && (*buflen == sizeof (int)) &&
	  !VCL_SESS_ATTR_TEST (session->attr, VCL_SESS_ATTR_LISTEN))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_REUSEPORT);
	  else
	    VCL_SESS_ATTR_CLR (session->attr, VCL_SESS_ATTR_REUSEPORT);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_REUSEPORT: %d, buflen %d,"
		" #VPP-TBD#", getpid (),
		VCL_SESS_ATTR_TEST (session->attr,
				    VCL_SESS_ATTR_REUSEPORT), *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_BROADCAST:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = VCL_SESS_ATTR_TEST (session->attr,
						VCL_SESS_ATTR_BROADCAST);
	  *buflen = sizeof (int);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_BROADCAST: %d, buflen %d,"
		" #VPP-TBD#", getpid (), *(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_BROADCAST:
      if (buffer && buflen && (*buflen == sizeof (int)))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_BROADCAST);
	  else
	    VCL_SESS_ATTR_CLR (session->attr, VCL_SESS_ATTR_BROADCAST);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_BROADCAST: %d, buflen %d, "
		"#VPP-TBD#", getpid (),
		VCL_SESS_ATTR_TEST (session->attr,
				    VCL_SESS_ATTR_BROADCAST), *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_V6ONLY:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = VCL_SESS_ATTR_TEST (session->attr,
						VCL_SESS_ATTR_V6ONLY);
	  *buflen = sizeof (int);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_V6ONLY: %d, buflen %d, "
		"#VPP-TBD#", getpid (), *(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_V6ONLY:
      if (buffer && buflen && (*buflen == sizeof (int)))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_V6ONLY);
	  else
	    VCL_SESS_ATTR_CLR (session->attr, VCL_SESS_ATTR_V6ONLY);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_V6ONLY: %d, buflen %d, "
		"#VPP-TBD#", getpid (),
		VCL_SESS_ATTR_TEST (session->attr,
				    VCL_SESS_ATTR_V6ONLY), *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_KEEPALIVE:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = VCL_SESS_ATTR_TEST (session->attr,
						VCL_SESS_ATTR_KEEPALIVE);
	  *buflen = sizeof (int);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_KEEPALIVE: %d, buflen %d, "
		"#VPP-TBD#", getpid (), *(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_KEEPALIVE:
      if (buffer && buflen && (*buflen == sizeof (int)))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_KEEPALIVE);
	  else
	    VCL_SESS_ATTR_CLR (session->attr, VCL_SESS_ATTR_KEEPALIVE);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_KEEPALIVE: %d, buflen %d, "
		"#VPP-TBD#", getpid (),
		VCL_SESS_ATTR_TEST (session->attr,
				    VCL_SESS_ATTR_KEEPALIVE), *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_TCP_NODELAY:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = VCL_SESS_ATTR_TEST (session->attr,
						VCL_SESS_ATTR_TCP_NODELAY);
	  *buflen = sizeof (int);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_TCP_NODELAY: %d, buflen %d, "
		"#VPP-TBD#", getpid (), *(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_TCP_NODELAY:
      if (buffer && buflen && (*buflen == sizeof (int)))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_TCP_NODELAY);
	  else
	    VCL_SESS_ATTR_CLR (session->attr, VCL_SESS_ATTR_TCP_NODELAY);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_TCP_NODELAY: %d, buflen %d, "
		"#VPP-TBD#", getpid (),
		VCL_SESS_ATTR_TEST (session->attr,
				    VCL_SESS_ATTR_TCP_NODELAY), *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_TCP_KEEPIDLE:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = VCL_SESS_ATTR_TEST (session->attr,
						VCL_SESS_ATTR_TCP_KEEPIDLE);
	  *buflen = sizeof (int);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_TCP_KEEPIDLE: %d, buflen %d, "
		"#VPP-TBD#", getpid (), *(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_TCP_KEEPIDLE:
      if (buffer && buflen && (*buflen == sizeof (int)))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_TCP_KEEPIDLE);
	  else
	    VCL_SESS_ATTR_CLR (session->attr, VCL_SESS_ATTR_TCP_KEEPIDLE);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_TCP_KEEPIDLE: %d, buflen %d, "
		"#VPP-TBD#", getpid (),
		VCL_SESS_ATTR_TEST (session->attr,
				    VCL_SESS_ATTR_TCP_KEEPIDLE), *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_TCP_KEEPINTVL:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = VCL_SESS_ATTR_TEST (session->attr,
						VCL_SESS_ATTR_TCP_KEEPINTVL);
	  *buflen = sizeof (int);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_TCP_KEEPINTVL: %d, buflen %d, "
		"#VPP-TBD#", getpid (), *(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_TCP_KEEPINTVL:
      if (buffer && buflen && (*buflen == sizeof (int)))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_TCP_KEEPINTVL);
	  else
	    VCL_SESS_ATTR_CLR (session->attr, VCL_SESS_ATTR_TCP_KEEPINTVL);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_TCP_KEEPINTVL: %d, buflen %d, "
		"#VPP-TBD#", getpid (),
		VCL_SESS_ATTR_TEST (session->attr,
				    VCL_SESS_ATTR_TCP_KEEPINTVL), *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_TCP_USER_MSS:
      if (buffer && buflen && (*buflen >= sizeof (u32)))
	{
	  /* VPP-TBD */
	  *(u32 *) buffer = session->user_mss;
	  *buflen = sizeof (int);

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_TCP_USER_MSS: %d, buflen %d,"
		" #VPP-TBD#", getpid (), *(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_TCP_USER_MSS:
      if (buffer && buflen && (*buflen == sizeof (u32)))
	{
	  /* VPP-TBD */
	  session->user_mss = *(u32 *) buffer;

	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_SET_TCP_USER_MSS: %u, buflen %d, "
		"#VPP-TBD#", getpid (), session->user_mss, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    default:
      rv = VPPCOM_EINVAL;
      break;
    }

done:
  VCL_SESSION_UNLOCK ();
  return rv;
}

int
vppcom_session_recvfrom (uint32_t session_index, void *buffer,
			 uint32_t buflen, int flags, vppcom_endpt_t * ep)
{
  int rv = VPPCOM_OK;
  vcl_session_t *session = 0;

  if (ep)
    {
      VCL_SESSION_LOCK ();
      rv = vppcom_session_at_index (session_index, &session);
      if (PREDICT_FALSE (rv))
	{
	  VCL_SESSION_UNLOCK ();
	  VDBG (0, "VCL<%d>: invalid session, sid (%u) has been closed!",
		getpid (), session_index);
	  rv = VPPCOM_EBADFD;
	  VCL_SESSION_UNLOCK ();
	  goto done;
	}
      ep->is_ip4 = session->transport.is_ip4;
      ep->port = session->transport.rmt_port;
      if (session->transport.is_ip4)
	clib_memcpy (ep->ip, &session->transport.rmt_ip.ip4,
		     sizeof (ip4_address_t));
      else
	clib_memcpy (ep->ip, &session->transport.rmt_ip.ip6,
		     sizeof (ip6_address_t));
      VCL_SESSION_UNLOCK ();
    }

  if (flags == 0)
    rv = vppcom_session_read (session_index, buffer, buflen);
  else if (flags & MSG_PEEK)
    rv = vppcom_session_peek (session_index, buffer, buflen);
  else
    {
      clib_warning ("VCL<%d>: Unsupport flags for recvfrom %d",
		    getpid (), flags);
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
      VDBG (2, "VCL<%d>: handling flags 0x%u (%d) not implemented yet.",
	    getpid (), flags, flags);
    }

  return (vppcom_session_write (session_index, buffer, buflen));
}

int
vppcom_poll (vcl_poll_t * vp, uint32_t n_sids, double wait_for_time)
{
  f64 timeout = clib_time_now (&vcm->clib_time) + wait_for_time;
  u32 i, keep_trying = 1;
  int rv, num_ev = 0;

  VDBG (3, "VCL<%d>: vp %p, nsids %u, wait_for_time %f",
	getpid (), vp, n_sids, wait_for_time);

  if (!vp)
    return VPPCOM_EFAULT;

  do
    {
      vcl_session_t *session;

      for (i = 0; i < n_sids; i++)
	{
	  ASSERT (vp[i].revents);

	  VCL_SESSION_LOCK_AND_GET (vp[i].sid, &session);
	  VCL_SESSION_UNLOCK ();

	  if (*vp[i].revents)
	    *vp[i].revents = 0;

	  if (POLLIN & vp[i].events)
	    {
	      VCL_SESSION_LOCK_AND_GET (vp[i].sid, &session);
	      rv = vppcom_session_read_ready (session, vp[i].sid);
	      VCL_SESSION_UNLOCK ();
	      if (rv > 0)
		{
		  *vp[i].revents |= POLLIN;
		  num_ev++;
		}
	      else if (rv < 0)
		{
		  switch (rv)
		    {
		    case VPPCOM_ECONNRESET:
		      *vp[i].revents = POLLHUP;
		      break;

		    default:
		      *vp[i].revents = POLLERR;
		      break;
		    }
		  num_ev++;
		}
	    }

	  if (POLLOUT & vp[i].events)
	    {
	      VCL_SESSION_LOCK_AND_GET (vp[i].sid, &session);
	      rv = vppcom_session_write_ready (session, vp[i].sid);
	      VCL_SESSION_UNLOCK ();
	      if (rv > 0)
		{
		  *vp[i].revents |= POLLOUT;
		  num_ev++;
		}
	      else if (rv < 0)
		{
		  switch (rv)
		    {
		    case VPPCOM_ECONNRESET:
		      *vp[i].revents = POLLHUP;
		      break;

		    default:
		      *vp[i].revents = POLLERR;
		      break;
		    }
		  num_ev++;
		}
	    }

	  if (0)		// Note "done:" label used by VCL_SESSION_LOCK_AND_GET()
	    {
	    done:
	      *vp[i].revents = POLLNVAL;
	      num_ev++;
	    }
	}
      if (wait_for_time != -1)
	keep_trying = (clib_time_now (&vcm->clib_time) <= timeout) ? 1 : 0;
    }
  while ((num_ev == 0) && keep_trying);

  if (VPPCOM_DEBUG > 3)
    {
      clib_warning ("VCL<%d>: returning %d", getpid (), num_ev);
      for (i = 0; i < n_sids; i++)
	{
	  clib_warning ("VCL<%d>: vp[%d].sid %d (0x%x), .events 0x%x, "
			".revents 0x%x", getpid (), i, vp[i].sid, vp[i].sid,
			vp[i].events, *vp[i].revents);
	}
    }
  return num_ev;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
