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

#include <vcl/vcl_private.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>

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

u8 *
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
  vl_api_session_enable_disable_reply_t_handler
  (vl_api_session_enable_disable_reply_t * mp)
{
  if (mp->retval)
    {
      clib_warning ("VCL<%d>: session_enable_disable failed: %U", getpid (),
		    format_api_error, ntohl (mp->retval));
    }
  else
    vcm->app_state = STATE_APP_ENABLED;
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
      clib_warning ("VCL<%d>: attach failed: %U", getpid (),
		    format_api_error, ntohl (mp->retval));
      return;
    }

  if (mp->segment_name_length == 0)
    {
      clib_warning ("VCL<%d>: segment_name_length zero", getpid ());
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
      clib_warning ("VCL<%d>: svm_fifo_segment_attach ('%s') failed",
		    getpid (), mp->segment_name);
      return;
    }

  vcm->app_event_queue =
    uword_to_pointer (mp->app_event_queue_address, svm_msg_q_t *);

  vcm->app_state = STATE_APP_ATTACHED;
}

static void
vl_api_application_detach_reply_t_handler (vl_api_application_detach_reply_t *
					   mp)
{
  if (mp->retval)
    clib_warning ("VCL<%d>: detach failed: %U", getpid (), format_api_error,
		  ntohl (mp->retval));

  vcm->app_state = STATE_APP_ENABLED;
}

static void
vl_api_disconnect_session_reply_t_handler (vl_api_disconnect_session_reply_t *
					   mp)
{
  if (mp->retval)
    clib_warning ("VCL<%d>: vpp handle 0x%llx: disconnect session failed: %U",
		  getpid (), mp->handle, format_api_error,
		  ntohl (mp->retval));
}

static void
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t * mp)
{
  static svm_fifo_segment_create_args_t _a;
  svm_fifo_segment_create_args_t *a = &_a;
  int rv;

  vcm->mounting_segment = 1;
  memset (a, 0, sizeof (*a));
  a->segment_name = (char *) mp->segment_name;
  a->segment_size = mp->segment_size;
  /* Attach to the segment vpp created */
  rv = svm_fifo_segment_attach (a);
  vec_reset_length (a->new_segment_indices);
  if (PREDICT_FALSE (rv))
    {
      clib_warning ("VCL<%d>: svm_fifo_segment_attach ('%s') failed",
		    getpid (), mp->segment_name);
      return;
    }

  VDBG (1, "VCL<%d>: mapped new segment '%s' size %d", getpid (),
	mp->segment_name, mp->segment_size);
  vcm->mounting_segment = 0;
}

static void
vl_api_unmap_segment_t_handler (vl_api_unmap_segment_t * mp)
{

/*
 * XXX Need segment_name to session_id hash,
 * XXX - have sessionID by handle hash currently
 */

  VDBG (1, "Unmapped segment '%s'", mp->segment_name);
}

static void
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  uword *p;

  p = hash_get (vcm->session_index_by_vpp_handles, mp->handle);
  if (p)
    {
      int rv;
      vcl_session_t *session = 0;
      u32 session_index = p[0];

      VCL_SESSION_LOCK_AND_GET (session_index, &session);
      session->session_state = STATE_CLOSE_ON_EMPTY;

      VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: setting state to 0x%x "
	    "(%s)", getpid (), mp->handle, session_index,
	    session->session_state,
	    vppcom_session_state_str (session->session_state));
      VCL_SESSION_UNLOCK ();
      return;

    done:
      VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: session lookup failed!",
	    getpid (), mp->handle, session_index);
    }
  else
    clib_warning ("VCL<%d>: vpp handle 0x%llx: session lookup by "
		  "handle failed!", getpid (), mp->handle);
}

static void
vl_api_reset_session_t_handler (vl_api_reset_session_t * mp)
{
  vcl_session_t *session = 0;
  vl_api_reset_session_reply_t *rmp;
  uword *p;
  int rv = 0;

  p = hash_get (vcm->session_index_by_vpp_handles, mp->handle);
  if (p)
    {
      int rval;
      VCL_SESSION_LOCK ();
      rval = vppcom_session_at_index (p[0], &session);
      if (PREDICT_FALSE (rval))
	{
	  rv = VNET_API_ERROR_INVALID_VALUE_2;
	  clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
			"session lookup failed! returning %d %U",
			getpid (), mp->handle, p[0],
			rv, format_api_error, rv);
	}
      else
	{
	  /* TBD: should this disconnect immediately and
	   * flush the fifos?
	   */
	  session->session_state = STATE_CLOSE_ON_EMPTY;

	  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: state set to %d "
		"(%s)!", getpid (), mp->handle, p[0], session->session_state,
		vppcom_session_state_str (session->session_state));
	}
      VCL_SESSION_UNLOCK ();
    }
  else
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx: session lookup "
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
  vcl_session_t *session = 0;
  u32 session_index;
  svm_fifo_t *rx_fifo, *tx_fifo;
  int rv = VPPCOM_OK;

  session_index = mp->context;
  VCL_SESSION_LOCK_AND_GET (session_index, &session);
done:
  if (mp->retval)
    {
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "connect failed! %U",
		    getpid (), mp->handle, session_index,
		    format_api_error, ntohl (mp->retval));
      if (session)
	{
	  session->session_state = STATE_FAILED;
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

  /*
   * Setup session
   */
  if (vcm->session_io_thread.io_sessions_lockp)
    {
      // Add this connection to the active io sessions list
      VCL_IO_SESSIONS_LOCK ();
      u32 *active_session_index;
      pool_get (vcm->session_io_thread.active_session_indexes,
		active_session_index);
      *active_session_index = session_index;
      VCL_IO_SESSIONS_UNLOCK ();
    }
  session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					 svm_msg_q_t *);

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;
  session->vpp_handle = mp->handle;
  session->transport.is_ip4 = mp->is_ip4;
  clib_memcpy (&session->transport.lcl_ip, mp->lcl_ip,
	       sizeof (session->transport.rmt_ip));
  session->transport.lcl_port = mp->lcl_port;
  session->session_state = STATE_CONNECT;

  /* Add it to lookup table */
  hash_set (vcm->session_index_by_vpp_handles, mp->handle, session_index);

  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: connect succeeded! "
	"session_rx_fifo %p, refcnt %d, session_tx_fifo %p, refcnt %d",
	getpid (), mp->handle, session_index, session->rx_fifo,
	session->rx_fifo->refcnt, session->tx_fifo, session->tx_fifo->refcnt);
done_unlock:
  VCL_SESSION_UNLOCK ();
}

static void
vl_api_bind_sock_reply_t_handler (vl_api_bind_sock_reply_t * mp)
{
  vcl_session_t *session = 0;
  u32 session_index = mp->context;
  int rv;

  VCL_SESSION_LOCK_AND_GET (session_index, &session);
done:
  if (mp->retval)
    {
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, "
		    "sid %u: bind failed: %U",
		    getpid (), mp->handle, session_index,
		    format_api_error, ntohl (mp->retval));
      rv = vppcom_session_at_index (session_index, &session);
      if (rv == VPPCOM_OK)
	{
	  session->session_state = STATE_FAILED;
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
  session->transport.is_ip4 = mp->lcl_is_ip4;
  clib_memcpy (&session->transport.lcl_ip, mp->lcl_ip,
	       sizeof (ip46_address_t));
  session->transport.lcl_port = mp->lcl_port;
  vppcom_session_table_add_listener (mp->handle, session_index);
  session->session_state = STATE_LISTEN;

  if (session->is_dgram)
    {
      svm_fifo_t *rx_fifo, *tx_fifo;
      session->vpp_evt_q = uword_to_pointer (mp->vpp_evt_q, svm_msg_q_t *);
      rx_fifo = uword_to_pointer (mp->rx_fifo, svm_fifo_t *);
      rx_fifo->client_session_index = session_index;
      tx_fifo = uword_to_pointer (mp->tx_fifo, svm_fifo_t *);
      tx_fifo->client_session_index = session_index;
      session->rx_fifo = rx_fifo;
      session->tx_fifo = tx_fifo;
    }

  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: bind succeeded!",
	getpid (), mp->handle, mp->context);
done_unlock:
  VCL_SESSION_UNLOCK ();
}

static void
vl_api_unbind_sock_reply_t_handler (vl_api_unbind_sock_reply_t * mp)
{
  if (mp->retval)
    clib_warning ("VCL<%d>: ERROR: sid %u: unbind failed: %U",
		  getpid (), mp->context, format_api_error,
		  ntohl (mp->retval));

  else
    VDBG (1, "VCL<%d>: sid %u: unbind succeeded!", getpid (), mp->context);
}

static void
vl_api_accept_session_t_handler (vl_api_accept_session_t * mp)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  vcl_session_t *session, *listen_session;
  u32 session_index;
  vce_event_connect_request_t *ecr;
  vce_event_t *ev;
  int rv;
  u32 ev_idx;
  uword elts = 0;

  VCL_SESSION_LOCK ();

  VCL_ACCEPT_FIFO_LOCK ();
  elts = clib_fifo_free_elts (vcm->client_session_index_fifo);
  VCL_ACCEPT_FIFO_UNLOCK ();

  if (!elts)
    {
      clib_warning ("VCL<%d>: client session queue is full!", getpid ());
      vppcom_send_accept_session_reply (mp->handle, mp->context,
					VNET_API_ERROR_QUEUE_FULL);
      VCL_SESSION_UNLOCK ();
      return;
    }

  listen_session = vppcom_session_table_lookup_listener (mp->listener_handle);
  if (!listen_session)
    {
      clib_warning ("VCL<%d>: ERROR: couldn't find listen session: "
		    "unknown vpp listener handle %llx",
		    getpid (), mp->listener_handle);
      vppcom_send_accept_session_reply (mp->handle, mp->context,
					VNET_API_ERROR_INVALID_ARGUMENT);
      VCL_SESSION_UNLOCK ();
      return;
    }

  /* TODO check listener depth and update */
  /* TODO on "child" fd close, update listener depth */

  /* Allocate local session and set it up */
  pool_get (vcm->sessions, session);
  memset (session, 0, sizeof (*session));
  session_index = (u32) (session - vcm->sessions);

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->vpp_handle = mp->handle;
  session->client_context = mp->context;
  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;
  session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					 svm_msg_q_t *);
  session->session_state = STATE_ACCEPT;
  session->transport.rmt_port = mp->port;
  session->transport.is_ip4 = mp->is_ip4;
  clib_memcpy (&session->transport.rmt_ip, mp->ip, sizeof (ip46_address_t));

  /* Add it to lookup table */
  hash_set (vcm->session_index_by_vpp_handles, mp->handle, session_index);
  session->transport.lcl_port = listen_session->transport.lcl_port;
  session->transport.lcl_ip = listen_session->transport.lcl_ip;

  /* Create an event for handlers */

  VCL_EVENTS_LOCK ();

  pool_get (vcm->event_thread.vce_events, ev);
  ev_idx = (u32) (ev - vcm->event_thread.vce_events);
  ecr = vce_get_event_data (ev, sizeof (*ecr));
  ev->evk.eid = VCL_EVENT_CONNECT_REQ_ACCEPTED;
  listen_session = vppcom_session_table_lookup_listener (mp->listener_handle);
  ev->evk.session_index = (u32) (listen_session - vcm->sessions);
  ecr->accepted_session_index = session_index;

  VCL_EVENTS_UNLOCK ();

  rv = vce_generate_event (&vcm->event_thread, ev_idx);
  ASSERT (rv == 0);

  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: client accept request from %s"
	" address %U port %d queue %p!", getpid (), mp->handle, session_index,
	mp->is_ip4 ? "IPv4" : "IPv6", format_ip46_address, &mp->ip,
	mp->is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
	clib_net_to_host_u16 (mp->port), session->vpp_evt_q);

  vcl_evt (VCL_EVT_ACCEPT, session, listen_session, session_index);
  VCL_SESSION_UNLOCK ();
}

#define foreach_sock_msg                                        \
_(SESSION_ENABLE_DISABLE_REPLY, session_enable_disable_reply)   \
_(BIND_SOCK_REPLY, bind_sock_reply)                             \
_(UNBIND_SOCK_REPLY, unbind_sock_reply)                         \
_(ACCEPT_SESSION, accept_session)                               \
_(CONNECT_SESSION_REPLY, connect_session_reply)                 \
_(DISCONNECT_SESSION, disconnect_session)                       \
_(DISCONNECT_SESSION_REPLY, disconnect_session_reply)           \
_(RESET_SESSION, reset_session)                                 \
_(APPLICATION_ATTACH_REPLY, application_attach_reply)           \
_(APPLICATION_DETACH_REPLY, application_detach_reply)           \
_(MAP_ANOTHER_SEGMENT, map_another_segment)                     \
_(UNMAP_SEGMENT, unmap_segment)

void
vppcom_api_hookup (void)
{
#define _(N, n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_sock_msg;
#undef _
}

/*
 * VPP-API message functions
 */
void
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

void
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
    (app_is_proxy ? APP_OPTIONS_FLAGS_IS_PROXY : 0) |
    APP_OPTIONS_FLAGS_USE_MQ_FOR_CTRL_MSGS;
  bmp->options[APP_OPTIONS_PROXY_TRANSPORT] =
    (u64) ((vcm->cfg.app_proxy_transport_tcp ? 1 << TRANSPORT_PROTO_TCP : 0) |
	   (vcm->cfg.app_proxy_transport_udp ? 1 << TRANSPORT_PROTO_UDP : 0));
  bmp->options[APP_OPTIONS_SEGMENT_SIZE] = vcm->cfg.segment_size;
  bmp->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = vcm->cfg.add_segment_size;
  bmp->options[APP_OPTIONS_RX_FIFO_SIZE] = vcm->cfg.rx_fifo_size;
  bmp->options[APP_OPTIONS_TX_FIFO_SIZE] = vcm->cfg.tx_fifo_size;
  bmp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] =
    vcm->cfg.preallocated_fifo_pairs;
  bmp->options[APP_OPTIONS_EVT_QUEUE_SIZE] = vcm->cfg.event_queue_size;
  if (nsid_len)
    {
      bmp->namespace_id_len = nsid_len;
      clib_memcpy (bmp->namespace_id, vcm->cfg.namespace_id, nsid_len);
      bmp->options[APP_OPTIONS_NAMESPACE_SECRET] = vcm->cfg.namespace_secret;
    }
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & bmp);
}

void
vppcom_app_send_detach (void)
{
  vl_api_application_detach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_DETACH);
  bmp->client_index = vcm->my_client_index;
  bmp->context = htonl (0xfeedface);
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & bmp);
}

void
vppcom_send_connect_sock (vcl_session_t * session, u32 session_index)
{
  vl_api_connect_sock_t *cmp;

  /* Assumes caller as acquired the spinlock: vcm->sessions_lockp */
  cmp = vl_msg_api_alloc (sizeof (*cmp));
  memset (cmp, 0, sizeof (*cmp));
  cmp->_vl_msg_id = ntohs (VL_API_CONNECT_SOCK);
  cmp->client_index = vcm->my_client_index;
  cmp->context = session_index;

  cmp->is_ip4 = session->transport.is_ip4;
  clib_memcpy (cmp->ip, &session->transport.rmt_ip, sizeof (cmp->ip));
  cmp->port = session->transport.rmt_port;
  cmp->proto = session->session_type;
  clib_memcpy (cmp->options, session->options, sizeof (cmp->options));
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & cmp);
}

void
vppcom_send_disconnect_session_reply (u64 vpp_handle, u32 session_index,
				      int rv)
{
  vl_api_disconnect_session_reply_t *rmp;

  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: sending disconnect msg",
	getpid (), vpp_handle, session_index);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION_REPLY);
  rmp->retval = htonl (rv);
  rmp->handle = vpp_handle;
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & rmp);
}

void
vppcom_send_disconnect_session (u64 vpp_handle, u32 session_index)
{
  vl_api_disconnect_session_t *dmp;

  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: sending disconnect msg",
	getpid (), vpp_handle, session_index);

  dmp = vl_msg_api_alloc (sizeof (*dmp));
  memset (dmp, 0, sizeof (*dmp));
  dmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION);
  dmp->client_index = vcm->my_client_index;
  dmp->handle = vpp_handle;
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & dmp);
}

/* VPP combines bind and listen as one operation. VCL manages the separation
 * of bind and listen locally via vppcom_session_bind() and
 * vppcom_session_listen() */
void
vppcom_send_bind_sock (vcl_session_t * session, u32 session_index)
{
  vl_api_bind_sock_t *bmp;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_BIND_SOCK);
  bmp->client_index = vcm->my_client_index;
  bmp->context = session_index;
  bmp->is_ip4 = session->transport.is_ip4;
  clib_memcpy (bmp->ip, &session->transport.lcl_ip, sizeof (bmp->ip));
  bmp->port = session->transport.lcl_port;
  bmp->proto = session->session_type;
  clib_memcpy (bmp->options, session->options, sizeof (bmp->options));
  vl_msg_api_send_shmem (vcm->vl_input_queue, (u8 *) & bmp);
}

void
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

void
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

u32
vcl_max_nsid_len (void)
{
  vl_api_application_attach_t *mp;
  return (sizeof (mp->namespace_id) - 1);
}

void
vppcom_init_error_string_table (void)
{
  vcm->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n, v, s) hash_set (vcm->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (vcm->error_string_by_error_number, 99, "Misc");
}

int
vppcom_connect_to_vpp (char *app_name)
{
  api_main_t *am = &api_main;
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;
  int rv = VPPCOM_OK;

  if (!vcl_cfg->vpp_api_filename)
    vcl_cfg->vpp_api_filename = format (0, "/vpe-api%c", 0);

  VDBG (0, "VCL<%d>: app (%s) connecting to VPP api (%s)...",
	getpid (), app_name, vcl_cfg->vpp_api_filename);

  if (vl_client_connect_to_vlib ((char *) vcl_cfg->vpp_api_filename, app_name,
				 vcm->cfg.vpp_api_q_length) < 0)
    {
      clib_warning ("VCL<%d>: app (%s) connect failed!", getpid (), app_name);
      rv = VPPCOM_ECONNREFUSED;
    }
  else
    {
      vcm->vl_input_queue = am->shmem_hdr->vl_input_queue;
      vcm->my_client_index = (u32) am->my_client_index;
      vcm->app_state = STATE_APP_CONN_VPP;

      VDBG (0, "VCL<%d>: app (%s) is connected to VPP!", getpid (), app_name);
    }

  vcl_evt (VCL_EVT_INIT, vcm);
  return rv;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
