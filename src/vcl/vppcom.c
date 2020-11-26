/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
#include <vcl/vppcom.h>
#include <vcl/vcl_debug.h>
#include <vcl/vcl_private.h>
#include <svm/fifo_segment.h>

__thread uword __vcl_worker_index = ~0;

static int
vcl_segment_is_not_mounted (vcl_worker_t * wrk, u64 segment_handle)
{
  u32 segment_index;

  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    return 0;

  segment_index = vcl_segment_table_lookup (segment_handle);
  if (segment_index != VCL_INVALID_SEGMENT_INDEX)
    return 0;

  return 1;
}

static inline int
vcl_mq_dequeue_batch (vcl_worker_t * wrk, svm_msg_q_t * mq, u32 n_max_msg)
{
  svm_msg_q_msg_t *msg;
  u32 n_msgs;
  int i;

  n_msgs = clib_min (svm_msg_q_size (mq), n_max_msg);
  for (i = 0; i < n_msgs; i++)
    {
      vec_add2 (wrk->mq_msg_vector, msg, 1);
      svm_msg_q_sub_w_lock (mq, msg);
    }
  return n_msgs;
}

const char *
vppcom_session_state_str (vcl_session_state_t state)
{
  char *st;

  switch (state)
    {
    case VCL_STATE_CLOSED:
      st = "STATE_CLOSED";
      break;
    case VCL_STATE_LISTEN:
      st = "STATE_LISTEN";
      break;
    case VCL_STATE_READY:
      st = "STATE_READY";
      break;
    case VCL_STATE_VPP_CLOSING:
      st = "STATE_VPP_CLOSING";
      break;
    case VCL_STATE_DISCONNECT:
      st = "STATE_DISCONNECT";
      break;
    case VCL_STATE_DETACHED:
      st = "STATE_DETACHED";
      break;
    case VCL_STATE_UPDATED:
      st = "STATE_UPDATED";
      break;
    case VCL_STATE_LISTEN_NO_MQ:
      st = "STATE_LISTEN_NO_MQ";
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

static void
vcl_send_session_listen (vcl_worker_t * wrk, vcl_session_t * s)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_listen_msg_t *mp;
  svm_msg_q_t *mq;

  mq = vcl_worker_ctrl_mq (wrk);
  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_LISTEN);
  mp = (session_listen_msg_t *) app_evt->evt->data;
  memset (mp, 0, sizeof (*mp));
  mp->client_index = wrk->api_client_handle;
  mp->context = s->session_index;
  mp->wrk_index = wrk->vpp_wrk_index;
  mp->is_ip4 = s->transport.is_ip4;
  clib_memcpy_fast (&mp->ip, &s->transport.lcl_ip, sizeof (mp->ip));
  mp->port = s->transport.lcl_port;
  mp->proto = s->session_type;
  if (s->flags & VCL_SESSION_F_CONNECTED)
    mp->flags = TRANSPORT_CFG_F_CONNECTED;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

static void
vcl_send_session_connect (vcl_worker_t * wrk, vcl_session_t * s)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_connect_msg_t *mp;
  svm_msg_q_t *mq;

  mq = vcl_worker_ctrl_mq (wrk);
  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_CONNECT);
  mp = (session_connect_msg_t *) app_evt->evt->data;
  memset (mp, 0, sizeof (*mp));
  mp->client_index = wrk->api_client_handle;
  mp->context = s->session_index;
  mp->wrk_index = wrk->vpp_wrk_index;
  mp->is_ip4 = s->transport.is_ip4;
  mp->parent_handle = s->parent_handle;
  clib_memcpy_fast (&mp->ip, &s->transport.rmt_ip, sizeof (mp->ip));
  clib_memcpy_fast (&mp->lcl_ip, &s->transport.lcl_ip, sizeof (mp->lcl_ip));
  mp->port = s->transport.rmt_port;
  mp->lcl_port = s->transport.lcl_port;
  mp->proto = s->session_type;
  if (s->flags & VCL_SESSION_F_CONNECTED)
    mp->flags |= TRANSPORT_CFG_F_CONNECTED;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

void
vcl_send_session_unlisten (vcl_worker_t * wrk, vcl_session_t * s)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_unlisten_msg_t *mp;
  svm_msg_q_t *mq;

  mq = vcl_worker_ctrl_mq (wrk);
  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_UNLISTEN);
  mp = (session_unlisten_msg_t *) app_evt->evt->data;
  memset (mp, 0, sizeof (*mp));
  mp->client_index = wrk->api_client_handle;
  mp->wrk_index = wrk->vpp_wrk_index;
  mp->handle = s->vpp_handle;
  mp->context = wrk->wrk_index;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

static void
vcl_send_session_disconnect (vcl_worker_t * wrk, vcl_session_t * s)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_disconnect_msg_t *mp;
  svm_msg_q_t *mq;

  /* Send to thread that owns the session */
  mq = s->vpp_evt_q;
  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_DISCONNECT);
  mp = (session_disconnect_msg_t *) app_evt->evt->data;
  memset (mp, 0, sizeof (*mp));
  mp->client_index = wrk->api_client_handle;
  mp->handle = s->vpp_handle;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

static void
vcl_send_app_detach (vcl_worker_t * wrk)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_app_detach_msg_t *mp;
  svm_msg_q_t *mq;

  mq = vcl_worker_ctrl_mq (wrk);
  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_APP_DETACH);
  mp = (session_app_detach_msg_t *) app_evt->evt->data;
  memset (mp, 0, sizeof (*mp));
  mp->client_index = wrk->api_client_handle;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

static void
vcl_send_session_accepted_reply (svm_msg_q_t * mq, u32 context,
				 session_handle_t handle, int retval)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_accepted_reply_msg_t *rmp;
  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_ACCEPTED_REPLY);
  rmp = (session_accepted_reply_msg_t *) app_evt->evt->data;
  rmp->handle = handle;
  rmp->context = context;
  rmp->retval = retval;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

static void
vcl_send_session_disconnected_reply (vcl_worker_t * wrk, vcl_session_t * s,
				     int retval)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_disconnected_reply_msg_t *rmp;
  app_alloc_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_DISCONNECTED_REPLY);
  rmp = (session_disconnected_reply_msg_t *) app_evt->evt->data;
  rmp->handle = s->vpp_handle;
  rmp->context = wrk->api_client_handle;
  rmp->retval = retval;
  app_send_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt);
}

static void
vcl_send_session_reset_reply (vcl_worker_t * wrk, vcl_session_t * s,
			      int retval)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_reset_reply_msg_t *rmp;
  app_alloc_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_RESET_REPLY);
  rmp = (session_reset_reply_msg_t *) app_evt->evt->data;
  rmp->handle = s->vpp_handle;
  rmp->context = wrk->api_client_handle;
  rmp->retval = retval;
  app_send_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt);
}

void
vcl_send_session_worker_update (vcl_worker_t * wrk, vcl_session_t * s,
				u32 wrk_index)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_worker_update_msg_t *mp;

  app_alloc_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_WORKER_UPDATE);
  mp = (session_worker_update_msg_t *) app_evt->evt->data;
  mp->client_index = wrk->api_client_handle;
  mp->handle = s->vpp_handle;
  mp->req_wrk_index = wrk->vpp_wrk_index;
  mp->wrk_index = wrk_index;
  app_send_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt);
}

int
vcl_send_worker_rpc (u32 dst_wrk_index, void *data, u32 data_len)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_app_wrk_rpc_msg_t *mp;
  vcl_worker_t *dst_wrk, *wrk;
  svm_msg_q_t *mq;
  int ret = -1;

  if (data_len > sizeof (mp->data))
    goto done;

  clib_spinlock_lock (&vcm->workers_lock);

  dst_wrk = vcl_worker_get_if_valid (dst_wrk_index);
  if (!dst_wrk)
    goto done;

  wrk = vcl_worker_get_current ();
  mq = vcl_worker_ctrl_mq (wrk);
  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_APP_WRK_RPC);
  mp = (session_app_wrk_rpc_msg_t *) app_evt->evt->data;
  mp->client_index = wrk->api_client_handle;
  mp->wrk_index = dst_wrk->vpp_wrk_index;
  clib_memcpy (mp->data, data, data_len);
  app_send_ctrl_evt_to_vpp (mq, app_evt);
  ret = 0;

done:
  clib_spinlock_unlock (&vcm->workers_lock);
  return ret;
}

static u32
vcl_session_accepted_handler (vcl_worker_t * wrk, session_accepted_msg_t * mp,
			      u32 ls_index)
{
  vcl_session_t *session, *listen_session;
  svm_fifo_t *rx_fifo, *tx_fifo;
  svm_msg_q_t *evt_q;

  session = vcl_session_alloc (wrk);

  listen_session = vcl_session_get (wrk, ls_index);
  if (listen_session->vpp_handle != mp->listener_handle)
    {
      VDBG (0, "ERROR: listener handle %lu does not match session %u",
	    mp->listener_handle, ls_index);
      goto error;
    }

  if (vcl_segment_is_not_mounted (wrk, mp->segment_handle))
    {
      VDBG (0, "ERROR: segment for session %u is not mounted!",
	    session->session_index);
      goto error;
    }

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					 svm_msg_q_t *);
  rx_fifo->client_session_index = session->session_index;
  tx_fifo->client_session_index = session->session_index;
  rx_fifo->client_thread_index = vcl_get_worker_index ();
  tx_fifo->client_thread_index = vcl_get_worker_index ();

  session->vpp_handle = mp->handle;
  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;

  session->session_state = VCL_STATE_READY;
  session->transport.rmt_port = mp->rmt.port;
  session->transport.is_ip4 = mp->rmt.is_ip4;
  clib_memcpy_fast (&session->transport.rmt_ip, &mp->rmt.ip,
		    sizeof (ip46_address_t));

  vcl_session_table_add_vpp_handle (wrk, mp->handle, session->session_index);
  session->transport.lcl_port = listen_session->transport.lcl_port;
  session->transport.lcl_ip = listen_session->transport.lcl_ip;
  session->session_type = listen_session->session_type;
  session->is_dgram = vcl_proto_is_dgram (session->session_type);
  session->listener_index = listen_session->session_index;
  listen_session->n_accepted_sessions++;

  VDBG (1, "session %u [0x%llx]: client accept request from %s address %U"
	" port %d queue %p!", session->session_index, mp->handle,
	mp->rmt.is_ip4 ? "IPv4" : "IPv6", format_ip46_address, &mp->rmt.ip,
	mp->rmt.is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
	clib_net_to_host_u16 (mp->rmt.port), session->vpp_evt_q);
  vcl_evt (VCL_EVT_ACCEPT, session, listen_session, session_index);

  vcl_send_session_accepted_reply (session->vpp_evt_q, mp->context,
				   session->vpp_handle, 0);

  return session->session_index;

error:
  evt_q = uword_to_pointer (mp->vpp_event_queue_address, svm_msg_q_t *);
  vcl_send_session_accepted_reply (evt_q, mp->context, mp->handle,
				   VNET_API_ERROR_INVALID_ARGUMENT);
  vcl_session_free (wrk, session);
  return VCL_INVALID_SESSION_INDEX;
}

static u32
vcl_session_connected_handler (vcl_worker_t * wrk,
			       session_connected_msg_t * mp)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  vcl_session_t *session = 0;
  u32 session_index;

  session_index = mp->context;
  session = vcl_session_get (wrk, session_index);
  if (!session)
    {
      VDBG (0, "ERROR: vpp handle 0x%llx has no session index (%u)!",
	    mp->handle, session_index);
      return VCL_INVALID_SESSION_INDEX;
    }
  if (mp->retval)
    {
      VDBG (0, "ERROR: session index %u: connect failed! %U",
	    session_index, format_session_error, mp->retval);
      session->session_state = VCL_STATE_DETACHED;
      session->vpp_handle = mp->handle;
      return session_index;
    }

  session->vpp_handle = mp->handle;
  session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					 svm_msg_q_t *);
  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  if (vcl_segment_is_not_mounted (wrk, mp->segment_handle))
    {
      VDBG (0, "segment for session %u is not mounted!",
	    session->session_index);
      session->session_state = VCL_STATE_DETACHED;
      vcl_send_session_disconnect (wrk, session);
      return session_index;
    }

  rx_fifo->client_session_index = session_index;
  tx_fifo->client_session_index = session_index;
  rx_fifo->client_thread_index = vcl_get_worker_index ();
  tx_fifo->client_thread_index = vcl_get_worker_index ();

  if (mp->ct_rx_fifo)
    {
      session->ct_rx_fifo = uword_to_pointer (mp->ct_rx_fifo, svm_fifo_t *);
      session->ct_tx_fifo = uword_to_pointer (mp->ct_tx_fifo, svm_fifo_t *);
      if (vcl_segment_is_not_mounted (wrk, mp->ct_segment_handle))
	{
	  VDBG (0, "ct segment for session %u is not mounted!",
		session->session_index);
	  session->session_state = VCL_STATE_DETACHED;
	  vcl_send_session_disconnect (wrk, session);
	  return session_index;
	}
    }

  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;
  session->transport.is_ip4 = mp->lcl.is_ip4;
  clib_memcpy_fast (&session->transport.lcl_ip, &mp->lcl.ip,
		    sizeof (session->transport.lcl_ip));
  session->transport.lcl_port = mp->lcl.port;

  /* Application closed session before connect reply */
  if (vcl_session_has_attr (session, VCL_SESS_ATTR_NONBLOCK)
      && session->session_state == VCL_STATE_CLOSED)
    vcl_send_session_disconnect (wrk, session);
  else
    session->session_state = VCL_STATE_READY;

  /* Add it to lookup table */
  vcl_session_table_add_vpp_handle (wrk, mp->handle, session_index);

  VDBG (1, "session %u [0x%llx] connected! rx_fifo %p, refcnt %d, tx_fifo %p,"
	" refcnt %d", session_index, mp->handle, session->rx_fifo,
	session->rx_fifo->refcnt, session->tx_fifo, session->tx_fifo->refcnt);

  return session_index;
}

static int
vcl_flag_accepted_session (vcl_session_t * session, u64 handle, u32 flags)
{
  vcl_session_msg_t *accepted_msg;
  int i;

  for (i = 0; i < vec_len (session->accept_evts_fifo); i++)
    {
      accepted_msg = &session->accept_evts_fifo[i];
      if (accepted_msg->accepted_msg.handle == handle)
	{
	  accepted_msg->flags |= flags;
	  return 1;
	}
    }
  return 0;
}

static u32
vcl_session_reset_handler (vcl_worker_t * wrk,
			   session_reset_msg_t * reset_msg)
{
  vcl_session_t *session;
  u32 sid;

  sid = vcl_session_index_from_vpp_handle (wrk, reset_msg->handle);
  session = vcl_session_get (wrk, sid);
  if (!session)
    {
      VDBG (0, "request to reset unknown handle 0x%llx", reset_msg->handle);
      return VCL_INVALID_SESSION_INDEX;
    }

  /* Caught a reset before actually accepting the session */
  if (session->session_state == VCL_STATE_LISTEN)
    {

      if (!vcl_flag_accepted_session (session, reset_msg->handle,
				      VCL_ACCEPTED_F_RESET))
	VDBG (0, "session was not accepted!");
      return VCL_INVALID_SESSION_INDEX;
    }

  if (session->session_state != VCL_STATE_CLOSED)
    session->session_state = VCL_STATE_DISCONNECT;
  VDBG (0, "reset session %u [0x%llx]", sid, reset_msg->handle);
  return sid;
}

static u32
vcl_session_bound_handler (vcl_worker_t * wrk, session_bound_msg_t * mp)
{
  vcl_session_t *session;
  u32 sid = mp->context;

  session = vcl_session_get (wrk, sid);
  if (mp->retval)
    {
      VERR ("session %u [0x%llx]: bind failed: %U", sid, mp->handle,
	    format_session_error, mp->retval);
      if (session)
	{
	  session->session_state = VCL_STATE_DETACHED;
	  session->vpp_handle = mp->handle;
	  return sid;
	}
      else
	{
	  VDBG (0, "ERROR: session %u [0x%llx]: Invalid session index!",
		sid, mp->handle);
	  return VCL_INVALID_SESSION_INDEX;
	}
    }

  session->vpp_handle = mp->handle;
  session->transport.is_ip4 = mp->lcl_is_ip4;
  clib_memcpy_fast (&session->transport.lcl_ip, mp->lcl_ip,
		    sizeof (ip46_address_t));
  session->transport.lcl_port = mp->lcl_port;
  vcl_session_table_add_listener (wrk, mp->handle, sid);
  session->session_state = VCL_STATE_LISTEN;
  session->vpp_evt_q = uword_to_pointer (mp->vpp_evt_q, svm_msg_q_t *);

  if (vcl_session_is_cl (session))
    {
      svm_fifo_t *rx_fifo, *tx_fifo;
      session->vpp_evt_q = uword_to_pointer (mp->vpp_evt_q, svm_msg_q_t *);
      rx_fifo = uword_to_pointer (mp->rx_fifo, svm_fifo_t *);
      rx_fifo->client_session_index = sid;
      tx_fifo = uword_to_pointer (mp->tx_fifo, svm_fifo_t *);
      tx_fifo->client_session_index = sid;
      session->rx_fifo = rx_fifo;
      session->tx_fifo = tx_fifo;
    }

  VDBG (0, "session %u [0x%llx]: listen succeeded!", sid, mp->handle);
  return sid;
}

static void
vcl_session_unlisten_reply_handler (vcl_worker_t * wrk, void *data)
{
  session_unlisten_reply_msg_t *mp = (session_unlisten_reply_msg_t *) data;
  vcl_session_t *s;

  s = vcl_session_get_w_vpp_handle (wrk, mp->handle);
  if (!s)
    {
      VDBG (0, "Unlisten reply with wrong handle %llx", mp->handle);
      return;
    }
  if (s->session_state != VCL_STATE_DISCONNECT)
    {
      /* Connected udp listener */
      if (s->session_type == VPPCOM_PROTO_UDP
	  && s->session_state == VCL_STATE_CLOSED)
	return;

      VDBG (0, "Unlisten session in wrong state %llx", mp->handle);
      return;
    }

  if (mp->retval)
    VDBG (0, "ERROR: session %u [0xllx]: unlisten failed: %U",
	  s->session_index, mp->handle, format_session_error, mp->retval);

  if (mp->context != wrk->wrk_index)
    VDBG (0, "wrong context");

  vcl_session_table_del_vpp_handle (wrk, mp->handle);
  vcl_session_free (wrk, s);
}

static void
vcl_session_migrated_handler (vcl_worker_t * wrk, void *data)
{
  session_migrated_msg_t *mp = (session_migrated_msg_t *) data;
  vcl_session_t *s;

  s = vcl_session_get_w_vpp_handle (wrk, mp->handle);
  if (!s)
    {
      VDBG (0, "Migrated notification with wrong handle %llx", mp->handle);
      return;
    }

  s->vpp_handle = mp->new_handle;
  s->vpp_evt_q = uword_to_pointer (mp->vpp_evt_q, svm_msg_q_t *);

  vcl_session_table_del_vpp_handle (wrk, mp->handle);
  vcl_session_table_add_vpp_handle (wrk, mp->new_handle, s->session_index);

  /* Generate new tx event if we have outstanding data */
  if (svm_fifo_has_event (s->tx_fifo))
    app_send_io_evt_to_vpp (s->vpp_evt_q, s->tx_fifo->master_session_index,
			    SESSION_IO_EVT_TX, SVM_Q_WAIT);

  VDBG (0, "Migrated 0x%lx to thread %u 0x%lx", mp->handle,
	mp->vpp_thread_index, mp->new_handle);
}

static vcl_session_t *
vcl_session_accepted (vcl_worker_t * wrk, session_accepted_msg_t * msg)
{
  vcl_session_msg_t *vcl_msg;
  vcl_session_t *session;

  session = vcl_session_get_w_vpp_handle (wrk, msg->handle);
  if (PREDICT_FALSE (session != 0))
    VWRN ("session overlap handle %lu state %u!", msg->handle,
	  session->session_state);

  session = vcl_session_table_lookup_listener (wrk, msg->listener_handle);
  if (!session)
    {
      VERR ("couldn't find listen session: listener handle %llx",
	    msg->listener_handle);
      return 0;
    }

  clib_fifo_add2 (session->accept_evts_fifo, vcl_msg);
  vcl_msg->flags = 0;
  vcl_msg->accepted_msg = *msg;
  /* Session handle points to listener until fully accepted by app */
  vcl_session_table_add_vpp_handle (wrk, msg->handle, session->session_index);

  return session;
}

static vcl_session_t *
vcl_session_disconnected_handler (vcl_worker_t * wrk,
				  session_disconnected_msg_t * msg)
{
  vcl_session_t *session;

  session = vcl_session_get_w_vpp_handle (wrk, msg->handle);
  if (!session)
    {
      VDBG (0, "request to disconnect unknown handle 0x%llx", msg->handle);
      return 0;
    }

  /* Late disconnect notification on a session that has been closed */
  if (session->session_state == VCL_STATE_CLOSED)
    return 0;

  /* Caught a disconnect before actually accepting the session */
  if (session->session_state == VCL_STATE_LISTEN)
    {
      if (!vcl_flag_accepted_session (session, msg->handle,
				      VCL_ACCEPTED_F_CLOSED))
	VDBG (0, "session was not accepted!");
      return 0;
    }

  /* If not already reset change state */
  if (session->session_state != VCL_STATE_DISCONNECT)
    session->session_state = VCL_STATE_VPP_CLOSING;

  return session;
}

static int
vppcom_session_disconnect (u32 session_handle)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session, *listen_session;
  vcl_session_state_t state;
  u64 vpp_handle;

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;

  vpp_handle = session->vpp_handle;
  state = session->session_state;

  VDBG (1, "session %u [0x%llx] state 0x%x (%s)", session->session_index,
	vpp_handle, state, vppcom_session_state_str (state));

  if (PREDICT_FALSE (state == VCL_STATE_LISTEN))
    {
      VDBG (0, "ERROR: Cannot disconnect a listen socket!");
      return VPPCOM_EBADFD;
    }

  if (state == VCL_STATE_VPP_CLOSING)
    {
      vcl_send_session_disconnected_reply (wrk, session, 0);
      VDBG (1, "session %u [0x%llx]: sending disconnect REPLY...",
	    session->session_index, vpp_handle);
    }
  else
    {
      /* Session doesn't have an event queue yet. Probably a non-blocking
       * connect. Wait for the reply */
      if (PREDICT_FALSE (!session->vpp_evt_q))
	return VPPCOM_OK;

      VDBG (1, "session %u [0x%llx]: sending disconnect...",
	    session->session_index, vpp_handle);
      vcl_send_session_disconnect (wrk, session);
    }

  if (session->listener_index != VCL_INVALID_SESSION_INDEX)
    {
      listen_session = vcl_session_get (wrk, session->listener_index);
      listen_session->n_accepted_sessions--;
    }

  return VPPCOM_OK;
}

static void
vcl_session_cleanup_handler (vcl_worker_t * wrk, void *data)
{
  session_cleanup_msg_t *msg;
  vcl_session_t *session;

  msg = (session_cleanup_msg_t *) data;
  session = vcl_session_get_w_vpp_handle (wrk, msg->handle);
  if (!session)
    {
      VDBG (0, "disconnect confirmed for unknown handle 0x%llx", msg->handle);
      return;
    }

  if (msg->type == SESSION_CLEANUP_TRANSPORT)
    {
      /* Transport was cleaned up before we confirmed close. Probably the
       * app is still waiting for some data that cannot be delivered.
       * Confirm close to make sure everything is cleaned up.
       * Move to undetermined state to ensure that the session is not
       * removed before both vpp and the app cleanup.
       * - If the app closes first, the session is moved to CLOSED state
       *   and the session cleanup notification from vpp removes the
       *   session.
       * - If vpp cleans up the session first, the session is moved to
       *   DETACHED state lower and subsequently the close from the app
       *   frees the session
       */
      if (session->session_state == VCL_STATE_VPP_CLOSING)
	{
	  vppcom_session_disconnect (vcl_session_handle (session));
	  session->session_state = VCL_STATE_UPDATED;
	}
      else if (session->session_state == VCL_STATE_DISCONNECT)
	{
	  vcl_send_session_reset_reply (wrk, session, 0);
	  session->session_state = VCL_STATE_UPDATED;
	}
      return;
    }

  vcl_session_table_del_vpp_handle (wrk, msg->handle);
  /* Should not happen. App did not close the connection so don't free it. */
  if (session->session_state != VCL_STATE_CLOSED)
    {
      VDBG (0, "app did not close session %d", session->session_index);
      session->session_state = VCL_STATE_DETACHED;
      session->vpp_handle = VCL_INVALID_SESSION_HANDLE;
      return;
    }
  vcl_session_free (wrk, session);
}

static void
vcl_session_req_worker_update_handler (vcl_worker_t * wrk, void *data)
{
  session_req_worker_update_msg_t *msg;
  vcl_session_t *s;

  msg = (session_req_worker_update_msg_t *) data;
  s = vcl_session_get_w_vpp_handle (wrk, msg->session_handle);
  if (!s)
    return;

  vec_add1 (wrk->pending_session_wrk_updates, s->session_index);
}

static void
vcl_session_worker_update_reply_handler (vcl_worker_t * wrk, void *data)
{
  session_worker_update_reply_msg_t *msg;
  vcl_session_t *s;

  msg = (session_worker_update_reply_msg_t *) data;
  s = vcl_session_get_w_vpp_handle (wrk, msg->handle);
  if (!s)
    {
      VDBG (0, "unknown handle 0x%llx", msg->handle);
      return;
    }
  if (vcl_segment_is_not_mounted (wrk, msg->segment_handle))
    {
      clib_warning ("segment for session %u is not mounted!",
		    s->session_index);
      return;
    }

  if (s->rx_fifo)
    {
      s->rx_fifo = uword_to_pointer (msg->rx_fifo, svm_fifo_t *);
      s->tx_fifo = uword_to_pointer (msg->tx_fifo, svm_fifo_t *);
      s->rx_fifo->client_session_index = s->session_index;
      s->tx_fifo->client_session_index = s->session_index;
      s->rx_fifo->client_thread_index = wrk->wrk_index;
      s->tx_fifo->client_thread_index = wrk->wrk_index;
    }
  s->session_state = VCL_STATE_UPDATED;

  VDBG (0, "session %u[0x%llx] moved to worker %u", s->session_index,
	s->vpp_handle, wrk->wrk_index);
}

static int
vcl_api_recv_fd (vcl_worker_t * wrk, int *fds, int n_fds)
{

  if (vcm->cfg.vpp_app_socket_api)
    return vcl_sapi_recv_fds (wrk, fds, n_fds);

  return vcl_bapi_recv_fds (wrk, fds, n_fds);
}

static void
vcl_session_app_add_segment_handler (vcl_worker_t * wrk, void *data)
{
  ssvm_segment_type_t seg_type = SSVM_SEGMENT_SHM;
  session_app_add_segment_msg_t *msg;
  u64 segment_handle;
  int fd = -1;

  msg = (session_app_add_segment_msg_t *) data;

  if (msg->fd_flags)
    {
      vcl_api_recv_fd (wrk, &fd, 1);
      seg_type = SSVM_SEGMENT_MEMFD;
    }

  segment_handle = msg->segment_handle;
  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    {
      clib_warning ("invalid segment handle");
      return;
    }

  if (vcl_segment_attach (segment_handle, (char *) msg->segment_name,
			  seg_type, fd))
    {
      VDBG (0, "vcl_segment_attach ('%s') failed", msg->segment_name);
      return;
    }

  VDBG (1, "mapped new segment '%s' size %d", msg->segment_name,
	msg->segment_size);
}

static void
vcl_session_app_del_segment_handler (vcl_worker_t * wrk, void *data)
{
  session_app_del_segment_msg_t *msg = (session_app_del_segment_msg_t *) data;
  vcl_segment_detach (msg->segment_handle);
  VDBG (1, "Unmapped segment: %d", msg->segment_handle);
}

static void
vcl_worker_rpc_handler (vcl_worker_t * wrk, void *data)
{
  if (!vcm->wrk_rpc_fn)
    return;

  (vcm->wrk_rpc_fn) (((session_app_wrk_rpc_msg_t *) data)->data);
}

static int
vcl_handle_mq_event (vcl_worker_t * wrk, session_event_t * e)
{
  session_disconnected_msg_t *disconnected_msg;
  session_connected_msg_t *connected_msg;
  session_reset_msg_t *reset_msg;
  session_event_t *ecpy;
  vcl_session_t *s;
  u32 sid;

  switch (e->event_type)
    {
    case SESSION_IO_EVT_RX:
    case SESSION_IO_EVT_TX:
      s = vcl_session_get (wrk, e->session_index);
      if (!s || !vcl_session_is_open (s))
	break;
      vec_add1 (wrk->unhandled_evts_vector, *e);
      break;
    case SESSION_CTRL_EVT_BOUND:
      /* We can only wait for only one listen so not postponed */
      vcl_session_bound_handler (wrk, (session_bound_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_ACCEPTED:
      s = vcl_session_accepted (wrk, (session_accepted_msg_t *) e->data);
      if (vcl_session_has_attr (s, VCL_SESS_ATTR_NONBLOCK))
	{
	  vec_add2 (wrk->unhandled_evts_vector, ecpy, 1);
	  *ecpy = *e;
	  ecpy->postponed = 1;
	  ecpy->session_index = s->session_index;
	}
      break;
    case SESSION_CTRL_EVT_CONNECTED:
      connected_msg = (session_connected_msg_t *) e->data;
      sid = vcl_session_connected_handler (wrk, connected_msg);
      if (!(s = vcl_session_get (wrk, sid)))
	break;
      if (vcl_session_has_attr (s, VCL_SESS_ATTR_NONBLOCK))
	{
	  vec_add2 (wrk->unhandled_evts_vector, ecpy, 1);
	  *ecpy = *e;
	  ecpy->postponed = 1;
	  ecpy->session_index = s->session_index;
	}
      break;
    case SESSION_CTRL_EVT_DISCONNECTED:
      disconnected_msg = (session_disconnected_msg_t *) e->data;
      if (!(s = vcl_session_get_w_vpp_handle (wrk, disconnected_msg->handle)))
	break;
      if (vcl_session_has_attr (s, VCL_SESS_ATTR_NONBLOCK))
	{
	  vec_add1 (wrk->unhandled_evts_vector, *e);
	  break;
	}
      if (!(s = vcl_session_disconnected_handler (wrk, disconnected_msg)))
	break;
      VDBG (0, "disconnected session %u [0x%llx]", s->session_index,
	    s->vpp_handle);
      break;
    case SESSION_CTRL_EVT_RESET:
      reset_msg = (session_reset_msg_t *) e->data;
      if (!(s = vcl_session_get_w_vpp_handle (wrk, reset_msg->handle)))
	break;
      if (vcl_session_has_attr (s, VCL_SESS_ATTR_NONBLOCK))
	{
	  vec_add1 (wrk->unhandled_evts_vector, *e);
	  break;
	}
      vcl_session_reset_handler (wrk, (session_reset_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_UNLISTEN_REPLY:
      vcl_session_unlisten_reply_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_MIGRATED:
      vcl_session_migrated_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_CLEANUP:
      vcl_session_cleanup_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_REQ_WORKER_UPDATE:
      vcl_session_req_worker_update_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_WORKER_UPDATE_REPLY:
      vcl_session_worker_update_reply_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_APP_ADD_SEGMENT:
      vcl_session_app_add_segment_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_APP_DEL_SEGMENT:
      vcl_session_app_del_segment_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_APP_WRK_RPC:
      vcl_worker_rpc_handler (wrk, e->data);
      break;
    default:
      clib_warning ("unhandled %u", e->event_type);
    }
  return VPPCOM_OK;
}

static int
vppcom_wait_for_session_state_change (u32 session_index,
				      vcl_session_state_t state,
				      f64 wait_for_time)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  f64 timeout = clib_time_now (&wrk->clib_time) + wait_for_time;
  vcl_session_t *volatile session;
  svm_msg_q_msg_t msg;
  session_event_t *e;

  do
    {
      session = vcl_session_get (wrk, session_index);
      if (PREDICT_FALSE (!session))
	{
	  return VPPCOM_EBADFD;
	}
      if (session->session_state == state)
	{
	  return VPPCOM_OK;
	}
      if (session->session_state == VCL_STATE_DETACHED)
	{
	  return VPPCOM_ECONNREFUSED;
	}

      if (svm_msg_q_sub (wrk->app_event_queue, &msg, SVM_Q_NOWAIT, 0))
	{
	  usleep (100);
	  continue;
	}
      e = svm_msg_q_msg_data (wrk->app_event_queue, &msg);
      vcl_handle_mq_event (wrk, e);
      svm_msg_q_free_msg (wrk->app_event_queue, &msg);
    }
  while (clib_time_now (&wrk->clib_time) < timeout);

  VDBG (0, "timeout waiting for state 0x%x (%s)", state,
	vppcom_session_state_str (state));
  vcl_evt (VCL_EVT_SESSION_TIMEOUT, session, session_state);

  return VPPCOM_ETIMEDOUT;
}

static void
vcl_handle_pending_wrk_updates (vcl_worker_t * wrk)
{
  vcl_session_state_t state;
  vcl_session_t *s;
  u32 *sip;

  if (PREDICT_TRUE (vec_len (wrk->pending_session_wrk_updates) == 0))
    return;

  vec_foreach (sip, wrk->pending_session_wrk_updates)
  {
    s = vcl_session_get (wrk, *sip);
    vcl_send_session_worker_update (wrk, s, wrk->wrk_index);
    state = s->session_state;
    vppcom_wait_for_session_state_change (s->session_index, VCL_STATE_UPDATED,
					  5);
    s->session_state = state;
  }
  vec_reset_length (wrk->pending_session_wrk_updates);
}

void
vcl_flush_mq_events (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  svm_msg_q_msg_t *msg;
  session_event_t *e;
  svm_msg_q_t *mq;
  int i;

  mq = wrk->app_event_queue;
  svm_msg_q_lock (mq);
  vcl_mq_dequeue_batch (wrk, mq, ~0);
  svm_msg_q_unlock (mq);

  for (i = 0; i < vec_len (wrk->mq_msg_vector); i++)
    {
      msg = vec_elt_at_index (wrk->mq_msg_vector, i);
      e = svm_msg_q_msg_data (mq, msg);
      vcl_handle_mq_event (wrk, e);
      svm_msg_q_free_msg (mq, msg);
    }
  vec_reset_length (wrk->mq_msg_vector);
  vcl_handle_pending_wrk_updates (wrk);
}

static int
vppcom_session_unbind (u32 session_handle)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  session_accepted_msg_t *accepted_msg;
  vcl_session_t *session = 0;
  vcl_session_msg_t *evt;

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;

  /* Flush pending accept events, if any */
  while (clib_fifo_elts (session->accept_evts_fifo))
    {
      clib_fifo_sub2 (session->accept_evts_fifo, evt);
      accepted_msg = &evt->accepted_msg;
      vcl_session_table_del_vpp_handle (wrk, accepted_msg->handle);
      vcl_send_session_accepted_reply (session->vpp_evt_q,
				       accepted_msg->context,
				       session->vpp_handle, -1);
    }
  clib_fifo_free (session->accept_evts_fifo);

  vcl_send_session_unlisten (wrk, session);

  VDBG (1, "session %u [0x%llx]: sending unbind!", session->session_index,
	session->vpp_handle);
  vcl_evt (VCL_EVT_UNBIND, session);

  session->vpp_handle = ~0;
  session->session_state = VCL_STATE_DISCONNECT;

  return VPPCOM_OK;
}

/**
 * Handle app exit
 *
 * Notify vpp of the disconnect and mark the worker as free. If we're the
 * last worker, do a full cleanup otherwise, since we're probably a forked
 * child, avoid syscalls as much as possible. We might've lost privileges.
 */
void
vppcom_app_exit (void)
{
  if (!pool_elts (vcm->workers))
    return;
  vcl_worker_cleanup (vcl_worker_get_current (), 1 /* notify vpp */ );
  vcl_set_worker_index (~0);
  vcl_elog_stop (vcm);
}

static int
vcl_api_attach (void)
{
  if (vcm->cfg.vpp_app_socket_api)
    return vcl_sapi_attach ();

  return vcl_bapi_attach ();
}

static void
vcl_api_detach (vcl_worker_t * wrk)
{
  vcl_send_app_detach (wrk);

  if (vcm->cfg.vpp_app_socket_api)
    return vcl_sapi_detach (wrk);

  return vcl_bapi_disconnect_from_vpp ();
}

/*
 * VPPCOM Public API functions
 */
int
vppcom_app_create (const char *app_name)
{
  vppcom_cfg_t *vcl_cfg = &vcm->cfg;
  int rv;

  if (vcm->is_init)
    {
      VDBG (1, "already initialized");
      return VPPCOM_EEXIST;
    }

  vcm->is_init = 1;
  vppcom_cfg (&vcm->cfg);
  vcl_cfg = &vcm->cfg;

  vcm->main_cpu = pthread_self ();
  vcm->main_pid = getpid ();
  vcm->app_name = format (0, "%s", app_name);
  fifo_segment_main_init (&vcm->segment_main, vcl_cfg->segment_baseva,
			  20 /* timeout in secs */ );
  pool_alloc (vcm->workers, vcl_cfg->max_workers);
  clib_spinlock_init (&vcm->workers_lock);
  clib_rwlock_init (&vcm->segment_table_lock);
  atexit (vppcom_app_exit);
  vcl_elog_init (vcm);

  /* Allocate default worker */
  vcl_worker_alloc_and_init ();

  if ((rv = vcl_api_attach ()))
    return rv;

  VDBG (0, "app_name '%s', my_client_index %d (0x%x)", app_name,
	vcm->workers[0].api_client_handle, vcm->workers[0].api_client_handle);

  return VPPCOM_OK;
}

void
vppcom_app_destroy (void)
{
  vcl_worker_t *wrk, *current_wrk;
  void *heap;

  if (!pool_elts (vcm->workers))
    return;

  vcl_evt (VCL_EVT_DETACH, vcm);

  current_wrk = vcl_worker_get_current ();

  /* *INDENT-OFF* */
  pool_foreach (wrk, vcm->workers, ({
    if (current_wrk != wrk)
      vcl_worker_cleanup (wrk, 0 /* notify vpp */ );
  }));
  /* *INDENT-ON* */

  vcl_api_detach (current_wrk);
  vcl_worker_cleanup (current_wrk, 0 /* notify vpp */ );

  vcl_elog_stop (vcm);

  /*
   * Free the heap and fix vcm
   */
  heap = clib_mem_get_heap ();
  munmap (clib_mem_get_heap_base (heap), clib_mem_get_heap_size (heap));

  vcm = &_vppcom_main;
  vcm->is_init = 0;
}

int
vppcom_session_create (u8 proto, u8 is_nonblocking)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session;

  session = vcl_session_alloc (wrk);

  session->session_type = proto;
  session->session_state = VCL_STATE_CLOSED;
  session->vpp_handle = ~0;
  session->is_dgram = vcl_proto_is_dgram (proto);

  if (is_nonblocking)
    vcl_session_set_attr (session, VCL_SESS_ATTR_NONBLOCK);

  vcl_evt (VCL_EVT_CREATE, session, session_type, session->session_state,
	   is_nonblocking, session_index);

  VDBG (0, "created session %u", session->session_index);

  return vcl_session_handle (session);
}

int
vcl_session_cleanup (vcl_worker_t * wrk, vcl_session_t * s,
		     vcl_session_handle_t sh, u8 do_disconnect)
{
  int rv = VPPCOM_OK;

  VDBG (1, "session %u [0x%llx] closing", s->session_index, s->vpp_handle);

  if (s->flags & VCL_SESSION_F_IS_VEP)
    {
      u32 next_sh = s->vep.next_sh;
      while (next_sh != ~0)
	{
	  rv = vppcom_epoll_ctl (sh, EPOLL_CTL_DEL, next_sh, 0);
	  if (PREDICT_FALSE (rv < 0))
	    VDBG (0, "vpp handle 0x%llx, sh %u: EPOLL_CTL_DEL vep_idx %u"
		  " failed! rv %d (%s)", s->vpp_handle, next_sh,
		  s->vep.vep_sh, rv, vppcom_retval_str (rv));
	  next_sh = s->vep.next_sh;
	}
      goto free_session;
    }

  if (s->flags & VCL_SESSION_F_IS_VEP_SESSION)
    {
      rv = vppcom_epoll_ctl (s->vep.vep_sh, EPOLL_CTL_DEL, sh, 0);
      if (rv < 0)
	VDBG (0, "session %u [0x%llx]: EPOLL_CTL_DEL vep_idx %u "
	      "failed! rv %d (%s)", s->session_index, s->vpp_handle,
	      s->vep.vep_sh, rv, vppcom_retval_str (rv));
    }

  if (!do_disconnect)
    {
      VDBG (1, "session %u [0x%llx] disconnect skipped",
	    s->session_index, s->vpp_handle);
      goto cleanup;
    }

  if (s->session_state == VCL_STATE_LISTEN)
    {
      rv = vppcom_session_unbind (sh);
      if (PREDICT_FALSE (rv < 0))
	VDBG (0, "session %u [0x%llx]: listener unbind failed! "
	      "rv %d (%s)", s->session_index, s->vpp_handle, rv,
	      vppcom_retval_str (rv));
      return rv;
    }
  else if (vcl_session_is_ready (s)
	   || (vcl_session_is_connectable_listener (wrk, s)))
    {
      rv = vppcom_session_disconnect (sh);
      if (PREDICT_FALSE (rv < 0))
	VDBG (0, "ERROR: session %u [0x%llx]: disconnect failed!"
	      " rv %d (%s)", s->session_index, s->vpp_handle,
	      rv, vppcom_retval_str (rv));
    }
  else if (s->session_state == VCL_STATE_DISCONNECT)
    {
      vcl_send_session_reset_reply (wrk, s, 0);
    }
  else if (s->session_state == VCL_STATE_DETACHED)
    {
      /* Should not happen. VPP cleaned up before app confirmed close */
      VDBG (0, "vpp freed session %d before close", s->session_index);
      goto free_session;
    }

  s->session_state = VCL_STATE_CLOSED;

  /* Session is removed only after vpp confirms the disconnect */
  return rv;

cleanup:
  vcl_session_table_del_vpp_handle (wrk, s->vpp_handle);
free_session:
  vcl_session_free (wrk, s);
  vcl_evt (VCL_EVT_CLOSE, s, rv);

  return rv;
}

int
vppcom_session_close (uint32_t session_handle)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session;

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;
  return vcl_session_cleanup (wrk, session, session_handle,
			      1 /* do_disconnect */ );
}

int
vppcom_session_bind (uint32_t session_handle, vppcom_endpt_t * ep)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session = 0;

  if (!ep || !ep->ip)
    return VPPCOM_EINVAL;

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;

  if (session->flags & VCL_SESSION_F_IS_VEP)
    {
      VDBG (0, "ERROR: cannot bind to epoll session %u!",
	    session->session_index);
      return VPPCOM_EBADFD;
    }

  session->transport.is_ip4 = ep->is_ip4;
  if (ep->is_ip4)
    clib_memcpy_fast (&session->transport.lcl_ip.ip4, ep->ip,
		      sizeof (ip4_address_t));
  else
    clib_memcpy_fast (&session->transport.lcl_ip.ip6, ep->ip,
		      sizeof (ip6_address_t));
  session->transport.lcl_port = ep->port;

  VDBG (0, "session %u handle %u: binding to local %s address %U port %u, "
	"proto %s", session->session_index, session_handle,
	session->transport.is_ip4 ? "IPv4" : "IPv6",
	format_ip46_address, &session->transport.lcl_ip,
	session->transport.is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
	clib_net_to_host_u16 (session->transport.lcl_port),
	vppcom_proto_str (session->session_type));
  vcl_evt (VCL_EVT_BIND, session);

  if (session->session_type == VPPCOM_PROTO_UDP)
    vppcom_session_listen (session_handle, 10);

  return VPPCOM_OK;
}

int
vppcom_session_listen (uint32_t listen_sh, uint32_t q_len)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *listen_session = 0;
  u64 listen_vpp_handle;
  int rv;

  listen_session = vcl_session_get_w_handle (wrk, listen_sh);
  if (!listen_session || (listen_session->flags & VCL_SESSION_F_IS_VEP))
    return VPPCOM_EBADFD;

  if (q_len == 0 || q_len == ~0)
    q_len = vcm->cfg.listen_queue_size;

  listen_vpp_handle = listen_session->vpp_handle;
  if (listen_session->session_state == VCL_STATE_LISTEN)
    {
      VDBG (0, "session %u [0x%llx]: already in listen state!",
	    listen_sh, listen_vpp_handle);
      return VPPCOM_OK;
    }

  VDBG (0, "session %u: sending vpp listen request...", listen_sh);

  /*
   * Send listen request to vpp and wait for reply
   */
  vcl_send_session_listen (wrk, listen_session);
  rv = vppcom_wait_for_session_state_change (listen_session->session_index,
					     VCL_STATE_LISTEN,
					     vcm->cfg.session_timeout);

  if (PREDICT_FALSE (rv))
    {
      listen_session = vcl_session_get_w_handle (wrk, listen_sh);
      VDBG (0, "session %u [0x%llx]: listen failed! returning %d (%s)",
	    listen_sh, listen_session->vpp_handle, rv,
	    vppcom_retval_str (rv));
      return rv;
    }

  return VPPCOM_OK;
}

static int
validate_args_session_accept_ (vcl_worker_t * wrk, vcl_session_t * ls)
{
  if (ls->flags & VCL_SESSION_F_IS_VEP)
    {
      VDBG (0, "ERROR: cannot accept on epoll session %u!",
	    ls->session_index);
      return VPPCOM_EBADFD;
    }

  if ((ls->session_state != VCL_STATE_LISTEN)
      && (!vcl_session_is_connectable_listener (wrk, ls)))
    {
      VDBG (0, "ERROR: session [0x%llx]: not in listen state! state 0x%x"
	    " (%s)", ls->vpp_handle, ls->session_state,
	    vppcom_session_state_str (ls->session_state));
      return VPPCOM_EBADFD;
    }
  return VPPCOM_OK;
}

int
vppcom_unformat_proto (uint8_t * proto, char *proto_str)
{
  if (!strcmp (proto_str, "TCP"))
    *proto = VPPCOM_PROTO_TCP;
  else if (!strcmp (proto_str, "tcp"))
    *proto = VPPCOM_PROTO_TCP;
  else if (!strcmp (proto_str, "UDP"))
    *proto = VPPCOM_PROTO_UDP;
  else if (!strcmp (proto_str, "udp"))
    *proto = VPPCOM_PROTO_UDP;
  else if (!strcmp (proto_str, "TLS"))
    *proto = VPPCOM_PROTO_TLS;
  else if (!strcmp (proto_str, "tls"))
    *proto = VPPCOM_PROTO_TLS;
  else if (!strcmp (proto_str, "QUIC"))
    *proto = VPPCOM_PROTO_QUIC;
  else if (!strcmp (proto_str, "quic"))
    *proto = VPPCOM_PROTO_QUIC;
  else
    return 1;
  return 0;
}

int
vppcom_session_accept (uint32_t listen_session_handle, vppcom_endpt_t * ep,
		       uint32_t flags)
{
  u32 client_session_index = ~0, listen_session_index, accept_flags = 0;
  vcl_worker_t *wrk = vcl_worker_get_current ();
  session_accepted_msg_t accepted_msg;
  vcl_session_t *listen_session = 0;
  vcl_session_t *client_session = 0;
  vcl_session_msg_t *evt;
  svm_msg_q_msg_t msg;
  session_event_t *e;
  u8 is_nonblocking;
  int rv;

  listen_session = vcl_session_get_w_handle (wrk, listen_session_handle);
  if (!listen_session)
    return VPPCOM_EBADFD;

  listen_session_index = listen_session->session_index;
  if ((rv = validate_args_session_accept_ (wrk, listen_session)))
    return rv;

  if (clib_fifo_elts (listen_session->accept_evts_fifo))
    {
      clib_fifo_sub2 (listen_session->accept_evts_fifo, evt);
      accept_flags = evt->flags;
      accepted_msg = evt->accepted_msg;
      goto handle;
    }

  is_nonblocking = vcl_session_has_attr (listen_session,
					 VCL_SESS_ATTR_NONBLOCK);
  while (1)
    {
      if (svm_msg_q_is_empty (wrk->app_event_queue) && is_nonblocking)
	return VPPCOM_EAGAIN;

      if (svm_msg_q_sub (wrk->app_event_queue, &msg, SVM_Q_WAIT, 0))
	return VPPCOM_EAGAIN;

      e = svm_msg_q_msg_data (wrk->app_event_queue, &msg);
      if (e->event_type != SESSION_CTRL_EVT_ACCEPTED)
	{
	  vcl_handle_mq_event (wrk, e);
	  svm_msg_q_free_msg (wrk->app_event_queue, &msg);
	  continue;
	}
      clib_memcpy_fast (&accepted_msg, e->data, sizeof (accepted_msg));
      svm_msg_q_free_msg (wrk->app_event_queue, &msg);
      break;
    }

handle:

  client_session_index = vcl_session_accepted_handler (wrk, &accepted_msg,
						       listen_session_index);
  if (client_session_index == VCL_INVALID_SESSION_INDEX)
    return VPPCOM_ECONNABORTED;

  listen_session = vcl_session_get (wrk, listen_session_index);
  client_session = vcl_session_get (wrk, client_session_index);

  if (flags & O_NONBLOCK)
    vcl_session_set_attr (client_session, VCL_SESS_ATTR_NONBLOCK);

  VDBG (1, "listener %u [0x%llx]: Got a connect request! session %u [0x%llx],"
	" flags %d, is_nonblocking %u", listen_session->session_index,
	listen_session->vpp_handle, client_session_index,
	client_session->vpp_handle, flags,
	vcl_session_has_attr (client_session, VCL_SESS_ATTR_NONBLOCK));

  if (ep)
    {
      ep->is_ip4 = client_session->transport.is_ip4;
      ep->port = client_session->transport.rmt_port;
      if (client_session->transport.is_ip4)
	clib_memcpy_fast (ep->ip, &client_session->transport.rmt_ip.ip4,
			  sizeof (ip4_address_t));
      else
	clib_memcpy_fast (ep->ip, &client_session->transport.rmt_ip.ip6,
			  sizeof (ip6_address_t));
    }

  VDBG (0, "listener %u [0x%llx] accepted %u [0x%llx] peer: %U:%u "
	"local: %U:%u", listen_session_handle, listen_session->vpp_handle,
	client_session_index, client_session->vpp_handle,
	format_ip46_address, &client_session->transport.rmt_ip,
	client_session->transport.is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
	clib_net_to_host_u16 (client_session->transport.rmt_port),
	format_ip46_address, &client_session->transport.lcl_ip,
	client_session->transport.is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
	clib_net_to_host_u16 (client_session->transport.lcl_port));
  vcl_evt (VCL_EVT_ACCEPT, client_session, listen_session,
	   client_session_index);

  /*
   * Session might have been closed already
   */
  if (accept_flags)
    {
      if (accept_flags & VCL_ACCEPTED_F_CLOSED)
	client_session->session_state = VCL_STATE_VPP_CLOSING;
      else if (accept_flags & VCL_ACCEPTED_F_RESET)
	client_session->session_state = VCL_STATE_DISCONNECT;
    }
  return vcl_session_handle (client_session);
}

int
vppcom_session_connect (uint32_t session_handle, vppcom_endpt_t * server_ep)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session = 0;
  u32 session_index;
  int rv;

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;
  session_index = session->session_index;

  if (PREDICT_FALSE (session->flags & VCL_SESSION_F_IS_VEP))
    {
      VDBG (0, "ERROR: cannot connect epoll session %u!",
	    session->session_index);
      return VPPCOM_EBADFD;
    }

  if (PREDICT_FALSE (vcl_session_is_ready (session)))
    {
      VDBG (0, "session handle %u [0x%llx]: session already "
	    "connected to %s %U port %d proto %s, state 0x%x (%s)",
	    session_handle, session->vpp_handle,
	    session->transport.is_ip4 ? "IPv4" : "IPv6", format_ip46_address,
	    &session->transport.rmt_ip, session->transport.is_ip4 ?
	    IP46_TYPE_IP4 : IP46_TYPE_IP6,
	    clib_net_to_host_u16 (session->transport.rmt_port),
	    vppcom_proto_str (session->session_type), session->session_state,
	    vppcom_session_state_str (session->session_state));
      return VPPCOM_OK;
    }

  /* Attempt to connect a connectionless listener */
  if (PREDICT_FALSE (session->session_state == VCL_STATE_LISTEN))
    {
      if (session->session_type != VPPCOM_PROTO_UDP)
	return VPPCOM_EINVAL;
      vcl_send_session_unlisten (wrk, session);
      session->session_state = VCL_STATE_CLOSED;
    }

  session->transport.is_ip4 = server_ep->is_ip4;
  vcl_ip_copy_from_ep (&session->transport.rmt_ip, server_ep);
  session->transport.rmt_port = server_ep->port;
  session->parent_handle = VCL_INVALID_SESSION_HANDLE;
  session->flags |= VCL_SESSION_F_CONNECTED;

  VDBG (0, "session handle %u (%s): connecting to peer %s %U "
	"port %d proto %s", session_handle,
	vppcom_session_state_str (session->session_state),
	session->transport.is_ip4 ? "IPv4" : "IPv6",
	format_ip46_address,
	&session->transport.rmt_ip, session->transport.is_ip4 ?
	IP46_TYPE_IP4 : IP46_TYPE_IP6,
	clib_net_to_host_u16 (session->transport.rmt_port),
	vppcom_proto_str (session->session_type));

  vcl_send_session_connect (wrk, session);

  if (vcl_session_has_attr (session, VCL_SESS_ATTR_NONBLOCK))
    {
      /* State set to STATE_UPDATED to ensure the session is not assumed
       * to be ready and to also allow the app to close it prior to vpp's
       * connected reply. */
      session->session_state = VCL_STATE_UPDATED;
      return VPPCOM_EINPROGRESS;
    }

  /*
   * Wait for reply from vpp if blocking
   */
  rv = vppcom_wait_for_session_state_change (session_index, VCL_STATE_READY,
					     vcm->cfg.session_timeout);

  session = vcl_session_get (wrk, session_index);
  VDBG (0, "session %u [0x%llx]: connect %s!", session->session_index,
	session->vpp_handle, rv ? "failed" : "succeeded");

  return rv;
}

int
vppcom_session_stream_connect (uint32_t session_handle,
			       uint32_t parent_session_handle)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session, *parent_session;
  u32 session_index, parent_session_index;
  int rv;

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;
  parent_session = vcl_session_get_w_handle (wrk, parent_session_handle);
  if (!parent_session)
    return VPPCOM_EBADFD;

  session_index = session->session_index;
  parent_session_index = parent_session->session_index;
  if (PREDICT_FALSE (session->flags & VCL_SESSION_F_IS_VEP))
    {
      VDBG (0, "ERROR: cannot connect epoll session %u!",
	    session->session_index);
      return VPPCOM_EBADFD;
    }

  if (PREDICT_FALSE (vcl_session_is_ready (session)))
    {
      VDBG (0, "session handle %u [0x%llx]: session already "
	    "connected to session %u [0x%llx] proto %s, state 0x%x (%s)",
	    session_handle, session->vpp_handle,
	    parent_session_handle, parent_session->vpp_handle,
	    vppcom_proto_str (session->session_type), session->session_state,
	    vppcom_session_state_str (session->session_state));
      return VPPCOM_OK;
    }

  /* Connect to quic session specifics */
  session->transport.is_ip4 = parent_session->transport.is_ip4;
  session->transport.rmt_ip.ip4.as_u32 = (uint32_t) 1;
  session->transport.rmt_port = 0;
  session->parent_handle = parent_session->vpp_handle;

  VDBG (0, "session handle %u: connecting to session %u [0x%llx]",
	session_handle, parent_session_handle, parent_session->vpp_handle);

  /*
   * Send connect request and wait for reply from vpp
   */
  vcl_send_session_connect (wrk, session);
  rv = vppcom_wait_for_session_state_change (session_index, VCL_STATE_READY,
					     vcm->cfg.session_timeout);

  session->listener_index = parent_session_index;
  parent_session = vcl_session_get_w_handle (wrk, parent_session_handle);
  if (parent_session)
    parent_session->n_accepted_sessions++;

  session = vcl_session_get (wrk, session_index);
  VDBG (0, "session %u [0x%llx]: connect %s!", session->session_index,
	session->vpp_handle, rv ? "failed" : "succeeded");

  return rv;
}

static u8
vcl_is_rx_evt_for_session (session_event_t * e, u32 sid, u8 is_ct)
{
  return (e->event_type == SESSION_IO_EVT_RX && e->session_index == sid);
}

static inline int
vppcom_session_read_internal (uint32_t session_handle, void *buf, int n,
			      u8 peek)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  int rv, n_read = 0, is_nonblocking;
  vcl_session_t *s = 0;
  svm_fifo_t *rx_fifo;
  svm_msg_q_msg_t msg;
  session_event_t *e;
  svm_msg_q_t *mq;
  u8 is_ct;

  if (PREDICT_FALSE (!buf))
    return VPPCOM_EINVAL;

  s = vcl_session_get_w_handle (wrk, session_handle);
  if (PREDICT_FALSE (!s || (s->flags & VCL_SESSION_F_IS_VEP)))
    return VPPCOM_EBADFD;

  if (PREDICT_FALSE (!vcl_session_is_open (s)))
    {
      VDBG (0, "session %u[0x%llx] is not open! state 0x%x (%s)",
	    s->session_index, s->vpp_handle, s->session_state,
	    vppcom_session_state_str (s->session_state));
      return vcl_session_closed_error (s);
    }

  is_nonblocking = vcl_session_has_attr (s, VCL_SESS_ATTR_NONBLOCK);
  is_ct = vcl_session_is_ct (s);
  mq = wrk->app_event_queue;
  rx_fifo = is_ct ? s->ct_rx_fifo : s->rx_fifo;
  s->flags &= ~VCL_SESSION_F_HAS_RX_EVT;

  if (svm_fifo_is_empty_cons (rx_fifo))
    {
      if (is_nonblocking)
	{
	  if (vcl_session_is_closing (s))
	    return vcl_session_closing_error (s);
	  if (is_ct)
	    svm_fifo_unset_event (s->rx_fifo);
	  svm_fifo_unset_event (rx_fifo);
	  return VPPCOM_EWOULDBLOCK;
	}
      while (svm_fifo_is_empty_cons (rx_fifo))
	{
	  if (vcl_session_is_closing (s))
	    return vcl_session_closing_error (s);

	  if (is_ct)
	    svm_fifo_unset_event (s->rx_fifo);
	  svm_fifo_unset_event (rx_fifo);
	  svm_msg_q_lock (mq);
	  if (svm_msg_q_is_empty (mq))
	    svm_msg_q_wait (mq);

	  svm_msg_q_sub_w_lock (mq, &msg);
	  e = svm_msg_q_msg_data (mq, &msg);
	  svm_msg_q_unlock (mq);
	  if (!vcl_is_rx_evt_for_session (e, s->session_index, is_ct))
	    vcl_handle_mq_event (wrk, e);
	  svm_msg_q_free_msg (mq, &msg);
	}
    }

read_again:

  if (s->is_dgram)
    rv = app_recv_dgram_raw (rx_fifo, buf, n, &s->transport, 0, peek);
  else
    rv = app_recv_stream_raw (rx_fifo, buf, n, 0, peek);

  ASSERT (rv >= 0);
  n_read += rv;

  if (svm_fifo_is_empty_cons (rx_fifo))
    {
      if (is_ct)
	svm_fifo_unset_event (s->rx_fifo);
      svm_fifo_unset_event (rx_fifo);
      if (!svm_fifo_is_empty_cons (rx_fifo)
	  && svm_fifo_set_event (rx_fifo) && is_nonblocking)
	{
	  vec_add2 (wrk->unhandled_evts_vector, e, 1);
	  e->event_type = SESSION_IO_EVT_RX;
	  e->session_index = s->session_index;
	}
    }
  else if (PREDICT_FALSE (rv < n && !s->is_dgram))
    {
      /* More data enqueued while reading. Try to drain it
       * or fill the buffer. Avoid doing that for dgrams */
      buf += rv;
      n -= rv;
      goto read_again;
    }

  if (PREDICT_FALSE (svm_fifo_needs_deq_ntf (rx_fifo, n_read)))
    {
      svm_fifo_clear_deq_ntf (rx_fifo);
      app_send_io_evt_to_vpp (s->vpp_evt_q, s->rx_fifo->master_session_index,
			      SESSION_IO_EVT_RX, SVM_Q_WAIT);
    }

  VDBG (2, "session %u[0x%llx]: read %d bytes from (%p)", s->session_index,
	s->vpp_handle, n_read, rx_fifo);

  return n_read;
}

int
vppcom_session_read (uint32_t session_handle, void *buf, size_t n)
{
  return (vppcom_session_read_internal (session_handle, buf, n, 0));
}

static int
vppcom_session_peek (uint32_t session_handle, void *buf, int n)
{
  return (vppcom_session_read_internal (session_handle, buf, n, 1));
}

int
vppcom_session_read_segments (uint32_t session_handle,
			      vppcom_data_segment_t * ds, uint32_t n_segments,
			      uint32_t max_bytes)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  int n_read = 0, is_nonblocking;
  vcl_session_t *s = 0;
  svm_fifo_t *rx_fifo;
  svm_msg_q_msg_t msg;
  session_event_t *e;
  svm_msg_q_t *mq;
  u8 is_ct;

  s = vcl_session_get_w_handle (wrk, session_handle);
  if (PREDICT_FALSE (!s || (s->flags & VCL_SESSION_F_IS_VEP)))
    return VPPCOM_EBADFD;

  if (PREDICT_FALSE (!vcl_session_is_open (s)))
    return vcl_session_closed_error (s);

  is_nonblocking = vcl_session_has_attr (s, VCL_SESS_ATTR_NONBLOCK);
  is_ct = vcl_session_is_ct (s);
  mq = wrk->app_event_queue;
  rx_fifo = is_ct ? s->ct_rx_fifo : s->rx_fifo;
  s->flags &= ~VCL_SESSION_F_HAS_RX_EVT;

  if (svm_fifo_is_empty_cons (rx_fifo))
    {
      if (is_nonblocking)
	{
	  if (is_ct)
	    svm_fifo_unset_event (s->rx_fifo);
	  svm_fifo_unset_event (rx_fifo);
	  return VPPCOM_EWOULDBLOCK;
	}
      while (svm_fifo_is_empty_cons (rx_fifo))
	{
	  if (vcl_session_is_closing (s))
	    return vcl_session_closing_error (s);

	  if (is_ct)
	    svm_fifo_unset_event (s->rx_fifo);
	  svm_fifo_unset_event (rx_fifo);
	  svm_msg_q_lock (mq);
	  if (svm_msg_q_is_empty (mq))
	    svm_msg_q_wait (mq);

	  svm_msg_q_sub_w_lock (mq, &msg);
	  e = svm_msg_q_msg_data (mq, &msg);
	  svm_msg_q_unlock (mq);
	  if (!vcl_is_rx_evt_for_session (e, s->session_index, is_ct))
	    vcl_handle_mq_event (wrk, e);
	  svm_msg_q_free_msg (mq, &msg);
	}
    }

  n_read = svm_fifo_segments (rx_fifo, s->rx_bytes_pending,
			      (svm_fifo_seg_t *) ds, n_segments, max_bytes);
  if (n_read < 0)
    return VPPCOM_EAGAIN;

  if (svm_fifo_max_dequeue_cons (rx_fifo) == n_read)
    {
      if (is_ct)
	svm_fifo_unset_event (s->rx_fifo);
      svm_fifo_unset_event (rx_fifo);
      if (svm_fifo_max_dequeue_cons (rx_fifo) != n_read
	  && svm_fifo_set_event (rx_fifo)
	  && vcl_session_has_attr (s, VCL_SESS_ATTR_NONBLOCK))
	{
	  session_event_t *e;
	  vec_add2 (wrk->unhandled_evts_vector, e, 1);
	  e->event_type = SESSION_IO_EVT_RX;
	  e->session_index = s->session_index;
	}
    }

  s->rx_bytes_pending += n_read;
  return n_read;
}

void
vppcom_session_free_segments (uint32_t session_handle, uint32_t n_bytes)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *s;
  u8 is_ct;

  s = vcl_session_get_w_handle (wrk, session_handle);
  if (PREDICT_FALSE (!s || (s->flags & VCL_SESSION_F_IS_VEP)))
    return;

  is_ct = vcl_session_is_ct (s);
  svm_fifo_dequeue_drop (is_ct ? s->ct_rx_fifo : s->rx_fifo, n_bytes);

  ASSERT (s->rx_bytes_pending < n_bytes);
  s->rx_bytes_pending -= n_bytes;
}

static u8
vcl_is_tx_evt_for_session (session_event_t * e, u32 sid, u8 is_ct)
{
  return (e->event_type == SESSION_IO_EVT_TX && e->session_index == sid);
}

always_inline u8
vcl_fifo_is_writeable (svm_fifo_t * f, u32 len, u8 is_dgram)
{
  u32 max_enq = svm_fifo_max_enqueue_prod (f);
  if (is_dgram)
    return max_enq >= (sizeof (session_dgram_hdr_t) + len);
  else
    return max_enq > 0;
}

always_inline int
vppcom_session_write_inline (vcl_worker_t * wrk, vcl_session_t * s, void *buf,
			     size_t n, u8 is_flush, u8 is_dgram)
{
  int n_write, is_nonblocking;
  session_evt_type_t et;
  svm_msg_q_msg_t msg;
  svm_fifo_t *tx_fifo;
  session_event_t *e;
  svm_msg_q_t *mq;
  u8 is_ct;

  if (PREDICT_FALSE (!buf || n == 0))
    return VPPCOM_EINVAL;

  if (PREDICT_FALSE (s->flags & VCL_SESSION_F_IS_VEP))
    {
      VDBG (0, "ERROR: session %u [0x%llx]: cannot write to an epoll"
	    " session!", s->session_index, s->vpp_handle);
      return VPPCOM_EBADFD;
    }

  if (PREDICT_FALSE (!vcl_session_is_open (s)))
    {
      VDBG (1, "session %u [0x%llx]: is not open! state 0x%x (%s)",
	    s->session_index, s->vpp_handle, s->session_state,
	    vppcom_session_state_str (s->session_state));
      return vcl_session_closed_error (s);;
    }

  is_ct = vcl_session_is_ct (s);
  tx_fifo = is_ct ? s->ct_tx_fifo : s->tx_fifo;
  is_nonblocking = vcl_session_has_attr (s, VCL_SESS_ATTR_NONBLOCK);

  mq = wrk->app_event_queue;
  if (!vcl_fifo_is_writeable (tx_fifo, n, is_dgram))
    {
      if (is_nonblocking)
	{
	  return VPPCOM_EWOULDBLOCK;
	}
      while (!vcl_fifo_is_writeable (tx_fifo, n, is_dgram))
	{
	  svm_fifo_add_want_deq_ntf (tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
	  if (vcl_session_is_closing (s))
	    return vcl_session_closing_error (s);
	  svm_msg_q_lock (mq);
	  if (svm_msg_q_is_empty (mq))
	    svm_msg_q_wait (mq);

	  svm_msg_q_sub_w_lock (mq, &msg);
	  e = svm_msg_q_msg_data (mq, &msg);
	  svm_msg_q_unlock (mq);

	  if (!vcl_is_tx_evt_for_session (e, s->session_index, is_ct))
	    vcl_handle_mq_event (wrk, e);
	  svm_msg_q_free_msg (mq, &msg);
	}
    }

  et = SESSION_IO_EVT_TX;
  if (is_flush && !is_ct)
    et = SESSION_IO_EVT_TX_FLUSH;

  if (is_dgram)
    n_write = app_send_dgram_raw (tx_fifo, &s->transport,
				  s->vpp_evt_q, buf, n, et,
				  0 /* do_evt */ , SVM_Q_WAIT);
  else
    n_write = app_send_stream_raw (tx_fifo, s->vpp_evt_q, buf, n, et,
				   0 /* do_evt */ , SVM_Q_WAIT);

  if (svm_fifo_set_event (s->tx_fifo))
    app_send_io_evt_to_vpp (s->vpp_evt_q, s->tx_fifo->master_session_index,
			    et, SVM_Q_WAIT);

  /* The underlying fifo segment can run out of memory */
  if (PREDICT_FALSE (n_write < 0))
    return VPPCOM_EAGAIN;

  VDBG (2, "session %u [0x%llx]: wrote %d bytes", s->session_index,
	s->vpp_handle, n_write);

  return n_write;
}

int
vppcom_session_write (uint32_t session_handle, void *buf, size_t n)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *s;

  s = vcl_session_get_w_handle (wrk, session_handle);
  if (PREDICT_FALSE (!s))
    return VPPCOM_EBADFD;

  return vppcom_session_write_inline (wrk, s, buf, n,
				      0 /* is_flush */ , s->is_dgram ? 1 : 0);
}

int
vppcom_session_write_msg (uint32_t session_handle, void *buf, size_t n)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *s;

  s = vcl_session_get_w_handle (wrk, session_handle);
  if (PREDICT_FALSE (!s))
    return VPPCOM_EBADFD;

  return vppcom_session_write_inline (wrk, s, buf, n,
				      1 /* is_flush */ , s->is_dgram ? 1 : 0);
}

#define vcl_fifo_rx_evt_valid_or_break(_s)				\
if (PREDICT_FALSE (!_s->rx_fifo))					\
  break;								\
if (PREDICT_FALSE (svm_fifo_is_empty (_s->rx_fifo)))			\
  {									\
    if (!vcl_session_is_ct (_s))					\
      {									\
	svm_fifo_unset_event (_s->rx_fifo);				\
	if (svm_fifo_is_empty (_s->rx_fifo))				\
	  break;							\
      }									\
    else if (svm_fifo_is_empty (_s->ct_rx_fifo))			\
      {									\
	svm_fifo_unset_event (_s->rx_fifo); /* rx evts on actual fifo*/	\
	if (svm_fifo_is_empty (_s->ct_rx_fifo))				\
	  break;							\
      }									\
  }									\

static void
vcl_select_handle_mq_event (vcl_worker_t * wrk, session_event_t * e,
			    unsigned long n_bits, unsigned long *read_map,
			    unsigned long *write_map,
			    unsigned long *except_map, u32 * bits_set)
{
  session_disconnected_msg_t *disconnected_msg;
  session_connected_msg_t *connected_msg;
  vcl_session_t *s;
  u32 sid;

  switch (e->event_type)
    {
    case SESSION_IO_EVT_RX:
      sid = e->session_index;
      s = vcl_session_get (wrk, sid);
      if (!s || !vcl_session_is_open (s))
	break;
      vcl_fifo_rx_evt_valid_or_break (s);
      if (sid < n_bits && read_map)
	{
	  clib_bitmap_set_no_check ((uword *) read_map, sid, 1);
	  *bits_set += 1;
	}
      break;
    case SESSION_IO_EVT_TX:
      sid = e->session_index;
      s = vcl_session_get (wrk, sid);
      if (!s || !vcl_session_is_open (s))
	break;
      if (sid < n_bits && write_map)
	{
	  clib_bitmap_set_no_check ((uword *) write_map, sid, 1);
	  *bits_set += 1;
	}
      break;
    case SESSION_CTRL_EVT_ACCEPTED:
      if (!e->postponed)
	s = vcl_session_accepted (wrk, (session_accepted_msg_t *) e->data);
      else
	s = vcl_session_get (wrk, e->session_index);
      if (!s)
	break;
      sid = s->session_index;
      if (sid < n_bits && read_map)
	{
	  clib_bitmap_set_no_check ((uword *) read_map, sid, 1);
	  *bits_set += 1;
	}
      break;
    case SESSION_CTRL_EVT_CONNECTED:
      if (!e->postponed)
	{
	  connected_msg = (session_connected_msg_t *) e->data;
	  sid = vcl_session_connected_handler (wrk, connected_msg);
	}
      else
	sid = e->session_index;
      if (sid == VCL_INVALID_SESSION_INDEX)
	break;
      if (sid < n_bits && write_map)
	{
	  clib_bitmap_set_no_check ((uword *) write_map, sid, 1);
	  *bits_set += 1;
	}
      break;
    case SESSION_CTRL_EVT_DISCONNECTED:
      disconnected_msg = (session_disconnected_msg_t *) e->data;
      s = vcl_session_disconnected_handler (wrk, disconnected_msg);
      if (!s)
	break;
      sid = s->session_index;
      if (sid < n_bits && except_map)
	{
	  clib_bitmap_set_no_check ((uword *) except_map, sid, 1);
	  *bits_set += 1;
	}
      break;
    case SESSION_CTRL_EVT_RESET:
      sid = vcl_session_reset_handler (wrk, (session_reset_msg_t *) e->data);
      if (sid < n_bits && except_map)
	{
	  clib_bitmap_set_no_check ((uword *) except_map, sid, 1);
	  *bits_set += 1;
	}
      break;
    case SESSION_CTRL_EVT_UNLISTEN_REPLY:
      vcl_session_unlisten_reply_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_MIGRATED:
      vcl_session_migrated_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_CLEANUP:
      vcl_session_cleanup_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_WORKER_UPDATE_REPLY:
      vcl_session_worker_update_reply_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_REQ_WORKER_UPDATE:
      vcl_session_req_worker_update_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_APP_ADD_SEGMENT:
      vcl_session_app_add_segment_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_APP_DEL_SEGMENT:
      vcl_session_app_del_segment_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_APP_WRK_RPC:
      vcl_worker_rpc_handler (wrk, e->data);
      break;
    default:
      clib_warning ("unhandled: %u", e->event_type);
      break;
    }
}

static int
vcl_select_handle_mq (vcl_worker_t * wrk, svm_msg_q_t * mq,
		      unsigned long n_bits, unsigned long *read_map,
		      unsigned long *write_map, unsigned long *except_map,
		      double time_to_wait, u32 * bits_set)
{
  svm_msg_q_msg_t *msg;
  session_event_t *e;
  u32 i;

  svm_msg_q_lock (mq);
  if (svm_msg_q_is_empty (mq))
    {
      if (*bits_set)
	{
	  svm_msg_q_unlock (mq);
	  return 0;
	}

      if (!time_to_wait)
	{
	  svm_msg_q_unlock (mq);
	  return 0;
	}
      else if (time_to_wait < 0)
	{
	  svm_msg_q_wait (mq);
	}
      else
	{
	  if (svm_msg_q_timedwait (mq, time_to_wait))
	    {
	      svm_msg_q_unlock (mq);
	      return 0;
	    }
	}
    }
  vcl_mq_dequeue_batch (wrk, mq, ~0);
  svm_msg_q_unlock (mq);

  for (i = 0; i < vec_len (wrk->mq_msg_vector); i++)
    {
      msg = vec_elt_at_index (wrk->mq_msg_vector, i);
      e = svm_msg_q_msg_data (mq, msg);
      vcl_select_handle_mq_event (wrk, e, n_bits, read_map, write_map,
				  except_map, bits_set);
      svm_msg_q_free_msg (mq, msg);
    }
  vec_reset_length (wrk->mq_msg_vector);
  vcl_handle_pending_wrk_updates (wrk);
  return *bits_set;
}

static int
vppcom_select_condvar (vcl_worker_t * wrk, int n_bits,
		       vcl_si_set * read_map, vcl_si_set * write_map,
		       vcl_si_set * except_map, double time_to_wait,
		       u32 * bits_set)
{
  double wait = 0, start = 0;

  if (!*bits_set)
    {
      wait = time_to_wait;
      start = clib_time_now (&wrk->clib_time);
    }

  do
    {
      vcl_select_handle_mq (wrk, wrk->app_event_queue, n_bits, read_map,
			    write_map, except_map, wait, bits_set);
      if (*bits_set)
	return *bits_set;
      if (wait == -1)
	continue;

      wait = wait - (clib_time_now (&wrk->clib_time) - start);
    }
  while (wait > 0);

  return 0;
}

static int
vppcom_select_eventfd (vcl_worker_t * wrk, int n_bits,
		       vcl_si_set * read_map, vcl_si_set * write_map,
		       vcl_si_set * except_map, double time_to_wait,
		       u32 * bits_set)
{
  vcl_mq_evt_conn_t *mqc;
  int __clib_unused n_read;
  int n_mq_evts, i;
  u64 buf;

  vec_validate (wrk->mq_events, pool_elts (wrk->mq_evt_conns));
  n_mq_evts = epoll_wait (wrk->mqs_epfd, wrk->mq_events,
			  vec_len (wrk->mq_events), time_to_wait);
  for (i = 0; i < n_mq_evts; i++)
    {
      mqc = vcl_mq_evt_conn_get (wrk, wrk->mq_events[i].data.u32);
      n_read = read (mqc->mq_fd, &buf, sizeof (buf));
      vcl_select_handle_mq (wrk, mqc->mq, n_bits, read_map, write_map,
			    except_map, 0, bits_set);
    }

  return (n_mq_evts > 0 ? (int) *bits_set : 0);
}

int
vppcom_select (int n_bits, vcl_si_set * read_map, vcl_si_set * write_map,
	       vcl_si_set * except_map, double time_to_wait)
{
  u32 sid, minbits = clib_max (n_bits, BITS (uword)), bits_set = 0;
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session = 0;
  int i;

  if (n_bits && read_map)
    {
      clib_bitmap_validate (wrk->rd_bitmap, minbits);
      clib_memcpy_fast (wrk->rd_bitmap, read_map,
			vec_len (wrk->rd_bitmap) * sizeof (vcl_si_set));
      memset (read_map, 0, vec_len (wrk->rd_bitmap) * sizeof (vcl_si_set));
    }
  if (n_bits && write_map)
    {
      clib_bitmap_validate (wrk->wr_bitmap, minbits);
      clib_memcpy_fast (wrk->wr_bitmap, write_map,
			vec_len (wrk->wr_bitmap) * sizeof (vcl_si_set));
      memset (write_map, 0, vec_len (wrk->wr_bitmap) * sizeof (vcl_si_set));
    }
  if (n_bits && except_map)
    {
      clib_bitmap_validate (wrk->ex_bitmap, minbits);
      clib_memcpy_fast (wrk->ex_bitmap, except_map,
			vec_len (wrk->ex_bitmap) * sizeof (vcl_si_set));
      memset (except_map, 0, vec_len (wrk->ex_bitmap) * sizeof (vcl_si_set));
    }

  if (!n_bits)
    return 0;

  if (!write_map)
    goto check_rd;

  /* *INDENT-OFF* */
  clib_bitmap_foreach (sid, wrk->wr_bitmap, ({
    if (!(session = vcl_session_get (wrk, sid)))
      {
	clib_bitmap_set_no_check ((uword*)write_map, sid, 1);
	bits_set++;
	continue;
      }

    if (vcl_session_write_ready (session))
      {
        clib_bitmap_set_no_check ((uword*)write_map, sid, 1);
        bits_set++;
      }
    else
      svm_fifo_add_want_deq_ntf (session->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
  }));

check_rd:
  if (!read_map)
    goto check_mq;

  clib_bitmap_foreach (sid, wrk->rd_bitmap, ({
    if (!(session = vcl_session_get (wrk, sid)))
      {
	clib_bitmap_set_no_check ((uword*)read_map, sid, 1);
	bits_set++;
	continue;
      }

    if (vcl_session_read_ready (session))
      {
        clib_bitmap_set_no_check ((uword*)read_map, sid, 1);
        bits_set++;
      }
  }));
  /* *INDENT-ON* */

check_mq:

  for (i = 0; i < vec_len (wrk->unhandled_evts_vector); i++)
    {
      vcl_select_handle_mq_event (wrk, &wrk->unhandled_evts_vector[i], n_bits,
				  read_map, write_map, except_map, &bits_set);
    }
  vec_reset_length (wrk->unhandled_evts_vector);

  if (vcm->cfg.use_mq_eventfd)
    vppcom_select_eventfd (wrk, n_bits, read_map, write_map, except_map,
			   time_to_wait, &bits_set);
  else
    vppcom_select_condvar (wrk, n_bits, read_map, write_map, except_map,
			   time_to_wait, &bits_set);

  return (bits_set);
}

static inline void
vep_verify_epoll_chain (vcl_worker_t * wrk, u32 vep_handle)
{
  vppcom_epoll_t *vep;
  u32 sh = vep_handle;
  vcl_session_t *s;

  if (VPPCOM_DEBUG <= 2)
    return;

  s = vcl_session_get_w_handle (wrk, vep_handle);
  if (PREDICT_FALSE (!s))
    {
      VDBG (0, "ERROR: Invalid vep_sh (%u)!", vep_handle);
      goto done;
    }
  if (PREDICT_FALSE (!(s->flags & VCL_SESSION_F_IS_VEP)))
    {
      VDBG (0, "ERROR: vep_sh (%u) is not a vep!", vep_handle);
      goto done;
    }
  vep = &s->vep;
  VDBG (0, "vep_sh (%u): Dumping epoll chain\n"
	"{\n"
	"   is_vep         = %u\n"
	"   is_vep_session = %u\n"
	"   next_sh        = 0x%x (%u)\n"
	"}\n", vep_handle, s->flags & VCL_SESSION_F_IS_VEP,
	s->flags & VCL_SESSION_F_IS_VEP_SESSION, vep->next_sh, vep->next_sh);

  for (sh = vep->next_sh; sh != ~0; sh = vep->next_sh)
    {
      s = vcl_session_get_w_handle (wrk, sh);
      if (PREDICT_FALSE (!s))
	{
	  VDBG (0, "ERROR: Invalid sh (%u)!", sh);
	  goto done;
	}
      if (PREDICT_FALSE (s->flags & VCL_SESSION_F_IS_VEP))
	{
	  VDBG (0, "ERROR: sh (%u) is a vep!", vep_handle);
	}
      else if (PREDICT_FALSE (!(s->flags & VCL_SESSION_F_IS_VEP_SESSION)))
	{
	  VDBG (0, "ERROR: sh (%u) is not a vep session handle!", sh);
	  goto done;
	}
      vep = &s->vep;
      if (PREDICT_FALSE (vep->vep_sh != vep_handle))
	VDBG (0, "ERROR: session (%u) vep_sh (%u) != vep_sh (%u)!",
	      sh, s->vep.vep_sh, vep_handle);
      if (s->flags & VCL_SESSION_F_IS_VEP_SESSION)
	{
	  VDBG (0, "vep_sh[%u]: sh 0x%x (%u)\n"
		"{\n"
		"   next_sh        = 0x%x (%u)\n"
		"   prev_sh        = 0x%x (%u)\n"
		"   vep_sh         = 0x%x (%u)\n"
		"   ev.events      = 0x%x\n"
		"   ev.data.u64    = 0x%llx\n"
		"   et_mask        = 0x%x\n"
		"}\n",
		vep_handle, sh, sh, vep->next_sh, vep->next_sh, vep->prev_sh,
		vep->prev_sh, vep->vep_sh, vep->vep_sh, vep->ev.events,
		vep->ev.data.u64, vep->et_mask);
	}
    }

done:
  VDBG (0, "vep_sh (%u): Dump complete!\n", vep_handle);
}

int
vppcom_epoll_create (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *vep_session;

  vep_session = vcl_session_alloc (wrk);

  vep_session->flags |= VCL_SESSION_F_IS_VEP;
  vep_session->vep.vep_sh = ~0;
  vep_session->vep.next_sh = ~0;
  vep_session->vep.prev_sh = ~0;
  vep_session->vpp_handle = ~0;

  vcl_evt (VCL_EVT_EPOLL_CREATE, vep_session, vep_session->session_index);
  VDBG (0, "Created vep_idx %u", vep_session->session_index);

  return vcl_session_handle (vep_session);
}

int
vppcom_epoll_ctl (uint32_t vep_handle, int op, uint32_t session_handle,
		  struct epoll_event *event)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *vep_session;
  int rv = VPPCOM_OK;
  vcl_session_t *s;
  svm_fifo_t *txf;

  if (vep_handle == session_handle)
    {
      VDBG (0, "vep_sh == session handle (%u)!", vep_handle);
      return VPPCOM_EINVAL;
    }

  vep_session = vcl_session_get_w_handle (wrk, vep_handle);
  if (PREDICT_FALSE (!vep_session))
    {
      VDBG (0, "Invalid vep_sh (%u)!", vep_handle);
      return VPPCOM_EBADFD;
    }
  if (PREDICT_FALSE (!(vep_session->flags & VCL_SESSION_F_IS_VEP)))
    {
      VDBG (0, "vep_sh (%u) is not a vep!", vep_handle);
      return VPPCOM_EINVAL;
    }

  ASSERT (vep_session->vep.vep_sh == ~0);
  ASSERT (vep_session->vep.prev_sh == ~0);

  s = vcl_session_get_w_handle (wrk, session_handle);
  if (PREDICT_FALSE (!s))
    {
      VDBG (0, "Invalid session_handle (%u)!", session_handle);
      return VPPCOM_EBADFD;
    }
  if (PREDICT_FALSE (s->flags & VCL_SESSION_F_IS_VEP))
    {
      VDBG (0, "session_handle (%u) is a vep!", vep_handle);
      return VPPCOM_EINVAL;
    }

  switch (op)
    {
    case EPOLL_CTL_ADD:
      if (PREDICT_FALSE (!event))
	{
	  VDBG (0, "EPOLL_CTL_ADD: NULL pointer to epoll_event structure!");
	  return VPPCOM_EINVAL;
	}
      if (vep_session->vep.next_sh != ~0)
	{
	  vcl_session_t *next_session;
	  next_session = vcl_session_get_w_handle (wrk,
						   vep_session->vep.next_sh);
	  if (PREDICT_FALSE (!next_session))
	    {
	      VDBG (0, "EPOLL_CTL_ADD: Invalid vep.next_sh (%u) on "
		    "vep_idx (%u)!", vep_session->vep.next_sh, vep_handle);
	      return VPPCOM_EBADFD;
	    }
	  ASSERT (next_session->vep.prev_sh == vep_handle);
	  next_session->vep.prev_sh = session_handle;
	}
      s->vep.next_sh = vep_session->vep.next_sh;
      s->vep.prev_sh = vep_handle;
      s->vep.vep_sh = vep_handle;
      s->vep.et_mask = VEP_DEFAULT_ET_MASK;
      s->vep.ev = *event;
      s->flags &= ~VCL_SESSION_F_IS_VEP;
      s->flags |= VCL_SESSION_F_IS_VEP_SESSION;
      vep_session->vep.next_sh = session_handle;

      txf = vcl_session_is_ct (s) ? s->ct_tx_fifo : s->tx_fifo;
      if (txf && (event->events & EPOLLOUT))
	svm_fifo_add_want_deq_ntf (txf, SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL);

      /* Generate EPOLLOUT if tx fifo not full */
      if ((event->events & EPOLLOUT) && (vcl_session_write_ready (s) > 0))
	{
	  session_event_t e = { 0 };
	  e.event_type = SESSION_IO_EVT_TX;
	  e.session_index = s->session_index;
	  vec_add1 (wrk->unhandled_evts_vector, e);
	}
      /* Generate EPOLLIN if rx fifo has data */
      if ((event->events & EPOLLIN) && (vcl_session_read_ready (s) > 0))
	{
	  session_event_t e = { 0 };
	  e.event_type = SESSION_IO_EVT_RX;
	  e.session_index = s->session_index;
	  vec_add1 (wrk->unhandled_evts_vector, e);
	}
      VDBG (1, "EPOLL_CTL_ADD: vep_sh %u, sh %u, events 0x%x, data 0x%llx!",
	    vep_handle, session_handle, event->events, event->data.u64);
      vcl_evt (VCL_EVT_EPOLL_CTLADD, s, event->events, event->data.u64);
      break;

    case EPOLL_CTL_MOD:
      if (PREDICT_FALSE (!event))
	{
	  VDBG (0, "EPOLL_CTL_MOD: NULL pointer to epoll_event structure!");
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      else if (PREDICT_FALSE (!(s->flags & VCL_SESSION_F_IS_VEP_SESSION)))
	{
	  VDBG (0, "sh %u EPOLL_CTL_MOD: not a vep session!", session_handle);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      else if (PREDICT_FALSE (s->vep.vep_sh != vep_handle))
	{
	  VDBG (0, "EPOLL_CTL_MOD: sh %u vep_sh (%u) != vep_sh (%u)!",
		session_handle, s->vep.vep_sh, vep_handle);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}

      /* Generate EPOLLOUT when tx_fifo/ct_tx_fifo not full */
      if ((event->events & EPOLLOUT) &&
	  !(s->vep.ev.events & EPOLLOUT) && (vcl_session_write_ready (s) > 0))
	{
	  session_event_t e = { 0 };
	  e.event_type = SESSION_IO_EVT_TX;
	  e.session_index = s->session_index;
	  vec_add1 (wrk->unhandled_evts_vector, e);
	}
      s->vep.et_mask = VEP_DEFAULT_ET_MASK;
      s->vep.ev = *event;
      txf = vcl_session_is_ct (s) ? s->ct_tx_fifo : s->tx_fifo;
      if (event->events & EPOLLOUT)
	svm_fifo_add_want_deq_ntf (txf, SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL);
      else
	svm_fifo_del_want_deq_ntf (txf, SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL);
      VDBG (1, "EPOLL_CTL_MOD: vep_sh %u, sh %u, events 0x%x, data 0x%llx!",
	    vep_handle, session_handle, event->events, event->data.u64);
      break;

    case EPOLL_CTL_DEL:
      if (PREDICT_FALSE (!(s->flags & VCL_SESSION_F_IS_VEP_SESSION)))
	{
	  VDBG (0, "EPOLL_CTL_DEL: %u not a vep session!", session_handle);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      else if (PREDICT_FALSE (s->vep.vep_sh != vep_handle))
	{
	  VDBG (0, "EPOLL_CTL_DEL: sh %u vep_sh (%u) != vep_sh (%u)!",
		session_handle, s->vep.vep_sh, vep_handle);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}

      if (s->vep.prev_sh == vep_handle)
	vep_session->vep.next_sh = s->vep.next_sh;
      else
	{
	  vcl_session_t *prev_session;
	  prev_session = vcl_session_get_w_handle (wrk, s->vep.prev_sh);
	  if (PREDICT_FALSE (!prev_session))
	    {
	      VDBG (0, "EPOLL_CTL_DEL: Invalid prev_sh (%u) on sh (%u)!",
		    s->vep.prev_sh, session_handle);
	      return VPPCOM_EBADFD;
	    }
	  ASSERT (prev_session->vep.next_sh == session_handle);
	  prev_session->vep.next_sh = s->vep.next_sh;
	}
      if (s->vep.next_sh != ~0)
	{
	  vcl_session_t *next_session;
	  next_session = vcl_session_get_w_handle (wrk, s->vep.next_sh);
	  if (PREDICT_FALSE (!next_session))
	    {
	      VDBG (0, "EPOLL_CTL_DEL: Invalid next_sh (%u) on sh (%u)!",
		    s->vep.next_sh, session_handle);
	      return VPPCOM_EBADFD;
	    }
	  ASSERT (next_session->vep.prev_sh == session_handle);
	  next_session->vep.prev_sh = s->vep.prev_sh;
	}

      memset (&s->vep, 0, sizeof (s->vep));
      s->vep.next_sh = ~0;
      s->vep.prev_sh = ~0;
      s->vep.vep_sh = ~0;
      s->flags &= ~VCL_SESSION_F_IS_VEP_SESSION;

      txf = vcl_session_is_ct (s) ? s->ct_tx_fifo : s->tx_fifo;
      if (txf)
	svm_fifo_del_want_deq_ntf (txf, SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL);

      VDBG (1, "EPOLL_CTL_DEL: vep_idx %u, sh %u!", vep_handle,
	    session_handle);
      vcl_evt (VCL_EVT_EPOLL_CTLDEL, s, vep_sh);
      break;

    default:
      VDBG (0, "Invalid operation (%d)!", op);
      rv = VPPCOM_EINVAL;
    }

  vep_verify_epoll_chain (wrk, vep_handle);

done:
  return rv;
}

static inline void
vcl_epoll_wait_handle_mq_event (vcl_worker_t * wrk, session_event_t * e,
				struct epoll_event *events, u32 * num_ev)
{
  session_disconnected_msg_t *disconnected_msg;
  session_connected_msg_t *connected_msg;
  u32 sid = ~0, session_events;
  u64 session_evt_data = ~0;
  vcl_session_t *s;
  u8 add_event = 0;

  switch (e->event_type)
    {
    case SESSION_IO_EVT_RX:
      sid = e->session_index;
      s = vcl_session_get (wrk, sid);
      if (vcl_session_is_closed (s))
	break;
      vcl_fifo_rx_evt_valid_or_break (s);
      session_events = s->vep.ev.events;
      if (!(EPOLLIN & s->vep.ev.events)
	  || (s->flags & VCL_SESSION_F_HAS_RX_EVT))
	break;
      add_event = 1;
      events[*num_ev].events |= EPOLLIN;
      session_evt_data = s->vep.ev.data.u64;
      s->flags |= VCL_SESSION_F_HAS_RX_EVT;
      break;
    case SESSION_IO_EVT_TX:
      sid = e->session_index;
      s = vcl_session_get (wrk, sid);
      if (vcl_session_is_closed (s))
	break;
      session_events = s->vep.ev.events;
      if (!(EPOLLOUT & session_events))
	break;
      add_event = 1;
      events[*num_ev].events |= EPOLLOUT;
      session_evt_data = s->vep.ev.data.u64;
      svm_fifo_reset_has_deq_ntf (vcl_session_is_ct (s) ?
				  s->ct_tx_fifo : s->tx_fifo);
      break;
    case SESSION_CTRL_EVT_ACCEPTED:
      if (!e->postponed)
	s = vcl_session_accepted (wrk, (session_accepted_msg_t *) e->data);
      else
	s = vcl_session_get (wrk, e->session_index);
      if (!s)
	break;
      session_events = s->vep.ev.events;
      sid = s->session_index;
      if (!(EPOLLIN & session_events))
	break;
      add_event = 1;
      events[*num_ev].events |= EPOLLIN;
      session_evt_data = s->vep.ev.data.u64;
      break;
    case SESSION_CTRL_EVT_CONNECTED:
      if (!e->postponed)
	{
	  connected_msg = (session_connected_msg_t *) e->data;
	  sid = vcl_session_connected_handler (wrk, connected_msg);
	}
      else
	sid = e->session_index;
      s = vcl_session_get (wrk, sid);
      if (vcl_session_is_closed (s))
	break;
      session_events = s->vep.ev.events;
      /* Generate EPOLLOUT because there's no connected event */
      if (!(EPOLLOUT & session_events))
	break;
      add_event = 1;
      events[*num_ev].events |= EPOLLOUT;
      session_evt_data = s->vep.ev.data.u64;
      if (s->session_state == VCL_STATE_DETACHED)
	events[*num_ev].events |= EPOLLHUP;
      break;
    case SESSION_CTRL_EVT_DISCONNECTED:
      disconnected_msg = (session_disconnected_msg_t *) e->data;
      s = vcl_session_disconnected_handler (wrk, disconnected_msg);
      if (vcl_session_is_closed (s))
	break;
      sid = s->session_index;
      session_events = s->vep.ev.events;
      add_event = 1;
      events[*num_ev].events |= EPOLLHUP | EPOLLRDHUP;
      session_evt_data = s->vep.ev.data.u64;
      break;
    case SESSION_CTRL_EVT_RESET:
      sid = vcl_session_reset_handler (wrk, (session_reset_msg_t *) e->data);
      s = vcl_session_get (wrk, sid);
      if (vcl_session_is_closed (s))
	break;
      session_events = s->vep.ev.events;
      add_event = 1;
      events[*num_ev].events |= EPOLLHUP | EPOLLRDHUP;
      session_evt_data = s->vep.ev.data.u64;
      break;
    case SESSION_CTRL_EVT_UNLISTEN_REPLY:
      vcl_session_unlisten_reply_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_MIGRATED:
      vcl_session_migrated_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_CLEANUP:
      vcl_session_cleanup_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_REQ_WORKER_UPDATE:
      vcl_session_req_worker_update_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_WORKER_UPDATE_REPLY:
      vcl_session_worker_update_reply_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_APP_ADD_SEGMENT:
      vcl_session_app_add_segment_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_APP_DEL_SEGMENT:
      vcl_session_app_del_segment_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_APP_WRK_RPC:
      vcl_worker_rpc_handler (wrk, e->data);
      break;
    default:
      VDBG (0, "unhandled: %u", e->event_type);
      break;
    }

  if (add_event)
    {
      events[*num_ev].data.u64 = session_evt_data;
      if (EPOLLONESHOT & session_events)
	{
	  s = vcl_session_get (wrk, sid);
	  s->vep.ev.events = 0;
	}
      *num_ev += 1;
    }
}

static int
vcl_epoll_wait_handle_mq (vcl_worker_t * wrk, svm_msg_q_t * mq,
			  struct epoll_event *events, u32 maxevents,
			  double wait_for_time, u32 * num_ev)
{
  svm_msg_q_msg_t *msg;
  session_event_t *e;
  int i;

  if (vec_len (wrk->mq_msg_vector) && svm_msg_q_is_empty (mq))
    goto handle_dequeued;

  svm_msg_q_lock (mq);
  if (svm_msg_q_is_empty (mq))
    {
      if (!wait_for_time)
	{
	  svm_msg_q_unlock (mq);
	  return 0;
	}
      else if (wait_for_time < 0)
	{
	  svm_msg_q_wait (mq);
	}
      else
	{
	  if (svm_msg_q_timedwait (mq, wait_for_time / 1e3))
	    {
	      svm_msg_q_unlock (mq);
	      return 0;
	    }
	}
    }
  ASSERT (maxevents > *num_ev);
  vcl_mq_dequeue_batch (wrk, mq, ~0);
  svm_msg_q_unlock (mq);

handle_dequeued:
  for (i = 0; i < vec_len (wrk->mq_msg_vector); i++)
    {
      msg = vec_elt_at_index (wrk->mq_msg_vector, i);
      e = svm_msg_q_msg_data (mq, msg);
      if (*num_ev < maxevents)
	vcl_epoll_wait_handle_mq_event (wrk, e, events, num_ev);
      else
	vcl_handle_mq_event (wrk, e);
      svm_msg_q_free_msg (mq, msg);
    }
  vec_reset_length (wrk->mq_msg_vector);
  vcl_handle_pending_wrk_updates (wrk);
  return *num_ev;
}

static int
vppcom_epoll_wait_condvar (vcl_worker_t * wrk, struct epoll_event *events,
			   int maxevents, u32 n_evts, double wait_for_time)
{
  double wait = 0, start = 0, now;

  if (!n_evts)
    {
      wait = wait_for_time;
      start = clib_time_now (&wrk->clib_time);
    }

  do
    {
      vcl_epoll_wait_handle_mq (wrk, wrk->app_event_queue, events, maxevents,
				wait, &n_evts);
      if (n_evts)
	return n_evts;
      if (wait == -1)
	continue;

      now = clib_time_now (&wrk->clib_time);
      wait -= (now - start) * 1e3;
      start = now;
    }
  while (wait > 0);

  return 0;
}

static int
vppcom_epoll_wait_eventfd (vcl_worker_t * wrk, struct epoll_event *events,
			   int maxevents, u32 n_evts, double wait_for_time)
{
  vcl_mq_evt_conn_t *mqc;
  int __clib_unused n_read;
  int n_mq_evts, i;
  u64 buf;

  vec_validate (wrk->mq_events, pool_elts (wrk->mq_evt_conns));
again:
  n_mq_evts = epoll_wait (wrk->mqs_epfd, wrk->mq_events,
			  vec_len (wrk->mq_events), wait_for_time);
  for (i = 0; i < n_mq_evts; i++)
    {
      mqc = vcl_mq_evt_conn_get (wrk, wrk->mq_events[i].data.u32);
      n_read = read (mqc->mq_fd, &buf, sizeof (buf));
      vcl_epoll_wait_handle_mq (wrk, mqc->mq, events, maxevents, 0, &n_evts);
    }
  if (!n_evts && n_mq_evts > 0)
    goto again;

  return (int) n_evts;
}

int
vppcom_epoll_wait (uint32_t vep_handle, struct epoll_event *events,
		   int maxevents, double wait_for_time)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *vep_session;
  u32 n_evts = 0;
  int i;

  if (PREDICT_FALSE (maxevents <= 0))
    {
      VDBG (0, "ERROR: Invalid maxevents (%d)!", maxevents);
      return VPPCOM_EINVAL;
    }

  vep_session = vcl_session_get_w_handle (wrk, vep_handle);
  if (!vep_session)
    return VPPCOM_EBADFD;

  if (PREDICT_FALSE (!(vep_session->flags & VCL_SESSION_F_IS_VEP)))
    {
      VDBG (0, "ERROR: vep_idx (%u) is not a vep!", vep_handle);
      return VPPCOM_EINVAL;
    }

  memset (events, 0, sizeof (*events) * maxevents);

  if (vec_len (wrk->unhandled_evts_vector))
    {
      for (i = 0; i < vec_len (wrk->unhandled_evts_vector); i++)
	{
	  vcl_epoll_wait_handle_mq_event (wrk, &wrk->unhandled_evts_vector[i],
					  events, &n_evts);
	  if (n_evts == maxevents)
	    {
	      vec_delete (wrk->unhandled_evts_vector, i + 1, 0);
	      return n_evts;
	    }
	}
      vec_reset_length (wrk->unhandled_evts_vector);
    }

  if (vcm->cfg.use_mq_eventfd)
    return vppcom_epoll_wait_eventfd (wrk, events, maxevents, n_evts,
				      wait_for_time);

  return vppcom_epoll_wait_condvar (wrk, events, maxevents, n_evts,
				    wait_for_time);
}

int
vppcom_session_attr (uint32_t session_handle, uint32_t op,
		     void *buffer, uint32_t * buflen)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session;
  int rv = VPPCOM_OK;
  u32 *flags = buffer, tmp_flags = 0;
  vppcom_endpt_t *ep = buffer;

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;

  switch (op)
    {
    case VPPCOM_ATTR_GET_NREAD:
      rv = vcl_session_read_ready (session);
      VDBG (2, "VPPCOM_ATTR_GET_NREAD: sh %u, nread = %d", session_handle,
	    rv);
      break;

    case VPPCOM_ATTR_GET_NWRITE:
      rv = vcl_session_write_ready (session);
      VDBG (2, "VPPCOM_ATTR_GET_NWRITE: sh %u, nwrite = %d", session_handle,
	    rv);
      break;

    case VPPCOM_ATTR_GET_FLAGS:
      if (PREDICT_TRUE (buffer && buflen && (*buflen >= sizeof (*flags))))
	{
	  *flags =
	    O_RDWR |
	    (vcl_session_has_attr (session, VCL_SESS_ATTR_NONBLOCK) ?
	     O_NONBLOCK : 0);
	  *buflen = sizeof (*flags);
	  VDBG (2, "VPPCOM_ATTR_GET_FLAGS: sh %u, flags = 0x%08x, "
		"is_nonblocking = %u", session_handle, *flags,
		vcl_session_has_attr (session, VCL_SESS_ATTR_NONBLOCK));
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_FLAGS:
      if (PREDICT_TRUE (buffer && buflen && (*buflen == sizeof (*flags))))
	{
	  if (*flags & O_NONBLOCK)
	    vcl_session_set_attr (session, VCL_SESS_ATTR_NONBLOCK);
	  else
	    vcl_session_clear_attr (session, VCL_SESS_ATTR_NONBLOCK);

	  VDBG (2, "VPPCOM_ATTR_SET_FLAGS: sh %u, flags = 0x%08x,"
		" is_nonblocking = %u", session_handle, *flags,
		vcl_session_has_attr (session, VCL_SESS_ATTR_NONBLOCK));
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
	    clib_memcpy_fast (ep->ip, &session->transport.rmt_ip.ip4,
			      sizeof (ip4_address_t));
	  else
	    clib_memcpy_fast (ep->ip, &session->transport.rmt_ip.ip6,
			      sizeof (ip6_address_t));
	  *buflen = sizeof (*ep);
	  VDBG (1, "VPPCOM_ATTR_GET_PEER_ADDR: sh %u, is_ip4 = %u, "
		"addr = %U, port %u", session_handle, ep->is_ip4,
		format_ip46_address, &session->transport.rmt_ip,
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
	    clib_memcpy_fast (ep->ip, &session->transport.lcl_ip.ip4,
			      sizeof (ip4_address_t));
	  else
	    clib_memcpy_fast (ep->ip, &session->transport.lcl_ip.ip6,
			      sizeof (ip6_address_t));
	  *buflen = sizeof (*ep);
	  VDBG (1, "VPPCOM_ATTR_GET_LCL_ADDR: sh %u, is_ip4 = %u, addr = %U"
		" port %d", session_handle, ep->is_ip4, format_ip46_address,
		&session->transport.lcl_ip,
		ep->is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
		clib_net_to_host_u16 (ep->port));
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_LCL_ADDR:
      if (PREDICT_TRUE (buffer && buflen &&
			(*buflen >= sizeof (*ep)) && ep->ip))
	{
	  session->transport.is_ip4 = ep->is_ip4;
	  session->transport.lcl_port = ep->port;
	  vcl_ip_copy_from_ep (&session->transport.lcl_ip, ep);
	  *buflen = sizeof (*ep);
	  VDBG (1, "VPPCOM_ATTR_SET_LCL_ADDR: sh %u, is_ip4 = %u, addr = %U"
		" port %d", session_handle, ep->is_ip4, format_ip46_address,
		&session->transport.lcl_ip,
		ep->is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
		clib_net_to_host_u16 (ep->port));
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_LIBC_EPFD:
      rv = session->libc_epfd;
      VDBG (2, "VPPCOM_ATTR_GET_LIBC_EPFD: libc_epfd %d", rv);
      break;

    case VPPCOM_ATTR_SET_LIBC_EPFD:
      if (PREDICT_TRUE (buffer && buflen &&
			(*buflen == sizeof (session->libc_epfd))))
	{
	  session->libc_epfd = *(int *) buffer;
	  *buflen = sizeof (session->libc_epfd);

	  VDBG (2, "VPPCOM_ATTR_SET_LIBC_EPFD: libc_epfd %d, buflen %d",
		session->libc_epfd, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_PROTOCOL:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  *(int *) buffer = session->session_type;
	  *buflen = sizeof (int);

	  VDBG (2, "VPPCOM_ATTR_GET_PROTOCOL: %d (%s), buflen %d",
		*(int *) buffer, *(int *) buffer ? "UDP" : "TCP", *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_LISTEN:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  *(int *) buffer = vcl_session_has_attr (session,
						  VCL_SESS_ATTR_LISTEN);
	  *buflen = sizeof (int);

	  VDBG (2, "VPPCOM_ATTR_GET_LISTEN: %d, buflen %d", *(int *) buffer,
		*buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_ERROR:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  *(int *) buffer = 0;
	  *buflen = sizeof (int);

	  VDBG (2, "VPPCOM_ATTR_GET_ERROR: %d, buflen %d, #VPP-TBD#",
		*(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_TX_FIFO_LEN:
      if (buffer && buflen && (*buflen >= sizeof (u32)))
	{

	  /* VPP-TBD */
	  *(size_t *) buffer = (session->sndbuf_size ? session->sndbuf_size :
				session->tx_fifo ?
				svm_fifo_size (session->tx_fifo) :
				vcm->cfg.tx_fifo_size);
	  *buflen = sizeof (u32);

	  VDBG (2, "VPPCOM_ATTR_GET_TX_FIFO_LEN: %u (0x%x), buflen %d,"
		" #VPP-TBD#", *(size_t *) buffer, *(size_t *) buffer,
		*buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_TX_FIFO_LEN:
      if (buffer && buflen && (*buflen == sizeof (u32)))
	{
	  /* VPP-TBD */
	  session->sndbuf_size = *(u32 *) buffer;
	  VDBG (2, "VPPCOM_ATTR_SET_TX_FIFO_LEN: %u (0x%x), buflen %d,"
		" #VPP-TBD#", session->sndbuf_size, session->sndbuf_size,
		*buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_RX_FIFO_LEN:
      if (buffer && buflen && (*buflen >= sizeof (u32)))
	{

	  /* VPP-TBD */
	  *(size_t *) buffer = (session->rcvbuf_size ? session->rcvbuf_size :
				session->rx_fifo ?
				svm_fifo_size (session->rx_fifo) :
				vcm->cfg.rx_fifo_size);
	  *buflen = sizeof (u32);

	  VDBG (2, "VPPCOM_ATTR_GET_RX_FIFO_LEN: %u (0x%x), buflen %d, "
		"#VPP-TBD#", *(size_t *) buffer, *(size_t *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_RX_FIFO_LEN:
      if (buffer && buflen && (*buflen == sizeof (u32)))
	{
	  /* VPP-TBD */
	  session->rcvbuf_size = *(u32 *) buffer;
	  VDBG (2, "VPPCOM_ATTR_SET_RX_FIFO_LEN: %u (0x%x), buflen %d,"
		" #VPP-TBD#", session->sndbuf_size, session->sndbuf_size,
		*buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_REUSEADDR:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = vcl_session_has_attr (session,
						  VCL_SESS_ATTR_REUSEADDR);
	  *buflen = sizeof (int);

	  VDBG (2, "VPPCOM_ATTR_GET_REUSEADDR: %d, buflen %d, #VPP-TBD#",
		*(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_REUSEADDR:
      if (buffer && buflen && (*buflen == sizeof (int)) &&
	  !vcl_session_has_attr (session, VCL_SESS_ATTR_LISTEN))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    vcl_session_set_attr (session, VCL_SESS_ATTR_REUSEADDR);
	  else
	    vcl_session_clear_attr (session, VCL_SESS_ATTR_REUSEADDR);

	  VDBG (2, "VPPCOM_ATTR_SET_REUSEADDR: %d, buflen %d, #VPP-TBD#",
		vcl_session_has_attr (session, VCL_SESS_ATTR_REUSEADDR),
		*buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_REUSEPORT:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = vcl_session_has_attr (session,
						  VCL_SESS_ATTR_REUSEPORT);
	  *buflen = sizeof (int);

	  VDBG (2, "VPPCOM_ATTR_GET_REUSEPORT: %d, buflen %d, #VPP-TBD#",
		*(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_REUSEPORT:
      if (buffer && buflen && (*buflen == sizeof (int)) &&
	  !vcl_session_has_attr (session, VCL_SESS_ATTR_LISTEN))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    vcl_session_set_attr (session, VCL_SESS_ATTR_REUSEPORT);
	  else
	    vcl_session_clear_attr (session, VCL_SESS_ATTR_REUSEPORT);

	  VDBG (2, "VPPCOM_ATTR_SET_REUSEPORT: %d, buflen %d, #VPP-TBD#",
		vcl_session_has_attr (session, VCL_SESS_ATTR_REUSEPORT),
		*buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_BROADCAST:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = vcl_session_has_attr (session,
						  VCL_SESS_ATTR_BROADCAST);
	  *buflen = sizeof (int);

	  VDBG (2, "VPPCOM_ATTR_GET_BROADCAST: %d, buflen %d, #VPP-TBD#",
		*(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_BROADCAST:
      if (buffer && buflen && (*buflen == sizeof (int)))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    vcl_session_set_attr (session, VCL_SESS_ATTR_BROADCAST);
	  else
	    vcl_session_clear_attr (session, VCL_SESS_ATTR_BROADCAST);

	  VDBG (2, "VPPCOM_ATTR_SET_BROADCAST: %d, buflen %d, #VPP-TBD#",
		vcl_session_has_attr (session, VCL_SESS_ATTR_BROADCAST),
		*buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_V6ONLY:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = vcl_session_has_attr (session,
						  VCL_SESS_ATTR_V6ONLY);
	  *buflen = sizeof (int);

	  VDBG (2, "VPPCOM_ATTR_GET_V6ONLY: %d, buflen %d, #VPP-TBD#",
		*(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_V6ONLY:
      if (buffer && buflen && (*buflen == sizeof (int)))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    vcl_session_set_attr (session, VCL_SESS_ATTR_V6ONLY);
	  else
	    vcl_session_clear_attr (session, VCL_SESS_ATTR_V6ONLY);

	  VDBG (2, "VPPCOM_ATTR_SET_V6ONLY: %d, buflen %d, #VPP-TBD#",
		vcl_session_has_attr (session, VCL_SESS_ATTR_V6ONLY),
		*buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_KEEPALIVE:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = vcl_session_has_attr (session,
						  VCL_SESS_ATTR_KEEPALIVE);
	  *buflen = sizeof (int);

	  VDBG (2, "VPPCOM_ATTR_GET_KEEPALIVE: %d, buflen %d, #VPP-TBD#",
		*(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_KEEPALIVE:
      if (buffer && buflen && (*buflen == sizeof (int)))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    vcl_session_set_attr (session, VCL_SESS_ATTR_KEEPALIVE);
	  else
	    vcl_session_clear_attr (session, VCL_SESS_ATTR_KEEPALIVE);

	  VDBG (2, "VPPCOM_ATTR_SET_KEEPALIVE: %d, buflen %d, #VPP-TBD#",
		vcl_session_has_attr (session, VCL_SESS_ATTR_KEEPALIVE),
		*buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_TCP_NODELAY:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = vcl_session_has_attr (session,
						  VCL_SESS_ATTR_TCP_NODELAY);
	  *buflen = sizeof (int);

	  VDBG (2, "VPPCOM_ATTR_GET_TCP_NODELAY: %d, buflen %d, #VPP-TBD#",
		*(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_TCP_NODELAY:
      if (buffer && buflen && (*buflen == sizeof (int)))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    vcl_session_set_attr (session, VCL_SESS_ATTR_TCP_NODELAY);
	  else
	    vcl_session_clear_attr (session, VCL_SESS_ATTR_TCP_NODELAY);

	  VDBG (2, "VPPCOM_ATTR_SET_TCP_NODELAY: %d, buflen %d, #VPP-TBD#",
		vcl_session_has_attr (session, VCL_SESS_ATTR_TCP_NODELAY),
		*buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_TCP_KEEPIDLE:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = vcl_session_has_attr (session,
						  VCL_SESS_ATTR_TCP_KEEPIDLE);
	  *buflen = sizeof (int);

	  VDBG (2, "VPPCOM_ATTR_GET_TCP_KEEPIDLE: %d, buflen %d, #VPP-TBD#",
		*(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_TCP_KEEPIDLE:
      if (buffer && buflen && (*buflen == sizeof (int)))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    vcl_session_set_attr (session, VCL_SESS_ATTR_TCP_KEEPIDLE);
	  else
	    vcl_session_clear_attr (session, VCL_SESS_ATTR_TCP_KEEPIDLE);

	  VDBG (2, "VPPCOM_ATTR_SET_TCP_KEEPIDLE: %d, buflen %d, #VPP-TBD#",
		vcl_session_has_attr (session,
				      VCL_SESS_ATTR_TCP_KEEPIDLE), *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_GET_TCP_KEEPINTVL:
      if (buffer && buflen && (*buflen >= sizeof (int)))
	{
	  /* VPP-TBD */
	  *(int *) buffer = vcl_session_has_attr (session,
						  VCL_SESS_ATTR_TCP_KEEPINTVL);
	  *buflen = sizeof (int);

	  VDBG (2, "VPPCOM_ATTR_GET_TCP_KEEPINTVL: %d, buflen %d, #VPP-TBD#",
		*(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_TCP_KEEPINTVL:
      if (buffer && buflen && (*buflen == sizeof (int)))
	{
	  /* VPP-TBD */
	  if (*(int *) buffer)
	    vcl_session_set_attr (session, VCL_SESS_ATTR_TCP_KEEPINTVL);
	  else
	    vcl_session_clear_attr (session, VCL_SESS_ATTR_TCP_KEEPINTVL);

	  VDBG (2, "VPPCOM_ATTR_SET_TCP_KEEPINTVL: %d, buflen %d, #VPP-TBD#",
		vcl_session_has_attr (session,
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

	  VDBG (2, "VPPCOM_ATTR_GET_TCP_USER_MSS: %d, buflen %d, #VPP-TBD#",
		*(int *) buffer, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_TCP_USER_MSS:
      if (buffer && buflen && (*buflen == sizeof (u32)))
	{
	  /* VPP-TBD */
	  session->user_mss = *(u32 *) buffer;

	  VDBG (2, "VPPCOM_ATTR_SET_TCP_USER_MSS: %u, buflen %d, #VPP-TBD#",
		session->user_mss, *buflen);
	}
      else
	rv = VPPCOM_EINVAL;
      break;

    case VPPCOM_ATTR_SET_SHUT:
      if (*flags == SHUT_RD || *flags == SHUT_RDWR)
	vcl_session_set_attr (session, VCL_SESS_ATTR_SHUT_RD);
      if (*flags == SHUT_WR || *flags == SHUT_RDWR)
	vcl_session_set_attr (session, VCL_SESS_ATTR_SHUT_WR);
      break;

    case VPPCOM_ATTR_GET_SHUT:
      if (vcl_session_has_attr (session, VCL_SESS_ATTR_SHUT_RD))
	tmp_flags = 1;
      if (vcl_session_has_attr (session, VCL_SESS_ATTR_SHUT_WR))
	tmp_flags |= 2;
      if (tmp_flags == 1)
	*(int *) buffer = SHUT_RD;
      else if (tmp_flags == 2)
	*(int *) buffer = SHUT_WR;
      else if (tmp_flags == 3)
	*(int *) buffer = SHUT_RDWR;
      *buflen = sizeof (int);
      break;

    case VPPCOM_ATTR_SET_CONNECTED:
      session->flags |= VCL_SESSION_F_CONNECTED;
      break;

    default:
      rv = VPPCOM_EINVAL;
      break;
    }

  return rv;
}

int
vppcom_session_recvfrom (uint32_t session_handle, void *buffer,
			 uint32_t buflen, int flags, vppcom_endpt_t * ep)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session;
  int rv = VPPCOM_OK;

  if (flags == 0)
    rv = vppcom_session_read (session_handle, buffer, buflen);
  else if (flags & MSG_PEEK)
    rv = vppcom_session_peek (session_handle, buffer, buflen);
  else
    {
      VDBG (0, "Unsupport flags for recvfrom %d", flags);
      return VPPCOM_EAFNOSUPPORT;
    }

  if (ep && rv > 0)
    {
      session = vcl_session_get_w_handle (wrk, session_handle);
      if (session->transport.is_ip4)
	clib_memcpy_fast (ep->ip, &session->transport.rmt_ip.ip4,
			  sizeof (ip4_address_t));
      else
	clib_memcpy_fast (ep->ip, &session->transport.rmt_ip.ip6,
			  sizeof (ip6_address_t));
      ep->is_ip4 = session->transport.is_ip4;
      ep->port = session->transport.rmt_port;
    }

  return rv;
}

int
vppcom_session_sendto (uint32_t session_handle, void *buffer,
		       uint32_t buflen, int flags, vppcom_endpt_t * ep)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *s;

  s = vcl_session_get_w_handle (wrk, session_handle);
  if (!s)
    return VPPCOM_EBADFD;

  if (!buffer)
    return VPPCOM_EINVAL;

  if (ep)
    {
      if (!vcl_session_is_cl (s))
	return VPPCOM_EINVAL;

      /* Session not connected/bound in vpp. Create it by 'connecting' it */
      if (PREDICT_FALSE (s->session_state == VCL_STATE_CLOSED))
	{
	  u32 session_index = s->session_index;
	  f64 timeout = vcm->cfg.session_timeout;
	  int rv;

	  vcl_send_session_connect (wrk, s);
	  rv = vppcom_wait_for_session_state_change (session_index,
						     VCL_STATE_READY,
						     timeout);
	  if (rv < 0)
	    return rv;
	  s = vcl_session_get (wrk, session_index);
	}

      s->transport.is_ip4 = ep->is_ip4;
      s->transport.rmt_port = ep->port;
      vcl_ip_copy_from_ep (&s->transport.rmt_ip, ep);
    }

  if (flags)
    {
      // TBD check the flags and do the right thing
      VDBG (2, "handling flags 0x%u (%d) not implemented yet.", flags, flags);
    }

  return (vppcom_session_write_inline (wrk, s, buffer, buflen, 1,
				       s->is_dgram ? 1 : 0));
}

int
vppcom_poll (vcl_poll_t * vp, uint32_t n_sids, double wait_for_time)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  f64 timeout = clib_time_now (&wrk->clib_time) + wait_for_time;
  u32 i, keep_trying = 1;
  svm_msg_q_msg_t msg;
  session_event_t *e;
  int rv, num_ev = 0;

  VDBG (3, "vp %p, nsids %u, wait_for_time %f", vp, n_sids, wait_for_time);

  if (!vp)
    return VPPCOM_EFAULT;

  do
    {
      vcl_session_t *session;

      /* Dequeue all events and drop all unhandled io events */
      while (svm_msg_q_sub (wrk->app_event_queue, &msg, SVM_Q_NOWAIT, 0) == 0)
	{
	  e = svm_msg_q_msg_data (wrk->app_event_queue, &msg);
	  vcl_handle_mq_event (wrk, e);
	  svm_msg_q_free_msg (wrk->app_event_queue, &msg);
	}
      vec_reset_length (wrk->unhandled_evts_vector);

      for (i = 0; i < n_sids; i++)
	{
	  session = vcl_session_get (wrk, vp[i].sh);
	  if (!session)
	    {
	      vp[i].revents = POLLHUP;
	      num_ev++;
	      continue;
	    }

	  vp[i].revents = 0;

	  if (POLLIN & vp[i].events)
	    {
	      rv = vcl_session_read_ready (session);
	      if (rv > 0)
		{
		  vp[i].revents |= POLLIN;
		  num_ev++;
		}
	      else if (rv < 0)
		{
		  switch (rv)
		    {
		    case VPPCOM_ECONNRESET:
		      vp[i].revents = POLLHUP;
		      break;

		    default:
		      vp[i].revents = POLLERR;
		      break;
		    }
		  num_ev++;
		}
	    }

	  if (POLLOUT & vp[i].events)
	    {
	      rv = vcl_session_write_ready (session);
	      if (rv > 0)
		{
		  vp[i].revents |= POLLOUT;
		  num_ev++;
		}
	      else if (rv < 0)
		{
		  switch (rv)
		    {
		    case VPPCOM_ECONNRESET:
		      vp[i].revents = POLLHUP;
		      break;

		    default:
		      vp[i].revents = POLLERR;
		      break;
		    }
		  num_ev++;
		}
	    }

	  if (0)		// Note "done:" label used by VCL_SESSION_LOCK_AND_GET()
	    {
	      vp[i].revents = POLLNVAL;
	      num_ev++;
	    }
	}
      if (wait_for_time != -1)
	keep_trying = (clib_time_now (&wrk->clib_time) <= timeout) ? 1 : 0;
    }
  while ((num_ev == 0) && keep_trying);

  return num_ev;
}

int
vppcom_mq_epoll_fd (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  return wrk->mqs_epfd;
}

int
vppcom_session_index (vcl_session_handle_t session_handle)
{
  return session_handle & 0xFFFFFF;
}

int
vppcom_session_worker (vcl_session_handle_t session_handle)
{
  return session_handle >> 24;
}

int
vppcom_worker_register (void)
{
  if (!vcl_worker_alloc_and_init ())
    return VPPCOM_EEXIST;

  if (vcl_worker_register_with_vpp ())
    return VPPCOM_EEXIST;

  return VPPCOM_OK;
}

void
vppcom_worker_unregister (void)
{
  vcl_worker_cleanup (vcl_worker_get_current (), 1 /* notify vpp */ );
  vcl_set_worker_index (~0);
}

void
vppcom_worker_index_set (int index)
{
  vcl_set_worker_index (index);
}

int
vppcom_worker_index (void)
{
  return vcl_get_worker_index ();
}

int
vppcom_worker_mqs_epfd (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  if (!vcm->cfg.use_mq_eventfd)
    return -1;
  return wrk->mqs_epfd;
}

int
vppcom_session_is_connectable_listener (uint32_t session_handle)
{
  vcl_session_t *session;
  vcl_worker_t *wrk = vcl_worker_get_current ();
  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;
  return vcl_session_is_connectable_listener (wrk, session);
}

int
vppcom_session_listener (uint32_t session_handle)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *listen_session, *session;
  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;
  if (session->listener_index == VCL_INVALID_SESSION_INDEX)
    return VPPCOM_EBADFD;
  listen_session = vcl_session_get_w_handle (wrk, session->listener_index);
  if (!listen_session)
    return VPPCOM_EBADFD;
  return vcl_session_handle (listen_session);
}

int
vppcom_session_n_accepted (uint32_t session_handle)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;
  return session->n_accepted_sessions;
}

const char *
vppcom_proto_str (vppcom_proto_t proto)
{
  char const *proto_str;

  switch (proto)
    {
    case VPPCOM_PROTO_TCP:
      proto_str = "TCP";
      break;
    case VPPCOM_PROTO_UDP:
      proto_str = "UDP";
      break;
    case VPPCOM_PROTO_TLS:
      proto_str = "TLS";
      break;
    case VPPCOM_PROTO_QUIC:
      proto_str = "QUIC";
      break;
    default:
      proto_str = "UNKNOWN";
      break;
    }
  return proto_str;
}

const char *
vppcom_retval_str (int retval)
{
  char const *st;

  switch (retval)
    {
    case VPPCOM_OK:
      st = "VPPCOM_OK";
      break;

    case VPPCOM_EAGAIN:
      st = "VPPCOM_EAGAIN";
      break;

    case VPPCOM_EFAULT:
      st = "VPPCOM_EFAULT";
      break;

    case VPPCOM_ENOMEM:
      st = "VPPCOM_ENOMEM";
      break;

    case VPPCOM_EINVAL:
      st = "VPPCOM_EINVAL";
      break;

    case VPPCOM_EBADFD:
      st = "VPPCOM_EBADFD";
      break;

    case VPPCOM_EAFNOSUPPORT:
      st = "VPPCOM_EAFNOSUPPORT";
      break;

    case VPPCOM_ECONNABORTED:
      st = "VPPCOM_ECONNABORTED";
      break;

    case VPPCOM_ECONNRESET:
      st = "VPPCOM_ECONNRESET";
      break;

    case VPPCOM_ENOTCONN:
      st = "VPPCOM_ENOTCONN";
      break;

    case VPPCOM_ECONNREFUSED:
      st = "VPPCOM_ECONNREFUSED";
      break;

    case VPPCOM_ETIMEDOUT:
      st = "VPPCOM_ETIMEDOUT";
      break;

    default:
      st = "UNKNOWN_STATE";
      break;
    }

  return st;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
