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
#include <vcl/vcl_debug.h>
#include <vcl/vcl_private.h>

__thread uword __vcl_worker_index = ~0;

static int
vcl_wait_for_segment (u64 segment_handle)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  u32 wait_for_seconds = 10, segment_index;
  f64 timeout;

  if (segment_handle == VCL_INVALID_SEGMENT_HANDLE)
    return 1;

  timeout = clib_time_now (&wrk->clib_time) + wait_for_seconds;
  while (clib_time_now (&wrk->clib_time) < timeout)
    {
      segment_index = vcl_segment_table_lookup (segment_handle);
      if (segment_index != VCL_INVALID_SEGMENT_INDEX)
	return 0;
      usleep (10);
    }
  return 1;
}

static inline int
vcl_mq_dequeue_batch (vcl_worker_t * wrk, svm_msg_q_t * mq)
{
  svm_msg_q_msg_t *msg;
  u32 n_msgs;
  int i;

  n_msgs = svm_msg_q_size (mq);
  for (i = 0; i < n_msgs; i++)
    {
      vec_add2 (wrk->mq_msg_vector, msg, 1);
      svm_msg_q_sub_w_lock (mq, msg);
    }
  return n_msgs;
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

    case STATE_VPP_CLOSING:
      st = "STATE_VPP_CLOSING";
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
vcl_send_session_disconnected_reply (svm_msg_q_t * mq, u32 context,
				     session_handle_t handle, int retval)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_disconnected_reply_msg_t *rmp;
  app_alloc_ctrl_evt_to_vpp (mq, app_evt,
			     SESSION_CTRL_EVT_DISCONNECTED_REPLY);
  rmp = (session_disconnected_reply_msg_t *) app_evt->evt->data;
  rmp->handle = handle;
  rmp->context = context;
  rmp->retval = retval;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

static void
vcl_send_session_reset_reply (svm_msg_q_t * mq, u32 context,
			      session_handle_t handle, int retval)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_reset_reply_msg_t *rmp;
  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_RESET_REPLY);
  rmp = (session_reset_reply_msg_t *) app_evt->evt->data;
  rmp->handle = handle;
  rmp->context = context;
  rmp->retval = retval;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

void
vcl_send_session_worker_update (vcl_worker_t * wrk, vcl_session_t * s,
				u32 wrk_index)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_worker_update_msg_t *mp;
  svm_msg_q_t *mq;

  mq = vcl_session_vpp_evt_q (wrk, s);
  app_alloc_ctrl_evt_to_vpp (mq, app_evt, SESSION_CTRL_EVT_WORKER_UPDATE);
  mp = (session_worker_update_msg_t *) app_evt->evt->data;
  mp->client_index = wrk->my_client_index;
  mp->handle = s->vpp_handle;
  mp->req_wrk_index = wrk->vpp_wrk_index;
  mp->wrk_index = wrk_index;
  app_send_ctrl_evt_to_vpp (mq, app_evt);
}

static u32
vcl_session_accepted_handler (vcl_worker_t * wrk, session_accepted_msg_t * mp)
{
  vcl_session_t *session, *listen_session;
  svm_fifo_t *rx_fifo, *tx_fifo;
  u32 vpp_wrk_index;
  svm_msg_q_t *evt_q;

  session = vcl_session_alloc (wrk);

  listen_session = vcl_session_table_lookup_listener (wrk,
						      mp->listener_handle);
  if (!listen_session)
    {
      svm_msg_q_t *evt_q;
      evt_q = uword_to_pointer (mp->vpp_event_queue_address, svm_msg_q_t *);
      clib_warning ("VCL<%d>: ERROR: couldn't find listen session: "
		    "unknown vpp listener handle %llx",
		    getpid (), mp->listener_handle);
      vcl_send_session_accepted_reply (evt_q, mp->context, mp->handle,
				       VNET_API_ERROR_INVALID_ARGUMENT);
      vcl_session_free (wrk, session);
      return VCL_INVALID_SESSION_INDEX;
    }

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);

  if (mp->server_event_queue_address)
    {
      session->vpp_evt_q = uword_to_pointer (mp->client_event_queue_address,
					     svm_msg_q_t *);
      session->our_evt_q = uword_to_pointer (mp->server_event_queue_address,
					     svm_msg_q_t *);
      if (vcl_wait_for_segment (mp->segment_handle))
	{
	  clib_warning ("segment for session %u couldn't be mounted!",
			session->session_index);
	  return VCL_INVALID_SESSION_INDEX;
	}
      rx_fifo->master_session_index = session->session_index;
      tx_fifo->master_session_index = session->session_index;
      rx_fifo->master_thread_index = vcl_get_worker_index ();
      tx_fifo->master_thread_index = vcl_get_worker_index ();
      vec_validate (wrk->vpp_event_queues, 0);
      evt_q = uword_to_pointer (mp->vpp_event_queue_address, svm_msg_q_t *);
      wrk->vpp_event_queues[0] = evt_q;
    }
  else
    {
      session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					     svm_msg_q_t *);
      rx_fifo->client_session_index = session->session_index;
      tx_fifo->client_session_index = session->session_index;
      rx_fifo->client_thread_index = vcl_get_worker_index ();
      tx_fifo->client_thread_index = vcl_get_worker_index ();
      vpp_wrk_index = tx_fifo->master_thread_index;
      vec_validate (wrk->vpp_event_queues, vpp_wrk_index);
      wrk->vpp_event_queues[vpp_wrk_index] = session->vpp_evt_q;
    }

  session->vpp_handle = mp->handle;
  session->vpp_thread_index = rx_fifo->master_thread_index;
  session->client_context = mp->context;
  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;

  session->session_state = STATE_ACCEPT;
  session->transport.rmt_port = mp->port;
  session->transport.is_ip4 = mp->is_ip4;
  clib_memcpy_fast (&session->transport.rmt_ip, mp->ip,
		    sizeof (ip46_address_t));

  vcl_session_table_add_vpp_handle (wrk, mp->handle, session->session_index);
  session->transport.lcl_port = listen_session->transport.lcl_port;
  session->transport.lcl_ip = listen_session->transport.lcl_ip;
  session->session_type = listen_session->session_type;
  session->is_dgram = session->session_type == VPPCOM_PROTO_UDP;

  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: client accept request from %s"
	" address %U port %d queue %p!", getpid (), mp->handle,
	session->session_index,
	mp->is_ip4 ? "IPv4" : "IPv6", format_ip46_address, &mp->ip,
	mp->is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
	clib_net_to_host_u16 (mp->port), session->vpp_evt_q);
  vcl_evt (VCL_EVT_ACCEPT, session, listen_session, session_index);

  return session->session_index;
}

static u32
vcl_session_connected_handler (vcl_worker_t * wrk,
			       session_connected_msg_t * mp)
{
  u32 session_index, vpp_wrk_index;
  svm_fifo_t *rx_fifo, *tx_fifo;
  vcl_session_t *session = 0;
  svm_msg_q_t *evt_q;

  session_index = mp->context;
  session = vcl_session_get (wrk, session_index);
  if (!session)
    {
      clib_warning ("[%s] ERROR: vpp handle 0x%llx, sid %u: "
		    "Invalid session index (%u)!",
		    getpid (), mp->handle, session_index);
      return VCL_INVALID_SESSION_INDEX;
    }
  if (mp->retval)
    {
      clib_warning ("VCL<%d>: ERROR: sid %u: connect failed! %U", getpid (),
		    session_index, format_api_error, ntohl (mp->retval));
      session->session_state = STATE_FAILED;
      session->vpp_handle = mp->handle;
      return session_index;
    }

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  if (vcl_wait_for_segment (mp->segment_handle))
    {
      clib_warning ("segment for session %u couldn't be mounted!",
		    session->session_index);
      return VCL_INVALID_SESSION_INDEX;
    }

  rx_fifo->client_session_index = session_index;
  tx_fifo->client_session_index = session_index;
  rx_fifo->client_thread_index = vcl_get_worker_index ();
  tx_fifo->client_thread_index = vcl_get_worker_index ();

  if (mp->client_event_queue_address)
    {
      session->vpp_evt_q = uword_to_pointer (mp->server_event_queue_address,
					     svm_msg_q_t *);
      session->our_evt_q = uword_to_pointer (mp->client_event_queue_address,
					     svm_msg_q_t *);

      vec_validate (wrk->vpp_event_queues, 0);
      evt_q = uword_to_pointer (mp->vpp_event_queue_address, svm_msg_q_t *);
      wrk->vpp_event_queues[0] = evt_q;
    }
  else
    {
      session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					     svm_msg_q_t *);
      vpp_wrk_index = tx_fifo->master_thread_index;
      vec_validate (wrk->vpp_event_queues, vpp_wrk_index);
      wrk->vpp_event_queues[vpp_wrk_index] = session->vpp_evt_q;
    }

  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;
  session->vpp_handle = mp->handle;
  session->vpp_thread_index = rx_fifo->master_thread_index;
  session->transport.is_ip4 = mp->is_ip4;
  clib_memcpy_fast (&session->transport.lcl_ip, mp->lcl_ip,
		    sizeof (session->transport.lcl_ip));
  session->transport.lcl_port = mp->lcl_port;
  session->session_state = STATE_CONNECT;

  /* Add it to lookup table */
  vcl_session_table_add_vpp_handle (wrk, mp->handle, session_index);

  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: connect succeeded! "
	"session_rx_fifo %p, refcnt %d, session_tx_fifo %p, refcnt %d",
	getpid (), mp->handle, session_index, session->rx_fifo,
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
  if (session->session_state == STATE_LISTEN)
    {

      if (!vcl_flag_accepted_session (session, reset_msg->handle,
				      VCL_ACCEPTED_F_RESET))
	VDBG (0, "session was not accepted!");
      return VCL_INVALID_SESSION_INDEX;
    }

  session->session_state = STATE_DISCONNECT;
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
      VERR ("vpp handle 0x%llx, sid %u: bind failed: %U", mp->handle, sid,
	    format_api_error, mp->retval);
      if (session)
	{
	  session->session_state = STATE_FAILED;
	  session->vpp_handle = mp->handle;
	  return sid;
	}
      else
	{
	  clib_warning ("[%s] ERROR: vpp handle 0x%llx, sid %u: "
			"Invalid session index (%u)!",
			getpid (), mp->handle, sid);
	  return VCL_INVALID_SESSION_INDEX;
	}
    }

  session->vpp_handle = mp->handle;
  session->transport.is_ip4 = mp->lcl_is_ip4;
  clib_memcpy_fast (&session->transport.lcl_ip, mp->lcl_ip,
		    sizeof (ip46_address_t));
  session->transport.lcl_port = mp->lcl_port;
  vcl_session_table_add_listener (wrk, mp->handle, sid);
  session->session_state = STATE_LISTEN;

  if (session->is_dgram)
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

  /* Caught a disconnect before actually accepting the session */
  if (session->session_state == STATE_LISTEN)
    {
      if (!vcl_flag_accepted_session (session, msg->handle,
				      VCL_ACCEPTED_F_CLOSED))
	VDBG (0, "session was not accepted!");
      return 0;
    }

  session->session_state = STATE_VPP_CLOSING;
  return session;
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
  if (vcl_wait_for_segment (msg->segment_handle))
    {
      clib_warning ("segment for session %u couldn't be mounted!",
		    s->session_index);
      return;
    }
  s->rx_fifo = uword_to_pointer (msg->rx_fifo, svm_fifo_t *);
  s->tx_fifo = uword_to_pointer (msg->tx_fifo, svm_fifo_t *);

  s->rx_fifo->client_session_index = s->session_index;
  s->tx_fifo->client_session_index = s->session_index;
  s->rx_fifo->client_thread_index = wrk->wrk_index;
  s->tx_fifo->client_thread_index = wrk->wrk_index;
  s->session_state = STATE_UPDATED;

  if (s->shared_index != VCL_INVALID_SESSION_INDEX)
    {
      vcl_shared_session_t *ss;
      ss = vcl_shared_session_get (s->shared_index);
      if (vec_len (ss->workers) > 1)
	VDBG (0, "workers need to be updated");
    }
  VDBG (0, "session %u[0x%llx] moved to worker %u", s->session_index,
	s->vpp_handle, wrk->wrk_index);
}

static int
vcl_handle_mq_event (vcl_worker_t * wrk, session_event_t * e)
{
  session_disconnected_msg_t *disconnected_msg;
  vcl_session_t *session;

  switch (e->event_type)
    {
    case FIFO_EVENT_APP_RX:
    case FIFO_EVENT_APP_TX:
    case SESSION_IO_EVT_CT_RX:
    case SESSION_IO_EVT_CT_TX:
      vec_add1 (wrk->unhandled_evts_vector, *e);
      break;
    case SESSION_CTRL_EVT_ACCEPTED:
      vcl_session_accepted (wrk, (session_accepted_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_CONNECTED:
      vcl_session_connected_handler (wrk,
				     (session_connected_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_DISCONNECTED:
      disconnected_msg = (session_disconnected_msg_t *) e->data;
      session = vcl_session_disconnected_handler (wrk, disconnected_msg);
      if (!session)
	break;
      session->session_state = STATE_DISCONNECT;
      VDBG (0, "disconnected session %u [0x%llx]", session->session_index,
	    session->vpp_handle);
      break;
    case SESSION_CTRL_EVT_RESET:
      vcl_session_reset_handler (wrk, (session_reset_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_BOUND:
      vcl_session_bound_handler (wrk, (session_bound_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_REQ_WORKER_UPDATE:
      vcl_session_req_worker_update_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_WORKER_UPDATE_REPLY:
      vcl_session_worker_update_reply_handler (wrk, e->data);
      break;
    default:
      clib_warning ("unhandled %u", e->event_type);
    }
  return VPPCOM_OK;
}

static int
vppcom_wait_for_session_state_change (u32 session_index,
				      session_state_t state,
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
      if (session->session_state & state)
	{
	  return VPPCOM_OK;
	}
      if (session->session_state & STATE_FAILED)
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
  session_state_t state;
  vcl_session_t *s;
  u32 *sip;

  if (PREDICT_TRUE (vec_len (wrk->pending_session_wrk_updates) == 0))
    return;

  vec_foreach (sip, wrk->pending_session_wrk_updates)
  {
    s = vcl_session_get (wrk, *sip);
    vcl_send_session_worker_update (wrk, s, wrk->wrk_index);
    state = s->session_state;
    vppcom_wait_for_session_state_change (s->session_index, STATE_UPDATED, 5);
    s->session_state = state;
  }
  vec_reset_length (wrk->pending_session_wrk_updates);
}

static void
vcl_flush_mq_events (void)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  svm_msg_q_msg_t *msg;
  session_event_t *e;
  svm_msg_q_t *mq;
  int i;

  mq = wrk->app_event_queue;
  svm_msg_q_lock (mq);
  vcl_mq_dequeue_batch (wrk, mq);
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
vppcom_app_session_enable (void)
{
  int rv;

  if (vcm->app_state != STATE_APP_ENABLED)
    {
      vppcom_send_session_enable_disable (1 /* is_enabled == TRUE */ );
      rv = vcl_wait_for_app_state_change (STATE_APP_ENABLED);
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
  rv = vcl_wait_for_app_state_change (STATE_APP_ATTACHED);
  if (PREDICT_FALSE (rv))
    {
      VDBG (0, "VCL<%d>: application attach timed out! returning %d (%s)",
	    getpid (), rv, vppcom_retval_str (rv));
      return rv;
    }

  return VPPCOM_OK;
}

static int
vppcom_session_unbind (u32 session_handle)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session = 0;
  u64 vpp_handle;

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;

  vpp_handle = session->vpp_handle;
  vcl_session_table_del_listener (wrk, vpp_handle);
  session->vpp_handle = ~0;
  session->session_state = STATE_DISCONNECT;

  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: sending unbind msg! new state"
	" 0x%x (%s)", getpid (), vpp_handle, session_handle, STATE_DISCONNECT,
	vppcom_session_state_str (STATE_DISCONNECT));
  vcl_evt (VCL_EVT_UNBIND, session);
  vppcom_send_unbind_sock (vpp_handle);

  return VPPCOM_OK;
}

static int
vppcom_session_disconnect (u32 session_handle)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  svm_msg_q_t *vpp_evt_q;
  vcl_session_t *session;
  session_state_t state;
  u64 vpp_handle;

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;

  vpp_handle = session->vpp_handle;
  state = session->session_state;

  VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u state 0x%x (%s)", getpid (),
	vpp_handle, session_handle, state, vppcom_session_state_str (state));

  if (PREDICT_FALSE (state & STATE_LISTEN))
    {
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "Cannot disconnect a listen socket!",
		    getpid (), vpp_handle, session_handle);
      return VPPCOM_EBADFD;
    }

  if (state & STATE_VPP_CLOSING)
    {
      vpp_evt_q = vcl_session_vpp_evt_q (wrk, session);
      vcl_send_session_disconnected_reply (vpp_evt_q, wrk->my_client_index,
					   vpp_handle, 0);
      VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: sending disconnect "
	    "REPLY...", getpid (), vpp_handle, session_handle);
    }
  else
    {
      VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: sending disconnect...",
	    getpid (), vpp_handle, session_handle);
      vppcom_send_disconnect_session (vpp_handle);
    }

  return VPPCOM_OK;
}

static void
vcl_cleanup_bapi (void)
{
  socket_client_main_t *scm = &socket_client_main;
  api_main_t *am = &api_main;

  am->my_client_index = ~0;
  am->my_registration = 0;
  am->vl_input_queue = 0;
  am->msg_index_by_name_and_crc = 0;
  scm->socket_fd = 0;

  vl_client_api_unmap ();
}

static void
vcl_cleanup_forked_child (vcl_worker_t * wrk, vcl_worker_t * child_wrk)
{
  vcl_worker_t *sub_child;
  int tries = 0;

  if (child_wrk->forked_child != ~0)
    {
      sub_child = vcl_worker_get_if_valid (child_wrk->forked_child);
      if (sub_child)
	{
	  /* Wait a bit, maybe the process is going away */
	  while (kill (sub_child->current_pid, 0) >= 0 && tries++ < 50)
	    usleep (1e3);
	  if (kill (sub_child->current_pid, 0) < 0)
	    vcl_cleanup_forked_child (child_wrk, sub_child);
	}
    }
  vcl_worker_cleanup (child_wrk, 1 /* notify vpp */ );
  VDBG (0, "Cleaned up wrk %u", child_wrk->wrk_index);
  wrk->forked_child = ~0;
}

static struct sigaction old_sa;

static void
vcl_intercept_sigchld_handler (int signum, siginfo_t * si, void *uc)
{
  vcl_worker_t *wrk, *child_wrk;

  if (vcl_get_worker_index () == ~0)
    return;

  if (sigaction (SIGCHLD, &old_sa, 0))
    {
      VERR ("couldn't restore sigchld");
      exit (-1);
    }

  wrk = vcl_worker_get_current ();
  if (wrk->forked_child == ~0)
    return;

  child_wrk = vcl_worker_get_if_valid (wrk->forked_child);
  if (!child_wrk)
    goto done;

  if (si && si->si_pid != child_wrk->current_pid)
    {
      VDBG (0, "unexpected child pid %u", si->si_pid);
      goto done;
    }
  vcl_cleanup_forked_child (wrk, child_wrk);

done:
  if (old_sa.sa_flags & SA_SIGINFO)
    {
      void (*fn) (int, siginfo_t *, void *) = old_sa.sa_sigaction;
      fn (signum, si, uc);
    }
  else
    {
      void (*fn) (int) = old_sa.sa_handler;
      if (fn)
	fn (signum);
    }
}

static void
vcl_incercept_sigchld ()
{
  struct sigaction sa;
  clib_memset (&sa, 0, sizeof (sa));
  sa.sa_sigaction = vcl_intercept_sigchld_handler;
  sa.sa_flags = SA_SIGINFO;
  if (sigaction (SIGCHLD, &sa, &old_sa))
    {
      VERR ("couldn't intercept sigchld");
      exit (-1);
    }
}

static void
vcl_app_pre_fork (void)
{
  vcl_incercept_sigchld ();
  vcl_flush_mq_events ();
}

static void
vcl_app_fork_child_handler (void)
{
  vcl_worker_t *parent_wrk, *wrk;
  int rv, parent_wrk_index;
  u8 *child_name;

  parent_wrk_index = vcl_get_worker_index ();
  VDBG (0, "initializing forked child with parent wrk %u", parent_wrk_index);

  /*
   * Allocate worker
   */
  vcl_set_worker_index (~0);
  if (!vcl_worker_alloc_and_init ())
    VERR ("couldn't allocate new worker");

  /*
   * Attach to binary api
   */
  child_name = format (0, "%v-child-%u%c", vcm->app_name, getpid (), 0);
  vcl_cleanup_bapi ();
  vppcom_api_hookup ();
  vcm->app_state = STATE_APP_START;
  rv = vppcom_connect_to_vpp ((char *) child_name);
  vec_free (child_name);
  if (rv)
    {
      VERR ("couldn't connect to VPP!");
      return;
    }

  /*
   * Register worker with vpp and share sessions
   */
  vcl_worker_register_with_vpp ();
  parent_wrk = vcl_worker_get (parent_wrk_index);
  wrk = vcl_worker_get_current ();
  wrk->vpp_event_queues = vec_dup (parent_wrk->vpp_event_queues);
  vcl_worker_share_sessions (parent_wrk);
  parent_wrk->forked_child = vcl_get_worker_index ();

  VDBG (0, "forked child main worker initialized");
  vcm->forking = 0;
}

static void
vcl_app_fork_parent_handler (void)
{
  vcm->forking = 1;
  while (vcm->forking)
    ;
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
  if (vec_len (vcm->workers) == 1)
    vl_client_disconnect_from_vlib ();
  else
    vl_client_send_disconnect (1 /* vpp should cleanup */ );
}

/*
 * VPPCOM Public API functions
 */
int
vppcom_app_create (char *app_name)
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
  vppcom_init_error_string_table ();
  svm_fifo_segment_main_init (&vcm->segment_main, vcl_cfg->segment_baseva,
			      20 /* timeout in secs */ );
  pool_alloc (vcm->workers, vcl_cfg->max_workers);
  clib_spinlock_init (&vcm->workers_lock);
  clib_rwlock_init (&vcm->segment_table_lock);
  pthread_atfork (vcl_app_pre_fork, vcl_app_fork_parent_handler,
		  vcl_app_fork_child_handler);
  atexit (vppcom_app_exit);

  /* Allocate default worker */
  vcl_worker_alloc_and_init ();

  /* API hookup and connect to VPP */
  vppcom_api_hookup ();
  vcl_elog_init (vcm);
  vcm->app_state = STATE_APP_START;
  rv = vppcom_connect_to_vpp (app_name);
  if (rv)
    {
      VERR ("couldn't connect to VPP!");
      return rv;
    }
  VDBG (0, "sending session enable");
  rv = vppcom_app_session_enable ();
  if (rv)
    {
      VERR ("vppcom_app_session_enable() failed!");
      return rv;
    }

  VDBG (0, "sending app attach");
  rv = vppcom_app_attach ();
  if (rv)
    {
      VERR ("vppcom_app_attach() failed!");
      return rv;
    }

  VDBG (0, "app_name '%s', my_client_index %d (0x%x)", app_name,
	vcm->workers[0].my_client_index, vcm->workers[0].my_client_index);

  vls_init ();
  return VPPCOM_OK;
}

void
vppcom_app_destroy (void)
{
  int rv;
  f64 orig_app_timeout;

  if (!pool_elts (vcm->workers))
    return;

  vcl_evt (VCL_EVT_DETACH, vcm);

  if (pool_elts (vcm->workers) == 1)
    {
      vppcom_app_send_detach ();
      orig_app_timeout = vcm->cfg.app_timeout;
      vcm->cfg.app_timeout = 2.0;
      rv = vcl_wait_for_app_state_change (STATE_APP_ENABLED);
      vcm->cfg.app_timeout = orig_app_timeout;
      if (PREDICT_FALSE (rv))
	VDBG (0, "application detach timed out! returning %d (%s)", rv,
	      vppcom_retval_str (rv));
      vec_free (vcm->app_name);
      vcl_worker_cleanup (vcl_worker_get_current (), 0 /* notify vpp */ );
    }
  else
    {
      vcl_worker_cleanup (vcl_worker_get_current (), 1 /* notify vpp */ );
    }

  vcl_set_worker_index (~0);
  vcl_elog_stop (vcm);
  vl_client_disconnect_from_vlib ();
}

int
vppcom_session_create (u8 proto, u8 is_nonblocking)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session;

  session = vcl_session_alloc (wrk);

  session->session_type = proto;
  session->session_state = STATE_START;
  session->vpp_handle = ~0;
  session->is_dgram = proto == VPPCOM_PROTO_UDP;

  if (is_nonblocking)
    VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_NONBLOCK);

  vcl_evt (VCL_EVT_CREATE, session, session_type, session->session_state,
	   is_nonblocking, session_index);

  VDBG (0, "created sid %u", session->session_index);

  return vcl_session_handle (session);
}

int
vppcom_session_close (uint32_t session_handle)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  u8 is_vep, do_disconnect = 1;
  vcl_session_t *session = 0;
  session_state_t state;
  u32 next_sh, vep_sh;
  int rv = VPPCOM_OK;
  u64 vpp_handle;

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;

  if (session->shared_index != ~0)
    do_disconnect = vcl_worker_unshare_session (wrk, session);

  is_vep = session->is_vep;
  next_sh = session->vep.next_sh;
  vep_sh = session->vep.vep_sh;
  state = session->session_state;
  vpp_handle = session->vpp_handle;

  VDBG (1, "closing session handle %u vpp handle %u", session_handle,
	vpp_handle);

  if (is_vep)
    {
      while (next_sh != ~0)
	{
	  rv = vppcom_epoll_ctl (session_handle, EPOLL_CTL_DEL, next_sh, 0);
	  if (PREDICT_FALSE (rv < 0))
	    VDBG (0, "vpp handle 0x%llx, sid %u: EPOLL_CTL_DEL vep_idx %u"
		  " failed! rv %d (%s)", vpp_handle, next_sh, vep_sh, rv,
		  vppcom_retval_str (rv));

	  next_sh = session->vep.next_sh;
	}
    }
  else
    {
      if (session->is_vep_session)
	{
	  rv = vppcom_epoll_ctl (vep_sh, EPOLL_CTL_DEL, session_handle, 0);
	  if (rv < 0)
	    VDBG (0, "vpp handle 0x%llx, sid %u: EPOLL_CTL_DEL vep_idx %u "
		  "failed! rv %d (%s)", vpp_handle, session_handle, vep_sh,
		  rv, vppcom_retval_str (rv));
	}

      if (!do_disconnect)
	{
	  VDBG (0, "session handle %u [0x%llx] disconnect skipped",
		session_handle, vpp_handle);
	  goto cleanup;
	}

      if (state & STATE_LISTEN)
	{
	  rv = vppcom_session_unbind (session_handle);
	  if (PREDICT_FALSE (rv < 0))
	    VDBG (0, "vpp handle 0x%llx, sid %u: listener unbind failed! "
		  "rv %d (%s)", vpp_handle, session_handle, rv,
		  vppcom_retval_str (rv));
	}
      else if (state & STATE_OPEN)
	{
	  rv = vppcom_session_disconnect (session_handle);
	  if (PREDICT_FALSE (rv < 0))
	    clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
			  "session disconnect failed! rv %d (%s)",
			  getpid (), vpp_handle, session_handle,
			  rv, vppcom_retval_str (rv));
	}
      else if (state == STATE_DISCONNECT)
	{
	  svm_msg_q_t *mq = vcl_session_vpp_evt_q (wrk, session);
	  vcl_send_session_reset_reply (mq, wrk->my_client_index,
					session->vpp_handle, 0);
	}
    }

cleanup:

  if (vcl_session_is_ct (session))
    {
      vcl_cut_through_registration_t *ctr;
      uword mq_addr;

      mq_addr = pointer_to_uword (session->our_evt_q);
      ctr = vcl_ct_registration_lock_and_lookup (wrk, mq_addr);
      ASSERT (ctr);
      if (ctr->epoll_evt_conn_index != ~0)
	vcl_mq_epoll_del_evfd (wrk, ctr->epoll_evt_conn_index);
      VDBG (0, "Removing ct registration %u",
	    vcl_ct_registration_index (wrk, ctr));
      vcl_ct_registration_del (wrk, ctr);
      vcl_ct_registration_lookup_del (wrk, mq_addr);
      vcl_ct_registration_unlock (wrk);
    }

  vcl_session_table_del_vpp_handle (wrk, vpp_handle);
  vcl_session_free (wrk, session);

  VDBG (0, "session handle %u [0x%llx] removed", session_handle, vpp_handle);

  vcl_evt (VCL_EVT_CLOSE, session, rv);

  return rv;
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

  if (session->is_vep)
    {
      clib_warning ("VCL<%d>: ERROR: sid %u: cannot "
		    "bind to an epoll session!", getpid (), session_handle);
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

  VDBG (0, "VCL<%d>: sid %u: binding to local %s address %U port %u, "
	"proto %s", getpid (), session_handle,
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
  if (!listen_session || listen_session->is_vep)
    return VPPCOM_EBADFD;

  if (q_len == 0 || q_len == ~0)
    q_len = vcm->cfg.listen_queue_size;

  listen_vpp_handle = listen_session->vpp_handle;
  if (listen_session->session_state & STATE_LISTEN)
    {
      VDBG (0, "session %u [0x%llx]: already in listen state!",
	    listen_sh, listen_vpp_handle);
      return VPPCOM_OK;
    }

  VDBG (0, "session %u [0x%llx]: sending vpp listen request...",
	listen_sh, listen_vpp_handle);

  /*
   * Send listen request to vpp and wait for reply
   */
  vppcom_send_bind_sock (listen_session);
  rv = vppcom_wait_for_session_state_change (listen_session->session_index,
					     STATE_LISTEN,
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

int
vppcom_session_tls_add_cert (uint32_t session_handle, char *cert,
			     uint32_t cert_len)
{

  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session = 0;

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;

  if (cert_len == 0 || cert_len == ~0)
    return VPPCOM_EBADFD;

  /*
   * Send listen request to vpp and wait for reply
   */
  vppcom_send_application_tls_cert_add (session, cert, cert_len);

  return VPPCOM_OK;

}

int
vppcom_session_tls_add_key (uint32_t session_handle, char *key,
			    uint32_t key_len)
{

  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session = 0;

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (!session)
    return VPPCOM_EBADFD;

  if (key_len == 0 || key_len == ~0)
    return VPPCOM_EBADFD;

  /*
   * Send listen request to vpp and wait for reply
   */
  vppcom_send_application_tls_key_add (session, key, key_len);

  return VPPCOM_OK;


}

static int
validate_args_session_accept_ (vcl_worker_t * wrk,
			       vcl_session_t * listen_session)
{
  /* Input validation - expects spinlock on sessions_lockp */
  if (listen_session->is_vep)
    {
      clib_warning ("VCL<%d>: ERROR: sid %u: cannot accept on an "
		    "epoll session!", getpid (),
		    listen_session->session_index);
      return VPPCOM_EBADFD;
    }

  if (listen_session->session_state != STATE_LISTEN)
    {
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "not in listen state! state 0x%x (%s)", getpid (),
		    listen_session->vpp_handle, listen_session->session_index,
		    listen_session->session_state,
		    vppcom_session_state_str (listen_session->session_state));
      return VPPCOM_EBADFD;
    }
  return VPPCOM_OK;
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
  svm_msg_q_t *vpp_evt_q;
  vcl_session_msg_t *evt;
  u64 listen_vpp_handle;
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

  is_nonblocking = VCL_SESS_ATTR_TEST (listen_session->attr,
				       VCL_SESS_ATTR_NONBLOCK);
  if (svm_msg_q_is_empty (wrk->app_event_queue) && is_nonblocking)
    return VPPCOM_EAGAIN;

  while (1)
    {
      if (svm_msg_q_sub (wrk->app_event_queue, &msg, SVM_Q_WAIT, 0))
	return VPPCOM_EAGAIN;

      e = svm_msg_q_msg_data (wrk->app_event_queue, &msg);
      if (e->event_type != SESSION_CTRL_EVT_ACCEPTED)
	{
	  clib_warning ("discarded event: %u", e->event_type);
	  svm_msg_q_free_msg (wrk->app_event_queue, &msg);
	  continue;
	}
      clib_memcpy_fast (&accepted_msg, e->data, sizeof (accepted_msg));
      svm_msg_q_free_msg (wrk->app_event_queue, &msg);
      break;
    }

handle:

  client_session_index = vcl_session_accepted_handler (wrk, &accepted_msg);
  listen_session = vcl_session_get (wrk, listen_session_index);
  client_session = vcl_session_get (wrk, client_session_index);

  if (flags & O_NONBLOCK)
    VCL_SESS_ATTR_SET (client_session->attr, VCL_SESS_ATTR_NONBLOCK);

  listen_vpp_handle = listen_session->vpp_handle;
  VDBG (1, "vpp handle 0x%llx, sid %u: Got a client request! "
	"vpp handle 0x%llx, sid %u, flags %d, is_nonblocking %u",
	listen_vpp_handle, listen_session_handle,
	client_session->vpp_handle, client_session_index,
	flags, VCL_SESS_ATTR_TEST (client_session->attr,
				   VCL_SESS_ATTR_NONBLOCK));

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

  if (accepted_msg.server_event_queue_address)
    vpp_evt_q = uword_to_pointer (accepted_msg.vpp_event_queue_address,
				  svm_msg_q_t *);
  else
    vpp_evt_q = client_session->vpp_evt_q;

  vcl_send_session_accepted_reply (vpp_evt_q, client_session->client_context,
				   client_session->vpp_handle, 0);

  VDBG (0, "listener %u [0x%llx] accepted %u [0x%llx] peer: %U:%u "
	"local: %U:%u", listen_session_handle, listen_vpp_handle,
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
	client_session->session_state = STATE_VPP_CLOSING;
      else if (accept_flags & VCL_ACCEPTED_F_RESET)
	client_session->session_state = STATE_DISCONNECT;
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

  if (PREDICT_FALSE (session->is_vep))
    {
      clib_warning ("VCL<%d>: ERROR: sid %u: cannot "
		    "connect on an epoll session!", getpid (),
		    session_handle);
      return VPPCOM_EBADFD;
    }

  if (PREDICT_FALSE (session->session_state & CLIENT_STATE_OPEN))
    {
      VDBG (0, "session handle %u [0x%llx]: session already "
	    "connected to %s %U port %d proto %s, state 0x%x (%s)",
	    session_handle, session->vpp_handle,
	    session->transport.is_ip4 ? "IPv4" : "IPv6",
	    format_ip46_address,
	    &session->transport.rmt_ip, session->transport.is_ip4 ?
	    IP46_TYPE_IP4 : IP46_TYPE_IP6,
	    clib_net_to_host_u16 (session->transport.rmt_port),
	    vppcom_proto_str (session->session_type), session->session_state,
	    vppcom_session_state_str (session->session_state));
      return VPPCOM_OK;
    }

  session->transport.is_ip4 = server_ep->is_ip4;
  if (session->transport.is_ip4)
    clib_memcpy_fast (&session->transport.rmt_ip.ip4, server_ep->ip,
		      sizeof (ip4_address_t));
  else
    clib_memcpy_fast (&session->transport.rmt_ip.ip6, server_ep->ip,
		      sizeof (ip6_address_t));
  session->transport.rmt_port = server_ep->port;

  VDBG (0, "session handle %u [0x%llx]: connecting to server %s %U "
	"port %d proto %s", session_handle, session->vpp_handle,
	session->transport.is_ip4 ? "IPv4" : "IPv6",
	format_ip46_address,
	&session->transport.rmt_ip, session->transport.is_ip4 ?
	IP46_TYPE_IP4 : IP46_TYPE_IP6,
	clib_net_to_host_u16 (session->transport.rmt_port),
	vppcom_proto_str (session->session_type));

  /*
   * Send connect request and wait for reply from vpp
   */
  vppcom_send_connect_sock (session);
  rv = vppcom_wait_for_session_state_change (session_index, STATE_CONNECT,
					     vcm->cfg.session_timeout);

  session = vcl_session_get (wrk, session_index);

  if (PREDICT_FALSE (rv))
    {
      if (VPPCOM_DEBUG > 0)
	{
	  if (session)
	    clib_warning ("VCL<%d>: vpp handle 0x%llx, sid %u: connect "
			  "failed! returning %d (%s)", getpid (),
			  session->vpp_handle, session_handle, rv,
			  vppcom_retval_str (rv));
	  else
	    clib_warning ("VCL<%d>: no session for sid %u: connect failed! "
			  "returning %d (%s)", getpid (),
			  session_handle, rv, vppcom_retval_str (rv));
	}
    }
  else
    VDBG (0, "VCL<%d>: vpp handle 0x%llx, sid %u: connected!",
	  getpid (), session->vpp_handle, session_handle);

  return rv;
}

static u8
vcl_is_rx_evt_for_session (session_event_t * e, u32 sid, u8 is_ct)
{
  if (!is_ct)
    return (e->event_type == FIFO_EVENT_APP_RX
	    && e->fifo->client_session_index == sid);
  else
    return (e->event_type == SESSION_IO_EVT_CT_TX);
}

static inline u8
vcl_session_is_readable (vcl_session_t * s)
{
  return ((s->session_state & STATE_OPEN)
	  || (s->session_state == STATE_LISTEN
	      && s->session_type == VPPCOM_PROTO_UDP));
}

static inline int
vppcom_session_read_internal (uint32_t session_handle, void *buf, int n,
			      u8 peek)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  int n_read = 0, rv, is_nonblocking;
  vcl_session_t *s = 0;
  svm_fifo_t *rx_fifo;
  svm_msg_q_msg_t msg;
  session_event_t *e;
  svm_msg_q_t *mq;
  u8 is_ct;

  if (PREDICT_FALSE (!buf))
    return VPPCOM_EINVAL;

  s = vcl_session_get_w_handle (wrk, session_handle);
  if (PREDICT_FALSE (!s || s->is_vep))
    return VPPCOM_EBADFD;

  if (PREDICT_FALSE (!vcl_session_is_readable (s)))
    {
      session_state_t state = s->session_state;
      rv = ((state & STATE_DISCONNECT) ? VPPCOM_ECONNRESET : VPPCOM_ENOTCONN);

      VDBG (0, "session handle %u[0x%llx] is not open! state 0x%x (%s),"
	    " returning %d (%s)", session_handle, s->vpp_handle, state,
	    vppcom_session_state_str (state), rv, vppcom_retval_str (rv));
      return rv;
    }

  is_nonblocking = VCL_SESS_ATTR_TEST (s->attr, VCL_SESS_ATTR_NONBLOCK);
  is_ct = vcl_session_is_ct (s);
  mq = is_ct ? s->our_evt_q : wrk->app_event_queue;
  rx_fifo = s->rx_fifo;
  s->has_rx_evt = 0;

  if (svm_fifo_is_empty (rx_fifo))
    {
      if (is_nonblocking)
	{
	  svm_fifo_unset_event (rx_fifo);
	  return VPPCOM_EWOULDBLOCK;
	}
      while (svm_fifo_is_empty (rx_fifo))
	{
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

	  if (PREDICT_FALSE (s->session_state == STATE_DISCONNECT))
	    return VPPCOM_ECONNRESET;
	}
    }

  if (s->is_dgram)
    n_read = app_recv_dgram_raw (rx_fifo, buf, n, &s->transport, 0, peek);
  else
    n_read = app_recv_stream_raw (rx_fifo, buf, n, 0, peek);

  if (svm_fifo_is_empty (rx_fifo))
    svm_fifo_unset_event (rx_fifo);

  if (is_ct && svm_fifo_want_tx_evt (rx_fifo))
    {
      svm_fifo_set_want_tx_evt (s->rx_fifo, 0);
      app_send_io_evt_to_vpp (s->vpp_evt_q, s->rx_fifo, SESSION_IO_EVT_CT_RX,
			      SVM_Q_WAIT);
    }

  VDBG (2, "vpp handle 0x%llx, sid %u: read %d bytes from (%p)",
	s->vpp_handle, session_handle, n_read, rx_fifo);

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
			      vppcom_data_segments_t ds)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  int n_read = 0, rv, is_nonblocking;
  vcl_session_t *s = 0;
  svm_fifo_t *rx_fifo;
  svm_msg_q_msg_t msg;
  session_event_t *e;
  svm_msg_q_t *mq;
  u8 is_ct;

  s = vcl_session_get_w_handle (wrk, session_handle);
  if (PREDICT_FALSE (!s || s->is_vep))
    return VPPCOM_EBADFD;

  if (PREDICT_FALSE (!vcl_session_is_readable (s)))
    {
      session_state_t state = s->session_state;
      rv = ((state & STATE_DISCONNECT) ? VPPCOM_ECONNRESET : VPPCOM_ENOTCONN);
      return rv;
    }

  is_nonblocking = VCL_SESS_ATTR_TEST (s->attr, VCL_SESS_ATTR_NONBLOCK);
  is_ct = vcl_session_is_ct (s);
  mq = is_ct ? s->our_evt_q : wrk->app_event_queue;
  rx_fifo = s->rx_fifo;
  s->has_rx_evt = 0;

  if (svm_fifo_is_empty (rx_fifo))
    {
      if (is_nonblocking)
	{
	  svm_fifo_unset_event (rx_fifo);
	  return VPPCOM_EWOULDBLOCK;
	}
      while (svm_fifo_is_empty (rx_fifo))
	{
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

	  if (PREDICT_FALSE (s->session_state == STATE_DISCONNECT))
	    return VPPCOM_ECONNRESET;
	}
    }

  n_read = svm_fifo_segments (rx_fifo, (svm_fifo_segment_t *) ds);
  svm_fifo_unset_event (rx_fifo);

  if (is_ct && n_read + svm_fifo_max_dequeue (rx_fifo) == rx_fifo->nitems)
    {
      /* If the peer is not polling send notification */
      if (!svm_fifo_has_event (s->rx_fifo))
	app_send_io_evt_to_vpp (s->vpp_evt_q, s->rx_fifo,
				SESSION_IO_EVT_CT_RX, SVM_Q_WAIT);
    }

  return n_read;
}

void
vppcom_session_free_segments (uint32_t session_handle,
			      vppcom_data_segments_t ds)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *s;

  s = vcl_session_get_w_handle (wrk, session_handle);
  if (PREDICT_FALSE (!s || s->is_vep))
    return;

  svm_fifo_segments_free (s->rx_fifo, (svm_fifo_segment_t *) ds);
}

static inline int
vppcom_session_read_ready (vcl_session_t * session)
{
  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  if (PREDICT_FALSE (session->is_vep))
    {
      clib_warning ("VCL<%d>: ERROR: sid %u: cannot read from an "
		    "epoll session!", getpid (), session->session_index);
      return VPPCOM_EBADFD;
    }

  if (PREDICT_FALSE (!(session->session_state & (STATE_OPEN | STATE_LISTEN))))
    {
      session_state_t state = session->session_state;
      int rv;

      rv = ((state & STATE_DISCONNECT) ? VPPCOM_ECONNRESET : VPPCOM_ENOTCONN);

      VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: session is not open!"
	    " state 0x%x (%s), returning %d (%s)", getpid (),
	    session->vpp_handle, session->session_index, state,
	    vppcom_session_state_str (state), rv, vppcom_retval_str (rv));
      return rv;
    }

  if (session->session_state & STATE_LISTEN)
    return clib_fifo_elts (session->accept_evts_fifo);

  return svm_fifo_max_dequeue (session->rx_fifo);
}

int
vppcom_data_segment_copy (void *buf, vppcom_data_segments_t ds, u32 max_bytes)
{
  u32 first_copy = clib_min (ds[0].len, max_bytes);
  clib_memcpy_fast (buf, ds[0].data, first_copy);
  if (first_copy < max_bytes)
    {
      clib_memcpy_fast (buf + first_copy, ds[1].data,
			clib_min (ds[1].len, max_bytes - first_copy));
    }
  return 0;
}

static u8
vcl_is_tx_evt_for_session (session_event_t * e, u32 sid, u8 is_ct)
{
  if (!is_ct)
    return (e->event_type == FIFO_EVENT_APP_TX
	    && e->fifo->client_session_index == sid);
  else
    return (e->event_type == SESSION_IO_EVT_CT_RX);
}

static inline int
vppcom_session_write_inline (uint32_t session_handle, void *buf, size_t n,
			     u8 is_flush)
{
  vcl_worker_t *wrk = vcl_worker_get_current ();
  int rv, n_write, is_nonblocking;
  vcl_session_t *s = 0;
  svm_fifo_t *tx_fifo = 0;
  session_evt_type_t et;
  svm_msg_q_msg_t msg;
  session_event_t *e;
  svm_msg_q_t *mq;
  u8 is_ct;

  if (PREDICT_FALSE (!buf))
    return VPPCOM_EINVAL;

  s = vcl_session_get_w_handle (wrk, session_handle);
  if (PREDICT_FALSE (!s))
    return VPPCOM_EBADFD;

  if (PREDICT_FALSE (s->is_vep))
    {
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "cannot write to an epoll session!",
		    getpid (), s->vpp_handle, session_handle);

      return VPPCOM_EBADFD;
    }

  if (PREDICT_FALSE (!(s->session_state & STATE_OPEN)))
    {
      session_state_t state = s->session_state;
      rv = ((state & STATE_DISCONNECT) ? VPPCOM_ECONNRESET : VPPCOM_ENOTCONN);
      VDBG (1, "VCL<%d>: vpp handle 0x%llx, sid %u: session is not open! "
	    "state 0x%x (%s)", getpid (), s->vpp_handle, session_handle,
	    state, vppcom_session_state_str (state));
      return rv;
    }

  tx_fifo = s->tx_fifo;
  is_ct = vcl_session_is_ct (s);
  is_nonblocking = VCL_SESS_ATTR_TEST (s->attr, VCL_SESS_ATTR_NONBLOCK);
  mq = is_ct ? s->our_evt_q : wrk->app_event_queue;
  if (svm_fifo_is_full (tx_fifo))
    {
      if (is_nonblocking)
	{
	  return VPPCOM_EWOULDBLOCK;
	}
      while (svm_fifo_is_full (tx_fifo))
	{
	  svm_fifo_set_want_tx_evt (tx_fifo, 1);
	  svm_msg_q_lock (mq);
	  if (svm_msg_q_is_empty (mq))
	    svm_msg_q_wait (mq);

	  svm_msg_q_sub_w_lock (mq, &msg);
	  e = svm_msg_q_msg_data (mq, &msg);
	  svm_msg_q_unlock (mq);

	  if (!vcl_is_tx_evt_for_session (e, s->session_index, is_ct))
	    vcl_handle_mq_event (wrk, e);
	  svm_msg_q_free_msg (mq, &msg);

	  if (PREDICT_FALSE (!(s->session_state & STATE_OPEN)))
	    return VPPCOM_ECONNRESET;
	}
    }

  ASSERT (FIFO_EVENT_APP_TX + 1 == SESSION_IO_EVT_CT_TX);
  et = FIFO_EVENT_APP_TX + vcl_session_is_ct (s);
  if (is_flush && !vcl_session_is_ct (s))
    et = SESSION_IO_EVT_TX_FLUSH;

  if (s->is_dgram)
    n_write = app_send_dgram_raw (tx_fifo, &s->transport,
				  s->vpp_evt_q, buf, n, et, SVM_Q_WAIT);
  else
    n_write = app_send_stream_raw (tx_fifo, s->vpp_evt_q, buf, n, et,
				   SVM_Q_WAIT);

  ASSERT (n_write > 0);

  VDBG (2, "VCL<%d>: vpp handle 0x%llx, sid %u: wrote %d bytes", getpid (),
	s->vpp_handle, session_handle, n_write);

  return n_write;
}

int
vppcom_session_write (uint32_t session_handle, void *buf, size_t n)
{
  return vppcom_session_write_inline (session_handle, buf, n,
				      0 /* is_flush */ );
}

int
vppcom_session_write_msg (uint32_t session_handle, void *buf, size_t n)
{
  return vppcom_session_write_inline (session_handle, buf, n,
				      1 /* is_flush */ );
}


static vcl_session_t *
vcl_ct_session_get_from_fifo (vcl_worker_t * wrk, svm_fifo_t * f, u8 type)
{
  vcl_session_t *s;
  s = vcl_session_get (wrk, f->client_session_index);
  if (s)
    {
      /* rx fifo */
      if (type == 0 && s->rx_fifo == f)
	return s;
      /* tx fifo */
      if (type == 1 && s->tx_fifo == f)
	return s;
    }
  s = vcl_session_get (wrk, f->master_session_index);
  if (s)
    {
      if (type == 0 && s->rx_fifo == f)
	return s;
      if (type == 1 && s->tx_fifo == f)
	return s;
    }
  return 0;
}

static inline int
vppcom_session_write_ready (vcl_session_t * session)
{
  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  if (PREDICT_FALSE (session->is_vep))
    {
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "cannot write to an epoll session!",
		    getpid (), session->vpp_handle, session->session_index);
      return VPPCOM_EBADFD;
    }

  if (PREDICT_FALSE (session->session_state & STATE_LISTEN))
    {
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "cannot write to a listen session!",
		    getpid (), session->vpp_handle, session->session_index);
      return VPPCOM_EBADFD;
    }

  if (PREDICT_FALSE (!(session->session_state & STATE_OPEN)))
    {
      session_state_t state = session->session_state;
      int rv;

      rv = ((state & STATE_DISCONNECT) ? VPPCOM_ECONNRESET : VPPCOM_ENOTCONN);
      clib_warning ("VCL<%d>: ERROR: vpp handle 0x%llx, sid %u: "
		    "session is not open! state 0x%x (%s), "
		    "returning %d (%s)", getpid (), session->vpp_handle,
		    session->session_index,
		    state, vppcom_session_state_str (state),
		    rv, vppcom_retval_str (rv));
      return rv;
    }

  VDBG (3, "VCL<%d>: vpp handle 0x%llx, sid %u: peek %s (%p), ready = %d",
	getpid (), session->vpp_handle, session->session_index,
	session->tx_fifo, svm_fifo_max_enqueue (session->tx_fifo));

  return svm_fifo_max_enqueue (session->tx_fifo);
}

#define vcl_fifo_rx_evt_valid_or_break(_fifo)			\
if (PREDICT_FALSE (svm_fifo_is_empty (_fifo)))			\
  {								\
    svm_fifo_unset_event (_fifo);				\
    if (svm_fifo_is_empty (_fifo))				\
      break;							\
  }								\

static void
vcl_select_handle_mq_event (vcl_worker_t * wrk, session_event_t * e,
			    unsigned long n_bits, unsigned long *read_map,
			    unsigned long *write_map,
			    unsigned long *except_map, u32 * bits_set)
{
  session_disconnected_msg_t *disconnected_msg;
  session_connected_msg_t *connected_msg;
  vcl_session_t *session;
  u32 sid;

  switch (e->event_type)
    {
    case FIFO_EVENT_APP_RX:
      vcl_fifo_rx_evt_valid_or_break (e->fifo);
      sid = e->fifo->client_session_index;
      session = vcl_session_get (wrk, sid);
      if (!session)
	break;
      if (sid < n_bits && read_map)
	{
	  clib_bitmap_set_no_check ((uword *) read_map, sid, 1);
	  *bits_set += 1;
	}
      break;
    case FIFO_EVENT_APP_TX:
      sid = e->fifo->client_session_index;
      session = vcl_session_get (wrk, sid);
      if (!session)
	break;
      if (sid < n_bits && write_map)
	{
	  clib_bitmap_set_no_check ((uword *) write_map, sid, 1);
	  *bits_set += 1;
	}
      break;
    case SESSION_IO_EVT_CT_TX:
      vcl_fifo_rx_evt_valid_or_break (e->fifo);
      session = vcl_ct_session_get_from_fifo (wrk, e->fifo, 0);
      if (!session)
	break;
      sid = session->session_index;
      if (sid < n_bits && read_map)
	{
	  clib_bitmap_set_no_check ((uword *) read_map, sid, 1);
	  *bits_set += 1;
	}
      break;
    case SESSION_IO_EVT_CT_RX:
      session = vcl_ct_session_get_from_fifo (wrk, e->fifo, 1);
      if (!session)
	break;
      sid = session->session_index;
      if (sid < n_bits && write_map)
	{
	  clib_bitmap_set_no_check ((uword *) write_map, sid, 1);
	  *bits_set += 1;
	}
      break;
    case SESSION_CTRL_EVT_ACCEPTED:
      session = vcl_session_accepted (wrk,
				      (session_accepted_msg_t *) e->data);
      if (!session)
	break;
      sid = session->session_index;
      if (sid < n_bits && read_map)
	{
	  clib_bitmap_set_no_check ((uword *) read_map, sid, 1);
	  *bits_set += 1;
	}
      break;
    case SESSION_CTRL_EVT_CONNECTED:
      connected_msg = (session_connected_msg_t *) e->data;
      vcl_session_connected_handler (wrk, connected_msg);
      break;
    case SESSION_CTRL_EVT_DISCONNECTED:
      disconnected_msg = (session_disconnected_msg_t *) e->data;
      session = vcl_session_disconnected_handler (wrk, disconnected_msg);
      if (!session)
	break;
      sid = session->session_index;
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
    case SESSION_CTRL_EVT_WORKER_UPDATE_REPLY:
      vcl_session_worker_update_reply_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_REQ_WORKER_UPDATE:
      vcl_session_req_worker_update_handler (wrk, e->data);
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
  vcl_mq_dequeue_batch (wrk, mq);
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
vppcom_select_condvar (vcl_worker_t * wrk, unsigned long n_bits,
		       unsigned long *read_map, unsigned long *write_map,
		       unsigned long *except_map, double time_to_wait,
		       u32 * bits_set)
{
  double total_wait = 0, wait_slice;
  vcl_cut_through_registration_t *cr;

  time_to_wait = (time_to_wait == -1) ? 10e9 : time_to_wait;
  wait_slice = wrk->cut_through_registrations ? 10e-6 : time_to_wait;
  do
    {
      vcl_ct_registration_lock (wrk);
      /* *INDENT-OFF* */
      pool_foreach (cr, wrk->cut_through_registrations, ({
	vcl_select_handle_mq (wrk, cr->mq, n_bits, read_map, write_map, except_map,
	                      0, bits_set);
      }));
      /* *INDENT-ON* */
      vcl_ct_registration_unlock (wrk);

      vcl_select_handle_mq (wrk, wrk->app_event_queue, n_bits, read_map,
			    write_map, except_map, time_to_wait, bits_set);
      total_wait += wait_slice;
      if (*bits_set)
	return *bits_set;
    }
  while (total_wait < time_to_wait);

  return 0;
}

static int
vppcom_select_eventfd (vcl_worker_t * wrk, unsigned long n_bits,
		       unsigned long *read_map, unsigned long *write_map,
		       unsigned long *except_map, double time_to_wait,
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
vppcom_select (unsigned long n_bits, unsigned long *read_map,
	       unsigned long *write_map, unsigned long *except_map,
	       double time_to_wait)
{
  u32 sid, minbits = clib_max (n_bits, BITS (uword)), bits_set = 0;
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *session = 0;
  int rv, i;

  STATIC_ASSERT (sizeof (clib_bitmap_t) == sizeof (unsigned long),
		 "vppcom bitmap size mismatch");
  STATIC_ASSERT (sizeof (clib_bitmap_t) == sizeof (fd_mask),
		 "vppcom bitmap size mismatch");
  STATIC_ASSERT (sizeof (clib_bitmap_t) == sizeof (uword),
		 "vppcom bitmap size mismatch");

  if (n_bits && read_map)
    {
      clib_bitmap_validate (wrk->rd_bitmap, minbits);
      clib_memcpy_fast (wrk->rd_bitmap, read_map,
			vec_len (wrk->rd_bitmap) * sizeof (unsigned long));
      memset (read_map, 0, vec_len (wrk->rd_bitmap) * sizeof (unsigned long));
    }
  if (n_bits && write_map)
    {
      clib_bitmap_validate (wrk->wr_bitmap, minbits);
      clib_memcpy_fast (wrk->wr_bitmap, write_map,
			vec_len (wrk->wr_bitmap) * sizeof (unsigned long));
      memset (write_map, 0,
	      vec_len (wrk->wr_bitmap) * sizeof (unsigned long));
    }
  if (n_bits && except_map)
    {
      clib_bitmap_validate (wrk->ex_bitmap, minbits);
      clib_memcpy_fast (wrk->ex_bitmap, except_map,
			vec_len (wrk->ex_bitmap) * sizeof (unsigned long));
      memset (except_map, 0,
	      vec_len (wrk->ex_bitmap) * sizeof (unsigned long));
    }

  if (!n_bits)
    return 0;

  if (!write_map)
    goto check_rd;

  /* *INDENT-OFF* */
  clib_bitmap_foreach (sid, wrk->wr_bitmap, ({
    if (!(session = vcl_session_get (wrk, sid)))
      {
        if (except_map && sid < minbits)
          clib_bitmap_set_no_check (except_map, sid, 1);
        continue;
      }

    rv = svm_fifo_is_full (session->tx_fifo);
    if (!rv)
      {
        clib_bitmap_set_no_check ((uword*)write_map, sid, 1);
        bits_set++;
      }
  }));

check_rd:
  if (!read_map)
    goto check_mq;

  clib_bitmap_foreach (sid, wrk->rd_bitmap, ({
    if (!(session = vcl_session_get (wrk, sid)))
      {
        if (except_map && sid < minbits)
          clib_bitmap_set_no_check (except_map, sid, 1);
        continue;
      }

    rv = vppcom_session_read_ready (session);
    if (rv)
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
vep_verify_epoll_chain (vcl_worker_t * wrk, u32 vep_idx)
{
  vcl_session_t *session;
  vppcom_epoll_t *vep;
  u32 sid = vep_idx;

  if (VPPCOM_DEBUG <= 1)
    return;

  /* Assumes caller has acquired spinlock: vcm->sessions_lockp */
  session = vcl_session_get (wrk, vep_idx);
  if (PREDICT_FALSE (!session))
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
		vep->next_sh, vep->next_sh,
		session->wait_cont_idx, session->wait_cont_idx);

  for (sid = vep->next_sh; sid != ~0; sid = vep->next_sh)
    {
      session = vcl_session_get (wrk, sid);
      if (PREDICT_FALSE (!session))
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
      if (PREDICT_FALSE (vep->vep_sh != vep_idx))
	clib_warning ("VCL<%d>: ERROR: session (%u) vep_idx (%u) != "
		      "vep_idx (%u)!", getpid (),
		      sid, session->vep.vep_sh, vep_idx);
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
			vep->next_sh, vep->next_sh,
			vep->prev_sh, vep->prev_sh,
			vep->vep_sh, vep->vep_sh,
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
  vcl_worker_t *wrk = vcl_worker_get_current ();
  vcl_session_t *vep_session;

  vep_session = vcl_session_alloc (wrk);

  vep_session->is_vep = 1;
  vep_session->vep.vep_sh = ~0;
  vep_session->vep.next_sh = ~0;
  vep_session->vep.prev_sh = ~0;
  vep_session->wait_cont_idx = ~0;
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
  vcl_session_t *session;
  int rv = VPPCOM_OK;

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
  if (PREDICT_FALSE (!vep_session->is_vep))
    {
      VDBG (0, "vep_sh (%u) is not a vep!", vep_handle);
      return VPPCOM_EINVAL;
    }

  ASSERT (vep_session->vep.vep_sh == ~0);
  ASSERT (vep_session->vep.prev_sh == ~0);

  session = vcl_session_get_w_handle (wrk, session_handle);
  if (PREDICT_FALSE (!session))
    {
      VDBG (0, "Invalid session_handle (%u)!", session_handle);
      return VPPCOM_EBADFD;
    }
  if (PREDICT_FALSE (session->is_vep))
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
	      VDBG (0, "EPOLL_CTL_ADD: Invalid vep.next_sid (%u) on "
		    "vep_idx (%u)!", vep_session->vep.next_sh, vep_handle);
	      return VPPCOM_EBADFD;
	    }
	  ASSERT (next_session->vep.prev_sh == vep_handle);
	  next_session->vep.prev_sh = session_handle;
	}
      session->vep.next_sh = vep_session->vep.next_sh;
      session->vep.prev_sh = vep_handle;
      session->vep.vep_sh = vep_handle;
      session->vep.et_mask = VEP_DEFAULT_ET_MASK;
      session->vep.ev = *event;
      session->is_vep = 0;
      session->is_vep_session = 1;
      vep_session->vep.next_sh = session_handle;

      VDBG (1, "EPOLL_CTL_ADD: vep_sh %u, sh %u, events 0x%x, data 0x%llx!",
	    vep_handle, session_handle, event->events, event->data.u64);
      vcl_evt (VCL_EVT_EPOLL_CTLADD, session, event->events, event->data.u64);
      break;

    case EPOLL_CTL_MOD:
      if (PREDICT_FALSE (!event))
	{
	  VDBG (0, "EPOLL_CTL_MOD: NULL pointer to epoll_event structure!");
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      else if (PREDICT_FALSE (!session->is_vep_session))
	{
	  VDBG (0, "sid %u EPOLL_CTL_MOD: not a vep session!",
		session_handle);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      else if (PREDICT_FALSE (session->vep.vep_sh != vep_handle))
	{
	  VDBG (0, "EPOLL_CTL_MOD: sh %u vep_sh (%u) != vep_sh (%u)!",
		session_handle, session->vep.vep_sh, vep_handle);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      session->vep.et_mask = VEP_DEFAULT_ET_MASK;
      session->vep.ev = *event;
      VDBG (1, "EPOLL_CTL_MOD: vep_sh %u, sh %u, events 0x%x, data 0x%llx!",
	    vep_handle, session_handle, event->events, event->data.u64);
      break;

    case EPOLL_CTL_DEL:
      if (PREDICT_FALSE (!session->is_vep_session))
	{
	  VDBG (0, "EPOLL_CTL_DEL: %u not a vep session!", session_handle);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}
      else if (PREDICT_FALSE (session->vep.vep_sh != vep_handle))
	{
	  VDBG (0, "EPOLL_CTL_DEL: sh %u vep_sh (%u) != vep_sh (%u)!",
		session_handle, session->vep.vep_sh, vep_handle);
	  rv = VPPCOM_EINVAL;
	  goto done;
	}

      vep_session->wait_cont_idx =
	(vep_session->wait_cont_idx == session_handle) ?
	session->vep.next_sh : vep_session->wait_cont_idx;

      if (session->vep.prev_sh == vep_handle)
	vep_session->vep.next_sh = session->vep.next_sh;
      else
	{
	  vcl_session_t *prev_session;
	  prev_session = vcl_session_get_w_handle (wrk, session->vep.prev_sh);
	  if (PREDICT_FALSE (!prev_session))
	    {
	      VDBG (0, "EPOLL_CTL_DEL: Invalid prev_sid (%u) on sid (%u)!",
		    session->vep.prev_sh, session_handle);
	      return VPPCOM_EBADFD;
	    }
	  ASSERT (prev_session->vep.next_sh == session_handle);
	  prev_session->vep.next_sh = session->vep.next_sh;
	}
      if (session->vep.next_sh != ~0)
	{
	  vcl_session_t *next_session;
	  next_session = vcl_session_get_w_handle (wrk, session->vep.next_sh);
	  if (PREDICT_FALSE (!next_session))
	    {
	      VDBG (0, "EPOLL_CTL_DEL: Invalid next_sid (%u) on sid (%u)!",
		    session->vep.next_sh, session_handle);
	      return VPPCOM_EBADFD;
	    }
	  ASSERT (next_session->vep.prev_sh == session_handle);
	  next_session->vep.prev_sh = session->vep.prev_sh;
	}

      memset (&session->vep, 0, sizeof (session->vep));
      session->vep.next_sh = ~0;
      session->vep.prev_sh = ~0;
      session->vep.vep_sh = ~0;
      session->is_vep_session = 0;
      VDBG (1, "EPOLL_CTL_DEL: vep_idx %u, sid %u!", vep_handle,
	    session_handle);
      vcl_evt (VCL_EVT_EPOLL_CTLDEL, session, vep_sh);
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
  vcl_session_t *session;
  u8 add_event = 0;

  switch (e->event_type)
    {
    case FIFO_EVENT_APP_RX:
      ASSERT (e->fifo->client_thread_index == vcl_get_worker_index ());
      vcl_fifo_rx_evt_valid_or_break (e->fifo);
      sid = e->fifo->client_session_index;
      if (!(session = vcl_session_get (wrk, sid)))
	break;
      session_events = session->vep.ev.events;
      if (!(EPOLLIN & session->vep.ev.events) || session->has_rx_evt)
	break;
      add_event = 1;
      events[*num_ev].events |= EPOLLIN;
      session_evt_data = session->vep.ev.data.u64;
      session->has_rx_evt = 1;
      break;
    case FIFO_EVENT_APP_TX:
      sid = e->fifo->client_session_index;
      if (!(session = vcl_session_get (wrk, sid)))
	break;
      session_events = session->vep.ev.events;
      if (!(EPOLLOUT & session_events))
	break;
      add_event = 1;
      events[*num_ev].events |= EPOLLOUT;
      session_evt_data = session->vep.ev.data.u64;
      break;
    case SESSION_IO_EVT_CT_TX:
      vcl_fifo_rx_evt_valid_or_break (e->fifo);
      session = vcl_ct_session_get_from_fifo (wrk, e->fifo, 0);
      if (PREDICT_FALSE (!session))
	break;
      sid = session->session_index;
      session_events = session->vep.ev.events;
      if (!(EPOLLIN & session->vep.ev.events) || session->has_rx_evt)
	break;
      add_event = 1;
      events[*num_ev].events |= EPOLLIN;
      session_evt_data = session->vep.ev.data.u64;
      session->has_rx_evt = 1;
      break;
    case SESSION_IO_EVT_CT_RX:
      session = vcl_ct_session_get_from_fifo (wrk, e->fifo, 1);
      if (PREDICT_FALSE (!session))
	break;
      sid = session->session_index;
      session_events = session->vep.ev.events;
      if (!(EPOLLOUT & session_events))
	break;
      add_event = 1;
      events[*num_ev].events |= EPOLLOUT;
      session_evt_data = session->vep.ev.data.u64;
      break;
    case SESSION_CTRL_EVT_ACCEPTED:
      session = vcl_session_accepted (wrk,
				      (session_accepted_msg_t *) e->data);
      if (!session)
	break;

      session_events = session->vep.ev.events;
      if (!(EPOLLIN & session_events))
	break;

      add_event = 1;
      events[*num_ev].events |= EPOLLIN;
      session_evt_data = session->vep.ev.data.u64;
      break;
    case SESSION_CTRL_EVT_CONNECTED:
      connected_msg = (session_connected_msg_t *) e->data;
      vcl_session_connected_handler (wrk, connected_msg);
      /* Generate EPOLLOUT because there's no connected event */
      sid = vcl_session_index_from_vpp_handle (wrk, connected_msg->handle);
      if (!(session = vcl_session_get (wrk, sid)))
	break;
      session_events = session->vep.ev.events;
      if (EPOLLOUT & session_events)
	{
	  add_event = 1;
	  events[*num_ev].events |= EPOLLOUT;
	  session_evt_data = session->vep.ev.data.u64;
	}
      break;
    case SESSION_CTRL_EVT_DISCONNECTED:
      disconnected_msg = (session_disconnected_msg_t *) e->data;
      session = vcl_session_disconnected_handler (wrk, disconnected_msg);
      if (!session)
	break;
      add_event = 1;
      events[*num_ev].events |= EPOLLHUP | EPOLLRDHUP;
      session_evt_data = session->vep.ev.data.u64;
      session_events = session->vep.ev.events;
      break;
    case SESSION_CTRL_EVT_RESET:
      sid = vcl_session_reset_handler (wrk, (session_reset_msg_t *) e->data);
      if (!(session = vcl_session_get (wrk, sid)))
	break;
      add_event = 1;
      events[*num_ev].events |= EPOLLHUP | EPOLLRDHUP;
      session_evt_data = session->vep.ev.data.u64;
      session_events = session->vep.ev.events;
      break;
    case SESSION_CTRL_EVT_REQ_WORKER_UPDATE:
      vcl_session_req_worker_update_handler (wrk, e->data);
      break;
    case SESSION_CTRL_EVT_WORKER_UPDATE_REPLY:
      vcl_session_worker_update_reply_handler (wrk, e->data);
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
	  session = vcl_session_get (wrk, sid);
	  session->vep.ev.events = 0;
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
  vcl_mq_dequeue_batch (wrk, mq);
  svm_msg_q_unlock (mq);

handle_dequeued:
  for (i = 0; i < vec_len (wrk->mq_msg_vector); i++)
    {
      msg = vec_elt_at_index (wrk->mq_msg_vector, i);
      e = svm_msg_q_msg_data (mq, msg);
      if (*num_ev < maxevents)
	vcl_epoll_wait_handle_mq_event (wrk, e, events, num_ev);
      else
	vec_add1 (wrk->unhandled_evts_vector, *e);
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
  vcl_cut_through_registration_t *cr;
  double total_wait = 0, wait_slice;
  int rv;

  wait_for_time = (wait_for_time == -1) ? (double) 10e9 : wait_for_time;
  wait_slice = wrk->cut_through_registrations ? 10e-6 : wait_for_time;

  do
    {
      vcl_ct_registration_lock (wrk);
      /* *INDENT-OFF* */
      pool_foreach (cr, wrk->cut_through_registrations, ({
        vcl_epoll_wait_handle_mq (wrk, cr->mq, events, maxevents, 0, &n_evts);
      }));
      /* *INDENT-ON* */
      vcl_ct_registration_unlock (wrk);

      rv = vcl_epoll_wait_handle_mq (wrk, wrk->app_event_queue, events,
				     maxevents, n_evts ? 0 : wait_slice,
				     &n_evts);
      if (rv)
	total_wait += wait_slice;
      if (n_evts)
	return n_evts;
    }
  while (total_wait < wait_for_time);
  return n_evts;
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
      clib_warning ("VCL<%d>: ERROR: Invalid maxevents (%d)!",
		    getpid (), maxevents);
      return VPPCOM_EINVAL;
    }

  vep_session = vcl_session_get_w_handle (wrk, vep_handle);
  if (!vep_session)
    return VPPCOM_EBADFD;

  if (PREDICT_FALSE (!vep_session->is_vep))
    {
      clib_warning ("VCL<%d>: ERROR: vep_idx (%u) is not a vep!",
		    getpid (), vep_handle);
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
	      i += 1;
	      break;
	    }
	}

      vec_delete (wrk->unhandled_evts_vector, i, 0);
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
      rv = vppcom_session_read_ready (session);
      VDBG (2, "VPPCOM_ATTR_GET_NREAD: sid %u, nread = %d", rv);
      break;

    case VPPCOM_ATTR_GET_NWRITE:
      rv = vppcom_session_write_ready (session);
      VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_NWRITE: sid %u, nwrite = %d",
	    getpid (), session_handle, rv);
      break;

    case VPPCOM_ATTR_GET_FLAGS:
      if (PREDICT_TRUE (buffer && buflen && (*buflen >= sizeof (*flags))))
	{
	  *flags = O_RDWR | (VCL_SESS_ATTR_TEST (session->attr,
						 VCL_SESS_ATTR_NONBLOCK));
	  *buflen = sizeof (*flags);
	  VDBG (2, "VCL<%d>: VPPCOM_ATTR_GET_FLAGS: sid %u, flags = 0x%08x, "
		"is_nonblocking = %u", getpid (),
		session_handle, *flags,
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
		getpid (), session_handle, *flags,
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
	    clib_memcpy_fast (ep->ip, &session->transport.rmt_ip.ip4,
			      sizeof (ip4_address_t));
	  else
	    clib_memcpy_fast (ep->ip, &session->transport.rmt_ip.ip6,
			      sizeof (ip6_address_t));
	  *buflen = sizeof (*ep);
	  VDBG (1, "VCL<%d>: VPPCOM_ATTR_GET_PEER_ADDR: sid %u, is_ip4 = %u, "
		"addr = %U, port %u", getpid (),
		session_handle, ep->is_ip4, format_ip46_address,
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
	    clib_memcpy_fast (ep->ip, &session->transport.lcl_ip.ip4,
			      sizeof (ip4_address_t));
	  else
	    clib_memcpy_fast (ep->ip, &session->transport.lcl_ip.ip6,
			      sizeof (ip6_address_t));
	  *buflen = sizeof (*ep);
	  VDBG (1, "VCL<%d>: VPPCOM_ATTR_GET_LCL_ADDR: sid %u, is_ip4 = %u,"
		" addr = %U port %d", getpid (),
		session_handle, ep->is_ip4, format_ip46_address,
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

    case VPPCOM_ATTR_GET_REFCNT:
      rv = vcl_session_get_refcnt (session);
      break;

    case VPPCOM_ATTR_SET_SHUT:
      if (*flags == SHUT_RD || *flags == SHUT_RDWR)
	VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_SHUT_RD);
      if (*flags == SHUT_WR || *flags == SHUT_RDWR)
	VCL_SESS_ATTR_SET (session->attr, VCL_SESS_ATTR_SHUT_WR);
      break;

    case VPPCOM_ATTR_GET_SHUT:
      if (VCL_SESS_ATTR_TEST (session->attr, VCL_SESS_ATTR_SHUT_RD))
	tmp_flags = 1;
      if (VCL_SESS_ATTR_TEST (session->attr, VCL_SESS_ATTR_SHUT_WR))
	tmp_flags |= 2;
      if (tmp_flags == 1)
	*(int *) buffer = SHUT_RD;
      else if (tmp_flags == 2)
	*(int *) buffer = SHUT_WR;
      else if (tmp_flags == 3)
	*(int *) buffer = SHUT_RDWR;
      *buflen = sizeof (int);
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
  int rv = VPPCOM_OK;
  vcl_session_t *session = 0;

  if (ep)
    {
      session = vcl_session_get_w_handle (wrk, session_handle);
      if (PREDICT_FALSE (!session))
	{
	  VDBG (0, "VCL<%d>: invalid session, sid (%u) has been closed!",
		getpid (), session_handle);
	  return VPPCOM_EBADFD;
	}
      ep->is_ip4 = session->transport.is_ip4;
      ep->port = session->transport.rmt_port;
    }

  if (flags == 0)
    rv = vppcom_session_read (session_handle, buffer, buflen);
  else if (flags & MSG_PEEK)
    rv = vppcom_session_peek (session_handle, buffer, buflen);
  else
    {
      VDBG (0, "Unsupport flags for recvfrom %d", flags);
      return VPPCOM_EAFNOSUPPORT;
    }

  if (ep)
    {
      if (session->transport.is_ip4)
	clib_memcpy_fast (ep->ip, &session->transport.rmt_ip.ip4,
			  sizeof (ip4_address_t));
      else
	clib_memcpy_fast (ep->ip, &session->transport.rmt_ip.ip6,
			  sizeof (ip6_address_t));
    }

  return rv;
}

int
vppcom_session_sendto (uint32_t session_handle, void *buffer,
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

  return (vppcom_session_write_inline (session_handle, buffer, buflen, 1));
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

  VDBG (3, "VCL<%d>: vp %p, nsids %u, wait_for_time %f",
	getpid (), vp, n_sids, wait_for_time);

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
	      rv = vppcom_session_read_ready (session);
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
	      rv = vppcom_session_write_ready (session);
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

  if (VPPCOM_DEBUG > 3)
    {
      clib_warning ("VCL<%d>: returning %d", getpid (), num_ev);
      for (i = 0; i < n_sids; i++)
	{
	  clib_warning ("VCL<%d>: vp[%d].sid %d (0x%x), .events 0x%x, "
			".revents 0x%x", getpid (), i, vp[i].sh, vp[i].sh,
			vp[i].events, vp[i].revents);
	}
    }
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
vppcom_session_handle (uint32_t session_index)
{
  return (vcl_get_worker_index () << 24) | session_index;
}

int
vppcom_worker_register (void)
{
  if (!vcl_worker_alloc_and_init ())
    return VPPCOM_EEXIST;

  if (vcl_worker_set_bapi ())
    return VPPCOM_EEXIST;

  if (vcl_worker_register_with_vpp ())
    return VPPCOM_EEXIST;

  return VPPCOM_OK;
}

int
vppcom_worker_index (void)
{
  return vcl_get_worker_index ();
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
