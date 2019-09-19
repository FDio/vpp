/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <stdio.h>
#include <signal.h>

#include <hs_apps/sapi/vpp_echo_common.h>

typedef struct _quic_echo_cb_vft
{
  void (*quic_connected_cb) (session_connected_msg_t * mp, u32 session_index);
  void (*client_stream_connected_cb) (session_connected_msg_t * mp,
				      u32 session_index);
  void (*server_stream_connected_cb) (session_connected_msg_t * mp,
				      u32 session_index);
  void (*quic_accepted_cb) (session_accepted_msg_t * mp, u32 session_index);
  void (*client_stream_accepted_cb) (session_accepted_msg_t * mp,
				     u32 session_index);
  void (*server_stream_accepted_cb) (session_accepted_msg_t * mp,
				     u32 session_index);
} quic_echo_cb_vft_t;

typedef struct
{
  quic_echo_cb_vft_t cb_vft;	/* cb vft for QUIC scenarios */
  u8 send_quic_disconnects;	/* actively send disconnect */
  u32 n_stream_clients;		/* Target Number of STREAM sessions per QUIC session */
  volatile u32 n_quic_clients_connected;	/* Number of connected QUIC sessions */
} quic_echo_proto_main_t;

quic_echo_proto_main_t quic_echo_proto_main;

/*
 *
 *  ECHO Callback definitions
 *
 */

static void
quic_echo_on_connected_connect (session_connected_msg_t * mp,
				u32 session_index)
{
  echo_main_t *em = &echo_main;
  quic_echo_proto_main_t *eqm = &quic_echo_proto_main;
  u8 *uri = format (0, "quic://session/%lu", mp->handle);
  u64 i;

  echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
  for (i = 0; i < eqm->n_stream_clients; i++)
    echo_send_rpc (em, echo_send_connect, (void *) uri, session_index);

  ECHO_LOG (0, "Qsession 0x%llx connected to %U:%d",
	    mp->handle, format_ip46_address, &mp->lcl.ip,
	    mp->lcl.is_ip4, clib_net_to_host_u16 (mp->lcl.port));
}

static void
quic_echo_on_connected_send (session_connected_msg_t * mp, u32 session_index)
{
  static u32 client_index = 0;
  echo_main_t *em = &echo_main;
  echo_session_t *session;

  session = pool_elt_at_index (em->sessions, session_index);
  session->bytes_to_send = em->bytes_to_send;
  session->bytes_to_receive = em->bytes_to_receive;
  session->session_state = ECHO_SESSION_STATE_READY;
  em->data_thread_args[client_index++] = session->session_index;
}

static void
quic_echo_on_connected_error (session_connected_msg_t * mp, u32 session_index)
{
  ECHO_FAIL (ECHO_FAIL_QUIC_WRONG_CONNECT,
	     "Got a wrong connected on session %u [%lx]", session_index,
	     mp->handle);
}

static void
quic_echo_on_accept_recv (session_accepted_msg_t * mp, u32 session_index)
{
  static u32 client_index = 0;
  echo_main_t *em = &echo_main;
  echo_session_t *session;

  session = pool_elt_at_index (em->sessions, session_index);
  session->bytes_to_send = em->bytes_to_send;
  session->bytes_to_receive = em->bytes_to_receive;
  em->data_thread_args[client_index++] = session->session_index;
  session->session_state = ECHO_SESSION_STATE_READY;
}

static void
quic_echo_on_accept_connect (session_accepted_msg_t * mp, u32 session_index)
{
  echo_main_t *em = &echo_main;
  quic_echo_proto_main_t *eqm = &quic_echo_proto_main;
  ECHO_LOG (1, "Accept on QSession 0x%lx %u", mp->handle);
  u8 *uri = format (0, "quic://session/%lu", mp->handle);
  u32 i;

  echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
  for (i = 0; i < eqm->n_stream_clients; i++)
    echo_send_rpc (em, echo_send_connect, (void *) uri, session_index);
}

static void
quic_echo_on_accept_error (session_accepted_msg_t * mp, u32 session_index)
{
  ECHO_FAIL (ECHO_FAIL_QUIC_WRONG_ACCEPT,
	     "Got a wrong accept on session %u [%lx]", session_index,
	     mp->handle);
}

static void
quic_echo_on_accept_log_ip (session_accepted_msg_t * mp, u32 session_index)
{
  u8 *ip_str;
  ip_str = format (0, "%U", format_ip46_address, &mp->rmt.ip, mp->rmt.is_ip4);
  ECHO_LOG (0, "Accepted session from: %s:%d", ip_str,
	    clib_net_to_host_u16 (mp->rmt.port));

}

static const quic_echo_cb_vft_t default_cb_vft = {
  /* Qsessions */
  .quic_accepted_cb = quic_echo_on_accept_log_ip,
  .quic_connected_cb = quic_echo_on_connected_connect,
  /* client initiated streams */
  .server_stream_accepted_cb = quic_echo_on_accept_recv,
  .client_stream_connected_cb = quic_echo_on_connected_send,
  /* server initiated streams */
  .client_stream_accepted_cb = quic_echo_on_accept_error,
  .server_stream_connected_cb = quic_echo_on_connected_error,
};

static const quic_echo_cb_vft_t server_stream_cb_vft = {
  /* Qsessions */
  .quic_accepted_cb = quic_echo_on_accept_connect,
  .quic_connected_cb = NULL,
  /* client initiated streams */
  .server_stream_accepted_cb = quic_echo_on_accept_error,
  .client_stream_connected_cb = quic_echo_on_connected_error,
  /* server initiated streams */
  .client_stream_accepted_cb = quic_echo_on_accept_recv,
  .server_stream_connected_cb = quic_echo_on_connected_send,
};

static void quic_echo_cleanup_cb (echo_session_t * s, u8 parent_died);

static inline void
quic_echo_cleanup_listener (u32 listener_index, echo_main_t * em,
			    quic_echo_proto_main_t * eqm)
{
  echo_session_t *ls;
  ls = pool_elt_at_index (em->sessions, listener_index);
  ASSERT (ls->session_type == ECHO_SESSION_TYPE_QUIC);
  if (!clib_atomic_sub_fetch (&ls->accepted_session_count, 1))
    {
      if (eqm->send_quic_disconnects == ECHO_CLOSE_F_ACTIVE)
	{
	  echo_send_rpc (em, echo_send_disconnect_session,
			 (void *) ls->vpp_session_handle, 0);
	  clib_atomic_fetch_add (&em->stats.active_count.q, 1);
	}
      else if (eqm->send_quic_disconnects == ECHO_CLOSE_F_NONE)
	{
	  quic_echo_cleanup_cb (ls, 0 /* parent_died */ );
	  clib_atomic_fetch_add (&em->stats.clean_count.q, 1);
	}
    }
}

static void
quic_echo_cleanup_cb (echo_session_t * s, u8 parent_died)
{
  echo_main_t *em = &echo_main;
  quic_echo_proto_main_t *eqm = &quic_echo_proto_main;
  ASSERT (s->session_state < ECHO_SESSION_STATE_CLOSED);
  if (s->session_type == ECHO_SESSION_TYPE_QUIC)
    {
      if (parent_died)
	clib_atomic_fetch_add (&em->stats.clean_count.q, 1);
      /* Don't cleanup listener as it's handled by main() */
      clib_atomic_sub_fetch (&eqm->n_quic_clients_connected, 1);
    }
  else if (s->session_type == ECHO_SESSION_TYPE_STREAM)
    {
      if (parent_died)
	clib_atomic_fetch_add (&em->stats.clean_count.s, 1);
      else
	quic_echo_cleanup_listener (s->listener_index, em, eqm);
      clib_atomic_sub_fetch (&em->n_clients_connected, 1);
    }

  ECHO_LOG (1, "Cleanup sessions (still %uQ %uS)",
	    eqm->n_quic_clients_connected, em->n_clients_connected);
  s->session_state = ECHO_SESSION_STATE_CLOSED;
  if (!em->n_clients_connected && !eqm->n_quic_clients_connected)
    em->state = STATE_DATA_DONE;
}

static void
quic_echo_initiate_qsession_close_no_stream (echo_main_t * em)
{
  quic_echo_proto_main_t *eqm = &quic_echo_proto_main;
  ECHO_LOG (1, "Closing Qsessions");
  /* Close Quic session without streams */
  echo_session_t *s;

  /* *INDENT-OFF* */
  pool_foreach (s, em->sessions,
  ({
    if (s->session_type == ECHO_SESSION_TYPE_QUIC)
      {
        if (eqm->send_quic_disconnects == ECHO_CLOSE_F_ACTIVE)
          {
            ECHO_LOG (1,"ACTIVE close 0x%lx", s->vpp_session_handle);
            echo_send_rpc (em, echo_send_disconnect_session, (void *) s->vpp_session_handle, 0);
            clib_atomic_fetch_add (&em->stats.active_count.q, 1);
          }
        else if (eqm->send_quic_disconnects == ECHO_CLOSE_F_NONE)
          {
            ECHO_LOG (1,"Discard close 0x%lx", s->vpp_session_handle);
            quic_echo_cleanup_cb (s, 0 /* parent_died */);
            clib_atomic_fetch_add (&em->stats.clean_count.q, 1);
          }
        else
          ECHO_LOG (1,"Passive close 0x%lx", s->vpp_session_handle);
      }
  }));
  /* *INDENT-ON* */
}

static void
quic_echo_on_connected (session_connected_msg_t * mp, u32 session_index)
{
  echo_main_t *em = &echo_main;
  quic_echo_proto_main_t *eqm = &quic_echo_proto_main;
  echo_session_t *listen_session;
  echo_session_t *session = pool_elt_at_index (em->sessions, session_index);
  if (session->listener_index == SESSION_INVALID_INDEX)
    {
      ECHO_LOG (1, "Connected session 0x%lx -> URI", mp->handle);
      session->session_type = ECHO_SESSION_TYPE_QUIC;
      session->accepted_session_count = 0;
      if (eqm->cb_vft.quic_connected_cb)
	eqm->cb_vft.quic_connected_cb (mp, session->session_index);
      clib_atomic_fetch_add (&eqm->n_quic_clients_connected, 1);
    }
  else
    {
      listen_session =
	pool_elt_at_index (em->sessions, session->listener_index);
      ECHO_LOG (1, "Connected session 0x%lx -> 0x%lx", mp->handle,
		listen_session->vpp_session_handle);
      session->session_type = ECHO_SESSION_TYPE_STREAM;
      clib_atomic_fetch_add (&listen_session->accepted_session_count, 1);
      if (em->i_am_master && eqm->cb_vft.server_stream_connected_cb)
	eqm->cb_vft.server_stream_connected_cb (mp, session->session_index);
      if (!em->i_am_master && eqm->cb_vft.client_stream_connected_cb)
	eqm->cb_vft.client_stream_connected_cb (mp, session->session_index);
      clib_atomic_fetch_add (&em->n_clients_connected, 1);
    }

  if (em->n_clients_connected == em->n_clients
      && em->n_clients_connected != 0)
    echo_notify_event (em, ECHO_EVT_LAST_SCONNECTED);

  if (eqm->n_quic_clients_connected == em->n_connects
      && em->state < STATE_READY)
    {
      echo_notify_event (em, ECHO_EVT_LAST_QCONNECTED);
      em->state = STATE_READY;
      if (eqm->n_stream_clients == 0)
	quic_echo_initiate_qsession_close_no_stream (em);
    }
}

static void
quic_echo_retry_connect (u32 session_index)
{
  /* retry connect */
  echo_session_t *session;
  echo_main_t *em = &echo_main;
  u8 *uri;
  if (session_index == SESSION_INVALID_INDEX)
    {
      ECHO_LOG (1, "Retrying connect %s", em->uri);
      echo_send_rpc (em, echo_send_connect, (void *) em->uri,
		     SESSION_INVALID_INDEX);
    }
  else
    {
      session = pool_elt_at_index (em->sessions, session_index);
      uri = format (0, "quic://session/%lu", session->vpp_session_handle);
      ECHO_LOG (1, "Retrying connect %s", uri);
      echo_send_rpc (em, echo_send_connect, (void *) uri, session_index);
    }
}

static void
quic_echo_connected_cb (session_connected_bundled_msg_t * mp,
			u32 session_index, u8 is_failed)
{
  if (is_failed)
    return quic_echo_retry_connect (session_index);
  return quic_echo_on_connected ((session_connected_msg_t *) mp,
				 session_index);
}

static void
quic_echo_accepted_cb (session_accepted_msg_t * mp, echo_session_t * session)
{
  echo_main_t *em = &echo_main;
  quic_echo_proto_main_t *eqm = &quic_echo_proto_main;
  echo_session_t *ls;
  ls = pool_elt_at_index (em->sessions, session->listener_index);
  if (ls->session_type == ECHO_SESSION_TYPE_LISTEN)
    {
      echo_notify_event (em, ECHO_EVT_FIRST_QCONNECT);
      session->session_type = ECHO_SESSION_TYPE_QUIC;
      session->accepted_session_count = 0;
      if (eqm->cb_vft.quic_accepted_cb)
	eqm->cb_vft.quic_accepted_cb (mp, session->session_index);
      clib_atomic_fetch_add (&eqm->n_quic_clients_connected, 1);
    }
  else
    {
      session->session_type = ECHO_SESSION_TYPE_STREAM;
      echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
      clib_atomic_fetch_add (&ls->accepted_session_count, 1);
      if (em->i_am_master && eqm->cb_vft.server_stream_accepted_cb)
	eqm->cb_vft.server_stream_accepted_cb (mp, session->session_index);
      if (!em->i_am_master && eqm->cb_vft.client_stream_accepted_cb)
	eqm->cb_vft.client_stream_accepted_cb (mp, session->session_index);
      clib_atomic_fetch_add (&em->n_clients_connected, 1);
    }

  if (em->n_clients_connected == em->n_clients
      && em->n_clients_connected != 0)
    echo_notify_event (em, ECHO_EVT_LAST_SCONNECTED);

  if (eqm->n_quic_clients_connected == em->n_connects
      && em->state < STATE_READY)
    {
      echo_notify_event (em, ECHO_EVT_LAST_QCONNECTED);
      em->state = STATE_READY;
      if (eqm->n_stream_clients == 0)
	quic_echo_initiate_qsession_close_no_stream (em);
    }
}

static void
quic_echo_disconnected_reply_cb (echo_session_t * s)
{
  if (s->session_type == ECHO_SESSION_TYPE_STREAM)
    s->session_state = ECHO_SESSION_STATE_CLOSING;
  else
    quic_echo_cleanup_cb (s, 0 /* parent_died */ );	/* We can clean Q/Lsessions right away */
}

static void
quic_echo_disconnected_cb (session_disconnected_msg_t * mp,
			   echo_session_t * s)
{
  echo_main_t *em = &echo_main;
  if (s->session_type == ECHO_SESSION_TYPE_STREAM)
    {
      echo_session_print_stats (em, s);
      if (s->bytes_to_receive || s->bytes_to_send)
	s->session_state = ECHO_SESSION_STATE_AWAIT_DATA;
      else
	s->session_state = ECHO_SESSION_STATE_CLOSING;
      clib_atomic_fetch_add (&em->stats.close_count.s, 1);
    }
  else
    {
      quic_echo_cleanup_cb (s, 0 /* parent_died */ );	/* We can clean Q/Lsessions right away */
      clib_atomic_fetch_add (&em->stats.close_count.q, 1);
    }
}

static void
quic_echo_reset_cb (session_reset_msg_t * mp, echo_session_t * s)
{
  echo_main_t *em = &echo_main;
  if (s->session_type == ECHO_SESSION_TYPE_STREAM)
    {
      clib_atomic_fetch_add (&em->stats.reset_count.s, 1);
      s->session_state = ECHO_SESSION_STATE_CLOSING;
    }
  else
    {
      clib_atomic_fetch_add (&em->stats.reset_count.q, 1);
      quic_echo_cleanup_cb (s, 0 /* parent_died */ );	/* We can clean Q/Lsessions right away */
    }
}

static uword
quic_echo_unformat_setup_vft (unformat_input_t * input, va_list * args)
{
  quic_echo_proto_main_t *eqm = &quic_echo_proto_main;
  if (unformat (input, "serverstream"))
    eqm->cb_vft = server_stream_cb_vft;
  else if (unformat (input, "default"))
    ;
  else
    return 0;
  return 1;
}

static int
quic_echo_process_opts_cb (unformat_input_t * a)
{
  echo_main_t *em = &echo_main;
  quic_echo_proto_main_t *eqm = &quic_echo_proto_main;
  if (unformat (a, "nclients %d/%d", &em->n_clients, &eqm->n_stream_clients))
    ;
  else if (unformat (a, "quic-setup %U", quic_echo_unformat_setup_vft))
    ;
  else if (unformat (a, "qclose=%U",
		     echo_unformat_close, &eqm->send_quic_disconnects))
    ;
  else
    return 0;
  return 1;
}

static void
quic_echo_set_defaults_before_opts_cb ()
{
  quic_echo_proto_main_t *eqm = &quic_echo_proto_main;
  eqm->cb_vft = default_cb_vft;
  eqm->n_stream_clients = 1;
}

static void
quic_echo_set_defaults_after_opts_cb ()
{
  quic_echo_proto_main_t *eqm = &quic_echo_proto_main;
  echo_main_t *em = &echo_main;
  u8 default_f_active;

  em->n_connects = em->n_clients;
  em->n_sessions =
    clib_max (1, eqm->n_stream_clients) * em->n_clients + em->n_clients + 1;
  em->n_clients = eqm->n_stream_clients * em->n_clients;

  if (em->i_am_master)
    default_f_active =
      em->bytes_to_send == 0 ? ECHO_CLOSE_F_ACTIVE : ECHO_CLOSE_F_PASSIVE;
  else
    default_f_active =
      em->bytes_to_receive == 0 ? ECHO_CLOSE_F_PASSIVE : ECHO_CLOSE_F_ACTIVE;
  if (eqm->send_quic_disconnects == ECHO_CLOSE_F_INVALID)
    eqm->send_quic_disconnects = default_f_active;
}

static void
quic_echo_print_usage_cb ()
{
  fprintf (stderr,
	   "-- QUIC specific options -- \n"
	   "  quic-setup OPT      OPT=serverstream : Client open N connections. \n"
	   "                       On each one server opens M streams\n"
	   "                      OPT=default : Client open N connections.\n"
	   "                       On each one client opens M streams\n"
	   "  qclose=[Y|N|W]      When a connection is done pass[N] send[Y] or wait[W] for close\n"
	   "\n"
	   "  nclients N[/M]      Open N QUIC connections, each one with M streams (M defaults to 1)\n");
}

echo_proto_cb_vft_t quic_echo_proto_cb_vft = {
  .disconnected_cb = quic_echo_disconnected_cb,
  .connected_cb = quic_echo_connected_cb,
  .accepted_cb = quic_echo_accepted_cb,
  .reset_cb = quic_echo_reset_cb,
  .disconnected_reply_cb = quic_echo_disconnected_reply_cb,
  .cleanup_cb = quic_echo_cleanup_cb,
  .process_opts_cb = quic_echo_process_opts_cb,
  .print_usage_cb = quic_echo_print_usage_cb,
  .set_defaults_before_opts_cb = quic_echo_set_defaults_before_opts_cb,
  .set_defaults_after_opts_cb = quic_echo_set_defaults_after_opts_cb,
};

ECHO_REGISTER_PROTO (TRANSPORT_PROTO_QUIC, quic_echo_proto_cb_vft);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
