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
  echo_connect_args_t _a, *a = &_a;
  u64 i;

  a->parent_session_handle = mp->handle;
  a->context = session_index;

  echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
  for (i = 0; i < eqm->n_stream_clients; i++)
    echo_send_connect_stream (em, a);

  ECHO_LOG (1, "Qsession 0x%llx S[%d] connected to %U:%d",
	    mp->handle, session_index, format_ip46_address, &mp->lcl.ip,
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
  ECHO_LOG (2, "Accept on QSession 0x%lx S[%u]", mp->handle, session_index);
  echo_connect_args_t _a, *a = &_a;
  u32 i;

  a->parent_session_handle = mp->handle;
  a->context = session_index;

  echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
  for (i = 0; i < eqm->n_stream_clients; i++)
    echo_send_connect_stream (em, a);
}

static void
quic_echo_on_accept_error (session_accepted_msg_t * mp, u32 session_index)
{
  ECHO_FAIL (ECHO_FAIL_QUIC_WRONG_ACCEPT,
	     "Got a wrong accept on session 0x%lx S[%u]", mp->handle,
	     session_index);
}

static void
quic_echo_on_accept_log_ip (session_accepted_msg_t * mp, u32 session_index)
{
  u8 *ip_str;
  ip_str = format (0, "%U", format_ip46_address, &mp->rmt.ip, mp->rmt.is_ip4);
  ECHO_LOG (1, "Accepted session from: %s:%d", ip_str,
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
  if (ls->session_type != ECHO_SESSION_TYPE_QUIC)
    {
      ECHO_LOG (2, "%U: Invalid listener session type",
		echo_format_session, ls);
      return;
    }
  if (!clib_atomic_sub_fetch (&ls->accepted_session_count, 1))
    {
      if (eqm->send_quic_disconnects == ECHO_CLOSE_F_ACTIVE)
	{
	  echo_send_rpc (em, echo_send_disconnect_session,
			 (echo_rpc_args_t *) & ls->vpp_session_handle);
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
  if ((em->state == STATE_DATA_DONE) ||
      !(s->session_state < ECHO_SESSION_STATE_CLOSED))
    return;
  ECHO_LOG (3, "%U cleanup (parent_died %d)", echo_format_session, s,
	    parent_died);
  s->session_state = ECHO_SESSION_STATE_CLOSED;
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
  if (!em->n_clients_connected && !eqm->n_quic_clients_connected)
    em->state = STATE_DATA_DONE;
  ECHO_LOG (2, "Cleanup sessions (still %uQ %uS): app %U",
	    eqm->n_quic_clients_connected, em->n_clients_connected,
	    echo_format_app_state, em->state);
}

static void
quic_echo_initiate_qsession_close_no_stream (echo_main_t * em)
{
  quic_echo_proto_main_t *eqm = &quic_echo_proto_main;
  ECHO_LOG (2, "Closing Qsessions");
  /* Close Quic session without streams */
  echo_session_t *s;

  pool_foreach (s, em->sessions)
   {
    if (s->session_type == ECHO_SESSION_TYPE_QUIC)
      {
        if (eqm->send_quic_disconnects == ECHO_CLOSE_F_ACTIVE)
          {
            ECHO_LOG (2,"%U: ACTIVE close", echo_format_session, s);
            echo_send_rpc (em, echo_send_disconnect_session,
                           (echo_rpc_args_t *) &s->vpp_session_handle);
            clib_atomic_fetch_add (&em->stats.active_count.q, 1);
          }
        else if (eqm->send_quic_disconnects == ECHO_CLOSE_F_NONE)
          {
            ECHO_LOG (2,"%U: CLEAN close", echo_format_session, s);
            quic_echo_cleanup_cb (s, 0 /* parent_died */);
            clib_atomic_fetch_add (&em->stats.clean_count.q, 1);
          }
        else
          ECHO_LOG (2,"%U: PASSIVE close", echo_format_session, s);
      }
  }
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
      clib_atomic_fetch_add (&em->stats.connected_count.q, 1);
      session->session_type = ECHO_SESSION_TYPE_QUIC;
      ECHO_LOG (2, "Connected %U -> URI", echo_format_session, session);
      session->accepted_session_count = 0;
      if (eqm->cb_vft.quic_connected_cb)
	eqm->cb_vft.quic_connected_cb (mp, session->session_index);
      clib_atomic_fetch_add (&eqm->n_quic_clients_connected, 1);

      if (em->stats.connected_count.q % LOGGING_BATCH == 0)
	ECHO_LOG (0, "Connected Q %d / %d", em->stats.connected_count.q,
		  em->n_connects);
    }
  else
    {
      clib_atomic_fetch_add (&em->stats.connected_count.s, 1);
      listen_session =
	pool_elt_at_index (em->sessions, session->listener_index);
      session->session_type = ECHO_SESSION_TYPE_STREAM;
      clib_atomic_fetch_add (&listen_session->accepted_session_count, 1);
      ECHO_LOG (2, "Connected %U -> %U", echo_format_session, session,
		echo_format_session, listen_session);
      if (em->i_am_master && eqm->cb_vft.server_stream_connected_cb)
	eqm->cb_vft.server_stream_connected_cb (mp, session->session_index);
      if (!em->i_am_master && eqm->cb_vft.client_stream_connected_cb)
	eqm->cb_vft.client_stream_connected_cb (mp, session->session_index);
      clib_atomic_fetch_add (&em->n_clients_connected, 1);

      if (em->stats.connected_count.s % LOGGING_BATCH == 0)
	ECHO_LOG (0, "Connected S %d / %d", em->stats.connected_count.s,
		  em->n_clients);
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
quic_echo_connected_cb (session_connected_bundled_msg_t * mp,
			u32 session_index, u8 is_failed)
{
  if (is_failed)
    {
      ECHO_FAIL (ECHO_FAIL_QUIC_WRONG_CONNECT, "Echo connect failed");
      return;
    }
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
      clib_atomic_fetch_add (&em->stats.accepted_count.q, 1);
      echo_notify_event (em, ECHO_EVT_FIRST_QCONNECT);
      session->session_type = ECHO_SESSION_TYPE_QUIC;
      session->accepted_session_count = 0;
      if (eqm->cb_vft.quic_accepted_cb)
	eqm->cb_vft.quic_accepted_cb (mp, session->session_index);
      clib_atomic_fetch_add (&eqm->n_quic_clients_connected, 1);

      if (em->stats.accepted_count.q % LOGGING_BATCH == 0)
	ECHO_LOG (0, "Accepted Q %d / %d", em->stats.accepted_count.q,
		  em->n_connects);
    }
  else
    {
      clib_atomic_fetch_add (&em->stats.accepted_count.s, 1);
      session->session_type = ECHO_SESSION_TYPE_STREAM;
      echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
      clib_atomic_fetch_add (&ls->accepted_session_count, 1);
      if (em->i_am_master && eqm->cb_vft.server_stream_accepted_cb)
	eqm->cb_vft.server_stream_accepted_cb (mp, session->session_index);
      if (!em->i_am_master && eqm->cb_vft.client_stream_accepted_cb)
	eqm->cb_vft.client_stream_accepted_cb (mp, session->session_index);
      clib_atomic_fetch_add (&em->n_clients_connected, 1);

      if (em->stats.accepted_count.s % LOGGING_BATCH == 0)
	ECHO_LOG (0, "Accepted S %d / %d", em->stats.accepted_count.s,
		  em->n_clients);

      if (em->connect_flag && !(mp->flags & em->connect_flag))
	{
	  ECHO_FAIL (ECHO_FAIL_UNIDIRECTIONAL,
		     "expected unidirectional streams");
	}
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
quic_echo_sent_disconnect_cb (echo_session_t * s)
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
  if (unformat (a, "quic-streams %d", &eqm->n_stream_clients))
    ;
  else if (unformat (a, "quic-setup %U", quic_echo_unformat_setup_vft))
    ;
  else if (unformat (a, "uni"))
    em->connect_flag = TRANSPORT_CFG_F_UNIDIRECTIONAL;
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
    clib_max (1,
	      eqm->n_stream_clients) * em->n_clients + em->n_clients +
    em->n_uris;
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
	   "  qclose=[Y|N|W]      When connection is done send[Y]|nop[N]|wait[W] for close\n"
	   "  uni                 Use unidirectional streams\n"
	   "\n"
	   "  quic-streams N      Open N QUIC streams (defaults to 1)\n");
}

echo_proto_cb_vft_t quic_echo_proto_cb_vft = {
  .disconnected_cb = quic_echo_disconnected_cb,
  .connected_cb = quic_echo_connected_cb,
  .accepted_cb = quic_echo_accepted_cb,
  .reset_cb = quic_echo_reset_cb,
  .sent_disconnect_cb = quic_echo_sent_disconnect_cb,
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
