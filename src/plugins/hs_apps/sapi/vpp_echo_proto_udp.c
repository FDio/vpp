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

static void
udp_echo_cleanup_cb (echo_session_t * s, u8 parent_died)
{
  echo_main_t *em = &echo_main;
  echo_session_t *ls;
  ASSERT (s->session_state < ECHO_SESSION_STATE_CLOSED);
  if (parent_died)
    clib_atomic_fetch_add (&em->stats.clean_count.s, 1);
  else if (s->listener_index != SESSION_INVALID_INDEX)
    {
      ls = pool_elt_at_index (em->sessions, s->listener_index);
      clib_atomic_sub_fetch (&ls->accepted_session_count, 1);
    }

  clib_atomic_sub_fetch (&em->n_clients_connected, 1);
  s->session_state = ECHO_SESSION_STATE_CLOSED;
  if (!em->n_clients_connected)
    em->state = STATE_DATA_DONE;
}

static void
udp_echo_connected_cb (session_connected_bundled_msg_t * mp,
		       u32 session_index, u8 is_failed)
{
  static u32 client_index = 0;
  echo_main_t *em = &echo_main;
  echo_session_t *session = pool_elt_at_index (em->sessions, session_index);
  if (is_failed)
    {
      ECHO_FAIL (ECHO_FAIL_UDP_BAPI_CONNECT,
		 "Bapi connect errored on session %u", session_index);
      return;			/* Dont handle bapi connect errors for now */
    }

  session->accepted_session_count = 0;
  session->session_type = ECHO_SESSION_TYPE_STREAM;

  session->bytes_to_send = em->bytes_to_send;
  session->bytes_to_receive = em->bytes_to_receive;
  session->session_state = ECHO_SESSION_STATE_READY;
  session->is_dgram = 1;

  em->data_thread_args[client_index++] = session->session_index;

  clib_atomic_fetch_add (&em->n_clients_connected, 1);
  if (em->n_clients_connected == em->n_clients && em->state < STATE_READY)
    {
      echo_notify_event (em, ECHO_EVT_LAST_SCONNECTED);
      em->state = STATE_READY;
    }
}

static void
udp_echo_accepted_cb (session_accepted_msg_t * mp, echo_session_t * session)
{
  static u32 client_index = 0;
  echo_main_t *em = &echo_main;
  echo_session_t *ls;

  echo_notify_event (em, ECHO_EVT_FIRST_QCONNECT);
  ls = pool_elt_at_index (em->sessions, session->listener_index);
  session->session_type = ECHO_SESSION_TYPE_STREAM;
  echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
  clib_atomic_fetch_add (&ls->accepted_session_count, 1);
  clib_atomic_fetch_add (&em->n_clients_connected, 1);

  session->bytes_to_send = em->bytes_to_send;
  session->bytes_to_receive = em->bytes_to_receive;
  session->is_dgram = 1;
  em->data_thread_args[client_index++] = session->session_index;
  session->session_state = ECHO_SESSION_STATE_READY;

  if (em->n_clients_connected == em->n_clients && em->state < STATE_READY)
    {
      echo_notify_event (em, ECHO_EVT_LAST_SCONNECTED);
      em->state = STATE_READY;
    }
}

static void
udp_echo_sent_disconnect_cb (echo_session_t * s)
{
  s->session_state = ECHO_SESSION_STATE_CLOSING;
}

static void
udp_echo_disconnected_cb (session_disconnected_msg_t * mp, echo_session_t * s)
{
  echo_main_t *em = &echo_main;
  echo_session_print_stats (em, s);
  if (s->bytes_to_receive || s->bytes_to_send)
    s->session_state = ECHO_SESSION_STATE_AWAIT_DATA;
  else
    s->session_state = ECHO_SESSION_STATE_CLOSING;
  clib_atomic_fetch_add (&em->stats.close_count.s, 1);
}

static void
udp_echo_reset_cb (session_reset_msg_t * mp, echo_session_t * s)
{
  echo_main_t *em = &echo_main;
  clib_atomic_fetch_add (&em->stats.reset_count.s, 1);
  s->session_state = ECHO_SESSION_STATE_CLOSING;
}

static void
udp_echo_bound_uri_cb (session_bound_msg_t * mp, echo_session_t * session)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  echo_main_t *em = &echo_main;
  u32 session_index = session->session_index;
  if (!em->i_am_master || em->uri_elts.transport_proto != TRANSPORT_PROTO_UDP)
    return;

  rx_fifo = uword_to_pointer (mp->rx_fifo, svm_fifo_t *);
  tx_fifo = uword_to_pointer (mp->tx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo->client_session_index = session_index;

  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;
  session->transport.is_ip4 = mp->lcl_is_ip4;
  clib_memcpy_fast (&session->transport.lcl_ip, mp->lcl_ip,
		    sizeof (ip46_address_t));
  session->transport.lcl_port = mp->lcl_port;
  session->vpp_evt_q = uword_to_pointer (mp->vpp_evt_q, svm_msg_q_t *);

  echo_notify_event (em, ECHO_EVT_FIRST_QCONNECT);
  session->session_type = ECHO_SESSION_TYPE_STREAM;
  echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
  clib_atomic_fetch_add (&em->n_clients_connected, 1);

  session->bytes_to_send = em->bytes_to_send;
  session->bytes_to_receive = em->bytes_to_receive;
  session->is_dgram = 1;
  em->data_thread_args[0] = session_index;
  session->session_state = ECHO_SESSION_STATE_READY;

  echo_notify_event (em, ECHO_EVT_LAST_SCONNECTED);
  em->state = STATE_READY;
}


echo_proto_cb_vft_t echo_udp_proto_cb_vft = {
  .disconnected_cb = udp_echo_disconnected_cb,
  .connected_cb = udp_echo_connected_cb,
  .accepted_cb = udp_echo_accepted_cb,
  .reset_cb = udp_echo_reset_cb,
  .sent_disconnect_cb = udp_echo_sent_disconnect_cb,
  .cleanup_cb = udp_echo_cleanup_cb,
  .bound_uri_cb = udp_echo_bound_uri_cb,
};

ECHO_REGISTER_PROTO (TRANSPORT_PROTO_UDP, echo_udp_proto_cb_vft);
ECHO_REGISTER_PROTO (TRANSPORT_PROTO_UDPC, echo_udp_proto_cb_vft);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
