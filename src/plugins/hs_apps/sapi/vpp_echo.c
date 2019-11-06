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

#include <vlibmemory/api.h>
#include <svm/fifo_segment.h>

#include <hs_apps/sapi/vpp_echo_common.h>

echo_main_t echo_main;

static void
echo_session_prealloc (echo_main_t * em)
{
  /* We need to prealloc to avoid vec resize in threads */
  echo_session_t *session;
  int i;
  for (i = 0; i < em->n_sessions; i++)
    {
      pool_get (em->sessions, session);
      clib_memset (session, 0, sizeof (*session));
      session->session_index = session - em->sessions;
      session->listener_index = SESSION_INVALID_INDEX;
      session->session_state = ECHO_SESSION_STATE_INITIAL;
    }
}

static void
echo_assert_test_suceeded (echo_main_t * em)
{
  if (em->rx_results_diff)
    CHECK_DIFF (ECHO_FAIL_TEST_ASSERT_RX_TOTAL, em->stats.rx_expected,
		em->stats.rx_total, "Invalid amount of data received");
  else
    CHECK_SAME (ECHO_FAIL_TEST_ASSERT_RX_TOTAL, em->stats.rx_expected,
		em->stats.rx_total, "Invalid amount of data received");

  if (em->tx_results_diff)
    CHECK_DIFF (ECHO_FAIL_TEST_ASSERT_TX_TOTAL, em->stats.tx_expected,
		em->stats.tx_total, "Invalid amount of data sent");
  else
    CHECK_SAME (ECHO_FAIL_TEST_ASSERT_TX_TOTAL, em->stats.tx_expected,
		em->stats.tx_total, "Invalid amount of data sent");

  clib_spinlock_lock (&em->sid_vpp_handles_lock);
  CHECK_SAME (ECHO_FAIL_TEST_ASSERT_ALL_SESSIONS_CLOSED,
	      0, hash_elts (em->session_index_by_vpp_handles),
	      "Some sessions are still open");
  clib_spinlock_unlock (&em->sid_vpp_handles_lock);
}

always_inline void
echo_session_dequeue_notify (echo_session_t * s)
{
  int rv;
  if (!svm_fifo_set_event (s->rx_fifo))
    return;
  if ((rv =
       app_send_io_evt_to_vpp (s->vpp_evt_q, s->rx_fifo->master_session_index,
			       SESSION_IO_EVT_RX, SVM_Q_WAIT)))
    ECHO_FAIL (ECHO_FAIL_SEND_IO_EVT, "app_send_io_evt_to_vpp errored %d",
	       rv);
  svm_fifo_clear_deq_ntf (s->rx_fifo);
}

static void
stop_signal (int signum)
{
  echo_main_t *em = &echo_main;
  em->time_to_stop = 1;
}

int
connect_to_vpp (char *name)
{
  echo_main_t *em = &echo_main;
  api_main_t *am = &api_main;

  if (em->use_sock_api)
    {
      if (vl_socket_client_connect ((char *) em->socket_name, name,
				    0 /* default rx, tx buffer */ ))
	{
	  ECHO_FAIL (ECHO_FAIL_SOCKET_CONNECT, "socket connect failed");
	  return -1;
	}

      if (vl_socket_client_init_shm (0, 1 /* want_pthread */ ))
	{
	  ECHO_FAIL (ECHO_FAIL_INIT_SHM_API, "init shm api failed");
	  return -1;
	}
    }
  else
    {
      if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0)
	{
	  ECHO_FAIL (ECHO_FAIL_SHMEM_CONNECT, "shmem connect failed");
	  return -1;
	}
    }
  em->vl_input_queue = am->shmem_hdr->vl_input_queue;
  em->my_client_index = am->my_client_index;
  return 0;
}

static void
print_global_json_stats (echo_main_t * em)
{
  u8 *start_evt =
    format (0, "%U", echo_format_timing_event, em->timing.start_event);
  u8 *end_evt =
    format (0, "%U", echo_format_timing_event, em->timing.end_event);
  u8 start_evt_missing = !(em->timing.events_sent & em->timing.start_event);
  u8 end_evt_missing = (em->rx_results_diff || em->tx_results_diff) ? 0 :
    !(em->timing.events_sent & em->timing.end_event);
  f64 deltat = start_evt_missing || end_evt_missing ? 0 :
    em->timing.end_time - em->timing.start_time;

  if (start_evt_missing)
    ECHO_FAIL (ECHO_FAIL_MISSING_START_EVENT,
	       "Expected event %v to happen, but it did not!", start_evt);

  if (end_evt_missing)
    ECHO_FAIL (ECHO_FAIL_MISSING_END_EVENT,
	       "Expected event %v to happen, but it did not!", end_evt);

  fformat (stdout, "vpp_echo JSON stats:\n{\n");
  fformat (stdout, "  \"role\": \"%s\",\n",
	   em->i_am_master ? "server" : "client");
  fformat (stdout, "  \"time\": \"%.9f\",\n", deltat);
  fformat (stdout, "  \"start_evt\": \"%v\",\n", start_evt);
  fformat (stdout, "  \"start_evt_missing\": \"%s\",\n",
	   start_evt_missing ? "True" : "False");
  fformat (stdout, "  \"end_evt\": \"%v\",\n", end_evt);
  fformat (stdout, "  \"end_evt_missing\": \"%s\",\n",
	   end_evt_missing ? "True" : "False");
  fformat (stdout, "  \"rx_data\": %lld,\n", em->stats.rx_total);
  fformat (stdout, "  \"tx_rx\": %lld,\n", em->stats.tx_total);
  fformat (stdout, "  \"closing\": {\n");
  fformat (stdout, "    \"reset\": { \"q\": %d, \"s\": %d },\n",
	   em->stats.reset_count.q, em->stats.reset_count.s);
  fformat (stdout, "    \"recv evt\": { \"q\": %d, \"s\": %d },\n",
	   em->stats.close_count.q, em->stats.close_count.s);
  fformat (stdout, "    \"send evt\": { \"q\": %d, \"s\": %d },\n",
	   em->stats.active_count.q, em->stats.active_count.s);
  fformat (stdout, "    \"clean\": { \"q\": %d, \"s\": %d }\n",
	   em->stats.clean_count.q, em->stats.clean_count.s);
  fformat (stdout, "  }\n");
  fformat (stdout, "  \"results\": {\n");
  fformat (stdout, "    \"has_failed\": \"%d\"\n", em->has_failed);
  fformat (stdout, "    \"fail_descr\": \"%v\"\n", em->fail_descr);
  fformat (stdout, "  }\n");
  fformat (stdout, "}\n");
  fflush (stdout);
  vec_free (start_evt);
  vec_free (end_evt);
}

static void
print_global_stats (echo_main_t * em)
{
  u8 *start_evt =
    format (0, "%U", echo_format_timing_event, em->timing.start_event);
  u8 *end_evt =
    format (0, "%U", echo_format_timing_event, em->timing.end_event);
  u8 start_evt_missing = !(em->timing.events_sent & em->timing.start_event);
  u8 end_evt_missing = (em->rx_results_diff || em->tx_results_diff) ? 0 :
    !(em->timing.events_sent & em->timing.end_event);
  f64 deltat = start_evt_missing || end_evt_missing ? 0 :
    em->timing.end_time - em->timing.start_time;

  if (start_evt_missing)
    ECHO_FAIL (ECHO_FAIL_MISSING_START_EVENT,
	       "Expected event %v to happen, but it did not!", start_evt);

  if (end_evt_missing)
    ECHO_FAIL (ECHO_FAIL_MISSING_END_EVENT,
	       "Expected event %v to happen, but it did not!", end_evt);

  fformat (stdout, "Timing %v:%v\n", start_evt, end_evt);
  if (start_evt_missing)
    fformat (stdout, "Missing Start Timing Event (%v)!\n", start_evt);
  if (end_evt_missing)
    fformat (stdout, "Missing End Timing Event (%v)!\n", end_evt);
  fformat (stdout, "-------- TX --------\n");
  fformat (stdout, "%lld bytes (%lld mbytes, %lld gbytes) in %.6f seconds\n",
	   em->stats.tx_total, em->stats.tx_total / (1ULL << 20),
	   em->stats.tx_total / (1ULL << 30), deltat);
  if (deltat)
    fformat (stdout, "%.4f Gbit/second\n",
	     (em->stats.tx_total * 8.0) / deltat / 1e9);
  fformat (stdout, "-------- RX --------\n");
  fformat (stdout, "%lld bytes (%lld mbytes, %lld gbytes) in %.6f seconds\n",
	   em->stats.rx_total, em->stats.rx_total / (1ULL << 20),
	   em->stats.rx_total / (1ULL << 30), deltat);
  if (deltat)
    fformat (stdout, "%.4f Gbit/second\n",
	     (em->stats.rx_total * 8.0) / deltat / 1e9);
  fformat (stdout, "--------------------\n");
  fformat (stdout, "Received close on %d streams (and %d Quic conn)\n",
	   em->stats.close_count.s, em->stats.close_count.q);
  fformat (stdout, "Received reset on %d streams (and %d Quic conn)\n",
	   em->stats.reset_count.s, em->stats.reset_count.q);
  fformat (stdout, "Sent close on     %d streams (and %d Quic conn)\n",
	   em->stats.active_count.s, em->stats.active_count.q);
  fformat (stdout, "Discarded         %d streams (and %d Quic conn)\n",
	   em->stats.clean_count.s, em->stats.clean_count.q);
  if (em->has_failed)
    fformat (stdout, "\nFailure Return Status: %d\n%v", em->has_failed,
	     em->fail_descr);
  vec_free (start_evt);
  vec_free (end_evt);
}

void
echo_update_count_on_session_close (echo_main_t * em, echo_session_t * s)
{

  ECHO_LOG (1, "[%lu/%lu] -> %U -> [%lu/%lu]",
	    s->bytes_received, s->bytes_received + s->bytes_to_receive,
	    echo_format_session, s, s->bytes_sent,
	    s->bytes_sent + s->bytes_to_send);
  clib_atomic_fetch_add (&em->stats.tx_total, s->bytes_sent);
  clib_atomic_fetch_add (&em->stats.rx_total, s->bytes_received);

  if (PREDICT_FALSE (em->stats.rx_total == em->stats.rx_expected))
    echo_notify_event (em, ECHO_EVT_LAST_BYTE);
}

static void
echo_free_sessions (echo_main_t * em)
{
  /* Free marked sessions */
  echo_session_t *s;
  u32 *session_indexes = 0, *session_index;

  /* *INDENT-OFF* */
  pool_foreach (s, em->sessions,
  ({
    if (s->session_state == ECHO_SESSION_STATE_CLOSED)
      vec_add1 (session_indexes, s->session_index);}
  ));
  /* *INDENT-ON* */
  vec_foreach (session_index, session_indexes)
  {
    /* Free session */
    s = pool_elt_at_index (em->sessions, *session_index);
    echo_session_handle_add_del (em, s->vpp_session_handle,
				 SESSION_INVALID_INDEX);
    clib_memset (s, 0xfe, sizeof (*s));
    pool_put (em->sessions, s);
  }
}

static void
test_recv_bytes (echo_main_t * em, echo_session_t * s, u8 * rx_buf,
		 u32 n_read)
{
  u32 i;
  u8 expected;
  for (i = 0; i < n_read; i++)
    {
      expected = (s->bytes_received + i) & 0xff;
      if (rx_buf[i] == expected || em->max_test_msg > 0)
	continue;
      ECHO_LOG (0, "Session 0x%lx byte %lld was 0x%x expected 0x%x",
		s->vpp_session_handle, s->bytes_received + i, rx_buf[i],
		expected);
      em->max_test_msg--;
      if (em->max_test_msg == 0)
	ECHO_LOG (0, "Too many errors, hiding next ones");
      if (em->test_return_packets == RETURN_PACKETS_ASSERT)
	ECHO_FAIL (ECHO_FAIL_TEST_BYTES_ERR, "test-bytes errored");
    }
}

static int
recv_data_chunk (echo_main_t * em, echo_session_t * s, u8 * rx_buf)
{
  int n_read;
  n_read = app_recv ((app_session_t *) s, rx_buf, vec_len (rx_buf));
  if (n_read <= 0)
    return 0;
  if (svm_fifo_needs_deq_ntf (s->rx_fifo, n_read))
    echo_session_dequeue_notify (s);

  if (em->test_return_packets)
    test_recv_bytes (em, s, rx_buf, n_read);

  s->bytes_received += n_read;
  s->bytes_to_receive -= n_read;
  return n_read;
}

static int
send_data_chunk (echo_session_t * s, u8 * tx_buf, int offset, int len)
{
  int n_sent;
  int bytes_this_chunk = clib_min (s->bytes_to_send, len - offset);
  if (!bytes_this_chunk)
    return 0;
  n_sent = app_send ((app_session_t *) s, tx_buf + offset,
		     bytes_this_chunk, SVM_Q_WAIT);
  if (n_sent < 0)
    return 0;
  s->bytes_to_send -= n_sent;
  s->bytes_sent += n_sent;
  return n_sent;
}

static int
mirror_data_chunk (echo_main_t * em, echo_session_t * s, u8 * tx_buf, u64 len)
{
  u64 n_sent = 0;
  while (n_sent < len && !em->time_to_stop)
    n_sent += send_data_chunk (s, tx_buf, n_sent, len);
  return n_sent;
}

static inline void
echo_check_closed_listener (echo_main_t * em, echo_session_t * s)
{
  echo_session_t *ls;
  /* if parent has died, terminate gracefully */
  if (s->listener_index == SESSION_INVALID_INDEX)
    {
      ECHO_LOG (2, "%U: listener_index == SESSION_INVALID_INDEX",
		echo_format_session, s);
      return;
    }
  ls = pool_elt_at_index (em->sessions, s->listener_index);
  if (ls->session_state < ECHO_SESSION_STATE_CLOSING)
    {
      ECHO_LOG (3, "%U: ls->session_state (%d) < "
		"ECHO_SESSION_STATE_CLOSING (%d)",
		echo_format_session, ls, ls->session_state,
		ECHO_SESSION_STATE_CLOSING);
      return;
    }

  ECHO_LOG (2, "%U died, close child %U", echo_format_session, ls,
	    echo_format_session, s);
  echo_update_count_on_session_close (em, s);
  em->proto_cb_vft->cleanup_cb (s, 1 /* parent_died */ );
}

/*
 * Rx/Tx polling thread per connection
 */
static void
echo_handle_data (echo_main_t * em, echo_session_t * s, u8 * rx_buf)
{
  int n_read, n_sent = 0;

  n_read = recv_data_chunk (em, s, rx_buf);
  if ((em->data_source == ECHO_TEST_DATA_SOURCE) && s->bytes_to_send)
    n_sent = send_data_chunk (s, em->connect_test_data,
			      s->bytes_sent % em->tx_buf_size,
			      em->tx_buf_size);
  else if (em->data_source == ECHO_RX_DATA_SOURCE)
    n_sent = mirror_data_chunk (em, s, rx_buf, n_read);
  if (!s->bytes_to_send && !s->bytes_to_receive)
    {
      /* Session is done, need to close */
      if (s->session_state == ECHO_SESSION_STATE_AWAIT_DATA)
	s->session_state = ECHO_SESSION_STATE_CLOSING;
      else
	{
	  s->session_state = ECHO_SESSION_STATE_AWAIT_CLOSING;
	  if (em->send_stream_disconnects == ECHO_CLOSE_F_ACTIVE)
	    {
	      echo_send_rpc (em, echo_send_disconnect_session,
			     (void *) s->vpp_session_handle, 0);
	      clib_atomic_fetch_add (&em->stats.active_count.s, 1);
	    }
	  else if (em->send_stream_disconnects == ECHO_CLOSE_F_NONE)
	    {
	      s->session_state = ECHO_SESSION_STATE_CLOSING;
	      clib_atomic_fetch_add (&em->stats.clean_count.s, 1);
	    }
	}
      ECHO_LOG (2, "%U: %U", echo_format_session, s,
		echo_format_session_state, s->session_state);
      return;
    }

  /* Check for idle clients */
  if (em->log_lvl > 1)
    {
      if (n_sent || n_read)
	s->idle_cycles = 0;
      else if (s->idle_cycles++ == 1e7)
	{
	  s->idle_cycles = 0;
	  ECHO_LOG (1, "Idle client TX:%dB RX:%dB", s->bytes_to_send,
		    s->bytes_to_receive);
	  ECHO_LOG (1, "Idle FIFOs TX:%dB RX:%dB",
		    svm_fifo_max_dequeue (s->tx_fifo),
		    svm_fifo_max_dequeue (s->rx_fifo));
	  ECHO_LOG (1, "Session 0x%lx state %U", s->vpp_session_handle,
		    echo_format_session_state, s->session_state);
	}
    }
}

static void *
echo_data_thread_fn (void *arg)
{
  clib_mem_set_thread_index ();	/* First thing to do in client thread */
  echo_main_t *em = &echo_main;
  u32 N = em->n_clients;
  u32 n = (N + em->n_rx_threads - 1) / em->n_rx_threads;
  u32 idx = (u64) arg;
  if (n * idx >= N)
    {
      ECHO_LOG (1, "Thread %u exiting, no sessions to care for", idx);
      pthread_exit (0);
    }
  u32 thread_n_sessions = clib_min (n, N - n * idx);

  u32 i = 0;
  u32 n_closed_sessions = 0;
  u32 session_index;
  u8 *rx_buf = 0;
  echo_session_t *s;
  vec_validate (rx_buf, em->rx_buf_size);

  for (i = 0; !em->time_to_stop; i = (i + 1) % thread_n_sessions)
    {
      n_closed_sessions = i == 0 ? 0 : n_closed_sessions;
      session_index = em->data_thread_args[n * idx + i];
      if (session_index == SESSION_INVALID_INDEX)
	continue;
      s = pool_elt_at_index (em->sessions, session_index);
      switch (s->session_state)
	{
	case ECHO_SESSION_STATE_READY:
	case ECHO_SESSION_STATE_AWAIT_DATA:
	  echo_handle_data (em, s, rx_buf);
	  echo_check_closed_listener (em, s);
	  break;
	case ECHO_SESSION_STATE_AWAIT_CLOSING:
	  ECHO_LOG (3, "%U: %U", echo_format_session, s,
		    echo_format_session_state, s->session_state);
	  echo_check_closed_listener (em, s);
	  break;
	case ECHO_SESSION_STATE_CLOSING:
	  ECHO_LOG (2, "%U: %U", echo_format_session, s,
		    echo_format_session_state, s->session_state);
	  echo_update_count_on_session_close (em, s);
	  em->proto_cb_vft->cleanup_cb (s, 0 /* parent_died */ );
	  break;
	case ECHO_SESSION_STATE_CLOSED:
	  ECHO_LOG (2, "%U: %U", echo_format_session, s,
		    echo_format_session_state, s->session_state);
	  n_closed_sessions++;
	  break;
	}
      if (n_closed_sessions == thread_n_sessions)
	break;
    }
  ECHO_LOG (1, "Mission accomplished!");
  pthread_exit (0);
}

static void
session_unlisten_handler (session_unlisten_msg_t * mp)
{
  echo_session_t *listen_session;
  echo_main_t *em = &echo_main;
  listen_session = pool_elt_at_index (em->sessions, em->listen_session_index);
  em->proto_cb_vft->cleanup_cb (listen_session, 0 /* parent_died */ );
  listen_session->session_state = ECHO_SESSION_STATE_CLOSED;
  em->state = STATE_DISCONNECTED;
}

static void
session_bound_handler (session_bound_msg_t * mp)
{
  echo_main_t *em = &echo_main;
  echo_session_t *listen_session;
  if (mp->retval)
    {
      ECHO_FAIL (ECHO_FAIL_BIND, "bind failed: %U", format_api_error,
		 clib_net_to_host_u32 (mp->retval));
      return;
    }
  ECHO_LOG (0, "listening on %U:%u", format_ip46_address, mp->lcl_ip,
	    mp->lcl_is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
	    clib_net_to_host_u16 (mp->lcl_port));

  /* Allocate local session and set it up */
  listen_session = echo_session_new (em);
  listen_session->session_type = ECHO_SESSION_TYPE_LISTEN;
  listen_session->vpp_session_handle = mp->handle;
  echo_session_handle_add_del (em, mp->handle, listen_session->session_index);
  em->state = STATE_LISTEN;
  em->listen_session_index = listen_session->session_index;
  if (em->proto_cb_vft->bound_uri_cb)
    em->proto_cb_vft->bound_uri_cb (mp, listen_session);
}

static void
session_accepted_handler (session_accepted_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_accepted_reply_msg_t *rmp;
  svm_fifo_t *rx_fifo, *tx_fifo;
  echo_main_t *em = &echo_main;
  echo_session_t *session, *ls;

  if (!(ls = echo_get_session_from_handle (em, mp->listener_handle)))
    {
      ECHO_FAIL (ECHO_FAIL_SESSION_ACCEPTED_BAD_LISTENER,
		 "Unknown listener handle 0x%lx", mp->listener_handle);
      return;
    }
  if (wait_for_segment_allocation (mp->segment_handle))
    {
      ECHO_FAIL (ECHO_FAIL_ACCEPTED_WAIT_FOR_SEG_ALLOC,
		 "accepted wait_for_segment_allocation errored");
      return;
    }

  /* Allocate local session and set it up */
  session = echo_session_new (em);
  session->vpp_session_handle = mp->handle;

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session->session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session->session_index;

  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;

  /* session->transport needed by app_send_dgram */
  clib_memcpy_fast (&session->transport.rmt_ip, &mp->rmt.ip,
		    sizeof (ip46_address_t));
  session->transport.is_ip4 = mp->rmt.is_ip4;
  session->transport.rmt_port = mp->rmt.port;
  clib_memcpy_fast (&session->transport.lcl_ip, &em->uri_elts.ip,
		    sizeof (ip46_address_t));
  session->transport.lcl_port = em->uri_elts.port;

  session->vpp_session_handle = mp->handle;
  session->start = clib_time_now (&em->clib_time);
  session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					 svm_msg_q_t *);
  session->listener_index = ls->session_index;

  /* Add it to lookup table */
  ECHO_LOG (1, "Accepted session 0x%lx S[%u] -> 0x%lx S[%u]",
	    mp->handle, session->session_index,
	    mp->listener_handle, session->listener_index);
  echo_session_handle_add_del (em, mp->handle, session->session_index);

  app_alloc_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_ACCEPTED_REPLY);
  rmp = (session_accepted_reply_msg_t *) app_evt->evt->data;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  app_send_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt);
  em->proto_cb_vft->accepted_cb (mp, session);
}

static void
session_connected_handler (session_connected_msg_t * mp)
{
  echo_main_t *em = &echo_main;
  echo_session_t *session;
  u32 listener_index = htonl (mp->context);
  svm_fifo_t *rx_fifo, *tx_fifo;

  if (mp->retval)
    {
      if (em->proto_cb_vft->connected_cb)
	em->
	  proto_cb_vft->connected_cb ((session_connected_bundled_msg_t *) mp,
				      listener_index, 1 /* is_failed */ );
      return;
    }

  session = echo_session_new (em);
  if (wait_for_segment_allocation (mp->segment_handle))
    {
      ECHO_FAIL (ECHO_FAIL_CONNECTED_WAIT_FOR_SEG_ALLOC,
		 "connected wait_for_segment_allocation errored");
      return;
    }

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session->session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session->session_index;

  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;
  session->vpp_session_handle = mp->handle;
  session->start = clib_time_now (&em->clib_time);
  session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					 svm_msg_q_t *);
  session->listener_index = listener_index;
  /* session->transport needed by app_send_dgram */
  clib_memcpy_fast (&session->transport.lcl_ip, &mp->lcl.ip,
		    sizeof (ip46_address_t));
  session->transport.is_ip4 = mp->lcl.is_ip4;
  session->transport.lcl_port = mp->lcl.port;
  clib_memcpy_fast (&session->transport.rmt_ip, &em->uri_elts.ip,
		    sizeof (ip46_address_t));
  session->transport.rmt_port = em->uri_elts.port;

  echo_session_handle_add_del (em, mp->handle, session->session_index);
  em->proto_cb_vft->connected_cb ((session_connected_bundled_msg_t *) mp,
				  session->session_index, 0 /* is_failed */ );
}

/*
 *
 *  End of ECHO callback definitions
 *
 */

static void
session_disconnected_handler (session_disconnected_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_disconnected_reply_msg_t *rmp;
  echo_main_t *em = &echo_main;
  echo_session_t *s;
  if (!(s = echo_get_session_from_handle (em, mp->handle)))
    {
      ECHO_LOG (0, "Invalid vpp_session_handle: 0x%lx", mp->handle);
      return;
    }
  if (s->session_state == ECHO_SESSION_STATE_CLOSED)
    {
      ECHO_LOG (1, "%U: already in ECHO_SESSION_STATE_CLOSED",
		echo_format_session, s);
    }
  else
    {
      ECHO_LOG (1, "%U: passive close", echo_format_session, s);
      em->proto_cb_vft->disconnected_cb (mp, s);
    }
  app_alloc_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_DISCONNECTED_REPLY);
  rmp = (session_disconnected_reply_msg_t *) app_evt->evt->data;
  rmp->retval = 0;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  app_send_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt);
}

static void
session_reset_handler (session_reset_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  echo_main_t *em = &echo_main;
  session_reset_reply_msg_t *rmp;
  echo_session_t *s = 0;
  if (!(s = echo_get_session_from_handle (em, mp->handle)))
    {
      ECHO_LOG (0, "Invalid vpp_session_handle: 0x%lx", mp->handle);
      return;
    }
  ECHO_LOG (1, "%U: session reset", echo_format_session, s);
  em->proto_cb_vft->reset_cb (mp, s);

  app_alloc_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_RESET_REPLY);
  rmp = (session_reset_reply_msg_t *) app_evt->evt->data;
  rmp->retval = 0;
  rmp->handle = mp->handle;
  app_send_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt);
}

static void
handle_mq_event (session_event_t * e)
{
  switch (e->event_type)
    {
    case SESSION_CTRL_EVT_BOUND:
      return session_bound_handler ((session_bound_msg_t *) e->data);
    case SESSION_CTRL_EVT_ACCEPTED:
      return session_accepted_handler ((session_accepted_msg_t *) e->data);
    case SESSION_CTRL_EVT_CONNECTED:
      return session_connected_handler ((session_connected_msg_t *) e->data);
    case SESSION_CTRL_EVT_DISCONNECTED:
      return session_disconnected_handler ((session_disconnected_msg_t *)
					   e->data);
    case SESSION_CTRL_EVT_RESET:
      return session_reset_handler ((session_reset_msg_t *) e->data);
    case SESSION_CTRL_EVT_UNLISTEN_REPLY:
      return session_unlisten_handler ((session_unlisten_msg_t *) e->data);
    case SESSION_IO_EVT_RX:
      break;
    default:
      ECHO_LOG (0, "unhandled event %u", e->event_type);
    }
}

static void
echo_process_rpcs (echo_main_t * em)
{
  echo_rpc_msg_t *rpc;
  svm_msg_q_msg_t msg;
  svm_msg_q_t *mq = em->rpc_msq_queue;

  while (em->state < STATE_DATA_DONE && !em->time_to_stop)
    {
      svm_msg_q_lock (mq);
      if (svm_msg_q_is_empty (mq) && svm_msg_q_timedwait (mq, 1))
	{
	  svm_msg_q_unlock (mq);
	  continue;
	}
      svm_msg_q_sub_w_lock (mq, &msg);
      rpc = svm_msg_q_msg_data (mq, &msg);
      svm_msg_q_unlock (mq);
      ((echo_rpc_t) rpc->fp) (rpc->arg, rpc->opaque);
      svm_msg_q_free_msg (mq, &msg);
    }
}

static inline int
echo_mq_dequeue_batch (svm_msg_q_t * mq, svm_msg_q_msg_t * msg_vec,
		       u32 n_max_msg)
{
  svm_msg_q_msg_t *msg;
  u32 n_msgs;
  int i;

  n_msgs = clib_min (svm_msg_q_size (mq), n_max_msg);
  for (i = 0; i < n_msgs; i++)
    {
      vec_add2 (msg_vec, msg, 1);
      svm_msg_q_sub_w_lock (mq, msg);
    }
  return n_msgs;
}

static void *
echo_mq_thread_fn (void *arg)
{
  clib_mem_set_thread_index ();	/* First thing to do in client thread */
  svm_msg_q_msg_t *msg_vec = 0;
  echo_main_t *em = &echo_main;
  session_event_t *e;
  svm_msg_q_msg_t *msg;
  svm_msg_q_t *mq;
  int i;

  vec_validate (msg_vec, em->evt_q_size);
  vec_reset_length (msg_vec);
  wait_for_state_change (em, STATE_ATTACHED, 0);
  mq = em->app_mq;
  if (em->state < STATE_ATTACHED || !mq)
    {
      ECHO_FAIL (ECHO_FAIL_APP_ATTACH, "Application failed to attach");
      pthread_exit (0);
    }

  while (em->state < STATE_DETACHED && !em->time_to_stop)
    {
      svm_msg_q_lock (mq);
      if (svm_msg_q_is_empty (mq) && svm_msg_q_timedwait (mq, 1))
	{
	  svm_msg_q_unlock (mq);
	  continue;
	}
      echo_mq_dequeue_batch (mq, msg_vec, ~0);
      svm_msg_q_unlock (mq);

      for (i = 0; i < vec_len (msg_vec); i++)
	{
	  msg = vec_elt_at_index (msg_vec, i);
	  e = svm_msg_q_msg_data (mq, msg);
	  handle_mq_event (e);
	  svm_msg_q_free_msg (mq, msg);	/* No lock, single thread dequeuing */
	}
      vec_reset_length (msg_vec);
    }
  vec_free (msg_vec);
  pthread_exit (0);
}

static void
clients_run (echo_main_t * em)
{
  u64 i;
  echo_notify_event (em, ECHO_EVT_FIRST_QCONNECT);
  for (i = 0; i < em->n_connects; i++)
    echo_send_connect (SESSION_INVALID_HANDLE, SESSION_INVALID_INDEX);
  wait_for_state_change (em, STATE_READY, 0);
  ECHO_LOG (1, "App is ready");
  echo_process_rpcs (em);
}

static void
server_run (echo_main_t * em)
{
  echo_session_t *ls;
  echo_send_listen (em);
  wait_for_state_change (em, STATE_READY, 0);
  ECHO_LOG (1, "App is ready");
  echo_process_rpcs (em);
  /* Cleanup */
  ECHO_LOG (1, "Unbind listen port");
  ls = pool_elt_at_index (em->sessions, em->listen_session_index);
  echo_send_unbind (em, ls);
  if (wait_for_state_change (em, STATE_DISCONNECTED, TIMEOUT))
    {
      ECHO_FAIL (ECHO_FAIL_SERVER_DISCONNECT_TIMEOUT,
		 "Timeout waiting for state disconnected");
      return;
    }
}

static void
print_usage_and_exit (void)
{
  echo_main_t *em = &echo_main;
  int i;
  fprintf (stderr,
	   "Usage: vpp_echo [socket-name SOCKET] [client|server] [uri URI] [OPTIONS]\n"
	   "Generates traffic and assert correct teardown of the QUIC hoststack\n"
	   "\n"
	   "  socket-name PATH    Specify the binary socket path to connect to VPP\n"
	   "  use-svm-api         Use SVM API to connect to VPP\n"
	   "  test-bytes[:assert] Check data correctness when receiving (assert fails on first error)\n"
	   "  fifo-size N[K|M|G]  Use N[K|M|G] fifos\n"
	   "  mq-size N           Use N event slots for vpp_echo <-> vpp events\n"
	   "  rx-buf N[K|M|G]     Use N[Kb|Mb|GB] RX buffer\n"
	   "  tx-buf N[K|M|G]     Use N[Kb|Mb|GB] TX test buffer\n"
	   "  appns NAMESPACE     Use the namespace NAMESPACE\n"
	   "  all-scope           all-scope option\n"
	   "  local-scope         local-scope option\n"
	   "  global-scope        global-scope option\n"
	   "  secret SECRET       set namespace secret\n"
	   "  chroot prefix PATH  Use PATH as memory root path\n"
	   "  sclose=[Y|N|W]      When stream is done, send[Y]|nop[N]|wait[W] for close\n"
	   "\n"
	   "  time START:END      Time between evts START & END, events being :\n"
	   "                       start - Start of the app\n"
	   "                       qconnect    - first Connection connect sent\n"
	   "                       qconnected  - last Connection connected\n"
	   "                       sconnect    - first Stream connect sent\n"
	   "                       sconnected  - last Stream got connected\n"
	   "                       lastbyte    - Last expected byte received\n"
	   "                       exit        - Exiting of the app\n"
	   "  rx-results-diff     Rx results different to pass test\n"
	   "  tx-results-diff     Tx results different to pass test\n"
	   "  json                Output global stats in json\n"
	   "  log=N               Set the log level to [0: no output, 1:errors, 2:log]\n"
	   "  crypto [engine]     Set the crypto engine [openssl, vpp, picotls, mbedtls]\n"
	   "\n"
	   "  nclients N          Open N clients sending data\n"
	   "  nthreads N          Use N busy loop threads for data [in addition to main & msg queue]\n"
	   "  TX=1337[K|M|G]|RX   Send 1337 [K|M|G]bytes, use TX=RX to reflect the data\n"
	   "  RX=1337[K|M|G]      Expect 1337 [K|M|G]bytes\n" "\n");
  for (i = 0; i < TRANSPORT_N_PROTO; i++)
    {
      echo_proto_cb_vft_t *vft = em->available_proto_cb_vft[i];
      if (vft && vft->print_usage_cb)
	vft->print_usage_cb ();
    }
  fprintf (stderr, "\nDefault configuration is :\n"
	   " server nclients 1 [quic-streams 1] RX=64Kb TX=RX\n"
	   " client nclients 1 [quic-streams 1] RX=64Kb TX=64Kb\n");
  exit (ECHO_FAIL_USAGE);
}

static int
echo_process_each_proto_opts (unformat_input_t * a)
{
  echo_main_t *em = &echo_main;
  int i, rv;
  for (i = 0; i < TRANSPORT_N_PROTO; i++)
    {
      echo_proto_cb_vft_t *vft = em->available_proto_cb_vft[i];
      if (vft && vft->process_opts_cb)
	if ((rv = vft->process_opts_cb (a)))
	  return rv;
    }
  return 0;
}

static void
echo_set_each_proto_defaults_before_opts (echo_main_t * em)
{
  int i;
  for (i = 0; i < TRANSPORT_N_PROTO; i++)
    {
      echo_proto_cb_vft_t *vft = em->available_proto_cb_vft[i];
      if (vft && vft->set_defaults_before_opts_cb)
	vft->set_defaults_before_opts_cb ();
    }
}

void
echo_process_opts (int argc, char **argv)
{
  echo_main_t *em = &echo_main;
  unformat_input_t _argv, *a = &_argv;
  u8 *chroot_prefix;
  u8 *uri = 0;
  u8 default_f_active;
  uword tmp;

  unformat_init_command_line (a, argv);
  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (echo_process_each_proto_opts (a))
	;
      else if (unformat (a, "chroot prefix %s", &chroot_prefix))
	vl_set_memory_root_path ((char *) chroot_prefix);
      else if (unformat (a, "uri %s", &uri))
	em->uri = format (0, "%s%c", uri, 0);
      else if (unformat (a, "server"))
	em->i_am_master = 1;
      else if (unformat (a, "client"))
	em->i_am_master = 0;
      else if (unformat (a, "test-bytes:assert"))
	em->test_return_packets = RETURN_PACKETS_ASSERT;
      else if (unformat (a, "test-bytes"))
	em->test_return_packets = RETURN_PACKETS_LOG_WRONG;
      else if (unformat (a, "socket-name %s", &em->socket_name))
	;
      else if (unformat (a, "use-svm-api"))
	em->use_sock_api = 0;
      else if (unformat (a, "fifo-size %U", unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    {
	      fprintf (stderr,
		       "ERROR: fifo-size %ld (0x%lx) too large\n", tmp, tmp);
	      print_usage_and_exit ();
	    }
	  em->fifo_size = tmp;
	}
      else if (unformat (a, "prealloc-fifos %u", &em->prealloc_fifo_pairs))
	;
      else
	if (unformat (a, "rx-buf %U", unformat_data_size, &em->rx_buf_size))
	;
      else
	if (unformat (a, "tx-buf %U", unformat_data_size, &em->tx_buf_size))
	;
      else if (unformat (a, "mq-size %d", &em->evt_q_size))
	;
      else if (unformat (a, "nclients %d", &em->n_clients))
	{
	  em->n_sessions = em->n_clients + 1;
	  em->n_connects = em->n_clients;
	}
      else if (unformat (a, "nthreads %d", &em->n_rx_threads))
	;
      else if (unformat (a, "crypto %U", echo_unformat_crypto_engine, &tmp))
	em->crypto_engine = tmp;
      else if (unformat (a, "appns %_%v%_", &em->appns_id))
	;
      else if (unformat (a, "all-scope"))
	em->appns_flags |= (APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE
			    | APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE);
      else if (unformat (a, "local-scope"))
	em->appns_flags = APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
      else if (unformat (a, "global-scope"))
	em->appns_flags = APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
      else if (unformat (a, "secret %lu", &em->appns_secret))
	;
      else if (unformat (a, "TX=RX"))
	em->data_source = ECHO_RX_DATA_SOURCE;
      else if (unformat (a, "TX=%U", unformat_data_size, &em->bytes_to_send))
	;
      else if (unformat (a, "RX=%U", unformat_data_size,
			 &em->bytes_to_receive))
	;
      else if (unformat (a, "rx-results-diff"))
	em->rx_results_diff = 1;
      else if (unformat (a, "tx-results-diff"))
	em->tx_results_diff = 1;
      else if (unformat (a, "json"))
	em->output_json = 1;
      else if (unformat (a, "wait-for-gdb"))
	em->wait_for_gdb = 1;
      else if (unformat (a, "log=%d", &em->log_lvl))
	;
      else if (unformat (a, "sclose=%U",
			 echo_unformat_close, &em->send_stream_disconnects))
	;
      else if (unformat (a, "time %U:%U",
			 echo_unformat_timing_event, &em->timing.start_event,
			 echo_unformat_timing_event, &em->timing.end_event))
	;
      else
	print_usage_and_exit ();
    }

  /* setting default for unset values
   *
   * bytes_to_send / bytes_to_receive & data_source  */
  if (em->bytes_to_receive == (u64) ~ 0)
    em->bytes_to_receive = 64 << 10;	/* default */
  if (em->bytes_to_send == (u64) ~ 0)
    em->bytes_to_send = 64 << 10;	/* default */
  else if (em->bytes_to_send == 0)
    em->data_source = ECHO_NO_DATA_SOURCE;
  else
    em->data_source = ECHO_TEST_DATA_SOURCE;

  if (em->data_source == ECHO_INVALID_DATA_SOURCE)
    em->data_source =
      em->i_am_master ? ECHO_RX_DATA_SOURCE : ECHO_TEST_DATA_SOURCE;
  if (em->data_source == ECHO_RX_DATA_SOURCE)
    em->bytes_to_send = em->bytes_to_receive;

  /* disconnect flags  */
  if (em->i_am_master)
    default_f_active =
      em->bytes_to_send == 0 ? ECHO_CLOSE_F_ACTIVE : ECHO_CLOSE_F_PASSIVE;
  else
    default_f_active =
      em->bytes_to_receive == 0 ? ECHO_CLOSE_F_PASSIVE : ECHO_CLOSE_F_ACTIVE;
  if (em->send_stream_disconnects == ECHO_CLOSE_F_INVALID)
    em->send_stream_disconnects = default_f_active;

  if (em->wait_for_gdb)
    {
      volatile u64 nop = 0;

      clib_warning ("Waiting for gdb...");
      while (em->wait_for_gdb)
	nop++;
      clib_warning ("Resuming execution (%llu)!", nop);
    }
}

void
echo_process_uri (echo_main_t * em)
{
  unformat_input_t _input, *input = &_input;
  u32 port;
  unformat_init_string (input, (char *) em->uri, strlen ((char *) em->uri));
  if (unformat
      (input, "%U://%U/%d", unformat_transport_proto,
       &em->uri_elts.transport_proto, unformat_ip4_address,
       &em->uri_elts.ip.ip4, &port))
    em->uri_elts.is_ip4 = 1;
  else
    if (unformat
	(input, "%U://%U/%d", unformat_transport_proto,
	 &em->uri_elts.transport_proto, unformat_ip6_address,
	 &em->uri_elts.ip.ip6, &port))
    em->uri_elts.is_ip4 = 0;
  else
    ECHO_FAIL (ECHO_FAIL_INVALID_URI, "Unable to process uri");
  em->uri_elts.port = clib_host_to_net_u16 (port);
  unformat_free (input);
}

static void __clib_constructor
vpp_echo_init ()
{
  /* init memory before proto register themselves */
  echo_main_t *em = &echo_main;
  clib_mem_init_thread_safe (0, 256 << 20);
  clib_memset (em, 0, sizeof (*em));
}

int
main (int argc, char **argv)
{
  echo_main_t *em = &echo_main;
  fifo_segment_main_t *sm = &em->segment_main;
  char *app_name;
  u64 i;
  svm_msg_q_cfg_t _cfg, *cfg = &_cfg;
  u32 rpc_queue_size = 64 << 10;

  em->session_index_by_vpp_handles = hash_create (0, sizeof (uword));
  clib_spinlock_init (&em->sid_vpp_handles_lock);
  em->shared_segment_handles = hash_create (0, sizeof (uword));
  clib_spinlock_init (&em->segment_handles_lock);
  em->socket_name = format (0, "%s%c", API_SOCKET_FILE, 0);
  em->use_sock_api = 1;
  em->fifo_size = 64 << 10;
  em->prealloc_fifo_pairs = 16;
  em->n_clients = 1;
  em->n_connects = 1;
  em->n_sessions = 2;
  em->max_test_msg = 50;
  em->time_to_stop = 0;
  em->i_am_master = 1;
  em->n_rx_threads = 4;
  em->evt_q_size = 256;
  em->test_return_packets = RETURN_PACKETS_NOTEST;
  em->timing.start_event = ECHO_EVT_FIRST_QCONNECT;
  em->timing.end_event = ECHO_EVT_LAST_BYTE;
  em->bytes_to_receive = ~0;	/* defaulted when we know if server/client */
  em->bytes_to_send = ~0;	/* defaulted when we know if server/client */
  em->rx_buf_size = 1 << 20;
  em->tx_buf_size = 1 << 20;
  em->data_source = ECHO_INVALID_DATA_SOURCE;
  em->uri = format (0, "%s%c", "tcp://0.0.0.0/1234", 0);
  em->crypto_engine = CRYPTO_ENGINE_NONE;
  echo_set_each_proto_defaults_before_opts (em);
  echo_process_opts (argc, argv);
  echo_process_uri (em);
  em->proto_cb_vft = em->available_proto_cb_vft[em->uri_elts.transport_proto];
  if (!em->proto_cb_vft)
    {
      ECHO_FAIL (ECHO_FAIL_PROTOCOL_NOT_SUPPORTED,
		 "Protocol %U is not supported",
		 format_transport_proto, em->uri_elts.transport_proto);
      goto exit_on_error;
    }
  if (em->proto_cb_vft->set_defaults_after_opts_cb)
    em->proto_cb_vft->set_defaults_after_opts_cb ();

  em->stats.rx_expected = em->bytes_to_receive * em->n_clients;
  em->stats.tx_expected = em->bytes_to_send * em->n_clients;

  vec_validate (em->data_thread_handles, em->n_rx_threads);
  vec_validate (em->data_thread_args, em->n_clients);
  for (i = 0; i < em->n_clients; i++)
    em->data_thread_args[i] = SESSION_INVALID_INDEX;
  clib_time_init (&em->clib_time);
  init_error_string_table ();
  fifo_segment_main_init (sm, HIGH_SEGMENT_BASEVA, 20);
  vec_validate (em->connect_test_data, em->tx_buf_size);
  for (i = 0; i < em->tx_buf_size; i++)
    em->connect_test_data[i] = i & 0xff;

  /* *INDENT-OFF* */
  svm_msg_q_ring_cfg_t rc[1] = {
    {rpc_queue_size, sizeof (echo_rpc_msg_t), 0},
  };
  /* *INDENT-ON* */
  cfg->consumer_pid = getpid ();
  cfg->n_rings = 1;
  cfg->q_nitems = rpc_queue_size;
  cfg->ring_cfgs = rc;
  em->rpc_msq_queue = svm_msg_q_alloc (cfg);

  signal (SIGINT, stop_signal);
  signal (SIGQUIT, stop_signal);
  signal (SIGTERM, stop_signal);
  echo_api_hookup (em);

  app_name = em->i_am_master ? "echo_server" : "echo_client";
  if (connect_to_vpp (app_name))
    {
      svm_region_exit ();
      ECHO_FAIL (ECHO_FAIL_CONNECT_TO_VPP, "Couldn't connect to vpp");
      goto exit_on_error;
    }

  echo_session_prealloc (em);
  echo_notify_event (em, ECHO_EVT_START);

  echo_send_attach (em);
  if (wait_for_state_change (em, STATE_ATTACHED_NO_CERT, TIMEOUT))
    {
      ECHO_FAIL (ECHO_FAIL_ATTACH_TO_VPP,
		 "Couldn't attach to vpp, did you run <session enable> ?");
      goto exit_on_error;
    }

  if (em->uri_elts.transport_proto != TRANSPORT_PROTO_QUIC
      && em->uri_elts.transport_proto != TRANSPORT_PROTO_TLS)
    em->state = STATE_ATTACHED;
  else
    {
      ECHO_LOG (1, "Adding crypto context %U", echo_format_crypto_engine,
		em->crypto_engine);
      echo_send_add_cert_key (em);
      if (wait_for_state_change (em, STATE_ATTACHED, TIMEOUT))
	{
	  ECHO_FAIL (ECHO_FAIL_APP_ATTACH,
		     "Couldn't add crypto context to vpp\n");
	  exit (1);
	}
    }

  if (pthread_create (&em->mq_thread_handle,
		      NULL /*attr */ , echo_mq_thread_fn, 0))
    {
      ECHO_FAIL (ECHO_FAIL_PTHREAD_CREATE, "pthread create errored");
      goto exit_on_error;
    }

  for (i = 0; i < em->n_rx_threads; i++)
    if (pthread_create (&em->data_thread_handles[i],
			NULL /*attr */ , echo_data_thread_fn, (void *) i))
      {
	ECHO_FAIL (ECHO_FAIL_PTHREAD_CREATE,
		   "pthread create errored (index %d)", i);
	goto exit_on_error;
      }
  if (em->i_am_master)
    server_run (em);
  else
    clients_run (em);
  echo_notify_event (em, ECHO_EVT_EXIT);
  echo_free_sessions (em);
  echo_send_del_cert_key (em);
  if (wait_for_state_change (em, STATE_CLEANED_CERT_KEY, TIMEOUT))
    {
      ECHO_FAIL (ECHO_FAIL_DEL_CERT_KEY, "Couldn't cleanup cert and key");
      goto exit_on_error;
    }

  echo_send_detach (em);
  if (wait_for_state_change (em, STATE_DETACHED, TIMEOUT))
    {
      ECHO_FAIL (ECHO_FAIL_DETACH, "Couldn't detach from vpp");
      goto exit_on_error;
    }
  int *rv;
  pthread_join (em->mq_thread_handle, (void **) &rv);
  if (rv)
    {
      ECHO_FAIL (ECHO_FAIL_MQ_PTHREAD, "mq pthread errored %d", rv);
      goto exit_on_error;
    }
  if (em->use_sock_api)
    vl_socket_client_disconnect ();
  else
    vl_client_disconnect_from_vlib ();
  echo_assert_test_suceeded (em);
exit_on_error:
  ECHO_LOG (0, "Test complete !\n");
  if (em->output_json)
    print_global_json_stats (em);
  else
    print_global_stats (em);
  vec_free (em->fail_descr);
  exit (em->has_failed);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
