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

#include <vpp/api/vpe_msg_enum.h>
#include <svm/fifo_segment.h>
#include <hs_apps/sapi/quic_echo.h>
#include <hs_apps/sapi/echo_common.c>

echo_main_t echo_main;

/*
 *
 *  Format functions
 *
 */

u8 *
format_quic_echo_state (u8 * s, va_list * args)
{
  u32 state = va_arg (*args, u32);
  if (state == STATE_START)
    return format (s, "STATE_START");
  if (state == STATE_ATTACHED)
    return format (s, "STATE_ATTACHED");
  if (state == STATE_LISTEN)
    return format (s, "STATE_LISTEN");
  if (state == STATE_READY)
    return format (s, "STATE_READY");
  if (state == STATE_DATA_DONE)
    return format (s, "STATE_DATA_DONE");
  if (state == STATE_DISCONNECTED)
    return format (s, "STATE_DISCONNECTED");
  if (state == STATE_DETACHED)
    return format (s, "STATE_DETACHED");
  else
    return format (s, "unknown state");
}

static uword
unformat_close (unformat_input_t * input, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  if (unformat (input, "Y"))
    *a = ECHO_CLOSE_F_ACTIVE;
  else if (unformat (input, "N"))
    *a = ECHO_CLOSE_F_NONE;
  else if (unformat (input, "W"))
    *a = ECHO_CLOSE_F_PASSIVE;
  else
    return 0;
  return 1;
}

static uword
echo_unformat_timing_event (unformat_input_t * input, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  if (unformat (input, "start"))
    *a = ECHO_EVT_START;
  else if (unformat (input, "qconnected"))
    *a = ECHO_EVT_LAST_QCONNECTED;
  else if (unformat (input, "qconnect"))
    *a = ECHO_EVT_FIRST_QCONNECT;
  else if (unformat (input, "sconnected"))
    *a = ECHO_EVT_LAST_SCONNECTED;
  else if (unformat (input, "sconnect"))
    *a = ECHO_EVT_FIRST_SCONNECT;
  else if (unformat (input, "lastbyte"))
    *a = ECHO_EVT_LAST_BYTE;
  else if (unformat (input, "exit"))
    *a = ECHO_EVT_EXIT;
  else
    return 0;
  return 1;
}

u8 *
echo_format_timing_event (u8 * s, va_list * args)
{
  u32 timing_event = va_arg (*args, u32);
  if (timing_event == ECHO_EVT_START)
    return format (s, "start");
  if (timing_event == ECHO_EVT_FIRST_QCONNECT)
    return format (s, "qconnect");
  if (timing_event == ECHO_EVT_LAST_QCONNECTED)
    return format (s, "qconnected");
  if (timing_event == ECHO_EVT_FIRST_SCONNECT)
    return format (s, "sconnect");
  if (timing_event == ECHO_EVT_LAST_SCONNECTED)
    return format (s, "sconnected");
  if (timing_event == ECHO_EVT_LAST_BYTE)
    return format (s, "lastbyte");
  if (timing_event == ECHO_EVT_EXIT)
    return format (s, "exit");
  else
    return format (s, "unknown timing event");
}

/*
 *
 *  End of format functions
 *
 */

static void
echo_session_prealloc (echo_main_t * em)
{
  /* We need to prealloc to avoid vec resize in threads */
  echo_session_t *session;
  int n_sessions = em->n_clients * (em->n_stream_clients + 1)
    + em->i_am_master;
  int i;
  for (i = 0; i < n_sessions; i++)
    {
      pool_get (em->sessions, session);
      clib_memset (session, 0, sizeof (*session));
      session->session_index = session - em->sessions;
      session->listener_index = SESSION_INVALID_INDEX;
      session->session_state = QUIC_SESSION_STATE_INITIAL;
    }
}

static echo_session_t *
echo_session_new (echo_main_t * em)
{
  /* thread safe new prealloced session */
  return pool_elt_at_index (em->sessions,
			    clib_atomic_fetch_add (&em->nxt_available_sidx,
						   1));
}


static int
echo_send_rpc (echo_main_t * em, void *fp, void *arg, u32 opaque)
{
  svm_msg_q_msg_t msg;
  echo_rpc_msg_t *evt;
  if (PREDICT_FALSE (svm_msg_q_lock (em->rpc_msq_queue)))
    {
      ECHO_LOG (1, "RPC lock failed");
      return -1;
    }
  if (PREDICT_FALSE (svm_msg_q_ring_is_full (em->rpc_msq_queue, 0)))
    {
      svm_msg_q_unlock (em->rpc_msq_queue);
      ECHO_LOG (1, "RPC ring is full");
      return -2;
    }
  msg = svm_msg_q_alloc_msg_w_ring (em->rpc_msq_queue, 0);
  if (PREDICT_FALSE (svm_msg_q_msg_is_invalid (&msg)))
    {
      ECHO_LOG (1, "RPC msg is invalid");
      svm_msg_q_unlock (em->rpc_msq_queue);
      return -2;
    }
  evt = (echo_rpc_msg_t *) svm_msg_q_msg_data (em->rpc_msq_queue, &msg);
  evt->arg = arg;
  evt->opaque = opaque;
  evt->fp = fp;

  svm_msg_q_add_and_unlock (em->rpc_msq_queue, &msg);
  return 0;
}

static inline void
echo_segment_handle_add_del (echo_main_t * em, u64 segment_handle, u8 add)
{
  clib_spinlock_lock (&em->segment_handles_lock);
  if (add)
    hash_set (em->shared_segment_handles, segment_handle, 1);
  else
    hash_unset (em->shared_segment_handles, segment_handle);
  clib_spinlock_unlock (&em->segment_handles_lock);
}

static inline void
echo_session_handle_add_del (echo_main_t * em, u64 handle, u32 sid)
{
  clib_spinlock_lock (&em->sid_vpp_handles_lock);
  if (sid == SESSION_INVALID_INDEX)
    hash_unset (em->session_index_by_vpp_handles, handle);
  else
    hash_set (em->session_index_by_vpp_handles, handle, sid);
  clib_spinlock_unlock (&em->sid_vpp_handles_lock);
}

static inline echo_session_t *
echo_get_session_from_handle (echo_main_t * em, u64 handle)
{
  uword *p;
  clib_spinlock_lock (&em->sid_vpp_handles_lock);
  p = hash_get (em->session_index_by_vpp_handles, handle);
  clib_spinlock_unlock (&em->sid_vpp_handles_lock);
  if (!p)
    {
      ECHO_FAIL ("unknown handle 0x%lx", handle);
      return 0;
    }
  return pool_elt_at_index (em->sessions, p[0]);
}

/*
 *
 *  Session API Calls
 *
 */

void
application_send_attach (echo_main_t * em)
{
  vl_api_application_attach_t *bmp;
  vl_api_application_tls_cert_add_t *cert_mp;
  vl_api_application_tls_key_add_t *key_mp;

  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_ATTACH);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_ACCEPT_REDIRECT;
  bmp->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_ADD_SEGMENT;
  bmp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 16;
  bmp->options[APP_OPTIONS_RX_FIFO_SIZE] = em->fifo_size;
  bmp->options[APP_OPTIONS_TX_FIFO_SIZE] = em->fifo_size;
  bmp->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  bmp->options[APP_OPTIONS_SEGMENT_SIZE] = 256 << 20;
  bmp->options[APP_OPTIONS_EVT_QUEUE_SIZE] = 256;
  if (em->appns_id)
    {
      bmp->namespace_id_len = vec_len (em->appns_id);
      clib_memcpy_fast (bmp->namespace_id, em->appns_id,
			bmp->namespace_id_len);
      bmp->options[APP_OPTIONS_FLAGS] |= em->appns_flags;
      bmp->options[APP_OPTIONS_NAMESPACE_SECRET] = em->appns_secret;
    }
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);

  cert_mp = vl_msg_api_alloc (sizeof (*cert_mp) + test_srv_crt_rsa_len);
  clib_memset (cert_mp, 0, sizeof (*cert_mp));
  cert_mp->_vl_msg_id = ntohs (VL_API_APPLICATION_TLS_CERT_ADD);
  cert_mp->client_index = em->my_client_index;
  cert_mp->context = ntohl (0xfeedface);
  cert_mp->cert_len = clib_host_to_net_u16 (test_srv_crt_rsa_len);
  clib_memcpy_fast (cert_mp->cert, test_srv_crt_rsa, test_srv_crt_rsa_len);
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & cert_mp);

  key_mp = vl_msg_api_alloc (sizeof (*key_mp) + test_srv_key_rsa_len);
  clib_memset (key_mp, 0, sizeof (*key_mp) + test_srv_key_rsa_len);
  key_mp->_vl_msg_id = ntohs (VL_API_APPLICATION_TLS_KEY_ADD);
  key_mp->client_index = em->my_client_index;
  key_mp->context = ntohl (0xfeedface);
  key_mp->key_len = clib_host_to_net_u16 (test_srv_key_rsa_len);
  clib_memcpy_fast (key_mp->key, test_srv_key_rsa, test_srv_key_rsa_len);
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & key_mp);
}

void
application_detach (echo_main_t * em)
{
  vl_api_application_detach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_DETACH);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);
}

static void
server_send_listen (echo_main_t * em)
{
  vl_api_bind_uri_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_BIND_URI);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  memcpy (bmp->uri, em->uri, vec_len (em->uri));
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);
}

static void
server_send_unbind (echo_main_t * em)
{
  vl_api_unbind_uri_t *ump;

  ump = vl_msg_api_alloc (sizeof (*ump));
  clib_memset (ump, 0, sizeof (*ump));

  ump->_vl_msg_id = ntohs (VL_API_UNBIND_URI);
  ump->client_index = em->my_client_index;
  memcpy (ump->uri, em->uri, vec_len (em->uri));
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & ump);
}

static void
echo_send_connect (u8 * uri, u32 opaque)
{
  echo_main_t *em = &echo_main;
  vl_api_connect_uri_t *cmp;
  cmp = vl_msg_api_alloc (sizeof (*cmp));
  clib_memset (cmp, 0, sizeof (*cmp));
  cmp->_vl_msg_id = ntohs (VL_API_CONNECT_URI);
  cmp->client_index = em->my_client_index;
  cmp->context = ntohl (opaque);
  memcpy (cmp->uri, uri, vec_len (uri));
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & cmp);
}

static void
echo_disconnect_session (echo_session_t * s, u32 opaque)
{
  echo_main_t *em = &echo_main;
  vl_api_disconnect_session_t *dmp;
  dmp = vl_msg_api_alloc (sizeof (*dmp));
  clib_memset (dmp, 0, sizeof (*dmp));
  dmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION);
  dmp->client_index = em->my_client_index;
  dmp->handle = s->vpp_session_handle;
  ECHO_LOG (1, "Disconnect session 0x%lx", dmp->handle);
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & dmp);
}

/*
 *
 *  End Session API Calls
 *
 */

static int
wait_for_segment_allocation (u64 segment_handle)
{
  echo_main_t *em = &echo_main;
  f64 timeout;
  timeout = clib_time_now (&em->clib_time) + TIMEOUT;
  uword *segment_present;
  ECHO_LOG (1, "Waiting for segment 0x%lx...", segment_handle);
  while (clib_time_now (&em->clib_time) < timeout)
    {
      clib_spinlock_lock (&em->segment_handles_lock);
      segment_present = hash_get (em->shared_segment_handles, segment_handle);
      clib_spinlock_unlock (&em->segment_handles_lock);
      if (segment_present != 0)
	return 0;
      if (em->time_to_stop == 1)
	return 0;
    }
  ECHO_LOG (1, "timeout wait_for_segment_allocation (0x%lx)", segment_handle);
  return -1;
}

static void
quic_echo_notify_event (echo_main_t * em, echo_test_evt_t e)
{
  if (em->timing.events_sent & e)
    return;
  if (em->timing.start_event == e)
    em->timing.start_time = clib_time_now (&em->clib_time);
  else if (em->timing.end_event == e)
    em->timing.end_time = clib_time_now (&em->clib_time);
  em->timing.events_sent |= e;
}

static void
echo_assert_test_suceeded (echo_main_t * em)
{
  CHECK (em->n_stream_clients * em->n_clients * em->bytes_to_receive,
	 em->stats.rx_total, "Not enough data received");
  CHECK (em->n_stream_clients * em->n_clients * em->bytes_to_send,
	 em->stats.tx_total, "Not enough data sent");
  clib_spinlock_lock (&em->sid_vpp_handles_lock);
  CHECK (0, hash_elts (em->session_index_by_vpp_handles),
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
    ECHO_FAIL ("app_send_io_evt_to_vpp errored %d", rv);
  svm_fifo_clear_deq_ntf (s->rx_fifo);
}

static int
ssvm_segment_attach (char *name, ssvm_segment_type_t type, int fd)
{
  fifo_segment_create_args_t _a, *a = &_a;
  fifo_segment_main_t *sm = &echo_main.segment_main;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->segment_name = (char *) name;
  a->segment_type = type;

  if (type == SSVM_SEGMENT_MEMFD)
    a->memfd_fd = fd;

  if ((rv = fifo_segment_attach (sm, a)))
    return rv;
  vec_reset_length (a->new_segment_indices);
  return 0;
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
	  ECHO_FAIL ("socket connect failed");
	  return -1;
	}

      if (vl_socket_client_init_shm (0, 1 /* want_pthread */ ))
	{
	  ECHO_FAIL ("init shm api failed");
	  return -1;
	}
    }
  else
    {
      if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0)
	{
	  ECHO_FAIL ("shmem connect failed");
	  return -1;
	}
    }
  em->vl_input_queue = am->shmem_hdr->vl_input_queue;
  em->my_client_index = am->my_client_index;
  return 0;
}

static void
session_print_stats (echo_main_t * em, echo_session_t * session)
{
  f64 deltat = clib_time_now (&em->clib_time) - session->start;
  ECHO_LOG (0, "Session 0x%x done in %.6fs RX[%.4f] TX[%.4f] Gbit/s\n",
	    session->vpp_session_handle, deltat,
	    (session->bytes_received * 8.0) / deltat / 1e9,
	    (session->bytes_sent * 8.0) / deltat / 1e9);
}

static void
echo_event_didnt_happen (u8 e)
{
  echo_main_t *em = &echo_main;
  u8 *s = format (0, "%U", echo_format_timing_event, e);
  ECHO_LOG (0, "Expected event %s to happend, which did not", s);
  em->has_failed = 1;
}

static void
print_global_json_stats (echo_main_t * em)
{
  if (!(em->timing.events_sent & em->timing.start_event))
    return echo_event_didnt_happen (em->timing.start_event);
  if (!(em->timing.events_sent & em->timing.end_event))
    return echo_event_didnt_happen (em->timing.end_event);
  f64 deltat = em->timing.end_time - em->timing.start_time;
  u8 *start_evt =
    format (0, "%U", echo_format_timing_event, em->timing.start_event);
  u8 *end_evt =
    format (0, "%U", echo_format_timing_event, em->timing.end_event);
  fformat (stdout, "{\n");
  fformat (stdout, "\"time\": \"%.9f\",\n", deltat);
  fformat (stdout, "\"start_evt\": \"%s\",\n", start_evt);
  fformat (stdout, "\"end_evt\": \"%s\",\n", end_evt);
  fformat (stdout, "\"rx_data\": %lld,\n", em->stats.rx_total);
  fformat (stdout, "\"tx_rx\": %lld,\n", em->stats.tx_total);
  fformat (stdout, "\"closing\": {\n");
  fformat (stdout, "  \"reset\": { \"q\": %d, \"s\": %d },\n",
	   em->stats.reset_count.q, em->stats.reset_count.s);
  fformat (stdout, "  \"close\": { \"q\": %d, \"s\": %d },\n",
	   em->stats.close_count.q, em->stats.close_count.s);
  fformat (stdout, "  \"active\": { \"q\": %d, \"s\": %d },\n",
	   em->stats.active_count.q, em->stats.active_count.s);
  fformat (stdout, "  \"clean\": { \"q\": %d, \"s\": %d }\n",
	   em->stats.clean_count.q, em->stats.clean_count.s);
  fformat (stdout, "}\n");
  fformat (stdout, "}\n");
}

static void
print_global_stats (echo_main_t * em)
{
  u8 *s;
  if (!(em->timing.events_sent & em->timing.start_event))
    return echo_event_didnt_happen (em->timing.start_event);
  if (!(em->timing.events_sent & em->timing.end_event))
    return echo_event_didnt_happen (em->timing.end_event);
  f64 deltat = em->timing.end_time - em->timing.start_time;
  s = format (0, "%U:%U",
	      echo_format_timing_event, em->timing.start_event,
	      echo_format_timing_event, em->timing.end_event);
  fformat (stdout, "Timing %s\n", s);
  fformat (stdout, "-------- TX --------\n");
  fformat (stdout, "%lld bytes (%lld mbytes, %lld gbytes) in %.6f seconds\n",
	   em->stats.tx_total, em->stats.tx_total / (1ULL << 20),
	   em->stats.tx_total / (1ULL << 30), deltat);
  fformat (stdout, "%.4f Gbit/second\n",
	   (em->stats.tx_total * 8.0) / deltat / 1e9);
  fformat (stdout, "-------- RX --------\n");
  fformat (stdout, "%lld bytes (%lld mbytes, %lld gbytes) in %.6f seconds\n",
	   em->stats.rx_total, em->stats.rx_total / (1ULL << 20),
	   em->stats.rx_total / (1ULL << 30), deltat);
  fformat (stdout, "%.4f Gbit/second\n",
	   (em->stats.rx_total * 8.0) / deltat / 1e9);
  fformat (stdout, "--------------------\n");
  fformat (stdout, "Received close on %dQ %dS\n", em->stats.close_count.q,
	   em->stats.close_count.s);
  fformat (stdout, "Received reset on %dQ %dS\n", em->stats.reset_count.q,
	   em->stats.reset_count.s);
  fformat (stdout, "Sent close on     %dQ %dS\n", em->stats.active_count.q,
	   em->stats.active_count.s);
  fformat (stdout, "Discarded         %dQ %dS\n", em->stats.clean_count.q,
	   em->stats.clean_count.s);
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
    if (s->session_state == QUIC_SESSION_STATE_CLOSED)
      vec_add1 (session_indexes, s->session_index);}
  ));
  /* *INDENT-ON* */
  vec_foreach (session_index, session_indexes)
  {
    /* Free session */
    s = pool_elt_at_index (em->sessions, *session_index);
    echo_session_handle_add_del (em, s->vpp_session_handle,
				 SESSION_INVALID_INDEX);
    pool_put (em->sessions, s);
    clib_memset (s, 0xfe, sizeof (*s));
  }
}

static void
echo_cleanup_session (echo_main_t * em, echo_session_t * s)
{
  echo_session_t *ls;
  ASSERT (s->session_state < QUIC_SESSION_STATE_CLOSED);
  if (s->session_type == QUIC_SESSION_TYPE_QUIC)
    {
      clib_atomic_sub_fetch (&em->n_quic_clients_connected, 1);
    }
  else if (s->session_type == QUIC_SESSION_TYPE_STREAM)
    {
      ls = pool_elt_at_index (em->sessions, s->listener_index);
      ASSERT (ls->session_type == QUIC_SESSION_TYPE_QUIC);
      if (!clib_atomic_sub_fetch (&ls->accepted_session_count, 1))
	{
	  if (em->send_quic_disconnects == ECHO_CLOSE_F_ACTIVE)
	    {
	      echo_send_rpc (em, echo_disconnect_session, (void *) ls, 0);
	      em->stats.active_count.q++;
	    }
	  else if (em->send_quic_disconnects == ECHO_CLOSE_F_NONE)
	    {
	      echo_cleanup_session (em, ls);
	      em->stats.clean_count.q++;
	    }
	}
      clib_atomic_sub_fetch (&em->n_clients_connected, 1);
    }
  ECHO_LOG (1, "Cleanup sessions (still %uQ %uS)",
	    em->n_quic_clients_connected, em->n_clients_connected);
  s->session_state = QUIC_SESSION_STATE_CLOSED;
}

static void
echo_initiate_qsession_close_no_stream (echo_main_t * em)
{
  ECHO_LOG (1, "Closing Qsessions");
  /* Close Quic session without streams */
  echo_session_t *s;

  /* *INDENT-OFF* */
  pool_foreach (s, em->sessions,
  ({
    if (s->session_type == QUIC_SESSION_TYPE_QUIC)
      {
	ECHO_LOG (1,"ACTIVE close 0x%lx", s->vpp_session_handle);
        if (em->send_quic_disconnects == ECHO_CLOSE_F_ACTIVE)
          {
	    echo_send_rpc (em, echo_disconnect_session, (void *) s, 0);
	    em->stats.active_count.q++;
          }
	else if (em->send_quic_disconnects == ECHO_CLOSE_F_NONE)
	  {
	    echo_cleanup_session (em, s);
	    em->stats.clean_count.q++;
	  }
      }
  }));
  /* *INDENT-ON* */
  em->state = STATE_DATA_DONE;
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
	ECHO_FAIL ("test-bytes errored");
    }
}

static int
recv_data_chunk (echo_main_t * em, echo_session_t * s, u8 * rx_buf)
{
  int n_read;
  n_read = app_recv_stream ((app_session_t *) s, rx_buf, vec_len (rx_buf));
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
  n_sent = app_send_stream ((app_session_t *) s, tx_buf + offset,
			    bytes_this_chunk, 0);
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

static void
echo_update_count_on_session_close (echo_main_t * em, echo_session_t * s)
{

  ECHO_LOG (1, "[%lu/%lu] -> S(%x) -> [%lu/%lu]",
	    s->bytes_received, s->bytes_received + s->bytes_to_receive,
	    s->session_index, s->bytes_sent,
	    s->bytes_sent + s->bytes_to_send);
  clib_atomic_fetch_add (&em->stats.tx_total, s->bytes_sent);
  clib_atomic_fetch_add (&em->stats.rx_total, s->bytes_received);

  if (PREDICT_FALSE (em->stats.rx_total ==
		     em->n_clients * em->n_stream_clients *
		     em->bytes_to_receive))
    quic_echo_notify_event (em, ECHO_EVT_LAST_BYTE);
}

static inline void
echo_check_closed_listener (echo_main_t * em, echo_session_t * s)
{
  echo_session_t *ls;
  /* if parent has died, terminate gracefully */
  ls = pool_elt_at_index (em->sessions, s->listener_index);
  if (ls->session_state < QUIC_SESSION_STATE_CLOSING)
    return;
  ECHO_LOG (2, "Session 0%lx died, close child 0x%lx", ls->vpp_session_handle,
	    s->vpp_session_handle);
  clib_atomic_sub_fetch (&em->n_clients_connected, 1);
  em->stats.clean_count.s++;
  echo_update_count_on_session_close (em, s);
  s->session_state = QUIC_SESSION_STATE_CLOSED;
}

/*
 * Rx/Tx polling thread per connection
 */
static void
echo_handle_data (echo_main_t * em, echo_session_t * s, u8 * rx_buf)
{
  int n_read, n_sent = 0;

  n_read = recv_data_chunk (em, s, rx_buf);
  if (em->data_source == ECHO_TEST_DATA_SOURCE)
    n_sent = send_data_chunk (s, em->connect_test_data,
			      s->bytes_sent % em->tx_buf_size,
			      em->tx_buf_size);
  else if (em->data_source == ECHO_RX_DATA_SOURCE)
    n_sent = mirror_data_chunk (em, s, rx_buf, n_read);
  if (!s->bytes_to_send && !s->bytes_to_receive)
    {
      /* Session is done, need to close */
      if (s->session_state == QUIC_SESSION_STATE_AWAIT_DATA)
	s->session_state = QUIC_SESSION_STATE_CLOSING;
      else
	{
	  s->session_state = QUIC_SESSION_STATE_AWAIT_CLOSING;
	  if (em->send_stream_disconnects == ECHO_CLOSE_F_ACTIVE)
	    {
	      echo_send_rpc (em, echo_disconnect_session, (void *) s, 0);
	      em->stats.close_count.s++;
	    }
	  else if (em->send_stream_disconnects == ECHO_CLOSE_F_NONE)
	    {
	      s->session_state = QUIC_SESSION_STATE_CLOSING;
	      em->stats.clean_count.s++;
	    }
	}
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
	  ECHO_LOG (1, "Session 0x%lx state %u", s->vpp_session_handle,
		    s->session_state);
	}
    }
}

static void *
echo_data_thread_fn (void *arg)
{
  clib_mem_set_thread_index ();
  echo_main_t *em = &echo_main;
  u32 N = em->n_clients * em->n_stream_clients;
  u32 n = (N + em->n_rx_threads - 1) / em->n_rx_threads;
  u32 idx = (u64) arg;
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
	case QUIC_SESSION_STATE_READY:
	case QUIC_SESSION_STATE_AWAIT_DATA:
	  echo_handle_data (em, s, rx_buf);
	  echo_check_closed_listener (em, s);
	  break;
	case QUIC_SESSION_STATE_AWAIT_CLOSING:
	  echo_check_closed_listener (em, s);
	  break;
	case QUIC_SESSION_STATE_CLOSING:
	  echo_update_count_on_session_close (em, s);
	  echo_cleanup_session (em, s);
	  break;
	case QUIC_SESSION_STATE_CLOSED:
	  n_closed_sessions++;
	  break;
	}
      if (n_closed_sessions == thread_n_sessions)
	break;
    }
  pthread_exit (0);
}

static void
session_bound_handler (session_bound_msg_t * mp)
{
  echo_main_t *em = &echo_main;
  echo_session_t *listen_session;
  if (mp->retval)
    {
      ECHO_FAIL ("bind failed: %U", format_api_error,
		 clib_net_to_host_u32 (mp->retval));
      return;
    }
  ECHO_LOG (0, "listening on %U:%u", format_ip46_address, mp->lcl_ip,
	    mp->lcl_is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
	    clib_net_to_host_u16 (mp->lcl_port));

  /* Allocate local session and set it up */
  listen_session = echo_session_new (em);
  listen_session->session_type = QUIC_SESSION_TYPE_LISTEN;
  echo_session_handle_add_del (em, mp->handle, listen_session->session_index);
  em->state = STATE_LISTEN;
  em->listen_session_index = listen_session->session_index;
}

static void
session_accepted_handler (session_accepted_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_accepted_reply_msg_t *rmp;
  svm_fifo_t *rx_fifo, *tx_fifo;
  echo_main_t *em = &echo_main;
  echo_session_t *session, *ls;
  /* Allocate local session and set it up */
  session = echo_session_new (em);

  if (wait_for_segment_allocation (mp->segment_handle))
    {
      ECHO_FAIL ("wait_for_segment_allocation errored");
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
  if (!(ls = echo_get_session_from_handle (em, mp->listener_handle)))
    return;
  session->listener_index = ls->session_index;

  /* Add it to lookup table */
  ECHO_LOG (1, "Accepted session 0x%lx -> 0x%lx", mp->handle,
	    mp->listener_handle);
  echo_session_handle_add_del (em, mp->handle, session->session_index);

  app_alloc_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_ACCEPTED_REPLY);
  rmp = (session_accepted_reply_msg_t *) app_evt->evt->data;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  app_send_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt);

  if (ls->session_type == QUIC_SESSION_TYPE_LISTEN)
    {
      quic_echo_notify_event (em, ECHO_EVT_FIRST_QCONNECT);
      session->session_type = QUIC_SESSION_TYPE_QUIC;
      session->accepted_session_count = 0;
      if (em->cb_vft.quic_accepted_cb)
	em->cb_vft.quic_accepted_cb (mp, session->session_index);
      clib_atomic_fetch_add (&em->n_quic_clients_connected, 1);
    }
  else
    {
      session->session_type = QUIC_SESSION_TYPE_STREAM;
      quic_echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
      clib_atomic_fetch_add (&ls->accepted_session_count, 1);
      if (em->i_am_master && em->cb_vft.server_stream_accepted_cb)
	em->cb_vft.server_stream_accepted_cb (mp, session->session_index);
      if (!em->i_am_master && em->cb_vft.client_stream_accepted_cb)
	em->cb_vft.client_stream_accepted_cb (mp, session->session_index);
      clib_atomic_fetch_add (&em->n_clients_connected, 1);
    }

  if (em->n_clients_connected == em->n_clients * em->n_stream_clients
      && em->n_clients_connected != 0)
    quic_echo_notify_event (em, ECHO_EVT_LAST_SCONNECTED);
  if (em->n_quic_clients_connected == em->n_clients
      && em->state < STATE_READY)
    {
      quic_echo_notify_event (em, ECHO_EVT_LAST_QCONNECTED);
      em->state = STATE_READY;
      if (em->n_stream_clients == 0)
	echo_initiate_qsession_close_no_stream (em);
    }
}

static void
session_connected_handler (session_connected_msg_t * mp)
{
  echo_main_t *em = &echo_main;
  echo_session_t *session, *listen_session;
  u32 listener_index = htonl (mp->context);
  svm_fifo_t *rx_fifo, *tx_fifo;

  if (mp->retval)
    {
      ECHO_FAIL ("connection failed with code: %U", format_api_error,
		 clib_net_to_host_u32 (mp->retval));
      return;
    }

  session = echo_session_new (em);
  if (wait_for_segment_allocation (mp->segment_handle))
    {
      ECHO_FAIL ("wait_for_segment_allocation errored");
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

  echo_session_handle_add_del (em, mp->handle, session->session_index);

  if (listener_index == SESSION_INVALID_INDEX)
    {
      ECHO_LOG (1, "Connected session 0x%lx -> URI", mp->handle);
      session->session_type = QUIC_SESSION_TYPE_QUIC;
      session->accepted_session_count = 0;
      if (em->cb_vft.quic_connected_cb)
	em->cb_vft.quic_connected_cb (mp, session->session_index);
      clib_atomic_fetch_add (&em->n_quic_clients_connected, 1);
    }
  else
    {
      listen_session = pool_elt_at_index (em->sessions, listener_index);
      session->listener_index = listener_index;
      ECHO_LOG (1, "Connected session 0x%lx -> 0x%lx", mp->handle,
		listen_session->vpp_session_handle);
      session->session_type = QUIC_SESSION_TYPE_STREAM;
      clib_atomic_fetch_add (&listen_session->accepted_session_count, 1);
      if (em->i_am_master && em->cb_vft.server_stream_connected_cb)
	em->cb_vft.server_stream_connected_cb (mp, session->session_index);
      if (!em->i_am_master && em->cb_vft.client_stream_connected_cb)
	em->cb_vft.client_stream_connected_cb (mp, session->session_index);
      clib_atomic_fetch_add (&em->n_clients_connected, 1);
    }

  if (em->n_clients_connected == em->n_clients * em->n_stream_clients
      && em->n_clients_connected != 0)
    quic_echo_notify_event (em, ECHO_EVT_LAST_SCONNECTED);
  if (em->n_quic_clients_connected == em->n_clients
      && em->state < STATE_READY)
    {
      quic_echo_notify_event (em, ECHO_EVT_LAST_QCONNECTED);
      em->state = STATE_READY;
      if (em->n_stream_clients == 0)
	echo_initiate_qsession_close_no_stream (em);
    }
}

/*
 *
 *  ECHO Callback definitions
 *
 */


static void
echo_on_connected_connect (session_connected_msg_t * mp, u32 session_index)
{
  echo_main_t *em = &echo_main;
  u8 *uri = format (0, "QUIC://session/%lu", mp->handle);
  u64 i;

  quic_echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
  for (i = 0; i < em->n_stream_clients; i++)
    echo_send_rpc (em, echo_send_connect, (void *) uri, session_index);

  ECHO_LOG (0, "Qsession 0x%llx connected to %U:%d",
	    mp->handle, format_ip46_address, &mp->lcl.ip,
	    mp->lcl.is_ip4, clib_net_to_host_u16 (mp->lcl.port));
}

static void
echo_on_connected_send (session_connected_msg_t * mp, u32 session_index)
{
  echo_main_t *em = &echo_main;
  echo_session_t *session;

  session = pool_elt_at_index (em->sessions, session_index);
  session->bytes_to_send = em->bytes_to_send;
  session->bytes_to_receive = em->bytes_to_receive;
  session->session_state = QUIC_SESSION_STATE_READY;
  em->data_thread_args[em->n_clients_connected] = session->session_index;
}

static void
echo_on_connected_error (session_connected_msg_t * mp, u32 session_index)
{
  ECHO_FAIL ("Got a wrong connected on session %u [%lx]", session_index,
	     mp->handle);
}

static void
echo_on_accept_recv (session_accepted_msg_t * mp, u32 session_index)
{
  echo_main_t *em = &echo_main;
  echo_session_t *session;

  session = pool_elt_at_index (em->sessions, session_index);
  session->bytes_to_send = em->bytes_to_send;
  session->bytes_to_receive = em->bytes_to_receive;
  em->data_thread_args[em->n_clients_connected] = session->session_index;
  session->session_state = QUIC_SESSION_STATE_READY;
}

static void
echo_on_accept_connect (session_accepted_msg_t * mp, u32 session_index)
{
  echo_main_t *em = &echo_main;
  ECHO_LOG (1, "Accept on QSession 0x%lx %u", mp->handle);
  u8 *uri = format (0, "QUIC://session/%lu", mp->handle);
  u32 i;

  quic_echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
  for (i = 0; i < em->n_stream_clients; i++)
    echo_send_rpc (em, echo_send_connect, (void *) uri, session_index);
}

static void
echo_on_accept_error (session_accepted_msg_t * mp, u32 session_index)
{
  ECHO_FAIL ("Got a wrong accept on session %u [%lx]", session_index,
	     mp->handle);
}

static void
echo_on_accept_log_ip (session_accepted_msg_t * mp, u32 session_index)
{
  u8 *ip_str;
  ip_str = format (0, "%U", format_ip46_address, &mp->rmt.ip, mp->rmt.is_ip4);
  ECHO_LOG (0, "Accepted session from: %s:%d", ip_str,
	    clib_net_to_host_u16 (mp->rmt.port));

}

static const quic_echo_cb_vft_t default_cb_vft = {
  /* Qsessions */
  .quic_accepted_cb = echo_on_accept_log_ip,
  .quic_connected_cb = echo_on_connected_connect,
  /* client initiated streams */
  .server_stream_accepted_cb = echo_on_accept_recv,
  .client_stream_connected_cb = echo_on_connected_send,
  /* server initiated streams */
  .client_stream_accepted_cb = echo_on_accept_error,
  .server_stream_connected_cb = echo_on_connected_error,
};

static const quic_echo_cb_vft_t server_stream_cb_vft = {
  /* Qsessions */
  .quic_accepted_cb = echo_on_accept_connect,
  .quic_connected_cb = NULL,
  /* client initiated streams */
  .server_stream_accepted_cb = echo_on_accept_error,
  .client_stream_connected_cb = echo_on_connected_error,
  /* server initiated streams */
  .client_stream_accepted_cb = echo_on_accept_recv,
  .server_stream_connected_cb = echo_on_connected_send,
};

static uword
echo_unformat_quic_setup_vft (unformat_input_t * input, va_list * args)
{
  echo_main_t *em = &echo_main;
  if (unformat (input, "serverstream"))
    em->cb_vft = server_stream_cb_vft;
  else if (unformat (input, "default"))
    ;
  else
    return 0;
  return 1;
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
  int rv = 0;
  ECHO_LOG (1, "passive close session 0x%lx", mp->handle);
  if (!(s = echo_get_session_from_handle (em, mp->handle)))
    return;

  app_alloc_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_DISCONNECTED_REPLY);
  rmp = (session_disconnected_reply_msg_t *) app_evt->evt->data;
  rmp->retval = rv;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  app_send_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt);

  if (s->session_type == QUIC_SESSION_TYPE_STREAM)
    {
      session_print_stats (em, s);
      if (s->bytes_to_receive || s->bytes_to_send)
	s->session_state = QUIC_SESSION_STATE_AWAIT_DATA;
      else
	s->session_state = QUIC_SESSION_STATE_CLOSING;
      em->stats.close_count.s++;
    }
  else
    {
      echo_cleanup_session (em, s);	/* We can clean Q/Lsessions right away */
      em->stats.close_count.q++;
    }
}

static void
session_reset_handler (session_reset_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  echo_main_t *em = &echo_main;
  session_reset_reply_msg_t *rmp;
  echo_session_t *s = 0;
  int rv = 0;

  ECHO_LOG (1, "Reset session 0x%lx", mp->handle);
  if (!(s = echo_get_session_from_handle (em, mp->handle)))
    return;
  if (s->session_type == QUIC_SESSION_TYPE_STREAM)
    {
      em->stats.reset_count.s++;
      s->session_state = QUIC_SESSION_STATE_CLOSING;
    }
  else
    {
      em->stats.reset_count.q++;
      echo_cleanup_session (em, s);	/* We can clean Q/Lsessions right away */
    }

  app_alloc_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_RESET_REPLY);
  rmp = (session_reset_reply_msg_t *) app_evt->evt->data;
  rmp->retval = rv;
  rmp->handle = mp->handle;
  app_send_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt);
}

static void
handle_mq_event (session_event_t * e)
{
  switch (e->event_type)
    {
    case SESSION_CTRL_EVT_BOUND:
      session_bound_handler ((session_bound_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_ACCEPTED:
      session_accepted_handler ((session_accepted_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_CONNECTED:
      session_connected_handler ((session_connected_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_DISCONNECTED:
      session_disconnected_handler ((session_disconnected_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_RESET:
      session_reset_handler ((session_reset_msg_t *) e->data);
      break;
    case SESSION_IO_EVT_RX:
      break;
    default:
      ECHO_LOG (0, "unhandled event %u", e->event_type);
    }
}

static int
wait_for_state_change (echo_main_t * em, connection_state_t state,
		       f64 timeout)
{
  f64 end_time = clib_time_now (&em->clib_time) + timeout;
  while (!timeout || clib_time_now (&em->clib_time) < end_time)
    {
      if (em->state == state)
	return 0;
      if (em->time_to_stop)
	return 1;
    }
  ECHO_LOG (1, "timeout waiting for %U", format_quic_echo_state, state);
  return -1;
}

static void
echo_process_rpcs (echo_main_t * em)
{
  echo_rpc_msg_t *rpc;
  svm_msg_q_msg_t msg;
  while (em->state < STATE_DATA_DONE && !em->time_to_stop)
    {
      if (svm_msg_q_sub (em->rpc_msq_queue, &msg, SVM_Q_TIMEDWAIT, 1))
	continue;
      rpc = svm_msg_q_msg_data (em->rpc_msq_queue, &msg);
      ((echo_rpc_t) rpc->fp) (rpc->arg, rpc->opaque);
      svm_msg_q_free_msg (em->rpc_msq_queue, &msg);
    }
}

static void *
echo_mq_thread_fn (void *arg)
{
  clib_mem_set_thread_index ();
  echo_main_t *em = &echo_main;
  session_event_t *e;
  svm_msg_q_msg_t msg;
  int rv;
  wait_for_state_change (em, STATE_ATTACHED, 0);
  if (em->state < STATE_ATTACHED || !em->our_event_queue)
    {
      ECHO_FAIL ("Application failed to attach");
      pthread_exit (0);
    }

  ECHO_LOG (1, "Waiting for data on %u clients", em->n_clients_connected);
  while (1)
    {
      if (!(rv = svm_msg_q_sub (em->our_event_queue,
				&msg, SVM_Q_TIMEDWAIT, 1)))
	{
	  e = svm_msg_q_msg_data (em->our_event_queue, &msg);
	  handle_mq_event (e);
	  svm_msg_q_free_msg (em->our_event_queue, &msg);
	}
      if (rv == ETIMEDOUT
	  && (em->time_to_stop || em->state == STATE_DETACHED))
	break;
      if (!em->n_clients_connected && !em->n_quic_clients_connected &&
	  em->state == STATE_READY)
	{
	  em->state = STATE_DATA_DONE;
	}
    }
  pthread_exit (0);
}

static void
clients_run (echo_main_t * em)
{
  u64 i;
  quic_echo_notify_event (em, ECHO_EVT_FIRST_QCONNECT);
  for (i = 0; i < em->n_clients; i++)
    echo_send_connect (em->uri, SESSION_INVALID_INDEX);
  wait_for_state_change (em, STATE_READY, 0);
  ECHO_LOG (1, "App is ready");
  echo_process_rpcs (em);
}

static void
server_run (echo_main_t * em)
{
  server_send_listen (em);
  wait_for_state_change (em, STATE_READY, 0);
  ECHO_LOG (1, "App is ready");
  echo_process_rpcs (em);
  /* Cleanup */
  server_send_unbind (em);
  if (wait_for_state_change (em, STATE_DISCONNECTED, TIMEOUT))
    {
      ECHO_FAIL ("Timeout waiting for state disconnected");
      return;
    }
}

/*
 *
 *  Session API handlers
 *
 */

static void
vl_api_application_attach_reply_t_handler (vl_api_application_attach_reply_t *
					   mp)
{
  echo_main_t *em = &echo_main;
  int *fds = 0, i;
  u32 n_fds = 0;
  u64 segment_handle;
  segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  ECHO_LOG (1, "Attached returned app %u", htons (mp->app_index));

  if (mp->retval)
    {
      ECHO_FAIL ("attach failed: %U", format_api_error,
		 clib_net_to_host_u32 (mp->retval));
      return;
    }

  if (mp->segment_name_length == 0)
    {
      ECHO_FAIL ("segment_name_length zero");
      return;
    }

  ASSERT (mp->app_event_queue_address);
  em->our_event_queue = uword_to_pointer (mp->app_event_queue_address,
					  svm_msg_q_t *);

  if (mp->n_fds)
    {
      vec_validate (fds, mp->n_fds);
      if (vl_socket_client_recv_fd_msg (fds, mp->n_fds, 5))
	{
	  ECHO_FAIL ("vl_socket_client_recv_fd_msg failed");
	  goto failed;
	}

      if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
	if (ssvm_segment_attach (0, SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  {
	    ECHO_FAIL ("svm_fifo_segment_attach failed");
	    goto failed;
	  }

      if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
	if (ssvm_segment_attach ((char *) mp->segment_name,
				 SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  {
	    ECHO_FAIL ("svm_fifo_segment_attach ('%s') failed",
		       mp->segment_name);
	    goto failed;
	  }
      if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
	svm_msg_q_set_consumer_eventfd (em->our_event_queue, fds[n_fds++]);

      vec_free (fds);
    }
  else
    {
      if (ssvm_segment_attach ((char *) mp->segment_name, SSVM_SEGMENT_SHM,
			       -1))
	{
	  ECHO_FAIL ("svm_fifo_segment_attach ('%s') failed",
		     mp->segment_name);
	  return;
	}
    }
  echo_segment_handle_add_del (em, segment_handle, 1 /* add */ );
  ECHO_LOG (1, "Mapped segment 0x%lx", segment_handle);

  em->state = STATE_ATTACHED;
  return;
failed:
  for (i = clib_max (n_fds - 1, 0); i < vec_len (fds); i++)
    close (fds[i]);
  vec_free (fds);
}

static void
vl_api_application_detach_reply_t_handler (vl_api_application_detach_reply_t *
					   mp)
{
  if (mp->retval)
    {
      ECHO_FAIL ("detach returned with err: %d", mp->retval);
      return;
    }
  echo_main.state = STATE_DETACHED;
}


static void
vl_api_unmap_segment_t_handler (vl_api_unmap_segment_t * mp)
{
  echo_main_t *em = &echo_main;
  u64 segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  echo_segment_handle_add_del (em, segment_handle, 0 /* add */ );
  ECHO_LOG (1, "Unmaped segment 0x%lx", segment_handle);
}

static void
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t * mp)
{
  fifo_segment_main_t *sm = &echo_main.segment_main;
  fifo_segment_create_args_t _a, *a = &_a;
  echo_main_t *em = &echo_main;
  int *fds = 0, i;
  char *seg_name = (char *) mp->segment_name;
  u64 segment_handle = clib_net_to_host_u64 (mp->segment_handle);

  if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
    {
      vec_validate (fds, 1);
      if (vl_socket_client_recv_fd_msg (fds, 1, 5))
	{
	  ECHO_FAIL ("vl_socket_client_recv_fd_msg failed");
	  goto failed;
	}

      if (ssvm_segment_attach (seg_name, SSVM_SEGMENT_MEMFD, fds[0]))
	{
	  ECHO_FAIL ("svm_fifo_segment_attach ('%s')"
		     "failed on SSVM_SEGMENT_MEMFD", seg_name);
	  goto failed;
	}
      vec_free (fds);
    }
  else
    {
      clib_memset (a, 0, sizeof (*a));
      a->segment_name = seg_name;
      a->segment_size = mp->segment_size;
      /* Attach to the segment vpp created */
      if (fifo_segment_attach (sm, a))
	{
	  ECHO_FAIL ("svm_fifo_segment_attach ('%s') failed", seg_name);
	  goto failed;
	}
    }
  echo_segment_handle_add_del (em, segment_handle, 1 /* add */ );
  ECHO_LOG (1, "Mapped segment 0x%lx", segment_handle);
  return;

failed:
  for (i = 0; i < vec_len (fds); i++)
    close (fds[i]);
  vec_free (fds);
}

static void
vl_api_bind_uri_reply_t_handler (vl_api_bind_uri_reply_t * mp)
{
  echo_main_t *em = &echo_main;
  if (mp->retval)
    {
      ECHO_FAIL ("bind failed: %U", format_api_error,
		 clib_net_to_host_u32 (mp->retval));
      return;
    }

  em->state = STATE_LISTEN;
}

static void
vl_api_unbind_uri_reply_t_handler (vl_api_unbind_uri_reply_t * mp)
{
  echo_session_t *listen_session;
  echo_main_t *em = &echo_main;
  if (mp->retval != 0)
    {
      ECHO_FAIL ("returned %d", ntohl (mp->retval));
      return;
    }
  em->state = STATE_DISCONNECTED;
  listen_session = pool_elt_at_index (em->sessions, em->listen_session_index);
  echo_cleanup_session (em, listen_session);
}

static void
vl_api_disconnect_session_reply_t_handler (vl_api_disconnect_session_reply_t *
					   mp)
{
  echo_main_t *em = &echo_main;
  echo_session_t *s;

  if (mp->retval)
    {
      ECHO_FAIL ("vpp complained about disconnect: %d", ntohl (mp->retval));
      return;
    }

  ECHO_LOG (1, "Got disonnected reply for session 0x%lx", mp->handle);
  if (!(s = echo_get_session_from_handle (em, mp->handle)))
    return;
  if (s->session_type == QUIC_SESSION_TYPE_STREAM)
    s->session_state = QUIC_SESSION_STATE_CLOSING;
  else
    echo_cleanup_session (em, s);	/* We can clean Q/Lsessions right away */
}

static void
  vl_api_application_tls_cert_add_reply_t_handler
  (vl_api_application_tls_cert_add_reply_t * mp)
{
  if (mp->retval)
    ECHO_FAIL ("failed to add tls cert");
}

static void
  vl_api_application_tls_key_add_reply_t_handler
  (vl_api_application_tls_key_add_reply_t * mp)
{
  if (mp->retval)
    ECHO_FAIL ("failed to add tls key");
}

static void
vl_api_connect_uri_reply_t_handler (vl_api_connect_uri_reply_t * mp)
{
  echo_session_t *session;
  echo_main_t *em = &echo_main;
  u8 *uri;
  if (!mp->retval)
    return;
  /* retry connect */
  if (mp->context == SESSION_INVALID_INDEX)
    {
      ECHO_LOG (1, "Retrying connect %s", em->uri);
      echo_send_rpc (em, echo_send_connect, (void *) em->uri,
		     SESSION_INVALID_INDEX);
    }
  else
    {
      session = pool_elt_at_index (em->sessions, mp->context);
      uri = format (0, "QUIC://session/%lu", session->vpp_session_handle);
      ECHO_LOG (1, "Retrying connect %s", uri);
      echo_send_rpc (em, echo_send_connect, (void *) uri, mp->context);
    }

}

#define foreach_quic_echo_msg                            		\
_(BIND_URI_REPLY, bind_uri_reply)                       		\
_(UNBIND_URI_REPLY, unbind_uri_reply)                   		\
_(DISCONNECT_SESSION_REPLY, disconnect_session_reply)   		\
_(APPLICATION_ATTACH_REPLY, application_attach_reply)   		\
_(APPLICATION_DETACH_REPLY, application_detach_reply)			\
_(MAP_ANOTHER_SEGMENT, map_another_segment)				\
_(UNMAP_SEGMENT, unmap_segment)			                        \
_(APPLICATION_TLS_CERT_ADD_REPLY, application_tls_cert_add_reply)	\
_(APPLICATION_TLS_KEY_ADD_REPLY, application_tls_key_add_reply)		\
_(CONNECT_URI_REPLY, connect_uri_reply)		\

void
quic_echo_api_hookup (echo_main_t * em)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_quic_echo_msg;
#undef _
}

/*
 *
 *  End Session API handlers
 *
 */

static void
print_usage_and_exit (void)
{
  fprintf (stderr,
	   "Usage: quic_echo [socket-name SOCKET] [client|server] [uri URI] [OPTIONS]\n"
	   "Generates traffic and assert correct teardown of the QUIC hoststack\n"
	   "\n"
	   "  socket-name PATH    Specify the binary socket path to connect to VPP\n"
	   "  use-svm-api         Use SVM API to connect to VPP\n"
	   "  test-bytes[:assert] Check data correctness when receiving (assert fails on first error)\n"
	   "  fifo-size N         Use N Kb fifos\n"
	   "  rx-buf N            Use N Kb RX buffer\n"
	   "  tx-buf N            Use N Kb TX test buffer\n"
	   "  appns NAMESPACE     Use the namespace NAMESPACE\n"
	   "  all-scope           all-scope option\n"
	   "  local-scope         local-scope option\n"
	   "  global-scope        global-scope option\n"
	   "  secret SECRET       set namespace secret\n"
	   "  chroot prefix PATH  Use PATH as memory root path\n"
	   "  quic-setup OPT      OPT=serverstream : Client open N connections. \n"
	   "                       On each one server opens M streams\n"
	   "                      OPT=default : Client open N connections.\n"
	   "                       On each one client opens M streams\n"
	   "  sclose=[Y|N|W]      When a stream is done,    pass[N] send[Y] or wait[W] for close\n"
	   "  qclose=[Y|N|W]      When a connection is done pass[N] send[Y] or wait[W] for close\n"
	   "\n"
	   "  time START:END      Time between evts START & END, events being :\n"
	   "                       start - Start of the app\n"
	   "                       qconnect    - first Connection connect sent\n"
	   "                       qconnected  - last Connection connected\n"
	   "                       sconnect    - first Stream connect sent\n"
	   "                       sconnected  - last Stream got connected\n"
	   "                       lastbyte    - Last expected byte received\n"
	   "                       exit        - Exiting of the app\n"
	   "  json                Output global stats in json\n"
	   "  log=N               Set the log level to [0: no output, 1:errors, 2:log]\n"
	   "  max-connects=N      Don't do more than N parallel connect_uri\n"
	   "\n"
	   "  nclients N[/M]      Open N QUIC connections, each one with M streams (M defaults to 1)\n"
	   "  nthreads N          Use N busy loop threads for data [in addition to main & msg queue]\n"
	   "  TX=1337[Kb|Mb|GB]   Send 1337 [K|M|G]bytes, use TX=RX to reflect the data\n"
	   "  RX=1337[Kb|Mb|GB]   Expect 1337 [K|M|G]bytes\n"
	   "\n"
	   "Default configuration is :\n"
	   " server nclients 1/1 RX=64Kb TX=RX\n"
	   " client nclients 1/1 RX=64Kb TX=64Kb\n");
  exit (1);
}


void
quic_echo_process_opts (int argc, char **argv)
{
  echo_main_t *em = &echo_main;
  unformat_input_t _argv, *a = &_argv;
  u32 tmp;
  u8 *chroot_prefix;
  u8 *uri = 0;
  u8 default_f_active;

  unformat_init_command_line (a, argv);
  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "chroot prefix %s", &chroot_prefix))
	{
	  vl_set_memory_root_path ((char *) chroot_prefix);
	}
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
      else if (unformat (a, "fifo-size %d", &tmp))
	em->fifo_size = tmp << 10;
      else if (unformat (a, "rx-buf %d", &tmp))
	em->rx_buf_size = tmp << 10;
      else if (unformat (a, "tx-buf %d", &tmp))
	em->rx_buf_size = tmp << 10;
      else
	if (unformat
	    (a, "nclients %d/%d", &em->n_clients, &em->n_stream_clients))
	;
      else if (unformat (a, "nclients %d", &em->n_clients))
	;
      else if (unformat (a, "nthreads %d", &em->n_rx_threads))
	;
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
      else if (unformat (a, "quic-setup %U", echo_unformat_quic_setup_vft))
	;
      else if (unformat (a, "TX=RX"))
	em->data_source = ECHO_RX_DATA_SOURCE;
      else if (unformat (a, "TX=%U", unformat_data, &em->bytes_to_send))
	;
      else if (unformat (a, "RX=%U", unformat_data, &em->bytes_to_receive))
	;
      else if (unformat (a, "json"))
	em->output_json = 1;
      else if (unformat (a, "log=%d", &em->log_lvl))
	;
      else
	if (unformat
	    (a, "sclose=%U", unformat_close, &em->send_stream_disconnects))
	;
      else
	if (unformat
	    (a, "qclose=%U", unformat_close, &em->send_quic_disconnects))
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
  if (em->send_quic_disconnects == ECHO_CLOSE_F_INVALID)
    em->send_quic_disconnects = default_f_active;
}

int
main (int argc, char **argv)
{
  echo_main_t *em = &echo_main;
  fifo_segment_main_t *sm = &em->segment_main;
  char *app_name;
  u64 n_clients, i;
  svm_msg_q_cfg_t _cfg, *cfg = &_cfg;
  u32 rpc_queue_size = 64 << 10;

  clib_mem_init_thread_safe (0, 256 << 20);
  clib_memset (em, 0, sizeof (*em));
  em->session_index_by_vpp_handles = hash_create (0, sizeof (uword));
  clib_spinlock_init (&em->sid_vpp_handles_lock);
  em->shared_segment_handles = hash_create (0, sizeof (uword));
  clib_spinlock_init (&em->segment_handles_lock);
  em->socket_name = format (0, "%s%c", API_SOCKET_FILE, 0);
  em->use_sock_api = 1;
  em->fifo_size = 64 << 10;
  em->n_clients = 1;
  em->n_stream_clients = 1;
  em->max_test_msg = 50;
  em->time_to_stop = 0;
  em->i_am_master = 1;
  em->n_rx_threads = 4;
  em->test_return_packets = RETURN_PACKETS_NOTEST;
  em->timing.start_event = ECHO_EVT_FIRST_QCONNECT;
  em->timing.end_event = ECHO_EVT_LAST_BYTE;
  em->bytes_to_receive = ~0;	/* defaulted when we know if server/client */
  em->bytes_to_send = ~0;	/* defaulted when we know if server/client */
  em->rx_buf_size = 1 << 20;
  em->tx_buf_size = 1 << 20;
  em->data_source = ECHO_INVALID_DATA_SOURCE;
  em->uri = format (0, "%s%c", "quic://0.0.0.0/1234", 0);
  em->cb_vft = default_cb_vft;
  quic_echo_process_opts (argc, argv);

  n_clients = em->n_clients * em->n_stream_clients;
  vec_validate (em->data_thread_handles, em->n_rx_threads - 1);
  vec_validate (em->data_thread_args, n_clients - 1);
  for (i = 0; i < n_clients; i++)
    em->data_thread_args[i] = SESSION_INVALID_INDEX;
  clib_time_init (&em->clib_time);
  init_error_string_table ();
  fifo_segment_main_init (sm, HIGH_SEGMENT_BASEVA, 20);
  vec_validate (em->connect_test_data, em->tx_buf_size);
  for (i = 0; i < em->tx_buf_size; i++)
    em->connect_test_data[i] = i & 0xff;

  /* *INDENT-OFF* */
  svm_msg_q_ring_cfg_t rc[SESSION_MQ_N_RINGS] = {
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
  quic_echo_api_hookup (em);

  app_name = em->i_am_master ? "quic_echo_server" : "quic_echo_client";
  if (connect_to_vpp (app_name))
    {
      svm_region_exit ();
      ECHO_FAIL ("Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  echo_session_prealloc (em);
  quic_echo_notify_event (em, ECHO_EVT_START);

  application_send_attach (em);
  if (wait_for_state_change (em, STATE_ATTACHED, TIMEOUT))
    {
      ECHO_FAIL ("Couldn't attach to vpp, did you run <session enable> ?\n");
      exit (1);
    }
  if (pthread_create (&em->mq_thread_handle,
		      NULL /*attr */ , echo_mq_thread_fn, 0))
    {
      ECHO_FAIL ("pthread create errored\n");
      exit (1);
    }
  for (i = 0; i < em->n_rx_threads; i++)
    if (pthread_create (&em->data_thread_handles[i],
			NULL /*attr */ , echo_data_thread_fn, (void *) i))
      {
	ECHO_FAIL ("pthread create errored\n");
	exit (1);
      }
  if (em->i_am_master)
    server_run (em);
  else
    clients_run (em);
  quic_echo_notify_event (em, ECHO_EVT_EXIT);
  if (em->output_json)
    print_global_json_stats (em);
  else
    print_global_stats (em);
  echo_free_sessions (em);
  echo_assert_test_suceeded (em);
  application_detach (em);
  if (wait_for_state_change (em, STATE_DETACHED, TIMEOUT))
    {
      ECHO_FAIL ("ECHO-ERROR: Couldn't detach from vpp, exiting...\n");
      exit (1);
    }
  int *rv;
  pthread_join (em->mq_thread_handle, (void **) &rv);
  if (rv)
    {
      ECHO_FAIL ("mq pthread errored %d", rv);
      exit (1);
    }
  if (em->use_sock_api)
    vl_socket_client_disconnect ();
  else
    vl_client_disconnect_from_vlib ();
  ECHO_LOG (0, "Test complete !\n");
  exit (em->has_failed);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
