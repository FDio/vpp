/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <setjmp.h>
#include <signal.h>
#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/time.h>
#include <vppinfra/macros.h>
#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>
#include <pthread.h>
#include <vnet/session/application_interface.h>
#include <svm/fifo_segment.h>
#include <hs_apps/sapi/echo_common.c>

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

typedef enum
{
  STATE_START,
  STATE_ATTACHED,
  STATE_READY,
  STATE_FAILED,
  STATE_DISCONNECTING,
  STATE_DETACHED
} connection_state_t;

typedef struct
{
  /* vpe input queue */
  svm_queue_t *vl_input_queue;
  u8 use_sock_api;
  u8 *socket_name;

  /* API client handle */
  u32 my_client_index;

  /* The URI we're playing with */
  u8 *uri;

  /* Session pool */
  app_session_t *sessions;

  /* Hash table for disconnect processing */
  uword *session_index_by_vpp_handles;

  /* intermediate rx buffer */
  u8 *rx_buf;

  u32 fifo_size;
  int i_am_server;
  u8 is_connected;

  /* Our event queue */
  svm_msg_q_t *our_event_queue;

  /* $$$ single thread only for the moment */
  svm_msg_q_t *vpp_event_queue;

  /* $$$$ hack: cut-through session index */
  volatile u32 cut_through_session_index;
  volatile u32 connected_session;

  /* For deadman timers */
  clib_time_t clib_time;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile connection_state_t state;

  volatile int time_to_stop;
  volatile int time_to_print_stats;

  u32 configured_segment_size;

  fifo_segment_main_t segment_main;

  u8 *connect_test_data;

  uword *segments_table;
  u8 have_return;
  u64 bytes_to_send;
  u64 bytes_sent;
} udp_echo_main_t;

udp_echo_main_t udp_echo_main;

static void
stop_signal (int signum)
{
  udp_echo_main_t *um = &udp_echo_main;

  um->time_to_stop = 1;
}

static void
stats_signal (int signum)
{
  udp_echo_main_t *um = &udp_echo_main;
  um->time_to_print_stats = 1;
}

static clib_error_t *
setup_signal_handlers (void)
{
  signal (SIGINT, stats_signal);
  signal (SIGQUIT, stop_signal);
  signal (SIGTERM, stop_signal);

  return 0;
}

static void
application_send_attach (udp_echo_main_t * utm)
{
  vl_api_application_attach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_ATTACH);
  bmp->client_index = utm->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_ACCEPT_REDIRECT;
  bmp->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_ADD_SEGMENT;
  bmp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 2;
  bmp->options[APP_OPTIONS_RX_FIFO_SIZE] = utm->fifo_size;
  bmp->options[APP_OPTIONS_TX_FIFO_SIZE] = utm->fifo_size;
  bmp->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  bmp->options[APP_OPTIONS_SEGMENT_SIZE] = 256 << 20;
  bmp->options[APP_OPTIONS_EVT_QUEUE_SIZE] = 256;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & bmp);
}

void
application_detach (udp_echo_main_t * utm)
{
  vl_api_application_detach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_DETACH);
  bmp->client_index = utm->my_client_index;
  bmp->context = ntohl (0xfeedface);
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & bmp);
}

static int
ssvm_segment_attach (char *name, ssvm_segment_type_t type, int fd)
{
  fifo_segment_create_args_t _a, *a = &_a;
  fifo_segment_main_t *sm = &udp_echo_main.segment_main;
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
vl_api_application_attach_reply_t_handler (vl_api_application_attach_reply_t *
					   mp)
{
  udp_echo_main_t *utm = &udp_echo_main;
  int *fds = 0, i;
  u32 n_fds = 0;

  if (mp->retval)
    {
      clib_warning ("attach failed: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
      return;
    }

  if (mp->segment_name_length == 0)
    {
      clib_warning ("segment_name_length zero");
      return;
    }

  ASSERT (mp->app_event_queue_address);
  utm->our_event_queue = uword_to_pointer (mp->app_event_queue_address,
					   svm_msg_q_t *);

  if (mp->n_fds)
    {
      vec_validate (fds, mp->n_fds);
      if (vl_socket_client_recv_fd_msg (fds, mp->n_fds, 5))
	{
	  clib_warning ("vl_socket_client_recv_fd_msg failed");
	  goto failed;
	}

      if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
	if (ssvm_segment_attach (0, SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  {
	    clib_warning ("svm_fifo_segment_attach failed");
	    goto failed;
	  }

      if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
	if (ssvm_segment_attach ((char *) mp->segment_name,
				 SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  {
	    clib_warning ("svm_fifo_segment_attach ('%s') failed",
			  mp->segment_name);
	    goto failed;
	  }
      if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
	svm_msg_q_set_consumer_eventfd (utm->our_event_queue, fds[n_fds++]);

      vec_free (fds);
    }
  else
    {
      if (ssvm_segment_attach ((char *) mp->segment_name, SSVM_SEGMENT_SHM,
			       -1))
	{
	  clib_warning ("svm_fifo_segment_attach ('%s') failed",
			mp->segment_name);
	  return;
	}
    }
  utm->state = STATE_ATTACHED;
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
    clib_warning ("detach returned with err: %d", mp->retval);
  udp_echo_main.state = STATE_DETACHED;
}

int
wait_for_state_change (udp_echo_main_t * utm, connection_state_t state)
{
#if CLIB_DEBUG > 0
#define TIMEOUT 600.0
#else
#define TIMEOUT 600.0
#endif

  f64 timeout = clib_time_now (&utm->clib_time) + TIMEOUT;

  while (clib_time_now (&utm->clib_time) < timeout)
    {
      if (utm->state == state)
	return 0;
      if (utm->state == STATE_FAILED)
	return -1;
    }
  return -1;
}

static void
session_accepted_handler (session_accepted_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  udp_echo_main_t *utm = &udp_echo_main;
  session_accepted_reply_msg_t *rmp;
  svm_fifo_t *rx_fifo, *tx_fifo;
  app_session_t *session;
  static f64 start_time;
  u32 session_index;
  int rv = 0;

  if (start_time == 0.0)
    start_time = clib_time_now (&utm->clib_time);

  utm->vpp_event_queue = uword_to_pointer (mp->vpp_event_queue_address,
					   svm_msg_q_t *);
  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);

  pool_get (utm->sessions, session);
  clib_memset (session, 0, sizeof (*session));
  session_index = session - utm->sessions;
  session->session_index = session_index;

  rx_fifo->client_session_index = session_index;
  tx_fifo->client_session_index = session_index;
  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;
  clib_memcpy_fast (&session->transport.rmt_ip, &mp->rmt.ip,
		    sizeof (ip46_address_t));
  session->transport.is_ip4 = mp->rmt.is_ip4;
  session->transport.rmt_port = mp->rmt.port;

  hash_set (utm->session_index_by_vpp_handles, mp->handle, session_index);
  if (pool_elts (utm->sessions) && (pool_elts (utm->sessions) % 20000) == 0)
    {
      f64 now = clib_time_now (&utm->clib_time);
      fformat (stdout, "%d active sessions in %.2f seconds, %.2f/sec...\n",
	       pool_elts (utm->sessions), now - start_time,
	       (f64) pool_elts (utm->sessions) / (now - start_time));
    }

  app_alloc_ctrl_evt_to_vpp (utm->vpp_event_queue, app_evt,
			     SESSION_CTRL_EVT_ACCEPTED_REPLY);
  rmp = (session_accepted_reply_msg_t *) app_evt->evt->data;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  rmp->retval = rv;
  app_send_ctrl_evt_to_vpp (utm->vpp_event_queue, app_evt);

  CLIB_MEMORY_BARRIER ();
  utm->state = STATE_READY;
}

static void
session_disconnected_handler (session_disconnected_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  udp_echo_main_t *utm = &udp_echo_main;
  session_disconnected_reply_msg_t *rmp;
  app_session_t *session;
  uword *p;
  int rv = 0;

  p = hash_get (utm->session_index_by_vpp_handles, mp->handle);

  if (p)
    {
      session = pool_elt_at_index (utm->sessions, p[0]);
      hash_unset (utm->session_index_by_vpp_handles, mp->handle);
      clib_warning ("disconnecting %u", session->session_index);
      pool_put (utm->sessions, session);
    }
  else
    {
      clib_warning ("couldn't find session key %llx", mp->handle);
      return;
    }

  app_alloc_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_DISCONNECTED_REPLY);
  rmp = (session_disconnected_reply_msg_t *) app_evt->evt->data;
  rmp->retval = rv;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  app_send_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt);
}

static void
session_connected_handler (session_connected_msg_t * mp)
{
  udp_echo_main_t *utm = &udp_echo_main;
  app_session_t *session;

  ASSERT (utm->i_am_server == 0);

  if (mp->retval)
    {
      clib_warning ("failed connect");
      return;
    }

  ASSERT (mp->server_rx_fifo && mp->server_tx_fifo);
  clib_warning ("Connected session 0%lx %p", mp->handle,
		mp->vpp_event_queue_address);

  pool_get (utm->sessions, session);
  session->session_index = session - utm->sessions;
  session->rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  session->tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);

  /* Cut-through case */
  if (mp->ct_rx_fifo)
    {
      clib_warning ("cut-through session");
      session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					     svm_msg_q_t *);
      utm->cut_through_session_index = session->session_index;
      session->is_dgram = 0;
      sleep (1);
      session->rx_fifo->client_session_index = session->session_index;
      session->tx_fifo->client_session_index = session->session_index;
      /* TODO use ct fifos */
    }
  else
    {
      utm->connected_session = session->session_index;
      session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					     svm_msg_q_t *);

      session->rx_fifo->client_session_index = session->session_index;
      session->tx_fifo->client_session_index = session->session_index;
      clib_memcpy_fast (&session->transport.lcl_ip, &mp->lcl.ip,
			sizeof (ip46_address_t));
      session->transport.is_ip4 = mp->lcl.is_ip4;
      session->transport.lcl_port = mp->lcl.port;
      session->is_dgram = !utm->is_connected;
    }
  utm->state = STATE_READY;
}

static void
session_bound_handler (session_bound_msg_t * mp)
{
  udp_echo_main_t *utm = &udp_echo_main;
  svm_fifo_t *rx_fifo, *tx_fifo;
  app_session_t *session;
  u32 session_index;

  if (mp->retval)
    {
      clib_warning ("bind failed: %d", mp->retval);
      utm->state = STATE_FAILED;
      return;
    }

  rx_fifo = uword_to_pointer (mp->rx_fifo, svm_fifo_t *);
  tx_fifo = uword_to_pointer (mp->tx_fifo, svm_fifo_t *);

  pool_get (utm->sessions, session);
  clib_memset (session, 0, sizeof (*session));
  session_index = session - utm->sessions;

  rx_fifo->client_session_index = session_index;
  tx_fifo->client_session_index = session_index;
  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;
  clib_memcpy_fast (&session->transport.lcl_ip, mp->lcl_ip,
		    sizeof (ip46_address_t));
  session->transport.is_ip4 = mp->lcl_is_ip4;
  session->transport.lcl_port = mp->lcl_port;
  session->vpp_evt_q = uword_to_pointer (mp->vpp_evt_q, svm_msg_q_t *);
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
    default:
      clib_warning ("unhandled %u", e->event_type);
    }
}

static void
udp_client_send_connect (udp_echo_main_t * utm)
{
  vl_api_connect_uri_t *cmp;
  cmp = vl_msg_api_alloc (sizeof (*cmp));
  clib_memset (cmp, 0, sizeof (*cmp));

  cmp->_vl_msg_id = ntohs (VL_API_CONNECT_URI);
  cmp->client_index = utm->my_client_index;
  cmp->context = ntohl (0xfeedface);
  memcpy (cmp->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & cmp);
}

static void
send_test_chunk (udp_echo_main_t * utm, app_session_t * s, u32 bytes)
{
  u64 test_buf_len, bytes_this_chunk, test_buf_offset;

  u8 *test_data = utm->connect_test_data;
  u32 enq_space;
  int written;

  test_buf_len = vec_len (test_data);
  test_buf_offset = utm->bytes_sent % test_buf_len;
  bytes_this_chunk = clib_min (test_buf_len - test_buf_offset,
			       utm->bytes_to_send);
  enq_space = svm_fifo_max_enqueue_prod (s->tx_fifo);
  bytes_this_chunk = clib_min (bytes_this_chunk, enq_space);

  written = app_send (s, test_data + test_buf_offset, bytes_this_chunk,
		      SVM_Q_WAIT);
  if (written > 0)
    {
      utm->bytes_to_send -= written;
      utm->bytes_sent += written;
    }
}

static void
recv_test_chunk (udp_echo_main_t * utm, app_session_t * s)
{
  app_recv (s, utm->rx_buf, vec_len (utm->rx_buf));
}

void
client_send_data (udp_echo_main_t * utm, u32 session_index)
{
  f64 start_time, end_time, delta;
  app_session_t *session;
  char *transfer_type;
  u8 *test_data;
  u64 total_to_send;
  int i;

  vec_validate_aligned (utm->connect_test_data, 1024 * 1024 - 1,
			CLIB_CACHE_LINE_BYTES);
  for (i = 0; i < vec_len (utm->connect_test_data); i++)
    utm->connect_test_data[i] = i & 0xff;

  test_data = utm->connect_test_data;
  session = pool_elt_at_index (utm->sessions, session_index);
  ASSERT (vec_len (test_data) > 0);

  total_to_send = utm->bytes_to_send;
  vec_validate (utm->rx_buf, vec_len (test_data) - 1);
  start_time = clib_time_now (&utm->clib_time);
  while (!utm->time_to_stop && utm->bytes_to_send)
    {
      send_test_chunk (utm, session, 0);
      if (utm->have_return)
	recv_test_chunk (utm, session);
      if (utm->time_to_stop)
	break;
    }

  if (utm->have_return)
    {
      f64 timeout = clib_time_now (&utm->clib_time) + 5;
      while (clib_time_now (&utm->clib_time) < timeout)
	recv_test_chunk (utm, session);
    }

  end_time = clib_time_now (&utm->clib_time);
  delta = end_time - start_time;
  transfer_type = utm->have_return ? "full-duplex" : "half-duplex";
  clib_warning ("%lld bytes (%lld mbytes, %lld gbytes) in %.2f seconds",
		total_to_send, total_to_send / (1ULL << 20),
		total_to_send / (1ULL << 30), delta);
  clib_warning ("%.2f bytes/second %s", ((f64) total_to_send) / (delta),
		transfer_type);
  clib_warning ("%.4f gbit/second %s",
		(((f64) total_to_send * 8.0) / delta / 1e9), transfer_type);
}

static int
application_attach (udp_echo_main_t * utm)
{
  application_send_attach (utm);
  if (wait_for_state_change (utm, STATE_ATTACHED))
    {
      clib_warning ("timeout waiting for STATE_ATTACHED");
      return -1;
    }
  return 0;
}

static void
client_test (udp_echo_main_t * utm)
{
  f64 start_time, timeout = 100.0;
  svm_msg_q_msg_t msg;
  session_event_t *e;

  if (application_attach (utm))
    return;

  udp_client_send_connect (utm);

  start_time = clib_time_now (&utm->clib_time);
  while (utm->state < STATE_READY)
    {
      svm_msg_q_sub (utm->our_event_queue, &msg, SVM_Q_WAIT, 0);
      e = svm_msg_q_msg_data (utm->our_event_queue, &msg);
      handle_mq_event (e);
      svm_msg_q_free_msg (utm->our_event_queue, &msg);

      if (clib_time_now (&utm->clib_time) - start_time >= timeout)
	break;
    }

  if (utm->cut_through_session_index != ~0)
    client_send_data (utm, utm->cut_through_session_index);
  else
    client_send_data (utm, utm->connected_session);

  application_detach (utm);
  wait_for_state_change (utm, STATE_DETACHED);
}

static void
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t * mp)
{
  fifo_segment_create_args_t _a, *a = &_a;
  udp_echo_main_t *utm = &udp_echo_main;
  fifo_segment_main_t *sm = &utm->segment_main;
  fifo_segment_t *seg;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->segment_name = (char *) mp->segment_name;
  a->segment_size = mp->segment_size;
  /* Attach to the segment vpp created */
  rv = fifo_segment_attach (sm, a);
  if (rv)
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed",
		    mp->segment_name);
      return;
    }
  seg = fifo_segment_get_segment (sm, a->new_segment_indices[0]);
  clib_warning ("Mapped new segment '%s' size %d", seg->ssvm.name,
		seg->ssvm.ssvm_size);
  hash_set (utm->segments_table, clib_net_to_host_u64 (mp->segment_handle),
	    a->new_segment_indices[0]);
}

static void
vl_api_unmap_segment_t_handler (vl_api_unmap_segment_t * mp)
{
  udp_echo_main_t *utm = &udp_echo_main;
  fifo_segment_main_t *sm = &utm->segment_main;
  fifo_segment_t *seg;
  uword *seg_indexp;
  u64 segment_handle;

  segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  seg_indexp = hash_get (utm->segments_table, segment_handle);
  if (!seg_indexp)
    {
      clib_warning ("segment not mapped: %s", segment_handle);
      return;
    }
  hash_unset (utm->segments_table, segment_handle);
  seg = fifo_segment_get_segment (sm, (u32) seg_indexp[0]);
  fifo_segment_delete (sm, seg);
  clib_warning ("Unmapped segment '%s'", segment_handle);
}

static void
vl_api_unbind_uri_reply_t_handler (vl_api_unbind_uri_reply_t * mp)
{
  udp_echo_main_t *utm = &udp_echo_main;

  if (mp->retval)
    clib_warning ("returned %d", ntohl (mp->retval));

  utm->state = STATE_START;
}

static void
vl_api_bind_uri_reply_t_handler (vl_api_bind_uri_reply_t * mp)
{
  if (mp->retval)
    clib_warning ("returned %d", ntohl (mp->retval));
}

static void
vl_api_connect_uri_reply_t_handler (vl_api_bind_uri_reply_t * mp)
{
  if (mp->retval)
    clib_warning ("returned %d", ntohl (mp->retval));
}

static void
  vl_api_app_cut_through_registration_add_t_handler
  (vl_api_app_cut_through_registration_add_t * mp)
{

}

#define foreach_tcp_echo_msg                         			\
_(UNBIND_URI_REPLY, unbind_uri_reply)                                   \
_(BIND_URI_REPLY, bind_uri_reply)                               \
_(CONNECT_URI_REPLY, connect_uri_reply)           			\
_(MAP_ANOTHER_SEGMENT, map_another_segment)				\
_(UNMAP_SEGMENT, unmap_segment)						\
_(APPLICATION_ATTACH_REPLY, application_attach_reply)			\
_(APPLICATION_DETACH_REPLY, application_detach_reply)			\
_(APP_CUT_THROUGH_REGISTRATION_ADD, app_cut_through_registration_add)	\

void
echo_api_hookup (udp_echo_main_t * utm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_tcp_echo_msg;
#undef _

}

int
connect_to_vpp (char *name)
{
  udp_echo_main_t *utm = &udp_echo_main;
  api_main_t *am = &api_main;

  if (utm->use_sock_api)
    {
      if (vl_socket_client_connect ((char *) utm->socket_name, name,
				    0 /* default rx, tx buffer */ ))
	return -1;

      if (vl_socket_client_init_shm (0, 1 /* want_pthread */ ))
	return -1;
    }
  else
    {
      if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0)
	return -1;
    }
  utm->vl_input_queue = am->shmem_hdr->vl_input_queue;
  utm->my_client_index = am->my_client_index;
  return 0;
}

void
server_handle_fifo_event_rx (udp_echo_main_t * utm, u32 session_index)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  int n_read;
  app_session_t *session;
  int rv;
  u32 max_dequeue, offset, max_transfer, rx_buf_len;

  session = pool_elt_at_index (utm->sessions, session_index);
  rx_buf_len = vec_len (utm->rx_buf);
  rx_fifo = session->rx_fifo;
  tx_fifo = session->tx_fifo;


  max_dequeue = svm_fifo_max_dequeue_cons (rx_fifo);
  /* Allow enqueuing of a new event */
  svm_fifo_unset_event (rx_fifo);

  if (PREDICT_FALSE (!max_dequeue))
    return;

  /* Read the max_dequeue */
  do
    {
      max_transfer = clib_min (rx_buf_len, max_dequeue);
      if (session->is_dgram)
	n_read = app_recv_dgram_raw (rx_fifo, utm->rx_buf, max_transfer,
				     &session->transport, 0, 0);
      else
	n_read = app_recv_stream_raw (rx_fifo, utm->rx_buf, max_transfer, 0,
				      0);

      if (n_read > 0)
	max_dequeue -= n_read;

      /* Reflect if a non-drop session */
      if (utm->have_return && n_read > 0)
	{
	  offset = 0;
	  do
	    {
	      rv = app_send (session, &utm->rx_buf[offset], n_read,
			     SVM_Q_WAIT);
	      if (rv > 0)
		{
		  n_read -= rv;
		  offset += rv;
		}
	    }
	  while ((rv <= 0 || n_read > 0) && !utm->time_to_stop);

	  /* If event wasn't set, add one */
	  if (svm_fifo_set_event (tx_fifo))
	    app_send_io_evt_to_vpp (session->vpp_evt_q,
				    tx_fifo->master_session_index,
				    SESSION_IO_EVT_TX, SVM_Q_WAIT);
	}
    }
  while ((n_read < 0 || max_dequeue > 0) && !utm->time_to_stop);
}

static void
server_handle_event_queue (udp_echo_main_t * utm)
{
  session_event_t *e;
  svm_msg_q_msg_t msg;
  svm_msg_q_t *mq = utm->our_event_queue;

  while (utm->state != STATE_READY)
    sleep (5);

  while (1)
    {
      if (svm_msg_q_sub (mq, &msg, SVM_Q_WAIT, 0))
	{
	  clib_warning ("svm msg q returned");
	  continue;
	}
      e = svm_msg_q_msg_data (mq, &msg);
      switch (e->event_type)
	{
	case SESSION_IO_EVT_RX:
	  server_handle_fifo_event_rx (utm, e->session_index);
	  break;

	default:
	  handle_mq_event (e);
	  break;
	}
      svm_msg_q_free_msg (mq, &msg);
      if (PREDICT_FALSE (utm->time_to_stop == 1))
	return;
      if (PREDICT_FALSE (utm->time_to_print_stats == 1))
	{
	  utm->time_to_print_stats = 0;
	  fformat (stdout, "%d connections\n", pool_elts (utm->sessions));
	}
    }
}

static void
server_unbind (udp_echo_main_t * utm)
{
  vl_api_unbind_uri_t *ump;

  ump = vl_msg_api_alloc (sizeof (*ump));
  clib_memset (ump, 0, sizeof (*ump));

  ump->_vl_msg_id = ntohs (VL_API_UNBIND_URI);
  ump->client_index = utm->my_client_index;
  memcpy (ump->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & ump);
}

static void
server_bind (udp_echo_main_t * utm)
{
  vl_api_bind_uri_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  clib_memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_BIND_URI);
  bmp->client_index = utm->my_client_index;
  bmp->context = ntohl (0xfeedface);
  memcpy (bmp->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & bmp);
}

void
udp_server_test (udp_echo_main_t * utm)
{
  application_send_attach (utm);

  /* Bind to uri */
  server_bind (utm);

  if (wait_for_state_change (utm, STATE_READY))
    {
      clib_warning ("timeout waiting for state change");
      return;
    }

  server_handle_event_queue (utm);

  /* Cleanup */
  server_unbind (utm);

  if (wait_for_state_change (utm, STATE_START))
    {
      clib_warning ("timeout waiting for STATE_START");
      return;
    }

  application_detach (utm);

  fformat (stdout, "Test complete...\n");
}

void
quic_echo_process_opts (int argc, char **argv)
{
  udp_echo_main_t *utm = &udp_echo_main;
  unformat_input_t _argv, *a = &_argv;
  u8 *chroot_prefix;
  u8 *uri = 0;
  u32 tmp;
  unformat_init_command_line (a, argv);

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "chroot prefix %s", &chroot_prefix))
	vl_set_memory_root_path ((char *) chroot_prefix);
      else if (unformat (a, "uri %s", &uri))
	utm->uri = format (0, "%s%c", uri, 0);
      else if (unformat (a, "segment-size %dM", &tmp))
	utm->configured_segment_size = tmp << 20;
      else if (unformat (a, "segment-size %dG", &tmp))
	utm->configured_segment_size = tmp << 30;
      else if (unformat (a, "server"))
	utm->i_am_server = 1;
      else if (unformat (a, "client"))
	utm->i_am_server = 0;
      else if (unformat (a, "socket-name %s", &utm->socket_name))
	;
      else if (unformat (a, "use-svm-api"))
	utm->use_sock_api = 0;
      else if (unformat (a, "no-return"))
	utm->have_return = 0;
      else if (unformat (a, "mbytes %d", &tmp))
	utm->bytes_to_send = (u64) tmp << 20;
      else if (unformat (a, "fifo-size %d", &tmp))
	utm->fifo_size = tmp << 10;
      else
	{
	  fformat (stderr, "%s: usage [server|client]\n");
	  exit (1);
	}
    }
}

int
main (int argc, char **argv)
{
  udp_echo_main_t *utm = &udp_echo_main;
  app_session_t *session;
  char *app_name;
  int i;

  clib_mem_init_thread_safe (0, 256 << 20);
  clib_memset (utm, 0, sizeof (*utm));
  vec_validate (utm->rx_buf, 128 << 10);
  utm->session_index_by_vpp_handles = hash_create (0, sizeof (uword));
  utm->configured_segment_size = 1 << 20;
  utm->have_return = 1;
  utm->bytes_to_send = 1024;
  utm->use_sock_api = 1;
  utm->fifo_size = 128 << 10;
  utm->uri = format (0, "%s%c", "udp://0.0.0.0/1234", 0);
  utm->cut_through_session_index = ~0;
  clib_time_init (&utm->clib_time);

  init_error_string_table ();
  quic_echo_process_opts (argc, argv);

  setup_signal_handlers ();
  echo_api_hookup (utm);

  app_name = utm->i_am_server ? "udp_echo_server" : "udp_echo_client";
  utm->is_connected = (utm->uri[4] == 'c');	/* ugly hack for UDPC */
  if (connect_to_vpp (app_name) < 0)
    {
      svm_region_exit ();
      fformat (stderr, "Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  if (utm->i_am_server)
    {
      clib_warning ("I am server %s", utm->uri);
      /* $$$$ hack preallocation */
      for (i = 0; i < 200000; i++)
	{
	  pool_get (utm->sessions, session);
	  clib_memset (session, 0, sizeof (*session));
	}
      for (i = 0; i < 200000; i++)
	pool_put_index (utm->sessions, i);

      udp_server_test (utm);
    }
  else
    {
      client_test (utm);
    }

  vl_client_disconnect_from_vlib ();
  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
