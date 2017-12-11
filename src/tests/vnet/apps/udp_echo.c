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
#include <svm/svm_fifo_segment.h>
#include <pthread.h>
#include <vnet/session/application_interface.h>

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
  STATE_BOUND,
  STATE_READY,
  STATE_FAILED,
  STATE_DISCONNECTING,
} connection_state_t;

typedef struct
{
  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;
} session_t;

typedef struct
{
  /* vpe input queue */
  unix_shared_memory_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  /* The URI we're playing with */
  u8 *uri;

  /* Session pool */
  session_t *sessions;

  /* Hash table for disconnect processing */
  uword *session_index_by_vpp_handles;

  /* fifo segment */
  svm_fifo_segment_private_t *seg;

  /* intermediate rx buffer */
  u8 *rx_buf;

  /* URI for connect */
  u8 *connect_uri;

  int i_am_master;

  /* Our event queue */
  unix_shared_memory_queue_t *our_event_queue;

  /* $$$ single thread only for the moment */
  unix_shared_memory_queue_t *vpp_event_queue;

  /* $$$$ hack: cut-through session index */
  volatile u32 cut_through_session_index;
  volatile u32 connected_session;

  /* unique segment name counter */
  u32 unique_segment_index;

  pid_t my_pid;

  /* pthread handle */
  pthread_t cut_through_thread_handle;

  /* For deadman timers */
  clib_time_t clib_time;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile connection_state_t state;

  volatile int time_to_stop;
  volatile int time_to_print_stats;

  u32 configured_segment_size;

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;

  /* convenience */
  svm_fifo_segment_main_t *segment_main;

  u8 *connect_test_data;
} uri_udp_test_main_t;

#if CLIB_DEBUG > 0
#define NITER 10000
#else
#define NITER 4000000
#endif

uri_udp_test_main_t uri_udp_test_main;

static void
stop_signal (int signum)
{
  uri_udp_test_main_t *um = &uri_udp_test_main;

  um->time_to_stop = 1;
}

static void
stats_signal (int signum)
{
  uri_udp_test_main_t *um = &uri_udp_test_main;

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

void
application_send_attach (uri_udp_test_main_t * utm)
{
  vl_api_application_attach_t *bmp;
  u32 fifo_size = 1 << 20;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_ATTACH);
  bmp->client_index = utm->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_ACCEPT_REDIRECT | APP_OPTIONS_FLAGS_ADD_SEGMENT;
  bmp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 2;
  bmp->options[SESSION_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  bmp->options[SESSION_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  bmp->options[SESSION_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  bmp->options[SESSION_OPTIONS_SEGMENT_SIZE] = 256 << 20;
  bmp->options[APP_EVT_QUEUE_SIZE] = 16768;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & bmp);
}

void
application_detach (uri_udp_test_main_t * utm)
{
  vl_api_application_detach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_DETACH);
  bmp->client_index = utm->my_client_index;
  bmp->context = ntohl (0xfeedface);
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & bmp);
}

static void
vl_api_application_attach_reply_t_handler (vl_api_application_attach_reply_t *
					   mp)
{
  uri_udp_test_main_t *utm = &uri_udp_test_main;
  svm_fifo_segment_create_args_t _a, *a = &_a;
  int rv;

  if (mp->retval)
    {
      clib_warning ("attach failed: %d", mp->retval);
      utm->state = STATE_FAILED;
      return;
    }

  if (mp->segment_name_length == 0)
    {
      clib_warning ("segment_name_length zero");
      return;
    }

  a->segment_name = (char *) mp->segment_name;
  a->segment_size = mp->segment_size;

  ASSERT (mp->app_event_queue_address);

  /* Attach to the segment vpp created */
  rv = svm_fifo_segment_attach (a);
  if (rv)
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed",
		    mp->segment_name);
      return;
    }

  utm->our_event_queue =
    uword_to_pointer (mp->app_event_queue_address,
		      unix_shared_memory_queue_t *);
}

static void
vl_api_application_detach_reply_t_handler (vl_api_application_detach_reply_t *
					   mp)
{
  if (mp->retval)
    clib_warning ("detach returned with err: %d", mp->retval);
}

u8 *
format_api_error (u8 * s, va_list * args)
{
  uri_udp_test_main_t *utm = va_arg (*args, uri_udp_test_main_t *);
  i32 error = va_arg (*args, u32);
  uword *p;

  p = hash_get (utm->error_string_by_error_number, -error);

  if (p)
    s = format (s, "%s", p[0]);
  else
    s = format (s, "%d", error);
  return s;
}

int
wait_for_state_change (uri_udp_test_main_t * utm, connection_state_t state)
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
    }
  return -1;
}

u64 server_bytes_received, server_bytes_sent;

static void *
cut_through_thread_fn (void *arg)
{
  session_t *s;
  svm_fifo_t *rx_fifo;
  svm_fifo_t *tx_fifo;
  u8 *my_copy_buffer = 0;
  uri_udp_test_main_t *utm = &uri_udp_test_main;
  i32 actual_transfer;
  int rv;
  u32 buffer_offset;

  while (utm->cut_through_session_index == ~0)
    ;

  s = pool_elt_at_index (utm->sessions, utm->cut_through_session_index);

  rx_fifo = s->server_rx_fifo;
  tx_fifo = s->server_tx_fifo;

  vec_validate (my_copy_buffer, 64 * 1024 - 1);

  while (true)
    {
      /* We read from the tx fifo and write to the rx fifo */
      do
	{
	  actual_transfer = svm_fifo_dequeue_nowait (tx_fifo,
						     vec_len (my_copy_buffer),
						     my_copy_buffer);
	}
      while (actual_transfer <= 0);

      server_bytes_received += actual_transfer;

      buffer_offset = 0;
      while (actual_transfer > 0)
	{
	  rv = svm_fifo_enqueue_nowait (rx_fifo, actual_transfer,
					my_copy_buffer + buffer_offset);
	  if (rv > 0)
	    {
	      actual_transfer -= rv;
	      buffer_offset += rv;
	      server_bytes_sent += rv;
	    }

	}
      if (PREDICT_FALSE (utm->time_to_stop))
	break;
    }

  pthread_exit (0);
}

static void
udp_client_connect (uri_udp_test_main_t * utm)
{
  vl_api_connect_uri_t *cmp;
  cmp = vl_msg_api_alloc (sizeof (*cmp));
  memset (cmp, 0, sizeof (*cmp));

  cmp->_vl_msg_id = ntohs (VL_API_CONNECT_URI);
  cmp->client_index = utm->my_client_index;
  cmp->context = ntohl (0xfeedface);
  memcpy (cmp->uri, utm->connect_uri, vec_len (utm->connect_uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & cmp);
}

static void
client_send_cut_through (uri_udp_test_main_t * utm, session_t * session)
{
  int i;
  u8 *test_data = 0;
  u64 bytes_received = 0, bytes_sent = 0;
  i32 bytes_to_read;
  int rv;
  f64 before, after, delta, bytes_per_second;
  svm_fifo_t *rx_fifo, *tx_fifo;
  int buffer_offset, bytes_to_send = 0;

  /*
   * Prepare test data
   */
  vec_validate (test_data, 64 * 1024 - 1);
  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i & 0xff;

  rx_fifo = session->server_rx_fifo;
  tx_fifo = session->server_tx_fifo;

  before = clib_time_now (&utm->clib_time);

  vec_validate (utm->rx_buf, vec_len (test_data) - 1);

  for (i = 0; i < NITER; i++)
    {
      bytes_to_send = vec_len (test_data);
      buffer_offset = 0;
      while (bytes_to_send > 0)
	{
	  rv = svm_fifo_enqueue_nowait (tx_fifo, bytes_to_send,
					test_data + buffer_offset);

	  if (rv > 0)
	    {
	      bytes_to_send -= rv;
	      buffer_offset += rv;
	      bytes_sent += rv;
	    }
	}

      bytes_to_read = svm_fifo_max_dequeue (rx_fifo);
      bytes_to_read = vec_len (utm->rx_buf) > bytes_to_read ?
	bytes_to_read : vec_len (utm->rx_buf);

      buffer_offset = 0;
      while (bytes_to_read > 0)
	{
	  rv = svm_fifo_dequeue_nowait (rx_fifo,
					bytes_to_read,
					utm->rx_buf + buffer_offset);
	  if (rv > 0)
	    {
	      bytes_to_read -= rv;
	      buffer_offset += rv;
	      bytes_received += rv;
	    }
	}
    }
  while (bytes_received < bytes_sent)
    {
      rv =
	svm_fifo_dequeue_nowait (rx_fifo, vec_len (utm->rx_buf), utm->rx_buf);
      if (rv > 0)
	{
#if CLIB_DEBUG > 0
	  int j;
	  for (j = 0; j < rv; j++)
	    {
	      if (utm->rx_buf[j] != ((bytes_received + j) & 0xff))
		{
		  clib_warning ("error at byte %lld, 0x%x not 0x%x",
				bytes_received + j,
				utm->rx_buf[j],
				((bytes_received + j) & 0xff));
		}
	    }
#endif
	  bytes_received += (u64) rv;
	}
    }

  after = clib_time_now (&utm->clib_time);
  delta = after - before;
  bytes_per_second = 0.0;

  if (delta > 0.0)
    bytes_per_second = (f64) bytes_received / delta;

  fformat (stdout,
	   "Done: %lld recv bytes in %.2f seconds, %.2f bytes/sec...\n\n",
	   bytes_received, delta, bytes_per_second);
  fformat (stdout,
	   "Done: %lld sent bytes in %.2f seconds, %.2f bytes/sec...\n\n",
	   bytes_sent, delta, bytes_per_second);
  fformat (stdout,
	   "client -> server -> client round trip: %.2f Gbit/sec \n\n",
	   (bytes_per_second * 8.0) / 1e9);
}

static void
send_test_chunk (uri_udp_test_main_t * utm, svm_fifo_t * tx_fifo, int mypid,
		 u32 bytes)
{
  u8 *test_data = utm->connect_test_data;
  u64 bytes_sent = 0;
  int test_buf_offset = 0;
  u32 bytes_to_snd;
  u32 queue_max_chunk = 128 << 10, actual_write;
  session_fifo_event_t evt;
  int rv;

  bytes_to_snd = (bytes == 0) ? vec_len (test_data) : bytes;
  if (bytes_to_snd > vec_len (test_data))
    bytes_to_snd = vec_len (test_data);

  while (bytes_to_snd > 0 && !utm->time_to_stop)
    {
      actual_write = (bytes_to_snd > queue_max_chunk) ?
	queue_max_chunk : bytes_to_snd;
      rv = svm_fifo_enqueue_nowait (tx_fifo, actual_write,
				    test_data + test_buf_offset);

      if (rv > 0)
	{
	  bytes_to_snd -= rv;
	  test_buf_offset += rv;
	  bytes_sent += rv;

	  if (svm_fifo_set_event (tx_fifo))
	    {
	      /* Fabricate TX event, send to vpp */
	      evt.fifo = tx_fifo;
	      evt.event_type = FIFO_EVENT_APP_TX;

	      unix_shared_memory_queue_add (utm->vpp_event_queue,
					    (u8 *) & evt,
					    0 /* do wait for mutex */ );
	    }
	}
    }
}

static void
recv_test_chunk (uri_udp_test_main_t * utm, session_t * session)
{
  svm_fifo_t *rx_fifo;
  int buffer_offset, bytes_to_read = 0, rv;

  rx_fifo = session->server_rx_fifo;
  bytes_to_read = svm_fifo_max_dequeue (rx_fifo);
  bytes_to_read =
    vec_len (utm->rx_buf) > bytes_to_read ?
    bytes_to_read : vec_len (utm->rx_buf);

  buffer_offset = 0;
  while (bytes_to_read > 0)
    {
      rv = svm_fifo_dequeue_nowait (rx_fifo, bytes_to_read,
				    utm->rx_buf + buffer_offset);
      if (rv > 0)
	{
	  bytes_to_read -= rv;
	  buffer_offset += rv;
	}
    }
}

void
client_send_data (uri_udp_test_main_t * utm)
{
  u8 *test_data;
  int mypid = getpid ();
  session_t *session;
  svm_fifo_t *tx_fifo;
  u32 n_iterations;
  int i;

  vec_validate (utm->connect_test_data, 64 * 1024 - 1);
  for (i = 0; i < vec_len (utm->connect_test_data); i++)
    utm->connect_test_data[i] = i & 0xff;

  test_data = utm->connect_test_data;
  session = pool_elt_at_index (utm->sessions, utm->connected_session);
  tx_fifo = session->server_tx_fifo;

  ASSERT (vec_len (test_data) > 0);

  vec_validate (utm->rx_buf, vec_len (test_data) - 1);
  n_iterations = NITER;

  for (i = 0; i < n_iterations; i++)
    {
      send_test_chunk (utm, tx_fifo, mypid, 0);
      recv_test_chunk (utm, session);
      if (utm->time_to_stop)
	break;
    }

  f64 timeout = clib_time_now (&utm->clib_time) + 5;
  while (clib_time_now (&utm->clib_time) < timeout)
    {
      recv_test_chunk (utm, session);
    }

}

static void
client_test (uri_udp_test_main_t * utm)
{
  session_t *session;

  application_send_attach (utm);
  udp_client_connect (utm);

  if (wait_for_state_change (utm, STATE_READY))
    {
      clib_warning ("timeout waiting for STATE_READY");
      return;
    }

  if (utm->cut_through_session_index != ~0)
    {
      session = pool_elt_at_index (utm->sessions,
				   utm->cut_through_session_index);
      client_send_cut_through (utm, session);
    }
  else
    {
      session = pool_elt_at_index (utm->sessions, utm->connected_session);
      client_send_data (utm);
    }

  application_detach (utm);
}

static void
vl_api_bind_uri_reply_t_handler (vl_api_bind_uri_reply_t * mp)
{
  uri_udp_test_main_t *utm = &uri_udp_test_main;

  if (mp->retval)
    {
      clib_warning ("bind failed: %d", mp->retval);
      utm->state = STATE_FAILED;
      return;
    }

  utm->state = STATE_BOUND;
}

static void
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t * mp)
{
  svm_fifo_segment_create_args_t _a, *a = &_a;
  int rv;

  memset (a, 0, sizeof (*a));
  a->segment_name = (char *) mp->segment_name;
  a->segment_size = mp->segment_size;
  /* Attach to the segment vpp created */
  rv = svm_fifo_segment_attach (a);
  if (rv)
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed",
		    mp->segment_name);
      return;
    }
  clib_warning ("Mapped new segment '%s' size %d", mp->segment_name,
		mp->segment_size);
}

/**
 * Acting as server for redirected connect requests
 */
static void
vl_api_connect_uri_t_handler (vl_api_connect_uri_t * mp)
{
  u32 segment_index;
  uri_udp_test_main_t *utm = &uri_udp_test_main;
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
  svm_fifo_segment_create_args_t _a, *a = &_a;
  svm_fifo_segment_private_t *seg;
  unix_shared_memory_queue_t *client_q;
  vl_api_connect_session_reply_t *rmp;
  session_t *session = 0;
  int rv = 0;

  /* Create the segment */
  a->segment_name = (char *) format (0, "%d:segment%d%c", utm->my_pid,
				     utm->unique_segment_index++, 0);
  a->segment_size = utm->configured_segment_size;

  rv = svm_fifo_segment_create (a);
  if (rv)
    {
      clib_warning ("sm_fifo_segment_create ('%s') failed", a->segment_name);
      rv = VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
      goto send_reply;
    }

  vec_add2 (utm->seg, seg, 1);

  segment_index = vec_len (sm->segments) - 1;
  memcpy (seg, sm->segments + segment_index, sizeof (utm->seg[0]));

  pool_get (utm->sessions, session);

  session->server_rx_fifo = svm_fifo_segment_alloc_fifo
    (utm->seg, 128 * 1024, FIFO_SEGMENT_RX_FREELIST);
  ASSERT (session->server_rx_fifo);

  session->server_tx_fifo = svm_fifo_segment_alloc_fifo
    (utm->seg, 128 * 1024, FIFO_SEGMENT_TX_FREELIST);
  ASSERT (session->server_tx_fifo);

  session->server_rx_fifo->master_session_index = session - utm->sessions;
  session->server_tx_fifo->master_session_index = session - utm->sessions;
  utm->cut_through_session_index = session - utm->sessions;

  rv = pthread_create (&utm->cut_through_thread_handle,
		       NULL /*attr */ , cut_through_thread_fn, 0);
  if (rv)
    {
      clib_warning ("pthread_create returned %d", rv);
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
    }

send_reply:
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id = ntohs (VL_API_CONNECT_SESSION_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->segment_name_length = vec_len (a->segment_name);
  if (session)
    {
      rmp->server_rx_fifo = pointer_to_uword (session->server_rx_fifo);
      rmp->server_tx_fifo = pointer_to_uword (session->server_tx_fifo);
    }

  memcpy (rmp->segment_name, a->segment_name, vec_len (a->segment_name));

  vec_free (a->segment_name);

  client_q =
    uword_to_pointer (mp->client_queue_address, unix_shared_memory_queue_t *);
  vl_msg_api_send_shmem (client_q, (u8 *) & rmp);
}

static void
vl_api_unbind_uri_reply_t_handler (vl_api_unbind_uri_reply_t * mp)
{
  uri_udp_test_main_t *utm = &uri_udp_test_main;

  if (mp->retval != 0)
    clib_warning ("returned %d", ntohl (mp->retval));

  utm->state = STATE_START;
}

static void
vl_api_accept_session_t_handler (vl_api_accept_session_t * mp)
{
  uri_udp_test_main_t *utm = &uri_udp_test_main;
  vl_api_accept_session_reply_t *rmp;
  svm_fifo_t *rx_fifo, *tx_fifo;
  session_t *session;
  static f64 start_time;

  if (start_time == 0.0)
    start_time = clib_time_now (&utm->clib_time);

  utm->vpp_event_queue =
    uword_to_pointer (mp->vpp_event_queue_address,
		      unix_shared_memory_queue_t *);

  pool_get (utm->sessions, session);

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session - utm->sessions;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session - utm->sessions;

  session->server_rx_fifo = rx_fifo;
  session->server_tx_fifo = tx_fifo;

  hash_set (utm->session_index_by_vpp_handles, mp->handle,
	    session - utm->sessions);

  if (pool_elts (utm->sessions) && (pool_elts (utm->sessions) % 20000) == 0)
    {
      f64 now = clib_time_now (&utm->clib_time);
      fformat (stdout, "%d active sessions in %.2f seconds, %.2f/sec...\n",
	       pool_elts (utm->sessions), now - start_time,
	       (f64) pool_elts (utm->sessions) / (now - start_time));
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ACCEPT_SESSION_REPLY);
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & rmp);

  CLIB_MEMORY_BARRIER ();
  utm->state = STATE_READY;
}

static void
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  uri_udp_test_main_t *utm = &uri_udp_test_main;
  session_t *session;
  vl_api_disconnect_session_reply_t *rmp;
  uword *p;
  int rv = 0;

  p = hash_get (utm->session_index_by_vpp_handles, mp->handle);

  if (p)
    {
      session = pool_elt_at_index (utm->sessions, p[0]);
      hash_unset (utm->session_index_by_vpp_handles, mp->handle);
      pool_put (utm->sessions, session);
    }
  else
    {
      clib_warning ("couldn't find session key %llx", mp->handle);
      rv = -11;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION_REPLY);
  rmp->retval = rv;
  rmp->handle = mp->handle;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & rmp);
}

static void
vl_api_connect_session_reply_t_handler (vl_api_connect_session_reply_t * mp)
{
  uri_udp_test_main_t *utm = &uri_udp_test_main;
  session_t *session;

  ASSERT (utm->i_am_master == 0);

  if (mp->retval)
    {
      clib_warning ("failed connect");
      return;
    }

  /* We've been redirected */
  if (mp->segment_name_length > 0)
    {
      svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
      svm_fifo_segment_create_args_t _a, *a = &_a;
      u32 segment_index;
      svm_fifo_segment_private_t *seg;
      int rv;

      memset (a, 0, sizeof (*a));
      a->segment_name = (char *) mp->segment_name;

      sleep (1);

      rv = svm_fifo_segment_attach (a);
      if (rv)
	{
	  clib_warning ("sm_fifo_segment_create ('%v') failed",
			mp->segment_name);
	  return;
	}

      segment_index = a->new_segment_indices[0];
      vec_add2 (utm->seg, seg, 1);
      memcpy (seg, sm->segments + segment_index, sizeof (*seg));
      sleep (1);
    }

  pool_get (utm->sessions, session);
  session->server_rx_fifo = uword_to_pointer (mp->server_rx_fifo,
					      svm_fifo_t *);
  ASSERT (session->server_rx_fifo);
  session->server_tx_fifo = uword_to_pointer (mp->server_tx_fifo,
					      svm_fifo_t *);
  ASSERT (session->server_tx_fifo);

  if (mp->segment_name_length > 0)
    utm->cut_through_session_index = session - utm->sessions;
  else
    {
      utm->connected_session = session - utm->sessions;
      utm->vpp_event_queue = uword_to_pointer (mp->vpp_event_queue_address,
					       unix_shared_memory_queue_t *);
    }
  utm->state = STATE_READY;
}

#define foreach_uri_msg                         	\
_(BIND_URI_REPLY, bind_uri_reply)               	\
_(CONNECT_URI, connect_uri)                     	\
_(CONNECT_SESSION_REPLY, connect_session_reply)       	\
_(UNBIND_URI_REPLY, unbind_uri_reply)           	\
_(ACCEPT_SESSION, accept_session)			\
_(DISCONNECT_SESSION, disconnect_session)		\
_(MAP_ANOTHER_SEGMENT, map_another_segment)		\
_(APPLICATION_ATTACH_REPLY, application_attach_reply)	\
_(APPLICATION_DETACH_REPLY, application_detach_reply)	\

void
uri_api_hookup (uri_udp_test_main_t * utm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_uri_msg;
#undef _

}

int
connect_to_vpp (char *name)
{
  uri_udp_test_main_t *utm = &uri_udp_test_main;
  api_main_t *am = &api_main;

  if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0)
    return -1;

  utm->vl_input_queue = am->shmem_hdr->vl_input_queue;
  utm->my_client_index = am->my_client_index;

  return 0;
}

void
vlib_cli_output (struct vlib_main_t *vm, char *fmt, ...)
{
  clib_warning ("BUG");
}

static void
init_error_string_table (uri_udp_test_main_t * utm)
{
  utm->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n,v,s) hash_set (utm->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (utm->error_string_by_error_number, 99, "Misc");
}

void
server_handle_fifo_event_rx (uri_udp_test_main_t * utm,
			     session_fifo_event_t * e)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  int nbytes;
  session_fifo_event_t evt;
  unix_shared_memory_queue_t *q;
  int rv;

  rx_fifo = e->fifo;
  tx_fifo = utm->sessions[rx_fifo->client_session_index].server_tx_fifo;
  svm_fifo_unset_event (rx_fifo);

  do
    {
      nbytes = svm_fifo_dequeue_nowait (rx_fifo, vec_len (utm->rx_buf),
					utm->rx_buf);
    }
  while (nbytes <= 0);
  do
    {
      rv = svm_fifo_enqueue_nowait (tx_fifo, nbytes, utm->rx_buf);
    }
  while (rv == -2);

  if (svm_fifo_set_event (tx_fifo))
    {
      /* Fabricate TX event, send to vpp */
      evt.fifo = tx_fifo;
      evt.event_type = FIFO_EVENT_APP_TX;
      q = utm->vpp_event_queue;
      unix_shared_memory_queue_add (q, (u8 *) & evt,
				    0 /* do wait for mutex */ );
    }
}

void
server_handle_event_queue (uri_udp_test_main_t * utm)
{
  session_fifo_event_t _e, *e = &_e;

  while (utm->state != STATE_READY)
    sleep (5);

  while (1)
    {
      unix_shared_memory_queue_sub (utm->our_event_queue, (u8 *) e,
				    0 /* nowait */ );
      switch (e->event_type)
	{
	case FIFO_EVENT_APP_RX:
	  server_handle_fifo_event_rx (utm, e);
	  break;

	case FIFO_EVENT_DISCONNECT:
	  return;

	default:
	  clib_warning ("unknown event type %d", e->event_type);
	  break;
	}
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
server_unbind (uri_udp_test_main_t * utm)
{
  vl_api_unbind_uri_t *ump;

  ump = vl_msg_api_alloc (sizeof (*ump));
  memset (ump, 0, sizeof (*ump));

  ump->_vl_msg_id = ntohs (VL_API_UNBIND_URI);
  ump->client_index = utm->my_client_index;
  memcpy (ump->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & ump);
}

static void
server_bind (uri_udp_test_main_t * utm)
{
  vl_api_bind_uri_t *bmp;

  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_BIND_URI);
  bmp->client_index = utm->my_client_index;
  bmp->context = ntohl (0xfeedface);
  memcpy (bmp->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & bmp);
}

void
udp_server_test (uri_udp_test_main_t * utm)
{

  application_send_attach (utm);

  /* Bind to uri */
  server_bind (utm);

  if (wait_for_state_change (utm, STATE_BOUND))
    {
      clib_warning ("timeout waiting for STATE_BOUND");
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

int
main (int argc, char **argv)
{
  uri_udp_test_main_t *utm = &uri_udp_test_main;
  unformat_input_t _argv, *a = &_argv;
  u8 *chroot_prefix;
  u8 *heap;
  u8 *bind_name = (u8 *) "udp://0.0.0.0/1234";
  u32 tmp;
  mheap_t *h;
  session_t *session;
  int i;
  int i_am_master = 1;

  clib_mem_init (0, 256 << 20);

  heap = clib_mem_get_per_cpu_heap ();
  h = mheap_header (heap);

  /* make the main heap thread-safe */
  h->flags |= MHEAP_FLAG_THREAD_SAFE;

  vec_validate (utm->rx_buf, 8192);

  utm->session_index_by_vpp_handles = hash_create (0, sizeof (uword));

  utm->my_pid = getpid ();
  utm->configured_segment_size = 1 << 20;

  clib_time_init (&utm->clib_time);
  init_error_string_table (utm);
  svm_fifo_segment_init (0x200000000ULL, 20);
  unformat_init_command_line (a, argv);

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "chroot prefix %s", &chroot_prefix))
	{
	  vl_set_memory_root_path ((char *) chroot_prefix);
	}
      else if (unformat (a, "uri %s", &bind_name))
	;
      else if (unformat (a, "segment-size %dM", &tmp))
	utm->configured_segment_size = tmp << 20;
      else if (unformat (a, "segment-size %dG", &tmp))
	utm->configured_segment_size = tmp << 30;
      else if (unformat (a, "master"))
	i_am_master = 1;
      else if (unformat (a, "slave"))
	i_am_master = 0;
      else
	{
	  fformat (stderr, "%s: usage [master|slave]\n");
	  exit (1);
	}
    }

  utm->cut_through_session_index = ~0;
  utm->uri = format (0, "%s%c", bind_name, 0);
  utm->i_am_master = i_am_master;
  utm->segment_main = &svm_fifo_segment_main;

  utm->connect_uri = format (0, "udp://6.0.1.2/1234%c", 0);

  setup_signal_handlers ();

  uri_api_hookup (utm);

  if (connect_to_vpp (i_am_master ? "uri_udp_master" : "uri_udp_slave") < 0)
    {
      svm_region_exit ();
      fformat (stderr, "Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  if (i_am_master == 0)
    {
      client_test (utm);
      exit (0);
    }

  /* $$$$ hack preallocation */
  for (i = 0; i < 200000; i++)
    {
      pool_get (utm->sessions, session);
      memset (session, 0, sizeof (*session));
    }
  for (i = 0; i < 200000; i++)
    pool_put_index (utm->sessions, i);

  udp_server_test (utm);

  vl_client_disconnect_from_vlib ();
  exit (0);
}

#undef vl_api_version
#define vl_api_version(n,v) static u32 vpe_api_version = v;
#include <vpp/api/vpe.api.h>
#undef vl_api_version

void
vl_client_add_api_signatures (vl_api_memclnt_create_t * mp)
{
  /*
   * Send the main API signature in slot 0. This bit of code must
   * match the checks in ../vpe/api/api.c: vl_msg_api_version_check().
   */
  mp->api_versions[0] = clib_host_to_net_u32 (vpe_api_version);
}

u32
vl (void *p)
{
  return vec_len (p);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
