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
#include <signal.h>

#include <vnet/session/application_interface.h>
#include <svm/svm_fifo_segment.h>
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

typedef struct
{
  svm_fifo_t *rx_fifo;
  svm_fifo_t *tx_fifo;

  u64 vpp_session_handle;
  u64 bytes_received;
  f64 start;
} session_t;

typedef enum
{
  STATE_START,
  STATE_ATTACHED,
  STATE_READY,
  STATE_DISCONNECTING,
  STATE_FAILED
} connection_state_t;

typedef struct
{
  /* vpe input queue */
  svm_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  /* The URI we're playing with */
  u8 *uri;

  /* Session pool */
  session_t *sessions;

  /* Hash table for disconnect processing */
  uword *session_index_by_vpp_handles;

  /* intermediate rx buffer */
  u8 *rx_buf;

  /* URI for slave's connect */
  u8 *connect_uri;

  u32 connected_session_index;

  int i_am_master;

  /* drop all packets */
  int drop_packets;

  /* Our event queue */
  svm_queue_t *our_event_queue;

  /* $$$ single thread only for the moment */
  svm_queue_t *vpp_event_queue;

  u8 *socket_name;

  pid_t my_pid;

  /* For deadman timers */
  clib_time_t clib_time;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile connection_state_t state;

  /* Signal variables */
  volatile int time_to_stop;
  volatile int time_to_print_stats;

  u32 configured_segment_size;

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;

  u8 *connect_test_data;
  pthread_t client_rx_thread_handle;
  u32 client_bytes_received;
  u8 test_return_packets;
  u64 bytes_to_send;

  /** Flag that decides if socket, instead of svm, api is used to connect to
   * vpp. If sock api is used, shm binary api is subsequently bootstrapped
   * and all other messages are exchanged using shm IPC. */
  u8 use_sock_api;

  /* convenience */
  svm_fifo_segment_main_t *segment_main;
} echo_main_t;

echo_main_t echo_main;

#if CLIB_DEBUG > 0
#define NITER 10000
#else
#define NITER 4000000
#endif

static u8 *
format_api_error (u8 * s, va_list * args)
{
  echo_main_t *em = &echo_main;
  i32 error = va_arg (*args, u32);
  uword *p;

  p = hash_get (em->error_string_by_error_number, -error);

  if (p)
    s = format (s, "%s", p[0]);
  else
    s = format (s, "%d", error);
  return s;
}

static void
init_error_string_table (echo_main_t * em)
{
  em->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n,v,s) hash_set (em->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (em->error_string_by_error_number, 99, "Misc");
}

int
wait_for_state_change (echo_main_t * em, connection_state_t state)
{
#if CLIB_DEBUG > 0
#define TIMEOUT 600.0
#else
#define TIMEOUT 600.0
#endif

  f64 timeout = clib_time_now (&em->clib_time) + TIMEOUT;

  while (clib_time_now (&em->clib_time) < timeout)
    {
      if (em->state == state)
	return 0;
      if (em->state == STATE_FAILED)
	return -1;
      if (em->time_to_stop == 1)
	return 0;
    }
  clib_warning ("timeout waiting for STATE_READY");
  return -1;
}

void
application_send_attach (echo_main_t * em)
{
  vl_api_application_attach_t *bmp;
  u32 fifo_size = 4 << 20;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_ATTACH);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_ACCEPT_REDIRECT | APP_OPTIONS_FLAGS_ADD_SEGMENT;
  bmp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 16;
  bmp->options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  bmp->options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  bmp->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  bmp->options[APP_OPTIONS_SEGMENT_SIZE] = 256 << 20;
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);
}

int
application_attach (echo_main_t * em)
{
  application_send_attach (em);
  if (wait_for_state_change (em, STATE_ATTACHED))
    {
      clib_warning ("timeout waiting for STATE_ATTACHED");
      return -1;
    }
  return 0;
}

void
application_detach (echo_main_t * em)
{
  vl_api_application_detach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_DETACH);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);

  clib_warning ("Sent detach");
}

static int
memfd_segment_attach (void)
{
  ssvm_private_t _ssvm = { 0 }, *ssvm = &_ssvm;
  clib_error_t *error;
  int rv;

  if ((error = vl_socket_client_recv_fd_msg (&ssvm->fd, 5)))
    {
      clib_error_report (error);
      return -1;
    }

  if ((rv = ssvm_slave_init_memfd (ssvm)))
    return rv;

  return 0;
}

static int
fifo_segment_attach (char *name, u32 size, ssvm_segment_type_t type)
{
  svm_fifo_segment_create_args_t _a, *a = &_a;
  clib_error_t *error;
  int rv;

  memset (a, 0, sizeof (*a));
  a->segment_name = (char *) name;
  a->segment_size = size;
  a->segment_type = type;

  if (type == SSVM_SEGMENT_MEMFD)
    {
      if ((error = vl_socket_client_recv_fd_msg (&a->memfd_fd, 5)))
	{
	  clib_error_report (error);
	  return -1;
	}
    }

  if ((rv = svm_fifo_segment_attach (a)))
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed", name);
      return rv;
    }

  return 0;
}

static void
vl_api_application_attach_reply_t_handler (vl_api_application_attach_reply_t *
					   mp)
{
  echo_main_t *em = &echo_main;
  ssvm_segment_type_t seg_type;

  if (mp->retval)
    {
      clib_warning ("attach failed: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
      em->state = STATE_FAILED;
      return;
    }

  if (mp->segment_name_length == 0)
    {
      clib_warning ("segment_name_length zero");
      return;
    }

  seg_type = em->use_sock_api ? SSVM_SEGMENT_MEMFD : SSVM_SEGMENT_SHM;

  /* Attach to fifo segment */
  if (fifo_segment_attach ((char *) mp->segment_name, mp->segment_size,
			   seg_type))
    {
      em->state = STATE_FAILED;
      return;
    }

  /* If we're using memfd segments, read and attach to event qs segment */
  if (seg_type == SSVM_SEGMENT_MEMFD)
    {
      if (memfd_segment_attach ())
	{
	  clib_warning ("failed to attach to evt q segment");
	  em->state = STATE_FAILED;
	  return;
	}
    }

  ASSERT (mp->app_event_queue_address);
  em->our_event_queue = uword_to_pointer (mp->app_event_queue_address,
					  svm_queue_t *);
  em->state = STATE_ATTACHED;
}

static void
vl_api_application_detach_reply_t_handler (vl_api_application_detach_reply_t *
					   mp)
{
  if (mp->retval)
    clib_warning ("detach returned with err: %d", mp->retval);
}

static void
stop_signal (int signum)
{
  echo_main_t *um = &echo_main;

  um->time_to_stop = 1;
}

static void
stats_signal (int signum)
{
  echo_main_t *um = &echo_main;

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
vlib_cli_output (struct vlib_main_t *vm, char *fmt, ...)
{
  clib_warning ("BUG");
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
	  clib_warning ("socket connect failed");
	  return -1;
	}

      if (vl_socket_client_init_shm (0))
	{
	  clib_warning ("init shm api failed");
	  return -1;
	}
    }
  else
    {
      if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0)
	{
	  clib_warning ("shmem connect failed");
	  return -1;
	}
    }
  em->vl_input_queue = am->shmem_hdr->vl_input_queue;
  em->my_client_index = am->my_client_index;
  return 0;
}

void
disconnect_from_vpp (echo_main_t * em)
{
  if (em->use_sock_api)
    vl_socket_client_disconnect ();
  else
    vl_client_disconnect_from_vlib ();
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

static void
session_print_stats (echo_main_t * em, session_t * session)
{
  f64 deltat;
  u64 bytes;

  deltat = clib_time_now (&em->clib_time) - session->start;
  bytes = em->i_am_master ? session->bytes_received : em->bytes_to_send;
  fformat (stdout, "Finished in %.6f\n", deltat);
  fformat (stdout, "%.4f Gbit/second\n", (bytes * 8.0) / deltat / 1e9);
}

static void
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  echo_main_t *em = &echo_main;
  session_t *session = 0;
  vl_api_disconnect_session_reply_t *rmp;
  uword *p;
  int rv = 0;

  p = hash_get (em->session_index_by_vpp_handles, mp->handle);

  if (p)
    {
      session = pool_elt_at_index (em->sessions, p[0]);
      hash_unset (em->session_index_by_vpp_handles, mp->handle);
      pool_put (em->sessions, session);
    }
  else
    {
      clib_warning ("couldn't find session key %llx", mp->handle);
      rv = -11;
    }

//  em->time_to_stop = 1;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION_REPLY);
  rmp->retval = rv;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & rmp);

  if (session)
    session_print_stats (em, session);
}

static void
vl_api_reset_session_t_handler (vl_api_reset_session_t * mp)
{
  echo_main_t *em = &echo_main;
  vl_api_reset_session_reply_t *rmp;
  uword *p;
  int rv = 0;

  p = hash_get (em->session_index_by_vpp_handles, mp->handle);

  if (p)
    {
      clib_warning ("got reset");
      /* Cleanup later */
      em->time_to_stop = 1;
    }
  else
    {
      clib_warning ("couldn't find session key %llx", mp->handle);
      rv = -11;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_RESET_SESSION_REPLY);
  rmp->retval = rv;
  rmp->handle = mp->handle;
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & rmp);
}

void
client_handle_fifo_event_rx (echo_main_t * em, session_fifo_event_t * e)
{
  svm_fifo_t *rx_fifo;
  int n_read, bytes, i;

  rx_fifo = e->fifo;

  bytes = svm_fifo_max_dequeue (rx_fifo);
  /* Allow enqueuing of new event */
  svm_fifo_unset_event (rx_fifo);

  /* Read the bytes */
  do
    {
      n_read = svm_fifo_dequeue_nowait (rx_fifo,
					clib_min (vec_len (em->rx_buf),
						  bytes), em->rx_buf);
      if (n_read > 0)
	{
	  bytes -= n_read;
	  if (em->test_return_packets)
	    {
	      for (i = 0; i < n_read; i++)
		{
		  if (em->rx_buf[i]
		      != ((em->client_bytes_received + i) & 0xff))
		    {
		      clib_warning ("error at byte %lld, 0x%x not 0x%x",
				    em->client_bytes_received + i,
				    em->rx_buf[i],
				    ((em->client_bytes_received + i) & 0xff));
		    }
		}
	    }
	  em->client_bytes_received += n_read;
	}
      else
	{
	  if (n_read == -2)
	    {
//            clib_warning ("weird!");
	      break;
	    }
	}

    }
  while (bytes > 0);
}

void
client_handle_event_queue (echo_main_t * em)
{
  session_fifo_event_t _e, *e = &_e;;

  svm_queue_sub (em->our_event_queue, (u8 *) e, SVM_Q_WAIT, 0);
  switch (e->event_type)
    {
    case FIFO_EVENT_APP_RX:
      client_handle_fifo_event_rx (em, e);
      break;

    case FIFO_EVENT_DISCONNECT:
      return;

    default:
      clib_warning ("unknown event type %d", e->event_type);
      break;
    }
}

static void *
client_rx_thread_fn (void *arg)
{
  session_fifo_event_t _e, *e = &_e;
  echo_main_t *em = &echo_main;

  em->client_bytes_received = 0;
  while (1)
    {
      svm_queue_sub (em->our_event_queue, (u8 *) e, SVM_Q_WAIT, 0);
      switch (e->event_type)
	{
	case FIFO_EVENT_APP_RX:
	  client_handle_fifo_event_rx (em, e);
	  break;

	case FIFO_EVENT_DISCONNECT:
	  return 0;
	default:
	  clib_warning ("unknown event type %d", e->event_type);
	  break;
	}

      if (PREDICT_FALSE (em->time_to_stop == 1))
	break;
    }
  pthread_exit (0);
}


static void
vl_api_connect_session_reply_t_handler (vl_api_connect_session_reply_t * mp)
{
  echo_main_t *em = &echo_main;
  session_t *session;
  u32 session_index;
  svm_fifo_t *rx_fifo, *tx_fifo;
  int rv;

  if (mp->retval)
    {
      clib_warning ("connection failed with code: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
      em->state = STATE_FAILED;
      return;
    }
  else
    {
      clib_warning ("connected with local ip %U port %d", format_ip46_address,
		    mp->lcl_ip, mp->is_ip4,
		    clib_net_to_host_u16 (mp->lcl_port));
    }

  em->vpp_event_queue =
    uword_to_pointer (mp->vpp_event_queue_address, svm_queue_t *);

  /*
   * Setup session
   */

  pool_get (em->sessions, session);
  session_index = session - em->sessions;

  rx_fifo = uword_to_pointer (mp->rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;
  session->vpp_session_handle = mp->handle;
  session->start = clib_time_now (&em->clib_time);

  /* Save handle */
  em->connected_session_index = session_index;
  em->state = STATE_READY;

  /* Add it to lookup table */
  hash_set (em->session_index_by_vpp_handles, mp->handle, session_index);

  /* Start RX thread */
  rv = pthread_create (&em->client_rx_thread_handle,
		       NULL /*attr */ , client_rx_thread_fn, 0);
  if (rv)
    {
      clib_warning ("pthread_create returned %d", rv);
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
    }
}

static void
send_test_chunk (echo_main_t * em, svm_fifo_t * tx_fifo, int mypid, u32 bytes)
{
  u8 *test_data = em->connect_test_data;
  u64 bytes_sent = 0;
  int test_buf_offset = 0;
  u32 bytes_to_snd;
  u32 queue_max_chunk = 128 << 10, actual_write;
  session_fifo_event_t evt;
  int rv;

  bytes_to_snd = (bytes == 0) ? vec_len (test_data) : bytes;
  if (bytes_to_snd > vec_len (test_data))
    bytes_to_snd = vec_len (test_data);

  while (bytes_to_snd > 0 && !em->time_to_stop)
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

	      svm_queue_add (em->vpp_event_queue,
			     (u8 *) & evt, 0 /* do wait for mutex */ );
	    }
	}
    }
}

void
client_send_data (echo_main_t * em)
{
  u8 *test_data = em->connect_test_data;
  int mypid = getpid ();
  session_t *session;
  svm_fifo_t *tx_fifo;
  u32 n_iterations, leftover;
  int i;

  session = pool_elt_at_index (em->sessions, em->connected_session_index);
  tx_fifo = session->tx_fifo;

  ASSERT (vec_len (test_data) > 0);

  vec_validate (em->rx_buf, vec_len (test_data) - 1);
  n_iterations = em->bytes_to_send / vec_len (test_data);

  for (i = 0; i < n_iterations; i++)
    {
      send_test_chunk (em, tx_fifo, mypid, 0);
      if (em->time_to_stop)
	break;
    }

  leftover = em->bytes_to_send % vec_len (test_data);
  if (leftover)
    send_test_chunk (em, tx_fifo, mypid, leftover);

  if (!em->drop_packets)
    {
      f64 timeout = clib_time_now (&em->clib_time) + 10;

      /* Wait for the outstanding packets */
      while (em->client_bytes_received <
	     vec_len (test_data) * n_iterations + leftover)
	{
	  if (clib_time_now (&em->clib_time) > timeout)
	    {
	      clib_warning ("timed out waiting for the missing packets");
	      break;
	    }
	}
    }
  em->time_to_stop = 1;
}

void
client_send_connect (echo_main_t * em)
{
  vl_api_connect_uri_t *cmp;
  cmp = vl_msg_api_alloc (sizeof (*cmp));
  memset (cmp, 0, sizeof (*cmp));

  cmp->_vl_msg_id = ntohs (VL_API_CONNECT_URI);
  cmp->client_index = em->my_client_index;
  cmp->context = ntohl (0xfeedface);
  memcpy (cmp->uri, em->connect_uri, vec_len (em->connect_uri));
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & cmp);
}

int
client_connect (echo_main_t * em)
{
  client_send_connect (em);
  if (wait_for_state_change (em, STATE_READY))
    {
      clib_warning ("Connect failed");
      return -1;
    }
  return 0;
}

void
client_send_disconnect (echo_main_t * em)
{
  session_t *connected_session;
  vl_api_disconnect_session_t *dmp;
  connected_session = pool_elt_at_index (em->sessions,
					 em->connected_session_index);
  dmp = vl_msg_api_alloc (sizeof (*dmp));
  memset (dmp, 0, sizeof (*dmp));
  dmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION);
  dmp->client_index = em->my_client_index;
  dmp->handle = connected_session->vpp_session_handle;
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & dmp);
}

int
client_disconnect (echo_main_t * em)
{
  client_send_disconnect (em);
  clib_warning ("Sent disconnect");
  if (wait_for_state_change (em, STATE_START))
    {
      clib_warning ("Disconnect failed");
      return -1;
    }
  return 0;
}

static void
client_run (echo_main_t * em)
{
  int i;

  if (application_attach (em))
    return;

  if (client_connect (em))
    {
      application_detach (em);
      return;
    }

  /* Init test data */
  vec_validate (em->connect_test_data, 128 * 1024 - 1);
  for (i = 0; i < vec_len (em->connect_test_data); i++)
    em->connect_test_data[i] = i & 0xff;

  /* Start send */
  client_send_data (em);

  /* Disconnect and detach */
  client_disconnect (em);
  application_detach (em);
}

static void
vl_api_bind_uri_reply_t_handler (vl_api_bind_uri_reply_t * mp)
{
  echo_main_t *em = &echo_main;

  if (mp->retval)
    {
      clib_warning ("bind failed: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
      em->state = STATE_FAILED;
      return;
    }

  em->state = STATE_READY;
}

static void
vl_api_unbind_uri_reply_t_handler (vl_api_unbind_uri_reply_t * mp)
{
  echo_main_t *em = &echo_main;

  if (mp->retval != 0)
    clib_warning ("returned %d", ntohl (mp->retval));

  em->state = STATE_START;
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

static void
vl_api_accept_session_t_handler (vl_api_accept_session_t * mp)
{
  echo_main_t *em = &echo_main;
  vl_api_accept_session_reply_t *rmp;
  svm_fifo_t *rx_fifo, *tx_fifo;
  session_t *session;
  static f64 start_time;
  u32 session_index;
  u8 *ip_str;

  if (start_time == 0.0)
    start_time = clib_time_now (&em->clib_time);

  ip_str = format (0, "%U", format_ip46_address, &mp->ip, mp->is_ip4);
  clib_warning ("Accepted session from: %s:%d", ip_str,
		clib_net_to_host_u16 (mp->port));
  em->vpp_event_queue =
    uword_to_pointer (mp->vpp_event_queue_address, svm_queue_t *);

  /* Allocate local session and set it up */
  pool_get (em->sessions, session);
  session_index = session - em->sessions;

  rx_fifo = uword_to_pointer (mp->rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;

  /* Add it to lookup table */
  hash_set (em->session_index_by_vpp_handles, mp->handle, session_index);

  em->state = STATE_READY;

  /* Stats printing */
  if (pool_elts (em->sessions) && (pool_elts (em->sessions) % 20000) == 0)
    {
      f64 now = clib_time_now (&em->clib_time);
      fformat (stdout, "%d active sessions in %.2f seconds, %.2f/sec...\n",
	       pool_elts (em->sessions), now - start_time,
	       (f64) pool_elts (em->sessions) / (now - start_time));
    }

  /*
   * Send accept reply to vpp
   */
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ACCEPT_SESSION_REPLY);
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & rmp);

  session->bytes_received = 0;
  session->start = clib_time_now (&em->clib_time);
}

void
server_handle_fifo_event_rx (echo_main_t * em, session_fifo_event_t * e)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  int n_read;
  session_fifo_event_t evt;
  svm_queue_t *q;
  session_t *session;
  int rv;
  u32 max_dequeue, offset, max_transfer, rx_buf_len;

  rx_buf_len = vec_len (em->rx_buf);
  rx_fifo = e->fifo;
  session = &em->sessions[rx_fifo->client_session_index];
  tx_fifo = session->tx_fifo;

  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  /* Allow enqueuing of a new event */
  svm_fifo_unset_event (rx_fifo);

  if (PREDICT_FALSE (max_dequeue == 0))
    {
      return;
    }

  /* Read the max_dequeue */
  do
    {
      max_transfer = clib_min (rx_buf_len, max_dequeue);
      n_read = svm_fifo_dequeue_nowait (rx_fifo, max_transfer, em->rx_buf);
      if (n_read > 0)
	{
	  max_dequeue -= n_read;
	  session->bytes_received += n_read;
	}

      /* Reflect if a non-drop session */
      if (!em->drop_packets && n_read > 0)
	{
	  offset = 0;
	  do
	    {
	      rv = svm_fifo_enqueue_nowait (tx_fifo, n_read,
					    &em->rx_buf[offset]);
	      if (rv > 0)
		{
		  n_read -= rv;
		  offset += rv;
		}
	    }
	  while ((rv <= 0 || n_read > 0) && !em->time_to_stop);

	  /* If event wasn't set, add one */
	  if (svm_fifo_set_event (tx_fifo))
	    {
	      /* Fabricate TX event, send to vpp */
	      evt.fifo = tx_fifo;
	      evt.event_type = FIFO_EVENT_APP_TX;

	      q = em->vpp_event_queue;
	      svm_queue_add (q, (u8 *) & evt, 1 /* do wait for mutex */ );
	    }
	}
    }
  while ((n_read < 0 || max_dequeue > 0) && !em->time_to_stop);
}

void
server_handle_event_queue (echo_main_t * em)
{
  session_fifo_event_t _e, *e = &_e;

  while (1)
    {
      svm_queue_sub (em->our_event_queue, (u8 *) e, SVM_Q_WAIT, 0);
      switch (e->event_type)
	{
	case FIFO_EVENT_APP_RX:
	  server_handle_fifo_event_rx (em, e);
	  break;

	case FIFO_EVENT_DISCONNECT:
	  return;

	default:
	  clib_warning ("unknown event type %d", e->event_type);
	  break;
	}
      if (PREDICT_FALSE (em->time_to_stop == 1))
	break;
      if (PREDICT_FALSE (em->time_to_print_stats == 1))
	{
	  em->time_to_print_stats = 0;
	  fformat (stdout, "%d connections\n", pool_elts (em->sessions));
	}
    }
}

void
server_send_listen (echo_main_t * em)
{
  vl_api_bind_uri_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_BIND_URI);
  bmp->client_index = em->my_client_index;
  bmp->context = ntohl (0xfeedface);
  memcpy (bmp->uri, em->uri, vec_len (em->uri));
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & bmp);
}

int
server_listen (echo_main_t * em)
{
  server_send_listen (em);
  if (wait_for_state_change (em, STATE_READY))
    {
      clib_warning ("timeout waiting for STATE_READY");
      return -1;
    }
  return 0;
}

void
server_send_unbind (echo_main_t * em)
{
  vl_api_unbind_uri_t *ump;

  ump = vl_msg_api_alloc (sizeof (*ump));
  memset (ump, 0, sizeof (*ump));

  ump->_vl_msg_id = ntohs (VL_API_UNBIND_URI);
  ump->client_index = em->my_client_index;
  memcpy (ump->uri, em->uri, vec_len (em->uri));
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & ump);
}

int
server_unbind (echo_main_t * em)
{
  server_send_unbind (em);
  if (wait_for_state_change (em, STATE_START))
    {
      clib_warning ("timeout waiting for STATE_START");
      return -1;
    }
  return 0;
}

void
server_run (echo_main_t * em)
{
  session_t *session;
  int i;

  /* $$$$ hack preallocation */
  for (i = 0; i < 200000; i++)
    {
      pool_get (em->sessions, session);
      memset (session, 0, sizeof (*session));
    }
  for (i = 0; i < 200000; i++)
    pool_put_index (em->sessions, i);

  if (application_attach (em))
    return;

  /* Bind to uri */
  if (server_listen (em))
    return;

  /* Enter handle event loop */
  server_handle_event_queue (em);

  /* Cleanup */
  server_send_unbind (em);

  application_detach (em);

  fformat (stdout, "Test complete...\n");
}

static void
vl_api_disconnect_session_reply_t_handler (vl_api_disconnect_session_reply_t *
					   mp)
{
  echo_main_t *em = &echo_main;
  session_t *session;

  if (mp->retval)
    {
      clib_warning ("vpp complained about disconnect: %d",
		    ntohl (mp->retval));
    }

  em->state = STATE_START;
  session = pool_elt_at_index (em->sessions, em->connected_session_index);
  if (session)
    session_print_stats (em, session);
}

#define foreach_tcp_echo_msg                            	\
_(BIND_URI_REPLY, bind_uri_reply)                       	\
_(UNBIND_URI_REPLY, unbind_uri_reply)                   	\
_(ACCEPT_SESSION, accept_session)                       	\
_(CONNECT_SESSION_REPLY, connect_session_reply)         	\
_(DISCONNECT_SESSION, disconnect_session)               	\
_(DISCONNECT_SESSION_REPLY, disconnect_session_reply)   	\
_(RESET_SESSION, reset_session)                         	\
_(APPLICATION_ATTACH_REPLY, application_attach_reply)   	\
_(APPLICATION_DETACH_REPLY, application_detach_reply)		\
_(MAP_ANOTHER_SEGMENT, map_another_segment)			\

void
tcp_echo_api_hookup (echo_main_t * em)
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
main (int argc, char **argv)
{
  int i_am_master = 1, drop_packets = 0, test_return_packets = 0;
  echo_main_t *em = &echo_main;
  unformat_input_t _argv, *a = &_argv;
  u8 *chroot_prefix;
  u8 *heap, *uri = 0;
  u8 *bind_uri = (u8 *) "tcp://0.0.0.0/1234";
  u8 *connect_uri = (u8 *) "tcp://6.0.1.2/1234";
  u64 bytes_to_send = 64 << 10, mbytes;
  char *app_name;
  u32 tmp;
  mheap_t *h;

  clib_mem_init (0, 256 << 20);

  heap = clib_mem_get_per_cpu_heap ();
  h = mheap_header (heap);

  /* make the main heap thread-safe */
  h->flags |= MHEAP_FLAG_THREAD_SAFE;

  vec_validate (em->rx_buf, 128 << 10);

  em->session_index_by_vpp_handles = hash_create (0, sizeof (uword));

  em->my_pid = getpid ();
  em->configured_segment_size = 1 << 20;
  em->socket_name = 0;
  em->use_sock_api = 1;

  clib_time_init (&em->clib_time);
  init_error_string_table (em);
  svm_fifo_segment_main_init (0x200000000ULL, 20);
  unformat_init_command_line (a, argv);

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "chroot prefix %s", &chroot_prefix))
	{
	  vl_set_memory_root_path ((char *) chroot_prefix);
	}
      else if (unformat (a, "uri %s", &uri))
	;
      else if (unformat (a, "segment-size %dM", &tmp))
	em->configured_segment_size = tmp << 20;
      else if (unformat (a, "segment-size %dG", &tmp))
	em->configured_segment_size = tmp << 30;
      else if (unformat (a, "master"))
	i_am_master = 1;
      else if (unformat (a, "slave"))
	i_am_master = 0;
      else if (unformat (a, "drop"))
	drop_packets = 1;
      else if (unformat (a, "test"))
	test_return_packets = 1;
      else if (unformat (a, "mbytes %lld", &mbytes))
	{
	  bytes_to_send = mbytes << 20;
	}
      else if (unformat (a, "gbytes %lld", &mbytes))
	{
	  bytes_to_send = mbytes << 30;
	}
      else if (unformat (a, "socket-name %s", &em->socket_name))
	;
      else if (unformat (a, "use-svm-api"))
	em->use_sock_api = 0;
      else
	{
	  fformat (stderr, "%s: usage [master|slave]\n");
	  exit (1);
	}
    }

  if (!em->socket_name)
    em->socket_name = format (0, "%s%c", API_SOCKET_FILE, 0);

  if (uri)
    {
      em->uri = format (0, "%s%c", uri, 0);
      em->connect_uri = format (0, "%s%c", uri, 0);
    }
  else
    {
      em->uri = format (0, "%s%c", bind_uri, 0);
      em->connect_uri = format (0, "%s%c", connect_uri, 0);
    }

  em->i_am_master = i_am_master;
  em->segment_main = &svm_fifo_segment_main;
  em->drop_packets = drop_packets;
  em->test_return_packets = test_return_packets;
  em->bytes_to_send = bytes_to_send;
  em->time_to_stop = 0;

  setup_signal_handlers ();
  tcp_echo_api_hookup (em);

  app_name = i_am_master ? "tcp_echo_server" : "tcp_echo_client";
  if (connect_to_vpp (app_name) < 0)
    {
      svm_region_exit ();
      fformat (stderr, "Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  if (i_am_master == 0)
    client_run (em);
  else
    server_run (em);

  disconnect_from_vpp (em);
  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
