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
#include <svm/svm_fifo_segment.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>
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

typedef struct
{
  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;

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
  unix_shared_memory_queue_t *vl_input_queue;

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
  unix_shared_memory_queue_t *our_event_queue;

  /* $$$ single thread only for the moment */
  unix_shared_memory_queue_t *vpp_event_queue;

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

  /* convenience */
  svm_fifo_segment_main_t *segment_main;
} uri_tcp_test_main_t;

uri_tcp_test_main_t uri_tcp_test_main;

#if CLIB_DEBUG > 0
#define NITER 10000
#else
#define NITER 4000000
#endif

static u8 *
format_api_error (u8 * s, va_list * args)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  i32 error = va_arg (*args, u32);
  uword *p;

  p = hash_get (utm->error_string_by_error_number, -error);

  if (p)
    s = format (s, "%s", p[0]);
  else
    s = format (s, "%d", error);
  return s;
}

static void
init_error_string_table (uri_tcp_test_main_t * utm)
{
  utm->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n,v,s) hash_set (utm->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (utm->error_string_by_error_number, 99, "Misc");
}

int
wait_for_state_change (uri_tcp_test_main_t * utm, connection_state_t state)
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
      if (utm->time_to_stop == 1)
	return 0;
    }
  clib_warning ("timeout waiting for STATE_READY");
  return -1;
}

void
application_send_attach (uri_tcp_test_main_t * utm)
{
  vl_api_application_attach_t *bmp;
  u32 fifo_size = 4 << 20;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_ATTACH);
  bmp->client_index = utm->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_ACCEPT_REDIRECT | APP_OPTIONS_FLAGS_ADD_SEGMENT;
  bmp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 16;
  bmp->options[SESSION_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  bmp->options[SESSION_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  bmp->options[SESSION_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  bmp->options[SESSION_OPTIONS_SEGMENT_SIZE] = 256 << 20;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & bmp);
}

int
application_attach (uri_tcp_test_main_t * utm)
{
  application_send_attach (utm);
  if (wait_for_state_change (utm, STATE_ATTACHED))
    {
      clib_warning ("timeout waiting for STATE_ATTACHED");
      return -1;
    }
  return 0;
}

void
application_detach (uri_tcp_test_main_t * utm)
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
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  svm_fifo_segment_create_args_t _a, *a = &_a;
  int rv;

  if (mp->retval)
    {
      clib_warning ("attach failed: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
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
  utm->state = STATE_ATTACHED;
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
  uri_tcp_test_main_t *um = &uri_tcp_test_main;

  um->time_to_stop = 1;
}

static void
stats_signal (int signum)
{
  uri_tcp_test_main_t *um = &uri_tcp_test_main;

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
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  api_main_t *am = &api_main;

  if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0)
    return -1;

  utm->vl_input_queue = am->shmem_hdr->vl_input_queue;
  utm->my_client_index = am->my_client_index;

  return 0;
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
session_print_stats (uri_tcp_test_main_t * utm, session_t * session)
{
  f64 deltat;
  u64 bytes;

  deltat = clib_time_now (&utm->clib_time) - session->start;
  bytes = utm->i_am_master ? session->bytes_received : utm->bytes_to_send;
  fformat (stdout, "Finished in %.6f\n", deltat);
  fformat (stdout, "%.4f Gbit/second\n", (bytes * 8.0) / deltat / 1e9);
}

static void
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  session_t *session = 0;
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

//  utm->time_to_stop = 1;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION_REPLY);
  rmp->retval = rv;
  rmp->handle = mp->handle;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & rmp);

  if (session)
    session_print_stats (utm, session);
}

static void
vl_api_reset_session_t_handler (vl_api_reset_session_t * mp)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  vl_api_reset_session_reply_t *rmp;
  uword *p;
  int rv = 0;

  p = hash_get (utm->session_index_by_vpp_handles, mp->handle);

  if (p)
    {
      clib_warning ("got reset");
      /* Cleanup later */
      utm->time_to_stop = 1;
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
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & rmp);
}

void
client_handle_fifo_event_rx (uri_tcp_test_main_t * utm,
			     session_fifo_event_t * e)
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
					clib_min (vec_len (utm->rx_buf),
						  bytes), utm->rx_buf);
      if (n_read > 0)
	{
	  bytes -= n_read;
	  if (utm->test_return_packets)
	    {
	      for (i = 0; i < n_read; i++)
		{
		  if (utm->rx_buf[i]
		      != ((utm->client_bytes_received + i) & 0xff))
		    {
		      clib_warning ("error at byte %lld, 0x%x not 0x%x",
				    utm->client_bytes_received + i,
				    utm->rx_buf[i],
				    ((utm->client_bytes_received +
				      i) & 0xff));
		    }
		}
	    }
	  utm->client_bytes_received += n_read;
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
client_handle_event_queue (uri_tcp_test_main_t * utm)
{
  session_fifo_event_t _e, *e = &_e;;

  unix_shared_memory_queue_sub (utm->our_event_queue, (u8 *) e,
				0 /* nowait */ );
  switch (e->event_type)
    {
    case FIFO_EVENT_APP_RX:
      client_handle_fifo_event_rx (utm, e);
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
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;

  utm->client_bytes_received = 0;
  while (1)
    {
      unix_shared_memory_queue_sub (utm->our_event_queue, (u8 *) e,
				    0 /* nowait */ );
      switch (e->event_type)
	{
	case FIFO_EVENT_APP_RX:
	  client_handle_fifo_event_rx (utm, e);
	  break;

	case FIFO_EVENT_DISCONNECT:
	  return 0;
	default:
	  clib_warning ("unknown event type %d", e->event_type);
	  break;
	}

      if (PREDICT_FALSE (utm->time_to_stop == 1))
	break;
    }
  pthread_exit (0);
}


static void
vl_api_connect_session_reply_t_handler (vl_api_connect_session_reply_t * mp)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  session_t *session;
  u32 session_index;
  svm_fifo_t *rx_fifo, *tx_fifo;
  int rv;

  if (mp->retval)
    {
      clib_warning ("connection failed with code: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
      utm->state = STATE_FAILED;
      return;
    }
  else
    {
      clib_warning ("connected with local ip %U port %d", format_ip46_address,
		    mp->lcl_ip, mp->is_ip4,
		    clib_net_to_host_u16 (mp->lcl_port));
    }

  utm->vpp_event_queue =
    uword_to_pointer (mp->vpp_event_queue_address,
		      unix_shared_memory_queue_t *);

  /*
   * Setup session
   */

  pool_get (utm->sessions, session);
  session_index = session - utm->sessions;

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->server_rx_fifo = rx_fifo;
  session->server_tx_fifo = tx_fifo;
  session->vpp_session_handle = mp->handle;
  session->start = clib_time_now (&utm->clib_time);

  /* Save handle */
  utm->connected_session_index = session_index;
  utm->state = STATE_READY;

  /* Add it to lookup table */
  hash_set (utm->session_index_by_vpp_handles, mp->handle, session_index);

  /* Start RX thread */
  rv = pthread_create (&utm->client_rx_thread_handle,
		       NULL /*attr */ , client_rx_thread_fn, 0);
  if (rv)
    {
      clib_warning ("pthread_create returned %d", rv);
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
    }
}

static void
send_test_chunk (uri_tcp_test_main_t * utm, svm_fifo_t * tx_fifo, int mypid,
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

void
client_send_data (uri_tcp_test_main_t * utm)
{
  u8 *test_data = utm->connect_test_data;
  int mypid = getpid ();
  session_t *session;
  svm_fifo_t *tx_fifo;
  u32 n_iterations, leftover;
  int i;

  session = pool_elt_at_index (utm->sessions, utm->connected_session_index);
  tx_fifo = session->server_tx_fifo;

  ASSERT (vec_len (test_data) > 0);

  vec_validate (utm->rx_buf, vec_len (test_data) - 1);
  n_iterations = utm->bytes_to_send / vec_len (test_data);

  for (i = 0; i < n_iterations; i++)
    {
      send_test_chunk (utm, tx_fifo, mypid, 0);
      if (utm->time_to_stop)
	break;
    }

  leftover = utm->bytes_to_send % vec_len (test_data);
  if (leftover)
    send_test_chunk (utm, tx_fifo, mypid, leftover);

  if (!utm->drop_packets)
    {
      f64 timeout = clib_time_now (&utm->clib_time) + 10;

      /* Wait for the outstanding packets */
      while (utm->client_bytes_received <
	     vec_len (test_data) * n_iterations + leftover)
	{
	  if (clib_time_now (&utm->clib_time) > timeout)
	    {
	      clib_warning ("timed out waiting for the missing packets");
	      break;
	    }
	}
    }
  utm->time_to_stop = 1;
}

void
client_send_connect (uri_tcp_test_main_t * utm)
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

int
client_connect (uri_tcp_test_main_t * utm)
{
  client_send_connect (utm);
  if (wait_for_state_change (utm, STATE_READY))
    {
      clib_warning ("Connect failed");
      return -1;
    }
  return 0;
}

void
client_send_disconnect (uri_tcp_test_main_t * utm)
{
  session_t *connected_session;
  vl_api_disconnect_session_t *dmp;
  connected_session = pool_elt_at_index (utm->sessions,
					 utm->connected_session_index);
  dmp = vl_msg_api_alloc (sizeof (*dmp));
  memset (dmp, 0, sizeof (*dmp));
  dmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION);
  dmp->client_index = utm->my_client_index;
  dmp->handle = connected_session->vpp_session_handle;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & dmp);
}

int
client_disconnect (uri_tcp_test_main_t * utm)
{
  client_send_disconnect (utm);
  clib_warning ("Sent disconnect");
  if (wait_for_state_change (utm, STATE_START))
    {
      clib_warning ("Disconnect failed");
      return -1;
    }
  return 0;
}

static void
client_test (uri_tcp_test_main_t * utm)
{
  int i;

  if (application_attach (utm))
    return;

  if (client_connect (utm))
    {
      application_detach (utm);
      return;
    }

  /* Init test data */
  vec_validate (utm->connect_test_data, 128 * 1024 - 1);
  for (i = 0; i < vec_len (utm->connect_test_data); i++)
    utm->connect_test_data[i] = i & 0xff;

  /* Start send */
  client_send_data (utm);

  /* Disconnect */
  client_disconnect (utm);

  application_detach (utm);
}

static void
vl_api_bind_uri_reply_t_handler (vl_api_bind_uri_reply_t * mp)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;

  if (mp->retval)
    {
      clib_warning ("bind failed: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
      utm->state = STATE_FAILED;
      return;
    }

  utm->state = STATE_READY;
}

static void
vl_api_unbind_uri_reply_t_handler (vl_api_unbind_uri_reply_t * mp)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;

  if (mp->retval != 0)
    clib_warning ("returned %d", ntohl (mp->retval));

  utm->state = STATE_START;
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
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  vl_api_accept_session_reply_t *rmp;
  svm_fifo_t *rx_fifo, *tx_fifo;
  session_t *session;
  static f64 start_time;
  u32 session_index;
  u8 *ip_str;

  if (start_time == 0.0)
    start_time = clib_time_now (&utm->clib_time);

  ip_str = format (0, "%U", format_ip46_address, &mp->ip, mp->is_ip4);
  clib_warning ("Accepted session from: %s:%d", ip_str,
		clib_net_to_host_u16 (mp->port));
  utm->vpp_event_queue =
    uword_to_pointer (mp->vpp_event_queue_address,
		      unix_shared_memory_queue_t *);

  /* Allocate local session and set it up */
  pool_get (utm->sessions, session);
  session_index = session - utm->sessions;

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->server_rx_fifo = rx_fifo;
  session->server_tx_fifo = tx_fifo;

  /* Add it to lookup table */
  hash_set (utm->session_index_by_vpp_handles, mp->handle, session_index);

  utm->state = STATE_READY;

  /* Stats printing */
  if (pool_elts (utm->sessions) && (pool_elts (utm->sessions) % 20000) == 0)
    {
      f64 now = clib_time_now (&utm->clib_time);
      fformat (stdout, "%d active sessions in %.2f seconds, %.2f/sec...\n",
	       pool_elts (utm->sessions), now - start_time,
	       (f64) pool_elts (utm->sessions) / (now - start_time));
    }

  /*
   * Send accept reply to vpp
   */
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ACCEPT_SESSION_REPLY);
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & rmp);

  session->bytes_received = 0;
  session->start = clib_time_now (&utm->clib_time);
}

void
server_handle_fifo_event_rx (uri_tcp_test_main_t * utm,
			     session_fifo_event_t * e)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  int n_read;
  session_fifo_event_t evt;
  unix_shared_memory_queue_t *q;
  session_t *session;
  int rv;
  u32 max_dequeue, offset, max_transfer, rx_buf_len;

  rx_buf_len = vec_len (utm->rx_buf);
  rx_fifo = e->fifo;
  session = &utm->sessions[rx_fifo->client_session_index];
  tx_fifo = session->server_tx_fifo;

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
      n_read = svm_fifo_dequeue_nowait (rx_fifo, max_transfer, utm->rx_buf);
      if (n_read > 0)
	{
	  max_dequeue -= n_read;
	  session->bytes_received += n_read;
	}

      /* Reflect if a non-drop session */
      if (!utm->drop_packets && n_read > 0)
	{
	  offset = 0;
	  do
	    {
	      rv = svm_fifo_enqueue_nowait (tx_fifo, n_read,
					    &utm->rx_buf[offset]);
	      if (rv > 0)
		{
		  n_read -= rv;
		  offset += rv;
		}
	    }
	  while ((rv <= 0 || n_read > 0) && !utm->time_to_stop);

	  /* If event wasn't set, add one */
	  if (svm_fifo_set_event (tx_fifo))
	    {
	      /* Fabricate TX event, send to vpp */
	      evt.fifo = tx_fifo;
	      evt.event_type = FIFO_EVENT_APP_TX;

	      q = utm->vpp_event_queue;
	      unix_shared_memory_queue_add (q, (u8 *) & evt,
					    1 /* do wait for mutex */ );
	    }
	}
    }
  while ((n_read < 0 || max_dequeue > 0) && !utm->time_to_stop);
}

void
server_handle_event_queue (uri_tcp_test_main_t * utm)
{
  session_fifo_event_t _e, *e = &_e;

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
	break;
      if (PREDICT_FALSE (utm->time_to_print_stats == 1))
	{
	  utm->time_to_print_stats = 0;
	  fformat (stdout, "%d connections\n", pool_elts (utm->sessions));
	}
    }
}

void
server_send_listen (uri_tcp_test_main_t * utm)
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

int
server_listen (uri_tcp_test_main_t * utm)
{
  server_send_listen (utm);
  if (wait_for_state_change (utm, STATE_READY))
    {
      clib_warning ("timeout waiting for STATE_READY");
      return -1;
    }
  return 0;
}

void
server_send_unbind (uri_tcp_test_main_t * utm)
{
  vl_api_unbind_uri_t *ump;

  ump = vl_msg_api_alloc (sizeof (*ump));
  memset (ump, 0, sizeof (*ump));

  ump->_vl_msg_id = ntohs (VL_API_UNBIND_URI);
  ump->client_index = utm->my_client_index;
  memcpy (ump->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & ump);
}

int
server_unbind (uri_tcp_test_main_t * utm)
{
  server_send_unbind (utm);
  if (wait_for_state_change (utm, STATE_START))
    {
      clib_warning ("timeout waiting for STATE_START");
      return -1;
    }
  return 0;
}

void
server_test (uri_tcp_test_main_t * utm)
{
  if (application_attach (utm))
    return;

  /* Bind to uri */
  if (server_listen (utm))
    return;

  /* Enter handle event loop */
  server_handle_event_queue (utm);

  /* Cleanup */
  server_send_unbind (utm);

  application_detach (utm);

  fformat (stdout, "Test complete...\n");
}

static void
vl_api_disconnect_session_reply_t_handler (vl_api_disconnect_session_reply_t *
					   mp)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  session_t *session;

  if (mp->retval)
    {
      clib_warning ("vpp complained about disconnect: %d",
		    ntohl (mp->retval));
    }

  utm->state = STATE_START;
  session = pool_elt_at_index (utm->sessions, utm->connected_session_index);
  if (session)
    session_print_stats (utm, session);
}

#define foreach_uri_msg                                 \
_(BIND_URI_REPLY, bind_uri_reply)                       \
_(UNBIND_URI_REPLY, unbind_uri_reply)                   \
_(ACCEPT_SESSION, accept_session)                       \
_(CONNECT_SESSION_REPLY, connect_session_reply)         \
_(DISCONNECT_SESSION, disconnect_session)               \
_(DISCONNECT_SESSION_REPLY, disconnect_session_reply)   \
_(RESET_SESSION, reset_session)                         \
_(APPLICATION_ATTACH_REPLY, application_attach_reply)   \
_(APPLICATION_DETACH_REPLY, application_detach_reply)	\
_(MAP_ANOTHER_SEGMENT, map_another_segment)		\

void
uri_api_hookup (uri_tcp_test_main_t * utm)
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
main (int argc, char **argv)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  unformat_input_t _argv, *a = &_argv;
  u8 *chroot_prefix;
  u8 *heap, *uri = 0;
  u8 *bind_uri = (u8 *) "tcp://0.0.0.0/1234";
  u8 *connect_uri = (u8 *) "tcp://6.0.1.2/1234";
  u64 bytes_to_send = 64 << 10, mbytes;
  u32 tmp;
  mheap_t *h;
  session_t *session;
  int i;
  int i_am_master = 1, drop_packets = 0, test_return_packets = 0;

  clib_mem_init (0, 256 << 20);

  heap = clib_mem_get_per_cpu_heap ();
  h = mheap_header (heap);

  /* make the main heap thread-safe */
  h->flags |= MHEAP_FLAG_THREAD_SAFE;

  vec_validate (utm->rx_buf, 128 << 10);

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
      else if (unformat (a, "uri %s", &uri))
	;
      else if (unformat (a, "segment-size %dM", &tmp))
	utm->configured_segment_size = tmp << 20;
      else if (unformat (a, "segment-size %dG", &tmp))
	utm->configured_segment_size = tmp << 30;
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
      else
	{
	  fformat (stderr, "%s: usage [master|slave]\n");
	  exit (1);
	}
    }

  if (uri)
    {
      utm->uri = format (0, "%s%c", uri, 0);
      utm->connect_uri = format (0, "%s%c", uri, 0);
    }
  else
    {
      utm->uri = format (0, "%s%c", bind_uri, 0);
      utm->connect_uri = format (0, "%s%c", connect_uri, 0);
    }

  utm->i_am_master = i_am_master;
  utm->segment_main = &svm_fifo_segment_main;
  utm->drop_packets = drop_packets;
  utm->test_return_packets = test_return_packets;
  utm->bytes_to_send = bytes_to_send;
  utm->time_to_stop = 0;

  setup_signal_handlers ();
  uri_api_hookup (utm);

  if (connect_to_vpp (i_am_master ? "uri_tcp_server" : "uri_tcp_client") < 0)
    {
      svm_region_exit ();
      fformat (stderr, "Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  if (i_am_master == 0)
    {
      client_test (utm);
      vl_client_disconnect_from_vlib ();
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

  server_test (utm);

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
