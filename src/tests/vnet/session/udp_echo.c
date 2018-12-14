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
  STATE_ATTACHED,
  STATE_BOUND,
  STATE_READY,
  STATE_FAILED,
  STATE_DISCONNECTING,
  STATE_DETACHED
} connection_state_t;

typedef struct
{
  /* vpe input queue */
  svm_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  /* The URI we're playing with */
  u8 *listen_uri;

  /* URI for connect */
  u8 *connect_uri;

  /* Session pool */
  app_session_t *sessions;

  /* Hash table for disconnect processing */
  uword *session_index_by_vpp_handles;

  /* fifo segment */
  svm_fifo_segment_private_t *seg;

  /* intermediate rx buffer */
  u8 *rx_buf;

  u32 fifo_size;
  int i_am_server;
  u8 is_connected;

  /* Our event queue */
  svm_msg_q_t *our_event_queue;
  svm_msg_q_t *ct_event_queue;

  /* $$$ single thread only for the moment */
  svm_msg_q_t *vpp_event_queue;

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

  svm_fifo_segment_main_t segment_main;

  u8 *connect_test_data;

  uword *segments_table;
  u8 do_echo;
  u8 have_return;
  u64 total_to_send;
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

uword
unformat_ip4_address (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  unsigned a[4];

  if (!unformat (input, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]))
    return 0;

  if (a[0] >= 256 || a[1] >= 256 || a[2] >= 256 || a[3] >= 256)
    return 0;

  result[0] = a[0];
  result[1] = a[1];
  result[2] = a[2];
  result[3] = a[3];

  return 1;
}

uword
unformat_ip6_address (unformat_input_t * input, va_list * args)
{
  ip6_address_t *result = va_arg (*args, ip6_address_t *);
  u16 hex_quads[8];
  uword hex_quad, n_hex_quads, hex_digit, n_hex_digits;
  uword c, n_colon, double_colon_index;

  n_hex_quads = hex_quad = n_hex_digits = n_colon = 0;
  double_colon_index = ARRAY_LEN (hex_quads);
  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      hex_digit = 16;
      if (c >= '0' && c <= '9')
	hex_digit = c - '0';
      else if (c >= 'a' && c <= 'f')
	hex_digit = c + 10 - 'a';
      else if (c >= 'A' && c <= 'F')
	hex_digit = c + 10 - 'A';
      else if (c == ':' && n_colon < 2)
	n_colon++;
      else
	{
	  unformat_put_input (input);
	  break;
	}

      /* Too many hex quads. */
      if (n_hex_quads >= ARRAY_LEN (hex_quads))
	return 0;

      if (hex_digit < 16)
	{
	  hex_quad = (hex_quad << 4) | hex_digit;

	  /* Hex quad must fit in 16 bits. */
	  if (n_hex_digits >= 4)
	    return 0;

	  n_colon = 0;
	  n_hex_digits++;
	}

      /* Save position of :: */
      if (n_colon == 2)
	{
	  /* More than one :: ? */
	  if (double_colon_index < ARRAY_LEN (hex_quads))
	    return 0;
	  double_colon_index = n_hex_quads;
	}

      if (n_colon > 0 && n_hex_digits > 0)
	{
	  hex_quads[n_hex_quads++] = hex_quad;
	  hex_quad = 0;
	  n_hex_digits = 0;
	}
    }

  if (n_hex_digits > 0)
    hex_quads[n_hex_quads++] = hex_quad;

  {
    word i;

    /* Expand :: to appropriate number of zero hex quads. */
    if (double_colon_index < ARRAY_LEN (hex_quads))
      {
	word n_zero = ARRAY_LEN (hex_quads) - n_hex_quads;

	for (i = n_hex_quads - 1; i >= (signed) double_colon_index; i--)
	  hex_quads[n_zero + i] = hex_quads[i];

	for (i = 0; i < n_zero; i++)
	  hex_quads[double_colon_index + i] = 0;

	n_hex_quads = ARRAY_LEN (hex_quads);
      }

    /* Too few hex quads given. */
    if (n_hex_quads < ARRAY_LEN (hex_quads))
      return 0;

    for (i = 0; i < ARRAY_LEN (hex_quads); i++)
      result->as_u16[i] = clib_host_to_net_u16 (hex_quads[i]);

    return 1;
  }
}

uword
unformat_uri (unformat_input_t * input, va_list * args)
{
  session_endpoint_cfg_t *sep = va_arg (*args, session_endpoint_cfg_t *);
  u32 port;
  char *tmp;

  if (unformat (input, "%s://%U/%d", &tmp, unformat_ip4_address, &sep->ip.ip4,
		&port))
    {
      sep->port = clib_host_to_net_u16 (port);
      sep->is_ip4 = 1;
      return 1;
    }
  else if (unformat (input, "%s://%U/%d", &tmp, unformat_ip6_address,
		     &sep->ip.ip6, &port))
    {
      sep->port = clib_host_to_net_u16 (port);
      sep->is_ip4 = 0;
      return 1;
    }
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
  bmp->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_ADD_SEGMENT;
  bmp->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  bmp->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  bmp->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_MQ_FOR_CTRL_MSGS;
  bmp->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 2;
  bmp->options[APP_OPTIONS_RX_FIFO_SIZE] = utm->fifo_size;
  bmp->options[APP_OPTIONS_TX_FIFO_SIZE] = utm->fifo_size;
  bmp->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  bmp->options[APP_OPTIONS_SEGMENT_SIZE] = 256 << 20;
  bmp->options[APP_OPTIONS_EVT_QUEUE_SIZE] = 16768;
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

static void
vl_api_application_attach_reply_t_handler (vl_api_application_attach_reply_t *
					   mp)
{
  svm_fifo_segment_create_args_t _a = { 0 }, *a = &_a;
  udp_echo_main_t *utm = &udp_echo_main;
  svm_fifo_segment_main_t *sm = &utm->segment_main;
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
  rv = svm_fifo_segment_attach (sm, a);
  if (rv)
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed",
		    mp->segment_name);
      return;
    }

  utm->our_event_queue = uword_to_pointer (mp->app_event_queue_address,
					   svm_msg_q_t *);
  utm->state = STATE_ATTACHED;
}

static void
vl_api_application_detach_reply_t_handler (vl_api_application_detach_reply_t *
					   mp)
{
  if (mp->retval)
    clib_warning ("detach returned with err: %d", mp->retval);
  udp_echo_main.state = STATE_DETACHED;
}

u8 *
format_api_error (u8 * s, va_list * args)
{
  udp_echo_main_t *utm = va_arg (*args, udp_echo_main_t *);
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

u64 server_bytes_received, server_bytes_sent;

static void *
cut_through_thread_fn (void *arg)
{
  app_session_t *s;
  svm_fifo_t *rx_fifo;
  svm_fifo_t *tx_fifo;
  u8 *my_copy_buffer = 0;
  udp_echo_main_t *utm = &udp_echo_main;
  i32 actual_transfer;
  int rv, do_dequeue = 0;
  u32 buffer_offset;

  while (utm->cut_through_session_index == ~0)
    ;

  s = pool_elt_at_index (utm->sessions, utm->cut_through_session_index);

  rx_fifo = s->rx_fifo;
  tx_fifo = s->tx_fifo;

  vec_validate (my_copy_buffer, 64 * 1024 - 1);

  while (1)
    {
      do
	{
	  /* We read from the tx fifo and write to the rx fifo */
	  if (utm->have_return || do_dequeue)
	    actual_transfer = svm_fifo_dequeue_nowait (rx_fifo,
						       vec_len
						       (my_copy_buffer),
						       my_copy_buffer);
	  else
	    {
	      /* We don't do anything with the data, drop it */
	      actual_transfer = svm_fifo_max_dequeue (rx_fifo);
	      svm_fifo_dequeue_drop (rx_fifo, actual_transfer);
	    }
	}
      while (actual_transfer <= 0);

      server_bytes_received += actual_transfer;

      if (utm->have_return)
	{
	  buffer_offset = 0;
	  while (actual_transfer > 0)
	    {
	      rv = svm_fifo_enqueue_nowait (tx_fifo, actual_transfer,
					    my_copy_buffer + buffer_offset);
	      if (rv > 0)
		{
		  actual_transfer -= rv;
		  buffer_offset += rv;
		  server_bytes_sent += rv;
		}

	    }
	}
      if (PREDICT_FALSE (utm->time_to_stop))
	break;
    }

  pthread_exit (0);
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

  /* Cut-through case */
  if (mp->server_event_queue_address)
    {
      clib_warning ("cut-through session");
      session->vpp_evt_q = uword_to_pointer (mp->client_event_queue_address,
					     svm_msg_q_t *);
      sleep (1);
      rx_fifo->master_session_index = session_index;
      tx_fifo->master_session_index = session_index;
      utm->cut_through_session_index = session_index;
      session->rx_fifo = rx_fifo;
      session->tx_fifo = tx_fifo;
      session->is_dgram = 0;

      rv = pthread_create (&utm->cut_through_thread_handle,
			   NULL /*attr */ , cut_through_thread_fn, 0);
      if (rv)
	{
	  clib_warning ("pthread_create returned %d", rv);
	  rv = VNET_API_ERROR_SYSCALL_ERROR_1;
	}
    }
  else
    {
      rx_fifo->client_session_index = session_index;
      tx_fifo->client_session_index = session_index;
      session->rx_fifo = rx_fifo;
      session->tx_fifo = tx_fifo;
      clib_memcpy_fast (&session->transport.rmt_ip, mp->ip,
			sizeof (ip46_address_t));
      session->transport.is_ip4 = mp->is_ip4;
      session->transport.rmt_port = mp->port;
    }

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
  unformat_input_t _input, *input = &_input;
  session_endpoint_cfg_t _sep, *sep = &_sep;
  app_session_t *session;

  ASSERT (utm->i_am_server == 0);

  if (mp->retval)
    {
      clib_warning ("failed connect");
      return;
    }

  ASSERT (mp->server_rx_fifo && mp->server_tx_fifo);

  pool_get (utm->sessions, session);
  session->session_index = session - utm->sessions;
  session->rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  session->tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);

  /* Cut-through case */
  if (mp->client_event_queue_address)
    {
      clib_warning ("cut-through session");
      session->vpp_evt_q = uword_to_pointer (mp->server_event_queue_address,
					     svm_msg_q_t *);
      utm->ct_event_queue = uword_to_pointer (mp->client_event_queue_address,
					      svm_msg_q_t *);
      utm->cut_through_session_index = session->session_index;
      session->is_dgram = 0;
      sleep (1);
      session->rx_fifo->client_session_index = session->session_index;
      session->tx_fifo->client_session_index = session->session_index;
    }
  else
    {
      utm->connected_session = session->session_index;
      utm->vpp_event_queue = uword_to_pointer (mp->vpp_event_queue_address,
					       svm_msg_q_t *);

      session->rx_fifo->client_session_index = session->session_index;
      session->tx_fifo->client_session_index = session->session_index;
      clib_memcpy_fast (&session->transport.lcl_ip, mp->lcl_ip,
			sizeof (ip46_address_t));
      session->transport.is_ip4 = mp->is_ip4;
      session->transport.lcl_port = mp->lcl_port;

      unformat_init_vector (input, utm->connect_uri);
      if (!unformat (input, "%U", unformat_uri, sep))
	{
	  clib_warning ("can't figure out remote ip and port");
	  utm->state = STATE_FAILED;
	  unformat_free (input);
	  return;
	}
      unformat_free (input);
      clib_memcpy_fast (&session->transport.rmt_ip, &sep->ip,
			sizeof (ip46_address_t));
      session->transport.rmt_port = sep->port;
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

  utm->state = utm->is_connected ? STATE_BOUND : STATE_READY;
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
  memcpy (cmp->uri, utm->connect_uri, vec_len (utm->connect_uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & cmp);
}

static void
send_test_chunk (udp_echo_main_t * utm, app_session_t * s, u32 bytes)
{
  u64 test_buf_len, bytes_this_chunk, test_buf_offset;

  u8 *test_data = utm->connect_test_data;
  u32 bytes_to_snd, enq_space, min_chunk;
  session_evt_type_t et = FIFO_EVENT_APP_TX;
  int written;

  test_buf_len = vec_len (test_data);
  test_buf_offset = utm->bytes_sent % test_buf_len;
  bytes_this_chunk = clib_min (test_buf_len - test_buf_offset,
			       utm->bytes_to_send);
  enq_space = svm_fifo_max_enqueue (s->tx_fifo);
  bytes_this_chunk = clib_min (bytes_this_chunk, enq_space);
  et += (s->session_index == utm->cut_through_session_index);

  if (s->is_dgram)
    written = app_send_dgram_raw (s->tx_fifo, &s->transport, s->vpp_evt_q,
				  test_data + test_buf_offset,
				  bytes_this_chunk, et, SVM_Q_WAIT);
  else
    written = app_send_stream_raw (s->tx_fifo, s->vpp_evt_q,
				   test_data + test_buf_offset,
				   bytes_this_chunk, et, SVM_Q_WAIT);

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
  int i;

  vec_validate_aligned (utm->connect_test_data, 1024 * 1024 - 1,
			CLIB_CACHE_LINE_BYTES);
  for (i = 0; i < vec_len (utm->connect_test_data); i++)
    utm->connect_test_data[i] = i & 0xff;

  test_data = utm->connect_test_data;
  session = pool_elt_at_index (utm->sessions, session_index);
  ASSERT (vec_len (test_data) > 0);

  utm->total_to_send = utm->bytes_to_send;
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
		utm->total_to_send, utm->total_to_send / (1ULL << 20),
		utm->total_to_send / (1ULL << 30), delta);
  clib_warning ("%.2f bytes/second %s", ((f64) utm->total_to_send) / (delta),
		transfer_type);
  clib_warning ("%.4f gbit/second %s",
		(((f64) utm->total_to_send * 8.0) / delta / 1e9),
		transfer_type);
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
  app_session_t *session;
  svm_msg_q_msg_t msg;
  session_event_t *e;

  if (application_attach (utm))
    return;

  udp_client_send_connect (utm);

  start_time = clib_time_now (&utm->clib_time);
  while (pool_elts (utm->sessions) != 1 && utm->state != STATE_FAILED)
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
vl_api_bind_uri_reply_t_handler (vl_api_bind_uri_reply_t * mp)
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

  utm->state = utm->is_connected ? STATE_BOUND : STATE_READY;
}

static void
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t * mp)
{
  svm_fifo_segment_create_args_t _a, *a = &_a;
  udp_echo_main_t *utm = &udp_echo_main;
  svm_fifo_segment_main_t *sm = &utm->segment_main;
  svm_fifo_segment_private_t *seg;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->segment_name = (char *) mp->segment_name;
  a->segment_size = mp->segment_size;
  /* Attach to the segment vpp created */
  rv = svm_fifo_segment_attach (sm, a);
  if (rv)
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed",
		    mp->segment_name);
      return;
    }
  seg = svm_fifo_segment_get_segment (sm, a->new_segment_indices[0]);
  clib_warning ("Mapped new segment '%s' size %d", seg->ssvm.name,
		seg->ssvm.ssvm_size);
  hash_set (utm->segments_table, clib_net_to_host_u64 (mp->segment_handle),
	    a->new_segment_indices[0]);
}

static void
vl_api_unmap_segment_t_handler (vl_api_unmap_segment_t * mp)
{
  udp_echo_main_t *utm = &udp_echo_main;
  svm_fifo_segment_main_t *sm = &utm->segment_main;
  svm_fifo_segment_private_t *seg;
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
  seg = svm_fifo_segment_get_segment (sm, (u32) seg_indexp[0]);
  svm_fifo_segment_delete (sm, seg);
  clib_warning ("Unmapped segment '%s'", segment_handle);
}

static void
vl_api_unbind_uri_reply_t_handler (vl_api_unbind_uri_reply_t * mp)
{
  udp_echo_main_t *utm = &udp_echo_main;

  if (mp->retval != 0)
    clib_warning ("returned %d", ntohl (mp->retval));

  utm->state = STATE_START;
}

static void
  vl_api_app_cut_through_registration_add_t_handler
  (vl_api_app_cut_through_registration_add_t * mp)
{

}

#define foreach_tcp_echo_msg                         			\
_(BIND_URI_REPLY, bind_uri_reply)               			\
_(UNBIND_URI_REPLY, unbind_uri_reply)           			\
_(MAP_ANOTHER_SEGMENT, map_another_segment)				\
_(UNMAP_SEGMENT, unmap_segment)						\
_(APPLICATION_ATTACH_REPLY, application_attach_reply)			\
_(APPLICATION_DETACH_REPLY, application_detach_reply)			\
_(APP_CUT_THROUGH_REGISTRATION_ADD, app_cut_through_registration_add)	\

void
tcp_echo_api_hookup (udp_echo_main_t * utm)
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
init_error_string_table (udp_echo_main_t * utm)
{
  utm->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n,v,s) hash_set (utm->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (utm->error_string_by_error_number, 99, "Misc");
}

void
server_handle_fifo_event_rx (udp_echo_main_t * utm, u32 session_index)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  int n_read;
  app_session_t *session;
  int rv;
  u32 max_dequeue, offset, max_transfer, rx_buf_len;
  session_evt_type_t et = FIFO_EVENT_APP_TX;

  session = pool_elt_at_index (utm->sessions, session_index);
  rx_buf_len = vec_len (utm->rx_buf);
  rx_fifo = session->rx_fifo;
  tx_fifo = session->tx_fifo;

  et += (session->session_index == utm->cut_through_session_index);

  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
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
	      if (session->is_dgram)
		rv = app_send_dgram_raw (tx_fifo, &session->transport,
					 session->vpp_evt_q,
					 &utm->rx_buf[offset], n_read, et,
					 SVM_Q_WAIT);
	      else
		rv = app_send_stream_raw (tx_fifo, session->vpp_evt_q,
					  &utm->rx_buf[offset], n_read, et,
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
	    app_send_io_evt_to_vpp (session->vpp_evt_q, tx_fifo,
				    et, SVM_Q_WAIT);
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
  int i;

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
	case FIFO_EVENT_APP_RX:
	  server_handle_fifo_event_rx (utm, e->fifo->client_session_index);
	  break;
	case SESSION_IO_EVT_CT_TX:
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
  memcpy (ump->uri, utm->listen_uri, vec_len (utm->listen_uri));
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
  memcpy (bmp->uri, utm->listen_uri, vec_len (utm->listen_uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & bmp);
}

void
udp_server_test (udp_echo_main_t * utm)
{
  u8 wait_for_state = utm->is_connected ? STATE_BOUND : STATE_READY;
  application_send_attach (utm);

  /* Bind to uri */
  server_bind (utm);

  if (wait_for_state_change (utm, wait_for_state))
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

int
main (int argc, char **argv)
{
  udp_echo_main_t *utm = &udp_echo_main;
  svm_fifo_segment_main_t *sm = &utm->segment_main;
  u8 *uri = (u8 *) "udp://6.0.1.1/1234";
  unformat_input_t _argv, *a = &_argv;
  int i_am_server = 1;
  app_session_t *session;
  u8 *chroot_prefix;
  char *app_name;
  u32 tmp;
  int i;

  clib_mem_init_thread_safe (0, 256 << 20);

  svm_fifo_segment_main_init (sm, HIGH_SEGMENT_BASEVA, 20);

  vec_validate (utm->rx_buf, 128 << 10);
  utm->session_index_by_vpp_handles = hash_create (0, sizeof (uword));
  utm->my_pid = getpid ();
  utm->configured_segment_size = 1 << 20;
  utm->have_return = 1;
  utm->bytes_to_send = 1024;
  utm->fifo_size = 128 << 10;
  utm->cut_through_session_index = ~0;
  clib_time_init (&utm->clib_time);

  init_error_string_table (utm);
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
      else if (unformat (a, "server"))
	i_am_server = 1;
      else if (unformat (a, "client"))
	i_am_server = 0;
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

  utm->i_am_server = i_am_server;

  setup_signal_handlers ();
  tcp_echo_api_hookup (utm);

  if (i_am_server)
    {
      utm->listen_uri = format (0, "%s%c", uri, 0);
      utm->is_connected = (utm->listen_uri[4] == 'c');
      app_name = "udp_echo_server";
    }
  else
    {
      app_name = "udp_echo_client";
      utm->connect_uri = format (0, "%s%c", uri, 0);
      utm->is_connected = (utm->connect_uri[4] == 'c');
    }
  if (connect_to_vpp (app_name) < 0)
    {
      svm_region_exit ();
      fformat (stderr, "Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  if (i_am_server == 0)
    {
      client_test (utm);
      goto done;
    }

  /* $$$$ hack preallocation */
  for (i = 0; i < 200000; i++)
    {
      pool_get (utm->sessions, session);
      clib_memset (session, 0, sizeof (*session));
    }
  for (i = 0; i < 200000; i++)
    pool_put_index (utm->sessions, i);

  udp_server_test (utm);

done:
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
