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
  svm_queue_t *our_event_queue;

  /* $$$ single thread only for the moment */
  svm_queue_t *vpp_event_queue;

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

  uword *segments_table;
  u8 do_echo;
} udp_echo_main_t;

#if CLIB_DEBUG > 0
#define NITER 10000
#else
#define NITER 4000000
#endif

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
  session_endpoint_extended_t *sep = va_arg (*args,
					     session_endpoint_extended_t *);
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

void
application_send_attach (udp_echo_main_t * utm)
{
  vl_api_application_attach_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_APPLICATION_ATTACH);
  bmp->client_index = utm->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_ADD_SEGMENT;
  bmp->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  bmp->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
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
  udp_echo_main_t *utm = &udp_echo_main;
  svm_fifo_segment_create_args_t _a = { 0 }, *a = &_a;
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
    uword_to_pointer (mp->app_event_queue_address, svm_queue_t *);
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
  int rv;
  u32 buffer_offset;

  while (utm->cut_through_session_index == ~0)
    ;

  s = pool_elt_at_index (utm->sessions, utm->cut_through_session_index);

  rx_fifo = s->rx_fifo;
  tx_fifo = s->tx_fifo;

  vec_validate (my_copy_buffer, 64 * 1024 - 1);

  while (true)
    {
      /* We read from the tx fifo and write to the rx fifo */
      do
	{
	  actual_transfer = svm_fifo_dequeue_nowait (rx_fifo,
						     vec_len (my_copy_buffer),
						     my_copy_buffer);
	}
      while (actual_transfer <= 0);

      server_bytes_received += actual_transfer;

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
      if (PREDICT_FALSE (utm->time_to_stop))
	break;
    }

  pthread_exit (0);
}

static void
udp_client_connect (udp_echo_main_t * utm)
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
client_send_cut_through (udp_echo_main_t * utm, app_session_t * session)
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

  rx_fifo = session->rx_fifo;
  tx_fifo = session->tx_fifo;

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
send_test_chunk (udp_echo_main_t * utm, app_session_t * s, u32 bytes)
{
  u8 *test_data = utm->connect_test_data;
  int test_buf_offset = 0;
  u64 bytes_sent = 0;
  u32 bytes_to_snd;
  int rv;

  bytes_to_snd = (bytes == 0) ? vec_len (test_data) : bytes;
  if (bytes_to_snd > vec_len (test_data))
    bytes_to_snd = vec_len (test_data);

  while (bytes_to_snd > 0 && !utm->time_to_stop)
    {
      rv = app_send (s, test_data + test_buf_offset, bytes_to_snd, 0);
      if (rv > 0)
	{
	  bytes_to_snd -= rv;
	  test_buf_offset += rv;
	  bytes_sent += rv;
	}
    }
}

static void
recv_test_chunk (udp_echo_main_t * utm, app_session_t * s)
{
  app_recv (s, utm->rx_buf, vec_len (utm->rx_buf));
}

void
client_send_data (udp_echo_main_t * utm)
{
  u8 *test_data;
  app_session_t *session;
  u32 n_iterations;
  int i;

  vec_validate (utm->connect_test_data, 64 * 1024 - 1);
  for (i = 0; i < vec_len (utm->connect_test_data); i++)
    utm->connect_test_data[i] = i & 0xff;

  test_data = utm->connect_test_data;
  session = pool_elt_at_index (utm->sessions, utm->connected_session);
  ASSERT (vec_len (test_data) > 0);

  vec_validate (utm->rx_buf, vec_len (test_data) - 1);
  n_iterations = NITER;

  for (i = 0; i < n_iterations; i++)
    {
      send_test_chunk (utm, session, 0);
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
client_test (udp_echo_main_t * utm)
{
  app_session_t *session;

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
  memset (session, 0, sizeof (*session));
  session_index = session - utm->sessions;

  rx_fifo->client_session_index = session_index;
  tx_fifo->client_session_index = session_index;
  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;
  clib_memcpy (&session->transport.lcl_ip, mp->lcl_ip,
	       sizeof (ip46_address_t));
  session->transport.is_ip4 = mp->lcl_is_ip4;
  session->transport.lcl_port = mp->lcl_port;
  session->vpp_evt_q = uword_to_pointer (mp->vpp_evt_q, svm_queue_t *);

  utm->state = utm->is_connected ? STATE_BOUND : STATE_READY;
}

static void
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t * mp)
{
  udp_echo_main_t *utm = &udp_echo_main;
  svm_fifo_segment_create_args_t _a, *a = &_a;
  svm_fifo_segment_private_t *seg;
  u8 *seg_name;
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
  seg = svm_fifo_segment_get_segment (a->new_segment_indices[0]);
  clib_warning ("Mapped new segment '%s' size %d", seg->ssvm.name,
		seg->ssvm.ssvm_size);
  seg_name = format (0, "%s", (char *) mp->segment_name);
  hash_set_mem (utm->segments_table, seg_name, a->new_segment_indices[0]);
  vec_free (seg_name);
}

static void
vl_api_unmap_segment_t_handler (vl_api_unmap_segment_t * mp)
{
  udp_echo_main_t *utm = &udp_echo_main;
  svm_fifo_segment_private_t *seg;
  u64 *seg_indexp;
  u8 *seg_name;


  seg_name = format (0, "%s", mp->segment_name);
  seg_indexp = hash_get_mem (utm->segments_table, seg_name);
  if (!seg_indexp)
    {
      clib_warning ("segment not mapped: %s", seg_name);
      return;
    }
  hash_unset_mem (utm->segments_table, seg_name);
  seg = svm_fifo_segment_get_segment ((u32) seg_indexp[0]);
  svm_fifo_segment_delete (seg);
  clib_warning ("Unmapped segment '%s'", seg_name);
  vec_free (seg_name);
}

/**
 * Acting as server for redirected connect requests
 */
static void
vl_api_connect_uri_t_handler (vl_api_connect_uri_t * mp)
{
  u32 segment_index;
  udp_echo_main_t *utm = &udp_echo_main;
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
  svm_fifo_segment_create_args_t _a, *a = &_a;
  svm_fifo_segment_private_t *seg;
  svm_queue_t *client_q;
  vl_api_connect_session_reply_t *rmp;
  app_session_t *session = 0;
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

  session->rx_fifo = svm_fifo_segment_alloc_fifo
    (utm->seg, 128 * 1024, FIFO_SEGMENT_RX_FREELIST);
  ASSERT (session->rx_fifo);

  session->tx_fifo = svm_fifo_segment_alloc_fifo
    (utm->seg, 128 * 1024, FIFO_SEGMENT_TX_FREELIST);
  ASSERT (session->tx_fifo);

  session->rx_fifo->master_session_index = session - utm->sessions;
  session->tx_fifo->master_session_index = session - utm->sessions;
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
      rmp->server_rx_fifo = pointer_to_uword (session->rx_fifo);
      rmp->server_tx_fifo = pointer_to_uword (session->tx_fifo);
    }

  memcpy (rmp->segment_name, a->segment_name, vec_len (a->segment_name));

  vec_free (a->segment_name);

  client_q = uword_to_pointer (mp->client_queue_address, svm_queue_t *);
  vl_msg_api_send_shmem (client_q, (u8 *) & rmp);
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
vl_api_accept_session_t_handler (vl_api_accept_session_t * mp)
{
  udp_echo_main_t *utm = &udp_echo_main;
  vl_api_accept_session_reply_t *rmp;
  svm_fifo_t *rx_fifo, *tx_fifo;
  app_session_t *session;
  static f64 start_time;
  u32 session_index;
  int rv = 0;

  if (start_time == 0.0)
    start_time = clib_time_now (&utm->clib_time);

  utm->vpp_event_queue = uword_to_pointer (mp->vpp_event_queue_address,
					   svm_queue_t *);
  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);

  pool_get (utm->sessions, session);
  memset (session, 0, sizeof (*session));
  session_index = session - utm->sessions;

  /* Cut-through case */
  if (mp->server_event_queue_address)
    {
      clib_warning ("cut-through session");
      utm->our_event_queue = uword_to_pointer (mp->server_event_queue_address,
					       svm_queue_t *);
      rx_fifo->master_session_index = session_index;
      tx_fifo->master_session_index = session_index;
      utm->cut_through_session_index = session_index;
      session->rx_fifo = rx_fifo;
      session->tx_fifo = tx_fifo;

      rv = pthread_create (&utm->cut_through_thread_handle,
			   NULL /*attr */ , cut_through_thread_fn, 0);
      if (rv)
	{
	  clib_warning ("pthread_create returned %d", rv);
	  rv = VNET_API_ERROR_SYSCALL_ERROR_1;
	}
      utm->do_echo = 1;
    }
  else
    {
      rx_fifo->client_session_index = session_index;
      tx_fifo->client_session_index = session_index;
      session->rx_fifo = rx_fifo;
      session->tx_fifo = tx_fifo;
      clib_memcpy (&session->transport.rmt_ip, mp->ip,
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

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ACCEPT_SESSION_REPLY);
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  rmp->retval = rv;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & rmp);

  CLIB_MEMORY_BARRIER ();
  utm->state = STATE_READY;
}

static void
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  udp_echo_main_t *utm = &udp_echo_main;
  app_session_t *session;
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
  rmp->context = mp->context;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & rmp);
}

static void
vl_api_connect_session_reply_t_handler (vl_api_connect_session_reply_t * mp)
{
  udp_echo_main_t *utm = &udp_echo_main;
  unformat_input_t _input, *input = &_input;
  session_endpoint_extended_t _sep, *sep = &_sep;
  app_session_t *session;

  ASSERT (utm->i_am_server == 0);

  if (mp->retval)
    {
      clib_warning ("failed connect");
      return;
    }

  ASSERT (mp->server_rx_fifo && mp->server_tx_fifo);

  pool_get (utm->sessions, session);
  session->rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  session->tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					 svm_queue_t *);
  /* Cut-through case */
  if (mp->client_event_queue_address)
    {
      clib_warning ("cut-through session");
      utm->cut_through_session_index = session - utm->sessions;
      utm->vpp_event_queue = uword_to_pointer (mp->vpp_event_queue_address,
					       svm_queue_t *);
      utm->our_event_queue = uword_to_pointer (mp->client_event_queue_address,
					       svm_queue_t *);
      utm->do_echo = 1;
    }
  else
    {
      utm->connected_session = session - utm->sessions;
      utm->vpp_event_queue = uword_to_pointer (mp->vpp_event_queue_address,
					       svm_queue_t *);

      clib_memcpy (&session->transport.lcl_ip, mp->lcl_ip,
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
      clib_memcpy (&session->transport.rmt_ip, &sep->ip,
		   sizeof (ip46_address_t));
      session->transport.rmt_port = sep->port;
      session->is_dgram = !utm->is_connected;
    }
  utm->state = STATE_READY;
}

#define foreach_tcp_echo_msg                         	\
_(BIND_URI_REPLY, bind_uri_reply)               	\
_(CONNECT_URI, connect_uri)                     	\
_(CONNECT_SESSION_REPLY, connect_session_reply)       	\
_(UNBIND_URI_REPLY, unbind_uri_reply)           	\
_(ACCEPT_SESSION, accept_session)			\
_(DISCONNECT_SESSION, disconnect_session)		\
_(MAP_ANOTHER_SEGMENT, map_another_segment)		\
_(UNMAP_SEGMENT, unmap_segment)				\
_(APPLICATION_ATTACH_REPLY, application_attach_reply)	\
_(APPLICATION_DETACH_REPLY, application_detach_reply)	\

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
server_handle_fifo_event_rx (udp_echo_main_t * utm, session_fifo_event_t * e)
{
  app_session_t *s;
  int rv;

  s = pool_elt_at_index (utm->sessions, e->fifo->client_session_index);
  app_recv (s, utm->rx_buf, vec_len (utm->rx_buf));

  if (utm->do_echo)
    {
      do
	{
	  rv = app_send_stream (s, utm->rx_buf, vec_len (utm->rx_buf), 0);
	}
      while (rv == SVM_FIFO_FULL);
    }
}

void
server_handle_event_queue (udp_echo_main_t * utm)
{
  session_fifo_event_t _e, *e = &_e;

  while (utm->state != STATE_READY)
    sleep (5);

  while (1)
    {
      svm_queue_sub (utm->our_event_queue, (u8 *) e, SVM_Q_WAIT, 0);
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
server_unbind (udp_echo_main_t * utm)
{
  vl_api_unbind_uri_t *ump;

  ump = vl_msg_api_alloc (sizeof (*ump));
  memset (ump, 0, sizeof (*ump));

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
  memset (bmp, 0, sizeof (*bmp));

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
  u8 *uri = (u8 *) "udp://0.0.0.0/1234";
  unformat_input_t _argv, *a = &_argv;
  int i_am_server = 1;
  app_session_t *session;
  u8 *chroot_prefix;
  char *app_name;
  mheap_t *h;
  u8 *heap;
  u32 tmp;
  int i;

  clib_mem_init (0, 256 << 20);

  heap = clib_mem_get_per_cpu_heap ();
  h = mheap_header (heap);

  /* make the main heap thread-safe */
  h->flags |= MHEAP_FLAG_THREAD_SAFE;

  vec_validate (utm->rx_buf, 8192);

  utm->session_index_by_vpp_handles = hash_create (0, sizeof (uword));
  utm->my_pid = getpid ();
  utm->configured_segment_size = 1 << 20;
  utm->segments_table = hash_create_vec (0, sizeof (u8), sizeof (u64));

  clib_time_init (&utm->clib_time);
  init_error_string_table (utm);
  svm_fifo_segment_main_init (0x200000000ULL, 20);
  unformat_init_command_line (a, argv);

  utm->fifo_size = 128 << 10;

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
      else
	{
	  fformat (stderr, "%s: usage [server|client]\n");
	  exit (1);
	}
    }

  utm->cut_through_session_index = ~0;
  utm->i_am_server = i_am_server;
  utm->segment_main = &svm_fifo_segment_main;

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
