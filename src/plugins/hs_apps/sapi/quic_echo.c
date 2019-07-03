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

#include <vnet/session/application_interface.h>
#include <vlibmemory/api.h>

#include <vpp/api/vpe_msg_enum.h>
#include <svm/fifo_segment.h>

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

#define SESSION_INVALID_INDEX ((u32)~0)
#define SESSION_INVALID_HANDLE ((u64)~0)

#define QUIC_ECHO_DBG 0
#define DBG(_fmt, _args...)			\
    if (QUIC_ECHO_DBG) 				\
      clib_warning (_fmt, ##_args)

#define CHECK(expected, result, _fmt, _args...)		\
    if (expected != result)				\
      ECHO_FAIL ("expected %d, got %d : " _fmt, expected, result, ##_args);

#define ECHO_FAIL(_fmt,_args...)	\
  {					\
    echo_main_t *em = &echo_main;	\
    em->has_failed = 1;		\
    em->time_to_stop = 1;		\
    clib_warning ("ECHO-ERROR: "_fmt, ##_args); 	\
  }

typedef enum
{
  SESSION_FLAG_NOFLAG = 0,
  SESSION_FLAG_SHOULD_CLOSE = 1,
  SESSION_FLAG_SHOULD_FREE = 2,
} echo_session_flag_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define _(type, name) type name;
  foreach_app_session_field
#undef _
  u64 vpp_session_handle;
  u64 bytes_sent;
  u64 bytes_to_send;
  volatile u64 bytes_received;
  volatile u64 bytes_to_receive;
  f64 start;
  u32 listener_index;		/* listener index in echo session pool */
  volatile u64 accepted_session_count;	/* sessions we accepted */
  volatile echo_session_flag_t flags;
} echo_session_t;

typedef enum
{
  ECHO_NO_DATA_SOURCE,
  ECHO_TEST_DATA_SOURCE,
  ECHO_RX_DATA_SOURCE,
  ECHO_INVALID_DATA_SOURCE
} data_source_t;

enum quic_session_type_t
{
  QUIC_SESSION_TYPE_QUIC,
  QUIC_SESSION_TYPE_STREAM,
  QUIC_SESSION_TYPE_LISTEN,
};


typedef enum
{
  STATE_START,
  STATE_ATTACHED,
  STATE_LISTEN,
  STATE_READY,
  STATE_DISCONNECTED,
  STATE_DETACHED
} connection_state_t;

typedef enum
{
  ECHO_EVT_START,		/* app starts */
  ECHO_EVT_FIRST_QCONNECT,	/* First connect Quic session sent */
  ECHO_EVT_LAST_QCONNECTED,	/* All Quic session are connected */
  ECHO_EVT_FIRST_SCONNECT,	/* First connect Stream session sent */
  ECHO_EVT_LAST_SCONNECTED,	/* All Stream session are connected */
  ECHO_EVT_LAST_BYTE,		/* Last byte received */
  ECHO_EVT_EXIT,		/* app exits */
} echo_test_evt_t;

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


typedef enum
{
  RETURN_PACKETS_NOTEST,
  RETURN_PACKETS_LOG_WRONG,
  RETURN_PACKETS_ASSERT,
} test_return_packets_t;

typedef struct
{
  /* vpe input queue */
  svm_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  /* The URI we're playing with */
  u8 *uri;

  /* Session pool */
  echo_session_t *sessions;

  /* Hash table for disconnect processing */
  uword *session_index_by_vpp_handles;
  /* Index of vpp listener session */
  u32 listen_session_index;

  /* Hash table for shared segment_names */
  uword *shared_segment_handles;
  clib_spinlock_t segment_handles_lock;

  int i_am_master;

  /* Our event queue */
  svm_msg_q_t *our_event_queue;

  u8 *socket_name;

  pid_t my_pid;

  /* For deadman timers */
  clib_time_t clib_time;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile connection_state_t state;

  /* Signal variables */
  volatile u8 time_to_stop;
  u8 has_failed;

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;

  u8 *connect_test_data;
  u8 test_return_packets;
  u64 bytes_to_send;
  u64 bytes_to_receive;
  u32 fifo_size;
  u32 rx_buf_size;
  u32 tx_buf_size;
  data_source_t data_source;
  u8 send_disconnects;		/* actively send disconnect */

  u8 *appns_id;
  u64 appns_flags;
  u64 appns_secret;

  pthread_t *client_thread_handles;
  u32 *thread_args;
  u32 n_clients;		/* Target number of QUIC sessions */
  u32 n_stream_clients;		/* Target Number of STREAM sessions per QUIC session */
  volatile u32 n_quic_clients_connected;	/* Number of connected QUIC sessions */
  volatile u32 n_clients_connected;	/* Number of STREAM sessions connected */

  u64 tx_total;
  u64 rx_total;

  /* Event based timing : start & end depend on CLI specified events */
  u8 first_sconnect_sent;	/* Sent the first Stream session connect ? */
  f64 start_time;
  f64 end_time;
  u8 timing_start_event;
  u8 timing_end_event;

  /* cb vft for QUIC scenarios */
  quic_echo_cb_vft_t cb_vft;

  /** Flag that decides if socket, instead of svm, api is used to connect to
   * vpp. If sock api is used, shm binary api is subsequently bootstrapped
   * and all other messages are exchanged using shm IPC. */
  u8 use_sock_api;

  /* Limit the number of incorrect data messages */
  int max_test_msg;

  fifo_segment_main_t segment_main;
} echo_main_t;

echo_main_t echo_main;

#if CLIB_DEBUG > 0
#define NITER 10000
#else
#define NITER 4000000
#endif

#if CLIB_DEBUG > 0
#define TIMEOUT 10.0
#else
#define TIMEOUT 10.0
#endif

/*
 *
 *  Format functions
 *
 */

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
  if (state == STATE_DISCONNECTED)
    return format (s, "STATE_DISCONNECTED");
  if (state == STATE_DETACHED)
    return format (s, "STATE_DETACHED");
  else
    return format (s, "unknown state");
}

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

static uword
unformat_data (unformat_input_t * input, va_list * args)
{
  u64 _a;
  u64 *a = va_arg (*args, u64 *);
  if (unformat (input, "%lluGb", &_a))
    {
      *a = _a << 30;
      return 1;
    }
  else if (unformat (input, "%lluMb", &_a))
    {
      *a = _a << 20;
      return 1;
    }
  else if (unformat (input, "%lluKb", &_a))
    {
      *a = _a << 10;
      return 1;
    }
  else if (unformat (input, "%llu", a))
    return 1;
  return 0;
}

static uword
echo_unformat_timing_event (unformat_input_t * input, va_list * args)
{
  echo_test_evt_t *a = va_arg (*args, echo_test_evt_t *);
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

static void
init_error_string_table (echo_main_t * em)
{
  em->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n,v,s) hash_set (em->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (em->error_string_by_error_number, 99, "Misc");
}

/*
 *
 *  End of format functions
 *
 */

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
echo_send_connect (echo_main_t * em, u8 * uri, u32 opaque)
{
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
echo_disconnect_session (echo_main_t * em, echo_session_t * s)
{
  vl_api_disconnect_session_t *dmp;
  dmp = vl_msg_api_alloc (sizeof (*dmp));
  clib_memset (dmp, 0, sizeof (*dmp));
  dmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION);
  dmp->client_index = em->my_client_index;
  dmp->handle = s->vpp_session_handle;
  DBG ("Disconnect session 0x%lx", dmp->handle);
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
  DBG ("Waiting for segment 0x%lx...", segment_handle);
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
  DBG ("timeout wait_for_segment_allocation (0x%lx)", segment_handle);
  return -1;
}

static void
quic_echo_notify_event (echo_main_t * em, echo_test_evt_t e)
{
  if (em->timing_start_event == e)
    em->start_time = clib_time_now (&em->clib_time);
  else if (em->timing_end_event == e)
    em->end_time = clib_time_now (&em->clib_time);
}

static void
echo_assert_test_suceeded (echo_main_t * em)
{
  CHECK (em->rx_total,
	 em->n_stream_clients * em->n_clients * em->bytes_to_receive,
	 "Not enough data received");
  CHECK (em->tx_total,
	 em->n_stream_clients * em->n_clients * em->bytes_to_send,
	 "Not enough data sent");
  CHECK (0, hash_elts (em->session_index_by_vpp_handles),
	 "Some sessions are still open");
}

always_inline void
echo_session_dequeue_notify (echo_session_t * s)
{
  int rv;
  rv = app_send_io_evt_to_vpp (s->vpp_evt_q, s->rx_fifo->master_session_index,
			       SESSION_IO_EVT_RX, SVM_Q_WAIT);
  svm_fifo_clear_deq_ntf (s->rx_fifo);
  if (rv)
    ECHO_FAIL ("app_send_io_evt_to_vpp errored %d", rv);
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
  echo_main_t *um = &echo_main;
  um->time_to_stop = 1;
}

static clib_error_t *
setup_signal_handlers (void)
{
  signal (SIGINT, stop_signal);
  signal (SIGQUIT, stop_signal);
  signal (SIGTERM, stop_signal);
  return 0;
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
  fformat (stdout, "Session 0x%x done in %.6fs RX[%.4f] TX[%.4f] Gbit/s\n",
	   session->vpp_session_handle, deltat,
	   (session->bytes_received * 8.0) / deltat / 1e9,
	   (session->bytes_sent * 8.0) / deltat / 1e9);
}

static void
print_global_stats (echo_main_t * em)
{
  f64 deltat = em->end_time - em->start_time;
  u8 *s = format (0, "%U:%U",
		  echo_format_timing_event, em->timing_start_event,
		  echo_format_timing_event, em->timing_end_event);
  fformat (stdout, "Timing %s\n", s);
  fformat (stdout, "-------- TX --------\n");
  fformat (stdout, "%lld bytes (%lld mbytes, %lld gbytes) in %.2f seconds\n",
	   em->tx_total, em->tx_total / (1ULL << 20),
	   em->tx_total / (1ULL << 30), deltat);
  fformat (stdout, "%.4f Gbit/second\n", (em->tx_total * 8.0) / deltat / 1e9);
  fformat (stdout, "-------- RX --------\n");
  fformat (stdout, "%lld bytes (%lld mbytes, %lld gbytes) in %.2f seconds\n",
	   em->rx_total, em->rx_total / (1ULL << 20),
	   em->rx_total / (1ULL << 30), deltat);
  fformat (stdout, "%.4f Gbit/second\n", (em->rx_total * 8.0) / deltat / 1e9);
  fformat (stdout, "--------------------\n");
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
    if (s->flags & SESSION_FLAG_SHOULD_FREE)
      vec_add1 (session_indexes, s->session_index);}
  ));
  /* *INDENT-ON* */
  vec_foreach (session_index, session_indexes)
  {
    /* Free session */
    s = pool_elt_at_index (em->sessions, *session_index);
    DBG ("Freeing session 0x%lx", s->vpp_session_handle);
    pool_put (em->sessions, s);
    clib_memset (s, 0xfe, sizeof (*s));
  }
}

static void
echo_cleanup_session (echo_main_t * em, echo_session_t * s)
{
  echo_session_t *ls;
  u64 accepted_session_count;
  if (s->listener_index != SESSION_INVALID_INDEX)
    {
      ls = pool_elt_at_index (em->sessions, s->listener_index);
      accepted_session_count =
	clib_atomic_sub_fetch (&ls->accepted_session_count, 1);
      if (accepted_session_count == 0
	  && ls->session_type != QUIC_SESSION_TYPE_LISTEN
	  && em->send_disconnects)
	echo_disconnect_session (em, ls);
    }
  if (s->session_type == QUIC_SESSION_TYPE_QUIC)
    clib_atomic_sub_fetch (&em->n_quic_clients_connected, 1);
  else if (s->session_type == QUIC_SESSION_TYPE_STREAM)
    clib_atomic_sub_fetch (&em->n_clients_connected, 1);

  DBG ("Cleanup sessions (still %uQ %uS)", em->n_quic_clients_connected,
       em->n_clients_connected);
  hash_unset (em->session_index_by_vpp_handles, s->vpp_session_handle);

  /* Mark session as to be freed */
  s->flags |= SESSION_FLAG_SHOULD_FREE;
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
      clib_warning ("Session 0x%lx byte %lld was 0x%x expected 0x%x",
		    s->vpp_session_handle, s->bytes_received + i, rx_buf[i],
		    expected);
      em->max_test_msg--;
      if (em->max_test_msg == 0)
	clib_warning ("Too many errors, hiding next ones");
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

  ASSERT (s->bytes_to_receive >= n_read);
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

/*
 * Rx/Tx polling thread per connection
 */
static void *
echo_thread_fn (void *arg)
{
  echo_main_t *em = &echo_main;
  u8 *rx_buf = 0;
  u32 session_index = *(u32 *) arg;
  echo_session_t *s;
  int n_read, n_sent, idle_loop = 0;
  vec_validate (rx_buf, em->rx_buf_size);

  while (!em->time_to_stop && em->state != STATE_READY)
    ;

  s = pool_elt_at_index (em->sessions, session_index);
  while (!em->time_to_stop)
    {
      n_read = recv_data_chunk (em, s, rx_buf);
      if (em->data_source == ECHO_TEST_DATA_SOURCE)
	n_sent =
	  send_data_chunk (s, em->connect_test_data,
			   s->bytes_sent % em->tx_buf_size, em->tx_buf_size);
      else if (em->data_source == ECHO_RX_DATA_SOURCE)
	n_sent = mirror_data_chunk (em, s, rx_buf, n_read);
      else
	n_sent = 0;
      if (!s->bytes_to_send && !s->bytes_to_receive)
	break;
      if (s->flags & SESSION_FLAG_SHOULD_CLOSE)
	break;

      /* check idle clients */
      if (!n_sent & !n_read)
	idle_loop++;
      else
	idle_loop = 0;
      if (idle_loop == 1e7)
	{
	  DBG ("Idle client TX:%dB RX:%dB", s->bytes_to_send,
	       s->bytes_to_receive);
	  DBG ("Idle FIFOs  TX:%dB RX:%dB", svm_fifo_max_dequeue (s->tx_fifo),
	       svm_fifo_max_dequeue (s->rx_fifo));
	}
    }
  DBG ("[%lu/%lu] -> S(%x) -> [%lu/%lu]",
       s->bytes_received, s->bytes_received + s->bytes_to_receive,
       session_index, s->bytes_sent, s->bytes_sent + s->bytes_to_send);
  em->tx_total += s->bytes_sent;
  em->rx_total += s->bytes_received;
  clib_warning ("%d/%d", em->rx_total,
		em->n_clients * em->n_stream_clients * em->bytes_to_receive);
  if (em->rx_total ==
      em->n_clients * em->n_stream_clients * em->bytes_to_receive)
    quic_echo_notify_event (em, ECHO_EVT_LAST_BYTE);
  if (em->send_disconnects)
    echo_disconnect_session (em, s);
  else
    {
      while (!(s->flags & SESSION_FLAG_SHOULD_CLOSE) & !em->time_to_stop)
	;
      echo_cleanup_session (em, s);
    }
  pthread_exit (0);
}

static void
session_bound_handler (session_bound_msg_t * mp)
{
  echo_main_t *em = &echo_main;
  echo_session_t *listen_session;
  u32 session_index;

  if (mp->retval)
    {
      ECHO_FAIL ("bind failed: %U", format_api_error,
		 clib_net_to_host_u32 (mp->retval));
      return;
    }

  clib_warning ("listening on %U:%u", format_ip46_address, mp->lcl_ip,
		mp->lcl_is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
		clib_net_to_host_u16 (mp->lcl_port));

  /* Allocate local session and set it up */
  pool_get (em->sessions, listen_session);
  listen_session->session_type = QUIC_SESSION_TYPE_LISTEN;
  listen_session->accepted_session_count = 0;
  session_index = listen_session - em->sessions;
  listen_session->session_index = session_index;
  hash_set (em->session_index_by_vpp_handles, mp->handle, session_index);
  em->state = STATE_LISTEN;
  em->listen_session_index = session_index;
}

static void
session_accepted_handler (session_accepted_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_accepted_reply_msg_t *rmp;
  svm_fifo_t *rx_fifo, *tx_fifo;
  echo_main_t *em = &echo_main;
  echo_session_t *session, *listen_session;
  u32 session_index;
  uword *p;
  /* Allocate local session and set it up */
  pool_get (em->sessions, session);
  session_index = session - em->sessions;

  if (wait_for_segment_allocation (mp->segment_handle))
    {
      ECHO_FAIL ("wait_for_segment_allocation errored");
      return;
    }

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;
  session->session_index = session_index;
  session->vpp_session_handle = mp->handle;
  session->start = clib_time_now (&em->clib_time);
  session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					 svm_msg_q_t *);

  session->accepted_session_count = 0;
  p = hash_get (em->session_index_by_vpp_handles, mp->listener_handle);
  if (!p)
    {
      ECHO_FAIL ("unknown handle 0x%lx", mp->listener_handle);
      return;
    }
  session->listener_index = p[0];
  listen_session = pool_elt_at_index (em->sessions, p[0]);
  clib_atomic_fetch_add (&listen_session->accepted_session_count, 1);

  /* Add it to lookup table */
  DBG ("Accepted session 0x%lx, Listener 0x%lx idx %lu", mp->handle,
       mp->listener_handle, session_index);
  hash_set (em->session_index_by_vpp_handles, mp->handle, session_index);

  app_alloc_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_ACCEPTED_REPLY);
  rmp = (session_accepted_reply_msg_t *) app_evt->evt->data;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  app_send_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt);

  if (listen_session->session_type == QUIC_SESSION_TYPE_LISTEN)
    {
      session->session_type = QUIC_SESSION_TYPE_QUIC;
      if (em->cb_vft.quic_accepted_cb)
	em->cb_vft.quic_accepted_cb (mp, session_index);
      clib_atomic_fetch_add (&em->n_quic_clients_connected, 1);
    }
  else if (em->i_am_master)
    {
      session->session_type = QUIC_SESSION_TYPE_STREAM;
      if (em->cb_vft.server_stream_accepted_cb)
	em->cb_vft.server_stream_accepted_cb (mp, session_index);
      clib_atomic_fetch_add (&em->n_clients_connected, 1);
    }
  else
    {
      session->session_type = QUIC_SESSION_TYPE_STREAM;
      if (em->cb_vft.client_stream_accepted_cb)
	em->cb_vft.client_stream_accepted_cb (mp, session_index);
      clib_atomic_fetch_add (&em->n_clients_connected, 1);
    }

  if (em->n_clients_connected == em->n_clients * em->n_stream_clients)
    {
      em->state = STATE_READY;
      quic_echo_notify_event (em, ECHO_EVT_LAST_SCONNECTED);
    }
  if (em->n_quic_clients_connected == em->n_clients)
    quic_echo_notify_event (em, ECHO_EVT_LAST_QCONNECTED);
}

static void
session_connected_handler (session_connected_msg_t * mp)
{
  echo_main_t *em = &echo_main;
  echo_session_t *session, *listen_session;
  u32 session_index;
  u32 listener_index = htonl (mp->context);
  svm_fifo_t *rx_fifo, *tx_fifo;

  if (mp->retval)
    {
      ECHO_FAIL ("connection failed with code: %U", format_api_error,
		 clib_net_to_host_u32 (mp->retval));
      return;
    }

  pool_get (em->sessions, session);
  clib_memset (session, 0, sizeof (*session));
  session_index = session - em->sessions;

  if (wait_for_segment_allocation (mp->segment_handle))
    {
      ECHO_FAIL ("wait_for_segment_allocation errored");
      return;
    }

  rx_fifo = uword_to_pointer (mp->server_rx_fifo, svm_fifo_t *);
  rx_fifo->client_session_index = session_index;
  tx_fifo = uword_to_pointer (mp->server_tx_fifo, svm_fifo_t *);
  tx_fifo->client_session_index = session_index;

  session->rx_fifo = rx_fifo;
  session->tx_fifo = tx_fifo;
  session->vpp_session_handle = mp->handle;
  session->session_index = session_index;
  session->start = clib_time_now (&em->clib_time);
  session->vpp_evt_q = uword_to_pointer (mp->vpp_event_queue_address,
					 svm_msg_q_t *);

  session->listener_index = listener_index;
  session->accepted_session_count = 0;
  if (listener_index != SESSION_INVALID_INDEX)
    {
      listen_session = pool_elt_at_index (em->sessions, listener_index);
      clib_atomic_fetch_add (&listen_session->accepted_session_count, 1);
    }

  DBG ("Connected session 0x%lx", mp->handle, session_index);
  hash_set (em->session_index_by_vpp_handles, mp->handle, session_index);

  if (listener_index == SESSION_INVALID_INDEX)
    {
      session->session_type = QUIC_SESSION_TYPE_QUIC;
      if (em->cb_vft.quic_connected_cb)
	em->cb_vft.quic_connected_cb (mp, session_index);
      clib_atomic_fetch_add (&em->n_quic_clients_connected, 1);
    }
  else if (em->i_am_master)
    {
      session->session_type = QUIC_SESSION_TYPE_STREAM;
      if (em->cb_vft.server_stream_connected_cb)
	em->cb_vft.server_stream_connected_cb (mp, session_index);
      clib_atomic_fetch_add (&em->n_clients_connected, 1);
    }
  else
    {
      session->session_type = QUIC_SESSION_TYPE_STREAM;
      if (em->cb_vft.client_stream_connected_cb)
	em->cb_vft.client_stream_connected_cb (mp, session_index);
      clib_atomic_fetch_add (&em->n_clients_connected, 1);
    }

  if (em->n_clients_connected == em->n_clients * em->n_stream_clients)
    {
      em->state = STATE_READY;
      quic_echo_notify_event (em, ECHO_EVT_LAST_SCONNECTED);
    }
  if (em->n_quic_clients_connected == em->n_clients)
    quic_echo_notify_event (em, ECHO_EVT_LAST_QCONNECTED);
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

  if (!em->first_sconnect_sent)
    {
      em->first_sconnect_sent = 1;
      quic_echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
    }
  for (i = 0; i < em->n_stream_clients; i++)
    echo_send_connect (em, uri, session_index);

  clib_warning ("Qsession 0x%llx connected to %U:%d",
		mp->handle, format_ip46_address, &mp->lcl.ip,
		mp->lcl.is_ip4, clib_net_to_host_u16 (mp->lcl.port));
}

static void
echo_on_connected_send (session_connected_msg_t * mp, u32 session_index)
{
  echo_main_t *em = &echo_main;
  int rv;
  echo_session_t *session;

  session = pool_elt_at_index (em->sessions, session_index);
  session->bytes_to_send = em->bytes_to_send;
  session->bytes_to_receive = em->bytes_to_receive;

  DBG ("Stream session 0x%lx connected", session->vpp_session_handle);

  /*
   * Start RX thread
   */
  em->thread_args[em->n_clients_connected] = session_index;
  rv = pthread_create (&em->client_thread_handles[em->n_clients_connected],
		       NULL /*attr */ , echo_thread_fn,
		       (void *) &em->thread_args[em->n_clients_connected]);
  if (rv)
    {
      ECHO_FAIL ("pthread_create returned %d", rv);
      return;
    }
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
  int rv;
  echo_session_t *session;

  session = pool_elt_at_index (em->sessions, session_index);
  session->bytes_to_send = em->bytes_to_send;
  session->bytes_to_receive = em->bytes_to_receive;

  DBG ("Stream session 0x%lx accepted", mp->handle);

  /*
   * Start RX thread
   */
  em->thread_args[em->n_clients_connected] = session_index;
  rv = pthread_create (&em->client_thread_handles[em->n_clients_connected],
		       NULL /*attr */ , echo_thread_fn,
		       (void *) &em->thread_args[em->n_clients_connected]);
  if (rv)
    {
      ECHO_FAIL ("pthread_create returned %d", rv);
      return;
    }
}

static void
echo_on_accept_connect (session_accepted_msg_t * mp, u32 session_index)
{
  echo_main_t *em = &echo_main;
  DBG ("Accept on QSession 0x%lx %u", mp->handle);
  u8 *uri = format (0, "QUIC://session/%lu", mp->handle);
  u32 i;

  if (!em->first_sconnect_sent)
    {
      em->first_sconnect_sent = 1;
      quic_echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
    }
  for (i = 0; i < em->n_stream_clients; i++)
    echo_send_connect (em, uri, session_index);
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
  clib_warning ("Accepted session from: %s:%d", ip_str,
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
  uword *p;
  int rv = 0;
  DBG ("passive close session 0x%lx", mp->handle);
  p = hash_get (em->session_index_by_vpp_handles, mp->handle);
  if (!p)
    {
      ECHO_FAIL ("couldn't find session key %llx", mp->handle);
      return;
    }

  s = pool_elt_at_index (em->sessions, p[0]);
  if (s->session_type == QUIC_SESSION_TYPE_STREAM)
    s->flags |= SESSION_FLAG_SHOULD_CLOSE;	/* tell thread to close session */
  else
    echo_cleanup_session (em, s);	/* We can clean Qsessions right away */

  app_alloc_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_DISCONNECTED_REPLY);
  rmp = (session_disconnected_reply_msg_t *) app_evt->evt->data;
  rmp->retval = rv;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  app_send_ctrl_evt_to_vpp (s->vpp_evt_q, app_evt);

  if (s->session_type == QUIC_SESSION_TYPE_STREAM)
    session_print_stats (em, s);
}

static void
session_reset_handler (session_reset_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  echo_main_t *em = &echo_main;
  session_reset_reply_msg_t *rmp;
  echo_session_t *session = 0;
  uword *p;
  int rv = 0;

  DBG ("Reset session 0x%lx", mp->handle);
  p = hash_get (em->session_index_by_vpp_handles, mp->handle);

  if (!p)
    {
      ECHO_FAIL ("couldn't find session key %llx", mp->handle);
      return;
    }

  session = pool_elt_at_index (em->sessions, p[0]);
  /* Cleanup later */
  em->time_to_stop = 1;
  app_alloc_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_RESET_REPLY);
  rmp = (session_reset_reply_msg_t *) app_evt->evt->data;
  rmp->retval = rv;
  rmp->handle = mp->handle;
  app_send_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt);
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
      clib_warning ("unhandled event %u", e->event_type);
    }
}

static int
wait_for_state_change (echo_main_t * em, connection_state_t state,
		       f64 timeout)
{
  svm_msg_q_msg_t msg;
  session_event_t *e;
  f64 end_time = clib_time_now (&em->clib_time) + timeout;

  while (!timeout || clib_time_now (&em->clib_time) < end_time)
    {
      if (em->state == state)
	return 0;
      if (em->time_to_stop == 1)
	return 0;
      if (!em->our_event_queue || em->state < STATE_ATTACHED)
	continue;

      if (svm_msg_q_sub (em->our_event_queue, &msg, SVM_Q_NOWAIT, 0))
	continue;
      e = svm_msg_q_msg_data (em->our_event_queue, &msg);
      handle_mq_event (e);
      svm_msg_q_free_msg (em->our_event_queue, &msg);
    }
  DBG ("timeout waiting for %U", format_quic_echo_state, state);
  return -1;
}

static void
echo_event_loop (echo_main_t * em)
{
  svm_msg_q_msg_t msg;
  session_event_t *e;

  DBG ("Waiting for data on %u clients", em->n_clients_connected);
  while (em->n_clients_connected | em->n_quic_clients_connected)
    {
      int rc = svm_msg_q_sub (em->our_event_queue, &msg, SVM_Q_TIMEDWAIT, 1);
      if (PREDICT_FALSE (rc == ETIMEDOUT && em->time_to_stop))
	break;
      if (rc == ETIMEDOUT)
	continue;
      e = svm_msg_q_msg_data (em->our_event_queue, &msg);
      handle_mq_event (e);
      svm_msg_q_free_msg (em->our_event_queue, &msg);
    }
}

static void
clients_run (echo_main_t * em)
{
  u64 i;
  quic_echo_notify_event (em, ECHO_EVT_FIRST_QCONNECT);
  for (i = 0; i < em->n_clients; i++)
    echo_send_connect (em, em->uri, SESSION_INVALID_INDEX);

  if (wait_for_state_change (em, STATE_READY, TIMEOUT))
    {
      ECHO_FAIL ("Timeout waiting for state ready");
      return;
    }

  echo_event_loop (em);
}

static void
server_run (echo_main_t * em)
{
  server_send_listen (em);
  if (wait_for_state_change (em, STATE_READY, 0))
    {
      ECHO_FAIL ("Timeout waiting for state ready");
      return;
    }
  echo_event_loop (em);

  /* Cleanup */
  server_send_unbind (em);
  wait_for_state_change (em, STATE_DISCONNECTED, TIMEOUT);
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
  int *fds = 0;
  u32 n_fds = 0;
  u64 segment_handle;
  segment_handle = clib_net_to_host_u64 (mp->segment_handle);
  DBG ("Attached returned app %u", htons (mp->app_index));

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
      vl_socket_client_recv_fd_msg (fds, mp->n_fds, 5);

      if (mp->fd_flags & SESSION_FD_F_VPP_MQ_SEGMENT)
	if (ssvm_segment_attach (0, SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  {
	    ECHO_FAIL ("svm_fifo_segment_attach failed");
	    return;
	  }

      if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
	if (ssvm_segment_attach ((char *) mp->segment_name,
				 SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  {
	    ECHO_FAIL ("svm_fifo_segment_attach ('%s') failed",
		       mp->segment_name);
	    return;
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
  clib_spinlock_lock (&em->segment_handles_lock);
  hash_set (em->shared_segment_handles, segment_handle, 1);
  clib_spinlock_unlock (&em->segment_handles_lock);
  DBG ("Mapped segment 0x%lx", segment_handle);

  em->state = STATE_ATTACHED;
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

  clib_spinlock_lock (&em->segment_handles_lock);
  hash_unset (em->shared_segment_handles, segment_handle);
  clib_spinlock_unlock (&em->segment_handles_lock);
  DBG ("Unmaped segment 0x%lx", segment_handle);
}

static void
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t * mp)
{
  fifo_segment_main_t *sm = &echo_main.segment_main;
  fifo_segment_create_args_t _a, *a = &_a;
  echo_main_t *em = &echo_main;
  int *fds = 0;
  char *seg_name = (char *) mp->segment_name;
  u64 segment_handle = clib_net_to_host_u64 (mp->segment_handle);

  if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
    {
      vec_validate (fds, 1);
      vl_socket_client_recv_fd_msg (fds, 1, 5);
      if (ssvm_segment_attach (seg_name, SSVM_SEGMENT_MEMFD, fds[0]))
	{
	  ECHO_FAIL ("svm_fifo_segment_attach ('%s')"
		     "failed on SSVM_SEGMENT_MEMFD", seg_name);
	  return;
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
	  return;
	}
    }
  clib_spinlock_lock (&em->segment_handles_lock);
  hash_set (em->shared_segment_handles, segment_handle, 1);
  clib_spinlock_unlock (&em->segment_handles_lock);
  DBG ("Mapped segment 0x%lx", segment_handle);
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
      /* ECHO_FAIL ("returned %d", ntohl (mp->retval));
         return;  FIXME : UDPC issue */
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
  uword *p;

  if (mp->retval)
    {
      ECHO_FAIL ("vpp complained about disconnect: %d", ntohl (mp->retval));
      return;
    }

  DBG ("Got disonnected reply for session 0x%lx", mp->handle);
  p = hash_get (em->session_index_by_vpp_handles, mp->handle);
  if (!p)
    {
      ECHO_FAIL ("couldn't find session key %llx", mp->handle);
      return;
    }

  s = pool_elt_at_index (em->sessions, p[0]);
  echo_cleanup_session (em, s);
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
	   "quic_echo [socket-name SOCKET] [client|server] [uri URI] [OPTIONS]\n"
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
	   "  quic-setup OPT      OPT=serverstream : Client open N connections. On each one server opens M streams\n"
	   "                            by default : Client open N connections. On each one client opens M streams\n"
	   "\n"
	   "  nclients N[/M]       Open N QUIC connections, each one with M streams (M defaults to 1)\n"
	   "  TX=1337[Kb|Mb|GB]    Send 1337 [K|M|G]bytes, use TX=RX to reflect the data\n"
	   "  RX=1337[Kb|Mb|GB]    Expect 1337 [K|M|G]bytes\n"
	   "\n"
	   "Default config is :\n"
	   "server nclients 1/1 RX=64Kb TX=RX\n"
	   "client nclients 1/1 RX=64Kb TX=64Kb\n");
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
      else if (unformat (a, "time %U:%U",
			 echo_unformat_timing_event, &em->timing_start_event,
			 echo_unformat_timing_event, &em->timing_end_event))
	;
      else
	print_usage_and_exit ();
    }

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

  em->send_disconnects = !em->i_am_master;
}

int
main (int argc, char **argv)
{
  echo_main_t *em = &echo_main;
  fifo_segment_main_t *sm = &em->segment_main;
  char *app_name;
  u32 n_clients, i;

  clib_mem_init_thread_safe (0, 256 << 20);
  clib_memset (em, 0, sizeof (*em));
  em->session_index_by_vpp_handles = hash_create (0, sizeof (uword));
  em->shared_segment_handles = hash_create (0, sizeof (uword));
  em->my_pid = getpid ();
  em->socket_name = format (0, "%s%c", API_SOCKET_FILE, 0);
  em->use_sock_api = 1;
  em->fifo_size = 64 << 10;
  em->n_clients = 1;
  em->n_stream_clients = 1;
  em->max_test_msg = 50;
  em->time_to_stop = 0;
  em->i_am_master = 1;
  em->test_return_packets = RETURN_PACKETS_NOTEST;
  em->timing_start_event = ECHO_EVT_FIRST_QCONNECT;
  em->timing_end_event = ECHO_EVT_LAST_BYTE;
  em->bytes_to_receive = ~0;	/* defaulted when we know if server/client */
  em->bytes_to_send = ~0;	/* defaulted when we know if server/client */
  em->rx_buf_size = 1 << 20;
  em->tx_buf_size = 1 << 20;
  em->data_source = ECHO_INVALID_DATA_SOURCE;
  em->uri = format (0, "%s%c", "quic://0.0.0.0/1234", 0);
  em->cb_vft = default_cb_vft;
  quic_echo_process_opts (argc, argv);

  n_clients = em->n_clients * em->n_stream_clients;
  vec_validate (em->client_thread_handles, n_clients - 1);
  vec_validate (em->thread_args, n_clients - 1);
  clib_time_init (&em->clib_time);
  init_error_string_table (em);
  fifo_segment_main_init (sm, HIGH_SEGMENT_BASEVA, 20);
  clib_spinlock_init (&em->segment_handles_lock);
  vec_validate (em->connect_test_data, em->tx_buf_size);
  for (i = 0; i < em->tx_buf_size; i++)
    em->connect_test_data[i] = i & 0xff;

  setup_signal_handlers ();
  quic_echo_api_hookup (em);

  app_name = em->i_am_master ? "quic_echo_server" : "quic_echo_client";
  if (connect_to_vpp (app_name) < 0)
    {
      svm_region_exit ();
      fformat (stderr, "ECHO-ERROR: Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  quic_echo_notify_event (em, ECHO_EVT_START);

  application_send_attach (em);
  if (wait_for_state_change (em, STATE_ATTACHED, TIMEOUT))
    {
      fformat (stderr, "ECHO-ERROR: Couldn't attach to vpp, exiting...\n");
      exit (1);
    }
  if (em->i_am_master)
    server_run (em);
  else
    clients_run (em);
  quic_echo_notify_event (em, ECHO_EVT_EXIT);
  print_global_stats (em);
  echo_free_sessions (em);
  echo_assert_test_suceeded (em);
  application_detach (em);
  if (wait_for_state_change (em, STATE_DETACHED, TIMEOUT))
    {
      fformat (stderr, "ECHO-ERROR: Couldn't detach from vpp, exiting...\n");
      exit (1);
    }
  if (em->use_sock_api)
    vl_socket_client_disconnect ();
  else
    vl_client_disconnect_from_vlib ();
  fformat (stdout, "Test complete !\n");
  exit (em->has_failed);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
