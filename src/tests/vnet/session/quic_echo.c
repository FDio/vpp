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

#define QUIC_ECHO_DBG 0
#define DBG(_fmt, _args...)			\
    if (QUIC_ECHO_DBG) 				\
      clib_warning (_fmt, ##_args)

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
} echo_session_t;

typedef enum
{
  STATE_START,
  STATE_ATTACHED,
  STATE_LISTEN,
  STATE_READY,
  STATE_DISCONNECTING,
  STATE_FAILED,
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

enum quic_session_type_t
{
  QUIC_SESSION_TYPE_QUIC = 0,
  QUIC_SESSION_TYPE_STREAM = 1,
  QUIC_SESSION_TYPE_LISTEN = INT32_MAX,
};

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
  /* Handle of vpp listener session */
  u64 listener_handle;

  /* Hash table for shared segment_names */
  uword *shared_segment_handles;
  clib_spinlock_t segment_handles_lock;

  /* intermediate rx buffer */
  u8 *rx_buf;

  int i_am_master;

  /* drop all packets */
  int no_return;

  /* Our event queue */
  svm_msg_q_t *our_event_queue;

  u8 *socket_name;

  pid_t my_pid;

  /* For deadman timers */
  clib_time_t clib_time;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile connection_state_t state;

  /* Signal variables */
  volatile int time_to_stop;

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;

  u8 *connect_test_data;
  pthread_t *client_thread_handles;
  u32 *thread_args;
  u8 test_return_packets;
  u64 bytes_to_send;
  u64 bytes_to_receive;
  u32 fifo_size;

  u8 *appns_id;
  u64 appns_flags;
  u64 appns_secret;

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
  if (state == STATE_DISCONNECTING)
    return format (s, "STATE_DISCONNECTING");
  if (state == STATE_FAILED)
    return format (s, "STATE_FAILED");
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

static void
quic_echo_notify_event (echo_main_t * em, echo_test_evt_t e)
{
  if (em->timing_start_event == e)
    em->start_time = clib_time_now (&em->clib_time);
  else if (em->timing_end_event == e)
    em->end_time = clib_time_now (&em->clib_time);
}

static uword
echo_unformat_timing_event (unformat_input_t * input, va_list * args)
{
  echo_test_evt_t *a = va_arg (*args, echo_test_evt_t *);
  if (unformat (input, "start"))
    *a = ECHO_EVT_START;
  else if (unformat (input, "qconnect"))
    *a = ECHO_EVT_FIRST_QCONNECT;
  else if (unformat (input, "qconnected"))
    *a = ECHO_EVT_LAST_QCONNECTED;
  else if (unformat (input, "sconnect"))
    *a = ECHO_EVT_FIRST_SCONNECT;
  else if (unformat (input, "sconnected"))
    *a = ECHO_EVT_LAST_SCONNECTED;
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

static void handle_mq_event (echo_main_t * em, session_event_t * e,
			     int handle_rx);
static void echo_handle_rx (echo_main_t * em, session_event_t * e);

static int
wait_for_segment_allocation (u64 segment_handle)
{
  echo_main_t *em = &echo_main;
  f64 timeout;
  timeout = clib_time_now (&em->clib_time) + TIMEOUT;
  uword *segment_present;
  DBG ("Waiting for segment %lx...", segment_handle);
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
  DBG ("timeout waiting for segment_allocation %lx", segment_handle);
  return -1;
}

static int
wait_for_disconnected_sessions (echo_main_t * em)
{
  f64 timeout;
  timeout = clib_time_now (&em->clib_time) + TIMEOUT;
  while (clib_time_now (&em->clib_time) < timeout)
    {
      if (hash_elts (em->session_index_by_vpp_handles) == 0)
	return 0;
    }
  DBG ("timeout waiting for disconnected_sessions");
  return -1;
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
      if (em->state == STATE_FAILED)
	return -1;
      if (em->time_to_stop == 1)
	return 0;
      if (!em->our_event_queue || em->state < STATE_ATTACHED)
	continue;

      if (svm_msg_q_sub (em->our_event_queue, &msg, SVM_Q_NOWAIT, 0))
	continue;
      e = svm_msg_q_msg_data (em->our_event_queue, &msg);
      handle_mq_event (em, e, 0 /* handle_rx */ );
      svm_msg_q_free_msg (em->our_event_queue, &msg);
    }
  clib_warning ("timeout waiting for state %U", format_quic_echo_state,
		state);
  return -1;
}

static void
notify_rx_data_to_vpp (echo_session_t * s)
{
  svm_fifo_t *f = s->tx_fifo;
  return;			/* FOR NOW */
  if (svm_fifo_set_event (f))
    {
      DBG ("did send event");
      app_send_io_evt_to_vpp (s->vpp_evt_q, f->master_session_index,
			      SESSION_IO_EVT_TX, 0 /* noblock */ );
    }
}

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

static int
application_attach (echo_main_t * em)
{
  application_send_attach (em);
  return wait_for_state_change (em, STATE_ATTACHED, TIMEOUT);
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

  DBG ("%s", "Sent detach");
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
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed", name);
      return rv;
    }
  vec_reset_length (a->new_segment_indices);
  return 0;
}

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
      clib_warning ("attach failed: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
      goto failed;
    }

  if (mp->segment_name_length == 0)
    {
      clib_warning ("segment_name_length zero");
      goto failed;
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
	  goto failed;

      if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
	if (ssvm_segment_attach ((char *) mp->segment_name,
				 SSVM_SEGMENT_MEMFD, fds[n_fds++]))
	  goto failed;

      if (mp->fd_flags & SESSION_FD_F_MQ_EVENTFD)
	svm_msg_q_set_consumer_eventfd (em->our_event_queue, fds[n_fds++]);

      vec_free (fds);
    }
  else
    {
      if (ssvm_segment_attach ((char *) mp->segment_name, SSVM_SEGMENT_SHM,
			       -1))
	goto failed;
    }
  clib_spinlock_lock (&em->segment_handles_lock);
  hash_set (em->shared_segment_handles, segment_handle, 1);
  clib_spinlock_unlock (&em->segment_handles_lock);
  DBG ("Mapped new segment %lx", segment_handle);

  em->state = STATE_ATTACHED;
  return;
failed:
  em->state = STATE_FAILED;
  return;
}

static void
vl_api_application_detach_reply_t_handler (vl_api_application_detach_reply_t *
					   mp)
{
  if (mp->retval)
    clib_warning ("detach returned with err: %d", mp->retval);
  echo_main.state = STATE_DETACHED;
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
	  clib_warning ("socket connect failed");
	  return -1;
	}

      if (vl_socket_client_init_shm (0, 1 /* want_pthread */ ))
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
  fifo_segment_main_t *sm = &echo_main.segment_main;
  fifo_segment_create_args_t _a, *a = &_a;
  echo_main_t *em = &echo_main;
  int rv;
  int *fds = 0;
  u64 segment_handle;
  segment_handle = clib_net_to_host_u64 (mp->segment_handle);

  if (mp->fd_flags & SESSION_FD_F_MEMFD_SEGMENT)
    {
      vec_validate (fds, 1);
      vl_socket_client_recv_fd_msg (fds, 1, 5);
      if (ssvm_segment_attach
	  ((char *) mp->segment_name, SSVM_SEGMENT_MEMFD, fds[0]))
	clib_warning
	  ("svm_fifo_segment_attach ('%s') failed on SSVM_SEGMENT_MEMFD",
	   mp->segment_name);
      clib_spinlock_lock (&em->segment_handles_lock);
      hash_set (em->shared_segment_handles, segment_handle, 1);
      clib_spinlock_unlock (&em->segment_handles_lock);
      vec_free (fds);
      DBG ("Mapped new segment %lx", segment_handle);
      return;
    }

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
  clib_spinlock_lock (&em->segment_handles_lock);
  hash_set (em->shared_segment_handles, mp->segment_name, 1);
  clib_spinlock_unlock (&em->segment_handles_lock);
  clib_warning ("Mapped new segment '%s' size %d", mp->segment_name,
		mp->segment_size);
}

static void
session_print_stats (echo_main_t * em, echo_session_t * session)
{
  f64 deltat = clib_time_now (&em->clib_time) - session->start;
  fformat (stdout, "Session %x done in %.6fs RX[%.4f] TX[%.4f] Gbit/s\n",
	   session->session_index, deltat,
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
  fformat (stdout, "Timinig %s\n", s);
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
test_recv_bytes (echo_main_t * em, echo_session_t * s, u8 * rx_buf,
		 u32 n_read)
{
  int i;
  u8 expected;
  for (i = 0; i < n_read; i++)
    {
      expected = (s->bytes_received + i) & 0xff;
      if (rx_buf[i] != expected && em->max_test_msg > 0)
	{
	  clib_warning
	    ("Session[%lx][0x%lx] byte[%lld], got 0x%x but expected 0x%x",
	     s->session_index, s->vpp_session_handle, s->bytes_received + i,
	     rx_buf[i], expected);
	  em->max_test_msg--;
	  if (em->max_test_msg == 0)
	    clib_warning ("Too many errors, hiding next ones");
	  if (em->test_return_packets == RETURN_PACKETS_ASSERT)
	    ASSERT (0);
	}
    }
}

static void
recv_data_chunk (echo_main_t * em, echo_session_t * s, u8 * rx_buf)
{
  int n_to_read, n_read;

  n_to_read = svm_fifo_max_dequeue (s->rx_fifo);
  if (!n_to_read)
    return;

  do
    {
      n_read =
	app_recv_stream ((app_session_t *) s, rx_buf, vec_len (rx_buf));
      if (n_read <= 0)
	break;
      notify_rx_data_to_vpp (s);
      if (em->test_return_packets)
	test_recv_bytes (em, s, rx_buf, n_read);

      ASSERT (s->bytes_to_receive >= n_read);
      n_to_read -= n_read;
      s->bytes_received += n_read;
      s->bytes_to_receive -= n_read;
    }
  while (n_to_read > 0);
}

static void
send_data_chunk (echo_main_t * em, echo_session_t * s)
{
  u64 test_buf_len, bytes_this_chunk, test_buf_offset;
  u8 *test_data = em->connect_test_data;
  int n_sent;

  test_buf_len = vec_len (test_data);
  test_buf_offset = s->bytes_sent % test_buf_len;
  bytes_this_chunk = clib_min (test_buf_len - test_buf_offset,
			       s->bytes_to_send);

  n_sent = app_send_stream ((app_session_t *) s, test_data + test_buf_offset,
			    bytes_this_chunk, 0);

  if (n_sent > 0)
    {
      s->bytes_to_send -= n_sent;
      s->bytes_sent += n_sent;
    }
}

/*
 * Rx/Tx polling thread per connection
 */
static void *
client_thread_fn (void *arg)
{
  echo_main_t *em = &echo_main;
  u8 *rx_buf = 0;
  u32 session_index = *(u32 *) arg;
  echo_session_t *s;

  vec_validate (rx_buf, 1 << 20);

  while (!em->time_to_stop && em->state != STATE_READY)
    ;

  s = pool_elt_at_index (em->sessions, session_index);
  while (!em->time_to_stop)
    {
      send_data_chunk (em, s);
      recv_data_chunk (em, s, rx_buf);
      if (!s->bytes_to_send && !s->bytes_to_receive)
	break;
    }

  DBG ("[%lu/%lu] -> S(%x) -> [%lu/%lu]",
       s->bytes_received, s->bytes_received + s->bytes_to_receive,
       session_index, s->bytes_sent, s->bytes_sent + s->bytes_to_send);
  em->tx_total += s->bytes_sent;
  em->rx_total += s->bytes_received;
  em->n_clients_connected--;

  if (em->n_clients_connected == 0)
    quic_echo_notify_event (em, ECHO_EVT_LAST_BYTE);

  pthread_exit (0);
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
client_disconnect_session (echo_main_t * em, echo_session_t * s)
{
  vl_api_disconnect_session_t *dmp;
  dmp = vl_msg_api_alloc (sizeof (*dmp));
  clib_memset (dmp, 0, sizeof (*dmp));
  dmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION);
  dmp->client_index = em->my_client_index;
  dmp->handle = s->vpp_session_handle;
  DBG ("Sending Session disonnect handle %lu", dmp->handle);
  vl_msg_api_send_shmem (em->vl_input_queue, (u8 *) & dmp);
  pool_put (em->sessions, s);
  clib_memset (s, 0xfe, sizeof (*s));
}

static void
session_bound_handler (session_bound_msg_t * mp)
{
  echo_main_t *em = &echo_main;

  if (mp->retval)
    {
      clib_warning ("bind failed: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
      em->state = STATE_FAILED;
      return;
    }

  clib_warning ("listening on %U:%u", format_ip46_address, mp->lcl_ip,
		mp->lcl_is_ip4 ? IP46_TYPE_IP4 : IP46_TYPE_IP6,
		clib_net_to_host_u16 (mp->lcl_port));
  em->listener_handle = mp->handle;
  em->state = STATE_LISTEN;
}

static void
session_accepted_handler (session_accepted_msg_t * mp)
{
  app_session_evt_t _app_evt, *app_evt = &_app_evt;
  session_accepted_reply_msg_t *rmp;
  svm_fifo_t *rx_fifo, *tx_fifo;
  echo_main_t *em = &echo_main;
  echo_session_t *session;
  u32 session_index;

  /* Allocate local session and set it up */
  pool_get (em->sessions, session);
  session_index = session - em->sessions;

  if (wait_for_segment_allocation (mp->segment_handle))
    return;

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

  /* Add it to lookup table */
  DBG ("Accepted session handle %lx, Listener %lx idx %lu", mp->handle,
       mp->listener_handle, session_index);
  hash_set (em->session_index_by_vpp_handles, mp->handle, session_index);

  app_alloc_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_ACCEPTED_REPLY);
  rmp = (session_accepted_reply_msg_t *) app_evt->evt->data;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  app_send_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt);

  DBG ("SSession handle is %lu", mp->handle);
  if (mp->listener_handle == em->listener_handle)
    {
      if (em->cb_vft.quic_accepted_cb)
	em->cb_vft.quic_accepted_cb (mp, session_index);
      em->n_quic_clients_connected++;
    }
  else if (em->i_am_master)
    {
      if (em->cb_vft.server_stream_accepted_cb)
	em->cb_vft.server_stream_accepted_cb (mp, session_index);
      em->n_clients_connected++;
    }
  else
    {
      if (em->cb_vft.client_stream_accepted_cb)
	em->cb_vft.client_stream_accepted_cb (mp, session_index);
      em->n_clients_connected++;
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
  echo_session_t *session;
  u32 session_index;
  svm_fifo_t *rx_fifo, *tx_fifo;

  if (mp->retval)
    {
      clib_warning ("connection failed with code: %U", format_api_error,
		    clib_net_to_host_u32 (mp->retval));
      em->state = STATE_FAILED;
      return;
    }

  pool_get (em->sessions, session);
  clib_memset (session, 0, sizeof (*session));
  session_index = session - em->sessions;
  DBG ("CONNECTED session[%lx][0x%lx]", session_index, mp->handle);

  if (wait_for_segment_allocation (mp->segment_handle))
    return;

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

  DBG ("Connected session handle %lx, idx %lu RX[%lx] TX[%lx]", mp->handle,
       session_index, rx_fifo, tx_fifo);
  hash_set (em->session_index_by_vpp_handles, mp->handle, session_index);

  if (mp->context == QUIC_SESSION_TYPE_QUIC)
    {
      if (em->cb_vft.quic_connected_cb)
	em->cb_vft.quic_connected_cb (mp, session_index);
      em->n_quic_clients_connected++;
    }
  else if (em->i_am_master)
    {
      if (em->cb_vft.server_stream_connected_cb)
	em->cb_vft.server_stream_connected_cb (mp, session_index);
      em->n_clients_connected++;
    }
  else
    {
      if (em->cb_vft.client_stream_connected_cb)
	em->cb_vft.client_stream_connected_cb (mp, session_index);
      em->n_clients_connected++;
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
  int i;

  if (!em->first_sconnect_sent)
    {
      em->first_sconnect_sent = 1;
      quic_echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
    }
  for (i = 0; i < em->n_stream_clients; i++)
    {
      DBG ("CONNECT : new QUIC stream #%d: %s", i, uri);
      echo_send_connect (em, uri, QUIC_SESSION_TYPE_STREAM);
    }

  clib_warning ("session %u (0x%llx) connected with local ip %U port %d",
		session_index, mp->handle, format_ip46_address, &mp->lcl.ip,
		mp->lcl.is_ip4, clib_net_to_host_u16 (mp->lcl.port));
}

static void
echo_on_connected_send (session_connected_msg_t * mp, u32 session_index)
{
  echo_main_t *em = &echo_main;
  int rv;
  echo_session_t *session;

  DBG ("Stream Session Connected");

  session = pool_elt_at_index (em->sessions, session_index);
  session->bytes_to_send = em->bytes_to_send;
  session->bytes_to_receive = em->bytes_to_receive;

  /*
   * Start RX thread
   */
  em->thread_args[em->n_clients_connected] = session_index;
  rv = pthread_create (&em->client_thread_handles[em->n_clients_connected],
		       NULL /*attr */ , client_thread_fn,
		       (void *) &em->thread_args[em->n_clients_connected]);
  if (rv)
    {
      clib_warning ("pthread_create returned %d", rv);
      return;
    }
}

static void
echo_on_connected_error (session_connected_msg_t * mp, u32 session_index)
{
  clib_warning ("Got a wrong connected on session %u [%lx]", session_index,
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

  DBG ("Stream session accepted 0x%lx, expecting %lu bytes",
       session->vpp_session_handle, session->bytes_to_receive);

  /*
   * Start RX thread
   */
  em->thread_args[em->n_clients_connected] = session_index;
  rv = pthread_create (&em->client_thread_handles[em->n_clients_connected],
		       NULL /*attr */ , client_thread_fn,
		       (void *) &em->thread_args[em->n_clients_connected]);
  if (rv)
    {
      clib_warning ("pthread_create returned %d", rv);
      return;
    }

}

static void
echo_on_accept_connect (session_accepted_msg_t * mp, u32 session_index)
{
  echo_main_t *em = &echo_main;
  DBG ("Accept on QSession index %u", mp->handle);
  u8 *uri = format (0, "QUIC://session/%lu", mp->handle);
  u32 i;

  if (!em->first_sconnect_sent)
    {
      em->first_sconnect_sent = 1;
      quic_echo_notify_event (em, ECHO_EVT_FIRST_SCONNECT);
    }
  for (i = 0; i < em->n_stream_clients; i++)
    {
      DBG ("ACCEPT : new QUIC stream #%d: %s", i, uri);
      echo_send_connect (em, uri, QUIC_SESSION_TYPE_STREAM);
    }
}

static void
echo_on_accept_error (session_accepted_msg_t * mp, u32 session_index)
{
  clib_warning ("Got a wrong accept on session %u [%lx]", session_index,
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
  .quic_accepted_cb = &echo_on_accept_log_ip,
  .quic_connected_cb = &echo_on_connected_connect,
  /* client initiated streams */
  .server_stream_accepted_cb = NULL,
  .client_stream_connected_cb = &echo_on_connected_send,
  /* server initiated streams */
  .client_stream_accepted_cb = &echo_on_accept_error,
  .server_stream_connected_cb = &echo_on_connected_error,
};

static const quic_echo_cb_vft_t server_stream_cb_vft = {
  /* Qsessions */
  .quic_accepted_cb = &echo_on_accept_connect,
  .quic_connected_cb = NULL,
  /* client initiated streams */
  .server_stream_accepted_cb = &echo_on_accept_error,
  .client_stream_connected_cb = &echo_on_connected_error,
  /* server initiated streams */
  .client_stream_accepted_cb = &echo_on_accept_recv,
  .server_stream_connected_cb = &echo_on_connected_send,
};

static uword
echo_unformat_quic_setup_vft (unformat_input_t * input, va_list * args)
{
  echo_main_t *em = &echo_main;
  if (unformat (input, "serverstream"))
    {
      clib_warning ("Using QUIC server initiated streams");
      em->no_return = 1;
      em->cb_vft = server_stream_cb_vft;
      return 1;
    }
  else if (unformat (input, "default"))
    return 1;
  return 0;
}

static uword
echo_unformat_data (unformat_input_t * input, va_list * args)
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
  echo_session_t *session = 0;
  uword *p;
  int rv = 0;
  DBG ("Disonnected session handle %lx", mp->handle);
  p = hash_get (em->session_index_by_vpp_handles, mp->handle);
  if (!p)
    {
      clib_warning ("couldn't find session key %llx", mp->handle);
      return;
    }

  session = pool_elt_at_index (em->sessions, p[0]);
  hash_unset (em->session_index_by_vpp_handles, mp->handle);

  pool_put (em->sessions, session);

  app_alloc_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_DISCONNECTED_REPLY);
  rmp = (session_disconnected_reply_msg_t *) app_evt->evt->data;
  rmp->retval = rv;
  rmp->handle = mp->handle;
  rmp->context = mp->context;
  app_send_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt);

  session_print_stats (em, session);
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

  DBG ("Reset session handle %lx", mp->handle);
  p = hash_get (em->session_index_by_vpp_handles, mp->handle);

  if (p)
    {
      session = pool_elt_at_index (em->sessions, p[0]);
      clib_warning ("got reset");
      /* Cleanup later */
      em->time_to_stop = 1;
    }
  else
    {
      clib_warning ("couldn't find session key %llx", mp->handle);
      return;
    }

  app_alloc_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt,
			     SESSION_CTRL_EVT_RESET_REPLY);
  rmp = (session_reset_reply_msg_t *) app_evt->evt->data;
  rmp->retval = rv;
  rmp->handle = mp->handle;
  app_send_ctrl_evt_to_vpp (session->vpp_evt_q, app_evt);
}

static void
handle_mq_event (echo_main_t * em, session_event_t * e, int handle_rx)
{
  switch (e->event_type)
    {
    case SESSION_CTRL_EVT_BOUND:
      DBG ("SESSION_CTRL_EVT_BOUND");
      session_bound_handler ((session_bound_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_ACCEPTED:
      DBG ("SESSION_CTRL_EVT_ACCEPTED");
      session_accepted_handler ((session_accepted_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_CONNECTED:
      DBG ("SESSION_CTRL_EVT_CONNECTED");
      session_connected_handler ((session_connected_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_DISCONNECTED:
      DBG ("SESSION_CTRL_EVT_DISCONNECTED");
      session_disconnected_handler ((session_disconnected_msg_t *) e->data);
      break;
    case SESSION_CTRL_EVT_RESET:
      DBG ("SESSION_CTRL_EVT_RESET");
      session_reset_handler ((session_reset_msg_t *) e->data);
      break;
    case SESSION_IO_EVT_RX:
      DBG ("SESSION_IO_EVT_RX");
      if (handle_rx)
	echo_handle_rx (em, e);
      break;
    default:
      clib_warning ("unhandled event %u", e->event_type);
    }
}

static int
clients_run (echo_main_t * em)
{
  svm_msg_q_msg_t msg;
  session_event_t *e;
  echo_session_t *s;
  hash_pair_t *p;
  int i;

  /*
   * Attach and connect the clients
   */
  if (application_attach (em))
    return -1;

  quic_echo_notify_event (em, ECHO_EVT_FIRST_QCONNECT);
  for (i = 0; i < em->n_clients; i++)
    echo_send_connect (em, em->uri, QUIC_SESSION_TYPE_QUIC);

  wait_for_state_change (em, STATE_READY, TIMEOUT);

  /*
   * Wait for client threads to send the data
   */
  DBG ("Waiting for data on %u clients", em->n_clients_connected);
  while (em->n_clients_connected)
    {
      if (svm_msg_q_is_empty (em->our_event_queue))
	continue;
      if (svm_msg_q_sub (em->our_event_queue, &msg, SVM_Q_TIMEDWAIT, 1))
	continue;
      e = svm_msg_q_msg_data (em->our_event_queue, &msg);
      handle_mq_event (em, e, 0 /* handle_rx */ );
      svm_msg_q_free_msg (em->our_event_queue, &msg);
    }

  /* *INDENT-OFF* */
  hash_foreach_pair (p, em->session_index_by_vpp_handles,
    ({
      s = pool_elt_at_index (em->sessions, p->value[0]);
      DBG ("Sending disconnect on session %lu", p->key);
      client_disconnect_session (em, s);
    }));
  /* *INDENT-ON* */

  wait_for_disconnected_sessions (em);
  application_detach (em);
  return 0;
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

  em->state = STATE_LISTEN;
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
echo_handle_rx (echo_main_t * em, session_event_t * e)
{
  int n_read, max_dequeue, n_sent;
  u32 offset, to_dequeue;
  echo_session_t *s;
  s = pool_elt_at_index (em->sessions, e->session_index);

  /* Clear event only once. Otherwise, if we do it in the loop by calling
   * app_recv_stream, we may end up with a lot of unhandled rx events on the
   * message queue */
  svm_fifo_unset_event (s->rx_fifo);
  max_dequeue = svm_fifo_max_dequeue (s->rx_fifo);
  if (PREDICT_FALSE (!max_dequeue))
    return;
  do
    {
      /* The options here are to limit ourselves to max_dequeue or read
       * even the data that was enqueued while we were dequeueing and which
       * now has an rx event in the mq. Either of the two work. */
      to_dequeue = clib_min (max_dequeue, vec_len (em->rx_buf));
      n_read = app_recv_stream_raw (s->rx_fifo, em->rx_buf, to_dequeue,
				    0 /* clear evt */ , 0 /* peek */ );

      if (n_read <= 0)
	break;
      DBG ("Notify cause %u bytes", n_read);
      notify_rx_data_to_vpp (s);
      if (em->test_return_packets)
	test_recv_bytes (em, s, em->rx_buf, n_read);

      max_dequeue -= n_read;
      s->bytes_received += n_read;
      s->bytes_to_receive -= n_read;

      /* Reflect if a non-drop session */
      if (!em->no_return)
	{
	  offset = 0;
	  do
	    {
	      n_sent = app_send_stream ((app_session_t *) s,
					em->rx_buf + offset,
					n_read, SVM_Q_WAIT);
	      if (n_sent <= 0)
		continue;
	      n_read -= n_sent;
	      s->bytes_to_send -= n_sent;
	      s->bytes_sent += n_sent;
	      offset += n_sent;
	    }
	  while (n_read > 0);
	}
    }
  while (max_dequeue > 0 && !em->time_to_stop);
}

static void
server_handle_mq (echo_main_t * em)
{
  svm_msg_q_msg_t msg;
  session_event_t *e;

  while (1)
    {
      int rc = svm_msg_q_sub (em->our_event_queue, &msg, SVM_Q_TIMEDWAIT, 1);
      if (PREDICT_FALSE (rc == ETIMEDOUT && em->time_to_stop))
	break;
      if (rc == ETIMEDOUT)
	continue;
      e = svm_msg_q_msg_data (em->our_event_queue, &msg);
      handle_mq_event (em, e, em->state == STATE_READY /* handle_rx */ );
      svm_msg_q_free_msg (em->our_event_queue, &msg);
    }
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

static int
server_run (echo_main_t * em)
{
  echo_session_t *session;
  int i;

  /* $$$$ hack preallocation */
  for (i = 0; i < 200000; i++)
    {
      pool_get (em->sessions, session);
      clib_memset (session, 0, sizeof (*session));
    }
  for (i = 0; i < 200000; i++)
    pool_put_index (em->sessions, i);

  if (application_attach (em))
    return -1;

  /* Bind to uri */
  server_send_listen (em);
  if (wait_for_state_change (em, STATE_READY, 0))
    return -2;

  /* Enter handle event loop */
  server_handle_mq (em);

  /* Cleanup */
  server_send_unbind (em);
  application_detach (em);
  fformat (stdout, "Test complete...\n");
  return 0;
}

static void
vl_api_disconnect_session_reply_t_handler (vl_api_disconnect_session_reply_t *
					   mp)
{
  echo_main_t *em = &echo_main;
  uword *p;
  DBG ("Got disonnected reply for session handle %lu", mp->handle);
  em->state = STATE_START;

  p = hash_get (em->session_index_by_vpp_handles, mp->handle);
  if (p)
    hash_unset (em->session_index_by_vpp_handles, mp->handle);
  else
    clib_warning ("couldn't find session key %llx", mp->handle);

  if (mp->retval)
    clib_warning ("vpp complained about disconnect: %d", ntohl (mp->retval));
}

static void
  vl_api_application_tls_cert_add_reply_t_handler
  (vl_api_application_tls_cert_add_reply_t * mp)
{
  if (mp->retval)
    clib_warning ("failed to add tls cert");
}

static void
  vl_api_application_tls_key_add_reply_t_handler
  (vl_api_application_tls_key_add_reply_t * mp)
{
  if (mp->retval)
    clib_warning ("failed to add tls key");
}

#define foreach_quic_echo_msg                            		\
_(BIND_URI_REPLY, bind_uri_reply)                       		\
_(UNBIND_URI_REPLY, unbind_uri_reply)                   		\
_(DISCONNECT_SESSION_REPLY, disconnect_session_reply)   		\
_(APPLICATION_ATTACH_REPLY, application_attach_reply)   		\
_(APPLICATION_DETACH_REPLY, application_detach_reply)			\
_(MAP_ANOTHER_SEGMENT, map_another_segment)				\
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
	   "  appns NAMESPACE     Use the namespace NAMESPACE\n"
	   "  all-scope           all-scope option\n"
	   "  local-scope         local-scope option\n"
	   "  global-scope        global-scope option\n"
	   "  secret SECRET       set namespace secret\n"
	   "  chroot prefix PATH  Use PATH as memory root path\n"
	   "  quic-setup OPT      OPT=serverstream : Client open N connections. On each one server opens M streams\n"
	   "                            by default : Client open N connections. On each one client opens M streams\n"
	   "\n"
	   "  no-return            Drop the data when received, dont reply\n"
	   "  nclients N[/M]       Open N QUIC connections, each one with M streams (M defaults to 1)\n"
	   "  send N[Kb|Mb|GB]     Send N [K|M|G]bytes\n"
	   "  recv N[Kb|Mb|GB]     Expect N [K|M|G]bytes\n"
	   "  nclients N[/M]       Open N QUIC connections, each one with M streams (M defaults to 1)\n");
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
      else if (unformat (a, "no-return"))
	em->no_return = 1;
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
      else
	if (unformat (a, "send %U", echo_unformat_data, &em->bytes_to_send))
	;
      else
	if (unformat
	    (a, "recv %U", echo_unformat_data, &em->bytes_to_receive))
	;
      else if (unformat (a, "time %U:%U",
			 echo_unformat_timing_event, &em->timing_start_event,
			 echo_unformat_timing_event, &em->timing_end_event))
	;
      else
	print_usage_and_exit ();
    }
}

int
main (int argc, char **argv)
{
  echo_main_t *em = &echo_main;
  fifo_segment_main_t *sm = &em->segment_main;
  char *app_name;
  int i, rv;
  u32 n_clients;

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
  em->bytes_to_receive = 64 << 10;
  em->bytes_to_send = 64 << 10;
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
  vec_validate (em->rx_buf, 4 << 20);
  vec_validate (em->connect_test_data, 1024 * 1024 - 1);
  for (i = 0; i < vec_len (em->connect_test_data); i++)
    em->connect_test_data[i] = i & 0xff;

  setup_signal_handlers ();
  quic_echo_api_hookup (em);

  app_name = em->i_am_master ? "quic_echo_server" : "quic_echo_client";
  if (connect_to_vpp (app_name) < 0)
    {
      svm_region_exit ();
      fformat (stderr, "Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  quic_echo_notify_event (em, ECHO_EVT_START);
  if (em->i_am_master)
    rv = server_run (em);
  else
    rv = clients_run (em);
  if (rv)
    exit (rv);
  quic_echo_notify_event (em, ECHO_EVT_EXIT);
  print_global_stats (em);

  /* Make sure detach finishes */
  if (wait_for_state_change (em, STATE_DETACHED, TIMEOUT))
    exit (-1);
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
