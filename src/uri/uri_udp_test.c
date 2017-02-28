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
#include <vpp-api/vpe_msg_enum.h>
#include <svm_fifo_segment.h>

#include <vnet/uri/uri.h>

#define vl_typedefs		/* define message structures */
#include <vpp-api/vpe_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <vpp-api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp-api/vpe_all_api_h.h>
#undef vl_printfun

/* Satisfy external references when not linking with -lvlib */
vlib_main_t vlib_global_main;
vlib_main_t **vlib_mains;

typedef enum
{
  STATE_START,
  STATE_READY,
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

  /* Our event queue */
  unix_shared_memory_queue_t *our_event_queue;

  /* $$$ single thread only for the moment */
  unix_shared_memory_queue_t *vpp_event_queue;

  /* For deadman timers */
  clib_time_t clib_time;

  /* State of the connection, shared between msg RX thread and main thread */
  volatile connection_state_t state;

  volatile int time_to_stop;
  volatile int time_to_print_stats;

  /* VNET_API_ERROR_FOO -> "Foo" hash table */
  uword *error_string_by_error_number;
} uri_udp_test_main_t;

#if CLIB_DEBUG > 0
#define NITER 1000
#else
#define NITER 1000000
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
  f64 timeout = clib_time_now (&utm->clib_time) + 5.0;

  while (clib_time_now (&utm->clib_time) < timeout)
    {
      if (utm->state == state)
	return 0;
    }
  return -1;
}

static void
vl_api_bind_uri_reply_t_handler (vl_api_bind_uri_reply_t * mp)
{
  uri_udp_test_main_t *utm = &uri_udp_test_main;
  svm_fifo_segment_create_args_t _a, *a = &_a;
  int rv;

  if (mp->segment_name_length == 0)
    {
      clib_warning ("segment_name_length zero");
      return;
    }

  a->segment_name = (char *) mp->segment_name;

  /* Attach to the segment vpp created */
  rv = svm_fifo_segment_attach (a);
  if (rv)
    {
      clib_warning ("sm_fifo_segment_create ('%s') failed", mp->segment_name);
      return;
    }

  utm->our_event_queue = (unix_shared_memory_queue_t *)
    mp->server_event_queue_address;

  utm->state = STATE_READY;
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
  u64 key;

  if (start_time == 0.0)
    start_time = clib_time_now (&utm->clib_time);

  utm->vpp_event_queue = (unix_shared_memory_queue_t *)
    mp->vpp_event_queue_address;

  pool_get (utm->sessions, session);

  rx_fifo = (svm_fifo_t *) mp->server_rx_fifo;
  rx_fifo->client_session_index = session - utm->sessions;
  tx_fifo = (svm_fifo_t *) mp->server_tx_fifo;
  tx_fifo->client_session_index = session - utm->sessions;

  session->server_rx_fifo = rx_fifo;
  session->server_tx_fifo = tx_fifo;

  key = (((u64) mp->session_thread_index) << 32) | (u64) mp->session_index;

  hash_set (utm->session_index_by_vpp_handles, key, session - utm->sessions);

  utm->state = STATE_READY;

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
  rmp->session_type = mp->session_type;
  rmp->session_index = mp->session_index;
  rmp->session_thread_index = mp->session_thread_index;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & rmp);
}

static void
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  uri_udp_test_main_t *utm = &uri_udp_test_main;
  session_t *session;
  vl_api_disconnect_session_reply_t *rmp;
  uword *p;
  int rv = 0;
  u64 key;

  key = (((u64) mp->session_thread_index) << 32) | (u64) mp->session_index;

  p = hash_get (utm->session_index_by_vpp_handles, key);

  if (p)
    {
      session = pool_elt_at_index (utm->sessions, p[0]);
      hash_unset (utm->session_index_by_vpp_handles, key);
      pool_put (utm->sessions, session);
    }
  else
    {
      clib_warning ("couldn't find session key %llx", key);
      rv = -11;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_DISCONNECT_SESSION_REPLY);
  rmp->retval = rv;
  rmp->session_index = mp->session_index;
  rmp->session_thread_index = mp->session_thread_index;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & rmp);
}

#define foreach_uri_msg                         \
_(BIND_URI_REPLY, bind_uri_reply)               \
_(UNBIND_URI_REPLY, unbind_uri_reply)           \
_(ACCEPT_SESSION, accept_session)		\
_(DISCONNECT_SESSION, disconnect_session)

void
uri_api_hookup (uri_udp_test_main_t * utm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,	        \
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
handle_fifo_event_server_rx (uri_udp_test_main_t * utm,
			     session_fifo_event_t * e)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  int nbytes;

  session_fifo_event_t evt;
  unix_shared_memory_queue_t *q;
  int rv;

  rx_fifo = e->fifo;
  tx_fifo = utm->sessions[rx_fifo->client_session_index].server_tx_fifo;

  do
    {
      nbytes = svm_fifo_dequeue_nowait (rx_fifo, 0,
					vec_len (utm->rx_buf), utm->rx_buf);
    }
  while (nbytes <= 0);
  do
    {
      rv = svm_fifo_enqueue_nowait (tx_fifo, 0, nbytes, utm->rx_buf);
    }
  while (rv == -2);

  /* Fabricate TX event, send to vpp */
  evt.fifo = tx_fifo;
  evt.event_type = FIFO_EVENT_SERVER_TX;
  /* $$$$ for event logging */
  evt.enqueue_length = nbytes;
  evt.event_id = e->event_id;
  q = utm->vpp_event_queue;
  unix_shared_memory_queue_add (q, (u8 *) & evt, 0 /* do wait for mutex */ );
}

void
handle_event_queue (uri_udp_test_main_t * utm)
{
  session_fifo_event_t _e, *e = &_e;;

  while (1)
    {
      unix_shared_memory_queue_sub (utm->our_event_queue, (u8 *) e,
				    0 /* nowait */ );
      switch (e->event_type)
	{
	case FIFO_EVENT_SERVER_RX:
	  handle_fifo_event_server_rx (utm, e);
	  break;

	case FIFO_EVENT_SERVER_EXIT:
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
uri_udp_test (uri_udp_test_main_t * utm)
{
  vl_api_bind_uri_t *bmp;
  vl_api_unbind_uri_t *ump;

  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_BIND_URI);
  bmp->client_index = utm->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->segment_size = 2 << 30;
  memcpy (bmp->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & bmp);

  if (wait_for_state_change (utm, STATE_READY))
    {
      clib_warning ("timeout waiting for STATE_READY");
      return;
    }

  handle_event_queue (utm);

  ump = vl_msg_api_alloc (sizeof (*ump));
  memset (ump, 0, sizeof (*ump));

  ump->_vl_msg_id = ntohs (VL_API_UNBIND_URI);
  ump->client_index = utm->my_client_index;
  memcpy (ump->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *) & ump);

  if (wait_for_state_change (utm, STATE_START))
    {
      clib_warning ("timeout waiting for STATE_START");
      return;
    }

  fformat (stdout, "Test complete...\n");
}

int
main (int argc, char **argv)
{
  uri_udp_test_main_t *utm = &uri_udp_test_main;
  unformat_input_t _argv, *a = &_argv;
  u8 *chroot_prefix;
  u8 *heap;
  u8 *bind_name = (u8 *) "udp4:1234";
  mheap_t *h;
  session_t *session;
  int i;

  clib_mem_init (0, 256 << 20);

  heap = clib_mem_get_per_cpu_heap ();
  h = mheap_header (heap);

  /* make the main heap thread-safe */
  h->flags |= MHEAP_FLAG_THREAD_SAFE;

  vec_validate (utm->rx_buf, 8192);

  utm->session_index_by_vpp_handles = hash_create (0, sizeof (uword));

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
      else
	{
	  fformat (stderr, "%s: usage [master|slave]\n");
	  exit (1);
	}
    }

  utm->uri = format (0, "%s%c", bind_name, 0);

  setup_signal_handlers ();

  uri_api_hookup (utm);

  if (connect_to_vpp ("uri_udp_test") < 0)
    {
      svm_region_exit ();
      fformat (stderr, "Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  /* $$$$ hack preallocation */
  for (i = 0; i < 200000; i++)
    {
      pool_get (utm->sessions, session);
      memset (session, 0, sizeof (*session));
    }
  for (i = 0; i < 200000; i++)
    pool_put_index (utm->sessions, i);

  uri_udp_test (utm);

  vl_client_disconnect_from_vlib ();
  exit (0);
}

#undef vl_api_version
#define vl_api_version(n,v) static u32 vpe_api_version = v;
#include <vpp-api/vpe.api.h>
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
