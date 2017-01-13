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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <svm/svm_fifo_segment.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>

#include <vnet/uri/uri.h>

#define vl_typedefs             /* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun            /* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

/* Satisfy external references when not linking with -lvlib */
vlib_main_t vlib_global_main;
vlib_main_t **vlib_mains;

typedef struct
{
  svm_fifo_t * server_rx_fifo;
  svm_fifo_t * server_tx_fifo;
} session_t;

typedef enum
{
  STATE_START,
  STATE_READY,
  STATE_DISCONNECTING,
} connection_state_t;

typedef struct
{
  /* vpe input queue */
  unix_shared_memory_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  /* The URI we're playing with */
  u8 * uri;

  /* Session pool */
  session_t * sessions;

  /* Hash table for disconnect processing */
  uword * session_index_by_vpp_handles;

  /* intermediate rx buffer */
  u8 * rx_buf;

  /* URI for slave's connect */
  u8 * connect_uri;

  u32 connected_session_index;

  int i_am_master;

  /* drop all packets */
  int drop_packets;

  /* Our event queue */
  unix_shared_memory_queue_t * our_event_queue;

  /* $$$ single thread only for the moment */
  unix_shared_memory_queue_t * vpp_event_queue;

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
  uword * error_string_by_error_number;

  /* convenience */
  svm_fifo_segment_main_t * segment_main;

} uri_tcp_test_main_t;

uri_tcp_test_main_t uri_tcp_test_main;

#if CLIB_DEBUG > 0
#define NITER 10000
#else
#define NITER 4000000
#endif

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
    }
  return -1;
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
vl_api_map_another_segment_t_handler (vl_api_map_another_segment_t *mp)
{
  svm_fifo_segment_create_args_t _a, *a = &_a;
  int rv;

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
vl_api_disconnect_session_t_handler (vl_api_disconnect_session_t * mp)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  session_t * session;
  vl_api_disconnect_session_reply_t * rmp;
  uword * p;
  int rv = 0;
  u64 key;

  key = (((u64)mp->session_thread_index) << 32) | (u64)mp->session_index;

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
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *)&rmp);
}

static void
uri_tcp_client_test (uri_tcp_test_main_t * utm)
{
  vl_api_connect_uri_t * cmp;
  int i;
  u8 * test_data = 0;
  u64 bytes_received = 0, bytes_sent = 0;
  i32 bytes_to_read;
  int rv;
  int mypid = getpid();
  f64 before, after, delta, bytes_per_second;
  session_t * session;
  svm_fifo_t * rx_fifo, * tx_fifo;
  int buffer_offset, bytes_to_send = 0;

  vec_validate (test_data, 64 * 1024 - 1);
  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i & 0xff;

  cmp = vl_msg_api_alloc (sizeof (*cmp));
  memset (cmp, 0, sizeof (*cmp));

  cmp->_vl_msg_id = ntohs (VL_API_CONNECT_URI);
  cmp->client_index = utm->my_client_index;
  cmp->context = ntohl(0xfeedface);
  memcpy (cmp->uri, utm->connect_uri, vec_len (utm->connect_uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *)&cmp);

  if (wait_for_state_change (utm, STATE_READY))
    {
      clib_warning ("timeout waiting for STATE_READY");
      return;
    }

  session = pool_elt_at_index (utm->sessions, utm->connected_session_index);
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
          rv = svm_fifo_enqueue_nowait2 (tx_fifo, mypid,
                                         bytes_to_send,
                                         test_data + buffer_offset);

          if (rv > 0)
            {
              bytes_to_send -= rv;
              buffer_offset += rv;
              bytes_sent += rv;
            }
        }

      bytes_to_read = svm_fifo_max_dequeue (rx_fifo);

      bytes_to_read = vec_len(utm->rx_buf) > bytes_to_read ?
        bytes_to_read : vec_len(utm->rx_buf);

      buffer_offset = 0;
      while (bytes_to_read > 0)
        {
          rv = svm_fifo_dequeue_nowait2 (rx_fifo, mypid,
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
      rv = svm_fifo_dequeue_nowait2 (rx_fifo, mypid,
                                     vec_len (utm->rx_buf),
                                     utm->rx_buf);
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
                                ((bytes_received + j )&0xff));
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

  fformat (stdout, "Done: %lld recv bytes in %.2f seconds, %.2f bytes/sec...\n\n",
           bytes_received, delta, bytes_per_second);
  fformat (stdout, "Done: %lld sent bytes in %.2f seconds, %.2f bytes/sec...\n\n",
           bytes_sent, delta, bytes_per_second);
  fformat (stdout, "client -> server -> client round trip: %.2f Gbit/sec \n\n",
           (bytes_per_second*8.0)/1e9);
}

void
handle_fifo_event_server_rx (uri_tcp_test_main_t *utm, fifo_event_t * e)
{
  svm_fifo_t * rx_fifo, * tx_fifo;
  int n_read;

  fifo_event_t evt;
  unix_shared_memory_queue_t *q;
  int rv, bytes;

  rx_fifo = e->fifo;
  tx_fifo = utm->sessions[rx_fifo->client_session_index].server_tx_fifo;

  bytes = e->enqueue_length;
  do
    {
      n_read = svm_fifo_dequeue_nowait2 (rx_fifo, 0, vec_len(utm->rx_buf),
                                         utm->rx_buf);

      /* Reflect if a non-drop session */
      if (!utm->drop_packets && n_read > 0)
        {
          do
            {
              rv = svm_fifo_enqueue_nowait2 (tx_fifo, 0, n_read, utm->rx_buf);
            }
          while (rv == -2);

          /* Fabricate TX event, send to vpp */
          evt.fifo = tx_fifo;
          evt.event_type = FIFO_EVENT_SERVER_TX;
          /* $$$$ for event logging */
          evt.enqueue_length = n_read;
          evt.event_id = e->event_id;
          q = utm->vpp_event_queue;
          unix_shared_memory_queue_add (q, (u8 *) &evt, 0 /* do wait for mutex */);
        }

      if (n_read > 0)
        bytes -= n_read;
    }
  while (n_read < 0 || bytes > 0);
}

void
handle_event_queue (uri_tcp_test_main_t * utm)
{
  fifo_event_t _e, *e = &_e;;

  while (1)
    {
      unix_shared_memory_queue_sub (utm->our_event_queue, (u8 *)e,
                                    0 /* nowait */);
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
      if (PREDICT_FALSE(utm->time_to_stop == 1))
        break;
      if (PREDICT_FALSE(utm->time_to_print_stats == 1))
        {
          utm->time_to_print_stats = 0;
          fformat(stdout, "%d connections\n", pool_elts (utm->sessions));
        }
    }
}

static void
vl_api_bind_uri_reply_t_handler (vl_api_bind_uri_reply_t * mp)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  svm_fifo_segment_create_args_t _a, *a = &_a;
  int rv;

  if (mp->segment_name_length == 0)
    {
      clib_warning ("segment_name_length zero");
      return;
    }

  a->segment_name = (char *) mp->segment_name;
  a->segment_size = mp->segment_size;

  ASSERT(mp->server_event_queue_address);

  /* Attach to the segment vpp created */
  rv = svm_fifo_segment_attach (a);
  if (rv)
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed",
                    mp->segment_name);
      return;
    }

  utm->our_event_queue = (unix_shared_memory_queue_t *)
    mp->server_event_queue_address;

  utm->state = STATE_READY;
}

static void
vl_api_connect_uri_reply_t_handler (vl_api_connect_uri_reply_t * mp)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  svm_fifo_segment_create_args_t _a, *a = &_a;
  session_t * session;
  u32 session_index;
  svm_fifo_t *rx_fifo, *tx_fifo;
  int rv;

  /*
   * Attatch to segment
   */

  if (mp->segment_name_length == 0)
    {
      clib_warning ("segment_name_length zero");
      return;
    }

  a->segment_name = (char *) mp->segment_name;
  a->segment_size = mp->segment_size;

  ASSERT(mp->client_event_queue_address);

  /* Attach to the segment vpp created */
  rv = svm_fifo_segment_attach (a);
  if (rv)
    {
      clib_warning ("svm_fifo_segment_attach ('%s') failed",
                    mp->segment_name);
      return;
    }

  /*
   * Save the queues
   */

  utm->our_event_queue = (unix_shared_memory_queue_t *)
    mp->client_event_queue_address;

  utm->vpp_event_queue = (unix_shared_memory_queue_t *)
    mp->vpp_event_queue_address;

  /*
   * Setup session
   */

  pool_get (utm->sessions, session);
  session_index = session - utm->sessions;

  rx_fifo = (svm_fifo_t *)mp->server_rx_fifo;
  rx_fifo->client_session_index = session_index;
  tx_fifo = (svm_fifo_t *)mp->server_tx_fifo;
  tx_fifo->client_session_index = session_index;

  session->server_rx_fifo = rx_fifo;
  session->server_tx_fifo = tx_fifo;

  /* Save handle */
  utm->connected_session_index = session_index;

  utm->state = STATE_READY;
}

void
uri_tcp_bind (uri_tcp_test_main_t *utm)
{
  vl_api_bind_uri_t * bmp;
  u32 fifo_size = 3 << 20;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_BIND_URI);
  bmp->client_index = utm->my_client_index;
  bmp->context = ntohl(0xfeedface);
  bmp->initial_segment_size = 256<<20;    /* size of initial segment */
  bmp->options[URI_OPTIONS_FLAGS] =
    URI_OPTIONS_FLAGS_USE_FIFO | URI_OPTIONS_FLAGS_ADD_SEGMENT;
  bmp->options[URI_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  bmp->options[URI_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  bmp->options[URI_OPTIONS_ADD_SEGMENT_SIZE] = 128<<20;
  memcpy (bmp->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *)&bmp);
}

static void
vl_api_unbind_uri_reply_t_handler (vl_api_unbind_uri_reply_t *mp)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;

  if (mp->retval != 0)
    clib_warning ("returned %d", ntohl(mp->retval));

  utm->state = STATE_START;
}

void
uri_tcp_unbind (uri_tcp_test_main_t *utm)
{
  vl_api_unbind_uri_t * ump;

  ump = vl_msg_api_alloc (sizeof (*ump));
  memset (ump, 0, sizeof (*ump));

  ump->_vl_msg_id = ntohs (VL_API_UNBIND_URI);
  ump->client_index = utm->my_client_index;
  memcpy (ump->uri, utm->uri, vec_len (utm->uri));
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *)&ump);
}

static void
vl_api_accept_session_t_handler (vl_api_accept_session_t * mp)
{
  uri_tcp_test_main_t *utm = &uri_tcp_test_main;
  vl_api_accept_session_reply_t *rmp;
  svm_fifo_t * rx_fifo, * tx_fifo;
  session_t * session;
  static f64 start_time;
  u64 key;
  u32 session_index;

  if (start_time == 0.0)
      start_time = clib_time_now (&utm->clib_time);

  utm->vpp_event_queue = (unix_shared_memory_queue_t *)
    mp->vpp_event_queue_address;

  /* Allocate local session and set it up */
  pool_get (utm->sessions, session);
  session_index = session - utm->sessions;

  rx_fifo = (svm_fifo_t *)mp->server_rx_fifo;
  rx_fifo->client_session_index = session_index;
  tx_fifo = (svm_fifo_t *)mp->server_tx_fifo;
  tx_fifo->client_session_index = session_index;

  session->server_rx_fifo = rx_fifo;
  session->server_tx_fifo = tx_fifo;

  /* Add it to lookup table */
  key = (((u64)mp->session_thread_index) << 32) | (u64)mp->session_index;
  hash_set (utm->session_index_by_vpp_handles, key, session_index);

  utm->state = STATE_READY;

  /* Stats printing */
  if (pool_elts (utm->sessions) && (pool_elts(utm->sessions) % 20000) == 0)
    {
      f64 now = clib_time_now (&utm->clib_time);
      fformat (stdout, "%d active sessions in %.2f seconds, %.2f/sec...\n",
               pool_elts(utm->sessions), now - start_time,
               (f64)pool_elts(utm->sessions) / (now - start_time));
    }

  /* Send accept reply to vpp */
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_ACCEPT_SESSION_REPLY);
  rmp->session_type = mp->session_type;
  rmp->session_index = mp->session_index;
  rmp->session_thread_index = mp->session_thread_index;
  vl_msg_api_send_shmem (utm->vl_input_queue, (u8 *)&rmp);
}

void
uri_tcp_server_test (uri_tcp_test_main_t * utm)
{

  /* Bind to uri */
  uri_tcp_bind (utm);

  if (wait_for_state_change (utm, STATE_READY))
    {
      clib_warning ("timeout waiting for STATE_READY");
      return;
    }

  /* Enter handle event loop */
  handle_event_queue (utm);

  /* Cleanup */
  uri_tcp_unbind (utm);

  if (wait_for_state_change (utm, STATE_START))
    {
      clib_warning ("timeout waiting for STATE_START");
      return;
    }

  fformat (stdout, "Test complete...\n");
}

#define foreach_uri_msg                         \
_(BIND_URI_REPLY, bind_uri_reply)               \
_(UNBIND_URI_REPLY, unbind_uri_reply)           \
_(ACCEPT_SESSION, accept_session)               \
_(CONNECT_URI_REPLY, connect_uri_reply)         \
_(DISCONNECT_SESSION, disconnect_session)       \
_(MAP_ANOTHER_SEGMENT, map_another_segment)

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
  u8 *heap;
  u8 * bind_name = (u8 *) "tcp://0.0.0.0/1234";
  u32 tmp;
  mheap_t *h;
  session_t * session;
  int i;
  int i_am_master = 1, drop_packets = 0;

  clib_mem_init (0, 256 << 20);

  heap = clib_mem_get_per_cpu_heap ();
  h = mheap_header (heap);

  /* make the main heap thread-safe */
  h->flags |= MHEAP_FLAG_THREAD_SAFE;

  vec_validate (utm->rx_buf, 65536);

  utm->session_index_by_vpp_handles =
    hash_create (0, sizeof(uword));

  utm->my_pid = getpid();
  utm->configured_segment_size = 1<<20;

  clib_time_init (&utm->clib_time);
  init_error_string_table (utm);
  svm_fifo_segment_init(0x200000000ULL, 20);
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
        utm->configured_segment_size = tmp<<20;
      else if (unformat (a, "segment-size %dG", &tmp))
        utm->configured_segment_size = tmp<<30;
      else if (unformat (a, "master"))
        i_am_master = 1;
      else if (unformat (a, "slave"))
        i_am_master = 0;
      else if (unformat (a, "drop"))
        drop_packets = 1;
      else
        {
          fformat (stderr, "%s: usage [master|slave]\n");
          exit (1);
        }
    }

  utm->uri = format (0, "%s%c", bind_name, 0);
  utm->i_am_master = i_am_master;
  utm->segment_main = &svm_fifo_segment_main;
  utm->drop_packets = drop_packets;

  utm->connect_uri = format (0, "tcp://6.0.1.2/1234%c", 0);

  setup_signal_handlers();
  uri_api_hookup (utm);

  if (connect_to_vpp (i_am_master? "uri_tcp_server":"uri_tcp_client") < 0)
    {
      svm_region_exit ();
      fformat (stderr, "Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  if (i_am_master == 0)
    {
      uri_tcp_client_test (utm);
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

  uri_tcp_server_test (utm);

  vl_client_disconnect_from_vlib ();
  exit (0);
}
