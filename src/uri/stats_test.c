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

  /* Counter for number of stats we have */
  u8 counter_epochs;

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
send_want_stats (uri_udp_test_main_t * utm)
{
  vl_api_want_stats_t *bmp;
  bmp = vl_msg_api_alloc (sizeof (*bmp));
  memset (bmp, 0, sizeof (*bmp));

  bmp->_vl_msg_id = ntohs (VL_API_WANT_STATS);
  bmp->client_index = utm->my_client_index;
  bmp->context = ntohl (0xfeedface);
  bmp->enable_disable = 1;
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

static void
stats_client_test (uri_udp_test_main_t * utm)
{

  utm->counter_epochs = 0;

  send_want_stats (utm);

  while (utm->counter_epochs == 0);

  application_detach (utm);
}


static void
vl_api_want_stats_t_handler (vl_api_want_stats_t * mp)
{
  uri_udp_test_main_t *um = &uri_udp_test_main;

  fformat (stdout,
           "Got stats \n");
  ++um->counter_epochs;
}


#define foreach_stats_msg                                               \
  _(WANT_STATS, want_stats)
  /* _(VNET_INTERFACE_SIMPLE_COUNTERS, vnet_interface_simple_counters)     \ */
  /* _(VNET_INTERFACE_COMBINED_COUNTERS, vnet_interface_combined_counters)	\ */
  /* _(VNET_IP4_FIB_COUNTERS, vnet_ip4_fib_counters)                       \ */
  /* _(VNET_IP6_FIB_COUNTERS, vnet_ip6_fib_counters)                       \ */
  /* _(VNET_IP4_NBR_COUNTERS, vnet_ip4_nbr_counters)                       \ */
  /* _(VNET_IP6_NBR_COUNTERS, vnet_ip6_nbr_counters) */

void
stats_api_hookup (uri_udp_test_main_t * utm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_stats_msg;
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

  /* Fabricate TX event, send to vpp */
  evt.fifo = tx_fifo;
  evt.event_type = FIFO_EVENT_APP_TX;
  evt.event_id = e->event_id;

  if (svm_fifo_set_event (tx_fifo))
    {
      q = utm->vpp_event_queue;
      unix_shared_memory_queue_add (q, (u8 *) & evt,
				    0 /* do wait for mutex */ );
    }
}

void
server_handle_event_queue (uri_udp_test_main_t * utm)
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


int
main (int argc, char **argv)
{
  uri_udp_test_main_t *utm = &uri_udp_test_main;
  /* u8 *heap; */
  /* mheap_t *h; */

  /* clib_mem_init (0, 256 << 20); */

  /* heap = clib_mem_get_per_cpu_heap (); */
  /* h = mheap_header (heap); */

  /* /\* make the main heap thread-safe *\/ */
  /* h->flags |= MHEAP_FLAG_THREAD_SAFE; */

  //vec_validate (utm->rx_buf, 8192);

  //utm->session_index_by_vpp_handles = hash_create (0, sizeof (uword));

  //utm->my_pid = getpid ();
  //utm->configured_segment_size = 1 << 20;

  clib_time_init (&utm->clib_time);
  init_error_string_table (utm);
  //  svm_fifo_segment_init (0x200000000ULL, 20);

  setup_signal_handlers ();

  stats_api_hookup (utm);

  if (connect_to_vpp ("stats_test") < 0)
    {
      svm_region_exit ();
      fformat (stderr, "Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  stats_client_test (utm);

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
