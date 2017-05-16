/*
* Copyright (c) 2015-2017 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>

/* define message IDs */
#include <vpp/api/vpe_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

typedef struct
{
  u8 *rx_buf;
  unix_shared_memory_queue_t **vpp_queue;
  u64 byte_index;

  /* Sever's event queue */
  unix_shared_memory_queue_t *vl_input_queue;

  /* API client handle */
  u32 my_client_index;

  u32 app_index;

  /* process node index for evnt scheduling */
  u32 node_index;
  vlib_main_t *vlib_main;
} builtin_server_main_t;

builtin_server_main_t builtin_server_main;

int
builtin_session_accept_callback (stream_session_t * s)
{
  builtin_server_main_t *bsm = &builtin_server_main;
  clib_warning ("called...");

  bsm->vpp_queue[s->thread_index] =
    session_manager_get_vpp_event_queue (s->thread_index);
  s->session_state = SESSION_STATE_READY;
  bsm->byte_index = 0;
  return 0;
}

void
builtin_session_disconnect_callback (stream_session_t * s)
{
  builtin_server_main_t *bsm = &builtin_server_main;
  vnet_disconnect_args_t _a, *a = &_a;
  clib_warning ("called...");

  a->handle = stream_session_handle (s);
  a->app_index = bsm->app_index;
  vnet_disconnect_session (a);
}

void
builtin_session_reset_callback (stream_session_t * s)
{
  clib_warning ("called.. ");

  stream_session_cleanup (s);
}


int
builtin_session_connected_callback (u32 app_index, u32 api_context,
				    stream_session_t * s, u8 is_fail)
{
  clib_warning ("called...");
  return -1;
}

int
builtin_add_segment_callback (u32 client_index,
			      const u8 * seg_name, u32 seg_size)
{
  clib_warning ("called...");
  return -1;
}

int
builtin_redirect_connect_callback (u32 client_index, void *mp)
{
  clib_warning ("called...");
  return -1;
}

void
test_bytes (builtin_server_main_t * bsm, int actual_transfer)
{
  int i;

  for (i = 0; i < actual_transfer; i++)
    {
      if (bsm->rx_buf[i] != ((bsm->byte_index + i) & 0xff))
	{
	  clib_warning ("at %lld expected %d got %d", bsm->byte_index + i,
			(bsm->byte_index + i) & 0xff, bsm->rx_buf[i]);
	}
    }
  bsm->byte_index += actual_transfer;
}

int
builtin_server_rx_callback (stream_session_t * s)
{
  u32 n_written, max_dequeue, max_enqueue, max_transfer;
  int actual_transfer;
  svm_fifo_t *tx_fifo, *rx_fifo;
  builtin_server_main_t *bsm = &builtin_server_main;
  session_fifo_event_t evt;
  static int serial_number = 0;

  tx_fifo = s->server_tx_fifo;
  rx_fifo = s->server_rx_fifo;

  max_dequeue = svm_fifo_max_dequeue (s->server_rx_fifo);
  max_enqueue = svm_fifo_max_enqueue (s->server_tx_fifo);

  if (PREDICT_FALSE (max_dequeue == 0))
    return 0;

  /* Number of bytes we're going to copy */
  max_transfer = (max_dequeue < max_enqueue) ? max_dequeue : max_enqueue;

  /* No space in tx fifo */
  if (PREDICT_FALSE (max_transfer == 0))
    {
      /* XXX timeout for session that are stuck */

    rx_event:
      /* Program self-tap to retry */
      if (svm_fifo_set_event (rx_fifo))
	{
	  evt.fifo = rx_fifo;
	  evt.event_type = FIFO_EVENT_BUILTIN_RX;
	  evt.event_id = 0;
	  unix_shared_memory_queue_add (bsm->vpp_queue[s->thread_index],
					(u8 *) & evt,
					0 /* do wait for mutex */ );
	}

      return 0;
    }

  vec_validate (bsm->rx_buf, max_transfer - 1);
  _vec_len (bsm->rx_buf) = max_transfer;

  actual_transfer = svm_fifo_dequeue_nowait (rx_fifo, max_transfer,
					     bsm->rx_buf);
  ASSERT (actual_transfer == max_transfer);

//  test_bytes (bsm, actual_transfer);

  /*
   * Echo back
   */

  n_written = svm_fifo_enqueue_nowait (tx_fifo, actual_transfer, bsm->rx_buf);

  if (n_written != max_transfer)
    clib_warning ("short trout!");

  if (svm_fifo_set_event (tx_fifo))
    {
      /* Fabricate TX event, send to vpp */
      evt.fifo = tx_fifo;
      evt.event_type = FIFO_EVENT_APP_TX;
      evt.event_id = serial_number++;

      unix_shared_memory_queue_add (bsm->vpp_queue[s->thread_index],
				    (u8 *) & evt, 0 /* do wait for mutex */ );
    }

  if (PREDICT_FALSE (max_enqueue < max_dequeue))
    goto rx_event;

  return 0;
}

static session_cb_vft_t builtin_session_cb_vft = {
  .session_accept_callback = builtin_session_accept_callback,
  .session_disconnect_callback = builtin_session_disconnect_callback,
  .session_connected_callback = builtin_session_connected_callback,
  .add_segment_callback = builtin_add_segment_callback,
  .redirect_connect_callback = builtin_redirect_connect_callback,
  .builtin_server_rx_callback = builtin_server_rx_callback,
  .session_reset_callback = builtin_session_reset_callback
};

/* Abuse VPP's input queue */
static int
create_api_loopback (vlib_main_t * vm)
{
  builtin_server_main_t *bsm = &builtin_server_main;
  vl_api_memclnt_create_t _m, *mp = &_m;
  extern void vl_api_memclnt_create_t_handler (vl_api_memclnt_create_t *);
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr;
  uword *event_data = 0, event_type;
  int resolved = 0;

  /*
   * Create a "loopback" API client connection
   * Don't do things like this unless you know what you're doing...
   */

  shmem_hdr = am->shmem_hdr;
  bsm->vl_input_queue = shmem_hdr->vl_input_queue;
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = VL_API_MEMCLNT_CREATE;
  mp->context = 0xFEEDFACE;
  mp->input_queue = pointer_to_uword (bsm->vl_input_queue);
  strncpy ((char *) mp->name, "tcp_test_server", sizeof (mp->name) - 1);

  vl_api_memclnt_create_t_handler (mp);

  /* Wait for reply */
  bsm->node_index = vlib_get_current_process (vm)->node_runtime.node_index;
  vlib_process_wait_for_event_or_clock (vm, 1.0);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case 1:
      resolved = 1;
      break;
    case ~0:
      /* timed out */
      break;
    default:
      clib_warning ("unknown event_type %d", event_type);
    }
  if (!resolved)
    return -1;

  return 0;
}

static int
server_attach ()
{
  builtin_server_main_t *bsm = &builtin_server_main;
  u8 segment_name[128];
  u64 options[SESSION_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  a->api_client_index = bsm->my_client_index;
  a->session_cb_vft = &builtin_session_cb_vft;
  a->options = options;
  a->options[SESSION_OPTIONS_SEGMENT_SIZE] = 128 << 20;
  a->options[SESSION_OPTIONS_RX_FIFO_SIZE] = 1 << 16;
  a->options[SESSION_OPTIONS_TX_FIFO_SIZE] = 1 << 16;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_BUILTIN_APP;
  a->segment_name = segment_name;
  a->segment_name_length = ARRAY_LEN (segment_name);

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  bsm->app_index = a->app_index;
  return 0;
}

static int
server_listen ()
{
  builtin_server_main_t *bsm = &builtin_server_main;
  vnet_bind_args_t _a, *a = &_a;
  memset (a, 0, sizeof (*a));
  a->app_index = bsm->app_index;
  a->uri = "tcp://0.0.0.0/1234";
  return vnet_bind_uri (a);
}

static int
server_create (vlib_main_t * vm)
{
  builtin_server_main_t *bsm = &builtin_server_main;
  u32 num_threads;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();

  if (bsm->my_client_index == (u32) ~ 0)
    {
      if (create_api_loopback (vm))
	return -1;
    }

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (builtin_server_main.vpp_queue, num_threads - 1);

  if (server_attach ())
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  if (server_listen ())
    {
      clib_warning ("failed to start listening");
      return -1;
    }
  return 0;
}

/* Get our api client index */
static void
vl_api_memclnt_create_reply_t_handler (vl_api_memclnt_create_reply_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  builtin_server_main_t *bsm = &builtin_server_main;
  bsm->my_client_index = mp->index;
  vlib_process_signal_event (vm, bsm->node_index, 1 /* evt */ ,
			     0 /* data */ );
}

#define foreach_tcp_builtin_server_api_msg      		\
_(MEMCLNT_CREATE_REPLY, memclnt_create_reply)   		\

static clib_error_t *
tcp_builtin_server_api_hookup (vlib_main_t * vm)
{
  vl_msg_api_msg_config_t _c, *c = &_c;

  /* Hook up client-side static APIs to our handlers */
#define _(N,n) do {                                             \
    c->id = VL_API_##N;                                         \
    c->name = #n;                                               \
    c->handler = vl_api_##n##_t_handler;                        \
    c->cleanup = vl_noop_handler;                               \
    c->endian = vl_api_##n##_t_endian;                          \
    c->print = vl_api_##n##_t_print;                            \
    c->size = sizeof(vl_api_##n##_t);                           \
    c->traced = 1; /* trace, so these msgs print */             \
    c->replay = 0; /* don't replay client create/delete msgs */ \
    c->message_bounce = 0; /* don't bounce this message */	\
    vl_msg_api_config(c);} while (0);

  foreach_tcp_builtin_server_api_msg;
#undef _

  return 0;
}

static clib_error_t *
server_create_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int rv;
#if 0
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "whatever %d", &whatever))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
#endif

  tcp_builtin_server_api_hookup (vm);
  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );
  rv = server_create (vm);
  switch (rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "server_create returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (server_create_command, static) =
{
  .path = "test tcp server",
  .short_help = "test tcp server",
  .function = server_create_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
builtin_tcp_server_main_init (vlib_main_t * vm)
{
  builtin_server_main_t *bsm = &builtin_server_main;
  bsm->my_client_index = ~0;
  return 0;
}

VLIB_INIT_FUNCTION (builtin_tcp_server_main_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
