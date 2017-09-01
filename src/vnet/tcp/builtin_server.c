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

typedef struct
{
  /*
   * Server app parameters
   */
  unix_shared_memory_queue_t **vpp_queue;
  unix_shared_memory_queue_t *vl_input_queue;	/**< Sever's event queue */

  u32 app_index;		/**< Server app index */
  u32 my_client_index;		/**< API client handle */
  u32 node_index;		/**< process node index for evnt scheduling */

  /*
   * Config params
   */
  u8 no_echo;			/**< Don't echo traffic */
  u32 fifo_size;			/**< Fifo size */
  u32 rcv_buffer_size;		/**< Rcv buffer size */
  u32 prealloc_fifos;		/**< Preallocate fifos */
  u32 private_segment_count;	/**< Number of private segments  */
  u32 private_segment_size;	/**< Size of private segments  */
  char *server_uri;		/**< Server URI */

  /*
   * Test state
   */
  u8 **rx_buf;			/**< Per-thread RX buffer */
  u64 byte_index;
  u32 **rx_retries;

  vlib_main_t *vlib_main;
} builtin_server_main_t;

builtin_server_main_t builtin_server_main;

int
builtin_session_accept_callback (stream_session_t * s)
{
  builtin_server_main_t *bsm = &builtin_server_main;

  bsm->vpp_queue[s->thread_index] =
    session_manager_get_vpp_event_queue (s->thread_index);
  s->session_state = SESSION_STATE_READY;
  bsm->byte_index = 0;
  vec_validate (bsm->rx_retries[s->thread_index], s->session_index);
  bsm->rx_retries[s->thread_index][s->session_index] = 0;
  return 0;
}

void
builtin_session_disconnect_callback (stream_session_t * s)
{
  builtin_server_main_t *bsm = &builtin_server_main;
  vnet_disconnect_args_t _a, *a = &_a;

  a->handle = stream_session_handle (s);
  a->app_index = bsm->app_index;
  vnet_disconnect_session (a);
}

void
builtin_session_reset_callback (stream_session_t * s)
{
  clib_warning ("Reset session %U", format_stream_session, s, 2);
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
  u32 my_thread_id = vlib_get_thread_index ();

  for (i = 0; i < actual_transfer; i++)
    {
      if (bsm->rx_buf[my_thread_id][i] != ((bsm->byte_index + i) & 0xff))
	{
	  clib_warning ("at %lld expected %d got %d", bsm->byte_index + i,
			(bsm->byte_index + i) & 0xff,
			bsm->rx_buf[my_thread_id][i]);
	}
    }
  bsm->byte_index += actual_transfer;
}

/*
 * If no-echo, just read the data and be done with it
 */
int
builtin_server_rx_callback_no_echo (stream_session_t * s)
{
  builtin_server_main_t *bsm = &builtin_server_main;
  u32 my_thread_id = vlib_get_thread_index ();
  int actual_transfer;
  svm_fifo_t *rx_fifo;

  rx_fifo = s->server_rx_fifo;

  do
    {
      actual_transfer =
	svm_fifo_dequeue_nowait (rx_fifo, bsm->rcv_buffer_size,
				 bsm->rx_buf[my_thread_id]);
    }
  while (actual_transfer > 0);
  return 0;
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
  u32 thread_index = vlib_get_thread_index ();

  ASSERT (s->thread_index == thread_index);

  rx_fifo = s->server_rx_fifo;
  tx_fifo = s->server_tx_fifo;

  ASSERT (rx_fifo->master_thread_index == thread_index);
  ASSERT (tx_fifo->master_thread_index == thread_index);

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
	  unix_shared_memory_queue_t *q;
	  evt.fifo = rx_fifo;
	  evt.event_type = FIFO_EVENT_BUILTIN_RX;
	  evt.event_id = 0;

	  q = bsm->vpp_queue[thread_index];
	  if (PREDICT_FALSE (q->cursize == q->maxsize))
	    clib_warning ("out of event queue space");
	  else if (unix_shared_memory_queue_add (q, (u8 *) & evt, 0))
	    clib_warning ("failed to enqueue self-tap");

	  if (bsm->rx_retries[thread_index][s->session_index] == 500000)
	    {
	      clib_warning ("session stuck: %U", format_stream_session, s, 2);
	    }
	  if (bsm->rx_retries[thread_index][s->session_index] < 500001)
	    bsm->rx_retries[thread_index][s->session_index]++;
	}

      return 0;
    }

  _vec_len (bsm->rx_buf[thread_index]) = max_transfer;

  actual_transfer = svm_fifo_dequeue_nowait (rx_fifo, max_transfer,
					     bsm->rx_buf[thread_index]);
  ASSERT (actual_transfer == max_transfer);

//  test_bytes (bsm, actual_transfer);

  /*
   * Echo back
   */

  n_written = svm_fifo_enqueue_nowait (tx_fifo, actual_transfer,
				       bsm->rx_buf[thread_index]);

  if (n_written != max_transfer)
    clib_warning ("short trout!");

  if (svm_fifo_set_event (tx_fifo))
    {
      /* Fabricate TX event, send to vpp */
      evt.fifo = tx_fifo;
      evt.event_type = FIFO_EVENT_APP_TX;
      evt.event_id = serial_number++;

      if (unix_shared_memory_queue_add (bsm->vpp_queue[s->thread_index],
					(u8 *) & evt,
					0 /* do wait for mutex */ ))
	clib_warning ("failed to enqueue tx evt");
    }

  if (PREDICT_FALSE (n_written < max_dequeue))
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
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr;

  shmem_hdr = am->shmem_hdr;
  bsm->vl_input_queue = shmem_hdr->vl_input_queue;
  bsm->my_client_index =
    vl_api_memclnt_create_internal ("tcp_test_server", bsm->vl_input_queue);
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

  if (bsm->no_echo)
    builtin_session_cb_vft.builtin_server_rx_callback =
      builtin_server_rx_callback_no_echo;
  else
    builtin_session_cb_vft.builtin_server_rx_callback =
      builtin_server_rx_callback;
  a->api_client_index = bsm->my_client_index;
  a->session_cb_vft = &builtin_session_cb_vft;
  a->options = options;
  a->options[SESSION_OPTIONS_SEGMENT_SIZE] = 512 << 20;
  a->options[SESSION_OPTIONS_RX_FIFO_SIZE] = bsm->fifo_size;
  a->options[SESSION_OPTIONS_TX_FIFO_SIZE] = bsm->fifo_size;
  a->options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT] = bsm->private_segment_count;
  a->options[APP_OPTIONS_PRIVATE_SEGMENT_SIZE] = bsm->private_segment_size;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] =
    bsm->prealloc_fifos ? bsm->prealloc_fifos : 1;

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
  a->uri = bsm->server_uri;
  return vnet_bind_uri (a);
}

static int
server_create (vlib_main_t * vm)
{
  builtin_server_main_t *bsm = &builtin_server_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;
  int i;

  if (bsm->my_client_index == (u32) ~ 0)
    {
      if (create_api_loopback (vm))
	{
	  clib_warning ("failed to create api loopback");
	  return -1;
	}
    }

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (builtin_server_main.vpp_queue, num_threads - 1);
  vec_validate (bsm->rx_buf, num_threads - 1);
  vec_validate (bsm->rx_retries, num_threads - 1);

  for (i = 0; i < num_threads; i++)
    vec_validate (bsm->rx_buf[i], bsm->rcv_buffer_size);

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

static clib_error_t *
server_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  builtin_server_main_t *bsm = &builtin_server_main;
  u8 server_uri_set = 0;
  int rv;
  u64 tmp;

  bsm->no_echo = 0;
  bsm->fifo_size = 64 << 10;
  bsm->rcv_buffer_size = 128 << 10;
  bsm->prealloc_fifos = 0;
  bsm->private_segment_count = 0;
  bsm->private_segment_size = 0;
  vec_free (bsm->server_uri);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "no-echo"))
	bsm->no_echo = 1;
      else if (unformat (input, "fifo-size %d", &bsm->fifo_size))
	bsm->fifo_size <<= 10;
      else if (unformat (input, "rcv-buf-size %d", &bsm->rcv_buffer_size))
	;
      else if (unformat (input, "prealloc-fifos %d", &bsm->prealloc_fifos))
	;
      else if (unformat (input, "private-segment-count %d",
			 &bsm->private_segment_count))
	;
      else if (unformat (input, "private-segment-size %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    return clib_error_return
	      (0, "private segment size %lld (%llu) too large", tmp, tmp);
	  bsm->private_segment_size = tmp;
	}
      else if (unformat (input, "uri %s", &bsm->server_uri))
	server_uri_set = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );

  if (!server_uri_set)
    bsm->server_uri = (char *) format (0, "tcp://0.0.0.0/1234%c", 0);

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
  .short_help = "test tcp server [no echo][fifo-size <mbytes>] "
      "[rcv-buf-size <bytes>][prealloc-fifos <count>]"
      "[private-segment-count <count>][private-segment-size <bytes[m|g]>]"
      "[uri <tcp://ip/port>]",
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
