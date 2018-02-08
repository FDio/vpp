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
  svm_queue_t **vpp_queue;
  svm_queue_t *vl_input_queue;	/**< Sever's event queue */

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
} echo_server_main_t;

echo_server_main_t echo_server_main;

int
echo_server_session_accept_callback (stream_session_t * s)
{
  echo_server_main_t *esm = &echo_server_main;

  esm->vpp_queue[s->thread_index] =
    session_manager_get_vpp_event_queue (s->thread_index);
  s->session_state = SESSION_STATE_READY;
  esm->byte_index = 0;
  vec_validate (esm->rx_retries[s->thread_index], s->session_index);
  esm->rx_retries[s->thread_index][s->session_index] = 0;
  return 0;
}

void
echo_server_session_disconnect_callback (stream_session_t * s)
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_disconnect_args_t _a, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = esm->app_index;
  vnet_disconnect_session (a);
}

void
echo_server_session_reset_callback (stream_session_t * s)
{
  clib_warning ("Reset session %U", format_stream_session, s, 2);
  stream_session_cleanup (s);
}

int
echo_server_session_connected_callback (u32 app_index, u32 api_context,
					stream_session_t * s, u8 is_fail)
{
  clib_warning ("called...");
  return -1;
}

int
echo_server_add_segment_callback (u32 client_index, const ssvm_private_t * sp)
{
  /* New heaps may be added */
  return 0;
}

int
echo_server_redirect_connect_callback (u32 client_index, void *mp)
{
  clib_warning ("called...");
  return -1;
}

void
test_bytes (echo_server_main_t * esm, int actual_transfer)
{
  int i;
  u32 my_thread_id = vlib_get_thread_index ();

  for (i = 0; i < actual_transfer; i++)
    {
      if (esm->rx_buf[my_thread_id][i] != ((esm->byte_index + i) & 0xff))
	{
	  clib_warning ("at %lld expected %d got %d", esm->byte_index + i,
			(esm->byte_index + i) & 0xff,
			esm->rx_buf[my_thread_id][i]);
	}
    }
  esm->byte_index += actual_transfer;
}

/*
 * If no-echo, just read the data and be done with it
 */
int
echo_server_builtin_server_rx_callback_no_echo (stream_session_t * s)
{
  echo_server_main_t *esm = &echo_server_main;
  u32 my_thread_id = vlib_get_thread_index ();
  int actual_transfer;
  svm_fifo_t *rx_fifo;

  rx_fifo = s->server_rx_fifo;

  do
    {
      actual_transfer =
	svm_fifo_dequeue_nowait (rx_fifo, esm->rcv_buffer_size,
				 esm->rx_buf[my_thread_id]);
    }
  while (actual_transfer > 0);
  return 0;
}

int
echo_server_rx_callback (stream_session_t * s)
{
  u32 n_written, max_dequeue, max_enqueue, max_transfer;
  int actual_transfer;
  svm_fifo_t *tx_fifo, *rx_fifo;
  echo_server_main_t *esm = &echo_server_main;
  session_fifo_event_t evt;
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
	  svm_queue_t *q;
	  evt.fifo = rx_fifo;
	  evt.event_type = FIFO_EVENT_BUILTIN_RX;

	  q = esm->vpp_queue[thread_index];
	  if (PREDICT_FALSE (q->cursize == q->maxsize))
	    clib_warning ("out of event queue space");
	  else if (svm_queue_add (q, (u8 *) & evt, 0))
	    clib_warning ("failed to enqueue self-tap");

	  if (esm->rx_retries[thread_index][s->session_index] == 500000)
	    {
	      clib_warning ("session stuck: %U", format_stream_session, s, 2);
	    }
	  if (esm->rx_retries[thread_index][s->session_index] < 500001)
	    esm->rx_retries[thread_index][s->session_index]++;
	}

      return 0;
    }

  _vec_len (esm->rx_buf[thread_index]) = max_transfer;

  actual_transfer = svm_fifo_dequeue_nowait (rx_fifo, max_transfer,
					     esm->rx_buf[thread_index]);
  ASSERT (actual_transfer == max_transfer);

//  test_bytes (esm, actual_transfer);

  /*
   * Echo back
   */

  n_written = svm_fifo_enqueue_nowait (tx_fifo, actual_transfer,
				       esm->rx_buf[thread_index]);

  if (n_written != max_transfer)
    clib_warning ("short trout!");

  if (svm_fifo_set_event (tx_fifo))
    {
      /* Fabricate TX event, send to vpp */
      evt.fifo = tx_fifo;
      evt.event_type = FIFO_EVENT_APP_TX;

      if (svm_queue_add (esm->vpp_queue[s->thread_index],
			 (u8 *) & evt, 0 /* do wait for mutex */ ))
	clib_warning ("failed to enqueue tx evt");
    }

  if (PREDICT_FALSE (n_written < max_dequeue))
    goto rx_event;

  return 0;
}

static session_cb_vft_t echo_server_session_cb_vft = {
  .session_accept_callback = echo_server_session_accept_callback,
  .session_disconnect_callback = echo_server_session_disconnect_callback,
  .session_connected_callback = echo_server_session_connected_callback,
  .add_segment_callback = echo_server_add_segment_callback,
  .builtin_server_rx_callback = echo_server_rx_callback,
  .session_reset_callback = echo_server_session_reset_callback
};

/* Abuse VPP's input queue */
static int
create_api_loopback (vlib_main_t * vm)
{
  echo_server_main_t *esm = &echo_server_main;
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr;

  shmem_hdr = am->shmem_hdr;
  esm->vl_input_queue = shmem_hdr->vl_input_queue;
  esm->my_client_index = vl_api_memclnt_create_internal ("echo_server",
							 esm->vl_input_queue);
  return 0;
}

static int
echo_server_attach (u8 * appns_id, u64 appns_flags, u64 appns_secret)
{
  echo_server_main_t *esm = &echo_server_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;
  u32 segment_size = 512 << 20;

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  if (esm->no_echo)
    echo_server_session_cb_vft.builtin_server_rx_callback =
      echo_server_builtin_server_rx_callback_no_echo;
  else
    echo_server_session_cb_vft.builtin_server_rx_callback =
      echo_server_rx_callback;

  if (esm->private_segment_size)
    segment_size = esm->private_segment_size;

  a->api_client_index = esm->my_client_index;
  a->session_cb_vft = &echo_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = esm->fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = esm->fifo_size;
  a->options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT] = esm->private_segment_count;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] =
    esm->prealloc_fifos ? esm->prealloc_fifos : 1;

  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  if (appns_id)
    {
      a->namespace_id = appns_id;
      a->options[APP_OPTIONS_FLAGS] |= appns_flags;
      a->options[APP_OPTIONS_NAMESPACE_SECRET] = appns_secret;
    }

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  esm->app_index = a->app_index;
  return 0;
}

static int
echo_server_detach (void)
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_app_detach_args_t _da, *da = &_da;
  int rv;

  da->app_index = esm->app_index;
  rv = vnet_application_detach (da);
  esm->app_index = ~0;
  return rv;
}

static int
echo_server_listen ()
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_bind_args_t _a, *a = &_a;
  memset (a, 0, sizeof (*a));
  a->app_index = esm->app_index;
  a->uri = esm->server_uri;
  return vnet_bind_uri (a);
}

static int
echo_server_create (vlib_main_t * vm, u8 * appns_id, u64 appns_flags,
		    u64 appns_secret)
{
  echo_server_main_t *esm = &echo_server_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;
  int i;

  if (esm->my_client_index == (u32) ~ 0)
    {
      if (create_api_loopback (vm))
	{
	  clib_warning ("failed to create api loopback");
	  return -1;
	}
    }

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (echo_server_main.vpp_queue, num_threads - 1);
  vec_validate (esm->rx_buf, num_threads - 1);
  vec_validate (esm->rx_retries, num_threads - 1);

  for (i = 0; i < num_threads; i++)
    vec_validate (esm->rx_buf[i], esm->rcv_buffer_size);

  if (echo_server_attach (appns_id, appns_flags, appns_secret))
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  if (echo_server_listen ())
    {
      clib_warning ("failed to start listening");
      if (echo_server_detach ())
	clib_warning ("failed to detach");
      return -1;
    }
  return 0;
}

static clib_error_t *
echo_server_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  echo_server_main_t *esm = &echo_server_main;
  u8 server_uri_set = 0, *appns_id = 0;
  u64 tmp, appns_flags = 0, appns_secret = 0;
  char *default_uri = "tcp://0.0.0.0/1234";
  int rv, is_stop = 0;

  esm->no_echo = 0;
  esm->fifo_size = 64 << 10;
  esm->rcv_buffer_size = 128 << 10;
  esm->prealloc_fifos = 0;
  esm->private_segment_count = 0;
  esm->private_segment_size = 0;
  vec_free (esm->server_uri);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "uri %s", &esm->server_uri))
	server_uri_set = 1;
      else if (unformat (input, "no-echo"))
	esm->no_echo = 1;
      else if (unformat (input, "fifo-size %d", &esm->fifo_size))
	esm->fifo_size <<= 10;
      else if (unformat (input, "rcv-buf-size %d", &esm->rcv_buffer_size))
	;
      else if (unformat (input, "prealloc-fifos %d", &esm->prealloc_fifos))
	;
      else if (unformat (input, "private-segment-count %d",
			 &esm->private_segment_count))
	;
      else if (unformat (input, "private-segment-size %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    return clib_error_return
	      (0, "private segment size %lld (%llu) too large", tmp, tmp);
	  esm->private_segment_size = tmp;
	}
      else if (unformat (input, "appns %_%v%_", &appns_id))
	;
      else if (unformat (input, "all-scope"))
	appns_flags |= (APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE
			| APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE);
      else if (unformat (input, "local-scope"))
	appns_flags |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
      else if (unformat (input, "global-scope"))
	appns_flags |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
      else if (unformat (input, "secret %lu", &appns_secret))
	;
      else if (unformat (input, "stop"))
	is_stop = 1;
      else
	return clib_error_return (0, "failed: unknown input `%U'",
				  format_unformat_error, input);
    }

  if (is_stop)
    {
      if (esm->app_index  == (u32)~0)
	{
	  clib_warning ("server not running");
	  return clib_error_return (0, "failed: server not running");
	}
      rv = echo_server_detach ();
      if (rv)
	{
	  clib_warning ("failed: detach");
	  return clib_error_return (0, "failed: server detach %d", rv);
	}
      return 0;
    }

  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );

  if (!server_uri_set)
    {
      clib_warning ("No uri provided! Using default: %s", default_uri);
      esm->server_uri = (char *) format (0, "%s%c", default_uri, 0);
    }

  rv = echo_server_create (vm, appns_id, appns_flags, appns_secret);
  vec_free (appns_id);
  if (rv)
    {
      vec_free (esm->server_uri);
      return clib_error_return (0, "failed: server_create returned %d", rv);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (echo_server_create_command, static) =
{
  .path = "test echo server",
  .short_help = "test echo server proto <proto> [no echo][fifo-size <mbytes>]"
      "[rcv-buf-size <bytes>][prealloc-fifos <count>]"
      "[private-segment-count <count>][private-segment-size <bytes[m|g]>]"
      "[uri <tcp://ip/port>]",
  .function = echo_server_create_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
echo_server_main_init (vlib_main_t * vm)
{
  echo_server_main_t *esm = &echo_server_main;
  esm->my_client_index = ~0;
  return 0;
}

VLIB_INIT_FUNCTION (echo_server_main_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
