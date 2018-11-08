/*
 * echo_client.c - vpp built-in echo client code
 *
 * Copyright (c) 2017 by Cisco and/or its affiliates.
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
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/session-apps/echo_client.h>

echo_client_main_t echo_client_main;

#define ECHO_CLIENT_DBG (0)

static void
signal_evt_to_cli_i (int *code)
{
  echo_client_main_t *ecm = &echo_client_main;
  ASSERT (vlib_get_thread_index () == 0);
  vlib_process_signal_event (ecm->vlib_main, ecm->cli_node_index, *code, 0);
}

static void
signal_evt_to_cli (int code)
{
  if (vlib_get_thread_index () != 0)
    vl_api_rpc_call_main_thread (signal_evt_to_cli_i, (u8 *) & code,
				 sizeof (code));
  else
    signal_evt_to_cli_i (&code);
}

static void
send_data_chunk (echo_client_main_t * ecm, eclient_session_t * s)
{
  u8 *test_data = ecm->connect_test_data;
  int test_buf_len, test_buf_offset, rv;
  u32 bytes_this_chunk;

  test_buf_len = vec_len (test_data);
  ASSERT (test_buf_len > 0);
  test_buf_offset = s->bytes_sent % test_buf_len;
  bytes_this_chunk = clib_min (test_buf_len - test_buf_offset,
			       s->bytes_to_send);

  if (!ecm->is_dgram)
    {
      if (ecm->no_copy)
	{
	  svm_fifo_t *f = s->data.tx_fifo;
	  rv = clib_min (svm_fifo_max_enqueue (f), bytes_this_chunk);
	  svm_fifo_enqueue_nocopy (f, rv);
	  session_send_io_evt_to_thread_custom (f, s->thread_index,
						FIFO_EVENT_APP_TX);
	}
      else
	rv = app_send_stream (&s->data, test_data + test_buf_offset,
			      bytes_this_chunk, 0);
    }
  else
    {
      if (ecm->no_copy)
	{
	  session_dgram_hdr_t hdr;
	  svm_fifo_t *f = s->data.tx_fifo;
	  app_session_transport_t *at = &s->data.transport;
	  u32 max_enqueue = svm_fifo_max_enqueue (f);

	  if (max_enqueue <= sizeof (session_dgram_hdr_t))
	    return;

	  max_enqueue -= sizeof (session_dgram_hdr_t);
	  rv = clib_min (max_enqueue, bytes_this_chunk);

	  hdr.data_length = rv;
	  hdr.data_offset = 0;
	  clib_memcpy (&hdr.rmt_ip, &at->rmt_ip, sizeof (ip46_address_t));
	  hdr.is_ip4 = at->is_ip4;
	  hdr.rmt_port = at->rmt_port;
	  clib_memcpy (&hdr.lcl_ip, &at->lcl_ip, sizeof (ip46_address_t));
	  hdr.lcl_port = at->lcl_port;
	  svm_fifo_enqueue_nowait (f, sizeof (hdr), (u8 *) & hdr);
	  svm_fifo_enqueue_nocopy (f, rv);
	  session_send_io_evt_to_thread_custom (f, s->thread_index,
						FIFO_EVENT_APP_TX);
	}
      else
	rv = app_send_dgram (&s->data, test_data + test_buf_offset,
			     bytes_this_chunk, 0);
    }

  /* If we managed to enqueue data... */
  if (rv > 0)
    {
      /* Account for it... */
      s->bytes_to_send -= rv;
      s->bytes_sent += rv;

      if (ECHO_CLIENT_DBG)
	{
          /* *INDENT-OFF* */
          ELOG_TYPE_DECLARE (e) =
            {
              .format = "tx-enq: xfer %d bytes, sent %u remain %u",
              .format_args = "i4i4i4",
            };
          /* *INDENT-ON* */
	  struct
	  {
	    u32 data[3];
	  } *ed;
	  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
	  ed->data[0] = rv;
	  ed->data[1] = s->bytes_sent;
	  ed->data[2] = s->bytes_to_send;
	}
    }
}

static void
receive_data_chunk (echo_client_main_t * ecm, eclient_session_t * s)
{
  svm_fifo_t *rx_fifo = s->data.rx_fifo;
  u32 thread_index = vlib_get_thread_index ();
  int n_read, i;

  if (ecm->test_bytes)
    {
      if (!ecm->is_dgram)
	n_read = app_recv_stream (&s->data, ecm->rx_buf[thread_index],
				  vec_len (ecm->rx_buf[thread_index]));
      else
	n_read = app_recv_dgram (&s->data, ecm->rx_buf[thread_index],
				 vec_len (ecm->rx_buf[thread_index]));
    }
  else
    {
      n_read = svm_fifo_max_dequeue (rx_fifo);
      svm_fifo_dequeue_drop (rx_fifo, n_read);
    }

  if (n_read > 0)
    {
      if (ECHO_CLIENT_DBG)
	{
          /* *INDENT-OFF* */
          ELOG_TYPE_DECLARE (e) =
            {
              .format = "rx-deq: %d bytes",
              .format_args = "i4",
            };
          /* *INDENT-ON* */
	  struct
	  {
	    u32 data[1];
	  } *ed;
	  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
	  ed->data[0] = n_read;
	}

      if (ecm->test_bytes)
	{
	  for (i = 0; i < n_read; i++)
	    {
	      if (ecm->rx_buf[thread_index][i]
		  != ((s->bytes_received + i) & 0xff))
		{
		  clib_warning ("read %d error at byte %lld, 0x%x not 0x%x",
				n_read, s->bytes_received + i,
				ecm->rx_buf[thread_index][i],
				((s->bytes_received + i) & 0xff));
		  ecm->test_failed = 1;
		}
	    }
	}
      ASSERT (n_read <= s->bytes_to_receive);
      s->bytes_to_receive -= n_read;
      s->bytes_received += n_read;
    }
}

static uword
echo_client_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * frame)
{
  echo_client_main_t *ecm = &echo_client_main;
  int my_thread_index = vlib_get_thread_index ();
  eclient_session_t *sp;
  int i;
  int delete_session;
  u32 *connection_indices;
  u32 *connections_this_batch;
  u32 nconnections_this_batch;

  connection_indices = ecm->connection_index_by_thread[my_thread_index];
  connections_this_batch =
    ecm->connections_this_batch_by_thread[my_thread_index];

  if ((ecm->run_test != ECHO_CLIENTS_RUNNING) ||
      ((vec_len (connection_indices) == 0)
       && vec_len (connections_this_batch) == 0))
    return 0;

  /* Grab another pile of connections */
  if (PREDICT_FALSE (vec_len (connections_this_batch) == 0))
    {
      nconnections_this_batch =
	clib_min (ecm->connections_per_batch, vec_len (connection_indices));

      ASSERT (nconnections_this_batch > 0);
      vec_validate (connections_this_batch, nconnections_this_batch - 1);
      clib_memcpy (connections_this_batch,
		   connection_indices + vec_len (connection_indices)
		   - nconnections_this_batch,
		   nconnections_this_batch * sizeof (u32));
      _vec_len (connection_indices) -= nconnections_this_batch;
    }

  if (PREDICT_FALSE (ecm->prev_conns != ecm->connections_per_batch
		     && ecm->prev_conns == vec_len (connections_this_batch)))
    {
      ecm->repeats++;
      ecm->prev_conns = vec_len (connections_this_batch);
      if (ecm->repeats == 500000)
	{
	  clib_warning ("stuck clients");
	}
    }
  else
    {
      ecm->prev_conns = vec_len (connections_this_batch);
      ecm->repeats = 0;
    }

  for (i = 0; i < vec_len (connections_this_batch); i++)
    {
      delete_session = 1;

      sp = pool_elt_at_index (ecm->sessions, connections_this_batch[i]);

      if (sp->bytes_to_send > 0)
	{
	  send_data_chunk (ecm, sp);
	  delete_session = 0;
	}
      if (sp->bytes_to_receive > 0)
	{
	  delete_session = 0;
	}
      if (PREDICT_FALSE (delete_session == 1))
	{
	  stream_session_t *s;

	  clib_atomic_fetch_add (&ecm->tx_total, sp->bytes_sent);
	  clib_atomic_fetch_add (&ecm->rx_total, sp->bytes_received);
	  s = session_get_from_handle_if_valid (sp->vpp_session_handle);

	  if (s)
	    {
	      vnet_disconnect_args_t _a, *a = &_a;
	      a->handle = session_handle (s);
	      a->app_index = ecm->app_index;
	      vnet_disconnect_session (a);

	      vec_delete (connections_this_batch, 1, i);
	      i--;
	      clib_atomic_fetch_add (&ecm->ready_connections, -1);
	    }
	  else
	    {
	      clib_warning ("session AWOL?");
	      vec_delete (connections_this_batch, 1, i);
	    }

	  /* Kick the debug CLI process */
	  if (ecm->ready_connections == 0)
	    {
	      signal_evt_to_cli (2);
	    }
	}
    }

  ecm->connection_index_by_thread[my_thread_index] = connection_indices;
  ecm->connections_this_batch_by_thread[my_thread_index] =
    connections_this_batch;
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (echo_clients_node) =
{
  .function = echo_client_node_fn,
  .name = "echo-clients",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */

static int
create_api_loopback (echo_client_main_t * ecm)
{
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr;

  shmem_hdr = am->shmem_hdr;
  ecm->vl_input_queue = shmem_hdr->vl_input_queue;
  ecm->my_client_index = vl_api_memclnt_create_internal ("echo_client",
							 ecm->vl_input_queue);
  return 0;
}

static int
echo_clients_init (vlib_main_t * vm)
{
  echo_client_main_t *ecm = &echo_client_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;
  int i;

  if (create_api_loopback (ecm))
    return -1;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  /* Init test data. Big buffer */
  vec_validate (ecm->connect_test_data, 4 * 1024 * 1024 - 1);
  for (i = 0; i < vec_len (ecm->connect_test_data); i++)
    ecm->connect_test_data[i] = i & 0xff;

  vec_validate (ecm->rx_buf, num_threads - 1);
  for (i = 0; i < num_threads; i++)
    vec_validate (ecm->rx_buf[i], vec_len (ecm->connect_test_data) - 1);

  ecm->is_init = 1;

  vec_validate (ecm->connection_index_by_thread, vtm->n_vlib_mains);
  vec_validate (ecm->connections_this_batch_by_thread, vtm->n_vlib_mains);
  vec_validate (ecm->vpp_event_queue, vtm->n_vlib_mains);

  return 0;
}

static int
echo_clients_session_connected_callback (u32 app_index, u32 api_context,
					 stream_session_t * s, u8 is_fail)
{
  echo_client_main_t *ecm = &echo_client_main;
  eclient_session_t *session;
  u32 session_index;
  u8 thread_index;

  if (PREDICT_FALSE (ecm->run_test != ECHO_CLIENTS_STARTING))
    return -1;

  if (is_fail)
    {
      clib_warning ("connection %d failed!", api_context);
      ecm->run_test = ECHO_CLIENTS_EXITING;
      signal_evt_to_cli (-1);
      return 0;
    }

  thread_index = s->thread_index;
  ASSERT (thread_index == vlib_get_thread_index ()
	  || session_transport_service_type (s) == TRANSPORT_SERVICE_CL);

  if (!ecm->vpp_event_queue[thread_index])
    ecm->vpp_event_queue[thread_index] =
      session_manager_get_vpp_event_queue (thread_index);

  /*
   * Setup session
   */
  clib_spinlock_lock_if_init (&ecm->sessions_lock);
  pool_get (ecm->sessions, session);
  clib_spinlock_unlock_if_init (&ecm->sessions_lock);

  clib_memset (session, 0, sizeof (*session));
  session_index = session - ecm->sessions;
  session->bytes_to_send = ecm->bytes_to_send;
  session->bytes_to_receive = ecm->no_return ? 0ULL : ecm->bytes_to_send;
  session->data.rx_fifo = s->server_rx_fifo;
  session->data.rx_fifo->client_session_index = session_index;
  session->data.tx_fifo = s->server_tx_fifo;
  session->data.tx_fifo->client_session_index = session_index;
  session->data.vpp_evt_q = ecm->vpp_event_queue[thread_index];
  session->vpp_session_handle = session_handle (s);

  if (ecm->is_dgram)
    {
      transport_connection_t *tc;
      tc = session_get_transport (s);
      clib_memcpy (&session->data.transport, tc,
		   sizeof (session->data.transport));
      session->data.is_dgram = 1;
    }

  vec_add1 (ecm->connection_index_by_thread[thread_index], session_index);
  clib_atomic_fetch_add (&ecm->ready_connections, 1);
  if (ecm->ready_connections == ecm->expected_connections)
    {
      ecm->run_test = ECHO_CLIENTS_RUNNING;
      /* Signal the CLI process that the action is starting... */
      signal_evt_to_cli (1);
    }

  return 0;
}

static void
echo_clients_session_reset_callback (stream_session_t * s)
{
  if (s->session_state == SESSION_STATE_READY)
    clib_warning ("Reset active connection %U", format_stream_session, s, 2);
  stream_session_cleanup (s);
  return;
}

static int
echo_clients_session_create_callback (stream_session_t * s)
{
  return 0;
}

static void
echo_clients_session_disconnect_callback (stream_session_t * s)
{
  echo_client_main_t *ecm = &echo_client_main;
  vnet_disconnect_args_t _a, *a = &_a;
  a->handle = session_handle (s);
  a->app_index = ecm->app_index;
  vnet_disconnect_session (a);
  return;
}

void
echo_clients_session_disconnect (stream_session_t * s)
{
  echo_client_main_t *ecm = &echo_client_main;
  vnet_disconnect_args_t _a, *a = &_a;
  a->handle = session_handle (s);
  a->app_index = ecm->app_index;
  vnet_disconnect_session (a);
}

static int
echo_clients_rx_callback (stream_session_t * s)
{
  echo_client_main_t *ecm = &echo_client_main;
  eclient_session_t *sp;

  if (PREDICT_FALSE (ecm->run_test != ECHO_CLIENTS_RUNNING))
    {
      echo_clients_session_disconnect (s);
      return -1;
    }

  sp = pool_elt_at_index (ecm->sessions,
			  s->server_rx_fifo->client_session_index);
  receive_data_chunk (ecm, sp);

  if (svm_fifo_max_dequeue (s->server_rx_fifo))
    {
      if (svm_fifo_set_event (s->server_rx_fifo))
	session_send_io_evt_to_thread (s->server_rx_fifo,
				       FIFO_EVENT_BUILTIN_RX);
    }
  return 0;
}

int
echo_client_add_segment_callback (u32 client_index, const ssvm_private_t * sp)
{
  /* New heaps may be added */
  return 0;
}

/* *INDENT-OFF* */
static session_cb_vft_t echo_clients = {
  .session_reset_callback = echo_clients_session_reset_callback,
  .session_connected_callback = echo_clients_session_connected_callback,
  .session_accept_callback = echo_clients_session_create_callback,
  .session_disconnect_callback = echo_clients_session_disconnect_callback,
  .builtin_app_rx_callback = echo_clients_rx_callback,
  .add_segment_callback = echo_client_add_segment_callback
};
/* *INDENT-ON* */

static clib_error_t *
echo_clients_attach (u8 * appns_id, u64 appns_flags, u64 appns_secret)
{
  u32 prealloc_fifos, segment_size = 256 << 20;
  echo_client_main_t *ecm = &echo_client_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[16];
  clib_error_t *error = 0;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = ecm->my_client_index;
  a->session_cb_vft = &echo_clients;

  prealloc_fifos = ecm->prealloc_fifos ? ecm->expected_connections : 1;

  if (ecm->private_segment_size)
    segment_size = ecm->private_segment_size;

  options[APP_OPTIONS_ACCEPT_COOKIE] = 0x12345678;
  options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  options[APP_OPTIONS_RX_FIFO_SIZE] = ecm->fifo_size;
  options[APP_OPTIONS_TX_FIFO_SIZE] = ecm->fifo_size;
  options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT] = ecm->private_segment_count;
  options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = prealloc_fifos;
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_TLS_ENGINE] = ecm->tls_engine;
  if (appns_id)
    {
      options[APP_OPTIONS_FLAGS] |= appns_flags;
      options[APP_OPTIONS_NAMESPACE_SECRET] = appns_secret;
    }
  a->options = options;
  a->namespace_id = appns_id;

  if ((error = vnet_application_attach (a)))
    return error;

  ecm->app_index = a->app_index;
  return 0;
}

static int
echo_clients_detach ()
{
  echo_client_main_t *ecm = &echo_client_main;
  vnet_app_detach_args_t _da, *da = &_da;
  int rv;

  da->app_index = ecm->app_index;
  rv = vnet_application_detach (da);
  ecm->test_client_attached = 0;
  ecm->app_index = ~0;
  return rv;
}

static void *
echo_client_thread_fn (void *arg)
{
  return 0;
}

/** Start a transmit thread */
int
echo_clients_start_tx_pthread (echo_client_main_t * ecm)
{
  if (ecm->client_thread_handle == 0)
    {
      int rv = pthread_create (&ecm->client_thread_handle,
			       NULL /*attr */ ,
			       echo_client_thread_fn, 0);
      if (rv)
	{
	  ecm->client_thread_handle = 0;
	  return -1;
	}
    }
  return 0;
}

clib_error_t *
echo_clients_connect (vlib_main_t * vm, u32 n_clients)
{
  echo_client_main_t *ecm = &echo_client_main;
  vnet_connect_args_t _a, *a = &_a;
  clib_error_t *error = 0;
  int i;

  clib_memset (a, 0, sizeof (*a));
  for (i = 0; i < n_clients; i++)
    {
      a->uri = (char *) ecm->connect_uri;
      a->api_context = i;
      a->app_index = ecm->app_index;

      if ((error = vnet_connect_uri (a)))
	return error;

      /* Crude pacing for call setups  */
      if ((i % 4) == 0)
	vlib_process_suspend (vm, 10e-6);
      ASSERT (i + 1 >= ecm->ready_connections);
      while (i + 1 - ecm->ready_connections > 1000)
	{
	  vlib_process_suspend (vm, 100e-6);
	}
    }
  return 0;
}

#define ec_cli_output(_fmt, _args...) 			\
  if (!ecm->no_output)  				\
    vlib_cli_output(vm, _fmt, ##_args)

static clib_error_t *
echo_clients_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  echo_client_main_t *ecm = &echo_client_main;
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();
  u64 tmp, total_bytes, appns_flags = 0, appns_secret = 0;
  f64 test_timeout = 20.0, syn_timeout = 20.0, delta;
  char *default_uri = "tcp://6.0.1.1/1234";
  uword *event_data = 0, event_type;
  f64 time_before_connects;
  u32 n_clients = 1;
  int preallocate_sessions = 0;
  char *transfer_type;
  clib_error_t *error = 0;
  u8 *appns_id = 0;
  int i;

  ecm->bytes_to_send = 8192;
  ecm->no_return = 0;
  ecm->fifo_size = 64 << 10;
  ecm->connections_per_batch = 1000;
  ecm->private_segment_count = 0;
  ecm->private_segment_size = 0;
  ecm->no_output = 0;
  ecm->test_bytes = 0;
  ecm->test_failed = 0;
  ecm->vlib_main = vm;
  ecm->tls_engine = TLS_ENGINE_OPENSSL;
  ecm->no_copy = 0;
  ecm->run_test = ECHO_CLIENTS_STARTING;

  if (thread_main->n_vlib_mains > 1)
    clib_spinlock_init (&ecm->sessions_lock);
  vec_free (ecm->connect_uri);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "uri %s", &ecm->connect_uri))
	;
      else if (unformat (input, "nclients %d", &n_clients))
	;
      else if (unformat (input, "mbytes %lld", &tmp))
	ecm->bytes_to_send = tmp << 20;
      else if (unformat (input, "gbytes %lld", &tmp))
	ecm->bytes_to_send = tmp << 30;
      else if (unformat (input, "bytes %lld", &ecm->bytes_to_send))
	;
      else if (unformat (input, "test-timeout %f", &test_timeout))
	;
      else if (unformat (input, "syn-timeout %f", &syn_timeout))
	;
      else if (unformat (input, "no-return"))
	ecm->no_return = 1;
      else if (unformat (input, "fifo-size %d", &ecm->fifo_size))
	ecm->fifo_size <<= 10;
      else if (unformat (input, "private-segment-count %d",
			 &ecm->private_segment_count))
	;
      else if (unformat (input, "private-segment-size %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    return clib_error_return
	      (0, "private segment size %lld (%llu) too large", tmp, tmp);
	  ecm->private_segment_size = tmp;
	}
      else if (unformat (input, "preallocate-fifos"))
	ecm->prealloc_fifos = 1;
      else if (unformat (input, "preallocate-sessions"))
	preallocate_sessions = 1;
      else
	if (unformat (input, "client-batch %d", &ecm->connections_per_batch))
	;
      else if (unformat (input, "appns %_%v%_", &appns_id))
	;
      else if (unformat (input, "all-scope"))
	appns_flags |= (APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE
			| APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE);
      else if (unformat (input, "local-scope"))
	appns_flags = APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
      else if (unformat (input, "global-scope"))
	appns_flags = APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
      else if (unformat (input, "secret %lu", &appns_secret))
	;
      else if (unformat (input, "no-output"))
	ecm->no_output = 1;
      else if (unformat (input, "test-bytes"))
	ecm->test_bytes = 1;
      else if (unformat (input, "tls-engine %d", &ecm->tls_engine))
	;
      else
	return clib_error_return (0, "failed: unknown input `%U'",
				  format_unformat_error, input);
    }

  /* Store cli process node index for signalling */
  ecm->cli_node_index =
    vlib_get_current_process (vm)->node_runtime.node_index;

  if (ecm->is_init == 0)
    {
      if (echo_clients_init (vm))
	return clib_error_return (0, "failed init");
    }


  ecm->ready_connections = 0;
  ecm->expected_connections = n_clients;
  ecm->rx_total = 0;
  ecm->tx_total = 0;

  if (!ecm->connect_uri)
    {
      clib_warning ("No uri provided. Using default: %s", default_uri);
      ecm->connect_uri = format (0, "%s%c", default_uri, 0);
    }

  if (ecm->connect_uri[0] == 'u' && ecm->connect_uri[3] != 'c')
    ecm->is_dgram = 1;

#if ECHO_CLIENT_PTHREAD
  echo_clients_start_tx_pthread ();
#endif

  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, 1 /* turn on session and transports */ );
  vlib_worker_thread_barrier_release (vm);

  if (ecm->test_client_attached == 0)
    {
      if ((error = echo_clients_attach (appns_id, appns_flags, appns_secret)))
	{
	  vec_free (appns_id);
	  clib_error_report (error);
	  return error;
	}
      vec_free (appns_id);
    }
  ecm->test_client_attached = 1;

  /* Turn on the builtin client input nodes */
  for (i = 0; i < thread_main->n_vlib_mains; i++)
    vlib_node_set_state (vlib_mains[i], echo_clients_node.index,
			 VLIB_NODE_STATE_POLLING);

  if (preallocate_sessions)
    pool_init_fixed (ecm->sessions, 1.1 * n_clients);

  /* Fire off connect requests */
  time_before_connects = vlib_time_now (vm);
  if ((error = echo_clients_connect (vm, n_clients)))
    goto cleanup;

  /* Park until the sessions come up, or ten seconds elapse... */
  vlib_process_wait_for_event_or_clock (vm, syn_timeout);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      ec_cli_output ("Timeout with only %d sessions active...",
		     ecm->ready_connections);
      error = clib_error_return (0, "failed: syn timeout with %d sessions",
				 ecm->ready_connections);
      goto cleanup;

    case 1:
      delta = vlib_time_now (vm) - time_before_connects;
      if (delta != 0.0)
	ec_cli_output ("%d three-way handshakes in %.2f seconds %.2f/s",
		       n_clients, delta, ((f64) n_clients) / delta);

      ecm->test_start_time = vlib_time_now (ecm->vlib_main);
      ec_cli_output ("Test started at %.6f", ecm->test_start_time);
      break;

    default:
      ec_cli_output ("unexpected event(1): %d", event_type);
      error = clib_error_return (0, "failed: unexpected event(1): %d",
				 event_type);
      goto cleanup;
    }

  /* Now wait for the sessions to finish... */
  vlib_process_wait_for_event_or_clock (vm, test_timeout);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      ec_cli_output ("Timeout with %d sessions still active...",
		     ecm->ready_connections);
      error = clib_error_return (0, "failed: timeout with %d sessions",
				 ecm->ready_connections);
      goto cleanup;

    case 2:
      ecm->test_end_time = vlib_time_now (vm);
      ec_cli_output ("Test finished at %.6f", ecm->test_end_time);
      break;

    default:
      ec_cli_output ("unexpected event(2): %d", event_type);
      error = clib_error_return (0, "failed: unexpected event(2): %d",
				 event_type);
      goto cleanup;
    }

  delta = ecm->test_end_time - ecm->test_start_time;
  if (delta != 0.0)
    {
      total_bytes = (ecm->no_return ? ecm->tx_total : ecm->rx_total);
      transfer_type = ecm->no_return ? "half-duplex" : "full-duplex";
      ec_cli_output ("%lld bytes (%lld mbytes, %lld gbytes) in %.2f seconds",
		     total_bytes, total_bytes / (1ULL << 20),
		     total_bytes / (1ULL << 30), delta);
      ec_cli_output ("%.2f bytes/second %s", ((f64) total_bytes) / (delta),
		     transfer_type);
      ec_cli_output ("%.4f gbit/second %s",
		     (((f64) total_bytes * 8.0) / delta / 1e9),
		     transfer_type);
    }
  else
    {
      ec_cli_output ("zero delta-t?");
      error = clib_error_return (0, "failed: zero delta-t");
      goto cleanup;
    }

  if (ecm->test_bytes && ecm->test_failed)
    error = clib_error_return (0, "failed: test bytes");

cleanup:
  ecm->run_test = ECHO_CLIENTS_EXITING;
  vlib_process_wait_for_event_or_clock (vm, 10e-3);
  for (i = 0; i < vec_len (ecm->connection_index_by_thread); i++)
    {
      vec_reset_length (ecm->connection_index_by_thread[i]);
      vec_reset_length (ecm->connections_this_batch_by_thread[i]);
    }

  pool_free (ecm->sessions);

  /* Detach the application, so we can use different fifo sizes next time */
  if (ecm->test_client_attached)
    {
      if (echo_clients_detach ())
	{
	  error = clib_error_return (0, "failed: app detach");
	  ec_cli_output ("WARNING: app detach failed...");
	}
    }
  if (error)
    ec_cli_output ("test failed");
  vec_free (ecm->connect_uri);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (echo_clients_command, static) =
{
  .path = "test echo clients",
  .short_help = "test echo clients [nclients %d][[m|g]bytes <bytes>]"
      "[test-timeout <time>][syn-timeout <time>][no-return][fifo-size <size>]"
      "[private-segment-count <count>][private-segment-size <bytes>[m|g]]"
      "[preallocate-fifos][preallocate-sessions][client-batch <batch-size>]"
      "[uri <tcp://ip/port>][test-bytes][no-output]",
  .function = echo_clients_command_fn,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

clib_error_t *
echo_clients_main_init (vlib_main_t * vm)
{
  echo_client_main_t *ecm = &echo_client_main;
  ecm->is_init = 0;
  return 0;
}

VLIB_INIT_FUNCTION (echo_clients_main_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
