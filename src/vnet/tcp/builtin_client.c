/*
 * builtin_client.c - vpp built-in tcp client/connect code
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
#include <vnet/plugin/plugin.h>
#include <vnet/tcp/builtin_client.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

#define TCP_BUILTIN_CLIENT_DBG (0)

static void
signal_evt_to_cli_i (int *code)
{
  tclient_main_t *tm = &tclient_main;
  ASSERT (vlib_get_thread_index () == 0);
  vlib_process_signal_event (tm->vlib_main, tm->cli_node_index, *code, 0);
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
send_test_chunk (tclient_main_t * tm, session_t * s)
{
  u8 *test_data = tm->connect_test_data;
  int test_buf_offset;
  u32 bytes_this_chunk;
  session_fifo_event_t evt;
  static int serial_number = 0;
  svm_fifo_t *txf;
  int rv;

  ASSERT (vec_len (test_data) > 0);

  test_buf_offset = s->bytes_sent % vec_len (test_data);
  bytes_this_chunk = vec_len (test_data) - test_buf_offset;

  bytes_this_chunk = bytes_this_chunk < s->bytes_to_send
    ? bytes_this_chunk : s->bytes_to_send;

  txf = s->server_tx_fifo;
  rv = svm_fifo_enqueue_nowait (txf, bytes_this_chunk,
				test_data + test_buf_offset);

  /* If we managed to enqueue data... */
  if (rv > 0)
    {
      /* Account for it... */
      s->bytes_to_send -= rv;
      s->bytes_sent += rv;

      if (TCP_BUILTIN_CLIENT_DBG)
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

      /* Poke the session layer */
      if (svm_fifo_set_event (txf))
	{
	  /* Fabricate TX event, send to vpp */
	  evt.fifo = txf;
	  evt.event_type = FIFO_EVENT_APP_TX;
	  evt.event_id = serial_number++;

	  if (unix_shared_memory_queue_add
	      (tm->vpp_event_queue[txf->master_thread_index], (u8 *) & evt,
	       0 /* do wait for mutex */ ))
	    clib_warning ("could not enqueue event");
	}
    }
}

static void
receive_test_chunk (tclient_main_t * tm, session_t * s)
{
  svm_fifo_t *rx_fifo = s->server_rx_fifo;
  int n_read, test_bytes = 0;
  u32 my_thread_index = vlib_get_thread_index ();

  /* Allow enqueuing of new event */
  // svm_fifo_unset_event (rx_fifo);

  if (test_bytes)
    {
      n_read = svm_fifo_dequeue_nowait (rx_fifo,
					vec_len (tm->rx_buf[my_thread_index]),
					tm->rx_buf[my_thread_index]);
    }
  else
    {
      n_read = svm_fifo_max_dequeue (rx_fifo);
      svm_fifo_dequeue_drop (rx_fifo, n_read);
    }

  if (n_read > 0)
    {
      if (TCP_BUILTIN_CLIENT_DBG)
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

      if (test_bytes)
	{
	  int i;
	  for (i = 0; i < n_read; i++)
	    {
	      if (tm->rx_buf[my_thread_index][i]
		  != ((s->bytes_received + i) & 0xff))
		{
		  clib_warning ("read %d error at byte %lld, 0x%x not 0x%x",
				n_read, s->bytes_received + i,
				tm->rx_buf[my_thread_index][i],
				((s->bytes_received + i) & 0xff));
		}
	    }
	}
      s->bytes_to_receive -= n_read;
      s->bytes_received += n_read;
    }
}

static uword
builtin_client_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * frame)
{
  tclient_main_t *tm = &tclient_main;
  int my_thread_index = vlib_get_thread_index ();
  session_t *sp;
  int i;
  int delete_session;
  u32 *connection_indices;
  u32 *connections_this_batch;
  u32 nconnections_this_batch;

  connection_indices = tm->connection_index_by_thread[my_thread_index];
  connections_this_batch =
    tm->connections_this_batch_by_thread[my_thread_index];

  if ((tm->run_test == 0) ||
      ((vec_len (connection_indices) == 0)
       && vec_len (connections_this_batch) == 0))
    return 0;

  /* Grab another pile of connections */
  if (PREDICT_FALSE (vec_len (connections_this_batch) == 0))
    {
      nconnections_this_batch =
	clib_min (tm->connections_per_batch, vec_len (connection_indices));

      ASSERT (nconnections_this_batch > 0);
      vec_validate (connections_this_batch, nconnections_this_batch - 1);
      clib_memcpy (connections_this_batch,
		   connection_indices + vec_len (connection_indices)
		   - nconnections_this_batch,
		   nconnections_this_batch * sizeof (u32));
      _vec_len (connection_indices) -= nconnections_this_batch;
    }

  if (PREDICT_FALSE (tm->prev_conns != tm->connections_per_batch
		     && tm->prev_conns == vec_len (connections_this_batch)))
    {
      tm->repeats++;
      tm->prev_conns = vec_len (connections_this_batch);
      if (tm->repeats == 500000)
	{
	  clib_warning ("stuck clients");
	}
    }
  else
    {
      tm->prev_conns = vec_len (connections_this_batch);
      tm->repeats = 0;
    }

  for (i = 0; i < vec_len (connections_this_batch); i++)
    {
      delete_session = 1;

      sp = pool_elt_at_index (tm->sessions, connections_this_batch[i]);

      if (sp->bytes_to_send > 0)
	{
	  send_test_chunk (tm, sp);
	  delete_session = 0;
	}
      if (sp->bytes_to_receive > 0)
	{
	  receive_test_chunk (tm, sp);
	  delete_session = 0;
	}
      if (PREDICT_FALSE (delete_session == 1))
	{
	  u32 index, thread_index;
	  stream_session_t *s;

	  __sync_fetch_and_add (&tm->tx_total, sp->bytes_sent);
	  __sync_fetch_and_add (&tm->rx_total, sp->bytes_received);

	  stream_session_parse_handle (sp->vpp_session_handle,
				       &index, &thread_index);
	  s = stream_session_get_if_valid (index, thread_index);

	  if (s)
	    {
	      vnet_disconnect_args_t _a, *a = &_a;
	      a->handle = stream_session_handle (s);
	      a->app_index = tm->app_index;
	      vnet_disconnect_session (a);

	      vec_delete (connections_this_batch, 1, i);
	      i--;
	      __sync_fetch_and_add (&tm->ready_connections, -1);
	    }
	  else
	    clib_warning ("session AWOL?");

	  /* Kick the debug CLI process */
	  if (tm->ready_connections == 0)
	    {
	      signal_evt_to_cli (2);
	    }
	}
    }

  tm->connection_index_by_thread[my_thread_index] = connection_indices;
  tm->connections_this_batch_by_thread[my_thread_index] =
    connections_this_batch;
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (builtin_client_node) =
{
  .function = builtin_client_node_fn,
  .name = "builtin-tcp-client",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */

static int
create_api_loopback (tclient_main_t * tm)
{
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr;

  shmem_hdr = am->shmem_hdr;
  tm->vl_input_queue = shmem_hdr->vl_input_queue;
  tm->my_client_index =
    vl_api_memclnt_create_internal ("tcp_test_client", tm->vl_input_queue);
  return 0;
}

static int
tcp_test_clients_init (vlib_main_t * vm)
{
  tclient_main_t *tm = &tclient_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;
  int i;

  if (create_api_loopback (tm))
    return -1;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  /* Init test data. Big buffer */
  vec_validate (tm->connect_test_data, 1024 * 1024 - 1);
  for (i = 0; i < vec_len (tm->connect_test_data); i++)
    tm->connect_test_data[i] = i & 0xff;

  vec_validate (tm->rx_buf, num_threads - 1);
  for (i = 0; i < num_threads; i++)
    vec_validate (tm->rx_buf[i], vec_len (tm->connect_test_data) - 1);

  tm->is_init = 1;

  vec_validate (tm->connection_index_by_thread, vtm->n_vlib_mains);
  vec_validate (tm->connections_this_batch_by_thread, vtm->n_vlib_mains);
  vec_validate (tm->vpp_event_queue, vtm->n_vlib_mains);

  return 0;
}

static int
builtin_session_connected_callback (u32 app_index, u32 api_context,
				    stream_session_t * s, u8 is_fail)
{
  tclient_main_t *tm = &tclient_main;
  session_t *session;
  u32 session_index;
  u8 thread_index = vlib_get_thread_index ();

  if (is_fail)
    {
      clib_warning ("connection %d failed!", api_context);
      signal_evt_to_cli (-1);
      return 0;
    }

  ASSERT (s->thread_index == thread_index);

  if (!tm->vpp_event_queue[thread_index])
    tm->vpp_event_queue[thread_index] =
      session_manager_get_vpp_event_queue (thread_index);

  /*
   * Setup session
   */
  clib_spinlock_lock_if_init (&tm->sessions_lock);
  pool_get (tm->sessions, session);
  clib_spinlock_unlock_if_init (&tm->sessions_lock);

  memset (session, 0, sizeof (*session));
  session_index = session - tm->sessions;
  session->bytes_to_send = tm->bytes_to_send;
  session->bytes_to_receive = tm->no_return ? 0ULL : tm->bytes_to_send;
  session->server_rx_fifo = s->server_rx_fifo;
  session->server_rx_fifo->client_session_index = session_index;
  session->server_tx_fifo = s->server_tx_fifo;
  session->server_tx_fifo->client_session_index = session_index;
  session->vpp_session_handle = stream_session_handle (s);

  vec_add1 (tm->connection_index_by_thread[thread_index], session_index);
  __sync_fetch_and_add (&tm->ready_connections, 1);
  if (tm->ready_connections == tm->expected_connections)
    {
      tm->run_test = 1;
      /* Signal the CLI process that the action is starting... */
      signal_evt_to_cli (1);
    }

  return 0;
}

static void
builtin_session_reset_callback (stream_session_t * s)
{
  if (s->session_state == SESSION_STATE_READY)
    clib_warning ("Reset active connection %U", format_stream_session, s, 2);
  stream_session_cleanup (s);
  return;
}

static int
builtin_session_create_callback (stream_session_t * s)
{
  return 0;
}

static void
builtin_session_disconnect_callback (stream_session_t * s)
{
  tclient_main_t *tm = &tclient_main;
  vnet_disconnect_args_t _a, *a = &_a;
  a->handle = stream_session_handle (s);
  a->app_index = tm->app_index;
  vnet_disconnect_session (a);
  return;
}

static int
builtin_server_rx_callback (stream_session_t * s)
{
  return 0;
}

/* *INDENT-OFF* */
static session_cb_vft_t builtin_clients = {
  .session_reset_callback = builtin_session_reset_callback,
  .session_connected_callback = builtin_session_connected_callback,
  .session_accept_callback = builtin_session_create_callback,
  .session_disconnect_callback = builtin_session_disconnect_callback,
  .builtin_server_rx_callback = builtin_server_rx_callback
};
/* *INDENT-ON* */

static int
attach_builtin_test_clients_app (void)
{
  tclient_main_t *tm = &tclient_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u8 segment_name[128];
  u32 segment_name_length, prealloc_fifos;
  u64 options[16];

  segment_name_length = ARRAY_LEN (segment_name);

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  a->api_client_index = tm->my_client_index;
  a->segment_name = segment_name;
  a->segment_name_length = segment_name_length;
  a->session_cb_vft = &builtin_clients;

  prealloc_fifos = tm->prealloc_fifos ? tm->expected_connections : 1;

  options[SESSION_OPTIONS_ACCEPT_COOKIE] = 0x12345678;
  options[SESSION_OPTIONS_SEGMENT_SIZE] = (2ULL << 32);
  options[SESSION_OPTIONS_RX_FIFO_SIZE] = tm->fifo_size;
  options[SESSION_OPTIONS_TX_FIFO_SIZE] = tm->fifo_size;
  options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT] = tm->private_segment_count;
  options[APP_OPTIONS_PRIVATE_SEGMENT_SIZE] = tm->private_segment_size;
  options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = prealloc_fifos;

  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_BUILTIN_APP;

  a->options = options;

  if (vnet_application_attach (a))
    return -1;

  tm->app_index = a->app_index;
  return 0;
}

static void *
tclient_thread_fn (void *arg)
{
  return 0;
}

/** Start a transmit thread */
int
start_tx_pthread (tclient_main_t * tm)
{
  if (tm->client_thread_handle == 0)
    {
      int rv = pthread_create (&tm->client_thread_handle,
			       NULL /*attr */ ,
			       tclient_thread_fn, 0);
      if (rv)
	{
	  tm->client_thread_handle = 0;
	  return -1;
	}
    }
  return 0;
}

void
clients_connect (vlib_main_t * vm, u8 * uri, u32 n_clients)
{
  tclient_main_t *tm = &tclient_main;
  vnet_connect_args_t _a, *a = &_a;
  int i;
  for (i = 0; i < n_clients; i++)
    {
      memset (a, 0, sizeof (*a));

      a->uri = (char *) uri;
      a->api_context = i;
      a->app_index = tm->app_index;
      a->mp = 0;
      vnet_connect_uri (a);

      /* Crude pacing for call setups  */
      if ((i % 4) == 0)
	vlib_process_suspend (vm, 10e-6);
      ASSERT (i + 1 >= tm->ready_connections);
      while (i + 1 - tm->ready_connections > 1000)
	{
	  vlib_process_suspend (vm, 100e-6);
	}
    }
}

static clib_error_t *
test_tcp_clients_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  tclient_main_t *tm = &tclient_main;
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();
  uword *event_data = 0, event_type;
  u8 *default_connect_uri = (u8 *) "tcp://6.0.1.1/1234", *uri;
  u64 tmp, total_bytes;
  f64 test_timeout = 20.0, syn_timeout = 20.0, delta;
  f64 time_before_connects;
  u32 n_clients = 1;
  int preallocate_sessions = 0;
  char *transfer_type;
  int i;

  tm->bytes_to_send = 8192;
  tm->no_return = 0;
  tm->fifo_size = 64 << 10;
  tm->connections_per_batch = 1000;
  tm->private_segment_count = 0;
  tm->private_segment_size = 0;
  tm->vlib_main = vm;
  if (thread_main->n_vlib_mains > 1)
    clib_spinlock_init (&tm->sessions_lock);
  vec_free (tm->connect_uri);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "nclients %d", &n_clients))
	;
      else if (unformat (input, "mbytes %lld", &tmp))
	tm->bytes_to_send = tmp << 20;
      else if (unformat (input, "gbytes %lld", &tmp))
	tm->bytes_to_send = tmp << 30;
      else if (unformat (input, "bytes %lld", &tm->bytes_to_send))
	;
      else if (unformat (input, "uri %s", &tm->connect_uri))
	;
      else if (unformat (input, "test-timeout %f", &test_timeout))
	;
      else if (unformat (input, "syn-timeout %f", &syn_timeout))
	;
      else if (unformat (input, "no-return"))
	tm->no_return = 1;
      else if (unformat (input, "fifo-size %d", &tm->fifo_size))
	tm->fifo_size <<= 10;
      else if (unformat (input, "private-segment-count %d",
			 &tm->private_segment_count))
	;
      else if (unformat (input, "private-segment-size %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    return clib_error_return
	      (0, "private segment size %lld (%llu) too large", tmp, tmp);
	  tm->private_segment_size = tmp;
	}
      else if (unformat (input, "preallocate-fifos"))
	tm->prealloc_fifos = 1;
      else if (unformat (input, "preallocate-sessions"))
	preallocate_sessions = 1;
      else
	if (unformat (input, "client-batch %d", &tm->connections_per_batch))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  /* Store cli process node index for signalling */
  tm->cli_node_index = vlib_get_current_process (vm)->node_runtime.node_index;

  if (tm->is_init == 0)
    {
      if (tcp_test_clients_init (vm))
	return clib_error_return (0, "failed init");
    }


  tm->ready_connections = 0;
  tm->expected_connections = n_clients;
  tm->rx_total = 0;
  tm->tx_total = 0;

  uri = default_connect_uri;
  if (tm->connect_uri)
    uri = tm->connect_uri;

#if TCP_BUILTIN_CLIENT_PTHREAD
  start_tx_pthread ();
#endif

  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );
  vlib_worker_thread_barrier_release (vm);

  if (tm->test_client_attached == 0)
    {
      if (attach_builtin_test_clients_app ())
	{
	  return clib_error_return (0, "app attach failed");
	}
    }
  tm->test_client_attached = 1;

  /* Turn on the builtin client input nodes */
  for (i = 0; i < thread_main->n_vlib_mains; i++)
    vlib_node_set_state (vlib_mains[i], builtin_client_node.index,
			 VLIB_NODE_STATE_POLLING);

  if (preallocate_sessions)
    {
      session_t *sp __attribute__ ((unused));
      for (i = 0; i < n_clients; i++)
	pool_get (tm->sessions, sp);
      for (i = 0; i < n_clients; i++)
	pool_put_index (tm->sessions, i);
    }

  /* Fire off connect requests */
  time_before_connects = vlib_time_now (vm);
  clients_connect (vm, uri, n_clients);

  /* Park until the sessions come up, or ten seconds elapse... */
  vlib_process_wait_for_event_or_clock (vm, syn_timeout);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      vlib_cli_output (vm, "Timeout with only %d sessions active...",
		       tm->ready_connections);
      goto cleanup;

    case 1:
      delta = vlib_time_now (vm) - time_before_connects;

      if (delta != 0.0)
	{
	  vlib_cli_output
	    (vm, "%d three-way handshakes in %.2f seconds, %.2f/sec",
	     n_clients, delta, ((f64) n_clients) / delta);
	}

      tm->test_start_time = vlib_time_now (tm->vlib_main);
      vlib_cli_output (vm, "Test started at %.6f", tm->test_start_time);
      break;

    default:
      vlib_cli_output (vm, "unexpected event(1): %d", event_type);
      goto cleanup;
    }

  /* Now wait for the sessions to finish... */
  vlib_process_wait_for_event_or_clock (vm, test_timeout);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      vlib_cli_output (vm, "Timeout with %d sessions still active...",
		       tm->ready_connections);
      goto cleanup;

    case 2:
      tm->test_end_time = vlib_time_now (vm);
      vlib_cli_output (vm, "Test finished at %.6f", tm->test_end_time);
      break;

    default:
      vlib_cli_output (vm, "unexpected event(2): %d", event_type);
      goto cleanup;
    }

  delta = tm->test_end_time - tm->test_start_time;

  if (delta != 0.0)
    {
      total_bytes = (tm->no_return ? tm->tx_total : tm->rx_total);
      transfer_type = tm->no_return ? "half-duplex" : "full-duplex";
      vlib_cli_output (vm,
		       "%lld bytes (%lld mbytes, %lld gbytes) in %.2f seconds",
		       total_bytes, total_bytes / (1ULL << 20),
		       total_bytes / (1ULL << 30), delta);
      vlib_cli_output (vm, "%.2f bytes/second %s",
		       ((f64) total_bytes) / (delta), transfer_type);
      vlib_cli_output (vm, "%.4f gbit/second %s",
		       (((f64) total_bytes * 8.0) / delta / 1e9),
		       transfer_type);
    }
  else
    vlib_cli_output (vm, "zero delta-t?");

cleanup:
  tm->run_test = 0;
  for (i = 0; i < vec_len (tm->connection_index_by_thread); i++)
    {
      vec_reset_length (tm->connection_index_by_thread[i]);
      vec_reset_length (tm->connections_this_batch_by_thread[i]);
    }

  pool_free (tm->sessions);

  /* Detach the application, so we can use different fifo sizes next time */
  if (tm->test_client_attached)
    {
      vnet_app_detach_args_t _da, *da = &_da;
      int rv;

      da->app_index = tm->app_index;

      rv = vnet_application_detach (da);
      if (rv)
	vlib_cli_output (vm, "WARNING: app detach failed...");
      tm->test_client_attached = 0;
      tm->app_index = ~0;
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_clients_command, static) =
{
  .path = "test tcp clients",
  .short_help = "test tcp clients [nclients %d] [[m|g]bytes <bytes>] "
      "[test-timeout <time>][syn-timeout <time>][no-return][fifo-size <size>]"
      "[private-segment-count <count>][private-segment-size <bytes>[m|g]]"
      "[preallocate-fifos][preallocate-sessions][client-batch <batch-size>]"
      "[uri <tcp://ip/port>]",
  .function = test_tcp_clients_command_fn,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

clib_error_t *
tcp_test_clients_main_init (vlib_main_t * vm)
{
  tclient_main_t *tm = &tclient_main;
  tm->is_init = 0;
  return 0;
}

VLIB_INIT_FUNCTION (tcp_test_clients_main_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
