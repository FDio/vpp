/*
 * echo_client.c - vpp built-in echo client code
 *
 * Copyright (c) 2017-2019 by Cisco and/or its affiliates.
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

#include <hs_apps/echo_client.h>

static ec_main_t ec_main;

#define ec_err(_fmt, _args...) clib_warning (_fmt, ##_args);

#define ec_dbg(_fmt, _args...)                                                \
  do                                                                          \
    {                                                                         \
      if (ec_main.cfg.verbose)                                                \
	ec_err (_fmt, ##_args);                                               \
    }                                                                         \
  while (0)

#define ec_cli(_fmt, _args...) vlib_cli_output (vm, _fmt, ##_args)

static void
signal_evt_to_cli_i (void *codep)
{
  ec_main_t *ecm = &ec_main;
  int code;

  ASSERT (vlib_get_thread_index () == 0);
  code = pointer_to_uword (codep);
  vlib_process_signal_event (ecm->vlib_main, ecm->cli_node_index, code, 0);
}

static void
signal_evt_to_cli (int code)
{
  if (vlib_get_thread_index () != 0)
    session_send_rpc_evt_to_thread_force (
      0, signal_evt_to_cli_i, uword_to_pointer ((uword) code, void *));
  else
    signal_evt_to_cli_i (uword_to_pointer ((uword) code, void *));
}

static inline ec_worker_t *
ec_worker_get (u32 thread_index)
{
  return vec_elt_at_index (ec_main.wrk, thread_index);
}

static inline ec_session_t *
ec_session_alloc (ec_worker_t *wrk)
{
  ec_session_t *ecs;

  pool_get_zero (wrk->sessions, ecs);
  ecs->session_index = ecs - wrk->sessions;
  ecs->thread_index = wrk->thread_index;

  return ecs;
}

static inline ec_session_t *
ec_session_get (ec_worker_t *wrk, u32 ec_index)
{
  return pool_elt_at_index (wrk->sessions, ec_index);
}

static void
send_data_chunk (ec_main_t *ecm, ec_session_t *es)
{
  u8 *test_data = ecm->connect_test_data;
  int test_buf_len, test_buf_offset, rv;
  u32 bytes_this_chunk;

  test_buf_len = vec_len (test_data);
  ASSERT (test_buf_len > 0);
  test_buf_offset = es->bytes_sent % test_buf_len;
  bytes_this_chunk =
    clib_min (test_buf_len - test_buf_offset, es->bytes_to_send);

  if (!es->is_dgram)
    {
      if (ecm->no_copy)
	{
	  svm_fifo_t *f = es->tx_fifo;
	  rv = clib_min (svm_fifo_max_enqueue_prod (f), bytes_this_chunk);
	  svm_fifo_enqueue_nocopy (f, rv);
	  session_send_io_evt_to_thread_custom (
	    &es->vpp_session_index, es->thread_index, SESSION_IO_EVT_TX);
	}
      else
	rv =
	  app_send_stream ((app_session_t *) es, test_data + test_buf_offset,
			   bytes_this_chunk, 0);
    }
  else
    {
      svm_fifo_t *f = es->tx_fifo;
      u32 max_enqueue = svm_fifo_max_enqueue_prod (f);

      if (max_enqueue < sizeof (session_dgram_hdr_t))
	return;

      max_enqueue -= sizeof (session_dgram_hdr_t);

      if (ecm->no_copy)
	{
	  session_dgram_hdr_t hdr;
	  app_session_transport_t *at = &es->transport;

	  rv = clib_min (max_enqueue, bytes_this_chunk);

	  hdr.data_length = rv;
	  hdr.data_offset = 0;
	  clib_memcpy_fast (&hdr.rmt_ip, &at->rmt_ip,
			    sizeof (ip46_address_t));
	  hdr.is_ip4 = at->is_ip4;
	  hdr.rmt_port = at->rmt_port;
	  clib_memcpy_fast (&hdr.lcl_ip, &at->lcl_ip,
			    sizeof (ip46_address_t));
	  hdr.lcl_port = at->lcl_port;
	  svm_fifo_enqueue (f, sizeof (hdr), (u8 *) & hdr);
	  svm_fifo_enqueue_nocopy (f, rv);
	  session_send_io_evt_to_thread_custom (
	    &es->vpp_session_index, es->thread_index, SESSION_IO_EVT_TX);
	}
      else
	{
	  bytes_this_chunk = clib_min (bytes_this_chunk, max_enqueue);
	  bytes_this_chunk = clib_min (bytes_this_chunk, 1460);
	  rv =
	    app_send_dgram ((app_session_t *) es, test_data + test_buf_offset,
			    bytes_this_chunk, 0);
	}
    }

  /* If we managed to enqueue data... */
  if (rv > 0)
    {
      /* Account for it... */
      es->bytes_to_send -= rv;
      es->bytes_sent += rv;

      if (ecm->cfg.verbose)
	{
          ELOG_TYPE_DECLARE (e) =
            {
              .format = "tx-enq: xfer %d bytes, sent %u remain %u",
              .format_args = "i4i4i4",
            };
	  struct
	  {
	    u32 data[3];
	  } *ed;
	  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
	  ed->data[0] = rv;
	  ed->data[1] = es->bytes_sent;
	  ed->data[2] = es->bytes_to_send;
	}
    }
}

static void
receive_data_chunk (ec_worker_t *wrk, ec_session_t *es)
{
  ec_main_t *ecm = &ec_main;
  svm_fifo_t *rx_fifo = es->rx_fifo;
  int n_read, i;

  if (ecm->cfg.test_bytes)
    {
      n_read =
	app_recv ((app_session_t *) es, wrk->rx_buf, vec_len (wrk->rx_buf));
    }
  else
    {
      n_read = svm_fifo_max_dequeue_cons (rx_fifo);
      svm_fifo_dequeue_drop (rx_fifo, n_read);
    }

  if (n_read > 0)
    {
      if (ecm->cfg.verbose)
	{
          ELOG_TYPE_DECLARE (e) =
            {
              .format = "rx-deq: %d bytes",
              .format_args = "i4",
            };
	  struct
	  {
	    u32 data[1];
	  } *ed;
	  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
	  ed->data[0] = n_read;
	}

      if (ecm->cfg.test_bytes)
	{
	  for (i = 0; i < n_read; i++)
	    {
	      if (wrk->rx_buf[i] != ((es->bytes_received + i) & 0xff))
		{
		  ec_err ("read %d error at byte %lld, 0x%x not 0x%x", n_read,
			  es->bytes_received + i, wrk->rx_buf[i],
			  ((es->bytes_received + i) & 0xff));
		  ecm->test_failed = 1;
		}
	    }
	}
      ASSERT (n_read <= es->bytes_to_receive);
      es->bytes_to_receive -= n_read;
      es->bytes_received += n_read;
    }
}

static uword
ec_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *conn_indices, *conns_this_batch, nconns_this_batch;
  int thread_index = vm->thread_index, i, delete_session;
  ec_main_t *ecm = &ec_main;
  ec_worker_t *wrk;
  ec_session_t *es;
  session_t *s;

  if (ecm->run_test != EC_RUNNING)
    return 0;

  wrk = ec_worker_get (thread_index);
  conn_indices = wrk->conn_indices;
  conns_this_batch = wrk->conns_this_batch;

  if (((vec_len (conn_indices) == 0) && vec_len (conns_this_batch) == 0))
    return 0;

  /* Grab another pile of connections */
  if (PREDICT_FALSE (vec_len (conns_this_batch) == 0))
    {
      nconns_this_batch =
	clib_min (ecm->connections_per_batch, vec_len (conn_indices));

      ASSERT (nconns_this_batch > 0);
      vec_validate (conns_this_batch, nconns_this_batch - 1);
      clib_memcpy_fast (conns_this_batch,
			conn_indices + vec_len (conn_indices) -
			  nconns_this_batch,
			nconns_this_batch * sizeof (u32));
      vec_dec_len (conn_indices, nconns_this_batch);
    }

  /*
   * Track progress
   */
  if (PREDICT_FALSE (ecm->prev_conns != ecm->connections_per_batch &&
		     ecm->prev_conns == vec_len (conns_this_batch)))
    {
      ecm->repeats++;
      ecm->prev_conns = vec_len (conns_this_batch);
      if (ecm->repeats == 500000)
	{
	  ec_err ("stuck clients");
	}
    }
  else
    {
      ecm->prev_conns = vec_len (conns_this_batch);
      ecm->repeats = 0;
    }

  /*
   * Handle connections in this batch
   */
  for (i = 0; i < vec_len (conns_this_batch); i++)
    {
      es = ec_session_get (wrk, conns_this_batch[i]);

      delete_session = 1;

      if (es->bytes_to_send > 0)
	{
	  send_data_chunk (ecm, es);
	  delete_session = 0;
	}

      if (es->bytes_to_receive > 0)
	{
	  delete_session = 0;
	}

      if (PREDICT_FALSE (delete_session == 1))
	{
	  clib_atomic_fetch_add (&ecm->tx_total, es->bytes_sent);
	  clib_atomic_fetch_add (&ecm->rx_total, es->bytes_received);
	  s = session_get_from_handle_if_valid (es->vpp_session_handle);

	  if (s)
	    {
	      vnet_disconnect_args_t _a, *a = &_a;
	      a->handle = session_handle (s);
	      a->app_index = ecm->app_index;
	      vnet_disconnect_session (a);

	      vec_delete (conns_this_batch, 1, i);
	      i--;
	      clib_atomic_fetch_add (&ecm->ready_connections, -1);
	    }
	  else
	    {
	      ec_err ("session AWOL?");
	      vec_delete (conns_this_batch, 1, i);
	    }

	  /* Kick the debug CLI process */
	  if (ecm->ready_connections == 0)
	    {
	      signal_evt_to_cli (EC_CLI_TEST_DONE);
	    }
	}
    }

  wrk->conn_indices = conn_indices;
  wrk->conns_this_batch = conns_this_batch;
  return 0;
}

VLIB_REGISTER_NODE (echo_clients_node) = {
  .function = ec_node_fn,
  .name = "echo-clients",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};

static void
ec_reset_runtime_config (ec_main_t *ecm)
{
  hs_test_cfg_init (&ecm->cfg);
  ecm->n_clients = 1;
  ecm->quic_streams = 1;
  ecm->bytes_to_send = 8192;
  ecm->echo_bytes = 0;
  ecm->fifo_size = 64 << 10;
  ecm->connections_per_batch = 1000;
  ecm->private_segment_count = 0;
  ecm->private_segment_size = 256 << 20;
  ecm->test_failed = 0;
  ecm->tls_engine = CRYPTO_ENGINE_OPENSSL;
  ecm->no_copy = 0;
  ecm->run_test = EC_STARTING;
  ecm->ready_connections = 0;
  ecm->connect_conn_index = 0;
  ecm->rx_total = 0;
  ecm->tx_total = 0;
  ecm->barrier_acq_needed = 0;
  ecm->prealloc_sessions = 0;
  ecm->prealloc_fifos = 0;
  ecm->appns_id = 0;
  ecm->appns_secret = 0;
  ecm->attach_flags = 0;
  ecm->syn_timeout = 20.0;
  ecm->test_timeout = 20.0;
  vec_free (ecm->connect_uri);
}

static int
ec_init (vlib_main_t *vm)
{
  ec_main_t *ecm = &ec_main;
  ec_worker_t *wrk;
  u32 num_threads;
  int i;

  ec_reset_runtime_config (ecm);

  /* Store cli process node index for signaling */
  ecm->cli_node_index = vlib_get_current_process (vm)->node_runtime.node_index;
  ecm->vlib_main = vm;

  if (vlib_num_workers ())
    {
      /* The request came over the binary api and the inband cli handler
       * is not mp_safe. Drop the barrier to make sure the workers are not
       * blocked.
       */
      if (vlib_thread_is_main_w_barrier ())
	{
	  ecm->barrier_acq_needed = 1;
	  vlib_worker_thread_barrier_release (vm);
	}
      /*
       * There's a good chance that both the client and the server echo
       * apps will be enabled so make sure the session queue node polls on
       * the main thread as connections will probably be established on it.
       */
      vlib_node_set_state (vm, session_queue_node.index,
			   VLIB_NODE_STATE_POLLING);
    }

  /* App init done only once */
  if (ecm->app_is_init)
    return 0;


  /* Init test data. Big buffer */
  vec_validate (ecm->connect_test_data, 4 * 1024 * 1024 - 1);
  for (i = 0; i < vec_len (ecm->connect_test_data); i++)
    ecm->connect_test_data[i] = i & 0xff;

  num_threads = 1 /* main thread */ + vlib_num_workers ();
  vec_validate (ecm->wrk, num_threads - 1);
  vec_foreach (wrk, ecm->wrk)
    {
      vec_validate (wrk->rx_buf, vec_len (ecm->connect_test_data) - 1);
      wrk->thread_index = wrk - ecm->wrk;
      wrk->vpp_event_queue =
	session_main_get_vpp_event_queue (wrk->thread_index);
    }

  ecm->app_is_init = 1;

  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, 1 /* turn on session and transports */);

  /* Turn on the builtin client input nodes */
  foreach_vlib_main ()
    vlib_node_set_state (this_vlib_main, echo_clients_node.index,
			 VLIB_NODE_STATE_POLLING);

  vlib_worker_thread_barrier_release (vm);

  return 0;
}

static void
ec_prealloc_sessions (ec_main_t *ecm)
{
  u32 sessions_per_wrk, n_wrks;
  ec_worker_t *wrk;

  n_wrks = vlib_num_workers () ? vlib_num_workers () : 1;

  sessions_per_wrk = ecm->n_clients / n_wrks;
  vec_foreach (wrk, ecm->wrk)
    pool_init_fixed (wrk->sessions, 1.1 * sessions_per_wrk);
}

static void
ec_worker_cleanup (ec_worker_t *wrk)
{
  pool_free (wrk->sessions);
  vec_free (wrk->conn_indices);
  vec_free (wrk->conns_this_batch);
}

static void
ec_cleanup (ec_main_t *ecm)
{
  ec_worker_t *wrk;

  vec_foreach (wrk, ecm->wrk)
    ec_worker_cleanup (wrk);

  vec_free (ecm->connect_uri);
  vec_free (ecm->appns_id);

  if (ecm->barrier_acq_needed)
    vlib_worker_thread_barrier_sync (ecm->vlib_main);
}

static int
quic_ec_qsession_connected_callback (u32 app_index, u32 api_context,
				     session_t *s, session_error_t err)
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  ec_main_t *ecm = &ec_main;
  vnet_connect_args_t _a, *a = &_a;
  u32 stream_n;
  int rv;

  ec_dbg ("QUIC Connection handle %d", session_handle (s));

  a->uri = (char *) ecm->connect_uri;
  if (parse_uri (a->uri, &sep))
    return -1;
  sep.parent_handle = session_handle (s);

  for (stream_n = 0; stream_n < ecm->quic_streams; stream_n++)
    {
      clib_memset (a, 0, sizeof (*a));
      a->app_index = ecm->app_index;
      a->api_context = -2 - api_context;
      clib_memcpy (&a->sep_ext, &sep, sizeof (sep));

      ec_dbg ("QUIC opening stream %d", stream_n);
      if ((rv = vnet_connect (a)))
	{
	  clib_error ("Stream session %d opening failed: %d", stream_n, rv);
	  return -1;
	}
      ec_dbg ("QUIC stream %d connected", stream_n);
    }
  return 0;
}

static int
ec_ctrl_send (hs_test_cmd_t cmd)
{
  ec_main_t *ecm = &ec_main;
  session_t *s;
  int rv;

  ecm->cfg.cmd = cmd;
  if (ecm->ctrl_session_handle == SESSION_INVALID_HANDLE)
    {
      ec_dbg ("ctrl session went away");
      return -1;
    }

  s = session_get_from_handle_if_valid (ecm->ctrl_session_handle);
  if (!s)
    {
      ec_err ("ctrl session not found");
      return -1;
    }

  ec_dbg ("sending test paramters to the server..");
  if (ecm->cfg.verbose)
    hs_test_cfg_dump (&ecm->cfg, 1);

  rv = svm_fifo_enqueue (s->tx_fifo, sizeof (ecm->cfg), (u8 *) &ecm->cfg);
  ASSERT (rv == sizeof (ecm->cfg));
  session_send_io_evt_to_thread (s->tx_fifo, SESSION_IO_EVT_TX);
  return 0;
}

static int
ec_ctrl_session_connected_callback (session_t *s)
{
  ec_main_t *ecm = &ec_main;

  s->opaque = HS_CTRL_HANDLE;
  ecm->ctrl_session_handle = session_handle (s);

  /* send test parameters to the server */
  ec_ctrl_send (HS_TEST_CMD_SYNC);
  return 0;
}

static int
quic_ec_session_connected_callback (u32 app_index, u32 api_context,
				    session_t *s, session_error_t err)
{
  ec_main_t *ecm = &ec_main;
  ec_session_t *es;
  ec_worker_t *wrk;
  u32 thread_index;

  if (PREDICT_FALSE (api_context == HS_CTRL_HANDLE))
    return ec_ctrl_session_connected_callback (s);

  if (PREDICT_FALSE (ecm->run_test != EC_STARTING))
    return -1;

  if (err)
    {
      ec_err ("connection %d failed!", api_context);
      ecm->run_test = EC_EXITING;
      signal_evt_to_cli (EC_CLI_CONNECTS_FAILED);
      return 0;
    }

  if (s->listener_handle == SESSION_INVALID_HANDLE)
    return quic_ec_qsession_connected_callback (app_index, api_context, s,
						err);
  ec_dbg ("STREAM Connection callback %d", api_context);

  thread_index = s->thread_index;
  ASSERT (thread_index == vlib_get_thread_index ()
	  || session_transport_service_type (s) == TRANSPORT_SERVICE_CL);

  wrk = ec_worker_get (thread_index);

  /*
   * Setup session
   */
  es = ec_session_alloc (wrk);
  hs_test_app_session_init (es, s);

  es->bytes_to_send = ecm->bytes_to_send;
  es->bytes_to_receive = ecm->echo_bytes ? ecm->bytes_to_send : 0ULL;
  es->vpp_session_handle = session_handle (s);
  es->vpp_session_index = s->session_index;
  s->opaque = es->session_index;

  vec_add1 (wrk->conn_indices, es->session_index);
  clib_atomic_fetch_add (&ecm->ready_connections, 1);
  if (ecm->ready_connections == ecm->expected_connections)
    {
      ecm->run_test = EC_RUNNING;
      /* Signal the CLI process that the action is starting... */
      signal_evt_to_cli (EC_CLI_CONNECTS_DONE);
    }

  return 0;
}

static int
ec_session_connected_callback (u32 app_index, u32 api_context, session_t *s,
			       session_error_t err)
{
  ec_main_t *ecm = &ec_main;
  ec_session_t *es;
  u32 thread_index;
  ec_worker_t *wrk;

  if (PREDICT_FALSE (ecm->run_test != EC_STARTING))
    return -1;

  if (err)
    {
      ec_err ("connection %d failed! %U", api_context, format_session_error,
	      err);
      ecm->run_test = EC_EXITING;
      signal_evt_to_cli (EC_CLI_CONNECTS_FAILED);
      return 0;
    }

  thread_index = s->thread_index;
  ASSERT (thread_index == vlib_get_thread_index ()
	  || session_transport_service_type (s) == TRANSPORT_SERVICE_CL);

  if (PREDICT_FALSE (api_context == HS_CTRL_HANDLE))
    return ec_ctrl_session_connected_callback (s);

  wrk = ec_worker_get (thread_index);

  /*
   * Setup session
   */
  es = ec_session_alloc (wrk);
  hs_test_app_session_init (es, s);

  es->bytes_to_send = ecm->bytes_to_send;
  es->bytes_to_receive = ecm->echo_bytes ? ecm->bytes_to_send : 0ULL;
  es->vpp_session_handle = session_handle (s);
  es->vpp_session_index = s->session_index;
  s->opaque = es->session_index;

  vec_add1 (wrk->conn_indices, es->session_index);
  clib_atomic_fetch_add (&ecm->ready_connections, 1);
  if (ecm->ready_connections == ecm->expected_connections)
    {
      ecm->run_test = EC_RUNNING;
      /* Signal the CLI process that the action is starting... */
      signal_evt_to_cli (EC_CLI_CONNECTS_DONE);
    }

  return 0;
}

static void
ec_session_reset_callback (session_t *s)
{
  ec_main_t *ecm = &ec_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  if (s->session_state == SESSION_STATE_READY)
    ec_err ("Reset active connection %U", format_session, s, 2);

  a->handle = session_handle (s);
  a->app_index = ecm->app_index;
  vnet_disconnect_session (a);
  return;
}

static int
ec_session_accept_callback (session_t *s)
{
  return 0;
}

static void
ec_session_disconnect_callback (session_t *s)
{
  ec_main_t *ecm = &ec_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  if (session_handle (s) == ecm->ctrl_session_handle)
    {
      ec_dbg ("ctrl session disconnect");
      ecm->ctrl_session_handle = SESSION_INVALID_HANDLE;
    }

  a->handle = session_handle (s);
  a->app_index = ecm->app_index;
  vnet_disconnect_session (a);
  return;
}

void
ec_session_disconnect (session_t *s)
{
  ec_main_t *ecm = &ec_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  a->handle = session_handle (s);
  a->app_index = ecm->app_index;
  vnet_disconnect_session (a);
}

static int
ec_ctrl_session_rx_callback (session_t *s)
{
  ec_main_t *ecm = &ec_main;
  int rx_bytes;
  hs_test_cfg_t cfg = { 0 };

  rx_bytes = svm_fifo_dequeue (s->rx_fifo, sizeof (cfg), (u8 *) &cfg);
  if (rx_bytes != sizeof (cfg))
    {
      ec_err ("invalid cfg length %d (expected %d)", rx_bytes, sizeof (cfg));
      signal_evt_to_cli (EC_CLI_CONNECTS_FAILED);
      return -1;
    }

  ec_dbg ("control message received:");
  if (ecm->cfg.verbose)
    hs_test_cfg_dump (&cfg, 1);

  switch (cfg.cmd)
    {
    case HS_TEST_CMD_SYNC:
      switch (ecm->run_test)
	{
	case EC_STARTING:
	  if (!hs_test_cfg_verify (&cfg, &ecm->cfg))
	    {
	      ec_err ("invalid config received from server!");
	      signal_evt_to_cli (EC_CLI_CONNECTS_FAILED);
	      return -1;
	    }
	  signal_evt_to_cli (EC_CLI_CFG_SYNC);
	  break;

	case EC_RUNNING:
	  ec_dbg ("test running..");
	  break;

	case EC_EXITING:
	  /* post test sync */
	  signal_evt_to_cli (EC_CLI_CFG_SYNC);
	  break;

	default:
	  ec_err ("unexpected test state! %d", ecm->run_test);
	  break;
	}
      break;
    case HS_TEST_CMD_START:
      signal_evt_to_cli (EC_CLI_START);
      break;
    case HS_TEST_CMD_STOP:
      signal_evt_to_cli (EC_CLI_STOP);
      break;
    default:
      ec_err ("unexpected cmd! %d", cfg.cmd);
      break;
    }

  return 0;
}

static int
ec_session_rx_callback (session_t *s)
{
  ec_main_t *ecm = &ec_main;
  ec_worker_t *wrk;
  ec_session_t *es;

  if (PREDICT_FALSE (s->opaque == HS_CTRL_HANDLE))
    return ec_ctrl_session_rx_callback (s);

  if (PREDICT_FALSE (ecm->run_test != EC_RUNNING))
    {
      ec_session_disconnect (s);
      return -1;
    }

  wrk = ec_worker_get (s->thread_index);
  es = ec_session_get (wrk, s->opaque);

  receive_data_chunk (wrk, es);

  if (svm_fifo_max_dequeue_cons (s->rx_fifo))
    session_enqueue_notify (s);

  return 0;
}

static int
ec_add_segment_callback (u32 app_index, u64 segment_handle)
{
  /* New segments may be added */
  return 0;
}

static int
ec_del_segment_callback (u32 app_index, u64 segment_handle)
{
  return 0;
}

static session_cb_vft_t ec_cb_vft = {
  .session_reset_callback = ec_session_reset_callback,
  .session_connected_callback = ec_session_connected_callback,
  .session_accept_callback = ec_session_accept_callback,
  .session_disconnect_callback = ec_session_disconnect_callback,
  .builtin_app_rx_callback = ec_session_rx_callback,
  .add_segment_callback = ec_add_segment_callback,
  .del_segment_callback = ec_del_segment_callback,
};

static clib_error_t *
ec_attach ()
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  ec_main_t *ecm = &ec_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u32 prealloc_fifos;
  u64 options[18];
  int rv;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = ~0;
  a->name = format (0, "echo_client");
  if (ecm->transport_proto == TRANSPORT_PROTO_QUIC)
    ec_cb_vft.session_connected_callback = quic_ec_session_connected_callback;
  a->session_cb_vft = &ec_cb_vft;

  prealloc_fifos = ecm->prealloc_fifos ? ecm->expected_connections : 1;

  options[APP_OPTIONS_ACCEPT_COOKIE] = 0x12345678;
  options[APP_OPTIONS_SEGMENT_SIZE] = ecm->private_segment_size;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = ecm->private_segment_size;
  options[APP_OPTIONS_RX_FIFO_SIZE] = ecm->fifo_size;
  options[APP_OPTIONS_TX_FIFO_SIZE] = ecm->fifo_size;
  options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT] = ecm->private_segment_count;
  options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = prealloc_fifos;
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_TLS_ENGINE] = ecm->tls_engine;
  options[APP_OPTIONS_PCT_FIRST_ALLOC] = 100;
  options[APP_OPTIONS_FLAGS] |= ecm->attach_flags;
  if (ecm->appns_id)
    {
      options[APP_OPTIONS_NAMESPACE_SECRET] = ecm->appns_secret;
      a->namespace_id = ecm->appns_id;
    }
  a->options = options;

  if ((rv = vnet_application_attach (a)))
    return clib_error_return (0, "attach returned %d", rv);

  ecm->app_index = a->app_index;
  vec_free (a->name);

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  ecm->ckpair_index = ck_pair->index;

  ecm->test_client_attached = 1;

  return 0;
}

static int
ec_detach ()
{
  ec_main_t *ecm = &ec_main;
  vnet_app_detach_args_t _da, *da = &_da;
  int rv;

  if (!ecm->test_client_attached)
    return 0;

  da->app_index = ecm->app_index;
  da->api_client_index = ~0;
  rv = vnet_application_detach (da);
  ecm->test_client_attached = 0;
  ecm->app_index = ~0;
  vnet_app_del_cert_key_pair (ecm->ckpair_index);

  return rv;
}

static int
ec_transport_needs_crypto (transport_proto_t proto)
{
  return proto == TRANSPORT_PROTO_TLS || proto == TRANSPORT_PROTO_DTLS ||
	 proto == TRANSPORT_PROTO_QUIC;
}

static int
ec_connect_rpc (void *args)
{
  ec_main_t *ecm = &ec_main;
  vnet_connect_args_t _a = {}, *a = &_a;
  int rv, needs_crypto;
  u32 n_clients, ci;

  n_clients = ecm->n_clients;
  needs_crypto = ec_transport_needs_crypto (ecm->transport_proto);
  clib_memcpy (&a->sep_ext, &ecm->connect_sep, sizeof (ecm->connect_sep));
  a->sep_ext.transport_flags |= TRANSPORT_CFG_F_CONNECTED;
  a->app_index = ecm->app_index;

  ci = ecm->connect_conn_index;

  while (ci < n_clients)
    {
      /* Crude pacing for call setups  */
      if (ci - ecm->ready_connections > 128)
	{
	  ecm->connect_conn_index = ci;
	  break;
	}

      a->api_context = ci;
      if (needs_crypto)
	{
	  session_endpoint_alloc_ext_cfg (&a->sep_ext,
					  TRANSPORT_ENDPT_EXT_CFG_CRYPTO);
	  a->sep_ext.ext_cfg->crypto.ckpair_index = ecm->ckpair_index;
	}

      rv = vnet_connect (a);

      if (needs_crypto)
	clib_mem_free (a->sep_ext.ext_cfg);

      if (rv)
	{
	  ec_err ("connect returned: %U", format_session_error, rv);
	  ecm->run_test = EC_EXITING;
	  signal_evt_to_cli (EC_CLI_CONNECTS_FAILED);
	  break;
	}

      ci += 1;
    }

  if (ci < ecm->expected_connections && ecm->run_test != EC_EXITING)
    ec_program_connects ();

  return 0;
}

void
ec_program_connects (void)
{
  session_send_rpc_evt_to_thread_force (transport_cl_thread (), ec_connect_rpc,
					0);
}

static clib_error_t *
ec_ctrl_connect_rpc ()
{
  session_error_t rv;
  ec_main_t *ecm = &ec_main;
  vnet_connect_args_t _a = {}, *a = &_a;

  a->api_context = HS_CTRL_HANDLE;
  ecm->cfg.cmd = HS_TEST_CMD_SYNC;
  clib_memcpy (&a->sep_ext, &ecm->connect_sep, sizeof (ecm->connect_sep));
  a->sep_ext.transport_proto = TRANSPORT_PROTO_TCP;
  a->app_index = ecm->app_index;

  rv = vnet_connect (a);
  if (rv)
    {
      ec_err ("ctrl connect returned: %U", format_session_error, rv);
      ecm->run_test = EC_EXITING;
      signal_evt_to_cli (EC_CLI_CONNECTS_FAILED);
    }
  return 0;
}

static void
ec_ctrl_connect (void)
{
  session_send_rpc_evt_to_thread_force (transport_cl_thread (),
					ec_ctrl_connect_rpc, 0);
}

static void
ec_ctrl_session_disconnect ()
{
  ec_main_t *ecm = &ec_main;
  vnet_disconnect_args_t _a, *a = &_a;
  session_error_t err;

  a->handle = ecm->ctrl_session_handle;
  a->app_index = ecm->app_index;
  err = vnet_disconnect_session (a);
  if (err)
    ec_err ("vnet_disconnect_session: %U", format_session_error, err);
}

static int
ec_ctrl_test_sync ()
{
  ec_main_t *ecm = &ec_main;
  ecm->cfg.test = HS_TEST_TYPE_ECHO;
  return ec_ctrl_send (HS_TEST_CMD_SYNC);
}

static int
ec_ctrl_test_start ()
{
  return ec_ctrl_send (HS_TEST_CMD_START);
}

static int
ec_ctrl_test_stop ()
{
  return ec_ctrl_send (HS_TEST_CMD_STOP);
}

#define ec_wait_for_signal(_sig)                                              \
  vlib_process_wait_for_event_or_clock (vm, ecm->syn_timeout);                \
  event_type = vlib_process_get_events (vm, &event_data);                     \
  switch (event_type)                                                         \
    {                                                                         \
    case ~0:                                                                  \
      ec_cli ("Timeout while waiting for " #_sig);                            \
      error =                                                                 \
	clib_error_return (0, "failed: timeout while waiting for " #_sig);    \
      goto cleanup;                                                           \
    case _sig:                                                                \
      break;                                                                  \
    default:                                                                  \
      ec_cli ("unexpected event while waiting for " #_sig ": %d",             \
	      event_type);                                                    \
      error =                                                                 \
	clib_error_return (0, "failed: unexpected event: %d", event_type);    \
      goto cleanup;                                                           \
    }

static clib_error_t *
ec_command_fn (vlib_main_t *vm, unformat_input_t *input,
	       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  char *default_uri = "tcp://6.0.1.1/1234", *transfer_type;
  ec_main_t *ecm = &ec_main;
  uword *event_data = 0, event_type;
  clib_error_t *error = 0;
  int rv, had_config = 1;
  u64 tmp, total_bytes;
  f64 delta;

  if (ecm->test_client_attached)
    return clib_error_return (0, "failed: already running!");

  if (ec_init (vm))
    {
      error = clib_error_return (0, "failed init");
      goto cleanup;
    }

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      had_config = 0;
      goto parse_config;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "uri %s", &ecm->connect_uri))
	;
      else if (unformat (line_input, "nclients %d", &ecm->n_clients))
	;
      else if (unformat (line_input, "quic-streams %d", &ecm->quic_streams))
	;
      else if (unformat (line_input, "mbytes %lld", &tmp))
	ecm->bytes_to_send = tmp << 20;
      else if (unformat (line_input, "gbytes %lld", &tmp))
	ecm->bytes_to_send = tmp << 30;
      else if (unformat (line_input, "bytes %U", unformat_memory_size,
			 &ecm->bytes_to_send))
	;
      else if (unformat (line_input, "test-timeout %f", &ecm->test_timeout))
	;
      else if (unformat (line_input, "syn-timeout %f", &ecm->syn_timeout))
	;
      else if (unformat (line_input, "echo-bytes"))
	ecm->echo_bytes = 1;
      else if (unformat (line_input, "fifo-size %U", unformat_memory_size,
			 &ecm->fifo_size))
	;
      else if (unformat (line_input, "private-segment-count %d",
			 &ecm->private_segment_count))
	;
      else if (unformat (line_input, "private-segment-size %U",
			 unformat_memory_size, &ecm->private_segment_size))
	;
      else if (unformat (line_input, "preallocate-fifos"))
	ecm->prealloc_fifos = 1;
      else if (unformat (line_input, "preallocate-sessions"))
	ecm->prealloc_sessions = 1;
      else if (unformat (line_input, "client-batch %d",
			 &ecm->connections_per_batch))
	;
      else if (unformat (line_input, "appns %_%v%_", &ecm->appns_id))
	;
      else if (unformat (line_input, "all-scope"))
	ecm->attach_flags |= (APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE |
			      APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE);
      else if (unformat (line_input, "local-scope"))
	ecm->attach_flags = APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
      else if (unformat (line_input, "global-scope"))
	ecm->attach_flags = APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
      else if (unformat (line_input, "secret %lu", &ecm->appns_secret))
	;
      else if (unformat (line_input, "verbose"))
	ecm->cfg.verbose = 1;
      else if (unformat (line_input, "test-bytes"))
	ecm->cfg.test_bytes = 1;
      else if (unformat (line_input, "tls-engine %d", &ecm->tls_engine))
	;
      else
	{
	  error = clib_error_return (0, "failed: unknown input `%U'",
				     format_unformat_error, line_input);
	  goto cleanup;
	}
    }

parse_config:

  ecm->cfg.num_test_sessions = ecm->expected_connections =
    ecm->n_clients * ecm->quic_streams;

  if (!ecm->connect_uri)
    {
      ec_cli ("No uri provided. Using default: %s", default_uri);
      ecm->connect_uri = format (0, "%s%c", default_uri, 0);
    }

  if ((rv = parse_uri ((char *) ecm->connect_uri, &ecm->connect_sep)))
    {
      error = clib_error_return (0, "Uri parse error: %d", rv);
      goto cleanup;
    }
  ecm->transport_proto = ecm->connect_sep.transport_proto;

  if (ecm->prealloc_sessions)
    ec_prealloc_sessions (ecm);

  if ((error = ec_attach ()))
    {
      clib_error_report (error);
      goto cleanup;
    }

  if (ecm->echo_bytes)
    ecm->cfg.test = HS_TEST_TYPE_BI;
  else
    ecm->cfg.test = HS_TEST_TYPE_UNI;

  ec_ctrl_connect ();
  ec_wait_for_signal (EC_CLI_CFG_SYNC);

  if (ec_ctrl_test_start () < 0)
    {
      ec_cli ("failed to send start command");
      goto cleanup;
    }
  ec_wait_for_signal (EC_CLI_START);

  /*
   * Start. Fire off connect requests
   */

  /* update data port */
  ecm->connect_sep.port = hs_make_data_port (ecm->connect_sep.port);

  ecm->syn_start_time = vlib_time_now (vm);
  ec_program_connects ();

  /*
   * Park until the sessions come up, or syn_timeout seconds pass
   */

  vlib_process_wait_for_event_or_clock (vm, ecm->syn_timeout);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      ec_cli ("Timeout with only %d sessions active...",
	      ecm->ready_connections);
      error = clib_error_return (0, "failed: syn timeout with %d sessions",
				 ecm->ready_connections);
      goto stop_test;

    case EC_CLI_CONNECTS_DONE:
      delta = vlib_time_now (vm) - ecm->syn_start_time;
      if (delta != 0.0)
	ec_cli ("%d three-way handshakes in %.2f seconds %.2f/s",
		ecm->n_clients, delta, ((f64) ecm->n_clients) / delta);
      break;

    case EC_CLI_CONNECTS_FAILED:
      error = clib_error_return (0, "failed: connect returned");
      goto stop_test;

    default:
      ec_cli ("unexpected event(2): %d", event_type);
      error =
	clib_error_return (0, "failed: unexpected event(2): %d", event_type);
      goto stop_test;
    }

  /*
   * Wait for the sessions to finish or test_timeout seconds pass
   */
  ecm->test_start_time = vlib_time_now (ecm->vlib_main);
  ec_cli ("Test started at %.6f", ecm->test_start_time);
  vlib_process_wait_for_event_or_clock (vm, ecm->test_timeout);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      ec_cli ("Timeout at %.6f with %d sessions still active...",
	      vlib_time_now (ecm->vlib_main), ecm->ready_connections);
      error = clib_error_return (0, "failed: timeout with %d sessions",
				 ecm->ready_connections);
      goto stop_test;

    case EC_CLI_TEST_DONE:
      ecm->test_end_time = vlib_time_now (vm);
      ec_cli ("Test finished at %.6f", ecm->test_end_time);
      break;

    default:
      ec_cli ("unexpected event(3): %d", event_type);
      error =
	clib_error_return (0, "failed: unexpected event(3): %d", event_type);
      goto stop_test;
    }

  /*
   * Done. Compute stats
   */
  delta = ecm->test_end_time - ecm->test_start_time;
  if (delta == 0.0)
    {
      ec_cli ("zero delta-t?");
      error = clib_error_return (0, "failed: zero delta-t");
      goto stop_test;
    }

  total_bytes = (ecm->echo_bytes ? ecm->rx_total : ecm->tx_total);
  transfer_type = ecm->echo_bytes ? "full-duplex" : "half-duplex";
  ec_cli ("%lld bytes (%lld mbytes, %lld gbytes) in %.2f seconds", total_bytes,
	  total_bytes / (1ULL << 20), total_bytes / (1ULL << 30), delta);
  ec_cli ("%.2f bytes/second %s", ((f64) total_bytes) / (delta),
	  transfer_type);
  ec_cli ("%.4f gbit/second %s", (((f64) total_bytes * 8.0) / delta / 1e9),
	  transfer_type);

  if (ecm->cfg.test_bytes && ecm->test_failed)
    error = clib_error_return (0, "failed: test bytes");

stop_test:
  ecm->run_test = EC_EXITING;

  /* send stop test command to the server */
  if (ec_ctrl_test_stop () < 0)
    {
      ec_cli ("failed to send stop command");
      goto cleanup;
    }
  ec_wait_for_signal (EC_CLI_STOP);

  /* post test sync */
  if (ec_ctrl_test_sync () < 0)
    {
      ec_cli ("failed to send post sync command");
      goto cleanup;
    }
  ec_wait_for_signal (EC_CLI_CFG_SYNC);

  /* disconnect control session */
  ec_ctrl_session_disconnect ();

cleanup:

  ecm->run_test = EC_EXITING;
  vlib_process_wait_for_event_or_clock (vm, 10e-3);

  /* Detach the application, so we can use different fifo sizes next time */
  if (ec_detach ())
    {
      error = clib_error_return (0, "failed: app detach");
      ec_cli ("WARNING: app detach failed...");
    }

  ec_cleanup (ecm);
  if (had_config)
    unformat_free (line_input);

  if (error)
    ec_cli ("test failed");

  return error;
}

VLIB_CLI_COMMAND (ec_command, static) = {
  .path = "test echo clients",
  .short_help =
    "test echo clients [nclients %d][[m|g]bytes <bytes>]"
    "[test-timeout <time>][syn-timeout <time>][echo-bytes][fifo-size <size>]"
    "[private-segment-count <count>][private-segment-size <bytes>[m|g]]"
    "[preallocate-fifos][preallocate-sessions][client-batch <batch-size>]"
    "[uri <tcp://ip/port>][test-bytes][verbose]",
  .function = ec_command_fn,
  .is_mp_safe = 1,
};

clib_error_t *
ec_main_init (vlib_main_t *vm)
{
  ec_main_t *ecm = &ec_main;
  ecm->app_is_init = 0;
  return 0;
}

VLIB_INIT_FUNCTION (ec_main_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
