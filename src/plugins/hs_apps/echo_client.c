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
#include <vnet/tcp/tcp_types.h>

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
ec_worker_get (clib_thread_index_t thread_index)
{
  return vec_elt_at_index (ec_main.wrk, thread_index);
}

static inline void
ec_sessions_stop_clean ()
{
  ec_main_t *ecm = &ec_main;
  ecm->test_timeout += 1;
  ecm->end_test = true;
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
update_rtt_stats (f64 session_rtt)
{
  ec_main_t *ecm = &ec_main;
  clib_spinlock_lock (&ecm->rtt_stats.w_lock);
  ecm->rtt_stats.last_rtt = session_rtt;
  ecm->rtt_stats.sum_rtt += session_rtt;
  ecm->rtt_stats.n_sum++;
  if (session_rtt < ecm->rtt_stats.min_rtt)
    ecm->rtt_stats.min_rtt = session_rtt;
  if (session_rtt > ecm->rtt_stats.max_rtt)
    ecm->rtt_stats.max_rtt = session_rtt;
  clib_spinlock_unlock (&ecm->rtt_stats.w_lock);
}

static void
update_rtt_stats_tcp (ec_session_t *es)
{
  session_t *s = session_get_from_handle_if_valid (es->vpp_session_handle);
  if (s)
    {
      transport_connection_t *tc;
      tcp_connection_t *tcpc;
      tc = transport_get_connection (TRANSPORT_PROTO_TCP, s->connection_index,
				     s->thread_index);
      if (PREDICT_TRUE (tc != NULL))
	{
	  tcpc = tcp_get_connection_from_transport (tc);
	  update_rtt_stats (tcpc->srtt * TCP_TICK);
	}
    }
}

static void
send_data_chunk (ec_main_t *ecm, ec_session_t *es)
{
  u8 *test_data = ecm->connect_test_data;
  int test_buf_len, rv;
  u64 bytes_to_send;
  u32 test_buf_offset;
  svm_fifo_t *f = es->tx_fifo;

  test_buf_len = vec_len (test_data);
  ASSERT (test_buf_len > 0);
  if (ecm->run_time)
    bytes_to_send =
      clib_min (svm_fifo_max_enqueue_prod (f), ecm->max_chunk_bytes);
  else
    bytes_to_send = clib_min (es->bytes_to_send, ecm->max_chunk_bytes);
  if (ecm->throughput)
    bytes_to_send = clib_min (es->bytes_paced_current, bytes_to_send);
  test_buf_offset = es->bytes_sent % test_buf_len;
  /* make sure we're sending evenly sized dgrams */
  if (ecm->transport_proto == TRANSPORT_PROTO_UDP &&
      (test_buf_len - test_buf_offset) < bytes_to_send)
    test_buf_offset = 0;
  bytes_to_send = clib_min (test_buf_len - test_buf_offset, bytes_to_send);

  if (!es->is_dgram)
    {
      if (ecm->no_copy)
	{
	  rv = clib_min (svm_fifo_max_enqueue_prod (f), bytes_to_send);
	  svm_fifo_enqueue_nocopy (f, rv);
	  session_program_tx_io_evt (es->tx_fifo->vpp_sh, SESSION_IO_EVT_TX);
	}
      else
	rv = app_send_stream ((app_session_t *) es,
			      test_data + test_buf_offset, bytes_to_send, 0);
    }
  else
    {
      u32 max_enqueue = svm_fifo_max_enqueue_prod (f);

      if (max_enqueue < sizeof (session_dgram_hdr_t))
	return;

      max_enqueue -= sizeof (session_dgram_hdr_t);

      if (ecm->no_copy)
	{
	  session_dgram_hdr_t hdr;
	  app_session_transport_t *at = &es->transport;

	  rv = clib_min (max_enqueue, bytes_to_send);

	  hdr.data_length = rv;
	  hdr.data_offset = 0;
	  hdr.gso_size = 0;
	  clib_memcpy_fast (&hdr.rmt_ip, &at->rmt_ip,
			    sizeof (ip46_address_t));
	  hdr.is_ip4 = at->is_ip4;
	  hdr.rmt_port = at->rmt_port;
	  clib_memcpy_fast (&hdr.lcl_ip, &at->lcl_ip,
			    sizeof (ip46_address_t));
	  hdr.lcl_port = at->lcl_port;
	  svm_fifo_enqueue (f, sizeof (hdr), (u8 *) & hdr);
	  svm_fifo_enqueue_nocopy (f, rv);
	  session_program_tx_io_evt (es->tx_fifo->vpp_sh, SESSION_IO_EVT_TX);
	}
      else
	{
	  bytes_to_send = clib_min (bytes_to_send, max_enqueue);
	  if (!ecm->throughput)
	    bytes_to_send = clib_min (bytes_to_send, 1460);
	  if (ecm->include_buffer_offset)
	    {
	      /* Include buffer offset info to also be able to verify
	       * out-of-order packets */
	      svm_fifo_seg_t data_segs[3] = {
		{ NULL, 0 },
		{ (u8 *) &test_buf_offset, sizeof (u32) },
		{ test_data + test_buf_offset, bytes_to_send }
	      };
	      if (ecm->echo_bytes &&
		  ((es->rtt_stat & EC_UDP_RTT_TX_FLAG) == 0))
		{
		  es->rtt_udp_buffer_offset = test_buf_offset;
		  es->send_rtt = vlib_time_now (vlib_get_main ());
		  es->rtt_stat |= EC_UDP_RTT_TX_FLAG;
		}
	      rv = app_send_dgram_segs ((app_session_t *) es, data_segs, 2,
					bytes_to_send + sizeof (u32), 0);
	      if (rv)
		rv -= sizeof (u32);
	    }
	  else
	    rv =
	      app_send_dgram ((app_session_t *) es,
			      test_data + test_buf_offset, bytes_to_send, 0);
	}
    }

  /* If we managed to enqueue data... */
  if (rv > 0)
    {
      if (es->is_dgram)
	es->dgrams_sent++;
      /* Account for it... */
      es->bytes_sent += rv;
      if (ecm->run_time)
	es->bytes_to_receive += rv;
      else
	es->bytes_to_send -= rv;
      if (ecm->throughput)
	{
	  es->bytes_paced_current -= rv;
	  es->bytes_paced_current += es->bytes_paced_target;
	}

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
	  ed = ELOG_DATA (vlib_get_elog_main (), e);
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
  session_dgram_pre_hdr_t ph;
  int n_read, i;
  u8 *rx_buf_start = wrk->rx_buf;
  u32 test_buf_offset = es->bytes_received;

  if (ecm->include_buffer_offset)
    {
      n_read =
	app_recv ((app_session_t *) es, wrk->rx_buf, vec_len (wrk->rx_buf));
      if (ecm->transport_proto != TRANSPORT_PROTO_TCP)
	{
	  test_buf_offset = *(u32 *) wrk->rx_buf;
	  rx_buf_start = wrk->rx_buf + sizeof (u32);
	  n_read -= sizeof (u32);
	  es->dgrams_received++;
	}
    }
  else
    {
      if (!es->is_dgram)
	{
	  n_read = svm_fifo_max_dequeue_cons (rx_fifo);
	  svm_fifo_dequeue_drop (rx_fifo, n_read);
	}
      else
	{
	  n_read = svm_fifo_max_dequeue_cons (rx_fifo);
	  if (n_read <= sizeof (session_dgram_hdr_t))
	    return;
	  svm_fifo_peek (rx_fifo, 0, sizeof (ph), (u8 *) &ph);
	  if (n_read < (ph.data_length + SESSION_CONN_HDR_LEN))
	    return;
	  svm_fifo_dequeue_drop (rx_fifo,
				 ph.data_length + SESSION_CONN_HDR_LEN);
	  n_read = ph.data_length;
	  es->dgrams_received++;
	}
    }

  if (n_read > 0)
    {
      if (ecm->transport_proto == TRANSPORT_PROTO_UDP && ecm->echo_bytes &&
	  (es->rtt_stat & EC_UDP_RTT_RX_FLAG) == 0)
	{
	  /* For periodic reports, verify that the buffer offset matches and we
	   * received the expected dgram, otherwise just match up the first
	   * received one */
	  if (((test_buf_offset == es->rtt_udp_buffer_offset) &&
	       ecm->report_interval) ||
	      !ecm->report_interval)
	    {
	      f64 rtt;
	      es->rtt_stat |= EC_UDP_RTT_RX_FLAG;
	      rtt = vlib_time_now (vlib_get_main ()) - es->send_rtt;
	      if (ecm->rtt_stats.last_rtt > 0)
		es->jitter =
		  clib_abs (rtt * 1000 - ecm->rtt_stats.last_rtt * 1000);
	      update_rtt_stats (rtt);
	    }
	}
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
	  ed = ELOG_DATA (vlib_get_elog_main (), e);
	  ed->data[0] = n_read;
	}

      if (ecm->cfg.test_bytes)
	{
	  for (i = 0; i < n_read; i++)
	    {
	      if (rx_buf_start[i] != ((test_buf_offset + i) & 0xff))
		{
		  ec_err ("read %d error at byte %lld, 0x%x not 0x%x", n_read,
			  test_buf_offset + i, rx_buf_start[i],
			  ((test_buf_offset + i) & 0xff));
		  ecm->test_failed = 1;
		}
	    }
	}
      if (n_read > es->bytes_to_receive)
	{
	  ec_err ("expected %llu, received %llu bytes!",
		  es->bytes_received + es->bytes_to_receive,
		  es->bytes_received + n_read);
	  ecm->test_failed = 1;
	  es->bytes_to_receive = n_read;
	}
      es->bytes_to_receive -= n_read;
      es->bytes_received += n_read;
    }
}

static uword
ec_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *conn_indices, *conns_this_batch, nconns_this_batch;
  int thread_index = vm->thread_index, i, delete_session;
  f64 time_now;
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
      if (ecm->repeats == 500000 && !ecm->run_time)
	{
	  ec_err ("stuck clients");
	}
    }
  else
    {
      ecm->prev_conns = vec_len (conns_this_batch);
      ecm->repeats = 0;
    }
  if (ecm->throughput)
    time_now = vlib_time_now (vm);
  /*
   * Handle connections in this batch
   */
  for (i = 0; i < vec_len (conns_this_batch); i++)
    {
      es = ec_session_get (wrk, conns_this_batch[i]);
      if (ecm->throughput)
	if (time_now < es->time_to_send)
	  continue;

      delete_session = 1;
      if (es->bytes_to_send > 0)
	{
	  send_data_chunk (ecm, es);
	  if (ecm->throughput)
	    es->time_to_send += ecm->pacing_window_len;
	  else
	    {
	      while (svm_fifo_max_enqueue_prod (es->tx_fifo) >
		       sizeof (session_dgram_hdr_t) &&
		     es->bytes_to_send > 0)
		send_data_chunk (ecm, es);
	    }
	  delete_session = 0;
	}

      if (es->bytes_to_receive > 0)
	{
	  delete_session = 0;
	}

      if (PREDICT_FALSE (delete_session == 1) || ecm->end_test)
	{
	  clib_atomic_fetch_add (&ecm->tx_total, es->bytes_sent);
	  clib_atomic_fetch_add (&ecm->rx_total, es->bytes_received);
	  clib_atomic_fetch_add (&ecm->tx_total_dgrams, es->dgrams_sent);
	  clib_atomic_fetch_add (&ecm->rx_total_dgrams, es->dgrams_received);
	  s = session_get_from_handle_if_valid (es->vpp_session_handle);

	  if (s)
	    {
	      if (ecm->transport_proto == TRANSPORT_PROTO_TCP)
		update_rtt_stats_tcp (es);

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
      if (ecm->throughput)
	time_now = vlib_time_now (vm);
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
  ecm->end_test = false;
  ecm->ready_connections = 0;
  ecm->connect_conn_index = 0;
  ecm->rx_total = 0;
  ecm->tx_total = 0;
  ecm->rx_total_dgrams = 0;
  ecm->tx_total_dgrams = 0;
  ecm->barrier_acq_needed = 0;
  ecm->prealloc_sessions = 0;
  ecm->prealloc_fifos = 0;
  ecm->appns_id = 0;
  ecm->appns_secret = 0;
  ecm->attach_flags = 0;
  ecm->syn_timeout = 20.0;
  ecm->test_timeout = 20.0;
  ecm->run_time = 0;
  ecm->throughput = 0;
  ecm->pacing_window_len = 1;
  ecm->max_chunk_bytes = 128 << 10;
  ecm->report_interval = 0;
  ecm->report_interval_total = 0;
  ecm->last_print_time = 0;
  ecm->last_total_tx_bytes = 0;
  ecm->last_total_rx_bytes = 0;
  ecm->last_total_rx_dgrams = 0;
  ecm->last_total_tx_dgrams = 0;
  ecm->report_interval_jitter = 0;
  ecm->include_buffer_offset = 0;
  clib_memset (&ecm->rtt_stats, 0, sizeof (ec_rttstat_t));
  ecm->rtt_stats.min_rtt = CLIB_F64_MAX;
  if (ecm->rtt_stats.w_lock == NULL)
    clib_spinlock_init (&ecm->rtt_stats.w_lock);
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

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, &args);

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
  if (ecm->throughput)
    ecm->pacing_window_len = 1;
  if (ecm->barrier_acq_needed)
    vlib_worker_thread_barrier_sync (ecm->vlib_main);
  clib_spinlock_free (&ecm->rtt_stats.w_lock);
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
  session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
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
  clib_thread_index_t thread_index;

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

static void
ec_calc_tput (ec_main_t *ecm)
{
  vlib_main_t *vm = vlib_get_main ();
  ec_worker_t *wrk;
  ec_session_t *sess;
  f64 pacing_base;
  u64 bytes_paced_target;
  u64 target_size_threshold;

  /* Choose an appropriate data size chunk threshold based on fifo size.
     ~30k is fine for most scenarios, unless the fifo starts getting
     smaller than 48k, where a slight curve is needed. */
  if (PREDICT_TRUE (ecm->fifo_size > 49152))
    target_size_threshold = 30720;
  else if (ecm->fifo_size > 20480)
    target_size_threshold = 12288;
  else if (ecm->fifo_size > 10240)
    target_size_threshold = 6144;
  else
    target_size_threshold = ecm->fifo_size;

  /* find a suitable pacing window length & data chunk size */
  bytes_paced_target =
    ecm->throughput * ecm->pacing_window_len / ecm->n_clients;
  while (
    bytes_paced_target > target_size_threshold ||
    (ecm->transport_proto == TRANSPORT_PROTO_UDP && bytes_paced_target > 1460))
    {
      ecm->pacing_window_len /= 2;
      bytes_paced_target /= 2;
    }

  /* order sessions to shoot out data sequentially */
  pacing_base = vlib_time_now (vm) - ecm->pacing_window_len;
  vec_foreach (wrk, ecm->wrk)
    {
      vec_foreach (sess, wrk->sessions)
	{
	  sess->time_to_send =
	    pacing_base + ecm->pacing_window_len / ecm->n_clients;
	  pacing_base = sess->time_to_send;
	  sess->bytes_paced_target = bytes_paced_target;
	  sess->bytes_paced_current = bytes_paced_target;
	}
    }
}

static int
ec_session_connected_callback (u32 app_index, u32 api_context, session_t *s,
			       session_error_t err)
{
  ec_main_t *ecm = &ec_main;
  ec_session_t *es;
  clib_thread_index_t thread_index;
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
  es->bytes_paced_target = ~0;
  es->bytes_paced_current = ~0;
  s->opaque = es->session_index;

  vec_add1 (wrk->conn_indices, es->session_index);
  clib_atomic_fetch_add (&ecm->ready_connections, 1);
  if (ecm->ready_connections == ecm->expected_connections)
    {
      if (ecm->throughput)
	ec_calc_tput (ecm);
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
  app_ca_trust_add_args_t _ca_args = {}, *ca_args = &_ca_args;
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

  options[APP_OPTIONS_SEGMENT_SIZE] = ecm->private_segment_size;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = ecm->private_segment_size;
  options[APP_OPTIONS_RX_FIFO_SIZE] = ecm->fifo_size;
  options[APP_OPTIONS_TX_FIFO_SIZE] = ecm->fifo_size;
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

  vec_validate (ca_args->ca_chain, test_ca_chain_rsa_len - 1);
  clib_memcpy (ca_args->ca_chain, test_ca_chain_rsa, test_ca_chain_rsa_len);
  vec_validate (ca_args->crl, test_ca_crl_len - 1);
  clib_memcpy (ca_args->crl, test_ca_crl, test_ca_crl_len);
  app_crypto_add_ca_trust (ecm->app_index, ca_args);
  ecm->ca_trust_index = ca_args->index;

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
	  transport_endpt_ext_cfg_t *ext_cfg = session_endpoint_add_ext_cfg (
	    &a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
	    sizeof (transport_endpt_crypto_cfg_t));
	  ext_cfg->crypto.ckpair_index = ecm->ckpair_index;
	  ext_cfg->crypto.ca_trust_index = ecm->ca_trust_index;
	}

      rv = vnet_connect (a);

      if (needs_crypto)
	session_endpoint_free_ext_cfgs (&a->sep_ext);

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

static void
ec_print_timeout_stats (vlib_main_t *vm)
{
  ec_main_t *ecm = &ec_main;
  u64 received_bytes = 0, sent_bytes = 0;
  ec_worker_t *wrk;
  ec_session_t *sess;
  vec_foreach (wrk, ecm->wrk)
    {
      pool_foreach (sess, wrk->sessions)
	{
	  received_bytes += sess->bytes_received;
	  sent_bytes += sess->bytes_sent;
	}
    }
  ec_cli ("Timeout at %.6f with %d sessions still active...",
	  vlib_time_now (vm), ecm->ready_connections);
  if (ecm->transport_proto == TRANSPORT_PROTO_UDP)
    {
      ec_cli ("Received %llu bytes out of %llu sent (%llu target)",
	      received_bytes, sent_bytes, ecm->bytes_to_send * ecm->n_clients);
    }
}

static void
ec_print_periodic_stats (vlib_main_t *vm, bool print_header, bool print_footer)
{
  ec_main_t *ecm = &ec_main;
  f64 time_now, print_delta, interval_start, interval_end, rtt = 0.0,
							   jitter = 0.0;
  u64 total_bytes,
    received_bytes = 0, sent_bytes = 0, dgrams_sent = 0, dgrams_received = 0,
    last_total_bytes = ecm->last_total_tx_bytes + ecm->last_total_rx_bytes;
  ec_worker_t *wrk;
  ec_session_t *sess;
  vec_foreach (wrk, ecm->wrk)
    {
      pool_foreach (sess, wrk->sessions)
	{
	  received_bytes += sess->bytes_received;
	  sent_bytes += sess->bytes_sent;
	  if (ecm->transport_proto == TRANSPORT_PROTO_UDP)
	    {
	      dgrams_received += sess->dgrams_received;
	      dgrams_sent += sess->dgrams_sent;
	      sess->rtt_stat = 0;
	      jitter += sess->jitter;
	    }
	  else if (ecm->transport_proto == TRANSPORT_PROTO_TCP)
	    {
	      session_t *s =
		session_get_from_handle_if_valid (sess->vpp_session_handle);
	      if (s)
		{
		  update_rtt_stats_tcp (sess);
		  rtt += ecm->rtt_stats.last_rtt;
		}
	    }
	}
    }
  time_now = vlib_time_now (vm);
  interval_end = time_now - ecm->test_start_time;
  interval_start = ecm->last_print_time - ecm->test_start_time;
  total_bytes = received_bytes + sent_bytes;
  print_delta = time_now - ecm->last_print_time;

  if (ecm->transport_proto == TRANSPORT_PROTO_UDP)
    {
      jitter /= ecm->n_clients;
      rtt = ecm->rtt_stats.last_rtt * 1000;
      if (print_header)
	{
	  ec_cli ("-----------------------------------------------------------"
		  "-------------------------");
	  if (ecm->report_interval_total)
	    ec_cli (
	      "Run time (s)  Transmitted   Received   Throughput   "
	      "%sSent/received dgrams",
	      (ecm->report_interval_jitter ? "Jitter      " : "Roundtrip   "));
	  else
	    ec_cli (
	      "Interval (s)  Transmitted   Received   Throughput   "
	      "%sSent/received dgrams",
	      (ecm->report_interval_jitter ? "Jitter      " : "Roundtrip   "));
	}
      if (ecm->report_interval_total)
	{
	  ec_cli ("%-13.1f %-13U %-10U %+9Ub/s %+9.3fms %llu/%llu",
		  interval_end, format_base10, sent_bytes, format_base10,
		  received_bytes, format_base10,
		  flt_round_nearest ((f64) (total_bytes - last_total_bytes) /
				     print_delta) *
		    8,
		  (ecm->report_interval_jitter ? jitter : rtt), dgrams_sent,
		  dgrams_received);
	}
      else
	{
	  rtt /= ecm->n_clients;
	  ec_cli ("%.1f-%-9.1f %-13U %-10U %+9Ub/s %+9.3fms %llu/%llu",
		  interval_start, interval_end, format_base10,
		  sent_bytes - ecm->last_total_tx_bytes, format_base10,
		  received_bytes - ecm->last_total_rx_bytes, format_base10,
		  flt_round_nearest ((f64) (total_bytes - last_total_bytes) /
				     print_delta) *
		    8,
		  (ecm->report_interval_jitter ? jitter : rtt),
		  (dgrams_sent - ecm->last_total_tx_dgrams),
		  (dgrams_received - ecm->last_total_rx_dgrams));
	}
      if (print_footer)
	ec_cli ("-------------------------------------------------------------"
		"-----------------------");
      ecm->last_total_tx_dgrams = dgrams_sent;
      ecm->last_total_rx_dgrams = dgrams_received;
    }
  else
    {
      if (print_header)
	{
	  ec_cli (
	    "-------------------------------------------------------------");
	  if (ecm->report_interval_total)
	    ec_cli (
	      "Run time (s)  Transmitted   Received   Throughput   Roundtrip");
	  else
	    ec_cli (
	      "Interval (s)  Transmitted   Received   Throughput   Roundtrip");
	}
      if (ecm->report_interval_total)
	ec_cli ("%-13.1f %-13U %-10U %+9Ub/s %+7.3fms", interval_end,
		format_base10, sent_bytes, format_base10, received_bytes,
		format_base10,
		flt_round_nearest ((f64) total_bytes /
				   (time_now - ecm->test_start_time)) *
		  8,
		rtt * 1000);
      else
	ec_cli ("%.1f-%-9.1f %-13U %-10U %+9Ub/s %+7.3fms", interval_start,
		interval_end, format_base10,
		sent_bytes - ecm->last_total_tx_bytes, format_base10,
		received_bytes - ecm->last_total_rx_bytes, format_base10,
		flt_round_nearest (((f64) (total_bytes - last_total_bytes)) /
				   print_delta) *
		  8,
		rtt * 1000);
      if (print_footer)
	ec_cli (
	  "-------------------------------------------------------------");
    }
  ecm->last_print_time = time_now;
  ecm->last_total_tx_bytes = sent_bytes;
  ecm->last_total_rx_bytes = received_bytes;
}

static void
ec_print_final_stats (vlib_main_t *vm, f64 total_delta)
{
  ec_main_t *ecm = &ec_main;
  u64 total_bytes;
  f64 dgram_loss;
  char *transfer_type;

  if (ecm->transport_proto == TRANSPORT_PROTO_TCP ||
      (ecm->transport_proto == TRANSPORT_PROTO_UDP && ecm->echo_bytes))
    {
      /* display rtt stats in milliseconds */
      if (ecm->rtt_stats.n_sum == 1)
	ec_cli ("%.05fms roundtrip", ecm->rtt_stats.min_rtt * 1000);
      else if (ecm->rtt_stats.n_sum > 1)
	ec_cli ("%.05fms/%.05fms/%.05fms min/avg/max roundtrip",
		ecm->rtt_stats.min_rtt * 1000,
		ecm->rtt_stats.sum_rtt / ecm->rtt_stats.n_sum * 1000,
		ecm->rtt_stats.max_rtt * 1000);
      else
	ec_cli ("error measuring roundtrip time");
    }
  if (ecm->transport_proto == TRANSPORT_PROTO_UDP)
    {
      ec_cli ("sent total %llu datagrams, received total %llu datagrams",
	      ecm->tx_total_dgrams, ecm->rx_total_dgrams);
      dgram_loss = (ecm->tx_total_dgrams ?
		      ((f64) (ecm->tx_total_dgrams - ecm->rx_total_dgrams) /
		       (f64) ecm->tx_total_dgrams * 100.0) :
		      0.0);
      if (ecm->echo_bytes && dgram_loss > 0.0)
	ec_cli ("lost %llu datagrams (%.2f%%)",
		ecm->tx_total_dgrams - ecm->rx_total_dgrams, dgram_loss);
    }
  total_bytes = (ecm->echo_bytes ? ecm->rx_total : ecm->tx_total);
  transfer_type = ecm->echo_bytes ? "full-duplex" : "half-duplex";
  ec_cli ("%lld bytes (%lld mbytes, %lld gbytes) in %.2f seconds", total_bytes,
	  total_bytes / (1ULL << 20), total_bytes / (1ULL << 30), total_delta);
  ec_cli ("%u bytes/second %s",
	  flt_round_nearest (((f64) total_bytes) / (total_delta)),
	  transfer_type);
  ec_cli ("%UB/s %s", format_base10,
	  flt_round_nearest (((f64) total_bytes) / (total_delta)),
	  transfer_type);
}

static clib_error_t *
ec_command_fn (vlib_main_t *vm, unformat_input_t *input,
	       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  char *default_uri = "tcp://6.0.1.1/1234";
  ec_main_t *ecm = &ec_main;
  uword *event_data = 0, event_type;
  clib_error_t *error = 0;
  int rv, timed_run_conflict = 0, tput_conflict = 0, had_config = 1;
  f64 delta, wait_time = 0;

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
      else if (unformat (line_input, "bytes %U", unformat_memory_size,
			 &ecm->bytes_to_send))
	timed_run_conflict++;
      else if (unformat (line_input, "test-timeout %f", &ecm->test_timeout))
	timed_run_conflict++;
      else if (unformat (line_input, "syn-timeout %f", &ecm->syn_timeout))
	;
      else if (unformat (line_input, "run-time %f", &ecm->run_time))
	ecm->test_timeout = ecm->run_time;
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
      else if (unformat (line_input, "throughput %U", unformat_base10,
			 &ecm->throughput))
	ecm->throughput /= 8;
      else if (unformat (line_input, "max-tx-chunk %U", unformat_memory_size,
			 &ecm->max_chunk_bytes))
	tput_conflict = 1;
      else if (unformat (line_input, "preallocate-fifos"))
	ecm->prealloc_fifos = 1;
      else if (unformat (line_input, "preallocate-sessions"))
	ecm->prealloc_sessions = 1;
      else if (unformat (line_input, "client-batch %d",
			 &ecm->connections_per_batch))
	;
      else if (unformat (line_input, "report-jitter"))
	ecm->report_interval_jitter = 1;
      else if (unformat (line_input, "report-interval-total %u",
			 &ecm->report_interval))
	ecm->report_interval_total = 1;
      else if (unformat (line_input, "report-interval %u",
			 &ecm->report_interval))
	;
      else if (unformat (line_input, "report-interval"))
	ecm->report_interval = 1;
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

  if (timed_run_conflict && ecm->run_time)
    return clib_error_return (0, "failed: invalid arguments for a timed run!");
  if (ecm->throughput && tput_conflict)
    return clib_error_return (
      0, "failed: can't set fixed tx chunk for a throughput run!");

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

  if (ecm->cfg.test_bytes ||
      (ecm->echo_bytes && ecm->transport_proto == TRANSPORT_PROTO_UDP))
    ecm->include_buffer_offset = 1;

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
      if (ecm->transport_proto == TRANSPORT_PROTO_TCP)
	{
	  delta = vlib_time_now (vm) - ecm->syn_start_time;
	  if (delta != 0.0)
	    ec_cli ("%d three-way handshakes in %.2f seconds %.2f/s",
		    ecm->n_clients, delta, ((f64) ecm->n_clients) / delta);
	}
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
  /* Testing officially starts now */
  ecm->test_start_time = vlib_time_now (ecm->vlib_main);
  if (ecm->report_interval)
    ecm->last_print_time = ecm->test_start_time;
  ec_cli ("Test started at %.6f", ecm->test_start_time);

  /*
   * Wait for the sessions to finish or test_timeout (timeout or length
   * of timed run) seconds pass. If providing periodic reports, wake up
   * every now and then to print them and loop.
   */
  u8 main_loop_done = false, print_header = true, report_timeout = false;
  do
    {
      if (ecm->report_interval)
	{
	  delta = vlib_time_now (vm) - ecm->test_start_time;
	  if (delta + (f64) ecm->report_interval > ecm->test_timeout)
	    {
	      report_timeout = true;
	      wait_time = ecm->test_timeout - delta;
	    }
	  else
	    wait_time = (f64) ecm->report_interval;
	}
      else
	{
	  report_timeout = true;
	  wait_time = (f64) ecm->test_timeout;
	}

      vlib_process_wait_for_event_or_clock (vm, wait_time);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type)
	{
	case ~0:
	  if (report_timeout)
	    {
	      if (ecm->run_time)
		{
		  ec_sessions_stop_clean ();
		  break;
		}
	      ec_print_timeout_stats (vm);
	      if (ecm->transport_proto != TRANSPORT_PROTO_UDP)
		error =
		  clib_error_return (0, "failed: timeout with %d sessions",
				     ecm->ready_connections);
	      else if (ecm->echo_bytes)
		{
		  ec_sessions_stop_clean ();
		  break;
		}
	      goto stop_test;
	    }
	  else
	    {
	      ec_print_periodic_stats (vm, print_header, false);
	      if (PREDICT_FALSE (print_header))
		print_header = false;
	    }
	  break;

	case EC_CLI_TEST_DONE:
	  ecm->test_end_time = vlib_time_now (vm);
	  main_loop_done = true;
	  break;

	default:
	  ec_cli ("unexpected event(3): %d", event_type);
	  error = clib_error_return (0, "failed: unexpected event(3): %d",
				     event_type);
	  goto stop_test;
	}
    }
  while (!main_loop_done);

  delta = ecm->test_end_time - ecm->test_start_time;
  if (delta == 0.0)
    {
      ec_cli ("zero delta-t?");
      error = clib_error_return (0, "failed: zero delta-t");
      goto stop_test;
    }
  /* Print last interval */
  if (ecm->report_interval &&
      vlib_time_now (vm) - ecm->last_print_time >= 0.1f)
    ec_print_periodic_stats (vm, print_header, true);
  ec_cli ("Test finished at %.6f", ecm->test_end_time);
  ec_print_final_stats (vm, delta);

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
    "test echo clients [nclients %d][bytes <bytes>[m|g]][test-timeout <time>]"
    "[run-time <time>][syn-timeout <time>][echo-bytes][fifo-size <size>]"
    "[private-segment-count <count>][private-segment-size <bytes>[m|g]]"
    "[preallocate-fifos][preallocate-sessions][client-batch <batch-size>]"
    "[throughput <bytes>[m|g]][report-interval[-total] "
    "<time>][report-jitter][[uri "
    "<tcp://ip/port>]"
    "[test-bytes][verbose]",
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
