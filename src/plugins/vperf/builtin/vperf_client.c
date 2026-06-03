/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 by Cisco and/or its affiliates.
 */

/* vperf_client.c - vpp built-in performance client code */

#include <float.h>
#include <vperf/builtin/vperf_client.h>
#include <vnet/tcp/tcp_types.h>

vp_client_main_t vp_client_main;

#define vp_client_err(_fmt, _args...) clib_warning (_fmt, ##_args);

#define vp_client_dbg(_fmt, _args...)                                                              \
  do                                                                                               \
    {                                                                                              \
      if (vp_client_main.cfg.test_cfg.verbose)                                                     \
	vp_client_err (_fmt, ##_args);                                                             \
    }                                                                                              \
  while (0)

static void
signal_evt_to_cli_i (void *codep)
{
  vp_client_main_t *vpcm = &vp_client_main;
  int code;

  ASSERT (vlib_get_thread_index () == 0);
  code = pointer_to_uword (codep);
  vlib_process_signal_event (vpcm->vlib_main, vpcm->cli_node_index, code, 0);
}

static void
signal_evt_to_cli (int code)
{
  if (vlib_get_thread_index () != 0)
    session_send_rpc_evt_to_thread_force (0, signal_evt_to_cli_i,
					  uword_to_pointer ((uword) code, void *));
  else
    signal_evt_to_cli_i (uword_to_pointer ((uword) code, void *));
}

static inline vp_test_worker_t *
vp_client_worker_get (clib_thread_index_t thread_index)
{
  return vec_elt_at_index (vp_client_main.wrk, thread_index);
}

static inline void
vp_client_sessions_stop_clean ()
{
  vp_client_main_t *vpcm = &vp_client_main;
  vpcm->test_timeout += 1;
  vpcm->end_test = true;
}

static inline vp_test_session_t *
vp_client_session_get (vp_test_worker_t *wrk, u32 vp_client_index)
{
  return pool_elt_at_index (wrk->sessions, vp_client_index);
}

static inline void
vp_client_session_accumulate_stats (vp_client_main_t *vpcm, vp_test_worker_t *wrk,
				    vp_test_session_t *es)
{
  wrk->bytes_sent += es->bytes_sent;
  wrk->bytes_received += es->bytes_received;
  wrk->dgrams_sent += es->dgrams_sent;
  wrk->dgrams_received += es->dgrams_received;

  if (vpcm->cfg.proto == VP_PROTO_TCP)
    vp_update_rtt_stats_tcp (es, &vpcm->stats.rtt_stats);
  else if (vpcm->cfg.proto == VP_PROTO_UDP)
    vp_update_rtt_stats_udp (es, &vpcm->stats.rtt_stats);
}

static void
vp_client_vec_del_session_index (u32 **session_indices, u32 session_index)
{
  u32 i;

  vec_foreach_index (i, *session_indices)
    {
      if ((*session_indices)[i] == session_index)
	{
	  vec_delete (*session_indices, 1, i);
	  return;
	}
    }
}

static void
vp_client_worker_del_session_index (vp_test_worker_t *wrk, u32 session_index)
{
  vp_client_vec_del_session_index (&wrk->conn_indices, session_index);
  vp_client_vec_del_session_index (&wrk->conns_this_batch, session_index);
}

static void
vp_client_session_peer_close (session_t *s, u8 is_reset)
{
  vp_client_main_t *vpcm = &vp_client_main;
  vp_test_session_t *es;
  vp_test_worker_t *wrk;
  u32 session_index;
  u8 was_running, was_starting, session_failed;

  session_index = s->opaque;
  wrk = vp_client_worker_get (s->thread_index);

  if (pool_is_free_index (wrk->sessions, session_index))
    return;

  es = vp_client_session_get (wrk, session_index);
  if (es->vpp_session_handle != session_handle (s))
    return;

  was_starting = vpcm->run_test == VP_CLIENT_STARTING;
  was_running = vpcm->run_test == VP_CLIENT_RUNNING;

  if (!was_starting)
    {
      vp_client_worker_del_session_index (wrk, session_index);
      vp_client_session_accumulate_stats (vpcm, wrk, es);
    }

  session_failed = was_running || (!was_starting && (es->bytes_to_send || es->bytes_to_receive));
  if (session_failed)
    {
      vpcm->test_failed = 1;
      vpcm->run_test = VP_CLIENT_EXITING;
      clib_atomic_fetch_add (&vpcm->failed_session_closes, 1);
      if (is_reset)
	clib_atomic_fetch_add (&vpcm->reset_count, 1);
      else
	clib_atomic_fetch_add (&vpcm->disconnect_count, 1);
    }

  es->bytes_to_send = 0;
  es->bytes_to_receive = 0;
  es->vpp_session_handle = SESSION_INVALID_HANDLE;

  if (was_running)
    {
      clib_atomic_sub_fetch (&vpcm->ready_connections, 1);
      signal_evt_to_cli (VP_CLIENT_CLI_TEST_DONE);
    }
}

static void
vp_client_ctrl_session_peer_close (session_t *s, u8 is_reset)
{
  vp_client_main_t *vpcm = &vp_client_main;
  u8 was_starting = vpcm->run_test == VP_CLIENT_STARTING;

  if (s->opaque == VPERF_CTRL_HANDLE || session_handle (s) == vpcm->ctrl_session_handle)
    vpcm->ctrl_session_handle = SESSION_INVALID_HANDLE;

  if (was_starting || vpcm->run_test == VP_CLIENT_RUNNING)
    {
      vpcm->test_failed = 1;
      vpcm->run_test = VP_CLIENT_EXITING;
      clib_atomic_fetch_add (&vpcm->failed_session_closes, 1);
      if (is_reset)
	clib_atomic_fetch_add (&vpcm->reset_count, 1);
      else
	clib_atomic_fetch_add (&vpcm->disconnect_count, 1);
      signal_evt_to_cli (was_starting ? VP_CLIENT_CLI_CONNECTS_FAILED : VP_CLIENT_CLI_TEST_DONE);
    }
}

always_inline void
vp_client_tx_data (vp_test_session_t *es, u8 run_time, u8 paced, u8 test_bytes)
{
  vp_client_main_t *vpcm = &vp_client_main;
  const vp_test_proto_vft_t *tp = &vp_test_main.protos[vpcm->cfg.proto];
  u32 n_send;
  u64 bytes_to_send;

  if (run_time)
    bytes_to_send = vpcm->max_chunk_bytes;
  else
    bytes_to_send = clib_min (es->bytes_to_send, vpcm->max_chunk_bytes);

  if (paced)
    {
      f64 time_now = vlib_time_now (vlib_get_main ());
      if (time_now < es->time_to_send)
	return;
      es->time_to_send += vpcm->pacing_window_len;
      bytes_to_send = clib_min (bytes_to_send, es->bytes_paced_current);
    }

  if (test_bytes)
    n_send = tp->client_tx_test_bytes (es, vpcm->connect_test_data, bytes_to_send);
  else
    n_send = tp->client_tx (es, bytes_to_send);

  if (vpcm->cfg.run_time)
    es->bytes_to_receive += n_send;
  else
    es->bytes_to_send -= n_send;

  if (vpcm->throughput)
    {
      if (n_send)
	{
	  es->bytes_paced_current -= n_send;
	  es->bytes_paced_current += es->bytes_paced_target;
	}
    }
}

static void
vp_client_tx_test_bytes (vp_test_session_t *es)
{
  vp_client_tx_data (es, 0, 0, 1);
}

static void
vp_client_tx_test_bytes_time (vp_test_session_t *es)
{
  vp_client_tx_data (es, 1, 0, 1);
}

static void
vp_client_tx_test_bytes_paced (vp_test_session_t *es)
{
  vp_client_tx_data (es, 0, 1, 1);
}

static void
vp_client_tx_test_bytes_paced_time (vp_test_session_t *es)
{
  vp_client_tx_data (es, 1, 1, 1);
}

static void
vp_client_tx_zc (vp_test_session_t *es)
{
  vp_client_tx_data (es, 0, 0, 0);
}

static void
vp_client_tx_zc_time (vp_test_session_t *es)
{
  vp_client_tx_data (es, 1, 0, 0);
}

static void
vp_client_tx_zc_paced (vp_test_session_t *es)
{
  vp_client_tx_data (es, 0, 1, 0);
}

static void
vp_client_tx_zc_paced_time (vp_test_session_t *es)
{
  vp_client_tx_data (es, 1, 1, 0);
}

always_inline void
vp_client_rx_data (session_t *s, u8 test_bytes)
{
  vp_client_main_t *vpcm = &vp_client_main;
  vp_test_session_t *es;
  vp_test_worker_t *wrk;
  const vp_test_proto_vft_t *tp;

  wrk = vp_client_worker_get (s->thread_index);
  es = vp_client_session_get (wrk, s->opaque);
  tp = &vp_test_main.protos[vpcm->cfg.proto];
  if (test_bytes)
    vpcm->test_failed = tp->client_rx_test_bytes (es, s, wrk->rx_buf);
  else
    vpcm->test_failed = tp->client_rx (es, s, wrk->rx_buf);
}

static void
vp_client_rx (session_t *s)
{
  vp_client_rx_data (s, 0);
}

static void
vp_client_rx_test_bytes (session_t *s)
{
  vp_client_rx_data (s, 1);
}

static uword
vp_client_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *conn_indices, *conns_this_batch, nconns_this_batch, n_active_conn;
  int thread_index = vm->thread_index, i, delete_session;
  vp_client_main_t *vpcm = &vp_client_main;
  vp_test_worker_t *wrk;
  vp_test_session_t *es;
  session_t *s;

  if (vpcm->run_test != VP_CLIENT_RUNNING)
    return 0;

  wrk = vp_client_worker_get (thread_index);
  conn_indices = wrk->conn_indices;
  conns_this_batch = wrk->conns_this_batch;

  if (((vec_len (conn_indices) == 0) && vec_len (conns_this_batch) == 0))
    return 0;

  /* Grab another pile of connections */
  if (PREDICT_FALSE (vec_len (conns_this_batch) == 0))
    {
      nconns_this_batch = clib_min (vpcm->connections_per_batch, vec_len (conn_indices));

      ASSERT (nconns_this_batch > 0);
      vec_validate (conns_this_batch, nconns_this_batch - 1);
      clib_memcpy_fast (conns_this_batch, conn_indices + vec_len (conn_indices) - nconns_this_batch,
			nconns_this_batch * sizeof (u32));
      vec_dec_len (conn_indices, nconns_this_batch);
    }

  /*
   * Track progress
   */
  if (PREDICT_FALSE (vpcm->prev_conns != vpcm->connections_per_batch &&
		     vpcm->prev_conns == vec_len (conns_this_batch)))
    {
      vpcm->repeats++;
      vpcm->prev_conns = vec_len (conns_this_batch);
      if (vpcm->repeats == 500000 && !vpcm->cfg.run_time)
	{
	  vp_client_err ("stuck clients");
	}
    }
  else
    {
      vpcm->prev_conns = vec_len (conns_this_batch);
      vpcm->repeats = 0;
    }

  /*
   * Handle connections in this batch
   */
  for (i = 0; i < vec_len (conns_this_batch); i++)
    {
      es = vp_client_session_get (wrk, conns_this_batch[i]);
      delete_session = 1;
      if (es->bytes_to_send > 0)
	{
	  vpcm->tx_callback (es);
	  delete_session = 0;
	}

      if (es->bytes_to_receive > 0)
	{
	  delete_session = 0;
	}

      if (PREDICT_FALSE (delete_session == 1) || vpcm->end_test)
	{
	  vp_client_session_accumulate_stats (vpcm, wrk, es);
	  s = session_get_from_handle_if_valid (es->vpp_session_handle);
	  es->vpp_session_handle = SESSION_INVALID_HANDLE;

	  if (s)
	    {
	      vnet_disconnect_args_t _a, *a = &_a;
	      a->handle = session_handle (s);
	      a->app_index = vpcm->app_index;
	      vnet_disconnect_session (a);
	    }

	  vec_delete (conns_this_batch, 1, i);
	  i--;
	  n_active_conn = clib_atomic_sub_fetch (&vpcm->ready_connections, 1);
	  /* Kick the debug CLI process */
	  if (n_active_conn == 0)
	    {
	      signal_evt_to_cli (VP_CLIENT_CLI_TEST_DONE);
	    }
	}
    }

  wrk->conn_indices = conn_indices;
  wrk->conns_this_batch = conns_this_batch;
  return 0;
}

VLIB_REGISTER_NODE (vperf_clients_node) = {
  .function = vp_client_node_fn,
  .name = "echo-clients",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};

static void
vp_client_reset_runtime_config (vp_client_main_t *vpcm)
{
  session_endpoint_cfg_t sep_null = SESSION_ENDPOINT_CFG_NULL;
  vpcm->cfg.sep = sep_null;
  vperf_cfg_init (&vpcm->cfg.test_cfg);
  vpcm->cfg.n_clients = 1;
  vpcm->cfg.n_streams = 1;
  vpcm->cfg.bytes_to_send = 8192;
  vpcm->cfg.echo_bytes = 0;
  vpcm->cfg.fifo_size = 4 << 20;
  vpcm->connections_per_batch = 1000;
  vpcm->cfg.private_segment_size = 256 << 20;
  vpcm->test_failed = 0;
  vpcm->cfg.tls_engine = CRYPTO_ENGINE_OPENSSL;
  vpcm->cfg.http_version = HTTP_VERSION_1;
  vpcm->cfg.http_connect_proto = VP_HTTP_CONNECT_PROTO_NONE;
  vpcm->run_test = VP_CLIENT_STARTING;
  vpcm->end_test = false;
  vpcm->ready_connections = 0;
  vpcm->failed_session_closes = 0;
  vpcm->reset_count = 0;
  vpcm->disconnect_count = 0;
  vpcm->connect_conn_index = 0;
  vpcm->barrier_acq_needed = 0;
  vpcm->prealloc_sessions = 0;
  vpcm->prealloc_fifos = 0;
  vpcm->appns_id = 0;
  vpcm->appns_secret = 0;
  vpcm->attach_flags = 0;
  vpcm->syn_timeout = 20.0;
  vpcm->test_timeout = 20.0;
  vpcm->cfg.run_time = 0;
  vpcm->throughput = 0;
  vpcm->pacing_window_len = 1;
  vpcm->max_chunk_bytes = TRANSPORT_PACER_MAX_BURST;
  vpcm->cfg.report_interval = 0;
  vpcm->cfg.report_interval_total = 0;
  vpcm->stats.last_print_time = 0;
  vpcm->stats.last_total_tx_bytes = 0;
  vpcm->stats.last_total_rx_bytes = 0;
  vpcm->stats.last_total_rx_dgrams = 0;
  vpcm->stats.last_total_tx_dgrams = 0;
  vpcm->cfg.report_interval_jitter = 0;
  vpcm->include_buffer_offset = 0;
  vpcm->cfg.is_server = 0;
  clib_memset (&vpcm->stats.rtt_stats, 0, sizeof (vp_rtt_stat_t));
  vpcm->stats.rtt_stats.min_rtt = CLIB_F64_MAX;
  if (vpcm->stats.rtt_stats.w_lock == NULL)
    clib_spinlock_init (&vpcm->stats.rtt_stats.w_lock);
  vec_free (vpcm->cfg.uri);
}

int
vp_client_init (vlib_main_t *vm)
{
  vp_client_main_t *vpcm = &vp_client_main;
  vp_test_worker_t *wrk;
  u32 num_threads;
  int i;

  vp_client_reset_runtime_config (vpcm);

  /* Store cli process node index for signaling */
  vpcm->cli_node_index = vlib_get_current_process (vm)->node_runtime.node_index;
  vpcm->vlib_main = vm;

  if (vlib_num_workers ())
    {
      /* The request came over the binary api and the inband cli handler
       * is not mp_safe. Drop the barrier to make sure the workers are not
       * blocked.
       */
      if (vlib_thread_is_main_w_barrier ())
	{
	  vpcm->barrier_acq_needed = 1;
	  vlib_worker_thread_barrier_release (vm);
	}
      /*
       * There's a good chance that both the client and the server echo
       * apps will be enabled so make sure the session queue node polls on
       * the main thread as connections will probably be established on it.
       */
      vlib_node_set_state (vm, session_queue_node.index, VLIB_NODE_STATE_POLLING);
    }

  /* App init done only once */
  if (vpcm->app_is_init)
    return 0;

  /* Init test data. Big buffer */
  vec_validate (vpcm->connect_test_data, 4 * 1024 * 1024 - 1);
  for (i = 0; i < vec_len (vpcm->connect_test_data); i++)
    vpcm->connect_test_data[i] = i & 0xff;

  num_threads = 1 /* main thread */ + vlib_num_workers ();
  vec_validate (vpcm->wrk, num_threads - 1);
  vec_foreach (wrk, vpcm->wrk)
    {
      vec_validate (wrk->rx_buf, vec_len (vpcm->connect_test_data) - 1);
    }

  vpcm->app_is_init = 1;

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type = RT_BACKEND_ENGINE_RULE_TABLE };
  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, &args);

  /* Turn on the builtin client input nodes */
  foreach_vlib_main ()
    vlib_node_set_state (this_vlib_main, vperf_clients_node.index, VLIB_NODE_STATE_POLLING);

  vlib_worker_thread_barrier_release (vm);

  return 0;
}

void
vp_client_prealloc_sessions (vp_client_main_t *vpcm)
{
  u32 sessions_per_wrk, n_wrks;
  vp_test_worker_t *wrk;

  n_wrks = vlib_num_workers () ? vlib_num_workers () : 1;

  sessions_per_wrk = vpcm->cfg.n_clients / n_wrks;
  vec_foreach (wrk, vpcm->wrk)
    pool_init_fixed (wrk->sessions, 1.1 * sessions_per_wrk);
}

static void
vp_client_worker_cleanup (vp_test_worker_t *wrk)
{
  pool_free (wrk->sessions);
  vec_free (wrk->conn_indices);
  vec_free (wrk->conns_this_batch);
}

void
vp_client_cleanup (vp_client_main_t *vpcm)
{
  vp_test_worker_t *wrk;

  vec_foreach (wrk, vpcm->wrk)
    vp_client_worker_cleanup (wrk);

  vec_free (vpcm->cfg.uri);
  vec_free (vpcm->appns_id);
  if (vpcm->throughput)
    vpcm->pacing_window_len = 1;
  if (vpcm->barrier_acq_needed)
    vlib_worker_thread_barrier_sync (vpcm->vlib_main);
  clib_spinlock_free (&vpcm->stats.rtt_stats.w_lock);
}

static int
vp_client_ctrl_send (vperf_cmd_t cmd)
{
  vp_client_main_t *vpcm = &vp_client_main;
  session_t *s;
  int rv;

  vpcm->cfg.test_cfg.cmd = cmd;
  if (vpcm->ctrl_session_handle == SESSION_INVALID_HANDLE)
    {
      vp_client_err ("ctrl session went away");
      return -1;
    }

  s = session_get_from_handle_if_valid (vpcm->ctrl_session_handle);
  if (!s)
    {
      vp_client_err ("ctrl session not found");
      return -1;
    }

  vp_client_dbg ("sending test paramters to the server..");
  if (vpcm->cfg.test_cfg.verbose)
    vperf_cfg_dump (&vpcm->cfg.test_cfg, 1);

  rv = svm_fifo_enqueue (s->tx_fifo, sizeof (vpcm->cfg.test_cfg), (u8 *) &vpcm->cfg.test_cfg);
  ASSERT (rv == sizeof (vpcm->cfg.test_cfg));
  session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
  return 0;
}

static int
vp_client_ctrl_session_connected_callback (session_t *s)
{
  vp_client_main_t *vpcm = &vp_client_main;

  s->opaque = VPERF_CTRL_HANDLE;
  vpcm->ctrl_session_handle = session_handle (s);

  /* send test parameters to the server */
  vp_client_ctrl_send (VPERF_CMD_SYNC);
  return 0;
}

static void
vp_client_calc_tput (vp_client_main_t *vpcm)
{
  vlib_main_t *vm = vlib_get_main ();
  vp_test_worker_t *wrk;
  vp_test_session_t *sess;
  f64 pacing_base;
  u64 bytes_paced_target;
  u64 target_size_threshold;

  /* Choose an appropriate data size chunk threshold based on fifo size.
     ~30k is fine for most scenarios, unless the fifo starts getting
     smaller than 48k, where a slight curve is needed. */
  if (PREDICT_TRUE (vpcm->cfg.fifo_size > 49152))
    target_size_threshold = 30720;
  else if (vpcm->cfg.fifo_size > 20480)
    target_size_threshold = 12288;
  else if (vpcm->cfg.fifo_size > 10240)
    target_size_threshold = 6144;
  else
    target_size_threshold = vpcm->cfg.fifo_size;

  /* find a suitable pacing window length & data chunk size */
  bytes_paced_target = vpcm->throughput * vpcm->pacing_window_len / vpcm->cfg.n_clients;
  while (bytes_paced_target > target_size_threshold ||
	 (vpcm->cfg.proto == VP_PROTO_UDP && bytes_paced_target > 1460))
    {
      vpcm->pacing_window_len /= 2;
      bytes_paced_target /= 2;
    }

  /* order sessions to shoot out data sequentially */
  pacing_base = vlib_time_now (vm) - vpcm->pacing_window_len;
  vec_foreach (wrk, vpcm->wrk)
    {
      vec_foreach (sess, wrk->sessions)
	{
	  sess->time_to_send = pacing_base + vpcm->pacing_window_len / vpcm->cfg.n_clients;
	  pacing_base = sess->time_to_send;
	  sess->bytes_paced_target = bytes_paced_target;
	  sess->bytes_paced_current = bytes_paced_target;
	}
    }
}

static int
vp_client_session_connected_callback (u32 app_index, u32 api_context, session_t *s,
				      session_error_t err)
{
  vp_client_main_t *vpcm = &vp_client_main;
  clib_thread_index_t thread_index;
  vp_test_worker_t *wrk;
  const vp_test_proto_vft_t *tp;
  u32 n_connected, n_ready;

  if (PREDICT_FALSE (vpcm->run_test != VP_CLIENT_STARTING))
    return -1;

  if (err)
    {
      vp_client_err ("connection %d failed! %U", api_context, format_session_error, err);
      vpcm->run_test = VP_CLIENT_EXITING;
      signal_evt_to_cli (VP_CLIENT_CLI_CONNECTS_FAILED);
      return 0;
    }

  thread_index = s->thread_index;
  ASSERT (thread_index == vlib_get_thread_index () ||
	  session_transport_service_type (s) == TRANSPORT_SERVICE_CL);

  if (PREDICT_FALSE (api_context == VPERF_CTRL_HANDLE))
    return vp_client_ctrl_session_connected_callback (s);

  wrk = vp_client_worker_get (thread_index);
  tp = &vp_test_main.protos[vpcm->cfg.proto];
  n_connected = tp->connected (s, &vpcm->cfg, wrk, vpcm->app_index);

  n_ready = clib_atomic_add_fetch (&vpcm->ready_connections, n_connected);
  if (n_ready == vpcm->expected_connections)
    {
      /* Signal the CLI process that the action is starting... */
      signal_evt_to_cli (VP_CLIENT_CLI_CONNECTS_DONE);
    }

  return 0;
}

static void
vp_client_session_reset_callback (session_t *s)
{
  vp_client_main_t *vpcm = &vp_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  if (PREDICT_FALSE (s->opaque == VPERF_CTRL_HANDLE ||
		     session_handle (s) == vpcm->ctrl_session_handle))
    {
      vp_client_dbg ("ctrl session reset");
      vp_client_ctrl_session_peer_close (s, 1 /* is_reset */);
      goto disconnect;
    }

  if (s->session_state == SESSION_STATE_READY)
    vp_client_err ("Reset active connection %U", format_session, s, 2);

  vp_client_session_peer_close (s, 1 /* is_reset */);

disconnect:
  a->handle = session_handle (s);
  a->app_index = vpcm->app_index;
  vnet_disconnect_session (a);
  return;
}

static int
vp_client_session_accept_callback (session_t *s)
{
  return 0;
}

static void
vp_client_session_disconnect_callback (session_t *s)
{
  vp_client_main_t *vpcm = &vp_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  if (s->opaque == VPERF_CTRL_HANDLE || session_handle (s) == vpcm->ctrl_session_handle)
    {
      vp_client_dbg ("ctrl session disconnect");
      vp_client_ctrl_session_peer_close (s, 0 /* is_reset */);
    }
  else
    vp_client_session_peer_close (s, 0 /* is_reset */);

  a->handle = session_handle (s);
  a->app_index = vpcm->app_index;
  vnet_disconnect_session (a);
  return;
}

void
vp_client_session_disconnect (session_t *s)
{
  vp_client_main_t *vpcm = &vp_client_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = vpcm->app_index;
  vnet_disconnect_session (a);
}

static int
vp_client_ctrl_session_rx_callback (session_t *s)
{
  vp_client_main_t *vpcm = &vp_client_main;
  int rx_bytes;
  vperf_cfg_t cfg = { 0 };

  rx_bytes = svm_fifo_dequeue (s->rx_fifo, sizeof (cfg), (u8 *) &cfg);
  if (rx_bytes != sizeof (cfg))
    {
      vp_client_err ("invalid cfg length %d (expected %d)", rx_bytes, sizeof (cfg));
      signal_evt_to_cli (VP_CLIENT_CLI_CONNECTS_FAILED);
      return -1;
    }

  vp_client_dbg ("control message received:");
  if (vpcm->cfg.test_cfg.verbose)
    vperf_cfg_dump (&cfg, 1);

  switch (cfg.cmd)
    {
    case VPERF_CMD_SYNC:
      switch (vpcm->run_test)
	{
	case VP_CLIENT_STARTING:
	  if (!vperf_cfg_verify (&cfg, &vpcm->cfg.test_cfg))
	    {
	      vp_client_err ("invalid config received from server!");
	      signal_evt_to_cli (VP_CLIENT_CLI_CONNECTS_FAILED);
	      return -1;
	    }
	  signal_evt_to_cli (VP_CLIENT_CLI_CFG_SYNC);
	  break;

	case VP_CLIENT_RUNNING:
	  vp_client_dbg ("test running..");
	  break;

	case VP_CLIENT_EXITING:
	  /* post test sync */
	  vpcm->stats.peer_bytes_received = cfg.total_bytes;
	  vpcm->stats.peer_dgrams_received = cfg.num_reads;
	  signal_evt_to_cli (VP_CLIENT_CLI_CFG_SYNC);
	  break;

	default:
	  vp_client_err ("unexpected test state! %d", vpcm->run_test);
	  break;
	}
      break;
    case VPERF_CMD_START:
      signal_evt_to_cli (VP_CLIENT_CLI_START);
      break;
    case VPERF_CMD_STOP:
      signal_evt_to_cli (VP_CLIENT_CLI_STOP);
      break;
    default:
      vp_client_err ("unexpected cmd! %d", cfg.cmd);
      break;
    }

  return 0;
}

static int
vp_client_session_rx_callback (session_t *s)
{
  vp_client_main_t *vpcm = &vp_client_main;

  if (PREDICT_FALSE (s->opaque == VPERF_CTRL_HANDLE))
    return vp_client_ctrl_session_rx_callback (s);

  vpcm->rx_callback (s);

  if (svm_fifo_max_dequeue_cons (s->rx_fifo))
    session_enqueue_notify (s);

  return 0;
}

static int
vp_client_add_segment_callback (u32 app_index, u64 segment_handle)
{
  /* New segments may be added */
  return 0;
}

static int
vp_client_del_segment_callback (u32 app_index, u64 segment_handle)
{
  return 0;
}

static session_cb_vft_t vp_client_cb_vft = {
  .session_reset_callback = vp_client_session_reset_callback,
  .session_connected_callback = vp_client_session_connected_callback,
  .session_accept_callback = vp_client_session_accept_callback,
  .session_disconnect_callback = vp_client_session_disconnect_callback,
  .builtin_app_rx_callback = vp_client_session_rx_callback,
  .add_segment_callback = vp_client_add_segment_callback,
  .del_segment_callback = vp_client_del_segment_callback,
};

clib_error_t *
vp_client_attach ()
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  app_ca_trust_add_args_t _ca_args = {}, *ca_args = &_ca_args;
  vp_client_main_t *vpcm = &vp_client_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u32 prealloc_fifos;
  u64 options[18];
  int rv;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = ~0;
  a->name = format (0, "vperf_client");
  a->session_cb_vft = &vp_client_cb_vft;

  prealloc_fifos = vpcm->prealloc_fifos ? vpcm->expected_connections : 1;

  options[APP_OPTIONS_SEGMENT_SIZE] = vpcm->cfg.private_segment_size;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = vpcm->cfg.private_segment_size;
  options[APP_OPTIONS_RX_FIFO_SIZE] = vpcm->cfg.fifo_size;
  options[APP_OPTIONS_TX_FIFO_SIZE] = vpcm->cfg.fifo_size;
  options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = prealloc_fifos;
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_TLS_ENGINE] = vpcm->cfg.tls_engine;
  options[APP_OPTIONS_PCT_FIRST_ALLOC] = 100;
  options[APP_OPTIONS_FLAGS] |= vpcm->attach_flags;
  if (vpcm->appns_id)
    {
      options[APP_OPTIONS_NAMESPACE_SECRET] = vpcm->appns_secret;
      a->namespace_id = vpcm->appns_id;
    }
  a->options = options;

  if ((rv = vnet_application_attach (a)))
    return clib_error_return (0, "attach returned %d", rv);

  vpcm->app_index = a->app_index;
  vec_free (a->name);

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  vpcm->cfg.ckpair_index = ck_pair->index;

  vec_validate (ca_args->ca_chain, test_ca_chain_rsa_len - 1);
  clib_memcpy (ca_args->ca_chain, test_ca_chain_rsa, test_ca_chain_rsa_len);
  vec_validate (ca_args->crl, test_ca_crl_len - 1);
  clib_memcpy (ca_args->crl, test_ca_crl, test_ca_crl_len);
  app_crypto_add_ca_trust (vpcm->app_index, ca_args);
  vpcm->cfg.ca_trust_index = ca_args->index;

  vpcm->test_client_attached = 1;

  return 0;
}

int
vp_client_detach ()
{
  vp_client_main_t *vpcm = &vp_client_main;
  vnet_app_detach_args_t _da, *da = &_da;
  int rv;

  if (!vpcm->test_client_attached)
    return 0;

  da->app_index = vpcm->app_index;
  da->api_client_index = ~0;
  rv = vnet_application_detach (da);
  vpcm->test_client_attached = 0;
  vpcm->app_index = ~0;
  vnet_app_del_cert_key_pair (vpcm->cfg.ckpair_index);

  return rv;
}

static int
vp_client_connect_rpc (void *args)
{
  vp_client_main_t *vpcm = &vp_client_main;
  vnet_connect_args_t _a = {}, *a = &_a;
  int rv;
  u32 n_clients, ci;
  const vp_test_proto_vft_t *tp;

  n_clients = vpcm->cfg.n_clients;
  tp = &vp_test_main.protos[vpcm->cfg.proto];
  clib_memcpy (&a->sep_ext, &vpcm->cfg.sep, sizeof (vpcm->cfg.sep));
  a->sep_ext.transport_flags |= TRANSPORT_CFG_F_CONNECTED;
  a->app_index = vpcm->app_index;

  ci = vpcm->connect_conn_index;

  while (ci < n_clients)
    {
      /* Crude pacing for call setups  */
      if (ci - clib_atomic_load_relax_n (&vpcm->ready_connections) > 128)
	{
	  vpcm->connect_conn_index = ci;
	  break;
	}

      a->api_context = ci;
      rv = tp->connect (a, &vpcm->cfg);
      if (rv)
	{
	  vp_client_err ("connect returned: %U", format_session_error, rv);
	  vpcm->run_test = VP_CLIENT_EXITING;
	  signal_evt_to_cli (VP_CLIENT_CLI_CONNECTS_FAILED);
	  break;
	}

      ci += 1;
    }

  if (ci < vpcm->expected_connections && vpcm->run_test != VP_CLIENT_EXITING)
    vp_client_program_connects ();

  return 0;
}

void
vp_client_program_connects (void)
{
  session_send_rpc_evt_to_thread_force (transport_cl_thread (), vp_client_connect_rpc, 0);
}

static clib_error_t *
vp_client_ctrl_connect_rpc ()
{
  session_error_t rv;
  vp_client_main_t *vpcm = &vp_client_main;
  vnet_connect_args_t _a = {}, *a = &_a;

  a->api_context = VPERF_CTRL_HANDLE;
  vpcm->cfg.test_cfg.cmd = VPERF_CMD_SYNC;
  clib_memcpy (&a->sep_ext, &vpcm->cfg.sep, sizeof (vpcm->cfg.sep));
  a->sep_ext.transport_proto = TRANSPORT_PROTO_TCP;
  a->app_index = vpcm->app_index;

  rv = vnet_connect (a);
  if (rv)
    {
      vp_client_err ("ctrl connect returned: %U", format_session_error, rv);
      vpcm->run_test = VP_CLIENT_EXITING;
      signal_evt_to_cli (VP_CLIENT_CLI_CONNECTS_FAILED);
    }
  return 0;
}

static void
vp_client_ctrl_connect (void)
{
  session_send_rpc_evt_to_thread_force (transport_cl_thread (), vp_client_ctrl_connect_rpc, 0);
}

static void
vp_client_ctrl_session_disconnect ()
{
  vp_client_main_t *vpcm = &vp_client_main;
  vnet_disconnect_args_t _a, *a = &_a;
  session_error_t err;

  if (vpcm->ctrl_session_handle == SESSION_INVALID_HANDLE)
    return;

  a->handle = vpcm->ctrl_session_handle;
  a->app_index = vpcm->app_index;
  err = vnet_disconnect_session (a);
  if (err)
    vp_client_err ("vnet_disconnect_session: %U", format_session_error, err);
}

static int
vp_client_ctrl_test_sync ()
{
  vp_client_main_t *vpcm = &vp_client_main;
  vpcm->cfg.test_cfg.test = VPERF_TEST_TYPE_ECHO;
  return vp_client_ctrl_send (VPERF_CMD_SYNC);
}

static int
vp_client_ctrl_test_start ()
{
  return vp_client_ctrl_send (VPERF_CMD_START);
}

static int
vp_client_ctrl_test_stop ()
{
  return vp_client_ctrl_send (VPERF_CMD_STOP);
}

#define vp_client_wait_for_signal(_sig)                                                            \
  vlib_process_wait_for_event_or_clock (vm, vpcm->syn_timeout);                                    \
  event_type = vlib_process_get_events (vm, &event_data);                                          \
  switch (event_type)                                                                              \
    {                                                                                              \
    case ~0:                                                                                       \
      vp_cli ("Timeout while waiting for " #_sig);                                                 \
      return clib_error_return (0, "failed: timeout while waiting for " #_sig);                    \
    case _sig:                                                                                     \
      break;                                                                                       \
    default:                                                                                       \
      vp_cli ("unexpected event while waiting for " #_sig ": %d", event_type);                     \
      return clib_error_return (0, "failed: unexpected event: %d", event_type);                    \
    }

static void
vp_client_print_timeout_stats (vlib_main_t *vm)
{
  vp_client_main_t *vpcm = &vp_client_main;
  u64 received_bytes = 0, sent_bytes = 0;
  vp_test_worker_t *wrk;
  vp_test_session_t *sess;
  vec_foreach (wrk, vpcm->wrk)
    {
      pool_foreach (sess, wrk->sessions)
	{
	  received_bytes += sess->bytes_received;
	  sent_bytes += sess->bytes_sent;
#if CLIB_DEBUG > 0
	  session_t *s = session_get_from_handle_if_valid (sess->vpp_session_handle);
	  if (s)
	    vp_proto_err ("%U", format_session, s, 2);
#endif
	}
    }
  vp_cli ("Timeout at %.6f with %d sessions still active...", vlib_time_now (vm),
	  vpcm->ready_connections);
  if (vpcm->cfg.echo_bytes)
    {
      vp_cli ("Received %llu bytes out of %llu sent (%llu target)", received_bytes, sent_bytes,
	      vpcm->cfg.bytes_to_send * vpcm->cfg.n_clients);
    }
}

static u8
vp_client_transport_proto_is_cless ()
{
  return (vp_client_main.cfg.proto == VP_PROTO_UDP || vp_client_main.cfg.proto == VP_PROTO_SRTP);
}

clib_error_t *
vp_client_run (vlib_main_t *vm)
{
  vp_client_main_t *vpcm = &vp_client_main;
  uword *event_data = 0, event_type;
  clib_error_t *error = 0;
  f64 delta = 0, wait_time = 0;
  vp_test_worker_t *wrk;
  const vp_test_proto_vft_t *tp = &vp_test_main.protos[vpcm->cfg.proto];

  vec_foreach (wrk, vpcm->wrk)
    {
      wrk->bytes_received = 0;
      wrk->dgrams_received = 0;
      wrk->bytes_sent = 0;
      wrk->dgrams_sent = 0;
    }

  if (vpcm->cfg.test_cfg.test_bytes || (vpcm->cfg.echo_bytes && vpcm->cfg.proto == VP_PROTO_UDP))
    {
      vpcm->cfg.test_cfg.test_bytes = 1;
      vpcm->include_buffer_offset = 1;
    }

  /* set tx function which we'll use */
  if (vpcm->cfg.test_cfg.test_bytes)
    {
      if (vpcm->throughput)
	vpcm->tx_callback =
	  vpcm->cfg.run_time ? vp_client_tx_test_bytes_paced_time : vp_client_tx_test_bytes_paced;
      else
	vpcm->tx_callback =
	  vpcm->cfg.run_time ? vp_client_tx_test_bytes_time : vp_client_tx_test_bytes;
    }
  else
    {
      if (vpcm->throughput)
	vpcm->tx_callback = vpcm->cfg.run_time ? vp_client_tx_zc_paced_time : vp_client_tx_zc_paced;
      else
	vpcm->tx_callback = vpcm->cfg.run_time ? vp_client_tx_zc_time : vp_client_tx_zc;
    }

  /* vperf_server might send one byte on accept */
  vpcm->rx_callback = vp_client_rx;
  if (vpcm->cfg.echo_bytes)
    {
      vpcm->cfg.test_cfg.test = VPERF_TEST_TYPE_BI;
      if (vpcm->include_buffer_offset)
	vpcm->rx_callback = vp_client_rx_test_bytes;
    }
  else
    vpcm->cfg.test_cfg.test = VPERF_TEST_TYPE_UNI;

  if (tp->test_init)
    tp->test_init (vm, vpcm->cli_node_index, &vpcm->cfg);

  vp_client_ctrl_connect ();
  vp_client_wait_for_signal (VP_CLIENT_CLI_CFG_SYNC);

  if (vp_client_ctrl_test_start () < 0)
    {
      return clib_error_return (0, "failed to send start command");
    }
  vp_client_wait_for_signal (VP_CLIENT_CLI_START);

  /*
   * Start. Fire off connect requests
   */

  /* update data port */
  vpcm->cfg.sep.port = vperf_make_data_port (vpcm->cfg.sep.port);

  vpcm->syn_start_time = vlib_time_now (vm);
  vp_client_program_connects ();

  /*
   * Park until the sessions come up, or syn_timeout seconds pass
   */
  vlib_process_wait_for_event_or_clock (vm, vpcm->syn_timeout);
  event_type = vlib_process_get_events (vm, &event_data);
  switch (event_type)
    {
    case ~0:
      vp_cli ("Timeout with only %u sessions active...", vpcm->ready_connections);
      error =
	clib_error_return (0, "failed: syn timeout with %u sessions", vpcm->ready_connections);
      goto stop_test;

    case VP_CLIENT_CLI_CONNECTS_DONE:
      if (clib_atomic_load_relax_n (&vpcm->failed_session_closes))
	{
	  error = clib_error_return (
	    0, "failed: session closed while connecting (%u reset, %u disconnected)",
	    clib_atomic_load_relax_n (&vpcm->reset_count),
	    clib_atomic_load_relax_n (&vpcm->disconnect_count));
	  goto stop_test;
	}
      vpcm->ready_connections = vpcm->expected_connections;
      if (vpcm->throughput)
	vp_client_calc_tput (vpcm);
      vpcm->run_test = VP_CLIENT_RUNNING;
      if (!vp_client_transport_proto_is_cless () && vpcm->expected_connections > 1)
	{
	  delta = vlib_time_now (vm) - vpcm->syn_start_time;
	  if (delta != 0.0)
	    vp_cli ("%u connections established in %.2f seconds %.2f/s", vpcm->cfg.n_clients, delta,
		    ((f64) vpcm->cfg.n_clients) / delta);
	}
      break;

    case VP_CLIENT_CLI_CONNECTS_FAILED:
      {
	u32 close_count = clib_atomic_load_relax_n (&vpcm->failed_session_closes);
	if (close_count)
	  {
	    u32 reset_count = clib_atomic_load_relax_n (&vpcm->reset_count);
	    u32 disconnect_count = clib_atomic_load_relax_n (&vpcm->disconnect_count);
	    error = clib_error_return (
	      0,
	      "failed: connect failed (%u sessions connected, %u session close events "
	      "while connecting: %u reset, %u disconnected)",
	      vpcm->ready_connections, close_count, reset_count, disconnect_count);
	  }
	else
	  error = clib_error_return (0, "failed: connect failed (%u sessions connected)",
				     vpcm->ready_connections);
      }
      goto stop_test;

    default:
      vp_cli ("unexpected event while waiting for connects to finish: %d", event_type);
      error = clib_error_return (0, "failed: unexpected event while waiting for connects: %d",
				 event_type);
      goto stop_test;
    }

  /* Testing officially starts now */
  vpcm->stats.test_start_time = vlib_time_now (vpcm->vlib_main);
  if (vpcm->cfg.report_interval)
    vpcm->stats.last_print_time = vpcm->stats.test_start_time;
  if (vpcm->cfg.test_cfg.verbose)
    vp_cli ("Test started at %.6f", vpcm->stats.test_start_time);

  /*
   * Wait for the sessions to finish or test_timeout (timeout or length
   * of timed run) seconds pass. If providing periodic reports, wake up
   * every now and then to print them and loop.
   */
  u8 main_loop_done = false, print_header = true, report_timeout = false;
  do
    {
      if (vpcm->cfg.report_interval)
	{
	  delta = vlib_time_now (vm) - vpcm->stats.test_start_time;
	  if (delta + (f64) vpcm->cfg.report_interval > vpcm->test_timeout)
	    {
	      report_timeout = true;
	      wait_time = vpcm->test_timeout - delta;
	    }
	  else
	    wait_time = (f64) vpcm->cfg.report_interval;
	}
      else
	{
	  report_timeout = true;
	  wait_time = (f64) vpcm->test_timeout;
	}

      vlib_process_wait_for_event_or_clock (vm, wait_time);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type)
	{
	case ~0:
	  if (report_timeout)
	    {
	      if (vpcm->cfg.run_time)
		{
		  vp_client_sessions_stop_clean ();
		  break;
		}
	      vp_client_print_timeout_stats (vm);
	      if (vpcm->cfg.proto != VP_PROTO_UDP)
		error = clib_error_return (0, "failed: test timeout");
	      else if (vpcm->cfg.echo_bytes)
		{
		  vp_client_sessions_stop_clean ();
		  break;
		}
	      goto stop_test;
	    }
	  else
	    {
	      vp_print_periodic_stats (vm, print_header, &vpcm->cfg, &vpcm->stats, vpcm->wrk);
	      if (PREDICT_FALSE (print_header))
		print_header = false;
	    }
	  break;

	case VP_CLIENT_CLI_TEST_DONE:
	  vpcm->stats.test_end_time = vlib_time_now (vm);
	  main_loop_done = true;
	  break;

	default:
	  vp_cli ("unexpected event while waiting for test end: %d", event_type);
	  error = clib_error_return (0, "failed: unexpected event while waiting for test end: %d",
				     event_type);
	  goto stop_test;
	}
    }
  while (!main_loop_done);

  if (clib_atomic_load_relax_n (&vpcm->failed_session_closes))
    {
      error = clib_error_return (
	0, "failed: %u session close events before test completion (%u reset, %u disconnected)",
	clib_atomic_load_relax_n (&vpcm->failed_session_closes),
	clib_atomic_load_relax_n (&vpcm->reset_count),
	clib_atomic_load_relax_n (&vpcm->disconnect_count));
      goto stop_test;
    }

  delta = vpcm->stats.test_end_time - vpcm->stats.test_start_time;
  if (delta < FLT_EPSILON)
    {
      vp_cli ("zero delta time?");
      error = clib_error_return (0, "failed: zero delta time");
      goto stop_test;
    }

  if (vpcm->cfg.report_interval)
    {
      /* Print last interval */
      if (vlib_time_now (vm) - vpcm->stats.last_print_time >= 0.1f)
	vp_print_periodic_stats (vm, print_header, &vpcm->cfg, &vpcm->stats, vpcm->wrk);
      vp_print_footer (vm, vpcm->cfg.proto);
    }
  if (vpcm->cfg.test_cfg.verbose)
    vp_cli ("Test finished at %.6f", vpcm->stats.test_end_time);

  if (vpcm->cfg.test_cfg.test_bytes && vpcm->test_failed)
    error = clib_error_return (0, "failed: test bytes");

stop_test:
  vpcm->run_test = VP_CLIENT_EXITING;

  if (clib_atomic_load_relax_n (&vpcm->failed_session_closes))
    {
      vp_client_ctrl_session_disconnect ();
      return error;
    }

  vlib_process_wait_for_event_or_clock (vm, VP_TEST_DELAY_DISCONNECT);
  /* no signals are expected - just wait for clock */
  (void) vlib_process_get_events (vm, 0);

  /* send stop test command to the server */
  if (vp_client_ctrl_test_stop () < 0)
    {
      vp_cli ("failed to send stop command");
      return error;
    }
  vp_client_wait_for_signal (VP_CLIENT_CLI_STOP);

  /* post test sync */
  if (vp_client_ctrl_test_sync () < 0)
    {
      vp_cli ("failed to send post sync command");
      return error;
    }
  vp_client_wait_for_signal (VP_CLIENT_CLI_CFG_SYNC);
  if (!error)
    vp_print_final_stats (vm, delta, &vpcm->cfg, &vpcm->stats, vpcm->wrk);

  /* disconnect control session */
  vp_client_ctrl_session_disconnect ();

  return error;
}
clib_error_t *
vp_client_main_init (vlib_main_t *vm)
{
  vp_client_main_t *vpcm = &vp_client_main;
  vpcm->app_is_init = 0;
  return 0;
}

VLIB_INIT_FUNCTION (vp_client_main_init);
