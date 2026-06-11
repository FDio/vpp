/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#include <vperf/builtin/vperf_server.h>
#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>

int vp_server_setup_test (vperf_cfg_t *c);

vp_server_main_t vp_server_main;

#define vp_server_err(_fmt, _args...) clib_warning (_fmt, ##_args);

#define vp_server_dbg(_fmt, _args...)                                                              \
  do                                                                                               \
    {                                                                                              \
      if (PREDICT_FALSE (vp_server_main.cfg.test_cfg.verbose))                                     \
	vp_server_err (_fmt, ##_args);                                                             \
    }                                                                                              \
  while (0)

static void
vp_server_signal_evt_to_cli_i (void *codep)
{
  vp_server_main_t *vpsm = &vp_server_main;
  int code;

  ASSERT (vlib_get_thread_index () == 0);
  code = pointer_to_uword (codep);
  vlib_process_signal_event (vpsm->vlib_main, vpsm->cli_node_index, code, 0);
}

static void
vp_server_signal_evt_to_cli (int code)
{
  vp_server_main_t *vpsm = &vp_server_main;

  if (!vpsm->cfg.report_interval)
    return;

  if (vlib_get_thread_index () != 0)
    session_send_rpc_evt_to_thread_force (0, vp_server_signal_evt_to_cli_i,
					  uword_to_pointer ((uword) code, void *));
  else
    vp_server_signal_evt_to_cli_i (uword_to_pointer ((uword) code, void *));
}

static inline vp_test_worker_t *
vp_server_worker_get (clib_thread_index_t thread_index)
{
  return vec_elt_at_index (vp_server_main.wrk, thread_index);
}

static inline vp_test_session_t *
vp_server_session_get (vp_test_worker_t *wrk, u32 vp_server_index)
{
  return pool_elt_at_index (wrk->sessions, vp_server_index);
}

static int
vp_server_ctrl_session_accept_callback (session_t *s)
{
  s->session_state = SESSION_STATE_READY;
  return 0;
}

static void
vp_server_session_alloc_and_init (session_t *s)
{
  vp_test_session_t *es;
  vp_test_worker_t *wrk = vp_server_worker_get (s->thread_index);

  es = vp_test_session_alloc (wrk);
  vperf_app_session_init (es, s);
  es->vpp_session_handle = session_handle (s);
  s->opaque = es->session_index;
}

int
vp_server_session_accept_callback (session_t *s)
{
  vp_server_main_t *vpsm = &vp_server_main;

  if (PREDICT_FALSE (vpsm->ctrl_listener_handle == s->listener_handle))
    return vp_server_ctrl_session_accept_callback (s);

  s->session_state = SESSION_STATE_READY;
  vp_server_session_alloc_and_init (s);
  return 0;
}

void
vp_server_session_disconnect_callback (session_t *s)
{
  vp_server_main_t *vpsm = &vp_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = vpsm->app_index;
  vnet_disconnect_session (a);
}

void
vp_server_session_reset_callback (session_t *s)
{
  vp_server_main_t *vpsm = &vp_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  vp_server_dbg ("Reset session %U", format_session, s, 2);
  a->handle = session_handle (s);
  a->app_index = vpsm->app_index;
  vnet_disconnect_session (a);
}

int
vp_server_session_connected_callback (u32 app_index, u32 api_context, session_t *s,
				      session_error_t err)
{
  vp_server_err ("called...");
  return -1;
}

int
vp_server_add_segment_callback (u32 client_index, u64 segment_handle)
{
  /* New heaps may be added */
  return 0;
}

int
vp_server_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static void
vp_server_foreach_thread (void *fp)
{
  vp_server_main_t *vpsm = &vp_server_main;
  uword thread_index;
  for (thread_index = 0; thread_index < vec_len (vpsm->wrk); thread_index++)
    {
      session_send_rpc_evt_to_thread (thread_index, fp, uword_to_pointer (thread_index, void *));
    }
}

static int
vp_server_wrk_prealloc_sessions (void *args)
{
  vp_server_main_t *vpsm = &vp_server_main;
  u32 sessions_per_wrk, n_wrks, thread_index;

  thread_index = pointer_to_uword (args);
  vp_test_worker_t *wrk = vp_server_worker_get (thread_index);
  n_wrks = vlib_num_workers () ? vlib_num_workers () : 1;
  sessions_per_wrk = vpsm->cfg.test_cfg.num_test_sessions / n_wrks;
  pool_alloc (wrk->sessions, 1.1 * sessions_per_wrk);
  return 0;
}

static void
vp_server_agregate_wrk_stats (vp_server_main_t *vpsm)
{
  vp_test_session_t *es;
  vp_test_worker_t *wrk;

  pool_foreach (wrk, vpsm->wrk)
    {
      pool_foreach (es, wrk->sessions)
	{
	  wrk->bytes_received += es->bytes_received;
	  wrk->dgrams_received += es->dgrams_received;
	  wrk->bytes_sent += es->bytes_sent;
	  wrk->dgrams_sent += es->dgrams_sent;
	}
    }
}

static int
vp_server_wrk_cleanup_sessions (void *args)
{
  vp_server_main_t *vpsm = &vp_server_main;
  vnet_disconnect_args_t _a = {}, *a = &_a;
  clib_thread_index_t thread_index = pointer_to_uword (args);
  vp_test_session_t *es;
  vp_test_worker_t *wrk;

  wrk = vp_server_worker_get (thread_index);
  a->app_index = vpsm->app_index;

  pool_foreach (es, wrk->sessions)
    {
      a->handle = es->vpp_session_handle;
      vnet_disconnect_session (a);
    }
  pool_free (wrk->sessions);

  return 0;
}

static void
vp_server_reset_stats ()
{
  vp_server_main_t *vpsm = &vp_server_main;
  vp_test_worker_t *wrk;
  pool_foreach (wrk, vpsm->wrk)
    {
      wrk->bytes_received = 0;
      wrk->dgrams_received = 0;
      wrk->bytes_sent = 0;
      wrk->dgrams_sent = 0;
    }
  vpsm->stats.test_start_time = vpsm->stats.last_print_time = vlib_time_now (vlib_get_main ());
  vpsm->stats.last_total_tx_bytes = 0;
  vpsm->stats.last_total_rx_bytes = 0;
  vpsm->stats.last_total_rx_dgrams = 0;
  vpsm->stats.last_total_tx_dgrams = 0;
  vpsm->stats.rtt_stats.min_rtt = CLIB_F64_MAX;
  vpsm->stats.rtt_stats.max_rtt = 0.0;
  vpsm->stats.rtt_stats.sum_rtt = 0.0;
  vpsm->stats.rtt_stats.last_rtt = 0.0;
  vpsm->stats.rtt_stats.n_sum = 0;
}

static void
vp_server_ctrl_reply (session_t *s, u8 final_sync)
{
  vp_server_main_t *vpsm = &vp_server_main;
  int rv;
  vp_test_worker_t *wrk;

  if (final_sync)
    {
      /* sync server rx stats */
      vpsm->cfg.test_cfg.total_bytes = 0;
      vpsm->cfg.test_cfg.num_reads = 0;
      pool_foreach (wrk, vpsm->wrk)
	{
	  vpsm->cfg.test_cfg.total_bytes += wrk->bytes_received;
	  vpsm->cfg.test_cfg.num_reads += wrk->dgrams_received;
	}
    }
  rv = svm_fifo_enqueue (s->tx_fifo, sizeof (vpsm->cfg.test_cfg), (u8 *) &vpsm->cfg.test_cfg);
  ASSERT (rv == sizeof (vpsm->cfg.test_cfg));
  session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
}

static int
vp_server_test_cmd_sync (vp_server_main_t *vpsm, session_t *s)
{
  int rv;

  rv = vp_server_setup_test (&vpsm->cfg.test_cfg);
  if (rv)
    vp_server_err ("setup test error!");

  vp_server_ctrl_reply (s, 0);
  return 0;
}

static int
vp_server_rx_ctrl_callback (session_t *s)
{
  vp_server_main_t *vpsm = &vp_server_main;
  int rv;

  rv = svm_fifo_dequeue (s->rx_fifo, sizeof (vpsm->cfg.test_cfg), (u8 *) &vpsm->cfg.test_cfg);
  ASSERT (rv == sizeof (vpsm->cfg.test_cfg));

  vp_server_dbg ("control message received:");
  if (vpsm->cfg.test_cfg.verbose)
    vperf_cfg_dump (&vpsm->cfg.test_cfg, 0);

  switch (vpsm->cfg.test_cfg.cmd)
    {
    case VPERF_CMD_SYNC:
      switch (vpsm->cfg.test_cfg.test)
	{
	case VPERF_TEST_TYPE_ECHO:
	case VPERF_TEST_TYPE_NONE:
	  vp_server_foreach_thread (vp_server_wrk_cleanup_sessions);
	  vp_server_ctrl_reply (s, 1);
	  break;
	case VPERF_TEST_TYPE_UNI:
	case VPERF_TEST_TYPE_BI:
	  return vp_server_test_cmd_sync (vpsm, s);
	  break;
	default:
	  vp_server_err ("unknown command type! %d", vpsm->cfg.test_cfg.cmd);
	}
      break;
    case VPERF_CMD_START:
      vp_server_reset_stats ();
      vp_server_ctrl_reply (s, 0);
      vp_server_signal_evt_to_cli (VP_SERVER_CLI_START);
      break;
    case VPERF_CMD_STOP:
      vpsm->stats.test_end_time = vlib_time_now (vlib_get_main ()) - VP_TEST_DELAY_DISCONNECT;
      vp_server_agregate_wrk_stats (vpsm);
      vp_server_signal_evt_to_cli (VP_SERVER_CLI_STOP);
      vp_server_ctrl_reply (s, 0);
      break;
    default:
      vp_server_err ("unknown command! %d", vpsm->cfg.test_cfg.cmd);
      break;
    }
  return 0;
}

/*
 * If no-echo, just drop the data and be done with it.
 */
static int
vp_server_rx_no_echo_callback (session_t *s)
{
  vp_server_main_t *vpsm = &vp_server_main;
  vp_test_worker_t *wrk;
  const vp_test_proto_vft_t *tp;
  vp_test_session_t *es;

  /* Closes are treated as half-closes by session layer */
  if (PREDICT_FALSE (s->flags & SESSION_F_APP_CLOSED))
    return 0;

  if (PREDICT_FALSE (vpsm->ctrl_listener_handle == s->listener_handle))
    return vp_server_rx_ctrl_callback (s);

  tp = &vp_test_main.protos[vpsm->cfg.proto];
  wrk = vp_server_worker_get (s->thread_index);
  es = vp_server_session_get (wrk, s->opaque);
  tp->server_rx_no_echo (es, s);

  return 0;
}

always_inline int
vp_server_rx (session_t *s, u8 test_bytes)
{
  vp_server_main_t *vpsm = &vp_server_main;
  clib_thread_index_t thread_index = s->thread_index;
  vp_test_worker_t *wrk;
  vp_test_session_t *es;
  const vp_test_proto_vft_t *tp;

  ASSERT (thread_index == vlib_get_thread_index ());

  /* Closes are treated as half-closes by session layer */
  if (PREDICT_FALSE (s->flags & SESSION_F_APP_CLOSED))
    return 0;

  if (PREDICT_FALSE (vpsm->ctrl_listener_handle == s->listener_handle))
    return vp_server_rx_ctrl_callback (s);

  tp = &vp_test_main.protos[vpsm->cfg.proto];
  wrk = vp_server_worker_get (thread_index);
  es = vp_server_session_get (wrk, s->opaque);
  if (test_bytes)
    return tp->server_rx_test_bytes (es, s, wrk->rx_buf);
  else
    return tp->server_rx (es, s, wrk->rx_buf);
}

static int
vp_server_rx_callback (session_t *s)
{
  return vp_server_rx (s, 0);
}

static int
vp_server_rx_test_bytes_callback (session_t *s)
{
  return vp_server_rx (s, 1);
}

int
vp_server_setup_test (vperf_cfg_t *c)
{
  vp_server_main_t *vpsm = &vp_server_main;

  if (c->test == VPERF_TEST_TYPE_UNI)
    {
      vpsm->cfg.echo_bytes = 0;
      vpsm->rx_callback = vp_server_rx_no_echo_callback;
    }
  else
    {
      vpsm->cfg.echo_bytes = 1;
      if (c->test_bytes)
	vpsm->rx_callback = vp_server_rx_test_bytes_callback;
      else
	vpsm->rx_callback = vp_server_rx_callback;
    }

  vp_server_foreach_thread (vp_server_wrk_prealloc_sessions);
  return 0;
}

int
vp_server_rx_callback_common (session_t *s)
{
  vp_server_main_t *vpsm = &vp_server_main;
  return vpsm->rx_callback (s);
}

static session_cb_vft_t vp_server_session_cb_vft = {
  .session_accept_callback = vp_server_session_accept_callback,
  .session_disconnect_callback = vp_server_session_disconnect_callback,
  .session_connected_callback = vp_server_session_connected_callback,
  .add_segment_callback = vp_server_add_segment_callback,
  .del_segment_callback = vp_server_del_segment_callback,
  .builtin_app_rx_callback = vp_server_rx_callback_common,
  .session_reset_callback = vp_server_session_reset_callback
};

static int
vp_server_attach (u8 *appns_id, u64 appns_flags, u64 appns_secret)
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  vp_server_main_t *vpsm = &vp_server_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  vpsm->rx_callback = vp_server_rx_callback;

  a->api_client_index = ~0;
  a->name = format (0, "vperf_server");
  a->session_cb_vft = &vp_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = vpsm->cfg.private_segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = vpsm->cfg.private_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = vpsm->cfg.fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = vpsm->cfg.fifo_size;
  a->options[APP_OPTIONS_TLS_ENGINE] = vpsm->cfg.tls_engine;
  a->options[APP_OPTIONS_PCT_FIRST_ALLOC] = 100;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] =
    vpsm->cfg.prealloc_fifos ? vpsm->cfg.prealloc_fifos : 1;

  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  if (appns_id)
    {
      a->namespace_id = appns_id;
      a->options[APP_OPTIONS_FLAGS] |= appns_flags;
      a->options[APP_OPTIONS_NAMESPACE_SECRET] = appns_secret;
    }

  if (vnet_application_attach (a))
    {
      vp_server_err ("failed to attach server");
      return -1;
    }
  vpsm->app_index = a->app_index;
  vec_free (a->name);

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  vpsm->cfg.ckpair_index = ck_pair->index;

  return 0;
}

int
vp_server_detach (void)
{
  vp_server_main_t *vpsm = &vp_server_main;
  vnet_app_detach_args_t _da, *da = &_da;
  int rv;

  vp_server_foreach_thread (vp_server_wrk_cleanup_sessions);

  da->app_index = vpsm->app_index;
  da->api_client_index = ~0;
  rv = vnet_application_detach (da);
  vpsm->app_index = APP_INVALID_INDEX;
  vnet_app_del_cert_key_pair (vpsm->cfg.ckpair_index);
  clib_spinlock_free (&vpsm->stats.rtt_stats.w_lock);
  return rv;
}

static int
vp_server_listen_ctrl ()
{
  vp_server_main_t *vpsm = &vp_server_main;
  vnet_listen_args_t _args = {}, *args = &_args;
  session_error_t rv;

  clib_memcpy (&args->sep_ext, &vpsm->cfg.sep, sizeof (vpsm->cfg.sep));
  args->sep_ext.transport_proto = TRANSPORT_PROTO_TCP;
  args->app_index = vpsm->app_index;

  rv = vnet_listen (args);
  vpsm->ctrl_listener_handle = args->handle;
  return rv;
}

static int
vp_server_listen ()
{
  i32 rv;
  vp_server_main_t *vpsm = &vp_server_main;
  vnet_listen_args_t _args = {}, *args = &_args;
  const vp_test_proto_vft_t *tp;

  clib_memcpy (&args->sep_ext, &vpsm->cfg.sep, sizeof (vpsm->cfg.sep));
  vp_test_set_proto (&vpsm->cfg);
  tp = &vp_test_main.protos[vpsm->cfg.proto];
  args->app_index = vpsm->app_index;
  args->sep_ext.port = vperf_make_data_port (args->sep_ext.port);
  rv = tp->listen (args, &vpsm->cfg);
  vpsm->listener_handle = args->handle;
  return rv;
}

int
vp_server_create (vlib_main_t *vm, u8 *appns_id, u64 appns_flags, u64 appns_secret)
{
  vp_server_main_t *vpsm = &vp_server_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  vp_test_worker_t *wrk;

  vec_validate (vpsm->wrk, vtm->n_threads);

  vec_foreach (wrk, vpsm->wrk)
    {
      vec_validate (wrk->rx_buf, vpsm->cfg.fifo_size);
    }

  if (vp_server_attach (appns_id, appns_flags, appns_secret))
    {
      vp_server_err ("failed to attach server");
      return -1;
    }
  if (vp_server_listen_ctrl ())
    {
      vp_server_err ("failed to start listening on ctrl session");
      if (vp_server_detach ())
	vp_server_err ("failed to detach");
      return -1;
    }
  if (vp_server_listen ())
    {
      vp_server_err ("failed to start listening");
      if (vp_server_detach ())
	vp_server_err ("failed to detach");
      return -1;
    }
  return 0;
}

void
vp_server_init (vlib_main_t *vm)
{
  vp_server_main_t *vpsm = &vp_server_main;
  session_endpoint_cfg_t sep_null = SESSION_ENDPOINT_CFG_NULL;

  /* Store cli process node index for signaling */
  vpsm->cli_node_index = vlib_get_current_process (vm)->node_runtime.node_index;
  vpsm->vlib_main = vm;
  vpsm->cfg.fifo_size = 4 << 20;
  vpsm->cfg.prealloc_fifos = 0;
  vpsm->cfg.private_segment_size = 512 << 20;
  vpsm->cfg.tls_engine = CRYPTO_ENGINE_OPENSSL;
  vpsm->cfg.report_interval = 0;
  vpsm->cfg.is_server = 1;
  vpsm->cfg.http_connect_proto = VP_HTTP_CONNECT_PROTO_NONE;
  vpsm->cfg.sep = sep_null;
  if (vpsm->app_index == APP_INVALID_INDEX)
    clib_spinlock_init (&vpsm->stats.rtt_stats.w_lock);
  vec_free (vpsm->cfg.uri);
}

clib_error_t *
vp_server_main_init (vlib_main_t *vm)
{
  vp_server_main_t *vpsm = &vp_server_main;
  vpsm->app_index = APP_INVALID_INDEX;
  return 0;
}

VLIB_INIT_FUNCTION (vp_server_main_init);
