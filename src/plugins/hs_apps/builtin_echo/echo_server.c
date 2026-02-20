/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#include <hs_apps/builtin_echo/echo_server.h>
#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>

int echo_server_setup_test (hs_test_cfg_t *c);

echo_server_main_t echo_server_main;

#define es_err(_fmt, _args...) clib_warning (_fmt, ##_args);

#define es_dbg(_fmt, _args...)                                                                     \
  do                                                                                               \
    {                                                                                              \
      if (PREDICT_FALSE (echo_server_main.cfg.test_cfg.verbose))                                   \
	es_err (_fmt, ##_args);                                                                    \
    }                                                                                              \
  while (0)

static inline echo_test_worker_t *
es_worker_get (clib_thread_index_t thread_index)
{
  return vec_elt_at_index (echo_server_main.wrk, thread_index);
}

static inline echo_test_session_t *
es_session_get (echo_test_worker_t *wrk, u32 es_index)
{
  return pool_elt_at_index (wrk->sessions, es_index);
}

static int
echo_server_ctrl_session_accept_callback (session_t *s)
{
  s->session_state = SESSION_STATE_READY;
  return 0;
}

static void
es_session_alloc_and_init (session_t *s)
{
  echo_test_session_t *es;
  echo_test_worker_t *wrk = es_worker_get (s->thread_index);

  es = echo_test_session_alloc (wrk);
  hs_test_app_session_init (es, s);
  es->vpp_session_handle = session_handle (s);
  s->opaque = es->session_index;
}

int
echo_server_session_accept_callback (session_t *s)
{
  echo_server_main_t *esm = &echo_server_main;

  if (PREDICT_FALSE (esm->ctrl_listener_handle == s->listener_handle))
    return echo_server_ctrl_session_accept_callback (s);

  s->session_state = SESSION_STATE_READY;
  es_session_alloc_and_init (s);
  return 0;
}

void
echo_server_session_disconnect_callback (session_t *s)
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = esm->app_index;
  vnet_disconnect_session (a);
}

void
echo_server_session_reset_callback (session_t *s)
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  es_dbg ("Reset session %U", format_session, s, 2);
  a->handle = session_handle (s);
  a->app_index = esm->app_index;
  vnet_disconnect_session (a);
}

int
echo_server_session_connected_callback (u32 app_index, u32 api_context, session_t *s,
					session_error_t err)
{
  es_err ("called...");
  return -1;
}

int
echo_server_add_segment_callback (u32 client_index, u64 segment_handle)
{
  /* New heaps may be added */
  return 0;
}

int
echo_server_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static void
es_foreach_thread (void *fp)
{
  echo_server_main_t *esm = &echo_server_main;
  uword thread_index;
  for (thread_index = 0; thread_index < vec_len (esm->wrk); thread_index++)
    {
      session_send_rpc_evt_to_thread (thread_index, fp, uword_to_pointer (thread_index, void *));
    }
}

static int
es_wrk_prealloc_sessions (void *args)
{
  echo_server_main_t *esm = &echo_server_main;
  u32 sessions_per_wrk, n_wrks, thread_index;

  thread_index = pointer_to_uword (args);
  echo_test_worker_t *wrk = es_worker_get (thread_index);
  n_wrks = vlib_num_workers () ? vlib_num_workers () : 1;
  sessions_per_wrk = esm->cfg.test_cfg.num_test_sessions / n_wrks;
  pool_alloc (wrk->sessions, 1.1 * sessions_per_wrk);
  return 0;
}

static int
es_wrk_cleanup_sessions (void *args)
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_disconnect_args_t _a = {}, *a = &_a;
  clib_thread_index_t thread_index = pointer_to_uword (args);
  echo_test_session_t *es;
  echo_test_worker_t *wrk;

  wrk = es_worker_get (thread_index);
  a->app_index = esm->app_index;

  pool_foreach (es, wrk->sessions)
    {
      wrk->bytes_received += es->bytes_received;
      wrk->dgrams_received += es->dgrams_received;
      a->handle = es->vpp_session_handle;
      vnet_disconnect_session (a);
    }
  pool_free (wrk->sessions);

  return 0;
}

static void
es_reset_stats ()
{
  echo_server_main_t *esm = &echo_server_main;
  echo_test_worker_t *wrk;
  pool_foreach (wrk, esm->wrk)
    {
      wrk->bytes_received = 0;
      wrk->dgrams_received = 0;
    }
}

static void
echo_server_ctrl_reply (session_t *s, u8 final_sync)
{
  echo_server_main_t *esm = &echo_server_main;
  int rv;
  echo_test_worker_t *wrk;

  if (final_sync)
    {
      /* sync server rx stats */
      esm->cfg.test_cfg.total_bytes = 0;
      esm->cfg.test_cfg.num_reads = 0;
      pool_foreach (wrk, esm->wrk)
	{
	  esm->cfg.test_cfg.total_bytes += wrk->bytes_received;
	  esm->cfg.test_cfg.num_reads += wrk->dgrams_received;
	}
    }
  rv = svm_fifo_enqueue (s->tx_fifo, sizeof (esm->cfg.test_cfg), (u8 *) &esm->cfg.test_cfg);
  ASSERT (rv == sizeof (esm->cfg.test_cfg));
  session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
}

static int
es_test_cmd_sync (echo_server_main_t *esm, session_t *s)
{
  int rv;

  rv = echo_server_setup_test (&esm->cfg.test_cfg);
  if (rv)
    es_err ("setup test error!");

  echo_server_ctrl_reply (s, 0);
  return 0;
}

static int
echo_server_rx_ctrl_callback (session_t *s)
{
  echo_server_main_t *esm = &echo_server_main;
  int rv;

  rv = svm_fifo_dequeue (s->rx_fifo, sizeof (esm->cfg.test_cfg), (u8 *) &esm->cfg.test_cfg);
  ASSERT (rv == sizeof (esm->cfg.test_cfg));

  es_dbg ("control message received:");
  if (esm->cfg.test_cfg.verbose)
    hs_test_cfg_dump (&esm->cfg.test_cfg, 0);

  switch (esm->cfg.test_cfg.cmd)
    {
    case HS_TEST_CMD_SYNC:
      switch (esm->cfg.test_cfg.test)
	{
	case HS_TEST_TYPE_ECHO:
	case HS_TEST_TYPE_NONE:
	  es_foreach_thread (es_wrk_cleanup_sessions);
	  echo_server_ctrl_reply (s, 1);
	  break;
	case HS_TEST_TYPE_UNI:
	case HS_TEST_TYPE_BI:
	  es_reset_stats ();
	  return es_test_cmd_sync (esm, s);
	  break;
	default:
	  es_err ("unknown command type! %d", esm->cfg.test_cfg.cmd);
	}
      break;
    case HS_TEST_CMD_START:
    case HS_TEST_CMD_STOP:
      echo_server_ctrl_reply (s, 0);
      break;
    default:
      es_err ("unknown command! %d", esm->cfg.test_cfg.cmd);
      break;
    }
  return 0;
}

/*
 * If no-echo, just drop the data and be done with it.
 */
static int
echo_server_rx_no_echo_callback (session_t *s)
{
  echo_server_main_t *esm = &echo_server_main;
  echo_test_worker_t *wrk;
  const echo_test_proto_vft_t *tp;
  echo_test_session_t *es;

  /* Closes are treated as half-closes by session layer */
  if (PREDICT_FALSE (s->flags & SESSION_F_APP_CLOSED))
    return 0;

  if (PREDICT_FALSE (esm->ctrl_listener_handle == s->listener_handle))
    return echo_server_rx_ctrl_callback (s);

  tp = &echo_test_main.protos[esm->cfg.proto];
  wrk = es_worker_get (s->thread_index);
  es = es_session_get (wrk, s->opaque);
  tp->server_rx_no_echo (es, s);

  return 0;
}

always_inline int
echo_server_rx (session_t *s, u8 test_bytes)
{
  echo_server_main_t *esm = &echo_server_main;
  clib_thread_index_t thread_index = s->thread_index;
  echo_test_worker_t *wrk;
  echo_test_session_t *es;
  const echo_test_proto_vft_t *tp;

  ASSERT (thread_index == vlib_get_thread_index ());

  /* Closes are treated as half-closes by session layer */
  if (PREDICT_FALSE (s->flags & SESSION_F_APP_CLOSED))
    return 0;

  if (PREDICT_FALSE (esm->ctrl_listener_handle == s->listener_handle))
    return echo_server_rx_ctrl_callback (s);

  tp = &echo_test_main.protos[esm->cfg.proto];
  wrk = es_worker_get (thread_index);
  es = es_session_get (wrk, s->opaque);
  if (test_bytes)
    return tp->server_rx_test_bytes (es, s, wrk->rx_buf);
  else
    return tp->server_rx (es, s, wrk->rx_buf);
}

static int
echo_server_rx_callback (session_t *s)
{
  return echo_server_rx (s, 0);
}

static int
echo_server_rx_test_bytes_callback (session_t *s)
{
  return echo_server_rx (s, 1);
}

int
echo_server_setup_test (hs_test_cfg_t *c)
{
  echo_server_main_t *esm = &echo_server_main;

  if (c->test == HS_TEST_TYPE_UNI)
    esm->rx_callback = echo_server_rx_no_echo_callback;
  else
    {
      if (c->test_bytes)
	esm->rx_callback = echo_server_rx_test_bytes_callback;
      else
	esm->rx_callback = echo_server_rx_callback;
    }

  es_foreach_thread (es_wrk_prealloc_sessions);
  return 0;
}

int
echo_server_rx_callback_common (session_t *s)
{
  echo_server_main_t *esm = &echo_server_main;
  return esm->rx_callback (s);
}

static session_cb_vft_t echo_server_session_cb_vft = {
  .session_accept_callback = echo_server_session_accept_callback,
  .session_disconnect_callback = echo_server_session_disconnect_callback,
  .session_connected_callback = echo_server_session_connected_callback,
  .add_segment_callback = echo_server_add_segment_callback,
  .del_segment_callback = echo_server_del_segment_callback,
  .builtin_app_rx_callback = echo_server_rx_callback_common,
  .session_reset_callback = echo_server_session_reset_callback
};

static int
echo_server_attach (u8 *appns_id, u64 appns_flags, u64 appns_secret)
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  echo_server_main_t *esm = &echo_server_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  esm->rx_callback = echo_server_rx_callback;

  a->api_client_index = ~0;
  a->name = format (0, "echo_server");
  a->session_cb_vft = &echo_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = esm->cfg.private_segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = esm->cfg.private_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = esm->cfg.fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = esm->cfg.fifo_size;
  a->options[APP_OPTIONS_TLS_ENGINE] = esm->cfg.tls_engine;
  a->options[APP_OPTIONS_PCT_FIRST_ALLOC] = 100;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] =
    esm->cfg.prealloc_fifos ? esm->cfg.prealloc_fifos : 1;

  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  if (appns_id)
    {
      a->namespace_id = appns_id;
      a->options[APP_OPTIONS_FLAGS] |= appns_flags;
      a->options[APP_OPTIONS_NAMESPACE_SECRET] = appns_secret;
    }

  if (vnet_application_attach (a))
    {
      es_err ("failed to attach server");
      return -1;
    }
  esm->app_index = a->app_index;
  vec_free (a->name);

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  esm->cfg.ckpair_index = ck_pair->index;

  return 0;
}

int
echo_server_detach (void)
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_app_detach_args_t _da, *da = &_da;
  int rv;

  da->app_index = esm->app_index;
  da->api_client_index = ~0;
  rv = vnet_application_detach (da);
  esm->app_index = ~0;
  vnet_app_del_cert_key_pair (esm->cfg.ckpair_index);
  return rv;
}

static int
echo_server_listen_ctrl ()
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_listen_args_t _args = {}, *args = &_args;
  session_error_t rv;

  if ((rv = parse_uri (esm->cfg.uri, &args->sep_ext)))
    return -1;
  args->sep_ext.transport_proto = TRANSPORT_PROTO_TCP;
  args->app_index = esm->app_index;

  rv = vnet_listen (args);
  esm->ctrl_listener_handle = args->handle;
  return rv;
}

static int
echo_server_listen ()
{
  i32 rv;
  echo_server_main_t *esm = &echo_server_main;
  vnet_listen_args_t _args = {}, *args = &_args;
  const echo_test_proto_vft_t *tp;

  if ((rv = parse_uri (esm->cfg.uri, &args->sep_ext)))
    {
      return -1;
    }
  esm->cfg.proto = args->sep_ext.transport_proto;
  tp = &echo_test_main.protos[esm->cfg.proto];
  args->app_index = esm->app_index;
  args->sep_ext.port = hs_make_data_port (args->sep_ext.port);
  rv = tp->listen (args, &esm->cfg);
  esm->listener_handle = args->handle;
  return rv;
}

int
echo_server_create (vlib_main_t *vm, u8 *appns_id, u64 appns_flags, u64 appns_secret)
{
  echo_server_main_t *esm = &echo_server_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  echo_test_worker_t *wrk;

  vec_validate (esm->wrk, vtm->n_threads);

  vec_foreach (wrk, esm->wrk)
    {
      vec_validate (wrk->rx_buf, esm->cfg.fifo_size);
    }

  if (echo_server_attach (appns_id, appns_flags, appns_secret))
    {
      es_err ("failed to attach server");
      return -1;
    }
  if (echo_server_listen_ctrl ())
    {
      es_err ("failed to start listening on ctrl session");
      if (echo_server_detach ())
	es_err ("failed to detach");
      return -1;
    }
  if (echo_server_listen ())
    {
      es_err ("failed to start listening");
      if (echo_server_detach ())
	es_err ("failed to detach");
      return -1;
    }
  return 0;
}

clib_error_t *
echo_server_main_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (echo_server_main_init);
