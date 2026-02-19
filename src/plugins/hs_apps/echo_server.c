/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#include <hs_apps/hs_test.h>
#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>

static void es_set_echo_rx_callbacks (u8 no_echo);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define _(type, name) type name;
  foreach_app_session_field
#undef _
    u64 vpp_session_handle;
  u32 vpp_session_index;
  u32 rx_retries;
  u8 byte_index;
} es_session_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  es_session_t *sessions;
  u8 *rx_buf; /**< Per-thread RX buffer */
  svm_msg_q_t *vpp_event_queue;
  clib_thread_index_t thread_index;
} es_worker_t;

typedef struct
{
  u32 app_index;		/**< Server app index */

  /*
   * Config params
   */
  hs_test_cfg_t cfg;
  u32 fifo_size;		/**< Fifo size */
  u32 rcv_buffer_size;		/**< Rcv buffer size */
  u32 prealloc_fifos;		/**< Preallocate fifos */
  u32 private_segment_count;	/**< Number of private segments  */
  u64 private_segment_size;	/**< Size of private segments  */
  char *server_uri;		/**< Server URI */
  u32 tls_engine;		/**< TLS engine: mbedtls/openssl */
  u32 ckpair_index;		/**< Cert and key for tls/quic */

  /*
   * Test state
   */
  es_worker_t *wrk;
  int (*rx_callback) (session_t *session);
  u8 transport_proto;
  u64 listener_handle;		/**< Session handle of the root listener */
  u64 ctrl_listener_handle;

  vlib_main_t *vlib_main;
} echo_server_main_t;

echo_server_main_t echo_server_main;

#define es_err(_fmt, _args...) clib_warning (_fmt, ##_args);

#define es_dbg(_fmt, _args...)                                                \
  do                                                                          \
    {                                                                         \
      if (PREDICT_FALSE (echo_server_main.cfg.verbose))                       \
	es_err (_fmt, ##_args);                                               \
    }                                                                         \
  while (0)

#define es_cli(_fmt, _args...) vlib_cli_output (vm, _fmt, ##_args)

static inline es_worker_t *
es_worker_get (clib_thread_index_t thread_index)
{
  return vec_elt_at_index (echo_server_main.wrk, thread_index);
}

static inline es_session_t *
es_session_alloc (es_worker_t *wrk)
{
  es_session_t *es;

  pool_get_zero (wrk->sessions, es);
  es->session_index = es - wrk->sessions;
  return es;
}

static inline es_session_t *
es_session_get (es_worker_t *wrk, u32 es_index)
{
  return pool_elt_at_index (wrk->sessions, es_index);
}

int
quic_echo_server_qsession_accept_callback (session_t * s)
{
  es_dbg ("QSession %u accept w/opaque %d", s->session_index, s->opaque);
  s->session_state = SESSION_STATE_READY;
  return 0;
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
  es_session_t *es;
  es_worker_t *wrk = es_worker_get (s->thread_index);

  es = es_session_alloc (wrk);
  hs_test_app_session_init (es, s);
  es->vpp_session_index = s->session_index;
  es->vpp_session_handle = session_handle (s);
  s->opaque = es->session_index;
}

int
quic_echo_server_session_accept_callback (session_t * s)
{
  echo_server_main_t *esm = &echo_server_main;

  if (PREDICT_FALSE (esm->ctrl_listener_handle == s->listener_handle))
    return echo_server_ctrl_session_accept_callback (s);

  if (s->listener_handle == esm->listener_handle)
    return quic_echo_server_qsession_accept_callback (s);

  es_dbg ("SSESSION %u accept w/opaque %d", s->session_index, s->opaque);

  s->session_state = SESSION_STATE_READY;
  es_session_alloc_and_init (s);
  return 0;
}

int
echo_server_session_accept_callback (session_t * s)
{
  echo_server_main_t *esm = &echo_server_main;

  if (PREDICT_FALSE (esm->ctrl_listener_handle == s->listener_handle))
    return echo_server_ctrl_session_accept_callback (s);

  s->session_state = SESSION_STATE_READY;
  es_session_alloc_and_init (s);
  return 0;
}

void
echo_server_session_disconnect_callback (session_t * s)
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = esm->app_index;
  vnet_disconnect_session (a);
}

void
echo_server_session_reset_callback (session_t * s)
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  es_dbg ("Reset session %U", format_session, s, 2);
  a->handle = session_handle (s);
  a->app_index = esm->app_index;
  vnet_disconnect_session (a);
}

int
echo_server_session_connected_callback (u32 app_index, u32 api_context,
					session_t * s, session_error_t err)
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

int
echo_server_redirect_connect_callback (u32 client_index, void *mp)
{
  es_err ("called...");
  return -1;
}

static void
es_foreach_thread (void *fp)
{
  echo_server_main_t *esm = &echo_server_main;
  uword thread_index;
  for (thread_index = 0; thread_index < vec_len (esm->wrk); thread_index++)
    {
      session_send_rpc_evt_to_thread (thread_index, fp,
				      uword_to_pointer (thread_index, void *));
    }
}

static int
es_wrk_prealloc_sessions (void *args)
{
  echo_server_main_t *esm = &echo_server_main;
  u32 sessions_per_wrk, n_wrks, thread_index;

  thread_index = pointer_to_uword (args);
  es_worker_t *wrk = es_worker_get (thread_index);
  n_wrks = vlib_num_workers () ? vlib_num_workers () : 1;
  sessions_per_wrk = esm->cfg.num_test_sessions / n_wrks;
  pool_alloc (wrk->sessions, 1.1 * sessions_per_wrk);
  return 0;
}

static int
echo_server_setup_test (hs_test_cfg_t *c)
{
  if (c->test == HS_TEST_TYPE_UNI)
    es_set_echo_rx_callbacks (1 /* no echo */);
  else
    es_set_echo_rx_callbacks (0 /* no echo */);

  es_foreach_thread (es_wrk_prealloc_sessions);
  return 0;
}

static void
echo_server_ctrl_reply (session_t *s)
{
  echo_server_main_t *esm = &echo_server_main;
  int rv;

  rv = svm_fifo_enqueue (s->tx_fifo, sizeof (esm->cfg), (u8 *) &esm->cfg);
  ASSERT (rv == sizeof (esm->cfg));
  session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
}

static int
es_test_cmd_sync (echo_server_main_t *esm, session_t *s)
{
  int rv;

  rv = echo_server_setup_test (&esm->cfg);
  if (rv)
    es_err ("setup test error!");

  echo_server_ctrl_reply (s);
  return 0;
}

static int
es_wrk_cleanup_sessions (void *args)
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_disconnect_args_t _a = {}, *a = &_a;
  clib_thread_index_t thread_index = pointer_to_uword (args);
  es_session_t *es;
  es_worker_t *wrk;

  wrk = es_worker_get (thread_index);
  a->app_index = esm->app_index;

  pool_foreach (es, wrk->sessions)
    {
      a->handle = es->vpp_session_handle;
      vnet_disconnect_session (a);
    }
  pool_free (wrk->sessions);

  return 0;
}

static int
echo_server_rx_ctrl_callback (session_t *s)
{
  echo_server_main_t *esm = &echo_server_main;
  int rv;

  rv = svm_fifo_dequeue (s->rx_fifo, sizeof (esm->cfg), (u8 *) &esm->cfg);
  ASSERT (rv == sizeof (esm->cfg));

  es_dbg ("control message received:");
  if (esm->cfg.verbose)
    hs_test_cfg_dump (&esm->cfg, 0);

  switch (esm->cfg.cmd)
    {
    case HS_TEST_CMD_SYNC:
      switch (esm->cfg.test)
	{
	case HS_TEST_TYPE_ECHO:
	case HS_TEST_TYPE_NONE:
	  es_foreach_thread (es_wrk_cleanup_sessions);
	  echo_server_ctrl_reply (s);
	  break;
	case HS_TEST_TYPE_UNI:
	case HS_TEST_TYPE_BI:
	  return es_test_cmd_sync (esm, s);
	  break;
	default:
	  es_err ("unknown command type! %d", esm->cfg.cmd);
	}
      break;
    case HS_TEST_CMD_START:
    case HS_TEST_CMD_STOP:
      echo_server_ctrl_reply (s);
      break;
    default:
      es_err ("unknown command! %d", esm->cfg.cmd);
      break;
    }
  return 0;
}

/*
 * If no-echo, just drop the data and be done with it.
 */
int
echo_server_builtin_server_rx_callback_no_echo (session_t * s)
{
  echo_server_main_t *esm = &echo_server_main;
  if (PREDICT_FALSE (esm->ctrl_listener_handle == s->listener_handle))
    return echo_server_rx_ctrl_callback (s);

  svm_fifo_t *rx_fifo = s->rx_fifo;
  int rv =
    svm_fifo_dequeue_drop (rx_fifo, svm_fifo_max_dequeue_cons (rx_fifo));
  if (rv > 0 && svm_fifo_needs_deq_ntf (rx_fifo, rv))
    {
      svm_fifo_clear_deq_ntf (rx_fifo);
      session_program_transport_io_evt (s->handle, SESSION_IO_EVT_RX);
    }

  return 0;
}

static void
es_test_bytes (u8 *rx_buf, int actual_transfer, u32 offset)
{
  int i;
  for (i = 0; i < actual_transfer; i++)
    {
      if (rx_buf[i] != ((offset + i) & 0xff))
	{
	  es_err ("at %lld expected %d got %d", offset + i,
		  (offset + i) & 0xff, rx_buf[i]);
	}
    }
}

int
echo_server_rx_callback (session_t * s)
{
  u32 n_written, max_dequeue, max_enqueue, max_transfer;
  int actual_transfer;
  svm_fifo_t *tx_fifo, *rx_fifo;
  echo_server_main_t *esm = &echo_server_main;
  clib_thread_index_t thread_index = s->thread_index;
  es_worker_t *wrk;
  es_session_t *es;

  ASSERT (thread_index == vlib_get_thread_index ());

  /* Closes are treated as half-closes by session layer */
  if (PREDICT_FALSE (s->flags & SESSION_F_APP_CLOSED))
    return 0;

  rx_fifo = s->rx_fifo;
  tx_fifo = s->tx_fifo;

  ASSERT (rx_fifo->master_thread_index == thread_index);
  ASSERT (tx_fifo->master_thread_index == thread_index);

  if (PREDICT_FALSE (esm->ctrl_listener_handle == s->listener_handle))
    return echo_server_rx_ctrl_callback (s);

  wrk = es_worker_get (thread_index);
  max_enqueue = svm_fifo_max_enqueue_prod (tx_fifo);
  es = es_session_get (wrk, s->opaque);

  if (es->is_dgram)
    {
      session_dgram_pre_hdr_t ph;
      svm_fifo_peek (rx_fifo, 0, sizeof (ph), (u8 *) & ph);
      max_dequeue = ph.data_length - ph.data_offset;
      ASSERT (wrk->vpp_event_queue);
      max_enqueue -= sizeof (session_dgram_hdr_t);
    }
  else
    {
      max_dequeue = svm_fifo_max_dequeue_cons (rx_fifo);
    }

  if (PREDICT_FALSE (max_dequeue == 0))
    return 0;

  /* Number of bytes we're going to copy */
  max_transfer = clib_min (max_dequeue, max_enqueue);

  /* No space in tx fifo */
  if (PREDICT_FALSE (max_transfer == 0))
    {
      /* XXX timeout for session that are stuck */

    rx_event:
      /* Program self-tap to retry */
      if (svm_fifo_set_event (rx_fifo))
	{
	  /* TODO should be session_enqueue_notify(s) but quic tests seem
	   * to fail if that's the case */
	  if (session_program_transport_io_evt (s->handle,
						SESSION_IO_EVT_BUILTIN_RX))
	    es_err ("failed to enqueue self-tap");

	  if (es->rx_retries == 500000)
	    {
	      es_err ("session stuck: %U", format_session, s, 2);
	    }
	  if (es->rx_retries < 500001)
	    es->rx_retries++;
	}

      return 0;
    }

  vec_validate (wrk->rx_buf, max_transfer);
  actual_transfer = app_recv ((app_session_t *) es, wrk->rx_buf, max_transfer);
  if (!actual_transfer)
    return 0;
  ASSERT (actual_transfer == max_transfer);

  if (esm->cfg.test_bytes)
    {
      if (esm->transport_proto == TRANSPORT_PROTO_TCP)
	{
	  es_test_bytes (wrk->rx_buf, actual_transfer, es->byte_index);
	  es->byte_index += actual_transfer;
	}
      else
	{
	  /* Sanity check, in case of a broken dgram */
	  if (actual_transfer < sizeof (u32) + 1)
	    return 0;
	  es_test_bytes ((wrk->rx_buf + sizeof (u32)),
			 actual_transfer - sizeof (u32), *(u32 *) wrk->rx_buf);
	}
    }

  /*
   * Echo back
   */

  n_written = app_send ((app_session_t *) es, wrk->rx_buf, actual_transfer, 0);

  if (n_written != max_transfer)
    es_err ("short trout! written %u read %u", n_written, max_transfer);

  if (PREDICT_FALSE (svm_fifo_max_dequeue_cons (rx_fifo)))
    goto rx_event;

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

static void
es_set_echo_rx_callbacks (u8 no_echo)
{
  echo_server_main_t *esm = &echo_server_main;
  if (no_echo)
    esm->rx_callback = echo_server_builtin_server_rx_callback_no_echo;
  else
    esm->rx_callback = echo_server_rx_callback;
}

static int
echo_server_attach (u8 * appns_id, u64 appns_flags, u64 appns_secret)
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  echo_server_main_t *esm = &echo_server_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  esm->rx_callback = echo_server_rx_callback;

  if (esm->transport_proto == TRANSPORT_PROTO_QUIC)
    echo_server_session_cb_vft.session_accept_callback =
      quic_echo_server_session_accept_callback;

  a->api_client_index = ~0;
  a->name = format (0, "echo_server");
  a->session_cb_vft = &echo_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = esm->private_segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = esm->private_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = esm->fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = esm->fifo_size;
  a->options[APP_OPTIONS_TLS_ENGINE] = esm->tls_engine;
  a->options[APP_OPTIONS_PCT_FIRST_ALLOC] = 100;
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
  esm->ckpair_index = ck_pair->index;

  return 0;
}

static int
echo_server_detach (void)
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_app_detach_args_t _da, *da = &_da;
  int rv;

  da->app_index = esm->app_index;
  da->api_client_index = ~0;
  rv = vnet_application_detach (da);
  esm->app_index = ~0;
  vnet_app_del_cert_key_pair (esm->ckpair_index);
  return rv;
}

static int
echo_client_transport_needs_crypto (transport_proto_t proto)
{
  return proto == TRANSPORT_PROTO_TLS || proto == TRANSPORT_PROTO_DTLS ||
	 proto == TRANSPORT_PROTO_QUIC;
}

static int
echo_server_listen_ctrl ()
{
  echo_server_main_t *esm = &echo_server_main;
  vnet_listen_args_t _args = {}, *args = &_args;
  session_error_t rv;

  if ((rv = parse_uri (esm->server_uri, &args->sep_ext)))
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
  int needs_crypto;

  if ((rv = parse_uri (esm->server_uri, &args->sep_ext)))
    {
      return -1;
    }
  args->app_index = esm->app_index;
  args->sep_ext.port = hs_make_data_port (args->sep_ext.port);
  needs_crypto =
    echo_client_transport_needs_crypto (args->sep_ext.transport_proto);
  if (needs_crypto)
    {
      transport_endpt_ext_cfg_t *ext_cfg = session_endpoint_add_ext_cfg (
	&args->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
	sizeof (transport_endpt_crypto_cfg_t));
      ext_cfg->crypto.ckpair_index = esm->ckpair_index;
    }

  if (args->sep_ext.transport_proto == TRANSPORT_PROTO_UDP)
    {
      args->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
    }

  rv = vnet_listen (args);
  esm->listener_handle = args->handle;
  if (needs_crypto)
    session_endpoint_free_ext_cfgs (&args->sep_ext);
  return rv;
}

static int
echo_server_create (vlib_main_t * vm, u8 * appns_id, u64 appns_flags,
		    u64 appns_secret)
{
  echo_server_main_t *esm = &echo_server_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  es_worker_t *wrk;

  esm->rcv_buffer_size = clib_max (esm->rcv_buffer_size, esm->fifo_size);
  vec_validate (esm->wrk, vtm->n_threads);

  vec_foreach (wrk, esm->wrk)
    {
      wrk->thread_index = wrk - esm->wrk;
      vec_validate (wrk->rx_buf, esm->rcv_buffer_size);
      wrk->vpp_event_queue =
	session_main_get_vpp_event_queue (wrk->thread_index);
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

static clib_error_t *
echo_server_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  echo_server_main_t *esm = &echo_server_main;
  u8 server_uri_set = 0, *appns_id = 0;
  u64 appns_flags = 0, appns_secret = 0;
  char *default_uri = "tcp://0.0.0.0/1234";
  int rv, is_stop = 0;
  clib_error_t *error = 0;

  esm->fifo_size = 64 << 10;
  esm->rcv_buffer_size = 128 << 10;
  esm->prealloc_fifos = 0;
  esm->private_segment_count = 0;
  esm->private_segment_size = 512 << 20;
  esm->tls_engine = CRYPTO_ENGINE_OPENSSL;
  vec_free (esm->server_uri);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "uri %s", &esm->server_uri))
	server_uri_set = 1;
      else if (unformat (input, "fifo-size %U", unformat_memory_size,
			 &esm->fifo_size))
	;
      else if (unformat (input, "rcv-buf-size %d", &esm->rcv_buffer_size))
	;
      else if (unformat (input, "prealloc-fifos %d", &esm->prealloc_fifos))
	;
      else if (unformat (input, "private-segment-count %d",
			 &esm->private_segment_count))
	;
      else if (unformat (input, "private-segment-size %U",
			 unformat_memory_size, &esm->private_segment_size))
	;
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
      else if (unformat (input, "tls-engine %d", &esm->tls_engine))
	;
      else
	{
	  error = clib_error_return (0, "failed: unknown input `%U'",
				     format_unformat_error, input);
	  goto cleanup;
	}
    }

  if (is_stop)
    {
      if (esm->app_index == (u32) ~ 0)
	{
	  es_cli ("server not running");
	  error = clib_error_return (0, "failed: server not running");
	  goto cleanup;
	}
      rv = echo_server_detach ();
      if (rv)
	{
	  es_cli ("failed: detach");
	  error = clib_error_return (0, "failed: server detach %d", rv);
	  goto cleanup;
	}
      goto cleanup;
    }

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vnet_session_enable_disable (vm, &args);

  if (!server_uri_set)
    {
      es_cli ("No uri provided! Using default: %s", default_uri);
      esm->server_uri = (char *) format (0, "%s%c", default_uri, 0);
    }

  if ((rv = parse_uri ((char *) esm->server_uri, &sep)))
    {
      error = clib_error_return (0, "Uri parse error: %d", rv);
      goto cleanup;
    }
  esm->transport_proto = sep.transport_proto;

  rv = echo_server_create (vm, appns_id, appns_flags, appns_secret);
  if (rv)
    {
      vec_free (esm->server_uri);
      error = clib_error_return (0, "failed: server_create returned %d", rv);
      goto cleanup;
    }

cleanup:
  vec_free (appns_id);

  return error;
}

VLIB_CLI_COMMAND (echo_server_create_command, static) = {
  .path = "test echo server",
  .short_help =
    "test echo server proto <proto> [fifo-size <mbytes>]"
    "[rcv-buf-size <bytes>][prealloc-fifos <count>]"
    "[private-segment-count <count>][private-segment-size <bytes[m|g]>]"
    "[uri <tcp://ip/port>]",
  .function = echo_server_create_command_fn,
};

clib_error_t *
echo_server_main_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (echo_server_main_init);
