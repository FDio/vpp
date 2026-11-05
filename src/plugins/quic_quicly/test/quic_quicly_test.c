/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <quic_quicly/quic_quicly.h>
#include <vnet/session/application.h>
#include <vpp/app/version.h>

#define QUICLY_TEST(cond, text)                                                                    \
  do                                                                                               \
    {                                                                                              \
      int test_ok = !!(cond);                                                                      \
      vlib_cli_output (vm, "%s:%d: %s", test_ok ? "PASS" : "FAIL", __LINE__, text);                \
      if (!test_ok)                                                                                \
	{                                                                                          \
	  res = 1;                                                                                 \
	  goto done;                                                                               \
	}                                                                                          \
    }                                                                                              \
  while (0)

static int
quicly_test_stream_close (vlib_main_t *vm, quic_quicly_main_t *qqm,
			  const quicly_stream_callbacks_t *callbacks,
			  const quic_engine_vft_t *engine, u32 thread_index, u64 stream_id,
			  u32 order)
{
  quic_main_t *qm = qqm->qm;
  quic_worker_ctx_t *worker = &qm->wrk_ctx[thread_index];
  struct _st_quicly_conn_public_t conn = {};
  svm_fifo_shared_t shared = { .size = 4096 };
  svm_fifo_t fifo = { .shr = &shared };
  quicly_stream_t stream = { .conn = (quicly_conn_t *) &conn, .stream_id = stream_id };
  session_t *session = session_alloc (thread_index);
  quic_stream_data_t *data;
  quic_ctx_t *ctx;
  u32 ctx_index;
  int res = 0;

  ctx_index = quic_ctx_alloc (qm, thread_index);
  ctx = pool_elt_at_index (worker->ctx_pool, ctx_index);
  ctx->c_c_index = ctx_index;
  ctx->c_s_index = session->session_index;
  ctx->c_proto = TRANSPORT_PROTO_QUIC;
  ctx->flags = QUIC_F_IS_STREAM;
  ctx->stream = &stream;
  ctx->udp_session_handle = 42;
  session->connection_index = ctx_index;
  session->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, 1);
  session->tx_fifo = &fifo;
  session->app_wrk_index = APP_INVALID_INDEX;
  /* Suppress application notifications already delivered in these fixtures.
   * The engine-first case starts before accept acknowledgment instead. */
  session->session_state = order == 1 ? SESSION_STATE_ACCEPTING : SESSION_STATE_TRANSPORT_DELETED;
  data = clib_mem_alloc (sizeof (*data));
  clib_memset (data, 0, sizeof (*data));
  data->ctx_id = ctx_index;
  data->thread_index = thread_index;
  stream.data = data;
  qqm->worker_stats[thread_index].n_streams = 1;

  vlib_cli_output (vm, "thread %u stream-id %lu close order %u", thread_index, stream_id, order);
  if (order == 0)
    {
      /* The synthetic send state is already shut down. App close records its
       * acknowledgment without calling quicly's packet scheduler. */
      engine->proto_on_close (ctx_index, thread_index);
      QUICLY_TEST (ctx->flags & QUIC_F_APP_CLOSED, "application close is recorded");
      QUICLY_TEST (pool_elts (worker->ctx_pool) == 1, "context survives until engine destruction");
    }
  else if (order == 2)
    shared.tail = 1; /* STOP_SENDING can destroy a stream with pending TX data. */

  callbacks->on_destroy (&stream, 0);
  stream.data = 0;
  QUICLY_TEST (qqm->worker_stats[thread_index].n_streams == 0,
	       "engine stream is counted closed once");
  if (order == 1)
    {
      QUICLY_TEST (pool_elts (worker->ctx_pool) == 1,
		   "engine destruction waits for application close");
      ctx = pool_elt_at_index (worker->ctx_pool, ctx_index);
      QUICLY_TEST (ctx->stream == 0, "destroyed engine stream is detached");
      QUICLY_TEST (ctx->udp_session_handle == SESSION_INVALID_HANDLE, "UDP handle is detached");
      QUICLY_TEST (ctx->flags & QUIC_F_STREAM_TX_CLOSED, "stream TX is marked closed");
      QUICLY_TEST (session->session_state == SESSION_STATE_TRANSPORT_CLOSING,
		   "session waits for application acknowledgment");
      /* Session-layer notification ordering is covered by HST. Mark its
       * acknowledgment delivered before exercising transport ownership. */
      session->session_state = SESSION_STATE_TRANSPORT_DELETED;
      engine->proto_on_close (ctx_index, thread_index);
    }
  QUICLY_TEST (pool_elts (worker->ctx_pool) == 0, "stream context is released");
  engine->proto_on_close (ctx_index, thread_index);
  QUICLY_TEST (pool_elts (worker->ctx_pool) == 0, "late close acknowledgment is harmless");
  QUICLY_TEST (qqm->worker_stats[thread_index].n_streams == 0,
	       "late close does not decrement engine count");

done:
  if (stream.data)
    clib_mem_free (stream.data);
  session_free (session);
  return res;
}

typedef struct
{
  quicly_update_open_count_t super;
  i64 count;
} quicly_test_conn_count_t;

static void
quicly_test_conn_count (quicly_update_open_count_t *self, ssize_t delta)
{
  ((quicly_test_conn_count_t *) self)->count += delta;
}

static int
quicly_test_retired_rx (vlib_main_t *vm, quic_quicly_main_t *qqm, const quic_engine_vft_t *engine)
{
  fifo_segment_main_t fsm = {};
  fifo_segment_create_args_t args = { .segment_type = SSVM_SEGMENT_PRIVATE,
				      .segment_size = 1 << 20,
				      .segment_name = "quicly-retired-rx" };
  fifo_segment_t *fs = NULL;
  svm_fifo_t *fifo = NULL;
  quicly_context_t *spec, quicly_ctx;
  ptls_context_t tls = {};
  ptls_get_time_t **get_time;
  typeof (quicly_connect) *connect;
  typeof (quicly_amend_ptls_context) *amend;
  typeof (quicly_decode_packet) *decode;
  quicly_test_conn_count_t count = { .super = { quicly_test_conn_count } };
  quicly_cid_plaintext_t cid = {};
  struct sockaddr_in peer = { .sin_family = AF_INET,
			      .sin_port = 1234,
			      .sin_addr.s_addr = clib_host_to_net_u32 (0x7f000001) };
  session_t *us = NULL;
  session_dgram_hdr_t hdr = { .data_length = 1200 };
  u8 initial[1200] = { 0xc0, 0, 0, 0, 1, 8, [16] = 0x44, [17] = 0x9e };
  quicly_decoded_packet_t packet;
  size_t offset = 0;
  quic_ctx_t *ctx;
  quicly_conn_t *conn = NULL;
  u32 ctx_index = ~0, thread_index = vlib_get_thread_index ();
  quic_worker_ctx_t *wc = &qqm->qm->wrk_ctx[thread_index];
  int res = 0;

#define RX_SYMBOL(symbol) vlib_get_plugin_symbol ("quic_quicly_plugin.so", #symbol)
  spec = RX_SYMBOL (quicly_spec_context);
  connect = RX_SYMBOL (quicly_connect);
  amend = RX_SYMBOL (quicly_amend_ptls_context);
  decode = RX_SYMBOL (quicly_decode_packet);
  tls.random_bytes = RX_SYMBOL (ptls_openssl_random_bytes);
  tls.key_exchanges = RX_SYMBOL (ptls_openssl_key_exchanges);
  tls.cipher_suites = RX_SYMBOL (ptls_openssl_cipher_suites);
  get_time = RX_SYMBOL (ptls_get_time);
#undef RX_SYMBOL
  QUICLY_TEST (spec && connect && amend && decode && tls.random_bytes && tls.key_exchanges &&
		 tls.cipher_suites && get_time,
	       "real engine fixture symbols loaded");
  tls.get_time = *get_time;
  amend (&tls);
  quicly_ctx = *spec;
  quicly_ctx.tls = &tls;
  quicly_ctx.update_open_count = &count.super;
  QUICLY_TEST (decode (&quicly_ctx, &packet, initial, sizeof (initial), &offset) != SIZE_MAX &&
		 offset == sizeof (initial) && packet.cid.dest.might_be_client_generated,
	       "late Initial passes packet decoding and pre-accept CID checks");
  QUICLY_TEST (fifo_segment_create (&fsm, &args) == 0, "late packet FIFO segment created");
  fs = fifo_segment_get_segment (&fsm, args.new_segment_indices[0]);
  fifo = fifo_segment_alloc_fifo_w_slice (fs, 0, 4096, FIFO_SEGMENT_RX_FIFO);
  QUICLY_TEST (fifo != NULL, "late packet FIFO allocated");
  us = session_alloc (thread_index);
  us->rx_fifo = fifo;
  us->app_wrk_index =
    application_get_default_worker (application_get (qqm->qm->app_index))->wrk_index;
  /* The UDP close has already been acknowledged. Suppress asynchronous close
   * events into the real session worker while these private pools are in use. */
  us->flags = SESSION_F_APP_CLOSED;
  ctx_index = quic_ctx_alloc (qqm->qm, thread_index);
  us->opaque = ctx_index;
  for (u32 state = QUIC_QUICLY_RX_STATE_ACCEPT; state < QUIC_QUICLY_RX_STATE_CLOSED; state++)
    {
      ctx = pool_elt_at_index (wc->ctx_pool, ctx_index);
      ctx->c_c_index = ctx_index;
      ctx->c_s_index = QUIC_SESSION_INVALID;
      ctx->flags = QUIC_F_NO_APP_SESSION;
      ctx->crypto_context_index = ~0; /* Retired RX must not look up crypto. */
      ctx->udp_session_handle = session_handle (us);
      ctx->opaque = state;
      if (state == QUIC_QUICLY_RX_STATE_ACCEPT)
	{
	  /* State left by quic_accept_timer_expired before UDP cleanup. */
	  ctx->conn_state = QUIC_CONN_STATE_CLOSED;
	}
      else
	{
	  QUICLY_TEST (connect (&conn, &quicly_ctx, "localhost", (void *) &peer, NULL, &cid,
				ptls_iovec_init (NULL, 0), NULL, NULL, NULL) == 0,
		       "real engine connection created");
	  ctx->conn = conn;
	  conn = NULL;
	  QUICLY_TEST (count.count == 1, "engine owns one connection before deletion");
	  ctx->conn_state = QUIC_CONN_STATE_TRANSPORT_CLOSED;
	  engine->transport_closed (ctx);
	  ctx = pool_elt_at_index (wc->ctx_pool, ctx_index);
	  QUICLY_TEST (!ctx->conn && ctx->opaque == QUIC_QUICLY_RX_STATE_CLOSED,
		       "deletion retires RX before UDP context cleanup");
	  QUICLY_TEST (count.count == 0, "deletion releases the real engine connection");
	  engine->transport_closed (ctx);
	  QUICLY_TEST (count.count == 0,
		       "duplicate transport close does not delete the engine twice");
	}

      /* A UDP dequeue event can still dispatch TX before UDP cleanup. */
      engine->send_packets (ctx);
      QUICLY_TEST (!ctx->conn && count.count == 0 &&
		     ctx->timers[QUIC_TIMER_TX] == QUIC_TIMER_HANDLE_INVALID,
		   "late TX without an engine connection does not send or reschedule");

      for (u32 i = 0; i < 2; i++)
	{
	  QUICLY_TEST (svm_fifo_enqueue (fifo, sizeof (hdr), (void *) &hdr) == sizeof (hdr),
		       "late datagram header queued");
	  QUICLY_TEST (svm_fifo_enqueue (fifo, sizeof (initial), initial) == sizeof (initial),
		       "late long-header datagram queued");
	}
      /* Match session-node builtin RX event consumption before the callback. */
      svm_fifo_set_event (fifo);
      svm_fifo_unset_event (fifo);
      QUICLY_TEST (engine->udp_session_rx_packets (us) == -1, "retired RX is rejected");
      QUICLY_TEST (svm_fifo_max_dequeue (fifo) == 0 && !svm_fifo_has_event (fifo),
		   "all queued datagrams are consumed without a busy RX event");
      QUICLY_TEST (engine->udp_session_rx_packets (us) == -1, "duplicate RX event is harmless");
      QUICLY_TEST (count.count == 0 && pool_elts (wc->ctx_pool) == 1,
		   "late RX creates no engine object and leaves context owned by UDP");
      if (state == QUIC_QUICLY_RX_STATE_ACCEPT)
	QUICLY_TEST (ctx->opaque == QUIC_QUICLY_RX_STATE_ACCEPT && !ctx->conn &&
		       ctx->conn_state == QUIC_CONN_STATE_CLOSED,
		     "late RX does not accept a connection after timeout");
    }

done:
  if (conn)
    {
      typeof (quicly_free) *free_conn =
	vlib_get_plugin_symbol ("quic_quicly_plugin.so", "quicly_free");
      free_conn (conn);
    }
  if (ctx_index != ~0)
    {
      ctx = pool_elt_at_index (wc->ctx_pool, ctx_index);
      if (ctx->conn)
	{
	  ctx->conn_state = QUIC_CONN_STATE_TRANSPORT_CLOSED;
	  engine->transport_closed (ctx);
	  ctx = pool_elt_at_index (wc->ctx_pool, ctx_index);
	}
      quic_ctx_free (qqm->qm, ctx);
    }
  if (us)
    session_free (us);
  if (fifo)
    fifo_segment_free_fifo (fs, fifo);
  if (fs)
    fifo_segment_delete (&fsm, fs);
  pool_free (fsm.segments);
  vec_free (args.new_segment_indices);
  return res;
}

static clib_error_t *
quicly_test_cancel_rx_complete (vlib_main_t *vm, quic_quicly_main_t *qqm,
				const quicly_stream_callbacks_t *callbacks,
				const quic_engine_vft_t *engine, u32 thread_index)
{
  quic_main_t *qm = qqm->qm;
  session_worker_t *sw = &session_main.wrk[thread_index];
  session_event_t rx_evt, close_evt;
  session_evt_elt_t *head, *elt;
  struct _st_quicly_conn_public_t conn = {};
  quicly_stream_t stream = { .conn = (quicly_conn_t *) &conn };
  quic_stream_data_t data = { .thread_index = thread_index };
  transport_endpt_attr_t attr = { .type = TRANSPORT_ENDPT_ATTR_APP_PROTO_ERR_CODE_RX,
				  .app_proto_err_code_rx = 0x100 };
  session_t *session = session_alloc (thread_index);
  u32 ctx_index = quic_ctx_alloc (qm, thread_index);
  quic_ctx_t *ctx = pool_elt_at_index (qm->wrk_ctx[thread_index].ctx_pool, ctx_index);
  int res = 0;

  ctx->c_c_index = ctx_index;
  ctx->c_s_index = session->session_index;
  ctx->c_proto = TRANSPORT_PROTO_QUIC;
  ctx->flags = QUIC_F_IS_STREAM;
  ctx->stream = &stream;
  ctx->app_err_code = 0x999;
  session->connection_index = ctx_index;
  session->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, 1);
  session->session_state = SESSION_STATE_READY;
  session->flags |= SESSION_F_RX_READY;
  data.ctx_id = ctx_index;
  stream.data = &data;
  stream.sendstate.final_size = UINT64_MAX;
  QUICLY_TEST (!session_transport_attribute (session, 0, &attr) && ctx->app_err_code_rx == 0x100,
	       "RX error code can be configured");
  QUICLY_TEST (ctx->flags == QUIC_F_IS_STREAM && ctx->app_err_code == 0x999,
	       "setting RX error code does not close RX or change the other error code");
  attr.app_proto_err_code_rx = 1ULL << 62;
  QUICLY_TEST (session_transport_attribute (session, 0, &attr) < 0 && ctx->app_err_code_rx == 0x100,
	       "invalid RX error code leaves the configured value intact");
  session_half_close (session, 1 /* is_rx */);
  QUICLY_TEST ((session->flags & (SESSION_F_RX_READY | SESSION_F_TX_READY)) == SESSION_F_TX_READY,
	       "RX half-close disables RX notifications and preserves TX readiness");
  session_half_close (session, 1 /* is_rx */);
  head = clib_llist_elt (sw->event_elts, sw->ctrl_head);
  elt = clib_llist_next (sw->event_elts, evt_list, head);
  rx_evt = elt->evt;
  clib_llist_remove (sw->event_elts, evt_list, elt);
  clib_llist_put (sw->event_elts, elt);
  QUICLY_TEST (rx_evt.event_type == SESSION_CTRL_EVT_HALF_CLOSE &&
		 rx_evt.session_handle == session_handle (session) &&
		 clib_llist_next (sw->event_elts, evt_list, head) == head,
	       "RX half-close queues one event and repeated RX close queues none");
  session_close (session);
  elt = clib_llist_next (sw->event_elts, evt_list, head);
  close_evt = elt->evt;
  clib_llist_remove (sw->event_elts, evt_list, elt);
  clib_llist_put (sw->event_elts, elt);
  QUICLY_TEST (close_evt.event_type == SESSION_CTRL_EVT_CLOSE &&
		 close_evt.session_handle == session_handle (session),
	       "full close remains available after RX half-close");
  QUICLY_TEST (ctx->flags == QUIC_F_IS_STREAM, "queuing half-close defers the transport operation");
  attr.type = TRANSPORT_ENDPT_ATTR_APP_PROTO_ERR_CODE;
  attr.app_proto_err_code = 0x777;
  QUICLY_TEST (!session_transport_attribute (session, 0, &attr) && ctx->app_err_code_rx == 0x100,
	       "a later reset error code does not overwrite the pending RX error code");
  /* No receive ranges and eos == 0 model a request already received through FIN. */
  engine->proto_on_half_close (ctx_index, thread_index, !!(session->flags & SESSION_F_TX_READY));
  tp_vfts[TRANSPORT_PROTO_QUIC].half_close (ctx_index, thread_index, 1 /* is_rx */);
  QUICLY_TEST (ctx->flags == (QUIC_F_IS_STREAM | QUIC_F_APP_CLOSED_RX),
	       "receive cancellation preserves TX and session ownership");
  QUICLY_TEST (!quicly_stop_requested (&stream),
	       "completed receive side does not need STOP_SENDING");
  session->session_state = SESSION_STATE_ACCEPTING;
  callbacks->on_receive (&stream, 0, 0, 0);
  callbacks->on_receive_reset (&stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE (0x100));
  QUICLY_TEST (session->session_state == SESSION_STATE_ACCEPTING,
	       "late FIN/reset after cancellation does not notify the application");
  QUICLY_TEST (ctx->app_err_code == 0x777 && stream.sendstate.final_size == UINT64_MAX,
	       "receive cancellation leaves the send state and error code intact");

done:
  quic_ctx_free (qm, ctx);
  session_free (session);
  return res ? clib_error_return (0, "receive cancellation test failed") : 0;
}

static clib_error_t *
quicly_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  quic_main_t *qm, *saved_qm;
  quic_quicly_main_t *qqm;
  quic_engine_vft_t **engines;
  const quicly_stream_callbacks_t *callbacks;
  quic_worker_ctx_t *workers = 0, *saved_workers;
  session_worker_t *sessions = 0, *saved_sessions;
  quic_quicly_worker_stats_t *stats = 0, *saved_stats;
  vlib_node_registration_t node = {}, *saved_node;
  vlib_node_t *quic_node;
  u32 counter_index;
  u64 saved_counter;
  u64 saved_closed_connections;
  clib_error_t *cancel_error = 0;
  const u64 stream_ids[] = { 0, 2, 3 }; /* bidi, sending uni, receiving uni */
  int res = 0;
  enum
  {
    TEST_NONE,
    TEST_STREAM_CLOSE,
    TEST_RX,
    TEST_CANCEL_RX,
    TEST_ALL,
  } test = TEST_NONE;

  if (unformat (input, "stream-close"))
    test = TEST_STREAM_CLOSE;
  else if (unformat (input, "rx"))
    test = TEST_RX;
  else if (unformat (input, "cancel-rx"))
    test = TEST_CANCEL_RX;
  else if (unformat (input, "all"))
    test = TEST_ALL;
  if (test == TEST_NONE || unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected exactly one of stream-close, rx, cancel-rx or all");
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_plugin.so", quic_main, qm);
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_plugin.so", quic_engine_vfts, engines);
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_quicly_plugin.so", quic_quicly_main, qqm);
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_quicly_plugin.so", quic_quicly_stream_callbacks,
				   callbacks);
  if ((test == TEST_RX || test == TEST_ALL) &&
      (qm->app_index == APP_INVALID_INDEX || !qm->engine_is_initialized[QUIC_ENGINE_QUICLY]))
    return clib_error_return (0, "QUIC RX tests require an enabled quicly engine (session enable)");
  quic_node = vlib_get_node_by_name (vm, (u8 *) "quic-input");
  if (!quic_node || vec_len (*engines) <= QUIC_ENGINE_QUICLY)
    return clib_error_return (0, "QUIC engine is not registered");
  node.index = quic_node->index;
  counter_index = quic_node->error_heap_index + QUIC_ERROR_CLOSED_STREAM;
  saved_counter = vm->error_main.counters[counter_index];
  saved_closed_connections =
    vm->error_main.counters[quic_node->error_heap_index + QUIC_ERROR_CLOSED_CONNECTION];
  saved_node = qm->quic_input_node;
  saved_workers = qm->wrk_ctx;
  saved_sessions = session_main.wrk;
  saved_qm = qqm->qm;
  saved_stats = qqm->worker_stats;
  vec_validate_aligned (workers, 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (sessions, 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (stats, 1, CLIB_CACHE_LINE_BYTES);
  for (u32 i = 0; i < 2; i++)
    {
      pool_alloc_aligned (workers[i].ctx_pool, 2 * POOL_REALLOC_SAFE_ELT_THRESH,
			  CLIB_CACHE_LINE_BYTES);
      pool_alloc_aligned (sessions[i].sessions, 2 * POOL_REALLOC_SAFE_ELT_THRESH,
			  CLIB_CACHE_LINE_BYTES);
      sessions[i].ctrl_head = clib_llist_make_head (sessions[i].event_elts, evt_list);
    }
  /* CLI worker barrier protects the temporary session/context pools. */
  qm->wrk_ctx = workers;
  qm->quic_input_node = &node;
  session_main.wrk = sessions;
  qqm->qm = qm;
  qqm->worker_stats = stats;
  if (test == TEST_STREAM_CLOSE || test == TEST_ALL)
    for (u32 thread_index = 0; thread_index < 2 && !res; thread_index++)
      for (u32 i = 0; i < ARRAY_LEN (stream_ids) && !res; i++)
	for (u32 order = 0; order < 3 && !res; order++)
	  res = quicly_test_stream_close (vm, qqm, callbacks, &(*engines)[QUIC_ENGINE_QUICLY],
					  thread_index, stream_ids[i], order);
  if (!res && (test == TEST_RX || test == TEST_ALL))
    res = quicly_test_retired_rx (vm, qqm, &(*engines)[QUIC_ENGINE_QUICLY]);
  if (test == TEST_CANCEL_RX || test == TEST_ALL)
    for (u32 thread_index = 0; thread_index < 2 && !res; thread_index++)
      {
	cancel_error = quicly_test_cancel_rx_complete (
	  vm, qqm, callbacks, &(*engines)[QUIC_ENGINE_QUICLY], thread_index);
	res = cancel_error != 0;
      }
  qm->wrk_ctx = saved_workers;
  qm->quic_input_node = saved_node;
  session_main.wrk = saved_sessions;
  qqm->qm = saved_qm;
  qqm->worker_stats = saved_stats;
  vm->error_main.counters[counter_index] = saved_counter;
  vm->error_main.counters[quic_node->error_heap_index + QUIC_ERROR_CLOSED_CONNECTION] =
    saved_closed_connections;
  for (u32 i = 0; i < 2; i++)
    {
      pool_free (workers[i].ctx_pool);
      pool_free (sessions[i].sessions);
      clib_llist_free (sessions[i].event_elts);
    }
  vec_free (workers);
  vec_free (sessions);
  vec_free (stats);
  if (cancel_error)
    return cancel_error;
  if (res)
    return clib_error_return (0, "quicly unit test failed");
  vlib_cli_output (vm, "SUCCESS");
  return 0;
}

VLIB_CLI_COMMAND (quicly_test_command, static) = {
  .path = "test quicly",
  .short_help = "test quicly [stream-close|rx|cancel-rx|all]",
  .function = quicly_test,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Quicly - Unit Test",
  .load_after = "quic_quicly_plugin.so",
  .default_disabled = 1,
};
