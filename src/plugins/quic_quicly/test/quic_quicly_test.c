/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <quic_quicly/quic_quicly.h>
#include <quic/quic_timer.h>
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

typedef struct
{
  quicly_stream_open_t super;
  quic_stream_data_t data;
} quicly_test_credit_stream_t;

static void
quicly_test_credit_destroy (quicly_stream_t *stream, quicly_error_t error)
{
}

static quicly_error_t
quicly_test_credit_open (quicly_stream_open_t *self, quicly_stream_t *stream)
{
  static const quicly_stream_callbacks_t callbacks = { .on_destroy = quicly_test_credit_destroy };
  stream->data = &((quicly_test_credit_stream_t *) self)->data;
  stream->callbacks = &callbacks;
  return 0;
}

static void
quicly_test_conn_count (quicly_update_open_count_t *self, ssize_t delta)
{
  ((quicly_test_conn_count_t *) self)->count += delta;
}

static int
quicly_test_rx_credit (vlib_main_t *vm, quic_quicly_main_t *qqm,
		       const quicly_stream_callbacks_t *callbacks, const quic_engine_vft_t *engine)
{
  fifo_segment_main_t fsm = {};
  fifo_segment_create_args_t args = { .segment_type = SSVM_SEGMENT_PRIVATE,
				      .segment_size = 1 << 20,
				      .segment_name = "quicly-rx-credit" };
  fifo_segment_t *fs = NULL;
  svm_fifo_t *txf = NULL;
  quicly_context_t *spec, context;
  ptls_context_t tls = {};
  ptls_get_time_t *get_time;
  typeof (quicly_connect) *connect;
  typeof (quicly_open_stream) *open_stream;
  typeof (quicly_recvstate_update) *receive;
  typeof (quicly_free) *free_conn;
  typeof (quicly_amend_ptls_context) *amend;
  typeof (tw_timer_wheel_init_quic_twslov) *wheel_init;
  typeof (tw_timer_wheel_free_quic_twslov) *wheel_free;
  typeof (quic_conn_tx_timer_stop) *stop_timer;
  quicly_test_credit_stream_t opened = { .super = { quicly_test_credit_open } };
  quicly_cid_plaintext_t cid = {};
  struct sockaddr_in peer = { .sin_family = AF_INET,
			      .sin_port = 1234,
			      .sin_addr.s_addr = clib_host_to_net_u32 (0x7f000001) };
  quicly_conn_t *conn = NULL;
  quicly_stream_t *stream;
  session_t *session = NULL;
  svm_fifo_shared_t shared = { .size = 4096 };
  svm_fifo_t fifo = { .shr = &shared };
  u8 emitted[4];
  u32 thread = vlib_get_thread_index (), parent_index = ~0, stream_index = ~0;
  quic_worker_ctx_t *wc = &qqm->qm->wrk_ctx[thread];
  quic_ctx_t *parent, *child;
  u8 wheel_ready = 0;
  int res = 0;

#define CREDIT_SYMBOL(symbol) vlib_get_plugin_symbol ("quic_quicly_plugin.so", #symbol)
  spec = CREDIT_SYMBOL (quicly_spec_context);
  connect = CREDIT_SYMBOL (quicly_connect);
  open_stream = CREDIT_SYMBOL (quicly_open_stream);
  receive = CREDIT_SYMBOL (quicly_recvstate_update);
  free_conn = CREDIT_SYMBOL (quicly_free);
  amend = CREDIT_SYMBOL (quicly_amend_ptls_context);
  tls.random_bytes = CREDIT_SYMBOL (ptls_openssl_random_bytes);
  tls.key_exchanges = CREDIT_SYMBOL (ptls_openssl_key_exchanges);
  tls.cipher_suites = CREDIT_SYMBOL (ptls_openssl_cipher_suites);
  get_time = CREDIT_SYMBOL (ptls_get_time);
#undef CREDIT_SYMBOL
  wheel_init = vlib_get_plugin_symbol ("quic_plugin.so", "tw_timer_wheel_init_quic_twslov");
  wheel_free = vlib_get_plugin_symbol ("quic_plugin.so", "tw_timer_wheel_free_quic_twslov");
  stop_timer = vlib_get_plugin_symbol ("quic_plugin.so", "quic_conn_tx_timer_stop");
  QUICLY_TEST (spec && connect && open_stream && receive && free_conn && amend &&
		 tls.random_bytes && tls.key_exchanges && tls.cipher_suites && get_time &&
		 wheel_init && wheel_free && stop_timer,
	       "RX credit fixture symbols loaded");
  tls.get_time = get_time;
  amend (&tls);
  context = *spec;
  context.tls = &tls;
  context.stream_open = &opened.super;
  context.transport_params.max_stream_data.bidi_local = shared.size;
  QUICLY_TEST (connect (&conn, &context, "localhost", (void *) &peer, NULL, &cid,
			ptls_iovec_init (NULL, 0), NULL, NULL, NULL) == 0,
	       "RX credit engine connection created");
  QUICLY_TEST (open_stream (conn, &stream, 0) == 0, "RX credit stream created");
  fifo_segment_main_init (&fsm, 0, 5);
  QUICLY_TEST (fifo_segment_create (&fsm, &args) == 0, "RX credit FIFO segment created");
  fs = fifo_segment_get_segment (&fsm, args.new_segment_indices[0]);
  txf = fifo_segment_alloc_fifo_w_slice (fs, 0, 4096, FIFO_SEGMENT_TX_FIFO);
  QUICLY_TEST (txf != NULL, "RX credit TX FIFO allocated");
  parent_index = quic_ctx_alloc (qqm->qm, thread);
  stream_index = quic_ctx_alloc (qqm->qm, thread);
  parent = pool_elt_at_index (wc->ctx_pool, parent_index);
  child = pool_elt_at_index (wc->ctx_pool, stream_index);
  parent->conn = conn;
  parent->conn_state = QUIC_CONN_STATE_HANDSHAKE;
  parent->c_s_index = QUIC_SESSION_INVALID;
  child->stream = stream;
  child->quic_connection_ctx_id = parent_index;
  session = session_alloc (thread);
  session->connection_index = stream_index;
  session->rx_fifo = &fifo;
  session->tx_fifo = txf;
  child->c_s_index = session->session_index;
  child->flags = QUIC_F_IS_STREAM | QUIC_F_STREAM_TX_DRAINED;
  opened.data.ctx_id = stream_index;
  opened.data.thread_index = thread;
  wheel_init (&wc->timer_wheel, NULL, QUIC_TIMER_INTERVAL, ~0);
  wheel_ready = 1;
  wc->time_now = tls.get_time->cb (tls.get_time);
  for (u32 i = 0; i < 4; i++)
    {
      size_t length = shared.size;
      if (i == 1)
	{
	  QUICLY_TEST (svm_fifo_enqueue (txf, 4, (u8 *) "data") == 4, "first TX data queued");
	  QUICLY_TEST (engine->stream_tx (child, session) == 1 &&
			 !(child->flags & QUIC_F_STREAM_TX_DRAINED),
		       "first write leaves the drained state");
	  stop_timer (wc, parent);
	}
      else if (i == 2)
	{
	  size_t emitted_len = sizeof (emitted);
	  int wrote_all = 0;
	  callbacks->on_send_emit (stream, 0, emitted, &emitted_len, &wrote_all);
	  QUICLY_TEST (emitted_len == 4 && wrote_all && !memcmp (emitted, "data", 4) &&
			 (child->flags & QUIC_F_STREAM_TX_DRAINED),
		       "emitting all TX data restores the drained state");
	  callbacks->on_send_shift (stream, emitted_len);
	}
      else if (i == 3)
	{
	  engine->proto_on_half_close (stream_index, thread, 0 /* is_rx */);
	  QUICLY_TEST ((child->flags & QUIC_F_APP_CLOSED_TX) &&
			 (child->flags & QUIC_F_STREAM_TX_DRAINED),
		       "TX shutdown preserves the drained state");
	  stop_timer (wc, parent);
	}
      QUICLY_TEST (receive (&stream->recvstate, stream->recvstate.data_off, &length, 0, 32) == 0,
		   "RX credit data received");
      opened.data.app_rx_data_len = length; /* The application drained the FIFO. */
      engine->ack_rx_data (session);
      QUICLY_TEST (stream->recvstate.data_off == (i + 1) * shared.size,
		   "application consumption advances the receive window");
      if (i == 1)
	QUICLY_TEST (parent->timers[QUIC_TIMER_TX] == QUIC_TIMER_HANDLE_INVALID,
		     "active TX avoids an RX credit timer update");
      else
	QUICLY_TEST (parent->timers[QUIC_TIMER_TX] != QUIC_TIMER_HANDLE_INVALID,
		     "idle RX credit rearms TX before first write, after drain and after shutdown");
      stop_timer (wc, parent);
    }
done:
  if (conn)
    free_conn (conn);
  if (wheel_ready)
    {
      wheel_free (&wc->timer_wheel);
      clib_memset (&wc->timer_wheel, 0, sizeof (wc->timer_wheel));
    }
  if (session)
    session_free (session);
  if (stream_index != ~0)
    quic_ctx_free (qqm->qm, pool_elt_at_index (wc->ctx_pool, stream_index));
  if (parent_index != ~0)
    quic_ctx_free (qqm->qm, pool_elt_at_index (wc->ctx_pool, parent_index));
  if (txf)
    fifo_segment_free_fifo (fs, txf);
  if (fs)
    fifo_segment_delete (&fsm, fs);
  vec_free (args.new_segment_indices);
  pool_free (fsm.segments);
  return res;
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
  ptls_get_time_t *get_time;
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
  tls.get_time = get_time;
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
  session_event_t half_close_evts[3], close_evt;
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
  session_half_close (session, 0 /* is_rx */);
  session_half_close (session, 1 /* is_rx */);
  QUICLY_TEST (session->flags == SESSION_F_RX_READY,
	       "queuing half-closes leaves session flags unchanged");
  for (u32 i = 0; i < ARRAY_LEN (half_close_evts); i++)
    {
      head = clib_llist_elt (sw->event_elts, sw->ctrl_head);
      elt = clib_llist_next (sw->event_elts, evt_list, head);
      QUICLY_TEST (elt != head, "half-close event is queued");
      half_close_evts[i] = elt->evt;
      clib_llist_remove (sw->event_elts, evt_list, elt);
      clib_llist_put (sw->event_elts, elt);
      QUICLY_TEST (half_close_evts[i].event_type == SESSION_CTRL_EVT_HALF_CLOSE &&
		     half_close_evts[i].session_handle == session_handle (session) &&
		     half_close_evts[i].as_u64[1] == (i != 1),
		   "queued RX/TX/RX half-closes retain their own direction");
    }
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
  engine->proto_on_half_close (ctx_index, thread_index, half_close_evts[0].as_u64[1]);
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

static int
quicly_test_rx_fin (vlib_main_t *vm, quic_quicly_main_t *qqm,
		    const quicly_stream_callbacks_t *callbacks, const quic_engine_vft_t *engine)
{
  static const struct
  {
    const char *name;
    u32 body_len;
    u8 tx_shutdown;
    u8 pending_tx;
    u8 fin_with_data;
    u8 cancel_rx;
  } tests[] = {
    { "empty FIN with TX open", 0, 0, 0, 0, 0 },
    { "empty FIN after TX shutdown", 0, 1, 0, 0, 0 },
    { "DATA and FIN after TX shutdown", 4, 1, 0, 1, 0 },
    { "FIN with a full RX FIFO", 4096, 1, 0, 0, 0 },
    { "empty FIN with TX awaiting acknowledgment", 0, 1, 1, 0, 0 },
    { "DATA and FIN with TX awaiting acknowledgment", 4, 1, 1, 1, 0 },
    { "FIN after RX cancellation and TX shutdown", 0, 1, 0, 0, 1 },
  };
  fifo_segment_main_t fsm = {};
  fifo_segment_create_args_t args = { .segment_type = SSVM_SEGMENT_PRIVATE,
				      .segment_size = 1 << 20,
				      .segment_name = "quicly-rx-fin" };
  quic_main_t *qm = qqm->qm;
  app_worker_t *app_wrk = application_get_default_worker (application_get (qm->app_index));
  u32 thread_index = vlib_get_thread_index ();
  i64 saved_streams = qqm->worker_stats[thread_index].n_streams;
  session_event_t *saved_events = app_wrk->wrk_evts[thread_index];
  session_event_t event;
  struct _st_quicly_conn_public_t conn = {};
  quicly_stream_t stream = { .conn = (quicly_conn_t *) &conn };
  quic_stream_data_t *data = 0;
  quicly_range_t range = {};
  fifo_segment_t *fs = 0;
  svm_fifo_t *rxf = 0, *txf = 0;
  session_t *session = 0;
  quic_ctx_t *ctx = 0;
  u32 ctx_index, n_events;
  u8 body[4096], received[4096];
  int res = 0;

  /* The CLI barrier protects the real app worker while its event FIFO and the
   * session/context pools are replaced. Inspect notifications without dispatching
   * callbacks into the application's real sessions. */
  app_wrk->wrk_evts[thread_index] = 0;
  session_main.wrk[thread_index].vm = vm;
  fifo_segment_main_init (&fsm, 0, 5);
  QUICLY_TEST (!fifo_segment_create (&fsm, &args), "FIN test FIFO segment created");
  fs = fifo_segment_get_segment (&fsm, args.new_segment_indices[0]);
  rxf = fifo_segment_alloc_fifo_w_slice (fs, 0, 4096, FIFO_SEGMENT_RX_FIFO);
  txf = fifo_segment_alloc_fifo_w_slice (fs, 0, 4096, FIFO_SEGMENT_TX_FIFO);
  QUICLY_TEST (rxf && txf, "FIN test FIFOs allocated");
  session = session_alloc (thread_index);
  session->rx_fifo = rxf;
  session->tx_fifo = txf;
  session->app_wrk_index = app_wrk->wrk_index;
  session->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, 1);
  ctx_index = quic_ctx_alloc (qm, thread_index);
  ctx = pool_elt_at_index (qm->wrk_ctx[thread_index].ctx_pool, ctx_index);
  ctx->c_c_index = ctx_index;
  ctx->c_s_index = session->session_index;
  ctx->c_proto = TRANSPORT_PROTO_QUIC;
  session->connection_index = ctx_index;
  for (u32 i = 0; i < sizeof (body); i++)
    body[i] = (i * 17 + 3) & 0xff;

  for (u32 i = 0; i < ARRAY_LEN (tests); i++)
    {
      vlib_cli_output (vm, "%s", tests[i].name);
      stream = (quicly_stream_t) { .conn = (quicly_conn_t *) &conn };
      data = clib_mem_alloc (sizeof (*data));
      clib_memset (data, 0, sizeof (*data));
      data->ctx_id = ctx_index;
      data->thread_index = thread_index;
      stream.data = data;
      stream._recv_aux.window = 4096;
      stream.recvstate.received.ranges = &range;
      stream.recvstate.received.num_ranges = 1;
      stream.recvstate.eos = UINT64_MAX;
      range = (quicly_range_t) {};
      stream.sendstate.final_size = tests[i].tx_shutdown ? 0 : UINT64_MAX;
      ctx->flags = QUIC_F_IS_STREAM;
      ctx->stream = &stream;
      ctx->bytes_written = 0;
      session->session_state = SESSION_STATE_READY;
      session->flags = SESSION_F_RX_READY;
      qqm->worker_stats[thread_index].n_streams = 1;
      if (tests[i].tx_shutdown)
	ctx->flags |= QUIC_F_APP_CLOSED_TX;
      if (tests[i].pending_tx)
	{
	  QUICLY_TEST (svm_fifo_enqueue (txf, 4, body) == 4, "unacknowledged TX bytes queued");
	  data->app_tx_data_len = 4;
	  stream.sendstate.final_size = UINT64_MAX;
	  ctx->flags &= ~QUIC_F_APP_CLOSED_TX;
	  ctx->flags |= QUIC_F_STREAM_TX_DRAINED;
	  engine->proto_on_half_close (ctx_index, thread_index, 0 /* is_rx */);
	  QUICLY_TEST ((ctx->flags & QUIC_F_APP_CLOSED_TX) &&
			 stream.sendstate.final_size == UINT64_MAX,
		       "TX half-close waits for acknowledgment before sending FIN");
	}
      if (tests[i].cancel_rx)
	ctx->flags |= QUIC_F_APP_CLOSED_RX;

      callbacks->on_receive (&stream, 0, 0, 0);
      QUICLY_TEST (session->session_state == SESSION_STATE_READY &&
		     clib_fifo_elts (app_wrk->wrk_evts[thread_index]) == 0,
		   "no EOF notification before receive transfer completes");
      if (tests[i].body_len && !tests[i].fin_with_data)
	{
	  range.end = tests[i].body_len;
	  callbacks->on_receive (&stream, 0, body, tests[i].body_len);
	  QUICLY_TEST (session->session_state == SESSION_STATE_READY &&
			 svm_fifo_max_enqueue_prod (rxf) == 0,
		       "received body fills RX FIFO without completing the message");
	}
      stream.recvstate.received.num_ranges = 0;
      stream.recvstate.eos = tests[i].body_len;
      callbacks->on_receive (&stream, 0, tests[i].fin_with_data ? body : 0,
			     tests[i].fin_with_data ? tests[i].body_len : 0);
      n_events = tests[i].cancel_rx ? 0 : 1 + !!tests[i].body_len;
      QUICLY_TEST (session->session_state ==
		     (tests[i].cancel_rx ? SESSION_STATE_READY : SESSION_STATE_TRANSPORT_CLOSING),
		   "FIN notifies receive EOF independently of TX shutdown");
      QUICLY_TEST (clib_fifo_elts (app_wrk->wrk_evts[thread_index]) == n_events,
		   "FIN queues exactly one disconnect event unless RX was cancelled");
      if (n_events)
	{
	  if (tests[i].body_len)
	    {
	      clib_fifo_sub1 (app_wrk->wrk_evts[thread_index], event);
	      QUICLY_TEST (event.event_type == SESSION_IO_EVT_RX,
			   "body data event precedes disconnect");
	    }
	  clib_fifo_sub1 (app_wrk->wrk_evts[thread_index], event);
	  QUICLY_TEST (event.event_type == SESSION_CTRL_EVT_DISCONNECTED,
		       "disconnect follows any RX data event");
	}
      QUICLY_TEST (ctx->stream == &stream && !(ctx->flags & QUIC_F_APP_CLOSED) &&
		     svm_fifo_max_dequeue_cons (txf) == (tests[i].pending_tx ? 4 : 0),
		   "receive EOF preserves the engine stream and pending TX bytes");
      callbacks->on_receive (&stream, 0, 0, 0);
      QUICLY_TEST (clib_fifo_elts (app_wrk->wrk_evts[thread_index]) == 0,
		   "repeated FIN does not duplicate disconnect");
      if (!tests[i].pending_tx && !tests[i].cancel_rx)
	{
	  callbacks->on_destroy (&stream, 0);
	  data = 0;
	  stream.data = 0;
	  QUICLY_TEST (clib_fifo_elts (app_wrk->wrk_evts[thread_index]) == 0,
		       "later stream destruction does not duplicate disconnect");
	}
      if (tests[i].body_len)
	QUICLY_TEST (svm_fifo_dequeue (rxf, tests[i].body_len, received) == tests[i].body_len &&
		       !memcmp (body, received, tests[i].body_len),
		     "all body bytes remain readable after EOF");
      svm_fifo_dequeue_drop_all (txf);
      clib_fifo_free (app_wrk->wrk_evts[thread_index]);
      if (data)
	{
	  clib_mem_free (data);
	  data = 0;
	}
    }

done:
  qqm->worker_stats[thread_index].n_streams = saved_streams;
  clib_fifo_free (app_wrk->wrk_evts[thread_index]);
  app_wrk->wrk_evts[thread_index] = saved_events;
  if (data)
    clib_mem_free (data);
  if (ctx)
    quic_ctx_free (qm, ctx);
  if (session)
    session_free (session);
  if (rxf)
    fifo_segment_free_fifo (fs, rxf);
  if (txf)
    fifo_segment_free_fifo (fs, txf);
  if (fs)
    fifo_segment_delete (&fsm, fs);
  pool_free (fsm.segments);
  vec_free (args.new_segment_indices);
  return res;
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
    TEST_RX_FIN,
    TEST_RX_CREDIT,
    TEST_ALL,
  } test = TEST_NONE;

  if (unformat (input, "stream-close"))
    test = TEST_STREAM_CLOSE;
  else if (unformat (input, "rx-fin"))
    test = TEST_RX_FIN;
  else if (unformat (input, "rx-credit"))
    test = TEST_RX_CREDIT;
  else if (unformat (input, "rx"))
    test = TEST_RX;
  else if (unformat (input, "cancel-rx"))
    test = TEST_CANCEL_RX;
  else if (unformat (input, "all"))
    test = TEST_ALL;
  if (test == TEST_NONE || unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (
      0, "expected exactly one of stream-close, rx, cancel-rx, rx-fin, rx-credit or all");
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_plugin.so", quic_main, qm);
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_plugin.so", quic_engine_vfts, engines);
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_quicly_plugin.so", quic_quicly_main, qqm);
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_quicly_plugin.so", quic_quicly_stream_callbacks,
				   callbacks);
  if ((test == TEST_RX || test == TEST_RX_FIN || test == TEST_RX_CREDIT || test == TEST_ALL) &&
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
  if (!res && (test == TEST_RX_FIN || test == TEST_ALL))
    res = quicly_test_rx_fin (vm, qqm, callbacks, &(*engines)[QUIC_ENGINE_QUICLY]);
  if (!res && (test == TEST_RX_CREDIT || test == TEST_ALL))
    res = quicly_test_rx_credit (vm, qqm, callbacks, &(*engines)[QUIC_ENGINE_QUICLY]);
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
      clib_bitmap_free (sessions[i].app_wrks_pending_ntf);
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
  .short_help = "test quicly [stream-close|rx|cancel-rx|rx-fin|rx-credit|all]",
  .function = quicly_test,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Quicly - Unit Test",
  .load_after = "quic_quicly_plugin.so",
  .default_disabled = 1,
};
