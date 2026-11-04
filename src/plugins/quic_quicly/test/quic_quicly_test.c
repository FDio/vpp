/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <quic_quicly/quic_quicly.h>
#include <vpp/app/version.h>

#define QUICLY_TEST(cond, text)                                                                    \
  do                                                                                               \
    {                                                                                              \
      vlib_cli_output (vm, "%s:%d: %s", (cond) ? "PASS" : "FAIL", __LINE__, text);                 \
      if (!(cond))                                                                                 \
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
  const u64 stream_ids[] = { 0, 2, 3 }; /* bidi, sending uni, receiving uni */
  int res = 0;

  if ((!unformat (input, "stream-close") && !unformat (input, "all")) ||
      unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected stream-close or all");
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_plugin.so", quic_main, qm);
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_plugin.so", quic_engine_vfts, engines);
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_quicly_plugin.so", quic_quicly_main, qqm);
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_quicly_plugin.so", quic_quicly_stream_callbacks,
				   callbacks);
  quic_node = vlib_get_node_by_name (vm, (u8 *) "quic-input");
  if (!quic_node || vec_len (*engines) <= QUIC_ENGINE_QUICLY)
    return clib_error_return (0, "QUIC engine is not registered");
  node.index = quic_node->index;
  counter_index = quic_node->error_heap_index + QUIC_ERROR_CLOSED_STREAM;
  saved_counter = vm->error_main.counters[counter_index];
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
    }
  /* CLI worker barrier protects the temporary session/context pools. */
  qm->wrk_ctx = workers;
  qm->quic_input_node = &node;
  session_main.wrk = sessions;
  qqm->qm = qm;
  qqm->worker_stats = stats;
  for (u32 thread_index = 0; thread_index < 2 && !res; thread_index++)
    for (u32 i = 0; i < ARRAY_LEN (stream_ids) && !res; i++)
      for (u32 order = 0; order < 3 && !res; order++)
	res = quicly_test_stream_close (vm, qqm, callbacks, &(*engines)[QUIC_ENGINE_QUICLY],
					thread_index, stream_ids[i], order);
  qm->wrk_ctx = saved_workers;
  qm->quic_input_node = saved_node;
  session_main.wrk = saved_sessions;
  qqm->qm = saved_qm;
  qqm->worker_stats = saved_stats;
  vm->error_main.counters[counter_index] = saved_counter;
  for (u32 i = 0; i < 2; i++)
    {
      pool_free (workers[i].ctx_pool);
      pool_free (sessions[i].sessions);
    }
  vec_free (workers);
  vec_free (sessions);
  vec_free (stats);
  if (res)
    return clib_error_return (0, "quicly unit test failed");
  vlib_cli_output (vm, "SUCCESS");
  return 0;
}

VLIB_CLI_COMMAND (quicly_test_command, static) = {
  .path = "test quicly",
  .short_help = "test quicly [stream-close|all]",
  .function = quicly_test,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Quicly - Unit Test",
  .load_after = "quic_quicly_plugin.so",
  .default_disabled = 1,
};
