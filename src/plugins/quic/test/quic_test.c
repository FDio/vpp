/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <quic/quic.h>
#include <vpp/app/version.h>

#define QUIC_TEST(_cond, _comment, _args...)                                                       \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	{                                                                                          \
	  vlib_cli_output (vm, "FAIL:%d: " _comment, __LINE__, ##_args);                           \
	  res = 1;                                                                                 \
	  goto done;                                                                               \
	}                                                                                          \
      vlib_cli_output (vm, "PASS:%d: " _comment, __LINE__, ##_args);                               \
    }                                                                                              \
  while (0)

typedef struct
{
  int error;
  u32 calls;
  u8 is_unidir;
} quic_test_engine_t;

static int
quic_test_connect_stream (void *conn, void **stream, quic_stream_data_t **stream_data, u8 is_unidir)
{
  quic_test_engine_t *engine = conn;

  engine->calls++;
  engine->is_unidir = !!is_unidir;
  *stream = 0;
  *stream_data = 0;
  return engine->error;
}

static int
quic_test_stream_open_failure (vlib_main_t *vm, quic_main_t *qm, clib_thread_index_t thread_index)
{
  const struct
  {
    const char *name;
    int error;
    u8 no_connection;
  } cases[] = {
    { "engine stream limit", SESSION_E_MAX_STREAMS_HIT, 0 },
    { "engine error", SESSION_E_UNKNOWN, 0 },
    { "missing engine connection", SESSION_E_UNKNOWN, 1 },
  };
  quic_worker_ctx_t *worker = &qm->wrk_ctx[thread_index];
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  session_t *parent, stream_session = {};
  quic_test_engine_t engine = {};
  quic_ctx_t *ctx, parent_before;
  u32 parent_index, conn_index;
  u32 sessions_before = pool_elts (session_main.wrk[thread_index].sessions);
  int rv, res = 0;

  parent = session_alloc (thread_index);
  parent->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, 1);
  parent->session_state = SESSION_STATE_READY;
  parent_index = quic_ctx_alloc (qm, thread_index);
  parent->connection_index = parent_index;
  ctx = pool_elt_at_index (worker->ctx_pool, parent_index);
  ctx->c_c_index = parent_index;
  ctx->c_s_index = parent->session_index;
  ctx->c_proto = TRANSPORT_PROTO_QUIC;
  ctx->conn_state = QUIC_CONN_STATE_READY;
  sep.parent_handle = session_handle (parent);
  sep.transport_proto = TRANSPORT_PROTO_QUIC;

  vlib_cli_output (vm, "QUIC stream open cleanup on thread %u", thread_index);
  for (u32 cycle = 0; cycle < 3; cycle++)
    for (u8 is_unidir = 0; is_unidir < 2; is_unidir++)
      for (u32 i = 0; i < ARRAY_LEN (cases); i++)
	{
	  ctx = pool_elt_at_index (worker->ctx_pool, parent_index);
	  ctx->conn = cases[i].no_connection ? 0 : &engine;
	  parent_before = *ctx;
	  engine.error = cases[i].error;
	  engine.calls = 0;
	  engine.is_unidir = !is_unidir;
	  sep.transport_flags = is_unidir ? TRANSPORT_CFG_F_UNIDIRECTIONAL : 0;
	  conn_index = QUIC_CTX_INVALID_INDEX;

	  rv = tp_vfts[TRANSPORT_PROTO_QUIC].connect_stream (
	    session_endpoint_to_transport_cfg (&sep), &stream_session, &conn_index);

	  QUIC_TEST (rv == cases[i].error, "%s propagates its error (cycle %u, unidir %u)",
		     cases[i].name, cycle, is_unidir);
	  QUIC_TEST (conn_index == QUIC_CTX_INVALID_INDEX, "failed open publishes no context");
	  QUIC_TEST (engine.calls == !cases[i].no_connection,
		     "engine is called only with a connection");
	  QUIC_TEST (!engine.calls || engine.is_unidir == is_unidir,
		     "stream direction reaches the engine");
	  QUIC_TEST (pool_elts (worker->ctx_pool) == 1, "failed open releases its context");
	  QUIC_TEST (pool_elts (session_main.wrk[thread_index].sessions) == sessions_before + 1,
		     "failed open leaves only the parent session");
	  ctx = pool_elt_at_index (worker->ctx_pool, parent_index);
	  QUIC_TEST (!memcmp (ctx, &parent_before, sizeof (*ctx)),
		     "failed open preserves the parent");
	}

done:
  session_free (parent);
  ctx = pool_elt_at_index (worker->ctx_pool, parent_index);
  quic_ctx_free (qm, ctx);
  if (pool_elts (session_main.wrk[thread_index].sessions) != sessions_before)
    {
      vlib_cli_output (vm, "FAIL: parent session cleanup on thread %u", thread_index);
      res = 1;
    }
  return res;
}

static clib_error_t *
quic_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  quic_main_t *qm;
  quic_worker_ctx_t *workers = 0, *saved_workers;
  session_worker_t *session_workers = 0, *saved_session_workers;
  quic_engine_vft_t *engines = 0, *saved_engines, **engine_vfts;
  const u32 n_threads = 2;
  int res = 0;

  if ((!unformat (input, "stream-open-failure") && !unformat (input, "all")) ||
      unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected stream-open-failure or all");
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_plugin.so", quic_main, qm);
  QUIC_LOAD_SYMBOL_FROM_PLUGIN_TO ("quic_plugin.so", quic_engine_vfts, engine_vfts);

  /* The CLI holds the worker barrier and never yields while the private
   * session/context pools and mock engine replace the runtime tables. The
   * synthetic thread indices exercise pool ownership without real workers. */
  saved_workers = qm->wrk_ctx;
  saved_session_workers = session_main.wrk;
  saved_engines = *engine_vfts;
  vec_validate_aligned (workers, n_threads - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (session_workers, n_threads - 1, CLIB_CACHE_LINE_BYTES);
  /* Keep spare elements above the safe-reallocation threshold so no realloc
   * RPC can be queued for a pool that is freed when the fixture is destroyed. */
  for (u32 i = 0; i < n_threads; i++)
    {
      pool_alloc_aligned (workers[i].ctx_pool, 2 * POOL_REALLOC_SAFE_ELT_THRESH,
			  CLIB_CACHE_LINE_BYTES);
      pool_alloc_aligned (session_workers[i].sessions, 2 * POOL_REALLOC_SAFE_ELT_THRESH,
			  CLIB_CACHE_LINE_BYTES);
    }
  vec_validate (engines, qm->engine_type);
  engines[qm->engine_type].connect_stream = quic_test_connect_stream;
  qm->wrk_ctx = workers;
  session_main.wrk = session_workers;
  *engine_vfts = engines;

  for (u32 thread_index = 0; thread_index < n_threads; thread_index++)
    if ((res = quic_test_stream_open_failure (vm, qm, thread_index)))
      break;

  qm->wrk_ctx = saved_workers;
  session_main.wrk = saved_session_workers;
  *engine_vfts = saved_engines;
  /* Also release contexts leaked by a failing implementation, so the test can
   * be rerun without leaving synthetic state in the running instance. */
  for (u32 i = 0; i < n_threads; i++)
    {
      pool_free (workers[i].ctx_pool);
      pool_free (session_workers[i].sessions);
    }
  vec_free (workers);
  vec_free (session_workers);
  vec_free (engines);

  if (res)
    return clib_error_return (0, "QUIC unit test failed");
  vlib_cli_output (vm, "SUCCESS");
  return 0;
}

VLIB_CLI_COMMAND (quic_test_command, static) = {
  .path = "test quic",
  .short_help = "test quic [stream-open-failure|all]",
  .function = quic_test,
  .is_mp_safe = 0,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "QUIC - Unit Test",
  .load_after = "quic_plugin.so",
  .default_disabled = 1,
};
