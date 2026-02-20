/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <hs_apps/builtin_echo/echo_client.h>
#include <hs_apps/builtin_echo/echo_server.h>

static clib_error_t *
echo_server_create_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  echo_server_main_t *esm = &echo_server_main;
  u8 server_uri_set = 0, *appns_id = 0;
  u64 appns_flags = 0, appns_secret = 0;
  char *default_uri = "tcp://0.0.0.0/1234";
  int rv, is_stop = 0;
  clib_error_t *error = 0;

  esm->cfg.fifo_size = 4 << 20;
  esm->cfg.prealloc_fifos = 0;
  esm->cfg.private_segment_size = 512 << 20;
  esm->cfg.tls_engine = CRYPTO_ENGINE_OPENSSL;
  vec_free (esm->cfg.uri);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "uri %s", &esm->cfg.uri))
	server_uri_set = 1;
      else if (unformat (input, "fifo-size %U", unformat_memory_size, &esm->cfg.fifo_size))
	;
      else if (unformat (input, "prealloc-fifos %d", &esm->cfg.prealloc_fifos))
	;
      else if (unformat (input, "private-segment-size %U", unformat_memory_size,
			 &esm->cfg.private_segment_size))
	;
      else if (unformat (input, "appns %_%v%_", &appns_id))
	;
      else if (unformat (input, "all-scope"))
	appns_flags |= (APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE | APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE);
      else if (unformat (input, "local-scope"))
	appns_flags |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
      else if (unformat (input, "global-scope"))
	appns_flags |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
      else if (unformat (input, "secret %lu", &appns_secret))
	;
      else if (unformat (input, "stop"))
	is_stop = 1;
      else if (unformat (input, "tls-engine %d", &esm->cfg.tls_engine))
	;
      else
	{
	  error = clib_error_return (0, "failed: unknown input `%U'", format_unformat_error, input);
	  goto cleanup;
	}
    }

  if (is_stop)
    {
      if (esm->app_index == (u32) ~0)
	{
	  echo_cli ("server not running");
	  error = clib_error_return (0, "failed: server not running");
	  goto cleanup;
	}
      rv = echo_server_detach ();
      if (rv)
	{
	  echo_cli ("failed: detach");
	  error = clib_error_return (0, "failed: server detach %d", rv);
	  goto cleanup;
	}
      goto cleanup;
    }

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type = RT_BACKEND_ENGINE_RULE_TABLE };
  vnet_session_enable_disable (vm, &args);

  if (!server_uri_set)
    {
      echo_cli ("No uri provided! Using default: %s", default_uri);
      esm->cfg.uri = (char *) format (0, "%s%c", default_uri, 0);
    }

  rv = echo_server_create (vm, appns_id, appns_flags, appns_secret);
  if (rv)
    {
      vec_free (esm->cfg.uri);
      error = clib_error_return (0, "failed: server_create returned %d", rv);
      goto cleanup;
    }

cleanup:
  vec_free (appns_id);

  return error;
}

/*?
 * Server for performing network throughput measurements.
 * It can test TCP, UDP, TLS or QUIC throughput.
 * To perform test you must establish both a server and a client.
 *
 * @cliexpar
 * Example of how to start server:
 * @cliexcmd{test echo server uri tcp://6.0.1.2:1234}
 ?*/
VLIB_CLI_COMMAND (echo_server_create_command, static) = {
  .path = "test echo server",
  .short_help = "test echo server [uri <proto://ip:port>] [fifo-size <bytes>[k|m|g]]\n"
		"[private-segment-count <n>] [private-segment-size <bytes>[k|m|g]]\n"
		"[all-scope|local-scope|global-scope] [secret <n>] [stop] [tls-engine <id>]\n"
		"[prealloc-fifos <n>] [appns <id>]",
  .function = echo_server_create_command_fn,
};

static clib_error_t *
ec_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  char *default_uri = "tcp://6.0.1.1/1234";
  ec_main_t *ecm = &ec_main;
  clib_error_t *error = 0;
  int rv, timed_run_conflict = 0, tput_conflict = 0, had_config = 1, use_default_mode = 1;

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
      if (unformat (line_input, "uri %s", &ecm->cfg.uri))
	;
      else if (unformat (line_input, "nclients %d", &ecm->cfg.n_clients))
	;
      else if (unformat (line_input, "nstreams %d", &ecm->cfg.n_streams))
	;
      else if (unformat (line_input, "bytes %U", unformat_memory_size, &ecm->cfg.bytes_to_send))
	{
	  timed_run_conflict++;
	  use_default_mode = 0;
	}
      else if (unformat (line_input, "test-timeout %f", &ecm->test_timeout))
	timed_run_conflict++;
      else if (unformat (line_input, "syn-timeout %f", &ecm->syn_timeout))
	;
      else if (unformat (line_input, "run-time %f", &ecm->run_time))
	{
	  ecm->test_timeout = ecm->run_time;
	  use_default_mode = 0;
	}
      else if (unformat (line_input, "echo-bytes"))
	{
	  ecm->cfg.echo_bytes = 1;
	  use_default_mode = 0;
	}
      else if (unformat (line_input, "fifo-size %U", unformat_memory_size, &ecm->cfg.fifo_size))
	;
      else if (unformat (line_input, "private-segment-size %U", unformat_memory_size,
			 &ecm->cfg.private_segment_size))
	;
      else if (unformat (line_input, "throughput %U", unformat_base10, &ecm->throughput))
	ecm->throughput /= 8;
      else if (unformat (line_input, "max-tx-chunk %U", unformat_memory_size,
			 &ecm->max_chunk_bytes))
	tput_conflict = 1;
      else if (unformat (line_input, "preallocate-fifos"))
	ecm->prealloc_fifos = 1;
      else if (unformat (line_input, "preallocate-sessions"))
	ecm->prealloc_sessions = 1;
      else if (unformat (line_input, "client-batch %d", &ecm->connections_per_batch))
	;
      else if (unformat (line_input, "report-jitter"))
	ecm->cfg.report_interval_jitter = 1;
      else if (unformat (line_input, "report-interval-total %u", &ecm->cfg.report_interval))
	ecm->cfg.report_interval_total = 1;
      else if (unformat (line_input, "report-interval %u", &ecm->cfg.report_interval))
	;
      else if (unformat (line_input, "report-interval"))
	ecm->cfg.report_interval = 1;
      else if (unformat (line_input, "appns %_%v%_", &ecm->appns_id))
	;
      else if (unformat (line_input, "all-scope"))
	ecm->attach_flags |=
	  (APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE | APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE);
      else if (unformat (line_input, "local-scope"))
	ecm->attach_flags |= APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
      else if (unformat (line_input, "global-scope"))
	ecm->attach_flags |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
      else if (unformat (line_input, "secret %lu", &ecm->appns_secret))
	;
      else if (unformat (line_input, "verbose"))
	ecm->cfg.test_cfg.verbose = 1;
      else if (unformat (line_input, "test-bytes"))
	ecm->cfg.test_cfg.test_bytes = 1;
      else if (unformat (line_input, "tls-engine %d", &ecm->cfg.tls_engine))
	;
      else
	{
	  error =
	    clib_error_return (0, "failed: unknown input `%U'", format_unformat_error, line_input);
	  goto cleanup;
	}
    }

  if (ecm->max_chunk_bytes > vec_len (ecm->connect_test_data))
    {
      echo_cli ("Provided max-tx-chunk %U too big, using default %U", format_memory_size,
		ecm->max_chunk_bytes, format_memory_size, vec_len (ecm->connect_test_data));
      ecm->max_chunk_bytes = vec_len (ecm->connect_test_data);
    }

  /* if just uri provided do 10 seconds upload test with 1 second report interval */
  if (use_default_mode)
    {
      ecm->test_timeout = ecm->run_time = 10.0;
      ecm->cfg.report_interval = 1;
    }
  else
    {
      if (timed_run_conflict && ecm->run_time)
	return clib_error_return (0, "failed: invalid arguments for a timed run!");
      if (ecm->throughput && tput_conflict)
	return clib_error_return (0, "failed: can't set fixed tx chunk for a throughput run!");
      /* if running for given time do periodic stats by default */
      if (ecm->run_time && !ecm->cfg.report_interval)
	ecm->cfg.report_interval = 1;
    }

parse_config:

  ecm->cfg.test_cfg.num_test_sessions = ecm->expected_connections =
    ecm->cfg.n_clients * ecm->cfg.n_streams;

  if (!ecm->cfg.uri)
    {
      echo_cli ("No uri provided. Using default: %s", default_uri);
      ecm->cfg.uri = (char *) format (0, "%s%c", default_uri, 0);
    }

  if ((rv = parse_uri (ecm->cfg.uri, &ecm->cfg.sep)))
    {
      error = clib_error_return (0, "Uri parse error: %d", rv);
      goto cleanup;
    }
  ecm->cfg.proto = ecm->cfg.sep.transport_proto;
  if (ecm->prealloc_sessions)
    ec_prealloc_sessions (ecm);

  if ((error = ec_attach ()))
    {
      clib_error_report (error);
      goto cleanup;
    }

  error = ec_run (vm);

cleanup:
  ecm->run_test = EC_EXITING;
  vlib_process_wait_for_event_or_clock (vm, 10e-3);

  /* Detach the application, so we can use different fifo sizes next time */
  if (ec_detach ())
    {
      error = clib_error_return (0, "failed: app detach");
      echo_cli ("WARNING: app detach failed...");
    }

  ec_cleanup (ecm);
  if (had_config)
    unformat_free (line_input);

  if (error)
    echo_cli ("test failed");

  return error;
}

/*?
 * Client for performing network throughput measurements.
 * It can test TCP, UDP, TLS or QUIC throughput.
 * To perform test you must establish both a server and a client.
 *
 * @cliexpar
 * Example of how to measure upload speed, test duration 10 seconds and measurement interval 1
 * second (zero copy):
 * @cliexcmd{test echo client uri tcp://6.0.1.2:1234}
 ?*/
VLIB_CLI_COMMAND (ec_command, static) = {
  .path = "test echo clients",
  .short_help =
    "test echo clients [nclients <n>] [bytes <bytes>[k|m|g] | run-time <seconds>]\n"
    "[test-timeout <seconds>] [syn-timeout <seconds>] [echo-bytes]\n"
    "[fifo-size <bytes>[k|m|g]] [appns <id>] [tls-engine <id>]\n"
    "[private-segment-size <bytes>[k|m|g]] [preallocate-fifos] [preallocate-sessions]\n"
    "[client-batch <n>] [max-tx-chunk <bytes>[k|m]] [nstreams <n>]\n"
    "[throughput <bytes>[k|m|g]] [report-interval[-total] [<seconds>]] [report-jitter]\n"
    "[uri <proto://ip:port>] [test-bytes] [verbose] [all-scope|local-scope|global-scope]",
  .function = ec_command_fn,
  .is_mp_safe = 1,
};
