/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <quic/quic.h>
#include <quic/quic_eng_inline.h>
#include <quic/quic_timer.h>
#include <vnet/session/application.h>

static u8 *
format_quic_ctx_state (u8 *s, va_list *args)
{
  quic_ctx_t *ctx;
  session_t *as;

  ctx = va_arg (*args, quic_ctx_t *);
  as = session_get (ctx->c_s_index, ctx->c_thread_index);
  if (as->session_state == SESSION_STATE_LISTENING)
    s = format (s, "%s", "LISTEN");
  else
    {
      if (as->session_state == SESSION_STATE_READY)
	s = format (s, "%s", "ESTABLISHED");
      else if (as->session_state == SESSION_STATE_ACCEPTING)
	s = format (s, "%s", "ACCEPTING");
      else if (as->session_state == SESSION_STATE_CONNECTING)
	s = format (s, "%s", "CONNECTING");
      else if (as->session_state >= SESSION_STATE_TRANSPORT_CLOSED)
	s = format (s, "%s", "CLOSED");
      else if (as->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
	s = format (s, "%s", "CLOSING");
      else
	s = format (s, "UNHANDLED %u", as->session_state);
    }

  return s;
}

static u8 *
format_quic_connection_id (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  u32 udp_si, udp_ti;

  session_parse_handle (ctx->udp_session_handle, &udp_si, &udp_ti);
  s = format (s, "[%d:%d][Q] conn %u app_wrk %u ts %d:%d", ctx->c_thread_index,
	      ctx->c_s_index, ctx->c_c_index, ctx->parent_app_wrk_id, udp_ti,
	      udp_si);
  return s;
}

static u8 *
format_quic_ctx_connection (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  u32 verbose = va_arg (*args, u32);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_quic_connection_id, ctx);
  if (verbose)
    {
      s =
	format (s, "%-" SESSION_CLI_STATE_LEN "U", format_quic_ctx_state, ctx);
      if (verbose > 1)
	s = format (s, "\n%U", quic_eng_format_connection_stats, ctx);
    }
  return s;
}

static u8 *
format_quic_stream_id (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  s =
    format (s, "[%d:%d][Q] stream %u stream-id 0x%lx conn %u",
	    ctx->c_thread_index, ctx->c_s_index, ctx->c_c_index,
	    quic_eng_stream_get_stream_id (ctx), ctx->quic_connection_ctx_id);
  return s;
}

static u8 *
format_quic_ctx_stream (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  u32 verbose = va_arg (*args, u32);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_quic_stream_id, ctx);
  if (verbose)
    {
      s =
	format (s, "%-" SESSION_CLI_STATE_LEN "U", format_quic_ctx_state, ctx);
      if (verbose > 1)
	s = format (s, "\n%U", quic_eng_format_stream_stats, ctx);
    }
  return s;
}

static u8 *
format_quic_ctx_listener (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  app_listener_t *al;
  session_t *lts;

  al = app_listener_get_w_handle (ctx->udp_session_handle);
  lts = app_listener_get_session (al);
  s = format (s, "[%d:%d][Q] app_wrk %u ts %d:%d", ctx->c_thread_index,
	      ctx->c_s_index, ctx->parent_app_wrk_id, lts->thread_index,
	      lts->session_index);
  return s;
}

static u8 *
format_quic_ho_conn_id (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);

  s = format (s, "[%d:%d][Q] half-open app_wrk %u ts %d:%d",
	      ctx->c_thread_index, ctx->c_s_index, ctx->parent_app_wrk_id,
	      session_thread_from_handle (ctx->udp_session_handle),
	      session_index_from_handle (ctx->udp_session_handle));
  return s;
}

u8 *
format_quic_connection (u8 *s, va_list *args)
{
  u32 qc_index = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (qc_index, thread_index);

  if (quic_ctx_is_stream (ctx))
    s = format (s, "%U", format_quic_ctx_stream, ctx, verbose);
  else
    s = format (s, "%U", format_quic_ctx_connection, ctx, verbose);
  return s;
}

u8 *
format_quic_half_open (u8 *s, va_list *args)
{
  u32 qc_index = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (qc_index, thread_index);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_quic_ho_conn_id, ctx);
  if (verbose)
    s = format (s, "%-" SESSION_CLI_STATE_LEN "U", format_quic_ctx_state, ctx);
  return s;
}

u8 *
format_quic_listener (u8 *s, va_list *args)
{
  u32 tci = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (tci, thread_index);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_quic_ctx_listener, ctx);
  if (verbose)
    s = format (s, "%-" SESSION_CLI_STATE_LEN "U", format_quic_ctx_state, ctx);
  return s;
}

static clib_error_t *
quic_list_crypto_context_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  quic_main_t *qm = &quic_main;

  session_cli_return_if_not_enabled ();
  if (qm->engine_type == QUIC_ENGINE_NONE)
    {
      vlib_cli_output (vm, "No QUIC engine plugin enabled");
      return 0;
    }
  if (qm->engine_is_initialized[qm->engine_type] == 0)
    {
      vlib_cli_output (vm, "quic engine %s not initialized",
		       quic_engine_type_str (qm->engine_type));
      return 0;
    }

  quic_eng_crypto_context_list (vm);
  return 0;
}

static clib_error_t *
quic_set_max_packets_per_key_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u64 tmp;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_memory_size, &tmp))
	{
	  quic_main.max_packets_per_key = tmp;
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, line_input);
    }

  return 0;
}

static clib_error_t *
quic_set_cc_fn (vlib_main_t *vm, unformat_input_t *input,
		vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  quic_main_t *qm = &quic_main;
  clib_error_t *e = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "reno"))
	qm->default_quic_cc = QUIC_CC_RENO;
      else if (unformat (line_input, "cubic"))
	qm->default_quic_cc = QUIC_CC_CUBIC;
      else
	{
	  e = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, line_input);
	  goto done;
	}
    }
done:
  unformat_free (line_input);
  return e;
}

static clib_error_t *
quic_plugin_crypto_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  quic_main_t *qm = &quic_main;
  clib_error_t *e = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "vpp"))
	{
	  qm->default_crypto_engine = CRYPTO_ENGINE_VPP;
	  qm->vnet_crypto_init = 0;
	}
      else if (unformat (line_input, "engine-lib"))
	{
	  qm->default_crypto_engine =
	    (qm->engine_type == QUIC_ENGINE_QUICLY) ?
	      CRYPTO_ENGINE_PICOTLS :
	      ((qm->engine_type == QUIC_ENGINE_OPENSSL) ?
		 CRYPTO_ENGINE_OPENSSL :
		 CRYPTO_ENGINE_NONE);
	  if (qm->default_crypto_engine != CRYPTO_ENGINE_NONE)
	    {
	      qm->vnet_crypto_init = 0;
	    }
	  else
	    {
	      e = clib_error_return (0,
				     "No quic engine available, using default "
				     "crypto engine '%U' (%u)",
				     format_crypto_engine,
				     qm->default_crypto_engine,
				     qm->default_crypto_engine);
	      goto done;
	    }
	}
      else
	{
	  e = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, line_input);
	  goto done;
	}
    }
done:
  unformat_free (line_input);
  return e;
}

u64 quic_fifosize = 0;
static clib_error_t *
quic_plugin_set_fifo_size_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  uword tmp;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    {
	      return clib_error_return (0, "fifo-size %llu (0x%llx) too large",
					tmp, tmp);
	    }
	  quic_main.udp_fifo_size = tmp;
	  quic_update_fifo_size ();
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, line_input);
    }

  return 0;
}

static inline u64
quic_get_counter_value (u32 event_code)
{
  vlib_node_t *n;
  vlib_main_t *vm;
  vlib_error_main_t *em;

  u32 code, i;
  u64 c, sum = 0;

  vm = vlib_get_main ();
  em = &vm->error_main;
  n = vlib_get_node (vm, quic_input_node.index);
  code = event_code;
  foreach_vlib_main ()
    {
      em = &this_vlib_main->error_main;
      i = n->error_heap_index + code;
      c = em->counters[i];

      if (i < vec_len (em->counters_last_clear))
	c -= em->counters_last_clear[i];
      sum += c;
    }
  return sum;
}

static void
quic_show_aggregated_stats (vlib_main_t *vm)
{
  u32 num_workers = vlib_num_workers ();
  quic_ctx_t *ctx = NULL;
  quic_stats_t st, agg_stats;
  u32 i, nconn = 0, nstream = 0;

  clib_memset (&agg_stats, 0, sizeof (agg_stats));
  for (i = 0; i < num_workers + 1; i++)
    {
      pool_foreach (ctx, quic_main.wrk_ctx[i].ctx_pool)
	{
	  if (quic_ctx_is_conn (ctx) && ctx->conn)
	    {
	      quic_eng_connection_get_stats (ctx->conn, &st);
	      agg_stats.rtt_smoothed += st.rtt_smoothed;
	      agg_stats.rtt_minimum += st.rtt_minimum;
	      agg_stats.rtt_variance += st.rtt_variance;
	      agg_stats.num_packets_received += st.num_packets_received;
	      agg_stats.num_packets_sent += st.num_packets_sent;
	      agg_stats.num_packets_lost += st.num_packets_lost;
	      agg_stats.num_packets_ack_received +=
		st.num_packets_ack_received;
	      agg_stats.num_bytes_received += st.num_bytes_received;
	      agg_stats.num_bytes_sent += st.num_bytes_sent;
	      nconn++;
	    }
	  else if (quic_ctx_is_stream (ctx))
	    nstream++;
	}
    }
  vlib_cli_output (vm, "-------- Connections --------");
  vlib_cli_output (vm, "Current:         %u", nconn);
  vlib_cli_output (vm, "Opened:          %d",
		   quic_get_counter_value (QUIC_ERROR_OPENED_CONNECTION));
  vlib_cli_output (vm, "Closed:          %d",
		   quic_get_counter_value (QUIC_ERROR_CLOSED_CONNECTION));
  vlib_cli_output (vm, "---------- Streams ----------");
  vlib_cli_output (vm, "Current:         %u", nstream);
  vlib_cli_output (vm, "Opened:          %d",
		   quic_get_counter_value (QUIC_ERROR_OPENED_STREAM));
  vlib_cli_output (vm, "Closed:          %d",
		   quic_get_counter_value (QUIC_ERROR_CLOSED_STREAM));
  vlib_cli_output (vm, "---------- Packets ----------");
  vlib_cli_output (vm, "RX Total:        %d",
		   quic_get_counter_value (QUIC_ERROR_RX_PACKETS));
  vlib_cli_output (vm, "RX 0RTT:         %d",
		   quic_get_counter_value (QUIC_ERROR_ZERO_RTT_RX_PACKETS));
  vlib_cli_output (vm, "RX 1RTT:         %d",
		   quic_get_counter_value (QUIC_ERROR_ONE_RTT_RX_PACKETS));
  vlib_cli_output (vm, "TX Total:        %d",
		   quic_get_counter_value (QUIC_ERROR_TX_PACKETS));
  vlib_cli_output (vm, "----------- Stats -----------");
  vlib_cli_output (vm, "Min      RTT     %f",
		   nconn > 0 ? agg_stats.rtt_minimum / nconn : 0);
  vlib_cli_output (vm, "Smoothed RTT     %f",
		   nconn > 0 ? agg_stats.rtt_smoothed / nconn : 0);
  vlib_cli_output (vm, "Variance on RTT  %f",
		   nconn > 0 ? agg_stats.rtt_variance / nconn : 0);
  vlib_cli_output (vm, "Packets Received %lu", agg_stats.num_packets_received);
  vlib_cli_output (vm, "Packets Sent     %lu", agg_stats.num_packets_sent);
  vlib_cli_output (vm, "Packets Lost     %lu", agg_stats.num_packets_lost);
  vlib_cli_output (vm, "Packets Acks     %lu",
		   agg_stats.num_packets_ack_received);
  vlib_cli_output (vm, "RX bytes         %lu", agg_stats.num_bytes_received);
  vlib_cli_output (vm, "TX bytes         %lu", agg_stats.num_bytes_sent);
}

static clib_error_t *
quic_show_connections_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  quic_main_t *qm = &quic_main;

  session_cli_return_if_not_enabled ();
  if (qm->engine_type == QUIC_ENGINE_NONE)
    {
      vlib_cli_output (vm, "No QUIC engine plugin enabled");
      return 0;
    }
  if (qm->engine_is_initialized[qm->engine_type] == 0)
    {
      vlib_cli_output (vm, "quic engine %s not initialized",
		       quic_engine_type_str (qm->engine_type));
      return 0;
    }

  vlib_cli_output (vm, "quic engine: %s",
		   quic_engine_type_str (qm->engine_type));
  vlib_cli_output (
    vm, "crypto engine: %s",
    qm->default_crypto_engine == CRYPTO_ENGINE_PICOTLS ?
      "picotls" :
      (qm->default_crypto_engine == CRYPTO_ENGINE_VPP ? "vpp" : "none"));
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      quic_show_aggregated_stats (vm);
      return 0;
    }
  else
    {
      error = clib_error_return (0, "unknown input `%U'",
				 format_unformat_error, line_input);
      goto done;
    }

done:
  unformat_free (line_input);
  return error;
}

/* TODO: This command should not be engine specific.
 * Current implementation is for quicly engine!
 * Fix quicly specific syntax (e.g. picotls) to be generic.
 */
VLIB_CLI_COMMAND (quic_plugin_crypto_command, static) = {
  .path = "quic set crypto api",
  .short_help = "quic set crypto api [engine-lib|vpp]",
  .function = quic_plugin_crypto_command_fn,
};
VLIB_CLI_COMMAND (quic_plugin_set_fifo_size_command, static) = {
  .path = "quic set fifo-size",
  .short_help = "quic set fifo-size N[K|M|G] (default 64K)",
  .function = quic_plugin_set_fifo_size_command_fn,
};
VLIB_CLI_COMMAND (quic_show_ctx_command, static) = {
  .path = "show quic",
  .short_help = "show quic",
  .function = quic_show_connections_command_fn,
};
VLIB_CLI_COMMAND (quic_list_crypto_context_command, static) = {
  .path = "show quic crypto context",
  .short_help = "list quic crypto contextes",
  .function = quic_list_crypto_context_command_fn,
};
VLIB_CLI_COMMAND (quic_set_max_packets_per_key, static) = {
  .path = "set quic max_packets_per_key",
  .short_help = "set quic max_packets_per_key 16777216",
  .function = quic_set_max_packets_per_key_fn,
};
VLIB_CLI_COMMAND (quic_set_cc, static) = {
  .path = "set quic cc",
  .short_help = "set quic cc [reno|cubic]",
  .function = quic_set_cc_fn,
};

static clib_error_t *
quic_config_fn (vlib_main_t *vm, unformat_input_t *input)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  quic_main_t *qm = &quic_main;
  clib_error_t *error = 0;
  uword tmp;
  u32 i;

  qm->udp_fifo_size = QUIC_DEFAULT_FIFO_SIZE;
  qm->udp_fifo_prealloc = 0;
  qm->connection_timeout = QUIC_DEFAULT_CONN_TIMEOUT;
  qm->enable_tx_pacing = 1;
  qm->first_seg_size = 32 << 20;
  qm->add_seg_size = 256 << 20;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "fifo-size %U", unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    {
	      error = clib_error_return (
		0, "fifo-size %llu (0x%llx) too large", tmp, tmp);
	      goto done;
	    }
	  qm->udp_fifo_size = tmp;
	}
      else if (unformat (input, "first-segment-size %U", unformat_memory_size, &qm->first_seg_size))
	;
      else if (unformat (input, "add-segment-size %U", unformat_memory_size, &qm->add_seg_size))
	;
      else if (unformat (line_input, "conn-timeout %u", &i))
	qm->connection_timeout = i;
      else if (unformat (line_input, "fifo-prealloc %u", &i))
	qm->udp_fifo_prealloc = i;
      else if (unformat (input, "no-tx-pacing"))
	qm->enable_tx_pacing = 0;
      /* TODO: add cli selection of quic_eng_<types> */
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }
done:
  unformat_free (line_input);
  return error;
}

VLIB_EARLY_CONFIG_FUNCTION (quic_config_fn, "quic");
