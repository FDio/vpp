/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vnet/session/application.h>
#include <vnet/session/session.h>

u8 *
format_stream_session_fifos (u8 * s, va_list * args)
{
  stream_session_t *ss = va_arg (*args, stream_session_t *);
  int verbose = va_arg (*args, int);
  session_fifo_event_t _e, *e = &_e;
  u8 found;

  s = format (s, " Rx fifo: %U", format_svm_fifo, ss->server_rx_fifo, 1);
  if (verbose > 2 && ss->server_rx_fifo->has_event)
    {
      found = session_node_lookup_fifo_event (ss->server_rx_fifo, e);
      s = format (s, " session node event: %s\n",
		  found ? "found" : "not found");
    }
  s = format (s, " Tx fifo: %U", format_svm_fifo, ss->server_tx_fifo, 1);
  if (verbose > 2 && ss->server_tx_fifo->has_event)
    {
      found = session_node_lookup_fifo_event (ss->server_tx_fifo, e);
      s = format (s, " session node event: %s\n",
		  found ? "found" : "not found");
    }
  return s;
}

/**
 * Format stream session as per the following format
 *
 * verbose:
 *   "Connection", "Rx fifo", "Tx fifo", "Session Index"
 * non-verbose:
 *   "Connection"
 */
u8 *
format_stream_session (u8 * s, va_list * args)
{
  stream_session_t *ss = va_arg (*args, stream_session_t *);
  int verbose = va_arg (*args, int);
  transport_proto_vft_t *tp_vft;
  u8 *str = 0;
  tp_vft = transport_protocol_get_vft (ss->session_type);

  if (verbose == 1 && ss->session_state >= SESSION_STATE_ACCEPTING)
    str = format (0, "%-10u%-10u%-10lld",
		  svm_fifo_max_dequeue (ss->server_rx_fifo),
		  svm_fifo_max_enqueue (ss->server_tx_fifo),
		  stream_session_get_index (ss));

  if (ss->session_state >= SESSION_STATE_ACCEPTING)
    {
      s = format (s, "%U", tp_vft->format_connection, ss->connection_index,
		  ss->thread_index, verbose);
      if (verbose == 1)
	s = format (s, "%v", str);
      if (verbose > 1)
	s = format (s, "%U", format_stream_session_fifos, ss, verbose);
    }
  else if (ss->session_state == SESSION_STATE_LISTENING)
    {
      s = format (s, "%-40U%v", tp_vft->format_listener, ss->connection_index,
		  str);
    }
  else if (ss->session_state == SESSION_STATE_CONNECTING)
    {
      s = format (s, "%-40U%v", tp_vft->format_half_open,
		  ss->connection_index, str);
    }
  else
    {
      clib_warning ("Session in state: %d!", ss->session_state);
    }
  vec_free (str);

  return s;
}

uword
unformat_stream_session_id (unformat_input_t * input, va_list * args)
{
  u8 *proto = va_arg (*args, u8 *);
  ip46_address_t *lcl = va_arg (*args, ip46_address_t *);
  ip46_address_t *rmt = va_arg (*args, ip46_address_t *);
  u16 *lcl_port = va_arg (*args, u16 *);
  u16 *rmt_port = va_arg (*args, u16 *);
  u8 *is_ip4 = va_arg (*args, u8 *);
  u8 tuple_is_set = 0;

  memset (lcl, 0, sizeof (*lcl));
  memset (rmt, 0, sizeof (*rmt));

  if (unformat (input, "tcp"))
    {
      *proto = TRANSPORT_PROTO_TCP;
    }
  if (unformat (input, "udp"))
    {
      *proto = TRANSPORT_PROTO_UDP;
    }
  if (unformat (input, "%U:%d->%U:%d", unformat_ip4_address, &lcl->ip4,
		lcl_port, unformat_ip4_address, &rmt->ip4, rmt_port))
    {
      *is_ip4 = 1;
      tuple_is_set = 1;
    }
  else if (unformat (input, "%U:%d->%U:%d", unformat_ip6_address, &lcl->ip6,
		     lcl_port, unformat_ip6_address, &rmt->ip6, rmt_port))
    {
      *is_ip4 = 0;
      tuple_is_set = 1;
    }

  return tuple_is_set;
}

uword
unformat_stream_session (unformat_input_t * input, va_list * args)
{
  stream_session_t **result = va_arg (*args, stream_session_t **);
  stream_session_t *s;
  u8 proto = ~0;
  ip46_address_t lcl, rmt;
  u32 lcl_port = 0, rmt_port = 0, fib_index = 0;
  u8 is_ip4 = 0;

  if (!unformat (input, "%U", unformat_stream_session_id, &proto, &lcl, &rmt,
		 &lcl_port, &rmt_port, &is_ip4))
    return 0;

  if (is_ip4)
    s = session_lookup_safe4 (fib_index, &lcl.ip4, &rmt.ip4,
			      clib_host_to_net_u16 (lcl_port),
			      clib_host_to_net_u16 (rmt_port), proto);
  else
    s = session_lookup_safe6 (fib_index, &lcl.ip6, &rmt.ip6,
			      clib_host_to_net_u16 (lcl_port),
			      clib_host_to_net_u16 (rmt_port), proto);
  if (s)
    {
      *result = s;
      session_pool_remove_peeker (s->thread_index);
      return 1;
    }
  return 0;
}

uword
unformat_transport_connection (unformat_input_t * input, va_list * args)
{
  transport_connection_t **result = va_arg (*args, transport_connection_t **);
  u32 suggested_proto = va_arg (*args, u32);
  transport_connection_t *tc;
  u8 proto = ~0;
  ip46_address_t lcl, rmt;
  u32 lcl_port = 0, rmt_port = 0, fib_index = 0;
  u8 is_ip4 = 0;

  if (!unformat (input, "%U", unformat_stream_session_id, &proto, &lcl, &rmt,
		 &lcl_port, &rmt_port, &is_ip4))
    return 0;

  proto = (proto == (u8) ~ 0) ? suggested_proto : proto;
  if (proto == (u8) ~ 0)
    return 0;
  if (is_ip4)
    tc = session_lookup_connection4 (fib_index, &lcl.ip4, &rmt.ip4,
				     clib_host_to_net_u16 (lcl_port),
				     clib_host_to_net_u16 (rmt_port), proto);
  else
    tc = session_lookup_connection6 (fib_index, &lcl.ip6, &rmt.ip6,
				     clib_host_to_net_u16 (lcl_port),
				     clib_host_to_net_u16 (rmt_port), proto);

  if (tc)
    {
      *result = tc;
      return 1;
    }
  return 0;
}

static clib_error_t *
show_session_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  session_manager_main_t *smm = &session_manager_main;
  u8 *str = 0, one_session = 0, do_listeners = 0, sst, *app_name;
  int verbose = 0, i;
  stream_session_t *pool, *s;
  u32 transport_proto = ~0;

  if (!smm->is_enabled)
    {
      return clib_error_return (0, "session layer is not enabled");
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %d", &verbose))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "listeners %U", unformat_transport_proto,
			 &transport_proto))
	do_listeners = 1;
      else if (unformat (input, "%U", unformat_stream_session, &s))
	{
	  one_session = 1;
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (one_session)
    {
      vlib_cli_output (vm, "%U", format_stream_session, s, 3);
      return 0;
    }

  if (do_listeners)
    {
      sst = session_type_from_proto_and_ip (transport_proto, 1);
      vlib_cli_output (vm, "There are %d active %U listeners",
		       pool_elts (smm->listen_sessions[sst]),
		       format_transport_proto, transport_proto);
      if (verbose)
	{
	  vlib_cli_output (vm, "%-40s%-24s%-10s", "Listener", "App", "S-idx");
          /* *INDENT-OFF* */
          pool_foreach (s, smm->listen_sessions[sst], ({
            app_name = application_name_from_index (s->app_index);
            vlib_cli_output (vm, "%U%-25v%-10u", format_stream_session, s, 1,
                             app_name, s->session_index);
            vec_free (app_name);
          }));
          /* *INDENT-ON* */
	}
      return 0;
    }

  for (i = 0; i < vec_len (smm->sessions); i++)
    {
      u32 once_per_pool;
      pool = smm->sessions[i];

      once_per_pool = 1;

      if (pool_elts (pool))
	{

	  vlib_cli_output (vm, "Thread %d: %d active sessions",
			   i, pool_elts (pool));
	  if (verbose)
	    {
	      if (once_per_pool && verbose == 1)
		{
		  str = format (str, "%-50s%-15s%-10s%-10s%-10s",
				"Connection", "State", "Rx-f", "Tx-f",
				"S-idx");
		  vlib_cli_output (vm, "%v", str);
		  vec_reset_length (str);
		  once_per_pool = 0;
		}

              /* *INDENT-OFF* */
              pool_foreach (s, pool,
              ({
        	vec_reset_length (str);
                str = format (str, "%U", format_stream_session, s, verbose);
                vlib_cli_output (vm, "%v", str);
              }));
              /* *INDENT-ON* */
	    }
	}
      else
	vlib_cli_output (vm, "Thread %d: no active sessions", i);
      vec_reset_length (str);
    }
  vec_free (str);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_show_session_command) =
{
  .path = "show session",
  .short_help = "show session [verbose [nnn]]",
  .function = show_session_command_fn,
};
/* *INDENT-ON* */

static int
clear_session (stream_session_t * s)
{
  application_t *server = application_get (s->app_index);
  server->cb_fns.session_disconnect_callback (s);
  return 0;
}

static clib_error_t *
clear_session_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  session_manager_main_t *smm = &session_manager_main;
  u32 thread_index = 0, clear_all = 0;
  u32 session_index = ~0;
  stream_session_t **pool, *session;

  if (!smm->is_enabled)
    {
      return clib_error_return (0, "session layer is not enabled");
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "thread %d", &thread_index))
	;
      else if (unformat (input, "session %d", &session_index))
	;
      else if (unformat (input, "all"))
	clear_all = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!clear_all && session_index == ~0)
    return clib_error_return (0, "session <nn> required, but not set.");

  if (session_index != ~0)
    {
      session = session_get_if_valid (session_index, thread_index);
      if (!session)
	return clib_error_return (0, "no session %d on thread %d",
				  session_index, thread_index);
      clear_session (session);
    }

  if (clear_all)
    {
      /* *INDENT-OFF* */
      vec_foreach (pool, smm->sessions)
	{
	  pool_foreach(session, *pool, ({
	    clear_session (session);
	  }));
	};
      /* *INDENT-ON* */
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_session_command, static) =
{
  .path = "clear session",
  .short_help = "clear session thread <thread> session <index>",
  .function = clear_session_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_session_fifo_trace_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  stream_session_t *s = 0;
  u8 is_rx = 0, *str = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_stream_session, &s))
	;
      else if (unformat (input, "rx"))
	is_rx = 1;
      else if (unformat (input, "tx"))
	is_rx = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!SVM_FIFO_TRACE)
    {
      vlib_cli_output (vm, "fifo tracing not enabled");
      return 0;
    }

  if (!s)
    {
      vlib_cli_output (vm, "could not find session");
      return 0;
    }

  str = is_rx ?
    svm_fifo_dump_trace (str, s->server_rx_fifo) :
    svm_fifo_dump_trace (str, s->server_tx_fifo);

  vlib_cli_output (vm, "%v", str);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_session_fifo_trace_command, static) =
{
  .path = "show session fifo trace",
  .short_help = "show session fifo trace <session>",
  .function = show_session_fifo_trace_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
session_replay_fifo_command_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  stream_session_t *s = 0;
  u8 is_rx = 0, *str = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_stream_session, &s))
	;
      else if (unformat (input, "rx"))
	is_rx = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!SVM_FIFO_TRACE)
    {
      vlib_cli_output (vm, "fifo tracing not enabled");
      return 0;
    }

  if (!s)
    {
      vlib_cli_output (vm, "could not find session");
      return 0;
    }

  str = is_rx ?
    svm_fifo_replay (str, s->server_rx_fifo, 0, 1) :
    svm_fifo_replay (str, s->server_tx_fifo, 0, 1);

  vlib_cli_output (vm, "%v", str);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (session_replay_fifo_trace_command, static) =
{
  .path = "session replay fifo",
  .short_help = "session replay fifo <session>",
  .function = session_replay_fifo_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
session_enable_disable_fn (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_en = 1;
  clib_error_t *error;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	is_en = 1;
      else if (unformat (line_input, "disable"))
	is_en = 0;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
	}
    }

  unformat_free (line_input);
  return vnet_session_enable_disable (vm, is_en);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (session_enable_disable_command, static) =
{
  .path = "session",
  .short_help = "session [enable|disable]",
  .function = session_enable_disable_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
