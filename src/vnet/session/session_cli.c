/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
format_session_fifos (u8 * s, va_list * args)
{
  session_t *ss = va_arg (*args, session_t *);
  int verbose = va_arg (*args, int);
  session_event_t _e, *e = &_e;
  u8 found;

  if (!ss->rx_fifo || !ss->tx_fifo)
    return s;

  s = format (s, " Rx fifo: %U", format_svm_fifo, ss->rx_fifo, verbose);
  if (verbose > 2 && ss->rx_fifo->shr->has_event)
    {
      found = session_node_lookup_fifo_event (ss->rx_fifo, e);
      s = format (s, " session node event: %s\n",
		  found ? "found" : "not found");
    }
  s = format (s, " Tx fifo: %U", format_svm_fifo, ss->tx_fifo, verbose);
  if (verbose > 2 && ss->tx_fifo->shr->has_event)
    {
      found = session_node_lookup_fifo_event (ss->tx_fifo, e);
      s = format (s, " session node event: %s\n",
		  found ? "found" : "not found");
    }
  return s;
}

const char *session_state_str[] = {
#define _(sym, str) str,
  foreach_session_state
#undef _
};

u8 *
format_session_state (u8 * s, va_list * args)
{
  session_t *ss = va_arg (*args, session_t *);

  if (ss->session_state < SESSION_N_STATES)
    s = format (s, "%s", session_state_str[ss->session_state]);
  else
    s = format (s, "UNKNOWN STATE (%d)", ss->session_state);

  return s;
}

const char *session_flags_str[] = {
#define _(sym, str) str,
  foreach_session_flag
#undef _
};

u8 *
format_session_flags (u8 * s, va_list * args)
{
  session_t *ss = va_arg (*args, session_t *);
  int i, last = -1;

  for (i = 0; i < SESSION_N_FLAGS; i++)
    if (ss->flags & (1 << i))
      last = i;

  for (i = 0; i < last; i++)
    {
      if (ss->flags & (1 << i))
	s = format (s, "%s, ", session_flags_str[i]);
    }
  if (last >= 0)
    s = format (s, "%s", session_flags_str[last]);

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
format_session (u8 * s, va_list * args)
{
  session_t *ss = va_arg (*args, session_t *);
  int verbose = va_arg (*args, int);
  u32 tp = session_get_transport_proto (ss);
  u8 *str = 0;

  if (ss->session_state >= SESSION_STATE_TRANSPORT_DELETED)
    {
      s = format (s, "[%u:%u] CLOSED", ss->thread_index, ss->session_index);
      return s;
    }

  if (verbose == 1)
    {
      u32 rxf, txf;

      rxf = ss->rx_fifo ? svm_fifo_max_dequeue (ss->rx_fifo) : 0;
      txf = ss->tx_fifo ? svm_fifo_max_dequeue (ss->tx_fifo) : 0;
      str = format (0, "%-10u%-10u", rxf, txf);
    }

  if (ss->session_state >= SESSION_STATE_ACCEPTING
      || ss->session_state == SESSION_STATE_CREATED)
    {
      s = format (s, "%U", format_transport_connection, tp,
		  ss->connection_index, ss->thread_index, verbose);
      if (verbose == 1)
	s = format (s, "%v", str);
      if (verbose > 1)
	{
	  s = format (s, "%U", format_session_fifos, ss, verbose);
	  s = format (s, " session: state: %U opaque: 0x%x flags: %U\n",
		      format_session_state, ss, ss->opaque,
		      format_session_flags, ss);
	}
    }
  else if (ss->session_state == SESSION_STATE_LISTENING)
    {
      s = format (s, "%U%v", format_transport_listen_connection,
		  tp, ss->connection_index, ss->thread_index, verbose, str);
      if (verbose > 1)
	s = format (s, "\n%U", format_session_fifos, ss, verbose);
    }
  else if (ss->session_state == SESSION_STATE_CONNECTING)
    {
      s = format (s, "%-40U%v", format_transport_half_open_connection,
		  tp, ss->connection_index, ss->thread_index, str);
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
  u32 *fib_index = va_arg (*args, u32 *);
  ip46_address_t *lcl = va_arg (*args, ip46_address_t *);
  ip46_address_t *rmt = va_arg (*args, ip46_address_t *);
  u16 *lcl_port = va_arg (*args, u16 *);
  u16 *rmt_port = va_arg (*args, u16 *);
  u8 *is_ip4 = va_arg (*args, u8 *);
  u8 tuple_is_set = 0;
  u32 vrf = ~0;

  clib_memset (lcl, 0, sizeof (*lcl));
  clib_memset (rmt, 0, sizeof (*rmt));

  if (unformat (input, "tcp"))
    {
      *proto = TRANSPORT_PROTO_TCP;
    }
  else if (unformat (input, "udp"))
    {
      *proto = TRANSPORT_PROTO_UDP;
    }
  else
    return 0;

  if (unformat (input, "vrf %u", &vrf))
    ;

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

  if (vrf != ~0)
    {
      fib_protocol_t fib_proto;
      fib_proto = *is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
      *fib_index = fib_table_find (fib_proto, vrf);
    }

  return tuple_is_set;
}

uword
unformat_session_state (unformat_input_t * input, va_list * args)
{
  session_state_t *state = va_arg (*args, session_state_t *);
  u8 *state_vec = 0;
  int rv = 0;

#define _(sym, str)					\
  if (unformat (input, str))				\
    {							\
      *state = SESSION_STATE_ ## sym;			\
      rv = 1;						\
      goto done;					\
    }
  foreach_session_state
#undef _
done:
  vec_free (state_vec);
  return rv;
}

uword
unformat_session (unformat_input_t * input, va_list * args)
{
  session_t **result = va_arg (*args, session_t **);
  u32 lcl_port = 0, rmt_port = 0, fib_index = 0;
  ip46_address_t lcl, rmt;
  session_t *s;
  u8 proto = ~0;
  u8 is_ip4 = 0;

  if (!unformat (input, "%U", unformat_stream_session_id, &proto, &fib_index,
		 &lcl, &rmt, &lcl_port, &rmt_port, &is_ip4))
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

  if (!unformat (input, "%U", unformat_stream_session_id, &fib_index, &proto,
		 &lcl, &rmt, &lcl_port, &rmt_port, &is_ip4))
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

static void
session_cli_show_all_sessions (vlib_main_t * vm, int verbose)
{
  session_main_t *smm = &session_main;
  u32 n_closed, thread_index;
  session_t *pool, *s;

  for (thread_index = 0; thread_index < vec_len (smm->wrk); thread_index++)
    {
      pool = smm->wrk[thread_index].sessions;

      if (!pool_elts (pool))
	{
	  vlib_cli_output (vm, "Thread %d: no sessions", thread_index);
	  continue;
	}

      if (!verbose)
	{
	  vlib_cli_output (vm, "Thread %d: %d sessions", thread_index,
			   pool_elts (pool));
	  continue;
	}

      if (pool_elts (pool) > 50)
	{
	  vlib_cli_output (vm, "Thread %u: %d sessions. Verbose output "
			   "suppressed. For more details use filters.",
			   thread_index, pool_elts (pool));
	  continue;
	}

      if (verbose == 1)
	vlib_cli_output (vm, "%s%-" SESSION_CLI_ID_LEN "s%-"
			 SESSION_CLI_STATE_LEN "s%-10s%-10s",
			 thread_index ? "\n" : "",
			 "Connection", "State", "Rx-f", "Tx-f");

      n_closed = 0;

      /* *INDENT-OFF* */
      pool_foreach (s, pool)  {
        if (s->session_state >= SESSION_STATE_TRANSPORT_DELETED)
          {
            n_closed += 1;
            continue;
          }
        vlib_cli_output (vm, "%U", format_session, s, verbose);
      }
      /* *INDENT-ON* */

      if (!n_closed)
	vlib_cli_output (vm, "Thread %d: active sessions %u", thread_index,
			 pool_elts (pool) - n_closed);
      else
	vlib_cli_output (vm, "Thread %d: active sessions %u closed %u",
			 thread_index, pool_elts (pool) - n_closed, n_closed);
    }
}

static int
session_cli_filter_check (session_t * s, session_state_t * states,
			  transport_proto_t tp)
{
  if (states)
    {
      session_state_t *state;
      vec_foreach (state, states) if (s->session_state == *state)
	goto check_transport;
      return 0;
    }

check_transport:

  if (tp != TRANSPORT_PROTO_INVALID && session_get_transport_proto (s) != tp)
    return 0;

  return 1;
}

static void
session_cli_show_session_filter (vlib_main_t * vm, u32 thread_index,
				 u32 start, u32 end, session_state_t * states,
				 transport_proto_t tp, int verbose)
{
  u8 output_suppressed = 0;
  session_worker_t *wrk;
  session_t *pool, *s;
  u32 count = 0, max_index;
  int i;

  wrk = session_main_get_worker_if_valid (thread_index);
  if (!wrk)
    {
      vlib_cli_output (vm, "invalid thread index %u", thread_index);
      return;
    }

  pool = wrk->sessions;

  if (tp == TRANSPORT_PROTO_INVALID && states == 0 && !verbose
      && (start == 0 && end == ~0))
    {
      vlib_cli_output (vm, "Thread %d: %u sessions", thread_index,
		       pool_elts (pool));
      return;
    }

  max_index = pool_len (pool) ? pool_len (pool) - 1 : 0;
  for (i = start; i <= clib_min (end, max_index); i++)
    {
      if (pool_is_free_index (pool, i))
	continue;

      s = pool_elt_at_index (pool, i);

      if (session_cli_filter_check (s, states, tp))
	{
	  count += 1;
	  if (verbose)
	    {
	      if (count > 50 || (verbose > 1 && count > 10))
		{
		  output_suppressed = 1;
		  continue;
		}
	      if (s->session_state < SESSION_STATE_TRANSPORT_DELETED)
		vlib_cli_output (vm, "%U", format_session, s, verbose);
	    }
	}
    }

  if (!output_suppressed)
    vlib_cli_output (vm, "Thread %d: %u sessions matched filter",
		     thread_index, count);
  else
    vlib_cli_output (vm, "Thread %d: %u sessions matched filter. Not all"
		     " shown. Use finer grained filter.", thread_index,
		     count);
}

void
session_cli_show_events_thread (vlib_main_t * vm, u32 thread_index)
{
  session_worker_t *wrk;

  wrk = session_main_get_worker_if_valid (thread_index);
  if (!wrk)
    {
      vlib_cli_output (vm, "invalid thread index %u", thread_index);
      return;
    }

  vlib_cli_output (vm, "Thread %d:\n", thread_index);
  vlib_cli_output (vm, " evt elements alloc: %u",
		   pool_elts (wrk->event_elts));
  vlib_cli_output (vm, " ctrl evt elt data alloc: %d",
		   pool_elts (wrk->ctrl_evts_data));
}

static void
session_cli_show_events (vlib_main_t * vm, u32 thread_index)
{
  session_main_t *smm = &session_main;
  if (!thread_index)
    {
      session_cli_show_events_thread (vm, thread_index);
      return;
    }

  for (thread_index = 0; thread_index < vec_len (smm->wrk); thread_index++)
    session_cli_show_events_thread (vm, thread_index);
}

static void
session_cli_print_session_states (vlib_main_t * vm)
{
#define _(sym, str) vlib_cli_output (vm, str);
  foreach_session_state
#undef _
}

static clib_error_t *
show_session_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  u8 one_session = 0, do_listeners = 0, sst, do_elog = 0, do_filter = 0;
  u32 track_index, thread_index = 0, start = 0, end = ~0, session_index;
  unformat_input_t _line_input, *line_input = &_line_input;
  transport_proto_t transport_proto = TRANSPORT_PROTO_INVALID;
  session_state_t state = SESSION_N_STATES, *states = 0;
  session_main_t *smm = &session_main;
  clib_error_t *error = 0;
  app_worker_t *app_wrk;
  u32 transport_index;
  const u8 *app_name;
  u8 do_events = 0;
  int verbose = 0;
  session_t *s;

  session_cli_return_if_not_enabled ();

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      session_cli_show_all_sessions (vm, 0);
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "verbose %d", &verbose))
	;
      else if (unformat (line_input, "verbose"))
	verbose = 1;
      else if (unformat (line_input, "listeners %U", unformat_transport_proto,
			 &transport_proto))
	do_listeners = 1;
      else if (unformat (line_input, "%U", unformat_session, &s))
	{
	  one_session = 1;
	}
      else if (unformat (line_input, "thread %u index %u", &thread_index,
			 &session_index))
	{
	  s = session_get_if_valid (session_index, thread_index);
	  if (!s)
	    {
	      vlib_cli_output (vm, "session is not allocated");
	      goto done;
	    }
	  one_session = 1;
	}
      else if (unformat (line_input, "thread %u", &thread_index))
	{
	  do_filter = 1;
	}
      else
	if (unformat (line_input, "state %U", unformat_session_state, &state))
	{
	  vec_add1 (states, state);
	  do_filter = 1;
	}
      else if (unformat (line_input, "proto %U index %u",
			 unformat_transport_proto, &transport_proto,
			 &transport_index))
	{
	  transport_connection_t *tc;
	  tc = transport_get_connection (transport_proto, transport_index,
					 thread_index);
	  if (!tc)
	    {
	      vlib_cli_output (vm, "transport connection %u thread %u is not"
			       " allocated", transport_index, thread_index);
	      goto done;
	    }
	  s = session_get_if_valid (tc->s_index, thread_index);
	  if (!s)
	    {
	      vlib_cli_output (vm, "session for transport connection %u "
			       "thread %u does not exist", transport_index,
			       thread_index);
	      goto done;
	    }
	  one_session = 1;
	}
      else if (unformat (line_input, "proto %U", unformat_transport_proto,
			 &transport_proto))
	do_filter = 1;
      else if (unformat (line_input, "range %u %u", &start, &end))
	do_filter = 1;
      else if (unformat (line_input, "range %u", &start))
	{
	  end = start + 50;
	  do_filter = 1;
	}
      else if (unformat (line_input, "elog"))
	do_elog = 1;
      else if (unformat (line_input, "protos"))
	{
	  vlib_cli_output (vm, "%U", format_transport_protos);
	  goto done;
	}
      else if (unformat (line_input, "states"))
	{
	  session_cli_print_session_states (vm);
	  goto done;
	}
      else if (unformat (line_input, "events"))
	do_events = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (one_session)
    {
      u8 *str = format (0, "%U", format_session, s, 3);
      if (do_elog && s->session_state != SESSION_STATE_LISTENING)
	{
	  elog_main_t *em = &vlib_global_main.elog_main;
	  transport_connection_t *tc;
	  f64 dt;

	  tc = session_get_transport (s);
	  track_index = transport_elog_track_index (tc);
	  dt = (em->init_time.cpu - vm->clib_time.init_cpu_time)
	    * vm->clib_time.seconds_per_clock;
	  if (track_index != ~0)
	    str = format (str, " session elog:\n%U", format_elog_track, em,
			  dt, track_index);
	}
      vlib_cli_output (vm, "%v", str);
      vec_free (str);
      goto done;
    }

  if (do_listeners)
    {
      sst = session_type_from_proto_and_ip (transport_proto, 1);
      vlib_cli_output (vm, "%-" SESSION_CLI_ID_LEN "s%-24s", "Listener",
		       "App");

      /* *INDENT-OFF* */
      pool_foreach (s, smm->wrk[0].sessions)  {
	if (s->session_state != SESSION_STATE_LISTENING
	    || s->session_type != sst)
	  continue;
	app_wrk = app_worker_get (s->app_wrk_index);
	app_name = application_name_from_index (app_wrk->app_index);
	vlib_cli_output (vm, "%U%-25v%", format_session, s, 0,
			 app_name);
      }
      /* *INDENT-ON* */
      goto done;
    }

  if (do_events)
    {
      session_cli_show_events (vm, thread_index);
      goto done;
    }

  if (do_filter)
    {
      if (end < start)
	{
	  error = clib_error_return (0, "invalid range start: %u end: %u",
				     start, end);
	  goto done;
	}
      session_cli_show_session_filter (vm, thread_index, start, end, states,
				       transport_proto, verbose);
      goto done;
    }

  session_cli_show_all_sessions (vm, verbose);

done:
  unformat_free (line_input);
  vec_free (states);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_show_session_command) =
{
  .path = "show session",
  .short_help = "show session [verbose [n]] [listeners <proto>] "
		"[<session-id> [elog]] [thread <n> [index <n>] "
		"[proto <proto>] [state <state>] [range <min> [<max>]] "
		"[protos] [states] ",
  .function = show_session_command_fn,
};
/* *INDENT-ON* */

static int
clear_session (session_t * s)
{
  app_worker_t *server_wrk = app_worker_get (s->app_wrk_index);
  app_worker_close_notify (server_wrk, s);
  return 0;
}

static clib_error_t *
clear_session_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  session_main_t *smm = &session_main;
  u32 thread_index = 0, clear_all = 0;
  session_worker_t *wrk;
  u32 session_index = ~0;
  session_t *session;

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
      vec_foreach (wrk, smm->wrk)
	{
	  pool_foreach (session, wrk->sessions)  {
	    clear_session (session);
	  }
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
  session_t *s = 0;
  u8 is_rx = 0, *str = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_session, &s))
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
    svm_fifo_dump_trace (str, s->rx_fifo) :
    svm_fifo_dump_trace (str, s->tx_fifo);

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
  session_t *s = 0;
  u8 is_rx = 0, *str = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_session, &s))
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
    svm_fifo_replay (str, s->rx_fifo, 0, 1) :
    svm_fifo_replay (str, s->tx_fifo, 0, 1);

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
    return clib_error_return (0, "expected enable | disable");

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
