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
  s = format (s, " Rx fifo: %U", format_svm_fifo, ss->server_rx_fifo, 1);
  s = format (s, " Tx fifo: %U", format_svm_fifo, ss->server_tx_fifo, 1);
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
  tp_vft = session_get_transport_vft (ss->session_type);

  if (verbose == 1)
    str = format (0, "%-10u%-10u%-10lld",
		  svm_fifo_max_dequeue (ss->server_rx_fifo),
		  svm_fifo_max_enqueue (ss->server_tx_fifo),
		  stream_session_get_index (ss));

  if (ss->session_state == SESSION_STATE_READY
      || ss->session_state == SESSION_STATE_ACCEPTING)
    {
      s = format (s, "%U", tp_vft->format_connection, ss->connection_index,
		  ss->thread_index, verbose);
      if (verbose == 1)
	s = format (s, "%v", str);
      if (verbose > 1)
	s = format (s, "%U", format_stream_session_fifos, ss);
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
  else if (ss->session_state == SESSION_STATE_CLOSED)
    {
      s =
	format (s, "[CL] %U", tp_vft->format_connection, ss->connection_index,
		ss->thread_index, verbose);
      if (verbose == 1)
	s = format (s, "%v", str);
      if (verbose > 1)
	s = format (s, "%U", format_stream_session_fifos, ss);
    }
  else
    {
      clib_warning ("Session in state: %d!", ss->session_state);
    }

  vec_free (str);

  return s;
}

static clib_error_t *
show_session_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  session_manager_main_t *smm = &session_manager_main;
  int verbose = 0, i;
  stream_session_t *pool;
  stream_session_t *s;
  u8 *str = 0, one_session = 0, proto_set = 0, proto = 0;
  u8 is_ip4 = 0, s_type = 0;
  ip4_address_t lcl_ip4, rmt_ip4;
  u32 lcl_port = 0, rmt_port = 0;

  memset (&lcl_ip4, 0, sizeof (lcl_ip4));
  memset (&rmt_ip4, 0, sizeof (rmt_ip4));

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
      else if (unformat (input, "tcp"))
	{
	  proto_set = 1;
	  proto = TRANSPORT_PROTO_TCP;
	}
      else if (unformat (input, "%U:%d->%U:%d",
			 unformat_ip4_address, &lcl_ip4, &lcl_port,
			 unformat_ip4_address, &rmt_ip4, &rmt_port))
	{
	  one_session = 1;
	  is_ip4 = 1;
	}

      else
	break;
    }

  if (one_session)
    {
      if (!proto_set)
	{
	  vlib_cli_output (vm, "proto not set");
	  return clib_error_return (0, "proto not set");
	}

      s_type = session_type_from_proto_and_ip (proto, is_ip4);
      s = stream_session_lookup4 (&lcl_ip4, &rmt_ip4,
				  clib_host_to_net_u16 (lcl_port),
				  clib_host_to_net_u16 (rmt_port), s_type);
      if (s)
	vlib_cli_output (vm, "%U", format_stream_session, s, 2);
      else
	vlib_cli_output (vm, "session does not exist");

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
		  str =
		    format (str, "%-50s%-15s%-10s%-10s%-10s", "Connection",
			    "State", "Rx-f", "Tx-f", "S-idx");
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
VLIB_CLI_COMMAND (show_session_command, static) =
{
  .path = "show session",
  .short_help = "show session [verbose]",
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
      session = stream_session_get_if_valid (session_index, thread_index);
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
session_enable_disable_fn (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  u8 is_en = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	is_en = 1;
      else if (unformat (input, "disable"))
	is_en = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

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
