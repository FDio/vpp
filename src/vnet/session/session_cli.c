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

  if (verbose)
    str = format (0, "%-20llp%-20llp%-15lld", ss->server_rx_fifo,
		  ss->server_tx_fifo, stream_session_get_index (ss));

  if (ss->session_state == SESSION_STATE_READY)
    {
      s = format (s, "%-40U%v", tp_vft->format_connection,
		  ss->connection_index, ss->thread_index, str);
    }
  else if (ss->session_state == SESSION_STATE_LISTENING)
    {
      s = format (s, "%-40U%v", tp_vft->format_listener, ss->connection_index,
		  str);
    }
  else if (ss->session_state == SESSION_STATE_READY)
    {
      s =
	format (s, "%-40U%v", tp_vft->format_half_open, ss->connection_index,
		str);
    }
  else if (ss->session_state == SESSION_STATE_CLOSED)
    {
      s = format (s, "[CL] %-40U%v", tp_vft->format_connection,
		  ss->connection_index, ss->thread_index, str);
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
  u8 *str = 0;

  if (!smm->is_enabled)
    {
      clib_error_return (0, "session layer is not enabled");
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	break;
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
	      if (once_per_pool)
		{
		  str = format (str, "%-50s%-20s%-20s%-15s",
				"Connection", "Rx fifo", "Tx fifo",
				"Session Index");
		  vlib_cli_output (vm, "%v", str);
		  vec_reset_length (str);
		  once_per_pool = 0;
		}

              /* *INDENT-OFF* */
              pool_foreach (s, pool,
              ({
                vlib_cli_output (vm, "%U", format_stream_session, s, verbose);
              }));
              /* *INDENT-ON* */
	    }
	}
      else
	vlib_cli_output (vm, "Thread %d: no active sessions", i);
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

static clib_error_t *
clear_session_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  session_manager_main_t *smm = &session_manager_main;
  u32 thread_index = 0;
  u32 session_index = ~0;
  stream_session_t *pool, *session;
  application_t *server;

  if (!smm->is_enabled)
    {
      clib_error_return (0, "session layer is not enabled");
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "thread %d", &thread_index))
	;
      else if (unformat (input, "session %d", &session_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (session_index == ~0)
    return clib_error_return (0, "session <nn> required, but not set.");

  if (thread_index > vec_len (smm->sessions))
    return clib_error_return (0, "thread %d out of range [0-%d]",
			      thread_index, vec_len (smm->sessions));

  pool = smm->sessions[thread_index];

  if (pool_is_free_index (pool, session_index))
    return clib_error_return (0, "session %d not active", session_index);

  session = pool_elt_at_index (pool, session_index);
  server = application_get (session->app_index);

  /* Disconnect both app and transport */
  server->cb_fns.session_disconnect_callback (session);

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
