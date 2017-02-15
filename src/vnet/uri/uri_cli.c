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
#include <vnet/uri/uri.h>

/* types: fifo, tcp4, udp4, tcp6, udp6 */
u8 *
format_bind_table_entry (u8 * s, va_list * args)
{
  uri_bind_table_entry_t * e = va_arg (*args, uri_bind_table_entry_t *);
  int verbose = va_arg (*args, int);

  if (e == 0)
    {
      if (verbose)
        s = format (s, "%-35s%-25s%-20s%-10s%-10s",
                    "URI", "Server", "Segment", "API Client", "Cookie");
      else
        s = format (s, "%-35s%-15s",
                    "URI", "Server");
      return s;
    }

  if (verbose)
    s = format (s, "%-35s%-25s%-20s%-10d%-10d",
                e->bind_name, e->server_name, e->segment_name,
                e->bind_client_index,
                e->accept_cookie);
  else
    s = format (s, "%-35s%-15s", e->bind_name, e->server_name);
  return s;
}

static clib_error_t *
show_uri_command_fn (vlib_main_t * vm, unformat_input_t * input,
                     vlib_cli_command_t * cmd)
{
  uri_main_t *um = &uri_main;
  session_manager_main_t * smm = &session_manager_main;
  uri_bind_table_entry_t * e;
  int do_server = 0;
  int do_session = 0;
  int verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "server"))
        do_server = 1;
      else if (unformat (input, "session"))
        do_session = 1;
      else if (unformat (input, "verbose"))
        verbose = 1;
      else if (unformat (input, "detail"))
        verbose = 2;
      else
        break;
    }

  if (do_server)
    {
      if (pool_elts (um->fifo_bind_table))
        {
          vlib_cli_output (vm, "%U", format_bind_table_entry, 0 /* header */,
                           verbose);
          /* *INDENT-OFF* */
          pool_foreach (e, um->fifo_bind_table,
          ({
            vlib_cli_output (vm, "%U", format_bind_table_entry, e, verbose);
          }));
          /* *INDENT-OFF* */
        }
      else
        vlib_cli_output (vm, "No active server bindings");
    }

  if (do_session)
    {
      int i;
      stream_session_t * pool;
      stream_session_t * s;
      transport_proto_vft_t *tp_vft;
      u8 * str = 0;

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
                      str = format (str, "%-20s%-20s%-10s%-10s%-8s%-20s%-20s%-15s",
                                    "Src", "Dst", "SrcP", "DstP", "Proto",
                                    "Rx fifo", "Tx fifo", "Session Index");
                      vlib_cli_output (vm, "%v", str);
                      vec_reset_length (str);
                      once_per_pool = 0;
                    }

                  /* *INDENT-OFF* */
                  pool_foreach (s, pool,
                  ({
                    str = format (str, "%-20llx%-20llx%-15lld",
                                  s->server_rx_fifo, s->server_tx_fifo,
                                  s - pool);
                    tp_vft = uri_get_transport (s->session_type);
                    vlib_cli_output (vm, "%U%v",
                                     tp_vft->format_connection,
                                     s->connection_index,
                                     s->session_thread_index, str);
                    vec_reset_length(str);
                  }));
                  /* *INDENT-OFF* */
                }
            }
          else
            vlib_cli_output (vm, "Thread %d: no active sessions", i);
        }
      vec_free(str);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_uri_command, static) = {
    .path = "show uri",
    .short_help = "show uri [server|session] [verbose]",
    .function = show_uri_command_fn,
};


static clib_error_t *
clear_uri_session_command_fn (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  session_manager_main_t * smm = &session_manager_main;
  u32 thread_index = 0;
  u32 session_index = ~0;
  stream_session_t * pool, * session;
  application_t * server;

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

  if (thread_index > vec_len(smm->sessions))
    return clib_error_return (0, "thread %d out of range [0-%d]",
                              thread_index, vec_len(smm->sessions));

  pool = smm->sessions[thread_index];

  if (pool_is_free_index (pool, session_index))
    return clib_error_return (0, "session %d not active", session_index);

  session = pool_elt_at_index (pool, session_index);

  server = pool_elt_at_index (smm->applications, session->server_index);

  server->session_clear_callback (smm, server, session);

  return 0;
}

VLIB_CLI_COMMAND (clear_uri_session_command, static) = {
    .path = "clear uri session",
    .short_help = "clear uri session",
    .function = clear_uri_session_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

