/*
 * Copyright (c) 2025 Internet Mastering & Company, Inc.
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

/**
 * @file tor_client_cli.c
 * @brief CLI commands for Tor client
 */

#include <tor_client/tor_client.h>

/**
 * @brief CLI command: tor client enable/disable
 *
 * Usage:
 *   tor client enable [port <port>]
 *   tor client disable
 */
static clib_error_t *
tor_client_enable_disable_command_fn(vlib_main_t *vm,
                                      unformat_input_t *input,
                                      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 enable = 0;
  u16 port = 0;
  clib_error_t *error = 0;

  if (!unformat_user(input, unformat_line_input, line_input))
    return clib_error_return(0, "expected 'enable' or 'disable'");

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat(line_input, "enable"))
        enable = 1;
      else if (unformat(line_input, "disable"))
        enable = 0;
      else if (unformat(line_input, "port %u", &port))
        ;
      else
        {
          error = clib_error_return(0, "unknown input '%U'",
                                    format_unformat_error, line_input);
          goto done;
        }
    }

  error = tor_client_enable_disable(enable, port);

done:
  unformat_free(line_input);
  return error;
}

VLIB_CLI_COMMAND(tor_client_enable_disable_command, static) = {
  .path = "tor client",
  .short_help = "tor client <enable [port <port>] | disable>",
  .function = tor_client_enable_disable_command_fn,
};

/**
 * @brief CLI command: show tor status
 */
static clib_error_t *
show_tor_status_command_fn(vlib_main_t *vm,
                            unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
  u8 *s = 0;

  s = format_tor_client_stats(s, 0);
  vlib_cli_output(vm, "%v", s);
  vec_free(s);

  return 0;
}

VLIB_CLI_COMMAND(show_tor_status_command, static) = {
  .path = "show tor status",
  .short_help = "show tor status",
  .function = show_tor_status_command_fn,
};

/**
 * @brief CLI command: show tor streams
 */
static clib_error_t *
show_tor_streams_command_fn(vlib_main_t *vm,
                              unformat_input_t *input,
                              vlib_cli_command_t *cmd)
{
  tor_client_main_t *tcm = &tor_client_main;
  tor_stream_t *stream;

  if (!tcm->config.enabled)
    {
      vlib_cli_output(vm, "Tor client is not enabled");
      return 0;
    }

  vlib_cli_output(vm, "Active Tor Streams: %u\n", tcm->active_streams);

  if (tcm->active_streams == 0)
    {
      vlib_cli_output(vm, "  (none)");
      return 0;
    }

  vlib_cli_output(vm, "%-6s %-21s %-10s %-15s %-15s",
                  "Index", "Destination", "Age", "TX Bytes", "RX Bytes");
  vlib_cli_output(vm, "%-6s %-21s %-10s %-15s %-15s",
                  "------", "---------------------", "----------",
                  "---------------", "---------------");

  pool_foreach(stream, tcm->stream_pool)
    {
      u32 stream_index = stream - tcm->stream_pool;
      f64 age = vlib_time_now(vm) - stream->created_at;

      vlib_cli_output(vm, "%-6u port %-14u %-10.1fs %-15llu %-15llu",
                      stream_index, stream->dst_port, age,
                      stream->bytes_sent, stream->bytes_received);
    }

  return 0;
}

VLIB_CLI_COMMAND(show_tor_streams_command, static) = {
  .path = "show tor streams",
  .short_help = "show tor streams",
  .function = show_tor_streams_command_fn,
};

/**
 * @brief CLI command: test tor connection
 *
 * Usage:
 *   test tor connect <hostname> <port>
 */
static clib_error_t *
test_tor_connect_command_fn(vlib_main_t *vm,
                             unformat_input_t *input,
                             vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *hostname = 0;
  u16 port = 0;
  u32 stream_index;
  clib_error_t *error = 0;

  if (!unformat_user(input, unformat_line_input, line_input))
    return clib_error_return(0, "expected connect <hostname> <port>");

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat(line_input, "connect"))
        ;
      else if (unformat(line_input, "%s", &hostname))
        ;
      else if (unformat(line_input, "%u", &port))
        ;
      else
        {
          error = clib_error_return(0, "unknown input '%U'",
                                    format_unformat_error, line_input);
          goto done;
        }
    }

  if (!hostname || port == 0)
    {
      error = clib_error_return(0, "usage: test tor connect <hostname> <port>");
      goto done;
    }

  vlib_cli_output(vm, "Connecting to %s:%u through Tor...", hostname, port);

  error = tor_client_stream_create((char *)hostname, port, &stream_index);

  if (!error)
    {
      vlib_cli_output(vm, "Success! Stream index: %u", stream_index);
      vlib_cli_output(vm, "Use 'show tor streams' to see details");
      vlib_cli_output(vm, "Note: Stream will remain open until explicitly closed");
    }

done:
  if (hostname)
    vec_free(hostname);
  unformat_free(line_input);
  return error;
}

VLIB_CLI_COMMAND(test_tor_connect_command, static) = {
  .path = "test tor connect",
  .short_help = "test tor connect <hostname> <port>",
  .function = test_tor_connect_command_fn,
};
