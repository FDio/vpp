/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>

typedef struct
{
  u32 app_index;
  session_endpoint_cfg_t proxy_server;
} proxy_client_main_t;

proxy_client_main_t proxy_client_main;

static clib_error_t *
proxy_client_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  clib_error_t *err = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *server_uri = 0;
  session_error_t rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "server-uri %s", &server_uri))
	;
    }

  if (!server_uri)
    {
      err = clib_error_return (0, "server-uri not provided");
      goto done;
    }
  if ((rv = parse_uri ((char *) server_uri, &pcm->proxy_server)))
    {
      err = clib_error_return (0, "server-uri parse error: %U",
			       format_session_error, rv);
      goto done;
    }

done:
  vec_free (server_uri);
  return err;
}

VLIB_CLI_COMMAND (proxy_client_command, static) = {
  .path = "test proxy client",
  .short_help = "server-uri <scheme://ip:port>",
  .function = proxy_client_command_fn,
};

clib_error_t *
proxy_client_main_init (vlib_main_t *vm)
{
  proxy_client_main_t *pcm = &proxy_client_main;
  session_endpoint_cfg_t sep_null = SESSION_ENDPOINT_CFG_NULL;

  pcm->app_index = APP_INVALID_INDEX;
  pcm->proxy_server = sep_null;
  return 0;
}

VLIB_INIT_FUNCTION (proxy_client_main_init);
