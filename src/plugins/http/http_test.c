/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <http/http.h>

static clib_error_t *
test_http_authority_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  u8 *target = 0;
  http_uri_t authority;
  int rv;

  if (!unformat (input, "%v", &target))
    return clib_error_return (0, "error: no input provided");

  rv = http_parse_authority_form_target (target, &authority);
  vec_free (target);
  if (rv)
    return clib_error_return (0, "error: parsing failed");

  target = http_serialize_authority_form_target (&authority);
  vlib_cli_output (vm, "%v", target);
  vec_free (target);

  return 0;
}

VLIB_CLI_COMMAND (test_http_authority_command) = {
  .path = "test http authority-form",
  .short_help = "test dns authority-form",
  .function = test_http_authority_command_fn,
};
