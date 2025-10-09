/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/sfdp/sfdp.h>

#include <vlib/vlib.h>

static clib_error_t *
sfdp_set_eviction_sessions_margin_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  u32 eviction_sessions_margin = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u", &eviction_sessions_margin))
	;
      else
	{
	  err = unformat_parse_error (line_input);
	  unformat_free (line_input);
	  return err;
	}
    }
  unformat_free (line_input);

  if (eviction_sessions_margin == ~0)
    {
      return clib_error_return (0, "Missing margin value");
    }
  else if ((err = sfdp_set_eviction_sessions_margin (
	      eviction_sessions_margin)) != NULL)
    {
      return err;
    }

  return 0;
}

VLIB_CLI_COMMAND (set_eviction_sessions_margin, static) = {
  .path = "set sfdp eviction sessions-margin",
  .short_help = "set sfdp eviction sessions-margin <n-sessions>",
  .function = sfdp_set_eviction_sessions_margin_fn
};

static clib_error_t *
test_sfdp_expiry_disable_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  (void) vm;
  (void) input;
  (void) cmd;
  sfdp_enable_disable_expiry_node (true /* is_disable */,
				   false /* skip main*/);
  return NULL;
}

/** Function used to force disable expiry in tests. */
VLIB_CLI_COMMAND (test_sfdp_expiry_disable, static) = {
  .path = "test sfdp expiry disable",
  .short_help = "[TEST ONLY] disable sfdp-expiry node",
  .function = test_sfdp_expiry_disable_fn
};

static clib_error_t *
test_sfdp_expiry_enable_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  (void) vm;
  (void) input;
  (void) cmd;
  sfdp_enable_disable_expiry_node (false /* is_disable */,
				   false /* skip main*/);
  return NULL;
}

/** Function used to enable-back expiry in tests. */
VLIB_CLI_COMMAND (test_sfdp_expiry_enable, static) = {
  .path = "test sfdp expiry enable",
  .short_help = "[TEST ONLY] enable sfdp-expiry node",
  .function = test_sfdp_expiry_enable_fn
};
