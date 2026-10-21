/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/l2/l2_input.h>

/* Make dynamic entries stale without scheduling an age scan. This lets
 * tests exercise the packet-before-scanner ordering without a timing race.
 * The CLI's default worker barrier protects the sequence-number update. */
static clib_error_t *
test_l2fib_invalidate (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 sw_if_index;
  vnet_main_t *vnm = vnet_get_main ();

  if (!unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index) ||
      unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected one interface");

  if (sw_if_index >= vec_len (l2input_main.configs))
    return clib_error_return (0, "interface has no L2 configuration");

  l2_input_config_t *config = vec_elt_at_index (l2input_main.configs, sw_if_index);
  if (!l2_input_is_bridge (config))
    return clib_error_return (0, "interface is not in a bridge domain");

  config->seq_num++;
  return 0;
}

VLIB_CLI_COMMAND (test_l2fib_invalidate_cli, static) = {
  .path = "test l2fib invalidate",
  .short_help = "test l2fib invalidate <interface>",
  .function = test_l2fib_invalidate,
};
