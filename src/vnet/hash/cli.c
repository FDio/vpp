/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/hash/hash.h>

static clib_error_t *
show_hash (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  vnet_hash_main_t *hm = &vnet_hash_main;
  vnet_hash_function_registration_t *hash;

  hash = hm->hash_registrations;

  vlib_cli_output (vm, "          NAME                     TYPE               "
		       "          DESCRIPTION\n");
  vlib_cli_output (vm, "========================   ====================    "
		       "======================================\n");
  while (hash)
    {
      vlib_cli_output (vm, "%-25s  %-22U  %-100s\n", hash->name,
		       format_vnet_hash_type, hash->type, hash->description);
      hash = hash->next;
    }

  return (error);
}

VLIB_CLI_COMMAND (cmd_show_hash, static) = {
  .path = "show hash",
  .short_help = "show hash",
  .function = show_hash,
};
