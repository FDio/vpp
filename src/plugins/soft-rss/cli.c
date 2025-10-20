/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/cli.h>
#include <vnet/interface.h>
#include <vppinfra/error.h>
#include <soft-rss/soft_rss.h>

static uword
unformat_soft_rss_hash_type (unformat_input_t *input, va_list *args)
{
  soft_rss_hash_type_t *hash_type = va_arg (*args, soft_rss_hash_type_t *);

  if (unformat (input, "crc32"))
    *hash_type = SOFT_RSS_HASH_CRC32;
  else if (unformat (input, "toeplitz"))
    *hash_type = SOFT_RSS_HASH_TOEPLITZ;
  else
    return 0;

  return 1;
}

static clib_error_t *
soft_rss_config_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = ~0;
  soft_rss_hash_type_t hash_type = SOFT_RSS_HASH_UNKNOWN;
  int hash_set = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	;
      else if (unformat (input, "hash %U", unformat_soft_rss_hash_type,
			 &hash_type))
	hash_set = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (hw_if_index == ~0)
    return clib_error_return (0, "hardware interface required");
  if (!hash_set)
    return clib_error_return (0, "hash type required");

  soft_rss_config_t cfg = {
    .hash_type = hash_type,
  };

  return soft_rss_config (vm, &cfg, hw_if_index);
}

static clib_error_t *
soft_rss_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (hw_if_index == ~0)
    return clib_error_return (0, "hardware interface required");

  return soft_rss_enable (vm, hw_if_index);
}

static clib_error_t *
soft_rss_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (hw_if_index == ~0)
    return clib_error_return (0, "hardware interface required");

  return soft_rss_disable (vm, hw_if_index);
}

static clib_error_t *
soft_rss_clear_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (hw_if_index == ~0)
    return clib_error_return (0, "hardware interface required");

  return soft_rss_clear (vm, hw_if_index);
}

VLIB_CLI_COMMAND (soft_rss_config_command, static) = {
  .path = "soft-rss config",
  .short_help = "soft-rss config <hw-interface> hash (crc32|toeplitz)",
  .function = soft_rss_config_command_fn,
};

VLIB_CLI_COMMAND (soft_rss_enable_command, static) = {
  .path = "soft-rss enable",
  .short_help = "soft-rss enable <hw-interface>",
  .function = soft_rss_enable_command_fn,
};

VLIB_CLI_COMMAND (soft_rss_disable_command, static) = {
  .path = "soft-rss disable",
  .short_help = "soft-rss disable <hw-interface>",
  .function = soft_rss_disable_command_fn,
};

VLIB_CLI_COMMAND (soft_rss_clear_command, static) = {
  .path = "soft-rss clear",
  .short_help = "soft-rss clear <hw-interface>",
  .function = soft_rss_clear_command_fn,
};
