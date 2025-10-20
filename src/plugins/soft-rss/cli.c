/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/cli.h>
#include <vnet/interface.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/vec.h>
#include <soft-rss/soft_rss.h>

static clib_error_t *
soft_rss_config_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = ~0;
  clib_error_t *err = 0;
  soft_rss_config_t cfg = {};

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	;
      else if (unformat (input, "threads %U", unformat_bitmap_list,
			 &cfg.threads))
	;
      else if (unformat (input, "rss-key %U", unformat_hex_string, &cfg.key))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
	  goto done;
	}
    }

  if (hw_if_index == ~0)
    {
      err = clib_error_return (0, "hardware interface required");
      goto done;
    }

  if (cfg.key && vec_len (cfg.key) < 8)
    {
      err = clib_error_return (0, "rss-key must be at least 8 bytes");
      goto done;
    }

  err = soft_rss_config (vm, &cfg, hw_if_index);

done:
  clib_bitmap_free (cfg.threads);
  vec_free (cfg.key);
  return err;
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

static clib_error_t *
soft_rss_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = sm->vnet_main ? sm->vnet_main : vnet_get_main ();
  u32 sw_if_index = ~0;
  u32 hw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	;
      else if (unformat (input, "%U", unformat_vnet_hw_interface, vnm,
			 &hw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (hw_if_index != ~0)
    {
      vnet_hw_interface_t *hi =
	vnet_get_hw_interface_or_null (vnm, hw_if_index);
      if (!hi)
	return clib_error_return (0, "invalid hardware interface %u",
				  hw_if_index);
      sw_if_index = hi->sw_if_index;
    }

  if (sw_if_index != ~0)
    {
      if (sw_if_index >= vec_len (sm->rt_by_sw_if_index) ||
	  sm->rt_by_sw_if_index[sw_if_index] == 0)
	{
	  vlib_cli_output (vm, "soft-rss not configured on interface %U",
			   format_vnet_sw_if_index_name, vnm, sw_if_index);
	  return 0;
	}

      vlib_cli_output (vm, "%U", format_soft_rss_if, vnm, sw_if_index,
		       sm->rt_by_sw_if_index[sw_if_index]);
      return 0;
    }

  u32 printed = 0;
  uword n_entries = vec_len (sm->rt_by_sw_if_index);

  for (uword i = 0; i < n_entries; i++)
    {
      soft_rss_rt_data_t *rt = sm->rt_by_sw_if_index[i];
      if (!rt)
	continue;

      printed++;
      vlib_cli_output (vm, "%U", format_soft_rss_if, vnm, (u32) i, rt);
    }

  if (!printed)
    vlib_cli_output (vm, "soft-rss not configured on any interface");

  return 0;
}

VLIB_CLI_COMMAND (soft_rss_config_command, static) = {
  .path = "soft-rss config",
  .short_help = "soft-rss config <hw-interface> [threads <bitmap-list>] "
		"[rss-key <hex-string>]",
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

VLIB_CLI_COMMAND (soft_rss_show_command, static) = {
  .path = "show soft-rss",
  .short_help = "show soft-rss [<interface>]",
  .function = soft_rss_show_command_fn,
  .is_mp_safe = 1,
};
