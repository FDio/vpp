/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/cli.h>
#include <vnet/interface.h>
#include <vnet/interface/cli_types.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/vec.h>
#include <soft-rss/soft_rss.h>

static const cli_choice_t soft_rss_type_choices[] = {
#define _(sym, str) { str, 0, SOFT_RSS_TYPE_##sym },
  foreach_soft_rss_type
#undef _
  {},
};

static clib_error_t *
soft_rss_config_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  soft_rss_config_t cfg = {
    .type = cli_u64 (ctx, "type", 0),
    .ipv4_type = cli_u64 (ctx, "ipv4-type", 0),
    .ipv6_type = cli_u64 (ctx, "ipv6-type", 0),
    .l2_hdr_offset = cli_u64 (ctx, "l2-offset", 0),
    .handoff_queue_size = cli_u64 (ctx, "handoff-queue-size", 0),
    .with_main_thread = cli_flag (ctx, "with-main-thread"),
  };
  cli_value_t *v;
  clib_error_t *err;

  if ((v = cli_get (ctx, "threads")))
    cfg.threads = clib_bitmap_dup ((uword *) v->str);
  if ((v = cli_get (ctx, "rss-key")))
    {
      if (vec_len (v->str) < 8)
	{
	  clib_bitmap_free (cfg.threads);
	  return clib_error_return (0, "rss-key must be at least 8 bytes");
	}
      cfg.key = vec_dup (v->str);
    }

  err = soft_rss_config (vm, &cfg, cli_index (ctx, "interface"));

  clib_bitmap_free (cfg.threads);
  vec_free (cfg.key);
  return err;
}

static clib_error_t *
soft_rss_enable_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return soft_rss_enable (vm, cli_index (ctx, "interface"));
}

static clib_error_t *
soft_rss_disable_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return soft_rss_disable (vm, cli_index (ctx, "interface"));
}

static clib_error_t *
soft_rss_clear_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return soft_rss_clear (vm, cli_index (ctx, "interface"));
}

static clib_error_t *
soft_rss_show_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = cli_index (ctx, "interface");

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
  .short_help = "Configure software RSS on an interface",
  .args = CLI_ARGS (
    CLI_VALUE ("interface", cli_type_hw_interface),
    CLI_OPT_KEYWORD ("type", cli_type_enum, .choices = soft_rss_type_choices, .help = "hash type"),
    CLI_OPT_KEYWORD ("ipv4-type", cli_type_enum, .choices = soft_rss_type_choices,
		     .help = "hash type for IPv4"),
    CLI_OPT_KEYWORD ("ipv6-type", cli_type_enum, .choices = soft_rss_type_choices,
		     .help = "hash type for IPv6"),
    CLI_OPT_KEYWORD ("l2-offset", cli_type_u32, .help = "bytes to skip before the L2 header"),
    CLI_OPT_KEYWORD ("threads", cli_type_bitmap, .help = "threads which receive the packets"),
    CLI_OPT_KEYWORD ("handoff-queue-size", cli_type_u32),
    CLI_OPT_KEYWORD ("rss-key", cli_type_hex, .help = "hash key, at least 8 bytes"),
    CLI_FLAG ("with-main-thread", .help = "main thread is one of the threads")),
  .handler = soft_rss_config_command_fn,
};

VLIB_CLI_COMMAND (soft_rss_enable_command, static) = {
  .path = "soft-rss enable",
  .short_help = "Enable software RSS on an interface",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_hw_interface)),
  .handler = soft_rss_enable_command_fn,
};

VLIB_CLI_COMMAND (soft_rss_disable_command, static) = {
  .path = "soft-rss disable",
  .short_help = "Disable software RSS on an interface",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_hw_interface)),
  .handler = soft_rss_disable_command_fn,
};

VLIB_CLI_COMMAND (soft_rss_clear_command, static) = {
  .path = "soft-rss clear",
  .short_help = "Clear the software RSS configuration of an interface",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_hw_interface)),
  .handler = soft_rss_clear_command_fn,
};

VLIB_CLI_COMMAND (soft_rss_show_command, static) = {
  .path = "show soft-rss",
  .short_help = "Show the software RSS configuration",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_sw_interface, .flags = CLI_F_OPTIONAL)),
  .handler = soft_rss_show_command_fn,
  .is_mp_safe = 1,
};
