/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief IPv6 DAD Auto-Remove Plugin Implementation
 *
 * This plugin automatically removes IPv6 addresses when they are detected
 * as duplicates by the DAD (Duplicate Address Detection) mechanism.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip6-nd/ip6_dad.h>
#include <vnet/ip/ip6_forward.h>
#include <vpp/app/version.h>

#include "ip6_dad_autoremove.h"

/* Global instance */
ip6_dad_autoremove_main_t ip6_dad_autoremove_main;

/* Logging macros */
#define AUTOREMOVE_DBG(...)  vlib_log_debug (ip6_dad_autoremove_main.log_class, __VA_ARGS__)
#define AUTOREMOVE_INFO(...) vlib_log_notice (ip6_dad_autoremove_main.log_class, __VA_ARGS__)
#define AUTOREMOVE_ERR(...)  vlib_log_err (ip6_dad_autoremove_main.log_class, __VA_ARGS__)

/**
 * Callback invoked when duplicate address is detected
 * Called on main thread by DAD core
 */
static void
ip6_dad_autoremove_duplicate_callback (u32 sw_if_index, const ip6_address_t *address,
				       u8 address_length)
{
  ip6_dad_autoremove_main_t *pm = &ip6_dad_autoremove_main;
  vlib_main_t *vm = pm->vlib_main;
  clib_error_t *error;

  AUTOREMOVE_INFO ("Duplicate detected: %U/%u on sw_if_index %u", format_ip6_address, address,
		   address_length, sw_if_index);

  /* Remove the duplicate address from the interface */
  error = ip6_add_del_interface_address (vm, sw_if_index, (ip6_address_t *) address, address_length,
					 1 /* is_del */);

  if (error)
    {
      AUTOREMOVE_ERR ("Failed to remove duplicate address %U/%u on sw_if_index %u: %v",
		      format_ip6_address, address, address_length, sw_if_index, error);
      clib_error_free (error);
    }
  else
    {
      AUTOREMOVE_INFO ("Auto-removed duplicate address %U/%u from sw_if_index %u",
		       format_ip6_address, address, address_length, sw_if_index);
    }
}

/**
 * Enable the auto-remove plugin
 */
clib_error_t *
ip6_dad_autoremove_enable (void)
{
  ip6_dad_autoremove_main_t *pm = &ip6_dad_autoremove_main;

  /* Check if already enabled */
  if (pm->enabled)
    return clib_error_return (0, "IPv6 DAD auto-remove already enabled");

  /* Ensure DAD is enabled */
  bool dad_enabled;
  u8 transmits;
  f64 delay;
  ip6_dad_get_config (&dad_enabled, &transmits, &delay);

  if (!dad_enabled)
    {
      AUTOREMOVE_INFO ("Enabling DAD to support auto-remove");
      ip6_dad_enable_disable (true);
    }

  /* Register callback with DAD core */
  pm->callback_handle = ip6_dad_register_duplicate_callback (ip6_dad_autoremove_duplicate_callback);

  if (pm->callback_handle == 0)
    return clib_error_return (0, "Failed to register duplicate callback");

  pm->enabled = true;
  AUTOREMOVE_INFO ("IPv6 DAD auto-remove enabled");

  return NULL;
}

/**
 * Disable the auto-remove plugin
 */
clib_error_t *
ip6_dad_autoremove_disable (void)
{
  ip6_dad_autoremove_main_t *pm = &ip6_dad_autoremove_main;

  /* Check if already disabled */
  if (!pm->enabled)
    return clib_error_return (0, "IPv6 DAD auto-remove already disabled");

  /* Unregister callback */
  if (pm->callback_handle != 0)
    {
      ip6_dad_unregister_duplicate_callback (pm->callback_handle);
      pm->callback_handle = 0;
    }

  pm->enabled = false;

  /* NOTE: We do NOT disable DAD here, as other features may be using it */

  AUTOREMOVE_INFO ("IPv6 DAD auto-remove disabled");

  return NULL;
}

/**
 * CLI command: set ip6 dad autoremove enable
 */
static clib_error_t *
ip6_dad_autoremove_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  return ip6_dad_autoremove_enable ();
}

/**
 * CLI command: set ip6 dad autoremove disable
 */
static clib_error_t *
ip6_dad_autoremove_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  return ip6_dad_autoremove_disable ();
}

/**
 * CLI command: show ip6 dad autoremove
 */
static clib_error_t *
ip6_dad_autoremove_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  ip6_dad_autoremove_main_t *pm = &ip6_dad_autoremove_main;

  vlib_cli_output (vm, "IPv6 DAD Auto-Remove Status:");
  vlib_cli_output (vm, "  Enabled: %s", pm->enabled ? "yes" : "no");

  if (pm->enabled)
    {
      vlib_cli_output (vm, "  Callback handle: %u", pm->callback_handle);
    }

  /* Show DAD status */
  bool dad_enabled;
  u8 transmits;
  f64 delay;
  ip6_dad_get_config (&dad_enabled, &transmits, &delay);

  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "DAD Status:");
  vlib_cli_output (vm, "  Enabled: %s", dad_enabled ? "yes" : "no");
  vlib_cli_output (vm, "  Transmits: %u", transmits);
  vlib_cli_output (vm, "  Delay: %.1f seconds", delay);

  return NULL;
}

/* Register CLI commands */
VLIB_CLI_COMMAND (ip6_dad_autoremove_enable_command, static) = {
  .path = "set ip6 dad autoremove enable",
  .short_help = "set ip6 dad autoremove enable",
  .function = ip6_dad_autoremove_enable_command_fn,
};

VLIB_CLI_COMMAND (ip6_dad_autoremove_disable_command, static) = {
  .path = "set ip6 dad autoremove disable",
  .short_help = "set ip6 dad autoremove disable",
  .function = ip6_dad_autoremove_disable_command_fn,
};

VLIB_CLI_COMMAND (ip6_dad_autoremove_show_command, static) = {
  .path = "show ip6 dad autoremove",
  .short_help = "show ip6 dad autoremove status",
  .function = ip6_dad_autoremove_show_command_fn,
};

/**
 * Plugin initialization
 */
static clib_error_t *
ip6_dad_autoremove_init (vlib_main_t *vm)
{
  ip6_dad_autoremove_main_t *pm = &ip6_dad_autoremove_main;

  /* Initialize main structure */
  clib_memset (pm, 0, sizeof (*pm));

  pm->vlib_main = vm;
  pm->vnet_main = vnet_get_main ();
  pm->enabled = false;
  pm->callback_handle = 0;

  /* Register logging class */
  pm->log_class = vlib_log_register_class ("ip6", "dad-autoremove");

  AUTOREMOVE_INFO ("IPv6 DAD auto-remove plugin initialized (disabled by default)");

  return NULL;
}

VLIB_INIT_FUNCTION (ip6_dad_autoremove_init);

/* Plugin registration */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "IPv6 DAD Duplicate Address Auto-Remove",
};
