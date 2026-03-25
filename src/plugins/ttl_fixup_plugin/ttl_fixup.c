/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

/*
 * ttl_fixup.c - TTL/Hop-Limit fixup plugin
 *
 * Two-phase TTL preservation for transparent host traffic forwarding:
 *
 * Phase 1 (input, on source interfaces): Mark incoming packets with
 *   VNET_BUFFER_F_LOCALLY_ORIGINATED flag so ip4/ip6-rewrite skips
 *   TTL decrement. This is essential for TTL=1 protocols.
 *
 * Phase 2 (output, on destination interfaces): Decrement TTL/hop-limit
 *   post-rewrite for packets that originated from a source interface.
 *   This restores normal router-hop behaviour for traffic which does
 *   not require transparent forwarding.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ttl_fixup_plugin/ttl_fixup.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

#include <ttl_fixup_plugin/ttl_fixup.api_enum.h>
#include <ttl_fixup_plugin/ttl_fixup.api_types.h>

#include <vnet/format_fns.h>

#define REPLY_MSG_ID_BASE tfm->msg_id_base
#include <vlibapi/api_helper_macros.h>

ttl_fixup_main_t ttl_fixup_main;

typedef struct
{
  const char *arc_name;
  const char *node_name;
} ttl_fixup_feature_t;

static const ttl_fixup_feature_t ttl_fixup_input_features[] = {
  { "ip4-unicast", "ttl-fixup-ip4-in" },
  { "ip6-unicast", "ttl-fixup-ip6-in" },
  { "ip4-multicast", "ttl-fixup-ip4-mcast-in" },
  { "ip6-multicast", "ttl-fixup-ip6-mcast-in" },
};

static const ttl_fixup_feature_t ttl_fixup_output_features[] = {
  { "ip4-output", "ttl-fixup-ip4-out" },
  { "ip6-output", "ttl-fixup-ip6-out" },
};

/*
 * Enable/disable a set of feature arcs and rollback on error so
 * per-interface state does not diverge from dataplane feature graph state.
 */
static int
ttl_fixup_toggle_feature_set (const ttl_fixup_feature_t *features, uword n_features,
			      u32 sw_if_index, int enable_disable)
{
  uword i;
  int rv;

  for (i = 0; i < n_features; i++)
    {
      rv = vnet_feature_enable_disable (features[i].arc_name, features[i].node_name, sw_if_index,
					enable_disable, 0, 0);
      if (rv)
	goto rollback;
    }

  return 0;

rollback:
  while (i > 0)
    {
      i--;
      (void) vnet_feature_enable_disable (features[i].arc_name, features[i].node_name, sw_if_index,
					  !enable_disable, 0, 0);
    }

  return rv;
}

/* Enable/disable input features on a source interface. */
static int
ttl_fixup_input_enable_disable (u32 sw_if_index, int enable_disable)
{
  ttl_fixup_main_t *tfm = &ttl_fixup_main;
  vnet_sw_interface_t *sw;
  int rv;
  u8 new_state;

  if (pool_is_free_index (tfm->vnet_main->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  sw = vnet_get_sw_interface (tfm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vec_validate_init_empty (tfm->input_enabled, sw_if_index, 0);
  new_state = enable_disable ? 1 : 0;

  if (tfm->input_enabled[sw_if_index] == new_state)
    return 0;

  rv = ttl_fixup_toggle_feature_set (ttl_fixup_input_features, ARRAY_LEN (ttl_fixup_input_features),
				     sw_if_index, new_state);
  if (rv)
    return rv;

  tfm->input_enabled[sw_if_index] = new_state;

  return 0;
}

/* Enable/disable output features on a destination interface. */
static int
ttl_fixup_output_enable_disable (u32 sw_if_index, int enable_disable)
{
  ttl_fixup_main_t *tfm = &ttl_fixup_main;
  vnet_sw_interface_t *sw;
  int rv;
  u8 new_state;

  if (pool_is_free_index (tfm->vnet_main->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  sw = vnet_get_sw_interface (tfm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vec_validate_init_empty (tfm->output_enabled, sw_if_index, 0);
  new_state = enable_disable ? 1 : 0;

  if (tfm->output_enabled[sw_if_index] == new_state)
    return 0;

  rv = ttl_fixup_toggle_feature_set (ttl_fixup_output_features,
				     ARRAY_LEN (ttl_fixup_output_features), sw_if_index, new_state);
  if (rv)
    return rv;

  tfm->output_enabled[sw_if_index] = new_state;

  return 0;
}

static clib_error_t *
ttl_fixup_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  ttl_fixup_main_t *tfm = &ttl_fixup_main;

  if (is_add)
    return 0;

  if (sw_if_index < vec_len (tfm->input_enabled) && tfm->input_enabled[sw_if_index])
    {
      (void) ttl_fixup_toggle_feature_set (ttl_fixup_input_features,
					   ARRAY_LEN (ttl_fixup_input_features), sw_if_index, 0);
      tfm->input_enabled[sw_if_index] = 0;
    }
  if (sw_if_index < vec_len (tfm->output_enabled) && tfm->output_enabled[sw_if_index])
    {
      (void) ttl_fixup_toggle_feature_set (ttl_fixup_output_features,
					   ARRAY_LEN (ttl_fixup_output_features), sw_if_index, 0);
      tfm->output_enabled[sw_if_index] = 0;
    }

  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ttl_fixup_sw_interface_add_del);

/* API message handlers */
static void
vl_api_ttl_fixup_input_enable_disable_t_handler (vl_api_ttl_fixup_input_enable_disable_t *mp)
{
  ttl_fixup_main_t *tfm = &ttl_fixup_main;
  vl_api_ttl_fixup_input_enable_disable_reply_t *rmp;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  rv = ttl_fixup_input_enable_disable (ntohl (mp->sw_if_index), mp->enable);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_TTL_FIXUP_INPUT_ENABLE_DISABLE_REPLY);
}

static void
vl_api_ttl_fixup_output_enable_disable_t_handler (vl_api_ttl_fixup_output_enable_disable_t *mp)
{
  ttl_fixup_main_t *tfm = &ttl_fixup_main;
  vl_api_ttl_fixup_output_enable_disable_reply_t *rmp;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  rv = ttl_fixup_output_enable_disable (ntohl (mp->sw_if_index), mp->enable);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_TTL_FIXUP_OUTPUT_ENABLE_DISABLE_REPLY);
}

/* Debug CLI for input feature */
static clib_error_t *
ttl_fixup_input_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
					   vlib_cli_command_t *cmd)
{
  u32 sw_if_index = ~0;
  int enable_disable = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "enable"))
	enable_disable = 1;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, ttl_fixup_main.vnet_main,
			 &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = ttl_fixup_input_enable_disable (sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "Invalid interface, only works on "
				   "hardware interfaces...");
    default:
      return clib_error_return (0, "ttl_fixup_input_enable_disable returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (ttl_fixup_input_enable_disable_command, static) = {
  .path = "ttl fixup input",
  .short_help = "ttl fixup input <interface> [enable|disable]",
  .function = ttl_fixup_input_enable_disable_command_fn,
};

/* Debug CLI for output feature */
static clib_error_t *
ttl_fixup_output_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
					    vlib_cli_command_t *cmd)
{
  u32 sw_if_index = ~0;
  int enable_disable = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "enable"))
	enable_disable = 1;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, ttl_fixup_main.vnet_main,
			 &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = ttl_fixup_output_enable_disable (sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "Invalid interface...");
    default:
      return clib_error_return (0, "ttl_fixup_output_enable_disable returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (ttl_fixup_output_enable_disable_command, static) = {
  .path = "ttl fixup output",
  .short_help = "ttl fixup output <interface> [enable|disable]",
  .function = ttl_fixup_output_enable_disable_command_fn,
};

/* Show CLI */
static clib_error_t *
ttl_fixup_show_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  ttl_fixup_main_t *tfm = &ttl_fixup_main;
  u32 ii;

  vlib_cli_output (vm, "Input (source) interfaces:");
  vec_foreach_index (ii, tfm->input_enabled)
    {
      if (tfm->input_enabled[ii])
	vlib_cli_output (vm, "  %U", format_vnet_sw_if_index_name, tfm->vnet_main, ii);
    }

  vlib_cli_output (vm, "Output (destination) interfaces:");
  vec_foreach_index (ii, tfm->output_enabled)
    {
      if (tfm->output_enabled[ii])
	vlib_cli_output (vm, "  %U", format_vnet_sw_if_index_name, tfm->vnet_main, ii);
    }

  return 0;
}

VLIB_CLI_COMMAND (ttl_fixup_show_command, static) = {
  .path = "show ttl fixup",
  .short_help = "show ttl fixup",
  .function = ttl_fixup_show_command_fn,
};

/* set up API message handling tables */
#include <ttl_fixup_plugin/ttl_fixup.api.c>

static clib_error_t *
ttl_fixup_api_hookup (vlib_main_t *vm)
{
  ttl_fixup_main_t *tfm = &ttl_fixup_main;

  tfm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (ttl_fixup_api_hookup);

static clib_error_t *
ttl_fixup_init (vlib_main_t *vm)
{
  ttl_fixup_main_t *tfm = &ttl_fixup_main;

  tfm->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (ttl_fixup_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "TTL/Hop-Limit fixup for transparent forwarding",
};
