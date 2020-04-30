/*
 * pfuzz.c - awkward chained buffer geometry test tool
 *
 * Copyright (c) 2019 by Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <pfuzz/pfuzz.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

/* define message IDs */
#include <pfuzz/pfuzz.api_enum.h>
#include <pfuzz/pfuzz.api_types.h>

#define REPLY_MSG_ID_BASE pm->msg_id_base
#include <vlibapi/api_helper_macros.h>

pfuzz_main_t pfuzz_main;

/* Action function shared between message handler and debug CLI */

int
pfuzz_enable_disable (pfuzz_main_t * pm, u32 sw_if_index, int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (pm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (pm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("device-input", "pfuzz",
			       sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
pfuzz_enable_disable_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  pfuzz_main_t *pm = &pfuzz_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 pm->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = pfuzz_enable_disable (pm, sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "pfuzz_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pfuzz_enable_disable_command, static) =
{
  .path = "pfuzz enable-disable",
  .short_help =
  "pfuzz enable-disable <interface-name> [disable]",
  .function = pfuzz_enable_disable_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_pfuzz_enable_disable_t_handler
  (vl_api_pfuzz_enable_disable_t * mp)
{
  vl_api_pfuzz_enable_disable_reply_t *rmp;
  pfuzz_main_t *pm = &pfuzz_main;
  u32 sw_if_index;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  rv = pfuzz_enable_disable (pm, sw_if_index, (int) (mp->enable_disable));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_PFUZZ_ENABLE_DISABLE_REPLY);
}

#include <pfuzz/pfuzz.api.c>
static clib_error_t *
pfuzz_init (vlib_main_t * vm)
{
  pfuzz_main_t *pm = &pfuzz_main;
  clib_error_t *error = 0;

  pm->vlib_main = vm;
  pm->vnet_main = vnet_get_main ();

  /* Ask for a correctly-sized block of API message decode slots */
  pm->msg_id_base = setup_message_id_table ();

  /* Basic setup */
  pm->seed = 0xdeaddabe;
  pm->mode = PFUZZ_MODE_HEADER;

  return error;
}

VLIB_INIT_FUNCTION (pfuzz_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (pfuzz, static) =
{
  .arc_name = "device-input",
  .node_name = "pfuzz",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Packet Fuzzer",
  .default_disabled = 1,
};
/* *INDENT-ON* */


static uword
unformat_pfuzz_mode (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);

#define _(n,s) if (unformat (input, s)) {*result = PFUZZ_MODE_##n; return 1;}
  foreach_pfuzz_mode;
#undef _
  return 0;
}

static clib_error_t *
pfuzz_config_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  pfuzz_main_t *pm = &pfuzz_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "seed %u", &pm->seed))
	;
      else if (unformat (line_input, "mode %U",
			 unformat_pfuzz_mode, &pm->mode))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }

  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pfuzz_config_command, static) =
{
  .path = "pfuzz configure",
  .short_help =
  "pfuzz configure [mode header|body] [seed nnn]",
  .function = pfuzz_config_command_fn,
};
/* *INDENT-ON* */



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
