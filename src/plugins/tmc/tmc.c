/*
 * tmc.c - skeleton vpp engine plug-in
 *
 * Copyright (c) 2018 Cisco and/or its affiliates
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
#include <tmc/tmc.h>

tmc_main_t tmc_main;

/* Action function shared between message handler and debug CLI */

static void
tmc_enable_disable_feat (u32 sw_if_index, int enable)
{
  vnet_feature_enable_disable ("ip4-unicast", "tcp-mss-clamping-ip4-in",
			       sw_if_index, enable, 0, 0);
  vnet_feature_enable_disable ("ip6-unicast", "tcp-mss-clamping-ip6-in",
			       sw_if_index, enable, 0, 0);
  vnet_feature_enable_disable ("ip4-output", "tcp-mss-clamping-ip4-out",
			       sw_if_index, enable, 0, 0);
  vnet_feature_enable_disable ("ip6-output", "tcp-mss-clamping-ip6-out",
			       sw_if_index, enable, 0, 0);
}

int
tmc_enable (u32 sw_if_index, u16 mss)
{
  tmc_main_t *tm = &tmc_main;
  int rv = 0;

  vec_validate_init_empty (tm->max_mss, sw_if_index, TMC_UNSET);

  if (TMC_UNSET == tm->max_mss[sw_if_index])
    {
      tmc_enable_disable_feat (sw_if_index, 1);
    }

  tm->max_mss[sw_if_index] = mss;

  return rv;
}

int
tmc_disable (u32 sw_if_index)
{
  tmc_main_t *tm = &tmc_main;
  int rv = 0;

  if (sw_if_index >= vec_len (tm->max_mss))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (TMC_UNSET != tm->max_mss[sw_if_index])
    {
      tmc_enable_disable_feat (sw_if_index, 0);
    }
  tm->max_mss[sw_if_index] = TMC_UNSET;

  return rv;
}


static clib_error_t *
tmc_enable_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 mss = ~0, sw_if_index = ~0;
  int rv, is_enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	is_enable = 0;
      else if (unformat (input, "enable"))
	is_enable = 1;
      else if (unformat (input, "mss %d", &mss))
	is_enable = 1;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");
  if (is_enable && mss == ~0)
    return clib_error_return (0, "Please specify the Max Segment Size...");

  if (is_enable)
    rv = tmc_enable (sw_if_index, mss);
  else
    rv = tmc_disable (sw_if_index);

  if (rv)
    return clib_error_return (0, "Failed: %d = %U",
			      rv, format_vnet_api_errno, rv);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tmc_enable_disable_command, static) =
{
  .path = "set interface tcp-mss-clamp",
  .short_help = "set interface tcp-mss-clamp [enable|disable] <interface-name> mss <size>",
  .function = tmc_enable_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
tmc_show_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  tmc_main_t *tm = &tmc_main;
  u32 sw_if_index = ~0;
  u32 ii;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnet_get_main (), &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      vec_foreach_index (ii, tm->max_mss)
      {
	if (TMC_UNSET != tm->max_mss[ii])
	  {
	    u32 mss = tm->max_mss[ii];
	    vlib_cli_output (vm, "%U: %d",
			     format_vnet_sw_if_index_name,
			     vnet_get_main (), ii, mss);
	  }
      }
    }
  else
    {
      if (vec_len (tm->max_mss) > sw_if_index
	  && TMC_UNSET != tm->max_mss[sw_if_index])
	{
	  u32 mss = tm->max_mss[sw_if_index];
	  vlib_cli_output (vm, "%U: %d",
			   format_vnet_sw_if_index_name,
			   vnet_get_main (), sw_if_index, mss);
	}
      else
	{
	  vlib_cli_output (vm, "%U: disabled",
			   format_vnet_sw_if_index_name,
			   vnet_get_main (), sw_if_index);
	}
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tmc_show_command, static) =
{
  .path = "show interface tcp-mss-clamp",
  .short_help = "show interface tcp-mss-clamp [interface-name]",
  .long_help = "show TCP MSS clamping configurations",
  .function = tmc_show_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
tmc_init (vlib_main_t * vm)
{
  return NULL;
}

VLIB_INIT_FUNCTION (tmc_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
