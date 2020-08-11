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
tmc_enable_disable_feat (u32 sw_if_index, u8 is_ipv6, u8 dir, int enable)
{
  if (dir == TMC_DIR_NONE)
    return;

  if (is_ipv6 == 0)
    {
      if ((dir & TMC_DIR_RX) != TMC_DIR_NONE)
	vnet_feature_enable_disable ("ip4-unicast", "tcp-mss-clamping-ip4-in",
				     sw_if_index, enable, 0, 0);
      if ((dir & TMC_DIR_TX) != TMC_DIR_NONE)
	vnet_feature_enable_disable ("ip4-output", "tcp-mss-clamping-ip4-out",
				     sw_if_index, enable, 0, 0);
    }
  else
    {
      if ((dir & TMC_DIR_RX) != TMC_DIR_NONE)
	vnet_feature_enable_disable ("ip6-unicast", "tcp-mss-clamping-ip6-in",
				     sw_if_index, enable, 0, 0);
      if ((dir & TMC_DIR_TX) != TMC_DIR_NONE)
	vnet_feature_enable_disable ("ip6-output", "tcp-mss-clamping-ip6-out",
				     sw_if_index, enable, 0, 0);
    }
}

int
tmc_enable_disable (u32 sw_if_index, u8 is_ipv6, u8 dir, u16 mss)
{
  tmc_main_t *tm = &tmc_main;
  u16 *max_mss;
  u8 *dir_enabled;
  int rv = 0;

  if (dir == TMC_DIR_NONE)
    mss = TMC_UNSET;

  if (is_ipv6 == 0)
    {
      vec_validate_init_empty (tm->max_mss4, sw_if_index, TMC_UNSET);
      max_mss = &tm->max_mss4[sw_if_index];
      vec_validate_init_empty (tm->dir_enabled4, sw_if_index, TMC_DIR_NONE);
      dir_enabled = &tm->dir_enabled4[sw_if_index];
    }
  else
    {
      vec_validate_init_empty (tm->max_mss6, sw_if_index, TMC_UNSET);
      max_mss = &tm->max_mss6[sw_if_index];
      vec_validate_init_empty (tm->dir_enabled6, sw_if_index, TMC_DIR_NONE);
      dir_enabled = &tm->dir_enabled6[sw_if_index];
    }

  // Disable the directions that are no longer needed
  tmc_enable_disable_feat (sw_if_index, is_ipv6, (*dir_enabled) & ~dir, 0);
  // Enable the new directions
  tmc_enable_disable_feat (sw_if_index, is_ipv6, ~(*dir_enabled) & dir, 1);

  *max_mss = mss;
  *dir_enabled = dir;

  return rv;
}

int
tmc_get_mss (u32 sw_if_index, u8 is_ipv6, u8 * dir, u16 * mss)
{
  tmc_main_t *tm = &tmc_main;
  int rv = VNET_API_ERROR_FEATURE_DISABLED;

  if (is_ipv6 == 0)
    {
      if (vec_len (tm->dir_enabled4) > sw_if_index
	  && TMC_DIR_NONE != tm->dir_enabled4[sw_if_index])
	{
	  *mss = tm->max_mss4[sw_if_index];
	  *dir = tm->dir_enabled4[sw_if_index];
	  rv = 0;
	}
    }
  else
    {
      if (vec_len (tm->dir_enabled6) > sw_if_index
	  && TMC_DIR_NONE != tm->dir_enabled6[sw_if_index])
	{
	  *mss = tm->max_mss6[sw_if_index];
	  *dir = tm->dir_enabled6[sw_if_index];
	  rv = 0;
	}
    }
  return rv;
}

static clib_error_t *
tmc_enable_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 mss = ~0, sw_if_index = ~0;
  int rv, is_enable = 1;
  u8 dir = TMC_DIR_NONE;
  u8 is_ipv6 = (u8) cmd->function_arg;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	is_enable = 0;
      else if (unformat (input, "enable"))
	is_enable = 1;
      else if (unformat (input, "mss %d", &mss))
	is_enable = 1;
      else if (unformat (input, "rx"))
	dir |= TMC_DIR_RX;
      else if (unformat (input, "tx"))
	dir |= TMC_DIR_TX;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface");
  if (is_enable)
    {
      if (mss == ~0)
	return clib_error_return (0, "Please specify the Max Segment Size");
      if (mss >= TMC_UNSET)
	return clib_error_return (0, "Invalid Max Segment Size");

      // No direction was specified, set it to both.
      if (dir == TMC_DIR_NONE)
	dir = TMC_DIR_BOTH;
    }
  else
    {
      if (dir != TMC_DIR_NONE)
	return clib_error_return (0,
				  "disable and tx/rx cannot be specified together");
    }



  rv = tmc_enable_disable (sw_if_index, is_ipv6, dir, mss);

  if (rv)
    return clib_error_return (0, "Failed: %d = %U",
			      rv, format_vnet_api_errno, rv);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tmc_ip4_enable_disable_command, static) =
{
  .path = "set interface ip tcp-mss-clamp",
  .short_help = "set interface ip tcp-mss-clamp [enable|disable|rx|tx] <interface-name> mss <size>",
  .function = tmc_enable_command_fn,
  .function_arg = 0, // IPv4
};

VLIB_CLI_COMMAND (tmc_ip6_enable_disable_command, static) =
{
  .path = "set interface ip6 tcp-mss-clamp",
  .short_help = "set interface ip6 tcp-mss-clamp [enable|disable|rx|tx] <interface-name> mss <size>",
  .function = tmc_enable_command_fn,
  .function_arg = 1, // IPv6
};
/* *INDENT-ON* */

static clib_error_t *
tmc_show_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  tmc_main_t *tm = &tmc_main;
  u32 sw_if_index = ~0;
  u8 is_ipv6 = (u8) cmd->function_arg;
  u32 ii;

#define DIR2S(d) \
  (((d) == TMC_DIR_BOTH) ? "" : (((d) == TMC_DIR_RX) ? " [RX]" : " [TX]"))

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
      u16 *max_mss;
      u8 *dir_enabled;
      if (is_ipv6 == 0)
	{
	  max_mss = tm->max_mss4;
	  dir_enabled = tm->dir_enabled4;
	}
      else
	{
	  max_mss = tm->max_mss6;
	  dir_enabled = tm->dir_enabled6;
	}
      vec_foreach_index (ii, dir_enabled)
      {
	if (TMC_DIR_NONE != dir_enabled[ii])
	  {
	    u32 mss = max_mss[ii];
	    vlib_cli_output (vm, "%U: %d%s",
			     format_vnet_sw_if_index_name,
			     vnet_get_main (), ii, mss,
			     DIR2S (dir_enabled[ii]));
	  }
      }
    }
  else
    {
      u16 mss16;
      u8 dir;
      if (tmc_get_mss (sw_if_index, is_ipv6, &dir, &mss16) == 0)
	{
	  u32 mss = mss16;
	  vlib_cli_output (vm, "%U: %d%s",
			   format_vnet_sw_if_index_name,
			   vnet_get_main (), sw_if_index, mss, DIR2S (dir));
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
VLIB_CLI_COMMAND (tmc_ip4_show_command, static) =
{
  .path = "show interface ip tcp-mss-clamp",
  .short_help = "show interface ip tcp-mss-clamp [interface-name]",
  .long_help = "show TCP MSS clamping configurations",
  .function = tmc_show_command_fn,
  .function_arg = 0, // IPv4
};

VLIB_CLI_COMMAND (tmc_ip6_show_command, static) =
{
  .path = "show interface ip6 tcp-mss-clamp",
  .short_help = "show interface ip6 tcp-mss-clamp [interface-name]",
  .long_help = "show TCP MSS clamping configurations",
  .function = tmc_show_command_fn,
  .function_arg = 1, // IPv6
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
