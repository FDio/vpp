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

/*
 * DB recording the size the window is clamped to for each interface
 */
u16 *tmc_db;
#define TMC_UNSET 0xffff

/* Action function shared between message handler and debug CLI */

int
tmc_enable (u32 sw_if_index, u16 mss)
{
  int rv = 0;

  vec_validate_init_empty (tmc_db, sw_if_index, ~0);

  if (TMC_UNSET == tmc_db[sw_if_index])
    {
      vnet_feature_enable_disable ("ip4-output",
				   "tcp-mss-clamping-ip4",
				   sw_if_index, 1, 0, 0);
      vnet_feature_enable_disable ("ip6-output",
				   "tcp-mss-clamping-ip6",
				   sw_if_index, 1, 0, 0);
    }

  /*
   * store in network order so it can be directly copied in the DP
   */
  tmc_db[sw_if_index] = clib_net_to_host_u16 (mss);

  return rv;
}

int
tmc_disable (u32 sw_if_index)
{
  int rv = 0;

  if (sw_if_index >= vec_len (tmc_db))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (TMC_UNSET != tmc_db[sw_if_index])
    {
      vnet_feature_enable_disable ("ip4-output", "tcp-mss-clamping-ip4",
				   sw_if_index, 0, 0, 0);
      vnet_feature_enable_disable ("ip6-output", "tcp-mss-clamping-ip6",
				   sw_if_index, 0, 0, 0);
    }
  tmc_db[sw_if_index] = TMC_UNSET;

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
  .path = "tmc",
  .short_help = "tmc [enable|disable] <interface-name>",
  .function = tmc_enable_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
tmc_show_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 ii;

  vec_foreach_index (ii, tmc_db)
  {
    if (TMC_UNSET != tmc_db[ii])
      {
	u32 mss = clib_net_to_host_u16 (tmc_db[ii]);
	vlib_cli_output (vm, "%U %d",
			 format_vnet_sw_if_index_name,
			 vnet_get_main (), ii, mss);
      }
  }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tmc_show_command, static) =
{
  .path = "show tmc",
  .short_help = "show TCP MSS clamping configurations",
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
