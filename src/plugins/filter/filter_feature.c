/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <filter/filter_table.h>
#include <vnet/feature/feature.h>

static clib_error_t *
filter_enable_cli (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 sw_if_index, dproto;
  u8 enable;

  enable = 1;
  sw_if_index = ~0;
  dproto = DPO_PROTO_NONE;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "%U", unformat_dpo_proto, &dproto))
	;
      else if (unformat (input, "%U",
			 unformat_vnet_sw_interface, vnet_get_main (),
			 &sw_if_index))
	;
      else
	break;
    }

  if (DPO_PROTO_NONE == dproto)
    return clib_error_return (0, "specify protocol");
  if (~0 == sw_if_index)
    return clib_error_return (0, "specify interface");

  if (enable)
    {
      if (DPO_PROTO_IP4 == dproto)
	{
	  vnet_feature_enable_disable ("ip4-unicast",
				       "filter-feature-input-ip4",
				       sw_if_index, 1, NULL, 0);
	  vnet_feature_enable_disable ("ip4-output",
				       "filter-feature-output-ip4",
				       sw_if_index, 1, NULL, 0);
	}
      else
	{
	  vnet_feature_enable_disable ("ip6-unicast",
				       "filter-feature-input-ip6",
				       sw_if_index, 1, NULL, 0);
	  vnet_feature_enable_disable ("ip6-output",
				       "filter-feature-output-ip6",
				       sw_if_index, 1, NULL, 0);
	}
    }
  else
    {
      return clib_error_return (0, "TODO");
    }

  return (NULL);
}

/*?
 * Configure a filter table
 *
 * @cliexpar
 * @cliexstart{filter enable <proto> <interface>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_enable_cli_node, static) = {
  .path = "filter enable",
  .short_help = "filter enable <proto> <interface>",
  .function = filter_enable_cli,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
