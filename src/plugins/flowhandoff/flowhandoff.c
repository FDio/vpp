/*
 * flowhandoff.c - ipfix probe plugin
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>

#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

#include <flowhandoff/flowhandoff.h>

#define BIHASH_IP4_NUM_BUCKETS (64 << 20)
#define BIHASH_IP4_MEM_SIZE (8ULL << 30)

flowhandoff_main_t flowhandoff_main = {
  .frame_queue_index = ~0,
};

/** *INDENT-OFF* */
VNET_FEATURE_INIT (flowhandof4_input, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "flowhandoff4-input",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
/** *INDENT-ON* */

int
flowhandoff_enable_disable (flowhandoff_main_t * sm, u32 sw_if_index,
			    int enable_disable)
{
  vlib_main_t *vm = vlib_get_main ();
  flowhandoff_main_t *fm = &flowhandoff_main;
  int rv = 0;

  if (fm->table4.nbuckets == 0)
    clib_bihash_init_16_8 (&fm->table4, "flowhandoff ipv4",
			   BIHASH_IP4_NUM_BUCKETS, BIHASH_IP4_MEM_SIZE);

  if (fm->frame_queue_index == ~0)
    {
      vlib_node_t *n = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
      fm->frame_queue_index = vlib_frame_queue_main_init (n->index, 0);
    }

  vnet_feature_enable_disable ("ip4-unicast", "flowhandoff4-input",
			       sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
flowhandoff_enable_disable_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  flowhandoff_main_t *sm = &flowhandoff_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int enable_disable = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = flowhandoff_enable_disable (sm, sw_if_index, enable_disable);

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
      return clib_error_return (0, "flowhandoff_enable_disable returned %d",
				rv);
    }
  return 0;
}

static clib_error_t *
show_flowhandoff_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  flowhandoff_main_t *sm = &flowhandoff_main;

  vlib_cli_output (vm, "%U", format_bihash_16_8, &sm->table4, 0);
  return 0;
}

VLIB_CLI_COMMAND (flow_handoff, static) = {
    .path = "flow-handoff",
    .short_help = "flow-handoff <interface-name> [disable]",
    .function = flowhandoff_enable_disable_command_fn,
};

VLIB_CLI_COMMAND (show_flow_handoff, static) = {
    .path = "show flow-handoff",
    .short_help = "show flow-handoff",
    .function = show_flowhandoff_command_fn,
};
static clib_error_t *
flowhandoff_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;
  return error;
}

VLIB_INIT_FUNCTION (flowhandoff_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Flow Handoff Plugub",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
