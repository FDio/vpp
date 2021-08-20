/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#include <vlib/vlib.h>
#include <vlib/time.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

static uword
vlib_time_virtual_input (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame)
{
  vlib_time_adjust_global (vlib_time_get_next_timer_global ());
  return 0;
}

VLIB_REGISTER_NODE (vlib_time_virtual_input_node) = {
  .function = vlib_time_virtual_input,
  /* using an input node instead of a pre-input node here is intentional: this
   * guarantee that we have at least 1 input node in poll-mode (this one)
   * which makes sure VPP does not sleep in unix-epoll-input */
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "virtual-time-input",
  .state = VLIB_NODE_STATE_DISABLED,
};

static clib_error_t *
vlib_time_adjust_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  f64 val;

  if (!unformat (input, "%f", &val))
    return clib_error_create ("unknown input `%U'", format_unformat_error,
			      input);
  vlib_node_set_state (vm, vlib_time_virtual_input_node.index,
		       VLIB_NODE_STATE_POLLING);
  vlib_process_wait_for_event_or_clock (vm, val);
  vlib_node_set_state (vm, vlib_time_virtual_input_node.index,
		       VLIB_NODE_STATE_DISABLED);

  return 0;
}

VLIB_CLI_COMMAND (vlib_time_adjust_command) = {
  .path = "set vlib time adjust",
  .short_help = "set vlib time adjust <nn>",
  .function = vlib_time_adjust_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "virtual-time",
  .default_disabled = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
