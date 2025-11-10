/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlib/vlib.h>

static uword
lua_process (vlib_main_t *vm, vlib_node_runtime_t *node,
             vlib_frame_t *frame)
{
  while (1)
    {
      vlib_process_wait_for_event (vm);
      vlib_process_get_events (vm, 0);
    }
  return 0;
}

VLIB_REGISTER_NODE (lua_process_node) = {
  .function = lua_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "lua",
  .state = VLIB_NODE_STATE_DISABLED,
};
