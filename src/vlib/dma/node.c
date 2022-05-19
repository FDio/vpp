/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 * Copyright (c) 2022 Intel and/or its affiliates.
 */

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vlib/dma/dma.h>

VLIB_NODE_FN (dma_dispatch_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_thread_t *thread = dm->threads + vm->thread_index;
  u32 *config_index;
  u32 cnt = 0;
  uword cookie;
  vlib_dma_completion_cb_fn_t cb;

  vec_foreach (config_index, thread->reg_configs)
    {
      do
	{
	  cnt = vlib_dma_get_completed (vm, config_index[0], &cb, &cookie);
	  if (cnt)
	    cb (vm, cookie);
	}
      while (cnt);
    }
  return 0;
}

VLIB_REGISTER_NODE (dma_dispatch_node) = {
  .name = "dma-dispatch",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};
