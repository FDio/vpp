/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vlib/dma/dma.h>

#define foreach_dma_op_status                                                 \
  _ (IDLE, "idle")                                                            \
  _ (PENDING, "pending")                                                      \
  _ (WORK_IN_PROGRESS, "work-in-progress")                                    \
  _ (COMPLETED, "completed")                                                  \
  _ (FAIL_NO_HANDLER, "no-handler")                                           \
  _ (FAIL_BAD_DESC, "bad-desc")                                               \
  _ (FAIL_ENGINE_ERR, "engine-error")

typedef enum
{
#define _(sym, str) VLIB_DMA_ERROR_##sym,
  foreach_dma_op_status
#undef _
    VLIB_DMA_N_ERROR,
} vlib_dma_error_t;

static char *vlib_dma_error_strings[] = {
#define _(sym, str) str,
  foreach_dma_op_status
#undef _
};

#define foreach_dma_dispatch_next _ (ERR_DROP, "error-drop")

typedef enum
{
#define _(n, s) DMA_DISPATCH_NEXT_##n,
  foreach_dma_dispatch_next
#undef _
    DMA_DISPATCH_N_NEXT,
} dma_dispatch_next_t;

VLIB_NODE_FN (dma_dispatch_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_thread_t *thread = dm->threads + vm->thread_index;
  vlib_dma_config_t *p;
  u32 *config_index;
  u16 cnt = 0;
  vlib_dma_completion_cb_fn_t cb;

  vec_foreach (config_index, thread->reg_configs)
    {
      p = dm->configs + config_index[0];
      do
	{
	  cnt = p->fn->get_completed (p->backend_data, &cb);
	  if (cnt)
	    cb (vm, cnt);
	}
      while (cnt);
    }
  return 0;
}

VLIB_REGISTER_NODE (dma_dispatch_node) = {
  .name = "dma-dispatch",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
//  .format_trace = format_dma_dispatch_trace,

  .n_errors = ARRAY_LEN(vlib_dma_error_strings),
  .error_strings = vlib_dma_error_strings,

  .n_next_nodes = DMA_DISPATCH_N_NEXT,
  .next_nodes = {
#define _(n, s) [DMA_DISPATCH_NEXT_##n] = s,
      foreach_dma_dispatch_next
#undef _
  },
};
