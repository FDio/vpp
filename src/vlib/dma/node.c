/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

// TODO: trace staff
static_always_inline void
dma_queue_head_update (vlib_frames_queue_t *queue)
{
  if (queue->head == queue->mask)
    queue->head = 0;
  else
    queue->head++;
}

static void
dma_poll_queue_inorder (vlib_main_t *vm, vlib_frames_queue_t *queue)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_frame_t *dma_frame = NULL;
  vlib_dma_config_t *config;
  while (queue->head != queue->tail)
    {
      dma_frame = queue->frames[queue->head];
      if (dma_frame->state == VLIB_DMA_FRAME_STATE_SUCCESS)
	{
	  config = dm->configs + dma_frame->config_index;
	  config->data.cb (vm, dma_frame->trans, dma_frame->n_transfers,
			   dma_frame->opaque);
	  config->n_transfers += dma_frame->n_transfers;
	  dma_frame->state = VLIB_DMA_FRAME_STATE_NOT_PROCESSED;
	  dma_queue_head_update (queue);
	}
      else
	break;
    };
}

static void
dma_poll_queue (vlib_main_t *vm, vlib_frames_queue_t *queue)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_frame_t *dma_frame = NULL;
  vlib_dma_config_t *config;
  u16 idx = queue->head;

  while (idx != queue->tail)
    {
      dma_frame = queue->frames[queue->head];
      if (dma_frame->state == VLIB_DMA_FRAME_STATE_SUCCESS)
	{
	  config = dm->configs + dma_frame->config_index;
	  config->data.cb (vm, dma_frame->trans, dma_frame->n_transfers,
			   dma_frame->opaque);
	  config->n_transfers += dma_frame->n_transfers;
	  dma_frame->state = VLIB_DMA_FRAME_STATE_NOT_PROCESSED;
	  if (idx == queue->head)
	    dma_queue_head_update (queue);
	}
      else if (dma_frame->state == VLIB_DMA_FRAME_STATE_NOT_PROCESSED)
	{
	  if (idx == queue->head)
	    dma_queue_head_update (queue);
	}

      if (idx == queue->mask)
	idx = 0;
      else
	idx++;
    };
}

VLIB_NODE_FN (dma_dispatch_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_thread_t *thread = dm->threads + vm->thread_index;
  vlib_dma_backend_t *p = thread->backend;
  vlib_dma_frame_t *dma_frame = NULL;
  vlib_frames_queue_t *queue;
  u16 cnt = 0;

  // for each active backend
  // pull completed frames, update status
  // for each config pending list
  // do call back for first completed pending frame
  if (p)
    {
      do
	{
	  cnt = p->fn->get_completed_count (p->ctx, &dma_frame);
	}
      while (cnt);
    }
  vec_foreach (queue, thread->queues)
    {
      if (queue->inorder)
	dma_poll_queue_inorder (vm, queue);
      else
	dma_poll_queue (vm, queue);
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
