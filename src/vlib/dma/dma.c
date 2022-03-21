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

vlib_dma_main_t dma_main;

clib_error_t *
vlib_dma_init (vlib_main_t *vm)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_dma_thread_t *thread;

  clib_spinlock_init (&dm->lock);
  vec_reset_length (dm->backends);

  /* create frame pool for each thread */
  vec_validate_aligned (dm->threads, tm->n_vlib_mains + 1,
			CLIB_CACHE_LINE_BYTES);
  vec_foreach (thread, dm->threads)
    {
      pool_alloc_aligned (thread->frame_pool, VLIB_DMA_FRAME_POOL_SIZE,
			  CLIB_CACHE_LINE_BYTES);
      vec_reset_length (thread->queues);
      thread->queue_map = clib_mem_alloc (sizeof (u32) * DMA_MAX_CONFIGS);
    }
  return NULL;
}

int
vlib_dma_register_backend (vlib_main_t *vm, void *ctx,
			   vlib_dma_register_backend_args_t *args)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_backend_t *p;
  vec_add2 (dm->backends, p, 1);
  p->name = args->name;
  p->fn = (vlib_dma_config_fn_t *) args->config_fn;
  p->ctx = ctx;

  if (!p->fn->get_capabilities)
    return -ENOTSUP;

  if (p->fn->get_capabilities (p->ctx, &p->status.cap))
    return -EINVAL;

  if (p->fn->configure (p->ctx))
    return -EINVAL;

  p->status.assigned = false;
  p->status.thread_index = 0;
  return p - dm->backends;
}

static_always_inline int
dma_check_requirements (vlib_dma_backend_status_t *st,
			vlib_dma_config_args_t *args, u32 numa_node)
{
  /* numa node must match for performance perspective */
  if (st->cap.numa_node != numa_node)
    return -1;
  if (args->max_transfer_size > st->cap.max_transfer_size)
    return -1;
  if (args->max_transfers > st->cap.max_transfers)
    return -1;
  if (args->barrier_before_last && !st->cap.ordered)
    return -1;
  return 0;
}

static_always_inline void
dma_sw_copy (vlib_dma_transfer_t *args, u32 n_transfers)
{
  u32 i;
  vlib_dma_transfer_t *transfer;
  for (i = 0; i < n_transfers; i++)
    {
      transfer = args + i;
      clib_memcpy (transfer->dst, transfer->src, transfer->size);
    }
}

static_always_inline void
dma_assign_backend (vlib_main_t *vm, vlib_dma_config_t *config,
		    vlib_dma_backend_t *backend)
{
  u32 thread_index = vm->thread_index;
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_backend_status_t *status;

  vlib_dma_thread_t *thread = dm->threads + thread_index;
  thread->backend = backend;
  config->data.backend = backend;

  if (backend)
    {
      status = &backend->status;
      status->thread_index = thread_index;
      status->assigned = true;
      status->config_num++;
    }
}

static_always_inline void
dma_unassign_backend (vlib_main_t *vm, vlib_dma_config_t *config)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_backend_status_t *status;
  u32 thread_index = vm->thread_index;
  vlib_dma_thread_t *thread = dm->threads + thread_index;

  if (config->data.backend)
    {
      status = &config->data.backend->status;
      status->config_num--;
      if (!status->config_num)
        {
	  config->data.backend->status.assigned = false;
	  config->data.backend->status.thread_index = 0;
	  thread->backend = NULL;
	  vec_reset_length (thread->queues);
	}
    }
}

static_always_inline void
dma_init_queue (vlib_dma_thread_t *thread, u32 config_index, bool inorder)
{
  vlib_frames_queue_t *queue;
  vec_add2 (thread->queues, queue, 1);
  /* Map between dma queue and config index */
  thread->queue_map[config_index] = queue - thread->queues;
  queue->frames = clib_mem_alloc_aligned (
    (sizeof (u64) * VLIB_DMA_FRAME_POOL_SIZE), CLIB_CACHE_LINE_BYTES);
  queue->head = 0;
  queue->tail = 0;
  queue->mask = VLIB_DMA_FRAME_POOL_SIZE - 1;
  queue->config_index = config_index;
  queue->inorder = inorder;
}

int
vlib_dma_config (vlib_main_t *vm, vlib_dma_config_args_t *args)
{
  vlib_dma_main_t *dm = &dma_main;
  u32 thread_index = vm->thread_index;
  u32 config_index;
  vlib_dma_config_t *p;
  vlib_dma_backend_t *backend = NULL;
  vlib_dma_thread_t *thread = dm->threads + thread_index;

  vec_add2 (dm->configs, p, 1);
  config_index = p - dm->configs;
  p->data.cb = args->cb;

  clib_spinlock_lock (&dm->lock);
  /* find free backend which match requirements */
  vec_foreach (backend, dm->backends)
    {
      if ((backend->status.assigned == false) &&
	   !dma_check_requirements (&backend->status, args, vm->numa_node))
	    break;
    }
  clib_spinlock_unlock (&dm->lock);

  dma_assign_backend (vm, p, backend);
 
  /* init dma pending list for this config */
  dma_init_queue (thread, config_index,
		  args->barrier_before_last ? true : false);
  return config_index;
}

int
vlib_dma_release (vlib_main_t *vm, u32 config_index)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_config_t *p;

  if (config_index > vec_len (dm->configs))
    return -ENODEV;

  p = dm->configs + config_index;
  dma_unassign_backend(vm, p);

  return 0;
}

u32
vlib_dma_transfer (vlib_main_t *vm, u32 config_index,
		   vlib_dma_transfer_t *args, u32 n_transfers, void *opaque)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_thread_t *thread = dm->threads + vm->thread_index;
  vlib_dma_config_t *config;
  vlib_dma_backend_t *backend;
  vlib_dma_frame_t *frame;
  vlib_frames_queue_t *queue;
  config = dm->configs + config_index;
  u32 queue_index;

  if (PREDICT_FALSE (config == NULL))
    return 0;

  backend = config->data.backend;
  queue_index = thread->queue_map[config_index];
  queue = thread->queues + queue_index;

  if ((queue->tail == queue->mask && queue->head == 0) ||
      (queue->tail + 1 == queue->head))
    {
      printf ("no space for pending frame, do by software\n");
      return 0;
    }

  pool_get_aligned (thread->frame_pool, frame, CLIB_CACHE_LINE_BYTES);
  frame->config_index = config_index;
  frame->state = VLIB_DMA_FRAME_STATE_NOT_PROCESSED;
  frame->vm = vm;
  frame->n_transfers = n_transfers;
  frame->opaque = opaque;
  clib_memcpy (&frame->trans, args,
	       sizeof (vlib_dma_transfer_t) * n_transfers);

  if (PREDICT_FALSE (queue->config_index != config_index || backend == NULL))
    {
      /* fallback to software copy when no backend */
      dma_sw_copy (args, n_transfers);
      frame->state = VLIB_DMA_FRAME_STATE_SUCCESS;
    }
  else
    {
      config->data.backend->fn->dma_transfer (backend->ctx, frame);
      frame->state = VLIB_DMA_FRAME_STATE_WORK_IN_PROGRESS;
    }

  /* save frame into pending list */
  queue->frames[queue->tail] = (void *) frame;

  if (queue->tail == queue->mask)
    queue->tail = 0;
  else
    queue->tail++;

  return n_transfers;
}

VLIB_INIT_FUNCTION (vlib_dma_init);
