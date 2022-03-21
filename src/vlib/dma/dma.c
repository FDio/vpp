/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 * Copyright (c) 2022 Intel and/or its affiliates.
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

  clib_spinlock_init (&dm->lock);
  vec_reset_length (dm->backends);

  vec_validate_aligned (dm->threads, tm->n_vlib_mains + 1,
			CLIB_CACHE_LINE_BYTES);

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

  p->status.state = DMA_BACKEND_READY;
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
dma_assign_backend (vlib_main_t *vm, vlib_dma_backend_t *backend, u16 size,
		    vlib_dma_transfer_t **array)
{
  u32 thread_index = vm->thread_index;
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_backend_status_t *status;

  vlib_dma_thread_t *thread = dm->threads + thread_index;
  thread->backend = backend;

  if (backend)
    {
      status = &backend->status;
      status->thread_index = thread_index;
      status->state = DMA_BACKEND_ASSIGNED;
      status->config_num++;
      backend->fn->configure (backend->ctx, size, vm->numa_node, array);
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
	  config->data.backend->status.state = DMA_BACKEND_READY;
	  config->data.backend->status.thread_index = 0;
	  thread->backend = NULL;
	}
    }
}

int
vlib_dma_config (vlib_main_t *vm, vlib_dma_config_args_t *args,
		 vlib_dma_transfer_t **array)
{
  vlib_dma_main_t *dm = &dma_main;
  u32 thread_index = vm->thread_index;
  u32 config_index;
  vlib_dma_config_t *p;
  vlib_dma_backend_t *backend, *assigned = NULL;
  vlib_dma_backend_status_t *status;
  vlib_dma_thread_t *thread = dm->threads + thread_index;
  int ret;

  vec_add2 (dm->configs, p, 1);
  config_index = p - dm->configs;
  p->data.cb = args->cb;

  if (thread->backend)
    {
      assigned = thread->backend;
      assigned->fn->configure (assigned->ctx, args->max_transfers,
			       vm->numa_node, array);
      return config_index;
    }

  clib_spinlock_lock (&dm->lock);
  /* find free backend which match requirements */
  vec_foreach (backend, dm->backends)
    {
      if ((backend->status.state == DMA_BACKEND_READY) &&
	  !dma_check_requirements (&backend->status, args, vm->numa_node))
	{
	  assigned = backend;
	  break;
	}
    }
  clib_spinlock_unlock (&dm->lock);

  if (!assigned)
    return -1;

  /* backend allocate transfers array for config */
  ret = assigned->fn->configure (backend->ctx, args->max_transfers,
				 vm->numa_node, array);
  if (ret)
    return -1;

  status = &backend->status;
  status->thread_index = thread_index;
  status->state = DMA_BACKEND_ASSIGNED;

  thread->backend = assigned;
  p->data.backend = assigned;

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
  dma_unassign_backend (vm, p);

  return 0;
}

VLIB_INIT_FUNCTION (vlib_dma_init);
