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
vlib_dma_register_backend (vlib_main_t *vm, void *instance,
			   vlib_dma_register_backend_args_t *args)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_backend_t *p;
  vec_add2 (dm->backends, p, 1);
  p->name = args->name;
  p->fn = (vlib_dma_config_fn_t *) args->config_fn;
  p->instance = instance;

  if (!p->fn->get_capabilities)
    return -ENOTSUP;

  if (p->fn->get_capabilities (p->instance, &p->status.cap))
    return -EINVAL;

  p->status.state = DMA_BACKEND_READY;
  p->status.thread_index = -1;
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
dma_unassign_backend (vlib_main_t *vm, vlib_dma_config_t *config)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_backend_t *backend = dm->backends + config->backend_index;

  if (backend)
    {
      backend->status.config_num--;
      if (!backend->status.config_num)
	{
	  backend->status.state = DMA_BACKEND_READY;
	  backend->status.thread_index = 0;
	}
    }
}

int
vlib_dma_config (vlib_main_t *vm, vlib_dma_config_args_t *args)
{
  vlib_dma_main_t *dm = &dma_main;
  u32 thread_index = vm->thread_index;
  u32 config_index;
  vlib_dma_config_t *p;
  vlib_dma_backend_t *backend, *assigned = NULL;
  vlib_dma_backend_status_t *status;
  vlib_dma_thread_t *thread = dm->threads + thread_index;
  u32 flags = 0;

  vec_add2 (dm->configs, p, 1);
  config_index = p - dm->configs;
  flags |= args->barrier_before_last << 1;
  flags |= args->cpu_fallback;

  backend = dm->backends + thread->backend_index;
  if (backend)
    {
      if (dma_check_requirements (&backend->status, args, vm->numa_node))
	return -1;
      backend->fn->configure (assigned->instance, vm, flags,
			      args->max_transfers, args->cb, &p->backend_data);
      vec_add1 (thread->reg_configs, config_index);
      p->fn = backend->fn;
      p->backend_index = backend - dm->backends;
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
  assigned->fn->configure (backend->instance, vm, flags, args->max_transfers,
			   args->cb, &p->backend_data);
  status = &backend->status;
  status->thread_index = thread_index;
  status->state = DMA_BACKEND_ASSIGNED;

  vec_add1 (thread->reg_configs, config_index);
  p->fn = assigned->fn;
  p->backend_index = assigned - dm->backends;
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
