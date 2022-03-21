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

  if (p->fn->get_capabilities (p->instance, &p->cap))
    return -EINVAL;

  p->state = DMA_BACKEND_READY;
  p->thread_index = -1;
  p->inflight_batch = 0;
  p->max_transfer = p->cap.max_transfers;
  return p - dm->backends;
}

static_always_inline int
dma_check_requirements (vlib_dma_backend_t *backend,
			vlib_dma_config_args_t *args, u32 numa_node)
{
  /* numa node must match for performance perspective */
  if (backend->cap.numa_node != numa_node)
    return -1;
  if (args->max_transfer_size > backend->cap.max_transfer_size)
    return -1;
  if (args->barrier_before_last && !backend->cap.ordered)
    return -1;
  return 0;
}

static_always_inline void
dma_unassign_backend (vlib_main_t *vm, vlib_dma_config_t *config)
{
  vlib_dma_main_t *dm = &dma_main;
  u32 thread_index = vm->thread_index;
  vlib_dma_thread_t *thread = dm->threads + thread_index;
  vlib_dma_backend_t *backend = dm->backends + config->backend_index;

  if (backend)
    {
      backend->attached_num--;
      if (!backend->attached_num)
	{
	  backend->state = DMA_BACKEND_READY;
	  backend->thread_index = 0;
	  thread->backend = NULL;
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
  vlib_dma_thread_t *thread = dm->threads + thread_index;
  u32 i;
  int ret;

  vec_add2 (dm->configs, p, 1);
  config_index = p - dm->configs;

  u32 size;
  size = dma_backend_data_size (args->max_transfer_size);
  p->backend_data = vlib_physmem_alloc_aligned_on_numa (
    vm, size * args->max_transfers, CLIB_CACHE_LINE_BYTES, vm->numa_node);
  bzero (p->backend_data, size * args->max_transfers);

  p->data_size = size;
  p->data_num = args->max_transfers;
  p->data_head = 0;
  p->data_tail = 0;
  p->cb = args->cb;
  p->cpu_fallback = args->cpu_fallback;

  size = args->max_transfers * sizeof (dma_result_t);
  p->result_data = vlib_physmem_alloc_aligned_on_numa (
    vm, size, CLIB_CACHE_LINE_BYTES, vm->numa_node);
  bzero (p->result_data, size);

  size = args->max_transfers * sizeof (vlib_dma_record_t);
  p->results = clib_mem_alloc_aligned (size, CLIB_CACHE_LINE_BYTES);
  bzero (p->results, size);

  for (i = 0; i < args->max_transfers; i++)
    {
      vlib_dma_record_t *record = p->results + i;
      record->record_addr = p->result_data + i * sizeof (dma_result_t);
    }

  if (thread->backend)
    {
      assigned = thread->backend;
      if (dma_check_requirements (assigned, args, vm->numa_node))
	goto free;
      ret =
	assigned->fn->configure (assigned->instance, vm, args, p->backend_data,
				 p->result_data, &p->template);
      if (ret)
	goto free;
      vec_add1 (thread->reg_configs, config_index);
      p->fn = assigned->fn;
      p->backend_index = assigned - dm->backends;
      return config_index;
    }

  clib_spinlock_lock (&dm->lock);
  /* find free backend which match requirements */
  vec_foreach (backend, dm->backends)
    {
      if ((backend->state == DMA_BACKEND_READY) &&
	  !dma_check_requirements (backend, args, vm->numa_node))
	{
	  assigned = backend;
	  break;
	}
    }
  clib_spinlock_unlock (&dm->lock);

  if (!assigned)
    goto free;

  /* backend allocate transfers array for config */
  ret = assigned->fn->configure (backend->instance, vm, args, p->backend_data,
				 p->result_data, &p->template);

  if (ret)
    goto free;

  backend->thread_index = thread_index;
  backend->state = DMA_BACKEND_ASSIGNED;

  vec_add1 (thread->reg_configs, config_index);
  thread->backend = assigned;
  thread->thread_index = thread_index;
  p->fn = assigned->fn;
  p->backend_index = assigned - dm->backends;
  return config_index;

free:
  vlib_physmem_free (vm, p->backend_data);
  vlib_physmem_free (vm, p->result_data);
  clib_mem_free (p->results);
  return -1;
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

  vlib_physmem_free (vm, p->backend_data);
  vlib_physmem_free (vm, p->result_data);
  clib_mem_free (p->results);
  return 0;
}

VLIB_INIT_FUNCTION (vlib_dma_init);
