/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 * Copyright (c) 2022 Intel and/or its affiliates.
 */

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vlib/node_funcs.h>
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
  p->fn = (vlib_dma_config_fn *) args->config_fn;
  p->instance = instance;

  if (!p->fn->get_capabilities)
    return -ENOTSUP;

  if (p->fn->get_capabilities (p->instance, &p->cap))
    return -EINVAL;

  return p - dm->backends;
}

static_always_inline int
dma_check_requirements (vlib_dma_backend_t *backend,
			vlib_dma_config_args_t *args, u32 numa_node)
{
  if (args->max_transfer_size > backend->cap.max_transfer_size)
    return -1;
  if (args->barrier_before_last && !backend->cap.ordered)
    return -1;
  return 0;
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
  int ret;

  vec_add2 (dm->configs, p, 1);
  config_index = p - dm->configs;
  p->backend_index = -1;

  clib_spinlock_lock (&dm->lock);
  /* find free backend which match requirements */
  vec_foreach (backend, dm->backends)
    {
      if (!dma_check_requirements (backend, args, vm->numa_node))
	{
	  ret = backend->fn->configure (backend->instance, vm, config_index,
					args, args->template);
	  if (!ret)
	    {
	      assigned = backend;
	      break;
	    }
	}
    }
  clib_spinlock_unlock (&dm->lock);

  if (!assigned)
    return -1;

  vec_add1 (thread->reg_configs, config_index);
  p->cb = args->cb;
  p->backend_index = assigned - dm->backends;
  p->cpu_fallback = args->cpu_fallback;
  p->fn = assigned->fn;
  p->template = args->template;

  vlib_node_set_state (vm, dma_dispatch_node.index, VLIB_NODE_STATE_POLLING);
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
  p->fn->release (vm, config_index);
  p->backend_index = -1;
  return 0;
}

VLIB_INIT_FUNCTION (vlib_dma_init);
