/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __vlib_rpc_funcs_h__
#define __vlib_rpc_funcs_h__

#include <vlib/vlib.h>

typedef u16 clib_thread_index_t;

static_always_inline void
vlib_rpc_call (vlib_main_t *vm, clib_thread_index_t thread_index,
	       vlib_rpc_fn_t *fn, u8 *args, u32 size, int under_barrier)
{
  vlib_main_t *rvm = vlib_get_main_by_index (thread_index);
  vlib_rpc_t *rpc = 0, *prev;

  ASSERT ((thread_index == 0) || (under_barrier == 1));

  if (size > sizeof (rpc->data))
    clib_panic ("RPC too big");

  vec_foreach_pointer (a, vm->rpc_allocs)
    if (a->in_use == 0)
      {
	rpc = a;
	break;
      }

  if (!rpc)
    {
      rpc =
	clib_mem_alloc_aligned (sizeof (vlib_rpc_t), CLIB_CACHE_LINE_BYTES);
      vec_add1 (vm->rpc_allocs, rpc);
    }

  rpc->rpc_fn = fn;
  rpc->next = 0;
  rpc->in_use = 1;
  rpc->completed = 0;
  clib_memcpy_fast (rpc->data, args, size);

  prev = __atomic_exchange_n (&rvm->rpc_tail, rpc, __ATOMIC_ACQ_REL);
  __atomic_store_n (&prev->next, rpc, __ATOMIC_RELEASE);
}

static_always_inline void
vlib_rpc_init (vlib_main_t *vm)
{
  vlib_rpc_t *stub =
    clib_mem_alloc_aligned (sizeof (vlib_rpc_t), CLIB_CACHE_LINE_BYTES);
  stub->next = 0;
  stub->in_use = 1;
  vm->rpc_head = stub;
  vm->rpc_tail = stub;
  vm->rpc_allocs = 0;
  vec_add1 (vm->rpc_allocs, stub);
}

static_always_inline vlib_rpc_t *
vlib_rpc_dequeue (vlib_main_t *vm)
{
  vlib_rpc_t *head, *next;

  head = vm->rpc_head;
  next = __atomic_load_n (&head->next, __ATOMIC_ACQUIRE);
  if (next == 0)
    return 0;

  vm->rpc_head = next;
  head->in_use = 0;
  return next;
}

static_always_inline void
vlib_rpc_release (vlib_rpc_t *rpc)
{
  rpc->rpc_fn = 0;
  __atomic_store_n (&rpc->completed, 1, __ATOMIC_RELEASE);
}

#endif /* __vlib_rpc_funcs_h__ */
