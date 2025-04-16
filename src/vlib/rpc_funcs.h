/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __vlib_rpc_funcs_h__
#define __vlib_rpc_funcs_h__

#include <vlib/vlib.h>

static_always_inline void
rpc_call (u16 thread_index, void *fn, u8 *args, u32 size)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_main_t *rvm = vlib_get_main_by_index (thread_index);
  vlib_rpc_t *rpc = 0, *prev;

  if (size > sizeof (rpc->data))
    clib_panic ("RPC too big");

  vec_foreach_pointer (a, vm->rpc_allocs)
    if (__atomic_load_n (&a->enqueued, __ATOMIC_ACQUIRE) == 0)
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
  rpc->enqueued = 1;
  clib_memcpy_fast (rpc->data, args, size);

  prev = __atomic_exchange_n (&rvm->rpc_tail, rpc, __ATOMIC_ACQ_REL);
  if (prev)
    __atomic_store_n (&prev->next, rpc, __ATOMIC_RELEASE);
  else
    __atomic_store_n (&rvm->rpc_head, rpc, __ATOMIC_RELEASE);
  fformat (stderr, "RPC %p %u -> %u enqueued", rpc, vm->thread_index,
	   thread_index);
}

static_always_inline void
vlib_rpc_init (vlib_main_t *vm)
{
  vm->rpc_head = vm->rpc_tail = 0;
  vm->rpc_allocs = 0;
}

static_always_inline vlib_rpc_t *
vlib_rpc_dequeue (vlib_main_t *vm)
{
  vlib_rpc_t *head, *next, *tail;

  head = __atomic_load_n (&vm->rpc_head, __ATOMIC_ACQUIRE);
  if (!head)
    return 0;

  next = __atomic_load_n (&head->next, __ATOMIC_ACQUIRE);

  if (next)
    {
      vm->rpc_head = next;
      return head;
    }

  tail = __atomic_load_n (&vm->rpc_tail, __ATOMIC_ACQUIRE);
  if (tail == head)
    {
      if (__atomic_compare_exchange_n (&vm->rpc_tail, &tail, 0, 0,
				       __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
	vm->rpc_head = 0;
      return head;
    }

  return 0;
}

static_always_inline void
vlib_rpc_release (vlib_rpc_t *rpc)
{
  __atomic_store_n (&rpc->rpc_fn, 0, __ATOMIC_RELEASE);
}

#endif /* __vlib_rpc_funcs_h__ */
