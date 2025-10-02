/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vppinfra/mem.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>

#include <vlib/delayed_free.h>
#include <vlib/vlib.h>

void
clib_mem_heap_free_mt_safe (void *heap, void *p)
{
  clib_mem_heap_t *h;
  clib_delayed_free_entry_t *e;
  vlib_main_t *vm = vlib_get_main ();

  /* For now, only the main thread can perform mt-safe reallocations. */
  ASSERT (vlib_get_thread_index () == 0);

  /* If no workers, no need for delayed free. */
  if (vlib_num_workers () == 0)
    {
      clib_mem_heap_free (heap, p);
      return;
    }

  if (heap == 0)
    h = clib_mem_get_per_cpu_heap ();
  else
    h = heap;

  /* Allocate the element in the vector. */
  vec_add2 (vm->pending_frees, e, 1);
  e->ptr_to_free = p;
  e->heap = h;
  e->type = CLIB_DELAYED_FREE_DLMALLOC;
}
