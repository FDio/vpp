/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/*
 *   WARNING!
 *   This driver is not intended for production use and it is unsupported.
 *   It is provided for educational use only.
 *   Please use supported DPDK driver instead.
 */


#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <mlx5/mlx5.h>

clib_error_t *
mlx5_mempage_alloc (void **va)
{
  mlx5_main_t *mm = &mlx5_main;
  mlx5_mempage_block_t *mb;
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error = 0;
  void *mem;
  uword index, slot = 0;

  /* *INDENT-OFF* */
  pool_foreach (mb, mm->mempage_blocks, ({
    if (mb->bitmap == ~0ULL)
      continue;
    while ((mb->bitmap & (1ULL << slot)))
      slot++;
    goto found;
  }));
  /* *INDENT-ON* */

  mem =
    vlib_physmem_alloc_aligned (vm, mm->physmem_region, &error, 4096 * 64,
				4096);

  if (error)
    return error;

  pool_get (mm->mempage_blocks, mb);
  mb->bitmap = 0;
  mb->mem = mem;

found:
  index = mb - mm->mempage_blocks;
  mb->bitmap |= 1ULL << slot;
  *va = mb->mem + slot * 4096;
  hash_set (mm->mempage_by_pa, mlx5_physmem_v2p (*va), index << 8 | slot);
  return 0;
}

void
mlx5_mempage_free_pa (uword pa)
{
  mlx5_main_t *mm = &mlx5_main;
  vlib_main_t *vm = vlib_get_main ();
  mlx5_mempage_block_t *mb;
  uword *p = hash_get (mm->mempage_by_pa, pa);
  int slot;
  int index;

  if (!p)
    return;

  index = p[0] >> 8;
  slot = p[0] & 0xff;
  mb = pool_elt_at_index (mm->mempage_blocks, index);

  mb->bitmap &= ~(1UL << slot);
  hash_unset (mm->mempage_by_pa, pa);

  if (mb->bitmap)
    return;

  vlib_physmem_free (vm, mm->physmem_region, mb->mem);
  pool_put (mm->mempage_blocks, mb);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
