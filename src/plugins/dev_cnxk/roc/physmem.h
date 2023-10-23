/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_physmem_h
#define included_onp_drv_inc_physmem_h

static_always_inline void
cnxk_drv_physmem_free (vlib_main_t *vm, void *mem)
{
  if (!mem)
    {
      clib_warning ("Invalid address %p", mem);
      return;
    }

  vlib_physmem_free (vm, mem);
}

static_always_inline void *
cnxk_drv_physmem_alloc (vlib_main_t *vm, u32 size, u32 align)
{
  clib_error_t *error = NULL;
  uword *mem = NULL;

  if (align)
    {
      /* Force cache line alloc in case alignment is less than cache line */
      align = align < CLIB_CACHE_LINE_BYTES ? CLIB_CACHE_LINE_BYTES : align;
      mem = vlib_physmem_alloc_aligned_on_numa (vm, size, align, 0);
    }
  else
    mem =
      vlib_physmem_alloc_aligned_on_numa (vm, size, CLIB_CACHE_LINE_BYTES, 0);
  if (!mem)
    return NULL;

  error = vfio_map_physmem_page (vm, mem);
  if (error)
    goto report_error;

  clib_memset (mem, 0, size);
  return mem;

report_error:
  clib_error_report (error);
  cnxk_drv_physmem_free (vm, mem);

  return NULL;
}

#endif /* included_onp_drv_inc_physmem_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
