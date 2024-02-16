/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vnet/vnet.h>
#include <vlib/pci/pci.h>
#include <vlib/linux/vfio.h>
#include <base/roc_api.h>
#include <common.h>

static oct_plt_memzone_list_t memzone_list;

static inline void
oct_plt_log (oct_plt_log_level_t level, oct_plt_log_class_t cls, char *fmt,
	     ...)
{
  vlib_log ((vlib_log_level_t) level, cls, fmt);
}

static inline void
oct_plt_spinlock_init (oct_plt_spinlock_t *p)
{
  clib_spinlock_init ((clib_spinlock_t *) p);
}

static void
oct_plt_spinlock_lock (oct_plt_spinlock_t *p)
{
  clib_spinlock_lock ((clib_spinlock_t *) p);
}

static void
oct_plt_spinlock_unlock (oct_plt_spinlock_t *p)
{
  clib_spinlock_unlock ((clib_spinlock_t *) p);
}

static int
oct_plt_spinlock_trylock (oct_plt_spinlock_t *p)
{
  return clib_spinlock_trylock ((clib_spinlock_t *) p);
}

static u64
oct_plt_get_thread_index (void)
{
  return __os_thread_index;
}

static u64
oct_plt_get_cache_line_size (void)
{
  return CLIB_CACHE_LINE_BYTES;
}

static void
oct_drv_physmem_free (vlib_main_t *vm, void *mem)
{
  if (!mem)
    {
      clib_warning ("Invalid address %p", mem);
      return;
    }

  vlib_physmem_free (vm, mem);
}

static void *
oct_drv_physmem_alloc (vlib_main_t *vm, u32 size, u32 align)
{
  clib_error_t *error = NULL;
  uword *mem = NULL;

  if (align)
    {
      /* Force ROC align alloc in case alignment is less than ROC align */
      align = align < ROC_ALIGN ? ROC_ALIGN : align;
      mem = vlib_physmem_alloc_aligned_on_numa (vm, size, align, 0);
    }
  else
    mem = vlib_physmem_alloc_aligned_on_numa (vm, size, ROC_ALIGN, 0);
  if (!mem)
    return NULL;

  error = vfio_map_physmem_page (vm, mem);
  if (error)
    goto report_error;

  clib_memset (mem, 0, size);
  return mem;

report_error:
  clib_error_report (error);
  oct_drv_physmem_free (vm, mem);

  return NULL;
}

static void
oct_plt_free (void *addr)
{
  vlib_main_t *vm = vlib_get_main ();

  oct_drv_physmem_free ((void *) vm, addr);
}

static void *
oct_plt_zmalloc (u32 size, u32 align)
{
  vlib_main_t *vm = vlib_get_main ();

  return oct_drv_physmem_alloc (vm, size, align);
}

static oct_plt_memzone_t *
memzone_get (u32 index)
{
  if (index == ((u32) ~0))
    return 0;

  return pool_elt_at_index (memzone_list.mem_pool, index);
}

static int
oct_plt_memzone_free (const oct_plt_memzone_t *name)
{
  uword *p;
  p = hash_get_mem (memzone_list.memzone_by_name, name);

  if (p[0] == ((u32) ~0))
    return -EINVAL;

  hash_unset_mem (memzone_list.memzone_by_name, name);

  pool_put_index (memzone_list.mem_pool, p[0]);

  return 0;
}

static oct_plt_memzone_t *
oct_plt_memzone_lookup (const char *name)
{
  uword *p;
  p = hash_get_mem (memzone_list.memzone_by_name, name);
  if (p)
    return memzone_get (p[0]);

  return 0;
}

static oct_plt_memzone_t *
oct_plt_memzone_reserve_aligned (const char *name, u64 len, u8 socket,
				 u32 flags, u32 align)
{
  oct_plt_memzone_t *mem_pool;
  void *p = NULL;

  pool_get_zero (memzone_list.mem_pool, mem_pool);

  p = oct_plt_zmalloc (len, align);
  if (!p)
    return NULL;

  mem_pool->addr = p;
  mem_pool->index = mem_pool - memzone_list.mem_pool;
  hash_set_mem (memzone_list.memzone_by_name, name, mem_pool->index);

  return mem_pool;
}

oct_plt_init_param_t oct_plt_init_param = {
  .oct_plt_log_reg_class = vlib_log_register_class,
  .oct_plt_log = oct_plt_log,
  .oct_plt_free = oct_plt_free,
  .oct_plt_zmalloc = oct_plt_zmalloc,
  .oct_plt_memzone_free = oct_plt_memzone_free,
  .oct_plt_memzone_lookup = oct_plt_memzone_lookup,
  .oct_plt_memzone_reserve_aligned = oct_plt_memzone_reserve_aligned,
  .oct_plt_spinlock_init = oct_plt_spinlock_init,
  .oct_plt_spinlock_lock = oct_plt_spinlock_lock,
  .oct_plt_spinlock_unlock = oct_plt_spinlock_unlock,
  .oct_plt_spinlock_trylock = oct_plt_spinlock_trylock,
  .oct_plt_get_thread_index = oct_plt_get_thread_index,
  .oct_plt_get_cache_line_size = oct_plt_get_cache_line_size,
};
