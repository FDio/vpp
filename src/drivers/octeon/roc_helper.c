/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vnet/vnet.h>
#include <vlib/pci/pci.h>
#include <vlib/linux/vfio.h>
#include <base/roc_api.h>
#include "common.h"
#include "octeon.h"

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
      align = ((align + ROC_ALIGN - 1) & ~(ROC_ALIGN - 1));
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

static void *
oct_plt_realloc (void *addr, u32 size, u32 align)
{
  align = CLIB_CACHE_LINE_ROUND (align);
  size = CLIB_CACHE_LINE_ROUND (size);

  if (align)
    return clib_mem_realloc_aligned (addr, size, align);
  else
    return clib_mem_realloc (addr, size);
}

static oct_plt_memzone_t *
oct_plt_memzone_lookup (const char *name)
{
  oct_plt_memzone_t *mem_pool;

  pool_foreach (mem_pool, memzone_list.mem_pool)
    {
      if (!strcmp (mem_pool->name, name))
	return mem_pool;
    }

  return 0;
}

static int
oct_plt_memzone_free (const oct_plt_memzone_t *mz)
{
  if (!mz || !oct_plt_memzone_lookup (mz->name))
    return -EINVAL;

  pool_put (memzone_list.mem_pool, mz);

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
  strcpy (mem_pool->name, name);

  return mem_pool;
}

static void
plt_msix_handler (vlib_main_t *vm, vlib_pci_dev_handle_t handle, uint16_t line)
{
  vnet_dev_t *dev = (vnet_dev_t *) vlib_pci_get_private_data (vm, handle);
  oct_device_t *cd = vnet_dev_get_data (dev);

  if (cd->msix_handler && cd->msix_handler[line].fn)
    cd->msix_handler[line].fn (cd->msix_handler[line].data);
}

static int
oct_plt_get_num_vectors (oct_pci_dev_handle_t handle)
{
  vlib_main_t *vm = vlib_get_main ();

  return vlib_pci_get_num_msix_interrupts (vm, handle);
}

static int
oct_plt_intr_enable (oct_pci_dev_handle_t handle, uint16_t start,
		     uint16_t count, uint8_t enable,
		     enum oct_msix_rsrc_op_t op)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_t *dev = (vnet_dev_t *) vlib_pci_get_private_data (vm, handle);
  oct_device_t *cd = vnet_dev_get_data (dev);
  clib_error_t *error = NULL;

  if (op == OCT_MSIX_RSRC_ALLOC)
    {
      if (cd->msix_handler)
	{
	  clib_warning ("MSIX handlers already allocated\n");
	  return -EINVAL;
	}
      cd->msix_handler = malloc (sizeof (*cd->msix_handler) * (start + count));
      if (!cd->msix_handler)
	{
	  clib_warning ("MSIX handlers alilocation failed\n");
	  return -ENOMEM;
	}
    }
  if (enable)
    error = vlib_pci_enable_msix_irq (vm, handle, start, count);
  else
    error = vlib_pci_disable_msix_irq (vm, handle, start, count);
  if (error)
    {
      clib_error_report (error);
      return -EINVAL;
    }
  if (op == OCT_MSIX_RSRC_FREE)
    {
      if (cd->msix_handler)
	free (cd->msix_handler);
    }

  return 0;
}

static int
oct_plt_intr_config (oct_pci_dev_handle_t handle, uint32_t vec,
		     plt_msix_handler_function_t handler, void *data,
		     int enable)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_t *dev = (vnet_dev_t *) vlib_pci_get_private_data (vm, handle);
  oct_device_t *cd = vnet_dev_get_data (dev);
  clib_error_t *error = NULL;

  /* Skip AF_PF_MBOX interrupt FIXME */
  if (vec == RVU_PF_INT_VEC_AFPF_MBOX)
    return 0;

  if (enable)
    {
      error =
	vlib_pci_register_msix_handler (vm, handle, vec, 1, plt_msix_handler);
      if (error)
	{
	  clib_error_report (error);
	  return -EINVAL;
	}
      if (cd->msix_handler)
	{
	  cd->msix_handler[vec].fn = handler;
	  cd->msix_handler[vec].vec = vec;
	  cd->msix_handler[vec].data = data;
	}
      error = vlib_pci_enable_msix_irq (vm, handle, vec, 1);
      if (error)
	{
	  clib_error_report (error);
	  return -EINVAL;
	}
    }
  else
    {
      error = vlib_pci_disable_msix_irq (vm, handle, vec, 1);
      if (error)
	{
	  clib_error_report (error);
	  return -EINVAL;
	}
      error = vlib_pci_unregister_msix_handler (vm, handle, vec, 1);
      if (error)
	{
	  clib_error_report (error);
	  return -EINVAL;
	}
      if (cd->msix_handler)
	{
	  cd->msix_handler[vec].fn = NULL;
	  cd->msix_handler[vec].data = NULL;
	}
    }

  return 0;
}

static inline __attribute__ ((__always_inline__)) int
plt_intr_max_intr_get (const struct plt_intr_handle *intr_handle)
{
  if (!intr_handle)
    return -EINVAL;

  return intr_handle->max_intr;
}

static inline __attribute__ ((__always_inline__)) int
plt_intr_max_intr_set (struct plt_intr_handle *intr_handle, int max_intr)
{
  if (!intr_handle)
    return -EINVAL;

  intr_handle->max_intr = max_intr;

  return 0;
}

static int
irq_get_info (struct plt_intr_handle *intr_handle)
{
  int num_vec;

  num_vec = oct_plt_get_num_vectors (intr_handle->pci_handle);
  if (num_vec == 0)
    {
      plt_err ("HW max=%d > PLT_MAX_RXTX_INTR_VEC_ID: %d", num_vec,
	       PLT_MAX_RXTX_INTR_VEC_ID);
      plt_intr_max_intr_set (intr_handle, PLT_MAX_RXTX_INTR_VEC_ID);
    }
  else
    {
      if (plt_intr_max_intr_set (intr_handle, num_vec))
	return -1;
    }

  return 0;
}

static int
irq_init (struct plt_intr_handle *intr_handle)
{
  int rc = oct_plt_intr_enable (intr_handle->pci_handle, 0,
				plt_intr_max_intr_get (intr_handle), 0,
				OCT_MSIX_RSRC_ALLOC);

  if (rc)
    plt_err ("Failed to set irqs vector rc=%d", rc);

  return rc;
}

static int
oct_plt_irq_register (struct oct_pci_intr_handle *intr_handle,
		      oct_plt_pci_intr_callback_fn cb, void *data,
		      unsigned int vec)
{
  /* If no max_intr read from VFIO */
  if (plt_intr_max_intr_get (intr_handle) == 0)
    {
      irq_get_info (intr_handle);
      irq_init (intr_handle);
    }

  if (vec > (uint32_t) plt_intr_max_intr_get (intr_handle))
    {
      plt_err ("Error registering MSI-X interrupts vec:%d > %d", vec,
	       plt_intr_max_intr_get (intr_handle));
      return -EINVAL;
    }

  oct_plt_intr_config (intr_handle->pci_handle, vec, cb, data, 1);

  return 0;
}

static void
oct_plt_irq_unregister (struct oct_pci_intr_handle *intr_handle,
			oct_plt_pci_intr_callback_fn cb, void *data,
			unsigned int vec)
{
  if (vec > (uint32_t) plt_intr_max_intr_get (intr_handle))
    {
      plt_err ("Error unregistering MSI-X interrupts vec:%d > %d", vec,
	       plt_intr_max_intr_get (intr_handle));
      return;
    }

  oct_plt_intr_config (intr_handle->pci_handle, vec, cb, data, 0);
}

static int
oct_plt_irq_disable (struct oct_pci_intr_handle *intr_handle)
{
  int rc = -EINVAL;

  if (!intr_handle)
    return rc;

  /* Clear max_intr to indicate re-init next time */
  rc = oct_plt_intr_enable (intr_handle->pci_handle, 0,
			    plt_intr_max_intr_get (intr_handle), 0,
			    OCT_MSIX_RSRC_FREE);
  plt_intr_max_intr_set (intr_handle, 0);
  return rc;
}

static int
oct_plt_irq_reconfigure (struct oct_pci_intr_handle *intr_handle,
			 uint16_t max_intr)
{
  /* Disable interrupts if enabled. */
  if (plt_intr_max_intr_get (intr_handle))
    oct_plt_irq_disable (intr_handle);

  plt_intr_max_intr_set (intr_handle, max_intr);
  return irq_init (intr_handle);
}

oct_plt_init_param_t oct_plt_init_param = {
  .oct_plt_log_reg_class = vlib_log_register_class,
  .oct_plt_log = oct_plt_log,
  .oct_plt_free = oct_plt_free,
  .oct_plt_zmalloc = oct_plt_zmalloc,
  .oct_plt_realloc = oct_plt_realloc,
  .oct_plt_memzone_free = oct_plt_memzone_free,
  .oct_plt_memzone_lookup = oct_plt_memzone_lookup,
  .oct_plt_memzone_reserve_aligned = oct_plt_memzone_reserve_aligned,
  .oct_plt_spinlock_init = oct_plt_spinlock_init,
  .oct_plt_spinlock_lock = oct_plt_spinlock_lock,
  .oct_plt_spinlock_unlock = oct_plt_spinlock_unlock,
  .oct_plt_spinlock_trylock = oct_plt_spinlock_trylock,
  .oct_plt_get_thread_index = oct_plt_get_thread_index,
  .oct_plt_get_cache_line_size = oct_plt_get_cache_line_size,
  .oct_plt_irq_reconfigure = oct_plt_irq_reconfigure,
  .oct_plt_irq_register = oct_plt_irq_register,
  .oct_plt_irq_unregister = oct_plt_irq_unregister,
  .oct_plt_irq_disable = oct_plt_irq_disable
};
