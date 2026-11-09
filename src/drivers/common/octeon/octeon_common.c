/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
 */

#include <sys/mman.h>

#include <vnet/dev/bus/pci.h>
#include <octeon_common.h>

struct roc_model oct_model;

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "common",
};

static struct
{
  u16 device_id;
  oct_device_type_t type;
  char *description;
} oct_dev_types[] = {

#define _(id, device_type, desc)                                                                   \
  { .device_id = (id), .type = OCT_DEVICE_TYPE_##device_type, .description = (desc) }

  _ (0xa063, RVU_PF, "Marvell Octeon Resource Virtualization Unit PF"),
  _ (0xa064, RVU_VF, "Marvell Octeon Resource Virtualization Unit VF"),
  _ (0xa0f8, LBK_VF, "Marvell Octeon Loopback Unit VF"),
  _ (0xa0f7, SDP_VF, "Marvell Octeon System DPI Packet Interface Unit VF"),
  _ (0xa0f3, O10K_CPT_VF, "Marvell Octeon-10 Cryptographic Accelerator Unit VF"),
  _ (0xa0fe, O9K_CPT_VF, "Marvell Octeon-9 Cryptographic Accelerator Unit VF"),
#undef _
};

u8 *
oct_dev_probe (vnet_dev_probe_args_t *args, int cpt)
{
  vnet_dev_bus_pci_device_info_t *di = args->device_info;

  if (di->vendor_id != 0x177d) /* Cavium */
    return 0;

  FOREACH_ARRAY_ELT (dt, oct_dev_types)
    {
      if (dt->device_id == di->device_id && OCT_DEVTYPE_IS_CPT (dt->type) == cpt)
	return format (0, "%s", dt->description);
    }

  return 0;
}

vnet_dev_rv_t
cnx_return_roc_err (vnet_dev_t *dev, int rrv, char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  u8 *s = va_format (0, fmt, &va);
  va_end (va);

  log_err (dev, "%v: %s [%d]", s, roc_error_msg_get (rrv), rrv);
  vec_free (s);

  return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
}

static vnet_dev_rv_t
oct_dev_pci_map_region (vlib_main_t *vm, vnet_dev_t *dev, u32 bar, void **addr)
{
  uword sys_page_sz = clib_mem_get_page_size ();
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);

  if (sys_page_sz < OCT_BAR_ALIGN)
    {
      u64 bar_size = 0;
      clib_error_t *err;
      uword va, reserve_sz;

      err = vlib_pci_get_region_size (vm, h, bar, &bar_size);
      if (err)
	{
	  clib_error_free (err);
	  bar_size = OCT_BAR_DEFAULT_SIZE;
	}

      va = clib_mem_vm_reserve (0, bar_size, 16);
      if (va != ~0)
	{
	  /* clib_mem_vm_reserve rounds size up to alignment and leaves a
	   * guard page before va; release the entire reservation so
	   * vlib_pci_map_region_fixed can re-map at this address. */
	  reserve_sz = round_pow2 (bar_size, OCT_BAR_ALIGN);
	  munmap ((void *) (va - sys_page_sz), reserve_sz + sys_page_sz);
	  err = vlib_pci_map_region_fixed (vm, h, bar, (u8 *) va, addr);
	  if (err)
	    {
	      clib_error_free (err);
	      return VNET_DEV_ERR_BUS;
	    }
	  return VNET_DEV_OK;
	}
    }

  return vnet_dev_pci_map_region (vm, dev, bar, addr);
}

vnet_dev_rv_t
oct_dev_pci_init (vlib_main_t *vm, vnet_dev_t *dev, int cpt)
{
  oct_dev_common_t *cd = vnet_dev_get_data (dev);
  vlib_pci_config_hdr_t pci_hdr;
  vnet_dev_rv_t rv;

  rv = vnet_dev_pci_read_config_header (vm, dev, &pci_hdr);
  if (rv != VNET_DEV_OK)
    return rv;

  if (pci_hdr.vendor_id != 0x177d)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  FOREACH_ARRAY_ELT (dt, oct_dev_types)
    {
      if (dt->device_id == pci_hdr.device_id)
	cd->type = dt->type;
    }

  if (cd->type == OCT_DEVICE_TYPE_UNKNOWN || OCT_DEVTYPE_IS_CPT (cd->type) != cpt)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  cd->plt_pci_dev = (struct plt_pci_device) {
    .id.vendor_id = pci_hdr.vendor_id,
    .id.device_id = pci_hdr.device_id,
    .id.class_id = pci_hdr.class << 16 | pci_hdr.subclass,
    .pci_handle = vnet_dev_get_pci_handle (dev),
  };
  cd->msix_handler = NULL;

  rv = oct_dev_pci_map_region (vm, dev, 2, &cd->plt_pci_dev.mem_resource[2].addr);
  if (rv != VNET_DEV_OK)
    return rv;

  if (!(roc_model_is_cn10k () && OCT_DEVTYPE_IS_VF (cd->type)))
    {
      rv = oct_dev_pci_map_region (vm, dev, 4, &cd->plt_pci_dev.mem_resource[4].addr);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  STATIC_ASSERT (sizeof (cd->plt_pci_dev.name) == sizeof (dev->device_id), "");

  rv = vnet_dev_pci_bus_master_enable (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  strncpy ((char *) cd->plt_pci_dev.name, dev->device_id, sizeof (dev->device_id));

  cd->plt_pci_dev.intr_handle = malloc (sizeof (struct oct_pci_intr_handle));
  if (!cd->plt_pci_dev.intr_handle)
    return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
  memset (cd->plt_pci_dev.intr_handle, 0x0, sizeof (struct oct_pci_intr_handle));
  cd->plt_pci_dev.intr_handle->pci_handle = cd->plt_pci_dev.pci_handle;

  return VNET_DEV_OK;
}

vnet_dev_rv_t
oct_roc_init (void)
{
  if (oct_plt_init (&oct_plt_init_param))
    return VNET_DEV_ERR_INIT_FAILED;

  if (roc_model_init (&oct_model))
    return VNET_DEV_ERR_INIT_FAILED;

#ifdef PLATFORM_OCTEON9
  if (!roc_model_is_cn9k ())
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
#else
  if (!roc_model_is_cn10k ())
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
#endif

  return VNET_DEV_OK;
}
