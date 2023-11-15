/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/pci/pci.h>

struct roc_model cnxk_model;
cnxk_plt_pci_device_t *cnxk_drv_roc_pci_devs;

/* clang-format off */

static pci_device_id_t cnxk_pci_device_ids[] = {

  { .vendor_id = PCI_VENDOR_ID_CAVIUM, .device_id = PCI_DEVID_CNXK_RVU_VF },
  { .vendor_id = PCI_VENDOR_ID_CAVIUM, .device_id = PCI_DEVID_CNXK_RVU_PF },
  { .vendor_id = PCI_VENDOR_ID_CAVIUM, .device_id = PCI_DEVID_CNXK_RVU_AF_VF },
  { .vendor_id = PCI_VENDOR_ID_CAVIUM, .device_id = PCI_DEVID_CNXK_RVU_SSO_TIM_VF },
  { .vendor_id = PCI_VENDOR_ID_CAVIUM, .device_id = PCI_DEVID_CNXK_RVU_SSO_TIM_PF },
  { .vendor_id = PCI_VENDOR_ID_CAVIUM, .device_id = PCI_DEVID_CNXK_RVU_NPA_VF },
  { .vendor_id = PCI_VENDOR_ID_CAVIUM, .device_id = PCI_DEVID_CNXK_DPI_VF },
  { .vendor_id = PCI_VENDOR_ID_CAVIUM, .device_id = PCI_DEVID_CNXK_RVU_SDP_VF },
  { .vendor_id = PCI_VENDOR_ID_CAVIUM, .device_id = PCI_DEVID_CN9K_RVU_CPT_VF },
  { .vendor_id = PCI_VENDOR_ID_CAVIUM, .device_id = PCI_DEVID_CN10K_RVU_CPT_VF },
  { .vendor_id = PCI_VENDOR_ID_CAVIUM, .device_id = PCI_DEVID_CNXK_RVU_NIX_INL_PF },
  { .vendor_id = PCI_VENDOR_ID_CAVIUM, .device_id = PCI_DEVID_CNXK_RVU_NIX_INL_VF },
  { 0 },
};

/* clang-format on */

clib_error_t *
cnxk_plt_model_init (void)
{
  clib_error_t *error = NULL;
  int rv;

  cnxk_plt_init ();
  rv = roc_model_init (&cnxk_model);
  if (rv)
    error = clib_error_return (0, "roc_model_init failed");

  return error;
}

void *
cnxk_pci_dev_probe (vlib_main_t *vm, vlib_pci_addr_t *addr,
		    vlib_pci_dev_handle_t *pci_handle)
{
  vlib_pci_device_info_t *info;
  vlib_pci_dev_handle_t handle;
  cnxk_plt_pci_device_t *dev;
  clib_error_t *error = NULL;
  int iter = 0;

  info = vlib_pci_get_device_info (vm, addr, &error);
  if (error)
    {
      error = clib_error_return (error,
				 "vlib_pci_get_device_info failed "
				 "on %U device",
				 format_vlib_pci_addr, addr);
      goto print_error;
    }

  error = vlib_pci_bind_to_uio (vm, addr, (char *) "vfio-pci", 0);
  if (error)
    {
      error = clib_error_return (error,
				 "vlib_pci_bind_to_uio failed "
				 "on %U device",
				 format_vlib_pci_addr, addr);
      goto free_pci_device_info;
    }

  error = vlib_pci_device_open (vm, addr, cnxk_pci_device_ids, &handle);
  if (error)
    {
      error = clib_error_return (error,
				 "vlib_pci_device_open failed "
				 "on %U device",
				 format_vlib_pci_addr, addr);
      goto free_pci_device_info;
    }

  error = vlib_pci_bus_master_enable (vm, handle);
  if (error)
    {
      error = clib_error_return (error,
				 "vlib_pci_bus_master_enable failed "
				 "on %U device",
				 format_vlib_pci_addr, addr);
      goto free_pci_device_info;
    }

  pool_get_zero (cnxk_drv_roc_pci_devs, dev);

  dev->index = dev - cnxk_drv_roc_pci_devs;
  dev->pci_handle = handle;
  dev->id.vendor_id = info->vendor_id;
  dev->id.device_id = info->device_id;
  dev->id.class_id = info->device_class;

  for (; iter < MAX_VFIO_PCI_BAR_REGIONS; iter++)
    {
      error = vlib_pci_map_region (vm, handle, iter,
				   (void **) &dev->mem_resource[iter].addr);
      /* Tolerate map errors for now, we will fail later in init stage */
      if (error)
	clib_error_free (error);
    }

  vlib_pci_set_private_data (vm, handle, dev->index);

  if (pci_handle)
    *pci_handle = handle;

  return dev;

free_pci_device_info:
  clib_mem_free (info);

print_error:
  if (error)
    clib_error_report (error);

  return NULL;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
