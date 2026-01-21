/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_PCI_H_
#define _VNET_DEV_PCI_H_

#include <vppinfra/clib.h>
#include <vlib/pci/pci.h>
#include <vnet/dev/dev.h>

typedef void (vnet_dev_pci_intx_handler_fn_t) (vlib_main_t *vm,
					       vnet_dev_t *dev);
typedef void (vnet_dev_pci_msix_handler_fn_t) (vlib_main_t *vm,
					       vnet_dev_t *dev, u16 line);

typedef enum

{

  VNET_DEV_PCI_STD_CAP_PM = 0x01,

  VNET_DEV_PCI_STD_CAP_MSI = 0x05,

  VNET_DEV_PCI_STD_CAP_MSIX = 0x11,

  VNET_DEV_PCI_STD_CAP_EXP = 0x10,

} vnet_dev_pci_std_cap_t;

typedef enum

{

  VNET_DEV_PCI_EXT_CAP_AER = 0x0001,

  VNET_DEV_PCI_EXT_CAP_VC = 0x0002,

  VNET_DEV_PCI_EXT_CAP_DSN = 0x0003,

  VNET_DEV_PCI_EXT_CAP_LTR = 0x0018,

  VNET_DEV_PCI_EXT_CAP_SRIOV = 0x0010,

  VNET_DEV_PCI_EXT_CAP_REBAR = 0x0015,

} vnet_dev_pci_ext_cap_t;

typedef struct

{

  vlib_pci_addr_t addr;

  u16 vendor_id;

  u16 device_id;

  u16 sub_vendor_id;

  u16 sub_device_id;

  u32 class_code;

  u8 revision;

} vnet_dev_bus_pci_device_info_t;

typedef struct

{

  u8 pci_handle_valid : 1;

  u8 is_passive : 1;

  u16 n_msix_int;

  u16 n_msi_int;

  vlib_pci_addr_t addr;

  vlib_pci_dev_handle_t handle;

  vnet_dev_pci_intx_handler_fn_t *intx_handler;

  vnet_dev_pci_msix_handler_fn_t **msix_handlers;

  vnet_dev_pci_msix_handler_fn_t **msi_handlers;

} vnet_dev_bus_pci_device_data_t;

static_always_inline vnet_dev_bus_pci_device_data_t *

vnet_dev_get_bus_pci_device_data (vnet_dev_t *dev)

{

  return (void *) dev->bus_data;
}

static_always_inline vlib_pci_dev_handle_t

vnet_dev_get_pci_handle (vnet_dev_t *dev)

{

  return ((vnet_dev_bus_pci_device_data_t *) (dev->bus_data))->handle;
}

static_always_inline vlib_pci_addr_t

vnet_dev_get_pci_addr (vnet_dev_t *dev)

{

  return ((vnet_dev_bus_pci_device_data_t *) (dev->bus_data))->addr;
}

static_always_inline vlib_pci_dev_handle_t

vnet_dev_get_pci_n_msix_interrupts (vnet_dev_t *dev)

{

  return vnet_dev_get_bus_pci_device_data (dev)->n_msix_int;
}

format_function_t format_dev_pci_device_name_from_ids;

format_function_t format_dev_pci_vendor_name_from_ids;

vnet_dev_rv_t vnet_dev_pci_config_read (vlib_main_t *, vnet_dev_t *, u32, u32, u32 *);
vnet_dev_rv_t vnet_dev_pci_config_write (vlib_main_t *, vnet_dev_t *, u32, u32, u32);

vnet_dev_rv_t vnet_dev_pci_read_config_header (vlib_main_t *, vnet_dev_t *,
					       vlib_pci_config_hdr_t *);
vnet_dev_rv_t vnet_dev_pci_read_config (vlib_main_t *, vnet_dev_t *,
					vlib_pci_config_t *);
vnet_dev_rv_t vnet_dev_pci_read_config_ext (vlib_main_t *, vnet_dev_t *,
					    vlib_pci_config_ext_t *);
vnet_dev_rv_t vnet_dev_pci_map_region (vlib_main_t *, vnet_dev_t *, u8,
				       void **);
vnet_dev_rv_t vnet_dev_pci_function_level_reset (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t vnet_dev_pci_bus_master_enable (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t vnet_dev_pci_bus_master_disable (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t vnet_dev_pci_set_power_state (vlib_main_t *, vnet_dev_t *, u8);
vnet_dev_rv_t vnet_dev_pci_get_power_state (vlib_main_t *, vnet_dev_t *, u8 *);

u8 vnet_dev_pci_find_next_std_capa_offset (vlib_main_t *, vnet_dev_t *, u8, u8);

vnet_dev_rv_t vnet_dev_pci_intx_add_handler (vlib_main_t *, vnet_dev_t *,
					     vnet_dev_pci_intx_handler_fn_t *);
vnet_dev_rv_t vnet_dev_pci_intx_remove_handler (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t vnet_dev_pci_msix_add_handler (vlib_main_t *, vnet_dev_t *,
					     vnet_dev_pci_msix_handler_fn_t *,
					     u16, u16);
vnet_dev_rv_t vnet_dev_pci_msix_remove_handler (vlib_main_t *, vnet_dev_t *,
						u16, u16);
vnet_dev_rv_t vnet_dev_pci_msix_enable (vlib_main_t *, vnet_dev_t *, u16, u16);
vnet_dev_rv_t vnet_dev_pci_msix_disable (vlib_main_t *, vnet_dev_t *, u16,
					 u16);
vnet_dev_rv_t vnet_dev_pci_msi_add_handler (vlib_main_t *, vnet_dev_t *,
					    vnet_dev_pci_msix_handler_fn_t *,
					    u16, u16);
vnet_dev_rv_t vnet_dev_pci_msi_remove_handler (vlib_main_t *, vnet_dev_t *,
					       u16, u16);
vnet_dev_rv_t vnet_dev_pci_msi_enable (vlib_main_t *, vnet_dev_t *, u16, u16);
vnet_dev_rv_t vnet_dev_pci_msi_disable (vlib_main_t *, vnet_dev_t *, u16, u16);
void vnet_dev_pci_msix_set_polling_thread (vlib_main_t *, vnet_dev_t *, u16,
					   u16);

static_always_inline u16
vnet_dev_get_pci_n_msi_interrupts (vnet_dev_t *dev)
{
  return vnet_dev_get_bus_pci_device_data (dev)->n_msi_int;
}

#endif /* _VNET_DEV_PCI_H_ */
