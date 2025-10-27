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

typedef struct
{
  vlib_pci_addr_t addr;
  u16 vendor_id;
  u16 device_id;
  u8 revision;
} vnet_dev_bus_pci_device_info_t;

typedef struct
{
  u8 pci_handle_valid : 1;
  u16 n_msix_int;
  vlib_pci_addr_t addr;
  vlib_pci_dev_handle_t handle;
  vnet_dev_pci_intx_handler_fn_t *intx_handler;
  vnet_dev_pci_msix_handler_fn_t **msix_handlers;
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
void vnet_dev_pci_msix_set_polling_thread (vlib_main_t *, vnet_dev_t *, u16,
					   u16);

#endif /* _VNET_DEV_PCI_H_ */
