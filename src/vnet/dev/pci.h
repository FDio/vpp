/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_PCI_H_
#define _VNET_DEV_PCI_H_

#include <vppinfra/clib.h>
#include <vlib/pci/pci.h>
#include <vnet/dev/dev.h>

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
  vlib_pci_addr_t addr;
  vlib_pci_dev_handle_t handle;
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

vnet_dev_rv_t vnet_dev_pci_read_config_header (vlib_main_t *, vnet_dev_t *,
					       vlib_pci_config_hdr_t *);

vnet_dev_rv_t vnet_dev_pci_map_region (vlib_main_t *, vnet_dev_t *, u8,
				       void **);
vnet_dev_rv_t vnet_dev_pci_function_level_reset (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t vnet_dev_pci_bus_master_enable (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t vnet_dev_pci_bus_master_disable (vlib_main_t *, vnet_dev_t *);

#endif /* _VNET_DEV_PCI_H_ */
