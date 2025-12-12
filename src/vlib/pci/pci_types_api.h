/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#ifndef __PCI_TYPES_API_H__
#define __PCI_TYPES_API_H__

#include <vlibapi/api_types.h>
#include <vlib/pci/pci.h>

struct _vl_api_pci_address;

extern void pci_address_decode (const struct _vl_api_pci_address * in, vlib_pci_addr_t * out);
extern void pci_address_encode (const vlib_pci_addr_t * in, struct _vl_api_pci_address * out);

#endif /* PCI_TYPES_API_H */
