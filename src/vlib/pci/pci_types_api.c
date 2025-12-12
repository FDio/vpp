/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#include <vlibapi/api_types.h>
#include <vlib/pci/pci_types_api.h>

#include <vlib/pci/pci_types.api_types.h>

void
pci_address_decode (const vl_api_pci_address_t * in, vlib_pci_addr_t * out)
{
  out->domain = in->domain;
  out->bus = in->bus;
  out->slot = in->slot;
  out->function = in->function;
}

void
pci_address_encode (const vlib_pci_addr_t * in, vl_api_pci_address_t * out)
{
  out->domain = in->domain;
  out->bus = in->bus;
  out->slot = in->slot;
  out->function = in->function;
}
