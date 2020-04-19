/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
