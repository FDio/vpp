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

#include <stdbool.h>
#include <vppinfra/mhash.h>
#include <vlib/vlib.h>
#include <vlib/cdb/cdb.h>
#include <vlib/pci/pci.h>

VLIB_REGISTER_CDB_TYPE (u16) = {
  .name = "u16",
  .size = sizeof (u16),
};

VLIB_REGISTER_CDB_TYPE (u32) = {
  .name = "u32",
  .size = sizeof (u32),
};

VLIB_REGISTER_CDB_TYPE (string) = {
  .name = "string",
  .size = sizeof (void *),
};

VLIB_REGISTER_CDB_TYPE (bool) = {
  .name = "bool",
  .size = sizeof (int),
};

VLIB_REGISTER_CDB_TYPE (pci_addr) = {
  .name = "pci-addr",
  .size = sizeof (vlib_pci_addr_t),
};

VLIB_REGISTER_CDB_TYPE (mac_addr) = {
  .name = "mac-addr",
  .size = 6,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
