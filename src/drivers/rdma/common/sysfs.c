/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vppinfra/file.h>
#include <common/common.h>

uword
rdma_sysfs_path_to_pci_addr (char *path, vlib_pci_addr_t *addr)
{
  unformat_input_t in;
  u8 *s;
  uword rv;

  s = clib_file_get_resolved_basename ("%s", path);
  if (s == 0)
    return 0;

  unformat_init_string (&in, (char *) s, strlen ((char *) s));
  rv = unformat (&in, "%U", unformat_vlib_pci_addr, addr);
  unformat_free (&in);
  vec_free (s);
  return rv;
}
