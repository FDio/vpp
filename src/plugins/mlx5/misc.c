/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/*
 *   WARNING!
 *   This driver is not intended for production use and it is unsupported.
 *   It is provided for educational use only.
 *   Please use supported DPDK driver instead.
 */


#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <mlx5/mlx5.h>

clib_error_t *
mlx5_physmem_alloc (vlib_main_t * vm, mlx5_device_t * md, uword sz,
		    uword al, void **ptr)
{
  *ptr = vlib_physmem_alloc_aligned (vm, sz, al);

  if (*ptr == 0)
    return vlib_physmem_last_error (vm);
  return vlib_pci_map_dma (vm, md->pci_dev_handle, *ptr);
}

#include <mlx5/mlx5.h>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
