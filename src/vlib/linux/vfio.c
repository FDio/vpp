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
 * pci.c: Linux user space PCI bus management.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/vfio.h>
#include <sys/ioctl.h>

#include <vppinfra/linux/sysfs.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vlib/linux/vfio.h>
#include <vlib/physmem.h>

linux_vfio_main_t vfio_main;

static int
map_regions (vlib_main_t * vm, int fd)
{
  vlib_physmem_main_t *vpm = &physmem_main;
  vlib_physmem_region_t *pr;
  struct vfio_iommu_type1_dma_map dm = { 0 };
  int i;

  dm.argsz = sizeof (struct vfio_iommu_type1_dma_map);
  dm.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

  /* *INDENT-OFF* */
  pool_foreach (pr, vpm->regions,
    {
      vec_foreach_index (i, pr->page_table)
        {
	  int rv;
	  dm.vaddr = pointer_to_uword (pr->mem) + (i << pr->log2_page_size);
	  dm.size = 1 << pr->log2_page_size;
	  dm.iova = dm.vaddr;
	  if ((rv = ioctl (fd, VFIO_IOMMU_MAP_DMA, &dm)))
	    return rv;
        }
    });
  /* *INDENT-ON* */
  return 0;
}

void
linux_vfio_dma_map_regions (vlib_main_t * vm)
{
  linux_vfio_main_t *lvm = &vfio_main;

  if (lvm->container_fd != -1)
    map_regions (vm, lvm->container_fd);
}

static linux_pci_vfio_iommu_group_t *
get_vfio_iommu_group (int group)
{
  linux_vfio_main_t *lvm = &vfio_main;
  uword *p;

  p = hash_get (lvm->iommu_pool_index_by_group, group);

  return p ? pool_elt_at_index (lvm->iommu_groups, p[0]) : 0;
}

static clib_error_t *
open_vfio_iommu_group (int group)
{
  linux_vfio_main_t *lvm = &vfio_main;
  linux_pci_vfio_iommu_group_t *g;
  clib_error_t *err = 0;
  struct vfio_group_status group_status;
  u8 *s = 0;
  int fd;

  g = get_vfio_iommu_group (group);
  if (g)
    {
      g->refcnt++;
      return 0;
    }
  s = format (s, "/dev/vfio/%u%c", group, 0);
  fd = open ((char *) s, O_RDWR);
  if (fd < 0)
    return clib_error_return_unix (0, "open '%s'", s);

  group_status.argsz = sizeof (group_status);
  if (ioctl (fd, VFIO_GROUP_GET_STATUS, &group_status) < 0)
    {
      err = clib_error_return_unix (0, "ioctl(VFIO_GROUP_GET_STATUS) '%s'",
				    s);
      goto error;
    }

  if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE))
    {
      err = clib_error_return (0, "iommu group %d is not viable (not all "
			       "devices in this group bound to vfio-pci)",
			       group);
      goto error;
    }

  if (ioctl (fd, VFIO_GROUP_SET_CONTAINER, &lvm->container_fd) < 0)
    {
      err = clib_error_return_unix (0, "ioctl(VFIO_GROUP_SET_CONTAINER) '%s'",
				    s);
      goto error;
    }

  if (lvm->iommu_mode == 0)
    {
      if (ioctl (lvm->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU) < 0)
	{
	  err = clib_error_return_unix (0, "ioctl(VFIO_SET_IOMMU) "
					"'/dev/vfio/vfio'");
	  goto error;
	}
      lvm->iommu_mode = VFIO_TYPE1_IOMMU;
    }


  pool_get (lvm->iommu_groups, g);
  g->fd = fd;
  g->refcnt = 1;
  hash_set (lvm->iommu_pool_index_by_group, group, g - lvm->iommu_groups);
  vec_free (s);
  return 0;
error:
  close (fd);
  return err;
}

clib_error_t *
linux_vfio_group_get_device_fd (vlib_pci_addr_t * addr, int *fdp)
{
  clib_error_t *err = 0;
  linux_pci_vfio_iommu_group_t *g;
  u8 *s = 0;
  int iommu_group;
  u8 *tmpstr;
  int fd;

  s = format (s, "/sys/bus/pci/devices/%U/iommu_group", format_vlib_pci_addr,
	      addr);
  tmpstr = clib_sysfs_link_to_name ((char *) s);
  if (tmpstr)
    {
      iommu_group = atoi ((char *) tmpstr);
      vec_free (tmpstr);
    }
  else
    {
      err = clib_error_return (0, "Cannot find IOMMU group for PCI device ",
			       "'%U'", format_vlib_pci_addr, addr);
      goto error;
    }
  vec_reset_length (s);

  if ((err = open_vfio_iommu_group (iommu_group)))
    return err;

  g = get_vfio_iommu_group (iommu_group);

  s = format (s, "%U%c", format_vlib_pci_addr, addr, 0);
  if ((fd = ioctl (g->fd, VFIO_GROUP_GET_DEVICE_FD, (char *) s)) < 0)
    {
      err = clib_error_return_unix (0, "ioctl(VFIO_GROUP_GET_DEVICE_FD) '%U'",
				    format_vlib_pci_addr, addr);
      goto error;
    }
  vec_reset_length (s);

  *fdp = fd;

error:
  vec_free (s);
  return err;
}

clib_error_t *
linux_vfio_init (vlib_main_t * vm)
{
  linux_vfio_main_t *lvm = &vfio_main;
  int fd;

  fd = open ("/dev/vfio/vfio", O_RDWR);

  /* check if iommu is available */
  if (fd != -1)
    {
      if (ioctl (fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION)
	{
	  close (fd);
	  fd = -1;
	}
      else if (ioctl (fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU) == 1)
	lvm->flags |= LINUX_VFIO_F_HAVE_IOMMU;
    }

  lvm->iommu_pool_index_by_group = hash_create (0, sizeof (uword));
  lvm->container_fd = fd;
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
