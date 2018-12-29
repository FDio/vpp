/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef VFIO_NOIOMMU_IOMMU
#define VFIO_NOIOMMU_IOMMU 8
#endif

linux_vfio_main_t vfio_main;

clib_error_t *
vfio_map_physmem_page (vlib_main_t * vm, void *addr)
{
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  linux_vfio_main_t *lvm = &vfio_main;
  struct vfio_iommu_type1_dma_map dm = { 0 };
  uword log2_page_size = vpm->pmalloc_main->def_log2_page_sz;
  uword physmem_start = pointer_to_uword (vpm->pmalloc_main->base);

  if (lvm->container_fd == -1)
    return clib_error_return (0, "No cointainer fd");

  u32 page_index = vlib_physmem_get_page_index (vm, addr);

  if (clib_bitmap_get (lvm->physmem_pages_mapped, page_index))
    {
      vlib_log_debug (lvm->log_default, "map DMA va:%p page:%u already "
		      "mapped", addr, page_index);
      return 0;
    }

  dm.argsz = sizeof (struct vfio_iommu_type1_dma_map);
  dm.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
  dm.vaddr = physmem_start + (page_index << log2_page_size);
  dm.size = 1ULL << log2_page_size;
  dm.iova = dm.vaddr;
  vlib_log_debug (lvm->log_default, "map DMA page:%u va:0x%lx iova:%lx "
		  "size:0x%lx", page_index, dm.vaddr, dm.iova, dm.size);

  if (ioctl (lvm->container_fd, VFIO_IOMMU_MAP_DMA, &dm) == -1)
    {
      vlib_log_err (lvm->log_default, "map DMA page:%u va:0x%lx iova:%lx "
		    "size:0x%lx failed, error %s (errno %d)", page_index,
		    dm.vaddr, dm.iova, dm.size, strerror (errno), errno);
      return clib_error_return_unix (0, "physmem DMA map failed");
    }

  lvm->physmem_pages_mapped = clib_bitmap_set (lvm->physmem_pages_mapped,
					       page_index, 1);
  return 0;
}

static linux_pci_vfio_iommu_group_t *
get_vfio_iommu_group (int group)
{
  linux_vfio_main_t *lvm = &vfio_main;
  uword *p;

  p = hash_get (lvm->iommu_pool_index_by_group, group);

  return p ? pool_elt_at_index (lvm->iommu_groups, p[0]) : 0;
}

clib_error_t *
linux_vfio_get_container_fd ()
{
  linux_vfio_main_t *lvm = &vfio_main;
  int fd;


  if ((fd = open ("/dev/vfio/vfio", O_RDWR)) == -1)
    return clib_error_return_unix (0, "failed to open VFIO container");

  if (ioctl (fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION)
    {
      close (fd);
      return clib_error_return_unix (0, "incompatible VFIO version");
    }

  lvm->iommu_pool_index_by_group = hash_create (0, sizeof (uword));
  lvm->container_fd = fd;

  return 0;
}

static clib_error_t *
open_vfio_iommu_group (int group, int is_noiommu)
{
  linux_vfio_main_t *lvm = &vfio_main;
  linux_pci_vfio_iommu_group_t *g;
  clib_error_t *err = 0;
  struct vfio_group_status group_status;
  u8 *s = 0;
  int fd;

  if (lvm->container_fd == -1)
    {
      err = linux_vfio_get_container_fd ();
      if (err)
	return err;
    }

  g = get_vfio_iommu_group (group);
  if (g)
    {
      g->refcnt++;
      return 0;
    }
  s = format (s, "/dev/vfio/%s%u%c", is_noiommu ? "noiommu-" : "", group, 0);
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
      if (is_noiommu)
	lvm->iommu_mode = VFIO_NOIOMMU_IOMMU;
      else
	lvm->iommu_mode = VFIO_TYPE1_IOMMU;

      if (ioctl (lvm->container_fd, VFIO_SET_IOMMU, lvm->iommu_mode) < 0)
	{
	  err = clib_error_return_unix (0, "ioctl(VFIO_SET_IOMMU) "
					"'/dev/vfio/vfio'");
	  goto error;
	}
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
linux_vfio_group_get_device_fd (vlib_pci_addr_t * addr, int *fdp,
				int *is_noiommu)
{
  clib_error_t *err = 0;
  linux_pci_vfio_iommu_group_t *g;
  u8 *s = 0;
  int iommu_group;
  u8 *tmpstr;
  int fd;

  *is_noiommu = 0;
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

  s = format (s, "/sys/bus/pci/devices/%U/iommu_group/name",
	      format_vlib_pci_addr, addr);
  err = clib_sysfs_read ((char *) s, "%s", &tmpstr);
  if (err == 0)
    {
      if (strncmp ((char *) tmpstr, "vfio-noiommu", 12) == 0)
	*is_noiommu = 1;

      vec_free (tmpstr);
    }
  else
    clib_error_free (err);
  vec_reset_length (s);
  if ((err = open_vfio_iommu_group (iommu_group, *is_noiommu)))
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

  lvm->log_default = vlib_log_register_class ("vfio", 0);
  lvm->container_fd = -1;

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
