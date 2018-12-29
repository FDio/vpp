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

#ifndef included_vlib_linux_vfio_h
#define included_vlib_linux_vfio_h

typedef struct
{
  int group;
  int fd;
  int refcnt;
} linux_pci_vfio_iommu_group_t;

typedef struct
{
  int container_fd;

  /* VFIO */
  int iommu_mode;

  /* pool of IOMMU groups */
  linux_pci_vfio_iommu_group_t *iommu_groups;

  /* iommu group pool index by group id  hash */
  uword *iommu_pool_index_by_group;

  clib_bitmap_t *physmem_pages_mapped;

  /* logging */
  vlib_log_class_t log_default;
} linux_vfio_main_t;

extern linux_vfio_main_t vfio_main;

clib_error_t *linux_vfio_init (vlib_main_t * vm);
clib_error_t *linux_vfio_get_container_fd ();
clib_error_t *vfio_map_physmem_page (vlib_main_t * vm, void *addr);
clib_error_t *linux_vfio_group_get_device_fd (vlib_pci_addr_t * addr,
					      int *fd, int *is_noiommu);


#endif /* included_vlib_linux_vfio_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
