/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
clib_error_t *vfio_map_physmem_page (vlib_main_t * vm, void *addr);
clib_error_t *linux_vfio_group_get_device_fd (vlib_pci_addr_t * addr,
					      int *fd, int *is_noiommu);

format_function_t format_vfio_region_info;
format_function_t format_vfio_irq_set;

#endif /* included_vlib_linux_vfio_h */
