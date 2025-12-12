/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef included_linux_sysfs_h
#define included_linux_sysfs_h

#include <vppinfra/error.h>
#include <vppinfra/bitmap.h>

clib_error_t *clib_sysfs_write (char *file_name, char *fmt, ...);

clib_error_t *clib_sysfs_read (char *file_name, char *fmt, ...);

clib_error_t *clib_sysfs_set_nr_hugepages (int numa_node,
					   int log2_page_size, int nr);
clib_error_t *clib_sysfs_get_nr_hugepages (int numa_node,
					   int log2_page_size, int *v);
clib_error_t *clib_sysfs_get_free_hugepages (int numa_node,
					     int log2_page_size, int *v);
clib_error_t *clib_sysfs_get_surplus_hugepages (int numa_node,
						int log2_page_size, int *v);
clib_error_t *clib_sysfs_prealloc_hugepages (int numa_node,
					     int log2_page_size, int nr);

uword *clib_sysfs_read_bitmap (char *fmt, ...);

#endif /* included_linux_sysfs_h */
