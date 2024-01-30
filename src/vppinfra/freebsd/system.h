/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Tom Jone <thj@freebsd.org>
 */

#ifndef included_freebsd_system_h
#define included_freebsd_system_h

#include <vppinfra/error.h>

/*
 * Provide clib_sysfs methods as a stop gap while bringing freebsd equivalents
 */

clib_error_t *clib_sysfs_write (char *file_name, char *fmt, ...);

clib_error_t *clib_sysfs_read (char *file_name, char *fmt, ...);

clib_error_t *clib_sysfs_set_nr_hugepages (int numa_node, int log2_page_size,
					   int nr);
clib_error_t *clib_sysfs_get_nr_hugepages (int numa_node, int log2_page_size,
					   int *v);
clib_error_t *clib_sysfs_get_free_hugepages (int numa_node, int log2_page_size,
					     int *v);
clib_error_t *clib_sysfs_get_surplus_hugepages (int numa_node,
						int log2_page_size, int *v);
clib_error_t *clib_sysfs_prealloc_hugepages (int numa_node, int log2_page_size,
					     int nr);

uword *clib_sysfs_list_to_bitmap (char *filename);

#endif /* included_freebsd_system_h */
