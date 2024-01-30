/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Tom Jone <thj@freebsd.org>
 */

#include <sys/cdefs.h>
#define _WANT_FREEBSD_BITSET

#include <sys/param.h>
#include <sys/types.h>
#include <sys/cpuset.h>
#include <sys/domainset.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <vppinfra/clib.h>
#include <vppinfra/clib_error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>

__clib_export clib_error_t *
clib_sysfs_write (char *file_name, char *fmt, ...)
{
  return NULL;
}

__clib_export clib_error_t *
clib_sysfs_read (char *file_name, char *fmt, ...)
{
  return NULL;
}

clib_error_t *
clib_sysfs_set_nr_hugepages (int numa_node, int log2_page_size, int nr)
{
  return NULL;
}

clib_error_t *
clib_sysfs_get_free_hugepages (int numa_node, int log2_page_size, int *v)
{
  return NULL;
}

clib_error_t *
clib_sysfs_get_nr_hugepages (int numa_node, int log2_page_size, int *v)
{
  return NULL;
}

clib_error_t *
clib_sysfs_get_surplus_hugepages (int numa_node, int log2_page_size, int *v)
{
  return NULL;
}

clib_error_t *
clib_sysfs_prealloc_hugepages (int numa_node, int log2_page_size, int nr)
{
  return NULL;
}

__clib_export uword *
clib_sysfs_list_to_bitmap (char *filename)
{
  return NULL;
}
