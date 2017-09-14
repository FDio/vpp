/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef included_linux_sysfs_h
#define included_linux_sysfs_h

#include <vppinfra/error.h>

clib_error_t *clib_sysfs_write (char *file_name, char *fmt, ...);

clib_error_t *clib_sysfs_read (char *file_name, char *fmt, ...);

u8 *clib_sysfs_link_to_name (char *link);

clib_error_t *clib_sysfs_set_nr_hugepages (int numa_node,
					   int page_size, int nr);
clib_error_t *clib_sysfs_get_nr_hugepages (int numa_node,
					   int page_size, int *v);
clib_error_t *clib_sysfs_get_free_hugepages (int numa_node,
					     int page_size, int *v);
clib_error_t *clib_sysfs_get_surplus_hugepages (int numa_node,
						int page_size, int *v);
clib_error_t *clib_sysfs_prealloc_hugepages (int numa_node,
					     int page_size, int nr);

#endif /* included_linux_sysfs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
