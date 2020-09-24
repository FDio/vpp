/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/time.h>
#include <vppinfra/format.h>
#include <vppinfra/clib_error.h>

clib_mem_main_t clib_mem_main;
u16 __thread __clib_mem_active_heap_index = 0;

void *
clib_mem_vm_map (void *base, uword size, clib_mem_page_sz_t log2_page_sz,
		 char *fmt, ...)
{
  va_list va;
  void *rv;
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  vec_add1 (s, 0);
  rv = clib_mem_vm_map_internal (base, log2_page_sz, size, -1, 0, (char *) s);
  va_end (va);
  vec_free (s);
  return rv;
}

void *
clib_mem_vm_map_stack (uword size, clib_mem_page_sz_t log2_page_sz,
		       char *fmt, ...)
{
  va_list va;
  void *rv;
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  vec_add1 (s, 0);
  rv = clib_mem_vm_map_internal (0, log2_page_sz, size, -1, 0, (char *) s);
  va_end (va);
  vec_free (s);
  return rv;
}

void *
clib_mem_vm_map_shared (void *base, uword size, int fd, uword offset,
			char *fmt, ...)
{
  va_list va;
  void *rv;
  u8 *s;
  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  vec_add1 (s, 0);
  rv = clib_mem_vm_map_internal (base, 0, size, fd, offset, (char *) s);
  va_end (va);
  vec_free (s);
  return rv;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
