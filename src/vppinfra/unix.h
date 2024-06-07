/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
  Copyright (c) 2005 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef included_clib_unix_h
#define included_clib_unix_h

#include <vppinfra/error.h>

/* Number of bytes in a Unix file. */
clib_error_t *clib_file_n_bytes (char *file, uword * result);

/* Read file contents into given buffer. */
clib_error_t *clib_file_read_contents (char *file, u8 * result,
				       uword n_bytes);

/* Read and return contents of Unix file. */
clib_error_t *clib_file_contents (char *file, u8 ** result);

/* As above but for /proc file system on Linux. */
clib_error_t *unix_proc_file_contents (char *file, u8 ** result);

/* Retrieve bitmap of online cpu cures */
clib_bitmap_t *os_get_online_cpu_core_bitmap ();

/* Retrieve bitmap of cpu affinity */
clib_bitmap_t *os_get_cpu_affinity_bitmap ();

/* Translate cpu index in cpu affinity bitmap */
int os_translate_cpu_to_affinity_bitmap (int cpu);

/* Retrieve cpu index after translation in cpu affinity bitmap */
int os_translate_cpu_from_affinity_bitmap (int cpu_translated);

/* Translate cpu bitmap based on cpu affinity bitmap */
clib_bitmap_t *
os_translate_cpu_bmp_to_affinity_bitmap (clib_bitmap_t *cpu_bmp);

/* Retrieve bitmap of online cpu nodes (sockets) */
clib_bitmap_t *os_get_online_cpu_node_bitmap ();

/* Retrieve bitmap of cpus with memory */
clib_bitmap_t *os_get_cpu_with_memory_bitmap ();

/* Retrieve bitmap of cpus on specific node */
clib_bitmap_t *os_get_cpu_on_node_bitmap (int node);

/* Retrieve physical core id of specific cpu, -1 if not available */
int os_get_cpu_phys_core_id (int cpu);

/* Retrieve the path of the current executable as a vector (not
 * null-terminated). */
u8 *os_get_exec_path ();

#endif /* included_clib_unix_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
