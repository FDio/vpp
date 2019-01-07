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
 * physmem.h: virtual <-> physical memory mapping for VLIB buffers
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

#ifndef included_vlib_physmem_funcs_h
#define included_vlib_physmem_funcs_h

clib_error_t *vlib_physmem_init (vlib_main_t * vm);
clib_error_t *vlib_physmem_shared_map_create (vlib_main_t * vm, char *name,
					      uword size, u32 log2_page_sz,
					      u32 numa_node, u32 * map_index);

vlib_physmem_map_t *vlib_physmem_get_map (vlib_main_t * vm, u32 index);

always_inline void *
vlib_physmem_alloc_aligned (vlib_main_t * vm, uword n_bytes, uword alignment)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  return clib_pmalloc_alloc_aligned (pm, n_bytes, alignment);
}

always_inline void *
vlib_physmem_alloc_aligned_on_numa (vlib_main_t * vm, uword n_bytes,
				    uword alignment, u32 numa_node)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  return clib_pmalloc_alloc_aligned_on_numa (pm, n_bytes, alignment,
					     numa_node);
}

/* By default allocate I/O memory with cache line alignment. */
always_inline void *
vlib_physmem_alloc (vlib_main_t * vm, uword n_bytes)
{
  return vlib_physmem_alloc_aligned (vm, n_bytes, CLIB_CACHE_LINE_BYTES);
}

always_inline void *
vlib_physmem_alloc_from_map (vlib_main_t * vm, u32 physmem_map_index,
			     uword n_bytes, uword alignment)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  vlib_physmem_map_t *map = vlib_physmem_get_map (vm, physmem_map_index);
  return clib_pmalloc_alloc_from_arena (pm, map->base, n_bytes,
					CLIB_CACHE_LINE_BYTES);
}

always_inline void
vlib_physmem_free (vlib_main_t * vm, void *p)
{
  if (p)
    clib_pmalloc_free (vm->physmem_main.pmalloc_main, p);
}

always_inline u64
vlib_physmem_get_page_index (vlib_main_t * vm, void *mem)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  return clib_pmalloc_get_page_index (pm, mem);
}

always_inline u64
vlib_physmem_get_pa (vlib_main_t * vm, void *mem)
{
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  return clib_pmalloc_get_pa (pm, mem);
}

always_inline clib_error_t *
vlib_physmem_last_error (struct vlib_main_t * vm)
{
  return clib_error_return (0, "unknown error");
}

#endif /* included_vlib_physmem_funcs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
