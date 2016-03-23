/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef __adj_alloc_h__
#define __adj_alloc_h__

/* 
 * Adjacency allocator: heap-like in that the code
 * will dole out contiguous chunks of n items. In the interests of 
 * thread safety, we don't bother about coalescing free blocks of size r
 * into free blocks of size s, where r < s.
 * 
 * We include explicit references to worker thread barrier synchronization
 * where necessary.  
 */ 

#include <vppinfra/vec.h>
#include <vlib/vlib.h>
#include <vnet/ip/lookup.h>

typedef struct {
  u32 ** free_indices_by_size;
} aa_header_t;

#define aa_aligned_header_bytes \
  vec_aligned_header_bytes (sizeof (aa_header_t), sizeof (void *))

/* Pool header from user pointer */
static inline aa_header_t * aa_header (void * v)
{
  return vec_aligned_header (v, sizeof (aa_header_t), sizeof (void *));
}

ip_adjacency_t * 
aa_alloc (ip_adjacency_t * adjs, ip_adjacency_t **blockp, u32 n);
void aa_free (ip_adjacency_t * adjs, ip_adjacency_t * adj);
ip_adjacency_t * aa_bootstrap (ip_adjacency_t * adjs, u32 n);

format_function_t format_adj_allocation;

#endif /* __adj_alloc_h__ */
