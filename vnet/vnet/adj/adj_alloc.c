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

#include <vnet/adj/adj_alloc.h>
#include <vnet/ip/ip.h>

/*
 * the single adj heap
 */
ip_adjacency_t *adj_heap;

/* 
 * any operation which could cause the adj vector to be reallocated
 * must have a worker thread barrier
 */
static inline int will_reallocate (ip_adjacency_t * adjs, u32 n)
{
  uword aligned_header_bytes, new_data_bytes;
  uword data_bytes;
  aa_header_t * ah = aa_header (adjs);

  if (adjs == 0)
    return 1;

  data_bytes = (vec_len (adjs) + n) * sizeof (*adjs);

  aligned_header_bytes = vec_header_bytes (aa_aligned_header_bytes);
  
  new_data_bytes = data_bytes + aligned_header_bytes;

  ASSERT (clib_mem_is_heap_object (_vec_find(ah)));

  if (PREDICT_TRUE(new_data_bytes <= clib_mem_size (_vec_find(ah))))
    return 0;

  return 1;
}

ip_adjacency_t * 
aa_alloc (void)
{
  vlib_main_t * vm = &vlib_global_main;
  aa_header_t * ah = aa_header (adj_heap);
  ip_adjacency_t * adj_block;
  u32 freelist_length;
  int need_barrier_sync = 0;
  u32 n = 1;
  
  ASSERT(os_get_cpu_number() == 0);
  ASSERT (clib_mem_is_heap_object (_vec_find(ah)));
  
  /* If we don't have a freelist of size N, fresh allocation is required */
  if (vec_len (ah->free_indices_by_size) <= n)
    {
      if (will_reallocate (adj_heap, n))
        {
          need_barrier_sync = 1;
          vlib_worker_thread_barrier_sync (vm);
        }
      /* Workers wont look at the freelists... */
      vec_validate (ah->free_indices_by_size, n);
      vec_add2_ha (adj_heap, adj_block, n, aa_aligned_header_bytes, 
                   CLIB_CACHE_LINE_BYTES);
      if (need_barrier_sync)
        vlib_worker_thread_barrier_release (vm);
      goto out;
    }
  /* See if we have a free adj block to dole out */
  if ((freelist_length = vec_len(ah->free_indices_by_size[n])))
    {
      u32 index = ah->free_indices_by_size[n][freelist_length-1];

      adj_block = &adj_heap[index];
      _vec_len(ah->free_indices_by_size[n]) -= 1;
      goto out;
    }
  /* Allocate a new block of size N */
  if (will_reallocate (adj_heap, n))
    {
      need_barrier_sync = 1;
      vlib_worker_thread_barrier_sync (vm);
    }
  vec_add2_ha (adj_heap, adj_block, n, aa_aligned_header_bytes, 
               CLIB_CACHE_LINE_BYTES);
  
  if (need_barrier_sync)
    vlib_worker_thread_barrier_release (vm);

 out:
  memset (adj_block, 0, n * (sizeof(*adj_block)));
  adj_block->heap_handle = adj_block - adj_heap;
  adj_block->n_adj = n;

  /*
   * the adj heap may have realloc'd. recache.
   */
  ip4_main.lookup_main.adjacency_heap = adj_heap;
  ip6_main.lookup_main.adjacency_heap = adj_heap;

  return (adj_block);
}

void aa_free (ip_adjacency_t * adj)
{
  aa_header_t * ah = aa_header (adj_heap);
  
  ASSERT (adj_heap && adj && (adj->heap_handle < vec_len (adj_heap)));
  ASSERT (adj->heap_handle != 0);
  
  vec_add1 (ah->free_indices_by_size[adj->n_adj], adj->heap_handle);
  adj->heap_handle = 0;
}

void aa_bootstrap (u32 n)
{
  ip_adjacency_t * adj_block;
  aa_header_t * ah;
  int i;

  vec_add2_ha (adj_heap, adj_block, n, aa_aligned_header_bytes, 
               CLIB_CACHE_LINE_BYTES);

  memset (adj_block, 0, n * sizeof(*adj_block));
  ah = aa_header (adj_heap);
  memset (ah, 0, sizeof (*ah));

  vec_validate (ah->free_indices_by_size, 1);

  for (i = 0 ; i < vec_len (adj_heap); i++)
    {
      adj_block->n_adj = 1;
      adj_block->heap_handle = ~0;
      /* Euchre the allocator into returning 0, 1, 2, etc. */
      vec_add1 (ah->free_indices_by_size[1], n - (i+1));
    }

  ip4_main.lookup_main.adjacency_heap = adj_heap;
  ip6_main.lookup_main.adjacency_heap = adj_heap;
}

u8 * format_adjacency_alloc (u8 * s, va_list * args)
{
  vnet_main_t * vnm = va_arg (*args, vnet_main_t *);
  int verbose = va_arg (*args, int);
  ip_adjacency_t * adj;
  u32 inuse = 0, freed = 0;
  u32 on_freelist = 0;
  int i, j;
  aa_header_t * ah = aa_header (adj_heap);

  for (i = 0; i < vec_len (adj_heap); i += adj->n_adj)
    {
      adj = adj_heap + i;
      if ((i == 0) || adj->heap_handle)
        inuse += adj->n_adj;
      else
        freed += adj->n_adj;
    }

  for (i = 1; i < vec_len(ah->free_indices_by_size); i++)
    {
      for (j = 0; j < vec_len(ah->free_indices_by_size[i]); j++)
        {
          adj = adj_heap + ah->free_indices_by_size[i][j];
          ASSERT(adj->heap_handle == 0);
          on_freelist += adj->n_adj;
        }
    }
      
  s = format (s, "adj_heap: %d total, %d in use, %d free, %d on freelists\n",
              vec_len(adj_heap), inuse, freed, on_freelist);
  if (verbose)
    {
      for (i = 0; i < vec_len (adj_heap); i += adj->n_adj)
        {
          adj = adj_heap + i;
          if ((i == 0) || adj->heap_handle)
            {
              if (adj->n_adj > 1)
                s = format (s, "[%d-%d] ", i, i+adj->n_adj-1);
              else
                s = format (s, "[%d] ", i);

              for (j = 0; j < adj->n_adj; j++)
                {
                  if (j > 0)
                    s = format (s, "      ");

                  s = format(s, "%U\n", format_ip_adjacency, 
			     vnm, i+j, FORMAT_IP_ADJACENCY_NONE);
                }
            }
        }
    }
  return s;
}

static clib_error_t *
show_adjacency_alloc_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  int verbose = 0;
  vnet_main_t *vnm = vnet_get_main();
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat (input, "verbose"))
        verbose = 1;
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }

  vlib_cli_output (vm, "%U", format_adjacency_alloc, vnm, verbose);

  return 0;
}

VLIB_CLI_COMMAND (show_adjacency_alloc_command, static) = {
  .path = "show adjacency alloc",
  .short_help = "show adjacency alloc",
  .function = show_adjacency_alloc_command_fn,
};
