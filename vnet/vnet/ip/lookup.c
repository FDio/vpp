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
 * ip/ip_lookup.c: ip4/6 adjacency and lookup table managment
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

#include <vppinfra/math.h>		/* for fabs */
#include <vnet/ip/ip.h>

static void
ip_multipath_del_adjacency (ip_lookup_main_t * lm, u32 del_adj_index);

always_inline void
ip_poison_adjacencies (ip_adjacency_t * adj, uword n_adj)
{
  if (CLIB_DEBUG > 0)
    memset (adj, 0xfe, n_adj * sizeof (adj[0]));
}

/* Create new block of given number of contiguous adjacencies. */
ip_adjacency_t *
ip_add_adjacency (ip_lookup_main_t * lm,
		  ip_adjacency_t * copy_adj,
		  u32 n_adj,
		  u32 * adj_index_return)
{
  ip_adjacency_t * adj;
  u32 ai, i, handle;

  /* See if we know enough to attempt to share an existing adjacency */
  if (copy_adj && n_adj == 1)
    {
      uword signature;
      uword * p;

      switch (copy_adj->lookup_next_index)
        {
        case IP_LOOKUP_NEXT_DROP:
          if (lm->drop_adj_index)
            {
              adj = ip_get_adjacency (lm, lm->drop_adj_index);
              *adj_index_return = lm->drop_adj_index;
              return (adj);
            }
          break;

        case IP_LOOKUP_NEXT_LOCAL:
          if (lm->local_adj_index)
            {
              adj = ip_get_adjacency (lm, lm->local_adj_index);
              *adj_index_return = lm->local_adj_index;
              return (adj);
            }
        default:
          break;
        }

      signature = vnet_ip_adjacency_signature (copy_adj);
      p = hash_get (lm->adj_index_by_signature, signature);
      if (p)
        {
          adj = heap_elt_at_index (lm->adjacency_heap, p[0]);
          while (1)
            {
              if (vnet_ip_adjacency_share_compare (adj, copy_adj))
                {
                  adj->share_count++;
                  *adj_index_return = p[0];
                  return adj;
                }
              if (adj->next_adj_with_signature == 0)
                break;
              adj = heap_elt_at_index (lm->adjacency_heap,
                                       adj->next_adj_with_signature);
            }
        }
    }

  ai = heap_alloc (lm->adjacency_heap, n_adj, handle);
  adj = heap_elt_at_index (lm->adjacency_heap, ai);

  ip_poison_adjacencies (adj, n_adj);

  /* Validate adjacency counters. */
  vlib_validate_combined_counter (&lm->adjacency_counters, ai + n_adj - 1);

  for (i = 0; i < n_adj; i++)
    {
      /* Make sure certain fields are always initialized. */
      adj[i].rewrite_header.sw_if_index = ~0;
      adj[i].explicit_fib_index = ~0;
      adj[i].mcast_group_index = ~0;
      adj[i].classify_table_index = ~0;
      adj[i].saved_lookup_next_index = 0;

      if (copy_adj)
	adj[i] = copy_adj[i];

      adj[i].heap_handle = handle;
      adj[i].n_adj = n_adj;
      adj[i].share_count = 0;
      adj[i].next_adj_with_signature = 0;

      /* Zero possibly stale counters for re-used adjacencies. */
      vlib_zero_combined_counter (&lm->adjacency_counters, ai + i);
    }

  /* Set up to share the adj later */
  if (copy_adj && n_adj == 1)
    {
      uword * p;
      u32 old_ai;
      uword signature = vnet_ip_adjacency_signature (adj);

      p = hash_get (lm->adj_index_by_signature, signature);
      /* Hash collision? */
      if (p)
        {
          /* Save the adj index, p[0] will be toast after the unset! */
          old_ai = p[0];
          hash_unset (lm->adj_index_by_signature, signature);
          hash_set (lm->adj_index_by_signature, signature, ai);
          adj->next_adj_with_signature = old_ai;
        }
      else
        {
          adj->next_adj_with_signature = 0;
          hash_set (lm->adj_index_by_signature, signature, ai);
        }
    }

  *adj_index_return = ai;
  return adj;
}

static void ip_del_adjacency2 (ip_lookup_main_t * lm, u32 adj_index, u32 delete_multipath_adjacency)
{
  ip_adjacency_t * adj;
  uword handle;

  ip_call_add_del_adjacency_callbacks (lm, adj_index, /* is_del */ 1);

  adj = ip_get_adjacency (lm, adj_index);
  handle = adj->heap_handle;

  /* Special-case local, drop adjs */
  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_DROP:
      return;
    default:
      break;
    }


  if (adj->n_adj == 1)
    {
      uword signature;
      uword * p;
      u32 this_ai;
      ip_adjacency_t * this_adj, * prev_adj = 0;
      if (adj->share_count > 0)
        {
          adj->share_count --;
          return;
        }

      signature = vnet_ip_adjacency_signature (adj);
      p = hash_get (lm->adj_index_by_signature, signature);
      if (p == 0)
        {
          clib_warning ("adj 0x%llx signature %llx not in table",
                        adj, signature);
          goto bag_it;
        }
      this_ai = p[0];
      /* At the top of the signature chain (likely)? */
      if (this_ai == adj_index)
        {
          if (adj->next_adj_with_signature == 0)
            {
              hash_unset (lm->adj_index_by_signature, signature);
              goto bag_it;
            }
          else
            {
              this_adj = ip_get_adjacency (lm, adj->next_adj_with_signature);
              hash_unset (lm->adj_index_by_signature, signature);
              hash_set (lm->adj_index_by_signature, signature,
                        this_adj->heap_handle);
            }
        }
      else                      /* walk signature chain */
        {
          this_adj = ip_get_adjacency (lm, this_ai);
          while (this_adj != adj)
            {
              prev_adj = this_adj;
              this_adj = ip_get_adjacency
                (lm, this_adj->next_adj_with_signature);
              ASSERT(this_adj->heap_handle != 0);
            }
          prev_adj->next_adj_with_signature = this_adj->next_adj_with_signature;
        }
    }

 bag_it:
  if (delete_multipath_adjacency)
    ip_multipath_del_adjacency (lm, adj_index);

  ip_poison_adjacencies (adj, adj->n_adj);

  heap_dealloc (lm->adjacency_heap, handle);
}

void ip_del_adjacency (ip_lookup_main_t * lm, u32 adj_index)
{ ip_del_adjacency2 (lm, adj_index, /* delete_multipath_adjacency */ 1); }

static int
next_hop_sort_by_weight (ip_multipath_next_hop_t * n1,
			 ip_multipath_next_hop_t * n2)
{
  int cmp = (int) n1->weight - (int) n2->weight;
  return (cmp == 0
	  ? (int) n1->next_hop_adj_index - (int) n2->next_hop_adj_index
	  : (cmp > 0 ? +1 : -1));
}

/* Given next hop vector is over-written with normalized one with sorted weights and
   with weights corresponding to the number of adjacencies for each next hop.
   Returns number of adjacencies in block. */
static u32 ip_multipath_normalize_next_hops (ip_lookup_main_t * lm,
					     ip_multipath_next_hop_t * raw_next_hops,
					     ip_multipath_next_hop_t ** normalized_next_hops)
{
  ip_multipath_next_hop_t * nhs;
  uword n_nhs, n_adj, n_adj_left, i;
  f64 sum_weight, norm, error;

  n_nhs = vec_len (raw_next_hops);
  ASSERT (n_nhs > 0);
  if (n_nhs == 0)
    return 0;

  /* Allocate enough space for 2 copies; we'll use second copy to save original weights. */
  nhs = *normalized_next_hops;
  vec_validate (nhs, 2*n_nhs - 1);

  /* Fast path: 1 next hop in block. */
  n_adj = n_nhs;
  if (n_nhs == 1)
    {
      nhs[0] = raw_next_hops[0];
      nhs[0].weight = 1;
      _vec_len (nhs) = 1;
      goto done;
    }

  else if (n_nhs == 2)
    {
      int cmp = next_hop_sort_by_weight (&raw_next_hops[0], &raw_next_hops[1]) < 0;

      /* Fast sort. */
      nhs[0] = raw_next_hops[cmp];
      nhs[1] = raw_next_hops[cmp ^ 1];

      /* Fast path: equal cost multipath with 2 next hops. */
      if (nhs[0].weight == nhs[1].weight)
	{
	  nhs[0].weight = nhs[1].weight = 1;
	  _vec_len (nhs) = 2;
	  goto done;
	}
    }
  else
    {
      memcpy (nhs, raw_next_hops, n_nhs * sizeof (raw_next_hops[0]));
      qsort (nhs, n_nhs, sizeof (nhs[0]), (void *) next_hop_sort_by_weight);
    }

  /* Find total weight to normalize weights. */
  sum_weight = 0;
  for (i = 0; i < n_nhs; i++)
    sum_weight += nhs[i].weight;

  /* In the unlikely case that all weights are given as 0, set them all to 1. */
  if (sum_weight == 0)
    {
      for (i = 0; i < n_nhs; i++)
	nhs[i].weight = 1;
      sum_weight = n_nhs;
    }

  /* Save copies of all next hop weights to avoid being overwritten in loop below. */
  for (i = 0; i < n_nhs; i++)
    nhs[n_nhs + i].weight = nhs[i].weight;

  /* Try larger and larger power of 2 sized adjacency blocks until we
     find one where traffic flows to within 1% of specified weights. */
  for (n_adj = max_pow2 (n_nhs); ; n_adj *= 2)
    {
      error = 0;

      norm = n_adj / sum_weight;
      n_adj_left = n_adj;
      for (i = 0; i < n_nhs; i++)
	{
	  f64 nf = nhs[n_nhs + i].weight * norm; /* use saved weights */
	  word n = flt_round_nearest (nf);

	  n = n > n_adj_left ? n_adj_left : n;
	  n_adj_left -= n;
	  error += fabs (nf - n);
	  nhs[i].weight = n;
	}
	
      nhs[0].weight += n_adj_left;

      /* Less than 5% average error per adjacency with this size adjacency block? */
      if (error <= lm->multipath_next_hop_error_tolerance*n_adj)
	{
	  /* Truncate any next hops with zero weight. */
	  _vec_len (nhs) = i;
	  break;
	}
    }

 done:
  /* Save vector for next call. */
  *normalized_next_hops = nhs;
  return n_adj;
}

always_inline uword
ip_next_hop_hash_key_from_handle (uword handle)
{ return 1 + 2*handle; }

always_inline uword
ip_next_hop_hash_key_is_heap_handle (uword k)
{ return k & 1; }

always_inline uword
ip_next_hop_hash_key_get_heap_handle (uword k)
{
  ASSERT (ip_next_hop_hash_key_is_heap_handle (k));
  return k / 2;
}

static u32
ip_multipath_adjacency_get (ip_lookup_main_t * lm,
			    ip_multipath_next_hop_t * raw_next_hops,
			    uword create_if_non_existent)
{
  uword * p;
  u32 i, j, n_adj, adj_index, adj_heap_handle;
  ip_adjacency_t * adj, * copy_adj;
  ip_multipath_next_hop_t * nh, * nhs;
  ip_multipath_adjacency_t * madj;

  n_adj = ip_multipath_normalize_next_hops (lm, raw_next_hops, &lm->next_hop_hash_lookup_key_normalized);
  nhs = lm->next_hop_hash_lookup_key_normalized;

  /* Basic sanity. */
  ASSERT (n_adj >= vec_len (raw_next_hops));

  /* Use normalized next hops to see if we've seen a block equivalent to this one before. */
  p = hash_get_mem (lm->multipath_adjacency_by_next_hops, nhs);
  if (p)
    return p[0];

  if (! create_if_non_existent)
    return 0;

  adj = ip_add_adjacency (lm, /* copy_adj */ 0, n_adj, &adj_index);
  adj_heap_handle = adj[0].heap_handle;

  /* Fill in adjacencies in block based on corresponding next hop adjacencies. */
  i = 0;
  vec_foreach (nh, nhs)
    {
      copy_adj = ip_get_adjacency (lm, nh->next_hop_adj_index);
      for (j = 0; j < nh->weight; j++)
	{
	  adj[i] = copy_adj[0];
	  adj[i].heap_handle = adj_heap_handle;
	  adj[i].n_adj = n_adj;
	  i++;
	}
    }

  /* All adjacencies should have been initialized. */
  ASSERT (i == n_adj);

  vec_validate (lm->multipath_adjacencies, adj_heap_handle);
  madj = vec_elt_at_index (lm->multipath_adjacencies, adj_heap_handle);

  madj->adj_index = adj_index;
  madj->n_adj_in_block = n_adj;
  madj->reference_count = 0;	/* caller will set to one. */

  madj->normalized_next_hops.count = vec_len (nhs);
  madj->normalized_next_hops.heap_offset
    = heap_alloc (lm->next_hop_heap, vec_len (nhs),
		  madj->normalized_next_hops.heap_handle);
  memcpy (lm->next_hop_heap + madj->normalized_next_hops.heap_offset,
	  nhs, vec_bytes (nhs));

  hash_set (lm->multipath_adjacency_by_next_hops,
	    ip_next_hop_hash_key_from_handle (madj->normalized_next_hops.heap_handle),
	    madj - lm->multipath_adjacencies);

  madj->unnormalized_next_hops.count = vec_len (raw_next_hops);
  madj->unnormalized_next_hops.heap_offset
    = heap_alloc (lm->next_hop_heap, vec_len (raw_next_hops),
		  madj->unnormalized_next_hops.heap_handle);
  memcpy (lm->next_hop_heap + madj->unnormalized_next_hops.heap_offset,
	  raw_next_hops, vec_bytes (raw_next_hops));

  ip_call_add_del_adjacency_callbacks (lm, adj_index, /* is_del */ 0);

  return adj_heap_handle;
}

/* Returns 0 for next hop not found. */
u32
ip_multipath_adjacency_add_del_next_hop (ip_lookup_main_t * lm,
					 u32 is_del,
					 u32 old_mp_adj_index,
					 u32 next_hop_adj_index,
					 u32 next_hop_weight,
					 u32 * new_mp_adj_index)
{
  ip_multipath_adjacency_t * mp_old, * mp_new;
  ip_multipath_next_hop_t * nh, * nhs, * hash_nhs;
  u32 n_nhs, i_nh;

  mp_new = mp_old = 0;
  n_nhs = 0;
  i_nh = 0;
  nhs = 0;

  /* If old multipath adjacency is valid, find requested next hop. */
  if (old_mp_adj_index < vec_len (lm->multipath_adjacencies)
      && lm->multipath_adjacencies[old_mp_adj_index].normalized_next_hops.count > 0)
    {
      mp_old = vec_elt_at_index (lm->multipath_adjacencies, old_mp_adj_index);
	
      nhs = vec_elt_at_index (lm->next_hop_heap, mp_old->unnormalized_next_hops.heap_offset);
      n_nhs = mp_old->unnormalized_next_hops.count;

      /* Linear search: ok since n_next_hops is small. */
      for (i_nh = 0; i_nh < n_nhs; i_nh++)
	if (nhs[i_nh].next_hop_adj_index == next_hop_adj_index)
	  break;

      /* Given next hop not found. */
      if (i_nh >= n_nhs && is_del)
	return 0;
    }

  hash_nhs = lm->next_hop_hash_lookup_key;
  if (hash_nhs)
    _vec_len (hash_nhs) = 0;

  if (is_del)
    {
      if (n_nhs > 1)
	{
	  /* Prepare lookup key for multipath with target next hop deleted. */
	  if (i_nh > 0)
	    vec_add (hash_nhs, nhs + 0, i_nh);
	  if (i_nh + 1 < n_nhs)
	    vec_add (hash_nhs, nhs + i_nh + 1, n_nhs - (i_nh + 1));
	}
    }
  else /* it's an add. */
    {
      /* If next hop is already there with the same weight, we have nothing to do. */
      if (i_nh < n_nhs && nhs[i_nh].weight == next_hop_weight)
	{
	  new_mp_adj_index[0] = ~0;
	  goto done;
	}

      /* Copy old next hops to lookup key vector. */
      if (n_nhs > 0)
	vec_add (hash_nhs, nhs, n_nhs);

      if (i_nh < n_nhs)
	{
	  /* Change weight of existing next hop. */
	  nh = vec_elt_at_index (hash_nhs, i_nh);
	}
      else
	{
	  /* Add a new next hop. */
	  vec_add2 (hash_nhs, nh, 1);
	  nh->next_hop_adj_index = next_hop_adj_index;
	}

      /* Set weight for added or old next hop. */
      nh->weight = next_hop_weight;
    }

  if (vec_len (hash_nhs) > 0)
    {
      u32 tmp = ip_multipath_adjacency_get (lm, hash_nhs,
					    /* create_if_non_existent */ 1);
      if (tmp != ~0)
	mp_new = vec_elt_at_index (lm->multipath_adjacencies, tmp);

      /* Fetch again since pool may have moved. */
      if (mp_old)
	mp_old = vec_elt_at_index (lm->multipath_adjacencies, old_mp_adj_index);
    }

  new_mp_adj_index[0] = mp_new ? mp_new - lm->multipath_adjacencies : ~0;

  if (mp_new != mp_old)
    {
      if (mp_old)
	{
	  ASSERT (mp_old->reference_count > 0);
	  mp_old->reference_count -= 1;
	}
      if (mp_new)
	mp_new->reference_count += 1;
    }

  if (mp_old && mp_old->reference_count == 0)
    ip_multipath_adjacency_free (lm, mp_old);

 done:
  /* Save key vector next call. */
  lm->next_hop_hash_lookup_key = hash_nhs;

  return 1;
}

static void
ip_multipath_del_adjacency (ip_lookup_main_t * lm, u32 del_adj_index)
{
  ip_adjacency_t * adj = ip_get_adjacency (lm, del_adj_index);
  ip_multipath_adjacency_t * madj, * new_madj;
  ip_multipath_next_hop_t * nhs, * hash_nhs;
  u32 i, n_nhs, madj_index, new_madj_index;

  if (adj->heap_handle >= vec_len (lm->multipath_adjacencies))
    return;

  vec_validate (lm->adjacency_remap_table, vec_len (lm->adjacency_heap) - 1);

  for (madj_index = 0; madj_index < vec_len (lm->multipath_adjacencies); madj_index++)
    {
      madj = vec_elt_at_index (lm->multipath_adjacencies, madj_index);
      if (madj->n_adj_in_block == 0)
	continue;

      nhs = heap_elt_at_index (lm->next_hop_heap, madj->unnormalized_next_hops.heap_offset);
      n_nhs = madj->unnormalized_next_hops.count;
      for (i = 0; i < n_nhs; i++)
	if (nhs[i].next_hop_adj_index == del_adj_index)
	  break;

      /* del_adj_index not found in unnormalized_next_hops?  We're done. */
      if (i >= n_nhs)
	continue;

      new_madj = 0;
      if (n_nhs > 1)
	{
	  hash_nhs = lm->next_hop_hash_lookup_key;
	  if (hash_nhs)
	    _vec_len (hash_nhs) = 0;
	  if (i > 0)
	    vec_add (hash_nhs, nhs + 0, i);
	  if (i + 1 < n_nhs)
	    vec_add (hash_nhs, nhs + i + 1, n_nhs - (i + 1));

	  new_madj_index = ip_multipath_adjacency_get (lm, hash_nhs, /* create_if_non_existent */ 1);

	  lm->next_hop_hash_lookup_key = hash_nhs;

	  if (new_madj_index == madj_index)
	    continue;

	  new_madj = vec_elt_at_index (lm->multipath_adjacencies, new_madj_index);
	}

      lm->adjacency_remap_table[madj->adj_index] = new_madj ? 1 + new_madj->adj_index : ~0;
      lm->n_adjacency_remaps += 1;
      ip_multipath_adjacency_free (lm, madj);
    }
}

void
ip_multipath_adjacency_free (ip_lookup_main_t * lm,
			     ip_multipath_adjacency_t * a)
{
  hash_unset (lm->multipath_adjacency_by_next_hops,
	      ip_next_hop_hash_key_from_handle (a->normalized_next_hops.heap_handle));
  heap_dealloc (lm->next_hop_heap, a->normalized_next_hops.heap_handle);
  heap_dealloc (lm->next_hop_heap, a->unnormalized_next_hops.heap_handle);

  ip_del_adjacency2 (lm, a->adj_index, a->reference_count == 0);
  memset (a, 0, sizeof (a[0]));
}

always_inline ip_multipath_next_hop_t *
ip_next_hop_hash_key_get_next_hops (ip_lookup_main_t * lm, uword k,
				    uword * n_next_hops)
{
  ip_multipath_next_hop_t * nhs;
  uword n_nhs;
  if (ip_next_hop_hash_key_is_heap_handle (k))
    {
      uword handle = ip_next_hop_hash_key_get_heap_handle (k);
      nhs = heap_elt_with_handle (lm->next_hop_heap, handle);
      n_nhs = heap_len (lm->next_hop_heap, handle);
    }
  else
    {
      nhs = uword_to_pointer (k, ip_multipath_next_hop_t *);
      n_nhs = vec_len (nhs);
    }
  *n_next_hops = n_nhs;
  return nhs;
}

static uword
ip_next_hop_hash_key_sum (hash_t * h, uword key0)
{
  ip_lookup_main_t * lm = uword_to_pointer (h->user, ip_lookup_main_t *);  
  ip_multipath_next_hop_t * k0;
  uword n0;

  k0 = ip_next_hop_hash_key_get_next_hops (lm, key0, &n0);
  return hash_memory (k0, n0 * sizeof (k0[0]), /* seed */ n0);
}

static uword
ip_next_hop_hash_key_equal (hash_t * h, uword key0, uword key1)
{
  ip_lookup_main_t * lm = uword_to_pointer (h->user, ip_lookup_main_t *);  
  ip_multipath_next_hop_t * k0, * k1;
  uword n0, n1;

  k0 = ip_next_hop_hash_key_get_next_hops (lm, key0, &n0);
  k1 = ip_next_hop_hash_key_get_next_hops (lm, key1, &n1);

  return n0 == n1 && ! memcmp (k0, k1, n0 * sizeof (k0[0]));
}

clib_error_t *
ip_interface_address_add_del (ip_lookup_main_t * lm,
			      u32 sw_if_index,
			      void * addr_fib,
			      u32 address_length,
			      u32 is_del,
			      u32 * result_if_address_index)
{
  vnet_main_t * vnm = vnet_get_main();
  ip_interface_address_t * a, * prev, * next;
  uword * p = mhash_get (&lm->address_to_if_address_index, addr_fib);

  vec_validate_init_empty (lm->if_address_pool_index_by_sw_if_index, sw_if_index, ~0);
  a = p ? pool_elt_at_index (lm->if_address_pool, p[0]) : 0;

  /* Verify given length. */
  if ((a && (address_length != a->address_length)) || (address_length == 0))
    {
      vnm->api_errno = VNET_API_ERROR_ADDRESS_LENGTH_MISMATCH;
      return clib_error_create 
        ( "%U wrong length (expected %d) for interface %U",
          lm->format_address_and_length, addr_fib,
          address_length, a? a->address_length : -1,
          format_vnet_sw_if_index_name, vnm, sw_if_index);
    }

  if (is_del)
    {
      if (!a) 
        {
          vnet_sw_interface_t * si = vnet_get_sw_interface (vnm, sw_if_index);
          vnm->api_errno = VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE;
          return clib_error_create ("%U not found for interface %U",
                                    lm->format_address_and_length, 
                                    addr_fib, address_length,
                                    format_vnet_sw_interface_name, vnm, si);
        }

      if (a->prev_this_sw_interface != ~0)
	{
	  prev = pool_elt_at_index (lm->if_address_pool, a->prev_this_sw_interface);
	  prev->next_this_sw_interface = a->next_this_sw_interface;
	}
      if (a->next_this_sw_interface != ~0)
	{
	  next = pool_elt_at_index (lm->if_address_pool, a->next_this_sw_interface);
	  next->prev_this_sw_interface = a->prev_this_sw_interface;

	  if(a->prev_this_sw_interface == ~0)
	         lm->if_address_pool_index_by_sw_if_index[sw_if_index]  = a->next_this_sw_interface;
	}

      if ((a->next_this_sw_interface  == ~0) &&  (a->prev_this_sw_interface == ~0))
	lm->if_address_pool_index_by_sw_if_index[sw_if_index] = ~0;

      mhash_unset (&lm->address_to_if_address_index, addr_fib,
		   /* old_value */ 0);
      pool_put (lm->if_address_pool, a);

      if (result_if_address_index)
	*result_if_address_index = ~0;
    }

  else if (! a)
    {
      u32 pi; /* previous index */
      u32 ai; 
      u32 hi; /* head index */

      pool_get (lm->if_address_pool, a);
      memset (a, ~0, sizeof (a[0]));
      ai = a - lm->if_address_pool;

      hi = pi = lm->if_address_pool_index_by_sw_if_index[sw_if_index];
      prev = 0;
      while (pi != (u32)~0)
        {
          prev = pool_elt_at_index(lm->if_address_pool, pi);
          pi = prev->next_this_sw_interface;
        }
      pi = prev ? prev - lm->if_address_pool : (u32)~0;

      a->address_key = mhash_set (&lm->address_to_if_address_index,
				  addr_fib, ai, /* old_value */ 0);
      a->address_length = address_length;
      a->sw_if_index = sw_if_index;
      a->flags = 0;
      a->prev_this_sw_interface = pi;
      a->next_this_sw_interface = ~0;
      if (prev)
          prev->next_this_sw_interface = ai;

      lm->if_address_pool_index_by_sw_if_index[sw_if_index] = 
        (hi != ~0) ? hi : ai;
      if (result_if_address_index)
	*result_if_address_index = ai;
    }
  else
    {
      if (result_if_address_index)
	*result_if_address_index = a - lm->if_address_pool;
    }
    

  return /* no error */ 0;
}

void serialize_vec_ip_adjacency (serialize_main_t * m, va_list * va)
{
  ip_adjacency_t * a = va_arg (*va, ip_adjacency_t *);
  u32 n = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n; i++)
    {
      serialize_integer (m, a[i].heap_handle, sizeof (a[i].heap_handle));
      serialize_integer (m, a[i].n_adj, sizeof (a[i].n_adj));
      serialize_integer (m, a[i].lookup_next_index, sizeof (a[i].lookup_next_index_as_int));
      switch (a[i].lookup_next_index)
	{
	case IP_LOOKUP_NEXT_LOCAL:
	  serialize_integer (m, a[i].if_address_index, sizeof (a[i].if_address_index));
	  break;

	case IP_LOOKUP_NEXT_ARP:
	  serialize_integer (m, a[i].if_address_index, sizeof (a[i].if_address_index));
	  serialize_integer (m, a[i].rewrite_header.sw_if_index, sizeof (a[i].rewrite_header.sw_if_index));
	  break;

	case IP_LOOKUP_NEXT_REWRITE:
	  serialize (m, serialize_vnet_rewrite, &a[i].rewrite_header, sizeof (a[i].rewrite_data));
	  break;

	default:
	  /* nothing else to serialize. */
	  break;
	}
    }
}

void unserialize_vec_ip_adjacency (serialize_main_t * m, va_list * va)
{
  ip_adjacency_t * a = va_arg (*va, ip_adjacency_t *);
  u32 n = va_arg (*va, u32);
  u32 i;
  ip_poison_adjacencies (a, n);
  for (i = 0; i < n; i++)
    {
      unserialize_integer (m, &a[i].heap_handle, sizeof (a[i].heap_handle));
      unserialize_integer (m, &a[i].n_adj, sizeof (a[i].n_adj));
      unserialize_integer (m, &a[i].lookup_next_index_as_int, sizeof (a[i].lookup_next_index_as_int));
      switch (a[i].lookup_next_index)
	{
	case IP_LOOKUP_NEXT_LOCAL:
	  unserialize_integer (m, &a[i].if_address_index, sizeof (a[i].if_address_index));
	  break;

	case IP_LOOKUP_NEXT_ARP:
	  unserialize_integer (m, &a[i].if_address_index, sizeof (a[i].if_address_index));
	  unserialize_integer (m, &a[i].rewrite_header.sw_if_index, sizeof (a[i].rewrite_header.sw_if_index));
	  break;

	case IP_LOOKUP_NEXT_REWRITE:
	  unserialize (m, unserialize_vnet_rewrite, &a[i].rewrite_header, sizeof (a[i].rewrite_data));
	  break;

	default:
	  /* nothing else to unserialize. */
	  break;
	}
    }
}

static void serialize_vec_ip_multipath_next_hop (serialize_main_t * m, va_list * va)
{
  ip_multipath_next_hop_t * nh = va_arg (*va, ip_multipath_next_hop_t *);
  u32 n = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n; i++)
    {
      serialize_integer (m, nh[i].next_hop_adj_index, sizeof (nh[i].next_hop_adj_index));
      serialize_integer (m, nh[i].weight, sizeof (nh[i].weight));
    }
}

static void unserialize_vec_ip_multipath_next_hop (serialize_main_t * m, va_list * va)
{
  ip_multipath_next_hop_t * nh = va_arg (*va, ip_multipath_next_hop_t *);
  u32 n = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n; i++)
    {
      unserialize_integer (m, &nh[i].next_hop_adj_index, sizeof (nh[i].next_hop_adj_index));
      unserialize_integer (m, &nh[i].weight, sizeof (nh[i].weight));
    }
}

static void serialize_vec_ip_multipath_adjacency (serialize_main_t * m, va_list * va)
{
  ip_multipath_adjacency_t * a = va_arg (*va, ip_multipath_adjacency_t *);
  u32 n = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n; i++)
    {
#define foreach_ip_multipath_adjacency_field		\
  _ (adj_index) _ (n_adj_in_block) _ (reference_count)	\
  _ (normalized_next_hops.count)			\
  _ (normalized_next_hops.heap_offset)			\
  _ (normalized_next_hops.heap_handle)			\
  _ (unnormalized_next_hops.count)			\
  _ (unnormalized_next_hops.heap_offset)		\
  _ (unnormalized_next_hops.heap_handle)

#define _(f) serialize_integer (m, a[i].f, sizeof (a[i].f));
      foreach_ip_multipath_adjacency_field;
#undef _
    }
}

static void unserialize_vec_ip_multipath_adjacency (serialize_main_t * m, va_list * va)
{
  ip_multipath_adjacency_t * a = va_arg (*va, ip_multipath_adjacency_t *);
  u32 n = va_arg (*va, u32);
  u32 i;
  for (i = 0; i < n; i++)
    {
#define _(f) unserialize_integer (m, &a[i].f, sizeof (a[i].f));
      foreach_ip_multipath_adjacency_field;
#undef _
    }
}

void serialize_ip_lookup_main (serialize_main_t * m, va_list * va)
{
  ip_lookup_main_t * lm = va_arg (*va, ip_lookup_main_t *);

  /* If this isn't true you need to call e.g. ip4_maybe_remap_adjacencies
     to make it true. */
  ASSERT (lm->n_adjacency_remaps == 0);

  serialize (m, serialize_heap, lm->adjacency_heap, serialize_vec_ip_adjacency);

  serialize (m, serialize_heap, lm->next_hop_heap, serialize_vec_ip_multipath_next_hop);
  vec_serialize (m, lm->multipath_adjacencies, serialize_vec_ip_multipath_adjacency);

  /* Adjacency counters (FIXME disabled for now). */
  if (0)
    serialize (m, serialize_vlib_combined_counter_main, &lm->adjacency_counters, /* incremental */ 0);
}

void unserialize_ip_lookup_main (serialize_main_t * m, va_list * va)
{
  ip_lookup_main_t * lm = va_arg (*va, ip_lookup_main_t *);

  unserialize (m, unserialize_heap, &lm->adjacency_heap, unserialize_vec_ip_adjacency);
  unserialize (m, unserialize_heap, &lm->next_hop_heap, unserialize_vec_ip_multipath_next_hop);
  vec_unserialize (m, &lm->multipath_adjacencies, unserialize_vec_ip_multipath_adjacency);

  /* Build hash table from unserialized data. */
  {
    ip_multipath_adjacency_t * a;

    vec_foreach (a, lm->multipath_adjacencies)
      {
	if (a->n_adj_in_block > 0 && a->reference_count > 0)
	  hash_set (lm->multipath_adjacency_by_next_hops,
		    ip_next_hop_hash_key_from_handle (a->normalized_next_hops.heap_handle),
		    a - lm->multipath_adjacencies);
      }
  }

  /* Validate adjacency counters. */
  vlib_validate_combined_counter (&lm->adjacency_counters, 
                                  vec_len (lm->adjacency_heap) - 1);

  /* Adjacency counters (FIXME disabled for now). */
  if (0)
    unserialize (m, unserialize_vlib_combined_counter_main, &lm->adjacency_counters, /* incremental */ 0);
}

void ip_lookup_init (ip_lookup_main_t * lm, u32 is_ip6)
{
  ip_adjacency_t * adj;
  ip_adjacency_t template_adj;

  /* ensure that adjacency is cacheline aligned and sized */
  ASSERT(STRUCT_OFFSET_OF(ip_adjacency_t, cacheline0) == 0);
  ASSERT(STRUCT_OFFSET_OF(ip_adjacency_t, cacheline1) == CLIB_CACHE_LINE_BYTES);

  lm->adj_index_by_signature = hash_create (0, sizeof (uword));
  memset (&template_adj, 0, sizeof (template_adj));

  /* Hand-craft special miss adjacency to use when nothing matches in the
     routing table.  Same for drop adjacency. */
  adj = ip_add_adjacency (lm, /* template */ 0, /* n-adj */ 1, &lm->miss_adj_index);
  adj->lookup_next_index = IP_LOOKUP_NEXT_MISS;
  ASSERT (lm->miss_adj_index == IP_LOOKUP_MISS_ADJ_INDEX);

  /* Make the "drop" adj sharable */
  template_adj.lookup_next_index = IP_LOOKUP_NEXT_DROP;
  adj = ip_add_adjacency (lm, &template_adj, /* n-adj */ 1, &lm->drop_adj_index);

  /* Make the "local" adj sharable */
  template_adj.lookup_next_index = IP_LOOKUP_NEXT_LOCAL;
  template_adj.if_address_index = ~0;
  adj = ip_add_adjacency (lm, &template_adj, /* n-adj */ 1, &lm->local_adj_index);

  if (! lm->fib_result_n_bytes)
    lm->fib_result_n_bytes = sizeof (uword);

  lm->multipath_adjacency_by_next_hops
    = hash_create2 (/* elts */ 0,
		    /* user */ pointer_to_uword (lm),
		    /* value_bytes */ sizeof (uword),
		    ip_next_hop_hash_key_sum,
		    ip_next_hop_hash_key_equal,
		    /* format pair/arg */
		    0, 0);

  /* 1% max error tolerance for multipath. */
  lm->multipath_next_hop_error_tolerance = .01;

  lm->is_ip6 = is_ip6;
  if (is_ip6)
    {
      lm->format_address_and_length = format_ip6_address_and_length;
      mhash_init (&lm->address_to_if_address_index, sizeof (uword),
		  sizeof (ip6_address_fib_t));
    }
  else
    {
      lm->format_address_and_length = format_ip4_address_and_length;
      mhash_init (&lm->address_to_if_address_index, sizeof (uword),
		  sizeof (ip4_address_fib_t));
    }

  {
    int i;

    /* Setup all IP protocols to be punted and builtin-unknown. */
    for (i = 0; i < 256; i++)
      {
	lm->local_next_by_ip_protocol[i] = IP_LOCAL_NEXT_PUNT;
	lm->builtin_protocol_by_ip_protocol[i] = IP_BUILTIN_PROTOCOL_UNKNOWN;
      }

    lm->local_next_by_ip_protocol[IP_PROTOCOL_UDP] = IP_LOCAL_NEXT_UDP_LOOKUP;
    lm->local_next_by_ip_protocol[is_ip6 ? IP_PROTOCOL_ICMP6 : IP_PROTOCOL_ICMP] = IP_LOCAL_NEXT_ICMP;
    lm->builtin_protocol_by_ip_protocol[IP_PROTOCOL_UDP] = IP_BUILTIN_PROTOCOL_UDP;
    lm->builtin_protocol_by_ip_protocol[is_ip6 ? IP_PROTOCOL_ICMP6 : IP_PROTOCOL_ICMP] = IP_BUILTIN_PROTOCOL_ICMP;
  }
}

u8 * format_ip_flow_hash_config (u8 * s, va_list * args)
{
  u32 flow_hash_config = va_arg (*args, u32);
    
#define _(n,v) if (flow_hash_config & v) s = format (s, "%s ", #n);
  foreach_flow_hash_bit;
#undef _

  return s;
}

u8 * format_ip_lookup_next (u8 * s, va_list * args)
{
  ip_lookup_next_t n = va_arg (*args, ip_lookup_next_t);
  char * t = 0;

  switch (n)
    {
    default:
      s = format (s, "unknown %d", n);
      return s;

    case IP_LOOKUP_NEXT_MISS: t = "miss"; break;
    case IP_LOOKUP_NEXT_DROP: t = "drop"; break;
    case IP_LOOKUP_NEXT_PUNT: t = "punt"; break;
    case IP_LOOKUP_NEXT_LOCAL: t = "local"; break;
    case IP_LOOKUP_NEXT_ARP: t = "arp"; break;
    case IP_LOOKUP_NEXT_CLASSIFY: t = "classify"; break;
    case IP_LOOKUP_NEXT_MAP: t = "map"; break;
    case IP_LOOKUP_NEXT_MAP_T: t = "map-t"; break;
    case IP_LOOKUP_NEXT_SIXRD: t = "sixrd"; break;
    case IP_LOOKUP_NEXT_REWRITE:
      break;
    }

  if (t)
    vec_add (s, t, strlen (t));

  return s;
}

static u8 * format_ip_interface_address (u8 * s, va_list * args)
{
  ip_lookup_main_t * lm = va_arg (*args, ip_lookup_main_t *);
  u32 if_address_index = va_arg (*args, u32);
  ip_interface_address_t * ia = pool_elt_at_index (lm->if_address_pool, if_address_index);
  void * a = ip_interface_address_get_address (lm, ia);

  if (lm->is_ip6)
    return format (s, "%U", format_ip6_address_and_length, a, ia->address_length);
  else
    return format (s, "%U", format_ip4_address_and_length, a, ia->address_length);
}

u8 * format_ip_adjacency (u8 * s, va_list * args)
{
  vnet_main_t * vnm = va_arg (*args, vnet_main_t *);
  ip_lookup_main_t * lm = va_arg (*args, ip_lookup_main_t *);
  u32 adj_index = va_arg (*args, u32);
  ip_adjacency_t * adj = ip_get_adjacency (lm, adj_index);

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_REWRITE:
      s = format (s, "%U",
		  format_vnet_rewrite,
		  vnm->vlib_main, &adj->rewrite_header, sizeof (adj->rewrite_data));
      break;

    default:
      s = format (s, "%U", format_ip_lookup_next, adj->lookup_next_index);
      if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP)
	s = format (s, " %U",
		    format_vnet_sw_interface_name,
		    vnm,
		    vnet_get_sw_interface (vnm, adj->rewrite_header.sw_if_index));
      switch (adj->lookup_next_index)
	{
	case IP_LOOKUP_NEXT_ARP:
	case IP_LOOKUP_NEXT_LOCAL:
	  if (adj->if_address_index != ~0)
	    s = format (s, " %U", format_ip_interface_address, lm, adj->if_address_index);
	  break;

        case IP_LOOKUP_NEXT_CLASSIFY:
            s = format (s, " table %d", adj->classify_table_index);

	default:
	  break;
	}
      break;
    }
  if (adj->explicit_fib_index != ~0 && adj->explicit_fib_index != 0)
    s = format (s, " lookup fib index %d", adj->explicit_fib_index);
  if (adj->share_count > 0)
    s = format (s, " shared %d", adj->share_count + 1);
  if (adj->next_adj_with_signature)
    s = format (s, " next_adj_with_signature %d", adj->next_adj_with_signature);

  return s;
}

u8 * format_ip_adjacency_packet_data (u8 * s, va_list * args)
{
  vnet_main_t * vnm = va_arg (*args, vnet_main_t *);
  ip_lookup_main_t * lm = va_arg (*args, ip_lookup_main_t *);
  u32 adj_index = va_arg (*args, u32);
  u8 * packet_data = va_arg (*args, u8 *);
  u32 n_packet_data_bytes = va_arg (*args, u32);
  ip_adjacency_t * adj = ip_get_adjacency (lm, adj_index);

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_REWRITE:
      s = format (s, "%U",
		  format_vnet_rewrite_header,
		  vnm->vlib_main, &adj->rewrite_header, packet_data, n_packet_data_bytes);
      break;

    default:
      break;
    }

  return s;
}

static uword unformat_ip_lookup_next (unformat_input_t * input, va_list * args)
{
  ip_lookup_next_t * result = va_arg (*args, ip_lookup_next_t *);
  ip_lookup_next_t n;

  if (unformat (input, "drop"))
    n = IP_LOOKUP_NEXT_DROP;

  else if (unformat (input, "punt"))
    n = IP_LOOKUP_NEXT_PUNT;

  else if (unformat (input, "local"))
    n = IP_LOOKUP_NEXT_LOCAL;

  else if (unformat (input, "arp"))
    n = IP_LOOKUP_NEXT_ARP;

  else if (unformat (input, "classify"))
    n = IP_LOOKUP_NEXT_CLASSIFY;

  else
    return 0;
    
  *result = n;
  return 1;
}

static uword unformat_ip_adjacency (unformat_input_t * input, va_list * args)
{
  vlib_main_t * vm = va_arg (*args, vlib_main_t *);
  ip_adjacency_t * adj = va_arg (*args, ip_adjacency_t *);
  u32 node_index = va_arg (*args, u32);
  vnet_main_t * vnm = vnet_get_main();
  u32 sw_if_index, is_ip6;
  ip46_address_t a46;
  ip_lookup_next_t next;

  is_ip6 = node_index == ip6_rewrite_node.index;
  adj->rewrite_header.node_index = node_index;
  adj->explicit_fib_index = ~0;

  if (unformat (input, "arp %U %U",
		unformat_vnet_sw_interface, vnm, &sw_if_index,
		unformat_ip46_address, &a46, is_ip6))
    {
      ip_lookup_main_t * lm = is_ip6 ? &ip6_main.lookup_main : &ip4_main.lookup_main;
      ip_adjacency_t * a_adj;
      u32 adj_index;

      if (is_ip6)
	adj_index = ip6_fib_lookup (&ip6_main, sw_if_index, &a46.ip6);
      else
	adj_index = ip4_fib_lookup (&ip4_main, sw_if_index, &a46.ip4);

      a_adj = ip_get_adjacency (lm, adj_index);

      if (a_adj->rewrite_header.sw_if_index != sw_if_index)
	return 0;

      if (is_ip6)
	ip6_adjacency_set_interface_route (vnm, adj, sw_if_index, a_adj->if_address_index);
      else
	ip4_adjacency_set_interface_route (vnm, adj, sw_if_index, a_adj->if_address_index);
    }

  else if (unformat_user (input, unformat_ip_lookup_next, &next))
    {
      adj->lookup_next_index = next;
      adj->if_address_index = ~0;
      if (next == IP_LOOKUP_NEXT_LOCAL)
        (void) unformat (input, "%d", &adj->if_address_index);
      else if (next == IP_LOOKUP_NEXT_CLASSIFY)
        {
          if (!unformat (input, "%d", &adj->classify_table_index))
            {
              clib_warning ("classify adj must specify table index");
              return 0;
            }
        }
      else if (next == IP_LOOKUP_NEXT_DROP)
        {
          adj->rewrite_header.node_index = 0;
        }
    }

  else if (unformat_user (input,
			  unformat_vnet_rewrite,
			  vm, &adj->rewrite_header, sizeof (adj->rewrite_data)))
    adj->lookup_next_index = IP_LOOKUP_NEXT_REWRITE;

  else
    return 0;

  return 1;
}

clib_error_t *
vnet_ip_route_cmd (vlib_main_t * vm, unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 table_id, is_del;
  u32 weight, * weights = 0;
  u32 * table_ids = 0;
  u32 sw_if_index, * sw_if_indices = 0;
  ip4_address_t ip4_addr, * ip4_dst_addresses = 0, * ip4_via_next_hops = 0;
  ip6_address_t ip6_addr, * ip6_dst_addresses = 0, * ip6_via_next_hops = 0;
  u32 dst_address_length, * dst_address_lengths = 0;
  ip_adjacency_t parse_adj, * add_adj = 0;
  unformat_input_t _line_input, * line_input = &_line_input;
  f64 count;
  u32 outer_table_id;

  is_del = 0;
  table_id = 0;
  count = 1;

  /* Get a line of input. */
  if (! unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  memset(&parse_adj, 0, sizeof (parse_adj));

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "add"))
	is_del = 0;
      else if (unformat (line_input, "count %f", &count))
	;

      else if (unformat (line_input, "%U/%d",
			 unformat_ip4_address, &ip4_addr,
			 &dst_address_length))
	{
	  vec_add1 (ip4_dst_addresses, ip4_addr);
	  vec_add1 (dst_address_lengths, dst_address_length);
	}

      else if (unformat (line_input, "%U/%d",
			 unformat_ip6_address, &ip6_addr,
			 &dst_address_length))
	{
	  vec_add1 (ip6_dst_addresses, ip6_addr);
	  vec_add1 (dst_address_lengths, dst_address_length);
	}

      else if (unformat (line_input, "via %U %U weight %u",
			 unformat_ip4_address, &ip4_addr,
			 unformat_vnet_sw_interface, vnm, &sw_if_index,
			 &weight))
	{
	  vec_add1 (ip4_via_next_hops, ip4_addr);
	  vec_add1 (sw_if_indices, sw_if_index);
	  vec_add1 (weights, weight);
          vec_add1 (table_ids, (u32)~0);
	}

      else if (unformat (line_input, "via %U %U weight %u",
			 unformat_ip6_address, &ip6_addr,
			 unformat_vnet_sw_interface, vnm, &sw_if_index,
			 &weight))
	{
	  vec_add1 (ip6_via_next_hops, ip6_addr);
	  vec_add1 (sw_if_indices, sw_if_index);
	  vec_add1 (weights, weight);
          vec_add1 (table_ids, (u32)~0);
	}

      else if (unformat (line_input, "via %U %U",
			 unformat_ip4_address, &ip4_addr,
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  vec_add1 (ip4_via_next_hops, ip4_addr);
	  vec_add1 (sw_if_indices, sw_if_index);
	  vec_add1 (weights, 1);
          vec_add1 (table_ids, (u32)~0);
	}
			 
      else if (unformat (line_input, "via %U %U",
			 unformat_ip6_address, &ip6_addr,
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  vec_add1 (ip6_via_next_hops, ip6_addr);
	  vec_add1 (sw_if_indices, sw_if_index);
	  vec_add1 (weights, 1);
          vec_add1 (table_ids, (u32)~0);
	}
      else if (unformat (line_input, "via %U",
			 unformat_ip4_address, &ip4_addr))
	{
	  vec_add1 (ip4_via_next_hops, ip4_addr);
	  vec_add1 (sw_if_indices, (u32)~0);
	  vec_add1 (weights, 1);
          vec_add1 (table_ids, table_id);
	}
      else if (unformat (line_input, "via %U",
			 unformat_ip6_address, &ip6_addr))
	{
	  vec_add1 (ip6_via_next_hops, ip6_addr);
	  vec_add1 (sw_if_indices, (u32)~0);
	  vec_add1 (weights, 1);
          vec_add1 (table_ids, (u32)table_id);
	}
			 
      else if (vec_len (ip4_dst_addresses) > 0
	       && unformat (line_input, "via %U",
			    unformat_ip_adjacency, vm, &parse_adj, ip4_rewrite_node.index))
          vec_add1 (add_adj, parse_adj);

      else if (vec_len (ip6_dst_addresses) > 0
	       && unformat (line_input, "via %U",
			    unformat_ip_adjacency, vm, &parse_adj, ip6_rewrite_node.index))
	vec_add1 (add_adj, parse_adj);
      else if (unformat (line_input, "lookup in table %d", &outer_table_id))
        {
          uword * p;

          if (vec_len (ip4_dst_addresses) > 0)
            p = hash_get (ip4_main.fib_index_by_table_id, outer_table_id);
          else
            p = hash_get (ip6_main.fib_index_by_table_id, outer_table_id);

          if (p == 0)
            {
              error = clib_error_return (0, "Nonexistent outer table id %d", 
                                         outer_table_id);
              goto done;
            }

          parse_adj.lookup_next_index = IP_LOOKUP_NEXT_LOCAL;
          parse_adj.explicit_fib_index = p[0];
          vec_add1 (add_adj, parse_adj);
        }
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }
    
  unformat_free (line_input);

  if (vec_len (ip4_dst_addresses) + vec_len (ip6_dst_addresses) == 0)
    {
      error = clib_error_return (0, "expected ip4/ip6 destination address/length.");
      goto done;
    }

  if (vec_len (ip4_dst_addresses) > 0 && vec_len (ip6_dst_addresses) > 0)
    {
      error = clib_error_return (0, "mixed ip4/ip6 address/length.");
      goto done;
    }

  if (vec_len (ip4_dst_addresses) > 0 && vec_len (ip6_via_next_hops) > 0)
    {
      error = clib_error_return (0, "ip4 destinations with ip6 next hops.");
      goto done;
    }

  if (vec_len (ip6_dst_addresses) > 0 && vec_len (ip4_via_next_hops) > 0)
    {
      error = clib_error_return (0, "ip6 destinations with ip4 next hops.");
      goto done;
    }

  if (! is_del && vec_len (add_adj) + vec_len (weights) == 0)
    {
      error = clib_error_return (0, "no next hops or adjacencies to add.");
      goto done;
    }

  if (vec_len(ip4_via_next_hops))
    {
      if (sw_if_indices[0] == (u32)~0)
        {
          u32 ai;
          uword * p;
          u32 fib_index;
          ip_adjacency_t *nh_adj;

          p = hash_get (ip4_main.fib_index_by_table_id, table_ids[0]);
          if (p == 0)
            {
              error = clib_error_return (0, "Nonexistent FIB id %d",
                                         table_ids[0]);
              goto done;
            }

          fib_index = p[0];

          ai = ip4_fib_lookup_with_table (&ip4_main,
                                          fib_index,
                                          ip4_via_next_hops,
                                          1 /* disable default route */);
          if (ai == 0)
            {
              error = clib_error_return (0, "next hop %U not in FIB",
                                         format_ip4_address,
                                         ip4_via_next_hops);
              goto done;
            }
          nh_adj = ip_get_adjacency (&ip4_main.lookup_main, ai);
          vec_add1 (add_adj, nh_adj[0]);
        }
    }
  if (vec_len(ip6_via_next_hops))
    {
      if (sw_if_indices[0] == (u32)~0)
        {
          u32 ai;
          uword * p;
          u32 fib_index;
          ip_adjacency_t *nh_adj;

          p = hash_get (ip6_main.fib_index_by_table_id, table_ids[0]);
          if (p == 0)
            {
              error = clib_error_return (0, "Nonexistent FIB id %d",
                                         table_ids[0]);
              goto done;
            }

          fib_index = p[0];
          ai = ip6_fib_lookup_with_table (&ip6_main,
                                          fib_index,
                                          ip6_via_next_hops);
          if (ai == 0)
            {
              error = clib_error_return (0, "next hop %U not in FIB",
                                         format_ip6_address,
                                         ip6_via_next_hops);
              goto done;
            }
          nh_adj = ip_get_adjacency (&ip6_main.lookup_main, ai);
          vec_add1 (add_adj, nh_adj[0]);
        }
    }

  {
    int i;
    ip4_main_t * im4 = &ip4_main;
    ip6_main_t * im6 = &ip6_main;

    for (i = 0; i < vec_len (ip4_dst_addresses); i++)
      {
	ip4_add_del_route_args_t a;

	memset (&a, 0, sizeof (a));
	a.flags = IP4_ROUTE_FLAG_TABLE_ID;
	a.table_index_or_table_id = table_id;
	a.dst_address = ip4_dst_addresses[i];
	a.dst_address_length = dst_address_lengths[i];
	a.adj_index = ~0;

	if (is_del)
	  {
	    if (vec_len (ip4_via_next_hops) == 0)
	      {
                uword * dst_hash, * dst_result;
                u32 dst_address_u32;
                ip4_fib_t * fib;

                fib = find_ip4_fib_by_table_index_or_id (im4, table_id, 
                                                         0 /* by table id */);

		a.flags |= IP4_ROUTE_FLAG_DEL;
                dst_address_u32 = a.dst_address.as_u32 
                  & im4->fib_masks[a.dst_address_length];

                dst_hash = 
                  fib->adj_index_by_dst_address[a.dst_address_length];
                dst_result = hash_get (dst_hash, dst_address_u32);
                if (dst_result)
                  a.adj_index = dst_result[0];
                else
                  {
                    clib_warning ("%U/%d not in FIB",
                                  format_ip4_address, &a.dst_address,
                                  a.dst_address_length);
                    continue;
                  }

		ip4_add_del_route (im4, &a);
		ip4_maybe_remap_adjacencies (im4, table_id, 
                                             IP4_ROUTE_FLAG_TABLE_ID);
	      }
	    else
	      {
                u32 i, j, n, f, incr;
		ip4_address_t dst = a.dst_address;
		f64 t[2];
		n = count;
		t[0] = vlib_time_now (vm);
                incr = 1<<(32 - a.dst_address_length);
		for (i = 0; i < n; i++)
		  {
		    f = i + 1 < n ? IP4_ROUTE_FLAG_NOT_LAST_IN_GROUP : 0;
		    a.dst_address = dst;
		    for (j = 0; j < vec_len (ip4_via_next_hops); j++)
                      {
                        if (table_ids[j] != (u32)~0)
                          {
                            uword * p = hash_get (im4->fib_index_by_table_id, 
                                                  table_ids[j]);
                            if (p == 0) 
                              {
                                clib_warning ("no such FIB table %d",
                                              table_ids[j]);
                                continue;
                              }
                            table_ids[j] = p[0];
                          }
                        
                        ip4_add_del_route_next_hop (im4,
                                                    IP4_ROUTE_FLAG_DEL | f,
                                                    &a.dst_address,
                                                    a.dst_address_length,
                                                    &ip4_via_next_hops[j],
                                                    sw_if_indices[j],
                                                    weights[j], (u32)~0, 
                                                    table_ids[j] /* fib index */);
                      }
                    dst.as_u32 = clib_host_to_net_u32 (incr + clib_net_to_host_u32 (dst.as_u32));
		  }
		t[1] = vlib_time_now (vm);
		if (count > 1)
		  vlib_cli_output (vm, "%.6e routes/sec", count / (t[1] - t[0]));
	      }
	  }
	else
	  {
	    if (vec_len (add_adj) > 0)
	      {
		a.flags |= IP4_ROUTE_FLAG_ADD;
		a.add_adj = add_adj;
		a.n_add_adj = vec_len (add_adj);
	      
		ip4_add_del_route (im4, &a);
	      }
	    else if (vec_len (ip4_via_next_hops) > 0)
	      {
                u32 i, j, n, f, incr;
		ip4_address_t dst = a.dst_address;
		f64 t[2];
		n = count;
		t[0] = vlib_time_now (vm);
                incr = 1<<(32 - a.dst_address_length);
		for (i = 0; i < n; i++)
		  {
		    f = i + 1 < n ? IP4_ROUTE_FLAG_NOT_LAST_IN_GROUP : 0;
		    a.dst_address = dst;
		    for (j = 0; j < vec_len (ip4_via_next_hops); j++)
                      {
                        if (table_ids[j] != (u32)~0)
                          {
                            uword * p = hash_get (im4->fib_index_by_table_id, 
                                                  table_ids[j]);
                            if (p == 0) 
                              {
                                clib_warning ("no such FIB table %d",
                                              table_ids[j]);
                                continue;
                              }
                            table_ids[j] = p[0];
                          }
		      ip4_add_del_route_next_hop (im4,
						  IP4_ROUTE_FLAG_ADD | f,
						  &a.dst_address,
						  a.dst_address_length,
						  &ip4_via_next_hops[j],
						  sw_if_indices[j],
						  weights[j], (u32)~0, 
                                                  table_ids[j] /* fib index */);
                      }
		    dst.as_u32 = clib_host_to_net_u32 (incr + clib_net_to_host_u32 (dst.as_u32));
		  }
		t[1] = vlib_time_now (vm);
		if (count > 1)
		  vlib_cli_output (vm, "%.6e routes/sec", count / (t[1] - t[0]));
	      }
	  }
      }

    for (i = 0; i < vec_len (ip6_dst_addresses); i++)
      {
	ip6_add_del_route_args_t a;
        

	memset (&a, 0, sizeof (a));
	a.flags = IP6_ROUTE_FLAG_TABLE_ID;
	a.table_index_or_table_id = table_id;
	a.dst_address = ip6_dst_addresses[i];
	a.dst_address_length = dst_address_lengths[i];
	a.adj_index = ~0;

	if (is_del)
	  {
	    if (vec_len (ip6_via_next_hops) == 0)
	      {
                BVT(clib_bihash_kv) kv, value;
                ip6_address_t dst_address;
                ip6_fib_t * fib;

                fib = find_ip6_fib_by_table_index_or_id (im6, table_id, 
                                                         0 /* by table id */);

		a.flags |= IP4_ROUTE_FLAG_DEL;

                dst_address = ip6_dst_addresses[i];

                ip6_address_mask (&dst_address, 
                                  &im6->fib_masks[dst_address_length]);
                
                kv.key[0] = dst_address.as_u64[0];
                kv.key[1] = dst_address.as_u64[1];
                kv.key[2] = ((u64)(fib - im6->fibs)<<32)
                  | a.dst_address_length;
                
                if (BV(clib_bihash_search)(&im6->ip6_lookup_table,
                                           &kv, &value) == 0)
                  a.adj_index = value.value;
                else
                  {
                    clib_warning ("%U/%d not in FIB",
                                  format_ip6_address, &a.dst_address,
                                  a.dst_address_length);
                    continue;
                  }
                
		a.flags |= IP6_ROUTE_FLAG_DEL;
		ip6_add_del_route (im6, &a);
		ip6_maybe_remap_adjacencies (im6, table_id, 
                                             IP6_ROUTE_FLAG_TABLE_ID);
	      }
	    else
	      {
		u32 i;
		for (i = 0; i < vec_len (ip6_via_next_hops); i++)
		  {
		    ip6_add_del_route_next_hop (im6,
						IP6_ROUTE_FLAG_DEL,
						&a.dst_address,
						a.dst_address_length,
						&ip6_via_next_hops[i],
						sw_if_indices[i],
						weights[i], (u32)~0,
                                                table_ids[i] /* fib index */);
		  }
	      }
	  }
	else
	  {
	    if (vec_len (add_adj) > 0)
	      {
		a.flags |= IP6_ROUTE_FLAG_ADD;
		a.add_adj = add_adj;
		a.n_add_adj = vec_len (add_adj);
	      
		ip6_add_del_route (im6, &a);
	      }
	    else if (vec_len (ip6_via_next_hops) > 0)
	      {
		u32 i;
		for (i = 0; i < vec_len (ip6_via_next_hops); i++)
		  {
		    ip6_add_del_route_next_hop (im6,
						IP6_ROUTE_FLAG_ADD,
						&a.dst_address,
						a.dst_address_length,
						&ip6_via_next_hops[i],
						sw_if_indices[i],
						weights[i], (u32)~0,
                                                table_ids[i]);
		  }
	      }
	  }
      }
  }

 done:
  vec_free (add_adj);
  vec_free (weights);
  vec_free (dst_address_lengths);
  vec_free (ip4_dst_addresses);
  vec_free (ip6_dst_addresses);
  vec_free (ip4_via_next_hops);
  vec_free (ip6_via_next_hops);
  return error;
}

VLIB_CLI_COMMAND (vlib_cli_ip_command, static) = {
  .path = "ip",
  .short_help = "Internet protocol (IP) commands",
};

VLIB_CLI_COMMAND (vlib_cli_show_ip_command, static) = {
  .path = "show ip",
  .short_help = "Internet protocol (IP) show commands",
};

VLIB_CLI_COMMAND (vlib_cli_show_ip4_command, static) = {
  .path = "show ip4",
  .short_help = "Internet protocol version 4 (IP4) show commands",
};

VLIB_CLI_COMMAND (vlib_cli_show_ip6_command, static) = {
  .path = "show ip6",
  .short_help = "Internet protocol version 6 (IP6) show commands",
};

VLIB_CLI_COMMAND (ip_route_command, static) = {
  .path = "ip route",
  .short_help = "Add/delete IP routes",
  .function = vnet_ip_route_cmd,
};

/* 
 * The next two routines address a longstanding script hemorrhoid.
 * Probing a v4 or v6 neighbor needs to appear to be synchronous,
 * or dependent route-adds will simply fail.
 */
static clib_error_t *
ip6_probe_neighbor_wait (vlib_main_t *vm, ip6_address_t * a, u32 sw_if_index,
                         int retry_count)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * e;
  int i;
  int resolved = 0;
  uword event_type;
  uword *event_data = 0;

  ASSERT (vlib_in_process_context(vm));

  if (retry_count > 0)
    vnet_register_ip6_neighbor_resolution_event 
      (vnm, a, vlib_get_current_process (vm)->node_runtime.node_index,
       1 /* event */, 0 /* data */);

  for (i = 0; i < retry_count; i++)
    {
      /* The interface may be down, etc. */
      e = ip6_probe_neighbor (vm, a, sw_if_index);
      
      if (e)
        return e;
      
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type) 
        {
        case 1: /* resolved... */
          vlib_cli_output (vm, "Resolved %U", 
                           format_ip6_address, a);
          resolved = 1;
          goto done;
          
        case ~0: /* timeout */
          break;
          
        default:
          clib_warning ("unknown event_type %d", event_type);
        }
    }
  
 done:
  vec_reset_length (event_data);

  if (!resolved)
    return clib_error_return (0, "Resolution failed for %U",
                              format_ip6_address, a);
  return 0;
}

static clib_error_t *
ip4_probe_neighbor_wait (vlib_main_t *vm, ip4_address_t * a, u32 sw_if_index,
                         int retry_count)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * e;
  int i;
  int resolved = 0;
  uword event_type;
  uword *event_data = 0;

  ASSERT (vlib_in_process_context(vm));

  if (retry_count > 0)
    vnet_register_ip4_arp_resolution_event 
      (vnm, a, vlib_get_current_process (vm)->node_runtime.node_index,
       1 /* event */, 0 /* data */);
  
  for (i = 0; i < retry_count; i++)
    {
      /* The interface may be down, etc. */
      e = ip4_probe_neighbor (vm, a, sw_if_index);
      
      if (e)
        return e;
      
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type) 
        {
        case 1: /* resolved... */
          vlib_cli_output (vm, "Resolved %U", 
                           format_ip4_address, a);
          resolved = 1;
          goto done;
          
        case ~0: /* timeout */
          break;
          
        default:
          clib_warning ("unknown event_type %d", event_type);
        }
    }
  
 done:

  vec_reset_length (event_data);

  if (!resolved)
    return clib_error_return (0, "Resolution failed for %U",
                              format_ip4_address, a);
  return 0;
}

static clib_error_t *
probe_neighbor_address (vlib_main_t * vm,
			unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  unformat_input_t _line_input, * line_input = &_line_input;
  ip4_address_t a4;
  ip6_address_t a6;
  clib_error_t * error = 0;
  u32 sw_if_index = ~0;
  int retry_count = 3;
  int is_ip4 = 1;
  int address_set = 0;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat_user (line_input, unformat_vnet_sw_interface, vnm, 
                         &sw_if_index))
        ;
      else if (unformat (line_input, "retry %d", &retry_count))
        ;

      else if (unformat (line_input, "%U", unformat_ip4_address, &a4))
        address_set++;
      else if (unformat (line_input, "%U", unformat_ip6_address, &a6))
        {
          address_set++;
          is_ip4 = 0;
        }
      else
        return clib_error_return (0, "unknown input '%U'",
                                  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface required, not set.");
  if (address_set == 0)
    return clib_error_return (0, "ip address required, not set.");
  if (address_set > 1)
    return clib_error_return (0, "Multiple ip addresses not supported.");
    
  if (is_ip4)
    error = ip4_probe_neighbor_wait (vm, &a4, sw_if_index, retry_count);
  else 
    error = ip6_probe_neighbor_wait (vm, &a6, sw_if_index, retry_count);

  return error;
}

VLIB_CLI_COMMAND (ip_probe_neighbor_command, static) = {
  .path = "ip probe-neighbor",
  .function = probe_neighbor_address,
  .short_help = "ip probe-neighbor <intfc> <ip4-addr> | <ip6-addr> [retry nn]",
};

typedef CLIB_PACKED (struct {
  ip4_address_t address;

  u32 address_length : 6;

  u32 index : 26;
}) ip4_route_t;

static int
ip4_route_cmp (void * a1, void * a2)
{
  ip4_route_t * r1 = a1;
  ip4_route_t * r2 = a2;

  int cmp = ip4_address_compare (&r1->address, &r2->address);
  return cmp ? cmp : ((int) r1->address_length - (int) r2->address_length);
}

static clib_error_t *
ip4_show_fib (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  ip4_main_t * im4 = &ip4_main;
  ip4_route_t * routes, * r;
  ip4_fib_t * fib;
  ip_lookup_main_t * lm = &im4->lookup_main;
  uword * results, i;
  int verbose, matching, mtrie, include_empty_fibs;
  ip4_address_t matching_address;
  u8 clear = 0;
  int table_id = -1;

  routes = 0;
  results = 0;
  verbose = 1;
  include_empty_fibs = 0;
  matching = 0;
  mtrie = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "brief") || unformat (input, "summary")
	  || unformat (input, "sum"))
	verbose = 0;

      else if (unformat (input, "mtrie"))
	mtrie = 1;

      else if (unformat (input, "include-empty"))
        include_empty_fibs = 1;

      else if (unformat (input, "%U", unformat_ip4_address, &matching_address))
	matching = 1;

      else if (unformat (input, "clear"))
        clear = 1;

      else if (unformat (input, "table %d", &table_id))
               ;
      else
	break;
    }

  vec_foreach (fib, im4->fibs)
    {
      int fib_not_empty;

      fib_not_empty = 0;
      for (i = 0; i < ARRAY_LEN (fib->adj_index_by_dst_address); i++)
        {
          uword * hash = fib->adj_index_by_dst_address[i];
          uword n_elts = hash_elts (hash);
          if (n_elts)
            {
              fib_not_empty = 1;
              break;
            }
        }
      
      if (fib_not_empty == 0 && include_empty_fibs == 0)
        continue;

      if (table_id >= 0 && table_id != (int)fib->table_id)
        continue;

      if (include_empty_fibs)
          vlib_cli_output (vm, "Table %d, fib_index %d, flow hash: %U", 
                           fib->table_id, fib - im4->fibs,
                           format_ip_flow_hash_config, fib->flow_hash_config);

      /* Show summary? */
      if (! verbose)
	{
        if (include_empty_fibs == 0)
            vlib_cli_output (vm, "Table %d, fib_index %d, flow hash: %U", 
                             fib->table_id, fib - im4->fibs,
                             format_ip_flow_hash_config, fib->flow_hash_config);
	  vlib_cli_output (vm, "%=20s%=16s", "Prefix length", "Count");
	  for (i = 0; i < ARRAY_LEN (fib->adj_index_by_dst_address); i++)
	    {
	      uword * hash = fib->adj_index_by_dst_address[i];
	      uword n_elts = hash_elts (hash);
	      if (n_elts > 0)
		vlib_cli_output (vm, "%20d%16d", i, n_elts);
	    }
	  continue;
	}

      if (routes)
	_vec_len (routes) = 0;
      if (results)
	_vec_len (results) = 0;

      for (i = 0; i < ARRAY_LEN (fib->adj_index_by_dst_address); i++)
	{
	  uword * hash = fib->adj_index_by_dst_address[i];
	  hash_pair_t * p;
	  ip4_route_t x;

	  x.address_length = i;

	  if (matching)
	    {
	      x.address.as_u32 = matching_address.as_u32 & im4->fib_masks[i];
	      p = hash_get_pair (hash, x.address.as_u32);
	      if (p)
		{
		  if (lm->fib_result_n_words > 1)
		    {
		      x.index = vec_len (results);
		      vec_add (results, p->value, lm->fib_result_n_words);
		    }
		  else
		    x.index = p->value[0];
		  vec_add1 (routes, x);
		}
	    }
	  else
	    {
	      hash_foreach_pair (p, hash, ({
		x.address.data_u32 = p->key;
		if (lm->fib_result_n_words > 1)
		  {
		    x.index = vec_len (results);
		    vec_add (results, p->value, lm->fib_result_n_words);
		  }
		else
		  x.index = p->value[0];

		vec_add1 (routes, x);
	      }));
	    }
	}

      vec_sort_with_function (routes, ip4_route_cmp);
      if (vec_len(routes)) {
          if (include_empty_fibs == 0)
              vlib_cli_output (vm, "Table %d, fib_index %d, flow hash: %U", 
                               fib->table_id, fib - im4->fibs,
                               format_ip_flow_hash_config, fib->flow_hash_config);
          if (mtrie)
              vlib_cli_output (vm, "%U", format_ip4_fib_mtrie, &fib->mtrie);
          vlib_cli_output (vm, "%=20s%=16s%=16s%=16s",
                           "Destination", "Packets", "Bytes", "Adjacency");
      }
      vec_foreach (r, routes)
	{
	  vlib_counter_t c, sum;
	  uword i, j, n_left, n_nhs, adj_index, * result = 0;
	  ip_adjacency_t * adj;
	  ip_multipath_next_hop_t * nhs, tmp_nhs[1];

	  adj_index = r->index;
	  if (lm->fib_result_n_words > 1)
	    {
	      result = vec_elt_at_index (results, adj_index);
	      adj_index = result[0];
	    }

	  adj = ip_get_adjacency (lm, adj_index);
	  if (adj->n_adj == 1)
	    {
	      nhs = &tmp_nhs[0];
	      nhs[0].next_hop_adj_index = ~0; /* not used */
	      nhs[0].weight = 1;
	      n_nhs = 1;
	    }
	  else
	    {
	      ip_multipath_adjacency_t * madj;
	      madj = vec_elt_at_index (lm->multipath_adjacencies, adj->heap_handle);
	      nhs = heap_elt_at_index (lm->next_hop_heap, madj->normalized_next_hops.heap_offset);
	      n_nhs = madj->normalized_next_hops.count;
	    }

	  n_left = nhs[0].weight;
	  vlib_counter_zero (&sum);
	  for (i = j = 0; i < adj->n_adj; i++)
	    {
	      n_left -= 1;
	      vlib_get_combined_counter (&lm->adjacency_counters, 
                                         adj_index + i, &c);
              if (clear)
                vlib_zero_combined_counter (&lm->adjacency_counters,
                                            adj_index + i);
	      vlib_counter_add (&sum, &c);
	      if (n_left == 0)
		{
		  u8 * msg = 0;
		  uword indent;

		  if (j == 0)
		    msg = format (msg, "%-20U",
				  format_ip4_address_and_length,
				  r->address.data, r->address_length);
		  else
		    msg = format (msg, "%U", format_white_space, 20);

		  msg = format (msg, "%16Ld%16Ld ", sum.packets, sum.bytes);

		  indent = vec_len (msg);
		  msg = format (msg, "weight %d, index %d\n%U%U",
				nhs[j].weight, adj_index + i,
				format_white_space, indent,
				format_ip_adjacency,
				vnm, lm, adj_index + i);

		  vlib_cli_output (vm, "%v", msg);
		  vec_free (msg);

		  if (result && lm->format_fib_result)
		    vlib_cli_output (vm, "%20s%U", "",
				     lm->format_fib_result, vm, lm, result,
				     i + 1 - nhs[j].weight,
				     nhs[j].weight);

		  j++;
		  if (j < n_nhs)
		    {
		      n_left = nhs[j].weight;
		      vlib_counter_zero (&sum);
		    }
		}
	    }
	}
    }

  vec_free (routes);
  vec_free (results);

  return 0;
}

VLIB_CLI_COMMAND (ip4_show_fib_command, static) = {
  .path = "show ip fib",
  .short_help = "show ip fib [mtrie] [summary] [table <n>] [<ip4-addr>] [clear] [include-empty]",
  .function = ip4_show_fib,
};

typedef struct {
  ip6_address_t address;

  u32 address_length;

  u32 index;
} ip6_route_t;

typedef struct {
  u32 fib_index;
  ip6_route_t ** routep;
} add_routes_in_fib_arg_t;

static void add_routes_in_fib (BVT(clib_bihash_kv) * kvp, void *arg)
{
  add_routes_in_fib_arg_t * ap = arg;

  if (kvp->key[2]>>32 == ap->fib_index)
    {
      ip6_address_t *addr;
      ip6_route_t * r;
      addr = (ip6_address_t *) kvp;
      vec_add2 (*ap->routep, r, 1);
      r->address = addr[0];
      r->address_length = kvp->key[2] & 0xFF;
      r->index = kvp->value;
    }
}

typedef struct {
  u32 fib_index;
  u64 count_by_prefix_length[129];
} count_routes_in_fib_at_prefix_length_arg_t;

static void count_routes_in_fib_at_prefix_length 
(BVT(clib_bihash_kv) * kvp, void *arg)
{
  count_routes_in_fib_at_prefix_length_arg_t * ap = arg;
  int mask_width;

  if ((kvp->key[2]>>32) != ap->fib_index)
    return;

  mask_width = kvp->key[2] & 0xFF;

  ap->count_by_prefix_length[mask_width]++;
}

static int
ip6_route_cmp (void * a1, void * a2)
{
  ip6_route_t * r1 = a1;
  ip6_route_t * r2 = a2;

  int cmp = ip6_address_compare (&r1->address, &r2->address);
  return cmp ? cmp : ((int) r1->address_length - (int) r2->address_length);
}

static clib_error_t *
ip6_show_fib (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_main_t * im6 = &ip6_main;
  ip6_route_t * routes, * r;
  ip6_fib_t * fib;
  ip_lookup_main_t * lm = &im6->lookup_main;
  uword * results;
  int verbose;
  BVT(clib_bihash) * h = &im6->ip6_lookup_table;
  __attribute__((unused)) u8 clear = 0;
  add_routes_in_fib_arg_t _a, *a=&_a;
  count_routes_in_fib_at_prefix_length_arg_t _ca, *ca = &_ca;

  routes = 0;
  results = 0;
  verbose = 1;
  if (unformat (input, "brief") || unformat (input, "summary")
      || unformat (input, "sum"))
    verbose = 0;

  if (unformat (input, "clear"))
    clear = 1;

  vlib_cli_output (vm, "FIB lookup table: %d buckets, %lld MB heap",
                   im6->lookup_table_nbuckets, im6->lookup_table_size>>20);
  vlib_cli_output (vm, "%U", format_mheap, h->mheap, 0 /*verbose*/); 
  vlib_cli_output (vm, " ");
  
  vec_foreach (fib, im6->fibs)
    {
      vlib_cli_output (vm, "VRF %d, fib_index %d, flow hash: %U", 
                       fib->table_id, fib - im6->fibs,
                       format_ip_flow_hash_config, fib->flow_hash_config);
      
      /* Show summary? */
      if (! verbose)
	{
          int len;
	  vlib_cli_output (vm, "%=20s%=16s", "Prefix length", "Count");

          memset (ca, 0, sizeof(*ca));
          ca->fib_index = fib - im6->fibs;

          BV(clib_bihash_foreach_key_value_pair)
            (h, count_routes_in_fib_at_prefix_length, ca);

          for (len = 128; len >= 0; len--)
            {
              if (ca->count_by_prefix_length[len])
                vlib_cli_output (vm, "%=20d%=16lld", 
                                 len, ca->count_by_prefix_length[len]);
            }
	  continue;
	}

      if (routes)
	_vec_len (routes) = 0;
      if (results)
	_vec_len (results) = 0;

      a->fib_index = fib - im6->fibs;
      a->routep = &routes;

      BV(clib_bihash_foreach_key_value_pair)(h, add_routes_in_fib, a);
      
      vec_sort_with_function (routes, ip6_route_cmp);

      vlib_cli_output (vm, "%=45s%=16s%=16s%=16s",
		       "Destination", "Packets", "Bytes", "Adjacency");
      vec_foreach (r, routes)
	{
	  vlib_counter_t c, sum;
	  uword i, j, n_left, n_nhs, adj_index, * result = 0;
	  ip_adjacency_t * adj;
	  ip_multipath_next_hop_t * nhs, tmp_nhs[1];

	  adj_index = r->index;
	  if (lm->fib_result_n_words > 1)
	    {
	      result = vec_elt_at_index (results, adj_index);
	      adj_index = result[0];
	    }

	  adj = ip_get_adjacency (lm, adj_index);
	  if (adj->n_adj == 1)
	    {
	      nhs = &tmp_nhs[0];
	      nhs[0].next_hop_adj_index = ~0; /* not used */
	      nhs[0].weight = 1;
	      n_nhs = 1;
	    }
	  else
	    {
	      ip_multipath_adjacency_t * madj;
	      madj = vec_elt_at_index (lm->multipath_adjacencies, adj->heap_handle);
	      nhs = heap_elt_at_index (lm->next_hop_heap, madj->normalized_next_hops.heap_offset);
	      n_nhs = madj->normalized_next_hops.count;
	    }

	  n_left = nhs[0].weight;
	  vlib_counter_zero (&sum);
	  for (i = j = 0; i < adj->n_adj; i++)
	    {
	      n_left -= 1;
	      vlib_get_combined_counter (&lm->adjacency_counters, 
                                         adj_index + i, &c);
              if (clear)
                vlib_zero_combined_counter (&lm->adjacency_counters, 
                                            adj_index + i);
	      vlib_counter_add (&sum, &c);
	      if (n_left == 0)
		{
		  u8 * msg = 0;
		  uword indent;

		  if (j == 0)
		    msg = format (msg, "%-45U",
				  format_ip6_address_and_length,
				  r->address.as_u8, r->address_length);
		  else
		    msg = format (msg, "%U", format_white_space, 20);

		  msg = format (msg, "%16Ld%16Ld ", sum.packets, sum.bytes);

		  indent = vec_len (msg);
		  msg = format (msg, "weight %d, index %d\n%U%U",
				nhs[j].weight, adj_index + i,
				format_white_space, indent,
				format_ip_adjacency,
				vnm, lm, adj_index + i);

		  vlib_cli_output (vm, "%v", msg);
		  vec_free (msg);

		  j++;
		  if (j < n_nhs)
		    {
		      n_left = nhs[j].weight;
		      vlib_counter_zero (&sum);
		    }
		}
	    }

	  if (result && lm->format_fib_result)
	    vlib_cli_output (vm, "%20s%U", "", lm->format_fib_result, vm, lm, result, 0);
	}
      vlib_cli_output (vm, " ");
    }

  vec_free (routes);
  vec_free (results);

  return 0;
}

VLIB_CLI_COMMAND (ip6_show_fib_command, static) = {
  .path = "show ip6 fib",
  .short_help = "show ip6 fib [summary] [clear]",
  .function = ip6_show_fib,
};
