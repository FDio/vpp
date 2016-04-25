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

#include <vnet/lisp-gpe/lisp_gpe.h>

/* avoids calling route callbacks for src fib */
static void
ip4_sd_fib_set_adj_index (lisp_gpe_main_t * lgm, ip4_fib_t * fib, u32 flags,
                           u32 dst_address_u32, u32 dst_address_length,
                           u32 adj_index)
{
  ip_lookup_main_t * lm = lgm->lm4;
  uword * hash;

  if (vec_bytes(fib->old_hash_values))
    memset (fib->old_hash_values, ~0, vec_bytes (fib->old_hash_values));
  if (vec_bytes(fib->new_hash_values))
    memset (fib->new_hash_values, ~0, vec_bytes (fib->new_hash_values));
  fib->new_hash_values[0] = adj_index;

  /* Make sure adj index is valid. */
  if (CLIB_DEBUG > 0)
    (void) ip_get_adjacency (lm, adj_index);

  hash = fib->adj_index_by_dst_address[dst_address_length];

  hash = _hash_set3 (hash, dst_address_u32,
                     fib->new_hash_values,
                     fib->old_hash_values);

  fib->adj_index_by_dst_address[dst_address_length] = hash;
}

/* copied from ip4_forward since it's static */
static void
ip4_fib_init_adj_index_by_dst_address (ip_lookup_main_t * lm,
                                       ip4_fib_t * fib,
                                       u32 address_length)
{
  hash_t * h;
  uword max_index;

  ASSERT (lm->fib_result_n_bytes >= sizeof (uword));
  lm->fib_result_n_words = round_pow2 (lm->fib_result_n_bytes, sizeof(uword))
      / sizeof(uword);

  fib->adj_index_by_dst_address[address_length] =
    hash_create (32 /* elts */, lm->fib_result_n_words * sizeof (uword));

  hash_set_flags (fib->adj_index_by_dst_address[address_length],
                  HASH_FLAG_NO_AUTO_SHRINK);

  h = hash_header (fib->adj_index_by_dst_address[address_length]);
  max_index = (hash_value_bytes (h) / sizeof (fib->new_hash_values[0])) - 1;

  /* Initialize new/old hash value vectors. */
  vec_validate_init_empty (fib->new_hash_values, max_index, ~0);
  vec_validate_init_empty (fib->old_hash_values, max_index, ~0);
}

static void
ip4_sd_fib_add_del_src_route (lisp_gpe_main_t * lgm,
                              ip4_add_del_route_args_t * a)
{
  ip_lookup_main_t * lm = lgm->lm4;
  ip4_fib_t * fib;
  u32 dst_address, dst_address_length, adj_index, old_adj_index;
  uword * hash, is_del;

  /* Either create new adjacency or use given one depending on arguments. */
  if (a->n_add_adj > 0)
      ip_add_adjacency (lm, a->add_adj, a->n_add_adj, &adj_index);
  else
    adj_index = a->adj_index;

  dst_address = a->dst_address.data_u32;
  dst_address_length = a->dst_address_length;

  fib = pool_elt_at_index(lgm->ip4_src_fibs, a->table_index_or_table_id);

  if (! fib->adj_index_by_dst_address[dst_address_length])
    ip4_fib_init_adj_index_by_dst_address (lm, fib, dst_address_length);

  hash = fib->adj_index_by_dst_address[dst_address_length];

  is_del = (a->flags & IP4_ROUTE_FLAG_DEL) != 0;

  if (is_del)
    {
      fib->old_hash_values[0] = ~0;
      hash = _hash_unset (hash, dst_address, fib->old_hash_values);
      fib->adj_index_by_dst_address[dst_address_length] = hash;
    }
  else
    ip4_sd_fib_set_adj_index (lgm, fib, a->flags, dst_address,
                              dst_address_length, adj_index);

  old_adj_index = fib->old_hash_values[0];

  ip4_fib_mtrie_add_del_route (fib, a->dst_address, dst_address_length,
                               is_del ? old_adj_index : adj_index,
                               is_del);

  /* Delete old adjacency index if present and changed. */
  if (! (a->flags & IP4_ROUTE_FLAG_KEEP_OLD_ADJACENCY)
      && old_adj_index != ~0
      && old_adj_index != adj_index)
    ip_del_adjacency (lm, old_adj_index);
}

static void *
ip4_sd_get_src_route (lisp_gpe_main_t * lgm, u32 src_fib_index,
                      ip4_address_t * src, u32 address_length)
{
  ip4_fib_t * fib = pool_elt_at_index (lgm->ip4_src_fibs, src_fib_index);
  uword * hash, * p;

  hash = fib->adj_index_by_dst_address[address_length];
  p = hash_get (hash, src->as_u32);
  return (void *) p;
}

typedef CLIB_PACKED (struct ip4_route {
  ip4_address_t address;
  u32 address_length : 6;
  u32 index : 26;
}) ip4_route_t;

void
ip4_sd_fib_clear_src_fib (lisp_gpe_main_t * lgm, ip4_fib_t * fib)
{
  ip4_route_t * routes = 0, * r;
  u32 i;

  vec_reset_length (routes);

  for (i = 0; i < ARRAY_LEN (fib->adj_index_by_dst_address); i++) {
      uword * hash = fib->adj_index_by_dst_address[i];
      hash_pair_t * p;
      ip4_route_t x;

      x.address_length = i;

      hash_foreach_pair (p, hash,
      ({
          x.address.data_u32 = p->key;
          vec_add1 (routes, x);
      }));
  }

  vec_foreach (r, routes) {
      ip4_add_del_route_args_t a;

      memset (&a, 0, sizeof (a));
      a.flags = IP4_ROUTE_FLAG_FIB_INDEX | IP4_ROUTE_FLAG_DEL;
      a.table_index_or_table_id = fib - lgm->ip4_src_fibs;
      a.dst_address = r->address;
      a.dst_address_length = r->address_length;
      a.adj_index = ~0;

      ip4_sd_fib_add_del_src_route (lgm, &a);
  }
}

static int
ip4_sd_fib_add_del_route (lisp_gpe_main_t * lgm, ip_prefix_t * dst_prefix,
                          ip_prefix_t * src_prefix, u32 table_id,
                          ip_adjacency_t * add_adj, u8 is_add)
{
  uword * p;
  ip4_add_del_route_args_t a;
  ip_adjacency_t * dst_adjp, dst_adj;
  ip4_address_t dst = ip_prefix_v4(dst_prefix), src;
  u32 dst_address_length = ip_prefix_len(dst_prefix), src_address_length = 0;
  ip4_fib_t * src_fib;

  if (src_prefix)
    {
      src = ip_prefix_v4(src_prefix);
      src_address_length = ip_prefix_len(src_prefix);
    }
  else
    memset(&src, 0, sizeof(src));

  /* lookup dst adj */
  p = ip4_get_route (lgm->im4, table_id, 0, dst.as_u8, dst_address_length);

  if (is_add)
    {
      /* insert dst prefix to ip4 fib, if it's not in yet */
      if (p == 0)
        {
          /* dst adj should point to lisp gpe lookup */
          dst_adj = add_adj[0];
          dst_adj.lookup_next_index = lgm->ip4_lookup_next_lgpe_ip4_lookup;

          memset(&a, 0, sizeof(a));
          a.flags = IP4_ROUTE_FLAG_TABLE_ID;
          a.table_index_or_table_id = table_id; /* vrf */
          a.adj_index = ~0;
          a.dst_address_length = dst_address_length;
          a.dst_address = dst;
          a.flags |= IP4_ROUTE_FLAG_ADD;
          a.add_adj = &dst_adj;
          a.n_add_adj = 1;

          ip4_add_del_route (lgm->im4, &a);

          /* lookup dst adj to obtain the adj index */
          p = ip4_get_route (lgm->im4, table_id, 0, dst.as_u8,
                             dst_address_length);
          if (p == 0)
            {
              clib_warning("Failed to insert dst route for eid %U!",
                           format_ip4_address_and_length, dst.as_u8,
                           dst_address_length);
              return -1;
            }

          /* allocate and init src ip4 fib */
          pool_get(lgm->ip4_src_fibs, src_fib);
          ip4_mtrie_init (&src_fib->mtrie);

          /* reuse rewrite header to store pointer to src fib */
          dst_adjp = ip_get_adjacency (lgm->lm4, p[0]);
          dst_adjp->rewrite_header.sw_if_index = src_fib - lgm->ip4_src_fibs;
        }
    }
  else
    {
      if (p == 0)
        {
          clib_warning("Trying to delete inexistent dst route for %U. Aborting",
                       format_ip4_address_and_length, dst.as_u8,
                       dst_address_length);
          return -1;
        }
    }

  dst_adjp = ip_get_adjacency (lgm->lm4, p[0]);

  /* add/del src prefix to src fib */
  memset(&a, 0, sizeof(a));
  a.flags = IP4_ROUTE_FLAG_TABLE_ID;
  a.table_index_or_table_id = dst_adjp->rewrite_header.sw_if_index;
  a.adj_index = ~0;
  a.flags |= is_add ? IP4_ROUTE_FLAG_ADD : IP4_ROUTE_FLAG_DEL;
  a.add_adj = add_adj;
  a.n_add_adj = 1;
  /* if src prefix is null, add 0/0 */
  a.dst_address_length = src_address_length;
  a.dst_address = src;
  ip4_sd_fib_add_del_src_route (lgm, &a);

  /* if a delete, check if there are elements left in the src fib */
  if (!is_add)
    {
      src_fib = pool_elt_at_index(lgm->ip4_src_fibs,
                                  dst_adjp->rewrite_header.sw_if_index);
      if (!src_fib)
        return 0;

      /* if there's nothing left */
      if (ARRAY_LEN(src_fib->adj_index_by_dst_address) == 0)
        {
          /* remove the src fib ..  */
          pool_put(lgm->ip4_src_fibs, src_fib);

          /* .. and remove dst route */
          memset(&a, 0, sizeof(a));
          a.flags = IP4_ROUTE_FLAG_TABLE_ID;
          a.table_index_or_table_id = table_id; /* vrf */
          a.adj_index = ~0;
          a.dst_address_length = dst_address_length;
          a.dst_address = dst;
          a.flags |= IP4_ROUTE_FLAG_DEL;

          ip4_add_del_route (lgm->im4, &a);
        }
    }

  return 0;
}

static void *
ip4_sd_fib_get_route (lisp_gpe_main_t * lgm, ip_prefix_t * dst_prefix,
                      ip_prefix_t * src_prefix, u32 table_id)
{
  uword * p;
  ip4_address_t dst = ip_prefix_v4(dst_prefix), src;
  u32 dst_address_length = ip_prefix_len(dst_prefix), src_address_length = 0;
  ip_adjacency_t * dst_adj;

  if (src_prefix)
    {
      src = ip_prefix_v4(src_prefix);
      src_address_length = ip_prefix_len(src_prefix);
    }
  else
    memset(&src, 0, sizeof(src));

  /* lookup dst adj */
  p = ip4_get_route (lgm->im4, table_id, 0, dst.as_u8, dst_address_length);
  if (p == 0)
      return p;

  dst_adj = ip_get_adjacency (lgm->lm4, p[0]);
  return ip4_sd_get_src_route (lgm, dst_adj->rewrite_header.sw_if_index, &src,
                               src_address_length);
}

static u32
ip6_sd_get_src_route (lisp_gpe_main_t * lgm, u32 src_fib_index,
                      ip6_address_t * src, u32 address_length)
{
  int i, len;
  int rv;
  BVT(clib_bihash_kv) kv, value;
  ip6_src_fib_t * fib = pool_elt_at_index (lgm->ip6_src_fibs, src_fib_index);

  len = vec_len (fib->prefix_lengths_in_search_order);

  for (i = 0; i < len; i++)
    {
      int dst_address_length = fib->prefix_lengths_in_search_order[i];
      ip6_address_t * mask;

      ASSERT(dst_address_length >= 0 && dst_address_length <= 128);

      mask = &fib->fib_masks[dst_address_length];

      kv.key[0] = src->as_u64[0] & mask->as_u64[0];
      kv.key[1] = src->as_u64[1] & mask->as_u64[1];
      kv.key[2] = dst_address_length;

      rv = BV(clib_bihash_search_inline_2)(&fib->ip6_lookup_table, &kv, &value);
      if (rv == 0)
        return value.value;
    }

  return 0;
}

static void
compute_prefix_lengths_in_search_order (ip6_src_fib_t * fib)
{
  int i;
  vec_reset_length(fib->prefix_lengths_in_search_order);
  /* Note: bitmap reversed so this is in fact a longest prefix match */
  clib_bitmap_foreach(i, fib->non_empty_dst_address_length_bitmap, ({
    int dst_address_length = 128 - i;
    vec_add1 (fib->prefix_lengths_in_search_order, dst_address_length);
  }));
}

/* Rewrite of ip6_add_del_route() because it uses im6 to find the fib */
static void
ip6_sd_fib_add_del_src_route (lisp_gpe_main_t * lgm,
                              ip6_add_del_route_args_t * a)
{
  ip_lookup_main_t * lm = lgm->lm6;
  ip6_src_fib_t * fib;
  ip6_address_t dst_address;
  u32 dst_address_length, adj_index;
  uword is_del;
  u32 old_adj_index = ~0;
  BVT(clib_bihash_kv) kv, value;

  vlib_smp_unsafe_warning();

  is_del = (a->flags & IP6_ROUTE_FLAG_DEL) != 0;

  /* Either create new adjacency or use given one depending on arguments. */
  if (a->n_add_adj > 0)
    {
      ip_add_adjacency (lm, a->add_adj, a->n_add_adj, &adj_index);
    }
  else
    adj_index = a->adj_index;

  dst_address = a->dst_address;
  dst_address_length = a->dst_address_length;
  fib = pool_elt_at_index(lgm->ip6_src_fibs, a->table_index_or_table_id);

  ASSERT (dst_address_length < ARRAY_LEN (fib->fib_masks));
  ip6_address_mask (&dst_address, &fib->fib_masks[dst_address_length]);

  /* refcount accounting */
  if (is_del)
    {
      ASSERT(fib->dst_address_length_refcounts[dst_address_length] > 0);
      if (--fib->dst_address_length_refcounts[dst_address_length] == 0)
        {
          fib->non_empty_dst_address_length_bitmap = clib_bitmap_set (
              fib->non_empty_dst_address_length_bitmap,
              128 - dst_address_length, 0);
          compute_prefix_lengths_in_search_order (fib);
        }
    }
  else
    {
      fib->dst_address_length_refcounts[dst_address_length]++;

      fib->non_empty_dst_address_length_bitmap =
        clib_bitmap_set (fib->non_empty_dst_address_length_bitmap,
                             128 - dst_address_length, 1);
      compute_prefix_lengths_in_search_order (fib);
    }

  kv.key[0] = dst_address.as_u64[0];
  kv.key[1] = dst_address.as_u64[1];
  kv.key[2] = dst_address_length;

  if (BV(clib_bihash_search)(&fib->ip6_lookup_table, &kv, &value) == 0)
    old_adj_index = value.value;

  if (is_del)
    BV(clib_bihash_add_del) (&fib->ip6_lookup_table, &kv, 0 /* is_add */);
  else
    {
      /* Make sure adj index is valid. */
      if (CLIB_DEBUG > 0)
        (void) ip_get_adjacency (lm, adj_index);

      kv.value = adj_index;

      BV(clib_bihash_add_del) (&fib->ip6_lookup_table, &kv, 1 /* is_add */);
    }

  /* Avoid spurious reference count increments */
  if (old_adj_index == adj_index
      && !(a->flags & IP6_ROUTE_FLAG_KEEP_OLD_ADJACENCY))
    {
      ip_adjacency_t * adj = ip_get_adjacency (lm, adj_index);
      if (adj->share_count > 0)
        adj->share_count --;
    }

  /* Delete old adjacency index if present and changed. */
  {
    if (! (a->flags & IP6_ROUTE_FLAG_KEEP_OLD_ADJACENCY)
        && old_adj_index != ~0
        && old_adj_index != adj_index)
      ip_del_adjacency (lm, old_adj_index);
  }
}

static void
ip6_src_fib_init (ip6_src_fib_t * fib)
{
  uword i;

  for (i = 0; i < ARRAY_LEN (fib->fib_masks); i++)
    {
      u32 j, i0, i1;

      i0 = i / 32;
      i1 = i % 32;

      for (j = 0; j < i0; j++)
        fib->fib_masks[i].as_u32[j] = ~0;

      if (i1)
        fib->fib_masks[i].as_u32[i0] = clib_host_to_net_u32 (
            pow2_mask (i1) << (32 - i1));
    }

  if (fib->lookup_table_nbuckets == 0)
    fib->lookup_table_nbuckets = IP6_FIB_DEFAULT_HASH_NUM_BUCKETS;

  fib->lookup_table_nbuckets = 1 << max_log2 (fib->lookup_table_nbuckets);

  if (fib->lookup_table_size == 0)
    fib->lookup_table_size = IP6_FIB_DEFAULT_HASH_MEMORY_SIZE;

  BV(clib_bihash_init) (&fib->ip6_lookup_table, "ip6 lookup table",
                        fib->lookup_table_nbuckets,
                        fib->lookup_table_size);

}

static int
ip6_sd_fib_add_del_route (lisp_gpe_main_t * lgm, ip_prefix_t * dst_prefix,
                          ip_prefix_t * src_prefix, u32 table_id,
                          ip_adjacency_t * add_adj, u8 is_add)
{
  u32 adj_index;
  ip6_add_del_route_args_t a;
  ip_adjacency_t * dst_adjp, dst_adj;
  ip6_address_t dst = ip_prefix_v6(dst_prefix), src;
  u32 dst_address_length = ip_prefix_len(dst_prefix), src_address_length = 0;
  ip6_src_fib_t * src_fib;

  if (src_prefix)
    {
      src = ip_prefix_v6(src_prefix);
      src_address_length = ip_prefix_len(src_prefix);
    }
  else
    memset(&src, 0, sizeof(src));

  /* lookup dst adj and create it if it doesn't exist */
  adj_index = ip6_get_route (lgm->im6, table_id, 0, &dst, dst_address_length);

  if (is_add)
    {
      /* insert dst prefix to ip6 fib, if it's not in yet */
      if (adj_index == 0)
        {
          /* dst adj should point to lisp gpe ip lookup */
          dst_adj = add_adj[0];
          dst_adj.lookup_next_index = lgm->ip6_lookup_next_lgpe_ip6_lookup;

          memset(&a, 0, sizeof(a));
          a.flags = IP6_ROUTE_FLAG_TABLE_ID;
          a.table_index_or_table_id = table_id; /* vrf */
          a.adj_index = ~0;
          a.dst_address_length = dst_address_length;
          a.dst_address = dst;
          a.flags |= IP6_ROUTE_FLAG_ADD;
          a.add_adj = &dst_adj;
          a.n_add_adj = 1;

          ip6_add_del_route (lgm->im6, &a);

          /* lookup dst adj to obtain the adj index */
          adj_index = ip6_get_route (lgm->im6, table_id, 0, &dst,
                                     dst_address_length);

          ASSERT(adj_index != 0);

          /* allocate and init src ip6 fib */
          pool_get(lgm->ip6_src_fibs, src_fib);
          memset(src_fib, 0, sizeof(src_fib[0]));
          ip6_src_fib_init (src_fib);

          /* reuse rewrite header to store pointer to src fib */
          dst_adjp = ip_get_adjacency (lgm->lm6, adj_index);
          dst_adjp->rewrite_header.sw_if_index = src_fib - lgm->ip6_src_fibs;
        }
    }
  else
    {
      if (adj_index == 0)
        {
          clib_warning("Trying to delete inexistent dst route for %U. Aborting",
                       format_ip6_address_and_length, dst.as_u8,
                       dst_address_length);
          return -1;
        }
    }

  dst_adjp = ip_get_adjacency (lgm->lm6, adj_index);

  /* add/del src prefix to src fib */
  memset(&a, 0, sizeof(a));
  a.flags = IP6_ROUTE_FLAG_TABLE_ID;
  a.table_index_or_table_id = dst_adjp->rewrite_header.sw_if_index;
  a.adj_index = ~0;
  a.flags |= is_add ? IP6_ROUTE_FLAG_ADD : IP6_ROUTE_FLAG_DEL;
  a.add_adj = add_adj;
  a.n_add_adj = 1;
  /* if src prefix is null, add ::0 */
  a.dst_address_length = src_address_length;
  a.dst_address = src;
  ip6_sd_fib_add_del_src_route (lgm, &a);

  /* if a delete, check if there are elements left in the src fib */
  if (!is_add)
    {
      src_fib = pool_elt_at_index(lgm->ip6_src_fibs,
                                  dst_adjp->rewrite_header.sw_if_index);
      if (!src_fib)
        return 0;

      /* if there's nothing left */
      if (clib_bitmap_count_set_bits (
          src_fib->non_empty_dst_address_length_bitmap) == 0)
        {
          /* remove src fib .. */
          pool_put(lgm->ip6_src_fibs, src_fib);

          /* .. and remove dst route */
          memset(&a, 0, sizeof(a));
          a.flags = IP6_ROUTE_FLAG_TABLE_ID;
          a.table_index_or_table_id = table_id; /* vrf */
          a.adj_index = ~0;
          a.dst_address_length = dst_address_length;
          a.dst_address = dst;
          a.flags |= IP6_ROUTE_FLAG_DEL;

          ip6_add_del_route (lgm->im6, &a);
        }
    }

  return 0;
}

static u32
ip6_sd_fib_get_route (lisp_gpe_main_t * lgm, ip_prefix_t * dst_prefix,
                      ip_prefix_t * src_prefix, u32 table_id)
{
  u32 adj_index;
  ip6_address_t dst = ip_prefix_v6(dst_prefix), src;
  u32 dst_address_length = ip_prefix_len(dst_prefix), src_address_length = 0;
  ip_adjacency_t * dst_adj;

  if (src_prefix)
    {
      src = ip_prefix_v6(src_prefix);
      src_address_length = ip_prefix_len(src_prefix);
    }
  else
    memset(&src, 0, sizeof(src));

  /* lookup dst adj */
  adj_index = ip6_get_route (lgm->im6, table_id, 0, &dst, dst_address_length);
  if (adj_index == 0)
      return adj_index;

  dst_adj = ip_get_adjacency (lgm->lm6, adj_index);
  return ip6_sd_get_src_route (lgm, dst_adj->rewrite_header.sw_if_index, &src,
                               src_address_length);
}

int
ip_sd_fib_add_del_route (lisp_gpe_main_t * lgm, ip_prefix_t * dst_prefix,
                         ip_prefix_t * src_prefix, u32 table_id,
                         ip_adjacency_t * add_adj, u8 is_add)
{
  return (
  ip_prefix_version(dst_prefix) == IP4 ?
      ip4_sd_fib_add_del_route : ip6_sd_fib_add_del_route) (lgm, dst_prefix,
                                                            src_prefix,
                                                            table_id, add_adj,
                                                            is_add);
}

u32
ip_sd_fib_get_route (lisp_gpe_main_t * lgm, ip_prefix_t * dst_prefix,
                     ip_prefix_t * src_prefix, u32 table_id)
{
  if (ip_prefix_version(dst_prefix) == IP4)
    {
      u32 * adj_index = ip4_sd_fib_get_route (lgm, dst_prefix, src_prefix,
                                              table_id);
      return (adj_index == 0) ? 0 : adj_index[0];
    }
  else
    return ip6_sd_fib_get_route (lgm, dst_prefix, src_prefix, table_id);
}

always_inline void
ip4_src_fib_lookup_one (lisp_gpe_main_t * lgm, u32 src_fib_index0,
                        ip4_address_t * addr0, u32 * src_adj_index0)
{
  ip4_fib_mtrie_leaf_t leaf0, leaf1;
  ip4_fib_mtrie_t * mtrie0;

  mtrie0 = &vec_elt_at_index(lgm->ip4_src_fibs, src_fib_index0)->mtrie;

  leaf0 = leaf1 = IP4_FIB_MTRIE_LEAF_ROOT;
  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 0);
  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 1);
  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 2);
  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 3);

  /* Handle default route. */
  leaf0 = (leaf0 == IP4_FIB_MTRIE_LEAF_EMPTY ? mtrie0->default_leaf : leaf0);
  src_adj_index0[0] = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
}

always_inline void
ip4_src_fib_lookup_two (lisp_gpe_main_t * lgm, u32 src_fib_index0,
                        u32 src_fib_index1, ip4_address_t * addr0,
                        ip4_address_t * addr1, u32 * src_adj_index0,
                        u32 * src_adj_index1)
{
  ip4_fib_mtrie_leaf_t leaf0, leaf1;
  ip4_fib_mtrie_t * mtrie0, * mtrie1;

  mtrie0 = &vec_elt_at_index(lgm->ip4_src_fibs, src_fib_index0)->mtrie;
  mtrie1 = &vec_elt_at_index(lgm->ip4_src_fibs, src_fib_index1)->mtrie;

  leaf0 = leaf1 = IP4_FIB_MTRIE_LEAF_ROOT;

  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 0);
  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, addr1, 0);

  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 1);
  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, addr1, 1);

  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 2);
  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, addr1, 2);

  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, addr0, 3);
  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, addr1, 3);

  /* Handle default route. */
  leaf0 = (leaf0 == IP4_FIB_MTRIE_LEAF_EMPTY ? mtrie0->default_leaf : leaf0);
  leaf1 = (leaf1 == IP4_FIB_MTRIE_LEAF_EMPTY ? mtrie1->default_leaf : leaf1);
  src_adj_index0[0] = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
  src_adj_index1[0] = ip4_fib_mtrie_leaf_get_adj_index (leaf1);
}

always_inline uword
lgpe_ip4_lookup (vlib_main_t * vm, vlib_node_runtime_t * node,
                 vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  lisp_gpe_main_t * lgm = &lisp_gpe_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          u32 bi0, bi1;
          vlib_buffer_t * b0, * b1;
          ip4_header_t * ip0, * ip1;
          u32 dst_adj_index0, src_adj_index0, src_fib_index0, dst_adj_index1,
              src_adj_index1, src_fib_index1;
          ip_adjacency_t * dst_adj0, * src_adj0, * dst_adj1, * src_adj1;
          u32 next0, next1;

          next0 = next1 = LGPE_IP4_LOOKUP_NEXT_LISP_CP_LOOKUP;

          /* Prefetch next iteration. */
          {
            vlib_buffer_t * p2, * p3;

            p2 = vlib_get_buffer (vm, from[2]);
            p3 = vlib_get_buffer (vm, from[3]);

            vlib_prefetch_buffer_header (p2, LOAD);
            vlib_prefetch_buffer_header (p3, LOAD);

            CLIB_PREFETCH (p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
            CLIB_PREFETCH (p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
          }

          bi0 = from[0];
          bi1 = from[1];
          to_next[0] = bi0;
          to_next[1] = bi1;
          from += 2;
          to_next += 2;
          n_left_to_next -= 2;
          n_left_from -= 2;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);

          ip0 = vlib_buffer_get_current (b0);
          ip1 = vlib_buffer_get_current (b1);

          /* dst lookup was done by ip4 lookup */
          dst_adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
          dst_adj_index1 = vnet_buffer(b1)->ip.adj_index[VLIB_TX];

          dst_adj0 = ip_get_adjacency (lgm->lm4, dst_adj_index0);
          dst_adj1 = ip_get_adjacency (lgm->lm4, dst_adj_index1);

          src_fib_index0 = dst_adj0->rewrite_header.sw_if_index;
          src_fib_index1 = dst_adj1->rewrite_header.sw_if_index;

          /* if default route not hit in ip4 lookup */
          if (PREDICT_TRUE(src_fib_index0 != (u32) ~0
                           && src_fib_index1 != (u32) ~0))
            {
              ip4_src_fib_lookup_two (lgm, src_fib_index0, src_fib_index1,
                                      &ip0->src_address, &ip1->src_address,
                                      &src_adj_index0, &src_adj_index1);

              vnet_buffer(b0)->ip.adj_index[VLIB_TX] = src_adj_index0;
              vnet_buffer(b1)->ip.adj_index[VLIB_TX] = src_adj_index1;

              src_adj0 = ip_get_adjacency (lgm->lm4, src_adj_index0);
              src_adj1 = ip_get_adjacency (lgm->lm4, src_adj_index1);

              next0 = src_adj0->lookup_next_index;
              next1 = src_adj1->lookup_next_index;

              /* prepare buffer for lisp-gpe output node */
              vnet_buffer (b0)->sw_if_index[VLIB_TX] =
                  src_adj0->rewrite_header.sw_if_index;
              vnet_buffer (b1)->sw_if_index[VLIB_TX] =
                  src_adj1->rewrite_header.sw_if_index;
            }
          else
            {
              if (src_fib_index0 != (u32) ~0)
                {
                  ip4_src_fib_lookup_one (lgm, src_fib_index0,
                                          &ip0->src_address, &src_adj_index0);
                  vnet_buffer(b0)->ip.adj_index[VLIB_TX] = src_adj_index0;
                  src_adj0 = ip_get_adjacency (lgm->lm4, src_adj_index0);
                  next0 = src_adj0->lookup_next_index;
                  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
                      src_adj0->rewrite_header.sw_if_index;
                }
              if (src_fib_index1 != (u32) ~0)
                {
                  ip4_src_fib_lookup_one (lgm, src_fib_index1,
                                          &ip1->src_address, &src_adj_index1);
                  vnet_buffer(b1)->ip.adj_index[VLIB_TX] = src_adj_index1;
                  src_adj1 = ip_get_adjacency (lgm->lm4, src_adj_index1);
                  next1 = src_adj1->lookup_next_index;
                  vnet_buffer (b1)->sw_if_index[VLIB_TX] =
                      src_adj1->rewrite_header.sw_if_index;
                }
            }

          vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                                          n_left_to_next, bi0, bi1, next0,
                                          next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          vlib_buffer_t * b0;
          ip4_header_t * ip0;
          u32 bi0, dst_adj_index0, src_adj_index0, src_fib_index0;
          u32 next0 = LGPE_IP4_LOOKUP_NEXT_LISP_CP_LOOKUP;
          ip_adjacency_t * dst_adj0, * src_adj0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          ip0 = vlib_buffer_get_current (b0);

          /* dst lookup was done by ip4 lookup */
          dst_adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
          dst_adj0 = ip_get_adjacency (lgm->lm4, dst_adj_index0);
          src_fib_index0 = dst_adj0->rewrite_header.sw_if_index;

          /* if default route not hit in ip4 lookup */
          if (PREDICT_TRUE(src_fib_index0 != (u32 ) ~0))
            {
              /* do src lookup */
              ip4_src_fib_lookup_one (lgm, src_fib_index0, &ip0->src_address,
                                      &src_adj_index0);
              vnet_buffer(b0)->ip.adj_index[VLIB_TX] = src_adj_index0;
              src_adj0 = ip_get_adjacency (lgm->lm4, src_adj_index0);
              next0 = src_adj0->lookup_next_index;

              /* prepare packet for lisp-gpe output node */
              vnet_buffer (b0)->sw_if_index[VLIB_TX] =
                  src_adj0->rewrite_header.sw_if_index;
            }

          vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (lgpe_ip4_lookup_node) = {
  .function = lgpe_ip4_lookup,
  .name = "lgpe-ip4-lookup",
  .vector_size = sizeof (u32),

  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LGPE_IP4_LOOKUP_N_NEXT,
  .next_nodes = {
#define _(sym,str) [LGPE_IP4_LOOKUP_NEXT_##sym] = str,
      foreach_lgpe_ip4_lookup_next
#undef _
  },
};

static u32
ip6_src_fib_lookup (lisp_gpe_main_t * lgm, u32 src_fib_index,
                    ip6_address_t * src)
{
  int i, len;
  int rv;
  BVT(clib_bihash_kv) kv, value;
  ip6_src_fib_t * fib = pool_elt_at_index (lgm->ip6_src_fibs, src_fib_index);

  len = vec_len (fib->prefix_lengths_in_search_order);

  for (i = 0; i < len; i++)
    {
      int dst_address_length = fib->prefix_lengths_in_search_order[i];
      ip6_address_t * mask;

      ASSERT(dst_address_length >= 0 && dst_address_length <= 128);

      mask = &fib->fib_masks[dst_address_length];

      kv.key[0] = src->as_u64[0] & mask->as_u64[0];
      kv.key[1] = src->as_u64[1] & mask->as_u64[1];
      kv.key[2] = dst_address_length;

      rv = BV(clib_bihash_search_inline_2)(&fib->ip6_lookup_table, &kv, &value);
      if (rv == 0)
        return value.value;
    }

  return 0;
}

always_inline uword
lgpe_ip6_lookup (vlib_main_t * vm, vlib_node_runtime_t * node,
                 vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  lisp_gpe_main_t * lgm = &lisp_gpe_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          u32 bi0, bi1;
          vlib_buffer_t * b0, * b1;
          ip6_header_t * ip0, * ip1;
          u32 dst_adj_index0, src_adj_index0, src_fib_index0, dst_adj_index1,
              src_adj_index1, src_fib_index1;
          ip_adjacency_t * dst_adj0, * src_adj0, * dst_adj1, * src_adj1;
          u32 next0, next1;

          next0 = next1 = LGPE_IP6_LOOKUP_NEXT_LISP_CP_LOOKUP;

          /* Prefetch next iteration. */
          {
            vlib_buffer_t * p2, * p3;

            p2 = vlib_get_buffer (vm, from[2]);
            p3 = vlib_get_buffer (vm, from[3]);

            vlib_prefetch_buffer_header (p2, LOAD);
            vlib_prefetch_buffer_header (p3, LOAD);

            CLIB_PREFETCH (p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
            CLIB_PREFETCH (p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
          }

          bi0 = from[0];
          bi1 = from[1];
          to_next[0] = bi0;
          to_next[1] = bi1;
          from += 2;
          to_next += 2;
          n_left_to_next -= 2;
          n_left_from -= 2;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);

          ip0 = vlib_buffer_get_current (b0);
          ip1 = vlib_buffer_get_current (b1);

          /* dst lookup was done by ip6 lookup */
          dst_adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
          dst_adj_index1 = vnet_buffer(b1)->ip.adj_index[VLIB_TX];

          dst_adj0 = ip_get_adjacency (lgm->lm6, dst_adj_index0);
          dst_adj1 = ip_get_adjacency (lgm->lm6, dst_adj_index1);

          src_fib_index0 = dst_adj0->rewrite_header.sw_if_index;
          src_fib_index1 = dst_adj1->rewrite_header.sw_if_index;

          /* if default route not hit in ip6 lookup */
          if (PREDICT_TRUE(src_fib_index0 != (u32) ~0
                           && src_fib_index1 != (u32) ~0))
            {
              /* do src lookup */
              src_adj_index0 = ip6_src_fib_lookup (lgm, src_fib_index0,
                                                   &ip0->src_address);
              src_adj_index1 = ip6_src_fib_lookup (lgm, src_fib_index1,
                                                   &ip1->src_address);

              vnet_buffer(b0)->ip.adj_index[VLIB_TX] = src_adj_index0;
              vnet_buffer(b1)->ip.adj_index[VLIB_TX] = src_adj_index1;

              src_adj0 = ip_get_adjacency (lgm->lm6, src_adj_index0);
              src_adj1 = ip_get_adjacency (lgm->lm6, src_adj_index1);

              next0 = src_adj0->lookup_next_index;
              next1 = src_adj1->lookup_next_index;

              /* prepare buffer for lisp-gpe output node */
              vnet_buffer (b0)->sw_if_index[VLIB_TX] =
                  src_adj0->rewrite_header.sw_if_index;
              vnet_buffer (b1)->sw_if_index[VLIB_TX] =
                  src_adj1->rewrite_header.sw_if_index;
            }
          else
            {
              if (src_fib_index0 != (u32) ~0)
                {
                  src_adj_index0 = ip6_src_fib_lookup (lgm, src_fib_index0,
                                                       &ip0->src_address);
                  vnet_buffer(b0)->ip.adj_index[VLIB_TX] = src_adj_index0;
                  src_adj0 = ip_get_adjacency (lgm->lm6, src_adj_index0);
                  next0 = src_adj0->lookup_next_index;
                  vnet_buffer (b0)->sw_if_index[VLIB_TX] =
                      src_adj0->rewrite_header.sw_if_index;
                }
              if (src_fib_index1 != (u32) ~0)
                {
                  src_adj_index1 = ip6_src_fib_lookup (lgm, src_fib_index1,
                                                       &ip1->src_address);
                  vnet_buffer(b1)->ip.adj_index[VLIB_TX] = src_adj_index1;
                  src_adj1 = ip_get_adjacency (lgm->lm6, src_adj_index1);
                  next1 = src_adj1->lookup_next_index;
                  vnet_buffer (b1)->sw_if_index[VLIB_TX] =
                      src_adj1->rewrite_header.sw_if_index;
                }
            }

          vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                                          n_left_to_next, bi0, bi1, next0,
                                          next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          vlib_buffer_t * b0;
          ip6_header_t * ip0;
          u32 bi0, dst_adj_index0, src_adj_index0, src_fib_index0;
          u32 next0 = LGPE_IP6_LOOKUP_NEXT_LISP_CP_LOOKUP;
          ip_adjacency_t * dst_adj0, * src_adj0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          ip0 = vlib_buffer_get_current (b0);

          /* dst lookup was done by ip6 lookup */
          dst_adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
          dst_adj0 = ip_get_adjacency (lgm->lm6, dst_adj_index0);
          src_fib_index0 = dst_adj0->rewrite_header.sw_if_index;

          /* if default route not hit in ip6 lookup */
          if (PREDICT_TRUE(src_fib_index0 != (u32 ) ~0))
            {
              /* do src lookup */
              src_adj_index0 = ip6_src_fib_lookup (lgm, src_fib_index0,
                                                   &ip0->src_address);

              vnet_buffer(b0)->ip.adj_index[VLIB_TX] = src_adj_index0;
              src_adj0 = ip_get_adjacency (lgm->lm6, src_adj_index0);
              next0 = src_adj0->lookup_next_index;

              /* prepare packet for lisp-gpe output node */
              vnet_buffer (b0)->sw_if_index[VLIB_TX] =
                  src_adj0->rewrite_header.sw_if_index;
            }

          vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (lgpe_ip6_lookup_node) = {
  .function = lgpe_ip6_lookup,
  .name = "lgpe-ip6-lookup",
  .vector_size = sizeof (u32),

  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LGPE_IP6_LOOKUP_N_NEXT,
  .next_nodes = {
#define _(sym,str) [LGPE_IP6_LOOKUP_NEXT_##sym] = str,
      foreach_lgpe_ip6_lookup_next
#undef _
  },
};
