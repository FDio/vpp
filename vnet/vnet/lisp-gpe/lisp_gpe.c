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

lisp_gpe_main_t lisp_gpe_main;

/* avoids calling route callbacks for src fib */
static void
ip4_sd_fib_set_adj_index (lisp_gpe_main_t * lgm, ip4_fib_t * fib, u32 flags,
                           u32 dst_address_u32, u32 dst_address_length,
                           u32 adj_index)
{
  ip_lookup_main_t * lm = lgm->lookup_main;
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
  lm->fib_result_n_words = round_pow2 (lm->fib_result_n_bytes, sizeof (uword)) / sizeof (uword);

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

void
ip4_sd_fib_add_del_src_route (lisp_gpe_main_t * lgm,
                              ip4_add_del_route_args_t * a)
{
  ip_lookup_main_t * lm = lgm->lookup_main;
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

  fib = pool_elt_at_index(lgm->src_fibs, a->table_index_or_table_id);

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

void *
ip4_sd_get_src_route (lisp_gpe_main_t * lgm, u32 src_fib_index,
                      ip4_address_t * src, u32 address_length)
{
  ip4_fib_t * fib = pool_elt_at_index (lgm->src_fibs, src_fib_index);
  uword * hash, * p;

  hash = fib->adj_index_by_dst_address[address_length];
  p = hash_get (hash, src->as_u32);
  return (void *) p;
}

typedef CLIB_PACKED (struct {
  ip4_address_t address;
  u32 address_length : 6;
  u32 index : 26;
}) ip4_route_t;

static void
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
      a.table_index_or_table_id = fib - lgm->src_fibs;
      a.dst_address = r->address;
      a.dst_address_length = r->address_length;
      a.adj_index = ~0;

      ip4_sd_fib_add_del_src_route (lgm, &a);
  }
}

int
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
          pool_get(lgm->src_fibs, src_fib);
          ip4_mtrie_init (&src_fib->mtrie);

          /* reuse rewrite header to store pointer to src fib */
          dst_adjp = ip_get_adjacency (lgm->lookup_main, p[0]);
          dst_adjp->rewrite_header.sw_if_index = src_fib - lgm->src_fibs;
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

  dst_adjp = ip_get_adjacency (lgm->lookup_main, p[0]);

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
      src_fib = pool_elt_at_index(lgm->src_fibs,
                                  dst_adjp->rewrite_header.sw_if_index);
      if (!src_fib)
        return 0;

      /* if there's nothing left, clear src fib .. */
      if (ARRAY_LEN(src_fib->adj_index_by_dst_address) == 0)
        {
          ip4_sd_fib_clear_src_fib (lgm, src_fib);
          pool_put(lgm->src_fibs, src_fib);
        }

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

  dst_adj = ip_get_adjacency (lgm->lookup_main, p[0]);
  return ip4_sd_get_src_route (lgm, dst_adj->rewrite_header.sw_if_index, &src,
                               src_address_length);
}

typedef enum
{
  LGPE_IP4_LOOKUP_NEXT_DROP,
  LGPE_IP4_LOOKUP_NEXT_LISP_CP_LOOKUP,
  LGPE_IP4_LOOKUP_N_NEXT,
} lgpe_ip4_lookup_next_t;

always_inline void
ip4_src_fib_lookup_one (lisp_gpe_main_t * lgm, u32 src_fib_index0,
                        ip4_address_t * addr0, u32 * src_adj_index0)
{
  ip4_fib_mtrie_leaf_t leaf0, leaf1;
  ip4_fib_mtrie_t * mtrie0;

  mtrie0 = &vec_elt_at_index(lgm->src_fibs, src_fib_index0)->mtrie;

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

  mtrie0 = &vec_elt_at_index(lgm->src_fibs, src_fib_index0)->mtrie;
  mtrie1 = &vec_elt_at_index(lgm->src_fibs, src_fib_index1)->mtrie;

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

          dst_adj0 = ip_get_adjacency (lgm->lookup_main, dst_adj_index0);
          dst_adj1 = ip_get_adjacency (lgm->lookup_main, dst_adj_index1);

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

              src_adj0 = ip_get_adjacency (lgm->lookup_main, src_adj_index0);
              src_adj1 = ip_get_adjacency (lgm->lookup_main, src_adj_index1);

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
                  src_adj0 = ip_get_adjacency (lgm->lookup_main,
                                               src_adj_index0);
                  next0 = src_adj0->lookup_next_index;
                  vnet_buffer (b0)->sw_if_index[VLIB_TX] = src_adj_index0;
                }
              if (src_fib_index1 != (u32) ~0)
                {
                  ip4_src_fib_lookup_one (lgm, src_fib_index1,
                                          &ip1->src_address, &src_adj_index1);
                  vnet_buffer(b1)->ip.adj_index[VLIB_TX] = src_adj_index1;
                  src_adj1 = ip_get_adjacency (lgm->lookup_main,
                                               src_adj_index1);
                  next1 = src_adj1->lookup_next_index;
                  vnet_buffer (b1)->sw_if_index[VLIB_TX] = src_adj_index1;
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
          dst_adj0 = ip_get_adjacency (lgm->lookup_main, dst_adj_index0);
          src_fib_index0 = dst_adj0->rewrite_header.sw_if_index;

          /* default route hit in ip4 lookup, send to lisp control plane */
          if (src_fib_index0 == (u32) ~0)
            goto done;

          /* src lookup we do here */
          ip4_src_fib_lookup_one (lgm, src_fib_index0, &ip0->src_address,
                                  &src_adj_index0);
          vnet_buffer(b0)->ip.adj_index[VLIB_TX] = src_adj_index0;
          src_adj0 = ip_get_adjacency (lgm->lookup_main, src_adj_index0);
          next0 = src_adj0->lookup_next_index;

          /* prepare packet for lisp-gpe output node */
          vnet_buffer (b0)->sw_if_index[VLIB_TX] =
              src_adj0->rewrite_header.sw_if_index;
        done:
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
      [LGPE_IP4_LOOKUP_NEXT_DROP] = "error-drop",
      [LGPE_IP4_LOOKUP_NEXT_LISP_CP_LOOKUP] = "lisp-cp-lookup",
  },
};

static int
lisp_gpe_rewrite (lisp_gpe_tunnel_t * t)
{
  u8 *rw = 0;
  ip4_header_t * ip0;
  lisp_gpe_header_t * lisp0;
  ip4_udp_lisp_gpe_header_t * h0;
  int len;

  len = sizeof(*h0);

  vec_validate_aligned(rw, len - 1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip4_udp_lisp_gpe_header_t *) rw;

  /* Fixed portion of the (outer) ip4 header */
  ip0 = &h0->ip4;
  ip0->ip_version_and_header_length = 0x45;
  ip0->ttl = 254;
  ip0->protocol = IP_PROTOCOL_UDP;

  /* we fix up the ip4 header length and checksum after-the-fact */
  ip0->src_address.as_u32 = t->src.as_u32;
  ip0->dst_address.as_u32 = t->dst.as_u32;
  ip0->checksum = ip4_header_checksum (ip0);

  /* UDP header, randomize src port on something, maybe? */
  h0->udp.src_port = clib_host_to_net_u16 (4341);
  h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_lisp_gpe);

  /* LISP-gpe header */
  lisp0 = &h0->lisp;

  lisp0->flags = t->flags;
  lisp0->ver_res = t->ver_res;
  lisp0->res = t->res;
  lisp0->next_protocol = t->next_protocol;
  lisp0->iid = clib_host_to_net_u32 (t->vni);

  t->rewrite = rw;
  return 0;
}

/* TODO remove */
int
vnet_lisp_gpe_add_del_tunnel (vnet_lisp_gpe_add_del_tunnel_args_t *a,
                              u32 * sw_if_indexp)
{
  clib_warning ("UNSUPPORTED! Use vnet_lisp_gpe_add_del_fwd_entry");
  return 0;
}

#define foreach_copy_field                      \
_(encap_fib_index)                              \
_(decap_fib_index)                              \
_(decap_next_index)                             \
_(flags)                                        \
_(next_protocol)                                \
_(ver_res)                                      \
_(res)                                          \
_(vni)

static u32
add_del_tunnel (vnet_lisp_gpe_add_del_fwd_entry_args_t *a, u32 * tun_index_res)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  lisp_gpe_tunnel_t *t = 0;
  uword * p;
  int rv;
  lisp_gpe_tunnel_key_t key;

  memset(&key, 0, sizeof(key));
  gid_address_copy(&key.eid, &a->deid);
  key.dst_loc = ip_addr_v4(&a->dlocator).as_u32;
  key.iid = clib_host_to_net_u32 (a->vni);

  p = mhash_get (&lgm->lisp_gpe_tunnel_by_key, &key);

  if (a->is_add)
    {
      /* adding a tunnel: tunnel must not already exist */
      if (p)
        return VNET_API_ERROR_INVALID_VALUE;

      if (a->decap_next_index >= LISP_GPE_INPUT_N_NEXT)
        return VNET_API_ERROR_INVALID_DECAP_NEXT;

      pool_get_aligned (lgm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));

      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _

      t->src = ip_addr_v4(&a->slocator);
      t->dst = ip_addr_v4(&a->dlocator);

      rv = lisp_gpe_rewrite (t);

      if (rv)
        {
          pool_put(lgm->tunnels, t);
          return rv;
        }

      mhash_set(&lgm->lisp_gpe_tunnel_by_key, &key, t - lgm->tunnels, 0);

      /* return tunnel index */
      if (tun_index_res)
        tun_index_res[0] = t - lgm->tunnels;
    }
  else
    {
      /* deleting a tunnel: tunnel must exist */
      if (!p)
        {
          clib_warning("Tunnel for eid %U doesn't exist!", format_gid_address,
                       &a->deid);
          return VNET_API_ERROR_NO_SUCH_ENTRY;
        }

      t = pool_elt_at_index(lgm->tunnels, p[0]);

      mhash_unset(&lgm->lisp_gpe_tunnel_by_key, &key, 0);

      vec_free(t->rewrite);
      pool_put(lgm->tunnels, t);
    }

  return 0;
}

static int
add_del_negative_fwd_entry (lisp_gpe_main_t * lgm,
                            vnet_lisp_gpe_add_del_fwd_entry_args_t * a)
{
  ip_adjacency_t adj;
  /* setup adjacency for eid */
  memset (&adj, 0, sizeof(adj));
  adj.n_adj = 1;
  adj.explicit_fib_index = ~0;

  ip_prefix_t * dpref = &gid_address_ippref(&a->deid);
  ip_prefix_t * spref = &gid_address_ippref(&a->seid);

  switch (a->action)
    {
    case NO_ACTION:
      /* TODO update timers? */
    case FORWARD_NATIVE:
      /* TODO check if route/next-hop for eid exists in fib and add
       * more specific for the eid with the next-hop found */
    case SEND_MAP_REQUEST:
      /* TODO insert tunnel that always sends map-request */
    case DROP:
      /* for drop fwd entries, just add route, no need to add encap tunnel */
      adj.lookup_next_index = LGPE_IP4_LOOKUP_NEXT_DROP;

      /* add/delete route for prefix */
      return ip4_sd_fib_add_del_route (lgm, dpref, spref, a->table_id, &adj,
                                       a->is_add);
      break;
    default:
      return -1;
    }
}

int
vnet_lisp_gpe_add_del_fwd_entry (vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
                                 u32 * hw_if_indexp)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  ip_adjacency_t adj, * adjp;
  u32 * adj_index, rv, tun_index = ~0;
  ip_prefix_t * dpref, * spref;
  uword * lookup_next_index, * lgpe_sw_if_index;

  /* treat negative fwd entries separately */
  if (a->is_negative)
    return add_del_negative_fwd_entry (lgm, a);

  /* add/del tunnel to tunnels pool and prepares rewrite */
  rv = add_del_tunnel (a, &tun_index);
  if (rv)
    return rv;

  dpref = &gid_address_ippref(&a->deid);
  spref = &gid_address_ippref(&a->seid);

  /* setup adjacency for eid */
  memset (&adj, 0, sizeof(adj));
  adj.n_adj = 1;
  adj.explicit_fib_index = ~0;

  if (a->is_add)
    {
      /* send packets that hit this adj to lisp-gpe interface output node in
       * requested vrf. */
      lookup_next_index = hash_get(lgm->lgpe_ip4_lookup_next_index_by_table_id,
                                   a->table_id);
      lgpe_sw_if_index = hash_get(lgm->lisp_gpe_hw_if_index_by_table_id,
                                  a->table_id);

      /* the assumption is that the interface must've been created before
       * programming the dp */
      ASSERT(lookup_next_index != 0);
      ASSERT(lgpe_sw_if_index != 0);

      adj.lookup_next_index = lookup_next_index[0];
      adj.rewrite_header.node_index = tun_index;
      adj.rewrite_header.sw_if_index = lgpe_sw_if_index[0];
    }

  /* add/delete route for prefix */
  rv = ip4_sd_fib_add_del_route (lgm, dpref, spref, a->table_id, &adj,
                                 a->is_add);

  /* check that everything worked */
  if (CLIB_DEBUG && a->is_add)
    {
      adj_index = ip4_sd_fib_get_route (lgm, dpref, spref, a->table_id);
      ASSERT(adj_index != 0);

      adjp = ip_get_adjacency (lgm->lookup_main, adj_index[0]);

      ASSERT(adjp != 0);
      ASSERT(adjp->rewrite_header.node_index == tun_index);
    }

  return rv;
}

static clib_error_t *
lisp_gpe_add_del_fwd_entry_command_fn (vlib_main_t * vm,
                                       unformat_input_t * input,
                                       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  ip_address_t slocator, dlocator, *slocators = 0, *dlocators = 0;
  ip_prefix_t * prefp;
  gid_address_t * eids = 0, eid;
  clib_error_t * error = 0;
  u32 i;

  prefp = &gid_address_ippref(&eid);

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat (line_input, "add"))
        is_add = 1;
      else if (unformat (line_input, "eid %U slocator %U dlocator %U",
                         unformat_ip_prefix, prefp,
                         unformat_ip_address, &slocator,
                         unformat_ip_address, &dlocator))
        {
          vec_add1 (eids, eid);
          vec_add1 (slocators, slocator);
          vec_add1 (dlocators, dlocator);
        }
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }
  unformat_free (line_input);

  if (vec_len (eids) + vec_len (slocators) == 0)
    {
      error = clib_error_return (0, "expected ip4/ip6 eids/locators.");
      goto done;
    }

  if (vec_len (eids) != vec_len (slocators))
    {
      error = clib_error_return (0, "number of eids not equal to that of "
          "locators.");
      goto done;
    }

  for (i = 0; i < vec_len(eids); i++)
    {
      vnet_lisp_gpe_add_del_fwd_entry_args_t a;
      memset (&a, 0, sizeof(a));

      a.is_add = is_add;
      a.deid = eids[i];
      a.slocator = slocators[i];
      a.dlocator = dlocators[i];
      prefp = &gid_address_ippref(&a.deid);
      a.decap_next_index = (ip_prefix_version(prefp) == IP4) ?
              LISP_GPE_INPUT_NEXT_IP4_INPUT : LISP_GPE_INPUT_NEXT_IP6_INPUT;
      vnet_lisp_gpe_add_del_fwd_entry (&a, 0);
    }

 done:
  vec_free(eids);
  vec_free(slocators);
  return error;
}

VLIB_CLI_COMMAND (add_del_lisp_gpe_mapping_tunnel_command, static) = {
  .path = "lisp gpe maptunnel",
  .short_help = "lisp gpe maptunnel eid <eid> sloc <src-locator> "
      "dloc <dst-locator> [del]",
  .function = lisp_gpe_add_del_fwd_entry_command_fn,
};

static u8 *
format_decap_next (u8 * s, va_list * args)
{
  u32 next_index = va_arg (*args, u32);

  switch (next_index)
    {
    case LISP_GPE_INPUT_NEXT_DROP:
      return format (s, "drop");
    case LISP_GPE_INPUT_NEXT_IP4_INPUT:
      return format (s, "ip4");
    case LISP_GPE_INPUT_NEXT_IP6_INPUT:
      return format (s, "ip6");
    default:
      return format (s, "unknown %d", next_index);
    }
  return s;
}

u8 *
format_lisp_gpe_tunnel (u8 * s, va_list * args)
{
  lisp_gpe_tunnel_t * t = va_arg (*args, lisp_gpe_tunnel_t *);
  lisp_gpe_main_t * lgm = &lisp_gpe_main;

  s = format (s,
              "[%d] %U (src) %U (dst) fibs: encap %d, decap %d",
              t - lgm->tunnels,
              format_ip4_address, &t->src,
              format_ip4_address, &t->dst,
              t->encap_fib_index,
              t->decap_fib_index);

  s = format (s, " decap next %U\n", format_decap_next, t->decap_next_index);
  s = format (s, "lisp ver %d ", (t->ver_res>>6));

#define _(n,v) if (t->flags & v) s = format (s, "%s-bit ", #n);
  foreach_lisp_gpe_flag_bit;
#undef _

  s = format (s, "next_protocol %d ver_res %x res %x\n",
              t->next_protocol, t->ver_res, t->res);

  s = format (s, "iid %d (0x%x)\n", t->vni, t->vni);
  return s;
}

static clib_error_t *
show_lisp_gpe_tunnel_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  lisp_gpe_tunnel_t * t;
  
  if (pool_elts (lgm->tunnels) == 0)
    vlib_cli_output (vm, "No lisp-gpe tunnels configured...");

  pool_foreach (t, lgm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_lisp_gpe_tunnel, t);
  }));
  
  return 0;
}

VLIB_CLI_COMMAND (show_lisp_gpe_tunnel_command, static) = {
    .path = "show lisp gpe tunnel",
    .function = show_lisp_gpe_tunnel_command_fn,
};

clib_error_t *
vnet_lisp_gpe_enable_disable (vnet_lisp_gpe_enable_disable_args_t * a)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  vnet_main_t * vnm = lgm->vnet_main;

  if (a->is_en)
    {
      /* add lgpe_ip4_lookup as possible next_node for ip4 lookup */
      if (lgm->ip4_lookup_next_lgpe_ip4_lookup == ~0)
        {
          lgm->ip4_lookup_next_lgpe_ip4_lookup = vlib_node_add_next (
              vnm->vlib_main, ip4_lookup_node.index,
              lgpe_ip4_lookup_node.index);
        }
      else
        {
          /* ask cp to re-add ifaces and defaults */
        }
    }
  else
    {
      CLIB_UNUSED(uword * val);
      hash_pair_t * p;
      u32 * table_ids = 0, * table_id;
      lisp_gpe_tunnel_key_t * tunnels = 0, * tunnel;
      vnet_lisp_gpe_add_del_fwd_entry_args_t _at, * at = &_at;
      vnet_lisp_gpe_add_del_iface_args_t _ai, * ai= &_ai;

      /* remove all tunnels */
      mhash_foreach(tunnel, val, &lgm->lisp_gpe_tunnel_by_key, ({
        vec_add1(tunnels, tunnel[0]);
      }));

      vec_foreach(tunnel, tunnels) {
        memset(at, 0, sizeof(at[0]));
        at->is_add = 0;
        gid_address_copy(&at->deid, &tunnel->eid);
        ip_addr_v4(&at->dlocator).as_u32= tunnel->dst_loc;
        vnet_lisp_gpe_add_del_fwd_entry (at, 0);
      }
      vec_free(tunnels);

      /* disable all ifaces */
      hash_foreach_pair(p, lgm->lisp_gpe_hw_if_index_by_table_id, ({
        vec_add1(table_ids, p->key);
      }));

      vec_foreach(table_id, table_ids) {
        ai->is_add = 0;
        ai->table_id = table_id[0];

        /* disables interface and removes defaults */
        vnet_lisp_gpe_add_del_iface(ai, 0);
      }
      vec_free(table_ids);
    }

  return 0;
}

static clib_error_t *
lisp_gpe_enable_disable_command_fn (vlib_main_t * vm, unformat_input_t * input,
                                    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_en = 1;
  vnet_lisp_gpe_enable_disable_args_t _a, * a = &_a;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
        is_en = 1;
      else if (unformat (line_input, "disable"))
        is_en = 0;
      else
        {
          return clib_error_return (0, "parse error: '%U'",
                                   format_unformat_error, line_input);
        }
    }
  a->is_en = is_en;
  return vnet_lisp_gpe_enable_disable (a);
}

VLIB_CLI_COMMAND (enable_disable_lisp_gpe_command, static) = {
  .path = "lisp gpe",
  .short_help = "lisp gpe [enable|disable]",
  .function = lisp_gpe_enable_disable_command_fn,
};

clib_error_t *
lisp_gpe_init (vlib_main_t *vm)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  clib_error_t * error = 0;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;

  lgm->vnet_main = vnet_get_main();
  lgm->vlib_main = vm;
  lgm->im4 = &ip4_main;
  lgm->lookup_main = &ip4_main.lookup_main;
  lgm->ip4_lookup_next_lgpe_ip4_lookup = ~0;

  mhash_init (&lgm->lisp_gpe_tunnel_by_key, sizeof(uword),
              sizeof(lisp_gpe_tunnel_key_t));

  udp_register_dst_port (vm, UDP_DST_PORT_lisp_gpe, 
                         lisp_gpe_input_node.index, 1 /* is_ip4 */);
  return 0;
}

VLIB_INIT_FUNCTION(lisp_gpe_init);
