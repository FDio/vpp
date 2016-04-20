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

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/udp.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/lisp-gpe/lisp_gpe.h>

#define foreach_lisp_gpe_tx_next        \
  _(DROP, "error-drop")                 \
  _(IP4_LOOKUP, "ip4-lookup")

typedef enum
{
#define _(sym,str) LISP_GPE_TX_NEXT_##sym,
  foreach_lisp_gpe_tx_next
#undef _
  LISP_GPE_TX_N_NEXT,
} lisp_gpe_tx_next_t;

typedef struct
{
  u32 tunnel_index;
} lisp_gpe_tx_trace_t;

u8 *
format_lisp_gpe_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lisp_gpe_tx_trace_t * t = va_arg (*args, lisp_gpe_tx_trace_t *);

  s = format (s, "LISP-GPE-TX: tunnel %d", t->tunnel_index);
  return s;
}

static uword
lisp_gpe_interface_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  u32 pkts_encapsulated = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          u32 bi0, bi1;
          vlib_buffer_t * b0, * b1;
          u32 next0, next1;
          u32 adj_index0, adj_index1, tunnel_index0, tunnel_index1;
          ip_adjacency_t * adj0, * adj1;
          lisp_gpe_tunnel_t * t0, * t1;

          next0 = next1 = LISP_GPE_TX_NEXT_IP4_LOOKUP;

          /* Prefetch next iteration. */
            {
              vlib_buffer_t * p2, *p3;

              p2 = vlib_get_buffer (vm, from[2]);
              p3 = vlib_get_buffer (vm, from[3]);

              vlib_prefetch_buffer_header(p2, LOAD);
              vlib_prefetch_buffer_header(p3, LOAD);

              CLIB_PREFETCH(p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
              CLIB_PREFETCH(p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
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

          /* Get adjacency and from it the tunnel_index */
          adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
          adj_index1 = vnet_buffer(b1)->ip.adj_index[VLIB_TX];

          adj0 = ip_get_adjacency (lgm->lookup_main, adj_index0);
          adj1 = ip_get_adjacency (lgm->lookup_main, adj_index1);

          tunnel_index0 = adj0->rewrite_header.node_index;
          tunnel_index1 = adj1->rewrite_header.node_index;

          t0 = pool_elt_at_index (lgm->tunnels, tunnel_index0);
          t1 = pool_elt_at_index (lgm->tunnels, tunnel_index1);

          ASSERT(t0 != 0);
          ASSERT(t1 != 0);

          ASSERT (sizeof(ip4_udp_lisp_gpe_header_t) == 36);
          ip4_udp_encap_two (vm, b0, b1, t0->rewrite, t1->rewrite, 36);

          /* Reset to look up tunnel partner in the configured FIB */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->encap_fib_index;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = t1->encap_fib_index;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              lisp_gpe_tx_trace_t *tr = vlib_add_trace (vm, node, b0,
                                                           sizeof(*tr));
              tr->tunnel_index = t0 - lgm->tunnels;
            }
          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
              lisp_gpe_tx_trace_t *tr = vlib_add_trace (vm, node, b1,
                                                           sizeof(*tr));
              tr->tunnel_index = t1 - lgm->tunnels;
            }

          pkts_encapsulated += 2;

          vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                                          n_left_to_next, bi0, bi1, next0,
                                          next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          vlib_buffer_t * b0;
          u32 bi0, adj_index0, tunnel_index0;
          u32 next0 = LISP_GPE_TX_NEXT_IP4_LOOKUP;
          lisp_gpe_tunnel_t * t0 = 0;
          ip_adjacency_t * adj0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          /* Get adjacency and from it the tunnel_index */
          adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
          adj0 = ip_get_adjacency (lgm->lookup_main, adj_index0);

          tunnel_index0 = adj0->rewrite_header.node_index;
          t0 = pool_elt_at_index (lgm->tunnels, tunnel_index0);

          ASSERT(t0 != 0);

          ASSERT (sizeof(ip4_udp_lisp_gpe_header_t) == 36);
          ip4_udp_encap_one (vm, b0, t0->rewrite, 36);

          /* Reset to look up tunnel partner in the configured FIB */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->encap_fib_index;

          pkts_encapsulated++;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              lisp_gpe_tx_trace_t *tr = vlib_add_trace (vm, node, b0,
                                                           sizeof(*tr));
              tr->tunnel_index = t0 - lgm->tunnels;
            }
          vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index,
                               LISP_GPE_ERROR_ENCAPSULATED, pkts_encapsulated);
  return from_frame->n_vectors;
}

static u8 *
format_lisp_gpe_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "lisp_gpe%d", dev_instance);
}

VNET_DEVICE_CLASS (lisp_gpe_device_class,static) = {
  .name = "LISP_GPE",
  .format_device_name = format_lisp_gpe_name,
  .format_tx_trace = format_lisp_gpe_tx_trace,
  .tx_function = lisp_gpe_interface_tx,
  .no_flatten_output_chains = 1,
};

static uword
dummy_set_rewrite (vnet_main_t * vnm, u32 sw_if_index, u32 l3_type,
                   void * dst_address, void * rewrite, uword max_rewrite_bytes)
{
  return 0;
}

u8 *
format_lisp_gpe_header_with_length (u8 * s, va_list * args)
{
  lisp_gpe_header_t * h = va_arg (*args, lisp_gpe_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "lisp-gpe header truncated");

  s = format (s, "flags: ");
#define _(n,v) if (h->flags & v) s = format (s, "%s ", #n);
  foreach_lisp_gpe_flag_bit;
#undef _

  s = format (s, "\n  ver_res %d res %d next_protocol %d iid %d(%x)",
              h->ver_res, h->res, h->next_protocol,
              clib_net_to_host_u32 (h->iid),
              clib_net_to_host_u32 (h->iid));
  return s;
}

VNET_HW_INTERFACE_CLASS (lisp_gpe_hw_class) = {
  .name = "LISP_GPE",
  .format_header = format_lisp_gpe_header_with_length,
  .set_rewrite = dummy_set_rewrite,
};

int
add_del_ip_prefix_route (ip_prefix_t * dst_prefix, u32 table_id,
                         ip_adjacency_t * add_adj, u8 is_add, u32 * adj_index)
{
  uword * p;

  if (ip_prefix_version(dst_prefix) == IP4)
    {
      ip4_main_t * im4 = &ip4_main;
      ip4_add_del_route_args_t a;
      ip4_address_t addr = ip_prefix_v4(dst_prefix);

      memset(&a, 0, sizeof(a));
      a.flags = IP4_ROUTE_FLAG_TABLE_ID;
      a.table_index_or_table_id = table_id;
      a.adj_index = ~0;
      a.dst_address_length = ip_prefix_len(dst_prefix);
      a.dst_address = addr;
      a.flags |= is_add ? IP4_ROUTE_FLAG_ADD : IP4_ROUTE_FLAG_DEL;
      a.add_adj = add_adj;
      a.n_add_adj = 1;
      ip4_add_del_route (im4, &a);

      if (is_add)
        {
          p = ip4_get_route (im4, table_id, 0, addr.as_u8,
                             ip_prefix_len(dst_prefix));
          if (p == 0)
            {
              clib_warning("Failed to insert route for eid %U!",
                           format_ip4_address_and_length, addr.as_u8,
                           ip_prefix_len(dst_prefix));
              return -1;
            }
          adj_index[0] = p[0];
        }
    }
  else
    {
      ip6_main_t * im6 = &ip6_main;
      ip6_add_del_route_args_t a;
      ip6_address_t addr = ip_prefix_v6(dst_prefix);

      memset(&a, 0, sizeof(a));
      a.flags = IP6_ROUTE_FLAG_TABLE_ID;
      a.table_index_or_table_id = table_id;
      a.adj_index = ~0;
      a.dst_address_length = ip_prefix_len(dst_prefix);
      a.dst_address = addr;
      a.flags |= is_add ? IP6_ROUTE_FLAG_ADD : IP6_ROUTE_FLAG_DEL;
      a.add_adj = add_adj;
      a.n_add_adj = 1;

      ip6_add_del_route (im6, &a);

      if (is_add)
        {
          adj_index[0] = ip6_get_route (im6, table_id, 0, &addr,
                                        ip_prefix_len(dst_prefix));
          if (adj_index[0] == 0)
            {
              clib_warning("Failed to insert route for eid %U!",
                           format_ip6_address_and_length, addr.as_u8,
                           ip_prefix_len(dst_prefix));
              return -1;
            }
        }
    }
  return 0;
}

static void
add_del_lisp_gpe_default_route (u32 table_id, u8 is_v4, u8 is_add)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  ip_adjacency_t adj;
  ip_prefix_t prefix;
  u32 adj_index = 0;

  /* setup adjacency */
  memset (&adj, 0, sizeof(adj));

  adj.n_adj = 1;
  adj.explicit_fib_index = ~0;
  adj.lookup_next_index = lgm->ip4_lookup_next_lgpe_ip4_lookup;
  /* default route has tunnel_index ~0 */
  adj.rewrite_header.sw_if_index = ~0;

  /* set prefix to 0/0 */
  memset(&prefix, 0, sizeof(prefix));
  ip_prefix_version(&prefix) = is_v4 ? IP4 : IP6;

  /* add/delete route for prefix */
  add_del_ip_prefix_route (&prefix, table_id, &adj, is_add, &adj_index);
}

static void
lisp_gpe_iface_set_table (u32 sw_if_index, u32 table_id, u8 is_ip4)
{
  if (is_ip4)
    {
      ip4_main_t * im4 = &ip4_main;
      ip4_fib_t * fib;
      fib = find_ip4_fib_by_table_index_or_id (im4, table_id,
                                               IP4_ROUTE_FLAG_TABLE_ID);

      /* fib's created if it doesn't exist */
      ASSERT(fib != 0);

      vec_validate(im4->fib_index_by_sw_if_index, sw_if_index);
      im4->fib_index_by_sw_if_index[sw_if_index] = fib->index;
    }
  else
    {
      ip6_main_t * im6 = &ip6_main;
      ip6_fib_t * fib;
      fib = find_ip6_fib_by_table_index_or_id (im6, table_id,
                                               IP6_ROUTE_FLAG_TABLE_ID);

      /* fib's created if it doesn't exist */
      ASSERT(fib != 0);

      vec_validate(im6->fib_index_by_sw_if_index, sw_if_index);
      im6->fib_index_by_sw_if_index[sw_if_index] = fib->index;
    }
}

void
vnet_lisp_gpe_add_del_iface (vnet_lisp_gpe_add_del_iface_args_t * a,
                             u32 * hw_if_indexp)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  vnet_main_t * vnm = lgm->vnet_main;
  vnet_hw_interface_t * hi;
  u32 hw_if_index = ~0, lookup_next_index, flen;
  uword * hip, * vni;

  hip = hash_get(lgm->lisp_gpe_hw_if_index_by_table_id, a->table_id);

  if (a->is_add)
    {
      if (hip)
        {
          clib_warning ("Interface for vrf %d already exists", a->table_id);
          return;
        }

      /* create hw lisp_gpeX iface if needed, otherwise reuse existing */
      flen = vec_len(lgm->free_lisp_gpe_tunnel_hw_if_indices);
      if (flen > 0)
        {
          hw_if_index = lgm->free_lisp_gpe_tunnel_hw_if_indices[flen - 1];
          _vec_len(lgm->free_lisp_gpe_tunnel_hw_if_indices) -= 1;
        }
      else
        {
          hw_if_index = vnet_register_interface (vnm,
                                                 lisp_gpe_device_class.index,
                                                 a->table_id,
                                                 lisp_gpe_hw_class.index, 0);
        }

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hash_set(lgm->lisp_gpe_hw_if_index_by_table_id, a->table_id, hw_if_index);

      /* set tunnel termination: post decap, packets are tagged as having been
       * originated by lisp-gpe interface */
      hash_set(lgm->tunnel_term_sw_if_index_by_vni, a->vni, hi->sw_if_index);
      hash_set(lgm->vni_by_tunnel_term_sw_if_index, hi->sw_if_index, a->vni);

      /* set ingress arc from lgpe_ip4_lookup */
      lookup_next_index = vlib_node_add_next (lgm->vlib_main,
                                              lgpe_ip4_lookup_node.index,
                                              hi->output_node_index);
      hash_set(lgm->lgpe_ip4_lookup_next_index_by_table_id, a->table_id,
               lookup_next_index);

      /* insert default routes that point to lgpe-ipx-lookup */
      add_del_lisp_gpe_default_route (a->table_id, /* is_v4 */1, 1);
      add_del_lisp_gpe_default_route (a->table_id, /* is_v4 */0, 1);

      /* set egress arcs */
#define _(sym,str) vlib_node_add_named_next_with_slot (vnm->vlib_main, \
                    hi->tx_node_index, str, LISP_GPE_TX_NEXT_##sym);
          foreach_lisp_gpe_tx_next
#undef _

      /* set interface in appropriate v4 and v6 FIBs */
      lisp_gpe_iface_set_table (hi->sw_if_index, a->table_id, 1);
      lisp_gpe_iface_set_table (hi->sw_if_index, a->table_id, 0);

      /* enable interface */
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index,
                                   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
      vnet_hw_interface_set_flags (vnm, hi->hw_if_index,
                                   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
  else
    {
      if (hip == 0)
        {
          clib_warning("The interface for vrf %d doesn't exist", a->table_id);
          return;
        }
      hi = vnet_get_hw_interface (vnm, hip[0]);

      /* disable interface */
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 0/* down */);
      vnet_hw_interface_set_flags (vnm, hi->hw_if_index, 0/* down */);
      hash_unset(lgm->lisp_gpe_hw_if_index_by_table_id, a->table_id);
      vec_add1(lgm->free_lisp_gpe_tunnel_hw_if_indices, hi->hw_if_index);

      /* clean tunnel termination and vni to sw_if_index binding */
      vni = hash_get(lgm->vni_by_tunnel_term_sw_if_index, hi->sw_if_index);
      hash_unset(lgm->tunnel_term_sw_if_index_by_vni, vni[0]);
      hash_unset(lgm->vni_by_tunnel_term_sw_if_index, hi->sw_if_index);

      /* unset default routes */
      add_del_lisp_gpe_default_route (a->table_id, /* is_v4 */1, 0);
      add_del_lisp_gpe_default_route (a->table_id, /* is_v4 */0, 0);
    }
}

static clib_error_t *
lisp_gpe_add_del_iface_command_fn (vlib_main_t * vm, unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  u32 table_id;

  vnet_lisp_gpe_add_del_iface_args_t _a, * a = &_a;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
        is_add = 1;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat (line_input, "vrf %d", &table_id))
        ;
      else
        {
          return clib_error_return (0, "parse error: '%U'",
                                   format_unformat_error, line_input);
        }
    }

  a->is_add = is_add;
  a->table_id = table_id;
  vnet_lisp_gpe_add_del_iface (a, 0);
  return 0;
}

VLIB_CLI_COMMAND (add_del_lisp_gpe_iface_command, static) = {
  .path = "lisp gpe iface",
  .short_help = "lisp gpe iface add/del table-index <table_index> vrf <vrf>",
  .function = lisp_gpe_add_del_iface_command_fn,
};
