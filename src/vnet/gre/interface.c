/*
 * gre_interface.c: gre interfaces
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/gre/gre.h>
#include <vnet/ip/format.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/mpls/mpls.h>

static const char *gre_tunnel_type_names[] = GRE_TUNNEL_TYPE_NAMES;

static inline u64
gre4_mk_key (const ip4_address_t *src,
            const ip4_address_t *dst,
            u32 out_fib_index)
{
  // FIXME. the fib index should be part of the key
  return ((u64)src->as_u32 << 32 | (u64)dst->as_u32);
}

static u8 *
format_gre_tunnel_type (u8 * s, va_list * args)
{
  gre_tunnel_type_t type = va_arg (*args, gre_tunnel_type_t);

  return (format(s, "%s", gre_tunnel_type_names[type]));
}

static u8 *
format_gre_tunnel (u8 * s, va_list * args)
{
  gre_tunnel_t * t = va_arg (*args, gre_tunnel_t *);
  gre_main_t * gm = &gre_main;
  u8 is_ipv6 = t->tunnel_dst.fp_proto == FIB_PROTOCOL_IP6 ? 1 : 0;

  if (!is_ipv6)
      s = format (s,
                  "[%d] %U (src) %U (dst) payload %U outer_fib_index %d",
                  t - gm->tunnels,
                  format_ip4_address, &t->tunnel_src.ip4,
                  format_ip4_address, &t->tunnel_dst.fp_addr.ip4,
                  format_gre_tunnel_type, t->type,
                  t->outer_fib_index);
  else
      s = format (s,
                  "[%d] %U (src) %U (dst) payload %U outer_fib_index %d",
                  t - gm->tunnels,
                  format_ip6_address, &t->tunnel_src.ip6,
                  format_ip6_address, &t->tunnel_dst.fp_addr.ip6,
                  format_gre_tunnel_type, t->type,
                  t->outer_fib_index);

  return s;
}

static gre_tunnel_t *
gre_tunnel_db_find (const ip46_address_t *src,
                    const ip46_address_t *dst,
                    u32 out_fib_index,
                    u8 is_ipv6)
{
  gre_main_t * gm = &gre_main;
  uword * p;
  u64 key4, key6[4];

  if (!is_ipv6)
    {
      key4 = gre4_mk_key(&src->ip4, &dst->ip4, out_fib_index);
      p = hash_get (gm->tunnel_by_key4, key4);
    }
  else
    {
      key6[0] = src->ip6.as_u64[0];
      key6[1] = src->ip6.as_u64[1];
      key6[2] = dst->ip6.as_u64[0];
      key6[3] = dst->ip6.as_u64[1];
      p = hash_get_mem (gm->tunnel_by_key6, key6);
    }

  if (NULL == p)
    return (NULL);

  return (pool_elt_at_index (gm->tunnels, p[0]));
}

static void
gre_tunnel_db_add (const gre_tunnel_t *t)
{
  gre_main_t * gm = &gre_main;
  u64 key4, key6[4], *key6_copy;
  u8 is_ipv6 = t->tunnel_dst.fp_proto == FIB_PROTOCOL_IP6 ? 1 : 0;

  if (!is_ipv6)
    {
      key4 = gre4_mk_key(&t->tunnel_src.ip4, &t->tunnel_dst.fp_addr.ip4,
                       t->outer_fib_index);
      hash_set (gm->tunnel_by_key4, key4, t - gm->tunnels);
    }
  else
    {
      key6[0] = t->tunnel_src.ip6.as_u64[0];
      key6[1] = t->tunnel_src.ip6.as_u64[1];
      key6[2] = t->tunnel_dst.fp_addr.ip6.as_u64[0];
      key6[3] = t->tunnel_dst.fp_addr.ip6.as_u64[1];
      key6_copy = clib_mem_alloc (sizeof (key6));
      clib_memcpy (key6_copy, key6, sizeof (key6));
      hash_set_mem (gm->tunnel_by_key6, key6_copy, t - gm->tunnels);
    }
}

static void
gre_tunnel_db_remove (const gre_tunnel_t *t)
{
  gre_main_t * gm = &gre_main;
  u64 key4, key6[4];
  u8 is_ipv6 = t->tunnel_dst.fp_proto == FIB_PROTOCOL_IP6 ? 1 : 0;

  if (!is_ipv6)
    {
      key4 = gre4_mk_key(&t->tunnel_src.ip4, &t->tunnel_dst.fp_addr.ip4,
                         t->outer_fib_index);
      hash_unset (gm->tunnel_by_key4, key4);
    }
  else
    {
      key6[0] = t->tunnel_src.ip6.as_u64[0];
      key6[1] = t->tunnel_src.ip6.as_u64[1];
      key6[2] = t->tunnel_dst.fp_addr.ip6.as_u64[0];
      key6[3] = t->tunnel_dst.fp_addr.ip6.as_u64[1];
      hash_unset_mem (gm->tunnel_by_key6, key6);
    }

}

static gre_tunnel_t *
gre_tunnel_from_fib_node (fib_node_t *node)
{
#if (CLIB_DEBUG > 0)
    ASSERT(FIB_NODE_TYPE_GRE_TUNNEL == node->fn_type);
#endif
    return ((gre_tunnel_t*) (((char*)node) -
                             STRUCT_OFFSET_OF(gre_tunnel_t, node)));
}

/**
 * gre_tunnel_stack
 *
 * 'stack' (resolve the recursion for) the tunnel's midchain adjacency
 */
void
gre_tunnel_stack (adj_index_t ai)
{
    gre_main_t * gm = &gre_main;
    ip_adjacency_t *adj;
    gre_tunnel_t *gt;
    u32 sw_if_index;

    adj = adj_get(ai);
    sw_if_index = adj->rewrite_header.sw_if_index;

    if ((vec_len(gm->tunnel_index_by_sw_if_index) < sw_if_index) ||
	(~0 == gm->tunnel_index_by_sw_if_index[sw_if_index]))
	return;

    gt = pool_elt_at_index(gm->tunnels,
			   gm->tunnel_index_by_sw_if_index[sw_if_index]);

    /*
     * find the adjacency that is contributed by the FIB entry
     * that this tunnel resovles via, and use it as the next adj
     * in the midchain
     */
    if (vnet_hw_interface_get_flags(vnet_get_main(),
				    gt->hw_if_index) &
	VNET_HW_INTERFACE_FLAG_LINK_UP)
    {
	adj_nbr_midchain_stack(
	    ai,
	    fib_entry_contribute_ip_forwarding(gt->fib_entry_index));
    }
    else
    {
	adj_nbr_midchain_unstack(ai);
    }
}

/**
 * @brief Call back when restacking all adjacencies on a GRE interface
 */
static adj_walk_rc_t
gre_adj_walk_cb (adj_index_t ai,
		 void *ctx)
{
    gre_tunnel_stack(ai);

    return (ADJ_WALK_RC_CONTINUE);
}

static void
gre_tunnel_restack (gre_tunnel_t *gt)
{
    fib_protocol_t proto;

    /*
     * walk all the adjacencies on th GRE interface and restack them
     */
    FOR_EACH_FIB_IP_PROTOCOL(proto)
    {
	adj_nbr_walk(gt->sw_if_index,
		     proto,
		     gre_adj_walk_cb,
		     NULL);
    }
}

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
gre_tunnel_back_walk (fib_node_t *node,
		      fib_node_back_walk_ctx_t *ctx)
{
    gre_tunnel_restack(gre_tunnel_from_fib_node(node));

    return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t*
gre_tunnel_fib_node_get (fib_node_index_t index)
{
    gre_tunnel_t * gt;
    gre_main_t * gm;

    gm  = &gre_main;
    gt = pool_elt_at_index(gm->tunnels, index);

    return (&gt->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
gre_tunnel_last_lock_gone (fib_node_t *node)
{
    /*
     * The MPLS GRE tunnel is a root of the graph. As such
     * it never has children and thus is never locked.
     */
    ASSERT(0);
}

/*
 * Virtual function table registered by MPLS GRE tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t gre_vft = {
    .fnv_get = gre_tunnel_fib_node_get,
    .fnv_last_lock = gre_tunnel_last_lock_gone,
    .fnv_back_walk = gre_tunnel_back_walk,
};

static int
vnet_gre_tunnel_add (vnet_gre_add_del_tunnel_args_t *a,
                     u32 * sw_if_indexp)
{
  gre_main_t * gm = &gre_main;
  vnet_main_t * vnm = gm->vnet_main;
  ip4_main_t * im4 = &ip4_main;
  ip6_main_t * im6 = &ip6_main;
  gre_tunnel_t * t;
  vnet_hw_interface_t * hi;
  u32 hw_if_index, sw_if_index;
  u32 outer_fib_index;
  u8 address[6];
  clib_error_t *error;
  u8 is_ipv6 = a->is_ipv6;

  if (!is_ipv6)
    outer_fib_index = ip4_fib_index_from_table_id(a->outer_fib_id);
  else
    outer_fib_index = ip6_fib_index_from_table_id(a->outer_fib_id);

  if (~0 == outer_fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  t = gre_tunnel_db_find(&a->src, &a->dst, a->outer_fib_id, a->is_ipv6);

  if (NULL != t)
    return VNET_API_ERROR_INVALID_VALUE;

  pool_get_aligned (gm->tunnels, t, CLIB_CACHE_LINE_BYTES);
  memset (t, 0, sizeof (*t));
  fib_node_init(&t->node, FIB_NODE_TYPE_GRE_TUNNEL);

  if (a->teb)
      t->type = GRE_TUNNEL_TYPE_TEB;
  else
      t->type = GRE_TUNNEL_TYPE_L3;

  if (vec_len (gm->free_gre_tunnel_hw_if_indices[t->type]) > 0) {
      vnet_interface_main_t * im = &vnm->interface_main;

      hw_if_index = gm->free_gre_tunnel_hw_if_indices[t->type]
          [vec_len (gm->free_gre_tunnel_hw_if_indices[t->type])-1];
      _vec_len (gm->free_gre_tunnel_hw_if_indices[t->type]) -= 1;

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->dev_instance = t - gm->tunnels;
      hi->hw_instance = hi->dev_instance;

      /* clear old stats of freed tunnel before reuse */
      sw_if_index = hi->sw_if_index;
      vnet_interface_counter_lock(im);
      vlib_zero_combined_counter
          (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX], sw_if_index);
      vlib_zero_combined_counter
          (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_RX], sw_if_index);
      vlib_zero_simple_counter
          (&im->sw_if_counters[VNET_INTERFACE_COUNTER_DROP], sw_if_index);
        vnet_interface_counter_unlock(im);
      if (GRE_TUNNEL_TYPE_TEB == t->type)
      {
          t->l2_tx_arc = vlib_node_add_named_next(vlib_get_main(),
                                                  hi->tx_node_index,
                                                  "adj-l2-midchain");
      }
    } else {
      if (GRE_TUNNEL_TYPE_TEB == t->type)
      {
        /* Default MAC address (d00b:eed0:0000 + sw_if_index) */
        memset (address, 0, sizeof (address));
        address[0] = 0xd0;
        address[1] = 0x0b;
        address[2] = 0xee;
        address[3] = 0xd0;
        address[4] = t - gm->tunnels;

        error = ethernet_register_interface(vnm,
					    gre_device_teb_class.index,
					    t - gm->tunnels, address,
					    &hw_if_index,
					    0);

        if (error)
        {
          clib_error_report (error);
          return VNET_API_ERROR_INVALID_REGISTRATION;
        }
	hi = vnet_get_hw_interface (vnm, hw_if_index);

	t->l2_tx_arc = vlib_node_add_named_next(vlib_get_main(),
						hi->tx_node_index,
						"adj-l2-midchain");
      } else {
	hw_if_index = vnet_register_interface(vnm,
					      gre_device_class.index,
					      t - gm->tunnels,
					      gre_hw_interface_class.index,
					      t - gm->tunnels);
      }
      hi = vnet_get_hw_interface (vnm, hw_if_index);
      sw_if_index = hi->sw_if_index;
    }

  t->hw_if_index = hw_if_index;
  t->outer_fib_index = outer_fib_index;
  t->sw_if_index = sw_if_index;
  t->l2_adj_index = ADJ_INDEX_INVALID;

  vec_validate_init_empty (gm->tunnel_index_by_sw_if_index, sw_if_index, ~0);
  gm->tunnel_index_by_sw_if_index[sw_if_index] = t - gm->tunnels;

  if (!is_ipv6)
    {
      vec_validate (im4->fib_index_by_sw_if_index, sw_if_index);
      hi->min_packet_bytes = 64 + sizeof (gre_header_t) + sizeof (ip4_header_t);
    }
  else
    {
      vec_validate (im6->fib_index_by_sw_if_index, sw_if_index);
      hi->min_packet_bytes = 64 + sizeof (gre_header_t) + sizeof (ip6_header_t);
    }

  hi->per_packet_overhead_bytes =
      /* preamble */ 8 + /* inter frame gap */ 12;

  /* Standard default gre MTU. */
  hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] = 9000;

  /*
   * source the FIB entry for the tunnel's destination
   * and become a child thereof. The tunnel will then get poked
   * when the forwarding for the entry updates, and the tunnel can
   * re-stack accordingly
   */

  clib_memcpy (&t->tunnel_src, &a->src, sizeof (t->tunnel_src));
  t->tunnel_dst.fp_len = !is_ipv6 ? 32 : 128;
  t->tunnel_dst.fp_proto = !is_ipv6 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  t->tunnel_dst.fp_addr = a->dst;

  gre_tunnel_db_add(t);

  t->fib_entry_index =
      fib_table_entry_special_add(outer_fib_index,
                                  &t->tunnel_dst,
                                  FIB_SOURCE_RR,
                                  FIB_ENTRY_FLAG_NONE);
  t->sibling_index =
      fib_entry_child_add(t->fib_entry_index,
                          FIB_NODE_TYPE_GRE_TUNNEL,
                          t - gm->tunnels);

  if (GRE_TUNNEL_TYPE_TEB == t->type)
  {
      t->l2_adj_index = adj_nbr_add_or_lock(t->tunnel_dst.fp_proto,
					    VNET_LINK_ETHERNET,
					    &zero_addr,
					    sw_if_index);
      gre_update_adj(vnm, t->sw_if_index, t->l2_adj_index);
  }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}

static int
vnet_gre_tunnel_delete (vnet_gre_add_del_tunnel_args_t *a,
                        u32 * sw_if_indexp)
{
  gre_main_t * gm = &gre_main;
  vnet_main_t * vnm = gm->vnet_main;
  gre_tunnel_t * t;
  u32 sw_if_index;

  t = gre_tunnel_db_find(&a->src, &a->dst, a->outer_fib_id, a->is_ipv6);

  if (NULL == t)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  sw_if_index = t->sw_if_index;
  vnet_sw_interface_set_flags (vnm, sw_if_index, 0 /* down */);
  /* make sure tunnel is removed from l2 bd or xconnect */
  set_int_l2_mode(gm->vlib_main, vnm, MODE_L3, sw_if_index, 0, 0, 0, 0);
  vec_add1 (gm->free_gre_tunnel_hw_if_indices[t->type], t->hw_if_index);
  gm->tunnel_index_by_sw_if_index[sw_if_index] = ~0;

  if (GRE_TUNNEL_TYPE_TEB == t->type)
    adj_unlock(t->l2_adj_index);

  if (t->l2_adj_index != ADJ_INDEX_INVALID)
      adj_unlock(t->l2_adj_index);

  fib_entry_child_remove(t->fib_entry_index,
                         t->sibling_index);
  fib_table_entry_delete_index(t->fib_entry_index,
                               FIB_SOURCE_RR);

  gre_tunnel_db_remove(t);
  fib_node_deinit(&t->node);
  pool_put (gm->tunnels, t);

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}

int
vnet_gre_add_del_tunnel (vnet_gre_add_del_tunnel_args_t *a,
                         u32 * sw_if_indexp)
{
  if (a->is_add)
    return (vnet_gre_tunnel_add(a, sw_if_indexp));
  else
    return (vnet_gre_tunnel_delete(a, sw_if_indexp));
}

clib_error_t *
gre_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  gre_main_t * gm = &gre_main;
  vnet_hw_interface_t * hi;
  gre_tunnel_t *t;
  u32 ti;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  if (NULL == gm->tunnel_index_by_sw_if_index ||
      hi->sw_if_index >= vec_len(gm->tunnel_index_by_sw_if_index))
      return (NULL);

  ti = gm->tunnel_index_by_sw_if_index[hi->sw_if_index];

  if (~0 == ti)
      /* not one of ours */
      return (NULL);

  t = pool_elt_at_index(gm->tunnels, ti);

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags (vnm, hw_if_index, VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, hw_if_index, 0 /* down */);

  gre_tunnel_restack(t);

  return /* no error */ 0;
}

static clib_error_t *
create_gre_tunnel_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  vnet_gre_add_del_tunnel_args_t _a, * a = &_a;
  ip46_address_t src, dst;
  u32 outer_fib_id = 0;
  u8 teb = 0;
  int rv;
  u32 num_m_args = 0;
  u8 is_add = 1;
  u32 sw_if_index;
  clib_error_t *error = NULL;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "src %U", unformat_ip4_address, &src.ip4)) {
      num_m_args++;
      ipv4_set = 1;
    } else if (unformat (line_input, "dst %U", unformat_ip4_address, &dst.ip4)) {
      num_m_args++;
      ipv4_set = 1;
    } else if (unformat (line_input, "src %U", unformat_ip6_address, &src.ip6)) {
      num_m_args++;
      ipv6_set = 1;
    } else if (unformat (line_input, "dst %U", unformat_ip6_address, &dst.ip6)) {
      num_m_args++;
      ipv6_set = 1;
    } else if (unformat (line_input, "outer-fib-id %d", &outer_fib_id))
      ;
    else if (unformat (line_input, "teb"))
      teb = 1;
    else
      {
        error = clib_error_return (0, "unknown input `%U'",
                                   format_unformat_error, line_input);
        goto done;
      }
  }

  if (num_m_args < 2)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      goto done;
    }

  if ((ipv4_set && memcmp (&src.ip4, &dst.ip4, sizeof(src.ip4)) == 0) ||
      (ipv6_set && memcmp (&src.ip6, &dst.ip6, sizeof(src.ip6)) == 0))
    {
      error = clib_error_return (0, "src and dst are identical");
      goto done;
    }

  if (ipv4_set && ipv6_set)
      return clib_error_return (0, "both IPv4 and IPv6 addresses specified");

  if ((ipv4_set && memcmp (&dst.ip4, &zero_addr.ip4, sizeof(dst.ip4)) == 0) ||
      (ipv6_set && memcmp (&dst.ip6, &zero_addr.ip6, sizeof(dst.ip6)) == 0))
    {
      error = clib_error_return (0, "dst address cannot be zero");
      goto done;
    }

  memset (a, 0, sizeof (*a));
  a->outer_fib_id = outer_fib_id;
  a->teb = teb;
  a->is_ipv6 = ipv6_set;
  if (!ipv6_set)
    {
      clib_memcpy(&a->src.ip4, &src.ip4, sizeof(src.ip4));
      clib_memcpy(&a->dst.ip4, &dst.ip4, sizeof(dst.ip4));
    }
  else
    {
      clib_memcpy(&a->src.ip6, &src.ip6, sizeof(src.ip6));
      clib_memcpy(&a->dst.ip6, &dst.ip6, sizeof(dst.ip6));
    }

  if (is_add)
    rv = vnet_gre_tunnel_add(a, &sw_if_index);
  else
    rv = vnet_gre_tunnel_delete(a, &sw_if_index);

  switch(rv)
    {
    case 0:
      vlib_cli_output(vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main(), sw_if_index);
      break;
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "GRE tunnel already exists...");
      goto done;
    case VNET_API_ERROR_NO_SUCH_FIB:
      error = clib_error_return (0, "outer fib ID %d doesn't exist\n",
                                 outer_fib_id);
      goto done;
    default:
      error = clib_error_return (0, "vnet_gre_add_del_tunnel returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (create_gre_tunnel_command, static) = {
  .path = "create gre tunnel",
  .short_help = "create gre tunnel src <addr> dst <addr> "
                "[outer-fib-id <fib>] [teb] [del]",
  .function = create_gre_tunnel_command_fn,
};

static clib_error_t *
show_gre_tunnel_command_fn (vlib_main_t * vm,
                            unformat_input_t * input,
                            vlib_cli_command_t * cmd)
{
  gre_main_t * gm = &gre_main;
  gre_tunnel_t * t;
  u32 ti = ~0;

  if (pool_elts (gm->tunnels) == 0)
    vlib_cli_output (vm, "No GRE tunnels configured...");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &ti))
        ;
      else
        break;
    }

  if (~0 == ti)
    {
      pool_foreach (t, gm->tunnels,
      ({
          vlib_cli_output (vm, "%U", format_gre_tunnel, t);
      }));
    }
  else
  {
      t = pool_elt_at_index(gm->tunnels, ti);

      vlib_cli_output (vm, "%U", format_gre_tunnel, t);
  }

  return 0;
}

VLIB_CLI_COMMAND (show_gre_tunnel_command, static) = {
    .path = "show gre tunnel",
    .function = show_gre_tunnel_command_fn,
};

/* force inclusion from application's main.c */
clib_error_t *gre_interface_init (vlib_main_t *vm)
{
  fib_node_register_type(FIB_NODE_TYPE_GRE_TUNNEL, &gre_vft);

  return 0;
}
VLIB_INIT_FUNCTION(gre_interface_init);
