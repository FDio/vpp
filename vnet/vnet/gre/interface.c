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
#include <vnet/adj/adj_midchain.h>
#include <vnet/mpls/mpls.h>

static inline u64
gre_mk_key (const ip4_address_t *src,
            const ip4_address_t *dst,
            u32 out_fib_index)
{
  // FIXME. the fib index should be part of the key
  return ((u64)src->as_u32 << 32 | (u64)dst->as_u32);
}

static u8 *
format_gre_tunnel (u8 * s, va_list * args)
{
  gre_tunnel_t * t = va_arg (*args, gre_tunnel_t *);
  int detail = va_arg (*args, int);
  gre_main_t * gm = &gre_main;

  s = format (s,
              "[%d] %U (src) %U (dst) payload %s outer_fib_index %d",
              t - gm->tunnels,
              format_ip4_address, &t->tunnel_src,
              format_ip4_address, &t->tunnel_dst,
              (t->teb ? "teb" : "ip"),
              t->outer_fib_index);
  if (detail)
  {
      s = format (s, "\n  fib-entry:%d adj-ip4:%d adj-ip6:%d adj-mpls:%d",
                  t->fib_entry_index,
                  t->adj_index[FIB_LINK_IP4],
                  t->adj_index[FIB_LINK_IP6],
                  t->adj_index[FIB_LINK_MPLS]);
  }

  return s;
}

static gre_tunnel_t *
gre_tunnel_db_find (const ip4_address_t *src,
                    const ip4_address_t *dst,
                    u32 out_fib_index)
{
  gre_main_t * gm = &gre_main;
  uword * p;
  u64 key;

  key = gre_mk_key(src, dst, out_fib_index);

  p = hash_get (gm->tunnel_by_key, key);

  if (NULL == p)
    return (NULL);

  return (pool_elt_at_index (gm->tunnels, p[0]));
}

static void
gre_tunnel_db_add (const gre_tunnel_t *t)
{
  gre_main_t * gm = &gre_main;
  u64 key;

  key = gre_mk_key(&t->tunnel_src, &t->tunnel_dst, t->outer_fib_index);
  hash_set (gm->tunnel_by_key, key, t - gm->tunnels);
}

static void
gre_tunnel_db_remove (const gre_tunnel_t *t)
{
  gre_main_t * gm = &gre_main;
  u64 key;

  key = gre_mk_key(&t->tunnel_src, &t->tunnel_dst, t->outer_fib_index);
  hash_unset (gm->tunnel_by_key, key);
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
gre_tunnel_stack (gre_tunnel_t *gt)
{
    fib_link_t linkt;

    /*
     * find the adjacency that is contributed by the FIB entry
     * that this tunnel resovles via, and use it as the next adj
     * in the midchain
     */
    FOR_EACH_FIB_LINK(linkt)
    {
        if (ADJ_INDEX_INVALID != gt->adj_index[linkt])
        {
	    if (vnet_hw_interface_get_flags(vnet_get_main(),
					    gt->hw_if_index) &
		VNET_HW_INTERFACE_FLAG_LINK_UP)
	    {
		adj_nbr_midchain_stack(
		    gt->adj_index[linkt],
		    fib_entry_contribute_ip_forwarding(gt->fib_entry_index));
	    }
	    else
	    {
		adj_nbr_midchain_unstack(gt->adj_index[linkt]);
	    }
        }
    }
}

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
gre_tunnel_back_walk (fib_node_t *node,
			   fib_node_back_walk_ctx_t *ctx)
{
    gre_tunnel_stack(gre_tunnel_from_fib_node(node));

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
gre_proto_from_fib_link (fib_link_t link)
{
    switch (link)
    {
    case FIB_LINK_IP4:
        return (GRE_PROTOCOL_ip4);
    case FIB_LINK_IP6:
        return (GRE_PROTOCOL_ip6);
    case FIB_LINK_MPLS:
        return (GRE_PROTOCOL_mpls_unicast);
    case FIB_LINK_ETHERNET:
        return (GRE_PROTOCOL_teb);
    }
    ASSERT(0);
    return (GRE_PROTOCOL_ip4);
}

static u8 *
gre_rewrite (gre_tunnel_t * t,
             fib_link_t link)
{
  ip4_and_gre_header_t * h0;
  u8 * rewrite_data = 0;

  vec_validate_init_empty (rewrite_data, sizeof (*h0) - 1, 0);

  h0 = (ip4_and_gre_header_t *) rewrite_data;

  h0->gre.protocol = clib_host_to_net_u16(gre_proto_from_fib_link(link));

  h0->ip4.ip_version_and_header_length = 0x45;
  h0->ip4.ttl = 254;
  h0->ip4.protocol = IP_PROTOCOL_GRE;
  /* $$$ fixup ip4 header length and checksum after-the-fact */
  h0->ip4.src_address.as_u32 = t->tunnel_src.as_u32;
  h0->ip4.dst_address.as_u32 = t->tunnel_dst.as_u32;
  h0->ip4.checksum = ip4_header_checksum (&h0->ip4);

  return (rewrite_data);
}

static void
gre_fixup (vlib_main_t *vm,
	   ip_adjacency_t *adj,
	   vlib_buffer_t *b0)
{
    ip4_header_t * ip0;

    ip0 = vlib_buffer_get_current (b0);

    /* Fixup the checksum and len fields in the GRE tunnel encap
     * that was applied at the midchain node */
    ip0->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
    ip0->checksum = ip4_header_checksum (ip0);
}

static int 
vnet_gre_tunnel_add (vnet_gre_add_del_tunnel_args_t *a,
                     u32 * sw_if_indexp)
{
  gre_main_t * gm = &gre_main;
  vnet_main_t * vnm = gm->vnet_main;
  ip4_main_t * im = &ip4_main;
  gre_tunnel_t * t;
  vnet_hw_interface_t * hi;
  u32 hw_if_index, sw_if_index;
  u32 outer_fib_index;
  u8 address[6];
  clib_error_t *error;
  fib_link_t linkt;
  u8 *rewrite;

  outer_fib_index = ip4_fib_index_from_table_id(a->outer_fib_id);

  if (~0 == outer_fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  t = gre_tunnel_db_find(&a->src, &a->dst, a->outer_fib_id);

  if (NULL != t)
    return VNET_API_ERROR_INVALID_VALUE;

  pool_get_aligned (gm->tunnels, t, CLIB_CACHE_LINE_BYTES);
  memset (t, 0, sizeof (*t));
  fib_node_init(&t->node, FIB_NODE_TYPE_GRE_TUNNEL);
  FOR_EACH_FIB_LINK(linkt)
  {
      t->adj_index[linkt] = ADJ_INDEX_INVALID;
  }

  if (vec_len (gm->free_gre_tunnel_hw_if_indices) > 0) {
      vnet_interface_main_t * im = &vnm->interface_main;

      hw_if_index = gm->free_gre_tunnel_hw_if_indices
          [vec_len (gm->free_gre_tunnel_hw_if_indices)-1];
      _vec_len (gm->free_gre_tunnel_hw_if_indices) -= 1;

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
      if (a->teb)
      {
	t->l2_tx_arc = vlib_node_add_named_next(vlib_get_main(),
						hi->tx_node_index,
						"adj-l2-midchain");
      }
    } else {
      if (a->teb)
      {
        /* Default MAC address (d00b:eed0:0000 + sw_if_index) */
        memset (address, 0, sizeof (address));
        address[0] = 0xd0;
        address[1] = 0x0b;
        address[2] = 0xee;
        address[3] = 0xd0;
        address[4] = t - gm->tunnels;

        error = ethernet_register_interface
          (vnm,
           gre_l2_device_class.index, t - gm->tunnels, address, &hw_if_index,
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
	hw_if_index = vnet_register_interface
	    (vnm, gre_device_class.index, t - gm->tunnels,
	     gre_hw_interface_class.index,
	     t - gm->tunnels);
      }
      hi = vnet_get_hw_interface (vnm, hw_if_index);
      sw_if_index = hi->sw_if_index;
    }

  t->hw_if_index = hw_if_index;
  t->outer_fib_index = outer_fib_index;
  t->sw_if_index = sw_if_index;
  t->teb = a->teb;

  vec_validate_init_empty (gm->tunnel_index_by_sw_if_index, sw_if_index, ~0);
  gm->tunnel_index_by_sw_if_index[sw_if_index] = t - gm->tunnels;

  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
  im->fib_index_by_sw_if_index[sw_if_index] = t->outer_fib_index;
  ip4_sw_interface_enable_disable(sw_if_index, 1);

  hi->min_packet_bytes = 64 + sizeof (gre_header_t) + sizeof (ip4_header_t);
  hi->per_packet_overhead_bytes =
      /* preamble */ 8 + /* inter frame gap */ 12;

  /* Standard default gre MTU. */
  hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] = 9000;

  clib_memcpy (&t->tunnel_src, &a->src, sizeof (t->tunnel_src));
  clib_memcpy (&t->tunnel_dst, &a->dst, sizeof (t->tunnel_dst));

  gre_tunnel_db_add(t);

  /*
   * source the FIB entry for the tunnel's destination
   * and become a child thereof. The tunnel will then get poked
   * when the forwarding for the entry updates, and the tunnel can
   * re-stack accordingly
   */
  const fib_prefix_t tun_dst_pfx = {
      .fp_len = 32,
      .fp_proto = FIB_PROTOCOL_IP4,
      .fp_addr = {
          .ip4 = t->tunnel_dst,
      }
  };

  t->fib_entry_index =
      fib_table_entry_special_add(outer_fib_index,
                                  &tun_dst_pfx,
                                  FIB_SOURCE_RR,
                                  FIB_ENTRY_FLAG_NONE,
                                  ADJ_INDEX_INVALID);
  t->sibling_index =
      fib_entry_child_add(t->fib_entry_index,
                          FIB_NODE_TYPE_GRE_TUNNEL,
                          t - gm->tunnels);

  /*
   * create and update the midchain adj this tunnel sources.
   * We could be smarter here and trigger this on an interface proto enable,
   * like we do for MPLS.
   */
  if (t->teb)
  {
      t->adj_index[FIB_LINK_ETHERNET] = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
							    FIB_LINK_ETHERNET,
							    &zero_addr,
							    sw_if_index);

      rewrite = gre_rewrite(t, FIB_LINK_ETHERNET);
      adj_nbr_midchain_update_rewrite(t->adj_index[FIB_LINK_ETHERNET],
				      gre_fixup,
				      ADJ_MIDCHAIN_FLAG_NO_COUNT,
				      rewrite);
      vec_free(rewrite);
  }
  else
  {
      FOR_EACH_FIB_IP_LINK (linkt)
      {
	  t->adj_index[linkt] = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
						    linkt,
						    &zero_addr,
						    sw_if_index);

	  rewrite = gre_rewrite(t, linkt);
	  adj_nbr_midchain_update_rewrite(t->adj_index[linkt],
					  gre_fixup,
					  ADJ_MIDCHAIN_FLAG_NONE,
					  rewrite);
	  vec_free(rewrite);
      }
  }

  t->adj_index[FIB_LINK_MPLS] = ADJ_INDEX_INVALID;

  clib_memcpy (&t->tunnel_src, &a->src, sizeof (t->tunnel_src));
  clib_memcpy (&t->tunnel_dst, &a->dst, sizeof (t->tunnel_dst));
  gre_tunnel_stack(t);

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
  fib_link_t linkt;
  u32 sw_if_index;

  t = gre_tunnel_db_find(&a->src, &a->dst, a->outer_fib_id);

  if (NULL == t)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  sw_if_index = t->sw_if_index;
  vnet_sw_interface_set_flags (vnm, sw_if_index, 0 /* down */);
  /* make sure tunnel is removed from l2 bd or xconnect */
  set_int_l2_mode(gm->vlib_main, vnm, MODE_L3, sw_if_index, 0, 0, 0, 0);
  vec_add1 (gm->free_gre_tunnel_hw_if_indices, t->hw_if_index);
  gm->tunnel_index_by_sw_if_index[sw_if_index] = ~0;
  ip4_sw_interface_enable_disable(sw_if_index, 0);

  fib_entry_child_remove(t->fib_entry_index,
                         t->sibling_index);
  fib_table_entry_delete_index(t->fib_entry_index,
                               FIB_SOURCE_RR);

  FOR_EACH_FIB_LINK(linkt)
  {
      adj_unlock(t->adj_index[linkt]);
  }

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

static void
gre_sw_interface_mpls_state_change (u32 sw_if_index,
                                    u32 is_enable)
{
  gre_main_t *gm = &gre_main;
  gre_tunnel_t *t;
  u8 *rewrite;

  if ((vec_len(gm->tunnel_index_by_sw_if_index) < sw_if_index) ||
      (~0 == gm->tunnel_index_by_sw_if_index[sw_if_index]))
      return;

  t = pool_elt_at_index(gm->tunnels,
                        gm->tunnel_index_by_sw_if_index[sw_if_index]);

  if (is_enable)
    {
      t->adj_index[FIB_LINK_MPLS] =
          adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                              FIB_LINK_MPLS,
                              &zero_addr,
                              sw_if_index);

      rewrite = gre_rewrite(t, FIB_LINK_MPLS);
      adj_nbr_midchain_update_rewrite(t->adj_index[FIB_LINK_MPLS],
				      gre_fixup,
				      ADJ_MIDCHAIN_FLAG_NONE,
                                      rewrite);
      vec_free(rewrite);
    }
  else
    {
      adj_unlock(t->adj_index[FIB_LINK_MPLS]);
      t->adj_index[FIB_LINK_MPLS] = ADJ_INDEX_INVALID;
    }

  gre_tunnel_stack(t);
}

static clib_error_t *
create_gre_tunnel_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  vnet_gre_add_del_tunnel_args_t _a, * a = &_a;
  ip4_address_t src, dst;
  u32 outer_fib_id = 0;
  u8 teb = 0;
  int rv;
  u32 num_m_args = 0;
  u8 is_add = 1;
  u32 sw_if_index;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "src %U", unformat_ip4_address, &src))
      num_m_args++;
    else if (unformat (line_input, "dst %U", unformat_ip4_address, &dst))
      num_m_args++;
    else if (unformat (line_input, "outer-fib-id %d", &outer_fib_id))
      ;
    else if (unformat (line_input, "teb"))
      teb = 1;
    else
      return clib_error_return (0, "unknown input `%U'",
                                format_unformat_error, input);
  }
  unformat_free (line_input);

  if (num_m_args < 2)
      return clib_error_return (0, "mandatory argument(s) missing");

  if (memcmp (&src, &dst, sizeof(src)) == 0)
      return clib_error_return (0, "src and dst are identical");

  memset (a, 0, sizeof (*a));
  a->outer_fib_id = outer_fib_id;
  a->teb = teb;
  clib_memcpy(&a->src, &src, sizeof(src));
  clib_memcpy(&a->dst, &dst, sizeof(dst));

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
      return clib_error_return (0, "GRE tunnel already exists...");
    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "outer fib ID %d doesn't exist\n",
                                outer_fib_id);
    default:
      return clib_error_return (0, "vnet_gre_add_del_tunnel returned %d", rv);
    }

  return 0;
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
          vlib_cli_output (vm, "%U", format_gre_tunnel, t, 0);
      }));
    }
  else
  {
      t = pool_elt_at_index(gm->tunnels, ti);

      vlib_cli_output (vm, "%U", format_gre_tunnel, t, 1);
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
  vec_add1(mpls_main.mpls_interface_state_change_callbacks,
           gre_sw_interface_mpls_state_change);

  fib_node_register_type(FIB_NODE_TYPE_GRE_TUNNEL, &gre_vft);

  return 0;
}
VLIB_INIT_FUNCTION(gre_interface_init);
