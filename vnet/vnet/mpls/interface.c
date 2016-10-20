/*
 * interface.c: mpls interfaces
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
#include <vnet/mpls/mpls.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/dpo/classify_dpo.h>

/* manually added to the interface output node */
#define MPLS_ETH_OUTPUT_NEXT_OUTPUT	1

static uword
mpls_eth_interface_tx (vlib_main_t * vm,
                       vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  mpls_main_t * gm = &mpls_main;
  vnet_main_t * vnm = gm->vnet_main;
  u32 next_index;
  u32 * from, * to_next, n_left_from, n_left_to_next;

  /* Vector of buffer / pkt indices we're supposed to process */
  from = vlib_frame_vector_args (frame);

  /* Number of buffers / pkts */
  n_left_from = frame->n_vectors;   

  /* Speculatively send the first buffer to the last disposition we used */
  next_index = node->cached_next_index;
  
  while (n_left_from > 0)
    {
      /* set up to enqueue to our disposition with index = next_index */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* 
       * As long as we have enough pkts left to process two pkts
       * and prefetch two pkts...
       */
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          vlib_buffer_t * b0, * b1;
	  u32 bi0, next0, bi1, next1;
          mpls_eth_tunnel_t * t0, * t1;
          u32 sw_if_index0, sw_if_index1;
          vnet_hw_interface_t * hi0, * hi1;
          u8 * dst0, * dst1;
      
	  /* Prefetch the next iteration */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

            /* 
             * Prefetch packet data. We expect to overwrite
             * the inbound L2 header with an ip header and a
             * gre header. Might want to prefetch the last line
             * of rewrite space as well; need profile data
             */
	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

          /* Pick up the next two buffer indices */
	  bi0 = from[0];
	  bi1 = from[1];

          /* Speculatively enqueue them where we sent the last buffer */
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;
      
	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index [VLIB_TX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index [VLIB_TX];

          /* get h/w intfcs */
          hi0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);
          hi1 = vnet_get_sup_hw_interface (vnm, sw_if_index1);
          
          /* hw_instance = tunnel pool index */
          t0 = pool_elt_at_index (gm->eth_tunnels, hi0->hw_instance);
          t1 = pool_elt_at_index (gm->eth_tunnels, hi1->hw_instance);

          /* Apply rewrite - $$$$$ fixme don't use memcpy */
          vlib_buffer_advance (b0, -(word)vec_len(t0->rewrite_data));
          vlib_buffer_advance (b1, -(word)vec_len(t1->rewrite_data));

          dst0 = vlib_buffer_get_current (b0);
          dst1 = vlib_buffer_get_current (b1);

          clib_memcpy (dst0, t0->rewrite_data, vec_len(t0->rewrite_data));
          clib_memcpy (dst1, t1->rewrite_data, vec_len(t1->rewrite_data));

          /* Fix TX fib indices */
          vnet_buffer(b0)->sw_if_index [VLIB_TX] = t0->tx_sw_if_index;
          vnet_buffer(b1)->sw_if_index [VLIB_TX] = t1->tx_sw_if_index;

          /* mpls-post-rewrite takes it from here... */
          next0 = MPLS_ETH_OUTPUT_NEXT_OUTPUT;
          next1 = MPLS_ETH_OUTPUT_NEXT_OUTPUT;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              mpls_eth_tx_trace_t *tr = vlib_add_trace (vm, node, 
                                                        b0, sizeof (*tr));
              tr->lookup_miss = 0;
              tr->tunnel_id = t0 - gm->eth_tunnels;
              tr->tx_sw_if_index = t0->tx_sw_if_index;
              tr->mpls_encap_index = t0->encap_index;
              tr->length = b0->current_length;
              hi0 = vnet_get_sup_hw_interface (vnm, t0->tx_sw_if_index);
              clib_memcpy (tr->dst, hi0->hw_address, sizeof (tr->dst));
            }
          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              mpls_eth_tx_trace_t *tr = vlib_add_trace (vm, node, 
                                                        b1, sizeof (*tr));
              tr->lookup_miss = 0;
              tr->tunnel_id = t1 - gm->eth_tunnels;
              tr->tx_sw_if_index = t1->tx_sw_if_index;
              tr->mpls_encap_index = t1->encap_index;
              tr->length = b1->current_length;
              hi1 = vnet_get_sup_hw_interface (vnm, t1->tx_sw_if_index);
              clib_memcpy (tr->dst, hi1->hw_address, sizeof (tr->dst));
            }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
      while (n_left_from > 0 && n_left_to_next > 0)
	{
          vlib_buffer_t * b0;
          u32 bi0, next0;
          mpls_eth_tunnel_t * t0;
          u32 sw_if_index0;
          vnet_hw_interface_t * hi0;
          u8 * dst0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index [VLIB_TX];

          hi0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);
          
          t0 = pool_elt_at_index (gm->eth_tunnels, hi0->hw_instance);

          /* Apply rewrite - $$$$$ fixme don't use memcpy */
          vlib_buffer_advance (b0, -(word)vec_len(t0->rewrite_data));

          dst0 = vlib_buffer_get_current (b0);

          clib_memcpy (dst0, t0->rewrite_data, vec_len(t0->rewrite_data));

          /* Fix the TX interface */
          vnet_buffer(b0)->sw_if_index [VLIB_TX] = t0->tx_sw_if_index;

          /* Send the packet */
          next0 = MPLS_ETH_OUTPUT_NEXT_OUTPUT;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              mpls_eth_tx_trace_t *tr = vlib_add_trace (vm, node, 
                                                        b0, sizeof (*tr));
              tr->lookup_miss = 0;
              tr->tunnel_id = t0 - gm->eth_tunnels;
              tr->tx_sw_if_index = t0->tx_sw_if_index;
              tr->mpls_encap_index = t0->encap_index;
              tr->length = b0->current_length;
              hi0 = vnet_get_sup_hw_interface (vnm, t0->tx_sw_if_index);
              clib_memcpy (tr->dst, hi0->hw_address, sizeof (tr->dst));
            }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
  
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, mpls_input_node.index,
                               MPLS_ERROR_PKTS_ENCAP, frame->n_vectors);

  return frame->n_vectors;
}

static u8 * format_mpls_eth_tunnel_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "mpls-eth%d", dev_instance);
}

static u8 * format_mpls_eth_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);

  s = format (s, "MPLS-ETH tunnel: id %d\n", dev_instance);
  return s;
}

VNET_DEVICE_CLASS (mpls_eth_device_class) = {
  .name = "MPLS-ETH tunnel device",
  .format_device_name = format_mpls_eth_tunnel_name,
  .format_device = format_mpls_eth_device,
  .format_tx_trace = format_mpls_eth_tx_trace,
  .tx_function = mpls_eth_interface_tx,
  .no_flatten_output_chains = 1,
#ifdef SOON
  .clear counter = 0;
  .admin_up_down_function = 0;
#endif
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (mpls_eth_device_class,
				   mpls_eth_interface_tx)

VNET_HW_INTERFACE_CLASS (mpls_eth_hw_interface_class) = {
  .name = "MPLS-ETH",
  .format_header = format_mpls_eth_header_with_length,
#if 0
  .unformat_header = unformat_mpls_eth_header,
#endif
  .build_rewrite = default_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

u8
mpls_sw_interface_is_enabled (u32 sw_if_index)
{
    mpls_main_t * mm = &mpls_main;

    if (vec_len(mm->mpls_enabled_by_sw_if_index) < sw_if_index)
        return (0);

    return (mm->mpls_enabled_by_sw_if_index[sw_if_index]);
}

void
mpls_sw_interface_enable_disable (mpls_main_t * mm,
                                  u32 sw_if_index,
                                  u8 is_enable)
{
  vlib_main_t * vm = vlib_get_main();
  ip_config_main_t * cm = &mm->feature_config_mains[VNET_IP_RX_UNICAST_FEAT];
  vnet_config_main_t * vcm = &cm->config_main;
  u32 lookup_feature_index;
  fib_node_index_t lfib_index;
  u32 ci;

  vec_validate_init_empty (mm->mpls_enabled_by_sw_if_index, sw_if_index, 0);

  /*
   * enable/disable only on the 1<->0 transition
   */
  if (is_enable)
    {
      if (1 != ++mm->mpls_enabled_by_sw_if_index[sw_if_index])
        return;

      lfib_index = fib_table_find_or_create_and_lock(FIB_PROTOCOL_MPLS,
						     MPLS_FIB_DEFAULT_TABLE_ID);
      vec_validate(mm->fib_index_by_sw_if_index, 0);
      mm->fib_index_by_sw_if_index[sw_if_index] = lfib_index;
    }
  else
    {
      ASSERT(mm->mpls_enabled_by_sw_if_index[sw_if_index] > 0);
      if (0 != --mm->mpls_enabled_by_sw_if_index[sw_if_index])
        return;

      fib_table_unlock(mm->fib_index_by_sw_if_index[sw_if_index],
		       FIB_PROTOCOL_MPLS);
    }

  vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
  ci = cm->config_index_by_sw_if_index[sw_if_index];

  lookup_feature_index = mm->mpls_rx_feature_lookup;

  if (is_enable)
    ci = vnet_config_add_feature (vm, vcm,
                                  ci,
                                  lookup_feature_index,
                                  /* config data */ 0,
                                  /* # bytes of config data */ 0);
  else
    ci = vnet_config_del_feature (vm, vcm, ci,
                                  lookup_feature_index,
                                  /* config data */ 0,
                                  /* # bytes of config data */ 0);

  cm->config_index_by_sw_if_index[sw_if_index] = ci;
}

u8 * format_mpls_encap_index (u8 * s, va_list * args)
{
  mpls_main_t * mm = va_arg (*args, mpls_main_t *);
  u32 entry_index = va_arg (*args, u32);
  mpls_encap_t * e;
  int i;

  e = pool_elt_at_index (mm->encaps, entry_index);
  
  for (i = 0; i < vec_len (e->labels); i++)
    s = format 
        (s, "%d ", vnet_mpls_uc_get_label(clib_net_to_host_u32 
                                          (e->labels[i].label_exp_s_ttl)));

  return s;
}

u8 * format_mpls_ethernet_tunnel (u8 * s, va_list * args)
{
  mpls_eth_tunnel_t * t = va_arg (*args, mpls_eth_tunnel_t *);
  mpls_main_t * mm = &mpls_main;
  
  s = format (s, "[%d]: dst %U, adj %U/%d, labels %U\n",
              t - mm->eth_tunnels, 
              format_ethernet_address, &t->tunnel_dst,
              format_ip4_address, &t->intfc_address,
              t->mask_width, 
              format_mpls_encap_index, mm, t->encap_index);


  s = format (s, "      tx on %U, rx fib index %d", 
              format_vnet_sw_if_index_name, mm->vnet_main, t->tx_sw_if_index,
              t->inner_fib_index);

  return s;
}

static clib_error_t *
show_mpls_tunnel_command_fn (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  mpls_main_t * mm = &mpls_main;
  mpls_eth_tunnel_t * et;

  if (pool_elts (mm->eth_tunnels))
    {
      vlib_cli_output (vm, "MPLS-Ethernet tunnels");
      pool_foreach (et, mm->eth_tunnels,
      ({
        vlib_cli_output (vm, "%U", format_mpls_ethernet_tunnel, et);
      }));
    }
  else
    vlib_cli_output (vm, "No MPLS-Ethernet tunnels");

  return 0;
}

VLIB_CLI_COMMAND (show_mpls_tunnel_command, static) = {
    .path = "show mpls tunnel",
    .short_help = "show mpls tunnel",
    .function = show_mpls_tunnel_command_fn,
};


/* force inclusion from application's main.c */
clib_error_t *mpls_interface_init (vlib_main_t *vm)
{
  clib_error_t * error;

  if ((error = vlib_call_init_function (vm, mpls_policy_encap_init)))
      return error;

  return 0;
}
VLIB_INIT_FUNCTION(mpls_interface_init);


static u8 * mpls_ethernet_rewrite (mpls_main_t *mm, mpls_eth_tunnel_t * t)
{
  u8 * rewrite_data = 0;
  mpls_encap_t * e;
  mpls_unicast_header_t *lp0;
  int i;

 /* look up the encap label stack using the RX FIB and adjacency address*/
  e = mpls_encap_by_fib_and_dest (mm, t->inner_fib_index, 
                                  t->intfc_address.as_u32);

  if (e == 0)
    {
      clib_warning ("no label for inner fib index %d, dst %U",
                    t->inner_fib_index, format_ip4_address, 
                    &t->intfc_address);
      return 0;
    }
 
  vec_validate (rewrite_data, 
                sizeof (mpls_unicast_header_t) * vec_len(e->labels) -1);

  /* Copy the encap label stack */
  lp0 = (mpls_unicast_header_t *) rewrite_data;
  
  for (i = 0; i < vec_len(e->labels); i++)
    lp0[i] = e->labels[i];
  
  return (rewrite_data);
}

int vnet_mpls_ethernet_add_del_tunnel (u8 *dst,
                                       ip4_address_t *intfc,
                                       u32 mask_width,
                                       u32 inner_fib_id, 
                                       u32 tx_sw_if_index,
                                       u32 * tunnel_sw_if_index,
                                       u8 l2_only,
                                       u8 is_add)
{
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  mpls_main_t * mm = &mpls_main;
  vnet_main_t * vnm = vnet_get_main();
  mpls_eth_tunnel_t *tp;
  u32 inner_fib_index = 0;
  ip_adjacency_t adj;
  u32 adj_index;
  u8 * rewrite_data;
  int found_tunnel = 0;
  mpls_encap_t * e = 0;
  u32 hw_if_index = ~0;
  vnet_hw_interface_t * hi;
  u32 slot;
  u32 dummy;
  
  if (tunnel_sw_if_index == 0)
    tunnel_sw_if_index = &dummy;

  *tunnel_sw_if_index = ~0;

  if (inner_fib_id != (u32)~0)
    {
      uword * p;
      
      p = hash_get (im->fib_index_by_table_id, inner_fib_id);
      if (! p)
        return VNET_API_ERROR_NO_SUCH_FIB;
      inner_fib_index = p[0];
    }

  /* suppress duplicate mpls interface generation. */
  pool_foreach (tp, mm->eth_tunnels, 
  ({
    /* 
     * If we have a tunnel which matches (src, dst, intfc/mask)
     * AND the expected route is in the FIB, it's a dup 
     */
    if (!memcmp (&tp->tunnel_dst, dst, sizeof (*dst))
        && !memcmp (&tp->intfc_address, intfc, sizeof (*intfc))
        && tp->inner_fib_index == inner_fib_index
	&& FIB_NODE_INDEX_INVALID != tp->fei)
      {
        found_tunnel = 1;

        if (is_add)
          {
            if (l2_only)
              return 1;
            else
              {
                e = mpls_encap_by_fib_and_dest (mm, inner_fib_index, 
                                                intfc->as_u32);
                if (e == 0)
                  return VNET_API_ERROR_NO_SUCH_LABEL;
                
                goto reinstall_it;
              }
          }
        else
          {
            /* Delete */
            goto add_del_route;
          }

      }
  }));
    
  /* Delete, and we can't find the tunnel */
  if (is_add == 0 && found_tunnel == 0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  e = mpls_encap_by_fib_and_dest (mm, inner_fib_index, intfc->as_u32);
  if (e == 0)
    return VNET_API_ERROR_NO_SUCH_LABEL;

  pool_get(mm->eth_tunnels, tp);
  memset (tp, 0, sizeof (*tp));
    
  if (vec_len (mm->free_eth_sw_if_indices) > 0)
    {
      hw_if_index = 
        mm->free_eth_sw_if_indices[vec_len(mm->free_eth_sw_if_indices)-1];
      _vec_len (mm->free_eth_sw_if_indices) -= 1;
      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->dev_instance = tp - mm->eth_tunnels;
      hi->hw_instance = tp - mm->eth_tunnels;
    }
  else 
    {
      hw_if_index = vnet_register_interface
        (vnm, mpls_eth_device_class.index, tp - mm->eth_tunnels,
         mpls_eth_hw_interface_class.index,
         tp - mm->eth_tunnels);
      hi = vnet_get_hw_interface (vnm, hw_if_index);

      /* ... to make the IP and L2 x-connect cases identical */
      slot = vlib_node_add_named_next_with_slot
        (vnm->vlib_main, hi->tx_node_index, 
         "interface-output", MPLS_ETH_OUTPUT_NEXT_OUTPUT);

      ASSERT (slot == MPLS_ETH_OUTPUT_NEXT_OUTPUT);
    }
  
  *tunnel_sw_if_index = hi->sw_if_index;
  vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 
                               VNET_SW_INTERFACE_FLAG_ADMIN_UP);      

  tp->hw_if_index = hw_if_index;

 reinstall_it:
  clib_memcpy(tp->tunnel_dst, dst, sizeof (tp->tunnel_dst));
  tp->intfc_address.as_u32 = intfc->as_u32;
  tp->mask_width = mask_width;
  tp->inner_fib_index = inner_fib_index;
  tp->encap_index = e - mm->encaps;
  tp->tx_sw_if_index = tx_sw_if_index;
  tp->l2_only = l2_only;

  /* Create the adjacency and add to v4 fib */
  memset(&adj, 0, sizeof (adj));
  adj.lookup_next_index = IP_LOOKUP_NEXT_REWRITE;
    
  rewrite_data = mpls_ethernet_rewrite (mm, tp);
  if (rewrite_data == 0)
    {
      if (*tunnel_sw_if_index != ~0)
        {
          hi = vnet_get_hw_interface (vnm, tp->hw_if_index);
          vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 
                                       0 /* admin down */);
          vec_add1 (mm->free_eth_sw_if_indices, tp->hw_if_index);
      }

      pool_put (mm->eth_tunnels, tp);
      return VNET_API_ERROR_NO_SUCH_LABEL;
    }
  
  vnet_rewrite_for_sw_interface
    (vnm,
     VNET_LINK_MPLS, 
     tx_sw_if_index,
     ip4_rewrite_node.index,
     tp->tunnel_dst,
     &adj.rewrite_header,
     sizeof (adj.rewrite_data));
  
  /* 
   * Prepend the (0,1,2) VLAN tag ethernet header 
   * we just built to the mpls header stack
   */
  vec_insert (rewrite_data, adj.rewrite_header.data_bytes, 0);
  clib_memcpy(rewrite_data, 
         vnet_rewrite_get_data_internal(&adj.rewrite_header, 
                                        sizeof (adj.rewrite_data)),
         adj.rewrite_header.data_bytes);

  vnet_rewrite_set_data_internal (&adj.rewrite_header, 
                                  sizeof(adj.rewrite_data),
                                  rewrite_data, 
                                  vec_len(rewrite_data));
  
  vec_free (tp->rewrite_data);
  
  tp->rewrite_data = rewrite_data;

  if (!l2_only)
    ip_add_adjacency (lm, &adj, 1 /* one adj */,
                      &adj_index);
  
 add_del_route:

  if (!l2_only)
    {
      const fib_prefix_t pfx = {
	  .fp_addr = {
	      .ip4 = tp->intfc_address,
	  },
	  .fp_len = tp->mask_width,
	  .fp_proto = FIB_PROTOCOL_IP4,
      };
      if (is_add)
	  tp->fei = fib_table_entry_special_add(tp->inner_fib_index,
						&pfx,
						FIB_SOURCE_API,
						FIB_ENTRY_FLAG_NONE,
						adj_index);
      else
        {
	  fib_table_entry_delete(tp->inner_fib_index, &pfx, FIB_SOURCE_API);
	  tp->fei = FIB_NODE_INDEX_INVALID;
	}
    }
  if (is_add == 0 && found_tunnel)
    {
      hi = vnet_get_hw_interface (vnm, tp->hw_if_index);
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 
                                   0 /* admin down */);
      vec_add1 (mm->free_eth_sw_if_indices, tp->hw_if_index);
      vec_free (tp->rewrite_data);
      pool_put (mm->eth_tunnels, tp);
    }

  return 0;
}

static clib_error_t *
create_mpls_ethernet_tunnel_command_fn (vlib_main_t * vm,
                                        unformat_input_t * input,
                                        vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  vnet_main_t * vnm = vnet_get_main();
  ip4_address_t intfc;
  int adj_set = 0;
  u8 dst[6];
  int dst_set = 0, intfc_set = 0;
  u32 mask_width;
  u32 inner_fib_id = (u32)~0;
  int rv;
  u8 is_del = 0;
  u8 l2_only = 0;
  u32 tx_sw_if_index;
  u32 sw_if_index = ~0;
  
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "dst %U", 
                    unformat_ethernet_address, &dst))
        dst_set = 1;
      else if (unformat (line_input, "adj %U/%d", 
                         unformat_ip4_address, &intfc, &mask_width))
        adj_set = 1;
      else if (unformat (line_input, "tx-intfc %U", 
                         unformat_vnet_sw_interface, vnm, &tx_sw_if_index))
        intfc_set = 1;
      else if (unformat (line_input, "fib-id %d", &inner_fib_id))
        ;
      else if (unformat (line_input, "l2-only"))
        l2_only = 1;
      else if (unformat (line_input, "del"))
        is_del = 1;
      else
        return clib_error_return (0, "unknown input '%U'",
                                  format_unformat_error, line_input);
    }

  if (!intfc_set)
    return clib_error_return (0, "missing tx-intfc");

  if (!dst_set)
    return clib_error_return (0, "missing: dst <ethernet-address>");
          
  if (!adj_set)
    return clib_error_return (0, "missing: intfc <ip-address>/<mask-width>");
  

  rv = vnet_mpls_ethernet_add_del_tunnel (dst, &intfc, mask_width, 
                                          inner_fib_id, tx_sw_if_index, 
                                          &sw_if_index,
                                          l2_only, !is_del);

  switch (rv) 
    {
    case 0:
      if (!is_del)
        vlib_cli_output(vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main(), sw_if_index);
      break;
    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "rx fib ID %d doesn't exist\n",
                                inner_fib_id);

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "tunnel not found\n");

    case VNET_API_ERROR_NO_SUCH_LABEL:
      /* 
       * This happens when there's no MPLS label for the dst address
       * no need for two error messages.
       */
        return clib_error_return (0, "no label for %U in fib %d", 
                                  format_ip4_address, &intfc, inner_fib_id);
      break;
      
    default:
      return clib_error_return (0, "vnet_mpls_ethernet_add_del_tunnel returned %d", rv);
      break;
    }
  return 0;
}


VLIB_CLI_COMMAND (create_mpls_ethernet_tunnel_command, static) = {
  .path = "create mpls ethernet tunnel",
  .short_help = 
  "create mpls ethernet tunnel [del] dst <mac-addr> intfc <addr>/<mw>",
  .function = create_mpls_ethernet_tunnel_command_fn,
};


int vnet_mpls_policy_tunnel_add_rewrite (mpls_main_t * mm, 
                                         mpls_encap_t * e, 
                                         u32 policy_tunnel_index)
{
  mpls_eth_tunnel_t * t;
  ip_adjacency_t adj;
  u8 * rewrite_data = 0;
  u8 * label_start;
  mpls_unicast_header_t *lp;
  int i;

  if (pool_is_free_index (mm->eth_tunnels, policy_tunnel_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  t = pool_elt_at_index (mm->eth_tunnels, policy_tunnel_index);

  memset (&adj, 0, sizeof (adj));

  /* Build L2 encap */
  vnet_rewrite_for_sw_interface
    (mm->vnet_main, 
     VNET_LINK_MPLS, 
     t->tx_sw_if_index,
     mpls_policy_encap_node.index,
     t->tunnel_dst,
     &adj.rewrite_header,
     sizeof (adj.rewrite_data));
  
  vec_validate (rewrite_data, adj.rewrite_header.data_bytes -1);

  clib_memcpy(rewrite_data, 
         vnet_rewrite_get_data_internal(&adj.rewrite_header, 
                                        sizeof (adj.rewrite_data)),
         adj.rewrite_header.data_bytes);

  /* Append the label stack */

  vec_add2 (rewrite_data, label_start, vec_len(e->labels) * sizeof (u32));

  lp = (mpls_unicast_header_t *) label_start;

  for (i = 0; i < vec_len(e->labels); i++)
    lp[i] = e->labels[i];
  
  /* Remember the rewrite data */
  e->rewrite = rewrite_data;
  e->output_next_index = adj.rewrite_header.next_index;

  return 0;
}

int vnet_mpls_ethernet_add_del_policy_tunnel (u8 *dst,
                                              ip4_address_t *intfc,
                                              u32 mask_width,
                                              u32 inner_fib_id, 
                                              u32 tx_sw_if_index,
                                              u32 * tunnel_sw_if_index,
                                              u32 classify_table_index,
                                              u32 * new_tunnel_index,
                                              u8 l2_only,
                                              u8 is_add)
{
  ip4_main_t * im = &ip4_main;
  mpls_main_t * mm = &mpls_main;
  vnet_main_t * vnm = vnet_get_main();
  mpls_eth_tunnel_t *tp;
  u32 inner_fib_index = 0;
  int found_tunnel = 0;
  mpls_encap_t * e = 0;
  u32 hw_if_index = ~0;
  vnet_hw_interface_t * hi;
  u32 slot;
  u32 dummy;
  
  if (tunnel_sw_if_index == 0)
    tunnel_sw_if_index = &dummy;

  *tunnel_sw_if_index = ~0;

  if (inner_fib_id != (u32)~0)
    {
      uword * p;
      
      p = hash_get (im->fib_index_by_table_id, inner_fib_id);
      if (! p)
        return VNET_API_ERROR_NO_SUCH_FIB;
      inner_fib_index = p[0];
    }

  /* suppress duplicate mpls interface generation. */
  pool_foreach (tp, mm->eth_tunnels, 
  ({
    /* 
     * If we have a tunnel which matches (src, dst, intfc/mask)
     * AND the expected route is in the FIB, it's a dup 
     */
    if (!memcmp (&tp->tunnel_dst, dst, sizeof (*dst))
        && !memcmp (&tp->intfc_address, intfc, sizeof (*intfc))
        && tp->inner_fib_index == inner_fib_index
	&& FIB_NODE_INDEX_INVALID != tp->fei)
      {
        found_tunnel = 1;

        if (is_add)
          {
            if (l2_only)
              return 1;
            else
              {
                goto reinstall_it;
              }
          }
        else
          {
            /* Delete */
            goto add_del_route;
          }

      }
  }));
    
  /* Delete, and we can't find the tunnel */
  if (is_add == 0 && found_tunnel == 0)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pool_get(mm->eth_tunnels, tp);
  memset (tp, 0, sizeof (*tp));
    
  if (vec_len (mm->free_eth_sw_if_indices) > 0)
    {
      hw_if_index = 
        mm->free_eth_sw_if_indices[vec_len(mm->free_eth_sw_if_indices)-1];
      _vec_len (mm->free_eth_sw_if_indices) -= 1;
      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->dev_instance = tp - mm->eth_tunnels;
      hi->hw_instance = tp - mm->eth_tunnels;
    }
  else 
    {
      hw_if_index = vnet_register_interface
        (vnm, mpls_eth_device_class.index, tp - mm->eth_tunnels,
         mpls_eth_hw_interface_class.index,
         tp - mm->eth_tunnels);
      hi = vnet_get_hw_interface (vnm, hw_if_index);

      /* ... to make the IP and L2 x-connect cases identical */
      slot = vlib_node_add_named_next_with_slot
        (vnm->vlib_main, hi->tx_node_index, 
         "interface-output", MPLS_ETH_OUTPUT_NEXT_OUTPUT);

      ASSERT (slot == MPLS_ETH_OUTPUT_NEXT_OUTPUT);
    }
  
  *tunnel_sw_if_index = hi->sw_if_index;
  vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 
                               VNET_SW_INTERFACE_FLAG_ADMIN_UP);      

  tp->hw_if_index = hw_if_index;

 reinstall_it:
  clib_memcpy(tp->tunnel_dst, dst, sizeof (tp->tunnel_dst));
  tp->intfc_address.as_u32 = intfc->as_u32;
  tp->mask_width = mask_width;
  tp->inner_fib_index = inner_fib_index;
  tp->encap_index = e - mm->encaps;
  tp->tx_sw_if_index = tx_sw_if_index;
  tp->l2_only = l2_only;
  tp->fei = FIB_NODE_INDEX_INVALID;

  if (new_tunnel_index)
    *new_tunnel_index = tp - mm->eth_tunnels;

 add_del_route:

  if (!l2_only)
    {
      const fib_prefix_t pfx = {
	  .fp_addr = {
	      .ip4 = tp->intfc_address,
	  },
	  .fp_len = tp->mask_width,
	  .fp_proto = FIB_PROTOCOL_IP4,
      };
      dpo_id_t dpo = DPO_INVALID;

      if (is_add)
        {
          dpo_set(&dpo,
                  DPO_CLASSIFY,
                  DPO_PROTO_IP4,
                  classify_dpo_create(FIB_PROTOCOL_IP4,
                                      classify_table_index));

          tp->fei = fib_table_entry_special_dpo_add(tp->inner_fib_index,
                                                    &pfx,
                                                    FIB_SOURCE_API,
                                                    FIB_ENTRY_FLAG_EXCLUSIVE,
                                                    &dpo);
          dpo_reset(&dpo);
        }
      else
        {
	  fib_table_entry_delete(tp->inner_fib_index, &pfx, FIB_SOURCE_API);
	  tp->fei = FIB_NODE_INDEX_INVALID;
	}
    }
  if (is_add == 0 && found_tunnel)
    {
      hi = vnet_get_hw_interface (vnm, tp->hw_if_index);
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 
                                   0 /* admin down */);
      vec_add1 (mm->free_eth_sw_if_indices, tp->hw_if_index);
      pool_put (mm->eth_tunnels, tp);
    }

  return 0;
}

static clib_error_t *
create_mpls_ethernet_policy_tunnel_command_fn (vlib_main_t * vm,
                                               unformat_input_t * input,
                                               vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  vnet_main_t * vnm = vnet_get_main();
  ip4_address_t intfc;
  int adj_set = 0;
  u8 dst[6];
  int dst_set = 0, intfc_set = 0;
  u32 mask_width;
  u32 inner_fib_id = (u32)~0;
  u32 classify_table_index = (u32)~0;
  u32 new_tunnel_index;
  int rv;
  u8 is_del = 0;
  u8 l2_only = 0;
  u32 tx_sw_if_index;
  
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "dst %U", 
                    unformat_ethernet_address, &dst))
        dst_set = 1;
      else if (unformat (line_input, "adj %U/%d", 
                         unformat_ip4_address, &intfc, &mask_width))
        adj_set = 1;
      else if (unformat (line_input, "tx-intfc %U", 
                         unformat_vnet_sw_interface, vnm, &tx_sw_if_index))
        intfc_set = 1;
      else if (unformat (line_input, "classify-table-index %d",
                         &classify_table_index))
        ;
      else if (unformat (line_input, "fib-id %d", &inner_fib_id))
        ;
      else if (unformat (line_input, "l2-only"))
        l2_only = 1;
      else if (unformat (line_input, "del"))
        is_del = 1;
      else
        return clib_error_return (0, "unknown input '%U'",
                                  format_unformat_error, line_input);
    }

  if (classify_table_index == ~0)
    return clib_error_return (0, "missing classify_table_index");

  if (!intfc_set)
    return clib_error_return (0, "missing tx-intfc");

  if (!dst_set)
    return clib_error_return (0, "missing: dst <ethernet-address>");
          
  if (!adj_set)
    return clib_error_return (0, "missing: intfc <ip-address>/<mask-width>");
  

  rv = vnet_mpls_ethernet_add_del_policy_tunnel (dst, &intfc, mask_width, 
                                                 inner_fib_id, tx_sw_if_index, 
                                                 0 /* tunnel sw_if_index */, 
                                                 classify_table_index,
                                                 &new_tunnel_index,
                                                 l2_only, !is_del);
  switch (rv) 
    {
    case 0:
      if (!is_del)
        vlib_cli_output(vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main(), new_tunnel_index);
      break;
    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "rx fib ID %d doesn't exist\n",
                                inner_fib_id);

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "tunnel not found\n");

    case VNET_API_ERROR_NO_SUCH_LABEL:
      /* 
       * This happens when there's no MPLS label for the dst address
       * no need for two error messages.
       */
        return clib_error_return (0, "no label for %U in fib %d", 
                                  format_ip4_address, &intfc, inner_fib_id);
      break;
      
    default:
      return clib_error_return (0, "vnet_mpls_ethernet_add_del_policy_tunnel returned %d", rv);
      break;
    }

  return 0;
}

VLIB_CLI_COMMAND (create_mpls_ethernet_policy_tunnel_command, static) = {
  .path = "create mpls ethernet policy tunnel",
  .short_help = 
  "create mpls ethernet policy tunnel [del] dst <mac-addr> intfc <addr>/<mw>\n"
  " classify-table-index <nn>",
  .function = create_mpls_ethernet_policy_tunnel_command_fn,
};

static clib_error_t *
mpls_interface_enable_disable (vlib_main_t * vm,
                               unformat_input_t * input,
                               vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 sw_if_index, enable;

  sw_if_index = ~0;

  if (! unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (unformat (input, "enable"))
      enable = 1;
  else if (unformat (input, "disable"))
      enable = 0;
  else
    {
      error = clib_error_return (0, "expected 'enable' or 'disable'",
				 format_unformat_error, input);
      goto done;
    }

  mpls_sw_interface_enable_disable(&mpls_main, sw_if_index, enable);

 done:
  return error;
}

VLIB_CLI_COMMAND (set_interface_ip_table_command, static) = {
  .path = "set interface mpls",
  .function = mpls_interface_enable_disable,
  .short_help = "Enable/Disable an interface for MPLS forwarding",
};
