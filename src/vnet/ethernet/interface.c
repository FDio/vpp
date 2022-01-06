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
 * ethernet_interface.c: ethernet interfaces
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

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
//#include <vnet/ethernet/arp.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/ip-neighbor/ip_neighbor.h>

/**
 * @file
 * @brief Loopback Interfaces.
 *
 * This file contains code to manage loopback interfaces.
 */

static const u8 *
ethernet_ip4_mcast_dst_addr (void)
{
  const static u8 ethernet_mcast_dst_mac[] = {
    0x1, 0x0, 0x5e, 0x0, 0x0, 0x0,
  };

  return (ethernet_mcast_dst_mac);
}

static const u8 *
ethernet_ip6_mcast_dst_addr (void)
{
  const static u8 ethernet_mcast_dst_mac[] = {
    0x33, 0x33, 0x00, 0x0, 0x0, 0x0,
  };

  return (ethernet_mcast_dst_mac);
}

/**
 * @brief build a rewrite string to use for sending packets of type 'link_type'
 * to 'dst_address'
 */
u8 *
ethernet_build_rewrite (vnet_main_t * vnm,
			u32 sw_if_index,
			vnet_link_t link_type, const void *dst_address)
{
  vnet_sw_interface_t *sub_sw = vnet_get_sw_interface (vnm, sw_if_index);
  vnet_sw_interface_t *sup_sw = vnet_get_sup_sw_interface (vnm, sw_if_index);
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  ethernet_main_t *em = &ethernet_main;
  ethernet_interface_t *ei;
  ethernet_header_t *h;
  ethernet_type_t type;
  uword n_bytes = sizeof (h[0]);
  u8 *rewrite = NULL;
  u8 is_p2p = 0;

  if ((sub_sw->type == VNET_SW_INTERFACE_TYPE_P2P) ||
      (sub_sw->type == VNET_SW_INTERFACE_TYPE_PIPE))
    is_p2p = 1;
  if (sub_sw != sup_sw)
    {
      if (sub_sw->sub.eth.flags.one_tag)
	{
	  n_bytes += sizeof (ethernet_vlan_header_t);
	}
      else if (sub_sw->sub.eth.flags.two_tags)
	{
	  n_bytes += 2 * (sizeof (ethernet_vlan_header_t));
	}
      else if (PREDICT_FALSE (is_p2p))
	{
	  n_bytes = sizeof (ethernet_header_t);
	}
      if (PREDICT_FALSE (!is_p2p))
	{
	  // Check for encaps that are not supported for L3 interfaces
	  if (!(sub_sw->sub.eth.flags.exact_match) ||
	      (sub_sw->sub.eth.flags.default_sub) ||
	      (sub_sw->sub.eth.flags.outer_vlan_id_any) ||
	      (sub_sw->sub.eth.flags.inner_vlan_id_any))
	    {
	      return 0;
	    }
	}
      else
	{
	  n_bytes = sizeof (ethernet_header_t);
	}
    }

  switch (link_type)
    {
#define _(a,b) case VNET_LINK_##a: type = ETHERNET_TYPE_##b; break
      _(IP4, IP4);
      _(IP6, IP6);
      _(MPLS, MPLS);
      _(ARP, ARP);
#undef _
    default:
      return NULL;
    }

  vec_validate (rewrite, n_bytes - 1);
  h = (ethernet_header_t *) rewrite;
  ei = pool_elt_at_index (em->interfaces, hw->hw_instance);
  clib_memcpy (h->src_address, &ei->address, sizeof (h->src_address));
  if (is_p2p)
    {
      clib_memcpy (h->dst_address, sub_sw->p2p.client_mac,
		   sizeof (h->dst_address));
    }
  else
    {
      if (dst_address)
	clib_memcpy (h->dst_address, dst_address, sizeof (h->dst_address));
      else
	clib_memset (h->dst_address, ~0, sizeof (h->dst_address));	/* broadcast */
    }

  if (PREDICT_FALSE (!is_p2p) && sub_sw->sub.eth.flags.one_tag)
    {
      ethernet_vlan_header_t *outer = (void *) (h + 1);

      h->type = sub_sw->sub.eth.flags.dot1ad ?
	clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD) :
	clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      outer->priority_cfi_and_id =
	clib_host_to_net_u16 (sub_sw->sub.eth.outer_vlan_id);
      outer->type = clib_host_to_net_u16 (type);

    }
  else if (PREDICT_FALSE (!is_p2p) && sub_sw->sub.eth.flags.two_tags)
    {
      ethernet_vlan_header_t *outer = (void *) (h + 1);
      ethernet_vlan_header_t *inner = (void *) (outer + 1);

      h->type = sub_sw->sub.eth.flags.dot1ad ?
	clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD) :
	clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      outer->priority_cfi_and_id =
	clib_host_to_net_u16 (sub_sw->sub.eth.outer_vlan_id);
      outer->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      inner->priority_cfi_and_id =
	clib_host_to_net_u16 (sub_sw->sub.eth.inner_vlan_id);
      inner->type = clib_host_to_net_u16 (type);

    }
  else
    {
      h->type = clib_host_to_net_u16 (type);
    }

  return (rewrite);
}

void
ethernet_update_adjacency (vnet_main_t * vnm, u32 sw_if_index, u32 ai)
{
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);

  if ((si->type == VNET_SW_INTERFACE_TYPE_P2P) ||
      (si->type == VNET_SW_INTERFACE_TYPE_PIPE))
    {
      default_update_adjacency (vnm, sw_if_index, ai);
    }
  else
    {
      ip_adjacency_t *adj;

      adj = adj_get (ai);

      switch (adj->lookup_next_index)
	{
	case IP_LOOKUP_NEXT_GLEAN:
	  adj_glean_update_rewrite (ai);
	  break;
	case IP_LOOKUP_NEXT_ARP:
	case IP_LOOKUP_NEXT_REWRITE:
	  ip_neighbor_update (vnm, ai);
	  break;
	case IP_LOOKUP_NEXT_BCAST:
	  adj_nbr_update_rewrite (ai,
				  ADJ_NBR_REWRITE_FLAG_COMPLETE,
				  ethernet_build_rewrite
				  (vnm,
				   adj->rewrite_header.sw_if_index,
				   adj->ia_link,
				   VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST));
	  break;
	case IP_LOOKUP_NEXT_MCAST:
	  {
	    /*
	     * Construct a partial rewrite from the known ethernet mcast dest MAC
	     */
	    u8 *rewrite;
	    u8 offset;

	    rewrite = ethernet_build_rewrite
	      (vnm,
	       sw_if_index,
	       adj->ia_link,
	       (adj->ia_nh_proto == FIB_PROTOCOL_IP6 ?
		ethernet_ip6_mcast_dst_addr () :
		ethernet_ip4_mcast_dst_addr ()));

	    /*
	     * Complete the remaining fields of the adj's rewrite to direct the
	     * complete of the rewrite at switch time by copying in the IP
	     * dst address's bytes.
	     * Ofset is 2 bytes into the destintation address.
	     */
	    offset = vec_len (rewrite) - 2;
	    adj_mcast_update_rewrite (ai, rewrite, offset);

	    break;
	  }
	case IP_LOOKUP_NEXT_DROP:
	case IP_LOOKUP_NEXT_PUNT:
	case IP_LOOKUP_NEXT_LOCAL:
	case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
	case IP_LOOKUP_NEXT_MIDCHAIN:
	case IP_LOOKUP_NEXT_ICMP_ERROR:
	case IP_LOOKUP_N_NEXT:
	  ASSERT (0);
	  break;
	}
    }
}

static void
ethernet_interface_address_copy (ethernet_interface_address_t * dst,
				 const u8 * mac)
{
  clib_memcpy (&dst->mac, (u8 *) mac, sizeof (dst->mac));
  /*
   * ethernet dataplane loads mac as u64, makes sure the last 2 bytes are 0
   * for comparison purpose
   */
  dst->zero = 0;
}

static void
ethernet_set_mac (vnet_hw_interface_t * hi, ethernet_interface_t * ei,
		  const u8 * mac_address)
{
  vec_validate (hi->hw_address, sizeof (mac_address_t) - 1);
  clib_memcpy (hi->hw_address, mac_address, sizeof (mac_address_t));
  ethernet_interface_address_copy (&ei->address, mac_address);
}

static clib_error_t *
ethernet_mac_change (vnet_hw_interface_t * hi,
		     const u8 * old_address, const u8 * mac_address)
{
  ethernet_interface_t *ei;
  ethernet_main_t *em;

  em = &ethernet_main;
  ei = pool_elt_at_index (em->interfaces, hi->hw_instance);

  ethernet_set_mac (hi, ei, mac_address);

  {
    ethernet_address_change_ctx_t *cb;
    vec_foreach (cb, em->address_change_callbacks)
      cb->function (em, hi->sw_if_index, cb->function_opaque);
  }

  return (NULL);
}

static clib_error_t *
ethernet_set_mtu (vnet_main_t *vnm, vnet_hw_interface_t *hi, u32 mtu)
{
  ethernet_interface_t *ei =
    pool_elt_at_index (ethernet_main.interfaces, hi->hw_instance);

#if 0
  if (ei->cb.set_mtu)
    return ei->cb.set_mtu (vnm, hi, mtu);
#else
  if (ei->cb.set_mtu)
    ei->cb.set_mtu (vnm, hi, mtu);
#endif

  return 0;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (ethernet_hw_interface_class) = {
  .name = "Ethernet",
  .tx_hash_fn_type = VNET_HASH_FN_TYPE_ETHERNET,
  .format_address = format_ethernet_address,
  .format_header = format_ethernet_header_with_length,
  .unformat_hw_address = unformat_ethernet_address,
  .unformat_header = unformat_ethernet_header,
  .build_rewrite = ethernet_build_rewrite,
  .update_adjacency = ethernet_update_adjacency,
  .mac_addr_change_function = ethernet_mac_change,
  .set_mtu = ethernet_set_mtu,
};
/* *INDENT-ON* */

uword
unformat_ethernet_interface (unformat_input_t * input, va_list * args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  u32 *result = va_arg (*args, u32 *);
  u32 hw_if_index;
  ethernet_main_t *em = &ethernet_main;
  ethernet_interface_t *eif;

  if (!unformat_user (input, unformat_vnet_hw_interface, vnm, &hw_if_index))
    return 0;

  eif = ethernet_get_interface (em, hw_if_index);
  if (eif)
    {
      *result = hw_if_index;
      return 1;
    }
  return 0;
}

u32
vnet_eth_register_interface (vnet_main_t *vnm,
			     vnet_eth_interface_registration_t *r)
{
  ethernet_main_t *em = &ethernet_main;
  ethernet_interface_t *ei;
  vnet_hw_interface_t *hi;
  u32 hw_if_index;

  pool_get (em->interfaces, ei);
  clib_memcpy (&ei->cb, &r->cb, sizeof (vnet_eth_if_callbacks_t));

  hw_if_index = vnet_register_interface (
    vnm, r->dev_class_index, r->dev_instance,
    ethernet_hw_interface_class.index, ei - em->interfaces);

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  ethernet_setup_node (vnm->vlib_main, hi->output_node_index);

  hi->min_packet_bytes = hi->min_supported_packet_bytes =
    ETHERNET_MIN_PACKET_BYTES;
  hi->max_supported_packet_bytes = ETHERNET_MAX_PACKET_BYTES;
  hi->max_packet_bytes = em->default_mtu;

  /* Default ethernet MTU, 9000 unless set by ethernet_config see below */
  vnet_sw_interface_set_mtu (vnm, hi->sw_if_index, em->default_mtu);

  ethernet_set_mac (hi, ei, r->address);
  return hw_if_index;
}

void
ethernet_delete_interface (vnet_main_t * vnm, u32 hw_if_index)
{
  ethernet_main_t *em = &ethernet_main;
  ethernet_interface_t *ei;
  vnet_hw_interface_t *hi;
  main_intf_t *main_intf;
  vlan_table_t *vlan_table;
  u32 idx;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  ei = pool_elt_at_index (em->interfaces, hi->hw_instance);

  /* Delete vlan mapping table for dot1q and dot1ad. */
  main_intf = vec_elt_at_index (em->main_intfs, hi->hw_if_index);
  if (main_intf->dot1q_vlans)
    {
      vlan_table = vec_elt_at_index (em->vlan_pool, main_intf->dot1q_vlans);
      for (idx = 0; idx < ETHERNET_N_VLAN; idx++)
	{
	  if (vlan_table->vlans[idx].qinqs)
	    {
	      pool_put_index (em->qinq_pool, vlan_table->vlans[idx].qinqs);
	      vlan_table->vlans[idx].qinqs = 0;
	    }
	}
      pool_put_index (em->vlan_pool, main_intf->dot1q_vlans);
      main_intf->dot1q_vlans = 0;
    }
  if (main_intf->dot1ad_vlans)
    {
      vlan_table = vec_elt_at_index (em->vlan_pool, main_intf->dot1ad_vlans);
      for (idx = 0; idx < ETHERNET_N_VLAN; idx++)
	{
	  if (vlan_table->vlans[idx].qinqs)
	    {
	      pool_put_index (em->qinq_pool, vlan_table->vlans[idx].qinqs);
	      vlan_table->vlans[idx].qinqs = 0;
	    }
	}
      pool_put_index (em->vlan_pool, main_intf->dot1ad_vlans);
      main_intf->dot1ad_vlans = 0;
    }

  vnet_delete_hw_interface (vnm, hw_if_index);
  pool_put (em->interfaces, ei);
}

u32
ethernet_set_flags (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  ethernet_main_t *em = &ethernet_main;
  vnet_hw_interface_t *hi;
  ethernet_interface_t *ei;
  u32 opn_flags = flags & ETHERNET_INTERFACE_FLAGS_SET_OPN_MASK;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  ASSERT (hi->hw_class_index == ethernet_hw_interface_class.index);

  ei = pool_elt_at_index (em->interfaces, hi->hw_instance);

  /* preserve status bits and update last set operation bits */
  ei->flags = (ei->flags & ETHERNET_INTERFACE_FLAGS_STATUS_MASK) | opn_flags;

  if (ei->cb.flag_change)
    {
      switch (opn_flags)
	{
	case ETHERNET_INTERFACE_FLAG_DEFAULT_L3:
	  if (hi->caps & VNET_HW_IF_CAP_MAC_FILTER)
	    {
	      if (ei->cb.flag_change (vnm, hi, opn_flags) != ~0)
		{
		  ei->flags |= ETHERNET_INTERFACE_FLAG_STATUS_L3;
		  return 0;
		}
	      ei->flags &= ~ETHERNET_INTERFACE_FLAG_STATUS_L3;
	      return ~0;
	    }
	  /* fall through */
	case ETHERNET_INTERFACE_FLAG_ACCEPT_ALL:
	  ei->flags &= ~ETHERNET_INTERFACE_FLAG_STATUS_L3;
	  /* fall through */
	default:
	  return ~0;
	}
    }
  return ~0;
}

/**
 * Echo packets back to ethernet/l2-input.
 */
static uword
simulated_ethernet_interface_tx (vlib_main_t * vm,
				 vlib_node_runtime_t *
				 node, vlib_frame_t * frame)
{
  u32 n_left_from, *from;
  u32 next_index = 0;
  u32 n_bytes;
  u32 thread_index = vm->thread_index;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  l2_input_config_t *config;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 new_rx_sw_if_index = ~0;
  u32 new_tx_sw_if_index = ~0;

  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  /* Ordinarily, this is the only config lookup. */
  config = l2input_intf_config (vnet_buffer (b[0])->sw_if_index[VLIB_TX]);
  next_index = (l2_input_is_bridge (config) ?
		VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT :
		VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT);
  new_tx_sw_if_index = l2_input_is_bvi (config) ? L2INPUT_BVI : ~0;
  new_rx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];

  while (n_left_from >= 4)
    {
      u32 sw_if_index0, sw_if_index1, sw_if_index2, sw_if_index3;
      u32 not_all_match_config;

      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left_from >= 8))
	{
	  vlib_prefetch_buffer_header (b[4], STORE);
	  vlib_prefetch_buffer_header (b[5], STORE);
	  vlib_prefetch_buffer_header (b[6], STORE);
	  vlib_prefetch_buffer_header (b[7], STORE);
	}

      /* Make sure all pkts were transmitted on the same (loop) intfc */
      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
      sw_if_index1 = vnet_buffer (b[1])->sw_if_index[VLIB_TX];
      sw_if_index2 = vnet_buffer (b[2])->sw_if_index[VLIB_TX];
      sw_if_index3 = vnet_buffer (b[3])->sw_if_index[VLIB_TX];

      not_all_match_config = (sw_if_index0 ^ sw_if_index1)
	^ (sw_if_index2 ^ sw_if_index3);
      not_all_match_config += sw_if_index0 ^ new_rx_sw_if_index;

      /* Speed path / expected case: all pkts on the same intfc */
      if (PREDICT_TRUE (not_all_match_config == 0))
	{
	  next[0] = next_index;
	  next[1] = next_index;
	  next[2] = next_index;
	  next[3] = next_index;
	  vnet_buffer (b[0])->sw_if_index[VLIB_RX] = new_rx_sw_if_index;
	  vnet_buffer (b[1])->sw_if_index[VLIB_RX] = new_rx_sw_if_index;
	  vnet_buffer (b[2])->sw_if_index[VLIB_RX] = new_rx_sw_if_index;
	  vnet_buffer (b[3])->sw_if_index[VLIB_RX] = new_rx_sw_if_index;
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = new_tx_sw_if_index;
	  vnet_buffer (b[1])->sw_if_index[VLIB_TX] = new_tx_sw_if_index;
	  vnet_buffer (b[2])->sw_if_index[VLIB_TX] = new_tx_sw_if_index;
	  vnet_buffer (b[3])->sw_if_index[VLIB_TX] = new_tx_sw_if_index;
	  n_bytes = vlib_buffer_length_in_chain (vm, b[0]);
	  n_bytes += vlib_buffer_length_in_chain (vm, b[1]);
	  n_bytes += vlib_buffer_length_in_chain (vm, b[2]);
	  n_bytes += vlib_buffer_length_in_chain (vm, b[3]);

	  if (next_index == VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT)
	    {
	      vnet_update_l2_len (b[0]);
	      vnet_update_l2_len (b[1]);
	      vnet_update_l2_len (b[2]);
	      vnet_update_l2_len (b[3]);
	    }

	  /* increment TX interface stat */
	  vlib_increment_combined_counter (im->combined_sw_if_counters +
					   VNET_INTERFACE_COUNTER_TX,
					   thread_index, new_rx_sw_if_index,
					   4 /* pkts */ , n_bytes);
	  b += 4;
	  next += 4;
	  n_left_from -= 4;
	  continue;
	}

      /*
       * Slow path: we know that at least one of the pkts
       * was transmitted on a different sw_if_index, so
       * check each sw_if_index against the cached data and proceed
       * accordingly.
       *
       * This shouldn't happen, but code can (and does) bypass the
       * per-interface output node, so deal with it.
       */
      if (PREDICT_FALSE (vnet_buffer (b[0])->sw_if_index[VLIB_TX]
			 != new_rx_sw_if_index))
	{
	  config = l2input_intf_config
	    (vnet_buffer (b[0])->sw_if_index[VLIB_TX]);
	  next_index = (l2_input_is_bridge (config) ?
			VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT :
			VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT);
	  new_tx_sw_if_index = l2_input_is_bvi (config) ? L2INPUT_BVI : ~0;
	  new_rx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	}
      next[0] = next_index;
      vnet_buffer (b[0])->sw_if_index[VLIB_RX] = new_rx_sw_if_index;
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = new_tx_sw_if_index;
      n_bytes = vlib_buffer_length_in_chain (vm, b[0]);
      if (next_index == VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT)
	vnet_update_l2_len (b[0]);

      vlib_increment_combined_counter (im->combined_sw_if_counters +
				       VNET_INTERFACE_COUNTER_TX,
				       thread_index, new_rx_sw_if_index,
				       1 /* pkts */ , n_bytes);

      if (PREDICT_FALSE (vnet_buffer (b[1])->sw_if_index[VLIB_TX]
			 != new_rx_sw_if_index))
	{
	  config = l2input_intf_config
	    (vnet_buffer (b[1])->sw_if_index[VLIB_TX]);
	  next_index = (l2_input_is_bridge (config) ?
			VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT :
			VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT);
	  new_rx_sw_if_index = vnet_buffer (b[1])->sw_if_index[VLIB_TX];
	  new_tx_sw_if_index = l2_input_is_bvi (config) ? L2INPUT_BVI : ~0;
	}
      next[1] = next_index;
      vnet_buffer (b[1])->sw_if_index[VLIB_RX] = new_rx_sw_if_index;
      vnet_buffer (b[1])->sw_if_index[VLIB_TX] = new_tx_sw_if_index;
      n_bytes = vlib_buffer_length_in_chain (vm, b[1]);
      if (next_index == VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT)
	vnet_update_l2_len (b[1]);

      vlib_increment_combined_counter (im->combined_sw_if_counters +
				       VNET_INTERFACE_COUNTER_TX,
				       thread_index, new_rx_sw_if_index,
				       1 /* pkts */ , n_bytes);

      if (PREDICT_FALSE (vnet_buffer (b[2])->sw_if_index[VLIB_TX]
			 != new_rx_sw_if_index))
	{
	  config = l2input_intf_config
	    (vnet_buffer (b[2])->sw_if_index[VLIB_TX]);
	  next_index = (l2_input_is_bridge (config) ?
			VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT :
			VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT);
	  new_rx_sw_if_index = vnet_buffer (b[2])->sw_if_index[VLIB_TX];
	  new_tx_sw_if_index = l2_input_is_bvi (config) ? L2INPUT_BVI : ~0;
	}
      next[2] = next_index;
      vnet_buffer (b[2])->sw_if_index[VLIB_RX] = new_rx_sw_if_index;
      vnet_buffer (b[2])->sw_if_index[VLIB_TX] = new_tx_sw_if_index;
      n_bytes = vlib_buffer_length_in_chain (vm, b[2]);
      if (next_index == VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT)
	vnet_update_l2_len (b[2]);

      vlib_increment_combined_counter (im->combined_sw_if_counters +
				       VNET_INTERFACE_COUNTER_TX,
				       thread_index, new_rx_sw_if_index,
				       1 /* pkts */ , n_bytes);

      if (PREDICT_FALSE (vnet_buffer (b[3])->sw_if_index[VLIB_TX]
			 != new_rx_sw_if_index))
	{
	  config = l2input_intf_config
	    (vnet_buffer (b[3])->sw_if_index[VLIB_TX]);
	  next_index = (l2_input_is_bridge (config) ?
			VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT :
			VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT);
	  new_rx_sw_if_index = vnet_buffer (b[3])->sw_if_index[VLIB_TX];
	  new_tx_sw_if_index = l2_input_is_bvi (config) ? L2INPUT_BVI : ~0;
	}
      next[3] = next_index;
      vnet_buffer (b[3])->sw_if_index[VLIB_RX] = new_rx_sw_if_index;
      vnet_buffer (b[3])->sw_if_index[VLIB_TX] = new_tx_sw_if_index;
      n_bytes = vlib_buffer_length_in_chain (vm, b[3]);
      if (next_index == VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT)
	vnet_update_l2_len (b[3]);

      vlib_increment_combined_counter (im->combined_sw_if_counters +
				       VNET_INTERFACE_COUNTER_TX,
				       thread_index, new_rx_sw_if_index,
				       1 /* pkts */ , n_bytes);
      b += 4;
      next += 4;
      n_left_from -= 4;
    }
  while (n_left_from > 0)
    {
      if (PREDICT_FALSE (vnet_buffer (b[0])->sw_if_index[VLIB_TX]
			 != new_rx_sw_if_index))
	{
	  config = l2input_intf_config
	    (vnet_buffer (b[0])->sw_if_index[VLIB_TX]);
	  next_index = (l2_input_is_bridge (config) ?
			VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT :
			VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT);
	  new_tx_sw_if_index = l2_input_is_bvi (config) ? L2INPUT_BVI : ~0;
	  new_rx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	}
      next[0] = next_index;
      vnet_buffer (b[0])->sw_if_index[VLIB_RX] = new_rx_sw_if_index;
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = new_tx_sw_if_index;
      n_bytes = vlib_buffer_length_in_chain (vm, b[0]);
      if (next_index == VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT)
	vnet_update_l2_len (b[0]);

      vlib_increment_combined_counter (im->combined_sw_if_counters +
				       VNET_INTERFACE_COUNTER_TX,
				       thread_index, new_rx_sw_if_index,
				       1 /* pkts */ , n_bytes);
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

static u8 *
format_simulated_ethernet_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "loop%d", dev_instance);
}

static clib_error_t *
simulated_ethernet_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				  u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);
  return 0;
}

static clib_error_t *
simulated_ethernet_mac_change (vnet_hw_interface_t * hi,
			       const u8 * old_address, const u8 * mac_address)
{
  l2input_interface_mac_change (hi->sw_if_index, old_address, mac_address);

  return (NULL);
}


/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ethernet_simulated_device_class) = {
  .name = "Loopback",
  .format_device_name = format_simulated_ethernet_name,
  .tx_function = simulated_ethernet_interface_tx,
  .admin_up_down_function = simulated_ethernet_admin_up_down,
  .mac_addr_change_function = simulated_ethernet_mac_change,
};
/* *INDENT-ON* */

/*
 * Maintain a bitmap of allocated loopback instance numbers.
 */
#define LOOPBACK_MAX_INSTANCE		(16 * 1024)

static u32
loopback_instance_alloc (u8 is_specified, u32 want)
{
  ethernet_main_t *em = &ethernet_main;

  /*
   * Check for dynamically allocaetd instance number.
   */
  if (!is_specified)
    {
      u32 bit;

      bit = clib_bitmap_first_clear (em->bm_loopback_instances);
      if (bit >= LOOPBACK_MAX_INSTANCE)
	{
	  return ~0;
	}
      em->bm_loopback_instances = clib_bitmap_set (em->bm_loopback_instances,
						   bit, 1);
      return bit;
    }

  /*
   * In range?
   */
  if (want >= LOOPBACK_MAX_INSTANCE)
    {
      return ~0;
    }

  /*
   * Already in use?
   */
  if (clib_bitmap_get (em->bm_loopback_instances, want))
    {
      return ~0;
    }

  /*
   * Grant allocation request.
   */
  em->bm_loopback_instances = clib_bitmap_set (em->bm_loopback_instances,
					       want, 1);

  return want;
}

static int
loopback_instance_free (u32 instance)
{
  ethernet_main_t *em = &ethernet_main;

  if (instance >= LOOPBACK_MAX_INSTANCE)
    {
      return -1;
    }

  if (clib_bitmap_get (em->bm_loopback_instances, instance) == 0)
    {
      return -1;
    }

  em->bm_loopback_instances = clib_bitmap_set (em->bm_loopback_instances,
					       instance, 0);
  return 0;
}

int
vnet_create_loopback_interface (u32 * sw_if_indexp, u8 * mac_address,
				u8 is_specified, u32 user_instance)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  u32 instance;
  u8 address[6];
  u32 hw_if_index;
  vnet_hw_interface_t *hw_if;
  u32 slot;

  ASSERT (sw_if_indexp);

  *sw_if_indexp = (u32) ~ 0;

  clib_memset (address, 0, sizeof (address));

  /*
   * Allocate a loopback instance.  Either select on dynamically
   * or try to use the desired user_instance number.
   */
  instance = loopback_instance_alloc (is_specified, user_instance);
  if (instance == ~0)
    {
      return VNET_API_ERROR_INVALID_REGISTRATION;
    }

  /*
   * Default MAC address (dead:0000:0000 + instance) is allocated
   * if zero mac_address is configured. Otherwise, user-configurable MAC
   * address is programmed on the loopback interface.
   */
  if (memcmp (address, mac_address, sizeof (address)))
    clib_memcpy (address, mac_address, sizeof (address));
  else
    {
      address[0] = 0xde;
      address[1] = 0xad;
      address[5] = instance;
    }

  vnet_eth_interface_registration_t eir = {};
  eir.dev_class_index = ethernet_simulated_device_class.index;
  eir.dev_instance = instance;
  eir.address = address;
  hw_if_index = vnet_eth_register_interface (vnm, &eir);
  hw_if = vnet_get_hw_interface (vnm, hw_if_index);
  slot = vlib_node_add_named_next_with_slot
    (vm, hw_if->tx_node_index,
     "ethernet-input", VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT);
  ASSERT (slot == VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT);

  slot = vlib_node_add_named_next_with_slot
    (vm, hw_if->tx_node_index,
     "l2-input", VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT);
  ASSERT (slot == VNET_SIMULATED_ETHERNET_TX_NEXT_L2_INPUT);

  {
    vnet_sw_interface_t *si = vnet_get_hw_sw_interface (vnm, hw_if_index);
    *sw_if_indexp = si->sw_if_index;

    /* By default don't flood to loopbacks, as packets just keep
     * coming back ... If this loopback becomes a BVI, we'll change it */
    si->flood_class = VNET_FLOOD_CLASS_NO_FLOOD;
  }

  return 0;
}

static clib_error_t *
create_simulated_ethernet_interfaces (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  int rv;
  u32 sw_if_index;
  u8 mac_address[6];
  u8 is_specified = 0;
  u32 user_instance = 0;

  clib_memset (mac_address, 0, sizeof (mac_address));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "mac %U", unformat_ethernet_address, mac_address))
	;
      if (unformat (input, "instance %d", &user_instance))
	is_specified = 1;
      else
	break;
    }

  rv = vnet_create_loopback_interface (&sw_if_index, mac_address,
				       is_specified, user_instance);

  if (rv)
    return clib_error_return (0, "vnet_create_loopback_interface failed");

  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);
  return 0;
}

/*?
 * Create a loopback interface. Optionally, a MAC Address can be
 * provided. If not provided, de:ad:00:00:00:<loopId> will be used.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{loopback create-interface [mac <mac-addr>] [instance <instance>]}
 * @cliexcmd{create loopback interface [mac <mac-addr>] [instance <instance>]}
 * Example of how to create a loopback interface:
 * @cliexcmd{loopback create-interface}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_simulated_ethernet_interface_command, static) = {
  .path = "loopback create-interface",
  .short_help = "loopback create-interface [mac <mac-addr>] [instance <instance>]",
  .function = create_simulated_ethernet_interfaces,
};
/* *INDENT-ON* */

/*?
 * Create a loopback interface. Optionally, a MAC Address can be
 * provided. If not provided, de:ad:00:00:00:<loopId> will be used.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{loopback create-interface [mac <mac-addr>] [instance <instance>]}
 * @cliexcmd{create loopback interface [mac <mac-addr>] [instance <instance>]}
 * Example of how to create a loopback interface:
 * @cliexcmd{create loopback interface}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_loopback_interface_command, static) = {
  .path = "create loopback interface",
  .short_help = "create loopback interface [mac <mac-addr>] [instance <instance>]",
  .function = create_simulated_ethernet_interfaces,
};
/* *INDENT-ON* */

ethernet_interface_t *
ethernet_get_interface (ethernet_main_t * em, u32 hw_if_index)
{
  vnet_hw_interface_t *i =
    vnet_get_hw_interface (vnet_get_main (), hw_if_index);
  return (i->hw_class_index ==
	  ethernet_hw_interface_class.
	  index ? pool_elt_at_index (em->interfaces, i->hw_instance) : 0);
}

mac_address_t *
ethernet_interface_add_del_address (ethernet_main_t * em,
				    u32 hw_if_index, const u8 * address,
				    u8 is_add)
{
  ethernet_interface_t *ei = ethernet_get_interface (em, hw_if_index);
  ethernet_interface_address_t *if_addr = 0;
  int found = 0;

  /* return if there is not an ethernet interface for this hw interface */
  if (!ei)
    return 0;

  /* determine whether the address is configured on the interface */
  vec_foreach (if_addr, ei->secondary_addrs)
  {
    if (ethernet_mac_address_equal (if_addr->mac.bytes, address))
      {
	found = 1;
	break;
      }
  }

  if (is_add)
    {
      if (!found)
	{
	  /* address not found yet: add it */
	  vec_add2 (ei->secondary_addrs, if_addr, 1);
	  ethernet_interface_address_copy (if_addr, address);
	}
      return &if_addr->mac;
    }

  /* delete case */
  if (found)
    vec_delete (ei->secondary_addrs, 1, if_addr - ei->secondary_addrs);

  return 0;
}

int
vnet_delete_loopback_interface (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == 0 || hw->dev_class_index != ethernet_simulated_device_class.index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (loopback_instance_free (hw->dev_instance) < 0)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  ethernet_delete_interface (vnm, hw->hw_if_index);

  return 0;
}

int
vnet_create_sub_interface (u32 sw_if_index, u32 id,
			   u32 flags, u16 inner_vlan_id, u16 outer_vlan_id,
			   u32 * sub_sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi;
  u64 sup_and_sub_key = ((u64) (sw_if_index) << 32) | (u64) id;
  vnet_sw_interface_t template;
  uword *p;
  u64 *kp;

  hi = vnet_get_sup_hw_interface (vnm, sw_if_index);

  p = hash_get_mem (im->sw_if_index_by_sup_and_sub, &sup_and_sub_key);
  if (p)
    {
      return (VNET_API_ERROR_VLAN_ALREADY_EXISTS);
    }

  clib_memset (&template, 0, sizeof (template));
  template.type = VNET_SW_INTERFACE_TYPE_SUB;
  template.flood_class = VNET_FLOOD_CLASS_NORMAL;
  template.sup_sw_if_index = sw_if_index;
  template.sub.id = id;
  template.sub.eth.raw_flags = flags;
  template.sub.eth.outer_vlan_id = outer_vlan_id;
  template.sub.eth.inner_vlan_id = inner_vlan_id;

  if (vnet_create_sw_interface (vnm, &template, sub_sw_if_index))
    return (VNET_API_ERROR_UNSPECIFIED);

  kp = clib_mem_alloc (sizeof (*kp));
  *kp = sup_and_sub_key;

  hash_set (hi->sub_interface_sw_if_index_by_id, id, *sub_sw_if_index);
  hash_set_mem (im->sw_if_index_by_sup_and_sub, kp, *sub_sw_if_index);

  return (0);
}

int
vnet_delete_sub_interface (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;
  int rv = 0;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  si = vnet_get_sw_interface (vnm, sw_if_index);
  if (si->type == VNET_SW_INTERFACE_TYPE_SUB ||
      si->type == VNET_SW_INTERFACE_TYPE_PIPE ||
      si->type == VNET_SW_INTERFACE_TYPE_P2P)
    {
      vnet_interface_main_t *im = &vnm->interface_main;
      vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
      u64 sup_and_sub_key =
	((u64) (si->sup_sw_if_index) << 32) | (u64) si->sub.id;
      hash_unset_mem_free (&im->sw_if_index_by_sup_and_sub, &sup_and_sub_key);
      hash_unset (hi->sub_interface_sw_if_index_by_id, si->sub.id);
      vnet_delete_sw_interface (vnm, sw_if_index);
    }
  else
    rv = VNET_API_ERROR_INVALID_SUB_SW_IF_INDEX;

  return rv;
}

static clib_error_t *
delete_simulated_ethernet_interfaces (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  int rv;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "intfc %U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface not specified");

  rv = vnet_delete_loopback_interface (sw_if_index);

  if (rv)
    return clib_error_return (0, "vnet_delete_loopback_interface failed");

  return 0;
}

static clib_error_t *
delete_sub_interface (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int rv = 0;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }
  if (sw_if_index == ~0)
    return clib_error_return (0, "interface doesn't exist");

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  else
    rv = vnet_delete_sub_interface (sw_if_index);
  if (rv)
    return clib_error_return (0, "delete_subinterface_interface failed");
  return 0;
}

/*?
 * Delete a loopback interface.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{loopback delete-interface intfc <interface>}
 * @cliexcmd{delete loopback interface intfc <interface>}
 * Example of how to delete a loopback interface:
 * @cliexcmd{loopback delete-interface intfc loop0}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (delete_simulated_ethernet_interface_command, static) = {
  .path = "loopback delete-interface",
  .short_help = "loopback delete-interface intfc <interface>",
  .function = delete_simulated_ethernet_interfaces,
};
/* *INDENT-ON* */

/*?
 * Delete a loopback interface.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{loopback delete-interface intfc <interface>}
 * @cliexcmd{delete loopback interface intfc <interface>}
 * Example of how to delete a loopback interface:
 * @cliexcmd{delete loopback interface intfc loop0}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (delete_loopback_interface_command, static) = {
  .path = "delete loopback interface",
  .short_help = "delete loopback interface intfc <interface>",
  .function = delete_simulated_ethernet_interfaces,
};
/* *INDENT-ON* */

/*?
 * Delete a sub-interface.
 *
 * @cliexpar
 * Example of how to delete a sub-interface:
 * @cliexcmd{delete sub-interface GigabitEthernet0/8/0.200}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (delete_sub_interface_command, static) = {
  .path = "delete sub-interface",
  .short_help = "delete sub-interface <interface>",
  .function = delete_sub_interface,
};
/* *INDENT-ON* */

/* ethernet { ... } configuration. */
/*?
 *
 * @cfgcmd{default-mtu &lt;n&gt;}
 * Specify the default mtu in the range of 64-9000. The default is 9000 bytes.
 *
 */
static clib_error_t *
ethernet_config (vlib_main_t * vm, unformat_input_t * input)
{
  ethernet_main_t *em = &ethernet_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "default-mtu %u", &em->default_mtu))
	{
	  if (em->default_mtu < 64 || em->default_mtu > 9000)
	    return clib_error_return (0, "default MTU must be >=64, <=9000");
	}
      else
	{
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (ethernet_config, "ethernet");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
