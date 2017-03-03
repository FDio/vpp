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
#include <vnet/l2/l2_input.h>
#include <vnet/adj/adj.h>

/**
 * @file
 * @brief Loopback Interfaces.
 *
 * This file contains code to manage loopback interfaces.
 */

const u8 *
ethernet_ip4_mcast_dst_addr (void)
{
  const static u8 ethernet_mcast_dst_mac[] = {
    0x1, 0x0, 0x5e, 0x0, 0x0, 0x0,
  };

  return (ethernet_mcast_dst_mac);
}

const u8 *
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
      // Check for encaps that are not supported for L3 interfaces
      if (!(sub_sw->sub.eth.flags.exact_match) ||
	  (sub_sw->sub.eth.flags.default_sub) ||
	  (sub_sw->sub.eth.flags.outer_vlan_id_any) ||
	  (sub_sw->sub.eth.flags.inner_vlan_id_any))
	{
	  return 0;
	}
    }

  switch (link_type)
    {
#define _(a,b) case VNET_LINK_##a: type = ETHERNET_TYPE_##b; break
      _(IP4, IP4);
      _(IP6, IP6);
      _(MPLS, MPLS_UNICAST);
      _(ARP, ARP);
#undef _
    default:
      return NULL;
    }

  vec_validate (rewrite, n_bytes - 1);
  h = (ethernet_header_t *) rewrite;
  ei = pool_elt_at_index (em->interfaces, hw->hw_instance);
  clib_memcpy (h->src_address, ei->address, sizeof (h->src_address));
  if (dst_address)
    clib_memcpy (h->dst_address, dst_address, sizeof (h->dst_address));
  else
    memset (h->dst_address, ~0, sizeof (h->dst_address));	/* broadcast */

  if (sub_sw->sub.eth.flags.one_tag)
    {
      ethernet_vlan_header_t *outer = (void *) (h + 1);

      h->type = sub_sw->sub.eth.flags.dot1ad ?
	clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD) :
	clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      outer->priority_cfi_and_id =
	clib_host_to_net_u16 (sub_sw->sub.eth.outer_vlan_id);
      outer->type = clib_host_to_net_u16 (type);

    }
  else if (sub_sw->sub.eth.flags.two_tags)
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
  ip_adjacency_t *adj;

  adj = adj_get (ai);

  if (FIB_PROTOCOL_IP4 == adj->ia_nh_proto)
    {
      arp_update_adjacency (vnm, sw_if_index, ai);
    }
  else if (FIB_PROTOCOL_IP6 == adj->ia_nh_proto)
    {
      ip6_ethernet_update_adjacency (vnm, sw_if_index, ai);
    }
  else
    {
      ASSERT (0);
    }
}

static clib_error_t *
ethernet_mac_change (vnet_hw_interface_t * hi, char *mac_address)
{
  ethernet_interface_t *ei;
  ethernet_main_t *em;

  em = &ethernet_main;
  ei = pool_elt_at_index (em->interfaces, hi->hw_instance);

  vec_validate (hi->hw_address,
		STRUCT_SIZE_OF (ethernet_header_t, src_address) - 1);
  clib_memcpy (hi->hw_address, mac_address, vec_len (hi->hw_address));

  clib_memcpy (ei->address, (u8 *) mac_address, sizeof (ei->address));
  ethernet_arp_change_mac (hi->sw_if_index);
  ethernet_ndp_change_mac (hi->sw_if_index);

  return (NULL);
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (ethernet_hw_interface_class) = {
  .name = "Ethernet",
  .format_address = format_ethernet_address,
  .format_header = format_ethernet_header_with_length,
  .unformat_hw_address = unformat_ethernet_address,
  .unformat_header = unformat_ethernet_header,
  .build_rewrite = ethernet_build_rewrite,
  .update_adjacency = ethernet_update_adjacency,
  .mac_addr_change_function = ethernet_mac_change,
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

clib_error_t *
ethernet_register_interface (vnet_main_t * vnm,
			     u32 dev_class_index,
			     u32 dev_instance,
			     u8 * address,
			     u32 * hw_if_index_return,
			     ethernet_flag_change_function_t flag_change)
{
  ethernet_main_t *em = &ethernet_main;
  ethernet_interface_t *ei;
  vnet_hw_interface_t *hi;
  clib_error_t *error = 0;
  u32 hw_if_index;

  pool_get (em->interfaces, ei);
  ei->flag_change = flag_change;

  hw_if_index = vnet_register_interface
    (vnm,
     dev_class_index, dev_instance,
     ethernet_hw_interface_class.index, ei - em->interfaces);
  *hw_if_index_return = hw_if_index;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  ethernet_setup_node (vnm->vlib_main, hi->output_node_index);

  hi->min_packet_bytes = hi->min_supported_packet_bytes =
    ETHERNET_MIN_PACKET_BYTES;
  hi->max_packet_bytes = hi->max_supported_packet_bytes =
    ETHERNET_MAX_PACKET_BYTES;
  hi->per_packet_overhead_bytes =
    /* preamble */ 8 + /* inter frame gap */ 12;

  /* Standard default ethernet MTU. */
  hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] = 9000;

  clib_memcpy (ei->address, address, sizeof (ei->address));
  vec_free (hi->hw_address);
  vec_add (hi->hw_address, address, sizeof (ei->address));

  if (error)
    {
      pool_put (em->interfaces, ei);
      return error;
    }
  return error;
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
	    }
	}
      pool_put_index (em->vlan_pool, main_intf->dot1q_vlans);
    }
  if (main_intf->dot1ad_vlans)
    {
      vlan_table = vec_elt_at_index (em->vlan_pool, main_intf->dot1ad_vlans);
      for (idx = 0; idx < ETHERNET_N_VLAN; idx++)
	{
	  if (vlan_table->vlans[idx].qinqs)
	    {
	      pool_put_index (em->qinq_pool, vlan_table->vlans[idx].qinqs);
	    }
	}
      pool_put_index (em->vlan_pool, main_intf->dot1ad_vlans);
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

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  ASSERT (hi->hw_class_index == ethernet_hw_interface_class.index);

  ei = pool_elt_at_index (em->interfaces, hi->hw_instance);
  if (ei->flag_change)
    return ei->flag_change (vnm, hi, flags);
  return (u32) ~ 0;
}

/* Echo packets back to ethernet/l2-input. */
static uword
simulated_ethernet_interface_tx (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  u32 n_left_from, n_left_to_next, n_copy, *from, *to_next;
  u32 next_index = VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT;
  u32 i, next_node_index, bvi_flag, sw_if_index;
  u32 n_pkts = 0, n_bytes = 0;
  u32 cpu_index = vm->cpu_index;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_node_main_t *nm = &vm->node_main;
  vlib_node_t *loop_node;
  vlib_buffer_t *b;

  // check tx node index, it is ethernet-input on loopback create
  // but can be changed to l2-input if loopback is configured as
  // BVI of a BD (Bridge Domain).
  loop_node = vec_elt (nm->nodes, node->node_index);
  next_node_index = loop_node->next_nodes[next_index];
  bvi_flag = (next_node_index == l2input_node.index) ? 1 : 0;

  n_left_from = frame->n_vectors;
  from = vlib_frame_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      n_copy = clib_min (n_left_from, n_left_to_next);

      clib_memcpy (to_next, from, n_copy * sizeof (from[0]));
      n_left_to_next -= n_copy;
      n_left_from -= n_copy;
      i = 0;
      b = vlib_get_buffer (vm, from[i]);
      sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
      while (1)
	{
	  // Set up RX and TX indices as if received from a real driver
	  // unless loopback is used as a BVI. For BVI case, leave TX index
	  // and update l2_len in packet as required for l2 forwarding path
	  vnet_buffer (b)->sw_if_index[VLIB_RX] = sw_if_index;
	  if (bvi_flag)
	    {
	      vnet_update_l2_len (b);
	      vnet_buffer (b)->sw_if_index[VLIB_TX] = L2INPUT_BVI;
	    }
	  else
	    vnet_buffer (b)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  i++;
	  n_pkts++;
	  n_bytes += vlib_buffer_length_in_chain (vm, b);

	  if (i < n_copy)
	    b = vlib_get_buffer (vm, from[i]);
	  else
	    break;
	}
      from += n_copy;

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

      /* increment TX interface stat */
      vlib_increment_combined_counter (im->combined_sw_if_counters +
				       VNET_INTERFACE_COUNTER_TX, cpu_index,
				       sw_if_index, n_pkts, n_bytes);
    }

  return n_left_from;
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

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ethernet_simulated_device_class) = {
  .name = "Loopback",
  .format_device_name = format_simulated_ethernet_name,
  .tx_function = simulated_ethernet_interface_tx,
  .admin_up_down_function = simulated_ethernet_admin_up_down,
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
  clib_error_t *error;
  u32 instance;
  u8 address[6];
  u32 hw_if_index;
  vnet_hw_interface_t *hw_if;
  u32 slot;
  int rv = 0;

  ASSERT (sw_if_indexp);

  *sw_if_indexp = (u32) ~ 0;

  memset (address, 0, sizeof (address));

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

  error = ethernet_register_interface
    (vnm,
     ethernet_simulated_device_class.index, instance, address, &hw_if_index,
     /* flag change */ 0);

  if (error)
    {
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      clib_error_report (error);
      return rv;
    }

  hw_if = vnet_get_hw_interface (vnm, hw_if_index);
  slot = vlib_node_add_named_next_with_slot
    (vm, hw_if->tx_node_index,
     "ethernet-input", VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT);
  ASSERT (slot == VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT);

  {
    vnet_sw_interface_t *si = vnet_get_hw_sw_interface (vnm, hw_if_index);
    *sw_if_indexp = si->sw_if_index;
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

  memset (mac_address, 0, sizeof (mac_address));

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

int
vnet_delete_loopback_interface (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;
  u32 hw_if_index;
  vnet_hw_interface_t *hw;
  u32 instance;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  si = vnet_get_sw_interface (vnm, sw_if_index);
  hw_if_index = si->hw_if_index;
  hw = vnet_get_hw_interface (vnm, hw_if_index);
  instance = hw->dev_instance;

  if (loopback_instance_free (instance) < 0)
    {
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }

  ethernet_delete_interface (vnm, hw_if_index);

  return 0;
}

int
vnet_delete_sub_interface (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  int rv = 0;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;


  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);

  if (si->type == VNET_SW_INTERFACE_TYPE_SUB)
    {
      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
      u64 sup_and_sub_key =
	((u64) (si->sup_sw_if_index) << 32) | (u64) si->sub.id;

      hash_unset_mem (im->sw_if_index_by_sup_and_sub, &sup_and_sub_key);
      vnet_delete_sw_interface (vnm, sw_if_index);
    }
  else
    {
      rv = VNET_API_ERROR_INVALID_SUB_SW_IF_INDEX;
    }
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
