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

static uword ethernet_set_rewrite (vnet_main_t * vnm,
				   u32 sw_if_index,
				   u32 l3_type,
				   void * dst_address,
				   void * rewrite,
				   uword max_rewrite_bytes)
{
  vnet_sw_interface_t * sub_sw = vnet_get_sw_interface (vnm, sw_if_index);
  vnet_sw_interface_t * sup_sw = vnet_get_sup_sw_interface (vnm, sw_if_index);
  vnet_hw_interface_t * hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  ethernet_main_t * em = &ethernet_main;
  ethernet_interface_t * ei;
  ethernet_header_t * h = rewrite;
  ethernet_type_t type;
  uword n_bytes = sizeof (h[0]);

  if (sub_sw != sup_sw) {
    if (sub_sw->sub.eth.flags.one_tag) {
      n_bytes += sizeof (ethernet_vlan_header_t);
    } else if (sub_sw->sub.eth.flags.two_tags) {
      n_bytes += 2 * (sizeof (ethernet_vlan_header_t));
    }
    // Check for encaps that are not supported for L3 interfaces
    if (!(sub_sw->sub.eth.flags.exact_match) ||
        (sub_sw->sub.eth.flags.default_sub) ||
        (sub_sw->sub.eth.flags.outer_vlan_id_any) ||
        (sub_sw->sub.eth.flags.inner_vlan_id_any)) {
      return 0;
    }
  }

  if (n_bytes > max_rewrite_bytes)
    return 0;

  switch (l3_type) {
#define _(a,b) case VNET_L3_PACKET_TYPE_##a: type = ETHERNET_TYPE_##b; break
    _ (IP4, IP4);
    _ (IP6, IP6);
    _ (MPLS_UNICAST, MPLS_UNICAST);
    _ (MPLS_MULTICAST, MPLS_MULTICAST);
    _ (ARP, ARP);
#undef _
  default:
    return 0;
  }

  ei = pool_elt_at_index (em->interfaces, hw->hw_instance);
  memcpy (h->src_address, ei->address, sizeof (h->src_address));
  if (dst_address)
    memcpy (h->dst_address, dst_address, sizeof (h->dst_address));
  else
    memset (h->dst_address, ~0, sizeof (h->dst_address)); /* broadcast */

  if (sub_sw->sub.eth.flags.one_tag) {
    ethernet_vlan_header_t * outer = (void *) (h + 1);

    h->type = sub_sw->sub.eth.flags.dot1ad ?
              clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD) :
              clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
    outer->priority_cfi_and_id = clib_host_to_net_u16 (sub_sw->sub.eth.outer_vlan_id);
    outer->type = clib_host_to_net_u16 (type);

  } else if (sub_sw->sub.eth.flags.two_tags) {
    ethernet_vlan_header_t * outer = (void *) (h + 1);
    ethernet_vlan_header_t * inner = (void *) (outer + 1);

    h->type = sub_sw->sub.eth.flags.dot1ad ?
              clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD) :
              clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
    outer->priority_cfi_and_id = clib_host_to_net_u16 (sub_sw->sub.eth.outer_vlan_id);
    outer->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
    inner->priority_cfi_and_id = clib_host_to_net_u16 (sub_sw->sub.eth.inner_vlan_id);
    inner->type = clib_host_to_net_u16 (type);

  } else {
    h->type = clib_host_to_net_u16 (type);
  }

  return n_bytes;
}

VNET_HW_INTERFACE_CLASS (ethernet_hw_interface_class) = {
  .name = "Ethernet",
  .format_address = format_ethernet_address,
  .format_header = format_ethernet_header_with_length,
  .unformat_hw_address = unformat_ethernet_address,
  .unformat_header = unformat_ethernet_header,
  .set_rewrite = ethernet_set_rewrite,
};

uword unformat_ethernet_interface (unformat_input_t * input, va_list * args)
{
  vnet_main_t * vnm = va_arg (*args, vnet_main_t *);
  u32 * result = va_arg (*args, u32 *);
  u32 hw_if_index;
  ethernet_main_t * em = &ethernet_main;
  ethernet_interface_t * eif;

  if (! unformat_user (input, unformat_vnet_hw_interface, vnm, &hw_if_index))
    return 0;

  eif = ethernet_get_interface (em, hw_if_index);
  if (eif)
    {
      *result =  hw_if_index;
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
  ethernet_main_t * em = &ethernet_main;
  ethernet_interface_t * ei;
  vnet_hw_interface_t * hi;
  clib_error_t * error = 0;
  u32 hw_if_index;

  pool_get (em->interfaces, ei);
  ei->flag_change = flag_change;

  hw_if_index = vnet_register_interface
    (vnm,
     dev_class_index, dev_instance,
     ethernet_hw_interface_class.index,
     ei - em->interfaces);
  *hw_if_index_return = hw_if_index;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  ethernet_setup_node (vnm->vlib_main, hi->output_node_index);

  hi->min_packet_bytes = ETHERNET_MIN_PACKET_BYTES;
  hi->max_packet_bytes = ETHERNET_MAX_PACKET_BYTES;
  hi->per_packet_overhead_bytes =
    /* preamble */ 8 + /* inter frame gap */ 12;

  /* Standard default ethernet MTU. */
  hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] = 9000;

  memcpy (ei->address, address, sizeof (ei->address));
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
  ethernet_main_t * em = &ethernet_main;
  ethernet_interface_t * ei;
  vnet_hw_interface_t * hi;
  main_intf_t * main_intf;
  vlan_table_t * vlan_table;
  u32           idx;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  ei = pool_elt_at_index (em->interfaces, hi->hw_instance);

  /* Delete vlan mapping table for dot1q and dot1ad. */
  main_intf = vec_elt_at_index (em->main_intfs, hi->hw_if_index);
  if (main_intf->dot1q_vlans) {
    vlan_table = vec_elt_at_index (em->vlan_pool, main_intf->dot1q_vlans);
    for (idx=0; idx<ETHERNET_N_VLAN; idx++ ) {
      if (vlan_table->vlans[idx].qinqs) {
        pool_put_index(em->qinq_pool, vlan_table->vlans[idx].qinqs);
      }
    }
    pool_put_index(em->vlan_pool, main_intf->dot1q_vlans);
  }
  if (main_intf->dot1ad_vlans) {
    vlan_table = vec_elt_at_index (em->vlan_pool, main_intf->dot1ad_vlans);
    for (idx=0; idx<ETHERNET_N_VLAN; idx++ ) {
      if (vlan_table->vlans[idx].qinqs) {
        pool_put_index(em->qinq_pool, vlan_table->vlans[idx].qinqs);
      }
    }
    pool_put_index(em->vlan_pool, main_intf->dot1ad_vlans);
  }
  
  vnet_delete_hw_interface (vnm, hw_if_index);
  pool_put (em->interfaces, ei);
}

u32 
ethernet_set_flags (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  ethernet_main_t * em = &ethernet_main;
  vnet_hw_interface_t * hi;
  ethernet_interface_t * ei;
  
  hi = vnet_get_hw_interface (vnm, hw_if_index);

  ASSERT (hi->hw_class_index == ethernet_hw_interface_class.index);

  ei = pool_elt_at_index (em->interfaces, hi->hw_instance);
  if (ei->flag_change)
    return ei->flag_change (vnm, hi, flags);
  return (u32)~0;
}

#define VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT VNET_INTERFACE_TX_N_NEXT

/* Echo packets back to ethernet input. */
static uword
simulated_ethernet_interface_tx (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  u32 n_left_from, n_left_to_next, n_copy, * from, * to_next;
  u32 next_index = VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT;
  u32 i;
  vlib_buffer_t * b;

  n_left_from = frame->n_vectors;
  from = vlib_frame_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      n_copy = clib_min (n_left_from, n_left_to_next);

      memcpy (to_next, from, n_copy * sizeof (from[0]));
      n_left_to_next -= n_copy;
      n_left_from -= n_copy;
      for (i = 0; i < n_copy; i++)
	{
	  b = vlib_get_buffer (vm, from[i]);
          /* Set up RX and TX indices as if received from a real driver */
	  vnet_buffer (b)->sw_if_index[VLIB_RX] = 
              vnet_buffer (b)->sw_if_index[VLIB_TX];
          vnet_buffer (b)->sw_if_index[VLIB_TX] = (u32) ~0;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return n_left_from;
}

static u8 * format_simulated_ethernet_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "loop%d", dev_instance);
}

VNET_DEVICE_CLASS (ethernet_simulated_device_class) = {
  .name = "Loopback",
  .format_device_name = format_simulated_ethernet_name,
  .tx_function = simulated_ethernet_interface_tx,
};

int vnet_create_loopback_interface (u32 * sw_if_indexp, u8 *mac_address)
{
  vnet_main_t * vnm = vnet_get_main();
  vlib_main_t * vm = vlib_get_main();
  clib_error_t * error;
  static u32 instance;
  u8 address[6];
  u32 hw_if_index;
  vnet_hw_interface_t * hw_if;
  u32 slot;
  int rv = 0;

  ASSERT(sw_if_indexp);

  *sw_if_indexp = (u32)~0;

  memset (address, 0, sizeof (address));

  /*
   * Default MAC address (dead:0000:0000 + instance) is allocated
   * if zero mac_address is configured. Otherwise, user-configurable MAC
   * address is programmed on the loopback interface.
   */
  if (memcmp (address, mac_address, sizeof (address)))
    memcpy (address, mac_address, sizeof (address));
  else
    {
      address[0] = 0xde;
      address[1] = 0xad;
      address[5] = instance;
    }

  error = ethernet_register_interface
    (vnm,
     ethernet_simulated_device_class.index,
     instance++,
     address,
     &hw_if_index, 
     /* flag change */ 0);

  if (error)
    {
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      clib_error_report(error);
      return rv;
    }

  hw_if = vnet_get_hw_interface (vnm, hw_if_index);
  slot = vlib_node_add_named_next_with_slot
    (vm, hw_if->tx_node_index,
     "ethernet-input",
     VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT);
  ASSERT (slot == VNET_SIMULATED_ETHERNET_TX_NEXT_ETHERNET_INPUT);

  {
    vnet_sw_interface_t * si = vnet_get_hw_sw_interface (vnm, hw_if_index);
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

  memset (mac_address, 0, sizeof (mac_address));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "mac %U", unformat_ethernet_address, mac_address))
        ;
      else
        break;
    }

  rv = vnet_create_loopback_interface (&sw_if_index, mac_address);

  if (rv)
    return clib_error_return (0, "vnet_create_loopback_interface failed");

  return 0;
}

VLIB_CLI_COMMAND (create_simulated_ethernet_interface_command, static) = {
  .path = "loopback create-interface",
  .short_help = "Create Loopback ethernet interface [mac <mac-addr>]",
  .function = create_simulated_ethernet_interfaces,
};

ethernet_interface_t *
ethernet_get_interface (ethernet_main_t * em, u32 hw_if_index)
{
  vnet_hw_interface_t * i = vnet_get_hw_interface (vnet_get_main(), hw_if_index);
  return (i->hw_class_index == ethernet_hw_interface_class.index
          ? pool_elt_at_index (em->interfaces, i->hw_instance)
          : 0);
}

int vnet_delete_loopback_interface (u32 sw_if_index)
{
  vnet_main_t * vnm = vnet_get_main();
  vnet_sw_interface_t * si;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces,
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  si = vnet_get_sw_interface (vnm, sw_if_index);
  ethernet_delete_interface (vnm, si->hw_if_index);

  return 0;
}

static clib_error_t *
delete_simulated_ethernet_interfaces (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  int rv;
  u32 sw_if_index = ~0;
  vnet_main_t * vnm = vnet_get_main();

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

VLIB_CLI_COMMAND (delete_simulated_ethernet_interface_command, static) = {
  .path = "loopback delete-interface",
  .short_help = "Delete Loopback ethernet interface intfc <interface>",
  .function = delete_simulated_ethernet_interfaces,
};
