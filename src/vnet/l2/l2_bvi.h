/*
 * l2_bvi.h : layer 2 Bridged Virtual Interface
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#ifndef included_l2bvi_h
#define included_l2bvi_h

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/sparse_vec.h>

#include <vnet/l2/l2_input.h>

#define TO_BVI_ERR_OK        0
#define TO_BVI_ERR_BAD_MAC   1
#define TO_BVI_ERR_ETHERTYPE 2

/**
 * Send a packet from L2 processing to L3 via the BVI interface.
 * Set next0 to the proper L3 input node.
 * Return an error if the packet isn't what we expect.
 */

static_always_inline u32
l2_to_bvi (vlib_main_t * vlib_main,
	   vnet_main_t * vnet_main,
	   vlib_buffer_t * b0,
	   u32 bvi_sw_if_index, next_by_ethertype_t * l3_next, u32 * next0)
{
  u8 l2_len;
  u16 ethertype;
  u8 *l3h;
  ethernet_header_t *e0;
  vnet_hw_interface_t *hi;

  e0 = vlib_buffer_get_current (b0);
  hi = vnet_get_sup_hw_interface (vnet_main, bvi_sw_if_index);

  /* Perform L3 my-mac filter */
  if ((!ethernet_address_cast (e0->dst_address)) &&
      (!eth_mac_equal ((u8 *) e0, hi->hw_address)))
    {
      return TO_BVI_ERR_BAD_MAC;
    }

  /* Save L2 header position which may be changed due to packet replication */
  vnet_buffer (b0)->l2_hdr_offset = b0->current_data;

  /* Strip L2 header */
  l2_len = vnet_buffer (b0)->l2.l2_len;
  vlib_buffer_advance (b0, l2_len);

  l3h = vlib_buffer_get_current (b0);
  ethertype = clib_net_to_host_u16 (*(u16 *) (l3h - 2));

  /* Set the input interface to be the BVI interface */
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = bvi_sw_if_index;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;

  /* Go to appropriate L3 input node */
  if (ethertype == ETHERNET_TYPE_IP4)
    {
      *next0 = l3_next->input_next_ip4;
    }
  else if (ethertype == ETHERNET_TYPE_IP6)
    {
      *next0 = l3_next->input_next_ip6;
    }
  else
    {
      /* uncommon ethertype, check table */
      u32 i0;

      i0 = sparse_vec_index (l3_next->input_next_by_type, ethertype);
      *next0 = vec_elt (l3_next->input_next_by_type, i0);

      if (i0 == SPARSE_VEC_INVALID_INDEX)
	{
	  return TO_BVI_ERR_ETHERTYPE;
	}
    }

  /* increment BVI RX interface stat */
  vlib_increment_combined_counter
    (vnet_main->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     vlib_main->thread_index,
     vnet_buffer (b0)->sw_if_index[VLIB_RX],
     1, vlib_buffer_length_in_chain (vlib_main, b0));
  return TO_BVI_ERR_OK;
}

void
l2bvi_register_input_type (vlib_main_t * vm,
			   ethernet_type_t type, u32 node_index);
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
