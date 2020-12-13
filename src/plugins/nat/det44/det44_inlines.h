/*
 * det44.h - deterministic NAT definitions
 *
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

/**
 * @file
 * @brief Deterministic NAT (CGN) inlines
 */

#ifndef __included_det44_inlines_h__
#define __included_det44_inlines_h__

static_always_inline int
det44_is_interface_addr (vlib_node_runtime_t * node,
			 u32 sw_if_index0, u32 ip4_addr)
{
  det44_runtime_t *rt = (det44_runtime_t *) node->runtime_data;
  det44_main_t *dm = &det44_main;
  ip4_address_t *first_int_addr;

  if (PREDICT_FALSE (rt->cached_sw_if_index != sw_if_index0))
    {
      first_int_addr = ip4_interface_first_address (dm->ip4_main,
						    sw_if_index0, 0);
      rt->cached_sw_if_index = sw_if_index0;
      if (first_int_addr)
	rt->cached_ip4_address = first_int_addr->as_u32;
      else
	rt->cached_ip4_address = 0;
    }
  if (PREDICT_FALSE (rt->cached_ip4_address == ip4_addr))
    return 0;
  return 1;
}

/**
 * @brief Check if packet should be translated
 *
 * Packets aimed at outside interface and external address with active session
 * should be translated.
 *
 * @param node          NAT runtime data
 * @param sw_if_index0  index of the inside interface
 * @param ip0           IPv4 header
 * @param proto0        NAT protocol
 * @param rx_fib_index0 RX FIB index
 *
 * @returns 0 if packet should be translated otherwise 1
 */
static_always_inline int
det44_translate (vlib_node_runtime_t * node, u32 sw_if_index0,
		 ip4_header_t * ip0, u32 proto0, u32 rx_fib_index0)
{
  det44_main_t *dm = &det44_main;
  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  det44_fib_t *outside_fib;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
		.ip4.as_u32 = ip0->dst_address.as_u32,
		}
    ,
  };

  /* Don't NAT packet aimed at the interface address */
  if (PREDICT_FALSE (!det44_is_interface_addr (node, sw_if_index0,
					       ip0->dst_address.as_u32)))
    {
      return 1;
    }

  /* find out if there is outside feature enabled for this destination */
  fei = fib_table_lookup (rx_fib_index0, &pfx);
  if (FIB_NODE_INDEX_INVALID != fei)
    {
      u32 sw_if_index = fib_entry_get_resolving_interface (fei);
      if (sw_if_index == ~0)
	{
	  // TODO: go over use cases
          /* *INDENT-OFF* */
	  vec_foreach (outside_fib, dm->outside_fibs)
	    {
	      fei = fib_table_lookup (outside_fib->fib_index, &pfx);
	      if (FIB_NODE_INDEX_INVALID != fei)
	        {
		  sw_if_index = fib_entry_get_resolving_interface (fei);
		  if (sw_if_index != ~0)
		    break;
	        }
	    }
          /* *INDENT-ON* */
	}
      if (sw_if_index != ~0)
	{
	  det44_interface_t *i;
          /* *INDENT-OFF* */
          pool_foreach (i, dm->interfaces)  {
            /* NAT packet aimed at outside interface */
	    if ((det44_interface_is_outside (i)) && (sw_if_index == i->sw_if_index))
              return 0;
          }
          /* *INDENT-ON* */
	}
    }
  return 1;
}

#endif /* __included_det44_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
