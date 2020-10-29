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
 * ip/ip4_forward.c: IP v4 forwarding
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
#include <vnet/ip/ip_frag.h>
#include <vnet/ethernet/ethernet.h>	/* for ethernet_header_t */
#include <vnet/ethernet/arp_packet.h>	/* for ethernet_arp_header_t */
#include <vnet/ppp/ppp.h>
#include <vnet/srp/srp.h>	/* for srp_hw_interface_class */
#include <vnet/api_errno.h>	/* for API error numbers */
#include <vnet/fib/fib_table.h>	/* for FIB table and entry creation */
#include <vnet/fib/fib_entry.h>	/* for FIB table and entry creation */
#include <vnet/fib/fib_urpf_list.h>	/* for FIB uRPF check */
#include <vnet/fib/ip4_fib.h>
#include <vnet/mfib/ip4_mfib.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>
#include <vnet/dpo/classify_dpo.h>
#include <vnet/mfib/mfib_table.h>	/* for mFIB table and entry creation */
#include <vnet/adj/adj_dp.h>

#include <vnet/ip/ip4_forward.h>
#include <vnet/interface_output.h>
#include <vnet/classify/vnet_classify.h>

/** @brief IPv4 lookup node.
    @node ip4-lookup

    This is the main IPv4 lookup dispatch node.

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched

    @par Graph mechanics: buffer metadata, next index usage

    @em Uses:
    - <code>vnet_buffer(b)->sw_if_index[VLIB_RX]</code>
        - Indicates the @c sw_if_index value of the interface that the
	  packet was received on.
    - <code>vnet_buffer(b)->sw_if_index[VLIB_TX]</code>
        - When the value is @c ~0 then the node performs a longest prefix
          match (LPM) for the packet destination address in the FIB attached
          to the receive interface.
        - Otherwise perform LPM for the packet destination address in the
          indicated FIB. In this case <code>[VLIB_TX]</code> is a FIB index
          value (0, 1, ...) and not a VRF id.

    @em Sets:
    - <code>vnet_buffer(b)->ip.adj_index[VLIB_TX]</code>
        - The lookup result adjacency index.

    <em>Next Index:</em>
    - Dispatches the packet to the node index found in
      ip_adjacency_t @c adj->lookup_next_index
      (where @c adj is the lookup result adjacency).
*/
VLIB_NODE_FN (ip4_lookup_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return ip4_lookup_inline (vm, node, frame);
}

static u8 *format_ip4_lookup_trace (u8 * s, va_list * args);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_lookup_node) =
{
  .name = "ip4-lookup",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_lookup_trace,
  .n_next_nodes = IP_LOOKUP_N_NEXT,
  .next_nodes = IP4_LOOKUP_NEXT_NODES,
};
/* *INDENT-ON* */

VLIB_NODE_FN (ip4_load_balance_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  vlib_combined_counter_main_t *cm = &load_balance_main.lbm_via_counters;
  u32 n_left, *from;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left >= 4)
    {
      const load_balance_t *lb0, *lb1;
      const ip4_header_t *ip0, *ip1;
      u32 lbi0, hc0, lbi1, hc1;
      const dpo_id_t *dpo0, *dpo1;

      /* Prefetch next iteration. */
      {
	vlib_prefetch_buffer_header (b[2], LOAD);
	vlib_prefetch_buffer_header (b[3], LOAD);

	CLIB_PREFETCH (b[2]->data, sizeof (ip0[0]), LOAD);
	CLIB_PREFETCH (b[3]->data, sizeof (ip0[0]), LOAD);
      }

      ip0 = vlib_buffer_get_current (b[0]);
      ip1 = vlib_buffer_get_current (b[1]);
      lbi0 = vnet_buffer (b[0])->ip.adj_index[VLIB_TX];
      lbi1 = vnet_buffer (b[1])->ip.adj_index[VLIB_TX];

      lb0 = load_balance_get (lbi0);
      lb1 = load_balance_get (lbi1);

      /*
       * this node is for via FIBs we can re-use the hash value from the
       * to node if present.
       * We don't want to use the same hash value at each level in the recursion
       * graph as that would lead to polarisation
       */
      hc0 = hc1 = 0;

      if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
	{
	  if (PREDICT_TRUE (vnet_buffer (b[0])->ip.flow_hash))
	    {
	      hc0 = vnet_buffer (b[0])->ip.flow_hash =
		vnet_buffer (b[0])->ip.flow_hash >> 1;
	    }
	  else
	    {
	      hc0 = vnet_buffer (b[0])->ip.flow_hash =
		ip4_compute_flow_hash (ip0, lb0->lb_hash_config);
	    }
	  dpo0 = load_balance_get_fwd_bucket
	    (lb0, (hc0 & (lb0->lb_n_buckets_minus_1)));
	}
      else
	{
	  dpo0 = load_balance_get_bucket_i (lb0, 0);
	}
      if (PREDICT_FALSE (lb1->lb_n_buckets > 1))
	{
	  if (PREDICT_TRUE (vnet_buffer (b[1])->ip.flow_hash))
	    {
	      hc1 = vnet_buffer (b[1])->ip.flow_hash =
		vnet_buffer (b[1])->ip.flow_hash >> 1;
	    }
	  else
	    {
	      hc1 = vnet_buffer (b[1])->ip.flow_hash =
		ip4_compute_flow_hash (ip1, lb1->lb_hash_config);
	    }
	  dpo1 = load_balance_get_fwd_bucket
	    (lb1, (hc1 & (lb1->lb_n_buckets_minus_1)));
	}
      else
	{
	  dpo1 = load_balance_get_bucket_i (lb1, 0);
	}

      next[0] = dpo0->dpoi_next_node;
      next[1] = dpo1->dpoi_next_node;

      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;
      vnet_buffer (b[1])->ip.adj_index[VLIB_TX] = dpo1->dpoi_index;

      vlib_increment_combined_counter
	(cm, thread_index, lbi0, 1, vlib_buffer_length_in_chain (vm, b[0]));
      vlib_increment_combined_counter
	(cm, thread_index, lbi1, 1, vlib_buffer_length_in_chain (vm, b[1]));

      b += 2;
      next += 2;
      n_left -= 2;
    }

  while (n_left > 0)
    {
      const load_balance_t *lb0;
      const ip4_header_t *ip0;
      const dpo_id_t *dpo0;
      u32 lbi0, hc0;

      ip0 = vlib_buffer_get_current (b[0]);
      lbi0 = vnet_buffer (b[0])->ip.adj_index[VLIB_TX];

      lb0 = load_balance_get (lbi0);

      hc0 = 0;
      if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
	{
	  if (PREDICT_TRUE (vnet_buffer (b[0])->ip.flow_hash))
	    {
	      hc0 = vnet_buffer (b[0])->ip.flow_hash =
		vnet_buffer (b[0])->ip.flow_hash >> 1;
	    }
	  else
	    {
	      hc0 = vnet_buffer (b[0])->ip.flow_hash =
		ip4_compute_flow_hash (ip0, lb0->lb_hash_config);
	    }
	  dpo0 = load_balance_get_fwd_bucket
	    (lb0, (hc0 & (lb0->lb_n_buckets_minus_1)));
	}
      else
	{
	  dpo0 = load_balance_get_bucket_i (lb0, 0);
	}

      next[0] = dpo0->dpoi_next_node;
      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

      vlib_increment_combined_counter
	(cm, thread_index, lbi0, 1, vlib_buffer_length_in_chain (vm, b[0]));

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_load_balance_node) =
{
  .name = "ip4-load-balance",
  .vector_size = sizeof (u32),
  .sibling_of = "ip4-lookup",
  .format_trace = format_ip4_lookup_trace,
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
/* get first interface address */
ip4_address_t *
ip4_interface_first_address (ip4_main_t * im, u32 sw_if_index,
			     ip_interface_address_t ** result_ia)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_address_t *ia = 0;
  ip4_address_t *result = 0;

  /* *INDENT-OFF* */
  foreach_ip_interface_address
    (lm, ia, sw_if_index,
     1 /* honor unnumbered */ ,
     ({
       ip4_address_t * a =
         ip_interface_address_get_address (lm, ia);
       result = a;
       break;
     }));
  /* *INDENT-OFF* */
  if (result_ia)
    *result_ia = result ? ia : 0;
  return result;
}
#endif

static void
ip4_add_subnet_bcast_route (u32 fib_index,
                            fib_prefix_t *pfx,
                            u32 sw_if_index)
{
  vnet_sw_interface_flags_t iflags;

  iflags = vnet_sw_interface_get_flags(vnet_get_main(), sw_if_index);

  fib_table_entry_special_remove(fib_index,
                                 pfx,
                                 FIB_SOURCE_INTERFACE);

  if (iflags & VNET_SW_INTERFACE_FLAG_DIRECTED_BCAST)
    {
      fib_table_entry_update_one_path (fib_index, pfx,
                                       FIB_SOURCE_INTERFACE,
                                       FIB_ENTRY_FLAG_NONE,
                                       DPO_PROTO_IP4,
                                       /* No next-hop address */
                                       &ADJ_BCAST_ADDR,
                                       sw_if_index,
                                       // invalid FIB index
                                       ~0,
                                       1,
                                       // no out-label stack
                                       NULL,
                                       FIB_ROUTE_PATH_FLAG_NONE);
    }
  else
    {
        fib_table_entry_special_add(fib_index,
                                    pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_DROP |
                                     FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT));
    }
}

static void
ip4_add_interface_prefix_routes (ip4_main_t *im,
				 u32 sw_if_index,
				 u32 fib_index,
				 ip_interface_address_t * a)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_prefix_t *if_prefix;
  ip4_address_t *address = ip_interface_address_get_address (lm, a);

  ip_interface_prefix_key_t key = {
    .prefix = {
      .fp_len = a->address_length,
      .fp_proto = FIB_PROTOCOL_IP4,
      .fp_addr.ip4.as_u32 = address->as_u32 & im->fib_masks[a->address_length],
    },
    .sw_if_index = sw_if_index,
  };

  fib_prefix_t pfx_special = {
    .fp_proto = FIB_PROTOCOL_IP4,
  };

  /* If prefix already set on interface, just increment ref count & return */
  if_prefix = ip_get_interface_prefix (lm, &key);
  if (if_prefix)
    {
      if_prefix->ref_count += 1;
      return;
    }

  /* New prefix - allocate a pool entry, initialize it, add to the hash */
  pool_get (lm->if_prefix_pool, if_prefix);
  if_prefix->ref_count = 1;
  if_prefix->src_ia_index = a - lm->if_address_pool;
  clib_memcpy (&if_prefix->key, &key, sizeof (key));
  mhash_set (&lm->prefix_to_if_prefix_index, &key,
	     if_prefix - lm->if_prefix_pool, 0 /* old value */);

  /* length <= 30 - add glean, drop first address, maybe drop bcast address */
  if (a->address_length <= 30)
    {
      pfx_special.fp_len = a->address_length;
      pfx_special.fp_addr.ip4.as_u32 = address->as_u32;

      /* set the glean route for the prefix */
      fib_table_entry_update_one_path (fib_index, &pfx_special,
				       FIB_SOURCE_INTERFACE,
				       (FIB_ENTRY_FLAG_CONNECTED |
					FIB_ENTRY_FLAG_ATTACHED),
				       DPO_PROTO_IP4,
				       /* No next-hop address */
				       NULL,
				       sw_if_index,
                                       /* invalid FIB index */
                                       ~0,
                                       1,
                                       /* no out-label stack */
                                       NULL,
                                       FIB_ROUTE_PATH_FLAG_NONE);

      /* set a drop route for the base address of the prefix */
      pfx_special.fp_len = 32;
      pfx_special.fp_addr.ip4.as_u32 =
	address->as_u32 & im->fib_masks[a->address_length];

      if (pfx_special.fp_addr.ip4.as_u32 != address->as_u32)
	fib_table_entry_special_add (fib_index, &pfx_special,
				     FIB_SOURCE_INTERFACE,
				     (FIB_ENTRY_FLAG_DROP |
				      FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT));

      /* set a route for the broadcast address of the prefix */
      pfx_special.fp_len = 32;
      pfx_special.fp_addr.ip4.as_u32 =
	address->as_u32 | ~im->fib_masks[a->address_length];
      if (pfx_special.fp_addr.ip4.as_u32 != address->as_u32)
	ip4_add_subnet_bcast_route (fib_index, &pfx_special, sw_if_index);


    }
  /* length == 31 - add an attached route for the other address */
  else if (a->address_length == 31)
    {
      pfx_special.fp_len = 32;
      pfx_special.fp_addr.ip4.as_u32 =
	address->as_u32 ^ clib_host_to_net_u32(1);

      fib_table_entry_update_one_path (fib_index, &pfx_special,
				       FIB_SOURCE_INTERFACE,
				       (FIB_ENTRY_FLAG_ATTACHED),
				       DPO_PROTO_IP4,
				       &pfx_special.fp_addr,
				       sw_if_index,
                                       /* invalid FIB index */
                                       ~0,
                                       1,
                                       NULL,
                                       FIB_ROUTE_PATH_FLAG_NONE);
    }
}

static void
ip4_add_interface_routes (u32 sw_if_index,
			  ip4_main_t * im, u32 fib_index,
			  ip_interface_address_t * a)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip4_address_t *address = ip_interface_address_get_address (lm, a);
  fib_prefix_t pfx = {
    .fp_len = 32,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr.ip4 = *address,
  };

  /* set special routes for the prefix if needed */
  ip4_add_interface_prefix_routes (im, sw_if_index, fib_index, a);

  if (sw_if_index < vec_len (lm->classify_table_index_by_sw_if_index))
    {
      u32 classify_table_index =
	lm->classify_table_index_by_sw_if_index[sw_if_index];
      if (classify_table_index != (u32) ~ 0)
	{
	  dpo_id_t dpo = DPO_INVALID;

	  dpo_set (&dpo,
		   DPO_CLASSIFY,
		   DPO_PROTO_IP4,
		   classify_dpo_create (DPO_PROTO_IP4, classify_table_index));

	  fib_table_entry_special_dpo_add (fib_index,
					   &pfx,
					   FIB_SOURCE_CLASSIFY,
					   FIB_ENTRY_FLAG_NONE, &dpo);
	  dpo_reset (&dpo);
	}
    }

  fib_table_entry_update_one_path (fib_index, &pfx,
                                   FIB_SOURCE_INTERFACE,
                                   (FIB_ENTRY_FLAG_CONNECTED |
                                    FIB_ENTRY_FLAG_LOCAL),
                                   DPO_PROTO_IP4,
                                   &pfx.fp_addr,
                                   sw_if_index,
                                   // invalid FIB index
                                   ~0,
				   1, NULL,
				   FIB_ROUTE_PATH_FLAG_NONE);
}

static void
ip4_del_interface_prefix_routes (ip4_main_t * im,
				 u32 sw_if_index,
				 u32 fib_index,
				 ip4_address_t * address,
				 u32 address_length)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_prefix_t *if_prefix;

  ip_interface_prefix_key_t key = {
    .prefix = {
      .fp_len = address_length,
      .fp_proto = FIB_PROTOCOL_IP4,
      .fp_addr.ip4.as_u32 = address->as_u32 & im->fib_masks[address_length],
    },
    .sw_if_index = sw_if_index,
  };

  fib_prefix_t pfx_special = {
    .fp_len = 32,
    .fp_proto = FIB_PROTOCOL_IP4,
  };

  if_prefix = ip_get_interface_prefix (lm, &key);
  if (!if_prefix)
    {
      clib_warning ("Prefix not found while deleting %U",
		    format_ip4_address_and_length, address, address_length);
      return;
    }

  if_prefix->ref_count -= 1;

  /*
   * Routes need to be adjusted if:
   * - deleting last intf addr in prefix
   * - deleting intf addr used as default source address in glean adjacency
   *
   * We're done now otherwise
   */
  if ((if_prefix->ref_count > 0) &&
      !pool_is_free_index (lm->if_address_pool, if_prefix->src_ia_index))
    return;

  /* length <= 30, delete glean route, first address, last address */
  if (address_length <= 30)
    {

      /* remove glean route for prefix */
      pfx_special.fp_addr.ip4 = *address;
      pfx_special.fp_len = address_length;
      fib_table_entry_delete (fib_index, &pfx_special, FIB_SOURCE_INTERFACE);

      /* if no more intf addresses in prefix, remove other special routes */
      if (!if_prefix->ref_count)
	{
	  /* first address in prefix */
	  pfx_special.fp_addr.ip4.as_u32 =
	    address->as_u32 & im->fib_masks[address_length];
	  pfx_special.fp_len = 32;

	  if (pfx_special.fp_addr.ip4.as_u32 != address->as_u32)
	  fib_table_entry_special_remove (fib_index,
					  &pfx_special,
					  FIB_SOURCE_INTERFACE);

	  /* prefix broadcast address */
	  pfx_special.fp_addr.ip4.as_u32 =
	    address->as_u32 | ~im->fib_masks[address_length];
	  pfx_special.fp_len = 32;

	  if (pfx_special.fp_addr.ip4.as_u32 != address->as_u32)
	  fib_table_entry_special_remove (fib_index,
					  &pfx_special,
					  FIB_SOURCE_INTERFACE);
	}
      else
	/* default source addr just got deleted, find another */
	{
	  ip_interface_address_t *new_src_ia = NULL;
	  ip4_address_t *new_src_addr = NULL;

	  new_src_addr =
	    ip4_interface_address_matching_destination
	      (im, address, sw_if_index, &new_src_ia);

	  if_prefix->src_ia_index = new_src_ia - lm->if_address_pool;

	  pfx_special.fp_len = address_length;
	  pfx_special.fp_addr.ip4 = *new_src_addr;

	  /* set new glean route for the prefix */
	  fib_table_entry_update_one_path (fib_index, &pfx_special,
					   FIB_SOURCE_INTERFACE,
					   (FIB_ENTRY_FLAG_CONNECTED |
					    FIB_ENTRY_FLAG_ATTACHED),
					   DPO_PROTO_IP4,
					   /* No next-hop address */
					   NULL,
					   sw_if_index,
					   /* invalid FIB index */
					   ~0,
					   1,
					   /* no out-label stack */
					   NULL,
					   FIB_ROUTE_PATH_FLAG_NONE);
	  return;
	}
    }
  /* length == 31, delete attached route for the other address */
  else if (address_length == 31)
    {
      pfx_special.fp_addr.ip4.as_u32 =
	address->as_u32 ^ clib_host_to_net_u32(1);

      fib_table_entry_delete (fib_index, &pfx_special, FIB_SOURCE_INTERFACE);
    }

  mhash_unset (&lm->prefix_to_if_prefix_index, &key, 0 /* old_value */);
  pool_put (lm->if_prefix_pool, if_prefix);
}

static void
ip4_del_interface_routes (u32 sw_if_index,
			  ip4_main_t * im,
			  u32 fib_index,
			  ip4_address_t * address, u32 address_length)
{
  fib_prefix_t pfx = {
    .fp_len = address_length,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr.ip4 = *address,
  };

  ip4_del_interface_prefix_routes (im, sw_if_index, fib_index,
				   address, address_length);

  pfx.fp_len = 32;
  fib_table_entry_delete (fib_index, &pfx, FIB_SOURCE_INTERFACE);
}

#ifndef CLIB_MARCH_VARIANT
void
ip4_sw_interface_enable_disable (u32 sw_if_index, u32 is_enable)
{
  ip4_main_t *im = &ip4_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);

  vec_validate_init_empty (im->ip_enabled_by_sw_if_index, sw_if_index, 0);

  /*
   * enable/disable only on the 1<->0 transition
   */
  if (is_enable)
    {
      if (1 != ++im->ip_enabled_by_sw_if_index[sw_if_index])
	return;
    }
  else
    {
      ASSERT (im->ip_enabled_by_sw_if_index[sw_if_index] > 0);
      if (0 != --im->ip_enabled_by_sw_if_index[sw_if_index])
	return;
    }
  vnet_feature_enable_disable ("ip4-unicast", "ip4-not-enabled", sw_if_index,
			       !is_enable, 0, 0);


  vnet_feature_enable_disable ("ip4-multicast", "ip4-not-enabled",
			       sw_if_index, !is_enable, 0, 0);

  if (is_enable)
    hi->l3_if_count++;
  else if (hi->l3_if_count)
    hi->l3_if_count--;

  {
    ip4_enable_disable_interface_callback_t *cb;
    vec_foreach (cb, im->enable_disable_interface_callbacks)
      cb->function (im, cb->function_opaque, sw_if_index, is_enable);
  }
}

static clib_error_t *
ip4_add_del_interface_address_internal (vlib_main_t * vm,
					u32 sw_if_index,
					ip4_address_t * address,
					u32 address_length, u32 is_del)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  clib_error_t *error = 0;
  u32 if_address_index;
  ip4_address_fib_t ip4_af, *addr_fib = 0;

  /* local0 interface doesn't support IP addressing  */
  if (sw_if_index == 0)
    {
      return
       clib_error_create ("local0 interface doesn't support IP addressing");
    }

  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
  ip4_addr_fib_init (&ip4_af, address,
		     vec_elt (im->fib_index_by_sw_if_index, sw_if_index));
  vec_add1 (addr_fib, ip4_af);

  /*
   * there is no support for adj-fib handling in the presence of overlapping
   * subnets on interfaces. Easy fix - disallow overlapping subnets, like
   * most routers do.
   */
  /* *INDENT-OFF* */
  if (!is_del)
    {
      /* When adding an address check that it does not conflict
         with an existing address on any interface in this table. */
      ip_interface_address_t *ia;
      vnet_sw_interface_t *sif;

      pool_foreach(sif, vnm->interface_main.sw_interfaces,
      ({
          if (im->fib_index_by_sw_if_index[sw_if_index] ==
              im->fib_index_by_sw_if_index[sif->sw_if_index])
            {
              foreach_ip_interface_address
                (&im->lookup_main, ia, sif->sw_if_index,
                 0 /* honor unnumbered */ ,
                 ({
                   ip4_address_t * x =
                     ip_interface_address_get_address
                     (&im->lookup_main, ia);

                   if (ip4_destination_matches_route
                       (im, address, x, ia->address_length) ||
                       ip4_destination_matches_route (im,
                                                      x,
                                                      address,
                                                      address_length))
                     {
		       /* an intf may have >1 addr from the same prefix */
		       if ((sw_if_index == sif->sw_if_index) &&
			   (ia->address_length == address_length) &&
			   (x->as_u32 != address->as_u32))
		         continue;

                       if (ia->flags & IP_INTERFACE_ADDRESS_FLAG_STALE)
                         /* if the address we're comparing against is stale
                          * then the CP has not added this one back yet, maybe
                          * it never will, so we have to assume it won't and
                          * ignore it. if it does add it back, then it will fail
                          * because this one is now present */
                         continue;

		       /* error if the length or intf was different */
                       vnm->api_errno = VNET_API_ERROR_ADDRESS_IN_USE;

                       error = clib_error_create
                         ("failed to add %U on %U which conflicts with %U for interface %U",
                          format_ip4_address_and_length, address,
                          address_length,
			  format_vnet_sw_if_index_name, vnm,
			  sw_if_index,
                          format_ip4_address_and_length, x,
                          ia->address_length,
                          format_vnet_sw_if_index_name, vnm,
                          sif->sw_if_index);
                       goto done;
                     }
                 }));
            }
      }));
    }
  /* *INDENT-ON* */

  if_address_index = ip_interface_address_find (lm, addr_fib, address_length);

  if (is_del)
    {
      if (~0 == if_address_index)
	{
	  vnm->api_errno = VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE;
	  error = clib_error_create ("%U not found for interface %U",
				     lm->format_address_and_length,
				     addr_fib, address_length,
				     format_vnet_sw_if_index_name, vnm,
				     sw_if_index);
	  goto done;
	}

      error = ip_interface_address_del (lm, vnm, if_address_index, addr_fib,
					address_length, sw_if_index);
      if (error)
	goto done;
    }
  else
    {
      if (~0 != if_address_index)
	{
	  ip_interface_address_t *ia;

	  ia = pool_elt_at_index (lm->if_address_pool, if_address_index);

	  if (ia->flags & IP_INTERFACE_ADDRESS_FLAG_STALE)
	    {
	      if (ia->sw_if_index == sw_if_index)
		{
		  /* re-adding an address during the replace action.
		   * consdier this the update. clear the flag and
		   * we're done */
		  ia->flags &= ~IP_INTERFACE_ADDRESS_FLAG_STALE;
		  goto done;
		}
	      else
		{
		  /* The prefix is moving from one interface to another.
		   * delete the stale and add the new */
		  ip4_add_del_interface_address_internal (vm,
							  ia->sw_if_index,
							  address,
							  address_length, 1);
		  ia = NULL;
		  error = ip_interface_address_add (lm, sw_if_index,
						    addr_fib, address_length,
						    &if_address_index);
		}
	    }
	  else
	    {
	      vnm->api_errno = VNET_API_ERROR_DUPLICATE_IF_ADDRESS;
	      error = clib_error_create
		("Prefix %U already found on interface %U",
		 lm->format_address_and_length, addr_fib, address_length,
		 format_vnet_sw_if_index_name, vnm, ia->sw_if_index);
	    }
	}
      else
	error = ip_interface_address_add (lm, sw_if_index,
					  addr_fib, address_length,
					  &if_address_index);
    }

  if (error)
    goto done;

  ip4_sw_interface_enable_disable (sw_if_index, !is_del);
  ip4_mfib_interface_enable_disable (sw_if_index, !is_del);

  /* intf addr routes are added/deleted on admin up/down */
  if (vnet_sw_interface_is_admin_up (vnm, sw_if_index))
    {
      if (is_del)
	ip4_del_interface_routes (sw_if_index,
				  im, ip4_af.fib_index, address,
				  address_length);
      else
	ip4_add_interface_routes (sw_if_index,
				  im, ip4_af.fib_index,
				  pool_elt_at_index
				  (lm->if_address_pool, if_address_index));
    }

  ip4_add_del_interface_address_callback_t *cb;
  vec_foreach (cb, im->add_del_interface_address_callbacks)
    cb->function (im, cb->function_opaque, sw_if_index,
		  address, address_length, if_address_index, is_del);

done:
  vec_free (addr_fib);
  return error;
}

clib_error_t *
ip4_add_del_interface_address (vlib_main_t * vm,
			       u32 sw_if_index,
			       ip4_address_t * address,
			       u32 address_length, u32 is_del)
{
  return ip4_add_del_interface_address_internal
    (vm, sw_if_index, address, address_length, is_del);
}

void
ip4_directed_broadcast (u32 sw_if_index, u8 enable)
{
  ip_interface_address_t *ia;
  ip4_main_t *im;

  im = &ip4_main;

  /*
   * when directed broadcast is enabled, the subnet braodcast route will forward
   * packets using an adjacency with a broadcast MAC. otherwise it drops
   */
  /* *INDENT-OFF* */
  foreach_ip_interface_address(&im->lookup_main, ia,
                               sw_if_index, 0,
     ({
       if (ia->address_length <= 30)
         {
           ip4_address_t *ipa;

           ipa = ip_interface_address_get_address (&im->lookup_main, ia);

           fib_prefix_t pfx = {
             .fp_len = 32,
             .fp_proto = FIB_PROTOCOL_IP4,
             .fp_addr = {
               .ip4.as_u32 = (ipa->as_u32 | ~im->fib_masks[ia->address_length]),
             },
           };

           ip4_add_subnet_bcast_route
             (fib_table_get_index_for_sw_if_index(FIB_PROTOCOL_IP4,
                                                  sw_if_index),
              &pfx, sw_if_index);
         }
     }));
  /* *INDENT-ON* */
}
#endif

static clib_error_t *
ip4_sw_interface_admin_up_down (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  ip4_main_t *im = &ip4_main;
  ip_interface_address_t *ia;
  ip4_address_t *a;
  u32 is_admin_up, fib_index;

  /* Fill in lookup tables with default table (0). */
  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);

  vec_validate_init_empty (im->
			   lookup_main.if_address_pool_index_by_sw_if_index,
			   sw_if_index, ~0);

  is_admin_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  fib_index = vec_elt (im->fib_index_by_sw_if_index, sw_if_index);

  /* *INDENT-OFF* */
  foreach_ip_interface_address (&im->lookup_main, ia, sw_if_index,
                                0 /* honor unnumbered */,
  ({
    a = ip_interface_address_get_address (&im->lookup_main, ia);
    if (is_admin_up)
      ip4_add_interface_routes (sw_if_index,
				im, fib_index,
				ia);
    else
      ip4_del_interface_routes (sw_if_index,
				im, fib_index,
				a, ia->address_length);
  }));
  /* *INDENT-ON* */

  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (ip4_sw_interface_admin_up_down);

/* Built-in ip4 unicast rx feature path definition */
/* *INDENT-OFF* */
VNET_FEATURE_ARC_INIT (ip4_unicast, static) =
{
  .arc_name = "ip4-unicast",
  .start_nodes = VNET_FEATURES ("ip4-input", "ip4-input-no-checksum"),
  .last_in_arc = "ip4-lookup",
  .arc_index_ptr = &ip4_main.lookup_main.ucast_feature_arc_index,
};

VNET_FEATURE_INIT (ip4_flow_classify, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-flow-classify",
  .runs_before = VNET_FEATURES ("ip4-inacl"),
};

VNET_FEATURE_INIT (ip4_inacl, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-inacl",
  .runs_before = VNET_FEATURES ("ip4-policer-classify"),
};

VNET_FEATURE_INIT (ip4_source_and_port_range_check_rx, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-source-and-port-range-check-rx",
  .runs_before = VNET_FEATURES ("ip4-policer-classify"),
};

VNET_FEATURE_INIT (ip4_policer_classify, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-policer-classify",
  .runs_before = VNET_FEATURES ("ipsec4-input-feature"),
};

VNET_FEATURE_INIT (ip4_ipsec, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ipsec4-input-feature",
  .runs_before = VNET_FEATURES ("vpath-input-ip4"),
};

VNET_FEATURE_INIT (ip4_vpath, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "vpath-input-ip4",
  .runs_before = VNET_FEATURES ("ip4-vxlan-bypass"),
};

VNET_FEATURE_INIT (ip4_vxlan_bypass, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-vxlan-bypass",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (ip4_not_enabled, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-not-enabled",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (ip4_lookup, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-lookup",
  .runs_before = 0,	/* not before any other features */
};

/* Built-in ip4 multicast rx feature path definition */
VNET_FEATURE_ARC_INIT (ip4_multicast, static) =
{
  .arc_name = "ip4-multicast",
  .start_nodes = VNET_FEATURES ("ip4-input", "ip4-input-no-checksum"),
  .last_in_arc = "ip4-mfib-forward-lookup",
  .arc_index_ptr = &ip4_main.lookup_main.mcast_feature_arc_index,
};

VNET_FEATURE_INIT (ip4_vpath_mc, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "vpath-input-ip4",
  .runs_before = VNET_FEATURES ("ip4-mfib-forward-lookup"),
};

VNET_FEATURE_INIT (ip4_mc_not_enabled, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "ip4-not-enabled",
  .runs_before = VNET_FEATURES ("ip4-mfib-forward-lookup"),
};

VNET_FEATURE_INIT (ip4_lookup_mc, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "ip4-mfib-forward-lookup",
  .runs_before = 0,	/* last feature */
};

/* Source and port-range check ip4 tx feature path definition */
VNET_FEATURE_ARC_INIT (ip4_output, static) =
{
  .arc_name = "ip4-output",
  .start_nodes = VNET_FEATURES ("ip4-rewrite", "ip4-midchain", "ip4-dvr-dpo"),
  .last_in_arc = "interface-output",
  .arc_index_ptr = &ip4_main.lookup_main.output_feature_arc_index,
};

VNET_FEATURE_INIT (ip4_source_and_port_range_check_tx, static) =
{
  .arc_name = "ip4-output",
  .node_name = "ip4-source-and-port-range-check-tx",
  .runs_before = VNET_FEATURES ("ip4-outacl"),
};

VNET_FEATURE_INIT (ip4_outacl, static) =
{
  .arc_name = "ip4-output",
  .node_name = "ip4-outacl",
  .runs_before = VNET_FEATURES ("ipsec4-output-feature"),
};

VNET_FEATURE_INIT (ip4_ipsec_output, static) =
{
  .arc_name = "ip4-output",
  .node_name = "ipsec4-output-feature",
  .runs_before = VNET_FEATURES ("interface-output"),
};

/* Built-in ip4 tx feature path definition */
VNET_FEATURE_INIT (ip4_interface_output, static) =
{
  .arc_name = "ip4-output",
  .node_name = "interface-output",
  .runs_before = 0,	/* not before any other features */
};
/* *INDENT-ON* */

static clib_error_t *
ip4_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  ip4_main_t *im = &ip4_main;

  /* Fill in lookup tables with default table (0). */
  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
  vec_validate (im->mfib_index_by_sw_if_index, sw_if_index);

  if (!is_add)
    {
      ip4_main_t *im4 = &ip4_main;
      ip_lookup_main_t *lm4 = &im4->lookup_main;
      ip_interface_address_t *ia = 0;
      ip4_address_t *address;
      vlib_main_t *vm = vlib_get_main ();

      vnet_sw_interface_update_unnumbered (sw_if_index, ~0, 0);
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm4, ia, sw_if_index, 0,
      ({
        address = ip_interface_address_get_address (lm4, ia);
        ip4_add_del_interface_address(vm, sw_if_index, address, ia->address_length, 1);
      }));
      /* *INDENT-ON* */
      ip4_mfib_interface_enable_disable (sw_if_index, 0);
    }

  vnet_feature_enable_disable ("ip4-unicast", "ip4-not-enabled", sw_if_index,
			       is_add, 0, 0);

  vnet_feature_enable_disable ("ip4-multicast", "ip4-not-enabled",
			       sw_if_index, is_add, 0, 0);

  return /* no error */ 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ip4_sw_interface_add_del);

/* Global IP4 main. */
#ifndef CLIB_MARCH_VARIANT
ip4_main_t ip4_main;
#endif /* CLIB_MARCH_VARIANT */

static clib_error_t *
ip4_lookup_init (vlib_main_t * vm)
{
  ip4_main_t *im = &ip4_main;
  clib_error_t *error;
  uword i;

  if ((error = vlib_call_init_function (vm, vnet_feature_init)))
    return error;
  if ((error = vlib_call_init_function (vm, ip4_mtrie_module_init)))
    return (error);
  if ((error = vlib_call_init_function (vm, fib_module_init)))
    return error;
  if ((error = vlib_call_init_function (vm, mfib_module_init)))
    return error;

  for (i = 0; i < ARRAY_LEN (im->fib_masks); i++)
    {
      u32 m;

      if (i < 32)
	m = pow2_mask (i) << (32 - i);
      else
	m = ~0;
      im->fib_masks[i] = clib_host_to_net_u32 (m);
    }

  ip_lookup_init (&im->lookup_main, /* is_ip6 */ 0);

  /* Create FIB with index 0 and table id of 0. */
  fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, 0,
				     FIB_SOURCE_DEFAULT_ROUTE);
  mfib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, 0,
				      MFIB_SOURCE_DEFAULT_ROUTE);

  {
    pg_node_t *pn;
    pn = pg_get_node (ip4_lookup_node.index);
    pn->unformat_edit = unformat_pg_ip4_header;
  }

  {
    ethernet_arp_header_t h;

    clib_memset (&h, 0, sizeof (h));

#define _16(f,v) h.f = clib_host_to_net_u16 (v);
#define _8(f,v) h.f = v;
    _16 (l2_type, ETHERNET_ARP_HARDWARE_TYPE_ethernet);
    _16 (l3_type, ETHERNET_TYPE_IP4);
    _8 (n_l2_address_bytes, 6);
    _8 (n_l3_address_bytes, 4);
    _16 (opcode, ETHERNET_ARP_OPCODE_request);
#undef _16
#undef _8

    vlib_packet_template_init (vm, &im->ip4_arp_request_packet_template,
			       /* data */ &h,
			       sizeof (h),
			       /* alloc chunk size */ 8,
			       "ip4 arp");
  }

  return error;
}

VLIB_INIT_FUNCTION (ip4_lookup_init);

typedef struct
{
  /* Adjacency taken. */
  u32 dpo_index;
  u32 flow_hash;
  u32 fib_index;

  /* Packet data, possibly *after* rewrite. */
  u8 packet_data[64 - 1 * sizeof (u32)];
}
ip4_forward_next_trace_t;

#ifndef CLIB_MARCH_VARIANT
u8 *
format_ip4_forward_next_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_forward_next_trace_t *t = va_arg (*args, ip4_forward_next_trace_t *);
  u32 indent = format_get_indent (s);
  s = format (s, "%U%U",
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}
#endif

static u8 *
format_ip4_lookup_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_forward_next_trace_t *t = va_arg (*args, ip4_forward_next_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "fib %d dpo-idx %d flow hash: 0x%08x",
	      t->fib_index, t->dpo_index, t->flow_hash);
  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static u8 *
format_ip4_rewrite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_forward_next_trace_t *t = va_arg (*args, ip4_forward_next_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "tx_sw_if_index %d dpo-idx %d : %U flow hash: 0x%08x",
	      t->fib_index, t->dpo_index, format_ip_adjacency,
	      t->dpo_index, FORMAT_IP_ADJACENCY_NONE, t->flow_hash);
  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_ip_adjacency_packet_data,
	      t->packet_data, sizeof (t->packet_data));
  return s;
}

#ifndef CLIB_MARCH_VARIANT
/* Common trace function for all ip4-forward next nodes. */
void
ip4_forward_next_trace (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * frame, vlib_rx_or_tx_t which_adj_index)
{
  u32 *from, n_left;
  ip4_main_t *im = &ip4_main;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      ip4_forward_next_trace_t *t0, *t1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
      vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

      bi0 = from[0];
      bi1 = from[1];

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->dpo_index = vnet_buffer (b0)->ip.adj_index[which_adj_index];
	  t0->flow_hash = vnet_buffer (b0)->ip.flow_hash;
	  t0->fib_index =
	    (vnet_buffer (b0)->sw_if_index[VLIB_TX] !=
	     (u32) ~ 0) ? vnet_buffer (b0)->sw_if_index[VLIB_TX] :
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (b0)->sw_if_index[VLIB_RX]);

	  clib_memcpy_fast (t0->packet_data,
			    vlib_buffer_get_current (b0),
			    sizeof (t0->packet_data));
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
	  t1->dpo_index = vnet_buffer (b1)->ip.adj_index[which_adj_index];
	  t1->flow_hash = vnet_buffer (b1)->ip.flow_hash;
	  t1->fib_index =
	    (vnet_buffer (b1)->sw_if_index[VLIB_TX] !=
	     (u32) ~ 0) ? vnet_buffer (b1)->sw_if_index[VLIB_TX] :
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (b1)->sw_if_index[VLIB_RX]);
	  clib_memcpy_fast (t1->packet_data, vlib_buffer_get_current (b1),
			    sizeof (t1->packet_data));
	}
      from += 2;
      n_left -= 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      ip4_forward_next_trace_t *t0;

      bi0 = from[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->dpo_index = vnet_buffer (b0)->ip.adj_index[which_adj_index];
	  t0->flow_hash = vnet_buffer (b0)->ip.flow_hash;
	  t0->fib_index =
	    (vnet_buffer (b0)->sw_if_index[VLIB_TX] !=
	     (u32) ~ 0) ? vnet_buffer (b0)->sw_if_index[VLIB_TX] :
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	  clib_memcpy_fast (t0->packet_data, vlib_buffer_get_current (b0),
			    sizeof (t0->packet_data));
	}
      from += 1;
      n_left -= 1;
    }
}

/* Compute TCP/UDP/ICMP4 checksum in software. */
u16
ip4_tcp_udp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
			      ip4_header_t * ip0)
{
  ip_csum_t sum0;
  u32 ip_header_length, payload_length_host_byte_order;

  /* Initialize checksum with ip header. */
  ip_header_length = ip4_header_bytes (ip0);
  payload_length_host_byte_order =
    clib_net_to_host_u16 (ip0->length) - ip_header_length;
  sum0 =
    clib_host_to_net_u32 (payload_length_host_byte_order +
			  (ip0->protocol << 16));

  if (BITS (uword) == 32)
    {
      sum0 =
	ip_csum_with_carry (sum0,
			    clib_mem_unaligned (&ip0->src_address, u32));
      sum0 =
	ip_csum_with_carry (sum0,
			    clib_mem_unaligned (&ip0->dst_address, u32));
    }
  else
    sum0 =
      ip_csum_with_carry (sum0, clib_mem_unaligned (&ip0->src_address, u64));

  return ip_calculate_l4_checksum (vm, p0, sum0,
				   payload_length_host_byte_order, (u8 *) ip0,
				   ip_header_length, NULL);
}

u32
ip4_tcp_udp_validate_checksum (vlib_main_t * vm, vlib_buffer_t * p0)
{
  ip4_header_t *ip0 = vlib_buffer_get_current (p0);
  udp_header_t *udp0;
  u16 sum16;

  ASSERT (ip0->protocol == IP_PROTOCOL_TCP
	  || ip0->protocol == IP_PROTOCOL_UDP);

  udp0 = (void *) (ip0 + 1);
  if (ip0->protocol == IP_PROTOCOL_UDP && udp0->checksum == 0)
    {
      p0->flags |= (VNET_BUFFER_F_L4_CHECKSUM_COMPUTED
		    | VNET_BUFFER_F_L4_CHECKSUM_CORRECT);
      return p0->flags;
    }

  sum16 = ip4_tcp_udp_compute_checksum (vm, p0, ip0);

  p0->flags |= (VNET_BUFFER_F_L4_CHECKSUM_COMPUTED
		| ((sum16 == 0) << VNET_BUFFER_F_LOG2_L4_CHECKSUM_CORRECT));

  return p0->flags;
}
#endif

/* *INDENT-OFF* */
VNET_FEATURE_ARC_INIT (ip4_local) =
{
  .arc_name  = "ip4-local",
  .start_nodes = VNET_FEATURES ("ip4-local"),
  .last_in_arc = "ip4-local-end-of-arc",
};
/* *INDENT-ON* */

static inline void
ip4_local_l4_csum_validate (vlib_main_t * vm, vlib_buffer_t * p,
			    ip4_header_t * ip, u8 is_udp, u8 * error,
			    u8 * good_tcp_udp)
{
  u32 flags0;
  flags0 = ip4_tcp_udp_validate_checksum (vm, p);
  *good_tcp_udp = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
  if (is_udp)
    {
      udp_header_t *udp;
      u32 ip_len, udp_len;
      i32 len_diff;
      udp = ip4_next_header (ip);
      /* Verify UDP length. */
      ip_len = clib_net_to_host_u16 (ip->length);
      udp_len = clib_net_to_host_u16 (udp->length);

      len_diff = ip_len - udp_len;
      *good_tcp_udp &= len_diff >= 0;
      *error = len_diff < 0 ? IP4_ERROR_UDP_LENGTH : *error;
    }
}

#define ip4_local_csum_is_offloaded(_b)					\
    (_b->flags & VNET_BUFFER_F_OFFLOAD &&                         \
    vnet_buffer2(_b)->oflags & (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM		\
	| VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))

#define ip4_local_need_csum_check(is_tcp_udp, _b) 			\
    (is_tcp_udp && !(_b->flags & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED 	\
	|| ip4_local_csum_is_offloaded (_b)))

#define ip4_local_csum_is_valid(_b)					\
    (_b->flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT			\
	|| (ip4_local_csum_is_offloaded (_b))) != 0

static inline void
ip4_local_check_l4_csum (vlib_main_t * vm, vlib_buffer_t * b,
			 ip4_header_t * ih, u8 * error)
{
  u8 is_udp, is_tcp_udp, good_tcp_udp;

  is_udp = ih->protocol == IP_PROTOCOL_UDP;
  is_tcp_udp = is_udp || ih->protocol == IP_PROTOCOL_TCP;

  if (PREDICT_FALSE (ip4_local_need_csum_check (is_tcp_udp, b)))
    ip4_local_l4_csum_validate (vm, b, ih, is_udp, error, &good_tcp_udp);
  else
    good_tcp_udp = ip4_local_csum_is_valid (b);

  ASSERT (IP4_ERROR_TCP_CHECKSUM + 1 == IP4_ERROR_UDP_CHECKSUM);
  *error = (is_tcp_udp && !good_tcp_udp
	    ? IP4_ERROR_TCP_CHECKSUM + is_udp : *error);
}

static inline void
ip4_local_check_l4_csum_x2 (vlib_main_t * vm, vlib_buffer_t ** b,
			    ip4_header_t ** ih, u8 * error)
{
  u8 is_udp[2], is_tcp_udp[2], good_tcp_udp[2];

  is_udp[0] = ih[0]->protocol == IP_PROTOCOL_UDP;
  is_udp[1] = ih[1]->protocol == IP_PROTOCOL_UDP;

  is_tcp_udp[0] = is_udp[0] || ih[0]->protocol == IP_PROTOCOL_TCP;
  is_tcp_udp[1] = is_udp[1] || ih[1]->protocol == IP_PROTOCOL_TCP;

  good_tcp_udp[0] = ip4_local_csum_is_valid (b[0]);
  good_tcp_udp[1] = ip4_local_csum_is_valid (b[1]);

  if (PREDICT_FALSE (ip4_local_need_csum_check (is_tcp_udp[0], b[0])
		     || ip4_local_need_csum_check (is_tcp_udp[1], b[1])))
    {
      if (is_tcp_udp[0])
	ip4_local_l4_csum_validate (vm, b[0], ih[0], is_udp[0], &error[0],
				    &good_tcp_udp[0]);
      if (is_tcp_udp[1])
	ip4_local_l4_csum_validate (vm, b[1], ih[1], is_udp[1], &error[1],
				    &good_tcp_udp[1]);
    }

  error[0] = (is_tcp_udp[0] && !good_tcp_udp[0] ?
	      IP4_ERROR_TCP_CHECKSUM + is_udp[0] : error[0]);
  error[1] = (is_tcp_udp[1] && !good_tcp_udp[1] ?
	      IP4_ERROR_TCP_CHECKSUM + is_udp[1] : error[1]);
}

static inline void
ip4_local_set_next_and_error (vlib_node_runtime_t * error_node,
			      vlib_buffer_t * b, u16 * next, u8 error,
			      u8 head_of_feature_arc)
{
  u8 arc_index = vnet_feat_arc_ip4_local.feature_arc_index;
  u32 next_index;

  *next = error != IP4_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : *next;
  b->error = error ? error_node->errors[error] : 0;
  if (head_of_feature_arc)
    {
      next_index = *next;
      if (PREDICT_TRUE (error == (u8) IP4_ERROR_UNKNOWN_PROTOCOL))
	{
	  vnet_feature_arc_start (arc_index,
				  vnet_buffer (b)->sw_if_index[VLIB_RX],
				  &next_index, b);
	  *next = next_index;
	}
    }
}

typedef struct
{
  ip4_address_t src;
  u32 lbi;
  u8 error;
  u8 first;
} ip4_local_last_check_t;

static inline void
ip4_local_check_src (vlib_buffer_t * b, ip4_header_t * ip0,
		     ip4_local_last_check_t * last_check, u8 * error0)
{
  ip4_fib_mtrie_leaf_t leaf0;
  ip4_fib_mtrie_t *mtrie0;
  const dpo_id_t *dpo0;
  load_balance_t *lb0;
  u32 lbi0;

  vnet_buffer (b)->ip.fib_index =
    vnet_buffer (b)->sw_if_index[VLIB_TX] != ~0 ?
    vnet_buffer (b)->sw_if_index[VLIB_TX] : vnet_buffer (b)->ip.fib_index;

  /*
   * vnet_buffer()->ip.adj_index[VLIB_RX] will be set to the index of the
   *  adjacency for the destination address (the local interface address).
   * vnet_buffer()->ip.adj_index[VLIB_TX] will be set to the index of the
   *  adjacency for the source address (the remote sender's address)
   */
  if (PREDICT_TRUE (last_check->src.as_u32 != ip0->src_address.as_u32) ||
      last_check->first)
    {
      mtrie0 = &ip4_fib_get (vnet_buffer (b)->ip.fib_index)->mtrie;
      leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, &ip0->src_address);
      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 2);
      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 3);
      lbi0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);

      vnet_buffer (b)->ip.adj_index[VLIB_RX] =
	vnet_buffer (b)->ip.adj_index[VLIB_TX];
      vnet_buffer (b)->ip.adj_index[VLIB_TX] = lbi0;

      lb0 = load_balance_get (lbi0);
      dpo0 = load_balance_get_bucket_i (lb0, 0);

      /*
       * Must have a route to source otherwise we drop the packet.
       * ip4 broadcasts are accepted, e.g. to make dhcp client work
       *
       * The checks are:
       *  - the source is a recieve => it's from us => bogus, do this
       *    first since it sets a different error code.
       *  - uRPF check for any route to source - accept if passes.
       *  - allow packets destined to the broadcast address from unknown sources
       */

      *error0 = ((*error0 == IP4_ERROR_UNKNOWN_PROTOCOL
		  && dpo0->dpoi_type == DPO_RECEIVE) ?
		 IP4_ERROR_SPOOFED_LOCAL_PACKETS : *error0);
      *error0 = ((*error0 == IP4_ERROR_UNKNOWN_PROTOCOL
		  && !fib_urpf_check_size (lb0->lb_urpf)
		  && ip0->dst_address.as_u32 != 0xFFFFFFFF) ?
		 IP4_ERROR_SRC_LOOKUP_MISS : *error0);

      last_check->src.as_u32 = ip0->src_address.as_u32;
      last_check->lbi = lbi0;
      last_check->error = *error0;
      last_check->first = 0;
    }
  else
    {
      vnet_buffer (b)->ip.adj_index[VLIB_RX] =
	vnet_buffer (b)->ip.adj_index[VLIB_TX];
      vnet_buffer (b)->ip.adj_index[VLIB_TX] = last_check->lbi;
      *error0 = last_check->error;
    }
}

static inline void
ip4_local_check_src_x2 (vlib_buffer_t ** b, ip4_header_t ** ip,
			ip4_local_last_check_t * last_check, u8 * error)
{
  ip4_fib_mtrie_leaf_t leaf[2];
  ip4_fib_mtrie_t *mtrie[2];
  const dpo_id_t *dpo[2];
  load_balance_t *lb[2];
  u32 not_last_hit;
  u32 lbi[2];

  not_last_hit = last_check->first;
  not_last_hit |= ip[0]->src_address.as_u32 ^ last_check->src.as_u32;
  not_last_hit |= ip[1]->src_address.as_u32 ^ last_check->src.as_u32;

  vnet_buffer (b[0])->ip.fib_index =
    vnet_buffer (b[0])->sw_if_index[VLIB_TX] != ~0 ?
    vnet_buffer (b[0])->sw_if_index[VLIB_TX] :
    vnet_buffer (b[0])->ip.fib_index;

  vnet_buffer (b[1])->ip.fib_index =
    vnet_buffer (b[1])->sw_if_index[VLIB_TX] != ~0 ?
    vnet_buffer (b[1])->sw_if_index[VLIB_TX] :
    vnet_buffer (b[1])->ip.fib_index;

  /*
   * vnet_buffer()->ip.adj_index[VLIB_RX] will be set to the index of the
   *  adjacency for the destination address (the local interface address).
   * vnet_buffer()->ip.adj_index[VLIB_TX] will be set to the index of the
   *  adjacency for the source address (the remote sender's address)
   */
  if (PREDICT_TRUE (not_last_hit))
    {
      mtrie[0] = &ip4_fib_get (vnet_buffer (b[0])->ip.fib_index)->mtrie;
      mtrie[1] = &ip4_fib_get (vnet_buffer (b[1])->ip.fib_index)->mtrie;

      leaf[0] = ip4_fib_mtrie_lookup_step_one (mtrie[0], &ip[0]->src_address);
      leaf[1] = ip4_fib_mtrie_lookup_step_one (mtrie[1], &ip[1]->src_address);

      leaf[0] = ip4_fib_mtrie_lookup_step (mtrie[0], leaf[0],
					   &ip[0]->src_address, 2);
      leaf[1] = ip4_fib_mtrie_lookup_step (mtrie[1], leaf[1],
					   &ip[1]->src_address, 2);

      leaf[0] = ip4_fib_mtrie_lookup_step (mtrie[0], leaf[0],
					   &ip[0]->src_address, 3);
      leaf[1] = ip4_fib_mtrie_lookup_step (mtrie[1], leaf[1],
					   &ip[1]->src_address, 3);

      lbi[0] = ip4_fib_mtrie_leaf_get_adj_index (leaf[0]);
      lbi[1] = ip4_fib_mtrie_leaf_get_adj_index (leaf[1]);

      vnet_buffer (b[0])->ip.adj_index[VLIB_RX] =
	vnet_buffer (b[0])->ip.adj_index[VLIB_TX];
      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = lbi[0];

      vnet_buffer (b[1])->ip.adj_index[VLIB_RX] =
	vnet_buffer (b[1])->ip.adj_index[VLIB_TX];
      vnet_buffer (b[1])->ip.adj_index[VLIB_TX] = lbi[1];

      lb[0] = load_balance_get (lbi[0]);
      lb[1] = load_balance_get (lbi[1]);

      dpo[0] = load_balance_get_bucket_i (lb[0], 0);
      dpo[1] = load_balance_get_bucket_i (lb[1], 0);

      error[0] = ((error[0] == IP4_ERROR_UNKNOWN_PROTOCOL &&
		   dpo[0]->dpoi_type == DPO_RECEIVE) ?
		  IP4_ERROR_SPOOFED_LOCAL_PACKETS : error[0]);
      error[0] = ((error[0] == IP4_ERROR_UNKNOWN_PROTOCOL &&
		   !fib_urpf_check_size (lb[0]->lb_urpf) &&
		   ip[0]->dst_address.as_u32 != 0xFFFFFFFF)
		  ? IP4_ERROR_SRC_LOOKUP_MISS : error[0]);

      error[1] = ((error[1] == IP4_ERROR_UNKNOWN_PROTOCOL &&
		   dpo[1]->dpoi_type == DPO_RECEIVE) ?
		  IP4_ERROR_SPOOFED_LOCAL_PACKETS : error[1]);
      error[1] = ((error[1] == IP4_ERROR_UNKNOWN_PROTOCOL &&
		   !fib_urpf_check_size (lb[1]->lb_urpf) &&
		   ip[1]->dst_address.as_u32 != 0xFFFFFFFF)
		  ? IP4_ERROR_SRC_LOOKUP_MISS : error[1]);

      last_check->src.as_u32 = ip[1]->src_address.as_u32;
      last_check->lbi = lbi[1];
      last_check->error = error[1];
      last_check->first = 0;
    }
  else
    {
      vnet_buffer (b[0])->ip.adj_index[VLIB_RX] =
	vnet_buffer (b[0])->ip.adj_index[VLIB_TX];
      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = last_check->lbi;

      vnet_buffer (b[1])->ip.adj_index[VLIB_RX] =
	vnet_buffer (b[1])->ip.adj_index[VLIB_TX];
      vnet_buffer (b[1])->ip.adj_index[VLIB_TX] = last_check->lbi;

      error[0] = last_check->error;
      error[1] = last_check->error;
    }
}

enum ip_local_packet_type_e
{
  IP_LOCAL_PACKET_TYPE_L4,
  IP_LOCAL_PACKET_TYPE_NAT,
  IP_LOCAL_PACKET_TYPE_FRAG,
};

/**
 * Determine packet type and next node.
 *
 * The expectation is that all packets that are not L4 will skip
 * checksums and source checks.
 */
always_inline u8
ip4_local_classify (vlib_buffer_t * b, ip4_header_t * ip, u16 * next)
{
  ip_lookup_main_t *lm = &ip4_main.lookup_main;

  if (PREDICT_FALSE (ip4_is_fragment (ip)))
    {
      *next = IP_LOCAL_NEXT_REASSEMBLY;
      return IP_LOCAL_PACKET_TYPE_FRAG;
    }
  if (PREDICT_FALSE (b->flags & VNET_BUFFER_F_IS_NATED))
    {
      *next = lm->local_next_by_ip_protocol[ip->protocol];
      return IP_LOCAL_PACKET_TYPE_NAT;
    }

  *next = lm->local_next_by_ip_protocol[ip->protocol];
  return IP_LOCAL_PACKET_TYPE_L4;
}

static inline uword
ip4_local_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame, int head_of_feature_arc)
{
  u32 *from, n_left_from;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_local_node.index);
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  ip4_header_t *ip[2];
  u8 error[2], pt[2];

  ip4_local_last_check_t last_check = {
    /*
     * 0.0.0.0 can appear as the source address of an IP packet,
     * as can any other address, hence the need to use the 'first'
     * member to make sure the .lbi is initialised for the first
     * packet.
     */
    .src = {.as_u32 = 0},
    .lbi = ~0,
    .error = IP4_ERROR_UNKNOWN_PROTOCOL,
    .first = 1,
  };

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from >= 6)
    {
      u8 not_batch = 0;

      /* Prefetch next iteration. */
      {
	vlib_prefetch_buffer_header (b[4], LOAD);
	vlib_prefetch_buffer_header (b[5], LOAD);

	CLIB_PREFETCH (b[4]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	CLIB_PREFETCH (b[5]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      }

      error[0] = error[1] = IP4_ERROR_UNKNOWN_PROTOCOL;

      ip[0] = vlib_buffer_get_current (b[0]);
      ip[1] = vlib_buffer_get_current (b[1]);

      vnet_buffer (b[0])->l3_hdr_offset = b[0]->current_data;
      vnet_buffer (b[1])->l3_hdr_offset = b[1]->current_data;

      pt[0] = ip4_local_classify (b[0], ip[0], &next[0]);
      pt[1] = ip4_local_classify (b[1], ip[1], &next[1]);

      not_batch = pt[0] ^ pt[1];

      if (head_of_feature_arc == 0 || (pt[0] && not_batch == 0))
	goto skip_checks;

      if (PREDICT_TRUE (not_batch == 0))
	{
	  ip4_local_check_l4_csum_x2 (vm, b, ip, error);
	  ip4_local_check_src_x2 (b, ip, &last_check, error);
	}
      else
	{
	  if (!pt[0])
	    {
	      ip4_local_check_l4_csum (vm, b[0], ip[0], &error[0]);
	      ip4_local_check_src (b[0], ip[0], &last_check, &error[0]);
	    }
	  if (!pt[1])
	    {
	      ip4_local_check_l4_csum (vm, b[1], ip[1], &error[1]);
	      ip4_local_check_src (b[1], ip[1], &last_check, &error[1]);
	    }
	}

    skip_checks:

      ip4_local_set_next_and_error (error_node, b[0], &next[0], error[0],
				    head_of_feature_arc);
      ip4_local_set_next_and_error (error_node, b[1], &next[1], error[1],
				    head_of_feature_arc);

      b += 2;
      next += 2;
      n_left_from -= 2;
    }

  while (n_left_from > 0)
    {
      error[0] = IP4_ERROR_UNKNOWN_PROTOCOL;

      ip[0] = vlib_buffer_get_current (b[0]);
      vnet_buffer (b[0])->l3_hdr_offset = b[0]->current_data;
      pt[0] = ip4_local_classify (b[0], ip[0], &next[0]);

      if (head_of_feature_arc == 0 || pt[0])
	goto skip_check;

      ip4_local_check_l4_csum (vm, b[0], ip[0], &error[0]);
      ip4_local_check_src (b[0], ip[0], &last_check, &error[0]);

    skip_check:

      ip4_local_set_next_and_error (error_node, b[0], &next[0], error[0],
				    head_of_feature_arc);

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_local_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  return ip4_local_inline (vm, node, frame, 1 /* head of feature arc */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_local_node) =
{
  .name = "ip4-local",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_forward_next_trace,
  .n_errors = IP4_N_ERROR,
  .error_strings = ip4_error_strings,
  .n_next_nodes = IP_LOCAL_N_NEXT,
  .next_nodes =
  {
    [IP_LOCAL_NEXT_DROP] = "ip4-drop",
    [IP_LOCAL_NEXT_PUNT] = "ip4-punt",
    [IP_LOCAL_NEXT_UDP_LOOKUP] = "ip4-udp-lookup",
    [IP_LOCAL_NEXT_ICMP] = "ip4-icmp-input",
    [IP_LOCAL_NEXT_REASSEMBLY] = "ip4-full-reassembly",
  },
};
/* *INDENT-ON* */


VLIB_NODE_FN (ip4_local_end_of_arc_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return ip4_local_inline (vm, node, frame, 0 /* head of feature arc */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_local_end_of_arc_node) = {
  .name = "ip4-local-end-of-arc",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_forward_next_trace,
  .sibling_of = "ip4-local",
};

VNET_FEATURE_INIT (ip4_local_end_of_arc, static) = {
  .arc_name = "ip4-local",
  .node_name = "ip4-local-end-of-arc",
  .runs_before = 0, /* not before any other features */
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
void
ip4_register_protocol (u32 protocol, u32 node_index)
{
  vlib_main_t *vm = vlib_get_main ();
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;

  ASSERT (protocol < ARRAY_LEN (lm->local_next_by_ip_protocol));
  lm->local_next_by_ip_protocol[protocol] =
    vlib_node_add_next (vm, ip4_local_node.index, node_index);
}

void
ip4_unregister_protocol (u32 protocol)
{
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;

  ASSERT (protocol < ARRAY_LEN (lm->local_next_by_ip_protocol));
  lm->local_next_by_ip_protocol[protocol] = IP_LOCAL_NEXT_PUNT;
}
#endif

static clib_error_t *
show_ip_local_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip4_main_t *im = &ip4_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  int i;

  vlib_cli_output (vm, "Protocols handled by ip4_local");
  for (i = 0; i < ARRAY_LEN (lm->local_next_by_ip_protocol); i++)
    {
      if (lm->local_next_by_ip_protocol[i] != IP_LOCAL_NEXT_PUNT)
	{
	  u32 node_index = vlib_get_node (vm,
					  ip4_local_node.index)->
	    next_nodes[lm->local_next_by_ip_protocol[i]];
	  vlib_cli_output (vm, "%U: %U", format_ip_protocol, i,
			   format_vlib_node_name, vm, node_index);
	}
    }
  return 0;
}



/*?
 * Display the set of protocols handled by the local IPv4 stack.
 *
 * @cliexpar
 * Example of how to display local protocol table:
 * @cliexstart{show ip local}
 * Protocols handled by ip4_local
 * 1
 * 17
 * 47
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip_local, static) =
{
  .path = "show ip local",
  .function = show_ip_local_command_fn,
  .short_help = "show ip local",
};
/* *INDENT-ON* */

typedef enum
{
  IP4_REWRITE_NEXT_DROP,
  IP4_REWRITE_NEXT_ICMP_ERROR,
  IP4_REWRITE_NEXT_FRAGMENT,
  IP4_REWRITE_N_NEXT		/* Last */
} ip4_rewrite_next_t;

/**
 * This bits of an IPv4 address to mask to construct a multicast
 * MAC address
 */
#if CLIB_ARCH_IS_BIG_ENDIAN
#define IP4_MCAST_ADDR_MASK 0x007fffff
#else
#define IP4_MCAST_ADDR_MASK 0xffff7f00
#endif

always_inline void
ip4_mtu_check (vlib_buffer_t * b, u16 packet_len,
	       u16 adj_packet_bytes, bool df, u16 * next,
	       u8 is_midchain, u32 * error)
{
  if (packet_len > adj_packet_bytes)
    {
      *error = IP4_ERROR_MTU_EXCEEDED;
      if (df)
	{
	  icmp4_error_set_vnet_buffer
	    (b, ICMP4_destination_unreachable,
	     ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set,
	     adj_packet_bytes);
	  *next = IP4_REWRITE_NEXT_ICMP_ERROR;
	}
      else
	{
	  /* IP fragmentation */
	  ip_frag_set_vnet_buffer (b, adj_packet_bytes,
				   (is_midchain ?
				    IP_FRAG_NEXT_IP_REWRITE_MIDCHAIN :
				    IP_FRAG_NEXT_IP_REWRITE), 0);
	  *next = IP4_REWRITE_NEXT_FRAGMENT;
	}
    }
}

/* increment TTL & update checksum.
   Works either endian, so no need for byte swap. */
static_always_inline void
ip4_ttl_inc (vlib_buffer_t * b, ip4_header_t * ip)
{
  i32 ttl;
  u32 checksum;
  if (PREDICT_FALSE (b->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED))
    return;

  ttl = ip->ttl;

  checksum = ip->checksum - clib_host_to_net_u16 (0x0100);
  checksum += checksum >= 0xffff;

  ip->checksum = checksum;
  ttl += 1;
  ip->ttl = ttl;

  ASSERT (ip4_header_checksum_is_valid (ip));
}

/* Decrement TTL & update checksum.
   Works either endian, so no need for byte swap. */
static_always_inline void
ip4_ttl_and_checksum_check (vlib_buffer_t * b, ip4_header_t * ip, u16 * next,
			    u32 * error)
{
  i32 ttl;
  u32 checksum;
  if (PREDICT_FALSE (b->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED))
    return;

  ttl = ip->ttl;

  /* Input node should have reject packets with ttl 0. */
  ASSERT (ip->ttl > 0);

  checksum = ip->checksum + clib_host_to_net_u16 (0x0100);
  checksum += checksum >= 0xffff;

  ip->checksum = checksum;
  ttl -= 1;
  ip->ttl = ttl;

  /*
   * If the ttl drops below 1 when forwarding, generate
   * an ICMP response.
   */
  if (PREDICT_FALSE (ttl <= 0))
    {
      *error = IP4_ERROR_TIME_EXPIRED;
      vnet_buffer (b)->sw_if_index[VLIB_TX] = (u32) ~ 0;
      icmp4_error_set_vnet_buffer (b, ICMP4_time_exceeded,
				   ICMP4_time_exceeded_ttl_exceeded_in_transit,
				   0);
      *next = IP4_REWRITE_NEXT_ICMP_ERROR;
    }

  /* Verify checksum. */
  ASSERT (ip4_header_checksum_is_valid (ip) ||
	  (vnet_buffer2 (b)->oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM));
}


always_inline uword
ip4_rewrite_inline_with_gso (vlib_main_t * vm,
			     vlib_node_runtime_t * node,
			     vlib_frame_t * frame,
			     int do_counters, int is_midchain, int is_mcast)
{
  ip_lookup_main_t *lm = &ip4_main.lookup_main;
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left_from;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_input_node.index);

  n_left_from = frame->n_vectors;
  u32 thread_index = vm->thread_index;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  clib_memset_u16 (nexts, IP4_REWRITE_NEXT_DROP, n_left_from);

#if (CLIB_N_PREFETCHES >= 8)
  if (n_left_from >= 6)
    {
      int i;
      for (i = 2; i < 6; i++)
	vlib_prefetch_buffer_header (bufs[i], LOAD);
    }

  next = nexts;
  b = bufs;
  while (n_left_from >= 8)
    {
      const ip_adjacency_t *adj0, *adj1;
      ip4_header_t *ip0, *ip1;
      u32 rw_len0, error0, adj_index0;
      u32 rw_len1, error1, adj_index1;
      u32 tx_sw_if_index0, tx_sw_if_index1;
      u8 *p;

      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      adj_index0 = vnet_buffer (b[0])->ip.adj_index[VLIB_TX];
      adj_index1 = vnet_buffer (b[1])->ip.adj_index[VLIB_TX];

      /*
       * pre-fetch the per-adjacency counters
       */
      if (do_counters)
	{
	  vlib_prefetch_combined_counter (&adjacency_counters,
					  thread_index, adj_index0);
	  vlib_prefetch_combined_counter (&adjacency_counters,
					  thread_index, adj_index1);
	}

      ip0 = vlib_buffer_get_current (b[0]);
      ip1 = vlib_buffer_get_current (b[1]);

      error0 = error1 = IP4_ERROR_NONE;

      ip4_ttl_and_checksum_check (b[0], ip0, next + 0, &error0);
      ip4_ttl_and_checksum_check (b[1], ip1, next + 1, &error1);

      /* Rewrite packet header and updates lengths. */
      adj0 = adj_get (adj_index0);
      adj1 = adj_get (adj_index1);

      /* Worth pipelining. No guarantee that adj0,1 are hot... */
      rw_len0 = adj0[0].rewrite_header.data_bytes;
      rw_len1 = adj1[0].rewrite_header.data_bytes;
      vnet_buffer (b[0])->ip.save_rewrite_length = rw_len0;
      vnet_buffer (b[1])->ip.save_rewrite_length = rw_len1;

      p = vlib_buffer_get_current (b[2]);
      CLIB_PREFETCH (p - CLIB_CACHE_LINE_BYTES, CLIB_CACHE_LINE_BYTES, STORE);
      CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);

      p = vlib_buffer_get_current (b[3]);
      CLIB_PREFETCH (p - CLIB_CACHE_LINE_BYTES, CLIB_CACHE_LINE_BYTES, STORE);
      CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);

      /* Check MTU of outgoing interface. */
      u16 ip0_len = clib_net_to_host_u16 (ip0->length);
      u16 ip1_len = clib_net_to_host_u16 (ip1->length);

      if (b[0]->flags & VNET_BUFFER_F_GSO)
	ip0_len = gso_mtu_sz (b[0]);
      if (b[1]->flags & VNET_BUFFER_F_GSO)
	ip1_len = gso_mtu_sz (b[1]);

      ip4_mtu_check (b[0], ip0_len,
		     adj0[0].rewrite_header.max_l3_packet_bytes,
		     ip0->flags_and_fragment_offset &
		     clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT),
		     next + 0, is_midchain, &error0);
      ip4_mtu_check (b[1], ip1_len,
		     adj1[0].rewrite_header.max_l3_packet_bytes,
		     ip1->flags_and_fragment_offset &
		     clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT),
		     next + 1, is_midchain, &error1);

      if (is_mcast)
	{
	  error0 = ((adj0[0].rewrite_header.sw_if_index ==
		     vnet_buffer (b[0])->sw_if_index[VLIB_RX]) ?
		    IP4_ERROR_SAME_INTERFACE : error0);
	  error1 = ((adj1[0].rewrite_header.sw_if_index ==
		     vnet_buffer (b[1])->sw_if_index[VLIB_RX]) ?
		    IP4_ERROR_SAME_INTERFACE : error1);
	}

      /* Don't adjust the buffer for ttl issue; icmp-error node wants
       * to see the IP header */
      if (PREDICT_TRUE (error0 == IP4_ERROR_NONE))
	{
	  u32 next_index = adj0[0].rewrite_header.next_index;
	  vlib_buffer_advance (b[0], -(word) rw_len0);

	  tx_sw_if_index0 = adj0[0].rewrite_header.sw_if_index;
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = tx_sw_if_index0;

	  if (PREDICT_FALSE
	      (adj0[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
	    vnet_feature_arc_start_w_cfg_index (lm->output_feature_arc_index,
						tx_sw_if_index0,
						&next_index, b[0],
						adj0->ia_cfg_index);

	  next[0] = next_index;
	  if (is_midchain)
	    vnet_calc_checksums_inline (vm, b[0], 1 /* is_ip4 */ ,
					0 /* is_ip6 */ );
	}
      else
	{
	  b[0]->error = error_node->errors[error0];
	  if (error0 == IP4_ERROR_MTU_EXCEEDED)
	    ip4_ttl_inc (b[0], ip0);
	}
      if (PREDICT_TRUE (error1 == IP4_ERROR_NONE))
	{
	  u32 next_index = adj1[0].rewrite_header.next_index;
	  vlib_buffer_advance (b[1], -(word) rw_len1);

	  tx_sw_if_index1 = adj1[0].rewrite_header.sw_if_index;
	  vnet_buffer (b[1])->sw_if_index[VLIB_TX] = tx_sw_if_index1;

	  if (PREDICT_FALSE
	      (adj1[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
	    vnet_feature_arc_start_w_cfg_index (lm->output_feature_arc_index,
						tx_sw_if_index1,
						&next_index, b[1],
						adj1->ia_cfg_index);
	  next[1] = next_index;
	  if (is_midchain)
	    vnet_calc_checksums_inline (vm, b[1], 1 /* is_ip4 */ ,
					0 /* is_ip6 */ );
	}
      else
	{
	  b[1]->error = error_node->errors[error1];
	  if (error1 == IP4_ERROR_MTU_EXCEEDED)
	    ip4_ttl_inc (b[1], ip1);
	}

      if (is_midchain)
	/* Guess we are only writing on ipv4 header. */
	vnet_rewrite_two_headers (adj0[0], adj1[0],
				  ip0, ip1, sizeof (ip4_header_t));
      else
	/* Guess we are only writing on simple Ethernet header. */
	vnet_rewrite_two_headers (adj0[0], adj1[0],
				  ip0, ip1, sizeof (ethernet_header_t));

      if (do_counters)
	{
	  if (error0 == IP4_ERROR_NONE)
	    vlib_increment_combined_counter
	      (&adjacency_counters,
	       thread_index,
	       adj_index0, 1,
	       vlib_buffer_length_in_chain (vm, b[0]) + rw_len0);

	  if (error1 == IP4_ERROR_NONE)
	    vlib_increment_combined_counter
	      (&adjacency_counters,
	       thread_index,
	       adj_index1, 1,
	       vlib_buffer_length_in_chain (vm, b[1]) + rw_len1);
	}

      if (is_midchain)
	{
	  if (error0 == IP4_ERROR_NONE)
	    adj_midchain_fixup (vm, adj0, b[0]);
	  if (error1 == IP4_ERROR_NONE)
	    adj_midchain_fixup (vm, adj1, b[1]);
	}

      if (is_mcast)
	{
	  /* copy bytes from the IP address into the MAC rewrite */
	  if (error0 == IP4_ERROR_NONE)
	    vnet_ip_mcast_fixup_header (IP4_MCAST_ADDR_MASK,
					adj0->rewrite_header.dst_mcast_offset,
					&ip0->dst_address.as_u32, (u8 *) ip0);
	  if (error1 == IP4_ERROR_NONE)
	    vnet_ip_mcast_fixup_header (IP4_MCAST_ADDR_MASK,
					adj1->rewrite_header.dst_mcast_offset,
					&ip1->dst_address.as_u32, (u8 *) ip1);
	}

      next += 2;
      b += 2;
      n_left_from -= 2;
    }
#elif (CLIB_N_PREFETCHES >= 4)
  next = nexts;
  b = bufs;
  while (n_left_from >= 1)
    {
      ip_adjacency_t *adj0;
      ip4_header_t *ip0;
      u32 rw_len0, error0, adj_index0;
      u32 tx_sw_if_index0;
      u8 *p;

      /* Prefetch next iteration */
      if (PREDICT_TRUE (n_left_from >= 4))
	{
	  ip_adjacency_t *adj2;
	  u32 adj_index2;

	  vlib_prefetch_buffer_header (b[3], LOAD);
	  vlib_prefetch_buffer_data (b[2], LOAD);

	  /* Prefetch adj->rewrite_header */
	  adj_index2 = vnet_buffer (b[2])->ip.adj_index[VLIB_TX];
	  adj2 = adj_get (adj_index2);
	  p = (u8 *) adj2;
	  CLIB_PREFETCH (p + CLIB_CACHE_LINE_BYTES, CLIB_CACHE_LINE_BYTES,
			 LOAD);
	}

      adj_index0 = vnet_buffer (b[0])->ip.adj_index[VLIB_TX];

      /*
       * Prefetch the per-adjacency counters
       */
      if (do_counters)
	{
	  vlib_prefetch_combined_counter (&adjacency_counters,
					  thread_index, adj_index0);
	}

      ip0 = vlib_buffer_get_current (b[0]);

      error0 = IP4_ERROR_NONE;

      ip4_ttl_and_checksum_check (b[0], ip0, next + 0, &error0);

      /* Rewrite packet header and updates lengths. */
      adj0 = adj_get (adj_index0);

      /* Rewrite header was prefetched. */
      rw_len0 = adj0[0].rewrite_header.data_bytes;
      vnet_buffer (b[0])->ip.save_rewrite_length = rw_len0;

      /* Check MTU of outgoing interface. */
      u16 ip0_len = clib_net_to_host_u16 (ip0->length);

      if (b[0]->flags & VNET_BUFFER_F_GSO)
	ip0_len = gso_mtu_sz (b[0]);

      ip4_mtu_check (b[0], ip0_len,
		     adj0[0].rewrite_header.max_l3_packet_bytes,
		     ip0->flags_and_fragment_offset &
		     clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT),
		     next + 0, is_midchain, &error0);

      if (is_mcast)
	{
	  error0 = ((adj0[0].rewrite_header.sw_if_index ==
		     vnet_buffer (b[0])->sw_if_index[VLIB_RX]) ?
		    IP4_ERROR_SAME_INTERFACE : error0);
	}

      /* Don't adjust the buffer for ttl issue; icmp-error node wants
       * to see the IP header */
      if (PREDICT_TRUE (error0 == IP4_ERROR_NONE))
	{
	  u32 next_index = adj0[0].rewrite_header.next_index;
	  vlib_buffer_advance (b[0], -(word) rw_len0);
	  tx_sw_if_index0 = adj0[0].rewrite_header.sw_if_index;
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = tx_sw_if_index0;

	  if (PREDICT_FALSE
	      (adj0[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
	    vnet_feature_arc_start_w_cfg_index (lm->output_feature_arc_index,
						tx_sw_if_index0,
						&next_index, b[0],
						adj0->ia_cfg_index);
	  next[0] = next_index;

	  if (is_midchain)
	    {
	      vnet_calc_checksums_inline (vm, b[0], 1 /* is_ip4 */ ,
					  0 /* is_ip6 */ );

	      /* Guess we are only writing on ipv4 header. */
	      vnet_rewrite_one_header (adj0[0], ip0, sizeof (ip4_header_t));
	    }
	  else
	    /* Guess we are only writing on simple Ethernet header. */
	    vnet_rewrite_one_header (adj0[0], ip0,
				     sizeof (ethernet_header_t));

	  /*
	   * Bump the per-adjacency counters
	   */
	  if (do_counters)
	    vlib_increment_combined_counter
	      (&adjacency_counters,
	       thread_index,
	       adj_index0, 1, vlib_buffer_length_in_chain (vm,
							   b[0]) + rw_len0);

	  if (is_midchain)
	    adj_midchain_fixup (vm, adj0, b[0]);

	  if (is_mcast)
	    /* copy bytes from the IP address into the MAC rewrite */
	    vnet_ip_mcast_fixup_header (IP4_MCAST_ADDR_MASK,
					adj0->rewrite_header.dst_mcast_offset,
					&ip0->dst_address.as_u32, (u8 *) ip0);
	}
      else
	{
	  b[0]->error = error_node->errors[error0];
	  if (error0 == IP4_ERROR_MTU_EXCEEDED)
	    ip4_ttl_inc (b[0], ip0);
	}

      next += 1;
      b += 1;
      n_left_from -= 1;
    }
#endif

  while (n_left_from > 0)
    {
      ip_adjacency_t *adj0;
      ip4_header_t *ip0;
      u32 rw_len0, adj_index0, error0;
      u32 tx_sw_if_index0;

      adj_index0 = vnet_buffer (b[0])->ip.adj_index[VLIB_TX];

      adj0 = adj_get (adj_index0);

      if (do_counters)
	vlib_prefetch_combined_counter (&adjacency_counters,
					thread_index, adj_index0);

      ip0 = vlib_buffer_get_current (b[0]);

      error0 = IP4_ERROR_NONE;

      ip4_ttl_and_checksum_check (b[0], ip0, next + 0, &error0);


      /* Update packet buffer attributes/set output interface. */
      rw_len0 = adj0[0].rewrite_header.data_bytes;
      vnet_buffer (b[0])->ip.save_rewrite_length = rw_len0;

      /* Check MTU of outgoing interface. */
      u16 ip0_len = clib_net_to_host_u16 (ip0->length);
      if (b[0]->flags & VNET_BUFFER_F_GSO)
	ip0_len = gso_mtu_sz (b[0]);

      ip4_mtu_check (b[0], ip0_len,
		     adj0[0].rewrite_header.max_l3_packet_bytes,
		     ip0->flags_and_fragment_offset &
		     clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT),
		     next + 0, is_midchain, &error0);

      if (is_mcast)
	{
	  error0 = ((adj0[0].rewrite_header.sw_if_index ==
		     vnet_buffer (b[0])->sw_if_index[VLIB_RX]) ?
		    IP4_ERROR_SAME_INTERFACE : error0);
	}

      /* Don't adjust the buffer for ttl issue; icmp-error node wants
       * to see the IP header */
      if (PREDICT_TRUE (error0 == IP4_ERROR_NONE))
	{
	  u32 next_index = adj0[0].rewrite_header.next_index;
	  vlib_buffer_advance (b[0], -(word) rw_len0);
	  tx_sw_if_index0 = adj0[0].rewrite_header.sw_if_index;
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = tx_sw_if_index0;

	  if (PREDICT_FALSE
	      (adj0[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
	    vnet_feature_arc_start_w_cfg_index (lm->output_feature_arc_index,
						tx_sw_if_index0,
						&next_index, b[0],
						adj0->ia_cfg_index);
	  next[0] = next_index;

	  if (is_midchain)
	    {
	      /* this acts on the packet that is about to be encapped */
	      vnet_calc_checksums_inline (vm, b[0], 1 /* is_ip4 */ ,
					  0 /* is_ip6 */ );

	      /* Guess we are only writing on ipv4 header. */
	      vnet_rewrite_one_header (adj0[0], ip0, sizeof (ip4_header_t));
	    }
	  else
	    /* Guess we are only writing on simple Ethernet header. */
	    vnet_rewrite_one_header (adj0[0], ip0,
				     sizeof (ethernet_header_t));

	  if (do_counters)
	    vlib_increment_combined_counter
	      (&adjacency_counters,
	       thread_index, adj_index0, 1,
	       vlib_buffer_length_in_chain (vm, b[0]) + rw_len0);

	  if (is_midchain && adj0->sub_type.midchain.fixup_func)
	    adj0->sub_type.midchain.fixup_func
	      (vm, adj0, b[0], adj0->sub_type.midchain.fixup_data);

	  if (is_mcast)
	    /* copy bytes from the IP address into the MAC rewrite */
	    vnet_ip_mcast_fixup_header (IP4_MCAST_ADDR_MASK,
					adj0->rewrite_header.dst_mcast_offset,
					&ip0->dst_address.as_u32, (u8 *) ip0);
	}
      else
	{
	  b[0]->error = error_node->errors[error0];
	  /* undo the TTL decrement - we'll be back to do it again */
	  if (error0 == IP4_ERROR_MTU_EXCEEDED)
	    ip4_ttl_inc (b[0], ip0);
	}

      next += 1;
      b += 1;
      n_left_from -= 1;
    }


  /* Need to do trace after rewrites to pick up new packet data. */
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

always_inline uword
ip4_rewrite_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame,
		    int do_counters, int is_midchain, int is_mcast)
{
  return ip4_rewrite_inline_with_gso (vm, node, frame, do_counters,
				      is_midchain, is_mcast);
}


/** @brief IPv4 rewrite node.
    @node ip4-rewrite

    This is the IPv4 transit-rewrite node: decrement TTL, fix the ipv4
    header checksum, fetch the ip adjacency, check the outbound mtu,
    apply the adjacency rewrite, and send pkts to the adjacency
    rewrite header's rewrite_next_index.

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched

    @par Graph mechanics: buffer metadata, next index usage

    @em Uses:
    - <code>vnet_buffer(b)->ip.adj_index[VLIB_TX]</code>
        - the rewrite adjacency index
    - <code>adj->lookup_next_index</code>
        - Must be IP_LOOKUP_NEXT_REWRITE or IP_LOOKUP_NEXT_ARP, otherwise
          the packet will be dropped.
    - <code>adj->rewrite_header</code>
        - Rewrite string length, rewrite string, next_index

    @em Sets:
    - <code>b->current_data, b->current_length</code>
        - Updated net of applying the rewrite string

    <em>Next Indices:</em>
    - <code> adj->rewrite_header.next_index </code>
      or @c ip4-drop
*/

VLIB_NODE_FN (ip4_rewrite_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip4_rewrite_inline (vm, node, frame, 1, 0, 0);
  else
    return ip4_rewrite_inline (vm, node, frame, 0, 0, 0);
}

VLIB_NODE_FN (ip4_rewrite_bcast_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip4_rewrite_inline (vm, node, frame, 1, 0, 0);
  else
    return ip4_rewrite_inline (vm, node, frame, 0, 0, 0);
}

VLIB_NODE_FN (ip4_midchain_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip4_rewrite_inline (vm, node, frame, 1, 1, 0);
  else
    return ip4_rewrite_inline (vm, node, frame, 0, 1, 0);
}

VLIB_NODE_FN (ip4_rewrite_mcast_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip4_rewrite_inline (vm, node, frame, 1, 0, 1);
  else
    return ip4_rewrite_inline (vm, node, frame, 0, 0, 1);
}

VLIB_NODE_FN (ip4_mcast_midchain_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip4_rewrite_inline (vm, node, frame, 1, 1, 1);
  else
    return ip4_rewrite_inline (vm, node, frame, 0, 1, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_rewrite_node) = {
  .name = "ip4-rewrite",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_rewrite_trace,

  .n_next_nodes = IP4_REWRITE_N_NEXT,
  .next_nodes = {
    [IP4_REWRITE_NEXT_DROP] = "ip4-drop",
    [IP4_REWRITE_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [IP4_REWRITE_NEXT_FRAGMENT] = "ip4-frag",
  },
};

VLIB_REGISTER_NODE (ip4_rewrite_bcast_node) = {
  .name = "ip4-rewrite-bcast",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_rewrite_trace,
  .sibling_of = "ip4-rewrite",
};

VLIB_REGISTER_NODE (ip4_rewrite_mcast_node) = {
  .name = "ip4-rewrite-mcast",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_rewrite_trace,
  .sibling_of = "ip4-rewrite",
};

VLIB_REGISTER_NODE (ip4_mcast_midchain_node) = {
  .name = "ip4-mcast-midchain",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_rewrite_trace,
  .sibling_of = "ip4-rewrite",
};

VLIB_REGISTER_NODE (ip4_midchain_node) = {
  .name = "ip4-midchain",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_rewrite_trace,
  .sibling_of = "ip4-rewrite",
};
/* *INDENT-ON */

static int
ip4_lookup_validate (ip4_address_t * a, u32 fib_index0)
{
  ip4_fib_mtrie_t *mtrie0;
  ip4_fib_mtrie_leaf_t leaf0;
  u32 lbi0;

  mtrie0 = &ip4_fib_get (fib_index0)->mtrie;

  leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, a);
  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, a, 2);
  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, a, 3);

  lbi0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);

  return lbi0 == ip4_fib_table_lookup_lb (ip4_fib_get (fib_index0), a);
}

static clib_error_t *
test_lookup_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip4_fib_t *fib;
  u32 table_id = 0;
  f64 count = 1;
  u32 n;
  int i;
  ip4_address_t ip4_base_address;
  u64 errors = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table %d", &table_id))
	{
	  /* Make sure the entry exists. */
	  fib = ip4_fib_get (table_id);
	  if ((fib) && (fib->index != table_id))
	    return clib_error_return (0, "<fib-index> %d does not exist",
				      table_id);
	}
      else if (unformat (input, "count %f", &count))
	;

      else if (unformat (input, "%U",
			 unformat_ip4_address, &ip4_base_address))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  n = count;

  for (i = 0; i < n; i++)
    {
      if (!ip4_lookup_validate (&ip4_base_address, table_id))
	errors++;

      ip4_base_address.as_u32 =
	clib_host_to_net_u32 (1 +
			      clib_net_to_host_u32 (ip4_base_address.as_u32));
    }

  if (errors)
    vlib_cli_output (vm, "%llu errors out of %d lookups\n", errors, n);
  else
    vlib_cli_output (vm, "No errors in %d lookups\n", n);

  return 0;
}

/*?
 * Perform a lookup of an IPv4 Address (or range of addresses) in the
 * given FIB table to determine if there is a conflict with the
 * adjacency table. The fib-id can be determined by using the
 * '<em>show ip fib</em>' command. If fib-id is not entered, default value
 * of 0 is used.
 *
 * @todo This command uses fib-id, other commands use table-id (not
 * just a name, they are different indexes). Would like to change this
 * to table-id for consistency.
 *
 * @cliexpar
 * Example of how to run the test lookup command:
 * @cliexstart{test lookup 172.16.1.1 table 1 count 2}
 * No errors in 2 lookups
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lookup_test_command, static) =
{
  .path = "test lookup",
  .short_help = "test lookup <ipv4-addr> [table <fib-id>] [count <nn>]",
  .function = test_lookup_command_fn,
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
int
vnet_set_ip4_flow_hash (u32 table_id, u32 flow_hash_config)
{
  u32 fib_index;

  fib_index = fib_table_find (FIB_PROTOCOL_IP4, table_id);

  if (~0 == fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  fib_table_set_flow_hash_config (fib_index, FIB_PROTOCOL_IP4,
				  flow_hash_config);

  return 0;
}
#endif

static clib_error_t *
set_ip_flow_hash_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  int matched = 0;
  u32 table_id = 0;
  u32 flow_hash_config = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table %d", &table_id))
	matched = 1;
#define _(a,v) \
    else if (unformat (input, #a)) { flow_hash_config |= v; matched=1;}
      foreach_flow_hash_bit
#undef _
	else
	break;
    }

  if (matched == 0)
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  rv = vnet_set_ip4_flow_hash (table_id, flow_hash_config);
  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "no such FIB table %d", table_id);

    default:
      clib_warning ("BUG: illegal flow hash config 0x%x", flow_hash_config);
      break;
    }

  return 0;
}

/*?
 * Configure the set of IPv4 fields used by the flow hash.
 *
 * @cliexpar
 * Example of how to set the flow hash on a given table:
 * @cliexcmd{set ip flow-hash table 7 dst sport dport proto}
 * Example of display the configured flow hash:
 * @cliexstart{show ip fib}
 * ipv4-VRF:0, fib_index 0, flow hash: src dst sport dport proto
 * 0.0.0.0/0
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:0 buckets:1 uRPF:0 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 0.0.0.0/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:1 buckets:1 uRPF:1 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 224.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:3 buckets:1 uRPF:3 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 6.0.1.2/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:30 buckets:1 uRPF:29 to:[0:0]]
 *     [0] [@3]: arp-ipv4: via 6.0.0.1 af_packet0
 * 7.0.0.1/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:31 buckets:4 uRPF:30 to:[0:0]]
 *     [0] [@3]: arp-ipv4: via 6.0.0.2 af_packet0
 *     [1] [@3]: arp-ipv4: via 6.0.0.2 af_packet0
 *     [2] [@3]: arp-ipv4: via 6.0.0.2 af_packet0
 *     [3] [@3]: arp-ipv4: via 6.0.0.1 af_packet0
 * 240.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:2 buckets:1 uRPF:2 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 255.255.255.255/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:4 buckets:1 uRPF:4 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * ipv4-VRF:7, fib_index 1, flow hash: dst sport dport proto
 * 0.0.0.0/0
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:12 buckets:1 uRPF:11 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 0.0.0.0/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:13 buckets:1 uRPF:12 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 172.16.1.0/24
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:17 buckets:1 uRPF:16 to:[0:0]]
 *     [0] [@4]: ipv4-glean: af_packet0
 * 172.16.1.1/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:18 buckets:1 uRPF:17 to:[1:84]]
 *     [0] [@2]: dpo-receive: 172.16.1.1 on af_packet0
 * 172.16.1.2/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:21 buckets:1 uRPF:20 to:[0:0]]
 *     [0] [@5]: ipv4 via 172.16.1.2 af_packet0: IP4: 02:fe:9e:70:7a:2b -> 26:a5:f6:9c:3a:36
 * 172.16.2.0/24
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:19 buckets:1 uRPF:18 to:[0:0]]
 *     [0] [@4]: ipv4-glean: af_packet1
 * 172.16.2.1/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:20 buckets:1 uRPF:19 to:[0:0]]
 *     [0] [@2]: dpo-receive: 172.16.2.1 on af_packet1
 * 224.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:15 buckets:1 uRPF:14 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 240.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:14 buckets:1 uRPF:13 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 255.255.255.255/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:16 buckets:1 uRPF:15 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ip_flow_hash_command, static) =
{
  .path = "set ip flow-hash",
  .short_help =
  "set ip flow-hash table <table-id> [src] [dst] [sport] [dport] [proto] [reverse]",
  .function = set_ip_flow_hash_command_fn,
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
int
vnet_set_ip4_classify_intfc (vlib_main_t * vm, u32 sw_if_index,
			     u32 table_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  ip4_main_t *ipm = &ip4_main;
  ip_lookup_main_t *lm = &ipm->lookup_main;
  vnet_classify_main_t *cm = &vnet_classify_main;
  ip4_address_t *if_addr;

  if (pool_is_free_index (im->sw_interfaces, sw_if_index))
    return VNET_API_ERROR_NO_MATCHING_INTERFACE;

  if (table_index != ~0 && pool_is_free_index (cm->tables, table_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vec_validate (lm->classify_table_index_by_sw_if_index, sw_if_index);
  lm->classify_table_index_by_sw_if_index[sw_if_index] = table_index;

  if_addr = ip4_interface_first_address (ipm, sw_if_index, NULL);

  if (NULL != if_addr)
    {
      fib_prefix_t pfx = {
	.fp_len = 32,
	.fp_proto = FIB_PROTOCOL_IP4,
	.fp_addr.ip4 = *if_addr,
      };
      u32 fib_index;

      fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						       sw_if_index);


      if (table_index != (u32) ~ 0)
	{
	  dpo_id_t dpo = DPO_INVALID;

	  dpo_set (&dpo,
		   DPO_CLASSIFY,
		   DPO_PROTO_IP4,
		   classify_dpo_create (DPO_PROTO_IP4, table_index));

	  fib_table_entry_special_dpo_add (fib_index,
					   &pfx,
					   FIB_SOURCE_CLASSIFY,
					   FIB_ENTRY_FLAG_NONE, &dpo);
	  dpo_reset (&dpo);
	}
      else
	{
	  fib_table_entry_special_remove (fib_index,
					  &pfx, FIB_SOURCE_CLASSIFY);
	}
    }

  return 0;
}
#endif

static clib_error_t *
set_ip_classify_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  u32 table_index = ~0;
  int table_index_set = 0;
  u32 sw_if_index = ~0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table-index %d", &table_index))
	table_index_set = 1;
      else if (unformat (input, "intfc %U", unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	;
      else
	break;
    }

  if (table_index_set == 0)
    return clib_error_return (0, "classify table-index must be specified");

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface / subif must be specified");

  rv = vnet_set_ip4_classify_intfc (vm, sw_if_index, table_index);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_MATCHING_INTERFACE:
      return clib_error_return (0, "No such interface");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "No such classifier table");
    }
  return 0;
}

/*?
 * Assign a classification table to an interface. The classification
 * table is created using the '<em>classify table</em>' and '<em>classify session</em>'
 * commands. Once the table is create, use this command to filter packets
 * on an interface.
 *
 * @cliexpar
 * Example of how to assign a classification table to an interface:
 * @cliexcmd{set ip classify intfc GigabitEthernet2/0/0 table-index 1}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ip_classify_command, static) =
{
    .path = "set ip classify",
    .short_help =
    "set ip classify intfc <interface> table-index <classify-idx>",
    .function = set_ip_classify_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
