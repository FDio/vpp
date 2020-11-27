/*
 * decap.c: vxlan gbp tunnel decap packet processing
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>

#include <vnet/vxlan-gbp/vxlan_gbp.h>

typedef struct
{
  u32 next_index;
  u32 tunnel_index;
  u32 error;
  u32 vni;
  u16 sclass;
  u8 flags;
} vxlan_gbp_rx_trace_t;

static u8 *
format_vxlan_gbp_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vxlan_gbp_rx_trace_t *t = va_arg (*args, vxlan_gbp_rx_trace_t *);

  if (t->tunnel_index == ~0)
    return format (s,
		   "VXLAN_GBP decap error - tunnel for vni %d does not exist",
		   t->vni);
  return format (s,
		 "VXLAN_GBP decap from vxlan_gbp_tunnel%d vni %d sclass %d"
		 " flags %U next %d error %d",
		 t->tunnel_index, t->vni, t->sclass,
		 format_vxlan_gbp_header_gpflags, t->flags,
		 t->next_index, t->error);
}

always_inline u32
buf_fib_index (vlib_buffer_t * b, u32 is_ip4)
{
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
  if (sw_if_index != (u32) ~ 0)
    return sw_if_index;

  u32 *fib_index_by_sw_if_index = is_ip4 ?
    ip4_main.fib_index_by_sw_if_index : ip6_main.fib_index_by_sw_if_index;
  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

  return vec_elt (fib_index_by_sw_if_index, sw_if_index);
}

typedef vxlan4_gbp_tunnel_key_t last_tunnel_cache4;

always_inline vxlan_gbp_tunnel_t *
vxlan4_gbp_find_tunnel (vxlan_gbp_main_t * vxm, last_tunnel_cache4 * cache,
			u32 fib_index, ip4_header_t * ip4_0,
			vxlan_gbp_header_t * vxlan_gbp0)
{
  /*
   * Check unicast first since that's where most of the traffic comes from
   *  Make sure VXLAN_GBP tunnel exist according to packet SIP, DIP and VNI
   */
  vxlan4_gbp_tunnel_key_t key4;
  int rv;

  key4.key[1] = (((u64) fib_index << 32) |
		 (vxlan_gbp0->vni_reserved &
		  clib_host_to_net_u32 (0xffffff00)));
  key4.key[0] =
    (((u64) ip4_0->dst_address.as_u32 << 32) | ip4_0->src_address.as_u32);

  if (PREDICT_FALSE (key4.key[0] != cache->key[0] ||
		     key4.key[1] != cache->key[1]))
    {
      rv = clib_bihash_search_inline_16_8 (&vxm->vxlan4_gbp_tunnel_by_key,
					   &key4);
      if (PREDICT_FALSE (rv == 0))
	{
	  *cache = key4;
	  return (pool_elt_at_index (vxm->tunnels, cache->value));
	}
    }
  else
    {
      return (pool_elt_at_index (vxm->tunnels, cache->value));
    }

  /* No unicast match - try multicast */
  if (PREDICT_TRUE (!ip4_address_is_multicast (&ip4_0->dst_address)))
    return (NULL);

  key4.key[0] = ip4_0->dst_address.as_u32;
  /* Make sure mcast VXLAN_GBP tunnel exist by packet DIP and VNI */
  rv = clib_bihash_search_inline_16_8 (&vxm->vxlan4_gbp_tunnel_by_key, &key4);

  if (PREDICT_FALSE (rv != 0))
    return (NULL);

  return (pool_elt_at_index (vxm->tunnels, key4.value));
}

typedef vxlan6_gbp_tunnel_key_t last_tunnel_cache6;

always_inline vxlan_gbp_tunnel_t *
vxlan6_gbp_find_tunnel (vxlan_gbp_main_t * vxm, last_tunnel_cache6 * cache,
			u32 fib_index, ip6_header_t * ip6_0,
			vxlan_gbp_header_t * vxlan_gbp0)
{
  /* Make sure VXLAN_GBP tunnel exist according to packet SIP and VNI */
  vxlan6_gbp_tunnel_key_t key6 = {
    .key = {
	    [0] = ip6_0->src_address.as_u64[0],
	    [1] = ip6_0->src_address.as_u64[1],
	    [2] = ((((u64) fib_index) << 32) |
		   (vxlan_gbp0->vni_reserved &
		    clib_host_to_net_u32 (0xffffff00))),
	    }
  };
  int rv;

  if (PREDICT_FALSE
      (clib_bihash_key_compare_24_8 (key6.key, cache->key) == 0))
    {
      rv = clib_bihash_search_inline_24_8 (&vxm->vxlan6_gbp_tunnel_by_key,
					   &key6);
      if (PREDICT_FALSE (rv != 0))
	return NULL;

      *cache = key6;
    }
  vxlan_gbp_tunnel_t *t0 = pool_elt_at_index (vxm->tunnels, cache->value);

  /* Validate VXLAN_GBP tunnel SIP against packet DIP */
  if (PREDICT_FALSE
      (!ip6_address_is_equal (&ip6_0->dst_address, &t0->src.ip6)))
    {
      /* try multicast */
      if (PREDICT_TRUE (!ip6_address_is_multicast (&ip6_0->dst_address)))
	return 0;

      /* Make sure mcast VXLAN_GBP tunnel exist by packet DIP and VNI */
      key6.key[0] = ip6_0->dst_address.as_u64[0];
      key6.key[1] = ip6_0->dst_address.as_u64[1];
      rv = clib_bihash_search_inline_24_8 (&vxm->vxlan6_gbp_tunnel_by_key,
					   &key6);
      if (PREDICT_FALSE (rv != 0))
	return 0;

    }

  return t0;
}

always_inline vxlan_gbp_input_next_t
vxlan_gbp_tunnel_get_next (const vxlan_gbp_tunnel_t * t, vlib_buffer_t * b0)
{
  if (VXLAN_GBP_TUNNEL_MODE_L2 == t->mode)
    return (VXLAN_GBP_INPUT_NEXT_L2_INPUT);
  else
    {
      ethernet_header_t *e0;
      u16 type0;

      e0 = vlib_buffer_get_current (b0);
      vlib_buffer_advance (b0, sizeof (*e0));
      type0 = clib_net_to_host_u16 (e0->type);
      switch (type0)
	{
	case ETHERNET_TYPE_IP4:
	  return (VXLAN_GBP_INPUT_NEXT_IP4_INPUT);
	case ETHERNET_TYPE_IP6:
	  return (VXLAN_GBP_INPUT_NEXT_IP6_INPUT);
	}
    }
  return (VXLAN_GBP_INPUT_NEXT_DROP);
}

always_inline uword
vxlan_gbp_input (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * from_frame, u8 is_ip4)
{
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;
  vnet_main_t *vnm = vxm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_combined_counter_main_t *rx_counter =
    im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX;
  vlib_combined_counter_main_t *drop_counter =
    im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_DROP;
  last_tunnel_cache4 last4;
  last_tunnel_cache6 last6;
  u32 pkts_decapsulated = 0;
  u32 thread_index = vlib_get_thread_index ();

  if (is_ip4)
    clib_memset (&last4, 0xff, sizeof last4);
  else
    clib_memset (&last6, 0xff, sizeof last6);

  u32 next_index = node->cached_next_index;

  u32 *from = vlib_frame_vector_args (from_frame);
  u32 n_left_from = from_frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 *to_next, n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  u32 bi0 = to_next[0] = from[0];
	  u32 bi1 = to_next[1] = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  vlib_buffer_t *b0, *b1;
	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /* udp leaves current_data pointing at the vxlan_gbp header */
	  void *cur0 = vlib_buffer_get_current (b0);
	  void *cur1 = vlib_buffer_get_current (b1);
	  vxlan_gbp_header_t *vxlan_gbp0 = cur0;
	  vxlan_gbp_header_t *vxlan_gbp1 = cur1;

	  ip4_header_t *ip4_0, *ip4_1;
	  ip6_header_t *ip6_0, *ip6_1;
	  if (is_ip4)
	    {
	      ip4_0 = cur0 - sizeof (udp_header_t) - sizeof (ip4_header_t);
	      ip4_1 = cur1 - sizeof (udp_header_t) - sizeof (ip4_header_t);
	    }
	  else
	    {
	      ip6_0 = cur0 - sizeof (udp_header_t) - sizeof (ip6_header_t);
	      ip6_1 = cur1 - sizeof (udp_header_t) - sizeof (ip6_header_t);
	    }

	  u32 fi0 = buf_fib_index (b0, is_ip4);
	  u32 fi1 = buf_fib_index (b1, is_ip4);

	  vxlan_gbp_tunnel_t *t0, *t1;
	  if (is_ip4)
	    {
	      t0 =
		vxlan4_gbp_find_tunnel (vxm, &last4, fi0, ip4_0, vxlan_gbp0);
	      t1 =
		vxlan4_gbp_find_tunnel (vxm, &last4, fi1, ip4_1, vxlan_gbp1);
	    }
	  else
	    {
	      t0 =
		vxlan6_gbp_find_tunnel (vxm, &last6, fi0, ip6_0, vxlan_gbp0);
	      t1 =
		vxlan6_gbp_find_tunnel (vxm, &last6, fi1, ip6_1, vxlan_gbp1);
	    }

	  u32 len0 = vlib_buffer_length_in_chain (vm, b0);
	  u32 len1 = vlib_buffer_length_in_chain (vm, b1);

	  vxlan_gbp_input_next_t next0, next1;
	  u8 error0 = 0, error1 = 0;
	  u8 flags0 = vxlan_gbp_get_flags (vxlan_gbp0);
	  u8 flags1 = vxlan_gbp_get_flags (vxlan_gbp1);
	  /* Required to make the l2 tag push / pop code work on l2 subifs */
	  /* pop vxlan_gbp */
	  vlib_buffer_advance (b0, sizeof *vxlan_gbp0);
	  vlib_buffer_advance (b1, sizeof *vxlan_gbp1);

	  u8 i_and_g0 = ((flags0 & VXLAN_GBP_FLAGS_GI) == VXLAN_GBP_FLAGS_GI);
	  u8 i_and_g1 = ((flags1 & VXLAN_GBP_FLAGS_GI) == VXLAN_GBP_FLAGS_GI);

	  /* Validate VXLAN_GBP tunnel encap-fib index against packet */
	  if (PREDICT_FALSE (t0 == NULL || !i_and_g0))
	    {
	      if (t0 != NULL && !i_and_g0)
		{
		  error0 = VXLAN_GBP_ERROR_BAD_FLAGS;
		  vlib_increment_combined_counter
		    (drop_counter, thread_index, t0->sw_if_index, 1, len0);
		  next0 = VXLAN_GBP_INPUT_NEXT_DROP;
		}
	      else
		{
		  error0 = VXLAN_GBP_ERROR_NO_SUCH_TUNNEL;
		  next0 = VXLAN_GBP_INPUT_NEXT_PUNT;
		  if (is_ip4)
		    b0->punt_reason =
		      vxm->punt_no_such_tunnel[FIB_PROTOCOL_IP4];
		  else
		    b0->punt_reason =
		      vxm->punt_no_such_tunnel[FIB_PROTOCOL_IP6];
		}
	      b0->error = node->errors[error0];
	    }
	  else
	    {
	      next0 = vxlan_gbp_tunnel_get_next (t0, b0);

	      /* Set packet input sw_if_index to unicast VXLAN tunnel for learning */
	      vnet_buffer (b0)->sw_if_index[VLIB_RX] = t0->sw_if_index;
	      vlib_increment_combined_counter
		(rx_counter, thread_index, t0->sw_if_index, 1, len0);
	      pkts_decapsulated++;
	    }

	  vnet_buffer2 (b0)->gbp.flags = (vxlan_gbp_get_gpflags (vxlan_gbp0) |
					  VXLAN_GBP_GPFLAGS_R);
	  vnet_buffer2 (b0)->gbp.sclass = vxlan_gbp_get_sclass (vxlan_gbp0);


	  if (PREDICT_FALSE (t1 == NULL || !i_and_g1))
	    {
	      if (t1 != NULL && !i_and_g1)
		{
		  error1 = VXLAN_GBP_ERROR_BAD_FLAGS;
		  vlib_increment_combined_counter
		    (drop_counter, thread_index, t1->sw_if_index, 1, len1);
		  next1 = VXLAN_GBP_INPUT_NEXT_DROP;
		}
	      else
		{
		  error1 = VXLAN_GBP_ERROR_NO_SUCH_TUNNEL;
		  next1 = VXLAN_GBP_INPUT_NEXT_PUNT;
		  if (is_ip4)
		    b1->punt_reason =
		      vxm->punt_no_such_tunnel[FIB_PROTOCOL_IP4];
		  else
		    b1->punt_reason =
		      vxm->punt_no_such_tunnel[FIB_PROTOCOL_IP6];
		}
	      b1->error = node->errors[error1];
	    }
	  else
	    {
	      next1 = vxlan_gbp_tunnel_get_next (t1, b1);

	      /* Set packet input sw_if_index to unicast VXLAN_GBP tunnel for learning */
	      vnet_buffer (b1)->sw_if_index[VLIB_RX] = t1->sw_if_index;
	      pkts_decapsulated++;

	      vlib_increment_combined_counter
		(rx_counter, thread_index, t1->sw_if_index, 1, len1);
	    }

	  vnet_buffer2 (b1)->gbp.flags = (vxlan_gbp_get_gpflags (vxlan_gbp1) |
					  VXLAN_GBP_GPFLAGS_R);

	  vnet_buffer2 (b1)->gbp.sclass = vxlan_gbp_get_sclass (vxlan_gbp1);

	  vnet_update_l2_len (b0);
	  vnet_update_l2_len (b1);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_gbp_rx_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->error = error0;
	      tr->tunnel_index = t0 == 0 ? ~0 : t0 - vxm->tunnels;
	      tr->vni = vxlan_gbp_get_vni (vxlan_gbp0);
	      tr->sclass = vxlan_gbp_get_sclass (vxlan_gbp0);
	      tr->flags = vxlan_gbp_get_gpflags (vxlan_gbp0);
	    }
	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_gbp_rx_trace_t *tr =
		vlib_add_trace (vm, node, b1, sizeof (*tr));
	      tr->next_index = next1;
	      tr->error = error1;
	      tr->tunnel_index = t1 == 0 ? ~0 : t1 - vxm->tunnels;
	      tr->vni = vxlan_gbp_get_vni (vxlan_gbp1);
	      tr->sclass = vxlan_gbp_get_sclass (vxlan_gbp1);
	      tr->flags = vxlan_gbp_get_gpflags (vxlan_gbp1);
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = to_next[0] = from[0];
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

	  /* udp leaves current_data pointing at the vxlan_gbp header */
	  void *cur0 = vlib_buffer_get_current (b0);
	  vxlan_gbp_header_t *vxlan_gbp0 = cur0;
	  ip4_header_t *ip4_0;
	  ip6_header_t *ip6_0;
	  if (is_ip4)
	    ip4_0 = cur0 - sizeof (udp_header_t) - sizeof (ip4_header_t);
	  else
	    ip6_0 = cur0 - sizeof (udp_header_t) - sizeof (ip6_header_t);

	  u32 fi0 = buf_fib_index (b0, is_ip4);

	  vxlan_gbp_tunnel_t *t0;
	  if (is_ip4)
	    t0 = vxlan4_gbp_find_tunnel (vxm, &last4, fi0, ip4_0, vxlan_gbp0);
	  else
	    t0 = vxlan6_gbp_find_tunnel (vxm, &last6, fi0, ip6_0, vxlan_gbp0);

	  uword len0 = vlib_buffer_length_in_chain (vm, b0);

	  vxlan_gbp_input_next_t next0;
	  u8 error0 = 0;
	  u8 flags0 = vxlan_gbp_get_flags (vxlan_gbp0);

	  /* pop (ip, udp, vxlan_gbp) */
	  vlib_buffer_advance (b0, sizeof (*vxlan_gbp0));

	  u8 i_and_g0 = ((flags0 & VXLAN_GBP_FLAGS_GI) == VXLAN_GBP_FLAGS_GI);

	  /* Validate VXLAN_GBP tunnel encap-fib index against packet */
	  if (PREDICT_FALSE (t0 == NULL || !i_and_g0))
	    {
	      if (t0 != NULL && !i_and_g0)
		{
		  error0 = VXLAN_GBP_ERROR_BAD_FLAGS;
		  vlib_increment_combined_counter
		    (drop_counter, thread_index, t0->sw_if_index, 1, len0);
		  next0 = VXLAN_GBP_INPUT_NEXT_DROP;
		}
	      else
		{
		  error0 = VXLAN_GBP_ERROR_NO_SUCH_TUNNEL;
		  next0 = VXLAN_GBP_INPUT_NEXT_PUNT;
		  if (is_ip4)
		    b0->punt_reason =
		      vxm->punt_no_such_tunnel[FIB_PROTOCOL_IP4];
		  else
		    b0->punt_reason =
		      vxm->punt_no_such_tunnel[FIB_PROTOCOL_IP6];
		}
	      b0->error = node->errors[error0];
	    }
	  else
	    {
	      next0 = vxlan_gbp_tunnel_get_next (t0, b0);
	      /* Set packet input sw_if_index to unicast VXLAN_GBP tunnel for learning */
	      vnet_buffer (b0)->sw_if_index[VLIB_RX] = t0->sw_if_index;
	      pkts_decapsulated++;

	      vlib_increment_combined_counter
		(rx_counter, thread_index, t0->sw_if_index, 1, len0);
	    }
	  vnet_buffer2 (b0)->gbp.flags = (vxlan_gbp_get_gpflags (vxlan_gbp0) |
					  VXLAN_GBP_GPFLAGS_R);

	  vnet_buffer2 (b0)->gbp.sclass = vxlan_gbp_get_sclass (vxlan_gbp0);

	  /* Required to make the l2 tag push / pop code work on l2 subifs */
	  vnet_update_l2_len (b0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_gbp_rx_trace_t *tr
		= vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->error = error0;
	      tr->tunnel_index = t0 == 0 ? ~0 : t0 - vxm->tunnels;
	      tr->vni = vxlan_gbp_get_vni (vxlan_gbp0);
	      tr->sclass = vxlan_gbp_get_sclass (vxlan_gbp0);
	      tr->flags = vxlan_gbp_get_gpflags (vxlan_gbp0);
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  /* Do we still need this now that tunnel tx stats is kept? */
  u32 node_idx =
    is_ip4 ? vxlan4_gbp_input_node.index : vxlan6_gbp_input_node.index;
  vlib_node_increment_counter (vm, node_idx, VXLAN_GBP_ERROR_DECAPSULATED,
			       pkts_decapsulated);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (vxlan4_gbp_input_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return vxlan_gbp_input (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (vxlan6_gbp_input_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return vxlan_gbp_input (vm, node, from_frame, /* is_ip4 */ 0);
}

static char *vxlan_gbp_error_strings[] = {
#define vxlan_gbp_error(n,s) s,
#include <vnet/vxlan-gbp/vxlan_gbp_error.def>
#undef vxlan_gbp_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vxlan4_gbp_input_node) =
{
  .name = "vxlan4-gbp-input",
  .vector_size = sizeof (u32),
  .n_errors = VXLAN_GBP_N_ERROR,
  .error_strings = vxlan_gbp_error_strings,
  .n_next_nodes = VXLAN_GBP_INPUT_N_NEXT,
  .format_trace = format_vxlan_gbp_rx_trace,
  .next_nodes = {
#define _(s,n) [VXLAN_GBP_INPUT_NEXT_##s] = n,
    foreach_vxlan_gbp_input_next
#undef _
  },
};

VLIB_REGISTER_NODE (vxlan6_gbp_input_node) =
{
  .name = "vxlan6-gbp-input",
  .vector_size = sizeof (u32),
  .n_errors = VXLAN_GBP_N_ERROR,
  .error_strings = vxlan_gbp_error_strings,
  .n_next_nodes = VXLAN_GBP_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [VXLAN_GBP_INPUT_NEXT_##s] = n,
    foreach_vxlan_gbp_input_next
#undef _
  },
  .format_trace = format_vxlan_gbp_rx_trace,
};
/* *INDENT-ON* */

typedef enum
{
  IP_VXLAN_GBP_BYPASS_NEXT_DROP,
  IP_VXLAN_GBP_BYPASS_NEXT_VXLAN_GBP,
  IP_VXLAN_GBP_BYPASS_N_NEXT,
} ip_vxlan_gbp_bypass_next_t;

always_inline uword
ip_vxlan_gbp_bypass_inline (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * frame, u32 is_ip4)
{
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;
  u32 *from, *to_next, n_left_from, n_left_to_next, next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_input_node.index);
  ip4_address_t addr4;		/* last IPv4 address matching a local VTEP address */
  ip6_address_t addr6;		/* last IPv6 address matching a local VTEP address */

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame);

  if (is_ip4)
    addr4.data_u32 = ~0;
  else
    ip6_address_set_zero (&addr6);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *b0, *b1;
	  ip4_header_t *ip40, *ip41;
	  ip6_header_t *ip60, *ip61;
	  udp_header_t *udp0, *udp1;
	  u32 bi0, ip_len0, udp_len0, flags0, next0;
	  u32 bi1, ip_len1, udp_len1, flags1, next1;
	  i32 len_diff0, len_diff1;
	  u8 error0, good_udp0, proto0;
	  u8 error1, good_udp1, proto1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      ip41 = vlib_buffer_get_current (b1);
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      ip61 = vlib_buffer_get_current (b1);
	    }

	  /* Setup packet for next IP feature */
	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);

	  if (is_ip4)
	    {
	      /* Treat IP frag packets as "experimental" protocol for now
	         until support of IP frag reassembly is implemented */
	      proto0 = ip4_is_fragment (ip40) ? 0xfe : ip40->protocol;
	      proto1 = ip4_is_fragment (ip41) ? 0xfe : ip41->protocol;
	    }
	  else
	    {
	      proto0 = ip60->protocol;
	      proto1 = ip61->protocol;
	    }

	  /* Process packet 0 */
	  if (proto0 != IP_PROTOCOL_UDP)
	    goto exit0;		/* not UDP packet */

	  if (is_ip4)
	    udp0 = ip4_next_header (ip40);
	  else
	    udp0 = ip6_next_header (ip60);

	  if (udp0->dst_port != clib_host_to_net_u16 (UDP_DST_PORT_vxlan_gbp))
	    goto exit0;		/* not VXLAN_GBP packet */

	  /* Validate DIP against VTEPs */
	  if (is_ip4)
	    {
	      if (addr4.as_u32 != ip40->dst_address.as_u32)
		{
		  if (!hash_get (vxm->vtep4, ip40->dst_address.as_u32))
		    goto exit0;	/* no local VTEP for VXLAN_GBP packet */
		  addr4 = ip40->dst_address;
		}
	    }
	  else
	    {
	      if (!ip6_address_is_equal (&addr6, &ip60->dst_address))
		{
		  if (!hash_get_mem (vxm->vtep6, &ip60->dst_address))
		    goto exit0;	/* no local VTEP for VXLAN_GBP packet */
		  addr6 = ip60->dst_address;
		}
	    }

	  flags0 = b0->flags;
	  good_udp0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_udp0 |= udp0->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip4)
	    ip_len0 = clib_net_to_host_u16 (ip40->length);
	  else
	    ip_len0 = clib_net_to_host_u16 (ip60->payload_length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);
	  len_diff0 = ip_len0 - udp_len0;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp0))
	    {
	      if ((flags0 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
		{
		  if (is_ip4)
		    flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
		  else
		    flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);
		  good_udp0 =
		    (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
		}
	    }

	  if (is_ip4)
	    {
	      error0 = good_udp0 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP4_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error0 = good_udp0 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP6_ERROR_UDP_LENGTH;
	    }

	  next0 = error0 ?
	    IP_VXLAN_GBP_BYPASS_NEXT_DROP :
	    IP_VXLAN_GBP_BYPASS_NEXT_VXLAN_GBP;
	  b0->error = error0 ? error_node->errors[error0] : 0;

	  /* vxlan-gbp-input node expect current at VXLAN_GBP header */
	  if (is_ip4)
	    vlib_buffer_advance (b0,
				 sizeof (ip4_header_t) +
				 sizeof (udp_header_t));
	  else
	    vlib_buffer_advance (b0,
				 sizeof (ip6_header_t) +
				 sizeof (udp_header_t));

	exit0:
	  /* Process packet 1 */
	  if (proto1 != IP_PROTOCOL_UDP)
	    goto exit1;		/* not UDP packet */

	  if (is_ip4)
	    udp1 = ip4_next_header (ip41);
	  else
	    udp1 = ip6_next_header (ip61);

	  if (udp1->dst_port != clib_host_to_net_u16 (UDP_DST_PORT_vxlan_gbp))
	    goto exit1;		/* not VXLAN_GBP packet */

	  /* Validate DIP against VTEPs */
	  if (is_ip4)
	    {
	      if (addr4.as_u32 != ip41->dst_address.as_u32)
		{
		  if (!hash_get (vxm->vtep4, ip41->dst_address.as_u32))
		    goto exit1;	/* no local VTEP for VXLAN_GBP packet */
		  addr4 = ip41->dst_address;
		}
	    }
	  else
	    {
	      if (!ip6_address_is_equal (&addr6, &ip61->dst_address))
		{
		  if (!hash_get_mem (vxm->vtep6, &ip61->dst_address))
		    goto exit1;	/* no local VTEP for VXLAN_GBP packet */
		  addr6 = ip61->dst_address;
		}
	    }

	  flags1 = b1->flags;
	  good_udp1 = (flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_udp1 |= udp1->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip4)
	    ip_len1 = clib_net_to_host_u16 (ip41->length);
	  else
	    ip_len1 = clib_net_to_host_u16 (ip61->payload_length);
	  udp_len1 = clib_net_to_host_u16 (udp1->length);
	  len_diff1 = ip_len1 - udp_len1;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp1))
	    {
	      if ((flags1 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
		{
		  if (is_ip4)
		    flags1 = ip4_tcp_udp_validate_checksum (vm, b1);
		  else
		    flags1 = ip6_tcp_udp_icmp_validate_checksum (vm, b1);
		  good_udp1 =
		    (flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
		}
	    }

	  if (is_ip4)
	    {
	      error1 = good_udp1 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error1 = (len_diff1 >= 0) ? error1 : IP4_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error1 = good_udp1 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error1 = (len_diff1 >= 0) ? error1 : IP6_ERROR_UDP_LENGTH;
	    }

	  next1 = error1 ?
	    IP_VXLAN_GBP_BYPASS_NEXT_DROP :
	    IP_VXLAN_GBP_BYPASS_NEXT_VXLAN_GBP;
	  b1->error = error1 ? error_node->errors[error1] : 0;

	  /* vxlan_gbp-input node expect current at VXLAN_GBP header */
	  if (is_ip4)
	    vlib_buffer_advance (b1,
				 sizeof (ip4_header_t) +
				 sizeof (udp_header_t));
	  else
	    vlib_buffer_advance (b1,
				 sizeof (ip6_header_t) +
				 sizeof (udp_header_t));

	exit1:
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  udp_header_t *udp0;
	  u32 bi0, ip_len0, udp_len0, flags0, next0;
	  i32 len_diff0;
	  u8 error0, good_udp0, proto0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  if (is_ip4)
	    ip40 = vlib_buffer_get_current (b0);
	  else
	    ip60 = vlib_buffer_get_current (b0);

	  /* Setup packet for next IP feature */
	  vnet_feature_next (&next0, b0);

	  if (is_ip4)
	    /* Treat IP4 frag packets as "experimental" protocol for now
	       until support of IP frag reassembly is implemented */
	    proto0 = ip4_is_fragment (ip40) ? 0xfe : ip40->protocol;
	  else
	    proto0 = ip60->protocol;

	  if (proto0 != IP_PROTOCOL_UDP)
	    goto exit;		/* not UDP packet */

	  if (is_ip4)
	    udp0 = ip4_next_header (ip40);
	  else
	    udp0 = ip6_next_header (ip60);

	  if (udp0->dst_port != clib_host_to_net_u16 (UDP_DST_PORT_vxlan_gbp))
	    goto exit;		/* not VXLAN_GBP packet */

	  /* Validate DIP against VTEPs */
	  if (is_ip4)
	    {
	      if (addr4.as_u32 != ip40->dst_address.as_u32)
		{
		  if (!hash_get (vxm->vtep4, ip40->dst_address.as_u32))
		    goto exit;	/* no local VTEP for VXLAN_GBP packet */
		  addr4 = ip40->dst_address;
		}
	    }
	  else
	    {
	      if (!ip6_address_is_equal (&addr6, &ip60->dst_address))
		{
		  if (!hash_get_mem (vxm->vtep6, &ip60->dst_address))
		    goto exit;	/* no local VTEP for VXLAN_GBP packet */
		  addr6 = ip60->dst_address;
		}
	    }

	  flags0 = b0->flags;
	  good_udp0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_udp0 |= udp0->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip4)
	    ip_len0 = clib_net_to_host_u16 (ip40->length);
	  else
	    ip_len0 = clib_net_to_host_u16 (ip60->payload_length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);
	  len_diff0 = ip_len0 - udp_len0;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp0))
	    {
	      if ((flags0 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
		{
		  if (is_ip4)
		    flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
		  else
		    flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);
		  good_udp0 =
		    (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
		}
	    }

	  if (is_ip4)
	    {
	      error0 = good_udp0 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP4_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error0 = good_udp0 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP6_ERROR_UDP_LENGTH;
	    }

	  next0 = error0 ?
	    IP_VXLAN_GBP_BYPASS_NEXT_DROP :
	    IP_VXLAN_GBP_BYPASS_NEXT_VXLAN_GBP;
	  b0->error = error0 ? error_node->errors[error0] : 0;

	  /* vxlan_gbp-input node expect current at VXLAN_GBP header */
	  if (is_ip4)
	    vlib_buffer_advance (b0,
				 sizeof (ip4_header_t) +
				 sizeof (udp_header_t));
	  else
	    vlib_buffer_advance (b0,
				 sizeof (ip6_header_t) +
				 sizeof (udp_header_t));

	exit:
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_vxlan_gbp_bypass_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return ip_vxlan_gbp_bypass_inline (vm, node, frame, /* is_ip4 */ 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_vxlan_gbp_bypass_node) =
{
  .name = "ip4-vxlan-gbp-bypass",
  .vector_size = sizeof (u32),
  .n_next_nodes = IP_VXLAN_GBP_BYPASS_N_NEXT,
  .next_nodes = {
	  [IP_VXLAN_GBP_BYPASS_NEXT_DROP] = "error-drop",
	  [IP_VXLAN_GBP_BYPASS_NEXT_VXLAN_GBP] = "vxlan4-gbp-input",
  },
  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_forward_next_trace,
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
/* Dummy init function to get us linked in. */
clib_error_t *
ip4_vxlan_gbp_bypass_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ip4_vxlan_gbp_bypass_init);
#endif /* CLIB_MARCH_VARIANT */

VLIB_NODE_FN (ip6_vxlan_gbp_bypass_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return ip_vxlan_gbp_bypass_inline (vm, node, frame, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_vxlan_gbp_bypass_node) =
{
  .name = "ip6-vxlan-gbp-bypass",
  .vector_size = sizeof (u32),
  .n_next_nodes = IP_VXLAN_GBP_BYPASS_N_NEXT,
  .next_nodes = {
    [IP_VXLAN_GBP_BYPASS_NEXT_DROP] = "error-drop",
    [IP_VXLAN_GBP_BYPASS_NEXT_VXLAN_GBP] = "vxlan6-gbp-input",
  },
  .format_buffer = format_ip6_header,
  .format_trace = format_ip6_forward_next_trace,
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
/* Dummy init function to get us linked in. */
clib_error_t *
ip6_vxlan_gbp_bypass_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ip6_vxlan_gbp_bypass_init);
#endif /* CLIB_MARCH_VARIANT */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
