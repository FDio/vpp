/*
 * decap.c: vxlan tunnel decap packet processing
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

#include <vlib/vlib.h>
#include <vnet/vxlan/vxlan.h>
#include <vnet/udp/udp_local.h>

#ifndef CLIB_MARCH_VARIANT
vlib_node_registration_t vxlan4_input_node;
vlib_node_registration_t vxlan6_input_node;
#endif

typedef struct
{
  u32 next_index;
  u32 tunnel_index;
  u32 error;
  u32 vni;
} vxlan_rx_trace_t;

static u8 *
format_vxlan_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vxlan_rx_trace_t *t = va_arg (*args, vxlan_rx_trace_t *);

  if (t->tunnel_index == ~0)
    return format (s, "VXLAN decap error - tunnel for vni %d does not exist",
		   t->vni);
  return format (s, "VXLAN decap from vxlan_tunnel%d vni %d next %d error %d",
		 t->tunnel_index, t->vni, t->next_index, t->error);
}

typedef vxlan4_tunnel_key_t last_tunnel_cache4;

static const vxlan_decap_info_t decap_not_found = {
  .sw_if_index = ~0,
  .next_index = VXLAN_INPUT_NEXT_DROP,
  .error = VXLAN_ERROR_NO_SUCH_TUNNEL
};

static const vxlan_decap_info_t decap_bad_flags = {
  .sw_if_index = ~0,
  .next_index = VXLAN_INPUT_NEXT_DROP,
  .error = VXLAN_ERROR_BAD_FLAGS
};

always_inline vxlan_decap_info_t
vxlan4_find_tunnel (vxlan_main_t * vxm, last_tunnel_cache4 * cache,
		    u32 fib_index, ip4_header_t * ip4_0,
		    vxlan_header_t * vxlan0, u32 * stats_sw_if_index)
{
  if (PREDICT_FALSE (vxlan0->flags != VXLAN_FLAGS_I))
    return decap_bad_flags;

  /* Make sure VXLAN tunnel exist according to packet S/D IP, UDP port, VRF,
   * and VNI */
  u32 dst = ip4_0->dst_address.as_u32;
  u32 src = ip4_0->src_address.as_u32;
  udp_header_t *udp = ip4_next_header (ip4_0);
  vxlan4_tunnel_key_t key4 = {
    .key[0] = ((u64) dst << 32) | src,
    .key[1] = ((u64) udp->dst_port << 48) | ((u64) fib_index << 32) |
	      vxlan0->vni_reserved,
  };

  if (PREDICT_TRUE
      (key4.key[0] == cache->key[0] && key4.key[1] == cache->key[1]))
    {
      /* cache hit */
      vxlan_decap_info_t di = {.as_u64 = cache->value };
      *stats_sw_if_index = di.sw_if_index;
      return di;
    }

  int rv = clib_bihash_search_inline_16_8 (&vxm->vxlan4_tunnel_by_key, &key4);
  if (PREDICT_TRUE (rv == 0))
    {
      *cache = key4;
      vxlan_decap_info_t di = {.as_u64 = key4.value };
      *stats_sw_if_index = di.sw_if_index;
      return di;
    }

  /* try multicast */
  if (PREDICT_TRUE (!ip4_address_is_multicast (&ip4_0->dst_address)))
    return decap_not_found;

  /* search for mcast decap info by mcast address */
  key4.key[0] = dst;
  rv = clib_bihash_search_inline_16_8 (&vxm->vxlan4_tunnel_by_key, &key4);
  if (rv != 0)
    return decap_not_found;

  /* search for unicast tunnel using the mcast tunnel local(src) ip */
  vxlan_decap_info_t mdi = {.as_u64 = key4.value };
  key4.key[0] = ((u64) mdi.local_ip.as_u32 << 32) | src;
  rv = clib_bihash_search_inline_16_8 (&vxm->vxlan4_tunnel_by_key, &key4);
  if (PREDICT_FALSE (rv != 0))
    return decap_not_found;

  /* mcast traffic does not update the cache */
  *stats_sw_if_index = mdi.sw_if_index;
  vxlan_decap_info_t di = {.as_u64 = key4.value };
  return di;
}

typedef vxlan6_tunnel_key_t last_tunnel_cache6;

always_inline vxlan_decap_info_t
vxlan6_find_tunnel (vxlan_main_t * vxm, last_tunnel_cache6 * cache,
		    u32 fib_index, ip6_header_t * ip6_0,
		    vxlan_header_t * vxlan0, u32 * stats_sw_if_index)
{
  if (PREDICT_FALSE (vxlan0->flags != VXLAN_FLAGS_I))
    return decap_bad_flags;

  /* Make sure VXLAN tunnel exist according to packet SIP, UDP port, VRF, and
   * VNI */
  udp_header_t *udp = ip6_next_header (ip6_0);
  vxlan6_tunnel_key_t key6 = {
    .key[0] = ip6_0->src_address.as_u64[0],
    .key[1] = ip6_0->src_address.as_u64[1],
    .key[2] = ((u64) udp->dst_port << 48) | ((u64) fib_index << 32) |
	      vxlan0->vni_reserved,
  };

  if (PREDICT_FALSE
      (clib_bihash_key_compare_24_8 (key6.key, cache->key) == 0))
    {
      int rv =
	clib_bihash_search_inline_24_8 (&vxm->vxlan6_tunnel_by_key, &key6);
      if (PREDICT_FALSE (rv != 0))
	return decap_not_found;

      *cache = key6;
    }
  vxlan_tunnel_t *t0 = pool_elt_at_index (vxm->tunnels, cache->value);

  /* Validate VXLAN tunnel SIP against packet DIP */
  if (PREDICT_TRUE (ip6_address_is_equal (&ip6_0->dst_address, &t0->src.ip6)))
    *stats_sw_if_index = t0->sw_if_index;
  else
    {
      /* try multicast */
      if (PREDICT_TRUE (!ip6_address_is_multicast (&ip6_0->dst_address)))
	return decap_not_found;

      /* Make sure mcast VXLAN tunnel exist by packet DIP and VNI */
      key6.key[0] = ip6_0->dst_address.as_u64[0];
      key6.key[1] = ip6_0->dst_address.as_u64[1];
      int rv =
	clib_bihash_search_inline_24_8 (&vxm->vxlan6_tunnel_by_key, &key6);
      if (PREDICT_FALSE (rv != 0))
	return decap_not_found;

      vxlan_tunnel_t *mcast_t0 = pool_elt_at_index (vxm->tunnels, key6.value);
      *stats_sw_if_index = mcast_t0->sw_if_index;
    }

  vxlan_decap_info_t di = {
    .sw_if_index = t0->sw_if_index,
    .next_index = t0->decap_next_index,
  };
  return di;
}

always_inline uword
vxlan_input (vlib_main_t * vm,
	     vlib_node_runtime_t * node,
	     vlib_frame_t * from_frame, u32 is_ip4)
{
  vxlan_main_t *vxm = &vxlan_main;
  vnet_main_t *vnm = vxm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_combined_counter_main_t *rx_counter =
    im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX;
  last_tunnel_cache4 last4;
  last_tunnel_cache6 last6;
  u32 pkts_dropped = 0;
  u32 thread_index = vlib_get_thread_index ();

  if (is_ip4)
    clib_memset (&last4, 0xff, sizeof last4);
  else
    clib_memset (&last6, 0xff, sizeof last6);

  u32 *from = vlib_frame_vector_args (from_frame);
  u32 n_left_from = from_frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  u32 stats_if0 = ~0, stats_if1 = ~0;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  while (n_left_from >= 4)
    {
      /* Prefetch next iteration. */
      vlib_prefetch_buffer_header (b[2], LOAD);
      vlib_prefetch_buffer_header (b[3], LOAD);

      /* udp leaves current_data pointing at the vxlan header */
      void *cur0 = vlib_buffer_get_current (b[0]);
      void *cur1 = vlib_buffer_get_current (b[1]);
      vxlan_header_t *vxlan0 = cur0;
      vxlan_header_t *vxlan1 = cur1;


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

      /* pop vxlan */
      vlib_buffer_advance (b[0], sizeof *vxlan0);
      vlib_buffer_advance (b[1], sizeof *vxlan1);

      u32 fi0 = vlib_buffer_get_ip_fib_index (b[0], is_ip4);
      u32 fi1 = vlib_buffer_get_ip_fib_index (b[1], is_ip4);

      vxlan_decap_info_t di0 = is_ip4 ?
	vxlan4_find_tunnel (vxm, &last4, fi0, ip4_0, vxlan0, &stats_if0) :
	vxlan6_find_tunnel (vxm, &last6, fi0, ip6_0, vxlan0, &stats_if0);
      vxlan_decap_info_t di1 = is_ip4 ?
	vxlan4_find_tunnel (vxm, &last4, fi1, ip4_1, vxlan1, &stats_if1) :
	vxlan6_find_tunnel (vxm, &last6, fi1, ip6_1, vxlan1, &stats_if1);

      /* Prefetch next iteration. */
      CLIB_PREFETCH (b[2]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH (b[3]->data, CLIB_CACHE_LINE_BYTES, LOAD);

      u32 len0 = vlib_buffer_length_in_chain (vm, b[0]);
      u32 len1 = vlib_buffer_length_in_chain (vm, b[1]);

      next[0] = di0.next_index;
      next[1] = di1.next_index;

      u8 any_error = di0.error | di1.error;
      if (PREDICT_TRUE (any_error == 0))
	{
	  /* Required to make the l2 tag push / pop code work on l2 subifs */
	  vnet_update_l2_len (b[0]);
	  vnet_update_l2_len (b[1]);
	  /* Set packet input sw_if_index to unicast VXLAN tunnel for learning */
	  vnet_buffer (b[0])->sw_if_index[VLIB_RX] = di0.sw_if_index;
	  vnet_buffer (b[1])->sw_if_index[VLIB_RX] = di1.sw_if_index;
	  vlib_increment_combined_counter (rx_counter, thread_index,
					   stats_if0, 1, len0);
	  vlib_increment_combined_counter (rx_counter, thread_index,
					   stats_if1, 1, len1);
	}
      else
	{
	  if (di0.error == 0)
	    {
	      vnet_update_l2_len (b[0]);
	      vnet_buffer (b[0])->sw_if_index[VLIB_RX] = di0.sw_if_index;
	      vlib_increment_combined_counter (rx_counter, thread_index,
					       stats_if0, 1, len0);
	    }
	  else
	    {
	      b[0]->error = node->errors[di0.error];
	      pkts_dropped++;
	    }

	  if (di1.error == 0)
	    {
	      vnet_update_l2_len (b[1]);
	      vnet_buffer (b[1])->sw_if_index[VLIB_RX] = di1.sw_if_index;
	      vlib_increment_combined_counter (rx_counter, thread_index,
					       stats_if1, 1, len1);
	    }
	  else
	    {
	      b[1]->error = node->errors[di1.error];
	      pkts_dropped++;
	    }
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  vxlan_rx_trace_t *tr =
	    vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->next_index = next[0];
	  tr->error = di0.error;
	  tr->tunnel_index = di0.sw_if_index == ~0 ?
	    ~0 : vxm->tunnel_index_by_sw_if_index[di0.sw_if_index];
	  tr->vni = vnet_get_vni (vxlan0);
	}
      if (PREDICT_FALSE (b[1]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  vxlan_rx_trace_t *tr =
	    vlib_add_trace (vm, node, b[1], sizeof (*tr));
	  tr->next_index = next[1];
	  tr->error = di1.error;
	  tr->tunnel_index = di1.sw_if_index == ~0 ?
	    ~0 : vxm->tunnel_index_by_sw_if_index[di1.sw_if_index];
	  tr->vni = vnet_get_vni (vxlan1);
	}
      b += 2;
      next += 2;
      n_left_from -= 2;
    }

  while (n_left_from > 0)
    {
      /* udp leaves current_data pointing at the vxlan header */
      void *cur0 = vlib_buffer_get_current (b[0]);
      vxlan_header_t *vxlan0 = cur0;
      ip4_header_t *ip4_0;
      ip6_header_t *ip6_0;
      if (is_ip4)
	ip4_0 = cur0 - sizeof (udp_header_t) - sizeof (ip4_header_t);
      else
	ip6_0 = cur0 - sizeof (udp_header_t) - sizeof (ip6_header_t);

      /* pop (ip, udp, vxlan) */
      vlib_buffer_advance (b[0], sizeof (*vxlan0));

      u32 fi0 = vlib_buffer_get_ip_fib_index (b[0], is_ip4);

      vxlan_decap_info_t di0 = is_ip4 ?
	vxlan4_find_tunnel (vxm, &last4, fi0, ip4_0, vxlan0, &stats_if0) :
	vxlan6_find_tunnel (vxm, &last6, fi0, ip6_0, vxlan0, &stats_if0);

      uword len0 = vlib_buffer_length_in_chain (vm, b[0]);

      next[0] = di0.next_index;

      /* Validate VXLAN tunnel encap-fib index against packet */
      if (di0.error == 0)
	{
	  /* Required to make the l2 tag push / pop code work on l2 subifs */
	  vnet_update_l2_len (b[0]);

	  /* Set packet input sw_if_index to unicast VXLAN tunnel for learning */
	  vnet_buffer (b[0])->sw_if_index[VLIB_RX] = di0.sw_if_index;

	  vlib_increment_combined_counter (rx_counter, thread_index,
					   stats_if0, 1, len0);
	}
      else
	{
	  b[0]->error = node->errors[di0.error];
	  pkts_dropped++;
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  vxlan_rx_trace_t *tr
	    = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->next_index = next[0];
	  tr->error = di0.error;
	  tr->tunnel_index = di0.sw_if_index == ~0 ?
	    ~0 : vxm->tunnel_index_by_sw_if_index[di0.sw_if_index];
	  tr->vni = vnet_get_vni (vxlan0);
	}
      b += 1;
      next += 1;
      n_left_from -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, from_frame->n_vectors);
  /* Do we still need this now that tunnel tx stats is kept? */
  u32 node_idx = is_ip4 ? vxlan4_input_node.index : vxlan6_input_node.index;
  vlib_node_increment_counter (vm, node_idx, VXLAN_ERROR_DECAPSULATED,
			       from_frame->n_vectors - pkts_dropped);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (vxlan4_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return vxlan_input (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (vxlan6_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return vxlan_input (vm, node, from_frame, /* is_ip4 */ 0);
}

static char *vxlan_error_strings[] = {
#define vxlan_error(n,s) s,
#include <vnet/vxlan/vxlan_error.def>
#undef vxlan_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vxlan4_input_node) =
{
  .name = "vxlan4-input",
  .vector_size = sizeof (u32),
  .n_errors = VXLAN_N_ERROR,
  .error_strings = vxlan_error_strings,
  .n_next_nodes = VXLAN_INPUT_N_NEXT,
  .format_trace = format_vxlan_rx_trace,
  .next_nodes = {
#define _(s,n) [VXLAN_INPUT_NEXT_##s] = n,
    foreach_vxlan_input_next
#undef _
  },
};

VLIB_REGISTER_NODE (vxlan6_input_node) =
{
  .name = "vxlan6-input",
  .vector_size = sizeof (u32),
  .n_errors = VXLAN_N_ERROR,
  .error_strings = vxlan_error_strings,
  .n_next_nodes = VXLAN_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [VXLAN_INPUT_NEXT_##s] = n,
    foreach_vxlan_input_next
#undef _
  },
  .format_trace = format_vxlan_rx_trace,
};
/* *INDENT-ON* */

typedef enum
{
  IP_VXLAN_BYPASS_NEXT_DROP,
  IP_VXLAN_BYPASS_NEXT_VXLAN,
  IP_VXLAN_BYPASS_N_NEXT,
} ip_vxlan_bypass_next_t;

always_inline uword
ip_vxlan_bypass_inline (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * frame, u32 is_ip4)
{
  vxlan_main_t *vxm = &vxlan_main;
  u32 *from, *to_next, n_left_from, n_left_to_next, next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_input_node.index);
  vtep4_key_t last_vtep4;	/* last IPv4 address / fib index
				   matching a local VTEP address */
  vtep6_key_t last_vtep6;	/* last IPv6 address / fib index
				   matching a local VTEP address */
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;

  last_tunnel_cache4 last4;
  last_tunnel_cache6 last6;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  vlib_get_buffers (vm, from, bufs, n_left_from);

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  if (is_ip4)
    {
      vtep4_key_init (&last_vtep4);
      clib_memset (&last4, 0xff, sizeof last4);
    }
  else
    {
      vtep6_key_init (&last_vtep6);
      clib_memset (&last6, 0xff, sizeof last6);
    }

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *b0, *b1;
	  ip4_header_t *ip40, *ip41;
	  ip6_header_t *ip60, *ip61;
	  udp_header_t *udp0, *udp1;
	  vxlan_header_t *vxlan0, *vxlan1;
	  u32 bi0, ip_len0, udp_len0, flags0, next0;
	  u32 bi1, ip_len1, udp_len1, flags1, next1;
	  i32 len_diff0, len_diff1;
	  u8 error0, good_udp0, proto0;
	  u8 error1, good_udp1, proto1;
	  u32 stats_if0 = ~0, stats_if1 = ~0;

	  /* Prefetch next iteration. */
	  {
	    vlib_prefetch_buffer_header (b[2], LOAD);
	    vlib_prefetch_buffer_header (b[3], LOAD);

	    CLIB_PREFETCH (b[2]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (b[3]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  b0 = b[0];
	  b1 = b[1];
	  b += 2;
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

	  u32 fi0 = vlib_buffer_get_ip_fib_index (b0, is_ip4);
	  vxlan0 = vlib_buffer_get_current (b0) + sizeof (udp_header_t) +
		   sizeof (ip4_header_t);

	  vxlan_decap_info_t di0 =
	    is_ip4 ?
	      vxlan4_find_tunnel (vxm, &last4, fi0, ip40, vxlan0, &stats_if0) :
	      vxlan6_find_tunnel (vxm, &last6, fi0, ip60, vxlan0, &stats_if0);

	  if (PREDICT_FALSE (di0.sw_if_index == ~0))
	    goto exit0; /* unknown interface */

	  /* Validate DIP against VTEPs */
	  if (is_ip4)
	    {
#ifdef CLIB_HAVE_VEC512
	      if (!vtep4_check_vector (&vxm->vtep_table, b0, ip40, &last_vtep4,
				       &vxm->vtep4_u512))
#else
	      if (!vtep4_check (&vxm->vtep_table, b0, ip40, &last_vtep4))
#endif
		goto exit0;	/* no local VTEP for VXLAN packet */
	    }
	  else
	    {
	      if (!vtep6_check (&vxm->vtep_table, b0, ip60, &last_vtep6))
		goto exit0;	/* no local VTEP for VXLAN packet */
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
	      if (is_ip4)
		flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
	      else
		flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);
	      good_udp0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
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
	    IP_VXLAN_BYPASS_NEXT_DROP : IP_VXLAN_BYPASS_NEXT_VXLAN;
	  b0->error = error0 ? error_node->errors[error0] : 0;

	  /* vxlan-input node expect current at VXLAN header */
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

	  u32 fi1 = vlib_buffer_get_ip_fib_index (b1, is_ip4);
	  vxlan1 = vlib_buffer_get_current (b1) + sizeof (udp_header_t) +
		   sizeof (ip4_header_t);

	  vxlan_decap_info_t di1 =
	    is_ip4 ?
	      vxlan4_find_tunnel (vxm, &last4, fi1, ip41, vxlan1, &stats_if1) :
	      vxlan6_find_tunnel (vxm, &last6, fi1, ip61, vxlan1, &stats_if1);

	  if (PREDICT_FALSE (di1.sw_if_index == ~0))
	    goto exit1; /* unknown interface */

	  /* Validate DIP against VTEPs */
	  if (is_ip4)
	    {
#ifdef CLIB_HAVE_VEC512
	      if (!vtep4_check_vector (&vxm->vtep_table, b1, ip41, &last_vtep4,
				       &vxm->vtep4_u512))
#else
	      if (!vtep4_check (&vxm->vtep_table, b1, ip41, &last_vtep4))
#endif
		goto exit1;	/* no local VTEP for VXLAN packet */
	    }
	  else
	    {
	      if (!vtep6_check (&vxm->vtep_table, b1, ip61, &last_vtep6))
		goto exit1;	/* no local VTEP for VXLAN packet */
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
	      if (is_ip4)
		flags1 = ip4_tcp_udp_validate_checksum (vm, b1);
	      else
		flags1 = ip6_tcp_udp_icmp_validate_checksum (vm, b1);
	      good_udp1 = (flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
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
	    IP_VXLAN_BYPASS_NEXT_DROP : IP_VXLAN_BYPASS_NEXT_VXLAN;
	  b1->error = error1 ? error_node->errors[error1] : 0;

	  /* vxlan-input node expect current at VXLAN header */
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
	  vxlan_header_t *vxlan0;
	  u32 bi0, ip_len0, udp_len0, flags0, next0;
	  i32 len_diff0;
	  u8 error0, good_udp0, proto0;
	  u32 stats_if0 = ~0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = b[0];
	  b++;
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

	  u32 fi0 = vlib_buffer_get_ip_fib_index (b0, is_ip4);
	  vxlan0 = vlib_buffer_get_current (b0) + sizeof (udp_header_t) +
		   sizeof (ip4_header_t);

	  vxlan_decap_info_t di0 =
	    is_ip4 ?
	      vxlan4_find_tunnel (vxm, &last4, fi0, ip40, vxlan0, &stats_if0) :
	      vxlan6_find_tunnel (vxm, &last6, fi0, ip60, vxlan0, &stats_if0);

	  if (PREDICT_FALSE (di0.sw_if_index == ~0))
	    goto exit; /* unknown interface */

	  /* Validate DIP against VTEPs */
	  if (is_ip4)
	    {
#ifdef CLIB_HAVE_VEC512
	      if (!vtep4_check_vector (&vxm->vtep_table, b0, ip40, &last_vtep4,
				       &vxm->vtep4_u512))
#else
	      if (!vtep4_check (&vxm->vtep_table, b0, ip40, &last_vtep4))
#endif
		goto exit;	/* no local VTEP for VXLAN packet */
	    }
	  else
	    {
	      if (!vtep6_check (&vxm->vtep_table, b0, ip60, &last_vtep6))
		goto exit;	/* no local VTEP for VXLAN packet */
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
	      if (is_ip4)
		flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
	      else
		flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);
	      good_udp0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
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
	    IP_VXLAN_BYPASS_NEXT_DROP : IP_VXLAN_BYPASS_NEXT_VXLAN;
	  b0->error = error0 ? error_node->errors[error0] : 0;

	  /* vxlan-input node expect current at VXLAN header */
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

VLIB_NODE_FN (ip4_vxlan_bypass_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return ip_vxlan_bypass_inline (vm, node, frame, /* is_ip4 */ 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_vxlan_bypass_node) =
{
  .name = "ip4-vxlan-bypass",
  .vector_size = sizeof (u32),
  .n_next_nodes = IP_VXLAN_BYPASS_N_NEXT,
  .next_nodes = {
	  [IP_VXLAN_BYPASS_NEXT_DROP] = "error-drop",
	  [IP_VXLAN_BYPASS_NEXT_VXLAN] = "vxlan4-input",
  },
  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_forward_next_trace,
};

/* *INDENT-ON* */

/* Dummy init function to get us linked in. */
static clib_error_t *
ip4_vxlan_bypass_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ip4_vxlan_bypass_init);

VLIB_NODE_FN (ip6_vxlan_bypass_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return ip_vxlan_bypass_inline (vm, node, frame, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_vxlan_bypass_node) =
{
  .name = "ip6-vxlan-bypass",
  .vector_size = sizeof (u32),
  .n_next_nodes = IP_VXLAN_BYPASS_N_NEXT,
  .next_nodes = {
    [IP_VXLAN_BYPASS_NEXT_DROP] = "error-drop",
    [IP_VXLAN_BYPASS_NEXT_VXLAN] = "vxlan6-input",
  },
  .format_buffer = format_ip6_header,
  .format_trace = format_ip6_forward_next_trace,
};

/* *INDENT-ON* */

/* Dummy init function to get us linked in. */
static clib_error_t *
ip6_vxlan_bypass_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ip6_vxlan_bypass_init);

#define foreach_vxlan_flow_input_next        \
_(DROP, "error-drop")                           \
_(L2_INPUT, "l2-input")

typedef enum
{
#define _(s,n) VXLAN_FLOW_NEXT_##s,
  foreach_vxlan_flow_input_next
#undef _
    VXLAN_FLOW_N_NEXT,
} vxlan_flow_input_next_t;

#define foreach_vxlan_flow_error					\
  _(NONE, "no error")							\
  _(IP_CHECKSUM_ERROR, "Rx ip checksum errors")				\
  _(IP_HEADER_ERROR, "Rx ip header errors")				\
  _(UDP_CHECKSUM_ERROR, "Rx udp checksum errors")				\
  _(UDP_LENGTH_ERROR, "Rx udp length errors")

typedef enum
{
#define _(f,s) VXLAN_FLOW_ERROR_##f,
  foreach_vxlan_flow_error
#undef _
    VXLAN_FLOW_N_ERROR,
} vxlan_flow_error_t;

static char *vxlan_flow_error_strings[] = {
#define _(n,s) s,
  foreach_vxlan_flow_error
#undef _
};


static_always_inline u8
vxlan_validate_udp_csum (vlib_main_t * vm, vlib_buffer_t * b)
{
  u32 flags = b->flags;
  enum
  { offset =
      sizeof (ip4_header_t) + sizeof (udp_header_t) + sizeof (vxlan_header_t),
  };

  /* Verify UDP checksum */
  if ((flags & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
    {
      vlib_buffer_advance (b, -offset);
      flags = ip4_tcp_udp_validate_checksum (vm, b);
      vlib_buffer_advance (b, offset);
    }

  return (flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
}

static_always_inline u8
vxlan_check_udp_csum (vlib_main_t * vm, vlib_buffer_t * b)
{
  ip4_vxlan_header_t *hdr = vlib_buffer_get_current (b) - sizeof *hdr;
  udp_header_t *udp = &hdr->udp;
  /* Don't verify UDP checksum for packets with explicit zero checksum. */
  u8 good_csum = (b->flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0 ||
    udp->checksum == 0;

  return !good_csum;
}

static_always_inline u8
vxlan_check_ip (vlib_buffer_t * b, u16 payload_len)
{
  ip4_vxlan_header_t *hdr = vlib_buffer_get_current (b) - sizeof *hdr;
  u16 ip_len = clib_net_to_host_u16 (hdr->ip4.length);
  u16 expected = payload_len + sizeof *hdr;
  return ip_len > expected || hdr->ip4.ttl == 0
    || hdr->ip4.ip_version_and_header_length != 0x45;
}

static_always_inline u8
vxlan_check_ip_udp_len (vlib_buffer_t * b)
{
  ip4_vxlan_header_t *hdr = vlib_buffer_get_current (b) - sizeof *hdr;
  u16 ip_len = clib_net_to_host_u16 (hdr->ip4.length);
  u16 udp_len = clib_net_to_host_u16 (hdr->udp.length);
  return udp_len > ip_len;
}

static_always_inline u8
vxlan_err_code (u8 ip_err0, u8 udp_err0, u8 csum_err0)
{
  u8 error0 = VXLAN_FLOW_ERROR_NONE;
  if (ip_err0)
    error0 = VXLAN_FLOW_ERROR_IP_HEADER_ERROR;
  if (udp_err0)
    error0 = VXLAN_FLOW_ERROR_UDP_LENGTH_ERROR;
  if (csum_err0)
    error0 = VXLAN_FLOW_ERROR_UDP_CHECKSUM_ERROR;
  return error0;
}

VLIB_NODE_FN (vxlan4_flow_input_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * f)
{
  enum
  { payload_offset = sizeof (ip4_vxlan_header_t) };

  vxlan_main_t *vxm = &vxlan_main;
  vnet_interface_main_t *im = &vnet_main.interface_main;
  vlib_combined_counter_main_t *rx_counter[VXLAN_FLOW_N_NEXT] = {
    [VXLAN_FLOW_NEXT_DROP] =
      im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_DROP,
    [VXLAN_FLOW_NEXT_L2_INPUT] =
      im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
  };
  u32 thread_index = vlib_get_thread_index ();

  u32 *from = vlib_frame_vector_args (f);
  u32 n_left_from = f->n_vectors;
  u32 next_index = VXLAN_FLOW_NEXT_L2_INPUT;

  while (n_left_from > 0)
    {
      u32 n_left_to_next, *to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 3 && n_left_to_next > 3)
	{
	  u32 bi0 = to_next[0] = from[0];
	  u32 bi1 = to_next[1] = from[1];
	  u32 bi2 = to_next[2] = from[2];
	  u32 bi3 = to_next[3] = from[3];
	  from += 4;
	  n_left_from -= 4;
	  to_next += 4;
	  n_left_to_next -= 4;

	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  vlib_buffer_t *b1 = vlib_get_buffer (vm, bi1);
	  vlib_buffer_t *b2 = vlib_get_buffer (vm, bi2);
	  vlib_buffer_t *b3 = vlib_get_buffer (vm, bi3);

	  vlib_buffer_advance (b0, payload_offset);
	  vlib_buffer_advance (b1, payload_offset);
	  vlib_buffer_advance (b2, payload_offset);
	  vlib_buffer_advance (b3, payload_offset);

	  u16 len0 = vlib_buffer_length_in_chain (vm, b0);
	  u16 len1 = vlib_buffer_length_in_chain (vm, b1);
	  u16 len2 = vlib_buffer_length_in_chain (vm, b2);
	  u16 len3 = vlib_buffer_length_in_chain (vm, b3);

	  u32 next0 = VXLAN_FLOW_NEXT_L2_INPUT, next1 =
	    VXLAN_FLOW_NEXT_L2_INPUT, next2 =
	    VXLAN_FLOW_NEXT_L2_INPUT, next3 = VXLAN_FLOW_NEXT_L2_INPUT;

	  u8 ip_err0 = vxlan_check_ip (b0, len0);
	  u8 ip_err1 = vxlan_check_ip (b1, len1);
	  u8 ip_err2 = vxlan_check_ip (b2, len2);
	  u8 ip_err3 = vxlan_check_ip (b3, len3);
	  u8 ip_err = ip_err0 | ip_err1 | ip_err2 | ip_err3;

	  u8 udp_err0 = vxlan_check_ip_udp_len (b0);
	  u8 udp_err1 = vxlan_check_ip_udp_len (b1);
	  u8 udp_err2 = vxlan_check_ip_udp_len (b2);
	  u8 udp_err3 = vxlan_check_ip_udp_len (b3);
	  u8 udp_err = udp_err0 | udp_err1 | udp_err2 | udp_err3;

	  u8 csum_err0 = vxlan_check_udp_csum (vm, b0);
	  u8 csum_err1 = vxlan_check_udp_csum (vm, b1);
	  u8 csum_err2 = vxlan_check_udp_csum (vm, b2);
	  u8 csum_err3 = vxlan_check_udp_csum (vm, b3);
	  u8 csum_err = csum_err0 | csum_err1 | csum_err2 | csum_err3;

	  if (PREDICT_FALSE (csum_err))
	    {
	      if (csum_err0)
		csum_err0 = !vxlan_validate_udp_csum (vm, b0);
	      if (csum_err1)
		csum_err1 = !vxlan_validate_udp_csum (vm, b1);
	      if (csum_err2)
		csum_err2 = !vxlan_validate_udp_csum (vm, b2);
	      if (csum_err3)
		csum_err3 = !vxlan_validate_udp_csum (vm, b3);
	      csum_err = csum_err0 | csum_err1 | csum_err2 | csum_err3;
	    }

	  if (PREDICT_FALSE (ip_err || udp_err || csum_err))
	    {
	      if (ip_err0 || udp_err0 || csum_err0)
		{
		  next0 = VXLAN_FLOW_NEXT_DROP;
		  u8 error0 = vxlan_err_code (ip_err0, udp_err0, csum_err0);
		  b0->error = node->errors[error0];
		}
	      if (ip_err1 || udp_err1 || csum_err1)
		{
		  next1 = VXLAN_FLOW_NEXT_DROP;
		  u8 error1 = vxlan_err_code (ip_err1, udp_err1, csum_err1);
		  b1->error = node->errors[error1];
		}
	      if (ip_err2 || udp_err2 || csum_err2)
		{
		  next2 = VXLAN_FLOW_NEXT_DROP;
		  u8 error2 = vxlan_err_code (ip_err2, udp_err2, csum_err2);
		  b2->error = node->errors[error2];
		}
	      if (ip_err3 || udp_err3 || csum_err3)
		{
		  next3 = VXLAN_FLOW_NEXT_DROP;
		  u8 error3 = vxlan_err_code (ip_err3, udp_err3, csum_err3);
		  b3->error = node->errors[error3];
		}
	    }

	  vnet_update_l2_len (b0);
	  vnet_update_l2_len (b1);
	  vnet_update_l2_len (b2);
	  vnet_update_l2_len (b3);

	  ASSERT (b0->flow_id != 0);
	  ASSERT (b1->flow_id != 0);
	  ASSERT (b2->flow_id != 0);
	  ASSERT (b3->flow_id != 0);

	  u32 t_index0 = b0->flow_id - vxm->flow_id_start;
	  u32 t_index1 = b1->flow_id - vxm->flow_id_start;
	  u32 t_index2 = b2->flow_id - vxm->flow_id_start;
	  u32 t_index3 = b3->flow_id - vxm->flow_id_start;

	  vxlan_tunnel_t *t0 = &vxm->tunnels[t_index0];
	  vxlan_tunnel_t *t1 = &vxm->tunnels[t_index1];
	  vxlan_tunnel_t *t2 = &vxm->tunnels[t_index2];
	  vxlan_tunnel_t *t3 = &vxm->tunnels[t_index3];

	  /* flow id consumed */
	  b0->flow_id = 0;
	  b1->flow_id = 0;
	  b2->flow_id = 0;
	  b3->flow_id = 0;

	  u32 sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	    t0->sw_if_index;
	  u32 sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX] =
	    t1->sw_if_index;
	  u32 sw_if_index2 = vnet_buffer (b2)->sw_if_index[VLIB_RX] =
	    t2->sw_if_index;
	  u32 sw_if_index3 = vnet_buffer (b3)->sw_if_index[VLIB_RX] =
	    t3->sw_if_index;

	  vlib_increment_combined_counter (rx_counter[next0], thread_index,
					   sw_if_index0, 1, len0);
	  vlib_increment_combined_counter (rx_counter[next1], thread_index,
					   sw_if_index1, 1, len1);
	  vlib_increment_combined_counter (rx_counter[next2], thread_index,
					   sw_if_index2, 1, len2);
	  vlib_increment_combined_counter (rx_counter[next3], thread_index,
					   sw_if_index3, 1, len3);

	  u32 flags = b0->flags | b1->flags | b2->flags | b3->flags;

	  if (PREDICT_FALSE (flags & VLIB_BUFFER_IS_TRACED))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  vxlan_rx_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof *tr);
		  u8 error0 = vxlan_err_code (ip_err0, udp_err0, csum_err0);
		  tr->next_index = next0;
		  tr->error = error0;
		  tr->tunnel_index = t_index0;
		  tr->vni = t0->vni;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  vxlan_rx_trace_t *tr =
		    vlib_add_trace (vm, node, b1, sizeof *tr);
		  u8 error1 = vxlan_err_code (ip_err1, udp_err1, csum_err1);
		  tr->next_index = next1;
		  tr->error = error1;
		  tr->tunnel_index = t_index1;
		  tr->vni = t1->vni;
		}
	      if (b2->flags & VLIB_BUFFER_IS_TRACED)
		{
		  vxlan_rx_trace_t *tr =
		    vlib_add_trace (vm, node, b2, sizeof *tr);
		  u8 error2 = vxlan_err_code (ip_err2, udp_err2, csum_err2);
		  tr->next_index = next2;
		  tr->error = error2;
		  tr->tunnel_index = t_index2;
		  tr->vni = t2->vni;
		}
	      if (b3->flags & VLIB_BUFFER_IS_TRACED)
		{
		  vxlan_rx_trace_t *tr =
		    vlib_add_trace (vm, node, b3, sizeof *tr);
		  u8 error3 = vxlan_err_code (ip_err3, udp_err3, csum_err3);
		  tr->next_index = next3;
		  tr->error = error3;
		  tr->tunnel_index = t_index3;
		  tr->vni = t3->vni;
		}
	    }
	  vlib_validate_buffer_enqueue_x4
	    (vm, node, next_index, to_next, n_left_to_next,
	     bi0, bi1, bi2, bi3, next0, next1, next2, next3);
	}
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = to_next[0] = from[0];
	  from++;
	  n_left_from--;
	  to_next++;
	  n_left_to_next--;

	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  vlib_buffer_advance (b0, payload_offset);

	  u16 len0 = vlib_buffer_length_in_chain (vm, b0);
	  u32 next0 = VXLAN_FLOW_NEXT_L2_INPUT;

	  u8 ip_err0 = vxlan_check_ip (b0, len0);
	  u8 udp_err0 = vxlan_check_ip_udp_len (b0);
	  u8 csum_err0 = vxlan_check_udp_csum (vm, b0);

	  if (csum_err0)
	    csum_err0 = !vxlan_validate_udp_csum (vm, b0);
	  if (ip_err0 || udp_err0 || csum_err0)
	    {
	      next0 = VXLAN_FLOW_NEXT_DROP;
	      u8 error0 = vxlan_err_code (ip_err0, udp_err0, csum_err0);
	      b0->error = node->errors[error0];
	    }

	  vnet_update_l2_len (b0);

	  ASSERT (b0->flow_id != 0);
	  u32 t_index0 = b0->flow_id - vxm->flow_id_start;
	  vxlan_tunnel_t *t0 = &vxm->tunnels[t_index0];
	  b0->flow_id = 0;

	  u32 sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	    t0->sw_if_index;
	  vlib_increment_combined_counter (rx_counter[next0], thread_index,
					   sw_if_index0, 1, len0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_rx_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof *tr);
	      u8 error0 = vxlan_err_code (ip_err0, udp_err0, csum_err0);
	      tr->next_index = next0;
	      tr->error = error0;
	      tr->tunnel_index = t_index0;
	      tr->vni = t0->vni;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return f->n_vectors;
}

/* *INDENT-OFF* */
#ifndef CLIB_MULTIARCH_VARIANT
VLIB_REGISTER_NODE (vxlan4_flow_input_node) = {
  .name = "vxlan-flow-input",
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),

  .format_trace = format_vxlan_rx_trace,

  .n_errors = VXLAN_FLOW_N_ERROR,
  .error_strings = vxlan_flow_error_strings,

  .n_next_nodes = VXLAN_FLOW_N_NEXT,
  .next_nodes = {
#define _(s,n) [VXLAN_FLOW_NEXT_##s] = n,
    foreach_vxlan_flow_input_next
#undef _
  },
};
#endif
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
