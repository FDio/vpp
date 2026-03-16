
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface_output.h>
#include <vxlan/vxlan.h>
#include <vnet/qos/qos_types.h>
#include <vnet/adj/rewrite.h>

/* Statistics (not all errors) */
#define foreach_vxlan_encap_error    \
_(ENCAPSULATED, "good packets encapsulated")

static char *vxlan_encap_error_strings[] = {
#define _(sym,string) string,
  foreach_vxlan_encap_error
#undef _
};

typedef enum
{
#define _(sym,str) VXLAN_ENCAP_ERROR_##sym,
  foreach_vxlan_encap_error
#undef _
    VXLAN_ENCAP_N_ERROR,
} vxlan_encap_error_t;

#define foreach_vxlan_p2mp_encap_error                                                             \
  _ (UNICAST, "unicast packets (MAC hit)")                                                         \
  _ (BUM, "BUM packets flooded to all endpoints")                                                  \
  _ (STALE, "packets dropped: stale MAC entry")                                                    \
  _ (NO_ENDPOINTS, "packets dropped: no endpoints")

static char *vxlan_p2mp_encap_error_strings[] = {
#define _(sym, string) string,
  foreach_vxlan_p2mp_encap_error
#undef _
};

typedef enum
{
#define _(sym, str) VXLAN_P2MP_ENCAP_ERROR_##sym,
  foreach_vxlan_p2mp_encap_error
#undef _
    VXLAN_P2MP_ENCAP_N_ERROR,
} vxlan_p2mp_encap_error_t;

typedef enum
{
  VXLAN_ENCAP_NEXT_DROP,
  VXLAN_ENCAP_N_NEXT,
} vxlan_encap_next_t;

typedef struct
{
  u32 tunnel_index;
  u32 vni;
} vxlan_encap_trace_t;

#ifndef CLIB_MARCH_VARIANT
u8 *
format_vxlan_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vxlan_encap_trace_t *t = va_arg (*args, vxlan_encap_trace_t *);

  s = format (s, "VXLAN encap to vxlan_tunnel%d vni %d",
	      t->tunnel_index, t->vni);
  return s;
}
#endif

always_inline uword
vxlan_encap_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *from_frame, u8 is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  vxlan_main_t *vxm = &vxlan_main;
  vnet_main_t *vnm = vxm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_combined_counter_main_t *tx_counter =
    im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX;
  u32 pkts_encapsulated = 0;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  u32 sw_if_index0 = 0, sw_if_index1 = 0;
  u32 next0 = 0, next1 = 0;
  vxlan_tunnel_t *t0 = NULL, *t1 = NULL;
  vxlan_endpoint_t *ep0 = NULL, *ep1 = NULL;
  index_t dpoi_idx0 = INDEX_INVALID, dpoi_idx1 = INDEX_INVALID;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  STATIC_ASSERT_SIZEOF (ip6_vxlan_header_t, 56);
  STATIC_ASSERT_SIZEOF (ip4_vxlan_header_t, 36);

  u8 const underlay_hdr_len = is_ip4 ?
    sizeof (ip4_vxlan_header_t) : sizeof (ip6_vxlan_header_t);
  u16 const l3_len = is_ip4 ? sizeof (ip4_header_t) : sizeof (ip6_header_t);
  u32 const outer_packet_csum_offload_flags =
    is_ip4 ? (VNET_BUFFER_OFFLOAD_F_OUTER_IP_CKSUM |
	      VNET_BUFFER_OFFLOAD_F_TNL_VXLAN) :
	     (VNET_BUFFER_OFFLOAD_F_OUTER_UDP_CKSUM |
	      VNET_BUFFER_OFFLOAD_F_TNL_VXLAN);

  vlib_get_buffers (vm, from, bufs, n_left_from);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  /* Prefetch next iteration. */
	  {
	    vlib_prefetch_buffer_header (b[2], LOAD);
	    vlib_prefetch_buffer_header (b[3], LOAD);

	    CLIB_PREFETCH (b[2]->data - CLIB_CACHE_LINE_BYTES,
			   2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (b[3]->data - CLIB_CACHE_LINE_BYTES,
			   2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  u32 bi0 = to_next[0] = from[0];
	  u32 bi1 = to_next[1] = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  vlib_buffer_t *b0 = b[0];
	  vlib_buffer_t *b1 = b[1];
	  b += 2;

	  u32 flow_hash0 = vnet_l2_compute_flow_hash (b0);
	  u32 flow_hash1 = vnet_l2_compute_flow_hash (b1);

	  /* Get next node index and adj index from tunnel next_dpo */
	  if (sw_if_index0 != vnet_buffer (b0)->sw_if_index[VLIB_TX])
	    {
	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      vnet_hw_interface_t *hi0 =
		vnet_get_sup_hw_interface (vnm, sw_if_index0);
	      t0 = &vxm->tunnels[hi0->dev_instance];
	      ep0 = pool_elt_at_index (vxm->endpoint_pool, t0->endpoint_indices[0]);
	      next0 = ep0->next_dpo.dpoi_next_node;
	      dpoi_idx0 = ep0->next_dpo.dpoi_index;
	    }

	  /* Get next node index and adj index from tunnel next_dpo */
	  if (sw_if_index1 != vnet_buffer (b1)->sw_if_index[VLIB_TX])
	    {
	      if (sw_if_index0 == vnet_buffer (b1)->sw_if_index[VLIB_TX])
		{
		  sw_if_index1 = sw_if_index0;
		  t1 = t0;
		  ep1 = ep0;
		  next1 = next0;
		  dpoi_idx1 = dpoi_idx0;
		}
	      else
		{
		  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];
		  vnet_hw_interface_t *hi1 =
		    vnet_get_sup_hw_interface (vnm, sw_if_index1);
		  t1 = &vxm->tunnels[hi1->dev_instance];
		  ep1 = pool_elt_at_index (vxm->endpoint_pool, t1->endpoint_indices[0]);
		  next1 = ep1->next_dpo.dpoi_next_node;
		  dpoi_idx1 = ep1->next_dpo.dpoi_index;
		}
	    }

	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = dpoi_idx0;
	  vnet_buffer (b1)->ip.adj_index[VLIB_TX] = dpoi_idx1;

	  ASSERT (ep0->rewrite_header.data_bytes == underlay_hdr_len);
	  ASSERT (ep1->rewrite_header.data_bytes == underlay_hdr_len);
	  vnet_rewrite_two_headers (*ep0, *ep1, vlib_buffer_get_current (b0),
				    vlib_buffer_get_current (b1), underlay_hdr_len);

	  vlib_buffer_advance (b0, -underlay_hdr_len);
	  vlib_buffer_advance (b1, -underlay_hdr_len);

	  u32 len0 = vlib_buffer_length_in_chain (vm, b0);
	  u32 len1 = vlib_buffer_length_in_chain (vm, b1);
	  u16 payload_l0 = clib_host_to_net_u16 (len0 - l3_len);
	  u16 payload_l1 = clib_host_to_net_u16 (len1 - l3_len);

	  void *underlay0 = vlib_buffer_get_current (b0);
	  void *underlay1 = vlib_buffer_get_current (b1);

	  ip4_header_t *ip4_0, *ip4_1;
	  qos_bits_t ip4_0_tos = 0, ip4_1_tos = 0;
	  ip6_header_t *ip6_0, *ip6_1;
	  udp_header_t *udp0, *udp1;
	  u8 *l3_0, *l3_1;
	  if (is_ip4)
	    {
	      ip4_vxlan_header_t *hdr0 = underlay0;
	      ip4_vxlan_header_t *hdr1 = underlay1;

	      /* Fix the IP4 checksum and length */
	      ip4_0 = &hdr0->ip4;
	      ip4_1 = &hdr1->ip4;
	      ip4_0->length = clib_host_to_net_u16 (len0);
	      ip4_1->length = clib_host_to_net_u16 (len1);

	      if (PREDICT_FALSE (b0->flags & VNET_BUFFER_F_QOS_DATA_VALID))
		{
		  ip4_0_tos = vnet_buffer2 (b0)->qos.bits;
		  ip4_0->tos = ip4_0_tos;
		}
	      if (PREDICT_FALSE (b1->flags & VNET_BUFFER_F_QOS_DATA_VALID))
		{
		  ip4_1_tos = vnet_buffer2 (b1)->qos.bits;
		  ip4_1->tos = ip4_1_tos;
		}

	      l3_0 = (u8 *) ip4_0;
	      l3_1 = (u8 *) ip4_1;
	      udp0 = &hdr0->udp;
	      udp1 = &hdr1->udp;
	    }
	  else			/* ipv6 */
	    {
	      ip6_vxlan_header_t *hdr0 = underlay0;
	      ip6_vxlan_header_t *hdr1 = underlay1;

	      /* Fix IP6 payload length */
	      ip6_0 = &hdr0->ip6;
	      ip6_1 = &hdr1->ip6;
	      ip6_0->payload_length = payload_l0;
	      ip6_1->payload_length = payload_l1;

	      l3_0 = (u8 *) ip6_0;
	      l3_1 = (u8 *) ip6_1;
	      udp0 = &hdr0->udp;
	      udp1 = &hdr1->udp;
	    }

	  /* Fix UDP length  and set source port */
	  udp0->length = payload_l0;
	  udp0->src_port = flow_hash0;
	  udp1->length = payload_l1;
	  udp1->src_port = flow_hash1;

	  if (b0->flags & VNET_BUFFER_F_OFFLOAD)
	    {
	      vnet_buffer2 (b0)->outer_l3_hdr_offset = l3_0 - b0->data;
	      vnet_buffer2 (b0)->outer_l4_hdr_offset = (u8 *) udp0 - b0->data;
	      vnet_buffer_offload_flags_set (b0,
					     outer_packet_csum_offload_flags);
	    }
	  /* IPv4 checksum only */
	  else if (is_ip4)
	    {
	      ip_csum_t sum0 = ip4_0->checksum;
	      sum0 = ip_csum_update (sum0, 0, ip4_0->length, ip4_header_t,
				     length /* changed member */);
	      if (PREDICT_FALSE (ip4_0_tos))
		{
		  sum0 = ip_csum_update (sum0, 0, ip4_0_tos, ip4_header_t,
					 tos /* changed member */);
		}
	      ip4_0->checksum = ip_csum_fold (sum0);
	    }
	  /* IPv6 UDP checksum is mandatory */
	  else
	    {
	      int bogus = 0;

	      udp0->checksum =
		ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip6_0, &bogus);
	      ASSERT (bogus == 0);
	      if (udp0->checksum == 0)
		udp0->checksum = 0xffff;
	    }

	  if (b1->flags & VNET_BUFFER_F_OFFLOAD)
	    {
	      vnet_buffer2 (b1)->outer_l3_hdr_offset = l3_1 - b1->data;
	      vnet_buffer2 (b1)->outer_l4_hdr_offset = (u8 *) udp1 - b1->data;
	      vnet_buffer_offload_flags_set (b1,
					     outer_packet_csum_offload_flags);
	    }
	  /* IPv4 checksum only */
	  else if (is_ip4)
	    {
	      ip_csum_t sum1 = ip4_1->checksum;
	      sum1 = ip_csum_update (sum1, 0, ip4_1->length, ip4_header_t,
				     length /* changed member */);
	      if (PREDICT_FALSE (ip4_1_tos))
		{
		  sum1 = ip_csum_update (sum1, 0, ip4_1_tos, ip4_header_t,
					 tos /* changed member */);
		}
	      ip4_1->checksum = ip_csum_fold (sum1);
	    }
	  /* IPv6 UDP checksum is mandatory */
	  else
	    {
	      int bogus = 0;

	      udp1->checksum = ip6_tcp_udp_icmp_compute_checksum
		(vm, b1, ip6_1, &bogus);
	      ASSERT (bogus == 0);
	      if (udp1->checksum == 0)
		udp1->checksum = 0xffff;
	    }

	  /* save inner packet flow_hash for load-balance node */
	  vnet_buffer (b0)->ip.flow_hash = flow_hash0;
	  vnet_buffer (b1)->ip.flow_hash = flow_hash1;

	  if (sw_if_index0 == sw_if_index1)
	    {
	      vlib_increment_combined_counter (tx_counter, thread_index,
					       sw_if_index0, 2, len0 + len1);
	    }
	  else
	    {
	      vlib_increment_combined_counter (tx_counter, thread_index,
					       sw_if_index0, 1, len0);
	      vlib_increment_combined_counter (tx_counter, thread_index,
					       sw_if_index1, 1, len1);
	    }
	  pkts_encapsulated += 2;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_encap_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->tunnel_index = t0 - vxm->tunnels;
	      tr->vni = t0->vni;
	    }

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_encap_trace_t *tr =
		vlib_add_trace (vm, node, b1, sizeof (*tr));
	      tr->tunnel_index = t1 - vxm->tunnels;
	      tr->vni = t1->vni;
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

	  vlib_buffer_t *b0 = b[0];
	  b += 1;

	  u32 flow_hash0 = vnet_l2_compute_flow_hash (b0);

	  /* Get next node index and adj index from tunnel next_dpo */
	  if (sw_if_index0 != vnet_buffer (b0)->sw_if_index[VLIB_TX])
	    {
	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      vnet_hw_interface_t *hi0 =
		vnet_get_sup_hw_interface (vnm, sw_if_index0);
	      t0 = &vxm->tunnels[hi0->dev_instance];
	      ep0 = pool_elt_at_index (vxm->endpoint_pool, t0->endpoint_indices[0]);
	      next0 = ep0->next_dpo.dpoi_next_node;
	      dpoi_idx0 = ep0->next_dpo.dpoi_index;
	    }
	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = dpoi_idx0;

	  ASSERT (ep0->rewrite_header.data_bytes == underlay_hdr_len);
	  vnet_rewrite_one_header (*ep0, vlib_buffer_get_current (b0), underlay_hdr_len);

	  vlib_buffer_advance (b0, -underlay_hdr_len);
	  void *underlay0 = vlib_buffer_get_current (b0);

	  u32 len0 = vlib_buffer_length_in_chain (vm, b0);
	  u16 payload_l0 = clib_host_to_net_u16 (len0 - l3_len);

	  udp_header_t *udp0;
	  ip4_header_t *ip4_0;
	  qos_bits_t ip4_0_tos = 0;
	  ip6_header_t *ip6_0;
	  u8 *l3_0;
	  if (is_ip4)
	    {
	      ip4_vxlan_header_t *hdr = underlay0;

	      /* Fix the IP4 checksum and length */
	      ip4_0 = &hdr->ip4;
	      ip4_0->length = clib_host_to_net_u16 (len0);

	      if (PREDICT_FALSE (b0->flags & VNET_BUFFER_F_QOS_DATA_VALID))
		{
		  ip4_0_tos = vnet_buffer2 (b0)->qos.bits;
		  ip4_0->tos = ip4_0_tos;
		}

	      l3_0 = (u8 *) ip4_0;
	      udp0 = &hdr->udp;
	    }
	  else			/* ip6 path */
	    {
	      ip6_vxlan_header_t *hdr = underlay0;

	      /* Fix IP6 payload length */
	      ip6_0 = &hdr->ip6;
	      ip6_0->payload_length = payload_l0;

	      l3_0 = (u8 *) ip6_0;
	      udp0 = &hdr->udp;
	    }

	  /* Fix UDP length  and set source port */
	  udp0->length = payload_l0;
	  udp0->src_port = flow_hash0;

	  if (b0->flags & VNET_BUFFER_F_OFFLOAD)
	    {
	      vnet_buffer2 (b0)->outer_l3_hdr_offset = l3_0 - b0->data;
	      vnet_buffer2 (b0)->outer_l4_hdr_offset = (u8 *) udp0 - b0->data;
	      vnet_buffer_offload_flags_set (b0,
					     outer_packet_csum_offload_flags);
	    }
	  /* IPv4 checksum only */
	  else if (is_ip4)
	    {
	      ip_csum_t sum0 = ip4_0->checksum;
	      sum0 = ip_csum_update (sum0, 0, ip4_0->length, ip4_header_t,
				     length /* changed member */);
	      if (PREDICT_FALSE (ip4_0_tos))
		{
		  sum0 = ip_csum_update (sum0, 0, ip4_0_tos, ip4_header_t,
					 tos /* changed member */);
		}
	      ip4_0->checksum = ip_csum_fold (sum0);
	    }
	  /* IPv6 UDP checksum is mandatory */
	  else
	    {
	      int bogus = 0;

	      udp0->checksum = ip6_tcp_udp_icmp_compute_checksum
		(vm, b0, ip6_0, &bogus);
	      ASSERT (bogus == 0);
	      if (udp0->checksum == 0)
		udp0->checksum = 0xffff;
	    }

	  /* reuse inner packet flow_hash for load-balance node */
	  vnet_buffer (b0)->ip.flow_hash = flow_hash0;

	  vlib_increment_combined_counter (tx_counter, thread_index,
					   sw_if_index0, 1, len0);
	  pkts_encapsulated++;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_encap_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->tunnel_index = t0 - vxm->tunnels;
	      tr->vni = t0->vni;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Do we still need this now that tunnel tx stats is kept? */
  vlib_node_increment_counter (vm, node->node_index,
			       VXLAN_ENCAP_ERROR_ENCAPSULATED,
			       pkts_encapsulated);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (vxlan4_encap_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  /* Disable chksum offload as setup overhead in tx node is not worthwhile
     for ip4 header checksum only, unless udp checksum is also required */
  return vxlan_encap_inline (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (vxlan6_encap_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  /* Enable checksum offload for ip6 as udp checksum is mandatory, */
  return vxlan_encap_inline (vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (vxlan4_encap_node) = {
  .name = "vxlan4-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_vxlan_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(vxlan_encap_error_strings),
  .error_strings = vxlan_encap_error_strings,
  .n_next_nodes = VXLAN_ENCAP_N_NEXT,
  .next_nodes = {
        [VXLAN_ENCAP_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (vxlan6_encap_node) = {
  .name = "vxlan6-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_vxlan_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(vxlan_encap_error_strings),
  .error_strings = vxlan_encap_error_strings,
  .n_next_nodes = VXLAN_ENCAP_N_NEXT,
  .next_nodes = {
        [VXLAN_ENCAP_NEXT_DROP] = "error-drop",
  },
};

/*
 * P2MP encap node.
 *
 * MAC lookup: for each buffer the destination MAC (bytes 0-5 of the L2
 * header) is looked up in the per-tunnel mac_to_ep bihash.
 *
 *   - MAC found -> known-unicast: encap a single copy toward that endpoint.
 *   - MAC not found -> BUM: replicate to all configured remote VTEPs
 *     (N endpoints -> N-1 buffer copies + original).
 *   - MAC found but endpoint stale (pool_is_free) -> DROP.
 *   - No endpoints configured -> DROP.
 *
 * Static MAC->endpoint mappings are programmed via the
 * vxlan_p2mp_add_del_mac_endpoint API / 'vxlan tunnel mac' CLI.
 */
always_inline uword
vxlan_p2mp_encap_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame,
			 u8 is_ip4)
{
  u32 n_left_from, *from;
  vxlan_main_t *vxm = &vxlan_main;
  vnet_main_t *vnm = vxm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_combined_counter_main_t *tx_counter =
    im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  u32 pkts_unicast = 0, pkts_bum = 0, pkts_stale = 0, pkts_no_ep = 0;

  u8 const underlay_hdr_len = is_ip4 ? sizeof (ip4_vxlan_header_t) : sizeof (ip6_vxlan_header_t);
  u16 const l3_len = is_ip4 ? sizeof (ip4_header_t) : sizeof (ip6_header_t);
  u32 const outer_packet_csum_offload_flags =
    is_ip4 ? (VNET_BUFFER_OFFLOAD_F_OUTER_IP_CKSUM | VNET_BUFFER_OFFLOAD_F_TNL_VXLAN) :
	     (VNET_BUFFER_OFFLOAD_F_OUTER_UDP_CKSUM | VNET_BUFFER_OFFLOAD_F_TNL_VXLAN);

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 next_index = node->cached_next_index;
  u32 *to_next;
  u32 n_left_to_next = 0;

  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

  while (n_left_from > 0)
    {
      u32 bi0 = from[0];
      from++;
      n_left_from--;

      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      u32 sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
      vnet_hw_interface_t *hi0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);
      vxlan_tunnel_t *t0 = &vxm->tunnels[hi0->dev_instance];
      u32 n_eps = vec_len (t0->endpoint_indices);
      u32 flow_hash0 = vnet_l2_compute_flow_hash (b0);

      if (PREDICT_FALSE (n_eps == 0))
	{
	  pkts_no_ep++;
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0,
					   VXLAN_ENCAP_NEXT_DROP);
	  if (PREDICT_FALSE (0 == n_left_to_next))
	    {
	      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
	    }
	  continue;
	}

      /*
       * Unicast vs BUM selection via per-tunnel MAC->ep_pool_index hash.
       *
       * Read the destination MAC from the inner Ethernet frame (at
       * current_data, which l2-output has already adjusted for VTR) and
       * look it up in t0->mac_to_ep.  A hit means known-unicast: send to
       * that single endpoint only, no vlib_buffer_copy.  A miss means BUM:
       * replicate to every endpoint.
       *
       * If the hash returns an ep_pool_index that no longer belongs to this
       * tunnel (stale entry after an endpoint was removed), drop the packet.
       */
      u32 *ep_indices;
      u32 ep_count;
      u32 unicast_ep_arr[1];

      if (t0->mac_to_ep_initialized)
	{
	  ethernet_header_t *eth0 = vlib_buffer_get_current (b0);
	  u64 dmac_key = 0;
	  clib_memcpy (&dmac_key, eth0->dst_address, 6);
	  clib_bihash_kv_8_8_t kv = { .key = dmac_key };
	  if (clib_bihash_search_8_8 (&t0->mac_to_ep, &kv, &kv) == 0)
	    {
	      u32 ep_pool_idx = (u32) kv.value;
	      u32 t_idx = t0 - vxm->tunnels;
	      /* Validate: endpoint must still exist and belong to this tunnel */
	      if (PREDICT_FALSE (
		    pool_is_free_index (vxm->endpoint_pool, ep_pool_idx) ||
		    pool_elt_at_index (vxm->endpoint_pool, ep_pool_idx)->tunnel_index != t_idx))
		{
		  /* Stale MAC entry: drop */
		  pkts_stale++;
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next,
						   bi0, VXLAN_ENCAP_NEXT_DROP);
		  if (PREDICT_FALSE (0 == n_left_to_next))
		    {
		      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
		      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
		    }
		  continue;
		}
	      unicast_ep_arr[0] = ep_pool_idx;
	      ep_indices = unicast_ep_arr;
	      ep_count = 1;
	      pkts_unicast++;
	    }
	  else
	    {
	      ep_indices = t0->endpoint_indices;
	      ep_count = n_eps;
	      pkts_bum++;
	    }
	}
      else
	{
	  ep_indices = t0->endpoint_indices;
	  ep_count = n_eps;
	  pkts_bum++;
	}

      /* Replicate to each selected endpoint.  For unicast ep_count == 1 so
       * vlib_buffer_copy is never called.  For BUM all N endpoints receive a
       * copy; the original buffer is used for the last one. */
      for (u32 ei = 0; ei < ep_count; ei++)
	{
	  vxlan_endpoint_t *ep = pool_elt_at_index (vxm->endpoint_pool, ep_indices[ei]);

	  u32 bic;
	  vlib_buffer_t *bc;

	  if (ei < ep_count - 1)
	    {
	      bc = vlib_buffer_copy (vm, b0);
	      if (PREDICT_FALSE (bc == NULL))
		continue; /* drop this copy on buffer alloc failure */
	      bic = vlib_get_buffer_index (vm, bc);
	    }
	  else
	    {
	      bic = bi0;
	      bc = b0;
	    }

	  /* Encapsulate bc with ep */
	  vnet_buffer (bc)->ip.adj_index[VLIB_TX] = ep->next_dpo.dpoi_index;
	  ASSERT (ep->rewrite_header.data_bytes == underlay_hdr_len);
	  vnet_rewrite_one_header (*ep, vlib_buffer_get_current (bc), underlay_hdr_len);
	  vlib_buffer_advance (bc, -underlay_hdr_len);
	  void *underlay = vlib_buffer_get_current (bc);
	  u32 len = vlib_buffer_length_in_chain (vm, bc);
	  u16 payload_l = clib_host_to_net_u16 (len - l3_len);

	  udp_header_t *udp;
	  ip4_header_t *ip4 = NULL;
	  qos_bits_t ip4_tos = 0;
	  ip6_header_t *ip6 = NULL;
	  u8 *l3;
	  if (is_ip4)
	    {
	      ip4_vxlan_header_t *hdr = underlay;
	      ip4 = &hdr->ip4;
	      ip4->length = clib_host_to_net_u16 (len);
	      if (PREDICT_FALSE (bc->flags & VNET_BUFFER_F_QOS_DATA_VALID))
		{
		  ip4_tos = vnet_buffer2 (bc)->qos.bits;
		  ip4->tos = ip4_tos;
		}
	      l3 = (u8 *) ip4;
	      udp = &hdr->udp;
	    }
	  else
	    {
	      ip6_vxlan_header_t *hdr = underlay;
	      ip6 = &hdr->ip6;
	      ip6->payload_length = payload_l;
	      l3 = (u8 *) ip6;
	      udp = &hdr->udp;
	    }

	  udp->length = payload_l;
	  udp->src_port = flow_hash0;

	  if (bc->flags & VNET_BUFFER_F_OFFLOAD)
	    {
	      vnet_buffer2 (bc)->outer_l3_hdr_offset = l3 - bc->data;
	      vnet_buffer2 (bc)->outer_l4_hdr_offset = (u8 *) udp - bc->data;
	      vnet_buffer_offload_flags_set (bc, outer_packet_csum_offload_flags);
	    }
	  else if (is_ip4)
	    {
	      ip_csum_t sum = ip4->checksum;
	      sum = ip_csum_update (sum, 0, ip4->length, ip4_header_t, length /* changed member */);
	      if (PREDICT_FALSE (ip4_tos))
		sum = ip_csum_update (sum, 0, ip4_tos, ip4_header_t, tos /* changed member */);
	      ip4->checksum = ip_csum_fold (sum);
	    }
	  else
	    {
	      int bogus = 0;
	      udp->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, bc, ip6, &bogus);
	      ASSERT (bogus == 0);
	      if (udp->checksum == 0)
		udp->checksum = 0xffff;
	    }

	  vnet_buffer (bc)->ip.flow_hash = flow_hash0;
	  vlib_increment_combined_counter (tx_counter, thread_index, sw_if_index0, 1, len);

	  if (PREDICT_FALSE (bc->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_encap_trace_t *tr = vlib_add_trace (vm, node, bc, sizeof (*tr));
	      tr->tunnel_index = t0 - vxm->tunnels;
	      tr->vni = t0->vni;
	    }

	  u32 next = ep->next_dpo.dpoi_next_node;
	  to_next[0] = bic;
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bic,
					   next);
	  if (PREDICT_FALSE (0 == n_left_to_next))
	    {
	      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
	    }
	}
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vlib_node_increment_counter (vm, node->node_index, VXLAN_P2MP_ENCAP_ERROR_UNICAST, pkts_unicast);
  vlib_node_increment_counter (vm, node->node_index, VXLAN_P2MP_ENCAP_ERROR_BUM, pkts_bum);
  vlib_node_increment_counter (vm, node->node_index, VXLAN_P2MP_ENCAP_ERROR_STALE, pkts_stale);
  vlib_node_increment_counter (vm, node->node_index, VXLAN_P2MP_ENCAP_ERROR_NO_ENDPOINTS,
			       pkts_no_ep);
  return from_frame->n_vectors;
}

VLIB_NODE_FN (vxlan4_p2mp_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return vxlan_p2mp_encap_inline (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (vxlan6_p2mp_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  return vxlan_p2mp_encap_inline (vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (vxlan4_p2mp_encap_node) = {
  .name = "vxlan4-p2mp-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_vxlan_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (vxlan_p2mp_encap_error_strings),
  .error_strings = vxlan_p2mp_encap_error_strings,
  .n_next_nodes = VXLAN_ENCAP_N_NEXT,
  .next_nodes = {
    [VXLAN_ENCAP_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (vxlan6_p2mp_encap_node) = {
  .name = "vxlan6-p2mp-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_vxlan_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (vxlan_p2mp_encap_error_strings),
  .error_strings = vxlan_p2mp_encap_error_strings,
  .n_next_nodes = VXLAN_ENCAP_N_NEXT,
  .next_nodes = {
    [VXLAN_ENCAP_NEXT_DROP] = "error-drop",
  },
};
