/*
 * Copyright (c) 2017 SUSE LLC.
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
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <geneve/geneve.h>

/* Statistics (not all errors) */
#define foreach_geneve_encap_error    \
_(ENCAPSULATED, "good packets encapsulated")

static char *geneve_encap_error_strings[] = {
#define _(sym,string) string,
  foreach_geneve_encap_error
#undef _
};

typedef enum
{
#define _(sym,str) GENEVE_ENCAP_ERROR_##sym,
  foreach_geneve_encap_error
#undef _
    GENEVE_ENCAP_N_ERROR,
} geneve_encap_error_t;

typedef enum
{
  GENEVE_ENCAP_NEXT_DROP,
  GENEVE_ENCAP_N_NEXT,
} geneve_encap_next_t;

#define foreach_fixed_header4_offset            \
    _(0) _(1) _(2) _(3)

#define foreach_fixed_header6_offset            \
    _(0) _(1) _(2) _(3) _(4) _(5) _(6)

always_inline uword
geneve_encap_inline (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * from_frame, u32 is_ip4)
{
  u32 n_left_from, next_index, *from, *to_next;
  geneve_main_t *vxm = &geneve_main;
  vnet_main_t *vnm = vxm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  u32 pkts_encapsulated = 0;
  u16 old_l0 = 0, old_l1 = 0;
  u32 thread_index = vm->thread_index;
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u32 sw_if_index0 = ~0, sw_if_index1 = ~0;
  u32 next0 = 0, next1 = 0;
  vnet_hw_interface_t *hi0, *hi1;
  geneve_tunnel_t *t0 = NULL, *t1 = NULL;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  u32 flow_hash0, flow_hash1;
	  u32 len0, len1;
	  ip4_header_t *ip4_0, *ip4_1;
	  ip6_header_t *ip6_0, *ip6_1;
	  udp_header_t *udp0, *udp1;
	  u64 *copy_src0, *copy_dst0;
	  u64 *copy_src1, *copy_dst1;
	  u32 *copy_src_last0, *copy_dst_last0;
	  u32 *copy_src_last1, *copy_dst_last1;
	  u16 new_l0, new_l1;
	  ip_csum_t sum0, sum1;

	  /* Prefetch next iteration. */
	  {
	    vlib_prefetch_buffer_header (b[2], LOAD);
	    vlib_prefetch_buffer_header (b[3], LOAD);

	    CLIB_PREFETCH (b[2]->data - CLIB_CACHE_LINE_BYTES,
			   2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (b[3]->data - CLIB_CACHE_LINE_BYTES,
			   2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  flow_hash0 = vnet_l2_compute_flow_hash (b[0]);
	  flow_hash1 = vnet_l2_compute_flow_hash (b[1]);


	  /* Get next node index and adj index from tunnel next_dpo */
	  if (sw_if_index0 != vnet_buffer (b[0])->sw_if_index[VLIB_TX])
	    {
	      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	      hi0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);
	      t0 = &vxm->tunnels[hi0->dev_instance];
	      /* Note: change to always set next0 if it may be set to drop */
	      next0 = t0->next_dpo.dpoi_next_node;
	    }

	  ALWAYS_ASSERT (t0 != NULL);

	  vnet_buffer (b[0])->ip.adj_index = t0->next_dpo.dpoi_index;

	  /* Get next node index and adj index from tunnel next_dpo */
	  if (sw_if_index1 != vnet_buffer (b[1])->sw_if_index[VLIB_TX])
	    {
	      sw_if_index1 = vnet_buffer (b[1])->sw_if_index[VLIB_TX];
	      hi1 = vnet_get_sup_hw_interface (vnm, sw_if_index1);
	      t1 = &vxm->tunnels[hi1->dev_instance];
	      /* Note: change to always set next1 if it may be set to drop */
	      next1 = t1->next_dpo.dpoi_next_node;
	    }

	  ALWAYS_ASSERT (t1 != NULL);

	  vnet_buffer (b[1])->ip.adj_index = t1->next_dpo.dpoi_index;

	  /* Apply the rewrite string. $$$$ vnet_rewrite? */
	  vlib_buffer_advance (b[0], -(word) _vec_len (t0->rewrite));
	  vlib_buffer_advance (b[1], -(word) _vec_len (t1->rewrite));

	  if (is_ip4)
	    {
	      u8 ip4_geneve_base_header_len =
		sizeof (ip4_header_t) + sizeof (udp_header_t) +
		GENEVE_BASE_HEADER_LENGTH;
	      u8 ip4_geneve_header_total_len0 = ip4_geneve_base_header_len;
	      u8 ip4_geneve_header_total_len1 = ip4_geneve_base_header_len;
#if SUPPORT_OPTIONS_HEADER==1
	      ip4_geneve_header_total_len0 += t0->options_len;
	      ip4_geneve_header_total_len1 += t1->options_len;
#endif
	      ASSERT (vec_len (t0->rewrite) == ip4_geneve_header_total_len0);
	      ASSERT (vec_len (t1->rewrite) == ip4_geneve_header_total_len1);

	      ip4_0 = vlib_buffer_get_current (b[0]);
	      ip4_1 = vlib_buffer_get_current (b[1]);

	      /* Copy the fixed header */
	      copy_dst0 = (u64 *) ip4_0;
	      copy_src0 = (u64 *) t0->rewrite;
	      copy_dst1 = (u64 *) ip4_1;
	      copy_src1 = (u64 *) t1->rewrite;
	      /* Copy first 32 octets 8-bytes at a time */
#define _(offs) copy_dst0[offs] = copy_src0[offs];
	      foreach_fixed_header4_offset;
#undef _
#define _(offs) copy_dst1[offs] = copy_src1[offs];
	      foreach_fixed_header4_offset;
#undef _
	      /* Last 4 octets. Hopefully gcc will be our friend */
	      copy_dst_last0 = (u32 *) (&copy_dst0[4]);
	      copy_src_last0 = (u32 *) (&copy_src0[4]);
	      copy_dst_last0[0] = copy_src_last0[0];
	      copy_dst_last1 = (u32 *) (&copy_dst1[4]);
	      copy_src_last1 = (u32 *) (&copy_src1[4]);
	      copy_dst_last1[0] = copy_src_last1[0];

	      /* Fix the IP4 checksum and length */
	      sum0 = ip4_0->checksum;
	      new_l0 =		/* old_l0 always 0, see the rewrite setup */
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b[0]));
	      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
				     length /* changed member */ );
	      ip4_0->checksum = ip_csum_fold (sum0);
	      ip4_0->length = new_l0;
	      sum1 = ip4_1->checksum;
	      new_l1 =		/* old_l1 always 0, see the rewrite setup */
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b[1]));
	      sum1 = ip_csum_update (sum1, old_l1, new_l1, ip4_header_t,
				     length /* changed member */ );
	      ip4_1->checksum = ip_csum_fold (sum1);
	      ip4_1->length = new_l1;

	      /* Fix UDP length and set source port */
	      udp0 = (udp_header_t *) (ip4_0 + 1);
	      new_l0 =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b[0]) -
				      sizeof (*ip4_0));
	      udp0->length = new_l0;
	      udp0->src_port = flow_hash0;
	      udp1 = (udp_header_t *) (ip4_1 + 1);
	      new_l1 =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b[1]) -
				      sizeof (*ip4_1));
	      udp1->length = new_l1;
	      udp1->src_port = flow_hash1;
	    }
	  else			/* ipv6 */
	    {
	      int bogus = 0;

	      u8 ip6_geneve_base_header_len =
		sizeof (ip6_header_t) + sizeof (udp_header_t) +
		GENEVE_BASE_HEADER_LENGTH;
	      u8 ip6_geneve_header_total_len0 = ip6_geneve_base_header_len;
	      u8 ip6_geneve_header_total_len1 = ip6_geneve_base_header_len;
#if SUPPORT_OPTIONS_HEADER==1
	      ip6_geneve_header_total_len0 += t0->options_len;
	      ip6_geneve_header_total_len1 += t1->options_len;
#endif
	      ASSERT (vec_len (t0->rewrite) == ip6_geneve_header_total_len0);
	      ASSERT (vec_len (t1->rewrite) == ip6_geneve_header_total_len1);

	      ip6_0 = vlib_buffer_get_current (b[0]);
	      ip6_1 = vlib_buffer_get_current (b[1]);

	      /* Copy the fixed header */
	      copy_dst0 = (u64 *) ip6_0;
	      copy_src0 = (u64 *) t0->rewrite;
	      copy_dst1 = (u64 *) ip6_1;
	      copy_src1 = (u64 *) t1->rewrite;
	      /* Copy first 56 (ip6) octets 8-bytes at a time */
#define _(offs) copy_dst0[offs] = copy_src0[offs];
	      foreach_fixed_header6_offset;
#undef _
#define _(offs) copy_dst1[offs] = copy_src1[offs];
	      foreach_fixed_header6_offset;
#undef _
	      /* Fix IP6 payload length */
	      new_l0 =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b[0])
				      - sizeof (*ip6_0));
	      ip6_0->payload_length = new_l0;
	      new_l1 =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b[1])
				      - sizeof (*ip6_1));
	      ip6_1->payload_length = new_l1;

	      /* Fix UDP length  and set source port */
	      udp0 = (udp_header_t *) (ip6_0 + 1);
	      udp0->length = new_l0;
	      udp0->src_port = flow_hash0;
	      udp1 = (udp_header_t *) (ip6_1 + 1);
	      udp1->length = new_l1;
	      udp1->src_port = flow_hash1;

	      /* IPv6 UDP checksum is mandatory */
	      udp0->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b[0],
								  ip6_0,
								  &bogus);
	      ASSERT (bogus == 0);
	      if (udp0->checksum == 0)
		udp0->checksum = 0xffff;
	      udp1->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b[1],
								  ip6_1,
								  &bogus);
	      ASSERT (bogus == 0);
	      if (udp1->checksum == 0)
		udp1->checksum = 0xffff;
	    }

	  pkts_encapsulated += 2;
	  len0 = vlib_buffer_length_in_chain (vm, b[0]);
	  len1 = vlib_buffer_length_in_chain (vm, b[1]);
	  stats_n_packets += 2;
	  stats_n_bytes += len0 + len1;

	  /* save inner packet flow_hash for load-balance node */
	  vnet_buffer (b[0])->ip.flow_hash = flow_hash0;
	  vnet_buffer (b[1])->ip.flow_hash = flow_hash1;

	  /* Batch stats increment on the same geneve tunnel so counter is not
	     incremented per packet. Note stats are still incremented for deleted
	     and admin-down tunnel where packets are dropped. It is not worthwhile
	     to check for this rare case and affect normal path performance. */
	  if (PREDICT_FALSE ((sw_if_index0 != stats_sw_if_index) ||
			     (sw_if_index1 != stats_sw_if_index)))
	    {
	      stats_n_packets -= 2;
	      stats_n_bytes -= len0 + len1;
	      if (sw_if_index0 == sw_if_index1)
		{
		  if (stats_n_packets)
		    vlib_increment_combined_counter
		      (im->combined_sw_if_counters +
		       VNET_INTERFACE_COUNTER_TX, thread_index,
		       stats_sw_if_index, stats_n_packets, stats_n_bytes);
		  stats_sw_if_index = sw_if_index0;
		  stats_n_packets = 2;
		  stats_n_bytes = len0 + len1;
		}
	      else
		{
		  vlib_increment_combined_counter
		    (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		     thread_index, sw_if_index0, 1, len0);
		  vlib_increment_combined_counter
		    (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		     thread_index, sw_if_index1, 1, len1);
		}
	    }

	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      geneve_encap_trace_t *tr =
		vlib_add_trace (vm, node, b[0], sizeof (*tr));
	      tr->tunnel_index = t0 - vxm->tunnels;
	      tr->vni = t0->vni;
	    }

	  if (PREDICT_FALSE (b[1]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      geneve_encap_trace_t *tr =
		vlib_add_trace (vm, node, b[1], sizeof (*tr));
	      tr->tunnel_index = t1 - vxm->tunnels;
	      tr->vni = t1->vni;
	    }
	  b += 2;

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  u32 flow_hash0;
	  u32 len0;
	  ip4_header_t *ip4_0;
	  ip6_header_t *ip6_0;
	  udp_header_t *udp0;
	  u64 *copy_src0, *copy_dst0;
	  u32 *copy_src_last0, *copy_dst_last0;
	  u16 new_l0;
	  ip_csum_t sum0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  flow_hash0 = vnet_l2_compute_flow_hash (b[0]);

	  /* Get next node index and adj index from tunnel next_dpo */
	  if (sw_if_index0 != vnet_buffer (b[0])->sw_if_index[VLIB_TX])
	    {
	      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	      hi0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);
	      t0 = &vxm->tunnels[hi0->dev_instance];
	      /* Note: change to always set next0 if it may be set to drop */
	      next0 = t0->next_dpo.dpoi_next_node;
	    }

	  ALWAYS_ASSERT (t0 != NULL);

	  vnet_buffer (b[0])->ip.adj_index = t0->next_dpo.dpoi_index;

	  /* Apply the rewrite string. $$$$ vnet_rewrite? */
	  vlib_buffer_advance (b[0], -(word) _vec_len (t0->rewrite));

	  if (is_ip4)
	    {
	      u8 ip4_geneve_base_header_len =
		sizeof (ip4_header_t) + sizeof (udp_header_t) +
		GENEVE_BASE_HEADER_LENGTH;
	      u8 ip4_geneve_header_total_len0 = ip4_geneve_base_header_len;
#if SUPPORT_OPTIONS_HEADER==1
	      ip4_geneve_header_total_len0 += t0->options_len;
#endif
	      ASSERT (vec_len (t0->rewrite) == ip4_geneve_header_total_len0);

	      ip4_0 = vlib_buffer_get_current (b[0]);

	      /* Copy the fixed header */
	      copy_dst0 = (u64 *) ip4_0;
	      copy_src0 = (u64 *) t0->rewrite;
	      /* Copy first 32 octets 8-bytes at a time */
#define _(offs) copy_dst0[offs] = copy_src0[offs];
	      foreach_fixed_header4_offset;
#undef _
	      /* Last 4 octets. Hopefully gcc will be our friend */
	      copy_dst_last0 = (u32 *) (&copy_dst0[4]);
	      copy_src_last0 = (u32 *) (&copy_src0[4]);
	      copy_dst_last0[0] = copy_src_last0[0];

	      /* Fix the IP4 checksum and length */
	      sum0 = ip4_0->checksum;
	      new_l0 =		/* old_l0 always 0, see the rewrite setup */
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b[0]));
	      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
				     length /* changed member */ );
	      ip4_0->checksum = ip_csum_fold (sum0);
	      ip4_0->length = new_l0;

	      /* Fix UDP length and set source port */
	      udp0 = (udp_header_t *) (ip4_0 + 1);
	      new_l0 =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b[0]) -
				      sizeof (*ip4_0));
	      udp0->length = new_l0;
	      udp0->src_port = flow_hash0;
	    }

	  else			/* ip6 path */
	    {
	      int bogus = 0;

	      u8 ip6_geneve_base_header_len =
		sizeof (ip6_header_t) + sizeof (udp_header_t) +
		GENEVE_BASE_HEADER_LENGTH;
	      u8 ip6_geneve_header_total_len0 = ip6_geneve_base_header_len;
#if SUPPORT_OPTIONS_HEADER==1
	      ip6_geneve_header_total_len0 += t0->options_len;
#endif
	      ASSERT (vec_len (t0->rewrite) == ip6_geneve_header_total_len0);

	      ip6_0 = vlib_buffer_get_current (b[0]);
	      /* Copy the fixed header */
	      copy_dst0 = (u64 *) ip6_0;
	      copy_src0 = (u64 *) t0->rewrite;
	      /* Copy first 56 (ip6) octets 8-bytes at a time */
#define _(offs) copy_dst0[offs] = copy_src0[offs];
	      foreach_fixed_header6_offset;
#undef _
	      /* Fix IP6 payload length */
	      new_l0 =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b[0])
				      - sizeof (*ip6_0));
	      ip6_0->payload_length = new_l0;

	      /* Fix UDP length  and set source port */
	      udp0 = (udp_header_t *) (ip6_0 + 1);
	      udp0->length = new_l0;
	      udp0->src_port = flow_hash0;

	      /* IPv6 UDP checksum is mandatory */
	      udp0->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b[0],
								  ip6_0,
								  &bogus);
	      ASSERT (bogus == 0);
	      if (udp0->checksum == 0)
		udp0->checksum = 0xffff;
	    }

	  pkts_encapsulated++;
	  len0 = vlib_buffer_length_in_chain (vm, b[0]);
	  stats_n_packets += 1;
	  stats_n_bytes += len0;

	  /* save inner packet flow_hash for load-balance node */
	  vnet_buffer (b[0])->ip.flow_hash = flow_hash0;

	  /* Batch stats increment on the same geneve tunnel so counter is not
	     incremented per packet. Note stats are still incremented for deleted
	     and admin-down tunnel where packets are dropped. It is not worthwhile
	     to check for this rare case and affect normal path performance. */
	  if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = sw_if_index0;
	    }

	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      geneve_encap_trace_t *tr =
		vlib_add_trace (vm, node, b[0], sizeof (*tr));
	      tr->tunnel_index = t0 - vxm->tunnels;
	      tr->vni = t0->vni;
	    }
	  b += 1;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Do we still need this now that tunnel tx stats is kept? */
  vlib_node_increment_counter (vm, node->node_index,
			       GENEVE_ENCAP_ERROR_ENCAPSULATED,
			       pkts_encapsulated);

  /* Increment any remaining batch stats */
  if (stats_n_packets)
    {
      vlib_increment_combined_counter
	(im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
	 thread_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
      node->runtime_data[0] = stats_sw_if_index;
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (geneve4_encap_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * from_frame)
{
  return geneve_encap_inline (vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (geneve6_encap_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * from_frame)
{
  return geneve_encap_inline (vm, node, from_frame, /* is_ip4 */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (geneve4_encap_node) = {
  .name = "geneve4-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_geneve_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (geneve_encap_error_strings),
  .error_strings = geneve_encap_error_strings,
  .n_next_nodes = GENEVE_ENCAP_N_NEXT,
  .next_nodes = {
        [GENEVE_ENCAP_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (geneve6_encap_node) = {
  .name = "geneve6-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_geneve_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (geneve_encap_error_strings),
  .error_strings = geneve_encap_error_strings,
  .n_next_nodes = GENEVE_ENCAP_N_NEXT,
  .next_nodes = {
        [GENEVE_ENCAP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
