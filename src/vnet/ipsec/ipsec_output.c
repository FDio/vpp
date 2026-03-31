/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

/* ipsec_output.c : IPSec output node */

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_io.h>
#include <vnet/ipsec/ipsec_output.h>

#define foreach_ipsec_output_error                   \
 _(RX_PKTS, "IPSec pkts received")                   \
 _(POLICY_DISCARD, "IPSec policy discard")           \
 _(POLICY_NO_MATCH, "IPSec policy (no match)")       \
 _(POLICY_PROTECT, "IPSec policy protect")           \
 _(POLICY_BYPASS, "IPSec policy bypass")             \
 _(ENCAPS_FAILED, "IPSec encapsulation failed")

typedef enum
{
#define _(sym,str) IPSEC_OUTPUT_ERROR_##sym,
  foreach_ipsec_output_error
#undef _
    IPSEC_DECAP_N_ERROR,
} ipsec_output_error_t;

static char *ipsec_output_error_strings[] = {
#define _(sym,string) string,
  foreach_ipsec_output_error
#undef _
};

static_always_inline void
ipsec_output_fix_offloads (vlib_main_t *vm, vlib_buffer_t **b, void *l3hdr, void *l4hdr,
			   int is_ipv6)
{
  int bogus;
  udp_header_t *udp0 = l4hdr;
  tcp_header_t *tcp0 = l4hdr;
  vnet_buffer_oflags_t oflags;

  if (PREDICT_TRUE ((b[0]->flags & VNET_BUFFER_F_OFFLOAD) == 0))
    return;

  oflags = vnet_buffer (b[0])->oflags;

  vnet_buffer_offload_flags_clear (b[0], oflags);

  if (is_ipv6)
    {
      ip6_header_t *ip0 = l3hdr;
      if (PREDICT_FALSE (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM))
	tcp0->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b[0], ip0, &bogus);
      if (PREDICT_FALSE (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
	udp0->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b[0], ip0, &bogus);
    }
  else
    {
      ip4_header_t *ip0 = l3hdr;
      if (PREDICT_FALSE (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM))
	ip0->checksum = ip4_header_checksum (ip0);
      if (PREDICT_FALSE (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM))
	tcp0->checksum = ip4_tcp_udp_compute_checksum (vm, b[0], ip0);
      if (PREDICT_FALSE (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
	udp0->checksum = ip4_tcp_udp_compute_checksum (vm, b[0], ip0);
    }
}

static inline uword
ipsec_output_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * from_frame, int is_ipv6)
{
  ipsec_main_t *im = &ipsec_main;
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 4], **b = buffers;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  u32 *buffer_indices, thread_index;
  u32 n_pkts, sw_if_index0, last_sw_if_index = (u32) ~0;
  u32 spd_index0 = ~0;
  ipsec_spd_t *spd0 = 0;
  ipsec4_flow_cache_bucket_t *flow_cache_tbl = im->ipsec4_out_spd_hash_tbl;
  u64 nc_protect = 0, nc_bypass = 0, nc_discard = 0, nc_nomatch = 0;
  u64 flow_cache_mask = im->output_flow_cache_flag ? im->ipsec4_out_spd_hash_num_buckets - 1 : 0;

  buffer_indices = vlib_frame_vector_args (from_frame);
  n_pkts = from_frame->n_vectors;
  thread_index = vm->thread_index;

  vlib_get_buffers (vm, buffer_indices, buffers, n_pkts);
  b[n_pkts] = b[n_pkts + 1] = b[n_pkts + 2] = b[n_pkts + 3] = b[n_pkts - 1];

  for (u32 n_left = n_pkts; n_left > 0; b += 1, next += 1, n_left -= 1)
    {
      u32 pi0;
      ipsec_policy_t *p0 = NULL;
      void *l3hdr;
      void *l4hdr;
      u32 iph_offset = 0;
      u64 bytes0;

      CLIB_PREFETCH (b[4], CLIB_CACHE_LINE_BYTES * 2, STORE);
      vlib_prefetch_buffer_data (b[4], LOAD);

      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
      iph_offset = vnet_buffer (b[0])->ip.save_rewrite_length;
      l3hdr = (u8 *) vlib_buffer_get_current (b[0]) + iph_offset;

      /* lookup for SPD only if sw_if_index is changed */
      if (PREDICT_FALSE (last_sw_if_index != sw_if_index0))
	{
	  ASSERT (sw_if_index0 < vec_len (im->spd_index_by_sw_if_index));
	  spd_index0 = im->spd_index_by_sw_if_index[sw_if_index0];
	  ASSERT (spd_index0 != INDEX_INVALID);
	  spd0 = pool_elt_at_index (im->spds, spd_index0);
	  last_sw_if_index = sw_if_index0;
	}

      if (is_ipv6)
	{
	  ip6_header_t *ip0 = l3hdr;
	  udp_header_t *udp0 = l4hdr = ip6_next_header (ip0);
	  bytes0 = clib_net_to_host_u16 (ip0->payload_length) + sizeof (ip6_header_t);
	  p0 = ipsec6_output_policy_match (spd0, &ip0->src_address, &ip0->dst_address,
					   udp0->src_port, udp0->dst_port, ip0->protocol);
	}
      else
	{
	  ip4_header_t *ip0 = l3hdr;
	  udp_header_t *udp0 = l4hdr = (u8 *) ip0 + ip4_header_bytes (ip0);
	  u32 sa = ip0->src_address.as_u32;
	  u32 da = ip0->dst_address.as_u32;
	  u16 sp = udp0->src_port;
	  u16 dp = udp0->dst_port;
	  bytes0 = clib_net_to_host_u16 (ip0->length);
	  /*
	   * Check whether flow cache is enabled.
	   */
	  if (flow_cache_mask)
	    p0 = ipsec4_out_spd_find_flow_cache_entry (flow_cache_tbl, im, ip0->protocol, sa, da,
						       sp, dp, flow_cache_mask);

	  /* Fall back to linear search if flow cache lookup fails */
	  if (p0 == NULL)
	    p0 = ipsec_output_policy_match (spd0, ip0->protocol, sa, da, sp, dp, flow_cache_mask);
	}

      if (PREDICT_TRUE (p0 != NULL))
	{
	  pi0 = p0 - im->policies;

	  vlib_prefetch_combined_counter (&ipsec_spd_policy_counters, thread_index, pi0);

	  if (p0->policy == IPSEC_POLICY_ACTION_PROTECT)
	    {
	      ipsec_sa_outb_rt_t *ort = ipsec_sa_get_outb_rt_by_index (p0->sa_index);
	      nc_protect++;
	      next[0] = is_ipv6 ? ort->ipsec6_output_next_index : ort->ipsec4_output_next_index;
	      vnet_buffer (b[0])->ipsec.sad_index = p0->sa_index;
	      ipsec_output_fix_offloads (vm, b, l3hdr, l4hdr, is_ipv6);
	      vlib_buffer_advance (b[0], iph_offset);
	    }
	  else if (p0->policy == IPSEC_POLICY_ACTION_BYPASS)
	    {
	      nc_bypass++;
	      vnet_feature_next_u16 (next, b[0]);
	    }
	  else
	    {
	      nc_discard++;
	      next[0] = IPSEC_OUTPUT_NEXT_DROP;
	    }
	  vlib_increment_combined_counter (&ipsec_spd_policy_counters, thread_index, pi0, 1,
					   bytes0);
	}
      else
	{
	  pi0 = ~0;
	  nc_nomatch++;
	  next[0] = IPSEC_OUTPUT_NEXT_DROP;
	}

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	  PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ipsec_output_trace_t *tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  if (spd0)
	    tr->spd_id = spd0->id;
	  tr->policy_id = pi0;
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, buffer_indices, nexts, from_frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index,
			       IPSEC_OUTPUT_ERROR_POLICY_PROTECT, nc_protect);
  vlib_node_increment_counter (vm, node->node_index,
			       IPSEC_OUTPUT_ERROR_POLICY_BYPASS, nc_bypass);
  vlib_node_increment_counter (vm, node->node_index,
			       IPSEC_OUTPUT_ERROR_POLICY_DISCARD, nc_discard);
  vlib_node_increment_counter (vm, node->node_index,
			       IPSEC_OUTPUT_ERROR_POLICY_NO_MATCH,
			       nc_nomatch);
  return from_frame->n_vectors;
}

VLIB_NODE_FN (ipsec4_output_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return ipsec_output_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (ipsec4_output_node) = {
  .name = "ipsec4-output-feature",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ipsec_output_error_strings),
  .error_strings = ipsec_output_error_strings,

  .n_next_nodes = IPSEC_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [IPSEC_OUTPUT_NEXT_##s] = n,
    foreach_ipsec_output_next
#undef _
  },
};

VLIB_NODE_FN (ipsec6_output_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return ipsec_output_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (ipsec6_output_node) = {
  .name = "ipsec6-output-feature",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ipsec_output_error_strings),
  .error_strings = ipsec_output_error_strings,

  .n_next_nodes = IPSEC_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [IPSEC_OUTPUT_NEXT_##s] = n,
    foreach_ipsec_output_next
#undef _
  },
};
