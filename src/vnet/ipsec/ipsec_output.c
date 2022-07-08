/*
 * ipsec_output.c : IPSec output node
 *
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

typedef struct
{
  u32 spd_id;
  u32 policy_id;
} ipsec_output_trace_t;

/* packet trace format function */
static u8 *
format_ipsec_output_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_output_trace_t *t = va_arg (*args, ipsec_output_trace_t *);

  s = format (s, "spd %u policy %d", t->spd_id, t->policy_id);

  return s;
}

static inline uword
ipsec_output_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * from_frame, int is_ipv6)
{
  ipsec_main_t *im = &ipsec_main;

  u32 *from, *to_next = 0, thread_index;
  u32 n_left_from, sw_if_index0, last_sw_if_index = (u32) ~ 0;
  u32 next_node_index = (u32) ~ 0, last_next_node_index = (u32) ~ 0;
  vlib_frame_t *f = 0;
  u32 spd_index0 = ~0;
  ipsec_spd_t *spd0 = 0;
  int bogus;
  u64 nc_protect = 0, nc_bypass = 0, nc_discard = 0, nc_nomatch = 0;
  u8 flow_cache_enabled = im->output_flow_cache_flag;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      u32 bi0, pi0, bi1;
      vlib_buffer_t *b0, *b1;
      ipsec_policy_t *p0 = NULL;
      ip4_header_t *ip0;
      ip6_header_t *ip6_0 = 0;
      udp_header_t *udp0;
      u32 iph_offset = 0;
      tcp_header_t *tcp0;
      u64 bytes0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      if (n_left_from > 1)
	{
	  bi1 = from[1];
	  b1 = vlib_get_buffer (vm, bi1);
	  CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES * 2, STORE);
	  vlib_prefetch_buffer_data (b1, LOAD);
	}
      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
      iph_offset = vnet_buffer (b0)->ip.save_rewrite_length;
      ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0)
			      + iph_offset);

      /* lookup for SPD only if sw_if_index is changed */
      if (PREDICT_FALSE (last_sw_if_index != sw_if_index0))
	{
	  uword *p = hash_get (im->spd_index_by_sw_if_index, sw_if_index0);
	  ALWAYS_ASSERT (p);
	  spd_index0 = p[0];
	  spd0 = pool_elt_at_index (im->spds, spd_index0);
	  last_sw_if_index = sw_if_index0;
	}

      if (is_ipv6)
	{
	  ip6_0 = (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b0)
				    + iph_offset);

	  udp0 = ip6_next_header (ip6_0);
#if 0
	  clib_warning
	    ("packet received from %U port %u to %U port %u spd_id %u",
	     format_ip6_address, &ip6_0->src_address,
	     clib_net_to_host_u16 (udp0->src_port), format_ip6_address,
	     &ip6_0->dst_address, clib_net_to_host_u16 (udp0->dst_port),
	     spd0->id);
#endif

	  p0 = ipsec6_output_policy_match (spd0,
					   &ip6_0->src_address,
					   &ip6_0->dst_address,
					   clib_net_to_host_u16
					   (udp0->src_port),
					   clib_net_to_host_u16
					   (udp0->dst_port), ip6_0->protocol);
	}
      else
	{
	  udp0 = (udp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));

#if 0
	  clib_warning ("packet received from %U to %U port %u",
			format_ip4_address, ip0->src_address.as_u8,
			format_ip4_address, ip0->dst_address.as_u8,
			clib_net_to_host_u16 (udp0->dst_port));
	  clib_warning ("sw_if_index0 %u spd_index0 %u spd_id %u",
			sw_if_index0, spd_index0, spd0->id);
#endif

	  /*
	   * Check whether flow cache is enabled.
	   */
	  if (flow_cache_enabled)
	    {
	      p0 = ipsec4_out_spd_find_flow_cache_entry (
		im, ip0->protocol, ip0->src_address.as_u32,
		ip0->dst_address.as_u32, udp0->src_port, udp0->dst_port);
	    }

	  /* Fall back to linear search if flow cache lookup fails */
	  if (p0 == NULL)
	    {
	      p0 = ipsec_output_policy_match (
		spd0, ip0->protocol,
		clib_net_to_host_u32 (ip0->src_address.as_u32),
		clib_net_to_host_u32 (ip0->dst_address.as_u32),
		clib_net_to_host_u16 (udp0->src_port),
		clib_net_to_host_u16 (udp0->dst_port), flow_cache_enabled);
	    }
	}
      tcp0 = (void *) udp0;

      if (PREDICT_TRUE (p0 != NULL))
	{
	  pi0 = p0 - im->policies;

	  vlib_prefetch_combined_counter (&ipsec_spd_policy_counters,
					  thread_index, pi0);

	  if (is_ipv6)
	    {
	      bytes0 = clib_net_to_host_u16 (ip6_0->payload_length);
	      bytes0 += sizeof (ip6_header_t);
	    }
	  else
	    {
	      bytes0 = clib_net_to_host_u16 (ip0->length);
	    }

	  if (p0->policy == IPSEC_POLICY_ACTION_PROTECT)
	    {
	      ipsec_sa_t *sa = 0;
	      nc_protect++;
	      sa = ipsec_sa_get (p0->sa_index);
	      if (sa->protocol == IPSEC_PROTOCOL_ESP)
		if (is_ipv6)
		  next_node_index = im->esp6_encrypt_node_index;
		else
		  next_node_index = im->esp4_encrypt_node_index;
	      else if (is_ipv6)
		next_node_index = im->ah6_encrypt_node_index;
	      else
		next_node_index = im->ah4_encrypt_node_index;
	      vnet_buffer (b0)->ipsec.sad_index = p0->sa_index;

	      if (PREDICT_FALSE (b0->flags & VNET_BUFFER_F_OFFLOAD))
		{
		  vnet_buffer_oflags_t oflags = vnet_buffer (b0)->oflags;

		  /*
		   * Clearing offload flags before checksum is computed
		   * It guarantees the cache hit!
		   */
		  vnet_buffer_offload_flags_clear (b0, oflags);

		  if (is_ipv6)
		    {
		      if (PREDICT_FALSE (oflags &
					 VNET_BUFFER_OFFLOAD_F_TCP_CKSUM))
			{
			  tcp0->checksum = ip6_tcp_udp_icmp_compute_checksum (
			    vm, b0, ip6_0, &bogus);
			}
		      if (PREDICT_FALSE (oflags &
					 VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
			{
			  udp0->checksum = ip6_tcp_udp_icmp_compute_checksum (
			    vm, b0, ip6_0, &bogus);
			}
		    }
		  else
		    {
		      if (PREDICT_FALSE (oflags &
					 VNET_BUFFER_OFFLOAD_F_IP_CKSUM))
			{
			  ip0->checksum = ip4_header_checksum (ip0);
			}
		      if (PREDICT_FALSE (oflags &
					 VNET_BUFFER_OFFLOAD_F_TCP_CKSUM))
			{
			  tcp0->checksum =
			    ip4_tcp_udp_compute_checksum (vm, b0, ip0);
			}
		      if (PREDICT_FALSE (oflags &
					 VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
			{
			  udp0->checksum =
			    ip4_tcp_udp_compute_checksum (vm, b0, ip0);
			}
		    }
		}
	      vlib_buffer_advance (b0, iph_offset);
	    }
	  else if (p0->policy == IPSEC_POLICY_ACTION_BYPASS)
	    {
	      nc_bypass++;
	      next_node_index = get_next_output_feature_node_index (b0, node);
	    }
	  else
	    {
	      nc_discard++;
	      next_node_index = im->error_drop_node_index;
	    }
	  vlib_increment_combined_counter
	    (&ipsec_spd_policy_counters, thread_index, pi0, 1, bytes0);
	}
      else
	{
	  pi0 = ~0;
	  nc_nomatch++;
	  next_node_index = im->error_drop_node_index;
	}

      from += 1;
      n_left_from -= 1;

      if (PREDICT_FALSE ((last_next_node_index != next_node_index) || f == 0))
	{
	  /* if this is not 1st frame */
	  if (f)
	    vlib_put_frame_to_node (vm, last_next_node_index, f);

	  last_next_node_index = next_node_index;

	  f = vlib_get_frame_to_node (vm, next_node_index);

	  /* frame->frame_flags, copy it from node */
	  /* Copy trace flag from next_frame and from runtime. */
	  f->frame_flags |= node->flags & VLIB_NODE_FLAG_TRACE;

	  to_next = vlib_frame_vector_args (f);
	}

      to_next[0] = bi0;
      to_next += 1;
      f->n_vectors++;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	  PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ipsec_output_trace_t *tr =
	    vlib_add_trace (vm, node, b0, sizeof (*tr));
	  if (spd0)
	    tr->spd_id = spd0->id;
	  tr->policy_id = pi0;
	}
    }

  vlib_put_frame_to_node (vm, next_node_index, f);
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

/* *INDENT-OFF* */
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
/* *INDENT-ON* */

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

