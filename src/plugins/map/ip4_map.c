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
 * Defines used for testing various optimisation schemes
 */

#include "map.h"
#include <vnet/ip/ip_frag.h>
#include <vnet/ip/ip4_to_ip6.h>

enum ip4_map_next_e
{
  IP4_MAP_NEXT_IP6_LOOKUP,
#ifdef MAP_SKIP_IP6_LOOKUP
  IP4_MAP_NEXT_IP6_REWRITE,
#endif
  IP4_MAP_NEXT_ICMP_ERROR,
  IP4_MAP_NEXT_DROP,
  IP4_MAP_N_NEXT,
};

static_always_inline u16
ip4_map_port_and_security_check (map_domain_t * d, vlib_buffer_t * b0,
				 u8 * error)
{
  u16 port;
  if (d->psid_length > 0)
    {
      ip4_header_t *ip = vlib_buffer_get_current (b0);

      if (PREDICT_FALSE
	  ((ip->ip_version_and_header_length != 0x45)
	   || clib_host_to_net_u16 (ip->length) < 28))
	{
	  return 0;
	}

      port = vnet_buffer (b0)->ip.reass.l4_dst_port;

      /* Verify that port is not among the well-known ports */
      if ((d->psid_offset > 0)
	  && (clib_net_to_host_u16 (port) < (0x1 << (16 - d->psid_offset))))
	{
	  *error = MAP_ERROR_ENCAP_SEC_CHECK;
	}
      else
	{
	  return port;
	}
    }
  return (0);
}

/*
 * ip4_map_vtcfl
 */
static_always_inline u32
ip4_map_vtcfl (ip4_header_t * ip4, vlib_buffer_t * p)
{
  map_main_t *mm = &map_main;
  u8 tc = mm->tc_copy ? ip4->tos : mm->tc;
  u32 vtcfl = 0x6 << 28;
  vtcfl |= tc << 20;
  vtcfl |= vnet_buffer (p)->ip.flow_hash & 0x000fffff;

  return (clib_host_to_net_u32 (vtcfl));
}

/*
 * ip4_map_ttl
 */
static inline void
ip4_map_decrement_ttl (ip4_header_t * ip, u8 * error)
{
  i32 ttl = ip->ttl;

  /* Input node should have reject packets with ttl 0. */
  ASSERT (ip->ttl > 0);

  u32 checksum = ip->checksum + clib_host_to_net_u16 (0x0100);
  checksum += checksum >= 0xffff;
  ip->checksum = checksum;
  ttl -= 1;
  ip->ttl = ttl;
  *error = ttl <= 0 ? IP4_ERROR_TIME_EXPIRED : *error;

  /* Verify checksum. */
  ASSERT (ip4_header_checksum_is_valid (ip));
}

static u32
ip4_map_fragment (vlib_main_t * vm, u32 bi, u16 mtu, bool df, u32 ** buffers,
		  u8 * error)
{
  map_main_t *mm = &map_main;
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);

  if (mm->frag_inner)
    {
      /* IPv4 fragmented packets inside of IPv6 */
      ip4_frag_do_fragment (vm, bi, mtu, sizeof (ip6_header_t), buffers);

      /* Fixup */
      u32 *i;
      vec_foreach (i, *buffers)
      {
	vlib_buffer_t *p = vlib_get_buffer (vm, *i);
	ip6_header_t *ip6 = vlib_buffer_get_current (p);
	ip6->payload_length =
	  clib_host_to_net_u16 (p->current_length - sizeof (ip6_header_t));
      }
    }
  else
    {
      if (df && !mm->frag_ignore_df)
	{
	  icmp4_error_set_vnet_buffer (b, ICMP4_destination_unreachable,
				       ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set,
				       mtu);
	  vlib_buffer_advance (b, sizeof (ip6_header_t));
	  *error = MAP_ERROR_DF_SET;
	  return (IP4_MAP_NEXT_ICMP_ERROR);
	}

      /* Create IPv6 fragments here */
      ip6_frag_do_fragment (vm, bi, mtu, 0, buffers);
    }
  return (IP4_MAP_NEXT_IP6_LOOKUP);
}

/*
 * ip4_map
 */
static uword
ip4_map (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_map_node.index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  map_main_t *mm = &map_main;
  vlib_combined_counter_main_t *cm = mm->domain_counters;
  u32 thread_index = vm->thread_index;
  u32 *buffer0 = 0;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  map_domain_t *d0;
	  u8 error0 = MAP_ERROR_NONE;
	  ip4_header_t *ip40;
	  u16 port0 = 0;
	  ip6_header_t *ip6h0;
	  u32 next0 = IP4_MAP_NEXT_IP6_LOOKUP;
	  u32 map_domain_index0 = ~0;
	  bool free_original_buffer0 = false;
	  u32 *frag_from0, frag_left0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip40 = vlib_buffer_get_current (p0);

	  d0 =
	    ip4_map_get_domain (&ip40->dst_address, &map_domain_index0,
				&error0);
	  if (!d0)
	    {			/* Guess it wasn't for us */
	      vnet_feature_next (&next0, p0);
	      goto exit;
	    }

	  /*
	   * Shared IPv4 address
	   */
	  port0 = ip4_map_port_and_security_check (d0, p0, &error0);

	  /*
	   * Clamp TCP MSS value.
	   */
	  if (ip40->protocol == IP_PROTOCOL_TCP)
	    {
	      tcp_header_t *tcp = ip4_next_header (ip40);
	      if (mm->tcp_mss > 0 && tcp_syn (tcp))
		{
		  ip_csum_t csum = tcp->checksum;
		  map_mss_clamping (tcp, &csum, mm->tcp_mss);
		  tcp->checksum = ip_csum_fold (csum);
		}
	    }

	  /* Decrement IPv4 TTL */
	  ip4_map_decrement_ttl (ip40, &error0);
	  bool df0 =
	    ip40->flags_and_fragment_offset &
	    clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);

	  /* MAP calc */
	  u32 da40 = clib_net_to_host_u32 (ip40->dst_address.as_u32);
	  u16 dp40 = clib_net_to_host_u16 (port0);
	  u64 dal60 = map_get_pfx (d0, da40, dp40);
	  u64 dar60 = map_get_sfx (d0, da40, dp40);
	  if (dal60 == 0 && dar60 == 0 && error0 == MAP_ERROR_NONE)
	    error0 = MAP_ERROR_NO_BINDING;

	  /* construct ipv6 header */
	  vlib_buffer_advance (p0, -(sizeof (ip6_header_t)));
	  ip6h0 = vlib_buffer_get_current (p0);
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  ip6h0->ip_version_traffic_class_and_flow_label =
	    ip4_map_vtcfl (ip40, p0);
	  ip6h0->payload_length = ip40->length;
	  ip6h0->protocol = IP_PROTOCOL_IP_IN_IP;
	  ip6h0->hop_limit = 0x40;
	  ip6h0->src_address = d0->ip6_src;
	  ip6h0->dst_address.as_u64[0] = clib_host_to_net_u64 (dal60);
	  ip6h0->dst_address.as_u64[1] = clib_host_to_net_u64 (dar60);

	  /*
	   * Determine next node. Can be one of:
	   * ip6-lookup, ip6-rewrite, error-drop
	   */
	  if (PREDICT_TRUE (error0 == MAP_ERROR_NONE))
	    {
	      if (PREDICT_FALSE
		  (d0->mtu
		   && (clib_net_to_host_u16 (ip6h0->payload_length) +
		       sizeof (*ip6h0) > d0->mtu)))
		{
		  next0 =
		    ip4_map_fragment (vm, pi0, d0->mtu, df0, &buffer0,
				      &error0);

		  if (error0 == MAP_ERROR_NONE)
		    {
		      free_original_buffer0 = true;
		    }
		}
	      else
		{
		  next0 =
		    ip4_map_ip6_lookup_bypass (p0,
					       ip40) ?
		    IP4_MAP_NEXT_IP6_REWRITE : next0;
		  vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_TX,
						   thread_index,
						   map_domain_index0, 1,
						   clib_net_to_host_u16
						   (ip6h0->payload_length) +
						   40);
		}
	    }
	  else
	    {
	      next0 = IP4_MAP_NEXT_DROP;
	    }

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      map_add_trace (vm, node, p0, map_domain_index0, port0);
	    }

	  p0->error = error_node->errors[error0];
	exit:
	  /* Send fragments that were added in the frame */
	  if (free_original_buffer0)
	    {
	      vlib_buffer_free_one (vm, pi0);	/* Free original packet */
	    }
	  else
	    {
	      vec_add1 (buffer0, pi0);
	    }

	  frag_from0 = buffer0;
	  frag_left0 = vec_len (buffer0);

	  while (frag_left0 > 0)
	    {
	      while (frag_left0 > 0 && n_left_to_next > 0)
		{
		  u32 i0;
		  i0 = to_next[0] = frag_from0[0];
		  frag_from0 += 1;
		  frag_left0 -= 1;
		  to_next += 1;
		  n_left_to_next -= 1;

		  vlib_get_buffer (vm, i0)->error =
		    error_node->errors[error0];
		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   i0, next0);
		}
	      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	      vlib_get_next_frame (vm, node, next_index, to_next,
				   n_left_to_next);
	    }
	  vec_reset_length (buffer0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vec_free (buffer0);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_map_feature, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-map",
  .runs_before = VNET_FEATURES ("ip4-flow-classify"),
  .runs_after = VNET_FEATURES("ip4-sv-reassembly-feature"),
};

VLIB_REGISTER_NODE(ip4_map_node) = {
  .function = ip4_map,
  .name = "ip4-map",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_counters = map_error_counters,

  .n_next_nodes = IP4_MAP_N_NEXT,
  .next_nodes = {
    [IP4_MAP_NEXT_IP6_LOOKUP] = "ip6-lookup",
#ifdef MAP_SKIP_IP6_LOOKUP
    [IP4_MAP_NEXT_IP6_REWRITE] = "ip6-load-balance",
#endif
    [IP4_MAP_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [IP4_MAP_NEXT_DROP] = "error-drop",
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
