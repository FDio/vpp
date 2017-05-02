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
#define MAP_ENCAP_DUAL 0

#include "map.h"
#include "../ip/ip_frag.h"
#include <vnet/ip/ip4_to_ip6.h>

vlib_node_registration_t ip4_map_reass_node;

enum ip4_map_next_e
{
  IP4_MAP_NEXT_IP6_LOOKUP,
#ifdef MAP_SKIP_IP6_LOOKUP
  IP4_MAP_NEXT_IP6_REWRITE,
#endif
  IP4_MAP_NEXT_IP4_FRAGMENT,
  IP4_MAP_NEXT_IP6_FRAGMENT,
  IP4_MAP_NEXT_REASS,
  IP4_MAP_NEXT_ICMP_ERROR,
  IP4_MAP_NEXT_DROP,
  IP4_MAP_N_NEXT,
};

enum ip4_map_reass_next_t
{
  IP4_MAP_REASS_NEXT_IP6_LOOKUP,
  IP4_MAP_REASS_NEXT_IP4_FRAGMENT,
  IP4_MAP_REASS_NEXT_DROP,
  IP4_MAP_REASS_N_NEXT,
};

typedef struct
{
  u32 map_domain_index;
  u16 port;
  u8 cached;
} map_ip4_map_reass_trace_t;

u8 *
format_ip4_map_reass_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  map_ip4_map_reass_trace_t *t = va_arg (*args, map_ip4_map_reass_trace_t *);
  return format (s, "MAP domain index: %d L4 port: %u Status: %s",
		 t->map_domain_index, t->port,
		 t->cached ? "cached" : "forwarded");
}

static_always_inline u16
ip4_map_port_and_security_check (map_domain_t * d, ip4_header_t * ip,
				 u32 * next, u8 * error)
{
  u16 port = 0;

  if (d->psid_length > 0)
    {
      if (ip4_get_fragment_offset (ip) == 0)
	{
	  if (PREDICT_FALSE
	      ((ip->ip_version_and_header_length != 0x45)
	       || clib_host_to_net_u16 (ip->length) < 28))
	    {
	      return 0;
	    }
	  port = ip4_get_port (ip, 0);
	  if (port)
	    {
	      /* Verify that port is not among the well-known ports */
	      if ((d->psid_offset > 0)
		  && (clib_net_to_host_u16 (port) <
		      (0x1 << (16 - d->psid_offset))))
		{
		  *error = MAP_ERROR_ENCAP_SEC_CHECK;
		}
	      else
		{
		  if (ip4_get_fragment_more (ip))
		    *next = IP4_MAP_NEXT_REASS;
		  return (port);
		}
	    }
	  else
	    {
	      *error = MAP_ERROR_BAD_PROTOCOL;
	    }
	}
      else
	{
	  *next = IP4_MAP_NEXT_REASS;
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

static_always_inline bool
ip4_map_ip6_lookup_bypass (vlib_buffer_t * p0, ip4_header_t * ip)
{
#ifdef MAP_SKIP_IP6_LOOKUP
  if (FIB_NODE_INDEX_INVALID != pre_resolved[FIB_PROTOCOL_IP6].fei)
    {
      vnet_buffer (p0)->ip.adj_index[VLIB_TX] =
	pre_resolved[FIB_PROTOCOL_IP6].dpo.dpoi_index;
      return (true);
    }
#endif
  return (false);
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
  ASSERT (ip->checksum == ip4_header_checksum (ip));
}

static u32
ip4_map_fragment (vlib_buffer_t * b, u16 mtu, bool df, u8 * error)
{
  map_main_t *mm = &map_main;

  if (mm->frag_inner)
    {
      ip_frag_set_vnet_buffer (b, sizeof (ip6_header_t), mtu,
			       IP4_FRAG_NEXT_IP6_LOOKUP,
			       IP_FRAG_FLAG_IP6_HEADER);
      return (IP4_MAP_NEXT_IP4_FRAGMENT);
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
      ip_frag_set_vnet_buffer (b, 0, mtu, IP6_FRAG_NEXT_IP6_LOOKUP,
			       IP_FRAG_FLAG_IP6_HEADER);
      return (IP4_MAP_NEXT_IP6_FRAGMENT);
    }
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
  u32 thread_index = vlib_get_thread_index ();

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Dual loop */
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 pi0, pi1;
	  vlib_buffer_t *p0, *p1;
	  map_domain_t *d0, *d1;
	  u8 error0 = MAP_ERROR_NONE, error1 = MAP_ERROR_NONE;
	  ip4_header_t *ip40, *ip41;
	  u16 port0 = 0, port1 = 0;
	  ip6_header_t *ip6h0, *ip6h1;
	  u32 map_domain_index0 = ~0, map_domain_index1 = ~0;
	  u32 next0 = IP4_MAP_NEXT_IP6_LOOKUP, next1 =
	    IP4_MAP_NEXT_IP6_LOOKUP;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, STORE);
	    vlib_prefetch_buffer_header (p3, STORE);
	    /* IPv4 + 8 = 28. possibly plus -40 */
	    CLIB_PREFETCH (p2->data - 40, 68, STORE);
	    CLIB_PREFETCH (p3->data - 40, 68, STORE);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);
	  ip40 = vlib_buffer_get_current (p0);
	  ip41 = vlib_buffer_get_current (p1);
	  map_domain_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	  d0 = ip4_map_get_domain (map_domain_index0);
	  map_domain_index1 = vnet_buffer (p1)->ip.adj_index[VLIB_TX];
	  d1 = ip4_map_get_domain (map_domain_index1);
	  ASSERT (d0);
	  ASSERT (d1);

	  /*
	   * Shared IPv4 address
	   */
	  port0 = ip4_map_port_and_security_check (d0, ip40, &next0, &error0);
	  port1 = ip4_map_port_and_security_check (d1, ip41, &next1, &error1);

	  /* Decrement IPv4 TTL */
	  ip4_map_decrement_ttl (ip40, &error0);
	  ip4_map_decrement_ttl (ip41, &error1);
	  bool df0 =
	    ip40->flags_and_fragment_offset &
	    clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);
	  bool df1 =
	    ip41->flags_and_fragment_offset &
	    clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);

	  /* MAP calc */
	  u32 da40 = clib_net_to_host_u32 (ip40->dst_address.as_u32);
	  u32 da41 = clib_net_to_host_u32 (ip41->dst_address.as_u32);
	  u16 dp40 = clib_net_to_host_u16 (port0);
	  u16 dp41 = clib_net_to_host_u16 (port1);
	  u64 dal60 = map_get_pfx (d0, da40, dp40);
	  u64 dal61 = map_get_pfx (d1, da41, dp41);
	  u64 dar60 = map_get_sfx (d0, da40, dp40);
	  u64 dar61 = map_get_sfx (d1, da41, dp41);
	  if (dal60 == 0 && dar60 == 0 && error0 == MAP_ERROR_NONE
	      && next0 != IP4_MAP_NEXT_REASS)
	    error0 = MAP_ERROR_NO_BINDING;
	  if (dal61 == 0 && dar61 == 0 && error1 == MAP_ERROR_NONE
	      && next1 != IP4_MAP_NEXT_REASS)
	    error1 = MAP_ERROR_NO_BINDING;

	  /* construct ipv6 header */
	  vlib_buffer_advance (p0, -sizeof (ip6_header_t));
	  vlib_buffer_advance (p1, -sizeof (ip6_header_t));
	  ip6h0 = vlib_buffer_get_current (p0);
	  ip6h1 = vlib_buffer_get_current (p1);
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  vnet_buffer (p1)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  ip6h0->ip_version_traffic_class_and_flow_label =
	    ip4_map_vtcfl (ip40, p0);
	  ip6h1->ip_version_traffic_class_and_flow_label =
	    ip4_map_vtcfl (ip41, p1);
	  ip6h0->payload_length = ip40->length;
	  ip6h1->payload_length = ip41->length;
	  ip6h0->protocol = IP_PROTOCOL_IP_IN_IP;
	  ip6h1->protocol = IP_PROTOCOL_IP_IN_IP;
	  ip6h0->hop_limit = 0x40;
	  ip6h1->hop_limit = 0x40;
	  ip6h0->src_address = d0->ip6_src;
	  ip6h1->src_address = d1->ip6_src;
	  ip6h0->dst_address.as_u64[0] = clib_host_to_net_u64 (dal60);
	  ip6h0->dst_address.as_u64[1] = clib_host_to_net_u64 (dar60);
	  ip6h1->dst_address.as_u64[0] = clib_host_to_net_u64 (dal61);
	  ip6h1->dst_address.as_u64[1] = clib_host_to_net_u64 (dar61);

	  /*
	   * Determine next node. Can be one of:
	   * ip6-lookup, ip6-rewrite, ip4-fragment, ip4-virtreass, error-drop
	   */
	  if (PREDICT_TRUE (error0 == MAP_ERROR_NONE))
	    {
	      if (PREDICT_FALSE
		  (d0->mtu
		   && (clib_net_to_host_u16 (ip6h0->payload_length) +
		       sizeof (*ip6h0) > d0->mtu)))
		{
		  next0 = ip4_map_fragment (p0, d0->mtu, df0, &error0);
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

	  /*
	   * Determine next node. Can be one of:
	   * ip6-lookup, ip6-rewrite, ip4-fragment, ip4-virtreass, error-drop
	   */
	  if (PREDICT_TRUE (error1 == MAP_ERROR_NONE))
	    {
	      if (PREDICT_FALSE
		  (d1->mtu
		   && (clib_net_to_host_u16 (ip6h1->payload_length) +
		       sizeof (*ip6h1) > d1->mtu)))
		{
		  next1 = ip4_map_fragment (p1, d1->mtu, df1, &error1);
		}
	      else
		{
		  next1 =
		    ip4_map_ip6_lookup_bypass (p1,
					       ip41) ?
		    IP4_MAP_NEXT_IP6_REWRITE : next1;
		  vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_TX,
						   thread_index,
						   map_domain_index1, 1,
						   clib_net_to_host_u16
						   (ip6h1->payload_length) +
						   40);
		}
	    }
	  else
	    {
	      next1 = IP4_MAP_NEXT_DROP;
	    }

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      map_trace_t *tr = vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->map_domain_index = map_domain_index0;
	      tr->port = port0;
	    }
	  if (PREDICT_FALSE (p1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      map_trace_t *tr = vlib_add_trace (vm, node, p1, sizeof (*tr));
	      tr->map_domain_index = map_domain_index1;
	      tr->port = port1;
	    }

	  p0->error = error_node->errors[error0];
	  p1->error = error_node->errors[error1];

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, pi1, next0,
					   next1);
	}

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

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip40 = vlib_buffer_get_current (p0);
	  map_domain_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	  d0 = ip4_map_get_domain (map_domain_index0);
	  ASSERT (d0);

	  /*
	   * Shared IPv4 address
	   */
	  port0 = ip4_map_port_and_security_check (d0, ip40, &next0, &error0);

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
	  if (dal60 == 0 && dar60 == 0 && error0 == MAP_ERROR_NONE
	      && next0 != IP4_MAP_NEXT_REASS)
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
	   * ip6-lookup, ip6-rewrite, ip4-fragment, ip4-virtreass, error-drop
	   */
	  if (PREDICT_TRUE (error0 == MAP_ERROR_NONE))
	    {
	      if (PREDICT_FALSE
		  (d0->mtu
		   && (clib_net_to_host_u16 (ip6h0->payload_length) +
		       sizeof (*ip6h0) > d0->mtu)))
		{
		  next0 = ip4_map_fragment (p0, d0->mtu, df0, &error0);
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
	      map_trace_t *tr = vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->map_domain_index = map_domain_index0;
	      tr->port = port0;
	    }

	  p0->error = error_node->errors[error0];
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/*
 * ip4_map_reass
 */
static uword
ip4_map_reass (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_map_reass_node.index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  map_main_t *mm = &map_main;
  vlib_combined_counter_main_t *cm = mm->domain_counters;
  u32 thread_index = vlib_get_thread_index ();
  u32 *fragments_to_drop = NULL;
  u32 *fragments_to_loopback = NULL;

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
	  i32 port0 = 0;
	  ip6_header_t *ip60;
	  u32 next0 = IP4_MAP_REASS_NEXT_IP6_LOOKUP;
	  u32 map_domain_index0;
	  u8 cached = 0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current (p0);
	  ip40 = (ip4_header_t *) (ip60 + 1);
	  map_domain_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	  d0 = ip4_map_get_domain (map_domain_index0);

	  map_ip4_reass_lock ();
	  map_ip4_reass_t *r = map_ip4_reass_get (ip40->src_address.as_u32,
						  ip40->dst_address.as_u32,
						  ip40->fragment_id,
						  ip40->protocol,
						  &fragments_to_drop);
	  if (PREDICT_FALSE (!r))
	    {
	      // Could not create a caching entry
	      error0 = MAP_ERROR_FRAGMENT_MEMORY;
	    }
	  else if (PREDICT_TRUE (ip4_get_fragment_offset (ip40)))
	    {
	      if (r->port >= 0)
		{
		  // We know the port already
		  port0 = r->port;
		}
	      else if (map_ip4_reass_add_fragment (r, pi0))
		{
		  // Not enough space for caching
		  error0 = MAP_ERROR_FRAGMENT_MEMORY;
		  map_ip4_reass_free (r, &fragments_to_drop);
		}
	      else
		{
		  cached = 1;
		}
	    }
	  else if ((port0 = ip4_get_port (ip40, 0)) == 0)
	    {
	      // Could not find port. We'll free the reassembly.
	      error0 = MAP_ERROR_BAD_PROTOCOL;
	      port0 = 0;
	      map_ip4_reass_free (r, &fragments_to_drop);
	    }
	  else
	    {
	      r->port = port0;
	      map_ip4_reass_get_fragments (r, &fragments_to_loopback);
	    }

#ifdef MAP_IP4_REASS_COUNT_BYTES
	  if (!cached && r)
	    {
	      r->forwarded += clib_host_to_net_u16 (ip40->length) - 20;
	      if (!ip4_get_fragment_more (ip40))
		r->expected_total =
		  ip4_get_fragment_offset (ip40) * 8 +
		  clib_host_to_net_u16 (ip40->length) - 20;
	      if (r->forwarded >= r->expected_total)
		map_ip4_reass_free (r, &fragments_to_drop);
	    }
#endif

	  map_ip4_reass_unlock ();

	  // NOTE: Most operations have already been performed by ip4_map
	  // All we need is the right destination address
	  ip60->dst_address.as_u64[0] =
	    map_get_pfx_net (d0, ip40->dst_address.as_u32, port0);
	  ip60->dst_address.as_u64[1] =
	    map_get_sfx_net (d0, ip40->dst_address.as_u32, port0);

	  if (PREDICT_FALSE
	      (d0->mtu
	       && (clib_net_to_host_u16 (ip60->payload_length) +
		   sizeof (*ip60) > d0->mtu)))
	    {
	      vnet_buffer (p0)->ip_frag.header_offset = sizeof (*ip60);
	      vnet_buffer (p0)->ip_frag.next_index = IP4_FRAG_NEXT_IP6_LOOKUP;
	      vnet_buffer (p0)->ip_frag.mtu = d0->mtu;
	      vnet_buffer (p0)->ip_frag.flags = IP_FRAG_FLAG_IP6_HEADER;
	      next0 = IP4_MAP_REASS_NEXT_IP4_FRAGMENT;
	    }

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      map_ip4_map_reass_trace_t *tr =
		vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->map_domain_index = map_domain_index0;
	      tr->port = port0;
	      tr->cached = cached;
	    }

	  if (cached)
	    {
	      //Dequeue the packet
	      n_left_to_next++;
	      to_next--;
	    }
	  else
	    {
	      if (error0 == MAP_ERROR_NONE)
		vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_TX,
						 thread_index,
						 map_domain_index0, 1,
						 clib_net_to_host_u16
						 (ip60->payload_length) + 40);
	      next0 =
		(error0 == MAP_ERROR_NONE) ? next0 : IP4_MAP_REASS_NEXT_DROP;
	      p0->error = error_node->errors[error0];
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, pi0, next0);
	    }

	  //Loopback when we reach the end of the inpu vector
	  if (n_left_from == 0 && vec_len (fragments_to_loopback))
	    {
	      from = vlib_frame_vector_args (frame);
	      u32 len = vec_len (fragments_to_loopback);
	      if (len <= VLIB_FRAME_SIZE)
		{
		  clib_memcpy (from, fragments_to_loopback,
			       sizeof (u32) * len);
		  n_left_from = len;
		  vec_reset_length (fragments_to_loopback);
		}
	      else
		{
		  clib_memcpy (from,
			       fragments_to_loopback + (len -
							VLIB_FRAME_SIZE),
			       sizeof (u32) * VLIB_FRAME_SIZE);
		  n_left_from = VLIB_FRAME_SIZE;
		  _vec_len (fragments_to_loopback) = len - VLIB_FRAME_SIZE;
		}
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  map_send_all_to_node (vm, fragments_to_drop, node,
			&error_node->errors[MAP_ERROR_FRAGMENT_DROPPED],
			IP4_MAP_REASS_NEXT_DROP);

  vec_free (fragments_to_drop);
  vec_free (fragments_to_loopback);
  return frame->n_vectors;
}

static char *map_error_strings[] = {
#define _(sym,string) string,
  foreach_map_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip4_map_node) = {
  .function = ip4_map,
  .name = "ip4-map",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_strings = map_error_strings,

  .n_next_nodes = IP4_MAP_N_NEXT,
  .next_nodes = {
    [IP4_MAP_NEXT_IP6_LOOKUP] = "ip6-lookup",
#ifdef MAP_SKIP_IP6_LOOKUP
    [IP4_MAP_NEXT_IP6_REWRITE] = "ip6-load-balance",
#endif
    [IP4_MAP_NEXT_IP4_FRAGMENT] = "ip4-frag",
    [IP4_MAP_NEXT_IP6_FRAGMENT] = "ip6-frag",
    [IP4_MAP_NEXT_REASS] = "ip4-map-reass",
    [IP4_MAP_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [IP4_MAP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip4_map_reass_node) = {
  .function = ip4_map_reass,
  .name = "ip4-map-reass",
  .vector_size = sizeof(u32),
  .format_trace = format_ip4_map_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_strings = map_error_strings,

  .n_next_nodes = IP4_MAP_REASS_N_NEXT,
  .next_nodes = {
    [IP4_MAP_REASS_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [IP4_MAP_REASS_NEXT_IP4_FRAGMENT] = "ip4-frag",
    [IP4_MAP_REASS_NEXT_DROP] = "error-drop",
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
