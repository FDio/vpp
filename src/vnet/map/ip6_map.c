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
#include "map.h"

#include "../ip/ip_frag.h"
#include <vnet/ip/ip4_to_ip6.h>
#include <vnet/ip/ip6_to_ip4.h>

enum ip6_map_next_e
{
  IP6_MAP_NEXT_IP4_LOOKUP,
#ifdef MAP_SKIP_IP6_LOOKUP
  IP6_MAP_NEXT_IP4_REWRITE,
#endif
  IP6_MAP_NEXT_IP6_REASS,
  IP6_MAP_NEXT_IP4_REASS,
  IP6_MAP_NEXT_IP4_FRAGMENT,
  IP6_MAP_NEXT_IP6_ICMP_RELAY,
  IP6_MAP_NEXT_IP6_LOCAL,
  IP6_MAP_NEXT_DROP,
  IP6_MAP_NEXT_ICMP,
  IP6_MAP_N_NEXT,
};

enum ip6_map_ip6_reass_next_e
{
  IP6_MAP_IP6_REASS_NEXT_IP6_MAP,
  IP6_MAP_IP6_REASS_NEXT_DROP,
  IP6_MAP_IP6_REASS_N_NEXT,
};

enum ip6_map_ip4_reass_next_e
{
  IP6_MAP_IP4_REASS_NEXT_IP4_LOOKUP,
  IP6_MAP_IP4_REASS_NEXT_IP4_FRAGMENT,
  IP6_MAP_IP4_REASS_NEXT_DROP,
  IP6_MAP_IP4_REASS_N_NEXT,
};

enum ip6_icmp_relay_next_e
{
  IP6_ICMP_RELAY_NEXT_IP4_LOOKUP,
  IP6_ICMP_RELAY_NEXT_DROP,
  IP6_ICMP_RELAY_N_NEXT,
};

vlib_node_registration_t ip6_map_ip4_reass_node;
vlib_node_registration_t ip6_map_ip6_reass_node;
static vlib_node_registration_t ip6_map_icmp_relay_node;

typedef struct
{
  u32 map_domain_index;
  u16 port;
  u8 cached;
} map_ip6_map_ip4_reass_trace_t;

u8 *
format_ip6_map_ip4_reass_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  map_ip6_map_ip4_reass_trace_t *t =
    va_arg (*args, map_ip6_map_ip4_reass_trace_t *);
  return format (s, "MAP domain index: %d L4 port: %u Status: %s",
		 t->map_domain_index, t->port,
		 t->cached ? "cached" : "forwarded");
}

typedef struct
{
  u16 offset;
  u16 frag_len;
  u8 out;
} map_ip6_map_ip6_reass_trace_t;

u8 *
format_ip6_map_ip6_reass_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  map_ip6_map_ip6_reass_trace_t *t =
    va_arg (*args, map_ip6_map_ip6_reass_trace_t *);
  return format (s, "Offset: %d Fragment length: %d Status: %s", t->offset,
		 t->frag_len, t->out ? "out" : "in");
}

/*
 * ip6_map_sec_check
 */
static_always_inline bool
ip6_map_sec_check (map_domain_t * d, u16 port, ip4_header_t * ip4,
		   ip6_header_t * ip6)
{
  u16 sp4 = clib_net_to_host_u16 (port);
  u32 sa4 = clib_net_to_host_u32 (ip4->src_address.as_u32);
  u64 sal6 = map_get_pfx (d, sa4, sp4);
  u64 sar6 = map_get_sfx (d, sa4, sp4);

  if (PREDICT_FALSE
      (sal6 != clib_net_to_host_u64 (ip6->src_address.as_u64[0])
       || sar6 != clib_net_to_host_u64 (ip6->src_address.as_u64[1])))
    return (false);
  return (true);
}

static_always_inline void
ip6_map_security_check (map_domain_t * d, ip4_header_t * ip4,
			ip6_header_t * ip6, u32 * next, u8 * error)
{
  map_main_t *mm = &map_main;
  if (d->ea_bits_len || d->rules)
    {
      if (d->psid_length > 0)
	{
	  if (!ip4_is_fragment (ip4))
	    {
	      u16 port = ip4_get_port (ip4, 1);
	      if (port)
		{
		  if (mm->sec_check)
		    *error =
		      ip6_map_sec_check (d, port, ip4,
					 ip6) ? MAP_ERROR_NONE :
		      MAP_ERROR_DECAP_SEC_CHECK;
		}
	      else
		{
		  *error = MAP_ERROR_BAD_PROTOCOL;
		}
	    }
	  else
	    {
	      *next = mm->sec_check_frag ? IP6_MAP_NEXT_IP4_REASS : *next;
	    }
	}
    }
}

static_always_inline bool
ip6_map_ip4_lookup_bypass (vlib_buffer_t * p0, ip4_header_t * ip)
{
#ifdef MAP_SKIP_IP6_LOOKUP
  if (FIB_NODE_INDEX_INVALID != pre_resolved[FIB_PROTOCOL_IP4].fei)
    {
      vnet_buffer (p0)->ip.adj_index[VLIB_TX] =
	pre_resolved[FIB_PROTOCOL_IP4].dpo.dpoi_index;
      return (true);
    }
#endif
  return (false);
}

/*
 * ip6_map
 */
static uword
ip6_map (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_node.index);
  map_main_t *mm = &map_main;
  vlib_combined_counter_main_t *cm = mm->domain_counters;
  u32 thread_index = vlib_get_thread_index ();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Dual loop */
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 pi0, pi1;
	  vlib_buffer_t *p0, *p1;
	  u8 error0 = MAP_ERROR_NONE;
	  u8 error1 = MAP_ERROR_NONE;
	  map_domain_t *d0 = 0, *d1 = 0;
	  ip4_header_t *ip40, *ip41;
	  ip6_header_t *ip60, *ip61;
	  u16 port0 = 0, port1 = 0;
	  u32 map_domain_index0 = ~0, map_domain_index1 = ~0;
	  u32 next0 = IP6_MAP_NEXT_IP4_LOOKUP;
	  u32 next1 = IP6_MAP_NEXT_IP4_LOOKUP;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    /* IPv6 + IPv4 header + 8 bytes of ULP */
	    CLIB_PREFETCH (p2->data, 68, LOAD);
	    CLIB_PREFETCH (p3->data, 68, LOAD);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);
	  ip60 = vlib_buffer_get_current (p0);
	  ip61 = vlib_buffer_get_current (p1);
	  vlib_buffer_advance (p0, sizeof (ip6_header_t));
	  vlib_buffer_advance (p1, sizeof (ip6_header_t));
	  ip40 = vlib_buffer_get_current (p0);
	  ip41 = vlib_buffer_get_current (p1);

	  /*
	   * Encapsulated IPv4 packet
	   *   - IPv4 fragmented -> Pass to virtual reassembly unless security check disabled
	   *   - Lookup/Rewrite or Fragment node in case of packet > MTU
	   * Fragmented IPv6 packet
	   * ICMP IPv6 packet
	   *   - Error -> Pass to ICMPv6/ICMPv4 relay
	   *   - Info -> Pass to IPv6 local
	   * Anything else -> drop
	   */
	  if (PREDICT_TRUE
	      (ip60->protocol == IP_PROTOCOL_IP_IN_IP
	       && clib_net_to_host_u16 (ip60->payload_length) > 20))
	    {
	      d0 =
		ip6_map_get_domain (vnet_buffer (p0)->ip.adj_index[VLIB_TX],
				    (ip4_address_t *) & ip40->
				    src_address.as_u32, &map_domain_index0,
				    &error0);
	    }
	  else if (ip60->protocol == IP_PROTOCOL_ICMP6 &&
		   clib_net_to_host_u16 (ip60->payload_length) >
		   sizeof (icmp46_header_t))
	    {
	      icmp46_header_t *icmp = (void *) (ip60 + 1);
	      next0 = (icmp->type == ICMP6_echo_request
		       || icmp->type ==
		       ICMP6_echo_reply) ? IP6_MAP_NEXT_IP6_LOCAL :
		IP6_MAP_NEXT_IP6_ICMP_RELAY;
	    }
	  else if (ip60->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
	    {
	      next0 = IP6_MAP_NEXT_IP6_REASS;
	    }
	  else
	    {
	      error0 = MAP_ERROR_BAD_PROTOCOL;
	    }
	  if (PREDICT_TRUE
	      (ip61->protocol == IP_PROTOCOL_IP_IN_IP
	       && clib_net_to_host_u16 (ip61->payload_length) > 20))
	    {
	      d1 =
		ip6_map_get_domain (vnet_buffer (p1)->ip.adj_index[VLIB_TX],
				    (ip4_address_t *) & ip41->
				    src_address.as_u32, &map_domain_index1,
				    &error1);
	    }
	  else if (ip61->protocol == IP_PROTOCOL_ICMP6 &&
		   clib_net_to_host_u16 (ip61->payload_length) >
		   sizeof (icmp46_header_t))
	    {
	      icmp46_header_t *icmp = (void *) (ip61 + 1);
	      next1 = (icmp->type == ICMP6_echo_request
		       || icmp->type ==
		       ICMP6_echo_reply) ? IP6_MAP_NEXT_IP6_LOCAL :
		IP6_MAP_NEXT_IP6_ICMP_RELAY;
	    }
	  else if (ip61->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
	    {
	      next1 = IP6_MAP_NEXT_IP6_REASS;
	    }
	  else
	    {
	      error1 = MAP_ERROR_BAD_PROTOCOL;
	    }

	  if (d0)
	    {
	      /* MAP inbound security check */
	      ip6_map_security_check (d0, ip40, ip60, &next0, &error0);

	      if (PREDICT_TRUE (error0 == MAP_ERROR_NONE &&
				next0 == IP6_MAP_NEXT_IP4_LOOKUP))
		{
		  if (PREDICT_FALSE
		      (d0->mtu
		       && (clib_host_to_net_u16 (ip40->length) > d0->mtu)))
		    {
		      vnet_buffer (p0)->ip_frag.header_offset = 0;
		      vnet_buffer (p0)->ip_frag.flags = 0;
		      vnet_buffer (p0)->ip_frag.next_index =
			IP4_FRAG_NEXT_IP4_LOOKUP;
		      vnet_buffer (p0)->ip_frag.mtu = d0->mtu;
		      next0 = IP6_MAP_NEXT_IP4_FRAGMENT;
		    }
		  else
		    {
		      next0 =
			ip6_map_ip4_lookup_bypass (p0,
						   ip40) ?
			IP6_MAP_NEXT_IP4_REWRITE : next0;
		    }
		  vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_RX,
						   thread_index,
						   map_domain_index0, 1,
						   clib_net_to_host_u16
						   (ip40->length));
		}
	    }
	  if (d1)
	    {
	      /* MAP inbound security check */
	      ip6_map_security_check (d1, ip41, ip61, &next1, &error1);

	      if (PREDICT_TRUE (error1 == MAP_ERROR_NONE &&
				next1 == IP6_MAP_NEXT_IP4_LOOKUP))
		{
		  if (PREDICT_FALSE
		      (d1->mtu
		       && (clib_host_to_net_u16 (ip41->length) > d1->mtu)))
		    {
		      vnet_buffer (p1)->ip_frag.header_offset = 0;
		      vnet_buffer (p1)->ip_frag.flags = 0;
		      vnet_buffer (p1)->ip_frag.next_index =
			IP4_FRAG_NEXT_IP4_LOOKUP;
		      vnet_buffer (p1)->ip_frag.mtu = d1->mtu;
		      next1 = IP6_MAP_NEXT_IP4_FRAGMENT;
		    }
		  else
		    {
		      next1 =
			ip6_map_ip4_lookup_bypass (p1,
						   ip41) ?
			IP6_MAP_NEXT_IP4_REWRITE : next1;
		    }
		  vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_RX,
						   thread_index,
						   map_domain_index1, 1,
						   clib_net_to_host_u16
						   (ip41->length));
		}
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

	  if (error0 == MAP_ERROR_DECAP_SEC_CHECK && mm->icmp6_enabled)
	    {
	      /* Set ICMP parameters */
	      vlib_buffer_advance (p0, -sizeof (ip6_header_t));
	      icmp6_error_set_vnet_buffer (p0, ICMP6_destination_unreachable,
					   ICMP6_destination_unreachable_source_address_failed_policy,
					   0);
	      next0 = IP6_MAP_NEXT_ICMP;
	    }
	  else
	    {
	      next0 = (error0 == MAP_ERROR_NONE) ? next0 : IP6_MAP_NEXT_DROP;
	    }

	  if (error1 == MAP_ERROR_DECAP_SEC_CHECK && mm->icmp6_enabled)
	    {
	      /* Set ICMP parameters */
	      vlib_buffer_advance (p1, -sizeof (ip6_header_t));
	      icmp6_error_set_vnet_buffer (p1, ICMP6_destination_unreachable,
					   ICMP6_destination_unreachable_source_address_failed_policy,
					   0);
	      next1 = IP6_MAP_NEXT_ICMP;
	    }
	  else
	    {
	      next1 = (error1 == MAP_ERROR_NONE) ? next1 : IP6_MAP_NEXT_DROP;
	    }

	  /* Reset packet */
	  if (next0 == IP6_MAP_NEXT_IP6_LOCAL)
	    vlib_buffer_advance (p0, -sizeof (ip6_header_t));
	  if (next1 == IP6_MAP_NEXT_IP6_LOCAL)
	    vlib_buffer_advance (p1, -sizeof (ip6_header_t));

	  p0->error = error_node->errors[error0];
	  p1->error = error_node->errors[error1];
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, pi1, next0,
					   next1);
	}

      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  u8 error0 = MAP_ERROR_NONE;
	  map_domain_t *d0 = 0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  i32 port0 = 0;
	  u32 map_domain_index0 = ~0;
	  u32 next0 = IP6_MAP_NEXT_IP4_LOOKUP;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current (p0);
	  vlib_buffer_advance (p0, sizeof (ip6_header_t));
	  ip40 = vlib_buffer_get_current (p0);

	  /*
	   * Encapsulated IPv4 packet
	   *   - IPv4 fragmented -> Pass to virtual reassembly unless security check disabled
	   *   - Lookup/Rewrite or Fragment node in case of packet > MTU
	   * Fragmented IPv6 packet
	   * ICMP IPv6 packet
	   *   - Error -> Pass to ICMPv6/ICMPv4 relay
	   *   - Info -> Pass to IPv6 local
	   * Anything else -> drop
	   */
	  if (PREDICT_TRUE
	      (ip60->protocol == IP_PROTOCOL_IP_IN_IP
	       && clib_net_to_host_u16 (ip60->payload_length) > 20))
	    {
	      d0 =
		ip6_map_get_domain (vnet_buffer (p0)->ip.adj_index[VLIB_TX],
				    (ip4_address_t *) & ip40->
				    src_address.as_u32, &map_domain_index0,
				    &error0);
	    }
	  else if (ip60->protocol == IP_PROTOCOL_ICMP6 &&
		   clib_net_to_host_u16 (ip60->payload_length) >
		   sizeof (icmp46_header_t))
	    {
	      icmp46_header_t *icmp = (void *) (ip60 + 1);
	      next0 = (icmp->type == ICMP6_echo_request
		       || icmp->type ==
		       ICMP6_echo_reply) ? IP6_MAP_NEXT_IP6_LOCAL :
		IP6_MAP_NEXT_IP6_ICMP_RELAY;
	    }
	  else if (ip60->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION &&
		   (((ip6_frag_hdr_t *) (ip60 + 1))->next_hdr ==
		    IP_PROTOCOL_IP_IN_IP))
	    {
	      next0 = IP6_MAP_NEXT_IP6_REASS;
	    }
	  else
	    {
	      error0 = MAP_ERROR_BAD_PROTOCOL;
	    }

	  if (d0)
	    {
	      /* MAP inbound security check */
	      ip6_map_security_check (d0, ip40, ip60, &next0, &error0);

	      if (PREDICT_TRUE (error0 == MAP_ERROR_NONE &&
				next0 == IP6_MAP_NEXT_IP4_LOOKUP))
		{
		  if (PREDICT_FALSE
		      (d0->mtu
		       && (clib_host_to_net_u16 (ip40->length) > d0->mtu)))
		    {
		      vnet_buffer (p0)->ip_frag.header_offset = 0;
		      vnet_buffer (p0)->ip_frag.flags = 0;
		      vnet_buffer (p0)->ip_frag.next_index =
			IP4_FRAG_NEXT_IP4_LOOKUP;
		      vnet_buffer (p0)->ip_frag.mtu = d0->mtu;
		      next0 = IP6_MAP_NEXT_IP4_FRAGMENT;
		    }
		  else
		    {
		      next0 =
			ip6_map_ip4_lookup_bypass (p0,
						   ip40) ?
			IP6_MAP_NEXT_IP4_REWRITE : next0;
		    }
		  vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_RX,
						   thread_index,
						   map_domain_index0, 1,
						   clib_net_to_host_u16
						   (ip40->length));
		}
	    }

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      map_trace_t *tr = vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->map_domain_index = map_domain_index0;
	      tr->port = (u16) port0;
	    }

	  if (mm->icmp6_enabled &&
	      (error0 == MAP_ERROR_DECAP_SEC_CHECK
	       || error0 == MAP_ERROR_NO_DOMAIN))
	    {
	      /* Set ICMP parameters */
	      vlib_buffer_advance (p0, -sizeof (ip6_header_t));
	      icmp6_error_set_vnet_buffer (p0, ICMP6_destination_unreachable,
					   ICMP6_destination_unreachable_source_address_failed_policy,
					   0);
	      next0 = IP6_MAP_NEXT_ICMP;
	    }
	  else
	    {
	      next0 = (error0 == MAP_ERROR_NONE) ? next0 : IP6_MAP_NEXT_DROP;
	    }

	  /* Reset packet */
	  if (next0 == IP6_MAP_NEXT_IP6_LOCAL)
	    vlib_buffer_advance (p0, -sizeof (ip6_header_t));

	  p0->error = error_node->errors[error0];
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}


static_always_inline void
ip6_map_ip6_reass_prepare (vlib_main_t * vm, vlib_node_runtime_t * node,
			   map_ip6_reass_t * r, u32 ** fragments_ready,
			   u32 ** fragments_to_drop)
{
  ip4_header_t *ip40;
  ip6_header_t *ip60;
  ip6_frag_hdr_t *frag0;
  vlib_buffer_t *p0;

  if (!r->ip4_header.ip_version_and_header_length)
    return;

  //The IP header is here, we need to check for packets
  //that can be forwarded
  int i;
  for (i = 0; i < MAP_IP6_REASS_MAX_FRAGMENTS_PER_REASSEMBLY; i++)
    {
      if (r->fragments[i].pi == ~0 ||
	  ((!r->fragments[i].next_data_len)
	   && (r->fragments[i].next_data_offset != (0xffff))))
	continue;

      p0 = vlib_get_buffer (vm, r->fragments[i].pi);
      ip60 = vlib_buffer_get_current (p0);
      frag0 = (ip6_frag_hdr_t *) (ip60 + 1);
      ip40 = (ip4_header_t *) (frag0 + 1);

      if (ip6_frag_hdr_offset (frag0))
	{
	  //Not first fragment, add the IPv4 header
	  clib_memcpy (ip40, &r->ip4_header, 20);
	}

#ifdef MAP_IP6_REASS_COUNT_BYTES
      r->forwarded +=
	clib_net_to_host_u16 (ip60->payload_length) - sizeof (*frag0);
#endif

      if (ip6_frag_hdr_more (frag0))
	{
	  //Not last fragment, we copy end of next
	  clib_memcpy (u8_ptr_add (ip60, p0->current_length),
		       r->fragments[i].next_data, 20);
	  p0->current_length += 20;
	  ip60->payload_length = u16_net_add (ip60->payload_length, 20);
	}

      if (!ip4_is_fragment (ip40))
	{
	  ip40->fragment_id = frag_id_6to4 (frag0->identification);
	  ip40->flags_and_fragment_offset =
	    clib_host_to_net_u16 (ip6_frag_hdr_offset (frag0));
	}
      else
	{
	  ip40->flags_and_fragment_offset =
	    clib_host_to_net_u16 (ip4_get_fragment_offset (ip40) +
				  ip6_frag_hdr_offset (frag0));
	}

      if (ip6_frag_hdr_more (frag0))
	ip40->flags_and_fragment_offset |=
	  clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);

      ip40->length =
	clib_host_to_net_u16 (p0->current_length - sizeof (*ip60) -
			      sizeof (*frag0));
      ip40->checksum = ip4_header_checksum (ip40);

      if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  map_ip6_map_ip6_reass_trace_t *tr =
	    vlib_add_trace (vm, node, p0, sizeof (*tr));
	  tr->offset = ip4_get_fragment_offset (ip40);
	  tr->frag_len = clib_net_to_host_u16 (ip40->length) - sizeof (*ip40);
	  tr->out = 1;
	}

      vec_add1 (*fragments_ready, r->fragments[i].pi);
      r->fragments[i].pi = ~0;
      r->fragments[i].next_data_len = 0;
      r->fragments[i].next_data_offset = 0;
      map_main.ip6_reass_buffered_counter--;

      //TODO: Best solution would be that ip6_map handles extension headers
      // and ignores atomic fragment. But in the meantime, let's just copy the header.

      u8 protocol = frag0->next_hdr;
      memmove (u8_ptr_add (ip40, -sizeof (*ip60)), ip60, sizeof (*ip60));
      ((ip6_header_t *) u8_ptr_add (ip40, -sizeof (*ip60)))->protocol =
	protocol;
      vlib_buffer_advance (p0, sizeof (*frag0));
    }
}

void
map_ip6_drop_pi (u32 pi)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_runtime_t *n =
    vlib_node_get_runtime (vm, ip6_map_ip6_reass_node.index);
  vlib_set_next_frame_buffer (vm, n, IP6_MAP_IP6_REASS_NEXT_DROP, pi);
}

void
map_ip4_drop_pi (u32 pi)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_runtime_t *n =
    vlib_node_get_runtime (vm, ip6_map_ip4_reass_node.index);
  vlib_set_next_frame_buffer (vm, n, IP6_MAP_IP4_REASS_NEXT_DROP, pi);
}

/*
 * ip6_reass
 * TODO: We should count the number of successfully
 * transmitted fragment bytes and compare that to the last fragment
 * offset such that we can free the reassembly structure when all fragments
 * have been forwarded.
 */
static uword
ip6_map_ip6_reass (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_ip6_reass_node.index);
  u32 *fragments_to_drop = NULL;
  u32 *fragments_ready = NULL;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  u8 error0 = MAP_ERROR_NONE;
	  ip6_header_t *ip60;
	  ip6_frag_hdr_t *frag0;
	  u16 offset;
	  u16 next_offset;
	  u16 frag_len;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current (p0);
	  frag0 = (ip6_frag_hdr_t *) (ip60 + 1);
	  offset =
	    clib_host_to_net_u16 (frag0->fragment_offset_and_more) & (~7);
	  frag_len =
	    clib_net_to_host_u16 (ip60->payload_length) - sizeof (*frag0);
	  next_offset =
	    ip6_frag_hdr_more (frag0) ? (offset + frag_len) : (0xffff);

	  //FIXME: Support other extension headers, maybe

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      map_ip6_map_ip6_reass_trace_t *tr =
		vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->offset = offset;
	      tr->frag_len = frag_len;
	      tr->out = 0;
	    }

	  map_ip6_reass_lock ();
	  map_ip6_reass_t *r =
	    map_ip6_reass_get (&ip60->src_address, &ip60->dst_address,
			       frag0->identification, frag0->next_hdr,
			       &fragments_to_drop);
	  //FIXME: Use better error codes
	  if (PREDICT_FALSE (!r))
	    {
	      // Could not create a caching entry
	      error0 = MAP_ERROR_FRAGMENT_MEMORY;
	    }
	  else if (PREDICT_FALSE ((frag_len <= 20 &&
				   (ip6_frag_hdr_more (frag0) || (!offset)))))
	    {
	      //Very small fragment are restricted to the last one and
	      //can't be the first one
	      error0 = MAP_ERROR_FRAGMENT_MALFORMED;
	    }
	  else
	    if (map_ip6_reass_add_fragment
		(r, pi0, offset, next_offset, (u8 *) (frag0 + 1), frag_len))
	    {
	      map_ip6_reass_free (r, &fragments_to_drop);
	      error0 = MAP_ERROR_FRAGMENT_MEMORY;
	    }
	  else
	    {
#ifdef MAP_IP6_REASS_COUNT_BYTES
	      if (!ip6_frag_hdr_more (frag0))
		r->expected_total = offset + frag_len;
#endif
	      ip6_map_ip6_reass_prepare (vm, node, r, &fragments_ready,
					 &fragments_to_drop);
#ifdef MAP_IP6_REASS_COUNT_BYTES
	      if (r->forwarded >= r->expected_total)
		map_ip6_reass_free (r, &fragments_to_drop);
#endif
	    }
	  map_ip6_reass_unlock ();

	  if (error0 == MAP_ERROR_NONE)
	    {
	      if (frag_len > 20)
		{
		  //Dequeue the packet
		  n_left_to_next++;
		  to_next--;
		}
	      else
		{
		  //All data from that packet was copied no need to keep it, but this is not an error
		  p0->error = error_node->errors[MAP_ERROR_NONE];
		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   pi0,
						   IP6_MAP_IP6_REASS_NEXT_DROP);
		}
	    }
	  else
	    {
	      p0->error = error_node->errors[error0];
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, pi0,
					       IP6_MAP_IP6_REASS_NEXT_DROP);
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  map_send_all_to_node (vm, fragments_ready, node,
			&error_node->errors[MAP_ERROR_NONE],
			IP6_MAP_IP6_REASS_NEXT_IP6_MAP);
  map_send_all_to_node (vm, fragments_to_drop, node,
			&error_node->errors[MAP_ERROR_FRAGMENT_DROPPED],
			IP6_MAP_IP6_REASS_NEXT_DROP);

  vec_free (fragments_to_drop);
  vec_free (fragments_ready);
  return frame->n_vectors;
}

/*
 * ip6_ip4_virt_reass
 */
static uword
ip6_map_ip4_reass (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_ip4_reass_node.index);
  map_main_t *mm = &map_main;
  vlib_combined_counter_main_t *cm = mm->domain_counters;
  u32 thread_index = vlib_get_thread_index ();
  u32 *fragments_to_drop = NULL;
  u32 *fragments_to_loopback = NULL;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  u8 error0 = MAP_ERROR_NONE;
	  map_domain_t *d0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  i32 port0 = 0;
	  u32 map_domain_index0 = ~0;
	  u32 next0 = IP6_MAP_IP4_REASS_NEXT_IP4_LOOKUP;
	  u8 cached = 0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip40 = vlib_buffer_get_current (p0);
	  ip60 = ((ip6_header_t *) ip40) - 1;

	  d0 =
	    ip6_map_get_domain (vnet_buffer (p0)->ip.adj_index[VLIB_TX],
				(ip4_address_t *) & ip40->src_address.as_u32,
				&map_domain_index0, &error0);

	  map_ip4_reass_lock ();
	  //This node only deals with fragmented ip4
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
	      // This is a fragment
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
	  else if ((port0 = ip4_get_port (ip40, 1)) == 0)
	    {
	      // Could not find port from first fragment. Stop reassembling.
	      error0 = MAP_ERROR_BAD_PROTOCOL;
	      port0 = 0;
	      map_ip4_reass_free (r, &fragments_to_drop);
	    }
	  else
	    {
	      // Found port. Remember it and loopback saved fragments
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

	  if (PREDICT_TRUE (error0 == MAP_ERROR_NONE))
	    error0 =
	      ip6_map_sec_check (d0, port0, ip40,
				 ip60) ? MAP_ERROR_NONE :
	      MAP_ERROR_DECAP_SEC_CHECK;

	  if (PREDICT_FALSE
	      (d0->mtu && (clib_host_to_net_u16 (ip40->length) > d0->mtu)
	       && error0 == MAP_ERROR_NONE && !cached))
	    {
	      vnet_buffer (p0)->ip_frag.header_offset = 0;
	      vnet_buffer (p0)->ip_frag.flags = 0;
	      vnet_buffer (p0)->ip_frag.next_index = IP4_FRAG_NEXT_IP4_LOOKUP;
	      vnet_buffer (p0)->ip_frag.mtu = d0->mtu;
	      next0 = IP6_MAP_IP4_REASS_NEXT_IP4_FRAGMENT;
	    }

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      map_ip6_map_ip4_reass_trace_t *tr =
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
		vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_RX,
						 thread_index,
						 map_domain_index0, 1,
						 clib_net_to_host_u16
						 (ip40->length));
	      next0 =
		(error0 ==
		 MAP_ERROR_NONE) ? next0 : IP6_MAP_IP4_REASS_NEXT_DROP;
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
			IP6_MAP_IP4_REASS_NEXT_DROP);

  vec_free (fragments_to_drop);
  vec_free (fragments_to_loopback);
  return frame->n_vectors;
}

/*
 * ip6_icmp_relay
 */
static uword
ip6_map_icmp_relay (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_icmp_relay_node.index);
  map_main_t *mm = &map_main;
  u32 thread_index = vlib_get_thread_index ();
  u16 *fragment_ids, *fid;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  /* Get random fragment IDs for replies. */
  fid = fragment_ids =
    clib_random_buffer_get_data (&vm->random_buffer,
				 n_left_from * sizeof (fragment_ids[0]));

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  u8 error0 = MAP_ERROR_NONE;
	  ip6_header_t *ip60;
	  u32 next0 = IP6_ICMP_RELAY_NEXT_IP4_LOOKUP;
	  u32 mtu;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current (p0);
	  u16 tlen = clib_net_to_host_u16 (ip60->payload_length);

	  /*
	   * In:
	   *  IPv6 header           (40)
	   *  ICMPv6 header          (8)
	   *  IPv6 header           (40)
	   *  Original IPv4 header / packet
	   * Out:
	   *  New IPv4 header
	   *  New ICMP header
	   *  Original IPv4 header / packet
	   */

	  /* Need at least ICMP(8) + IPv6(40) + IPv4(20) + L4 header(8) */
	  if (tlen < 76)
	    {
	      error0 = MAP_ERROR_ICMP_RELAY;
	      goto error;
	    }

	  icmp46_header_t *icmp60 = (icmp46_header_t *) (ip60 + 1);
	  ip6_header_t *inner_ip60 = (ip6_header_t *) (icmp60 + 2);

	  if (inner_ip60->protocol != IP_PROTOCOL_IP_IN_IP)
	    {
	      error0 = MAP_ERROR_ICMP_RELAY;
	      goto error;
	    }

	  ip4_header_t *inner_ip40 = (ip4_header_t *) (inner_ip60 + 1);
	  vlib_buffer_advance (p0, 60);	/* sizeof ( IPv6 + ICMP + IPv6 - IPv4 - ICMP ) */
	  ip4_header_t *new_ip40 = vlib_buffer_get_current (p0);
	  icmp46_header_t *new_icmp40 = (icmp46_header_t *) (new_ip40 + 1);

	  /*
	   * Relay according to RFC2473, section 8.3
	   */
	  switch (icmp60->type)
	    {
	    case ICMP6_destination_unreachable:
	    case ICMP6_time_exceeded:
	    case ICMP6_parameter_problem:
	      /* Type 3 - destination unreachable, Code 1 - host unreachable */
	      new_icmp40->type = ICMP4_destination_unreachable;
	      new_icmp40->code =
		ICMP4_destination_unreachable_destination_unreachable_host;
	      break;

	    case ICMP6_packet_too_big:
	      /* Type 3 - destination unreachable, Code 4 - packet too big */
	      /* Potential TODO: Adjust domain tunnel MTU based on the value received here */
	      mtu = clib_net_to_host_u32 (*((u32 *) (icmp60 + 1)));

	      /* Check DF flag */
	      if (!
		  (inner_ip40->flags_and_fragment_offset &
		   clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT)))
		{
		  error0 = MAP_ERROR_ICMP_RELAY;
		  goto error;
		}

	      new_icmp40->type = ICMP4_destination_unreachable;
	      new_icmp40->code =
		ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set;
	      *((u32 *) (new_icmp40 + 1)) =
		clib_host_to_net_u32 (mtu < 1280 ? 1280 : mtu);
	      break;

	    default:
	      error0 = MAP_ERROR_ICMP_RELAY;
	      break;
	    }

	  /*
	   * Ensure the total ICMP packet is no longer than 576 bytes (RFC1812)
	   */
	  new_ip40->ip_version_and_header_length = 0x45;
	  new_ip40->tos = 0;
	  u16 nlen = (tlen - 20) > 576 ? 576 : tlen - 20;
	  new_ip40->length = clib_host_to_net_u16 (nlen);
	  new_ip40->fragment_id = fid[0];
	  fid++;
	  new_ip40->ttl = 64;
	  new_ip40->protocol = IP_PROTOCOL_ICMP;
	  new_ip40->src_address = mm->icmp4_src_address;
	  new_ip40->dst_address = inner_ip40->src_address;
	  new_ip40->checksum = ip4_header_checksum (new_ip40);

	  new_icmp40->checksum = 0;
	  ip_csum_t sum = ip_incremental_checksum (0, new_icmp40, nlen - 20);
	  new_icmp40->checksum = ~ip_csum_fold (sum);

	  vlib_increment_simple_counter (&mm->icmp_relayed, thread_index, 0,
					 1);

	error:
	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      map_trace_t *tr = vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->map_domain_index = 0;
	      tr->port = 0;
	    }

	  next0 =
	    (error0 == MAP_ERROR_NONE) ? next0 : IP6_ICMP_RELAY_NEXT_DROP;
	  p0->error = error_node->errors[error0];
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;

}

static char *map_error_strings[] = {
#define _(sym,string) string,
  foreach_map_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip6_map_node) = {
  .function = ip6_map,
  .name = "ip6-map",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_strings = map_error_strings,

  .n_next_nodes = IP6_MAP_N_NEXT,
  .next_nodes = {
    [IP6_MAP_NEXT_IP4_LOOKUP] = "ip4-lookup",
#ifdef MAP_SKIP_IP6_LOOKUP
    [IP6_MAP_NEXT_IP4_REWRITE] = "ip4-load-balance",
#endif
    [IP6_MAP_NEXT_IP6_REASS] = "ip6-map-ip6-reass",
    [IP6_MAP_NEXT_IP4_REASS] = "ip6-map-ip4-reass",
    [IP6_MAP_NEXT_IP4_FRAGMENT] = "ip4-frag",
    [IP6_MAP_NEXT_IP6_ICMP_RELAY] = "ip6-map-icmp-relay",
    [IP6_MAP_NEXT_IP6_LOCAL] = "ip6-local",
    [IP6_MAP_NEXT_DROP] = "error-drop",
    [IP6_MAP_NEXT_ICMP] = "ip6-icmp-error",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip6_map_ip6_reass_node) = {
  .function = ip6_map_ip6_reass,
  .name = "ip6-map-ip6-reass",
  .vector_size = sizeof(u32),
  .format_trace = format_ip6_map_ip6_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = MAP_N_ERROR,
  .error_strings = map_error_strings,
  .n_next_nodes = IP6_MAP_IP6_REASS_N_NEXT,
  .next_nodes = {
    [IP6_MAP_IP6_REASS_NEXT_IP6_MAP] = "ip6-map",
    [IP6_MAP_IP6_REASS_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip6_map_ip4_reass_node) = {
  .function = ip6_map_ip4_reass,
  .name = "ip6-map-ip4-reass",
  .vector_size = sizeof(u32),
  .format_trace = format_ip6_map_ip4_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = MAP_N_ERROR,
  .error_strings = map_error_strings,
  .n_next_nodes = IP6_MAP_IP4_REASS_N_NEXT,
  .next_nodes = {
    [IP6_MAP_IP4_REASS_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IP6_MAP_IP4_REASS_NEXT_IP4_FRAGMENT] = "ip4-frag",
    [IP6_MAP_IP4_REASS_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip6_map_icmp_relay_node, static) = {
  .function = ip6_map_icmp_relay,
  .name = "ip6-map-icmp-relay",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace, //FIXME
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = MAP_N_ERROR,
  .error_strings = map_error_strings,
  .n_next_nodes = IP6_ICMP_RELAY_N_NEXT,
  .next_nodes = {
    [IP6_ICMP_RELAY_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IP6_ICMP_RELAY_NEXT_DROP] = "error-drop",
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
