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

#include <vnet/ip/ip_frag.h>
#include <vnet/ip/ip4_to_ip6.h>
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/ip/reass/ip4_sv_reass.h>

enum ip6_map_next_e
{
  IP6_MAP_NEXT_IP4_LOOKUP,
#ifdef MAP_SKIP_IP6_LOOKUP
  IP6_MAP_NEXT_IP4_REWRITE,
#endif
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

enum ip6_map_post_ip4_reass_next_e
{
  IP6_MAP_POST_IP4_REASS_NEXT_IP4_LOOKUP,
  IP6_MAP_POST_IP4_REASS_NEXT_IP4_FRAGMENT,
  IP6_MAP_POST_IP4_REASS_NEXT_DROP,
  IP6_MAP_POST_IP4_REASS_N_NEXT,
};

enum ip6_icmp_relay_next_e
{
  IP6_ICMP_RELAY_NEXT_IP4_LOOKUP,
  IP6_ICMP_RELAY_NEXT_DROP,
  IP6_ICMP_RELAY_N_NEXT,
};

vlib_node_registration_t ip6_map_post_ip4_reass_node;
vlib_node_registration_t ip6_map_ip6_reass_node;
static vlib_node_registration_t ip6_map_icmp_relay_node;

typedef struct
{
  u32 map_domain_index;
  u16 port;
  u8 cached;
} map_ip6_map_ip4_reass_trace_t;

u8 *
format_ip6_map_post_ip4_reass_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  map_ip6_map_ip4_reass_trace_t *t =
    va_arg (*args, map_ip6_map_ip4_reass_trace_t *);
  return format (s, "MAP domain index: %d L4 port: %u Status: %s",
		 t->map_domain_index, clib_net_to_host_u16 (t->port),
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
ip6_map_security_check (map_domain_t * d, vlib_buffer_t * b0,
			ip4_header_t * ip4, ip6_header_t * ip6, u32 * next,
			u8 * error)
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
	      if (mm->sec_check_frag)
		{
		  vnet_buffer (b0)->ip.reass.next_index =
		    map_main.ip4_sv_reass_custom_next_index;
		  *next = IP6_MAP_NEXT_IP4_REASS;
		}
	    }
	}
    }
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
  clib_thread_index_t thread_index = vm->thread_index;

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
		ip4_map_get_domain ((ip4_address_t *) & ip40->
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
	      error0 = MAP_ERROR_FRAGMENTED;
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
		ip4_map_get_domain ((ip4_address_t *) & ip41->
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
	      error1 = MAP_ERROR_FRAGMENTED;
	    }
	  else
	    {
	      error1 = MAP_ERROR_BAD_PROTOCOL;
	    }

	  if (d0)
	    {
	      /* MAP inbound security check */
	      ip6_map_security_check (d0, p0, ip40, ip60, &next0, &error0);

	      if (PREDICT_TRUE (error0 == MAP_ERROR_NONE &&
				next0 == IP6_MAP_NEXT_IP4_LOOKUP))
		{
		  if (PREDICT_FALSE
		      (d0->mtu
		       && (clib_host_to_net_u16 (ip40->length) > d0->mtu)))
		    {
		      vnet_buffer (p0)->ip_frag.flags = 0;
		      vnet_buffer (p0)->ip_frag.next_index =
			IP_FRAG_NEXT_IP4_LOOKUP;
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
	      ip6_map_security_check (d1, p1, ip41, ip61, &next1, &error1);

	      if (PREDICT_TRUE (error1 == MAP_ERROR_NONE &&
				next1 == IP6_MAP_NEXT_IP4_LOOKUP))
		{
		  if (PREDICT_FALSE
		      (d1->mtu
		       && (clib_host_to_net_u16 (ip41->length) > d1->mtu)))
		    {
		      vnet_buffer (p1)->ip_frag.flags = 0;
		      vnet_buffer (p1)->ip_frag.next_index =
			IP_FRAG_NEXT_IP4_LOOKUP;
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
	      map_add_trace (vm, node, p0, map_domain_index0, port0);
	    }

	  if (PREDICT_FALSE (p1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      map_add_trace (vm, node, p1, map_domain_index1, port1);
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
		ip4_map_get_domain ((ip4_address_t *) & ip40->
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
	      error0 = MAP_ERROR_FRAGMENTED;
	    }
	  else
	    {
	      /* XXX: Move get_domain to ip6_get_domain lookup on source */
	      //error0 = MAP_ERROR_BAD_PROTOCOL;
	      vlib_buffer_advance (p0, -sizeof (ip6_header_t));
	      vnet_feature_next (&next0, p0);
	    }

	  if (d0)
	    {
	      /* MAP inbound security check */
	      ip6_map_security_check (d0, p0, ip40, ip60, &next0, &error0);

	      if (PREDICT_TRUE (error0 == MAP_ERROR_NONE &&
				next0 == IP6_MAP_NEXT_IP4_LOOKUP))
		{
		  if (PREDICT_FALSE
		      (d0->mtu
		       && (clib_host_to_net_u16 (ip40->length) > d0->mtu)))
		    {
		      vnet_buffer (p0)->ip_frag.flags = 0;
		      vnet_buffer (p0)->ip_frag.next_index =
			IP_FRAG_NEXT_IP4_LOOKUP;
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
	      map_add_trace (vm, node, p0, map_domain_index0, port0);
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


void
map_ip6_drop_pi (u32 pi)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_runtime_t *n =
    vlib_node_get_runtime (vm, ip6_map_ip6_reass_node.index);
  vlib_set_next_frame_buffer (vm, n, IP6_MAP_IP6_REASS_NEXT_DROP, pi);
}

/*
 * ip6_map_post_ip4_reass
 */
static uword
ip6_map_post_ip4_reass (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_post_ip4_reass_node.index);
  map_main_t *mm = &map_main;
  vlib_combined_counter_main_t *cm = mm->domain_counters;
  clib_thread_index_t thread_index = vm->thread_index;

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
	  u32 next0 = IP6_MAP_POST_IP4_REASS_NEXT_IP4_LOOKUP;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip40 = vlib_buffer_get_current (p0);
	  ip60 = ((ip6_header_t *) ip40) - 1;

	  d0 =
	    ip4_map_get_domain ((ip4_address_t *) & ip40->src_address.as_u32,
				&map_domain_index0, &error0);

	  port0 = vnet_buffer (p0)->ip.reass.l4_src_port;

	  if (PREDICT_TRUE (error0 == MAP_ERROR_NONE))
	    error0 =
	      ip6_map_sec_check (d0, port0, ip40,
				 ip60) ? MAP_ERROR_NONE :
	      MAP_ERROR_DECAP_SEC_CHECK;

	  if (PREDICT_FALSE
	      (error0 == MAP_ERROR_NONE &&
	       d0->mtu && (clib_host_to_net_u16 (ip40->length) > d0->mtu)))
	    {
	      vnet_buffer (p0)->ip_frag.flags = 0;
	      vnet_buffer (p0)->ip_frag.next_index = IP_FRAG_NEXT_IP4_LOOKUP;
	      vnet_buffer (p0)->ip_frag.mtu = d0->mtu;
	      next0 = IP6_MAP_POST_IP4_REASS_NEXT_IP4_FRAGMENT;
	    }

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      map_ip6_map_ip4_reass_trace_t *tr =
		vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->map_domain_index = map_domain_index0;
	      tr->port = port0;
	    }

	  if (error0 == MAP_ERROR_NONE)
	    vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_RX,
					     thread_index,
					     map_domain_index0, 1,
					     clib_net_to_host_u16
					     (ip40->length));
	  next0 =
	    (error0 ==
	     MAP_ERROR_NONE) ? next0 : IP6_MAP_POST_IP4_REASS_NEXT_DROP;
	  p0->error = error_node->errors[error0];
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);

	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
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
  clib_thread_index_t thread_index = vm->thread_index;
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

VNET_FEATURE_INIT (ip6_map_feature, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-map",
  .runs_before = VNET_FEATURES ("ip6-flow-classify"),
  .runs_after = VNET_FEATURES ("ip6-full-reassembly-feature"),
};

VLIB_REGISTER_NODE(ip6_map_node) = {
  .function = ip6_map,
  .name = "ip6-map",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_counters = map_error_counters,

  .n_next_nodes = IP6_MAP_N_NEXT,
  .next_nodes = {
    [IP6_MAP_NEXT_IP4_LOOKUP] = "ip4-lookup",
#ifdef MAP_SKIP_IP6_LOOKUP
    [IP6_MAP_NEXT_IP4_REWRITE] = "ip4-load-balance",
#endif
    [IP6_MAP_NEXT_IP4_REASS] = "ip4-sv-reassembly-custom-next",
    [IP6_MAP_NEXT_IP4_FRAGMENT] = "ip4-frag",
    [IP6_MAP_NEXT_IP6_ICMP_RELAY] = "ip6-map-icmp-relay",
    [IP6_MAP_NEXT_IP6_LOCAL] = "ip6-local",
    [IP6_MAP_NEXT_DROP] = "error-drop",
    [IP6_MAP_NEXT_ICMP] = "ip6-icmp-error",
  },
};

VLIB_REGISTER_NODE(ip6_map_post_ip4_reass_node) = {
  .function = ip6_map_post_ip4_reass,
  .name = "ip6-map-post-ip4-reass",
  .vector_size = sizeof(u32),
  .format_trace = format_ip6_map_post_ip4_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = MAP_N_ERROR,
  .error_counters = map_error_counters,
  .n_next_nodes = IP6_MAP_POST_IP4_REASS_N_NEXT,
  .next_nodes = {
    [IP6_MAP_POST_IP4_REASS_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IP6_MAP_POST_IP4_REASS_NEXT_IP4_FRAGMENT] = "ip4-frag",
    [IP6_MAP_POST_IP4_REASS_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE(ip6_map_icmp_relay_node, static) = {
  .function = ip6_map_icmp_relay,
  .name = "ip6-map-icmp-relay",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace, //FIXME
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = MAP_N_ERROR,
  .error_counters = map_error_counters,
  .n_next_nodes = IP6_ICMP_RELAY_N_NEXT,
  .next_nodes = {
    [IP6_ICMP_RELAY_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IP6_ICMP_RELAY_NEXT_DROP] = "error-drop",
  },
};

clib_error_t *
ip6_map_init (vlib_main_t * vm)
{
  map_main.ip4_sv_reass_custom_next_index =
    ip4_sv_reass_custom_register_next_node
    (ip6_map_post_ip4_reass_node.index);
  return 0;
}

VLIB_INIT_FUNCTION (ip6_map_init) =
{
.runs_after = VLIB_INITS ("map_init"),};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
