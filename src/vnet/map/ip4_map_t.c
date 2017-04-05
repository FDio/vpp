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

#define IP4_MAP_T_DUAL_LOOP 1

typedef enum
{
  IP4_MAPT_NEXT_MAPT_TCP_UDP,
  IP4_MAPT_NEXT_MAPT_ICMP,
  IP4_MAPT_NEXT_MAPT_FRAGMENTED,
  IP4_MAPT_NEXT_DROP,
  IP4_MAPT_N_NEXT
} ip4_mapt_next_t;

typedef enum
{
  IP4_MAPT_ICMP_NEXT_IP6_LOOKUP,
  IP4_MAPT_ICMP_NEXT_IP6_FRAG,
  IP4_MAPT_ICMP_NEXT_DROP,
  IP4_MAPT_ICMP_N_NEXT
} ip4_mapt_icmp_next_t;

typedef enum
{
  IP4_MAPT_TCP_UDP_NEXT_IP6_LOOKUP,
  IP4_MAPT_TCP_UDP_NEXT_IP6_FRAG,
  IP4_MAPT_TCP_UDP_NEXT_DROP,
  IP4_MAPT_TCP_UDP_N_NEXT
} ip4_mapt_tcp_udp_next_t;

typedef enum
{
  IP4_MAPT_FRAGMENTED_NEXT_IP6_LOOKUP,
  IP4_MAPT_FRAGMENTED_NEXT_IP6_FRAG,
  IP4_MAPT_FRAGMENTED_NEXT_DROP,
  IP4_MAPT_FRAGMENTED_N_NEXT
} ip4_mapt_fragmented_next_t;

//This is used to pass information within the buffer data.
//Buffer structure being too small to contain big structures like this.
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip6_address_t daddr;
  ip6_address_t saddr;
  //IPv6 header + Fragmentation header will be here
  //sizeof(ip6) + sizeof(ip_frag) - sizeof(ip4)
  u8 unused[28];
}) ip4_mapt_pseudo_header_t;
/* *INDENT-ON* */

#define frag_id_4to6(id) (id)

//TODO: Find the right place in memory for this.
/* *INDENT-OFF* */
static u8 icmp_to_icmp6_updater_pointer_table[] =
  { 0, 1, 4, 4, ~0,
    ~0, ~0, ~0, 7, 6,
    ~0, ~0, 8, 8, 8,
    8, 24, 24, 24, 24
  };
/* *INDENT-ON* */


static_always_inline int
ip4_map_fragment_cache (ip4_header_t * ip4, u16 port)
{
  u32 *ignore = NULL;
  map_ip4_reass_lock ();
  map_ip4_reass_t *r =
    map_ip4_reass_get (ip4->src_address.as_u32, ip4->dst_address.as_u32,
		       ip4->fragment_id,
		       (ip4->protocol ==
			IP_PROTOCOL_ICMP) ? IP_PROTOCOL_ICMP6 : ip4->protocol,
		       &ignore);
  if (r)
    r->port = port;

  map_ip4_reass_unlock ();
  return !r;
}

static_always_inline i32
ip4_map_fragment_get_port (ip4_header_t * ip4)
{
  u32 *ignore = NULL;
  map_ip4_reass_lock ();
  map_ip4_reass_t *r =
    map_ip4_reass_get (ip4->src_address.as_u32, ip4->dst_address.as_u32,
		       ip4->fragment_id,
		       (ip4->protocol ==
			IP_PROTOCOL_ICMP) ? IP_PROTOCOL_ICMP6 : ip4->protocol,
		       &ignore);
  i32 ret = r ? r->port : -1;
  map_ip4_reass_unlock ();
  return ret;
}


/* Statelessly translates an ICMP packet into ICMPv6.
 *
 * Warning: The checksum will need to be recomputed.
 *
 */
static_always_inline int
ip4_icmp_to_icmp6_in_place (icmp46_header_t * icmp, u32 icmp_len,
			    i32 * receiver_port, ip4_header_t ** inner_ip4)
{
  *inner_ip4 = NULL;
  switch (icmp->type)
    {
    case ICMP4_echo_reply:
      *receiver_port = ((u16 *) icmp)[2];
      icmp->type = ICMP6_echo_reply;
      break;
    case ICMP4_echo_request:
      *receiver_port = ((u16 *) icmp)[2];
      icmp->type = ICMP6_echo_request;
      break;
    case ICMP4_destination_unreachable:
      *inner_ip4 = (ip4_header_t *) (((u8 *) icmp) + 8);
      *receiver_port = ip4_get_port (*inner_ip4, MAP_SENDER, icmp_len - 8);

      switch (icmp->code)
	{
	case ICMP4_destination_unreachable_destination_unreachable_net:	//0
	case ICMP4_destination_unreachable_destination_unreachable_host:	//1
	  icmp->type = ICMP6_destination_unreachable;
	  icmp->code = ICMP6_destination_unreachable_no_route_to_destination;
	  break;
	case ICMP4_destination_unreachable_protocol_unreachable:	//2
	  icmp->type = ICMP6_parameter_problem;
	  icmp->code = ICMP6_parameter_problem_unrecognized_next_header;
	  break;
	case ICMP4_destination_unreachable_port_unreachable:	//3
	  icmp->type = ICMP6_destination_unreachable;
	  icmp->code = ICMP6_destination_unreachable_port_unreachable;
	  break;
	case ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set:	//4
	  icmp->type =
	    ICMP6_packet_too_big;
	  icmp->code = 0;
	  {
	    u32 advertised_mtu = clib_net_to_host_u32 (*((u32 *) (icmp + 1)));
	    if (advertised_mtu)
	      advertised_mtu += 20;
	    else
	      advertised_mtu = 1000;	//FIXME ! (RFC 1191 - plateau value)

	    //FIXME: = minimum(advertised MTU+20, MTU_of_IPv6_nexthop, (MTU_of_IPv4_nexthop)+20)
	    *((u32 *) (icmp + 1)) = clib_host_to_net_u32 (advertised_mtu);
	  }
	  break;

	case ICMP4_destination_unreachable_source_route_failed:	//5
	case ICMP4_destination_unreachable_destination_network_unknown:	//6
	case ICMP4_destination_unreachable_destination_host_unknown:	//7
	case ICMP4_destination_unreachable_source_host_isolated:	//8
	case ICMP4_destination_unreachable_network_unreachable_for_type_of_service:	//11
	case ICMP4_destination_unreachable_host_unreachable_for_type_of_service:	//12
	  icmp->type =
	    ICMP6_destination_unreachable;
	  icmp->code = ICMP6_destination_unreachable_no_route_to_destination;
	  break;
	case ICMP4_destination_unreachable_network_administratively_prohibited:	//9
	case ICMP4_destination_unreachable_host_administratively_prohibited:	//10
	case ICMP4_destination_unreachable_communication_administratively_prohibited:	//13
	case ICMP4_destination_unreachable_precedence_cutoff_in_effect:	//15
	  icmp->type = ICMP6_destination_unreachable;
	  icmp->code =
	    ICMP6_destination_unreachable_destination_administratively_prohibited;
	  break;
	case ICMP4_destination_unreachable_host_precedence_violation:	//14
	default:
	  return -1;
	}
      break;

    case ICMP4_time_exceeded:	//11
      *inner_ip4 = (ip4_header_t *) (((u8 *) icmp) + 8);
      *receiver_port = ip4_get_port (*inner_ip4, MAP_SENDER, icmp_len - 8);
      icmp->type = ICMP6_time_exceeded;
      //icmp->code = icmp->code //unchanged
      break;

    case ICMP4_parameter_problem:
      *inner_ip4 = (ip4_header_t *) (((u8 *) icmp) + 8);
      *receiver_port = ip4_get_port (*inner_ip4, MAP_SENDER, icmp_len - 8);

      switch (icmp->code)
	{
	case ICMP4_parameter_problem_pointer_indicates_error:
	case ICMP4_parameter_problem_bad_length:
	  icmp->type = ICMP6_parameter_problem;
	  icmp->code = ICMP6_parameter_problem_erroneous_header_field;
	  {
	    u8 ptr =
	      icmp_to_icmp6_updater_pointer_table[*((u8 *) (icmp + 1))];
	    if (ptr == 0xff)
	      return -1;

	    *((u32 *) (icmp + 1)) = clib_host_to_net_u32 (ptr);
	  }
	  break;
	default:
	  //All other codes cause dropping the packet
	  return -1;
	}
      break;

    default:
      //All other types cause dropping the packet
      return -1;
      break;
    }
  return 0;
}

static_always_inline void
_ip4_map_t_icmp (map_domain_t * d, vlib_buffer_t * p, u8 * error)
{
  ip4_header_t *ip4, *inner_ip4;
  ip6_header_t *ip6, *inner_ip6;
  u32 ip_len;
  icmp46_header_t *icmp;
  i32 recv_port;
  ip_csum_t csum;
  u16 *inner_L4_checksum = 0;
  ip6_frag_hdr_t *inner_frag;
  u32 inner_frag_id;
  u32 inner_frag_offset;
  u8 inner_frag_more;

  ip4 = vlib_buffer_get_current (p);
  ip_len = clib_net_to_host_u16 (ip4->length);
  ASSERT (ip_len <= p->current_length);

  icmp = (icmp46_header_t *) (ip4 + 1);
  if (ip4_icmp_to_icmp6_in_place (icmp, ip_len - sizeof (*ip4),
				  &recv_port, &inner_ip4))
    {
      *error = MAP_ERROR_ICMP;
      return;
    }

  if (recv_port < 0)
    {
      // In case of 1:1 mapping, we don't care about the port
      if (d->ea_bits_len == 0 && d->rules)
	{
	  recv_port = 0;
	}
      else
	{
	  *error = MAP_ERROR_ICMP;
	  return;
	}
    }

  if (inner_ip4)
    {
      //We have 2 headers to translate.
      //We need to make some room in the middle of the packet

      if (PREDICT_FALSE (ip4_is_fragment (inner_ip4)))
	{
	  //Here it starts getting really tricky
	  //We will add a fragmentation header in the inner packet

	  if (!ip4_is_first_fragment (inner_ip4))
	    {
	      //For now we do not handle unless it is the first fragment
	      //Ideally we should handle the case as we are in slow path already
	      *error = MAP_ERROR_FRAGMENTED;
	      return;
	    }

	  vlib_buffer_advance (p,
			       -2 * (sizeof (*ip6) - sizeof (*ip4)) -
			       sizeof (*inner_frag));
	  ip6 = vlib_buffer_get_current (p);
	  clib_memcpy (u8_ptr_add (ip6, sizeof (*ip6) - sizeof (*ip4)), ip4,
		       20 + 8);
	  ip4 =
	    (ip4_header_t *) u8_ptr_add (ip6, sizeof (*ip6) - sizeof (*ip4));
	  icmp = (icmp46_header_t *) (ip4 + 1);

	  inner_ip6 =
	    (ip6_header_t *) u8_ptr_add (inner_ip4,
					 sizeof (*ip4) - sizeof (*ip6) -
					 sizeof (*inner_frag));
	  inner_frag =
	    (ip6_frag_hdr_t *) u8_ptr_add (inner_ip6, sizeof (*inner_ip6));
	  ip6->payload_length =
	    u16_net_add (ip4->length,
			 sizeof (*ip6) - 2 * sizeof (*ip4) +
			 sizeof (*inner_frag));
	  inner_frag_id = frag_id_4to6 (inner_ip4->fragment_id);
	  inner_frag_offset = ip4_get_fragment_offset (inner_ip4);
	  inner_frag_more =
	    ! !(inner_ip4->flags_and_fragment_offset &
		clib_net_to_host_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS));
	}
      else
	{
	  vlib_buffer_advance (p, -2 * (sizeof (*ip6) - sizeof (*ip4)));
	  ip6 = vlib_buffer_get_current (p);
	  clib_memcpy (u8_ptr_add (ip6, sizeof (*ip6) - sizeof (*ip4)), ip4,
		       20 + 8);
	  ip4 =
	    (ip4_header_t *) u8_ptr_add (ip6, sizeof (*ip6) - sizeof (*ip4));
	  icmp = (icmp46_header_t *) u8_ptr_add (ip4, sizeof (*ip4));
	  inner_ip6 =
	    (ip6_header_t *) u8_ptr_add (inner_ip4,
					 sizeof (*ip4) - sizeof (*ip6));
	  ip6->payload_length =
	    u16_net_add (ip4->length, sizeof (*ip6) - 2 * sizeof (*ip4));
	  inner_frag = NULL;
	}

      if (PREDICT_TRUE (inner_ip4->protocol == IP_PROTOCOL_TCP))
	{
	  inner_L4_checksum = &((tcp_header_t *) (inner_ip4 + 1))->checksum;
	  *inner_L4_checksum =
	    ip_csum_fold (ip_csum_sub_even
			  (*inner_L4_checksum,
			   *((u64 *) (&inner_ip4->src_address))));
	}
      else if (PREDICT_TRUE (inner_ip4->protocol == IP_PROTOCOL_UDP))
	{
	  inner_L4_checksum = &((udp_header_t *) (inner_ip4 + 1))->checksum;
	  if (!*inner_L4_checksum)
	    {
	      //The inner packet was first translated, and therefore came from IPv6.
	      //As the packet was an IPv6 packet, the UDP checksum can't be NULL
	      *error = MAP_ERROR_ICMP;
	      return;
	    }
	  *inner_L4_checksum =
	    ip_csum_fold (ip_csum_sub_even
			  (*inner_L4_checksum,
			   *((u64 *) (&inner_ip4->src_address))));
	}
      else if (inner_ip4->protocol == IP_PROTOCOL_ICMP)
	{
	  //We have an ICMP inside an ICMP
	  //It needs to be translated, but not for error ICMP messages
	  icmp46_header_t *inner_icmp = (icmp46_header_t *) (inner_ip4 + 1);
	  csum = inner_icmp->checksum;
	  //Only types ICMP4_echo_request and ICMP4_echo_reply are handled by ip4_icmp_to_icmp6_in_place
	  csum = ip_csum_sub_even (csum, *((u16 *) inner_icmp));
	  inner_icmp->type = (inner_icmp->type == ICMP4_echo_request) ?
	    ICMP6_echo_request : ICMP6_echo_reply;
	  csum = ip_csum_add_even (csum, *((u16 *) inner_icmp));
	  csum =
	    ip_csum_add_even (csum, clib_host_to_net_u16 (IP_PROTOCOL_ICMP6));
	  csum =
	    ip_csum_add_even (csum, inner_ip4->length - sizeof (*inner_ip4));
	  inner_icmp->checksum = ip_csum_fold (csum);
	  inner_L4_checksum = &inner_icmp->checksum;
	  inner_ip4->protocol = IP_PROTOCOL_ICMP6;
	}
      else
	{
	  /* To shut up Coverity */
	  os_panic ();
	}

      //FIXME: Security check with the port found in the inner packet

      csum = *inner_L4_checksum;	//Initial checksum of the inner L4 header
      //FIXME: Shouldn't we remove ip addresses from there ?

      inner_ip6->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 ((6 << 28) + (inner_ip4->tos << 20));
      inner_ip6->payload_length =
	u16_net_add (inner_ip4->length, -sizeof (*inner_ip4));
      inner_ip6->hop_limit = inner_ip4->ttl;
      inner_ip6->protocol = inner_ip4->protocol;

      //Note that the source address is within the domain
      //while the destination address is the one outside the domain
      ip4_map_t_embedded_address (d, &inner_ip6->dst_address,
				  &inner_ip4->dst_address);
      inner_ip6->src_address.as_u64[0] =
	map_get_pfx_net (d, inner_ip4->src_address.as_u32, recv_port);
      inner_ip6->src_address.as_u64[1] =
	map_get_sfx_net (d, inner_ip4->src_address.as_u32, recv_port);

      if (PREDICT_FALSE (inner_frag != NULL))
	{
	  inner_frag->next_hdr = inner_ip6->protocol;
	  inner_frag->identification = inner_frag_id;
	  inner_frag->rsv = 0;
	  inner_frag->fragment_offset_and_more =
	    ip6_frag_hdr_offset_and_more (inner_frag_offset, inner_frag_more);
	  inner_ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
	  inner_ip6->payload_length =
	    clib_host_to_net_u16 (clib_net_to_host_u16
				  (inner_ip6->payload_length) +
				  sizeof (*inner_frag));
	}

      csum = ip_csum_add_even (csum, inner_ip6->src_address.as_u64[0]);
      csum = ip_csum_add_even (csum, inner_ip6->src_address.as_u64[1]);
      csum = ip_csum_add_even (csum, inner_ip6->dst_address.as_u64[0]);
      csum = ip_csum_add_even (csum, inner_ip6->dst_address.as_u64[1]);
      *inner_L4_checksum = ip_csum_fold (csum);

    }
  else
    {
      vlib_buffer_advance (p, sizeof (*ip4) - sizeof (*ip6));
      ip6 = vlib_buffer_get_current (p);
      ip6->payload_length =
	clib_host_to_net_u16 (clib_net_to_host_u16 (ip4->length) -
			      sizeof (*ip4));
    }

  //Translate outer IPv6
  ip6->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 ((6 << 28) + (ip4->tos << 20));

  ip6->hop_limit = ip4->ttl;
  ip6->protocol = IP_PROTOCOL_ICMP6;

  ip4_map_t_embedded_address (d, &ip6->src_address, &ip4->src_address);
  ip6->dst_address.as_u64[0] =
    map_get_pfx_net (d, ip4->dst_address.as_u32, recv_port);
  ip6->dst_address.as_u64[1] =
    map_get_sfx_net (d, ip4->dst_address.as_u32, recv_port);

  //Truncate when the packet exceeds the minimal IPv6 MTU
  if (p->current_length > 1280)
    {
      ip6->payload_length = clib_host_to_net_u16 (1280 - sizeof (*ip6));
      p->current_length = 1280;	//Looks too simple to be correct...
    }

  //TODO: We could do an easy diff-checksum for echo requests/replies
  //Recompute ICMP checksum
  icmp->checksum = 0;
  csum = ip_csum_with_carry (0, ip6->payload_length);
  csum = ip_csum_with_carry (csum, clib_host_to_net_u16 (ip6->protocol));
  csum = ip_csum_with_carry (csum, ip6->src_address.as_u64[0]);
  csum = ip_csum_with_carry (csum, ip6->src_address.as_u64[1]);
  csum = ip_csum_with_carry (csum, ip6->dst_address.as_u64[0]);
  csum = ip_csum_with_carry (csum, ip6->dst_address.as_u64[1]);
  csum =
    ip_incremental_checksum (csum, icmp,
			     clib_net_to_host_u16 (ip6->payload_length));
  icmp->checksum = ~ip_csum_fold (csum);
}

static uword
ip4_map_t_icmp (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_map_t_icmp_node.index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  vlib_combined_counter_main_t *cm = map_main.domain_counters;
  u32 thread_index = vlib_get_thread_index ();

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  ip4_mapt_icmp_next_t next0;
	  u8 error0;
	  map_domain_t *d0;
	  u16 len0;

	  next0 = IP4_MAPT_ICMP_NEXT_IP6_LOOKUP;
	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  error0 = MAP_ERROR_NONE;

	  p0 = vlib_get_buffer (vm, pi0);
	  vlib_buffer_advance (p0, sizeof (ip4_mapt_pseudo_header_t));	//The pseudo-header is not used
	  len0 =
	    clib_net_to_host_u16 (((ip4_header_t *)
				   vlib_buffer_get_current (p0))->length);
	  d0 =
	    pool_elt_at_index (map_main.domains,
			       vnet_buffer (p0)->map_t.map_domain_index);
	  _ip4_map_t_icmp (d0, p0, &error0);

	  if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
	    {
	      vnet_buffer (p0)->ip_frag.header_offset = 0;
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.next_index = IP6_FRAG_NEXT_IP6_LOOKUP;
	      next0 = IP4_MAPT_ICMP_NEXT_IP6_FRAG;
	    }
	  if (PREDICT_TRUE (error0 == MAP_ERROR_NONE))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_TX,
					       thread_index,
					       vnet_buffer (p0)->map_t.
					       map_domain_index, 1, len0);
	    }
	  else
	    {
	      next0 = IP4_MAPT_ICMP_NEXT_DROP;
	    }
	  p0->error = error_node->errors[error0];
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, pi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

static uword
ip4_map_t_fragmented (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  ip6_frag_hdr_t *frag0;
	  ip4_mapt_pseudo_header_t *pheader0;
	  ip4_mapt_fragmented_next_t next0;

	  next0 = IP4_MAPT_FRAGMENTED_NEXT_IP6_LOOKUP;
	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);

	  //Accessing pseudo header
	  pheader0 = vlib_buffer_get_current (p0);
	  vlib_buffer_advance (p0, sizeof (*pheader0));

	  //Accessing ip4 header
	  ip40 = vlib_buffer_get_current (p0);
	  frag0 =
	    (ip6_frag_hdr_t *) u8_ptr_add (ip40,
					   sizeof (*ip40) - sizeof (*frag0));
	  ip60 =
	    (ip6_header_t *) u8_ptr_add (ip40,
					 sizeof (*ip40) - sizeof (*frag0) -
					 sizeof (*ip60));
	  vlib_buffer_advance (p0,
			       sizeof (*ip40) - sizeof (*ip60) -
			       sizeof (*frag0));

	  //We know that the protocol was one of ICMP, TCP or UDP
	  //because the first fragment was found and cached
	  frag0->next_hdr =
	    (ip40->protocol ==
	     IP_PROTOCOL_ICMP) ? IP_PROTOCOL_ICMP6 : ip40->protocol;
	  frag0->identification = frag_id_4to6 (ip40->fragment_id);
	  frag0->rsv = 0;
	  frag0->fragment_offset_and_more =
	    ip6_frag_hdr_offset_and_more (ip4_get_fragment_offset (ip40),
					  clib_net_to_host_u16
					  (ip40->flags_and_fragment_offset) &
					  IP4_HEADER_FLAG_MORE_FRAGMENTS);

	  ip60->ip_version_traffic_class_and_flow_label =
	    clib_host_to_net_u32 ((6 << 28) + (ip40->tos << 20));
	  ip60->payload_length =
	    clib_host_to_net_u16 (clib_net_to_host_u16 (ip40->length) -
				  sizeof (*ip40) + sizeof (*frag0));
	  ip60->hop_limit = ip40->ttl;
	  ip60->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
	  ip60->dst_address.as_u64[0] = pheader0->daddr.as_u64[0];
	  ip60->dst_address.as_u64[1] = pheader0->daddr.as_u64[1];
	  ip60->src_address.as_u64[0] = pheader0->saddr.as_u64[0];
	  ip60->src_address.as_u64[1] = pheader0->saddr.as_u64[1];

	  if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
	    {
	      vnet_buffer (p0)->ip_frag.header_offset = 0;
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.next_index = IP6_FRAG_NEXT_IP6_LOOKUP;
	      next0 = IP4_MAPT_FRAGMENTED_NEXT_IP6_FRAG;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, pi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

static uword
ip4_map_t_tcp_udp (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

#ifdef IP4_MAP_T_DUAL_LOOP
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 pi0, pi1;
	  vlib_buffer_t *p0, *p1;
	  ip4_header_t *ip40, *ip41;
	  ip6_header_t *ip60, *ip61;
	  ip_csum_t csum0, csum1;
	  u16 *checksum0, *checksum1;
	  ip6_frag_hdr_t *frag0, *frag1;
	  u32 frag_id0, frag_id1;
	  ip4_mapt_pseudo_header_t *pheader0, *pheader1;
	  ip4_mapt_tcp_udp_next_t next0, next1;

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  next0 = IP4_MAPT_TCP_UDP_NEXT_IP6_LOOKUP;
	  next1 = IP4_MAPT_TCP_UDP_NEXT_IP6_LOOKUP;
	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  //Accessing pseudo header
	  pheader0 = vlib_buffer_get_current (p0);
	  pheader1 = vlib_buffer_get_current (p1);
	  vlib_buffer_advance (p0, sizeof (*pheader0));
	  vlib_buffer_advance (p1, sizeof (*pheader1));

	  //Accessing ip4 header
	  ip40 = vlib_buffer_get_current (p0);
	  ip41 = vlib_buffer_get_current (p1);
	  checksum0 =
	    (u16 *) u8_ptr_add (ip40,
				vnet_buffer (p0)->map_t.checksum_offset);
	  checksum1 =
	    (u16 *) u8_ptr_add (ip41,
				vnet_buffer (p1)->map_t.checksum_offset);

	  //UDP checksum is optional over IPv4 but mandatory for IPv6
	  //We do not check udp->length sanity but use our safe computed value instead
	  if (PREDICT_FALSE
	      (!*checksum0 && ip40->protocol == IP_PROTOCOL_UDP))
	    {
	      u16 udp_len =
		clib_host_to_net_u16 (ip40->length) - sizeof (*ip40);
	      udp_header_t *udp =
		(udp_header_t *) u8_ptr_add (ip40, sizeof (*ip40));
	      ip_csum_t csum;
	      csum = ip_incremental_checksum (0, udp, udp_len);
	      csum =
		ip_csum_with_carry (csum, clib_host_to_net_u16 (udp_len));
	      csum =
		ip_csum_with_carry (csum,
				    clib_host_to_net_u16 (IP_PROTOCOL_UDP));
	      csum =
		ip_csum_with_carry (csum, *((u64 *) (&ip40->src_address)));
	      *checksum0 = ~ip_csum_fold (csum);
	    }
	  if (PREDICT_FALSE
	      (!*checksum1 && ip41->protocol == IP_PROTOCOL_UDP))
	    {
	      u16 udp_len =
		clib_host_to_net_u16 (ip41->length) - sizeof (*ip40);
	      udp_header_t *udp =
		(udp_header_t *) u8_ptr_add (ip41, sizeof (*ip40));
	      ip_csum_t csum;
	      csum = ip_incremental_checksum (0, udp, udp_len);
	      csum =
		ip_csum_with_carry (csum, clib_host_to_net_u16 (udp_len));
	      csum =
		ip_csum_with_carry (csum,
				    clib_host_to_net_u16 (IP_PROTOCOL_UDP));
	      csum =
		ip_csum_with_carry (csum, *((u64 *) (&ip41->src_address)));
	      *checksum1 = ~ip_csum_fold (csum);
	    }

	  csum0 = ip_csum_sub_even (*checksum0, ip40->src_address.as_u32);
	  csum1 = ip_csum_sub_even (*checksum1, ip41->src_address.as_u32);
	  csum0 = ip_csum_sub_even (csum0, ip40->dst_address.as_u32);
	  csum1 = ip_csum_sub_even (csum1, ip41->dst_address.as_u32);

	  // Deal with fragmented packets
	  if (PREDICT_FALSE (ip40->flags_and_fragment_offset &
			     clib_host_to_net_u16
			     (IP4_HEADER_FLAG_MORE_FRAGMENTS)))
	    {
	      ip60 =
		(ip6_header_t *) u8_ptr_add (ip40,
					     sizeof (*ip40) - sizeof (*ip60) -
					     sizeof (*frag0));
	      frag0 =
		(ip6_frag_hdr_t *) u8_ptr_add (ip40,
					       sizeof (*ip40) -
					       sizeof (*frag0));
	      frag_id0 = frag_id_4to6 (ip40->fragment_id);
	      vlib_buffer_advance (p0,
				   sizeof (*ip40) - sizeof (*ip60) -
				   sizeof (*frag0));
	    }
	  else
	    {
	      ip60 =
		(ip6_header_t *) (((u8 *) ip40) + sizeof (*ip40) -
				  sizeof (*ip60));
	      vlib_buffer_advance (p0, sizeof (*ip40) - sizeof (*ip60));
	      frag0 = NULL;
	    }

	  if (PREDICT_FALSE (ip41->flags_and_fragment_offset &
			     clib_host_to_net_u16
			     (IP4_HEADER_FLAG_MORE_FRAGMENTS)))
	    {
	      ip61 =
		(ip6_header_t *) u8_ptr_add (ip41,
					     sizeof (*ip40) - sizeof (*ip60) -
					     sizeof (*frag0));
	      frag1 =
		(ip6_frag_hdr_t *) u8_ptr_add (ip41,
					       sizeof (*ip40) -
					       sizeof (*frag0));
	      frag_id1 = frag_id_4to6 (ip41->fragment_id);
	      vlib_buffer_advance (p1,
				   sizeof (*ip40) - sizeof (*ip60) -
				   sizeof (*frag0));
	    }
	  else
	    {
	      ip61 =
		(ip6_header_t *) (((u8 *) ip41) + sizeof (*ip40) -
				  sizeof (*ip60));
	      vlib_buffer_advance (p1, sizeof (*ip40) - sizeof (*ip60));
	      frag1 = NULL;
	    }

	  ip60->ip_version_traffic_class_and_flow_label =
	    clib_host_to_net_u32 ((6 << 28) + (ip40->tos << 20));
	  ip61->ip_version_traffic_class_and_flow_label =
	    clib_host_to_net_u32 ((6 << 28) + (ip41->tos << 20));
	  ip60->payload_length = u16_net_add (ip40->length, -sizeof (*ip40));
	  ip61->payload_length = u16_net_add (ip41->length, -sizeof (*ip40));
	  ip60->hop_limit = ip40->ttl;
	  ip61->hop_limit = ip41->ttl;
	  ip60->protocol = ip40->protocol;
	  ip61->protocol = ip41->protocol;

	  if (PREDICT_FALSE (frag0 != NULL))
	    {
	      frag0->next_hdr = ip60->protocol;
	      frag0->identification = frag_id0;
	      frag0->rsv = 0;
	      frag0->fragment_offset_and_more =
		ip6_frag_hdr_offset_and_more (0, 1);
	      ip60->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
	      ip60->payload_length =
		u16_net_add (ip60->payload_length, sizeof (*frag0));
	    }

	  if (PREDICT_FALSE (frag1 != NULL))
	    {
	      frag1->next_hdr = ip61->protocol;
	      frag1->identification = frag_id1;
	      frag1->rsv = 0;
	      frag1->fragment_offset_and_more =
		ip6_frag_hdr_offset_and_more (0, 1);
	      ip61->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
	      ip61->payload_length =
		u16_net_add (ip61->payload_length, sizeof (*frag0));
	    }

	  //Finally copying the address
	  ip60->dst_address.as_u64[0] = pheader0->daddr.as_u64[0];
	  ip61->dst_address.as_u64[0] = pheader1->daddr.as_u64[0];
	  ip60->dst_address.as_u64[1] = pheader0->daddr.as_u64[1];
	  ip61->dst_address.as_u64[1] = pheader1->daddr.as_u64[1];
	  ip60->src_address.as_u64[0] = pheader0->saddr.as_u64[0];
	  ip61->src_address.as_u64[0] = pheader1->saddr.as_u64[0];
	  ip60->src_address.as_u64[1] = pheader0->saddr.as_u64[1];
	  ip61->src_address.as_u64[1] = pheader1->saddr.as_u64[1];

	  csum0 = ip_csum_add_even (csum0, ip60->src_address.as_u64[0]);
	  csum1 = ip_csum_add_even (csum1, ip61->src_address.as_u64[0]);
	  csum0 = ip_csum_add_even (csum0, ip60->src_address.as_u64[1]);
	  csum1 = ip_csum_add_even (csum1, ip61->src_address.as_u64[1]);
	  csum0 = ip_csum_add_even (csum0, ip60->dst_address.as_u64[0]);
	  csum1 = ip_csum_add_even (csum1, ip61->dst_address.as_u64[0]);
	  csum0 = ip_csum_add_even (csum0, ip60->dst_address.as_u64[1]);
	  csum1 = ip_csum_add_even (csum1, ip61->dst_address.as_u64[1]);
	  *checksum0 = ip_csum_fold (csum0);
	  *checksum1 = ip_csum_fold (csum1);

	  if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
	    {
	      vnet_buffer (p0)->ip_frag.header_offset = 0;
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.next_index = IP6_FRAG_NEXT_IP6_LOOKUP;
	      next0 = IP4_MAPT_TCP_UDP_NEXT_IP6_FRAG;
	    }

	  if (vnet_buffer (p1)->map_t.mtu < p1->current_length)
	    {
	      vnet_buffer (p1)->ip_frag.header_offset = 0;
	      vnet_buffer (p1)->ip_frag.mtu = vnet_buffer (p1)->map_t.mtu;
	      vnet_buffer (p1)->ip_frag.next_index = IP6_FRAG_NEXT_IP6_LOOKUP;
	      next1 = IP4_MAPT_TCP_UDP_NEXT_IP6_FRAG;
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next, pi0, pi1,
					   next0, next1);
	}
#endif

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  ip_csum_t csum0;
	  u16 *checksum0;
	  ip6_frag_hdr_t *frag0;
	  u32 frag_id0;
	  ip4_mapt_pseudo_header_t *pheader0;
	  ip4_mapt_tcp_udp_next_t next0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  next0 = IP4_MAPT_TCP_UDP_NEXT_IP6_LOOKUP;
	  p0 = vlib_get_buffer (vm, pi0);

	  //Accessing pseudo header
	  pheader0 = vlib_buffer_get_current (p0);
	  vlib_buffer_advance (p0, sizeof (*pheader0));

	  //Accessing ip4 header
	  ip40 = vlib_buffer_get_current (p0);
	  checksum0 =
	    (u16 *) u8_ptr_add (ip40,
				vnet_buffer (p0)->map_t.checksum_offset);

	  //UDP checksum is optional over IPv4 but mandatory for IPv6
	  //We do not check udp->length sanity but use our safe computed value instead
	  if (PREDICT_FALSE
	      (!*checksum0 && ip40->protocol == IP_PROTOCOL_UDP))
	    {
	      u16 udp_len =
		clib_host_to_net_u16 (ip40->length) - sizeof (*ip40);
	      udp_header_t *udp =
		(udp_header_t *) u8_ptr_add (ip40, sizeof (*ip40));
	      ip_csum_t csum;
	      csum = ip_incremental_checksum (0, udp, udp_len);
	      csum =
		ip_csum_with_carry (csum, clib_host_to_net_u16 (udp_len));
	      csum =
		ip_csum_with_carry (csum,
				    clib_host_to_net_u16 (IP_PROTOCOL_UDP));
	      csum =
		ip_csum_with_carry (csum, *((u64 *) (&ip40->src_address)));
	      *checksum0 = ~ip_csum_fold (csum);
	    }

	  csum0 = ip_csum_sub_even (*checksum0, ip40->src_address.as_u32);
	  csum0 = ip_csum_sub_even (csum0, ip40->dst_address.as_u32);

	  // Deal with fragmented packets
	  if (PREDICT_FALSE (ip40->flags_and_fragment_offset &
			     clib_host_to_net_u16
			     (IP4_HEADER_FLAG_MORE_FRAGMENTS)))
	    {
	      ip60 =
		(ip6_header_t *) u8_ptr_add (ip40,
					     sizeof (*ip40) - sizeof (*ip60) -
					     sizeof (*frag0));
	      frag0 =
		(ip6_frag_hdr_t *) u8_ptr_add (ip40,
					       sizeof (*ip40) -
					       sizeof (*frag0));
	      frag_id0 = frag_id_4to6 (ip40->fragment_id);
	      vlib_buffer_advance (p0,
				   sizeof (*ip40) - sizeof (*ip60) -
				   sizeof (*frag0));
	    }
	  else
	    {
	      ip60 =
		(ip6_header_t *) (((u8 *) ip40) + sizeof (*ip40) -
				  sizeof (*ip60));
	      vlib_buffer_advance (p0, sizeof (*ip40) - sizeof (*ip60));
	      frag0 = NULL;
	    }

	  ip60->ip_version_traffic_class_and_flow_label =
	    clib_host_to_net_u32 ((6 << 28) + (ip40->tos << 20));
	  ip60->payload_length = u16_net_add (ip40->length, -sizeof (*ip40));
	  ip60->hop_limit = ip40->ttl;
	  ip60->protocol = ip40->protocol;

	  if (PREDICT_FALSE (frag0 != NULL))
	    {
	      frag0->next_hdr = ip60->protocol;
	      frag0->identification = frag_id0;
	      frag0->rsv = 0;
	      frag0->fragment_offset_and_more =
		ip6_frag_hdr_offset_and_more (0, 1);
	      ip60->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
	      ip60->payload_length =
		u16_net_add (ip60->payload_length, sizeof (*frag0));
	    }

	  //Finally copying the address
	  ip60->dst_address.as_u64[0] = pheader0->daddr.as_u64[0];
	  ip60->dst_address.as_u64[1] = pheader0->daddr.as_u64[1];
	  ip60->src_address.as_u64[0] = pheader0->saddr.as_u64[0];
	  ip60->src_address.as_u64[1] = pheader0->saddr.as_u64[1];

	  csum0 = ip_csum_add_even (csum0, ip60->src_address.as_u64[0]);
	  csum0 = ip_csum_add_even (csum0, ip60->src_address.as_u64[1]);
	  csum0 = ip_csum_add_even (csum0, ip60->dst_address.as_u64[0]);
	  csum0 = ip_csum_add_even (csum0, ip60->dst_address.as_u64[1]);
	  *checksum0 = ip_csum_fold (csum0);

	  if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
	    {
	      //Send to fragmentation node if necessary
	      vnet_buffer (p0)->ip_frag.header_offset = 0;
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.next_index = IP6_FRAG_NEXT_IP6_LOOKUP;
	      next0 = IP4_MAPT_TCP_UDP_NEXT_IP6_FRAG;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, pi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static_always_inline void
ip4_map_t_classify (vlib_buffer_t * p0, map_domain_t * d0,
		    ip4_header_t * ip40, u16 ip4_len0, i32 * dst_port0,
		    u8 * error0, ip4_mapt_next_t * next0)
{
  if (PREDICT_FALSE (ip4_get_fragment_offset (ip40)))
    {
      *next0 = IP4_MAPT_NEXT_MAPT_FRAGMENTED;
      if (d0->ea_bits_len == 0 && d0->rules)
	{
	  *dst_port0 = 0;
	}
      else
	{
	  *dst_port0 = ip4_map_fragment_get_port (ip40);
	  *error0 = (*dst_port0 == -1) ? MAP_ERROR_FRAGMENT_MEMORY : *error0;
	}
    }
  else if (PREDICT_TRUE (ip40->protocol == IP_PROTOCOL_TCP))
    {
      vnet_buffer (p0)->map_t.checksum_offset = 36;
      *next0 = IP4_MAPT_NEXT_MAPT_TCP_UDP;
      *error0 = ip4_len0 < 40 ? MAP_ERROR_MALFORMED : *error0;
      *dst_port0 = (i32) * ((u16 *) u8_ptr_add (ip40, sizeof (*ip40) + 2));
    }
  else if (PREDICT_TRUE (ip40->protocol == IP_PROTOCOL_UDP))
    {
      vnet_buffer (p0)->map_t.checksum_offset = 26;
      *next0 = IP4_MAPT_NEXT_MAPT_TCP_UDP;
      *error0 = ip4_len0 < 28 ? MAP_ERROR_MALFORMED : *error0;
      *dst_port0 = (i32) * ((u16 *) u8_ptr_add (ip40, sizeof (*ip40) + 2));
    }
  else if (ip40->protocol == IP_PROTOCOL_ICMP)
    {
      *next0 = IP4_MAPT_NEXT_MAPT_ICMP;
      if (d0->ea_bits_len == 0 && d0->rules)
	*dst_port0 = 0;
      else if (((icmp46_header_t *) u8_ptr_add (ip40, sizeof (*ip40)))->code
	       == ICMP4_echo_reply
	       || ((icmp46_header_t *)
		   u8_ptr_add (ip40,
			       sizeof (*ip40)))->code == ICMP4_echo_request)
	*dst_port0 = (i32) * ((u16 *) u8_ptr_add (ip40, sizeof (*ip40) + 6));
    }
  else
    {
      *error0 = MAP_ERROR_BAD_PROTOCOL;
    }
}

static uword
ip4_map_t (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_map_t_node.index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  vlib_combined_counter_main_t *cm = map_main.domain_counters;
  u32 thread_index = vlib_get_thread_index ();

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

#ifdef IP4_MAP_T_DUAL_LOOP
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 pi0, pi1;
	  vlib_buffer_t *p0, *p1;
	  ip4_header_t *ip40, *ip41;
	  map_domain_t *d0, *d1;
	  ip4_mapt_next_t next0 = 0, next1 = 0;
	  u16 ip4_len0, ip4_len1;
	  u8 error0, error1;
	  i32 dst_port0, dst_port1;
	  ip4_mapt_pseudo_header_t *pheader0, *pheader1;

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  error0 = MAP_ERROR_NONE;
	  error1 = MAP_ERROR_NONE;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);
	  ip40 = vlib_buffer_get_current (p0);
	  ip41 = vlib_buffer_get_current (p1);
	  ip4_len0 = clib_host_to_net_u16 (ip40->length);
	  ip4_len1 = clib_host_to_net_u16 (ip41->length);

	  if (PREDICT_FALSE (p0->current_length < ip4_len0 ||
			     ip40->ip_version_and_header_length != 0x45))
	    {
	      error0 = MAP_ERROR_UNKNOWN;
	      next0 = IP4_MAPT_NEXT_DROP;
	    }

	  if (PREDICT_FALSE (p1->current_length < ip4_len1 ||
			     ip41->ip_version_and_header_length != 0x45))
	    {
	      error1 = MAP_ERROR_UNKNOWN;
	      next1 = IP4_MAPT_NEXT_DROP;
	    }

	  vnet_buffer (p0)->map_t.map_domain_index =
	    vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	  d0 = ip4_map_get_domain (vnet_buffer (p0)->map_t.map_domain_index);
	  vnet_buffer (p1)->map_t.map_domain_index =
	    vnet_buffer (p1)->ip.adj_index[VLIB_TX];
	  d1 = ip4_map_get_domain (vnet_buffer (p1)->map_t.map_domain_index);

	  vnet_buffer (p0)->map_t.mtu = d0->mtu ? d0->mtu : ~0;
	  vnet_buffer (p1)->map_t.mtu = d1->mtu ? d1->mtu : ~0;

	  dst_port0 = -1;
	  dst_port1 = -1;

	  ip4_map_t_classify (p0, d0, ip40, ip4_len0, &dst_port0, &error0,
			      &next0);
	  ip4_map_t_classify (p1, d1, ip41, ip4_len1, &dst_port1, &error1,
			      &next1);

	  //Add MAP-T pseudo header in front of the packet
	  vlib_buffer_advance (p0, -sizeof (*pheader0));
	  vlib_buffer_advance (p1, -sizeof (*pheader1));
	  pheader0 = vlib_buffer_get_current (p0);
	  pheader1 = vlib_buffer_get_current (p1);

	  //Save addresses within the packet
	  ip4_map_t_embedded_address (d0, &pheader0->saddr,
				      &ip40->src_address);
	  ip4_map_t_embedded_address (d1, &pheader1->saddr,
				      &ip41->src_address);
	  pheader0->daddr.as_u64[0] =
	    map_get_pfx_net (d0, ip40->dst_address.as_u32, (u16) dst_port0);
	  pheader0->daddr.as_u64[1] =
	    map_get_sfx_net (d0, ip40->dst_address.as_u32, (u16) dst_port0);
	  pheader1->daddr.as_u64[0] =
	    map_get_pfx_net (d1, ip41->dst_address.as_u32, (u16) dst_port1);
	  pheader1->daddr.as_u64[1] =
	    map_get_sfx_net (d1, ip41->dst_address.as_u32, (u16) dst_port1);

	  if (PREDICT_FALSE
	      (ip4_is_first_fragment (ip40) && (dst_port0 != -1)
	       && (d0->ea_bits_len != 0 || !d0->rules)
	       && ip4_map_fragment_cache (ip40, dst_port0)))
	    {
	      error0 = MAP_ERROR_FRAGMENT_MEMORY;
	    }

	  if (PREDICT_FALSE
	      (ip4_is_first_fragment (ip41) && (dst_port1 != -1)
	       && (d1->ea_bits_len != 0 || !d1->rules)
	       && ip4_map_fragment_cache (ip41, dst_port1)))
	    {
	      error1 = MAP_ERROR_FRAGMENT_MEMORY;
	    }

	  if (PREDICT_TRUE
	      (error0 == MAP_ERROR_NONE && next0 != IP4_MAPT_NEXT_MAPT_ICMP))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_TX,
					       thread_index,
					       vnet_buffer (p0)->map_t.
					       map_domain_index, 1,
					       clib_net_to_host_u16 (ip40->
								     length));
	    }

	  if (PREDICT_TRUE
	      (error1 == MAP_ERROR_NONE && next1 != IP4_MAPT_NEXT_MAPT_ICMP))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_TX,
					       thread_index,
					       vnet_buffer (p1)->map_t.
					       map_domain_index, 1,
					       clib_net_to_host_u16 (ip41->
								     length));
	    }

	  next0 = (error0 != MAP_ERROR_NONE) ? IP4_MAPT_NEXT_DROP : next0;
	  next1 = (error1 != MAP_ERROR_NONE) ? IP4_MAPT_NEXT_DROP : next1;
	  p0->error = error_node->errors[error0];
	  p1->error = error_node->errors[error1];
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, pi1, next0,
					   next1);
	}
#endif

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  ip4_header_t *ip40;
	  map_domain_t *d0;
	  ip4_mapt_next_t next0;
	  u16 ip4_len0;
	  u8 error0;
	  i32 dst_port0;
	  ip4_mapt_pseudo_header_t *pheader0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  error0 = MAP_ERROR_NONE;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip40 = vlib_buffer_get_current (p0);
	  ip4_len0 = clib_host_to_net_u16 (ip40->length);
	  if (PREDICT_FALSE (p0->current_length < ip4_len0 ||
			     ip40->ip_version_and_header_length != 0x45))
	    {
	      error0 = MAP_ERROR_UNKNOWN;
	      next0 = IP4_MAPT_NEXT_DROP;
	    }

	  vnet_buffer (p0)->map_t.map_domain_index =
	    vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	  d0 = ip4_map_get_domain (vnet_buffer (p0)->map_t.map_domain_index);

	  vnet_buffer (p0)->map_t.mtu = d0->mtu ? d0->mtu : ~0;

	  dst_port0 = -1;
	  ip4_map_t_classify (p0, d0, ip40, ip4_len0, &dst_port0, &error0,
			      &next0);

	  //Add MAP-T pseudo header in front of the packet
	  vlib_buffer_advance (p0, -sizeof (*pheader0));
	  pheader0 = vlib_buffer_get_current (p0);

	  //Save addresses within the packet
	  ip4_map_t_embedded_address (d0, &pheader0->saddr,
				      &ip40->src_address);
	  pheader0->daddr.as_u64[0] =
	    map_get_pfx_net (d0, ip40->dst_address.as_u32, (u16) dst_port0);
	  pheader0->daddr.as_u64[1] =
	    map_get_sfx_net (d0, ip40->dst_address.as_u32, (u16) dst_port0);

	  //It is important to cache at this stage because the result might be necessary
	  //for packets within the same vector.
	  //Actually, this approach even provides some limited out-of-order fragments support
	  if (PREDICT_FALSE
	      (ip4_is_first_fragment (ip40) && (dst_port0 != -1)
	       && (d0->ea_bits_len != 0 || !d0->rules)
	       && ip4_map_fragment_cache (ip40, dst_port0)))
	    {
	      error0 = MAP_ERROR_UNKNOWN;
	    }

	  if (PREDICT_TRUE
	      (error0 == MAP_ERROR_NONE && next0 != IP4_MAPT_NEXT_MAPT_ICMP))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_TX,
					       thread_index,
					       vnet_buffer (p0)->map_t.
					       map_domain_index, 1,
					       clib_net_to_host_u16 (ip40->
								     length));
	    }

	  next0 = (error0 != MAP_ERROR_NONE) ? IP4_MAPT_NEXT_DROP : next0;
	  p0->error = error_node->errors[error0];
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, pi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

static char *map_t_error_strings[] = {
#define _(sym,string) string,
  foreach_map_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip4_map_t_fragmented_node) = {
  .function = ip4_map_t_fragmented,
  .name = "ip4-map-t-fragmented",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_strings = map_t_error_strings,

  .n_next_nodes = IP4_MAPT_FRAGMENTED_N_NEXT,
  .next_nodes = {
      [IP4_MAPT_FRAGMENTED_NEXT_IP6_LOOKUP] = "ip6-lookup",
      [IP4_MAPT_FRAGMENTED_NEXT_IP6_FRAG] = IP6_FRAG_NODE_NAME,
      [IP4_MAPT_FRAGMENTED_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip4_map_t_icmp_node) = {
  .function = ip4_map_t_icmp,
  .name = "ip4-map-t-icmp",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_strings = map_t_error_strings,

  .n_next_nodes = IP4_MAPT_ICMP_N_NEXT,
  .next_nodes = {
      [IP4_MAPT_ICMP_NEXT_IP6_LOOKUP] = "ip6-lookup",
      [IP4_MAPT_ICMP_NEXT_IP6_FRAG] = IP6_FRAG_NODE_NAME,
      [IP4_MAPT_ICMP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip4_map_t_tcp_udp_node) = {
  .function = ip4_map_t_tcp_udp,
  .name = "ip4-map-t-tcp-udp",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_strings = map_t_error_strings,

  .n_next_nodes = IP4_MAPT_TCP_UDP_N_NEXT,
  .next_nodes = {
      [IP4_MAPT_TCP_UDP_NEXT_IP6_LOOKUP] = "ip6-lookup",
      [IP4_MAPT_TCP_UDP_NEXT_IP6_FRAG] = IP6_FRAG_NODE_NAME,
      [IP4_MAPT_TCP_UDP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip4_map_t_node) = {
  .function = ip4_map_t,
  .name = "ip4-map-t",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_strings = map_t_error_strings,

  .n_next_nodes = IP4_MAPT_N_NEXT,
  .next_nodes = {
      [IP4_MAPT_NEXT_MAPT_TCP_UDP] = "ip4-map-t-tcp-udp",
      [IP4_MAPT_NEXT_MAPT_ICMP] = "ip4-map-t-icmp",
      [IP4_MAPT_NEXT_MAPT_FRAGMENTED] = "ip4-map-t-fragmented",
      [IP4_MAPT_NEXT_DROP] = "error-drop",
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
