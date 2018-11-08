/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief IPv4 to IPv6 translation
 */
#ifndef __included_ip4_to_ip6_h__
#define __included_ip4_to_ip6_h__

#include <vnet/ip/ip.h>


/**
 * IPv4 to IPv6 set call back function type
 */
typedef int (*ip4_to_ip6_set_fn_t) (ip4_header_t * ip4, ip6_header_t * ip6,
				    void *ctx);

/* *INDENT-OFF* */
static u8 icmp_to_icmp6_updater_pointer_table[] =
  { 0, 1, 4, 4, ~0,
    ~0, ~0, ~0, 7, 6,
    ~0, ~0, 8, 8, 8,
    8, 24, 24, 24, 24
  };
/* *INDENT-ON* */

#define frag_id_4to6(id) (id)

/**
 * @brief Get TCP/UDP port number or ICMP id from IPv4 packet.
 *
 * @param ip4        IPv4 header.
 * @param sender     1 get sender port, 0 get receiver port.
 *
 * @returns Port number on success, 0 otherwise.
 */
always_inline u16
ip4_get_port (ip4_header_t * ip, u8 sender)
{
  if (ip->ip_version_and_header_length != 0x45 ||
      ip4_get_fragment_offset (ip))
    return 0;

  if (PREDICT_TRUE ((ip->protocol == IP_PROTOCOL_TCP) ||
		    (ip->protocol == IP_PROTOCOL_UDP)))
    {
      udp_header_t *udp = (void *) (ip + 1);
      return (sender) ? udp->src_port : udp->dst_port;
    }
  else if (ip->protocol == IP_PROTOCOL_ICMP)
    {
      icmp46_header_t *icmp = (void *) (ip + 1);
      if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply)
	{
	  return *((u16 *) (icmp + 1));
	}
      else if (clib_net_to_host_u16 (ip->length) >= 64)
	{
	  ip = (ip4_header_t *) (icmp + 2);
	  if (PREDICT_TRUE ((ip->protocol == IP_PROTOCOL_TCP) ||
			    (ip->protocol == IP_PROTOCOL_UDP)))
	    {
	      udp_header_t *udp = (void *) (ip + 1);
	      return (sender) ? udp->dst_port : udp->src_port;
	    }
	  else if (ip->protocol == IP_PROTOCOL_ICMP)
	    {
	      icmp46_header_t *icmp = (void *) (ip + 1);
	      if (icmp->type == ICMP4_echo_request ||
		  icmp->type == ICMP4_echo_reply)
		{
		  return *((u16 *) (icmp + 1));
		}
	    }
	}
    }
  return 0;
}

/**
 * @brief Convert type and code value from ICMP4 to ICMP6.
 *
 * @param icmp      ICMP header.
 * @param inner_ip4 Inner IPv4 header if present, 0 otherwise.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
always_inline int
icmp_to_icmp6_header (icmp46_header_t * icmp, ip4_header_t ** inner_ip4)
{
  *inner_ip4 = NULL;
  switch (icmp->type)
    {
    case ICMP4_echo_reply:
      icmp->type = ICMP6_echo_reply;
      break;
    case ICMP4_echo_request:
      icmp->type = ICMP6_echo_request;
      break;
    case ICMP4_destination_unreachable:
      *inner_ip4 = (ip4_header_t *) (((u8 *) icmp) + 8);

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
      icmp->type = ICMP6_time_exceeded;
      break;

    case ICMP4_parameter_problem:
      *inner_ip4 = (ip4_header_t *) (((u8 *) icmp) + 8);

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
	  //All other codes cause error
	  return -1;
	}
      break;

    default:
      //All other types cause error
      return -1;
      break;
    }
  return 0;
}

/**
 * @brief Translate ICMP4 packet to ICMP6.
 *
 * @param p         Buffer to translate.
 * @param fn        The function to translate outer header.
 * @param ctx       A context passed in the outer header translate function.
 * @param inner_fn  The function to translate inner header.
 * @param inner_ctx A context passed in the inner header translate function.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
always_inline int
icmp_to_icmp6 (vlib_buffer_t * p, ip4_to_ip6_set_fn_t fn, void *ctx,
	       ip4_to_ip6_set_fn_t inner_fn, void *inner_ctx)
{
  ip4_header_t *ip4, *inner_ip4;
  ip6_header_t *ip6, *inner_ip6;
  u32 ip_len;
  icmp46_header_t *icmp;
  ip_csum_t csum;
  ip6_frag_hdr_t *inner_frag;
  u32 inner_frag_id;
  u32 inner_frag_offset;
  u8 inner_frag_more;
  u16 *inner_L4_checksum = 0;
  int rv;

  ip4 = vlib_buffer_get_current (p);
  ip_len = clib_net_to_host_u16 (ip4->length);
  ASSERT (ip_len <= p->current_length);

  icmp = (icmp46_header_t *) (ip4 + 1);
  if (icmp_to_icmp6_header (icmp, &inner_ip4))
    return -1;

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
	      return -1;
	    }

	  vlib_buffer_advance (p,
			       -2 * (sizeof (*ip6) - sizeof (*ip4)) -
			       sizeof (*inner_frag));
	  ip6 = vlib_buffer_get_current (p);
	  memmove (u8_ptr_add (ip6, sizeof (*ip6) - sizeof (*ip4)), ip4,
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
	  memmove (u8_ptr_add (ip6, sizeof (*ip6) - sizeof (*ip4)), ip4,
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
	  if (*inner_L4_checksum)
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
	  //Only types ICMP4_echo_request and ICMP4_echo_reply are handled by icmp_to_icmp6_header
	  inner_icmp->type = (inner_icmp->type == ICMP4_echo_request) ?
	    ICMP6_echo_request : ICMP6_echo_reply;
	  inner_L4_checksum = &inner_icmp->checksum;
	  inner_ip4->protocol = IP_PROTOCOL_ICMP6;
	}
      else
	{
	  /* To shut up Coverity */
	  os_panic ();
	}

      inner_ip6->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 ((6 << 28) + (inner_ip4->tos << 20));
      inner_ip6->payload_length =
	u16_net_add (inner_ip4->length, -sizeof (*inner_ip4));
      inner_ip6->hop_limit = inner_ip4->ttl;
      inner_ip6->protocol = inner_ip4->protocol;

      if ((rv = inner_fn (inner_ip4, inner_ip6, inner_ctx)) != 0)
	return rv;

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

      csum = *inner_L4_checksum;
      if (inner_ip6->protocol == IP_PROTOCOL_ICMP6)
	{
	  //Recompute ICMP checksum
	  icmp46_header_t *inner_icmp = (icmp46_header_t *) (inner_ip4 + 1);

	  inner_icmp->checksum = 0;
	  csum = ip_csum_with_carry (0, inner_ip6->payload_length);
	  csum =
	    ip_csum_with_carry (csum,
				clib_host_to_net_u16 (inner_ip6->protocol));
	  csum = ip_csum_with_carry (csum, inner_ip6->src_address.as_u64[0]);
	  csum = ip_csum_with_carry (csum, inner_ip6->src_address.as_u64[1]);
	  csum = ip_csum_with_carry (csum, inner_ip6->dst_address.as_u64[0]);
	  csum = ip_csum_with_carry (csum, inner_ip6->dst_address.as_u64[1]);
	  csum =
	    ip_incremental_checksum (csum, inner_icmp,
				     clib_net_to_host_u16
				     (inner_ip6->payload_length));
	  inner_icmp->checksum = ~ip_csum_fold (csum);
	}
      else
	{
	  /* UDP checksum is optional */
	  if (csum)
	    {
	      csum =
		ip_csum_add_even (csum, inner_ip6->src_address.as_u64[0]);
	      csum =
		ip_csum_add_even (csum, inner_ip6->src_address.as_u64[1]);
	      csum =
		ip_csum_add_even (csum, inner_ip6->dst_address.as_u64[0]);
	      csum =
		ip_csum_add_even (csum, inner_ip6->dst_address.as_u64[1]);
	      *inner_L4_checksum = ip_csum_fold (csum);
	    }
	}
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

  if ((rv = fn (ip4, ip6, ctx)) != 0)
    return rv;

  //Truncate when the packet exceeds the minimal IPv6 MTU
  if (p->current_length > 1280)
    {
      ip6->payload_length = clib_host_to_net_u16 (1280 - sizeof (*ip6));
      p->current_length = 1280;	//Looks too simple to be correct...
    }

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

  return 0;
}

/**
 * @brief Translate IPv4 fragmented packet to IPv6.
 *
 * @param p   Buffer to translate.
 * @param fn  The function to translate header.
 * @param ctx A context passed in the header translate function.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
always_inline int
ip4_to_ip6_fragmented (vlib_buffer_t * p, ip4_to_ip6_set_fn_t fn, void *ctx)
{
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  ip6_frag_hdr_t *frag;
  int rv;

  ip4 = vlib_buffer_get_current (p);
  frag = (ip6_frag_hdr_t *) u8_ptr_add (ip4, sizeof (*ip4) - sizeof (*frag));
  ip6 =
    (ip6_header_t *) u8_ptr_add (ip4,
				 sizeof (*ip4) - sizeof (*frag) -
				 sizeof (*ip6));
  vlib_buffer_advance (p, sizeof (*ip4) - sizeof (*ip6) - sizeof (*frag));

  //We know that the protocol was one of ICMP, TCP or UDP
  //because the first fragment was found and cached
  frag->next_hdr =
    (ip4->protocol == IP_PROTOCOL_ICMP) ? IP_PROTOCOL_ICMP6 : ip4->protocol;
  frag->identification = frag_id_4to6 (ip4->fragment_id);
  frag->rsv = 0;
  frag->fragment_offset_and_more =
    ip6_frag_hdr_offset_and_more (ip4_get_fragment_offset (ip4),
				  clib_net_to_host_u16
				  (ip4->flags_and_fragment_offset) &
				  IP4_HEADER_FLAG_MORE_FRAGMENTS);

  ip6->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 ((6 << 28) + (ip4->tos << 20));
  ip6->payload_length =
    clib_host_to_net_u16 (clib_net_to_host_u16 (ip4->length) -
			  sizeof (*ip4) + sizeof (*frag));
  ip6->hop_limit = ip4->ttl;
  ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;

  if ((rv = fn (ip4, ip6, ctx)) != 0)
    return rv;

  return 0;
}

/**
 * @brief Translate IPv4 UDP/TCP packet to IPv6.
 *
 * @param p   Buffer to translate.
 * @param fn  The function to translate header.
 * @param ctx A context passed in the header translate function.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
always_inline int
ip4_to_ip6_tcp_udp (vlib_buffer_t * p, ip4_to_ip6_set_fn_t fn, void *ctx)
{
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  ip_csum_t csum;
  u16 *checksum;
  ip6_frag_hdr_t *frag;
  u32 frag_id;
  int rv;
  ip4_address_t old_src, old_dst;

  ip4 = vlib_buffer_get_current (p);

  if (ip4->protocol == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = ip4_next_header (ip4);
      checksum = &udp->checksum;

      //UDP checksum is optional over IPv4 but mandatory for IPv6
      //We do not check udp->length sanity but use our safe computed value instead
      if (PREDICT_FALSE (!*checksum))
	{
	  u16 udp_len = clib_host_to_net_u16 (ip4->length) - sizeof (*ip4);
	  csum = ip_incremental_checksum (0, udp, udp_len);
	  csum = ip_csum_with_carry (csum, clib_host_to_net_u16 (udp_len));
	  csum =
	    ip_csum_with_carry (csum, clib_host_to_net_u16 (IP_PROTOCOL_UDP));
	  csum = ip_csum_with_carry (csum, *((u64 *) (&ip4->src_address)));
	  *checksum = ~ip_csum_fold (csum);
	}
    }
  else
    {
      tcp_header_t *tcp = ip4_next_header (ip4);
      checksum = &tcp->checksum;
    }

  old_src.as_u32 = ip4->src_address.as_u32;
  old_dst.as_u32 = ip4->dst_address.as_u32;

  // Deal with fragmented packets
  if (PREDICT_FALSE (ip4->flags_and_fragment_offset &
		     clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS)))
    {
      ip6 =
	(ip6_header_t *) u8_ptr_add (ip4,
				     sizeof (*ip4) - sizeof (*ip6) -
				     sizeof (*frag));
      frag =
	(ip6_frag_hdr_t *) u8_ptr_add (ip4, sizeof (*ip4) - sizeof (*frag));
      frag_id = frag_id_4to6 (ip4->fragment_id);
      vlib_buffer_advance (p, sizeof (*ip4) - sizeof (*ip6) - sizeof (*frag));
    }
  else
    {
      ip6 = (ip6_header_t *) (((u8 *) ip4) + sizeof (*ip4) - sizeof (*ip6));
      vlib_buffer_advance (p, sizeof (*ip4) - sizeof (*ip6));
      frag = NULL;
    }

  ip6->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 ((6 << 28) + (ip4->tos << 20));
  ip6->payload_length = u16_net_add (ip4->length, -sizeof (*ip4));
  ip6->hop_limit = ip4->ttl;
  ip6->protocol = ip4->protocol;

  if (PREDICT_FALSE (frag != NULL))
    {
      frag->next_hdr = ip6->protocol;
      frag->identification = frag_id;
      frag->rsv = 0;
      frag->fragment_offset_and_more = ip6_frag_hdr_offset_and_more (0, 1);
      ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
      ip6->payload_length = u16_net_add (ip6->payload_length, sizeof (*frag));
    }

  if ((rv = fn (ip4, ip6, ctx)) != 0)
    return rv;

  csum = ip_csum_sub_even (*checksum, old_src.as_u32);
  csum = ip_csum_sub_even (csum, old_dst.as_u32);
  csum = ip_csum_add_even (csum, ip6->src_address.as_u64[0]);
  csum = ip_csum_add_even (csum, ip6->src_address.as_u64[1]);
  csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[0]);
  csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[1]);
  *checksum = ip_csum_fold (csum);

  return 0;
}

/**
 * @brief Translate IPv4 packet to IPv6 (IP header only).
 *
 * @param p   Buffer to translate.
 * @param fn  The function to translate header.
 * @param ctx A context passed in the header translate function.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
always_inline int
ip4_to_ip6 (vlib_buffer_t * p, ip4_to_ip6_set_fn_t fn, void *ctx)
{
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  ip6_frag_hdr_t *frag;
  u32 frag_id;
  int rv;

  ip4 = vlib_buffer_get_current (p);

  // Deal with fragmented packets
  if (PREDICT_FALSE (ip4->flags_and_fragment_offset &
		     clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS)))
    {
      ip6 =
	(ip6_header_t *) u8_ptr_add (ip4,
				     sizeof (*ip4) - sizeof (*ip6) -
				     sizeof (*frag));
      frag =
	(ip6_frag_hdr_t *) u8_ptr_add (ip4, sizeof (*ip4) - sizeof (*frag));
      frag_id = frag_id_4to6 (ip4->fragment_id);
      vlib_buffer_advance (p, sizeof (*ip4) - sizeof (*ip6) - sizeof (*frag));
    }
  else
    {
      ip6 = (ip6_header_t *) (((u8 *) ip4) + sizeof (*ip4) - sizeof (*ip6));
      vlib_buffer_advance (p, sizeof (*ip4) - sizeof (*ip6));
      frag = NULL;
    }

  ip6->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 ((6 << 28) + (ip4->tos << 20));
  ip6->payload_length = u16_net_add (ip4->length, -sizeof (*ip4));
  ip6->hop_limit = ip4->ttl;
  ip6->protocol = ip4->protocol;

  if (PREDICT_FALSE (frag != NULL))
    {
      frag->next_hdr = ip6->protocol;
      frag->identification = frag_id;
      frag->rsv = 0;
      frag->fragment_offset_and_more = ip6_frag_hdr_offset_and_more (0, 1);
      ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
      ip6->payload_length = u16_net_add (ip6->payload_length, sizeof (*frag));
    }

  if ((rv = fn (ip4, ip6, ctx)) != 0)
    return rv;

  return 0;
}

#endif /* __included_ip4_to_ip6_h__ */
