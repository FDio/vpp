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
 * @brief IPv6 to IPv4 translation
 */
#ifndef __included_ip6_to_ip4_h__
#define __included_ip6_to_ip4_h__

#include <vnet/ip/ip.h>

/**
 * IPv6 to IPv4 set call back function type
 */
typedef int (*ip6_to_ip4_set_fn_t) (ip6_header_t * ip6, ip4_header_t * ip4,
				    void *ctx);

/* *INDENT-OFF* */
static u8 icmp6_to_icmp_updater_pointer_table[] =
  { 0, 1, ~0, ~0,
    2, 2, 9, 8,
    12, 12, 12, 12,
    12, 12, 12, 12,
    12, 12, 12, 12,
    12, 12, 12, 12,
    24, 24, 24, 24,
    24, 24, 24, 24,
    24, 24, 24, 24,
    24, 24, 24, 24
  };
/* *INDENT-ON* */

#define frag_id_6to4(id) ((id) ^ ((id) >> 16))

/**
 * @brief Parse some useful information from IPv6 header.
 *
 * @param ip6             IPv6 header.
 * @param buff_len        Buffer length.
 * @param l4_protocol     L4 protocol number.
 * @param l4_offset       L4 header offset.
 * @param frag_hdr_offset Fragment header offset if present, 0 otherwise.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
static_always_inline int
ip6_parse (const ip6_header_t * ip6, u32 buff_len,
	   u8 * l4_protocol, u16 * l4_offset, u16 * frag_hdr_offset)
{
  if (ip6->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
    {
      *l4_protocol = ((ip6_frag_hdr_t *) (ip6 + 1))->next_hdr;
      *frag_hdr_offset = sizeof (*ip6);
      *l4_offset = sizeof (*ip6) + sizeof (ip6_frag_hdr_t);
    }
  else
    {
      *l4_protocol = ip6->protocol;
      *frag_hdr_offset = 0;
      *l4_offset = sizeof (*ip6);
    }

  return (buff_len < (*l4_offset + 4)) ||
    (clib_net_to_host_u16 (ip6->payload_length) <
     (*l4_offset + 4 - sizeof (*ip6)));
}

/**
 * @brief Get TCP/UDP port number or ICMP id from IPv6 packet.
 *
 * @param ip6        IPv6 header.
 * @param sender     1 get sender port, 0 get receiver port.
 * @param buffer_len Buffer length.
 *
 * @returns Port number on success, 0 otherwise.
 */
always_inline u16
ip6_get_port (ip6_header_t * ip6, u8 sender, u16 buffer_len)
{
  u8 l4_protocol;
  u16 l4_offset;
  u16 frag_offset;
  u8 *l4;

  if (ip6_parse (ip6, buffer_len, &l4_protocol, &l4_offset, &frag_offset))
    return 0;

  if (frag_offset &&
      ip6_frag_hdr_offset (((ip6_frag_hdr_t *)
			    u8_ptr_add (ip6, frag_offset))))
    return 0;			//Can't deal with non-first fragment for now

  l4 = u8_ptr_add (ip6, l4_offset);
  if (l4_protocol == IP_PROTOCOL_TCP || l4_protocol == IP_PROTOCOL_UDP)
    {
      return (sender) ? ((udp_header_t *) (l4))->src_port : ((udp_header_t
							      *)
							     (l4))->dst_port;
    }
  else if (l4_protocol == IP_PROTOCOL_ICMP6)
    {
      icmp46_header_t *icmp = (icmp46_header_t *) (l4);
      if (icmp->type == ICMP6_echo_request)
	{
	  return (sender) ? ((u16 *) (icmp))[2] : -1;
	}
      else if (icmp->type == ICMP6_echo_reply)
	{
	  return (sender) ? -1 : ((u16 *) (icmp))[2];
	}
    }
  return 0;
}

/**
 * @brief Convert type and code value from ICMP6 to ICMP4.
 *
 * @param icmp      ICMP header.
 * @param inner_ip6 Inner IPv6 header if present, 0 otherwise.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
static_always_inline int
icmp6_to_icmp_header (icmp46_header_t * icmp, ip6_header_t ** inner_ip6)
{
  *inner_ip6 = NULL;
  switch (icmp->type)
    {
    case ICMP6_echo_request:
      icmp->type = ICMP4_echo_request;
      break;
    case ICMP6_echo_reply:
      icmp->type = ICMP4_echo_reply;
      break;
    case ICMP6_destination_unreachable:
      *inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);

      switch (icmp->code)
	{
	case ICMP6_destination_unreachable_no_route_to_destination:	//0
	case ICMP6_destination_unreachable_beyond_scope_of_source_address:	//2
	case ICMP6_destination_unreachable_address_unreachable:	//3
	  icmp->type = ICMP4_destination_unreachable;
	  icmp->code =
	    ICMP4_destination_unreachable_destination_unreachable_host;
	  break;
	case ICMP6_destination_unreachable_destination_administratively_prohibited:	//1
	  icmp->type =
	    ICMP4_destination_unreachable;
	  icmp->code =
	    ICMP4_destination_unreachable_communication_administratively_prohibited;
	  break;
	case ICMP6_destination_unreachable_port_unreachable:
	  icmp->type = ICMP4_destination_unreachable;
	  icmp->code = ICMP4_destination_unreachable_port_unreachable;
	  break;
	default:
	  return -1;
	}
      break;
    case ICMP6_packet_too_big:
      *inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);

      icmp->type = ICMP4_destination_unreachable;
      icmp->code = 4;
      {
	u32 advertised_mtu = clib_net_to_host_u32 (*((u32 *) (icmp + 1)));
	advertised_mtu -= 20;
	//FIXME: = minimum(advertised MTU-20, MTU_of_IPv4_nexthop, (MTU_of_IPv6_nexthop)-20)
	((u16 *) (icmp))[3] = clib_host_to_net_u16 (advertised_mtu);
      }
      break;

    case ICMP6_time_exceeded:
      *inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);

      icmp->type = ICMP4_time_exceeded;
      break;

    case ICMP6_parameter_problem:
      *inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);

      switch (icmp->code)
	{
	case ICMP6_parameter_problem_erroneous_header_field:
	  icmp->type = ICMP4_parameter_problem;
	  icmp->code = ICMP4_parameter_problem_pointer_indicates_error;
	  u32 pointer = clib_net_to_host_u32 (*((u32 *) (icmp + 1)));
	  if (pointer >= 40)
	    return -1;

	  ((u8 *) (icmp + 1))[0] =
	    icmp6_to_icmp_updater_pointer_table[pointer];
	  break;
	case ICMP6_parameter_problem_unrecognized_next_header:
	  icmp->type = ICMP4_destination_unreachable;
	  icmp->code = ICMP4_destination_unreachable_port_unreachable;
	  break;
	case ICMP6_parameter_problem_unrecognized_option:
	default:
	  return -1;
	}
      break;
    default:
      return -1;
      break;
    }
  return 0;
}

/**
 * @brief Translate TOS value from IPv6 to IPv4.
 *
 * @param ip6 IPv6 header.
 *
 * @returns IPv4 TOS value.
 */
static_always_inline u8
ip6_translate_tos (const ip6_header_t * ip6)
{
  return (clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label)
	  & 0x0ff00000) >> 20;
}

/**
 * @brief Translate ICMP6 packet to ICMP4.
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
icmp6_to_icmp (vlib_buffer_t * p, ip6_to_ip4_set_fn_t fn, void *ctx,
	       ip6_to_ip4_set_fn_t inner_fn, void *inner_ctx)
{
  ip6_header_t *ip6, *inner_ip6;
  ip4_header_t *ip4, *inner_ip4;
  u32 ip6_pay_len;
  icmp46_header_t *icmp;
  ip_csum_t csum;
  int rv;
  ip6_address_t old_src, old_dst;

  ip6 = vlib_buffer_get_current (p);
  ip6_pay_len = clib_net_to_host_u16 (ip6->payload_length);
  icmp = (icmp46_header_t *) (ip6 + 1);
  ASSERT (ip6_pay_len + sizeof (*ip6) <= p->current_length);

  //No extensions headers allowed here
  if (ip6->protocol != IP_PROTOCOL_ICMP6)
    return -1;

  //There are no fragmented ICMP messages, so no extension header for now
  if (icmp6_to_icmp_header (icmp, &inner_ip6))
    return -1;

  if (inner_ip6)
    {
      u16 *inner_L4_checksum, inner_l4_offset, inner_frag_offset,
	inner_frag_id;
      u8 *inner_l4, inner_protocol;

      //We have two headers to translate
      //   FROM
      //   [   IPv6   ]<- ext ->[IC][   IPv6   ]<- ext ->[L4 header ...
      // Handled cases:
      //                     [   IPv6   ][IC][   IPv6   ][L4 header ...
      //                 [   IPv6   ][IC][   IPv6   ][Fr][L4 header ...
      //    TO
      //                               [ IPv4][IC][ IPv4][L4 header ...

      if (ip6_parse (inner_ip6, ip6_pay_len - 8,
		     &inner_protocol, &inner_l4_offset, &inner_frag_offset))
	return -1;

      inner_l4 = u8_ptr_add (inner_ip6, inner_l4_offset);
      inner_ip4 =
	(ip4_header_t *) u8_ptr_add (inner_l4, -sizeof (*inner_ip4));
      if (inner_frag_offset)
	{
	  ip6_frag_hdr_t *inner_frag =
	    (ip6_frag_hdr_t *) u8_ptr_add (inner_ip6, inner_frag_offset);
	  inner_frag_id = frag_id_6to4 (inner_frag->identification);
	}
      else
	{
	  inner_frag_id = 0;
	}

      //Do the translation of the inner packet
      if (inner_protocol == IP_PROTOCOL_TCP)
	{
	  inner_L4_checksum = (u16 *) u8_ptr_add (inner_l4, 16);
	}
      else if (inner_protocol == IP_PROTOCOL_UDP)
	{
	  inner_L4_checksum = (u16 *) u8_ptr_add (inner_l4, 6);
	}
      else if (inner_protocol == IP_PROTOCOL_ICMP6)
	{
	  icmp46_header_t *inner_icmp = (icmp46_header_t *) inner_l4;
	  //It cannot be of a different type as ip6_icmp_to_icmp6_in_place succeeded
	  inner_icmp->type = (inner_icmp->type == ICMP6_echo_request) ?
	    ICMP4_echo_request : ICMP4_echo_reply;
	  inner_protocol = IP_PROTOCOL_ICMP;	//Will be copied to ip6 later
	  inner_L4_checksum = &inner_icmp->checksum;
	}
      else
	{
	  return -1;
	}

      old_src.as_u64[0] = inner_ip6->src_address.as_u64[0];
      old_src.as_u64[1] = inner_ip6->src_address.as_u64[1];
      old_dst.as_u64[0] = inner_ip6->dst_address.as_u64[0];
      old_dst.as_u64[1] = inner_ip6->dst_address.as_u64[1];

      if ((rv = inner_fn (inner_ip6, inner_ip4, inner_ctx)) != 0)
	return rv;

      inner_ip4->ip_version_and_header_length =
	IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
      inner_ip4->tos = ip6_translate_tos (inner_ip6);
      inner_ip4->length =
	u16_net_add (inner_ip6->payload_length,
		     sizeof (*ip4) + sizeof (*ip6) - inner_l4_offset);
      inner_ip4->fragment_id = inner_frag_id;
      inner_ip4->flags_and_fragment_offset =
	clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
      inner_ip4->ttl = inner_ip6->hop_limit;
      inner_ip4->protocol = inner_protocol;
      inner_ip4->checksum = ip4_header_checksum (inner_ip4);

      if (inner_ip4->protocol == IP_PROTOCOL_ICMP)
	{
	  //Recompute ICMP checksum
	  icmp46_header_t *inner_icmp = (icmp46_header_t *) inner_l4;
	  inner_icmp->checksum = 0;
	  csum =
	    ip_incremental_checksum (0, inner_icmp,
				     clib_net_to_host_u16 (inner_ip4->length)
				     - sizeof (*inner_ip4));
	  inner_icmp->checksum = ~ip_csum_fold (csum);
	}
      else
	{
	  //Update to new pseudo-header
	  csum = *inner_L4_checksum;
	  csum = ip_csum_sub_even (csum, old_src.as_u64[0]);
	  csum = ip_csum_sub_even (csum, old_src.as_u64[1]);
	  csum = ip_csum_sub_even (csum, old_dst.as_u64[0]);
	  csum = ip_csum_sub_even (csum, old_dst.as_u64[1]);
	  csum = ip_csum_add_even (csum, inner_ip4->src_address.as_u32);
	  csum = ip_csum_add_even (csum, inner_ip4->dst_address.as_u32);
	  *inner_L4_checksum = ip_csum_fold (csum);
	}

      //Move up icmp header
      ip4 = (ip4_header_t *) u8_ptr_add (inner_l4, -2 * sizeof (*ip4) - 8);
      clib_memcpy (u8_ptr_add (inner_l4, -sizeof (*ip4) - 8), icmp, 8);
      icmp = (icmp46_header_t *) u8_ptr_add (inner_l4, -sizeof (*ip4) - 8);
    }
  else
    {
      //Only one header to translate
      ip4 = (ip4_header_t *) u8_ptr_add (ip6, sizeof (*ip6) - sizeof (*ip4));
    }

  vlib_buffer_advance (p, (u32) (((u8 *) ip4) - ((u8 *) ip6)));

  if ((rv = fn (ip6, ip4, ctx)) != 0)
    return rv;

  ip4->ip_version_and_header_length =
    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
  ip4->tos = ip6_translate_tos (ip6);
  ip4->fragment_id = 0;
  ip4->flags_and_fragment_offset = 0;
  ip4->ttl = ip6->hop_limit;
  ip4->protocol = IP_PROTOCOL_ICMP;
  //TODO fix the length depending on offset length
  ip4->length = u16_net_add (ip6->payload_length,
			     (inner_ip6 ==
			      NULL) ? sizeof (*ip4) : (2 * sizeof (*ip4) -
						       sizeof (*ip6)));
  ip4->checksum = ip4_header_checksum (ip4);

  //Recompute ICMP checksum
  icmp->checksum = 0;
  csum =
    ip_incremental_checksum (0, icmp,
			     clib_net_to_host_u16 (ip4->length) -
			     sizeof (*ip4));
  icmp->checksum = ~ip_csum_fold (csum);

  return 0;
}

/**
 * @brief Translate IPv6 fragmented packet to IPv4.
 *
 * @param p   Buffer to translate.
 * @param fn  The function to translate header.
 * @param ctx A context passed in the header translate function.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
always_inline int
ip6_to_ip4_fragmented (vlib_buffer_t * p, ip6_to_ip4_set_fn_t fn, void *ctx)
{
  ip6_header_t *ip6;
  ip6_frag_hdr_t *frag;
  ip4_header_t *ip4;
  u16 frag_id;
  u8 frag_more;
  u16 frag_offset;
  u8 l4_protocol;
  u16 l4_offset;
  int rv;

  ip6 = vlib_buffer_get_current (p);

  if (ip6_parse
      (ip6, p->current_length, &l4_protocol, &l4_offset, &frag_offset))
    return -1;

  frag = (ip6_frag_hdr_t *) u8_ptr_add (ip6, frag_offset);
  ip4 = (ip4_header_t *) u8_ptr_add (ip6, l4_offset - sizeof (*ip4));
  vlib_buffer_advance (p, l4_offset - sizeof (*ip4));

  frag_id = frag_id_6to4 (frag->identification);
  frag_more = ip6_frag_hdr_more (frag);
  frag_offset = ip6_frag_hdr_offset (frag);

  if ((rv = fn (ip6, ip4, ctx)) != 0)
    return rv;

  ip4->ip_version_and_header_length =
    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
  ip4->tos = ip6_translate_tos (ip6);
  ip4->length = u16_net_add (ip6->payload_length,
			     sizeof (*ip4) - l4_offset + sizeof (*ip6));
  ip4->fragment_id = frag_id;
  ip4->flags_and_fragment_offset =
    clib_host_to_net_u16 (frag_offset |
			  (frag_more ? IP4_HEADER_FLAG_MORE_FRAGMENTS : 0));
  ip4->ttl = ip6->hop_limit;
  ip4->protocol =
    (l4_protocol == IP_PROTOCOL_ICMP6) ? IP_PROTOCOL_ICMP : l4_protocol;
  ip4->checksum = ip4_header_checksum (ip4);

  return 0;
}

/**
 * @brief Translate IPv6 UDP/TCP packet to IPv4.
 *
 * @param p   Buffer to translate.
 * @param fn  The function to translate header.
 * @param ctx A context passed in the header translate function.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
always_inline int
ip6_to_ip4_tcp_udp (vlib_buffer_t * p, ip6_to_ip4_set_fn_t fn, void *ctx,
		    u8 udp_checksum)
{
  ip6_header_t *ip6;
  u16 *checksum;
  ip_csum_t csum = 0;
  ip4_header_t *ip4;
  u16 fragment_id;
  u16 flags;
  u16 frag_offset;
  u8 l4_protocol;
  u16 l4_offset;
  int rv;
  ip6_address_t old_src, old_dst;

  ip6 = vlib_buffer_get_current (p);

  if (ip6_parse
      (ip6, p->current_length, &l4_protocol, &l4_offset, &frag_offset))
    return -1;

  if (l4_protocol == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = ip6_next_header (ip6);
      checksum = &tcp->checksum;
    }
  else
    {
      udp_header_t *udp = ip6_next_header (ip6);
      checksum = &udp->checksum;
    }

  old_src.as_u64[0] = ip6->src_address.as_u64[0];
  old_src.as_u64[1] = ip6->src_address.as_u64[1];
  old_dst.as_u64[0] = ip6->dst_address.as_u64[0];
  old_dst.as_u64[1] = ip6->dst_address.as_u64[1];

  ip4 = (ip4_header_t *) u8_ptr_add (ip6, l4_offset - sizeof (*ip4));

  vlib_buffer_advance (p, l4_offset - sizeof (*ip4));

  if (PREDICT_FALSE (frag_offset))
    {
      //Only the first fragment
      ip6_frag_hdr_t *hdr = (ip6_frag_hdr_t *) u8_ptr_add (ip6, frag_offset);
      fragment_id = frag_id_6to4 (hdr->identification);
      flags = clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
    }
  else
    {
      fragment_id = 0;
      flags = 0;
    }

  if ((rv = fn (ip6, ip4, ctx)) != 0)
    return rv;

  ip4->ip_version_and_header_length =
    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
  ip4->tos = ip6_translate_tos (ip6);
  ip4->length = u16_net_add (ip6->payload_length,
			     sizeof (*ip4) + sizeof (*ip6) - l4_offset);
  ip4->fragment_id = fragment_id;
  ip4->flags_and_fragment_offset = flags;
  ip4->ttl = ip6->hop_limit;
  ip4->protocol = l4_protocol;
  ip4->checksum = ip4_header_checksum (ip4);

  //UDP checksum is optional over IPv4
  if (!udp_checksum && l4_protocol == IP_PROTOCOL_UDP)
    {
      *checksum = 0;
    }
  else
    {
      csum = ip_csum_sub_even (*checksum, old_src.as_u64[0]);
      csum = ip_csum_sub_even (csum, old_src.as_u64[1]);
      csum = ip_csum_sub_even (csum, old_dst.as_u64[0]);
      csum = ip_csum_sub_even (csum, old_dst.as_u64[1]);
      csum = ip_csum_add_even (csum, ip4->dst_address.as_u32);
      csum = ip_csum_add_even (csum, ip4->src_address.as_u32);
      *checksum = ip_csum_fold (csum);
    }

  return 0;
}

/**
 * @brief Translate IPv6 packet to IPv4 (IP header only).
 *
 * @param p   Buffer to translate.
 * @param fn  The function to translate header.
 * @param ctx A context passed in the header translate function.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
always_inline int
ip6_to_ip4 (vlib_buffer_t * p, ip6_to_ip4_set_fn_t fn, void *ctx)
{
  ip6_header_t *ip6;
  ip4_header_t *ip4;
  u16 fragment_id;
  u16 flags;
  u16 frag_offset;
  u8 l4_protocol;
  u16 l4_offset;
  int rv;

  ip6 = vlib_buffer_get_current (p);

  if (ip6_parse
      (ip6, p->current_length, &l4_protocol, &l4_offset, &frag_offset))
    return -1;

  ip4 = (ip4_header_t *) u8_ptr_add (ip6, l4_offset - sizeof (*ip4));

  vlib_buffer_advance (p, l4_offset - sizeof (*ip4));

  if (PREDICT_FALSE (frag_offset))
    {
      //Only the first fragment
      ip6_frag_hdr_t *hdr = (ip6_frag_hdr_t *) u8_ptr_add (ip6, frag_offset);
      fragment_id = frag_id_6to4 (hdr->identification);
      flags = clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
    }
  else
    {
      fragment_id = 0;
      flags = 0;
    }

  if ((rv = fn (ip6, ip4, ctx)) != 0)
    return rv;

  ip4->ip_version_and_header_length =
    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
  ip4->tos = ip6_translate_tos (ip6);
  ip4->length = u16_net_add (ip6->payload_length,
			     sizeof (*ip4) + sizeof (*ip6) - l4_offset);
  ip4->fragment_id = fragment_id;
  ip4->flags_and_fragment_offset = flags;
  ip4->ttl = ip6->hop_limit;
  ip4->protocol = l4_protocol;
  ip4->checksum = ip4_header_checksum (ip4);

  return 0;
}

#endif /* __included_ip6_to_ip4_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
