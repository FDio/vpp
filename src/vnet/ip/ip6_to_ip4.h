/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
typedef int (*ip6_to_ip4_icmp_set_fn_t) (ip6_header_t * ip6,
					 ip4_header_t * ip4, void *ctx);

typedef int (*ip6_to_ip4_tcp_udp_set_fn_t) (vlib_buffer_t * b,
					    ip6_header_t * ip6,
					    ip4_header_t * ip4, void *ctx);

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

#define frag_id_6to4(id) ((id) ^ ((id) >> 16))

/**
 * @brief Parse some useful information from IPv6 header.
 *
 * @param vm              vlib main
 * @param b               vlib buffer
 * @param ip6             IPv6 header.
 * @param buff_len        Buffer length.
 * @param l4_protocol     L4 protocol number.
 * @param l4_offset       L4 header offset.
 * @param frag_hdr_offset Fragment header offset if present, 0 otherwise.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
static_always_inline int
ip6_parse (vlib_main_t *vm, vlib_buffer_t *b, ip6_header_t *ip6, u32 buff_len,
	   u8 *l4_protocol, u16 *l4_offset, u16 *frag_hdr_offset)
{
  ip6_ext_hdr_chain_t hdr_chain;
  int res =
    ip6_ext_header_walk (b, ip6, IP_PROTOCOL_IPV6_FRAGMENTATION, &hdr_chain);
  if (res < 0)
    {
      return -1;
    }
  if (hdr_chain.eh[res].protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
    *frag_hdr_offset = hdr_chain.eh[res].offset;
  else
    *frag_hdr_offset = 0;

  *l4_protocol = hdr_chain.eh[hdr_chain.length - 1].protocol;
  *l4_offset = hdr_chain.eh[hdr_chain.length - 1].offset;

  return 0;
}

/*
 * The extractor understands the L4 header of these protocols. A caller
 * passes the set it treats as supported. The extractor reports any
 * other terminating protocol as IP6_L4_INFO_UNSUPPORTED.
 */
typedef enum
{
  IP6_L4_SUPPORT_TCP = 1 << 0,
  IP6_L4_SUPPORT_UDP = 1 << 1,
  IP6_L4_SUPPORT_ICMP6 = 1 << 2,
  IP6_L4_SUPPORT_DCCP = 1 << 3,
  IP6_L4_SUPPORT_SCTP = 1 << 4,
  IP6_L4_SUPPORT_UDP_LITE = 1 << 5,
} ip6_l4_support_t;

/*
 * The outcome of extracting L4 information from an IPv6 packet.
 */
typedef enum
{
  /* The walk found a supported L4 header and extracted its information. */
  IP6_L4_INFO_OK,
  /* The walk stopped at the scan limit before an L4 header. The packet
   * is not malformed, but it has no L4 information. */
  IP6_L4_INFO_NO_L4,
  /* The chain ended at a protocol outside the caller's support set. */
  IP6_L4_INFO_UNSUPPORTED,
  /* The chain is truncated or is a non-first fragment, so there is no
   * usable L4 header. */
  IP6_L4_INFO_MALFORMED,
} ip6_l4_info_status_t;

typedef struct
{
  u8 protocol;
  u16 src_port;
  u16 dst_port;
  u8 icmp_type_or_tcp_flags;
  u32 tcp_ack_number;
  u32 tcp_seq_number;
  void *l4_hdr;
} ip6_l4_info_t;

static_always_inline u32
ip6_l4_support_bit (u8 protocol)
{
  switch (protocol)
    {
    case IP_PROTOCOL_TCP:
      return IP6_L4_SUPPORT_TCP;
    case IP_PROTOCOL_UDP:
      return IP6_L4_SUPPORT_UDP;
    case IP_PROTOCOL_ICMP6:
      return IP6_L4_SUPPORT_ICMP6;
    case IP_PROTOCOL_DCCP:
      return IP6_L4_SUPPORT_DCCP;
    case IP_PROTOCOL_SCTP:
      return IP6_L4_SUPPORT_SCTP;
    case IP_PROTOCOL_UDP_LITE:
      return IP6_L4_SUPPORT_UDP_LITE;
    default:
      return 0;
    }
}

/*
 * Extract L4 information from the header where the chain ended.
 * ip6_l4_info_extract() handles ICMP6 error messages.
 *
 * chain, when not NULL, is a chain already walked from ip6. The function
 * skips the walk and uses it.
 *
 * The walk validates the fixed header length only for TCP, UDP and
 * ICMP6. This function checks the port header of the other supported
 * protocols, and checks an ICMP6 echo identifier when check_icmp_id is
 * set.
 */
static_always_inline ip6_l4_info_status_t
ip6_l4_info_parse (vlib_buffer_t *b, ip6_header_t *ip6, const ip6_ext_hdr_chain_t *chain,
		   u32 support, bool check_icmp_id, ip6_l4_info_t *info)
{
  u8 *data_end = u8_ptr_add (vlib_buffer_get_current (b), b->current_length);
  ip6_ext_hdr_chain_t local_chain;
  ip6_ext_hdr_chain_status_t status;
  u8 *l4;

  clib_memset (info, 0, sizeof (*info));

  if (!chain)
    {
      /*
       * Bound the walk by the bytes present in the buffer.
       * ip6_ext_header_walk_buffer() uses vlib_bytes_left_in_buffer(),
       * which underflows when ip6 is past the buffer's current data end,
       * as happens for the packet quoted by an ICMPv6 error.
       */
      u32 bytes_left = (u8 *) ip6 < data_end ? (u32) (data_end - (u8 *) ip6) : 0;
      u32 valid_end;
      u32 datagram_end;

      if (bytes_left < sizeof (*ip6))
	return IP6_L4_INFO_MALFORMED;

      datagram_end = ip6_ext_header_datagram_end (b, ip6);
      valid_end = clib_min (bytes_left, datagram_end);
      ip6_ext_header_walk_bounded (ip6, valid_end, datagram_end, &local_chain);
      chain = &local_chain;
    }

  status = chain->status;

  if (status == IP6_EXT_HDR_CHAIN_NON_FIRST_FRAG || status == IP6_EXT_HDR_CHAIN_L4_TRUNCATED ||
      (status == IP6_EXT_HDR_CHAIN_TRUNCATED && !chain->buffer_bound) ||
      (status == IP6_EXT_HDR_CHAIN_LIMIT && chain->length == 0))
    return IP6_L4_INFO_MALFORMED;

  if (status == IP6_EXT_HDR_CHAIN_TRUNCATED && chain->buffer_bound)
    {
      info->protocol = chain->term_protocol;
      info->l4_hdr = u8_ptr_add (ip6, chain->term_offset);
      return IP6_L4_INFO_NO_L4;
    }

  if (status == IP6_EXT_HDR_CHAIN_LIMIT)
    {
      info->protocol = chain->eh[chain->length - 1].protocol;
      info->l4_hdr = u8_ptr_add (ip6, chain->eh[chain->length - 1].offset);
      return IP6_L4_INFO_NO_L4;
    }

  info->protocol = chain->term_protocol;
  l4 = u8_ptr_add (ip6, chain->term_offset);
  info->l4_hdr = l4;

  if (!(ip6_l4_support_bit (info->protocol) & support))
    return IP6_L4_INFO_UNSUPPORTED;

  switch (info->protocol)
    {
    case IP_PROTOCOL_TCP:
      if (u8_ptr_add (l4, sizeof (tcp_header_t)) > data_end)
	return IP6_L4_INFO_MALFORMED;
      info->src_port = ((tcp_header_t *) l4)->src_port;
      info->dst_port = ((tcp_header_t *) l4)->dst_port;
      info->icmp_type_or_tcp_flags = ((tcp_header_t *) l4)->flags;
      info->tcp_ack_number = ((tcp_header_t *) l4)->ack_number;
      info->tcp_seq_number = ((tcp_header_t *) l4)->seq_number;
      break;

    case IP_PROTOCOL_UDP:
    case IP_PROTOCOL_DCCP:
    case IP_PROTOCOL_SCTP:
    case IP_PROTOCOL_UDP_LITE:
      if (u8_ptr_add (l4, sizeof (udp_header_t)) > data_end)
	return IP6_L4_INFO_MALFORMED;
      info->src_port = ((udp_header_t *) l4)->src_port;
      info->dst_port = ((udp_header_t *) l4)->dst_port;
      break;

    case IP_PROTOCOL_ICMP6:
      {
	icmp46_header_t *icmp = (icmp46_header_t *) l4;

	if (u8_ptr_add (l4, sizeof (icmp46_header_t)) > data_end)
	  return IP6_L4_INFO_MALFORMED;
	info->icmp_type_or_tcp_flags = icmp->type;
	if (icmp->type == ICMP6_echo_request || icmp->type == ICMP6_echo_reply)
	  {
	    if (check_icmp_id && u8_ptr_add (l4, sizeof (icmp46_header_t) + 2) > data_end)
	      return IP6_L4_INFO_MALFORMED;
	    info->src_port = ((u16 *) icmp)[2];
	    info->dst_port = ((u16 *) icmp)[2];
	  }
      }
      break;

    default:
      /* The support bit test rejects every protocol without a case. */
      return IP6_L4_INFO_UNSUPPORTED;
    }

  return IP6_L4_INFO_OK;
}

/*
 * Extract L4 information from an IPv6 packet, including the ports of the
 * packet quoted by an ICMP6 error message.
 *
 * chain, when not NULL, is a chain already walked from ip6. The outer
 * packet uses it instead of walking again.
 *
 * inner_failure_fatal selects whether an unusable quoted packet fails
 * the extraction or leaves the ports zero.
 */
static_always_inline ip6_l4_info_status_t
ip6_l4_info_extract (vlib_buffer_t *b, ip6_header_t *ip6, const ip6_ext_hdr_chain_t *chain,
		     u32 support, bool inner_failure_fatal, bool check_icmp_id, ip6_l4_info_t *info)
{
  ip6_l4_info_status_t status;

  status = ip6_l4_info_parse (b, ip6, chain, support, check_icmp_id, info);

  if (status != IP6_L4_INFO_OK || info->protocol != IP_PROTOCOL_ICMP6 ||
      info->icmp_type_or_tcp_flags < ICMP6_destination_unreachable ||
      info->icmp_type_or_tcp_flags > ICMP6_parameter_problem ||
      clib_net_to_host_u16 (ip6->payload_length) < 64)
    return status;

  {
    ip6_header_t *inner_ip6 = (ip6_header_t *) u8_ptr_add (info->l4_hdr, 8);
    ip6_l4_info_t inner_info;
    ip6_l4_info_status_t inner_status;

    inner_status = ip6_l4_info_parse (b, inner_ip6, NULL, support, check_icmp_id, &inner_info);

    if (inner_status == IP6_L4_INFO_MALFORMED)
      return inner_failure_fatal ? IP6_L4_INFO_MALFORMED : IP6_L4_INFO_OK;

    if (inner_status == IP6_L4_INFO_OK)
      {
	info->src_port = inner_info.dst_port;
	info->dst_port = inner_info.src_port;
      }
    return IP6_L4_INFO_OK;
  }
}

/**
 * @brief Get L4 information like port number or ICMP id from IPv6 packet.
 *
 * @param ip6        IPv6 header.
 * @param buffer_len Buffer length.
 * @param ip_protocol L4 protocol
 * @param src_port L4 src port or icmp id
 * @param dst_post L4 dst port or icmp id
 * @param icmp_type_or_tcp_flags ICMP type or TCP flags, if applicable
 * @param tcp_ack_number TCP ack number, if applicable
 * @param tcp_seq_number TCP seq number, if applicable
 *
 * @returns 1 on success, 0 otherwise.
 */
always_inline u16
ip6_get_port (vlib_main_t *vm, vlib_buffer_t *b, ip6_header_t *ip6,
	      u16 buffer_len, u8 *ip_protocol, u16 *src_port, u16 *dst_port,
	      u8 *icmp_type_or_tcp_flags, u32 *tcp_ack_number,
	      u32 *tcp_seq_number, void **l4_hdr)
{
  u8 l4_protocol;
  u16 l4_offset;
  u16 frag_offset;
  u8 *l4;

  if (ip6_parse (vm, b, ip6, buffer_len, &l4_protocol, &l4_offset,
		 &frag_offset))
    {
      return 0;
    }
  if (frag_offset &&
      ip6_frag_hdr_offset (((ip6_frag_hdr_t *) u8_ptr_add (ip6, frag_offset))))
    return 0;			//Can't deal with non-first fragment for now

  if (ip_protocol)
    {
      *ip_protocol = l4_protocol;
    }
  l4 = u8_ptr_add (ip6, l4_offset);
  if (l4_hdr)
    *l4_hdr = l4;
  if (l4_protocol == IP_PROTOCOL_TCP || l4_protocol == IP_PROTOCOL_UDP)
    {
      if ((IP_PROTOCOL_UDP == l4_protocol &&
	   u8_ptr_add (l4, sizeof (udp_header_t)) >
	     u8_ptr_add (vlib_buffer_get_current (b), b->current_length)) ||
	  (IP_PROTOCOL_TCP == l4_protocol &&
	   u8_ptr_add (l4, sizeof (tcp_header_t)) >
	     u8_ptr_add (vlib_buffer_get_current (b), b->current_length)))
	{
	  return 0;
	}
      if (src_port)
	*src_port = ((udp_header_t *) (l4))->src_port;
      if (dst_port)
	*dst_port = ((udp_header_t *) (l4))->dst_port;
      if (icmp_type_or_tcp_flags && l4_protocol == IP_PROTOCOL_TCP)
	*icmp_type_or_tcp_flags = ((tcp_header_t *) (l4))->flags;
      if (tcp_ack_number && l4_protocol == IP_PROTOCOL_TCP)
	*tcp_ack_number = ((tcp_header_t *) (l4))->ack_number;
      if (tcp_seq_number && l4_protocol == IP_PROTOCOL_TCP)
	*tcp_seq_number = ((tcp_header_t *) (l4))->seq_number;
    }
  else if (l4_protocol == IP_PROTOCOL_ICMP6)
    {
      if (u8_ptr_add (l4, sizeof (icmp46_header_t)) >
	  u8_ptr_add (vlib_buffer_get_current (b), b->current_length))
	{
	  return 0;
	}
      icmp46_header_t *icmp = (icmp46_header_t *) (l4);
      if (icmp_type_or_tcp_flags)
	*icmp_type_or_tcp_flags = ((icmp46_header_t *) (l4))->type;
      if (icmp->type == ICMP6_echo_request)
	{
	  if (src_port)
	    *src_port = ((u16 *) (icmp))[2];
	  if (dst_port)
	    *dst_port = ((u16 *) (icmp))[2];
	}
      else if (icmp->type == ICMP6_echo_reply)
	{
	  if (src_port)
	    *src_port = ((u16 *) (icmp))[2];
	  if (dst_port)
	    *dst_port = ((u16 *) (icmp))[2];
	}
      /*
       * if there is enough data and ICMP type indicates ICMP error, then parse
       * inner packet
       *
       * ICMP6 errors are:
       *   1 - destination_unreachable
       *   2 - packet_too_big
       *   3 - time_exceeded
       *   4 - parameter_problem
       */
      else if (clib_net_to_host_u16 (ip6->payload_length) >= 64 &&
	       icmp->type >= ICMP6_destination_unreachable &&
	       icmp->type <= ICMP6_parameter_problem)
	{
	  u16 ip6_pay_len;
	  ip6_header_t *inner_ip6;
	  u8 inner_l4_protocol;
	  u16 inner_l4_offset;
	  u16 inner_frag_offset;
	  u8 *inner_l4;

	  ip6_pay_len = clib_net_to_host_u16 (ip6->payload_length);
	  inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);

	  if (ip6_parse (vm, b, inner_ip6, ip6_pay_len - 8,
			 &inner_l4_protocol, &inner_l4_offset,
			 &inner_frag_offset))
	    return 0;

	  if (inner_frag_offset &&
	      ip6_frag_hdr_offset (((ip6_frag_hdr_t *)
				    u8_ptr_add (inner_ip6,
						inner_frag_offset))))
	    return 0;

	  inner_l4 = u8_ptr_add (inner_ip6, inner_l4_offset);
	  if (inner_l4_protocol == IP_PROTOCOL_TCP ||
	      inner_l4_protocol == IP_PROTOCOL_UDP)
	    {
	      if (src_port)
		*src_port = ((udp_header_t *) (inner_l4))->dst_port;
	      if (dst_port)
		*dst_port = ((udp_header_t *) (inner_l4))->src_port;
	    }
	  else if (inner_l4_protocol == IP_PROTOCOL_ICMP6)
	    {
	      icmp46_header_t *inner_icmp = (icmp46_header_t *) (inner_l4);
	      if (inner_icmp->type == ICMP6_echo_request)
		{
		  if (src_port)
		    *src_port = ((u16 *) (inner_icmp))[2];
		  if (dst_port)
		    *dst_port = ((u16 *) (inner_icmp))[2];
		}
	      else if (inner_icmp->type == ICMP6_echo_reply)
		{
		  if (src_port)
		    *src_port = ((u16 *) (inner_icmp))[2];
		  if (dst_port)
		    *dst_port = ((u16 *) (inner_icmp))[2];
		}
	    }
	}
    }
  return 1;
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
 * @param ip_version_traffic_class_and_flow_label in network byte order
 *
 * @returns IPv4 TOS value.
 */
static_always_inline u8
ip6_translate_tos (u32 ip_version_traffic_class_and_flow_label)
{
  return (clib_net_to_host_u32 (ip_version_traffic_class_and_flow_label)
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
icmp6_to_icmp (vlib_main_t * vm, vlib_buffer_t * p,
	       ip6_to_ip4_icmp_set_fn_t fn, void *ctx,
	       ip6_to_ip4_icmp_set_fn_t inner_fn, void *inner_ctx)
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

      if (ip6_parse (vm, p, inner_ip6, ip6_pay_len - 8,
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
      inner_ip4->tos =
	ip6_translate_tos
	(inner_ip6->ip_version_traffic_class_and_flow_label);
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
      clib_memcpy_fast (u8_ptr_add (inner_l4, -sizeof (*ip4) - 8), icmp, 8);
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
  ip4->tos = ip6_translate_tos (ip6->ip_version_traffic_class_and_flow_label);
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

#endif /* __included_ip6_to_ip4_h__ */
