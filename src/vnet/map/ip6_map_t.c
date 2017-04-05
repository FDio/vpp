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

#define IP6_MAP_T_DUAL_LOOP

typedef enum
{
  IP6_MAPT_NEXT_MAPT_TCP_UDP,
  IP6_MAPT_NEXT_MAPT_ICMP,
  IP6_MAPT_NEXT_MAPT_FRAGMENTED,
  IP6_MAPT_NEXT_DROP,
  IP6_MAPT_N_NEXT
} ip6_mapt_next_t;

typedef enum
{
  IP6_MAPT_ICMP_NEXT_IP4_LOOKUP,
  IP6_MAPT_ICMP_NEXT_IP4_FRAG,
  IP6_MAPT_ICMP_NEXT_DROP,
  IP6_MAPT_ICMP_N_NEXT
} ip6_mapt_icmp_next_t;

typedef enum
{
  IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP,
  IP6_MAPT_TCP_UDP_NEXT_IP4_FRAG,
  IP6_MAPT_TCP_UDP_NEXT_DROP,
  IP6_MAPT_TCP_UDP_N_NEXT
} ip6_mapt_tcp_udp_next_t;

typedef enum
{
  IP6_MAPT_FRAGMENTED_NEXT_IP4_LOOKUP,
  IP6_MAPT_FRAGMENTED_NEXT_IP4_FRAG,
  IP6_MAPT_FRAGMENTED_NEXT_DROP,
  IP6_MAPT_FRAGMENTED_N_NEXT
} ip6_mapt_fragmented_next_t;

static_always_inline int
ip6_map_fragment_cache (ip6_header_t * ip6, ip6_frag_hdr_t * frag,
			map_domain_t * d, u16 port)
{
  u32 *ignore = NULL;
  map_ip4_reass_lock ();
  map_ip4_reass_t *r = map_ip4_reass_get (map_get_ip4 (&ip6->src_address),
					  ip6_map_t_embedded_address (d,
								      &ip6->
								      dst_address),
					  frag_id_6to4 (frag->identification),
					  (ip6->protocol ==
					   IP_PROTOCOL_ICMP6) ?
					  IP_PROTOCOL_ICMP : ip6->protocol,
					  &ignore);
  if (r)
    r->port = port;

  map_ip4_reass_unlock ();
  return !r;
}

/* Returns the associated port or -1 */
static_always_inline i32
ip6_map_fragment_get (ip6_header_t * ip6, ip6_frag_hdr_t * frag,
		      map_domain_t * d)
{
  u32 *ignore = NULL;
  map_ip4_reass_lock ();
  map_ip4_reass_t *r = map_ip4_reass_get (map_get_ip4 (&ip6->src_address),
					  ip6_map_t_embedded_address (d,
								      &ip6->
								      dst_address),
					  frag_id_6to4 (frag->identification),
					  (ip6->protocol ==
					   IP_PROTOCOL_ICMP6) ?
					  IP_PROTOCOL_ICMP : ip6->protocol,
					  &ignore);
  i32 ret = r ? r->port : -1;
  map_ip4_reass_unlock ();
  return ret;
}

static_always_inline u8
ip6_translate_tos (const ip6_header_t * ip6)
{
#ifdef IP6_MAP_T_OVERRIDE_TOS
  return IP6_MAP_T_OVERRIDE_TOS;
#else
  return (clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label)
	  & 0x0ff00000) >> 20;
#endif
}

//TODO: Find right place in memory for that
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

static_always_inline int
ip6_icmp_to_icmp6_in_place (icmp46_header_t * icmp, u32 icmp_len,
			    i32 * sender_port, ip6_header_t ** inner_ip6)
{
  *inner_ip6 = NULL;
  switch (icmp->type)
    {
    case ICMP6_echo_request:
      *sender_port = ((u16 *) icmp)[2];
      icmp->type = ICMP4_echo_request;
      break;
    case ICMP6_echo_reply:
      *sender_port = ((u16 *) icmp)[2];
      icmp->type = ICMP4_echo_reply;
      break;
    case ICMP6_destination_unreachable:
      *inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);
      *sender_port = ip6_get_port (*inner_ip6, MAP_RECEIVER, icmp_len);

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
      *sender_port = ip6_get_port (*inner_ip6, MAP_RECEIVER, icmp_len);

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
      *sender_port = ip6_get_port (*inner_ip6, MAP_RECEIVER, icmp_len);

      icmp->type = ICMP4_time_exceeded;
      break;

    case ICMP6_parameter_problem:
      *inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);
      *sender_port = ip6_get_port (*inner_ip6, MAP_RECEIVER, icmp_len);

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

static_always_inline void
_ip6_map_t_icmp (map_domain_t * d, vlib_buffer_t * p, u8 * error)
{
  ip6_header_t *ip6, *inner_ip6;
  ip4_header_t *ip4, *inner_ip4;
  u32 ip6_pay_len;
  icmp46_header_t *icmp;
  i32 sender_port;
  ip_csum_t csum;
  u32 ip4_sadr, inner_ip4_dadr;

  ip6 = vlib_buffer_get_current (p);
  ip6_pay_len = clib_net_to_host_u16 (ip6->payload_length);
  icmp = (icmp46_header_t *) (ip6 + 1);
  ASSERT (ip6_pay_len + sizeof (*ip6) <= p->current_length);

  if (ip6->protocol != IP_PROTOCOL_ICMP6)
    {
      //No extensions headers allowed here
      //TODO: SR header
      *error = MAP_ERROR_MALFORMED;
      return;
    }

  //There are no fragmented ICMP messages, so no extension header for now

  if (ip6_icmp_to_icmp6_in_place
      (icmp, ip6_pay_len, &sender_port, &inner_ip6))
    {
      //TODO: In case of 1:1 mapping it is not necessary to have the sender port
      *error = MAP_ERROR_ICMP;
      return;
    }

  if (sender_port < 0)
    {
      // In case of 1:1 mapping, we don't care about the port
      if (d->ea_bits_len == 0 && d->rules)
	{
	  sender_port = 0;
	}
      else
	{
	  *error = MAP_ERROR_ICMP;
	  return;
	}
    }

  //Security check
  //Note that this prevents an intermediate IPv6 router from answering the request
  ip4_sadr = map_get_ip4 (&ip6->src_address);
  if (ip6->src_address.as_u64[0] != map_get_pfx_net (d, ip4_sadr, sender_port)
      || ip6->src_address.as_u64[1] != map_get_sfx_net (d, ip4_sadr,
							sender_port))
    {
      *error = MAP_ERROR_SEC_CHECK;
      return;
    }

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

      //TODO: This was already done deep in ip6_icmp_to_icmp6_in_place
      //We shouldn't have to do it again
      if (ip6_parse (inner_ip6, ip6_pay_len - 8,
		     &inner_protocol, &inner_l4_offset, &inner_frag_offset))
	{
	  *error = MAP_ERROR_MALFORMED;
	  return;
	}

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
	  csum = inner_icmp->checksum;
	  csum = ip_csum_sub_even (csum, *((u16 *) inner_icmp));
	  //It cannot be of a different type as ip6_icmp_to_icmp6_in_place succeeded
	  inner_icmp->type = (inner_icmp->type == ICMP6_echo_request) ?
	    ICMP4_echo_request : ICMP4_echo_reply;
	  csum = ip_csum_add_even (csum, *((u16 *) inner_icmp));
	  inner_icmp->checksum = ip_csum_fold (csum);
	  inner_protocol = IP_PROTOCOL_ICMP;	//Will be copied to ip6 later
	  inner_L4_checksum = &inner_icmp->checksum;
	}
      else
	{
	  *error = MAP_ERROR_BAD_PROTOCOL;
	  return;
	}

      csum = *inner_L4_checksum;
      csum = ip_csum_sub_even (csum, inner_ip6->src_address.as_u64[0]);
      csum = ip_csum_sub_even (csum, inner_ip6->src_address.as_u64[1]);
      csum = ip_csum_sub_even (csum, inner_ip6->dst_address.as_u64[0]);
      csum = ip_csum_sub_even (csum, inner_ip6->dst_address.as_u64[1]);

      //Sanity check of the outer destination address
      if (ip6->dst_address.as_u64[0] != inner_ip6->src_address.as_u64[0] &&
	  ip6->dst_address.as_u64[1] != inner_ip6->src_address.as_u64[1])
	{
	  *error = MAP_ERROR_SEC_CHECK;
	  return;
	}

      //Security check of inner packet
      inner_ip4_dadr = map_get_ip4 (&inner_ip6->dst_address);
      if (inner_ip6->dst_address.as_u64[0] !=
	  map_get_pfx_net (d, inner_ip4_dadr, sender_port)
	  || inner_ip6->dst_address.as_u64[1] != map_get_sfx_net (d,
								  inner_ip4_dadr,
								  sender_port))
	{
	  *error = MAP_ERROR_SEC_CHECK;
	  return;
	}

      inner_ip4->dst_address.as_u32 = inner_ip4_dadr;
      inner_ip4->src_address.as_u32 =
	ip6_map_t_embedded_address (d, &inner_ip6->src_address);
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
	  //Remove remainings of the pseudo-header in the csum
	  csum =
	    ip_csum_sub_even (csum, clib_host_to_net_u16 (IP_PROTOCOL_ICMP6));
	  csum =
	    ip_csum_sub_even (csum, inner_ip4->length - sizeof (*inner_ip4));
	}
      else
	{
	  //Update to new pseudo-header
	  csum = ip_csum_add_even (csum, inner_ip4->src_address.as_u32);
	  csum = ip_csum_add_even (csum, inner_ip4->dst_address.as_u32);
	}
      *inner_L4_checksum = ip_csum_fold (csum);

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

  ip4->dst_address.as_u32 = ip6_map_t_embedded_address (d, &ip6->dst_address);
  ip4->src_address.as_u32 = ip4_sadr;
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

  //TODO: We could do an easy diff-checksum for echo requests/replies
  //Recompute ICMP checksum
  icmp->checksum = 0;
  csum =
    ip_incremental_checksum (0, icmp,
			     clib_net_to_host_u16 (ip4->length) -
			     sizeof (*ip4));
  icmp->checksum = ~ip_csum_fold (csum);
}

static uword
ip6_map_t_icmp (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_t_icmp_node.index);
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
	  u8 error0;
	  ip6_mapt_icmp_next_t next0;
	  map_domain_t *d0;
	  u16 len0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  error0 = MAP_ERROR_NONE;
	  next0 = IP6_MAPT_ICMP_NEXT_IP4_LOOKUP;

	  p0 = vlib_get_buffer (vm, pi0);
	  len0 =
	    clib_net_to_host_u16 (((ip6_header_t *)
				   vlib_buffer_get_current
				   (p0))->payload_length);
	  d0 =
	    pool_elt_at_index (map_main.domains,
			       vnet_buffer (p0)->map_t.map_domain_index);
	  _ip6_map_t_icmp (d0, p0, &error0);

	  if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
	    {
	      //Send to fragmentation node if necessary
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.header_offset = 0;
	      vnet_buffer (p0)->ip_frag.next_index = IP4_FRAG_NEXT_IP4_LOOKUP;
	      next0 = IP6_MAPT_ICMP_NEXT_IP4_FRAG;
	    }

	  if (PREDICT_TRUE (error0 == MAP_ERROR_NONE))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_RX,
					       thread_index,
					       vnet_buffer (p0)->
					       map_t.map_domain_index, 1,
					       len0);
	    }
	  else
	    {
	      next0 = IP6_MAPT_ICMP_NEXT_DROP;
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
ip6_map_t_fragmented (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

#ifdef IP6_MAP_T_DUAL_LOOP
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 pi0, pi1;
	  vlib_buffer_t *p0, *p1;
	  ip6_header_t *ip60, *ip61;
	  ip6_frag_hdr_t *frag0, *frag1;
	  ip4_header_t *ip40, *ip41;
	  u16 frag_id0, frag_offset0, frag_id1, frag_offset1;
	  u8 frag_more0, frag_more1;
	  u32 next0, next1;

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  next0 = IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP;
	  next1 = IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP;
	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);
	  ip60 = vlib_buffer_get_current (p0);
	  ip61 = vlib_buffer_get_current (p1);
	  frag0 =
	    (ip6_frag_hdr_t *) u8_ptr_add (ip60,
					   vnet_buffer (p0)->map_t.
					   v6.frag_offset);
	  frag1 =
	    (ip6_frag_hdr_t *) u8_ptr_add (ip61,
					   vnet_buffer (p1)->map_t.
					   v6.frag_offset);
	  ip40 =
	    (ip4_header_t *) u8_ptr_add (ip60,
					 vnet_buffer (p0)->map_t.
					 v6.l4_offset - sizeof (*ip40));
	  ip41 =
	    (ip4_header_t *) u8_ptr_add (ip61,
					 vnet_buffer (p1)->map_t.
					 v6.l4_offset - sizeof (*ip40));
	  vlib_buffer_advance (p0,
			       vnet_buffer (p0)->map_t.v6.l4_offset -
			       sizeof (*ip40));
	  vlib_buffer_advance (p1,
			       vnet_buffer (p1)->map_t.v6.l4_offset -
			       sizeof (*ip40));

	  frag_id0 = frag_id_6to4 (frag0->identification);
	  frag_id1 = frag_id_6to4 (frag1->identification);
	  frag_more0 = ip6_frag_hdr_more (frag0);
	  frag_more1 = ip6_frag_hdr_more (frag1);
	  frag_offset0 = ip6_frag_hdr_offset (frag0);
	  frag_offset1 = ip6_frag_hdr_offset (frag1);

	  ip40->dst_address.as_u32 = vnet_buffer (p0)->map_t.v6.daddr;
	  ip41->dst_address.as_u32 = vnet_buffer (p1)->map_t.v6.daddr;
	  ip40->src_address.as_u32 = vnet_buffer (p0)->map_t.v6.saddr;
	  ip41->src_address.as_u32 = vnet_buffer (p1)->map_t.v6.saddr;
	  ip40->ip_version_and_header_length =
	    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
	  ip41->ip_version_and_header_length =
	    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
	  ip40->tos = ip6_translate_tos (ip60);
	  ip41->tos = ip6_translate_tos (ip61);
	  ip40->length = u16_net_add (ip60->payload_length,
				      sizeof (*ip40) -
				      vnet_buffer (p0)->map_t.v6.l4_offset +
				      sizeof (*ip60));
	  ip41->length =
	    u16_net_add (ip61->payload_length,
			 sizeof (*ip40) -
			 vnet_buffer (p1)->map_t.v6.l4_offset +
			 sizeof (*ip60));
	  ip40->fragment_id = frag_id0;
	  ip41->fragment_id = frag_id1;
	  ip40->flags_and_fragment_offset =
	    clib_host_to_net_u16 (frag_offset0 |
				  (frag_more0 ? IP4_HEADER_FLAG_MORE_FRAGMENTS
				   : 0));
	  ip41->flags_and_fragment_offset =
	    clib_host_to_net_u16 (frag_offset1 |
				  (frag_more1 ? IP4_HEADER_FLAG_MORE_FRAGMENTS
				   : 0));
	  ip40->ttl = ip60->hop_limit;
	  ip41->ttl = ip61->hop_limit;
	  ip40->protocol =
	    (vnet_buffer (p0)->map_t.v6.l4_protocol ==
	     IP_PROTOCOL_ICMP6) ? IP_PROTOCOL_ICMP : vnet_buffer (p0)->
	    map_t.v6.l4_protocol;
	  ip41->protocol =
	    (vnet_buffer (p1)->map_t.v6.l4_protocol ==
	     IP_PROTOCOL_ICMP6) ? IP_PROTOCOL_ICMP : vnet_buffer (p1)->
	    map_t.v6.l4_protocol;
	  ip40->checksum = ip4_header_checksum (ip40);
	  ip41->checksum = ip4_header_checksum (ip41);

	  if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
	    {
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.header_offset = 0;
	      vnet_buffer (p0)->ip_frag.next_index = IP4_FRAG_NEXT_IP4_LOOKUP;
	      next0 = IP6_MAPT_FRAGMENTED_NEXT_IP4_FRAG;
	    }

	  if (vnet_buffer (p1)->map_t.mtu < p1->current_length)
	    {
	      vnet_buffer (p1)->ip_frag.mtu = vnet_buffer (p1)->map_t.mtu;
	      vnet_buffer (p1)->ip_frag.header_offset = 0;
	      vnet_buffer (p1)->ip_frag.next_index = IP4_FRAG_NEXT_IP4_LOOKUP;
	      next1 = IP6_MAPT_FRAGMENTED_NEXT_IP4_FRAG;
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
	  ip6_header_t *ip60;
	  ip6_frag_hdr_t *frag0;
	  ip4_header_t *ip40;
	  u16 frag_id0;
	  u8 frag_more0;
	  u16 frag_offset0;
	  u32 next0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  next0 = IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP;
	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current (p0);
	  frag0 =
	    (ip6_frag_hdr_t *) u8_ptr_add (ip60,
					   vnet_buffer (p0)->map_t.
					   v6.frag_offset);
	  ip40 =
	    (ip4_header_t *) u8_ptr_add (ip60,
					 vnet_buffer (p0)->map_t.
					 v6.l4_offset - sizeof (*ip40));
	  vlib_buffer_advance (p0,
			       vnet_buffer (p0)->map_t.v6.l4_offset -
			       sizeof (*ip40));

	  frag_id0 = frag_id_6to4 (frag0->identification);
	  frag_more0 = ip6_frag_hdr_more (frag0);
	  frag_offset0 = ip6_frag_hdr_offset (frag0);

	  ip40->dst_address.as_u32 = vnet_buffer (p0)->map_t.v6.daddr;
	  ip40->src_address.as_u32 = vnet_buffer (p0)->map_t.v6.saddr;
	  ip40->ip_version_and_header_length =
	    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
	  ip40->tos = ip6_translate_tos (ip60);
	  ip40->length = u16_net_add (ip60->payload_length,
				      sizeof (*ip40) -
				      vnet_buffer (p0)->map_t.v6.l4_offset +
				      sizeof (*ip60));
	  ip40->fragment_id = frag_id0;
	  ip40->flags_and_fragment_offset =
	    clib_host_to_net_u16 (frag_offset0 |
				  (frag_more0 ? IP4_HEADER_FLAG_MORE_FRAGMENTS
				   : 0));
	  ip40->ttl = ip60->hop_limit;
	  ip40->protocol =
	    (vnet_buffer (p0)->map_t.v6.l4_protocol ==
	     IP_PROTOCOL_ICMP6) ? IP_PROTOCOL_ICMP : vnet_buffer (p0)->
	    map_t.v6.l4_protocol;
	  ip40->checksum = ip4_header_checksum (ip40);

	  if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
	    {
	      //Send to fragmentation node if necessary
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.header_offset = 0;
	      vnet_buffer (p0)->ip_frag.next_index = IP4_FRAG_NEXT_IP4_LOOKUP;
	      next0 = IP6_MAPT_FRAGMENTED_NEXT_IP4_FRAG;
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
ip6_map_t_tcp_udp (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

#ifdef IP6_MAP_T_DUAL_LOOP
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 pi0, pi1;
	  vlib_buffer_t *p0, *p1;
	  ip6_header_t *ip60, *ip61;
	  ip_csum_t csum0, csum1;
	  ip4_header_t *ip40, *ip41;
	  u16 fragment_id0, flags0, *checksum0,
	    fragment_id1, flags1, *checksum1;
	  ip6_mapt_tcp_udp_next_t next0, next1;

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  next0 = IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP;
	  next1 = IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);
	  ip60 = vlib_buffer_get_current (p0);
	  ip61 = vlib_buffer_get_current (p1);
	  ip40 =
	    (ip4_header_t *) u8_ptr_add (ip60,
					 vnet_buffer (p0)->map_t.
					 v6.l4_offset - sizeof (*ip40));
	  ip41 =
	    (ip4_header_t *) u8_ptr_add (ip61,
					 vnet_buffer (p1)->map_t.
					 v6.l4_offset - sizeof (*ip40));
	  vlib_buffer_advance (p0,
			       vnet_buffer (p0)->map_t.v6.l4_offset -
			       sizeof (*ip40));
	  vlib_buffer_advance (p1,
			       vnet_buffer (p1)->map_t.v6.l4_offset -
			       sizeof (*ip40));
	  checksum0 =
	    (u16 *) u8_ptr_add (ip60,
				vnet_buffer (p0)->map_t.checksum_offset);
	  checksum1 =
	    (u16 *) u8_ptr_add (ip61,
				vnet_buffer (p1)->map_t.checksum_offset);

	  csum0 = ip_csum_sub_even (*checksum0, ip60->src_address.as_u64[0]);
	  csum1 = ip_csum_sub_even (*checksum1, ip61->src_address.as_u64[0]);
	  csum0 = ip_csum_sub_even (csum0, ip60->src_address.as_u64[1]);
	  csum1 = ip_csum_sub_even (csum1, ip61->src_address.as_u64[1]);
	  csum0 = ip_csum_sub_even (csum0, ip60->dst_address.as_u64[0]);
	  csum1 = ip_csum_sub_even (csum0, ip61->dst_address.as_u64[0]);
	  csum0 = ip_csum_sub_even (csum0, ip60->dst_address.as_u64[1]);
	  csum1 = ip_csum_sub_even (csum1, ip61->dst_address.as_u64[1]);
	  csum0 = ip_csum_add_even (csum0, vnet_buffer (p0)->map_t.v6.daddr);
	  csum1 = ip_csum_add_even (csum1, vnet_buffer (p1)->map_t.v6.daddr);
	  csum0 = ip_csum_add_even (csum0, vnet_buffer (p0)->map_t.v6.saddr);
	  csum1 = ip_csum_add_even (csum1, vnet_buffer (p1)->map_t.v6.saddr);
	  *checksum0 = ip_csum_fold (csum0);
	  *checksum1 = ip_csum_fold (csum1);

	  if (PREDICT_FALSE (vnet_buffer (p0)->map_t.v6.frag_offset))
	    {
	      ip6_frag_hdr_t *hdr = (ip6_frag_hdr_t *) u8_ptr_add (ip60,
								   vnet_buffer
								   (p0)->
								   map_t.
								   v6.frag_offset);
	      fragment_id0 = frag_id_6to4 (hdr->identification);
	      flags0 = clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
	    }
	  else
	    {
	      fragment_id0 = 0;
	      flags0 = 0;
	    }

	  if (PREDICT_FALSE (vnet_buffer (p1)->map_t.v6.frag_offset))
	    {
	      ip6_frag_hdr_t *hdr = (ip6_frag_hdr_t *) u8_ptr_add (ip61,
								   vnet_buffer
								   (p1)->
								   map_t.
								   v6.frag_offset);
	      fragment_id1 = frag_id_6to4 (hdr->identification);
	      flags1 = clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
	    }
	  else
	    {
	      fragment_id1 = 0;
	      flags1 = 0;
	    }

	  ip40->dst_address.as_u32 = vnet_buffer (p0)->map_t.v6.daddr;
	  ip41->dst_address.as_u32 = vnet_buffer (p1)->map_t.v6.daddr;
	  ip40->src_address.as_u32 = vnet_buffer (p0)->map_t.v6.saddr;
	  ip41->src_address.as_u32 = vnet_buffer (p1)->map_t.v6.saddr;
	  ip40->ip_version_and_header_length =
	    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
	  ip41->ip_version_and_header_length =
	    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
	  ip40->tos = ip6_translate_tos (ip60);
	  ip41->tos = ip6_translate_tos (ip61);
	  ip40->length = u16_net_add (ip60->payload_length,
				      sizeof (*ip40) + sizeof (*ip60) -
				      vnet_buffer (p0)->map_t.v6.l4_offset);
	  ip41->length =
	    u16_net_add (ip61->payload_length,
			 sizeof (*ip40) + sizeof (*ip60) -
			 vnet_buffer (p1)->map_t.v6.l4_offset);
	  ip40->fragment_id = fragment_id0;
	  ip41->fragment_id = fragment_id1;
	  ip40->flags_and_fragment_offset = flags0;
	  ip41->flags_and_fragment_offset = flags1;
	  ip40->ttl = ip60->hop_limit;
	  ip41->ttl = ip61->hop_limit;
	  ip40->protocol = vnet_buffer (p0)->map_t.v6.l4_protocol;
	  ip41->protocol = vnet_buffer (p1)->map_t.v6.l4_protocol;
	  ip40->checksum = ip4_header_checksum (ip40);
	  ip41->checksum = ip4_header_checksum (ip41);

	  if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
	    {
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.header_offset = 0;
	      vnet_buffer (p0)->ip_frag.next_index = IP4_FRAG_NEXT_IP4_LOOKUP;
	      next0 = IP6_MAPT_TCP_UDP_NEXT_IP4_FRAG;
	    }

	  if (vnet_buffer (p1)->map_t.mtu < p1->current_length)
	    {
	      vnet_buffer (p1)->ip_frag.mtu = vnet_buffer (p1)->map_t.mtu;
	      vnet_buffer (p1)->ip_frag.header_offset = 0;
	      vnet_buffer (p1)->ip_frag.next_index = IP4_FRAG_NEXT_IP4_LOOKUP;
	      next1 = IP6_MAPT_TCP_UDP_NEXT_IP4_FRAG;
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, pi1, next0,
					   next1);
	}
#endif

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  ip6_header_t *ip60;
	  u16 *checksum0;
	  ip_csum_t csum0;
	  ip4_header_t *ip40;
	  u16 fragment_id0;
	  u16 flags0;
	  ip6_mapt_tcp_udp_next_t next0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  next0 = IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current (p0);
	  ip40 =
	    (ip4_header_t *) u8_ptr_add (ip60,
					 vnet_buffer (p0)->map_t.
					 v6.l4_offset - sizeof (*ip40));
	  vlib_buffer_advance (p0,
			       vnet_buffer (p0)->map_t.v6.l4_offset -
			       sizeof (*ip40));
	  checksum0 =
	    (u16 *) u8_ptr_add (ip60,
				vnet_buffer (p0)->map_t.checksum_offset);

	  //TODO: This can probably be optimized
	  csum0 = ip_csum_sub_even (*checksum0, ip60->src_address.as_u64[0]);
	  csum0 = ip_csum_sub_even (csum0, ip60->src_address.as_u64[1]);
	  csum0 = ip_csum_sub_even (csum0, ip60->dst_address.as_u64[0]);
	  csum0 = ip_csum_sub_even (csum0, ip60->dst_address.as_u64[1]);
	  csum0 = ip_csum_add_even (csum0, vnet_buffer (p0)->map_t.v6.daddr);
	  csum0 = ip_csum_add_even (csum0, vnet_buffer (p0)->map_t.v6.saddr);
	  *checksum0 = ip_csum_fold (csum0);

	  if (PREDICT_FALSE (vnet_buffer (p0)->map_t.v6.frag_offset))
	    {
	      //Only the first fragment
	      ip6_frag_hdr_t *hdr = (ip6_frag_hdr_t *) u8_ptr_add (ip60,
								   vnet_buffer
								   (p0)->
								   map_t.
								   v6.frag_offset);
	      fragment_id0 = frag_id_6to4 (hdr->identification);
	      flags0 = clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
	    }
	  else
	    {
	      fragment_id0 = 0;
	      flags0 = 0;
	    }

	  ip40->dst_address.as_u32 = vnet_buffer (p0)->map_t.v6.daddr;
	  ip40->src_address.as_u32 = vnet_buffer (p0)->map_t.v6.saddr;
	  ip40->ip_version_and_header_length =
	    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
	  ip40->tos = ip6_translate_tos (ip60);
	  ip40->length = u16_net_add (ip60->payload_length,
				      sizeof (*ip40) + sizeof (*ip60) -
				      vnet_buffer (p0)->map_t.v6.l4_offset);
	  ip40->fragment_id = fragment_id0;
	  ip40->flags_and_fragment_offset = flags0;
	  ip40->ttl = ip60->hop_limit;
	  ip40->protocol = vnet_buffer (p0)->map_t.v6.l4_protocol;
	  ip40->checksum = ip4_header_checksum (ip40);

	  if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
	    {
	      //Send to fragmentation node if necessary
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.header_offset = 0;
	      vnet_buffer (p0)->ip_frag.next_index = IP4_FRAG_NEXT_IP4_LOOKUP;
	      next0 = IP6_MAPT_TCP_UDP_NEXT_IP4_FRAG;
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
ip6_map_t_classify (vlib_buffer_t * p0, ip6_header_t * ip60,
		    map_domain_t * d0, i32 * src_port0,
		    u8 * error0, ip6_mapt_next_t * next0,
		    u32 l4_len0, ip6_frag_hdr_t * frag0)
{
  if (PREDICT_FALSE (vnet_buffer (p0)->map_t.v6.frag_offset &&
		     ip6_frag_hdr_offset (frag0)))
    {
      *next0 = IP6_MAPT_NEXT_MAPT_FRAGMENTED;
      if (d0->ea_bits_len == 0 && d0->rules)
	{
	  *src_port0 = 0;
	}
      else
	{
	  *src_port0 = ip6_map_fragment_get (ip60, frag0, d0);
	  *error0 = (*src_port0 != -1) ? *error0 : MAP_ERROR_FRAGMENT_DROPPED;
	}
    }
  else
    if (PREDICT_TRUE
	(vnet_buffer (p0)->map_t.v6.l4_protocol == IP_PROTOCOL_TCP))
    {
      *error0 =
	l4_len0 < sizeof (tcp_header_t) ? MAP_ERROR_MALFORMED : *error0;
      vnet_buffer (p0)->map_t.checksum_offset =
	vnet_buffer (p0)->map_t.v6.l4_offset + 16;
      *next0 = IP6_MAPT_NEXT_MAPT_TCP_UDP;
      *src_port0 =
	(i32) *
	((u16 *) u8_ptr_add (ip60, vnet_buffer (p0)->map_t.v6.l4_offset));
    }
  else
    if (PREDICT_TRUE
	(vnet_buffer (p0)->map_t.v6.l4_protocol == IP_PROTOCOL_UDP))
    {
      *error0 =
	l4_len0 < sizeof (udp_header_t) ? MAP_ERROR_MALFORMED : *error0;
      vnet_buffer (p0)->map_t.checksum_offset =
	vnet_buffer (p0)->map_t.v6.l4_offset + 6;
      *next0 = IP6_MAPT_NEXT_MAPT_TCP_UDP;
      *src_port0 =
	(i32) *
	((u16 *) u8_ptr_add (ip60, vnet_buffer (p0)->map_t.v6.l4_offset));
    }
  else if (vnet_buffer (p0)->map_t.v6.l4_protocol == IP_PROTOCOL_ICMP6)
    {
      *error0 =
	l4_len0 < sizeof (icmp46_header_t) ? MAP_ERROR_MALFORMED : *error0;
      *next0 = IP6_MAPT_NEXT_MAPT_ICMP;
      if (d0->ea_bits_len == 0 && d0->rules)
	{
	  *src_port0 = 0;
	}
      else
	if (((icmp46_header_t *)
	     u8_ptr_add (ip60,
			 vnet_buffer (p0)->map_t.v6.l4_offset))->code ==
	    ICMP6_echo_reply
	    || ((icmp46_header_t *)
		u8_ptr_add (ip60,
			    vnet_buffer (p0)->map_t.v6.l4_offset))->code ==
	    ICMP6_echo_request)
	{
	  *src_port0 =
	    (i32) *
	    ((u16 *)
	     u8_ptr_add (ip60, vnet_buffer (p0)->map_t.v6.l4_offset + 6));
	}
    }
  else
    {
      //TODO: In case of 1:1 mapping, it might be possible to do something with those packets.
      *error0 = MAP_ERROR_BAD_PROTOCOL;
    }
}

static uword
ip6_map_t (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_t_node.index);
  vlib_combined_counter_main_t *cm = map_main.domain_counters;
  u32 thread_index = vlib_get_thread_index ();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

#ifdef IP6_MAP_T_DUAL_LOOP
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 pi0, pi1;
	  vlib_buffer_t *p0, *p1;
	  ip6_header_t *ip60, *ip61;
	  u8 error0, error1;
	  ip6_mapt_next_t next0, next1;
	  u32 l4_len0, l4_len1;
	  i32 src_port0, src_port1;
	  map_domain_t *d0, *d1;
	  ip6_frag_hdr_t *frag0, *frag1;
	  u32 saddr0, saddr1;
	  next0 = next1 = 0;	//Because compiler whines

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
	  ip60 = vlib_buffer_get_current (p0);
	  ip61 = vlib_buffer_get_current (p1);

	  saddr0 = map_get_ip4 (&ip60->src_address);
	  saddr1 = map_get_ip4 (&ip61->src_address);
	  d0 = ip6_map_get_domain (vnet_buffer (p0)->ip.adj_index[VLIB_TX],
				   (ip4_address_t *) & saddr0,
				   &vnet_buffer (p0)->map_t.map_domain_index,
				   &error0);
	  d1 =
	    ip6_map_get_domain (vnet_buffer (p1)->ip.adj_index[VLIB_TX],
				(ip4_address_t *) & saddr1,
				&vnet_buffer (p1)->map_t.map_domain_index,
				&error1);

	  vnet_buffer (p0)->map_t.v6.saddr = saddr0;
	  vnet_buffer (p1)->map_t.v6.saddr = saddr1;
	  vnet_buffer (p0)->map_t.v6.daddr =
	    ip6_map_t_embedded_address (d0, &ip60->dst_address);
	  vnet_buffer (p1)->map_t.v6.daddr =
	    ip6_map_t_embedded_address (d1, &ip61->dst_address);
	  vnet_buffer (p0)->map_t.mtu = d0->mtu ? d0->mtu : ~0;
	  vnet_buffer (p1)->map_t.mtu = d1->mtu ? d1->mtu : ~0;

	  if (PREDICT_FALSE (ip6_parse (ip60, p0->current_length,
					&(vnet_buffer (p0)->map_t.
					  v6.l4_protocol),
					&(vnet_buffer (p0)->map_t.
					  v6.l4_offset),
					&(vnet_buffer (p0)->map_t.
					  v6.frag_offset))))
	    {
	      error0 = MAP_ERROR_MALFORMED;
	      next0 = IP6_MAPT_NEXT_DROP;
	    }

	  if (PREDICT_FALSE (ip6_parse (ip61, p1->current_length,
					&(vnet_buffer (p1)->map_t.
					  v6.l4_protocol),
					&(vnet_buffer (p1)->map_t.
					  v6.l4_offset),
					&(vnet_buffer (p1)->map_t.
					  v6.frag_offset))))
	    {
	      error1 = MAP_ERROR_MALFORMED;
	      next1 = IP6_MAPT_NEXT_DROP;
	    }

	  src_port0 = src_port1 = -1;
	  l4_len0 = (u32) clib_net_to_host_u16 (ip60->payload_length) +
	    sizeof (*ip60) - vnet_buffer (p0)->map_t.v6.l4_offset;
	  l4_len1 = (u32) clib_net_to_host_u16 (ip61->payload_length) +
	    sizeof (*ip60) - vnet_buffer (p1)->map_t.v6.l4_offset;
	  frag0 =
	    (ip6_frag_hdr_t *) u8_ptr_add (ip60,
					   vnet_buffer (p0)->map_t.
					   v6.frag_offset);
	  frag1 =
	    (ip6_frag_hdr_t *) u8_ptr_add (ip61,
					   vnet_buffer (p1)->map_t.
					   v6.frag_offset);

	  ip6_map_t_classify (p0, ip60, d0, &src_port0, &error0, &next0,
			      l4_len0, frag0);
	  ip6_map_t_classify (p1, ip61, d1, &src_port1, &error1, &next1,
			      l4_len1, frag1);

	  if (PREDICT_FALSE
	      ((src_port0 != -1)
	       && (ip60->src_address.as_u64[0] !=
		   map_get_pfx_net (d0, vnet_buffer (p0)->map_t.v6.saddr,
				    src_port0)
		   || ip60->src_address.as_u64[1] != map_get_sfx_net (d0,
								      vnet_buffer
								      (p0)->map_t.v6.saddr,
								      src_port0))))
	    {
	      error0 = MAP_ERROR_SEC_CHECK;
	    }

	  if (PREDICT_FALSE
	      ((src_port1 != -1)
	       && (ip61->src_address.as_u64[0] !=
		   map_get_pfx_net (d1, vnet_buffer (p1)->map_t.v6.saddr,
				    src_port1)
		   || ip61->src_address.as_u64[1] != map_get_sfx_net (d1,
								      vnet_buffer
								      (p1)->map_t.v6.saddr,
								      src_port1))))
	    {
	      error1 = MAP_ERROR_SEC_CHECK;
	    }

	  if (PREDICT_FALSE (vnet_buffer (p0)->map_t.v6.frag_offset &&
			     !ip6_frag_hdr_offset ((ip6_frag_hdr_t *)
						   u8_ptr_add (ip60,
							       vnet_buffer
							       (p0)->map_t.
							       v6.frag_offset)))
	      && (src_port0 != -1) && (d0->ea_bits_len != 0 || !d0->rules)
	      && (error0 == MAP_ERROR_NONE))
	    {
	      ip6_map_fragment_cache (ip60,
				      (ip6_frag_hdr_t *) u8_ptr_add (ip60,
								     vnet_buffer
								     (p0)->map_t.
								     v6.frag_offset),
				      d0, src_port0);
	    }

	  if (PREDICT_FALSE (vnet_buffer (p1)->map_t.v6.frag_offset &&
			     !ip6_frag_hdr_offset ((ip6_frag_hdr_t *)
						   u8_ptr_add (ip61,
							       vnet_buffer
							       (p1)->map_t.
							       v6.frag_offset)))
	      && (src_port1 != -1) && (d1->ea_bits_len != 0 || !d1->rules)
	      && (error1 == MAP_ERROR_NONE))
	    {
	      ip6_map_fragment_cache (ip61,
				      (ip6_frag_hdr_t *) u8_ptr_add (ip61,
								     vnet_buffer
								     (p1)->map_t.
								     v6.frag_offset),
				      d1, src_port1);
	    }

	  if (PREDICT_TRUE
	      (error0 == MAP_ERROR_NONE && next0 != IP6_MAPT_NEXT_MAPT_ICMP))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_RX,
					       thread_index,
					       vnet_buffer (p0)->
					       map_t.map_domain_index, 1,
					       clib_net_to_host_u16
					       (ip60->payload_length));
	    }

	  if (PREDICT_TRUE
	      (error1 == MAP_ERROR_NONE && next1 != IP6_MAPT_NEXT_MAPT_ICMP))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_RX,
					       thread_index,
					       vnet_buffer (p1)->
					       map_t.map_domain_index, 1,
					       clib_net_to_host_u16
					       (ip61->payload_length));
	    }

	  next0 = (error0 != MAP_ERROR_NONE) ? IP6_MAPT_NEXT_DROP : next0;
	  next1 = (error1 != MAP_ERROR_NONE) ? IP6_MAPT_NEXT_DROP : next1;
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
	  ip6_header_t *ip60;
	  u8 error0;
	  u32 l4_len0;
	  i32 src_port0;
	  map_domain_t *d0;
	  ip6_frag_hdr_t *frag0;
	  ip6_mapt_next_t next0 = 0;
	  u32 saddr;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  error0 = MAP_ERROR_NONE;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current (p0);
	  //Save saddr in a different variable to not overwrite ip.adj_index
	  saddr = map_get_ip4 (&ip60->src_address);
	  d0 = ip6_map_get_domain (vnet_buffer (p0)->ip.adj_index[VLIB_TX],
				   (ip4_address_t *) & saddr,
				   &vnet_buffer (p0)->map_t.map_domain_index,
				   &error0);

	  //FIXME: What if d0 is null
	  vnet_buffer (p0)->map_t.v6.saddr = saddr;
	  vnet_buffer (p0)->map_t.v6.daddr =
	    ip6_map_t_embedded_address (d0, &ip60->dst_address);
	  vnet_buffer (p0)->map_t.mtu = d0->mtu ? d0->mtu : ~0;

	  if (PREDICT_FALSE (ip6_parse (ip60, p0->current_length,
					&(vnet_buffer (p0)->map_t.
					  v6.l4_protocol),
					&(vnet_buffer (p0)->map_t.
					  v6.l4_offset),
					&(vnet_buffer (p0)->map_t.
					  v6.frag_offset))))
	    {
	      error0 = MAP_ERROR_MALFORMED;
	      next0 = IP6_MAPT_NEXT_DROP;
	    }

	  src_port0 = -1;
	  l4_len0 = (u32) clib_net_to_host_u16 (ip60->payload_length) +
	    sizeof (*ip60) - vnet_buffer (p0)->map_t.v6.l4_offset;
	  frag0 =
	    (ip6_frag_hdr_t *) u8_ptr_add (ip60,
					   vnet_buffer (p0)->map_t.
					   v6.frag_offset);


	  if (PREDICT_FALSE (vnet_buffer (p0)->map_t.v6.frag_offset &&
			     ip6_frag_hdr_offset (frag0)))
	    {
	      src_port0 = ip6_map_fragment_get (ip60, frag0, d0);
	      error0 = (src_port0 != -1) ? error0 : MAP_ERROR_FRAGMENT_MEMORY;
	      next0 = IP6_MAPT_NEXT_MAPT_FRAGMENTED;
	    }
	  else
	    if (PREDICT_TRUE
		(vnet_buffer (p0)->map_t.v6.l4_protocol == IP_PROTOCOL_TCP))
	    {
	      error0 =
		l4_len0 <
		sizeof (tcp_header_t) ? MAP_ERROR_MALFORMED : error0;
	      vnet_buffer (p0)->map_t.checksum_offset =
		vnet_buffer (p0)->map_t.v6.l4_offset + 16;
	      next0 = IP6_MAPT_NEXT_MAPT_TCP_UDP;
	      src_port0 =
		(i32) *
		((u16 *)
		 u8_ptr_add (ip60, vnet_buffer (p0)->map_t.v6.l4_offset));
	    }
	  else
	    if (PREDICT_TRUE
		(vnet_buffer (p0)->map_t.v6.l4_protocol == IP_PROTOCOL_UDP))
	    {
	      error0 =
		l4_len0 <
		sizeof (udp_header_t) ? MAP_ERROR_MALFORMED : error0;
	      vnet_buffer (p0)->map_t.checksum_offset =
		vnet_buffer (p0)->map_t.v6.l4_offset + 6;
	      next0 = IP6_MAPT_NEXT_MAPT_TCP_UDP;
	      src_port0 =
		(i32) *
		((u16 *)
		 u8_ptr_add (ip60, vnet_buffer (p0)->map_t.v6.l4_offset));
	    }
	  else if (vnet_buffer (p0)->map_t.v6.l4_protocol ==
		   IP_PROTOCOL_ICMP6)
	    {
	      error0 =
		l4_len0 <
		sizeof (icmp46_header_t) ? MAP_ERROR_MALFORMED : error0;
	      next0 = IP6_MAPT_NEXT_MAPT_ICMP;
	      if (((icmp46_header_t *)
		   u8_ptr_add (ip60,
			       vnet_buffer (p0)->map_t.v6.l4_offset))->code ==
		  ICMP6_echo_reply
		  || ((icmp46_header_t *)
		      u8_ptr_add (ip60,
				  vnet_buffer (p0)->map_t.v6.
				  l4_offset))->code == ICMP6_echo_request)
		src_port0 =
		  (i32) *
		  ((u16 *)
		   u8_ptr_add (ip60,
			       vnet_buffer (p0)->map_t.v6.l4_offset + 6));
	    }
	  else
	    {
	      //TODO: In case of 1:1 mapping, it might be possible to do something with those packets.
	      error0 = MAP_ERROR_BAD_PROTOCOL;
	    }

	  //Security check
	  if (PREDICT_FALSE
	      ((src_port0 != -1)
	       && (ip60->src_address.as_u64[0] !=
		   map_get_pfx_net (d0, vnet_buffer (p0)->map_t.v6.saddr,
				    src_port0)
		   || ip60->src_address.as_u64[1] != map_get_sfx_net (d0,
								      vnet_buffer
								      (p0)->map_t.v6.saddr,
								      src_port0))))
	    {
	      //Security check when src_port0 is not zero (non-first fragment, UDP or TCP)
	      error0 = MAP_ERROR_SEC_CHECK;
	    }

	  //Fragmented first packet needs to be cached for following packets
	  if (PREDICT_FALSE (vnet_buffer (p0)->map_t.v6.frag_offset &&
			     !ip6_frag_hdr_offset ((ip6_frag_hdr_t *)
						   u8_ptr_add (ip60,
							       vnet_buffer
							       (p0)->map_t.
							       v6.frag_offset)))
	      && (src_port0 != -1) && (d0->ea_bits_len != 0 || !d0->rules)
	      && (error0 == MAP_ERROR_NONE))
	    {
	      ip6_map_fragment_cache (ip60,
				      (ip6_frag_hdr_t *) u8_ptr_add (ip60,
								     vnet_buffer
								     (p0)->map_t.
								     v6.frag_offset),
				      d0, src_port0);
	    }

	  if (PREDICT_TRUE
	      (error0 == MAP_ERROR_NONE && next0 != IP6_MAPT_NEXT_MAPT_ICMP))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_RX,
					       thread_index,
					       vnet_buffer (p0)->
					       map_t.map_domain_index, 1,
					       clib_net_to_host_u16
					       (ip60->payload_length));
	    }

	  next0 = (error0 != MAP_ERROR_NONE) ? IP6_MAPT_NEXT_DROP : next0;
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
VLIB_REGISTER_NODE(ip6_map_t_fragmented_node) = {
  .function = ip6_map_t_fragmented,
  .name = "ip6-map-t-fragmented",
  .vector_size = sizeof (u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_strings = map_t_error_strings,

  .n_next_nodes = IP6_MAPT_FRAGMENTED_N_NEXT,
  .next_nodes = {
      [IP6_MAPT_FRAGMENTED_NEXT_IP4_LOOKUP] = "ip4-lookup",
      [IP6_MAPT_FRAGMENTED_NEXT_IP4_FRAG] = IP4_FRAG_NODE_NAME,
      [IP6_MAPT_FRAGMENTED_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip6_map_t_icmp_node) = {
  .function = ip6_map_t_icmp,
  .name = "ip6-map-t-icmp",
  .vector_size = sizeof (u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_strings = map_t_error_strings,

  .n_next_nodes = IP6_MAPT_ICMP_N_NEXT,
  .next_nodes = {
      [IP6_MAPT_ICMP_NEXT_IP4_LOOKUP] = "ip4-lookup",
      [IP6_MAPT_ICMP_NEXT_IP4_FRAG] = IP4_FRAG_NODE_NAME,
      [IP6_MAPT_ICMP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip6_map_t_tcp_udp_node) = {
  .function = ip6_map_t_tcp_udp,
  .name = "ip6-map-t-tcp-udp",
  .vector_size = sizeof (u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_strings = map_t_error_strings,

  .n_next_nodes = IP6_MAPT_TCP_UDP_N_NEXT,
  .next_nodes = {
      [IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP] = "ip4-lookup",
      [IP6_MAPT_TCP_UDP_NEXT_IP4_FRAG] = IP4_FRAG_NODE_NAME,
      [IP6_MAPT_TCP_UDP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip6_map_t_node) = {
  .function = ip6_map_t,
  .name = "ip6-map-t",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_strings = map_t_error_strings,

  .n_next_nodes = IP6_MAPT_N_NEXT,
  .next_nodes = {
      [IP6_MAPT_NEXT_MAPT_TCP_UDP] = "ip6-map-t-tcp-udp",
      [IP6_MAPT_NEXT_MAPT_ICMP] = "ip6-map-t-icmp",
      [IP6_MAPT_NEXT_MAPT_FRAGMENTED] = "ip6-map-t-fragmented",
      [IP6_MAPT_NEXT_DROP] = "error-drop",
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
