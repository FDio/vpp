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

typedef enum
{
  IP4_MAPT_NEXT_MAPT_TCP_UDP,
  IP4_MAPT_NEXT_MAPT_ICMP,
  IP4_MAPT_NEXT_MAPT_FRAGMENTED,
  IP4_MAPT_NEXT_ICMP_ERROR,
  IP4_MAPT_NEXT_DROP,
  IP4_MAPT_N_NEXT
} ip4_mapt_next_t;

typedef enum
{
  IP4_MAPT_ICMP_NEXT_IP6_LOOKUP,
  IP4_MAPT_ICMP_NEXT_IP6_REWRITE,
  IP4_MAPT_ICMP_NEXT_IP6_FRAG,
  IP4_MAPT_ICMP_NEXT_DROP,
  IP4_MAPT_ICMP_N_NEXT
} ip4_mapt_icmp_next_t;

typedef enum
{
  IP4_MAPT_TCP_UDP_NEXT_IP6_LOOKUP,
  IP4_MAPT_TCP_UDP_NEXT_IP6_REWRITE,
  IP4_MAPT_TCP_UDP_NEXT_IP6_FRAG,
  IP4_MAPT_TCP_UDP_NEXT_DROP,
  IP4_MAPT_TCP_UDP_N_NEXT
} ip4_mapt_tcp_udp_next_t;

typedef enum
{
  IP4_MAPT_FRAGMENTED_NEXT_IP6_LOOKUP,
  IP4_MAPT_FRAGMENTED_NEXT_IP6_REWRITE,
  IP4_MAPT_FRAGMENTED_NEXT_IP6_FRAG,
  IP4_MAPT_FRAGMENTED_NEXT_DROP,
  IP4_MAPT_FRAGMENTED_N_NEXT
} ip4_mapt_fragmented_next_t;

//This is used to pass information within the buffer data.
//Buffer structure being too small to contain big structures like this.
typedef CLIB_PACKED (struct {
  ip6_address_t daddr;
  ip6_address_t saddr;
  //IPv6 header + Fragmentation header will be here
  //sizeof(ip6) + sizeof(ip_frag) - sizeof(ip4)
  u8 unused[28];
}) ip4_mapt_pseudo_header_t;

typedef struct
{
  map_domain_t *d;
  u16 recv_port;
} icmp_to_icmp6_ctx_t;

static int
ip4_to_ip6_set_icmp_cb (vlib_buffer_t * b, ip4_header_t * ip4,
			ip6_header_t * ip6, void *arg)
{
  icmp_to_icmp6_ctx_t *ctx = arg;

  ip4_map_t_embedded_address (ctx->d, &ip6->src_address, &ip4->src_address);
  ip6->dst_address.as_u64[0] =
    map_get_pfx_net (ctx->d, ip4->dst_address.as_u32, ctx->recv_port);
  ip6->dst_address.as_u64[1] =
    map_get_sfx_net (ctx->d, ip4->dst_address.as_u32, ctx->recv_port);

  return 0;
}

static int
ip4_to_ip6_set_inner_icmp_cb (vlib_buffer_t * b, ip4_header_t * ip4,
			      ip6_header_t * ip6, void *arg)
{
  icmp_to_icmp6_ctx_t *ctx = arg;
  ip4_address_t old_src, old_dst;

  old_src.as_u32 = ip4->src_address.as_u32;
  old_dst.as_u32 = ip4->dst_address.as_u32;

  //Note that the source address is within the domain
  //while the destination address is the one outside the domain
  ip4_map_t_embedded_address (ctx->d, &ip6->dst_address, &old_dst);
  ip6->src_address.as_u64[0] =
    map_get_pfx_net (ctx->d, old_src.as_u32, ctx->recv_port);
  ip6->src_address.as_u64[1] =
    map_get_sfx_net (ctx->d, old_src.as_u32, ctx->recv_port);

  return 0;
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
  clib_thread_index_t thread_index = vm->thread_index;

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
	  icmp_to_icmp6_ctx_t ctx0;
	  ip4_header_t *ip40;

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

	  ip40 = vlib_buffer_get_current (p0);
	  ctx0.recv_port = ip4_get_port (ip40, 0);
	  ctx0.d = d0;
	  if (ctx0.recv_port == 0)
	    {
	      // In case of 1:1 mapping, we don't care about the port
	      if (!(d0->ea_bits_len == 0 && d0->rules))
		{
		  error0 = MAP_ERROR_ICMP;
		  goto err0;
		}
	    }

	  if (icmp_to_icmp6
	      (p0, ip4_to_ip6_set_icmp_cb, &ctx0,
	       ip4_to_ip6_set_inner_icmp_cb, &ctx0))
	    {
	      error0 = MAP_ERROR_ICMP;
	      goto err0;
	    }

	  if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
	    {
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.next_index = IP_FRAG_NEXT_IP6_LOOKUP;
	      next0 = IP4_MAPT_ICMP_NEXT_IP6_FRAG;
	    }
	  else
	    {
	      next0 = ip4_map_ip6_lookup_bypass (p0, NULL) ?
		IP4_MAPT_ICMP_NEXT_IP6_REWRITE : next0;
	    }
	err0:
	  if (PREDICT_TRUE (error0 == MAP_ERROR_NONE))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_TX,
					       thread_index,
					       vnet_buffer (p0)->
					       map_t.map_domain_index, 1,
					       len0);
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

/*
 * Translate fragmented IPv4 UDP/TCP packet to IPv6.
 */
always_inline int
map_ip4_to_ip6_fragmented (vlib_buffer_t * p,
			   ip4_mapt_pseudo_header_t * pheader)
{
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  ip6_frag_hdr_t *frag;

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

  ip6->dst_address.as_u64[0] = pheader->daddr.as_u64[0];
  ip6->dst_address.as_u64[1] = pheader->daddr.as_u64[1];
  ip6->src_address.as_u64[0] = pheader->saddr.as_u64[0];
  ip6->src_address.as_u64[1] = pheader->saddr.as_u64[1];

  return 0;
}

static uword
ip4_map_t_fragmented (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_map_t_fragmented_node.index);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
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

	  if (map_ip4_to_ip6_fragmented (p0, pheader0))
	    {
	      p0->error = error_node->errors[MAP_ERROR_FRAGMENT_DROPPED];
	      next0 = IP4_MAPT_FRAGMENTED_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
		{
		  vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
		  vnet_buffer (p0)->ip_frag.next_index =
		    IP_FRAG_NEXT_IP6_LOOKUP;
		  next0 = IP4_MAPT_FRAGMENTED_NEXT_IP6_FRAG;
		}
	      else
		{
		  next0 = ip4_map_ip6_lookup_bypass (p0, NULL) ?
		    IP4_MAPT_FRAGMENTED_NEXT_IP6_REWRITE : next0;
		}
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, pi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

/*
 * Translate IPv4 UDP/TCP packet to IPv6.
 */
always_inline int
map_ip4_to_ip6_tcp_udp (vlib_buffer_t * p, ip4_mapt_pseudo_header_t * pheader)
{
  map_main_t *mm = &map_main;
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  ip_csum_t csum;
  u16 *checksum;
  ip6_frag_hdr_t *frag;
  u32 frag_id;
  ip4_address_t old_src, old_dst;

  ip4 = vlib_buffer_get_current (p);

  if (ip4->protocol == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = ip4_next_header (ip4);
      checksum = &udp->checksum;

      /*
       * UDP checksum is optional over IPv4 but mandatory for IPv6 We
       * do not check udp->length sanity but use our safe computed
       * value instead
       */
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
      if (mm->tcp_mss > 0)
	{
	  csum = tcp->checksum;
	  map_mss_clamping (tcp, &csum, mm->tcp_mss);
	  tcp->checksum = ip_csum_fold (csum);
	}
      checksum = &tcp->checksum;
    }

  old_src.as_u32 = ip4->src_address.as_u32;
  old_dst.as_u32 = ip4->dst_address.as_u32;

  /* Deal with fragmented packets */
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

  ip6->dst_address.as_u64[0] = pheader->daddr.as_u64[0];
  ip6->dst_address.as_u64[1] = pheader->daddr.as_u64[1];
  ip6->src_address.as_u64[0] = pheader->saddr.as_u64[0];
  ip6->src_address.as_u64[1] = pheader->saddr.as_u64[1];

  csum = ip_csum_sub_even (*checksum, old_src.as_u32);
  csum = ip_csum_sub_even (csum, old_dst.as_u32);
  csum = ip_csum_add_even (csum, ip6->src_address.as_u64[0]);
  csum = ip_csum_add_even (csum, ip6->src_address.as_u64[1]);
  csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[0]);
  csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[1]);
  *checksum = ip_csum_fold (csum);

  return 0;
}

static uword
ip4_map_t_tcp_udp (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_map_t_tcp_udp_node.index);


  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
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

	  if (map_ip4_to_ip6_tcp_udp (p0, pheader0))
	    {
	      p0->error = error_node->errors[MAP_ERROR_UNKNOWN];
	      next0 = IP4_MAPT_TCP_UDP_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
		{
		  //Send to fragmentation node if necessary
		  vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
		  vnet_buffer (p0)->ip_frag.next_index =
		    IP_FRAG_NEXT_IP6_LOOKUP;
		  next0 = IP4_MAPT_TCP_UDP_NEXT_IP6_FRAG;
		}
	      else
		{
		  next0 = ip4_map_ip6_lookup_bypass (p0, NULL) ?
		    IP4_MAPT_TCP_UDP_NEXT_IP6_REWRITE : next0;
		}
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
		    u8 * error0, ip4_mapt_next_t * next0, u16 l4_dst_port)
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
	  *dst_port0 = l4_dst_port;
	  *error0 = (*dst_port0 == -1) ? MAP_ERROR_FRAGMENT_MEMORY : *error0;
	}
    }
  else if (PREDICT_TRUE (ip40->protocol == IP_PROTOCOL_TCP))
    {
      vnet_buffer (p0)->map_t.checksum_offset = 36;
      *next0 = IP4_MAPT_NEXT_MAPT_TCP_UDP;
      *error0 = ip4_len0 < 40 ? MAP_ERROR_MALFORMED : *error0;
      *dst_port0 = l4_dst_port;
    }
  else if (PREDICT_TRUE (ip40->protocol == IP_PROTOCOL_UDP))
    {
      vnet_buffer (p0)->map_t.checksum_offset = 26;
      *next0 = IP4_MAPT_NEXT_MAPT_TCP_UDP;
      *error0 = ip4_len0 < 28 ? MAP_ERROR_MALFORMED : *error0;
      *dst_port0 = l4_dst_port;
    }
  else if (ip40->protocol == IP_PROTOCOL_ICMP)
    {
      *next0 = IP4_MAPT_NEXT_MAPT_ICMP;
      if (d0->ea_bits_len == 0 && d0->rules)
	*dst_port0 = 0;
      else if (((icmp46_header_t *) u8_ptr_add (ip40, sizeof (*ip40)))->type
	       == ICMP4_echo_reply
	       || ((icmp46_header_t *)
		   u8_ptr_add (ip40,
			       sizeof (*ip40)))->type == ICMP4_echo_request)
	*dst_port0 = l4_dst_port;
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
  clib_thread_index_t thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  ip4_header_t *ip40;
	  map_domain_t *d0;
	  ip4_mapt_next_t next0 = 0;
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

	  u16 l4_dst_port = vnet_buffer (p0)->ip.reass.l4_dst_port;

	  ip40 = vlib_buffer_get_current (p0);
	  ip4_len0 = clib_host_to_net_u16 (ip40->length);
	  if (PREDICT_FALSE (p0->current_length < ip4_len0 ||
			     ip40->ip_version_and_header_length != 0x45))
	    {
	      error0 = MAP_ERROR_UNKNOWN;
	    }

	  d0 = ip4_map_get_domain (&ip40->dst_address,
				   &vnet_buffer (p0)->map_t.map_domain_index,
				   &error0);

	  if (!d0)
	    {			/* Guess it wasn't for us */
	      vnet_feature_next (&next0, p0);
	      goto exit;
	    }

	  dst_port0 = -1;

	  if (PREDICT_FALSE (ip40->ttl == 1))
	    {
	      icmp4_error_set_vnet_buffer (p0, ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      p0->error = error_node->errors[MAP_ERROR_TIME_EXCEEDED];
	      next0 = IP4_MAPT_NEXT_ICMP_ERROR;
	      goto trace;
	    }

	  bool df0 =
	    ip40->flags_and_fragment_offset &
	    clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);

	  vnet_buffer (p0)->map_t.mtu = d0->mtu ? d0->mtu : ~0;

	  if (PREDICT_FALSE
	      (df0 && !map_main.frag_ignore_df
	       &&
	       ((ip4_len0 +
		 (sizeof (ip6_header_t) - sizeof (ip4_header_t))) >
		vnet_buffer (p0)->map_t.mtu)))
	    {
	      icmp4_error_set_vnet_buffer (p0, ICMP4_destination_unreachable,
					   ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set,
					   vnet_buffer (p0)->map_t.mtu -
					   (sizeof (ip6_header_t) -
					    sizeof (ip4_header_t)));
	      p0->error = error_node->errors[MAP_ERROR_DF_SET];
	      next0 = IP4_MAPT_NEXT_ICMP_ERROR;
	      goto trace;
	    }

	  ip4_map_t_classify (p0, d0, ip40, ip4_len0, &dst_port0, &error0,
			      &next0, l4_dst_port);

	  /* Verify that port is not among the well-known ports */
	  if ((d0->psid_length > 0 && d0->psid_offset > 0)
	      && (clib_net_to_host_u16 (dst_port0) <
		  (0x1 << (16 - d0->psid_offset))))
	    {
	      error0 = MAP_ERROR_SEC_CHECK;
	    }

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

	  if (PREDICT_TRUE
	      (error0 == MAP_ERROR_NONE && next0 != IP4_MAPT_NEXT_MAPT_ICMP))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_TX,
					       thread_index,
					       vnet_buffer (p0)->
					       map_t.map_domain_index, 1,
					       clib_net_to_host_u16
					       (ip40->length));
	    }

	  next0 = (error0 != MAP_ERROR_NONE) ? IP4_MAPT_NEXT_DROP : next0;
	  p0->error = error_node->errors[error0];
	trace:
	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      map_add_trace (vm, node, p0, d0 - map_main.domains, dst_port0);
	    }
	exit:
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, pi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

VNET_FEATURE_INIT (ip4_map_t_feature, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "ip4-map-t",
    .runs_before = VNET_FEATURES ("ip4-flow-classify"),
    .runs_after = VNET_FEATURES ("ip4-sv-reassembly-feature"),
};

VLIB_REGISTER_NODE(ip4_map_t_fragmented_node) = {
  .function = ip4_map_t_fragmented,
  .name = "ip4-map-t-fragmented",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_counters = map_error_counters,

  .n_next_nodes = IP4_MAPT_FRAGMENTED_N_NEXT,
  .next_nodes = {
      [IP4_MAPT_FRAGMENTED_NEXT_IP6_LOOKUP] = "ip6-lookup",
      [IP4_MAPT_FRAGMENTED_NEXT_IP6_REWRITE] = "ip6-load-balance",
      [IP4_MAPT_FRAGMENTED_NEXT_IP6_FRAG] = IP6_FRAG_NODE_NAME,
      [IP4_MAPT_FRAGMENTED_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE(ip4_map_t_icmp_node) = {
  .function = ip4_map_t_icmp,
  .name = "ip4-map-t-icmp",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_counters = map_error_counters,

  .n_next_nodes = IP4_MAPT_ICMP_N_NEXT,
  .next_nodes = {
      [IP4_MAPT_ICMP_NEXT_IP6_LOOKUP] = "ip6-lookup",
      [IP4_MAPT_ICMP_NEXT_IP6_REWRITE] = "ip6-load-balance",
      [IP4_MAPT_ICMP_NEXT_IP6_FRAG] = IP6_FRAG_NODE_NAME,
      [IP4_MAPT_ICMP_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE(ip4_map_t_tcp_udp_node) = {
  .function = ip4_map_t_tcp_udp,
  .name = "ip4-map-t-tcp-udp",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_counters = map_error_counters,

  .n_next_nodes = IP4_MAPT_TCP_UDP_N_NEXT,
  .next_nodes = {
      [IP4_MAPT_TCP_UDP_NEXT_IP6_LOOKUP] = "ip6-lookup",
      [IP4_MAPT_TCP_UDP_NEXT_IP6_REWRITE] = "ip6-load-balance",
      [IP4_MAPT_TCP_UDP_NEXT_IP6_FRAG] = IP6_FRAG_NODE_NAME,
      [IP4_MAPT_TCP_UDP_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE(ip4_map_t_node) = {
  .function = ip4_map_t,
  .name = "ip4-map-t",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_counters = map_error_counters,

  .n_next_nodes = IP4_MAPT_N_NEXT,
  .next_nodes = {
      [IP4_MAPT_NEXT_MAPT_TCP_UDP] = "ip4-map-t-tcp-udp",
      [IP4_MAPT_NEXT_MAPT_ICMP] = "ip4-map-t-icmp",
      [IP4_MAPT_NEXT_MAPT_FRAGMENTED] = "ip4-map-t-fragmented",
      [IP4_MAPT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
      [IP4_MAPT_NEXT_DROP] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
