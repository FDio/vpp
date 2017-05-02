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

typedef struct
{
  map_domain_t *d;
  u16 recv_port;
} icmp_to_icmp6_ctx_t;

static int
ip4_to_ip6_set_icmp_cb (ip4_header_t * ip4, ip6_header_t * ip6, void *arg)
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
ip4_to_ip6_set_inner_icmp_cb (ip4_header_t * ip4, ip6_header_t * ip6,
			      void *arg)
{
  icmp_to_icmp6_ctx_t *ctx = arg;

  //Note that the source address is within the domain
  //while the destination address is the one outside the domain
  ip4_map_t_embedded_address (ctx->d, &ip6->dst_address, &ip4->dst_address);
  ip6->src_address.as_u64[0] =
    map_get_pfx_net (ctx->d, ip4->src_address.as_u32, ctx->recv_port);
  ip6->src_address.as_u64[1] =
    map_get_sfx_net (ctx->d, ip4->src_address.as_u32, ctx->recv_port);

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
	  ctx0.recv_port = ip4_get_port (ip40, 1);
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
	      vnet_buffer (p0)->ip_frag.header_offset = 0;
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.next_index = IP6_FRAG_NEXT_IP6_LOOKUP;
	      next0 = IP4_MAPT_ICMP_NEXT_IP6_FRAG;
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

static int
ip4_to_ip6_set_cb (ip4_header_t * ip4, ip6_header_t * ip6, void *ctx)
{
  ip4_mapt_pseudo_header_t *pheader = ctx;

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

	  if (ip4_to_ip6_fragmented (p0, ip4_to_ip6_set_cb, pheader0))
	    {
	      p0->error = error_node->errors[MAP_ERROR_FRAGMENT_DROPPED];
	      next0 = IP4_MAPT_FRAGMENTED_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
		{
		  vnet_buffer (p0)->ip_frag.header_offset = 0;
		  vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
		  vnet_buffer (p0)->ip_frag.next_index =
		    IP6_FRAG_NEXT_IP6_LOOKUP;
		  next0 = IP4_MAPT_FRAGMENTED_NEXT_IP6_FRAG;
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

#ifdef IP4_MAP_T_DUAL_LOOP
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 pi0, pi1;
	  vlib_buffer_t *p0, *p1;
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

	  if (ip4_to_ip6_tcp_udp (p0, ip4_to_ip6_set_cb, pheader0))
	    {
	      p0->error = error_node->errors[MAP_ERROR_UNKNOWN];
	      next0 = IP4_MAPT_TCP_UDP_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
		{
		  //Send to fragmentation node if necessary
		  vnet_buffer (p0)->ip_frag.header_offset = 0;
		  vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
		  vnet_buffer (p0)->ip_frag.next_index =
		    IP6_FRAG_NEXT_IP6_LOOKUP;
		  next0 = IP4_MAPT_TCP_UDP_NEXT_IP6_FRAG;
		}
	    }

	  if (ip4_to_ip6_tcp_udp (p1, ip4_to_ip6_set_cb, pheader1))
	    {
	      p1->error = error_node->errors[MAP_ERROR_UNKNOWN];
	      next1 = IP4_MAPT_TCP_UDP_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p1)->map_t.mtu < p1->current_length)
		{
		  //Send to fragmentation node if necessary
		  vnet_buffer (p1)->ip_frag.header_offset = 0;
		  vnet_buffer (p1)->ip_frag.mtu = vnet_buffer (p1)->map_t.mtu;
		  vnet_buffer (p1)->ip_frag.next_index =
		    IP6_FRAG_NEXT_IP6_LOOKUP;
		  next1 = IP4_MAPT_TCP_UDP_NEXT_IP6_FRAG;
		}
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

	  if (ip4_to_ip6_tcp_udp (p0, ip4_to_ip6_set_cb, pheader0))
	    {
	      p0->error = error_node->errors[MAP_ERROR_UNKNOWN];
	      next0 = IP4_MAPT_TCP_UDP_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
		{
		  //Send to fragmentation node if necessary
		  vnet_buffer (p0)->ip_frag.header_offset = 0;
		  vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
		  vnet_buffer (p0)->ip_frag.next_index =
		    IP6_FRAG_NEXT_IP6_LOOKUP;
		  next0 = IP4_MAPT_TCP_UDP_NEXT_IP6_FRAG;
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
					       vnet_buffer (p0)->
					       map_t.map_domain_index, 1,
					       clib_net_to_host_u16
					       (ip40->length));
	    }

	  if (PREDICT_TRUE
	      (error1 == MAP_ERROR_NONE && next1 != IP4_MAPT_NEXT_MAPT_ICMP))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_TX,
					       thread_index,
					       vnet_buffer (p1)->
					       map_t.map_domain_index, 1,
					       clib_net_to_host_u16
					       (ip41->length));
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
					       vnet_buffer (p0)->
					       map_t.map_domain_index, 1,
					       clib_net_to_host_u16
					       (ip40->length));
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
