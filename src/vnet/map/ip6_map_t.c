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
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/ip/ip4_to_ip6.h>

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

typedef struct
{
  map_domain_t *d;
  u16 sender_port;
} icmp6_to_icmp_ctx_t;

static int
ip6_to_ip4_set_icmp_cb (ip6_header_t * ip6, ip4_header_t * ip4, void *arg)
{
  icmp6_to_icmp_ctx_t *ctx = arg;
  u32 ip4_sadr;

  //Security check
  //Note that this prevents an intermediate IPv6 router from answering the request
  ip4_sadr = map_get_ip4 (&ip6->src_address);
  if (ip6->src_address.as_u64[0] !=
      map_get_pfx_net (ctx->d, ip4_sadr, ctx->sender_port)
      || ip6->src_address.as_u64[1] != map_get_sfx_net (ctx->d, ip4_sadr,
							ctx->sender_port))
    return -1;

  ip4->dst_address.as_u32 =
    ip6_map_t_embedded_address (ctx->d, &ip6->dst_address);
  ip4->src_address.as_u32 = ip4_sadr;

  return 0;
}

static int
ip6_to_ip4_set_inner_icmp_cb (ip6_header_t * ip6, ip4_header_t * ip4,
			      void *arg)
{
  icmp6_to_icmp_ctx_t *ctx = arg;
  u32 inner_ip4_dadr;

  //Security check of inner packet
  inner_ip4_dadr = map_get_ip4 (&ip6->dst_address);
  if (ip6->dst_address.as_u64[0] !=
      map_get_pfx_net (ctx->d, inner_ip4_dadr, ctx->sender_port)
      || ip6->dst_address.as_u64[1] != map_get_sfx_net (ctx->d,
							inner_ip4_dadr,
							ctx->sender_port))
    return -1;

  ip4->dst_address.as_u32 = inner_ip4_dadr;
  ip4->src_address.as_u32 =
    ip6_map_t_embedded_address (ctx->d, &ip6->src_address);

  return 0;
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
	  icmp6_to_icmp_ctx_t ctx0;
	  ip6_header_t *ip60;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  error0 = MAP_ERROR_NONE;
	  next0 = IP6_MAPT_ICMP_NEXT_IP4_LOOKUP;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current (p0);
	  len0 = clib_net_to_host_u16 (ip60->payload_length);
	  d0 =
	    pool_elt_at_index (map_main.domains,
			       vnet_buffer (p0)->map_t.map_domain_index);
	  ctx0.sender_port = ip6_get_port (ip60, 0, len0);
	  ctx0.d = d0;
	  if (ctx0.sender_port == 0)
	    {
	      // In case of 1:1 mapping, we don't care about the port
	      if (!(d0->ea_bits_len == 0 && d0->rules))
		{
		  error0 = MAP_ERROR_ICMP;
		  goto err0;
		}
	    }

	  if (icmp6_to_icmp
	      (p0, ip6_to_ip4_set_icmp_cb, d0, ip6_to_ip4_set_inner_icmp_cb,
	       d0))
	    {
	      error0 = MAP_ERROR_ICMP;
	      goto err0;
	    }

	  if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
	    {
	      //Send to fragmentation node if necessary
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.header_offset = 0;
	      vnet_buffer (p0)->ip_frag.next_index = IP4_FRAG_NEXT_IP4_LOOKUP;
	      next0 = IP6_MAPT_ICMP_NEXT_IP4_FRAG;
	    }
	err0:
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

static int
ip6_to_ip4_set_cb (ip6_header_t * ip6, ip4_header_t * ip4, void *ctx)
{
  vlib_buffer_t *p = ctx;

  ip4->dst_address.as_u32 = vnet_buffer (p)->map_t.v6.daddr;
  ip4->src_address.as_u32 = vnet_buffer (p)->map_t.v6.saddr;

  return 0;
}

static uword
ip6_map_t_fragmented (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_t_fragmented_node.index);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

#ifdef IP6_MAP_T_DUAL_LOOP
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 pi0, pi1;
	  vlib_buffer_t *p0, *p1;
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

	  if (ip6_to_ip4_fragmented (p0, ip6_to_ip4_set_cb, p0))
	    {
	      p0->error = error_node->errors[MAP_ERROR_FRAGMENT_DROPPED];
	      next0 = IP6_MAPT_FRAGMENTED_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
		{
		  //Send to fragmentation node if necessary
		  vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
		  vnet_buffer (p0)->ip_frag.header_offset = 0;
		  vnet_buffer (p0)->ip_frag.next_index =
		    IP4_FRAG_NEXT_IP4_LOOKUP;
		  next0 = IP6_MAPT_FRAGMENTED_NEXT_IP4_FRAG;
		}
	    }

	  if (ip6_to_ip4_fragmented (p1, ip6_to_ip4_set_cb, p1))
	    {
	      p1->error = error_node->errors[MAP_ERROR_FRAGMENT_DROPPED];
	      next1 = IP6_MAPT_FRAGMENTED_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p1)->map_t.mtu < p1->current_length)
		{
		  //Send to fragmentation node if necessary
		  vnet_buffer (p1)->ip_frag.mtu = vnet_buffer (p1)->map_t.mtu;
		  vnet_buffer (p1)->ip_frag.header_offset = 0;
		  vnet_buffer (p1)->ip_frag.next_index =
		    IP4_FRAG_NEXT_IP4_LOOKUP;
		  next1 = IP6_MAPT_FRAGMENTED_NEXT_IP4_FRAG;
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
	  u32 next0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  next0 = IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP;
	  p0 = vlib_get_buffer (vm, pi0);

	  if (ip6_to_ip4_fragmented (p0, ip6_to_ip4_set_cb, p0))
	    {
	      p0->error = error_node->errors[MAP_ERROR_FRAGMENT_DROPPED];
	      next0 = IP6_MAPT_FRAGMENTED_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
		{
		  //Send to fragmentation node if necessary
		  vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
		  vnet_buffer (p0)->ip_frag.header_offset = 0;
		  vnet_buffer (p0)->ip_frag.next_index =
		    IP4_FRAG_NEXT_IP4_LOOKUP;
		  next0 = IP6_MAPT_FRAGMENTED_NEXT_IP4_FRAG;
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
ip6_map_t_tcp_udp (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_t_tcp_udp_node.index);

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

	  if (ip6_to_ip4_tcp_udp (p0, ip6_to_ip4_set_cb, p0, 1))
	    {
	      p0->error = error_node->errors[MAP_ERROR_UNKNOWN];
	      next0 = IP6_MAPT_TCP_UDP_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
		{
		  //Send to fragmentation node if necessary
		  vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
		  vnet_buffer (p0)->ip_frag.header_offset = 0;
		  vnet_buffer (p0)->ip_frag.next_index =
		    IP4_FRAG_NEXT_IP4_LOOKUP;
		  next0 = IP6_MAPT_TCP_UDP_NEXT_IP4_FRAG;
		}
	    }

	  if (ip6_to_ip4_tcp_udp (p1, ip6_to_ip4_set_cb, p1, 1))
	    {
	      p1->error = error_node->errors[MAP_ERROR_UNKNOWN];
	      next1 = IP6_MAPT_TCP_UDP_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p1)->map_t.mtu < p1->current_length)
		{
		  //Send to fragmentation node if necessary
		  vnet_buffer (p1)->ip_frag.mtu = vnet_buffer (p1)->map_t.mtu;
		  vnet_buffer (p1)->ip_frag.header_offset = 0;
		  vnet_buffer (p1)->ip_frag.next_index =
		    IP4_FRAG_NEXT_IP4_LOOKUP;
		  next1 = IP6_MAPT_TCP_UDP_NEXT_IP4_FRAG;
		}
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
	  ip6_mapt_tcp_udp_next_t next0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  next0 = IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP;

	  p0 = vlib_get_buffer (vm, pi0);

	  if (ip6_to_ip4_tcp_udp (p0, ip6_to_ip4_set_cb, p0, 1))
	    {
	      p0->error = error_node->errors[MAP_ERROR_UNKNOWN];
	      next0 = IP6_MAPT_TCP_UDP_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
		{
		  //Send to fragmentation node if necessary
		  vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
		  vnet_buffer (p0)->ip_frag.header_offset = 0;
		  vnet_buffer (p0)->ip_frag.next_index =
		    IP4_FRAG_NEXT_IP4_LOOKUP;
		  next0 = IP6_MAPT_TCP_UDP_NEXT_IP4_FRAG;
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
