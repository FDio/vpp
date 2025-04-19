/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <nat/nat64/nat64.h>
#include <vnet/ip/ip4_to_ip6.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/udp/udp_local.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
} nat64_out2in_trace_t;

static u8 *
format_nat64_out2in_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat64_out2in_trace_t *t = va_arg (*args, nat64_out2in_trace_t *);

  s =
    format (s, "NAT64-out2in: sw_if_index %d, next index %d", t->sw_if_index,
	    t->next_index);

  return s;
}

#define foreach_nat64_out2in_error                       \
_(UNSUPPORTED_PROTOCOL, "unsupported protocol")          \
_(NO_TRANSLATION, "no translation")                      \
_(UNKNOWN, "unknown")

typedef enum
{
#define _(sym,str) NAT64_OUT2IN_ERROR_##sym,
  foreach_nat64_out2in_error
#undef _
    NAT64_OUT2IN_N_ERROR,
} nat64_out2in_error_t;

static char *nat64_out2in_error_strings[] = {
#define _(sym,string) string,
  foreach_nat64_out2in_error
#undef _
};

typedef enum
{
  NAT64_OUT2IN_NEXT_IP6_LOOKUP,
  NAT64_OUT2IN_NEXT_IP4_LOOKUP,
  NAT64_OUT2IN_NEXT_DROP,
  NAT64_OUT2IN_N_NEXT,
} nat64_out2in_next_t;

typedef struct nat64_out2in_set_ctx_t_
{
  vlib_buffer_t *b;
  vlib_main_t *vm;
  clib_thread_index_t thread_index;
} nat64_out2in_set_ctx_t;

static int
nat64_out2in_tcp_udp (vlib_main_t * vm, vlib_buffer_t * b,
		      nat64_out2in_set_ctx_t * ctx)
{
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  ip_csum_t csum;
  u16 *checksum = NULL;
  ip6_frag_hdr_t *frag;
  u32 frag_id;
  ip4_address_t old_src, old_dst;

  nat64_main_t *nm = &nat64_main;
  nat64_db_bib_entry_t *bibe;
  nat64_db_st_entry_t *ste;
  ip46_address_t saddr;
  ip46_address_t daddr;
  ip6_address_t ip6_saddr;
  u8 proto = vnet_buffer (b)->ip.reass.ip_proto;
  u16 dport = vnet_buffer (b)->ip.reass.l4_dst_port;
  u16 sport = vnet_buffer (b)->ip.reass.l4_src_port;
  u32 sw_if_index, fib_index;
  nat64_db_t *db = &nm->db[ctx->thread_index];

  ip4 = vlib_buffer_get_current (b);

  udp_header_t *udp = ip4_next_header (ip4);
  tcp_header_t *tcp = ip4_next_header (ip4);
  if (!vnet_buffer (b)->ip.reass.is_non_first_fragment)
    {
      if (ip4->protocol == IP_PROTOCOL_UDP)
	{
	  checksum = &udp->checksum;
	  //UDP checksum is optional over IPv4 but mandatory for IPv6
	  //We do not check udp->length sanity but use our safe computed value instead
	  if (PREDICT_FALSE (!*checksum))
	    {
	      u16 udp_len =
		clib_host_to_net_u16 (ip4->length) - sizeof (*ip4);
	      csum = ip_incremental_checksum (0, udp, udp_len);
	      csum =
		ip_csum_with_carry (csum, clib_host_to_net_u16 (udp_len));
	      csum =
		ip_csum_with_carry (csum,
				    clib_host_to_net_u16 (IP_PROTOCOL_UDP));
	      csum =
		ip_csum_with_carry (csum, *((u64 *) (&ip4->src_address)));
	      *checksum = ~ip_csum_fold (csum);
	    }
	}
      else
	{
	  checksum = &tcp->checksum;
	}
    }

  old_src.as_u32 = ip4->src_address.as_u32;
  old_dst.as_u32 = ip4->dst_address.as_u32;

  // Deal with fragmented packets
  u16 frag_offset = ip4_get_fragment_offset (ip4);
  if (PREDICT_FALSE (ip4_get_fragment_more (ip4) || frag_offset))
    {
      ip6 =
	(ip6_header_t *) u8_ptr_add (ip4,
				     sizeof (*ip4) - sizeof (*ip6) -
				     sizeof (*frag));
      frag =
	(ip6_frag_hdr_t *) u8_ptr_add (ip4, sizeof (*ip4) - sizeof (*frag));
      frag_id = frag_id_4to6 (ip4->fragment_id);
      vlib_buffer_advance (b, sizeof (*ip4) - sizeof (*ip6) - sizeof (*frag));
    }
  else
    {
      ip6 = (ip6_header_t *) (((u8 *) ip4) + sizeof (*ip4) - sizeof (*ip6));
      vlib_buffer_advance (b, sizeof (*ip4) - sizeof (*ip6));
      frag = NULL;
    }

  ip6->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 ((6 << 28) + (ip4->tos << 20));
  ip6->payload_length = u16_net_add (ip4->length, -sizeof (*ip4));
  ip6->hop_limit = ip4->ttl;
  ip6->protocol = ip4->protocol;

  sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
  fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  clib_memset (&saddr, 0, sizeof (saddr));
  saddr.ip4.as_u32 = ip4->src_address.as_u32;
  clib_memset (&daddr, 0, sizeof (daddr));
  daddr.ip4.as_u32 = ip4->dst_address.as_u32;

  ste =
    nat64_db_st_entry_find (db, &daddr, &saddr, dport, sport, proto,
			    fib_index, 0);
  if (ste)
    {
      bibe = nat64_db_bib_entry_by_index (db, proto, ste->bibe_index);
      if (!bibe)
	return -1;
    }
  else
    {
      bibe = nat64_db_bib_entry_find (db, &daddr, dport, proto, fib_index, 0);

      if (!bibe)
	return -1;

      nat64_compose_ip6 (&ip6_saddr, &old_src, bibe->fib_index);
      ste =
	nat64_db_st_entry_create (ctx->thread_index, db, bibe, &ip6_saddr,
				  &saddr.ip4, sport);

      if (!ste)
	return -1;

      vlib_set_simple_counter (&nm->total_sessions, ctx->thread_index, 0,
			       db->st.st_entries_num);
    }

  ip6->src_address.as_u64[0] = ste->in_r_addr.as_u64[0];
  ip6->src_address.as_u64[1] = ste->in_r_addr.as_u64[1];

  ip6->dst_address.as_u64[0] = bibe->in_addr.as_u64[0];
  ip6->dst_address.as_u64[1] = bibe->in_addr.as_u64[1];

  vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;

  nat64_session_reset_timeout (ste, ctx->vm);

  if (PREDICT_FALSE (frag != NULL))
    {
      frag->next_hdr = ip6->protocol;
      frag->identification = frag_id;
      frag->rsv = 0;
      frag->fragment_offset_and_more =
	ip6_frag_hdr_offset_and_more (frag_offset, 1);
      ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
      ip6->payload_length = u16_net_add (ip6->payload_length, sizeof (*frag));
    }

  if (!vnet_buffer (b)->ip.reass.is_non_first_fragment)
    {
      udp->dst_port = bibe->in_port;

      if (proto == IP_PROTOCOL_TCP)
	{
	  nat64_tcp_session_set_state (ste, tcp, 0);
	}

      csum = ip_csum_sub_even (*checksum, dport);
      csum = ip_csum_add_even (csum, udp->dst_port);
      csum = ip_csum_sub_even (csum, old_src.as_u32);
      csum = ip_csum_sub_even (csum, old_dst.as_u32);
      csum = ip_csum_add_even (csum, ip6->src_address.as_u64[0]);
      csum = ip_csum_add_even (csum, ip6->src_address.as_u64[1]);
      csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[0]);
      csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[1]);
      *checksum = ip_csum_fold (csum);
    }

  return 0;
}

static int
nat64_out2in_icmp_set_cb (vlib_buffer_t * b, ip4_header_t * ip4,
			  ip6_header_t * ip6, void *arg)
{
  nat64_main_t *nm = &nat64_main;
  nat64_out2in_set_ctx_t *ctx = arg;
  nat64_db_bib_entry_t *bibe;
  nat64_db_st_entry_t *ste;
  ip46_address_t saddr, daddr;
  ip6_address_t ip6_saddr;
  u32 sw_if_index, fib_index;
  icmp46_header_t *icmp = ip4_next_header (ip4);
  nat64_db_t *db = &nm->db[ctx->thread_index];

  sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
  fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  clib_memset (&saddr, 0, sizeof (saddr));
  saddr.ip4.as_u32 = ip4->src_address.as_u32;
  clib_memset (&daddr, 0, sizeof (daddr));
  daddr.ip4.as_u32 = ip4->dst_address.as_u32;

  if (icmp->type == ICMP6_echo_request || icmp->type == ICMP6_echo_reply)
    {
      u16 out_id = ((u16 *) (icmp))[2];
      ste =
	nat64_db_st_entry_find (db, &daddr, &saddr, out_id, 0,
				IP_PROTOCOL_ICMP, fib_index, 0);

      if (ste)
	{
	  bibe =
	    nat64_db_bib_entry_by_index (db, IP_PROTOCOL_ICMP,
					 ste->bibe_index);
	  if (!bibe)
	    return -1;
	}
      else
	{
	  bibe =
	    nat64_db_bib_entry_find (db, &daddr, out_id,
				     IP_PROTOCOL_ICMP, fib_index, 0);
	  if (!bibe)
	    return -1;

	  nat64_compose_ip6 (&ip6_saddr, &ip4->src_address, bibe->fib_index);
	  ste =
	    nat64_db_st_entry_create (ctx->thread_index, db,
				      bibe, &ip6_saddr, &saddr.ip4, 0);

	  if (!ste)
	    return -1;

	  vlib_set_simple_counter (&nm->total_sessions, ctx->thread_index, 0,
				   db->st.st_entries_num);
	}

      nat64_session_reset_timeout (ste, ctx->vm);

      ip6->src_address.as_u64[0] = ste->in_r_addr.as_u64[0];
      ip6->src_address.as_u64[1] = ste->in_r_addr.as_u64[1];

      ip6->dst_address.as_u64[0] = bibe->in_addr.as_u64[0];
      ip6->dst_address.as_u64[1] = bibe->in_addr.as_u64[1];
      ((u16 *) (icmp))[2] = bibe->in_port;

      vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;
    }
  else
    {
      ip6_header_t *inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);

      nat64_compose_ip6 (&ip6->src_address, &ip4->src_address,
			 vnet_buffer (ctx->b)->sw_if_index[VLIB_TX]);
      ip6->dst_address.as_u64[0] = inner_ip6->src_address.as_u64[0];
      ip6->dst_address.as_u64[1] = inner_ip6->src_address.as_u64[1];
    }

  return 0;
}

static int
nat64_out2in_inner_icmp_set_cb (vlib_buffer_t * b, ip4_header_t * ip4,
				ip6_header_t * ip6, void *arg)
{
  nat64_main_t *nm = &nat64_main;
  nat64_out2in_set_ctx_t *ctx = arg;
  nat64_db_bib_entry_t *bibe;
  nat64_db_st_entry_t *ste;
  ip46_address_t saddr, daddr;
  u32 sw_if_index, fib_index;
  u8 proto = ip4->protocol;
  nat64_db_t *db = &nm->db[ctx->thread_index];

  sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
  fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, sw_if_index);

  clib_memset (&saddr, 0, sizeof (saddr));
  saddr.ip4.as_u32 = ip4->src_address.as_u32;
  clib_memset (&daddr, 0, sizeof (daddr));
  daddr.ip4.as_u32 = ip4->dst_address.as_u32;

  if (proto == IP_PROTOCOL_ICMP6)
    {
      icmp46_header_t *icmp = ip4_next_header (ip4);
      u16 out_id = ((u16 *) (icmp))[2];
      proto = IP_PROTOCOL_ICMP;

      if (!
	  (icmp->type == ICMP6_echo_request
	   || icmp->type == ICMP6_echo_reply))
	return -1;

      ste =
	nat64_db_st_entry_find (db, &saddr, &daddr, out_id, 0, proto,
				fib_index, 0);
      if (!ste)
	return -1;

      bibe = nat64_db_bib_entry_by_index (db, proto, ste->bibe_index);
      if (!bibe)
	return -1;

      ip6->dst_address.as_u64[0] = ste->in_r_addr.as_u64[0];
      ip6->dst_address.as_u64[1] = ste->in_r_addr.as_u64[1];
      ip6->src_address.as_u64[0] = bibe->in_addr.as_u64[0];
      ip6->src_address.as_u64[1] = bibe->in_addr.as_u64[1];
      ((u16 *) (icmp))[2] = bibe->in_port;

      vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;
    }
  else
    {
      udp_header_t *udp = ip4_next_header (ip4);
      tcp_header_t *tcp = ip4_next_header (ip4);
      u16 dport = udp->dst_port;
      u16 sport = udp->src_port;
      u16 *checksum;
      ip_csum_t csum;

      ste =
	nat64_db_st_entry_find (db, &saddr, &daddr, sport, dport, proto,
				fib_index, 0);
      if (!ste)
	return -1;

      bibe = nat64_db_bib_entry_by_index (db, proto, ste->bibe_index);
      if (!bibe)
	return -1;

      nat64_compose_ip6 (&ip6->dst_address, &daddr.ip4, bibe->fib_index);
      ip6->src_address.as_u64[0] = bibe->in_addr.as_u64[0];
      ip6->src_address.as_u64[1] = bibe->in_addr.as_u64[1];
      udp->src_port = bibe->in_port;

      if (proto == IP_PROTOCOL_UDP)
	checksum = &udp->checksum;
      else
	checksum = &tcp->checksum;
      if (*checksum)
	{
	  csum = ip_csum_sub_even (*checksum, sport);
	  csum = ip_csum_add_even (csum, udp->src_port);
	  *checksum = ip_csum_fold (csum);
	}

      vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;
    }

  return 0;
}

static int
nat64_out2in_unk_proto (vlib_main_t * vm, vlib_buffer_t * p,
			nat64_out2in_set_ctx_t * ctx)
{
  ip4_header_t *ip4 = vlib_buffer_get_current (p);
  ip6_header_t *ip6;
  ip6_frag_hdr_t *frag;
  u32 frag_id;

  nat64_main_t *nm = &nat64_main;
  nat64_db_bib_entry_t *bibe;
  nat64_db_st_entry_t *ste;
  ip46_address_t saddr, daddr;
  ip6_address_t ip6_saddr;
  u32 sw_if_index, fib_index;
  u8 proto = ip4->protocol;
  nat64_db_t *db = &nm->db[ctx->thread_index];

  // Deal with fragmented packets
  u16 frag_offset = ip4_get_fragment_offset (ip4);
  if (PREDICT_FALSE (ip4_get_fragment_more (ip4) || frag_offset))
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
      frag->fragment_offset_and_more =
	ip6_frag_hdr_offset_and_more (frag_offset, 1);
      ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
      ip6->payload_length = u16_net_add (ip6->payload_length, sizeof (*frag));
    }

  sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
  fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  clib_memset (&saddr, 0, sizeof (saddr));
  saddr.ip4.as_u32 = ip4->src_address.as_u32;
  clib_memset (&daddr, 0, sizeof (daddr));
  daddr.ip4.as_u32 = ip4->dst_address.as_u32;

  ste =
    nat64_db_st_entry_find (db, &daddr, &saddr, 0, 0, proto, fib_index, 0);
  if (ste)
    {
      bibe = nat64_db_bib_entry_by_index (db, proto, ste->bibe_index);
      if (!bibe)
	return -1;
    }
  else
    {
      bibe = nat64_db_bib_entry_find (db, &daddr, 0, proto, fib_index, 0);

      if (!bibe)
	return -1;

      nat64_compose_ip6 (&ip6_saddr, &ip4->src_address, bibe->fib_index);
      ste = nat64_db_st_entry_create (ctx->thread_index, db,
				      bibe, &ip6_saddr, &saddr.ip4, 0);

      if (!ste)
	return -1;

      vlib_set_simple_counter (&nm->total_sessions, ctx->thread_index, 0,
			       db->st.st_entries_num);
    }

  nat64_session_reset_timeout (ste, ctx->vm);

  ip6->src_address.as_u64[0] = ste->in_r_addr.as_u64[0];
  ip6->src_address.as_u64[1] = ste->in_r_addr.as_u64[1];

  ip6->dst_address.as_u64[0] = bibe->in_addr.as_u64[0];
  ip6->dst_address.as_u64[1] = bibe->in_addr.as_u64[1];

  vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;

  return 0;
}

VLIB_NODE_FN (nat64_out2in_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  nat64_out2in_next_t next_index;
  nat64_main_t *nm = &nat64_main;
  clib_thread_index_t thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  ip4_header_t *ip40;
	  u32 proto0;
	  nat64_out2in_set_ctx_t ctx0;
	  udp_header_t *udp0;
	  u32 sw_if_index0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip40 = vlib_buffer_get_current (b0);

	  ctx0.b = b0;
	  ctx0.vm = vm;
	  ctx0.thread_index = thread_index;

	  next0 = NAT64_OUT2IN_NEXT_IP6_LOOKUP;

	  proto0 = ip_proto_to_nat_proto (ip40->protocol);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_OTHER))
	    {
	      if (nat64_out2in_unk_proto (vm, b0, &ctx0))
		{
		  next0 = NAT64_OUT2IN_NEXT_DROP;
		  b0->error = node->errors[NAT64_OUT2IN_ERROR_NO_TRANSLATION];
		}
	      vlib_increment_simple_counter (&nm->counters.out2in.other,
					     thread_index, sw_if_index0, 1);
	      goto trace0;
	    }

	  if (proto0 == NAT_PROTOCOL_ICMP)
	    {
	      vlib_increment_simple_counter (&nm->counters.out2in.icmp,
					     thread_index, sw_if_index0, 1);
	      if (icmp_to_icmp6
		  (b0, nat64_out2in_icmp_set_cb, &ctx0,
		   nat64_out2in_inner_icmp_set_cb, &ctx0))
		{
		  next0 = NAT64_OUT2IN_NEXT_DROP;
		  b0->error = node->errors[NAT64_OUT2IN_ERROR_NO_TRANSLATION];
		  goto trace0;
		}
	    }
	  else
	    {
	      if (proto0 == NAT_PROTOCOL_TCP)
		vlib_increment_simple_counter (&nm->counters.out2in.tcp,
					       thread_index, sw_if_index0, 1);
	      else
		vlib_increment_simple_counter (&nm->counters.out2in.udp,
					       thread_index, sw_if_index0, 1);

	      if (nat64_out2in_tcp_udp (vm, b0, &ctx0))
		{
		  udp0 = ip4_next_header (ip40);
		  /*
		   * Send DHCP packets to the ipv4 stack, or we won't
		   * be able to use dhcp client on the outside interface
		   */
		  if ((proto0 == NAT_PROTOCOL_UDP)
		      && (udp0->dst_port ==
			  clib_host_to_net_u16 (UDP_DST_PORT_dhcp_to_client)))
		    {
		      next0 = NAT64_OUT2IN_NEXT_IP4_LOOKUP;
		      goto trace0;
		    }
		  next0 = NAT64_OUT2IN_NEXT_DROP;
		  b0->error = node->errors[NAT64_OUT2IN_ERROR_NO_TRANSLATION];
		  goto trace0;
		}
	    }

	trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat64_out2in_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	    }

	  if (next0 == NAT64_OUT2IN_NEXT_DROP)
	    {
	      vlib_increment_simple_counter (&nm->counters.out2in.drops,
					     thread_index, sw_if_index0, 1);
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (nat64_out2in_node) = {
  .name = "nat64-out2in",
  .vector_size = sizeof (u32),
  .format_trace = format_nat64_out2in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat64_out2in_error_strings),
  .error_strings = nat64_out2in_error_strings,
  .n_next_nodes = NAT64_OUT2IN_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [NAT64_OUT2IN_NEXT_DROP] = "error-drop",
    [NAT64_OUT2IN_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [NAT64_OUT2IN_NEXT_IP4_LOOKUP] = "ip4-lookup",
  },
};

typedef struct nat64_out2in_frag_set_ctx_t_
{
  vlib_main_t *vm;
  vlib_buffer_t *b;
  u32 sess_index;
  clib_thread_index_t thread_index;
  u8 proto;
  u8 first_frag;
} nat64_out2in_frag_set_ctx_t;

#define foreach_nat64_out2in_handoff_error                       \
_(CONGESTION_DROP, "congestion drop")                            \
_(SAME_WORKER, "same worker")                                    \
_(DO_HANDOFF, "do handoff")

typedef enum
{
#define _(sym,str) NAT64_OUT2IN_HANDOFF_ERROR_##sym,
  foreach_nat64_out2in_handoff_error
#undef _
    NAT64_OUT2IN_HANDOFF_N_ERROR,
} nat64_out2in_handoff_error_t;

static char *nat64_out2in_handoff_error_strings[] = {
#define _(sym,string) string,
  foreach_nat64_out2in_handoff_error
#undef _
};

typedef struct
{
  u32 next_worker_index;
} nat64_out2in_handoff_trace_t;

static u8 *
format_nat64_out2in_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat64_out2in_handoff_trace_t *t =
    va_arg (*args, nat64_out2in_handoff_trace_t *);

  s =
    format (s, "NAT64-OUT2IN-HANDOFF: next-worker %d", t->next_worker_index);

  return s;
}

VLIB_NODE_FN (nat64_out2in_handoff_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  nat64_main_t *nm = &nat64_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_enq, n_left_from, *from;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 fq_index;
  clib_thread_index_t thread_index = vm->thread_index;
  u32 do_handoff = 0, same_worker = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  fq_index = nm->fq_out2in_index;

  while (n_left_from > 0)
    {
      ip4_header_t *ip0;

      ip0 = vlib_buffer_get_current (b[0]);
      ti[0] = nat64_get_worker_out2in (b[0], ip0);

      if (ti[0] != thread_index)
	do_handoff++;
      else
	same_worker++;

      if (PREDICT_FALSE
	  ((node->flags & VLIB_NODE_FLAG_TRACE)
	   && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat64_out2in_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->next_worker_index = ti[0];
	}

      n_left_from -= 1;
      ti += 1;
      b += 1;
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 NAT64_OUT2IN_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);
  vlib_node_increment_counter (vm, node->node_index,
			       NAT64_OUT2IN_HANDOFF_ERROR_SAME_WORKER,
			       same_worker);
  vlib_node_increment_counter (vm, node->node_index,
			       NAT64_OUT2IN_HANDOFF_ERROR_DO_HANDOFF,
			       do_handoff);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (nat64_out2in_handoff_node) = {
  .name = "nat64-out2in-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_nat64_out2in_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat64_out2in_handoff_error_strings),
  .error_strings = nat64_out2in_handoff_error_strings,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
