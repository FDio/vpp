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
 * @brief NAT64 IPv6 to IPv4 translation (inside to outside network)
 */

#include <snat/nat64.h>
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/fib/fib_table.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
} nat64_in2out_trace_t;

static u8 *
format_nat64_in2out_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat64_in2out_trace_t *t = va_arg (*args, nat64_in2out_trace_t *);

  s =
    format (s, "NAT64-in2out: sw_if_index %d, next index %d", t->sw_if_index,
	    t->next_index);

  return s;
}

vlib_node_registration_t nat64_in2out_node;

#define foreach_nat64_in2out_error                 \
_(UNSUPPORTED_PROTOCOL, "unsupported protocol")    \
_(IN2OUT_PACKETS, "good in2out packets processed") \
_(NO_TRANSLATION, "no translation")                \
_(UNKNOWN, "unknown")

typedef enum
{
#define _(sym,str) NAT64_IN2OUT_ERROR_##sym,
  foreach_nat64_in2out_error
#undef _
    NAT64_IN2OUT_N_ERROR,
} nat64_in2out_error_t;

static char *nat64_in2out_error_strings[] = {
#define _(sym,string) string,
  foreach_nat64_in2out_error
#undef _
};

typedef enum
{
  NAT64_IN2OUT_NEXT_IP4_LOOKUP,
  NAT64_IN2OUT_NEXT_IP6_LOOKUP,
  NAT64_IN2OUT_NEXT_DROP,
  NAT64_IN2OUT_N_NEXT,
} nat64_in2out_next_t;

typedef struct nat64_in2out_set_ctx_t_
{
  vlib_buffer_t *b;
  vlib_main_t *vm;
} nat64_in2out_set_ctx_t;

/**
 * @brief Check whether is a hairpinning.
 *
 * If the destination IP address of the packet is an IPv4 address assigned to
 * the NAT64 itself, then the packet is a hairpin packet.
 *
 * param dst_addr Destination address of the packet.
 *
 * @returns 1 if hairpinning, otherwise 0.
 */
static_always_inline int
is_hairpinning (ip6_address_t * dst_addr)
{
  nat64_main_t *nm = &nat64_main;
  int i;

  for (i = 0; i < vec_len (nm->addr_pool); i++)
    {
      if (nm->addr_pool[i].addr.as_u32 == dst_addr->as_u32[3])
	return 1;
    }

  return 0;
}

static int
nat64_in2out_tcp_udp_set_cb (ip6_header_t * ip6, ip4_header_t * ip4,
			     void *arg)
{
  nat64_main_t *nm = &nat64_main;
  nat64_in2out_set_ctx_t *ctx = arg;
  nat64_db_bib_entry_t *bibe;
  nat64_db_st_entry_t *ste;
  ip46_address_t saddr, daddr;
  u32 sw_if_index, fib_index;
  udp_header_t *udp = ip6_next_header (ip6);
  snat_protocol_t proto = ip_proto_to_snat_proto (ip6->protocol);
  u16 sport = udp->src_port;
  u16 dport = udp->dst_port;

  sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
  fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, sw_if_index);

  saddr.as_u64[0] = ip6->src_address.as_u64[0];
  saddr.as_u64[1] = ip6->src_address.as_u64[1];
  daddr.as_u64[0] = ip6->dst_address.as_u64[0];
  daddr.as_u64[1] = ip6->dst_address.as_u64[1];

  ste =
    nat64_db_st_entry_find (&nm->db, &saddr, &daddr, sport, dport, proto,
			    fib_index, 1);

  if (ste)
    {
      bibe = nat64_db_bib_entry_by_index (&nm->db, proto, ste->bibe_index);
      if (!bibe)
	return -1;
    }
  else
    {
      bibe =
	nat64_db_bib_entry_find (&nm->db, &saddr, sport, proto, fib_index, 1);

      if (!bibe)
	{
	  u16 out_port;
	  ip4_address_t out_addr;
	  if (nat64_alloc_out_addr_and_port
	      (fib_index, proto, &out_addr, &out_port))
	    return -1;

	  bibe =
	    nat64_db_bib_entry_create (&nm->db, &ip6->src_address, &out_addr,
				       sport, clib_host_to_net_u16 (out_port),
				       fib_index, proto, 0);
	  if (!bibe)
	    return -1;
	}

      nat64_extract_ip4 (&ip6->dst_address, &daddr.ip4, fib_index);
      ste =
	nat64_db_st_entry_create (&nm->db, bibe, &ip6->dst_address,
				  &daddr.ip4, dport);
      if (!ste)
	return -1;
    }

  nat64_session_reset_timeout (ste, ctx->vm);

  ip4->src_address.as_u32 = bibe->out_addr.as_u32;
  udp->src_port = bibe->out_port;

  ip4->dst_address.as_u32 = ste->out_r_addr.as_u32;

  if (proto == SNAT_PROTOCOL_TCP)
    {
      u16 *checksum;
      ip_csum_t csum;
      tcp_header_t *tcp = ip6_next_header (ip6);

      checksum = &tcp->checksum;
      csum = ip_csum_sub_even (*checksum, sport);
      csum = ip_csum_add_even (csum, udp->src_port);
      *checksum = ip_csum_fold (csum);
    }

  return 0;
}

static int
nat64_in2out_icmp_set_cb (ip6_header_t * ip6, ip4_header_t * ip4, void *arg)
{
  nat64_main_t *nm = &nat64_main;
  nat64_in2out_set_ctx_t *ctx = arg;
  nat64_db_bib_entry_t *bibe;
  nat64_db_st_entry_t *ste;
  ip46_address_t saddr, daddr;
  u32 sw_if_index, fib_index;
  icmp46_header_t *icmp = ip6_next_header (ip6);

  sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
  fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, sw_if_index);

  saddr.as_u64[0] = ip6->src_address.as_u64[0];
  saddr.as_u64[1] = ip6->src_address.as_u64[1];
  daddr.as_u64[0] = ip6->dst_address.as_u64[0];
  daddr.as_u64[1] = ip6->dst_address.as_u64[1];

  if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply)
    {
      u16 in_id = ((u16 *) (icmp))[2];
      ste =
	nat64_db_st_entry_find (&nm->db, &saddr, &daddr, in_id, 0,
				SNAT_PROTOCOL_ICMP, fib_index, 1);

      if (ste)
	{
	  bibe =
	    nat64_db_bib_entry_by_index (&nm->db, SNAT_PROTOCOL_ICMP,
					 ste->bibe_index);
	  if (!bibe)
	    return -1;
	}
      else
	{
	  bibe =
	    nat64_db_bib_entry_find (&nm->db, &saddr, in_id,
				     SNAT_PROTOCOL_ICMP, fib_index, 1);

	  if (!bibe)
	    {
	      u16 out_id;
	      ip4_address_t out_addr;
	      if (nat64_alloc_out_addr_and_port
		  (fib_index, SNAT_PROTOCOL_ICMP, &out_addr, &out_id))
		return -1;

	      bibe =
		nat64_db_bib_entry_create (&nm->db, &ip6->src_address,
					   &out_addr, in_id,
					   clib_host_to_net_u16 (out_id),
					   fib_index, SNAT_PROTOCOL_ICMP, 0);
	      if (!bibe)
		return -1;
	    }

	  nat64_extract_ip4 (&ip6->dst_address, &daddr.ip4, fib_index);
	  ste =
	    nat64_db_st_entry_create (&nm->db, bibe, &ip6->dst_address,
				      &daddr.ip4, 0);
	  if (!ste)
	    return -1;
	}

      nat64_session_reset_timeout (ste, ctx->vm);

      ip4->src_address.as_u32 = bibe->out_addr.as_u32;
      ((u16 *) (icmp))[2] = bibe->out_port;

      ip4->dst_address.as_u32 = ste->out_r_addr.as_u32;
    }
  else
    {
      if (!vec_len (nm->addr_pool))
	return -1;

      ip4->src_address.as_u32 = nm->addr_pool[0].addr.as_u32;
      nat64_extract_ip4 (&ip6->dst_address, &ip4->dst_address, fib_index);
    }

  return 0;
}

static int
nat64_in2out_inner_icmp_set_cb (ip6_header_t * ip6, ip4_header_t * ip4,
				void *arg)
{
  nat64_main_t *nm = &nat64_main;
  nat64_in2out_set_ctx_t *ctx = arg;
  nat64_db_st_entry_t *ste;
  nat64_db_bib_entry_t *bibe;
  ip46_address_t saddr, daddr;
  u32 sw_if_index, fib_index;
  snat_protocol_t proto = ip_proto_to_snat_proto (ip6->protocol);

  sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
  fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, sw_if_index);

  saddr.as_u64[0] = ip6->src_address.as_u64[0];
  saddr.as_u64[1] = ip6->src_address.as_u64[1];
  daddr.as_u64[0] = ip6->dst_address.as_u64[0];
  daddr.as_u64[1] = ip6->dst_address.as_u64[1];

  if (proto == SNAT_PROTOCOL_ICMP)
    {
      icmp46_header_t *icmp = ip6_next_header (ip6);
      u16 in_id = ((u16 *) (icmp))[2];

      if (!
	  (icmp->type == ICMP4_echo_request
	   || icmp->type == ICMP4_echo_reply))
	return -1;

      ste =
	nat64_db_st_entry_find (&nm->db, &daddr, &saddr, in_id, 0, proto,
				fib_index, 1);
      if (!ste)
	return -1;

      bibe = nat64_db_bib_entry_by_index (&nm->db, proto, ste->bibe_index);
      if (!bibe)
	return -1;

      ip4->dst_address.as_u32 = bibe->out_addr.as_u32;
      ((u16 *) (icmp))[2] = bibe->out_port;
      ip4->src_address.as_u32 = ste->out_r_addr.as_u32;
    }
  else
    {
      udp_header_t *udp = ip6_next_header (ip6);
      tcp_header_t *tcp = ip6_next_header (ip6);
      u16 *checksum;
      ip_csum_t csum;

      u16 sport = udp->src_port;
      u16 dport = udp->dst_port;

      ste =
	nat64_db_st_entry_find (&nm->db, &daddr, &saddr, dport, sport, proto,
				fib_index, 1);
      if (!ste)
	return -1;

      bibe = nat64_db_bib_entry_by_index (&nm->db, proto, ste->bibe_index);
      if (!bibe)
	return -1;

      ip4->dst_address.as_u32 = bibe->out_addr.as_u32;
      udp->dst_port = bibe->out_port;
      ip4->src_address.as_u32 = ste->out_r_addr.as_u32;

      if (proto == SNAT_PROTOCOL_TCP)
	checksum = &tcp->checksum;
      else
	checksum = &udp->checksum;
      csum = ip_csum_sub_even (*checksum, dport);
      csum = ip_csum_add_even (csum, udp->dst_port);
      *checksum = ip_csum_fold (csum);
    }

  return 0;
}

static int
nat64_in2out_tcp_udp_hairpinning (vlib_main_t * vm, vlib_buffer_t * b,
				  ip6_header_t * ip6)
{
  nat64_main_t *nm = &nat64_main;
  nat64_db_bib_entry_t *bibe;
  nat64_db_st_entry_t *ste;
  ip46_address_t saddr, daddr;
  u32 sw_if_index, fib_index;
  udp_header_t *udp = ip6_next_header (ip6);
  tcp_header_t *tcp = ip6_next_header (ip6);
  snat_protocol_t proto = ip_proto_to_snat_proto (ip6->protocol);
  u16 sport = udp->src_port;
  u16 dport = udp->dst_port;
  u16 *checksum;
  ip_csum_t csum;

  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, sw_if_index);

  saddr.as_u64[0] = ip6->src_address.as_u64[0];
  saddr.as_u64[1] = ip6->src_address.as_u64[1];
  daddr.as_u64[0] = ip6->dst_address.as_u64[0];
  daddr.as_u64[1] = ip6->dst_address.as_u64[1];

  if (proto == SNAT_PROTOCOL_UDP)
    checksum = &udp->checksum;
  else
    checksum = &tcp->checksum;

  csum = ip_csum_sub_even (*checksum, ip6->src_address.as_u64[0]);
  csum = ip_csum_sub_even (csum, ip6->src_address.as_u64[1]);
  csum = ip_csum_sub_even (csum, ip6->dst_address.as_u64[0]);
  csum = ip_csum_sub_even (csum, ip6->dst_address.as_u64[1]);
  csum = ip_csum_sub_even (csum, sport);
  csum = ip_csum_sub_even (csum, dport);

  ste =
    nat64_db_st_entry_find (&nm->db, &saddr, &daddr, sport, dport, proto,
			    fib_index, 1);

  if (ste)
    {
      bibe = nat64_db_bib_entry_by_index (&nm->db, proto, ste->bibe_index);
      if (!bibe)
	return -1;
    }
  else
    {
      bibe =
	nat64_db_bib_entry_find (&nm->db, &saddr, sport, proto, fib_index, 1);

      if (!bibe)
	{
	  u16 out_port;
	  ip4_address_t out_addr;
	  if (nat64_alloc_out_addr_and_port
	      (fib_index, proto, &out_addr, &out_port))
	    return -1;

	  bibe =
	    nat64_db_bib_entry_create (&nm->db, &ip6->src_address, &out_addr,
				       sport, clib_host_to_net_u16 (out_port),
				       fib_index, proto, 0);
	  if (!bibe)
	    return -1;
	}

      nat64_extract_ip4 (&ip6->dst_address, &daddr.ip4, fib_index);
      ste =
	nat64_db_st_entry_create (&nm->db, bibe, &ip6->dst_address,
				  &daddr.ip4, dport);
      if (!ste)
	return -1;
    }

  nat64_session_reset_timeout (ste, vm);

  sport = udp->src_port = bibe->out_port;
  nat64_compose_ip6 (&ip6->src_address, &bibe->out_addr, fib_index);

  memset (&saddr, 0, sizeof (saddr));
  memset (&daddr, 0, sizeof (daddr));
  saddr.ip4.as_u32 = bibe->out_addr.as_u32;
  daddr.ip4.as_u32 = ste->out_r_addr.as_u32;

  ste =
    nat64_db_st_entry_find (&nm->db, &daddr, &saddr, dport, sport, proto, 0,
			    0);

  if (ste)
    {
      bibe = nat64_db_bib_entry_by_index (&nm->db, proto, ste->bibe_index);
      if (!bibe)
	return -1;
    }
  else
    {
      bibe = nat64_db_bib_entry_find (&nm->db, &daddr, dport, proto, 0, 0);

      if (!bibe)
	return -1;

      ste =
	nat64_db_st_entry_create (&nm->db, bibe, &ip6->src_address,
				  &saddr.ip4, sport);
    }

  ip6->dst_address.as_u64[0] = bibe->in_addr.as_u64[0];
  ip6->dst_address.as_u64[1] = bibe->in_addr.as_u64[1];
  udp->dst_port = bibe->in_port;

  csum = ip_csum_add_even (csum, ip6->src_address.as_u64[0]);
  csum = ip_csum_add_even (csum, ip6->src_address.as_u64[1]);
  csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[0]);
  csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[1]);
  csum = ip_csum_add_even (csum, udp->src_port);
  csum = ip_csum_add_even (csum, udp->dst_port);
  *checksum = ip_csum_fold (csum);

  return 0;
}

static int
nat64_in2out_icmp_hairpinning (vlib_main_t * vm, vlib_buffer_t * b,
			       ip6_header_t * ip6)
{
  nat64_main_t *nm = &nat64_main;
  nat64_db_bib_entry_t *bibe;
  nat64_db_st_entry_t *ste;
  icmp46_header_t *icmp = ip6_next_header (ip6);
  ip6_header_t *inner_ip6;
  ip46_address_t saddr, daddr;
  u32 sw_if_index, fib_index;
  snat_protocol_t proto;
  udp_header_t *udp;
  tcp_header_t *tcp;
  u16 *checksum, sport, dport;
  ip_csum_t csum;

  if (icmp->type == ICMP6_echo_request || icmp->type == ICMP6_echo_reply)
    return -1;

  inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);

  proto = ip_proto_to_snat_proto (inner_ip6->protocol);

  if (proto == SNAT_PROTOCOL_ICMP)
    return -1;

  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, sw_if_index);

  saddr.as_u64[0] = inner_ip6->src_address.as_u64[0];
  saddr.as_u64[1] = inner_ip6->src_address.as_u64[1];
  daddr.as_u64[0] = inner_ip6->dst_address.as_u64[0];
  daddr.as_u64[1] = inner_ip6->dst_address.as_u64[1];

  udp = ip6_next_header (inner_ip6);
  tcp = ip6_next_header (inner_ip6);

  sport = udp->src_port;
  dport = udp->dst_port;

  if (proto == SNAT_PROTOCOL_UDP)
    checksum = &udp->checksum;
  else
    checksum = &tcp->checksum;

  csum = ip_csum_sub_even (*checksum, inner_ip6->src_address.as_u64[0]);
  csum = ip_csum_sub_even (csum, inner_ip6->src_address.as_u64[1]);
  csum = ip_csum_sub_even (csum, inner_ip6->dst_address.as_u64[0]);
  csum = ip_csum_sub_even (csum, inner_ip6->dst_address.as_u64[1]);
  csum = ip_csum_sub_even (csum, sport);
  csum = ip_csum_sub_even (csum, dport);

  ste =
    nat64_db_st_entry_find (&nm->db, &daddr, &saddr, dport, sport, proto,
			    fib_index, 1);
  if (!ste)
    return -1;

  bibe = nat64_db_bib_entry_by_index (&nm->db, proto, ste->bibe_index);
  if (!bibe)
    return -1;

  dport = udp->dst_port = bibe->out_port;
  nat64_compose_ip6 (&inner_ip6->dst_address, &bibe->out_addr, fib_index);

  memset (&saddr, 0, sizeof (saddr));
  memset (&daddr, 0, sizeof (daddr));
  saddr.ip4.as_u32 = ste->out_r_addr.as_u32;
  daddr.ip4.as_u32 = bibe->out_addr.as_u32;

  ste =
    nat64_db_st_entry_find (&nm->db, &saddr, &daddr, sport, dport, proto, 0,
			    0);
  if (!ste)
    return -1;

  bibe = nat64_db_bib_entry_by_index (&nm->db, proto, ste->bibe_index);
  if (!bibe)
    return -1;

  inner_ip6->src_address.as_u64[0] = bibe->in_addr.as_u64[0];
  inner_ip6->src_address.as_u64[1] = bibe->in_addr.as_u64[1];
  udp->src_port = bibe->in_port;

  csum = ip_csum_add_even (csum, inner_ip6->src_address.as_u64[0]);
  csum = ip_csum_add_even (csum, inner_ip6->src_address.as_u64[1]);
  csum = ip_csum_add_even (csum, inner_ip6->dst_address.as_u64[0]);
  csum = ip_csum_add_even (csum, inner_ip6->dst_address.as_u64[1]);
  csum = ip_csum_add_even (csum, udp->src_port);
  csum = ip_csum_add_even (csum, udp->dst_port);
  *checksum = ip_csum_fold (csum);

  if (!vec_len (nm->addr_pool))
    return -1;

  nat64_compose_ip6 (&ip6->src_address, &nm->addr_pool[0].addr, fib_index);
  ip6->dst_address.as_u64[0] = inner_ip6->src_address.as_u64[0];
  ip6->dst_address.as_u64[1] = inner_ip6->src_address.as_u64[1];

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

static uword
nat64_in2out_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  nat64_in2out_next_t next_index;
  u32 pkts_processed = 0;

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
	  ip6_header_t *ip60;
	  u16 l4_offset0, frag_offset0;
	  u8 l4_protocol0;
	  u32 proto0;
	  nat64_in2out_set_ctx_t ctx0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip60 = vlib_buffer_get_current (b0);

	  ctx0.b = b0;
	  ctx0.vm = vm;

	  next0 = NAT64_IN2OUT_NEXT_IP4_LOOKUP;

	  if (PREDICT_FALSE
	      (ip6_parse
	       (ip60, b0->current_length, &l4_protocol0, &l4_offset0,
		&frag_offset0)))
	    {
	      next0 = NAT64_IN2OUT_NEXT_DROP;
	      b0->error = node->errors[NAT64_IN2OUT_ERROR_UNKNOWN];
	      goto trace0;
	    }

	  proto0 = ip_proto_to_snat_proto (l4_protocol0);
	  if (PREDICT_FALSE ((proto0 == ~0) || (frag_offset0 != 0)))
	    {
	      next0 = NAT64_IN2OUT_NEXT_DROP;
	      b0->error =
		node->errors[NAT64_IN2OUT_ERROR_UNSUPPORTED_PROTOCOL];
	      goto trace0;
	    }

	  if (proto0 == SNAT_PROTOCOL_ICMP)
	    {
	      if (is_hairpinning (&ip60->dst_address))
		{
		  next0 = NAT64_IN2OUT_NEXT_IP6_LOOKUP;
		  if (nat64_in2out_icmp_hairpinning (vm, b0, ip60))
		    {
		      next0 = NAT64_IN2OUT_NEXT_DROP;
		      b0->error =
			node->errors[NAT64_IN2OUT_ERROR_NO_TRANSLATION];
		    }
		  goto trace0;
		}

	      if (icmp6_to_icmp
		  (b0, nat64_in2out_icmp_set_cb, &ctx0,
		   nat64_in2out_inner_icmp_set_cb, &ctx0))
		{
		  next0 = NAT64_IN2OUT_NEXT_DROP;
		  b0->error = node->errors[NAT64_IN2OUT_ERROR_NO_TRANSLATION];
		  goto trace0;
		}
	    }
	  else
	    {
	      if (is_hairpinning (&ip60->dst_address))
		{
		  next0 = NAT64_IN2OUT_NEXT_IP6_LOOKUP;
		  if (nat64_in2out_tcp_udp_hairpinning (vm, b0, ip60))
		    {
		      next0 = NAT64_IN2OUT_NEXT_DROP;
		      b0->error =
			node->errors[NAT64_IN2OUT_ERROR_NO_TRANSLATION];
		    }
		  goto trace0;
		}

	      if (ip6_to_ip4_tcp_udp
		  (b0, nat64_in2out_tcp_udp_set_cb, &ctx0, 0))
		{
		  next0 = NAT64_IN2OUT_NEXT_DROP;
		  b0->error = node->errors[NAT64_IN2OUT_ERROR_NO_TRANSLATION];
		  goto trace0;
		}
	    }

	trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat64_in2out_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	    }

	  pkts_processed += next0 != NAT64_IN2OUT_NEXT_DROP;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, nat64_in2out_node.index,
			       NAT64_IN2OUT_ERROR_IN2OUT_PACKETS,
			       pkts_processed);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat64_in2out_node) = {
  .function = nat64_in2out_node_fn,.name = "nat64-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_nat64_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat64_in2out_error_strings),
  .error_strings = nat64_in2out_error_strings,
  .n_next_nodes = 2,
  /* edit / add dispositions here */
  .next_nodes = {
    [NAT64_IN2OUT_NEXT_DROP] = "error-drop",
    [NAT64_IN2OUT_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [NAT64_IN2OUT_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (nat64_in2out_node, nat64_in2out_node_fn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
