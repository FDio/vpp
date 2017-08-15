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
 * @brief NAT64 IPv4 to IPv6 translation (otside to inside network)
 */

#include <nat/nat64.h>
#include <nat/nat_reass.h>
#include <vnet/ip/ip4_to_ip6.h>
#include <vnet/fib/ip4_fib.h>

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

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u8 cached;
} nat64_out2in_reass_trace_t;

static u8 *
format_nat64_out2in_reass_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat64_out2in_reass_trace_t *t =
    va_arg (*args, nat64_out2in_reass_trace_t *);

  s =
    format (s, "NAT64-out2in-reass: sw_if_index %d, next index %d, status %s",
	    t->sw_if_index, t->next_index,
	    t->cached ? "cached" : "translated");

  return s;
}

vlib_node_registration_t nat64_out2in_node;
vlib_node_registration_t nat64_out2in_reass_node;

#define foreach_nat64_out2in_error                       \
_(UNSUPPORTED_PROTOCOL, "Unsupported protocol")          \
_(OUT2IN_PACKETS, "Good out2in packets processed")       \
_(NO_TRANSLATION, "No translation")                      \
_(UNKNOWN, "unknown")                                    \
_(DROP_FRAGMENT, "Drop fragment")                        \
_(MAX_REASS, "Maximum reassemblies exceeded")            \
_(MAX_FRAG, "Maximum fragments per reassembly exceeded")


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
  NAT64_OUT2IN_NEXT_LOOKUP,
  NAT64_OUT2IN_NEXT_DROP,
  NAT64_OUT2IN_NEXT_REASS,
  NAT64_OUT2IN_N_NEXT,
} nat64_out2in_next_t;

typedef struct nat64_out2in_set_ctx_t_
{
  vlib_buffer_t *b;
  vlib_main_t *vm;
} nat64_out2in_set_ctx_t;

static int
nat64_out2in_tcp_udp_set_cb (ip4_header_t * ip4, ip6_header_t * ip6,
			     void *arg)
{
  nat64_main_t *nm = &nat64_main;
  nat64_out2in_set_ctx_t *ctx = arg;
  nat64_db_bib_entry_t *bibe;
  nat64_db_st_entry_t *ste;
  ip46_address_t saddr, daddr;
  ip6_address_t ip6_saddr;
  udp_header_t *udp = ip4_next_header (ip4);
  tcp_header_t *tcp = ip4_next_header (ip4);
  u8 proto = ip4->protocol;
  u16 dport = udp->dst_port;
  u16 sport = udp->src_port;
  u32 sw_if_index, fib_index;
  u16 *checksum;
  ip_csum_t csum;

  sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
  fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  memset (&saddr, 0, sizeof (saddr));
  saddr.ip4.as_u32 = ip4->src_address.as_u32;
  memset (&daddr, 0, sizeof (daddr));
  daddr.ip4.as_u32 = ip4->dst_address.as_u32;

  ste =
    nat64_db_st_entry_find (&nm->db, &daddr, &saddr, dport, sport, proto,
			    fib_index, 0);
  if (ste)
    {
      bibe = nat64_db_bib_entry_by_index (&nm->db, proto, ste->bibe_index);
      if (!bibe)
	return -1;
    }
  else
    {
      bibe =
	nat64_db_bib_entry_find (&nm->db, &daddr, dport, proto, fib_index, 0);

      if (!bibe)
	return -1;

      nat64_compose_ip6 (&ip6_saddr, &ip4->src_address, bibe->fib_index);
      ste =
	nat64_db_st_entry_create (&nm->db, bibe, &ip6_saddr, &saddr.ip4,
				  sport);
    }

  nat64_session_reset_timeout (ste, ctx->vm);

  ip6->src_address.as_u64[0] = ste->in_r_addr.as_u64[0];
  ip6->src_address.as_u64[1] = ste->in_r_addr.as_u64[1];

  ip6->dst_address.as_u64[0] = bibe->in_addr.as_u64[0];
  ip6->dst_address.as_u64[1] = bibe->in_addr.as_u64[1];
  udp->dst_port = bibe->in_port;

  if (proto == IP_PROTOCOL_UDP)
    checksum = &udp->checksum;
  else
    checksum = &tcp->checksum;
  csum = ip_csum_sub_even (*checksum, dport);
  csum = ip_csum_add_even (csum, udp->dst_port);
  *checksum = ip_csum_fold (csum);

  vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;

  return 0;
}

static int
nat64_out2in_icmp_set_cb (ip4_header_t * ip4, ip6_header_t * ip6, void *arg)
{
  nat64_main_t *nm = &nat64_main;
  nat64_out2in_set_ctx_t *ctx = arg;
  nat64_db_bib_entry_t *bibe;
  nat64_db_st_entry_t *ste;
  ip46_address_t saddr, daddr;
  ip6_address_t ip6_saddr;
  u32 sw_if_index, fib_index;
  icmp46_header_t *icmp = ip4_next_header (ip4);

  sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
  fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  memset (&saddr, 0, sizeof (saddr));
  saddr.ip4.as_u32 = ip4->src_address.as_u32;
  memset (&daddr, 0, sizeof (daddr));
  daddr.ip4.as_u32 = ip4->dst_address.as_u32;

  if (icmp->type == ICMP6_echo_request || icmp->type == ICMP6_echo_reply)
    {
      u16 out_id = ((u16 *) (icmp))[2];
      ste =
	nat64_db_st_entry_find (&nm->db, &daddr, &saddr, out_id, 0,
				IP_PROTOCOL_ICMP, fib_index, 0);

      if (ste)
	{
	  bibe =
	    nat64_db_bib_entry_by_index (&nm->db, IP_PROTOCOL_ICMP,
					 ste->bibe_index);
	  if (!bibe)
	    return -1;
	}
      else
	{
	  bibe =
	    nat64_db_bib_entry_find (&nm->db, &daddr, out_id,
				     IP_PROTOCOL_ICMP, fib_index, 0);
	  if (!bibe)
	    return -1;

	  nat64_compose_ip6 (&ip6_saddr, &ip4->src_address, bibe->fib_index);
	  ste =
	    nat64_db_st_entry_create (&nm->db, bibe, &ip6_saddr, &saddr.ip4,
				      0);
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
nat64_out2in_inner_icmp_set_cb (ip4_header_t * ip4, ip6_header_t * ip6,
				void *arg)
{
  nat64_main_t *nm = &nat64_main;
  nat64_out2in_set_ctx_t *ctx = arg;
  nat64_db_bib_entry_t *bibe;
  nat64_db_st_entry_t *ste;
  ip46_address_t saddr, daddr;
  u32 sw_if_index, fib_index;
  u8 proto = ip4->protocol;

  sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
  fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, sw_if_index);

  memset (&saddr, 0, sizeof (saddr));
  saddr.ip4.as_u32 = ip4->src_address.as_u32;
  memset (&daddr, 0, sizeof (daddr));
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
	nat64_db_st_entry_find (&nm->db, &saddr, &daddr, out_id, 0, proto,
				fib_index, 0);
      if (!ste)
	return -1;

      bibe = nat64_db_bib_entry_by_index (&nm->db, proto, ste->bibe_index);
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
	nat64_db_st_entry_find (&nm->db, &saddr, &daddr, sport, dport, proto,
				fib_index, 0);
      if (!ste)
	return -1;

      bibe = nat64_db_bib_entry_by_index (&nm->db, proto, ste->bibe_index);
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
nat64_out2in_unk_proto_set_cb (ip4_header_t * ip4, ip6_header_t * ip6,
			       void *arg)
{
  nat64_main_t *nm = &nat64_main;
  nat64_out2in_set_ctx_t *ctx = arg;
  nat64_db_bib_entry_t *bibe;
  nat64_db_st_entry_t *ste;
  ip46_address_t saddr, daddr;
  ip6_address_t ip6_saddr;
  u32 sw_if_index, fib_index;
  u8 proto = ip4->protocol;

  sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
  fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  memset (&saddr, 0, sizeof (saddr));
  saddr.ip4.as_u32 = ip4->src_address.as_u32;
  memset (&daddr, 0, sizeof (daddr));
  daddr.ip4.as_u32 = ip4->dst_address.as_u32;

  ste =
    nat64_db_st_entry_find (&nm->db, &daddr, &saddr, 0, 0, proto, fib_index,
			    0);
  if (ste)
    {
      bibe = nat64_db_bib_entry_by_index (&nm->db, proto, ste->bibe_index);
      if (!bibe)
	return -1;
    }
  else
    {
      bibe =
	nat64_db_bib_entry_find (&nm->db, &daddr, 0, proto, fib_index, 0);

      if (!bibe)
	return -1;

      nat64_compose_ip6 (&ip6_saddr, &ip4->src_address, bibe->fib_index);
      ste =
	nat64_db_st_entry_create (&nm->db, bibe, &ip6_saddr, &saddr.ip4, 0);
    }

  nat64_session_reset_timeout (ste, ctx->vm);

  ip6->src_address.as_u64[0] = ste->in_r_addr.as_u64[0];
  ip6->src_address.as_u64[1] = ste->in_r_addr.as_u64[1];

  ip6->dst_address.as_u64[0] = bibe->in_addr.as_u64[0];
  ip6->dst_address.as_u64[1] = bibe->in_addr.as_u64[1];

  vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;

  return 0;
}

static uword
nat64_out2in_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  nat64_out2in_next_t next_index;
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
	  ip4_header_t *ip40;
	  u32 proto0;
	  nat64_out2in_set_ctx_t ctx0;

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

	  next0 = NAT64_OUT2IN_NEXT_LOOKUP;

	  proto0 = ip_proto_to_snat_proto (ip40->protocol);

	  if (PREDICT_FALSE (proto0 == ~0))
	    {
	      if (ip4_to_ip6 (b0, nat64_out2in_unk_proto_set_cb, &ctx0))
		{
		  next0 = NAT64_OUT2IN_NEXT_DROP;
		  b0->error = node->errors[NAT64_OUT2IN_ERROR_NO_TRANSLATION];
		}
	      goto trace0;
	    }

	  if (PREDICT_FALSE (ip4_is_fragment (ip40)))
	    {
	      next0 = NAT64_OUT2IN_NEXT_REASS;
	      goto trace0;
	    }

	  if (proto0 == SNAT_PROTOCOL_ICMP)
	    {
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
	      if (ip4_to_ip6_tcp_udp (b0, nat64_out2in_tcp_udp_set_cb, &ctx0))
		{
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

	  pkts_processed += next0 != NAT64_OUT2IN_NEXT_DROP;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, nat64_out2in_node.index,
			       NAT64_OUT2IN_ERROR_OUT2IN_PACKETS,
			       pkts_processed);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat64_out2in_node) = {
  .function = nat64_out2in_node_fn,
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
    [NAT64_OUT2IN_NEXT_LOOKUP] = "ip6-lookup",
    [NAT64_OUT2IN_NEXT_REASS] = "nat64-out2in-reass",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (nat64_out2in_node, nat64_out2in_node_fn);

typedef struct nat64_out2in_frag_set_ctx_t_
{
  vlib_main_t *vm;
  vlib_buffer_t *b;
  u32 sess_index;
  u8 proto;
  u8 first_frag;
} nat64_out2in_frag_set_ctx_t;

static int
nat64_out2in_frag_set_cb (ip4_header_t * ip4, ip6_header_t * ip6, void *arg)
{
  nat64_main_t *nm = &nat64_main;
  nat64_out2in_frag_set_ctx_t *ctx = arg;
  nat64_db_st_entry_t *ste;
  nat64_db_bib_entry_t *bibe;
  udp_header_t *udp = ip4_next_header (ip4);
  ip_csum_t csum;
  u16 *checksum;

  ste = nat64_db_st_entry_by_index (&nm->db, ctx->proto, ctx->sess_index);
  if (!ste)
    return -1;

  bibe = nat64_db_bib_entry_by_index (&nm->db, ctx->proto, ste->bibe_index);
  if (!bibe)
    return -1;

  nat64_session_reset_timeout (ste, ctx->vm);

  if (ctx->first_frag)
    {
      udp->dst_port = bibe->in_port;

      if (ip4->protocol == IP_PROTOCOL_UDP)
	{
	  checksum = &udp->checksum;

	  if (!checksum)
	    {
	      u16 udp_len =
		clib_host_to_net_u16 (ip4->length) - sizeof (*ip4);
	      csum = ip_incremental_checksum (0, udp, udp_len);
	      csum =
		ip_csum_with_carry (csum, clib_host_to_net_u16 (udp_len));
	      csum =
		ip_csum_with_carry (csum,
				    clib_host_to_net_u16 (IP_PROTOCOL_UDP));
	      csum = ip_csum_with_carry (csum, ste->in_r_addr.as_u64[0]);
	      csum = ip_csum_with_carry (csum, ste->in_r_addr.as_u64[1]);
	      csum = ip_csum_with_carry (csum, bibe->in_addr.as_u64[0]);
	      csum = ip_csum_with_carry (csum, bibe->in_addr.as_u64[1]);
	      *checksum = ~ip_csum_fold (csum);
	    }
	  else
	    {
	      csum = ip_csum_sub_even (*checksum, bibe->out_addr.as_u32);
	      csum = ip_csum_sub_even (csum, ste->out_r_addr.as_u32);
	      csum = ip_csum_sub_even (csum, bibe->out_port);
	      csum = ip_csum_add_even (csum, ste->in_r_addr.as_u64[0]);
	      csum = ip_csum_add_even (csum, ste->in_r_addr.as_u64[1]);
	      csum = ip_csum_add_even (csum, bibe->in_addr.as_u64[0]);
	      csum = ip_csum_add_even (csum, bibe->in_addr.as_u64[1]);
	      csum = ip_csum_add_even (csum, bibe->in_port);
	      *checksum = ip_csum_fold (csum);
	    }
	}
      else
	{
	  tcp_header_t *tcp = ip4_next_header (ip4);
	  checksum = &tcp->checksum;
	  csum = ip_csum_sub_even (*checksum, bibe->out_addr.as_u32);
	  csum = ip_csum_sub_even (csum, ste->out_r_addr.as_u32);
	  csum = ip_csum_sub_even (csum, bibe->out_port);
	  csum = ip_csum_add_even (csum, ste->in_r_addr.as_u64[0]);
	  csum = ip_csum_add_even (csum, ste->in_r_addr.as_u64[1]);
	  csum = ip_csum_add_even (csum, bibe->in_addr.as_u64[0]);
	  csum = ip_csum_add_even (csum, bibe->in_addr.as_u64[1]);
	  csum = ip_csum_add_even (csum, bibe->in_port);
	  *checksum = ip_csum_fold (csum);
	}

    }

  ip6->src_address.as_u64[0] = ste->in_r_addr.as_u64[0];
  ip6->src_address.as_u64[1] = ste->in_r_addr.as_u64[1];

  ip6->dst_address.as_u64[0] = bibe->in_addr.as_u64[0];
  ip6->dst_address.as_u64[1] = bibe->in_addr.as_u64[1];

  vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;

  return 0;
}

static uword
nat64_out2in_reass_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  nat64_out2in_next_t next_index;
  u32 pkts_processed = 0;
  u32 *fragments_to_drop = 0;
  u32 *fragments_to_loopback = 0;
  nat64_main_t *nm = &nat64_main;

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
	  u8 cached0 = 0;
	  u32 sw_if_index0, fib_index0;
	  udp_header_t *udp0;
	  nat_reass_ip4_t *reass0;
	  ip46_address_t saddr0, daddr0;
	  nat64_db_st_entry_t *ste0;
	  nat64_db_bib_entry_t *bibe0;
	  ip6_address_t ip6_saddr0;
	  nat64_out2in_frag_set_ctx_t ctx0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  next0 = NAT64_OUT2IN_NEXT_LOOKUP;

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  fib_index0 =
	    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						 sw_if_index0);

	  if (PREDICT_FALSE (nat_reass_is_drop_frag (1)))
	    {
	      next0 = NAT64_OUT2IN_NEXT_DROP;
	      b0->error = node->errors[NAT64_OUT2IN_ERROR_DROP_FRAGMENT];
	      goto trace0;
	    }

	  ip40 = vlib_buffer_get_current (b0);

	  if (PREDICT_FALSE (!(ip40->protocol == IP_PROTOCOL_TCP
			       || ip40->protocol == IP_PROTOCOL_UDP)))
	    {
	      next0 = NAT64_OUT2IN_NEXT_DROP;
	      b0->error = node->errors[NAT64_OUT2IN_ERROR_DROP_FRAGMENT];
	      goto trace0;
	    }

	  udp0 = ip4_next_header (ip40);

	  reass0 = nat_ip4_reass_find_or_create (ip40->src_address,
						 ip40->dst_address,
						 ip40->fragment_id,
						 ip40->protocol,
						 1, &fragments_to_drop);

	  if (PREDICT_FALSE (!reass0))
	    {
	      next0 = NAT64_OUT2IN_NEXT_DROP;
	      b0->error = node->errors[NAT64_OUT2IN_ERROR_MAX_REASS];
	      goto trace0;
	    }

	  if (PREDICT_FALSE (ip4_is_first_fragment (ip40)))
	    {
	      ctx0.first_frag = 1;

	      memset (&saddr0, 0, sizeof (saddr0));
	      saddr0.ip4.as_u32 = ip40->src_address.as_u32;
	      memset (&daddr0, 0, sizeof (daddr0));
	      daddr0.ip4.as_u32 = ip40->dst_address.as_u32;

	      ste0 =
		nat64_db_st_entry_find (&nm->db, &daddr0, &saddr0,
					udp0->dst_port, udp0->src_port,
					ip40->protocol, fib_index0, 0);
	      if (!ste0)
		{
		  bibe0 =
		    nat64_db_bib_entry_find (&nm->db, &daddr0, udp0->dst_port,
					     ip40->protocol, fib_index0, 0);
		  if (!bibe0)
		    {
		      next0 = NAT64_OUT2IN_NEXT_DROP;
		      b0->error =
			node->errors[NAT64_OUT2IN_ERROR_NO_TRANSLATION];
		      goto trace0;
		    }

		  nat64_compose_ip6 (&ip6_saddr0, &ip40->src_address,
				     bibe0->fib_index);
		  ste0 =
		    nat64_db_st_entry_create (&nm->db, bibe0, &ip6_saddr0,
					      &saddr0.ip4, udp0->src_port);

		  if (!ste0)
		    {
		      next0 = NAT64_OUT2IN_NEXT_DROP;
		      b0->error =
			node->errors[NAT64_OUT2IN_ERROR_NO_TRANSLATION];
		      goto trace0;
		    }
		}
	      reass0->sess_index =
		nat64_db_st_entry_get_index (&nm->db, ste0);

	      nat_ip4_reass_get_frags (reass0, &fragments_to_loopback);
	    }
	  else
	    {
	      ctx0.first_frag = 0;

	      if (PREDICT_FALSE (reass0->sess_index == (u32) ~ 0))
		{
		  if (nat_ip4_reass_add_fragment (reass0, bi0))
		    {
		      b0->error = node->errors[NAT64_OUT2IN_ERROR_MAX_FRAG];
		      next0 = NAT64_OUT2IN_NEXT_DROP;
		      goto trace0;
		    }
		  cached0 = 1;
		  goto trace0;
		}
	    }

	  ctx0.sess_index = reass0->sess_index;
	  ctx0.proto = ip40->protocol;
	  ctx0.vm = vm;
	  ctx0.b = b0;

	  if (ip4_to_ip6_fragmented (b0, nat64_out2in_frag_set_cb, &ctx0))
	    {
	      next0 = NAT64_OUT2IN_NEXT_DROP;
	      b0->error = node->errors[NAT64_OUT2IN_ERROR_UNKNOWN];
	      goto trace0;
	    }

	trace0:
	  if (PREDICT_FALSE
	      ((node->flags & VLIB_NODE_FLAG_TRACE)
	       && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat64_out2in_reass_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->cached = cached0;
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	    }

	  if (cached0)
	    {
	      n_left_to_next++;
	      to_next--;
	    }
	  else
	    {
	      pkts_processed += next0 != NAT64_OUT2IN_NEXT_DROP;

	      /* verify speculative enqueue, maybe switch current next frame */
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next,
					       bi0, next0);
	    }

	  if (n_left_from == 0 && vec_len (fragments_to_loopback))
	    {
	      from = vlib_frame_vector_args (frame);
	      u32 len = vec_len (fragments_to_loopback);
	      if (len <= VLIB_FRAME_SIZE)
		{
		  clib_memcpy (from, fragments_to_loopback,
			       sizeof (u32) * len);
		  n_left_from = len;
		  vec_reset_length (fragments_to_loopback);
		}
	      else
		{
		  clib_memcpy (from,
			       fragments_to_loopback + (len -
							VLIB_FRAME_SIZE),
			       sizeof (u32) * VLIB_FRAME_SIZE);
		  n_left_from = VLIB_FRAME_SIZE;
		  _vec_len (fragments_to_loopback) = len - VLIB_FRAME_SIZE;
		}
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, nat64_out2in_reass_node.index,
			       NAT64_OUT2IN_ERROR_OUT2IN_PACKETS,
			       pkts_processed);

  nat_send_all_to_node (vm, fragments_to_drop, node,
			&node->errors[NAT64_OUT2IN_ERROR_DROP_FRAGMENT],
			NAT64_OUT2IN_NEXT_DROP);

  vec_free (fragments_to_drop);
  vec_free (fragments_to_loopback);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat64_out2in_reass_node) = {
  .function = nat64_out2in_reass_node_fn,
  .name = "nat64-out2in-reass",
  .vector_size = sizeof (u32),
  .format_trace = format_nat64_out2in_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat64_out2in_error_strings),
  .error_strings = nat64_out2in_error_strings,
  .n_next_nodes = NAT64_OUT2IN_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [NAT64_OUT2IN_NEXT_DROP] = "error-drop",
    [NAT64_OUT2IN_NEXT_LOOKUP] = "ip6-lookup",
    [NAT64_OUT2IN_NEXT_REASS] = "nat64-out2in-reass",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (nat64_out2in_reass_node,
			      nat64_out2in_reass_node_fn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
