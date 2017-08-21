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

vlib_node_registration_t nat64_out2in_node;

#define foreach_nat64_out2in_error                 \
_(UNSUPPORTED_PROTOCOL, "Unsupported protocol")    \
_(OUT2IN_PACKETS, "Good out2in packets processed") \
_(NO_TRANSLATION, "No translation")                \
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
  NAT64_OUT2IN_NEXT_LOOKUP,
  NAT64_OUT2IN_NEXT_DROP,
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
	  else if (proto0 == SNAT_PROTOCOL_TCP || proto0 == SNAT_PROTOCOL_UDP)
	    {
	      if (ip4_to_ip6_tcp_udp (b0, nat64_out2in_tcp_udp_set_cb, &ctx0))
		{
		  next0 = NAT64_OUT2IN_NEXT_DROP;
		  b0->error = node->errors[NAT64_OUT2IN_ERROR_NO_TRANSLATION];
		  goto trace0;
		}
	    }
	  else
	    {
	      if (ip4_to_ip6 (b0, nat64_out2in_unk_proto_set_cb, &ctx0))
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
  .error_strings = nat64_out2in_error_strings,.n_next_nodes = 2,
  /* edit / add dispositions here */
  .next_nodes = {
    [NAT64_OUT2IN_NEXT_DROP] = "error-drop",
    [NAT64_OUT2IN_NEXT_LOOKUP] = "ip6-lookup",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (nat64_out2in_node, nat64_out2in_node_fn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
