/*
 * gre.c: gre
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/gre/gre.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/tunnel/tunnel_dp.h>

extern gre_main_t gre_main;

#ifndef CLIB_MARCH_VARIANT
gre_main_t gre_main;

typedef struct
{
  union
  {
    ip4_and_gre_header_t ip4_and_gre;
    u64 as_u64[3];
  };
} ip4_and_gre_union_t;

typedef struct
{
  union
  {
    ip6_and_gre_header_t ip6_and_gre;
    u64 as_u64[3];
  };
} ip6_and_gre_union_t;
#endif /* CLIB_MARCH_VARIANT */


/* Packet trace structure */
typedef struct
{
  /* Tunnel-id / index in tunnel vector */
  u32 tunnel_id;

  /* pkt length */
  u32 length;

  /* tunnel ip addresses */
  ip46_address_t src;
  ip46_address_t dst;
} gre_tx_trace_t;

extern u8 *format_gre_tx_trace (u8 * s, va_list * args);

#ifndef CLIB_MARCH_VARIANT
u8 *
format_gre_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gre_tx_trace_t *t = va_arg (*args, gre_tx_trace_t *);

  s = format (s, "GRE: tunnel %d len %d src %U dst %U",
	      t->tunnel_id, t->length,
	      format_ip46_address, &t->src, IP46_TYPE_ANY,
	      format_ip46_address, &t->dst, IP46_TYPE_ANY);
  return s;
}

u8 *
format_gre_protocol (u8 * s, va_list * args)
{
  gre_protocol_t p = va_arg (*args, u32);
  gre_main_t *gm = &gre_main;
  gre_protocol_info_t *pi = gre_get_protocol_info (gm, p);

  if (pi)
    s = format (s, "%s", pi->name);
  else
    s = format (s, "0x%04x", p);

  return s;
}

u8 *
format_gre_header_with_length (u8 * s, va_list * args)
{
  gre_main_t *gm = &gre_main;
  gre_header_t *h = va_arg (*args, gre_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  gre_protocol_t p = clib_net_to_host_u16 (h->protocol);
  u32 indent, header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "gre header truncated");

  indent = format_get_indent (s);

  s = format (s, "GRE %U", format_gre_protocol, p);

  if (max_header_bytes != 0 && header_bytes < max_header_bytes)
    {
      gre_protocol_info_t *pi = gre_get_protocol_info (gm, p);
      vlib_node_t *node = vlib_get_node (gm->vlib_main, pi->node_index);
      if (node->format_buffer)
	s = format (s, "\n%U%U",
		    format_white_space, indent,
		    node->format_buffer, (void *) (h + 1),
		    max_header_bytes - header_bytes);
    }

  return s;
}

u8 *
format_gre_header (u8 * s, va_list * args)
{
  gre_header_t *h = va_arg (*args, gre_header_t *);
  return format (s, "%U", format_gre_header_with_length, h, 0);
}

/* Returns gre protocol as an int in host byte order. */
uword
unformat_gre_protocol_host_byte_order (unformat_input_t * input,
				       va_list * args)
{
  u16 *result = va_arg (*args, u16 *);
  gre_main_t *gm = &gre_main;
  int i;

  /* Named type. */
  if (unformat_user (input, unformat_vlib_number_by_name,
		     gm->protocol_info_by_name, &i))
    {
      gre_protocol_info_t *pi = vec_elt_at_index (gm->protocol_infos, i);
      *result = pi->protocol;
      return 1;
    }

  return 0;
}

uword
unformat_gre_protocol_net_byte_order (unformat_input_t * input,
				      va_list * args)
{
  u16 *result = va_arg (*args, u16 *);
  if (!unformat_user (input, unformat_gre_protocol_host_byte_order, result))
    return 0;
  *result = clib_host_to_net_u16 ((u16) * result);
  return 1;
}

uword
unformat_gre_header (unformat_input_t * input, va_list * args)
{
  u8 **result = va_arg (*args, u8 **);
  gre_header_t _h, *h = &_h;
  u16 p;

  if (!unformat (input, "%U", unformat_gre_protocol_host_byte_order, &p))
    return 0;

  h->protocol = clib_host_to_net_u16 (p);

  /* Add header to result. */
  {
    void *p;
    u32 n_bytes = sizeof (h[0]);

    vec_add2 (*result, p, n_bytes);
    clib_memcpy (p, h, n_bytes);
  }

  return 1;
}

static int
gre_proto_from_vnet_link (vnet_link_t link)
{
  switch (link)
    {
    case VNET_LINK_IP4:
      return (GRE_PROTOCOL_ip4);
    case VNET_LINK_IP6:
      return (GRE_PROTOCOL_ip6);
    case VNET_LINK_MPLS:
      return (GRE_PROTOCOL_mpls_unicast);
    case VNET_LINK_ETHERNET:
      return (GRE_PROTOCOL_teb);
    case VNET_LINK_ARP:
      return (GRE_PROTOCOL_arp);
    case VNET_LINK_NSH:
      ASSERT (0);
      break;
    }
  ASSERT (0);
  return (GRE_PROTOCOL_ip4);
}

static u8 *
gre_build_rewrite (vnet_main_t * vnm,
		   u32 sw_if_index,
		   vnet_link_t link_type, const void *dst_address)
{
  gre_main_t *gm = &gre_main;
  const ip46_address_t *dst;
  ip4_and_gre_header_t *h4;
  ip6_and_gre_header_t *h6;
  gre_header_t *gre;
  u8 *rewrite = NULL;
  gre_tunnel_t *t;
  u32 ti;
  u8 is_ipv6;

  dst = dst_address;
  ti = gm->tunnel_index_by_sw_if_index[sw_if_index];

  if (~0 == ti)
    /* not one of ours */
    return (0);

  t = pool_elt_at_index (gm->tunnels, ti);

  is_ipv6 = t->tunnel_dst.fp_proto == FIB_PROTOCOL_IP6 ? 1 : 0;

  if (!is_ipv6)
    {
      vec_validate (rewrite, sizeof (*h4) - 1);
      h4 = (ip4_and_gre_header_t *) rewrite;
      gre = &h4->gre;
      h4->ip4.ip_version_and_header_length = 0x45;
      h4->ip4.ttl = 254;
      h4->ip4.protocol = IP_PROTOCOL_GRE;
      /* fixup ip4 header length and checksum after-the-fact */
      h4->ip4.src_address.as_u32 = t->tunnel_src.ip4.as_u32;
      h4->ip4.dst_address.as_u32 = dst->ip4.as_u32;
      h4->ip4.checksum = ip4_header_checksum (&h4->ip4);
    }
  else
    {
      vec_validate (rewrite, sizeof (*h6) - 1);
      h6 = (ip6_and_gre_header_t *) rewrite;
      gre = &h6->gre;
      h6->ip6.ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (6 << 28);
      h6->ip6.hop_limit = 255;
      h6->ip6.protocol = IP_PROTOCOL_GRE;
      /* fixup ip6 header length and checksum after-the-fact */
      h6->ip6.src_address.as_u64[0] = t->tunnel_src.ip6.as_u64[0];
      h6->ip6.src_address.as_u64[1] = t->tunnel_src.ip6.as_u64[1];
      h6->ip6.dst_address.as_u64[0] = dst->ip6.as_u64[0];
      h6->ip6.dst_address.as_u64[1] = dst->ip6.as_u64[1];
    }

  if (PREDICT_FALSE (t->type == GRE_TUNNEL_TYPE_ERSPAN))
    {
      gre->protocol = clib_host_to_net_u16 (GRE_PROTOCOL_erspan);
      gre->flags_and_version = clib_host_to_net_u16 (GRE_FLAGS_SEQUENCE);
    }
  else
    gre->protocol =
      clib_host_to_net_u16 (gre_proto_from_vnet_link (link_type));

  return (rewrite);
}

static void
gre44_fixup (vlib_main_t * vm,
	     const ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  tunnel_encap_decap_flags_t flags;
  ip4_and_gre_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);
  flags = pointer_to_uword (data);

  /* Fixup the checksum and len fields in the GRE tunnel encap
   * that was applied at the midchain node */
  ip0->ip4.length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  tunnel_encap_fixup_4o4 (flags, (ip4_header_t *) (ip0 + 1), &ip0->ip4);
  ip0->ip4.checksum = ip4_header_checksum (&ip0->ip4);
}

static void
gre64_fixup (vlib_main_t * vm,
	     const ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  tunnel_encap_decap_flags_t flags;
  ip4_and_gre_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);
  flags = pointer_to_uword (data);

  /* Fixup the checksum and len fields in the GRE tunnel encap
   * that was applied at the midchain node */
  ip0->ip4.length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  tunnel_encap_fixup_6o4 (flags, (ip6_header_t *) (ip0 + 1), &ip0->ip4);
  ip0->ip4.checksum = ip4_header_checksum (&ip0->ip4);
}

static void
grex4_fixup (vlib_main_t * vm,
	     const ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  ip4_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);

  /* Fixup the checksum and len fields in the GRE tunnel encap
   * that was applied at the midchain node */
  ip0->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  ip0->checksum = ip4_header_checksum (ip0);
}

static void
gre46_fixup (vlib_main_t * vm,
	     const ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  tunnel_encap_decap_flags_t flags;
  ip6_and_gre_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);
  flags = pointer_to_uword (data);

  /* Fixup the payload length field in the GRE tunnel encap that was applied
   * at the midchain node */
  ip0->ip6.payload_length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			  sizeof (ip0->ip6));
  tunnel_encap_fixup_4o6 (flags, (ip4_header_t *) (ip0 + 1), &ip0->ip6);
}

static void
gre66_fixup (vlib_main_t * vm,
	     const ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  tunnel_encap_decap_flags_t flags;
  ip6_and_gre_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);
  flags = pointer_to_uword (data);

  /* Fixup the payload length field in the GRE tunnel encap that was applied
   * at the midchain node */
  ip0->ip6.payload_length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			  sizeof (ip0->ip6));
  tunnel_encap_fixup_6o6 (flags, (ip6_header_t *) (ip0 + 1), &ip0->ip6);
}

static void
grex6_fixup (vlib_main_t * vm,
	     const ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  ip6_and_gre_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);

  /* Fixup the payload length field in the GRE tunnel encap that was applied
   * at the midchain node */
  ip0->ip6.payload_length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			  sizeof (ip0->ip6));
}

/**
 * return the appropriate fixup function given the overlay (link-type) and
 * underlay (fproto) combination
 */
static adj_midchain_fixup_t
gre_get_fixup (fib_protocol_t fproto, vnet_link_t lt)
{
  if (fproto == FIB_PROTOCOL_IP6 && lt == VNET_LINK_IP6)
    return (gre66_fixup);
  if (fproto == FIB_PROTOCOL_IP6 && lt == VNET_LINK_IP4)
    return (gre46_fixup);
  if (fproto == FIB_PROTOCOL_IP4 && lt == VNET_LINK_IP6)
    return (gre64_fixup);
  if (fproto == FIB_PROTOCOL_IP4 && lt == VNET_LINK_IP4)
    return (gre44_fixup);
  if (fproto == FIB_PROTOCOL_IP6)
    return (grex6_fixup);
  if (fproto == FIB_PROTOCOL_IP4)
    return (grex4_fixup);

  ASSERT (0);
  return (gre44_fixup);
}

void
gre_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  gre_main_t *gm = &gre_main;
  gre_tunnel_t *t;
  adj_flags_t af;
  u32 ti;

  ti = gm->tunnel_index_by_sw_if_index[sw_if_index];
  t = pool_elt_at_index (gm->tunnels, ti);
  af = ADJ_FLAG_MIDCHAIN_IP_STACK;

  if (VNET_LINK_ETHERNET == adj_get_link_type (ai))
    af |= ADJ_FLAG_MIDCHAIN_NO_COUNT;

  adj_nbr_midchain_update_rewrite
    (ai, gre_get_fixup (t->tunnel_dst.fp_proto,
			adj_get_link_type (ai)),
     uword_to_pointer (t->flags, void *), af,
     gre_build_rewrite (vnm, sw_if_index, adj_get_link_type (ai),
			&t->tunnel_dst.fp_addr));

  gre_tunnel_stack (ai);
}

adj_walk_rc_t
mgre_mk_complete_walk (adj_index_t ai, void *data)
{
  mgre_walk_ctx_t *ctx = data;

  adj_nbr_midchain_update_rewrite
    (ai, gre_get_fixup (ctx->t->tunnel_dst.fp_proto,
			adj_get_link_type (ai)),
     uword_to_pointer (ctx->t->flags, void *),
     ADJ_FLAG_MIDCHAIN_IP_STACK,
     gre_build_rewrite (vnet_get_main (),
			ctx->t->sw_if_index,
			adj_get_link_type (ai),
			&teib_entry_get_nh (ctx->ne)->fp_addr));

  teib_entry_adj_stack (ctx->ne, ai);

  return (ADJ_WALK_RC_CONTINUE);
}

adj_walk_rc_t
mgre_mk_incomplete_walk (adj_index_t ai, void *data)
{
  gre_tunnel_t *t = data;

  adj_nbr_midchain_update_rewrite (ai, gre_get_fixup (t->tunnel_dst.fp_proto,
						      adj_get_link_type (ai)),
				   NULL, ADJ_FLAG_NONE, NULL);

  adj_midchain_delegate_unstack (ai);

  return (ADJ_WALK_RC_CONTINUE);
}

void
mgre_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  gre_main_t *gm = &gre_main;
  ip_adjacency_t *adj;
  teib_entry_t *ne;
  gre_tunnel_t *t;
  u32 ti;

  adj = adj_get (ai);
  ti = gm->tunnel_index_by_sw_if_index[sw_if_index];
  t = pool_elt_at_index (gm->tunnels, ti);

  ne = teib_entry_find_46 (sw_if_index,
			   adj->ia_nh_proto, &adj->sub_type.nbr.next_hop);

  if (NULL == ne)
    // no NHRP entry to provide the next-hop
    return;

  mgre_walk_ctx_t ctx = {
    .t = t,
    .ne = ne
  };
  adj_nbr_walk_nh (sw_if_index,
		   adj->ia_nh_proto,
		   &adj->sub_type.nbr.next_hop, mgre_mk_complete_walk, &ctx);
}
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  GRE_ENCAP_NEXT_L2_MIDCHAIN,
  GRE_ENCAP_N_NEXT,
} gre_encap_next_t;

/**
 * @brief TX function. Only called for L2 payload including TEB or ERSPAN.
 *        L3 traffic uses the adj-midchains.
 */
static_always_inline u32
gre_encap_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame, gre_tunnel_type_t type)
{
  gre_main_t *gm = &gre_main;
  u32 *from, n_left_from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 sw_if_index[2] = { ~0, ~0 };
  const gre_tunnel_t *gt[2] = { 0 };
  adj_index_t adj_index[2] = { ADJ_INDEX_INVALID, ADJ_INDEX_INVALID };

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  while (n_left_from >= 2)
    {

      if (PREDICT_FALSE
	  (sw_if_index[0] != vnet_buffer (b[0])->sw_if_index[VLIB_TX]))
	{
	  const vnet_hw_interface_t *hi;
	  sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	  hi = vnet_get_sup_hw_interface (gm->vnet_main, sw_if_index[0]);
	  gt[0] = &gm->tunnels[hi->dev_instance];
	  adj_index[0] = gt[0]->l2_adj_index;
	}
      if (PREDICT_FALSE
	  (sw_if_index[1] != vnet_buffer (b[1])->sw_if_index[VLIB_TX]))
	{
	  const vnet_hw_interface_t *hi;
	  sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_TX];
	  hi = vnet_get_sup_hw_interface (gm->vnet_main, sw_if_index[1]);
	  gt[1] = &gm->tunnels[hi->dev_instance];
	  adj_index[1] = gt[1]->l2_adj_index;
	}

      vnet_buffer (b[0])->ip.adj_index = adj_index[0];
      vnet_buffer (b[1])->ip.adj_index = adj_index[1];

      if (type == GRE_TUNNEL_TYPE_ERSPAN)
	{
	  /* Encap GRE seq# and ERSPAN type II header */
	  erspan_t2_t *h0;
	  u32 seq_num;
	  u64 hdr;
	  vlib_buffer_advance (b[0], -sizeof (erspan_t2_t));
	  h0 = vlib_buffer_get_current (b[0]);
	  seq_num = clib_atomic_fetch_add (&gt[0]->gre_sn->seq_num, 1);
	  hdr = clib_host_to_net_u64 (ERSPAN_HDR2);
	  h0->seq_num = clib_host_to_net_u32 (seq_num);
	  h0->t2_u64 = hdr;
	  h0->t2.cos_en_t_session |= clib_host_to_net_u16 (gt[0]->session_id);
	}
      if (type == GRE_TUNNEL_TYPE_ERSPAN)
	{
	  /* Encap GRE seq# and ERSPAN type II header */
	  erspan_t2_t *h0;
	  u32 seq_num;
	  u64 hdr;
	  vlib_buffer_advance (b[1], -sizeof (erspan_t2_t));
	  h0 = vlib_buffer_get_current (b[1]);
	  seq_num = clib_atomic_fetch_add (&gt[1]->gre_sn->seq_num, 1);
	  hdr = clib_host_to_net_u64 (ERSPAN_HDR2);
	  h0->seq_num = clib_host_to_net_u32 (seq_num);
	  h0->t2_u64 = hdr;
	  h0->t2.cos_en_t_session |= clib_host_to_net_u16 (gt[1]->session_id);
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  gre_tx_trace_t *tr = vlib_add_trace (vm, node,
					       b[0], sizeof (*tr));
	  tr->tunnel_id = gt[0] - gm->tunnels;
	  tr->src = gt[0]->tunnel_src;
	  tr->dst = gt[0]->tunnel_dst.fp_addr;
	  tr->length = vlib_buffer_length_in_chain (vm, b[0]);
	}
      if (PREDICT_FALSE (b[1]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  gre_tx_trace_t *tr = vlib_add_trace (vm, node,
					       b[1], sizeof (*tr));
	  tr->tunnel_id = gt[1] - gm->tunnels;
	  tr->src = gt[1]->tunnel_src;
	  tr->dst = gt[1]->tunnel_dst.fp_addr;
	  tr->length = vlib_buffer_length_in_chain (vm, b[1]);
	}

      b += 2;
      n_left_from -= 2;
    }

  while (n_left_from >= 1)
    {

      if (PREDICT_FALSE
	  (sw_if_index[0] != vnet_buffer (b[0])->sw_if_index[VLIB_TX]))
	{
	  const vnet_hw_interface_t *hi;
	  sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	  hi = vnet_get_sup_hw_interface (gm->vnet_main, sw_if_index[0]);
	  gt[0] = &gm->tunnels[hi->dev_instance];
	  adj_index[0] = gt[0]->l2_adj_index;
	}

      vnet_buffer (b[0])->ip.adj_index = adj_index[0];

      if (type == GRE_TUNNEL_TYPE_ERSPAN)
	{
	  /* Encap GRE seq# and ERSPAN type II header */
	  erspan_t2_t *h0;
	  u32 seq_num;
	  u64 hdr;
	  ASSERT (gt[0]->type == GRE_TUNNEL_TYPE_ERSPAN);
	  vlib_buffer_advance (b[0], -sizeof (erspan_t2_t));
	  h0 = vlib_buffer_get_current (b[0]);
	  seq_num = clib_atomic_fetch_add (&gt[0]->gre_sn->seq_num, 1);
	  hdr = clib_host_to_net_u64 (ERSPAN_HDR2);
	  h0->seq_num = clib_host_to_net_u32 (seq_num);
	  h0->t2_u64 = hdr;
	  h0->t2.cos_en_t_session |= clib_host_to_net_u16 (gt[0]->session_id);
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  gre_tx_trace_t *tr = vlib_add_trace (vm, node,
					       b[0], sizeof (*tr));
	  tr->tunnel_id = gt[0] - gm->tunnels;
	  tr->src = gt[0]->tunnel_src;
	  tr->dst = gt[0]->tunnel_dst.fp_addr;
	  tr->length = vlib_buffer_length_in_chain (vm, b[0]);
	}

      b += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_single_next (vm, node, from,
				      GRE_ENCAP_NEXT_L2_MIDCHAIN,
				      frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index,
			       GRE_ERROR_PKTS_ENCAP, frame->n_vectors);

  return frame->n_vectors;
}

static char *gre_error_strings[] = {
#define gre_error(n,s) s,
#include "error.def"
#undef gre_error
};

VLIB_NODE_FN (gre_teb_encap_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return (gre_encap_inline (vm, node, frame, GRE_TUNNEL_TYPE_TEB));
}

VLIB_NODE_FN (gre_erspan_encap_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return (gre_encap_inline (vm, node, frame, GRE_TUNNEL_TYPE_ERSPAN));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gre_teb_encap_node) =
{
  .name = "gre-teb-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_gre_tx_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = GRE_N_ERROR,
  .error_strings = gre_error_strings,
  .n_next_nodes = GRE_ENCAP_N_NEXT,
  .next_nodes = {
    [GRE_ENCAP_NEXT_L2_MIDCHAIN] = "adj-l2-midchain",
  },
};
VLIB_REGISTER_NODE (gre_erspan_encap_node) =
{
  .name = "gre-erspan-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_gre_tx_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = GRE_N_ERROR,
  .error_strings = gre_error_strings,
  .n_next_nodes = GRE_ENCAP_N_NEXT,
  .next_nodes = {
    [GRE_ENCAP_NEXT_L2_MIDCHAIN] = "adj-l2-midchain",
  },
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
static u8 *
format_gre_tunnel_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  gre_main_t *gm = &gre_main;
  gre_tunnel_t *t;

  if (dev_instance >= vec_len (gm->tunnels))
    return format (s, "<improperly-referenced>");

  t = pool_elt_at_index (gm->tunnels, dev_instance);
  return format (s, "gre%d", t->user_instance);
}

static u8 *
format_gre_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);

  s = format (s, "GRE tunnel: id %d\n", dev_instance);
  return s;
}

static int
gre_tunnel_desc (u32 sw_if_index,
		 ip46_address_t * src, ip46_address_t * dst, u8 * is_l2)
{
  gre_main_t *gm = &gre_main;
  gre_tunnel_t *t;
  u32 ti;

  ti = gm->tunnel_index_by_sw_if_index[sw_if_index];

  if (~0 == ti)
    /* not one of ours */
    return -1;

  t = pool_elt_at_index (gm->tunnels, ti);

  *src = t->tunnel_src;
  *dst = t->tunnel_dst.fp_addr;
  *is_l2 = t->type == GRE_TUNNEL_TYPE_TEB;

  return (0);
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (gre_device_class) = {
  .name = "GRE tunnel device",
  .format_device_name = format_gre_tunnel_name,
  .format_device = format_gre_device,
  .format_tx_trace = format_gre_tx_trace,
  .admin_up_down_function = gre_interface_admin_up_down,
  .ip_tun_desc = gre_tunnel_desc,
#ifdef SOON
  .clear counter = 0;
#endif
};

VNET_HW_INTERFACE_CLASS (gre_hw_interface_class) = {
  .name = "GRE",
  .format_header = format_gre_header_with_length,
  .unformat_header = unformat_gre_header,
  .build_rewrite = gre_build_rewrite,
  .update_adjacency = gre_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

VNET_HW_INTERFACE_CLASS (mgre_hw_interface_class) = {
  .name = "mGRE",
  .format_header = format_gre_header_with_length,
  .unformat_header = unformat_gre_header,
  .build_rewrite = gre_build_rewrite,
  .update_adjacency = mgre_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_NBMA,
};
/* *INDENT-ON* */
#endif /* CLIB_MARCH_VARIANT */

static void
add_protocol (gre_main_t * gm, gre_protocol_t protocol, char *protocol_name)
{
  gre_protocol_info_t *pi;
  u32 i;

  vec_add2 (gm->protocol_infos, pi, 1);
  i = pi - gm->protocol_infos;

  pi->name = protocol_name;
  pi->protocol = protocol;
  pi->next_index = pi->node_index = ~0;

  hash_set (gm->protocol_info_by_protocol, protocol, i);
  hash_set_mem (gm->protocol_info_by_name, pi->name, i);
}

static clib_error_t *
gre_init (vlib_main_t * vm)
{
  gre_main_t *gm = &gre_main;
  clib_error_t *error;
  ip_main_t *im = &ip_main;
  ip_protocol_info_t *pi;

  clib_memset (gm, 0, sizeof (gm[0]));
  gm->vlib_main = vm;
  gm->vnet_main = vnet_get_main ();

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip6_lookup_init)))
    return error;

  /* Set up the ip packet generator */
  pi = ip_get_protocol_info (im, IP_PROTOCOL_GRE);
  pi->format_header = format_gre_header;
  pi->unformat_pg_edit = unformat_pg_gre_header;

  gm->protocol_info_by_name = hash_create_string (0, sizeof (uword));
  gm->protocol_info_by_protocol = hash_create (0, sizeof (uword));
  gm->tunnel_by_key4 =
    hash_create_mem (0, sizeof (gre_tunnel_key4_t), sizeof (uword));
  gm->tunnel_by_key6 =
    hash_create_mem (0, sizeof (gre_tunnel_key6_t), sizeof (uword));
  gm->seq_num_by_key =
    hash_create_mem (0, sizeof (gre_sn_key_t), sizeof (uword));

#define _(n,s) add_protocol (gm, GRE_PROTOCOL_##s, #s);
  foreach_gre_protocol
#undef _
    return vlib_call_init_function (vm, gre_input_init);
}

VLIB_INIT_FUNCTION (gre_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
