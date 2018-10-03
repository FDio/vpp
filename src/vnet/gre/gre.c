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
  ip4_and_gre_header_t *h4;
  ip6_and_gre_header_t *h6;
  gre_header_t *gre;
  u8 *rewrite = NULL;
  gre_tunnel_t *t;
  u32 ti;
  u8 is_ipv6;

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
      h4->ip4.dst_address.as_u32 = t->tunnel_dst.fp_addr.ip4.as_u32;
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
      h6->ip6.dst_address.as_u64[0] = t->tunnel_dst.fp_addr.ip6.as_u64[0];
      h6->ip6.dst_address.as_u64[1] = t->tunnel_dst.fp_addr.ip6.as_u64[1];
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

#define is_v4_packet(_h) ((*(u8*) _h) & 0xF0) == 0x40

static void
gre4_fixup (vlib_main_t * vm,
	    ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  ip4_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);

  /* Fixup the checksum and len fields in the GRE tunnel encap
   * that was applied at the midchain node */
  ip0->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  ip0->checksum = ip4_header_checksum (ip0);
}

static void
gre6_fixup (vlib_main_t * vm,
	    ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  ip6_header_t *ip0;

  ip0 = vlib_buffer_get_current (b0);

  /* Fixup the payload length field in the GRE tunnel encap that was applied
   * at the midchain node */
  ip0->payload_length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			  sizeof (*ip0));
}

void
gre_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  gre_main_t *gm = &gre_main;
  gre_tunnel_t *t;
  u32 ti;
  u8 is_ipv6;

  ti = gm->tunnel_index_by_sw_if_index[sw_if_index];
  t = pool_elt_at_index (gm->tunnels, ti);
  is_ipv6 = t->tunnel_dst.fp_proto == FIB_PROTOCOL_IP6 ? 1 : 0;

  adj_nbr_midchain_update_rewrite
    (ai, !is_ipv6 ? gre4_fixup : gre6_fixup, NULL,
     (VNET_LINK_ETHERNET == adj_get_link_type (ai) ?
      ADJ_FLAG_MIDCHAIN_NO_COUNT : ADJ_FLAG_NONE),
     gre_build_rewrite (vnm, sw_if_index, adj_get_link_type (ai), NULL));

  gre_tunnel_stack (ai);
}


typedef enum
{
  GRE_ENCAP_NEXT_L2_MIDCHAIN,
  GRE_ENCAP_N_NEXT,
} gre_encap_next_t;

/**
 * @brief TX function. Only called for L2 payload including TEB or ERSPAN.
 *        L3 traffic uses the adj-midchains.
 */
static uword
gre_interface_tx (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  gre_main_t *gm = &gre_main;
  vnet_main_t *vnm = gm->vnet_main;
  u32 next_index;
  u32 *from, *to_next, n_left_from, n_left_to_next;
  u32 sw_if_index0 = 0;
  u32 sw_if_index1 = 0;
  adj_index_t adj_index0 = ADJ_INDEX_INVALID;
  adj_index_t adj_index1 = ADJ_INDEX_INVALID;
  gre_tunnel_t *gt0 = NULL;
  gre_tunnel_t *gt1 = NULL;

  /* Vector of buffer / pkt indices we're supposed to process */
  from = vlib_frame_vector_args (frame);

  /* Number of buffers / pkts */
  n_left_from = frame->n_vectors;

  /* Speculatively send the first buffer to the last disposition we used */
  next_index = GRE_ENCAP_NEXT_L2_MIDCHAIN;

  while (n_left_from > 0)
    {
      /* set up to enqueue to our disposition with index = next_index */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0 = from[0];
	  u32 bi1 = from[1];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  vlib_buffer_t *b1 = vlib_get_buffer (vm, bi1);

	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  if (sw_if_index0 != vnet_buffer (b0)->sw_if_index[VLIB_TX])
	    {
	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      vnet_hw_interface_t *hi0 =
		vnet_get_sup_hw_interface (vnm, sw_if_index0);
	      gt0 = &gm->tunnels[hi0->dev_instance];
	      adj_index0 = gt0->l2_adj_index;
	    }

	  if (sw_if_index1 != vnet_buffer (b1)->sw_if_index[VLIB_TX])
	    {
	      if (sw_if_index0 == vnet_buffer (b1)->sw_if_index[VLIB_TX])
		{
		  sw_if_index1 = sw_if_index0;
		  gt1 = gt0;
		  adj_index1 = adj_index0;
		}
	      else
		{
		  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];
		  vnet_hw_interface_t *hi1 =
		    vnet_get_sup_hw_interface (vnm, sw_if_index1);
		  gt1 = &gm->tunnels[hi1->dev_instance];
		  adj_index1 = gt1->l2_adj_index;
		}
	    }

	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = adj_index0;
	  vnet_buffer (b1)->ip.adj_index[VLIB_TX] = adj_index1;

	  if (PREDICT_FALSE (gt0->type == GRE_TUNNEL_TYPE_ERSPAN))
	    {
	      /* Encap GRE seq# and ERSPAN type II header */
	      vlib_buffer_advance (b0, -sizeof (erspan_t2_t));
	      erspan_t2_t *h0 = vlib_buffer_get_current (b0);
	      u32 seq_num = clib_atomic_fetch_add (&gt0->gre_sn->seq_num, 1);
	      u64 hdr = clib_host_to_net_u64 (ERSPAN_HDR2);
	      h0->seq_num = clib_host_to_net_u32 (seq_num);
	      h0->t2_u64 = hdr;
	      h0->t2.cos_en_t_session |=
		clib_host_to_net_u16 (gt0->session_id);
	    }
	  if (PREDICT_FALSE (gt1->type == GRE_TUNNEL_TYPE_ERSPAN))
	    {
	      /* Encap GRE seq# and ERSPAN type II header */
	      vlib_buffer_advance (b1, -sizeof (erspan_t2_t));
	      erspan_t2_t *h1 = vlib_buffer_get_current (b1);
	      u32 seq_num = clib_atomic_fetch_add (&gt1->gre_sn->seq_num, 1);
	      u64 hdr = clib_host_to_net_u64 (ERSPAN_HDR2);
	      h1->seq_num = clib_host_to_net_u32 (seq_num);
	      h1->t2_u64 = hdr;
	      h1->t2.cos_en_t_session |=
		clib_host_to_net_u16 (gt1->session_id);
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gre_tx_trace_t *tr0 = vlib_add_trace (vm, node,
						    b0, sizeof (*tr0));
	      tr0->tunnel_id = gt0 - gm->tunnels;
	      tr0->src = gt0->tunnel_src;
	      tr0->dst = gt0->tunnel_dst.fp_addr;
	      tr0->length = vlib_buffer_length_in_chain (vm, b0);
	    }
	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gre_tx_trace_t *tr1 = vlib_add_trace (vm, node,
						    b1, sizeof (*tr1));
	      tr1->tunnel_id = gt1 - gm->tunnels;
	      tr1->src = gt1->tunnel_src;
	      tr1->dst = gt1->tunnel_dst.fp_addr;
	      tr1->length = vlib_buffer_length_in_chain (vm, b1);
	    }
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = from[0];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  if (sw_if_index0 != vnet_buffer (b0)->sw_if_index[VLIB_TX])
	    {
	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      vnet_hw_interface_t *hi0 =
		vnet_get_sup_hw_interface (vnm, sw_if_index0);
	      gt0 = &gm->tunnels[hi0->dev_instance];
	      adj_index0 = gt0->l2_adj_index;
	    }

	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = adj_index0;

	  if (PREDICT_FALSE (gt0->type == GRE_TUNNEL_TYPE_ERSPAN))
	    {
	      /* Encap GRE seq# and ERSPAN type II header */
	      vlib_buffer_advance (b0, -sizeof (erspan_t2_t));
	      erspan_t2_t *h0 = vlib_buffer_get_current (b0);
	      u32 seq_num = clib_atomic_fetch_add (&gt0->gre_sn->seq_num, 1);
	      u64 hdr = clib_host_to_net_u64 (ERSPAN_HDR2);
	      h0->seq_num = clib_host_to_net_u32 (seq_num);
	      h0->t2_u64 = hdr;
	      h0->t2.cos_en_t_session |=
		clib_host_to_net_u16 (gt0->session_id);
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gre_tx_trace_t *tr = vlib_add_trace (vm, node,
						   b0, sizeof (*tr));
	      tr->tunnel_id = gt0 - gm->tunnels;
	      tr->src = gt0->tunnel_src;
	      tr->dst = gt0->tunnel_dst.fp_addr;
	      tr->length = vlib_buffer_length_in_chain (vm, b0);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       GRE_ERROR_PKTS_ENCAP, frame->n_vectors);

  return frame->n_vectors;
}

static char *gre_error_strings[] = {
#define gre_error(n,s) s,
#include "error.def"
#undef gre_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gre_encap_node) =
{
  .function = gre_interface_tx,
  .name = "gre-encap",
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

VLIB_NODE_FUNCTION_MULTIARCH (gre_encap_node, gre_interface_tx)
/* *INDENT-ON* */

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

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (gre_device_class) = {
  .name = "GRE tunnel device",
  .format_device_name = format_gre_tunnel_name,
  .format_device = format_gre_device,
  .format_tx_trace = format_gre_tx_trace,
  .admin_up_down_function = gre_interface_admin_up_down,
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
/* *INDENT-ON* */

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

  memset (gm, 0, sizeof (gm[0]));
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
