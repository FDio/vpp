/*
 * lcp_enthernet_node.c : linux control plane ethernet node
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <sys/socket.h>
#include <linux/if.h>

#include <plugins/linux-cp/lcp_interface.h>
#include <plugins/linux-cp/lcp_adj.h>

#include <vnet/feature/feature.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip_types.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/l2/l2_input.h>

#define foreach_lip_punt                          \
  _(IO, "punt to host")				  \
  _(DROP, "unknown input interface")

typedef enum
{
#define _(sym,str) LIP_PUNT_NEXT_##sym,
  foreach_lip_punt
#undef _
    LIP_PUNT_N_NEXT,
} lip_punt_next_t;

typedef struct lip_punt_trace_t_
{
  u32 phy_sw_if_index;
  u32 host_sw_if_index;
} lip_punt_trace_t;

/* packet trace format function */
static u8 *
format_lip_punt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lip_punt_trace_t *t = va_arg (*args, lip_punt_trace_t *);

  s = format (s, "lip-punt: %u -> %u", t->phy_sw_if_index,
	      t->host_sw_if_index);

  return s;
}

/**
 * Pass punted packets from the PHY to the HOST.
 */
VLIB_NODE_FN (lip_punt_node) (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lip_punt_next_t next_index;

  next_index = node->cached_next_index;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  const lcp_itf_pair_t *lip0 = NULL;
	  u32 next0 = ~0;
	  u32 bi0, lipi0;
	  u32 sw_if_index0;
	  u8 len0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = LIP_PUNT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  lipi0 = lcp_itf_pair_find_by_phy (sw_if_index0);
	  if (PREDICT_FALSE (lipi0 == INDEX_INVALID))
	    goto trace0;

	  lip0 = lcp_itf_pair_get (lipi0);
	  next0 = LIP_PUNT_NEXT_IO;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = lip0->lip_host_sw_if_index;

	  if (PREDICT_TRUE (lip0->lip_host_type == LCP_ITF_HOST_TAP))
	    {
	      /*
	       * rewind to ethernet header
	       */
	      len0 = ((u8 *) vlib_buffer_get_current (b0) -
		      (u8 *) ethernet_buffer_get_header (b0));
	      vlib_buffer_advance (b0, -len0);
	    }
	  /* Tun packets don't need any special treatment, just need to
	   * be escorted past the TTL decrement. If we still want to use
	   * ip[46]-punt-redirect with these, we could just set the
	   * VNET_BUFFER_F_LOCALLY_ORIGINATED in an 'else {}' here and
	   * then pass to the next node on the ip[46]-punt feature arc
	   */

	trace0:
	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lip_punt_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->phy_sw_if_index = sw_if_index0;
	      t->host_sw_if_index = (lipi0 == INDEX_INVALID) ? ~0 :
		lip0->lip_host_sw_if_index;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lip_punt_node) = {
  .name = "linux-cp-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_lip_punt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LIP_PUNT_N_NEXT,
  .next_nodes = {
    [LIP_PUNT_NEXT_DROP] = "error-drop",
    [LIP_PUNT_NEXT_IO] = "interface-output",
  },
};
/* *INDENT-ON* */

#define foreach_lcp_punt_l3			  \
  _(DROP, "unknown error")

typedef enum
{
#define _(sym,str) LCP_LOCAL_NEXT_##sym,
  foreach_lcp_punt_l3
#undef _
    LCP_LOCAL_N_NEXT,
} lcp_punt_l3_next_t;

typedef struct lcp_punt_l3_trace_t_
{
  u32 phy_sw_if_index;
} lcp_punt_l3_trace_t;

/* packet trace format function */
static u8 *
format_lcp_punt_l3_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_punt_l3_trace_t *t = va_arg (*args, lcp_punt_l3_trace_t *);

  s = format (s, "linux-cp-punt-l3: %u", t->phy_sw_if_index);

  return s;
}

VLIB_NODE_FN (lcp_punt_l3_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lip_punt_next_t next_index;

  next_index = node->cached_next_index;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 next0 = LCP_LOCAL_NEXT_DROP;
	  u32 bi0;
	  index_t lipi0;
	  lcp_itf_pair_t *lip0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  vnet_feature_next (&next0, b0);

	  lipi0 =
	    lcp_itf_pair_find_by_phy (vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	  if (lipi0 != INDEX_INVALID)
	    {
	      /*
	       * Avoid TTL check for packets which arrived on a tunnel and
	       * are being punted to the local host.
	       */
	      lip0 = lcp_itf_pair_get (lipi0);
	      if (lip0->lip_host_type == LCP_ITF_HOST_TUN)
		b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lcp_punt_l3_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->phy_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lcp_punt_l3_node) = {
  .name = "linux-cp-punt-l3",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_punt_l3_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = 1,
  .next_nodes = {
    [LCP_LOCAL_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT(lcp_punt_l3_ip4, static) =
{
  .arc_name = "ip4-punt",
  .node_name = "linux-cp-punt-l3",
  .runs_before = VNET_FEATURES ("ip4-punt-redirect"),
};

VNET_FEATURE_INIT(lip_punt_l3_ip6, static) =
{
  .arc_name = "ip6-punt",
  .node_name = "linux-cp-punt-l3",
  .runs_before = VNET_FEATURES ("ip6-punt-redirect"),
};
/* *INDENT-ON* */


#define foreach_lcp_xc                          \
  _(DROP, "drop")                               \
  _(XC_IP4, "x-connnect-ip4")                   \
  _(XC_IP6, "x-connnect-ip6")

typedef enum
{
#define _(sym,str) LCP_XC_NEXT_##sym,
  foreach_lcp_xc
#undef _
    LCP_XC_N_NEXT,
} lcp_xc_next_t;

typedef struct lcp_xc_trace_t_
{
  u32 phy_sw_if_index;
  adj_index_t adj_index;
} lcp_xc_trace_t;

/* packet trace format function */
static u8 *
format_lcp_xc_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_xc_trace_t *t = va_arg (*args, lcp_xc_trace_t *);

  s = format (s, "lcp-xc: itf:%d adj:%d", t->phy_sw_if_index, t->adj_index);

  return s;
}

/**
 * X-connect all packets from the HOST to the PHY.
 *
 * This runs in either the IP4 or IP6 path. The MAC rewrite on the received
 * packet from the host is used as a key to find the adjacency used on the phy.
 * This allows this code to start the feature arc on that adjacency. Consequently,
 * all packet sent from the host are also subject to output features, which is
 * symmetric w.r.t. to input features.
 */
static_always_inline u32
lcp_xc_inline (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * frame,
               ip_address_family_t af)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lcp_xc_next_t next_index;
  ip_lookup_main_t *lm;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  if (AF_IP4 == af)
    lm = &ip4_main.lookup_main;
  else
    lm = &ip6_main.lookup_main;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          const ethernet_header_t *eth;
	  const lcp_itf_pair_t *lip;
          u32 next0, bi0, lipi, ai;
	  vlib_buffer_t *b0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  lipi = lcp_itf_pair_find_by_host (vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	  lip = lcp_itf_pair_get (lipi);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = lip->lip_phy_sw_if_index;
          vlib_buffer_advance (b0, -lip->lip_rewrite_len);
          eth = vlib_buffer_get_current (b0);

          if (ethernet_address_cast(eth->dst_address))
            ai = lip->lip_phy_adjs.adj_index[af];
          else
            ai = lcp_adj_lkup ((u8*) eth,
                               lip->lip_rewrite_len,
                               vnet_buffer(b0)->sw_if_index[VLIB_TX]);

          if (ADJ_INDEX_INVALID != ai)
            {
              const ip_adjacency_t *adj;

              adj = adj_get(ai);
              vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ai;
	      next0 = adj->rewrite_header.next_index;
              vnet_buffer(b0)->ip.save_rewrite_length =
                lip->lip_rewrite_len;

	      if (PREDICT_FALSE
		  (adj->rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
                vnet_feature_arc_start_w_cfg_index (lm->output_feature_arc_index,
                                                    vnet_buffer(b0)->sw_if_index[VLIB_TX],
                                                    &next0, b0,
                                                    adj->ia_cfg_index);
            }
          else
            next0 = LCP_XC_NEXT_DROP;

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lcp_xc_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->phy_sw_if_index = lip->lip_phy_sw_if_index;
              t->adj_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (lcp_xc_ip4) (vlib_main_t * vm,
                           vlib_node_runtime_t * node,
                           vlib_frame_t * frame)
{
  return (lcp_xc_inline (vm, node, frame, AF_IP4));
}

VLIB_NODE_FN (lcp_xc_ip6) (vlib_main_t * vm,
                           vlib_node_runtime_t * node,
                           vlib_frame_t * frame)
{
  return (lcp_xc_inline (vm, node, frame, AF_IP6));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lcp_xc_ip4) = {
  .name = "linux-cp-xc-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_xc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "ip4-rewrite"
};

VNET_FEATURE_INIT(lcp_xc_ip4_ucast_node, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "linux-cp-xc-ip4",
};
VNET_FEATURE_INIT(lcp_xc_ip4_mcast_node, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "linux-cp-xc-ip4",
};

VLIB_REGISTER_NODE (lcp_xc_ip6) = {
  .name = "linux-cp-xc-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_xc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "ip6-rewrite"
};

VNET_FEATURE_INIT(lcp_xc_ip6_ucast_node, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "linux-cp-xc-ip6",
};
VNET_FEATURE_INIT(lcp_xc_ip6_mcast_node, static) =
{
  .arc_name = "ip6-multicast",
  .node_name = "linux-cp-xc-ip6",
};

/* *INDENT-ON* */


typedef enum
{
  LCP_XC_L3_NEXT_XC,
  LCP_XC_L3_N_NEXT,
} lcp_xc_l3_next_t;

/**
 * X-connect all packets from the HOST to the PHY on L3 interfaces
 *
 * There's only one adjacency that can be used on thises links.
 */
static_always_inline u32
lcp_xc_l3_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame, ip_address_family_t af)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lcp_xc_next_t next_index;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  const lcp_itf_pair_t *lip;
	  u32 next0 = ~0;
	  u32 bi0, lipi;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Flag buffers as locally originated. Otherwise their TTL will
	   * be checked & decremented. That would break services like BGP
	   * which set a TTL of 1 by default.
	   */
	  b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

	  lipi = lcp_itf_pair_find_by_host (vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	  lip = lcp_itf_pair_get (lipi);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = lip->lip_phy_sw_if_index;
          next0 = LCP_XC_L3_NEXT_XC;
          vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
            lip->lip_phy_adjs.adj_index[af];

	  /* point current data to the IP header */
	  vlib_buffer_advance (b0, sizeof (ethernet_header_t));

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lcp_xc_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->phy_sw_if_index = lip->lip_phy_sw_if_index;
              t->adj_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/**
 * X-connect all packets from the HOST to the PHY.
 */
VLIB_NODE_FN (lcp_xc_l3_ip4_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return (lcp_xc_l3_inline (vm, node, frame, AF_IP4));
}
VLIB_NODE_FN (lcp_xc_l3_ip6_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return (lcp_xc_l3_inline (vm, node, frame, AF_IP6));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lcp_xc_l3_ip4_node) = {
  .name = "linux-cp-xc-l3-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_xc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LCP_XC_L3_N_NEXT,
  .next_nodes = {
    [LCP_XC_L3_NEXT_XC] = "ip4-midchain",
  },
};

VNET_FEATURE_INIT(lcp_xc_node_l3_ip4_unicast, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "linux-cp-xc-l3-ip4",
};

VNET_FEATURE_INIT(lcp_xc_node_l3_ip4_multicaast, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "linux-cp-xc-l3-ip4",
};

VLIB_REGISTER_NODE (lcp_xc_l3_ip6_node) = {
  .name = "linux-cp-xc-l3-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_xc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LCP_XC_L3_N_NEXT,
  .next_nodes = {
    [LCP_XC_L3_NEXT_XC] = "ip6-midchain",
  },
};

VNET_FEATURE_INIT(lcp_xc_node_l3_ip6_unicast, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "linux-cp-xc-l3-ip6",
};

VNET_FEATURE_INIT(lcp_xc_node_l3_ip6_multicast, static) =
{
  .arc_name = "ip6-multicast",
  .node_name = "linux-cp-xc-l3-ip6",
};
/* *INDENT-ON* */


#define foreach_lcp_arp                               \
  _(DROP, "error-drop")				      \
  _(IO, "interface-output")

typedef enum
{
#define _(sym,str) LCP_ARP_NEXT_##sym,
  foreach_lcp_arp
#undef _
    LCP_ARP_N_NEXT,
} lcp_arp_next_t;

typedef struct lcp_arp_trace_t_
{
  u32 rx_sw_if_index;
  u16 arp_opcode;
} lcp_arp_trace_t;

/* packet trace format function */
static u8 *
format_lcp_arp_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_arp_trace_t *t = va_arg (*args, lcp_arp_trace_t *);

  s = format (s, "rx-sw-if-index: %u opcode: %u", t->rx_sw_if_index,
	      t->arp_opcode);

  return s;
}

#define foreach_lcp_arp_error                               \
_(PACKETS, "ARP packets processed")			    \
_(COPIES, "ARP replies copied to host")

typedef enum
{
#define _(sym,str) LCP_ARP_ERROR_##sym,
  foreach_lcp_arp_error
#undef _
    LCP_ARP_N_ERROR,
} lcp_arp_phy_t;

char *lcp_arp_phy_error_strings[] = {
#define _(sym,str) str,
  foreach_lcp_arp_error
#undef _
};

/**
 * punt ARP replies to the host
 */
VLIB_NODE_FN (lcp_arp_phy_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lcp_arp_next_t next_index;
  u32 reply_copies[VLIB_FRAME_SIZE];
  u32 n_copies = 0;

  next_index = node->cached_next_index;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 2 && n_left_to_next >= 2)
	{
	  u32 next0, next1, bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  ethernet_arp_header_t *arp0, *arp1;

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  next0 = next1 = LCP_ARP_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  arp0 = vlib_buffer_get_current (b0);
	  arp1 = vlib_buffer_get_current (b1);

	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);

	  /*
	   * Replies might need to be received by the host, so we
	   * make a copy of them.
	   */
	  if (arp0->opcode ==
	      clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply))
	    {
	      lcp_itf_pair_t *lip0 = 0;
	      u32 lipi0;
	      vlib_buffer_t *c0;
	      u8 len0;

	      lipi0 =
		lcp_itf_pair_find_by_phy
		(vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	      lip0 = lcp_itf_pair_get (lipi0);

	      if (lip0)
		{
		  /*
		   * rewind to eth header, copy, advance back to current
		   */
		  len0 = ((u8 *) vlib_buffer_get_current (b0) -
			  (u8 *) ethernet_buffer_get_header (b0));
		  vlib_buffer_advance (b0, -len0);
		  c0 = vlib_buffer_copy (vm, b0);
		  vlib_buffer_advance (b0, len0);

		  /* Send to the host */
		  vnet_buffer (c0)->sw_if_index[VLIB_TX] =
		    lip0->lip_host_sw_if_index;
		  reply_copies[n_copies++] = vlib_get_buffer_index (vm, c0);
		}
	    }
	  if (arp1->opcode ==
	      clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply))
	    {
	      lcp_itf_pair_t *lip1 = 0;
	      u32 lipi1;
	      vlib_buffer_t *c1;
	      u8 len1;

	      lipi1 =
		lcp_itf_pair_find_by_phy
		(vnet_buffer (b1)->sw_if_index[VLIB_RX]);
	      lip1 = lcp_itf_pair_get (lipi1);

	      if (lip1)
		{
		  /*
		   * rewind to reveal the ethernet header
		   */
		  len1 = ((u8 *) vlib_buffer_get_current (b1) -
			  (u8 *) ethernet_buffer_get_header (b1));
		  vlib_buffer_advance (b1, -len1);
		  c1 = vlib_buffer_copy (vm, b1);
		  vlib_buffer_advance (b1, len1);

		  /* Send to the host */
		  vnet_buffer (c1)->sw_if_index[VLIB_TX] =
		    lip1->lip_host_sw_if_index;
		  reply_copies[n_copies++] = vlib_get_buffer_index (vm, c1);
		}
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lcp_arp_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	    }
	  if (PREDICT_FALSE ((b1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lcp_arp_trace_t *t =
		vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->rx_sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 next0, bi0;
	  vlib_buffer_t *b0;
	  ethernet_arp_header_t *arp0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  next0 = LCP_ARP_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  arp0 = vlib_buffer_get_current (b0);

	  vnet_feature_next (&next0, b0);

	  /*
	   * Replies might need to be received by the host, so we
	   * make a copy of them.
	   */
	  if (arp0->opcode ==
	      clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply))
	    {
	      lcp_itf_pair_t *lip0 = 0;
	      vlib_buffer_t *c0;
	      u32 lipi0;
	      u8 len0;

	      lipi0 =
		lcp_itf_pair_find_by_phy
		(vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	      lip0 = lcp_itf_pair_get (lipi0);

	      if (lip0)
		{

		  /*
		   * rewind to reveal the ethernet header
		   */
		  len0 = ((u8 *) vlib_buffer_get_current (b0) -
			  (u8 *) ethernet_buffer_get_header (b0));
		  vlib_buffer_advance (b0, -len0);
		  c0 = vlib_buffer_copy (vm, b0);
		  vlib_buffer_advance (b0, len0);

		  /* Send to the host */
		  vnet_buffer (c0)->sw_if_index[VLIB_TX] =
		    lip0->lip_host_sw_if_index;
		  reply_copies[n_copies++] = vlib_get_buffer_index (vm, c0);
		}
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lcp_arp_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

    }

  if (n_copies)
    {
      vlib_buffer_enqueue_to_single_next (vm, node, reply_copies,
					  LCP_ARP_NEXT_IO, n_copies);
      vlib_error_count (vm, node->node_index, LCP_ARP_ERROR_COPIES,
			n_copies);
    }

  vlib_error_count (vm, node->node_index, LCP_ARP_ERROR_PACKETS,
		    frame->n_vectors);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lcp_arp_phy_node) = {
  .name = "linux-cp-arp-phy",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_arp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LCP_ARP_N_ERROR,
  .error_strings = lcp_arp_phy_error_strings,
  .n_next_nodes = LCP_ARP_N_NEXT,
  .next_nodes = {
    [LCP_ARP_NEXT_DROP] = "error-drop",
    [LCP_ARP_NEXT_IO] = "interface-output",
  },
};

VNET_FEATURE_INIT (lcp_arp_phy_arp_feat, static) =
{
  .arc_name = "arp",
  .node_name = "linux-cp-arp-phy",
  .runs_before = VNET_FEATURES ("arp-reply"),
};

/**
 * x-connect ARP packets from the host to the phy
 */
VLIB_NODE_FN (lcp_arp_host_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lcp_arp_next_t next_index;

  next_index = node->cached_next_index;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          const lcp_itf_pair_t *lip0;
	  lcp_arp_next_t next0;
	  vlib_buffer_t *b0;
          u32 bi0, lipi0;
          u8 len0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  next0 = LCP_ARP_NEXT_IO;

	  b0 = vlib_get_buffer (vm, bi0);

          lipi0 = lcp_itf_pair_find_by_host (vnet_buffer (b0)->sw_if_index[VLIB_RX]);
          lip0 = lcp_itf_pair_get (lipi0);

          /* Send to the phy */
          vnet_buffer (b0)->sw_if_index[VLIB_TX] = lip0->lip_phy_sw_if_index;

          len0 = ((u8 *) vlib_buffer_get_current (b0) -
                  (u8 *) ethernet_buffer_get_header (b0));
          vlib_buffer_advance (b0, -len0);

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lcp_arp_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

    }

  vlib_error_count (vm, node->node_index, LCP_ARP_ERROR_PACKETS,
		    frame->n_vectors);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lcp_arp_host_node) = {
  .name = "linux-cp-arp-host",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_arp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LCP_ARP_N_ERROR,
  .error_strings = lcp_arp_phy_error_strings,
  .n_next_nodes = LCP_ARP_N_NEXT,
  .next_nodes = {
    [LCP_ARP_NEXT_DROP] = "error-drop",
    [LCP_ARP_NEXT_IO] = "interface-output",
  },
};

VNET_FEATURE_INIT (lcp_arp_host_arp_feat, static) =
{
  .arc_name = "arp",
  .node_name = "linux-cp-arp-host",
  .runs_before = VNET_FEATURES ("arp-reply"),
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
