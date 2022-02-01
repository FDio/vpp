/*
 * l2_input.c : layer 2 input packet processing
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/fib/fib_node.h>
#include <vnet/ethernet/arp_packet.h>
#include <vlib/cli.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_bvi.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/l2/l2_bd.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>

/**
 * @file
 * @brief Interface Input Mode (Layer 2 Cross-Connect or Bridge / Layer 3).
 *
 * This file contains the CLI Commands that modify the input mode of an
 * interface. For interfaces in a Layer 2 cross-connect, all packets
 * received on one interface will be transmitted to the other. For
 * interfaces in a bridge-domain, packets will be forwarded to other
 * interfaces in the same bridge-domain based on destination mac address.
 * For interfaces in Layer 3 mode, the packets will be routed.
 */

typedef struct
{
  /* per-pkt trace data */
  u8 dst_and_src[12];
  u32 sw_if_index;
  u32 feat_mask;
} l2input_trace_t;

/* packet trace format function */
static u8 *
format_l2input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2input_trace_t *t = va_arg (*args, l2input_trace_t *);

  s = format (s, "l2-input: sw_if_index %d dst %U src %U [%U]",
	      t->sw_if_index,
	      format_ethernet_address, t->dst_and_src,
	      format_ethernet_address, t->dst_and_src + 6,
	      format_l2_input_feature_bitmap, t->feat_mask, 0);
  return s;
}

extern l2input_main_t l2input_main;

#ifndef CLIB_MARCH_VARIANT
l2input_main_t l2input_main;
#endif /* CLIB_MARCH_VARIANT */

#define foreach_l2input_error			\
_(L2INPUT,     "L2 input packets")		\
_(DROP,        "L2 input drops")

typedef enum
{
#define _(sym,str) L2INPUT_ERROR_##sym,
  foreach_l2input_error
#undef _
    L2INPUT_N_ERROR,
} l2input_error_t;

static char *l2input_error_strings[] = {
#define _(sym,string) string,
  foreach_l2input_error
#undef _
};

typedef enum
{				/*  */
  L2INPUT_NEXT_LEARN,
  L2INPUT_NEXT_FWD,
  L2INPUT_NEXT_DROP,
  L2INPUT_N_NEXT,
} l2input_next_t;

static_always_inline void
classify_and_dispatch (l2input_main_t * msm, vlib_buffer_t * b0, u16 * next0)
{
  /*
   * Load L2 input feature struct
   * Load bridge domain struct
   * Parse ethernet header to determine unicast/mcast/broadcast
   * take L2 input stat
   * classify packet as IP/UDP/TCP, control, other
   * mask feature bitmap
   * go to first node in bitmap
   * Later: optimize VTM
   *
   * For L2XC,
   *   set tx sw-if-handle
   */

  u32 feat_mask = ~0;
  u32 sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  ethernet_header_t *h0 = vlib_buffer_get_current (b0);

  /* Get config for the input interface */
  l2_input_config_t *config = vec_elt_at_index (msm->configs, sw_if_index0);

  /* Save split horizon group */
  vnet_buffer (b0)->l2.shg = config->shg;

  /* determine layer2 kind for stat and mask */
  if (PREDICT_FALSE (ethernet_address_cast (h0->dst_address)))
    {
      u8 *l3h0 = (u8 *) h0 + vnet_buffer (b0)->l2.l2_len;

#define get_u16(addr) ( *((u16 *)(addr)) )
      u16 ethertype = clib_net_to_host_u16 (get_u16 (l3h0 - 2));
      u8 protocol = ((ip6_header_t *) l3h0)->protocol;

      /* Disable bridge forwarding (flooding will execute instead if not xconnect) */
      feat_mask &=
	~(L2INPUT_FEAT_FWD | L2INPUT_FEAT_UU_FLOOD | L2INPUT_FEAT_UU_FWD);

      if (ethertype != ETHERNET_TYPE_ARP)
	feat_mask &= ~(L2INPUT_FEAT_ARP_UFWD);

      /* Disable ARP-term for non-ARP and non-ICMP6 packet */
      if (ethertype != ETHERNET_TYPE_ARP &&
	  (ethertype != ETHERNET_TYPE_IP6 || protocol != IP_PROTOCOL_ICMP6))
	feat_mask &= ~(L2INPUT_FEAT_ARP_TERM);
      /*
       * For packet from BVI - set SHG of ARP request or ICMPv6 neighbor
       * solicitation packet from BVI to 0 so it can also flood to VXLAN
       * tunnels or other ports with the same SHG as that of the BVI.
       */
      else if (PREDICT_FALSE (vnet_buffer (b0)->sw_if_index[VLIB_TX] ==
			      L2INPUT_BVI))
	{
	  if (ethertype == ETHERNET_TYPE_ARP)
	    {
	      ethernet_arp_header_t *arp0 = (ethernet_arp_header_t *) l3h0;
	      if (arp0->opcode ==
		  clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request))
		vnet_buffer (b0)->l2.shg = 0;
	    }
	  else			/* must be ICMPv6 */
	    {
	      ip6_header_t *iph0 = (ip6_header_t *) l3h0;
	      icmp6_neighbor_solicitation_or_advertisement_header_t *ndh0;
	      ndh0 = ip6_next_header (iph0);
	      if (ndh0->icmp.type == ICMP6_neighbor_solicitation)
		vnet_buffer (b0)->l2.shg = 0;
	    }
	}
    }
  else
    {
      /*
       * For packet from BVI - set SHG of unicast packet from BVI to 0 so it
       * is not dropped on output to VXLAN tunnels or other ports with the
       * same SHG as that of the BVI.
       */
      if (PREDICT_FALSE (vnet_buffer (b0)->sw_if_index[VLIB_TX] ==
			 L2INPUT_BVI))
	vnet_buffer (b0)->l2.shg = 0;
    }


  if (l2_input_is_bridge (config))
    {
      /* Do bridge-domain processing */
      /* save BD ID for next feature graph nodes */
      vnet_buffer (b0)->l2.bd_index = config->bd_index;

      /* Save bridge domain and interface seq_num */
      vnet_buffer (b0)->l2.l2fib_sn = l2_fib_mk_seq_num
	(config->bd_seq_num, config->seq_num);
      vnet_buffer (b0)->l2.bd_age = config->bd_mac_age;

      /*
       * Process bridge domain feature enables.
       * To perform learning/flooding/forwarding, the corresponding bit
       * must be enabled in both the input interface config and in the
       * bridge domain config. In the bd_bitmap, bits for features other
       * than learning/flooding/forwarding should always be set.
       */
      feat_mask = feat_mask & config->bd_feature_bitmap;
    }
  else if (l2_input_is_xconnect (config))
    {
      /* Set the output interface */
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = config->output_sw_if_index;
    }
  else
    feat_mask = L2INPUT_FEAT_DROP;

  /* mask out features from bitmap using packet type and bd config */
  u32 feature_bitmap = config->feature_bitmap & feat_mask;

  /* save for next feature graph nodes */
  vnet_buffer (b0)->l2.feature_bitmap = feature_bitmap;

  /* Determine the next node */
  *next0 = feat_bitmap_get_next_node_index (msm->feat_next_node_index,
					    feature_bitmap);
}

static_always_inline uword
l2input_node_inline (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame,
		     int do_trace)
{
  u32 n_left, *from;
  l2input_main_t *msm = &l2input_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;	/* number of packets to process */

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      while (n_left >= 8)
	{
	  u32 sw_if_index0, sw_if_index1, sw_if_index2, sw_if_index3;

	  /* Prefetch next iteration. */
	  {
	    /* Prefetch the buffer header and packet for the N+2 loop iteration */
	    vlib_prefetch_buffer_header (b[4], LOAD);
	    vlib_prefetch_buffer_header (b[5], LOAD);
	    vlib_prefetch_buffer_header (b[6], LOAD);
	    vlib_prefetch_buffer_header (b[7], LOAD);

	    clib_prefetch_store (b[4]->data);
	    clib_prefetch_store (b[5]->data);
	    clib_prefetch_store (b[6]->data);
	    clib_prefetch_store (b[7]->data);
	  }

	  classify_and_dispatch (msm, b[0], &next[0]);
	  classify_and_dispatch (msm, b[1], &next[1]);
	  classify_and_dispatch (msm, b[2], &next[2]);
	  classify_and_dispatch (msm, b[3], &next[3]);

	  if (do_trace)
	    {
	      /* RX interface handles */
	      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      sw_if_index1 = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
	      sw_if_index2 = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
	      sw_if_index3 = vnet_buffer (b[3])->sw_if_index[VLIB_RX];

	      if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ethernet_header_t *h0 = vlib_buffer_get_current (b[0]);
		  l2input_trace_t *t =
		    vlib_add_trace (vm, node, b[0], sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  t->feat_mask = vnet_buffer (b[0])->l2.feature_bitmap;
		  clib_memcpy_fast (t->dst_and_src, h0->dst_address,
				    sizeof (h0->dst_address) +
				    sizeof (h0->src_address));
		}
	      if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ethernet_header_t *h1 = vlib_buffer_get_current (b[1]);
		  l2input_trace_t *t =
		    vlib_add_trace (vm, node, b[1], sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  t->feat_mask = vnet_buffer (b[1])->l2.feature_bitmap;
		  clib_memcpy_fast (t->dst_and_src, h1->dst_address,
				    sizeof (h1->dst_address) +
				    sizeof (h1->src_address));
		}
	      if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ethernet_header_t *h2 = vlib_buffer_get_current (b[2]);
		  l2input_trace_t *t =
		    vlib_add_trace (vm, node, b[2], sizeof (*t));
		  t->sw_if_index = sw_if_index2;
		  t->feat_mask = vnet_buffer (b[2])->l2.feature_bitmap;
		  clib_memcpy_fast (t->dst_and_src, h2->dst_address,
				    sizeof (h2->dst_address) +
				    sizeof (h2->src_address));
		}
	      if (b[3]->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ethernet_header_t *h3 = vlib_buffer_get_current (b[3]);
		  l2input_trace_t *t =
		    vlib_add_trace (vm, node, b[3], sizeof (*t));
		  t->sw_if_index = sw_if_index3;
		  t->feat_mask = vnet_buffer (b[3])->l2.feature_bitmap;
		  clib_memcpy_fast (t->dst_and_src, h3->dst_address,
				    sizeof (h3->dst_address) +
				    sizeof (h3->src_address));
		}
	    }

	  b += 4;
	  n_left -= 4;
	  next += 4;
	}

      while (n_left > 0)
	{
	  classify_and_dispatch (msm, b[0], &next[0]);

	  if (do_trace && PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ethernet_header_t *h0 = vlib_buffer_get_current (b[0]);
	      l2input_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      t->feat_mask = vnet_buffer (b[0])->l2.feature_bitmap;
	      clib_memcpy_fast (t->dst_and_src, h0->dst_address,
				sizeof (h0->dst_address) +
				sizeof (h0->src_address));
	    }

	  b += 1;
	  next += 1;
	  n_left -= 1;
	}
    }

  vlib_node_increment_counter (vm, l2input_node.index,
			       L2INPUT_ERROR_L2INPUT, frame->n_vectors);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (l2input_node) (vlib_main_t * vm,
			     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return l2input_node_inline (vm, node, frame, 1 /* do_trace */ );
  return l2input_node_inline (vm, node, frame, 0 /* do_trace */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2input_node) = {
  .name = "l2-input",
  .vector_size = sizeof (u32),
  .format_trace = format_l2input_trace,
  .format_buffer = format_ethernet_header_with_length,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2input_error_strings),
  .error_strings = l2input_error_strings,

  .n_next_nodes = L2INPUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
       [L2INPUT_NEXT_LEARN] = "l2-learn",
       [L2INPUT_NEXT_FWD]   = "l2-fwd",
       [L2INPUT_NEXT_DROP]  = "error-drop",
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
