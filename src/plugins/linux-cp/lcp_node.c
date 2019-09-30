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

#include <vnet/feature/feature.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/ethernet/ethernet.h>

#define foreach_lip_xc                          \
  _(XC, "x-connnect")

typedef enum
{
#define _(sym,str) LIP_XC_NEXT_##sym,
  foreach_lip_xc
#undef _
    LIP_XC_N_NEXT,
} lip_xc_next_t;

typedef struct lip_xc_trace_t_
{
  u32 phy_sw_if_index;
} lip_xc_trace_t;

/* packet trace format function */
static u8 *
format_lip_xc_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lip_xc_trace_t *t = va_arg (*args, lip_xc_trace_t *);

  s = format (s, "lip-xc: %d", t->phy_sw_if_index);

  return s;
}

/**
 * X-connect all packets from the HOST to the PHY.
 */
VLIB_NODE_FN (lip_xc_node) (vlib_main_t * vm,
			    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lip_xc_next_t next_index;

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
	  next0 = LIP_XC_NEXT_XC;

	  b0 = vlib_get_buffer (vm, bi0);

	  lipi =
	    *(u32 *) vnet_feature_next_with_data (&next0, b0, sizeof (lipi));
	  lip = lcp_itf_pair_get (lipi);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = lip->lip_phy_sw_if_index;
	  next0 = LIP_XC_NEXT_XC;

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lip_xc_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->phy_sw_if_index = lip->lip_phy_sw_if_index;
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
VLIB_REGISTER_NODE (lip_xc_node) = {
  .name = "linux-cp-xc",
  .vector_size = sizeof (u32),
  .format_trace = format_lip_xc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LIP_XC_N_NEXT,
  .next_nodes = {
    [LIP_XC_NEXT_XC] = "interface-output",
  },
};

VNET_FEATURE_INIT(lip_xc_node, static) =
{
  .arc_name = "device-input",
  .node_name = "linux-cp-xc",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON* */


#define foreach_lip_ethernet                          \
  _(IO, "interface-output")

typedef enum
{
#define _(sym,str) LIP_ETHERNET_NEXT_##sym,
  foreach_lip_ethernet
#undef _
    LIP_ETHERNET_N_NEXT,
} lip_ethernet_next_t;

typedef struct lip_ethernet_trace_t_
{
  u32 host_sw_if_index;
} lip_ethernet_trace_t;

/* packet trace format function */
static u8 *
format_lip_ethernet_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lip_ethernet_trace_t *t = va_arg (*args, lip_ethernet_trace_t *);

  s = format (s, "host-sw-if-index: %d", t->host_sw_if_index);

  return s;
}

/**
 * punt unknown ether types to the host
 */
VLIB_NODE_FN (lcp_ethernet_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lip_ethernet_next_t next_index;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  const lcp_itf_pair_t *lip;
	  u32 next0, bi0, lipi;
	  vlib_buffer_t *b0;
	  u8 len0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  next0 = LIP_ETHERNET_NEXT_IO;

	  b0 = vlib_get_buffer (vm, bi0);

	  lipi =
	    lcp_itf_pair_find_by_phy (vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	  lip = lcp_itf_pair_get (lipi);

	  /*
	   * rewind to reveal the ethernet header
	   */
	  len0 = ((u8 *) vlib_buffer_get_current (b0) -
		  (u8 *) ethernet_buffer_get_header (b0));
	  vlib_buffer_advance (b0, -len0);

	  /* Send to the host */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = lip->lip_host_sw_if_index;

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lip_ethernet_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->host_sw_if_index = lip->lip_host_sw_if_index;
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
VLIB_REGISTER_NODE (lcp_ethernet_node) = {
  .name = "linux-cp-ethernet",
  .vector_size = sizeof (u32),
  .format_trace = format_lip_ethernet_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LIP_ETHERNET_N_NEXT,
  .next_nodes = {
    [LIP_ETHERNET_NEXT_IO] = "interface-output",
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
