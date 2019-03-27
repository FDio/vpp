/*
 * DHCP feature; applied as an input feature to select DHCP packets
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

#include <vnet/dhcp/client.h>
#include <vnet/udp/udp.h>

#define foreach_dhcp_client_detect                    \
  _(EXTRACT, "Extract")

typedef enum
{
#define _(sym,str) DHCP_CLIENT_DETECT_ERROR_##sym,
  foreach_dhcp_client_detect
#undef _
    DHCP_CLIENT_DETECT_N_ERROR,
} dhcp_client_detect_error_t;

static char *dhcp_client_detect_error_strings[] = {
#define _(sym,string) string,
  foreach_dhcp_client_detect
#undef _
};

typedef enum
{
#define _(sym,str) DHCP_CLIENT_DETECT_NEXT_##sym,
  foreach_dhcp_client_detect
#undef _
    DHCP_CLIENT_DETECT_N_NEXT,
} dhcp_client_detect_next_t;

/**
 * per-packet trace data
 */
typedef struct dhcp_client_detect_trace_t_
{
  /* per-pkt trace data */
  u8 extracted;
} dhcp_client_detect_trace_t;

VLIB_NODE_FN (dhcp_client_detect_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
  dhcp_client_detect_next_t next_index;
  u16 dhcp_client_port_network_order;
  u32 n_left_from, *from, *to_next;
  u32 extractions;

  dhcp_client_port_network_order =
    clib_net_to_host_u16 (UDP_DST_PORT_dhcp_to_client);
  next_index = 0;
  extractions = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /*
       * This loop is optimised not so we can really quickly process DHCp
       * offers... but so we can quickly sift them out when the interface
       * is also receiving 'normal' packets
       */
      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  udp_header_t *udp0, *udp1, *udp2, *udp3;
	  ip4_header_t *ip0, *ip1, *ip2, *ip3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  u32 next0, next1, next2, next3;
	  u32 bi0, bi1, bi2, bi3;

	  next0 = next1 = next2 = next3 = ~0;
	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];
	  bi2 = to_next[2] = from[2];
	  bi3 = to_next[3] = from[3];

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3, *p4, *p5;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);

	    vlib_prefetch_buffer_header (p2, STORE);
	    vlib_prefetch_buffer_header (p3, STORE);
	    vlib_prefetch_buffer_header (p4, STORE);
	    vlib_prefetch_buffer_header (p5, STORE);

	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]) + sizeof (udp0[0]),
			   STORE);
	    CLIB_PREFETCH (p3->data, sizeof (ip0[0]) + sizeof (udp0[0]),
			   STORE);
	    CLIB_PREFETCH (p4->data, sizeof (ip0[0]) + sizeof (udp0[0]),
			   STORE);
	    CLIB_PREFETCH (p5->data, sizeof (ip0[0]) + sizeof (udp0[0]),
			   STORE);
	  }

	  from += 4;
	  to_next += 4;
	  n_left_from -= 4;
	  n_left_to_next -= 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);
	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  ip2 = vlib_buffer_get_current (b2);
	  ip3 = vlib_buffer_get_current (b2);

	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);
	  vnet_feature_next (&next2, b2);
	  vnet_feature_next (&next3, b3);

	  if (ip0->protocol == IP_PROTOCOL_UDP)
	    {
	      udp0 = (udp_header_t *) (ip0 + 1);

	      if (dhcp_client_port_network_order == udp0->dst_port)
		{
		  next0 = DHCP_CLIENT_DETECT_NEXT_EXTRACT;
		  extractions++;
		}
	    }
	  if (ip1->protocol == IP_PROTOCOL_UDP)
	    {
	      udp1 = (udp_header_t *) (ip1 + 1);

	      if (dhcp_client_port_network_order == udp1->dst_port)
		{
		  next1 = DHCP_CLIENT_DETECT_NEXT_EXTRACT;
		  extractions++;
		}
	    }
	  if (ip2->protocol == IP_PROTOCOL_UDP)
	    {
	      udp2 = (udp_header_t *) (ip2 + 1);

	      if (dhcp_client_port_network_order == udp2->dst_port)
		{
		  next2 = DHCP_CLIENT_DETECT_NEXT_EXTRACT;
		  extractions++;
		}
	    }
	  if (ip3->protocol == IP_PROTOCOL_UDP)
	    {
	      udp3 = (udp_header_t *) (ip3 + 1);

	      if (dhcp_client_port_network_order == udp3->dst_port)
		{
		  next3 = DHCP_CLIENT_DETECT_NEXT_EXTRACT;
		  extractions++;
		}
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      dhcp_client_detect_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->extracted = (next0 == DHCP_CLIENT_DETECT_NEXT_EXTRACT);
	    }
	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      dhcp_client_detect_trace_t *t =
		vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->extracted = (next1 == DHCP_CLIENT_DETECT_NEXT_EXTRACT);
	    }
	  if (PREDICT_FALSE (b2->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      dhcp_client_detect_trace_t *t =
		vlib_add_trace (vm, node, b2, sizeof (*t));
	      t->extracted = (next2 == DHCP_CLIENT_DETECT_NEXT_EXTRACT);
	    }
	  if (PREDICT_FALSE (b3->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      dhcp_client_detect_trace_t *t =
		vlib_add_trace (vm, node, b3, sizeof (*t));
	      t->extracted = (next3 == DHCP_CLIENT_DETECT_NEXT_EXTRACT);
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  udp_header_t *udp0;
	  vlib_buffer_t *b0;
	  ip4_header_t *ip0;
	  u32 next0 = ~0;
	  u32 bi0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);

	  /*
	   * when this feature is applied on an interface that is already
	   * accepting packets (because e.g. the interface has other addresses
	   * assigned) we are looking for the preverbial needle in the haystack
	   * so assume the packet is not the one we are looking for.
	   */
	  vnet_feature_next (&next0, b0);

	  /*
	   * all we are looking for here is DHCP/BOOTP packet-to-client
	   * UDO port.
	   */
	  if (ip0->protocol == IP_PROTOCOL_UDP)
	    {
	      udp0 = (udp_header_t *) (ip0 + 1);

	      if (dhcp_client_port_network_order == udp0->dst_port)
		{
		  next0 = DHCP_CLIENT_DETECT_NEXT_EXTRACT;
		  extractions++;
		}
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      dhcp_client_detect_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->extracted = (next0 == DHCP_CLIENT_DETECT_NEXT_EXTRACT);
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       DHCP_CLIENT_DETECT_ERROR_EXTRACT, extractions);

  return frame->n_vectors;
}

/* packet trace format function */
static u8 *
format_dhcp_client_detect_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dhcp_client_detect_trace_t *t =
    va_arg (*args, dhcp_client_detect_trace_t *);

  s = format (s, "dhcp-client-detect: %s", (t->extracted ? "yes" : "no"));

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dhcp_client_detect_node) = {
  .name = "ip4-dhcp-client-detect",
  .vector_size = sizeof (u32),
  .format_trace = format_dhcp_client_detect_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(dhcp_client_detect_error_strings),
  .error_strings = dhcp_client_detect_error_strings,

  .n_next_nodes = DHCP_CLIENT_DETECT_N_NEXT,
  .next_nodes = {
    /*
     * Jump straight to the UDP dispatch node thus avoiding
     * the RPF checks in ip4-local that will fail
     */
    [DHCP_CLIENT_DETECT_NEXT_EXTRACT] = "ip4-udp-lookup",
  },
};

VNET_FEATURE_INIT (ip4_dvr_reinject_feat_node, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-dhcp-client-detect",
  .runs_before = VNET_FEATURES ("ip4-not-enabled"),
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
