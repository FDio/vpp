/*
 * gbp.h : Group Based Policy
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <plugins/gbp/gbp.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/fib/fib_table.h>
#include <vnet/vxlan-gbp/vxlan_gbp_packet.h>

typedef enum gbp_src_classify_type_t_
{
  GBP_SRC_CLASSIFY_NULL,
  GBP_SRC_CLASSIFY_PORT,
} gbp_src_classify_type_t;

#define GBP_SRC_N_CLASSIFY (GBP_SRC_CLASSIFY_PORT + 1)

/**
 * Grouping of global data for the GBP source EPG classification feature
 */
typedef struct gbp_src_classify_main_t_
{
  /**
   * Next nodes for L2 output features
   */
  u32 l2_input_feat_next[GBP_SRC_N_CLASSIFY][32];
} gbp_src_classify_main_t;

static gbp_src_classify_main_t gbp_src_classify_main;

/**
 * per-packet trace data
 */
typedef struct gbp_classify_trace_t_
{
  /* per-pkt trace data */
  epg_id_t src_epg;
} gbp_classify_trace_t;

/*
 * determine the SRC EPG form the input port
 */
always_inline uword
gbp_classify_inline (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * frame,
		     gbp_src_classify_type_t type, dpo_proto_t dproto)
{
  gbp_src_classify_main_t *gscm = &gbp_src_classify_main;
  u32 n_left_from, *from, *to_next;
  u32 next_index;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 next0, bi0, src_epg, sw_if_index0;
	  const gbp_endpoint_t *ge0;
	  vlib_buffer_t *b0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  vnet_buffer2 (b0)->gbp.flags = VXLAN_GBP_GPFLAGS_NONE;

	  if (GBP_SRC_CLASSIFY_NULL == type)
	    {
	      src_epg = EPG_INVALID;
	      next0 =
		vnet_l2_feature_next (b0, gscm->l2_input_feat_next[type],
				      L2INPUT_FEAT_GBP_NULL_CLASSIFY);
	    }
	  else
	    {
	      if (DPO_PROTO_ETHERNET == dproto)
		{
		  const ethernet_header_t *h0;

		  h0 = vlib_buffer_get_current (b0);
		  next0 =
		    vnet_l2_feature_next (b0, gscm->l2_input_feat_next[type],
					  L2INPUT_FEAT_GBP_SRC_CLASSIFY);
		  ge0 = gbp_endpoint_find_mac (h0->src_address,
					       vnet_buffer (b0)->l2.bd_index);
		}
	      else if (DPO_PROTO_IP4 == dproto)
		{
		  const ip4_header_t *h0;

		  h0 = vlib_buffer_get_current (b0);

		  ge0 = gbp_endpoint_find_ip4
		    (&h0->src_address,
		     fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
							  sw_if_index0));


		  /*
		   * Go straight to looukp, do not pass go, do not collect $200
		   */
		  next0 = 0;
		}
	      else if (DPO_PROTO_IP6 == dproto)
		{
		  const ip6_header_t *h0;

		  h0 = vlib_buffer_get_current (b0);

		  ge0 = gbp_endpoint_find_ip6
		    (&h0->src_address,
		     fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6,
							  sw_if_index0));


		  /*
		   * Go straight to lookup, do not pass go, do not collect $200
		   */
		  next0 = 0;
		}
	      else
		{
		  ge0 = NULL;
		  next0 = 0;
		  ASSERT (0);
		}

	      if (PREDICT_TRUE (NULL != ge0))
		src_epg = ge0->ge_epg_id;
	      else
		src_epg = EPG_INVALID;
	    }

	  vnet_buffer2 (b0)->gbp.src_epg = src_epg;

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      gbp_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->src_epg = src_epg;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
gbp_src_classify (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_classify_inline (vm, node, frame,
			       GBP_SRC_CLASSIFY_PORT, DPO_PROTO_ETHERNET));
}

static uword
gbp_null_classify (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_classify_inline (vm, node, frame,
			       GBP_SRC_CLASSIFY_NULL, DPO_PROTO_ETHERNET));
}

static uword
gbp_ip4_src_classify (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_classify_inline (vm, node, frame,
			       GBP_SRC_CLASSIFY_PORT, DPO_PROTO_IP4));
}

static uword
gbp_ip6_src_classify (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_classify_inline (vm, node, frame,
			       GBP_SRC_CLASSIFY_PORT, DPO_PROTO_IP6));
}


/* packet trace format function */
static u8 *
format_gbp_classify_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_classify_trace_t *t = va_arg (*args, gbp_classify_trace_t *);

  s = format (s, "src-epg:%d", t->src_epg);

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_null_classify_node) = {
  .function = gbp_null_classify,
  .name = "gbp-null-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 0,
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_null_classify_node, gbp_null_classify);

VLIB_REGISTER_NODE (gbp_src_classify_node) = {
  .function = gbp_src_classify,
  .name = "gbp-src-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 0,
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_src_classify_node, gbp_src_classify);

VLIB_REGISTER_NODE (gbp_ip4_src_classify_node) = {
  .function = gbp_ip4_src_classify,
  .name = "ip4-gbp-src-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip4-lookup"
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_ip4_src_classify_node, gbp_ip4_src_classify);

VLIB_REGISTER_NODE (gbp_ip6_src_classify_node) = {
  .function = gbp_ip6_src_classify,
  .name = "ip6-gbp-src-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip6-lookup"
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_ip6_src_classify_node, gbp_ip6_src_classify);

VNET_FEATURE_INIT (gbp_ip4_src_classify_feat_node, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-gbp-src-classify",
  .runs_before = VNET_FEATURES ("nat44-out2in"),
};
VNET_FEATURE_INIT (gbp_ip6_src_classify_feat_node, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-gbp-src-classify",
  .runs_before = VNET_FEATURES ("nat66-out2in"),
};

static clib_error_t *
gbp_src_classify_init (vlib_main_t * vm)
{
  gbp_src_classify_main_t *em = &gbp_src_classify_main;

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       gbp_src_classify_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       em->l2_input_feat_next[GBP_SRC_CLASSIFY_NULL]);
  feat_bitmap_init_next_nodes (vm,
			       gbp_null_classify_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       em->l2_input_feat_next[GBP_SRC_CLASSIFY_PORT]);

  return 0;
}

VLIB_INIT_FUNCTION (gbp_src_classify_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
