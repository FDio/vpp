/*
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
#include <plugins/gbp/gbp_itf.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_in_out_feat_arc.h>

/**
 * Grouping of global data for the GBP source EPG classification feature
 */
typedef struct gbp_sclass_main_t_
{
  /**
   * Next nodes for L2 output features
   */
  u32 gel_l2_input_feat_next[32];
  u32 gel_l2_output_feat_next[32];
} gbp_sclass_main_t;

static gbp_sclass_main_t gbp_sclass_main;

#define foreach_gbp_sclass                      \
  _(DROP,    "drop")


typedef enum
{
#define _(sym,str) GBP_SCLASS_NEXT_##sym,
  foreach_gbp_sclass
#undef _
    GBP_SCLASS_N_NEXT,
} gbp_sclass_next_t;

typedef struct gbp_sclass_trace_t_
{
  /* per-pkt trace data */
  u32 epg;
  u32 sclass;
} gbp_sclass_trace_t;

static_always_inline uword
gbp_sclass_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame, int is_id_2_sclass, int is_l2)
{
  u32 n_left_from, *from, *to_next, next_index;
  gbp_sclass_main_t *glm;

  glm = &gbp_sclass_main;
  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  gbp_sclass_next_t next0;
	  vlib_buffer_t *b0;
	  epg_id_t epg0;
	  u16 sclass0;
	  u32 bi0;

	  next0 = GBP_SCLASS_NEXT_DROP;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  if (is_id_2_sclass)
	    {
	      // output direction - convert from the SRC-EPD to the sclass
	      gbp_endpoint_group_t *gg;

	      epg0 = vnet_buffer2 (b0)->gbp.src_epg;
	      gg = gbp_epg_get (epg0);

	      if (NULL != gg)
		{
		  sclass0 = vnet_buffer2 (b0)->gbp.sclass = gg->gg_sclass;
		  if (is_l2)
		    next0 =
		      vnet_l2_feature_next (b0, glm->gel_l2_output_feat_next,
					    L2OUTPUT_FEAT_GBP_ID_2_SCLASS);
		  else
		    vnet_feature_next (&next0, b0);
		}
	      else
		sclass0 = 0;
	    }
	  else
	    {
	      /* input direction - convert from the sclass to the SRC-EGD */
	      sclass0 = vnet_buffer2 (b0)->gbp.sclass;
	      vnet_buffer2 (b0)->gbp.src_epg =
		gbp_epg_sclass_2_id (vnet_buffer2 (b0)->gbp.sclass);
	      epg0 = vnet_buffer2 (b0)->gbp.src_epg;

	      if (EPG_INVALID != epg0)
		{
		  vnet_feature_next (&next0, b0);
		}
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      gbp_sclass_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->epg = epg0;
	      t->sclass = sclass0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

uword
l2_gbp_id_2_sclass (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_sclass_inline (vm, node, frame, 1, 1));
}

uword
l2_gbp_sclass_2_id (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_sclass_inline (vm, node, frame, 0, 1));
}

uword
ip4_gbp_id_2_sclass (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_sclass_inline (vm, node, frame, 1, 0));
}

uword
ip4_gbp_sclass_2_id (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_sclass_inline (vm, node, frame, 0, 0));
}

uword
ip6_gbp_id_2_sclass (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_sclass_inline (vm, node, frame, 1, 0));
}

uword
ip6_gbp_sclass_2_id (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_sclass_inline (vm, node, frame, 0, 0));
}

/* packet trace format function */
static u8 *
format_gbp_sclass_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_sclass_trace_t *t = va_arg (*args, gbp_sclass_trace_t *);

  s = format (s, "epg:%d sclass:%d", t->epg, t->sclass);

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2_gbp_id_2_sclass_node) = {
  .function = l2_gbp_id_2_sclass,
  .name = "l2-gbp-id-2-sclass",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_sclass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = GBP_SCLASS_N_NEXT,

  .next_nodes = {
    [GBP_SCLASS_NEXT_DROP] = "error-drop",
  },
};
VLIB_REGISTER_NODE (l2_gbp_sclass_2_id_node) = {
  .function = l2_gbp_sclass_2_id,
  .name = "l2-gbp-sclass-2-id",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_sclass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = GBP_SCLASS_N_NEXT,

  .next_nodes = {
    [GBP_SCLASS_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ip4_gbp_id_2_sclass_node) = {
  .function = ip4_gbp_id_2_sclass,
  .name = "ip4-gbp-id-2-sclass",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_sclass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = GBP_SCLASS_N_NEXT,

  .next_nodes = {
    [GBP_SCLASS_NEXT_DROP] = "error-drop",
  },
};
VLIB_REGISTER_NODE (ip4_gbp_sclass_2_id_node) = {
  .function = ip4_gbp_sclass_2_id,
  .name = "ip4-gbp-sclass-2-id",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_sclass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = GBP_SCLASS_N_NEXT,

  .next_nodes = {
    [GBP_SCLASS_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ip6_gbp_id_2_sclass_node) = {
  .function = ip6_gbp_id_2_sclass,
  .name = "ip6-gbp-id-2-sclass",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_sclass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = GBP_SCLASS_N_NEXT,

  .next_nodes = {
    [GBP_SCLASS_NEXT_DROP] = "error-drop",
  },
};
VLIB_REGISTER_NODE (ip6_gbp_sclass_2_id_node) = {
  .function = ip6_gbp_sclass_2_id,
  .name = "ip6-gbp-sclass-2-id",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_sclass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = GBP_SCLASS_N_NEXT,

  .next_nodes = {
    [GBP_SCLASS_NEXT_DROP] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (l2_gbp_id_2_sclass_node, l2_gbp_id_2_sclass);
VLIB_NODE_FUNCTION_MULTIARCH (l2_gbp_sclass_2_id_node, l2_gbp_sclass_2_id);

VLIB_NODE_FUNCTION_MULTIARCH (ip4_gbp_id_2_sclass_node, ip4_gbp_id_2_sclass);
VLIB_NODE_FUNCTION_MULTIARCH (ip4_gbp_sclass_2_id_node, ip4_gbp_sclass_2_id);
VLIB_NODE_FUNCTION_MULTIARCH (ip6_gbp_id_2_sclass_node, ip6_gbp_id_2_sclass);
VLIB_NODE_FUNCTION_MULTIARCH (ip6_gbp_sclass_2_id_node, ip6_gbp_sclass_2_id);

VNET_L2_IN_FEATURE_INIT_ALL(l2_gbp_sclass_2_id_feat,
  VNET_L2_FEATURE_INIT(
    .node_name = "l2-gbp-sclass-2-id",
    .runs_before = VNET_FEATURES ("l2-gbp-lpm-classify")), static);

VNET_FEATURE_INIT (ip4_gbp_sclass_2_id_feat, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-gbp-sclass-2-id",
  .runs_before = VNET_FEATURES ("gbp-learn-ip4"),
};
VNET_FEATURE_INIT (ip6_gbp_sclass_2_id_feat, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-gbp-sclass-2-id",
  .runs_before = VNET_FEATURES ("gbp-learn-ip6"),
};
VNET_FEATURE_INIT (ip4_gbp_id_2_sclass_feat, static) =
{
  .arc_name = "ip4-output",
  .node_name = "ip4-gbp-id-2-sclass",
};
VNET_FEATURE_INIT (ip6_gbp_id_2_sclass_feat, static) =
{
  .arc_name = "ip6-output",
  .node_name = "ip6-gbp-id-2-sclass",
};
/* *INDENT-ON* */

void
gbp_sclass_enable_l2 (u32 sw_if_index)
{
  vnet_l2_input_feature_enable_disable_all ("l2-gbp-sclass-2-id", sw_if_index,
					    1, 0, 0);
  l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_GBP_ID_2_SCLASS, 1);
}

void
gbp_sclass_disable_l2 (u32 sw_if_index)
{
  vnet_l2_input_feature_enable_disable_all ("l2-gbp-sclass-2-id", sw_if_index,
					    0, 0, 0);
  l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_GBP_ID_2_SCLASS, 0);
}

void
gbp_sclass_enable_ip (u32 sw_if_index)
{
  vnet_feature_enable_disable ("ip4-unicast",
			       "ip4-gbp-sclass-2-id", sw_if_index, 1, 0, 0);
  vnet_feature_enable_disable ("ip6-unicast",
			       "ip6-gbp-sclass-2-id", sw_if_index, 1, 0, 0);
  vnet_feature_enable_disable ("ip4-output",
			       "ip4-gbp-id-2-sclass", sw_if_index, 1, 0, 0);
  vnet_feature_enable_disable ("ip6-output",
			       "ip6-gbp-id-2-sclass", sw_if_index, 1, 0, 0);
}

void
gbp_sclass_disable_ip (u32 sw_if_index)
{
  vnet_feature_enable_disable ("ip4-unicast",
			       "ip4-gbp-sclass-2-id", sw_if_index, 0, 0, 0);
  vnet_feature_enable_disable ("ip6-unicast",
			       "ip6-gbp-sclass-2-id", sw_if_index, 0, 0, 0);
  vnet_feature_enable_disable ("ip4-output",
			       "ip4-gbp-id-2-sclass", sw_if_index, 0, 0, 0);
  vnet_feature_enable_disable ("ip6-output",
			       "ip6-gbp-id-2-sclass", sw_if_index, 0, 0, 0);
}

static clib_error_t *
gbp_sclass_init (vlib_main_t * vm)
{
  gbp_sclass_main_t *glm = &gbp_sclass_main;

  /* Initialize the feature next-node indices */
  feat_bitmap_init_next_nodes (vm,
			       l2_gbp_sclass_2_id_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       glm->gel_l2_input_feat_next);
  feat_bitmap_init_next_nodes (vm,
			       l2_gbp_id_2_sclass_node.index,
			       L2OUTPUT_N_FEAT,
			       l2output_get_feat_names (),
			       glm->gel_l2_output_feat_next);

  return (NULL);
}

VLIB_INIT_FUNCTION (gbp_sclass_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
