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
#include <plugins/gbp/gbp_policy_dpo.h>
#include <plugins/gbp/gbp_ext_itf.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/fib/fib_table.h>
#include <vnet/vxlan-gbp/vxlan_gbp_packet.h>

typedef enum gbp_src_classify_type_t_
{
  GBP_SRC_CLASSIFY_NULL,
  GBP_SRC_CLASSIFY_PORT,
  GBP_SRC_CLASSIFY_LPM,
} gbp_src_classify_type_t;

#define GBP_SRC_N_CLASSIFY (GBP_SRC_CLASSIFY_LPM + 1)

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
		src_epg = ge0->ge_fwd.gef_epg_id;
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

/* *INDENT-ON* */

typedef enum gbp_lpm_classify_next_t_
{
  GPB_LPM_CLASSIFY_DROP,
} gbp_lpm_classify_next_t;

always_inline dpo_proto_t
ethertype_to_dpo_proto (const ethernet_header_t * eh0)
{
  u16 etype = clib_net_to_host_u16 (eh0->type);

  switch (etype)
    {
    case ETHERNET_TYPE_IP4:
      return (DPO_PROTO_IP4);
    case ETHERNET_TYPE_IP6:
      return (DPO_PROTO_IP6);
    case ETHERNET_TYPE_VLAN:
      {
	ethernet_vlan_header_t *vh0;

	vh0 = (ethernet_vlan_header_t *) (eh0 + 1);

	switch (clib_net_to_host_u16 (vh0->type))
	  {
	  case ETHERNET_TYPE_IP4:
	    return (DPO_PROTO_IP4);
	  case ETHERNET_TYPE_IP6:
	    return (DPO_PROTO_IP6);
	  }
      }
    }

  return (DPO_PROTO_NONE);
}

/*
 * Determine the SRC EPG from a LPM
 */
always_inline uword
gbp_lpm_classify_inline (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * frame,
			 dpo_proto_t dproto, u8 is_recirc)
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
	  u32 bi0, sw_if_index0, fib_index0, lbi0;
	  gbp_lpm_classify_next_t next0;
	  const gbp_policy_dpo_t *gpd0;
	  const gbp_ext_itf_t *gx0;
	  const gbp_recirc_t *gr0;
	  const dpo_id_t *dpo0;
	  load_balance_t *lb0;
	  ip4_header_t *ip4_0 = NULL;
	  ip6_header_t *ip6_0 = NULL;
	  vlib_buffer_t *b0;
	  epg_id_t src_epg0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = GPB_LPM_CLASSIFY_DROP;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  vnet_buffer2 (b0)->gbp.flags = VXLAN_GBP_GPFLAGS_NONE;

	  if (DPO_PROTO_IP4 == dproto)
	    ip4_0 = vlib_buffer_get_current (b0);
	  else if (DPO_PROTO_IP6 == dproto)
	    ip6_0 = vlib_buffer_get_current (b0);
	  else if (DPO_PROTO_ETHERNET == dproto)
	    {
	      const ethernet_header_t *eh0;

	      eh0 = vlib_buffer_get_current (b0);

	      dproto = ethertype_to_dpo_proto (eh0);

	      switch (dproto)
		{
		case DPO_PROTO_IP4:
		  ip4_0 = (vlib_buffer_get_current (b0) +
			   vnet_buffer (b0)->l2.l2_len);
		  break;
		case DPO_PROTO_IP6:
		  ip6_0 = (vlib_buffer_get_current (b0) +
			   vnet_buffer (b0)->l2.l2_len);
		  break;
		default:
		  /* not IP so no LPM classify possible */
		  src_epg0 = EPG_INVALID;
		  goto trace;
		}
	    }

	  if (is_recirc)
	    {
	      gr0 = gbp_recirc_get (sw_if_index0);
	      fib_index0 = gr0->gr_fib_index[dproto];

	      vnet_feature_next (&next0, b0);
	    }
	  else
	    {
	      gx0 = gbp_ext_itf_get (sw_if_index0);
	      fib_index0 = gx0->gx_fib_index[dproto];

	      next0 = vnet_l2_feature_next
		(b0, gscm->l2_input_feat_next[GBP_SRC_CLASSIFY_LPM],
		 L2INPUT_FEAT_GBP_LPM_CLASSIFY);
	    }

	  if (DPO_PROTO_IP4 == dproto)
	    {
	      lbi0 = ip4_fib_forwarding_lookup (fib_index0,
						&ip4_0->src_address);
	    }
	  else if (DPO_PROTO_IP6 == dproto)
	    {
	      lbi0 = ip6_fib_table_fwding_lookup (&ip6_main, fib_index0,
						  &ip6_0->src_address);
	    }
	  else
	    {
	      /* not IP so no LPM classify possible */
	      src_epg0 = EPG_INVALID;
	      goto trace;
	    }
	  lb0 = load_balance_get (lbi0);
	  dpo0 = load_balance_get_bucket_i (lb0, 0);

	  if (gbp_policy_dpo_type == dpo0->dpoi_type)
	    {
	      gpd0 = gbp_policy_dpo_get (dpo0->dpoi_index);
	      src_epg0 = gpd0->gpd_epg;
	    }
	  else
	    {
	      /* could not classify => drop */
	      src_epg0 = EPG_INVALID;
	      next0 = GPB_LPM_CLASSIFY_DROP;
	    }

	trace:
	  vnet_buffer2 (b0)->gbp.src_epg = src_epg0;

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      gbp_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->src_epg = src_epg0;
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
gbp_ip4_lpm_classify (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_lpm_classify_inline (vm, node, frame, DPO_PROTO_IP4, 1));
}

static uword
gbp_ip6_lpm_classify (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_lpm_classify_inline (vm, node, frame, DPO_PROTO_IP6, 1));
}

static uword
gbp_l2_lpm_classify (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (gbp_lpm_classify_inline (vm, node, frame, DPO_PROTO_ETHERNET, 0));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_ip4_lpm_classify_node) = {
  .function = gbp_ip4_lpm_classify,
  .name = "ip4-gbp-lpm-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,
  .next_nodes = {
    [GPB_LPM_CLASSIFY_DROP] = "ip4-drop"
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_ip4_lpm_classify_node, gbp_ip4_lpm_classify);

VLIB_REGISTER_NODE (gbp_ip6_lpm_classify_node) = {
  .function = gbp_ip6_lpm_classify,
  .name = "ip6-gbp-lpm-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,
  .next_nodes = {
    [GPB_LPM_CLASSIFY_DROP] = "ip6-drop"
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_ip6_lpm_classify_node, gbp_ip6_lpm_classify);

VLIB_REGISTER_NODE (gbp_l2_lpm_classify_node) = {
  .function = gbp_l2_lpm_classify,
  .name = "l2-gbp-lpm-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,
  .next_nodes = {
    [GPB_LPM_CLASSIFY_DROP] = "error-drop"
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gbp_l2_lpm_classify_node, gbp_l2_lpm_classify);

VNET_FEATURE_INIT (gbp_ip4_lpm_classify_feat_node, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-gbp-lpm-classify",
  .runs_before = VNET_FEATURES ("nat44-out2in"),
};
VNET_FEATURE_INIT (gbp_ip6_lpm_classify_feat_node, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-gbp-lpm-classify",
  .runs_before = VNET_FEATURES ("nat66-out2in"),
};

/* *INDENT-ON* */

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
  feat_bitmap_init_next_nodes (vm,
			       gbp_l2_lpm_classify_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       em->l2_input_feat_next[GBP_SRC_CLASSIFY_LPM]);

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
