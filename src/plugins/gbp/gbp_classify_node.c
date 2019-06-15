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
#include <plugins/gbp/gbp_classify.h>
#include <plugins/gbp/gbp_policy_dpo.h>
#include <plugins/gbp/gbp_ext_itf.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/fib/fib_table.h>
#include <vnet/vxlan-gbp/vxlan_gbp_packet.h>
#include <vnet/ethernet/arp_packet.h>

/**
 * per-packet trace data
 */
typedef struct gbp_classify_trace_t_
{
  /* per-pkt trace data */
  sclass_t sclass;
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
	  u32 next0, bi0, sw_if_index0;
	  const gbp_endpoint_t *ge0;
	  vlib_buffer_t *b0;
	  sclass_t sclass0;

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
	      sclass0 = SCLASS_INVALID;
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
		sclass0 = ge0->ge_fwd.gef_sclass;
	      else
		sclass0 = SCLASS_INVALID;
	    }

	  vnet_buffer2 (b0)->gbp.sclass = sclass0;

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      gbp_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
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

VLIB_NODE_FN (gbp_src_classify_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return (gbp_classify_inline (vm, node, frame,
			       GBP_SRC_CLASSIFY_PORT, DPO_PROTO_ETHERNET));
}

VLIB_NODE_FN (gbp_null_classify_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * frame)
{
  return (gbp_classify_inline (vm, node, frame,
			       GBP_SRC_CLASSIFY_NULL, DPO_PROTO_ETHERNET));
}

VLIB_NODE_FN (gbp_ip4_src_classify_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return (gbp_classify_inline (vm, node, frame,
			       GBP_SRC_CLASSIFY_PORT, DPO_PROTO_IP4));
}

VLIB_NODE_FN (gbp_ip6_src_classify_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
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

  s = format (s, "sclass:%d", t->sclass);

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_null_classify_node) = {
  .name = "gbp-null-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (gbp_src_classify_node) = {
  .name = "gbp-src-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (gbp_ip4_src_classify_node) = {
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

VLIB_REGISTER_NODE (gbp_ip6_src_classify_node) = {
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

always_inline void
gbp_classify_get_src_ip4_address (const ethernet_header_t * eh0,
				  const ip4_address_t ** ip4)
{
  const ip4_header_t *iph4;

  iph4 = (ip4_header_t *) (eh0 + 1);
  *ip4 = &iph4->src_address;
}

always_inline void
gbp_classify_get_src_ip6_address (const ethernet_header_t * eh0,
				  const ip6_address_t ** ip6)
{
  const ip6_header_t *iph6;

  iph6 = (ip6_header_t *) (eh0 + 1);
  *ip6 = &iph6->src_address;
}

always_inline void
gbp_classify_get_src_ip_address (const ethernet_header_t * eh0,
				 const ip4_address_t ** ip4,
				 const ip6_address_t ** ip6)
{
  u16 etype = clib_net_to_host_u16 (eh0->type);

  switch (etype)
    {
    case ETHERNET_TYPE_IP4:
      gbp_classify_get_src_ip4_address (eh0, ip4);
      break;
    case ETHERNET_TYPE_IP6:
      gbp_classify_get_src_ip6_address (eh0, ip6);
      break;
    case ETHERNET_TYPE_VLAN:
      {
	ethernet_vlan_header_t *vh0;

	vh0 = (ethernet_vlan_header_t *) (eh0 + 1);

	switch (clib_net_to_host_u16 (vh0->type))
	  {
	  case ETHERNET_TYPE_IP4:
	    {
	      gbp_classify_get_src_ip4_address (eh0, ip4);
	      break;
	  case ETHERNET_TYPE_IP6:
	      gbp_classify_get_src_ip6_address (eh0, ip6);
	      break;
	    }
	  }
	break;
      }
    case ETHERNET_TYPE_ARP:
      {
	const ethernet_arp_header_t *ea0;

	ea0 = (ethernet_arp_header_t *) (eh0 + 1);

	*ip4 = &ea0->ip4_over_ethernet[0].ip4;
	break;
      }
    default:
      break;
    }
}

/**
 * per-packet trace data
 */
typedef struct gbp_lpm_classify_trace_t_
{
  sclass_t sclass;
  index_t lbi;
  ip46_address_t src;
} gbp_lpm_classify_trace_t;

/* packet trace format function */
static u8 *
format_gbp_lpm_classify_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_lpm_classify_trace_t *t = va_arg (*args, gbp_lpm_classify_trace_t *);

  s = format (s, "sclass:%d lb:%d src:%U",
	      t->sclass, t->lbi, format_ip46_address, &t->src, IP46_TYPE_ANY);

  return s;
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
	  const ethernet_header_t *eh0;
	  const gbp_policy_dpo_t *gpd0;
	  const ip4_address_t *ip4_0;
	  const ip6_address_t *ip6_0;
	  const gbp_endpoint_t *ge0;
	  const gbp_recirc_t *gr0;
	  const dpo_id_t *dpo0;
	  load_balance_t *lb0;
	  vlib_buffer_t *b0;
	  sclass_t sclass0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  ip4_0 = NULL;
	  ip6_0 = NULL;
	  next0 = GPB_LPM_CLASSIFY_DROP;

	  lbi0 = ~0;
	  eh0 = NULL;
	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  vnet_buffer2 (b0)->gbp.flags = VXLAN_GBP_GPFLAGS_NONE;

	  if (DPO_PROTO_IP4 == dproto)
	    ip4_0 =
	      &((ip4_header_t *) vlib_buffer_get_current (b0))->src_address;
	  else if (DPO_PROTO_IP6 == dproto)
	    ip6_0 =
	      &((ip6_header_t *) vlib_buffer_get_current (b0))->src_address;
	  else if (DPO_PROTO_ETHERNET == dproto)
	    {
	      eh0 = vlib_buffer_get_current (b0);
	      gbp_classify_get_src_ip_address (eh0, &ip4_0, &ip6_0);
	    }

	  if (is_recirc)
	    {
	      gr0 = gbp_recirc_get (sw_if_index0);
	      fib_index0 = gr0->gr_fib_index[dproto];
	      ge0 = NULL;

	      vnet_feature_next (&next0, b0);
	    }
	  else
	    {
	      if (NULL == eh0)
		{
		  /* packet should be l2 */
		  sclass0 = SCLASS_INVALID;
		  goto trace;
		}

	      ge0 = gbp_endpoint_find_mac (eh0->src_address,
					   vnet_buffer (b0)->l2.bd_index);

	      if (NULL == ge0)
		{
		  /* packet must have come from an EP's mac */
		  sclass0 = SCLASS_INVALID;
		  goto trace;
		}

	      fib_index0 = ge0->ge_fwd.gef_fib_index;

	      if (~0 == fib_index0)
		{
		  sclass0 = SCLASS_INVALID;
		  goto trace;
		}

	      if (ip4_0)
		{
		  ge0 = gbp_endpoint_find_ip4 (ip4_0, fib_index0);
		}
	      else if (ip6_0)
		{
		  ge0 = gbp_endpoint_find_ip6 (ip6_0, fib_index0);
		}

	      next0 = vnet_l2_feature_next
		(b0, gscm->l2_input_feat_next[GBP_SRC_CLASSIFY_LPM],
		 L2INPUT_FEAT_GBP_LPM_CLASSIFY);

	      /*
	       * if we found the EP by IP lookup, it must be from the EP
	       * not a network behind it
	       */
	      if (NULL != ge0)
		{
		  sclass0 = ge0->ge_fwd.gef_sclass;
		  goto trace;
		}
	    }

	  if (ip4_0)
	    {
	      lbi0 = ip4_fib_forwarding_lookup (fib_index0, ip4_0);
	    }
	  else if (ip6_0)
	    {
	      lbi0 =
		ip6_fib_table_fwding_lookup (&ip6_main, fib_index0, ip6_0);
	    }
	  else
	    {
	      /* not IP so no LPM classify possible */
	      sclass0 = SCLASS_INVALID;
	      next0 = GPB_LPM_CLASSIFY_DROP;
	      goto trace;
	    }
	  lb0 = load_balance_get (lbi0);
	  dpo0 = load_balance_get_bucket_i (lb0, 0);

	  /* all packets from an external network should not be learned by the
	   * reciever. so set the Do-not-learn bit here */
	  vnet_buffer2 (b0)->gbp.flags = VXLAN_GBP_GPFLAGS_D;

	  if (gbp_policy_dpo_type == dpo0->dpoi_type)
	    {
	      gpd0 = gbp_policy_dpo_get (dpo0->dpoi_index);
	      sclass0 = gpd0->gpd_sclass;
	    }
	  else
	    {
	      /* could not classify => drop */
	      sclass0 = SCLASS_INVALID;
	      goto trace;
	    }

	trace:
	  vnet_buffer2 (b0)->gbp.sclass = sclass0;

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      gbp_lpm_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sclass = sclass0;
	      t->lbi = lbi0;
	      if (ip4_0)
		t->src.ip4 = *ip4_0;
	      if (ip6_0)
		t->src.ip6 = *ip6_0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (gbp_ip4_lpm_classify_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return (gbp_lpm_classify_inline (vm, node, frame, DPO_PROTO_IP4, 1));
}

VLIB_NODE_FN (gbp_ip6_lpm_classify_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return (gbp_lpm_classify_inline (vm, node, frame, DPO_PROTO_IP6, 1));
}

VLIB_NODE_FN (gbp_l2_lpm_classify_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  return (gbp_lpm_classify_inline (vm, node, frame, DPO_PROTO_ETHERNET, 0));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_ip4_lpm_classify_node) = {
  .name = "ip4-gbp-lpm-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_lpm_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,
  .next_nodes = {
    [GPB_LPM_CLASSIFY_DROP] = "ip4-drop"
  },
};

VLIB_REGISTER_NODE (gbp_ip6_lpm_classify_node) = {
  .name = "ip6-gbp-lpm-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_lpm_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,
  .next_nodes = {
    [GPB_LPM_CLASSIFY_DROP] = "ip6-drop"
  },
};

VLIB_REGISTER_NODE (gbp_l2_lpm_classify_node) = {
  .name = "l2-gbp-lpm-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_lpm_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,
  .next_nodes = {
    [GPB_LPM_CLASSIFY_DROP] = "error-drop"
  },
};

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
