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

#include <vnet/qos/qos_record.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/feature/feature.h>
#include <vnet/qos/qos_types.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>

extern u8 *qos_record_configs[QOS_N_SOURCES];
extern u32 l2_qos_input_next[QOS_N_SOURCES][32];

/**
 * per-packet trace data
 */
typedef struct qos_record_trace_t_
{
  /* per-pkt trace data */
  qos_bits_t bits;
} qos_record_trace_t;

/* packet trace format function */
static u8 *
format_qos_record_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  qos_record_trace_t *t = va_arg (*args, qos_record_trace_t *);

  s = format (s, "qos:%d", t->bits);

  return s;
}

static inline uword
qos_record_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame,
		   qos_source_t qos_src, dpo_proto_t dproto, int is_l2)
{
  u32 n_left_from, *from, *to_next, next_index;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  ip4_header_t *ip4_0;
	  ip6_header_t *ip6_0;
	  vlib_buffer_t *b0;
	  u32 next0, bi0;
	  qos_bits_t qos0;
	  u8 l2_len;

	  next0 = 0;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  if (is_l2)
	    {
	      l2_len = vnet_buffer (b0)->l2.l2_len;
	      u8 *l3h;
	      u16 ethertype;

	      vlib_buffer_advance (b0, l2_len);

	      l3h = vlib_buffer_get_current (b0);
	      ethertype = clib_net_to_host_u16 (*(u16 *) (l3h - 2));

	      if (ethertype == ETHERNET_TYPE_IP4)
		dproto = DPO_PROTO_IP4;
	      else if (ethertype == ETHERNET_TYPE_IP6)
		dproto = DPO_PROTO_IP6;
	      else if (ethertype == ETHERNET_TYPE_MPLS)
		dproto = DPO_PROTO_MPLS;
	      else
		goto non_ip;
	    }

	  if (DPO_PROTO_IP6 == dproto)
	    {
	      ip6_0 = vlib_buffer_get_current (b0);
	      qos0 = ip6_traffic_class_network_order (ip6_0);
	    }
	  else if (DPO_PROTO_IP4 == dproto)
	    {
	      ip4_0 = vlib_buffer_get_current (b0);
	      qos0 = ip4_0->tos;
	    }
	  else if (DPO_PROTO_ETHERNET == dproto)
	    {
	      ethernet_vlan_header_t *vlan0;

	      vlan0 = (vlib_buffer_get_current (b0) -
		       sizeof (ethernet_vlan_header_t));

	      qos0 = ethernet_vlan_header_get_priority_net_order (vlan0);
	    }
	  else if (DPO_PROTO_MPLS)
	    {
	      mpls_unicast_header_t *mh;

	      mh = vlib_buffer_get_current (b0);
	      qos0 = vnet_mpls_uc_get_exp (mh->label_exp_s_ttl);
	    }

	  vnet_buffer2 (b0)->qos.bits = qos0;
	  vnet_buffer2 (b0)->qos.source = qos_src;
	  b0->flags |= VNET_BUFFER_F_QOS_DATA_VALID;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      qos_record_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->bits = qos0;
	    }

	non_ip:
	  if (is_l2)
	    {
	      vlib_buffer_advance (b0, -l2_len);
	      next0 = vnet_l2_feature_next (b0,
					    l2_qos_input_next[qos_src],
					    L2INPUT_FEAT_L2_IP_QOS_RECORD);
	    }
	  else
	    vnet_feature_next (&next0, b0);

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}


VLIB_NODE_FN (ip4_qos_record_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return (qos_record_inline (vm, node, frame, QOS_SOURCE_IP,
			     DPO_PROTO_IP4, 0));
}

VLIB_NODE_FN (ip6_qos_record_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return (qos_record_inline (vm, node, frame, QOS_SOURCE_IP,
			     DPO_PROTO_IP6, 0));
}

VLIB_NODE_FN (mpls_qos_record_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return (qos_record_inline (vm, node, frame, QOS_SOURCE_MPLS,
			     DPO_PROTO_MPLS, 0));
}

VLIB_NODE_FN (vlan_ip4_qos_record_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  return (qos_record_inline (vm, node, frame, QOS_SOURCE_VLAN,
			     DPO_PROTO_ETHERNET, 0));
}

VLIB_NODE_FN (vlan_ip6_qos_record_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  return (qos_record_inline (vm, node, frame, QOS_SOURCE_VLAN,
			     DPO_PROTO_ETHERNET, 0));
}

VLIB_NODE_FN (vlan_mpls_qos_record_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  return (qos_record_inline (vm, node, frame, QOS_SOURCE_VLAN,
			     DPO_PROTO_ETHERNET, 0));
}

VLIB_NODE_FN (l2_ip_qos_record_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return (qos_record_inline (vm, node, frame, QOS_SOURCE_VLAN, 0, 1));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_qos_record_node) = {
  .name = "ip4-qos-record",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_record_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "ip4-drop",
  },
};

VNET_FEATURE_INIT (ip4_qos_record_node, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "ip4-qos-record",
};
VNET_FEATURE_INIT (ip4m_qos_record_node, static) = {
    .arc_name = "ip4-multicast",
    .node_name = "ip4-qos-record",
};

VLIB_REGISTER_NODE (ip6_qos_record_node) = {
  .name = "ip6-qos-record",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_record_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "ip6-drop",
  },
};

VNET_FEATURE_INIT (ip6_qos_record_node, static) = {
    .arc_name = "ip6-unicast",
    .node_name = "ip6-qos-record",
};
VNET_FEATURE_INIT (ip6m_qos_record_node, static) = {
    .arc_name = "ip6-multicast",
    .node_name = "ip6-qos-record",
};

VLIB_REGISTER_NODE (mpls_qos_record_node) = {
  .name = "mpls-qos-record",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_record_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "mpls-drop",
  },
};

VNET_FEATURE_INIT (mpls_qos_record_node, static) = {
    .arc_name = "mpls-input",
    .node_name = "mpls-qos-record",
};

VLIB_REGISTER_NODE (vlan_mpls_qos_record_node) = {
  .name = "vlan-mpls-qos-record",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_record_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "mpls-drop",
  },
};

VNET_FEATURE_INIT (vlan_mpls_qos_record_node, static) = {
    .arc_name = "mpls-input",
    .node_name = "vlan-mpls-qos-record",
    .runs_before = VNET_FEATURES ("mpls-qos-record"),
};

VLIB_REGISTER_NODE (vlan_ip4_qos_record_node) = {
  .name = "vlan-ip4-qos-record",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_record_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "ip4-drop",
  },
};

VNET_FEATURE_INIT (vlan_ip4_qos_record_node, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "vlan-ip4-qos-record",
    .runs_before = VNET_FEATURES ("ip4-qos-record"),
};
VNET_FEATURE_INIT (vlan_ip4m_qos_record_node, static) = {
    .arc_name = "ip4-multicast",
    .node_name = "vlan-ip4-qos-record",
    .runs_before = VNET_FEATURES ("ip4-qos-record"),
};

VLIB_REGISTER_NODE (vlan_ip6_qos_record_node) = {
  .name = "vlan-ip6-qos-record",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_record_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "ip6-drop",
  },
};

VNET_FEATURE_INIT (vlan_ip6_qos_record_node, static) = {
    .arc_name = "ip6-unicast",
    .node_name = "vlan-ip6-qos-record",
    .runs_before = VNET_FEATURES ("ip6-qos-record"),
};
VNET_FEATURE_INIT (vlan_ip6m_qos_record_node, static) = {
    .arc_name = "ip6-multicast",
    .node_name = "vlan-ip6-qos-record",
    .runs_before = VNET_FEATURES ("ip6-qos-record"),
};

VLIB_REGISTER_NODE (l2_ip_qos_record_node) = {
  .name = "l2-ip-qos-record",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_record_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  /* Consider adding error "no IP after L2, no recording" */
  .next_nodes = {
    [0] = "error-drop",
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
