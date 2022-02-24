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

static_always_inline bool
qos_record_get_bits (vlib_buffer_t *b, qos_source_t qos_src,
		     dpo_proto_t dproto, int is_l2, qos_bits_t *qos0)
{
  const ip4_header_t *ip4_0;
  const ip6_header_t *ip6_0;

  if (is_l2)
    {
      u8 *l3h;
      u16 ethertype;

      l3h = (u8 *) vlib_buffer_get_current (b) + vnet_buffer (b)->l2.l2_len;
      ethertype = clib_net_to_host_u16 (*(u16 *) (l3h - 2));

      if (ethertype == ETHERNET_TYPE_IP4)
	dproto = DPO_PROTO_IP4;
      else if (ethertype == ETHERNET_TYPE_IP6)
	dproto = DPO_PROTO_IP6;
      else if (ethertype == ETHERNET_TYPE_MPLS)
	dproto = DPO_PROTO_MPLS;
      else
	return false;
    }

  if (DPO_PROTO_IP6 == dproto)
    {
      ip6_0 = vlib_buffer_get_current (b);
      *qos0 = ip6_traffic_class_network_order (ip6_0);
      b->flags |= VNET_BUFFER_F_IS_IP6;
    }
  else if (DPO_PROTO_IP4 == dproto)
    {
      ip4_0 = vlib_buffer_get_current (b);
      *qos0 = ip4_0->tos;
      b->flags |= VNET_BUFFER_F_IS_IP4;
    }
  else if (DPO_PROTO_ETHERNET == dproto)
    {
      const ethernet_vlan_header_t *vlan0;

      vlan0 = (vlib_buffer_get_current (b) - sizeof (ethernet_vlan_header_t));

      *qos0 = ethernet_vlan_header_get_priority_net_order (vlan0);
    }
  else if (DPO_PROTO_MPLS)
    {
      const mpls_unicast_header_t *mh;

      mh = vlib_buffer_get_current (b);
      *qos0 = vnet_mpls_uc_get_exp (mh->label_exp_s_ttl);
    }

  return (true);
}

#define vlib_prefetch_buffer_header2(b, type)                                 \
  CLIB_PREFETCH (b->second_half, 64, type)

static inline uword
qos_record_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		   vlib_frame_t *frame, qos_source_t qos_src,
		   dpo_proto_t dproto, int is_l2)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left, *from;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  b = bufs;
  next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 2)
    {
      qos_bits_t qos0 = 0, qos1 = 0;

      if (PREDICT_TRUE (n_left >= 4))
	{
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  vlib_prefetch_buffer_header2 (b[2], LOAD);
	  vlib_prefetch_buffer_data (b[2], LOAD);
	  vlib_prefetch_buffer_header (b[3], LOAD);
	  vlib_prefetch_buffer_header2 (b[3], LOAD);
	  vlib_prefetch_buffer_data (b[3], LOAD);
	}

      if (qos_record_get_bits (b[0], qos_src, dproto, is_l2, &qos0))
	b[0]->flags |= VNET_BUFFER_F_QOS_DATA_VALID;
      if (qos_record_get_bits (b[1], qos_src, dproto, is_l2, &qos1))
	b[1]->flags |= VNET_BUFFER_F_QOS_DATA_VALID;

      vnet_buffer2 (b[0])->qos.bits = qos0;
      vnet_buffer2 (b[0])->qos.source = qos_src;
      vnet_buffer2 (b[1])->qos.bits = qos1;
      vnet_buffer2 (b[1])->qos.source = qos_src;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	{
	  if (PREDICT_FALSE ((b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      qos_record_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->bits = qos0;
	    }
	  if (PREDICT_FALSE ((b[1]->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      qos_record_trace_t *t =
		vlib_add_trace (vm, node, b[1], sizeof (*t));
	      t->bits = qos1;
	    }
	}

      if (is_l2)
	{
	  next[0] = vnet_l2_feature_next (b[0], l2_qos_input_next[qos_src],
					  L2INPUT_FEAT_L2_IP_QOS_RECORD);
	  next[1] = vnet_l2_feature_next (b[1], l2_qos_input_next[qos_src],
					  L2INPUT_FEAT_L2_IP_QOS_RECORD);
	}
      else
	{
	  vnet_feature_next_u16 (&next[0], b[0]);
	  vnet_feature_next_u16 (&next[1], b[1]);
	}

      next += 2;
      b += 2;
      n_left -= 2;
    }

  while (n_left > 0)
    {
      qos_bits_t qos0 = 0;

      if (qos_record_get_bits (b[0], qos_src, dproto, is_l2, &qos0))
	b[0]->flags |= VNET_BUFFER_F_QOS_DATA_VALID;

      vnet_buffer2 (b[0])->qos.bits = qos0;
      vnet_buffer2 (b[0])->qos.source = qos_src;

      if (PREDICT_FALSE ((b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  qos_record_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->bits = qos0;
	}

      if (is_l2)
	{
	  next[0] = vnet_l2_feature_next (b[0], l2_qos_input_next[qos_src],
					  L2INPUT_FEAT_L2_IP_QOS_RECORD);
	}
      else
	vnet_feature_next_u16 (&next[0], b[0]);

      next += 1;
      b += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

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
