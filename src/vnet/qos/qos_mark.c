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

#include <vnet/ip/ip.h>
#include <vnet/feature/feature.h>
#include <vnet/qos/qos_egress_map.h>
#include <vnet/qos/qos_mark.h>

/**
 * per-interface vector of which MAP is used by which interface
 * for each output source
 */
index_t *qos_mark_configs[QOS_N_SOURCES];

void
qos_mark_ip_enable_disable (u32 sw_if_index, u8 enable)
{
  vnet_feature_enable_disable ("ip6-output", "ip6-qos-mark",
			       sw_if_index, enable, NULL, 0);
  vnet_feature_enable_disable ("ip4-output", "ip4-qos-mark",
			       sw_if_index, enable, NULL, 0);
}

void
qos_mark_vlan_enable_disable (u32 sw_if_index, u8 enable)
{
  vnet_feature_enable_disable ("interface-output", "vlan-qos-mark",
			       sw_if_index, enable, NULL, 0);
}

void
qos_mark_mpls_enable_disable (u32 sw_if_index, u8 enable)
{
  vnet_feature_enable_disable ("mpls-output", "mpls-qos-mark",
			       sw_if_index, enable, NULL, 0);
}

static void
qos_egress_map_feature_config (u32 sw_if_index, qos_source_t qs, u8 enable)
{
  switch (qs)
    {
    case QOS_SOURCE_EXT:
      ASSERT (0);
      break;
    case QOS_SOURCE_VLAN:
      qos_mark_vlan_enable_disable (sw_if_index, enable);
      break;
    case QOS_SOURCE_MPLS:
      qos_mark_mpls_enable_disable (sw_if_index, enable);
      break;
    case QOS_SOURCE_IP:
      qos_mark_ip_enable_disable (sw_if_index, enable);
      break;
    }
}

always_inline qos_egress_map_t *
qos_egress_map_interface (u32 sw_if_index, qos_source_t output_source)
{
  ASSERT (vec_len (qos_mark_configs[output_source]) > sw_if_index);

  return pool_elt_at_index (qem_pool,
			    qos_mark_configs[output_source][sw_if_index]);
}

/**
 * per-packet trace data
 */
typedef struct qos_mark_trace_t_
{
  /* per-pkt trace data */
  qos_bits_t bits;
  qos_source_t input;
  u32 used;
} qos_mark_trace_t;

static inline uword
qos_mark_inline (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * frame, qos_source_t output_source, int is_ip6)
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
	  qos_source_t input_source0;
	  ethernet_vlan_header_t *vlan0;
	  u32 sw_if_index0, next0, bi0;
	  qos_egress_map_t *qem0;
	  ip4_header_t *ip4_0;
	  ip6_header_t *ip6_0;
	  vlib_buffer_t *b0;
	  qos_bits_t qos0;
	  u8 *mpls_bytes_0;
	  u8 eos0;

	  next0 = 0;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  input_source0 = vnet_buffer2 (b0)->qos.source;

	  qem0 = qos_egress_map_interface (sw_if_index0, output_source);
	  qos0 = qem0->qem_output[input_source0][vnet_buffer2 (b0)->qos.bits];

	  if (PREDICT_TRUE (b0->flags & VNET_BUFFER_F_QOS_DATA_VALID))
	    {
	      /* there is a source of QoS recording for this packet */
	      if (QOS_SOURCE_IP == output_source)
		{
		  if (is_ip6)
		    {
		      ip6_0 = (vlib_buffer_get_current (b0) +
			       vnet_buffer (b0)->ip.save_rewrite_length);

		      ip6_set_traffic_class_network_order (ip6_0, qos0);
		    }
		  else
		    {
		      ip4_0 = (vlib_buffer_get_current (b0) +
			       vnet_buffer (b0)->ip.save_rewrite_length);
		      if (PREDICT_FALSE (qos0 != ip4_0->tos))
			{
			  ip4_0->tos = qos0;
			  ip4_0->checksum = ip4_header_checksum (ip4_0);
			}
		    }
		}
	      else if (QOS_SOURCE_MPLS == output_source)
		{
		  mpls_bytes_0 = (vlib_buffer_get_current (b0) +
				  vnet_buffer (b0)->mpls.save_rewrite_length);

		  /* apply to all the labels in the stack */
		  do
		    {
		      /* clear out the old COS bts */
		      mpls_bytes_0[2] &= 0xf1;
		      /* OR in 3 bits of the mapped value */
		      mpls_bytes_0[2] |= (qos0 & 0x7) << 1;
		      eos0 = mpls_bytes_0[2] & 0x1;
		      mpls_bytes_0 += 4;
		    }
		  while (!eos0);
		}
	      else if (QOS_SOURCE_VLAN == output_source)
		{
		  vlan0 = (vlib_buffer_get_current (b0) +
			   sizeof (ethernet_header_t));

		  ethernet_vlan_header_set_priority_net_order (vlan0, qos0);
		}
	    }
	  vnet_feature_next (sw_if_index0, &next0, b0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      qos_mark_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->bits = qos0;
	      t->input = input_source0;
	      t->used = (b0->flags & VNET_BUFFER_F_QOS_DATA_VALID);
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* packet trace format function */
static u8 *
format_qos_mark_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  qos_mark_trace_t *t = va_arg (*args, qos_mark_trace_t *);

  s = format (s, "source:%U qos:%d used:%s",
	      format_qos_source, t->input, t->bits, (t->used ? "yes" : "no"));

  return s;
}

static inline uword
ip4_qos_mark (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  return (qos_mark_inline (vm, node, frame, QOS_SOURCE_IP, 0));
}

static inline uword
ip6_qos_mark (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  return (qos_mark_inline (vm, node, frame, QOS_SOURCE_IP, 1));
}

static inline uword
mpls_qos_mark (vlib_main_t * vm, vlib_node_runtime_t * node,
	       vlib_frame_t * frame)
{
  return (qos_mark_inline (vm, node, frame, QOS_SOURCE_MPLS, 0));
}

static inline uword
vlan_qos_mark (vlib_main_t * vm, vlib_node_runtime_t * node,
	       vlib_frame_t * frame)
{
  return (qos_mark_inline (vm, node, frame, QOS_SOURCE_VLAN, 0));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_qos_mark_node) = {
  .function = ip4_qos_mark,
  .name = "ip4-qos-mark",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_mark_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "ip4-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_qos_mark_node, ip4_qos_mark);

VNET_FEATURE_INIT (ip4_qos_mark_node, static) = {
    .arc_name = "ip4-output",
    .node_name = "ip4-qos-mark",
};

VLIB_REGISTER_NODE (ip6_qos_mark_node) = {
  .function = ip6_qos_mark,
  .name = "ip6-qos-mark",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_mark_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "ip6-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_qos_mark_node, ip6_qos_mark);

VNET_FEATURE_INIT (ip6_qos_mark_node, static) = {
    .arc_name = "ip6-output",
    .node_name = "ip6-qos-mark",
};

VLIB_REGISTER_NODE (mpls_qos_mark_node) = {
  .function = mpls_qos_mark,
  .name = "mpls-qos-mark",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_mark_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "mpls-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (mpls_qos_mark_node, mpls_qos_mark);

VNET_FEATURE_INIT (mpls_qos_mark_node, static) = {
    .arc_name = "mpls-output",
    .node_name = "mpls-qos-mark",
};
VLIB_REGISTER_NODE (vlan_qos_mark_node) = {
  .function = vlan_qos_mark,
  .name = "vlan-qos-mark",
  .vector_size = sizeof (u32),
  .format_trace = format_qos_mark_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = 0,
  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (vlan_qos_mark_node, vlan_qos_mark);

VNET_FEATURE_INIT (vlan_qos_mark_node, static) = {
    .arc_name = "interface-output",
    .node_name = "vlan-qos-mark",
};
/* *INDENT-ON* */

int
qos_mark_enable (u32 sw_if_index,
		 qos_source_t output_source, qos_egress_map_id_t mid)
{
  index_t qemi;

  vec_validate_init_empty (qos_mark_configs[output_source],
			   sw_if_index, INDEX_INVALID);

  qemi = qos_egress_map_find (mid);

  if (INDEX_INVALID == qemi)
    return VNET_API_ERROR_NO_SUCH_TABLE;

  if (INDEX_INVALID == qos_mark_configs[output_source][sw_if_index])
    {
      qos_egress_map_feature_config (sw_if_index, output_source, 1);
    }

  qos_mark_configs[output_source][sw_if_index] = qemi;

  return (0);
}

int
qos_mark_disable (u32 sw_if_index, qos_source_t output_source)
{
  if (vec_len (qos_mark_configs[output_source]) < sw_if_index)
    return VNET_API_ERROR_NO_MATCHING_INTERFACE;
  if (INDEX_INVALID == qos_mark_configs[output_source][sw_if_index])
    return VNET_API_ERROR_VALUE_EXIST;

  if (INDEX_INVALID != qos_mark_configs[output_source][sw_if_index])
    {
      qos_egress_map_feature_config (sw_if_index, output_source, 0);
    }

  qos_mark_configs[output_source][sw_if_index] = INDEX_INVALID;

  return (0);
}

static clib_error_t *
qos_mark_cli (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  qos_egress_map_id_t map_id;
  u32 sw_if_index, qs;
  vnet_main_t *vnm;
  int rv, enable;

  vnm = vnet_get_main ();
  map_id = ~0;
  qs = 0xff;
  enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "id %d", &map_id))
	;
      else if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "%U", unformat_qos_source, &qs))
	;
      else if (unformat (input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");
  if (0xff == qs)
    return clib_error_return (0, "output location must be specified");

  if (enable)
    rv = qos_mark_enable (sw_if_index, qs, map_id);
  else
    rv = qos_mark_disable (sw_if_index, qs);

  if (0 == rv)
    return (NULL);

  return clib_error_return (0, "Failed to map interface");
}

/*?
 * Apply a QoS egress mapping table to an interface for QoS marking packets
 * at the given output protocol.
 *
 * @cliexpar
 * @cliexcmd{qos egress interface GigEthernet0/9/0 id 0 output ip}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_egress_map_interface_command, static) = {
  .path = "qos mark",
  .short_help = "qos mark <SOURCE> <INTERFACE> id <MAP>",
  .function = qos_mark_cli,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*
*/
