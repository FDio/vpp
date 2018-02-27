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

/**
 * Per-interface, per-protocol vector of feature on/off configurations
 */
static u8 *qos_record_configs[QOS_N_SOURCES];

static void
qos_record_feature_config (u32 sw_if_index,
			   qos_source_t input_source, u8 enable)
{
  switch (input_source)
    {
    case QOS_SOURCE_IP:
      vnet_feature_enable_disable ("ip6-unicast", "ip6-qos-record",
				   sw_if_index, enable, NULL, 0);
      vnet_feature_enable_disable ("ip6-multicast", "ip6-qos-record",
				   sw_if_index, enable, NULL, 0);
      vnet_feature_enable_disable ("ip4-unicast", "ip4-qos-record",
				   sw_if_index, enable, NULL, 0);
      vnet_feature_enable_disable ("ip4-multicast", "ip4-qos-record",
				   sw_if_index, enable, NULL, 0);
      break;
    case QOS_SOURCE_MPLS:
    case QOS_SOURCE_VLAN:
    case QOS_SOURCE_EXT:
      // not implemented yet
      break;
    }
}

int
qos_record_enable (u32 sw_if_index, qos_source_t input_source)
{
  vec_validate (qos_record_configs[input_source], sw_if_index);

  if (0 == qos_record_configs[input_source][sw_if_index])
    {
      qos_record_feature_config (sw_if_index, input_source, 1);
    }

  qos_record_configs[input_source][sw_if_index]++;
  return (0);
}

int
qos_record_disable (u32 sw_if_index, qos_source_t input_source)
{
  if (vec_len (qos_record_configs[input_source]) < sw_if_index)
    return VNET_API_ERROR_NO_MATCHING_INTERFACE;

  if (0 == qos_record_configs[input_source][sw_if_index])
    return VNET_API_ERROR_VALUE_EXIST;

  qos_record_configs[input_source][sw_if_index]--;

  if (0 == qos_record_configs[input_source][sw_if_index])
    {
      qos_record_feature_config (sw_if_index, input_source, 0);
    }

  return (0);
}

/*
 * Disable recording feautre for all protocols when the interface
 * is deleted
 */
static clib_error_t *
qos_record_ip_interface_add_del (vnet_main_t * vnm,
				 u32 sw_if_index, u32 is_add)
{
  if (!is_add)
    {
      qos_source_t qs;

      FOR_EACH_QOS_SOURCE (qs)
      {
	qos_record_disable (sw_if_index, qs);
      }
    }

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (qos_record_ip_interface_add_del);

/**
 * per-packet trace data
 */
typedef struct qos_record_trace_t_
{
  /* per-pkt trace data */
  qos_bits_t bits;
} qos_record_trace_t;

static inline uword
qos_record_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame, int is_ip6)
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
	  u32 sw_if_index0, next0, bi0;
	  qos_bits_t qos0;

	  next0 = 0;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  if (is_ip6)
	    {
	      ip6_0 = vlib_buffer_get_current (b0);
	      qos0 = ip6_traffic_class_network_order (ip6_0);
	    }
	  else
	    {
	      ip4_0 = vlib_buffer_get_current (b0);
	      qos0 = ip4_0->tos;
	    }
	  vnet_buffer2 (b0)->qos.bits = qos0;
	  vnet_buffer2 (b0)->qos.source = QOS_SOURCE_IP;
	  b0->flags |= VNET_BUFFER_F_QOS_DATA_VALID;
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  vnet_feature_next (sw_if_index0, &next0, b0);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      qos_record_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->bits = qos0;
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
format_qos_record_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  qos_record_trace_t *t = va_arg (*args, qos_record_trace_t *);

  s = format (s, "qos:%d", t->bits);

  return s;
}

static inline uword
ip4_qos_record (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  return (qos_record_inline (vm, node, frame, 0));
}

static inline uword
ip6_qos_record (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  return (qos_record_inline (vm, node, frame, 1));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_qos_record_node) = {
  .function = ip4_qos_record,
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

VLIB_NODE_FUNCTION_MULTIARCH (ip4_qos_record_node, ip4_qos_record);

VNET_FEATURE_INIT (ip4_qos_record_node, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "ip4-qos-record",
};

VLIB_REGISTER_NODE (ip6_qos_record_node) = {
  .function = ip6_qos_record,
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

VLIB_NODE_FUNCTION_MULTIARCH (ip6_qos_record_node, ip6_qos_record);

VNET_FEATURE_INIT (ip6_qos_record_node, static) = {
    .arc_name = "ip6-unicast",
    .node_name = "ip6-qos-record",
};
/* *INDENT-ON* */


static clib_error_t *
qos_record_cli (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index, qs;
  u8 enable;

  qs = 0xff;
  enable = 1;
  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "%U", unformat_qos_source, &qs))
	;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");
  if (0xff == qs)
    return clib_error_return (0, "input location must be specified");

  if (enable)
    qos_record_enable (sw_if_index, qs);
  else
    qos_record_disable (sw_if_index, qs);

  return (NULL);
}

/*?
 * Enable QoS bit recording on an interface using the packet's input DSCP bits
 * Which input QoS bits to use are either; IP, MPLS or VLAN. If more than
 * one protocol is chosen (which is foolish) the higer layers override the
 * lower.
 *
 * @cliexpar
 * @cliexcmd{qos record ip GigEthernet0/1/0}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_record_command, static) = {
  .path = "qos record",
  .short_help = "qos record <record-source> <INTERFACE> [disable]",
  .function = qos_record_cli,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
