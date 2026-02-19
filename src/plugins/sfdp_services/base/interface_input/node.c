/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include "vnet/flow/flow.h"
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <sfdp_services/base/interface_input/interface_input.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/service.h>
#include <vnet/sfdp/common.h>
typedef struct
{
  u32 tenant_id;
  u32 sw_if_index;
} sfdp_interface_input_trace_t;

static u8 *
format_sfdp_interface_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sfdp_interface_input_trace_t *t =
    va_arg (*args, sfdp_interface_input_trace_t *);

  s = format (s, "sfdp-interface-input: sw_if_index %d, tenant %d\n",
	      t->sw_if_index, t->tenant_id);

  return s;
}

#define foreach_sfdp_interface_input_ip4_next                                                      \
  _ (LOOKUP, "sfdp-lookup-ip4")                                                                    \
  _ (LOOKUP_OFFLOAD, "sfdp-lookup-ip4-offload")                                                    \
  _ (LOOKUP_OFFLOAD_1ST_PACKET, "sfdp-lookup-ip4-offload-1st-packet")
#define foreach_sfdp_interface_input_ip6_next _ (LOOKUP, "sfdp-lookup-ip6")
#define foreach_sfdp_interface_input_error _ (NOERROR, "No error")

typedef enum
{
#define _(sym, str) SFDP_INTERFACE_INPUT_ERROR_##sym,
  foreach_sfdp_interface_input_error
#undef _
    SFDP_INTERFACE_INPUT_N_ERROR,
} sfdp_interface_input_error_t;

static char *sfdp_interface_input_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_interface_input_error
#undef _
};

typedef enum
{
#define _(s, n) SFDP_INTERFACE_INPUT_IP4_NEXT_##s,
  foreach_sfdp_interface_input_ip4_next
#undef _
    SFDP_INTERFACE_INPUT_IP4_N_NEXT
} sfdp_interface_input_ip4_next_t;

typedef enum
{
#define _(s, n) SFDP_INTERFACE_INPUT_IP6_NEXT_##s,
  foreach_sfdp_interface_input_ip6_next
#undef _
    SFDP_INTERFACE_INPUT_IP6_N_NEXT
} sfdp_interface_input_ip6_next_t;

static_always_inline uword
sfdp_interface_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
			     u8 is_ipv6)
{
  /*
   * use sw_if_index as tenant ID
   * tenant_id + proto -> tenant index
   * drop unknown tenants
   * store tenant_id into opaque1
   */
  sfdp_main_t *sfdp = &sfdp_main;
  u8 proto = is_ipv6 ? SFDP_INTERFACE_INPUT_PROTO_IP6 : SFDP_INTERFACE_INPUT_PROTO_IP4;
  sfdp_interface_input_main_t *vim = &sfdp_interface_input_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vlib_combined_counter_main_t *cm =
    &sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_INCOMING];

  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  uword thread_index = vlib_get_thread_index ();
  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  while (n_left)
    {
      u32 len = vlib_buffer_length_in_chain (vm, b[0]);
      u32 rx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      u32 tenant_idx = vim->tenant_idx_by_sw_if_idx[proto][rx_sw_if_index];
      u8 offload_enabled = vim->offload_enabled_by_sw_if_idx[proto][rx_sw_if_index];
      sfdp_tenant_t *tenant;
      if (tenant_idx == ~0)
	{
	  vnet_feature_next_u16 (current_next, b[0]);
	  goto end_of_packet;
	}

      sfdp_buffer (b[0])->tenant_index = tenant_idx;

      if (is_ipv6)
	{
	  current_next[0] = SFDP_INTERFACE_INPUT_IP6_NEXT_LOOKUP;
	}
      else if (offload_enabled)
	{
	  if (b[0]->flow_id == 0)
	    {
	      current_next[0] = SFDP_INTERFACE_INPUT_IP4_NEXT_LOOKUP_OFFLOAD_1ST_PACKET;
	    }
	  else
	    {
	      current_next[0] = SFDP_INTERFACE_INPUT_IP4_NEXT_LOOKUP_OFFLOAD;
	    }
	}
      else
	{
	  tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
	  b[0]->flow_id = tenant->context_id;
	  current_next[0] = SFDP_INTERFACE_INPUT_IP4_NEXT_LOOKUP;
	}

      vlib_increment_combined_counter (cm, thread_index, tenant_idx, 1, len);

    end_of_packet:
      b += 1;
      current_next += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (sfdp_interface_input_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_interface_input_inline (vm, node, frame, 0 /* is_ipv6 */);
}

VLIB_NODE_FN (sfdp_interface_input_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_interface_input_inline (vm, node, frame, 1 /* is_ipv6 */);
}

VLIB_REGISTER_NODE (sfdp_interface_input_ip4_node) = {
  .name = "sfdp-interface-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_interface_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_interface_input_error_strings),
  .error_strings = sfdp_interface_input_error_strings,
  .n_next_nodes = SFDP_INTERFACE_INPUT_IP4_N_NEXT,
  .next_nodes = {
#define _(s, n) [SFDP_INTERFACE_INPUT_IP4_NEXT_##s] = n,
          foreach_sfdp_interface_input_ip4_next
#undef _
  },
};

VLIB_REGISTER_NODE (sfdp_interface_input_ip6_node) = {
  .name = "sfdp-interface-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_interface_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_interface_input_error_strings),
  .error_strings = sfdp_interface_input_error_strings,
  .n_next_nodes = SFDP_INTERFACE_INPUT_IP6_N_NEXT,
  .next_nodes = {
          [SFDP_INTERFACE_INPUT_IP6_NEXT_LOOKUP] = "sfdp-lookup-ip6",
  },
};

VNET_FEATURE_INIT (sfdp_interface_input_ip4_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "sfdp-interface-input-ip4",
};

VNET_FEATURE_INIT (sfdp_interface_input_ip6_feat, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "sfdp-interface-input-ip6",
};

SFDP_SERVICE_DEFINE (ip4_lookup) = { .node_name = "ip4-lookup",
				     .runs_before = SFDP_SERVICES (0),
				     .runs_after = SFDP_SERVICES ("sfdp-drop", "sfdp-l4-lifecycle",
								  "sfdp-tcp-check"),
				     .is_terminal = 1 };

SFDP_SERVICE_DEFINE (ip6_lookup) = { .node_name = "ip6-lookup",
				     .runs_before = SFDP_SERVICES (0),
				     .runs_after = SFDP_SERVICES ("sfdp-drop", "sfdp-l4-lifecycle",
								  "sfdp-tcp-check"),
				     .is_terminal = 1 };
