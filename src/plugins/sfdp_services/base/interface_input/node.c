/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <sfdp_services/base/interface_input/interface_input.h>
#include <vnet/sfdp/sfdp.h>
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

#define foreach_sfdp_interface_input_next  _ (LOOKUP, "sfdp-lookup-ip4")
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
#define _(s, n) SFDP_INTERFACE_INPUT_NEXT_##s,
  foreach_sfdp_interface_input_next
#undef _
    SFDP_INTERFACE_INPUT_N_NEXT
} sfdp_interface_input_next_t;

static_always_inline uword
sfdp_interface_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			     vlib_frame_t *frame)
{
  /*
   * use VNI as tenant ID
   * tenant_id -> tenant index
   * drop unknown tenants
   * store tenant_id into opaque1
   * advance current data to beginning of IP packet
   */
  sfdp_main_t *sfdp = &sfdp_main;
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
      u32 tenant_idx = vim->tenant_idx_by_sw_if_idx[rx_sw_if_index];
      sfdp_tenant_t *tenant;
      if (tenant_idx == ~0)
	{
	  vnet_feature_next_u16 (current_next, b[0]);
	  goto end_of_packet;
	}
      tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
      b[0]->flow_id = tenant->context_id;
      sfdp_buffer (b[0])->tenant_index = tenant_idx;
      current_next[0] = SFDP_INTERFACE_INPUT_NEXT_LOOKUP;

      vlib_increment_combined_counter (cm, thread_index, tenant_idx, 1, len);
    end_of_packet:
      b += 1;
      current_next += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (sfdp_interface_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_interface_input_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (sfdp_interface_input_node) = {
  .name = "sfdp-interface-input",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_interface_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_interface_input_error_strings),
  .error_strings = sfdp_interface_input_error_strings,
  .n_next_nodes = SFDP_INTERFACE_INPUT_N_NEXT,
  .next_nodes = {
          [SFDP_INTERFACE_INPUT_NEXT_LOOKUP] = "sfdp-lookup-ip4",
  },
};

VNET_FEATURE_INIT (sfdp_interface_input_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "sfdp-interface-input",
};