/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/common.h>
#include <vnet/sfdp/service.h>
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} sfdp_dummy_dot1q_input_trace_t;

static u8 *
format_sfdp_dummy_dot1q_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  CLIB_UNUSED (sfdp_dummy_dot1q_input_trace_t * t) =
    va_arg (*args, sfdp_dummy_dot1q_input_trace_t *);

  /*s = format (s, "snort-enq: sw_if_index %d, next index %d\n",
     t->sw_if_index, t->next_index);*/

  return s;
}

#define foreach_sfdp_dummy_dot1q_input_next                                   \
  _ (LOOKUP_IP4, "sfdp-lookup-ip4")                                           \
  _ (LOOKUP_IP6, "sfdp-lookup-ip6")
#define foreach_sfdp_dummy_dot1q_input_error _ (NOERROR, "No error")

typedef enum
{
#define _(sym, str) SFDP_DUMMY_DOT1Q_ERROR_##sym,
  foreach_sfdp_dummy_dot1q_input_error
#undef _
    SFDP_DUMMY_DOT1Q_N_ERROR,
} sfdp_dummy_dot1q_input_error_t;

static char *sfdp_dummy_dot1q_input_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_dummy_dot1q_input_error
#undef _
};

typedef enum
{
#define _(s, n) SFDP_DUMMY_DOT1Q_INPUT_NEXT_##s,
  foreach_sfdp_dummy_dot1q_input_next
#undef _
    SFDP_DUMMY_DOT1Q_INPUT_N_NEXT
} sfdp_dummy_dot1q_input_next_t;

/*-----------------------------*/

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} sfdp_dummy_dot1q_output_trace_t;

static u8 *
format_sfdp_dummy_dot1q_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  CLIB_UNUSED (sfdp_dummy_dot1q_output_trace_t * t) =
    va_arg (*args, sfdp_dummy_dot1q_output_trace_t *);

  /*s = format (s, "snort-enq: sw_if_index %d, next index %d\n",
     t->sw_if_index, t->next_index);*/

  return s;
}

#define foreach_sfdp_dummy_dot1q_output_next                                  \
  _ (LOOKUP_IP4, "sfdp-lookup-ip4")                                           \
  _ (LOOKUP_IP6, "sfdp-lookup-ip6")
#define foreach_sfdp_dummy_dot1q_output_error _ (NOERROR, "No error")

typedef enum
{
#define _(sym, str) SFDP_DUMMY_DOT1Q_OUTPUT_ERROR_##sym,
  foreach_sfdp_dummy_dot1q_output_error
#undef _
    SFDP_DUMMY_DOT1Q_OUTPUT_N_ERROR,
} sfdp_dummy_dot1q_output_error_t;

static char *sfdp_dummy_dot1q_output_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_dummy_dot1q_output_error
#undef _
};

typedef enum
{
#define _(s, n) SFDP_DUMMY_DOT1Q_OUTPUT_NEXT_##s,
  foreach_sfdp_dummy_dot1q_output_next
#undef _
    SFDP_DUMMY_DOT1Q_OUTPUT_N_NEXT
} sfdp_dummy_dot1q_output_next_t;

static_always_inline void
process_one_pkt (vlib_main_t *vm, sfdp_main_t *sfdp,
		 vlib_combined_counter_main_t *cm, u32 thread_index,
		 vlib_buffer_t **b, u16 *current_next)
{
  sfdp_tenant_t *tenant;
  clib_bihash_kv_8_8_t kv = { 0 };
  u8 *data = vlib_buffer_get_current (b[0]);
  u32 orig_len = vlib_buffer_length_in_chain (vm, b[0]);
  ethernet_header_t *eth = (void *) data;
  sfdp_tenant_id_t tenant_id = 0;
  u32 off = sizeof (eth[0]);
  u16 type = clib_net_to_host_u16 (eth->type);
  sfdp_tenant_index_t tenant_idx;
  if (type == ETHERNET_TYPE_VLAN)
    {
      ethernet_vlan_header_t *vlan = (void *) (data + sizeof (eth[0]));
      tenant_id = clib_net_to_host_u16 (vlan->priority_cfi_and_id) & 0xfff;
      type = clib_net_to_host_u16 (vlan->type);
      off += sizeof (vlan[0]);
    }
  if (type != ETHERNET_TYPE_IP4 && type != ETHERNET_TYPE_IP6)
    {
      vnet_feature_next_u16 (current_next, b[0]);
      return;
    }
  /* Tenant-id lookup */
  kv.key = (u64) tenant_id;
  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    {
      /* Not found */
      vnet_feature_next_u16 (current_next, b[0]);
      return;
    }
  tenant_idx = kv.value;
  tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
  b[0]->flow_id = tenant->context_id;
  sfdp_buffer (b[0])->tenant_index = tenant_idx;
  vnet_buffer (b[0])->l2_hdr_offset = b[0]->current_data;
  vnet_buffer (b[0])->l3_hdr_offset = b[0]->current_data + off;
  b[0]->flags |=
    VNET_BUFFER_F_L2_HDR_OFFSET_VALID | VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
  current_next[0] = type == ETHERNET_TYPE_IP4 ?
		      SFDP_DUMMY_DOT1Q_INPUT_NEXT_LOOKUP_IP4 :
		      SFDP_DUMMY_DOT1Q_INPUT_NEXT_LOOKUP_IP6;
  vlib_increment_combined_counter (cm, thread_index, tenant_idx, 1,
				   orig_len - off);
  vlib_buffer_advance (b[0], off);
}

static_always_inline uword
sfdp_dummy_dot1q_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
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
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  u32 thread_index = vlib_get_thread_index ();
  vlib_combined_counter_main_t *cm =
    &sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_INCOMING];
  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  while (n_left)
    {
      process_one_pkt (vm, sfdp, cm, thread_index, b, current_next);
      b += 1;
      current_next += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (sfdp_dummy_dot1q_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_dummy_dot1q_input_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (sfdp_dummy_dot1q_input_node) = {
  .name = "sfdp-dummy-dot1q-input",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_dummy_dot1q_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_dummy_dot1q_input_error_strings),
  .error_strings = sfdp_dummy_dot1q_input_error_strings,
  .n_next_nodes = SFDP_DUMMY_DOT1Q_INPUT_N_NEXT,
  .next_nodes = {
          [SFDP_DUMMY_DOT1Q_INPUT_NEXT_LOOKUP_IP4] = "sfdp-lookup-ip4",
          [SFDP_DUMMY_DOT1Q_INPUT_NEXT_LOOKUP_IP6] = "sfdp-lookup-ip6",
  },
};

VNET_FEATURE_INIT (sfdp_dummy_dot1q_input_feat, static) = {
  .arc_name = "device-input",
  .node_name = "sfdp-dummy-dot1q-input",
};

#define SFDP_PREFETCH_SIZE 8
VLIB_NODE_FN (sfdp_dummy_dot1q_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  sfdp_main_t *sfdp = &sfdp_main;
  vlib_combined_counter_main_t *cm =
    &sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_OUTGOING];
  u32 thread_index = vlib_get_thread_index ();
  sfdp_tenant_index_t tenant_idx[SFDP_PREFETCH_SIZE];
  u32 orig_len[SFDP_PREFETCH_SIZE];
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;

  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > SFDP_PREFETCH_SIZE)
    {
      word l2_len[SFDP_PREFETCH_SIZE];
      if (n_left > 2 * SFDP_PREFETCH_SIZE)
	for (int i = 0; i < SFDP_PREFETCH_SIZE; i++)
	  vlib_prefetch_buffer_header (b[0], STORE);

      for (int i = 0; i < SFDP_PREFETCH_SIZE; i++)
	{
	  orig_len[i] = vlib_buffer_length_in_chain (vm, b[i]);
	  tenant_idx[i] = sfdp_buffer (b[i])->tenant_index;
	  vlib_increment_combined_counter (cm, thread_index, tenant_idx[i], 1,
					   orig_len[i]);
	  l2_len[i] = vnet_buffer (b[i])->l3_hdr_offset;
	  l2_len[i] -= vnet_buffer (b[i])->l2_hdr_offset;
	  vlib_buffer_advance (b[i], -l2_len[i]);
	  vnet_feature_next_u16 (to_next + i, b[i]);
	}

      b += SFDP_PREFETCH_SIZE;
      to_next += SFDP_PREFETCH_SIZE;
      n_left -= SFDP_PREFETCH_SIZE;
    }
  while (n_left)
    {
      word l2_len;
      u32 orig_len = vlib_buffer_length_in_chain (vm, b[0]);
      sfdp_tenant_index_t tenant_idx = sfdp_buffer (b[0])->tenant_index;
      vlib_increment_combined_counter (cm, thread_index, tenant_idx, 1,
				       orig_len);
      l2_len = vnet_buffer (b[0])->l3_hdr_offset;
      l2_len -= vnet_buffer (b[0])->l2_hdr_offset;
      vlib_buffer_advance (b[0], -l2_len);
      vnet_feature_next_u16 (to_next, b[0]);

      b += 1;
      to_next += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}
#undef SFDP_PREFETCH_SIZE

VLIB_REGISTER_NODE (sfdp_dummy_dot1q_output_node) = {
  .name = "sfdp-dummy-dot1q-output",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_dummy_dot1q_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_dummy_dot1q_output_error_strings),
  .error_strings = sfdp_dummy_dot1q_output_error_strings,

  .sibling_of = "sfdp-dummy-dot1q-input"
};

SFDP_SERVICE_DEFINE (dummy_dot1q_output) = {
  .node_name = "sfdp-dummy-dot1q-output",
  .runs_before = SFDP_SERVICES (0),
  .runs_after = SFDP_SERVICES ("sfdp-drop", "sfdp-l4-lifecycle",
			       "sfdp-tcp-check"),
  .is_terminal = 1
};
