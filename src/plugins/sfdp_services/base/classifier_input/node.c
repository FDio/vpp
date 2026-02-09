/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <sfdp_services/base/classifier_input/classifier_input.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/common.h>
#include <vnet/classify/vnet_classify.h>

typedef struct
{
  u32 tenant_id;
  u32 sw_if_index;
  u32 table_index;
  u32 hash;
  u8 hit;
} sfdp_classifier_input_trace_t;

static u8 *
format_sfdp_classifier_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sfdp_classifier_input_trace_t *t = va_arg (*args, sfdp_classifier_input_trace_t *);

  s = format (s,
	      "sfdp-classifier-input: sw_if_index %d, table %d, hash 0x%x, "
	      "hit %d, tenant %d\n",
	      t->sw_if_index, t->table_index, t->hash, t->hit, t->tenant_id);

  return s;
}

#define foreach_sfdp_classifier_input_ip4_next _ (LOOKUP, "sfdp-lookup-ip4")

#define foreach_sfdp_classifier_input_ip6_next _ (LOOKUP, "sfdp-lookup-ip6")

#define foreach_sfdp_classifier_input_error                                                        \
  _ (NOERROR, "No error")                                                                          \
  _ (NO_TABLE, "No classifier table configured")                                                   \
  _ (MISS, "Classifier miss")                                                                      \
  _ (NO_TENANT, "No tenant mapping for session")

typedef enum
{
#define _(sym, str) SFDP_CLASSIFIER_INPUT_ERROR_##sym,
  foreach_sfdp_classifier_input_error
#undef _
    SFDP_CLASSIFIER_INPUT_N_ERROR,
} sfdp_classifier_input_error_t;

static char *sfdp_classifier_input_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_classifier_input_error
#undef _
};

typedef enum
{
#define _(s, n) SFDP_CLASSIFIER_INPUT_IP4_NEXT_##s,
  foreach_sfdp_classifier_input_ip4_next
#undef _
    SFDP_CLASSIFIER_INPUT_IP4_N_NEXT
} sfdp_classifier_input_ip4_next_t;

typedef enum
{
#define _(s, n) SFDP_CLASSIFIER_INPUT_IP6_NEXT_##s,
  foreach_sfdp_classifier_input_ip6_next
#undef _
    SFDP_CLASSIFIER_INPUT_IP6_N_NEXT
} sfdp_classifier_input_ip6_next_t;

static_always_inline uword
sfdp_classifier_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
			      u8 is_ip6)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;
  vnet_classify_main_t *vcm = &vnet_classify_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vlib_combined_counter_main_t *cm = &sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_INCOMING];
  u16 lookup_next_index =
    is_ip6 ? SFDP_CLASSIFIER_INPUT_IP6_NEXT_LOOKUP : SFDP_CLASSIFIER_INPUT_IP4_NEXT_LOOKUP;

  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  uword thread_index = vlib_get_thread_index ();
  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;
  f64 now = vlib_time_now (vm);

  u32 table_index = scim->classify_table_index;
  vnet_classify_table_t *t = NULL;

  if (PREDICT_TRUE (table_index != ~0))
    t = pool_elt_at_index (vcm->tables, table_index);

  /* First pass: compute hashes if we have a table */
  if (PREDICT_TRUE (t != NULL))
    {
      u32 n = n_left;
      vlib_buffer_t **bp = bufs;
      while (n > 0)
	{
	  u8 *h = vlib_buffer_get_current (bp[0]);
	  vnet_buffer (bp[0])->l2_classify.hash = vnet_classify_hash_packet_inline (t, h);
	  vnet_classify_prefetch_bucket (t, vnet_buffer (bp[0])->l2_classify.hash);
	  bp += 1;
	  n -= 1;
	}
    }

  while (n_left)
    {
      u32 len = vlib_buffer_length_in_chain (vm, b[0]);
      u32 rx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      u16 tenant_idx = ~0;
      sfdp_tenant_t *tenant;
      vnet_classify_entry_t *e = NULL;
      u32 hash = 0;
      u8 hit = 0;

      if (PREDICT_FALSE (t == NULL))
	{
	  /* No table configured, pass through */
	  vnet_feature_next_u16 (current_next, b[0]);
	  goto trace;
	}

      hash = vnet_buffer (b[0])->l2_classify.hash;
      u8 *h = vlib_buffer_get_current (b[0]);

      e = vnet_classify_find_entry_inline (t, h, hash, now);

      if (PREDICT_FALSE (e == NULL))
	{
	  /* No match, pass through */
	  vnet_feature_next_u16 (current_next, b[0]);
	  goto trace;
	}

      hit = 1;

      /* Get tenant index from opaque_index */
      if (sfdp_classifier_input_get_tenant_idx (e->opaque_index, &tenant_idx))
	{
	  /* No tenant mapping, pass through */
	  vnet_feature_next_u16 (current_next, b[0]);
	  goto trace;
	}

      tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
      b[0]->flow_id = tenant->context_id;
      sfdp_buffer (b[0])->tenant_index = tenant_idx;
      current_next[0] = lookup_next_index;

      vlib_increment_combined_counter (cm, thread_index, tenant_idx, 1, len);

    trace:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  sfdp_classifier_input_trace_t *tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->sw_if_index = rx_sw_if_index;
	  tr->table_index = table_index;
	  tr->hash = hash;
	  tr->hit = hit;
	  tr->tenant_id =
	    (tenant_idx != (u16) ~0) ? sfdp_tenant_at_index (sfdp, tenant_idx)->tenant_id : ~0;
	}

      b += 1;
      current_next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (sfdp_classifier_input_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_classifier_input_inline (vm, node, frame, 0 /* is_ip6 */);
}

VLIB_NODE_FN (sfdp_classifier_input_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_classifier_input_inline (vm, node, frame, 1 /* is_ip6 */);
}

VLIB_REGISTER_NODE (sfdp_classifier_input_ip4_node) = {
  .name = "sfdp-classifier-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_classifier_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_classifier_input_error_strings),
  .error_strings = sfdp_classifier_input_error_strings,
  .n_next_nodes = SFDP_CLASSIFIER_INPUT_IP4_N_NEXT,
  .next_nodes = {
          [SFDP_CLASSIFIER_INPUT_IP4_NEXT_LOOKUP] = "sfdp-lookup-ip4",
  },
};

VLIB_REGISTER_NODE (sfdp_classifier_input_ip6_node) = {
  .name = "sfdp-classifier-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_classifier_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_classifier_input_error_strings),
  .error_strings = sfdp_classifier_input_error_strings,
  .n_next_nodes = SFDP_CLASSIFIER_INPUT_IP6_N_NEXT,
  .next_nodes = {
          [SFDP_CLASSIFIER_INPUT_IP6_NEXT_LOOKUP] = "sfdp-lookup-ip6",
  },
};

VNET_FEATURE_INIT (sfdp_classifier_input_ip4_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "sfdp-classifier-input-ip4",
};

VNET_FEATURE_INIT (sfdp_classifier_input_ip6_feat, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "sfdp-classifier-input-ip6",
};
