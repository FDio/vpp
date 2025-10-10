/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <sfdp_services/geneve/gateway.h>
#include <vnet/sfdp/common.h>
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} sfdp_geneve_input_trace_t;

static u8 *
format_sfdp_geneve_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sfdp_geneve_input_trace_t *t = va_arg (*args, sfdp_geneve_input_trace_t *);

  s = format (s, "snort-enq: sw_if_index %d, next index %d\n", t->sw_if_index,
	      t->next_index);

  return s;
}

#define foreach_sfdp_geneve_input_next                                        \
  _ (LOOKUP_IP4, "sfdp-lookup-ip4")                                           \
  _ (LOOKUP_IP6, "sfdp-lookup-ip6")
#define foreach_sfdp_geneve_input_error _ (NOERROR, "No error")

typedef enum
{
#define _(sym, str) SFDP_GENEVE_INPUT_ERROR_##sym,
  foreach_sfdp_geneve_input_error
#undef _
    SFDP_GENEVE_INPUT_N_ERROR,
} sfdp_geneve_input_error_t;

static char *sfdp_geneve_input_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_geneve_input_error
#undef _
};

typedef enum
{
#define _(s, n) SFDP_GENEVE_INPUT_NEXT_##s,
  foreach_sfdp_geneve_input_next
#undef _
    SFDP_GENEVE_INPUT_N_NEXT
} sfdp_geneve_input_next_t;

static_always_inline uword
sfdp_geneve_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
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
  vlib_combined_counter_main_t *cm =
    &sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_INCOMING];
  sfdp_tenant_t *tenant;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  u32 thread_index = vlib_get_thread_index ();

  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  while (n_left)
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b[0]);
      udp_header_t *udp;
      u32 *gnv;
      u32 tenant_id;
      u16 tenant_idx;
      clib_bihash_kv_8_8_t kv = {};
      u16 off = 0;
      u32 len = vlib_buffer_length_in_chain (vm, b[0]);
      u16 ethtype;
      if (ip4->protocol != IP_PROTOCOL_UDP)
	{
	  vnet_feature_next_u16 (current_next, b[0]);
	  goto end_of_packet;
	}
      off += ip4_header_bytes (ip4);
      udp = (udp_header_t *) (b[0]->data + b[0]->current_data + off);
      if (udp->dst_port != 0xC117)
	{
	  vnet_feature_next_u16 (current_next, b[0]);
	  goto end_of_packet;
	}
      off += sizeof (udp[0]);
      gnv = (u32 *) (b[0]->data + b[0]->current_data + off);

      /* Extract VNI */
      tenant_id = clib_net_to_host_u32 (gnv[1]) >> 8;
      kv.key = (u64) tenant_id;
      if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
	{
	  /* Not found */
	  vnet_feature_next_u16 (current_next, b[0]);
	  goto end_of_packet;
	}

      /* Store tenant_id as flow_id (to simplify the future lookup) */
      tenant_idx = kv.value;
      tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
      b[0]->flow_id = tenant->context_id;
      sfdp_buffer (b[0])->tenant_index = tenant_idx;
      ethtype = *(u16 *) (b[0]->data + b[0]->current_data + off + 20);
      ethtype = clib_net_to_host_u16 (ethtype);
      current_next[0] = ethtype == ETHERNET_TYPE_IP6 ?
			  SFDP_GENEVE_INPUT_NEXT_LOOKUP_IP6 :
			  SFDP_GENEVE_INPUT_NEXT_LOOKUP_IP4;
      off +=
	8 /* geneve header no options */ + 14 /* ethernet header, no tag*/;
      vlib_buffer_advance (b[0], off);
      vlib_increment_combined_counter (cm, thread_index, tenant_idx, 1,
				       len - off);
    end_of_packet:
      b += 1;
      current_next += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (sfdp_geneve_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_geneve_input_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (sfdp_geneve_input_node) = {
  .name = "sfdp-geneve-input",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_geneve_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_geneve_input_error_strings),
  .error_strings = sfdp_geneve_input_error_strings,
  .n_next_nodes = SFDP_GENEVE_INPUT_N_NEXT,
  .next_nodes = {
          [SFDP_GENEVE_INPUT_NEXT_LOOKUP_IP4] = "sfdp-lookup-ip4",
          [SFDP_GENEVE_INPUT_NEXT_LOOKUP_IP6] = "sfdp-lookup-ip6",
  },
};

VNET_FEATURE_INIT (sfdp_geneve_input_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "sfdp-geneve-input",
};
