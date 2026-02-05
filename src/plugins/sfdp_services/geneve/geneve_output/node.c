/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <sfdp_services/geneve/gateway.h>
#include <vnet/sfdp/common.h>
#include <vnet/sfdp/service.h>
#define SFDP_GENEVE_OPTION_CLASS	   ((u16) 0xDEAD)
#define SFDP_GENEVE_OPTION_TYPE_SESSION_ID ((u8) 0xBE)
#define SFDP_GENEVE_OPTION_SESSION_ID_SIZE ((u8) 0x2)
#define SFDP_GENEVE_OPTION_SESSION_ID_FIRST_WORD                              \
  (SFDP_GENEVE_OPTION_CLASS << 16) |                                          \
    (SFDP_GENEVE_OPTION_TYPE_SESSION_ID << 8) |                               \
    (SFDP_GENEVE_OPTION_SESSION_ID_SIZE << 0)
#define SFDP_GENEVE_OPTION_LEN (12)
#define SFDP_GENEVE_TOTAL_LEN  (8 + SFDP_GENEVE_OPTION_LEN)

#define foreach_sfdp_geneve_output_error _ (NO_OUTPUT, "no output data")

typedef enum
{
#define _(sym, str) SFDP_GENEVE_OUTPUT_ERROR_##sym,
  foreach_sfdp_geneve_output_error
#undef _
    SFDP_GENEVE_OUTPUT_N_ERROR,
} sfdp_geneve_output_error_t;

static char *sfdp_geneve_output_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_geneve_output_error
#undef _
};

#define foreach_sfdp_geneve_output_next                                       \
  _ (DROP, "error-drop")                                                      \
  _ (IP4_LOOKUP, "ip4-lookup")

typedef enum
{
#define _(n, x) SFDP_GENEVE_OUTPUT_NEXT_##n,
  foreach_sfdp_geneve_output_next
#undef _
    SFDP_GENEVE_OUTPUT_N_NEXT
} sfdp_geneve_output_next_t;

typedef struct
{
  u32 flow_id;
  u16 encap_size;
  u8 encap_data[124];
} sfdp_geneve_output_trace_t;

static u8 *
format_sfdp_geneve_output_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  sfdp_geneve_output_trace_t *t = va_arg (*args, sfdp_geneve_output_trace_t *);
  u32 indent = format_get_indent (s);
  s =
    format (s, "sfdp-geneve_output: flow-id %u (session %u, %s)\n", t->flow_id,
	    t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward");
  s = format (s, "%U", format_white_space, indent);
  s = format (s, "encap-data: %U", format_hex_bytes, t->encap_data,
	      t->encap_size);
  return s;
}

static_always_inline int
sfdp_geneve_output_load_data (gw_main_t *gm,
			      gw_geneve_output_data_t *geneve_out,
			      sfdp_session_t *session, vlib_buffer_t *b)
{
  sfdp_tenant_index_t tenant_idx = sfdp_buffer (b)->tenant_index;
  gw_tenant_t *tenant = gw_tenant_at_index (gm, tenant_idx);
  u8 direction = b->flow_id & 0x1;
  ip4_header_t *ip4 = (void *) geneve_out->encap_data;
  udp_header_t *udp;
  ethernet_header_t *eth;
  u32 *gnv;
  if (PREDICT_FALSE (!(tenant->flags & GW_TENANT_F_OUTPUT_DATA_SET)))
    return -1;
  geneve_out->session_version = session->session_version;
  geneve_out->encap_size = 0;
  /* Start with IP header */
  ip4->src_address = tenant->geneve_src_ip[direction];
  ip4->dst_address = tenant->geneve_dst_ip[direction];
  ip4->protocol = IP_PROTOCOL_UDP;
  ip4->ip_version_and_header_length = 0x45;
  ip4->tos = IP_DSCP_CS0;
  ip4->ttl = 0xff;
  ip4->flags_and_fragment_offset = 0;
  ip4->length = 0;
  ip4->checksum = ip4_header_checksum (ip4);
  ip4->length = /* stored in host byte order, incremented and swapped
		   later */
    sizeof (ip4_header_t) + sizeof (udp_header_t) + SFDP_GENEVE_TOTAL_LEN +
    sizeof (ethernet_header_t);
  geneve_out->encap_size += sizeof (*ip4);
  udp = (void *) (geneve_out->encap_data + geneve_out->encap_size);
  udp->src_port = tenant->geneve_src_port[direction];
  udp->dst_port = tenant->geneve_dst_port[direction];
  udp->checksum = 0;
  udp->length = /* stored in host byte order, incremented and swapped
		   later */
    sizeof (udp_header_t) + SFDP_GENEVE_TOTAL_LEN + sizeof (ethernet_header_t);
  geneve_out->encap_size += sizeof (*udp);
  gnv = (void *) (geneve_out->encap_data + geneve_out->encap_size);
  gnv[0] =
    // Not sure if 0x0C or 0x03 (number of bytes or of 4B-words???)
    clib_host_to_net_u32 (0x03006558); /*3 words of option geneve version 0*/
  gnv[1] = clib_host_to_net_u32 (tenant->output_tenant_id << 8);
  gnv[2] = clib_host_to_net_u32 (SFDP_GENEVE_OPTION_SESSION_ID_FIRST_WORD);
  gnv[3] =
    clib_host_to_net_u32 (session->session_id >> 32); /* session id high  */
  gnv[4] = clib_host_to_net_u32 (session->session_id |
				 direction); /* session id low */
  geneve_out->encap_size += SFDP_GENEVE_TOTAL_LEN;
  eth = (void *) (geneve_out->encap_data + geneve_out->encap_size);
  if (tenant->flags & GW_TENANT_F_STATIC_MAC)
    {
      clib_memcpy_fast (eth->src_address, tenant->src_mac[direction].bytes,
			sizeof (mac_address_t));
      clib_memcpy_fast (eth->dst_address, tenant->dst_mac[direction].bytes,
			sizeof (mac_address_t));
      eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4);
    }
  else
    clib_memcpy_fast (eth, b->data + b->current_data - sizeof (*eth),
		      sizeof (*eth));

  geneve_out->encap_size += sizeof (*eth);
  ASSERT (geneve_out->encap_size < sizeof (geneve_out->encap_data));
  return 0;
}

static_always_inline void
geneve_output_rewrite_one (vlib_main_t *vm, vlib_node_runtime_t *node,
			   gw_main_t *gm, vlib_combined_counter_main_t *cm,
			   gw_geneve_output_data_t *geneve_out,
			   sfdp_session_t *session, u32 thread_index,
			   u32 session_idx, u16 *to_next, vlib_buffer_t **b)
{
  if (PREDICT_FALSE (
	geneve_out->session_version != session->session_version &&
	sfdp_geneve_output_load_data (gm, geneve_out, session, b[0])))
    {
      to_next[0] = SFDP_GENEVE_OUTPUT_NEXT_DROP;
      vlib_node_increment_counter (vm, node->node_index,
				   SFDP_GENEVE_OUTPUT_ERROR_NO_OUTPUT, 1);
    }
  else
    {
      ip4_header_t *ip;
      udp_header_t *udp;
      ip_csum_t csum;
      u8 *data;
      u16 orig_len = vlib_buffer_length_in_chain (vm, b[0]);
      b[0]->flags |=
	(VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	 VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
      vnet_buffer (b[0])->oflags |=
	VNET_BUFFER_OFFLOAD_F_UDP_CKSUM | VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
      vlib_buffer_advance (b[0], -geneve_out->encap_size);
      data = vlib_buffer_get_current (b[0]);
      vnet_buffer (b[0])->l3_hdr_offset = b[0]->current_data;
      vnet_buffer (b[0])->l4_hdr_offset =
	b[0]->current_data + sizeof (ip4_header_t);
      clib_memcpy_fast (data, geneve_out->encap_data, geneve_out->encap_size);
      /* fixup */
      ip = (void *) data;
      ip->length = clib_net_to_host_u16 (ip->length + orig_len);
      csum = ip->checksum;
      csum = ip_csum_update (csum, 0, ip->length, ip4_header_t, length);
      ip->checksum = ip_csum_fold (csum);
      udp = (void *) (data + sizeof (ip4_header_t));
      udp->length = clib_net_to_host_u16 (udp->length + orig_len);
      to_next[0] = SFDP_GENEVE_OUTPUT_NEXT_IP4_LOOKUP;
      vlib_increment_combined_counter (cm, thread_index, session->tenant_idx,
				       1, orig_len);
    }
}

#define vlib_prefetch_buffer_data_with_offset(b, type, offset)                \
  CLIB_PREFETCH (b->data + b->current_data + (offset), CLIB_CACHE_LINE_BYTES, \
		 type)
VLIB_NODE_FN (sfdp_geneve_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  gw_main_t *gm = &gateway_main;
  sfdp_main_t *sfdp = &sfdp_main;
  vlib_combined_counter_main_t *cm =
    &sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_OUTGOING];
  u32 thread_index = vm->thread_index;

  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left);

  /* Pipeline load buffer data -> load session_data + geneve_output_data
   * ->process */
#define SFDP_PREFETCH_SIZE 2
  while (n_left >= SFDP_PREFETCH_SIZE)
    {
      u32 si[SFDP_PREFETCH_SIZE * 2];
      sfdp_session_t *session[SFDP_PREFETCH_SIZE];
      gw_geneve_output_data_t *geneve_out[SFDP_PREFETCH_SIZE];
      if (n_left >= SFDP_PREFETCH_SIZE * 3)
	{
	  for (int i = 0; i < SFDP_PREFETCH_SIZE; i++)
	    {
	      vlib_prefetch_buffer_header (b[2 * SFDP_PREFETCH_SIZE + i],
					   STORE);
	      vlib_prefetch_buffer_data_with_offset (
		b[2 * SFDP_PREFETCH_SIZE + i], STORE, -64);
	    }
	}
      if (n_left >= SFDP_PREFETCH_SIZE * 2)
	{
	  for (int i = 0; i < SFDP_PREFETCH_SIZE; i++)
	    {
	      si[SFDP_PREFETCH_SIZE + i] = sfdp_session_from_flow_index (
		b[SFDP_PREFETCH_SIZE + i]->flow_id);
	      CLIB_PREFETCH (sfdp->sessions + si[SFDP_PREFETCH_SIZE + i],
			     CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (gm->output + b[SFDP_PREFETCH_SIZE + i]->flow_id,
			     2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    }
	}
      for (int i = 0; i < SFDP_PREFETCH_SIZE; i++)
	{
	  si[i] = sfdp_session_from_flow_index (b[i]->flow_id);
	  session[i] = sfdp_session_at_index (si[i]);
	  geneve_out[i] = vec_elt_at_index (gm->output, b[i]->flow_id);
	  geneve_output_rewrite_one (vm, node, gm, cm, geneve_out[i],
				     session[i], thread_index, si[i],
				     to_next + i, b + i);
	}
      to_next += SFDP_PREFETCH_SIZE;
      b += SFDP_PREFETCH_SIZE;
      n_left -= SFDP_PREFETCH_SIZE;
    }

  while (n_left)
    {
      u32 session_idx = sfdp_session_from_flow_index (b[0]->flow_id);
      sfdp_session_t *session = sfdp_session_at_index (session_idx);
      gw_geneve_output_data_t *geneve_out =
	vec_elt_at_index (gm->output, b[0]->flow_id);

      geneve_output_rewrite_one (vm, node, gm, cm, geneve_out, session,
				 thread_index, session_idx, to_next, b);
      to_next++;
      b++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      n_left = frame->n_vectors;
      b = bufs;
      for (i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sfdp_geneve_output_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->flow_id = b[0]->flow_id;
	      t->encap_size = gm->output[b[0]->flow_id].encap_size;
	      clib_memcpy_fast (t->encap_data,
				gm->output[b[0]->flow_id].encap_data,
				gm->output[b[0]->flow_id].encap_size);
	      b++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (sfdp_geneve_output_node) = {
  .name = "sfdp-geneve-output",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_geneve_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_geneve_output_error_strings),
  .error_strings = sfdp_geneve_output_error_strings,

  .n_next_nodes = SFDP_GENEVE_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(n, x) [SFDP_GENEVE_OUTPUT_NEXT_##n] = x,
          foreach_sfdp_geneve_output_next
#undef _
  }

};

SFDP_SERVICE_DEFINE (geneve_output) = {
  .node_name = "sfdp-geneve-output",
  .runs_before = SFDP_SERVICES (0),
  .runs_after = SFDP_SERVICES ("sfdp-drop", "sfdp-l4-lifecycle",
			       "sfdp-tcp-check"),
  .is_terminal = 1
};