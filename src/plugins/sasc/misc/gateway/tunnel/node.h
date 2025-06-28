// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_tunnel_node_h
#define included_vcdp_tunnel_node_h

#include <vlib/vlib.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vnet/feature/feature.h>
#include <gateway/gateway.h>
#include <vcdp/common.h>
#include "vxlan_packet.h"
#include <vpp_plugins/geneve/geneve_packet.h>
#include "tunnel.h"
#include <gateway/gateway.api_enum.h>

static inline u8 *
format_vcdp_tunnel_decap_trace(u8 *s, va_list *args)
{
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  vcdp_tunnel_trace_t *t = va_arg(*args, vcdp_tunnel_trace_t *);

  if (t->lookup_rv == 0)
    s = format(s, "tunnel-decap: tunnel_index %d, tenant %d, next-index: %d error index: %d",
               t->tunnel_index, t->tenant_index, t->next_index, t->error_index);
  else
    s = format(s, "tunnel-decap: not a tunnel rv: %d", t->lookup_rv);
  return s;
}

static inline u8 *
format_vcdp_tunnel_encap_trace(u8 *s, va_list *args)
{
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  vcdp_tunnel_trace_t *t = va_arg(*args, vcdp_tunnel_trace_t *);

  s = format(s, "tunnel-encap: tunnel_index %d, tenant %d, next-index: %d error index: %d",
              t->tunnel_index, t->tenant_index, t->next_index, t->error_index);
  return s;
}

// Next nodes
typedef enum {
  VCDP_TUNNEL_INPUT_NEXT_DROP,
  VCDP_TUNNEL_INPUT_NEXT_IP4_LOOKUP,
  VCDP_TUNNEL_INPUT_N_NEXT
} vcdp_tunnel_input_next_t;

// Graph node for VXLAN and Geneve tunnel decap
static inline uword
vcdp_tunnel_input_node_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_tunnel_main_t *tm = &vcdp_tunnel_main;
  u32 thread_index = vm->thread_index;
  u32 n_left_from, *from;
  u16 nexts[VLIB_FRAME_SIZE] = {0}, *next = nexts;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_tenant_t *tenant;
  u32 tunnel_indicies[VLIB_FRAME_SIZE] = {0},
      *tunnel_idx = tunnel_indicies; // Used only for tracing
  u16 tenant_indicies[VLIB_FRAME_SIZE] = {0},
      *tenant_idx = tenant_indicies; // Used only for tracing
  int lookup_rvs[VLIB_FRAME_SIZE] = {0},
      *lookup_rv = lookup_rvs; // Used only for tracing

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers(vm, from, b, n_left_from);

  while (n_left_from > 0) {
    /* By default pass packet to next node in the feature chain */
    vnet_feature_next_u16(next, b[0]);
    b[0]->error = 0;

    // Do we have enough bytes to do the lookup?
    // No support for reassembly so pass-through for non-first fragments
    ip4_header_t *ip = (ip4_header_t *) vlib_buffer_get_current(b[0]);
    u16 min_lookup_bytes = ip4_header_bytes(ip) + sizeof(udp_header_t);
    if (vlib_buffer_has_space(b[0], min_lookup_bytes) == 0 || ip4_is_fragment(ip)) {
      goto next;
    }
    u16 orglen = vlib_buffer_length_in_chain(vm, b[0]);

    udp_header_t *udp = ip4_next_header(ip);
    u32 context_id = 0;
    u64 value;
    int rv = vcdp_tunnel_lookup(context_id, ip->dst_address, ip->src_address, ip->protocol, 0, udp->dst_port, &value);
    lookup_rv[0] = rv;
    if (rv != 0) {
      // Silently ignore lookup failures, might not have been a tunnel packet.
      goto next;
    }

    vcdp_tunnel_t *t = pool_elt_at_index(vcdp_tunnel_main.tunnels, value);
    u16 bytes_to_inner_ip;
    u32 vni;
    *tunnel_idx = value;

    switch (t->method) {

    case VL_API_VCDP_TUNNEL_GENEVE_L3:
      bytes_to_inner_ip = ip4_header_bytes(ip) + sizeof(udp_header_t) + sizeof(geneve_header_t);
      if (vlib_buffer_has_space(b[0], bytes_to_inner_ip + 28) == 0) {
        next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
        b[0]->error = node->errors[VCDP_TUNNEL_INPUT_ERROR_TRUNCATED];
        goto next;
      }
      geneve_header_t *geneve = (geneve_header_t *) (udp + 1);
      if (vnet_get_geneve_options_len(geneve) != 0) {
        next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
        goto next;
      }
      vni = vnet_get_geneve_vni(geneve);
      if (vnet_get_geneve_protocol(geneve) != ETHERNET_TYPE_IP4) {
        next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
        goto next;
      }
      break;

    case VL_API_VCDP_TUNNEL_VXLAN_DUMMY_L2:
      bytes_to_inner_ip =
        ip4_header_bytes(ip) + sizeof(udp_header_t) + sizeof(vxlan_header_t) + sizeof(ethernet_header_t);
      if (vlib_buffer_has_space(b[0], bytes_to_inner_ip + 28) == 0) {
        next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
        b[0]->error = node->errors[VCDP_TUNNEL_INPUT_ERROR_TRUNCATED];
        goto next;
      }
      vxlan_header_t *vxlan = (vxlan_header_t *) (udp + 1);
      vni = vnet_get_vni(vxlan);
      ethernet_header_t *eth = (ethernet_header_t *) (vxlan + 1);
      if (clib_net_to_host_u16(eth->type) != ETHERNET_TYPE_IP4) {
        next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
        b[0]->error = node->errors[VCDP_TUNNEL_INPUT_ERROR_NOT_SUPPORTED];
        goto next;
      }
      break;

    default:
      // unknown tunnel type
      next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
      b[0]->error = node->errors[VCDP_TUNNEL_INPUT_ERROR_NOT_SUPPORTED];
      goto next;
    }

    // Two choices. Either a tunnel can be hardcoded with a tenant or the VNI is
    // used as tenant id. ignoring VNI for NATaaS / SWG integration
    u32 tenant_id = t->tenant_id == ~0 ? (u64) vni : t->tenant_id;
    tenant = vcdp_tenant_get_by_id(tenant_id, tenant_idx);
    if (!tenant) {
      next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
      b[0]->error = node->errors[VCDP_TUNNEL_INPUT_ERROR_NO_TENANT];
      goto next;
    }

    /* Store context_id as flow_id (to simplify the future lookup) */
    vcdp_buffer(b[0])->context_id = tenant->context_id;

    vlib_buffer_advance(b[0], bytes_to_inner_ip);
    vcdp_buffer(b[0])->tenant_index = *tenant_idx;
    vcdp_buffer(b[0])->rx_id = value; // Store tunnel index in buffer

    next[0] = VCDP_TUNNEL_INPUT_NEXT_IP4_LOOKUP;
    vlib_increment_combined_counter(&tm->combined_counters[VCDP_TUNNEL_COUNTER_RX], thread_index, tunnel_idx[0], 1, orglen);

  next:
    next += 1;
    n_left_from -= 1;
    b += 1;
    tunnel_idx += 1;
    tenant_idx += 1;
    lookup_rv += 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    tunnel_idx = tunnel_indicies;
    tenant_idx = tenant_indicies;
    lookup_rv = lookup_rvs;
    next = nexts;
    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_tunnel_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->is_encap = false;
        t->tunnel_index = tunnel_idx[0];
        t->tenant_index = tenant_idx[0];
        t->next_index = next[0];
        t->error_index = b[0]->error;
        t->lookup_rv = lookup_rv[0];
        b++;
        tunnel_idx++;
        tenant_idx++;
        lookup_rv++;
        next++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

// Encapsulation
typedef struct {
  u32 next_index;
  u32 sw_if_index;
} vcdp_tunnel_output_trace_t;

// Next nodes
typedef enum {
  VCDP_TUNNEL_OUTPUT_NEXT_DROP,
  VCDP_TUNNEL_OUTPUT_NEXT_IP4_LOOKUP,
  VCDP_TUNNEL_OUTPUT_NEXT_ICMP_ERROR,
  VCDP_TUNNEL_OUTPUT_N_NEXT
} vcdp_tunnel_output_next_t;

static void
vcdp_vxlan_dummy_l2_fixup(vlib_main_t *vm, vlib_buffer_t *b, ip4_header_t *inner_ip)
{
  ip4_header_t *ip;
  udp_header_t *udp;

  ip = vlib_buffer_get_current(b);
  u16 len = vlib_buffer_length_in_chain(vm, b);

  ip->length = clib_host_to_net_u16(len);
  ip->checksum = ip4_header_checksum(ip);
  udp = (udp_header_t *) (ip + 1);
  udp->length = clib_host_to_net_u16(len - sizeof(ip4_header_t));
  if (udp->src_port == 0) {
    udp->src_port = inner_ip->src_address.as_u32 ^ inner_ip->dst_address.as_u32;
    udp->src_port |= clib_host_to_net_u16(0xC000);
  }
}

static inline uword
vcdp_tunnel_output_node_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_tunnel_main_t *tm = &vcdp_tunnel_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 tunnel_indicies[VLIB_FRAME_SIZE] = {0},
      *tunnel_idx = tunnel_indicies; // Used only for tracing
  u16 tenant_indicies[VLIB_FRAME_SIZE] = {0},
      *tenant_idx = tenant_indicies; // Used only for tracing

  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;

  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers(vm, from, bufs, n_left);

  while (n_left > 0) {
    u32 session_idx = vcdp_session_from_flow_index(b[0]->flow_id);
    vcdp_session_t *session = vcdp_session_at_index(vcdp, session_idx);
    vcdp_tunnel_t *t = vcdp_tunnel_get(session->rx_id);
    tunnel_idx[0] = session->rx_id;
    tenant_idx[0] = session->tenant_idx;
    if (t == 0) {
      to_next[0] = VCDP_TUNNEL_OUTPUT_NEXT_DROP;
      b[0]->error = node->errors[VCDP_TUNNEL_OUTPUT_ERROR_NO_TENANT];
      goto done;
    }
    b[0]->flags |= (VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
    vnet_buffer(b[0])->oflags |= VNET_BUFFER_OFFLOAD_F_UDP_CKSUM | VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
    ip4_header_t *inner_ip = vlib_buffer_get_current(b[0]);

    /*
     * If the ttl drops below 1 when forwarding, generate
     * an ICMP response.
     */
    i32 ttl = inner_ip->ttl;
    u32 checksum = inner_ip->checksum + clib_host_to_net_u16 (0x0100);
    checksum += checksum >= 0xffff;
    inner_ip->checksum = checksum;
    ttl -= 1;
    inner_ip->ttl = ttl;

    if (PREDICT_FALSE(ttl <= 0)) {
      b[0]->error = node->errors[VCDP_TUNNEL_OUTPUT_ERROR_TIME_EXPIRED];
      vnet_buffer(b[0])->sw_if_index[VLIB_TX] = (u32) ~0;
      icmp4_error_set_vnet_buffer(b[0], ICMP4_time_exceeded, ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
      to_next[0] = VCDP_TUNNEL_OUTPUT_NEXT_ICMP_ERROR;
      goto done;
    }

    vlib_buffer_advance(b[0], -t->encap_size);
    ip4_header_t *ip = vlib_buffer_get_current(b[0]);
    vnet_buffer(b[0])->l3_hdr_offset = b[0]->current_data;
    vnet_buffer(b[0])->l4_hdr_offset = b[0]->current_data + sizeof(ip4_header_t);
    clib_memcpy_fast(ip, t->rewrite, t->encap_size);
    vcdp_vxlan_dummy_l2_fixup(vm, b[0], inner_ip);
    to_next[0] = VCDP_TUNNEL_OUTPUT_NEXT_IP4_LOOKUP;

    vlib_increment_combined_counter(&tm->combined_counters[VCDP_TUNNEL_COUNTER_TX], thread_index, tunnel_idx[0], 1,
                                    vlib_buffer_length_in_chain(vm, b[0]));

  done:
    to_next++;
    b++;
    n_left--;
    tunnel_idx += 1;
    tenant_idx += 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    tunnel_idx = tunnel_indicies;
    tenant_idx = tenant_indicies;
    for (i = 0; i < frame->n_vectors; i++) {
      // TODO: Add more details
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_tunnel_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->is_encap = true;
        t->tunnel_index = tunnel_idx[0];
        t->tenant_index = tenant_idx[0];
        b++;
        tunnel_idx++;
        tenant_idx++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

#endif