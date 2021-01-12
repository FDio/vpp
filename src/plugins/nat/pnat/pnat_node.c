/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

/*
 * Policy NAT.
 * Match packet against rule in a hash and translate according to given instructions.
 * Rules are kept in a flow-cache bihash. Instructions in a pool of translation entries.
 *
 * All rules for a given interface/direction must use the same lookup pattern. E.g. SA+SP.
 *
 * A dynamic NAT would punt to slow path on a miss in the flow cache, in this case the miss behaviour is configurable.
 * Default behaviour is pass packet along unchanged.
 *
 * The data structures are shared and assuming that updates to the tables are rare. Data-structures are protected
 * depending on the API/CLI barriers.
 */

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/clib_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/fib/ip4_fib.h>
#include "pnat.h"
#include <pnat/pnat.api_enum.h>  /* For error counters */

/* PNAT next-nodes */
typedef enum {
  PNAT_NEXT_DROP,
  PNAT_N_NEXT
} pnat_next_t;

/* Packet trace information */
typedef struct {
  u32 pool_index;
  pnat_5tuple_t match;
  pnat_5tuple_t rewrite;
  u32 trace_index;
} pnat_trace_t;

u8 *format_pnat_key (u8 * s, va_list * args);
u8 *format_pnat_5tuple (u8 * s, va_list * args);
static u8 *
format_pnat_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pnat_trace_t *t = va_arg (*args, pnat_trace_t *);

  s = format(s, "pnat: index %d\n", t->pool_index);
  if (t->pool_index != ~0) {
    s = format(s, "        match: %U\n", format_pnat_5tuple, &t->match);
    s = format(s, "        rewrite: %U", format_pnat_5tuple, &t->rewrite);
  }
  return s;
}

/*
 * Given a packet and rewrite instructions from a translation modify packet.
 */
static u32
rewrite (u32 pool_index, ip4_header_t *ip)
{
  pnat_main_t *pm = &pnat_main;
  if (pool_is_free_index(pm->translations, pool_index)) {
    return PNAT_ERROR_REWRITE;
  }
  pnat_translation_t *t = pool_elt_at_index (pm->translations, pool_index);

  /* Calculate the checksum delta for the header (could be done at configuration time */
  ip_csum_t csumd = 0;

  if (t->instructions & PNAT_INSTR_DESTINATION_ADDRESS) {
    csumd = ip_csum_sub_even(csumd, ip->dst_address.as_u32);
    csumd = ip_csum_add_even(csumd, t->post_da.as_u32);
    ip->dst_address = t->post_da;
  }
  if (t->instructions & PNAT_INSTR_SOURCE_ADDRESS) {
    csumd = ip_csum_sub_even(csumd, ip->src_address.as_u32);
    csumd = ip_csum_add_even(csumd, t->post_sa.as_u32);
    ip->src_address = t->post_sa;
  }

  ip_csum_t csum = ip->checksum;
  csum = ip_csum_sub_even(csum, csumd);
  ip->checksum = ip_csum_fold(csum);
  ASSERT (ip->checksum == ip4_header_checksum (ip));

  /* L4 ports */
  if (ip->protocol == IP_PROTOCOL_TCP) {
    tcp_header_t *tcp = ip4_next_header (ip);
    ip_csum_t l4csum = tcp->checksum;
    if (t->instructions & PNAT_INSTR_DESTINATION_PORT) {
      l4csum = ip_csum_sub_even(l4csum, tcp->dst_port);
      l4csum = ip_csum_add_even(l4csum, clib_net_to_host_u16(t->post_dp));
      tcp->dst_port = clib_net_to_host_u16(t->post_dp);
    }
    if (t->instructions & PNAT_INSTR_SOURCE_PORT) {
      l4csum = ip_csum_sub_even(l4csum, tcp->src_port);
      l4csum = ip_csum_add_even(l4csum, clib_net_to_host_u16(t->post_sp));
      tcp->src_port = clib_net_to_host_u16(t->post_sp);
    }
    l4csum = ip_csum_sub_even(l4csum, csumd);
    tcp->checksum = ip_csum_fold(l4csum);
  } else if (ip->protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = ip4_next_header (ip);
    ip_csum_t l4csum = udp->checksum;
    if (t->instructions & PNAT_INSTR_DESTINATION_PORT) {
      l4csum = ip_csum_sub_even(l4csum, udp->dst_port);
      l4csum = ip_csum_add_even(l4csum, clib_net_to_host_u16(t->post_dp));
      udp->dst_port = clib_net_to_host_u16(t->post_dp);
    }
    if (t->instructions & PNAT_INSTR_SOURCE_PORT) {
      l4csum = ip_csum_sub_even(l4csum, udp->src_port);
      l4csum = ip_csum_add_even(l4csum, clib_net_to_host_u16(t->post_sp));
      udp->src_port = clib_net_to_host_u16(t->post_sp);
    }
    if (udp->checksum) {
      l4csum = ip_csum_sub_even(l4csum, csumd);
      udp->checksum = ip_csum_fold(l4csum);
    }
  }
  return 0;
}

/*
 * Create a hash key from a packet given the lookup mask.
 */
static inline void
pnat_calc_key (u32 sw_if_index, bool input, pnat_mask_t lookup_mask,
               ip4_header_t *ip, u16 sport, u16 dport, pnat_key_t *k)
{
  k->as_u64[0] = k->as_u64[1] = 0;
  if (lookup_mask & PNAT_SA)
    clib_memcpy_fast(&k->sa, &ip->src_address, 4);
  if (lookup_mask & PNAT_DA)
    clib_memcpy_fast(&k->da, &ip->dst_address, 4);
  k->proto = ip->protocol;
  k->sw_if_index = sw_if_index;
  k->input = input;
  if (lookup_mask & PNAT_SPORT)
    k->sp = clib_net_to_host_u16(sport);
  if (lookup_mask & PNAT_DPORT)
    k->dp = clib_net_to_host_u16(dport);
}

/*
 * Lookup the packet tuple in the flow cache, given the lookup mask.
 * If a binding is found, rewrite the packet according to instructions,
 * otherwise follow configured default action (forward, punt or drop)
 */
static_always_inline uword
pnat_node_inline (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame,
                  bool input)
{
  pnat_main_t *pm = &pnat_main;

  u16 *next;

  u32 n_left_from, *from;
  u16 nexts[VLIB_FRAME_SIZE] = { 0 };
  u32 to_buffers[VLIB_FRAME_SIZE], *tb = to_buffers;
  u32 pool_indicies[VLIB_FRAME_SIZE], *pi = pool_indicies;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  pnat_key_t keys[VLIB_FRAME_SIZE], *k = keys;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;

  u32 *bi;
  ip4_header_t *ip0;
  clib_bihash_kv_16_8_t kv;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, b, n_left_from);

  /* Stage 1: build vector of flow hash (based on lookup mask) */
  while (n_left_from > 0) {
    u32 sw_if_index0 = input ? vnet_buffer (b[0])->sw_if_index[VLIB_RX] : vnet_buffer (b[0])->sw_if_index[VLIB_TX];
    u16 sport0 = vnet_buffer (b[0])->ip.reass.l4_src_port;
    u16 dport0 = vnet_buffer (b[0])->ip.reass.l4_dst_port;
    u32 iph_offset = input ? 0: vnet_buffer (b[0])->ip.reass.save_rewrite_length;
    ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b[0]) + iph_offset);
    pnat_interface_t *interface = pnat_interface_by_sw_if_index(sw_if_index0);
    pnat_mask_t lookup_mask = input ? interface->input_lookup_mask : interface->output_lookup_mask;
    pnat_calc_key(sw_if_index0, input, lookup_mask, ip0, sport0, dport0, k);
    clib_memcpy_fast (&kv.key, k, 16);
    h[0] = clib_bihash_hash_16_8 (&kv);

    b += 1;
    k += 1;
    h += 1;
    n_left_from -= 1;
  }

  n_left_from = frame->n_vectors;
  h = hashes;
  k = keys;
  b = bufs;
  bi = from;
  next = nexts;

  /* Stage 2: Lookup flow cache and rewrite */
  while (n_left_from > 0) {
    u32 errno0 = 0;
    if (PREDICT_TRUE (n_left_from >= 16))
      clib_bihash_prefetch_bucket_16_8 (&pm->flowhash, h[15]);

    if (PREDICT_TRUE (n_left_from >= 8))
      clib_bihash_prefetch_data_16_8 (&pm->flowhash, h[7]);

    clib_memcpy_fast (&kv.key, k, 16);

    /* By default pass packet to next node in the feature chain */
    vnet_feature_next_u16(next, b[0]);

    /* 6-tuple lookup */
    if (clib_bihash_search_inline_with_hash_16_8 (&pm->flowhash, h[0], &kv) == 0) {
      /* Cache hit */
      *pi = kv.value;
      u32 iph_offset = input ? 0: vnet_buffer (b[0])->ip.reass.save_rewrite_length;
      ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b[0]) + iph_offset);
      errno0 = rewrite(kv.value, ip0);
      if (errno0) {
        next[0] = PNAT_NEXT_DROP;
        b[0]->error = node->errors[errno0];
      }
    } else {
      /* Cache miss */
      *pi = ~0;
    }
    tb[0] = bi[0];
    tb += 1;
    next += 1;

    /*next: */
    n_left_from -= 1;
    k += 1;
    h += 1;
    b += 1;
    bi += 1;
    pi += 1;
  }

  /* Packet trace */
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE))) {
    u32 i;
    b = bufs;
    pi = pool_indicies;
    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        pnat_trace_t *t =
          vlib_add_trace (vm, node, b[0], sizeof (*t));
        if (*pi != ~0) {
          pnat_translation_t *tr = pool_elt_at_index (pm->translations, *pi);
          ASSERT(tr);
          t->match = tr->match;
          t->rewrite = tr->rewrite;
        }
        t->pool_index = *pi;
        t->trace_index = vlib_buffer_get_trace_index (b[0]);
        b += 1;
        pi += 1;
      } else
        break;
    }
  }

  vlib_buffer_enqueue_to_next (vm, node, to_buffers, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (pnat_input_node) (vlib_main_t * vm,
                                vlib_node_runtime_t * node,
                                vlib_frame_t * frame)
{
  return pnat_node_inline (vm, node, frame, 1);
}
VLIB_NODE_FN (pnat_output_node) (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  return pnat_node_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (pnat_input_node) = {
  .name = "pnat-input",
  .vector_size = sizeof (u32),
  .format_trace = format_pnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = PNAT_N_ERROR,
  .error_counters = pnat_error_counters,
  .n_next_nodes = PNAT_N_NEXT,
  .next_nodes =
  {
   [PNAT_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (pnat_output_node) = {
  .name = "pnat-output",
  .vector_size = sizeof (u32),
  .format_trace = format_pnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = PNAT_N_ERROR,
  .error_counters = pnat_error_counters,
  .sibling_of = "pnat-input",
};

/* Hook up features */
VNET_FEATURE_INIT (pnat_input, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "pnat-input",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (pnat_output, static) = {
  .arc_name = "ip4-output",
  .node_name = "pnat-output",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa",
                               "ip4-sv-reassembly-output-feature"),
};
