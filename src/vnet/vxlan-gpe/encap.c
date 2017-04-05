/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/**
 *  @file
 *  @brief Functions for encapsulating VXLAN GPE tunnels
 *
*/
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>

/** Statistics (not really errors) */
#define foreach_vxlan_gpe_encap_error    \
_(ENCAPSULATED, "good packets encapsulated")

/**
 * @brief VXLAN GPE encap error strings
 */
static char * vxlan_gpe_encap_error_strings[] = {
#define _(sym,string) string,
  foreach_vxlan_gpe_encap_error
#undef _
};

/**
 * @brief Struct for VXLAN GPE errors/counters
 */
typedef enum {
#define _(sym,str) VXLAN_GPE_ENCAP_ERROR_##sym,
    foreach_vxlan_gpe_encap_error
#undef _
    VXLAN_GPE_ENCAP_N_ERROR,
} vxlan_gpe_encap_error_t;

/**
 * @brief Struct for tracing VXLAN GPE encapsulated packets
 */
typedef struct {
  u32 tunnel_index;
} vxlan_gpe_encap_trace_t;

/**
 * @brief Trace of packets encapsulated in VXLAN GPE
 *
 * @param *s
 * @param *args
 *
 * @return *s
 *
 */
u8 * format_vxlan_gpe_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vxlan_gpe_encap_trace_t * t
      = va_arg (*args, vxlan_gpe_encap_trace_t *);

  s = format (s, "VXLAN-GPE-ENCAP: tunnel %d", t->tunnel_index);
  return s;
}

/**
 * @brief Instantiates UDP + VXLAN-GPE header then set next node to IP4|6 lookup
 *
 * @param *ngm
 * @param *b0
 * @param *t0 contains rewrite header
 * @param *next0 relative index of next dispatch function (next node)
 * @param is_v4 Is this IPv4? (or IPv6)
 *
 */
always_inline void
vxlan_gpe_encap_one_inline (vxlan_gpe_main_t * ngm, vlib_buffer_t * b0,
                            vxlan_gpe_tunnel_t * t0, u32 * next0,
                            u8 is_v4)
{
  ASSERT(sizeof(ip4_vxlan_gpe_header_t) == 36);
  ASSERT(sizeof(ip6_vxlan_gpe_header_t) == 56);

  ip_udp_encap_one (ngm->vlib_main, b0, t0->rewrite, t0->rewrite_size, is_v4);
  next0[0] = t0->encap_next_node;
}

/**
 * @brief Instantiates UDP + VXLAN-GPE header then set next node to IP4|6 lookup for two packets
 *
 * @param *ngm
 * @param *b0 Packet0
 * @param *b1 Packet1
 * @param *t0 contains rewrite header for Packet0
 * @param *t1 contains rewrite header for Packet1
 * @param *next0 relative index of next dispatch function (next node) for Packet0
 * @param *next1 relative index of next dispatch function (next node) for Packet1
 * @param is_v4 Is this IPv4? (or IPv6)
 *
 */
always_inline void
vxlan_gpe_encap_two_inline (vxlan_gpe_main_t * ngm, vlib_buffer_t * b0,
                            vlib_buffer_t * b1, vxlan_gpe_tunnel_t * t0,
                            vxlan_gpe_tunnel_t * t1, u32 * next0,
                            u32 * next1, u8 is_v4)
{
  ASSERT(sizeof(ip4_vxlan_gpe_header_t) == 36);
  ASSERT(sizeof(ip6_vxlan_gpe_header_t) == 56);

  ip_udp_encap_one (ngm->vlib_main, b0, t0->rewrite, t0->rewrite_size, is_v4);
  ip_udp_encap_one (ngm->vlib_main, b1, t1->rewrite, t1->rewrite_size, is_v4);
  next0[0] = next1[0] = t0->encap_next_node;
}

/**
 * @brief Common processing for IPv4 and IPv6 VXLAN GPE encap dispatch functions
 *
 * It is worth noting that other than trivial UDP forwarding (transit), VXLAN GPE
 * tunnels are "establish local". This means that we don't have a TX interface as yet
 * as we need to look up where the outer-header dest is. By setting the TX index in the
 * buffer metadata to the encap FIB, we can do a lookup to get the adjacency and real TX.
 *
 *      vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->encap_fib_index;
 *
 * @node vxlan-gpe-input
 * @param *vm
 * @param *node
 * @param *from_frame
 *
 * @return from_frame->n_vectors
 *
 */
static uword
vxlan_gpe_encap (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  vxlan_gpe_main_t * ngm = &vxlan_gpe_main;
  vnet_main_t * vnm = ngm->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 pkts_encapsulated = 0;
  u32 thread_index = vlib_get_thread_index ();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
  {
    u32 n_left_to_next;

    vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from >= 4 && n_left_to_next >= 2)
    {
      u32 bi0, bi1;
      vlib_buffer_t * b0, *b1;
      u32 next0, next1;
      u32 sw_if_index0, sw_if_index1, len0, len1;
      vnet_hw_interface_t * hi0, *hi1;
      vxlan_gpe_tunnel_t * t0, *t1;
      u8 is_ip4_0, is_ip4_1;

      next0 = next1 = VXLAN_GPE_ENCAP_NEXT_IP4_LOOKUP;

      /* Prefetch next iteration. */
      {
        vlib_buffer_t * p2, *p3;

        p2 = vlib_get_buffer (vm, from[2]);
        p3 = vlib_get_buffer (vm, from[3]);

        vlib_prefetch_buffer_header(p2, LOAD);
        vlib_prefetch_buffer_header(p3, LOAD);

        CLIB_PREFETCH(p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
        CLIB_PREFETCH(p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
      }

      bi0 = from[0];
      bi1 = from[1];
      to_next[0] = bi0;
      to_next[1] = bi1;
      from += 2;
      to_next += 2;
      n_left_to_next -= 2;
      n_left_from -= 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      /* 1-wide cache? */
      sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_TX];
      sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_TX];
      hi0 = vnet_get_sup_hw_interface (vnm, vnet_buffer(b0)->sw_if_index[VLIB_TX]);
      hi1 = vnet_get_sup_hw_interface (vnm, vnet_buffer(b1)->sw_if_index[VLIB_TX]);

      t0 = pool_elt_at_index(ngm->tunnels, hi0->dev_instance);
      t1 = pool_elt_at_index(ngm->tunnels, hi1->dev_instance);

      is_ip4_0 = (t0->flags & VXLAN_GPE_TUNNEL_IS_IPV4);
      is_ip4_1 = (t1->flags & VXLAN_GPE_TUNNEL_IS_IPV4);

      if (PREDICT_TRUE(is_ip4_0 == is_ip4_1))
      {
        vxlan_gpe_encap_two_inline (ngm, b0, b1, t0, t1, &next0, &next1,is_ip4_0);
      }
      else
      {
        vxlan_gpe_encap_one_inline (ngm, b0, t0, &next0, is_ip4_0);
        vxlan_gpe_encap_one_inline (ngm, b1, t1, &next1, is_ip4_1);
      }

      /* Reset to look up tunnel partner in the configured FIB */
      vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->encap_fib_index;
      vnet_buffer(b1)->sw_if_index[VLIB_TX] = t1->encap_fib_index;
      vnet_buffer(b0)->sw_if_index[VLIB_RX] = sw_if_index0;
      vnet_buffer(b1)->sw_if_index[VLIB_RX] = sw_if_index1;
      pkts_encapsulated += 2;

      len0 = vlib_buffer_length_in_chain (vm, b0);
      len1 = vlib_buffer_length_in_chain (vm, b0);
      stats_n_packets += 2;
      stats_n_bytes += len0 + len1;

      /* Batch stats increment on the same vxlan tunnel so counter is not
       incremented per packet. Note stats are still incremented for deleted
       and admin-down tunnel where packets are dropped. It is not worthwhile
       to check for this rare case and affect normal path performance. */
      if (PREDICT_FALSE((sw_if_index0 != stats_sw_if_index)
              || (sw_if_index1 != stats_sw_if_index)))
      {
        stats_n_packets -= 2;
        stats_n_bytes -= len0 + len1;
        if (sw_if_index0 == sw_if_index1)
        {
          if (stats_n_packets)
            vlib_increment_combined_counter (
                im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
                thread_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
          stats_sw_if_index = sw_if_index0;
          stats_n_packets = 2;
          stats_n_bytes = len0 + len1;
        }
        else
        {
          vlib_increment_combined_counter (
              im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
              thread_index, sw_if_index0, 1, len0);
          vlib_increment_combined_counter (
              im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
              thread_index, sw_if_index1, 1, len1);
        }
      }

      if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
      {
        vxlan_gpe_encap_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof(*tr));
        tr->tunnel_index = t0 - ngm->tunnels;
      }

      if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
      {
        vxlan_gpe_encap_trace_t *tr = vlib_add_trace (vm, node, b1,
                                                      sizeof(*tr));
        tr->tunnel_index = t1 - ngm->tunnels;
      }

      vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                                      n_left_to_next, bi0, bi1, next0, next1);
    }

    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      u32 next0 = VXLAN_GPE_ENCAP_NEXT_IP4_LOOKUP;
      u32 sw_if_index0, len0;
      vnet_hw_interface_t * hi0;
      vxlan_gpe_tunnel_t * t0;
      u8 is_ip4_0;

      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      /* 1-wide cache? */
      sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_TX];
      hi0 = vnet_get_sup_hw_interface (vnm, vnet_buffer(b0)->sw_if_index[VLIB_TX]);

      t0 = pool_elt_at_index(ngm->tunnels, hi0->dev_instance);

      is_ip4_0 = (t0->flags & VXLAN_GPE_TUNNEL_IS_IPV4);

      vxlan_gpe_encap_one_inline (ngm, b0, t0, &next0, is_ip4_0);

      /* Reset to look up tunnel partner in the configured FIB */
      vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->encap_fib_index;
      vnet_buffer(b0)->sw_if_index[VLIB_RX] = sw_if_index0;
      pkts_encapsulated++;

      len0 = vlib_buffer_length_in_chain (vm, b0);
      stats_n_packets += 1;
      stats_n_bytes += len0;

      /* Batch stats increment on the same vxlan tunnel so counter is not
       *  incremented per packet. Note stats are still incremented for deleted
       *  and admin-down tunnel where packets are dropped. It is not worthwhile
       *  to check for this rare case and affect normal path performance. */
      if (PREDICT_FALSE(sw_if_index0 != stats_sw_if_index))
      {
        stats_n_packets -= 1;
        stats_n_bytes -= len0;
        if (stats_n_packets)
          vlib_increment_combined_counter (
              im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
              thread_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
        stats_n_packets = 1;
        stats_n_bytes = len0;
        stats_sw_if_index = sw_if_index0;
      }
      if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
      {
        vxlan_gpe_encap_trace_t *tr = vlib_add_trace (vm, node, b0,
                                                      sizeof(*tr));
        tr->tunnel_index = t0 - ngm->tunnels;
      }
      vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                      n_left_to_next, bi0, next0);
    }

    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  vlib_node_increment_counter (vm, node->node_index,
                               VXLAN_GPE_ENCAP_ERROR_ENCAPSULATED,
                               pkts_encapsulated);
  /* Increment any remaining batch stats */
  if (stats_n_packets)
  {
    vlib_increment_combined_counter (
        im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX, thread_index,
        stats_sw_if_index, stats_n_packets, stats_n_bytes);
    node->runtime_data[0] = stats_sw_if_index;
  }

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (vxlan_gpe_encap_node) = {
  .function = vxlan_gpe_encap,
  .name = "vxlan-gpe-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_vxlan_gpe_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vxlan_gpe_encap_error_strings),
  .error_strings = vxlan_gpe_encap_error_strings,

  .n_next_nodes = VXLAN_GPE_ENCAP_N_NEXT,

  .next_nodes = {
    [VXLAN_GPE_ENCAP_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [VXLAN_GPE_ENCAP_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [VXLAN_GPE_ENCAP_NEXT_DROP] = "error-drop",
  },
};

