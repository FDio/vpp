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
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>

/* Statistics (not really errors) */
#define foreach_vxlan_gpe_encap_error    \
_(ENCAPSULATED, "good packets encapsulated")

static char * vxlan_gpe_encap_error_strings[] = {
#define _(sym,string) string,
  foreach_vxlan_gpe_encap_error
#undef _
};

typedef enum {
#define _(sym,str) VXLAN_GPE_ENCAP_ERROR_##sym,
    foreach_vxlan_gpe_encap_error
#undef _
    VXLAN_GPE_ENCAP_N_ERROR,
} vxlan_gpe_encap_error_t;

typedef enum {
  VXLAN_GPE_ENCAP_NEXT_IP4_LOOKUP,
  VXLAN_GPE_ENCAP_NEXT_DROP,
  VXLAN_GPE_ENCAP_N_NEXT
} vxlan_gpe_encap_next_t;

typedef struct {
  u32 tunnel_index;
} vxlan_gpe_encap_trace_t;


u8 * format_vxlan_gpe_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vxlan_gpe_encap_trace_t * t 
      = va_arg (*args, vxlan_gpe_encap_trace_t *);

  s = format (s, "VXLAN-GPE-ENCAP: tunnel %d", t->tunnel_index);
  return s;
}

#define foreach_fixed_header_offset             \
_(0) _(1) _(2) _(3) _(4) _(5) _(6)

static uword
vxlan_gpe_encap (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  vxlan_gpe_main_t * ngm = &vxlan_gpe_main;
  vnet_main_t * vnm = ngm->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 pkts_encapsulated = 0;
  u16 old_l0 = 0, old_l1 = 0;
  u32 cpu_index = os_get_cpu_number();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
	  u32 next0 = VXLAN_GPE_ENCAP_NEXT_IP4_LOOKUP;
          u32 next1 = VXLAN_GPE_ENCAP_NEXT_IP4_LOOKUP;
          u32 sw_if_index0, sw_if_index1, len0, len1;
          vnet_hw_interface_t * hi0, * hi1;
          ip4_header_t * ip0, * ip1;
          udp_header_t * udp0, * udp1;
          u64 * copy_src0, * copy_dst0;
          u64 * copy_src1, * copy_dst1;
          u32 * copy_src_last0, * copy_dst_last0;
          u32 * copy_src_last1, * copy_dst_last1;
          vxlan_gpe_tunnel_t * t0, * t1;
          u16 new_l0, new_l1;
          ip_csum_t sum0, sum1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
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
          hi0 = vnet_get_sup_hw_interface
            (vnm, vnet_buffer(b0)->sw_if_index[VLIB_TX]);
          hi1 = vnet_get_sup_hw_interface
            (vnm, vnet_buffer(b1)->sw_if_index[VLIB_TX]);

          t0 = pool_elt_at_index (ngm->tunnels, hi0->dev_instance);
          t1 = pool_elt_at_index (ngm->tunnels, hi1->dev_instance);

          ASSERT(vec_len(t0->rewrite) >= 24);
          ASSERT(vec_len(t1->rewrite) >= 24);

          /* Apply the rewrite string. $$$$ vnet_rewrite? */
          vlib_buffer_advance (b0, -(word)_vec_len(t0->rewrite));
          vlib_buffer_advance (b1, -(word)_vec_len(t1->rewrite));

          ip0 = vlib_buffer_get_current(b0);
          ip1 = vlib_buffer_get_current(b1);
          /* Copy the fixed header */
          copy_dst0 = (u64 *) ip0;
          copy_src0 = (u64 *) t0->rewrite;
          copy_dst1 = (u64 *) ip1;
          copy_src1 = (u64 *) t1->rewrite;

          ASSERT (sizeof (ip4_vxlan_gpe_header_t) == 36);

          /* Copy first 36 octets 8-bytes at a time */
#define _(offs) copy_dst0[offs] = copy_src0[offs];
          foreach_fixed_header_offset;
#undef _
#define _(offs) copy_dst1[offs] = copy_src1[offs];
          foreach_fixed_header_offset;
#undef _

          /* Last 4 octets. Hopefully gcc will be our friend */
          copy_dst_last0 = (u32 *)(&copy_dst0[7]);
          copy_src_last0 = (u32 *)(&copy_src0[7]);
          copy_dst_last1 = (u32 *)(&copy_dst1[7]);
          copy_src_last1 = (u32 *)(&copy_src1[7]);
          
          copy_dst_last0[0] = copy_src_last0[0];
          copy_dst_last1[0] = copy_src_last1[0];

          /* If there are TLVs to copy, do so */
          if (PREDICT_FALSE (_vec_len(t0->rewrite) > 64))
            clib_memcpy (&copy_dst0[3], t0->rewrite + 64 , 
                    _vec_len (t0->rewrite)-64);

          if (PREDICT_FALSE (_vec_len(t1->rewrite) > 64))
            clib_memcpy (&copy_dst0[3], t1->rewrite + 64 , 
                    _vec_len (t1->rewrite)-64);

          /* fix the <bleep>ing outer-IP checksum */
          sum0 = ip0->checksum;
          /* old_l0 always 0, see the rewrite setup */
          new_l0 = 
            clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
          
          sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
                                 length /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);
          ip0->length = new_l0;

          sum1 = ip1->checksum;
          /* old_l1 always 0, see the rewrite setup */
          new_l1 = 
            clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b1));
          
          sum1 = ip_csum_update (sum1, old_l1, new_l1, ip4_header_t,
                                 length /* changed member */);
          ip1->checksum = ip_csum_fold (sum1);
          ip1->length = new_l1;
          
          /* Fix UDP length */
          udp0 = (udp_header_t *)(ip0+1);
          new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
                                         - sizeof (*ip0));
          udp1 = (udp_header_t *)(ip1+1);
          new_l1 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b1)
                                         - sizeof (*ip1));

          udp0->length = new_l0;
          udp1->length = new_l1;

          /* Reset to look up tunnel partner in the configured FIB */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->encap_fib_index;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = t1->encap_fib_index;
          vnet_buffer(b0)->sw_if_index[VLIB_RX] = sw_if_index0;
          vnet_buffer(b1)->sw_if_index[VLIB_RX] = sw_if_index1;
          pkts_encapsulated += 2;

          len0 = vlib_buffer_length_in_chain(vm, b0);
          len1 = vlib_buffer_length_in_chain(vm, b0);
          stats_n_packets += 2;
          stats_n_bytes += len0 + len1;

          /* Batch stats increment on the same vxlan tunnel so counter is not
           incremented per packet. Note stats are still incremented for deleted
           and admin-down tunnel where packets are dropped. It is not worthwhile
           to check for this rare case and affect normal path performance. */
          if (PREDICT_FALSE(
              (sw_if_index0 != stats_sw_if_index)
                  || (sw_if_index1 != stats_sw_if_index))) {
            stats_n_packets -= 2;
            stats_n_bytes -= len0 + len1;
            if (sw_if_index0 == sw_if_index1) {
              if (stats_n_packets)
                vlib_increment_combined_counter(
                    im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
                    cpu_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
              stats_sw_if_index = sw_if_index0;
              stats_n_packets = 2;
              stats_n_bytes = len0 + len1;
            } else {
              vlib_increment_combined_counter(
                  im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
                  cpu_index, sw_if_index0, 1, len0);
              vlib_increment_combined_counter(
                  im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
                  cpu_index, sw_if_index1, 1, len1);
            }
          }

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              vxlan_gpe_encap_trace_t *tr =
                vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->tunnel_index = t0 - ngm->tunnels;
            }

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
              vxlan_gpe_encap_trace_t *tr =
                vlib_add_trace (vm, node, b1, sizeof (*tr));
              tr->tunnel_index = t1 - ngm->tunnels;
            }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
	  u32 next0 = VXLAN_GPE_ENCAP_NEXT_IP4_LOOKUP;
	  u32 sw_if_index0, len0;
          vnet_hw_interface_t * hi0;
          ip4_header_t * ip0;
          udp_header_t * udp0;
          u64 * copy_src0, * copy_dst0;
          u32 * copy_src_last0, * copy_dst_last0;
          vxlan_gpe_tunnel_t * t0;
          u16 new_l0;
          ip_csum_t sum0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          /* 1-wide cache? */
	  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_TX];
          hi0 = vnet_get_sup_hw_interface
            (vnm, vnet_buffer(b0)->sw_if_index[VLIB_TX]);

          t0 = pool_elt_at_index (ngm->tunnels, hi0->dev_instance);

          ASSERT(vec_len(t0->rewrite) >= 24);

          /* Apply the rewrite string. $$$$ vnet_rewrite? */
          vlib_buffer_advance (b0, -(word)_vec_len(t0->rewrite));

          ip0 = vlib_buffer_get_current(b0);
          /* Copy the fixed header */
          copy_dst0 = (u64 *) ip0;
          copy_src0 = (u64 *) t0->rewrite;

          ASSERT (sizeof (ip4_vxlan_gpe_header_t) == 36);

          /* Copy first 36 octets 8-bytes at a time */
#define _(offs) copy_dst0[offs] = copy_src0[offs];
          foreach_fixed_header_offset;
#undef _
          /* Last 4 octets. Hopefully gcc will be our friend */
          copy_dst_last0 = (u32 *)(&copy_dst0[7]);
          copy_src_last0 = (u32 *)(&copy_src0[7]);
          
          copy_dst_last0[0] = copy_src_last0[0];

          /* If there are TLVs to copy, do so */
          if (PREDICT_FALSE (_vec_len(t0->rewrite) > 64))
            clib_memcpy (&copy_dst0[3], t0->rewrite + 64 , 
                    _vec_len (t0->rewrite)-64);

          /* fix the <bleep>ing outer-IP checksum */
          sum0 = ip0->checksum;
          /* old_l0 always 0, see the rewrite setup */
          new_l0 = 
            clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
          
          sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
                                 length /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);
          ip0->length = new_l0;

          /* Fix UDP length */
          udp0 = (udp_header_t *)(ip0+1);
          new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
                                         - sizeof (*ip0));

          udp0->length = new_l0;

          /* Reset to look up tunnel partner in the configured FIB */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->encap_fib_index;
	  vnet_buffer(b0)->sw_if_index[VLIB_RX] = sw_if_index0;
          pkts_encapsulated ++;

	  len0 = vlib_buffer_length_in_chain(vm, b0); 
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
		vlib_increment_combined_counter( 
						im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX, 
						cpu_index, stats_sw_if_index, stats_n_packets, stats_n_bytes); 
	      stats_n_packets = 1;
	      stats_n_bytes = len0; 
	      stats_sw_if_index = sw_if_index0; 
	    } 
	  if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vxlan_gpe_encap_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->tunnel_index = t0 - ngm->tunnels;
            }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index,
                               VXLAN_GPE_ENCAP_ERROR_ENCAPSULATED,
                               pkts_encapsulated);
  /* Increment any remaining batch stats */
  if (stats_n_packets) { 
    vlib_increment_combined_counter( 
				    im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX, cpu_index, 
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
        [VXLAN_GPE_ENCAP_NEXT_DROP] = "error-drop",
  },
};

