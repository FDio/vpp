/*
 * decap.c - decapsulate VXLAN GPE
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>

typedef struct {
  u32 next_index;
  u32 tunnel_index;
  u32 error;
} vxlan_gpe_rx_trace_t;

static u8 * format_vxlan_gpe_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vxlan_gpe_rx_trace_t * t = va_arg (*args, vxlan_gpe_rx_trace_t *);

  if (t->tunnel_index != ~0)
    {
      s = format (s, "VXLAN-GPE: tunnel %d next %d error %d", t->tunnel_index, 
                  t->next_index, t->error);
    }
  else
    {
      s = format (s, "VXLAN-GPE: no tunnel next %d error %d\n", t->next_index, 
                  t->error);
    }
  return s;
}


static u8 * format_vxlan_gpe_with_length (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);


  return s;
}

static uword
vxlan_gpe_input (vlib_main_t * vm,
                     vlib_node_runtime_t * node,
                     vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  vxlan_gpe_main_t * ngm = &vxlan_gpe_main;
  vnet_main_t * vnm = ngm->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 last_tunnel_index = ~0;
  vxlan_gpe_tunnel_key_t last_key;
  u32 pkts_decapsulated = 0;
  u32 cpu_index = os_get_cpu_number();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;

  memset (&last_key, 0xff, sizeof (last_key));

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
	  u32 next0, next1;
          ip4_vxlan_gpe_header_t * iuvn0, * iuvn1;
	  uword * p0, * p1;
          u32 tunnel_index0, tunnel_index1;
          vxlan_gpe_tunnel_t * t0, * t1;
          vxlan_gpe_tunnel_key_t key0, key1;
          u32 error0, error1;
          u32 sw_if_index0, sw_if_index1, len0, len1;

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

          /* udp leaves current_data pointing at the vxlan header */
          vlib_buffer_advance 
            (b0, -(word)(sizeof(udp_header_t)+sizeof(ip4_header_t)));
          vlib_buffer_advance 
            (b1, -(word)(sizeof(udp_header_t)+sizeof(ip4_header_t)));

          iuvn0 = vlib_buffer_get_current (b0);
          iuvn1 = vlib_buffer_get_current (b1);

          /* pop (ip, udp, vxlan) */
          vlib_buffer_advance (b0, sizeof (*iuvn0));
          vlib_buffer_advance (b1, sizeof (*iuvn1));

          tunnel_index0 = ~0;
          tunnel_index1 = ~0;
          error0 = 0;
          error1 = 0;

	  next0 = (iuvn0->vxlan.protocol < VXLAN_GPE_INPUT_N_NEXT) ? iuvn0->vxlan.protocol : VXLAN_GPE_INPUT_NEXT_DROP;
	  next1 = (iuvn1->vxlan.protocol < VXLAN_GPE_INPUT_N_NEXT) ? iuvn1->vxlan.protocol : VXLAN_GPE_INPUT_NEXT_DROP;




          key0.local = iuvn0->ip4.dst_address.as_u32;
          key1.local = iuvn1->ip4.dst_address.as_u32;

	  key0.remote = iuvn0->ip4.src_address.as_u32;
	  key1.remote = iuvn1->ip4.src_address.as_u32;

          key0.vni = iuvn0->vxlan.vni_res;
          key1.vni = iuvn1->vxlan.vni_res;

          key0.pad = 0;
          key1.pad = 0;

	  /* Processing for key0 */
          if (PREDICT_FALSE ((key0.as_u64[0] != last_key.as_u64[0])
                             || (key0.as_u64[1] != last_key.as_u64[1])))
            {
              p0 = hash_get_mem (ngm->vxlan_gpe_tunnel_by_key, &key0);

              if (p0 == 0)
                {
                  error0 = VXLAN_GPE_ERROR_NO_SUCH_TUNNEL;
                  goto trace0;
                }

              last_key.as_u64[0] = key0.as_u64[0];
              last_key.as_u64[1] = key0.as_u64[1];
              tunnel_index0 = last_tunnel_index = p0[0];
            }
          else
            tunnel_index0 = last_tunnel_index;

          t0 = pool_elt_at_index (ngm->tunnels, tunnel_index0);

          next0 = t0->protocol;

          sw_if_index0 = t0->sw_if_index;
          len0 = vlib_buffer_length_in_chain(vm, b0);

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          vnet_update_l2_len (b0);
	  
	  /*
	   * ip[46] lookup in the configured FIB
	   */
	  vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->decap_fib_index;

          pkts_decapsulated++;
          stats_n_packets += 1;
          stats_n_bytes += len0;

          if (PREDICT_FALSE(sw_if_index0 != stats_sw_if_index))
          {
            stats_n_packets -= 1;
            stats_n_bytes -= len0;
            if (stats_n_packets)
              vlib_increment_combined_counter(
                  im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
                  cpu_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
            stats_n_packets = 1;
            stats_n_bytes = len0;
            stats_sw_if_index = sw_if_index0;
          }

        trace0:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              vxlan_gpe_rx_trace_t *tr
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->tunnel_index = tunnel_index0;
            }


	  /* Processing for key1 */
          if (PREDICT_FALSE ((key1.as_u64[0] != last_key.as_u64[0])
                             || (key1.as_u64[1] != last_key.as_u64[1])))
            {
              p1 = hash_get_mem (ngm->vxlan_gpe_tunnel_by_key, &key1);

              if (p1 == 0)
                {
                  error1 = VXLAN_GPE_ERROR_NO_SUCH_TUNNEL;
                  goto trace1;
                }

              last_key.as_u64[0] = key1.as_u64[0];
              last_key.as_u64[1] = key1.as_u64[1];
              tunnel_index1 = last_tunnel_index = p1[0];
            }
          else
            tunnel_index1 = last_tunnel_index;

          t1 = pool_elt_at_index (ngm->tunnels, tunnel_index1);

          next1 = t1->protocol;
          sw_if_index1 = t1->sw_if_index;
          len1 = vlib_buffer_length_in_chain(vm, b1);

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          vnet_update_l2_len (b1);

	  /*
	   * ip[46] lookup in the configured FIB
	   */
	  vnet_buffer(b1)->sw_if_index[VLIB_TX] = t1->decap_fib_index;


          pkts_decapsulated++;
          stats_n_packets += 1;
          stats_n_bytes += len1;
          
	  /* Batch stats increment on the same vxlan tunnel so counter
           is not incremented per packet */
          if (PREDICT_FALSE(sw_if_index1 != stats_sw_if_index))
          {
            stats_n_packets -= 1;
            stats_n_bytes -= len1;
            if (stats_n_packets)
              vlib_increment_combined_counter(
                  im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
                  cpu_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
            stats_n_packets = 1;
            stats_n_bytes = len1;
            stats_sw_if_index = sw_if_index1;
          }
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = t1->decap_fib_index;

        trace1:
          b1->error = error1 ? node->errors[error1] : 0;

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
              vxlan_gpe_rx_trace_t *tr
                = vlib_add_trace (vm, node, b1, sizeof (*tr));
              tr->next_index = next1;
              tr->error = error1;
              tr->tunnel_index = tunnel_index1;
            }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
    
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
	  u32 next0;
          ip4_vxlan_gpe_header_t * iuvn0;
	  uword * p0;
          u32 tunnel_index0;
          vxlan_gpe_tunnel_t * t0;
          vxlan_gpe_tunnel_key_t key0;
          u32 error0;
          u32 sw_if_index0, len0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          /* udp leaves current_data pointing at the vxlan header */
          vlib_buffer_advance 
            (b0, -(word)(sizeof(udp_header_t)+sizeof(ip4_header_t)));

          iuvn0 = vlib_buffer_get_current (b0);

          /* pop (ip, udp, vxlan) */
          vlib_buffer_advance (b0, sizeof (*iuvn0));

          tunnel_index0 = ~0;
          error0 = 0;
          next0 = (iuvn0->vxlan.protocol < VXLAN_GPE_INPUT_N_NEXT) ? iuvn0->vxlan.protocol : VXLAN_GPE_INPUT_NEXT_DROP;

          key0.local = iuvn0->ip4.dst_address.as_u32;
	  key0.remote = iuvn0->ip4.src_address.as_u32;
          key0.vni = iuvn0->vxlan.vni_res;
          key0.pad = 0;

          if (PREDICT_FALSE ((key0.as_u64[0] != last_key.as_u64[0])
                             || (key0.as_u64[1] != last_key.as_u64[1])))
            {
              p0 = hash_get_mem (ngm->vxlan_gpe_tunnel_by_key, &key0);
          
              if (p0 == 0)
                {
                  error0 = VXLAN_GPE_ERROR_NO_SUCH_TUNNEL;
                  goto trace00;
                }

              last_key.as_u64[0] = key0.as_u64[0];
              last_key.as_u64[1] = key0.as_u64[1];
              tunnel_index0 = last_tunnel_index = p0[0];
            }
          else
            tunnel_index0 = last_tunnel_index;

          t0 = pool_elt_at_index (ngm->tunnels, tunnel_index0);

          next0 = t0->protocol;
	  
	  sw_if_index0 = t0->sw_if_index;
          len0 = vlib_buffer_length_in_chain(vm, b0);

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          vnet_update_l2_len (b0);

	  /*
	   * ip[46] lookup in the configured FIB
	   */
	  vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->decap_fib_index;

          pkts_decapsulated ++;
          stats_n_packets += 1;
          stats_n_bytes += len0;

          /* Batch stats increment on the same vxlan-gpe tunnel so counter
           is not incremented per packet */
          if (PREDICT_FALSE(sw_if_index0 != stats_sw_if_index))
          {
            stats_n_packets -= 1;
            stats_n_bytes -= len0;
            if (stats_n_packets)
              vlib_increment_combined_counter(
                  im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
                  cpu_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
            stats_n_packets = 1;
            stats_n_bytes = len0;
            stats_sw_if_index = sw_if_index0;
          }

        trace00:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              vxlan_gpe_rx_trace_t *tr
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->tunnel_index = tunnel_index0;
            }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, vxlan_gpe_input_node.index,
                               VXLAN_GPE_ERROR_DECAPSULATED,
                               pkts_decapsulated);
  /* Increment any remaining batch stats */
  if (stats_n_packets)
  {
    vlib_increment_combined_counter(
        im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX, cpu_index,
        stats_sw_if_index, stats_n_packets, stats_n_bytes);
    node->runtime_data[0] = stats_sw_if_index;
  }
  return from_frame->n_vectors;
}

static char * vxlan_gpe_error_strings[] = {
#define vxlan_gpe_error(n,s) s,
#include <vnet/vxlan-gpe/vxlan_gpe_error.def>
#undef vxlan_gpe_error
#undef _
};

VLIB_REGISTER_NODE (vxlan_gpe_input_node) = {
  .function = vxlan_gpe_input,
  .name = "vxlan-gpe-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(vxlan_gpe_error_strings),
  .error_strings = vxlan_gpe_error_strings,

  .n_next_nodes = VXLAN_GPE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [VXLAN_GPE_INPUT_NEXT_##s] = n,
    foreach_vxlan_gpe_input_next
#undef _
  },

  .format_buffer = format_vxlan_gpe_with_length,
  .format_trace = format_vxlan_gpe_rx_trace,
  // $$$$ .unformat_buffer = unformat_vxlan_gpe_header,
};


