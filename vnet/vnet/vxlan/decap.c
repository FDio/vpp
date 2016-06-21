/*
 * decap.c: vxlan tunnel decap packet processing
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
#include <vnet/vxlan/vxlan.h>

vlib_node_registration_t vxlan_input_node;

typedef struct {
  u32 next_index;
  u32 tunnel_index;
  u32 error;
  u32 vni;
} vxlan_rx_trace_t;

static u8 * format_vxlan_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vxlan_rx_trace_t * t = va_arg (*args, vxlan_rx_trace_t *);

  if (t->tunnel_index != ~0)
    {
      s = format (s, "VXLAN: tunnel %d vni %d next %d error %d", 
                  t->tunnel_index, t->vni, t->next_index, t->error);
    }
  else
    {
      s = format (s, "VXLAN: no tunnel for vni %d next %d error %d", 
                  t->vni, t->next_index, t->error);
    }
  return s;
}

always_inline uword
vxlan_input (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame,
             char is_ip4)
{
  u32 n_left_from, next_index, * from, * to_next;
  vxlan_main_t * vxm = &vxlan_main;
  vnet_main_t * vnm = vxm->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 last_tunnel_index = ~0;
  vxlan4_tunnel_key_t last_key4;
  vxlan6_tunnel_key_t last_key6;
  u32 pkts_decapsulated = 0;
  u32 cpu_index = os_get_cpu_number();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;

  last_key4.as_u64 = ~0;

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
          ip4_header_t * ip4_0, * ip4_1;
          ip6_header_t * ip6_0, * ip6_1;
          vxlan_header_t * vxlan0, * vxlan1;
	  uword * p0, * p1;
          u32 tunnel_index0, tunnel_index1;
          vxlan_tunnel_t * t0, * t1;
          vxlan4_tunnel_key_t key4_0, key4_1;
          vxlan6_tunnel_key_t key6_0, key6_1;
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
          vxlan0 = vlib_buffer_get_current (b0);
          vxlan1 = vlib_buffer_get_current (b1);

          if (is_ip4) {
          vlib_buffer_advance 
            (b0, -(word)(sizeof(udp_header_t)+sizeof(ip4_header_t)));
          vlib_buffer_advance 
            (b1, -(word)(sizeof(udp_header_t)+sizeof(ip4_header_t)));
            ip4_0 = vlib_buffer_get_current (b0);
            ip4_1 = vlib_buffer_get_current (b1);
	  } else {
            vlib_buffer_advance
              (b0, -(word)(sizeof(udp_header_t)+sizeof(ip6_header_t)));
            vlib_buffer_advance
              (b1, -(word)(sizeof(udp_header_t)+sizeof(ip6_header_t)));
            ip6_0 = vlib_buffer_get_current (b0);
            ip6_1 = vlib_buffer_get_current (b1);
	  }

          /* pop (ip, udp, vxlan) */
          if (is_ip4) {
            vlib_buffer_advance
              (b0, sizeof(*ip4_0)+sizeof(udp_header_t)+sizeof(*vxlan0));
          vlib_buffer_advance 
              (b1, sizeof(*ip4_1)+sizeof(udp_header_t)+sizeof(*vxlan1));
          } else {
          vlib_buffer_advance 
              (b0, sizeof(*ip6_0)+sizeof(udp_header_t)+sizeof(*vxlan0));
            vlib_buffer_advance
              (b1, sizeof(*ip6_1)+sizeof(udp_header_t)+sizeof(*vxlan1));
          }

          tunnel_index0 = ~0;
          error0 = 0;

          tunnel_index1 = ~0;
          error1 = 0;

          if (is_ip4) {
            key4_0.src = ip4_0->src_address.as_u32;
            key4_0.vni = vxlan0->vni_reserved;

            if (PREDICT_FALSE (key4_0.as_u64 != last_key4.as_u64))
              {
                p0 = hash_get (vxm->vxlan4_tunnel_by_key, key4_0.as_u64);

                if (p0 == 0)
                  {
                    error0 = VXLAN_ERROR_NO_SUCH_TUNNEL;
                    next0 = VXLAN_INPUT_NEXT_DROP;
                    goto trace0;
                  }

                last_key4.as_u64 = key4_0.as_u64;
                tunnel_index0 = last_tunnel_index = p0[0];
              }
            else
              tunnel_index0 = last_tunnel_index;
          } else /* !is_ip4 */ {
            key6_0.src.as_u64[0] = ip6_0->src_address.as_u64[0];
            key6_0.src.as_u64[1] = ip6_0->src_address.as_u64[1];
            key6_0.vni = vxlan0->vni_reserved;

            if (PREDICT_FALSE (memcmp(&key6_0, &last_key6, sizeof(last_key6)) != 0))
              {
                p0 = hash_get_mem (vxm->vxlan6_tunnel_by_key, &key6_0);

                if (p0 == 0)
                  {
                    error0 = VXLAN_ERROR_NO_SUCH_TUNNEL;
                    next0 = VXLAN_INPUT_NEXT_DROP;
                    goto trace0;
                  }

                clib_memcpy (&last_key6, &key6_0, sizeof(key6_0));
                tunnel_index0 = last_tunnel_index = p0[0];
              }
            else
              tunnel_index0 = last_tunnel_index;
          }

          t0 = pool_elt_at_index (vxm->tunnels, tunnel_index0);

          next0 = t0->decap_next_index;
          sw_if_index0 = t0->sw_if_index;
          len0 = vlib_buffer_length_in_chain (vm, b0);

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          if (PREDICT_TRUE(next0 == VXLAN_INPUT_NEXT_L2_INPUT))
            vnet_update_l2_len (b0);

          if (next0 == VXLAN_INPUT_NEXT_NSH_PROXY_ENCAP)
          {
              /*
               * Save vni, spi_si, tunnel_type and sw_if_index to buffer's opaque.
               */
              vnet_buffer(b0)->nsh_proxy.vni = vxlan0->vni_reserved << 8;
              vnet_buffer(b0)->nsh_proxy.tunnel_type = NSH_PROXY_OUTBOUND_TRANSPORT_VXLAN;
              vnet_buffer(b0)->nsh_proxy.sw_if_index = t0->sw_if_index;
          }

          /* Set input sw_if_index to VXLAN tunnel for learning */
          vnet_buffer(b0)->sw_if_index[VLIB_RX] = sw_if_index0;

          pkts_decapsulated ++;
          stats_n_packets += 1;
          stats_n_bytes += len0;

	  /* Batch stats increment on the same vxlan tunnel so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index)) 
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter 
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		   cpu_index, stats_sw_if_index, 
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = sw_if_index0;
	    }

        trace0:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              vxlan_rx_trace_t *tr 
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->tunnel_index = tunnel_index0;
              tr->vni = vnet_get_vni (vxlan0);
            }


          if (is_ip4) {
            key4_1.src = ip4_1->src_address.as_u32;
            key4_1.vni = vxlan1->vni_reserved;

            if (PREDICT_FALSE (key4_1.as_u64 != last_key4.as_u64))
              {
                p1 = hash_get (vxm->vxlan4_tunnel_by_key, key4_1.as_u64);

                if (p1 == 0)
                  {
                    error1 = VXLAN_ERROR_NO_SUCH_TUNNEL;
                    next1 = VXLAN_INPUT_NEXT_DROP;
                    goto trace1;
                  }

                last_key4.as_u64 = key4_1.as_u64;
                tunnel_index1 = last_tunnel_index = p1[0];
              }
            else
              tunnel_index1 = last_tunnel_index;
          } else /* !is_ip4 */ {
            key6_1.src.as_u64[0] = ip6_1->src_address.as_u64[0];
            key6_1.src.as_u64[1] = ip6_1->src_address.as_u64[1];
            key6_1.vni = vxlan1->vni_reserved;

            if (PREDICT_FALSE (memcmp(&key6_1, &last_key6, sizeof(last_key6)) != 0))
              {
                p1 = hash_get_mem (vxm->vxlan6_tunnel_by_key, &key6_1);

                if (p1 == 0)
                  {
                    error1 = VXLAN_ERROR_NO_SUCH_TUNNEL;
                    next1 = VXLAN_INPUT_NEXT_DROP;
                    goto trace1;
                  }

                clib_memcpy (&last_key6, &key6_1, sizeof(key6_1));
                tunnel_index1 = last_tunnel_index = p1[0];
              }
            else
              tunnel_index1 = last_tunnel_index;
          }

          t1 = pool_elt_at_index (vxm->tunnels, tunnel_index1);

          next1 = t1->decap_next_index;
          sw_if_index1 = t1->sw_if_index;
          len1 = vlib_buffer_length_in_chain (vm, b1);

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          if (PREDICT_TRUE(next1 == VXLAN_INPUT_NEXT_L2_INPUT))
            vnet_update_l2_len (b1);

          if (next1 == VXLAN_INPUT_NEXT_NSH_PROXY_ENCAP)
          {
              /*
               * Save src, vni, spi_si, tunnel_type and sw_if_index to buffer's opaque.
               */
              vnet_buffer(b1)->nsh_proxy.vni = vxlan1->vni_reserved << 8;
              vnet_buffer(b1)->nsh_proxy.tunnel_type = NSH_PROXY_OUTBOUND_TRANSPORT_VXLAN;
              vnet_buffer(b1)->nsh_proxy.sw_if_index = t1->sw_if_index;
          }
          /* Set input sw_if_index to VXLAN tunnel for learning */
          vnet_buffer(b1)->sw_if_index[VLIB_RX] = sw_if_index1;

          pkts_decapsulated ++;
          stats_n_packets += 1;
          stats_n_bytes += len1;

	  /* Batch stats increment on the same vxlan tunnel so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index1 != stats_sw_if_index)) 
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len1;
	      if (stats_n_packets)
		vlib_increment_combined_counter 
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		   cpu_index, stats_sw_if_index, 
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len1;
	      stats_sw_if_index = sw_if_index1;
	    }

        trace1:
          b1->error = error1 ? node->errors[error1] : 0;

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              vxlan_rx_trace_t *tr 
                = vlib_add_trace (vm, node, b1, sizeof (*tr));
              tr->next_index = next1;
              tr->error = error1;
              tr->tunnel_index = tunnel_index1;
              tr->vni = vnet_get_vni (vxlan1);
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
          ip4_header_t * ip4_0;
          ip6_header_t * ip6_0;
          vxlan_header_t * vxlan0;
	  uword * p0;
          u32 tunnel_index0;
          vxlan_tunnel_t * t0;
          vxlan4_tunnel_key_t key4_0;
          vxlan6_tunnel_key_t key6_0;
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
          vxlan0 = vlib_buffer_get_current (b0);

          if (is_ip4) {
          vlib_buffer_advance 
            (b0, -(word)(sizeof(udp_header_t)+sizeof(ip4_header_t)));
            ip4_0 = vlib_buffer_get_current (b0);
          } else {
            vlib_buffer_advance
              (b0, -(word)(sizeof(udp_header_t)+sizeof(ip6_header_t)));
            ip6_0 = vlib_buffer_get_current (b0);
          }

          /* pop (ip, udp, vxlan) */
          if (is_ip4) {
            vlib_buffer_advance
              (b0, sizeof(*ip4_0)+sizeof(udp_header_t)+sizeof(*vxlan0));
          } else {
          vlib_buffer_advance 
              (b0, sizeof(*ip6_0)+sizeof(udp_header_t)+sizeof(*vxlan0));
          }

          tunnel_index0 = ~0;
          error0 = 0;

          if (is_ip4) {
            key4_0.src = ip4_0->src_address.as_u32;
            key4_0.vni = vxlan0->vni_reserved;

            if (PREDICT_FALSE (key4_0.as_u64 != last_key4.as_u64))
              {
                p0 = hash_get (vxm->vxlan4_tunnel_by_key, key4_0.as_u64);

                if (p0 == 0)
                  {
                    error0 = VXLAN_ERROR_NO_SUCH_TUNNEL;
                    next0 = VXLAN_INPUT_NEXT_DROP;
                    goto trace00;
                  }

                last_key4.as_u64 = key4_0.as_u64;
                tunnel_index0 = last_tunnel_index = p0[0];
              }
            else
              tunnel_index0 = last_tunnel_index;
          } else /* !is_ip4 */ {
            key6_0.src.as_u64[0] = ip6_0->src_address.as_u64[0];
            key6_0.src.as_u64[1] = ip6_0->src_address.as_u64[1];
            key6_0.vni = vxlan0->vni_reserved;

            if (PREDICT_FALSE (memcmp(&key6_0, &last_key6, sizeof(last_key6)) != 0))
              {
                p0 = hash_get_mem (vxm->vxlan6_tunnel_by_key, &key6_0);

                if (p0 == 0)
                  {
                    error0 = VXLAN_ERROR_NO_SUCH_TUNNEL;
                    next0 = VXLAN_INPUT_NEXT_DROP;
                    goto trace00;
                  }

                clib_memcpy (&last_key6, &key6_0, sizeof(key6_0));
                tunnel_index0 = last_tunnel_index = p0[0];
              }
            else
              tunnel_index0 = last_tunnel_index;
          }

          t0 = pool_elt_at_index (vxm->tunnels, tunnel_index0);

          next0 = t0->decap_next_index;
          sw_if_index0 = t0->sw_if_index;
          len0 = vlib_buffer_length_in_chain (vm, b0);

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          if (PREDICT_TRUE(next0 == VXLAN_INPUT_NEXT_L2_INPUT))
            vnet_update_l2_len (b0);

          if (next0 == VXLAN_INPUT_NEXT_NSH_PROXY_ENCAP)
          {
              /*
               * Save src, vni, spi_si, tunnel_type and sw_if_index to buffer's opaque.
               */
              vnet_buffer(b0)->nsh_proxy.vni = vxlan0->vni_reserved << 8;
              vnet_buffer(b0)->nsh_proxy.tunnel_type = NSH_PROXY_OUTBOUND_TRANSPORT_VXLAN;
              vnet_buffer(b0)->nsh_proxy.sw_if_index = t0->sw_if_index;
          }
          /* Set input sw_if_index to VXLAN tunnel for learning */
          vnet_buffer(b0)->sw_if_index[VLIB_RX] = sw_if_index0;

          pkts_decapsulated ++;
          stats_n_packets += 1;
          stats_n_bytes += len0;

	  /* Batch stats increment on the same vxlan tunnel so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index)) 
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter 
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		   cpu_index, stats_sw_if_index, 
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = sw_if_index0;
	    }

        trace00:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              vxlan_rx_trace_t *tr 
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->tunnel_index = tunnel_index0;
              tr->vni = vnet_get_vni (vxlan0);
            }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  /* Do we still need this now that tunnel tx stats is kept? */
  vlib_node_increment_counter (vm, vxlan_input_node.index,
                               VXLAN_ERROR_DECAPSULATED, 
                               pkts_decapsulated);

  /* Increment any remaining batch stats */
  if (stats_n_packets)
    {
      vlib_increment_combined_counter 
	(im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
	 cpu_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
      node->runtime_data[0] = stats_sw_if_index;
    }

  return from_frame->n_vectors;
}

static uword
vxlan4_input (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
	return vxlan_input(vm, node, from_frame, /* is_ip4 */ 1);
}

static uword
vxlan6_input (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
	return vxlan_input(vm, node, from_frame, /* is_ip4 */ 0);
}

static char * vxlan_error_strings[] = {
#define vxlan_error(n,s) s,
#include <vnet/vxlan/vxlan_error.def>
#undef vxlan_error
#undef _
};

VLIB_REGISTER_NODE (vxlan4_input_node) = {
  .function = vxlan4_input,
  .name = "vxlan4-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = VXLAN_N_ERROR,
  .error_strings = vxlan_error_strings,

  .n_next_nodes = VXLAN_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [VXLAN_INPUT_NEXT_##s] = n,
    foreach_vxlan_input_next
#undef _
  },

//temp  .format_buffer = format_vxlan_header,
  .format_trace = format_vxlan_rx_trace,
  // $$$$ .unformat_buffer = unformat_vxlan_header,
};

VLIB_NODE_FUNCTION_MULTIARCH (vxlan4_input_node, vxlan4_input)

VLIB_REGISTER_NODE (vxlan6_input_node) = {
  .function = vxlan6_input,
  .name = "vxlan6-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = VXLAN_N_ERROR,
  .error_strings = vxlan_error_strings,

  .n_next_nodes = VXLAN_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [VXLAN_INPUT_NEXT_##s] = n,
    foreach_vxlan_input_next
#undef _
  },

//temp  .format_buffer = format_vxlan_header,
  .format_trace = format_vxlan_rx_trace,
  // $$$$ .unformat_buffer = unformat_vxlan_header,
};

VLIB_NODE_FUNCTION_MULTIARCH (vxlan6_input_node, vxlan6_input)

