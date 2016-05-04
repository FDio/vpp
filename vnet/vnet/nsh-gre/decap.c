/*
 * nsh.c: nsh packet processing
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
#include <vnet/nsh-gre/nsh_gre.h>
#include <vnet/nsh/nsh_packet.h>

vlib_node_registration_t nsh_input_node;

typedef struct {
  u32 next_index;
  u32 tunnel_index;
  u32 error;
  nsh_header_t h;
} nsh_rx_trace_t;


u8 * format_nsh_header_with_length (u8 * s, va_list * args)
{
  nsh_header_t * h = va_arg (*args, nsh_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 tmp, header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "gre-nsh header truncated");

  s = format (s, "ver %d ", h->ver_o_c>>6);

  if (h->ver_o_c & NSH_O_BIT)
      s = format (s, "O-set ");

  if (h->ver_o_c & NSH_C_BIT)
      s = format (s, "C-set ");

  s = format (s, "len %d (%d bytes) md_type %d next_protocol %d\n",
              h->length, h->length * 4, h->md_type, h->next_protocol);
  
  tmp = clib_net_to_host_u32 (h->spi_si);

  s = format (s, "  spi %d si %d ",
              (tmp>>NSH_SPI_SHIFT) & NSH_SPI_MASK,
              tmp & NSH_SINDEX_MASK);

  s = format (s, "c1 %u c2 %u c3 %u c4 %u",
              clib_net_to_host_u32 (h->c1),
              clib_net_to_host_u32 (h->c2),
              clib_net_to_host_u32 (h->c3),
              clib_net_to_host_u32 (h->c4));

  return s;
}


u8 * format_nsh_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nsh_rx_trace_t * t = va_arg (*args, nsh_rx_trace_t *);

  if (t->tunnel_index != ~0)
    {
      s = format (s, "NSH: tunnel %d next %d error %d", t->tunnel_index, 
                  t->next_index, t->error);
    }
  else
    {
      s = format (s, "NSH: no tunnel next %d error %d\n", t->next_index, 
                  t->error);
    }
  s = format (s, "\n  %U", format_nsh_header_with_length, &t->h, 
              (u32) sizeof (t->h) /* max size */);
  return s;
}

static uword
nsh_gre_input (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  nsh_gre_main_t * ngm = &nsh_gre_main;
  vnet_main_t * vnm = ngm->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 last_tunnel_index = ~0;
  u64 last_key = ~0ULL;
  u32 pkts_decapsulated = 0;
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
	  u32 next0, next1;
	  nsh_header_t * h0, * h1;
	  uword * p0, * p1;
          u32 tunnel_index0, tunnel_index1;
          nsh_gre_tunnel_t * t0, * t1;
          u64 key0, key1;
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

          h0 = vlib_buffer_get_current (b0);
          h1 = vlib_buffer_get_current (b1);

          /* gre stashed the src ip4 address for us... */
          key0 = (((u64)(vnet_buffer(b0)->gre.src))<<32) | h0->spi_si;
          key1 = (((u64)(vnet_buffer(b1)->gre.src))<<32) | h1->spi_si;

          /* "pop" nsh header */
          vlib_buffer_advance (b0, sizeof (*h0));
          vlib_buffer_advance (b1, sizeof (*h1));

          tunnel_index0 = ~0;
          tunnel_index1 = ~0;
          error0 = 0;
          error1 = 0;
          next0 = NSH_GRE_INPUT_NEXT_DROP;
          next1 = NSH_GRE_INPUT_NEXT_DROP;

          if (PREDICT_FALSE(key0 != last_key))
            {
              p0 = hash_get (ngm->nsh_gre_tunnel_by_src_address, key0);

              if (p0 == 0)
                {
                  error0 = NSH_GRE_ERROR_NO_SUCH_TUNNEL;
                  goto trace0;
                }

              last_key = key0;
              tunnel_index0 = last_tunnel_index = p0[0];
            }
          else
            tunnel_index0 = last_tunnel_index;

          t0 = pool_elt_at_index (ngm->tunnels, tunnel_index0);

          next0 = t0->decap_next_index;
          sw_if_index0 = t0->sw_if_index;
          len0 = vlib_buffer_length_in_chain(vm, b0);

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          vnet_update_l2_len (b0);

          next0 = t0->decap_next_index;

          /* ip[46] lookup in the configured FIB, otherwise an opaque */
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
              nsh_rx_trace_t *tr = vlib_add_trace (vm, node, 
                                                   b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->tunnel_index = tunnel_index0;
              tr->h = h0[0];
            }

          if (PREDICT_FALSE(key1 != last_key))
            {
              p1 = hash_get (ngm->nsh_gre_tunnel_by_src_address, key1);

              if (p1 == 0)
                {
                  error1 = NSH_GRE_ERROR_NO_SUCH_TUNNEL;
                  goto trace1;
                }

              last_key = key1;
              tunnel_index1 = last_tunnel_index = p1[0];
            }
          else
            tunnel_index1 = last_tunnel_index;

          t1 = pool_elt_at_index (ngm->tunnels, tunnel_index1);

          next1 = t1->decap_next_index;
          sw_if_index1 = t1->sw_if_index;
          len1 = vlib_buffer_length_in_chain(vm, b1);

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          vnet_update_l2_len (b1);

          next1 = t1->decap_next_index;

          /* ip[46] lookup in the configured FIB, otherwise an opaque */
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = t1->decap_fib_index;

          pkts_decapsulated++;
          stats_n_packets += 1;
          stats_n_bytes += len1;
          /* Batch stats increment on the same nsh-gre tunnel so counter
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
              nsh_rx_trace_t *tr = vlib_add_trace (vm, node, 
                                                   b1, sizeof (*tr));
              tr->next_index = next1;
              tr->error = error1;
              tr->tunnel_index = tunnel_index1;
              tr->h = h1[0];
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
	  nsh_header_t * h0;
	  uword * p0;
          u32 tunnel_index0;
          nsh_gre_tunnel_t * t0;
          u64 key0;
          u32 error0;
          u32 sw_if_index0, len0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          h0 = vlib_buffer_get_current (b0);

          /* gre stashed the src ip4 address for us... */
          key0 = (((u64)(vnet_buffer(b0)->gre.src))<<32) | h0->spi_si;

          /* "pop" nsh header */
          vlib_buffer_advance (b0, sizeof (*h0));

          tunnel_index0 = ~0;
          error0 = 0;
          next0 = NSH_GRE_INPUT_NEXT_DROP;

          if (PREDICT_FALSE(key0 != last_key))
            {
              p0 = hash_get (ngm->nsh_gre_tunnel_by_src_address, key0);

              if (p0 == 0)
                {
                  error0 = NSH_GRE_ERROR_NO_SUCH_TUNNEL;
                  goto trace00;
                }

              last_key = key0;
              tunnel_index0 = last_tunnel_index = p0[0];
            }
          else
            tunnel_index0 = last_tunnel_index;

          t0 = pool_elt_at_index (ngm->tunnels, tunnel_index0);

          next0 = t0->decap_next_index;
          sw_if_index0 = t0->sw_if_index;
          len0 = vlib_buffer_length_in_chain(vm, b0);

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          vnet_update_l2_len (b0);

          next0 = t0->decap_next_index;

          /* ip[46] lookup in the configured FIB, otherwise an opaque */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->decap_fib_index;
          pkts_decapsulated ++;

          stats_n_packets += 1;
          stats_n_bytes += len0;

          /* Batch stats increment on the same nsh-gre tunnel so counter
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
              nsh_rx_trace_t *tr = vlib_add_trace (vm, node, 
                                                   b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->tunnel_index = tunnel_index0;
              tr->h = h0[0];
            }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, nsh_gre_input_node.index,
                               NSH_GRE_ERROR_DECAPSULATED, 
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

static char * nsh_error_strings[] = {
#define nsh_gre_error(n,s) s,
#include <vnet/nsh/nsh_error.def>
#undef nsh_gre_error
#undef _
};

VLIB_REGISTER_NODE (nsh_gre_input_node) = {
  .function = nsh_gre_input,
  .name = "nsh-gre-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = NSH_GRE_N_ERROR,
  .error_strings = nsh_error_strings,

  .n_next_nodes = NSH_GRE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [NSH_GRE_INPUT_NEXT_##s] = n,
    foreach_nsh_gre_input_next
#undef _
  },

  .format_buffer = format_nsh_header_with_length,
  .format_trace = format_nsh_rx_trace,
  // $$$$ .unformat_buffer = unformat_nsh_gre_header,
};
