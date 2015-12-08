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
#include <vnet/nsh-vxlan-gpe/nsh_vxlan_gpe.h>

vlib_node_registration_t nsh_vxlan_gpe_input_node;

/* From nsh-gre */
u8 * format_nsh_header_with_length (u8 * s, va_list * args);

typedef struct {
  u32 next_index;
  u32 tunnel_index;
  u32 error;
  nsh_header_t h;
} nsh_vxlan_gpe_rx_trace_t;

static u8 * format_nsh_vxlan_gpe_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nsh_vxlan_gpe_rx_trace_t * t = va_arg (*args, nsh_vxlan_gpe_rx_trace_t *);

  if (t->tunnel_index != ~0)
    {
      s = format (s, "NSH-VXLAN: tunnel %d next %d error %d", t->tunnel_index, 
                  t->next_index, t->error);
    }
  else
    {
      s = format (s, "NSH-VXLAN: no tunnel next %d error %d\n", t->next_index, 
                  t->error);
    }
  s = format (s, "\n  %U", format_nsh_header_with_length, &t->h, 
              (u32) sizeof (t->h) /* max size */);
  return s;
}

static uword
nsh_vxlan_gpe_input (vlib_main_t * vm,
                     vlib_node_runtime_t * node,
                     vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  nsh_vxlan_gpe_main_t * ngm = &nsh_vxlan_gpe_main;
  u32 last_tunnel_index = ~0;
  nsh_vxlan_gpe_tunnel_key_t last_key;
  u32 pkts_decapsulated = 0;

  memset (&last_key, 0xff, sizeof (last_key));

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

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
          ip4_vxlan_gpe_and_nsh_header_t * iuvn0, * iuvn1;
	  uword * p0, * p1;
          u32 tunnel_index0, tunnel_index1;
          nsh_vxlan_gpe_tunnel_t * t0, * t1;
          nsh_vxlan_gpe_tunnel_key_t key0, key1;
          u32 error0, error1;

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

          /* pop (ip, udp, vxlan, nsh) */
          vlib_buffer_advance (b0, sizeof (*iuvn0));
          vlib_buffer_advance (b1, sizeof (*iuvn1));

          tunnel_index0 = ~0;
          error0 = 0;
          next0 = NSH_VXLAN_GPE_INPUT_NEXT_DROP;

          tunnel_index1 = ~0;
          error1 = 0;
          next1 = NSH_VXLAN_GPE_INPUT_NEXT_DROP;

          key0.src = iuvn0->ip4.src_address.as_u32;
          key0.vni = iuvn0->vxlan.vni_res;
          key0.spi_si = iuvn0->nsh.spi_si;
          key0.pad = 0;

          if (PREDICT_FALSE ((key0.as_u64[0] != last_key.as_u64[0])
                             || (key0.as_u64[1] != last_key.as_u64[1])))
            {
              p0 = hash_get_mem (ngm->nsh_vxlan_gpe_tunnel_by_key, &key0);

              if (p0 == 0)
                {
                  error0 = NSH_VXLAN_GPE_ERROR_NO_SUCH_TUNNEL;
                  goto trace0;
                }

              last_key.as_u64[0] = key0.as_u64[0];
              last_key.as_u64[1] = key0.as_u64[1];
              tunnel_index0 = last_tunnel_index = p0[0];
            }
          else
            tunnel_index0 = last_tunnel_index;

          t0 = pool_elt_at_index (ngm->tunnels, tunnel_index0);

          next0 = t0->decap_next_index;

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          vnet_update_l2_len (b0);

          /* 
           * ip[46] lookup in the configured FIB
           * nsh-vxlan-gpe-encap, here's the encap tunnel sw_if_index
           */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->decap_fib_index;

        trace0:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              nsh_vxlan_gpe_rx_trace_t *tr 
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->tunnel_index = tunnel_index0;
              tr->h = iuvn0->nsh;
            }

          key1.src = iuvn1->ip4.src_address.as_u32;
          key1.vni = iuvn1->vxlan.vni_res;
          key1.spi_si = iuvn1->nsh.spi_si;
          key1.pad = 0;

          if (PREDICT_FALSE ((key1.as_u64[0] != last_key.as_u64[0])
                             || (key1.as_u64[1] != last_key.as_u64[1])))
            {
              p1 = hash_get_mem (ngm->nsh_vxlan_gpe_tunnel_by_key, &key1);

              if (p1 == 0)
                {
                  error1 = NSH_VXLAN_GPE_ERROR_NO_SUCH_TUNNEL;
                  goto trace1;
                }

              last_key.as_u64[0] = key1.as_u64[0];
              last_key.as_u64[1] = key1.as_u64[1];
              tunnel_index1 = last_tunnel_index = p1[0];
            }
          else
            tunnel_index1 = last_tunnel_index;

          t1 = pool_elt_at_index (ngm->tunnels, tunnel_index1);

          next1 = t1->decap_next_index;

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          vnet_update_l2_len (b1);

          /* 
           * ip[46] lookup in the configured FIB
           * nsh-vxlan-gpe-encap, here's the encap tunnel sw_if_index
           */
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = t1->decap_fib_index;
          pkts_decapsulated += 2;

        trace1:
          b1->error = error1 ? node->errors[error1] : 0;

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              nsh_vxlan_gpe_rx_trace_t *tr 
                = vlib_add_trace (vm, node, b1, sizeof (*tr));
              tr->next_index = next1;
              tr->error = error1;
              tr->tunnel_index = tunnel_index1;
              tr->h = iuvn1->nsh;
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
          ip4_vxlan_gpe_and_nsh_header_t * iuvn0;
	  uword * p0;
          u32 tunnel_index0;
          nsh_vxlan_gpe_tunnel_t * t0;
          nsh_vxlan_gpe_tunnel_key_t key0;
          u32 error0;

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

          /* pop (ip, udp, vxlan, nsh) */
          vlib_buffer_advance (b0, sizeof (*iuvn0));

          tunnel_index0 = ~0;
          error0 = 0;
          next0 = NSH_VXLAN_GPE_INPUT_NEXT_DROP;

          key0.src = iuvn0->ip4.src_address.as_u32;
          key0.vni = iuvn0->vxlan.vni_res;
          key0.spi_si = iuvn0->nsh.spi_si;
          key0.pad = 0;

          if (PREDICT_FALSE ((key0.as_u64[0] != last_key.as_u64[0])
                             || (key0.as_u64[1] != last_key.as_u64[1])))
            {
              p0 = hash_get_mem (ngm->nsh_vxlan_gpe_tunnel_by_key, &key0);

              if (p0 == 0)
                {
                  error0 = NSH_VXLAN_GPE_ERROR_NO_SUCH_TUNNEL;
                  goto trace00;
                }

              last_key.as_u64[0] = key0.as_u64[0];
              last_key.as_u64[1] = key0.as_u64[1];
              tunnel_index0 = last_tunnel_index = p0[0];
            }
          else
            tunnel_index0 = last_tunnel_index;

          t0 = pool_elt_at_index (ngm->tunnels, tunnel_index0);

          next0 = t0->decap_next_index;

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          vnet_update_l2_len (b0);

          /* 
           * ip[46] lookup in the configured FIB
           * nsh-vxlan-gpe-encap, here's the encap tunnel sw_if_index
           */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->decap_fib_index;
          pkts_decapsulated ++;

        trace00:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              nsh_vxlan_gpe_rx_trace_t *tr 
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->tunnel_index = tunnel_index0;
              tr->h = iuvn0->nsh;
            }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, nsh_vxlan_gpe_input_node.index,
                               NSH_VXLAN_GPE_ERROR_DECAPSULATED, 
                               pkts_decapsulated);
  return from_frame->n_vectors;
}

static char * nsh_vxlan_gpe_error_strings[] = {
#define nsh_vxlan_gpe_error(n,s) s,
#include <vnet/nsh-vxlan-gpe/nsh_vxlan_gpe_error.def>
#undef nsh_vxlan_gpe_error
#undef _
};

VLIB_REGISTER_NODE (nsh_vxlan_gpe_input_node) = {
  .function = nsh_vxlan_gpe_input,
  .name = "nsh-vxlan-gpe-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = NSH_VXLAN_GPE_N_ERROR,
  .error_strings = nsh_vxlan_gpe_error_strings,

  .n_next_nodes = NSH_VXLAN_GPE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [NSH_VXLAN_GPE_INPUT_NEXT_##s] = n,
    foreach_nsh_vxlan_gpe_input_next
#undef _
  },

  .format_buffer = format_nsh_header_with_length,
  .format_trace = format_nsh_vxlan_gpe_rx_trace,
  // $$$$ .unformat_buffer = unformat_nsh_vxlan_gpe_header,
};
