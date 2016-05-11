/*
 * node.c: mpls-o-gre decap processing
 *
 * Copyright (c) 2012-2014 Cisco and/or its affiliates.
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
#include <vnet/mpls-gre/mpls.h>

typedef struct {
  u32 next_index;
  u32 decap_index;
  u32 tx_fib_index;
  u32 label_host_byte_order;
} mpls_rx_trace_t;

u8 * format_mpls_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mpls_rx_trace_t * t = va_arg (*args, mpls_rx_trace_t *);
  char * next_name;

  next_name = "BUG!";

#define _(a,b) if (t->next_index == MPLS_INPUT_NEXT_##a) next_name = b;
  foreach_mpls_input_next;
#undef _
  
  s = format (s, "MPLS: next %s, lookup fib index %d, decap index %d\n",
              next_name, t->next_index, t->tx_fib_index, t->decap_index);
  if (t->decap_index != ~0)
    {
      s = format (s, "    label %d", 
                  vnet_mpls_uc_get_label(t->label_host_byte_order));
    }
  return s;
}

vlib_node_registration_t mpls_input_node;

typedef struct {
  u32 last_label;
  u32 last_inner_fib_index;
  u32 last_outer_fib_index;
  mpls_main_t * mpls_main;
} mpls_input_runtime_t;

static inline uword
mpls_input_inline (vlib_main_t * vm,
                   vlib_node_runtime_t * node,
                   vlib_frame_t * from_frame, int is_mpls_o_gre)
{
  u32 n_left_from, next_index, * from, * to_next;
  ip4_main_t * im = &ip4_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  mpls_input_runtime_t * rt;
  mpls_main_t * mm;

  rt = vlib_node_get_runtime_data (vm, mpls_input_node.index);
  mm = rt->mpls_main;
  /* 
   * Force an initial lookup every time, in case the control-plane
   * changed the label->FIB mapping.
   */
  rt->last_label = ~0;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

#if 0
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
	  mpls_unicast_header_t * h0, * h1;
          int li0, li1;
          u64 key0, key1;
          u32 label0, label1;
	  u32 next0, next1;
	  uword * p0, * p1;
          u32 fib_index0, fib_index1;

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

          /* $$$$$ dual loop me */

          vlib_buffer_advance (b0, sizeof (*h0));
          vlib_buffer_advance (b1, sizeof (*h1));

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
    
#endif

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
	  mpls_unicast_header_t * h0;
          u32 label0;
	  u32 next0;
          u64 key0;
	  uword * p0;
          u32 rx_fib_index0;
          mpls_decap_t *d0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          h0 = vlib_buffer_get_current (b0);

          if (is_mpls_o_gre)
            {
              rx_fib_index0 = vec_elt (im->fib_index_by_sw_if_index, 
                                       vnet_buffer(b0)->sw_if_index[VLIB_RX]);
            }
          else
            {
#if 0
              /* If separate RX numbering spaces are required... */
              rx_fib_index0 = vec_elt (mm->fib_index_by_sw_if_index, 
                                       vnet_buffer(b0)->sw_if_index[VLIB_RX]);
#endif
              rx_fib_index0 = 0;
            }
          
          next0 = ~0;
          d0 = 0;

          /* 
           * Expect the control-plane team to squeal like pigs.
           * If they don't program a decap label entry for each
           * and every label in the stack, packets go into the trash...
           */

          do
            {
              label0 = clib_net_to_host_u32 (h0->label_exp_s_ttl);
              /* TTL expired? */
              if (PREDICT_FALSE(vnet_mpls_uc_get_ttl (label0) == 0))
                {
                  next0 = MPLS_INPUT_NEXT_DROP;
                  b0->error = node->errors[MPLS_ERROR_TTL_EXPIRED];
                  break;
                }
              
              key0 = ((u64)rx_fib_index0<<32) 
                | ((u64)vnet_mpls_uc_get_label (label0)<<12) 
                | ((u64)vnet_mpls_uc_get_s (label0)<<8);

              /* 
               * The architecture crew claims that we won't need
               * separate ip4, ip6, mpls-o-ethernet label numbering
               * spaces. Use the low 8 key bits as a discriminator.
               */

              p0 = hash_get (mm->mpls_decap_by_rx_fib_and_label, key0);
              if (p0 == 0)
                {
                  next0 = MPLS_INPUT_NEXT_DROP;
                  b0->error = node->errors[MPLS_ERROR_BAD_LABEL];
                  break;
                }
              d0 = pool_elt_at_index (mm->decaps, p0[0]);
              next0 = d0->next_index;
              vnet_buffer(b0)->sw_if_index[VLIB_TX] = d0->tx_fib_index;
              vlib_buffer_advance (b0, sizeof (*h0));
              h0 = vlib_buffer_get_current (b0);
            } while (!vnet_mpls_uc_get_s(label0));

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              mpls_rx_trace_t *tr = vlib_add_trace (vm, node, 
                                                   b0, sizeof (*tr));
              tr->next_index = next0;
              tr->decap_index = d0 ? d0 - mm->decaps : ~0;
              tr->tx_fib_index = vnet_buffer(b0)->sw_if_index[VLIB_TX];
              tr->label_host_byte_order = label0;
            }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, mpls_input_node.index,
                               MPLS_ERROR_PKTS_DECAP, from_frame->n_vectors);
  return from_frame->n_vectors;
}

static uword
mpls_input (vlib_main_t * vm,
            vlib_node_runtime_t * node,
            vlib_frame_t * from_frame)
{
  return mpls_input_inline (vm, node, from_frame, 1 /* is mpls-o-gre */);
}

static char * mpls_error_strings[] = {
#define mpls_error(n,s) s,
#include "error.def"
#undef mpls_error
};

VLIB_REGISTER_NODE (mpls_input_node) = {
  .function = mpls_input,
  .name = "mpls-gre-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .runtime_data_bytes = sizeof(mpls_input_runtime_t),

  .n_errors = MPLS_N_ERROR,
  .error_strings = mpls_error_strings,

  .n_next_nodes = MPLS_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [MPLS_INPUT_NEXT_##s] = n,
    foreach_mpls_input_next
#undef _
  },

  .format_buffer = format_mpls_gre_header_with_length,
  .format_trace = format_mpls_rx_trace,
  .unformat_buffer = unformat_mpls_gre_header,
};

VLIB_NODE_FUNCTION_MULTIARCH (mpls_input_node, mpls_input)

static uword
mpls_ethernet_input (vlib_main_t * vm,
                     vlib_node_runtime_t * node,
                     vlib_frame_t * from_frame)
{
  return mpls_input_inline (vm, node, from_frame, 0 /* is mpls-o-gre */);
}


VLIB_REGISTER_NODE (mpls_ethernet_input_node) = {
  .function = mpls_ethernet_input,
  .name = "mpls-ethernet-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .runtime_data_bytes = sizeof(mpls_input_runtime_t),

  .n_errors = MPLS_N_ERROR,
  .error_strings = mpls_error_strings,

  .n_next_nodes = MPLS_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [MPLS_INPUT_NEXT_##s] = n,
    foreach_mpls_input_next
#undef _
  },

  .format_buffer = format_mpls_eth_header_with_length,
  .format_trace = format_mpls_rx_trace,
  .unformat_buffer = unformat_mpls_gre_header,
};

VLIB_NODE_FUNCTION_MULTIARCH (mpls_ethernet_input_node, mpls_ethernet_input)

static void
mpls_setup_nodes (vlib_main_t * vm)
{
  vlib_node_t * n = vlib_get_node (vm, mpls_input_node.index);
  pg_node_t * pn = pg_get_node (mpls_input_node.index);
  mpls_input_runtime_t * rt;

  n->format_buffer = format_mpls_gre_header_with_length;
  n->unformat_buffer = unformat_mpls_gre_header;
  pn->unformat_edit = unformat_pg_mpls_header;

  rt = vlib_node_get_runtime_data (vm, mpls_input_node.index);
  rt->last_label = (u32) ~0;
  rt->last_inner_fib_index = 0;
  rt->last_outer_fib_index = 0;
  rt->mpls_main = &mpls_main;

  n = vlib_get_node (vm, mpls_ethernet_input_node.index);

  n->format_buffer = format_mpls_eth_header_with_length;

  n->unformat_buffer = 0; /* unformat_mpls_ethernet_header; */

  rt = vlib_node_get_runtime_data (vm, mpls_ethernet_input_node.index);
  rt->last_label = (u32) ~0;
  rt->last_inner_fib_index = 0;
  rt->last_outer_fib_index = 0;
  rt->mpls_main = &mpls_main;

  ethernet_register_input_type (vm, ETHERNET_TYPE_MPLS_UNICAST,
                                mpls_ethernet_input_node.index);
}

static clib_error_t * mpls_input_init (vlib_main_t * vm)
{
  clib_error_t * error; 

  error = vlib_call_init_function (vm, mpls_init);
  if (error)
    clib_error_report (error);

  mpls_setup_nodes (vm);

  return 0;
}

VLIB_INIT_FUNCTION (mpls_input_init);
