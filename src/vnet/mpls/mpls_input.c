/*
 * node.c: MPLS input
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
#include <vnet/mpls/mpls.h>
#include <vnet/feature/feature.h>

typedef struct {
  u32 next_index;
  u32 label_net_byte_order;
} mpls_input_trace_t;

#define foreach_mpls_input_next			\
_(DROP, "error-drop")                           \
_(LOOKUP, "mpls-lookup")

typedef enum {
#define _(s,n) MPLS_INPUT_NEXT_##s,
  foreach_mpls_input_next
#undef _
  MPLS_INPUT_N_NEXT,
} mpls_input_next_t;

static u8 *
format_mpls_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mpls_input_trace_t * t = va_arg (*args, mpls_input_trace_t *);
  char * next_name;
  u32 label;
  next_name = "BUG!";
  label = clib_net_to_host_u32(t->label_net_byte_order);

#define _(a,b) if (t->next_index == MPLS_INPUT_NEXT_##a) next_name = b;
  foreach_mpls_input_next;
#undef _
  
  s = format (s, "MPLS: next %s[%d]  label %d ttl %d", 
              next_name, t->next_index,
	      vnet_mpls_uc_get_label(label),
	      vnet_mpls_uc_get_ttl(label));

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
                   vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  mpls_input_runtime_t * rt;
  mpls_main_t * mm;
  u32 thread_index = vlib_get_thread_index();
  vlib_simple_counter_main_t * cm;
  vnet_main_t * vnm = vnet_get_main();

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  rt = vlib_node_get_runtime_data (vm, mpls_input_node.index);
  mm = rt->mpls_main;
  /* 
   * Force an initial lookup every time, in case the control-plane
   * changed the label->FIB mapping.
   */
  rt->last_label = ~0;

  next_index = node->cached_next_index;

  cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
                         VNET_INTERFACE_COUNTER_MPLS);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          u32 bi0, next0, sw_if_index0;
          u32 bi1, next1, sw_if_index1;
          vlib_buffer_t *b0, *b1;
          char *h0, *h1;

          /* Prefetch next iteration. */
          {
              vlib_buffer_t * p2, * p3;

              p2 = vlib_get_buffer (vm, from[2]);
              p3 = vlib_get_buffer (vm, from[3]);

              vlib_prefetch_buffer_header (p2, STORE);
              vlib_prefetch_buffer_header (p3, STORE);

              CLIB_PREFETCH (p2->data, sizeof (h0[0]), STORE);
              CLIB_PREFETCH (p3->data, sizeof (h1[0]), STORE);
          }

          bi0 = to_next[0] = from[0];
          bi1 = to_next[1] = from[1];

          from += 2;
          to_next += 2;
          n_left_from -= 2;
          n_left_to_next -= 2;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);

          h0 = vlib_buffer_get_current (b0);
          h1 = vlib_buffer_get_current (b1);

          sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

          /* TTL expired? */
          if (PREDICT_FALSE(h0[3] == 0))
          {
              next0 = MPLS_INPUT_NEXT_DROP;
              b0->error = node->errors[MPLS_ERROR_TTL_EXPIRED];
          }
          else
          {
              next0 = MPLS_INPUT_NEXT_LOOKUP;
              vnet_feature_arc_start(mm->input_feature_arc_index,
                                     sw_if_index0, &next0, b0);
              vlib_increment_simple_counter (cm, thread_index, sw_if_index0, 1);
          }

          if (PREDICT_FALSE(h1[3] == 0))
          {
              next1 = MPLS_INPUT_NEXT_DROP;
              b1->error = node->errors[MPLS_ERROR_TTL_EXPIRED];
          }
          else
          {
              next1 = MPLS_INPUT_NEXT_LOOKUP;
              vnet_feature_arc_start(mm->input_feature_arc_index,
                                     sw_if_index1, &next1, b1);
              vlib_increment_simple_counter (cm, thread_index, sw_if_index1, 1);
          }

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_input_trace_t *tr = vlib_add_trace (vm, node,
                                                       b0, sizeof (*tr));
              tr->next_index = next0;
              tr->label_net_byte_order = *((u32*)h0);
          }
          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_input_trace_t *tr = vlib_add_trace (vm, node,
                                                       b1, sizeof (*tr));
              tr->next_index = next1;
              tr->label_net_byte_order = *((u32*)h1);
          }

          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1,
                                           next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 sw_if_index0, next0, bi0;
	  vlib_buffer_t * b0;
	  char * h0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          h0 = vlib_buffer_get_current (b0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /* TTL expired? */
	  if (PREDICT_FALSE(h0[3] == 0))
           {
              next0 = MPLS_INPUT_NEXT_DROP;
              b0->error = node->errors[MPLS_ERROR_TTL_EXPIRED];
            }
	  else
            {
              next0 = MPLS_INPUT_NEXT_LOOKUP;
	      vnet_feature_arc_start(mm->input_feature_arc_index, sw_if_index0, &next0, b0);
              vlib_increment_simple_counter (cm, thread_index, sw_if_index0, 1);
            }

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              mpls_input_trace_t *tr = vlib_add_trace (vm, node, 
						       b0, sizeof (*tr));
              tr->next_index = next0;
              tr->label_net_byte_order = *(u32*)h0;
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
  return mpls_input_inline (vm, node, from_frame);
}

static char * mpls_error_strings[] = {
#define mpls_error(n,s) s,
#include "error.def"
#undef mpls_error
};

VLIB_REGISTER_NODE (mpls_input_node) = {
  .function = mpls_input,
  .name = "mpls-input",
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

  .format_buffer = format_mpls_unicast_header_net_byte_order,
  .format_trace = format_mpls_input_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (mpls_input_node, mpls_input)

static void
mpls_setup_nodes (vlib_main_t * vm)
{
  mpls_input_runtime_t * rt;
  pg_node_t * pn;

  pn = pg_get_node (mpls_input_node.index);
  pn->unformat_edit = unformat_pg_mpls_header;

  rt = vlib_node_get_runtime_data (vm, mpls_input_node.index);
  rt->last_label = (u32) ~0;
  rt->last_inner_fib_index = 0;
  rt->last_outer_fib_index = 0;
  rt->mpls_main = &mpls_main;

  ethernet_register_input_type (vm, ETHERNET_TYPE_MPLS,
                                mpls_input_node.index);
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

static clib_error_t * mpls_input_worker_init (vlib_main_t * vm)
{
  mpls_input_runtime_t * rt;
  rt = vlib_node_get_runtime_data (vm, mpls_input_node.index);
  rt->last_label = (u32) ~0;
  rt->last_inner_fib_index = 0;
  rt->last_outer_fib_index = 0;
  rt->mpls_main = &mpls_main;
  return 0;
}

VLIB_WORKER_INIT_FUNCTION (mpls_input_worker_init);
