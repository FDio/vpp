/*
 * policy_encap.c: mpls-o-e policy encap
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
  u32 encap_index;
} mpls_policy_encap_trace_t;

u8 * format_mpls_policy_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mpls_policy_encap_trace_t * t = va_arg (*args, mpls_policy_encap_trace_t *);

  s = format (s, "MPLS-POLICY-ENCAP: next-index %d encap-index %d",
              t->next_index, t->encap_index);

  return s;
}

vlib_node_registration_t mpls_policy_encap_node;

#define foreach_mpls_policy_encap_next          \
_(DROP, "error-drop")

typedef enum {
#define _(s,n) MPLS_POLICY_ENCAP_NEXT_##s,
  foreach_mpls_policy_encap_next
#undef _
  MPLS_POLICY_ENCAP_N_NEXT,
} mpls_policy_encap_next_t;

#define foreach_mpls_policy_error                               \
_(PKTS_ENCAP, "mpls policy tunnel packets encapsulated")

typedef enum {
#define _(n,s) MPLS_POLICY_ENCAP_ERROR_##n,
  foreach_mpls_policy_error
  MPLS_POLICY_ENCAP_N_ERROR,
#undef _
} mpls_policy_encap_error_t;

static char * mpls_policy_encap_error_strings[] =
  {
#define _(n,s) s,
    foreach_mpls_policy_error
#undef _
};
    
static uword
mpls_policy_encap (vlib_main_t * vm,
                   vlib_node_runtime_t * node,
                   vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  mpls_main_t * mm = &mpls_main;
  
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  
  next_index = node->cached_next_index;
  
  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
          u8 * h0;
          u32 encap_index0;
          u32 next0;
          mpls_encap_t * e0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          encap_index0 = vnet_buffer(b0)->l2_classify.opaque_index;

          e0 = pool_elt_at_index (mm->encaps, encap_index0);

          vlib_buffer_advance (b0, -(word)vec_len(e0->rewrite));
          h0 = vlib_buffer_get_current (b0);
          memcpy (h0, e0->rewrite, vec_len(e0->rewrite));

          next0 = e0->output_next_index;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              mpls_policy_encap_trace_t *tr = 
                vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->encap_index = encap_index0;
            }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, mpls_policy_encap_node.index,
                               MPLS_POLICY_ENCAP_ERROR_PKTS_ENCAP, 
                               from_frame->n_vectors);
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (mpls_policy_encap_node) =  {
  .function = mpls_policy_encap,
  .name = "mpls-policy-encap",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  
  .runtime_data_bytes = 0,
  
  .n_errors = MPLS_POLICY_ENCAP_N_ERROR,
  .error_strings = mpls_policy_encap_error_strings,
  
  .format_trace = format_mpls_policy_encap_trace,
  
  .n_next_nodes = MPLS_POLICY_ENCAP_N_NEXT,
  .next_nodes = {
#define _(s,n) [MPLS_POLICY_ENCAP_NEXT_##s] = n,
    foreach_mpls_policy_encap_next
#undef _
  },
};

static clib_error_t *
mpls_policy_encap_init (vlib_main_t * vm)
{
  mpls_main_t * mm = &mpls_main;
  clib_error_t * error;
  u32 ip6_next_index;

  if ((error = vlib_call_init_function (vm, mpls_init)))
    return error;
  
  mm->ip_classify_mpls_policy_encap_next_index = 
    vlib_node_add_next (mm->vlib_main,
                        ip4_classify_node.index, 
                        mpls_policy_encap_node.index);

  /* 
   * Must add the same arc to ip6_classify so the
   * next-index vectors are congruent
   */
  ip6_next_index = 
    vlib_node_add_next (mm->vlib_main,
                        ip6_classify_node.index, 
                        mpls_policy_encap_node.index);

  if (ip6_next_index != mm->ip_classify_mpls_policy_encap_next_index)
    return clib_error_return 
      (0, "ip4/ip6 classifier next vector botch: %d vs %d", 
       ip6_next_index, mm->ip_classify_mpls_policy_encap_next_index);

  return 0;
}

VLIB_INIT_FUNCTION (mpls_policy_encap_init);
