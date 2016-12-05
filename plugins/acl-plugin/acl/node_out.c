/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <acl/acl.h>

#include "node_out.h"

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 match_acl_index;
  u32 match_rule_index;
  u32 trace_bitmap;
} acl_out_trace_t;

/* packet trace format function */
static u8 *
format_acl_out_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  acl_out_trace_t *t = va_arg (*args, acl_out_trace_t *);
  s =
    format (s,
	    "ACL_OUT: sw_if_index %d, next index %d, match: outacl %d rule %d trace_bits %08x",
	    t->sw_if_index, t->next_index, t->match_acl_index,
	    t->match_rule_index, t->trace_bitmap);
  return s;
}

vlib_node_registration_t acl_out_node;

#define foreach_acl_out_error \
_(ACL_CHECK, "OutACL check packets processed")

typedef enum
{
#define _(sym,str) ACL_OUT_ERROR_##sym,
  foreach_acl_out_error
#undef _
    ACL_OUT_N_ERROR,
} acl_out_error_t;

static char *acl_out_error_strings[] = {
#define _(sym,string) string,
  foreach_acl_out_error
#undef _
};

static uword
acl_out_node_fn (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  acl_main_t *am = &acl_main;
  l2_output_next_nodes_st *next_nodes = &am->acl_out_output_next_nodes;
  u32 n_left_from, *from, *to_next;
  acl_out_next_t next_index;
  u32 pkts_acl_checked = 0;
  u32 feature_bitmap0;
  u32 cached_sw_if_index = (u32) ~ 0;
  u32 cached_next_index = (u32) ~ 0;
  u32 match_acl_index = ~0;
  u32 match_rule_index = ~0;
  u32 trace_bitmap = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = ~0;
	  u32 next = 0;
	  u32 sw_if_index0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);


	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  feature_bitmap0 = vnet_buffer (b0)->l2.feature_bitmap;

	  output_acl_packet_match (sw_if_index0, b0, &next, &match_acl_index,
				   &match_rule_index, &trace_bitmap);
	  if (next != ~0)
	    {
	      next0 = next;
	    }
	  if (next0 == ~0)
	    {
	      l2_output_dispatch (vm,
				  am->vnet_main,
				  node,
				  acl_out_node.index,
				  &cached_sw_if_index,
				  &cached_next_index,
				  next_nodes,
				  b0, sw_if_index0, feature_bitmap0, &next0);
	    }



	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      acl_out_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->match_acl_index = match_acl_index;
	      t->match_rule_index = match_rule_index;
	      t->trace_bitmap = trace_bitmap;
	    }

	  pkts_acl_checked += 1;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, acl_out_node.index,
			       ACL_OUT_ERROR_ACL_CHECK, pkts_acl_checked);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (acl_out_node) =
{
  .function = acl_out_node_fn,.name = "acl-plugin-out",.vector_size =
    sizeof (u32),.format_trace = format_acl_out_trace,.type =
    VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (acl_out_error_strings),.error_strings =
    acl_out_error_strings,.n_next_nodes = ACL_OUT_N_NEXT,
    /* edit / add dispositions here */
    .next_nodes =
  {
  [ACL_OUT_ERROR_DROP] = "error-drop",
      [ACL_OUT_INTERFACE_OUTPUT] = "interface-output",
      [ACL_OUT_L2S_OUTPUT_IP4_ADD] = "aclp-l2s-output-ip4-add",
      [ACL_OUT_L2S_OUTPUT_IP6_ADD] = "aclp-l2s-output-ip6-add",}
,};
