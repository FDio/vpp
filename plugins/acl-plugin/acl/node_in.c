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
#include "node_in.h"

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 match_acl_index;
  u32 match_rule_index;
  u32 trace_bitmap;
} acl_in_trace_t;

/* packet trace format function */
static u8 *
format_acl_in_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  acl_in_trace_t *t = va_arg (*args, acl_in_trace_t *);

  s =
    format (s,
	    "ACL_IN: sw_if_index %d, next index %d, match: inacl %d rule %d trace_bits %08x",
	    t->sw_if_index, t->next_index, t->match_acl_index,
	    t->match_rule_index, t->trace_bitmap);
  return s;
}

vlib_node_registration_t acl_in_node;

#define foreach_acl_in_error \
_(ACL_CHECK, "InACL check packets processed")

typedef enum
{
#define _(sym,str) ACL_IN_ERROR_##sym,
  foreach_acl_in_error
#undef _
    ACL_IN_N_ERROR,
} acl_in_error_t;

static char *acl_in_error_strings[] = {
#define _(sym,string) string,
  foreach_acl_in_error
#undef _
};

static uword
acl_in_node_fn (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  acl_in_next_t next_index;
  u32 pkts_acl_checked = 0;
  u32 feature_bitmap0;
  u32 trace_bitmap = 0;
  u32 *input_feat_next_node_index =
    acl_main.acl_in_node_feat_next_node_index;

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
	  u32 sw_if_index0;
	  u32 next = ~0;
	  u32 match_acl_index = ~0;
	  u32 match_rule_index = ~0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);


	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  feature_bitmap0 = vnet_buffer (b0)->l2.feature_bitmap;

	  input_acl_packet_match (sw_if_index0, b0, &next, &match_acl_index,
				  &match_rule_index, &trace_bitmap);
	  if (next != ~0)
	    {
	      next0 = next;
	    }
	  if (next0 == ~0)
	    {
	      next0 =
		feat_bitmap_get_next_node_index (input_feat_next_node_index,
						 feature_bitmap0);
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      acl_in_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->match_acl_index = match_acl_index;
	      t->match_rule_index = match_rule_index;
	      t->trace_bitmap = trace_bitmap;
	    }

	  next0 = next0 < node->n_next_nodes ? next0 : 0;

	  pkts_acl_checked += 1;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, acl_in_node.index,
			       ACL_IN_ERROR_ACL_CHECK, pkts_acl_checked);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (acl_in_node) =
{
  .function = acl_in_node_fn,.name = "acl-plugin-in",.vector_size =
    sizeof (u32),.format_trace = format_acl_in_trace,.type =
    VLIB_NODE_TYPE_INTERNAL,.n_errors =
    ARRAY_LEN (acl_in_error_strings),.error_strings =
    acl_in_error_strings,.n_next_nodes = ACL_IN_N_NEXT,
    /* edit / add dispositions here */
    .next_nodes =
  {
  [ACL_IN_ERROR_DROP] = "error-drop",
      [ACL_IN_ETHERNET_INPUT] = "ethernet-input",
      [ACL_IN_L2S_INPUT_IP4_ADD] = "aclp-l2s-input-ip4-add",
      [ACL_IN_L2S_INPUT_IP6_ADD] = "aclp-l2s-input-ip6-add",}
,};
