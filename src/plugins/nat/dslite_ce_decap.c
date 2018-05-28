/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <nat/dslite.h>
#include <nat/nat_inlines.h>

vlib_node_registration_t dslite_ce_decap_node;

typedef enum
{
  DSLITE_CE_DECAP_NEXT_IP4_LOOKUP,
  DSLITE_IN2OUT_NEXT_IP6_ICMP,
  DSLITE_CE_DECAP_NEXT_DROP,
  DSLITE_CE_DECAP_N_NEXT,
} dslite_ce_decap_next_t;

static char *dslite_ce_decap_error_strings[] = {
#define _(sym,string) string,
  foreach_dslite_error
#undef _
};

static uword
dslite_ce_decap_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  dslite_ce_decap_next_t next_index;

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
	  u32 next0 = DSLITE_CE_DECAP_NEXT_IP4_LOOKUP;
	  u8 error0 = DSLITE_ERROR_CE_DECAP;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  u32 proto0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip60 = vlib_buffer_get_current (b0);

	  if (PREDICT_FALSE (ip60->protocol != IP_PROTOCOL_IP_IN_IP))
	    {
	      if (ip60->protocol == IP_PROTOCOL_ICMP6)
		{
		  next0 = DSLITE_IN2OUT_NEXT_IP6_ICMP;
		  goto trace0;
		}
	      error0 = DSLITE_ERROR_BAD_IP6_PROTOCOL;
	      next0 = DSLITE_CE_DECAP_NEXT_DROP;
	      goto trace0;
	    }

	  ip40 = vlib_buffer_get_current (b0) + sizeof (ip6_header_t);
	  proto0 = ip_proto_to_snat_proto (ip40->protocol);

	  if (PREDICT_FALSE (proto0 == ~0))
	    {
	      error0 = DSLITE_ERROR_UNSUPPORTED_PROTOCOL;
	      next0 = DSLITE_CE_DECAP_NEXT_DROP;
	      goto trace0;
	    }

	  ip40->tos =
	    (clib_net_to_host_u32
	     (ip60->ip_version_traffic_class_and_flow_label) & 0x0ff00000) >>
	    20;
	  vlib_buffer_advance (b0, sizeof (ip6_header_t));

	trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      dslite_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	    }

	  b0->error = node->errors[error0];

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dslite_ce_decap_node) = {
  .function = dslite_ce_decap_node_fn,
  .name = "dslite-ce-decap",
  .vector_size = sizeof (u32),
  .format_trace = format_dslite_ce_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (dslite_ce_decap_error_strings),
  .error_strings = dslite_ce_decap_error_strings,
  .n_next_nodes = DSLITE_CE_DECAP_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [DSLITE_CE_DECAP_NEXT_DROP] = "error-drop",
    [DSLITE_CE_DECAP_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [DSLITE_IN2OUT_NEXT_IP6_ICMP] = "ip6-icmp-input",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (dslite_ce_decap_node, dslite_ce_decap_node_fn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
