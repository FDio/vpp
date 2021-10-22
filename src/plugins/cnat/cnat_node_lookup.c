/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vlibmemory/api.h>
#include <cnat/cnat_node.h>
#include <cnat/cnat_translation.h>
#include <cnat/cnat_inline.h>
#include <cnat/cnat_src_policy.h>
#include <cnat/cnat_snat_policy.h>

#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>

#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

typedef enum cnat_feature_next_
{
  CNAT_FEATURE_NEXT_DROP,
  CNAT_FEATURE_N_NEXT,
} cnat_feature_next_t;

vlib_node_registration_t cnat_lookup_feature_ip4_node;
vlib_node_registration_t cnat_lookup_feature_ip6_node;
vlib_node_registration_t cnat_writeback_feature_ip4_node;
vlib_node_registration_t cnat_writeback_feature_ip6_node;

VLIB_NODE_FN (cnat_lookup_feature_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_lookup_inline (vm, node, frame, AF_IP4, 1 /* do_trace */, NULL,
			       1 /* is_feature */);
  return cnat_lookup_inline (vm, node, frame, AF_IP4, 0 /* do_trace */, NULL,
			     1 /* is_feature */);
}

VLIB_REGISTER_NODE (cnat_lookup_feature_ip4_node) = {
  .name = "cnat-lookup-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CNAT_N_ERROR,
  .error_strings = cnat_error_strings,
  .sibling_of = "ip4-lookup",
};

VNET_FEATURE_INIT (cnat_in_ip4_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "cnat-lookup-ip4",
};

VLIB_NODE_FN (cnat_lookup_feature_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_lookup_inline (vm, node, frame, AF_IP6, 1 /* do_trace */, NULL,
			       1 /* is_feature */);
  return cnat_lookup_inline (vm, node, frame, AF_IP6, 0 /* do_trace */, NULL,
			     1 /* is_feature */);
}

VLIB_REGISTER_NODE (cnat_lookup_feature_ip6_node) = {
  .name = "cnat-lookup-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CNAT_N_ERROR,
  .error_strings = cnat_error_strings,
  .sibling_of = "ip6-lookup",
};

VNET_FEATURE_INIT (cnat_in_ip6_feature, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "cnat-lookup-ip6",
  .runs_before = VNET_FEATURES ("acl-plugin-in-ip6-fa"),
};

always_inline uword
cnat_writeback_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame, ip_address_family_t af,
		       u8 do_trace)
{
  u32 n_left, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {

      if (vnet_buffer (b[0])->session.state == CNAT_LOOKUP_IS_NEW)
	{

	  if (!(vnet_buffer (b[0])->session.flags &
		CNAT_BUFFER_SESSION_FLAG_NO_RETURN))
	    {
	      cnat_bihash_kv_t bvalue;
	      cnat_bihash_kv_t bkey;
	      cnat_session_t *session = (cnat_session_t *) &bkey;
	      u32 iph_offset;
	      int rv;

	      iph_offset = vnet_buffer (b[0])->ip.save_rewrite_length;
	      cnat_session_make_key (b[0], af, &bkey, iph_offset,
				     1 /* swap */);

	      /* First search for existing reverse session */
	      rv = cnat_bihash_search_i2 (&cnat_session_db, &bkey, &bvalue);
	      if (!rv)
		{
		  /* Reverse session already exists
		    cleanup before creating for refcnts */
		  cnat_session_t *found_rsession = (cnat_session_t *) &bvalue;
		  cnat_session_free (found_rsession);
		}

	      session->value.cs_session_index =
		vnet_buffer (b[0])->session.generic_flow_id;
	      session->value.cs_flags = CNAT_SESSION_IS_RETURN;
	      cnat_bihash_add_del (&cnat_session_db, &bkey, 1 /* add */);
	    }
	}

      vnet_feature_next_u16 (&next[0], b[0]);

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (cnat_writeback_feature_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_writeback_inline (vm, node, frame, AF_IP4, 1 /* do_trace */);
  return cnat_writeback_inline (vm, node, frame, AF_IP4, 0 /* do_trace */);
}

VLIB_REGISTER_NODE (cnat_writeback_feature_ip4_node) = {
  .name = "cnat-writeback-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CNAT_N_ERROR,
  .error_strings = cnat_error_strings,
  .n_next_nodes = CNAT_FEATURE_N_NEXT,
  .next_nodes = {
      [CNAT_FEATURE_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (cnat_out_ip4_feature, static) = {
  .arc_name = "ip4-output",
  .node_name = "cnat-writeback-ip4",
  .runs_before = VNET_FEATURES ("gso-ip4"),
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
};

VLIB_NODE_FN (cnat_writeback_feature_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_writeback_inline (vm, node, frame, AF_IP6, 1 /* do_trace */);
  return cnat_writeback_inline (vm, node, frame, AF_IP6, 0 /* do_trace */);
}

VLIB_REGISTER_NODE (cnat_writeback_feature_ip6_node) = {
  .name = "cnat-writeback-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CNAT_N_ERROR,
  .error_strings = cnat_error_strings,
  .n_next_nodes = CNAT_FEATURE_N_NEXT,
  .next_nodes = {
      [CNAT_FEATURE_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (cnat_out_ip6_feature, static) = {
  .arc_name = "ip6-output",
  .node_name = "cnat-writeback-ip6",
  .runs_before = VNET_FEATURES ("gso-ip6"),
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip6-fa"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
