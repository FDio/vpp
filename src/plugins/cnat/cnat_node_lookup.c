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
			       1 /* is_feature */,
			       true /* alloc_if_not_found */);
  return cnat_lookup_inline (vm, node, frame, AF_IP4, 0 /* do_trace */, NULL,
			     1 /* is_feature */,
			     true /* alloc_if_not_found */);
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
  .runs_after = VNET_FEATURES ("vxlan4-input", "ipip4-input"),
};

VLIB_NODE_FN (cnat_lookup_feature_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_lookup_inline (vm, node, frame, AF_IP6, 1 /* do_trace */, NULL,
			       1 /* is_feature */,
			       true /* alloc_if_not_found */);
  return cnat_lookup_inline (vm, node, frame, AF_IP6, 0 /* do_trace */, NULL,
			     1 /* is_feature */,
			     true /* alloc_if_not_found */);
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
  .runs_after = VNET_FEATURES ("vxlan6-input", "ipip6-input"),
};

always_inline void
set_buffer_fib_index_from_interface (u32 *fib_index_by_sw_if_index,
				     vlib_buffer_t *b)
{
  vnet_buffer (b)->ip.fib_index =
    vec_elt (fib_index_by_sw_if_index, vnet_buffer (b)->sw_if_index[VLIB_RX]);
  vnet_buffer (b)->ip.fib_index =
    ((vnet_buffer (b)->sw_if_index[VLIB_TX] == (u32) ~0) ?
       vnet_buffer (b)->ip.fib_index :
       vec_elt (fib_index_by_sw_if_index,
		vnet_buffer (b)->sw_if_index[VLIB_TX]));
}

always_inline void
cnat_writeback_new_flow (vlib_buffer_t *b, ip_address_family_t af, u16 *next)
{
  cnat_bihash_kv_t bkey;
  cnat_timestamp_t *ts;
  cnat_session_t *session = (cnat_session_t *) &bkey;
  u32 iph_offset, n_retries = 0, rv, port_seed = 0;

  if (vnet_buffer2 (b)->session.flags & CNAT_BUFFER_SESSION_FLAG_NO_RETURN)
    return;

  ts =
    cnat_timestamp_get_if_exists (vnet_buffer2 (b)->session.generic_flow_id);
  if (ts == NULL)
    {
      *next = 0; // TODO: DROP, probably needs improvement
      return;
    }

  clib_memset_u8 (&session->key, 0, sizeof (session->key));
  iph_offset = vnet_buffer (b)->ip.save_rewrite_length;
  cnat_5tuple_t *rewrite_from;
  rewrite_from = &ts->cts_rewrites[CNAT_LOCATION_INPUT].tuple;
  if (ts->cts_rewrites[CNAT_LOCATION_OUTPUT].tuple.iproto != 0)
    /* this is for snat (output) */
    rewrite_from = &ts->cts_rewrites[CNAT_LOCATION_OUTPUT].tuple;

  cnat_make_buffer_5tuple (b, af, &session->key.cs_5tuple, iph_offset,
			   1 /* swap */, rewrite_from);
  u32 *fib_index_by_sw_if_index = AF_IP6 == af ?
				    ip6_main.fib_index_by_sw_if_index :
				    ip4_main.fib_index_by_sw_if_index;
  set_buffer_fib_index_from_interface (fib_index_by_sw_if_index, b);
  session->key.fib_index = vnet_buffer (b)->ip.fib_index;
  session->value.cs_session_index = vnet_buffer2 (b)->session.generic_flow_id;
  session->value.cs_flags = CNAT_SESSION_IS_RETURN;

  u8 protocol =
    (af == AF_IP4) ?
      ((ip4_header_t *) ((u8 *) vlib_buffer_get_current (b) + iph_offset))
	->protocol :
      ((ip6_header_t *) ((u8 *) vlib_buffer_get_current (b) + iph_offset))
	->protocol;
  u16 udp_dst_port;
  if (protocol == IP_PROTOCOL_UDP)
    {
      udp_dst_port =
	(af == AF_IP4) ?
	  ((udp_header_t *) (((ip4_header_t *) ((u8 *)
						  vlib_buffer_get_current (b) +
						iph_offset)) +
			     1))
	    ->dst_port :
	  ((udp_header_t *) (((ip6_header_t *) ((u8 *)
						  vlib_buffer_get_current (b) +
						iph_offset)) +
			     1))
	    ->dst_port;
    }

  /* Increment refcnt only if not IP-in-IP or VXLAN (UDP dst port 4789) */
  if ((protocol != IP_PROTOCOL_IP_IN_IP) &&
      !(protocol == IP_PROTOCOL_UDP &&
	clib_net_to_host_u16 (udp_dst_port) == 4789))
    clib_atomic_add_fetch (&ts->ts_session_refcnt, 1);

  ASSERT (ts->ts_session_refcnt <= 2);

retry_add_ression:
  // FIXME
  rv = cnat_bihash_add_with_overwrite_cb (
    &cnat_session_db, &bkey,
    n_retries < 100 ? NULL : cnat_session_free_stale_cb, NULL);
  if (rv && n_retries++ < 100)
    {
      random_u32 (&port_seed);
      session->key.cs_5tuple.port[VLIB_TX] = port_seed;
      goto retry_add_ression;
    }
}

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

  if (n_left >= 4)
    {
      vnet_feature_next_u16 (&next[0], b[0]);
      vnet_feature_next_u16 (&next[1], b[1]);
      vnet_feature_next_u16 (&next[2], b[2]);
      vnet_feature_next_u16 (&next[3], b[3]);
    }

  while (n_left >= 4)
    {

      if (vnet_buffer2 (b[0])->session.state == CNAT_LOOKUP_IS_NEW)
	cnat_writeback_new_flow (b[0], af, &next[0]);
      if (vnet_buffer2 (b[1])->session.state == CNAT_LOOKUP_IS_NEW)
	cnat_writeback_new_flow (b[1], af, &next[1]);
      if (vnet_buffer2 (b[2])->session.state == CNAT_LOOKUP_IS_NEW)
	cnat_writeback_new_flow (b[2], af, &next[2]);
      if (vnet_buffer2 (b[3])->session.state == CNAT_LOOKUP_IS_NEW)
	cnat_writeback_new_flow (b[3], af, &next[3]);

      if (n_left >= 8)
	{
	  vnet_feature_next_u16 (&next[4], b[4]);
	  vnet_feature_next_u16 (&next[5], b[5]);
	  vnet_feature_next_u16 (&next[6], b[6]);
	  vnet_feature_next_u16 (&next[7], b[7]);
	}

      if (n_left >= 12)
	{
	  vlib_prefetch_buffer_header (b[8], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[11], LOAD);
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      vnet_feature_next_u16 (&next[0], b[0]);

      if (vnet_buffer2 (b[0])->session.state == CNAT_LOOKUP_IS_NEW)
	cnat_writeback_new_flow (b[0], af, &next[0]);

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
