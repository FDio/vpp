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

vlib_node_registration_t cnat_input_feature_ip4_node;
vlib_node_registration_t cnat_input_feature_ip6_node;
vlib_node_registration_t cnat_output_feature_ip4_node;
vlib_node_registration_t cnat_output_feature_ip6_node;

always_inline uword
cnat_input_feature_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_buffer_t *b, cnat_node_ctx_t *ctx,
		       int session_not_found, cnat_session_t *session)
{
  vlib_combined_counter_main_t *cntm = &cnat_translation_counters;
  const cnat_translation_t *ct = NULL;
  ip4_header_t *ip4 = NULL;
  ip_protocol_t iproto;
  ip6_header_t *ip6 = NULL;
  udp_header_t *udp0;
  cnat_client_t *cc;
  u32 next0;
  index_t cti;
  u8 trace_flags = 0;

  /* By default follow arc default next */
  vnet_feature_next (&next0, b);

  if (AF_IP4 == ctx->af)
    {
      ip4 = vlib_buffer_get_current (b);
      iproto = ip4->protocol;
      udp0 = (udp_header_t *) (ip4 + 1);
      cc = cnat_client_ip4_find (
	&ip4->dst_address); /* TODO do this only if no session? */
    }
  else
    {
      ip6 = vlib_buffer_get_current (b);
      iproto = ip6->protocol;
      udp0 = (udp_header_t *) (ip6 + 1);
      cc = cnat_client_ip6_find (&ip6->dst_address); /* TODO: same as above */
    }

  /* Wrong session key */
  if (session->key.cs_proto == 0)
    goto trace;

  if (!session_not_found)
    /* session table hit */
    cnat_timestamp_update (session->value.cs_ts_index, ctx->now);
  else if (!cc)
    goto trace; /* dst address is not a vip */
  else
    {
      ct = cnat_find_translation (
	cc->parent_cci, clib_host_to_net_u16 (udp0->dst_port), iproto);
      if (NULL == ct)
	/* Dont translate  */
	/* TODO: create identity session to avoid slowpath ? */
	goto trace;

      /* New flow, create the sessions */
      const load_balance_t *lb0;
      cnat_ep_trk_t *trk0;
      u32 rsession_flags = CNAT_SESSION_FLAG_NO_CLIENT;
      u32 dpoi_index = -1;

      lb0 = load_balance_get (ct->ct_lb.dpoi_index);
      if (!lb0->lb_n_buckets)
	/* Can't translate TODO: should drop / reject? */
	goto trace;

      /* session table miss */
      trk0 = cnat_load_balance (ct, ctx->af, ip4, ip6, &dpoi_index);
      if (PREDICT_FALSE (NULL == trk0))
	{
	  /* Dont translate & Follow the fib programming */
	  vnet_buffer (b)->ip.adj_index[VLIB_TX] = cc->cc_parent.dpoi_index;
	  next0 = cc->cc_parent.dpoi_next_node;
	  goto trace;
	}

      ip46_address_copy (&session->value.cs_ip[VLIB_TX],
			 &trk0->ct_ep[VLIB_TX].ce_ip.ip);

      /* never source nat in this node */
      if (AF_IP4 == ctx->af)
	ip46_address_set_ip4 (&session->value.cs_ip[VLIB_RX],
			      &ip4->src_address);
      else
	ip46_address_set_ip6 (&session->value.cs_ip[VLIB_RX],
			      &ip6->src_address);

      session->value.cs_port[VLIB_TX] =
	clib_host_to_net_u16 (trk0->ct_ep[VLIB_TX].ce_port);
      session->value.cs_port[VLIB_RX] = udp0->src_port;

      if (trk0->ct_flags & CNAT_TRK_FLAG_NO_NAT)
	{
	  const dpo_id_t *dpo0;
	  const load_balance_t *lb1;

	  lb1 = load_balance_get (trk0->ct_dpo.dpoi_index);
	  /* Assume backend has exactly one item in LB */
	  dpo0 = load_balance_get_bucket_i (lb1, 0);

	  session->value.dpoi_next_node = dpo0->dpoi_next_node;
	  session->value.cs_lbi = dpo0->dpoi_index;
	  session->value.flags = CNAT_SESSION_FLAG_NO_NAT;
	}

      /* refcnt session in current client */
      cnat_client_cnt_session (cc);
      cnat_session_create (session, ctx, CNAT_LOCATION_OUTPUT, rsession_flags);
      trace_flags |= CNAT_TRACE_SESSION_CREATED;
    }

  if (session->value.flags & CNAT_SESSION_FLAG_NO_NAT)
    {
      /* If we don't translate, directly do the lookup & bypass arc */
      next0 = session->value.dpoi_next_node;
      vnet_buffer (b)->ip.adj_index[VLIB_TX] = session->value.cs_lbi;
      goto trace;
    }

  if (AF_IP4 == ctx->af)
    cnat_translation_ip4 (session, ip4, udp0);
  else
    cnat_translation_ip6 (session, ip6, udp0);

  if (NULL != ct)
    {
      cti = ct - cnat_translation_pool;
      vlib_increment_combined_counter (cntm, ctx->thread_index, cti, 1,
				       vlib_buffer_length_in_chain (vm, b));
    }

trace:
  if (PREDICT_FALSE (ctx->do_trace))
    {
      trace_flags |= session_not_found ? 0 : CNAT_TRACE_SESSION_FOUND;
      cnat_add_trace (vm, node, b, session, ct, trace_flags);
    }
  return next0;
}

VLIB_NODE_FN (cnat_input_feature_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_node_inline (vm, node, frame, cnat_input_feature_fn, AF_IP4,
			     CNAT_LOCATION_INPUT, 1 /* do_trace */);
  return cnat_node_inline (vm, node, frame, cnat_input_feature_fn, AF_IP4,
			   CNAT_LOCATION_INPUT, 0 /* do_trace */);
}

VLIB_REGISTER_NODE (cnat_input_feature_ip4_node) = {
  .name = "cnat-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CNAT_N_ERROR,
  .error_strings = cnat_error_strings,
  .sibling_of = "ip4-lookup",
};

VNET_FEATURE_INIT (cnat_in_ip4_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "cnat-input-ip4",
  .runs_before = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};

VLIB_NODE_FN (cnat_input_feature_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_node_inline (vm, node, frame, cnat_input_feature_fn, AF_IP6,
			     CNAT_LOCATION_INPUT, 1 /* do_trace */);
  return cnat_node_inline (vm, node, frame, cnat_input_feature_fn, AF_IP6,
			   CNAT_LOCATION_INPUT, 0 /* do_trace */);
}

VLIB_REGISTER_NODE (cnat_input_feature_ip6_node) = {
  .name = "cnat-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CNAT_N_ERROR,
  .error_strings = cnat_error_strings,
  .sibling_of = "ip6-lookup",
};

VNET_FEATURE_INIT (cnat_in_ip6_feature, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "cnat-input-ip6",
  .runs_before = VNET_FEATURES ("acl-plugin-in-ip6-fa"),
};

/* output feature node, creates snat sessions when required and
 * translates back for existing sessions */
always_inline uword
cnat_output_feature_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_buffer_t *b, cnat_node_ctx_t *ctx,
			int session_not_found, cnat_session_t *session)
{
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;
  ip4_header_t *ip4 = NULL;
  ip_protocol_t iproto;
  ip6_header_t *ip6 = NULL;
  udp_header_t *udp0;
  u32 iph_offset = 0;
  u32 next0;
  u16 sport;
  u8 do_snat = 0;
  u8 trace_flags = 0;
  int rv;

  /* By default follow arc default next */
  vnet_feature_next (&next0, b);
  iph_offset = vnet_buffer (b)->ip.save_rewrite_length;

  if (AF_IP4 == ctx->af)
    {
      ip4 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b) + iph_offset);
      iproto = ip4->protocol;
      udp0 = (udp_header_t *) (ip4 + 1);
    }
  else
    {
      ip6 = (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b) + iph_offset);
      iproto = ip6->protocol;
      udp0 = (udp_header_t *) (ip6 + 1);
    }

  /* Wrong session key */
  if (session->key.cs_proto == 0)
    goto trace;

  if (!session_not_found)
    {
      /* session table hit */
      cnat_timestamp_update (session->value.cs_ts_index, ctx->now);
    }
  else if (!cpm->snat_policy)
    goto trace;
  else
    {
      do_snat = cpm->snat_policy (b, session);
      if (do_snat != 1)
	goto trace;

      if (AF_IP4 == ctx->af)
	{
	  if (ip_address_is_zero (&cpm->snat_ip4.ce_ip))
	    goto trace;

	  ip46_address_set_ip4 (&session->value.cs_ip[VLIB_RX],
				&ip_addr_v4 (&cpm->snat_ip4.ce_ip));
	  ip46_address_set_ip4 (&session->value.cs_ip[VLIB_TX],
				&ip4->dst_address);
	}
      else
	{
	  if (ip_address_is_zero (&cpm->snat_ip6.ce_ip))
	    goto trace;

	  ip46_address_set_ip6 (&session->value.cs_ip[VLIB_RX],
				&ip_addr_v6 (&cpm->snat_ip6.ce_ip));
	  ip46_address_set_ip6 (&session->value.cs_ip[VLIB_TX],
				&ip6->dst_address);
	}
      sport = 0;
      rv = cnat_allocate_port (&sport, iproto);
      if (rv)
	{
	  vlib_node_increment_counter (vm, cnat_output_feature_ip6_node.index,
				       CNAT_ERROR_EXHAUSTED_PORTS, 1);
	  next0 = CNAT_FEATURE_NEXT_DROP;
	  goto trace;
	}
      session->value.cs_port[VLIB_RX] = sport;
      session->value.cs_port[VLIB_TX] = sport;
      if (iproto == IP_PROTOCOL_TCP || iproto == IP_PROTOCOL_UDP)
	session->value.cs_port[VLIB_TX] = udp0->dst_port;

      session->value.cs_lbi = INDEX_INVALID;
      session->value.flags =
	CNAT_SESSION_FLAG_NO_CLIENT | CNAT_SESSION_FLAG_ALLOC_PORT;

      trace_flags |= CNAT_TRACE_SESSION_CREATED;
      cnat_session_create (session, ctx, CNAT_LOCATION_INPUT,
			   CNAT_SESSION_FLAG_NO_CLIENT);
    }

  if (AF_IP4 == ctx->af)
    cnat_translation_ip4 (session, ip4, udp0);
  else
    cnat_translation_ip6 (session, ip6, udp0);

trace:
  if (PREDICT_FALSE (ctx->do_trace))
    {
      trace_flags |= do_snat ? 0 : CNAT_TRACE_NO_NAT;
      trace_flags |= session_not_found ? 0 : CNAT_TRACE_SESSION_FOUND;
      cnat_add_trace (vm, node, b, session, NULL, trace_flags);
    }
  return next0;
}

VLIB_NODE_FN (cnat_output_feature_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_node_inline (vm, node, frame, cnat_output_feature_fn, AF_IP4,
			     CNAT_LOCATION_OUTPUT, 1 /* do_trace */);
  return cnat_node_inline (vm, node, frame, cnat_output_feature_fn, AF_IP4,
			   CNAT_LOCATION_OUTPUT, 0 /* do_trace */);
}

VLIB_REGISTER_NODE (cnat_output_feature_ip4_node) = {
  .name = "cnat-output-ip4",
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
  .node_name = "cnat-output-ip4",
  .runs_before = VNET_FEATURES ("gso-ip4"),
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa"),
};

VLIB_NODE_FN (cnat_output_feature_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_node_inline (vm, node, frame, cnat_output_feature_fn, AF_IP6,
			     CNAT_LOCATION_OUTPUT, 1 /* do_trace */);
  return cnat_node_inline (vm, node, frame, cnat_output_feature_fn, AF_IP6,
			   CNAT_LOCATION_OUTPUT, 0 /* do_trace */);
}

VLIB_REGISTER_NODE (cnat_output_feature_ip6_node) = {
  .name = "cnat-output-ip6",
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
  .node_name = "cnat-output-ip6",
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
