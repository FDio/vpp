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
#include <cnat/cnat_snat_policy.h>
#include <cnat/cnat_inline.h>
#include <cnat/cnat_src_policy.h>

typedef enum cnat_snat_next_
{
  CNAT_SNAT_NEXT_DROP,
  CNAT_SNAT_N_NEXT,
} cnat_snat_next_t;

vlib_node_registration_t cnat_snat_ip4_node;
vlib_node_registration_t cnat_snat_ip6_node;

/* CNat sub for source NAT as a feature arc on ip[46]-unicast
   This node's sub shouldn't apply to the same flows as
   cnat_vip_inline */
static uword
cnat_snat_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		   vlib_buffer_t *b, cnat_node_ctx_t *ctx,
		   int session_not_found, cnat_session_t *session)
{
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;
  ip4_header_t *ip4 = NULL;
  ip_protocol_t iproto;
  ip6_header_t *ip6 = NULL;
  udp_header_t *udp0;
  u32 arc_next0;
  u16 next0;
  u16 sport;
  u8 trace_flags = 0;
  int rv, do_snat;

  if (AF_IP4 == ctx->af)
    {
      ip4 = vlib_buffer_get_current (b);
      iproto = ip4->protocol;
      udp0 = (udp_header_t *) (ip4 + 1);
    }
  else
    {
      ip6 = vlib_buffer_get_current (b);
      iproto = ip6->protocol;
      udp0 = (udp_header_t *) (ip6 + 1);
    }

  /* By default don't follow previous next0 */
  vnet_feature_next (&arc_next0, b);
  next0 = arc_next0;

  /* Wrong session key */
  if (session->key.cs_proto == 0)
    goto trace;

  if (!session_not_found)
    {
      /* session table hit */
      cnat_timestamp_update (session->value.cs_ts_index, ctx->now);
    }
  else
    {
      ip46_address_t ip46_dst_address;
      if (AF_IP4 == ctx->af)
	ip46_address_set_ip4 (&ip46_dst_address, &ip4->dst_address);
      else
	ip46_address_set_ip6 (&ip46_dst_address, &ip6->dst_address);

      do_snat = cpm->snat_policy (b, session);
      if (!do_snat)
	goto trace;

      /* New flow, create the sessions if necessary. session will be a snat
         session, and rsession will be a dnat session
         Note: packet going through this path are going to the outside,
         so they will never hit the NAT again (they are not going towards
         a VIP) */
      if (AF_IP4 == ctx->af)
	{
	  if (!(cpm->snat_ip4.ce_flags & CNAT_EP_FLAG_RESOLVED))
	    goto trace;
	  ip46_address_set_ip4 (&session->value.cs_ip[VLIB_RX],
				&ip_addr_v4 (&cpm->snat_ip4.ce_ip));
	  ip46_address_set_ip4 (&session->value.cs_ip[VLIB_TX],
				&ip4->dst_address);
	}
      else
	{
	  if (!(cpm->snat_ip6.ce_flags & CNAT_EP_FLAG_RESOLVED))
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
	  vlib_node_increment_counter (vm, cnat_snat_ip4_node.index,
				       CNAT_ERROR_EXHAUSTED_PORTS, 1);
	  next0 = CNAT_SNAT_NEXT_DROP;
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

      cnat_session_create (session, ctx);
      cnat_rsession_create (session, ctx, CNAT_LOCATION_FIB,
			    CNAT_SESSION_FLAG_HAS_SNAT);
    }

  if (AF_IP4 == ctx->af)
    cnat_translation_ip4 (session, ip4, udp0, vnet_buffer (b)->oflags);
  else
    cnat_translation_ip6 (session, ip6, udp0, vnet_buffer (b)->oflags);

trace:
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      trace_flags |= session_not_found ? 0 : CNAT_TRACE_SESSION_FOUND;
      cnat_add_trace (vm, node, b, session, NULL, trace_flags);
    }
  return next0;
}

VLIB_NODE_FN (cnat_snat_ip4_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_node_inline (vm, node, frame, cnat_snat_node_fn, AF_IP4,
			     CNAT_LOCATION_FIB, 1 /* do_trace */);
  return cnat_node_inline (vm, node, frame, cnat_snat_node_fn, AF_IP4,
			   CNAT_LOCATION_FIB, 0 /* do_trace */);
}

VLIB_NODE_FN (cnat_snat_ip6_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_node_inline (vm, node, frame, cnat_snat_node_fn, AF_IP6,
			     CNAT_LOCATION_FIB, 1 /* do_trace */);
  return cnat_node_inline (vm, node, frame, cnat_snat_node_fn, AF_IP6,
			   CNAT_LOCATION_FIB, 0 /* do_trace */);
}

VLIB_REGISTER_NODE (cnat_snat_ip4_node) = {
  .name = "cnat-snat-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CNAT_N_ERROR,
  .error_strings = cnat_error_strings,
  .n_next_nodes = CNAT_SNAT_N_NEXT,
  .next_nodes = {
      [CNAT_SNAT_NEXT_DROP] = "ip4-drop",
  },
};

VLIB_REGISTER_NODE (cnat_snat_ip6_node) = {
  .name = "cnat-snat-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CNAT_N_ERROR,
  .error_strings = cnat_error_strings,
  .n_next_nodes = CNAT_SNAT_N_NEXT,
  .next_nodes = {
      [CNAT_SNAT_NEXT_DROP] = "ip6-drop",
  },
};

VNET_FEATURE_INIT (cnat_snat_ip4_node, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "cnat-snat-ip4",
};

VNET_FEATURE_INIT (cnat_snat_ip6_node, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "cnat-snat-ip6",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
