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
#include <cnat/cnat_snat.h>
#include <cnat/cnat_inline.h>
#include <cnat/cnat_src_policy.h>

typedef enum cnat_snat_next_
{
  CNAT_SNAT_NEXT_DROP,
  CNAT_SNAT_N_NEXT,
} cnat_snat_next_t;

typedef struct cnat_snat_trace_
{
  cnat_session_t session;
  u32 found_session;
  u32 created_session;
} cnat_snat_trace_t;

vlib_node_registration_t cnat_snat_ip4_node;
vlib_node_registration_t cnat_snat_ip6_node;

static u8 *
format_cnat_snat_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cnat_snat_trace_t *t = va_arg (*args, cnat_snat_trace_t *);

  if (t->found_session)
    s = format (s, "found: %U", format_cnat_session, &t->session, 1);
  else if (t->created_session)
    s = format (s, "created: %U\n  tr: %U",
		format_cnat_session, &t->session, 1);
  else
    s = format (s, "not found");
  return s;
}

/* CNat sub for source NAT as a feature arc on ip[46]-unicast
   This node's sub shouldn't apply to the same flows as
   cnat_vip_inline */
always_inline uword
cnat_snat_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_buffer_t * b,
		  cnat_node_ctx_t * ctx, int rv, cnat_session_t * session)
{
  cnat_main_t *cm = &cnat_main;
  int created_session = 0;
  ip4_header_t *ip4;
  ip_protocol_t iproto;
  ip6_header_t *ip6;
  udp_header_t *udp0;
  u32 arc_next0;
  u16 next0;
  u16 sport;

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

  if (iproto != IP_PROTOCOL_UDP && iproto != IP_PROTOCOL_TCP
      && iproto != IP_PROTOCOL_ICMP && iproto != IP_PROTOCOL_ICMP6)
    {
      /* Dont translate */
      goto trace;
    }

  if (!rv)
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
      rv = cnat_search_snat_prefix (&ip46_dst_address, ctx->af);
      if (!rv)
	{
	  /* Prefix table hit, we shouldn't source NAT */
	  goto trace;
	}
      /* New flow, create the sessions if necessary. session will be a snat
         session, and rsession will be a dnat session
         Note: packet going through this path are going to the outside,
         so they will never hit the NAT again (they are not going towards
         a VIP) */
      if (AF_IP4 == ctx->af)
	{
	  ip46_address_set_ip4 (&session->value.cs_ip[VLIB_RX],
				&ip_addr_v4 (&cm->snat_ip4.ce_ip));
	  ip46_address_set_ip4 (&session->value.cs_ip[VLIB_TX],
				&ip4->dst_address);
	}
      else
	{
	  ip46_address_set_ip6 (&session->value.cs_ip[VLIB_RX],
				&ip_addr_v6 (&cm->snat_ip6.ce_ip));
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

      created_session = 1;
      cnat_session_create (session, ctx, CNAT_SESSION_FLAG_HAS_SNAT);
    }


  if (AF_IP4 == ctx->af)
    cnat_translation_ip4 (session, ip4, udp0);
  else
    cnat_translation_ip6 (session, ip6, udp0);

trace:
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      cnat_snat_trace_t *t;

      t = vlib_add_trace (vm, node, b, sizeof (*t));

      t->found_session = !rv;
      t->created_session = created_session;
      if (t->found_session || t->created_session)
	clib_memcpy (&t->session, session, sizeof (t->session));
    }
  return next0;
}

VLIB_NODE_FN (cnat_snat_ip4_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_node_inline (vm, node, frame, cnat_snat_inline, AF_IP4,
			     1 /* do_trace */ );
  return cnat_node_inline (vm, node, frame, cnat_snat_inline, AF_IP4,
			   0 /* do_trace */ );
}

VLIB_NODE_FN (cnat_snat_ip6_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_node_inline (vm, node, frame, cnat_snat_inline, AF_IP6,
			     1 /* do_trace */ );
  return cnat_node_inline (vm, node, frame, cnat_snat_inline, AF_IP6,
			   0 /* do_trace */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cnat_snat_ip4_node) =
{
  .name = "ip4-cnat-snat",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_snat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CNAT_N_ERROR,
  .error_strings = cnat_error_strings,
  .n_next_nodes = CNAT_SNAT_N_NEXT,
  .next_nodes =
  {
    [CNAT_SNAT_NEXT_DROP] = "ip4-drop",
  }
};

VLIB_REGISTER_NODE (cnat_snat_ip6_node) =
{
  .name = "ip6-cnat-snat",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_snat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CNAT_N_ERROR,
  .error_strings = cnat_error_strings,
  .n_next_nodes = CNAT_SNAT_N_NEXT,
  .next_nodes =
  {
    [CNAT_SNAT_NEXT_DROP] = "ip6-drop",
  }
};

VNET_FEATURE_INIT (cnat_snat_ip4_node, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-cnat-snat",
};

VNET_FEATURE_INIT (cnat_snat_ip6_node, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-cnat-snat",
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
