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
#include <cnat/cnat_inline.h>
#include <cnat/cnat_src_policy.h>

typedef enum cnat_translation_next_t_
{
  CNAT_TRANSLATION_NEXT_DROP,
  CNAT_TRANSLATION_NEXT_LOOKUP,
  CNAT_TRANSLATION_N_NEXT,
} cnat_translation_next_t;

vlib_node_registration_t cnat_vip_ip4_node;
vlib_node_registration_t cnat_vip_ip6_node;

/* CNat sub for NAT behind a fib entry (VIP or interposed real IP) */
static uword
cnat_vip_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		  cnat_node_ctx_t *ctx, int session_not_found,
		  cnat_session_t *session)
{
  vlib_combined_counter_main_t *cntm = &cnat_translation_counters;
  cnat_src_policy_main_t *cspm = &cnat_src_policy_main;
  const cnat_translation_t *ct = NULL;
  ip4_header_t *ip4 = NULL;
  ip_protocol_t iproto;
  ip6_header_t *ip6 = NULL;
  udp_header_t *udp0;
  cnat_client_t *cc;
  u16 next0;
  index_t cti;
  u8 trace_flags = 0;
  int rv;

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

  cc = cnat_client_get (vnet_buffer (b)->ip.adj_index[VLIB_TX]);

  /* Wrong session key */
  if (session->key.cs_proto == 0)
    {
      /* Dont translate & follow the fib programming */
      next0 = cc->cc_parent.dpoi_next_node;
      vnet_buffer (b)->ip.adj_index[VLIB_TX] = cc->cc_parent.dpoi_index;
      goto trace;
    }

  if (!session_not_found)
    {
      /* session table hit */
      cnat_timestamp_update (session->value.cs_ts_index, ctx->now);

      if (INDEX_INVALID != session->value.cs_lbi)
	{
	  /* Translate & follow the translation given LB */
	  next0 = session->value.dpoi_next_node;
	  vnet_buffer (b)->ip.adj_index[VLIB_TX] = session->value.cs_lbi;
	}
      else if (session->value.flags & CNAT_SESSION_FLAG_HAS_SNAT)
	{
	  /* The return needs DNAT, so we need an additionnal
	   * lookup after translation */
	  next0 = CNAT_TRANSLATION_NEXT_LOOKUP;
	}
      else
	{
	  /* Translate & follow the fib programming */
	  next0 = cc->cc_parent.dpoi_next_node;
	  vnet_buffer (b)->ip.adj_index[VLIB_TX] = cc->cc_parent.dpoi_index;
	}
    }
  else
    {
      ct =
	cnat_find_translation (cc->parent_cci,
			       clib_host_to_net_u16 (udp0->dst_port), iproto);
      if (NULL == ct)
	{
	  /* Dont translate & Follow the fib programming */
	  vnet_buffer (b)->ip.adj_index[VLIB_TX] = cc->cc_parent.dpoi_index;
	  next0 = cc->cc_parent.dpoi_next_node;
	  goto trace;
	}

      /* New flow, create the sessions */
      cnat_ep_trk_t *trk0;
      u32 rsession_flags = 0;
      u32 dpoi_index = -1;

      trk0 = cnat_load_balance (ct, ctx->af, ip4, ip6, &dpoi_index);
      if (PREDICT_FALSE (NULL == trk0))
	{
	  /* Dont translate & Follow the fib programming */
	  vnet_buffer (b)->ip.adj_index[VLIB_TX] = cc->cc_parent.dpoi_index;
	  next0 = cc->cc_parent.dpoi_next_node;
	  goto trace;
	}

      /* add the session */
      ip46_address_copy (&session->value.cs_ip[VLIB_TX],
			 &trk0->ct_ep[VLIB_TX].ce_ip.ip);
      if (ip_address_is_zero (&trk0->ct_ep[VLIB_RX].ce_ip))
	{
	  if (AF_IP4 == ctx->af)
	    ip46_address_set_ip4 (&session->value.cs_ip[VLIB_RX],
				  &ip4->src_address);
	  else
	    ip46_address_set_ip6 (&session->value.cs_ip[VLIB_RX],
				  &ip6->src_address);
	}
      else
	{
	  /* We source NAT with the translation */
	  rsession_flags |= CNAT_SESSION_FLAG_HAS_SNAT;
	  ip46_address_copy (&session->value.cs_ip[VLIB_RX],
			     &trk0->ct_ep[VLIB_RX].ce_ip.ip);
	}
      session->value.cs_port[VLIB_TX] =
	clib_host_to_net_u16 (trk0->ct_ep[VLIB_TX].ce_port);
      session->value.cs_port[VLIB_RX] =
	clib_host_to_net_u16 (trk0->ct_ep[VLIB_RX].ce_port);

      session->value.dpoi_next_node = ct->ct_lb.dpoi_next_node;
      session->value.cs_lbi = dpoi_index;
      session->value.flags = 0;

      rv = cspm->vip_policy (vm, b, session, &rsession_flags, ct, ctx);
      if (CNAT_SOURCE_ERROR_USE_DEFAULT == rv)
	rv = cspm->default_policy (vm, b, session, &rsession_flags, ct, ctx);
      if (rv)
	{
	  if (CNAT_SOURCE_ERROR_EXHAUSTED_PORTS == rv)
	    {
	      vlib_node_registration_t *node =
		(AF_IP4 == ctx->af) ? &cnat_vip_ip4_node : &cnat_vip_ip6_node;
	      vlib_node_increment_counter (vm, node->index,
					   CNAT_ERROR_EXHAUSTED_PORTS, 1);
	    }
	  next0 = CNAT_TRANSLATION_NEXT_DROP;
	  goto trace;
	}

      /* refcnt session in current client */
      cnat_client_cnt_session (cc);
      cnat_session_create (session, ctx, CNAT_LOCATION_FIB, rsession_flags);
      trace_flags |= CNAT_TRACE_SESSION_CREATED;

      next0 = ct->ct_lb.dpoi_next_node;
      vnet_buffer (b)->ip.adj_index[VLIB_TX] = session->value.cs_lbi;
    }

  if (AF_IP4 == ctx->af)
    cnat_translation_ip4 (session, ip4, udp0, vnet_buffer (b)->oflags);
  else
    cnat_translation_ip6 (session, ip6, udp0, vnet_buffer (b)->oflags);

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

VLIB_NODE_FN (cnat_vip_ip4_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_node_inline (vm, node, frame, cnat_vip_node_fn, AF_IP4,
			     CNAT_LOCATION_FIB, 1 /* do_trace */);
  return cnat_node_inline (vm, node, frame, cnat_vip_node_fn, AF_IP4,
			   CNAT_LOCATION_FIB, 0 /* do_trace */);
}

VLIB_NODE_FN (cnat_vip_ip6_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_node_inline (vm, node, frame, cnat_vip_node_fn, AF_IP6,
			     CNAT_LOCATION_FIB, 1 /* do_trace */);
  return cnat_node_inline (vm, node, frame, cnat_vip_node_fn, AF_IP6,
			   CNAT_LOCATION_FIB, 0 /* do_trace */);
}

VLIB_REGISTER_NODE (cnat_vip_ip4_node) =
{
  .name = "ip4-cnat-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = CNAT_TRANSLATION_N_NEXT,
  .next_nodes =
  {
    [CNAT_TRANSLATION_NEXT_DROP] = "ip4-drop",
    [CNAT_TRANSLATION_NEXT_LOOKUP] = "ip4-lookup",
  },
};
VLIB_REGISTER_NODE (cnat_vip_ip6_node) =
{
  .name = "ip6-cnat-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = CNAT_TRANSLATION_N_NEXT,
  .next_nodes =
  {
    [CNAT_TRANSLATION_NEXT_DROP] = "ip6-drop",
    [CNAT_TRANSLATION_NEXT_LOOKUP] = "ip6-lookup",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
