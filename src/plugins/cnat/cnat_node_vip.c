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

#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>

#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

typedef struct cnat_translation_trace_t_
{
  cnat_session_t session;
  cnat_translation_t tr;
  u32 found_session;
  u32 created_session;
  u32 has_tr;
} cnat_translation_trace_t;

typedef enum cnat_translation_next_t_
{
  CNAT_TRANSLATION_NEXT_DROP,
  CNAT_TRANSLATION_NEXT_LOOKUP,
  CNAT_TRANSLATION_N_NEXT,
} cnat_translation_next_t;

vlib_node_registration_t cnat_vip_ip4_node;
vlib_node_registration_t cnat_vip_ip6_node;

static u8 *
format_cnat_translation_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cnat_translation_trace_t *t = va_arg (*args, cnat_translation_trace_t *);

  if (t->found_session)
    s = format (s, "found: %U", format_cnat_session, &t->session, 1);
  else if (t->created_session)
    s = format (s, "created: %U\n  tr: %U",
		format_cnat_session, &t->session, 1,
		format_cnat_translation, &t->tr, 0);
  else if (t->has_tr)
    s = format (s, "tr pass: %U", format_cnat_translation, &t->tr, 0);
  else
    s = format (s, "not found");
  return s;
}

/* CNat sub for NAT behind a fib entry (VIP or interposed real IP) */
static uword
cnat_vip_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_buffer_t * b,
		  cnat_node_ctx_t * ctx, int rv, cnat_session_t * session)
{
  vlib_combined_counter_main_t *cntm = &cnat_translation_counters;
  const cnat_translation_t *ct = NULL;
  ip4_header_t *ip4 = NULL;
  ip_protocol_t iproto;
  ip6_header_t *ip6 = NULL;
  udp_header_t *udp0;
  cnat_client_t *cc;
  u16 next0;
  index_t cti;
  int created_session = 0;
  cnat_src_policy_main_t *cspm = &cnat_src_policy_main;
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

  cc = cnat_client_get (vnet_buffer (b)->ip.adj_index);

  if (iproto != IP_PROTOCOL_UDP && iproto != IP_PROTOCOL_TCP
      && iproto != IP_PROTOCOL_ICMP && iproto != IP_PROTOCOL_ICMP6)
    {
      /* Dont translate & follow the fib programming */
      next0 = cc->cc_parent.dpoi_next_node;
      vnet_buffer (b)->ip.adj_index = cc->cc_parent.dpoi_index;
      goto trace;
    }

  if (!rv)
    {
      /* session table hit */
      cnat_timestamp_update (session->value.cs_ts_index, ctx->now);

      if (INDEX_INVALID != session->value.cs_lbi)
	{
	  /* Translate & follow the translation given LB */
	  ct = cnat_translation_get (session->value.ct_index);
	  next0 = ct->ct_lb.dpoi_next_node;
	  vnet_buffer (b)->ip.adj_index = session->value.cs_lbi;
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
	  vnet_buffer (b)->ip.adj_index = cc->cc_parent.dpoi_index;
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
	  vnet_buffer (b)->ip.adj_index = cc->cc_parent.dpoi_index;
	  next0 = cc->cc_parent.dpoi_next_node;
	  goto trace;
	}

      /* New flow, create the sessions */
      const load_balance_t *lb0;
      cnat_ep_trk_t *trk0;
      u32 hash_c0, bucket0;
      u32 rsession_flags = 0;
      const dpo_id_t *dpo0;

      lb0 = load_balance_get (ct->ct_lb.dpoi_index);
      if (!lb0->lb_n_buckets)
	{
	  /* Dont translate & Follow the fib programming */
	  vnet_buffer (b)->ip.adj_index = cc->cc_parent.dpoi_index;
	  next0 = cc->cc_parent.dpoi_next_node;
	  goto trace;
	}

      /* session table miss */
      hash_c0 = (AF_IP4 == ctx->af ?
		 ip4_compute_flow_hash (ip4, lb0->lb_hash_config) :
		 ip6_compute_flow_hash (ip6, lb0->lb_hash_config));
      bucket0 = hash_c0 % lb0->lb_n_buckets;
      dpo0 = load_balance_get_fwd_bucket (lb0, bucket0);

      /* add the session */
      trk0 = &ct->ct_paths[bucket0];

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

      session->value.ct_index = ct - cnat_translation_pool;
      session->value.cs_lbi = dpo0->dpoi_index;

      rv = cspm->vip_policy (vm, b, session, &rsession_flags, ct, ctx);
      if (CNAT_SOURCE_ERROR_USE_DEFAULT == rv)
	rv = cspm->default_policy (vm, b, session, &rsession_flags, ct, ctx);
      if (rv)
	{
	  if (CNAT_SOURCE_ERROR_EXHAUSTED_PORTS == rv)
	    vlib_node_increment_counter (vm, cnat_vip_ip4_node.index,
					 CNAT_ERROR_EXHAUSTED_PORTS, 1);
	  next0 = CNAT_TRANSLATION_NEXT_DROP;
	  goto trace;
	}

      /* refcnt session in current client */
      cnat_client_cnt_session (cc);
      cnat_session_create (session, ctx, rsession_flags);
      created_session = 1;

      next0 = ct->ct_lb.dpoi_next_node;
      vnet_buffer (b)->ip.adj_index = session->value.cs_lbi;
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
      cnat_translation_trace_t *t;

      t = vlib_add_trace (vm, node, b, sizeof (*t));

      t->found_session = !rv;
      t->created_session = created_session;
      if (t->found_session || t->created_session)
	clib_memcpy (&t->session, session, sizeof (t->session));
      t->has_tr = (NULL != ct);
      if (t->has_tr)
	clib_memcpy (&t->tr, ct, sizeof (cnat_translation_t));
    }
  return next0;
}

VLIB_NODE_FN (cnat_vip_ip4_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_node_inline (vm, node, frame, cnat_vip_node_fn, AF_IP4,
			     1 /* do_trace */ );
  return cnat_node_inline (vm, node, frame, cnat_vip_node_fn, AF_IP4,
			   0 /* do_trace */ );
}

VLIB_NODE_FN (cnat_vip_ip6_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_node_inline (vm, node, frame, cnat_vip_node_fn, AF_IP6,
			     1 /* do_trace */ );
  return cnat_node_inline (vm, node, frame, cnat_vip_node_fn, AF_IP6,
			   0 /* do_trace */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cnat_vip_ip4_node) =
{
  .name = "ip4-cnat-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_translation_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = CNAT_TRANSLATION_N_NEXT,
  .next_nodes =
  {
    [CNAT_TRANSLATION_NEXT_DROP] = "ip4-drop",
    [CNAT_TRANSLATION_NEXT_LOOKUP] = "ip4-lookup",
  }
};
VLIB_REGISTER_NODE (cnat_vip_ip6_node) =
{
  .name = "ip6-cnat-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_translation_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = CNAT_TRANSLATION_N_NEXT,
  .next_nodes =
  {
    [CNAT_TRANSLATION_NEXT_DROP] = "ip6-drop",
    [CNAT_TRANSLATION_NEXT_LOOKUP] = "ip6-lookup",
  }
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
