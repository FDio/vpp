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
#include <calico/calico_node.h>
#include <calico/calico_translation.h>

#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>

typedef struct calico_translation_trace_t_
{
  u32 found;
  calico_session_t session;
} calico_translation_trace_t;

typedef enum calico_translation_next_t_
{
  CALICO_TRANSLATION_NEXT_DROP,
  CALICO_TRANSLATION_NEXT_LOOKUP,
  CALICO_TRANSLATION_N_NEXT,
} calico_translation_next_t;

static u8 *
format_calico_translation_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  calico_translation_trace_t *t =
    va_arg (*args, calico_translation_trace_t *);

  s =
    format (s, "found:%d %U", t->found, format_calico_session, &t->session,
	    1);
  return s;
}

/* Calico sub for NAT behind a fib entry (VIP or interposed real IP) */
always_inline uword
calico_vip_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_buffer_t * b,
		   calico_node_ctx_t * ctx, int rv, calico_session_t * session)
{
  vlib_combined_counter_main_t *cm = &calico_translation_counters;
  const calico_translation_t *ct;
  ip4_header_t *ip4;
  ip_protocol_t iproto;
  ip6_header_t *ip6;
  udp_header_t *udp0;
  calico_client_t *cc;
  u16 next0;
  index_t cti;
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

  cc = calico_client_get (vnet_buffer (b)->ip.adj_index[VLIB_TX]);

  if (iproto != IP_PROTOCOL_UDP && iproto != IP_PROTOCOL_TCP)
    {
      /* Dont translate & follow the fib programming */
      next0 = cc->cc_parent.dpoi_next_node;
      vnet_buffer (b)->ip.adj_index[VLIB_TX] = cc->cc_parent.dpoi_index;
      goto trace;
    }

  ct = calico_find_translation (cc->parent_cci,
				clib_host_to_net_u16 (udp0->dst_port),
				iproto);

  if (!rv)
    {
      /* session table hit */
      calico_timestamp_update (session->value.cs_ts_index, ctx->now);

      if (NULL != ct)
	{
	  /* Translate & follow the translation given LB */
	  next0 = ct->ct_lb.dpoi_next_node;
	  vnet_buffer (b)->ip.adj_index[VLIB_TX] = session->value.cs_lbi;
	}
      else if (session->value.flags & CALICO_SESSION_FLAG_HAS_SNAT)
	{
	  /* The return needs DNAT, so we need an additionnal
	   * lookup after translation */
	  next0 = CALICO_TRANSLATION_NEXT_LOOKUP;
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
      if (NULL == ct)
	{
	  /* Dont translate & Follow the fib programming */
	  vnet_buffer (b)->ip.adj_index[VLIB_TX] = cc->cc_parent.dpoi_index;
	  next0 = cc->cc_parent.dpoi_next_node;
	  goto trace;
	}

      /* New flow, create the sessions */
      const load_balance_t *lb0;
      calico_ep_trk_t *trk0;
      u32 hash_c0, bucket0;
      u32 rsession_flags = 0;
      const dpo_id_t *dpo0;

      lb0 = load_balance_get (ct->ct_lb.dpoi_index);

      /* session table miss */
      hash_c0 = (AF_IP4 == ctx->af ?
		 ip4_compute_flow_hash (ip4, lb0->lb_hash_config) :
		 ip6_compute_flow_hash (ip6, lb0->lb_hash_config));
      bucket0 = hash_c0 & lb0->lb_n_buckets_minus_1;
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
	  rsession_flags |= CALICO_SESSION_FLAG_HAS_SNAT;
	  ip46_address_copy (&session->value.cs_ip[VLIB_RX],
			     &trk0->ct_ep[VLIB_RX].ce_ip.ip);
	}
      session->value.cs_port[VLIB_TX] =
	clib_host_to_net_u16 (trk0->ct_ep[VLIB_TX].ce_port);
      session->value.cs_port[VLIB_RX] =
	clib_host_to_net_u16 (trk0->ct_ep[VLIB_RX].ce_port);
      if (!session->value.cs_port[VLIB_RX])
	session->value.cs_port[VLIB_RX] = udp0->src_port;
      session->value.cs_lbi = dpo0->dpoi_index;
      session->value.flags = 0;

      calico_client_cnt_session (cc);
      calico_session_create (session, ctx, rsession_flags);

      next0 = ct->ct_lb.dpoi_next_node;
      vnet_buffer (b)->ip.adj_index[VLIB_TX] = session->value.cs_lbi;
      cti = ct - calico_translation_pool;
      vlib_increment_combined_counter (cm, ctx->thread_index, cti, 1,
				       vlib_buffer_length_in_chain (vm, b));
    }


  if (AF_IP4 == ctx->af)
    calico_translation_ip4 (session, ip4, udp0);
  else
    calico_translation_ip6 (session, ip6, udp0);

trace:
  if (PREDICT_FALSE (ctx->do_trace))
    {
      calico_translation_trace_t *t;

      t = vlib_add_trace (vm, node, b, sizeof (*t));

      t->found = !rv;
      if (NULL != session)
	clib_memcpy (&t->session, session, sizeof (t->session));
    }
  return next0;
}

VLIB_NODE_FN (calico_vip_ip4_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return calico_node_inline (vm, node, frame, calico_vip_inline, AF_IP4,
			       1 /* do_trace */ );
  return calico_node_inline (vm, node, frame, calico_vip_inline, AF_IP4,
			     0 /* do_trace */ );
}

VLIB_NODE_FN (calico_vip_ip6_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return calico_node_inline (vm, node, frame, calico_vip_inline, AF_IP6,
			       1 /* do_trace */ );
  return calico_node_inline (vm, node, frame, calico_vip_inline, AF_IP6,
			     0 /* do_trace */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (calico_vip_ip4_node) =
{
  .name = "ip4-calico-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_calico_translation_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = CALICO_TRANSLATION_N_NEXT,
  .next_nodes =
  {
    [CALICO_TRANSLATION_NEXT_DROP] = "ip4-drop",
    [CALICO_TRANSLATION_NEXT_LOOKUP] = "ip4-lookup",
  }
};
VLIB_REGISTER_NODE (calico_vip_ip6_node) =
{
  .name = "ip6-calico-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_calico_translation_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = CALICO_TRANSLATION_N_NEXT,
  .next_nodes =
  {
    [CALICO_TRANSLATION_NEXT_DROP] = "ip6-drop",
    [CALICO_TRANSLATION_NEXT_LOOKUP] = "ip6-lookup",
  }
};
/* *INDENT-ON* */

