/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vlibmemory/api.h>
#include <cnat/cnat_node.h>
#include <cnat/cnat_inline.h>
#include <cnat/cnat_src_policy.h>

vlib_node_registration_t cnat_vip_ip4_node;
vlib_node_registration_t cnat_vip_ip6_node;

static_always_inline cnat_timestamp_rewrite_t *
cnat_vip_feature_new_flow_inline (vlib_main_t *vm, vlib_buffer_t *b, ip_address_family_t af,
				  cnat_timestamp_t *ts, cnat_client_t *cc)
{
  vlib_combined_counter_main_t *cntm = &cnat_translation_counters;
  cnat_src_policy_main_t *cspm = &cnat_src_policy_main;
  cnat_timestamp_rewrite_t *rw = NULL;
  const cnat_translation_t *ct = NULL;
  ip4_header_t *ip4 = NULL;
  ip6_header_t *ip6 = NULL;
  ip_protocol_t iproto;
  udp_header_t *udp0;
  cnat_ep_trk_t *trk0;
  u32 dpoi_index = -1;
  u8 do_snat = 0;
  index_t cti;
  int rv;

  if (AF_IP4 == af)
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

  ct = cnat_find_translation (cc->parent_cci, clib_host_to_net_u16 (udp0->dst_port), iproto);
  if (!ct)
    return (NULL);

  cti = ct - cnat_translation_pool;
  vlib_increment_combined_counter (cntm, vm->thread_index, cti, 1,
				   vlib_buffer_length_in_chain (vm, b));

  /* add the rewrite object */
  rw = &ts->cts_rewrites[CNAT_LOCATION_FIB];
  ts->ts_rw_bm |= 1 << CNAT_LOCATION_FIB;

  trk0 = cnat_load_balance (ct, af, ip4, ip6, &dpoi_index);
  if (PREDICT_FALSE (!trk0))
    {
      /* Load balance is empty or not resolved, drop  */
      rw->cts_dpoi_next_node = CNAT_NODE_VIP_NEXT_DROP;
      return (rw);
    }

  cnat_make_buffer_5tuple (b, af, &rw->tuple, 0 /* iph_offset */, 0 /* swap */);

  if (af == AF_IP4)
    rw->tuple.ip4[VLIB_TX].as_u32 = trk0->ct_ep[VLIB_TX].ce_ip.ip.ip4.as_u32;
  else
    ip6_address_copy (&rw->tuple.ip6[VLIB_TX], &trk0->ct_ep[VLIB_TX].ce_ip.ip.ip6);
  rw->tuple.port[VLIB_TX] = trk0->ct_ep[VLIB_TX].ce_port ?
			      clib_host_to_net_u16 (trk0->ct_ep[VLIB_TX].ce_port) :
			      rw->tuple.port[VLIB_TX];
  rw->tuple.port[VLIB_RX] = trk0->ct_ep[VLIB_RX].ce_port ?
			      clib_host_to_net_u16 (trk0->ct_ep[VLIB_RX].ce_port) :
			      rw->tuple.port[VLIB_RX];

  if (!ip_address_is_zero (&trk0->ct_ep[VLIB_RX].ce_ip))
    {
      /* We source NAT with the translation */
      do_snat = 1;
      if (af == AF_IP4)
	rw->tuple.ip4[VLIB_RX].as_u32 = trk0->ct_ep[VLIB_RX].ce_ip.ip.ip4.as_u32;
      else
	ip6_address_copy (&rw->tuple.ip6[VLIB_RX], &trk0->ct_ep[VLIB_RX].ce_ip.ip.ip6);
      if (ct->flags & CNAT_TR_FLAG_ALLOCATE_PORT)
	{
	  rv = cspm->vip_policy (iproto, &rw->tuple.port[VLIB_RX]);
	  if (CNAT_SOURCE_ERROR_USE_DEFAULT == rv)
	    rv = cspm->default_policy (iproto, &rw->tuple.port[VLIB_RX]);
	  if (rv)
	    {
	      if (CNAT_SOURCE_ERROR_EXHAUSTED_PORTS == rv)
		{
		  vlib_node_registration_t *node =
		    (AF_IP4 == af) ? &cnat_vip_ip4_node : &cnat_vip_ip6_node;
		  vlib_node_increment_counter (vm, node->index, CNAT_ERROR_EXHAUSTED_PORTS, 1);
		}
	      /* If we encounter an error, store the drop decision
	       * in the rewrite object, as default action is fwd */
	      rw->cts_dpoi_next_node = CNAT_NODE_VIP_NEXT_DROP;
	      return (rw);
	    }
	}
      rw->cts_flags |= CNAT_TS_RW_FLAG_HAS_ALLOCATED_PORT;
    }

  rw->cts_dpoi_next_node = ct->ct_lb.dpoi_next_node;
  rw->cts_lbi = dpoi_index;

  /* refcnt session in current client */
  cnat_client_cnt_session (cc);
  if (!(ct->flags & CNAT_TR_FLAG_NO_RETURN_SESSION))
    {
      cnat_timestamp_rewrite_t *rrw = NULL;

      rrw = &ts->cts_rewrites[CNAT_LOCATION_FIB + CNAT_IS_RETURN];
      ts->ts_rw_bm |= 1 << (CNAT_LOCATION_FIB + CNAT_IS_RETURN);

      /* The return needs DNAT, so we need an additionnal
       * lookup after translation */
      rrw->cts_dpoi_next_node = do_snat ? CNAT_NODE_VIP_NEXT_LOOKUP : ~0;
      rrw->cts_lbi = (u32) ~0;

      cnat_make_buffer_5tuple (b, af, &rrw->tuple, 0 /* iph_offset */, 1 /* swap */);

      clib_atomic_add_fetch (&ts->ts_session_refcnt, 1);

      cnat_rsession_create (rw, vnet_buffer2 (b)->session.generic_flow_id, CNAT_FIB_TABLE);
    }

  return rw;
}

/* CNat sub for NAT behind a fib entry (VIP or interposed real IP) */
static void
cnat_vip_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next0,
		  ip_address_family_t af, f64 now, u8 do_trace)
{
  cnat_timestamp_rewrite_t *rw = NULL;
  cnat_timestamp_t *ts;
  cnat_client_t *cc;

  cc = cnat_client_get (vnet_buffer (b)->ip.adj_index[VLIB_TX]);
  /* By default dont translate & Follow the fib programming */
  vnet_buffer (b)->ip.adj_index[VLIB_TX] = cc->cc_parent.dpoi_index;
  *next0 = cc->cc_parent.dpoi_next_node;

  ts = cnat_timestamp_update (vnet_buffer2 (b)->session.generic_flow_id, now);
  if (vnet_buffer2 (b)->session.state == CNAT_LOOKUP_IS_OK)
    {
      /* Translate & follow the translation given LB */
      rw = (ts->ts_rw_bm & (1 << CNAT_LOCATION_FIB)) ? &ts->cts_rewrites[CNAT_LOCATION_FIB] : NULL;
    }
  else if (vnet_buffer2 (b)->session.state == CNAT_LOOKUP_IS_RETURN)
    {
      rw = (ts->ts_rw_bm & (1 << (CNAT_IS_RETURN + CNAT_LOCATION_FIB))) ?
	     &ts->cts_rewrites[CNAT_IS_RETURN + CNAT_LOCATION_FIB] :
	     NULL;
    }
  else if (vnet_buffer2 (b)->session.state == CNAT_LOOKUP_IS_NEW)
    rw = cnat_vip_feature_new_flow_inline (vm, b, af, ts, cc);

  cnat_translation (b, af, rw, &ts->lifetime, 0 /* iph_offset */);
  cnat_set_rw_next_node (b, rw, next0);

  if (PREDICT_FALSE (do_trace))
    cnat_add_trace (vm, node, b, ts, rw);
}

VLIB_NODE_FN (cnat_vip_ip4_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_lookup_inline (vm, node, frame, AF_IP4, 1 /* do_trace */, cnat_vip_node_fn,
			       0 /* is_feature */);
  return cnat_lookup_inline (vm, node, frame, AF_IP4, 0 /* do_trace */, cnat_vip_node_fn,
			     0 /* is_feature */);
}

VLIB_NODE_FN (cnat_vip_ip6_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_lookup_inline (vm, node, frame, AF_IP6, 1 /* do_trace */, cnat_vip_node_fn,
			       0 /* is_feature */);
  return cnat_lookup_inline (vm, node, frame, AF_IP6, 0 /* do_trace */, cnat_vip_node_fn,
			     0 /* is_feature */);
}

VLIB_REGISTER_NODE (cnat_vip_ip4_node) =
{
  .name = "ip4-cnat-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = CNAT_NODE_VIP_N_NEXT,
  .next_nodes =
  {
    [CNAT_NODE_VIP_NEXT_DROP] = "ip4-drop",
    [CNAT_NODE_VIP_NEXT_LOOKUP] = "ip4-lookup",
  },
};

VLIB_REGISTER_NODE (cnat_vip_ip6_node) =
{
  .name = "ip6-cnat-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = CNAT_NODE_VIP_N_NEXT,
  .next_nodes =
  {
    [CNAT_NODE_VIP_NEXT_DROP] = "ip6-drop",
    [CNAT_NODE_VIP_NEXT_LOOKUP] = "ip6-lookup",
  },
};
