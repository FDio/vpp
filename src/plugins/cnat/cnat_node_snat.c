/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vlibmemory/api.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <cnat/cnat_node.h>
#include <cnat/cnat_snat_policy.h>
#include <cnat/cnat_inline.h>
#include <cnat/cnat_src_policy.h>

typedef enum cnat_snat_next_
{
  CNAT_NODE_SNAT_NEXT_DROP,
  CNAT_NODE_SNAT_N_NEXT,
} cnat_snat_next_t;

vlib_node_registration_t cnat_snat_ip4_node;
vlib_node_registration_t cnat_snat_ip6_node;

static_always_inline cnat_timestamp_rewrite_t *
cnat_snat_feature_new_flow_inline (vlib_main_t *vm, vlib_buffer_t *b, ip_address_family_t af,
				   cnat_timestamp_t *ts)
{
  cnat_timestamp_rewrite_t *rw = NULL;
  ip4_header_t *ip4 = NULL;
  ip_protocol_t iproto;
  ip6_header_t *ip6 = NULL;
  udp_header_t *udp0;
  int rv, do_snat;
  u16 sport;

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

  u32 fwd_fib_index = vnet_buffer (b)->ip.fib_index;
  cnat_snat_policy_entry_t *cpe = cnat_snat_policy_entry_get (af, fwd_fib_index);
  if (!cpe)
    return 0; /* no policy for this vrf */

  if (!cpe->snat_policy)
    return (NULL);

  do_snat = cpe->snat_policy (b, af, ip4, ip6, iproto, udp0);
  if (!do_snat)
    return (NULL);

  /* New flow, create the sessions if necessary. session will be a snat
      session, and rsession will be a dnat session
      Note: packet going through this path are going to the outside,
      so they will never hit the NAT again (they are not going towards
      a VIP) */
  rw = &ts->cts_rewrites[CNAT_LOCATION_FIB];
  ts->ts_rw_bm |= 1 << CNAT_LOCATION_FIB;

  rw->cts_lbi = (u32) ~0;
  rw->cts_dpoi_next_node = (u32) ~0;

  cnat_make_buffer_5tuple (b, af, &rw->tuple, 0 /* iph_offset */, 0 /* swap */);

  if (AF_IP4 == af)
    {
      if (!(cpe->snat_ip4.ce_flags & CNAT_EP_FLAG_RESOLVED))
	{
	  rw->cts_dpoi_next_node = CNAT_NODE_SNAT_NEXT_DROP;
	  return (rw);
	}
      cnat_node_select_ip4 (&rw->tuple.ip4[VLIB_RX], &ip_addr_v4 (&cpe->snat_ip4.ce_ip),
			    cpe->snat_ip4_mask);
    }
  else
    {
      if (!(cpe->snat_ip6.ce_flags & CNAT_EP_FLAG_RESOLVED))
	{
	  rw->cts_dpoi_next_node = CNAT_NODE_SNAT_NEXT_DROP;
	  return (rw);
	}
      cnat_node_select_ip6 (&rw->tuple.ip6[VLIB_RX], &ip_addr_v6 (&cpe->snat_ip6.ce_ip),
			    cpe->snat_ip6_mask);
    }

  sport = 0;
  rv = cnat_allocate_port (fwd_fib_index, &sport, iproto);
  if (rv)
    {
      vlib_node_increment_counter (vm, cnat_snat_ip4_node.index, CNAT_ERROR_EXHAUSTED_PORTS, 1);
      rw->cts_dpoi_next_node = CNAT_NODE_SNAT_NEXT_DROP;
      return (rw);
    }
  rw->tuple.port[VLIB_RX] = sport;

  rw->cts_lbi = INDEX_INVALID;
  rw->cts_flags |= CNAT_TS_RW_FLAG_HAS_ALLOCATED_PORT;
  rw->fib_index = fwd_fib_index;

  /*
   * Add the reverse flow, located in FIB
   */
  cnat_timestamp_rewrite_t *rrw;

  rrw = &ts->cts_rewrites[CNAT_IS_RETURN + CNAT_LOCATION_FIB];
  ts->ts_rw_bm |= 1 << (CNAT_LOCATION_FIB + CNAT_IS_RETURN);

  rrw->cts_lbi = (u32) ~0;
  rrw->cts_dpoi_next_node = CNAT_NODE_VIP_NEXT_LOOKUP;
  u32 ret_fib_index = AF_IP4 == af ? cpe->ret_fib_index4 : cpe->ret_fib_index6;
  rrw->fib_index = ret_fib_index;

  cnat_make_buffer_5tuple (b, af, &rrw->tuple, 0 /* iph_offset */, 1 /* swap */);

  clib_atomic_add_fetch (&ts->ts_session_refcnt, 1);

  cnat_rsession_create (rw, vnet_buffer2 (b)->session.generic_flow_id, ret_fib_index,
			0 /* add client */);
  return (rw);
}

/* CNat sub for source NAT as a feature arc on ip[46]-unicast
   This node's sub shouldn't apply to the same flows as
   cnat_vip_inline */
static void
cnat_snat_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 *next0,
		   ip_address_family_t af, f64 now, u8 do_trace)
{
  cnat_timestamp_rewrite_t *rw = NULL;
  cnat_timestamp_t *ts;

  ts = cnat_timestamp_update (vnet_buffer2 (b)->session.generic_flow_id, now);
  if (vnet_buffer2 (b)->session.state == CNAT_LOOKUP_IS_OK)
    {
      /* Translate & follow the translation given LB */
      rw = (ts->ts_rw_bm & (1 << CNAT_LOCATION_FIB)) ? &ts->cts_rewrites[CNAT_LOCATION_FIB] : NULL;
    }
  else if (vnet_buffer2 (b)->session.state == CNAT_LOOKUP_IS_NEW)
    rw = cnat_snat_feature_new_flow_inline (vm, b, af, ts);

  /* Return traffic is handled by cnat_node_vip */

  cnat_translation (b, af, rw, &ts->lifetime, 0 /* iph_offset */);
  cnat_set_rw_next_node (b, rw, next0);

  if (PREDICT_FALSE (do_trace))
    cnat_add_trace (vm, node, b, ts, rw);
}

VLIB_NODE_FN (cnat_snat_ip4_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_lookup_inline (vm, node, frame, AF_IP4, 1 /* do_trace */, cnat_snat_node_fn,
			       1 /* is_feature */);
  return cnat_lookup_inline (vm, node, frame, AF_IP4, 0 /* do_trace */, cnat_snat_node_fn,
			     1 /* is_feature */);
}

VLIB_NODE_FN (cnat_snat_ip6_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_lookup_inline (vm, node, frame, AF_IP6, 1 /* do_trace */, cnat_snat_node_fn,
			       1 /* is_feature */);
  return cnat_lookup_inline (vm, node, frame, AF_IP6, 0 /* do_trace */, cnat_snat_node_fn,
			     1 /* is_feature */);
}

VLIB_REGISTER_NODE (cnat_snat_ip4_node) = {
  .name = "cnat-snat-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CNAT_N_ERROR,
  .error_strings = cnat_error_strings,
  .n_next_nodes = CNAT_NODE_SNAT_N_NEXT,
  .next_nodes = {
      [CNAT_NODE_SNAT_NEXT_DROP] = "ip4-drop",
  },
};

VLIB_REGISTER_NODE (cnat_snat_ip6_node) = {
  .name = "cnat-snat-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_cnat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CNAT_N_ERROR,
  .error_strings = cnat_error_strings,
  .n_next_nodes = CNAT_NODE_SNAT_N_NEXT,
  .next_nodes = {
      [CNAT_NODE_SNAT_NEXT_DROP] = "ip6-drop",
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
