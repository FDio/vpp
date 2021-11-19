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

static_always_inline cnat_timestamp_rewrite_t *
cnat_input_feature_new_flow_inline (vlib_buffer_t *b, ip_address_family_t af,
				    cnat_timestamp_t *ts)
{
  const cnat_translation_t *ct = NULL;
  cnat_timestamp_rewrite_t *rw = NULL;
  cnat_client_t *cc;
  ip_protocol_t iproto;
  cnat_ep_trk_t *trk0;
  u32 dpoi_index = -1;
  ip4_header_t *ip4 = NULL;
  ip6_header_t *ip6 = NULL;
  udp_header_t *udp0;

  if (AF_IP4 == af)
    {
      ip4 = vlib_buffer_get_current (b);
      udp0 = (udp_header_t *) (ip4 + 1);
    }
  else
    {
      ip6 = vlib_buffer_get_current (b);
      udp0 = (udp_header_t *) (ip6 + 1);
    }

  cc = AF_IP4 == af ? cnat_client_ip4_find (&ip4->dst_address) :
		      cnat_client_ip6_find (&ip6->dst_address);
  if (!cc)
    return NULL; /* dst address is not a vip */

  iproto = AF_IP4 == af ? ip4->protocol : ip6->protocol;

  ct = cnat_find_translation (cc->parent_cci,
			      clib_host_to_net_u16 (udp0->dst_port), iproto);
  if (!ct)
    /* Don't translate, follow fib  */
    return NULL;

  /* add the rewrite object */
  rw = &ts->cts_rewrites[CNAT_LOCATION_INPUT];
  ts->ts_rw_bm |= 1 << CNAT_LOCATION_INPUT;

  rw->cts_lbi = (u32) ~0;
  rw->cts_dpoi_next_node = (u32) ~0;

  cnat_make_buffer_5tuple (b, af, &rw->tuple, 0, 0);

  /* session table miss */
  trk0 = cnat_load_balance (ct, af, ip4, ip6, &dpoi_index);
  if (PREDICT_FALSE (!trk0))
    {
      /* Load balance is empty or not resolved, drop  */
      rw->cts_dpoi_next_node = IP_LOOKUP_NEXT_DROP;
      return (rw);
    }

  /* never source nat in this node */
  ip46_address_copy (&rw->tuple.ip[VLIB_TX], &trk0->ct_ep[VLIB_TX].ce_ip.ip);
  rw->tuple.port[VLIB_TX] =
    trk0->ct_ep[VLIB_TX].ce_port ?
      clib_host_to_net_u16 (trk0->ct_ep[VLIB_TX].ce_port) :
      rw->tuple.port[VLIB_TX];

  if (trk0->ct_flags & CNAT_TRK_FLAG_NO_NAT)
    {
      const dpo_id_t *dpo0;
      const load_balance_t *lb1;

      lb1 = load_balance_get (trk0->ct_dpo.dpoi_index);
      /* Assume backend has exactly one item in LB :: FIXME */
      dpo0 = load_balance_get_bucket_i (lb1, 0);

      rw->cts_dpoi_next_node = dpo0->dpoi_next_node;
      rw->cts_lbi = dpo0->dpoi_index;
      rw->cts_flags |= CNAT_SESSION_FLAG_NO_NAT;
    }

  /* refcnt session in current client */
  cnat_client_cnt_session (cc);
  if (ct->flags & CNAT_TR_FLAG_NO_RETURN_SESSION)
    vnet_buffer (b)->session.flags |= CNAT_BUFFER_SESSION_FLAG_NO_RETURN;
  else
    {
      cnat_timestamp_rewrite_t *rrw;
      /*
       * Add the reverse flow, located in output
       */
      rrw = &ts->cts_rewrites[CNAT_IS_RETURN + CNAT_LOCATION_OUTPUT];
      ts->ts_rw_bm |= 1 << (CNAT_IS_RETURN + CNAT_LOCATION_OUTPUT);

      rrw->cts_lbi = (u32) ~0;
      rrw->cts_dpoi_next_node = (u32) ~0;

      cnat_make_buffer_5tuple (b, af, &rrw->tuple, 0, 1 /* swap */);
    }

  return rw;
}

always_inline cnat_timestamp_rewrite_t *
cnat_input_feature_get_rw (vlib_buffer_t *b, ip_address_family_t af,
			   cnat_timestamp_t *ts)
{
  if (vnet_buffer (b)->session.state == CNAT_LOOKUP_IS_OK)
    return (ts->ts_rw_bm & (1 << CNAT_LOCATION_INPUT)) ?
	     &ts->cts_rewrites[CNAT_LOCATION_INPUT] :
	     NULL;
  if (vnet_buffer (b)->session.state == CNAT_LOOKUP_IS_RETURN)
    return (ts->ts_rw_bm & (1 << (CNAT_IS_RETURN + CNAT_LOCATION_INPUT))) ?
	     &ts->cts_rewrites[CNAT_IS_RETURN + CNAT_LOCATION_INPUT] :
	     NULL;
  else if (vnet_buffer (b)->session.state == CNAT_LOOKUP_IS_NEW)
    return cnat_input_feature_new_flow_inline (b, af, ts);
  else
    return NULL;
}

always_inline uword
cnat_input_feature_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame, ip_address_family_t af,
		       u8 do_trace)
{
  u32 n_left, *from;
  f64 now = vlib_time_now (vm);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  cnat_timestamp_rewrite_t *rw[4];
  cnat_timestamp_t *ts[4];

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);

  /* kickstart out state */
  if (n_left >= 4)
    {
      vnet_feature_next_u16 (&next[0], b[0]);
      vnet_feature_next_u16 (&next[1], b[1]);
      vnet_feature_next_u16 (&next[2], b[2]);
      vnet_feature_next_u16 (&next[3], b[3]);

      ts[0] = cnat_timestamp_update (
	vnet_buffer (b[0])->session.generic_flow_id, now);
      ts[1] = cnat_timestamp_update (
	vnet_buffer (b[1])->session.generic_flow_id, now);
      ts[2] = cnat_timestamp_update (
	vnet_buffer (b[2])->session.generic_flow_id, now);
      ts[3] = cnat_timestamp_update (
	vnet_buffer (b[3])->session.generic_flow_id, now);
    }

  while (n_left >= 4)
    {
      if (n_left >= 12)
	{
	  vlib_prefetch_buffer_header (b[8], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[11], LOAD);
	}

      rw[0] = cnat_input_feature_get_rw (b[0], af, ts[0]);
      rw[1] = cnat_input_feature_get_rw (b[1], af, ts[1]);
      rw[2] = cnat_input_feature_get_rw (b[2], af, ts[2]);
      rw[3] = cnat_input_feature_get_rw (b[3], af, ts[3]);

      cnat_translation (b[0], af, rw[0], &ts[0]->lifetime, 0 /* iph_offset */);
      cnat_translation (b[1], af, rw[1], &ts[1]->lifetime, 0 /* iph_offset */);
      cnat_translation (b[2], af, rw[2], &ts[2]->lifetime, 0 /* iph_offset */);
      cnat_translation (b[3], af, rw[3], &ts[3]->lifetime, 0 /* iph_offset */);

      cnat_set_rw_next_node (b[0], rw[0], &next[0]);
      cnat_set_rw_next_node (b[1], rw[1], &next[1]);
      cnat_set_rw_next_node (b[2], rw[2], &next[2]);
      cnat_set_rw_next_node (b[3], rw[3], &next[3]);

      /* Prefetch next iteration. */

      if (n_left >= 8)
	{
	  vnet_feature_next_u16 (&next[4], b[4]);
	  vnet_feature_next_u16 (&next[5], b[5]);
	  vnet_feature_next_u16 (&next[6], b[6]);
	  vnet_feature_next_u16 (&next[7], b[7]);

	  ts[0] = cnat_timestamp_update (
	    vnet_buffer (b[4])->session.generic_flow_id, now);
	  ts[1] = cnat_timestamp_update (
	    vnet_buffer (b[5])->session.generic_flow_id, now);
	  ts[2] = cnat_timestamp_update (
	    vnet_buffer (b[6])->session.generic_flow_id, now);
	  ts[3] = cnat_timestamp_update (
	    vnet_buffer (b[7])->session.generic_flow_id, now);

	  vlib_prefetch_buffer_data (b[4], LOAD);
	  vlib_prefetch_buffer_data (b[5], LOAD);
	  vlib_prefetch_buffer_data (b[6], LOAD);
	  vlib_prefetch_buffer_data (b[7], LOAD);
	}

      if (PREDICT_FALSE (do_trace))
	{
	  cnat_add_trace (vm, node, b[0], rw[0], NULL /* ct: fixme */);
	  cnat_add_trace (vm, node, b[1], rw[1], NULL /* ct: fixme */);
	  cnat_add_trace (vm, node, b[2], rw[2], NULL /* ct: fixme */);
	  cnat_add_trace (vm, node, b[3], rw[3], NULL /* ct: fixme */);
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      vnet_feature_next_u16 (&next[0], b[0]);
      ts[0] = cnat_timestamp_update (
	vnet_buffer (b[0])->session.generic_flow_id, now);

      rw[0] = cnat_input_feature_get_rw (b[0], af, ts[0]);
      cnat_translation (b[0], af, rw[0], &ts[0]->lifetime, 0 /* iph_offset */);
      cnat_set_rw_next_node (b[0], rw[0], &next[0]);

      if (PREDICT_FALSE (do_trace))
	cnat_add_trace (vm, node, b[0], rw[0], NULL /* ct: fixme */);

      //      if (rw->cts_flags & CNAT_SESSION_FLAG_NO_NAT)
      // {
      //   /* If we don't translate, directly do the lookup & bypass arc */
      //   next[0] = rw->cts_dpoi_next_node;
      //   vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = rw->cts_lbi;
      //   goto trace;
      // }
      // FIXME : CNAT_SESSION_FLAG_NO_NAT

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (cnat_input_feature_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_input_feature_fn (vm, node, frame, AF_IP4, 1 /* do_trace */);
  return cnat_input_feature_fn (vm, node, frame, AF_IP4, 0 /* do_trace */);
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
  .runs_after = VNET_FEATURES ("cnat-lookup-ip4"),
};

VLIB_NODE_FN (cnat_input_feature_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_input_feature_fn (vm, node, frame, AF_IP6, 1 /* do_trace */);
  return cnat_input_feature_fn (vm, node, frame, AF_IP6, 0 /* do_trace */);
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
  .runs_after = VNET_FEATURES ("cnat-lookup-ip6"),
};

static_always_inline cnat_timestamp_rewrite_t *
cnat_output_feature_new_flow_inline (vlib_main_t *vm, vlib_buffer_t *b,
				     ip_address_family_t af,
				     cnat_timestamp_t *ts)
{
  cnat_timestamp_rewrite_t *rw = NULL;
  ip_protocol_t iproto;
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;

  ip4_header_t *ip4 = NULL;
  ip6_header_t *ip6 = NULL;
  udp_header_t *udp0;

  int rv;
  u16 sport;
  u8 do_snat = 0;
  u32 iph_offset = vnet_buffer (b)->ip.save_rewrite_length;

  if (AF_IP4 == af)
    {
      ip4 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b) + iph_offset);
      udp0 = (udp_header_t *) (ip4 + 1);
      iproto = ip4->protocol;
    }
  else
    {
      ip6 = (ip6_header_t *) ((u8 *) vlib_buffer_get_current (b) + iph_offset);
      udp0 = (udp_header_t *) (ip6 + 1);
      iproto = ip6->protocol;
    }

  /* new session */
  do_snat = cpm->snat_policy (b, af, ip4, ip6, iproto, udp0);
  if (do_snat != 1)
    return (NULL);

  rw = &ts->cts_rewrites[CNAT_LOCATION_OUTPUT];
  ts->ts_rw_bm |= 1 << (CNAT_LOCATION_OUTPUT);

  rw->cts_lbi = (u32) ~0;
  rw->cts_dpoi_next_node = (u32) ~0;

  cnat_make_buffer_5tuple (b, af, &rw->tuple, iph_offset, 0);

  if (AF_IP4 == af)
    {
      if (ip_address_is_zero (&cpm->snat_ip4.ce_ip))
	{
	  rw->cts_dpoi_next_node = CNAT_FEATURE_NEXT_DROP;
	  return (rw);
	}

      ip46_address_set_ip4 (&rw->tuple.ip[VLIB_RX],
			    &ip_addr_v4 (&cpm->snat_ip4.ce_ip));
    }
  else
    {
      if (ip_address_is_zero (&cpm->snat_ip6.ce_ip))
	{
	  rw->cts_dpoi_next_node = CNAT_FEATURE_NEXT_DROP;
	  return (rw);
	}

      ip46_address_set_ip6 (&rw->tuple.ip[VLIB_RX],
			    &ip_addr_v6 (&cpm->snat_ip6.ce_ip));
    }

  sport = 0;
  rv = cnat_allocate_port (&sport, iproto);
  if (rv)
    {
      vlib_node_registration_t *node = (AF_IP4 == af) ?
					 &cnat_output_feature_ip4_node :
					 &cnat_output_feature_ip6_node;
      vlib_node_increment_counter (vm, node->index, CNAT_ERROR_EXHAUSTED_PORTS,
				   1);
      rw->cts_dpoi_next_node = CNAT_FEATURE_NEXT_DROP;
      return (rw);
    }
  rw->tuple.port[VLIB_RX] = sport;

  rw->cts_lbi = INDEX_INVALID;
  rw->cts_flags |= CNAT_SESSION_FLAG_ALLOC_PORT;

  /*
   * Add the reverse flow, located in input
   */
  cnat_timestamp_rewrite_t *rrw;

  rrw = &ts->cts_rewrites[CNAT_IS_RETURN + CNAT_LOCATION_INPUT];
  ts->ts_rw_bm |= 1 << (CNAT_IS_RETURN + CNAT_LOCATION_INPUT);

  rrw->cts_lbi = (u32) ~0;
  rrw->cts_dpoi_next_node = (u32) ~0;

  cnat_make_buffer_5tuple (b, af, &rrw->tuple, iph_offset, 1 /* swap */);

  return rw;
}

always_inline cnat_timestamp_rewrite_t *
cnat_output_feature_get_rw (vlib_main_t *vm, vlib_buffer_t *b,
			    ip_address_family_t af, cnat_timestamp_t *ts)
{
  if (vnet_buffer (b)->session.state == CNAT_LOOKUP_IS_OK)
    return (ts->ts_rw_bm & (1 << CNAT_LOCATION_OUTPUT)) ?
	     &ts->cts_rewrites[CNAT_LOCATION_OUTPUT] :
	     NULL;
  if (vnet_buffer (b)->session.state == CNAT_LOOKUP_IS_RETURN)
    return (ts->ts_rw_bm & (1 << (CNAT_IS_RETURN + CNAT_LOCATION_OUTPUT))) ?
	     &ts->cts_rewrites[CNAT_IS_RETURN + CNAT_LOCATION_OUTPUT] :
	     NULL;
  else if (vnet_buffer (b)->session.state == CNAT_LOOKUP_IS_NEW)
    return cnat_output_feature_new_flow_inline (vm, b, af, ts);
  else
    return NULL;
}

/* output feature node, creates snat sessions when required and
 * translates back for existing sessions */
always_inline uword
cnat_output_feature_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame, ip_address_family_t af,
			u8 do_trace)
{
  u32 n_left, *from;
  f64 now = vlib_time_now (vm);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  cnat_timestamp_rewrite_t *rw[4];
  cnat_timestamp_t *ts[4];

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);

  /* kickstart out state */
  if (n_left >= 4)
    {
      vnet_feature_next_u16 (&next[0], b[0]);
      vnet_feature_next_u16 (&next[1], b[1]);
      vnet_feature_next_u16 (&next[2], b[2]);
      vnet_feature_next_u16 (&next[3], b[3]);

      ts[0] = cnat_timestamp_update (
	vnet_buffer (b[0])->session.generic_flow_id, now);
      ts[1] = cnat_timestamp_update (
	vnet_buffer (b[1])->session.generic_flow_id, now);
      ts[2] = cnat_timestamp_update (
	vnet_buffer (b[2])->session.generic_flow_id, now);
      ts[3] = cnat_timestamp_update (
	vnet_buffer (b[3])->session.generic_flow_id, now);
    }

  while (n_left >= 4)
    {
      rw[0] = cnat_output_feature_get_rw (vm, b[0], af, ts[0]);
      rw[1] = cnat_output_feature_get_rw (vm, b[1], af, ts[1]);
      rw[2] = cnat_output_feature_get_rw (vm, b[2], af, ts[2]);
      rw[3] = cnat_output_feature_get_rw (vm, b[3], af, ts[3]);

      cnat_translation (b[0], af, rw[0], &ts[0]->lifetime,
			vnet_buffer (b[0])->ip.save_rewrite_length);
      cnat_translation (b[1], af, rw[1], &ts[1]->lifetime,
			vnet_buffer (b[1])->ip.save_rewrite_length);
      cnat_translation (b[2], af, rw[2], &ts[2]->lifetime,
			vnet_buffer (b[2])->ip.save_rewrite_length);
      cnat_translation (b[3], af, rw[3], &ts[3]->lifetime,
			vnet_buffer (b[3])->ip.save_rewrite_length);

      /* Prefetch next iteration. */

      if (n_left >= 8)
	{
	  vnet_feature_next_u16 (&next[4], b[4]);
	  vnet_feature_next_u16 (&next[5], b[5]);
	  vnet_feature_next_u16 (&next[6], b[6]);
	  vnet_feature_next_u16 (&next[7], b[7]);

	  ts[0] = cnat_timestamp_update (
	    vnet_buffer (b[4])->session.generic_flow_id, now);
	  ts[1] = cnat_timestamp_update (
	    vnet_buffer (b[5])->session.generic_flow_id, now);
	  ts[2] = cnat_timestamp_update (
	    vnet_buffer (b[6])->session.generic_flow_id, now);
	  ts[3] = cnat_timestamp_update (
	    vnet_buffer (b[7])->session.generic_flow_id, now);

	  vlib_prefetch_buffer_data (b[4], LOAD);
	  vlib_prefetch_buffer_data (b[5], LOAD);
	  vlib_prefetch_buffer_data (b[6], LOAD);
	  vlib_prefetch_buffer_data (b[7], LOAD);
	}

      if (n_left >= 12)
	{
	  vlib_prefetch_buffer_header (b[8], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[11], LOAD);
	}

      if (PREDICT_FALSE (do_trace))
	{
	  cnat_add_trace (vm, node, b[0], rw[0], NULL /* ct */);
	  cnat_add_trace (vm, node, b[1], rw[1], NULL /* ct */);
	  cnat_add_trace (vm, node, b[2], rw[2], NULL /* ct */);
	  cnat_add_trace (vm, node, b[3], rw[3], NULL /* ct */);
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      /* By default follow arc default next */
      vnet_feature_next_u16 (&next[0], b[0]);

      ts[0] = cnat_timestamp_update (
	vnet_buffer (b[0])->session.generic_flow_id, now);
      rw[0] = cnat_output_feature_get_rw (vm, b[0], af, ts[0]);
      cnat_translation (b[0], af, rw[0], &ts[0]->lifetime,
			vnet_buffer (b[0])->ip.save_rewrite_length);

      if (PREDICT_FALSE (do_trace))
	cnat_add_trace (vm, node, b[0], rw[0], NULL /* ct */);

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}
VLIB_NODE_FN (cnat_output_feature_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return cnat_output_feature_fn (vm, node, frame, AF_IP4, 1 /* do_trace */);
  return cnat_output_feature_fn (vm, node, frame, AF_IP4, 0 /* do_trace */);
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
    return cnat_output_feature_fn (vm, node, frame, AF_IP6, 1 /* do_trace */);
  return cnat_output_feature_fn (vm, node, frame, AF_IP6, 0 /* do_trace */);
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
