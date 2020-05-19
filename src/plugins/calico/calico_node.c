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
#include <calico/calico_translation.h>
#include <calico/calico_session.h>
#include <calico/calico_client.h>
#include <calico/calico_snat.h>

#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>
#include <vnet/fib/ip4_fib.h>

throttle_t calico_throttle;

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

typedef enum calico_snat_next_
{
  CALICO_SNAT_NEXT_DROP,
  CALICO_SNAT_N_NEXT,
} calico_snat_next_t;

typedef struct calico_snat_trace_
{
  u32 found;
  calico_session_t session;
} calico_snat_trace_t;

static char *calico_error_strings[] = {
#define calico_error(n,s) s,
#include <calico/calico_error.def>
#undef calico_error
};

typedef enum
{
#define calico_error(n,s) CALICO_ERROR_##n,
#include <calico/calico_error.def>
#undef calico_error
  CALICO_N_ERROR,
} calico_error_t;

vlib_node_registration_t calico_snat_ip4_node;
vlib_node_registration_t calico_snat_ip6_node;

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

static u8 *
format_calico_snat_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  calico_snat_trace_t *t = va_arg (*args, calico_snat_trace_t *);

  s = format (s, "found:%d %U", t->found, format_calico_session, &t->session,
	      1);
  return s;
}

always_inline uword
calico_vip_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame, ip_address_family_t af)
{
  vlib_combined_counter_main_t *cm = &calico_translation_counters;
  u32 n_left, *from, thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  f64 now;
  u64 seed;

  thread_index = vm->thread_index;
  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);
  now = vlib_time_now (vm);
  seed = throttle_seed (&calico_throttle, thread_index, vlib_time_now (vm));

  while (n_left)
    {
      const calico_translation_t *ct;
      clib_bihash_kv_40_48_t bkey, bvalue;
      calico_session_t *session = NULL, *key;
      ip_protocol_t iproto;
      udp_header_t *udp0;
      ip4_header_t *ip4;
      ip6_header_t *ip6;
      calico_client_t *cc;
      index_t cti;
      int rv = 0;

      key = (calico_session_t *) & bkey;

      if (AF_IP4 == af)
	{
	  ip4 = vlib_buffer_get_current (b[0]);
	  iproto = ip4->protocol;
	  udp0 = (udp_header_t *) (ip4 + 1);
	  calico_mk_ip4_key (key, ip4, udp0);
	}
      else
	{
	  ip6 = vlib_buffer_get_current (b[0]);
	  iproto = ip6->protocol;
	  udp0 = (udp_header_t *) (ip6 + 1);

	  calico_mk_ip6_key (key, ip6, udp0);
	}

      cc = calico_client_get (vnet_buffer (b[0])->ip.adj_index[VLIB_TX]);

      if (iproto != IP_PROTOCOL_UDP && iproto != IP_PROTOCOL_TCP)
	{
	  /* Dont translate & follow the fib programming */
	  next[0] = cc->cc_parent.dpoi_next_node;
	  vnet_buffer (b[0])->ip.adj_index[VLIB_TX] =
	    cc->cc_parent.dpoi_index;
	  goto trace;
	}

      ct = calico_find_translation (cc->parent_cci,
				    clib_host_to_net_u16 (udp0->dst_port),
				    iproto);

      rv = clib_bihash_search_inline_2_40_48 (&calico_session_db,
					      &bkey, &bvalue);

      if (!rv)
	{
	  /* session table hit */
	  session = (calico_session_t *) & bvalue;
	  calico_timestamp_update (session->value.cs_ts_index, now);

	  if (NULL != ct)
	    {
	      /* Translate & follow the translation given LB */
	      next[0] = ct->ct_lb.dpoi_next_node;
	      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] =
		session->value.cs_lbi;
	    }
	  else if (session->value.flags & CALICO_SESSION_FLAG_HAS_SNAT)
	    {
	      /* The return needs DNAT, so we need an additionnal
	       * lookup after translation */
	      next[0] = CALICO_TRANSLATION_NEXT_LOOKUP;
	    }
	  else
	    {
	      /* Translate & follow the fib programming */
	      next[0] = cc->cc_parent.dpoi_next_node;
	      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] =
		cc->cc_parent.dpoi_index;
	    }
	}
      else
	{
	  if (NULL == ct)
	    {
	      /* Dont translate & Follow the fib programming */
	      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] =
		cc->cc_parent.dpoi_index;
	      next[0] = cc->cc_parent.dpoi_next_node;
	      goto trace;
	    }

	  /* New flow, create the sessions */
	  const load_balance_t *lb0;
	  clib_bihash_kv_40_48_t rkey;
	  calico_session_t *rsession;
	  calico_ep_trk_t *trk0;
	  u32 hash_c0, bucket0;
	  u32 rsession_flags = 0;
	  const dpo_id_t *dpo0;

	  lb0 = load_balance_get (ct->ct_lb.dpoi_index);

	  /* session table miss */
	  hash_c0 = (AF_IP4 == af ?
		     ip4_compute_flow_hash (ip4, lb0->lb_hash_config) :
		     ip6_compute_flow_hash (ip6, lb0->lb_hash_config));
	  bucket0 = hash_c0 & lb0->lb_n_buckets_minus_1;
	  dpo0 = load_balance_get_fwd_bucket (lb0, bucket0);

	  /* add the session */
	  session = (calico_session_t *) & bkey;

	  trk0 = &ct->ct_paths[bucket0];

	  ip46_address_copy (&session->value.cs_ip[VLIB_TX],
			     &trk0->ct_ep[VLIB_TX].ce_ip.ip);
	  if (ip_address_is_zero (&trk0->ct_ep[VLIB_RX].ce_ip))
	    {
	      if (AF_IP4 == af)
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
	  session->value.cs_ts_index = calico_timestamp_new (now);
	  calico_client_cnt_session (cc);

	  clib_bihash_add_del_40_48 (&calico_session_db, &bkey, 1);

	  /* is this the first time we've seen this source address */
	  cc = (AF_IP4 == af ?
		calico_client_ip4_find (&session->value.cs_ip[VLIB_RX].ip4) :
		calico_client_ip6_find (&session->value.cs_ip[VLIB_RX].ip6));

	  if (NULL == cc)
	    {
	      u64 r0 = 17;
	      if (AF_IP4 == af)
		r0 = (u64) session->value.cs_ip[VLIB_RX].ip4.as_u32;
	      else
		{
		  r0 = r0 * 31 + session->value.cs_ip[VLIB_RX].ip6.as_u64[0];
		  r0 = r0 * 31 + session->value.cs_ip[VLIB_RX].ip6.as_u64[1];
		}

	      /* Rate limit */
	      if (!throttle_check (&calico_throttle, thread_index, r0, seed))
		{
		  calico_learn_arg_t l;
		  l.addr.version = af;
		  ip46_address_copy (&l.addr.ip,
				     &session->value.cs_ip[VLIB_RX]);
		  /* fire client create to the main thread */
		  vl_api_rpc_call_main_thread (calico_client_learn,
					       (u8 *) & l, sizeof (l));
		}
	    }
	  else
	    {
	      calico_client_cnt_session (cc);
	    }

	  /* add the reverse flow */
	  rsession = (calico_session_t *) & rkey;
	  ip46_address_copy (&rsession->key.cs_ip[VLIB_RX],
			     &session->value.cs_ip[VLIB_TX]);
	  ip46_address_copy (&rsession->key.cs_ip[VLIB_TX],
			     &session->value.cs_ip[VLIB_RX]);
	  ip46_address_copy (&rsession->value.cs_ip[VLIB_RX],
			     &session->key.cs_ip[VLIB_TX]);
	  ip46_address_copy (&rsession->value.cs_ip[VLIB_TX],
			     &session->key.cs_ip[VLIB_RX]);
	  rsession->key.cs_proto = session->key.cs_proto;
	  rsession->key.__cs_pad[0] = 0;
	  rsession->key.__cs_pad[1] = 0;
	  rsession->key.cs_af = af;
	  rsession->value.cs_ts_index = session->value.cs_ts_index;
	  rsession->value.cs_lbi = INDEX_INVALID;
	  rsession->value.flags = rsession_flags;
	  rsession->key.cs_port[VLIB_RX] = session->value.cs_port[VLIB_TX];
	  rsession->key.cs_port[VLIB_TX] = session->value.cs_port[VLIB_RX];
	  rsession->value.cs_port[VLIB_TX] = session->key.cs_port[VLIB_RX];
	  rsession->value.cs_port[VLIB_RX] = session->key.cs_port[VLIB_TX];

	  clib_bihash_add_del_40_48 (&calico_session_db, &rkey, 1);


	  next[0] = ct->ct_lb.dpoi_next_node;
	  vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = session->value.cs_lbi;
	  cti = ct - calico_translation_pool;
	  vlib_increment_combined_counter (cm, thread_index, cti, 1,
					   vlib_buffer_length_in_chain (vm,
									b
									[0]));
	}


      if (AF_IP4 == af)
	calico_translation_ip4 (session, ip4, udp0);
      else
	calico_translation_ip6 (session, ip6, udp0);

    trace:
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  calico_translation_trace_t *t;

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));

	  t->found = !rv;
	  if (NULL != session)
	    {
	      clib_memcpy (&t->session, session, sizeof (t->session));
	    }
	}

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

always_inline uword
calico_snat_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame, ip_address_family_t af)
{
  u32 n_left, *from, thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  f64 now;
  u64 seed;

  thread_index = vm->thread_index;
  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);
  now = vlib_time_now (vm);
  seed = throttle_seed (&calico_throttle, thread_index, vlib_time_now (vm));

  while (n_left)
    {
      calico_session_t *session = NULL, *key;
      clib_bihash_kv_40_48_t bkey, bvalue;
      calico_main_t *cm = &calico_main;
      ip_protocol_t iproto;
      calico_client_t *cc;
      udp_header_t *udp0;
      ip4_header_t *ip4;
      ip6_header_t *ip6;
      int rv = 0;
      u16 sport;
      u32 arc_next0;

      key = (calico_session_t *) & bkey;

      if (AF_IP4 == af)
	{
	  ip4 = vlib_buffer_get_current (b[0]);
	  iproto = ip4->protocol;
	  udp0 = (udp_header_t *) (ip4 + 1);
	  calico_mk_ip4_key (key, ip4, udp0);
	}
      else
	{
	  ip6 = vlib_buffer_get_current (b[0]);
	  iproto = ip6->protocol;
	  udp0 = (udp_header_t *) (ip6 + 1);

	  calico_mk_ip6_key (key, ip6, udp0);
	}

      /* By default don't follow previous next0 */
      vnet_feature_next (&arc_next0, b[0]);
      next[0] = arc_next0;

      if (iproto != IP_PROTOCOL_UDP && iproto != IP_PROTOCOL_TCP)
	{
	  /* Dont translate */
	  goto trace;
	}
      rv = clib_bihash_search_inline_2_40_48 (&calico_session_db,
					      &bkey, &bvalue);

      if (!rv)
	{
	  /* session table hit */
	  session = (calico_session_t *) & bvalue;
	  calico_timestamp_update (session->value.cs_ts_index, now);
	}
      else
	{
	  ip46_address_t ip46_dst_address;
	  calico_session_t *rsession;
	  clib_bihash_kv_40_48_t rkey;
	  if (AF_IP4 == af)
	    ip46_address_set_ip4 (&ip46_dst_address, &ip4->dst_address);
	  else
	    ip46_address_set_ip6 (&ip46_dst_address, &ip6->dst_address);
	  rv = calico_search_snat_prefix (&ip46_dst_address, af);
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
	  session = (calico_session_t *) & bkey;
	  if (AF_IP4 == af)
	    {
	      ip46_address_set_ip4 (&session->value.cs_ip[VLIB_RX],
				    &cm->snat_ip4);
	      ip46_address_set_ip4 (&session->value.cs_ip[VLIB_TX],
				    &ip4->dst_address);
	    }
	  else
	    {
	      ip46_address_set_ip6 (&session->value.cs_ip[VLIB_RX],
				    &cm->snat_ip6);
	      ip46_address_set_ip6 (&session->value.cs_ip[VLIB_TX],
				    &ip6->dst_address);
	    }

	  /* Port allocation, first try to use the original port, allocate one
	     if it is already used */
	  sport = udp0->src_port;
	  rv = calico_allocate_port (cm, &sport);
	  if (rv)
	    {
	      vlib_node_increment_counter (vm, calico_snat_ip4_node.index,
					   CALICO_ERROR_EXHAUSTED_PORTS, 1);
	      next[0] = CALICO_SNAT_NEXT_DROP;
	      goto trace;
	    }

	  session->value.cs_port[VLIB_RX] = sport;
	  session->value.cs_port[VLIB_TX] = udp0->dst_port;
	  session->value.cs_lbi = INDEX_INVALID;
	  session->value.flags = CALICO_SESSION_FLAG_NO_CLIENT;
	  session->value.cs_ts_index = calico_timestamp_new (now);
	  clib_bihash_add_del_40_48 (&calico_session_db, &bkey, 1);

	  /* is this the first time we've seen this source address */
	  cc = (AF_IP4 == af ?
		calico_client_ip4_find (&session->value.cs_ip[VLIB_RX].ip4) :
		calico_client_ip6_find (&session->value.cs_ip[VLIB_RX].ip6));

	  if (NULL == cc)
	    {
	      u64 r0 = 17;
	      if (AF_IP4 == af)
		r0 = (u64) session->value.cs_ip[VLIB_RX].ip4.as_u32;
	      else
		{
		  r0 = r0 * 31 + session->value.cs_ip[VLIB_RX].ip6.as_u64[0];
		  r0 = r0 * 31 + session->value.cs_ip[VLIB_RX].ip6.as_u64[1];
		}

	      /* Rate limit */
	      if (!throttle_check (&calico_throttle, thread_index, r0, seed))
		{
		  calico_learn_arg_t l;
		  l.addr.version = af;
		  ip46_address_copy (&l.addr.ip,
				     &session->value.cs_ip[VLIB_RX]);
		  /* fire client create to the main thread */
		  vl_api_rpc_call_main_thread (calico_client_learn,
					       (u8 *) & l, sizeof (l));
		}
	    }
	  else
	    {
	      calico_client_cnt_session (cc);
	    }

	  /* add the reverse flow */
	  rsession = (calico_session_t *) & rkey;
	  ip46_address_copy (&rsession->key.cs_ip[VLIB_RX],
			     &session->value.cs_ip[VLIB_TX]);
	  ip46_address_copy (&rsession->key.cs_ip[VLIB_TX],
			     &session->value.cs_ip[VLIB_RX]);
	  ip46_address_copy (&rsession->value.cs_ip[VLIB_RX],
			     &session->key.cs_ip[VLIB_TX]);
	  ip46_address_copy (&rsession->value.cs_ip[VLIB_TX],
			     &session->key.cs_ip[VLIB_RX]);
	  rsession->key.cs_proto = session->key.cs_proto;
	  rsession->key.__cs_pad[0] = 0;
	  rsession->key.__cs_pad[1] = 0;
	  rsession->key.cs_af = af;
	  rsession->value.cs_ts_index = session->value.cs_ts_index;
	  rsession->value.cs_lbi = INDEX_INVALID;
	  rsession->value.flags = CALICO_SESSION_FLAG_HAS_SNAT;
	  rsession->key.cs_port[VLIB_RX] = session->value.cs_port[VLIB_TX];
	  rsession->key.cs_port[VLIB_TX] = session->value.cs_port[VLIB_RX];
	  rsession->value.cs_port[VLIB_TX] = session->key.cs_port[VLIB_RX];
	  rsession->value.cs_port[VLIB_RX] = session->key.cs_port[VLIB_TX];

	  clib_bihash_add_del_40_48 (&calico_session_db, &rkey, 1);

	}


      if (AF_IP4 == af)
	calico_translation_ip4 (session, ip4, udp0);
      else
	calico_translation_ip6 (session, ip6, udp0);

    trace:
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  calico_snat_trace_t *t;

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));

	  if (NULL != session)
	    {
	      clib_memcpy (&t->session, session, sizeof (t->session));
	    }
	}

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}


VLIB_NODE_FN (calico_snat_ip4_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return calico_snat_inline (vm, node, frame, AF_IP4);
}

VLIB_NODE_FN (calico_snat_ip6_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return calico_snat_inline (vm, node, frame, AF_IP6);
}

VLIB_NODE_FN (calico_vip_ip4_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return calico_vip_inline (vm, node, frame, AF_IP4);
}

VLIB_NODE_FN (calico_vip_ip6_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return calico_vip_inline (vm, node, frame, AF_IP6);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (calico_snat_ip4_node) =
{
  .name = "ip4-calico-snat",
  .vector_size = sizeof (u32),
  .format_trace = format_calico_snat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CALICO_N_ERROR,
  .error_strings = calico_error_strings,
  .n_next_nodes = CALICO_SNAT_N_NEXT,
  .next_nodes =
  {
    [CALICO_SNAT_NEXT_DROP] = "ip4-drop",
  }
};

VLIB_REGISTER_NODE (calico_snat_ip6_node) =
{
  .name = "ip6-calico-snat",
  .vector_size = sizeof (u32),
  .format_trace = format_calico_snat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CALICO_N_ERROR,
  .error_strings = calico_error_strings,
  .n_next_nodes = CALICO_SNAT_N_NEXT,
  .next_nodes =
  {
    [CALICO_SNAT_NEXT_DROP] = "ip6-drop",
  }
};

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
/* *INDENT-OFF* */

VNET_FEATURE_INIT (calico_snat_ip4_node, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ip4-calico-snat",
};

VNET_FEATURE_INIT (calico_snat_ip6_node, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ip6-calico-snat",
};

static clib_error_t *
calico_node_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = &vlib_thread_main;
  u32 n_vlib_mains = tm->n_vlib_mains;
  calico_main_t *cm = &calico_main;

  clib_spinlock_init (&cm->src_ports_lock);
  clib_bitmap_validate (cm->src_ports, UINT16_MAX);
  throttle_init (&calico_throttle, n_vlib_mains, 1e-3);

  return (NULL);
}

VLIB_INIT_FUNCTION (calico_node_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
