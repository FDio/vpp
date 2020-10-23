/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief NAT44 endpoint-dependent inside to outside network translation
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/udp/udp_local.h>
#include <vppinfra/error.h>
#include <nat/nat.h>
#include <nat/lib/ipfix_logging.h>
#include <nat/nat_inlines.h>
#include <nat/nat44/inlines.h>
#include <nat/lib/nat_syslog.h>
#include <nat/nat_ha.h>
#include <nat/nat44/ed_inlines.h>
#include <nat/lib/nat_inlines.h>

/* number of attempts to get a port for ED overloading algorithm, if rolling
 * a dice this many times doesn't produce a free port, it's treated
 * as if there were no free ports available to conserve resources */
#define ED_PORT_ALLOC_ATTEMPTS (10)

static char *nat_in2out_ed_error_strings[] = {
#define _(sym,string) string,
  foreach_nat_in2out_ed_error
#undef _
};

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
  u32 is_slow_path;
  u32 translation_error;
} nat_in2out_ed_trace_t;

static u8 *
format_nat_in2out_ed_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat_in2out_ed_trace_t *t = va_arg (*args, nat_in2out_ed_trace_t *);
  char *tag;

  tag =
    t->is_slow_path ? "NAT44_IN2OUT_ED_SLOW_PATH" :
    "NAT44_IN2OUT_ED_FAST_PATH";

  s =
    format (s,
	    "%s: sw_if_index %d, next index %d, session %d, translation error %d",
	    tag, t->sw_if_index, t->next_index, t->session_index,
	    t->translation_error);

  return s;
}

static int
nat_ed_alloc_addr_and_port (snat_main_t * sm, u32 rx_fib_index,
			    u32 nat_proto, u32 thread_index,
			    ip4_address_t r_addr, u16 r_port, u8 proto,
			    u16 port_per_thread, u32 snat_thread_index,
			    snat_session_t * s,
			    ip4_address_t * outside_addr,
			    u16 * outside_port, nat_6t_flow_t ** flow)
{
  int i;
  snat_address_t *a, *ga = 0;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  const u16 port_thread_offset = (port_per_thread * snat_thread_index) + 1024;

  clib_bihash_kv_16_8_t o2i_kv;

  /* destination addr/port filled after hash insert with real values */
  nat_6t_flow_t *f =
    nat_6t_flow_alloc (sm, thread_index, s, r_addr, r_port, r_addr, r_port,
		       s->out2in.fib_index, proto);
  *flow = f;

  for (i = 0; i < vec_len (sm->addresses); i++)
    {
      a = sm->addresses + i;
      switch (nat_proto)
	{
#define _(N, j, n, unused)                                                   \
  case NAT_PROTOCOL_##N:                                                     \
    if (a->fib_index == rx_fib_index)                                        \
      {                                                                      \
        f->match.daddr = a->addr;                                            \
        /* first try port suggested by caller */                             \
        u16 port = clib_net_to_host_u16 (*outside_port);                     \
        u16 port_offset = port - port_thread_offset;                         \
        if (port <= port_thread_offset ||                                    \
            port > port_thread_offset + port_per_thread)                     \
          {                                                                  \
            /* need to pick a different port, suggested port doesn't fit in  \
             * this thread's port range */                                   \
            port_offset = snat_random_port (0, port_per_thread - 1);         \
            port = port_thread_offset + port_offset;                         \
          }                                                                  \
        u16 attempts = ED_PORT_ALLOC_ATTEMPTS;                               \
        do                                                                   \
          {                                                                  \
            f->match.dport = clib_host_to_net_u16 (port);                    \
            nat_6t_flow_to_ed_kv (tsm, f, &o2i_kv);                     \
            int rv = clib_bihash_add_del_16_8 (&sm->flow_hash, &o2i_kv, \
                                               2 /* is_add */);              \
            if (0 == rv)                                                     \
              {                                                              \
                ++a->busy_##n##_port_refcounts[port];                        \
                a->busy_##n##_ports_per_thread[thread_index]++;              \
                a->busy_##n##_ports++;                                       \
                *outside_addr = a->addr;                                     \
                *outside_port = clib_host_to_net_u16 (port);                 \
                return 0;                                                    \
              }                                                              \
            port_offset = snat_random_port (0, port_per_thread - 1);         \
            port = port_thread_offset + port_offset;                         \
            --attempts;                                                      \
          }                                                                  \
        while (attempts > 0);                                                \
      }                                                                      \
    else if (a->fib_index == ~0)                                             \
      {                                                                      \
        ga = a;                                                              \
      }                                                                      \
    break;

	  foreach_nat_protocol;
	default:
	  nat_elog_info ("unknown protocol");
	  return 1;
	}
    }

  if (ga)
    {
      /* fake fib_index to reuse macro */
      rx_fib_index = ~0;
      a = ga;
      switch (nat_proto)
	{
	  foreach_nat_protocol;
	default:
	  nat_elog_info ("unknown protocol");
	  return 1;
	}
    }

#undef _

  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

static_always_inline u32
nat_outside_fib_index_lookup (snat_main_t * sm, ip4_address_t addr)
{
  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  nat_outside_fib_t *outside_fib;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {.ip4.as_u32 = addr.as_u32,}
    ,
  };
  // TODO: multiple vrfs none can resolve addr
  /* *INDENT-OFF* */
  vec_foreach (outside_fib, sm->outside_fibs)
    {
      fei = fib_table_lookup (outside_fib->fib_index, &pfx);
      if (FIB_NODE_INDEX_INVALID != fei)
        {
          if (fib_entry_get_resolving_interface (fei) != ~0)
            {
              return outside_fib->fib_index;
            }
        }
    }
  /* *INDENT-ON* */
  return ~0;
}

#if 0
int
snat_ed_hairpinning (vlib_main_t * vm, vlib_node_runtime_t * node,
		     snat_main_t * sm, vlib_buffer_t * b0, ip4_header_t * ip0,
		     udp_header_t * udp0, tcp_header_t * tcp0, u32 proto0,
		     int do_trace)
{
  snat_session_t *s0 = NULL;
  clib_bihash_kv_8_8_t kv0, value0;
  ip_csum_t sum0;
  u32 new_dst_addr0 = 0, old_dst_addr0, ti = 0, si = ~0;
  u16 new_dst_port0 = ~0, old_dst_port0;
  int rv;
  ip4_address_t sm0_addr;
  u16 sm0_port;
  u32 sm0_fib_index;
  /* Check if destination is static mappings */
  if (!snat_static_mapping_match
      (sm, ip0->dst_address, udp0->dst_port, sm->outside_fib_index, proto0,
       &sm0_addr, &sm0_port, &sm0_fib_index, 1, 0, 0, 0, 0, 0, 0))
    {
      new_dst_addr0 = sm0_addr.as_u32;
      new_dst_port0 = sm0_port;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = sm0_fib_index;
    }
  /* or active session */
  else
    {
      if (sm->num_workers > 1)
	ti =
	  (clib_net_to_host_u16 (udp0->dst_port) -
	   1024) / sm->port_per_thread;
      else
	ti = sm->num_workers;

      clib_bihash_kv_16_8_t ed_kv, ed_value;
      init_ed_k (&ed_kv, ip0->dst_address, udp0->dst_port,
		 ip0->src_address, udp0->src_port, sm->outside_fib_index,
		 ip0->protocol);
      rv = clib_bihash_search_16_8 (&sm->ed_hash, &ed_kv, &ed_value);
      ASSERT (ti == ed_value_get_thread_index (&ed_value));
      si = ed_value_get_session_index (&ed_value);
      if (rv)
	{
	  rv = 0;
	  goto trace;
	}

      s0 = pool_elt_at_index (sm->per_thread_data[ti].sessions, si);
      new_dst_addr0 = s0->in2out.addr.as_u32;
      new_dst_port0 = s0->in2out.port;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;
    }

  /* Destination is behind the same NAT, use internal address and port */
  if (new_dst_addr0)
    {
      old_dst_addr0 = ip0->dst_address.as_u32;
      ip0->dst_address.as_u32 = new_dst_addr0;
      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0,
			     ip4_header_t, dst_address);
      ip0->checksum = ip_csum_fold (sum0);

      old_dst_port0 = tcp0->dst;
      if (PREDICT_TRUE (new_dst_port0 != old_dst_port0))
	{
	  if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	    {
	      tcp0->dst = new_dst_port0;
	      sum0 = tcp0->checksum;
	      sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0,
				     ip4_header_t, dst_address);
	      sum0 = ip_csum_update (sum0, old_dst_port0, new_dst_port0,
				     ip4_header_t /* cheat */ , length);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  else
	    {
	      udp0->dst_port = new_dst_port0;
	      udp0->checksum = 0;
	    }
	}
      else
	{
	  if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	    {
	      sum0 = tcp0->checksum;
	      sum0 = ip_csum_update (sum0, old_dst_addr0, new_dst_addr0,
				     ip4_header_t, dst_address);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	}
      rv = 1;
      goto trace;
    }
  rv = 0;
trace:
  if (do_trace && PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
				 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
    {
      nat_hairpin_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
      t->addr.as_u32 = new_dst_addr0;
      t->port = new_dst_port0;
      t->fib_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
      if (s0)
	{
	  t->session_index = si;
	}
      else
	{
	  t->session_index = ~0;
	}
    }
  return rv;
}
#endif

static u32
slow_path_ed (snat_main_t * sm,
	      vlib_buffer_t * b,
	      ip4_address_t l_addr,
	      ip4_address_t r_addr,
	      u16 l_port,
	      u16 r_port,
	      u8 proto,
	      u32 rx_fib_index,
	      snat_session_t ** sessionp,
	      nat_6t_flow_t ** i2ofp,
	      vlib_node_runtime_t * node, u32 next, u32 thread_index, f64 now)
{
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  clib_bihash_kv_16_8_t out2in_ed_kv;
  ip4_address_t outside_addr;
  u16 outside_port;
  u32 outside_fib_index;
  u8 identity_nat;

  u32 nat_proto = ip_proto_to_nat_proto (proto);
  snat_session_t *s = NULL;
  lb_nat_type_t lb = 0;

  if (PREDICT_TRUE (nat_proto == NAT_PROTOCOL_TCP))
    {
      if (PREDICT_FALSE
	  (!tcp_flags_is_init
	   (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags)))
	{
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_NON_SYN];
	  return NAT_NEXT_DROP;
	}
    }

  if (PREDICT_FALSE
      (nat44_ed_maximum_sessions_exceeded (sm, rx_fib_index, thread_index)))
    {
      if (!nat_lru_free_one (sm, thread_index, now))
	{
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_MAX_SESSIONS_EXCEEDED];
	  nat_ipfix_logging_max_sessions (thread_index,
					  sm->max_translations_per_thread);
	  nat_elog_notice ("maximum sessions exceeded");
	  return NAT_NEXT_DROP;
	}
    }

  outside_fib_index = sm->outside_fib_index;

  switch (vec_len (sm->outside_fibs))
    {
    case 0:
      outside_fib_index = sm->outside_fib_index;
      break;
    case 1:
      outside_fib_index = sm->outside_fibs[0].fib_index;
      break;
    default:
      outside_fib_index = nat_outside_fib_index_lookup (sm, r_addr);
      break;
    }

  ip4_address_t sm_addr;
  u16 sm_port;
  u32 sm_fib_index;
  nat_6t_flow_t *o2if;
  /* First try to match static mapping by local address and port */
  if (snat_static_mapping_match
      (sm, l_addr, l_port, rx_fib_index, nat_proto, &sm_addr, &sm_port,
       &sm_fib_index, 0, 0, 0, &lb, 0, &identity_nat, 0))
    {
      s = nat_ed_session_alloc (sm, thread_index, now, proto);
      ASSERT (s);
      s->in2out.addr = l_addr;
      s->in2out.port = l_port;
      s->nat_proto = nat_proto;
      s->in2out.fib_index = rx_fib_index;
      s->out2in.fib_index = outside_fib_index;

      /* Try to create dynamic translation */
      outside_port = l_port;	// suggest using local port to allocation function
      if (nat_ed_alloc_addr_and_port
	  (sm, rx_fib_index, nat_proto, thread_index, r_addr, r_port, proto,
	   sm->port_per_thread, tsm->snat_thread_index, s, &outside_addr,
	   &outside_port, &o2if))
	{
	  /* FIXME session memory leak ?? */
	  nat_elog_notice ("addresses exhausted");
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_OUT_OF_PORTS];
	  nat_ed_session_delete (sm, s, thread_index, 1);
	  return NAT_NEXT_DROP;
	}
      s->out2in.addr = outside_addr;
      s->out2in.port = outside_port;
    }
  else
    {
      if (PREDICT_FALSE (identity_nat))
	{
	  *sessionp = NULL;
	  *i2ofp = NULL;
	  return next;
	}
      s = nat_ed_session_alloc (sm, thread_index, now, proto);
      ASSERT (s);
      s->out2in.addr = outside_addr = sm_addr;
      s->out2in.port = outside_port = sm_port;
      s->in2out.addr = l_addr;
      s->in2out.port = l_port;
      s->nat_proto = nat_proto;
      s->in2out.fib_index = rx_fib_index;
      s->out2in.fib_index = outside_fib_index;
      s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
      o2if = nat_6t_flow_alloc (sm, thread_index, s, r_addr, r_port, sm_addr,
				sm_port, s->out2in.fib_index, proto);
      nat_6t_flow_to_ed_kv (tsm, o2if, &out2in_ed_kv);
      if (clib_bihash_add_del_16_8 (&sm->flow_hash, &out2in_ed_kv, 1))
	{
	  /* FIXME session memory leak ?? */
	  nat_elog_notice ("flow hash key add failed");
	}
    }

  nat_6t_flow_daddr_rewrite_set (o2if, l_addr.as_u32);
  nat_6t_flow_dport_rewrite_set (o2if, l_port);
  nat_6t_flow_txfib_rewrite_set (o2if, rx_fib_index);

  if (lb)
    s->flags |= SNAT_SESSION_FLAG_LOAD_BALANCING;
  s->flags |= SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT;
  s->ext_host_addr = r_addr;
  s->ext_host_port = r_port;

  clib_bihash_kv_16_8_t i2o_kv;
  nat_6t_flow_t *i2of =
    nat_6t_flow_alloc (sm, thread_index, s, l_addr, l_port, r_addr, r_port,
		       rx_fib_index, proto);
  nat_6t_flow_saddr_rewrite_set (i2of, outside_addr.as_u32);
  nat_6t_flow_sport_rewrite_set (i2of, outside_port);
  nat_6t_flow_txfib_rewrite_set (o2if, outside_fib_index);
  nat_6t_flow_to_ed_kv (tsm, i2of, &i2o_kv);
  if (clib_bihash_add_del_16_8 (&sm->flow_hash, &i2o_kv, 1))
    {
      // FIXME should free the session, it will not work anyway
      nat_elog_notice ("in2out-ed key add failed");
    }

  // hairpinning ?
  clib_bihash_kv_8_8_t kv, value;
  init_nat_k (&kv, outside_addr, 0, outside_fib_index, 0);
  if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
    {
      snat_static_mapping_t *hm =
	pool_elt_at_index (sm->static_mappings, value.value);

      nat_6t_flow_daddr_rewrite_set (i2of, hm->local_addr.as_u32);
      nat_6t_flow_txfib_rewrite_set (i2of, hm->fib_index);

      nat_6t_flow_saddr_rewrite_set (o2if, r_addr.as_u32);

      if (NAT_PROTOCOL_TCP == nat_proto || NAT_PROTOCOL_UDP == nat_proto)
	{
	  nat_6t_flow_dport_rewrite_set (i2of, hm->local_port);

	  nat_6t_flow_sport_rewrite_set (o2if, r_port);
	}
    }

  *sessionp = s;
  *i2ofp = i2of;

  /* log NAT event */
  nat_ipfix_logging_nat44_ses_create (thread_index,
				      s->in2out.addr.as_u32,
				      s->out2in.addr.as_u32,
				      s->nat_proto,
				      s->in2out.port,
				      s->out2in.port, s->in2out.fib_index);

  nat_syslog_nat44_sadd (s->user_index, s->in2out.fib_index,
			 &s->in2out.addr, s->in2out.port,
			 &s->ext_host_nat_addr, s->ext_host_nat_port,
			 &s->out2in.addr, s->out2in.port,
			 &s->ext_host_addr, s->ext_host_port, s->nat_proto,
			 0);

  nat_ha_sadd (&s->in2out.addr, s->in2out.port, &s->out2in.addr,
	       s->out2in.port, &s->ext_host_addr, s->ext_host_port,
	       &s->ext_host_nat_addr, s->ext_host_nat_port,
	       s->nat_proto, s->in2out.fib_index, s->flags, thread_index, 0);

  per_vrf_sessions_register_session (s, thread_index);

  return next;
}

static_always_inline int
nat44_ed_not_translate (snat_main_t * sm, vlib_node_runtime_t * node,
			u32 sw_if_index, ip4_header_t * ip, u32 proto,
			u32 rx_fib_index, u32 thread_index)
{
  udp_header_t *udp = ip4_next_header (ip);
  clib_bihash_kv_16_8_t kv, value;

  init_ed_k (&kv, ip->dst_address, udp->dst_port, ip->src_address,
	     udp->src_port, sm->outside_fib_index, ip->protocol);

  /* NAT packet aimed at external address if has active sessions */
  if (clib_bihash_search_16_8 (&sm->flow_hash, &kv, &value))
    {
      /* or is static mappings */
      ip4_address_t placeholder_addr;
      u16 placeholder_port;
      u32 placeholder_fib_index;
      if (!snat_static_mapping_match
	  (sm, ip->dst_address, udp->dst_port, sm->outside_fib_index, proto,
	   &placeholder_addr, &placeholder_port, &placeholder_fib_index, 1, 0,
	   0, 0, 0, 0, 0))
	return 0;
    }
  else
    return 0;

  if (sm->forwarding_enabled)
    return 1;

  return snat_not_translate_fast (sm, node, sw_if_index, ip, proto,
				  rx_fib_index);
}

static_always_inline int
nat_not_translate_output_feature_fwd (snat_main_t * sm, ip4_header_t * ip,
				      u32 thread_index, f64 now,
				      vlib_main_t * vm, vlib_buffer_t * b)
{
  clib_bihash_kv_16_8_t kv, value;
  snat_session_t *s = 0;
  nat_6t_flow_t *f;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  if (!sm->forwarding_enabled)
    return 0;

  if (ip->protocol == IP_PROTOCOL_ICMP)
    {
      if (get_icmp_i2o_ed_key (b, ip, 0, ~0, ~0, 0, 0, 0, &kv))
	return 0;
    }
  else if (ip->protocol == IP_PROTOCOL_UDP || ip->protocol == IP_PROTOCOL_TCP)
    {
      init_ed_k (&kv, ip->src_address, vnet_buffer (b)->ip.reass.l4_src_port,
		 ip->dst_address, vnet_buffer (b)->ip.reass.l4_dst_port, 0,
		 ip->protocol);
    }
  else
    {
      init_ed_k (&kv, ip->src_address, 0, ip->dst_address, 0, 0,
		 ip->protocol);
    }

  if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv, &value))
    {
      ASSERT (thread_index == ed_value_get_thread_index (&value));
      f = pool_elt_at_index (tsm->flows, ed_value_get_flow_index (&value));
      s = pool_elt_at_index (tsm->sessions, f->session_idx);

      if (is_fwd_bypass_session (s))
	{
	  if (ip->protocol == IP_PROTOCOL_TCP)
	    {
	      nat44_set_tcp_session_state_i2o (sm, now, s, b, thread_index);
	    }
	  /* Accounting */
	  nat44_session_update_counters (s, now,
					 vlib_buffer_length_in_chain (vm, b),
					 thread_index);
	  /* Per-user LRU list maintenance */
	  nat44_session_update_lru (sm, s, thread_index);
	  return 1;
	}
      else
	return 0;
    }

  return 0;
}

static_always_inline int
nat44_ed_not_translate_output_feature (snat_main_t * sm, ip4_header_t * ip,
				       u16 src_port, u16 dst_port,
				       u32 thread_index, u32 rx_sw_if_index,
				       u32 tx_sw_if_index)
{
  clib_bihash_kv_16_8_t kv, value;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  snat_interface_t *i;
  snat_session_t *s;
  nat_6t_flow_t *f;
  u32 rx_fib_index = ip4_fib_table_get_index_for_sw_if_index (rx_sw_if_index);
  u32 tx_fib_index = ip4_fib_table_get_index_for_sw_if_index (tx_sw_if_index);

  /* src NAT check */
  init_ed_k (&kv, ip->src_address, src_port, ip->dst_address, dst_port,
	     tx_fib_index, ip->protocol);
  if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv, &value))
    {
      ASSERT (thread_index == ed_value_get_thread_index (&value));
      f = pool_elt_at_index (tsm->flows, ed_value_get_flow_index (&value));
      s = pool_elt_at_index (tsm->sessions, f->session_idx);

      if (nat44_is_ses_closed (s))
	{
	  nat_free_session_data (sm, s, thread_index, 0);
	  nat_ed_session_delete (sm, s, thread_index, 1);
	}
      else
	s->flags |= SNAT_SESSION_FLAG_OUTPUT_FEATURE;
      return 1;
    }

  /* dst NAT check */
  init_ed_k (&kv, ip->dst_address, dst_port, ip->src_address, src_port,
	     rx_fib_index, ip->protocol);
  if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv, &value))
    {
      ASSERT (thread_index == ed_value_get_thread_index (&value));
      f = pool_elt_at_index (tsm->flows, ed_value_get_flow_index (&value));
      s = pool_elt_at_index (tsm->sessions, f->session_idx);

      if (is_fwd_bypass_session (s))
	return 0;

      /* hairpinning */
      /* *INDENT-OFF* */
      pool_foreach (i, sm->output_feature_interfaces,
      ({
        if ((nat_interface_is_inside (i)) && (rx_sw_if_index == i->sw_if_index))
           return 0;
      }));
      /* *INDENT-ON* */
      return 1;
    }

  return 0;
}

static inline u32
icmp_in2out_ed_slow_path (snat_main_t * sm, vlib_buffer_t * b,
			  ip4_header_t * ip, icmp46_header_t * icmp,
			  u32 sw_if_index, u32 rx_fib_index,
			  vlib_node_runtime_t * node, u32 next, f64 now,
			  u32 thread_index, nat_protocol_t nat_proto,
			  snat_session_t ** s_p)
{
  vlib_main_t *vm = vlib_get_main ();
  icmp_echo_header_t *echo, *inner_echo = 0;
  ip4_header_t *inner_ip;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp;
  u32 new_addr, old_addr;
  u16 old_id, new_id;
  u16 old_checksum, new_checksum;
  ip_csum_t sum;
  u16 checksum;

  echo = (icmp_echo_header_t *) (icmp + 1);

  clib_bihash_kv_16_8_t kv;
  int err;
  nat_protocol_t proto;
  snat_session_t *s = NULL;
  nat_6t_flow_t *i2of = NULL;
  u16 l_port = 0, r_port = 0;	// initialize to workaround gcc warning

  err = get_icmp_i2o_ed_key (b, ip, rx_fib_index, ~0, ~0, &proto, &l_port,
			     &r_port, &kv);
  if (err != 0)
    {
      b->error = node->errors[err];
      return NAT_NEXT_DROP;
    }

  if (vnet_buffer (b)->sw_if_index[VLIB_TX] != ~0)
    {
      if (PREDICT_FALSE
	  (nat44_ed_not_translate_output_feature
	   (sm, ip, l_port, r_port, thread_index, sw_if_index,
	    vnet_buffer (b)->sw_if_index[VLIB_TX])))
	{
	  return next;
	}
    }
  else
    {
      if (PREDICT_FALSE (nat44_ed_not_translate (sm, node, sw_if_index, ip,
						 NAT_PROTOCOL_ICMP,
						 rx_fib_index, thread_index)))
	{
	  return next;
	}
    }

  if (PREDICT_FALSE
      (icmp_type_is_error_message
       (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags)))
    {
      b->error = node->errors[NAT_IN2OUT_ED_ERROR_BAD_ICMP_TYPE];
      return NAT_NEXT_DROP;
    }

  next =
    slow_path_ed (sm, b, ip->src_address, ip->dst_address, l_port, r_port,
		  ip->protocol, rx_fib_index, &s, &i2of, node, next,
		  thread_index, vlib_time_now (vm));

  if (NAT_NEXT_DROP == next)
    goto out;

  if (PREDICT_TRUE (!ip4_is_fragment (ip)))
    {
      ip_csum_t sum = ip_incremental_checksum_buffer (vm, b,
						      (u8 *) icmp -
						      (u8 *)
						      vlib_buffer_get_current
						      (b),
						      ntohs (ip->length) -
						      ip4_header_bytes (ip),
						      0);
      checksum = ~ip_csum_fold (sum);
      if (PREDICT_FALSE (checksum != 0 && checksum != 0xffff))
	{
	  next = NAT_NEXT_DROP;
	  goto out;
	}
    }

  u16 new_src_port = i2of->rwr.sport;
  ip4_address_t new_src_addr = i2of->rwr.saddr;
  if (!vnet_buffer (b)->ip.reass.is_non_first_fragment)
    {
      if (icmp->checksum == 0)
	icmp->checksum = 0xffff;

      if (!icmp_type_is_error_message (icmp->type))
	{
	  new_id = new_src_port;
	  if (PREDICT_FALSE (new_id != echo->identifier))
	    {
	      old_id = echo->identifier;
	      new_id = new_src_port;
	      echo->identifier = new_id;

	      sum = icmp->checksum;
	      sum =
		ip_csum_update (sum, old_id, new_id, icmp_echo_header_t,
				identifier);
	      icmp->checksum = ip_csum_fold (sum);
	    }
	}
      else
	{
	  inner_ip = (ip4_header_t *) (echo + 1);
	  l4_header = ip4_next_header (inner_ip);

	  if (!ip4_header_checksum_is_valid (inner_ip))
	    {
	      next = NAT_NEXT_DROP;
	      goto out;
	    }

	  /* update inner destination IP address */
	  old_addr = inner_ip->dst_address.as_u32;
	  inner_ip->dst_address.as_u32 = new_src_addr.as_u32;
	  new_addr = inner_ip->dst_address.as_u32;
	  sum = icmp->checksum;
	  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t,
				dst_address /* changed member */ );
	  icmp->checksum = ip_csum_fold (sum);

	  /* update inner IP header checksum */
	  old_checksum = inner_ip->checksum;
	  sum = inner_ip->checksum;
	  sum =
	    ip_csum_update (sum, old_addr, new_addr, ip4_header_t,
			    dst_address /* changed member */ );
	  inner_ip->checksum = ip_csum_fold (sum);
	  new_checksum = inner_ip->checksum;
	  sum = icmp->checksum;
	  sum =
	    ip_csum_update (sum, old_checksum, new_checksum, ip4_header_t,
			    checksum);
	  icmp->checksum = ip_csum_fold (sum);

	  switch (nat_proto)
	    {
	    case NAT_PROTOCOL_ICMP:
	      inner_icmp = (icmp46_header_t *) l4_header;
	      inner_echo = (icmp_echo_header_t *) (inner_icmp + 1);

	      old_id = inner_echo->identifier;
	      new_id = new_src_port;
	      inner_echo->identifier = new_id;

	      sum = icmp->checksum;
	      sum =
		ip_csum_update (sum, old_id, new_id, icmp_echo_header_t,
				identifier);
	      icmp->checksum = ip_csum_fold (sum);
	      break;
	    case NAT_PROTOCOL_UDP:
	    case NAT_PROTOCOL_TCP:
	      old_id = ((tcp_udp_header_t *) l4_header)->dst_port;
	      new_id = new_src_port;
	      ((tcp_udp_header_t *) l4_header)->dst_port = new_id;

	      sum = icmp->checksum;
	      sum = ip_csum_update (sum, old_id, new_id, tcp_udp_header_t,
				    dst_port);
	      icmp->checksum = ip_csum_fold (sum);
	      break;
	    default:
	      ASSERT (0);
	    }
	}
    }

out:
  if (PREDICT_TRUE (next != NAT_NEXT_DROP && s))
    {
      /* Accounting */
      nat44_session_update_counters (s, now,
				     vlib_buffer_length_in_chain
				     (vm, b), thread_index);
      /* Per-user LRU list maintenance */
      nat44_session_update_lru (sm, s, thread_index);
    }
  else
    {
      nat_ed_session_delete (sm, s, thread_index, 1);
      s = NULL;
    }
  *s_p = s;
  return next;
}

static snat_session_t *
nat44_ed_in2out_slowpath_unknown_proto (snat_main_t * sm,
					vlib_buffer_t * b,
					ip4_header_t * ip,
					u32 rx_fib_index,
					u32 thread_index,
					f64 now,
					vlib_main_t * vm,
					vlib_node_runtime_t * node)
{
  clib_bihash_kv_8_8_t kv, value;
  clib_bihash_kv_16_8_t s_kv, s_value;
  snat_static_mapping_t *m = NULL;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  snat_session_t *s = NULL;
  nat_6t_flow_t *i2of, *o2if = NULL;
  u32 outside_fib_index = sm->outside_fib_index;
  int i;
  ip4_address_t new_src_addr = { 0 };

  if (PREDICT_FALSE
      (nat44_ed_maximum_sessions_exceeded (sm, rx_fib_index, thread_index)))
    {
      b->error = node->errors[NAT_IN2OUT_ED_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_ipfix_logging_max_sessions (thread_index,
				      sm->max_translations_per_thread);
      nat_elog_notice ("maximum sessions exceeded");
      return 0;
    }

  switch (vec_len (sm->outside_fibs))
    {
    case 0:
      outside_fib_index = sm->outside_fib_index;
      break;
    case 1:
      outside_fib_index = sm->outside_fibs[0].fib_index;
      break;
    default:
      outside_fib_index = nat_outside_fib_index_lookup (sm, ip->dst_address);
      break;
    }

  init_nat_k (&kv, ip->src_address, 0, rx_fib_index, 0);

  /* Try to find static mapping first */
  if (!clib_bihash_search_8_8 (&sm->static_mapping_by_local, &kv, &value))
    {
      m = pool_elt_at_index (sm->static_mappings, value.value);
      new_src_addr = m->external_addr;
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach (s, tsm->sessions, {
        if (s->ext_host_addr.as_u32 == ip->dst_address.as_u32)
          {
            init_ed_k (&s_kv, s->out2in.addr, 0, ip->dst_address, 0,
                       outside_fib_index, ip->protocol);
            if (clib_bihash_search_16_8 (&sm->flow_hash, &s_kv, &s_value))
              {
                new_src_addr = s->out2in.addr;
              }
            break;
          }
      });
      /* *INDENT-ON* */

      if (!new_src_addr.as_u32)
	{
	  for (i = 0; i < vec_len (sm->addresses); i++)
	    {
	      init_ed_k (&s_kv, sm->addresses[i].addr, 0, ip->dst_address, 0,
			 outside_fib_index, ip->protocol);
	      if (clib_bihash_search_16_8 (&sm->flow_hash, &s_kv, &s_value))
		{
		  new_src_addr = sm->addresses[i].addr;
		}
	    }
	}
    }

  if (!new_src_addr.as_u32)
    {
      // could not allocate address for translation ...
      return 0;
    }

  s = nat_ed_session_alloc (sm, thread_index, now, ip->protocol);
  if (!s)
    {
      b->error = node->errors[NAT_IN2OUT_ED_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_elog_warn ("create NAT session failed");
      return 0;
    }

  i2of = nat_6t_flow_alloc (sm, thread_index, s, s->in2out.addr, 0,
			    ip->dst_address, 0, rx_fib_index, ip->protocol);
  nat_6t_flow_saddr_rewrite_set (i2of, new_src_addr.as_u32);
  nat_6t_flow_txfib_rewrite_set (i2of, outside_fib_index);

  o2if = nat_6t_flow_alloc (sm, thread_index, s, s->out2in.addr, 0,
			    ip->dst_address, 0, outside_fib_index,
			    ip->protocol);
  nat_6t_flow_daddr_rewrite_set (o2if, ip->src_address.as_u32);
  nat_6t_flow_txfib_rewrite_set (o2if, rx_fib_index);

  // hairpinning ?
  init_nat_k (&kv, new_src_addr, 0, outside_fib_index, 0);
  if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
    {
      snat_static_mapping_t *hm =
	pool_elt_at_index (sm->static_mappings, value.value);

      nat_6t_flow_daddr_rewrite_set (i2of, hm->local_addr.as_u32);
      nat_6t_flow_txfib_rewrite_set (i2of, hm->fib_index);

      nat_6t_flow_saddr_rewrite_set (o2if, ip->dst_address.as_u32);
    }

  s->ext_host_addr.as_u32 = ip->dst_address.as_u32;
  s->flags |= SNAT_SESSION_FLAG_UNKNOWN_PROTO;
  s->flags |= SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT;
  s->out2in.addr.as_u32 = new_src_addr.as_u32;
  s->out2in.fib_index = outside_fib_index;
  s->in2out.addr.as_u32 = ip->src_address.as_u32;
  s->in2out.fib_index = rx_fib_index;
  s->in2out.port = s->out2in.port = ip->protocol;
  if (m)
    s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;

  nat_6t_flow_to_ed_kv (tsm, i2of, &s_kv);
  if (clib_bihash_add_del_16_8 (&sm->flow_hash, &s_kv, 1))
    {
      /* FIXME */
      nat_elog_notice ("in2out flow hash add failed");
    }

  nat_6t_flow_to_ed_kv (tsm, o2if, &s_kv);
  if (clib_bihash_add_del_16_8 (&sm->flow_hash, &s_kv, 1))
    {
      /* FIXME */
      nat_elog_notice ("out2in flow hash add failed");
    }

  per_vrf_sessions_register_session (s, thread_index);

  if (!nat_6t_flow_translate_buf
      (sm, b, ip, i2of, ip_proto_to_nat_proto (ip->protocol)))
    {
      /* FIXME */
      abort ();
    }

  /* Accounting */
  nat44_session_update_counters (s, now, vlib_buffer_length_in_chain (vm, b),
				 thread_index);
  /* Per-user LRU list maintenance */
  nat44_session_update_lru (sm, s, thread_index);

  return s;
}

static inline uword
nat44_ed_in2out_fast_path_node_fn_inline (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame,
					  int is_output_feature)
{
  u32 n_left_from, *from;
  snat_main_t *sm = &snat_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  u32 def_slow = is_output_feature ? NAT_NEXT_IN2OUT_ED_OUTPUT_SLOW_PATH
    : NAT_NEXT_IN2OUT_ED_SLOW_PATH;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  vlib_get_buffers (vm, from, b, n_left_from);

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0;
      u32 sw_if_index0, rx_fib_index0, proto0, iph_offset0 = 0;
      ip4_header_t *ip0;
      udp_header_t *udp0;
      tcp_header_t *tcp0;
      snat_session_t *s0 = 0;
      nat_6t_flow_t *f0 = 0;
      clib_bihash_kv_16_8_t kv0, value0;
      int translation_error = 0;

      b0 = *b;
      b++;

      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left_from >= 2))
	{
	  vlib_buffer_t *p2;

	  p2 = *b;

	  vlib_prefetch_buffer_header (p2, LOAD);

	  CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, LOAD);
	}

      if (is_output_feature)
	{
	  iph_offset0 = vnet_buffer (b0)->ip.reass.save_rewrite_length;
	}

      next[0] = vnet_buffer2 (b0)->nat.arc_next;

      ip0 =
	(ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) + iph_offset0);

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      rx_fib_index0 =
	fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index0);

      if (PREDICT_FALSE (ip0->ttl == 1))
	{
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next[0] = NAT_NEXT_ICMP_ERROR;
	  goto trace0;
	}

      udp0 = ip4_next_header (ip0);
      tcp0 = (tcp_header_t *) udp0;
      proto0 = ip_proto_to_nat_proto (ip0->protocol);

      if (is_output_feature)
	{
	  if (PREDICT_FALSE
	      (nat_not_translate_output_feature_fwd
	       (sm, ip0, thread_index, now, vm, b0)))
	    goto trace0;
	}

      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	{
	  if (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
	      ICMP4_echo_request &&
	      vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
	      ICMP4_echo_reply &&
	      !icmp_type_is_error_message (vnet_buffer (b0)->ip.
					   reass.icmp_type_or_tcp_flags))
	    {
	      b0->error = node->errors[NAT_IN2OUT_ED_ERROR_BAD_ICMP_TYPE];
	      next[0] = NAT_NEXT_DROP;
	      goto trace0;
	    }
	  int err = get_icmp_i2o_ed_key (b0, ip0, rx_fib_index0, ~0, ~0, 0, 0,
					 0, &kv0);
	  if (err != 0)
	    {
	      b0->error = node->errors[err];
	      next[0] = NAT_NEXT_DROP;
	      goto trace0;
	    }
	}
      else
	{
	  init_ed_k (&kv0, ip0->src_address,
		     vnet_buffer (b0)->ip.reass.l4_src_port, ip0->dst_address,
		     vnet_buffer (b0)->ip.reass.l4_dst_port, rx_fib_index0,
		     ip0->protocol);
	}

      // lookup flow
      if (clib_bihash_search_16_8 (&sm->flow_hash, &kv0, &value0))
	{
	  // flow does not exist go slow path
	  next[0] = def_slow;
	  goto trace0;
	}
      ASSERT (thread_index == ed_value_get_thread_index (&value0));
      f0 = pool_elt_at_index (tsm->flows, ed_value_get_flow_index (&value0));
      s0 = pool_elt_at_index (tsm->sessions, f0->session_idx);

      if (PREDICT_FALSE (per_vrf_sessions_is_expired (s0, thread_index)))
	{
	  // session is closed, go slow path
	  nat_free_session_data (sm, s0, thread_index, 0);
	  nat_ed_session_delete (sm, s0, thread_index, 1);
	  next[0] = NAT_NEXT_OUT2IN_ED_SLOW_PATH;
	  goto trace0;
	}

      if (s0->tcp_closed_timestamp)
	{
	  if (now >= s0->tcp_closed_timestamp)
	    {
	      // session is closed, go slow path, freed in slow path
	      next[0] = def_slow;
	    }
	  else
	    {
	      // session in transitory timeout, drop
	      b0->error = node->errors[NAT_IN2OUT_ED_ERROR_TCP_CLOSED];
	      next[0] = NAT_NEXT_DROP;
	    }
	  goto trace0;
	}

      // drop if session expired
      u64 sess_timeout_time;
      sess_timeout_time =
	s0->last_heard + (f64) nat44_session_get_timeout (sm, s0);
      if (now >= sess_timeout_time)
	{
	  nat_free_session_data (sm, s0, thread_index, 0);
	  nat_ed_session_delete (sm, s0, thread_index, 1);
	  // session is closed, go slow path
	  next[0] = def_slow;
	  goto trace0;
	}

      b0->flags |= VNET_BUFFER_F_IS_NATED;

      if (!nat_6t_flow_translate_buf (sm, b0, ip0, f0, proto0))
	{
	  translation_error = 1;
	  nat_free_session_data (sm, s0, thread_index, 0);
	  nat_ed_session_delete (sm, s0, thread_index, 1);
	  goto trace0;
	}

      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	{
	  vlib_increment_simple_counter (&sm->counters.fastpath.in2out_ed.tcp,
					 thread_index, sw_if_index0, 1);
	  nat44_set_tcp_session_state_i2o (sm, now, s0, b0, thread_index);
	}
      else if (proto0 == NAT_PROTOCOL_UDP)
	{
	  vlib_increment_simple_counter (&sm->counters.fastpath.in2out_ed.udp,
					 thread_index, sw_if_index0, 1);
	}
      else
	{
	  vlib_increment_simple_counter (&sm->counters.fastpath.
					 in2out_ed.other, thread_index,
					 sw_if_index0, 1);
	}

      /* Accounting */
      nat44_session_update_counters (s0, now,
				     vlib_buffer_length_in_chain (vm, b0),
				     thread_index);
      /* Per-user LRU list maintenance */
      nat44_session_update_lru (sm, s0, thread_index);

    trace0:
      if (PREDICT_FALSE
	  ((node->flags & VLIB_NODE_FLAG_TRACE)
	   && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat_in2out_ed_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->next_index = next[0];
	  t->is_slow_path = 0;
	  t->translation_error = translation_error;

	  if (s0)
	    t->session_index = s0 - tsm->sessions;
	  else
	    t->session_index = ~0;
	}

      if (next[0] == NAT_NEXT_DROP)
	{
	  vlib_increment_simple_counter (&sm->counters.fastpath.
					 in2out_ed.drops, thread_index,
					 sw_if_index0, 1);
	}

      n_left_from--;
      next++;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
			       frame->n_vectors);
  return frame->n_vectors;
}

static inline uword
nat44_ed_in2out_slow_path_node_fn_inline (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame,
					  int is_output_feature)
{
  u32 n_left_from, *from;
  snat_main_t *sm = &snat_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  vlib_get_buffers (vm, from, b, n_left_from);

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0;
      u32 sw_if_index0, rx_fib_index0, proto0, iph_offset0 = 0;
      ip4_header_t *ip0;
      udp_header_t *udp0;
      tcp_header_t *tcp0;
      icmp46_header_t *icmp0;
      snat_session_t *s0 = 0;
      nat_6t_flow_t *f0 = NULL;
      clib_bihash_kv_16_8_t kv0, value0;
      int translation_error = 0;

      b0 = *b;

      if (is_output_feature)
	iph_offset0 = vnet_buffer (b0)->ip.reass.save_rewrite_length;

      next[0] = vnet_buffer2 (b0)->nat.arc_next;

      ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
			      iph_offset0);

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      rx_fib_index0 =
	fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index0);

      if (PREDICT_FALSE (ip0->ttl == 1))
	{
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next[0] = NAT_NEXT_ICMP_ERROR;
	  goto trace0;
	}

      udp0 = ip4_next_header (ip0);
      tcp0 = (tcp_header_t *) udp0;
      icmp0 = (icmp46_header_t *) udp0;
      proto0 = ip_proto_to_nat_proto (ip0->protocol);

      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_OTHER))
	{
	  s0 = nat44_ed_in2out_slowpath_unknown_proto (sm, b0, ip0,
						       rx_fib_index0,
						       thread_index, now, vm,
						       node);
	  if (!s0)
	    next[0] = NAT_NEXT_DROP;

	  vlib_increment_simple_counter (&sm->counters.slowpath.
					 in2out_ed.other, thread_index,
					 sw_if_index0, 1);
	  goto trace0;
	}

      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	{
	  next[0] =
	    icmp_in2out_ed_slow_path (sm, b0, ip0, icmp0, sw_if_index0,
				      rx_fib_index0, node, next[0], now,
				      thread_index, proto0, &s0);
	  vlib_increment_simple_counter (&sm->counters.slowpath.
					 in2out_ed.icmp, thread_index,
					 sw_if_index0, 1);
	  goto trace0;
	}

      init_ed_k (&kv0, ip0->src_address,
		 vnet_buffer (b0)->ip.reass.l4_src_port, ip0->dst_address,
		 vnet_buffer (b0)->ip.reass.l4_dst_port, rx_fib_index0,
		 ip0->protocol);
      if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv0, &value0))
	{
	  ASSERT (thread_index == ed_value_get_thread_index (&value0));
	  f0 =
	    pool_elt_at_index (tsm->flows, ed_value_get_flow_index (&value0));
	  s0 = pool_elt_at_index (tsm->sessions, f0->session_idx);

	  if (s0->tcp_closed_timestamp && now >= s0->tcp_closed_timestamp)
	    {
	      nat_free_session_data (sm, s0, thread_index, 0);
	      nat_ed_session_delete (sm, s0, thread_index, 1);
	      s0 = NULL;
	    }
	}

      if (!s0)
	{
	  if (is_output_feature)
	    {
	      if (PREDICT_FALSE
		  (nat44_ed_not_translate_output_feature
		   (sm, ip0, vnet_buffer (b0)->ip.reass.l4_src_port,
		    vnet_buffer (b0)->ip.reass.l4_dst_port, thread_index,
		    sw_if_index0, vnet_buffer (b0)->sw_if_index[VLIB_TX])))
		goto trace0;

	      /*
	       * Send DHCP packets to the ipv4 stack, or we won't
	       * be able to use dhcp client on the outside interface
	       */
	      if (PREDICT_FALSE
		  (proto0 == NAT_PROTOCOL_UDP
		   && (vnet_buffer (b0)->ip.reass.l4_dst_port ==
		       clib_host_to_net_u16 (UDP_DST_PORT_dhcp_to_server))
		   && ip0->dst_address.as_u32 == 0xffffffff))
		goto trace0;
	    }
	  else
	    {
	      if (PREDICT_FALSE
		  (nat44_ed_not_translate
		   (sm, node, sw_if_index0, ip0, proto0, rx_fib_index0,
		    thread_index)))
		goto trace0;
	    }

	  next[0] =
	    slow_path_ed (sm, b0, ip0->src_address, ip0->dst_address,
			  vnet_buffer (b0)->ip.reass.l4_src_port,
			  vnet_buffer (b0)->ip.reass.l4_dst_port,
			  ip0->protocol, rx_fib_index0, &s0, &f0, node,
			  next[0], thread_index, now);

	  if (PREDICT_FALSE (next[0] == NAT_NEXT_DROP))
	    goto trace0;

	  if (PREDICT_FALSE (!s0))
	    goto trace0;

	}

      b0->flags |= VNET_BUFFER_F_IS_NATED;

      if (!nat_6t_flow_translate_buf (sm, b0, ip0, f0, proto0))
	{
	  translation_error = 1;
	  nat_free_session_data (sm, s0, thread_index, 0);
	  nat_ed_session_delete (sm, s0, thread_index, 1);
	  s0 = NULL;
	  goto trace0;
	}

      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	{
	  vlib_increment_simple_counter (&sm->counters.slowpath.in2out_ed.tcp,
					 thread_index, sw_if_index0, 1);
	  nat44_set_tcp_session_state_i2o (sm, now, s0, b0, thread_index);
	}
      else
	{
	  vlib_increment_simple_counter (&sm->counters.slowpath.in2out_ed.udp,
					 thread_index, sw_if_index0, 1);
	}

      /* Accounting */
      nat44_session_update_counters (s0, now,
				     vlib_buffer_length_in_chain
				     (vm, b0), thread_index);
      /* Per-user LRU list maintenance */
      nat44_session_update_lru (sm, s0, thread_index);

    trace0:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat_in2out_ed_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->next_index = next[0];
	  t->is_slow_path = 1;
	  t->translation_error = translation_error;

	  if (s0)
	    t->session_index = s0 - tsm->sessions;
	  else
	    t->session_index = ~0;
	}

      if (next[0] == NAT_NEXT_DROP)
	{
	  vlib_increment_simple_counter (&sm->counters.slowpath.
					 in2out_ed.drops, thread_index,
					 sw_if_index0, 1);
	}

      n_left_from--;
      next++;
      b++;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
			       frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (nat44_ed_in2out_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return nat44_ed_in2out_fast_path_node_fn_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_in2out_node) = {
  .name = "nat44-ed-in2out",
  .vector_size = sizeof (u32),
  .sibling_of = "nat-default",
  .format_trace = format_nat_in2out_ed_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_in2out_ed_error_strings),
  .error_strings = nat_in2out_ed_error_strings,
  .runtime_data_bytes = sizeof (snat_runtime_t),
};
/* *INDENT-ON* */

VLIB_NODE_FN (nat44_ed_in2out_output_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  return nat44_ed_in2out_fast_path_node_fn_inline (vm, node, frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_in2out_output_node) = {
  .name = "nat44-ed-in2out-output",
  .vector_size = sizeof (u32),
  .sibling_of = "nat-default",
  .format_trace = format_nat_in2out_ed_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_in2out_ed_error_strings),
  .error_strings = nat_in2out_ed_error_strings,
  .runtime_data_bytes = sizeof (snat_runtime_t),
};
/* *INDENT-ON* */

VLIB_NODE_FN (nat44_ed_in2out_slowpath_node) (vlib_main_t * vm,
					      vlib_node_runtime_t *
					      node, vlib_frame_t * frame)
{
  return nat44_ed_in2out_slow_path_node_fn_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_in2out_slowpath_node) = {
  .name = "nat44-ed-in2out-slowpath",
  .vector_size = sizeof (u32),
  .sibling_of = "nat-default",
  .format_trace = format_nat_in2out_ed_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_in2out_ed_error_strings),
  .error_strings = nat_in2out_ed_error_strings,
  .runtime_data_bytes = sizeof (snat_runtime_t),
};
/* *INDENT-ON* */

VLIB_NODE_FN (nat44_ed_in2out_output_slowpath_node) (vlib_main_t * vm,
						     vlib_node_runtime_t
						     * node,
						     vlib_frame_t * frame)
{
  return nat44_ed_in2out_slow_path_node_fn_inline (vm, node, frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_in2out_output_slowpath_node) = {
  .name = "nat44-ed-in2out-output-slowpath",
  .vector_size = sizeof (u32),
  .sibling_of = "nat-default",
  .format_trace = format_nat_in2out_ed_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_in2out_ed_error_strings),
  .error_strings = nat_in2out_ed_error_strings,
  .runtime_data_bytes = sizeof (snat_runtime_t),
};
/* *INDENT-ON* */

static u8 *
format_nat_pre_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat_pre_trace_t *t = va_arg (*args, nat_pre_trace_t *);
  return format (s, "in2out next_index %d arc_next_index %d", t->next_index,
		 t->arc_next_index);
}

VLIB_NODE_FN (nat_pre_in2out_node)
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return nat_pre_node_fn_inline (vm, node, frame,
				 NAT_NEXT_IN2OUT_ED_FAST_PATH);
}

VLIB_NODE_FN (nat_pre_in2out_output_node)
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return nat_pre_node_fn_inline (vm, node, frame,
				 NAT_NEXT_IN2OUT_ED_OUTPUT_FAST_PATH);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat_pre_in2out_node) = {
  .name = "nat-pre-in2out",
  .vector_size = sizeof (u32),
  .sibling_of = "nat-default",
  .format_trace = format_nat_pre_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
};

VLIB_REGISTER_NODE (nat_pre_in2out_output_node) = {
  .name = "nat-pre-in2out-output",
  .vector_size = sizeof (u32),
  .sibling_of = "nat-default",
  .format_trace = format_nat_pre_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
