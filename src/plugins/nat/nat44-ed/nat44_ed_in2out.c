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

#include <nat/lib/nat_inlines.h>
#include <nat/lib/ipfix_logging.h>

#include <nat/nat44-ed/nat44_ed.h>
#include <nat/nat44-ed/nat44_ed_inlines.h>

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
  nat_translation_error_e translation_error;
  nat_6t_flow_t i2of;
  nat_6t_flow_t o2if;
  clib_bihash_kv_16_8_t search_key;
  u8 is_slow_path;
  u8 translation_via_i2of;
  u8 lookup_skipped;
  u8 tcp_state;
  u8 l4_layer_truncated;
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

  s = format (s, "%s: sw_if_index %d, next index %d", tag, t->sw_if_index,
	      t->next_index);
  if (~0 != t->session_index)
    {
      s = format (s, ", session %d, translation result '%U' via %s",
		  t->session_index, format_nat_ed_translation_error,
		  t->translation_error,
		  t->translation_via_i2of ? "i2of" : "o2if");
      s = format (s, "\n  i2of %U", format_nat_6t_flow, &t->i2of);
      s = format (s, "\n  o2if %U", format_nat_6t_flow, &t->o2if);
    }
  if (!t->is_slow_path)
    {
      if (t->lookup_skipped)
	{
	  s = format (s, "\n  lookup skipped - cached session index used");
	}
      else if (t->l4_layer_truncated)
	{
	  s = format (s, "\n  lookup skipped - l4 layer truncated");
	}
      else
	{
	  s = format (s, "\n  search key %U", format_ed_session_kvp,
		      &t->search_key);
	}
    }
  if (IP_PROTOCOL_TCP == t->i2of.match.proto)
    {
      s = format (s, "\n  TCP state: %U", format_nat44_ed_tcp_state,
		  t->tcp_state);
    }

  return s;
}

/**
 * @brief Check if packet should be translated
 *
 * Packets aimed at outside interface and external address with active session
 * should be translated.
 *
 * @param sm            NAT main
 * @param rt            NAT runtime data
 * @param sw_if_index0  index of the inside interface
 * @param ip0           IPv4 header
 * @param rx_fib_index0 RX FIB index
 *
 * @returns 0 if packet should be translated otherwise 1
 */
static inline int
snat_not_translate_fast (snat_main_t *sm, vlib_node_runtime_t *node,
			 u32 sw_if_index0, ip4_header_t *ip0,
			 u32 rx_fib_index0)
{
  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  nat_outside_fib_t *outside_fib;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
		.ip4.as_u32 = ip0->dst_address.as_u32,
		}
    ,
  };

  /* Don't NAT packet aimed at the intfc address */
  if (PREDICT_FALSE (
	is_interface_addr (sm, node, sw_if_index0, ip0->dst_address.as_u32)))
    return 1;

  fei = fib_table_lookup (rx_fib_index0, &pfx);
  if (FIB_NODE_INDEX_INVALID != fei)
    {
      u32 sw_if_index = fib_entry_get_resolving_interface (fei);
      if (sw_if_index == ~0)
	{
	  vec_foreach (outside_fib, sm->outside_fibs)
	    {
	      fei = fib_table_lookup (outside_fib->fib_index, &pfx);
	      if (FIB_NODE_INDEX_INVALID != fei)
		{
		  sw_if_index = fib_entry_get_resolving_interface (fei);
		  if (sw_if_index != ~0)
		    break;
		}
	    }
	}
      if (sw_if_index == ~0)
	return 1;

      snat_interface_t *i;
      pool_foreach (i, sm->interfaces)
	{
	  /* NAT packet aimed at outside interface */
	  if ((nat44_ed_is_interface_outside (i)) &&
	      (sw_if_index == i->sw_if_index))
	    return 0;
	}
    }

  return 1;
}

static int
nat_ed_alloc_addr_and_port_with_snat_address (
  snat_main_t *sm, u8 proto, u32 thread_index, snat_address_t *a,
  u16 port_per_thread, u32 snat_thread_index, snat_session_t *s,
  ip4_address_t *outside_addr, u16 *outside_port)
{
  const u16 port_thread_offset = (port_per_thread * snat_thread_index) + 1024;

  s->o2i.match.daddr = a->addr;
  /* first try port suggested by caller */
  u16 port = clib_net_to_host_u16 (*outside_port);
  u16 port_offset = port - port_thread_offset;
  if (port <= port_thread_offset ||
      port > port_thread_offset + port_per_thread)
    {
      /* need to pick a different port, suggested port doesn't fit in
       * this thread's port range */
      port_offset = snat_random_port (0, port_per_thread - 1);
      port = port_thread_offset + port_offset;
    }
  u16 attempts = ED_PORT_ALLOC_ATTEMPTS;
  do
    {
      if (IP_PROTOCOL_ICMP == proto)
	{
	  s->o2i.match.sport = clib_host_to_net_u16 (port);
	}
      s->o2i.match.dport = clib_host_to_net_u16 (port);
      if (0 == nat_ed_ses_o2i_flow_hash_add_del (sm, thread_index, s, 2))
	{
	  *outside_addr = a->addr;
	  *outside_port = clib_host_to_net_u16 (port);
	  return 0;
	}
      port_offset = snat_random_port (0, port_per_thread - 1);
      port = port_thread_offset + port_offset;
      --attempts;
    }
  while (attempts > 0);
  return 1;
}

static int
nat_ed_alloc_addr_and_port (snat_main_t *sm, u32 rx_fib_index,
			    u32 tx_sw_if_index, u32 nat_proto,
			    u32 thread_index, ip4_address_t s_addr,
			    ip4_address_t d_addr, u32 snat_thread_index,
			    snat_session_t *s, ip4_address_t *outside_addr,
			    u16 *outside_port)
{
  if (vec_len (sm->addresses) > 0)
    {
      u32 s_addr_offset = s_addr.as_u32 % vec_len (sm->addresses);
      snat_address_t *a, *ja = 0, *ra = 0, *ba = 0;
      int i;

      // output feature
      if (tx_sw_if_index != ~0)
	{
	  for (i = s_addr_offset; i < vec_len (sm->addresses); ++i)
	    {
	      a = sm->addresses + i;
	      if (a->fib_index == rx_fib_index)
		{
		  if (a->sw_if_index == tx_sw_if_index)
		    {
		      if ((a->addr_len != ~0) &&
			  (a->net.as_u32 ==
			   (d_addr.as_u32 & ip4_main.fib_masks[a->addr_len])))

			{
			  return nat_ed_alloc_addr_and_port_with_snat_address (
			    sm, nat_proto, thread_index, a,
			    sm->port_per_thread, snat_thread_index, s,
			    outside_addr, outside_port);
			}
		      ra = a;
		    }
		  ja = a;
		}
	      else if (a->fib_index == ~0)
		{
		  ba = a;
		}
	    }
	  for (i = 0; i < s_addr_offset; ++i)
	    {
	      a = sm->addresses + i;
	      if (a->fib_index == rx_fib_index)
		{
		  if (a->sw_if_index == tx_sw_if_index)
		    {
		      if ((a->addr_len != ~0) &&
			  (a->net.as_u32 ==
			   (d_addr.as_u32 & ip4_main.fib_masks[a->addr_len])))

			{
			  return nat_ed_alloc_addr_and_port_with_snat_address (
			    sm, nat_proto, thread_index, a,
			    sm->port_per_thread, snat_thread_index, s,
			    outside_addr, outside_port);
			}
		      ra = a;
		    }
		  ja = a;
		}
	      else if (a->fib_index == ~0)
		{
		  ba = a;
		}
	    }
	  if (ra)
	    {
	      return nat_ed_alloc_addr_and_port_with_snat_address (
		sm, nat_proto, thread_index, ra, sm->port_per_thread,
		snat_thread_index, s, outside_addr, outside_port);
	    }
	}
      else
	{
	  // first try nat pool addresses to sw interface addreses mappings
	  for (i = s_addr_offset; i < vec_len (sm->addresses); ++i)
	    {
	      a = sm->addresses + i;
	      if (a->fib_index == rx_fib_index)
		{
		  if ((a->addr_len != ~0) &&
		      (a->net.as_u32 ==
		       (d_addr.as_u32 & ip4_main.fib_masks[a->addr_len])))
		    {
		      return nat_ed_alloc_addr_and_port_with_snat_address (
			sm, nat_proto, thread_index, a, sm->port_per_thread,
			snat_thread_index, s, outside_addr, outside_port);
		    }
		  ja = a;
		}
	      else if (a->fib_index == ~0)
		{
		  ba = a;
		}
	    }
	  for (i = 0; i < s_addr_offset; ++i)
	    {
	      a = sm->addresses + i;
	      if (a->fib_index == rx_fib_index)
		{
		  if ((a->addr_len != ~0) &&
		      (a->net.as_u32 ==
		       (d_addr.as_u32 & ip4_main.fib_masks[a->addr_len])))
		    {
		      return nat_ed_alloc_addr_and_port_with_snat_address (
			sm, nat_proto, thread_index, a, sm->port_per_thread,
			snat_thread_index, s, outside_addr, outside_port);
		    }
		  ja = a;
		}
	      else if (a->fib_index == ~0)
		{
		  ba = a;
		}
	    }
	}

      if (ja || ba)
	{
	  a = ja ? ja : ba;
	  return nat_ed_alloc_addr_and_port_with_snat_address (
	    sm, nat_proto, thread_index, a, sm->port_per_thread,
	    snat_thread_index, s, outside_addr, outside_port);
	}
    }
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
  return ~0;
}

static_always_inline int
nat44_ed_external_sm_lookup (snat_main_t *sm, ip4_address_t match_addr,
			     u16 match_port, ip_protocol_t match_protocol,
			     ip4_address_t *daddr, u16 *dport)
{
  snat_static_mapping_t *m =
    nat44_ed_sm_o2i_lookup (sm, match_addr, match_port, 0, match_protocol);
  if (!m)
    {
      /* Try address only mapping */
      m = nat44_ed_sm_o2i_lookup (sm, match_addr, 0, 0, 0);
      if (!m)
	return 0;
    }
  *daddr = m->local_addr;
  if (dport)
    {
      /* Address only mapping doesn't change port */
      *dport = is_sm_addr_only (m->flags) ? match_port : m->local_port;
    }
  return 1;
}

static u32
slow_path_ed (vlib_main_t *vm, snat_main_t *sm, vlib_buffer_t *b,
	      ip4_address_t l_addr, ip4_address_t r_addr, u16 l_port,
	      u16 r_port, u8 proto, u32 rx_fib_index, u32 tx_sw_if_index,
	      snat_session_t **sessionp, vlib_node_runtime_t *node, u32 next,
	      u32 thread_index, f64 now)
{
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  ip4_address_t outside_addr;
  u16 outside_port;
  u32 outside_fib_index;
  u8 is_identity_nat = 0;

  snat_session_t *s = NULL;
  lb_nat_type_t lb = 0;
  ip4_address_t daddr = r_addr;
  u16 dport = r_port;

  if (PREDICT_FALSE
      (nat44_ed_maximum_sessions_exceeded (sm, rx_fib_index, thread_index)))
    {
      if (!nat_lru_free_one (sm, thread_index, now))
	{
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_MAX_SESSIONS_EXCEEDED];
	  nat_ipfix_logging_max_sessions (thread_index,
					  sm->max_translations_per_thread);
	  nat_elog_notice (sm, "maximum sessions exceeded");
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
  /* First try to match static mapping by local address and port */
  int is_sm;
  if (snat_static_mapping_match (vm, sm, l_addr, l_port, rx_fib_index, proto,
				 &sm_addr, &sm_port, &sm_fib_index, 0,
				 vnet_buffer (b)->ip.reass.l4_layer_truncated,
				 0, 0, &lb, 0, &is_identity_nat, 0))
    {
      if (PREDICT_FALSE (vnet_buffer (b)->ip.reass.l4_layer_truncated))
	{
	  *sessionp = NULL;
	  return NAT_NEXT_DROP;
	}
      is_sm = 0;
    }
  else
    {
      if (PREDICT_FALSE (is_identity_nat))
	{
	  *sessionp = NULL;
	  return next;
	}
      is_sm = 1;
    }

  if (PREDICT_TRUE (proto == IP_PROTOCOL_TCP))
    {
      if (PREDICT_FALSE (!tcp_flags_is_init (
	    vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags)))
	{
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_NON_SYN];
	  return NAT_NEXT_DROP;
	}
    }

  s = nat_ed_session_alloc (sm, thread_index, now, proto);
  ASSERT (s);

  if (!is_sm)
    {
      s->in2out.addr = l_addr;
      s->in2out.port = l_port;
      s->proto = proto;
      s->in2out.fib_index = rx_fib_index;
      s->out2in.fib_index = outside_fib_index;

      // suggest using local port to allocation function
      outside_port = l_port;

      // hairpinning?
      int is_hairpinning = nat44_ed_external_sm_lookup (sm, r_addr, r_port,
							proto, &daddr, &dport);
      s->flags |= is_hairpinning * SNAT_SESSION_FLAG_HAIRPINNING;

      // destination addr/port updated with real values in
      // nat_ed_alloc_addr_and_port
      nat_6t_o2i_flow_init (sm, thread_index, s, daddr, dport, daddr, 0,
			    s->out2in.fib_index, proto);
      nat_6t_flow_daddr_rewrite_set (&s->o2i, l_addr.as_u32);
      if (IP_PROTOCOL_ICMP == proto)
	{
	  nat_6t_flow_icmp_id_rewrite_set (&s->o2i, l_port);
	}
      else
	{
	  nat_6t_flow_dport_rewrite_set (&s->o2i, l_port);
	}
      nat_6t_flow_txfib_rewrite_set (&s->o2i, rx_fib_index);

      if (nat_ed_alloc_addr_and_port (
	    sm, rx_fib_index, tx_sw_if_index, proto, thread_index, l_addr,
	    r_addr, tsm->snat_thread_index, s, &outside_addr, &outside_port))
	{
	  nat_elog_notice (sm, "addresses exhausted");
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_OUT_OF_PORTS];
	  nat_ed_session_delete (sm, s, thread_index, 1);
	  return NAT_NEXT_DROP;
	}
      s->out2in.addr = outside_addr;
      s->out2in.port = outside_port;
    }
  else
    {
      // static mapping
      s->out2in.addr = outside_addr = sm_addr;
      s->out2in.port = outside_port = sm_port;
      s->in2out.addr = l_addr;
      s->in2out.port = l_port;
      s->proto = proto;
      s->in2out.fib_index = rx_fib_index;
      s->out2in.fib_index = outside_fib_index;
      s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;

      // hairpinning?
      int is_hairpinning = nat44_ed_external_sm_lookup (sm, r_addr, r_port,
							proto, &daddr, &dport);
      s->flags |= is_hairpinning * SNAT_SESSION_FLAG_HAIRPINNING;

      if (IP_PROTOCOL_ICMP == proto)
	{
	  nat_6t_o2i_flow_init (sm, thread_index, s, daddr, sm_port, sm_addr,
				sm_port, s->out2in.fib_index, proto);
	  nat_6t_flow_icmp_id_rewrite_set (&s->o2i, l_port);
	}
      else
	{
	  nat_6t_o2i_flow_init (sm, thread_index, s, daddr, dport, sm_addr,
				sm_port, s->out2in.fib_index, proto);
	  nat_6t_flow_dport_rewrite_set (&s->o2i, l_port);
	}
      nat_6t_flow_daddr_rewrite_set (&s->o2i, l_addr.as_u32);
      nat_6t_flow_txfib_rewrite_set (&s->o2i, rx_fib_index);
      if (nat_ed_ses_o2i_flow_hash_add_del (sm, thread_index, s, 2))
	{
	  nat_elog_notice (sm, "out2in key add failed");
	  goto error;
	}
    }

  if (lb)
    s->flags |= SNAT_SESSION_FLAG_LOAD_BALANCING;
  s->ext_host_addr = r_addr;
  s->ext_host_port = r_port;

  nat_6t_i2o_flow_init (sm, thread_index, s, l_addr, l_port, r_addr, r_port,
			rx_fib_index, proto);
  nat_6t_flow_saddr_rewrite_set (&s->i2o, outside_addr.as_u32);
  nat_6t_flow_daddr_rewrite_set (&s->i2o, daddr.as_u32);

  if (IP_PROTOCOL_ICMP == proto)
    {
      nat_6t_flow_icmp_id_rewrite_set (&s->i2o, outside_port);
    }
  else
    {
      nat_6t_flow_sport_rewrite_set (&s->i2o, outside_port);
      nat_6t_flow_dport_rewrite_set (&s->i2o, dport);
    }
  nat_6t_flow_txfib_rewrite_set (&s->i2o, outside_fib_index);

  if (nat_ed_ses_i2o_flow_hash_add_del (sm, thread_index, s, 1))
    {
      nat_elog_notice (sm, "in2out key add failed");
      goto error;
    }

  /* log NAT event */
  nat_ipfix_logging_nat44_ses_create (
    thread_index, s->in2out.addr.as_u32, s->out2in.addr.as_u32, s->proto,
    s->in2out.port, s->out2in.port, s->in2out.fib_index);

  nat_syslog_nat44_sadd (0, s->in2out.fib_index, &s->in2out.addr,
			 s->in2out.port, &s->ext_host_nat_addr,
			 s->ext_host_nat_port, &s->out2in.addr, s->out2in.port,
			 &s->ext_host_addr, s->ext_host_port, s->proto, 0);

  per_vrf_sessions_register_session (s, thread_index);

  *sessionp = s;
  return next;
error:
  if (s)
    {
      nat_ed_session_delete (sm, s, thread_index, 1);
    }
  *sessionp = s = NULL;
  return NAT_NEXT_DROP;
}

static_always_inline int
nat44_ed_not_translate (vlib_main_t *vm, snat_main_t *sm,
			vlib_node_runtime_t *node, u32 sw_if_index,
			vlib_buffer_t *b, ip4_header_t *ip, u32 proto,
			u32 rx_fib_index)
{
  clib_bihash_kv_16_8_t kv, value;

  init_ed_k (&kv, ip->dst_address.as_u32,
	     vnet_buffer (b)->ip.reass.l4_dst_port, ip->src_address.as_u32,
	     vnet_buffer (b)->ip.reass.l4_src_port, sm->outside_fib_index,
	     ip->protocol);

  /* NAT packet aimed at external address if has active sessions */
  if (PREDICT_FALSE (vnet_buffer (b)->ip.reass.l4_layer_truncated) ||
      clib_bihash_search_16_8 (&sm->flow_hash, &kv, &value))
    {
      /* or is static mappings */
      ip4_address_t placeholder_addr;
      u16 placeholder_port;
      u32 placeholder_fib_index;
      if (!snat_static_mapping_match (
	    vm, sm, ip->dst_address, vnet_buffer (b)->ip.reass.l4_dst_port,
	    sm->outside_fib_index, proto, &placeholder_addr, &placeholder_port,
	    &placeholder_fib_index, 1,
	    vnet_buffer (b)->ip.reass.l4_layer_truncated, 0, 0, 0, 0, 0, 0))
	return 0;
    }
  else
    return 0;

  if (sm->forwarding_enabled)
    return 1;

  return snat_not_translate_fast (sm, node, sw_if_index, ip, rx_fib_index);
}

static_always_inline int
nat_not_translate_output_feature_fwd (snat_main_t * sm, ip4_header_t * ip,
				      u32 thread_index, f64 now,
				      vlib_main_t * vm, vlib_buffer_t * b)
{
  clib_bihash_kv_16_8_t kv, value;
  snat_session_t *s = 0;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  if (!sm->forwarding_enabled)
    return 0;

  if (ip->protocol == IP_PROTOCOL_ICMP)
    {
      ip4_address_t lookup_saddr, lookup_daddr;
      u16 lookup_sport, lookup_dport;
      u8 lookup_protocol;
      if (nat_get_icmp_session_lookup_values (b, ip, &lookup_saddr,
					      &lookup_sport, &lookup_daddr,
					      &lookup_dport, &lookup_protocol))
	return 0;
      init_ed_k (&kv, lookup_saddr.as_u32, lookup_sport, lookup_daddr.as_u32,
		 lookup_dport, 0, lookup_protocol);
    }
  else if (ip->protocol == IP_PROTOCOL_UDP || ip->protocol == IP_PROTOCOL_TCP)
    {
      init_ed_k (&kv, ip->src_address.as_u32,
		 vnet_buffer (b)->ip.reass.l4_src_port, ip->dst_address.as_u32,
		 vnet_buffer (b)->ip.reass.l4_dst_port, 0, ip->protocol);
    }
  else
    {
      init_ed_k (&kv, ip->src_address.as_u32, 0, ip->dst_address.as_u32, 0, 0,
		 ip->protocol);
    }

  if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv, &value))
    {
      ASSERT (thread_index == ed_value_get_thread_index (&value));
      s =
	pool_elt_at_index (tsm->sessions,
			   ed_value_get_session_index (&value));

      if (na44_ed_is_fwd_bypass_session (s))
	{
	  if (ip->protocol == IP_PROTOCOL_TCP)
	    {
	      nat44_set_tcp_session_state_i2o (
		sm, now, s, vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags,
		thread_index);
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
nat44_ed_not_translate_output_feature (snat_main_t *sm, vlib_buffer_t *b,
				       ip4_header_t *ip, u16 src_port,
				       u16 dst_port, u32 thread_index,
				       u32 rx_sw_if_index, u32 tx_sw_if_index,
				       int is_multi_worker)
{
  clib_bihash_kv_16_8_t kv, value;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  snat_interface_t *i;
  snat_session_t *s;
  u32 rx_fib_index = ip4_fib_table_get_index_for_sw_if_index (rx_sw_if_index);
  u32 tx_fib_index = ip4_fib_table_get_index_for_sw_if_index (tx_sw_if_index);

  /* src NAT check */
  init_ed_k (&kv, ip->src_address.as_u32, src_port, ip->dst_address.as_u32,
	     dst_port, tx_fib_index, ip->protocol);
  if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv, &value))
    {
      ASSERT (thread_index == ed_value_get_thread_index (&value));
      s =
	pool_elt_at_index (tsm->sessions,
			   ed_value_get_session_index (&value));
      return 1;
    }

  /* dst NAT check */
  if (is_multi_worker &&
      PREDICT_TRUE (!pool_is_free_index (
	tsm->sessions, vnet_buffer2 (b)->nat.cached_dst_nat_session_index)))
    {
      nat_6t_t lookup;
      lookup.fib_index = rx_fib_index;
      lookup.proto = ip->protocol;
      lookup.daddr.as_u32 = ip->src_address.as_u32;
      lookup.dport = src_port;
      lookup.saddr.as_u32 = ip->dst_address.as_u32;
      lookup.sport = dst_port;
      s = pool_elt_at_index (
	tsm->sessions, vnet_buffer2 (b)->nat.cached_dst_nat_session_index);
      if (PREDICT_TRUE (nat_6t_t_eq (&s->i2o.match, &lookup)))
	{
	  goto skip_dst_nat_lookup;
	}
      s = NULL;
    }

  init_ed_k (&kv, ip->dst_address.as_u32, dst_port, ip->src_address.as_u32,
	     src_port, rx_fib_index, ip->protocol);
  if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv, &value))
    {
      ASSERT (thread_index == ed_value_get_thread_index (&value));
      s =
	pool_elt_at_index (tsm->sessions,
			   ed_value_get_session_index (&value));

    skip_dst_nat_lookup:
      if (na44_ed_is_fwd_bypass_session (s))
	return 0;

      /* hairpinning */
      pool_foreach (i, sm->output_feature_interfaces)
	{
	  if ((nat44_ed_is_interface_inside (i)) &&
	      (rx_sw_if_index == i->sw_if_index))
	    return 0;
	}
      return 1;
    }

  return 0;
}

static inline u32
icmp_in2out_ed_slow_path (snat_main_t *sm, vlib_buffer_t *b, ip4_header_t *ip,
			  icmp46_header_t *icmp, u32 sw_if_index,
			  u32 tx_sw_if_index, u32 rx_fib_index,
			  vlib_node_runtime_t *node, u32 next, f64 now,
			  u32 thread_index, snat_session_t **s_p,
			  int is_multi_worker)
{
  vlib_main_t *vm = vlib_get_main ();
  u16 checksum;
  int err;
  snat_session_t *s = NULL;
  u8 lookup_protocol = ip->protocol;
  u16 lookup_sport, lookup_dport;
  ip4_address_t lookup_saddr, lookup_daddr;

  err = nat_get_icmp_session_lookup_values (b, ip, &lookup_saddr,
					    &lookup_sport, &lookup_daddr,
					    &lookup_dport, &lookup_protocol);
  if (err != 0)
    {
      b->error = node->errors[err];
      return NAT_NEXT_DROP;
    }

  if (tx_sw_if_index != ~0)
    {
      if (PREDICT_FALSE (nat44_ed_not_translate_output_feature (
	    sm, b, ip, lookup_sport, lookup_dport, thread_index, sw_if_index,
	    tx_sw_if_index, is_multi_worker)))
	{
	  return next;
	}
    }
  else
    {
      if (PREDICT_FALSE (nat44_ed_not_translate (
	    vm, sm, node, sw_if_index, b, ip, IP_PROTOCOL_ICMP, rx_fib_index)))
	{
	  return next;
	}
    }

  if (PREDICT_FALSE (icmp_type_is_error_message (
	vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags)))
    {
      b->error = node->errors[NAT_IN2OUT_ED_ERROR_BAD_ICMP_TYPE];
      return NAT_NEXT_DROP;
    }

  next =
    slow_path_ed (vm, sm, b, ip->src_address, ip->dst_address, lookup_sport,
		  lookup_dport, ip->protocol, rx_fib_index, tx_sw_if_index, &s,
		  node, next, thread_index, vlib_time_now (vm));

  if (NAT_NEXT_DROP == next)
    goto out;

  if (PREDICT_TRUE (!ip4_is_fragment (ip)))
    {
      ip_csum_t sum = ip_incremental_checksum_buffer (
	vm, b, (u8 *) icmp - (u8 *) vlib_buffer_get_current (b),
	ntohs (ip->length) - ip4_header_bytes (ip), 0);
      checksum = ~ip_csum_fold (sum);
      if (PREDICT_FALSE (checksum != 0 && checksum != 0xffff))
	{
	  next = NAT_NEXT_DROP;
	  goto out;
	}
    }

out:
  if (PREDICT_TRUE (next != NAT_NEXT_DROP && s))
    {
      /* Accounting */
      nat44_session_update_counters (
	s, now, vlib_buffer_length_in_chain (vm, b), thread_index);
      /* Per-user LRU list maintenance */
      nat44_session_update_lru (sm, s, thread_index);
    }
  *s_p = s;
  return next;
}

static snat_session_t *
nat44_ed_in2out_slowpath_unknown_proto (snat_main_t *sm, vlib_buffer_t *b,
					ip4_header_t *ip, u32 rx_fib_index,
					u32 thread_index, f64 now,
					vlib_main_t *vm,
					vlib_node_runtime_t *node)
{
  clib_bihash_kv_16_8_t s_kv, s_value;
  snat_static_mapping_t *m = NULL;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  snat_session_t *s = NULL;
  u32 outside_fib_index = sm->outside_fib_index;
  int i;
  ip4_address_t new_src_addr = { 0 };
  ip4_address_t new_dst_addr = ip->dst_address;

  if (PREDICT_FALSE (
	nat44_ed_maximum_sessions_exceeded (sm, rx_fib_index, thread_index)))
    {
      b->error = node->errors[NAT_IN2OUT_ED_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_ipfix_logging_max_sessions (thread_index,
				      sm->max_translations_per_thread);
      nat_elog_notice (sm, "maximum sessions exceeded");
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

  /* Try to find static mapping first */
  m = nat44_ed_sm_i2o_lookup (sm, ip->src_address, 0, rx_fib_index,
			      ip->protocol);
  if (m)
    {
      new_src_addr = m->external_addr;
    }
  else
    {
      pool_foreach (s, tsm->sessions)
	{
	  if (s->ext_host_addr.as_u32 == ip->dst_address.as_u32)
	    {
	      init_ed_k (&s_kv, s->out2in.addr.as_u32, 0,
			 ip->dst_address.as_u32, 0, outside_fib_index,
			 ip->protocol);
	      if (clib_bihash_search_16_8 (&sm->flow_hash, &s_kv, &s_value))
		{
		  new_src_addr = s->out2in.addr;
		}
	      break;
	    }
	}

      if (!new_src_addr.as_u32)
	{
	  for (i = 0; i < vec_len (sm->addresses); i++)
	    {
	      init_ed_k (&s_kv, sm->addresses[i].addr.as_u32, 0,
			 ip->dst_address.as_u32, 0, outside_fib_index,
			 ip->protocol);
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
      nat_elog_warn (sm, "create NAT session failed");
      return 0;
    }

  nat_6t_i2o_flow_init (sm, thread_index, s, ip->src_address, 0,
			ip->dst_address, 0, rx_fib_index, ip->protocol);
  nat_6t_flow_saddr_rewrite_set (&s->i2o, new_src_addr.as_u32);
  nat_6t_flow_txfib_rewrite_set (&s->i2o, outside_fib_index);

  // hairpinning?
  int is_hairpinning = nat44_ed_external_sm_lookup (
    sm, ip->dst_address, 0, ip->protocol, &new_dst_addr, NULL);
  s->flags |= is_hairpinning * SNAT_SESSION_FLAG_HAIRPINNING;

  nat_6t_flow_daddr_rewrite_set (&s->i2o, new_dst_addr.as_u32);
  nat_6t_flow_txfib_rewrite_set (&s->i2o, outside_fib_index);

  nat_6t_o2i_flow_init (sm, thread_index, s, new_dst_addr, 0, new_src_addr, 0,
			outside_fib_index, ip->protocol);
  nat_6t_flow_saddr_rewrite_set (&s->o2i, ip->dst_address.as_u32);
  nat_6t_flow_daddr_rewrite_set (&s->o2i, ip->src_address.as_u32);
  nat_6t_flow_txfib_rewrite_set (&s->o2i, rx_fib_index);

  s->ext_host_addr.as_u32 = ip->dst_address.as_u32;
  s->out2in.addr.as_u32 = new_src_addr.as_u32;
  s->out2in.fib_index = outside_fib_index;
  s->in2out.addr.as_u32 = ip->src_address.as_u32;
  s->in2out.fib_index = rx_fib_index;
  s->in2out.port = s->out2in.port = ip->protocol;
  if (m)
    s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;

  if (nat_ed_ses_i2o_flow_hash_add_del (sm, thread_index, s, 1))
    {
      nat_elog_notice (sm, "in2out flow hash add failed");
      nat_ed_session_delete (sm, s, thread_index, 1);
      return NULL;
    }

  if (nat_ed_ses_o2i_flow_hash_add_del (sm, thread_index, s, 1))
    {
      nat_elog_notice (sm, "out2in flow hash add failed");
      nat_ed_session_delete (sm, s, thread_index, 1);
      return NULL;
    }

  per_vrf_sessions_register_session (s, thread_index);

  /* Accounting */
  nat44_session_update_counters (s, now, vlib_buffer_length_in_chain (vm, b),
				 thread_index);
  /* Per-user LRU list maintenance */
  nat44_session_update_lru (sm, s, thread_index);

  return s;
}

static inline uword
nat44_ed_in2out_fast_path_node_fn_inline (vlib_main_t *vm,
					  vlib_node_runtime_t *node,
					  vlib_frame_t *frame,
					  int is_output_feature,
					  int is_multi_worker)
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
      u32 rx_sw_if_index0, rx_fib_index0, iph_offset0 = 0;
      u32 tx_sw_if_index0;
      u32 cntr_sw_if_index0;
      ip_protocol_t proto0;
      ip4_header_t *ip0;
      snat_session_t *s0 = 0;
      clib_bihash_kv_16_8_t kv0, value0;
      nat_translation_error_e translation_error = NAT_ED_TRNSL_ERR_SUCCESS;
      nat_6t_flow_t *f = 0;
      nat_6t_t lookup;
      int lookup_skipped = 0;

      b0 = *b;
      b++;

      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left_from >= 2))
	{
	  vlib_buffer_t *p2;

	  p2 = *b;

	  vlib_prefetch_buffer_header (p2, LOAD);

	  clib_prefetch_load (p2->data);
	}

      if (is_output_feature)
	{
	  iph_offset0 = vnet_buffer (b0)->ip.reass.save_rewrite_length;
	}

      next[0] = vnet_buffer2 (b0)->nat.arc_next;

      ip0 =
	(ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) + iph_offset0);

      rx_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      tx_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
      cntr_sw_if_index0 =
	is_output_feature ? tx_sw_if_index0 : rx_sw_if_index0;
      rx_fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
							   rx_sw_if_index0);
      lookup.fib_index = rx_fib_index0;

      if (PREDICT_FALSE (!is_output_feature && ip0->ttl == 1))
	{
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next[0] = NAT_NEXT_ICMP_ERROR;
	  goto trace0;
	}

      proto0 = ip0->protocol;

      if (is_output_feature)
	{
	  if (PREDICT_FALSE
	      (nat_not_translate_output_feature_fwd
	       (sm, ip0, thread_index, now, vm, b0)))
	    goto trace0;
	}

      if (vnet_buffer (b0)->ip.reass.l4_layer_truncated)
	{
	  next[0] = def_slow;
	  goto trace0;
	}

      if (PREDICT_FALSE (proto0 == IP_PROTOCOL_ICMP))
	{
	  if (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
		ICMP4_echo_request &&
	      vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
		ICMP4_echo_reply &&
	      !icmp_type_is_error_message (
		vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags))
	    {
	      b0->error = node->errors[NAT_IN2OUT_ED_ERROR_BAD_ICMP_TYPE];
	      next[0] = NAT_NEXT_DROP;
	      goto trace0;
	    }
	  int err = nat_get_icmp_session_lookup_values (
	    b0, ip0, &lookup.saddr, &lookup.sport, &lookup.daddr,
	    &lookup.dport, &lookup.proto);
	  if (err != 0)
	    {
	      b0->error = node->errors[err];
	      next[0] = NAT_NEXT_DROP;
	      goto trace0;
	    }
	}
      else
	{
	  lookup.proto = ip0->protocol;
	  lookup.saddr.as_u32 = ip0->src_address.as_u32;
	  lookup.daddr.as_u32 = ip0->dst_address.as_u32;
	  lookup.sport = vnet_buffer (b0)->ip.reass.l4_src_port;
	  lookup.dport = vnet_buffer (b0)->ip.reass.l4_dst_port;
	}

      /* there might be a stashed index in vnet_buffer2 from handoff or
       * classify node, see if it can be used */
      if (is_multi_worker &&
	  !pool_is_free_index (tsm->sessions,
			       vnet_buffer2 (b0)->nat.cached_session_index))
	{
	  s0 = pool_elt_at_index (tsm->sessions,
				  vnet_buffer2 (b0)->nat.cached_session_index);
	  if (PREDICT_TRUE (
		nat_6t_t_eq (&s0->i2o.match, &lookup)
		// for some hairpinning cases there are two "i2i" flows instead
		// of i2o and o2i as both hosts are on inside
		|| (s0->flags & SNAT_SESSION_FLAG_HAIRPINNING &&
		    nat_6t_t_eq (&s0->o2i.match, &lookup))))
	    {
	      /* yes, this is the droid we're looking for */
	      lookup_skipped = 1;
	      goto skip_lookup;
	    }
	  s0 = NULL;
	}

      init_ed_k (&kv0, lookup.saddr.as_u32, lookup.sport, lookup.daddr.as_u32,
		 lookup.dport, lookup.fib_index, lookup.proto);

      // lookup flow
      if (clib_bihash_search_16_8 (&sm->flow_hash, &kv0, &value0))
	{
	  // flow does not exist go slow path
	  next[0] = def_slow;
	  goto trace0;
	}

      ASSERT (thread_index == ed_value_get_thread_index (&value0));
      s0 =
	pool_elt_at_index (tsm->sessions,
			   ed_value_get_session_index (&value0));

    skip_lookup:

      ASSERT (thread_index == s0->thread_index);

      if (PREDICT_FALSE (per_vrf_sessions_is_expired (s0, thread_index)))
	{
	  // session is closed, go slow path
	  nat44_ed_free_session_data (sm, s0, thread_index, 0);
	  nat_ed_session_delete (sm, s0, thread_index, 1);
	  next[0] = NAT_NEXT_OUT2IN_ED_SLOW_PATH;
	  goto trace0;
	}

      // drop if session expired
      u64 sess_timeout_time;
      sess_timeout_time =
	s0->last_heard + (f64) nat44_session_get_timeout (sm, s0);
      if (now >= sess_timeout_time)
	{
	  nat44_ed_free_session_data (sm, s0, thread_index, 0);
	  nat_ed_session_delete (sm, s0, thread_index, 1);
	  // session is closed, go slow path
	  next[0] = def_slow;
	  goto trace0;
	}

      b0->flags |= VNET_BUFFER_F_IS_NATED;

      if (nat_6t_t_eq (&s0->i2o.match, &lookup))
	{
	  f = &s0->i2o;
	}
      else if (s0->flags & SNAT_SESSION_FLAG_HAIRPINNING &&
	       nat_6t_t_eq (&s0->o2i.match, &lookup))
	{
	  f = &s0->o2i;
	}
      else
	{
	  translation_error = NAT_ED_TRNSL_ERR_FLOW_MISMATCH;
	  nat44_ed_free_session_data (sm, s0, thread_index, 0);
	  nat_ed_session_delete (sm, s0, thread_index, 1);
	  next[0] = NAT_NEXT_DROP;
	  b0->error = node->errors[NAT_IN2OUT_ED_ERROR_TRNSL_FAILED];
	  goto trace0;
	}

      if (NAT_ED_TRNSL_ERR_SUCCESS !=
	  (translation_error = nat_6t_flow_buf_translate_i2o (
	     vm, sm, b0, ip0, f, proto0, is_output_feature)))
	{
	  nat44_ed_free_session_data (sm, s0, thread_index, 0);
	  nat_ed_session_delete (sm, s0, thread_index, 1);
	  next[0] = NAT_NEXT_DROP;
	  b0->error = node->errors[NAT_IN2OUT_ED_ERROR_TRNSL_FAILED];
	  goto trace0;
	}

      switch (proto0)
	{
	case IP_PROTOCOL_TCP:
	  vlib_increment_simple_counter (&sm->counters.fastpath.in2out.tcp,
					 thread_index, cntr_sw_if_index0, 1);
	  nat44_set_tcp_session_state_i2o (
	    sm, now, s0, vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags,
	    thread_index);
	  break;
	case IP_PROTOCOL_UDP:
	  vlib_increment_simple_counter (&sm->counters.fastpath.in2out.udp,
					 thread_index, cntr_sw_if_index0, 1);
	  break;
	case IP_PROTOCOL_ICMP:
	  vlib_increment_simple_counter (&sm->counters.fastpath.in2out.icmp,
					 thread_index, cntr_sw_if_index0, 1);
	  break;
	default:
	  vlib_increment_simple_counter (&sm->counters.fastpath.in2out.other,
					 thread_index, cntr_sw_if_index0, 1);
	  break;
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
	  t->sw_if_index = rx_sw_if_index0;
	  t->next_index = next[0];
	  t->is_slow_path = 0;
	  t->translation_error = translation_error;
	  t->lookup_skipped = lookup_skipped;
	  clib_memcpy (&t->search_key, &kv0, sizeof (t->search_key));

	  if (s0)
	    {
	      t->session_index = s0 - tsm->sessions;
	      clib_memcpy (&t->i2of, &s0->i2o, sizeof (t->i2of));
	      clib_memcpy (&t->o2if, &s0->o2i, sizeof (t->o2if));
	      t->translation_via_i2of = (&s0->i2o == f);
	      t->tcp_state = s0->tcp_state;
	    }
	  else
	    {
	      t->session_index = ~0;
	    }
	  t->l4_layer_truncated =
	    vnet_buffer (b0)->ip.reass.l4_layer_truncated;
	}

      if (next[0] == NAT_NEXT_DROP)
	{
	  vlib_increment_simple_counter (&sm->counters.fastpath.in2out.drops,
					 thread_index, cntr_sw_if_index0, 1);
	}

      n_left_from--;
      next++;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
			       frame->n_vectors);
  return frame->n_vectors;
}

static inline uword
nat44_ed_in2out_slow_path_node_fn_inline (vlib_main_t *vm,
					  vlib_node_runtime_t *node,
					  vlib_frame_t *frame,
					  int is_output_feature,
					  int is_multi_worker)
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
      u32 rx_sw_if_index0, rx_fib_index0, iph_offset0 = 0;
      u32 tx_sw_if_index0;
      u32 cntr_sw_if_index0;
      ip_protocol_t proto0;
      ip4_header_t *ip0;
      udp_header_t *udp0;
      icmp46_header_t *icmp0;
      snat_session_t *s0 = 0;
      clib_bihash_kv_16_8_t kv0, value0;
      int translation_error = NAT_ED_TRNSL_ERR_SUCCESS;

      b0 = *b;

      if (is_output_feature)
	iph_offset0 = vnet_buffer (b0)->ip.reass.save_rewrite_length;

      next[0] = vnet_buffer2 (b0)->nat.arc_next;

      ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0) +
			      iph_offset0);

      rx_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      tx_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
      cntr_sw_if_index0 =
	is_output_feature ? tx_sw_if_index0 : rx_sw_if_index0;
      rx_fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
							   rx_sw_if_index0);

      if (PREDICT_FALSE (!is_output_feature && ip0->ttl == 1))
	{
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next[0] = NAT_NEXT_ICMP_ERROR;
	  goto trace0;
	}

      udp0 = ip4_next_header (ip0);
      icmp0 = (icmp46_header_t *) udp0;
      proto0 = ip0->protocol;

      if (PREDICT_FALSE (nat44_ed_is_unk_proto (proto0)))
	{
	  s0 = nat44_ed_in2out_slowpath_unknown_proto (
	    sm, b0, ip0, rx_fib_index0, thread_index, now, vm, node);
	  if (!s0)
	    next[0] = NAT_NEXT_DROP;

	  if (NAT_NEXT_DROP != next[0] && s0 &&
	      NAT_ED_TRNSL_ERR_SUCCESS !=
		(translation_error = nat_6t_flow_buf_translate_i2o (
		   vm, sm, b0, ip0, &s0->i2o, proto0, is_output_feature)))
	    {
	      nat44_ed_free_session_data (sm, s0, thread_index, 0);
	      nat_ed_session_delete (sm, s0, thread_index, 1);
	      next[0] = NAT_NEXT_DROP;
	      b0->error = node->errors[NAT_IN2OUT_ED_ERROR_TRNSL_FAILED];
	      goto trace0;
	    }

	  vlib_increment_simple_counter (&sm->counters.slowpath.in2out.other,
					 thread_index, cntr_sw_if_index0, 1);
	  goto trace0;
	}

      if (PREDICT_FALSE (vnet_buffer (b0)->ip.reass.l4_layer_truncated))
	{
	  goto skip_lookup;
	}

      if (PREDICT_FALSE (proto0 == IP_PROTOCOL_ICMP))
	{
	  next[0] = icmp_in2out_ed_slow_path (
	    sm, b0, ip0, icmp0, rx_sw_if_index0, tx_sw_if_index0,
	    rx_fib_index0, node, next[0], now, thread_index, &s0,
	    is_multi_worker);
	  if (NAT_NEXT_DROP != next[0] && s0 &&
	      NAT_ED_TRNSL_ERR_SUCCESS !=
		(translation_error = nat_6t_flow_buf_translate_i2o (
		   vm, sm, b0, ip0, &s0->i2o, proto0, is_output_feature)))
	    {
	      nat44_ed_free_session_data (sm, s0, thread_index, 0);
	      nat_ed_session_delete (sm, s0, thread_index, 1);
	      next[0] = NAT_NEXT_DROP;
	      b0->error = node->errors[NAT_IN2OUT_ED_ERROR_TRNSL_FAILED];
	      goto trace0;
	    }

	  vlib_increment_simple_counter (&sm->counters.slowpath.in2out.icmp,
					 thread_index, cntr_sw_if_index0, 1);
	  goto trace0;
	}

      init_ed_k (
	&kv0, ip0->src_address.as_u32, vnet_buffer (b0)->ip.reass.l4_src_port,
	ip0->dst_address.as_u32, vnet_buffer (b0)->ip.reass.l4_dst_port,
	rx_fib_index0, ip0->protocol);
      if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv0, &value0))
	{
	  ASSERT (thread_index == ed_value_get_thread_index (&value0));
	  s0 =
	    pool_elt_at_index (tsm->sessions,
			       ed_value_get_session_index (&value0));
	}

    skip_lookup:
      if (!s0)
	{
	  if (is_output_feature &&
	      !vnet_buffer (b0)->ip.reass.l4_layer_truncated)
	    {
	      if (PREDICT_FALSE (nat44_ed_not_translate_output_feature (
		    sm, b0, ip0, vnet_buffer (b0)->ip.reass.l4_src_port,
		    vnet_buffer (b0)->ip.reass.l4_dst_port, thread_index,
		    rx_sw_if_index0, tx_sw_if_index0, is_multi_worker)))
		goto trace0;

	      /*
	       * Send DHCP packets to the ipv4 stack, or we won't
	       * be able to use dhcp client on the outside interface
	       */
	      if (PREDICT_FALSE (
		    proto0 == IP_PROTOCOL_UDP &&
		    (vnet_buffer (b0)->ip.reass.l4_dst_port ==
		     clib_host_to_net_u16 (UDP_DST_PORT_dhcp_to_server)) &&
		    ip0->dst_address.as_u32 == 0xffffffff))
		goto trace0;
	    }
	  else if (!is_output_feature)
	    {
	      if (PREDICT_FALSE (
		    nat44_ed_not_translate (vm, sm, node, rx_sw_if_index0, b0,
					    ip0, proto0, rx_fib_index0)))
		goto trace0;
	    }

	  next[0] =
	    slow_path_ed (vm, sm, b0, ip0->src_address, ip0->dst_address,
			  vnet_buffer (b0)->ip.reass.l4_src_port,
			  vnet_buffer (b0)->ip.reass.l4_dst_port,
			  ip0->protocol, rx_fib_index0, tx_sw_if_index0, &s0,
			  node, next[0], thread_index, now);

	  if (PREDICT_FALSE (next[0] == NAT_NEXT_DROP))
	    goto trace0;

	  if (PREDICT_FALSE (!s0))
	    goto trace0;

	}

      b0->flags |= VNET_BUFFER_F_IS_NATED;

      if (NAT_ED_TRNSL_ERR_SUCCESS !=
	  (translation_error = nat_6t_flow_buf_translate_i2o (
	     vm, sm, b0, ip0, &s0->i2o, proto0, is_output_feature)))
	{
	  nat44_ed_free_session_data (sm, s0, thread_index, 0);
	  nat_ed_session_delete (sm, s0, thread_index, 1);
	  next[0] = NAT_NEXT_DROP;
	  b0->error = node->errors[NAT_IN2OUT_ED_ERROR_TRNSL_FAILED];
	  goto trace0;
	}

      if (PREDICT_TRUE (proto0 == IP_PROTOCOL_TCP))
	{
	  vlib_increment_simple_counter (&sm->counters.slowpath.in2out.tcp,
					 thread_index, cntr_sw_if_index0, 1);
	  nat44_set_tcp_session_state_i2o (
	    sm, now, s0, vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags,
	    thread_index);
	}
      else
	{
	  vlib_increment_simple_counter (&sm->counters.slowpath.in2out.udp,
					 thread_index, cntr_sw_if_index0, 1);
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
	  t->sw_if_index = rx_sw_if_index0;
	  t->next_index = next[0];
	  t->is_slow_path = 1;
	  t->translation_error = translation_error;
	  clib_memcpy (&t->search_key, &kv0, sizeof (t->search_key));

	  if (s0)
	    {
	      t->session_index = s0 - tsm->sessions;
	      clib_memcpy (&t->i2of, &s0->i2o, sizeof (t->i2of));
	      clib_memcpy (&t->o2if, &s0->o2i, sizeof (t->o2if));
	      t->translation_via_i2of = 1;
	      t->tcp_state = s0->tcp_state;
	    }

	  else
	    {
	      t->session_index = ~0;
	    }
	}

      if (next[0] == NAT_NEXT_DROP)
	{
	  vlib_increment_simple_counter (&sm->counters.slowpath.in2out.drops,
					 thread_index, cntr_sw_if_index0, 1);
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
  if (snat_main.num_workers > 1)
    {
      return nat44_ed_in2out_fast_path_node_fn_inline (vm, node, frame, 0, 1);
    }
  else
    {
      return nat44_ed_in2out_fast_path_node_fn_inline (vm, node, frame, 0, 0);
    }
}

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

VLIB_NODE_FN (nat44_ed_in2out_output_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  if (snat_main.num_workers > 1)
    {
      return nat44_ed_in2out_fast_path_node_fn_inline (vm, node, frame, 1, 1);
    }
  else
    {
      return nat44_ed_in2out_fast_path_node_fn_inline (vm, node, frame, 1, 0);
    }
}

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

VLIB_NODE_FN (nat44_ed_in2out_slowpath_node) (vlib_main_t * vm,
					      vlib_node_runtime_t *
					      node, vlib_frame_t * frame)
{
  if (snat_main.num_workers > 1)
    {
      return nat44_ed_in2out_slow_path_node_fn_inline (vm, node, frame, 0, 1);
    }
  else
    {
      return nat44_ed_in2out_slow_path_node_fn_inline (vm, node, frame, 0, 0);
    }
}

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

VLIB_NODE_FN (nat44_ed_in2out_output_slowpath_node) (vlib_main_t * vm,
						     vlib_node_runtime_t
						     * node,
						     vlib_frame_t * frame)
{
  if (snat_main.num_workers > 1)
    {
      return nat44_ed_in2out_slow_path_node_fn_inline (vm, node, frame, 1, 1);
    }
  else
    {
      return nat44_ed_in2out_slow_path_node_fn_inline (vm, node, frame, 1, 0);
    }
}

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
