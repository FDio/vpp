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
 * @brief NAT44 endpoint-dependent outside to inside network translation
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/udp/udp_local.h>
#include <vppinfra/error.h>

#include <nat/lib/ipfix_logging.h>

#include <nat/nat44-ed/nat44_ed.h>
#include <nat/nat44-ed/nat44_ed_inlines.h>

static char *nat_out2in_ed_error_strings[] = {
#define _(sym,string) string,
  foreach_nat_out2in_ed_error
#undef _
};

typedef enum
{
  NAT_ED_SP_REASON_NO_REASON,
  NAT_ED_SP_REASON_LOOKUP_FAILED,
  NAT_ED_SP_REASON_VRF_EXPIRED,
  NAT_ED_SP_SESS_EXPIRED,
} nat_slow_path_reason_e;

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
  nat_slow_path_reason_e slow_path_reason;
} nat44_ed_out2in_trace_t;

static u8 *
format_slow_path_reason (u8 *s, va_list *args)
{
  nat_slow_path_reason_e reason = va_arg (*args, nat_slow_path_reason_e);
  switch (reason)
    {
    case NAT_ED_SP_REASON_NO_REASON:
      return format (s, "no reason for slow path");
    case NAT_ED_SP_REASON_LOOKUP_FAILED:
      return format (s, "slow path because lookup failed");
    case NAT_ED_SP_REASON_VRF_EXPIRED:
      return format (s, "slow path because vrf expired");
    case NAT_ED_SP_SESS_EXPIRED:
      return format (s, "slow path because session expired");
    }
  return format (s, "invalid reason value");
}

static u8 *
format_nat44_ed_out2in_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat44_ed_out2in_trace_t *t = va_arg (*args, nat44_ed_out2in_trace_t *);
  char *tag;

  tag =
    t->is_slow_path ? "NAT44_OUT2IN_ED_SLOW_PATH" :
    "NAT44_OUT2IN_ED_FAST_PATH";

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
      else
	{
	  s = format (s, "\n  search key %U", format_ed_session_kvp,
		      &t->search_key);
	}
      s = format (s, "\n  %U", format_slow_path_reason, t->slow_path_reason);
    }
  if (IP_PROTOCOL_TCP == t->i2of.match.proto)
    {
      s = format (s, "\n  TCP state: %U", format_nat44_ed_tcp_state,
		  t->tcp_state);
    }

  return s;
}

static int
next_src_nat (snat_main_t *sm, ip4_header_t *ip, u16 src_port, u16 dst_port,
	      u32 rx_fib_index)
{
  clib_bihash_kv_16_8_t kv, value;

  init_ed_k (&kv, ip->src_address.as_u32, src_port, ip->dst_address.as_u32,
	     dst_port, rx_fib_index, ip->protocol);
  if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv, &value))
    return 1;

  return 0;
}

static void create_bypass_for_fwd (snat_main_t *sm, vlib_buffer_t *b,
				   snat_session_t *s, ip4_header_t *ip,
				   u32 rx_fib_index, u32 thread_index);

static snat_session_t *create_session_for_static_mapping_ed (
  snat_main_t *sm, vlib_buffer_t *b, ip4_address_t i2o_addr, u16 i2o_port,
  u32 i2o_fib_index, ip4_address_t o2i_addr, u16 o2i_port, u32 o2i_fib_index,
  ip_protocol_t proto, vlib_node_runtime_t *node, u32 thread_index,
  twice_nat_type_t twice_nat, lb_nat_type_t lb_nat, f64 now,
  snat_static_mapping_t *mapping);

static inline u32
icmp_out2in_ed_slow_path (snat_main_t *sm, vlib_buffer_t *b, ip4_header_t *ip,
			  icmp46_header_t *icmp, u32 sw_if_index,
			  u32 rx_fib_index, vlib_node_runtime_t *node,
			  u32 next, f64 now, u32 thread_index,
			  snat_session_t **s_p)
{
  vlib_main_t *vm = vlib_get_main ();

  ip_csum_t sum;
  u16 checksum;

  snat_session_t *s = 0;
  u8 is_addr_only, identity_nat;
  ip4_address_t sm_addr;
  u16 sm_port;
  u32 sm_fib_index;
  snat_static_mapping_t *m;
  u8 lookup_protocol;
  ip4_address_t lookup_saddr, lookup_daddr;
  u16 lookup_sport, lookup_dport;

  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  rx_fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  if (nat_get_icmp_session_lookup_values (b, ip, &lookup_saddr, &lookup_sport,
					  &lookup_daddr, &lookup_dport,
					  &lookup_protocol))
    {
      b->error = node->errors[NAT_OUT2IN_ED_ERROR_UNSUPPORTED_PROTOCOL];
      next = NAT_NEXT_DROP;
      goto out;
    }

  if (snat_static_mapping_match (vm, sm, ip->dst_address, lookup_sport,
				 rx_fib_index, ip->protocol, &sm_addr,
				 &sm_port, &sm_fib_index, 1, &is_addr_only, 0,
				 0, 0, &identity_nat, &m))
    {
      // static mapping not matched
      if (!sm->forwarding_enabled)
	{
	  /* Don't NAT packet aimed at the intfc address */
	  if (!is_interface_addr (sm, node, sw_if_index,
				  ip->dst_address.as_u32))
	    {
	      b->error = node->errors[NAT_OUT2IN_ED_ERROR_NO_TRANSLATION];
	      next = NAT_NEXT_DROP;
	    }
	}
      else
	{
	  if (next_src_nat (sm, ip, lookup_sport, lookup_dport, rx_fib_index))
	    {
	      next = NAT_NEXT_IN2OUT_ED_FAST_PATH;
	    }
	  else
	    {
	      create_bypass_for_fwd (sm, b, s, ip, rx_fib_index, thread_index);
	    }
	}
      goto out;
    }

  if (PREDICT_FALSE (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags !=
		       ICMP4_echo_reply &&
		     (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags !=
			ICMP4_echo_request ||
		      !is_addr_only)))
    {
      b->error = node->errors[NAT_OUT2IN_ED_ERROR_BAD_ICMP_TYPE];
      next = NAT_NEXT_DROP;
      goto out;
    }

  if (PREDICT_FALSE (identity_nat))
    {
      goto out;
    }

  /* Create session initiated by host from external network */
  s = create_session_for_static_mapping_ed (
    sm, b, sm_addr, sm_port, sm_fib_index, ip->dst_address, lookup_sport,
    rx_fib_index, lookup_protocol, node, thread_index, 0, 0,
    vlib_time_now (vm), m);
  if (!s)
    next = NAT_NEXT_DROP;

  if (PREDICT_TRUE (!ip4_is_fragment (ip)))
    {
      sum = ip_incremental_checksum_buffer (
	vm, b, (u8 *) icmp - (u8 *) vlib_buffer_get_current (b),
	ntohs (ip->length) - ip4_header_bytes (ip), 0);
      checksum = ~ip_csum_fold (sum);
      if (checksum != 0 && checksum != 0xffff)
	{
	  next = NAT_NEXT_DROP;
	  goto out;
	}
    }

  if (PREDICT_TRUE (next != NAT_NEXT_DROP && s))
    {
      /* Accounting */
      nat44_session_update_counters (
	s, now, vlib_buffer_length_in_chain (vm, b), thread_index);
      /* Per-user LRU list maintenance */
      nat44_session_update_lru (sm, s, thread_index);
    }
out:
  if (NAT_NEXT_DROP == next && s)
    {
      nat_ed_session_delete (sm, s, thread_index, 1);
      s = 0;
    }
  *s_p = s;
  return next;
}

static_always_inline int
nat44_ed_alloc_i2o_port (snat_main_t *sm, snat_address_t *a, snat_session_t *s,
			 ip4_address_t i2o_addr, u16 i2o_port,
			 u32 i2o_fib_index, ip_protocol_t proto,
			 u32 thread_index, u32 snat_thread_index,
			 ip4_address_t *outside_addr, u16 *outside_port)
{
  u32 portnum;

  for (int i = 0; i < ED_PORT_ALLOC_ATTEMPTS; ++i)
    {
      portnum = (sm->port_per_thread * snat_thread_index) +
		snat_random_port (0, sm->port_per_thread - 1) + 1024;
      portnum = clib_host_to_net_u16 (portnum);
      nat_6t_i2o_flow_init (sm, thread_index, s, i2o_addr, i2o_port, a->addr,
			    portnum, i2o_fib_index, proto);
      if (!nat_ed_ses_i2o_flow_hash_add_del (sm, thread_index, s,
					     1 /* is_add */))
	{
	  *outside_addr = a->addr;
	  *outside_port = portnum;
	  return 0;
	}
    }

  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

static_always_inline int
nat44_ed_alloc_i2o_addr_and_port (snat_main_t *sm, snat_address_t *addresses,
				  snat_session_t *s, ip4_address_t i2o_addr,
				  u16 i2o_port, u32 i2o_fib_index,
				  ip_protocol_t proto, u32 thread_index,
				  u32 snat_thread_index,
				  ip4_address_t *outside_addr,
				  u16 *outside_port)
{
  snat_address_t *a, *ga = 0;
  int i;

  if (vec_len (addresses) > 0)
    {
      int s_addr_offset = i2o_addr.as_u32 % vec_len (addresses);

      for (i = s_addr_offset; i < vec_len (addresses); ++i)
	{
	  a = addresses + i;
	  if (a->fib_index == i2o_fib_index)
	    {
	      return nat44_ed_alloc_i2o_port (
		sm, a, s, i2o_addr, i2o_port, i2o_fib_index, proto,
		thread_index, snat_thread_index, outside_addr, outside_port);
	    }
	  else if (a->fib_index == ~0)
	    {
	      ga = a;
	    }
	}

      for (i = 0; i < s_addr_offset; ++i)
	{
	  a = addresses + i;
	  if (a->fib_index == i2o_fib_index)
	    {
	      return nat44_ed_alloc_i2o_port (
		sm, a, s, i2o_addr, i2o_port, i2o_fib_index, proto,
		thread_index, snat_thread_index, outside_addr, outside_port);
	    }
	  else if (a->fib_index == ~0)
	    {
	      ga = a;
	    }
	}

      if (ga)
	{
	  return nat44_ed_alloc_i2o_port (
	    sm, a, s, i2o_addr, i2o_port, i2o_fib_index, proto, thread_index,
	    snat_thread_index, outside_addr, outside_port);
	}
    }

  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

static snat_session_t *
create_session_for_static_mapping_ed (
  snat_main_t *sm, vlib_buffer_t *b, ip4_address_t i2o_addr, u16 i2o_port,
  u32 i2o_fib_index, ip4_address_t o2i_addr, u16 o2i_port, u32 o2i_fib_index,
  ip_protocol_t proto, vlib_node_runtime_t *node, u32 thread_index,
  twice_nat_type_t twice_nat, lb_nat_type_t lb_nat, f64 now,
  snat_static_mapping_t *mapping)
{
  snat_session_t *s;
  ip4_header_t *ip;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  if (PREDICT_FALSE (
	nat44_ed_maximum_sessions_exceeded (sm, o2i_fib_index, thread_index)))
    {
      b->error = node->errors[NAT_OUT2IN_ED_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_elog_notice (sm, "maximum sessions exceeded");
      return 0;
    }

  s = nat_ed_session_alloc (sm, thread_index, now, proto);
  if (!s)
    {
      b->error = node->errors[NAT_OUT2IN_ED_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_elog_warn (sm, "create NAT session failed");
      return 0;
    }

  ip = vlib_buffer_get_current (b);

  s->ext_host_addr.as_u32 = ip->src_address.as_u32;
  s->ext_host_port =
    proto == IP_PROTOCOL_ICMP ? 0 : vnet_buffer (b)->ip.reass.l4_src_port;
  s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
  if (lb_nat)
    s->flags |= SNAT_SESSION_FLAG_LOAD_BALANCING;
  if (lb_nat == AFFINITY_LB_NAT)
    s->flags |= SNAT_SESSION_FLAG_AFFINITY;
  s->out2in.addr = o2i_addr;
  s->out2in.port = o2i_port;
  s->out2in.fib_index = o2i_fib_index;
  s->in2out.addr = i2o_addr;
  s->in2out.port = i2o_port;
  s->in2out.fib_index = i2o_fib_index;
  s->proto = proto;

  if (IP_PROTOCOL_ICMP == proto)
    {
      nat_6t_o2i_flow_init (sm, thread_index, s, s->ext_host_addr, o2i_port,
			    o2i_addr, o2i_port, o2i_fib_index, ip->protocol);
      nat_6t_flow_icmp_id_rewrite_set (&s->o2i, i2o_port);
    }
  else
    {
      nat_6t_o2i_flow_init (sm, thread_index, s, s->ext_host_addr,
			    s->ext_host_port, o2i_addr, o2i_port,
			    o2i_fib_index, ip->protocol);
      nat_6t_flow_dport_rewrite_set (&s->o2i, i2o_port);
    }
  nat_6t_flow_daddr_rewrite_set (&s->o2i, i2o_addr.as_u32);
  nat_6t_flow_txfib_rewrite_set (&s->o2i, i2o_fib_index);

  if (nat_ed_ses_o2i_flow_hash_add_del (sm, thread_index, s, 1))
    {
      b->error = node->errors[NAT_OUT2IN_ED_ERROR_HASH_ADD_FAILED];
      nat_ed_session_delete (sm, s, thread_index, 1);
      nat_elog_warn (sm, "out2in flow hash add failed");
      return 0;
    }

  if (twice_nat == TWICE_NAT || (twice_nat == TWICE_NAT_SELF &&
				 ip->src_address.as_u32 == i2o_addr.as_u32))
    {
      int rc = 0;
      snat_address_t *filter = 0;

      // if exact address is specified use this address
      if (is_sm_exact_address (mapping->flags))
	{
	  snat_address_t *ap;
	  vec_foreach (ap, sm->twice_nat_addresses)
	  {
	    if (mapping->pool_addr.as_u32 == ap->addr.as_u32)
	      {
		filter = ap;
		break;
	      }
	  }
	}

      if (filter)
	{
	  rc = nat44_ed_alloc_i2o_port (
	    sm, filter, s, i2o_addr, i2o_port, i2o_fib_index, proto,
	    thread_index, tsm->snat_thread_index, &s->ext_host_nat_addr,
	    &s->ext_host_nat_port);
	  s->flags |= SNAT_SESSION_FLAG_EXACT_ADDRESS;
	}
      else
	{
	  rc = nat44_ed_alloc_i2o_addr_and_port (
	    sm, sm->twice_nat_addresses, s, i2o_addr, i2o_port, i2o_fib_index,
	    proto, thread_index, tsm->snat_thread_index, &s->ext_host_nat_addr,
	    &s->ext_host_nat_port);
	}

      if (rc)
	{
	  b->error = node->errors[NAT_OUT2IN_ED_ERROR_OUT_OF_PORTS];
	  nat_ed_session_delete (sm, s, thread_index, 1);
	  return 0;
	}

      s->flags |= SNAT_SESSION_FLAG_TWICE_NAT;

      nat_6t_flow_saddr_rewrite_set (&s->o2i, s->ext_host_nat_addr.as_u32);
      if (IP_PROTOCOL_ICMP == proto)
	{
	  nat_6t_flow_icmp_id_rewrite_set (&s->o2i, s->ext_host_nat_port);
	}
      else
	{
	  nat_6t_flow_sport_rewrite_set (&s->o2i, s->ext_host_nat_port);
	}

      nat_6t_l3_l4_csum_calc (&s->o2i);

      nat_6t_flow_daddr_rewrite_set (&s->i2o, s->ext_host_addr.as_u32);
      if (IP_PROTOCOL_ICMP == proto)
	{
	  nat_6t_flow_icmp_id_rewrite_set (&s->i2o, s->ext_host_port);
	}
      else
	{
	  nat_6t_flow_dport_rewrite_set (&s->i2o, s->ext_host_port);
	}

      nat_6t_flow_saddr_rewrite_set (&s->i2o, o2i_addr.as_u32);
      if (IP_PROTOCOL_ICMP == proto)
	{
	  nat_6t_flow_icmp_id_rewrite_set (&s->i2o, o2i_port);
	}
      else
	{
	  nat_6t_flow_sport_rewrite_set (&s->i2o, o2i_port);
	}
      nat_6t_l3_l4_csum_calc (&s->i2o);
    }
  else
    {
      if (IP_PROTOCOL_ICMP == proto)
	{
	  nat_6t_i2o_flow_init (sm, thread_index, s, i2o_addr, i2o_port,
				s->ext_host_addr, i2o_port, i2o_fib_index,
				ip->protocol);
	}
      else
	{
	  nat_6t_i2o_flow_init (sm, thread_index, s, i2o_addr, i2o_port,
				s->ext_host_addr, s->ext_host_port,
				i2o_fib_index, ip->protocol);
	}

  nat_6t_flow_saddr_rewrite_set (&s->i2o, o2i_addr.as_u32);
  if (IP_PROTOCOL_ICMP == proto)
    {
      nat_6t_flow_icmp_id_rewrite_set (&s->i2o, o2i_port);
    }
  else
    {
      nat_6t_flow_sport_rewrite_set (&s->i2o, o2i_port);
    }

  if (nat_ed_ses_i2o_flow_hash_add_del (sm, thread_index, s, 1))
    {
      nat_elog_notice (sm, "in2out flow hash add failed");
      if (nat_ed_ses_o2i_flow_hash_add_del (sm, thread_index, s, 0))
	{
	  nat_elog_warn (sm, "out2in flow hash del failed");
	}
      nat_ed_session_delete (sm, s, thread_index, 1);
      return 0;
    }
    }
  nat_ipfix_logging_nat44_ses_create (
    thread_index, s->in2out.addr.as_u32, s->out2in.addr.as_u32, s->proto,
    s->in2out.port, s->out2in.port, s->in2out.fib_index);

  nat_syslog_nat44_sadd (0, s->in2out.fib_index, &s->in2out.addr,
			 s->in2out.port, &s->ext_host_nat_addr,
			 s->ext_host_nat_port, &s->out2in.addr, s->out2in.port,
			 &s->ext_host_addr, s->ext_host_port, s->proto,
			 nat44_ed_is_twice_nat_session (s));

  per_vrf_sessions_register_session (s, thread_index);

  return s;
}

static void
create_bypass_for_fwd (snat_main_t *sm, vlib_buffer_t *b, snat_session_t *s,
		       ip4_header_t *ip, u32 rx_fib_index, u32 thread_index)
{
  clib_bihash_kv_16_8_t kv, value;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);
  u16 lookup_sport, lookup_dport;
  u8 lookup_protocol;
  ip4_address_t lookup_saddr, lookup_daddr;

  if (ip->protocol == IP_PROTOCOL_ICMP)
    {
      if (nat_get_icmp_session_lookup_values (b, ip, &lookup_daddr,
					      &lookup_sport, &lookup_saddr,
					      &lookup_dport, &lookup_protocol))
	return;
    }
  else
    {
      if (ip->protocol == IP_PROTOCOL_UDP || ip->protocol == IP_PROTOCOL_TCP)
	{
	  lookup_sport = vnet_buffer (b)->ip.reass.l4_dst_port;
	  lookup_dport = vnet_buffer (b)->ip.reass.l4_src_port;
	}
      else
	{
	  lookup_sport = 0;
	  lookup_dport = 0;
	}
      lookup_saddr.as_u32 = ip->dst_address.as_u32;
      lookup_daddr.as_u32 = ip->src_address.as_u32;
      lookup_protocol = ip->protocol;
    }

  init_ed_k (&kv, lookup_saddr.as_u32, lookup_sport, lookup_daddr.as_u32,
	     lookup_dport, rx_fib_index, lookup_protocol);

  if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv, &value))
    {
      ASSERT (thread_index == ed_value_get_thread_index (&value));
      s =
	pool_elt_at_index (tsm->sessions,
			   ed_value_get_session_index (&value));
    }
  else if (ip->protocol == IP_PROTOCOL_ICMP &&
	   icmp_type_is_error_message
	   (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags))
    {
      return;
    }
  else
    {
      if (PREDICT_FALSE
	  (nat44_ed_maximum_sessions_exceeded
	   (sm, rx_fib_index, thread_index)))
	return;

      s = nat_ed_session_alloc (sm, thread_index, now, ip->protocol);
      if (!s)
	{
	  nat_elog_warn (sm, "create NAT session failed");
	  return;
	}

      s->ext_host_addr = ip->src_address;
      s->ext_host_port = lookup_dport;
      s->flags |= SNAT_SESSION_FLAG_FWD_BYPASS;
      s->out2in.addr = ip->dst_address;
      s->out2in.port = lookup_sport;
      s->proto = ip->protocol;
      s->out2in.fib_index = rx_fib_index;
      s->in2out.addr = s->out2in.addr;
      s->in2out.port = s->out2in.port;
      s->in2out.fib_index = s->out2in.fib_index;

      nat_6t_i2o_flow_init (sm, thread_index, s, ip->dst_address, lookup_sport,
			    ip->src_address, lookup_dport, rx_fib_index,
			    ip->protocol);
      nat_6t_flow_txfib_rewrite_set (&s->i2o, rx_fib_index);
      if (nat_ed_ses_i2o_flow_hash_add_del (sm, thread_index, s, 1))
	{
	  nat_elog_notice (sm, "in2out flow add failed");
	  nat_ed_session_delete (sm, s, thread_index, 1);
	  return;
	}

      per_vrf_sessions_register_session (s, thread_index);
    }

  if (ip->protocol == IP_PROTOCOL_TCP)
    {
      nat44_set_tcp_session_state_o2i (
	sm, now, s, vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags,
	thread_index);
    }

  /* Accounting */
  nat44_session_update_counters (s, now, 0, thread_index);
  /* Per-user LRU list maintenance */
  nat44_session_update_lru (sm, s, thread_index);
}

static snat_session_t *
nat44_ed_out2in_slowpath_unknown_proto (snat_main_t *sm, vlib_buffer_t *b,
					ip4_header_t *ip, u32 rx_fib_index,
					u32 thread_index, f64 now,
					vlib_main_t *vm,
					vlib_node_runtime_t *node)
{
  snat_static_mapping_t *m;
  snat_session_t *s;

  if (PREDICT_FALSE (
	nat44_ed_maximum_sessions_exceeded (sm, rx_fib_index, thread_index)))
    {
      b->error = node->errors[NAT_OUT2IN_ED_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_elog_notice (sm, "maximum sessions exceeded");
      return 0;
    }

  m = nat44_ed_sm_o2i_lookup (sm, ip->dst_address, 0, 0, ip->protocol);
  if (!m)
    {
      b->error = node->errors[NAT_OUT2IN_ED_ERROR_NO_TRANSLATION];
      return 0;
    }

  /* Create a new session */
  s = nat_ed_session_alloc (sm, thread_index, now, ip->protocol);
  if (!s)
    {
      b->error = node->errors[NAT_OUT2IN_ED_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_elog_warn (sm, "create NAT session failed");
      return 0;
    }

  s->ext_host_addr.as_u32 = ip->src_address.as_u32;
  s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
  s->out2in.addr.as_u32 = ip->dst_address.as_u32;
  s->out2in.fib_index = rx_fib_index;
  s->in2out.addr.as_u32 = m->local_addr.as_u32;
  s->in2out.fib_index = m->fib_index;
  s->in2out.port = s->out2in.port = ip->protocol;

  nat_6t_o2i_flow_init (sm, thread_index, s, ip->dst_address, 0,
			ip->src_address, 0, m->fib_index, ip->protocol);
  nat_6t_flow_saddr_rewrite_set (&s->i2o, ip->dst_address.as_u32);
  if (nat_ed_ses_i2o_flow_hash_add_del (sm, thread_index, s, 1))
    {
      nat_elog_notice (sm, "in2out key add failed");
      nat_ed_session_delete (sm, s, thread_index, 1);
      return NULL;
    }

  nat_6t_o2i_flow_init (sm, thread_index, s, ip->src_address, 0,
			ip->dst_address, 0, rx_fib_index, ip->protocol);
  nat_6t_flow_daddr_rewrite_set (&s->o2i, m->local_addr.as_u32);
  nat_6t_flow_txfib_rewrite_set (&s->o2i, m->fib_index);
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
nat44_ed_out2in_fast_path_node_fn_inline (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame,
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
      u32 sw_if_index0, rx_fib_index0;
      ip_protocol_t proto0;
      ip4_header_t *ip0;
      snat_session_t *s0 = 0;
      clib_bihash_kv_16_8_t kv0, value0;
      nat_translation_error_e translation_error = NAT_ED_TRNSL_ERR_SUCCESS;
      nat_slow_path_reason_e slow_path_reason = NAT_ED_SP_REASON_NO_REASON;
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

      next[0] = vnet_buffer2 (b0)->nat.arc_next;

      lookup.sport = vnet_buffer (b0)->ip.reass.l4_src_port;
      lookup.dport = vnet_buffer (b0)->ip.reass.l4_dst_port;

      vnet_buffer (b0)->snat.flags = 0;
      ip0 = vlib_buffer_get_current (b0);

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      rx_fib_index0 =
	fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index0);

      lookup.fib_index = rx_fib_index0;

      if (PREDICT_FALSE (ip0->ttl == 1))
	{
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
				       ICMP4_time_exceeded_ttl_exceeded_in_transit,
				       0);
	  next[0] = NAT_NEXT_ICMP_ERROR;
	  goto trace0;
	}

      proto0 = ip0->protocol;

      if (PREDICT_FALSE (proto0 == IP_PROTOCOL_ICMP))
	{
	  if (vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
		ICMP4_echo_request &&
	      vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags !=
		ICMP4_echo_reply &&
	      !icmp_type_is_error_message (
		vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags))
	    {
	      b0->error = node->errors[NAT_OUT2IN_ED_ERROR_BAD_ICMP_TYPE];
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
	  lookup.saddr.as_u32 = ip0->src_address.as_u32;
	  lookup.daddr.as_u32 = ip0->dst_address.as_u32;
	  lookup.proto = ip0->protocol;
	}

      /* there might be a stashed index in vnet_buffer2 from handoff or
       * classify node, see if it can be used */
      if (is_multi_worker &&
	  !pool_is_free_index (tsm->sessions,
			       vnet_buffer2 (b0)->nat.cached_session_index))
	{
	  s0 = pool_elt_at_index (tsm->sessions,
				  vnet_buffer2 (b0)->nat.cached_session_index);
	  if (PREDICT_TRUE (nat_6t_t_eq (&s0->o2i.match, &lookup)) ||
	      (s0->flags & SNAT_SESSION_FLAG_TWICE_NAT &&
	       nat_6t_t_eq (&s0->i2o.match, &lookup)))
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
	  slow_path_reason = NAT_ED_SP_REASON_LOOKUP_FAILED;
	  next[0] = NAT_NEXT_OUT2IN_ED_SLOW_PATH;
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
	  slow_path_reason = NAT_ED_SP_REASON_VRF_EXPIRED;
	  next[0] = NAT_NEXT_OUT2IN_ED_SLOW_PATH;
	  goto trace0;
	}

      // drop if session expired
      u64 sess_timeout_time;
      sess_timeout_time =
	s0->last_heard + (f64) nat44_session_get_timeout (sm, s0);
      if (now >= sess_timeout_time)
	{
	  // session is closed, go slow path
	  nat44_ed_free_session_data (sm, s0, thread_index, 0);
	  nat_ed_session_delete (sm, s0, thread_index, 1);
	  slow_path_reason = NAT_ED_SP_SESS_EXPIRED;
	  next[0] = NAT_NEXT_OUT2IN_ED_SLOW_PATH;
	  goto trace0;
	}

      if (nat_6t_t_eq (&s0->o2i.match, &lookup))
	{
	  f = &s0->o2i;
	}
      else if (s0->flags & SNAT_SESSION_FLAG_TWICE_NAT &&
	       nat_6t_t_eq (&s0->i2o.match, &lookup))
	{
	  f = &s0->i2o;
	}
      else
	{
	  /*
	   * Send DHCP packets to the ipv4 stack, or we won't
	   * be able to use dhcp client on the outside interface
	   */
	  if (PREDICT_FALSE (
		proto0 == IP_PROTOCOL_UDP &&
		(vnet_buffer (b0)->ip.reass.l4_dst_port ==
		 clib_host_to_net_u16 (UDP_DST_PORT_dhcp_to_client))))
	    {
	      goto trace0;
	    }

	  if (!sm->forwarding_enabled)
	    {
	      b0->error = node->errors[NAT_OUT2IN_ED_ERROR_NO_TRANSLATION];
	      next[0] = NAT_NEXT_DROP;
	      goto trace0;
	    }
	  else
	    {
	      if (nat_6t_t_eq (&s0->i2o.match, &lookup))
		{
		  f = &s0->i2o;
		}
	      else
		{
		  // FIXME TODO bypass ???
		  //  create_bypass_for_fwd (sm, b0, s0, ip0, rx_fib_index0,
		  //                       thread_index);
		  translation_error = NAT_ED_TRNSL_ERR_FLOW_MISMATCH;
		  nat44_ed_free_session_data (sm, s0, thread_index, 0);
		  nat_ed_session_delete (sm, s0, thread_index, 1);
		  next[0] = NAT_NEXT_DROP;
		  b0->error = node->errors[NAT_OUT2IN_ED_ERROR_TRNSL_FAILED];
		  goto trace0;
		}
	    }
	}

      if (NAT_ED_TRNSL_ERR_SUCCESS !=
	  (translation_error = nat_6t_flow_buf_translate_o2i (
	     vm, sm, b0, ip0, f, proto0, 0 /* is_output_feature */)))
	{
	  next[0] = NAT_NEXT_DROP;
	  b0->error = node->errors[NAT_OUT2IN_ED_ERROR_TRNSL_FAILED];
	  goto trace0;
	}

      switch (proto0)
	{
	case IP_PROTOCOL_TCP:
	  vlib_increment_simple_counter (&sm->counters.fastpath.out2in.tcp,
					 thread_index, sw_if_index0, 1);
	  nat44_set_tcp_session_state_o2i (sm, now, s0,
					   vnet_buffer (b0)->ip.
					   reass.icmp_type_or_tcp_flags,
					   thread_index);
	  break;
	case IP_PROTOCOL_UDP:
	  vlib_increment_simple_counter (&sm->counters.fastpath.out2in.udp,
					 thread_index, sw_if_index0, 1);
	  break;
	case IP_PROTOCOL_ICMP:
	  vlib_increment_simple_counter (&sm->counters.fastpath.out2in.icmp,
					 thread_index, sw_if_index0, 1);
	  break;
	default:
	  vlib_increment_simple_counter (&sm->counters.fastpath.out2in.other,
					 thread_index, sw_if_index0, 1);
	  break;
	}

      /* Accounting */
      nat44_session_update_counters (s0, now,
				     vlib_buffer_length_in_chain (vm, b0),
				     thread_index);
      /* Per-user LRU list maintenance */
      nat44_session_update_lru (sm, s0, thread_index);

    trace0:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat44_ed_out2in_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->next_index = next[0];
	  t->is_slow_path = 0;
	  t->translation_error = translation_error;
	  clib_memcpy (&t->search_key, &kv0, sizeof (t->search_key));
	  t->lookup_skipped = lookup_skipped;
	  t->slow_path_reason = slow_path_reason;

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
	}

      if (next[0] == NAT_NEXT_DROP)
	{
	  vlib_increment_simple_counter (&sm->counters.fastpath.out2in.drops,
					 thread_index, sw_if_index0, 1);
	}

      n_left_from--;
      next++;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
			       frame->n_vectors);
  return frame->n_vectors;
}

static inline uword
nat44_ed_out2in_slow_path_node_fn_inline (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  u32 n_left_from, *from;
  snat_main_t *sm = &snat_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  snat_static_mapping_t *m;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  vlib_get_buffers (vm, from, b, n_left_from);

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0;
      u32 sw_if_index0, rx_fib_index0;
      ip_protocol_t proto0;
      ip4_header_t *ip0;
      udp_header_t *udp0;
      icmp46_header_t *icmp0;
      snat_session_t *s0 = 0;
      clib_bihash_kv_16_8_t kv0, value0;
      lb_nat_type_t lb_nat0;
      twice_nat_type_t twice_nat0;
      u8 identity_nat0;
      ip4_address_t sm_addr;
      u16 sm_port;
      u32 sm_fib_index;
      nat_translation_error_e translation_error = NAT_ED_TRNSL_ERR_SUCCESS;

      b0 = *b;
      next[0] = vnet_buffer2 (b0)->nat.arc_next;

      vnet_buffer (b0)->snat.flags = 0;
      ip0 = vlib_buffer_get_current (b0);

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
      icmp0 = (icmp46_header_t *) udp0;
      proto0 = ip0->protocol;

      if (PREDICT_FALSE (nat44_ed_is_unk_proto (proto0)))
	{
	  s0 = nat44_ed_out2in_slowpath_unknown_proto (
	    sm, b0, ip0, rx_fib_index0, thread_index, now, vm, node);
	  if (!sm->forwarding_enabled)
	    {
	      if (!s0)
		next[0] = NAT_NEXT_DROP;
	    }
	  if (NAT_NEXT_DROP != next[0] && s0 &&
	      NAT_ED_TRNSL_ERR_SUCCESS !=
		(translation_error = nat_6t_flow_buf_translate_o2i (
		   vm, sm, b0, ip0, &s0->o2i, proto0,
		   0 /* is_output_feature */)))
	    {
	      next[0] = NAT_NEXT_DROP;
	      b0->error = node->errors[NAT_OUT2IN_ED_ERROR_TRNSL_FAILED];
	      goto trace0;
	    }

	  vlib_increment_simple_counter (&sm->counters.slowpath.out2in.other,
					 thread_index, sw_if_index0, 1);
	  goto trace0;
	}

      if (PREDICT_FALSE (proto0 == IP_PROTOCOL_ICMP))
	{
	  next[0] = icmp_out2in_ed_slow_path
	    (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
	     next[0], now, thread_index, &s0);

	  if (NAT_NEXT_DROP != next[0] && s0 &&
	      NAT_ED_TRNSL_ERR_SUCCESS !=
		(translation_error = nat_6t_flow_buf_translate_o2i (
		   vm, sm, b0, ip0, &s0->o2i, proto0,
		   0 /* is_output_feature */)))
	    {
	      next[0] = NAT_NEXT_DROP;
	      b0->error = node->errors[NAT_OUT2IN_ED_ERROR_TRNSL_FAILED];
	      goto trace0;
	    }

	  vlib_increment_simple_counter (&sm->counters.slowpath.out2in.icmp,
					 thread_index, sw_if_index0, 1);
	  goto trace0;
	}

      init_ed_k (
	&kv0, ip0->src_address.as_u32, vnet_buffer (b0)->ip.reass.l4_src_port,
	ip0->dst_address.as_u32, vnet_buffer (b0)->ip.reass.l4_dst_port,
	rx_fib_index0, ip0->protocol);

      s0 = NULL;
      if (!clib_bihash_search_16_8 (&sm->flow_hash, &kv0, &value0))
	{
	  ASSERT (thread_index == ed_value_get_thread_index (&value0));
	  s0 =
	    pool_elt_at_index (tsm->sessions,
			       ed_value_get_session_index (&value0));
	}

      if (!s0)
	{
	  /* Try to match static mapping by external address and port,
	     destination address and port in packet */

	  if (snat_static_mapping_match (
		vm, sm, ip0->dst_address,
		vnet_buffer (b0)->ip.reass.l4_dst_port, rx_fib_index0, proto0,
		&sm_addr, &sm_port, &sm_fib_index, 1, 0, &twice_nat0, &lb_nat0,
		&ip0->src_address, &identity_nat0, &m))
	    {
	      /*
	       * Send DHCP packets to the ipv4 stack, or we won't
	       * be able to use dhcp client on the outside interface
	       */
	      if (PREDICT_FALSE (
		    proto0 == IP_PROTOCOL_UDP &&
		    (vnet_buffer (b0)->ip.reass.l4_dst_port ==
		     clib_host_to_net_u16 (UDP_DST_PORT_dhcp_to_client))))
		{
		  goto trace0;
		}

	      if (!sm->forwarding_enabled)
		{
		  b0->error =
		    node->errors[NAT_OUT2IN_ED_ERROR_NO_TRANSLATION];
		  next[0] = NAT_NEXT_DROP;
		}
	      else
		{
		  if (next_src_nat (
			sm, ip0, vnet_buffer (b0)->ip.reass.l4_src_port,
			vnet_buffer (b0)->ip.reass.l4_dst_port, rx_fib_index0))
		    {
		      next[0] = NAT_NEXT_IN2OUT_ED_FAST_PATH;
		    }
		  else
		    {
		      create_bypass_for_fwd (sm, b0, s0, ip0, rx_fib_index0,
					     thread_index);
		    }
		}
	      goto trace0;
	    }

	  if (PREDICT_FALSE (identity_nat0))
	    goto trace0;

	  if ((proto0 == IP_PROTOCOL_TCP) &&
	      !tcp_flags_is_init (
		vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags))
	    {
	      b0->error = node->errors[NAT_OUT2IN_ED_ERROR_NON_SYN];
	      next[0] = NAT_NEXT_DROP;
	      goto trace0;
	    }

	  /* Create session initiated by host from external network */
	  s0 = create_session_for_static_mapping_ed (
	    sm, b0, sm_addr, sm_port, sm_fib_index, ip0->dst_address,
	    vnet_buffer (b0)->ip.reass.l4_dst_port, rx_fib_index0, proto0,
	    node, thread_index, twice_nat0, lb_nat0, now, m);
	  if (!s0)
	    {
	      next[0] = NAT_NEXT_DROP;
	      goto trace0;
	    }
	}

      if (NAT_ED_TRNSL_ERR_SUCCESS !=
	  (translation_error = nat_6t_flow_buf_translate_o2i (
	     vm, sm, b0, ip0, &s0->o2i, proto0, 0 /* is_output_feature */)))
	{
	  next[0] = NAT_NEXT_DROP;
	  goto trace0;
	}

      if (PREDICT_TRUE (proto0 == IP_PROTOCOL_TCP))
	{
	  vlib_increment_simple_counter (&sm->counters.slowpath.out2in.tcp,
					 thread_index, sw_if_index0, 1);
	  nat44_set_tcp_session_state_o2i (sm, now, s0,
					   vnet_buffer (b0)->ip.
					   reass.icmp_type_or_tcp_flags,
					   thread_index);
	}
      else
	{
	  vlib_increment_simple_counter (&sm->counters.slowpath.out2in.udp,
					 thread_index, sw_if_index0, 1);
	}

      /* Accounting */
      nat44_session_update_counters (s0, now,
				     vlib_buffer_length_in_chain (vm, b0),
				     thread_index);
      /* Per-user LRU list maintenance */
      nat44_session_update_lru (sm, s0, thread_index);

    trace0:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat44_ed_out2in_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->next_index = next[0];
	  t->is_slow_path = 1;
	  t->translation_error = translation_error;
	  clib_memcpy (&t->search_key, &kv0, sizeof (t->search_key));

	  if (s0)
	    {
	      t->session_index = s0 - tsm->sessions;
	      clib_memcpy (&t->i2of, &s0->i2o, sizeof (t->i2of));
	      clib_memcpy (&t->o2if, &s0->o2i, sizeof (t->o2if));
	      t->tcp_state = s0->tcp_state;
	    }
	  else
	    {
	      t->session_index = ~0;
	    }
	}

      if (next[0] == NAT_NEXT_DROP)
	{
	  vlib_increment_simple_counter (&sm->counters.slowpath.out2in.drops,
					 thread_index, sw_if_index0, 1);
	}

      n_left_from--;
      next++;
      b++;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
			       frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (nat44_ed_out2in_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  if (snat_main.num_workers > 1)
    {
      return nat44_ed_out2in_fast_path_node_fn_inline (vm, node, frame, 1);
    }
  else
    {
      return nat44_ed_out2in_fast_path_node_fn_inline (vm, node, frame, 0);
    }
}

VLIB_REGISTER_NODE (nat44_ed_out2in_node) = {
  .name = "nat44-ed-out2in",
  .vector_size = sizeof (u32),
  .sibling_of = "nat-default",
  .format_trace = format_nat44_ed_out2in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat_out2in_ed_error_strings),
  .error_strings = nat_out2in_ed_error_strings,
  .runtime_data_bytes = sizeof (snat_runtime_t),
};

VLIB_NODE_FN (nat44_ed_out2in_slowpath_node) (vlib_main_t * vm,
					      vlib_node_runtime_t * node,
					      vlib_frame_t * frame)
{
  return nat44_ed_out2in_slow_path_node_fn_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (nat44_ed_out2in_slowpath_node) = {
  .name = "nat44-ed-out2in-slowpath",
  .vector_size = sizeof (u32),
  .sibling_of = "nat-default",
  .format_trace = format_nat44_ed_out2in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat_out2in_ed_error_strings),
  .error_strings = nat_out2in_ed_error_strings,
  .runtime_data_bytes = sizeof (snat_runtime_t),
};

static u8 *
format_nat_pre_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat_pre_trace_t *t = va_arg (*args, nat_pre_trace_t *);
  return format (s, "out2in next_index %d arc_next_index %d", t->next_index,
		 t->arc_next_index);
}

VLIB_NODE_FN (nat_pre_out2in_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return nat_pre_node_fn_inline (vm, node, frame,
				 NAT_NEXT_OUT2IN_ED_FAST_PATH);
}

VLIB_REGISTER_NODE (nat_pre_out2in_node) = {
  .name = "nat-pre-out2in",
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
