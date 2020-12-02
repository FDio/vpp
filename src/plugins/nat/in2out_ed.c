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

  s = format (s, "%s: sw_if_index %d, next index %d, session %d", tag,
	      t->sw_if_index, t->next_index, t->session_index);

  return s;
}

#ifndef CLIB_MARCH_VARIANT
int
nat44_i2o_ed_is_idle_session_cb (clib_bihash_kv_16_8_t * kv, void *arg)
{
  snat_main_t *sm = &snat_main;
  nat44_is_idle_session_ctx_t *ctx = arg;
  snat_session_t *s;
  u64 sess_timeout_time;
  u8 proto;
  u16 r_port, l_port;
  ip4_address_t *l_addr, *r_addr;
  u32 fib_index;
  clib_bihash_kv_16_8_t ed_kv;
  int i;
  snat_address_t *a;
  snat_main_per_thread_data_t *tsm = vec_elt_at_index (sm->per_thread_data,
						       ctx->thread_index);

  ASSERT (ctx->thread_index == ed_value_get_thread_index (kv));
  s = pool_elt_at_index (tsm->sessions, ed_value_get_session_index (kv));
  sess_timeout_time = s->last_heard + (f64) nat44_session_get_timeout (sm, s);
  if (ctx->now >= sess_timeout_time)
    {
      if (is_fwd_bypass_session (s))
	goto delete;

      l_addr = &s->out2in.addr;
      r_addr = &s->ext_host_addr;
      fib_index = s->out2in.fib_index;
      if (snat_is_unk_proto_session (s))
	{
	  proto = s->in2out.port;
	  r_port = 0;
	  l_port = 0;
	}
      else
	{
	  proto = nat_proto_to_ip_proto (s->nat_proto);
	  l_port = s->out2in.port;
	  r_port = s->ext_host_port;
	}
      init_ed_k (&ed_kv, *l_addr, l_port, *r_addr, r_port, fib_index, proto);
      if (clib_bihash_add_del_16_8 (&sm->out2in_ed, &ed_kv, 0))
	nat_elog_warn ("out2in_ed key del failed");

      if (snat_is_unk_proto_session (s))
	goto delete;

      nat_ipfix_logging_nat44_ses_delete (ctx->thread_index,
					  s->in2out.addr.as_u32,
					  s->out2in.addr.as_u32,
					  s->nat_proto,
					  s->in2out.port,
					  s->out2in.port,
					  s->in2out.fib_index);

      nat_syslog_nat44_sdel (s->user_index, s->in2out.fib_index,
			     &s->in2out.addr, s->in2out.port,
			     &s->ext_host_nat_addr, s->ext_host_nat_port,
			     &s->out2in.addr, s->out2in.port,
			     &s->ext_host_addr, s->ext_host_port,
			     s->nat_proto, is_twice_nat_session (s));

      nat_ha_sdel (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
		   s->ext_host_port, s->nat_proto, s->out2in.fib_index,
		   ctx->thread_index);

      if (is_twice_nat_session (s))
	{
	  for (i = 0; i < vec_len (sm->twice_nat_addresses); i++)
	    {
	      // TODO FIXME this is obviously broken - which address should be
	      // freed here?!
	      a = sm->twice_nat_addresses + i;
	      if (a->addr.as_u32 == s->ext_host_nat_addr.as_u32)
		{
		  snat_free_outside_address_and_port (sm->twice_nat_addresses,
						      ctx->thread_index,
						      &s->ext_host_nat_addr,
						      s->ext_host_nat_port,
						      s->nat_proto);
		  break;
		}
	    }
	}

      if (snat_is_session_static (s))
	goto delete;

      snat_free_outside_address_and_port (sm->addresses, ctx->thread_index,
					  &s->out2in.addr, s->out2in.port,
					  s->nat_proto);
    delete:
      nat_ed_session_delete (sm, s, ctx->thread_index, 1);
      return 1;
    }

  return 0;
}
#endif

static inline u32
icmp_in2out_ed_slow_path (snat_main_t * sm, vlib_buffer_t * b0,
			  ip4_header_t * ip0, icmp46_header_t * icmp0,
			  u32 sw_if_index0, u32 rx_fib_index0,
			  vlib_node_runtime_t * node, u32 next0, f64 now,
			  u32 thread_index, snat_session_t ** p_s0)
{
  vlib_main_t *vm = vlib_get_main ();

  next0 = icmp_in2out (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
		       next0, thread_index, p_s0, 0);
  snat_session_t *s0 = *p_s0;
  if (PREDICT_TRUE (next0 != NAT_NEXT_DROP && s0))
    {
      /* Accounting */
      nat44_session_update_counters (s0, now,
				     vlib_buffer_length_in_chain
				     (vm, b0), thread_index);
      /* Per-user LRU list maintenance */
      nat44_session_update_lru (sm, s0, thread_index);
    }
  return next0;
}

static int
nat_ed_alloc_addr_and_port (snat_main_t * sm, u32 rx_fib_index,
			    u32 nat_proto, u32 thread_index,
			    ip4_address_t r_addr, u16 r_port, u8 proto,
			    u16 port_per_thread, u32 snat_thread_index,
			    snat_session_t * s,
			    ip4_address_t * outside_addr,
			    u16 * outside_port,
			    clib_bihash_kv_16_8_t * out2in_ed_kv)
{
  int i;
  snat_address_t *a, *ga = 0;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  const u16 port_thread_offset = (port_per_thread * snat_thread_index) + 1024;

  for (i = 0; i < vec_len (sm->addresses); i++)
    {
      a = sm->addresses + i;
      switch (nat_proto)
	{
#define _(N, j, n, unused)                                                   \
  case NAT_PROTOCOL_##N:                                                     \
    if (a->fib_index == rx_fib_index)                                        \
      {                                                                      \
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
            init_ed_kv (out2in_ed_kv, a->addr, clib_host_to_net_u16 (port),  \
                        r_addr, r_port, s->out2in.fib_index, proto,          \
                        thread_index, s - tsm->sessions);                    \
            int rv = clib_bihash_add_del_16_8 (&sm->out2in_ed, out2in_ed_kv, \
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
	      vlib_node_runtime_t * node, u32 next, u32 thread_index, f64 now)
{
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  clib_bihash_kv_16_8_t out2in_ed_kv;
  nat44_is_idle_session_ctx_t ctx;
  ip4_address_t outside_addr;
  u16 outside_port;
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

  ip4_address_t sm_addr;
  u16 sm_port;
  u32 sm_fib_index;
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
      s->out2in.fib_index = sm->outside_fib_index;

      switch (vec_len (sm->outside_fibs))
	{
	case 0:
	  s->out2in.fib_index = sm->outside_fib_index;
	  break;
	case 1:
	  s->out2in.fib_index = sm->outside_fibs[0].fib_index;
	  break;
	default:
	  s->out2in.fib_index = nat_outside_fib_index_lookup (sm, r_addr);
	  break;
	}

      /* Try to create dynamic translation */
      outside_port = l_port;	// suggest using local port to allocation function
      if (nat_ed_alloc_addr_and_port (sm, rx_fib_index, nat_proto,
				      thread_index, r_addr, r_port, proto,
				      sm->port_per_thread,
				      tsm->snat_thread_index, s,
				      &outside_addr,
				      &outside_port, &out2in_ed_kv))
	{
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
	  return next;
	}
      s = nat_ed_session_alloc (sm, thread_index, now, proto);
      ASSERT (s);
      s->out2in.addr = sm_addr;
      s->out2in.port = sm_port;
      s->in2out.addr = l_addr;
      s->in2out.port = l_port;
      s->nat_proto = nat_proto;
      s->in2out.fib_index = rx_fib_index;
      s->out2in.fib_index = sm->outside_fib_index;
      switch (vec_len (sm->outside_fibs))
	{
	case 0:
	  s->out2in.fib_index = sm->outside_fib_index;
	  break;
	case 1:
	  s->out2in.fib_index = sm->outside_fibs[0].fib_index;
	  break;
	default:
	  s->out2in.fib_index = nat_outside_fib_index_lookup (sm, r_addr);
	  break;
	}

      s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;

      init_ed_kv (&out2in_ed_kv, sm_addr, sm_port, r_addr, r_port,
		  s->out2in.fib_index, proto, thread_index,
		  s - tsm->sessions);
      if (clib_bihash_add_or_overwrite_stale_16_8
	  (&sm->out2in_ed, &out2in_ed_kv, nat44_o2i_ed_is_idle_session_cb,
	   &ctx))
	nat_elog_notice ("out2in-ed key add failed");
    }

  if (lb)
    s->flags |= SNAT_SESSION_FLAG_LOAD_BALANCING;
  s->flags |= SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT;
  s->ext_host_addr = r_addr;
  s->ext_host_port = r_port;

  clib_bihash_kv_16_8_t in2out_ed_kv;
  init_ed_kv (&in2out_ed_kv, l_addr, l_port, r_addr, r_port, rx_fib_index,
	      proto, thread_index, s - tsm->sessions);
  ctx.now = now;
  ctx.thread_index = thread_index;
  if (clib_bihash_add_or_overwrite_stale_16_8 (&tsm->in2out_ed, &in2out_ed_kv,
					       nat44_i2o_ed_is_idle_session_cb,
					       &ctx))
    nat_elog_notice ("in2out-ed key add failed");

  *sessionp = s;

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
  if (clib_bihash_search_16_8 (&sm->out2in_ed, &kv, &value))
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

  if (!clib_bihash_search_16_8 (&tsm->in2out_ed, &kv, &value))
    {
      ASSERT (thread_index == ed_value_get_thread_index (&value));
      s =
	pool_elt_at_index (tsm->sessions,
			   ed_value_get_session_index (&value));
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
  u32 rx_fib_index = ip4_fib_table_get_index_for_sw_if_index (rx_sw_if_index);
  u32 tx_fib_index = ip4_fib_table_get_index_for_sw_if_index (tx_sw_if_index);

  /* src NAT check */
  init_ed_k (&kv, ip->src_address, src_port, ip->dst_address, dst_port,
	     tx_fib_index, ip->protocol);
  if (!clib_bihash_search_16_8 (&sm->out2in_ed, &kv, &value))
    {
      ASSERT (thread_index == ed_value_get_thread_index (&value));
      s =
	pool_elt_at_index (tsm->sessions,
			   ed_value_get_session_index (&value));
      return 1;
    }

  /* dst NAT check */
  init_ed_k (&kv, ip->dst_address, dst_port, ip->src_address, src_port,
	     rx_fib_index, ip->protocol);
  if (!clib_bihash_search_16_8 (&tsm->in2out_ed, &kv, &value))
    {
      ASSERT (thread_index == ed_value_get_thread_index (&value));
      s =
	pool_elt_at_index (tsm->sessions,
			   ed_value_get_session_index (&value));
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

#ifndef CLIB_MARCH_VARIANT
u32
icmp_match_in2out_ed (snat_main_t * sm, vlib_node_runtime_t * node,
		      u32 thread_index, vlib_buffer_t * b,
		      ip4_header_t * ip, ip4_address_t * addr,
		      u16 * port, u32 * fib_index, nat_protocol_t * proto,
		      void *d, void *e, u8 * dont_translate)
{
  u32 sw_if_index;
  u32 rx_fib_index;
  clib_bihash_kv_16_8_t kv, value;
  u32 next = ~0;
  int err;
  snat_session_t *s = NULL;
  u16 l_port = 0, r_port = 0;	// initialize to workaround gcc warning
  vlib_main_t *vm = vlib_get_main ();
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  *dont_translate = 0;

  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  rx_fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  err =
    get_icmp_i2o_ed_key (b, ip, rx_fib_index, ~0, ~0, proto, &l_port,
			 &r_port, &kv);
  if (err != 0)
    {
      b->error = node->errors[err];
      next = NAT_NEXT_DROP;
      goto out;
    }

  if (clib_bihash_search_16_8 (&tsm->in2out_ed, &kv, &value))
    {
      if (vnet_buffer (b)->sw_if_index[VLIB_TX] != ~0)
	{
	  if (PREDICT_FALSE
	      (nat44_ed_not_translate_output_feature
	       (sm, ip, l_port, r_port, thread_index,
		sw_if_index, vnet_buffer (b)->sw_if_index[VLIB_TX])))
	    {
	      *dont_translate = 1;
	      goto out;
	    }
	}
      else
	{
	  if (PREDICT_FALSE (nat44_ed_not_translate (sm, node, sw_if_index,
						     ip, NAT_PROTOCOL_ICMP,
						     rx_fib_index,
						     thread_index)))
	    {
	      *dont_translate = 1;
	      goto out;
	    }
	}

      if (PREDICT_FALSE
	  (icmp_type_is_error_message
	   (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags)))
	{
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_BAD_ICMP_TYPE];
	  next = NAT_NEXT_DROP;
	  goto out;
	}

      next =
	slow_path_ed (sm, b, ip->src_address, ip->dst_address, l_port, r_port,
		      ip->protocol, rx_fib_index, &s, node, next,
		      thread_index, vlib_time_now (vm));

      if (PREDICT_FALSE (next == NAT_NEXT_DROP))
	goto out;

      if (!s)
	{
	  *dont_translate = 1;
	  goto out;
	}
    }
  else
    {
      if (PREDICT_FALSE
	  (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags !=
	   ICMP4_echo_request
	   && vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags !=
	   ICMP4_echo_reply
	   && !icmp_type_is_error_message (vnet_buffer (b)->ip.
					   reass.icmp_type_or_tcp_flags)))
	{
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_BAD_ICMP_TYPE];
	  next = NAT_NEXT_DROP;
	  goto out;
	}

      ASSERT (thread_index == ed_value_get_thread_index (&value));
      s =
	pool_elt_at_index (tsm->sessions,
			   ed_value_get_session_index (&value));
    }
out:
  if (s)
    {
      *addr = s->out2in.addr;
      *port = s->out2in.port;
      *fib_index = s->out2in.fib_index;
    }
  if (d)
    {
      *(snat_session_t **) d = s;
    }
  return next;
}
#endif

static snat_session_t *
nat44_ed_in2out_unknown_proto (snat_main_t * sm,
			       vlib_buffer_t * b,
			       ip4_header_t * ip,
			       u32 rx_fib_index,
			       u32 thread_index,
			       f64 now,
			       vlib_main_t * vm, vlib_node_runtime_t * node)
{
  clib_bihash_kv_8_8_t kv, value;
  clib_bihash_kv_16_8_t s_kv, s_value;
  snat_static_mapping_t *m;
  u32 old_addr, new_addr = 0;
  ip_csum_t sum;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  snat_session_t *s;
  u32 outside_fib_index = sm->outside_fib_index;
  int i;
  u8 is_sm = 0;

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
  old_addr = ip->src_address.as_u32;

  init_ed_k (&s_kv, ip->src_address, 0, ip->dst_address, 0, rx_fib_index,
	     ip->protocol);

  if (!clib_bihash_search_16_8 (&tsm->in2out_ed, &s_kv, &s_value))
    {
      ASSERT (thread_index == ed_value_get_thread_index (&s_value));
      s =
	pool_elt_at_index (tsm->sessions,
			   ed_value_get_session_index (&s_value));
      new_addr = ip->src_address.as_u32 = s->out2in.addr.as_u32;
    }
  else
    {
      if (PREDICT_FALSE
	  (nat44_ed_maximum_sessions_exceeded
	   (sm, rx_fib_index, thread_index)))
	{
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_MAX_SESSIONS_EXCEEDED];
	  nat_ipfix_logging_max_sessions (thread_index,
					  sm->max_translations_per_thread);
	  nat_elog_notice ("maximum sessions exceeded");
	  return 0;
	}

      init_nat_k (&kv, ip->src_address, 0, rx_fib_index, 0);

      /* Try to find static mapping first */
      if (!clib_bihash_search_8_8 (&sm->static_mapping_by_local, &kv, &value))
	{
	  m = pool_elt_at_index (sm->static_mappings, value.value);
	  new_addr = ip->src_address.as_u32 = m->external_addr.as_u32;
	  is_sm = 1;
	  goto create_ses;
	}
      else
	{
	  /* *INDENT-OFF* */
	  pool_foreach (s, tsm->sessions, {
      	    if (s->ext_host_addr.as_u32 == ip->dst_address.as_u32)
      	      {
      	        new_addr = ip->src_address.as_u32 = s->out2in.addr.as_u32;

      	        init_ed_k(&s_kv, s->out2in.addr, 0, ip->dst_address, 0, outside_fib_index, ip->protocol);
      	        if (clib_bihash_search_16_8 (&sm->out2in_ed, &s_kv, &s_value))
      	          goto create_ses;

      	        break;
      	      }
      	  });
      	  /* *INDENT-ON* */

	  for (i = 0; i < vec_len (sm->addresses); i++)
	    {
	      init_ed_k (&s_kv, sm->addresses[i].addr, 0, ip->dst_address, 0,
			 outside_fib_index, ip->protocol);
	      if (clib_bihash_search_16_8 (&sm->out2in_ed, &s_kv, &s_value))
		{
		  new_addr = ip->src_address.as_u32 =
		    sm->addresses[i].addr.as_u32;
		  goto create_ses;
		}
	    }
	  return 0;
	}

    create_ses:
      s = nat_ed_session_alloc (sm, thread_index, now, ip->protocol);
      if (!s)
	{
	  b->error = node->errors[NAT_IN2OUT_ED_ERROR_MAX_SESSIONS_EXCEEDED];
	  nat_elog_warn ("create NAT session failed");
	  return 0;
	}

      s->ext_host_addr.as_u32 = ip->dst_address.as_u32;
      s->flags |= SNAT_SESSION_FLAG_UNKNOWN_PROTO;
      s->flags |= SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT;
      s->out2in.addr.as_u32 = new_addr;
      s->out2in.fib_index = outside_fib_index;
      s->in2out.addr.as_u32 = old_addr;
      s->in2out.fib_index = rx_fib_index;
      s->in2out.port = s->out2in.port = ip->protocol;
      if (is_sm)
	s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;

      /* Add to lookup tables */
      init_ed_kv (&s_kv, s->in2out.addr, 0, ip->dst_address, 0, rx_fib_index,
		  ip->protocol, thread_index, s - tsm->sessions);
      if (clib_bihash_add_del_16_8 (&tsm->in2out_ed, &s_kv, 1))
	nat_elog_notice ("in2out key add failed");

      init_ed_kv (&s_kv, s->out2in.addr, 0, ip->dst_address, 0,
		  outside_fib_index, ip->protocol, thread_index,
		  s - tsm->sessions);
      if (clib_bihash_add_del_16_8 (&sm->out2in_ed, &s_kv, 1))
	nat_elog_notice ("out2in key add failed");

      per_vrf_sessions_register_session (s, thread_index);
    }

  /* Update IP checksum */
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, src_address);
  ip->checksum = ip_csum_fold (sum);

  /* Accounting */
  nat44_session_update_counters (s, now, vlib_buffer_length_in_chain (vm, b),
				 thread_index);
  /* Per-user LRU list maintenance */
  nat44_session_update_lru (sm, s, thread_index);

  /* Hairpinning */
  if (vnet_buffer (b)->sw_if_index[VLIB_TX] == ~0)
    nat44_ed_hairpinning_unknown_proto (sm, b, ip);

  if (vnet_buffer (b)->sw_if_index[VLIB_TX] == ~0)
    vnet_buffer (b)->sw_if_index[VLIB_TX] = outside_fib_index;

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
      u32 sw_if_index0, rx_fib_index0, proto0, new_addr0, old_addr0,
	iph_offset0 = 0;
      u16 old_port0, new_port0;
      ip4_header_t *ip0;
      udp_header_t *udp0;
      tcp_header_t *tcp0;
      snat_session_t *s0 = 0;
      clib_bihash_kv_16_8_t kv0, value0;
      ip_csum_t sum0;

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

      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_OTHER))
	{
	  next[0] = def_slow;
	  goto trace0;
	}

      if (is_output_feature)
	{
	  if (PREDICT_FALSE
	      (nat_not_translate_output_feature_fwd
	       (sm, ip0, thread_index, now, vm, b0)))
	    goto trace0;
	}

      if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	{
	  next[0] = def_slow;
	  goto trace0;
	}

      init_ed_k (&kv0, ip0->src_address,
		 vnet_buffer (b0)->ip.reass.l4_src_port, ip0->dst_address,
		 vnet_buffer (b0)->ip.reass.l4_dst_port, rx_fib_index0,
		 ip0->protocol);

      // lookup for session
      if (clib_bihash_search_16_8 (&tsm->in2out_ed, &kv0, &value0))
	{
	  // session does not exist go slow path
	  next[0] = def_slow;
	  goto trace0;
	}
      ASSERT (thread_index == ed_value_get_thread_index (&value0));
      s0 =
	pool_elt_at_index (tsm->sessions,
			   ed_value_get_session_index (&value0));

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

      if (!is_output_feature)
	vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

      old_addr0 = ip0->src_address.as_u32;
      new_addr0 = ip0->src_address.as_u32 = s0->out2in.addr.as_u32;
      sum0 = ip0->checksum;
      sum0 =
	ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
			src_address);
      if (PREDICT_FALSE (is_twice_nat_session (s0)))
	sum0 =
	  ip_csum_update (sum0, ip0->dst_address.as_u32,
			  s0->ext_host_addr.as_u32, ip4_header_t,
			  dst_address);
      ip0->checksum = ip_csum_fold (sum0);

      old_port0 = vnet_buffer (b0)->ip.reass.l4_src_port;

      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	{
	  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
	    {
	      new_port0 = udp0->src_port = s0->out2in.port;
	      sum0 = tcp0->checksum;
	      sum0 =
		ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				dst_address);
	      sum0 =
		ip_csum_update (sum0, old_port0, new_port0, ip4_header_t,
				length);
	      if (PREDICT_FALSE (is_twice_nat_session (s0)))
		{
		  sum0 =
		    ip_csum_update (sum0, ip0->dst_address.as_u32,
				    s0->ext_host_addr.as_u32, ip4_header_t,
				    dst_address);
		  sum0 =
		    ip_csum_update (sum0,
				    vnet_buffer (b0)->ip.reass.l4_dst_port,
				    s0->ext_host_port, ip4_header_t, length);
		  tcp0->dst_port = s0->ext_host_port;
		  ip0->dst_address.as_u32 = s0->ext_host_addr.as_u32;
		}
	      mss_clamping (sm->mss_clamping, tcp0, &sum0);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  vlib_increment_simple_counter (&sm->counters.fastpath.in2out_ed.tcp,
					 thread_index, sw_if_index0, 1);
	  nat44_set_tcp_session_state_i2o (sm, now, s0, b0, thread_index);
	}
      else if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment
	       && udp0->checksum)
	{
	  new_port0 = udp0->src_port = s0->out2in.port;
	  sum0 = udp0->checksum;
	  sum0 =
	    ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
			    dst_address);
	  sum0 =
	    ip_csum_update (sum0, old_port0, new_port0, ip4_header_t, length);
	  if (PREDICT_FALSE (is_twice_nat_session (s0)))
	    {
	      sum0 =
		ip_csum_update (sum0, ip0->dst_address.as_u32,
				s0->ext_host_addr.as_u32, ip4_header_t,
				dst_address);
	      sum0 =
		ip_csum_update (sum0, vnet_buffer (b0)->ip.reass.l4_dst_port,
				s0->ext_host_port, ip4_header_t, length);
	      udp0->dst_port = s0->ext_host_port;
	      ip0->dst_address.as_u32 = s0->ext_host_addr.as_u32;
	    }
	  udp0->checksum = ip_csum_fold (sum0);
	  vlib_increment_simple_counter (&sm->counters.fastpath.in2out_ed.udp,
					 thread_index, sw_if_index0, 1);
	}
      else
	{
	  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
	    {
	      new_port0 = udp0->src_port = s0->out2in.port;
	      if (PREDICT_FALSE (is_twice_nat_session (s0)))
		{
		  udp0->dst_port = s0->ext_host_port;
		  ip0->dst_address.as_u32 = s0->ext_host_addr.as_u32;
		}
	      vlib_increment_simple_counter (&sm->counters.fastpath.
					     in2out_ed.udp, thread_index,
					     sw_if_index0, 1);
	    }
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
      u32 sw_if_index0, rx_fib_index0, proto0, new_addr0, old_addr0,
	iph_offset0 = 0;
      u16 old_port0, new_port0;
      ip4_header_t *ip0;
      udp_header_t *udp0;
      tcp_header_t *tcp0;
      icmp46_header_t *icmp0;
      snat_session_t *s0 = 0;
      clib_bihash_kv_16_8_t kv0, value0;
      ip_csum_t sum0;

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
	  s0 = nat44_ed_in2out_unknown_proto (sm, b0, ip0,
					      rx_fib_index0,
					      thread_index, now, vm, node);
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
				      thread_index, &s0);
	  vlib_increment_simple_counter (&sm->counters.slowpath.
					 in2out_ed.icmp, thread_index,
					 sw_if_index0, 1);
	  goto trace0;
	}

      init_ed_k (&kv0, ip0->src_address,
		 vnet_buffer (b0)->ip.reass.l4_src_port, ip0->dst_address,
		 vnet_buffer (b0)->ip.reass.l4_dst_port, rx_fib_index0,
		 ip0->protocol);
      if (!clib_bihash_search_16_8 (&tsm->in2out_ed, &kv0, &value0))
	{
	  ASSERT (thread_index == ed_value_get_thread_index (&value0));
	  s0 =
	    pool_elt_at_index (tsm->sessions,
			       ed_value_get_session_index (&value0));

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
			  ip0->protocol, rx_fib_index0, &s0, node, next[0],
			  thread_index, now);

	  if (PREDICT_FALSE (next[0] == NAT_NEXT_DROP))
	    goto trace0;

	  if (PREDICT_FALSE (!s0))
	    goto trace0;

	}

      b0->flags |= VNET_BUFFER_F_IS_NATED;

      if (!is_output_feature)
	vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->out2in.fib_index;

      old_addr0 = ip0->src_address.as_u32;
      new_addr0 = ip0->src_address.as_u32 = s0->out2in.addr.as_u32;
      sum0 = ip0->checksum;
      sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
			     src_address);
      if (PREDICT_FALSE (is_twice_nat_session (s0)))
	sum0 = ip_csum_update (sum0, ip0->dst_address.as_u32,
			       s0->ext_host_addr.as_u32, ip4_header_t,
			       dst_address);
      ip0->checksum = ip_csum_fold (sum0);

      old_port0 = vnet_buffer (b0)->ip.reass.l4_src_port;

      if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	{
	  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
	    {
	      new_port0 = udp0->src_port = s0->out2in.port;
	      sum0 = tcp0->checksum;
	      sum0 =
		ip_csum_update (sum0, old_addr0, new_addr0,
				ip4_header_t, dst_address);
	      sum0 =
		ip_csum_update (sum0, old_port0, new_port0,
				ip4_header_t, length);
	      if (PREDICT_FALSE (is_twice_nat_session (s0)))
		{
		  sum0 =
		    ip_csum_update (sum0, ip0->dst_address.as_u32,
				    s0->ext_host_addr.as_u32,
				    ip4_header_t, dst_address);
		  sum0 =
		    ip_csum_update (sum0,
				    vnet_buffer (b0)->ip.reass.l4_dst_port,
				    s0->ext_host_port, ip4_header_t, length);
		  tcp0->dst_port = s0->ext_host_port;
		  ip0->dst_address.as_u32 = s0->ext_host_addr.as_u32;
		}
	      mss_clamping (sm->mss_clamping, tcp0, &sum0);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  vlib_increment_simple_counter (&sm->counters.slowpath.in2out_ed.tcp,
					 thread_index, sw_if_index0, 1);
	  nat44_set_tcp_session_state_i2o (sm, now, s0, b0, thread_index);
	}
      else if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment
	       && udp0->checksum)
	{
	  new_port0 = udp0->src_port = s0->out2in.port;
	  sum0 = udp0->checksum;
	  sum0 =
	    ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
			    dst_address);
	  sum0 =
	    ip_csum_update (sum0, old_port0, new_port0, ip4_header_t, length);
	  if (PREDICT_FALSE (is_twice_nat_session (s0)))
	    {
	      sum0 = ip_csum_update (sum0, ip0->dst_address.as_u32,
				     s0->ext_host_addr.as_u32,
				     ip4_header_t, dst_address);
	      sum0 =
		ip_csum_update (sum0,
				vnet_buffer (b0)->ip.reass.l4_dst_port,
				s0->ext_host_port, ip4_header_t, length);
	      udp0->dst_port = s0->ext_host_port;
	      ip0->dst_address.as_u32 = s0->ext_host_addr.as_u32;
	    }
	  udp0->checksum = ip_csum_fold (sum0);
	  vlib_increment_simple_counter (&sm->counters.slowpath.in2out_ed.udp,
					 thread_index, sw_if_index0, 1);
	}
      else
	{
	  if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
	    {
	      new_port0 = udp0->src_port = s0->out2in.port;
	      if (PREDICT_FALSE (is_twice_nat_session (s0)))
		{
		  udp0->dst_port = s0->ext_host_port;
		  ip0->dst_address.as_u32 = s0->ext_host_addr.as_u32;
		}
	      vlib_increment_simple_counter (&sm->counters.slowpath.
					     in2out_ed.udp, thread_index,
					     sw_if_index0, 1);
	    }
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
