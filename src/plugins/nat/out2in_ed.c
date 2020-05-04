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
#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/udp/udp.h>
#include <vppinfra/error.h>
#include <nat/nat.h>
#include <nat/nat_ipfix_logging.h>
#include <nat/nat_inlines.h>
#include <nat/nat44/inlines.h>
#include <nat/nat_syslog.h>
#include <nat/nat_ha.h>
#include <nat/nat44/ed_inlines.h>

static char *nat_out2in_ed_error_strings[] = {
#define _(sym,string) string,
  foreach_nat_out2in_ed_error
#undef _
};

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
  u32 is_slow_path;
} nat44_ed_out2in_trace_t;

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

  s = format (s, "%s: sw_if_index %d, next index %d, session %d", tag,
	      t->sw_if_index, t->next_index, t->session_index);

  return s;
}

static inline u32
icmp_out2in_ed_slow_path (snat_main_t * sm, vlib_buffer_t * b0,
			  ip4_header_t * ip0, icmp46_header_t * icmp0,
			  u32 sw_if_index0, u32 rx_fib_index0,
			  vlib_node_runtime_t * node, u32 next0, f64 now,
			  u32 thread_index, snat_session_t ** p_s0)
{
  vlib_main_t *vm = vlib_get_main ();

  next0 = icmp_out2in (sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
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

#ifndef CLIB_MARCH_VARIANT
int
nat44_o2i_ed_is_idle_session_cb (clib_bihash_kv_16_8_t * kv, void *arg)
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
  snat_session_key_t key;
  snat_main_per_thread_data_t *tsm = vec_elt_at_index (sm->per_thread_data,
						       ctx->thread_index);

  s = pool_elt_at_index (tsm->sessions, kv->value);
  sess_timeout_time = s->last_heard + (f64) nat44_session_get_timeout (sm, s);
  if (ctx->now >= sess_timeout_time)
    {
      l_addr = &s->in2out.addr;
      r_addr = &s->ext_host_addr;
      fib_index = s->in2out.fib_index;
      if (snat_is_unk_proto_session (s))
	{
	  proto = s->in2out.port;
	  r_port = 0;
	  l_port = 0;
	}
      else
	{
	  proto = nat_proto_to_ip_proto (s->in2out.protocol);
	  l_port = s->in2out.port;
	  r_port = s->ext_host_port;
	}
      if (is_twice_nat_session (s))
	{
	  r_addr = &s->ext_host_nat_addr;
	  r_port = s->ext_host_nat_port;
	}
      make_ed_kv (l_addr, r_addr, proto, fib_index, l_port, r_port, ~0ULL,
		  &ed_kv);
      if (clib_bihash_add_del_16_8 (&tsm->in2out_ed, &ed_kv, 0))
	nat_elog_warn ("in2out_ed key del failed");

      if (snat_is_unk_proto_session (s))
	goto delete;

      snat_ipfix_logging_nat44_ses_delete (ctx->thread_index,
					   s->in2out.addr.as_u32,
					   s->out2in.addr.as_u32,
					   s->in2out.protocol,
					   s->in2out.port,
					   s->out2in.port,
					   s->in2out.fib_index);

      nat_syslog_nat44_sdel (s->user_index, s->in2out.fib_index,
			     &s->in2out.addr, s->in2out.port,
			     &s->ext_host_nat_addr, s->ext_host_nat_port,
			     &s->out2in.addr, s->out2in.port,
			     &s->ext_host_addr, s->ext_host_port,
			     s->in2out.protocol, is_twice_nat_session (s));

      nat_ha_sdel (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
		   s->ext_host_port, s->out2in.protocol, s->out2in.fib_index,
		   ctx->thread_index);

      if (is_twice_nat_session (s))
	{
	  for (i = 0; i < vec_len (sm->twice_nat_addresses); i++)
	    {
	      key.protocol = s->in2out.protocol;
	      key.port = s->ext_host_nat_port;
	      a = sm->twice_nat_addresses + i;
	      if (a->addr.as_u32 == s->ext_host_nat_addr.as_u32)
		{
		  snat_free_outside_address_and_port (sm->twice_nat_addresses,
						      ctx->thread_index,
						      &key);
		  break;
		}
	    }
	}

      if (snat_is_session_static (s))
	goto delete;

      snat_free_outside_address_and_port (sm->addresses, ctx->thread_index,
					  &s->out2in);
    delete:
      nat_ed_session_delete (sm, s, ctx->thread_index, 1);
      return 1;
    }

  return 0;
}
#endif

static snat_session_t *
create_session_for_static_mapping_ed (snat_main_t * sm,
				      vlib_buffer_t * b,
				      snat_session_key_t l_key,
				      snat_session_key_t e_key,
				      vlib_node_runtime_t * node,
				      u32 rx_fib_index,
				      u32 thread_index,
				      twice_nat_type_t twice_nat,
				      lb_nat_type_t lb_nat, f64 now)
{
  snat_session_t *s;
  ip4_header_t *ip;
  udp_header_t *udp;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  clib_bihash_kv_16_8_t kv;
  snat_session_key_t eh_key;
  nat44_is_idle_session_ctx_t ctx;

  if (PREDICT_FALSE
      (nat44_ed_maximum_sessions_exceeded (sm, rx_fib_index, thread_index)))
    {
      b->error = node->errors[NAT_OUT2IN_ED_ERROR_MAX_SESSIONS_EXCEEDED];
      nat_elog_notice ("maximum sessions exceeded");
      return 0;
    }

  s = nat_ed_session_alloc (sm, thread_index, now, e_key.protocol);
  if (!s)
    {
      b->error = node->errors[NAT_OUT2IN_ED_ERROR_MAX_USER_SESS_EXCEEDED];
      nat_elog_warn ("create NAT session failed");
      return 0;
    }

  ip = vlib_buffer_get_current (b);
  udp = ip4_next_header (ip);

  s->ext_host_addr.as_u32 = ip->src_address.as_u32;
  s->ext_host_port = e_key.protocol == NAT_PROTOCOL_ICMP ? 0 : udp->src_port;
  s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
  if (lb_nat)
    s->flags |= SNAT_SESSION_FLAG_LOAD_BALANCING;
  if (lb_nat == AFFINITY_LB_NAT)
    s->flags |= SNAT_SESSION_FLAG_AFFINITY;
  s->flags |= SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT;
  s->out2in = e_key;
  s->in2out = l_key;
  s->in2out.protocol = s->out2in.protocol;

  /* Add to lookup tables */
  make_ed_kv (&e_key.addr, &s->ext_host_addr, ip->protocol,
	      e_key.fib_index, e_key.port, s->ext_host_port,
	      s - tsm->sessions, &kv);
  ctx.now = now;
  ctx.thread_index = thread_index;
  if (clib_bihash_add_or_overwrite_stale_16_8 (&tsm->out2in_ed, &kv,
					       nat44_o2i_ed_is_idle_session_cb,
					       &ctx))
    nat_elog_notice ("out2in-ed key add failed");

  if (twice_nat == TWICE_NAT || (twice_nat == TWICE_NAT_SELF &&
				 ip->src_address.as_u32 == l_key.addr.as_u32))
    {
      eh_key.protocol = e_key.protocol;
      if (snat_alloc_outside_address_and_port (sm->twice_nat_addresses, 0,
					       thread_index, &eh_key,
					       sm->port_per_thread,
					       tsm->snat_thread_index))
	{
	  b->error = node->errors[NAT_OUT2IN_ED_ERROR_OUT_OF_PORTS];
	  nat_ed_session_delete (sm, s, thread_index, 1);
	  if (clib_bihash_add_del_16_8 (&tsm->out2in_ed, &kv, 0))
	    nat_elog_notice ("out2in-ed key del failed");
	  return 0;
	}
      s->ext_host_nat_addr.as_u32 = eh_key.addr.as_u32;
      s->ext_host_nat_port = eh_key.port;
      s->flags |= SNAT_SESSION_FLAG_TWICE_NAT;
      make_ed_kv (&l_key.addr, &s->ext_host_nat_addr, ip->protocol,
		  l_key.fib_index, l_key.port, s->ext_host_nat_port,
		  s - tsm->sessions, &kv);
    }
  else
    {
      make_ed_kv (&l_key.addr, &s->ext_host_addr, ip->protocol,
		  l_key.fib_index, l_key.port, s->ext_host_port,
		  s - tsm->sessions, &kv);
    }
  if (clib_bihash_add_or_overwrite_stale_16_8 (&tsm->in2out_ed, &kv,
					       nat44_i2o_ed_is_idle_session_cb,
					       &ctx))
    nat_elog_notice ("in2out-ed key add failed");

  snat_ipfix_logging_nat44_ses_create (thread_index,
				       s->in2out.addr.as_u32,
				       s->out2in.addr.as_u32,
				       s->in2out.protocol,
				       s->in2out.port,
				       s->out2in.port, s->in2out.fib_index);

  nat_syslog_nat44_sadd (s->user_index, s->in2out.fib_index,
			 &s->in2out.addr, s->in2out.port,
			 &s->ext_host_nat_addr, s->ext_host_nat_port,
			 &s->out2in.addr, s->out2in.port,
			 &s->ext_host_addr, s->ext_host_port,
			 s->in2out.protocol, is_twice_nat_session (s));

  nat_ha_sadd (&s->in2out.addr, s->in2out.port, &s->out2in.addr,
	       s->out2in.port, &s->ext_host_addr, s->ext_host_port,
	       &s->ext_host_nat_addr, s->ext_host_nat_port,
	       s->in2out.protocol, s->in2out.fib_index, s->flags,
	       thread_index, 0);

  return s;
}

static int
next_src_nat (snat_main_t * sm, ip4_header_t * ip, u16 src_port,
	      u16 dst_port, u32 thread_index, u32 rx_fib_index)
{
  clib_bihash_kv_16_8_t kv, value;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  make_ed_kv (&ip->src_address, &ip->dst_address, ip->protocol,
	      rx_fib_index, src_port, dst_port, ~0ULL, &kv);
  if (!clib_bihash_search_16_8 (&tsm->in2out_ed, &kv, &value))
    return 1;

  return 0;
}

static void
create_bypass_for_fwd (snat_main_t * sm, vlib_buffer_t * b, ip4_header_t * ip,
		       u32 rx_fib_index, u32 thread_index)
{
  clib_bihash_kv_16_8_t kv, value;
  udp_header_t *udp;
  snat_session_t *s = 0;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);
  u16 l_port, r_port;

  if (ip->protocol == IP_PROTOCOL_ICMP)
    {
      if (get_icmp_o2i_ed_key
	  (b, ip, rx_fib_index, ~0ULL, 0, &l_port, &r_port, &kv))
	return;
    }
  else
    {
      if (ip->protocol == IP_PROTOCOL_UDP || ip->protocol == IP_PROTOCOL_TCP)
	{
	  udp = ip4_next_header (ip);
	  l_port = udp->dst_port;
	  r_port = udp->src_port;
	}
      else
	{
	  l_port = 0;
	  r_port = 0;
	}
      make_ed_kv (&ip->dst_address, &ip->src_address, ip->protocol,
		  rx_fib_index, l_port, r_port, ~0ULL, &kv);
    }

  if (!clib_bihash_search_16_8 (&tsm->in2out_ed, &kv, &value))
    {
      s = pool_elt_at_index (tsm->sessions, value.value);
    }
  else
    {
      u32 proto;

      if (PREDICT_FALSE
	  (nat44_ed_maximum_sessions_exceeded
	   (sm, rx_fib_index, thread_index)))
	return;

      s = nat_ed_session_alloc (sm, thread_index, now, ip->protocol);
      if (!s)
	{
	  nat_elog_warn ("create NAT session failed");
	  return;
	}

      proto = ip_proto_to_nat_proto (ip->protocol);

      s->ext_host_addr = ip->src_address;
      s->ext_host_port = r_port;
      s->flags |= SNAT_SESSION_FLAG_FWD_BYPASS;
      s->out2in.addr = ip->dst_address;
      s->out2in.port = l_port;
      s->out2in.protocol = proto;
      if (proto == NAT_PROTOCOL_OTHER)
	{
	  s->flags |= SNAT_SESSION_FLAG_UNKNOWN_PROTO;
	  s->out2in.port = ip->protocol;
	}
      s->out2in.fib_index = 0;
      s->in2out = s->out2in;

      kv.value = s - tsm->sessions;
      if (clib_bihash_add_del_16_8 (&tsm->in2out_ed, &kv, 1))
	nat_elog_notice ("in2out_ed key add failed");
    }

  if (ip->protocol == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = ip4_next_header (ip);
      if (nat44_set_tcp_session_state_o2i
	  (sm, now, s, tcp->flags, tcp->ack_number, tcp->seq_number,
	   thread_index))
	return;
    }

  /* Accounting */
  nat44_session_update_counters (s, now, 0, thread_index);
  /* Per-user LRU list maintenance */
  nat44_session_update_lru (sm, s, thread_index);
}

static inline void
create_bypass_for_fwd_worker (snat_main_t * sm, vlib_buffer_t * b,
			      ip4_header_t * ip, u32 rx_fib_index)
{
  ip4_header_t ip_wkr = {
    .src_address = ip->dst_address,
  };
  u32 thread_index = sm->worker_in2out_cb (&ip_wkr, rx_fib_index, 0);

  create_bypass_for_fwd (sm, b, ip, rx_fib_index, thread_index);
}

#ifndef CLIB_MARCH_VARIANT
u32
icmp_match_out2in_ed (snat_main_t * sm, vlib_node_runtime_t * node,
		      u32 thread_index, vlib_buffer_t * b, ip4_header_t * ip,
		      u8 * p_proto, snat_session_key_t * p_value,
		      u8 * p_dont_translate, void *d, void *e)
{
  u32 next = ~0, sw_if_index, rx_fib_index;
  clib_bihash_kv_16_8_t kv, value;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  snat_session_t *s = 0;
  u8 dont_translate = 0, is_addr_only, identity_nat;
  snat_session_key_t e_key, l_key;
  u16 l_port, r_port;
  vlib_main_t *vm = vlib_get_main ();

  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  rx_fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  if (get_icmp_o2i_ed_key
      (b, ip, rx_fib_index, ~0ULL, p_proto, &l_port, &r_port, &kv))
    {
      b->error = node->errors[NAT_OUT2IN_ED_ERROR_UNSUPPORTED_PROTOCOL];
      next = NAT_NEXT_DROP;
      goto out;
    }

  if (clib_bihash_search_16_8 (&tsm->out2in_ed, &kv, &value))
    {
      /* Try to match static mapping */
      e_key.addr = ip->dst_address;
      e_key.port = l_port;
      e_key.protocol = ip_proto_to_nat_proto (ip->protocol);
      e_key.fib_index = rx_fib_index;
      if (snat_static_mapping_match
	  (sm, e_key, &l_key, 1, &is_addr_only, 0, 0, 0, &identity_nat))
	{
	  if (!sm->forwarding_enabled)
	    {
	      /* Don't NAT packet aimed at the intfc address */
	      if (PREDICT_FALSE (is_interface_addr (sm, node, sw_if_index,
						    ip->dst_address.as_u32)))
		{
		  dont_translate = 1;
		  goto out;
		}
	      b->error = node->errors[NAT_OUT2IN_ED_ERROR_NO_TRANSLATION];
	      next = NAT_NEXT_DROP;
	      goto out;
	    }
	  else
	    {
	      dont_translate = 1;
	      if (next_src_nat (sm, ip, l_port, r_port,
				thread_index, rx_fib_index))
		{
		  next = NAT_NEXT_IN2OUT_ED_FAST_PATH;
		  goto out;
		}
	      if (sm->num_workers > 1)
		create_bypass_for_fwd_worker (sm, b, ip, rx_fib_index);
	      else
		create_bypass_for_fwd (sm, b, ip, rx_fib_index, thread_index);
	      goto out;
	    }
	}

      if (PREDICT_FALSE
	  (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags !=
	   ICMP4_echo_reply
	   && (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags !=
	       ICMP4_echo_request || !is_addr_only)))
	{
	  b->error = node->errors[NAT_OUT2IN_ED_ERROR_BAD_ICMP_TYPE];
	  next = NAT_NEXT_DROP;
	  goto out;
	}

      if (PREDICT_FALSE (identity_nat))
	{
	  dont_translate = 1;
	  goto out;
	}

      /* Create session initiated by host from external network */
      s = create_session_for_static_mapping_ed (sm, b, l_key, e_key, node,
						rx_fib_index, thread_index, 0,
						0, vlib_time_now (vm));

      if (!s)
	{
	  next = NAT_NEXT_DROP;
	  goto out;
	}
    }
  else
    {
      if (PREDICT_FALSE
	  (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags !=
	   ICMP4_echo_reply
	   && vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags !=
	   ICMP4_echo_request
	   && !icmp_type_is_error_message (vnet_buffer (b)->ip.
					   reass.icmp_type_or_tcp_flags)))
	{
	  b->error = node->errors[NAT_OUT2IN_ED_ERROR_BAD_ICMP_TYPE];
	  next = NAT_NEXT_DROP;
	  goto out;
	}

      s = pool_elt_at_index (tsm->sessions, value.value);
    }
out:
  if (s)
    *p_value = s->in2out;
  *p_dont_translate = dont_translate;
  if (d)
    *(snat_session_t **) d = s;
  return next;
}
#endif

static snat_session_t *
nat44_ed_out2in_unknown_proto (snat_main_t * sm,
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
  u32 old_addr, new_addr;
  ip_csum_t sum;
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  old_addr = ip->dst_address.as_u32;

  make_ed_kv (&ip->dst_address, &ip->src_address, ip->protocol, rx_fib_index,
	      0, 0, ~0ULL, &s_kv);

  if (!clib_bihash_search_16_8 (&tsm->out2in_ed, &s_kv, &s_value))
    {
      s = pool_elt_at_index (tsm->sessions, s_value.value);
      new_addr = ip->dst_address.as_u32 = s->in2out.addr.as_u32;
    }
  else
    {
      if (PREDICT_FALSE
	  (nat44_ed_maximum_sessions_exceeded
	   (sm, rx_fib_index, thread_index)))
	{
	  b->error = node->errors[NAT_OUT2IN_ED_ERROR_MAX_SESSIONS_EXCEEDED];
	  nat_elog_notice ("maximum sessions exceeded");
	  return 0;
	}

      make_sm_kv (&kv, &ip->dst_address, 0, 0, 0);
      if (clib_bihash_search_8_8
	  (&sm->static_mapping_by_external, &kv, &value))
	{
	  b->error = node->errors[NAT_OUT2IN_ED_ERROR_NO_TRANSLATION];
	  return 0;
	}

      m = pool_elt_at_index (sm->static_mappings, value.value);

      new_addr = ip->dst_address.as_u32 = m->local_addr.as_u32;

      /* Create a new session */
      s = nat_ed_session_alloc (sm, thread_index, now, ip->protocol);
      if (!s)
	{
	  b->error = node->errors[NAT_OUT2IN_ED_ERROR_MAX_USER_SESS_EXCEEDED];
	  nat_elog_warn ("create NAT session failed");
	  return 0;
	}

      s->ext_host_addr.as_u32 = ip->src_address.as_u32;
      s->flags |= SNAT_SESSION_FLAG_UNKNOWN_PROTO;
      s->flags |= SNAT_SESSION_FLAG_STATIC_MAPPING;
      s->flags |= SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT;
      s->out2in.addr.as_u32 = old_addr;
      s->out2in.fib_index = rx_fib_index;
      s->in2out.addr.as_u32 = new_addr;
      s->in2out.fib_index = m->fib_index;
      s->in2out.port = s->out2in.port = ip->protocol;

      /* Add to lookup tables */
      s_kv.value = s - tsm->sessions;
      if (clib_bihash_add_del_16_8 (&tsm->out2in_ed, &s_kv, 1))
	nat_elog_notice ("out2in key add failed");

      make_ed_kv (&ip->dst_address, &ip->src_address, ip->protocol,
		  m->fib_index, 0, 0, s - tsm->sessions, &s_kv);
      if (clib_bihash_add_del_16_8 (&tsm->in2out_ed, &s_kv, 1))
	nat_elog_notice ("in2out key add failed");
    }

  /* Update IP checksum */
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address);
  ip->checksum = ip_csum_fold (sum);

  vnet_buffer (b)->sw_if_index[VLIB_TX] = s->in2out.fib_index;

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
					  vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, pkts_processed = 0, stats_node_index;
  nat_next_t next_index;
  snat_main_t *sm = &snat_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  u32 tcp_packets = 0, udp_packets = 0, icmp_packets = 0, other_packets =
    0, fragments = 0;

  stats_node_index = sm->ed_out2in_node_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0, sw_if_index0, rx_fib_index0, proto0, old_addr0,
	    new_addr0;
	  u16 old_port0, new_port0;
	  ip4_header_t *ip0;
	  udp_header_t *udp0;
	  tcp_header_t *tcp0;
	  snat_session_t *s0 = 0;
	  clib_bihash_kv_16_8_t kv0, value0;
	  ip_csum_t sum0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  next0 = vnet_buffer2 (b0)->nat.arc_next;

	  vnet_buffer (b0)->snat.flags = 0;
	  ip0 = vlib_buffer_get_current (b0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 =
	    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						 sw_if_index0);

	  if (PREDICT_FALSE (ip0->ttl == 1))
	    {
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next0 = NAT_NEXT_ICMP_ERROR;
	      goto trace0;
	    }

	  udp0 = ip4_next_header (ip0);
	  tcp0 = (tcp_header_t *) udp0;
	  proto0 = ip_proto_to_nat_proto (ip0->protocol);

	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_OTHER))
	    {
	      next0 = NAT_NEXT_OUT2IN_ED_SLOW_PATH;
	      goto trace0;
	    }

	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	    {
	      next0 = NAT_NEXT_OUT2IN_ED_SLOW_PATH;
	      goto trace0;
	    }

	  make_ed_kv (&ip0->dst_address, &ip0->src_address,
		      ip0->protocol, rx_fib_index0,
		      vnet_buffer (b0)->ip.reass.l4_dst_port,
		      vnet_buffer (b0)->ip.reass.l4_src_port, ~0ULL, &kv0);

	  if (clib_bihash_search_16_8 (&tsm->out2in_ed, &kv0, &value0))
	    {
	      next0 = NAT_NEXT_OUT2IN_ED_SLOW_PATH;
	      goto trace0;
	    }
	  s0 = pool_elt_at_index (tsm->sessions, value0.value);

	  if (s0->tcp_closed_timestamp)
	    {
	      if (now >= s0->tcp_closed_timestamp)
		{
		  // session is closed, go slow path
		  next0 = NAT_NEXT_OUT2IN_ED_SLOW_PATH;
		}
	      else
		{
		  // session in transitory timeout, drop
		  b0->error = node->errors[NAT_OUT2IN_ED_ERROR_TCP_CLOSED];
		  next0 = NAT_NEXT_DROP;
		}
	      goto trace0;
	    }

	  // drop if session expired
	  u64 sess_timeout_time;
	  sess_timeout_time = s0->last_heard +
	    (f64) nat44_session_get_timeout (sm, s0);
	  if (now >= sess_timeout_time)
	    {
	      // session is closed, go slow path
	      nat_free_session_data (sm, s0, thread_index, 0);
	      nat_ed_session_delete (sm, s0, thread_index, 1);
	      next0 = NAT_NEXT_OUT2IN_ED_SLOW_PATH;
	      goto trace0;
	    }
	  //

	  old_addr0 = ip0->dst_address.as_u32;
	  new_addr0 = ip0->dst_address.as_u32 = s0->in2out.addr.as_u32;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;

	  sum0 = ip0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				 dst_address);
	  if (PREDICT_FALSE (is_twice_nat_session (s0)))
	    sum0 = ip_csum_update (sum0, ip0->src_address.as_u32,
				   s0->ext_host_nat_addr.as_u32, ip4_header_t,
				   src_address);
	  ip0->checksum = ip_csum_fold (sum0);

	  old_port0 = vnet_buffer (b0)->ip.reass.l4_dst_port;

	  if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	    {
	      if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
		{
		  new_port0 = udp0->dst_port = s0->in2out.port;
		  sum0 = tcp0->checksum;
		  sum0 =
		    ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				    dst_address);
		  sum0 =
		    ip_csum_update (sum0, old_port0, new_port0, ip4_header_t,
				    length);
		  if (is_twice_nat_session (s0))
		    {
		      sum0 = ip_csum_update (sum0, ip0->src_address.as_u32,
					     s0->ext_host_nat_addr.as_u32,
					     ip4_header_t, dst_address);
		      sum0 =
			ip_csum_update (sum0,
					vnet_buffer (b0)->ip.
					reass.l4_src_port,
					s0->ext_host_nat_port, ip4_header_t,
					length);
		      tcp0->src_port = s0->ext_host_nat_port;
		      ip0->src_address.as_u32 = s0->ext_host_nat_addr.as_u32;
		    }
		  tcp0->checksum = ip_csum_fold (sum0);
		}
	      tcp_packets++;
	      if (nat44_set_tcp_session_state_o2i
		  (sm, now, s0,
		   vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags,
		   vnet_buffer (b0)->ip.reass.tcp_ack_number,
		   vnet_buffer (b0)->ip.reass.tcp_seq_number, thread_index))
		goto trace0;
	    }
	  else if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment
		   && udp0->checksum)
	    {
	      new_port0 = udp0->dst_port = s0->in2out.port;
	      sum0 = udp0->checksum;
	      sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				     dst_address);
	      sum0 = ip_csum_update (sum0, old_port0, new_port0, ip4_header_t,
				     length);
	      if (PREDICT_FALSE (is_twice_nat_session (s0)))
		{
		  sum0 = ip_csum_update (sum0, ip0->src_address.as_u32,
					 s0->ext_host_nat_addr.as_u32,
					 ip4_header_t, dst_address);
		  sum0 =
		    ip_csum_update (sum0,
				    vnet_buffer (b0)->ip.reass.l4_src_port,
				    s0->ext_host_nat_port, ip4_header_t,
				    length);
		  udp0->src_port = s0->ext_host_nat_port;
		  ip0->src_address.as_u32 = s0->ext_host_nat_addr.as_u32;
		}
	      udp0->checksum = ip_csum_fold (sum0);
	      udp_packets++;
	    }
	  else
	    {
	      if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
		{
		  new_port0 = udp0->dst_port = s0->in2out.port;
		  if (PREDICT_FALSE (is_twice_nat_session (s0)))
		    {
		      udp0->src_port = s0->ext_host_nat_port;
		      ip0->src_address.as_u32 = s0->ext_host_nat_addr.as_u32;
		    }
		}
	      udp_packets++;
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
	      t->next_index = next0;
	      t->is_slow_path = 0;

	      if (s0)
		t->session_index = s0 - tsm->sessions;
	      else
		t->session_index = ~0;
	    }

	  pkts_processed += next0 == vnet_buffer2 (b0)->nat.arc_next;
	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_OUT2IN_ED_ERROR_OUT2IN_PACKETS,
			       pkts_processed);
  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_OUT2IN_ED_ERROR_TCP_PACKETS, tcp_packets);
  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_OUT2IN_ED_ERROR_UDP_PACKETS, udp_packets);
  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_OUT2IN_ED_ERROR_ICMP_PACKETS,
			       icmp_packets);
  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_OUT2IN_ED_ERROR_OTHER_PACKETS,
			       other_packets);
  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_OUT2IN_ED_ERROR_FRAGMENTS, fragments);
  return frame->n_vectors;
}

static inline uword
nat44_ed_out2in_slow_path_node_fn_inline (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, pkts_processed = 0, stats_node_index;
  nat_next_t next_index;
  snat_main_t *sm = &snat_main;
  // HERE
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  u32 tcp_packets = 0, udp_packets = 0, icmp_packets = 0, other_packets =
    0, fragments = 0;

  stats_node_index = sm->ed_out2in_slowpath_node_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0, sw_if_index0, rx_fib_index0, proto0, old_addr0,
	    new_addr0;
	  u16 old_port0, new_port0;
	  ip4_header_t *ip0;
	  udp_header_t *udp0;
	  tcp_header_t *tcp0;
	  icmp46_header_t *icmp0;
	  snat_session_t *s0 = 0;
	  clib_bihash_kv_16_8_t kv0, value0;
	  ip_csum_t sum0;
	  snat_session_key_t e_key0, l_key0;
	  lb_nat_type_t lb_nat0;
	  twice_nat_type_t twice_nat0;
	  u8 identity_nat0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  next0 = vnet_buffer2 (b0)->nat.arc_next;

	  vnet_buffer (b0)->snat.flags = 0;
	  ip0 = vlib_buffer_get_current (b0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  rx_fib_index0 =
	    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						 sw_if_index0);

	  if (PREDICT_FALSE (ip0->ttl == 1))
	    {
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      icmp4_error_set_vnet_buffer (b0, ICMP4_time_exceeded,
					   ICMP4_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      next0 = NAT_NEXT_ICMP_ERROR;
	      goto trace0;
	    }

	  udp0 = ip4_next_header (ip0);
	  tcp0 = (tcp_header_t *) udp0;
	  icmp0 = (icmp46_header_t *) udp0;
	  proto0 = ip_proto_to_nat_proto (ip0->protocol);

	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_OTHER))
	    {
	      s0 =
		nat44_ed_out2in_unknown_proto (sm, b0, ip0, rx_fib_index0,
					       thread_index, now, vm, node);
	      if (!sm->forwarding_enabled)
		{
		  if (!s0)
		    next0 = NAT_NEXT_DROP;
		}
	      other_packets++;
	      goto trace0;
	    }

	  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_ICMP))
	    {
	      next0 = icmp_out2in_ed_slow_path
		(sm, b0, ip0, icmp0, sw_if_index0, rx_fib_index0, node,
		 next0, now, thread_index, &s0);
	      icmp_packets++;
	      goto trace0;
	    }

	  make_ed_kv (&ip0->dst_address, &ip0->src_address,
		      ip0->protocol, rx_fib_index0,
		      vnet_buffer (b0)->ip.reass.l4_dst_port,
		      vnet_buffer (b0)->ip.reass.l4_src_port, ~0ULL, &kv0);

	  s0 = NULL;
	  if (!clib_bihash_search_16_8 (&tsm->out2in_ed, &kv0, &value0))
	    {
	      s0 = pool_elt_at_index (tsm->sessions, value0.value);

	      if (s0->tcp_closed_timestamp && now >= s0->tcp_closed_timestamp)
		{
		  nat_free_session_data (sm, s0, thread_index, 0);
		  nat_ed_session_delete (sm, s0, thread_index, 1);
		  s0 = NULL;
		}
	    }

	  if (!s0)
	    {
	      /* Try to match static mapping by external address and port,
	         destination address and port in packet */
	      e_key0.addr = ip0->dst_address;
	      e_key0.port = vnet_buffer (b0)->ip.reass.l4_dst_port;
	      e_key0.protocol = proto0;
	      e_key0.fib_index = rx_fib_index0;

	      if (snat_static_mapping_match (sm, e_key0, &l_key0, 1, 0,
					     &twice_nat0, &lb_nat0,
					     &ip0->src_address,
					     &identity_nat0))
		{
		  /*
		   * Send DHCP packets to the ipv4 stack, or we won't
		   * be able to use dhcp client on the outside interface
		   */
		  if (PREDICT_FALSE (proto0 == NAT_PROTOCOL_UDP
				     && (vnet_buffer (b0)->ip.
					 reass.l4_dst_port ==
					 clib_host_to_net_u16
					 (UDP_DST_PORT_dhcp_to_client))))
		    {
		      goto trace0;
		    }

		  if (!sm->forwarding_enabled)
		    {
		      b0->error =
			node->errors[NAT_OUT2IN_ED_ERROR_NO_TRANSLATION];
		      next0 = NAT_NEXT_DROP;
		    }
		  else
		    {
		      if (next_src_nat
			  (sm, ip0, vnet_buffer (b0)->ip.reass.l4_src_port,
			   vnet_buffer (b0)->ip.reass.l4_dst_port,
			   thread_index, rx_fib_index0))
			{
			  next0 = NAT_NEXT_IN2OUT_ED_FAST_PATH;
			  goto trace0;
			}
		      if (sm->num_workers > 1)
			create_bypass_for_fwd_worker (sm, b0, ip0,
						      rx_fib_index0);
		      else
			create_bypass_for_fwd (sm, b0, ip0, rx_fib_index0,
					       thread_index);
		    }
		  goto trace0;
		}

	      if (PREDICT_FALSE (identity_nat0))
		goto trace0;

	      if ((proto0 == NAT_PROTOCOL_TCP)
		  && !tcp_flags_is_init (vnet_buffer (b0)->ip.
					 reass.icmp_type_or_tcp_flags))
		{
		  b0->error = node->errors[NAT_OUT2IN_ED_ERROR_NON_SYN];
		  next0 = NAT_NEXT_DROP;
		  goto trace0;
		}

	      /* Create session initiated by host from external network */
	      s0 = create_session_for_static_mapping_ed (sm, b0, l_key0,
							 e_key0, node,
							 rx_fib_index0,
							 thread_index,
							 twice_nat0,
							 lb_nat0, now);
	      if (!s0)
		{
		  next0 = NAT_NEXT_DROP;
		  goto trace0;
		}
	    }

	  old_addr0 = ip0->dst_address.as_u32;
	  new_addr0 = ip0->dst_address.as_u32 = s0->in2out.addr.as_u32;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->in2out.fib_index;

	  sum0 = ip0->checksum;
	  sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				 dst_address);
	  if (PREDICT_FALSE (is_twice_nat_session (s0)))
	    sum0 = ip_csum_update (sum0, ip0->src_address.as_u32,
				   s0->ext_host_nat_addr.as_u32, ip4_header_t,
				   src_address);
	  ip0->checksum = ip_csum_fold (sum0);

	  old_port0 = vnet_buffer (b0)->ip.reass.l4_dst_port;

	  if (PREDICT_TRUE (proto0 == NAT_PROTOCOL_TCP))
	    {
	      if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
		{
		  new_port0 = udp0->dst_port = s0->in2out.port;
		  sum0 = tcp0->checksum;
		  sum0 =
		    ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				    dst_address);
		  sum0 =
		    ip_csum_update (sum0, old_port0, new_port0, ip4_header_t,
				    length);
		  if (is_twice_nat_session (s0))
		    {
		      sum0 = ip_csum_update (sum0, ip0->src_address.as_u32,
					     s0->ext_host_nat_addr.as_u32,
					     ip4_header_t, dst_address);
		      sum0 =
			ip_csum_update (sum0,
					vnet_buffer (b0)->ip.
					reass.l4_src_port,
					s0->ext_host_nat_port, ip4_header_t,
					length);
		      tcp0->src_port = s0->ext_host_nat_port;
		      ip0->src_address.as_u32 = s0->ext_host_nat_addr.as_u32;
		    }
		  tcp0->checksum = ip_csum_fold (sum0);
		}
	      tcp_packets++;
	      if (nat44_set_tcp_session_state_o2i
		  (sm, now, s0,
		   vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags,
		   vnet_buffer (b0)->ip.reass.tcp_ack_number,
		   vnet_buffer (b0)->ip.reass.tcp_seq_number, thread_index))
		goto trace0;
	    }
	  else if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment
		   && udp0->checksum)
	    {
	      new_port0 = udp0->dst_port = s0->in2out.port;
	      sum0 = udp0->checksum;
	      sum0 = ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				     dst_address);
	      sum0 = ip_csum_update (sum0, old_port0, new_port0, ip4_header_t,
				     length);
	      if (PREDICT_FALSE (is_twice_nat_session (s0)))
		{
		  sum0 = ip_csum_update (sum0, ip0->src_address.as_u32,
					 s0->ext_host_nat_addr.as_u32,
					 ip4_header_t, dst_address);
		  sum0 =
		    ip_csum_update (sum0,
				    vnet_buffer (b0)->ip.reass.l4_src_port,
				    s0->ext_host_nat_port, ip4_header_t,
				    length);
		  udp0->src_port = s0->ext_host_nat_port;
		  ip0->src_address.as_u32 = s0->ext_host_nat_addr.as_u32;
		}
	      udp0->checksum = ip_csum_fold (sum0);
	      udp_packets++;
	    }
	  else
	    {
	      if (!vnet_buffer (b0)->ip.reass.is_non_first_fragment)
		{
		  new_port0 = udp0->dst_port = s0->in2out.port;
		  if (PREDICT_FALSE (is_twice_nat_session (s0)))
		    {
		      udp0->src_port = s0->ext_host_nat_port;
		      ip0->src_address.as_u32 = s0->ext_host_nat_addr.as_u32;
		    }
		}
	      udp_packets++;
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
	      t->next_index = next0;
	      t->is_slow_path = 1;

	      if (s0)
		t->session_index = s0 - tsm->sessions;
	      else
		t->session_index = ~0;
	    }

	  pkts_processed += next0 == vnet_buffer2 (b0)->nat.arc_next;
	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_OUT2IN_ED_ERROR_OUT2IN_PACKETS,
			       pkts_processed);
  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_OUT2IN_ED_ERROR_TCP_PACKETS, tcp_packets);
  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_OUT2IN_ED_ERROR_UDP_PACKETS, udp_packets);
  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_OUT2IN_ED_ERROR_ICMP_PACKETS,
			       icmp_packets);
  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_OUT2IN_ED_ERROR_OTHER_PACKETS,
			       other_packets);
  vlib_node_increment_counter (vm, stats_node_index,
			       NAT_OUT2IN_ED_ERROR_FRAGMENTS, fragments);
  return frame->n_vectors;
}

VLIB_NODE_FN (nat44_ed_out2in_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return nat44_ed_out2in_fast_path_node_fn_inline (vm, node, frame);
}

/* *INDENT-OFF* */
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
/* *INDENT-ON* */

VLIB_NODE_FN (nat44_ed_out2in_slowpath_node) (vlib_main_t * vm,
					      vlib_node_runtime_t * node,
					      vlib_frame_t * frame)
{
  return nat44_ed_out2in_slow_path_node_fn_inline (vm, node, frame);
}

/* *INDENT-OFF* */
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
/* *INDENT-ON* */

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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat_pre_out2in_node) = {
  .name = "nat-pre-out2in",
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
