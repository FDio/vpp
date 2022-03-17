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

#include <nat/nat44-ed/nat44_ed.h>
#include <nat/nat44-ed/nat44_ed_inlines.h>

u8 *
format_ed_session_kvp (u8 *s, va_list *args)
{
  clib_bihash_kv_16_8_t *v = va_arg (*args, clib_bihash_kv_16_8_t *);

  u8 proto;
  u16 r_port, l_port;
  ip4_address_t l_addr, r_addr;
  u32 fib_index;

  split_ed_kv (v, &l_addr, &r_addr, &proto, &fib_index, &l_port, &r_port);
  s = format (s,
	      "local %U:%d remote %U:%d proto %U fib %d thread-index %u "
	      "session-index %u",
	      format_ip4_address, &l_addr, clib_net_to_host_u16 (l_port),
	      format_ip4_address, &r_addr, clib_net_to_host_u16 (r_port),
	      format_ip_protocol, proto, fib_index,
	      ed_value_get_thread_index (v), ed_value_get_session_index (v));

  return s;
}

u8 *
format_snat_session (u8 * s, va_list * args)
{
  snat_main_t *sm = va_arg (*args, snat_main_t *);
  snat_main_per_thread_data_t *tsm =
    va_arg (*args, snat_main_per_thread_data_t *);
  snat_session_t *sess = va_arg (*args, snat_session_t *);
  f64 now = va_arg (*args, f64);

  if (nat44_ed_is_unk_proto (sess->proto))
    {
      s = format (s, "  i2o %U proto %u fib %u\n",
		  format_ip4_address, &sess->in2out.addr,
		  sess->in2out.port, sess->in2out.fib_index);
      s =
	format (s, "    o2i %U proto %u fib %u\n", format_ip4_address,
		&sess->out2in.addr, sess->out2in.port, sess->out2in.fib_index);
    }
  else
    {
      s = format (s, "  i2o %U proto %U port %d fib %d\n", format_ip4_address,
		  &sess->in2out.addr, format_ip_protocol, sess->proto,
		  clib_net_to_host_u16 (sess->in2out.port),
		  sess->in2out.fib_index);
      s = format (s, "    o2i %U proto %U port %d fib %d\n",
		  format_ip4_address, &sess->out2in.addr, format_ip_protocol,
		  sess->proto, clib_net_to_host_u16 (sess->out2in.port),
		  sess->out2in.fib_index);
    }
  if (nat44_ed_is_twice_nat_session (sess))
    {
      s = format (s, "       external host o2i %U:%d i2o %U:%d\n",
		  format_ip4_address, &sess->ext_host_addr,
		  clib_net_to_host_u16 (sess->ext_host_port),
		  format_ip4_address, &sess->ext_host_nat_addr,
		  clib_net_to_host_u16 (sess->ext_host_nat_port));
    }
      else
	{
	  if (sess->ext_host_addr.as_u32)
	    s = format (s, "       external host %U:%u\n",
			format_ip4_address, &sess->ext_host_addr,
			clib_net_to_host_u16 (sess->ext_host_port));
	}
      s = format (s, "       i2o flow: %U\n", format_nat_6t_flow, &sess->i2o);
      s = format (s, "       o2i flow: %U\n", format_nat_6t_flow, &sess->o2i);
  s = format (s, "       index %llu\n", sess - tsm->sessions);
  s = format (s, "       last heard %.2f\n", sess->last_heard);
  s = format (s, "       timeout in %.2f\n",
	      nat44_session_get_timeout (sm, sess) - (now - sess->last_heard));
  s = format (s, "       total pkts %d, total bytes %lld\n", sess->total_pkts,
	      sess->total_bytes);
  if (nat44_ed_is_session_static (sess))
    s = format (s, "       static translation\n");
  else
    s = format (s, "       dynamic translation\n");
  if (na44_ed_is_fwd_bypass_session (sess))
    s = format (s, "       forwarding-bypass\n");
  if (nat44_ed_is_lb_session (sess))
    s = format (s, "       load-balancing\n");
  if (nat44_ed_is_twice_nat_session (sess))
    s = format (s, "       twice-nat\n");
  return s;
}

u8 *
format_snat_static_mapping (u8 * s, va_list * args)
{
  snat_static_mapping_t *m = va_arg (*args, snat_static_mapping_t *);
  nat44_lb_addr_port_t *local;

  if (is_sm_identity_nat (m->flags))
    {
      if (is_sm_addr_only (m->flags))
	s = format (s, "identity mapping %U",
		    format_ip4_address, &m->local_addr);
      else
	s = format (s, "identity mapping %U %U:%d", format_ip_protocol,
		    m->proto, format_ip4_address, &m->local_addr,
		    clib_net_to_host_u16 (m->local_port));

      pool_foreach (local, m->locals)
       {
        s = format (s, " vrf %d", local->vrf_id);
      }

      return s;
    }

  if (is_sm_addr_only (m->flags))
    s =
      format (s, "local %U external %U vrf %d %s %s", format_ip4_address,
	      &m->local_addr, format_ip4_address, &m->external_addr, m->vrf_id,
	      is_sm_twice_nat (m->flags) ?
		"twice-nat" :
		is_sm_self_twice_nat (m->flags) ? "self-twice-nat" : "",
	      is_sm_out2in_only (m->flags) ? "out2in-only" : "");
  else
    {
      if (is_sm_lb (m->flags))
	{
	  s =
	    format (s, "%U external %U:%d %s %s", format_ip_protocol, m->proto,
		    format_ip4_address, &m->external_addr,
		    clib_net_to_host_u16 (m->external_port),
		    is_sm_twice_nat (m->flags) ?
		      "twice-nat" :
		      is_sm_self_twice_nat (m->flags) ? "self-twice-nat" : "",
		    is_sm_out2in_only (m->flags) ? "out2in-only" : "");

	  pool_foreach (local, m->locals)
	    {
	      s = format (s, "\n  local %U:%d vrf %d probability %d\%",
			  format_ip4_address, &local->addr,
			  clib_net_to_host_u16 (local->port), local->vrf_id,
			  local->probability);
	    }
	}
      else
	s = format (s, "%U local %U:%d external %U:%d vrf %d %s %s",
		    format_ip_protocol, m->proto, format_ip4_address,
		    &m->local_addr, clib_net_to_host_u16 (m->local_port),
		    format_ip4_address, &m->external_addr,
		    clib_net_to_host_u16 (m->external_port), m->vrf_id,
		    is_sm_twice_nat (m->flags) ?
		      "twice-nat" :
		      is_sm_self_twice_nat (m->flags) ? "self-twice-nat" : "",
		    is_sm_out2in_only (m->flags) ? "out2in-only" : "");
    }
  return s;
}

u8 *
format_snat_static_map_to_resolve (u8 * s, va_list * args)
{
  snat_static_mapping_resolve_t *m =
    va_arg (*args, snat_static_mapping_resolve_t *);
  vnet_main_t *vnm = vnet_get_main ();

  if (is_sm_addr_only (m->flags))
    s = format (s, "local %U external %U vrf %d",
		format_ip4_address, &m->l_addr,
		format_vnet_sw_if_index_name, vnm, m->sw_if_index, m->vrf_id);
  else
    s = format (s, "%U local %U:%d external %U:%d vrf %d", format_ip_protocol,
		m->proto, format_ip4_address, &m->l_addr,
		clib_net_to_host_u16 (m->l_port), format_vnet_sw_if_index_name,
		vnm, m->sw_if_index, clib_net_to_host_u16 (m->e_port),
		m->vrf_id);

  return s;
}

u8 *
format_nat_ed_translation_error (u8 *s, va_list *args)
{
  nat_translation_error_e e = va_arg (*args, nat_translation_error_e);

  switch (e)
    {
    case NAT_ED_TRNSL_ERR_SUCCESS:
      s = format (s, "success");
      break;
    case NAT_ED_TRNSL_ERR_TRANSLATION_FAILED:
      s = format (s, "translation-failed");
      break;
    case NAT_ED_TRNSL_ERR_FLOW_MISMATCH:
      s = format (s, "flow-mismatch");
      break;
    case NAT_ED_TRNSL_ERR_PACKET_TRUNCATED:
      s = format (s, "packet-truncated");
      break;
    case NAT_ED_TRNSL_ERR_INNER_IP_CORRUPT:
      s = format (s, "inner-ip-corrupted");
      break;
    case NAT_ED_TRNSL_ERR_INVALID_CSUM:
      s = format (s, "invalid-checksum");
      break;
    }
  return s;
}

u8 *
format_nat_6t_flow (u8 *s, va_list *args)
{
  nat_6t_flow_t *f = va_arg (*args, nat_6t_flow_t *);

  s = format (s, "match: %U ", format_nat_6t, &f->match);
  int r = 0;
  if (f->ops & NAT_FLOW_OP_SADDR_REWRITE)
    {
      s = format (s, "rewrite: saddr %U ", format_ip4_address,
		  f->rewrite.saddr.as_u8);
      r = 1;
    }
  if (f->ops & NAT_FLOW_OP_SPORT_REWRITE)
    {
      if (!r)
	{
	  s = format (s, "rewrite: ");
	  r = 1;
	}
      s = format (s, "sport %u ", clib_net_to_host_u16 (f->rewrite.sport));
    }
  if (f->ops & NAT_FLOW_OP_DADDR_REWRITE)
    {
      if (!r)
	{
	  s = format (s, "rewrite: ");
	  r = 1;
	}
      s = format (s, "daddr %U ", format_ip4_address, f->rewrite.daddr.as_u8);
    }
  if (f->ops & NAT_FLOW_OP_DPORT_REWRITE)
    {
      if (!r)
	{
	  s = format (s, "rewrite: ");
	  r = 1;
	}
      s = format (s, "dport %u ", clib_net_to_host_u16 (f->rewrite.dport));
    }
  if (f->ops & NAT_FLOW_OP_ICMP_ID_REWRITE)
    {
      if (!r)
	{
	  s = format (s, "rewrite: ");
	  r = 1;
	}
      s = format (s, "icmp-id %u ", clib_net_to_host_u16 (f->rewrite.icmp_id));
    }
  if (f->ops & NAT_FLOW_OP_TXFIB_REWRITE)
    {
      if (!r)
	{
	  s = format (s, "rewrite: ");
	  r = 1;
	}
      s = format (s, "txfib %u ", f->rewrite.fib_index);
    }
  return s;
}

u8 *
format_nat_6t (u8 *s, va_list *args)
{
  nat_6t_t *t = va_arg (*args, nat_6t_t *);

  s = format (s, "saddr %U sport %u daddr %U dport %u proto %U fib_idx %u",
	      format_ip4_address, t->saddr.as_u8,
	      clib_net_to_host_u16 (t->sport), format_ip4_address,
	      t->daddr.as_u8, clib_net_to_host_u16 (t->dport),
	      format_ip_protocol, t->proto, t->fib_index);
  return s;
}

u8 *
format_nat44_ed_tcp_state (u8 *s, va_list *args)
{
  nat44_ed_tcp_state_e e = va_arg (*args, nat44_ed_tcp_state_e);
  switch (e)
    {
    case NAT44_ED_TCP_STATE_CLOSED:
      s = format (s, "closed");
      break;
    case NAT44_ED_TCP_STATE_ESTABLISHED:
      s = format (s, "established");
      break;
    case NAT44_ED_TCP_STATE_CLOSING:
      s = format (s, "closing");
      break;
    case NAT44_ED_TCP_N_STATE:
      s = format (s, "BUG! unexpected N_STATE! BUG!");
      break;
    }
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
