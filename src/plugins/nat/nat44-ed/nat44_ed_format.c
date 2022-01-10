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
 * @brief NAT formatting
 */

#include <nat/nat44-ed/nat44_ed.h>
#include <nat/nat44-ed/nat44_ed_inlines.h>

u8 *
format_nat_addr_and_port_alloc_alg (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v, N, s) case NAT_ADDR_AND_PORT_ALLOC_ALG_##N: t = (u8 *) s; break;
      foreach_nat_addr_and_port_alloc_alg
#undef _
    default:
      s = format (s, "unknown");
      return s;
    }
  s = format (s, "%s", t);
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
