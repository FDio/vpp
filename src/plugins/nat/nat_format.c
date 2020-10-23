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

#include <nat/nat.h>
#include <nat/nat_inlines.h>

uword
unformat_nat_protocol (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(N, i, n, s) else if (unformat (input, s)) *r = NAT_PROTOCOL_##N;
  foreach_nat_protocol
#undef _
    else
    return 0;
  return 1;
}

u8 *
format_nat_protocol (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(N, j, n, str) case NAT_PROTOCOL_##N: t = (u8 *) str; break;
      foreach_nat_protocol
#undef _
    default:
      s = format (s, "unknown");
      return s;
    }
  s = format (s, "%s", t);
  return s;
}

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
format_snat_key (u8 * s, va_list * args)
{
  u64 key = va_arg (*args, u64);

  ip4_address_t addr;
  u16 port;
  nat_protocol_t protocol;
  u32 fib_index;

  split_nat_key (key, &addr, &port, &fib_index, &protocol);

  s = format (s, "%U proto %U port %d fib %d",
	      format_ip4_address, &addr,
	      format_nat_protocol, protocol,
	      clib_net_to_host_u16 (port), fib_index);
  return s;
}

u8 *
format_snat_session_state (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v, N, str) case SNAT_SESSION_##N: t = (u8 *) str; break;
      foreach_snat_session_state
#undef _
    default:
      t = format (t, "unknown");
    }
  s = format (s, "%s", t);
  return s;
}

u8 *
format_snat_session (u8 * s, va_list * args)
{
  snat_main_per_thread_data_t *tsm =
    va_arg (*args, snat_main_per_thread_data_t *);
  snat_session_t *sess = va_arg (*args, snat_session_t *);

  if (snat_is_unk_proto_session (sess))
    {
      s = format (s, "  i2o %U proto %u fib %u\n",
		  format_ip4_address, &sess->in2out.addr,
		  sess->in2out.port, sess->in2out.fib_index);
      s = format (s, "    o2i %U proto %u fib %u\n",
		  format_ip4_address, &sess->out2in.addr,
		  sess->out2in.port, sess->out2in.fib_index);
    }
  else
    {
      s = format (s, "  i2o %U proto %U port %d fib %d\n",
		  format_ip4_address, &sess->in2out.addr,
		  format_nat_protocol, sess->nat_proto,
		  clib_net_to_host_u16 (sess->in2out.port),
		  sess->in2out.fib_index);
      s = format (s, "    o2i %U proto %U port %d fib %d\n",
		  format_ip4_address, &sess->out2in.addr,
		  format_nat_protocol, sess->nat_proto,
		  clib_net_to_host_u16 (sess->out2in.port),
		  sess->out2in.fib_index);
    }
  if (is_ed_session (sess) || is_fwd_bypass_session (sess))
    {
      if (is_twice_nat_session (sess))
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
    }
  s = format (s, "       index %llu\n", sess - tsm->sessions);
  s = format (s, "       last heard %.2f\n", sess->last_heard);
  s = format (s, "       total pkts %d, total bytes %lld\n",
	      sess->total_pkts, sess->total_bytes);
  if (snat_is_session_static (sess))
    s = format (s, "       static translation\n");
  else
    s = format (s, "       dynamic translation\n");
  if (is_fwd_bypass_session (sess))
    s = format (s, "       forwarding-bypass\n");
  if (is_lb_session (sess))
    s = format (s, "       load-balancing\n");
  if (is_twice_nat_session (sess))
    s = format (s, "       twice-nat\n");

  return s;
}

u8 *
format_snat_user (u8 * s, va_list * args)
{
  snat_main_per_thread_data_t *tsm =
    va_arg (*args, snat_main_per_thread_data_t *);
  snat_user_t *u = va_arg (*args, snat_user_t *);
  int verbose = va_arg (*args, int);
  dlist_elt_t *head, *elt;
  u32 elt_index, head_index;
  u32 session_index;
  snat_session_t *sess;

  s = format (s, "%U: %d dynamic translations, %d static translations\n",
	      format_ip4_address, &u->addr, u->nsessions, u->nstaticsessions);

  if (verbose == 0)
    return s;

  if (u->nsessions || u->nstaticsessions)
    {
      head_index = u->sessions_per_user_list_head_index;
      head = pool_elt_at_index (tsm->list_pool, head_index);

      elt_index = head->next;
      elt = pool_elt_at_index (tsm->list_pool, elt_index);
      session_index = elt->value;

      while (session_index != ~0)
	{
	  sess = pool_elt_at_index (tsm->sessions, session_index);

	  s = format (s, "  %U\n", format_snat_session, tsm, sess);

	  elt_index = elt->next;
	  elt = pool_elt_at_index (tsm->list_pool, elt_index);
	  session_index = elt->value;
	}
    }

  return s;
}

u8 *
format_snat_static_mapping (u8 * s, va_list * args)
{
  snat_static_mapping_t *m = va_arg (*args, snat_static_mapping_t *);
  nat44_lb_addr_port_t *local;

  if (is_identity_static_mapping (m))
    {
      if (is_addr_only_static_mapping (m))
	s = format (s, "identity mapping %U",
		    format_ip4_address, &m->local_addr);
      else
	s = format (s, "identity mapping %U %U:%d",
		    format_nat_protocol, m->proto,
		    format_ip4_address, &m->local_addr,
		    clib_net_to_host_u16 (m->local_port));

      /* *INDENT-OFF* */
      pool_foreach (local, m->locals,
      ({
        s = format (s, " vrf %d", local->vrf_id);
      }));
      /* *INDENT-ON* */

      return s;
    }

  if (is_addr_only_static_mapping (m))
    s = format (s, "local %U external %U vrf %d %s %s",
		format_ip4_address, &m->local_addr,
		format_ip4_address, &m->external_addr,
		m->vrf_id,
		m->twice_nat == TWICE_NAT ? "twice-nat" :
		m->twice_nat == TWICE_NAT_SELF ? "self-twice-nat" : "",
		is_out2in_only_static_mapping (m) ? "out2in-only" : "");
  else
    {
      if (is_lb_static_mapping (m))
	{
	  s = format (s, "%U external %U:%d %s %s",
		      format_nat_protocol, m->proto,
		      format_ip4_address, &m->external_addr,
		      clib_net_to_host_u16 (m->external_port),
		      m->twice_nat == TWICE_NAT ? "twice-nat" :
		      m->twice_nat == TWICE_NAT_SELF ? "self-twice-nat" : "",
		      is_out2in_only_static_mapping (m) ? "out2in-only" : "");

          /* *INDENT-OFF* */
          pool_foreach (local, m->locals,
          ({
	    s = format (s, "\n  local %U:%d vrf %d probability %d\%",
			format_ip4_address, &local->addr,
                        clib_net_to_host_u16 (local->port),
			local->vrf_id, local->probability);
          }));
          /* *INDENT-ON* */

	}
      else
	s = format (s, "%U local %U:%d external %U:%d vrf %d %s %s",
		    format_nat_protocol, m->proto,
		    format_ip4_address, &m->local_addr,
		    clib_net_to_host_u16 (m->local_port),
		    format_ip4_address, &m->external_addr,
		    clib_net_to_host_u16 (m->external_port),
		    m->vrf_id,
		    m->twice_nat == TWICE_NAT ? "twice-nat" :
		    m->twice_nat == TWICE_NAT_SELF ? "self-twice-nat" : "",
		    is_out2in_only_static_mapping (m) ? "out2in-only" : "");
    }
  return s;
}

u8 *
format_snat_static_map_to_resolve (u8 * s, va_list * args)
{
  snat_static_map_resolve_t *m = va_arg (*args, snat_static_map_resolve_t *);
  vnet_main_t *vnm = vnet_get_main ();

  if (m->addr_only)
    s = format (s, "local %U external %U vrf %d",
		format_ip4_address, &m->l_addr,
		format_vnet_sw_if_index_name, vnm, m->sw_if_index, m->vrf_id);
  else
    s = format (s, "%U local %U:%d external %U:%d vrf %d",
		format_nat_protocol, m->proto,
		format_ip4_address, &m->l_addr,
		clib_net_to_host_u16 (m->l_port),
		format_vnet_sw_if_index_name, vnm, m->sw_if_index,
		clib_net_to_host_u16 (m->e_port), m->vrf_id);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
