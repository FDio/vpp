/*
 * nat44_ei.c - nat44 endpoint dependent plugin
 *
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/plugin/plugin.h>
#include <nat/nat.h>
#include <nat/nat_dpo.h>
#include <nat/lib/ipfix_logging.h>
#include <nat/lib/nat_syslog.h>
#include <nat/nat_inlines.h>
#include <nat/nat44/inlines.h>
#include <nat/nat_affinity.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vppinfra/bihash_16_8.h>
#include <nat/nat44/ed_inlines.h>
#include <vnet/ip/ip_table.h>

#include <nat/nat44-ei/nat44_ei_inlines.h>
#include <nat/nat44-ei/nat44_ei.h>

nat44_ei_main_t nat44_ei_main;

static void nat44_ei_db_free ();

static void nat44_ei_db_init (u32 translations, u32 translation_buckets,
			      u32 user_buckets);

int
nat44_ei_plugin_enable (nat44_ei_config_t c)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  snat_main_t *sm = &snat_main;

  clib_memset (nm, 0, sizeof (*nm));

  if (!c.users)
    c.users = 1024;

  if (!c.sessions)
    c.sessions = 10 * 1024;

  nm->rconfig = c;

  nm->translations = c.sessions;
  nm->translation_buckets = nat_calc_bihash_buckets (c.sessions);
  nm->user_buckets = nat_calc_bihash_buckets (c.users);

  // OBSOLETE

  sm->static_mapping_only = c.static_mapping_only;
  sm->static_mapping_connection_tracking = c.connection_tracking;
  sm->out2in_dpo = c.out2in_dpo;
  sm->forwarding_enabled = 0;
  sm->mss_clamping = 0;
  sm->pat = (!c.static_mapping_only ||
	     (c.static_mapping_only && c.connection_tracking));

  sm->max_users_per_thread = c.users;
  sm->max_translations_per_thread = c.sessions;
  sm->translation_buckets = nat_calc_bihash_buckets (c.sessions);
  sm->max_translations_per_user =
    c.user_sessions ? c.user_sessions : sm->max_translations_per_thread;

  sm->inside_vrf_id = c.inside_vrf;
  sm->inside_fib_index = fib_table_find_or_create_and_lock (
    FIB_PROTOCOL_IP4, c.inside_vrf, sm->fib_src_hi);

  sm->outside_vrf_id = c.outside_vrf;
  sm->outside_fib_index = fib_table_find_or_create_and_lock (
    FIB_PROTOCOL_IP4, c.outside_vrf, sm->fib_src_hi);

  sm->worker_in2out_cb = nat44_ei_get_in2out_worker_index;
  sm->worker_out2in_cb = nat44_ei_get_out2in_worker_index;

  sm->in2out_node_index = sm->ei_in2out_node_index;
  sm->out2in_node_index = sm->ei_out2in_node_index;

  sm->in2out_output_node_index = sm->ei_in2out_output_node_index;

  if (sm->pat)
    {
      sm->icmp_match_in2out_cb = icmp_match_in2out_slow;
      sm->icmp_match_out2in_cb = icmp_match_out2in_slow;
    }
  else
    {
      sm->icmp_match_in2out_cb = icmp_match_in2out_fast;
      sm->icmp_match_out2in_cb = icmp_match_out2in_fast;
    }

  nat_reset_timeouts (&sm->timeouts);
  nat44_ei_db_init (nm->translations, nm->translation_buckets,
		    nm->user_buckets);
  nat44_ei_set_alloc_default ();
  nat_ha_enable ();

  // TODO: function for reset counters
  vlib_zero_simple_counter (&sm->total_users, 0);
  vlib_zero_simple_counter (&sm->total_sessions, 0);
  vlib_zero_simple_counter (&sm->user_limit_reached, 0);

  if (!sm->frame_queue_nelts)
    sm->frame_queue_nelts = NAT_FQ_NELTS_DEFAULT;

  sm->enabled = 1;

  return 0;
}

int
nat44_ei_plugin_disable ()
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  snat_main_t *sm = &snat_main;
  snat_interface_t *i, *vec;
  int error = 0;

  // first unregister all nodes from interfaces
  vec = vec_dup (sm->interfaces);
  vec_foreach (i, vec)
    {
      if (nat_interface_is_inside (i))
	error = snat_interface_add_del (i->sw_if_index, 1, 1);
      if (nat_interface_is_outside (i))
	error = snat_interface_add_del (i->sw_if_index, 0, 1);

      if (error)
	{
	  nat_log_err ("error occurred while removing interface %u",
		       i->sw_if_index);
	}
    }
  vec_free (vec);
  sm->interfaces = 0;

  vec = vec_dup (sm->output_feature_interfaces);
  vec_foreach (i, vec)
    {
      if (nat_interface_is_inside (i))
	error = snat_interface_add_del_output_feature (i->sw_if_index, 1, 1);
      if (nat_interface_is_outside (i))
	error = snat_interface_add_del_output_feature (i->sw_if_index, 0, 1);

      if (error)
	{
	  nat_log_err ("error occurred while removing interface %u",
		       i->sw_if_index);
	}
    }
  vec_free (vec);
  sm->output_feature_interfaces = 0;

  nat_ha_disable ();
  nat44_ei_db_free ();

  nat44_addresses_free (&sm->addresses);
  nat44_addresses_free (&sm->twice_nat_addresses);

  vec_free (sm->to_resolve);
  vec_free (sm->auto_add_sw_if_indices);
  vec_free (sm->auto_add_sw_if_indices_twice_nat);

  sm->to_resolve = 0;
  sm->auto_add_sw_if_indices = 0;
  sm->auto_add_sw_if_indices_twice_nat = 0;

  sm->forwarding_enabled = 0;

  sm->enabled = 0;
  clib_memset (&nm->rconfig, 0, sizeof (nm->rconfig));
  clib_memset (&sm->rconfig, 0, sizeof (sm->rconfig));

  return error;
}

void
nat44_ei_free_session_data (snat_main_t *sm, snat_session_t *s,
			    u32 thread_index, u8 is_ha)
{
  clib_bihash_kv_8_8_t kv;

  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_index);

  init_nat_i2o_k (&kv, s);
  if (clib_bihash_add_del_8_8 (&tsm->in2out, &kv, 0))
    nat_elog_warn ("in2out key del failed");

  init_nat_o2i_k (&kv, s);
  if (clib_bihash_add_del_8_8 (&tsm->out2in, &kv, 0))
    nat_elog_warn ("out2in key del failed");

  if (!is_ha)
    {
      nat_syslog_nat44_apmdel (s->user_index, s->in2out.fib_index,
			       &s->in2out.addr, s->in2out.port,
			       &s->out2in.addr, s->out2in.port, s->nat_proto);

      nat_ipfix_logging_nat44_ses_delete (
	thread_index, s->in2out.addr.as_u32, s->out2in.addr.as_u32,
	s->nat_proto, s->in2out.port, s->out2in.port, s->in2out.fib_index);

      nat_ha_sdel (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
		   s->ext_host_port, s->nat_proto, s->out2in.fib_index,
		   thread_index);
    }

  if (snat_is_session_static (s))
    return;

  snat_free_outside_address_and_port (sm->addresses, thread_index,
				      &s->out2in.addr, s->out2in.port,
				      s->nat_proto);
}

static_always_inline void
nat44_ei_user_del_sessions (snat_user_t *u, u32 thread_index)
{
  dlist_elt_t *elt;
  snat_session_t *s;

  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  // get head
  elt =
    pool_elt_at_index (tsm->list_pool, u->sessions_per_user_list_head_index);
  // get first element
  elt = pool_elt_at_index (tsm->list_pool, elt->next);

  while (elt->value != ~0)
    {
      s = pool_elt_at_index (tsm->sessions, elt->value);
      elt = pool_elt_at_index (tsm->list_pool, elt->next);

      nat44_ei_free_session_data (sm, s, thread_index, 0);
      nat44_delete_session (sm, s, thread_index);
    }
}

int
nat44_ei_user_del (ip4_address_t *addr, u32 fib_index)
{
  int rv = 1;

  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;

  snat_user_key_t user_key;
  clib_bihash_kv_8_8_t kv, value;

  if (sm->endpoint_dependent)
    return rv;

  user_key.addr.as_u32 = addr->as_u32;
  user_key.fib_index = fib_index;
  kv.key = user_key.as_u64;

  if (sm->num_workers > 1)
    {
      vec_foreach (tsm, sm->per_thread_data)
	{
	  if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
	    {
	      nat44_ei_user_del_sessions (
		pool_elt_at_index (tsm->users, value.value),
		tsm->thread_index);
	      rv = 0;
	      break;
	    }
	}
    }
  else
    {
      tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);
      if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
	{
	  nat44_ei_user_del_sessions (
	    pool_elt_at_index (tsm->users, value.value), tsm->thread_index);
	  rv = 0;
	}
    }
  return rv;
}

void
nat44_ei_static_mapping_del_sessions (snat_main_t *sm,
				      snat_main_per_thread_data_t *tsm,
				      snat_user_key_t u_key, int addr_only,
				      ip4_address_t e_addr, u16 e_port)
{
  clib_bihash_kv_8_8_t kv, value;
  kv.key = u_key.as_u64;
  u64 user_index;
  dlist_elt_t *head, *elt;
  snat_user_t *u;
  snat_session_t *s;
  u32 elt_index, head_index, ses_index;

  if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
    {
      user_index = value.value;
      u = pool_elt_at_index (tsm->users, user_index);
      if (u->nstaticsessions)
	{
	  head_index = u->sessions_per_user_list_head_index;
	  head = pool_elt_at_index (tsm->list_pool, head_index);
	  elt_index = head->next;
	  elt = pool_elt_at_index (tsm->list_pool, elt_index);
	  ses_index = elt->value;
	  while (ses_index != ~0)
	    {
	      s = pool_elt_at_index (tsm->sessions, ses_index);
	      elt = pool_elt_at_index (tsm->list_pool, elt->next);
	      ses_index = elt->value;

	      if (!addr_only)
		{
		  if ((s->out2in.addr.as_u32 != e_addr.as_u32) ||
		      (s->out2in.port != e_port))
		    continue;
		}

	      if (is_lb_session (s))
		continue;

	      if (!snat_is_session_static (s))
		continue;

	      nat_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
	      nat44_delete_session (sm, s, tsm - sm->per_thread_data);

	      if (!addr_only)
		break;
	    }
	}
    }
}

u32
nat44_ei_get_in2out_worker_index (ip4_header_t *ip0, u32 rx_fib_index0,
				  u8 is_output)
{
  snat_main_t *sm = &snat_main;
  u32 next_worker_index = 0;
  u32 hash;

  next_worker_index = sm->first_worker_index;
  hash = ip0->src_address.as_u32 + (ip0->src_address.as_u32 >> 8) +
	 (ip0->src_address.as_u32 >> 16) + (ip0->src_address.as_u32 >> 24);

  if (PREDICT_TRUE (is_pow2 (_vec_len (sm->workers))))
    next_worker_index += sm->workers[hash & (_vec_len (sm->workers) - 1)];
  else
    next_worker_index += sm->workers[hash % _vec_len (sm->workers)];

  return next_worker_index;
}

u32
nat44_ei_get_out2in_worker_index (vlib_buffer_t *b, ip4_header_t *ip0,
				  u32 rx_fib_index0, u8 is_output)
{
  snat_main_t *sm = &snat_main;
  udp_header_t *udp;
  u16 port;
  clib_bihash_kv_8_8_t kv, value;
  snat_static_mapping_t *m;
  u32 proto;
  u32 next_worker_index = 0;

  /* first try static mappings without port */
  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
    {
      init_nat_k (&kv, ip0->dst_address, 0, rx_fib_index0, 0);
      if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv,
				   &value))
	{
	  m = pool_elt_at_index (sm->static_mappings, value.value);
	  return m->workers[0];
	}
    }

  proto = ip_proto_to_nat_proto (ip0->protocol);
  udp = ip4_next_header (ip0);
  port = udp->dst_port;

  /* unknown protocol */
  if (PREDICT_FALSE (proto == NAT_PROTOCOL_OTHER))
    {
      /* use current thread */
      return vlib_get_thread_index ();
    }

  if (PREDICT_FALSE (ip0->protocol == IP_PROTOCOL_ICMP))
    {
      icmp46_header_t *icmp = (icmp46_header_t *) udp;
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      if (!icmp_type_is_error_message (
	    vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags))
	port = vnet_buffer (b)->ip.reass.l4_src_port;
      else
	{
	  /* if error message, then it's not fragmented and we can access it */
	  ip4_header_t *inner_ip = (ip4_header_t *) (echo + 1);
	  proto = ip_proto_to_nat_proto (inner_ip->protocol);
	  void *l4_header = ip4_next_header (inner_ip);
	  switch (proto)
	    {
	    case NAT_PROTOCOL_ICMP:
	      icmp = (icmp46_header_t *) l4_header;
	      echo = (icmp_echo_header_t *) (icmp + 1);
	      port = echo->identifier;
	      break;
	    case NAT_PROTOCOL_UDP:
	    case NAT_PROTOCOL_TCP:
	      port = ((tcp_udp_header_t *) l4_header)->src_port;
	      break;
	    default:
	      return vlib_get_thread_index ();
	    }
	}
    }

  /* try static mappings with port */
  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
    {
      init_nat_k (&kv, ip0->dst_address, port, rx_fib_index0, proto);
      if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv,
				   &value))
	{
	  m = pool_elt_at_index (sm->static_mappings, value.value);
	  return m->workers[0];
	}
    }

  /* worker by outside port */
  next_worker_index = sm->first_worker_index;
  next_worker_index +=
    sm->workers[(clib_net_to_host_u16 (port) - 1024) / sm->port_per_thread];
  return next_worker_index;
}

static int
nat44_ei_alloc_default_cb (snat_address_t *addresses, u32 fib_index,
			   u32 thread_index, nat_protocol_t proto,
			   ip4_address_t *addr, u16 *port, u16 port_per_thread,
			   u32 snat_thread_index)
{
  int i;
  snat_address_t *a, *ga = 0;
  u32 portnum;

  for (i = 0; i < vec_len (addresses); i++)
    {
      a = addresses + i;
      switch (proto)
	{
#define _(N, j, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    if (a->busy_##n##_ports_per_thread[thread_index] < port_per_thread)       \
      {                                                                       \
	if (a->fib_index == fib_index)                                        \
	  {                                                                   \
	    while (1)                                                         \
	      {                                                               \
		portnum = (port_per_thread * snat_thread_index) +             \
			  snat_random_port (0, port_per_thread - 1) + 1024;   \
		if (a->busy_##n##_port_refcounts[portnum])                    \
		  continue;                                                   \
		--a->busy_##n##_port_refcounts[portnum];                      \
		a->busy_##n##_ports_per_thread[thread_index]++;               \
		a->busy_##n##_ports++;                                        \
		*addr = a->addr;                                              \
		*port = clib_host_to_net_u16 (portnum);                       \
		return 0;                                                     \
	      }                                                               \
	  }                                                                   \
	else if (a->fib_index == ~0)                                          \
	  {                                                                   \
	    ga = a;                                                           \
	  }                                                                   \
      }                                                                       \
    break;
	  foreach_nat_protocol
#undef _
	    default : nat_elog_info ("unknown protocol");
	  return 1;
	}
    }

  if (ga)
    {
      a = ga;
      switch (proto)
	{
#define _(N, j, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    while (1)                                                                 \
      {                                                                       \
	portnum = (port_per_thread * snat_thread_index) +                     \
		  snat_random_port (0, port_per_thread - 1) + 1024;           \
	if (a->busy_##n##_port_refcounts[portnum])                            \
	  continue;                                                           \
	++a->busy_##n##_port_refcounts[portnum];                              \
	a->busy_##n##_ports_per_thread[thread_index]++;                       \
	a->busy_##n##_ports++;                                                \
	*addr = a->addr;                                                      \
	*port = clib_host_to_net_u16 (portnum);                               \
	return 0;                                                             \
      }
	  break;
	  foreach_nat_protocol
#undef _
	    default : nat_elog_info ("unknown protocol");
	  return 1;
	}
    }

  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

static int
nat44_ei_alloc_range_cb (snat_address_t *addresses, u32 fib_index,
			 u32 thread_index, nat_protocol_t proto,
			 ip4_address_t *addr, u16 *port, u16 port_per_thread,
			 u32 snat_thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_address_t *a = addresses;
  u16 portnum, ports;

  ports = sm->end_port - sm->start_port + 1;

  if (!vec_len (addresses))
    goto exhausted;

  switch (proto)
    {
#define _(N, i, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    if (a->busy_##n##_ports < ports)                                          \
      {                                                                       \
	while (1)                                                             \
	  {                                                                   \
	    portnum = snat_random_port (sm->start_port, sm->end_port);        \
	    if (a->busy_##n##_port_refcounts[portnum])                        \
	      continue;                                                       \
	    ++a->busy_##n##_port_refcounts[portnum];                          \
	    a->busy_##n##_ports++;                                            \
	    *addr = a->addr;                                                  \
	    *port = clib_host_to_net_u16 (portnum);                           \
	    return 0;                                                         \
	  }                                                                   \
      }                                                                       \
    break;
      foreach_nat_protocol
#undef _
	default : nat_elog_info ("unknown protocol");
      return 1;
    }

exhausted:
  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

static int
nat44_ei_alloc_mape_cb (snat_address_t *addresses, u32 fib_index,
			u32 thread_index, nat_protocol_t proto,
			ip4_address_t *addr, u16 *port, u16 port_per_thread,
			u32 snat_thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_address_t *a = addresses;
  u16 m, ports, portnum, A, j;
  m = 16 - (sm->psid_offset + sm->psid_length);
  ports = (1 << (16 - sm->psid_length)) - (1 << m);

  if (!vec_len (addresses))
    goto exhausted;

  switch (proto)
    {
#define _(N, i, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    if (a->busy_##n##_ports < ports)                                          \
      {                                                                       \
	while (1)                                                             \
	  {                                                                   \
	    A = snat_random_port (1, pow2_mask (sm->psid_offset));            \
	    j = snat_random_port (0, pow2_mask (m));                          \
	    portnum = A | (sm->psid << sm->psid_offset) | (j << (16 - m));    \
	    if (a->busy_##n##_port_refcounts[portnum])                        \
	      continue;                                                       \
	    ++a->busy_##n##_port_refcounts[portnum];                          \
	    a->busy_##n##_ports++;                                            \
	    *addr = a->addr;                                                  \
	    *port = clib_host_to_net_u16 (portnum);                           \
	    return 0;                                                         \
	  }                                                                   \
      }                                                                       \
    break;
      foreach_nat_protocol
#undef _
	default : nat_elog_info ("unknown protocol");
      return 1;
    }

exhausted:
  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

void
nat44_ei_set_alloc_default ()
{
  snat_main_t *sm = &snat_main;

  sm->addr_and_port_alloc_alg = NAT_ADDR_AND_PORT_ALLOC_ALG_DEFAULT;
  sm->alloc_addr_and_port = nat44_ei_alloc_default_cb;
}

void
nat44_ei_set_alloc_range (u16 start_port, u16 end_port)
{
  snat_main_t *sm = &snat_main;

  sm->addr_and_port_alloc_alg = NAT_ADDR_AND_PORT_ALLOC_ALG_RANGE;
  sm->alloc_addr_and_port = nat44_ei_alloc_range_cb;
  sm->start_port = start_port;
  sm->end_port = end_port;
}

void
nat44_ei_set_alloc_mape (u16 psid, u16 psid_offset, u16 psid_length)
{
  snat_main_t *sm = &snat_main;

  sm->addr_and_port_alloc_alg = NAT_ADDR_AND_PORT_ALLOC_ALG_MAPE;
  sm->alloc_addr_and_port = nat44_ei_alloc_mape_cb;
  sm->psid = psid;
  sm->psid_offset = psid_offset;
  sm->psid_length = psid_length;
}

static void
nat44_ei_add_static_mapping_when_resolved (ip4_address_t l_addr, u16 l_port,
					   u16 e_port, nat_protocol_t proto,
					   u32 sw_if_index, u32 vrf_id,
					   int addr_only, int identity_nat,
					   u8 *tag)
{
  snat_main_t *sm = &snat_main;
  snat_static_map_resolve_t *rp;

  vec_add2 (sm->to_resolve, rp, 1);
  clib_memset (rp, 0, sizeof (*rp));

  rp->l_addr.as_u32 = l_addr.as_u32;
  rp->l_port = l_port;
  rp->e_port = e_port;
  rp->sw_if_index = sw_if_index;
  rp->vrf_id = vrf_id;
  rp->proto = proto;
  rp->addr_only = addr_only;
  rp->identity_nat = identity_nat;
  rp->tag = vec_dup (tag);
}

int
nat44_ei_del_session (snat_main_t *sm, ip4_address_t *addr, u16 port,
		      nat_protocol_t proto, u32 vrf_id, int is_in)
{
  snat_main_per_thread_data_t *tsm;
  clib_bihash_kv_8_8_t kv, value;
  ip4_header_t ip;
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);
  snat_session_t *s;
  clib_bihash_8_8_t *t;

  if (sm->endpoint_dependent)
    return VNET_API_ERROR_UNSUPPORTED;

  ip.dst_address.as_u32 = ip.src_address.as_u32 = addr->as_u32;
  if (sm->num_workers > 1)
    tsm = vec_elt_at_index (sm->per_thread_data,
			    sm->worker_in2out_cb (&ip, fib_index, 0));
  else
    tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

  init_nat_k (&kv, *addr, port, fib_index, proto);
  t = is_in ? &tsm->in2out : &tsm->out2in;
  if (!clib_bihash_search_8_8 (t, &kv, &value))
    {
      if (pool_is_free_index (tsm->sessions, value.value))
	return VNET_API_ERROR_UNSPECIFIED;

      s = pool_elt_at_index (tsm->sessions, value.value);
      nat_free_session_data (sm, s, tsm - sm->per_thread_data, 0);
      nat44_delete_session (sm, s, tsm - sm->per_thread_data);
      return 0;
    }

  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

int
nat44_ei_add_del_static_mapping (ip4_address_t l_addr, ip4_address_t e_addr,
				 u16 l_port, u16 e_port, nat_protocol_t proto,
				 u32 sw_if_index, u32 vrf_id, u8 addr_only,
				 u8 identity_nat, u8 *tag, u8 is_add)
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m = 0;
  clib_bihash_kv_8_8_t kv, value;
  snat_address_t *a = 0;
  u32 fib_index = ~0;
  snat_interface_t *interface;
  snat_main_per_thread_data_t *tsm;
  snat_user_key_t u_key;
  snat_user_t *u;
  dlist_elt_t *head, *elt;
  u32 elt_index, head_index;
  u32 ses_index;
  u64 user_index;
  snat_session_t *s;
  snat_static_map_resolve_t *rp, *rp_match = 0;
  nat44_lb_addr_port_t *local;
  u32 find = ~0;
  int i;

  if (sw_if_index != ~0)
    {
      ip4_address_t *first_int_addr;

      for (i = 0; i < vec_len (sm->to_resolve); i++)
	{
	  rp = sm->to_resolve + i;
	  if (rp->sw_if_index != sw_if_index ||
	      rp->l_addr.as_u32 != l_addr.as_u32 || rp->vrf_id != vrf_id ||
	      rp->addr_only != addr_only)
	    continue;

	  if (!addr_only)
	    {
	      if ((rp->l_port != l_port && rp->e_port != e_port) ||
		  rp->proto != proto)
		continue;
	    }

	  rp_match = rp;
	  break;
	}

      /* Might be already set... */
      first_int_addr = ip4_interface_first_address (
	sm->ip4_main, sw_if_index, 0 /* just want the address */);

      if (is_add)
	{
	  if (rp_match)
	    return VNET_API_ERROR_VALUE_EXIST;

	  nat44_ei_add_static_mapping_when_resolved (
	    l_addr, l_port, e_port, proto, sw_if_index, vrf_id, addr_only,
	    identity_nat, tag);

	  /* DHCP resolution required? */
	  if (!first_int_addr)
	    return 0;

	  e_addr.as_u32 = first_int_addr->as_u32;
	  /* Identity mapping? */
	  if (l_addr.as_u32 == 0)
	    l_addr.as_u32 = e_addr.as_u32;
	}
      else
	{
	  if (!rp_match)
	    return VNET_API_ERROR_NO_SUCH_ENTRY;

	  vec_del1 (sm->to_resolve, i);

	  if (!first_int_addr)
	    return 0;

	  e_addr.as_u32 = first_int_addr->as_u32;
	  /* Identity mapping? */
	  if (l_addr.as_u32 == 0)
	    l_addr.as_u32 = e_addr.as_u32;
	}
    }

  init_nat_k (&kv, e_addr, addr_only ? 0 : e_port, 0, addr_only ? 0 : proto);
  if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv, &value))
    m = pool_elt_at_index (sm->static_mappings, value.value);

  if (is_add)
    {
      if (m)
	{
	  // identity mapping for second vrf
	  if (is_identity_static_mapping (m))
	    {
	      pool_foreach (local, m->locals)
		{
		  if (local->vrf_id == vrf_id)
		    return VNET_API_ERROR_VALUE_EXIST;
		}
	      pool_get (m->locals, local);
	      local->vrf_id = vrf_id;
	      local->fib_index = fib_table_find_or_create_and_lock (
		FIB_PROTOCOL_IP4, vrf_id, sm->fib_src_low);
	      init_nat_kv (&kv, m->local_addr, m->local_port, local->fib_index,
			   m->proto, m - sm->static_mappings);
	      clib_bihash_add_del_8_8 (&sm->static_mapping_by_local, &kv, 1);
	      return 0;
	    }
	  return VNET_API_ERROR_VALUE_EXIST;
	}

      /* Convert VRF id to FIB index */
      if (vrf_id != ~0)
	{
	  fib_index = fib_table_find_or_create_and_lock (
	    FIB_PROTOCOL_IP4, vrf_id, sm->fib_src_low);
	}
      /* If not specified use inside VRF id from NAT44 plugin config */
      else
	{
	  fib_index = sm->inside_fib_index;
	  vrf_id = sm->inside_vrf_id;
	  fib_table_lock (fib_index, FIB_PROTOCOL_IP4, sm->fib_src_low);
	}

      if (!identity_nat)
	{
	  init_nat_k (&kv, l_addr, addr_only ? 0 : l_port, fib_index,
		      addr_only ? 0 : proto);
	  if (!clib_bihash_search_8_8 (&sm->static_mapping_by_local, &kv,
				       &value))
	    return VNET_API_ERROR_VALUE_EXIST;
	}

      /* Find external address in allocated addresses and reserve port for
	 address and port pair mapping when dynamic translations enabled */
      if (!(addr_only || sm->static_mapping_only))
	{
	  for (i = 0; i < vec_len (sm->addresses); i++)
	    {
	      if (sm->addresses[i].addr.as_u32 == e_addr.as_u32)
		{
		  a = sm->addresses + i;
		  /* External port must be unused */
		  switch (proto)
		    {
#define _(N, j, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    if (a->busy_##n##_port_refcounts[e_port])                                 \
      return VNET_API_ERROR_INVALID_VALUE;                                    \
    ++a->busy_##n##_port_refcounts[e_port];                                   \
    if (e_port > 1024)                                                        \
      {                                                                       \
	a->busy_##n##_ports++;                                                \
	a->busy_##n##_ports_per_thread[get_thread_idx_by_port (e_port)]++;    \
      }                                                                       \
    break;
		      foreach_nat_protocol
#undef _
			default : nat_elog_info ("unknown protocol");
		      return VNET_API_ERROR_INVALID_VALUE_2;
		    }
		  break;
		}
	    }
	  /* External address must be allocated */
	  if (!a && (l_addr.as_u32 != e_addr.as_u32))
	    {
	      if (sw_if_index != ~0)
		{
		  for (i = 0; i < vec_len (sm->to_resolve); i++)
		    {
		      rp = sm->to_resolve + i;
		      if (rp->addr_only)
			continue;
		      if (rp->sw_if_index != sw_if_index &&
			  rp->l_addr.as_u32 != l_addr.as_u32 &&
			  rp->vrf_id != vrf_id && rp->l_port != l_port &&
			  rp->e_port != e_port && rp->proto != proto)
			continue;

		      vec_del1 (sm->to_resolve, i);
		      break;
		    }
		}
	      return VNET_API_ERROR_NO_SUCH_ENTRY;
	    }
	}

      pool_get (sm->static_mappings, m);
      clib_memset (m, 0, sizeof (*m));
      m->tag = vec_dup (tag);
      m->local_addr = l_addr;
      m->external_addr = e_addr;

      if (addr_only)
	m->flags |= NAT_STATIC_MAPPING_FLAG_ADDR_ONLY;
      else
	{
	  m->local_port = l_port;
	  m->external_port = e_port;
	  m->proto = proto;
	}

      if (identity_nat)
	{
	  m->flags |= NAT_STATIC_MAPPING_FLAG_IDENTITY_NAT;
	  pool_get (m->locals, local);
	  local->vrf_id = vrf_id;
	  local->fib_index = fib_index;
	}
      else
	{
	  m->vrf_id = vrf_id;
	  m->fib_index = fib_index;
	}

      if (sm->num_workers > 1)
	{
	  ip4_header_t ip = {
	    .src_address = m->local_addr,
	  };
	  vec_add1 (m->workers, sm->worker_in2out_cb (&ip, m->fib_index, 0));
	  tsm = vec_elt_at_index (sm->per_thread_data, m->workers[0]);
	}
      else
	tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

      init_nat_kv (&kv, m->local_addr, m->local_port, fib_index, m->proto,
		   m - sm->static_mappings);
      clib_bihash_add_del_8_8 (&sm->static_mapping_by_local, &kv, 1);

      init_nat_kv (&kv, m->external_addr, m->external_port, 0, m->proto,
		   m - sm->static_mappings);
      clib_bihash_add_del_8_8 (&sm->static_mapping_by_external, &kv, 1);

      /* Delete dynamic sessions matching local address (+ local port) */
      // TODO: based on type of NAT EI/ED
      if (!(sm->static_mapping_only))
	{
	  u_key.addr = m->local_addr;
	  u_key.fib_index = m->fib_index;
	  kv.key = u_key.as_u64;
	  if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
	    {
	      user_index = value.value;
	      u = pool_elt_at_index (tsm->users, user_index);
	      if (u->nsessions)
		{
		  head_index = u->sessions_per_user_list_head_index;
		  head = pool_elt_at_index (tsm->list_pool, head_index);
		  elt_index = head->next;
		  elt = pool_elt_at_index (tsm->list_pool, elt_index);
		  ses_index = elt->value;
		  while (ses_index != ~0)
		    {
		      s = pool_elt_at_index (tsm->sessions, ses_index);
		      elt = pool_elt_at_index (tsm->list_pool, elt->next);
		      ses_index = elt->value;

		      if (snat_is_session_static (s))
			continue;

		      if (!addr_only && s->in2out.port != m->local_port)
			continue;

		      nat_free_session_data (sm, s, tsm - sm->per_thread_data,
					     0);
		      nat44_delete_session (sm, s, tsm - sm->per_thread_data);

		      if (!addr_only)
			break;
		    }
		}
	    }
	}
    }
  else
    {
      if (!m)
	{
	  if (sw_if_index != ~0)
	    return 0;
	  else
	    return VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      if (identity_nat)
	{
	  if (vrf_id == ~0)
	    vrf_id = sm->inside_vrf_id;

	  pool_foreach (local, m->locals)
	    {
	      if (local->vrf_id == vrf_id)
		find = local - m->locals;
	    }
	  if (find == ~0)
	    return VNET_API_ERROR_NO_SUCH_ENTRY;

	  local = pool_elt_at_index (m->locals, find);
	  fib_index = local->fib_index;
	  pool_put (m->locals, local);
	}
      else
	fib_index = m->fib_index;

      /* Free external address port */
      if (!(addr_only || sm->static_mapping_only))
	{
	  for (i = 0; i < vec_len (sm->addresses); i++)
	    {
	      if (sm->addresses[i].addr.as_u32 == e_addr.as_u32)
		{
		  a = sm->addresses + i;
		  switch (proto)
		    {
#define _(N, j, n, s)                                                         \
  case NAT_PROTOCOL_##N:                                                      \
    --a->busy_##n##_port_refcounts[e_port];                                   \
    if (e_port > 1024)                                                        \
      {                                                                       \
	a->busy_##n##_ports--;                                                \
	a->busy_##n##_ports_per_thread[get_thread_idx_by_port (e_port)]--;    \
      }                                                                       \
    break;
		      foreach_nat_protocol
#undef _
			default : return VNET_API_ERROR_INVALID_VALUE_2;
		    }
		  break;
		}
	    }
	}

      if (sm->num_workers > 1)
	tsm = vec_elt_at_index (sm->per_thread_data, m->workers[0]);
      else
	tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

      init_nat_k (&kv, m->local_addr, m->local_port, fib_index, m->proto);
      clib_bihash_add_del_8_8 (&sm->static_mapping_by_local, &kv, 0);

      /* Delete session(s) for static mapping if exist */
      if (!(sm->static_mapping_only) ||
	  (sm->static_mapping_only && sm->static_mapping_connection_tracking))
	{
	  u_key.addr = m->local_addr;
	  u_key.fib_index = fib_index;
	  kv.key = u_key.as_u64;
	  nat44_ei_static_mapping_del_sessions (sm, tsm, u_key, addr_only,
						e_addr, e_port);
	}

      fib_table_unlock (fib_index, FIB_PROTOCOL_IP4, sm->fib_src_low);
      if (pool_elts (m->locals))
	return 0;

      init_nat_k (&kv, m->external_addr, m->external_port, 0, m->proto);
      clib_bihash_add_del_8_8 (&sm->static_mapping_by_external, &kv, 0);

      vec_free (m->tag);
      vec_free (m->workers);
      /* Delete static mapping from pool */
      pool_put (sm->static_mappings, m);
    }

  if (!addr_only || (l_addr.as_u32 == e_addr.as_u32))
    return 0;

  /* Add/delete external address to FIB */
  pool_foreach (interface, sm->interfaces)
    {
      if (nat_interface_is_inside (interface) || sm->out2in_dpo)
	continue;

      snat_add_del_addr_to_fib (&e_addr, 32, interface->sw_if_index, is_add);
      break;
    }
  pool_foreach (interface, sm->output_feature_interfaces)
    {
      if (nat_interface_is_inside (interface) || sm->out2in_dpo)
	continue;

      snat_add_del_addr_to_fib (&e_addr, 32, interface->sw_if_index, is_add);
      break;
    }
  return 0;
}

int
nat44_ei_static_mapping_match (ip4_address_t match_addr, u16 match_port,
			       u32 match_fib_index,
			       nat_protocol_t match_protocol,
			       ip4_address_t *mapping_addr, u16 *mapping_port,
			       u32 *mapping_fib_index, u8 by_external,
			       u8 *is_addr_only, u8 *is_identity_nat)
{
  snat_main_t *sm = &snat_main;
  clib_bihash_kv_8_8_t kv, value;
  snat_static_mapping_t *m;
  u16 port;

  if (by_external)
    {
      init_nat_k (&kv, match_addr, match_port, 0, match_protocol);
      if (clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv,
				  &value))
	{
	  /* Try address only mapping */
	  init_nat_k (&kv, match_addr, 0, 0, 0);
	  if (clib_bihash_search_8_8 (&sm->static_mapping_by_external, &kv,
				      &value))
	    return 1;
	}
      m = pool_elt_at_index (sm->static_mappings, value.value);

      *mapping_fib_index = m->fib_index;
      *mapping_addr = m->local_addr;
      port = m->local_port;
    }
  else
    {
      init_nat_k (&kv, match_addr, match_port, match_fib_index,
		  match_protocol);
      if (clib_bihash_search_8_8 (&sm->static_mapping_by_local, &kv, &value))
	{
	  /* Try address only mapping */
	  init_nat_k (&kv, match_addr, 0, match_fib_index, 0);
	  if (clib_bihash_search_8_8 (&sm->static_mapping_by_local, &kv,
				      &value))
	    return 1;
	}
      m = pool_elt_at_index (sm->static_mappings, value.value);

      *mapping_fib_index = sm->outside_fib_index;
      *mapping_addr = m->external_addr;
      port = m->external_port;
    }

  /* Address only mapping doesn't change port */
  if (is_addr_only_static_mapping (m))
    *mapping_port = match_port;
  else
    *mapping_port = port;

  if (PREDICT_FALSE (is_addr_only != 0))
    *is_addr_only = is_addr_only_static_mapping (m);

  if (PREDICT_FALSE (is_identity_nat != 0))
    *is_identity_nat = is_identity_static_mapping (m);

  return 0;
}

static void
nat44_ei_worker_db_free (snat_main_per_thread_data_t *tsm)
{
  pool_free (tsm->list_pool);
  pool_free (tsm->lru_pool);
  pool_free (tsm->sessions);
  pool_free (tsm->users);

  clib_bihash_free_8_8 (&tsm->in2out);
  clib_bihash_free_8_8 (&tsm->out2in);
  clib_bihash_free_8_8 (&tsm->user_hash);
}

static void
nat44_ei_worker_db_init (snat_main_per_thread_data_t *tsm, u32 translations,
			 u32 translation_buckets, u32 user_buckets)
{
  dlist_elt_t *head;

  pool_alloc (tsm->list_pool, translations);
  pool_alloc (tsm->lru_pool, translations);
  pool_alloc (tsm->sessions, translations);

  clib_bihash_init_8_8 (&tsm->in2out, "in2out", translation_buckets, 0);
  clib_bihash_init_8_8 (&tsm->out2in, "out2in", translation_buckets, 0);
  clib_bihash_init_8_8 (&tsm->user_hash, "users", user_buckets, 0);

  clib_bihash_set_kvp_format_fn_8_8 (&tsm->in2out, format_session_kvp);
  clib_bihash_set_kvp_format_fn_8_8 (&tsm->out2in, format_session_kvp);
  clib_bihash_set_kvp_format_fn_8_8 (&tsm->user_hash, format_user_kvp);

  pool_get (tsm->lru_pool, head);
  tsm->tcp_trans_lru_head_index = head - tsm->lru_pool;
  clib_dlist_init (tsm->lru_pool, tsm->tcp_trans_lru_head_index);

  pool_get (tsm->lru_pool, head);
  tsm->tcp_estab_lru_head_index = head - tsm->lru_pool;
  clib_dlist_init (tsm->lru_pool, tsm->tcp_estab_lru_head_index);

  pool_get (tsm->lru_pool, head);
  tsm->udp_lru_head_index = head - tsm->lru_pool;
  clib_dlist_init (tsm->lru_pool, tsm->udp_lru_head_index);

  pool_get (tsm->lru_pool, head);
  tsm->icmp_lru_head_index = head - tsm->lru_pool;
  clib_dlist_init (tsm->lru_pool, tsm->icmp_lru_head_index);

  pool_get (tsm->lru_pool, head);
  tsm->unk_proto_lru_head_index = head - tsm->lru_pool;
  clib_dlist_init (tsm->lru_pool, tsm->unk_proto_lru_head_index);
}

static void
nat44_ei_db_free ()
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;

  pool_free (sm->static_mappings);
  clib_bihash_free_8_8 (&sm->static_mapping_by_local);
  clib_bihash_free_8_8 (&sm->static_mapping_by_external);

  if (sm->pat)
    {
      vec_foreach (tsm, sm->per_thread_data)
	{
	  nat44_ei_worker_db_free (tsm);
	}
    }
}

static void
nat44_ei_db_init (u32 translations, u32 translation_buckets, u32 user_buckets)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;

  u32 static_mapping_buckets = 1024;
  u32 static_mapping_memory_size = 64 << 20;

  clib_bihash_init_8_8 (&sm->static_mapping_by_local,
			"static_mapping_by_local", static_mapping_buckets,
			static_mapping_memory_size);
  clib_bihash_init_8_8 (&sm->static_mapping_by_external,
			"static_mapping_by_external", static_mapping_buckets,
			static_mapping_memory_size);
  clib_bihash_set_kvp_format_fn_8_8 (&sm->static_mapping_by_local,
				     format_static_mapping_kvp);
  clib_bihash_set_kvp_format_fn_8_8 (&sm->static_mapping_by_external,
				     format_static_mapping_kvp);

  if (sm->pat)
    {
      vec_foreach (tsm, sm->per_thread_data)
	{
	  nat44_ei_worker_db_init (tsm, translations, translation_buckets,
				   user_buckets);
	}
    }
}

void
nat44_ei_sessions_clear ()
{
  nat44_ei_main_t *nm = &nat44_ei_main;

  snat_main_per_thread_data_t *tsm;
  snat_main_t *sm = &snat_main;

  if (sm->pat)
    {
      vec_foreach (tsm, sm->per_thread_data)
	{
	  nat44_ei_worker_db_free (tsm);
	  nat44_ei_worker_db_init (tsm, nm->translations,
				   nm->translation_buckets, nm->user_buckets);
	}
    }

  // TODO: function for reset counters
  vlib_zero_simple_counter (&sm->total_users, 0);
  vlib_zero_simple_counter (&sm->total_sessions, 0);
  vlib_zero_simple_counter (&sm->user_limit_reached, 0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
