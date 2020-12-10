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

int
nat44_ei_plugin_enable ()
{
  nat44_ei_set_alloc_default ();
  nat_ha_enable ();
  return 0;
}

void
nat44_ei_plugin_disable ()
{
  nat_ha_disable ();
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
