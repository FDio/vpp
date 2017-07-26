/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 * @brief NAT64 implementation
 */

#include <nat/nat64.h>
#include <nat/nat64_db.h>
#include <vnet/fib/ip4_fib.h>


nat64_main_t nat64_main;

/* *INDENT-OFF* */

/* Hook up input features */
VNET_FEATURE_INIT (nat64_in2out, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "nat64-in2out",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
VNET_FEATURE_INIT (nat64_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat64-out2in",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

static u8 well_known_prefix[] = {
  0x00, 0x64, 0xff, 0x9b,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

/* *INDENT-ON* */

clib_error_t *
nat64_init (vlib_main_t * vm)
{
  nat64_main_t *nm = &nat64_main;
  clib_error_t *error = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  nm->is_disabled = 0;

  if (tm->n_vlib_mains > 1)
    {
      nm->is_disabled = 1;
      goto error;
    }

  if (nat64_db_init (&nm->db))
    {
      error = clib_error_return (0, "NAT64 DB init failed");
      goto error;
    }

  /* set session timeouts to default values */
  nm->udp_timeout = SNAT_UDP_TIMEOUT;
  nm->icmp_timeout = SNAT_ICMP_TIMEOUT;
  nm->tcp_trans_timeout = SNAT_TCP_TRANSITORY_TIMEOUT;
  nm->tcp_est_timeout = SNAT_TCP_ESTABLISHED_TIMEOUT;
  nm->tcp_incoming_syn_timeout = SNAT_TCP_INCOMING_SYN;

error:
  return error;
}

int
nat64_add_del_pool_addr (ip4_address_t * addr, u32 vrf_id, u8 is_add)
{
  nat64_main_t *nm = &nat64_main;
  snat_address_t *a = 0;
  snat_interface_t *interface;
  int i;

  /* Check if address already exists */
  for (i = 0; i < vec_len (nm->addr_pool); i++)
    {
      if (nm->addr_pool[i].addr.as_u32 == addr->as_u32)
	{
	  a = nm->addr_pool + i;
	  break;
	}
    }

  if (is_add)
    {
      if (a)
	return VNET_API_ERROR_VALUE_EXIST;

      vec_add2 (nm->addr_pool, a, 1);
      a->addr = *addr;
      a->fib_index = 0;
      if (vrf_id != ~0)
	a->fib_index =
	  fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6, vrf_id,
					     FIB_SOURCE_PLUGIN_HI);
#define _(N, i, n, s) \
      clib_bitmap_alloc (a->busy_##n##_port_bitmap, 65535);
      foreach_snat_protocol
#undef _
    }
  else
    {
      if (!a)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if (a->fib_index)
	fib_table_unlock (a->fib_index, FIB_PROTOCOL_IP6,
			  FIB_SOURCE_PLUGIN_HI);

#define _(N, id, n, s) \
      clib_bitmap_free (a->busy_##n##_port_bitmap);
      foreach_snat_protocol
#undef _
	/* Delete sessions using address */
	nat64_db_free_out_addr (&nm->db, &a->addr);
      vec_del1 (nm->addr_pool, i);
    }

  /* Add/del external address to FIB */
  /* *INDENT-OFF* */
  pool_foreach (interface, nm->interfaces,
  ({
    if (interface->is_inside)
      continue;

    snat_add_del_addr_to_fib (addr, 32, interface->sw_if_index, is_add);
    break;
  }));
  /* *INDENT-ON* */

  return 0;
}

void
nat64_pool_addr_walk (nat64_pool_addr_walk_fn_t fn, void *ctx)
{
  nat64_main_t *nm = &nat64_main;
  snat_address_t *a = 0;

  /* *INDENT-OFF* */
  vec_foreach (a, nm->addr_pool)
    {
      if (fn (a, ctx))
        break;
    };
  /* *INDENT-ON* */
}

int
nat64_add_del_interface (u32 sw_if_index, u8 is_inside, u8 is_add)
{
  nat64_main_t *nm = &nat64_main;
  snat_interface_t *interface = 0, *i;
  snat_address_t *ap;
  const char *feature_name, *arc_name;

  /* Check if address already exists */
  /* *INDENT-OFF* */
  pool_foreach (i, nm->interfaces,
  ({
    if (i->sw_if_index == sw_if_index)
      {
        interface = i;
        break;
      }
  }));
  /* *INDENT-ON* */

  if (is_add)
    {
      if (interface)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (nm->interfaces, interface);
      interface->sw_if_index = sw_if_index;
      interface->is_inside = is_inside;

    }
  else
    {
      if (!interface)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      pool_put (nm->interfaces, interface);
    }

  if (!is_inside)
    {
      /* *INDENT-OFF* */
      vec_foreach (ap, nm->addr_pool)
        snat_add_del_addr_to_fib(&ap->addr, 32, sw_if_index, is_add);
      /* *INDENT-ON* */
    }

  arc_name = is_inside ? "ip6-unicast" : "ip4-unicast";
  feature_name = is_inside ? "nat64-in2out" : "nat64-out2in";

  return vnet_feature_enable_disable (arc_name, feature_name, sw_if_index,
				      is_add, 0, 0);
}

void
nat64_interfaces_walk (nat64_interface_walk_fn_t fn, void *ctx)
{
  nat64_main_t *nm = &nat64_main;
  snat_interface_t *i = 0;

  /* *INDENT-OFF* */
  pool_foreach (i, nm->interfaces,
  ({
    if (fn (i, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

int
nat64_alloc_out_addr_and_port (u32 fib_index, snat_protocol_t proto,
			       ip4_address_t * addr, u16 * port)
{
  nat64_main_t *nm = &nat64_main;
  snat_main_t *sm = &snat_main;
  int i;
  snat_address_t *a, *ga = 0;
  u32 portnum;

  for (i = 0; i < vec_len (nm->addr_pool); i++)
    {
      a = nm->addr_pool + i;
      switch (proto)
	{
#define _(N, j, n, s) \
        case SNAT_PROTOCOL_##N: \
          if (a->busy_##n##_ports < (65535-1024)) \
            { \
              if (a->fib_index == fib_index) \
                { \
                  while (1) \
                    { \
                      portnum = random_u32 (&sm->random_seed); \
                      portnum &= 0xFFFF; \
                      if (portnum < 1024) \
                        continue; \
                      if (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, \
                                                    portnum)) \
                        continue; \
                      clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, \
                                                portnum, 1); \
                      a->busy_##n##_ports++; \
                      *port = portnum; \
                      addr->as_u32 = a->addr.as_u32; \
                      return 0; \
                    } \
                 } \
               else if (a->fib_index == 0) \
                 ga = a; \
            } \
          break;
	  foreach_snat_protocol
#undef _
	default:
	  clib_warning ("unknown protocol");
	  return 1;
	}
    }

  if (ga)
    {
      switch (proto)
	{
#define _(N, j, n, s) \
        case SNAT_PROTOCOL_##N: \
          while (1) \
            { \
              portnum = random_u32 (&sm->random_seed); \
              portnum &= 0xFFFF; \
              if (portnum < 1024) \
                continue; \
              if (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, \
                                            portnum)) \
                continue; \
              clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, \
                                        portnum, 1); \
              a->busy_##n##_ports++; \
              *port = portnum; \
              addr->as_u32 = a->addr.as_u32; \
              return 0; \
            }
	  break;
	  foreach_snat_protocol
#undef _
	default:
	  clib_warning ("unknown protocol");
	  return 1;
	}
    }

  /* Totally out of translations to use... */
  //TODO: IPFix
  return 1;
}

void
nat64_free_out_addr_and_port (ip4_address_t * addr, u16 port,
			      snat_protocol_t proto)
{
  nat64_main_t *nm = &nat64_main;
  int i;
  snat_address_t *a;

  for (i = 0; i < vec_len (nm->addr_pool); i++)
    {
      a = nm->addr_pool + i;
      if (addr->as_u32 != a->addr.as_u32)
	continue;
      switch (proto)
	{
#define _(N, j, n, s) \
        case SNAT_PROTOCOL_##N: \
          ASSERT (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, \
                  port) == 1); \
          clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, port, 0); \
          a->busy_##n##_ports--; \
          break;
	  foreach_snat_protocol
#undef _
	default:
	  clib_warning ("unknown protocol");
	  return;
	}
      break;
    }
}

int
nat64_add_del_static_bib_entry (ip6_address_t * in_addr,
				ip4_address_t * out_addr, u16 in_port,
				u16 out_port, u8 proto, u32 vrf_id, u8 is_add)
{
  nat64_main_t *nm = &nat64_main;
  nat64_db_bib_entry_t *bibe;
  u32 fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6, vrf_id,
						     FIB_SOURCE_PLUGIN_HI);
  snat_protocol_t p = ip_proto_to_snat_proto (proto);
  ip46_address_t addr;
  int i;
  snat_address_t *a;

  addr.as_u64[0] = in_addr->as_u64[0];
  addr.as_u64[1] = in_addr->as_u64[1];
  bibe =
    nat64_db_bib_entry_find (&nm->db, &addr, clib_host_to_net_u16 (in_port),
			     proto, fib_index, 1);

  if (is_add)
    {
      if (bibe)
	return VNET_API_ERROR_VALUE_EXIST;

      for (i = 0; i < vec_len (nm->addr_pool); i++)
	{
	  a = nm->addr_pool + i;
	  if (out_addr->as_u32 != a->addr.as_u32)
	    continue;
	  switch (p)
	    {
#define _(N, j, n, s) \
            case SNAT_PROTOCOL_##N: \
              if (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, \
                                            out_port)) \
                return VNET_API_ERROR_INVALID_VALUE; \
              clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, \
                                        out_port, 1); \
              if (out_port > 1024) \
                a->busy_##n##_ports++; \
              break;
	      foreach_snat_protocol
#undef _
	    default:
	      memset (&addr, 0, sizeof (addr));
	      addr.ip4.as_u32 = out_addr->as_u32;
	      if (nat64_db_bib_entry_find
		  (&nm->db, &addr, 0, proto, fib_index, 0))
		return VNET_API_ERROR_INVALID_VALUE;
	    }
	  break;
	}
      bibe =
	nat64_db_bib_entry_create (&nm->db, in_addr, out_addr,
				   clib_host_to_net_u16 (in_port),
				   clib_host_to_net_u16 (out_port), fib_index,
				   proto, 1);
      if (!bibe)
	return VNET_API_ERROR_UNSPECIFIED;
    }
  else
    {
      if (!bibe)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      nat64_free_out_addr_and_port (out_addr, out_port, p);
      nat64_db_bib_entry_free (&nm->db, bibe);
    }

  return 0;
}

int
nat64_set_udp_timeout (u32 timeout)
{
  nat64_main_t *nm = &nat64_main;

  if (timeout == 0)
    nm->udp_timeout = SNAT_UDP_TIMEOUT;
  else if (timeout < SNAT_UDP_TIMEOUT_MIN)
    return VNET_API_ERROR_INVALID_VALUE;
  else
    nm->udp_timeout = timeout;

  return 0;
}

u32
nat64_get_udp_timeout (void)
{
  nat64_main_t *nm = &nat64_main;

  return nm->udp_timeout;
}

int
nat64_set_icmp_timeout (u32 timeout)
{
  nat64_main_t *nm = &nat64_main;

  if (timeout == 0)
    nm->icmp_timeout = SNAT_ICMP_TIMEOUT;
  else
    nm->icmp_timeout = timeout;

  return 0;
}

u32
nat64_get_icmp_timeout (void)
{
  nat64_main_t *nm = &nat64_main;

  return nm->icmp_timeout;
}

int
nat64_set_tcp_timeouts (u32 trans, u32 est, u32 incoming_syn)
{
  nat64_main_t *nm = &nat64_main;

  if (trans == 0)
    nm->tcp_trans_timeout = SNAT_TCP_TRANSITORY_TIMEOUT;
  else
    nm->tcp_trans_timeout = trans;

  if (est == 0)
    nm->tcp_est_timeout = SNAT_TCP_ESTABLISHED_TIMEOUT;
  else
    nm->tcp_est_timeout = est;

  if (incoming_syn == 0)
    nm->tcp_incoming_syn_timeout = SNAT_TCP_INCOMING_SYN;
  else
    nm->tcp_incoming_syn_timeout = incoming_syn;

  return 0;
}

u32
nat64_get_tcp_trans_timeout (void)
{
  nat64_main_t *nm = &nat64_main;

  return nm->tcp_trans_timeout;
}

u32
nat64_get_tcp_est_timeout (void)
{
  nat64_main_t *nm = &nat64_main;

  return nm->tcp_est_timeout;
}

u32
nat64_get_tcp_incoming_syn_timeout (void)
{
  nat64_main_t *nm = &nat64_main;

  return nm->tcp_incoming_syn_timeout;
}

void
nat64_session_reset_timeout (nat64_db_st_entry_t * ste, vlib_main_t * vm)
{
  nat64_main_t *nm = &nat64_main;
  u32 now = (u32) vlib_time_now (vm);

  switch (ip_proto_to_snat_proto (ste->proto))
    {
    case SNAT_PROTOCOL_ICMP:
      ste->expire = now + nm->icmp_timeout;
      return;
    case SNAT_PROTOCOL_TCP:
      {
	switch (ste->tcp_state)
	  {
	  case NAT64_TCP_STATE_V4_INIT:
	  case NAT64_TCP_STATE_V6_INIT:
	  case NAT64_TCP_STATE_V4_FIN_RCV:
	  case NAT64_TCP_STATE_V6_FIN_RCV:
	  case NAT64_TCP_STATE_V6_FIN_V4_FIN_RCV:
	  case NAT64_TCP_STATE_TRANS:
	    ste->expire = now + nm->tcp_trans_timeout;
	    return;
	  case NAT64_TCP_STATE_ESTABLISHED:
	    ste->expire = now + nm->tcp_est_timeout;
	    return;
	  default:
	    return;
	  }
      }
    case SNAT_PROTOCOL_UDP:
      ste->expire = now + nm->udp_timeout;
      return;
    default:
      ste->expire = now + nm->udp_timeout;
      return;
    }
}

void
nat64_tcp_session_set_state (nat64_db_st_entry_t * ste, tcp_header_t * tcp,
			     u8 is_ip6)
{
  switch (ste->tcp_state)
    {
    case NAT64_TCP_STATE_CLOSED:
      {
	if (tcp->flags & TCP_FLAG_SYN)
	  {
	    if (is_ip6)
	      ste->tcp_state = NAT64_TCP_STATE_V6_INIT;
	    else
	      ste->tcp_state = NAT64_TCP_STATE_V4_INIT;
	  }
	return;
      }
    case NAT64_TCP_STATE_V4_INIT:
      {
	if (is_ip6 && (tcp->flags & TCP_FLAG_SYN))
	  ste->tcp_state = NAT64_TCP_STATE_ESTABLISHED;
	return;
      }
    case NAT64_TCP_STATE_V6_INIT:
      {
	if (!is_ip6 && (tcp->flags & TCP_FLAG_SYN))
	  ste->tcp_state = NAT64_TCP_STATE_ESTABLISHED;
	return;
      }
    case NAT64_TCP_STATE_ESTABLISHED:
      {
	if (tcp->flags & TCP_FLAG_FIN)
	  {
	    if (is_ip6)
	      ste->tcp_state = NAT64_TCP_STATE_V6_FIN_RCV;
	    else
	      ste->tcp_state = NAT64_TCP_STATE_V4_FIN_RCV;
	  }
	else if (tcp->flags & TCP_FLAG_RST)
	  {
	    ste->tcp_state = NAT64_TCP_STATE_TRANS;
	  }
	return;
      }
    case NAT64_TCP_STATE_V4_FIN_RCV:
      {
	if (is_ip6 && (tcp->flags & TCP_FLAG_FIN))
	  ste->tcp_state = NAT64_TCP_STATE_V6_FIN_V4_FIN_RCV;
	return;
      }
    case NAT64_TCP_STATE_V6_FIN_RCV:
      {
	if (!is_ip6 && (tcp->flags & TCP_FLAG_FIN))
	  ste->tcp_state = NAT64_TCP_STATE_V6_FIN_V4_FIN_RCV;
	return;
      }
    case NAT64_TCP_STATE_TRANS:
      {
	if (!(tcp->flags & TCP_FLAG_RST))
	  ste->tcp_state = NAT64_TCP_STATE_ESTABLISHED;
	return;
      }
    default:
      return;
    }
}

int
nat64_add_del_prefix (ip6_address_t * prefix, u8 plen, u32 vrf_id, u8 is_add)
{
  nat64_main_t *nm = &nat64_main;
  nat64_prefix_t *p = 0;
  int i;

  /* Verify prefix length */
  if (plen != 32 && plen != 40 && plen != 48 && plen != 56 && plen != 64
      && plen != 96)
    return VNET_API_ERROR_INVALID_VALUE;

  /* Check if tenant already have prefix */
  for (i = 0; i < vec_len (nm->pref64); i++)
    {
      if (nm->pref64[i].vrf_id == vrf_id)
	{
	  p = nm->pref64 + i;
	  break;
	}
    }

  if (is_add)
    {
      if (!p)
	{
	  vec_add2 (nm->pref64, p, 1);
	  p->fib_index =
	    fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6, vrf_id,
					       FIB_SOURCE_PLUGIN_HI);
	  p->vrf_id = vrf_id;
	}

      p->prefix.as_u64[0] = prefix->as_u64[0];
      p->prefix.as_u64[1] = prefix->as_u64[1];
      p->plen = plen;
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      vec_del1 (nm->pref64, i);
    }

  return 0;
}

void
nat64_prefix_walk (nat64_prefix_walk_fn_t fn, void *ctx)
{
  nat64_main_t *nm = &nat64_main;
  nat64_prefix_t *p = 0;

  /* *INDENT-OFF* */
  vec_foreach (p, nm->pref64)
    {
      if (fn (p, ctx))
        break;
    };
  /* *INDENT-ON* */
}

void
nat64_compose_ip6 (ip6_address_t * ip6, ip4_address_t * ip4, u32 fib_index)
{
  nat64_main_t *nm = &nat64_main;
  nat64_prefix_t *p, *gp = 0, *prefix = 0;

  /* *INDENT-OFF* */
  vec_foreach (p, nm->pref64)
    {
      if (p->fib_index == fib_index)
        {
          prefix = p;
          break;
        }

      if (p->fib_index == 0)
        gp = p;
    };
  /* *INDENT-ON* */

  if (!prefix)
    prefix = gp;

  if (prefix)
    {
      memset (ip6, 0, 16);
      memcpy (ip6, &p->prefix, p->plen);
      switch (p->plen)
	{
	case 32:
	  ip6->as_u32[1] = ip4->as_u32;
	  break;
	case 40:
	  ip6->as_u8[5] = ip4->as_u8[0];
	  ip6->as_u8[6] = ip4->as_u8[1];
	  ip6->as_u8[7] = ip4->as_u8[2];
	  ip6->as_u8[9] = ip4->as_u8[3];
	  break;
	case 48:
	  ip6->as_u8[6] = ip4->as_u8[0];
	  ip6->as_u8[7] = ip4->as_u8[1];
	  ip6->as_u8[9] = ip4->as_u8[2];
	  ip6->as_u8[10] = ip4->as_u8[3];
	  break;
	case 56:
	  ip6->as_u8[7] = ip4->as_u8[0];
	  ip6->as_u8[9] = ip4->as_u8[1];
	  ip6->as_u8[10] = ip4->as_u8[2];
	  ip6->as_u8[11] = ip4->as_u8[3];
	  break;
	case 64:
	  ip6->as_u8[9] = ip4->as_u8[0];
	  ip6->as_u8[10] = ip4->as_u8[1];
	  ip6->as_u8[11] = ip4->as_u8[2];
	  ip6->as_u8[12] = ip4->as_u8[3];
	  break;
	case 96:
	  ip6->as_u32[3] = ip4->as_u32;
	  break;
	default:
	  clib_warning ("invalid prefix length");
	  break;
	}
    }
  else
    {
      memcpy (ip6, well_known_prefix, 16);
      ip6->as_u32[3] = ip4->as_u32;
    }
}

void
nat64_extract_ip4 (ip6_address_t * ip6, ip4_address_t * ip4, u32 fib_index)
{
  nat64_main_t *nm = &nat64_main;
  nat64_prefix_t *p, *gp = 0;
  u8 plen = 0;

  /* *INDENT-OFF* */
  vec_foreach (p, nm->pref64)
    {
      if (p->fib_index == fib_index)
        {
          plen = p->plen;
          break;
        }

      if (p->vrf_id == 0)
        gp = p;
    };
  /* *INDENT-ON* */

  if (!plen)
    {
      if (gp)
	plen = gp->plen;
      else
	plen = 96;
    }

  switch (plen)
    {
    case 32:
      ip4->as_u32 = ip6->as_u32[1];
      break;
    case 40:
      ip4->as_u8[0] = ip6->as_u8[5];
      ip4->as_u8[1] = ip6->as_u8[6];
      ip4->as_u8[2] = ip6->as_u8[7];
      ip4->as_u8[3] = ip6->as_u8[9];
      break;
    case 48:
      ip4->as_u8[0] = ip6->as_u8[6];
      ip4->as_u8[1] = ip6->as_u8[7];
      ip4->as_u8[2] = ip6->as_u8[9];
      ip4->as_u8[3] = ip6->as_u8[10];
      break;
    case 56:
      ip4->as_u8[0] = ip6->as_u8[7];
      ip4->as_u8[1] = ip6->as_u8[9];
      ip4->as_u8[2] = ip6->as_u8[10];
      ip4->as_u8[3] = ip6->as_u8[11];
      break;
    case 64:
      ip4->as_u8[0] = ip6->as_u8[9];
      ip4->as_u8[1] = ip6->as_u8[10];
      ip4->as_u8[2] = ip6->as_u8[11];
      ip4->as_u8[3] = ip6->as_u8[12];
      break;
    case 96:
      ip4->as_u32 = ip6->as_u32[3];
      break;
    default:
      clib_warning ("invalid prefix length");
      break;
    }
}

/**
 * @brief The 'nat64-expire-walk' process's main loop.
 *
 * Check expire time for NAT64 sessions.
 */
static uword
nat64_expire_walk_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
		      vlib_frame_t * f)
{
  nat64_main_t *nm = &nat64_main;

  while (!nm->is_disabled)
    {
      vlib_process_wait_for_event_or_clock (vm, 10.0);
      vlib_process_get_events (vm, NULL);
      u32 now = (u32) vlib_time_now (vm);

      nad64_db_st_free_expired (&nm->db, now);
    }

  return 0;
}

static vlib_node_registration_t nat64_expire_walk_node;

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat64_expire_walk_node, static) = {
    .function = nat64_expire_walk_fn,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "nat64-expire-walk",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
