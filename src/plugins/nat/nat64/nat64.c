/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vppinfra/crc32.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/ip/ip4_to_ip6.h>

#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/ip/reass/ip6_sv_reass.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <nat/lib/ipfix_logging.h>
#include <nat/nat64/nat64.h>

nat64_main_t nat64_main;

/* Hook up input features */
VNET_FEATURE_INIT (nat64_in2out, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "nat64-in2out",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
  .runs_after = VNET_FEATURES ("ip6-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (nat64_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat64-out2in",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
  .runs_after = VNET_FEATURES ("ip4-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (nat64_in2out_handoff, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "nat64-in2out-handoff",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
  .runs_after = VNET_FEATURES ("ip6-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (nat64_out2in_handoff, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat64-out2in-handoff",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
  .runs_after = VNET_FEATURES ("ip4-sv-reassembly-feature"),
};
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "NAT64",
};
static u8 well_known_prefix[] = {
  0x00, 0x64, 0xff, 0x9b,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

#define nat_elog_str(_str)                      \
do                                              \
  {                                             \
    ELOG_TYPE_DECLARE (e) =                     \
      {                                         \
        .format = "nat-msg " _str,              \
        .format_args = "",                      \
      };                                        \
    ELOG_DATA (&vlib_global_main.elog_main, e); \
  } while (0);

static void
nat64_ip4_add_del_interface_address_cb (ip4_main_t * im, uword opaque,
					u32 sw_if_index,
					ip4_address_t * address,
					u32 address_length,
					u32 if_address_index, u32 is_delete)
{
  nat64_main_t *nm = &nat64_main;
  int i, j;

  if (plugin_enabled () == 0)
    return;

  for (i = 0; i < vec_len (nm->auto_add_sw_if_indices); i++)
    {
      if (sw_if_index == nm->auto_add_sw_if_indices[i])
	{
	  if (!is_delete)
	    {
	      /* Don't trip over lease renewal, static config */
	      for (j = 0; j < vec_len (nm->addr_pool); j++)
		if (nm->addr_pool[j].addr.as_u32 == address->as_u32)
		  return;

	      (void) nat64_add_del_pool_addr (vlib_get_thread_index (),
					      address, ~0, 1);
	      return;
	    }
	  else
	    {
	      (void) nat64_add_del_pool_addr (vlib_get_thread_index (),
					      address, ~0, 0);
	      return;
	    }
	}
    }
}

u32
nat64_get_worker_in2out (ip6_address_t * addr)
{
  nat64_main_t *nm = &nat64_main;
  u32 next_worker_index = nm->first_worker_index;
  u32 hash;

#ifdef clib_crc32c_uses_intrinsics
  hash = clib_crc32c ((u8 *) addr->as_u32, 16);
#else
  u64 tmp = addr->as_u64[0] ^ addr->as_u64[1];
  hash = clib_xxhash (tmp);
#endif

  if (PREDICT_TRUE (is_pow2 (_vec_len (nm->workers))))
    next_worker_index += nm->workers[hash & (_vec_len (nm->workers) - 1)];
  else
    next_worker_index += nm->workers[hash % _vec_len (nm->workers)];

  return next_worker_index;
}

static u32
get_thread_idx_by_port (u16 e_port)
{
  nat64_main_t *nm = &nat64_main;
  u32 thread_idx = nm->num_workers;
  if (nm->num_workers > 1)
    {
      thread_idx = nm->first_worker_index +
		   nm->workers[(e_port - 1024) / nm->port_per_thread %
			       _vec_len (nm->workers)];
    }
  return thread_idx;
}

u32
nat64_get_worker_out2in (vlib_buffer_t * b, ip4_header_t * ip)
{
  nat64_main_t *nm = &nat64_main;
  udp_header_t *udp;
  u16 port;
  u32 proto;

  proto = ip_proto_to_nat_proto (ip->protocol);
  udp = ip4_next_header (ip);
  port = udp->dst_port;

  /* unknown protocol */
  if (PREDICT_FALSE (proto == NAT_PROTOCOL_OTHER))
    {
      nat64_db_t *db;
      ip46_address_t daddr;
      nat64_db_bib_entry_t *bibe;

      clib_memset (&daddr, 0, sizeof (daddr));
      daddr.ip4.as_u32 = ip->dst_address.as_u32;

      vec_foreach (db, nm->db)
        {
          bibe = nat64_db_bib_entry_find (db, &daddr, 0, ip->protocol, 0, 0);
          if (bibe)
            return (u32) (db - nm->db);
        }
      return vlib_get_thread_index ();
    }

  /* ICMP */
  if (PREDICT_FALSE (ip->protocol == IP_PROTOCOL_ICMP))
    {
      icmp46_header_t *icmp = (icmp46_header_t *) udp;
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      if (!icmp_type_is_error_message
	  (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags))
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

  /* worker by outside port  (TCP/UDP) */
  port = clib_net_to_host_u16 (port);
  if (port > 1024)
    return get_thread_idx_by_port (port);

  return vlib_get_thread_index ();
}

clib_error_t *
nat64_init (vlib_main_t * vm)
{
  nat64_main_t *nm = &nat64_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  ip4_add_del_interface_address_callback_t cb4;
  vlib_node_t *node;

  clib_memset (nm, 0, sizeof (*nm));

  nm->ip4_main = &ip4_main;
  nm->log_class = vlib_log_register_class ("nat64", 0);

  nm->port_per_thread = 0xffff - 1024;

  nm->fq_in2out_index = ~0;
  nm->fq_out2in_index = ~0;

  node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  nm->error_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat64-in2out");
  nm->in2out_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat64-in2out-slowpath");
  nm->in2out_slowpath_node_index = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "nat64-out2in");
  nm->out2in_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "nat64-expire-worker-walk");
  nm->expire_worker_walk_node_index = node->index;

  nm->fib_src_hi = fib_source_allocate ("nat64-hi",
					FIB_SOURCE_PRIORITY_HI,
					FIB_SOURCE_BH_SIMPLE);
  nm->fib_src_low = fib_source_allocate ("nat64-low",
					 FIB_SOURCE_PRIORITY_LOW,
					 FIB_SOURCE_BH_SIMPLE);

  // set protocol timeouts to defaults
  nat64_reset_timeouts ();

  /* Set up the interface address add/del callback */
  cb4.function = nat64_ip4_add_del_interface_address_cb;
  cb4.function_opaque = 0;
  vec_add1 (nm->ip4_main->add_del_interface_address_callbacks, cb4);

  /* Init counters */
  nm->total_bibs.name = "total-bibs";
  nm->total_bibs.stat_segment_name = "/nat64/total-bibs";
  vlib_validate_simple_counter (&nm->total_bibs, 0);
  vlib_zero_simple_counter (&nm->total_bibs, 0);
  nm->total_sessions.name = "total-sessions";
  nm->total_sessions.stat_segment_name = "/nat64/total-sessions";
  vlib_validate_simple_counter (&nm->total_sessions, 0);
  vlib_zero_simple_counter (&nm->total_sessions, 0);

  uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  if (p)
    {
      vlib_thread_registration_t *tr;
      tr = (vlib_thread_registration_t *) p[0];
      if (tr)
	{
	  nm->num_workers = tr->count;
	  nm->first_worker_index = tr->first_index;
	}
    }

  if (nm->num_workers > 1)
    {
      int i;
      uword *bitmap = 0;

      for (i = 0; i < nm->num_workers; i++)
	bitmap = clib_bitmap_set (bitmap, i, 1);

      clib_bitmap_foreach (i, bitmap)
         {
          vec_add1(nm->workers, i);
        }

      clib_bitmap_free (bitmap);

      nm->port_per_thread = (0xffff - 1024) / _vec_len (nm->workers);
    }

  /* Init IPFIX logging */
  nat_ipfix_logging_init (vm);

#define _(x)                                                     \
  nm->counters.in2out.x.name = #x;                               \
  nm->counters.in2out.x.stat_segment_name = "/nat64/in2out/" #x; \
  nm->counters.out2in.x.name = #x;                               \
  nm->counters.out2in.x.stat_segment_name = "/nat64/out2in/" #x;
  foreach_nat_counter;
#undef _
  return nat64_api_hookup (vm);
}

VLIB_INIT_FUNCTION (nat64_init);

static void nat64_free_out_addr_and_port (struct nat64_db_s *db,
					  ip4_address_t * addr, u16 port,
					  u8 protocol);

int
nat64_init_hash (nat64_config_t c)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  nat64_main_t *nm = &nat64_main;
  nat64_db_t *db;
  int rv = 0;

  vec_validate (nm->db, tm->n_vlib_mains - 1);

  vec_foreach (db, nm->db)
    {
      if (nat64_db_init (db, c, nat64_free_out_addr_and_port))
        {
	  nat64_log_err ("NAT64 DB init failed");
          rv = 1;
        }
    }

  return rv;
}

int
nat64_free_hash ()
{
  nat64_main_t *nm = &nat64_main;
  nat64_db_t *db;
  int rv = 0;

  vec_foreach (db, nm->db)
    {
      if (nat64_db_free (db))
        {
	  nat64_log_err ("NAT64 DB free failed");
          rv = 1;
        }
    }

  vec_free (nm->db);

  return rv;
}

int
nat64_add_del_pool_addr (clib_thread_index_t thread_index, ip4_address_t *addr,
			 u32 vrf_id, u8 is_add)
{
  nat64_main_t *nm = &nat64_main;
  nat64_address_t *a = 0;
  nat64_interface_t *interface;
  int i;
  nat64_db_t *db;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

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
      a->fib_index = ~0;
      if (vrf_id != ~0)
	a->fib_index =
	  fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6, vrf_id,
					     nm->fib_src_hi);
#define _(N, id, n, s) \
      clib_memset (a->busy_##n##_port_refcounts, 0, sizeof(a->busy_##n##_port_refcounts)); \
      a->busy_##n##_ports = 0; \
      vec_validate_init_empty (a->busy_##n##_ports_per_thread, tm->n_vlib_mains - 1, 0);
      foreach_nat_protocol
#undef _
    }
  else
    {
      if (!a)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if (a->fib_index != ~0)
	fib_table_unlock (a->fib_index, FIB_PROTOCOL_IP6, nm->fib_src_hi);
      /* Delete sessions using address */
      vec_foreach (db, nm->db)
        {
          nat64_db_free_out_addr (thread_index, db, &a->addr);
          vlib_set_simple_counter (&nm->total_bibs, db - nm->db, 0,
                                   db->bib.bib_entries_num);
          vlib_set_simple_counter (&nm->total_sessions, db - nm->db, 0,
                                   db->st.st_entries_num);
        }
      vec_del1 (nm->addr_pool, i);
    }

  /* Add/del external address to FIB */
  pool_foreach (interface, nm->interfaces)
   {
    if (nat64_interface_is_inside(interface))
      continue;

    nat64_add_del_addr_to_fib (addr, 32, interface->sw_if_index, is_add);
    break;
  }

  return 0;
}

void
nat64_pool_addr_walk (nat64_pool_addr_walk_fn_t fn, void *ctx)
{
  nat64_main_t *nm = &nat64_main;
  nat64_address_t *a = 0;

  vec_foreach (a, nm->addr_pool)
    {
      if (fn (a, ctx))
        break;
    };
}

int
nat64_add_interface_address (u32 sw_if_index, int is_add)
{
  nat64_main_t *nm = &nat64_main;
  ip4_main_t *ip4_main = nm->ip4_main;
  ip4_address_t *first_int_addr;
  int i;

  first_int_addr = ip4_interface_first_address (ip4_main, sw_if_index, 0);

  for (i = 0; i < vec_len (nm->auto_add_sw_if_indices); i++)
    {
      if (nm->auto_add_sw_if_indices[i] == sw_if_index)
	{
	  if (is_add)
	    return VNET_API_ERROR_VALUE_EXIST;
	  else
	    {
	      /* if have address remove it */
	      if (first_int_addr)
		(void) nat64_add_del_pool_addr (vlib_get_thread_index (),
						first_int_addr, ~0, 0);
	      vec_del1 (nm->auto_add_sw_if_indices, i);
	      return 0;
	    }
	}
    }

  if (!is_add)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* add to the auto-address list */
  vec_add1 (nm->auto_add_sw_if_indices, sw_if_index);

  /* If the address is already bound - or static - add it now */
  if (first_int_addr)
    (void) nat64_add_del_pool_addr (vlib_get_thread_index (),
				    first_int_addr, ~0, 1);

  return 0;
}

static void
nat64_validate_counters (nat64_main_t * nm, u32 sw_if_index)
{
#define _(x)                                                          \
  vlib_validate_simple_counter (&nm->counters.in2out.x, sw_if_index); \
  vlib_zero_simple_counter (&nm->counters.in2out.x, sw_if_index);     \
  vlib_validate_simple_counter (&nm->counters.out2in.x, sw_if_index); \
  vlib_zero_simple_counter (&nm->counters.out2in.x, sw_if_index);
  foreach_nat_counter;
#undef _
}

void
nat64_add_del_addr_to_fib (ip4_address_t * addr, u8 p_len, u32 sw_if_index,
			   int is_add)
{
  nat64_main_t *nm = &nat64_main;
  fib_prefix_t prefix = {
    .fp_len = p_len,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr = {
		.ip4.as_u32 = addr->as_u32,
		},
  };
  u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

  if (is_add)
    fib_table_entry_update_one_path (fib_index,
				     &prefix,
				     nm->fib_src_low,
				     (FIB_ENTRY_FLAG_CONNECTED |
				      FIB_ENTRY_FLAG_LOCAL |
				      FIB_ENTRY_FLAG_EXCLUSIVE),
				     DPO_PROTO_IP4,
				     NULL,
				     sw_if_index,
				     ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
  else
    fib_table_entry_delete (fib_index, &prefix, nm->fib_src_low);
}

int
nat64_interface_add_del (u32 sw_if_index, u8 is_inside, u8 is_add)
{
  vlib_main_t *vm = vlib_get_main ();
  nat64_main_t *nm = &nat64_main;
  nat64_interface_t *interface = 0, *i;
  nat64_address_t *ap;
  const char *feature_name, *arc_name;

  // TODO: is enabled ? we can't signal if it is not

  /* Check if interface already exists */
  pool_foreach (i, nm->interfaces)
   {
    if (i->sw_if_index == sw_if_index)
      {
        interface = i;
        break;
      }
  }

  if (is_add)
    {
      if (interface)
	goto set_flags;

      pool_get (nm->interfaces, interface);
      interface->sw_if_index = sw_if_index;
      interface->flags = 0;
      nat64_validate_counters (nm, sw_if_index);
    set_flags:
      if (is_inside)
	interface->flags |= NAT64_INTERFACE_FLAG_IS_INSIDE;
      else
	interface->flags |= NAT64_INTERFACE_FLAG_IS_OUTSIDE;

      nm->total_enabled_count++;
      vlib_process_signal_event (vm,
				 nm->expire_walk_node_index,
				 NAT64_CLEANER_RESCHEDULE, 0);

    }
  else
    {
      if (!interface)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if ((nat64_interface_is_inside (interface)
	   && nat64_interface_is_outside (interface)))
	interface->flags &=
	  is_inside ? ~NAT64_INTERFACE_FLAG_IS_INSIDE :
	  ~NAT64_INTERFACE_FLAG_IS_OUTSIDE;
      else
	pool_put (nm->interfaces, interface);

      nm->total_enabled_count--;
    }

  if (!is_inside)
    {
      vec_foreach (ap, nm->addr_pool)
        nat64_add_del_addr_to_fib (&ap->addr, 32, sw_if_index, is_add);
    }

  if (nm->num_workers > 1)
    {
      feature_name =
	is_inside ? "nat64-in2out-handoff" : "nat64-out2in-handoff";
      if (nm->fq_in2out_index == ~0)
	nm->fq_in2out_index =
	  vlib_frame_queue_main_init (nat64_in2out_node.index, 0);
      if (nm->fq_out2in_index == ~0)
	nm->fq_out2in_index =
	  vlib_frame_queue_main_init (nat64_out2in_node.index, 0);
    }
  else
    feature_name = is_inside ? "nat64-in2out" : "nat64-out2in";

  arc_name = is_inside ? "ip6-unicast" : "ip4-unicast";

  if (is_inside)
    {
      int rv = ip6_sv_reass_enable_disable_with_refcnt (sw_if_index, is_add);
      if (rv)
	return rv;
    }
  else
    {
      int rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, is_add);
      if (rv)
	return rv;
    }

  return vnet_feature_enable_disable (arc_name, feature_name, sw_if_index,
				      is_add, 0, 0);
}

void
nat64_interfaces_walk (nat64_interface_walk_fn_t fn, void *ctx)
{
  nat64_main_t *nm = &nat64_main;
  nat64_interface_t *i = 0;

  pool_foreach (i, nm->interfaces)
   {
    if (fn (i, ctx))
      break;
  }
}

// TODO: plugin independent
static_always_inline u16
nat64_random_port (u16 min, u16 max)
{
  nat64_main_t *nm = &nat64_main;
  u32 rwide;
  u16 r;

  rwide = random_u32 (&nm->random_seed);
  r = rwide & 0xFFFF;
  if (r >= min && r <= max)
    return r;

  return min + (rwide % (max - min + 1));
}

static_always_inline int
nat64_alloc_addr_and_port_default (nat64_address_t *addresses, u32 fib_index,
				   clib_thread_index_t thread_index,
				   nat_protocol_t proto, ip4_address_t *addr,
				   u16 *port, u16 port_per_thread,
				   u32 nat_thread_index)
{
  int i;
  nat64_address_t *a, *ga = 0;
  u32 portnum;

  for (i = 0; i < vec_len (addresses); i++)
    {
      a = addresses + i;
      switch (proto)
	{
#define _(N, j, n, s) \
        case NAT_PROTOCOL_##N: \
          if (a->busy_##n##_ports_per_thread[thread_index] < port_per_thread) \
            { \
              if (a->fib_index == fib_index) \
                { \
                  while (1) \
                    { \
                      portnum = (port_per_thread * \
                        nat_thread_index) + \
                        nat64_random_port(0, port_per_thread - 1) + 1024; \
                      if (a->busy_##n##_port_refcounts[portnum]) \
                        continue; \
		      --a->busy_##n##_port_refcounts[portnum]; \
                      a->busy_##n##_ports_per_thread[thread_index]++; \
                      a->busy_##n##_ports++; \
                      *addr = a->addr; \
                      *port = clib_host_to_net_u16(portnum); \
                      return 0; \
                    } \
                } \
              else if (a->fib_index == ~0) \
                { \
                  ga = a; \
                } \
            } \
          break;
	  foreach_nat_protocol
#undef _
	default:
	  return 1;
	}

    }

  if (ga)
    {
      a = ga;
      switch (proto)
	{
#define _(N, j, n, s) \
        case NAT_PROTOCOL_##N: \
          while (1) \
            { \
              portnum = (port_per_thread * \
                nat_thread_index) + \
                nat64_random_port(0, port_per_thread - 1) + 1024; \
	      if (a->busy_##n##_port_refcounts[portnum]) \
                continue; \
	      ++a->busy_##n##_port_refcounts[portnum]; \
              a->busy_##n##_ports_per_thread[thread_index]++; \
              a->busy_##n##_ports++; \
              *addr = a->addr; \
              *port = clib_host_to_net_u16(portnum); \
              return 0; \
            }
	  break;
	  foreach_nat_protocol
#undef _
	default:
	  return 1;
	}
    }

  /* Totally out of translations to use... */
  nat_ipfix_logging_addresses_exhausted (thread_index, 0);
  return 1;
}

int
nat64_alloc_out_addr_and_port (u32 fib_index, nat_protocol_t proto,
			       ip4_address_t *addr, u16 *port,
			       clib_thread_index_t thread_index)
{
  nat64_main_t *nm = &nat64_main;
  u32 worker_index = 0;
  int rv;

  if (nm->num_workers > 1)
    worker_index = thread_index - nm->first_worker_index;

  rv = nat64_alloc_addr_and_port_default (nm->addr_pool, fib_index,
					  thread_index,
					  proto, addr, port,
					  nm->port_per_thread, worker_index);

  return rv;
}

static void
nat64_free_out_addr_and_port (struct nat64_db_s *db, ip4_address_t * addr,
			      u16 port, u8 protocol)
{
  nat64_main_t *nm = &nat64_main;
  clib_thread_index_t thread_index = db - nm->db;
  nat_protocol_t proto = ip_proto_to_nat_proto (protocol);
  u16 port_host_byte_order = clib_net_to_host_u16 (port);
  nat64_address_t *a;
  int i;

  for (i = 0; i < vec_len (nm->addr_pool); i++)
    {
      a = nm->addr_pool + i;
      if (addr->as_u32 != a->addr.as_u32)
	continue;
      switch (proto)
	{
#define _(N, j, n, s) \
        case NAT_PROTOCOL_##N: \
          ASSERT (a->busy_##n##_port_refcounts[port_host_byte_order] >= 1); \
          --a->busy_##n##_port_refcounts[port_host_byte_order]; \
          a->busy_##n##_ports--; \
          a->busy_##n##_ports_per_thread[thread_index]--; \
          break;
	  foreach_nat_protocol
#undef _
	default:
	  nat_elog_str ("unknown protocol");
	  return;
	}
      break;
    }
}

/**
 * @brief Add/delete static BIB entry in worker thread.
 */
static uword
nat64_static_bib_worker_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
			    vlib_frame_t * f)
{
  nat64_main_t *nm = &nat64_main;
  clib_thread_index_t thread_index = vm->thread_index;
  nat64_db_t *db = &nm->db[thread_index];
  nat64_static_bib_to_update_t *static_bib;
  nat64_db_bib_entry_t *bibe;
  ip46_address_t addr;

  pool_foreach (static_bib, nm->static_bibs)
   {
    if ((static_bib->thread_index != thread_index) || (static_bib->done))
      continue;

    if (static_bib->is_add)
      {
          (void) nat64_db_bib_entry_create (thread_index, db,
                                            &static_bib->in_addr,
                                            &static_bib->out_addr,
                                            static_bib->in_port,
                                            static_bib->out_port,
                                            static_bib->fib_index,
                                            static_bib->proto, 1);
          vlib_set_simple_counter (&nm->total_bibs, thread_index, 0,
                                   db->bib.bib_entries_num);
      }
    else
      {
        addr.as_u64[0] = static_bib->in_addr.as_u64[0];
        addr.as_u64[1] = static_bib->in_addr.as_u64[1];
        bibe = nat64_db_bib_entry_find (db, &addr, static_bib->in_port,
                                        static_bib->proto,
                                        static_bib->fib_index, 1);
        if (bibe)
          {
            nat64_db_bib_entry_free (thread_index, db, bibe);
            vlib_set_simple_counter (&nm->total_bibs, thread_index, 0,
                                     db->bib.bib_entries_num);
            vlib_set_simple_counter (&nm->total_sessions, thread_index, 0,
                                     db->st.st_entries_num);
          }
      }

      static_bib->done = 1;
  }

  return 0;
}

static vlib_node_registration_t nat64_static_bib_worker_node;

VLIB_REGISTER_NODE (nat64_static_bib_worker_node, static) = {
    .function = nat64_static_bib_worker_fn,
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_INTERRUPT,
    .name = "nat64-static-bib-worker",
};

int
nat64_add_del_static_bib_entry (ip6_address_t * in_addr,
				ip4_address_t * out_addr, u16 in_port,
				u16 out_port, u8 proto, u32 vrf_id, u8 is_add)
{
  nat64_main_t *nm = &nat64_main;
  nat64_db_bib_entry_t *bibe;
  u32 fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6, vrf_id,
						     nm->fib_src_hi);
  nat_protocol_t p = ip_proto_to_nat_proto (proto);
  ip46_address_t addr;
  int i;
  nat64_address_t *a;
  clib_thread_index_t thread_index = 0;
  nat64_db_t *db;
  nat64_static_bib_to_update_t *static_bib;
  vlib_main_t *worker_vm;
  u32 *to_be_free = 0, *index;

  if (nm->num_workers > 1)
    {
      thread_index = nat64_get_worker_in2out (in_addr);
      db = &nm->db[thread_index];
    }
  else
    db = &nm->db[nm->num_workers];

  addr.as_u64[0] = in_addr->as_u64[0];
  addr.as_u64[1] = in_addr->as_u64[1];
  bibe =
    nat64_db_bib_entry_find (db, &addr, clib_host_to_net_u16 (in_port),
			     proto, fib_index, 1);

  if (is_add)
    {
      if (bibe)
	return VNET_API_ERROR_VALUE_EXIST;

      /* outside port must be assigned to same thread as internall address */
      if ((out_port > 1024) && (nm->num_workers > 1))
	{
	  if (thread_index != get_thread_idx_by_port (out_port))
	    return VNET_API_ERROR_INVALID_VALUE_2;
	}

      for (i = 0; i < vec_len (nm->addr_pool); i++)
	{
	  a = nm->addr_pool + i;
	  if (out_addr->as_u32 != a->addr.as_u32)
	    continue;
	  switch (p)
	    {
#define _(N, j, n, s) \
            case NAT_PROTOCOL_##N: \
              if (a->busy_##n##_port_refcounts[out_port]) \
                return VNET_API_ERROR_INVALID_VALUE; \
	      ++a->busy_##n##_port_refcounts[out_port]; \
              if (out_port > 1024) \
                { \
                  a->busy_##n##_ports++; \
                  a->busy_##n##_ports_per_thread[thread_index]++; \
                } \
              break;
	      foreach_nat_protocol
#undef _
	    default:
	      clib_memset (&addr, 0, sizeof (addr));
	      addr.ip4.as_u32 = out_addr->as_u32;
	      if (nat64_db_bib_entry_find (db, &addr, 0, proto, fib_index, 0))
		return VNET_API_ERROR_INVALID_VALUE;
	    }
	  break;
	}
      if (!nm->num_workers)
	{
	  bibe =
	    nat64_db_bib_entry_create (thread_index, db, in_addr, out_addr,
				       clib_host_to_net_u16 (in_port),
				       clib_host_to_net_u16 (out_port),
				       fib_index, proto, 1);
	  if (!bibe)
	    return VNET_API_ERROR_UNSPECIFIED;

	  vlib_set_simple_counter (&nm->total_bibs, thread_index, 0,
				   db->bib.bib_entries_num);
	}
    }
  else
    {
      if (!bibe)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if (!nm->num_workers)
	{
	  nat64_db_bib_entry_free (thread_index, db, bibe);
	  vlib_set_simple_counter (&nm->total_bibs, thread_index, 0,
				   db->bib.bib_entries_num);
	}
    }

  if (nm->num_workers)
    {
      pool_foreach (static_bib, nm->static_bibs)
       {
        if (static_bib->done)
          vec_add1 (to_be_free, static_bib - nm->static_bibs);
      }
      vec_foreach (index, to_be_free)
        pool_put_index (nm->static_bibs, index[0]);
      vec_free (to_be_free);
      pool_get (nm->static_bibs, static_bib);
      static_bib->in_addr.as_u64[0] = in_addr->as_u64[0];
      static_bib->in_addr.as_u64[1] = in_addr->as_u64[1];
      static_bib->in_port = clib_host_to_net_u16 (in_port);
      static_bib->out_addr.as_u32 = out_addr->as_u32;
      static_bib->out_port = clib_host_to_net_u16 (out_port);
      static_bib->fib_index = fib_index;
      static_bib->proto = proto;
      static_bib->is_add = is_add;
      static_bib->thread_index = thread_index;
      static_bib->done = 0;
      worker_vm = vlib_get_main_by_index (thread_index);
      if (worker_vm)
	vlib_node_set_interrupt_pending (worker_vm,
					 nat64_static_bib_worker_node.index);
      else
	return VNET_API_ERROR_UNSPECIFIED;
    }

  return 0;
}

int
nat64_set_udp_timeout (u32 timeout)
{
  nat64_main_t *nm = &nat64_main;

  if (timeout == 0)
    nm->udp_timeout = NAT_UDP_TIMEOUT;
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
    nm->icmp_timeout = NAT_ICMP_TIMEOUT;
  else
    nm->icmp_timeout = timeout;

  return 0;
}

void
nat64_reset_timeouts ()
{
  nat64_main_t *nm = &nat64_main;

  nm->udp_timeout = NAT_UDP_TIMEOUT;
  nm->icmp_timeout = NAT_ICMP_TIMEOUT;
  nm->tcp_est_timeout = NAT_TCP_ESTABLISHED_TIMEOUT;
  nm->tcp_trans_timeout = NAT_TCP_TRANSITORY_TIMEOUT;
}

u32
nat64_get_icmp_timeout (void)
{
  nat64_main_t *nm = &nat64_main;

  return nm->icmp_timeout;
}

int
nat64_set_tcp_timeouts (u32 trans, u32 est)
{
  nat64_main_t *nm = &nat64_main;

  if (trans == 0)
    nm->tcp_trans_timeout = NAT_TCP_TRANSITORY_TIMEOUT;
  else
    nm->tcp_trans_timeout = trans;

  if (est == 0)
    nm->tcp_est_timeout = NAT_TCP_ESTABLISHED_TIMEOUT;
  else
    nm->tcp_est_timeout = est;

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

void
nat64_session_reset_timeout (nat64_db_st_entry_t * ste, vlib_main_t * vm)
{
  nat64_main_t *nm = &nat64_main;
  u32 now = (u32) vlib_time_now (vm);

  switch (ip_proto_to_nat_proto (ste->proto))
    {
    case NAT_PROTOCOL_ICMP:
      ste->expire = now + nm->icmp_timeout;
      return;
    case NAT_PROTOCOL_TCP:
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
    case NAT_PROTOCOL_UDP:
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
					       nm->fib_src_hi);
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

      // TODO: missing fib_table_unlock ?

      vec_del1 (nm->pref64, i);
    }

  return 0;
}

void
nat64_prefix_walk (nat64_prefix_walk_fn_t fn, void *ctx)
{
  nat64_main_t *nm = &nat64_main;
  nat64_prefix_t *p = 0;

  vec_foreach (p, nm->pref64)
    {
      if (fn (p, ctx))
        break;
    };
}

void
nat64_compose_ip6 (ip6_address_t * ip6, ip4_address_t * ip4, u32 fib_index)
{
  nat64_main_t *nm = &nat64_main;
  nat64_prefix_t *p, *gp = 0, *prefix = 0;

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

  if (!prefix)
    prefix = gp;

  if (prefix)
    {
      clib_memcpy_fast (ip6, &p->prefix, sizeof (ip6_address_t));
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
	  nat_elog_str ("invalid prefix length");
	  break;
	}
    }
  else
    {
      clib_memcpy_fast (ip6, well_known_prefix, sizeof (ip6_address_t));
      ip6->as_u32[3] = ip4->as_u32;
    }
}

void
nat64_extract_ip4 (ip6_address_t * ip6, ip4_address_t * ip4, u32 fib_index)
{
  nat64_main_t *nm = &nat64_main;
  nat64_prefix_t *p, *gp = 0;
  u8 plen = 0;

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
      nat_elog_str ("invalid prefix length");
      break;
    }
}

/**
 * @brief Per worker process checking expire time for NAT64 sessions.
 */
static uword
nat64_expire_worker_walk_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
			     vlib_frame_t * f)
{
  nat64_main_t *nm = &nat64_main;
  clib_thread_index_t thread_index = vm->thread_index;
  nat64_db_t *db;
  u32 now;

  // TODO: barier sync on plugin enabled
  if (plugin_enabled () == 0)
    return 0;

  db = &nm->db[thread_index];
  now = (u32) vlib_time_now (vm);

  nad64_db_st_free_expired (thread_index, db, now);
  vlib_set_simple_counter (&nm->total_bibs, thread_index, 0,
			   db->bib.bib_entries_num);
  vlib_set_simple_counter (&nm->total_sessions, thread_index, 0,
			   db->st.st_entries_num);
  return 0;
}

VLIB_REGISTER_NODE (nat64_expire_worker_walk_node, static) = {
    .function = nat64_expire_worker_walk_fn,
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_INTERRUPT,
    .name = "nat64-expire-worker-walk",
};

/**
 * @brief Centralized process to drive per worker expire walk.
 */
static uword
nat64_expire_walk_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
		      vlib_frame_t * f)
{
  nat64_main_t *nm = &nat64_main;
  vlib_main_t **worker_vms = 0, *worker_vm;
  int i;
  uword event_type, *event_data = 0;

  if (vlib_get_n_threads () == 0)
    vec_add1 (worker_vms, vm);
  else
    {
      for (i = 0; i < vlib_get_n_threads (); i++)
	{
	  worker_vm = vlib_get_main_by_index (i);
	  if (worker_vm)
	    vec_add1 (worker_vms, worker_vm);
	}
    }

  while (1)
    {
      if (nm->total_enabled_count)
	{
	  vlib_process_wait_for_event_or_clock (vm, 10.0);
	  event_type = vlib_process_get_events (vm, &event_data);
	}
      else
	{
	  vlib_process_wait_for_event (vm);
	  event_type = vlib_process_get_events (vm, &event_data);
	}

      switch (event_type)
	{
	case ~0:
	  break;
	case NAT64_CLEANER_RESCHEDULE:
	  break;
	default:
	  nat64_log_err ("unknown event %u", event_type);
	  break;
	}

      for (i = 0; i < vec_len (worker_vms); i++)
	{
	  worker_vm = worker_vms[i];
	  vlib_node_set_interrupt_pending (worker_vm,
					   nm->expire_worker_walk_node_index);
	}
    }

  return 0;
}

void
nat64_create_expire_walk_process ()
{
  nat64_main_t *nm = &nat64_main;

  if (nm->expire_walk_node_index)
    return;
  nm->expire_walk_node_index = vlib_process_create (vlib_get_main (),
						    "nat64-expire-walk",
						    nat64_expire_walk_fn,
						    16 /* stack_bytes */ );
}

int
nat64_plugin_enable (nat64_config_t c)
{
  nat64_main_t *nm = &nat64_main;

  if (plugin_enabled () == 1)
    {
      nat64_log_err ("plugin already enabled!");
      return 1;
    }

  if (!c.bib_buckets)
    c.bib_buckets = 1024;

  if (!c.bib_memory_size)
    c.bib_memory_size = 128 << 20;

  if (!c.st_buckets)
    c.st_buckets = 2048;

  if (!c.st_memory_size)
    c.st_memory_size = 256 << 20;

  nm->config = c;

  if (nat64_init_hash (c))
    {
      nat64_log_err ("initializing hashes failed!");
      return 1;
    }

  nat64_create_expire_walk_process ();

  nm->enabled = 1;
  return 0;
}

int
nat64_plugin_disable ()
{
  nat64_main_t *nm = &nat64_main;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = 0;

  nat64_address_t *a;
  nat64_interface_t *i, *interfaces = 0;

  if (plugin_enabled () == 0)
    {
      nat64_log_err ("plugin already disabled!");
      return 1;
    }
  nm->enabled = 0;

  pool_foreach (i, nm->interfaces)
   {
    vec_add1 (interfaces, *i);
  }
  vec_foreach (i, interfaces)
  {
    rv = nat64_interface_add_del (i->sw_if_index, i->flags, 0);
    if (rv)
      {
	nat64_log_err ("%U %s interface del failed",
		       format_vnet_sw_if_index_name, vnm, i->sw_if_index,
		       i->flags & NAT64_INTERFACE_FLAG_IS_INSIDE ?
		       "inside" : "outside");
      }
  }
  vec_free (interfaces);
  pool_free (nm->interfaces);

  nat64_reset_timeouts ();

  if (nat64_free_hash ())
    {
      rv = 1;
      nat64_log_err ("freeing hashes failed!");
    }

  // TODO: based on nat64_add_del_prefix fib_table_unlock is not called
  vec_free (nm->pref64);

  if (vec_len (nm->addr_pool))
    {
      vec_foreach (a, nm->addr_pool)
      {
	if (a->fib_index != ~0)
	  fib_table_unlock (a->fib_index, FIB_PROTOCOL_IP6, nm->fib_src_hi);
      }
      vec_free (nm->addr_pool);
    }
  return rv;
}

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
