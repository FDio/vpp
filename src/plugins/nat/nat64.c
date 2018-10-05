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
#include <nat/nat_reass.h>
#include <nat/nat_inlines.h>
#include <vnet/fib/ip4_fib.h>
#include <vppinfra/crc32.h>


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
VNET_FEATURE_INIT (nat64_in2out_handoff, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "nat64-in2out-handoff",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
VNET_FEATURE_INIT (nat64_out2in_handoff, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat64-out2in-handoff",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};


static u8 well_known_prefix[] = {
  0x00, 0x64, 0xff, 0x9b,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

/* *INDENT-ON* */

static void
nat64_ip4_add_del_interface_address_cb (ip4_main_t * im, uword opaque,
					u32 sw_if_index,
					ip4_address_t * address,
					u32 address_length,
					u32 if_address_index, u32 is_delete)
{
  nat64_main_t *nm = &nat64_main;
  int i, j;

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

	      (void) nat64_add_del_pool_addr (address, ~0, 1);
	      return;
	    }
	  else
	    {
	      (void) nat64_add_del_pool_addr (address, ~0, 0);
	      return;
	    }
	}
    }
}

u32
nat64_get_worker_in2out (ip6_address_t * addr)
{
  nat64_main_t *nm = &nat64_main;
  snat_main_t *sm = nm->sm;
  u32 next_worker_index = nm->sm->first_worker_index;
  u32 hash;

#ifdef clib_crc32c_uses_intrinsics
  hash = clib_crc32c ((u8 *) addr->as_u32, 16);
#else
  u64 tmp = addr->as_u64[0] ^ addr->as_u64[1];
  hash = clib_xxhash (tmp);
#endif

  if (PREDICT_TRUE (is_pow2 (_vec_len (sm->workers))))
    next_worker_index += sm->workers[hash & (_vec_len (sm->workers) - 1)];
  else
    next_worker_index += sm->workers[hash % _vec_len (sm->workers)];

  return next_worker_index;
}

u32
nat64_get_worker_out2in (ip4_header_t * ip)
{
  nat64_main_t *nm = &nat64_main;
  snat_main_t *sm = nm->sm;
  udp_header_t *udp;
  u16 port;
  u32 proto;

  proto = ip_proto_to_snat_proto (ip->protocol);
  udp = ip4_next_header (ip);
  port = udp->dst_port;

  /* fragments */
  if (PREDICT_FALSE (ip4_is_fragment (ip)))
    {
      if (PREDICT_FALSE (nat_reass_is_drop_frag (0)))
	return vlib_get_thread_index ();

      if (PREDICT_TRUE (!ip4_is_first_fragment (ip)))
	{
	  nat_reass_ip4_t *reass;

	  reass = nat_ip4_reass_find (ip->src_address, ip->dst_address,
				      ip->fragment_id, ip->protocol);

	  if (reass && (reass->thread_index != (u32) ~ 0))
	    return reass->thread_index;
	  else
	    return vlib_get_thread_index ();
	}
    }

  /* unknown protocol */
  if (PREDICT_FALSE (proto == ~0))
    {
      nat64_db_t *db;
      ip46_address_t daddr;
      nat64_db_bib_entry_t *bibe;

      memset (&daddr, 0, sizeof (daddr));
      daddr.ip4.as_u32 = ip->dst_address.as_u32;

      /* *INDENT-OFF* */
      vec_foreach (db, nm->db)
        {
          bibe = nat64_db_bib_entry_find (db, &daddr, 0, ip->protocol, 0, 0);
          if (bibe)
            return (u32) (db - nm->db);
        }
      /* *INDENT-ON* */
      return vlib_get_thread_index ();
    }

  /* ICMP */
  if (PREDICT_FALSE (ip->protocol == IP_PROTOCOL_ICMP))
    {
      icmp46_header_t *icmp = (icmp46_header_t *) udp;
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      if (!icmp_is_error_message (icmp))
	port = echo->identifier;
      else
	{
	  ip4_header_t *inner_ip = (ip4_header_t *) (echo + 1);
	  proto = ip_proto_to_snat_proto (inner_ip->protocol);
	  void *l4_header = ip4_next_header (inner_ip);
	  switch (proto)
	    {
	    case SNAT_PROTOCOL_ICMP:
	      icmp = (icmp46_header_t *) l4_header;
	      echo = (icmp_echo_header_t *) (icmp + 1);
	      port = echo->identifier;
	      break;
	    case SNAT_PROTOCOL_UDP:
	    case SNAT_PROTOCOL_TCP:
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
    return nm->sm->first_worker_index + ((port - 1024) / sm->port_per_thread);

  return vlib_get_thread_index ();
}

clib_error_t *
nat64_init (vlib_main_t * vm)
{
  nat64_main_t *nm = &nat64_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  ip4_add_del_interface_address_callback_t cb4;
  ip4_main_t *im = &ip4_main;
  vlib_node_t *error_drop_node =
    vlib_get_node_by_name (vm, (u8 *) "error-drop");

  vec_validate (nm->db, tm->n_vlib_mains - 1);

  nm->sm = &snat_main;

  nm->fq_in2out_index = ~0;
  nm->fq_out2in_index = ~0;
  nm->error_node_index = error_drop_node->index;

  /* set session timeouts to default values */
  nm->udp_timeout = SNAT_UDP_TIMEOUT;
  nm->icmp_timeout = SNAT_ICMP_TIMEOUT;
  nm->tcp_trans_timeout = SNAT_TCP_TRANSITORY_TIMEOUT;
  nm->tcp_est_timeout = SNAT_TCP_ESTABLISHED_TIMEOUT;

  nm->total_enabled_count = 0;

  /* Set up the interface address add/del callback */
  cb4.function = nat64_ip4_add_del_interface_address_cb;
  cb4.function_opaque = 0;
  vec_add1 (im->add_del_interface_address_callbacks, cb4);
  nm->ip4_main = im;

  return 0;
}

static void nat64_free_out_addr_and_port (struct nat64_db_s *db,
					  ip4_address_t * addr, u16 port,
					  u8 protocol);

void
nat64_set_hash (u32 bib_buckets, u32 bib_memory_size, u32 st_buckets,
		u32 st_memory_size)
{
  nat64_main_t *nm = &nat64_main;
  nat64_db_t *db;

  nm->bib_buckets = bib_buckets;
  nm->bib_memory_size = bib_memory_size;
  nm->st_buckets = st_buckets;
  nm->st_memory_size = st_memory_size;

  /* *INDENT-OFF* */
  vec_foreach (db, nm->db)
    {
      if (nat64_db_init (db, bib_buckets, bib_memory_size, st_buckets,
                         st_memory_size, nat64_free_out_addr_and_port))
	nat_log_err ("NAT64 DB init failed");
    }
  /* *INDENT-ON* */
}

int
nat64_add_del_pool_addr (ip4_address_t * addr, u32 vrf_id, u8 is_add)
{
  nat64_main_t *nm = &nat64_main;
  snat_address_t *a = 0;
  snat_interface_t *interface;
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
					     FIB_SOURCE_PLUGIN_HI);
#define _(N, id, n, s) \
      clib_bitmap_alloc (a->busy_##n##_port_bitmap, 65535); \
      a->busy_##n##_ports = 0; \
      vec_validate_init_empty (a->busy_##n##_ports_per_thread, tm->n_vlib_mains - 1, 0);
      foreach_snat_protocol
#undef _
    }
  else
    {
      if (!a)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if (a->fib_index != ~0)
	fib_table_unlock (a->fib_index, FIB_PROTOCOL_IP6,
			  FIB_SOURCE_PLUGIN_HI);
      /* Delete sessions using address */
        /* *INDENT-OFF* */
        vec_foreach (db, nm->db)
          nat64_db_free_out_addr (db, &a->addr);
#define _(N, id, n, s) \
      clib_bitmap_free (a->busy_##n##_port_bitmap);
      foreach_snat_protocol
#undef _
        /* *INDENT-ON* */
      vec_del1 (nm->addr_pool, i);
    }

  /* Add/del external address to FIB */
  /* *INDENT-OFF* */
  pool_foreach (interface, nm->interfaces,
  ({
    if (nat_interface_is_inside(interface))
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
		(void) nat64_add_del_pool_addr (first_int_addr, ~0, 0);

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
    (void) nat64_add_del_pool_addr (first_int_addr, ~0, 1);

  return 0;
}

int
nat64_add_del_interface (u32 sw_if_index, u8 is_inside, u8 is_add)
{
  nat64_main_t *nm = &nat64_main;
  snat_interface_t *interface = 0, *i;
  snat_address_t *ap;
  const char *feature_name, *arc_name;

  /* Check if interface already exists */
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
	goto set_flags;

      pool_get (nm->interfaces, interface);
      interface->sw_if_index = sw_if_index;
      interface->flags = 0;
    set_flags:
      if (is_inside)
	interface->flags |= NAT_INTERFACE_FLAG_IS_INSIDE;
      else
	interface->flags |= NAT_INTERFACE_FLAG_IS_OUTSIDE;

      nm->total_enabled_count++;
      vlib_process_signal_event (nm->sm->vlib_main,
				 nm->nat64_expire_walk_node_index,
				 NAT64_CLEANER_RESCHEDULE, 0);

    }
  else
    {
      if (!interface)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if ((nat_interface_is_inside (interface)
	   && nat_interface_is_outside (interface)))
	interface->flags &=
	  is_inside ? ~NAT_INTERFACE_FLAG_IS_INSIDE :
	  ~NAT_INTERFACE_FLAG_IS_OUTSIDE;
      else
	pool_put (nm->interfaces, interface);

      nm->total_enabled_count--;
    }

  if (!is_inside)
    {
      /* *INDENT-OFF* */
      vec_foreach (ap, nm->addr_pool)
        snat_add_del_addr_to_fib(&ap->addr, 32, sw_if_index, is_add);
      /* *INDENT-ON* */
    }

  if (nm->sm->num_workers > 1)
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
			       ip4_address_t * addr, u16 * port,
			       u32 thread_index)
{
  nat64_main_t *nm = &nat64_main;
  snat_main_t *sm = nm->sm;
  snat_session_key_t k;
  u32 worker_index = 0;
  int rv;

  k.protocol = proto;

  if (sm->num_workers > 1)
    worker_index = thread_index - sm->first_worker_index;

  rv =
    sm->alloc_addr_and_port (nm->addr_pool, fib_index, thread_index, &k,
			     sm->port_per_thread, worker_index);

  if (!rv)
    {
      *port = k.port;
      addr->as_u32 = k.addr.as_u32;
    }

  return rv;
}

static void
nat64_free_out_addr_and_port (struct nat64_db_s *db, ip4_address_t * addr,
			      u16 port, u8 protocol)
{
  nat64_main_t *nm = &nat64_main;
  int i;
  snat_address_t *a;
  u32 thread_index = db - nm->db;
  snat_protocol_t proto = ip_proto_to_snat_proto (protocol);
  u16 port_host_byte_order = clib_net_to_host_u16 (port);

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
                  port_host_byte_order) == 1); \
          clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, port, 0); \
          a->busy_##n##_ports--; \
          a->busy_##n##_ports_per_thread[thread_index]--; \
          break;
	  foreach_snat_protocol
#undef _
	default:
	  nat_log_notice ("unknown protocol");
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
  u32 thread_index = vm->thread_index;
  nat64_db_t *db = &nm->db[thread_index];
  nat64_static_bib_to_update_t *static_bib;
  nat64_db_bib_entry_t *bibe;
  ip46_address_t addr;

  /* *INDENT-OFF* */
  pool_foreach (static_bib, nm->static_bibs,
  ({
    if ((static_bib->thread_index != thread_index) || (static_bib->done))
      continue;

    if (static_bib->is_add)
      (void) nat64_db_bib_entry_create (db, &static_bib->in_addr,
                                        &static_bib->out_addr,
                                        static_bib->in_port,
                                        static_bib->out_port,
				        static_bib->fib_index,
                                        static_bib->proto, 1);
    else
      {
        addr.as_u64[0] = static_bib->in_addr.as_u64[0];
        addr.as_u64[1] = static_bib->in_addr.as_u64[1];
        bibe = nat64_db_bib_entry_find (db, &addr, static_bib->in_port,
                                        static_bib->proto,
                                        static_bib->fib_index, 1);
        if (bibe)
          nat64_db_bib_entry_free (db, bibe);
      }

      static_bib->done = 1;
  }));
  /* *INDENT-ON* */

  return 0;
}

static vlib_node_registration_t nat64_static_bib_worker_node;

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat64_static_bib_worker_node, static) = {
    .function = nat64_static_bib_worker_fn,
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_INTERRUPT,
    .name = "nat64-static-bib-worker",
};
/* *INDENT-ON* */

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
  u32 thread_index = 0;
  nat64_db_t *db;
  nat64_static_bib_to_update_t *static_bib;
  vlib_main_t *worker_vm;
  u32 *to_be_free = 0, *index;

  if (nm->sm->num_workers > 1)
    {
      thread_index = nat64_get_worker_in2out (in_addr);
      db = &nm->db[thread_index];
    }
  else
    db = &nm->db[nm->sm->num_workers];

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
      if ((out_port > 1024) && (nm->sm->num_workers > 1))
	{
	  if (thread_index != ((out_port - 1024) / nm->sm->port_per_thread))
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
            case SNAT_PROTOCOL_##N: \
              if (clib_bitmap_get_no_check (a->busy_##n##_port_bitmap, \
                                            out_port)) \
                return VNET_API_ERROR_INVALID_VALUE; \
              clib_bitmap_set_no_check (a->busy_##n##_port_bitmap, \
                                        out_port, 1); \
              if (out_port > 1024) \
                { \
                  a->busy_##n##_ports++; \
                  a->busy_##n##_ports_per_thread[thread_index]++; \
                } \
              break;
	      foreach_snat_protocol
#undef _
	    default:
	      memset (&addr, 0, sizeof (addr));
	      addr.ip4.as_u32 = out_addr->as_u32;
	      if (nat64_db_bib_entry_find (db, &addr, 0, proto, fib_index, 0))
		return VNET_API_ERROR_INVALID_VALUE;
	    }
	  break;
	}
      if (!nm->sm->num_workers)
	{
	  bibe =
	    nat64_db_bib_entry_create (db, in_addr, out_addr,
				       clib_host_to_net_u16 (in_port),
				       clib_host_to_net_u16 (out_port),
				       fib_index, proto, 1);
	  if (!bibe)
	    return VNET_API_ERROR_UNSPECIFIED;
	}
    }
  else
    {
      if (!bibe)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if (!nm->sm->num_workers)
	nat64_db_bib_entry_free (db, bibe);
    }

  if (nm->sm->num_workers)
    {
      /* *INDENT-OFF* */
      pool_foreach (static_bib, nm->static_bibs,
      ({
        if (static_bib->done)
          vec_add1 (to_be_free, static_bib - nm->static_bibs);
      }));
      vec_foreach (index, to_be_free)
        pool_put_index (nm->static_bibs, index[0]);
      /* *INDENT-ON* */
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
      worker_vm = vlib_mains[thread_index];
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
    nm->udp_timeout = SNAT_UDP_TIMEOUT;
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
nat64_set_tcp_timeouts (u32 trans, u32 est)
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
      clib_memcpy (ip6, &p->prefix, sizeof (ip6_address_t));
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
	  nat_log_notice ("invalid prefix length");
	  break;
	}
    }
  else
    {
      clib_memcpy (ip6, well_known_prefix, sizeof (ip6_address_t));
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
      nat_log_notice ("invalid prefix length");
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
  u32 thread_index = vm->thread_index;
  nat64_db_t *db = &nm->db[thread_index];
  u32 now = (u32) vlib_time_now (vm);

  nad64_db_st_free_expired (db, now);

  return 0;
}

static vlib_node_registration_t nat64_expire_worker_walk_node;

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat64_expire_worker_walk_node, static) = {
    .function = nat64_expire_worker_walk_fn,
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_INTERRUPT,
    .name = "nat64-expire-worker-walk",
};
/* *INDENT-ON* */

static vlib_node_registration_t nat64_expire_walk_node;

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

  nm->nat64_expire_walk_node_index = nat64_expire_walk_node.index;

  if (vec_len (vlib_mains) == 0)
    vec_add1 (worker_vms, vm);
  else
    {
      for (i = 0; i < vec_len (vlib_mains); i++)
	{
	  worker_vm = vlib_mains[i];
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
	  nat_log_notice ("unknown event %u", event_type);
	  break;
	}

      for (i = 0; i < vec_len (worker_vms); i++)
	{
	  worker_vm = worker_vms[i];
	  vlib_node_set_interrupt_pending (worker_vm,
					   nat64_expire_worker_walk_node.index);
	}
    }

  return 0;
}

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
